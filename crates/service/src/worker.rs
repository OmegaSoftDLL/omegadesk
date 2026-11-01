//! Per-session capture/input worker (`service worker`).
//!
//! The service launches this process as SYSTEM in the active console session
//! (see [`crate::token`]). It connects back to the service over the named pipe,
//! completes the hello handshake, then runs the real capture/input work on a
//! dedicated OS thread that:
//!
//! - selects the active input desktop with
//!   [`omegadesk_capture::service_desktop::select_input_desktop`]
//!   (`SetThreadDesktop`), and re-selects it whenever the input desktop switches
//!   between `winsta0\default` and `winsta0\winlogon` (lock screen, UAC secure
//!   desktop, login screen) so capture and injection follow the user;
//! - captures frames through the `DXGI -> WGC -> GDI` fallback chain
//!   ([`omegadesk_capture::open_display_tracked`]);
//! - injects remote input with [`omegadesk_input`] on the current desktop —
//!   because the worker is SYSTEM it can inject on the secure desktop; and
//! - toggles privacy-mode blanking ([`crate::privacy`]) on command.
//!
//! The service forwards Shutdown/Privacy/Input/Desktop messages to the capture
//! thread; the capture thread reports `WorkerStatus` back. Network streaming of
//! the captured frames is wired in with the session integration; here the
//! frames prove the capture path runs as SYSTEM across every desktop, which is
//! the hard part this phase delivers.

use std::sync::mpsc::{Receiver, TryRecvError};
use std::time::{Duration, Instant};

use anyhow::Context;
use omegadesk_capture::open_display_tracked;
use omegadesk_capture::service_desktop::{
    CaptureBackendKind, DesktopHandoffMonitor, input_desktop_selected, select_input_desktop,
};
use omegadesk_input::InputInjector;
use omegadesk_protocol::service::SERVICE_PROTOCOL_VERSION;
use omegadesk_protocol::service::v1::{
    CaptureBackend, InjectInput, PrivacyCommand, ServiceEnvelope, WorkerHello, WorkerStatus,
    inject_input::Event as InjectEvent, service_envelope::Message as SvcMessage,
};
use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeClient};
use tokio::sync::mpsc::UnboundedSender;
use tracing::{info, warn};

use crate::cli::WorkerArgs;
use crate::ipc::{IpcConnection, IpcError, pipe_path};
use crate::privacy::PrivacyOverlay;

/// A command the IPC side forwards to the capture/input thread.
enum Command {
    Shutdown,
    SetPrivacy(bool),
    Inject(InjectEvent),
    FollowDesktop,
}

/// Runs the worker. Builds a runtime, connects, handshakes, then pumps IPC.
///
/// # Errors
///
/// Returns an error if the runtime cannot be built or the initial connection /
/// handshake with the service fails.
pub(crate) fn run(args: &WorkerArgs) -> anyhow::Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .context("failed to build the worker runtime")?;
    runtime.block_on(run_worker(args.clone()))
}

async fn run_worker(args: WorkerArgs) -> anyhow::Result<()> {
    let session_id = current_session_id();
    info!(session = session_id, pipe = %args.pipe, "worker starting");

    let path = pipe_path(&args.pipe);
    let client = connect_with_retry(&path).await?;
    let mut connection = IpcConnection::new(client);

    // Hello handshake.
    connection
        .send(&ServiceEnvelope {
            message: Some(SvcMessage::WorkerHello(WorkerHello {
                protocol_version: SERVICE_PROTOCOL_VERSION,
                session_id,
                pid: std::process::id(),
            })),
        })
        .await
        .context("failed to send WorkerHello")?;
    match connection.recv().await?.message {
        Some(SvcMessage::ServiceWelcome(welcome)) if welcome.accepted => {}
        Some(SvcMessage::ServiceWelcome(_)) => {
            anyhow::bail!("service rejected the worker (wrong session or protocol)");
        }
        _ => anyhow::bail!("expected ServiceWelcome from the service"),
    }

    let (command_tx, command_rx) = std::sync::mpsc::channel::<Command>();
    let (status_tx, mut status_rx) = tokio::sync::mpsc::unbounded_channel::<ServiceEnvelope>();

    let display = args.display;
    let capture_thread = std::thread::Builder::new()
        .name("omegadesk-capture".to_owned())
        .spawn(move || capture_loop(session_id, display, &command_rx, &status_tx))
        .context("failed to spawn the capture thread")?;

    let (mut reader, writer) = connection.split();

    // Forward worker status/heartbeats to the service.
    let writer_task = tokio::spawn(async move {
        let mut writer = writer;
        while let Some(envelope) = status_rx.recv().await {
            if writer.send(&envelope).await.is_err() {
                break;
            }
        }
    });

    // Pump inbound service commands to the capture thread.
    loop {
        match reader.recv().await {
            Ok(envelope) => {
                if dispatch_command(&command_tx, envelope.message) {
                    break; // Shutdown
                }
            }
            Err(IpcError::Closed) => {
                info!("service closed the IPC connection; worker exiting");
                let _ = command_tx.send(Command::Shutdown);
                break;
            }
            Err(error) => {
                warn!(%error, "worker IPC error; exiting");
                let _ = command_tx.send(Command::Shutdown);
                break;
            }
        }
    }

    // Let the capture thread stop before we return.
    let _ = tokio::task::spawn_blocking(move || capture_thread.join()).await;
    writer_task.abort();
    Ok(())
}

/// Forwards one inbound IPC message to the capture thread. Returns `true` when
/// the worker should stop.
#[allow(
    clippy::needless_pass_by_value,
    reason = "the InjectInput arm moves the event payload out of `message` into a Command"
)]
fn dispatch_command(tx: &std::sync::mpsc::Sender<Command>, message: Option<SvcMessage>) -> bool {
    match message {
        Some(SvcMessage::Shutdown(_)) => {
            let _ = tx.send(Command::Shutdown);
            true
        }
        Some(SvcMessage::PrivacyCommand(PrivacyCommand { enable, .. })) => {
            let _ = tx.send(Command::SetPrivacy(enable));
            false
        }
        Some(SvcMessage::InjectInput(InjectInput { event: Some(event) })) => {
            let _ = tx.send(Command::Inject(event));
            false
        }
        Some(SvcMessage::DesktopDirective(_)) => {
            let _ = tx.send(Command::FollowDesktop);
            false
        }
        _ => false,
    }
}

/// Connects to the service pipe, retrying briefly while the server finishes
/// setting it up.
async fn connect_with_retry(path: &str) -> anyhow::Result<NamedPipeClient> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match ClientOptions::new().open(path) {
            Ok(client) => return Ok(client),
            Err(error) if Instant::now() < deadline => {
                tracing::debug!(%error, "service pipe not ready; retrying");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(error) => {
                return Err(anyhow::anyhow!(
                    "failed to open the service pipe {path}: {error}"
                ));
            }
        }
    }
}

/// The capture/input loop, run on a dedicated OS thread bound to the active
/// input desktop.
fn capture_loop(
    session_id: u32,
    display: u32,
    commands: &Receiver<Command>,
    status: &UnboundedSender<ServiceEnvelope>,
) {
    // Bind this thread to whatever desktop is currently in front.
    let mut current_desktop = select_input_desktop().unwrap_or_else(|| "Default".to_owned());
    let mut handoff = DesktopHandoffMonitor::new();
    let _ = handoff.observe(session_id, &current_desktop);

    let mut injector: Option<Box<dyn InputInjector>> = match omegadesk_input::open() {
        Ok(injector) => Some(injector),
        Err(error) => {
            warn!(%error, "input injection unavailable in this session");
            None
        }
    };
    let mut privacy: Option<PrivacyOverlay> = None;
    let mut capturer = None;
    let mut backend = CaptureBackendKind::GdiBitBlt;
    let mut frames_since_status: u64 = 0;
    let mut last_status = Instant::now();
    let frame_timeout = Duration::from_millis(100);

    loop {
        // Apply pending commands.
        loop {
            match commands.try_recv() {
                Ok(Command::Shutdown) | Err(TryRecvError::Disconnected) => {
                    if let Some(overlay) = privacy.take() {
                        overlay.disable();
                    }
                    return;
                }
                Ok(Command::SetPrivacy(true)) => {
                    if privacy.is_none() {
                        match PrivacyOverlay::enable() {
                            Ok(overlay) => {
                                info!("privacy mode enabled (local screen blanked)");
                                privacy = Some(overlay);
                            }
                            Err(error) => warn!("failed to enable privacy mode: {error:#}"),
                        }
                    }
                }
                Ok(Command::SetPrivacy(false)) => {
                    if let Some(overlay) = privacy.take() {
                        overlay.disable();
                        info!("privacy mode disabled");
                    }
                }
                Ok(Command::Inject(event)) => inject(&mut injector, event),
                Ok(Command::FollowDesktop) => {}
                Err(TryRecvError::Empty) => break,
            }
        }

        // Follow desktop switches (Default <-> Winlogon secure desktop).
        if !input_desktop_selected()
            && let Some(name) = select_input_desktop()
        {
            info!(from = %current_desktop, to = %name, "input desktop switched");
            name.clone_into(&mut current_desktop);
            let _ = handoff.observe(session_id, &current_desktop);
            capturer = None; // reopen on the new desktop
        }

        // Ensure a capturer is open.
        if capturer.is_none() {
            match open_display_tracked(display) {
                Ok((opened, kind)) => {
                    backend = kind;
                    capturer = Some(opened);
                }
                Err(error) => {
                    tracing::debug!(%error, "capture open failed; retrying");
                    send_status(status, &current_desktop, backend, privacy.is_some(), 0);
                    std::thread::sleep(Duration::from_millis(250));
                    continue;
                }
            }
        }

        if let Some(cap) = capturer.as_mut() {
            match cap.next_frame(frame_timeout) {
                Ok(Some(frame)) => {
                    // Touch the captured pixels so the capture cannot be elided.
                    std::hint::black_box(frame.bgra.first().copied());
                    frames_since_status = frames_since_status.wrapping_add(1);
                }
                Ok(None) => {}
                Err(omegadesk_capture::CaptureError::AccessLost) => capturer = None,
                Err(error) => {
                    tracing::debug!(%error, "capture error; reopening");
                    capturer = None;
                    std::thread::sleep(Duration::from_millis(200));
                }
            }
        }

        if last_status.elapsed() >= Duration::from_secs(1) {
            last_status = Instant::now();
            send_status(
                status,
                &current_desktop,
                backend,
                privacy.is_some(),
                frames_since_status,
            );
            frames_since_status = 0;
        }
    }
}

/// Injects one input event on the current desktop.
fn inject(injector: &mut Option<Box<dyn InputInjector>>, event: InjectEvent) {
    let Some(injector) = injector.as_mut() else {
        return;
    };
    let result = match event {
        InjectEvent::Key(key) => injector.key(&key),
        InjectEvent::Pointer(pointer) => injector.pointer(&pointer),
    };
    if let Err(error) = result {
        tracing::debug!(%error, "input injection rejected");
    }
}

/// Sends a [`WorkerStatus`] to the service.
fn send_status(
    status: &UnboundedSender<ServiceEnvelope>,
    desktop: &str,
    backend: CaptureBackendKind,
    privacy_active: bool,
    frames: u64,
) {
    let _ = status.send(ServiceEnvelope {
        message: Some(SvcMessage::WorkerStatus(WorkerStatus {
            current_desktop: desktop.to_owned(),
            backend: backend_code(backend),
            privacy_active,
            frames_captured: frames,
        })),
    });
}

/// Maps a capture backend to its protobuf enum value.
fn backend_code(backend: CaptureBackendKind) -> i32 {
    let value = match backend {
        CaptureBackendKind::DxgiDesktopDuplication => CaptureBackend::Dxgi,
        CaptureBackendKind::WindowsGraphicsCapture => CaptureBackend::Wgc,
        CaptureBackendKind::GdiBitBlt => CaptureBackend::Gdi,
    };
    value as i32
}

/// Returns the Windows session id of the current process.
fn current_session_id() -> u32 {
    #![allow(
        unsafe_code,
        reason = "ProcessIdToSessionId needs the process id and an out-pointer via FFI"
    )]
    use windows::Win32::System::RemoteDesktop::ProcessIdToSessionId;
    use windows::Win32::System::Threading::GetCurrentProcessId;
    // SAFETY: `GetCurrentProcessId` has no preconditions.
    let pid = unsafe { GetCurrentProcessId() };
    let mut session = 0u32;
    // SAFETY: `pid` is this process's id; `session` is a valid out-pointer.
    if unsafe { ProcessIdToSessionId(pid, &raw mut session) }.is_ok() {
        session
    } else {
        0
    }
}
