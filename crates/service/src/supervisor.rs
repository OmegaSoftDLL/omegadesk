//! Service supervisor: keeps exactly one capture/input worker alive in the
//! active console session, over the whole lifetime of the service.
//!
//! Drives the [`crate::state::WorkerSupervisorState`] machine from the active
//! console session id (`WTSGetActiveConsoleSessionId`) and worker-exit events,
//! and performs the actions it returns: open a per-launch named pipe, spawn the
//! worker as SYSTEM with the session's winlogon token ([`crate::token`]),
//! complete the hello handshake, then supervise it. This mirrors RustDesk
//! `run_service` (launch on the current session, relaunch when it changes or
//! the process dies) and Aspia's `host_service` supervising `user_session`
//! workers.

use std::time::Duration;

use omegadesk_capture::service_desktop::active_console_session_id;
use omegadesk_protocol::service::SERVICE_PROTOCOL_VERSION;
use omegadesk_protocol::service::v1::{
    ServiceEnvelope, ServiceWelcome, Shutdown, service_envelope::Message as SvcMessage,
};
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::dispatch::ServiceEvent;
use crate::ipc::{FramedWriter, IpcConnection, IpcError, pipe_path};
use crate::state::{SupervisorAction, WorkerSupervisorState};
use crate::token::{WorkerProcess, launch_worker_in_session, session_has_interactive_user};

/// How often the supervisor re-checks the active session and worker liveness,
/// in addition to reacting to SCM session-change events.
const TICK: Duration = Duration::from_secs(2);

/// How long to wait for the freshly launched worker to connect to the pipe.
const WORKER_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// The monitor the worker captures. The service has no display argument yet, so
/// it supervises the primary monitor; multi-monitor selection arrives with the
/// network session integration.
const WORKER_DISPLAY: u32 = 0;

/// A live worker: its process handle, the session it serves, the IPC writer and
/// the background reader task draining its status/heartbeat messages.
struct WorkerHandle {
    process: WorkerProcess,
    session_id: u32,
    writer: FramedWriter<tokio::io::WriteHalf<NamedPipeServer>>,
    reader_task: JoinHandle<()>,
}

impl WorkerHandle {
    /// Asks the worker to exit, gives it a moment, then terminates it if needed.
    async fn shutdown(mut self) {
        let shutdown = ServiceEnvelope {
            message: Some(SvcMessage::Shutdown(Shutdown {})),
        };
        if let Err(error) = self.writer.send(&shutdown).await {
            warn!(session = self.session_id, %error, "failed to send Shutdown to the worker");
        }
        for _ in 0..20 {
            if !self.process.is_alive() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        if self.process.is_alive() {
            self.process.terminate();
        }
        self.reader_task.abort();
    }
}

/// Runs the supervisor until the service is asked to stop.
pub(crate) async fn run(mut events: UnboundedReceiver<ServiceEvent>) {
    let mut state = WorkerSupervisorState::new();
    let mut worker: Option<WorkerHandle> = None;
    let mut launch_counter: u64 = 0;

    // Prime with the current active console session.
    let action = state.observe_active_session(active_console_session_id());
    perform(action, &mut state, &mut worker, &mut launch_counter).await;

    let mut tick = tokio::time::interval(TICK);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            event = events.recv() => {
                match event {
                    None | Some(ServiceEvent::Stop) => {
                        info!("service stop requested");
                        break;
                    }
                    Some(ServiceEvent::SessionChange { change, session_id }) => {
                        info!(?change, session_id, "session-change notification");
                        if change.may_change_active_session() {
                            let action = state.observe_active_session(active_console_session_id());
                            perform(action, &mut state, &mut worker, &mut launch_counter).await;
                        }
                    }
                }
            }
            _ = tick.tick() => {
                // Relaunch a worker that exited unexpectedly.
                if let Some(handle) = worker.as_ref()
                    && !handle.process.is_alive()
                {
                    let session_id = handle.session_id;
                    warn!(session = session_id, "worker exited; evaluating relaunch");
                    worker = None;
                    let action = state.observe_worker_exited(session_id);
                    perform(action, &mut state, &mut worker, &mut launch_counter).await;
                }
                // Catch active-session changes even without an SCM event.
                let action = state.observe_active_session(active_console_session_id());
                perform(action, &mut state, &mut worker, &mut launch_counter).await;
            }
        }
    }

    if let Some(handle) = worker.take() {
        handle.shutdown().await;
        state.worker_stopped();
    }
}

/// Executes one [`SupervisorAction`].
async fn perform(
    action: SupervisorAction,
    state: &mut WorkerSupervisorState,
    worker: &mut Option<WorkerHandle>,
    launch_counter: &mut u64,
) {
    match action {
        SupervisorAction::Idle => {}
        SupervisorAction::StopWorker => {
            if let Some(handle) = worker.take() {
                handle.shutdown().await;
            }
            state.worker_stopped();
        }
        SupervisorAction::LaunchWorker { session_id } => {
            // Replace any worker from a previous session first.
            if let Some(handle) = worker.take() {
                handle.shutdown().await;
            }
            *launch_counter += 1;
            match launch_worker(session_id, *launch_counter).await {
                Ok(handle) => {
                    info!(
                        session = session_id,
                        pid = handle.process.pid(),
                        "worker launched"
                    );
                    *worker = Some(handle);
                    state.worker_launched(session_id);
                }
                Err(error) => {
                    warn!(session = session_id, "failed to launch worker: {error:#}");
                    // Leave state as not-launched so the next tick retries.
                    state.worker_stopped();
                }
            }
        }
    }
}

/// Opens a per-launch named pipe, spawns the worker as SYSTEM in `session_id`,
/// and completes the hello handshake.
async fn launch_worker(session_id: u32, launch_counter: u64) -> anyhow::Result<WorkerHandle> {
    let has_user = session_has_interactive_user(session_id);
    info!(
        session = session_id,
        interactive_user = has_user,
        "launching worker (login screen only when no interactive user)"
    );
    let instance = format!("{}.{launch_counter}", std::process::id());
    let path = pipe_path(&instance);
    let server = ServerOptions::new()
        .first_pipe_instance(true)
        .reject_remote_clients(true)
        .create(&path)?;

    let process = launch_worker_in_session(session_id, &instance, WORKER_DISPLAY)?;

    // Wait for the worker to connect to the pipe.
    tokio::time::timeout(WORKER_CONNECT_TIMEOUT, server.connect())
        .await
        .map_err(|_| anyhow::anyhow!("worker did not connect within {WORKER_CONNECT_TIMEOUT:?}"))?
        .map_err(|error| anyhow::anyhow!("worker pipe connect failed: {error}"))?;

    let mut connection = IpcConnection::new(server);
    handshake(&mut connection, session_id).await?;

    let (mut reader, writer) = connection.split();
    let reader_task = tokio::spawn(async move {
        loop {
            match reader.recv().await {
                Ok(envelope) => log_worker_message(session_id, &envelope),
                Err(IpcError::Closed) => {
                    info!(session = session_id, "worker IPC closed");
                    break;
                }
                Err(error) => {
                    warn!(session = session_id, %error, "worker IPC error");
                    break;
                }
            }
        }
    });

    Ok(WorkerHandle {
        process,
        session_id,
        writer,
        reader_task,
    })
}

/// Exchanges `WorkerHello` / `ServiceWelcome` and verifies the worker runs in
/// the session we launched it into.
async fn handshake(
    connection: &mut IpcConnection<NamedPipeServer>,
    expected_session: u32,
) -> anyhow::Result<()> {
    let hello = connection.recv().await?;
    let Some(SvcMessage::WorkerHello(hello)) = hello.message else {
        anyhow::bail!("expected WorkerHello as the first IPC message");
    };
    let accepted =
        hello.session_id == expected_session && hello.protocol_version == SERVICE_PROTOCOL_VERSION;
    connection
        .send(&ServiceEnvelope {
            message: Some(SvcMessage::ServiceWelcome(ServiceWelcome {
                protocol_version: SERVICE_PROTOCOL_VERSION,
                accepted,
            })),
        })
        .await?;
    if !accepted {
        anyhow::bail!(
            "worker reported session {} / protocol {} (expected {expected_session} / {SERVICE_PROTOCOL_VERSION})",
            hello.session_id,
            hello.protocol_version
        );
    }
    Ok(())
}

/// Logs a status message received from the worker (other messages, such as
/// heartbeats, need no action).
fn log_worker_message(session_id: u32, envelope: &ServiceEnvelope) {
    if let Some(SvcMessage::WorkerStatus(status)) = &envelope.message {
        info!(
            session = session_id,
            desktop = %status.current_desktop,
            backend = status.backend,
            privacy = status.privacy_active,
            frames = status.frames_captured,
            "worker status",
        );
    }
}
