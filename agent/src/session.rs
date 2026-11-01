//! Remote access session handling: handshake, video streaming, and control messages.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use anyhow::bail;
use omegadesk_codec::EncoderSettings;
use omegadesk_identity::DeviceId;
use omegadesk_input::{InputInjector, TargetDisplay};
use omegadesk_protocol::v1::{
    Capabilities, Envelope, Error as ProtocolError, ErrorCode, HelloAck, Pong, VideoCodec,
    envelope::Payload,
};
use omegadesk_protocol::{PROTOCOL_VERSION, negotiate_codec};
use omegadesk_transport::{Connection, EnvelopeReader, SendStream, send_envelope};
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::capture_loop::{self, EncoderChoice};

/// Video codecs this agent can encode, in preference order.
const ENCODERS: [VideoCodec; 1] = [VideoCodec::H264];

/// Artificial delay before replying to a wrong password to slow down brute-force attempts.
const WRONG_PASSWORD_DELAY: Duration = Duration::from_secs(1);

/// Grace period allowing the client to read the rejection message before the connection closes.
const REJECT_GRACE: Duration = Duration::from_secs(2);

/// Bounded queue of encoded video frames waiting to be sent on the network.
/// Intentionally tiny: frames that do not fit are dropped at capture time
/// (see `capture_loop`).
const VIDEO_QUEUE: usize = 2;

/// QUIC application close codes.
mod close_code {
    pub(super) const NORMAL: u32 = 0;
    pub(super) const REJECTED: u32 = 1;
}

/// What the connecting client declared about itself in `Hello`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerDescriptor {
    /// Display name the client chose (`Hello.device_name`).
    pub device_name: String,
    /// Device identifier derived from the client's signing key, when the key
    /// was well formed.
    pub device_id: Option<DeviceId>,
}

/// Decides, once the client's access password has been verified and a codec
/// negotiated, whether the session may start. The agent runs without a gate;
/// QuickSupport plugs its remote-user consent prompt in here, so the end user
/// is only asked about technicians who already know the temporary password.
pub trait SessionGate: Send + Sync + std::fmt::Debug {
    /// Returns `Err(reason)` to reject the session; `reason` is sent to the
    /// client in the `Error` message.
    fn authorize<'a>(
        &'a self,
        peer: &'a PeerDescriptor,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>>;
}

/// Session configuration derived from CLI arguments.
#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// Machine name sent to the client in `HelloAck`.
    pub name: String,
    /// Ed25519 signing public key of this device, sent in `HelloAck`.
    pub device_public_key: [u8; 32],
    /// Access password the client must present in `Hello`.
    pub password: String,
    /// Monitor index to share (`0` is the primary monitor).
    pub monitor: u32,
    /// Video encoder selection policy.
    pub encoder: EncoderChoice,
    /// Bitrate and frame-rate cap of the video encoder.
    pub settings: EncoderSettings,
    /// Whether remote keyboard and mouse events are injected.
    pub input: bool,
    /// Consulted after the password check and before `HelloAck`; `None` admits
    /// every authenticated client.
    pub gate: Option<Arc<dyn SessionGate>>,
}

/// Shared state between the blocking capture thread and the async control task.
#[derive(Debug, Default)]
pub(crate) struct SessionState {
    pub(crate) stop: AtomicBool,
    pub(crate) keyframe_requested: AtomicBool,
    target: Mutex<Option<TargetDisplay>>,
}

impl SessionState {
    pub(crate) fn set_target(&self, target: TargetDisplay) {
        *self.target.lock().unwrap_or_else(PoisonError::into_inner) = Some(target);
    }

    fn target(&self) -> Option<TargetDisplay> {
        *self.target.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Serves a single client connection from handshake to teardown.
///
/// # Errors
///
/// Returns an error when the handshake fails (a wrong password is reported as
/// [`crate::password::Rejected`], reachable through `downcast_ref`) or the
/// session ends abnormally.
pub async fn run(connection: Connection, config: Arc<SessionConfig>) -> anyhow::Result<()> {
    let result = serve(&connection, &config).await;
    let reason: &[u8] = if result.is_ok() { b"done" } else { b"error" };
    connection.close(close_code::NORMAL.into(), reason);
    let stats = connection.stats();
    info!(
        "network: rtt {:?}, {} lost packets out of {}, {} congestion events",
        stats.path.rtt,
        stats.path.lost_packets,
        stats.path.sent_packets,
        stats.path.congestion_events,
    );
    result
}

async fn serve(connection: &Connection, config: &Arc<SessionConfig>) -> anyhow::Result<()> {
    let (mut control_send, control_recv) = connection.accept_bi().await?;
    let mut control = EnvelopeReader::new(control_recv);
    if let Err(error) = handshake(&mut control_send, &mut control, config).await {
        // Ensure the rejection reason reaches the client before closing:
        // finish the stream and give the client a brief window to read it.
        let _ = control_send.finish();
        let _ = tokio::time::timeout(REJECT_GRACE, connection.closed()).await;
        connection.close(close_code::REJECTED.into(), b"rejected");
        return Err(error);
    }

    // Dedicated unidirectional stream for video so large keyframes do not block control messages.
    let mut video_send = connection.open_uni().await?;
    let state = Arc::new(SessionState {
        keyframe_requested: AtomicBool::new(true),
        ..SessionState::default()
    });
    let (frame_tx, mut frame_rx) = mpsc::channel(VIDEO_QUEUE);

    let capture = {
        let state = state.clone();
        let config = config.clone();
        std::thread::Builder::new()
            .name("capture".into())
            .spawn(move || {
                capture_loop::run(
                    config.monitor,
                    config.encoder,
                    config.settings,
                    &frame_tx,
                    &state,
                );
            })?
    };

    let video = tokio::spawn(async move {
        while let Some(frame) = frame_rx.recv().await {
            let envelope = Envelope {
                payload: Some(Payload::VideoFrame(frame)),
            };
            if send_envelope(&mut video_send, &envelope).await.is_err() {
                break;
            }
        }
    });

    let injector = if config.input {
        match omegadesk_input::open() {
            Ok(injector) => Some(injector),
            Err(error) => {
                warn!("remote keyboard and mouse disabled: {error}");
                None
            }
        }
    } else {
        None
    };

    let result = serve_control(&mut control_send, &mut control, injector, &state).await;

    state.stop.store(true, Ordering::Relaxed);
    video.abort();
    // `join` blocks, so run it off the async runtime worker threads.
    if tokio::task::spawn_blocking(move || capture.join().is_err())
        .await
        .unwrap_or(true)
    {
        warn!("capture thread panicked");
    }
    result
}

/// Receives `Hello`, verifies the access password, negotiates a video codec, and replies with `HelloAck`.
async fn handshake(
    control_send: &mut SendStream,
    control: &mut EnvelopeReader,
    config: &SessionConfig,
) -> anyhow::Result<VideoCodec> {
    let Some(Envelope {
        payload: Some(Payload::Hello(hello)),
    }) = control.next().await?
    else {
        bail!("client did not start with Hello");
    };
    if hello.protocol_version != PROTOCOL_VERSION {
        reject(
            control_send,
            ErrorCode::UnsupportedVersion,
            "unsupported protocol version",
        )
        .await;
        bail!(
            "client uses unsupported protocol version {}",
            hello.protocol_version
        );
    }
    if !crate::password::matches(&config.password, &hello.access_password) {
        tokio::time::sleep(WRONG_PASSWORD_DELAY).await;
        reject(control_send, ErrorCode::Unauthorized, "invalid password").await;
        return Err(crate::password::Rejected.into());
    }
    let client_decoders: Vec<VideoCodec> = hello
        .capabilities
        .as_ref()
        .map(|caps| caps.decoders().collect())
        .unwrap_or_default();
    let Some(codec) = negotiate_codec(&ENCODERS, &client_decoders) else {
        reject(
            control_send,
            ErrorCode::NoCommonCodec,
            "no common video codec",
        )
        .await;
        bail!("no common video codec with client");
    };
    if let Some(gate) = &config.gate {
        let peer = PeerDescriptor {
            device_name: hello.device_name.clone(),
            device_id: <[u8; 32]>::try_from(hello.device_public_key.as_ref())
                .ok()
                .map(|key| DeviceId::from_signing_key(&key)),
        };
        if let Err(reason) = gate.authorize(&peer).await {
            reject(control_send, ErrorCode::Unauthorized, &reason).await;
            bail!("session declined: {reason}");
        }
    }
    info!(
        "client {:?} ({}) authorized, using {codec:?}",
        hello.device_name,
        describe_device(&hello.device_public_key),
    );

    send_envelope(
        control_send,
        &Envelope {
            payload: Some(Payload::HelloAck(HelloAck {
                protocol_version: PROTOCOL_VERSION,
                device_public_key: config.device_public_key.to_vec().into(),
                device_name: config.name.clone(),
                capabilities: Some(Capabilities {
                    decoders: Vec::new(),
                    encoders: ENCODERS.iter().map(|c| *c as i32).collect(),
                }),
                selected_codec: codec as i32,
            })),
        },
    )
    .await?;
    Ok(codec)
}

/// Serves the bidirectional control stream: ping/pong, keyframe requests, and input events.
async fn serve_control(
    control_send: &mut SendStream,
    control: &mut EnvelopeReader,
    mut injector: Option<Box<dyn InputInjector>>,
    state: &SessionState,
) -> anyhow::Result<()> {
    let mut target = None;
    while let Some(envelope) = control.next().await? {
        match envelope.payload {
            Some(Payload::Ping(ping)) => {
                let reply = Envelope {
                    payload: Some(Payload::Pong(Pong {
                        sequence: ping.sequence,
                        ping_sent_at_micros: ping.sent_at_micros,
                    })),
                };
                send_envelope(control_send, &reply).await?;
            }
            Some(Payload::RequestKeyframe(_) | Payload::InvalidateRefFrames(_)) => {
                state.keyframe_requested.store(true, Ordering::Relaxed);
            }
            Some(Payload::KeyEvent(key)) => {
                if let Some(injector) = injector.as_mut()
                    && let Err(error) = injector.key(&key)
                {
                    warn!("key event not injected: {error}");
                }
            }
            Some(Payload::PointerEvent(pointer)) => {
                if let Some(injector) = injector.as_mut() {
                    // The captured monitor bounds may change across reopen/mode switches.
                    let current = state.target();
                    if current != target
                        && let Some(display) = current
                    {
                        injector.set_target(display);
                        target = current;
                    }
                    if let Err(error) = injector.pointer(&pointer) {
                        warn!("pointer event not injected: {error}");
                    }
                }
            }
            Some(Payload::Error(error)) => {
                bail!("client reported error: {}", error.message);
            }
            Some(
                Payload::Hello(_)
                | Payload::HelloAck(_)
                | Payload::Pong(_)
                | Payload::FrameAck(_)
                | Payload::VideoFrame(_)
                | Payload::AudioFrame(_)
                | Payload::DisplayList(_)
                | Payload::SelectDisplay(_)
                | Payload::ClipboardEvent(_)
                | Payload::FileTransferOffer(_)
                | Payload::FileTransferChunk(_)
                | Payload::FileTransferAck(_)
                | Payload::ChatMessage(_)
                | Payload::TerminalData(_)
                | Payload::TerminalResize(_),
            )
            | None => {}
        }
    }
    Ok(())
}

async fn reject(stream: &mut SendStream, code: ErrorCode, message: &str) {
    let envelope = Envelope {
        payload: Some(Payload::Error(ProtocolError {
            code: code as i32,
            message: message.to_owned(),
        })),
    };
    let _ = send_envelope(stream, &envelope).await;
}

/// Formats the peer's `DeviceId` from its 32-byte signing public key for logging.
/// In Phase 2 the coordinator authorizes sessions using this identity.
fn describe_device(public_key: &[u8]) -> String {
    <[u8; 32]>::try_from(public_key).map_or_else(
        |_| "no identity".to_owned(),
        |key| {
            format!(
                "ID {}",
                omegadesk_identity::DeviceId::from_signing_key(&key)
            )
        },
    )
}
