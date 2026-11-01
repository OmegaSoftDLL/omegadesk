//! Browser session proxy: one `WebSocket` towards the browser, one QUIC session
//! towards the agent, and the gateway in between speaking both dialects.
//!
//! The shape is Guacamole's tunnel model
//! (`apache_guacamole-client/guacamole-common/src/main/java/org/apache/guacamole/websocket/GuacamoleWebSocketTunnelEndpoint.java`,
//! Apache-2.0): the endpoint opens the backend connection when the socket opens, a
//! reader task forwards backend output to the socket, socket messages are written
//! to the backend, and closing either side closes the other. MeshCentral's
//! `meshrelay.js` (Apache-2.0) relays the same way between a browser `WebSocket`
//! and the agent connection, authorizing the target device before the first byte
//! flows. Here the backend is the agent's real session protocol
//! (`crates/protocol/proto/omegadesk/v1/session.proto`): the gateway sends `Hello`
//! with the password typed in the browser, waits for `HelloAck`, forwards the video
//! unidirectional stream as [`crate::web_gateway::WEB_VIDEO_PROTOCOL`] frames and relays keyboard,
//! pointer and keyframe requests on the control bidirectional stream, exactly like
//! `client/src/network.rs` does for the native client.
//!
//! Backpressure is Selkies' per-frame ACK gate (`websockets_mode.py`
//! `_run_frame_backpressure_logic`): delta frames are dropped while the oldest
//! unacknowledged frame is older than the smoothed RTT plus the allowed desync, and a
//! dropped or gapped frame makes the gateway request an IDR from the agent and skip
//! deltas until it arrives (the native client does the same in `decode_loop`).

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use axum::extract::ws::{Message, WebSocket};
use bytes::Bytes;
use futures_util::stream::SplitSink;
use futures_util::{SinkExt, StreamExt};
use omegadesk_magicsock::{Node, NodeError};
use omegadesk_protocol::PROTOCOL_VERSION;
use omegadesk_protocol::v1::{
    Capabilities, Envelope, Hello, Ping, RequestKeyframe, VideoCodec, VideoFrame, envelope::Payload,
};
use omegadesk_transport::{Connection, EnvelopeReader, SendStream, send_envelope};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::web_gateway::{
    FrameBackpressureGate, MAX_WEBSOCKET_CLIENT_PAYLOAD_LEN, WebClientMessage, WebGatewayError,
    WebServerMessage, key_event_from_browser, pack_web_video_frame, parse_web_frame_ack,
    pointer_event_from_browser, web_codec_string,
};

/// How long the browser has to send its `connect` message after the upgrade.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Bound on reaching the agent over the mesh (netmap wait plus QUIC handshake).
pub const AGENT_DIAL_TIMEOUT: Duration = Duration::from_secs(20);

/// Bound on the `Hello` / `HelloAck` exchange.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// A browser that sends nothing (not even its 1 s ping) for this long is dropped
/// (`WEB_SOCKET_IDLE_TIMEOUT` in SubnetDesk `web_gateway.rs`).
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Interval between gateway-to-agent latency probes (`client/src/network.rs`).
pub const PING_INTERVAL: Duration = Duration::from_millis(500);

/// Interval between `stats` messages to the browser.
pub const STATS_INTERVAL: Duration = Duration::from_secs(1);

/// Minimum interval between keyframe requests forwarded to the agent
/// (`KEYFRAME_REQUEST_INTERVAL` in `client/src/network.rs`).
pub const KEYFRAME_REQUEST_INTERVAL: Duration = Duration::from_millis(250);

/// While the browser is stalled (no ACK for [`crate::web_gateway::STALLED_CLIENT_TIMEOUT`]) it is sent no
/// delta frames and the agent is asked for one probe IDR at most this often
/// (Selkies `STALLED_CLIENT_REPROBE_SECONDS`).
pub const STALLED_REPROBE_INTERVAL: Duration = Duration::from_secs(2);

/// Encoded frames queued between the QUIC reader and the `WebSocket` writer. Anything
/// beyond this is latency, so the reader drops and the gateway asks for a keyframe.
pub const VIDEO_QUEUE: usize = 4;

/// How long a dialer waits for a freshly enrolled agent to show up in the netmap.
pub const NETMAP_WAIT: Duration = Duration::from_secs(5);

/// Errors reaching an agent.
#[derive(Debug, thiserror::Error)]
pub enum DialError {
    /// The name is not in this tenant's netmap.
    #[error("no agent named `{0}` is enrolled in this tenant")]
    UnknownAgent(String),
    /// The agent is known but the QUIC connection did not come up within
    /// [`AGENT_DIAL_TIMEOUT`].
    #[error("connecting to `{0}` timed out")]
    Timeout(String),
    /// The mesh connection failed.
    #[error(transparent)]
    Node(#[from] NodeError),
}

/// Opens QUIC sessions to agents by name. The production implementation is
/// [`MeshDialer`]; tests may substitute any transport that yields a
/// [`Connection`] speaking the session protocol.
pub trait AgentDialer: Send + Sync {
    /// Connects to the agent called `name` (`office-pc` or `office-pc.omega`).
    fn dial<'a>(
        &'a self,
        name: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Connection, DialError>> + Send + 'a>>;
}

/// Reaches agents through the gateway's own mesh [`Node`].
pub struct MeshDialer {
    node: Arc<Node>,
    netmap_wait: Duration,
}

impl MeshDialer {
    /// Dials through `node`, waiting up to [`NETMAP_WAIT`] for unknown names to be
    /// announced by a netmap delta.
    #[must_use]
    pub fn new(node: Arc<Node>) -> Self {
        Self {
            node,
            netmap_wait: NETMAP_WAIT,
        }
    }

    /// Overrides the netmap wait (tests).
    #[must_use]
    pub fn with_netmap_wait(mut self, wait: Duration) -> Self {
        self.netmap_wait = wait;
        self
    }
}

impl std::fmt::Debug for MeshDialer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MeshDialer")
            .field("node", &self.node)
            .finish_non_exhaustive()
    }
}

impl AgentDialer for MeshDialer {
    fn dial<'a>(
        &'a self,
        name: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Connection, DialError>> + Send + 'a>> {
        Box::pin(async move {
            let deadline = Instant::now() + self.netmap_wait;
            while self.node.resolve(name).is_none() {
                if Instant::now() >= deadline {
                    return Err(DialError::UnknownAgent(name.to_owned()));
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Ok(self.node.connect(name).await?)
        })
    }
}

/// What the gateway says about itself in `Hello`.
#[derive(Debug, Clone)]
pub struct GatewayIdentity {
    /// Ed25519 signing public key of the gateway node.
    pub device_public_key: [u8; 32],
    /// Device name shown by the agent in its log.
    pub device_name: String,
}

/// Why a browser session ended.
#[derive(Debug, thiserror::Error)]
pub enum WebSessionError {
    /// The browser closed or misbehaved before the handshake finished.
    #[error("browser disconnected before connecting to an agent")]
    BrowserGone,
    /// The browser took too long to send `connect`, or went silent.
    #[error("browser timed out")]
    BrowserTimeout,
    /// The browser sent an invalid frame.
    #[error(transparent)]
    Protocol(#[from] WebGatewayError),
    /// The agent could not be reached.
    #[error(transparent)]
    Dial(#[from] DialError),
    /// The agent refused or dropped the session.
    #[error("agent: {0}")]
    Agent(String),
    /// A QUIC stream failed.
    #[error(transparent)]
    Transport(#[from] omegadesk_transport::TransportError),
    /// The `WebSocket` failed.
    #[error("websocket: {0}")]
    WebSocket(#[from] axum::Error),
}

type WsSink = SplitSink<WebSocket, Message>;

/// Serves one browser session from the `WebSocket` upgrade to teardown.
///
/// # Errors
///
/// Returns the reason the session ended; the browser has already been told with a
/// [`WebServerMessage::Error`] whenever the socket was still usable.
pub async fn run_web_session(
    socket: WebSocket,
    dialer: Arc<dyn AgentDialer>,
    identity: Arc<GatewayIdentity>,
    remote: SocketAddr,
) -> Result<(), WebSessionError> {
    let (mut ws_tx, mut ws_rx) = socket.split();
    let result = serve(&mut ws_tx, &mut ws_rx, dialer, identity, remote).await;
    if let Err(error) = &result {
        let message = match error {
            WebSessionError::BrowserGone | WebSessionError::WebSocket(_) => None,
            other @ (WebSessionError::BrowserTimeout
            | WebSessionError::Protocol(_)
            | WebSessionError::Dial(_)
            | WebSessionError::Agent(_)
            | WebSessionError::Transport(_)) => Some(other.to_string()),
        };
        if let Some(message) = message {
            let _ = ws_tx
                .send(Message::Text(
                    WebServerMessage::Error { message }.to_json().into(),
                ))
                .await;
        }
    }
    let _ = ws_tx.send(Message::Close(None)).await;
    result
}

async fn serve(
    ws_tx: &mut WsSink,
    ws_rx: &mut futures_util::stream::SplitStream<WebSocket>,
    dialer: Arc<dyn AgentDialer>,
    identity: Arc<GatewayIdentity>,
    remote: SocketAddr,
) -> Result<(), WebSessionError> {
    let (agent, password) = await_connect(ws_rx).await?;
    info!(%remote, %agent, "browser requests a session");

    let connection = tokio::time::timeout(AGENT_DIAL_TIMEOUT, dialer.dial(&agent))
        .await
        .map_err(|_| DialError::Timeout(agent.clone()))??;
    let result = proxy(ws_tx, ws_rx, &connection, &identity, &password, remote).await;
    connection.close(0u32.into(), b"done");
    let stats = connection.stats();
    info!(
        %remote,
        rtt = ?stats.path.rtt,
        lost = stats.path.lost_packets,
        sent = stats.path.sent_packets,
        "browser session ended"
    );
    result
}

/// Waits for the browser's `connect` message; every other message before it is a
/// protocol error.
async fn await_connect(
    ws_rx: &mut futures_util::stream::SplitStream<WebSocket>,
) -> Result<(String, String), WebSessionError> {
    let deadline = tokio::time::sleep(CONNECT_TIMEOUT);
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            () = &mut deadline => return Err(WebSessionError::BrowserTimeout),
            incoming = ws_rx.next() => match incoming {
                Some(Ok(Message::Text(text))) => {
                    match WebClientMessage::parse(text.as_str())? {
                        WebClientMessage::Connect { agent, password } => {
                            return Ok((agent, password));
                        }
                        WebClientMessage::Ping { .. } => {}
                        WebClientMessage::Key { .. }
                        | WebClientMessage::Pointer { .. }
                        | WebClientMessage::RequestKeyframe { .. } => {
                            return Err(WebGatewayError::InvalidControlMessage(
                                "expected connect".to_owned(),
                            )
                            .into());
                        }
                    }
                }
                Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
                Some(Ok(Message::Binary(_))) => {
                    return Err(WebGatewayError::InvalidControlMessage(
                        "binary frame before connect".to_owned(),
                    )
                    .into());
                }
                Some(Ok(Message::Close(_))) | None => return Err(WebSessionError::BrowserGone),
                Some(Err(error)) => return Err(error.into()),
            },
        }
    }
}

/// Per-session forwarding state.
struct Relay {
    gate: FrameBackpressureGate,
    next_frame_id: u16,
    waiting_keyframe: bool,
    expected_sequence: Option<u64>,
    last_keyframe_request: Option<Instant>,
    video_config: Option<(u32, u32)>,
    codec_string: &'static str,
    agent_rtt_ms: u64,
    host_processing_ms: u32,
    frames_sent: u64,
    frames_dropped: Arc<AtomicU64>,
    gap: Arc<AtomicBool>,
    ping_started: Instant,
    ping_sequence: u64,
}

impl Relay {
    fn stats(&self) -> WebServerMessage {
        WebServerMessage::Stats {
            agent_rtt_ms: self.agent_rtt_ms,
            browser_rtt_ms: self.gate.smoothed_rtt_ms(),
            host_processing_ms: self.host_processing_ms,
            frames_sent: self.frames_sent,
            frames_dropped: self.frames_dropped.load(Ordering::Relaxed),
            in_flight: self.gate.in_flight_len(),
        }
    }

    fn drop_frame(&self) {
        self.frames_dropped.fetch_add(1, Ordering::Relaxed);
    }

    /// Whether a keyframe request may go to the agent now (rate limited to `interval`).
    fn keyframe_request_due(&mut self, now: Instant, interval: Duration) -> bool {
        if self
            .last_keyframe_request
            .is_none_or(|at| now.saturating_duration_since(at) >= interval)
        {
            self.last_keyframe_request = Some(now);
            true
        } else {
            false
        }
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "one select loop owns every side of the relay"
)]
async fn proxy(
    ws_tx: &mut WsSink,
    ws_rx: &mut futures_util::stream::SplitStream<WebSocket>,
    connection: &Connection,
    identity: &GatewayIdentity,
    password: &str,
    remote: SocketAddr,
) -> Result<(), WebSessionError> {
    let (mut control_send, control_recv) = connection
        .open_bi()
        .await
        .map_err(omegadesk_transport::TransportError::from)?;
    let mut control = EnvelopeReader::new(control_recv);
    let ack = tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        handshake(&mut control_send, &mut control, identity, password, remote),
    )
    .await
    .map_err(|_| WebSessionError::Agent("handshake timed out".to_owned()))??;

    let codec = VideoCodec::try_from(ack.selected_codec).unwrap_or(VideoCodec::Unspecified);
    let Some(codec_string) = web_codec_string(codec) else {
        return Err(WebSessionError::Agent(format!(
            "agent selected {codec:?}, which the browser cannot decode"
        )));
    };
    let device_id = <[u8; 32]>::try_from(ack.device_public_key.as_ref()).map_or_else(
        |_| "no identity".to_owned(),
        |key| omegadesk_identity::DeviceId::from_signing_key(&key).to_string(),
    );
    info!(%remote, agent = %ack.device_name, %device_id, ?codec, "browser session established");
    send_text(
        ws_tx,
        &WebServerMessage::Connected {
            agent: ack.device_name.clone(),
            device_id,
        },
    )
    .await?;

    let video_recv = connection
        .accept_uni()
        .await
        .map_err(omegadesk_transport::TransportError::from)?;
    let frames_dropped = Arc::new(AtomicU64::new(0));
    let gap = Arc::new(AtomicBool::new(false));
    let (video_tx, mut video_rx) = mpsc::channel::<VideoFrame>(VIDEO_QUEUE);
    let reader = tokio::spawn(read_video(
        video_recv,
        video_tx,
        Arc::clone(&frames_dropped),
        Arc::clone(&gap),
    ));

    let mut relay = Relay {
        gate: FrameBackpressureGate::new(),
        next_frame_id: 0,
        waiting_keyframe: true,
        expected_sequence: None,
        last_keyframe_request: None,
        video_config: None,
        codec_string,
        agent_rtt_ms: 0,
        host_processing_ms: 0,
        frames_sent: 0,
        frames_dropped,
        gap,
        ping_started: Instant::now(),
        ping_sequence: 0,
    };

    let mut ping_ticker = tokio::time::interval(PING_INTERVAL);
    let mut stats_ticker = tokio::time::interval(STATS_INTERVAL);
    let idle = tokio::time::sleep(IDLE_TIMEOUT);
    tokio::pin!(idle);

    let result = loop {
        tokio::select! {
            () = &mut idle => break Err(WebSessionError::BrowserTimeout),
            _ = ping_ticker.tick() => {
                relay.ping_sequence += 1;
                let ping = Envelope {
                    payload: Some(Payload::Ping(Ping {
                        sequence: relay.ping_sequence,
                        sent_at_micros: elapsed_micros(relay.ping_started),
                    })),
                };
                if let Err(error) = send_envelope(&mut control_send, &ping).await {
                    break Err(error.into());
                }
            }
            _ = stats_ticker.tick() => {
                if let Err(error) = send_text(ws_tx, &relay.stats()).await {
                    break Err(error);
                }
            }
            frame = video_rx.recv() => {
                let Some(frame) = frame else {
                    break Err(WebSessionError::Agent("video stream closed".to_owned()));
                };
                if let Err(error) = forward_frame(ws_tx, &mut control_send, &mut relay, frame).await {
                    break Err(error);
                }
            }
            envelope = control.next() => match envelope {
                Ok(Some(Envelope { payload: Some(Payload::Pong(pong)) })) => {
                    let now = elapsed_micros(relay.ping_started);
                    let sample_ms = now.saturating_sub(pong.ping_sent_at_micros) / 1000;
                    relay.agent_rtt_ms = if relay.agent_rtt_ms == 0 {
                        sample_ms
                    } else {
                        (relay.agent_rtt_ms * 7 + sample_ms) / 8
                    };
                }
                Ok(Some(Envelope { payload: Some(Payload::Error(error)) })) => {
                    break Err(WebSessionError::Agent(error.message));
                }
                Ok(Some(_)) => {}
                Ok(None) => break Err(WebSessionError::Agent("control stream closed".to_owned())),
                Err(error) => break Err(error.into()),
            },
            incoming = ws_rx.next() => {
                idle.as_mut().reset(tokio::time::Instant::now() + IDLE_TIMEOUT);
                match incoming {
                    Some(Ok(message)) => {
                        if let Err(error) = handle_browser_message(ws_tx, &mut control_send, &mut relay, message).await {
                            break Err(error);
                        }
                    }
                    Some(Err(error)) => break Err(error.into()),
                    None => break Ok(()),
                }
            }
        }
    };
    reader.abort();
    match result {
        // A browser that closes its socket is a normal end of session.
        Ok(()) | Err(WebSessionError::BrowserGone) => Ok(()),
        Err(error) => Err(error),
    }
}

/// Sends `Hello` and waits for `HelloAck`, surfacing the agent's rejection message.
async fn handshake(
    control_send: &mut SendStream,
    control: &mut EnvelopeReader,
    identity: &GatewayIdentity,
    password: &str,
    remote: SocketAddr,
) -> Result<omegadesk_protocol::v1::HelloAck, WebSessionError> {
    send_envelope(
        control_send,
        &Envelope {
            payload: Some(Payload::Hello(Hello {
                protocol_version: PROTOCOL_VERSION,
                device_public_key: identity.device_public_key.to_vec().into(),
                device_name: format!("{} ({})", identity.device_name, remote.ip()),
                capabilities: Some(Capabilities {
                    decoders: vec![VideoCodec::H264 as i32],
                    encoders: Vec::new(),
                }),
                access_password: password.to_owned(),
                // The gateway cannot attest the browser's OS, so it reports no
                // posture: a policy that requires one fails the session closed
                // (per-connection MFA for browser sessions lands with Phase 4).
                posture: None,
            })),
        },
    )
    .await?;
    match control.next().await? {
        Some(Envelope {
            payload: Some(Payload::HelloAck(ack)),
        }) => Ok(ack),
        Some(Envelope {
            payload: Some(Payload::Error(error)),
        }) => Err(WebSessionError::Agent(error.message)),
        Some(_) => Err(WebSessionError::Agent(
            "unexpected response to Hello".to_owned(),
        )),
        None => Err(WebSessionError::Agent(
            "agent closed the control stream".to_owned(),
        )),
    }
}

/// Reads `VideoFrame` envelopes from the agent and queues them for the browser.
/// When the browser side is behind, the frame is dropped here (never buffered) and
/// `gap` tells the relay to wait for the next keyframe.
async fn read_video(
    stream: omegadesk_transport::RecvStream,
    video_tx: mpsc::Sender<VideoFrame>,
    frames_dropped: Arc<AtomicU64>,
    gap: Arc<AtomicBool>,
) {
    let mut reader = EnvelopeReader::new(stream);
    loop {
        match reader.next().await {
            Ok(Some(Envelope {
                payload: Some(Payload::VideoFrame(frame)),
            })) => match video_tx.try_send(frame) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Full(_)) => {
                    frames_dropped.fetch_add(1, Ordering::Relaxed);
                    gap.store(true, Ordering::Relaxed);
                }
                Err(mpsc::error::TrySendError::Closed(_)) => return,
            },
            Ok(Some(_)) => {}
            Ok(None) => {
                debug!("agent finished the video stream");
                return;
            }
            Err(error) => {
                warn!("video stream error: {error}");
                return;
            }
        }
    }
}

/// Applies the keyframe gate and backpressure to one frame and forwards it.
async fn forward_frame(
    ws_tx: &mut WsSink,
    control_send: &mut SendStream,
    relay: &mut Relay,
    frame: VideoFrame,
) -> Result<(), WebSessionError> {
    let now = Instant::now();
    if relay.gap.swap(false, Ordering::Relaxed) {
        relay.waiting_keyframe = true;
    }
    if relay
        .expected_sequence
        .is_some_and(|expected| frame.sequence != expected)
        && !frame.keyframe
    {
        relay.waiting_keyframe = true;
    }
    relay.expected_sequence = Some(frame.sequence.wrapping_add(1));

    let stalled = relay.gate.is_client_stalled(now);
    if frame.keyframe {
        relay.waiting_keyframe = false;
        if stalled {
            // Selkies re-probes a stalled client with one IDR and times the stall from
            // that send; a client that is still gone trips it again, a returned one ACKs.
            relay.gate.record_probe_sent(now);
        }
    } else {
        let reason = if stalled {
            Some(("browser stalled", STALLED_REPROBE_INTERVAL))
        } else if relay.waiting_keyframe {
            Some(("waiting for keyframe", KEYFRAME_REQUEST_INTERVAL))
        } else if relay.gate.should_drop_delta_frame(now) {
            Some(("browser decode backlog", KEYFRAME_REQUEST_INTERVAL))
        } else {
            None
        };
        if let Some((reason, interval)) = reason {
            relay.drop_frame();
            relay.waiting_keyframe = true;
            if relay.keyframe_request_due(now, interval) {
                debug!("requesting keyframe: {reason}");
                send_envelope(control_send, &keyframe_request()).await?;
            }
            return Ok(());
        }
    }

    let dims = (frame.width, frame.height);
    if relay.video_config != Some(dims) {
        relay.video_config = Some(dims);
        send_text(
            ws_tx,
            &WebServerMessage::VideoConfig {
                codec: relay.codec_string.to_owned(),
                width: frame.width,
                height: frame.height,
            },
        )
        .await?;
    }

    let frame_id = relay.next_frame_id;
    relay.next_frame_id = relay.next_frame_id.wrapping_add(1);
    let packet = pack_web_video_frame(
        frame_id,
        frame.keyframe,
        frame.captured_at_micros,
        &frame.data,
    );
    ws_tx.send(Message::Binary(Bytes::from(packet))).await?;
    relay.gate.record_frame_sent(frame_id, now);
    relay.frames_sent += 1;
    relay.host_processing_ms = frame.host_processing_micros / 1000;
    Ok(())
}

/// Handles one `WebSocket` message from the browser after the handshake.
async fn handle_browser_message(
    ws_tx: &mut WsSink,
    control_send: &mut SendStream,
    relay: &mut Relay,
    message: Message,
) -> Result<(), WebSessionError> {
    match message {
        Message::Binary(bytes) => {
            if bytes.len() > MAX_WEBSOCKET_CLIENT_PAYLOAD_LEN {
                return Err(WebGatewayError::InvalidPayloadLength(bytes.len()).into());
            }
            let ack = parse_web_frame_ack(&bytes)?;
            relay.gate.record_frame_ack(ack.frame_id, Instant::now());
            Ok(())
        }
        Message::Text(text) => match WebClientMessage::parse(text.as_str())? {
            WebClientMessage::Connect { .. } => {
                Err(WebGatewayError::InvalidControlMessage("already connected".to_owned()).into())
            }
            WebClientMessage::Key {
                code,
                key,
                pressed,
                modifiers,
            } => {
                if let Some(event) = key_event_from_browser(&code, &key, pressed, modifiers) {
                    send_envelope(
                        control_send,
                        &Envelope {
                            payload: Some(Payload::KeyEvent(event)),
                        },
                    )
                    .await?;
                }
                Ok(())
            }
            WebClientMessage::Pointer {
                x,
                y,
                buttons,
                wheel_x,
                wheel_y,
            } => {
                let event = pointer_event_from_browser(x, y, buttons, wheel_x, wheel_y);
                send_envelope(
                    control_send,
                    &Envelope {
                        payload: Some(Payload::PointerEvent(event)),
                    },
                )
                .await?;
                Ok(())
            }
            WebClientMessage::RequestKeyframe { reason } => {
                let now = Instant::now();
                relay.waiting_keyframe = true;
                if relay.keyframe_request_due(now, KEYFRAME_REQUEST_INTERVAL) {
                    debug!("browser requests keyframe: {reason}");
                    send_envelope(control_send, &keyframe_request()).await?;
                }
                Ok(())
            }
            WebClientMessage::Ping { sent_at_ms } => {
                send_text(ws_tx, &WebServerMessage::Pong { sent_at_ms }).await
            }
        },
        Message::Ping(_) | Message::Pong(_) => Ok(()),
        Message::Close(_) => Err(WebSessionError::BrowserGone),
    }
}

async fn send_text(ws_tx: &mut WsSink, message: &WebServerMessage) -> Result<(), WebSessionError> {
    ws_tx
        .send(Message::Text(message.to_json().into()))
        .await
        .map_err(WebSessionError::from)
}

fn keyframe_request() -> Envelope {
    Envelope {
        payload: Some(Payload::RequestKeyframe(RequestKeyframe {})),
    }
}

fn elapsed_micros(since: Instant) -> u64 {
    u64::try_from(since.elapsed().as_micros()).unwrap_or(u64::MAX)
}
