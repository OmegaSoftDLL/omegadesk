//! Background QUIC session task (running on its own Tokio runtime) and
//! dedicated video decoder thread.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::mpsc as std_mpsc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, bail};
use omegadesk_codec::{OpenH264Decoder, VideoDecoder};
use omegadesk_identity::DeviceIdentity;
use omegadesk_magicsock::{Node, NodeConfig};
use omegadesk_protocol::PROTOCOL_VERSION;
use omegadesk_protocol::v1::{
    Capabilities, Envelope, Hello, Ping, RequestKeyframe, VideoCodec, VideoFrame, envelope::Payload,
};
use omegadesk_transport::{Connection, EnvelopeReader, SendStream, connect, send_envelope};
use tokio::sync::mpsc;
use tracing::{info, warn};
use winit::event_loop::EventLoopProxy;

use crate::stats::{LatestFrame, Shared};
use crate::window::UserEvent;

/// Interval between round-trip latency probes.
const PING_INTERVAL: Duration = Duration::from_millis(500);

/// Maximum encoded frames queued for the decoder. Anything beyond this adds
/// latency, so we drop and request a keyframe (Moonlight uses a 3-frame queue
/// in `pacer.cpp`).
const DECODE_QUEUE: usize = 3;

/// Minimum interval between keyframe requests to avoid flooding the agent.
const KEYFRAME_REQUEST_INTERVAL: Duration = Duration::from_millis(250);

fn unix_micros() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_micros()).unwrap_or(u64::MAX))
}

/// How the agent is reached.
#[derive(Debug, Clone)]
pub(crate) enum Route {
    /// Phase 1: direct QUIC to an address, pinning the agent's certificate.
    Lan {
        address: SocketAddr,
        fingerprint: String,
    },
    /// Phase 2: enroll in the mesh and connect to the agent by name; TLS is
    /// bound to the agent identity distributed by the coordinator.
    Mesh(Box<MeshRoute>),
}

/// Mesh enrollment parameters and the agent name to reach.
#[derive(Debug, Clone)]
pub(crate) struct MeshRoute {
    pub(crate) identity: Arc<DeviceIdentity>,
    pub(crate) node_config: NodeConfig,
    pub(crate) name: String,
}

/// Connection parameters for reaching the remote agent.
#[derive(Debug, Clone)]
pub(crate) struct Target {
    /// Ed25519 signing public key of this client device, sent in `Hello`.
    pub(crate) device_public_key: [u8; 32],
    pub(crate) route: Route,
    pub(crate) password: String,
}

/// Spawns the background network thread and returns the channel used to send
/// control messages (keyboard, pointer, keyframe requests) to the agent.
pub(crate) fn start(
    target: Target,
    shared: Shared,
    proxy: EventLoopProxy<UserEvent>,
) -> mpsc::UnboundedSender<Envelope> {
    let (control_tx, control_rx) = mpsc::unbounded_channel();
    let requests = control_tx.clone();
    std::thread::spawn(move || {
        let runtime = match tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
        {
            Ok(runtime) => runtime,
            Err(error) => {
                shared.set_status(format!("error: {error}"));
                let _ = proxy.send_event(UserEvent::Disconnected);
                return;
            }
        };
        let result = runtime.block_on(run(
            target,
            shared.clone(),
            proxy.clone(),
            control_rx,
            requests,
        ));
        let status = match result {
            Ok(()) => "disconnected".to_owned(),
            Err(error) => format!("error: {error:#}"),
        };
        warn!("{status}");
        shared.set_status(status);
        let _ = proxy.send_event(UserEvent::Disconnected);
    });
    control_tx
}

async fn run(
    target: Target,
    shared: Shared,
    proxy: EventLoopProxy<UserEvent>,
    mut control_rx: mpsc::UnboundedReceiver<Envelope>,
    requests: mpsc::UnboundedSender<Envelope>,
) -> anyhow::Result<()> {
    // Keeps the LAN endpoint or the mesh node alive for the whole session.
    let (_endpoint, mesh_node, connection) = match &target.route {
        Route::Lan {
            address,
            fingerprint,
        } => {
            shared.set_status(format!("connecting to {address}…"));
            let _ = proxy.send_event(UserEvent::Status);
            let (endpoint, connection) = connect(*address, fingerprint)
                .await
                .context("failed to connect to agent")?;
            (Some(endpoint), None, connection)
        }
        Route::Mesh(mesh) => {
            let MeshRoute {
                identity,
                node_config,
                name,
            } = mesh.as_ref();
            shared.set_status("joining the mesh…".to_owned());
            let _ = proxy.send_event(UserEvent::Status);
            let node = Node::start(Arc::clone(identity), node_config.clone())
                .await
                .context("failed to join the mesh")?;
            info!(
                "enrolled as {} ({})",
                node.self_info().fqdn,
                node.self_info().ipv4
            );
            shared.set_status(format!("connecting to {name}…"));
            let _ = proxy.send_event(UserEvent::Status);
            let connection = wait_and_connect(&node, name)
                .await
                .with_context(|| format!("failed to connect to {name} through the mesh"))?;
            if let Some(peer) = node.peer_at(connection.remote_address()) {
                info!(
                    "mesh path to {}: {:?}",
                    peer.fqdn,
                    node.peer_path(peer.id())
                );
            }
            (None, Some(node), connection)
        }
    };

    let result = session(
        &connection,
        &target,
        &shared,
        &proxy,
        &mut control_rx,
        requests,
    )
    .await;
    connection.close(0u32.into(), b"done");
    log_connection(&connection);
    if let Some(node) = &mesh_node
        && let Some(peer) = node.peer_at(connection.remote_address())
    {
        info!(
            "mesh path to {} at the end: {:?}",
            peer.fqdn,
            node.peer_path(peer.id())
        );
    }
    drop(mesh_node);
    result
}

/// Waits (bounded) for the agent to appear in the netmap, then connects. The
/// netmap snapshot arrives with the enrollment, but an agent that enrolls a
/// moment later is only announced by a delta.
async fn wait_and_connect(node: &Node, name: &str) -> anyhow::Result<Connection> {
    let deadline = Instant::now() + Duration::from_secs(15);
    while node.resolve(name).is_none() {
        if Instant::now() >= deadline {
            bail!("no agent named `{name}` is enrolled in this tenant");
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    Ok(node.connect(name).await?)
}

/// Logs the connection close reason and final QUIC path statistics.
fn log_connection(connection: &Connection) {
    if let Some(reason) = connection.close_reason() {
        info!("connection closed: {reason}");
    }
    let stats = connection.stats();
    info!(
        "network: rtt {:?}, {} lost packets out of {}, {} congestion events, MTU {}",
        stats.path.rtt,
        stats.path.lost_packets,
        stats.path.sent_packets,
        stats.path.congestion_events,
        stats.path.current_mtu,
    );
}

async fn session(
    connection: &Connection,
    target: &Target,
    shared: &Shared,
    proxy: &EventLoopProxy<UserEvent>,
    control_rx: &mut mpsc::UnboundedReceiver<Envelope>,
    requests: mpsc::UnboundedSender<Envelope>,
) -> anyhow::Result<()> {
    let (mut control_send, control_recv) = connection.open_bi().await?;
    let mut control = EnvelopeReader::new(control_recv);
    send_envelope(
        &mut control_send,
        &Envelope {
            payload: Some(Payload::Hello(Hello {
                protocol_version: PROTOCOL_VERSION,
                device_public_key: target.device_public_key.to_vec().into(),
                device_name: "omegadesk-client".to_owned(),
                capabilities: Some(Capabilities {
                    decoders: vec![VideoCodec::H264 as i32],
                    encoders: Vec::new(),
                }),
                access_password: target.password.clone(),
            })),
        },
    )
    .await?;

    let ack = match control.next().await? {
        Some(Envelope {
            payload: Some(Payload::HelloAck(ack)),
        }) => ack,
        Some(Envelope {
            payload: Some(Payload::Error(error)),
        }) => bail!("agent rejected session: {}", error.message),
        _ => bail!("unexpected response from agent"),
    };
    let agent_id = <[u8; 32]>::try_from(ack.device_public_key.as_ref()).map_or_else(
        |_| "no identity".to_owned(),
        |key| omegadesk_identity::DeviceId::from_signing_key(&key).to_string(),
    );
    info!("connected to {:?} (ID {agent_id})", ack.device_name);
    shared.set_status(format!("connected to {}", ack.device_name));
    let _ = proxy.send_event(UserEvent::Status);

    let video_recv = connection.accept_uni().await?;
    let decoder = Decoder::spawn(shared.clone(), proxy.clone(), requests);

    let video = tokio::spawn(async move {
        let mut reader = EnvelopeReader::new(video_recv);
        loop {
            match reader.next().await {
                Ok(Some(envelope)) => {
                    if let Some(Payload::VideoFrame(frame)) = envelope.payload
                        && !decoder.submit(frame)
                    {
                        warn!("decoder stopped; ending video stream");
                        break;
                    }
                }
                Ok(None) => {
                    warn!("agent closed the video stream");
                    break;
                }
                Err(error) => {
                    warn!("video stream error: {error}");
                    break;
                }
            }
        }
    });

    let control_task = control_loop(&mut control_send, &mut control, control_rx, shared);
    tokio::select! {
        result = control_task => result,
        _ = video => Ok(()),
    }
}

/// Sends periodic pings and outgoing control messages, and processes incoming pongs.
async fn control_loop(
    send: &mut SendStream,
    control: &mut EnvelopeReader,
    control_rx: &mut mpsc::UnboundedReceiver<Envelope>,
    shared: &Shared,
) -> anyhow::Result<()> {
    let started = Instant::now();
    let mut ticker = tokio::time::interval(PING_INTERVAL);
    let mut sequence = 0u64;
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                sequence += 1;
                let ping = Envelope {
                    payload: Some(Payload::Ping(Ping {
                        sequence,
                        sent_at_micros: u64::try_from(started.elapsed().as_micros())
                            .unwrap_or(u64::MAX),
                    })),
                };
                send_envelope(send, &ping).await?;
            }
            event = control_rx.recv() => {
                let Some(event) = event else { return Ok(()) };
                send_envelope(send, &event).await?;
            }
            envelope = control.next() => {
                match envelope? {
                    Some(Envelope { payload: Some(Payload::Pong(pong)) }) => {
                        let now = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
                        shared.set_rtt(Duration::from_micros(
                            now.saturating_sub(pong.ping_sent_at_micros),
                        ));
                    }
                    Some(_) => {}
                    None => return Ok(()),
                }
            }
        }
    }
}

/// Bounded queue feeding the dedicated decoder thread.
struct Decoder {
    queue: std_mpsc::SyncSender<VideoFrame>,
    requests: mpsc::UnboundedSender<Envelope>,
}

impl Decoder {
    fn spawn(
        shared: Shared,
        proxy: EventLoopProxy<UserEvent>,
        requests: mpsc::UnboundedSender<Envelope>,
    ) -> Self {
        let (queue, rx) = std_mpsc::sync_channel::<VideoFrame>(DECODE_QUEUE);
        let thread_requests = requests.clone();
        std::thread::spawn(move || decode_loop(&rx, &shared, &proxy, &thread_requests));
        Self { queue, requests }
    }

    /// Submits a frame to the decoder. If the queue is full, drops the frame
    /// and requests a keyframe. Returns `false` if the decoder thread exited.
    fn submit(&self, frame: VideoFrame) -> bool {
        match self.queue.try_send(frame) {
            Ok(()) => true,
            Err(std_mpsc::TrySendError::Full(_)) => {
                // The decoder will skip P-frames until the requested keyframe arrives.
                let _ = self.requests.send(keyframe_request());
                true
            }
            Err(std_mpsc::TrySendError::Disconnected(_)) => false,
        }
    }
}

fn keyframe_request() -> Envelope {
    Envelope {
        payload: Some(Payload::RequestKeyframe(RequestKeyframe {})),
    }
}

/// Decodes frames and publishes only the latest image. While waiting for a
/// valid keyframe (at startup, after a sequence gap, or after a decode error),
/// skips P-frames and requests a fresh keyframe, matching Moonlight
/// (`ffmpeg.cpp`) and RustDesk (`refresh_video`).
fn decode_loop(
    rx: &std_mpsc::Receiver<VideoFrame>,
    shared: &Shared,
    proxy: &EventLoopProxy<UserEvent>,
    requests: &mpsc::UnboundedSender<Envelope>,
) {
    let mut decoder = match OpenH264Decoder::new() {
        Ok(decoder) => decoder,
        Err(error) => {
            shared.set_status(format!("decoder unavailable: {error}"));
            return;
        }
    };
    let mut expected_sequence: Option<u64> = None;
    let mut waiting_keyframe = true;
    let mut last_request: Option<Instant> = None;
    let mut request_keyframe = |reason: &str| {
        if last_request.is_none_or(|at| at.elapsed() >= KEYFRAME_REQUEST_INTERVAL) {
            info!("requesting keyframe: {reason}");
            let _ = requests.send(keyframe_request());
            last_request = Some(Instant::now());
        }
    };
    let mut logged_clock_skew = false;

    while let Ok(frame) = rx.recv() {
        // Sequence gap: at least one frame was dropped in transit or in the queue.
        if expected_sequence.is_some_and(|expected| frame.sequence != expected) && !frame.keyframe {
            waiting_keyframe = true;
        }
        expected_sequence = Some(frame.sequence + 1);
        if frame.keyframe {
            waiting_keyframe = false;
        } else if waiting_keyframe {
            request_keyframe("waiting for keyframe");
            continue;
        }

        let start = Instant::now();
        match decoder.decode(&frame.data) {
            Ok(Some(image)) => {
                shared.publish(LatestFrame {
                    image,
                    host_processing: Duration::from_micros(u64::from(frame.host_processing_micros)),
                    decode: start.elapsed(),
                    decoded_at: Instant::now(),
                });
                if proxy.send_event(UserEvent::Frame).is_err() {
                    break;
                }
            }
            Ok(None) => {}
            Err(error) => {
                warn!("frame {} failed to decode: {error}", frame.sequence);
                waiting_keyframe = true;
                request_keyframe("decode error");
            }
        }
        if !logged_clock_skew {
            let skew = unix_micros().abs_diff(frame.captured_at_micros);
            info!("host/client clock offset + network: {} ms", skew / 1000);
            logged_clock_skew = true;
        }
    }
}
