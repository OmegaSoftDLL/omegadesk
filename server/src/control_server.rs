//! Noise `IK` control-plane server: one long-lived connection per node carrying
//! enrollment, relay tickets, endpoint updates and the batched netmap stream
//! (Headscale `/machine/map` long-poll model, Tailscale `tailcfg` semantics).
//!
//! Lives in the library so integration tests can run a coordinator in-process.
//!
//! Robustness rules (each one closes a review finding on PR #35):
//! - every outbound message fits one Noise frame: snapshots and batches are
//!   split into chunks of at most [`MAX_NODES_PER_MESSAGE`] nodes;
//! - a stalled writer (node that stops reading) is cut after [`WRITE_TIMEOUT`];
//! - the reader, the writer and the netmap forwarder are supervised together:
//!   when any of them ends, the session is torn down;
//! - sessions carry the coordinator's enrollment generation, so an old
//!   connection closing late never removes the node's current enrollment.

use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use omegadesk_identity::{DeviceId, DeviceIdentity, DevicePublic};
use omegadesk_noise::{
    HANDSHAKE_INIT_LEN, MAX_FRAME_CIPHERTEXT_LEN, NoiseReceiver, NoiseSender, ResponderHandshake,
};
use omegadesk_protocol::control::CONTROL_PROTOCOL_VERSION;
use omegadesk_protocol::control::v1 as control;
use prost::Message;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::{Coordinator, CoordinatorError, EnrollmentBundle, NetmapDelta, parse_endpoints};

/// Prologue mixed into every control-channel Noise handshake.
pub const CONTROL_PROLOGUE: &[u8] = b"omegadesk-control-v1";

/// Time a connection has to finish the handshake and enroll.
pub const ENROLL_TIMEOUT: Duration = Duration::from_secs(15);

/// A node that stays silent for this long is considered gone. Nodes send a
/// keepalive every 30 s, so this tolerates three lost keepalives.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(120);

/// A node that does not read its control stream for this long is disconnected.
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(20);

/// Maximum nodes per `EnrollResponse` peer list or per `NetmapBatch`. A node
/// record with many endpoints serializes to roughly 1 KiB, so 256 nodes stay
/// far below the 1 MiB Noise frame limit.
pub const MAX_NODES_PER_MESSAGE: usize = 256;

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Wraps a payload in a [`control::ControlEnvelope`].
#[must_use]
pub fn envelope(payload: control::control_envelope::Payload) -> control::ControlEnvelope {
    control::ControlEnvelope {
        payload: Some(payload),
    }
}

fn error_envelope(
    code: control::ControlErrorCode,
    message: impl Into<String>,
) -> control::ControlEnvelope {
    envelope(control::control_envelope::Payload::Error(
        control::ControlError {
            code: code as i32,
            message: message.into(),
        },
    ))
}

/// Splits an enrollment into one `EnrollResponse` carrying the first
/// [`MAX_NODES_PER_MESSAGE`] peers and follow-up `NetmapBatch` messages with
/// `PeerUpserted` for the rest, so every message fits one Noise frame.
#[must_use]
pub fn enrollment_messages(bundle: &EnrollmentBundle) -> Vec<control::ControlEnvelope> {
    let mut response = bundle.to_proto();
    let all_peers = std::mem::take(&mut response.peers);
    let mut chunks = all_peers.chunks(MAX_NODES_PER_MESSAGE);
    response.peers = chunks
        .next()
        .map(<[control::NodeInfo]>::to_vec)
        .unwrap_or_default();
    let mut out = vec![envelope(
        control::control_envelope::Payload::EnrollResponse(response),
    )];
    for chunk in chunks {
        out.push(envelope(control::control_envelope::Payload::NetmapBatch(
            control::NetmapBatch {
                deltas: chunk
                    .iter()
                    .map(|peer| control::NetmapDelta {
                        change: Some(control::netmap_delta::Change::PeerUpserted(peer.clone())),
                    })
                    .collect(),
            },
        )));
    }
    out
}

/// Converts a batch of deltas into `NetmapBatch` messages of bounded size.
#[must_use]
pub fn batch_messages(batch: &[NetmapDelta]) -> Vec<control::ControlEnvelope> {
    let deltas: Vec<control::NetmapDelta> =
        batch.iter().filter_map(NetmapDelta::to_proto).collect();
    deltas
        .chunks(MAX_NODES_PER_MESSAGE)
        .map(|chunk| {
            envelope(control::control_envelope::Payload::NetmapBatch(
                control::NetmapBatch {
                    deltas: chunk.to_vec(),
                },
            ))
        })
        .collect()
}

/// Reads one encrypted control frame from `reader`, validating the declared
/// length against [`MAX_FRAME_CIPHERTEXT_LEN`] before allocating.
///
/// # Errors
///
/// Returns an error on I/O failure, oversized frames, AEAD failure, or a
/// malformed protobuf payload.
pub async fn read_control(
    reader: &mut OwnedReadHalf,
    rx: &mut NoiseReceiver,
) -> Result<control::ControlEnvelope> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await?;
    let body_len = usize::try_from(u32::from_be_bytes(len_buf))?;
    if body_len > MAX_FRAME_CIPHERTEXT_LEN {
        anyhow::bail!("control frame of {body_len} bytes exceeds the limit");
    }
    let mut body = vec![0u8; body_len];
    reader.read_exact(&mut body).await?;
    let plain = rx.read_body(&body)?;
    Ok(control::ControlEnvelope::decode(plain.as_slice())?)
}

/// Owns the write half and the Noise send state; everything the connection
/// sends goes through this task so frames are never interleaved. Returns when
/// the channel closes, a write fails, or a write stalls for [`WRITE_TIMEOUT`].
pub async fn writer_loop(
    mut writer: OwnedWriteHalf,
    mut tx: NoiseSender,
    mut outbound: mpsc::Receiver<control::ControlEnvelope>,
) {
    while let Some(msg) = outbound.recv().await {
        let Ok(frame) = tx.write_frame(&msg.encode_to_vec()) else {
            break;
        };
        match tokio::time::timeout(WRITE_TIMEOUT, writer.write_all(&frame)).await {
            Ok(Ok(())) => {}
            Ok(Err(_)) | Err(_) => break,
        }
    }
    let _ = writer.shutdown().await;
}

/// Forwards batched netmap deltas from the coordinator to the node. Returns
/// when the subscription or the outbound channel closes.
async fn netmap_forwarder(
    mut netmap_rx: mpsc::Receiver<Vec<NetmapDelta>>,
    outbound: mpsc::Sender<control::ControlEnvelope>,
) {
    while let Some(batch) = netmap_rx.recv().await {
        for msg in batch_messages(&batch) {
            if outbound.send(msg).await.is_err() {
                return;
            }
        }
    }
}

fn enroll(
    coordinator: &Arc<Mutex<Coordinator>>,
    request: &control::EnrollRequest,
    peer: DevicePublic,
) -> Result<EnrollmentBundle, Box<control::ControlEnvelope>> {
    if request.protocol_version != CONTROL_PROTOCOL_VERSION {
        return Err(Box::new(error_envelope(
            control::ControlErrorCode::UnsupportedVersion,
            format!(
                "unsupported control protocol version {}",
                request.protocol_version
            ),
        )));
    }
    let mut guard = coordinator.lock().map_err(|_| {
        Box::new(error_envelope(
            control::ControlErrorCode::Internal,
            "coordinator unavailable",
        ))
    })?;
    guard
        .enroll_machine(
            &request.preauth_key,
            peer,
            &request.hostname,
            parse_endpoints(&request.endpoints),
            unix_now(),
        )
        .map_err(|error| {
            let code = match error {
                CoordinatorError::MalformedPreAuthKey
                | CoordinatorError::InvalidPreAuthKey
                | CoordinatorError::PreAuthKeyAlreadyUsed
                | CoordinatorError::PreAuthKeyExpired => {
                    control::ControlErrorCode::InvalidPreauthKey
                }
                CoordinatorError::InvalidAclTag(_)
                | CoordinatorError::UnknownNode(_)
                | CoordinatorError::AddressPoolExhausted
                | CoordinatorError::MalformedControlMessage(_) => {
                    control::ControlErrorCode::Internal
                }
            };
            Box::new(error_envelope(code, error.to_string()))
        })
}

/// Serves one node connection from handshake to disconnect.
///
/// # Errors
///
/// Returns an error when the handshake, enrollment or stream fails; the node's
/// session is always released (and the node removed, if ephemeral) before
/// returning, unless a newer enrollment of the same node has replaced it.
pub async fn handle_connection(
    stream: TcpStream,
    server_id: Arc<DeviceIdentity>,
    coordinator: Arc<Mutex<Coordinator>>,
) -> Result<()> {
    stream.set_nodelay(true)?;
    let (mut reader, mut writer) = stream.into_split();

    let (session, request) = tokio::time::timeout(ENROLL_TIMEOUT, async {
        let mut init_msg = vec![0u8; HANDSHAKE_INIT_LEN];
        reader.read_exact(&mut init_msg).await?;
        let (session, reply) = ResponderHandshake::accept(&server_id, CONTROL_PROLOGUE, &init_msg)?;
        writer.write_all(&reply).await?;
        let (tx, mut rx) = session.split();
        let first = read_control(&mut reader, &mut rx).await?;
        Ok::<_, anyhow::Error>(((tx, rx), first))
    })
    .await
    .context("enrollment timeout")??;
    let (tx, mut rx) = session;
    let peer = *tx.peer_public();
    let node_id: DeviceId = peer.id();

    let (outbound_tx, outbound_rx) = mpsc::channel(64);
    let mut writer_task = tokio::spawn(writer_loop(writer, tx, outbound_rx));

    let Some(control::control_envelope::Payload::EnrollRequest(enroll_request)) = request.payload
    else {
        let _ = outbound_tx
            .send(error_envelope(
                control::ControlErrorCode::NotEnrolled,
                "first message must be EnrollRequest",
            ))
            .await;
        drop(outbound_tx);
        let _ = writer_task.await;
        anyhow::bail!("first control message was not EnrollRequest");
    };

    let bundle = match enroll(&coordinator, &enroll_request, peer) {
        Ok(bundle) => bundle,
        Err(error) => {
            let _ = outbound_tx.send(*error).await;
            drop(outbound_tx);
            let _ = writer_task.await;
            anyhow::bail!("enrollment rejected for {node_id}");
        }
    };
    let generation = bundle.generation;
    info!(node = %node_id, fqdn = %bundle.node.fqdn, ipv4 = %bundle.node.ipv4, generation, "node enrolled");
    for msg in enrollment_messages(&bundle) {
        outbound_tx.send(msg).await?;
    }
    let mut forwarder = tokio::spawn(netmap_forwarder(bundle.netmap_rx, outbound_tx.clone()));

    // Supervise all three: the session ends as soon as any of them does.
    let result = tokio::select! {
        result = serve_node(&mut reader, &mut rx, node_id, &coordinator, &outbound_tx) => result,
        _ = &mut writer_task => Err(anyhow::anyhow!("control writer ended")),
        _ = &mut forwarder => Err(anyhow::anyhow!("netmap subscription ended")),
    };

    forwarder.abort();
    drop(outbound_tx);
    writer_task.abort();
    if let Ok(mut guard) = coordinator.lock() {
        guard.handle_disconnect(node_id, generation);
    }
    info!(node = %node_id, generation, "node disconnected");
    result
}

async fn serve_node(
    reader: &mut OwnedReadHalf,
    rx: &mut NoiseReceiver,
    node_id: DeviceId,
    coordinator: &Arc<Mutex<Coordinator>>,
    outbound: &mpsc::Sender<control::ControlEnvelope>,
) -> Result<()> {
    loop {
        let msg = tokio::time::timeout(IDLE_TIMEOUT, read_control(reader, rx))
            .await
            .context("node idle timeout")??;
        match msg.payload {
            Some(control::control_envelope::Payload::EndpointUpdate(update)) => {
                let mut guard = coordinator
                    .lock()
                    .map_err(|_| anyhow::anyhow!("coordinator mutex poisoned"))?;
                guard.update_endpoints(node_id, parse_endpoints(&update.endpoints))?;
                guard.flush_netmap();
            }
            Some(control::control_envelope::Payload::RelayTicketRequest(_)) => {
                let grants = {
                    let guard = coordinator
                        .lock()
                        .map_err(|_| anyhow::anyhow!("coordinator mutex poisoned"))?;
                    guard.issue_relay_grants(node_id, unix_now())?
                };
                let reply = envelope(control::control_envelope::Payload::RelayTicketResponse(
                    control::RelayTicketResponse {
                        relays: grants.iter().map(crate::RelayGrant::to_proto).collect(),
                    },
                ));
                outbound.send(reply).await?;
            }
            Some(control::control_envelope::Payload::Keepalive(keepalive)) => {
                // The node initiates; the coordinator echoes once (never re-echoed).
                let reply = envelope(control::control_envelope::Payload::Keepalive(keepalive));
                outbound.send(reply).await?;
            }
            Some(control::control_envelope::Payload::Error(error)) => {
                anyhow::bail!("node reported error: {}", error.message);
            }
            Some(
                control::control_envelope::Payload::EnrollRequest(_)
                | control::control_envelope::Payload::EnrollResponse(_)
                | control::control_envelope::Payload::NetmapBatch(_)
                | control::control_envelope::Payload::RelayTicketResponse(_),
            )
            | None => {}
        }
    }
}

/// Accepts control connections forever (until the listener fails).
///
/// # Errors
///
/// Returns an error when `accept` fails.
pub async fn serve(
    listener: TcpListener,
    server_id: Arc<DeviceIdentity>,
    coordinator: Arc<Mutex<Coordinator>>,
) -> Result<()> {
    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let id_clone = Arc::clone(&server_id);
        let coord_clone = Arc::clone(&coordinator);
        tokio::spawn(async move {
            if let Err(err) = handle_connection(stream, id_clone, coord_clone).await {
                warn!(%peer_addr, error = %err, "control connection closed");
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NodeRecord;

    fn record(n: usize) -> NodeRecord {
        NodeRecord {
            public: DeviceIdentity::generate().public(),
            tenant: "t".into(),
            hostname: format!("n{n}"),
            fqdn: format!("n{n}.omega"),
            ipv4: std::net::Ipv4Addr::new(100, 64, 0, 1),
            ipv6: std::net::Ipv6Addr::LOCALHOST,
            endpoints: vec![],
            tags: vec![],
            ephemeral: false,
        }
    }

    #[test]
    fn large_snapshots_and_batches_are_chunked_to_fit_one_frame() {
        let (_tx, netmap_rx) = mpsc::channel(1);
        let peers: Vec<NodeRecord> = (0..(MAX_NODES_PER_MESSAGE * 2 + 3)).map(record).collect();
        let bundle = EnrollmentBundle {
            generation: 1,
            node: record(9999),
            peers: peers.clone(),
            relays: vec![],
            netmap_rx,
        };
        let messages = enrollment_messages(&bundle);
        assert_eq!(messages.len(), 3);
        let Some(control::control_envelope::Payload::EnrollResponse(first)) =
            messages[0].payload.as_ref()
        else {
            panic!("first message must be the EnrollResponse");
        };
        assert_eq!(first.peers.len(), MAX_NODES_PER_MESSAGE);
        let mut total = first.peers.len();
        for msg in &messages[1..] {
            let Some(control::control_envelope::Payload::NetmapBatch(batch)) = msg.payload.as_ref()
            else {
                panic!("follow-ups must be NetmapBatch");
            };
            assert!(batch.deltas.len() <= MAX_NODES_PER_MESSAGE);
            total += batch.deltas.len();
        }
        assert_eq!(total, peers.len());
        for msg in &messages {
            assert!(msg.encode_to_vec().len() < omegadesk_noise::MAX_FRAME_BODY_LEN);
        }

        let deltas: Vec<NetmapDelta> = peers
            .iter()
            .cloned()
            .map(NetmapDelta::PeerUpserted)
            .collect();
        let batches = batch_messages(&deltas);
        assert_eq!(batches.len(), 3);
    }
}
