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
//!
//! RMM (Phase 6) rides the same connection: after enrollment the node's
//! outbound channel is registered with the [`RmmService`] so the coordinator
//! can push [`control::ScriptDispatch`] messages, and inbound
//! [`control::InventoryReport`] / [`control::ScriptResult`] messages are handed
//! to the service (MeshCentral keeps `sysinfo` and `coreinfo` on the single
//! agent web socket in `meshagent.js` for the same reason: one authenticated
//! channel per device).

use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use omegadesk_identity::{DeviceId, DeviceIdentity, DevicePublic};
use omegadesk_noise::{
    HANDSHAKE_INIT_LEN, MAX_FRAME_CIPHERTEXT_LEN, NoiseReceiver, NoiseSender, ResponderHandshake,
};
use omegadesk_policy::{AuditKind, AuditOutcome};
use omegadesk_protocol::control::CONTROL_PROTOCOL_VERSION;
use omegadesk_protocol::control::v1 as control;
use prost::Message;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::rmm_service::{DeviceSession, RmmService};
use crate::{
    Coordinator, CoordinatorError, EnrollmentBundle, NetmapDelta, parse_endpoints,
    parse_quicksupport_id,
};

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

/// Interval of the RMM housekeeping tick (schedules, offline checks, state file).
pub const RMM_TICK_INTERVAL: Duration = Duration::from_secs(5);

/// Current Unix time in seconds.
#[must_use]
pub fn unix_now() -> u64 {
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

/// Successful enrollment plus what the RMM side learned from it.
struct Enrolled {
    bundle: EnrollmentBundle,
    /// Site assigned by the deployment link the node enrolled through.
    site_id: Option<String>,
}

fn internal_error(message: &str) -> Box<control::ControlEnvelope> {
    Box::new(error_envelope(control::ControlErrorCode::Internal, message))
}

/// Resolves the credential of an `EnrollRequest`: the pre-auth key as given,
/// or the pre-auth key bound to a redeemed deployment token.
fn resolve_credential(
    rmm: &Arc<Mutex<RmmService>>,
    request: &control::EnrollRequest,
    peer: DeviceId,
) -> Result<(String, Option<String>), Box<control::ControlEnvelope>> {
    if !request.preauth_key.is_empty() || request.deployment_token.is_empty() {
        return Ok((request.preauth_key.clone(), None));
    }
    let mut guard = rmm
        .lock()
        .map_err(|_| internal_error("rmm service unavailable"))?;
    let binding = guard
        .redeem_deployment_token(peer, &request.deployment_token, unix_now())
        .map_err(|error| {
            Box::new(error_envelope(
                control::ControlErrorCode::InvalidDeploymentToken,
                error.to_string(),
            ))
        })?;
    Ok((binding.preauth_key, Some(binding.site_id)))
}

fn enroll(
    coordinator: &Arc<Mutex<Coordinator>>,
    rmm: &Arc<Mutex<RmmService>>,
    request: &control::EnrollRequest,
    peer: DevicePublic,
) -> Result<Enrolled, Box<control::ControlEnvelope>> {
    if request.protocol_version != CONTROL_PROTOCOL_VERSION {
        return Err(Box::new(error_envelope(
            control::ControlErrorCode::UnsupportedVersion,
            format!(
                "unsupported control protocol version {}",
                request.protocol_version
            ),
        )));
    }
    let to_error = |error: CoordinatorError| {
        let code = match error {
            CoordinatorError::MalformedPreAuthKey
            | CoordinatorError::InvalidPreAuthKey
            | CoordinatorError::PreAuthKeyAlreadyUsed
            | CoordinatorError::PreAuthKeyExpired => control::ControlErrorCode::InvalidPreauthKey,
            CoordinatorError::MalformedControlMessage(_) => {
                control::ControlErrorCode::MalformedRequest
            }
            CoordinatorError::InvalidAclTag(_)
            | CoordinatorError::UnknownNode(_)
            | CoordinatorError::AddressPoolExhausted
            | CoordinatorError::QuickSupportIdUnavailable => control::ControlErrorCode::Internal,
        };
        Box::new(error_envelope(code, error.to_string()))
    };
    let (preauth_key, site_id) = resolve_credential(rmm, request, peer.id())?;
    let quicksupport = parse_quicksupport_id(&request.quicksupport_id).map_err(to_error)?;
    let mut guard = coordinator.lock().map_err(|_| {
        Box::new(error_envelope(
            control::ControlErrorCode::Internal,
            "coordinator unavailable",
        ))
    })?;
    let endpoints = parse_endpoints(&request.endpoints);
    match quicksupport {
        Some(proposed) => guard.enroll_quicksupport(
            &preauth_key,
            peer,
            &request.hostname,
            endpoints,
            proposed,
            unix_now(),
        ),
        None => guard.enroll_machine(&preauth_key, peer, &request.hostname, endpoints, unix_now()),
    }
    .map(|bundle| Enrolled { bundle, site_id })
    .map_err(to_error)
}

/// Serves one node connection from handshake to disconnect with a private,
/// in-memory RMM service (see [`handle_connection_with`] for the shared one).
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
    let rmm = Arc::new(Mutex::new(RmmService::in_memory()));
    handle_connection_with(stream, server_id, coordinator, rmm).await
}

/// Serves one node connection from handshake to disconnect, registering it
/// with the shared [`RmmService`].
///
/// # Errors
///
/// Returns an error when the handshake, enrollment or stream fails; the node's
/// session is always released (and the node removed, if ephemeral) before
/// returning, unless a newer enrollment of the same node has replaced it.
pub async fn handle_connection_with(
    stream: TcpStream,
    server_id: Arc<DeviceIdentity>,
    coordinator: Arc<Mutex<Coordinator>>,
    rmm: Arc<Mutex<RmmService>>,
) -> Result<()> {
    stream.set_nodelay(true)?;
    let peer_addr = stream.peer_addr()?;
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

    let Enrolled { bundle, site_id } = match enroll(&coordinator, &rmm, &enroll_request, peer) {
        Ok(enrolled) => enrolled,
        Err(error) => {
            if let Ok(guard) = coordinator.lock() {
                let reason = match error.payload.as_ref() {
                    Some(control::control_envelope::Payload::Error(e)) => e.message.clone(),
                    _ => "rejected".to_owned(),
                };
                guard.audit(
                    &Coordinator::audit_event(AuditKind::EnrollmentDenied, AuditOutcome::Denied)
                        .actor(node_id.to_string())
                        .remote(&peer_addr)
                        .detail(reason),
                );
            }
            let _ = outbound_tx.send(*error).await;
            drop(outbound_tx);
            let _ = writer_task.await;
            anyhow::bail!("enrollment rejected for {node_id}");
        }
    };
    let generation = bundle.generation;
    let tenant = bundle.node.tenant.clone();
    info!(node = %node_id, fqdn = %bundle.node.fqdn, ipv4 = %bundle.node.ipv4, generation, "node enrolled");
    if let Ok(guard) = coordinator.lock() {
        guard.audit(
            &Coordinator::audit_event(AuditKind::NodeEnrolled, AuditOutcome::Ok)
                .actor(node_id.to_string())
                .target(bundle.node.tenant.clone())
                .remote(&peer_addr)
                .detail(format!(
                    "{} ({}) user={:?} tags={:?}",
                    bundle.node.fqdn, bundle.node.ipv4, bundle.node.user, bundle.node.tags
                )),
        );
    }
    for msg in enrollment_messages(&bundle) {
        outbound_tx.send(msg).await?;
    }
    if let Ok(mut guard) = rmm.lock() {
        guard.device_connected(
            &DeviceSession {
                device_id: node_id,
                tenant: &tenant,
                hostname: &bundle.node.hostname,
                site_id: site_id.as_deref(),
                generation,
            },
            outbound_tx.clone(),
            unix_now(),
        );
    }
    let mut forwarder = tokio::spawn(netmap_forwarder(bundle.netmap_rx, outbound_tx.clone()));

    let node = NodeSession {
        node_id,
        tenant,
        coordinator: &coordinator,
        rmm: &rmm,
        outbound: &outbound_tx,
    };
    // Supervise all three: the session ends as soon as any of them does.
    let result = tokio::select! {
        result = node.serve(&mut reader, &mut rx) => result,
        _ = &mut writer_task => Err(anyhow::anyhow!("control writer ended")),
        _ = &mut forwarder => Err(anyhow::anyhow!("netmap subscription ended")),
    };

    forwarder.abort();
    drop(outbound_tx);
    writer_task.abort();
    if let Ok(mut guard) = coordinator.lock() {
        guard.handle_disconnect(node_id, generation);
        guard.audit(
            &Coordinator::audit_event(AuditKind::NodeDisconnected, AuditOutcome::Ok)
                .actor(node_id.to_string())
                .remote(&peer_addr)
                .detail(match &result {
                    Ok(()) => "closed".to_owned(),
                    Err(error) => error.to_string(),
                }),
        );
    }
    if let Ok(mut guard) = rmm.lock() {
        guard.device_disconnected(node_id, generation, unix_now());
    }
    info!(node = %node_id, generation, "node disconnected");
    result
}

/// One enrolled node's message loop.
struct NodeSession<'a> {
    node_id: DeviceId,
    tenant: String,
    coordinator: &'a Arc<Mutex<Coordinator>>,
    rmm: &'a Arc<Mutex<RmmService>>,
    outbound: &'a mpsc::Sender<control::ControlEnvelope>,
}

impl NodeSession<'_> {
    async fn lookup_quicksupport(&self, request: control::QuickSupportLookupRequest) -> Result<()> {
        // A malformed or unknown ID is answered with an empty response
        // (not an error, which would end the control session).
        let node = match request.quicksupport_id.parse() {
            Ok(id) => {
                let guard = self
                    .coordinator
                    .lock()
                    .map_err(|_| anyhow::anyhow!("coordinator mutex poisoned"))?;
                guard
                    .lookup_quicksupport(self.node_id, id)?
                    .map(crate::NodeRecord::to_proto)
            }
            Err(_) => None,
        };
        let reply = envelope(
            control::control_envelope::Payload::QuickSupportLookupResponse(
                control::QuickSupportLookupResponse {
                    quicksupport_id: request.quicksupport_id,
                    node,
                },
            ),
        );
        self.outbound.send(reply).await?;
        Ok(())
    }

    async fn serve(&self, reader: &mut OwnedReadHalf, rx: &mut NoiseReceiver) -> Result<()> {
        loop {
            let msg = tokio::time::timeout(IDLE_TIMEOUT, read_control(reader, rx))
                .await
                .context("node idle timeout")??;
            match msg.payload {
                Some(control::control_envelope::Payload::EndpointUpdate(update)) => {
                    let mut guard = self
                        .coordinator
                        .lock()
                        .map_err(|_| anyhow::anyhow!("coordinator mutex poisoned"))?;
                    guard.update_endpoints(self.node_id, parse_endpoints(&update.endpoints))?;
                    guard.flush_netmap();
                }
                Some(control::control_envelope::Payload::RelayTicketRequest(_)) => {
                    let grants = {
                        let guard = self
                            .coordinator
                            .lock()
                            .map_err(|_| anyhow::anyhow!("coordinator mutex poisoned"))?;
                        guard.issue_relay_grants(self.node_id, unix_now())?
                    };
                    let reply = envelope(control::control_envelope::Payload::RelayTicketResponse(
                        control::RelayTicketResponse {
                            relays: grants.iter().map(crate::RelayGrant::to_proto).collect(),
                        },
                    ));
                    self.outbound.send(reply).await?;
                }
                Some(control::control_envelope::Payload::Keepalive(keepalive)) => {
                    // The node initiates; the coordinator echoes once (never re-echoed).
                    let reply = envelope(control::control_envelope::Payload::Keepalive(keepalive));
                    self.outbound.send(reply).await?;
                }
                Some(control::control_envelope::Payload::InventoryReport(report)) => {
                    let transitions = {
                        let mut guard = self
                            .rmm
                            .lock()
                            .map_err(|_| anyhow::anyhow!("rmm mutex poisoned"))?;
                        guard.ingest_report(self.node_id, &self.tenant, &report, unix_now())
                    };
                    info!(
                        node = %self.node_id,
                        reason = report.reason,
                        host = %report.hostname,
                        cpu = report.cpu_utilization_pct,
                        "inventory report"
                    );
                    log_transitions(&transitions);
                }
                Some(control::control_envelope::Payload::ScriptResult(result)) => {
                    let transitions = {
                        let mut guard = self
                            .rmm
                            .lock()
                            .map_err(|_| anyhow::anyhow!("rmm mutex poisoned"))?;
                        guard.ingest_script_result(self.node_id, &result, unix_now())
                    };
                    info!(
                        node = %self.node_id,
                        run = result.run_id,
                        script = %result.script_id,
                        exit = result.exit_code,
                        timed_out = result.timed_out,
                        "script result"
                    );
                    log_transitions(&transitions);
                }
                Some(control::control_envelope::Payload::QuickSupportLookupRequest(request)) => {
                    self.lookup_quicksupport(request).await?;
                }
                Some(control::control_envelope::Payload::Error(error)) => {
                    anyhow::bail!("node reported error: {}", error.message);
                }
                Some(
                    control::control_envelope::Payload::EnrollRequest(_)
                    | control::control_envelope::Payload::EnrollResponse(_)
                    | control::control_envelope::Payload::NetmapBatch(_)
                    | control::control_envelope::Payload::RelayTicketResponse(_)
                    | control::control_envelope::Payload::QuickSupportLookupResponse(_)
                    | control::control_envelope::Payload::ScriptDispatch(_),
                )
                | None => {}
            }
        }
    }
}

fn log_transitions(transitions: &[crate::rmm_service::AlertTransition]) {
    for transition in transitions {
        info!(
            alert = %transition.alert_id,
            state = transition.state.as_str(),
            severity = transition.severity.as_str(),
            detail = %transition.detail,
            "alert transition"
        );
    }
}

/// Runs [`RmmService::tick`] every [`RMM_TICK_INTERVAL`] until the service is dropped.
pub async fn rmm_housekeeping(rmm: Arc<Mutex<RmmService>>) {
    let mut interval = tokio::time::interval(RMM_TICK_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        interval.tick().await;
        let Ok(mut guard) = rmm.lock() else {
            warn!("rmm mutex poisoned; housekeeping stopped");
            return;
        };
        let transitions = guard.tick(unix_now());
        drop(guard);
        log_transitions(&transitions);
    }
}

/// Accepts control connections forever (until the listener fails) with a
/// fresh in-memory [`RmmService`] shared by every connection.
///
/// # Errors
///
/// Returns an error when `accept` fails.
pub async fn serve(
    listener: TcpListener,
    server_id: Arc<DeviceIdentity>,
    coordinator: Arc<Mutex<Coordinator>>,
) -> Result<()> {
    let rmm = Arc::new(Mutex::new(RmmService::in_memory()));
    serve_with(listener, server_id, coordinator, rmm).await
}

/// Accepts control connections forever (until the listener fails), feeding
/// the given [`RmmService`] and running its housekeeping tick.
///
/// # Errors
///
/// Returns an error when `accept` fails.
pub async fn serve_with(
    listener: TcpListener,
    server_id: Arc<DeviceIdentity>,
    coordinator: Arc<Mutex<Coordinator>>,
    rmm: Arc<Mutex<RmmService>>,
) -> Result<()> {
    let housekeeping = tokio::spawn(rmm_housekeeping(Arc::clone(&rmm)));
    let result = loop {
        let (stream, peer_addr) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(error) => break Err(error.into()),
        };
        let id_clone = Arc::clone(&server_id);
        let coord_clone = Arc::clone(&coordinator);
        let rmm_clone = Arc::clone(&rmm);
        tokio::spawn(async move {
            if let Err(err) = handle_connection_with(stream, id_clone, coord_clone, rmm_clone).await
            {
                warn!(%peer_addr, error = %err, "control connection closed");
            }
        });
    };
    housekeeping.abort();
    result
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
            quicksupport_id: None,
            user: String::new(),
            session: None,
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
        assert_eq!(
            first.peer_count as usize,
            peers.len(),
            "peer_count covers the whole snapshot"
        );
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

    #[test]
    fn deployment_token_resolves_to_the_bound_preauth_key() {
        let rmm = Arc::new(Mutex::new(RmmService::in_memory()));
        let token = rmm
            .lock()
            .unwrap()
            .create_deployment_link("acme", "site-sp", "odk_a_b".to_owned(), u64::MAX, 0)
            .1;
        let device = DeviceIdentity::generate().id();

        // A pre-auth key wins over a token; no token and no key is just an empty key.
        let plain = control::EnrollRequest {
            preauth_key: "odk_x_y".to_owned(),
            deployment_token: token.clone(),
            ..Default::default()
        };
        assert_eq!(
            resolve_credential(&rmm, &plain, device).unwrap(),
            ("odk_x_y".to_owned(), None)
        );
        let none = control::EnrollRequest::default();
        assert_eq!(
            resolve_credential(&rmm, &none, device).unwrap(),
            (String::new(), None)
        );

        let linked = control::EnrollRequest {
            deployment_token: token,
            ..Default::default()
        };
        assert_eq!(
            resolve_credential(&rmm, &linked, device).unwrap(),
            ("odk_a_b".to_owned(), Some("site-sp".to_owned()))
        );
        let bogus = control::EnrollRequest {
            deployment_token: "odl_nope_nope".to_owned(),
            ..Default::default()
        };
        let error = resolve_credential(&rmm, &bogus, device).unwrap_err();
        let Some(control::control_envelope::Payload::Error(error)) = error.payload else {
            panic!("expected an error envelope");
        };
        assert_eq!(
            error.code,
            control::ControlErrorCode::InvalidDeploymentToken as i32
        );
    }
}
