//! Node-side client of the OmegaDesk coordinator (`omegadesk-control`).
//!
//! One long-lived TCP connection protected by Noise `IK` (the node knows the
//! coordinator's public identity up front, like a Tailscale node knows its
//! control server key): the node enrolls with a pre-authorized key, receives
//! its own record, the peers of its tenant and one relay ticket per relay, then
//! keeps receiving batched netmap deltas and sends endpoint updates, ticket
//! refresh requests and keepalives. Semantics follow Tailscale `tailcfg`
//! (`MapRequest`/`MapResponse`) and Headscale's long-poll map stream; the wire
//! format is the project's own `omegadesk.control.v1` protobuf.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use omegadesk_identity::{DeviceId, DeviceIdentity, DevicePublic, IdentityError, QuickSupportId};
use omegadesk_noise::{
    InitiatorHandshake, MAX_FRAME_CIPHERTEXT_LEN, NoiseError, NoiseReceiver, NoiseSender,
};
pub use omegadesk_policy::SessionDecision;
use omegadesk_protocol::control::CONTROL_PROTOCOL_VERSION;
use omegadesk_protocol::control::v1 as control;
use omegadesk_relay::{RelayError, RelayTicket};
use prost::Message;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, warn};

/// Prologue mixed into every control-channel Noise handshake (must match the server).
pub const CONTROL_PROLOGUE: &[u8] = b"omegadesk-control-v1";

/// Interval between keepalives sent to the coordinator.
pub const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);

/// Time allowed for the TCP connect, handshake and enrollment reply.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// A control connection on which nothing arrives for this long is considered
/// dead and reported as [`NetmapEvent::Disconnected`]. The coordinator echoes
/// every keepalive ([`KEEPALIVE_INTERVAL`]), so this tolerates three lost
/// echoes; a blackholed TCP path (no FIN/RST) is detected instead of waiting
/// forever.
pub const READ_IDLE_TIMEOUT: Duration = Duration::from_secs(100);

/// Prefix of a deployment-link token (`odl_<link_id>_<mac hex>`), as opposed
/// to a pre-auth key (`odk_<prefix>_<secret>`).
pub const DEPLOYMENT_TOKEN_PREFIX: &str = "odl_";

/// Whether an enrollment credential is a deployment-link token rather than a
/// pre-auth key. [`ControlConfig::preauth_key`] accepts both: the client puts a
/// token in `EnrollRequest.deployment_token` so the coordinator can map it to
/// the pre-auth key bound to the link.
#[must_use]
pub fn is_deployment_token(credential: &str) -> bool {
    credential.trim().starts_with(DEPLOYMENT_TOKEN_PREFIX)
}

/// Errors returned by the control client.
#[derive(Debug, thiserror::Error)]
pub enum ControlError {
    /// TCP or handshake I/O failure.
    #[error("control connection: {0}")]
    Io(#[from] std::io::Error),
    /// Noise handshake or frame failure.
    #[error("control channel: {0}")]
    Noise(#[from] NoiseError),
    /// The coordinator rejected the request.
    #[error("coordinator rejected the request ({code:?}): {message}")]
    Rejected {
        /// Error code reported by the coordinator.
        code: control::ControlErrorCode,
        /// Human-readable reason.
        message: String,
    },
    /// A message could not be decoded or converted.
    #[error("malformed control message: {0}")]
    Malformed(&'static str),
    /// Protobuf decoding failed.
    #[error("control message decode: {0}")]
    Decode(#[from] prost::DecodeError),
    /// The connection was closed before the expected reply arrived.
    #[error("control connection closed")]
    Closed,
    /// The operation did not complete within [`CONNECT_TIMEOUT`].
    #[error("control operation timed out")]
    Timeout,
    /// Relay ticket bytes were malformed.
    #[error("relay ticket: {0}")]
    Relay(#[from] RelayError),
    /// A `--server-key` string was malformed.
    #[error("server key must be 128 hex characters (signing key then exchange key)")]
    InvalidServerKey,
}

impl From<IdentityError> for ControlError {
    fn from(_: IdentityError) -> Self {
        Self::Malformed("invalid public key")
    }
}

/// Parses `--server-key`: 64 hex chars of Ed25519 signing key followed by 64 hex
/// chars of X25519 exchange key, as printed by `omegadesk-server` at startup.
///
/// # Errors
///
/// Returns [`ControlError::InvalidServerKey`] if the string is malformed.
pub fn parse_server_key(hex: &str) -> Result<DevicePublic, ControlError> {
    let bytes = data_encoding::HEXLOWER_PERMISSIVE
        .decode(hex.trim().as_bytes())
        .map_err(|_| ControlError::InvalidServerKey)?;
    if bytes.len() != 64 {
        return Err(ControlError::InvalidServerKey);
    }
    let mut signing = [0u8; 32];
    signing.copy_from_slice(&bytes[..32]);
    let mut exchange = [0u8; 32];
    exchange.copy_from_slice(&bytes[32..]);
    DevicePublic::from_bytes(&signing, &exchange).map_err(|_| ControlError::InvalidServerKey)
}

/// A node of the network map as seen by this node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerInfo {
    /// Cryptographic identity of the peer.
    pub public: DevicePublic,
    /// Tenant the peer belongs to (always this node's tenant).
    pub tenant: String,
    /// Sanitized hostname label.
    pub hostname: String,
    /// `<hostname>.omega`.
    pub fqdn: String,
    /// Mesh IPv4 address (`100.64.0.0/10`).
    pub ipv4: Ipv4Addr,
    /// Mesh IPv6 address (`fd7a:115c:a1e0::/48`).
    pub ipv6: Ipv6Addr,
    /// Direct UDP endpoints advertised by the peer.
    pub endpoints: Vec<SocketAddr>,
    /// ACL tags.
    pub tags: Vec<String>,
    /// Whether the peer is removed when it disconnects.
    pub ephemeral: bool,
    /// Nine-digit QuickSupport ID assigned by the coordinator; `None` for
    /// agents and clients.
    pub quicksupport_id: Option<QuickSupportId>,
    /// Owner of the peer in the policy (`alice@example.com`); empty for tagged machines.
    pub user: String,
    /// What this peer may do when it opens a remote session on *this* node, compiled by
    /// the coordinator from the tenant policy. `None` when the coordinator runs without a
    /// policy file: every peer of the tenant is visible and only the access password applies.
    pub session: Option<SessionDecision>,
}

impl PeerInfo {
    /// Device identifier of the peer.
    #[must_use]
    pub fn id(&self) -> DeviceId {
        self.public.id()
    }

    /// Converts a control-protocol node.
    ///
    /// # Errors
    ///
    /// Returns [`ControlError::Malformed`] on bad keys or addresses.
    pub fn from_proto(info: &control::NodeInfo) -> Result<Self, ControlError> {
        let signing: [u8; 32] = info
            .signing_key
            .as_ref()
            .try_into()
            .map_err(|_| ControlError::Malformed("signing key length"))?;
        let exchange: [u8; 32] = info
            .exchange_key
            .as_ref()
            .try_into()
            .map_err(|_| ControlError::Malformed("exchange key length"))?;
        Ok(Self {
            public: DevicePublic::from_bytes(&signing, &exchange)?,
            tenant: info.tenant.clone(),
            hostname: info.hostname.clone(),
            fqdn: info.fqdn.clone(),
            ipv4: info
                .ipv4
                .parse()
                .map_err(|_| ControlError::Malformed("ipv4"))?,
            ipv6: info
                .ipv6
                .parse()
                .map_err(|_| ControlError::Malformed("ipv6"))?,
            endpoints: parse_endpoints(&info.endpoints),
            tags: info.tags.clone(),
            ephemeral: info.ephemeral,
            quicksupport_id: if info.quicksupport_id.is_empty() {
                None
            } else {
                Some(
                    info.quicksupport_id
                        .parse()
                        .map_err(|_| ControlError::Malformed("quicksupport id"))?,
                )
            },
            user: info.user.clone(),
            session: info.session.as_ref().map(SessionDecision::from_proto),
        })
    }
}

/// Parses `ip:port` strings, dropping malformed entries.
#[must_use]
pub fn parse_endpoints(raw: &[String]) -> Vec<SocketAddr> {
    raw.iter().filter_map(|s| s.parse().ok()).collect()
}

/// A relay this node may use, with a single-use ticket for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayGrant {
    /// `host:port` of the relay TCP listener.
    pub address: String,
    /// Relay X25519 public key (also the ticket audience).
    pub exchange_key: [u8; 32],
    /// Single-use ticket bound to this node and this relay.
    pub ticket: RelayTicket,
    /// `host:port` of the relay STUN responder, if it runs one.
    pub stun_address: Option<String>,
}

impl RelayGrant {
    /// Converts a control-protocol relay entry.
    ///
    /// # Errors
    ///
    /// Returns [`ControlError`] on a bad key length or ticket.
    pub fn from_proto(info: &control::RelayInfo) -> Result<Self, ControlError> {
        let exchange_key: [u8; 32] = info
            .exchange_key
            .as_ref()
            .try_into()
            .map_err(|_| ControlError::Malformed("relay key length"))?;
        Ok(Self {
            address: info.address.clone(),
            exchange_key,
            ticket: RelayTicket::from_bytes(&info.ticket)?,
            stun_address: (!info.stun_address.is_empty()).then(|| info.stun_address.clone()),
        })
    }
}

/// Result of a successful enrollment.
#[derive(Debug, Clone)]
pub struct Enrollment {
    /// This node's record as assigned by the coordinator.
    pub self_node: PeerInfo,
    /// Peers of the same tenant known at enrollment time. May be only the
    /// first chunk of a large tenant: the rest follows as
    /// [`NetmapEvent::PeerUpserted`] until `total_peers` have been seen.
    pub peers: Vec<PeerInfo>,
    /// Relays with tickets.
    pub relays: Vec<RelayGrant>,
    /// Size of the complete peer snapshot (`peers.len()` once complete).
    pub total_peers: usize,
}

impl Enrollment {
    /// Whether `peers` already holds the whole snapshot.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.peers.len() >= self.total_peers
    }
}

/// Netmap changes pushed by the coordinator after enrollment.
#[derive(Debug, Clone, PartialEq)]
pub enum NetmapEvent {
    /// A peer joined or changed.
    PeerUpserted(Box<PeerInfo>),
    /// A peer's direct endpoints changed.
    EndpointsUpdated {
        /// Ed25519 signing key of the peer.
        signing_key: [u8; 32],
        /// New endpoints.
        endpoints: Vec<SocketAddr>,
    },
    /// A peer left the mesh.
    PeerRemoved {
        /// Ed25519 signing key of the peer.
        signing_key: [u8; 32],
    },
    /// The coordinator asks this node to run a script (RMM). Not a netmap
    /// change: it rides the same stream so the mesh layer forwards it to the
    /// RMM task as [`RmmEvent::ScriptDispatch`].
    ScriptDispatch(Box<control::ScriptDispatch>),
    /// The control connection ended; the node must re-enroll.
    Disconnected(String),
}

/// What the RMM task of an agent receives from the control link.
#[derive(Debug, Clone, PartialEq)]
pub enum RmmEvent {
    /// A (re-)enrollment completed: the agent sends a fresh inventory report,
    /// because the coordinator may have restarted and lost its memory of it.
    Enrolled,
    /// Run this script and report the result with [`ControlHandle::send_script_result`].
    ScriptDispatch(Box<control::ScriptDispatch>),
}

/// Configuration for [`ControlClient::connect`].
#[derive(Debug, Clone)]
pub struct ControlConfig {
    /// `host:port` of the coordinator.
    pub server_addr: String,
    /// Coordinator public identity (`--server-key`).
    pub server_public: DevicePublic,
    /// Enrollment credential: an `odk_<prefix>_<secret>` pre-authorized key or
    /// an `odl_<link>_<mac>` deployment-link token (see [`is_deployment_token`]).
    pub preauth_key: String,
    /// Requested hostname.
    pub hostname: String,
    /// Direct UDP endpoints known at startup.
    pub endpoints: Vec<SocketAddr>,
    /// `Some` enrolls as a QuickSupport host proposing this nine-digit ID
    /// (usually [`QuickSupportId::proposed_for`] the device, or the ID assigned
    /// by a previous enrollment so a reconnect keeps the number the end user
    /// read aloud). The coordinator keeps the proposal when it is free or
    /// already bound to this device and assigns another one otherwise; the
    /// result is `Enrollment::self_node.quicksupport_id`. QuickSupport hosts
    /// are always ephemeral. `None` for agents and clients.
    pub quicksupport_id: Option<QuickSupportId>,
}

enum Outbound {
    Message(Box<control::ControlEnvelope>),
    TicketRequest(oneshot::Sender<Vec<RelayGrant>>),
    QuickSupportLookup(QuickSupportId, oneshot::Sender<Option<PeerInfo>>),
}

/// Handle to the control connection: sends updates and requests tickets.
#[derive(Clone)]
pub struct ControlHandle {
    outbound: mpsc::Sender<Outbound>,
}

impl ControlHandle {
    /// Reports the node's current direct endpoints (LAN + STUN) to the coordinator.
    ///
    /// # Errors
    ///
    /// Returns [`ControlError::Closed`] if the connection is gone.
    pub async fn update_endpoints(&self, endpoints: Vec<SocketAddr>) -> Result<(), ControlError> {
        let msg = envelope(control::control_envelope::Payload::EndpointUpdate(
            control::EndpointUpdate {
                signing_key: Vec::new().into(),
                endpoints: endpoints.iter().map(ToString::to_string).collect(),
            },
        ));
        self.outbound
            .send(Outbound::Message(Box::new(msg)))
            .await
            .map_err(|_| ControlError::Closed)
    }

    /// Sends an RMM inventory report / heartbeat to the coordinator.
    ///
    /// # Errors
    ///
    /// Returns [`ControlError::Closed`] if the connection is gone.
    pub async fn send_inventory(
        &self,
        report: control::InventoryReport,
    ) -> Result<(), ControlError> {
        let msg = envelope(control::control_envelope::Payload::InventoryReport(report));
        self.outbound
            .send(Outbound::Message(Box::new(msg)))
            .await
            .map_err(|_| ControlError::Closed)
    }

    /// Reports the outcome of a [`control::ScriptDispatch`].
    ///
    /// # Errors
    ///
    /// Returns [`ControlError::Closed`] if the connection is gone.
    pub async fn send_script_result(
        &self,
        result: control::ScriptResult,
    ) -> Result<(), ControlError> {
        let msg = envelope(control::control_envelope::Payload::ScriptResult(result));
        self.outbound
            .send(Outbound::Message(Box::new(msg)))
            .await
            .map_err(|_| ControlError::Closed)
    }

    /// Requests fresh single-use relay tickets.
    ///
    /// # Errors
    ///
    /// Returns [`ControlError::Closed`] if the connection is gone or
    /// [`ControlError::Timeout`] if the coordinator does not answer in time.
    pub async fn request_relay_tickets(&self) -> Result<Vec<RelayGrant>, ControlError> {
        let (tx, rx) = oneshot::channel();
        self.outbound
            .send(Outbound::TicketRequest(tx))
            .await
            .map_err(|_| ControlError::Closed)?;
        match tokio::time::timeout(CONNECT_TIMEOUT, rx).await {
            Ok(Ok(grants)) => Ok(grants),
            Ok(Err(_)) => Err(ControlError::Closed),
            Err(_) => Err(ControlError::Timeout),
        }
    }

    /// Asks the coordinator which node of this tenant currently holds the
    /// QuickSupport ID `id`. `Ok(None)` when no such node exists (the ID
    /// expired with its host or belongs to another tenant).
    ///
    /// # Errors
    ///
    /// Returns [`ControlError::Closed`] if the connection is gone or
    /// [`ControlError::Timeout`] if the coordinator does not answer in time.
    pub async fn lookup_quicksupport(
        &self,
        id: QuickSupportId,
    ) -> Result<Option<PeerInfo>, ControlError> {
        let (tx, rx) = oneshot::channel();
        self.outbound
            .send(Outbound::QuickSupportLookup(id, tx))
            .await
            .map_err(|_| ControlError::Closed)?;
        match tokio::time::timeout(CONNECT_TIMEOUT, rx).await {
            Ok(Ok(peer)) => Ok(peer),
            Ok(Err(_)) => Err(ControlError::Closed),
            Err(_) => Err(ControlError::Timeout),
        }
    }
}

/// Source of fresh relay tickets, implemented by [`ControlHandle`] and by tests.
pub trait TicketSource: Send + Sync {
    /// Requests fresh single-use tickets for every relay.
    fn fresh_grants(
        &self,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Vec<RelayGrant>, ControlError>> + Send + '_>,
    >;
}

impl TicketSource for ControlHandle {
    fn fresh_grants(
        &self,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Vec<RelayGrant>, ControlError>> + Send + '_>,
    > {
        Box::pin(self.request_relay_tickets())
    }
}

/// Live control connection: a handle plus the stream of netmap events.
pub struct ControlClient {
    handle: ControlHandle,
    events: mpsc::Receiver<NetmapEvent>,
}

impl ControlClient {
    /// Connects, performs the Noise `IK` handshake and enrolls.
    ///
    /// # Errors
    ///
    /// Returns [`ControlError`] if the connection, handshake or enrollment fails.
    pub async fn connect(
        identity: Arc<DeviceIdentity>,
        config: ControlConfig,
    ) -> Result<(Self, Enrollment), ControlError> {
        Self::connect_with(identity, config, READ_IDLE_TIMEOUT).await
    }

    /// Like [`Self::connect`], with an explicit read-idle timeout after which a
    /// silent connection is reported as [`NetmapEvent::Disconnected`].
    ///
    /// # Errors
    ///
    /// Returns [`ControlError`] if the connection, handshake or enrollment fails.
    pub async fn connect_with(
        identity: Arc<DeviceIdentity>,
        config: ControlConfig,
        read_idle_timeout: Duration,
    ) -> Result<(Self, Enrollment), ControlError> {
        tokio::time::timeout(
            CONNECT_TIMEOUT,
            Self::connect_inner(identity, config, read_idle_timeout),
        )
        .await
        .map_err(|_| ControlError::Timeout)?
    }

    async fn connect_inner(
        identity: Arc<DeviceIdentity>,
        config: ControlConfig,
        read_idle_timeout: Duration,
    ) -> Result<(Self, Enrollment), ControlError> {
        let stream = TcpStream::connect(&config.server_addr).await?;
        stream.set_nodelay(true)?;
        let (mut reader, mut writer) = stream.into_split();

        let (handshake, msg1) =
            InitiatorHandshake::start(&identity, config.server_public, CONTROL_PROLOGUE)?;
        writer.write_all(&msg1).await?;
        let mut msg2 = vec![0u8; omegadesk_noise::HANDSHAKE_RESPONSE_LEN];
        reader.read_exact(&mut msg2).await?;
        let session = handshake.complete(&identity, &msg2)?;
        let (mut tx, mut rx) = session.split();

        let (preauth_key, deployment_token) = if is_deployment_token(&config.preauth_key) {
            (String::new(), config.preauth_key.trim().to_owned())
        } else {
            (config.preauth_key.clone(), String::new())
        };
        let request = envelope(control::control_envelope::Payload::EnrollRequest(
            control::EnrollRequest {
                protocol_version: CONTROL_PROTOCOL_VERSION,
                preauth_key,
                hostname: config.hostname.clone(),
                endpoints: config.endpoints.iter().map(ToString::to_string).collect(),
                quicksupport_id: config
                    .quicksupport_id
                    .map(QuickSupportId::digits)
                    .unwrap_or_default(),
                deployment_token,
            },
        ));
        writer
            .write_all(&tx.write_frame(&request.encode_to_vec())?)
            .await?;
        let reply = read_control(&mut reader, &mut rx).await?;
        let response = match reply.payload {
            Some(control::control_envelope::Payload::EnrollResponse(response)) => response,
            Some(control::control_envelope::Payload::Error(error)) => {
                return Err(ControlError::Rejected {
                    code: control::ControlErrorCode::try_from(error.code)
                        .unwrap_or(control::ControlErrorCode::Unspecified),
                    message: error.message,
                });
            }
            _ => return Err(ControlError::Malformed("expected EnrollResponse")),
        };
        let self_node = response
            .self_node
            .as_ref()
            .ok_or(ControlError::Malformed("missing self node"))
            .and_then(PeerInfo::from_proto)?;
        let peers = response
            .peers
            .iter()
            .map(PeerInfo::from_proto)
            .collect::<Result<Vec<_>, _>>()?;
        let relays = response
            .relays
            .iter()
            .map(RelayGrant::from_proto)
            .collect::<Result<Vec<_>, _>>()?;
        // Coordinators that predate `peer_count` send 0: the list is then complete.
        let total_peers = usize::try_from(response.peer_count)
            .unwrap_or(usize::MAX)
            .max(peers.len());

        let (outbound_tx, outbound_rx) = mpsc::channel(64);
        let (events_tx, events_rx) = mpsc::channel(256);
        let (ticket_waiters_tx, ticket_waiters_rx) = mpsc::unbounded_channel();
        let (lookup_waiters_tx, lookup_waiters_rx) = mpsc::unbounded_channel();
        tokio::spawn(writer_loop(
            writer,
            tx,
            outbound_rx,
            ticket_waiters_tx,
            lookup_waiters_tx,
        ));
        tokio::spawn(reader_loop(
            reader,
            rx,
            events_tx,
            ticket_waiters_rx,
            lookup_waiters_rx,
            read_idle_timeout,
        ));

        Ok((
            Self {
                handle: ControlHandle {
                    outbound: outbound_tx,
                },
                events: events_rx,
            },
            Enrollment {
                self_node,
                peers,
                relays,
                total_peers,
            },
        ))
    }

    /// Handle for sending updates and ticket requests.
    #[must_use]
    pub fn handle(&self) -> ControlHandle {
        self.handle.clone()
    }

    /// Receives the next netmap event; `None` after [`NetmapEvent::Disconnected`].
    pub async fn next_event(&mut self) -> Option<NetmapEvent> {
        self.events.recv().await
    }

    /// Splits into the handle and the raw event receiver.
    #[must_use]
    pub fn into_parts(self) -> (ControlHandle, mpsc::Receiver<NetmapEvent>) {
        (self.handle, self.events)
    }
}

fn envelope(payload: control::control_envelope::Payload) -> control::ControlEnvelope {
    control::ControlEnvelope {
        payload: Some(payload),
    }
}

async fn read_control(
    reader: &mut OwnedReadHalf,
    rx: &mut NoiseReceiver,
) -> Result<control::ControlEnvelope, ControlError> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await?;
    let body_len = usize::try_from(u32::from_be_bytes(len_buf))
        .map_err(|_| ControlError::Malformed("length"))?;
    if body_len > MAX_FRAME_CIPHERTEXT_LEN {
        return Err(ControlError::Noise(NoiseError::FrameTooLarge(body_len)));
    }
    let mut body = vec![0u8; body_len];
    reader.read_exact(&mut body).await?;
    let plain = rx.read_body(&body)?;
    Ok(control::ControlEnvelope::decode(plain.as_slice())?)
}

/// A pending QuickSupport lookup: the ID asked for and who waits for the answer.
type LookupWaiter = (QuickSupportId, oneshot::Sender<Option<PeerInfo>>);

async fn writer_loop(
    mut writer: OwnedWriteHalf,
    mut tx: NoiseSender,
    mut outbound: mpsc::Receiver<Outbound>,
    ticket_waiters: mpsc::UnboundedSender<oneshot::Sender<Vec<RelayGrant>>>,
    lookup_waiters: mpsc::UnboundedSender<LookupWaiter>,
) {
    let mut keepalive = tokio::time::interval(KEEPALIVE_INTERVAL);
    keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    keepalive.tick().await;
    let mut sequence = 0u64;
    loop {
        let msg = tokio::select! {
            item = outbound.recv() => match item {
                Some(Outbound::Message(msg)) => *msg,
                Some(Outbound::TicketRequest(waiter)) => {
                    if ticket_waiters.send(waiter).is_err() {
                        break;
                    }
                    envelope(control::control_envelope::Payload::RelayTicketRequest(
                        control::RelayTicketRequest {},
                    ))
                }
                Some(Outbound::QuickSupportLookup(id, waiter)) => {
                    if lookup_waiters.send((id, waiter)).is_err() {
                        break;
                    }
                    envelope(control::control_envelope::Payload::QuickSupportLookupRequest(
                        control::QuickSupportLookupRequest {
                            quicksupport_id: id.digits(),
                        },
                    ))
                }
                None => break,
            },
            _ = keepalive.tick() => {
                sequence += 1;
                envelope(control::control_envelope::Payload::Keepalive(control::Keepalive { sequence }))
            }
        };
        let Ok(frame) = tx.write_frame(&msg.encode_to_vec()) else {
            break;
        };
        if writer.write_all(&frame).await.is_err() {
            break;
        }
    }
    let _ = writer.shutdown().await;
}

async fn reader_loop(
    mut reader: OwnedReadHalf,
    mut rx: NoiseReceiver,
    events: mpsc::Sender<NetmapEvent>,
    mut ticket_waiters: mpsc::UnboundedReceiver<oneshot::Sender<Vec<RelayGrant>>>,
    mut lookup_waiters: mpsc::UnboundedReceiver<LookupWaiter>,
    read_idle_timeout: Duration,
) {
    // Lookups are answered in request order; waiters whose caller gave up
    // (dropped receiver) are skipped when matching.
    let mut pending_lookups: std::collections::VecDeque<LookupWaiter> =
        std::collections::VecDeque::new();
    let reason = loop {
        let msg = match tokio::time::timeout(read_idle_timeout, read_control(&mut reader, &mut rx))
            .await
        {
            Ok(Ok(msg)) => msg,
            Ok(Err(error)) => break error.to_string(),
            Err(_) => break format!("no control traffic for {read_idle_timeout:?}"),
        };
        match msg.payload {
            Some(control::control_envelope::Payload::NetmapBatch(batch)) => {
                for delta in batch.deltas {
                    let event = match delta.change {
                        Some(control::netmap_delta::Change::PeerUpserted(info)) => {
                            match PeerInfo::from_proto(&info) {
                                Ok(peer) => NetmapEvent::PeerUpserted(Box::new(peer)),
                                Err(error) => {
                                    warn!(%error, "ignoring malformed peer in netmap");
                                    continue;
                                }
                            }
                        }
                        Some(control::netmap_delta::Change::EndpointsUpdated(update)) => {
                            let Ok(signing_key) = <[u8; 32]>::try_from(update.signing_key.as_ref())
                            else {
                                continue;
                            };
                            NetmapEvent::EndpointsUpdated {
                                signing_key,
                                endpoints: parse_endpoints(&update.endpoints),
                            }
                        }
                        Some(control::netmap_delta::Change::PeerRemoved(key)) => {
                            let Ok(signing_key) = <[u8; 32]>::try_from(key.as_ref()) else {
                                continue;
                            };
                            NetmapEvent::PeerRemoved { signing_key }
                        }
                        None => continue,
                    };
                    if events.send(event).await.is_err() {
                        return;
                    }
                }
            }
            Some(control::control_envelope::Payload::RelayTicketResponse(response)) => {
                let grants: Vec<RelayGrant> = response
                    .relays
                    .iter()
                    .filter_map(|r| RelayGrant::from_proto(r).ok())
                    .collect();
                if let Ok(waiter) = ticket_waiters.try_recv() {
                    let _ = waiter.send(grants);
                } else {
                    debug!("unsolicited relay ticket response");
                }
            }
            Some(control::control_envelope::Payload::QuickSupportLookupResponse(response)) => {
                while let Ok(waiter) = lookup_waiters.try_recv() {
                    pending_lookups.push_back(waiter);
                }
                let peer = response.node.as_ref().and_then(|info| {
                    PeerInfo::from_proto(info)
                        .inspect_err(|error| warn!(%error, "malformed QuickSupport lookup reply"))
                        .ok()
                });
                let position = pending_lookups
                    .iter()
                    .position(|(id, _)| id.digits() == response.quicksupport_id);
                if let Some((_, waiter)) = position.and_then(|index| pending_lookups.remove(index))
                {
                    let _ = waiter.send(peer);
                } else {
                    debug!("unsolicited QuickSupport lookup response");
                }
            }
            Some(control::control_envelope::Payload::ScriptDispatch(dispatch)) => {
                if events
                    .send(NetmapEvent::ScriptDispatch(Box::new(dispatch)))
                    .await
                    .is_err()
                {
                    return;
                }
            }
            Some(control::control_envelope::Payload::Error(error)) => {
                break format!("coordinator error: {}", error.message);
            }
            Some(
                control::control_envelope::Payload::EnrollRequest(_)
                | control::control_envelope::Payload::EnrollResponse(_)
                | control::control_envelope::Payload::EndpointUpdate(_)
                | control::control_envelope::Payload::RelayTicketRequest(_)
                | control::control_envelope::Payload::Keepalive(_)
                | control::control_envelope::Payload::QuickSupportLookupRequest(_)
                | control::control_envelope::Payload::InventoryReport(_)
                | control::control_envelope::Payload::ScriptResult(_),
            )
            | None => {}
        }
    };
    let _ = events.send(NetmapEvent::Disconnected(reason)).await;
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use omegadesk_server::control_server;
    use omegadesk_server::{Coordinator, RelayNode};
    use tokio::net::TcpListener;

    use super::*;

    async fn start_coordinator(
        relay_key: [u8; 32],
    ) -> (SocketAddr, DevicePublic, String, Arc<Mutex<Coordinator>>) {
        let server_id = Arc::new(DeviceIdentity::generate());
        let mut coord = Coordinator::new([7u8; 32]);
        coord.add_relay(RelayNode {
            address: "relay.test:443".into(),
            exchange_key: relay_key,
            stun_address: Some("relay.test:3478".into()),
        });
        let key = coord
            .create_preauth_key("acme", true, true, vec!["tag:test".into()], None)
            .unwrap();
        let coordinator = Arc::new(Mutex::new(coord));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let public = server_id.public();
        let coord_clone = Arc::clone(&coordinator);
        tokio::spawn(control_server::serve(listener, server_id, coord_clone));
        (addr, public, key, coordinator)
    }

    #[tokio::test]
    async fn enrolls_receives_netmap_deltas_and_refreshes_tickets() {
        let relay_key = [9u8; 32];
        let (addr, server_public, key, _coord) = start_coordinator(relay_key).await;

        let alice = Arc::new(DeviceIdentity::generate());
        let (mut alice_ctl, alice_enrollment) = ControlClient::connect(
            Arc::clone(&alice),
            ControlConfig {
                server_addr: addr.to_string(),
                server_public,
                preauth_key: key.clone(),
                hostname: "Alice Desk".into(),
                endpoints: vec!["192.168.1.2:7070".parse().unwrap()],
                quicksupport_id: None,
            },
        )
        .await
        .unwrap();
        assert_eq!(alice_enrollment.self_node.fqdn, "alice-desk.omega");
        assert_eq!(alice_enrollment.peers.len(), 0);
        assert_eq!(alice_enrollment.relays.len(), 1);
        assert_eq!(alice_enrollment.relays[0].exchange_key, relay_key);
        assert_eq!(
            alice_enrollment.relays[0].ticket.client_exchange_key,
            alice.public().exchange_key_bytes()
        );
        assert_eq!(
            alice_enrollment.relays[0].stun_address.as_deref(),
            Some("relay.test:3478")
        );

        // Bob enrolls: Alice receives PeerUpserted(bob).
        let bob = Arc::new(DeviceIdentity::generate());
        let (bob_ctl, bob_enrollment) = ControlClient::connect(
            Arc::clone(&bob),
            ControlConfig {
                server_addr: addr.to_string(),
                server_public,
                preauth_key: key,
                hostname: "bob".into(),
                endpoints: vec![],
                quicksupport_id: None,
            },
        )
        .await
        .unwrap();
        assert_eq!(bob_enrollment.peers.len(), 1);
        assert_eq!(bob_enrollment.peers[0].id(), alice.id());
        let event = tokio::time::timeout(Duration::from_secs(5), alice_ctl.next_event())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(event, NetmapEvent::PeerUpserted(peer) if peer.id() == bob.id()));

        // Bob updates endpoints: Alice receives EndpointsUpdated.
        bob_ctl
            .handle()
            .update_endpoints(vec!["203.0.113.5:40000".parse().unwrap()])
            .await
            .unwrap();
        let event = tokio::time::timeout(Duration::from_secs(5), alice_ctl.next_event())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            event,
            NetmapEvent::EndpointsUpdated {
                signing_key: bob.public().signing_key_bytes(),
                endpoints: vec!["203.0.113.5:40000".parse().unwrap()],
            }
        );

        // Fresh tickets on request.
        let grants = alice_ctl.handle().request_relay_tickets().await.unwrap();
        assert_eq!(grants.len(), 1);
        assert_ne!(
            grants[0].ticket.ticket_id,
            alice_enrollment.relays[0].ticket.ticket_id
        );

        // Bob (ephemeral) disconnects: Alice receives PeerRemoved.
        drop(bob_ctl);
        let event = tokio::time::timeout(Duration::from_secs(5), alice_ctl.next_event())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            event,
            NetmapEvent::PeerRemoved {
                signing_key: bob.public().signing_key_bytes()
            }
        );
    }

    #[tokio::test]
    async fn quicksupport_hosts_get_an_id_that_peers_resolve_until_they_leave() {
        let (addr, server_public, key, _coord) = start_coordinator([3u8; 32]).await;

        let technician = Arc::new(DeviceIdentity::generate());
        let (tech_ctl, _) = ControlClient::connect(
            Arc::clone(&technician),
            ControlConfig {
                server_addr: addr.to_string(),
                server_public,
                preauth_key: key.clone(),
                hostname: "tech".into(),
                endpoints: vec![],
                quicksupport_id: None,
            },
        )
        .await
        .unwrap();
        // Nothing holds the ID yet.
        let wanted: QuickSupportId = "123 456 789".parse().unwrap();
        assert_eq!(
            tech_ctl.handle().lookup_quicksupport(wanted).await.unwrap(),
            None
        );

        // The end user's machine enrolls proposing an ID; it comes back assigned.
        let host = Arc::new(DeviceIdentity::generate());
        let (host_ctl, enrollment) = ControlClient::connect(
            Arc::clone(&host),
            ControlConfig {
                server_addr: addr.to_string(),
                server_public,
                preauth_key: key,
                hostname: "QuickSupport".into(),
                endpoints: vec![],
                quicksupport_id: Some(wanted),
            },
        )
        .await
        .unwrap();
        assert_eq!(enrollment.self_node.quicksupport_id, Some(wanted));
        assert!(
            enrollment.self_node.ephemeral,
            "QuickSupport hosts are ephemeral"
        );

        // The technician resolves the ID through the coordinator...
        let found = tech_ctl
            .handle()
            .lookup_quicksupport(wanted)
            .await
            .unwrap()
            .expect("the host owns the ID");
        assert_eq!(found.id(), host.id());
        assert_eq!(found.quicksupport_id, Some(wanted));
        // ...and concurrent lookups are matched by ID, not by arrival order.
        let other: QuickSupportId = "987654321".parse().unwrap();
        let handle = tech_ctl.handle();
        let (missing, present) = tokio::join!(
            handle.lookup_quicksupport(other),
            handle.lookup_quicksupport(wanted)
        );
        assert_eq!(missing.unwrap(), None);
        assert_eq!(present.unwrap().map(|p| p.id()), Some(host.id()));

        // The host leaves: its ID expires immediately.
        drop(host_ctl);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            if tech_ctl
                .handle()
                .lookup_quicksupport(wanted)
                .await
                .unwrap()
                .is_none()
            {
                break;
            }
            assert!(tokio::time::Instant::now() < deadline, "ID never expired");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    #[tokio::test]
    async fn rejects_bad_preauth_key_and_wrong_server_key() {
        let (addr, server_public, _key, _coord) = start_coordinator([1u8; 32]).await;
        let node = Arc::new(DeviceIdentity::generate());
        let err = ControlClient::connect(
            Arc::clone(&node),
            ControlConfig {
                server_addr: addr.to_string(),
                server_public,
                preauth_key: "odk_nope_nope".into(),
                hostname: "x".into(),
                endpoints: vec![],
                quicksupport_id: None,
            },
        )
        .await
        .err()
        .unwrap();
        assert!(matches!(
            err,
            ControlError::Rejected {
                code: control::ControlErrorCode::InvalidPreauthKey,
                ..
            }
        ));

        let impostor = DeviceIdentity::generate().public();
        let err = ControlClient::connect(
            node,
            ControlConfig {
                server_addr: addr.to_string(),
                server_public: impostor,
                preauth_key: "odk_x_y".into(),
                hostname: "x".into(),
                endpoints: vec![],
                quicksupport_id: None,
            },
        )
        .await
        .err()
        .unwrap();
        assert!(matches!(
            err,
            ControlError::Io(_) | ControlError::Noise(_) | ControlError::Closed
        ));
    }

    type SharedRmm = Arc<Mutex<omegadesk_server::rmm_service::RmmService>>;

    /// A coordinator whose RMM service the test can inspect, plus a deployment
    /// token for tenant `acme`, site `site-sp`.
    async fn start_rmm_coordinator() -> (SocketAddr, DevicePublic, SharedRmm, String) {
        let server_id = Arc::new(DeviceIdentity::generate());
        let mut coord = Coordinator::new([5u8; 32]);
        let preauth_key = coord
            .create_preauth_key("acme", true, false, vec![], None)
            .unwrap();
        let coordinator = Arc::new(Mutex::new(coord));
        let rmm: SharedRmm = Arc::new(Mutex::new(
            omegadesk_server::rmm_service::RmmService::in_memory(),
        ));
        let token = rmm
            .lock()
            .unwrap()
            .create_deployment_link("acme", "site-sp", preauth_key, u64::MAX, 0)
            .1;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let public = server_id.public();
        tokio::spawn(control_server::serve_with(
            listener,
            server_id,
            coordinator,
            Arc::clone(&rmm),
        ));
        (addr, public, rmm, token)
    }

    async fn wait_until(mut condition: impl FnMut() -> bool) {
        tokio::time::timeout(Duration::from_secs(5), async {
            while !condition() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("condition never became true");
    }

    fn config(
        addr: SocketAddr,
        public: DevicePublic,
        credential: &str,
        host: &str,
    ) -> ControlConfig {
        ControlConfig {
            server_addr: addr.to_string(),
            server_public: public,
            preauth_key: credential.to_owned(),
            hostname: host.to_owned(),
            endpoints: vec![],
            quicksupport_id: None,
        }
    }

    #[tokio::test]
    async fn deployment_tokens_enroll_and_rmm_messages_ride_the_control_stream() {
        let (addr, public, rmm, token) = start_rmm_coordinator().await;
        assert!(is_deployment_token(&token));
        assert!(!is_deployment_token("odk_a_b"));

        let node = Arc::new(DeviceIdentity::generate());
        let (mut ctl, enrollment) =
            ControlClient::connect(Arc::clone(&node), config(addr, public, &token, "pc"))
                .await
                .unwrap();
        assert_eq!(enrollment.self_node.tenant, "acme");
        {
            let guard = rmm.lock().unwrap();
            let inventory = guard.inventory(node.id()).unwrap();
            assert_eq!(inventory.site_id.as_deref(), Some("site-sp"));
            assert!(guard.is_online(node.id()));
        }

        // Inventory reaches the service; a dispatch reaches the node; its result is stored.
        ctl.handle()
            .send_inventory(control::InventoryReport {
                hostname: "PC".into(),
                cpu_utilization_pct: 7,
                ..Default::default()
            })
            .await
            .unwrap();
        wait_until(|| {
            rmm.lock()
                .unwrap()
                .inventory(node.id())
                .is_some_and(|inv| inv.cpu_utilization_pct == 7)
        })
        .await;
        let (_, dispatch) = rmm
            .lock()
            .unwrap()
            .run_script(
                "pc",
                "",
                Some(omegadesk_server::rmm::ScriptingShell::Bash),
                "echo hi",
                5,
            )
            .unwrap();
        let event = tokio::time::timeout(Duration::from_secs(5), ctl.next_event())
            .await
            .unwrap()
            .unwrap();
        let NetmapEvent::ScriptDispatch(script) = event else {
            panic!("expected a ScriptDispatch, got {event:?}");
        };
        assert_eq!(
            dispatch,
            omegadesk_server::rmm_service::Dispatch::Sent(script.run_id)
        );
        assert_eq!(script.content, "echo hi");
        assert_eq!(script.timeout_secs, 5);
        ctl.handle()
            .send_script_result(control::ScriptResult {
                run_id: script.run_id,
                script_id: script.script_id.clone(),
                exit_code: 0,
                stdout: "hi\n".into(),
                ..Default::default()
            })
            .await
            .unwrap();
        wait_until(|| !rmm.lock().unwrap().results(Some(node.id()), 1).is_empty()).await;
        assert_eq!(
            rmm.lock().unwrap().results(Some(node.id()), 1)[0]
                .outcome
                .stdout,
            "hi\n"
        );

        // Disconnecting marks the device offline in the service.
        drop(ctl);
        wait_until(|| !rmm.lock().unwrap().is_online(node.id())).await;
    }

    #[tokio::test]
    async fn forged_deployment_tokens_are_rejected_with_their_own_code() {
        let (addr, public, _rmm, _token) = start_rmm_coordinator().await;
        let stranger = Arc::new(DeviceIdentity::generate());
        let err = ControlClient::connect(stranger, config(addr, public, "odl_nope_ff", "x"))
            .await
            .err()
            .unwrap();
        assert!(matches!(
            err,
            ControlError::Rejected {
                code: control::ControlErrorCode::InvalidDeploymentToken,
                ..
            }
        ));
    }

    #[test]
    fn parses_server_key() {
        let id = DeviceIdentity::generate();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&id.public().signing_key_bytes());
        bytes.extend_from_slice(&id.public().exchange_key_bytes());
        let hex = data_encoding::HEXLOWER.encode(&bytes);
        assert_eq!(parse_server_key(&hex).unwrap(), id.public());
        assert!(matches!(
            parse_server_key("abcd"),
            Err(ControlError::InvalidServerKey)
        ));
    }

    #[tokio::test]
    async fn silent_coordinator_is_reported_as_disconnected() {
        let (addr, server_public, key, _coord) = start_coordinator([3u8; 32]).await;
        let node = Arc::new(DeviceIdentity::generate());
        // The coordinator only echoes keepalives (sent every 30 s), so a tight
        // idle deadline fires without any traffic: a blackholed path is
        // detected and reported instead of waiting forever.
        let (mut ctl, _enrollment) = ControlClient::connect_with(
            node,
            ControlConfig {
                server_addr: addr.to_string(),
                server_public,
                preauth_key: key,
                hostname: "quiet".into(),
                endpoints: vec![],
                quicksupport_id: None,
            },
            Duration::from_millis(300),
        )
        .await
        .unwrap();
        let event = tokio::time::timeout(Duration::from_secs(5), ctl.next_event())
            .await
            .expect("idle deadline must fire");
        assert!(
            matches!(event, Some(NetmapEvent::Disconnected(ref reason)) if reason.contains("no control traffic")),
            "{event:?}"
        );
    }

    /// Phase 5, in process over the real control protocol: with a policy loaded the
    /// coordinator hands every node a filtered netmap whose peers carry the session
    /// grant, and a policy reload reaches the connected nodes as deltas.
    #[tokio::test]
    #[allow(clippy::too_many_lines, reason = "one scenario over the real protocol")]
    async fn policy_filters_the_netmap_received_over_the_control_channel() {
        let (addr, server_public, _key, coord) = start_coordinator([5u8; 32]).await;
        let (helpdesk_key, server_key, guest_key) = {
            let mut guard = coord.lock().unwrap();
            (
                guard
                    .create_preauth_key_for_user(
                        "acme",
                        "alice@example.com",
                        true,
                        false,
                        vec!["tag:helpdesk".into()],
                        None,
                    )
                    .unwrap(),
                guard
                    .create_preauth_key("acme", true, false, vec!["tag:servers".into()], None)
                    .unwrap(),
                guard
                    .create_preauth_key("acme", true, false, vec!["tag:guest".into()], None)
                    .unwrap(),
            )
        };
        let policy = omegadesk_policy::PolicyV2::parse_hujson(
            r#"{ "sessions": [
                { "action": "check", "src": ["tag:helpdesk"], "dst": ["tag:servers"], "record": true }
            ] }"#,
        )
        .unwrap();
        coord.lock().unwrap().set_policy(Some(policy));

        let connect = |identity: Arc<DeviceIdentity>, key: String, hostname: &str| {
            let config = ControlConfig {
                server_addr: addr.to_string(),
                server_public,
                preauth_key: key,
                hostname: hostname.to_owned(),
                endpoints: vec![],
                quicksupport_id: None,
            };
            ControlClient::connect(identity, config)
        };
        let server = Arc::new(DeviceIdentity::generate());
        let (mut server_ctl, server_enrollment) =
            connect(Arc::clone(&server), server_key, "server")
                .await
                .unwrap();
        assert_eq!(server_enrollment.peers, Vec::<PeerInfo>::new());

        // The guest is enrolled but invisible to the server, and sees nobody.
        let guest = Arc::new(DeviceIdentity::generate());
        let (mut guest_ctl, guest_enrollment) = connect(Arc::clone(&guest), guest_key, "guest")
            .await
            .unwrap();
        assert_eq!(guest_enrollment.peers, Vec::<PeerInfo>::new());

        // Helpdesk appears at the server with its grant; the guest hears nothing.
        let helpdesk = Arc::new(DeviceIdentity::generate());
        let (_helpdesk_ctl, helpdesk_enrollment) =
            connect(Arc::clone(&helpdesk), helpdesk_key, "helpdesk")
                .await
                .unwrap();
        assert_eq!(helpdesk_enrollment.self_node.user, "alice@example.com");
        assert_eq!(helpdesk_enrollment.peers.len(), 1);
        let server_as_seen = &helpdesk_enrollment.peers[0];
        assert_eq!(server_as_seen.id(), server.id());
        assert_eq!(
            server_as_seen.session,
            Some(SessionDecision::DENIED),
            "the server may not open a session on the helpdesk machine"
        );
        let event = tokio::time::timeout(Duration::from_secs(5), server_ctl.next_event())
            .await
            .unwrap()
            .unwrap();
        let NetmapEvent::PeerUpserted(peer) = event else {
            panic!("expected PeerUpserted, got {event:?}");
        };
        assert_eq!(peer.id(), helpdesk.id());
        let grant = peer.session.expect("grant travels with the peer");
        assert!(grant.allowed && grant.require_mfa && grant.record);
        assert!(!grant.watermark);

        // Reload: the guest becomes a helpdesk by policy and shows up at the server.
        let widened = omegadesk_policy::PolicyV2::parse_hujson(
            r#"{ "sessions": [
                { "action": "check", "src": ["tag:helpdesk"], "dst": ["tag:servers"], "record": true },
                { "action": "accept", "src": ["tag:guest"], "dst": ["tag:servers"], "watermark": true }
            ] }"#,
        )
        .unwrap();
        let sent = coord.lock().unwrap().set_policy(Some(widened));
        assert!(sent >= 2, "{sent}");
        let event = tokio::time::timeout(Duration::from_secs(5), server_ctl.next_event())
            .await
            .unwrap()
            .unwrap();
        let NetmapEvent::PeerUpserted(peer) = event else {
            panic!("expected PeerUpserted, got {event:?}");
        };
        assert_eq!(peer.id(), guest.id());
        let grant = peer.session.unwrap();
        assert!(grant.allowed && grant.watermark && !grant.require_mfa);
        let event = tokio::time::timeout(Duration::from_secs(5), guest_ctl.next_event())
            .await
            .unwrap()
            .unwrap();
        assert!(
            matches!(&event, NetmapEvent::PeerUpserted(peer) if peer.id() == server.id()),
            "{event:?}"
        );

        // Tighten again: the guest loses the server.
        let narrow = omegadesk_policy::PolicyV2::parse_hujson(r#"{ "sessions": [] }"#).unwrap();
        coord.lock().unwrap().set_policy(Some(narrow));
        let event = tokio::time::timeout(Duration::from_secs(5), guest_ctl.next_event())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            event,
            NetmapEvent::PeerRemoved {
                signing_key: server.public().signing_key_bytes()
            }
        );
    }
}
