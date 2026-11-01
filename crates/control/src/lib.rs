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

use omegadesk_identity::{DeviceId, DeviceIdentity, DevicePublic, IdentityError};
use omegadesk_noise::{
    InitiatorHandshake, MAX_FRAME_CIPHERTEXT_LEN, NoiseError, NoiseReceiver, NoiseSender,
};
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
#[derive(Debug, Clone, PartialEq, Eq)]
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
    /// The control connection ended; the node must re-enroll.
    Disconnected(String),
}

/// Configuration for [`ControlClient::connect`].
#[derive(Debug, Clone)]
pub struct ControlConfig {
    /// `host:port` of the coordinator.
    pub server_addr: String,
    /// Coordinator public identity (`--server-key`).
    pub server_public: DevicePublic,
    /// `odk_<prefix>_<secret>` pre-authorized key.
    pub preauth_key: String,
    /// Requested hostname.
    pub hostname: String,
    /// Direct UDP endpoints known at startup.
    pub endpoints: Vec<SocketAddr>,
}

enum Outbound {
    Message(Box<control::ControlEnvelope>),
    TicketRequest(oneshot::Sender<Vec<RelayGrant>>),
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

        let request = envelope(control::control_envelope::Payload::EnrollRequest(
            control::EnrollRequest {
                protocol_version: CONTROL_PROTOCOL_VERSION,
                preauth_key: config.preauth_key.clone(),
                hostname: config.hostname.clone(),
                endpoints: config.endpoints.iter().map(ToString::to_string).collect(),
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
        tokio::spawn(writer_loop(writer, tx, outbound_rx, ticket_waiters_tx));
        tokio::spawn(reader_loop(
            reader,
            rx,
            events_tx,
            ticket_waiters_rx,
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

async fn writer_loop(
    mut writer: OwnedWriteHalf,
    mut tx: NoiseSender,
    mut outbound: mpsc::Receiver<Outbound>,
    ticket_waiters: mpsc::UnboundedSender<oneshot::Sender<Vec<RelayGrant>>>,
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
    read_idle_timeout: Duration,
) {
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
            Some(control::control_envelope::Payload::Error(error)) => {
                break format!("coordinator error: {}", error.message);
            }
            Some(
                control::control_envelope::Payload::EnrollRequest(_)
                | control::control_envelope::Payload::EnrollResponse(_)
                | control::control_envelope::Payload::EndpointUpdate(_)
                | control::control_envelope::Payload::RelayTicketRequest(_)
                | control::control_envelope::Payload::Keepalive(_),
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
}
