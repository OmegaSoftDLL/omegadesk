//! Sans-I/O mesh connectivity engine (`omegadesk-mesh`).
//!
//! Combines two reference designs:
//! - **Firezone `snownet`** (`rust/libs/connlib/snownet/src/node.rs`, Apache-2.0):
//!   a sans-I/O state machine driven purely by timestamps and buffers
//!   (`poll_timeout`, `handle_timeout`, `handle_receive`, `poll_transmit`,
//!   `poll_event`, `encapsulate`), so NAT traversal and relay failover are
//!   deterministic and testable without sockets.
//! - **Tailscale `disco`, `magicsock` and `net/stun`** (BSD-3-Clause): STUN
//!   discovery of the reflexive endpoint, `CallMeMaybe` -> `Ping` -> `Pong`
//!   hole punching, relay fallback within [`RELAY_FALLBACK_TIMEOUT`], and the
//!   `magicsock` trust model for a direct path: a validated address is trusted
//!   for [`TRUST_UDP_ADDR_DURATION`], kept alive with a heartbeat `Ping` every
//!   [`HEARTBEAT_INTERVAL`], and abandoned (back to the relay) when no `Pong`
//!   arrives before the trust expires (`trustUDPAddrDuration`,
//!   `heartbeatInterval` in `wgengine/magicsock/magicsock.go`).
//!
//! Tunnel data packets use ChaCha20-Poly1305 with a **direction-specific key
//! bound to a per-process random epoch**: `key = H(dh, sender, receiver, sender_epoch)`.
//! The two directions therefore never share a key, a restart picks a fresh
//! epoch (fresh key, counters restart safely) and the receiver's replay window
//! is scoped to the sender's epoch.

pub mod disco;
pub mod peer_routing;
pub mod stun;

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use omegadesk_identity::{DeviceId, DeviceIdentity, DevicePublic};
use omegadesk_tun::{IpPacket, TunError};
use rand_core::{OsRng, RngCore};
use ring::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey};
use sha2::{Digest, Sha256};
use x25519_dalek::PublicKey as X25519Public;

pub use disco::{DiscoError, DiscoMessage, MAGIC as DISCO_MAGIC, TxId, random_tx_id};
pub use peer_routing::{
    DEFAULT_LAZY_CONN_INACTIVITY_THRESHOLD, LazyConnManager, LazyPeerState, LinkNeighbor,
    LinkStateAdvertisement, LinkStateRouter, PeerRelayCertificate, RoutePath,
};

/// Maximum time to wait for a direct `Pong` before falling back to the relay
/// (1.5 seconds, satisfying the `< 2 s` Phase 2 requirement).
pub const RELAY_FALLBACK_TIMEOUT: Duration = Duration::from_millis(1500);

/// Interval between direct-path probes (`CallMeMaybe` + `Ping`) while the
/// relay fallback deadline has not passed yet.
pub const DIRECT_PROBE_INTERVAL: Duration = Duration::from_millis(500);

/// Interval between direct-path upgrade probes once traffic flows over the
/// relay (Tailscale `discoPingInterval`, `tsconst.DefaultPingInterval`).
pub const RELAYED_PROBE_INTERVAL: Duration = Duration::from_secs(5);

/// Heartbeat `Ping` interval on a validated direct path (Tailscale `heartbeatInterval`).
pub const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(3);

/// How long a validated direct address stays trusted without a new `Pong`
/// (Tailscale `trustUDPAddrDuration`).
pub const TRUST_UDP_ADDR_DURATION: Duration = Duration::from_millis(6500);

/// Time after which an unanswered `Ping` or STUN request is forgotten
/// (Tailscale `tsconst.DefaultPingTimeout`).
pub const PING_TIMEOUT: Duration = Duration::from_secs(5);

/// Interval between STUN refreshes of the reflexive endpoint while peers exist
/// (Tailscale re-runs `netcheck` roughly every 30 s while active).
pub const STUN_REFRESH_INTERVAL: Duration = Duration::from_secs(30);

/// Minimum latency improvement before an already validated direct address is
/// replaced by another candidate (Tailscale `goodEnoughLatency`).
pub const GOOD_ENOUGH_LATENCY: Duration = Duration::from_millis(5);

/// Four-byte header identifying an encrypted tunnel data packet on the wire
/// (analogous to WireGuard's Type 4 Transport Data header).
pub const DATA_HEADER_MAGIC: [u8; 4] = *b"ODWG";

/// Tunnel data header: 4B magic + 32B sender X25519 + 8B sender epoch + 8B LE counter.
const DATA_HEADER_LEN: usize = 4 + 32 + 8 + 8;
const TAG_LEN: usize = 16;

/// Active transport path for a peer in the mesh, modeled after Firezone's
/// `snownet::ConnectionPath`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionPath {
    /// Direct peer-to-peer UDP socket address validated via `disco`.
    Direct {
        /// Validated remote UDP socket address of the peer.
        remote: SocketAddr,
    },
    /// Relayed through an `omegadesk-relay` server addressed by the peer's
    /// 32-byte X25519 public key.
    Relayed {
        /// Peer's 32-byte X25519 public key used as its relay destination.
        peer_exchange_key: [u8; 32],
    },
}

/// Destination for an outbound packet produced by [`MeshNode::poll_transmit`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransmitTarget {
    /// Send directly as a UDP datagram to `SocketAddr`.
    DirectUdp(SocketAddr),
    /// Send over the relay addressed to the peer's 32-byte X25519 key.
    Relay([u8; 32]),
}

/// Outbound packet queued by the sans-I/O [`MeshNode`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transmit {
    /// Where to send the packet (direct UDP vs relay).
    pub target: TransmitTarget,
    /// Raw wire bytes to transmit.
    pub payload: Vec<u8>,
}

/// Events emitted by [`MeshNode::poll_event`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MeshEvent {
    /// Initial connectivity established with `peer` on `path`.
    Connected {
        /// Peer device identifier.
        peer: DeviceId,
        /// Initial path selected (`Direct` or `Relayed`).
        path: ConnectionPath,
    },
    /// Traffic for `peer` now flows over the relay: either direct probing did
    /// not succeed within [`RELAY_FALLBACK_TIMEOUT`], or a validated direct
    /// path stopped answering heartbeats. Background probing continues.
    FallbackToRelay {
        /// Peer device identifier.
        peer: DeviceId,
    },
    /// A direct UDP path was validated via `disco` `Ping`/`Pong`, upgrading
    /// the peer from the relay to a direct connection.
    PathUpgraded {
        /// Peer device identifier.
        peer: DeviceId,
        /// Validated direct UDP endpoint of the peer.
        remote: SocketAddr,
        /// Measured round-trip latency of the winning `Ping`/`Pong`.
        rtt: Duration,
    },
    /// The set of local endpoints to advertise (LAN + STUN reflexive) changed;
    /// the caller should report [`MeshNode::local_endpoints`] to the coordinator.
    LocalEndpointsChanged(Vec<SocketAddr>),
    /// A peer's exchange key changed; all tunnel state for it was reset.
    PeerKeyRotated {
        /// Peer device identifier.
        peer: DeviceId,
    },
}

/// Errors returned by [`MeshNode`] operations.
#[derive(Debug, thiserror::Error)]
pub enum MeshError {
    /// Peer is not registered in the local netmap.
    #[error("unknown mesh peer: {0}")]
    UnknownPeer(DeviceId),
    /// Disco packet error.
    #[error("disco error: {0}")]
    Disco(#[from] DiscoError),
    /// Tunnel data packet authentication or anti-replay check failed.
    #[error("tunnel packet authentication failed")]
    TunnelAuthFailed,
    /// Decapsulated payload is not a valid IPv4/IPv6 packet.
    #[error("invalid inner IP packet: {0}")]
    InvalidIpPacket(#[from] TunError),
    /// Nonce counter exhausted for the current epoch.
    #[error("tunnel send counter exhausted")]
    CounterExhausted,
}

/// Sliding 64-packet anti-replay window (RFC 6479 / WireGuard style).
#[derive(Debug, Default, Clone)]
struct ReplayWindow {
    highest_seq: u64,
    bitmap: u64,
    initialized: bool,
}

impl ReplayWindow {
    fn check_and_accept(&mut self, seq: u64) -> bool {
        if !self.initialized {
            self.initialized = true;
            self.highest_seq = seq;
            self.bitmap = 1;
            return true;
        }
        if seq > self.highest_seq {
            let shift = seq - self.highest_seq;
            if shift >= 64 {
                self.bitmap = 1;
            } else {
                self.bitmap = (self.bitmap << shift) | 1;
            }
            self.highest_seq = seq;
            true
        } else {
            let diff = self.highest_seq - seq;
            if diff >= 64 {
                return false;
            }
            let mask = 1u64 << diff;
            if (self.bitmap & mask) != 0 {
                return false;
            }
            self.bitmap |= mask;
            true
        }
    }
}

/// Receive-side cipher state for one sender epoch.
#[derive(Debug, Clone)]
struct RecvEpoch {
    epoch: [u8; 8],
    key: [u8; 32],
    replay: ReplayWindow,
}

struct PeerState {
    public: DevicePublic,
    candidates: Vec<SocketAddr>,
    path: ConnectionPath,
    /// Direct path validity (Tailscale `trustBestAddrUntil`).
    trust_until: Option<Instant>,
    best_rtt: Option<Duration>,
    shared_secret: [u8; 32],
    send_key: [u8; 32],
    send_counter: u64,
    /// Receive states for the current and the previous sender epoch (newest
    /// last). Keeping the previous epoch alive lets in-flight packets from
    /// before a peer restart still be checked against their own replay window
    /// instead of resetting it.
    recv: Vec<RecvEpoch>,
    next_probe_at: Instant,
    next_heartbeat_at: Instant,
    fallback_deadline: Option<Instant>,
    inflight_pings: HashMap<TxId, (SocketAddr, Instant)>,
    connected_emitted: bool,
}

/// Sans-I/O mesh connectivity engine managing peer tunnels, STUN, `disco`
/// hole-punching, direct-path trust and relay fallback.
pub struct MeshNode {
    local_identity: DeviceIdentity,
    local_epoch: [u8; 8],
    local_candidates: Vec<SocketAddr>,
    stun_servers: Vec<SocketAddr>,
    inflight_stun: HashMap<stun::TxId, (SocketAddr, Instant)>,
    reflexive: HashMap<SocketAddr, SocketAddr>,
    next_stun_at: Option<Instant>,
    peers_by_id: HashMap<DeviceId, PeerState>,
    peers_by_exchange: HashMap<[u8; 32], DeviceId>,
    transmits: VecDeque<Transmit>,
    events: VecDeque<MeshEvent>,
}

impl MeshNode {
    /// Creates a new sans-I/O [`MeshNode`] for `local_identity` advertising
    /// `local_candidates` as its LAN UDP endpoints and using `stun_servers`
    /// to discover its reflexive endpoint.
    #[must_use]
    pub fn new(
        local_identity: DeviceIdentity,
        local_candidates: Vec<SocketAddr>,
        stun_servers: Vec<SocketAddr>,
    ) -> Self {
        let mut local_epoch = [0u8; 8];
        OsRng.fill_bytes(&mut local_epoch);
        Self {
            local_identity,
            local_epoch,
            local_candidates,
            stun_servers,
            inflight_stun: HashMap::new(),
            reflexive: HashMap::new(),
            next_stun_at: None,
            peers_by_id: HashMap::new(),
            peers_by_exchange: HashMap::new(),
            transmits: VecDeque::new(),
            events: VecDeque::new(),
        }
    }

    /// Local [`DeviceId`] of this node.
    #[must_use]
    pub fn local_id(&self) -> DeviceId {
        self.local_identity.id()
    }

    /// Public identity of this node.
    #[must_use]
    pub fn local_public(&self) -> DevicePublic {
        self.local_identity.public()
    }

    /// Replaces the advertised LAN endpoints (for example after an interface
    /// change) and re-advertises them to every peer on the next probe.
    pub fn set_local_candidates(&mut self, candidates: Vec<SocketAddr>, now: Instant) {
        if candidates == self.local_candidates {
            return;
        }
        self.local_candidates = candidates;
        self.endpoints_changed(now);
    }

    /// All endpoints this node currently advertises: LAN candidates followed
    /// by STUN-discovered reflexive addresses.
    #[must_use]
    pub fn local_endpoints(&self) -> Vec<SocketAddr> {
        let mut out = self.local_candidates.clone();
        for addr in self.reflexive.values() {
            if !out.contains(addr) {
                out.push(*addr);
            }
        }
        out
    }

    /// Starts a STUN refresh immediately (also scheduled automatically every
    /// [`STUN_REFRESH_INTERVAL`] while peers exist).
    pub fn refresh_stun(&mut self, now: Instant) {
        for server in self.stun_servers.clone() {
            let tx_id = stun::new_tx_id();
            self.inflight_stun.insert(tx_id, (server, now));
            self.transmits.push_back(Transmit {
                target: TransmitTarget::DirectUdp(server),
                payload: stun::binding_request(&tx_id),
            });
        }
        if !self.stun_servers.is_empty() {
            self.next_stun_at = Some(now + STUN_REFRESH_INTERVAL);
        }
    }

    /// Registers or updates a peer from the coordinator's netmap and begins
    /// direct UDP probing while keeping the relay path ready.
    ///
    /// If the peer's exchange key changed, all tunnel and path state is reset
    /// and [`MeshEvent::PeerKeyRotated`] is emitted.
    pub fn upsert_peer(
        &mut self,
        peer_public: DevicePublic,
        candidates: Vec<SocketAddr>,
        now: Instant,
    ) {
        let peer_id = peer_public.id();
        let peer_exchange = peer_public.exchange_key_bytes();

        if let Some(existing) = self.peers_by_id.get_mut(&peer_id) {
            if existing.public.exchange_key_bytes() == peer_exchange {
                existing.candidates = candidates;
                existing.next_probe_at = now;
                self.send_probes_for_peer(peer_id, now);
                return;
            }
            let old_key = existing.public.exchange_key_bytes();
            self.peers_by_exchange.remove(&old_key);
            self.peers_by_id.remove(&peer_id);
            self.events
                .push_back(MeshEvent::PeerKeyRotated { peer: peer_id });
        }

        if self.stun_servers.is_empty() {
            // Nothing to discover; still make sure the first probe happens now.
        } else if self.reflexive.is_empty() && self.inflight_stun.is_empty() {
            self.refresh_stun(now);
        }

        let shared_secret = dh_shared(&self.local_identity, &peer_exchange);
        let local_pub = self.local_identity.public().exchange_key_bytes();
        let send_key =
            derive_direction_key(&shared_secret, &local_pub, &peer_exchange, self.local_epoch);
        self.peers_by_exchange.insert(peer_exchange, peer_id);
        self.peers_by_id.insert(
            peer_id,
            PeerState {
                public: peer_public,
                candidates,
                path: ConnectionPath::Relayed {
                    peer_exchange_key: peer_exchange,
                },
                trust_until: None,
                best_rtt: None,
                shared_secret,
                send_key,
                send_counter: 0,
                recv: Vec::new(),
                next_probe_at: now,
                next_heartbeat_at: now + HEARTBEAT_INTERVAL,
                fallback_deadline: Some(now + RELAY_FALLBACK_TIMEOUT),
                inflight_pings: HashMap::new(),
                connected_emitted: false,
            },
        );
        self.send_probes_for_peer(peer_id, now);
    }

    /// Removes `peer` and all of its state (netmap removal or ephemeral node gone).
    pub fn remove_peer(&mut self, peer: DeviceId) {
        if let Some(state) = self.peers_by_id.remove(&peer) {
            self.peers_by_exchange
                .remove(&state.public.exchange_key_bytes());
        }
    }

    /// Returns the currently active [`ConnectionPath`] for `peer`.
    #[must_use]
    pub fn peer_path(&self, peer: DeviceId) -> Option<ConnectionPath> {
        self.peers_by_id.get(&peer).map(|p| p.path)
    }

    /// Resolves the peer that owns a validated direct `remote` address.
    #[must_use]
    pub fn peer_by_direct_addr(&self, remote: SocketAddr) -> Option<DeviceId> {
        self.peers_by_id.iter().find_map(|(id, p)| match p.path {
            ConnectionPath::Direct { remote: r } if r == remote => Some(*id),
            ConnectionPath::Direct { .. } | ConnectionPath::Relayed { .. } => None,
        })
    }

    /// Resolves the peer that owns `exchange_key`.
    #[must_use]
    pub fn peer_by_exchange_key(&self, exchange_key: &[u8; 32]) -> Option<DeviceId> {
        self.peers_by_exchange.get(exchange_key).copied()
    }

    /// Returns the earliest [`Instant`] at which [`Self::handle_timeout`] must be called.
    #[must_use]
    pub fn poll_timeout(&self) -> Option<Instant> {
        let mut earliest: Option<Instant> = None;
        let mut consider = |t: Instant| {
            earliest = Some(earliest.map_or(t, |e| e.min(t)));
        };
        for peer in self.peers_by_id.values() {
            consider(peer.next_probe_at);
            if let Some(deadline) = peer.fallback_deadline {
                consider(deadline);
            }
            if matches!(peer.path, ConnectionPath::Direct { .. }) {
                consider(peer.next_heartbeat_at);
                if let Some(trust) = peer.trust_until {
                    consider(trust);
                }
            }
            if let Some(oldest) = peer.inflight_pings.values().map(|(_, t)| *t).min() {
                consider(oldest + PING_TIMEOUT);
            }
        }
        if let Some(next) = self.next_stun_at {
            consider(next);
        }
        if let Some(oldest) = self.inflight_stun.values().map(|(_, t)| *t).min() {
            consider(oldest + PING_TIMEOUT);
        }
        earliest
    }

    /// Advances internal timers to `now`: relay fallback, direct-path trust
    /// expiry, heartbeats, upgrade probes, STUN refresh and probe expiry.
    pub fn handle_timeout(&mut self, now: Instant) {
        self.inflight_stun
            .retain(|_, (_, sent)| now.saturating_duration_since(*sent) < PING_TIMEOUT);
        if let Some(next) = self.next_stun_at
            && now >= next
            && !self.peers_by_id.is_empty()
        {
            self.refresh_stun(now);
        }

        let peer_ids: Vec<DeviceId> = self.peers_by_id.keys().copied().collect();
        for peer_id in peer_ids {
            let mut probe = false;
            let mut heartbeat_to: Option<SocketAddr> = None;
            if let Some(peer) = self.peers_by_id.get_mut(&peer_id) {
                peer.inflight_pings
                    .retain(|_, (_, sent)| now.saturating_duration_since(*sent) < PING_TIMEOUT);

                match peer.path {
                    ConnectionPath::Direct { remote } => {
                        if peer.trust_until.is_some_and(|trust| now >= trust) {
                            // No Pong for TRUST_UDP_ADDR_DURATION: the path is dead.
                            peer.path = ConnectionPath::Relayed {
                                peer_exchange_key: peer.public.exchange_key_bytes(),
                            };
                            peer.trust_until = None;
                            peer.best_rtt = None;
                            peer.fallback_deadline = None;
                            peer.next_probe_at = now;
                            self.events
                                .push_back(MeshEvent::FallbackToRelay { peer: peer_id });
                            probe = true;
                        } else if now >= peer.next_heartbeat_at {
                            peer.next_heartbeat_at = now + HEARTBEAT_INTERVAL;
                            heartbeat_to = Some(remote);
                        }
                    }
                    ConnectionPath::Relayed { .. } => {
                        if let Some(deadline) = peer.fallback_deadline
                            && now >= deadline
                        {
                            peer.fallback_deadline = None;
                            if !peer.connected_emitted {
                                peer.connected_emitted = true;
                                self.events.push_back(MeshEvent::Connected {
                                    peer: peer_id,
                                    path: peer.path,
                                });
                            }
                            self.events
                                .push_back(MeshEvent::FallbackToRelay { peer: peer_id });
                        }
                        if now >= peer.next_probe_at {
                            probe = true;
                        }
                    }
                }
            }
            if probe {
                self.send_probes_for_peer(peer_id, now);
            }
            if let Some(remote) = heartbeat_to {
                self.send_ping(peer_id, remote, now);
            }
        }
    }

    /// Encapsulates and encrypts an outbound [`IpPacket`] destined for `peer`
    /// and queues it for transmission on the peer's active [`ConnectionPath`].
    ///
    /// # Errors
    ///
    /// Returns [`MeshError::UnknownPeer`] if `peer` is not in the netmap, or
    /// [`MeshError::CounterExhausted`] if the send counter wrapped.
    pub fn encapsulate(&mut self, peer_id: DeviceId, packet: &IpPacket) -> Result<(), MeshError> {
        let local_exchange = self.local_identity.public().exchange_key_bytes();
        let local_epoch = self.local_epoch;
        let peer = self
            .peers_by_id
            .get_mut(&peer_id)
            .ok_or(MeshError::UnknownPeer(peer_id))?;

        if peer.send_counter == u64::MAX {
            return Err(MeshError::CounterExhausted);
        }
        let counter = peer.send_counter;
        peer.send_counter += 1;

        let mut header = Vec::with_capacity(DATA_HEADER_LEN);
        header.extend_from_slice(&DATA_HEADER_MAGIC);
        header.extend_from_slice(&local_exchange);
        header.extend_from_slice(&local_epoch);
        header.extend_from_slice(&counter.to_le_bytes());

        let key = aead_key(&peer.send_key)?;
        let mut body = packet.as_bytes().to_vec();
        key.seal_in_place_append_tag(counter_nonce(counter), Aad::from(&header), &mut body)
            .map_err(|_| MeshError::TunnelAuthFailed)?;

        let mut wire = Vec::with_capacity(DATA_HEADER_LEN + body.len());
        wire.extend_from_slice(&header);
        wire.extend_from_slice(&body);

        let target = match peer.path {
            ConnectionPath::Direct { remote } => TransmitTarget::DirectUdp(remote),
            ConnectionPath::Relayed { peer_exchange_key } => {
                TransmitTarget::Relay(peer_exchange_key)
            }
        };
        self.transmits.push_back(Transmit {
            target,
            payload: wire,
        });
        Ok(())
    }

    /// Processes an inbound datagram arriving from direct UDP (`from_udp = Some(addr)`)
    /// or from the relay (`from_udp = None`).
    ///
    /// Returns `Ok(Some((peer_id, ip_packet)))` for a tunnel data packet, or
    /// `Ok(None)` for STUN and `disco` control traffic handled internally.
    ///
    /// # Errors
    ///
    /// Returns [`MeshError`] if authentication, anti-replay, or inner IP parsing fails.
    pub fn handle_receive(
        &mut self,
        from_udp: Option<SocketAddr>,
        datagram: &[u8],
        now: Instant,
    ) -> Result<Option<(DeviceId, IpPacket)>, MeshError> {
        if from_udp.is_some() && stun::is_stun(datagram) {
            self.handle_stun(datagram, now);
            return Ok(None);
        }
        if DiscoMessage::looks_like_disco(datagram) {
            let (sender_exchange, msg) =
                DiscoMessage::open(datagram, self.local_identity.exchange_secret())?;
            let Some(&peer_id) = self.peers_by_exchange.get(&sender_exchange) else {
                return Ok(None);
            };
            self.handle_disco_message(peer_id, sender_exchange, from_udp, msg, now)?;
            return Ok(None);
        }

        if datagram.len() < DATA_HEADER_LEN + TAG_LEN || datagram[..4] != DATA_HEADER_MAGIC {
            return Err(MeshError::TunnelAuthFailed);
        }
        let header = &datagram[..DATA_HEADER_LEN];
        let mut sender_exchange = [0u8; 32];
        sender_exchange.copy_from_slice(&datagram[4..36]);
        let mut epoch = [0u8; 8];
        epoch.copy_from_slice(&datagram[36..44]);
        let mut counter_bytes = [0u8; 8];
        counter_bytes.copy_from_slice(&datagram[44..52]);
        let counter = u64::from_le_bytes(counter_bytes);

        let local_pub = self.local_identity.public().exchange_key_bytes();
        let Some(&peer_id) = self.peers_by_exchange.get(&sender_exchange) else {
            return Err(MeshError::TunnelAuthFailed);
        };
        let peer = self
            .peers_by_id
            .get_mut(&peer_id)
            .ok_or(MeshError::UnknownPeer(peer_id))?;

        // Receive key for the sender's epoch. A new epoch (peer restarted) gets a
        // fresh key and a fresh replay window once a packet authenticates; the
        // previous epoch stays valid with its own window so late packets are
        // still replay-checked and an old epoch can never reset the new one.
        let known = peer.recv.iter().position(|r| r.epoch == epoch);
        let key_bytes = match known {
            Some(i) => peer.recv[i].key,
            None => derive_direction_key(&peer.shared_secret, &sender_exchange, &local_pub, epoch),
        };
        let key = aead_key(&key_bytes)?;
        let mut buf = datagram[DATA_HEADER_LEN..].to_vec();
        let plaintext = key
            .open_in_place(counter_nonce(counter), Aad::from(header), &mut buf)
            .map_err(|_| MeshError::TunnelAuthFailed)?
            .to_vec();

        let index = if let Some(i) = known {
            i
        } else {
            if peer.recv.len() >= 2 {
                peer.recv.remove(0);
            }
            peer.recv.push(RecvEpoch {
                epoch,
                key: key_bytes,
                replay: ReplayWindow::default(),
            });
            peer.recv.len() - 1
        };
        if !peer.recv[index].replay.check_and_accept(counter) {
            return Err(MeshError::TunnelAuthFailed);
        }

        let ip_packet = IpPacket::parse(plaintext)?;
        Ok(Some((peer_id, ip_packet)))
    }

    /// Pops the next outbound [`Transmit`] queued by the state machine.
    pub fn poll_transmit(&mut self) -> Option<Transmit> {
        self.transmits.pop_front()
    }

    /// Pops the next [`MeshEvent`] emitted by the state machine.
    pub fn poll_event(&mut self) -> Option<MeshEvent> {
        self.events.pop_front()
    }

    fn handle_stun(&mut self, datagram: &[u8], now: Instant) {
        let Ok((tx_id, reflexive)) = stun::parse_binding_response(datagram) else {
            return;
        };
        let Some((server, _)) = self.inflight_stun.remove(&tx_id) else {
            return;
        };
        let changed = self.reflexive.insert(server, reflexive) != Some(reflexive);
        if changed {
            self.endpoints_changed(now);
        }
    }

    /// Re-advertises endpoints to every peer and notifies the caller.
    fn endpoints_changed(&mut self, now: Instant) {
        self.events
            .push_back(MeshEvent::LocalEndpointsChanged(self.local_endpoints()));
        let relayed: Vec<DeviceId> = self
            .peers_by_id
            .iter()
            .filter(|(_, p)| matches!(p.path, ConnectionPath::Relayed { .. }))
            .map(|(id, _)| *id)
            .collect();
        for peer_id in relayed {
            self.send_probes_for_peer(peer_id, now);
        }
    }

    fn send_ping(&mut self, peer_id: DeviceId, to: SocketAddr, now: Instant) {
        let local_pub = self.local_identity.public().exchange_key_bytes();
        let Some(peer) = self.peers_by_id.get_mut(&peer_id) else {
            return;
        };
        let peer_exchange = peer.public.exchange_key_bytes();
        let tx_id = random_tx_id();
        let ping = DiscoMessage::Ping {
            tx_id,
            node_key: local_pub,
            padding: 0,
        };
        if let Ok(sealed) = ping.seal(self.local_identity.exchange_secret(), &peer_exchange) {
            peer.inflight_pings.insert(tx_id, (to, now));
            self.transmits.push_back(Transmit {
                target: TransmitTarget::DirectUdp(to),
                payload: sealed,
            });
        }
    }

    fn send_probes_for_peer(&mut self, peer_id: DeviceId, now: Instant) {
        let my_numbers = self.local_endpoints();
        let Some(peer) = self.peers_by_id.get(&peer_id) else {
            return;
        };
        let peer_exchange = peer.public.exchange_key_bytes();
        let candidates = peer.candidates.clone();
        let interval = if peer.fallback_deadline.is_some() {
            DIRECT_PROBE_INTERVAL
        } else {
            RELAYED_PROBE_INTERVAL
        };

        // 1. CallMeMaybe over the relay so the peer punches back toward our endpoints.
        let cmm = DiscoMessage::CallMeMaybe { my_numbers };
        if let Ok(sealed_cmm) = cmm.seal(self.local_identity.exchange_secret(), &peer_exchange) {
            self.transmits.push_back(Transmit {
                target: TransmitTarget::Relay(peer_exchange),
                payload: sealed_cmm,
            });
        }
        // 2. Direct UDP Ping to every known candidate of the peer.
        for candidate in candidates {
            self.send_ping(peer_id, candidate, now);
        }
        if let Some(peer) = self.peers_by_id.get_mut(&peer_id) {
            peer.next_probe_at = now + interval;
        }
    }

    fn handle_disco_message(
        &mut self,
        peer_id: DeviceId,
        sender_exchange: [u8; 32],
        from_udp: Option<SocketAddr>,
        msg: DiscoMessage,
        now: Instant,
    ) -> Result<(), MeshError> {
        match msg {
            DiscoMessage::Ping { tx_id, .. } => {
                if let Some(src_addr) = from_udp {
                    // Endpoints learned from incoming pings become candidates
                    // (Tailscale `handlePingLocked` adds unknown endpoints).
                    if let Some(peer) = self.peers_by_id.get_mut(&peer_id)
                        && !peer.candidates.contains(&src_addr)
                    {
                        peer.candidates.push(src_addr);
                    }
                    let pong = DiscoMessage::Pong {
                        tx_id,
                        src: src_addr,
                    };
                    let sealed =
                        pong.seal(self.local_identity.exchange_secret(), &sender_exchange)?;
                    self.transmits.push_back(Transmit {
                        target: TransmitTarget::DirectUdp(src_addr),
                        payload: sealed,
                    });
                }
            }
            DiscoMessage::Pong { tx_id, src } => {
                let Some(remote_addr) = from_udp else {
                    return Ok(());
                };
                let Some(peer) = self.peers_by_id.get_mut(&peer_id) else {
                    return Ok(());
                };
                let Some((_, sent_at)) = peer.inflight_pings.remove(&tx_id) else {
                    return Ok(());
                };
                let rtt = now.saturating_duration_since(sent_at);

                // The peer saw our packet from `src`: a reflexive endpoint
                // (built-in STUN, Tailscale `addCandidateEndpoint`).
                let endpoints_changed = !self.local_candidates.contains(&src)
                    && self.reflexive.insert(remote_addr, src) != Some(src);

                let was_relayed = matches!(peer.path, ConnectionPath::Relayed { .. });
                let better = match (peer.path, peer.best_rtt) {
                    (ConnectionPath::Direct { remote }, Some(best)) if remote != remote_addr => {
                        best.saturating_sub(rtt) > GOOD_ENOUGH_LATENCY
                    }
                    _ => true,
                };
                if better {
                    peer.path = ConnectionPath::Direct {
                        remote: remote_addr,
                    };
                    peer.best_rtt = Some(rtt);
                }
                if matches!(peer.path, ConnectionPath::Direct { remote } if remote == remote_addr) {
                    peer.trust_until = Some(now + TRUST_UDP_ADDR_DURATION);
                    peer.next_heartbeat_at = now + HEARTBEAT_INTERVAL;
                }
                peer.fallback_deadline = None;
                if !peer.connected_emitted {
                    peer.connected_emitted = true;
                    self.events.push_back(MeshEvent::Connected {
                        peer: peer_id,
                        path: peer.path,
                    });
                }
                if was_relayed && better {
                    self.events.push_back(MeshEvent::PathUpgraded {
                        peer: peer_id,
                        remote: remote_addr,
                        rtt,
                    });
                }
                if endpoints_changed {
                    self.endpoints_changed(now);
                }
            }
            DiscoMessage::CallMeMaybe { my_numbers } => {
                if let Some(peer) = self.peers_by_id.get_mut(&peer_id) {
                    for addr in &my_numbers {
                        if !peer.candidates.contains(addr) {
                            peer.candidates.push(*addr);
                        }
                    }
                }
                for addr in my_numbers {
                    self.send_ping(peer_id, addr, now);
                }
            }
        }
        Ok(())
    }
}

fn dh_shared(local: &DeviceIdentity, peer_exchange: &[u8; 32]) -> [u8; 32] {
    let pub_point = X25519Public::from(*peer_exchange);
    local
        .exchange_secret()
        .diffie_hellman(&pub_point)
        .to_bytes()
}

/// `H("omegadesk-tunnel-v2:" || dh || sender || receiver || sender_epoch)`.
fn derive_direction_key(
    shared: &[u8; 32],
    sender: &[u8; 32],
    receiver: &[u8; 32],
    sender_epoch: [u8; 8],
) -> [u8; 32] {
    let digest = Sha256::new()
        .chain_update(b"omegadesk-tunnel-v2:")
        .chain_update(shared)
        .chain_update(sender)
        .chain_update(receiver)
        .chain_update(sender_epoch)
        .finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&digest);
    key
}

fn aead_key(key: &[u8; 32]) -> Result<LessSafeKey, MeshError> {
    let unbound =
        UnboundKey::new(&CHACHA20_POLY1305, key).map_err(|_| MeshError::TunnelAuthFailed)?;
    Ok(LessSafeKey::new(unbound))
}

fn counter_nonce(counter: u64) -> Nonce {
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[4..12].copy_from_slice(&counter.to_le_bytes());
    Nonce::assume_unique_for_key(nonce_bytes)
}

/// Deduplicating helper for tests and callers merging endpoint lists.
#[must_use]
pub fn merge_endpoints(a: &[SocketAddr], b: &[SocketAddr]) -> Vec<SocketAddr> {
    let mut seen = HashSet::new();
    a.iter()
        .chain(b.iter())
        .filter(|addr| seen.insert(**addr))
        .copied()
        .collect()
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    fn relay_all(from: &mut MeshNode, to: &mut MeshNode, now: Instant) {
        while let Some(tx) = from.poll_transmit() {
            if matches!(tx.target, TransmitTarget::Relay(_)) {
                to.handle_receive(None, &tx.payload, now).unwrap();
            }
        }
    }

    fn deliver_direct(from: &mut MeshNode, from_addr: SocketAddr, to: &mut MeshNode, now: Instant) {
        while let Some(tx) = from.poll_transmit() {
            if let TransmitTarget::DirectUdp(_) = tx.target {
                to.handle_receive(Some(from_addr), &tx.payload, now)
                    .unwrap();
            }
        }
    }

    fn drain_events(node: &mut MeshNode) -> Vec<MeshEvent> {
        let mut out = Vec::new();
        while let Some(ev) = node.poll_event() {
            out.push(ev);
        }
        out
    }

    #[test]
    fn upgrades_from_relay_to_direct_path_via_disco_hole_punch() {
        let now = Instant::now();
        let alice_id = DeviceIdentity::generate();
        let bob_id = DeviceIdentity::generate();
        let alice_pub = alice_id.public();
        let bob_pub = bob_id.public();
        let alice_addr: SocketAddr = "198.51.100.10:51820".parse().unwrap();
        let bob_addr: SocketAddr = "203.0.113.20:51820".parse().unwrap();

        let mut alice = MeshNode::new(alice_id, vec![alice_addr], vec![]);
        let mut bob = MeshNode::new(bob_id, vec![bob_addr], vec![]);
        alice.upsert_peer(bob_pub, vec![], now);
        bob.upsert_peer(alice_pub, vec![], now);

        relay_all(&mut alice, &mut bob, now + Duration::from_millis(10));
        deliver_direct(
            &mut bob,
            bob_addr,
            &mut alice,
            now + Duration::from_millis(25),
        );
        deliver_direct(
            &mut alice,
            alice_addr,
            &mut bob,
            now + Duration::from_millis(40),
        );

        assert_eq!(
            bob.peer_path(alice_pub.id()),
            Some(ConnectionPath::Direct { remote: alice_addr })
        );
        let events = drain_events(&mut bob);
        assert!(events.iter().any(|e| matches!(e, MeshEvent::PathUpgraded { remote, rtt, .. } if *remote == alice_addr && *rtt == Duration::from_millis(30))));

        // Data over the direct path, replay rejected.
        let inner = IpPacket::ipv4_udp(
            Ipv4Addr::new(100, 64, 0, 2),
            Ipv4Addr::new(100, 64, 0, 1),
            1234,
            5678,
            b"direct-mesh-payload",
        )
        .unwrap();
        bob.encapsulate(alice_pub.id(), &inner).unwrap();
        let data_tx = bob.poll_transmit().unwrap();
        assert_eq!(data_tx.target, TransmitTarget::DirectUdp(alice_addr));
        let (_, decapsulated) = alice
            .handle_receive(Some(bob_addr), &data_tx.payload, now)
            .unwrap()
            .unwrap();
        assert_eq!(decapsulated, inner);
        assert!(matches!(
            alice.handle_receive(Some(bob_addr), &data_tx.payload, now),
            Err(MeshError::TunnelAuthFailed)
        ));
    }

    #[test]
    fn directions_use_distinct_keys_and_restart_gets_a_fresh_epoch() {
        let now = Instant::now();
        let alice_id = DeviceIdentity::generate();
        let bob_id = DeviceIdentity::generate();
        let alice_pub = alice_id.public();
        let bob_pub = bob_id.public();
        let alice_secret = alice_id.to_secret_bytes();

        let mut alice = MeshNode::new(alice_id, vec![], vec![]);
        let mut bob = MeshNode::new(bob_id, vec![], vec![]);
        alice.upsert_peer(bob_pub, vec![], now);
        bob.upsert_peer(alice_pub, vec![], now);
        while alice.poll_transmit().is_some() {}
        while bob.poll_transmit().is_some() {}

        let pkt = IpPacket::ipv4_udp(
            Ipv4Addr::new(100, 64, 0, 1),
            Ipv4Addr::new(100, 64, 0, 2),
            1,
            2,
            b"same-plaintext",
        )
        .unwrap();
        // Same plaintext, same counter (0) in both directions: ciphertexts differ.
        alice.encapsulate(bob_pub.id(), &pkt).unwrap();
        bob.encapsulate(alice_pub.id(), &pkt).unwrap();
        let a_to_b = alice.poll_transmit().unwrap().payload;
        let b_to_a = bob.poll_transmit().unwrap().payload;
        assert_ne!(a_to_b[DATA_HEADER_LEN..], b_to_a[DATA_HEADER_LEN..]);
        assert_eq!(
            bob.handle_receive(None, &a_to_b, now).unwrap().unwrap().1,
            pkt
        );
        assert_eq!(
            alice.handle_receive(None, &b_to_a, now).unwrap().unwrap().1,
            pkt
        );
        // A packet from the other direction is never accepted as our own key.
        assert!(bob.handle_receive(None, &b_to_a, now).is_err());

        // Alice restarts: counter 0 again, but a fresh epoch means a fresh key,
        // and Bob accepts it instead of treating it as a replay.
        let alice_restarted = DeviceIdentity::from_secret_bytes(&alice_secret).unwrap();
        let mut alice2 = MeshNode::new(alice_restarted, vec![], vec![]);
        alice2.upsert_peer(bob_pub, vec![], now);
        while alice2.poll_transmit().is_some() {}
        alice2.encapsulate(bob_pub.id(), &pkt).unwrap();
        let restarted = alice2.poll_transmit().unwrap().payload;
        assert_ne!(restarted[36..44], a_to_b[36..44], "epoch must change");
        assert_eq!(
            bob.handle_receive(None, &restarted, now)
                .unwrap()
                .unwrap()
                .1,
            pkt
        );
        // The old epoch keeps its own replay window: the earlier packet is a replay.
        assert!(bob.handle_receive(None, &a_to_b, now).is_err());
        // A late packet from the old epoch that was never seen is still accepted.
        alice.encapsulate(bob_pub.id(), &pkt).unwrap();
        let late_old = alice.poll_transmit().unwrap().payload;
        assert_eq!(
            bob.handle_receive(None, &late_old, now).unwrap().unwrap().1,
            pkt
        );
    }

    #[test]
    fn falls_back_to_relay_under_two_seconds_when_udp_blocked() {
        let now = Instant::now();
        let alice_id = DeviceIdentity::generate();
        let bob_pub = DeviceIdentity::generate().public();
        let mut alice = MeshNode::new(alice_id, vec!["10.0.0.2:51820".parse().unwrap()], vec![]);
        alice.upsert_peer(bob_pub, vec!["203.0.113.99:51820".parse().unwrap()], now);
        while alice.poll_transmit().is_some() {}

        let timeout = alice.poll_timeout().unwrap();
        assert!(timeout <= now + RELAY_FALLBACK_TIMEOUT);
        assert!(RELAY_FALLBACK_TIMEOUT < Duration::from_secs(2));

        alice.handle_timeout(now + RELAY_FALLBACK_TIMEOUT);
        let events = drain_events(&mut alice);
        assert!(events.contains(&MeshEvent::FallbackToRelay { peer: bob_pub.id() }));
        assert_eq!(
            alice.peer_path(bob_pub.id()),
            Some(ConnectionPath::Relayed {
                peer_exchange_key: bob_pub.exchange_key_bytes()
            })
        );
        // Unanswered pings are forgotten after PING_TIMEOUT: the probe sent at
        // the fallback instant is gone, only the probe sent now remains.
        let later = now + RELAY_FALLBACK_TIMEOUT + PING_TIMEOUT;
        alice.handle_timeout(later);
        let peer = &alice.peers_by_id[&bob_pub.id()];
        assert_eq!(peer.inflight_pings.len(), 1);
        assert!(peer.inflight_pings.values().all(|(_, sent)| *sent == later));
        // Probing continues at the slower relayed interval.
        assert_eq!(peer.next_probe_at, later + RELAYED_PROBE_INTERVAL);
    }

    #[test]
    fn dead_direct_path_falls_back_to_relay_after_trust_expires() {
        let now = Instant::now();
        let alice_id = DeviceIdentity::generate();
        let bob_id = DeviceIdentity::generate();
        let alice_pub = alice_id.public();
        let bob_pub = bob_id.public();
        let alice_addr: SocketAddr = "198.51.100.10:51820".parse().unwrap();
        let bob_addr: SocketAddr = "203.0.113.20:51820".parse().unwrap();
        let mut alice = MeshNode::new(alice_id, vec![alice_addr], vec![]);
        let mut bob = MeshNode::new(bob_id, vec![bob_addr], vec![]);
        alice.upsert_peer(bob_pub, vec![bob_addr], now);
        bob.upsert_peer(alice_pub, vec![alice_addr], now);
        deliver_direct(&mut alice, alice_addr, &mut bob, now);
        deliver_direct(&mut bob, bob_addr, &mut alice, now);
        assert!(matches!(
            alice.peer_path(bob_pub.id()),
            Some(ConnectionPath::Direct { .. })
        ));
        drain_events(&mut alice);

        // Heartbeats are sent every HEARTBEAT_INTERVAL while direct.
        alice.handle_timeout(now + HEARTBEAT_INTERVAL);
        let heartbeat = alice.poll_transmit().unwrap();
        assert_eq!(heartbeat.target, TransmitTarget::DirectUdp(bob_addr));
        assert!(DiscoMessage::looks_like_disco(&heartbeat.payload));

        // Bob never answers: after TRUST_UDP_ADDR_DURATION the path is dropped.
        alice.handle_timeout(now + TRUST_UDP_ADDR_DURATION);
        assert!(matches!(
            alice.peer_path(bob_pub.id()),
            Some(ConnectionPath::Relayed { .. })
        ));
        assert!(
            drain_events(&mut alice).contains(&MeshEvent::FallbackToRelay { peer: bob_pub.id() })
        );
        // And probing resumes immediately.
        assert!(alice.poll_transmit().is_some());
    }

    #[test]
    fn stun_discovers_reflexive_endpoint_and_readvertises_it() {
        let now = Instant::now();
        let alice_id = DeviceIdentity::generate();
        let bob_pub = DeviceIdentity::generate().public();
        let stun_server: SocketAddr = "198.51.100.1:3478".parse().unwrap();
        let lan: SocketAddr = "192.168.1.10:51820".parse().unwrap();
        let mut alice = MeshNode::new(alice_id, vec![lan], vec![stun_server]);
        alice.upsert_peer(bob_pub, vec![], now);

        let mut stun_tx = None;
        while let Some(tx) = alice.poll_transmit() {
            if tx.target == TransmitTarget::DirectUdp(stun_server) {
                assert!(stun::is_stun(&tx.payload));
                let mut id = [0u8; 12];
                id.copy_from_slice(&tx.payload[8..20]);
                stun_tx = Some(id);
            }
        }
        let tx_id = stun_tx.expect("STUN request sent");
        let public: SocketAddr = "203.0.113.5:40001".parse().unwrap();
        alice
            .handle_receive(
                Some(stun_server),
                &stun::binding_response(&tx_id, public),
                now,
            )
            .unwrap();
        assert_eq!(alice.local_endpoints(), vec![lan, public]);
        let events = drain_events(&mut alice);
        assert!(events.contains(&MeshEvent::LocalEndpointsChanged(vec![lan, public])));
        // The new endpoint set is announced to the (relayed) peer right away.
        let cmm = alice.poll_transmit().unwrap();
        assert_eq!(
            cmm.target,
            TransmitTarget::Relay(bob_pub.exchange_key_bytes())
        );
        // STUN is refreshed periodically while peers exist.
        assert_eq!(alice.next_stun_at, Some(now + STUN_REFRESH_INTERVAL));
        // A reply to an unknown transaction is ignored.
        alice
            .handle_receive(
                Some(stun_server),
                &stun::binding_response(&[9u8; 12], public),
                now,
            )
            .unwrap();
    }

    #[test]
    fn exchange_key_rotation_resets_peer_state() {
        let now = Instant::now();
        let alice_id = DeviceIdentity::generate();
        let bob_id = DeviceIdentity::generate();
        let bob_pub = bob_id.public();
        let mut alice = MeshNode::new(alice_id, vec![], vec![]);
        alice.upsert_peer(bob_pub, vec![], now);
        // Same signing key, different exchange key.
        let rotated = DevicePublic::from_bytes(
            &bob_pub.signing_key_bytes(),
            &DeviceIdentity::generate().public().exchange_key_bytes(),
        )
        .unwrap();
        alice.upsert_peer(rotated, vec![], now);
        assert_eq!(
            alice.peer_by_exchange_key(&bob_pub.exchange_key_bytes()),
            None
        );
        assert_eq!(
            alice.peer_by_exchange_key(&rotated.exchange_key_bytes()),
            Some(bob_pub.id())
        );
        assert!(
            drain_events(&mut alice).contains(&MeshEvent::PeerKeyRotated { peer: bob_pub.id() })
        );
        alice.remove_peer(bob_pub.id());
        assert_eq!(alice.peer_path(bob_pub.id()), None);
    }
}
