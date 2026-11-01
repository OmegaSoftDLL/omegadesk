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
//!   `heartbeatInterval` in `wgengine/magicsock/magicsock.go`). On top of that,
//!   while traffic is actively sent on a direct path, silence from the peer for
//!   [`DIRECT_LIVENESS_TIMEOUT`] triggers an immediate fallback so an outage is
//!   detected within the 2 s Phase 2 budget.
//!
//! Tunnel data packets use ChaCha20-Poly1305 with a key bound to **both peers'
//! session freshness**: each side picks a random epoch per peer and announces
//! it in every authenticated `disco` message; the key is
//! `H(dh, sender, receiver, sender_epoch, receiver_epoch)`. A restart on either
//! side changes an epoch, hence the key, so recorded ciphertext can never be
//! replayed into a new session, and the two directions never share a key.

pub mod disco;
pub mod peer_routing;
pub mod stun;

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use omegadesk_identity::{DeviceId, DeviceIdentity, DevicePublic};
use omegadesk_tun::{IpPacket, TunError};
use ring::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey};
use sha2::{Digest, Sha256};
use x25519_dalek::PublicKey as X25519Public;

pub use disco::{DiscoError, DiscoMessage, Epoch, MAGIC as DISCO_MAGIC, TxId, random_tx_id};
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

/// While traffic is being sent on a direct path, a liveness `Ping` is sent once
/// nothing has been received from the peer for this long.
pub const DIRECT_LIVENESS_PROBE_AFTER: Duration = Duration::from_millis(500);

/// While traffic is being sent on a direct path, silence from the peer for this
/// long abandons the path and falls back to the relay (within the 2 s budget):
/// [`DIRECT_LIVENESS_PROBE_AFTER`] of silence, then [`DIRECT_LIVENESS_PONG_TIMEOUT`]
/// for the liveness `Ping` to be answered.
pub const DIRECT_LIVENESS_TIMEOUT: Duration = Duration::from_millis(1500);

/// Time the liveness `Ping` has to be answered by a `Pong` before the direct
/// path is abandoned. Only the explicit `Pong` (from any address of the peer)
/// or a direct packet from the peer counts: a peer that currently sends *its*
/// traffic through the relay while still answering our pings keeps our
/// direct path valid (asymmetric paths are legitimate, Tailscale `magicsock`
/// treats each direction independently).
pub const DIRECT_LIVENESS_PONG_TIMEOUT: Duration = Duration::from_millis(1000);

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

/// Tunnel data header: 4B magic + 32B sender X25519 + 8B sender epoch +
/// 8B receiver epoch + 8B LE counter.
const DATA_HEADER_LEN: usize = 4 + 32 + 8 + 8 + 8;
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
    /// path stopped answering. Background probing continues.
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
    /// The peer's tunnel epoch is not known yet (no authenticated `disco`
    /// message received from it); data cannot be encrypted for it.
    #[error("mesh peer {0} has not completed epoch exchange yet")]
    PeerEpochUnknown(DeviceId),
    /// Disco packet error.
    #[error("disco error: {0}")]
    Disco(#[from] DiscoError),
    /// Tunnel data packet authentication, epoch or anti-replay check failed.
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

struct PeerState {
    public: DevicePublic,
    candidates: Vec<SocketAddr>,
    path: ConnectionPath,
    /// Direct path validity (Tailscale `trustBestAddrUntil`).
    trust_until: Option<Instant>,
    best_rtt: Option<Duration>,
    shared_secret: [u8; 32],
    /// Our epoch for this peer: random per `PeerState`, so re-adding a peer
    /// never reuses a key/counter pair.
    local_epoch: Epoch,
    /// The peer's epoch for us, learned from its authenticated `disco` messages.
    peer_epoch: Option<Epoch>,
    send_key: Option<[u8; 32]>,
    send_counter: u64,
    recv_key: Option<[u8; 32]>,
    replay: ReplayWindow,
    next_probe_at: Instant,
    next_heartbeat_at: Instant,
    fallback_deadline: Option<Instant>,
    inflight_pings: HashMap<TxId, (SocketAddr, Instant)>,
    connected_emitted: bool,
    /// Last datagram (data or disco) received from the validated direct address.
    last_direct_rx: Option<Instant>,
    /// Last datagram we sent on the validated direct address.
    last_direct_tx: Option<Instant>,
    /// When the liveness `Ping` for the current silence was sent, if any.
    liveness_probe_at: Option<Instant>,
}

impl PeerState {
    fn tunnel_keys(&self, local_pub: &[u8; 32]) -> Option<([u8; 32], [u8; 32])> {
        let peer_epoch = self.peer_epoch?;
        let peer_pub = self.public.exchange_key_bytes();
        let send = derive_direction_key(
            &self.shared_secret,
            local_pub,
            &peer_pub,
            self.local_epoch,
            peer_epoch,
        );
        let recv = derive_direction_key(
            &self.shared_secret,
            &peer_pub,
            local_pub,
            peer_epoch,
            self.local_epoch,
        );
        Some((send, recv))
    }

    /// Records the peer's epoch from an authenticated disco message. A new
    /// epoch (peer restarted or re-added us) re-keys both directions.
    fn learn_peer_epoch(&mut self, epoch: Epoch, local_pub: &[u8; 32]) {
        if self.peer_epoch == Some(epoch) {
            return;
        }
        self.peer_epoch = Some(epoch);
        let (send, recv) = self
            .tunnel_keys(local_pub)
            .unwrap_or(([0u8; 32], [0u8; 32]));
        self.send_key = Some(send);
        self.recv_key = Some(recv);
        self.send_counter = 0;
        self.replay = ReplayWindow::default();
    }

    /// Whether traffic is actively being sent on the direct path (we sent
    /// after the last time we heard from the peer); returns the instant of the
    /// last thing heard, which anchors the liveness timers.
    fn direct_traffic_pending(&self) -> Option<Instant> {
        match (self.last_direct_tx, self.last_direct_rx) {
            (Some(tx), Some(rx)) if tx > rx => Some(rx),
            _ => None,
        }
    }
}

/// Sans-I/O mesh connectivity engine managing peer tunnels, STUN, `disco`
/// hole-punching, direct-path trust and relay fallback.
pub struct MeshNode {
    local_identity: DeviceIdentity,
    local_candidates: Vec<SocketAddr>,
    stun_servers: Vec<SocketAddr>,
    /// Never use direct paths: no pings, no pongs, direct datagrams dropped.
    relay_only: bool,
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
        Self {
            local_identity,
            local_candidates,
            stun_servers,
            relay_only: false,
            inflight_stun: HashMap::new(),
            reflexive: HashMap::new(),
            next_stun_at: None,
            peers_by_id: HashMap::new(),
            peers_by_exchange: HashMap::new(),
            transmits: VecDeque::new(),
            events: VecDeque::new(),
        }
    }

    /// Relay-only policy: the node never probes, answers or accepts a direct
    /// path (every datagram arriving on the UDP socket other than STUN is
    /// dropped, `CallMeMaybe` endpoints are ignored, no `Pong` is sent), so a
    /// peer with direct candidates can never upgrade a path towards it.
    pub fn set_relay_only(&mut self, relay_only: bool) {
        self.relay_only = relay_only;
        if relay_only {
            self.local_candidates.clear();
            self.stun_servers.clear();
            self.reflexive.clear();
            self.inflight_stun.clear();
            self.next_stun_at = None;
            for peer in self.peers_by_id.values_mut() {
                peer.candidates.clear();
            }
        }
    }

    /// Whether the relay-only policy is active.
    #[must_use]
    pub fn relay_only(&self) -> bool {
        self.relay_only
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
        let candidates = if self.relay_only {
            Vec::new()
        } else {
            candidates
        };

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

        if !self.stun_servers.is_empty()
            && self.reflexive.is_empty()
            && self.inflight_stun.is_empty()
        {
            self.refresh_stun(now);
        }

        let shared_secret = dh_shared(&self.local_identity, &peer_exchange);
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
                local_epoch: disco::random_epoch(),
                peer_epoch: None,
                send_key: None,
                send_counter: 0,
                recv_key: None,
                replay: ReplayWindow::default(),
                next_probe_at: now,
                next_heartbeat_at: now + HEARTBEAT_INTERVAL,
                fallback_deadline: Some(now + RELAY_FALLBACK_TIMEOUT),
                inflight_pings: HashMap::new(),
                connected_emitted: false,
                last_direct_rx: None,
                last_direct_tx: None,
                liveness_probe_at: None,
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
        if self.peers_by_id.is_empty() {
            self.next_stun_at = None;
        }
    }

    /// Returns the currently active [`ConnectionPath`] for `peer`.
    #[must_use]
    pub fn peer_path(&self, peer: DeviceId) -> Option<ConnectionPath> {
        self.peers_by_id.get(&peer).map(|p| p.path)
    }

    /// Whether the peer's tunnel epoch is known (data can be encrypted for it).
    #[must_use]
    pub fn peer_ready(&self, peer: DeviceId) -> bool {
        self.peers_by_id
            .get(&peer)
            .is_some_and(|p| p.peer_epoch.is_some())
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

    /// Records that the caller sent a datagram to `peer` on its direct path
    /// (callers that carry their own payloads, like a QUIC socket, must report
    /// activity so liveness detection works).
    pub fn record_direct_tx(&mut self, peer: DeviceId, now: Instant) {
        if let Some(p) = self.peers_by_id.get_mut(&peer)
            && matches!(p.path, ConnectionPath::Direct { .. })
        {
            p.last_direct_tx = Some(now);
        }
    }

    /// Records that a datagram arrived from `peer`'s validated direct address.
    pub fn record_direct_rx(&mut self, peer: DeviceId, now: Instant) {
        if let Some(p) = self.peers_by_id.get_mut(&peer)
            && matches!(p.path, ConnectionPath::Direct { .. })
        {
            p.last_direct_rx = Some(now);
            p.liveness_probe_at = None;
        }
    }

    /// Returns the earliest [`Instant`] at which [`Self::handle_timeout`] must be called.
    #[must_use]
    pub fn poll_timeout(&self) -> Option<Instant> {
        let mut earliest: Option<Instant> = None;
        let mut consider = |t: Instant| {
            earliest = Some(earliest.map_or(t, |e| e.min(t)));
        };
        for peer in self.peers_by_id.values() {
            match peer.path {
                ConnectionPath::Relayed { .. } => {
                    consider(peer.next_probe_at);
                    if let Some(deadline) = peer.fallback_deadline {
                        consider(deadline);
                    }
                }
                ConnectionPath::Direct { .. } => {
                    consider(peer.next_heartbeat_at);
                    if let Some(trust) = peer.trust_until {
                        consider(trust);
                    }
                    if let Some(rx) = peer.direct_traffic_pending() {
                        match peer.liveness_probe_at {
                            None => consider(rx + DIRECT_LIVENESS_PROBE_AFTER),
                            Some(probe) => consider(probe + DIRECT_LIVENESS_PONG_TIMEOUT),
                        }
                    }
                }
            }
            if let Some(oldest) = peer.inflight_pings.values().map(|(_, t)| *t).min() {
                consider(oldest + PING_TIMEOUT);
            }
        }
        if let Some(next) = self.next_stun_at
            && !self.peers_by_id.is_empty()
        {
            consider(next);
        }
        if let Some(oldest) = self.inflight_stun.values().map(|(_, t)| *t).min() {
            consider(oldest + PING_TIMEOUT);
        }
        earliest
    }

    /// Advances internal timers to `now`: relay fallback, direct-path trust and
    /// liveness, heartbeats, upgrade probes, STUN refresh and probe expiry.
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
            let mut ping_to: Option<SocketAddr> = None;
            if let Some(peer) = self.peers_by_id.get_mut(&peer_id) {
                peer.inflight_pings
                    .retain(|_, (_, sent)| now.saturating_duration_since(*sent) < PING_TIMEOUT);

                match peer.path {
                    ConnectionPath::Direct { remote } => {
                        let trust_expired = peer.trust_until.is_some_and(|trust| now >= trust);
                        let probe_unanswered = peer.direct_traffic_pending().is_some()
                            && peer
                                .liveness_probe_at
                                .is_some_and(|probe| now >= probe + DIRECT_LIVENESS_PONG_TIMEOUT);
                        if trust_expired || probe_unanswered {
                            // No Pong for TRUST_UDP_ADDR_DURATION, or the liveness Ping
                            // sent under active traffic went unanswered: the path is dead.
                            peer.path = ConnectionPath::Relayed {
                                peer_exchange_key: peer.public.exchange_key_bytes(),
                            };
                            peer.trust_until = None;
                            peer.best_rtt = None;
                            peer.fallback_deadline = None;
                            peer.last_direct_rx = None;
                            peer.last_direct_tx = None;
                            peer.liveness_probe_at = None;
                            peer.next_probe_at = now;
                            self.events
                                .push_back(MeshEvent::FallbackToRelay { peer: peer_id });
                            probe = true;
                        } else if peer
                            .direct_traffic_pending()
                            .is_some_and(|rx| now >= rx + DIRECT_LIVENESS_PROBE_AFTER)
                            && peer.liveness_probe_at.is_none()
                        {
                            peer.liveness_probe_at = Some(now);
                            ping_to = Some(remote);
                        } else if now >= peer.next_heartbeat_at {
                            peer.next_heartbeat_at = now + HEARTBEAT_INTERVAL;
                            ping_to = Some(remote);
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
            if let Some(remote) = ping_to {
                self.send_ping(peer_id, remote, now);
            }
        }
    }

    /// Encapsulates and encrypts an outbound [`IpPacket`] destined for `peer`
    /// and queues it for transmission on the peer's active [`ConnectionPath`].
    ///
    /// # Errors
    ///
    /// Returns [`MeshError::UnknownPeer`] if `peer` is not in the netmap,
    /// [`MeshError::PeerEpochUnknown`] before the first authenticated disco
    /// message from the peer, or [`MeshError::CounterExhausted`].
    pub fn encapsulate(
        &mut self,
        peer_id: DeviceId,
        packet: &IpPacket,
        now: Instant,
    ) -> Result<(), MeshError> {
        let local_exchange = self.local_identity.public().exchange_key_bytes();
        let peer = self
            .peers_by_id
            .get_mut(&peer_id)
            .ok_or(MeshError::UnknownPeer(peer_id))?;
        let (Some(peer_epoch), Some(send_key)) = (peer.peer_epoch, peer.send_key) else {
            return Err(MeshError::PeerEpochUnknown(peer_id));
        };
        if peer.send_counter == u64::MAX {
            return Err(MeshError::CounterExhausted);
        }
        let counter = peer.send_counter;
        peer.send_counter += 1;

        let mut header = Vec::with_capacity(DATA_HEADER_LEN);
        header.extend_from_slice(&DATA_HEADER_MAGIC);
        header.extend_from_slice(&local_exchange);
        header.extend_from_slice(&peer.local_epoch);
        header.extend_from_slice(&peer_epoch);
        header.extend_from_slice(&counter.to_le_bytes());

        let key = aead_key(&send_key)?;
        let mut body = packet.as_bytes().to_vec();
        key.seal_in_place_append_tag(counter_nonce(counter), Aad::from(&header), &mut body)
            .map_err(|_| MeshError::TunnelAuthFailed)?;

        let mut wire = Vec::with_capacity(DATA_HEADER_LEN + body.len());
        wire.extend_from_slice(&header);
        wire.extend_from_slice(&body);

        let target = match peer.path {
            ConnectionPath::Direct { remote } => {
                peer.last_direct_tx = Some(now);
                TransmitTarget::DirectUdp(remote)
            }
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
    /// Returns [`MeshError`] if authentication, epochs, anti-replay, or inner IP parsing fails.
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
        if from_udp.is_some() && self.relay_only {
            // Relay-only: nothing but STUN is accepted on the UDP socket, so no
            // Pong ever validates a direct path towards this node.
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
        let mut sender_epoch = [0u8; 8];
        sender_epoch.copy_from_slice(&datagram[36..44]);
        let mut receiver_epoch = [0u8; 8];
        receiver_epoch.copy_from_slice(&datagram[44..52]);
        let mut counter_bytes = [0u8; 8];
        counter_bytes.copy_from_slice(&datagram[52..60]);
        let counter = u64::from_le_bytes(counter_bytes);

        let Some(&peer_id) = self.peers_by_exchange.get(&sender_exchange) else {
            return Err(MeshError::TunnelAuthFailed);
        };
        let peer = self
            .peers_by_id
            .get_mut(&peer_id)
            .ok_or(MeshError::UnknownPeer(peer_id))?;
        // Only the current, authenticated epochs of both sides are accepted:
        // stale or replayed sessions never derive a usable key.
        if receiver_epoch != peer.local_epoch || peer.peer_epoch != Some(sender_epoch) {
            return Err(MeshError::TunnelAuthFailed);
        }
        let recv_key = peer.recv_key.ok_or(MeshError::TunnelAuthFailed)?;
        let key = aead_key(&recv_key)?;
        let mut buf = datagram[DATA_HEADER_LEN..].to_vec();
        let plaintext = key
            .open_in_place(counter_nonce(counter), Aad::from(header), &mut buf)
            .map_err(|_| MeshError::TunnelAuthFailed)?
            .to_vec();
        if !peer.replay.check_and_accept(counter) {
            return Err(MeshError::TunnelAuthFailed);
        }
        // Any authenticated packet that arrived directly proves the peer is
        // alive on the direct path, whichever of its addresses it came from:
        // a multi-homed or double-NATed peer is seen through several aliases
        // (LAN address and the router's address), and its replies may use a
        // different one than the validated `remote`.
        if from_udp.is_some() && matches!(peer.path, ConnectionPath::Direct { .. }) {
            peer.last_direct_rx = Some(now);
            peer.liveness_probe_at = None;
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
            epoch: peer.local_epoch,
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

        // 1. CallMeMaybe over the relay so the peer punches back toward our endpoints
        //    (and learns our epoch even when every direct candidate is unreachable).
        let cmm = DiscoMessage::CallMeMaybe {
            my_numbers,
            epoch: peer.local_epoch,
        };
        if let Ok(sealed_cmm) = cmm.seal(self.local_identity.exchange_secret(), &peer_exchange) {
            self.transmits.push_back(Transmit {
                target: TransmitTarget::Relay(peer_exchange),
                payload: sealed_cmm,
            });
        }
        // 2. Direct UDP Ping to every known candidate of the peer (never in
        //    relay-only mode).
        if !self.relay_only {
            for candidate in candidates {
                self.send_ping(peer_id, candidate, now);
            }
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
        let local_pub = self.local_identity.public().exchange_key_bytes();
        let epoch = msg.epoch();
        let mut epoch_changed = false;
        if let Some(peer) = self.peers_by_id.get_mut(&peer_id) {
            epoch_changed = peer.peer_epoch != Some(epoch);
            peer.learn_peer_epoch(epoch, &local_pub);
            if from_udp.is_some() && matches!(peer.path, ConnectionPath::Direct { .. }) {
                peer.last_direct_rx = Some(now);
                peer.liveness_probe_at = None;
            }
        }
        match msg {
            DiscoMessage::Ping { tx_id, .. } => {
                if let Some(src_addr) = from_udp {
                    // Endpoints learned from incoming pings become candidates
                    // (Tailscale `handlePingLocked` adds unknown endpoints).
                    let Some(peer) = self.peers_by_id.get_mut(&peer_id) else {
                        return Ok(());
                    };
                    if !peer.candidates.contains(&src_addr) {
                        peer.candidates.push(src_addr);
                    }
                    let pong = DiscoMessage::Pong {
                        tx_id,
                        src: src_addr,
                        epoch: peer.local_epoch,
                    };
                    let sealed =
                        pong.seal(self.local_identity.exchange_secret(), &sender_exchange)?;
                    self.transmits.push_back(Transmit {
                        target: TransmitTarget::DirectUdp(src_addr),
                        payload: sealed,
                    });
                }
            }
            DiscoMessage::Pong { tx_id, src, .. } => {
                self.handle_pong(peer_id, from_udp, tx_id, src, now);
            }
            DiscoMessage::CallMeMaybe { my_numbers, .. } => {
                let my_numbers = if self.relay_only {
                    Vec::new()
                } else {
                    my_numbers
                };
                if let Some(peer) = self.peers_by_id.get_mut(&peer_id) {
                    for addr in &my_numbers {
                        if !peer.candidates.contains(addr) {
                            peer.candidates.push(*addr);
                        }
                    }
                }
                if epoch_changed {
                    // A new (or first) epoch from the peer: it restarted or just
                    // added us. Answer with our own CallMeMaybe right away so it
                    // learns our epoch even when no direct candidate is reachable;
                    // the exchange converges because an already-known epoch does
                    // not trigger another announcement.
                    self.send_probes_for_peer(peer_id, now);
                } else {
                    for addr in my_numbers {
                        self.send_ping(peer_id, addr, now);
                    }
                }
            }
        }
        Ok(())
    }

    /// A `Pong` validates the candidate it came back from: the peer is
    /// reachable there, the RTT is known, and a better or first direct path
    /// replaces the relay (Tailscale `handlePongConnLocked`).
    fn handle_pong(
        &mut self,
        peer_id: DeviceId,
        from_udp: Option<SocketAddr>,
        tx_id: TxId,
        src: SocketAddr,
        now: Instant,
    ) {
        let Some(remote_addr) = from_udp else {
            return;
        };
        let Some(peer) = self.peers_by_id.get_mut(&peer_id) else {
            return;
        };
        let Some((pinged, sent_at)) = peer.inflight_pings.remove(&tx_id) else {
            return;
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
        // The Pong validates the current path when it comes back from the
        // validated address or answers a Ping we sent to it (a multi-homed or
        // double-NATed peer may reply from another of its addresses).
        let validates_current = matches!(
            peer.path,
            ConnectionPath::Direct { remote } if remote == remote_addr || remote == pinged
        );
        if validates_current {
            peer.trust_until = Some(now + TRUST_UDP_ADDR_DURATION);
            peer.next_heartbeat_at = now + HEARTBEAT_INTERVAL;
            peer.last_direct_rx = Some(now);
            peer.liveness_probe_at = None;
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
}

fn dh_shared(local: &DeviceIdentity, peer_exchange: &[u8; 32]) -> [u8; 32] {
    let pub_point = X25519Public::from(*peer_exchange);
    local
        .exchange_secret()
        .diffie_hellman(&pub_point)
        .to_bytes()
}

/// `H("omegadesk-tunnel-v3:" || dh || sender || receiver || sender_epoch || receiver_epoch)`.
fn derive_direction_key(
    shared: &[u8; 32],
    sender: &[u8; 32],
    receiver: &[u8; 32],
    sender_epoch: Epoch,
    receiver_epoch: Epoch,
) -> [u8; 32] {
    let digest = Sha256::new()
        .chain_update(b"omegadesk-tunnel-v3:")
        .chain_update(shared)
        .chain_update(sender)
        .chain_update(receiver)
        .chain_update(sender_epoch)
        .chain_update(receiver_epoch)
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

/// Deduplicating helper for callers merging endpoint lists.
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

    /// Exchanges epochs over the relay in both directions (as the first
    /// `CallMeMaybe` round does in practice).
    fn exchange_epochs(a: &mut MeshNode, b: &mut MeshNode, now: Instant) {
        // Three legs cover every starting state: whoever hears a new epoch
        // re-announces its own once, so the exchange converges and stops.
        relay_all(a, b, now);
        relay_all(b, a, now);
        relay_all(a, b, now);
        while a.poll_transmit().is_some() {}
        while b.poll_transmit().is_some() {}
    }

    fn drain_events(node: &mut MeshNode) -> Vec<MeshEvent> {
        let mut out = Vec::new();
        while let Some(ev) = node.poll_event() {
            out.push(ev);
        }
        out
    }

    fn sample_packet() -> IpPacket {
        IpPacket::ipv4_udp(
            Ipv4Addr::new(100, 64, 0, 2),
            Ipv4Addr::new(100, 64, 0, 1),
            1234,
            5678,
            b"direct-mesh-payload",
        )
        .unwrap()
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
        assert!(!alice.peer_ready(bob_pub.id()));

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
        assert!(bob.peer_ready(alice_pub.id()) && alice.peer_ready(bob_pub.id()));
        let events = drain_events(&mut bob);
        assert!(events.iter().any(|e| matches!(e, MeshEvent::PathUpgraded { remote, rtt, .. } if *remote == alice_addr && *rtt == Duration::from_millis(30))));

        let inner = sample_packet();
        bob.encapsulate(alice_pub.id(), &inner, now).unwrap();
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
    fn keys_bind_both_epochs_and_a_restart_on_either_side_rekeys() {
        let now = Instant::now();
        let alice_id = DeviceIdentity::generate();
        let bob_id = DeviceIdentity::generate();
        let alice_pub = alice_id.public();
        let bob_pub = bob_id.public();
        let alice_secret = alice_id.to_secret_bytes();
        let bob_secret = bob_id.to_secret_bytes();

        let mut alice = MeshNode::new(alice_id, vec![], vec![]);
        let mut bob = MeshNode::new(bob_id, vec![], vec![]);
        alice.upsert_peer(bob_pub, vec![], now);
        bob.upsert_peer(alice_pub, vec![], now);
        let pkt = sample_packet();
        // Before the epoch exchange nothing can be encrypted.
        assert!(matches!(
            alice.encapsulate(bob_pub.id(), &pkt, now),
            Err(MeshError::PeerEpochUnknown(_))
        ));
        exchange_epochs(&mut alice, &mut bob, now);

        // Same plaintext, same counter (0) in both directions: ciphertexts differ.
        alice.encapsulate(bob_pub.id(), &pkt, now).unwrap();
        bob.encapsulate(alice_pub.id(), &pkt, now).unwrap();
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
        assert!(bob.handle_receive(None, &b_to_a, now).is_err());
        // Replay is rejected.
        assert!(bob.handle_receive(None, &a_to_b, now).is_err());

        // Alice restarts: fresh epoch. Her old ciphertext is useless to the new
        // Bob session, and Bob accepts her new packets after the exchange.
        let mut alice2 = MeshNode::new(
            DeviceIdentity::from_secret_bytes(&alice_secret).unwrap(),
            vec![],
            vec![],
        );
        alice2.upsert_peer(bob_pub, vec![], now);
        exchange_epochs(&mut alice2, &mut bob, now);
        alice2.encapsulate(bob_pub.id(), &pkt, now).unwrap();
        let fresh = alice2.poll_transmit().unwrap().payload;
        assert_ne!(fresh[36..44], a_to_b[36..44], "sender epoch must change");
        assert_eq!(
            bob.handle_receive(None, &fresh, now).unwrap().unwrap().1,
            pkt
        );
        assert!(
            bob.handle_receive(None, &a_to_b, now).is_err(),
            "old epoch is retired"
        );

        // Bob restarts: recorded ciphertext from Alice cannot be replayed into
        // the new Bob, because the key also binds the receiver's fresh epoch.
        let mut bob2 = MeshNode::new(
            DeviceIdentity::from_secret_bytes(&bob_secret).unwrap(),
            vec![],
            vec![],
        );
        bob2.upsert_peer(alice_pub, vec![], now);
        exchange_epochs(&mut alice2, &mut bob2, now);
        assert!(bob2.handle_receive(None, &fresh, now).is_err());
        alice2.encapsulate(bob_pub.id(), &pkt, now).unwrap();
        let after_bob_restart = alice2.poll_transmit().unwrap().payload;
        assert_eq!(
            bob2.handle_receive(None, &after_bob_restart, now)
                .unwrap()
                .unwrap()
                .1,
            pkt
        );

        // Removing and re-adding a peer on the same node also rekeys (no counter reuse).
        alice2.remove_peer(bob_pub.id());
        alice2.upsert_peer(bob_pub, vec![], now);
        exchange_epochs(&mut alice2, &mut bob2, now);
        alice2.encapsulate(bob_pub.id(), &pkt, now).unwrap();
        let readded = alice2.poll_transmit().unwrap().payload;
        assert_ne!(readded[36..44], after_bob_restart[36..44]);
        assert_ne!(
            readded[DATA_HEADER_LEN..],
            after_bob_restart[DATA_HEADER_LEN..]
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
        let later = now + RELAY_FALLBACK_TIMEOUT + PING_TIMEOUT;
        alice.handle_timeout(later);
        let peer = &alice.peers_by_id[&bob_pub.id()];
        assert_eq!(peer.inflight_pings.len(), 1);
        assert!(peer.inflight_pings.values().all(|(_, sent)| *sent == later));
        assert_eq!(peer.next_probe_at, later + RELAYED_PROBE_INTERVAL);
    }

    #[test]
    fn dead_direct_path_falls_back_after_trust_expires_or_within_two_seconds_under_traffic() {
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

        // While direct and idle, the next wake-up is the heartbeat, not a stale probe timer.
        assert_eq!(alice.poll_timeout(), Some(now + HEARTBEAT_INTERVAL));
        alice.handle_timeout(now + HEARTBEAT_INTERVAL);
        let heartbeat = alice.poll_transmit().unwrap();
        assert_eq!(heartbeat.target, TransmitTarget::DirectUdp(bob_addr));
        assert!(DiscoMessage::looks_like_disco(&heartbeat.payload));

        // Idle path: Bob never answers; after TRUST_UDP_ADDR_DURATION the path is dropped.
        alice.handle_timeout(now + TRUST_UDP_ADDR_DURATION);
        assert!(matches!(
            alice.peer_path(bob_pub.id()),
            Some(ConnectionPath::Relayed { .. })
        ));
        assert!(
            drain_events(&mut alice).contains(&MeshEvent::FallbackToRelay { peer: bob_pub.id() })
        );
        assert!(
            alice.poll_transmit().is_some(),
            "probing resumes immediately"
        );

        // Active traffic: re-validate, then send data right after the Pong and let the peer vanish.
        let t1 = now + Duration::from_secs(20);
        while alice.poll_transmit().is_some() {}
        alice.handle_timeout(t1);
        deliver_direct(&mut alice, alice_addr, &mut bob, t1);
        deliver_direct(&mut bob, bob_addr, &mut alice, t1);
        assert!(matches!(
            alice.peer_path(bob_pub.id()),
            Some(ConnectionPath::Direct { .. })
        ));
        drain_events(&mut alice);
        let t_send = t1 + Duration::from_millis(100);
        alice
            .encapsulate(bob_pub.id(), &sample_packet(), t_send)
            .unwrap();
        while alice.poll_transmit().is_some() {}
        // A liveness probe goes out 500 ms after the last thing heard from Bob...
        let probe_at = alice.poll_timeout().unwrap();
        assert_eq!(probe_at, t1 + DIRECT_LIVENESS_PROBE_AFTER);
        alice.handle_timeout(probe_at);
        assert!(alice.poll_transmit().is_some());
        // ...and the path is abandoned 1.5 s after it, well under 2 s.
        let drop_at = alice.poll_timeout().unwrap();
        assert_eq!(drop_at, t1 + DIRECT_LIVENESS_TIMEOUT);
        assert!(drop_at - t_send < Duration::from_secs(2));
        alice.handle_timeout(drop_at);
        assert!(matches!(
            alice.peer_path(bob_pub.id()),
            Some(ConnectionPath::Relayed { .. })
        ));
        assert!(
            drain_events(&mut alice).contains(&MeshEvent::FallbackToRelay { peer: bob_pub.id() })
        );
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
        let cmm = alice.poll_transmit().unwrap();
        assert_eq!(
            cmm.target,
            TransmitTarget::Relay(bob_pub.exchange_key_bytes())
        );
        assert_eq!(alice.next_stun_at, Some(now + STUN_REFRESH_INTERVAL));
        alice
            .handle_receive(
                Some(stun_server),
                &stun::binding_response(&[9u8; 12], public),
                now,
            )
            .unwrap();

        // With no peers left the periodic refresh is not scheduled, so an idle
        // driver never spins on a past deadline.
        alice.remove_peer(bob_pub.id());
        alice.handle_timeout(now + PING_TIMEOUT);
        assert_eq!(alice.poll_timeout(), None);
    }

    #[test]
    fn exchange_key_rotation_resets_peer_state() {
        let now = Instant::now();
        let alice_id = DeviceIdentity::generate();
        let bob_id = DeviceIdentity::generate();
        let bob_pub = bob_id.public();
        let mut alice = MeshNode::new(alice_id, vec![], vec![]);
        alice.upsert_peer(bob_pub, vec![], now);
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

    /// Delivers every queued transmit of `from` to `to`: direct ones as if
    /// they arrived from `from_addr`, relayed ones through the relay.
    fn deliver_everything(
        from: &mut MeshNode,
        from_addr: SocketAddr,
        to: &mut MeshNode,
        now: Instant,
    ) {
        while let Some(tx) = from.poll_transmit() {
            let via = match tx.target {
                TransmitTarget::DirectUdp(_) => Some(from_addr),
                TransmitTarget::Relay(_) => None,
            };
            to.handle_receive(via, &tx.payload, now).unwrap();
        }
    }

    /// Sends one data packet from `from` to `to` and asserts it rides the relay.
    fn relayed_round_trip(
        from: &mut MeshNode,
        to: &mut MeshNode,
        to_pub: &DevicePublic,
        now: Instant,
    ) {
        let pkt = sample_packet();
        from.encapsulate(to_pub.id(), &pkt, now).unwrap();
        let data = from.poll_transmit().unwrap();
        assert_eq!(
            data.target,
            TransmitTarget::Relay(to_pub.exchange_key_bytes())
        );
        let (_, received) = to
            .handle_receive(None, &data.payload, now)
            .unwrap()
            .unwrap();
        assert_eq!(received, pkt);
    }

    #[test]
    fn relay_only_node_never_validates_a_direct_path_even_with_a_normal_peer() {
        let now = Instant::now();
        let alice_id = DeviceIdentity::generate();
        let bob_id = DeviceIdentity::generate();
        let alice_pub = alice_id.public();
        let bob_pub = bob_id.public();
        let alice_addr: SocketAddr = "198.51.100.10:51820".parse().unwrap();
        let bob_addr: SocketAddr = "203.0.113.20:51820".parse().unwrap();
        // Alice is relay-only but still has an address a peer could reach;
        // Bob is a normal node that knows it from the netmap.
        let mut alice = MeshNode::new(alice_id, vec![alice_addr], vec![]);
        alice.set_relay_only(true);
        assert!(alice.relay_only());
        assert!(alice.local_endpoints().is_empty(), "nothing is advertised");
        let mut bob = MeshNode::new(bob_id, vec![bob_addr], vec![]);
        alice.upsert_peer(bob_pub, vec![bob_addr], now);
        bob.upsert_peer(alice_pub, vec![alice_addr], now);

        // Alice never sends anything directly, even though Bob's candidate is
        // known; Bob's direct pings are dropped and his CallMeMaybe endpoints
        // ignored, so no Pong ever comes back.
        for _ in 0..3 {
            while let Some(tx) = alice.poll_transmit() {
                assert!(matches!(tx.target, TransmitTarget::Relay(_)), "{tx:?}");
                bob.handle_receive(None, &tx.payload, now).unwrap();
            }
            deliver_everything(&mut bob, bob_addr, &mut alice, now);
        }
        assert!(
            alice.poll_transmit().is_none(),
            "no Pong, no ping from Alice"
        );
        assert!(matches!(
            alice.peer_path(bob_pub.id()),
            Some(ConnectionPath::Relayed { .. })
        ));
        assert!(matches!(
            bob.peer_path(alice_pub.id()),
            Some(ConnectionPath::Relayed { .. })
        ));

        // Bob gives up on the direct path within the budget, and data still
        // flows over the relay in both directions.
        bob.handle_timeout(now + RELAY_FALLBACK_TIMEOUT);
        assert!(
            drain_events(&mut bob).contains(&MeshEvent::FallbackToRelay {
                peer: alice_pub.id()
            })
        );
        assert!(alice.peer_ready(bob_pub.id()) && bob.peer_ready(alice_pub.id()));
        // The fallback re-probes; deliver those first so only data is left.
        deliver_everything(&mut bob, bob_addr, &mut alice, now);
        deliver_everything(&mut alice, alice_addr, &mut bob, now);
        relayed_round_trip(&mut bob, &mut alice, &alice_pub, now);
        relayed_round_trip(&mut alice, &mut bob, &bob_pub, now);
        // A direct data packet aimed at Alice is dropped without an error.
        bob.encapsulate(alice_pub.id(), &sample_packet(), now)
            .unwrap();
        let data = bob.poll_transmit().unwrap();
        assert_eq!(
            alice
                .handle_receive(Some(bob_addr), &data.payload, now)
                .unwrap(),
            None
        );
    }

    #[test]
    fn direct_liveness_counts_packets_from_any_alias_of_the_peer() {
        // Field test 2026-11-01: a peer behind a double NAT answered from its
        // router's address while the validated path pointed at its LAN
        // address; every packet from the "other" alias was ignored for
        // liveness, so the path flapped to the relay every 1.5 s.
        let now = Instant::now();
        let alice_id = DeviceIdentity::generate();
        let bob_id = DeviceIdentity::generate();
        let alice_pub = alice_id.public();
        let bob_pub = bob_id.public();
        let alice_addr: SocketAddr = "192.168.1.19:64141".parse().unwrap();
        let bob_lan: SocketAddr = "192.168.15.36:7070".parse().unwrap();
        let bob_router: SocketAddr = "192.168.1.14:7070".parse().unwrap();
        let mut alice = MeshNode::new(alice_id, vec![alice_addr], vec![]);
        let mut bob = MeshNode::new(bob_id, vec![bob_lan], vec![]);
        alice.upsert_peer(bob_pub, vec![bob_lan], now);
        bob.upsert_peer(alice_pub, vec![alice_addr], now);
        deliver_direct(&mut alice, alice_addr, &mut bob, now);
        deliver_direct(&mut bob, bob_lan, &mut alice, now);
        assert_eq!(
            alice.peer_path(bob_pub.id()),
            Some(ConnectionPath::Direct { remote: bob_lan })
        );
        drain_events(&mut alice);

        // Alice keeps sending; Bob's replies arrive from the router alias.
        let mut t = now;
        for _ in 0..6 {
            t += Duration::from_millis(400);
            alice.handle_timeout(t);
            alice
                .encapsulate(bob_pub.id(), &sample_packet(), t)
                .unwrap();
            while alice.poll_transmit().is_some() {}
            bob.encapsulate(alice_pub.id(), &sample_packet(), t)
                .unwrap();
            let reply = bob.poll_transmit().unwrap();
            alice
                .handle_receive(Some(bob_router), &reply.payload, t)
                .unwrap()
                .unwrap();
        }
        alice.handle_timeout(t + DIRECT_LIVENESS_TIMEOUT);
        assert!(
            !drain_events(&mut alice).contains(&MeshEvent::FallbackToRelay { peer: bob_pub.id() }),
            "replies from an alias keep the direct path alive"
        );
        assert_eq!(
            alice.peer_path(bob_pub.id()),
            Some(ConnectionPath::Direct { remote: bob_lan })
        );
    }

    /// Validates a direct path from `a` to `b` by exchanging the initial probes.
    fn establish_direct(
        a: &mut MeshNode,
        a_addr: SocketAddr,
        b: &mut MeshNode,
        b_addr: SocketAddr,
        now: Instant,
    ) {
        deliver_direct(a, a_addr, b, now);
        deliver_direct(b, b_addr, a, now);
        drain_events(a);
        drain_events(b);
    }

    #[test]
    fn asymmetric_paths_are_stable_when_liveness_pings_are_answered() {
        // Field test 2026-11-01: both sides flapped every ~2 s. Alice sent
        // directly while Bob (who had just fallen back) sent through the relay;
        // Bob's relayed data did not count as liveness for Alice, so her path
        // died 1.5 s later and dragged Bob along. Only the answer to the
        // explicit liveness Ping decides now.
        let now = Instant::now();
        let alice_id = DeviceIdentity::generate();
        let bob_id = DeviceIdentity::generate();
        let alice_pub = alice_id.public();
        let bob_pub = bob_id.public();
        let alice_addr: SocketAddr = "192.168.1.19:64141".parse().unwrap();
        let bob_addr: SocketAddr = "192.168.1.14:7070".parse().unwrap();
        let mut alice = MeshNode::new(alice_id, vec![alice_addr], vec![]);
        let mut bob = MeshNode::new(bob_id, vec![bob_addr], vec![]);
        alice.upsert_peer(bob_pub, vec![bob_addr], now);
        bob.upsert_peer(alice_pub, vec![alice_addr], now);
        establish_direct(&mut alice, alice_addr, &mut bob, bob_addr, now);
        assert!(matches!(
            alice.peer_path(bob_pub.id()),
            Some(ConnectionPath::Direct { .. })
        ));

        let mut t = now;
        for _ in 0..12 {
            t += Duration::from_millis(500);
            // Alice sends directly; Bob's data comes back through the relay only.
            alice
                .encapsulate(bob_pub.id(), &sample_packet(), t)
                .unwrap();
            while alice.poll_transmit().is_some() {}
            bob.encapsulate(alice_pub.id(), &sample_packet(), t)
                .unwrap();
            let relayed = bob.poll_transmit().unwrap();
            alice
                .handle_receive(None, &relayed.payload, t)
                .unwrap()
                .unwrap();
            // Alice's timers: a liveness Ping goes out; Bob answers it directly.
            alice.handle_timeout(t);
            deliver_direct(&mut alice, alice_addr, &mut bob, t);
            deliver_direct(&mut bob, bob_addr, &mut alice, t);
        }
        assert!(
            !drain_events(&mut alice).contains(&MeshEvent::FallbackToRelay { peer: bob_pub.id() }),
            "answered liveness pings keep the direct path"
        );
        assert_eq!(
            alice.peer_path(bob_pub.id()),
            Some(ConnectionPath::Direct { remote: bob_addr })
        );
    }

    #[test]
    fn heartbeat_pong_from_an_alias_refreshes_trust() {
        let now = Instant::now();
        let alice_id = DeviceIdentity::generate();
        let bob_id = DeviceIdentity::generate();
        let alice_pub = alice_id.public();
        let bob_pub = bob_id.public();
        let alice_addr: SocketAddr = "192.168.1.19:64141".parse().unwrap();
        let bob_lan: SocketAddr = "192.168.15.36:7070".parse().unwrap();
        let bob_router: SocketAddr = "192.168.1.14:7070".parse().unwrap();
        let mut alice = MeshNode::new(alice_id, vec![alice_addr], vec![]);
        let mut bob = MeshNode::new(bob_id, vec![bob_lan], vec![]);
        alice.upsert_peer(bob_pub, vec![bob_lan], now);
        bob.upsert_peer(alice_pub, vec![alice_addr], now);
        establish_direct(&mut alice, alice_addr, &mut bob, bob_lan, now);
        assert_eq!(
            alice.peer_path(bob_pub.id()),
            Some(ConnectionPath::Direct { remote: bob_lan })
        );

        // Idle path: heartbeats every 3 s, each Pong arriving from the router
        // alias instead of the validated LAN address, for longer than the
        // 6.5 s trust window.
        let mut t = now;
        for _ in 0..4 {
            t += HEARTBEAT_INTERVAL;
            alice.handle_timeout(t);
            deliver_direct(&mut alice, alice_addr, &mut bob, t);
            deliver_direct(&mut bob, bob_router, &mut alice, t);
        }
        assert!(
            !drain_events(&mut alice).contains(&MeshEvent::FallbackToRelay { peer: bob_pub.id() }),
            "a Pong answering a Ping to the validated address refreshes trust"
        );
        assert_eq!(
            alice.peer_path(bob_pub.id()),
            Some(ConnectionPath::Direct { remote: bob_lan })
        );
    }
}
