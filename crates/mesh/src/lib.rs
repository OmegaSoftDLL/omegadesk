//! Sans-I/O mesh connectivity engine (`omegadesk-mesh`).
//!
//! Combines two reference designs:
//! - **Firezone `snownet`** (`rust/libs/connlib/snownet/src/node.rs`, Apache-2.0):
//!   Sans-I/O [`MeshNode`] state machine driven purely by timestamps and buffers
//!   (`poll_timeout`, `handle_timeout`, `handle_receive`, `poll_transmit`,
//!   `poll_event`, `encapsulate`), making NAT traversal and relay failover
//!   100% deterministic and testable without real sockets.
//! - **Tailscale `disco` & `magicsock`** (`disco/disco.go`, BSD-3-Clause):
//!   Continuous background hole-punching (`CallMeMaybe` -> `Ping` -> `Pong`)
//!   that falls back to the relay within [`RELAY_FALLBACK_TIMEOUT`] (1.5 s, well
//!   under the 2 s Phase 2 target) when direct UDP fails, and upgrades seamlessly
//!   to [`ConnectionPath::Direct`] as soon as a direct `Pong` arrives.

pub mod disco;

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use omegadesk_identity::{DeviceId, DeviceIdentity, DevicePublic};
use omegadesk_tun::{IpPacket, TunError};
use ring::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey};
use sha2::{Digest, Sha256};
use x25519_dalek::PublicKey as X25519Public;

pub use disco::{DiscoError, DiscoMessage, MAGIC as DISCO_MAGIC, TxId, random_tx_id};

/// Maximum time to wait for a direct `Pong` before falling back to the relay
/// (1.5 seconds, satisfying the `< 2 s` Phase 2 requirement).
pub const RELAY_FALLBACK_TIMEOUT: Duration = Duration::from_millis(1500);

/// Interval between direct path upgrade probes (`CallMeMaybe` + `Ping`).
pub const DIRECT_PROBE_INTERVAL: Duration = Duration::from_millis(500);

/// Four-byte header identifying an encrypted tunnel data packet on the wire
/// (analogous to WireGuard's Type 4 Transport Data header).
pub const DATA_HEADER_MAGIC: [u8; 4] = *b"ODWG";

const DATA_HEADER_LEN: usize = 4 + 32 + 8; // 4B magic + 32B sender X25519 + 8B LE counter
const TAG_LEN: usize = 16;

/// Active transport path for a peer in the mesh, modeled after Firezone's
/// `snownet::ConnectionPath`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionPath {
    /// Direct peer-to-peer UDP socket address discovered via `disco`.
    Direct {
        ///Validated remote UDP socket address of the peer.
        remote: SocketAddr,
    },
    /// Relayed through an `omegadesk-relay` server addressed by the peer's
    /// 32-byte X25519 public key.
    Relayed {
        /// Peer's 32-byte X25519 public key used as its DERP/relay destination.
        peer_exchange_key: [u8; 32],
    },
}

/// Destination for an outbound packet produced by [`MeshNode::poll_transmit`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransmitTarget {
    /// Send directly as a UDP datagram to `SocketAddr`.
    DirectUdp(SocketAddr),
    /// Send over the HTTPS/TCP relay addressed to the peer's 32-byte X25519 key.
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
    /// Direct UDP probes did not succeed within [`RELAY_FALLBACK_TIMEOUT`];
    /// traffic is now flowing over the relay while background probing continues.
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
    /// Built-in STUN feedback: a peer reported our observed reflexive UDP address.
    ObservedReflexiveAddr(SocketAddr),
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
    session_key: [u8; 32],
    send_counter: u64,
    replay: ReplayWindow,
    added_at: Instant,
    next_probe_at: Instant,
    fallback_deadline: Option<Instant>,
    inflight_pings: HashMap<TxId, (SocketAddr, Instant)>,
    connected_emitted: bool,
}

/// Sans-I/O mesh connectivity engine managing peer tunnels, `disco` hole-punching,
/// and relay-to-direct path upgrades.
pub struct MeshNode {
    local_identity: DeviceIdentity,
    local_candidates: Vec<SocketAddr>,
    observed_reflexives: Vec<SocketAddr>,
    peers_by_id: HashMap<DeviceId, PeerState>,
    peers_by_exchange: HashMap<[u8; 32], DeviceId>,
    transmits: VecDeque<Transmit>,
    events: VecDeque<MeshEvent>,
}

impl MeshNode {
    /// Creates a new sans-I/O [`MeshNode`] for `local_identity` advertising
    /// `local_candidates` as its local LAN UDP endpoints.
    #[must_use]
    pub fn new(local_identity: DeviceIdentity, local_candidates: Vec<SocketAddr>) -> Self {
        Self {
            local_identity,
            local_candidates,
            observed_reflexives: Vec::new(),
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

    /// Registers or updates a peer from the coordinator's netmap and immediately
    /// begins simultaneous direct UDP probing while keeping the relay path ready.
    pub fn upsert_peer(
        &mut self,
        peer_public: DevicePublic,
        candidates: Vec<SocketAddr>,
        now: Instant,
    ) {
        let peer_id = peer_public.id();
        let peer_exchange = peer_public.exchange_key_bytes();
        let session_key = derive_tunnel_key(&self.local_identity, &peer_exchange);

        self.peers_by_exchange.insert(peer_exchange, peer_id);

        if let Some(existing) = self.peers_by_id.get_mut(&peer_id) {
            existing.candidates = candidates;
            existing.next_probe_at = now;
        } else {
            let state = PeerState {
                public: peer_public,
                candidates,
                path: ConnectionPath::Relayed {
                    peer_exchange_key: peer_exchange,
                },
                session_key,
                send_counter: 0,
                replay: ReplayWindow::default(),
                added_at: now,
                next_probe_at: now,
                fallback_deadline: Some(now + RELAY_FALLBACK_TIMEOUT),
                inflight_pings: HashMap::new(),
                connected_emitted: false,
            };
            self.peers_by_id.insert(peer_id, state);
        }

        self.send_probes_for_peer(peer_id, now);
    }

    /// Returns the currently active [`ConnectionPath`] for `peer`.
    #[must_use]
    pub fn peer_path(&self, peer: DeviceId) -> Option<ConnectionPath> {
        self.peers_by_id.get(&peer).map(|p| p.path)
    }

    /// Returns the earliest [`Instant`] at which [`Self::handle_timeout`] must be called.
    #[must_use]
    pub fn poll_timeout(&self) -> Option<Instant> {
        let mut earliest: Option<Instant> = None;
        for peer in self.peers_by_id.values() {
            earliest = Some(earliest.map_or(peer.next_probe_at, |e| e.min(peer.next_probe_at)));
            if let Some(deadline) = peer.fallback_deadline {
                earliest = Some(earliest.map_or(deadline, |e| e.min(deadline)));
            }
        }
        earliest
    }

    /// Advances internal timers to `now`, triggering relay fallback if direct
    /// hole-punching has not completed within [`RELAY_FALLBACK_TIMEOUT`] and
    /// scheduling periodic direct-upgrade probes while on the relay.
    pub fn handle_timeout(&mut self, now: Instant) {
        let peer_ids: Vec<DeviceId> = self.peers_by_id.keys().copied().collect();
        for peer_id in peer_ids {
            let mut should_probe = false;
            if let Some(peer) = self.peers_by_id.get_mut(&peer_id) {
                if let Some(deadline) = peer.fallback_deadline
                    && now >= deadline
                {
                    peer.fallback_deadline = None;
                    if matches!(peer.path, ConnectionPath::Relayed { .. }) {
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
                }
                if now >= peer.next_probe_at {
                    should_probe = matches!(peer.path, ConnectionPath::Relayed { .. });
                    peer.next_probe_at = now + DIRECT_PROBE_INTERVAL;
                }
            }
            if should_probe {
                self.send_probes_for_peer(peer_id, now);
            }
        }
    }

    /// Encapsulates and encrypts an outbound [`IpPacket`] destined for `peer`
    /// and queues it for transmission on the peer's active [`ConnectionPath`].
    ///
    /// # Errors
    ///
    /// Returns [`MeshError::UnknownPeer`] if `peer` is not in the netmap.
    pub fn encapsulate(
        &mut self,
        peer_id: DeviceId,
        packet: &IpPacket,
        now: Instant,
    ) -> Result<(), MeshError> {
        let _ = now;
        let peer = self
            .peers_by_id
            .get_mut(&peer_id)
            .ok_or(MeshError::UnknownPeer(peer_id))?;

        let counter = peer.send_counter;
        peer.send_counter += 1;

        let local_exchange = self.local_identity.public().exchange_key_bytes();
        let mut header = Vec::with_capacity(DATA_HEADER_LEN);
        header.extend_from_slice(&DATA_HEADER_MAGIC);
        header.extend_from_slice(&local_exchange);
        header.extend_from_slice(&counter.to_le_bytes());

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..12].copy_from_slice(&counter.to_le_bytes());

        let unbound = UnboundKey::new(&CHACHA20_POLY1305, &peer.session_key)
            .map_err(|_| MeshError::TunnelAuthFailed)?;
        let key = LessSafeKey::new(unbound);

        let mut body = packet.as_bytes().to_vec();
        key.seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce_bytes),
            Aad::from(&header),
            &mut body,
        )
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

    /// Processes an inbound datagram arriving from either direct UDP (`from_udp = Some(addr)`)
    /// or the relay (`from_udp = None`).
    ///
    /// Returns `Ok(Some((peer_id, ip_packet)))` when the datagram is an encrypted
    /// tunnel data packet, or `Ok(None)` when it was a `disco` control message
    /// handled internally.
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
        let mut counter_bytes = [0u8; 8];
        counter_bytes.copy_from_slice(&datagram[36..44]);
        let counter = u64::from_le_bytes(counter_bytes);

        let Some(&peer_id) = self.peers_by_exchange.get(&sender_exchange) else {
            return Err(MeshError::TunnelAuthFailed);
        };
        let peer = self
            .peers_by_id
            .get_mut(&peer_id)
            .ok_or(MeshError::UnknownPeer(peer_id))?;

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..12].copy_from_slice(&counter_bytes);

        let unbound = UnboundKey::new(&CHACHA20_POLY1305, &peer.session_key)
            .map_err(|_| MeshError::TunnelAuthFailed)?;
        let key = LessSafeKey::new(unbound);

        let mut buf = datagram[DATA_HEADER_LEN..].to_vec();
        let plaintext = key
            .open_in_place(
                Nonce::assume_unique_for_key(nonce_bytes),
                Aad::from(header),
                &mut buf,
            )
            .map_err(|_| MeshError::TunnelAuthFailed)?;

        if !peer.replay.check_and_accept(counter) {
            return Err(MeshError::TunnelAuthFailed);
        }

        let ip_packet = IpPacket::parse(plaintext.to_vec())?;
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

    fn all_self_numbers(&self) -> Vec<SocketAddr> {
        let mut out = self.local_candidates.clone();
        for addr in &self.observed_reflexives {
            if !out.contains(addr) {
                out.push(*addr);
            }
        }
        out
    }

    fn send_probes_for_peer(&mut self, peer_id: DeviceId, now: Instant) {
        let my_numbers = self.all_self_numbers();
        let local_pub = self.local_identity.public().exchange_key_bytes();

        let Some(peer) = self.peers_by_id.get_mut(&peer_id) else {
            return;
        };
        let peer_exchange = peer.public.exchange_key_bytes();

        // 1. Send CallMeMaybe over the relay so the peer punches back toward our endpoints.
        let cmm = DiscoMessage::CallMeMaybe { my_numbers };
        if let Ok(sealed_cmm) = cmm.seal(self.local_identity.exchange_secret(), &peer_exchange) {
            self.transmits.push_back(Transmit {
                target: TransmitTarget::Relay(peer_exchange),
                payload: sealed_cmm,
            });
        }

        // 2. Send direct UDP Ping probes to every known candidate of the peer.
        let candidates = peer.candidates.clone();
        for candidate in candidates {
            let tx_id = random_tx_id();
            let ping = DiscoMessage::Ping {
                tx_id,
                node_key: local_pub,
                padding: 0,
            };
            if let Ok(sealed_ping) =
                ping.seal(self.local_identity.exchange_secret(), &peer_exchange)
            {
                peer.inflight_pings.insert(tx_id, (candidate, now));
                self.transmits.push_back(Transmit {
                    target: TransmitTarget::DirectUdp(candidate),
                    payload: sealed_ping,
                });
            }
        }
        let _ = peer.added_at;
        peer.next_probe_at = now + DIRECT_PROBE_INTERVAL;
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
                if !self.observed_reflexives.contains(&src) {
                    self.observed_reflexives.push(src);
                    self.events.push_back(MeshEvent::ObservedReflexiveAddr(src));
                }
                if let Some(remote_addr) = from_udp
                    && let Some(peer) = self.peers_by_id.get_mut(&peer_id)
                    && let Some((_, sent_at)) = peer.inflight_pings.remove(&tx_id)
                {
                    let rtt = now.saturating_duration_since(sent_at);
                    let was_relayed = matches!(peer.path, ConnectionPath::Relayed { .. });
                    peer.path = ConnectionPath::Direct {
                        remote: remote_addr,
                    };
                    peer.fallback_deadline = None;
                    if !peer.connected_emitted {
                        peer.connected_emitted = true;
                        self.events.push_back(MeshEvent::Connected {
                            peer: peer_id,
                            path: peer.path,
                        });
                    }
                    if was_relayed {
                        self.events.push_back(MeshEvent::PathUpgraded {
                            peer: peer_id,
                            remote: remote_addr,
                            rtt,
                        });
                    }
                }
            }
            DiscoMessage::CallMeMaybe { my_numbers } => {
                let local_pub = self.local_identity.public().exchange_key_bytes();
                if let Some(peer) = self.peers_by_id.get_mut(&peer_id) {
                    for addr in my_numbers {
                        if !peer.candidates.contains(&addr) {
                            peer.candidates.push(addr);
                        }
                        let tx_id = random_tx_id();
                        let ping = DiscoMessage::Ping {
                            tx_id,
                            node_key: local_pub,
                            padding: 0,
                        };
                        let sealed =
                            ping.seal(self.local_identity.exchange_secret(), &sender_exchange)?;
                        peer.inflight_pings.insert(tx_id, (addr, now));
                        self.transmits.push_back(Transmit {
                            target: TransmitTarget::DirectUdp(addr),
                            payload: sealed,
                        });
                    }
                }
            }
        }
        Ok(())
    }
}

fn derive_tunnel_key(local: &DeviceIdentity, peer_exchange: &[u8; 32]) -> [u8; 32] {
    let local_pub = local.public().exchange_key_bytes();
    let (first_key, second_key) = if local_pub <= *peer_exchange {
        (local_pub, *peer_exchange)
    } else {
        (*peer_exchange, local_pub)
    };
    let pub_point = X25519Public::from(*peer_exchange);
    let shared = local.exchange_secret().diffie_hellman(&pub_point);
    let digest = Sha256::new()
        .chain_update(b"omegadesk-wg-tunnel-v1:")
        .chain_update(shared.as_bytes())
        .chain_update(first_key)
        .chain_update(second_key)
        .finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&digest);
    key
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn upgrades_from_relay_to_direct_path_via_disco_hole_punch() {
        let now = Instant::now();
        let alice_id = DeviceIdentity::generate();
        let bob_id = DeviceIdentity::generate();
        let alice_pub = alice_id.public();
        let bob_pub = bob_id.public();

        let alice_addr: SocketAddr = "198.51.100.10:51820".parse().unwrap();
        let bob_addr: SocketAddr = "203.0.113.20:51820".parse().unwrap();

        let mut alice = MeshNode::new(alice_id, vec![alice_addr]);
        let mut bob = MeshNode::new(bob_id, vec![bob_addr]);

        // Alice learns about Bob with no initial direct candidates (only relay)
        alice.upsert_peer(bob_pub, vec![], now);
        // Bob learns about Alice with no initial direct candidates
        bob.upsert_peer(alice_pub, vec![], now);

        // Alice's CallMeMaybe travels over the relay to Bob
        while let Some(tx) = alice.poll_transmit() {
            if matches!(tx.target, TransmitTarget::Relay(_)) {
                bob.handle_receive(None, &tx.payload, now + Duration::from_millis(10))
                    .unwrap();
            }
        }

        // Bob responds to Alice's CallMeMaybe with a direct UDP Ping to `alice_addr`
        while let Some(tx) = bob.poll_transmit() {
            if let TransmitTarget::DirectUdp(dst) = tx.target {
                assert_eq!(dst, alice_addr);
                alice
                    .handle_receive(Some(bob_addr), &tx.payload, now + Duration::from_millis(25))
                    .unwrap();
            }
        }

        // Alice replies with a direct UDP Pong to `bob_addr`
        while let Some(tx) = alice.poll_transmit() {
            if let TransmitTarget::DirectUdp(dst) = tx.target {
                assert_eq!(dst, bob_addr);
                bob.handle_receive(
                    Some(alice_addr),
                    &tx.payload,
                    now + Duration::from_millis(40),
                )
                .unwrap();
            }
        }

        // Bob has now upgraded to a Direct path to Alice in 40 ms (< 2 s)!
        assert_eq!(
            bob.peer_path(alice_pub.id()),
            Some(ConnectionPath::Direct { remote: alice_addr })
        );

        let mut saw_upgrade = false;
        while let Some(ev) = bob.poll_event() {
            if let MeshEvent::PathUpgraded { peer, remote, rtt } = ev {
                assert_eq!(peer, alice_pub.id());
                assert_eq!(remote, alice_addr);
                assert_eq!(rtt, Duration::from_millis(30));
                saw_upgrade = true;
            }
        }
        assert!(saw_upgrade);

        // Encapsulate an IPv4 packet from Bob to Alice over the newly upgraded direct path
        let inner = IpPacket::ipv4_udp(
            Ipv4Addr::new(100, 64, 0, 2),
            Ipv4Addr::new(100, 64, 0, 1),
            1234,
            5678,
            b"direct-mesh-payload",
        );
        bob.encapsulate(alice_pub.id(), &inner, now + Duration::from_millis(50))
            .unwrap();
        let data_tx = bob.poll_transmit().unwrap();
        assert_eq!(data_tx.target, TransmitTarget::DirectUdp(alice_addr));

        let (_, decapsulated) = alice
            .handle_receive(
                Some(bob_addr),
                &data_tx.payload,
                now + Duration::from_millis(55),
            )
            .unwrap()
            .unwrap();
        assert_eq!(decapsulated, inner);

        // Replaying the exact same encrypted packet must be rejected by the anti-replay window
        assert!(matches!(
            alice.handle_receive(
                Some(bob_addr),
                &data_tx.payload,
                now + Duration::from_millis(56),
            ),
            Err(MeshError::TunnelAuthFailed)
        ));
    }

    #[test]
    fn falls_back_to_relay_under_two_seconds_when_udp_blocked() {
        let now = Instant::now();
        let alice_id = DeviceIdentity::generate();
        let bob_id = DeviceIdentity::generate();
        let bob_pub = bob_id.public();

        let mut alice = MeshNode::new(alice_id, vec!["10.0.0.2:51820".parse().unwrap()]);
        alice.upsert_peer(bob_pub, vec!["203.0.113.99:51820".parse().unwrap()], now);

        // Drain initial probes (simulate 100% UDP packet loss)
        while alice.poll_transmit().is_some() {}

        let timeout = alice.poll_timeout().unwrap();
        assert!(timeout <= now + RELAY_FALLBACK_TIMEOUT);
        assert!(RELAY_FALLBACK_TIMEOUT < Duration::from_secs(2));

        // Advance time to RELAY_FALLBACK_TIMEOUT (1.5 s)
        alice.handle_timeout(now + RELAY_FALLBACK_TIMEOUT);

        let mut saw_fallback = false;
        while let Some(ev) = alice.poll_event() {
            if ev == (MeshEvent::FallbackToRelay { peer: bob_pub.id() }) {
                saw_fallback = true;
            }
        }
        assert!(saw_fallback);
        assert_eq!(
            alice.peer_path(bob_pub.id()),
            Some(ConnectionPath::Relayed {
                peer_exchange_key: bob_pub.exchange_key_bytes()
            })
        );
    }
}
