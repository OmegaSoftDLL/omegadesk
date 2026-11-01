//! Peer relaying (`Nebula`-style signed relay certificates) and coordinator-free
//! link-state routing (`OSPF` / Dijkstra shortest-path tree).
//!
//! Architecture & reference design (`docs/plan.md` §2.2 lines 44–45 & §4 Phase 7 line 307):
//! - **Peer Relaying (`Nebula` model)**: any mesh node holding a valid
//!   [`PeerRelayCertificate`] signed by the tenant authority with `can_relay = true`
//!   can forward encrypted WireGuard/QUIC packets between two peers that cannot establish
//!   a direct UDP path.
//! - **Coordinator-Free Link-State Routing (`OSPF` model inspired by `EasyTier`)**:
//!   nodes exchange sequence-numbered [`LinkStateAdvertisement`] (`LSA`) packets carrying
//!   measured neighbor RTTs, and [`LinkStateRouter`] computes minimum-RTT paths (direct or
//!   via an authorized peer relay) using Dijkstra's shortest-path algorithm without
//!   requiring a central coordinator.

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, HashSet};
use std::time::{Duration, Instant};

use omegadesk_identity::{DeviceId, DeviceIdentity, DevicePublic, IdentityError};

/// Default inactivity timeout before an on-demand (`lazyconn`) peer tunnel is put back
/// to sleep (`NetBird` `client/internal/lazyconn/inactivity`, 15 minutes).
pub const DEFAULT_LAZY_CONN_INACTIVITY_THRESHOLD: Duration = Duration::from_secs(15 * 60);

/// Per-peer state in [`LazyConnManager`] (`docs/plan.md` §2.2 line 43, modeled after
/// `NetBird` `client/internal/lazyconn/manager/manager.go`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LazyPeerState {
    /// Tunnel is idle/sleeping with only an activity watcher armed.
    Sleeping,
    /// Outbound traffic or HA-group activation woke the peer; tunnel is active.
    Active {
        /// Timestamp of the most recent packet activity on this peer tunnel.
        last_activity: Instant,
    },
    /// Peer is excluded from lazy connection management and maintains a permanent tunnel.
    ExcludedPermanent,
}

/// On-demand (`lazyconn`) peer tunnel lifecycle manager (`docs/plan.md` §2.2 line 43,
/// ported from `NetBird` `client/internal/lazyconn/manager/manager.go`).
///
/// Keeps mesh peer tunnels in [`LazyPeerState::Sleeping`] until outbound packets target
/// the peer (or a co-member of its High-Availability route group wakes up), and transitions
/// idle tunnels back to [`LazyPeerState::Sleeping`] once `inactivity_threshold` elapses.
#[derive(Debug, Clone)]
pub struct LazyConnManager {
    inactivity_threshold: Duration,
    peers: HashMap<DeviceId, LazyPeerState>,
    ha_groups: HashMap<String, Vec<DeviceId>>,
}

impl LazyConnManager {
    /// Creates a new [`LazyConnManager`] with the given `inactivity_threshold`.
    #[must_use]
    pub fn new(inactivity_threshold: Duration) -> Self {
        Self {
            inactivity_threshold: inactivity_threshold.max(Duration::from_secs(1)),
            peers: HashMap::new(),
            ha_groups: HashMap::new(),
        }
    }

    /// Registers a managed peer in [`LazyPeerState::Sleeping`] (unless already excluded).
    pub fn register_lazy_peer(&mut self, peer: DeviceId) {
        self.peers.entry(peer).or_insert(LazyPeerState::Sleeping);
    }

    /// Updates the set of peers excluded from lazy connection management (permanent tunnels),
    /// matching `NetBird` `Manager.ExcludePeer`.
    pub fn set_excluded_peers(&mut self, excluded: &HashSet<DeviceId>, now: Instant) {
        for (&peer, state) in &mut self.peers {
            if excluded.contains(&peer) {
                *state = LazyPeerState::ExcludedPermanent;
            } else if *state == LazyPeerState::ExcludedPermanent {
                *state = LazyPeerState::Active { last_activity: now };
            }
        }
        for &peer in excluded {
            self.peers.insert(peer, LazyPeerState::ExcludedPermanent);
        }
    }

    /// Registers a High-Availability (`HA`) route group so waking any peer in `group_id`
    /// simultaneously activates all peers in the group (`NetBird` `UpdateRouteHAMap`).
    pub fn set_ha_group(&mut self, group_id: impl Into<String>, members: Vec<DeviceId>) {
        self.ha_groups.insert(group_id.into(), members);
    }

    /// Records packet activity for `peer` at `now`, waking `peer` (and any co-members of its
    /// HA groups) from [`LazyPeerState::Sleeping`] to [`LazyPeerState::Active`].
    ///
    /// Returns the list of peers that transitioned from `Sleeping` to `Active`.
    pub fn on_peer_activity(&mut self, peer: DeviceId, now: Instant) -> Vec<DeviceId> {
        let mut woken = Vec::new();
        let mut targets = vec![peer];
        for members in self.ha_groups.values() {
            if members.contains(&peer) {
                for &m in members {
                    if !targets.contains(&m) {
                        targets.push(m);
                    }
                }
            }
        }

        for target in targets {
            match self.peers.get_mut(&target) {
                Some(LazyPeerState::ExcludedPermanent) => {}
                Some(state @ LazyPeerState::Sleeping) => {
                    *state = LazyPeerState::Active { last_activity: now };
                    woken.push(target);
                }
                Some(LazyPeerState::Active { last_activity }) => {
                    *last_activity = now;
                }
                None => {
                    self.peers
                        .insert(target, LazyPeerState::Active { last_activity: now });
                    woken.push(target);
                }
            }
        }
        woken
    }

    /// Evaluates inactivity timeouts at `now`, putting any [`LazyPeerState::Active`] peer
    /// back to [`LazyPeerState::Sleeping`] if neither it nor any peer in its HA group has
    /// had activity within `inactivity_threshold`.
    pub fn expire_inactive_peers(&mut self, now: Instant) -> Vec<DeviceId> {
        let threshold = self.inactivity_threshold;
        let is_recently_active =
            |peer_id: DeviceId, map: &HashMap<DeviceId, LazyPeerState>| match map.get(&peer_id) {
                // An excluded peer keeps only its own tunnel permanent; it does not
                // count as activity that keeps its HA partners awake.
                Some(LazyPeerState::Active { last_activity }) => {
                    now.saturating_duration_since(*last_activity) < threshold
                }
                Some(LazyPeerState::ExcludedPermanent | LazyPeerState::Sleeping) | None => false,
            };

        let mut to_sleep = Vec::new();
        for (&peer, &state) in &self.peers {
            if let LazyPeerState::Active { last_activity } = state
                && now.saturating_duration_since(last_activity) >= threshold
            {
                let kept_awake_by_ha = self.ha_groups.values().any(|members| {
                    members.contains(&peer)
                        && members
                            .iter()
                            .any(|&m| m != peer && is_recently_active(m, &self.peers))
                });
                if !kept_awake_by_ha {
                    to_sleep.push(peer);
                }
            }
        }

        for &peer in &to_sleep {
            self.peers.insert(peer, LazyPeerState::Sleeping);
        }
        to_sleep
    }

    /// Returns the current [`LazyPeerState`] of `peer`.
    #[must_use]
    pub fn peer_state(&self, peer: DeviceId) -> Option<LazyPeerState> {
        self.peers.get(&peer).copied()
    }
}

/// Certificate signed by a tenant authority binding a node's [`DeviceId`], groups, and
/// peer-relay capability (`Nebula` model, `docs/plan.md` §2.2 line 44).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerRelayCertificate {
    /// Subject node [`DeviceId`].
    pub subject: DeviceId,
    /// Groups embedded in the certificate.
    pub groups: Vec<String>,
    /// Whether this node is authorized to act as a peer relay for other mesh nodes.
    pub can_relay: bool,
    /// Expiration timestamp in UNIX seconds.
    pub expires_at_unix_secs: u64,
    /// Ed25519 signature over the canonical certificate transcript by the authority key.
    pub signature: [u8; 64],
}

impl PeerRelayCertificate {
    /// Issues and signs a [`PeerRelayCertificate`] using `authority`.
    #[must_use]
    pub fn issue(
        authority: &DeviceIdentity,
        subject: DeviceId,
        groups: Vec<String>,
        can_relay: bool,
        expires_at_unix_secs: u64,
    ) -> Self {
        let transcript = Self::transcript_bytes(subject, &groups, can_relay, expires_at_unix_secs);
        let signature = authority.sign(&transcript);
        Self {
            subject,
            groups,
            can_relay,
            expires_at_unix_secs,
            signature,
        }
    }

    /// Verifies the certificate signature against `authority_public` and checks that
    /// `now_unix_secs < self.expires_at_unix_secs`.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::InvalidSignature`] if the signature is invalid or the
    /// certificate has expired.
    pub fn verify(
        &self,
        authority_public: &DevicePublic,
        now_unix_secs: u64,
    ) -> Result<(), IdentityError> {
        if now_unix_secs >= self.expires_at_unix_secs {
            return Err(IdentityError::InvalidSignature);
        }
        let transcript = Self::transcript_bytes(
            self.subject,
            &self.groups,
            self.can_relay,
            self.expires_at_unix_secs,
        );
        authority_public.verify(&transcript, &self.signature)
    }

    fn transcript_bytes(
        subject: DeviceId,
        groups: &[String],
        can_relay: bool,
        expires_at_unix_secs: u64,
    ) -> Vec<u8> {
        // Length-prefixed fields so `["a\0b"]` and `["a", "b"]` never share a
        // transcript (the signature binds the exact group membership).
        let mut out = Vec::with_capacity(96);
        out.extend_from_slice(b"omegadesk-nebula-cert-v2:");
        out.extend_from_slice(subject.as_bytes());
        out.push(u8::from(can_relay));
        out.extend_from_slice(&expires_at_unix_secs.to_le_bytes());
        out.extend_from_slice(
            &u32::try_from(groups.len())
                .unwrap_or(u32::MAX)
                .to_le_bytes(),
        );
        for g in groups {
            out.extend_from_slice(&u32::try_from(g.len()).unwrap_or(u32::MAX).to_le_bytes());
            out.extend_from_slice(g.as_bytes());
        }
        out
    }
}

/// Direct link metric to a neighbor reported in a [`LinkStateAdvertisement`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkNeighbor {
    /// Neighbor [`DeviceId`].
    pub peer: DeviceId,
    /// Measured round-trip latency in milliseconds (`>= 1`).
    pub rtt_ms: u32,
}

/// Sequence-numbered OSPF Link-State Advertisement (`LSA`) flooded between mesh peers
/// without a central coordinator (`docs/plan.md` §2.2 line 45 & §4 Phase 7 line 307).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkStateAdvertisement {
    /// Originating node.
    pub origin: DeviceId,
    /// Monotonically increasing sequence number for loop-free flooding.
    pub sequence: u64,
    /// Whether `origin` holds a valid `can_relay = true` [`PeerRelayCertificate`].
    pub can_relay: bool,
    /// Direct active neighbors and their RTT costs.
    pub neighbors: Vec<LinkNeighbor>,
}

/// Computed shortest-path route from a source node to a destination node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutePath {
    /// First-hop neighbor to send the packet to.
    pub next_hop: DeviceId,
    /// Full ordered sequence of hops from source (exclusive) to destination (inclusive).
    pub hops: Vec<DeviceId>,
    /// Total end-to-end RTT cost in milliseconds.
    pub total_rtt_ms: u32,
}

/// Coordinator-free OSPF link-state routing table computing minimum-RTT paths via Dijkstra's
/// algorithm (`docs/plan.md` §2.2 line 45 & §4 Phase 7 line 307).
///
/// Relay eligibility is **never** taken from the advertised `can_relay` flag: a
/// node becomes a transit hop only after a [`PeerRelayCertificate`] signed by
/// the configured authority was verified with [`Self::register_relay_certificate`],
/// and only until that certificate expires (Nebula model).
#[derive(Debug, Clone)]
pub struct LinkStateRouter {
    authority: DevicePublic,
    lsdb: HashMap<DeviceId, LinkStateAdvertisement>,
    /// Verified relay certificates: subject -> expiry (UNIX seconds).
    relay_until: HashMap<DeviceId, u64>,
}

impl LinkStateRouter {
    /// Creates an empty link-state router trusting relay certificates signed by `authority`.
    #[must_use]
    pub fn new(authority: DevicePublic) -> Self {
        Self {
            authority,
            lsdb: HashMap::new(),
            relay_until: HashMap::new(),
        }
    }

    /// Verifies `cert` against the authority and records the subject as an
    /// authorized relay until the certificate expires.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::InvalidSignature`] if the certificate is not
    /// signed by the authority, has expired, or does not grant `can_relay`.
    pub fn register_relay_certificate(
        &mut self,
        cert: &PeerRelayCertificate,
        now_unix_secs: u64,
    ) -> Result<(), IdentityError> {
        cert.verify(&self.authority, now_unix_secs)?;
        if !cert.can_relay {
            return Err(IdentityError::InvalidSignature);
        }
        self.relay_until
            .insert(cert.subject, cert.expires_at_unix_secs);
        Ok(())
    }

    /// Returns `true` if `node` holds a verified, unexpired relay certificate.
    #[must_use]
    pub fn is_authorized_relay(&self, node: DeviceId, now_unix_secs: u64) -> bool {
        self.relay_until
            .get(&node)
            .is_some_and(|&expires| now_unix_secs < expires)
    }

    /// Ingests a [`LinkStateAdvertisement`], returning `true` if it is newer than any previously
    /// seen LSA from `lsa.origin` (and should therefore be flooded to neighbors).
    pub fn ingest_lsa(&mut self, lsa: LinkStateAdvertisement) -> bool {
        if let Some(existing) = self.lsdb.get(&lsa.origin)
            && lsa.sequence <= existing.sequence
        {
            return false;
        }
        self.lsdb.insert(lsa.origin, lsa);
        true
    }

    /// Computes the minimum-latency [`RoutePath`] from `source` to `destination` using
    /// Dijkstra's algorithm, allowing intermediate transit hops only through nodes whose
    /// relay certificate was verified and is valid at `now_unix_secs`.
    #[must_use]
    pub fn compute_route(
        &self,
        source: DeviceId,
        destination: DeviceId,
        now_unix_secs: u64,
    ) -> Option<RoutePath> {
        if source == destination {
            return None;
        }

        let mut dist: HashMap<DeviceId, u32> = HashMap::new();
        let mut prev: HashMap<DeviceId, DeviceId> = HashMap::new();
        let mut heap: BinaryHeap<(Reverse<u32>, DeviceId)> = BinaryHeap::new();

        dist.insert(source, 0);
        heap.push((Reverse(0), source));

        while let Some((Reverse(cost), current)) = heap.pop() {
            if current == destination {
                break;
            }
            if dist.get(&current).is_some_and(|&best| cost > best) {
                continue;
            }
            // Intermediate transit nodes (other than `source`) must be authorized peer relays.
            let Some(lsa) = self.lsdb.get(&current) else {
                continue;
            };
            if current != source && !self.is_authorized_relay(current, now_unix_secs) {
                continue;
            }

            for link in &lsa.neighbors {
                let next_cost = cost.saturating_add(link.rtt_ms.max(1));
                let is_better = dist.get(&link.peer).is_none_or(|&old| next_cost < old);
                if is_better {
                    dist.insert(link.peer, next_cost);
                    prev.insert(link.peer, current);
                    heap.push((Reverse(next_cost), link.peer));
                }
            }
        }

        let total_rtt_ms = *dist.get(&destination)?;
        let mut hops = Vec::new();
        let mut cur = destination;
        while cur != source {
            hops.push(cur);
            cur = *prev.get(&cur)?;
        }
        hops.reverse();
        let next_hop = *hops.first()?;

        Some(RoutePath {
            next_hop,
            hops,
            total_rtt_ms,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nebula_peer_relay_cert_and_coordinator_free_ospf_routing() {
        let authority = DeviceIdentity::generate();
        let node_a = DeviceIdentity::generate().id();
        let node_b_relay = DeviceIdentity::generate().id();
        let node_c = DeviceIdentity::generate().id();

        let cert = PeerRelayCertificate::issue(
            &authority,
            node_b_relay,
            vec!["group:relays".to_owned()],
            true,
            5_000,
        );
        assert!(cert.verify(&authority.public(), 1_000).is_ok());
        assert!(cert.verify(&authority.public(), 6_000).is_err());

        // Coordinator-free link-state routing:
        // Direct A -> C has high latency (200 ms), whereas A -> B (15 ms) -> C (20 ms) is 35 ms
        // through peer-relay B.
        let mut router = LinkStateRouter::new(authority.public());
        // Advertising `can_relay = true` alone grants nothing.
        assert!(router.ingest_lsa(LinkStateAdvertisement {
            origin: node_a,
            sequence: 1,
            can_relay: false,
            neighbors: vec![
                LinkNeighbor {
                    peer: node_b_relay,
                    rtt_ms: 15,
                },
                LinkNeighbor {
                    peer: node_c,
                    rtt_ms: 200,
                },
            ],
        }));
        assert!(router.ingest_lsa(LinkStateAdvertisement {
            origin: node_b_relay,
            sequence: 1,
            can_relay: true,
            neighbors: vec![LinkNeighbor {
                peer: node_c,
                rtt_ms: 20,
            }],
        }));
        let direct_only = router.compute_route(node_a, node_c, 1_000).unwrap();
        assert_eq!(direct_only.hops, vec![node_c]);
        assert_eq!(direct_only.total_rtt_ms, 200);

        // A forged or foreign certificate is rejected; the real one authorizes B.
        let forged = PeerRelayCertificate::issue(
            &DeviceIdentity::generate(),
            node_b_relay,
            vec![],
            true,
            5_000,
        );
        assert!(router.register_relay_certificate(&forged, 1_000).is_err());
        router.register_relay_certificate(&cert, 1_000).unwrap();
        assert!(router.ingest_lsa(LinkStateAdvertisement {
            origin: node_a,
            sequence: 2,
            can_relay: false,
            neighbors: vec![
                LinkNeighbor {
                    peer: node_b_relay,
                    rtt_ms: 15,
                },
                LinkNeighbor {
                    peer: node_c,
                    rtt_ms: 200,
                },
            ],
        }));
        assert!(router.ingest_lsa(LinkStateAdvertisement {
            origin: node_b_relay,
            sequence: 2,
            can_relay: true,
            neighbors: vec![LinkNeighbor {
                peer: node_c,
                rtt_ms: 20,
            }],
        }));

        let route = router
            .compute_route(node_a, node_c, 1_000)
            .unwrap_or_else(|| unreachable!());
        assert_eq!(route.next_hop, node_b_relay);
        assert_eq!(route.hops, vec![node_b_relay, node_c]);
        assert_eq!(route.total_rtt_ms, 35);
        // Once the certificate expires, B is no longer a transit hop.
        let expired = router.compute_route(node_a, node_c, 6_000).unwrap();
        assert_eq!(expired.hops, vec![node_c]);

        // Group lists are length-prefixed in the transcript, so moving a NUL
        // between two groups changes the signed message.
        let two = PeerRelayCertificate::issue(
            &authority,
            node_a,
            vec!["a".into(), "b".into()],
            false,
            5_000,
        );
        let mut joined = two.clone();
        joined.groups = vec!["a\0b".to_owned()];
        assert!(joined.verify(&authority.public(), 1_000).is_err());
    }

    #[test]
    fn netbird_lazyconn_wakes_ha_group_and_sleeps_after_inactivity() {
        let t0 = Instant::now();
        let peer_a = DeviceIdentity::generate().id();
        let peer_b = DeviceIdentity::generate().id();
        let peer_permanent = DeviceIdentity::generate().id();

        let mut lazy = LazyConnManager::new(Duration::from_secs(60));
        lazy.register_lazy_peer(peer_a);
        lazy.register_lazy_peer(peer_b);
        lazy.set_ha_group("ha-exit-1", vec![peer_a, peer_b]);
        lazy.set_excluded_peers(&HashSet::from([peer_permanent]), t0);

        assert_eq!(lazy.peer_state(peer_a), Some(LazyPeerState::Sleeping));
        assert_eq!(
            lazy.peer_state(peer_permanent),
            Some(LazyPeerState::ExcludedPermanent)
        );

        // Outbound packet to peer_a wakes both peer_a and HA-group partner peer_b.
        let woken = lazy.on_peer_activity(peer_a, t0);
        assert_eq!(woken.len(), 2);
        assert!(matches!(
            lazy.peer_state(peer_b),
            Some(LazyPeerState::Active { .. })
        ));

        // After 70 seconds of silence, both peer_a and peer_b go back to sleep, while
        // peer_permanent stays ExcludedPermanent.
        let slept = lazy.expire_inactive_peers(t0 + Duration::from_secs(70));
        assert_eq!(slept.len(), 2);
        assert_eq!(lazy.peer_state(peer_a), Some(LazyPeerState::Sleeping));
        assert_eq!(lazy.peer_state(peer_b), Some(LazyPeerState::Sleeping));
        assert_eq!(
            lazy.peer_state(peer_permanent),
            Some(LazyPeerState::ExcludedPermanent)
        );
    }
}
