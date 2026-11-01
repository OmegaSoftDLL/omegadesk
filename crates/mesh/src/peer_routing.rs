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
use std::collections::{BinaryHeap, HashMap};

use omegadesk_identity::{DeviceId, DeviceIdentity, DevicePublic, IdentityError};

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
        let mut out = Vec::with_capacity(96);
        out.extend_from_slice(b"omegadesk-nebula-cert-v1:");
        out.extend_from_slice(subject.as_bytes());
        out.push(u8::from(can_relay));
        out.extend_from_slice(&expires_at_unix_secs.to_le_bytes());
        for g in groups {
            out.extend_from_slice(g.as_bytes());
            out.push(0);
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
#[derive(Debug, Default, Clone)]
pub struct LinkStateRouter {
    lsdb: HashMap<DeviceId, LinkStateAdvertisement>,
}

impl LinkStateRouter {
    /// Creates an empty link-state router.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
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
    /// Dijkstra's algorithm, allowing intermediate transit hops only through nodes with
    /// `can_relay == true`.
    #[must_use]
    pub fn compute_route(&self, source: DeviceId, destination: DeviceId) -> Option<RoutePath> {
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
            if current != source && !lsa.can_relay {
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
        let mut router = LinkStateRouter::new();
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

        let route = router
            .compute_route(node_a, node_c)
            .unwrap_or_else(|| unreachable!());
        assert_eq!(route.next_hop, node_b_relay);
        assert_eq!(route.hops, vec![node_b_relay, node_c]);
        assert_eq!(route.total_rtt_ms, 35);
    }
}
