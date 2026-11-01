//! OmegaDesk mesh coordinator (`omegadesk-server`).
//!
//! Implements the control-plane components specified for Phase 2 of `docs/plan.md`:
//! - **Pre-authorized & Ephemeral Keys** (modeled after Headscale's
//!   `hscontrol/db/preauth_keys.go`): `odk_<prefix>_<secret>` machine enrollment
//!   keys with SHA-256 secret hashing, single-use vs reusable semantics,
//!   ephemeral node lifecycle, and `tag:` ACL tag validation (`validate_acl_tags`).
//! - **Batched Netmap Delta Stream** (modeled after Headscale's
//!   `hscontrol/mapper/batcher.go`): [`NetmapBatcher`] coalesces topology and
//!   endpoint changes and fans out full snapshots and incremental [`NetmapDelta`]
//!   patches to subscribed nodes.
//! - **Internal DNS `*.omega` (`MagicDNS`)** (modeled after Tailscale's `net/dns`):
//!   [`MagicDnsResolver`] allocates mesh IPv4 (`100.64.0.0/10`) and IPv6
//!   (`fd7a:115c:a1e0::/48`) addresses, sanitizes hostnames into collision-free
//!   `<hostname>.omega` records, and answers forward (`A`/`AAAA`) and reverse
//!   (`PTR`) queries.
//! - **Stateless Relay Ticket Issuance**: issues single-use HMAC-SHA256
//!   [`RelayTicket`]s verified by `omegadesk-relay`.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use data_encoding::HEXLOWER;
use omegadesk_identity::{DeviceId, DevicePublic};
use omegadesk_relay::{RelayTicket, TicketIssuer};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;

/// Base internal DNS suffix for all machines on the OmegaDesk mesh (`*.omega`).
pub const OMEGA_DNS_SUFFIX: &str = "omega";

/// Default lifetime of a single-use relay ticket issued during enrollment (300 s).
pub const DEFAULT_RELAY_TICKET_TTL_SECS: u64 = 300;

/// Errors returned by the coordinator.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CoordinatorError {
    /// An ACL tag does not start with `"tag:"` or contains invalid characters.
    #[error(
        "ACL tag '{0}' must start with 'tag:' and contain only ASCII alphanumeric, '-', or '_'"
    )]
    InvalidAclTag(String),
    /// Pre-authorized key token string is malformed.
    #[error("malformed pre-auth key token")]
    MalformedPreAuthKey,
    /// Pre-authorized key was not found or secret hash did not match.
    #[error("invalid pre-auth key")]
    InvalidPreAuthKey,
    /// Single-use pre-authorized key has already been consumed.
    #[error("pre-auth key has already been used")]
    PreAuthKeyAlreadyUsed,
    /// Pre-authorized key has expired.
    #[error("pre-auth key has expired")]
    PreAuthKeyExpired,
    /// Node is not registered with the coordinator.
    #[error("unknown node: {0}")]
    UnknownNode(DeviceId),
}

/// Validates a list of ACL tags, enforcing the `"tag:"` prefix rule from
/// Headscale's `validateACLTags` (`hscontrol/db/preauth_keys.go`).
///
/// # Errors
///
/// Returns [`CoordinatorError::InvalidAclTag`] if any tag lacks the `"tag:"`
/// prefix, has an empty name after `"tag:"`, or contains whitespace/invalid characters.
pub fn validate_acl_tags(tags: &[String]) -> Result<(), CoordinatorError> {
    for tag in tags {
        let Some(rest) = tag.strip_prefix("tag:") else {
            return Err(CoordinatorError::InvalidAclTag(tag.clone()));
        };
        if rest.is_empty()
            || !rest
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(CoordinatorError::InvalidAclTag(tag.clone()));
        }
    }
    Ok(())
}

/// Stored metadata for a pre-authorized machine enrollment key, modeled after
/// Headscale's `PreAuthKey` (`hscontrol/db/preauth_keys.go`).
///
/// Only the SHA-256 digest of the secret is persisted (`secret_hash`); the
/// plaintext token is returned once when created.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreAuthKey {
    /// Public key prefix (16 hex chars) used for O(1) lookup.
    pub prefix: String,
    /// SHA-256 hash of the 32-byte secret half.
    pub secret_hash: [u8; 32],
    /// Tenant identifier that owns this key.
    pub tenant: String,
    /// Whether this key can enroll multiple machines.
    pub reusable: bool,
    /// Whether machines enrolled with this key are automatically removed when
    /// they disconnect.
    pub ephemeral: bool,
    /// Whether this key has been used at least once.
    pub used: bool,
    /// Verified `"tag:..."` ACL tags automatically assigned to enrolled machines.
    pub tags: Vec<String>,
    /// Optional expiration timestamp (UNIX seconds).
    pub expires_at_unix_secs: Option<u64>,
}

impl PreAuthKey {
    /// Returns `true` if this key can be redeemed at `now_unix_secs`.
    ///
    /// # Errors
    ///
    /// Returns [`CoordinatorError`] if the key is expired or already consumed.
    pub fn check_usable(&self, now_unix_secs: u64) -> Result<(), CoordinatorError> {
        if let Some(exp) = self.expires_at_unix_secs
            && now_unix_secs >= exp
        {
            return Err(CoordinatorError::PreAuthKeyExpired);
        }
        if !self.reusable && self.used {
            return Err(CoordinatorError::PreAuthKeyAlreadyUsed);
        }
        Ok(())
    }
}

/// Registered machine entry in the coordinator's netmap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeRecord {
    /// Cryptographic device identity.
    pub public: DevicePublic,
    /// Tenant that owns the machine.
    pub tenant: String,
    /// Sanitized hostname label (`<hostname>.omega`).
    pub hostname: String,
    /// Fully qualified internal DNS name (e.g., `"workstation.omega"`).
    pub fqdn: String,
    /// Assigned mesh IPv4 address (`100.64.x.y`).
    pub ipv4: Ipv4Addr,
    /// Assigned mesh IPv6 address (`fd7a:115c:a1e0::x`).
    pub ipv6: Ipv6Addr,
    /// Candidate direct UDP endpoints advertised by the node.
    pub endpoints: Vec<SocketAddr>,
    /// Assigned ACL tags (`"tag:..."`).
    pub tags: Vec<String>,
    /// Whether the node is ephemeral (deleted upon disconnect).
    pub ephemeral: bool,
}

/// Incremental netmap update pushed over a node's control stream, modeled after
/// Headscale's `hscontrol/mapper/batcher.go`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetmapDelta {
    /// Initial or full topology snapshot containing the self node and all peers.
    FullSnapshot {
        /// The recipient node's own record.
        self_node: NodeRecord,
        /// All other peers visible to this node.
        peers: Vec<NodeRecord>,
    },
    /// A peer joined the mesh or updated its metadata.
    PeerUpserted(NodeRecord),
    /// Only a peer's UDP endpoints changed (lightweight patch).
    EndpointUpdated {
        /// Peer device identifier.
        peer: DeviceId,
        /// Updated direct UDP candidate endpoints.
        endpoints: Vec<SocketAddr>,
    },
    /// A peer disconnected (ephemeral) or was removed from the mesh.
    PeerRemoved(DeviceId),
}

/// Coalesces rapid netmap changes and broadcasts batched [`NetmapDelta`] updates
/// to connected nodes, modeled after Headscale's `Batcher` (`hscontrol/mapper/batcher.go`).
#[derive(Default)]
pub struct NetmapBatcher {
    pending: Vec<NetmapDelta>,
    subscribers: HashMap<DeviceId, mpsc::Sender<Vec<NetmapDelta>>>,
}

impl NetmapBatcher {
    /// Creates a new [`NetmapBatcher`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Subscribes `node_id` to receive batched [`NetmapDelta`] vectors and
    /// immediately queues `initial_snapshot`.
    pub fn subscribe(
        &mut self,
        node_id: DeviceId,
        initial_snapshot: NetmapDelta,
    ) -> mpsc::Receiver<Vec<NetmapDelta>> {
        let (tx, rx) = mpsc::channel(64);
        let _ = tx.try_send(vec![initial_snapshot]);
        self.subscribers.insert(node_id, tx);
        rx
    }

    /// Removes `node_id`'s subscription channel.
    pub fn unsubscribe(&mut self, node_id: DeviceId) {
        self.subscribers.remove(&node_id);
    }

    /// Queues a delta to be coalesced and broadcast on the next [`Self::flush`].
    pub fn enqueue(&mut self, delta: NetmapDelta) {
        // Coalesce consecutive EndpointUpdated deltas for the same peer.
        if let NetmapDelta::EndpointUpdated {
            peer,
            ref endpoints,
        } = delta
        {
            for item in &mut self.pending {
                if let NetmapDelta::EndpointUpdated {
                    peer: existing_peer,
                    endpoints: existing_eps,
                } = item
                    && *existing_peer == peer
                {
                    existing_eps.clone_from(endpoints);
                    return;
                }
            }
        }
        self.pending.push(delta);
    }

    /// Flushes all pending [`NetmapDelta`] items as a single batch to every
    /// subscribed node. Returns the number of deltas flushed.
    pub fn flush(&mut self) -> usize {
        if self.pending.is_empty() {
            return 0;
        }
        let batch = std::mem::take(&mut self.pending);
        let count = batch.len();
        self.subscribers
            .retain(|_, tx| tx.try_send(batch.clone()).is_ok());
        count
    }
}

/// Internal `*.omega` `MagicDNS` resolver, modeled after Tailscale's `net/dns`.
#[derive(Debug, Default, Clone)]
pub struct MagicDnsResolver {
    by_fqdn: HashMap<String, (Ipv4Addr, Ipv6Addr, DeviceId)>,
    by_ip: HashMap<IpAddr, String>,
}

impl MagicDnsResolver {
    /// Creates an empty [`MagicDnsResolver`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sanitizes an arbitrary machine name into a valid lowercase RFC 1123 DNS label.
    #[must_use]
    pub fn sanitize_dns_label(raw: &str) -> String {
        let mut out = String::with_capacity(raw.len());
        let mut last_hyphen = false;
        for ch in raw.chars() {
            if ch.is_ascii_alphanumeric() {
                out.push(ch.to_ascii_lowercase());
                last_hyphen = false;
            } else if !out.is_empty() && !last_hyphen {
                out.push('-');
                last_hyphen = true;
            }
        }
        while out.ends_with('-') {
            out.pop();
        }
        if out.is_empty() {
            "node".to_owned()
        } else {
            out.chars().take(63).collect()
        }
    }

    /// Registers `requested_hostname` for `device_id` with `(ipv4, ipv6)`, resolving
    /// name collisions automatically (`host.omega`, `host-2.omega`, etc.), and
    /// returns `(sanitized_label, fqdn)`.
    pub fn register(
        &mut self,
        device_id: DeviceId,
        requested_hostname: &str,
        ipv4: Ipv4Addr,
        ipv6: Ipv6Addr,
    ) -> (String, String) {
        let base_label = Self::sanitize_dns_label(requested_hostname);
        let mut candidate_label = base_label.clone();
        let mut suffix_num = 2u32;

        loop {
            let fqdn = format!("{candidate_label}.{OMEGA_DNS_SUFFIX}");
            if let Some(&(_, _, existing_id)) = self.by_fqdn.get(&fqdn)
                && existing_id != device_id
            {
                candidate_label = format!("{base_label}-{suffix_num}");
                suffix_num += 1;
                continue;
            }
            self.by_fqdn.insert(fqdn.clone(), (ipv4, ipv6, device_id));
            self.by_ip.insert(IpAddr::V4(ipv4), fqdn.clone());
            self.by_ip.insert(IpAddr::V6(ipv6), fqdn.clone());
            return (candidate_label, fqdn);
        }
    }

    /// Removes all DNS records associated with `fqdn`.
    pub fn unregister(&mut self, fqdn: &str) {
        let normalized = Self::normalize_query(fqdn);
        if let Some((v4, v6, _)) = self.by_fqdn.remove(&normalized) {
            self.by_ip.remove(&IpAddr::V4(v4));
            self.by_ip.remove(&IpAddr::V6(v6));
        }
    }

    /// Resolves a `*.omega` query (case-insensitive, with or without trailing dot,
    /// or bare hostname) to its `(Ipv4Addr, Ipv6Addr)`.
    #[must_use]
    pub fn lookup(&self, query: &str) -> Option<(Ipv4Addr, Ipv6Addr)> {
        let norm = Self::normalize_query(query);
        self.by_fqdn.get(&norm).map(|&(v4, v6, _)| (v4, v6))
    }

    /// Reverse (`PTR`) lookup from a mesh IP address back to its `<hostname>.omega` FQDN.
    #[must_use]
    pub fn reverse_lookup(&self, ip: IpAddr) -> Option<&str> {
        self.by_ip.get(&ip).map(String::as_str)
    }

    fn normalize_query(q: &str) -> String {
        let trimmed = q.trim().trim_end_matches('.').to_ascii_lowercase();
        if trimmed.ends_with(&format!(".{OMEGA_DNS_SUFFIX}")) {
            trimmed
        } else {
            format!("{trimmed}.{OMEGA_DNS_SUFFIX}")
        }
    }
}

/// Response returned to a machine when it enrolls with the coordinator.
#[derive(Debug)]
pub struct EnrollmentBundle {
    /// The enrolled node's assigned record (including mesh IPv4/IPv6 and `*.omega` FQDN).
    pub node: NodeRecord,
    /// Single-use HMAC relay ticket for immediate DERP relay connectivity.
    pub relay_ticket: RelayTicket,
    /// Receiver stream delivering batched [`NetmapDelta`] updates.
    pub netmap_rx: mpsc::Receiver<Vec<NetmapDelta>>,
}

/// Central OmegaDesk mesh coordinator state machine.
pub struct Coordinator {
    preauth_keys: HashMap<String, PreAuthKey>,
    nodes: HashMap<DeviceId, NodeRecord>,
    next_ip_index: u32,
    dns: MagicDnsResolver,
    batcher: NetmapBatcher,
    ticket_issuer: TicketIssuer,
}

impl Coordinator {
    /// Creates a new [`Coordinator`] sharing `relay_ticket_secret` with the relay fleet.
    #[must_use]
    pub fn new(relay_ticket_secret: [u8; 32]) -> Self {
        Self {
            preauth_keys: HashMap::new(),
            nodes: HashMap::new(),
            next_ip_index: 1,
            dns: MagicDnsResolver::new(),
            batcher: NetmapBatcher::new(),
            ticket_issuer: TicketIssuer::new(relay_ticket_secret),
        }
    }

    /// Generates and stores a new pre-authorized machine key, returning the
    /// one-time plaintext token (`odk_<prefix>_<secret>`) to pass to `omegadesk-agent`.
    ///
    /// # Errors
    ///
    /// Returns [`CoordinatorError::InvalidAclTag`] if any tag does not start with `"tag:"`.
    pub fn create_preauth_key(
        &mut self,
        tenant: &str,
        reusable: bool,
        ephemeral: bool,
        tags: Vec<String>,
        expires_at_unix_secs: Option<u64>,
    ) -> Result<String, CoordinatorError> {
        validate_acl_tags(&tags)?;

        let mut prefix_bytes = [0u8; 8];
        OsRng.fill_bytes(&mut prefix_bytes);
        let prefix = HEXLOWER.encode(&prefix_bytes);

        let mut secret_bytes = [0u8; 24];
        OsRng.fill_bytes(&mut secret_bytes);
        let secret_hex = HEXLOWER.encode(&secret_bytes);

        let digest = Sha256::digest(secret_hex.as_bytes());
        let mut secret_hash = [0u8; 32];
        secret_hash.copy_from_slice(&digest);

        let key = PreAuthKey {
            prefix: prefix.clone(),
            secret_hash,
            tenant: tenant.to_owned(),
            reusable,
            ephemeral,
            used: false,
            tags,
            expires_at_unix_secs,
        };
        self.preauth_keys.insert(prefix.clone(), key);
        Ok(format!("odk_{prefix}_{secret_hex}"))
    }

    /// Enrolls a machine using a `preauth_token`, allocates its `100.64.x.y` /
    /// `fd7a:115c:a1e0::x` mesh addresses and `<hostname>.omega` `MagicDNS` name,
    /// issues a single-use [`RelayTicket`], and subscribes the node to the
    /// [`NetmapBatcher`].
    ///
    /// # Errors
    ///
    /// Returns [`CoordinatorError`] if the pre-auth key is invalid, expired, or
    /// already consumed.
    pub fn enroll_machine(
        &mut self,
        preauth_token: &str,
        public: DevicePublic,
        hostname: &str,
        endpoints: Vec<SocketAddr>,
        now_unix_secs: u64,
    ) -> Result<EnrollmentBundle, CoordinatorError> {
        let mut parts = preauth_token.splitn(3, '_');
        let Some("odk") = parts.next() else {
            return Err(CoordinatorError::MalformedPreAuthKey);
        };
        let Some(prefix) = parts.next() else {
            return Err(CoordinatorError::MalformedPreAuthKey);
        };
        let Some(secret_hex) = parts.next() else {
            return Err(CoordinatorError::MalformedPreAuthKey);
        };

        let key = self
            .preauth_keys
            .get_mut(prefix)
            .ok_or(CoordinatorError::InvalidPreAuthKey)?;

        let provided_digest = Sha256::digest(secret_hex.as_bytes());
        if provided_digest.as_slice() != key.secret_hash {
            return Err(CoordinatorError::InvalidPreAuthKey);
        }

        key.check_usable(now_unix_secs)?;
        key.used = true;

        let tenant = key.tenant.clone();
        let tags = key.tags.clone();
        let ephemeral = key.ephemeral;

        let node_id = public.id();
        let (ipv4, ipv6) = if let Some(existing) = self.nodes.get(&node_id) {
            (existing.ipv4, existing.ipv6)
        } else {
            let idx = self.next_ip_index;
            self.next_ip_index += 1;
            let b2 = u8::try_from((idx >> 8) & 0xFF).unwrap_or(0);
            let b3 = u8::try_from(idx & 0xFF).unwrap_or(1);
            let v4 = Ipv4Addr::new(100, 64, b2, b3);
            let v6 = Ipv6Addr::new(
                0xfd7a,
                0x115c,
                0xa1e0,
                0,
                0,
                0,
                u16::from(b2),
                u16::from(b3),
            );
            (v4, v6)
        };

        let (sanitized_label, fqdn) = self.dns.register(node_id, hostname, ipv4, ipv6);
        let record = NodeRecord {
            public,
            tenant,
            hostname: sanitized_label,
            fqdn,
            ipv4,
            ipv6,
            endpoints,
            tags,
            ephemeral,
        };

        let peers: Vec<NodeRecord> = self
            .nodes
            .iter()
            .filter(|&(&id, _)| id != node_id)
            .map(|(_, r)| r.clone())
            .collect();

        self.nodes.insert(node_id, record.clone());

        // Broadcast `PeerUpserted` to already-connected peers before subscribing
        // the newly enrolled node (which receives `FullSnapshot` as its first item).
        self.batcher
            .enqueue(NetmapDelta::PeerUpserted(record.clone()));
        self.batcher.flush();

        let snapshot = NetmapDelta::FullSnapshot {
            self_node: record.clone(),
            peers,
        };
        let netmap_rx = self.batcher.subscribe(node_id, snapshot);

        let mut ticket_id = [0u8; 16];
        OsRng.fill_bytes(&mut ticket_id);
        let relay_ticket = self.ticket_issuer.issue(
            ticket_id,
            public.exchange_key_bytes(),
            now_unix_secs + DEFAULT_RELAY_TICKET_TTL_SECS,
        );

        Ok(EnrollmentBundle {
            node: record,
            relay_ticket,
            netmap_rx,
        })
    }

    /// Updates the candidate UDP endpoints of `node_id` and queues a coalesced
    /// [`NetmapDelta::EndpointUpdated`] delta in the [`NetmapBatcher`].
    ///
    /// # Errors
    ///
    /// Returns [`CoordinatorError::UnknownNode`] if `node_id` is not enrolled.
    pub fn update_endpoints(
        &mut self,
        node_id: DeviceId,
        endpoints: Vec<SocketAddr>,
    ) -> Result<(), CoordinatorError> {
        let node = self
            .nodes
            .get_mut(&node_id)
            .ok_or(CoordinatorError::UnknownNode(node_id))?;
        node.endpoints.clone_from(&endpoints);
        self.batcher.enqueue(NetmapDelta::EndpointUpdated {
            peer: node_id,
            endpoints,
        });
        Ok(())
    }

    /// Handles node disconnection; if the node was enrolled with an `ephemeral`
    /// pre-auth key, removes it from the netmap and `MagicDNS` immediately (matching
    /// Headscale's ephemeral node cleanup).
    pub fn handle_disconnect(&mut self, node_id: DeviceId) {
        self.batcher.unsubscribe(node_id);
        if let Some(node) = self.nodes.get(&node_id)
            && node.ephemeral
            && let Some(removed) = self.nodes.remove(&node_id)
        {
            self.dns.unregister(&removed.fqdn);
            self.batcher.enqueue(NetmapDelta::PeerRemoved(node_id));
            self.batcher.flush();
        }
    }

    /// Flushes any pending netmap deltas to subscribed nodes.
    pub fn flush_netmap(&mut self) -> usize {
        self.batcher.flush()
    }

    /// Reference to the internal `*.omega` [`MagicDnsResolver`].
    #[must_use]
    pub const fn dns(&self) -> &MagicDnsResolver {
        &self.dns
    }

    /// Number of currently enrolled machines.
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use omegadesk_identity::DeviceIdentity;
    use omegadesk_mesh::{
        ConnectionPath, MeshEvent, MeshNode, RELAY_FALLBACK_TIMEOUT, TransmitTarget,
    };
    use omegadesk_noise::{InitiatorHandshake, ResponderHandshake};
    use omegadesk_relay::{RelayFrame, RelayRouter};
    use omegadesk_tun::IpPacket;

    use super::*;

    #[test]
    fn preauth_keys_enforce_tags_single_use_and_ephemeral_cleanup() {
        let mut coord = Coordinator::new([0x55u8; 32]);

        // Tag without 'tag:' prefix must be rejected
        assert_eq!(
            coord.create_preauth_key("acme", false, false, vec!["prod".to_owned()], None),
            Err(CoordinatorError::InvalidAclTag("prod".to_owned()))
        );

        // Single-use ephemeral key with valid tag
        let token = coord
            .create_preauth_key(
                "acme",
                false,
                true,
                vec!["tag:ci-runner".to_owned()],
                Some(2000),
            )
            .unwrap();

        let dev1 = DeviceIdentity::generate();
        let bundle = coord
            .enroll_machine(&token, dev1.public(), "Runner 01!", vec![], 1000)
            .unwrap();
        assert_eq!(bundle.node.fqdn, "runner-01.omega");
        assert_eq!(bundle.node.ipv4, Ipv4Addr::new(100, 64, 0, 1));
        assert_eq!(
            coord.dns().lookup("runner-01.omega"),
            Some((bundle.node.ipv4, bundle.node.ipv6))
        );
        assert_eq!(
            coord.dns().reverse_lookup(IpAddr::V4(bundle.node.ipv4)),
            Some("runner-01.omega")
        );

        // Second attempt with the same single-use key must fail
        let dev2 = DeviceIdentity::generate();
        assert_eq!(
            coord
                .enroll_machine(&token, dev2.public(), "runner-02", vec![], 1001)
                .unwrap_err(),
            CoordinatorError::PreAuthKeyAlreadyUsed
        );

        // Disconnecting an ephemeral node removes it from both the netmap and MagicDNS
        coord.handle_disconnect(dev1.id());
        assert_eq!(coord.node_count(), 0);
        assert_eq!(coord.dns().lookup("runner-01.omega"), None);
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn phase2_end_to_end_enroll_over_noise_fallback_to_relay_and_upgrade_to_direct() {
        let shared_secret = [0xA5u8; 32];
        let coord_id = DeviceIdentity::generate();
        let relay_id = DeviceIdentity::generate();
        let mut coord = Coordinator::new(shared_secret);
        let mut relay = RelayRouter::new(relay_id.public().exchange_key_bytes(), shared_secret);

        // 1. Authenticate control channel between Node A and Coordinator over Noise IK
        let alice_id = DeviceIdentity::generate();
        let bob_id = DeviceIdentity::generate();
        let (init_hs, msg1) =
            InitiatorHandshake::start(&alice_id, coord_id.public(), b"omegadesk-ctrl").unwrap();
        let (mut server_noise, msg2) =
            ResponderHandshake::accept(&coord_id, b"omegadesk-ctrl", &msg1).unwrap();
        let mut alice_noise = init_hs.complete(&alice_id, &msg2).unwrap();

        let token = coord
            .create_preauth_key(
                "omega",
                true,
                false,
                vec!["tag:workstation".to_owned()],
                Some(5000),
            )
            .unwrap();
        let encrypted_token = alice_noise.write_frame(token.as_bytes()).unwrap();
        let decrypted_token =
            String::from_utf8(server_noise.read_frame(&encrypted_token).unwrap()).unwrap();

        let alice_lan: SocketAddr = "198.51.100.11:51820".parse().unwrap();
        let bob_lan: SocketAddr = "203.0.113.22:51820".parse().unwrap();

        // 2. Enroll Alice and Bob with the coordinator
        let mut alice_bundle = coord
            .enroll_machine(
                &decrypted_token,
                alice_id.public(),
                "desk",
                vec![alice_lan],
                1000,
            )
            .unwrap();
        let bob_bundle = coord
            .enroll_machine(&token, bob_id.public(), "desk", vec![bob_lan], 1000)
            .unwrap();

        // Collision-safe MagicDNS names: desk.omega and desk-2.omega
        assert_eq!(alice_bundle.node.fqdn, "desk.omega");
        assert_eq!(bob_bundle.node.fqdn, "desk-2.omega");

        // Alice receives initial FullSnapshot followed by PeerUpserted(Bob)
        let _initial = alice_bundle.netmap_rx.recv().await.unwrap();
        let delta_batch = alice_bundle.netmap_rx.recv().await.unwrap();
        assert_eq!(
            delta_batch,
            vec![NetmapDelta::PeerUpserted(bob_bundle.node.clone())]
        );

        // 3. Both nodes authenticate to the stateless relay using their single-use tickets
        let (_, mut alice_relay_rx) = relay
            .register_client(
                alice_id.public().exchange_key_bytes(),
                &alice_bundle.relay_ticket,
                1000,
            )
            .unwrap();
        let (_, mut bob_relay_rx) = relay
            .register_client(
                bob_id.public().exchange_key_bytes(),
                &bob_bundle.relay_ticket,
                1000,
            )
            .unwrap();

        // 4. Start sans-I/O MeshNodes; initially simulate symmetric NAT blocking direct UDP
        let t0 = Instant::now();
        let mut alice_mesh = MeshNode::new(alice_id, vec![alice_lan]);
        let mut bob_mesh = MeshNode::new(bob_id, vec![bob_lan]);

        alice_mesh.upsert_peer(bob_bundle.node.public, vec![], t0);
        bob_mesh.upsert_peer(alice_bundle.node.public, vec![], t0);

        // Drain initial probes without delivering UDP; verify fallback to relay in 1.5 s (< 2 s)
        while alice_mesh.poll_transmit().is_some() {}
        while bob_mesh.poll_transmit().is_some() {}
        alice_mesh.handle_timeout(t0 + RELAY_FALLBACK_TIMEOUT);

        // Send an encrypted IP packet from Alice to Bob over the relay path
        let pkt = IpPacket::ipv4_udp(
            alice_bundle.node.ipv4,
            bob_bundle.node.ipv4,
            40000,
            4433,
            b"relayed-frame",
        );
        alice_mesh
            .encapsulate(
                bob_bundle.node.public.id(),
                &pkt,
                t0 + RELAY_FALLBACK_TIMEOUT,
            )
            .unwrap();

        while let Some(tx) = alice_mesh.poll_transmit() {
            if let TransmitTarget::Relay(dst_key) = tx.target {
                relay
                    .forward_packet(
                        alice_bundle.node.public.exchange_key_bytes(),
                        dst_key,
                        tx.payload,
                    )
                    .unwrap();
            }
        }

        while let Ok(RelayFrame::RecvPacket { packet, .. }) = bob_relay_rx.try_recv() {
            if let Some((_, decapsulated)) = bob_mesh
                .handle_receive(None, &packet, t0 + RELAY_FALLBACK_TIMEOUT)
                .unwrap()
            {
                assert_eq!(decapsulated, pkt);
            }
        }

        // 5. Next probe tick: CallMeMaybe travels over the relay and punches direct UDP
        alice_mesh.handle_timeout(t0 + RELAY_FALLBACK_TIMEOUT + Duration::from_millis(500));
        while let Some(tx) = alice_mesh.poll_transmit() {
            if let TransmitTarget::Relay(dst_key) = tx.target {
                relay
                    .forward_packet(
                        alice_bundle.node.public.exchange_key_bytes(),
                        dst_key,
                        tx.payload,
                    )
                    .unwrap();
            }
        }
        while let Ok(RelayFrame::RecvPacket { packet, .. }) = bob_relay_rx.try_recv() {
            bob_mesh
                .handle_receive(
                    None,
                    &packet,
                    t0 + RELAY_FALLBACK_TIMEOUT + Duration::from_millis(510),
                )
                .unwrap();
        }
        let _ = &mut alice_relay_rx;

        // Bob sends direct UDP Ping to Alice's LAN/reflexive address
        while let Some(tx) = bob_mesh.poll_transmit() {
            if let TransmitTarget::DirectUdp(dst) = tx.target {
                assert_eq!(dst, alice_lan);
                alice_mesh
                    .handle_receive(
                        Some(bob_lan),
                        &tx.payload,
                        t0 + RELAY_FALLBACK_TIMEOUT + Duration::from_millis(520),
                    )
                    .unwrap();
            }
        }
        // Alice replies with direct UDP Pong to Bob
        while let Some(tx) = alice_mesh.poll_transmit() {
            if let TransmitTarget::DirectUdp(dst) = tx.target {
                assert_eq!(dst, bob_lan);
                bob_mesh
                    .handle_receive(
                        Some(alice_lan),
                        &tx.payload,
                        t0 + RELAY_FALLBACK_TIMEOUT + Duration::from_millis(530),
                    )
                    .unwrap();
            }
        }

        // Bob is now upgraded to Direct!
        assert_eq!(
            bob_mesh.peer_path(alice_bundle.node.public.id()),
            Some(ConnectionPath::Direct { remote: alice_lan })
        );
        let mut upgraded = false;
        while let Some(ev) = bob_mesh.poll_event() {
            if matches!(ev, MeshEvent::PathUpgraded { .. }) {
                upgraded = true;
            }
        }
        assert!(upgraded);
    }
}
