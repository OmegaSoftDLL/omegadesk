//! OmegaDesk mesh coordinator (`omegadesk-server`).
//!
//! Implements the control-plane components specified for Phase 2 of `docs/plan.md`:
//! - **Pre-authorized & ephemeral keys** (modeled after Headscale's
//!   `hscontrol/db/preauth_keys.go`): `odk_<prefix>_<secret>` machine enrollment
//!   keys with SHA-256 secret hashing, single-use vs reusable semantics,
//!   ephemeral node lifecycle, and `tag:` ACL tag validation (`validate_acl_tags`).
//! - **Tenant-scoped batched netmap stream** (modeled after Headscale's
//!   `hscontrol/mapper/batcher.go` and its per-node visibility filtering):
//!   [`NetmapBatcher`] coalesces changes and fans out snapshots and
//!   incremental [`NetmapDelta`] patches **only to nodes of the same tenant**.
//! - **Internal DNS `*.omega` (`MagicDNS`)** (modeled after Tailscale's `net/dns`):
//!   [`MagicDnsResolver`] allocates mesh IPv4 (`100.64.0.0/10`) and IPv6
//!   (`fd7a:115c:a1e0::/48`) addresses, sanitizes hostnames into collision-free
//!   RFC 1123 labels of at most 63 bytes, and answers forward and reverse queries.
//! - **Relay-bound single-use tickets**: one HMAC-SHA256 [`RelayTicket`] per
//!   configured relay, each valid on that relay only (`omegadesk-relay`).
//! - **Control protocol conversions** between the in-memory netmap and the
//!   `omegadesk.control.v1` protobuf messages carried over Noise IK.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use data_encoding::HEXLOWER;
use omegadesk_identity::{DeviceId, DevicePublic, IdentityError};
use omegadesk_protocol::control::v1 as control;
use omegadesk_relay::{RelayTicket, TicketIssuer};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;

pub mod control_server;
pub mod rmm;
pub mod web_gateway;
pub mod webhooks_audit;

/// Base internal DNS suffix for all machines on the OmegaDesk mesh (`*.omega`).
pub const OMEGA_DNS_SUFFIX: &str = "omega";

/// Maximum length of one DNS label (RFC 1035 §2.3.4).
pub const MAX_DNS_LABEL_LEN: usize = 63;

/// Default lifetime of a single-use relay ticket issued during enrollment (300 s).
pub const DEFAULT_RELAY_TICKET_TTL_SECS: u64 = 300;

/// Number of host addresses in the `100.64.0.0/10` mesh pool (2^22).
pub const IPV4_POOL_SIZE: u32 = 1 << 22;

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
    /// Every address of the `100.64.0.0/10` pool is allocated.
    #[error("mesh address pool exhausted")]
    AddressPoolExhausted,
    /// A control message could not be converted (bad key length, bad address).
    #[error("malformed control message: {0}")]
    MalformedControlMessage(&'static str),
}

impl From<IdentityError> for CoordinatorError {
    fn from(_: IdentityError) -> Self {
        Self::MalformedControlMessage("invalid public key")
    }
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
    /// SHA-256 hash of the 24-byte secret half (hex encoded).
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
    /// Returns `Ok(())` if this key can be redeemed at `now_unix_secs`.
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

impl NodeRecord {
    /// Converts this record into its control-protocol representation.
    #[must_use]
    pub fn to_proto(&self) -> control::NodeInfo {
        control::NodeInfo {
            signing_key: self.public.signing_key_bytes().to_vec().into(),
            exchange_key: self.public.exchange_key_bytes().to_vec().into(),
            tenant: self.tenant.clone(),
            hostname: self.hostname.clone(),
            fqdn: self.fqdn.clone(),
            ipv4: self.ipv4.to_string(),
            ipv6: self.ipv6.to_string(),
            endpoints: self.endpoints.iter().map(ToString::to_string).collect(),
            tags: self.tags.clone(),
            ephemeral: self.ephemeral,
        }
    }

    /// Parses a control-protocol node into a record.
    ///
    /// # Errors
    ///
    /// Returns [`CoordinatorError::MalformedControlMessage`] on bad keys or addresses.
    pub fn from_proto(info: &control::NodeInfo) -> Result<Self, CoordinatorError> {
        let public = public_from_bytes(&info.signing_key, &info.exchange_key)?;
        let ipv4: Ipv4Addr = info
            .ipv4
            .parse()
            .map_err(|_| CoordinatorError::MalformedControlMessage("ipv4"))?;
        let ipv6: Ipv6Addr = info
            .ipv6
            .parse()
            .map_err(|_| CoordinatorError::MalformedControlMessage("ipv6"))?;
        Ok(Self {
            public,
            tenant: info.tenant.clone(),
            hostname: info.hostname.clone(),
            fqdn: info.fqdn.clone(),
            ipv4,
            ipv6,
            endpoints: parse_endpoints(&info.endpoints),
            tags: info.tags.clone(),
            ephemeral: info.ephemeral,
        })
    }
}

/// Parses `ip:port` strings, silently dropping malformed entries (a peer's bad
/// endpoint must never break the whole netmap).
#[must_use]
pub fn parse_endpoints(raw: &[String]) -> Vec<SocketAddr> {
    raw.iter().filter_map(|s| s.parse().ok()).collect()
}

/// Builds a [`DevicePublic`] from the raw 32-byte keys carried in control messages.
///
/// # Errors
///
/// Returns [`CoordinatorError::MalformedControlMessage`] if a key has the wrong
/// length or is not a valid Ed25519 point.
pub fn public_from_bytes(
    signing: &[u8],
    exchange: &[u8],
) -> Result<DevicePublic, CoordinatorError> {
    let signing: [u8; 32] = signing
        .try_into()
        .map_err(|_| CoordinatorError::MalformedControlMessage("signing key length"))?;
    let exchange: [u8; 32] = exchange
        .try_into()
        .map_err(|_| CoordinatorError::MalformedControlMessage("exchange key length"))?;
    Ok(DevicePublic::from_bytes(&signing, &exchange)?)
}

/// Incremental netmap update pushed over a node's control stream, modeled after
/// Headscale's `hscontrol/mapper/batcher.go`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetmapDelta {
    /// Initial or full topology snapshot containing the self node and all
    /// peers of the same tenant.
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
        /// Ed25519 signing key of the peer (for the wire representation).
        signing_key: [u8; 32],
        /// Updated direct UDP candidate endpoints.
        endpoints: Vec<SocketAddr>,
    },
    /// A peer disconnected (ephemeral) or was removed from the mesh.
    PeerRemoved {
        /// Peer device identifier.
        peer: DeviceId,
        /// Ed25519 signing key of the peer (for the wire representation).
        signing_key: [u8; 32],
    },
}

impl NetmapDelta {
    /// Converts an incremental delta into its control-protocol representation.
    /// Snapshots are delivered in `EnrollResponse`, never inside a batch.
    #[must_use]
    pub fn to_proto(&self) -> Option<control::NetmapDelta> {
        let change = match self {
            Self::FullSnapshot { .. } => return None,
            Self::PeerUpserted(record) => {
                control::netmap_delta::Change::PeerUpserted(record.to_proto())
            }
            Self::EndpointUpdated {
                signing_key,
                endpoints,
                ..
            } => control::netmap_delta::Change::EndpointsUpdated(control::EndpointUpdate {
                signing_key: signing_key.to_vec().into(),
                endpoints: endpoints.iter().map(ToString::to_string).collect(),
            }),
            Self::PeerRemoved { signing_key, .. } => {
                control::netmap_delta::Change::PeerRemoved(signing_key.to_vec().into())
            }
        };
        Some(control::NetmapDelta {
            change: Some(change),
        })
    }
}

/// Coalesces rapid netmap changes and broadcasts batched [`NetmapDelta`] updates
/// to the connected nodes **of the affected tenant only**, modeled after
/// Headscale's `Batcher` (`hscontrol/mapper/batcher.go`).
#[derive(Default)]
pub struct NetmapBatcher {
    pending: Vec<(String, NetmapDelta)>,
    subscribers: HashMap<DeviceId, (String, mpsc::Sender<Vec<NetmapDelta>>)>,
}

impl NetmapBatcher {
    /// Creates a new [`NetmapBatcher`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Subscribes `node_id` (member of `tenant`) to receive batched [`NetmapDelta`]
    /// vectors and immediately queues `initial_snapshot`.
    pub fn subscribe(
        &mut self,
        node_id: DeviceId,
        tenant: &str,
        initial_snapshot: NetmapDelta,
    ) -> mpsc::Receiver<Vec<NetmapDelta>> {
        let (tx, rx) = mpsc::channel(64);
        let _ = tx.try_send(vec![initial_snapshot]);
        self.subscribers.insert(node_id, (tenant.to_owned(), tx));
        rx
    }

    /// Removes `node_id`'s subscription channel.
    pub fn unsubscribe(&mut self, node_id: DeviceId) {
        self.subscribers.remove(&node_id);
    }

    /// Queues a delta for `tenant`, to be coalesced and broadcast on the next [`Self::flush`].
    pub fn enqueue(&mut self, tenant: &str, delta: NetmapDelta) {
        // Coalesce consecutive EndpointUpdated deltas for the same peer.
        if let NetmapDelta::EndpointUpdated {
            peer,
            ref endpoints,
            ..
        } = delta
        {
            for (_, item) in &mut self.pending {
                if let NetmapDelta::EndpointUpdated {
                    peer: existing_peer,
                    endpoints: existing_eps,
                    ..
                } = item
                    && *existing_peer == peer
                {
                    existing_eps.clone_from(endpoints);
                    return;
                }
            }
        }
        self.pending.push((tenant.to_owned(), delta));
    }

    /// Flushes all pending [`NetmapDelta`] items, one batch per tenant, to the
    /// subscribed nodes of that tenant. Returns the number of deltas flushed.
    pub fn flush(&mut self) -> usize {
        if self.pending.is_empty() {
            return 0;
        }
        let pending = std::mem::take(&mut self.pending);
        let count = pending.len();
        let mut by_tenant: HashMap<String, Vec<NetmapDelta>> = HashMap::new();
        for (tenant, delta) in pending {
            by_tenant.entry(tenant).or_default().push(delta);
        }
        let mut dead = Vec::new();
        for (node_id, (tenant, tx)) in &self.subscribers {
            if let Some(batch) = by_tenant.get(tenant)
                && tx.try_send(batch.clone()).is_err()
            {
                dead.push(*node_id);
            }
        }
        for node_id in dead {
            self.subscribers.remove(&node_id);
        }
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

    /// Sanitizes an arbitrary machine name into a valid lowercase RFC 1123 DNS
    /// label of at most `max_len` bytes (`63` for a full label).
    #[must_use]
    pub fn sanitize_dns_label_with_len(raw: &str, max_len: usize) -> String {
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
        out.truncate(max_len.min(MAX_DNS_LABEL_LEN));
        // Truncation can leave a trailing hyphen: trim it after the cut.
        while out.ends_with('-') {
            out.pop();
        }
        if out.is_empty() {
            "node".to_owned()
        } else {
            out
        }
    }

    /// Sanitizes a name into a full-length (63 byte) label.
    #[must_use]
    pub fn sanitize_dns_label(raw: &str) -> String {
        Self::sanitize_dns_label_with_len(raw, MAX_DNS_LABEL_LEN)
    }

    /// Registers `requested_hostname` for `device_id` with `(ipv4, ipv6)`, resolving
    /// name collisions automatically (`host.omega`, `host-2.omega`, …) while keeping
    /// every label within 63 bytes, and returns `(sanitized_label, fqdn)`.
    pub fn register(
        &mut self,
        device_id: DeviceId,
        requested_hostname: &str,
        ipv4: Ipv4Addr,
        ipv6: Ipv6Addr,
    ) -> (String, String) {
        let base_label = Self::sanitize_dns_label(requested_hostname);
        let mut suffix_num = 1u32;
        loop {
            let candidate_label = if suffix_num == 1 {
                base_label.clone()
            } else {
                let suffix = format!("-{suffix_num}");
                let mut trimmed = Self::sanitize_dns_label_with_len(
                    &base_label,
                    MAX_DNS_LABEL_LEN - suffix.len(),
                );
                trimmed.push_str(&suffix);
                trimmed
            };
            let fqdn = format!("{candidate_label}.{OMEGA_DNS_SUFFIX}");
            if let Some(&(_, _, existing_id)) = self.by_fqdn.get(&fqdn)
                && existing_id != device_id
            {
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

/// A relay node known to the coordinator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayNode {
    /// `host:port` of the relay TCP listener.
    pub address: String,
    /// Relay X25519 public key (ticket audience).
    pub exchange_key: [u8; 32],
    /// `host:port` of the relay STUN responder, if any.
    pub stun_address: Option<String>,
}

/// Ticket issued for one relay, ready to be sent to a node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayGrant {
    /// The relay this ticket is valid on.
    pub relay: RelayNode,
    /// Single-use ticket bound to the node and the relay.
    pub ticket: RelayTicket,
}

impl RelayGrant {
    /// Control-protocol representation.
    #[must_use]
    pub fn to_proto(&self) -> control::RelayInfo {
        control::RelayInfo {
            address: self.relay.address.clone(),
            exchange_key: self.relay.exchange_key.to_vec().into(),
            ticket: self.ticket.to_bytes().to_vec().into(),
            stun_address: self.relay.stun_address.clone().unwrap_or_default(),
        }
    }
}

/// Response returned to a machine when it enrolls with the coordinator.
#[derive(Debug)]
pub struct EnrollmentBundle {
    /// Session generation of this enrollment; pass it to
    /// [`Coordinator::handle_disconnect`] so a stale connection never tears
    /// down its replacement.
    pub generation: u64,
    /// The enrolled node's assigned record (including mesh IPv4/IPv6 and `*.omega` FQDN).
    pub node: NodeRecord,
    /// Peers of the same tenant visible at enrollment time.
    pub peers: Vec<NodeRecord>,
    /// One single-use ticket per configured relay.
    pub relays: Vec<RelayGrant>,
    /// Receiver stream delivering batched [`NetmapDelta`] updates.
    pub netmap_rx: mpsc::Receiver<Vec<NetmapDelta>>,
}

impl EnrollmentBundle {
    /// Builds the `EnrollResponse` control message for this enrollment.
    #[must_use]
    pub fn to_proto(&self) -> control::EnrollResponse {
        control::EnrollResponse {
            protocol_version: omegadesk_protocol::control::CONTROL_PROTOCOL_VERSION,
            self_node: Some(self.node.to_proto()),
            peers: self.peers.iter().map(NodeRecord::to_proto).collect(),
            relays: self.relays.iter().map(RelayGrant::to_proto).collect(),
        }
    }
}

/// Computes the mesh IPv4 and IPv6 addresses for pool index `index`
/// (`1..IPV4_POOL_SIZE`) without truncating the index: `100.64.0.0/10 + index`
/// and `fd7a:115c:a1e0::/48` with `index` in the low 32 bits.
#[must_use]
pub fn mesh_addresses(index: u32) -> Option<(Ipv4Addr, Ipv6Addr)> {
    if index == 0 || index >= IPV4_POOL_SIZE {
        return None;
    }
    let v4 = Ipv4Addr::from(u32::from(Ipv4Addr::new(100, 64, 0, 0)) + index);
    let v6 = Ipv6Addr::new(
        0xfd7a,
        0x115c,
        0xa1e0,
        0,
        0,
        0,
        u16::try_from(index >> 16).unwrap_or(0),
        u16::try_from(index & 0xFFFF).unwrap_or(0),
    );
    Some((v4, v6))
}

/// Central OmegaDesk mesh coordinator state machine.
pub struct Coordinator {
    preauth_keys: HashMap<String, PreAuthKey>,
    nodes: HashMap<DeviceId, NodeRecord>,
    /// Current session generation per node (incremented on every enrollment).
    sessions: HashMap<DeviceId, u64>,
    next_generation: u64,
    next_ip_index: u32,
    dns: MagicDnsResolver,
    batcher: NetmapBatcher,
    ticket_issuer: TicketIssuer,
    relays: Vec<RelayNode>,
}

impl Coordinator {
    /// Creates a new [`Coordinator`] sharing `relay_ticket_secret` with the relay fleet.
    #[must_use]
    pub fn new(relay_ticket_secret: [u8; 32]) -> Self {
        Self {
            preauth_keys: HashMap::new(),
            nodes: HashMap::new(),
            sessions: HashMap::new(),
            next_generation: 1,
            next_ip_index: 1,
            dns: MagicDnsResolver::new(),
            batcher: NetmapBatcher::new(),
            ticket_issuer: TicketIssuer::new(relay_ticket_secret),
            relays: Vec::new(),
        }
    }

    /// Registers a relay node for which tickets are issued at enrollment.
    pub fn add_relay(&mut self, relay: RelayNode) {
        self.relays.retain(|r| r.exchange_key != relay.exchange_key);
        self.relays.push(relay);
    }

    /// Configured relays.
    #[must_use]
    pub fn relays(&self) -> &[RelayNode] {
        &self.relays
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

    /// Issues fresh single-use tickets for `node_id` on every configured relay.
    ///
    /// # Errors
    ///
    /// Returns [`CoordinatorError::UnknownNode`] if `node_id` is not enrolled.
    pub fn issue_relay_grants(
        &self,
        node_id: DeviceId,
        now_unix_secs: u64,
    ) -> Result<Vec<RelayGrant>, CoordinatorError> {
        let node = self
            .nodes
            .get(&node_id)
            .ok_or(CoordinatorError::UnknownNode(node_id))?;
        let client_key = node.public.exchange_key_bytes();
        Ok(self
            .relays
            .iter()
            .map(|relay| RelayGrant {
                relay: relay.clone(),
                ticket: self.ticket_issuer.issue_random(
                    client_key,
                    relay.exchange_key,
                    now_unix_secs + DEFAULT_RELAY_TICKET_TTL_SECS,
                ),
            })
            .collect())
    }

    /// Enrolls a machine using a `preauth_token`, allocates its `100.64.x.y` /
    /// `fd7a:115c:a1e0::x` mesh addresses and `<hostname>.omega` `MagicDNS` name,
    /// issues one relay ticket per relay, and subscribes the node to the
    /// tenant-scoped [`NetmapBatcher`].
    ///
    /// # Errors
    ///
    /// Returns [`CoordinatorError`] if the pre-auth key is invalid, expired, or
    /// already consumed, or if the address pool is exhausted.
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

        let node_id = public.id();
        // Allocate addresses before consuming the key so an exhausted pool does
        // not burn a single-use key.
        let (ipv4, ipv6) = if let Some(existing) = self.nodes.get(&node_id) {
            (existing.ipv4, existing.ipv6)
        } else {
            let (v4, v6) =
                mesh_addresses(self.next_ip_index).ok_or(CoordinatorError::AddressPoolExhausted)?;
            self.next_ip_index += 1;
            (v4, v6)
        };
        key.used = true;
        let tenant = key.tenant.clone();
        let tags = key.tags.clone();
        let ephemeral = key.ephemeral;

        // Re-enrollment with a new hostname must not leave the old name resolving,
        // and moving to another tenant must remove the node from the old tenant's
        // netmaps.
        if let Some(previous) = self.nodes.get(&node_id) {
            self.dns.unregister(&previous.fqdn);
            if previous.tenant != tenant {
                let old_tenant = previous.tenant.clone();
                let signing_key = previous.public.signing_key_bytes();
                self.batcher.enqueue(
                    &old_tenant,
                    NetmapDelta::PeerRemoved {
                        peer: node_id,
                        signing_key,
                    },
                );
            }
        }
        let generation = self.next_generation;
        self.next_generation += 1;
        self.sessions.insert(node_id, generation);
        let (sanitized_label, fqdn) = self.dns.register(node_id, hostname, ipv4, ipv6);
        let record = NodeRecord {
            public,
            tenant: tenant.clone(),
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
            .values()
            .filter(|r| r.public.id() != node_id && r.tenant == tenant)
            .cloned()
            .collect();
        self.nodes.insert(node_id, record.clone());

        // Broadcast `PeerUpserted` to the tenant's connected peers before
        // subscribing the newly enrolled node (which receives `FullSnapshot`).
        self.batcher
            .enqueue(&tenant, NetmapDelta::PeerUpserted(record.clone()));
        self.batcher.flush();

        let snapshot = NetmapDelta::FullSnapshot {
            self_node: record.clone(),
            peers: peers.clone(),
        };
        let netmap_rx = self.batcher.subscribe(node_id, &tenant, snapshot);
        let relays = self.issue_relay_grants(node_id, now_unix_secs)?;

        Ok(EnrollmentBundle {
            generation,
            node: record,
            peers,
            relays,
            netmap_rx,
        })
    }

    /// Updates the candidate UDP endpoints of `node_id` and queues a coalesced
    /// [`NetmapDelta::EndpointUpdated`] delta for its tenant.
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
        let tenant = node.tenant.clone();
        let signing_key = node.public.signing_key_bytes();
        self.batcher.enqueue(
            &tenant,
            NetmapDelta::EndpointUpdated {
                peer: node_id,
                signing_key,
                endpoints,
            },
        );
        Ok(())
    }

    /// Handles node disconnection of the session with `generation`; a stale
    /// generation (the node already re-enrolled on another connection) is a
    /// no-op. If the node was enrolled with an `ephemeral` pre-auth key, removes
    /// it from the netmap and `MagicDNS` immediately (matching Headscale's
    /// ephemeral node cleanup).
    pub fn handle_disconnect(&mut self, node_id: DeviceId, generation: u64) {
        if self.sessions.get(&node_id) != Some(&generation) {
            return;
        }
        self.sessions.remove(&node_id);
        self.batcher.unsubscribe(node_id);
        if let Some(node) = self.nodes.get(&node_id)
            && node.ephemeral
            && let Some(removed) = self.nodes.remove(&node_id)
        {
            self.dns.unregister(&removed.fqdn);
            self.batcher.enqueue(
                &removed.tenant,
                NetmapDelta::PeerRemoved {
                    peer: node_id,
                    signing_key: removed.public.signing_key_bytes(),
                },
            );
            self.batcher.flush();
        }
    }

    /// Flushes any pending netmap deltas to subscribed nodes.
    pub fn flush_netmap(&mut self) -> usize {
        self.batcher.flush()
    }

    /// Looks up an enrolled node.
    #[must_use]
    pub fn node(&self, node_id: DeviceId) -> Option<&NodeRecord> {
        self.nodes.get(&node_id)
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

/// Named CIDR subnet carved out of the root `100.64.0.0/10` mesh space (`tonarino/innernet`
/// hierarchical CIDR model, `docs/references.md` line 55).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CidrSubnet {
    /// Human-readable CIDR block name (e.g., `"infra"`, `"developers"`, `"ci-runners"`).
    pub name: String,
    /// Network base address in host byte order.
    pub network_u32: u32,
    /// Prefix length (`10..=30`).
    pub prefix_len: u8,
    /// Next host offset to allocate within this subnet.
    next_host_offset: u32,
}

impl CidrSubnet {
    /// Returns the bitmask for `prefix_len`.
    #[must_use]
    pub const fn mask(prefix_len: u8) -> u32 {
        if prefix_len == 0 {
            0
        } else {
            !0u32 << (32 - prefix_len)
        }
    }

    /// Returns `true` if `other_net / other_prefix` overlaps with `self`.
    #[must_use]
    pub const fn overlaps(&self, other_net: u32, other_prefix: u8) -> bool {
        let min_prefix = if self.prefix_len < other_prefix {
            self.prefix_len
        } else {
            other_prefix
        };
        let mask = Self::mask(min_prefix);
        (self.network_u32 & mask) == (other_net & mask)
    }
}

/// Hierarchical CIDR allocator modeled after `tonarino/innernet` (`docs/references.md` line 55),
/// allowing operators to partition the root `100.64.0.0/10` CGNAT space into non-overlapping
/// named subnets (`infra`, `prod`, `dev`) and allocate deterministic host IPv4 addresses.
#[derive(Debug, Clone, Default)]
pub struct HierarchicalCidrAllocator {
    subnets: HashMap<String, CidrSubnet>,
}

impl HierarchicalCidrAllocator {
    /// Root `100.64.0.0/10` network in host byte order.
    pub const ROOT_NET_U32: u32 = u32::from_be_bytes([100, 64, 0, 0]);
    /// Root prefix length (`/10`).
    pub const ROOT_PREFIX_LEN: u8 = 10;

    /// Creates an empty [`HierarchicalCidrAllocator`] rooted at `100.64.0.0/10`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Carves a new non-overlapping child subnet `network/prefix_len` under the `100.64.0.0/10`
    /// root block. Returns `false` if the block is outside `100.64.0.0/10`, has an invalid prefix,
    /// or overlaps with an existing child CIDR.
    pub fn create_subnet(
        &mut self,
        name: impl Into<String>,
        network: Ipv4Addr,
        prefix_len: u8,
    ) -> bool {
        if !(11..=30).contains(&prefix_len) {
            return false;
        }
        let mask = CidrSubnet::mask(prefix_len);
        let net_u32 = u32::from(network) & mask;
        let root_mask = CidrSubnet::mask(Self::ROOT_PREFIX_LEN);
        if (net_u32 & root_mask) != Self::ROOT_NET_U32 {
            return false;
        }
        let name = name.into();
        if self.subnets.contains_key(&name)
            || self
                .subnets
                .values()
                .any(|existing| existing.overlaps(net_u32, prefix_len))
        {
            return false;
        }
        self.subnets.insert(
            name.clone(),
            CidrSubnet {
                name,
                network_u32: net_u32,
                prefix_len,
                next_host_offset: 1,
            },
        );
        true
    }

    /// Allocates the next available host [`Ipv4Addr`] inside the named child subnet.
    pub fn allocate_host_ip(&mut self, subnet_name: &str) -> Option<Ipv4Addr> {
        let subnet = self.subnets.get_mut(subnet_name)?;
        let host_bits = 32 - subnet.prefix_len;
        let max_host = (1u32 << host_bits) - 2; // exclude broadcast
        if subnet.next_host_offset > max_host {
            return None;
        }
        let ip = Ipv4Addr::from(subnet.network_u32 + subnet.next_host_offset);
        subnet.next_host_offset += 1;
        Some(ip)
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
    use omegadesk_relay::{RelayFrame, RelayRouter, seal_client_login};
    use omegadesk_tun::IpPacket;

    use super::*;

    #[test]
    fn preauth_keys_enforce_tags_single_use_and_ephemeral_cleanup() {
        let mut coord = Coordinator::new([0x55u8; 32]);
        assert_eq!(
            coord.create_preauth_key("acme", false, false, vec!["prod".to_owned()], None),
            Err(CoordinatorError::InvalidAclTag("prod".to_owned()))
        );
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

        let dev2 = DeviceIdentity::generate();
        assert_eq!(
            coord
                .enroll_machine(&token, dev2.public(), "runner-02", vec![], 1001)
                .unwrap_err(),
            CoordinatorError::PreAuthKeyAlreadyUsed
        );

        coord.handle_disconnect(dev1.id(), bundle.generation);
        assert_eq!(coord.node_count(), 0);
        assert_eq!(coord.dns().lookup("runner-01.omega"), None);
    }

    #[test]
    fn netmap_is_scoped_to_the_tenant() {
        let mut coord = Coordinator::new([1u8; 32]);
        let acme = coord
            .create_preauth_key("acme", true, false, vec![], None)
            .unwrap();
        let globex = coord
            .create_preauth_key("globex", true, true, vec![], None)
            .unwrap();
        let a1 = DeviceIdentity::generate();
        let a2 = DeviceIdentity::generate();
        let g1 = DeviceIdentity::generate();

        let mut a1_bundle = coord
            .enroll_machine(&acme, a1.public(), "a1", vec![], 10)
            .unwrap();
        let g1_bundle = coord
            .enroll_machine(&globex, g1.public(), "g1", vec![], 10)
            .unwrap();
        assert!(g1_bundle.peers.is_empty(), "globex must not see acme nodes");
        let a2_bundle = coord
            .enroll_machine(&acme, a2.public(), "a2", vec![], 10)
            .unwrap();
        assert_eq!(a2_bundle.peers.len(), 1);
        assert_eq!(a2_bundle.peers[0].public.id(), a1.id());

        // a1 saw its snapshot, then PeerUpserted(a2) but nothing about g1.
        let snapshot = a1_bundle.netmap_rx.try_recv().unwrap();
        assert!(matches!(snapshot[0], NetmapDelta::FullSnapshot { .. }));
        let delta = a1_bundle.netmap_rx.try_recv().unwrap();
        assert_eq!(
            delta,
            vec![NetmapDelta::PeerUpserted(a2_bundle.node.clone())]
        );
        assert!(a1_bundle.netmap_rx.try_recv().is_err());

        // Endpoint updates and removals follow the same scope.
        coord
            .update_endpoints(g1.id(), vec!["203.0.113.1:1".parse().unwrap()])
            .unwrap();
        coord.flush_netmap();
        assert!(a1_bundle.netmap_rx.try_recv().is_err());
        coord.handle_disconnect(g1.id(), g1_bundle.generation);
        assert!(a1_bundle.netmap_rx.try_recv().is_err());
        coord
            .update_endpoints(a2.id(), vec!["203.0.113.2:2".parse().unwrap()])
            .unwrap();
        coord.flush_netmap();
        let delta = a1_bundle.netmap_rx.try_recv().unwrap();
        assert!(matches!(
            &delta[0],
            NetmapDelta::EndpointUpdated { peer, .. } if *peer == a2.id()
        ));
        // Deltas convert to the wire representation; snapshots do not.
        assert!(delta[0].to_proto().is_some());
        assert!(snapshot[0].to_proto().is_none());
    }

    #[test]
    fn addresses_never_wrap_and_names_stay_valid_labels() {
        let (v4, v6) = mesh_addresses(1).unwrap();
        assert_eq!(v4, Ipv4Addr::new(100, 64, 0, 1));
        assert_eq!(v6, "fd7a:115c:a1e0::1".parse::<Ipv6Addr>().unwrap());
        let (v4, _) = mesh_addresses(65_537).unwrap();
        assert_eq!(v4, Ipv4Addr::new(100, 65, 0, 1));
        let (v4, v6) = mesh_addresses(IPV4_POOL_SIZE - 1).unwrap();
        assert_eq!(v4, Ipv4Addr::new(100, 127, 255, 255));
        assert_eq!(v6, "fd7a:115c:a1e0::3f:ffff".parse::<Ipv6Addr>().unwrap());
        assert_eq!(mesh_addresses(0), None);
        assert_eq!(mesh_addresses(IPV4_POOL_SIZE), None);

        // 62 'a' + "-b": truncation to 63 would end in '-'; the hyphen is trimmed.
        let long = format!("{}-b", "a".repeat(62));
        let label = MagicDnsResolver::sanitize_dns_label(&long);
        assert_eq!(label.len(), 62);
        assert!(!label.ends_with('-'));

        // Collision suffixes keep the label within 63 bytes.
        let mut dns = MagicDnsResolver::new();
        let name = "x".repeat(70);
        let (l1, _) = dns.register(
            DeviceIdentity::generate().id(),
            &name,
            Ipv4Addr::new(100, 64, 0, 1),
            Ipv6Addr::LOCALHOST,
        );
        let (l2, fqdn2) = dns.register(
            DeviceIdentity::generate().id(),
            &name,
            Ipv4Addr::new(100, 64, 0, 2),
            "fd7a::2".parse().unwrap(),
        );
        assert_eq!(l1.len(), 63);
        assert_eq!(l2.len(), 63);
        assert!(l2.ends_with("-2"), "{l2}");
        assert_eq!(
            dns.lookup(&fqdn2).map(|(v4, _)| v4),
            Some(Ipv4Addr::new(100, 64, 0, 2))
        );

        // Re-enrolling with a new hostname removes the old record.
        let mut coord = Coordinator::new([2u8; 32]);
        let key = coord
            .create_preauth_key("t", true, false, vec![], None)
            .unwrap();
        let dev = DeviceIdentity::generate();
        let first = coord
            .enroll_machine(&key, dev.public(), "old-name", vec![], 1)
            .unwrap();
        let second = coord
            .enroll_machine(&key, dev.public(), "new-name", vec![], 2)
            .unwrap();
        assert_eq!(first.node.ipv4, second.node.ipv4, "addresses are stable");
        assert_eq!(coord.dns().lookup("old-name.omega"), None);
        assert!(coord.dns().lookup("new-name.omega").is_some());
        // The stale first session cannot tear down the second enrollment.
        assert_ne!(first.generation, second.generation);
        coord.handle_disconnect(dev.id(), first.generation);
        assert!(coord.node(dev.id()).is_some());
    }

    #[test]
    fn moving_to_another_tenant_removes_the_node_from_the_old_tenant() {
        let mut coord = Coordinator::new([4u8; 32]);
        let acme = coord
            .create_preauth_key("acme", true, false, vec![], None)
            .unwrap();
        let globex = coord
            .create_preauth_key("globex", true, false, vec![], None)
            .unwrap();
        let watcher = DeviceIdentity::generate();
        let mover = DeviceIdentity::generate();
        let mut watcher_bundle = coord
            .enroll_machine(&acme, watcher.public(), "watcher", vec![], 1)
            .unwrap();
        let _ = coord
            .enroll_machine(&acme, mover.public(), "mover", vec![], 2)
            .unwrap();
        let _ = watcher_bundle.netmap_rx.try_recv().unwrap(); // snapshot
        let _ = watcher_bundle.netmap_rx.try_recv().unwrap(); // PeerUpserted(mover)
        let moved = coord
            .enroll_machine(&globex, mover.public(), "mover", vec![], 3)
            .unwrap();
        assert_eq!(moved.node.tenant, "globex");
        let delta = watcher_bundle.netmap_rx.try_recv().unwrap();
        assert!(matches!(&delta[0], NetmapDelta::PeerRemoved { peer, .. } if *peer == mover.id()));
    }

    #[test]
    fn relay_grants_are_bound_to_each_relay_and_round_trip_through_proto() {
        let mut coord = Coordinator::new([3u8; 32]);
        let relay_a = DeviceIdentity::generate().public().exchange_key_bytes();
        let relay_b = DeviceIdentity::generate().public().exchange_key_bytes();
        coord.add_relay(RelayNode {
            address: "relay-a.example:443".into(),
            exchange_key: relay_a,
            stun_address: Some("relay-a.example:3478".into()),
        });
        coord.add_relay(RelayNode {
            address: "relay-b.example:443".into(),
            exchange_key: relay_b,
            stun_address: None,
        });
        let key = coord
            .create_preauth_key("t", true, false, vec!["tag:x".into()], None)
            .unwrap();
        let dev = DeviceIdentity::generate();
        let bundle = coord
            .enroll_machine(
                &key,
                dev.public(),
                "desk",
                vec!["192.168.0.5:7070".parse().unwrap()],
                100,
            )
            .unwrap();
        assert_eq!(bundle.relays.len(), 2);
        assert_eq!(bundle.relays[0].ticket.relay_exchange_key, relay_a);
        assert_eq!(bundle.relays[1].ticket.relay_exchange_key, relay_b);
        assert_eq!(
            bundle.relays[0].ticket.client_exchange_key,
            dev.public().exchange_key_bytes()
        );

        let proto = bundle.to_proto();
        let self_node = NodeRecord::from_proto(proto.self_node.as_ref().unwrap()).unwrap();
        assert_eq!(self_node, bundle.node);
        assert_eq!(proto.relays[0].stun_address, "relay-a.example:3478");
        assert_eq!(
            RelayTicket::from_bytes(&proto.relays[1].ticket).unwrap(),
            bundle.relays[1].ticket
        );
        let fresh = coord.issue_relay_grants(dev.id(), 200).unwrap();
        assert_ne!(fresh[0].ticket.ticket_id, bundle.relays[0].ticket.ticket_id);
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn phase2_end_to_end_enroll_over_noise_fallback_to_relay_and_upgrade_to_direct() {
        let shared_secret = [0xA5u8; 32];
        let coord_id = DeviceIdentity::generate();
        let relay_id = DeviceIdentity::generate();
        let relay_key = relay_id.public().exchange_key_bytes();
        let mut coord = Coordinator::new(shared_secret);
        coord.add_relay(RelayNode {
            address: "relay.example:443".into(),
            exchange_key: relay_key,
            stun_address: None,
        });
        let mut relay = RelayRouter::new(
            DeviceIdentity::from_secret_bytes(&relay_id.to_secret_bytes()).unwrap(),
            shared_secret,
        );

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
        assert_eq!(alice_bundle.node.fqdn, "desk.omega");
        assert_eq!(bob_bundle.node.fqdn, "desk-2.omega");

        let _initial = alice_bundle.netmap_rx.recv().await.unwrap();
        let delta_batch = alice_bundle.netmap_rx.recv().await.unwrap();
        assert_eq!(
            delta_batch,
            vec![NetmapDelta::PeerUpserted(bob_bundle.node.clone())]
        );

        // 3. Both nodes authenticate to the stateless relay using their single-use
        //    tickets, sealed with their private keys (proof of key possession).
        let (_, alice_challenge) = relay.server_key_frame();
        let alice_login = seal_client_login(
            &alice_id,
            &relay_key,
            &alice_challenge,
            &alice_bundle.relays[0].ticket,
        )
        .unwrap();
        let mut alice_relay_rx = relay
            .register_client(
                alice_id.public().exchange_key_bytes(),
                &alice_challenge,
                &alice_login,
                1000,
            )
            .unwrap()
            .outbound;
        let (_, bob_challenge) = relay.server_key_frame();
        let bob_login = seal_client_login(
            &bob_id,
            &relay_key,
            &bob_challenge,
            &bob_bundle.relays[0].ticket,
        )
        .unwrap();
        let mut bob_relay_rx = relay
            .register_client(
                bob_id.public().exchange_key_bytes(),
                &bob_challenge,
                &bob_login,
                1000,
            )
            .unwrap()
            .outbound;

        // 4. Start sans-I/O MeshNodes; symmetric NAT blocks direct UDP at first
        let t0 = Instant::now();
        let mut alice_mesh = MeshNode::new(alice_id, vec![alice_lan], vec![]);
        let mut bob_mesh = MeshNode::new(bob_id, vec![bob_lan], vec![]);
        alice_mesh.upsert_peer(bob_bundle.node.public, vec![], t0);
        bob_mesh.upsert_peer(alice_bundle.node.public, vec![], t0);
        while alice_mesh.poll_transmit().is_some() {}
        while bob_mesh.poll_transmit().is_some() {}
        alice_mesh.handle_timeout(t0 + RELAY_FALLBACK_TIMEOUT);

        let pkt = IpPacket::ipv4_udp(
            alice_bundle.node.ipv4,
            bob_bundle.node.ipv4,
            40000,
            4433,
            b"relayed-frame",
        )
        .unwrap();
        // Epochs travel in the CallMeMaybe/Ping messages exchanged over the relay.
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
                .handle_receive(None, &packet, t0 + RELAY_FALLBACK_TIMEOUT)
                .unwrap();
        }
        bob_mesh.handle_timeout(t0 + RELAY_FALLBACK_TIMEOUT);
        while let Some(tx) = bob_mesh.poll_transmit() {
            if let TransmitTarget::Relay(dst_key) = tx.target {
                relay
                    .forward_packet(
                        bob_bundle.node.public.exchange_key_bytes(),
                        dst_key,
                        tx.payload,
                    )
                    .unwrap();
            }
        }
        while let Ok(RelayFrame::RecvPacket { packet, .. }) = alice_relay_rx.try_recv() {
            alice_mesh
                .handle_receive(None, &packet, t0 + RELAY_FALLBACK_TIMEOUT)
                .unwrap();
        }
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
        let mut delivered = false;
        while let Ok(RelayFrame::RecvPacket { packet, .. }) = bob_relay_rx.try_recv() {
            if let Some((_, decapsulated)) = bob_mesh
                .handle_receive(None, &packet, t0 + RELAY_FALLBACK_TIMEOUT)
                .unwrap()
            {
                assert_eq!(decapsulated, pkt);
                delivered = true;
            }
        }
        assert!(delivered, "the relayed IP packet must reach Bob");

        // 5. Next probe tick: CallMeMaybe travels over the relay and punches direct UDP
        alice_mesh.handle_timeout(t0 + RELAY_FALLBACK_TIMEOUT + Duration::from_secs(5));
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
                    t0 + RELAY_FALLBACK_TIMEOUT + Duration::from_millis(5010),
                )
                .unwrap();
        }
        while let Some(tx) = bob_mesh.poll_transmit() {
            if let TransmitTarget::DirectUdp(dst) = tx.target {
                assert_eq!(dst, alice_lan);
                alice_mesh
                    .handle_receive(
                        Some(bob_lan),
                        &tx.payload,
                        t0 + RELAY_FALLBACK_TIMEOUT + Duration::from_millis(5020),
                    )
                    .unwrap();
            }
        }
        while let Some(tx) = alice_mesh.poll_transmit() {
            if let TransmitTarget::DirectUdp(dst) = tx.target {
                assert_eq!(dst, bob_lan);
                bob_mesh
                    .handle_receive(
                        Some(alice_lan),
                        &tx.payload,
                        t0 + RELAY_FALLBACK_TIMEOUT + Duration::from_millis(5030),
                    )
                    .unwrap();
            }
        }
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

    #[test]
    fn innernet_hierarchical_cidr_allocator_prevents_overlap() {
        let mut tree = HierarchicalCidrAllocator::new();
        assert!(tree.create_subnet("infra", Ipv4Addr::new(100, 64, 1, 0), 24));
        assert!(tree.create_subnet("developers", Ipv4Addr::new(100, 64, 2, 0), 24));
        assert!(!tree.create_subnet("overlap", Ipv4Addr::new(100, 64, 1, 128), 25));
        assert!(!tree.create_subnet("invalid", Ipv4Addr::new(192, 168, 1, 0), 24));
        assert_eq!(
            tree.allocate_host_ip("infra"),
            Some(Ipv4Addr::new(100, 64, 1, 1))
        );
        assert_eq!(
            tree.allocate_host_ip("infra"),
            Some(Ipv4Addr::new(100, 64, 1, 2))
        );
        assert_eq!(
            tree.allocate_host_ip("developers"),
            Some(Ipv4Addr::new(100, 64, 2, 1))
        );
    }
}
