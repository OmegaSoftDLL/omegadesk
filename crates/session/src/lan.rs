//! Serverless LAN mode: mDNS service announcement, signed transcript handshake,
//! and Trust On First Use (`TOFU`) device pinning.
//!
//! Modeled after **SubnetDesk** (`src/lan_mdns.rs`, `src/lan_protocol.rs`,
//! `src/lan_identity.rs`, AGPL-3.0):
//! - Announces `_omegadesk._udp.local.` on the local network with TXT properties
//!   carrying `display_name`, `platform`, `device_id`, and `protocol_version`.
//! - Authenticates the peer without a central coordinator by signing the
//!   handshake transcript (`TRANSCRIPT_PREFIX || protocol_version || client_nonce ||
//!   server_nonce || ephemeral_x25519_pk`) with the server's Ed25519 [`DeviceIdentity`].
//! - Pins each LAN peer's Ed25519 public key on first connection (`TOFU`) in
//!   [`TofuStore`], rejecting any subsequent connection where a known host or
//!   [`DeviceId`] presents a different key.

use std::collections::HashMap;
use std::net::IpAddr;

use omegadesk_identity::{DeviceId, DeviceIdentity, DevicePublic, IdentityError};
use omegadesk_protocol::PROTOCOL_VERSION;
use rand_core::{OsRng, RngCore};

/// mDNS service type advertised by OmegaDesk agents in serverless LAN mode,
/// modeled after SubnetDesk's `SERVICE_TYPE` (`src/lan_mdns.rs`).
pub const SERVICE_TYPE: &str = "_omegadesk._udp.local.";

/// Default UDP port used for serverless LAN connections.
pub const DEFAULT_LAN_PORT: u16 = 7070;

/// Domain-separation prefix for the signed LAN handshake transcript,
/// modeled after `TRANSCRIPT_PREFIX` in SubnetDesk (`src/lan_protocol.rs`).
pub const TRANSCRIPT_PREFIX: &[u8] = b"omegadesk-lan-handshake-v1\0";

/// Length of the random client and server nonces in bytes.
pub const NONCE_LEN: usize = 24;

/// Maximum display name length in an mDNS announcement (`src/lan_identity.rs`).
pub const MAX_DISPLAY_NAME_LEN: usize = 64;

/// Errors returned by serverless LAN discovery, handshake, or TOFU verification.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LanError {
    /// Display name is empty, exceeds [`MAX_DISPLAY_NAME_LEN`], or contains control characters.
    #[error("invalid LAN display name")]
    InvalidDisplayName,
    /// Protocol version mismatch between LAN peers.
    #[error("LAN protocol version mismatch: local {local}, remote {remote}")]
    VersionMismatch {
        /// Local protocol version.
        local: u32,
        /// Remote peer's protocol version.
        remote: u32,
    },
    /// Handshake transcript signature verification failed.
    #[error("LAN transcript signature verification failed")]
    InvalidTranscriptSignature,
    /// TOFU violation: a previously pinned LAN peer changed its public key!
    #[error("TOFU key-change conflict for peer {peer}: expected {expected:?}, got {actual:?}")]
    TofuKeyConflict {
        /// Peer identifier or host label.
        peer: String,
        /// Previously pinned Ed25519 signing key.
        expected: [u8; 32],
        /// Newly presented Ed25519 signing key.
        actual: [u8; 32],
    },
}

/// Sanitized mDNS LAN announcement modeled after SubnetDesk's `Announcement` (`src/lan_mdns.rs`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LanAnnouncement {
    /// Human-readable display name (sanitized of control characters).
    pub display_name: String,
    /// Collision-safe mDNS host label (`<name>-<short-id>.local.`).
    pub dns_label: String,
    /// Operating system platform string (`"windows"`, `"linux"`, `"macos"`).
    pub platform: String,
    /// Cryptographic [`DeviceId`] of the host.
    pub device_id: DeviceId,
    /// Listening UDP port.
    pub port: u16,
    /// Advertised LAN IP addresses.
    pub addresses: Vec<IpAddr>,
}

impl LanAnnouncement {
    /// Builds a validated [`LanAnnouncement`] for `public_identity`.
    ///
    /// # Errors
    ///
    /// Returns [`LanError::InvalidDisplayName`] if `display_name` is empty, too long,
    /// or contains control characters.
    pub fn new(
        display_name: &str,
        platform: &str,
        public_identity: &DevicePublic,
        port: u16,
        addresses: Vec<IpAddr>,
    ) -> Result<Self, LanError> {
        let trimmed = display_name.trim();
        if trimmed.is_empty()
            || trimmed.len() > MAX_DISPLAY_NAME_LEN
            || trimmed.chars().any(char::is_control)
        {
            return Err(LanError::InvalidDisplayName);
        }

        let device_id = public_identity.id();
        let id_str = device_id.to_string();
        let short_id = id_str.split('-').next().unwrap_or("node");
        let dns_label = dns_host_label(trimmed, short_id);

        Ok(Self {
            display_name: trimmed.to_owned(),
            dns_label,
            platform: platform.to_owned(),
            device_id,
            port: if port == 0 { DEFAULT_LAN_PORT } else { port },
            addresses,
        })
    }

    /// Formats the `.local.` hostname for mDNS registration.
    #[must_use]
    pub fn mdns_hostname(&self) -> String {
        format!("{}.local.", self.dns_label)
    }

    /// Returns the mDNS TXT record key-value properties.
    #[must_use]
    pub fn txt_properties(&self) -> Vec<(String, String)> {
        vec![
            ("name".to_owned(), self.display_name.clone()),
            ("platform".to_owned(), self.platform.clone()),
            ("id".to_owned(), self.device_id.to_string()),
            ("ver".to_owned(), PROTOCOL_VERSION.to_string()),
        ]
    }
}

/// Maximum length of a single DNS label in bytes (RFC 1035 §2.3.4).
pub const MAX_DNS_LABEL_LEN: usize = 63;

/// Builds the collision-safe `<slug>-<short_id>` mDNS host label, following
/// `dns_host_label` in SubnetDesk's `src/lan_mdns.rs`: the ASCII slug is lower-cased,
/// runs of non-alphanumerics collapse into a single `-`, and the slug is truncated to
/// the space left after the `-<short_id>` suffix so the whole label never exceeds
/// [`MAX_DNS_LABEL_LEN`] bytes (a 64-char display name previously produced a 69-byte label).
fn dns_host_label(display_name: &str, short_id: &str) -> String {
    let mut slug = String::with_capacity(display_name.len());
    let mut last_was_hyphen = false;
    for byte in display_name.bytes() {
        if byte.is_ascii_alphanumeric() {
            slug.push(byte.to_ascii_lowercase() as char);
            last_was_hyphen = false;
        } else if !last_was_hyphen {
            slug.push('-');
            last_was_hyphen = true;
        }
    }
    let max_slug_len = MAX_DNS_LABEL_LEN.saturating_sub(short_id.len() + 1);
    let mut prefix: String = slug.trim_matches('-').chars().take(max_slug_len).collect();
    while prefix.ends_with('-') {
        prefix.pop();
    }
    if prefix.is_empty() {
        prefix.push_str("omegadesk");
    }
    format!("{prefix}-{short_id}")
}

/// Client hello sent to initiate a serverless LAN handshake (`src/lan_protocol.rs`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LanClientHello {
    /// Wire protocol version (`PROTOCOL_VERSION`).
    pub protocol_version: u32,
    /// Fresh 24-byte random nonce chosen by the client.
    pub client_nonce: [u8; NONCE_LEN],
}

impl LanClientHello {
    /// Generates a new [`LanClientHello`] with a fresh OS CSPRNG nonce.
    #[must_use]
    pub fn generate() -> Self {
        let mut client_nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut client_nonce);
        Self {
            protocol_version: PROTOCOL_VERSION,
            client_nonce,
        }
    }
}

/// Server hello signed by the agent's [`DeviceIdentity`] over the LAN transcript,
/// modeled after SubnetDesk's `LanServerHello` (`src/lan_protocol.rs`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LanServerHello {
    /// Wire protocol version (`PROTOCOL_VERSION`).
    pub protocol_version: u32,
    /// Fresh 24-byte random nonce chosen by the server.
    pub server_nonce: [u8; NONCE_LEN],
    /// Server's 32-byte Ed25519 signing public key.
    pub signing_public_key: [u8; 32],
    /// Server's 32-byte X25519 key-exchange public key.
    pub exchange_public_key: [u8; 32],
    /// 64-byte Ed25519 signature over the canonical transcript.
    pub signature: [u8; 64],
}

/// Builds the canonical handshake transcript bytes signed by the server,
/// matching `transcript()` in SubnetDesk's `src/lan_protocol.rs`.
#[must_use]
pub fn build_lan_transcript(
    protocol_version: u32,
    client_nonce: &[u8; NONCE_LEN],
    server_nonce: &[u8; NONCE_LEN],
    exchange_public_key: &[u8; 32],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(TRANSCRIPT_PREFIX.len() + 4 + NONCE_LEN * 2 + 32);
    out.extend_from_slice(TRANSCRIPT_PREFIX);
    out.extend_from_slice(&protocol_version.to_be_bytes());
    out.extend_from_slice(client_nonce);
    out.extend_from_slice(server_nonce);
    out.extend_from_slice(exchange_public_key);
    out
}

impl LanServerHello {
    /// Responds to `client_hello` by signing the transcript with `server_identity`.
    ///
    /// # Errors
    ///
    /// Returns [`LanError::VersionMismatch`] if `client_hello.protocol_version != PROTOCOL_VERSION`.
    pub fn respond(
        client_hello: &LanClientHello,
        server_identity: &DeviceIdentity,
    ) -> Result<Self, LanError> {
        if client_hello.protocol_version != PROTOCOL_VERSION {
            return Err(LanError::VersionMismatch {
                local: PROTOCOL_VERSION,
                remote: client_hello.protocol_version,
            });
        }
        let mut server_nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut server_nonce);

        let public = server_identity.public();
        let signing_public_key = public.signing_key_bytes();
        let exchange_public_key = public.exchange_key_bytes();

        let transcript = build_lan_transcript(
            PROTOCOL_VERSION,
            &client_hello.client_nonce,
            &server_nonce,
            &exchange_public_key,
        );
        let signature = server_identity.sign(&transcript);

        Ok(Self {
            protocol_version: PROTOCOL_VERSION,
            server_nonce,
            signing_public_key,
            exchange_public_key,
            signature,
        })
    }

    /// Verifies the server's transcript signature against `client_hello` and
    /// returns the authenticated [`DevicePublic`].
    ///
    /// # Errors
    ///
    /// Returns [`LanError`] if the protocol version mismatches or signature verification fails.
    pub fn verify(&self, client_hello: &LanClientHello) -> Result<DevicePublic, LanError> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err(LanError::VersionMismatch {
                local: PROTOCOL_VERSION,
                remote: self.protocol_version,
            });
        }
        let peer_public =
            DevicePublic::from_bytes(&self.signing_public_key, &self.exchange_public_key)
                .map_err(|_: IdentityError| LanError::InvalidTranscriptSignature)?;
        let expected_transcript = build_lan_transcript(
            self.protocol_version,
            &client_hello.client_nonce,
            &self.server_nonce,
            &self.exchange_public_key,
        );
        peer_public
            .verify(&expected_transcript, &self.signature)
            .map_err(|_| LanError::InvalidTranscriptSignature)?;
        Ok(peer_public)
    }
}

/// Outcome of checking a LAN peer against the local [`TofuStore`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TofuDecision {
    /// First connection to this peer; its public key has now been pinned.
    TrustedFirstUse,
    /// Peer matches its previously pinned public key.
    TrustedPinned,
}

/// Trust On First Use (`TOFU`) pin store for serverless LAN peers.
#[derive(Debug, Default, Clone)]
pub struct TofuStore {
    by_host: HashMap<String, [u8; 32]>,
    by_device_id: HashMap<DeviceId, [u8; 32]>,
}

impl TofuStore {
    /// Creates an empty [`TofuStore`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Verifies `peer_public` for `host_label` against pinned keys, pinning it
    /// if seen for the first time or returning [`LanError::TofuKeyConflict`] if
    /// a pinned host changed its identity key (MITM protection).
    ///
    /// # Errors
    ///
    /// Returns [`LanError::TofuKeyConflict`] if `host_label` was previously
    /// pinned to a different Ed25519 key.
    pub fn verify_or_pin(
        &mut self,
        host_label: &str,
        peer_public: &DevicePublic,
    ) -> Result<TofuDecision, LanError> {
        let key_bytes = peer_public.signing_key_bytes();
        let dev_id = peer_public.id();

        if let Some(&pinned_key) = self.by_host.get(host_label) {
            if pinned_key != key_bytes {
                return Err(LanError::TofuKeyConflict {
                    peer: host_label.to_owned(),
                    expected: pinned_key,
                    actual: key_bytes,
                });
            }
            return Ok(TofuDecision::TrustedPinned);
        }

        if let Some(&pinned_key) = self.by_device_id.get(&dev_id)
            && pinned_key != key_bytes
        {
            return Err(LanError::TofuKeyConflict {
                peer: dev_id.to_string(),
                expected: pinned_key,
                actual: key_bytes,
            });
        }

        self.by_host.insert(host_label.to_owned(), key_bytes);
        self.by_device_id.insert(dev_id, key_bytes);
        Ok(TofuDecision::TrustedFirstUse)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lan_announcement_and_signed_handshake_with_tofu_pinning() {
        let host_id = DeviceIdentity::generate();
        let announcement = LanAnnouncement::new(
            "Office Workstation",
            "windows",
            &host_id.public(),
            7070,
            vec!["192.168.1.50".parse().unwrap()],
        )
        .unwrap();
        assert!(announcement.mdns_hostname().ends_with(".local."));
        assert_eq!(announcement.txt_properties().len(), 4);

        let client_hello = LanClientHello::generate();
        let server_hello = LanServerHello::respond(&client_hello, &host_id).unwrap();
        let verified_pub = server_hello.verify(&client_hello).unwrap();
        assert_eq!(verified_pub, host_id.public());

        // Tampering with the server nonce invalidates the signature
        let mut tampered = server_hello.clone();
        tampered.server_nonce[0] ^= 0xFF;
        assert_eq!(
            tampered.verify(&client_hello),
            Err(LanError::InvalidTranscriptSignature)
        );

        // TOFU pinning: first use succeeds, second use matches, MITM key change fails!
        let mut tofu = TofuStore::new();
        assert_eq!(
            tofu.verify_or_pin(&announcement.dns_label, &verified_pub)
                .unwrap(),
            TofuDecision::TrustedFirstUse
        );
        assert_eq!(
            tofu.verify_or_pin(&announcement.dns_label, &verified_pub)
                .unwrap(),
            TofuDecision::TrustedPinned
        );

        let impostor = DeviceIdentity::generate();
        assert!(matches!(
            tofu.verify_or_pin(&announcement.dns_label, &impostor.public()),
            Err(LanError::TofuKeyConflict { .. })
        ));
    }

    /// Regression for #27 `lan.rs:126`: a 64-character display name plus `-<short_id>`
    /// produced a 69-byte label; DNS labels are capped at 63 bytes.
    #[test]
    fn dns_label_never_exceeds_63_bytes_for_maximum_length_display_names() {
        let identity = DeviceIdentity::generate();
        let public = identity.public();
        let short_id = public
            .id()
            .to_string()
            .split('-')
            .next()
            .unwrap()
            .to_owned();
        let suffix = format!("-{short_id}");

        for len in [59usize, 60, 63, MAX_DISPLAY_NAME_LEN] {
            let name = "a".repeat(len);
            let announcement =
                LanAnnouncement::new(&name, "linux", &public, 0, Vec::new()).unwrap();
            assert!(
                announcement.dns_label.len() <= MAX_DNS_LABEL_LEN,
                "{len}-char name produced {}-byte label {}",
                announcement.dns_label.len(),
                announcement.dns_label
            );
            assert!(announcement.dns_label.ends_with(&suffix));
            assert!(!announcement.dns_label.starts_with('-'));
            assert!(!announcement.dns_label.contains("--"));
            assert!(
                announcement.dns_label.len() > suffix.len(),
                "slug must not be truncated to nothing"
            );
        }

        // Truncation must not leave a dangling hyphen before the suffix, and runs of
        // separators collapse into one (`dns_host_label` in SubnetDesk `src/lan_mdns.rs`).
        let spaced = format!("{} Workstation!!  Lab", "x".repeat(40));
        let announcement =
            LanAnnouncement::new(&spaced, "windows", &public, 0, Vec::new()).unwrap();
        assert!(announcement.dns_label.len() <= MAX_DNS_LABEL_LEN);
        assert!(!announcement.dns_label.contains("--"));
        assert!(announcement.dns_label.ends_with(&suffix));
        assert!(
            !announcement
                .dns_label
                .trim_end_matches(&suffix)
                .ends_with('-')
        );
    }
}
