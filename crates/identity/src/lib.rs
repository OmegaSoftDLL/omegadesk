//! Cryptographic identity of an OmegaDesk device.
//!
//! Each device holds two locally generated keypairs whose private keys never
//! leave the machine:
//!
//! - **signing** (`ed25519`): proves device identity and signs netmaps, relay
//!   tickets, and handshake transcripts;
//! - **key exchange** (`x25519`): used by the WireGuard mesh and the Noise
//!   control channel.
//!
//! [`DeviceId`] is derived from the signing public key, so it cannot be forged
//! without possessing the corresponding private key.

mod store;
pub mod vault;

use std::fmt;

use ed25519_dalek::pkcs8::EncodePrivateKey;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as ExchangePublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub use store::{FileStore, KeyStore, KeyringStore, MemoryStore, StoreError, default_store};
pub use vault::{
    CredentialVault, EnvelopeRecord, PBKDF2_ITERATIONS, VAULT_KEY_LEN, VaultError,
    derive_master_kek,
};

/// Length of serialized secret key material: 32 signing bytes + 32 exchange bytes.
const SECRET_LEN: usize = 64;

/// Version byte prefixing serialized secret key material to support future migrations.
const SECRET_FORMAT_VERSION: u8 = 1;

/// Identity errors.
#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    /// Serialized secret bytes do not match the expected format.
    #[error("invalid serialized device identity")]
    InvalidEncoding,
    /// The public key is not a valid Ed25519 curve point.
    #[error("invalid public key")]
    InvalidPublicKey,
    /// Signature verification failed.
    #[error("invalid signature")]
    InvalidSignature,
    /// Node key certificate has expired and must be rotated.
    #[error("node key expired at {0} unix secs")]
    NodeKeyExpired(u64),
    /// Zero-knowledge unattended access proof failed verification.
    #[error("unattended access verifier rejected client proof")]
    InvalidUnattendedProof,
}

/// Tailscale `badOldPrefix` (`[109, 167, 116, 213, 215, 116]`) that base64-encodes to
/// `[bad01]` ("bad ol'") to make expired node keys immediately recognizable in logs
/// (`tailscale_tailscale/types/key/node.go` lines 224–239).
pub const BAD_OLD_NODE_KEY_PREFIX: [u8; 6] = [109, 167, 116, 213, 215, 116];

/// Returns a copy of `node_public` with its leading 6 bytes replaced by
/// [`BAD_OLD_NODE_KEY_PREFIX`] (`NodePublicWithBadOldPrefix` in `node.go` lines 234–239).
#[must_use]
pub const fn mark_node_key_expired_prefix(mut node_public: [u8; 32]) -> [u8; 32] {
    node_public[0] = BAD_OLD_NODE_KEY_PREFIX[0];
    node_public[1] = BAD_OLD_NODE_KEY_PREFIX[1];
    node_public[2] = BAD_OLD_NODE_KEY_PREFIX[2];
    node_public[3] = BAD_OLD_NODE_KEY_PREFIX[3];
    node_public[4] = BAD_OLD_NODE_KEY_PREFIX[4];
    node_public[5] = BAD_OLD_NODE_KEY_PREFIX[5];
    node_public
}

/// Rotating node key certificate signed by a device's persistent [`DeviceIdentity`]
/// (machine key), modeled after Tailscale's machine key + rotating node key architecture
/// (`tailscale_tailscale/types/key/node.go`, `docs/plan.md` §2.10 line 151 & §3 line 204).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeKeyCertificate {
    /// Persistent machine public identity that signed this node key.
    pub machine_public: DevicePublic,
    /// Ephemeral/rotating X25519 node public key (`nodekey:<hex>`).
    pub node_exchange_public: [u8; 32],
    /// Monotonic rotation sequence number (`1, 2, ...`).
    pub sequence: u64,
    /// Issuance timestamp in seconds since the Unix epoch.
    pub issued_at_unix_secs: u64,
    /// Expiration timestamp in seconds since the Unix epoch.
    pub expires_at_unix_secs: u64,
    /// Ed25519 signature by `machine_public` over the canonical rotation transcript.
    pub signature: [u8; 64],
}

impl NodeKeyCertificate {
    fn transcript(
        machine_id: DeviceId,
        node_exchange_public: &[u8; 32],
        sequence: u64,
        issued_at_unix_secs: u64,
        expires_at_unix_secs: u64,
    ) -> [u8; 32] {
        let digest = Sha256::new()
            .chain_update(b"omegadesk-node-key-rot-v1")
            .chain_update(machine_id.as_bytes())
            .chain_update(node_exchange_public)
            .chain_update(sequence.to_be_bytes())
            .chain_update(issued_at_unix_secs.to_be_bytes())
            .chain_update(expires_at_unix_secs.to_be_bytes())
            .finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        out
    }

    /// Issues and signs a fresh rotating X25519 node key bound to `machine_identity`.
    #[must_use]
    pub fn issue(
        machine_identity: &DeviceIdentity,
        sequence: u64,
        issued_at_unix_secs: u64,
        expires_at_unix_secs: u64,
    ) -> (StaticSecret, Self) {
        let node_secret = StaticSecret::random_from_rng(OsRng);
        let node_exchange_public = ExchangePublicKey::from(&node_secret).to_bytes();
        let machine_public = machine_identity.public();
        let transcript = Self::transcript(
            machine_public.id(),
            &node_exchange_public,
            sequence,
            issued_at_unix_secs,
            expires_at_unix_secs,
        );
        let signature = machine_identity.sign(&transcript);
        (
            node_secret,
            Self {
                machine_public,
                node_exchange_public,
                sequence,
                issued_at_unix_secs,
                expires_at_unix_secs,
                signature,
            },
        )
    }

    /// Verifies the machine-key signature and checks that `now_unix_secs < self.expires_at_unix_secs`.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::NodeKeyExpired`] if the node key has expired, or
    /// [`IdentityError::InvalidSignature`] if the machine key signature is invalid.
    pub fn verify(&self, now_unix_secs: u64) -> Result<(), IdentityError> {
        if now_unix_secs >= self.expires_at_unix_secs {
            return Err(IdentityError::NodeKeyExpired(self.expires_at_unix_secs));
        }
        let transcript = Self::transcript(
            self.machine_public.id(),
            &self.node_exchange_public,
            self.sequence,
            self.issued_at_unix_secs,
            self.expires_at_unix_secs,
        );
        self.machine_public.verify(&transcript, &self.signature)
    }
}

/// Zero-knowledge unattended access verifier where the credential never crosses the wire
/// in plaintext, modeled after Aspia's SRP verifier architecture
/// (`dchapyshev_aspia/source/base/crypto/srp_math.cc` lines 394–418 & 660–730,
/// `docs/plan.md` §2.10 line 150).
///
/// The agent stores only `(salt, verifier_public_key)` derived from
/// `PBKDF2-HMAC-SHA256(salt, identity_lower || ":" || kdf_input)` as an Ed25519
/// verifying key. During connection setup, the client proves possession of `kdf_input`
/// by signing the session challenge transcript `(server_nonce, client_nonce, host_id)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnattendedVerifier {
    /// 16-byte random salt (`s` in `SrpMath::calc_x`).
    pub salt: [u8; 16],
    /// Derived Ed25519 verifier public key (`v = g^x` equivalent).
    pub verifier_public: [u8; 32],
}

impl UnattendedVerifier {
    fn derive_signing_key(salt: &[u8; 16], account_id: &str, kdf_input: &[u8]) -> SigningKey {
        // Mirrors Aspia's `SrpMath::calc_x`: hash `lower(I) || ":" || p` with `salt` via PBKDF2.
        let mut inner = Sha256::new();
        inner.update(account_id.to_ascii_lowercase().as_bytes());
        inner.update(b":");
        inner.update(kdf_input);
        let inner_digest = inner.finalize();

        let seed = crate::vault::derive_master_kek(&inner_digest, salt);
        SigningKey::from_bytes(&seed)
    }

    /// Enrolls a new unattended access verifier on the agent from `account_id` and `kdf_input`.
    /// Only the salt and public verifier point are retained on disk.
    #[must_use]
    pub fn enroll(salt: [u8; 16], account_id: &str, kdf_input: &[u8]) -> Self {
        let signing = Self::derive_signing_key(&salt, account_id, kdf_input);
        Self {
            salt,
            verifier_public: signing.verifying_key().to_bytes(),
        }
    }

    /// Computes a client-side zero-knowledge proof over `(host_id, server_challenge, client_nonce)`
    /// without transmitting `kdf_input` over the network.
    #[must_use]
    pub fn prove_client(
        salt: &[u8; 16],
        account_id: &str,
        kdf_input: &[u8],
        host_id: DeviceId,
        server_challenge: &[u8; 32],
        client_nonce: &[u8; 32],
    ) -> [u8; 64] {
        let signing = Self::derive_signing_key(salt, account_id, kdf_input);
        let transcript = Self::challenge_transcript(host_id, server_challenge, client_nonce);
        signing.sign(&transcript).to_bytes()
    }

    /// Verifies the client's zero-knowledge proof on the agent using only `self.verifier_public`.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::InvalidUnattendedProof`] if the proof is invalid.
    pub fn verify_client_proof(
        &self,
        host_id: DeviceId,
        server_challenge: &[u8; 32],
        client_nonce: &[u8; 32],
        proof_signature: &[u8; 64],
    ) -> Result<(), IdentityError> {
        let verifying = VerifyingKey::from_bytes(&self.verifier_public)
            .map_err(|_| IdentityError::InvalidUnattendedProof)?;
        let transcript = Self::challenge_transcript(host_id, server_challenge, client_nonce);
        let sig = Signature::from_bytes(proof_signature);
        verifying
            .verify_strict(&transcript, &sig)
            .map_err(|_| IdentityError::InvalidUnattendedProof)
    }

    fn challenge_transcript(
        host_id: DeviceId,
        server_challenge: &[u8; 32],
        client_nonce: &[u8; 32],
    ) -> [u8; 32] {
        let digest = Sha256::new()
            .chain_update(b"omegadesk-unattended-zkp-v1")
            .chain_update(host_id.as_bytes())
            .chain_update(server_challenge)
            .chain_update(client_nonce)
            .finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        out
    }
}

/// Complete device identity, including private keys.
#[derive(ZeroizeOnDrop)]
pub struct DeviceIdentity {
    signing: SigningKey,
    exchange: StaticSecret,
}

impl DeviceIdentity {
    /// Generates a fresh device identity using the operating system CSPRNG.
    #[must_use]
    pub fn generate() -> Self {
        Self {
            signing: SigningKey::generate(&mut OsRng),
            exchange: StaticSecret::random_from_rng(OsRng),
        }
    }

    /// Returns the public half of this identity, suitable for sharing with peers.
    #[must_use]
    pub fn public(&self) -> DevicePublic {
        DevicePublic {
            signing: self.signing.verifying_key(),
            exchange: ExchangePublicKey::from(&self.exchange),
        }
    }

    /// Stable identifier of this device.
    #[must_use]
    pub fn id(&self) -> DeviceId {
        self.public().id()
    }

    /// Signs a message with the device's Ed25519 signing key.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing.sign(message).to_bytes()
    }

    /// X25519 key-exchange secret used for WireGuard and Noise.
    #[must_use]
    pub fn exchange_secret(&self) -> &StaticSecret {
        &self.exchange
    }

    /// Ed25519 signing key as PKCS#8 v1 DER (RFC 8410), for TLS stacks that
    /// derive the node's certificate from its identity. Empty on encoding failure,
    /// which cannot happen for a valid key.
    #[must_use]
    pub fn signing_key_pkcs8_der(&self) -> Zeroizing<Vec<u8>> {
        self.signing.to_pkcs8_der().map_or_else(
            |_| Zeroizing::new(Vec::new()),
            |doc| Zeroizing::new(doc.as_bytes().to_vec()),
        )
    }

    /// Serializes private keys for storage in a [`KeyStore`].
    #[must_use]
    pub fn to_secret_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut bytes = Zeroizing::new(Vec::with_capacity(1 + SECRET_LEN));
        bytes.push(SECRET_FORMAT_VERSION);
        bytes.extend_from_slice(self.signing.as_bytes());
        bytes.extend_from_slice(self.exchange.as_bytes());
        bytes
    }

    /// Reconstructs a device identity from [`to_secret_bytes`](Self::to_secret_bytes).
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::InvalidEncoding`] if the version or length is unrecognized.
    pub fn from_secret_bytes(bytes: &[u8]) -> Result<Self, IdentityError> {
        let Some((&version, keys)) = bytes.split_first() else {
            return Err(IdentityError::InvalidEncoding);
        };
        if version != SECRET_FORMAT_VERSION || keys.len() != SECRET_LEN {
            return Err(IdentityError::InvalidEncoding);
        }
        let (signing_bytes, exchange_bytes) = keys.split_at(32);

        let mut signing = [0u8; 32];
        signing.copy_from_slice(signing_bytes);
        let mut exchange = [0u8; 32];
        exchange.copy_from_slice(exchange_bytes);

        let identity = Self {
            signing: SigningKey::from_bytes(&signing),
            exchange: StaticSecret::from(exchange),
        };
        signing.zeroize();
        exchange.zeroize();
        Ok(identity)
    }

    /// Loads an existing identity from `store`, or generates and persists a new one.
    ///
    /// # Errors
    ///
    /// Returns an error if the store fails or if existing stored bytes are
    /// corrupted (in which case nothing is overwritten).
    pub fn load_or_create(store: &dyn KeyStore) -> Result<Self, StoreError> {
        if let Some(secret) = store.load()? {
            return Ok(Self::from_secret_bytes(&secret)?);
        }
        let identity = Self::generate();
        store.save(&identity.to_secret_bytes())?;
        Ok(identity)
    }
}

impl fmt::Debug for DeviceIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceIdentity")
            .field("id", &self.id())
            .finish_non_exhaustive()
    }
}

/// Public half of a device identity.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct DevicePublic {
    signing: VerifyingKey,
    exchange: ExchangePublicKey,
}

impl DevicePublic {
    /// Builds a public identity from raw key bytes received from a peer.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::InvalidPublicKey`] if `signing` is not a valid
    /// Ed25519 public key.
    pub fn from_bytes(signing: &[u8; 32], exchange: &[u8; 32]) -> Result<Self, IdentityError> {
        Ok(Self {
            signing: VerifyingKey::from_bytes(signing)
                .map_err(|_| IdentityError::InvalidPublicKey)?,
            exchange: ExchangePublicKey::from(*exchange),
        })
    }

    /// Ed25519 signing public key bytes.
    #[must_use]
    pub fn signing_key_bytes(&self) -> [u8; 32] {
        self.signing.to_bytes()
    }

    /// X25519 key-exchange public key bytes.
    #[must_use]
    pub fn exchange_key_bytes(&self) -> [u8; 32] {
        self.exchange.to_bytes()
    }

    /// Stable identifier of this device.
    #[must_use]
    pub fn id(&self) -> DeviceId {
        DeviceId::from_signing_key(&self.signing.to_bytes())
    }

    /// Verifies a signature produced by this device.
    ///
    /// Uses strict Ed25519 verification, rejecting malleable signatures and
    /// small-order public keys.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::InvalidSignature`] if verification fails.
    pub fn verify(&self, message: &[u8], signature: &[u8; 64]) -> Result<(), IdentityError> {
        let signature = Signature::from_bytes(signature);
        self.signing
            .verify_strict(message, &signature)
            .map_err(|_| IdentityError::InvalidSignature)
    }
}

impl fmt::Debug for DevicePublic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DevicePublic")
            .field("id", &self.id())
            .finish_non_exhaustive()
    }
}

/// Device identifier: the first 20 bytes of the SHA-256 digest of the signing
/// public key, formatted in lowercase base32 in 4-character groups for human
/// readability.
///
/// Example: `k3xq-7f2m-…` (32 characters across 8 groups).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DeviceId([u8; 20]);

impl DeviceId {
    /// Derives the device identifier from an Ed25519 signing public key.
    #[must_use]
    pub fn from_signing_key(signing_key: &[u8; 32]) -> Self {
        let digest = Sha256::new()
            .chain_update(b"omegadesk-device-id-v1")
            .chain_update(signing_key)
            .finalize();
        let mut id = [0u8; 20];
        id.copy_from_slice(&digest[..20]);
        Self(id)
    }

    /// Raw 20-byte identifier.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }
}

impl fmt::Display for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let encoded = data_encoding::BASE32_NOPAD.encode(&self.0).to_lowercase();
        let groups: Vec<&str> = encoded
            .as_bytes()
            .chunks(4)
            .filter_map(|chunk| std::str::from_utf8(chunk).ok())
            .collect();
        f.write_str(&groups.join("-"))
    }
}

impl fmt::Debug for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DeviceId({self})")
    }
}

#[cfg(test)]
mod tests {
    use super::{DeviceIdentity, DevicePublic, IdentityError, MemoryStore};

    #[test]
    fn sign_and_verify() {
        let identity = DeviceIdentity::generate();
        let signature = identity.sign(b"netmap v1");
        let public = identity.public();
        public.verify(b"netmap v1", &signature).unwrap();
        assert!(matches!(
            public.verify(b"netmap v2", &signature),
            Err(IdentityError::InvalidSignature)
        ));
    }

    #[test]
    fn secret_round_trip_keeps_identity() {
        let identity = DeviceIdentity::generate();
        let restored = DeviceIdentity::from_secret_bytes(&identity.to_secret_bytes()).unwrap();
        assert_eq!(identity.public(), restored.public());
        assert_eq!(identity.id(), restored.id());
    }

    #[test]
    fn rejects_bad_secret_encoding() {
        assert!(DeviceIdentity::from_secret_bytes(&[]).is_err());
        assert!(DeviceIdentity::from_secret_bytes(&[1; 10]).is_err());
        let mut wrong_version = DeviceIdentity::generate().to_secret_bytes();
        wrong_version[0] = 99;
        assert!(DeviceIdentity::from_secret_bytes(&wrong_version).is_err());
    }

    #[test]
    fn public_round_trip() {
        let public = DeviceIdentity::generate().public();
        let restored =
            DevicePublic::from_bytes(&public.signing_key_bytes(), &public.exchange_key_bytes())
                .unwrap();
        assert_eq!(public, restored);
    }

    #[test]
    fn device_id_format() {
        let id = DeviceIdentity::generate().id().to_string();
        assert_eq!(id.len(), 32 + 7);
        assert_eq!(id.split('-').count(), 8);
        assert!(
            id.chars()
                .all(|c| c == '-' || c.is_ascii_lowercase() || c.is_ascii_digit())
        );
    }

    #[test]
    fn different_devices_have_different_ids() {
        assert_ne!(
            DeviceIdentity::generate().id(),
            DeviceIdentity::generate().id()
        );
    }

    #[test]
    fn load_or_create_is_stable() {
        let store = MemoryStore::default();
        let first = DeviceIdentity::load_or_create(&store).unwrap();
        let second = DeviceIdentity::load_or_create(&store).unwrap();
        assert_eq!(first.id(), second.id());
    }

    #[test]
    fn machine_key_rotates_node_key_with_expiry_and_unattended_zkp_verifier() {
        use super::{
            BAD_OLD_NODE_KEY_PREFIX, NodeKeyCertificate, UnattendedVerifier,
            mark_node_key_expired_prefix,
        };

        let machine = DeviceIdentity::generate();
        let (_node_secret, cert) = NodeKeyCertificate::issue(&machine, 1, 1_000, 2_000);
        assert!(cert.verify(1_500).is_ok());
        assert!(cert.verify(2_000).is_err());

        let marked = mark_node_key_expired_prefix(cert.node_exchange_public);
        assert_eq!(&marked[..6], &BAD_OLD_NODE_KEY_PREFIX);

        // Zero-knowledge unattended access proof: credential never crosses the wire
        let salt = [0x11u8; 16];
        let kdf_input = b"unattended-host-access-material";
        let verifier = UnattendedVerifier::enroll(salt, "AdminUser", kdf_input);
        let server_challenge = [0xAAu8; 32];
        let client_nonce = [0xBBu8; 32];

        let proof = UnattendedVerifier::prove_client(
            &verifier.salt,
            "adminuser",
            kdf_input,
            machine.id(),
            &server_challenge,
            &client_nonce,
        );
        assert!(
            verifier
                .verify_client_proof(machine.id(), &server_challenge, &client_nonce, &proof)
                .is_ok()
        );

        let wrong_proof = UnattendedVerifier::prove_client(
            &verifier.salt,
            "adminuser",
            b"wrong-material",
            machine.id(),
            &server_challenge,
            &client_nonce,
        );
        assert!(
            verifier
                .verify_client_proof(machine.id(), &server_challenge, &client_nonce, &wrong_proof)
                .is_err()
        );
    }
}
