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
}
