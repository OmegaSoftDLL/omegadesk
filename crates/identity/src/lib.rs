//! Identidade criptográfica de um dispositivo OmegaDesk.
//!
//! Cada dispositivo tem dois pares de chaves gerados localmente, que nunca
//! saem da máquina:
//!
//! - **assinatura** (ed25519): prova quem é o dispositivo e assina o netmap,
//!   os tickets de relay e a transcrição do handshake;
//! - **troca de chaves** (x25519): usada pelo WireGuard da malha e pelo canal
//!   de controle Noise.
//!
//! O [`DeviceId`] é derivado da chave de assinatura, então não pode ser
//! forjado sem a chave privada.

mod store;

use std::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as ExchangePublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub use store::{FileStore, KeyStore, KeyringStore, MemoryStore, StoreError, default_store};

/// Tamanho do segredo serializado: 32 bytes de assinatura + 32 de troca.
const SECRET_LEN: usize = 64;

/// Versão do formato serializado, para permitir migrações futuras.
const SECRET_FORMAT_VERSION: u8 = 1;

/// Erros de identidade.
#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    /// Os bytes serializados não têm o formato esperado.
    #[error("identidade serializada inválida")]
    InvalidEncoding,
    /// A chave pública não é um ponto ed25519 válido.
    #[error("chave pública inválida")]
    InvalidPublicKey,
    /// A assinatura não confere.
    #[error("assinatura inválida")]
    InvalidSignature,
}

/// Identidade completa do dispositivo, com as chaves privadas.
#[derive(ZeroizeOnDrop)]
pub struct DeviceIdentity {
    signing: SigningKey,
    exchange: StaticSecret,
}

impl DeviceIdentity {
    /// Gera uma identidade nova com o gerador aleatório do sistema.
    #[must_use]
    pub fn generate() -> Self {
        Self {
            signing: SigningKey::generate(&mut OsRng),
            exchange: StaticSecret::random_from_rng(OsRng),
        }
    }

    /// Parte pública, que pode ser enviada ao servidor e a outros peers.
    #[must_use]
    pub fn public(&self) -> DevicePublic {
        DevicePublic {
            signing: self.signing.verifying_key(),
            exchange: ExchangePublicKey::from(&self.exchange),
        }
    }

    /// Identificador estável do dispositivo.
    #[must_use]
    pub fn id(&self) -> DeviceId {
        self.public().id()
    }

    /// Assina uma mensagem com a chave de assinatura do dispositivo.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing.sign(message).to_bytes()
    }

    /// Segredo de troca de chaves x25519, para o WireGuard e o Noise.
    #[must_use]
    pub fn exchange_secret(&self) -> &StaticSecret {
        &self.exchange
    }

    /// Serializa as chaves privadas para guardar num [`KeyStore`].
    #[must_use]
    pub fn to_secret_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut bytes = Zeroizing::new(Vec::with_capacity(1 + SECRET_LEN));
        bytes.push(SECRET_FORMAT_VERSION);
        bytes.extend_from_slice(self.signing.as_bytes());
        bytes.extend_from_slice(self.exchange.as_bytes());
        bytes
    }

    /// Reconstrói a identidade a partir de [`to_secret_bytes`](Self::to_secret_bytes).
    ///
    /// # Errors
    ///
    /// Retorna [`IdentityError::InvalidEncoding`] se o formato não for reconhecido.
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

    /// Carrega a identidade guardada ou gera e guarda uma nova.
    ///
    /// # Errors
    ///
    /// Retorna erro se o armazenamento falhar ou se o conteúdo guardado
    /// estiver corrompido. Nesse caso nada é sobrescrito.
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

/// Parte pública da identidade de um dispositivo.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct DevicePublic {
    signing: VerifyingKey,
    exchange: ExchangePublicKey,
}

impl DevicePublic {
    /// Monta a identidade pública a partir das chaves recebidas de um peer.
    ///
    /// # Errors
    ///
    /// Retorna [`IdentityError::InvalidPublicKey`] se a chave de assinatura
    /// não for um ponto ed25519 válido.
    pub fn from_bytes(signing: &[u8; 32], exchange: &[u8; 32]) -> Result<Self, IdentityError> {
        Ok(Self {
            signing: VerifyingKey::from_bytes(signing)
                .map_err(|_| IdentityError::InvalidPublicKey)?,
            exchange: ExchangePublicKey::from(*exchange),
        })
    }

    /// Chave pública de assinatura (ed25519).
    #[must_use]
    pub fn signing_key_bytes(&self) -> [u8; 32] {
        self.signing.to_bytes()
    }

    /// Chave pública de troca de chaves (x25519).
    #[must_use]
    pub fn exchange_key_bytes(&self) -> [u8; 32] {
        self.exchange.to_bytes()
    }

    /// Identificador estável do dispositivo.
    #[must_use]
    pub fn id(&self) -> DeviceId {
        DeviceId::from_signing_key(&self.signing.to_bytes())
    }

    /// Confere uma assinatura feita por este dispositivo.
    ///
    /// Usa a verificação estrita do ed25519, que rejeita assinaturas
    /// maleáveis e chaves de ordem baixa.
    ///
    /// # Errors
    ///
    /// Retorna [`IdentityError::InvalidSignature`] se a assinatura não conferir.
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

/// Identificador do dispositivo: os primeiros 20 bytes do SHA-256 da chave de
/// assinatura, em base32 minúsculo, agrupado de 4 em 4 para leitura humana.
///
/// Exemplo: `k3xq-7f2m-…` (32 caracteres em 8 grupos).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DeviceId([u8; 20]);

impl DeviceId {
    /// Deriva o identificador de uma chave pública de assinatura.
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

    /// Bytes brutos do identificador.
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
