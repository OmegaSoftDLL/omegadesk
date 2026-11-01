//! Authenticated envelope credential vault (`PBKDF2-HMAC-SHA256` + `ChaCha20-Poly1305` `KEK`/`DEK`).
//!
//! Reference implementations and security improvements:
//! - `FreeRDP_Remmina/src/remmina_crypt.c` (lines 47–160): Remmina's credential encryption hooks
//!   (`remmina_crypt_init`, `remmina_crypt_encrypt`, `remmina_crypt_decrypt`), upgraded from
//!   legacy `GCRY_CIPHER_3DES` in `CBC` mode to authenticated 256-bit `ChaCha20-Poly1305` AEAD.
//! - `1Remote_1Remote/Ui/Utils/UnSafeStringEncipher.cs` (lines 6–39): replaces `1Remote`'s
//!   static-salt `UnSafeStringEncipher` with per-vault random 128-bit salts, `PBKDF2-HMAC-SHA256`
//!   (`100_000` iterations) Key Encryption Keys (`KEK`), and unique per-item 256-bit Data
//!   Encryption Keys (`DEK`) wrapped under AEAD with `zeroize` on drop (`docs/plan.md` §2.11).

use std::collections::HashMap;
use std::num::NonZeroU32;

use rand_core::{OsRng, RngCore};
use ring::{aead, pbkdf2};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Length in bytes of 256-bit `KEK` and `DEK` keys.
pub const VAULT_KEY_LEN: usize = 32;

/// Default `PBKDF2-HMAC-SHA256` iteration count (`100_000` iterations).
pub const PBKDF2_ITERATIONS: u32 = 100_000;

/// Vault encryption or decryption errors.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum VaultError {
    /// AEAD authentication tag verification failed (wrong `KEK`, tampered `DEK`, or tampered ciphertext).
    #[error("vault AEAD authentication failed")]
    AuthenticationFailed,
    /// Requested credential identifier does not exist in the vault.
    #[error("credential entry not found: {0}")]
    EntryNotFound(String),
}

/// Derives a 256-bit Key Encryption Key (`KEK`) from `kdf_input` and `salt` using
/// `PBKDF2-HMAC-SHA256` with [`PBKDF2_ITERATIONS`] rounds.
#[must_use]
pub fn derive_master_kek(kdf_input: &[u8], salt: &[u8; 16]) -> Zeroizing<[u8; VAULT_KEY_LEN]> {
    let mut kek = Zeroizing::new([0u8; VAULT_KEY_LEN]);
    let iterations = NonZeroU32::new(PBKDF2_ITERATIONS).unwrap_or(NonZeroU32::MIN);
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        iterations,
        salt,
        kdf_input,
        kek.as_mut(),
    );
    kek
}

/// Sealed credential entry storing a wrapped per-item 256-bit `DEK` and the `DEK`-encrypted payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvelopeRecord {
    /// Entry identifier (bound into AEAD Additional Authenticated Data).
    pub entry_id: String,
    /// 96-bit nonce used to wrap the per-entry `DEK` under the vault `KEK`.
    pub dek_wrap_nonce: [u8; 12],
    /// Wrapped 256-bit `DEK` + 128-bit `ChaCha20-Poly1305` authentication tag (`48` bytes).
    pub wrapped_dek: Vec<u8>,
    /// 96-bit nonce used to encrypt the credential payload under the per-entry `DEK`.
    pub payload_nonce: [u8; 12],
    /// Encrypted credential payload + 128-bit authentication tag.
    pub ciphertext: Vec<u8>,
}

/// Authenticated envelope credential vault (`KEK` wrapping per-entry `DEK`s, `docs/plan.md` §2.11).
#[derive(ZeroizeOnDrop)]
pub struct CredentialVault {
    salt: [u8; 16],
    kek: [u8; VAULT_KEY_LEN],
    #[zeroize(skip)]
    entries: HashMap<String, EnvelopeRecord>,
}

impl CredentialVault {
    /// Creates a new vault initialized with a random 128-bit salt and derives the master `KEK`
    /// from `kdf_input`.
    #[must_use]
    pub fn new(kdf_input: &[u8]) -> Self {
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);
        let kek = derive_master_kek(kdf_input, &salt);
        Self {
            salt,
            kek: *kek,
            entries: HashMap::new(),
        }
    }

    /// Reconstructs a vault from an existing `salt` and `kdf_input`.
    #[must_use]
    pub fn from_salt(kdf_input: &[u8], salt: [u8; 16]) -> Self {
        let kek = derive_master_kek(kdf_input, &salt);
        Self {
            salt,
            kek: *kek,
            entries: HashMap::new(),
        }
    }

    /// Returns the 128-bit KDF salt for this vault.
    #[must_use]
    pub const fn salt(&self) -> &[u8; 16] {
        &self.salt
    }

    /// Generates a fresh 256-bit random `DEK` via `OsRng`, encrypts `plaintext` with that `DEK`,
    /// wraps the `DEK` under the vault's master `KEK`, and stores the resulting [`EnvelopeRecord`].
    ///
    /// # Errors
    ///
    /// Returns [`VaultError::AuthenticationFailed`] if the underlying AEAD primitive fails.
    pub fn seal_entry(
        &mut self,
        entry_id: impl Into<String>,
        plaintext: &[u8],
    ) -> Result<EnvelopeRecord, VaultError> {
        let id = entry_id.into();
        let mut dek = Zeroizing::new([0u8; VAULT_KEY_LEN]);
        OsRng.fill_bytes(dek.as_mut());

        let mut payload_nonce = [0u8; 12];
        OsRng.fill_bytes(&mut payload_nonce);
        let ciphertext = aead_seal(&dek, &payload_nonce, id.as_bytes(), plaintext)?;

        let mut dek_wrap_nonce = [0u8; 12];
        OsRng.fill_bytes(&mut dek_wrap_nonce);
        let wrapped_dek = aead_seal(&self.kek, &dek_wrap_nonce, id.as_bytes(), dek.as_ref())?;

        let record = EnvelopeRecord {
            entry_id: id.clone(),
            dek_wrap_nonce,
            wrapped_dek,
            payload_nonce,
            ciphertext,
        };
        self.entries.insert(id, record.clone());
        Ok(record)
    }

    /// Unwraps the entry's `DEK` using the vault's master `KEK` and decrypts the credential
    /// into a [`Zeroizing<Vec<u8>>`] buffer.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError::EntryNotFound`] if `entry_id` is absent or
    /// [`VaultError::AuthenticationFailed`] if AEAD verification fails.
    pub fn open_entry(&self, entry_id: &str) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        let record = self
            .entries
            .get(entry_id)
            .ok_or_else(|| VaultError::EntryNotFound(entry_id.to_owned()))?;
        self.open_record(record)
    }

    /// Decrypts an [`EnvelopeRecord`] directly using this vault's master `KEK`.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError::AuthenticationFailed`] if the `KEK`, `DEK`, or AAD does not match.
    pub fn open_record(&self, record: &EnvelopeRecord) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        let mut unwrapped_dek = aead_open(
            &self.kek,
            &record.dek_wrap_nonce,
            record.entry_id.as_bytes(),
            &record.wrapped_dek,
        )?;
        if unwrapped_dek.len() != VAULT_KEY_LEN {
            unwrapped_dek.zeroize();
            return Err(VaultError::AuthenticationFailed);
        }
        let mut dek_array = Zeroizing::new([0u8; VAULT_KEY_LEN]);
        dek_array.copy_from_slice(&unwrapped_dek);
        unwrapped_dek.zeroize();

        aead_open(
            &dek_array,
            &record.payload_nonce,
            record.entry_id.as_bytes(),
            &record.ciphertext,
        )
    }
}

fn aead_seal(
    key_bytes: &[u8; VAULT_KEY_LEN],
    nonce_bytes: &[u8; 12],
    aad_bytes: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, VaultError> {
    let unbound = aead::UnboundKey::new(&aead::CHACHA20_POLY1305, key_bytes)
        .map_err(|_| VaultError::AuthenticationFailed)?;
    let key = aead::LessSafeKey::new(unbound);
    let nonce = aead::Nonce::assume_unique_for_key(*nonce_bytes);
    let mut in_out = plaintext.to_vec();
    key.seal_in_place_append_tag(nonce, aead::Aad::from(aad_bytes), &mut in_out)
        .map_err(|_| VaultError::AuthenticationFailed)?;
    Ok(in_out)
}

fn aead_open(
    key_bytes: &[u8; VAULT_KEY_LEN],
    nonce_bytes: &[u8; 12],
    aad_bytes: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    let unbound = aead::UnboundKey::new(&aead::CHACHA20_POLY1305, key_bytes)
        .map_err(|_| VaultError::AuthenticationFailed)?;
    let key = aead::LessSafeKey::new(unbound);
    let nonce = aead::Nonce::assume_unique_for_key(*nonce_bytes);
    let mut buf = Zeroizing::new(ciphertext.to_vec());
    let decrypted_len = key
        .open_in_place(nonce, aead::Aad::from(aad_bytes), buf.as_mut())
        .map_err(|_| VaultError::AuthenticationFailed)?
        .len();
    buf.truncate(decrypted_len);
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_vault_seals_and_opens_with_per_entry_dek() {
        let mut kdf_material = [0u8; 32];
        OsRng.fill_bytes(&mut kdf_material);

        let mut vault = CredentialVault::new(&kdf_material);
        let payload = b"ssh-ed25519-private-material";

        let rec1 = vault.seal_entry("host-prod-1", payload);
        let rec2 = vault.seal_entry("host-prod-1", payload);
        assert!(rec1.is_ok() && rec2.is_ok());
        // Different random DEKs and nonces produce distinct ciphertexts for identical plaintexts.
        let r1 = rec1.unwrap_or_else(|_| unreachable!());
        let r2 = rec2.unwrap_or_else(|_| unreachable!());
        assert_ne!(r1.wrapped_dek, r2.wrapped_dek);

        let opened = vault.open_entry("host-prod-1");
        assert!(opened.is_ok());
        assert_eq!(
            opened.unwrap_or_else(|_| unreachable!()).as_slice(),
            payload
        );

        let mut wrong_kdf = [0u8; 32];
        OsRng.fill_bytes(&mut wrong_kdf);
        let other_vault = CredentialVault::from_salt(&wrong_kdf, *vault.salt());
        assert_eq!(
            other_vault.open_record(&r2),
            Err(VaultError::AuthenticationFailed)
        );
    }
}
