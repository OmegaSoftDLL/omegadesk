//! Storage backends for private device keys.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use zeroize::Zeroizing;

use crate::IdentityError;

/// Key storage errors.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// The operating system credential store rejected or failed the operation.
    #[error("system credential store: {0}")]
    Keyring(#[from] keyring::Error),
    /// Failed to read or write the key file on disk.
    #[error("key file: {0}")]
    Io(#[from] std::io::Error),
    /// Stored bytes do not represent a valid device identity.
    #[error(transparent)]
    Identity(#[from] IdentityError),
    /// In-memory store mutex was poisoned by a panicking thread.
    #[error("in-memory store mutex poisoned")]
    Poisoned,
}

/// Persistent or ephemeral storage backend for private device keys.
pub trait KeyStore {
    /// Loads the stored secret, or returns `None` if no secret has been stored yet.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying storage backend fails.
    fn load(&self) -> Result<Option<Zeroizing<Vec<u8>>>, StoreError>;

    /// Persists `secret`, replacing any previous value.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying storage backend fails.
    fn save(&self, secret: &[u8]) -> Result<(), StoreError>;
}

/// Opens the default key store for `account` on the current operating system:
///
/// - Windows and macOS: operating system credential store (Credential Manager,
///   Keychain);
/// - Linux and other Unix platforms: `<config>/omegadesk/<account>.key` with
///   mode `0600`. The Linux kernel keyring (`keyutils`) is cleared on reboot,
///   which would change the device ID, and D-Bus Secret Service is unavailable
///   on headless servers.
///
/// # Errors
///
/// Returns an error if the credential store cannot be opened or no
/// configuration directory is available.
pub fn default_store(account: &str) -> Result<Box<dyn KeyStore>, StoreError> {
    if cfg!(any(windows, target_os = "macos")) {
        Ok(Box::new(KeyringStore::new(account)?))
    } else {
        Ok(Box::new(FileStore::in_config_dir(account)?))
    }
}

/// Opens `path` when given, otherwise the [`default_store`]; when the OS
/// credential store exists but cannot be used in this context (Windows
/// Credential Manager returns `ERROR_NO_SUCH_LOGON_SESSION` inside SSH and
/// service sessions, Keychain is locked on headless macOS) the identity falls
/// back to `<config>/omegadesk/<account>.key` so the device keeps a stable ID.
/// Returns the store and a note describing the fallback, if one happened.
///
/// # Errors
///
/// Returns an error if no store can be opened or read.
pub fn resolve_store(
    account: &str,
    path: Option<&Path>,
) -> Result<(Box<dyn KeyStore>, Option<String>), StoreError> {
    if let Some(path) = path {
        return Ok((Box::new(FileStore::new(path)), None));
    }
    let store = default_store(account)?;
    match store.load() {
        Ok(_) => Ok((store, None)),
        Err(error) => {
            let fallback = FileStore::in_config_dir(account)?;
            let note = format!(
                "OS credential store unavailable ({error}); using {}",
                fallback.path().display()
            );
            Ok((Box::new(fallback), Some(note)))
        }
    }
}

/// Operating system credential store: Windows Credential Manager and macOS Keychain.
#[derive(Debug)]
pub struct KeyringStore {
    entry: keyring::Entry,
}

impl KeyringStore {
    /// Service name registered in the OS credential store.
    pub const SERVICE: &'static str = "omegadesk";

    /// Opens the `account` entry in the OS credential store. Use distinct
    /// account names for the agent (system service) and the client (user app).
    ///
    /// # Errors
    ///
    /// Returns an error if the OS credential store is unavailable.
    pub fn new(account: &str) -> Result<Self, StoreError> {
        Ok(Self {
            entry: keyring::Entry::new(Self::SERVICE, account)?,
        })
    }
}

impl KeyStore for KeyringStore {
    fn load(&self) -> Result<Option<Zeroizing<Vec<u8>>>, StoreError> {
        match self.entry.get_secret() {
            Ok(secret) => Ok(Some(Zeroizing::new(secret))),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    fn save(&self, secret: &[u8]) -> Result<(), StoreError> {
        Ok(self.entry.set_secret(secret)?)
    }
}

/// File store restricted to the file owner (`0600` on Unix).
#[derive(Debug, Clone)]
pub struct FileStore {
    path: PathBuf,
}

impl FileStore {
    /// Stores keys in `path`.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// Uses `<config>/omegadesk/<account>.key`, where `<config>` is resolved
    /// from `$XDG_CONFIG_HOME`, `%APPDATA%`, or `~/.config`.
    ///
    /// # Errors
    ///
    /// Returns an error if no configuration directory environment variable is set.
    pub fn in_config_dir(account: &str) -> Result<Self, StoreError> {
        let base = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("APPDATA").map(PathBuf::from))
            .or_else(|| std::env::var_os("HOME").map(|home| Path::new(&home).join(".config")))
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "no configuration directory found (XDG_CONFIG_HOME, APPDATA, or HOME)",
                )
            })?;
        Ok(Self::new(
            base.join("omegadesk").join(format!("{account}.key")),
        ))
    }

    /// Path to the key file.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl KeyStore for FileStore {
    fn load(&self) -> Result<Option<Zeroizing<Vec<u8>>>, StoreError> {
        match std::fs::read(&self.path) {
            Ok(secret) => Ok(Some(Zeroizing::new(secret))),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    fn save(&self, secret: &[u8]) -> Result<(), StoreError> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        // Write to a temporary file and rename atomically so a crash mid-write
        // never leaves a half-written identity on disk.
        let temporary = self.path.with_extension("key.tmp");
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        let mut file = options.open(&temporary)?;
        file.write_all(secret)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&temporary, &self.path)?;
        Ok(())
    }
}

/// In-memory key store for tests and ephemeral identities (such as `QuickSupport`).
#[derive(Debug, Default)]
pub struct MemoryStore {
    secret: Mutex<Option<Zeroizing<Vec<u8>>>>,
}

impl KeyStore for MemoryStore {
    fn load(&self) -> Result<Option<Zeroizing<Vec<u8>>>, StoreError> {
        let guard = self.secret.lock().map_err(|_| StoreError::Poisoned)?;
        Ok(guard.clone())
    }

    fn save(&self, secret: &[u8]) -> Result<(), StoreError> {
        let mut guard = self.secret.lock().map_err(|_| StoreError::Poisoned)?;
        *guard = Some(Zeroizing::new(secret.to_vec()));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{FileStore, KeyStore};
    use crate::DeviceIdentity;

    #[test]
    fn explicit_key_file_bypasses_the_os_store() {
        let directory =
            std::env::temp_dir().join(format!("omegadesk-identity-resolve-{}", std::process::id()));
        let path = directory.join("node.key");
        let (store, note) = super::resolve_store("ignored", Some(&path)).unwrap();
        assert!(note.is_none(), "an explicit file is not a fallback");
        let first = DeviceIdentity::load_or_create(store.as_ref()).unwrap();
        let (again, _) = super::resolve_store("ignored", Some(&path)).unwrap();
        let second = DeviceIdentity::load_or_create(again.as_ref()).unwrap();
        assert_eq!(first.id(), second.id());
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn file_store_round_trip() {
        let directory =
            std::env::temp_dir().join(format!("omegadesk-identity-test-{}", std::process::id()));
        let store = FileStore::new(directory.join("nested").join("agent.key"));
        assert!(store.load().unwrap().is_none());

        let first = DeviceIdentity::load_or_create(&store).unwrap();
        let second = DeviceIdentity::load_or_create(&store).unwrap();
        assert_eq!(first.id(), second.id());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(store.path())
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "key file permissions must be 0600");
        }
        std::fs::remove_dir_all(&directory).unwrap();
    }
}
