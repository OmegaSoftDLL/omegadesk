//! Armazenamento das chaves privadas do dispositivo.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use zeroize::Zeroizing;

use crate::IdentityError;

/// Erros de armazenamento.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// O cofre do sistema operacional recusou ou falhou na operação.
    #[error("cofre do sistema: {0}")]
    Keyring(#[from] keyring::Error),
    /// Falha ao ler ou gravar o arquivo de chaves.
    #[error("arquivo de chaves: {0}")]
    Io(#[from] std::io::Error),
    /// O conteúdo guardado não é uma identidade válida.
    #[error(transparent)]
    Identity(#[from] IdentityError),
    /// O armazenamento em memória ficou inconsistente (thread em pânico).
    #[error("armazenamento em memória inconsistente")]
    Poisoned,
}

/// Onde as chaves privadas do dispositivo ficam guardadas.
pub trait KeyStore {
    /// Lê o segredo guardado, ou `None` se ainda não existe.
    ///
    /// # Errors
    ///
    /// Retorna erro se o armazenamento falhar.
    fn load(&self) -> Result<Option<Zeroizing<Vec<u8>>>, StoreError>;

    /// Guarda o segredo, substituindo o anterior.
    ///
    /// # Errors
    ///
    /// Retorna erro se o armazenamento falhar.
    fn save(&self, secret: &[u8]) -> Result<(), StoreError>;
}

/// Armazenamento padrão para `account` neste sistema operacional:
///
/// - Windows e macOS: cofre do sistema (Gerenciador de Credenciais, Keychain);
/// - Linux e outros: arquivo `<config>/omegadesk/<account>.key` com permissão
///   0600. O keyring do kernel (keyutils) perde as chaves no reboot, o que
///   mudaria o ID do dispositivo, e o Secret Service não existe em servidores
///   sem sessão gráfica.
///
/// # Errors
///
/// Retorna erro se o cofre não estiver disponível ou se não houver diretório
/// de configuração.
pub fn default_store(account: &str) -> Result<Box<dyn KeyStore>, StoreError> {
    if cfg!(any(windows, target_os = "macos")) {
        Ok(Box::new(KeyringStore::new(account)?))
    } else {
        Ok(Box::new(FileStore::in_config_dir(account)?))
    }
}

/// Cofre do sistema operacional: Gerenciador de Credenciais no Windows e
/// Keychain no macOS.
#[derive(Debug)]
pub struct KeyringStore {
    entry: keyring::Entry,
}

impl KeyringStore {
    /// Nome do serviço usado no cofre do sistema.
    pub const SERVICE: &'static str = "omegadesk";

    /// Abre a entrada `account` do cofre. Use nomes diferentes para o agente
    /// (serviço do sistema) e para o cliente (usuário).
    ///
    /// # Errors
    ///
    /// Retorna erro se o cofre do sistema não estiver disponível.
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

/// Arquivo com permissão restrita ao dono (0600 em Unix).
#[derive(Debug, Clone)]
pub struct FileStore {
    path: PathBuf,
}

impl FileStore {
    /// Usa o arquivo `path`.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// Usa `<config>/omegadesk/<account>.key`, onde `<config>` é
    /// `$XDG_CONFIG_HOME` ou `~/.config` (ou `%APPDATA%` no Windows).
    ///
    /// # Errors
    ///
    /// Retorna erro se nenhum diretório de configuração estiver definido.
    pub fn in_config_dir(account: &str) -> Result<Self, StoreError> {
        let base = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("APPDATA").map(PathBuf::from))
            .or_else(|| std::env::var_os("HOME").map(|home| Path::new(&home).join(".config")))
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "nenhum diretório de configuração (XDG_CONFIG_HOME, APPDATA ou HOME)",
                )
            })?;
        Ok(Self::new(
            base.join("omegadesk").join(format!("{account}.key")),
        ))
    }

    /// Caminho do arquivo.
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
        // Grava num arquivo temporário e renomeia: uma queda no meio não deixa
        // a identidade corrompida.
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

/// Armazenamento em memória, para testes e para identidades efêmeras
/// (por exemplo, o `QuickSupport`).
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
            assert_eq!(mode & 0o777, 0o600, "o arquivo de chaves precisa ser 0600");
        }
        std::fs::remove_dir_all(&directory).unwrap();
    }
}
