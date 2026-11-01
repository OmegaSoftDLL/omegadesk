//! The QuickSupport host: the end user's side of a support session.
//!
//! [`QuickSupportHost::join`] enrolls in the mesh as an ephemeral node
//! ([`omegadesk_magicsock::Node`]) proposing the nine-digit ID derived from
//! the device identity; the coordinator confirms or replaces it and peers of
//! the tenant resolve it (`omegadesk-client 123 456 789`). Every incoming QUIC
//! connection is then served by the agent's own session code
//! ([`omegadesk_agent::session::run`]): the technician must present the
//! temporary password, and [`SessionGate`] asks the end user for consent
//! before `HelloAck`. Ten wrong passwords in a row rotate the password
//! ([`TemporaryPasswordGuard`], RustDesk `check_update_temporary_password`).
//!
//! [`ConsoleConsent`] is the console implementation of the gate used by the
//! binary; tests and future UIs implement [`SessionGate`] themselves.

use std::fmt;
use std::future::Future;
use std::io::Write;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use omegadesk_agent::access::{AccessConfig, AccessControl};
use omegadesk_agent::capture_loop::EncoderChoice;
use omegadesk_agent::password;
use omegadesk_agent::session::{self, PeerDescriptor, SessionConfig, SessionGate};
use omegadesk_codec::EncoderSettings;
use omegadesk_control::{ControlConfig, PeerInfo};
use omegadesk_identity::{DeviceIdentity, QuickSupportId};
use omegadesk_magicsock::{Node, NodeConfig, NodeError};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::{
    ClientPermissions, ConsentChannelKind, ConsentDecision, ConsentManager, ConsentPolicy,
    HostUserState, TemporaryPasswordGuard,
};

/// Length of the temporary password shown to the end user (RustDesk uses 6).
pub const DEFAULT_PASSWORD_LENGTH: usize = 6;

/// How a QuickSupport host joins the mesh and shares its screen.
#[derive(Debug, Clone)]
pub struct HostConfig {
    /// Coordinator and pre-auth key. `hostname` is the name shown to the
    /// technician; `quicksupport_id` is overwritten with this device's proposal.
    pub control: ControlConfig,
    /// Local UDP bind address of the mesh socket (`0.0.0.0:0` picks a port).
    pub bind: SocketAddr,
    /// Never attempt direct paths; send everything through the relays.
    pub relay_only: bool,
    /// Monitor index to share (`0` is the primary monitor).
    pub monitor: u32,
    /// Video encoder selection policy.
    pub encoder: EncoderChoice,
    /// Bitrate and frame-rate cap of the video encoder.
    pub settings: EncoderSettings,
    /// What a connected technician may do; remote input is injected only when
    /// at least one `INPUT_*` bit is set.
    pub permissions: ClientPermissions,
    /// Temporary password length (clamped to `6..=16`).
    pub password_length: usize,
}

/// Errors of the QuickSupport host.
#[derive(Debug, thiserror::Error)]
pub enum HostError {
    /// Joining the mesh failed.
    #[error(transparent)]
    Mesh(#[from] NodeError),
    /// The coordinator enrolled the node without a QuickSupport ID (it does
    /// not speak this version of the control protocol).
    #[error("the coordinator did not assign a QuickSupport ID")]
    NoId,
    /// The mesh QUIC endpoint stopped accepting connections.
    #[error("the mesh endpoint closed")]
    EndpointClosed,
}

/// How one accepted connection ended.
#[derive(Debug)]
pub enum SessionOutcome {
    /// The technician authenticated, the end user consented and the session
    /// ran to completion.
    Served {
        /// The technician's mesh record, when the connection came from a known peer.
        peer: Option<Box<PeerInfo>>,
    },
    /// The technician presented a wrong temporary password.
    WrongPassword {
        /// Whether this was the tenth consecutive failure and the password
        /// was rotated: show the new one to the end user.
        rotated: bool,
    },
    /// The handshake or the session failed for another reason (declined by
    /// the end user, protocol error, network error).
    Failed(anyhow::Error),
}

/// A QuickSupport host enrolled in the mesh.
pub struct QuickSupportHost {
    node: Node,
    identity: Arc<DeviceIdentity>,
    password: Mutex<TemporaryPasswordGuard>,
    access: Arc<AccessControl>,
    config: HostConfig,
}

impl QuickSupportHost {
    /// Joins the mesh as an ephemeral QuickSupport node. Returns once the
    /// coordinator assigned the ID; relay and direct paths come up in the background.
    ///
    /// # Errors
    ///
    /// Returns [`HostError::Mesh`] when enrollment fails and [`HostError::NoId`]
    /// when the coordinator did not assign an ID.
    pub async fn join(
        identity: Arc<DeviceIdentity>,
        config: HostConfig,
    ) -> Result<Self, HostError> {
        let mut config = config;
        config.control.quicksupport_id = Some(QuickSupportId::proposed_for(identity.id()));
        let mut node_config = NodeConfig::new(config.control.clone());
        node_config.bind = config.bind;
        node_config.relay_only = config.relay_only;
        let node = Node::start(Arc::clone(&identity), node_config).await?;
        let id = node.quicksupport_id().ok_or(HostError::NoId)?;
        info!(%id, fqdn = %node.self_info().fqdn, "QuickSupport host enrolled");
        let access = Arc::new(AccessControl::new(AccessConfig {
            agent_name: config.control.hostname.clone(),
            agent_id: identity.id(),
            totp_secret: None,
            recordings_dir: None,
            audit: None,
        }));
        Ok(Self {
            node,
            identity,
            password: Mutex::new(TemporaryPasswordGuard::new(config.password_length)),
            access,
            config,
        })
    }

    /// The nine-digit ID the end user reads to the technician. It can change
    /// after a coordinator reconnect when another host took the number in the
    /// meantime; callers that display it should re-check it periodically.
    #[must_use]
    pub fn id(&self) -> QuickSupportId {
        self.node
            .quicksupport_id()
            .unwrap_or_else(|| QuickSupportId::proposed_for(self.identity.id()))
    }

    /// The current temporary password.
    #[must_use]
    pub fn password(&self) -> String {
        self.guard().password().to_owned()
    }

    /// Replaces the temporary password immediately and returns the new one.
    pub fn rotate_password(&self) -> String {
        self.guard().rotate().to_owned()
    }

    /// The mesh node (for peer and path diagnostics).
    #[must_use]
    pub fn node(&self) -> &Node {
        &self.node
    }

    /// This host's device identity.
    #[must_use]
    pub fn identity(&self) -> &Arc<DeviceIdentity> {
        &self.identity
    }

    /// Permissions granted to connected technicians.
    #[must_use]
    pub fn permissions(&self) -> ClientPermissions {
        self.config.permissions
    }

    fn guard(&self) -> MutexGuard<'_, TemporaryPasswordGuard> {
        self.password.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Accepts the next connection and serves it with the agent's session code,
    /// consulting `gate` after the password check. Returns when that session ends.
    ///
    /// # Errors
    ///
    /// Returns [`HostError::EndpointClosed`] once the mesh endpoint is closed.
    pub async fn serve_one(&self, gate: Arc<dyn SessionGate>) -> Result<SessionOutcome, HostError> {
        let incoming = self
            .node
            .endpoint()
            .accept()
            .await
            .ok_or(HostError::EndpointClosed)?;
        let connection = match incoming.await {
            Ok(connection) => connection,
            Err(error) => return Ok(SessionOutcome::Failed(error.into())),
        };
        let remote = connection.remote_address();
        let peer = self.node.peer_at(remote).map(Box::new);
        if let Some(peer) = &peer {
            info!("technician connected: {} ({remote})", peer.fqdn);
        } else {
            info!("technician connected: {remote}");
        }
        let config = Arc::new(SessionConfig {
            name: self.config.control.hostname.clone(),
            device_public_key: self.identity.public().signing_key_bytes(),
            password: self.password(),
            monitor: self.config.monitor,
            encoder: self.config.encoder,
            settings: self.config.settings,
            input: self
                .config
                .permissions
                .intersects(ClientPermissions::ALL_INPUTS),
            gate: Some(gate),
            clipboard: self.config.permissions.contains(
                ClientPermissions::CLIPBOARD_READ.union(ClientPermissions::CLIPBOARD_SET),
            ),
            file_transfer: self
                .config
                .permissions
                .contains(ClientPermissions::FILE_UPLOAD),
            receive_dir: omegadesk_session::file_io::default_receive_dir(),
            send_files: Vec::new(),
            access: Arc::clone(&self.access),
        });
        match session::run(connection, config, peer.as_deref().cloned()).await {
            Ok(()) => {
                self.guard().record_success();
                Ok(SessionOutcome::Served { peer })
            }
            Err(error) if error.downcast_ref::<password::Rejected>().is_some() => {
                let rotated = self.guard().record_failure();
                warn!(rotated, "technician presented a wrong temporary password");
                Ok(SessionOutcome::WrongPassword { rotated })
            }
            Err(error) => {
                warn!("session ended with error: {error:#}");
                Ok(SessionOutcome::Failed(error))
            }
        }
    }
}

impl fmt::Debug for QuickSupportHost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QuickSupportHost")
            .field("id", &self.id())
            .field("node", &self.node)
            .finish_non_exhaustive()
    }
}

/// Console consent prompt: the end user answers `y`, `n` or `a` (allow this
/// technician without asking again for five minutes) on the terminal where
/// QuickSupport runs. Decisions follow [`ConsentManager`] (MeshCentral's
/// layered consent, timeout and auto-allow grace period).
pub struct ConsoleConsent {
    manager: Mutex<ConsentManager>,
    lines: tokio::sync::Mutex<mpsc::Receiver<String>>,
}

impl ConsoleConsent {
    /// Starts reading the console in the background. Must be called on a Tokio runtime.
    #[must_use]
    pub fn new(policy: ConsentPolicy) -> Self {
        let (tx, rx) = mpsc::channel(8);
        tokio::spawn(async move {
            let mut lines = BufReader::new(tokio::io::stdin()).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                if tx.send(line).await.is_err() {
                    break;
                }
            }
        });
        Self {
            manager: Mutex::new(ConsentManager::new(policy)),
            lines: tokio::sync::Mutex::new(rx),
        }
    }

    fn manager(&self) -> MutexGuard<'_, ConsentManager> {
        self.manager.lock().unwrap_or_else(PoisonError::into_inner)
    }

    async fn prompt(&self, peer: &PeerDescriptor, timeout_secs: u64) -> Result<(), String> {
        let operator = operator_id(peer);
        let mut lines = self.lines.lock().await;
        // Anything typed before the prompt is not an answer to it.
        while lines.try_recv().is_ok() {}
        {
            let mut out = std::io::stdout().lock();
            let _ = writeln!(out);
            let _ = writeln!(
                out,
                "Technician {:?} (ID {}) wants to view and control this screen.",
                peer.device_name,
                peer.device_id
                    .map_or_else(|| "unknown".to_owned(), |id| id.to_string()),
            );
            let _ = write!(
                out,
                "Allow? [y]es / [n]o / [a]lways for 5 minutes ({timeout_secs} s): "
            );
            let _ = out.flush();
        }
        let answer = tokio::time::timeout(Duration::from_secs(timeout_secs), lines.recv()).await;
        drop(lines);
        let decision = match answer {
            Ok(Some(line)) => {
                let answer = line.trim().to_ascii_lowercase();
                let accepted = matches!(answer.as_str(), "y" | "yes" | "a" | "always");
                let grace = matches!(answer.as_str(), "a" | "always");
                self.manager()
                    .record_user_response(&operator, accepted, grace, Instant::now())
            }
            Ok(None) => return Err("console input closed before the user answered".to_owned()),
            Err(_) => self.manager().resolve_timeout(),
        };
        match decision {
            ConsentDecision::Accepted { .. }
            | ConsentDecision::AllowedImmediately
            | ConsentDecision::TimedOut {
                auto_accepted: true,
            } => Ok(()),
            ConsentDecision::Rejected => Err("the user declined the session".to_owned()),
            ConsentDecision::TimedOut {
                auto_accepted: false,
            } => Err(format!("the user did not answer within {timeout_secs} s")),
            ConsentDecision::PromptRequired { .. } => {
                Err("consent prompt could not be resolved".to_owned())
            }
        }
    }
}

impl fmt::Debug for ConsoleConsent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConsoleConsent")
            .field("policy", self.manager().policy())
            .finish_non_exhaustive()
    }
}

impl SessionGate for ConsoleConsent {
    fn authorize<'a>(
        &'a self,
        peer: &'a PeerDescriptor,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            // The end user is sitting at this console, so there is an
            // interactive, unlocked session.
            let decision = self.manager().evaluate(
                &operator_id(peer),
                ConsentChannelKind::Desktop,
                HostUserState {
                    user_logged_in: true,
                    session_locked: false,
                },
                Instant::now(),
            );
            match decision {
                ConsentDecision::AllowedImmediately | ConsentDecision::Accepted { .. } => Ok(()),
                ConsentDecision::PromptRequired { timeout_secs } => {
                    self.prompt(peer, timeout_secs).await
                }
                ConsentDecision::Rejected => Err("the user declined the session".to_owned()),
                ConsentDecision::TimedOut { auto_accepted } => {
                    if auto_accepted {
                        Ok(())
                    } else {
                        Err("consent timed out".to_owned())
                    }
                }
            }
        })
    }
}

/// Key under which consent grace periods are remembered: the technician's
/// device ID when known, otherwise the name it declared.
fn operator_id(peer: &PeerDescriptor) -> String {
    peer.device_id
        .map_or_else(|| peer.device_name.clone(), |id| id.to_string())
}
