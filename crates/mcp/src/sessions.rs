//! Guarded actions behind the MCP tools: launching `omegadesk-client` sessions and running
//! scripts on the machine that hosts the MCP server.
//!
//! Model: QuickDesk `quickdesk-mcp/src/server.rs` (`connect_device`, `disconnect_device`,
//! `run_command` through the skill host). OmegaDesk starts the regular client binary so the
//! remote user's consent, policies and recording keep applying; the MCP server never
//! injects input itself.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tokio::process::{Child, Command};

use crate::directory::DeviceEntry;

/// Coordinator parameters forwarded to every launched client.
#[derive(Debug, Clone)]
pub struct MeshLaunchArgs {
    /// Coordinator `host:port`.
    pub server: String,
    /// Coordinator public key (128 hex characters).
    pub server_key: String,
    /// Pre-authorized key (`odk_...`) the client enrolls with.
    pub preauth_key: String,
    /// Force the relay path.
    pub relay_only: bool,
}

/// Lifecycle state of a launched session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum SessionState {
    /// The client process is running.
    Running,
    /// The client process exited (`code` is `None` when killed by a signal).
    Exited {
        /// Process exit code.
        code: Option<i32>,
    },
}

/// A session started through the MCP server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SessionInfo {
    /// Identifier to pass to `stop_session`.
    pub id: u64,
    /// Device the client connects to (`fqdn`).
    pub device: String,
    /// Operating-system process id of the client.
    pub pid: Option<u32>,
    /// Unix time (seconds) at which the client was launched.
    pub started_at_unix_secs: u64,
    /// Current state.
    #[serde(flatten)]
    pub state: SessionState,
}

/// Errors of [`SessionLauncher`].
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    /// No coordinator was configured, so the client cannot reach a mesh device.
    #[error(
        "no coordinator configured: start omegadesk-mcp with --server, --server-key and --preauth-key to reach {0}"
    )]
    NoMesh(String),
    /// Unknown session id.
    #[error("session {0} not found")]
    NotFound(u64),
    /// The client binary could not be started.
    #[error("failed to launch {0}: {1}")]
    Spawn(String, #[source] std::io::Error),
    /// The client process could not be signalled.
    #[error("failed to stop session {0}: {1}")]
    Kill(u64, #[source] std::io::Error),
}

struct LaunchedSession {
    info: SessionInfo,
    child: Child,
}

/// Starts and stops `omegadesk-client` processes.
pub struct SessionLauncher {
    client_binary: PathBuf,
    mesh: Option<MeshLaunchArgs>,
    sessions: Mutex<BTreeMap<u64, LaunchedSession>>,
    next_id: AtomicU64,
}

impl std::fmt::Debug for SessionLauncher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionLauncher")
            .field("client_binary", &self.client_binary)
            .field("mesh", &self.mesh.as_ref().map(|mesh| &mesh.server))
            .finish_non_exhaustive()
    }
}

fn unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

impl SessionLauncher {
    /// Launcher for `client_binary`; without `mesh` only `status` and `stop` work.
    #[must_use]
    pub fn new(client_binary: PathBuf, mesh: Option<MeshLaunchArgs>) -> Self {
        Self {
            client_binary,
            mesh,
            sessions: Mutex::new(BTreeMap::new()),
            next_id: AtomicU64::new(1),
        }
    }

    /// `omegadesk-client` next to the running executable when it exists there, otherwise
    /// the bare name resolved through `PATH`.
    #[must_use]
    pub fn default_client_binary() -> PathBuf {
        let name = format!("omegadesk-client{}", std::env::consts::EXE_SUFFIX);
        std::env::current_exe()
            .ok()
            .and_then(|exe| exe.parent().map(|dir| dir.join(&name)))
            .filter(|candidate| candidate.is_file())
            .unwrap_or_else(|| PathBuf::from(name))
    }

    /// Path of the client binary this launcher starts.
    #[must_use]
    pub fn client_binary(&self) -> &Path {
        &self.client_binary
    }

    /// Whether launched clients can reach mesh devices.
    #[must_use]
    pub fn has_mesh(&self) -> bool {
        self.mesh.is_some()
    }

    /// Command line (program and arguments) used to connect to `device`; the access
    /// password travels in the `OMEGADESK_PASSWORD` environment variable, never in the
    /// argument list.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::NoMesh`] without coordinator parameters.
    pub fn command_line(
        &self,
        device: &DeviceEntry,
        view_only: bool,
    ) -> Result<Vec<String>, SessionError> {
        let mesh = self
            .mesh
            .as_ref()
            .ok_or_else(|| SessionError::NoMesh(device.record.fqdn.clone()))?;
        let mut args = vec![
            self.client_binary.display().to_string(),
            device.record.fqdn.clone(),
            "--server".to_owned(),
            mesh.server.clone(),
            "--server-key".to_owned(),
            mesh.server_key.clone(),
            "--preauth-key".to_owned(),
            mesh.preauth_key.clone(),
        ];
        if mesh.relay_only {
            args.push("--relay-only".to_owned());
        }
        if view_only {
            args.push("--view-only".to_owned());
        }
        Ok(args)
    }

    /// Launches a client session to `device`.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::NoMesh`] without coordinator parameters and
    /// [`SessionError::Spawn`] when the client binary cannot be started.
    pub fn start(
        &self,
        device: &DeviceEntry,
        password: &str,
        view_only: bool,
    ) -> Result<SessionInfo, SessionError> {
        let command_line = self.command_line(device, view_only)?;
        let (program, args) = command_line
            .split_first()
            .ok_or_else(|| SessionError::NoMesh(device.record.fqdn.clone()))?;
        let child = Command::new(OsStr::new(program))
            .args(args)
            .env("OMEGADESK_PASSWORD", password)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(|error| SessionError::Spawn(program.clone(), error))?;
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let info = SessionInfo {
            id,
            device: device.record.fqdn.clone(),
            pid: child.id(),
            started_at_unix_secs: unix_secs(),
            state: SessionState::Running,
        };
        self.lock().insert(id, LaunchedSession {
            info: info.clone(),
            child,
        });
        Ok(info)
    }

    /// Kills the client process of session `id`.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::NotFound`] for unknown ids and [`SessionError::Kill`] when
    /// the process cannot be signalled.
    pub fn stop(&self, id: u64) -> Result<SessionInfo, SessionError> {
        let mut sessions = self.lock();
        let session = sessions.get_mut(&id).ok_or(SessionError::NotFound(id))?;
        if matches!(session.info.state, SessionState::Running) {
            match session.child.try_wait() {
                Ok(Some(status)) => session.info.state = SessionState::Exited { code: status.code() },
                Ok(None) => {
                    session
                        .child
                        .start_kill()
                        .map_err(|error| SessionError::Kill(id, error))?;
                    session.info.state = SessionState::Exited { code: None };
                }
                Err(error) => return Err(SessionError::Kill(id, error)),
            }
        }
        Ok(session.info.clone())
    }

    /// All sessions started by this launcher with their current state.
    #[must_use]
    pub fn status(&self) -> Vec<SessionInfo> {
        let mut sessions = self.lock();
        for session in sessions.values_mut() {
            if matches!(session.info.state, SessionState::Running)
                && let Ok(Some(status)) = session.child.try_wait()
            {
                session.info.state = SessionState::Exited { code: status.code() };
            }
        }
        sessions.values().map(|session| session.info.clone()).collect()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, BTreeMap<u64, LaunchedSession>> {
        self.sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// Result of a script run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ScriptOutcome {
    /// Exit code (`None` when killed or timed out).
    pub exit_code: Option<i32>,
    /// Whether the script was killed at the timeout.
    pub timed_out: bool,
    /// Wall-clock duration in milliseconds.
    pub duration_ms: u64,
    /// Captured standard output (lossy UTF-8, truncated to the configured limit).
    pub stdout: String,
    /// Captured standard error (lossy UTF-8, truncated to the configured limit).
    pub stderr: String,
    /// Whether `stdout` was truncated.
    pub stdout_truncated: bool,
    /// Whether `stderr` was truncated.
    pub stderr_truncated: bool,
}

/// Runs shell commands on the local machine with a timeout and bounded output.
#[derive(Debug, Clone, Copy)]
pub struct ScriptRunner {
    /// Timeout applied when the tool call does not specify one.
    pub default_timeout: Duration,
    /// Longest timeout a tool call may request.
    pub max_timeout: Duration,
    /// Bytes of each stream kept in the result.
    pub max_output_bytes: usize,
}

impl Default for ScriptRunner {
    fn default() -> Self {
        Self {
            default_timeout: Duration::from_secs(60),
            max_timeout: Duration::from_secs(600),
            max_output_bytes: 64 * 1024,
        }
    }
}

fn truncate_output(bytes: &[u8], limit: usize) -> (String, bool) {
    if bytes.len() <= limit {
        (String::from_utf8_lossy(bytes).into_owned(), false)
    } else {
        (String::from_utf8_lossy(&bytes[..limit]).into_owned(), true)
    }
}

impl ScriptRunner {
    /// Shell used to run scripts on this platform.
    #[must_use]
    pub fn shell() -> (&'static str, &'static [&'static str]) {
        if cfg!(windows) {
            ("cmd", &["/D", "/C"])
        } else {
            ("sh", &["-c"])
        }
    }

    /// Runs `command` through the platform shell, killing it at `timeout`
    /// (clamped to [`Self::max_timeout`]).
    ///
    /// # Errors
    ///
    /// Returns the I/O error when the shell cannot be spawned.
    pub async fn run(
        &self,
        command: &str,
        timeout: Option<Duration>,
    ) -> Result<ScriptOutcome, std::io::Error> {
        let timeout = timeout.unwrap_or(self.default_timeout).min(self.max_timeout);
        let (shell, shell_args) = Self::shell();
        let child = Command::new(shell)
            .args(shell_args)
            .arg(command)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;
        let started = Instant::now();
        // Dropping the future on timeout kills the child (`kill_on_drop`).
        let output = tokio::time::timeout(timeout, child.wait_with_output()).await;
        let duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        match output {
            Ok(output) => {
                let output = output?;
                let (stdout, stdout_truncated) =
                    truncate_output(&output.stdout, self.max_output_bytes);
                let (stderr, stderr_truncated) =
                    truncate_output(&output.stderr, self.max_output_bytes);
                Ok(ScriptOutcome {
                    exit_code: output.status.code(),
                    timed_out: false,
                    duration_ms,
                    stdout,
                    stderr,
                    stdout_truncated,
                    stderr_truncated,
                })
            }
            Err(_) => Ok(ScriptOutcome {
                exit_code: None,
                timed_out: true,
                duration_ms,
                stdout: String::new(),
                stderr: String::new(),
                stdout_truncated: false,
                stderr_truncated: false,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::directory::DeviceRecord;
    use omegadesk_identity::DeviceIdentity;

    fn device(fqdn: &str) -> DeviceEntry {
        let identity = DeviceIdentity::generate();
        DeviceEntry {
            id: identity.id(),
            record: DeviceRecord {
                id: identity.id().to_string(),
                hostname: fqdn.trim_end_matches(".omega").to_owned(),
                fqdn: fqdn.to_owned(),
                ipv4: None,
                ipv6: None,
                tags: Vec::new(),
                ephemeral: false,
            },
        }
    }

    #[test]
    fn command_line_targets_the_fqdn_and_never_carries_the_password() {
        let launcher = SessionLauncher::new(
            PathBuf::from("omegadesk-client"),
            Some(MeshLaunchArgs {
                server: "coord:8080".to_owned(),
                server_key: "ab".repeat(64),
                preauth_key: "odk_x_y".to_owned(),
                relay_only: true,
            }),
        );
        let line = launcher.command_line(&device("office-pc.omega"), true).unwrap();
        assert_eq!(line[0], "omegadesk-client");
        assert_eq!(line[1], "office-pc.omega");
        assert!(line.contains(&"--relay-only".to_owned()));
        assert!(line.contains(&"--view-only".to_owned()));
        assert!(line.iter().all(|arg| !arg.contains("password")));

        let offline = SessionLauncher::new(PathBuf::from("omegadesk-client"), None);
        assert!(matches!(
            offline.command_line(&device("x.omega"), false),
            Err(SessionError::NoMesh(_))
        ));
        assert!(matches!(offline.stop(7), Err(SessionError::NotFound(7))));
        assert!(offline.status().is_empty());
    }

    #[tokio::test]
    async fn script_runner_captures_output_and_enforces_the_timeout() {
        let runner = ScriptRunner {
            default_timeout: Duration::from_secs(10),
            max_timeout: Duration::from_secs(10),
            max_output_bytes: 8,
        };
        let outcome = runner.run("echo omegadesk-mcp", None).await.unwrap();
        assert_eq!(outcome.exit_code, Some(0));
        assert!(!outcome.timed_out);
        assert!(outcome.stdout.starts_with("omegades"), "{outcome:?}");
        assert!(outcome.stdout_truncated);

        let sleep = if cfg!(windows) {
            "ping -n 6 127.0.0.1 > nul"
        } else {
            "sleep 5"
        };
        let outcome = runner
            .run(sleep, Some(Duration::from_millis(200)))
            .await
            .unwrap();
        assert!(outcome.timed_out);
        assert_eq!(outcome.exit_code, None);
        assert!(outcome.duration_ms < 5_000);
    }
}
