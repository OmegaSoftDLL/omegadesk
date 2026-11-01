//! Security audit event stream: one JSON object per line, appended and flushed per event.
//!
//! Reference implementations:
//! - `jumpserver_jumpserver/apps/terminal/models/session/session.py` (lines 25–47):
//!   the `Session` record fields (`user`, `asset`, `remote_addr`, `is_success`,
//!   `date_start`/`date_end`, `error_reason`) that every session event carries here as
//!   `actor`, `target`, `remote`, `outcome`, `timestamp_ms` and `detail`.
//! - `Ylianst_MeshCentral/meshrelay.js` (lines 540–556): the relay logs who connected to
//!   which node, from where and when, before the first byte of the session flows; this
//!   stream is the equivalent for the coordinator (enrollment, policy) and the agent
//!   (connections, MFA, DLP, recordings).
//!
//! JSON Lines keeps the log append-only and greppable without a database: a line is
//! complete or absent, and the writer flushes after every event so a crash loses at most
//! the event being written.

use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

/// Which binary produced the event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditComponent {
    /// `omegadesk-server`.
    Coordinator,
    /// `omegadesk-agent`.
    Agent,
}

/// Event kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditKind {
    /// A node enrolled with the coordinator (`actor` is the node, `target` its tenant).
    NodeEnrolled,
    /// A node's control connection ended.
    NodeDisconnected,
    /// The coordinator refused an enrollment.
    EnrollmentDenied,
    /// The coordinator loaded or reloaded its policy file (`detail` says which).
    PolicyLoaded,
    /// A policy reload failed; the previous policy stays in force.
    PolicyRejected,
    /// A client passed the handshake and the session opened.
    SessionConnected,
    /// A session ended (`detail` carries the duration and the reason).
    SessionDisconnected,
    /// A client was refused before the session opened (`detail` says why).
    SessionDenied,
    /// The agent sent an MFA challenge.
    MfaChallenged,
    /// The MFA code was accepted.
    MfaOk,
    /// An MFA code was rejected (wrong, replayed, expired or locked out).
    MfaFailed,
    /// A clipboard transfer was blocked by the DLP limits.
    DlpBlocked,
    /// A session recording file was opened (`detail` is the path).
    RecordingStarted,
    /// A session recording file was closed (`detail` is the path and record count).
    RecordingFinished,
}

/// Outcome of the audited action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditOutcome {
    /// The action succeeded or the state change took place.
    Ok,
    /// The action was refused by policy or authentication.
    Denied,
    /// The action failed for a technical reason.
    Failed,
}

/// One audit event (one JSON line).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuditEvent {
    /// Milliseconds since the Unix epoch.
    pub timestamp_ms: u64,
    /// Producer.
    pub component: AuditComponent,
    /// Event kind.
    pub kind: AuditKind,
    /// Result.
    pub outcome: AuditOutcome,
    /// Who acted: a device ID, `user@tenant`, or a peer name. Omitted when unknown.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    /// What was acted on: the agent, the tenant, the policy file.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// Network address the actor connected from.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote: Option<String>,
    /// Session identifier shared by every event of one remote session.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Free-form explanation (rejection reason, file path, duration).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl AuditEvent {
    /// Creates an event stamped with the current wall-clock time and no optional fields.
    #[must_use]
    pub fn new(component: AuditComponent, kind: AuditKind, outcome: AuditOutcome) -> Self {
        Self {
            timestamp_ms: unix_millis(),
            component,
            kind,
            outcome,
            actor: None,
            target: None,
            remote: None,
            session_id: None,
            detail: None,
        }
    }

    /// Sets `actor`.
    #[must_use]
    pub fn actor(mut self, actor: impl Into<String>) -> Self {
        self.actor = Some(actor.into());
        self
    }

    /// Sets `target`.
    #[must_use]
    pub fn target(mut self, target: impl Into<String>) -> Self {
        self.target = Some(target.into());
        self
    }

    /// Sets `remote`.
    #[must_use]
    pub fn remote(mut self, remote: &impl std::fmt::Display) -> Self {
        self.remote = Some(remote.to_string());
        self
    }

    /// Sets `session_id`.
    #[must_use]
    pub fn session(mut self, session_id: impl Into<String>) -> Self {
        self.session_id = Some(session_id.into());
        self
    }

    /// Sets `detail`.
    #[must_use]
    pub fn detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    /// Serializes the event as one JSON line (with the trailing newline).
    #[must_use]
    pub fn to_json_line(&self) -> String {
        // Serializing a struct of strings, integers and unit enums cannot fail.
        let mut line = serde_json::to_string(self).unwrap_or_default();
        line.push('\n');
        line
    }
}

/// Current time in milliseconds since the Unix epoch (`0` if the clock is before 1970).
#[must_use]
pub fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// Append-only JSON Lines audit log. Thread-safe; every [`Self::append`] flushes.
#[derive(Debug)]
pub struct AuditLog {
    writer: Mutex<BufWriter<File>>,
    path: String,
}

impl AuditLog {
    /// Opens (creating if needed) `path` for appending.
    ///
    /// # Errors
    ///
    /// Returns the I/O error if the file cannot be opened.
    pub fn open(path: &Path) -> std::io::Result<Self> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self {
            writer: Mutex::new(BufWriter::new(file)),
            path: path.display().to_string(),
        })
    }

    /// Path the log writes to, for log messages.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Appends one event and flushes it to the operating system.
    ///
    /// # Errors
    ///
    /// Returns the I/O error if the write or flush fails. Callers log and continue: an audit
    /// write failure must not take the session down, but it must be visible.
    pub fn append(&self, event: &AuditEvent) -> std::io::Result<()> {
        let line = event.to_json_line();
        let mut writer = self
            .writer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        writer.write_all(line.as_bytes())?;
        writer.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn events_are_one_json_object_per_line_and_appended() {
        let dir = std::env::temp_dir().join(format!(
            "omegadesk-audit-{}-{}",
            std::process::id(),
            unix_millis()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("audit.jsonl");
        let log = AuditLog::open(&path).unwrap();

        let first = AuditEvent::new(
            AuditComponent::Agent,
            AuditKind::SessionDenied,
            AuditOutcome::Denied,
        )
        .actor("ID abc")
        .remote(&"100.64.0.9:7070")
        .detail("policy: no session rule");
        log.append(&first).unwrap();
        log.append(&AuditEvent::new(
            AuditComponent::Coordinator,
            AuditKind::PolicyLoaded,
            AuditOutcome::Ok,
        ))
        .unwrap();
        // Reopening appends instead of truncating.
        drop(log);
        let log = AuditLog::open(&path).unwrap();
        log.append(&AuditEvent::new(
            AuditComponent::Agent,
            AuditKind::MfaOk,
            AuditOutcome::Ok,
        ))
        .unwrap();

        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 3);
        let parsed: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(parsed["component"], "agent");
        assert_eq!(parsed["kind"], "session_denied");
        assert_eq!(parsed["outcome"], "denied");
        assert_eq!(parsed["actor"], "ID abc");
        assert_eq!(parsed["remote"], "100.64.0.9:7070");
        assert!(
            parsed.get("session_id").is_none(),
            "unset fields are omitted"
        );
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(lines[2]).unwrap()["kind"],
            "mfa_ok"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
