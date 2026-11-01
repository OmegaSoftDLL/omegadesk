//! Session authorization beyond the access password: the coordinator's policy decision for
//! the connecting peer, posture checks, per-connection TOTP step-up, DLP limits, `.odrec`
//! recording and the audit stream. `session::handshake` calls `AccessControl::authorize`
//! once; the returned `SessionAccess` is then consulted by the video and control loops.
//!
//! Where the decision comes from: on the mesh the coordinator compiles the tenant's `HuJSON`
//! policy per node and ships, inside the netmap, a [`SessionDecision`] for every peer that may
//! reach this agent (`omegadesk-server`, Headscale `BuildPeerMap` model). The connecting peer
//! is identified by the mesh address the QUIC connection arrived from: that address is only
//! reachable through the tunnel keyed to the peer's identity (`omegadesk-magicsock`), so it is
//! authenticated, and the `Hello.device_public_key` must match it. In LAN mode (no coordinator)
//! there is no decision and the agent enforces the access password alone, as in Phase 1.
//!
//! Reference implementations:
//! - RustDesk `src/server/connection.rs` (`require_2fa`, `awaiting_2fa`, `REQUIRE_2FA`,
//!   lines 375–376 and 1850–1888) and `src/auth_2fa.rs`: the controlled machine owns the TOTP
//!   secret, answers a valid login with a "2FA required" error instead of closing the
//!   connection, and keeps the connection open for the code. Here [`MfaRequired`] /
//!   `MfaResponse` play that role and the secret comes from `--totp-secret`.
//! - `jumpserver_jumpserver/apps/acls/` (`ActionChoices.accept` / `review` / `reject`): the
//!   graded login decision the coordinator compiles into [`SessionDecision`].
//! - `Ylianst_MeshCentral/meshrelay.js` (lines 500–556 and 691–703): the recording file is
//!   opened before the first byte flows, starts with a metadata block (user, node, addresses,
//!   time, protocol) and every relayed message is appended with a 16-byte header; lines
//!   834–840 close it with a type-3 record. The relay could do that because it terminated the
//!   WebSocket and saw plaintext. OmegaDesk's relay only forwards tunnel ciphertext between
//!   two identity keys, so the agent, which holds the encoded frames and the keyframe flags
//!   the `.odrec` index needs, records.
//! - `kasmtech_KasmVNC/common/rfb/ServerCore.cxx` (`DLP_ClipSendMax`, `DLP_ClipAcceptMax`):
//!   clipboard byte limits per direction, enforced before the data moves.

use std::fs::File;
use std::io::{BufWriter, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use bytes::Bytes;
use omegadesk_control::PeerInfo;
use omegadesk_identity::DeviceId;
use omegadesk_policy::{
    AuditComponent, AuditEvent, AuditKind, AuditLog, AuditOutcome, BruteForceGuard,
    ConnectionMfaChallenge, ConnectionMfaVerifier, MfaError, SessionDecision, parse_os_family,
    unix_millis,
};
use omegadesk_protocol::v1::{
    Envelope, ErrorCode, Hello, MfaRequired, VideoFrame, envelope::Payload,
};
use omegadesk_recording::{OdrecRecord, OdrecStreamWriter, RecordFlags, RecordType};
use omegadesk_session::dlp::WatermarkConfig;
use omegadesk_session::dlp::{ClipboardDirection, DlpEnforcer, DlpPolicy, DlpViolation};
use omegadesk_transport::{EnvelopeReader, SendStream, send_envelope};
use prost::Message;
use rand_core::{OsRng, RngCore};
use tracing::{info, warn};
use zeroize::Zeroizing;

/// Wrong TOTP codes allowed per challenge before the connection is rejected.
const MFA_ATTEMPTS_PER_CHALLENGE: u32 = 3;

/// Consecutive MFA failures (across connections) that lock the peer out.
const MFA_LOCKOUT_FAILURES: u32 = 5;

/// Lockout duration after [`MFA_LOCKOUT_FAILURES`] (RustDesk and Guacamole use minutes).
const MFA_LOCKOUT: Duration = Duration::from_secs(300);

/// Time the client has to answer a challenge; also the challenge's validity.
const MFA_RESPONSE_TIMEOUT: Duration = Duration::from_secs(120);

/// Pause after a wrong code, mirroring the wrong-password delay of the handshake.
const WRONG_CODE_DELAY: Duration = Duration::from_millis(500);

/// Alpha of the forensic watermark (`0..=255`); legible without hiding the desktop.
const WATERMARK_OPACITY: u8 = 96;

/// Buffer in front of the recording file; the OS page cache absorbs the actual disk I/O.
const RECORDING_BUFFER: usize = 1 << 20;

/// Agent-wide authorization settings from the command line.
#[derive(Debug)]
pub struct AccessConfig {
    /// `--name`, written into recordings and audit events.
    pub agent_name: String,
    /// This agent's identity, the target device of MFA challenges.
    pub agent_id: DeviceId,
    /// Decoded `--totp-secret`; without it a policy that requires MFA rejects the session.
    pub totp_secret: Option<Zeroizing<Vec<u8>>>,
    /// `--recordings-dir`; without it a policy that requires recording rejects the session.
    pub recordings_dir: Option<PathBuf>,
    /// `--audit-log`.
    pub audit: Option<Arc<AuditLog>>,
}

/// Why the handshake must reject the client; the handshake sends it as a protocol `Error`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Rejection {
    pub(crate) code: ErrorCode,
    pub(crate) message: String,
}

impl Rejection {
    fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for Rejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}: {}", self.code, self.message)
    }
}

/// Shared across every session of the agent: MFA challenge state and the brute-force guard.
#[derive(Debug)]
pub struct AccessControl {
    config: AccessConfig,
    mfa: Mutex<ConnectionMfaVerifier>,
    guard: Mutex<BruteForceGuard>,
}

/// Identity of the connecting peer as the handshake established it.
struct PeerContext {
    /// `fqdn (ID ...)` on the mesh, `ID ...` or `no identity` on the LAN.
    label: String,
    /// Policy owner of the peer, or its device ID when it has none.
    user: String,
    /// Device ID string, the brute-force subject.
    subject: String,
    decision: Option<SessionDecision>,
}

impl AccessControl {
    /// Creates shared policy, MFA and audit state for all sessions of one host.
    #[must_use]
    pub fn new(config: AccessConfig) -> Self {
        Self {
            config,
            mfa: Mutex::new(ConnectionMfaVerifier::new()),
            guard: Mutex::new(BruteForceGuard::new(
                MFA_LOCKOUT_FAILURES,
                u64::try_from(MFA_LOCKOUT.as_millis()).unwrap_or(u64::MAX),
            )),
        }
    }

    fn audit(&self, event: &AuditEvent) {
        if let Some(log) = &self.config.audit
            && let Err(error) = log.append(event)
        {
            warn!(path = log.path(), %error, "audit event not written");
        }
    }

    fn event(kind: AuditKind, outcome: AuditOutcome) -> AuditEvent {
        AuditEvent::new(AuditComponent::Agent, kind, outcome)
    }

    /// Authorizes the client whose valid `Hello` (password already checked) arrived on the
    /// control stream from `remote`, running the TOTP step-up over that stream when the
    /// policy requires it. `peer` is the netmap entry owning `remote` (`None` on the LAN).
    ///
    /// # Errors
    ///
    /// Returns the [`Rejection`] to send to the client; every rejection is audited.
    #[allow(
        clippy::too_many_lines,
        reason = "one linear pass over the policy decision, in the order the checks apply"
    )]
    pub(crate) async fn authorize(
        &self,
        control_send: &mut SendStream,
        control: &mut EnvelopeReader,
        hello: &Hello,
        peer: Option<&PeerInfo>,
        remote: SocketAddr,
    ) -> Result<SessionAccess, Rejection> {
        let context = Self::identify(hello, peer).inspect_err(|rejection| {
            self.audit(
                &Self::event(AuditKind::SessionDenied, AuditOutcome::Denied)
                    .actor(describe_device(&hello.device_public_key))
                    .remote(&remote)
                    .detail(rejection.message.clone()),
            );
        })?;
        let denied = |message: String, code: ErrorCode| {
            self.audit(
                &Self::event(AuditKind::SessionDenied, AuditOutcome::Denied)
                    .actor(context.label.clone())
                    .remote(&remote)
                    .detail(message.clone()),
            );
            Rejection::new(code, message)
        };

        if let Some(decision) = &context.decision {
            if !decision.allowed {
                return Err(denied(
                    "the coordinator policy does not allow this device to open a session"
                        .to_owned(),
                    ErrorCode::PolicyDenied,
                ));
            }
            let os = hello.posture.as_ref().and_then(|p| {
                parse_os_family(&p.os_family)
                    .map(|family| (family, (p.os_major, p.os_minor, p.os_patch)))
            });
            let violations = decision.posture.evaluate(os, remote.ip());
            if !violations.is_empty() {
                let detail = violations
                    .iter()
                    .map(|v| format!("{v:?}"))
                    .collect::<Vec<_>>()
                    .join("; ");
                return Err(denied(
                    format!("device posture rejected by policy: {detail}"),
                    ErrorCode::PostureRejected,
                ));
            }
            if decision.require_mfa {
                self.step_up(control_send, control, &context, remote)
                    .await?;
            }
            if decision.record && self.config.recordings_dir.is_none() {
                return Err(denied(
                    "policy requires session recording but the agent has no --recordings-dir"
                        .to_owned(),
                    ErrorCode::Internal,
                ));
            }
        }

        let session_id = random_hex(8);
        let started_unix_ms = unix_millis();
        let decision = context.decision.clone().unwrap_or_default();
        let recorder = match (&self.config.recordings_dir, decision.record) {
            (Some(dir), true) => Some(
                Recorder::open(
                    dir,
                    &self.config.agent_name,
                    &context,
                    remote,
                    &session_id,
                    started_unix_ms,
                )
                .map_err(|error| {
                    denied(
                        format!("session recording could not be started: {error}"),
                        ErrorCode::Internal,
                    )
                })?,
            ),
            _ => None,
        };
        if let Some(recorder) = &recorder {
            self.audit(
                &Self::event(AuditKind::RecordingStarted, AuditOutcome::Ok)
                    .actor(context.label.clone())
                    .session(session_id.clone())
                    .detail(recorder.path.display().to_string()),
            );
        }
        let dlp = (decision.max_clipboard_copy_bytes.is_some()
            || decision.max_clipboard_paste_bytes.is_some())
        .then(|| {
            Mutex::new(DlpEnforcer::new(DlpPolicy {
                max_copy_from_host_bytes: to_usize(decision.max_clipboard_copy_bytes),
                max_paste_to_host_bytes: to_usize(decision.max_clipboard_paste_bytes),
                max_keystrokes_per_sec: 0,
                redacted_regions: Vec::new(),
            }))
        });
        let watermark = decision.watermark.then(|| WatermarkConfig {
            user_id: context.user.clone(),
            client_ip: remote.ip().to_string(),
            session_id: session_id.clone(),
            opacity: WATERMARK_OPACITY,
        });
        self.audit(
            &Self::event(AuditKind::SessionConnected, AuditOutcome::Ok)
                .actor(context.label.clone())
                .target(self.config.agent_name.clone())
                .remote(&remote)
                .session(session_id.clone())
                .detail(format!(
                    "mfa={} record={} watermark={} clipboard_copy={:?} clipboard_paste={:?}",
                    decision.require_mfa,
                    recorder.is_some(),
                    watermark.is_some(),
                    decision.max_clipboard_copy_bytes,
                    decision.max_clipboard_paste_bytes
                )),
        );
        info!(
            "session {session_id} with {} authorized (mfa {}, recording {}, watermark {})",
            context.label,
            decision.require_mfa,
            recorder.is_some(),
            watermark.is_some()
        );
        Ok(SessionAccess {
            inner: Arc::new(SessionInner {
                session_id,
                peer_label: context.label,
                remote,
                audit: self.config.audit.clone(),
                started: Instant::now(),
                dlp,
                watermark,
                recorder: Mutex::new(recorder),
            }),
        })
    }

    /// Binds the `Hello` to the mesh identity and extracts the policy decision.
    fn identify(hello: &Hello, peer: Option<&PeerInfo>) -> Result<PeerContext, Rejection> {
        let Some(peer) = peer else {
            let label = describe_device(&hello.device_public_key);
            return Ok(PeerContext {
                subject: label.clone(),
                user: label.clone(),
                label,
                decision: None,
            });
        };
        if hello.device_public_key.as_ref() != peer.public.signing_key_bytes() {
            return Err(Rejection::new(
                ErrorCode::Unauthorized,
                "the device key in Hello does not match the mesh identity of the connection",
            ));
        }
        let id = peer.id().to_string();
        Ok(PeerContext {
            label: format!("{} ({id})", peer.fqdn),
            user: if peer.user.is_empty() {
                id.clone()
            } else {
                peer.user.clone()
            },
            subject: id,
            decision: peer.session.clone(),
        })
    }

    /// Runs the TOTP step-up: issues a challenge, sends [`MfaRequired`] and verifies the
    /// client's `MfaResponse`s under the brute-force guard.
    #[allow(
        clippy::too_many_lines,
        reason = "the challenge loop and every failure path are audited inline"
    )]
    async fn step_up(
        &self,
        control_send: &mut SendStream,
        control: &mut EnvelopeReader,
        context: &PeerContext,
        remote: SocketAddr,
    ) -> Result<(), Rejection> {
        let mfa_event = |kind: AuditKind, outcome: AuditOutcome, detail: String| {
            Self::event(kind, outcome)
                .actor(context.label.clone())
                .remote(&remote)
                .detail(detail)
        };
        let now = unix_millis();
        if let Err(error) = self.guard().check_allowed(&context.subject, now) {
            self.audit(&mfa_event(
                AuditKind::MfaFailed,
                AuditOutcome::Denied,
                error.to_string(),
            ));
            return Err(Rejection::new(ErrorCode::MfaFailed, error.to_string()));
        }
        let Some(secret) = &self.config.totp_secret else {
            let message = "policy requires MFA but the agent has no --totp-secret";
            self.audit(&mfa_event(
                AuditKind::SessionDenied,
                AuditOutcome::Failed,
                message.to_owned(),
            ));
            return Err(Rejection::new(ErrorCode::Internal, message));
        };

        let challenge_id = random_hex(16);
        self.mfa().issue(ConnectionMfaChallenge {
            challenge_id: challenge_id.clone(),
            user_id: context.subject.clone(),
            target_device: self.config.agent_id,
            expires_at_ms: now.saturating_add(
                u64::try_from(MFA_RESPONSE_TIMEOUT.as_millis()).unwrap_or(u64::MAX),
            ),
        });
        self.audit(&mfa_event(
            AuditKind::MfaChallenged,
            AuditOutcome::Ok,
            format!("challenge {challenge_id}"),
        ));

        for attempt in 0..MFA_ATTEMPTS_PER_CHALLENGE {
            let required = Envelope {
                payload: Some(Payload::MfaRequired(MfaRequired {
                    challenge_id: challenge_id.clone(),
                    method: "totp".to_owned(),
                    attempts_left: MFA_ATTEMPTS_PER_CHALLENGE - attempt,
                })),
            };
            send_envelope(control_send, &required)
                .await
                .map_err(|e| Rejection::new(ErrorCode::Internal, e.to_string()))?;

            let response = match tokio::time::timeout(MFA_RESPONSE_TIMEOUT, control.next()).await {
                Ok(Ok(Some(Envelope {
                    payload: Some(Payload::MfaResponse(response)),
                }))) => response,
                Ok(Ok(Some(_))) => {
                    return Err(Rejection::new(
                        ErrorCode::MfaFailed,
                        "expected an MfaResponse to the pending challenge",
                    ));
                }
                Ok(Ok(None)) => {
                    return Err(Rejection::new(
                        ErrorCode::MfaFailed,
                        "client closed the control stream during MFA",
                    ));
                }
                Ok(Err(error)) => {
                    return Err(Rejection::new(ErrorCode::Internal, error.to_string()));
                }
                Err(_) => {
                    let message = "no MFA code received in time";
                    self.audit(&mfa_event(
                        AuditKind::MfaFailed,
                        AuditOutcome::Denied,
                        message.to_owned(),
                    ));
                    return Err(Rejection::new(ErrorCode::MfaFailed, message));
                }
            };
            if response.challenge_id != challenge_id {
                return Err(Rejection::new(
                    ErrorCode::MfaFailed,
                    "MfaResponse does not answer the pending challenge",
                ));
            }
            let now = unix_millis();
            let result = match parse_code(&response.code) {
                Some(code) => self
                    .mfa()
                    .verify_and_consume(&challenge_id, secret, code, now),
                None => Err(MfaError::InvalidCode),
            };
            match result {
                Ok(_grant) => {
                    self.guard().record_success(&context.subject);
                    self.audit(&mfa_event(
                        AuditKind::MfaOk,
                        AuditOutcome::Ok,
                        format!("challenge {challenge_id}"),
                    ));
                    return Ok(());
                }
                Err(error @ (MfaError::InvalidCode | MfaError::CodeAlreadyUsed { .. })) => {
                    let lockout = self.guard().record_failure(&context.subject, now).err();
                    self.audit(&mfa_event(
                        AuditKind::MfaFailed,
                        AuditOutcome::Denied,
                        error.to_string(),
                    ));
                    tokio::time::sleep(WRONG_CODE_DELAY).await;
                    if let Some(lockout) = lockout {
                        return Err(Rejection::new(ErrorCode::MfaFailed, lockout.to_string()));
                    }
                }
                Err(error) => {
                    self.audit(&mfa_event(
                        AuditKind::MfaFailed,
                        AuditOutcome::Denied,
                        error.to_string(),
                    ));
                    return Err(Rejection::new(ErrorCode::MfaFailed, error.to_string()));
                }
            }
        }
        Err(Rejection::new(
            ErrorCode::MfaFailed,
            "too many wrong MFA codes for this connection",
        ))
    }

    fn mfa(&self) -> std::sync::MutexGuard<'_, ConnectionMfaVerifier> {
        self.mfa.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn guard(&self) -> std::sync::MutexGuard<'_, BruteForceGuard> {
        self.guard.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Per-session enforcement state handed to the video and control loops. Cheap to clone.
#[derive(Clone)]
pub(crate) struct SessionAccess {
    inner: Arc<SessionInner>,
}

struct SessionInner {
    session_id: String,
    peer_label: String,
    remote: SocketAddr,
    audit: Option<Arc<AuditLog>>,
    started: Instant,
    dlp: Option<Mutex<DlpEnforcer>>,
    watermark: Option<WatermarkConfig>,
    recorder: Mutex<Option<Recorder>>,
}

impl SessionAccess {
    /// Watermark to compose into every frame, when the policy asks for one.
    pub(crate) fn watermark(&self) -> Option<WatermarkConfig> {
        self.inner.watermark.clone()
    }

    /// Whether the session is being recorded (still open).
    #[cfg(test)]
    pub(crate) fn is_recording(&self) -> bool {
        self.inner.recorder().is_some()
    }

    /// Appends an encoded video frame to the recording. Returns `true` when the recorder
    /// wants the encoder to produce a keyframe soon (the `.odrec` seek index only grows on
    /// keyframes). A write failure closes the recording, is audited and logged, and the
    /// session continues: the operator sees `recording_finished` with outcome `failed`.
    pub(crate) fn record_frame(&self, frame: &VideoFrame) -> bool {
        let mut slot = self.inner.recorder();
        let Some(recorder) = slot.as_mut() else {
            return false;
        };
        let timestamp_ms = unix_millis();
        let flags = if frame.keyframe {
            RecordFlags::KEYFRAME
        } else {
            RecordFlags::NONE
        };
        let record = OdrecRecord {
            record_type: RecordType::FrameData,
            flags,
            timestamp_ms,
            payload: Bytes::from(frame.encode_to_vec()),
        };
        match recorder.writer.append(&record) {
            Ok(_) => recorder.writer.keyframe_hint_due(timestamp_ms),
            Err(error) => {
                let path = recorder.path.display().to_string();
                warn!("recording {path} failed: {error}; the session continues unrecorded");
                *slot = None;
                drop(slot);
                self.audit(
                    AuditEvent::new(
                        AuditComponent::Agent,
                        AuditKind::RecordingFinished,
                        AuditOutcome::Failed,
                    )
                    .detail(format!("{path}: {error}")),
                );
                false
            }
        }
    }

    /// Appends a client input or clipboard message to the recording (flag `FROM_USER`).
    pub(crate) fn record_input(&self, payload: &Payload) {
        let record_type = match payload {
            Payload::KeyEvent(_) | Payload::PointerEvent(_) => RecordType::InputEvent,
            Payload::ClipboardEvent(_) => RecordType::ClipboardEvent,
            Payload::Hello(_)
            | Payload::HelloAck(_)
            | Payload::Ping(_)
            | Payload::Pong(_)
            | Payload::Error(_)
            | Payload::RequestKeyframe(_)
            | Payload::FrameAck(_)
            | Payload::InvalidateRefFrames(_)
            | Payload::VideoFrame(_)
            | Payload::AudioFrame(_)
            | Payload::DisplayList(_)
            | Payload::SelectDisplay(_)
            | Payload::FileTransferOffer(_)
            | Payload::FileTransferChunk(_)
            | Payload::FileTransferAck(_)
            | Payload::ChatMessage(_)
            | Payload::TerminalData(_)
            | Payload::TerminalResize(_)
            | Payload::MfaRequired(_)
            | Payload::MfaResponse(_) => return,
        };
        let mut slot = self.inner.recorder();
        let Some(recorder) = slot.as_mut() else {
            return;
        };
        let envelope = Envelope {
            payload: Some(payload.clone()),
        };
        let record = OdrecRecord {
            record_type,
            flags: RecordFlags::FROM_USER,
            timestamp_ms: unix_millis(),
            payload: Bytes::from(envelope.encode_to_vec()),
        };
        if let Err(error) = recorder.writer.append(&record) {
            warn!("recording {} failed: {error}", recorder.path.display());
            *slot = None;
        }
    }

    /// Applies the clipboard limits of the policy to a transfer of `len` bytes.
    ///
    /// # Errors
    ///
    /// Returns the [`DlpViolation`] (also audited) when the transfer must be dropped.
    pub(crate) fn check_clipboard(
        &self,
        direction: ClipboardDirection,
        len: usize,
    ) -> Result<(), DlpViolation> {
        let Some(dlp) = &self.inner.dlp else {
            return Ok(());
        };
        let result = dlp
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .check_clipboard(direction, len);
        if let Err(violation) = &result {
            warn!("clipboard transfer blocked by policy: {violation}");
            self.audit(
                AuditEvent::new(
                    AuditComponent::Agent,
                    AuditKind::DlpBlocked,
                    AuditOutcome::Denied,
                )
                .detail(format!("{direction:?}: {violation}")),
            );
        }
        result
    }

    /// Closes the recording and audits the end of the session. Call once.
    pub(crate) fn finish(&self, outcome: &str) {
        let recorder = self.inner.recorder().take();
        if let Some(recorder) = recorder {
            let path = recorder.path.display().to_string();
            let records = recorder.writer.record_count() + 1;
            let (kind_outcome, detail) = match recorder.writer.finish(unix_millis()) {
                Ok(_) => (AuditOutcome::Ok, format!("{path}: {records} records")),
                Err(error) => (AuditOutcome::Failed, format!("{path}: {error}")),
            };
            info!("recording closed: {detail}");
            self.audit(
                AuditEvent::new(
                    AuditComponent::Agent,
                    AuditKind::RecordingFinished,
                    kind_outcome,
                )
                .detail(detail),
            );
        }
        self.audit(
            AuditEvent::new(
                AuditComponent::Agent,
                AuditKind::SessionDisconnected,
                AuditOutcome::Ok,
            )
            .remote(&self.inner.remote)
            .detail(format!(
                "{outcome} after {} s",
                self.inner.started.elapsed().as_secs()
            )),
        );
    }

    fn audit(&self, event: AuditEvent) {
        if let Some(log) = &self.inner.audit {
            let event = event
                .actor(self.inner.peer_label.clone())
                .session(self.inner.session_id.clone());
            if let Err(error) = log.append(&event) {
                warn!(path = log.path(), %error, "audit event not written");
            }
        }
    }
}

impl SessionInner {
    fn recorder(&self) -> std::sync::MutexGuard<'_, Option<Recorder>> {
        self.recorder.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Open `.odrec` file of one session.
struct Recorder {
    writer: OdrecStreamWriter<BufWriter<File>>,
    path: PathBuf,
}

impl Recorder {
    /// Creates `<dir>/<start>-<agent>-<peer id>-<session>.odrec` and writes the metadata record.
    fn open(
        dir: &Path,
        agent_name: &str,
        context: &PeerContext,
        remote: SocketAddr,
        session_id: &str,
        started_unix_ms: u64,
    ) -> std::io::Result<Self> {
        std::fs::create_dir_all(dir)?;
        let path = dir.join(format!(
            "{started_unix_ms}-{}-{}-{session_id}.odrec",
            filename_label(agent_name),
            filename_label(&context.subject)
        ));
        let file = File::options().create_new(true).write(true).open(&path)?;
        let mut writer = OdrecStreamWriter::new(BufWriter::with_capacity(RECORDING_BUFFER, file))?;
        let metadata = serde_json::json!({
            "magic": "OmegaDeskSession",
            "version": 1,
            "session_id": session_id,
            "started_unix_ms": started_unix_ms,
            "agent": agent_name,
            "peer": context.label,
            "user": context.user,
            "remote": remote.to_string(),
            "protocol": "desktop",
            "frame_payload": "omegadesk.v1.VideoFrame",
            "input_payload": "omegadesk.v1.Envelope",
        });
        writer.append(&OdrecRecord {
            record_type: RecordType::Metadata,
            flags: RecordFlags::NONE,
            timestamp_ms: started_unix_ms,
            payload: Bytes::from(metadata.to_string()),
        })?;
        Ok(Self { writer, path })
    }
}

/// Keeps `[A-Za-z0-9._-]` and replaces the rest, for file names (MeshCentral `makeFilename`).
fn filename_label(raw: &str) -> String {
    let mut out: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect();
    out.truncate(48);
    if out.is_empty() {
        "node".to_owned()
    } else {
        out
    }
}

fn to_usize(limit: Option<u64>) -> usize {
    limit.map_or(usize::MAX, |v| usize::try_from(v).unwrap_or(usize::MAX))
}

/// Parses a six-digit TOTP code (surrounding whitespace tolerated).
fn parse_code(text: &str) -> Option<u32> {
    let digits = text.trim();
    if digits.len() != 6 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

fn random_hex(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    OsRng.fill_bytes(&mut buf);
    data_encoding::HEXLOWER.encode(&buf)
}

/// Formats the peer's `DeviceId` from its 32-byte signing public key for logging.
pub(crate) fn describe_device(public_key: &[u8]) -> String {
    <[u8; 32]>::try_from(public_key).map_or_else(
        |_| "no identity".to_owned(),
        |key| format!("ID {}", DeviceId::from_signing_key(&key)),
    )
}

/// Decodes a base32 (RFC 4648) TOTP secret as printed by `--generate-totp-secret` or an
/// authenticator enrollment; spaces, hyphens and padding are ignored, case does not matter.
#[must_use]
pub fn decode_totp_secret(text: &str) -> Option<Zeroizing<Vec<u8>>> {
    let normalized: String = text
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-' && *c != '=')
        .map(|c| c.to_ascii_uppercase())
        .collect();
    let bytes = data_encoding::BASE32_NOPAD
        .decode(normalized.as_bytes())
        .ok()?;
    (bytes.len() >= 10).then(|| Zeroizing::new(bytes))
}

/// Generates a 20-byte TOTP secret encoded in base32.
#[must_use]
pub fn generate_totp_secret() -> String {
    let mut secret = [0u8; 20];
    OsRng.fill_bytes(&mut secret);
    data_encoding::BASE32_NOPAD.encode(&secret)
}

/// `otpauth://` URI an authenticator app enrolls from. The codes are HMAC-SHA256, six digits,
/// 30-second steps (`omegadesk_policy::compute_totp_sha256`).
#[must_use]
pub fn totp_uri(agent_name: &str, secret_base32: &str) -> String {
    format!(
        "otpauth://totp/OmegaDesk:{}?secret={secret_base32}&issuer=OmegaDesk&algorithm=SHA256&digits=6&period=30",
        filename_label(agent_name)
    )
}

/// Writes `text` to `writer`, used by the CLI for the generated secret (no `print!`: the
/// agent's stdout is reserved for this one deliberate output).
///
/// # Errors
///
/// Returns the writer's I/O error.
pub fn write_line(mut writer: impl Write, text: &str) -> std::io::Result<()> {
    writer.write_all(text.as_bytes())?;
    writer.write_all(b"\n")
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use omegadesk_codec::EncoderSettings;
    use omegadesk_identity::DeviceIdentity;
    use omegadesk_policy::{SessionPosture, compute_totp_sha256, parse_cidr};
    use omegadesk_protocol::PROTOCOL_VERSION;
    use omegadesk_protocol::v1::{
        Capabilities, ClipboardEvent, ClipboardFormat, DevicePosture, MfaResponse, VideoCodec,
    };
    use omegadesk_recording::parse_odrec_stream;
    use omegadesk_transport::{connect, server_endpoint};

    use super::*;
    use crate::capture_loop::EncoderChoice;
    use crate::session::SessionConfig;

    /// A fresh random TOTP secret, so no cryptographic key is hard-coded in the tests
    /// (`CodeQL` `rust/hardcoded-cryptographic-value`). The same bytes are given to the
    /// `AccessControl` under test and used to compute the codes the client sends.
    fn fresh_secret() -> Zeroizing<Vec<u8>> {
        decode_totp_secret(&generate_totp_secret()).expect("generated secret decodes")
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "omegadesk-agent-{tag}-{}-{}",
            std::process::id(),
            unix_millis()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn access(dir: &Path, totp_secret: Option<&[u8]>) -> Arc<AccessControl> {
        Arc::new(AccessControl::new(AccessConfig {
            agent_name: "test-agent".to_owned(),
            agent_id: DeviceIdentity::generate().id(),
            totp_secret: totp_secret.map(|s| Zeroizing::new(s.to_vec())),
            recordings_dir: Some(dir.join("recordings")),
            audit: Some(Arc::new(AuditLog::open(&dir.join("audit.jsonl")).unwrap())),
        }))
    }

    fn peer(client: &DeviceIdentity, decision: SessionDecision) -> PeerInfo {
        PeerInfo {
            public: client.public(),
            tenant: "acme".to_owned(),
            hostname: "viewer".to_owned(),
            fqdn: "viewer.omega".to_owned(),
            ipv4: Ipv4Addr::new(100, 64, 0, 9),
            ipv6: Ipv6Addr::LOCALHOST,
            endpoints: vec![],
            tags: vec!["tag:helpdesk".to_owned()],
            ephemeral: false,
            quicksupport_id: None,
            user: "alice@example.com".to_owned(),
            session: Some(decision),
        }
    }

    fn hello(client: &DeviceIdentity, password: &str) -> Envelope {
        Envelope {
            payload: Some(Payload::Hello(Hello {
                protocol_version: PROTOCOL_VERSION,
                device_public_key: client.public().signing_key_bytes().to_vec().into(),
                device_name: "viewer".to_owned(),
                capabilities: Some(Capabilities {
                    decoders: vec![VideoCodec::H264 as i32],
                    encoders: vec![],
                }),
                access_password: password.to_owned(),
                posture: Some(DevicePosture {
                    os_family: "windows".to_owned(),
                    os_major: 10,
                    os_minor: 0,
                    os_patch: 19_045,
                }),
            })),
        }
    }

    fn mfa_response(challenge_id: &str, code: &str) -> Envelope {
        Envelope {
            payload: Some(Payload::MfaResponse(MfaResponse {
                challenge_id: challenge_id.to_owned(),
                code: code.to_owned(),
            })),
        }
    }

    fn audit_kinds(dir: &Path) -> Vec<String> {
        std::fs::read_to_string(dir.join("audit.jsonl"))
            .unwrap()
            .lines()
            .map(|line| {
                serde_json::from_str::<serde_json::Value>(line).unwrap()["kind"]
                    .as_str()
                    .unwrap()
                    .to_owned()
            })
            .collect()
    }

    /// Starts an agent-side QUIC endpoint serving one session for `peer`, and a client
    /// connection to it. Returns the client's control streams and the agent task.
    async fn connect_pair(
        access: Arc<AccessControl>,
        peer: PeerInfo,
        password: &str,
    ) -> (
        SendStream,
        EnvelopeReader,
        omegadesk_transport::Connection,
        tokio::task::JoinHandle<anyhow::Result<()>>,
    ) {
        let (endpoint, fingerprint) = server_endpoint("127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = endpoint.local_addr().unwrap();
        let config = Arc::new(SessionConfig {
            name: "test-agent".to_owned(),
            device_public_key: DeviceIdentity::generate().public().signing_key_bytes(),
            password: password.to_owned(),
            monitor: 0,
            encoder: EncoderChoice::Software,
            settings: EncoderSettings {
                bitrate_bps: 1_000_000,
                max_fps: 5.0,
            },
            input: false,
            gate: None,
            clipboard: false,
            file_transfer: false,
            receive_dir: omegadesk_session::file_io::default_receive_dir(),
            send_files: Vec::new(),
            access,
        });
        let agent = tokio::spawn(async move {
            let incoming = endpoint.accept().await.unwrap();
            let connection = incoming.await.unwrap();
            crate::session::run(connection, config, Some(peer)).await
        });
        let (_client_endpoint, connection) = connect(addr, &fingerprint).await.unwrap();
        let (send, recv) = connection.open_bi().await.unwrap();
        (send, EnvelopeReader::new(recv), connection, agent)
    }

    /// MFA step-up round trip through the real handshake: wrong code, right code, `HelloAck`,
    /// then a clipboard paste over the DLP limit is blocked and the session is recorded.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::too_many_lines, reason = "one end-to-end scenario")]
    async fn mfa_step_up_dlp_and_recording_through_the_real_handshake() {
        let dir = temp_dir("mfa");
        let secret = fresh_secret();
        let access = access(&dir, Some(&secret));
        let client = DeviceIdentity::generate();
        let password = random_hex(16);
        let decision = SessionDecision {
            allowed: true,
            require_mfa: true,
            record: true,
            max_clipboard_copy_bytes: None,
            max_clipboard_paste_bytes: Some(4),
            watermark: true,
            posture: SessionPosture {
                min_os: vec![omegadesk_policy::posture::OsVersionRequirement {
                    family: omegadesk_policy::posture::OsFamily::Windows,
                    min_version: (10, 0, 19_045),
                }],
                networks: vec![parse_cidr("127.0.0.0/8").unwrap()],
            },
        };
        let (mut send, mut recv, connection, agent) =
            connect_pair(Arc::clone(&access), peer(&client, decision), &password).await;

        send_envelope(&mut send, &hello(&client, &password))
            .await
            .unwrap();
        let Some(Envelope {
            payload: Some(Payload::MfaRequired(required)),
        }) = recv.next().await.unwrap()
        else {
            panic!("expected MfaRequired");
        };
        assert_eq!(required.method, "totp");
        assert_eq!(required.attempts_left, 3);

        // A wrong code is answered with a fresh prompt, not a rejection.
        let now_secs = unix_millis() / 1_000;
        let good = compute_totp_sha256(&secret, now_secs);
        let wrong = format!("{:06}", (good + 1) % 1_000_000);
        send_envelope(&mut send, &mfa_response(&required.challenge_id, &wrong))
            .await
            .unwrap();
        let Some(Envelope {
            payload: Some(Payload::MfaRequired(again)),
        }) = recv.next().await.unwrap()
        else {
            panic!("expected a second MfaRequired");
        };
        assert_eq!(again.challenge_id, required.challenge_id);
        assert_eq!(again.attempts_left, 2);

        send_envelope(
            &mut send,
            &mfa_response(&required.challenge_id, &format!("{good:06}")),
        )
        .await
        .unwrap();
        let Some(Envelope {
            payload: Some(Payload::HelloAck(ack)),
        }) = recv.next().await.unwrap()
        else {
            panic!("expected HelloAck after the right code");
        };
        assert_eq!(ack.device_name, "test-agent");

        // DLP: a 10-byte paste exceeds the 4-byte limit and is dropped; 3 bytes pass.
        for len in [10usize, 3] {
            send_envelope(
                &mut send,
                &Envelope {
                    payload: Some(Payload::ClipboardEvent(ClipboardEvent {
                        format: ClipboardFormat::Utf8Text as i32,
                        data: vec![b'x'; len].into(),
                        content_sha256: Bytes::new(),
                    })),
                },
            )
            .await
            .unwrap();
        }
        // Give the agent time to process the control messages, then end the session.
        tokio::time::sleep(Duration::from_millis(300)).await;
        connection.close(0u32.into(), b"done");
        let _ = tokio::time::timeout(Duration::from_secs(10), agent).await;

        let kinds = audit_kinds(&dir);
        assert_eq!(
            kinds.iter().filter(|k| *k == "mfa_failed").count(),
            1,
            "{kinds:?}"
        );
        assert!(kinds.contains(&"mfa_challenged".to_owned()));
        assert!(kinds.contains(&"mfa_ok".to_owned()));
        assert!(kinds.contains(&"session_connected".to_owned()));
        assert!(kinds.contains(&"recording_started".to_owned()));
        assert_eq!(kinds.iter().filter(|k| *k == "dlp_blocked").count(), 1);
        assert!(kinds.contains(&"recording_finished".to_owned()));
        assert_eq!(
            kinds.last().map(String::as_str),
            Some("session_disconnected")
        );

        // The recording parses with `omegadesk-recording`: metadata first, the clipboard
        // record that passed DLP (flagged FROM_USER), end-of-stream last.
        let recordings: Vec<PathBuf> = std::fs::read_dir(dir.join("recordings"))
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        assert_eq!(recordings.len(), 1);
        let bytes = std::fs::read(&recordings[0]).unwrap();
        let records = parse_odrec_stream(&bytes).unwrap();
        assert_eq!(records[0].record_type, RecordType::Metadata);
        let meta: serde_json::Value = serde_json::from_slice(&records[0].payload).unwrap();
        assert_eq!(meta["magic"], "OmegaDeskSession");
        assert_eq!(meta["user"], "alice@example.com");
        let clipboard: Vec<_> = records
            .iter()
            .filter(|r| r.record_type == RecordType::ClipboardEvent)
            .collect();
        assert_eq!(
            clipboard.len(),
            1,
            "only the paste under the limit is recorded"
        );
        assert!(clipboard[0].flags.contains(RecordFlags::FROM_USER));
        let envelope = Envelope::decode(clipboard[0].payload.as_ref()).unwrap();
        assert!(matches!(
            envelope.payload,
            Some(Payload::ClipboardEvent(ref e)) if e.data.len() == 3
        ));
        assert_eq!(records.last().unwrap().record_type, RecordType::EndOfStream);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A denied grant, a posture failure, a device-key mismatch and repeated wrong codes are
    /// each rejected with the right error code, and the brute-force guard locks the peer out.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rejections_carry_their_reason_and_wrong_codes_lock_the_peer_out() {
        let dir = temp_dir("deny");
        let secret = fresh_secret();
        let access = access(&dir, Some(&secret));
        let client = DeviceIdentity::generate();
        let password = random_hex(16);

        // Policy denies the session.
        let (mut send, mut recv, conn, agent) = connect_pair(
            Arc::clone(&access),
            peer(&client, SessionDecision::DENIED),
            &password,
        )
        .await;
        send_envelope(&mut send, &hello(&client, &password))
            .await
            .unwrap();
        expect_error(&mut recv, &conn, ErrorCode::PolicyDenied).await;
        assert!(agent.await.unwrap().is_err());

        // Posture: the policy wants Windows 11 and the client reports Windows 10.
        let mut strict = SessionDecision::DENIED;
        strict.allowed = true;
        strict
            .posture
            .min_os
            .push(omegadesk_policy::posture::OsVersionRequirement {
                family: omegadesk_policy::posture::OsFamily::Windows,
                min_version: (10, 0, 22_000),
            });
        let (mut send, mut recv, conn, agent) =
            connect_pair(Arc::clone(&access), peer(&client, strict), &password).await;
        send_envelope(&mut send, &hello(&client, &password))
            .await
            .unwrap();
        let message = expect_error(&mut recv, &conn, ErrorCode::PostureRejected).await;
        assert!(message.contains("OutdatedOs"), "{message}");
        assert!(agent.await.unwrap().is_err());

        // The Hello claims another device key than the mesh identity of the connection.
        let mut allow = SessionDecision::DENIED;
        allow.allowed = true;
        let impostor = DeviceIdentity::generate();
        let (mut send, mut recv, conn, agent) =
            connect_pair(Arc::clone(&access), peer(&client, allow.clone()), &password).await;
        send_envelope(&mut send, &hello(&impostor, &password))
            .await
            .unwrap();
        expect_error(&mut recv, &conn, ErrorCode::Unauthorized).await;
        assert!(agent.await.unwrap().is_err());

        // Three wrong codes end the connection; two more on the next one lock the peer out
        // (five failures), and a further connection is refused before any challenge.
        let mut mfa = allow;
        mfa.require_mfa = true;
        let wrong_codes = |count: u32| {
            let access = Arc::clone(&access);
            let client = &client;
            let mfa = mfa.clone();
            let password = password.clone();
            async move {
                let (mut send, mut recv, conn, agent) =
                    connect_pair(access, peer(client, mfa), &password).await;
                send_envelope(&mut send, &hello(client, &password))
                    .await
                    .unwrap();
                for _ in 0..count {
                    let Some(Envelope {
                        payload: Some(Payload::MfaRequired(required)),
                    }) = recv.next().await.unwrap()
                    else {
                        panic!("expected MfaRequired");
                    };
                    send_envelope(&mut send, &mfa_response(&required.challenge_id, "000000"))
                        .await
                        .unwrap();
                }
                let message = expect_error(&mut recv, &conn, ErrorCode::MfaFailed).await;
                let _ = agent.await;
                message
            }
        };
        let message = wrong_codes(3).await;
        assert!(message.contains("too many"), "{message}");
        let message = wrong_codes(2).await;
        assert!(message.contains("locked out"), "{message}");
        let message = wrong_codes(0).await;
        assert!(message.contains("locked out"), "{message}");

        let kinds = audit_kinds(&dir);
        assert_eq!(kinds.iter().filter(|k| *k == "session_denied").count(), 3);
        assert_eq!(kinds.iter().filter(|k| *k == "mfa_failed").count(), 6);
        assert!(!kinds.contains(&"session_connected".to_owned()));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Frames recorded through `SessionAccess` come back through `omegadesk-recording` with
    /// the keyframe flags the player seeks on and decodable `VideoFrame` payloads.
    #[tokio::test]
    async fn recorded_frames_parse_with_the_recording_crate() {
        let dir = temp_dir("frames");
        let access = access(&dir, None);
        let client = DeviceIdentity::generate();
        let mut decision = SessionDecision::DENIED;
        decision.allowed = true;
        decision.record = true;
        let peer = peer(&client, decision);
        let remote: SocketAddr = "127.0.0.1:4242".parse().unwrap();
        let mut streams = Loopback::open().await;
        let Some(Payload::Hello(hello_msg)) = hello(&client, &random_hex(16)).payload else {
            unreachable!()
        };
        let session = access
            .authorize(
                &mut streams.send,
                &mut streams.recv,
                &hello_msg,
                Some(&peer),
                remote,
            )
            .await
            .unwrap();
        assert!(session.is_recording());
        assert!(session.watermark().is_none());

        let frame = |sequence: u64, keyframe: bool| VideoFrame {
            sequence,
            captured_at_micros: sequence * 16_000,
            host_processing_micros: 1_000,
            codec: VideoCodec::H264 as i32,
            keyframe,
            display_index: 0,
            width: 1280,
            height: 720,
            data: vec![u8::try_from(sequence % 251).unwrap(); 2_000].into(),
        };
        // The first frame (no keyframe indexed yet) asks for a keyframe.
        assert!(session.record_frame(&frame(1, false)));
        assert!(!session.record_frame(&frame(2, true)));
        for i in 3..40 {
            session.record_frame(&frame(i, false));
        }
        session.record_input(&Payload::KeyEvent(omegadesk_protocol::v1::KeyEvent {
            hid_usage: 4,
            keysym: 0x61,
            pressed: true,
            modifiers: 0,
        }));
        session.finish("test");

        let recordings: Vec<PathBuf> = std::fs::read_dir(dir.join("recordings"))
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        assert_eq!(recordings.len(), 1);
        assert!(recordings[0].extension().is_some_and(|e| e == "odrec"));
        let records = parse_odrec_stream(&std::fs::read(&recordings[0]).unwrap()).unwrap();
        // metadata + 39 frames + 1 input + end
        assert_eq!(records.len(), 42);
        let frames: Vec<_> = records
            .iter()
            .filter(|r| r.record_type == RecordType::FrameData)
            .collect();
        assert_eq!(frames.len(), 39);
        assert!(!frames[0].flags.contains(RecordFlags::KEYFRAME));
        assert!(frames[1].flags.contains(RecordFlags::KEYFRAME));
        let decoded = VideoFrame::decode(frames[1].payload.as_ref()).unwrap();
        assert_eq!(decoded.sequence, 2);
        assert!(decoded.keyframe);
        assert_eq!(decoded.width, 1280);
        assert!(records[40].flags.contains(RecordFlags::FROM_USER));
        assert_eq!(records[40].record_type, RecordType::InputEvent);
        assert_eq!(records[41].record_type, RecordType::EndOfStream);
        // Timestamps never go backwards: the player schedules frames by them.
        assert!(
            records
                .windows(2)
                .all(|w| w[0].timestamp_ms <= w[1].timestamp_ms)
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Reads the rejection the agent sends and closes the client side of the connection.
    async fn expect_error(
        recv: &mut EnvelopeReader,
        connection: &omegadesk_transport::Connection,
        code: ErrorCode,
    ) -> String {
        let Some(Envelope {
            payload: Some(Payload::Error(error)),
        }) = recv.next().await.unwrap()
        else {
            panic!("expected Error({code:?})");
        };
        assert_eq!(error.code, code as i32, "{}", error.message);
        connection.close(0u32.into(), b"rejected");
        error.message
    }

    /// The agent side of a QUIC control stream on loopback, for exercising `authorize`
    /// without a session; the client side is kept alive alongside.
    struct Loopback {
        send: SendStream,
        recv: EnvelopeReader,
        _keep: (
            omegadesk_transport::Endpoint,
            omegadesk_transport::Connection,
            omegadesk_transport::Connection,
            SendStream,
        ),
    }

    impl Loopback {
        async fn open() -> Self {
            let (endpoint, fingerprint) = server_endpoint("127.0.0.1:0".parse().unwrap()).unwrap();
            let addr = endpoint.local_addr().unwrap();
            let accept = tokio::spawn(async move {
                let connection = endpoint.accept().await.unwrap().await.unwrap();
                let (send, recv) = connection.accept_bi().await.unwrap();
                (connection, send, recv)
            });
            let (client_endpoint, connection) = connect(addr, &fingerprint).await.unwrap();
            let (mut client_send, _client_recv) = connection.open_bi().await.unwrap();
            // A stream only exists for the peer once a byte is sent on it.
            client_send.write_all(&[0]).await.unwrap();
            let (server_connection, send, recv) = accept.await.unwrap();
            Self {
                send,
                recv: EnvelopeReader::new(recv),
                _keep: (client_endpoint, connection, server_connection, client_send),
            }
        }
    }

    #[test]
    fn totp_secret_round_trips_and_codes_are_six_digits() {
        let secret = generate_totp_secret();
        let decoded = decode_totp_secret(&secret).unwrap();
        assert_eq!(decoded.len(), 20);
        assert_eq!(
            decode_totp_secret(&format!(
                "{} {}=",
                secret[..8].to_ascii_lowercase(),
                &secret[8..]
            ))
            .unwrap(),
            decoded
        );
        assert!(decode_totp_secret("short").is_none());
        assert!(decode_totp_secret("not base32 !!").is_none());
        assert!(
            totp_uri("Office PC", &secret)
                .starts_with("otpauth://totp/OmegaDesk:Office_PC?secret=")
        );
        assert_eq!(parse_code(" 012345 "), Some(12_345));
        assert_eq!(parse_code("12345"), None);
        assert_eq!(parse_code("12345a"), None);
        assert_eq!(filename_label("ID abc/def"), "ID_abc_def");
    }
}
