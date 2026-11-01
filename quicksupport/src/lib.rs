//! QuickSupport single-executable core: 9-digit formatted ID, brute-force-resistant
//! temporary password rotation, per-client permission flags, and layered remote-user
//! consent. With the `host` feature (on by default) the [`host`] module adds the
//! mesh node and the session loop that the `omegadesk-quicksupport` binary runs.
//!
//! Reference implementations:
//! - `ClassicOldSong_Apollo/src/crypto.h` (`enum class PERM: uint32_t` with 3 8-bit
//!   groups: input `1 << 8..12`, operation `1 << 16..20`, and action `1 << 24..26`).
//! - `Ylianst_MeshCentral/meshrelay.js` & `agents/meshcore.js` (layered consent flags
//!   `domain.userconsentflags | mesh.consent | command.consent | LocalConsent`,
//!   `consentTimeout = 30`, `consentAutoAccept*`, and 5-minute `server_check_consentTimer`).
//! - `rustdesk_rustdesk/src/server/connection.rs` (`check_update_temporary_password`
//!   with `MAX_CONSECUTIVE_FAILURES = 10` automatic rotation).
//! - `rustdesk_rustdesk/src/rendezvous_mediator.rs` and
//!   `rustdesk_rustdesk-server/src/rendezvous_server.rs` (the node proposes its ID,
//!   the server owns the registry; see [`omegadesk_identity::QuickSupportId`]).

#[cfg(feature = "host")]
pub mod host;

use std::collections::HashMap;
use std::time::{Duration, Instant};

use omegadesk_identity::{DeviceId, QuickSupportId};
use rand_core::{OsRng, RngCore};
use thiserror::Error;

/// Maximum consecutive failed password attempts before automatic rotation
/// (`rustdesk/src/server/connection.rs:2555`).
pub const MAX_CONSECUTIVE_FAILURES: u32 = 10;

/// Default consent prompt timeout in seconds (`MeshCentral/agents/meshcore.js:1408`).
pub const DEFAULT_CONSENT_TIMEOUT_SECS: u64 = 30;

/// Grace period after the local user selects "Auto-allow for 5 minutes"
/// (`MeshCentral/agents/meshcore.js:1314`).
pub const AUTO_ALLOW_GRACE_PERIOD: Duration = Duration::from_secs(300);

/// QuickSupport errors.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum QuickSupportError {
    /// Provided temporary password did not match.
    #[error("invalid temporary password")]
    InvalidPassword,
    /// Client was disconnected because view permission was revoked (`Apollo/src/crypto.h:68`).
    #[error("client lacks view permission (_allow_view)")]
    ViewPermissionRevoked,
}

/// Per-client permission flags ported directly from `ClassicOldSong_Apollo/src/crypto.h`
/// (`enum class PERM: uint32_t`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct ClientPermissions(u32);

impl ClientPermissions {
    /// Base reserved bit (`Apollo PERM::_reserved = 1`).
    pub const RESERVED: Self = Self(1);

    // --- Input permission group (`_reserved << 8`) ---
    /// Allow controller/gamepad input (`PERM::input_controller`).
    pub const INPUT_CONTROLLER: Self = Self(1 << 8);
    /// Allow touch input (`PERM::input_touch`).
    pub const INPUT_TOUCH: Self = Self(1 << 9);
    /// Allow pen/stylus input (`PERM::input_pen`).
    pub const INPUT_PEN: Self = Self(1 << 10);
    /// Allow mouse input (`PERM::input_mouse`).
    pub const INPUT_MOUSE: Self = Self(1 << 11);
    /// Allow keyboard input (`PERM::input_kbd`).
    pub const INPUT_KBD: Self = Self(1 << 12);
    /// All input permissions (`PERM::_all_inputs`).
    pub const ALL_INPUTS: Self = Self(
        Self::INPUT_CONTROLLER.0
            | Self::INPUT_TOUCH.0
            | Self::INPUT_PEN.0
            | Self::INPUT_MOUSE.0
            | Self::INPUT_KBD.0,
    );

    // --- Operation permission group (`_input << 8`) ---
    /// Allow setting host clipboard from client (`PERM::clipboard_set`).
    pub const CLIPBOARD_SET: Self = Self(1 << 16);
    /// Allow reading host clipboard (`PERM::clipboard_read`).
    pub const CLIPBOARD_READ: Self = Self(1 << 17);
    /// Allow uploading files to host (`PERM::file_upload`).
    pub const FILE_UPLOAD: Self = Self(1 << 18);
    /// Allow downloading files from host (`PERM::file_dwnload`).
    pub const FILE_DOWNLOAD: Self = Self(1 << 19);
    /// Allow executing terminal/server commands (`PERM::server_cmd`).
    pub const SERVER_CMD: Self = Self(1 << 20);
    /// All operation permissions (`PERM::_all_opeiations`).
    pub const ALL_OPERATIONS: Self = Self(
        Self::CLIPBOARD_SET.0
            | Self::CLIPBOARD_READ.0
            | Self::FILE_UPLOAD.0
            | Self::FILE_DOWNLOAD.0
            | Self::SERVER_CMD.0,
    );

    // --- Action permission group (`_operation << 8`) ---
    /// Allow listing displays/apps (`PERM::list`).
    pub const LIST: Self = Self(1 << 24);
    /// Allow viewing desktop stream (`PERM::view`).
    pub const VIEW: Self = Self(1 << 25);
    /// Allow launching sessions/apps (`PERM::launch`).
    pub const LAUNCH: Self = Self(1 << 26);
    /// Required view mask (`PERM::_allow_view = view | launch`). If neither is set,
    /// the session must be disconnected (`Apollo/src/stream.cpp:1965`).
    pub const ALLOW_VIEW: Self = Self(Self::VIEW.0 | Self::LAUNCH.0);
    /// All action permissions (`PERM::_all_actions`).
    pub const ALL_ACTIONS: Self = Self(Self::LIST.0 | Self::VIEW.0 | Self::LAUNCH.0);

    /// Default permissions for newly connected clients (`PERM::_default = view | list`).
    pub const DEFAULT: Self = Self(Self::VIEW.0 | Self::LIST.0);
    /// No permissions (`PERM::_no = 0`).
    pub const NONE: Self = Self(0);
    /// All permissions (`PERM::_all`).
    pub const ALL: Self = Self(Self::ALL_INPUTS.0 | Self::ALL_OPERATIONS.0 | Self::ALL_ACTIONS.0);

    /// Constructs permissions from raw bits, masking to valid `ALL` bits (`Apollo/src/confighttp.cpp:917`).
    #[must_use]
    pub const fn from_bits_masked(bits: u32) -> Self {
        Self(bits & Self::ALL.0)
    }

    /// Returns the raw `u32` bitmask.
    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Returns `true` if all bits in `other` are present in `self`.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Returns `true` if any bit in `other` is present in `self`.
    #[must_use]
    pub const fn intersects(self, other: Self) -> bool {
        (self.0 & other.0) != 0
    }

    /// Unions two permission sets.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Intersects two permission sets.
    #[must_use]
    pub const fn intersection(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    /// Validates that the client still holds at least one `ALLOW_VIEW` bit
    /// (`Apollo/src/stream.cpp:1965`).
    ///
    /// # Errors
    ///
    /// Returns [`QuickSupportError::ViewPermissionRevoked`] if neither `VIEW` nor `LAUNCH` is set.
    pub const fn ensure_can_view(self) -> Result<(), QuickSupportError> {
        if self.intersects(Self::ALLOW_VIEW) {
            Ok(())
        } else {
            Err(QuickSupportError::ViewPermissionRevoked)
        }
    }
}

impl Default for ClientPermissions {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Formats the 9-digit QuickSupport ID a device proposes for itself
/// (`NNN NNN NNN`). The coordinator may assign a different number when this
/// one is taken; once enrolled, show the assigned one (`host::QuickSupportHost::id`)
/// rather than this proposal.
#[must_use]
pub fn format_quicksupport_id(device_id: DeviceId) -> String {
    QuickSupportId::proposed_for(device_id).to_string()
}

/// Brute-force-resistant temporary password manager ported from
/// `rustdesk_rustdesk/src/server/connection.rs` (`check_update_temporary_password`).
#[derive(Debug, Clone)]
pub struct TemporaryPasswordGuard {
    password: String,
    length: usize,
    consecutive_failures: u32,
}

impl TemporaryPasswordGuard {
    /// Creates a new temporary password manager with a randomly generated alphanumeric password.
    #[must_use]
    pub fn new(length: usize) -> Self {
        let len = length.clamp(6, 16);
        Self {
            password: Self::generate_password(len),
            length: len,
            consecutive_failures: 0,
        }
    }

    /// Returns the active temporary password.
    #[must_use]
    pub fn password(&self) -> &str {
        &self.password
    }

    /// Returns the number of consecutive failed validation attempts.
    #[must_use]
    pub const fn consecutive_failures(&self) -> u32 {
        self.consecutive_failures
    }

    /// Rotates the temporary password immediately and resets the failure counter.
    pub fn rotate(&mut self) -> &str {
        self.password = Self::generate_password(self.length);
        self.consecutive_failures = 0;
        &self.password
    }

    /// Validates `candidate` against the current temporary password.
    ///
    /// Mirrors `rustdesk/src/server/connection.rs:2554-2599`:
    /// - A match resets `consecutive_failures` to `0`.
    /// - A mismatch increments `consecutive_failures`; once it reaches
    ///   [`MAX_CONSECUTIVE_FAILURES`] (`10`), the password is automatically rotated
    ///   and `consecutive_failures` is reset to `0`.
    ///
    /// # Errors
    ///
    /// Returns [`QuickSupportError::InvalidPassword`] when `candidate` does not match.
    pub fn verify(&mut self, candidate: &str) -> Result<(), QuickSupportError> {
        if !self.password.is_empty() && constant_time_matches(&self.password, candidate) {
            self.record_success();
            return Ok(());
        }
        self.record_failure();
        Err(QuickSupportError::InvalidPassword)
    }

    /// Records a failed attempt verified elsewhere (the agent session handshake
    /// compares the password itself and reports `password::Rejected`). Returns
    /// `true` when this failure reached [`MAX_CONSECUTIVE_FAILURES`] and the
    /// password was rotated, so the caller can show the new one.
    pub fn record_failure(&mut self) -> bool {
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        if self.consecutive_failures >= MAX_CONSECUTIVE_FAILURES {
            self.rotate();
            return true;
        }
        false
    }

    /// Records a successful attempt verified elsewhere, resetting the failure counter.
    pub const fn record_success(&mut self) {
        self.consecutive_failures = 0;
    }

    fn generate_password(length: usize) -> String {
        const CHARSET: &[u8] = b"abcdefghjkmnpqrstuvwxyz23456789";
        let mut out = String::with_capacity(length);
        while out.len() < length {
            let mut byte = [0u8; 1];
            OsRng.fill_bytes(&mut byte);
            // Rejection sampling: 248 is the largest multiple of 31 below 256.
            if byte[0] < 248 {
                out.push(char::from(CHARSET[usize::from(byte[0]) % CHARSET.len()]));
            }
        }
        out
    }
}

fn constant_time_matches(expected: &str, received: &str) -> bool {
    let (expected, received) = (expected.as_bytes(), received.as_bytes());
    let mut difference = u8::from(expected.len() != received.len());
    for (index, &byte) in expected.iter().enumerate() {
        difference |= byte ^ received.get(index).copied().unwrap_or(0);
    }
    difference == 0
}

/// Layered user consent bitflags ported from `Ylianst_MeshCentral/meshrelay.js` &
/// `agents/meshcore.js`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(transparent)]
pub struct ConsentFlags(u32);

impl ConsentFlags {
    /// No consent flags required.
    pub const NONE: Self = Self(0);
    /// Notify user when desktop session starts (`1`).
    pub const DESKTOP_NOTIFY: Self = Self(0x0001);
    /// Notify user when terminal session starts (`2`).
    pub const TERMINAL_NOTIFY: Self = Self(0x0002);
    /// Notify user when file transfer starts (`4`).
    pub const FILES_NOTIFY: Self = Self(0x0004);
    /// Prompt local user for consent before desktop session (`8`, `meshcore.js:3785`).
    pub const DESKTOP_PROMPT: Self = Self(0x0008);
    /// Prompt local user for consent before terminal session (`16`, `meshcore.js:3641`).
    pub const TERMINAL_PROMPT: Self = Self(0x0010);
    /// Prompt local user for consent before file session (`32`, `meshcore.js:3925`).
    pub const FILES_PROMPT: Self = Self(0x0020);
    /// Show active session privacy bar (`64`).
    pub const PRIVACY_BAR: Self = Self(0x0040);

    /// Mask of all prompt flags (`8 | 16 | 32 = 56`, cleared via `& !56` in `meshcore.js:1401`
    /// when within the 5-minute auto-allow timer).
    pub const ALL_PROMPTS: Self =
        Self(Self::DESKTOP_PROMPT.0 | Self::TERMINAL_PROMPT.0 | Self::FILES_PROMPT.0);

    /// Creates consent flags from raw bits.
    #[must_use]
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    /// Returns raw bits.
    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Combines layered consent flags (`tenant | group | machine | user`,
    /// `meshrelay.js:264-265` & `meshcore.js:1393`).
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Removes the specified flags (`meshcore.js:1401`).
    #[must_use]
    pub const fn without(self, mask: Self) -> Self {
        Self(self.0 & !mask.0)
    }

    /// Checks whether all bits in `other` are set.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }
}

/// Session channel kind requesting consent (`meshcore.js:3641, 3785, 3925`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsentChannelKind {
    /// Remote desktop viewing/control (`DESKTOP_PROMPT`).
    Desktop,
    /// Remote shell/terminal (`TERMINAL_PROMPT`).
    Terminal,
    /// Remote file transfer (`FILES_PROMPT`).
    Files,
}

/// Host session state inspected before prompting (`meshcore.js:3643, 3788, 3927`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostUserState {
    /// Whether at least one interactive user is logged into the machine.
    pub user_logged_in: bool,
    /// Whether the active desktop session is locked (`Winlogon` / lock screen).
    pub session_locked: bool,
}

/// Layered consent policy combining tenant, group, machine, and user requirements
/// (`MeshCentral/meshrelay.js:918-931` & `agents/meshcore.js:1392-1417`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsentPolicy {
    /// Tenant-wide required consent flags (`domain.userconsentflags`).
    pub tenant_flags: ConsentFlags,
    /// Device-group consent flags (`mesh.consent`).
    pub group_flags: ConsentFlags,
    /// Machine-local consent flags (`_MSH().LocalConsent`).
    pub machine_flags: ConsentFlags,
    /// Per-user consent flags (`command.consent`).
    pub user_flags: ConsentFlags,
    /// Prompt timeout in seconds (`consentTimeout`, default 30 s).
    pub timeout_secs: u64,
    /// Automatically accept when the prompt times out (`consentAutoAccept`).
    pub auto_accept_on_timeout: bool,
    /// Automatically accept if no interactive user is logged in (`consentAutoAcceptIfNoUser`).
    pub auto_accept_if_no_user: bool,
    /// Automatically accept if the local session is locked (`consentAutoAcceptIfLocked`).
    pub auto_accept_if_locked: bool,
}

impl Default for ConsentPolicy {
    fn default() -> Self {
        Self {
            tenant_flags: ConsentFlags::NONE,
            group_flags: ConsentFlags::NONE,
            machine_flags: ConsentFlags::DESKTOP_PROMPT.union(ConsentFlags::PRIVACY_BAR),
            user_flags: ConsentFlags::NONE,
            timeout_secs: DEFAULT_CONSENT_TIMEOUT_SECS,
            auto_accept_on_timeout: false,
            auto_accept_if_no_user: false,
            auto_accept_if_locked: false,
        }
    }
}

impl ConsentPolicy {
    /// Computes the effective consent flags across all four hierarchy layers
    /// (`tenant | group | machine | user`, `meshrelay.js:264-265`).
    #[must_use]
    pub const fn effective_flags(&self) -> ConsentFlags {
        self.tenant_flags
            .union(self.group_flags)
            .union(self.machine_flags)
            .union(self.user_flags)
    }
}

/// Outcome of evaluating or resolving a remote-user consent request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsentDecision {
    /// Session is allowed immediately without prompting (no prompt flag, auto-accepted due
    /// to no user / locked desktop, or within the 5-minute auto-allow timer).
    AllowedImmediately,
    /// Local user must be prompted with a timeout of `timeout_secs`.
    PromptRequired {
        /// Prompt timeout in seconds.
        timeout_secs: u64,
    },
    /// Local user explicitly accepted the session (`allow_five_min_grace` records the
    /// 5-minute timer from `meshcore.js:1309`).
    Accepted {
        /// Whether the user chose "Auto allow for 5 minutes".
        allow_five_min_grace: bool,
    },
    /// Local user explicitly rejected the session.
    Rejected,
    /// Prompt timed out without user response (`auto_accepted` reflects `consentAutoAccept`).
    TimedOut {
        /// Whether the policy auto-accepted the session on timeout.
        auto_accepted: bool,
    },
}

/// Stateful consent evaluator with per-operator 5-minute grace timers
/// (`MeshCentral/agents/meshcore.js:1308-1417`).
#[derive(Debug, Default)]
pub struct ConsentManager {
    policy: ConsentPolicy,
    grace_timers: HashMap<String, Instant>,
}

impl ConsentManager {
    /// Creates a new consent manager with the given layered policy.
    #[must_use]
    pub fn new(policy: ConsentPolicy) -> Self {
        Self {
            policy,
            grace_timers: HashMap::new(),
        }
    }

    /// Returns a reference to the active consent policy.
    #[must_use]
    pub const fn policy(&self) -> &ConsentPolicy {
        &self.policy
    }

    /// Evaluates whether a connection from `operator_id` on `channel` requires an interactive
    /// prompt or can proceed immediately (`meshcore.js:1401, 3641, 3785, 3925`).
    #[must_use]
    pub fn evaluate(
        &mut self,
        operator_id: &str,
        channel: ConsentChannelKind,
        host_state: HostUserState,
        now: Instant,
    ) -> ConsentDecision {
        let mut flags = self.policy.effective_flags();

        // Check 5-minute auto-allow timer (`server_check_consentTimer`, `meshcore.js:1312-1401`).
        if let Some(&granted_at) = self.grace_timers.get(operator_id) {
            if now.saturating_duration_since(granted_at) < AUTO_ALLOW_GRACE_PERIOD {
                flags = flags.without(ConsentFlags::ALL_PROMPTS);
            } else {
                self.grace_timers.remove(operator_id);
            }
        }

        let required_prompt = match channel {
            ConsentChannelKind::Desktop => ConsentFlags::DESKTOP_PROMPT,
            ConsentChannelKind::Terminal => ConsentFlags::TERMINAL_PROMPT,
            ConsentChannelKind::Files => ConsentFlags::FILES_PROMPT,
        };

        if !flags.contains(required_prompt) {
            return ConsentDecision::AllowedImmediately;
        }

        if !host_state.user_logged_in && self.policy.auto_accept_if_no_user {
            return ConsentDecision::AllowedImmediately;
        }

        if host_state.user_logged_in
            && host_state.session_locked
            && self.policy.auto_accept_if_locked
        {
            return ConsentDecision::AllowedImmediately;
        }

        ConsentDecision::PromptRequired {
            timeout_secs: self.policy.timeout_secs.max(1),
        }
    }

    /// Records the local user's response to a consent prompt (`meshcore.js:2807-2808`).
    pub fn record_user_response(
        &mut self,
        operator_id: &str,
        accepted: bool,
        allow_five_min_grace: bool,
        now: Instant,
    ) -> ConsentDecision {
        if accepted {
            if allow_five_min_grace {
                self.grace_timers.insert(operator_id.to_owned(), now);
            }
            ConsentDecision::Accepted {
                allow_five_min_grace,
            }
        } else {
            self.grace_timers.remove(operator_id);
            ConsentDecision::Rejected
        }
    }

    /// Resolves a prompt timeout according to `auto_accept_on_timeout` (`meshcore.js:3523`).
    #[must_use]
    pub const fn resolve_timeout(&self) -> ConsentDecision {
        ConsentDecision::TimedOut {
            auto_accepted: self.policy.auto_accept_on_timeout,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_nine_digit_quicksupport_id() {
        let id = format_quicksupport_id(DeviceId::from_signing_key(&[0x42; 32]));
        assert_eq!(id.len(), 11);
        assert_eq!(&id[3..4], " ");
        assert_eq!(&id[7..8], " ");
        assert!(id.chars().filter(|c| *c != ' ').all(|c| c.is_ascii_digit()));
        assert!(QuickSupportId::looks_like(&id));
    }

    #[test]
    fn externally_verified_failures_rotate_after_ten_and_successes_reset() {
        let mut guard = TemporaryPasswordGuard::new(6);
        let initial = guard.password().to_owned();
        for _ in 0..(MAX_CONSECUTIVE_FAILURES - 1) {
            assert!(!guard.record_failure());
        }
        guard.record_success();
        assert_eq!(guard.consecutive_failures(), 0);
        assert_eq!(guard.password(), initial, "a success resets the count");
        for _ in 0..(MAX_CONSECUTIVE_FAILURES - 1) {
            assert!(!guard.record_failure());
        }
        assert!(guard.record_failure(), "the tenth failure rotates");
        assert_ne!(guard.password(), initial);
        assert_eq!(guard.consecutive_failures(), 0);
    }

    #[test]
    fn apollo_permissions_enforce_view_and_bitmasking() {
        let default_perm = ClientPermissions::DEFAULT;
        assert!(default_perm.contains(ClientPermissions::VIEW));
        assert!(default_perm.contains(ClientPermissions::LIST));
        assert!(!default_perm.contains(ClientPermissions::INPUT_MOUSE));
        assert!(default_perm.ensure_can_view().is_ok());

        let no_view = ClientPermissions::INPUT_KBD.union(ClientPermissions::CLIPBOARD_READ);
        assert_eq!(
            no_view.ensure_can_view(),
            Err(QuickSupportError::ViewPermissionRevoked)
        );
    }

    #[test]
    fn temporary_password_rotates_after_ten_consecutive_failures() {
        let mut guard = TemporaryPasswordGuard::new(8);
        let initial = guard.password().to_owned();
        assert!(guard.verify(&initial).is_ok());

        for attempt in 1..MAX_CONSECUTIVE_FAILURES {
            assert_eq!(
                guard.verify("00000000"),
                Err(QuickSupportError::InvalidPassword)
            );
            assert_eq!(guard.consecutive_failures(), attempt);
            assert_eq!(guard.password(), initial);
        }

        // 10th consecutive wrong attempt triggers rotation (`connection.rs:2586-2598`).
        assert_eq!(
            guard.verify("00000000"),
            Err(QuickSupportError::InvalidPassword)
        );
        assert_eq!(guard.consecutive_failures(), 0);
        assert_ne!(guard.password(), initial);
    }

    #[test]
    fn layered_consent_combines_hierarchy_and_honors_five_min_grace_timer() {
        let policy = ConsentPolicy {
            tenant_flags: ConsentFlags::PRIVACY_BAR,
            group_flags: ConsentFlags::DESKTOP_NOTIFY,
            machine_flags: ConsentFlags::DESKTOP_PROMPT,
            user_flags: ConsentFlags::TERMINAL_PROMPT,
            timeout_secs: 30,
            auto_accept_on_timeout: false,
            auto_accept_if_no_user: true,
            auto_accept_if_locked: false,
        };
        let mut mgr = ConsentManager::new(policy);
        let t0 = Instant::now();

        // No user logged in + auto_accept_if_no_user => allowed immediately.
        assert_eq!(
            mgr.evaluate(
                "alice@omega",
                ConsentChannelKind::Desktop,
                HostUserState {
                    user_logged_in: false,
                    session_locked: false,
                },
                t0,
            ),
            ConsentDecision::AllowedImmediately
        );

        // Interactive user present => prompt required.
        let active_host = HostUserState {
            user_logged_in: true,
            session_locked: false,
        };
        assert_eq!(
            mgr.evaluate("alice@omega", ConsentChannelKind::Desktop, active_host, t0),
            ConsentDecision::PromptRequired { timeout_secs: 30 }
        );

        // User accepts with "Auto allow for 5 minutes".
        assert_eq!(
            mgr.record_user_response("alice@omega", true, true, t0),
            ConsentDecision::Accepted {
                allow_five_min_grace: true
            }
        );

        // Subsequent terminal request within 5 minutes skips prompt (`meshcore.js:1401`).
        assert_eq!(
            mgr.evaluate(
                "alice@omega",
                ConsentChannelKind::Terminal,
                active_host,
                t0 + Duration::from_secs(120),
            ),
            ConsentDecision::AllowedImmediately
        );

        // After 5 minutes expire, prompt is required again.
        assert_eq!(
            mgr.evaluate(
                "alice@omega",
                ConsentChannelKind::Terminal,
                active_host,
                t0 + Duration::from_secs(301),
            ),
            ConsentDecision::PromptRequired { timeout_secs: 30 }
        );
    }
}
