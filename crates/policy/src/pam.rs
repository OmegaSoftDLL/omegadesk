//! Privileged Access Management (PAM): multi-level access approval tickets,
//! graded login/command ACL actions (`Accept`, `Reject`, `Review`, `Warn`, `NotifyAndWarn`),
//! and live session sharing (`ReadOnly` / `ReadWrite` join codes) with operator lock/terminate.
//!
//! Reference implementations:
//! - `jumpserver_jumpserver/apps/tickets/models/ticket/general.py` (lines 38–160):
//!   `TicketStep`, `TicketAssignee`, and multi-level sequential approval state transitions.
//! - `jumpserver_jumpserver/apps/acls/models/base.py` (lines 34–78): `BaseACL` priority-ordered
//!   (`1..=100`, lower matches first) graded ACL evaluation (`ActionChoices.accept`,
//!   `ActionChoices.reject`, `ActionChoices.review`, `ActionChoices.warn`,
//!   `ActionChoices.notify_and_warn`).
//! - `jumpserver_jumpserver/apps/terminal/models/session/sharing.py` (lines 19–160):
//!   `SessionSharing` (`verify_code`, `expired_time`, `action_permission = writable | readonly`,
//!   `can_join`) and `SessionJoinRecord`.
//! - `Ylianst_MeshCentral/meshdesktopmultiplex.js` (lines 25–135): `CreateDesktopMultiplexor`
//!   multi-viewer session multiplexing and live session pause/lock/termination.

use std::collections::{HashMap, HashSet};

use omegadesk_identity::DeviceId;
use thiserror::Error;

/// Errors returned by PAM ticket workflows or live session sharing.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum PamError {
    /// Ticket is no longer pending and cannot be modified.
    #[error("ticket '{0}' is already closed or finalized")]
    TicketAlreadyFinalized(String),
    /// User is not an authorized assignee for the current approval step.
    #[error("user '{user}' is not an assignee for step {step_level}")]
    UnauthorizedApprover {
        /// User attempting to approve or reject.
        user: String,
        /// One-based approval step level.
        step_level: usize,
    },
    /// Share link does not exist, is inactive, or has expired (`sharing.py` lines 106–115).
    #[error("session share cannot be joined: {0}")]
    ShareJoinDenied(&'static str),
    /// Approval workflow has no steps, or a step has no assignees, so nobody could ever review it.
    #[error("ticket '{ticket_id}' has an empty approval workflow: {reason}")]
    EmptyApprovalWorkflow {
        /// Ticket being created.
        ticket_id: String,
        /// Which part of the workflow is empty.
        reason: &'static str,
    },
    /// Share link names a different live session than the controller that received it.
    #[error("share '{share_id}' belongs to session '{share_session}', not '{controller_session}'")]
    ShareSessionMismatch {
        /// Share identifier.
        share_id: String,
        /// Session named by the share link.
        share_session: String,
        /// Session managed by the controller.
        controller_session: String,
    },
}

/// Lifecycle state of an [`AccessTicket`] or [`ApprovalStep`] (`general.py` lines 22–25).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TicketState {
    /// Awaiting reviewer decision.
    Pending,
    /// Approved by all required approval levels.
    Approved,
    /// Rejected by an assignee at any level.
    Rejected,
    /// Cancelled/closed by the applicant or system.
    Closed,
}

/// A single approval level in a multi-step [`AccessTicket`] (`TicketStep` in `general.py` lines 38–86).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalStep {
    /// One-based approval level (`1`, `2`, ...).
    pub level: usize,
    /// Set of candidate reviewers authorized to approve or reject this step.
    pub assignees: HashSet<String>,
    /// Current state of this step.
    pub state: TicketState,
    /// Reviewer who processed this step, if finalized.
    pub processed_by: Option<String>,
}

/// Multi-level PAM access request ticket (`Ticket` in `general.py`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessTicket {
    /// Unique ticket identifier.
    pub ticket_id: String,
    /// User requesting temporary privileged access.
    pub applicant: String,
    /// Target device requested.
    pub target_device: DeviceId,
    /// Ordered approval steps (`level 1`, `level 2`, ...).
    pub steps: Vec<ApprovalStep>,
    /// Zero-based index of the currently active approval step.
    pub current_step_idx: usize,
    /// Overall ticket state.
    pub state: TicketState,
}

impl AccessTicket {
    /// Creates a new pending [`AccessTicket`] with one or more sequential approval steps.
    ///
    /// Every ticket starts [`TicketState::Pending`]: in JumpServer a ticket is only approved
    /// through `Ticket.approve(processor)` after `create_process_steps_by_flow` built the steps
    /// (`apps/tickets/models/ticket/general.py` lines 169–171 and 278–286), never because the
    /// flow had no rules. A missing or empty approval configuration therefore fails closed.
    ///
    /// # Errors
    ///
    /// Returns [`PamError::EmptyApprovalWorkflow`] if `step_assignees` is empty or any step has
    /// no assignees, since such a ticket could never be reviewed by anyone.
    pub fn new(
        ticket_id: impl Into<String>,
        applicant: impl Into<String>,
        target_device: DeviceId,
        step_assignees: Vec<HashSet<String>>,
    ) -> Result<Self, PamError> {
        let ticket_id = ticket_id.into();
        if step_assignees.is_empty() {
            return Err(PamError::EmptyApprovalWorkflow {
                ticket_id,
                reason: "no approval steps configured",
            });
        }
        if step_assignees.iter().any(HashSet::is_empty) {
            return Err(PamError::EmptyApprovalWorkflow {
                ticket_id,
                reason: "an approval step has no assignees",
            });
        }
        let steps: Vec<ApprovalStep> = step_assignees
            .into_iter()
            .enumerate()
            .map(|(idx, assignees)| ApprovalStep {
                level: idx + 1,
                assignees,
                state: TicketState::Pending,
                processed_by: None,
            })
            .collect();
        Ok(Self {
            ticket_id,
            applicant: applicant.into(),
            target_device,
            steps,
            current_step_idx: 0,
            state: TicketState::Pending,
        })
    }

    /// Approves the currently active step on behalf of `processor`, advancing to the next step
    /// or transitioning the ticket to [`TicketState::Approved`] if the final step completed
    /// (`general.py` lines 56–73).
    ///
    /// # Errors
    ///
    /// Returns [`PamError`] if the ticket is already finalized or `processor` is not an assignee.
    pub fn approve_current_step(&mut self, processor: &str) -> Result<TicketState, PamError> {
        if self.state != TicketState::Pending {
            return Err(PamError::TicketAlreadyFinalized(self.ticket_id.clone()));
        }
        let step = &mut self.steps[self.current_step_idx];
        if !step.assignees.contains(processor) {
            return Err(PamError::UnauthorizedApprover {
                user: processor.to_owned(),
                step_level: step.level,
            });
        }
        step.state = TicketState::Approved;
        step.processed_by = Some(processor.to_owned());

        if self.current_step_idx + 1 < self.steps.len() {
            self.current_step_idx += 1;
        } else {
            self.state = TicketState::Approved;
        }
        Ok(self.state)
    }

    /// Rejects the currently active step on behalf of `processor`, immediately transitioning
    /// the ticket to [`TicketState::Rejected`].
    ///
    /// # Errors
    ///
    /// Returns [`PamError`] if the ticket is already finalized or `processor` is not an assignee.
    pub fn reject_current_step(&mut self, processor: &str) -> Result<TicketState, PamError> {
        if self.state != TicketState::Pending {
            return Err(PamError::TicketAlreadyFinalized(self.ticket_id.clone()));
        }
        let step = &mut self.steps[self.current_step_idx];
        if !step.assignees.contains(processor) {
            return Err(PamError::UnauthorizedApprover {
                user: processor.to_owned(),
                step_level: step.level,
            });
        }
        step.state = TicketState::Rejected;
        step.processed_by = Some(processor.to_owned());
        self.state = TicketState::Rejected;
        Ok(self.state)
    }
}

/// Graded ACL decision ported from `JumpServer` `ActionChoices` (`apps/acls/models/base.py` line 41).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GradedAction {
    /// Immediately allow the login or command (`ActionChoices.accept`).
    Accept,
    /// Immediately deny the login or command (`ActionChoices.reject`).
    Reject,
    /// Pause and require an approved [`AccessTicket`] from `reviewers` (`ActionChoices.review`).
    Review,
    /// Allow but display an interactive warning banner to the operator (`ActionChoices.warn`).
    Warn,
    /// Allow, display a warning, and emit a security alert (`ActionChoices.notify_and_warn`).
    NotifyAndWarn,
}

/// Priority-ordered graded ACL rule (`BaseACL` in `apps/acls/models/base.py` lines 34–78).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GradedAclRule {
    /// Human-readable rule name.
    pub name: String,
    /// Priority in `1..=100` (lower value matches first, `base.py` line 38).
    pub priority: u8,
    /// Whether the rule is currently active.
    pub is_active: bool,
    /// Users matched by this rule (`"*"` matches all users).
    pub users: HashSet<String>,
    /// Target accounts or command patterns matched (`"*"` matches all).
    pub patterns: HashSet<String>,
    /// Graded action taken when matched.
    pub action: GradedAction,
    /// Required reviewers when `action == GradedAction::Review` (`base.py` line 67).
    pub reviewers: HashSet<String>,
}

/// Evaluates a slice of [`GradedAclRule`] items in `JumpServer` priority order (`priority` ascending,
/// skipping inactive rules or `Review` rules with no reviewers, `base.py` lines 49 & 67).
#[must_use]
pub fn evaluate_graded_acls<'a>(
    rules: &'a [GradedAclRule],
    user: &str,
    target_or_command: &str,
) -> Option<&'a GradedAclRule> {
    let mut active_rules: Vec<&GradedAclRule> = rules
        .iter()
        .filter(|r| r.is_active && !(r.action == GradedAction::Review && r.reviewers.is_empty()))
        .collect();
    active_rules.sort_by(|a, b| {
        a.priority
            .cmp(&b.priority)
            .then_with(|| a.name.cmp(&b.name))
    });

    active_rules.into_iter().find(|rule| {
        let user_match = rule.users.contains("*") || rule.users.contains(user);
        let pattern_match = rule.patterns.contains("*")
            || rule
                .patterns
                .iter()
                .any(|pat| target_or_command.contains(pat));
        user_match && pattern_match
    })
}

/// Guest permission level for a shared live session (`action_permission` in `sharing.py` line 44).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SharePermission {
    /// Guest can view the screen/terminal but cannot inject input (`readonly`).
    ReadOnly,
    /// Guest can both view and send input (`writable`).
    ReadWrite,
}

/// Active sharing link for a live session (`SessionSharing` in `sharing.py` lines 19–116).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionShareLink {
    /// Share identifier.
    pub share_id: String,
    /// Underlying live session identifier.
    pub session_id: String,
    /// Operator who created the share link.
    pub creator_id: String,
    /// Verification code required to join (`verify_code` in `sharing.py` line 35).
    pub verify_code: String,
    /// Whether the link is active (`is_active`).
    pub is_active: bool,
    /// Expiration timestamp in milliseconds (`date_expired`).
    pub expires_at_ms: u64,
    /// Optional allow-list of user IDs permitted to join (empty means any authenticated user).
    pub allowed_users: HashSet<String>,
    /// Guest input permission (`ReadOnly` vs `ReadWrite`).
    pub permission: SharePermission,
}

impl SessionShareLink {
    /// Validates whether `joiner_id` can join this shared session using `verify_code` at `now_ms`,
    /// ported directly from `SessionSharing.can_join` (`sharing.py` lines 106–115).
    ///
    /// # Errors
    ///
    /// Returns [`PamError::ShareJoinDenied`] if the link is inactive, expired, the code mismatches,
    /// or `joiner_id` is not in `allowed_users`.
    pub fn validate_join(
        &self,
        joiner_id: &str,
        verify_code: &str,
        now_ms: u64,
    ) -> Result<SharePermission, PamError> {
        if self.creator_id.is_empty() || joiner_id.is_empty() {
            return Err(PamError::ShareJoinDenied("User does not exist"));
        }
        if !self.is_active {
            return Err(PamError::ShareJoinDenied("Link not active"));
        }
        if now_ms > self.expires_at_ms {
            return Err(PamError::ShareJoinDenied("Link expired"));
        }
        if self.verify_code != verify_code {
            return Err(PamError::ShareJoinDenied("Invalid verify code"));
        }
        if !self.allowed_users.is_empty() && !self.allowed_users.contains(joiner_id) {
            return Err(PamError::ShareJoinDenied("User not allowed to join"));
        }
        Ok(self.permission)
    }
}

/// Audit record of a guest joining a live shared session (`SessionJoinRecord` in `sharing.py` lines 118–160).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionJoinRecord {
    /// Live session identifier.
    pub session_id: String,
    /// Share identifier used to join.
    pub share_id: String,
    /// Guest user identifier.
    pub joiner_id: String,
    /// Guest permission granted.
    pub permission: SharePermission,
    /// Timestamp in milliseconds when the guest joined.
    pub joined_at_ms: u64,
}

/// Live session controller supporting multi-viewer sharing, input locking, and immediate
/// administrative termination (`sharing.py` & `MeshCentral/meshdesktopmultiplex.js`).
#[derive(Debug, Clone)]
pub struct LiveSessionController {
    session_id: String,
    locked: bool,
    terminated: bool,
    shares: HashMap<String, SessionShareLink>,
    join_records: Vec<SessionJoinRecord>,
}

impl LiveSessionController {
    /// Creates a controller for `session_id`.
    #[must_use]
    pub fn new(session_id: impl Into<String>) -> Self {
        Self {
            session_id: session_id.into(),
            locked: false,
            terminated: false,
            shares: HashMap::new(),
            join_records: Vec::new(),
        }
    }

    /// Returns the managed session identifier.
    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Registers a new [`SessionShareLink`] for this live session.
    ///
    /// In JumpServer the join record's session is always derived from the sharing object
    /// (`SessionJoinRecordSerializer.create` sets `session = sharing.session`,
    /// `apps/terminal/serializers/sharing.py` lines 80–85) because `SessionSharing.session` is a
    /// foreign key that can only point at one session. The controller enforces the same
    /// invariant: a link that names another session is refused instead of silently authorizing
    /// access to this one with a misleading audit record.
    ///
    /// # Errors
    ///
    /// Returns [`PamError::ShareSessionMismatch`] if `share.session_id` differs from the managed
    /// session.
    pub fn create_share(&mut self, share: SessionShareLink) -> Result<(), PamError> {
        self.ensure_share_belongs_here(&share)?;
        self.shares.insert(share.share_id.clone(), share);
        Ok(())
    }

    fn ensure_share_belongs_here(&self, share: &SessionShareLink) -> Result<(), PamError> {
        if share.session_id != self.session_id {
            return Err(PamError::ShareSessionMismatch {
                share_id: share.share_id.clone(),
                share_session: share.session_id.clone(),
                controller_session: self.session_id.clone(),
            });
        }
        Ok(())
    }

    /// Validates a join attempt and records a [`SessionJoinRecord`] on success.
    ///
    /// # Errors
    ///
    /// Returns [`PamError::ShareJoinDenied`] if the session is terminated or share validation
    /// fails, or [`PamError::ShareSessionMismatch`] if the link names a different session.
    pub fn join_shared_session(
        &mut self,
        share_id: &str,
        joiner_id: &str,
        verify_code: &str,
        now_ms: u64,
    ) -> Result<SharePermission, PamError> {
        if self.terminated {
            return Err(PamError::ShareJoinDenied("Session already terminated"));
        }
        let Some(share) = self.shares.get(share_id) else {
            return Err(PamError::ShareJoinDenied("Share link not found"));
        };
        self.ensure_share_belongs_here(share)?;
        let perm = share.validate_join(joiner_id, verify_code, now_ms)?;
        self.join_records.push(SessionJoinRecord {
            session_id: self.session_id.clone(),
            share_id: share_id.to_owned(),
            joiner_id: joiner_id.to_owned(),
            permission: perm,
            joined_at_ms: now_ms,
        });
        Ok(perm)
    }

    /// Locks operator input on the live session (`lock_session`).
    pub fn lock_session(&mut self) {
        self.locked = true;
    }

    /// Unlocks operator input on the live session.
    pub fn unlock_session(&mut self) {
        self.locked = false;
    }

    /// Returns `true` if operator input is currently paused/locked.
    #[must_use]
    pub const fn is_locked(&self) -> bool {
        self.locked
    }

    /// Immediately terminates the live session and deactivates all share links (`terminate_session`).
    pub fn terminate_session(&mut self) {
        self.terminated = true;
        for share in self.shares.values_mut() {
            share.is_active = false;
        }
    }

    /// Returns `true` if the session has been terminated by an administrator or auditor.
    #[must_use]
    pub const fn is_terminated(&self) -> bool {
        self.terminated
    }

    /// Returns the audit log of guests who joined this session.
    #[must_use]
    pub fn join_records(&self) -> &[SessionJoinRecord] {
        &self.join_records
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use omegadesk_identity::DeviceIdentity;

    #[test]
    fn multi_step_ticket_approval_and_graded_acl() {
        let device_id = DeviceIdentity::generate().id();
        let mut ticket = AccessTicket::new(
            "tkt-100",
            "operator-1",
            device_id,
            vec![
                HashSet::from(["team-lead".to_owned()]),
                HashSet::from(["sec-admin".to_owned()]),
            ],
        )
        .unwrap();

        assert!(ticket.approve_current_step("random-user").is_err());
        assert_eq!(
            ticket.approve_current_step("team-lead"),
            Ok(TicketState::Pending)
        );
        assert_eq!(
            ticket.approve_current_step("sec-admin"),
            Ok(TicketState::Approved)
        );

        let rules = vec![
            GradedAclRule {
                name: "warn-systemctl".to_owned(),
                priority: 20,
                is_active: true,
                users: HashSet::from(["*".to_owned()]),
                patterns: HashSet::from(["systemctl".to_owned()]),
                action: GradedAction::Warn,
                reviewers: HashSet::new(),
            },
            GradedAclRule {
                name: "review-rm".to_owned(),
                priority: 10,
                is_active: true,
                users: HashSet::from(["*".to_owned()]),
                patterns: HashSet::from(["rm -rf".to_owned()]),
                action: GradedAction::Review,
                reviewers: HashSet::from(["sec-admin".to_owned()]),
            },
        ];

        let matched = evaluate_graded_acls(&rules, "operator-1", "sudo rm -rf /var/log/old");
        assert_eq!(matched.map(|r| r.action), Some(GradedAction::Review));
    }

    /// Issue #29 `pam.rs:105`: an empty approval workflow must be rejected, never auto-approved.
    #[test]
    fn empty_approval_workflow_is_rejected_instead_of_auto_approved() {
        let device_id = DeviceIdentity::generate().id();

        let no_steps = AccessTicket::new("tkt-empty", "operator-1", device_id, Vec::new());
        assert_eq!(
            no_steps,
            Err(PamError::EmptyApprovalWorkflow {
                ticket_id: "tkt-empty".to_owned(),
                reason: "no approval steps configured",
            })
        );

        let empty_step = AccessTicket::new(
            "tkt-hollow",
            "operator-1",
            device_id,
            vec![HashSet::from(["team-lead".to_owned()]), HashSet::new()],
        );
        assert!(matches!(
            empty_step,
            Err(PamError::EmptyApprovalWorkflow { ref ticket_id, .. }) if ticket_id == "tkt-hollow"
        ));

        let valid = AccessTicket::new(
            "tkt-ok",
            "operator-1",
            device_id,
            vec![HashSet::from(["team-lead".to_owned()])],
        )
        .unwrap();
        assert_eq!(valid.state, TicketState::Pending);
    }

    fn share(share_id: &str, session_id: &str) -> SessionShareLink {
        SessionShareLink {
            share_id: share_id.to_owned(),
            session_id: session_id.to_owned(),
            creator_id: "alice".to_owned(),
            verify_code: "849201".to_owned(),
            is_active: true,
            expires_at_ms: 50_000,
            allowed_users: HashSet::from(["bob".to_owned()]),
            permission: SharePermission::ReadOnly,
        }
    }

    /// Issue #29 `pam.rs:366`: a share link whose `session_id` differs from the managed session
    /// must be rejected, so a guest can never be admitted to a session the link does not name.
    #[test]
    fn share_link_for_another_session_is_rejected() {
        let mut controller = LiveSessionController::new("sess-99");

        let err = controller.create_share(share("shr-foreign", "sess-42"));
        assert_eq!(
            err,
            Err(PamError::ShareSessionMismatch {
                share_id: "shr-foreign".to_owned(),
                share_session: "sess-42".to_owned(),
                controller_session: "sess-99".to_owned(),
            })
        );
        assert_eq!(
            controller.join_shared_session("shr-foreign", "bob", "849201", 10_000),
            Err(PamError::ShareJoinDenied("Share link not found"))
        );
        assert_eq!(controller.join_records(), []);

        assert_eq!(controller.create_share(share("shr-1", "sess-99")), Ok(()));
        assert_eq!(
            controller.join_shared_session("shr-1", "bob", "849201", 10_000),
            Ok(SharePermission::ReadOnly)
        );
        assert_eq!(controller.join_records()[0].session_id, "sess-99");
    }

    #[test]
    fn live_session_sharing_and_operator_termination() {
        let mut controller = LiveSessionController::new("sess-99");
        controller
            .create_share(SessionShareLink {
                share_id: "shr-1".to_owned(),
                session_id: "sess-99".to_owned(),
                creator_id: "alice".to_owned(),
                verify_code: "849201".to_owned(),
                is_active: true,
                expires_at_ms: 50_000,
                allowed_users: HashSet::from(["bob".to_owned()]),
                permission: SharePermission::ReadOnly,
            })
            .unwrap();

        assert_eq!(
            controller.join_shared_session("shr-1", "bob", "849201", 10_000),
            Ok(SharePermission::ReadOnly)
        );
        assert!(
            controller
                .join_shared_session("shr-1", "mallory", "849201", 10_000)
                .is_err()
        );

        controller.lock_session();
        assert!(controller.is_locked());
        controller.terminate_session();
        assert!(controller.is_terminated());
        assert!(
            controller
                .join_shared_session("shr-1", "bob", "849201", 12_000)
                .is_err()
        );
    }
}
