//! Supervisor state machine deciding when to launch, relaunch or stop the
//! per-session worker as the active console session changes.
//!
//! This is the pure, platform-independent core of the service's main loop. The
//! Windows service (`dispatch`/`supervisor`) feeds it the active console
//! session id (from `WTSGetActiveConsoleSessionId`) on every session-change
//! notification and periodic tick, plus worker-exit events, and performs the
//! returned [`SupervisorAction`]. Keeping the decision logic here lets it be
//! unit-tested on every platform, matching the loop in RustDesk
//! `src/platform/windows.rs::run_service` (which launches the worker in the
//! current session and relaunches it whenever `get_current_session` changes or
//! the worker process exits).

/// The high-level reason the Service Control Manager delivered a
/// session-change control event. Used for logging and to decide whether to
/// re-query the active console session; the authoritative session id always
/// comes from `WTSGetActiveConsoleSessionId`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionChange {
    /// A session connected to the physical console (`WTS_CONSOLE_CONNECT`).
    ConsoleConnect,
    /// A session disconnected from the physical console (`WTS_CONSOLE_DISCONNECT`).
    ConsoleDisconnect,
    /// A session connected to a remote (RDP) terminal (`WTS_REMOTE_CONNECT`).
    RemoteConnect,
    /// A session disconnected from a remote terminal (`WTS_REMOTE_DISCONNECT`).
    RemoteDisconnect,
    /// A user logged on to a session (`WTS_SESSION_LOGON`).
    SessionLogon,
    /// A user logged off from a session (`WTS_SESSION_LOGOFF`).
    SessionLogoff,
    /// A session was locked (`WTS_SESSION_LOCK`); handled by the worker
    /// following the input desktop, not by respawning.
    SessionLock,
    /// A session was unlocked (`WTS_SESSION_UNLOCK`).
    SessionUnlock,
}

impl SessionChange {
    /// Whether this event can change which session owns the physical console,
    /// so the service should re-query `WTSGetActiveConsoleSessionId`. Lock and
    /// unlock keep the same active session (only the desktop switches), so the
    /// worker handles them itself and no respawn is needed.
    #[must_use]
    pub const fn may_change_active_session(self) -> bool {
        !matches!(self, Self::SessionLock | Self::SessionUnlock)
    }
}

/// What the supervisor should do after an observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SupervisorAction {
    /// Launch (or relaunch) the worker in this console session.
    LaunchWorker {
        /// Target Windows session id.
        session_id: u32,
    },
    /// Terminate the running worker: there is no active console session
    /// (`0xFFFF_FFFF`, e.g. every user signed out).
    StopWorker,
    /// Nothing to do.
    Idle,
}

/// Tracks the active console session and the worker currently serving it.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct WorkerSupervisorState {
    active_session: Option<u32>,
    worker_session: Option<u32>,
    worker_alive: bool,
}

impl WorkerSupervisorState {
    /// Creates a supervisor with no active session and no worker.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records the active console session id (`None` when there is no active
    /// console session). Returns the action the service must perform.
    pub fn observe_active_session(&mut self, session: Option<u32>) -> SupervisorAction {
        self.active_session = session;
        match session {
            None => {
                if self.worker_alive {
                    SupervisorAction::StopWorker
                } else {
                    SupervisorAction::Idle
                }
            }
            Some(session_id) => {
                if self.worker_alive && self.worker_session == Some(session_id) {
                    SupervisorAction::Idle
                } else {
                    SupervisorAction::LaunchWorker { session_id }
                }
            }
        }
    }

    /// Records that the worker serving `session` exited. Relaunches it if that
    /// session is still the active console session.
    pub fn observe_worker_exited(&mut self, session: u32) -> SupervisorAction {
        if self.worker_session == Some(session) {
            self.worker_alive = false;
        }
        if self.active_session == Some(session) {
            SupervisorAction::LaunchWorker {
                session_id: session,
            }
        } else {
            SupervisorAction::Idle
        }
    }

    /// Records that a worker launch succeeded in `session`.
    pub fn worker_launched(&mut self, session: u32) {
        self.worker_session = Some(session);
        self.worker_alive = true;
    }

    /// Records that the worker was stopped (service shutdown or no active
    /// session).
    pub fn worker_stopped(&mut self) {
        self.worker_alive = false;
        self.worker_session = None;
    }

    /// The session the live worker is serving, if any.
    #[must_use]
    pub fn worker_session(&self) -> Option<u32> {
        if self.worker_alive {
            self.worker_session
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_active_session_launches_a_worker() {
        let mut state = WorkerSupervisorState::new();
        assert_eq!(
            state.observe_active_session(Some(1)),
            SupervisorAction::LaunchWorker { session_id: 1 }
        );
        state.worker_launched(1);
        assert_eq!(state.worker_session(), Some(1));
        // Re-observing the same active session is a no-op.
        assert_eq!(
            state.observe_active_session(Some(1)),
            SupervisorAction::Idle
        );
    }

    #[test]
    fn switching_console_session_relaunches_the_worker() {
        let mut state = WorkerSupervisorState::new();
        state.observe_active_session(Some(1));
        state.worker_launched(1);
        // Fast user switch / RDP handoff to session 2.
        assert_eq!(
            state.observe_active_session(Some(2)),
            SupervisorAction::LaunchWorker { session_id: 2 }
        );
        state.worker_launched(2);
        assert_eq!(state.worker_session(), Some(2));
    }

    #[test]
    fn no_active_session_stops_the_worker() {
        let mut state = WorkerSupervisorState::new();
        state.observe_active_session(Some(1));
        state.worker_launched(1);
        assert_eq!(
            state.observe_active_session(None),
            SupervisorAction::StopWorker
        );
        state.worker_stopped();
        assert_eq!(state.worker_session(), None);
        // With no worker and still no session, nothing to do.
        assert_eq!(state.observe_active_session(None), SupervisorAction::Idle);
    }

    #[test]
    fn worker_crash_relaunches_only_for_the_active_session() {
        let mut state = WorkerSupervisorState::new();
        state.observe_active_session(Some(1));
        state.worker_launched(1);
        // The worker for session 1 crashed while session 1 is still active.
        assert_eq!(
            state.observe_worker_exited(1),
            SupervisorAction::LaunchWorker { session_id: 1 }
        );
        state.worker_launched(1);

        // The active session moved to 2 and the stale session-1 worker exits:
        // no relaunch for the session that is no longer active.
        state.observe_active_session(Some(2));
        state.worker_launched(2);
        assert_eq!(state.observe_worker_exited(1), SupervisorAction::Idle);
        assert_eq!(state.worker_session(), Some(2));
    }

    #[test]
    fn lock_and_unlock_do_not_change_the_active_session() {
        assert!(!SessionChange::SessionLock.may_change_active_session());
        assert!(!SessionChange::SessionUnlock.may_change_active_session());
        assert!(SessionChange::ConsoleConnect.may_change_active_session());
        assert!(SessionChange::RemoteDisconnect.may_change_active_session());
        assert!(SessionChange::SessionLogoff.may_change_active_session());
    }
}
