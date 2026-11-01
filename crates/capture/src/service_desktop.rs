//! Windows `SYSTEM` service desktop switching (`Winlogon` / UAC Secure Desktop),
//! session process discovery (`winlogon.exe` / `explorer.exe` / `sihost.exe`),
//! capture fallback chain (`DXGI -> WGC -> GDI`), and privacy mode ownership.
//!
//! Ported from:
//! - **`RustDesk` `src/platform/windows.cc` & `src/platform/windows.rs`** (AGPL-3.0)
//!   and **`TigerVNC` `win/rfb_win32/Service.cxx`**:
//!   - [`input_desktop_selected`] and [`select_input_desktop`] (`GetThreadDesktop`,
//!     `OpenInputDesktop`, `GetUserObjectInformationW(UOI_NAME)`, `SetThreadDesktop`,
//!     `CloseDesktop`) to follow switches between `winsta0\default` and the
//!     `winsta0\winlogon` Secure Desktop (login screen, lock screen, UAC prompt).
//!   - [`find_session_target_pid`] (`CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS)` +
//!     `ProcessIdToSessionId` matching `winlogon.exe` for `SYSTEM` capture or
//!     `explorer.exe` / `sihost.exe` for user-session helpers).
//! - **RustDesk `src/privacy_mode.rs`** (AGPL-3.0):
//!   - [`PrivacyModeController`] with [`INVALID_PRIVACY_MODE_CONN_ID`], [`OCCUPIED`],
//!     and [`TURN_OFF_OTHER_ID`] ownership semantics so one connection cannot disable
//!     another connection's privacy screen, while service shutdown (`conn_id = 0`)
//!     always restores the physical monitor.

/// Connection ID `0` bypasses the privacy mode ownership check during shutdown,
/// reset, or guard cleanup (matching `INVALID_PRIVACY_MODE_CONN_ID` in
/// `rustdesk/src/privacy_mode.rs`).
pub const INVALID_PRIVACY_MODE_CONN_ID: i32 = 0;

/// Error message when another connection already holds privacy mode (`rustdesk/src/privacy_mode.rs`).
pub const OCCUPIED: &str = "Privacy occupied by another one.";

/// Error message when a non-owning connection attempts to disable privacy mode (`rustdesk/src/privacy_mode.rs`).
pub const TURN_OFF_OTHER_ID: &str = "Failed to turn off privacy mode that belongs to someone else.";

/// Ordered screen capture backends on Windows (`DXGI -> WGC -> GDI`),
/// modeled after Sunshine (`src/platform/windows/display_base.cpp`) and CrossDesk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureBackendKind {
    /// Primary zero-copy GPU path: `IDXGIOutput5::DuplicateOutput1`.
    DxgiDesktopDuplication,
    /// Secondary compositor path: `Windows.Graphics.Capture` (`WGC`).
    WindowsGraphicsCapture,
    /// Universal fallback path (works in nested RDP / basic display): GDI `BitBlt`.
    GdiBitBlt,
}

/// Manages fallback progression across [`CaptureBackendKind`]s (`DXGI -> WGC -> GDI`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureFallbackChain {
    current: CaptureBackendKind,
}

impl Default for CaptureFallbackChain {
    fn default() -> Self {
        Self::new()
    }
}

impl CaptureFallbackChain {
    /// Starts at the highest-performance backend ([`CaptureBackendKind::DxgiDesktopDuplication`]).
    #[must_use]
    pub const fn new() -> Self {
        Self {
            current: CaptureBackendKind::DxgiDesktopDuplication,
        }
    }

    /// Currently active capture backend.
    #[must_use]
    pub const fn current(&self) -> CaptureBackendKind {
        self.current
    }

    /// Advances to the next fallback backend after initialization failure,
    /// returning `None` if even [`CaptureBackendKind::GdiBitBlt`] failed.
    pub const fn advance_on_failure(&mut self) -> Option<CaptureBackendKind> {
        match self.current {
            CaptureBackendKind::DxgiDesktopDuplication => {
                self.current = CaptureBackendKind::WindowsGraphicsCapture;
                Some(self.current)
            }
            CaptureBackendKind::WindowsGraphicsCapture => {
                self.current = CaptureBackendKind::GdiBitBlt;
                Some(self.current)
            }
            CaptureBackendKind::GdiBitBlt => None,
        }
    }

    /// Resets the chain back to [`CaptureBackendKind::DxgiDesktopDuplication`]
    /// (e.g., after a desktop/session switch completes).
    pub const fn reset(&mut self) {
        self.current = CaptureBackendKind::DxgiDesktopDuplication;
    }
}

/// Reason privacy mode was turned off, matching `PrivacyModeState` in
/// `rustdesk/src/privacy_mode.rs`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivacyModeState {
    /// Restored cleanly by the owning connection or shutdown guard.
    OffSucceeded,
    /// Restored because the remote peer disconnected.
    OffByPeer,
    /// Restored due to an unexpected error or desktop reset.
    OffUnknown,
}

/// Errors returned by [`PrivacyModeController`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PrivacyError {
    /// Another connection already owns privacy mode.
    #[error("{OCCUPIED}")]
    Occupied,
    /// The caller's `conn_id` does not match the connection that enabled privacy mode.
    #[error("{TURN_OFF_OTHER_ID}")]
    WrongOwner,
}

/// Tracks privacy-mode ownership and physical display blanking state, ported from
/// `PrivacyMode` in `rustdesk/src/privacy_mode.rs`.
#[derive(Debug, Clone)]
pub struct PrivacyModeController {
    owner_conn_id: i32,
    active: bool,
    last_off_state: Option<PrivacyModeState>,
}

impl Default for PrivacyModeController {
    fn default() -> Self {
        Self::new()
    }
}

impl PrivacyModeController {
    /// Creates a new [`PrivacyModeController`] with privacy mode off.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            owner_conn_id: INVALID_PRIVACY_MODE_CONN_ID,
            active: false,
            last_off_state: None,
        }
    }

    /// Returns `true` if the physical monitor is currently blanked in privacy mode.
    #[must_use]
    pub const fn is_active(&self) -> bool {
        self.active
    }

    /// Returns the connection ID that currently owns privacy mode (`0` if none).
    #[must_use]
    pub const fn owner_conn_id(&self) -> i32 {
        self.owner_conn_id
    }

    /// Last recorded [`PrivacyModeState`] when privacy mode was turned off.
    #[must_use]
    pub const fn last_off_state(&self) -> Option<PrivacyModeState> {
        self.last_off_state
    }

    /// Checks whether `conn_id` may turn on privacy mode (`check_on_conn_id` in
    /// `rustdesk/src/privacy_mode.rs`).
    ///
    /// # Errors
    ///
    /// Returns [`PrivacyError::Occupied`] if another connection already holds privacy mode.
    pub const fn check_on_conn_id(&self, conn_id: i32) -> Result<bool, PrivacyError> {
        if self.owner_conn_id == conn_id && conn_id != INVALID_PRIVACY_MODE_CONN_ID {
            return Ok(true);
        }
        if self.owner_conn_id != INVALID_PRIVACY_MODE_CONN_ID {
            return Err(PrivacyError::Occupied);
        }
        Ok(false)
    }

    /// Checks whether `conn_id` may turn off privacy mode (`check_off_conn_id` in
    /// `rustdesk/src/privacy_mode.rs`).
    ///
    /// Passing [`INVALID_PRIVACY_MODE_CONN_ID`] (`0`) deliberately bypasses the
    /// ownership check so service shutdown or reset always restores the physical monitor.
    ///
    /// # Errors
    ///
    /// Returns [`PrivacyError::WrongOwner`] if `conn_id` is non-zero and does not
    /// match `self.owner_conn_id`.
    pub const fn check_off_conn_id(&self, conn_id: i32) -> Result<(), PrivacyError> {
        if self.owner_conn_id != INVALID_PRIVACY_MODE_CONN_ID
            && conn_id != INVALID_PRIVACY_MODE_CONN_ID
            && self.owner_conn_id != conn_id
        {
            return Err(PrivacyError::WrongOwner);
        }
        Ok(())
    }

    /// Enables privacy mode for `conn_id`.
    ///
    /// # Errors
    ///
    /// Returns [`PrivacyError::Occupied`] if another connection owns privacy mode.
    pub fn turn_on(&mut self, conn_id: i32) -> Result<bool, PrivacyError> {
        if self.check_on_conn_id(conn_id)? {
            return Ok(true);
        }
        self.owner_conn_id = conn_id;
        self.active = true;
        Ok(true)
    }

    /// Disables privacy mode for `conn_id` (or unconditionally when
    /// `conn_id == INVALID_PRIVACY_MODE_CONN_ID`).
    ///
    /// # Errors
    ///
    /// Returns [`PrivacyError::WrongOwner`] if `conn_id` belongs to another viewer.
    pub fn turn_off(
        &mut self,
        conn_id: i32,
        state: Option<PrivacyModeState>,
    ) -> Result<(), PrivacyError> {
        self.check_off_conn_id(conn_id)?;
        self.owner_conn_id = INVALID_PRIVACY_MODE_CONN_ID;
        self.active = false;
        self.last_off_state = state;
        Ok(())
    }
}

/// Target token kind when the `SYSTEM` service launches a worker in an active
/// Windows session (`GetLogonPid` in `rustdesk/src/platform/windows.cc`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionTokenTarget {
    /// Use `winlogon.exe` (`SYSTEM` token inside the session) to capture the
    /// login screen, lock screen, and UAC Secure Desktop (`as_user = FALSE`).
    WinlogonSystem,
    /// Use `explorer.exe` (falling back to `sihost.exe`) to run as the logged-in
    /// interactive user (`as_user = TRUE`).
    InteractiveUser,
}

/// Action required when the Windows console/RDP session or input desktop changes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DesktopHandoffAction {
    /// Session and desktop are unchanged.
    None,
    /// The input desktop switched within the same session (e.g., `Default` -> `Winlogon`
    /// for UAC or lock screen); call [`select_input_desktop`] and reopen the capturer.
    SwitchDesktop {
        /// New input desktop name (`"Default"`, `"Winlogon"`, etc.).
        desktop_name: String,
    },
    /// The active Windows session ID changed (e.g., console login or RDP handoff);
    /// relaunch the capture worker in `new_session_id` using `winlogon.exe`.
    RespawnSessionWorker {
        /// Previous Windows session ID.
        previous_session_id: Option<u32>,
        /// New active Windows session ID.
        new_session_id: u32,
        /// Current input desktop name.
        desktop_name: String,
    },
}

/// Tracks Windows session ID and desktop transitions (`winsta0\default` <->
/// `winsta0\winlogon`) for the `SYSTEM` service supervisor.
#[derive(Debug, Default, Clone)]
pub struct DesktopHandoffMonitor {
    current_session_id: Option<u32>,
    current_desktop_name: String,
}

impl DesktopHandoffMonitor {
    /// Creates a new [`DesktopHandoffMonitor`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Observes `(session_id, desktop_name)` and returns the required [`DesktopHandoffAction`].
    pub fn observe(&mut self, session_id: u32, desktop_name: &str) -> DesktopHandoffAction {
        if self.current_session_id != Some(session_id) {
            let previous = self.current_session_id.replace(session_id);
            desktop_name.clone_into(&mut self.current_desktop_name);
            return DesktopHandoffAction::RespawnSessionWorker {
                previous_session_id: previous,
                new_session_id: session_id,
                desktop_name: desktop_name.to_owned(),
            };
        }
        if !self.current_desktop_name.eq_ignore_ascii_case(desktop_name) {
            desktop_name.clone_into(&mut self.current_desktop_name);
            return DesktopHandoffAction::SwitchDesktop {
                desktop_name: desktop_name.to_owned(),
            };
        }
        DesktopHandoffAction::None
    }
}

#[cfg(windows)]
#[allow(
    unsafe_code,
    reason = "Win32 desktop switching and process snapshot APIs require FFI"
)]
mod windows_impl {
    use std::mem::size_of;

    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
        TH32CS_SNAPPROCESS,
    };
    use windows::Win32::System::RemoteDesktop::{
        ProcessIdToSessionId, WTSGetActiveConsoleSessionId,
    };
    use windows::Win32::System::StationsAndDesktops::{
        CloseDesktop, DESKTOP_ACCESS_FLAGS, DESKTOP_CONTROL_FLAGS, DESKTOP_CREATEMENU,
        DESKTOP_CREATEWINDOW, DESKTOP_ENUMERATE, DESKTOP_HOOKCONTROL, DESKTOP_READOBJECTS,
        DESKTOP_SWITCHDESKTOP, DESKTOP_WRITEOBJECTS, GetThreadDesktop, GetUserObjectInformationW,
        HDESK, OpenInputDesktop, SetThreadDesktop, UOI_NAME,
    };
    use windows::Win32::System::Threading::GetCurrentThreadId;

    use super::SessionTokenTarget;

    const DESKTOP_ACCESS_MASK: u32 = DESKTOP_CREATEMENU.0
        | DESKTOP_CREATEWINDOW.0
        | DESKTOP_ENUMERATE.0
        | DESKTOP_HOOKCONTROL.0
        | DESKTOP_WRITEOBJECTS.0
        | DESKTOP_READOBJECTS.0
        | DESKTOP_SWITCHDESKTOP.0
        | 0x4000_0000; // GENERIC_WRITE

    /// Returns the active Windows console session ID (`WTSGetActiveConsoleSessionId`).
    #[must_use]
    pub fn active_console_session_id() -> Option<u32> {
        // SAFETY: `WTSGetActiveConsoleSessionId` takes no parameters and is always safe to call.
        let id = unsafe { WTSGetActiveConsoleSessionId() };
        if id == 0xFFFF_FFFF { None } else { Some(id) }
    }

    /// Queries the name of a desktop handle (`"Default"`, `"Winlogon"`, etc.) via
    /// `GetUserObjectInformationW(..., UOI_NAME, ...)`.
    fn desktop_name(desk: HDESK) -> Option<String> {
        let mut buf = [0u16; 128];
        let mut needed = 0u32;
        #[allow(clippy::cast_possible_truncation)]
        let byte_len = (buf.len() * size_of::<u16>()) as u32;
        // SAFETY: `buf` is a stack buffer of `byte_len` bytes and `needed` is a valid out-pointer.
        let ok = unsafe {
            GetUserObjectInformationW(
                HANDLE(desk.0),
                UOI_NAME,
                Some(buf.as_mut_ptr().cast()),
                byte_len,
                Some(&raw mut needed),
            )
        };
        if ok.is_err() {
            return None;
        }
        let nul_pos = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        String::from_utf16(&buf[..nul_pos]).ok()
    }

    /// Determines whether the current thread's desktop matches the active input
    /// desktop, ported from `inputDesktopSelected()` in `rustdesk/src/platform/windows.cc`.
    #[must_use]
    pub fn input_desktop_selected() -> bool {
        // SAFETY: `GetCurrentThreadId` has no preconditions.
        let thread_id = unsafe { GetCurrentThreadId() };
        // SAFETY: `GetThreadDesktop` returns a non-owning handle for the current thread.
        let Ok(current) = (unsafe { GetThreadDesktop(thread_id) }) else {
            return false;
        };
        // SAFETY: `OpenInputDesktop` opens the currently active input desktop.
        let Ok(input) = (unsafe {
            OpenInputDesktop(
                DESKTOP_CONTROL_FLAGS(0),
                false,
                DESKTOP_ACCESS_FLAGS(DESKTOP_ACCESS_MASK),
            )
        }) else {
            return false;
        };
        let cur_name = desktop_name(current);
        let in_name = desktop_name(input);
        // SAFETY: `input` was opened by `OpenInputDesktop` and must be closed with `CloseDesktop`.
        unsafe {
            let _ = CloseDesktop(input);
        }
        match (cur_name, in_name) {
            (Some(a), Some(b)) => a.eq_ignore_ascii_case(&b),
            _ => false,
        }
    }

    /// Switches the calling thread onto the active input desktop (`winsta0\default`
    /// or `winsta0\winlogon`), ported from `selectInputDesktop()` in
    /// `rustdesk/src/platform/windows.cc`.
    #[must_use]
    pub fn select_input_desktop() -> Option<String> {
        // SAFETY: `OpenInputDesktop` opens a handle to the active input desktop.
        let Ok(input) = (unsafe {
            OpenInputDesktop(
                DESKTOP_CONTROL_FLAGS(0),
                false,
                DESKTOP_ACCESS_FLAGS(DESKTOP_ACCESS_MASK),
            )
        }) else {
            return None;
        };
        let name = desktop_name(input);
        // SAFETY: `GetCurrentThreadId` has no preconditions.
        let thread_id = unsafe { GetCurrentThreadId() };
        // SAFETY: `GetThreadDesktop` returns the previous desktop handle of this thread.
        let old_desktop = unsafe { GetThreadDesktop(thread_id) }.ok();
        // SAFETY: `input` is a valid desktop handle from `OpenInputDesktop`.
        let switched = unsafe { SetThreadDesktop(input) };
        if switched.is_err() {
            // SAFETY: Close `input` when `SetThreadDesktop` fails.
            unsafe {
                let _ = CloseDesktop(input);
            }
            return None;
        }
        if let Some(old) = old_desktop {
            // SAFETY: Close the old desktop handle after switching (matching `switchToDesktop` in `windows.cc`).
            unsafe {
                let _ = CloseDesktop(old);
            }
        }
        name
    }

    /// Finds the PID of `winlogon.exe` (for `SessionTokenTarget::WinlogonSystem`) or
    /// `explorer.exe` / `sihost.exe` (for `SessionTokenTarget::InteractiveUser`) in
    /// `session_id`, ported from `GetLogonPid` and `GetFallbackUserPid` in
    /// `rustdesk/src/platform/windows.cc`.
    #[must_use]
    pub fn find_session_target_pid(session_id: u32, target: SessionTokenTarget) -> Option<u32> {
        let primary_exe = match target {
            SessionTokenTarget::WinlogonSystem => "winlogon.exe",
            SessionTokenTarget::InteractiveUser => "explorer.exe",
        };
        if let Some(pid) = scan_process_in_session(session_id, primary_exe) {
            return Some(pid);
        }
        if target == SessionTokenTarget::InteractiveUser {
            return scan_process_in_session(session_id, "sihost.exe");
        }
        None
    }

    fn scan_process_in_session(target_session_id: u32, exe_name: &str) -> Option<u32> {
        // SAFETY: `CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)` takes a process snapshot.
        let Ok(snap) = (unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }) else {
            return None;
        };
        #[allow(clippy::cast_possible_truncation)]
        let dw_size = size_of::<PROCESSENTRY32W>() as u32;
        let mut entry = PROCESSENTRY32W {
            dwSize: dw_size,
            ..PROCESSENTRY32W::default()
        };

        let mut matched_pid = None;
        // SAFETY: `entry.dwSize` is initialized to `size_of::<PROCESSENTRY32W>()`.
        if unsafe { Process32FirstW(snap, &raw mut entry) }.is_ok() {
            loop {
                let nul = entry
                    .szExeFile
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(entry.szExeFile.len());
                if let Ok(name) = String::from_utf16(&entry.szExeFile[..nul])
                    && name.eq_ignore_ascii_case(exe_name)
                {
                    let mut proc_session = 0u32;
                    // SAFETY: `proc_session` is a valid out-pointer for `ProcessIdToSessionId`.
                    if unsafe { ProcessIdToSessionId(entry.th32ProcessID, &raw mut proc_session) }
                        .is_ok()
                        && proc_session == target_session_id
                    {
                        matched_pid = Some(entry.th32ProcessID);
                        break;
                    }
                }
                // SAFETY: `snap` and `entry` are valid for iterating the snapshot.
                if unsafe { Process32NextW(snap, &raw mut entry) }.is_err() {
                    break;
                }
            }
        }
        // SAFETY: `snap` is a valid snapshot handle from `CreateToolhelp32Snapshot`.
        unsafe {
            let _ = CloseHandle(snap);
        }
        matched_pid
    }
}

#[cfg(windows)]
pub use windows_impl::{
    active_console_session_id, find_session_target_pid, input_desktop_selected,
    select_input_desktop,
};

#[cfg(not(windows))]
/// Stub for non-Windows platforms.
#[must_use]
pub const fn active_console_session_id() -> Option<u32> {
    None
}

#[cfg(not(windows))]
/// Stub for non-Windows platforms.
#[must_use]
pub const fn input_desktop_selected() -> bool {
    true
}

#[cfg(not(windows))]
/// Stub for non-Windows platforms.
#[must_use]
pub const fn select_input_desktop() -> Option<String> {
    None
}

#[cfg(not(windows))]
/// Stub for non-Windows platforms.
#[must_use]
pub const fn find_session_target_pid(_session_id: u32, _target: SessionTokenTarget) -> Option<u32> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fallback_chain_progresses_dxgi_to_wgc_to_gdi() {
        let mut chain = CaptureFallbackChain::new();
        assert_eq!(chain.current(), CaptureBackendKind::DxgiDesktopDuplication);
        assert_eq!(
            chain.advance_on_failure(),
            Some(CaptureBackendKind::WindowsGraphicsCapture)
        );
        assert_eq!(
            chain.advance_on_failure(),
            Some(CaptureBackendKind::GdiBitBlt)
        );
        assert_eq!(chain.advance_on_failure(), None);
        chain.reset();
        assert_eq!(chain.current(), CaptureBackendKind::DxgiDesktopDuplication);
    }

    #[test]
    fn privacy_mode_enforces_owner_conn_id_and_allows_zero_override() {
        let mut privacy = PrivacyModeController::new();
        assert!(!privacy.is_active());

        // Connection 101 turns on privacy mode
        assert!(privacy.turn_on(101).unwrap());
        assert!(privacy.is_active());
        assert_eq!(privacy.owner_conn_id(), 101);

        // Connection 202 cannot turn on or turn off Connection 101's privacy mode
        assert_eq!(privacy.turn_on(202), Err(PrivacyError::Occupied));
        assert_eq!(
            privacy.turn_off(202, Some(PrivacyModeState::OffByPeer)),
            Err(PrivacyError::WrongOwner)
        );

        // Connection 101 can turn it off
        privacy
            .turn_off(101, Some(PrivacyModeState::OffByPeer))
            .unwrap();
        assert!(!privacy.is_active());
        assert_eq!(privacy.last_off_state(), Some(PrivacyModeState::OffByPeer));

        // Service shutdown (`INVALID_PRIVACY_MODE_CONN_ID = 0`) always turns off privacy mode
        privacy.turn_on(303).unwrap();
        privacy
            .turn_off(
                INVALID_PRIVACY_MODE_CONN_ID,
                Some(PrivacyModeState::OffSucceeded),
            )
            .unwrap();
        assert!(!privacy.is_active());
    }

    #[test]
    fn desktop_handoff_monitor_detects_winlogon_and_rdp_transitions() {
        let mut mon = DesktopHandoffMonitor::new();
        assert_eq!(
            mon.observe(1, "Default"),
            DesktopHandoffAction::RespawnSessionWorker {
                previous_session_id: None,
                new_session_id: 1,
                desktop_name: "Default".to_owned(),
            }
        );
        assert_eq!(mon.observe(1, "default"), DesktopHandoffAction::None);

        // UAC prompt or screen lock switches desktop to Winlogon within session 1
        assert_eq!(
            mon.observe(1, "Winlogon"),
            DesktopHandoffAction::SwitchDesktop {
                desktop_name: "Winlogon".to_owned(),
            }
        );

        // RDP handoff or fast user switch moves active console to session 2
        assert_eq!(
            mon.observe(2, "Default"),
            DesktopHandoffAction::RespawnSessionWorker {
                previous_session_id: Some(1),
                new_session_id: 2,
                desktop_name: "Default".to_owned(),
            }
        );
    }
}
