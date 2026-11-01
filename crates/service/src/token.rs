//! Launches the per-session worker as SYSTEM in a target console session.
//!
//! Ported from RustDesk `src/platform/windows.cc` (`GetSessionUserTokenWin` +
//! `LaunchProcessWin`) and `src/platform/windows.rs::launch_server`, and Aspia
//! `source/base/win/process_util.cc` (`createProcessWithToken`):
//!
//! 1. Find `winlogon.exe` in the target session (its token is the session's
//!    SYSTEM token) via
//!    [`omegadesk_capture::service_desktop::find_session_target_pid`].
//! 2. Open and duplicate that token to a primary token
//!    (`OpenProcessToken` + `DuplicateTokenEx`).
//! 3. `CreateProcessAsUserW` with `lpDesktop = winsta0\default` so the worker
//!    starts on the interactive desktop and then follows the input desktop
//!    (Default <-> Winlogon) itself with `SetThreadDesktop`.
//!
//! The worker is launched with the SYSTEM token (not the interactive user's
//! `WTSQueryUserToken` token) precisely so it can attach to the Winlogon secure
//! desktop and inject input there, which a non-elevated user token cannot do
//! (this is what "the worker runs as SYSTEM" means for secure-desktop support).
//! [`session_has_interactive_user`] still uses `WTSQueryUserToken` to tell a
//! logged-in session apart from the bare login screen for logging.

#![allow(
    unsafe_code,
    reason = "launching a process with another session's SYSTEM token requires Win32 token and process-creation FFI"
)]

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;

use anyhow::{Context, bail};
use omegadesk_capture::service_desktop::{SessionTokenTarget, find_session_target_pid};
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Security::{
    DuplicateTokenEx, SECURITY_ATTRIBUTES, SecurityImpersonation, TOKEN_ACCESS_MASK,
    TOKEN_ALL_ACCESS, TokenPrimary,
};
use windows::Win32::System::Environment::{CreateEnvironmentBlock, DestroyEnvironmentBlock};
use windows::Win32::System::RemoteDesktop::WTSQueryUserToken;
use windows::Win32::System::Threading::{
    CREATE_NO_WINDOW, CREATE_UNICODE_ENVIRONMENT, CreateProcessAsUserW, DETACHED_PROCESS,
    GetExitCodeProcess, OpenProcess, OpenProcessToken, PROCESS_CREATION_FLAGS, PROCESS_INFORMATION,
    PROCESS_QUERY_INFORMATION, STARTF_USESHOWWINDOW, STARTUPINFOW, TerminateProcess,
};
use windows::core::PWSTR;

/// `GetExitCodeProcess` returns this while the process is still running.
const STILL_ACTIVE: u32 = 259;

/// An owned Win32 `HANDLE` that is closed on drop.
struct OwnedHandle(HANDLE);

impl OwnedHandle {
    fn get(&self) -> HANDLE {
        self.0
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            // SAFETY: `self.0` is a valid handle this type owns and closes exactly once.
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

/// A launched worker process. The process handle is closed on drop; the worker
/// itself is not terminated on drop (use [`Self::terminate`]).
#[derive(Debug)]
pub(crate) struct WorkerProcess {
    process: HANDLE,
    pid: u32,
}

// SAFETY: a process HANDLE is a kernel handle valid across threads; the
// supervisor owns exactly one `WorkerProcess` and accesses it from one task.
unsafe impl Send for WorkerProcess {}

impl WorkerProcess {
    /// Process id of the worker.
    #[must_use]
    pub(crate) fn pid(&self) -> u32 {
        self.pid
    }

    /// Returns `true` while the worker process is still running.
    #[must_use]
    pub(crate) fn is_alive(&self) -> bool {
        let mut code = 0u32;
        // SAFETY: `self.process` is a valid process handle with query rights;
        // `code` is a valid out-pointer.
        let ok = unsafe { GetExitCodeProcess(self.process, &raw mut code) };
        ok.is_ok() && code == STILL_ACTIVE
    }

    /// Terminates the worker process (best effort).
    pub(crate) fn terminate(&self) {
        // SAFETY: `self.process` is a valid process handle; terminating an
        // already-exited process simply fails, which is ignored.
        unsafe {
            let _ = TerminateProcess(self.process, 1);
        }
    }
}

impl Drop for WorkerProcess {
    fn drop(&mut self) {
        if !self.process.is_invalid() {
            // SAFETY: `self.process` is a valid handle this type owns and closes once.
            unsafe {
                let _ = CloseHandle(self.process);
            }
        }
    }
}

/// Reports whether an interactive user is logged on to `session_id`
/// (`WTSQueryUserToken` succeeds), as opposed to the bare login screen.
#[must_use]
pub(crate) fn session_has_interactive_user(session_id: u32) -> bool {
    let mut token = HANDLE::default();
    // SAFETY: `token` is a valid out-pointer; on success it owns a handle we close.
    let ok = unsafe { WTSQueryUserToken(session_id, &raw mut token) };
    if ok.is_ok() && !token.is_invalid() {
        // SAFETY: `token` was returned by `WTSQueryUserToken` and is closed once.
        unsafe {
            let _ = CloseHandle(token);
        }
        true
    } else {
        false
    }
}

/// Launches the worker (`omegadesk-agent service worker ...`) as SYSTEM in
/// `session_id`, connecting back to the service on the named pipe `instance`.
///
/// # Errors
///
/// Returns an error if `winlogon.exe` is not found in the session, if its token
/// cannot be opened or duplicated, or if `CreateProcessAsUserW` fails.
pub(crate) fn launch_worker_in_session(
    session_id: u32,
    pipe_instance: &str,
    display: u32,
) -> anyhow::Result<WorkerProcess> {
    let winlogon_pid = find_session_target_pid(session_id, SessionTokenTarget::WinlogonSystem)
        .with_context(|| format!("winlogon.exe not found in session {session_id}"))?;
    let primary = duplicate_primary_token(winlogon_pid).with_context(|| {
        format!("failed to obtain SYSTEM token from winlogon pid {winlogon_pid}")
    })?;

    let exe = std::env::current_exe().context("failed to resolve the agent executable path")?;
    let exe = exe.to_string_lossy();
    // Quote the exe path (it can contain spaces); the worker reparses these args
    // with the same clap definition that produced them.
    let command = format!(
        "\"{exe}\" service worker --pipe {pipe_instance} --session {session_id} --display {display}"
    );
    let mut command_wide: Vec<u16> = OsStr::new(&command).encode_wide().chain([0]).collect();

    let desktop = wide(r"winsta0\default");
    let startup = STARTUPINFOW {
        cb: u32::try_from(size_of::<STARTUPINFOW>()).unwrap_or(0),
        dwFlags: STARTF_USESHOWWINDOW,
        lpDesktop: PWSTR(desktop.as_ptr().cast_mut()),
        ..Default::default()
    };
    let mut info = PROCESS_INFORMATION::default();

    // An environment block for the token keeps the worker's %PATH%/%TEMP% sane.
    let mut environment: *mut core::ffi::c_void = std::ptr::null_mut();
    // SAFETY: `primary` is a valid primary token; `environment` is a valid out-pointer.
    let has_env =
        unsafe { CreateEnvironmentBlock(&raw mut environment, Some(primary.get()), false).is_ok() };
    let mut flags: PROCESS_CREATION_FLAGS = CREATE_NO_WINDOW | DETACHED_PROCESS;
    if has_env {
        flags |= CREATE_UNICODE_ENVIRONMENT;
    }
    let env_ptr = if has_env {
        Some(environment.cast_const())
    } else {
        None
    };

    // SAFETY: `primary` is a valid primary token with full access; `command_wide`
    // is a NUL-terminated, writable UTF-16 command line; `startup` is a correctly
    // sized STARTUPINFOW pointing at a valid desktop string that outlives the
    // call; `info` is a valid out-pointer. `env_ptr`, when set, points at the
    // block CreateEnvironmentBlock just allocated.
    let result = unsafe {
        CreateProcessAsUserW(
            Some(primary.get()),
            None,
            Some(PWSTR(command_wide.as_mut_ptr())),
            None,
            None,
            false,
            flags,
            env_ptr,
            None,
            &raw const startup,
            &raw mut info,
        )
    };
    // `desktop`, `command_wide` and `startup` must outlive the call above, and
    // they do: they are locals dropped only at the end of the function.

    if has_env && !environment.is_null() {
        // SAFETY: `environment` was allocated by CreateEnvironmentBlock and is freed once.
        unsafe {
            let _ = DestroyEnvironmentBlock(environment);
        }
    }

    result.with_context(|| format!("CreateProcessAsUserW failed for session {session_id}"))?;

    if !info.hThread.is_invalid() {
        // SAFETY: `hThread` is a valid handle returned by CreateProcessAsUserW; closed once.
        unsafe {
            let _ = CloseHandle(info.hThread);
        }
    }
    Ok(WorkerProcess {
        process: info.hProcess,
        pid: info.dwProcessId,
    })
}

/// Opens `pid`'s token and duplicates it into a primary token usable by
/// `CreateProcessAsUserW`.
fn duplicate_primary_token(pid: u32) -> anyhow::Result<OwnedHandle> {
    // SAFETY: `pid` is a process id; `OpenProcess` returns a handle or an error.
    let process = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION, false, pid) }
        .with_context(|| format!("OpenProcess failed for pid {pid}"))?;
    let process = OwnedHandle(process);

    let mut token = HANDLE::default();
    // SAFETY: `process` is a valid handle; `token` is a valid out-pointer.
    unsafe { OpenProcessToken(process.get(), TOKEN_ALL_ACCESS, &raw mut token) }
        .context("OpenProcessToken failed")?;
    let token = OwnedHandle(token);

    let mut primary = HANDLE::default();
    // SAFETY: `token` is a valid token handle; `primary` is a valid out-pointer.
    unsafe {
        DuplicateTokenEx(
            token.get(),
            TOKEN_ACCESS_MASK(TOKEN_ALL_ACCESS.0),
            Some(&SECURITY_ATTRIBUTES::default()),
            SecurityImpersonation,
            TokenPrimary,
            &raw mut primary,
        )
    }
    .context("DuplicateTokenEx failed")?;
    if primary.is_invalid() {
        bail!("DuplicateTokenEx returned an invalid token");
    }
    Ok(OwnedHandle(primary))
}

/// Encodes a string as a NUL-terminated UTF-16 buffer for Win32.
fn wide(value: &str) -> Vec<u16> {
    OsStr::new(value).encode_wide().chain([0]).collect()
}
