//! Privacy mode: blanks the local screen while the remote operator keeps
//! working.
//!
//! Approach and why this one. RustDesk's `win_mag` privacy mode pairs a
//! fullscreen black *topmost* window (`src/privacy_mode/win_topmost_window.rs`,
//! which blanks the local display) with a Magnification-API capturer
//! (`libs/scrap/src/dxgi/mag.rs`, which still captures the real screen for the
//! remote by excluding that black window from the magnifier source). That needs
//! a second, separate capture path and a 5-second exclude-retry loop.
//!
//! OmegaDesk reaches the same result with a single primitive:
//! `SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE)`. A window with this
//! affinity is shown normally on the physical monitor but is **absent from
//! screen captures** (DXGI Desktop Duplication on Windows 10 2004+ and Windows
//! Graphics Capture both honour it). So a fullscreen opaque black window with
//! `WDA_EXCLUDEFROMCAPTURE`:
//! - covers the physical display -> the local person sees only black, and
//! - is excluded from the capture -> the remote operator sees the real desktop
//!   underneath, through the existing DXGI/WGC capture path, with no second
//!   capturer and no magnifier message pumping.
//!
//! This is also exactly the "connection-scoped `WDA_EXCLUDEFROMCAPTURE`
//! exclusion" the project already modelled: the overlay is owned by one
//! connection (`PrivacyModeController::owner_conn_id`) and
//! [`set_excluded_from_capture`] is the reusable primitive for excluding any
//! window (e.g. a sensitive local app) from a connection's stream.
//!
//! The overlay lives on its own thread with a minimal message loop, placed on
//! the active input desktop so it blanks whichever desktop (Default or
//! Winlogon) is in front.

#![allow(
    unsafe_code,
    reason = "creating a layered topmost window and setting its display affinity requires User32 FFI"
)]

use std::sync::mpsc;
use std::thread::JoinHandle;

use anyhow::{Context, bail};
use windows::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
use windows::Win32::Graphics::Gdi::{BLACK_BRUSH, GetStockObject, HBRUSH};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetMessageW,
    GetSystemMetrics, HWND_TOPMOST, MSG, PostQuitMessage, PostThreadMessageW, RegisterClassExW,
    SM_CXVIRTUALSCREEN, SM_CYVIRTUALSCREEN, SM_XVIRTUALSCREEN, SM_YVIRTUALSCREEN, SW_SHOW,
    SWP_NOACTIVATE, SetWindowDisplayAffinity, SetWindowPos, ShowWindow, TranslateMessage,
    WDA_EXCLUDEFROMCAPTURE, WDA_NONE, WINDOW_DISPLAY_AFFINITY, WM_APP, WM_DESTROY, WNDCLASSEXW,
    WS_EX_LAYERED, WS_EX_NOACTIVATE, WS_EX_TOOLWINDOW, WS_EX_TOPMOST, WS_POPUP,
};
use windows::core::w;

/// Private message that tells the overlay thread to tear the window down.
const WM_PRIVACY_CLOSE: u32 = WM_APP + 1;

/// A fullscreen black overlay that blanks the local screen. Dropping it (or
/// calling [`Self::disable`]) removes the overlay and restores the display.
#[derive(Debug)]
pub(crate) struct PrivacyOverlay {
    thread_id: u32,
    handle: Option<JoinHandle<()>>,
}

impl PrivacyOverlay {
    /// Creates the overlay on the active input desktop and returns once it is
    /// shown and excluded from capture.
    ///
    /// # Errors
    ///
    /// Returns an error if the window class cannot be registered or the window
    /// cannot be created.
    pub(crate) fn enable() -> anyhow::Result<Self> {
        let (tx, rx) = mpsc::channel::<anyhow::Result<u32>>();
        let handle = std::thread::Builder::new()
            .name("omegadesk-privacy".to_owned())
            .spawn(move || overlay_thread(&tx))
            .context("failed to spawn the privacy overlay thread")?;
        match rx.recv() {
            Ok(Ok(thread_id)) => Ok(Self {
                thread_id,
                handle: Some(handle),
            }),
            Ok(Err(error)) => {
                let _ = handle.join();
                Err(error)
            }
            Err(_) => {
                let _ = handle.join();
                bail!("the privacy overlay thread exited before signalling readiness")
            }
        }
    }

    /// Removes the overlay and waits for its thread to exit.
    pub(crate) fn disable(mut self) {
        self.teardown();
    }

    fn teardown(&mut self) {
        if let Some(handle) = self.handle.take() {
            // SAFETY: `thread_id` is the id of the still-running overlay thread;
            // posting a thread message to it is always safe.
            unsafe {
                let _ = PostThreadMessageW(self.thread_id, WM_PRIVACY_CLOSE, WPARAM(0), LPARAM(0));
            }
            let _ = handle.join();
        }
    }
}

impl Drop for PrivacyOverlay {
    fn drop(&mut self) {
        self.teardown();
    }
}

/// Body of the overlay thread: put the thread on the active input desktop,
/// create the fullscreen black window, mark it excluded from capture, and pump
/// messages until asked to close.
fn overlay_thread(ready: &mpsc::Sender<anyhow::Result<u32>>) {
    // The overlay must live on whichever desktop is currently in front.
    let _ = omegadesk_capture::service_desktop::select_input_desktop();

    let hwnd = match create_overlay_window() {
        Ok(hwnd) => hwnd,
        Err(error) => {
            let _ = ready.send(Err(error));
            return;
        }
    };
    // SAFETY: `GetCurrentThreadId` has no preconditions.
    let thread_id = unsafe { windows::Win32::System::Threading::GetCurrentThreadId() };
    if ready.send(Ok(thread_id)).is_err() {
        // The owner went away before we signalled; tear down immediately.
        // SAFETY: `hwnd` is the window this thread just created.
        unsafe {
            let _ = DestroyWindow(hwnd);
        }
        return;
    }

    let mut msg = MSG::default();
    loop {
        // SAFETY: `msg` is a valid out-pointer; a null HWND filter pumps both
        // window messages and thread messages for this thread.
        let got = unsafe { GetMessageW(&raw mut msg, None, 0, 0) };
        if got.0 <= 0 {
            break; // WM_QUIT (0) or error (-1).
        }
        if msg.message == WM_PRIVACY_CLOSE {
            // SAFETY: `hwnd` is valid for the lifetime of this loop.
            unsafe {
                let _ = DestroyWindow(hwnd);
            }
            continue;
        }
        // SAFETY: `msg` was filled by GetMessageW.
        unsafe {
            let _ = TranslateMessage(&raw const msg);
        }
        // SAFETY: `msg` was filled by GetMessageW.
        unsafe {
            DispatchMessageW(&raw const msg);
        }
    }
}

/// Creates the fullscreen, topmost, black, capture-excluded overlay window.
fn create_overlay_window() -> anyhow::Result<HWND> {
    // SAFETY: passing None returns the current module handle without allocation.
    let instance = unsafe { GetModuleHandleW(None) }.context("GetModuleHandleW failed")?;

    let class_name = w!("OmegaDeskPrivacyOverlay");
    let wnd_class = WNDCLASSEXW {
        cbSize: u32::try_from(size_of::<WNDCLASSEXW>()).unwrap_or(0),
        lpfnWndProc: Some(overlay_wndproc),
        hInstance: instance.into(),
        // SAFETY: BLACK_BRUSH is a valid stock-object index; the returned
        // handle is a stock brush that must not be freed.
        hbrBackground: HBRUSH(unsafe { GetStockObject(BLACK_BRUSH) }.0),
        lpszClassName: class_name,
        ..Default::default()
    };
    // SAFETY: `wnd_class` is fully initialised and points at a static class
    // name and the stock brush. A zero return is tolerated when the class was
    // already registered by a previous privacy-mode activation.
    let _ = unsafe { RegisterClassExW(&raw const wnd_class) };

    let x = metric(SM_XVIRTUALSCREEN);
    let y = metric(SM_YVIRTUALSCREEN);
    let width = metric(SM_CXVIRTUALSCREEN).max(1);
    let height = metric(SM_CYVIRTUALSCREEN).max(1);

    // SAFETY: `class_name` is registered above, `instance` is valid, and all
    // other arguments are plain values; a null return is checked below.
    let hwnd = unsafe {
        CreateWindowExW(
            WS_EX_TOPMOST | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE | WS_EX_LAYERED,
            class_name,
            w!("OmegaDesk Privacy"),
            WS_POPUP,
            x,
            y,
            width,
            height,
            None,
            None,
            Some(instance.into()),
            None,
        )
    }
    .context("CreateWindowExW failed for the privacy overlay")?;

    // Exclude the overlay from screen capture so the remote sees through it,
    // then show it opaque on top of everything. This is the same
    // connection-scoped exclusion primitive exposed as
    // [`set_excluded_from_capture`].
    set_excluded_from_capture(hwnd, true)
        .context("excluding the privacy overlay from capture failed")?;
    // SAFETY: `hwnd` is valid; HWND_TOPMOST with SWP_NOACTIVATE keeps it on top.
    unsafe {
        let _ = SetWindowPos(
            hwnd,
            Some(HWND_TOPMOST),
            x,
            y,
            width,
            height,
            SWP_NOACTIVATE,
        );
    }
    // SAFETY: `hwnd` is valid; showing it makes the blanking visible.
    unsafe {
        let _ = ShowWindow(hwnd, SW_SHOW);
    }
    Ok(hwnd)
}

/// Returns a `GetSystemMetrics` value for one metric index.
fn metric(index: windows::Win32::UI::WindowsAndMessaging::SYSTEM_METRICS_INDEX) -> i32 {
    // SAFETY: GetSystemMetrics takes a valid metric index and cannot fail.
    unsafe { GetSystemMetrics(index) }
}

/// Window procedure: black background paints the window; closing it quits the
/// thread message loop.
extern "system" fn overlay_wndproc(
    hwnd: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    if message == WM_DESTROY {
        // SAFETY: no preconditions; signals GetMessageW to return 0.
        unsafe { PostQuitMessage(0) };
        return LRESULT(0);
    }
    // SAFETY: forwarding to the default procedure with the original arguments is
    // always valid.
    unsafe { DefWindowProcW(hwnd, message, wparam, lparam) }
}

/// Excludes `hwnd` from (or restores it to) screen capture via
/// `SetWindowDisplayAffinity`. This is the connection-scoped exclusion
/// primitive: an operator can hide a sensitive local window from one stream.
///
/// # Errors
///
/// Returns an error if the window handle is invalid or the call fails.
pub(crate) fn set_excluded_from_capture(hwnd: HWND, excluded: bool) -> anyhow::Result<()> {
    let affinity: WINDOW_DISPLAY_AFFINITY = if excluded {
        WDA_EXCLUDEFROMCAPTURE
    } else {
        WDA_NONE
    };
    // SAFETY: `hwnd` is supplied by the caller; the call validates it and
    // returns an error for an invalid handle, which is propagated.
    unsafe { SetWindowDisplayAffinity(hwnd, affinity) }
        .context("SetWindowDisplayAffinity failed")?;
    Ok(())
}
