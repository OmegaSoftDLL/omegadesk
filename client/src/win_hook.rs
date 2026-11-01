//! Windows client integration: Per-Monitor V2 DPI awareness, lock-key state
//! querying (`CapsLock`/`NumLock`), and a low-level keyboard hook
//! (`WH_KEYBOARD_LL`) that intercepts `Alt+Tab`, `Alt+Esc`, `LWin`, `RWin`, and
//! Windows synthetic `AltGr` left-Control events while the client window is focused.
//!
//! Reference implementations:
//! - RustDesk (`src/keyboard.rs`): `WH_KEYBOARD_LL` hook suppressing synthetic
//!   `AltGr` scan code `0x021D` and forwarding `VK_LWIN`/`VK_RWIN`/`Alt+Tab`.
//! - FreeRDP (`client/Windows/wf_event.c`): `wf_ll_kbd_proc` low-level hook
//!   capturing system shortcuts when the remote window has focus.
//! - Sunshine (`src/platform/windows/display_base.cpp`):
//!   `SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2)`.

#![cfg_attr(
    not(windows),
    allow(
        dead_code,
        reason = "hook classifier items are exercised by unit tests on all platforms and by Win32 hook on Windows"
    )
)]

use std::sync::atomic::{AtomicBool, Ordering};

use omegadesk_input::INJECTED_MARKER;
use omegadesk_protocol::v1::Envelope;
use tokio::sync::mpsc;

/// Scan code emitted by Windows for the synthetic `ControlLeft` event that
/// precedes `AltRight` on layouts with `AltGr` (RustDesk `src/keyboard.rs:697`).
pub(crate) const ALTGR_FAKE_LCNTRL_SCANCODE: u32 = 0x021D;

static FOCUSED: AtomicBool = AtomicBool::new(false);

/// Action decided by the low-level keyboard hook classifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HookDecision {
    /// Pass the key event to the next hook / local window procedure.
    PassThrough,
    /// Swallow the key event without sending anything to the remote host
    /// (used for the synthetic `0x021D` left-Control emitted by `AltGr`).
    Swallow,
    /// Swallow the key event locally and forward the given HID usage to the
    /// remote host.
    ForwardHid(u32),
}

/// Pure classifier for `WH_KEYBOARD_LL` events so the interception rules can be
/// unit-tested on every platform.
#[must_use]
pub(crate) fn classify_ll_key(
    focused: bool,
    vkey: u32,
    scan_code: u32,
    alt_down: bool,
    extra_info: usize,
) -> HookDecision {
    if !focused || extra_info == INJECTED_MARKER {
        return HookDecision::PassThrough;
    }
    if scan_code == ALTGR_FAKE_LCNTRL_SCANCODE {
        return HookDecision::Swallow;
    }
    match vkey {
        // VK_LWIN (0x5B) -> HID Keyboard Left GUI (0xE3)
        0x5B => HookDecision::ForwardHid(0xE3),
        // VK_RWIN (0x5C) -> HID Keyboard Right GUI (0xE7)
        0x5C => HookDecision::ForwardHid(0xE7),
        // VK_TAB (0x09) with Alt held -> HID Keyboard Tab (0x2B)
        0x09 if alt_down => HookDecision::ForwardHid(0x2B),
        // VK_ESCAPE (0x1B) with Alt held -> HID Keyboard Escape (0x29)
        0x1B if alt_down => HookDecision::ForwardHid(0x29),
        _ => HookDecision::PassThrough,
    }
}

/// Updates whether the client window currently owns keyboard focus.
pub(crate) fn set_focused(focused: bool) {
    FOCUSED.store(focused, Ordering::Relaxed);
}

/// Enables Per-Monitor V2 DPI awareness before creating any windows.
pub(crate) fn enable_dpi_awareness() {
    #[cfg(windows)]
    windows_impl::enable_dpi_awareness();
}

/// Reads the current local `CapsLock` and `NumLock` toggle states as protocol
/// modifier flags.
#[must_use]
pub(crate) fn lock_modifiers() -> u32 {
    #[cfg(windows)]
    {
        windows_impl::lock_modifiers()
    }
    #[cfg(not(windows))]
    {
        0
    }
}

/// RAII guard for the thread-scoped `WH_KEYBOARD_LL` hook on Windows.
pub(crate) struct KeyboardHook {
    #[cfg(windows)]
    #[allow(dead_code, reason = "RAII guard keeps WH_KEYBOARD_LL installed")]
    inner: Option<windows_impl::HookGuard>,
}

impl KeyboardHook {
    /// Installs the low-level keyboard hook when `view_only` is `false`.
    #[must_use]
    pub(crate) fn install(sender: mpsc::UnboundedSender<Envelope>, view_only: bool) -> Self {
        #[cfg(windows)]
        {
            let inner = if view_only {
                None
            } else {
                windows_impl::HookGuard::install(sender)
            };
            Self { inner }
        }
        #[cfg(not(windows))]
        {
            let _ = (sender, view_only);
            Self {}
        }
    }
}

#[cfg(windows)]
#[allow(
    unsafe_code,
    reason = "Win32 SetProcessDpiAwarenessContext, GetKeyState, and SetWindowsHookExW"
)]
mod windows_impl {
    use std::sync::Mutex;
    use std::sync::atomic::Ordering;

    use omegadesk_input::modifiers;
    use omegadesk_protocol::v1::{Envelope, KeyEvent, envelope::Payload};
    use tokio::sync::mpsc;
    use tracing::debug;
    use windows::Win32::Foundation::{LPARAM, LRESULT, WPARAM};
    use windows::Win32::UI::HiDpi::{
        DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2, SetProcessDpiAwarenessContext,
    };
    use windows::Win32::UI::Input::KeyboardAndMouse::{GetKeyState, VK_CAPITAL, VK_NUMLOCK};
    use windows::Win32::UI::WindowsAndMessaging::{
        CallNextHookEx, HC_ACTION, HHOOK, KBDLLHOOKSTRUCT, LLKHF_ALTDOWN, SetWindowsHookExW,
        UnhookWindowsHookEx, WH_KEYBOARD_LL, WM_KEYDOWN, WM_KEYUP, WM_SYSKEYDOWN, WM_SYSKEYUP,
    };

    use super::{FOCUSED, HookDecision, classify_ll_key};

    static HOOK_SENDER: Mutex<Option<mpsc::UnboundedSender<Envelope>>> = Mutex::new(None);

    pub(super) fn enable_dpi_awareness() {
        // SAFETY: `DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2` is a valid predefined
        // Win32 constant; failure is benign if a manifest or parent already set it.
        let result =
            unsafe { SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2) };
        if let Err(error) = result {
            debug!("SetProcessDpiAwarenessContext(PerMonitorV2) skipped: {error}");
        }
    }

    pub(super) fn lock_modifiers() -> u32 {
        // SAFETY: `GetKeyState` is safe to call on any thread; bit 0 indicates the toggle state.
        let caps_on = (unsafe { GetKeyState(i32::from(VK_CAPITAL.0)) } & 1) != 0;
        // SAFETY: `GetKeyState` is safe to call on any thread; bit 0 indicates the toggle state.
        let num_on = (unsafe { GetKeyState(i32::from(VK_NUMLOCK.0)) } & 1) != 0;
        let mut bits = modifiers::LOCK_STATE_VALID;
        if caps_on {
            bits |= modifiers::CAPS_LOCK;
        }
        if num_on {
            bits |= modifiers::NUM_LOCK;
        }
        bits
    }

    pub(super) struct HookGuard {
        hook: HHOOK,
    }

    impl HookGuard {
        pub(super) fn install(sender: mpsc::UnboundedSender<Envelope>) -> Option<Self> {
            if let Ok(mut slot) = HOOK_SENDER.lock() {
                *slot = Some(sender);
            }
            // SAFETY: `ll_keyboard_proc` has the exact `HOOKPROC` ABI required by
            // `WH_KEYBOARD_LL`, and the current thread pumps a Win32 message loop via `winit`.
            let hook =
                unsafe { SetWindowsHookExW(WH_KEYBOARD_LL, Some(ll_keyboard_proc), None, 0) }
                    .ok()?;
            Some(Self { hook })
        }
    }

    impl Drop for HookGuard {
        fn drop(&mut self) {
            if let Ok(mut slot) = HOOK_SENDER.lock() {
                *slot = None;
            }
            // SAFETY: `self.hook` was returned by a successful `SetWindowsHookExW`.
            let _ = unsafe { UnhookWindowsHookEx(self.hook) };
        }
    }

    unsafe extern "system" fn ll_keyboard_proc(
        code: i32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        if code == HC_ACTION.cast_signed() && lparam.0 != 0 {
            // SAFETY: when `code == HC_ACTION`, Windows guarantees `lparam` points
            // to a valid `KBDLLHOOKSTRUCT` for the duration of the callback.
            let kb = unsafe { &*(lparam.0 as *const KBDLLHOOKSTRUCT) };
            let focused = FOCUSED.load(Ordering::Relaxed);
            let alt_down = kb.flags.contains(LLKHF_ALTDOWN);
            let decision =
                classify_ll_key(focused, kb.vkCode, kb.scanCode, alt_down, kb.dwExtraInfo);
            #[allow(
                clippy::cast_possible_truncation,
                reason = "Win32 message IDs fit in u32"
            )]
            let msg = wparam.0 as u32;
            let pressed = match msg {
                WM_KEYDOWN | WM_SYSKEYDOWN => Some(true),
                WM_KEYUP | WM_SYSKEYUP => Some(false),
                _ => None,
            };
            match (decision, pressed) {
                (HookDecision::Swallow, _) => return LRESULT(1),
                (HookDecision::ForwardHid(hid_usage), Some(pressed)) => {
                    if let Ok(guard) = HOOK_SENDER.lock()
                        && let Some(sender) = guard.as_ref()
                    {
                        let _ = sender.send(Envelope {
                            payload: Some(Payload::KeyEvent(KeyEvent {
                                hid_usage,
                                keysym: 0,
                                pressed,
                                modifiers: lock_modifiers(),
                            })),
                        });
                    }
                    return LRESULT(1);
                }
                _ => {}
            }
        }
        // SAFETY: forwards unhandled hook notifications down the Win32 hook chain.
        unsafe { CallNextHookEx(None, code, wparam, lparam) }
    }
}

#[cfg(test)]
mod tests {
    use omegadesk_input::INJECTED_MARKER;

    use super::{ALTGR_FAKE_LCNTRL_SCANCODE, HookDecision, classify_ll_key};

    #[test]
    fn hook_ignores_unfocused_or_self_injected_events() {
        assert_eq!(
            classify_ll_key(false, 0x5B, 0, false, 0),
            HookDecision::PassThrough
        );
        assert_eq!(
            classify_ll_key(true, 0x5B, 0, false, INJECTED_MARKER),
            HookDecision::PassThrough
        );
    }

    #[test]
    fn hook_swallows_altgr_synthetic_left_ctrl() {
        assert_eq!(
            classify_ll_key(true, 0xA2, ALTGR_FAKE_LCNTRL_SCANCODE, true, 0),
            HookDecision::Swallow
        );
    }

    #[test]
    fn hook_forwards_win_keys_and_alt_tab_or_esc() {
        assert_eq!(
            classify_ll_key(true, 0x5B, 0x5B, false, 0),
            HookDecision::ForwardHid(0xE3)
        );
        assert_eq!(
            classify_ll_key(true, 0x5C, 0x5C, false, 0),
            HookDecision::ForwardHid(0xE7)
        );
        assert_eq!(
            classify_ll_key(true, 0x09, 0x0F, true, 0),
            HookDecision::ForwardHid(0x2B)
        );
        assert_eq!(
            classify_ll_key(true, 0x09, 0x0F, false, 0),
            HookDecision::PassThrough
        );
        assert_eq!(
            classify_ll_key(true, 0x1B, 0x01, true, 0),
            HookDecision::ForwardHid(0x29)
        );
    }
}
