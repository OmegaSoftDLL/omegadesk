//! Windows input injection using `SendInput` and `SendSAS`.
//!
//! References: `RustDesk` (`src/server/input_service.rs` for releasing stuck
//! keys and synchronizing `CapsLock`/`NumLock`, `src/platform/windows.rs` for
//! `SendSAS`, and `libs/enigo/src/win/win_impl.rs` for virtual desktop
//! coordinates) and Apollo (`src/platform/windows/input.cpp` for `VK_PAUSE`).

#![allow(unsafe_code, reason = "SendInput and SendSAS are Win32 APIs")]

use std::collections::BTreeSet;

use omegadesk_protocol::v1::{KeyEvent, PointerEvent};
use windows::Win32::Foundation::FreeLibrary;
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
use windows::Win32::UI::Input::KeyboardAndMouse::{
    GetKeyState, INPUT, INPUT_0, INPUT_KEYBOARD, INPUT_MOUSE, KEYBD_EVENT_FLAGS, KEYBDINPUT,
    KEYEVENTF_EXTENDEDKEY, KEYEVENTF_KEYUP, KEYEVENTF_SCANCODE, MOUSE_EVENT_FLAGS,
    MOUSEEVENTF_ABSOLUTE, MOUSEEVENTF_HWHEEL, MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP,
    MOUSEEVENTF_MIDDLEDOWN, MOUSEEVENTF_MIDDLEUP, MOUSEEVENTF_MOVE, MOUSEEVENTF_RIGHTDOWN,
    MOUSEEVENTF_RIGHTUP, MOUSEEVENTF_VIRTUALDESK, MOUSEEVENTF_WHEEL, MOUSEEVENTF_XDOWN,
    MOUSEEVENTF_XUP, MOUSEINPUT, SendInput, VIRTUAL_KEY, VK_CAPITAL, VK_NUMLOCK, VK_PAUSE,
};
use windows::Win32::UI::WindowsAndMessaging::{
    GetSystemMetrics, SM_CXVIRTUALSCREEN, SM_CYVIRTUALSCREEN, SM_XVIRTUALSCREEN, SM_YVIRTUALSCREEN,
};
use windows::core::{PCSTR, w};

use crate::{
    INJECTED_MARKER, InputError, InputInjector, TargetDisplay, buttons, hid_to_scancode, modifiers,
};

/// Win32 `XBUTTON1` and `XBUTTON2` values.
const XBUTTON1: i32 = 1;
const XBUTTON2: i32 = 2;

/// USB HID usage codes for special keys.
const HID_CAPS_LOCK: u32 = 0x39;
const HID_PAUSE: u32 = 0x48;
const HID_DELETE: u32 = 0x4C;
const HID_NUM_LOCK: u32 = 0x53;
const HID_LEFT_CTRL: u32 = 0xE0;
const HID_LEFT_ALT: u32 = 0xE2;
const HID_RIGHT_CTRL: u32 = 0xE4;
const HID_RIGHT_ALT: u32 = 0xE6;

#[derive(Debug, Default)]
pub(crate) struct WindowsInjector {
    pressed_buttons: u32,
    pressed_keys: BTreeSet<u32>,
    target: Option<TargetDisplay>,
}

fn send(inputs: &[INPUT]) -> Result<(), InputError> {
    if inputs.is_empty() {
        return Ok(());
    }
    let size = i32::try_from(size_of::<INPUT>()).map_err(|_| InputError::Rejected)?;
    // SAFETY: `inputs` is a valid slice of fully initialized `INPUT` structs
    // (`windows-rs` passes both the pointer and length) and `size` equals
    // `size_of::<INPUT>()` as required by `SendInput`, which only reads the slice.
    let sent = unsafe { SendInput(inputs, size) };
    if sent as usize == inputs.len() {
        Ok(())
    } else {
        Err(InputError::Rejected)
    }
}

fn mouse(flags: MOUSE_EVENT_FLAGS, dx: i32, dy: i32, data: i32) -> INPUT {
    INPUT {
        r#type: INPUT_MOUSE,
        Anonymous: INPUT_0 {
            mi: MOUSEINPUT {
                dx,
                dy,
                mouseData: data.cast_unsigned(),
                dwFlags: flags,
                time: 0,
                dwExtraInfo: INJECTED_MARKER,
            },
        },
    }
}

fn keyboard(usage: u32, pressed: bool) -> Option<INPUT> {
    let (virtual_key, scan, mut flags) = if usage == HID_PAUSE {
        // Pause generates an `E1 1D 45` sequence; sending `VK_PAUSE` lets Windows synthesize it.
        (VK_PAUSE, 0, KEYBD_EVENT_FLAGS(0))
    } else {
        let scancode = hid_to_scancode(usage)?;
        let mut flags = KEYEVENTF_SCANCODE;
        if scancode.extended {
            flags |= KEYEVENTF_EXTENDEDKEY;
        }
        (VIRTUAL_KEY(0), scancode.code, flags)
    };
    if !pressed {
        flags |= KEYEVENTF_KEYUP;
    }
    Some(INPUT {
        r#type: INPUT_KEYBOARD,
        Anonymous: INPUT_0 {
            ki: KEYBDINPUT {
                wVk: virtual_key,
                wScan: scan,
                dwFlags: flags,
                time: 0,
                dwExtraInfo: INJECTED_MARKER,
            },
        },
    })
}

/// Converts normalized monitor coordinates (`0..=65535` within `target`) into
/// the absolute virtual desktop coordinates (`0..=65535` across all monitors)
/// expected by `SendInput` when `MOUSEEVENTF_VIRTUALDESK` is set.
fn virtual_desk_position(target: TargetDisplay, x: u32, y: u32) -> (i32, i32) {
    // SAFETY: valid `SM_XVIRTUALSCREEN` index, no pointers; returns 0 on failure.
    let left = unsafe { GetSystemMetrics(SM_XVIRTUALSCREEN) };
    // SAFETY: valid `SM_YVIRTUALSCREEN` index, no pointers.
    let top = unsafe { GetSystemMetrics(SM_YVIRTUALSCREEN) };
    // SAFETY: valid `SM_CXVIRTUALSCREEN` index, no pointers.
    let width = unsafe { GetSystemMetrics(SM_CXVIRTUALSCREEN) }.max(1);
    // SAFETY: valid `SM_CYVIRTUALSCREEN` index, no pointers.
    let height = unsafe { GetSystemMetrics(SM_CYVIRTUALSCREEN) }.max(1);
    let axis = |normalized: u32, origin: i32, extent: u32, desk_origin: i32, desk_extent: i32| {
        let pixel =
            i64::from(origin) + i64::from(normalized.min(65_535)) * i64::from(extent) / 65_536;
        let relative = (pixel - i64::from(desk_origin)).clamp(0, i64::from(desk_extent) - 1);
        // Aim at the center of the pixel to avoid rounding into an adjacent pixel.
        let scaled = (relative * 65_535 + 32_767) / i64::from((desk_extent - 1).max(1));
        i32::try_from(scaled.clamp(0, 65_535)).unwrap_or(65_535)
    };
    (
        axis(x, target.x, target.width, left, width),
        axis(y, target.y, target.height, top, height),
    )
}

impl WindowsInjector {
    fn position(&self, x: u32, y: u32) -> (MOUSE_EVENT_FLAGS, i32, i32) {
        match self.target {
            Some(target) => {
                let (dx, dy) = virtual_desk_position(target, x, y);
                (
                    MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK,
                    dx,
                    dy,
                )
            }
            // No target display set: map directly to the primary monitor (0..=65535).
            None => (
                MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE,
                i32::try_from(x.min(65_535)).unwrap_or(65_535),
                i32::try_from(y.min(65_535)).unwrap_or(65_535),
            ),
        }
    }

    fn is_ctrl_alt_del(&self, event: &KeyEvent) -> bool {
        if !event.pressed {
            return false;
        }
        if event.modifiers & modifiers::CTRL_ALT_DEL != 0 {
            return true;
        }
        let ctrl = self.pressed_keys.contains(&HID_LEFT_CTRL)
            || self.pressed_keys.contains(&HID_RIGHT_CTRL)
            || (event.modifiers & modifiers::CTRL != 0);
        let alt = self.pressed_keys.contains(&HID_LEFT_ALT)
            || self.pressed_keys.contains(&HID_RIGHT_ALT)
            || (event.modifiers & modifiers::ALT != 0);
        event.hid_usage == HID_DELETE && ctrl && alt
    }
}

/// Returns whether a toggle lock key (`VK_CAPITAL` or `VK_NUMLOCK`) is currently toggled on.
fn is_lock_key_toggled(vk: VIRTUAL_KEY) -> bool {
    // SAFETY: `GetKeyState` takes a virtual-key code by value and returns a `SHORT`
    // whose low-order bit indicates the toggle state.
    let state = unsafe { GetKeyState(i32::from(vk.0)) };
    (state & 1) != 0
}

/// Appends a press-and-release sequence for `hid_usage` if the client's desired
/// lock state (`want_toggled`) differs from the host's current toggle state
/// (referencing `RustDesk` `src/server/input_service.rs`).
fn sync_single_lock_key(
    inputs: &mut Vec<INPUT>,
    vk: VIRTUAL_KEY,
    hid_usage: u32,
    want_toggled: bool,
) {
    if is_lock_key_toggled(vk) != want_toggled
        && let (Some(down), Some(up)) = (keyboard(hid_usage, true), keyboard(hid_usage, false))
    {
        inputs.push(down);
        inputs.push(up);
    }
}

/// Synchronizes `CapsLock` and `NumLock` toggle states before injecting a key press
/// when [`modifiers::LOCK_STATE_VALID`] is set.
fn sync_lock_keys(inputs: &mut Vec<INPUT>, event: &KeyEvent) {
    if !event.pressed || (event.modifiers & modifiers::LOCK_STATE_VALID == 0) {
        return;
    }
    if event.hid_usage != HID_CAPS_LOCK {
        sync_single_lock_key(
            inputs,
            VK_CAPITAL,
            HID_CAPS_LOCK,
            event.modifiers & modifiers::CAPS_LOCK != 0,
        );
    }
    if event.hid_usage != HID_NUM_LOCK {
        sync_single_lock_key(
            inputs,
            VK_NUMLOCK,
            HID_NUM_LOCK,
            event.modifiers & modifiers::NUM_LOCK != 0,
        );
    }
}

/// Invokes `SendSAS(FALSE)` from `sas.dll` to synthesize `Ctrl+Alt+Del` on
/// Windows (referencing `RustDesk` `src/platform/windows.rs` and `FreeRDP`).
fn trigger_sas() {
    type SendSasFn = unsafe extern "system" fn(i32);

    // SAFETY: `w!("sas.dll")` is a static null-terminated UTF-16 string.
    let Ok(module) = (unsafe { LoadLibraryW(w!("sas.dll")) }) else {
        return;
    };
    // SAFETY: `module` is a valid loaded library handle and `"SendSAS\0"` is null-terminated.
    let proc = unsafe { GetProcAddress(module, PCSTR(c"SendSAS".as_ptr().cast())) };
    if let Some(proc) = proc {
        // SAFETY: `SendSAS` in `sas.dll` has signature `VOID WINAPI SendSAS(BOOL AsUser)`.
        let send_sas: SendSasFn = unsafe { std::mem::transmute(proc) };
        // SAFETY: `0` (`FALSE`) requests SAS generation as a service / system application.
        unsafe { send_sas(0) };
    }
    // SAFETY: `module` was returned by `LoadLibraryW` above and is not used afterwards.
    let _ = unsafe { FreeLibrary(module) };
}

impl InputInjector for WindowsInjector {
    fn set_target(&mut self, target: TargetDisplay) {
        self.target = Some(target);
    }

    fn key(&mut self, event: &KeyEvent) -> Result<(), InputError> {
        if self.is_ctrl_alt_del(event) {
            trigger_sas();
        }
        let mut inputs = Vec::with_capacity(5);
        sync_lock_keys(&mut inputs, event);
        if let Some(input) = keyboard(event.hid_usage, event.pressed) {
            inputs.push(input);
        }
        send(&inputs)?;
        if event.pressed {
            self.pressed_keys.insert(event.hid_usage);
        } else {
            self.pressed_keys.remove(&event.hid_usage);
        }
        Ok(())
    }

    fn pointer(&mut self, event: &PointerEvent) -> Result<(), InputError> {
        let (flags, dx, dy) = self.position(event.x, event.y);
        let mut inputs = vec![mouse(flags, dx, dy, 0)];

        let changed = event.buttons ^ self.pressed_buttons;
        let transitions = [
            (buttons::LEFT, MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP, 0),
            (
                buttons::RIGHT,
                MOUSEEVENTF_RIGHTDOWN,
                MOUSEEVENTF_RIGHTUP,
                0,
            ),
            (
                buttons::MIDDLE,
                MOUSEEVENTF_MIDDLEDOWN,
                MOUSEEVENTF_MIDDLEUP,
                0,
            ),
            (buttons::BACK, MOUSEEVENTF_XDOWN, MOUSEEVENTF_XUP, XBUTTON1),
            (
                buttons::FORWARD,
                MOUSEEVENTF_XDOWN,
                MOUSEEVENTF_XUP,
                XBUTTON2,
            ),
        ];
        for (bit, down, up, data) in transitions {
            if changed & bit != 0 {
                let flags = if event.buttons & bit == 0 { up } else { down };
                inputs.push(mouse(flags, 0, 0, data));
            }
        }

        if event.wheel_y != 0 {
            inputs.push(mouse(MOUSEEVENTF_WHEEL, 0, 0, event.wheel_y));
        }
        if event.wheel_x != 0 {
            inputs.push(mouse(MOUSEEVENTF_HWHEEL, 0, 0, event.wheel_x));
        }
        send(&inputs)?;
        // Update state only after `SendInput` succeeds so a rejected event can be retried.
        self.pressed_buttons = event.buttons;
        Ok(())
    }

    fn release_all(&mut self) {
        let mut inputs: Vec<INPUT> = self
            .pressed_keys
            .iter()
            .filter_map(|&usage| keyboard(usage, false))
            .collect();
        let releases = [
            (buttons::LEFT, MOUSEEVENTF_LEFTUP, 0),
            (buttons::RIGHT, MOUSEEVENTF_RIGHTUP, 0),
            (buttons::MIDDLE, MOUSEEVENTF_MIDDLEUP, 0),
            (buttons::BACK, MOUSEEVENTF_XUP, XBUTTON1),
            (buttons::FORWARD, MOUSEEVENTF_XUP, XBUTTON2),
        ];
        for (bit, up, data) in releases {
            if self.pressed_buttons & bit != 0 {
                inputs.push(mouse(up, 0, 0, data));
            }
        }
        let _ = send(&inputs);
        self.pressed_keys.clear();
        self.pressed_buttons = 0;
    }
}

impl Drop for WindowsInjector {
    fn drop(&mut self) {
        // Release any held keys or mouse buttons if the session drops while Ctrl/Shift/etc. are pressed.
        self.release_all();
    }
}

#[cfg(test)]
mod tests {
    use omegadesk_protocol::v1::KeyEvent;

    use super::{HID_DELETE, HID_LEFT_ALT, HID_LEFT_CTRL, WindowsInjector, keyboard};
    use crate::modifiers;

    #[test]
    fn pause_uses_virtual_key() {
        let input = keyboard(0x48, true).unwrap();
        // SAFETY: `keyboard` builds an `INPUT_KEYBOARD` by initializing the `ki` union variant.
        let key = unsafe { input.Anonymous.ki };
        assert_eq!(key.wVk.0, 0x13);
        assert_eq!(key.wScan, 0);
    }

    #[test]
    fn letters_use_scancode() {
        let input = keyboard(0x04, false).unwrap();
        // SAFETY: `keyboard` builds an `INPUT_KEYBOARD` by initializing the `ki` union variant.
        let key = unsafe { input.Anonymous.ki };
        assert_eq!(key.wScan, 0x1E);
        assert_ne!(key.dwFlags.0 & 0x2, 0, "KEYEVENTF_KEYUP");
    }

    #[test]
    fn detects_ctrl_alt_del_by_flag_or_chord() {
        let mut injector = WindowsInjector::default();
        assert!(injector.is_ctrl_alt_del(&KeyEvent {
            hid_usage: HID_DELETE,
            keysym: 0,
            pressed: true,
            modifiers: modifiers::CTRL_ALT_DEL,
        }));

        injector.pressed_keys.insert(HID_LEFT_CTRL);
        injector.pressed_keys.insert(HID_LEFT_ALT);
        assert!(injector.is_ctrl_alt_del(&KeyEvent {
            hid_usage: HID_DELETE,
            keysym: 0,
            pressed: true,
            modifiers: 0,
        }));
    }
}
