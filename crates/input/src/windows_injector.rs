//! Windows input injection using `SendInput`.
//!
//! References: `RustDesk` (`src/server/input_service.rs` for releasing stuck
//! keys and `libs/enigo/src/win/win_impl.rs` for virtual desktop coordinates)
//! and Apollo (`src/platform/windows/input.cpp` for `VK_PAUSE`).

#![allow(unsafe_code, reason = "SendInput is a Win32 API")]

use std::collections::BTreeSet;

use omegadesk_protocol::v1::{KeyEvent, PointerEvent};
use windows::Win32::UI::Input::KeyboardAndMouse::{
    INPUT, INPUT_0, INPUT_KEYBOARD, INPUT_MOUSE, KEYBD_EVENT_FLAGS, KEYBDINPUT,
    KEYEVENTF_EXTENDEDKEY, KEYEVENTF_KEYUP, KEYEVENTF_SCANCODE, MOUSE_EVENT_FLAGS,
    MOUSEEVENTF_ABSOLUTE, MOUSEEVENTF_HWHEEL, MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP,
    MOUSEEVENTF_MIDDLEDOWN, MOUSEEVENTF_MIDDLEUP, MOUSEEVENTF_MOVE, MOUSEEVENTF_RIGHTDOWN,
    MOUSEEVENTF_RIGHTUP, MOUSEEVENTF_VIRTUALDESK, MOUSEEVENTF_WHEEL, MOUSEEVENTF_XDOWN,
    MOUSEEVENTF_XUP, MOUSEINPUT, SendInput, VIRTUAL_KEY, VK_PAUSE,
};
use windows::Win32::UI::WindowsAndMessaging::{
    GetSystemMetrics, SM_CXVIRTUALSCREEN, SM_CYVIRTUALSCREEN, SM_XVIRTUALSCREEN, SM_YVIRTUALSCREEN,
};

use crate::{InputError, InputInjector, TargetDisplay, buttons, hid_to_scancode};

/// Win32 `XBUTTON1` and `XBUTTON2` values.
const XBUTTON1: i32 = 1;
const XBUTTON2: i32 = 2;

/// USB HID usage code for Pause/Break, which has no single Set 1 scancode.
const HID_PAUSE: u32 = 0x48;

/// Marks events injected by OmegaDesk so hooks can distinguish them from local
/// hardware input (matching RustDesk's `enigo` marker).
const INJECTED_MARKER: usize = 0x4F4D_4547; // "OMEG"

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
}

impl InputInjector for WindowsInjector {
    fn set_target(&mut self, target: TargetDisplay) {
        self.target = Some(target);
    }

    fn key(&mut self, event: &KeyEvent) -> Result<(), InputError> {
        let Some(input) = keyboard(event.hid_usage, event.pressed) else {
            return Ok(());
        };
        send(&[input])?;
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
    use super::keyboard;

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
}
