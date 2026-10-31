//! Injeção com `SendInput` no Windows.
//!
//! Referências: `RustDesk` (`src/server/input_service.rs`, teclas presas e
//! `libs/enigo/src/win/win_impl.rs`, área de trabalho virtual) e Apollo
//! (`src/platform/windows/input.cpp`, Pause via tecla virtual).

#![allow(unsafe_code, reason = "SendInput é uma API Win32")]

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

/// `XBUTTON1` e `XBUTTON2` do Win32.
const XBUTTON1: i32 = 1;
const XBUTTON2: i32 = 2;

/// Código HID da tecla Pause/Break, que não tem scancode simples.
const HID_PAUSE: u32 = 0x48;

/// Marca os eventos injetados pelo OmegaDesk, para distinguir da entrada local
/// (o `enigo` do `RustDesk` faz o mesmo).
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
    // SAFETY: `inputs` é um slice vivo de INPUTs totalmente inicializados (o
    // tamanho vai junto, pelo windows-rs) e `size` é o `size_of::<INPUT>()`
    // que a API exige; o SendInput só lê o slice.
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
        // Pause gera uma sequência E1 1D 45; pela tecla virtual o Windows a monta.
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

/// Converte a posição normalizada (0..=65535 no monitor alvo) para as
/// coordenadas absolutas da área de trabalho virtual que o `SendInput` usa com
/// `MOUSEEVENTF_VIRTUALDESK` (0..=65535 sobre todos os monitores).
fn virtual_desk_position(target: TargetDisplay, x: u32, y: u32) -> (i32, i32) {
    // SAFETY: índice SM_XVIRTUALSCREEN válido, sem ponteiros; erro devolve 0.
    let left = unsafe { GetSystemMetrics(SM_XVIRTUALSCREEN) };
    // SAFETY: índice SM_YVIRTUALSCREEN válido, sem ponteiros.
    let top = unsafe { GetSystemMetrics(SM_YVIRTUALSCREEN) };
    // SAFETY: índice SM_CXVIRTUALSCREEN válido, sem ponteiros.
    let width = unsafe { GetSystemMetrics(SM_CXVIRTUALSCREEN) }.max(1);
    // SAFETY: índice SM_CYVIRTUALSCREEN válido, sem ponteiros.
    let height = unsafe { GetSystemMetrics(SM_CYVIRTUALSCREEN) }.max(1);
    let axis = |normalized: u32, origin: i32, extent: u32, desk_origin: i32, desk_extent: i32| {
        let pixel =
            i64::from(origin) + i64::from(normalized.min(65_535)) * i64::from(extent) / 65_536;
        let relative = (pixel - i64::from(desk_origin)).clamp(0, i64::from(desk_extent) - 1);
        // Centro do pixel, para não cair no vizinho por arredondamento.
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
            // Sem alvo definido: monitor principal, 0..=65535.
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
        // Só depois do envio: se falhar, a próxima tentativa refaz a transição.
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
        // Sessão caiu com Ctrl, Shift ou botão apertado: solta tudo na máquina
        // remota para nada ficar preso.
        self.release_all();
    }
}

#[cfg(test)]
mod tests {
    use super::keyboard;

    #[test]
    fn pause_uses_virtual_key() {
        let input = keyboard(0x48, true).unwrap();
        // SAFETY: `keyboard` monta um INPUT_KEYBOARD escrevendo o campo `ki`
        // da união, então é ele que está inicializado.
        let key = unsafe { input.Anonymous.ki };
        assert_eq!(key.wVk.0, 0x13);
        assert_eq!(key.wScan, 0);
    }

    #[test]
    fn letters_use_scancode() {
        let input = keyboard(0x04, false).unwrap();
        // SAFETY: `keyboard` monta um INPUT_KEYBOARD escrevendo o campo `ki`
        // da união, então é ele que está inicializado.
        let key = unsafe { input.Anonymous.ki };
        assert_eq!(key.wScan, 0x1E);
        assert_ne!(key.dwFlags.0 & 0x2, 0, "KEYEVENTF_KEYUP");
    }
}
