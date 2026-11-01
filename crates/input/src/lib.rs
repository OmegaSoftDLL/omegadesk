//! Keyboard and mouse injection for OmegaDesk.
//!
//! Keys arrive as layout-independent USB HID usage codes and are translated
//! into physical keyboard scancodes on the remote machine. The layout configured
//! on the remote machine (ABNT2, US, …) determines the produced character,
//! matching a physical keyboard attached to that machine.

mod hid;
#[cfg(windows)]
mod windows_injector;

pub use hid::{Scancode, hid_to_scancode};
use omegadesk_protocol::v1::{KeyEvent, PointerEvent};

/// Pointer button bitflags used in `PointerEvent::buttons`.
pub mod buttons {
    /// Primary (left) mouse button.
    pub const LEFT: u32 = 1;
    /// Secondary (right) mouse button.
    pub const RIGHT: u32 = 1 << 1;
    /// Middle (wheel) mouse button.
    pub const MIDDLE: u32 = 1 << 2;
    /// Side "back" mouse button (`XBUTTON1`).
    pub const BACK: u32 = 1 << 3;
    /// Side "forward" mouse button (`XBUTTON2`).
    pub const FORWARD: u32 = 1 << 4;
}

/// Modifier, lock-key, and special action bitflags used in `KeyEvent::modifiers`.
pub mod modifiers {
    /// Either Shift key is held.
    pub const SHIFT: u32 = 1;
    /// Either Control key is held.
    pub const CTRL: u32 = 1 << 1;
    /// Either Alt key is held.
    pub const ALT: u32 = 1 << 2;
    /// Either Super / Windows / Command key is held.
    pub const META: u32 = 1 << 3;
    /// Caps Lock is active on the client.
    pub const CAPS_LOCK: u32 = 1 << 4;
    /// Num Lock is active on the client.
    pub const NUM_LOCK: u32 = 1 << 5;
    /// Requests the agent to trigger a Secure Attention Sequence (`Ctrl+Alt+Del` / `SendSAS`).
    pub const CTRL_ALT_DEL: u32 = 1 << 6;
    /// Indicates that [`CAPS_LOCK`] and [`NUM_LOCK`] carry the client's current lock states.
    pub const LOCK_STATE_VALID: u32 = 1 << 7;
}

/// Marker stored in `dwExtraInfo` on events injected by OmegaDesk so low-level
/// input hooks can distinguish them from local hardware input (matching
/// `RustDesk`'s `enigo` marker).
pub const INJECTED_MARKER: usize = 0x4F4D_4547; // "OMEG"

/// One discrete scroll wheel notch, matching Windows `WHEEL_DELTA`.
pub const WHEEL_STEP: i32 = 120;

/// Target monitor receiving pointer events, in virtual desktop pixel coordinates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TargetDisplay {
    /// Top-left x coordinate.
    pub x: i32,
    /// Top-left y coordinate.
    pub y: i32,
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels.
    pub height: u32,
}

/// Input injection errors.
#[derive(Debug, thiserror::Error)]
pub enum InputError {
    /// Input injection is not implemented for this operating system yet.
    #[error("input injection is not yet supported on this operating system")]
    Unsupported,
    /// `SendInput` rejected the event (for instance because the input desktop
    /// switched to UAC or the lock screen). Note that UIPI blocks against
    /// elevated windows are dropped silently by Windows without returning an error.
    #[error("the operating system rejected the input event")]
    Rejected,
}

/// Injects remote keyboard and pointer events into the local desktop session.
pub trait InputInjector: Send {
    /// Sets the target monitor for absolute pointer coordinates (matching the
    /// captured monitor). When unset, pointer coordinates map to the primary monitor.
    fn set_target(&mut self, target: TargetDisplay);

    /// Presses or releases a key.
    ///
    /// # Errors
    ///
    /// Returns an error if the operating system rejects the event.
    fn key(&mut self, event: &KeyEvent) -> Result<(), InputError>;

    /// Moves the pointer, presses/releases mouse buttons, and scrolls the wheel.
    ///
    /// # Errors
    ///
    /// Returns an error if the operating system rejects the event.
    fn pointer(&mut self, event: &PointerEvent) -> Result<(), InputError>;

    /// Releases all keys and mouse buttons currently held down by this injector.
    fn release_all(&mut self);
}

/// Opens the input injector for the current operating system.
///
/// # Errors
///
/// Returns [`InputError::Unsupported`] on non-Windows platforms for now.
pub fn open() -> Result<Box<dyn InputInjector>, InputError> {
    #[cfg(windows)]
    {
        Ok(Box::new(windows_injector::WindowsInjector::default()))
    }
    #[cfg(not(windows))]
    {
        Err(InputError::Unsupported)
    }
}
