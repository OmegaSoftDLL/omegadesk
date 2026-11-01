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

/// Multi-touch contact lifecycle phase (`POINTER_FLAG_DOWN | UPDATE | UP | CANCELED`
/// on Windows `InjectSyntheticPointerInput`, `docs/plan.md` §3 line 211).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TouchPhase {
    /// Finger touched the screen (`POINTER_FLAG_DOWN | POINTER_FLAG_INRANGE | POINTER_FLAG_INCONTACT`).
    Down,
    /// Finger moved across the screen (`POINTER_FLAG_UPDATE | POINTER_FLAG_INRANGE | POINTER_FLAG_INCONTACT`).
    Move,
    /// Finger lifted from the screen (`POINTER_FLAG_UP`).
    Up,
    /// Touch contact canceled by the system (`POINTER_FLAG_CANCELED | POINTER_FLAG_UP`).
    Cancel,
}

/// Single multi-touch contact point in normalized `0..=65535` target-display coordinates
/// (`POINTER_TOUCH_INFO`, `docs/plan.md` §3 line 211).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TouchContact {
    /// Unique touch pointer identifier (`0..255`).
    pub pointer_id: u32,
    /// Target monitor index.
    pub display_index: u32,
    /// Contact phase.
    pub phase: TouchPhase,
    /// Normalized horizontal coordinate (`0..=65535`).
    pub x: u32,
    /// Normalized vertical coordinate (`0..=65535`).
    pub y: u32,
    /// Normalized contact pressure (`0..=1024`, default `512`).
    pub pressure: u16,
    /// Contact bounding-box radius in normalized units.
    pub radius: u16,
}

/// Stylus / pen state flags (`PEN_FLAG_BARREL | PEN_FLAG_INVERTED | PEN_FLAG_ERASER`,
/// `docs/plan.md` §3 line 211).
pub mod pen_flags {
    /// Stylus tip is in contact with the digitizer surface (`POINTER_FLAG_INCONTACT`).
    pub const IN_CONTACT: u32 = 1;
    /// Barrel button on the side of the stylus is pressed (`PEN_FLAG_BARREL`).
    pub const BARREL_BUTTON: u32 = 1 << 1;
    /// Stylus is inverted to the eraser end (`PEN_FLAG_INVERTED`).
    pub const INVERTED: u32 = 1 << 2;
    /// Eraser tip is actively erasing (`PEN_FLAG_ERASER`).
    pub const ERASER: u32 = 1 << 3;
}

/// Stylus / pen digitizer input event (`POINTER_PEN_INFO`, `docs/plan.md` §3 line 211).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PenStylusEvent {
    /// Target monitor index.
    pub display_index: u32,
    /// Normalized horizontal coordinate (`0..=65535`).
    pub x: u32,
    /// Normalized vertical coordinate (`0..=65535`).
    pub y: u32,
    /// Bitmask of [`pen_flags`].
    pub flags: u32,
    /// Normalized pen tip pressure (`0..=1024`, matching Windows `POINTER_PEN_INFO::pressure`).
    pub pressure: u16,
    /// Tilt along the X axis in degrees (`-90..=90`, matching `POINTER_PEN_INFO::tiltX`).
    pub tilt_x: i8,
    /// Tilt along the Y axis in degrees (`-90..=90`, matching `POINTER_PEN_INFO::tiltY`).
    pub tilt_y: i8,
    /// Pen barrel twist rotation in degrees (`0..=359`, matching `POINTER_PEN_INFO::rotation`).
    pub rotation: u16,
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

    /// Injects a frame of simultaneous multi-touch contacts (`POINTER_TOUCH_INFO`).
    ///
    /// When the platform injector does not have a synthetic touch digitizer attached,
    /// falls back to translating the primary contact (`contacts[0]`) into a pointer event.
    ///
    /// # Errors
    ///
    /// Returns an error if the operating system rejects the event.
    fn touch(&mut self, contacts: &[TouchContact]) -> Result<(), InputError> {
        let Some(primary) = contacts.first() else {
            return Ok(());
        };
        let buttons = match primary.phase {
            TouchPhase::Down | TouchPhase::Move => buttons::LEFT,
            TouchPhase::Up | TouchPhase::Cancel => 0,
        };
        self.pointer(&PointerEvent {
            display_index: primary.display_index,
            x: primary.x,
            y: primary.y,
            buttons,
            wheel_x: 0,
            wheel_y: 0,
        })
    }

    /// Injects a stylus / pen digitizer event (`POINTER_PEN_INFO`).
    ///
    /// # Errors
    ///
    /// Returns an error if the operating system rejects the event.
    fn pen(&mut self, event: &PenStylusEvent) -> Result<(), InputError> {
        let mut btn = 0;
        if (event.flags & pen_flags::IN_CONTACT) != 0 {
            btn |= buttons::LEFT;
        }
        if (event.flags & pen_flags::BARREL_BUTTON) != 0 {
            btn |= buttons::RIGHT;
        }
        self.pointer(&PointerEvent {
            display_index: event.display_index,
            x: event.x,
            y: event.y,
            buttons: btn,
            wheel_x: 0,
            wheel_y: 0,
        })
    }

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
