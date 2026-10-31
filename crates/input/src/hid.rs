//! USB HID keyboard usage page (`0x07`) to PC/AT Set 1 scancode translation
//! table used by Windows `SendInput`.

/// PC/AT Set 1 scancode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Scancode {
    /// Scancode byte without the `0xE0` prefix.
    pub code: u16,
    /// Extended key (`0xE0` prefix): arrow keys, Insert, right Ctrl/Alt…
    pub extended: bool,
}

const fn plain(code: u16) -> Scancode {
    Scancode {
        code,
        extended: false,
    }
}

const fn extended(code: u16) -> Scancode {
    Scancode {
        code,
        extended: true,
    }
}

/// Translates a USB HID keyboard usage code into a Set 1 scancode. Returns
/// `None` for keys without a single Set 1 scancode (such as Pause, which uses
/// a multi-byte sequence).
#[must_use]
pub const fn hid_to_scancode(usage: u32) -> Option<Scancode> {
    let scancode = match usage {
        // Letters A–Z.
        0x04 => plain(0x1E),
        0x05 => plain(0x30),
        0x06 => plain(0x2E),
        0x07 => plain(0x20),
        0x08 => plain(0x12),
        0x09 => plain(0x21),
        0x0A => plain(0x22),
        0x0B => plain(0x23),
        0x0C => plain(0x17),
        0x0D => plain(0x24),
        0x0E => plain(0x25),
        0x0F => plain(0x26),
        0x10 => plain(0x32),
        0x11 => plain(0x31),
        0x12 => plain(0x18),
        0x13 => plain(0x19),
        0x14 => plain(0x10),
        0x15 => plain(0x13),
        0x16 => plain(0x1F),
        0x17 => plain(0x14),
        0x18 => plain(0x16),
        0x19 => plain(0x2F),
        0x1A => plain(0x11),
        0x1B => plain(0x2D),
        0x1C => plain(0x15),
        0x1D => plain(0x2C),
        // Digits 1–9 and 0 (0x1E..=0x27 -> 0x02..=0x0B).
        #[allow(clippy::cast_possible_truncation, reason = "range bounded by 0x27")]
        0x1E..=0x27 => plain((usage - 0x1E + 0x02) as u16),
        0x28 => plain(0x1C),        // Enter
        0x29 => plain(0x01),        // Escape
        0x2A => plain(0x0E),        // Backspace
        0x2B => plain(0x0F),        // Tab
        0x2C => plain(0x39),        // Space
        0x2D => plain(0x0C),        // - _
        0x2E => plain(0x0D),        // = +
        0x2F => plain(0x1A),        // [ {   (on ABNT2: ´ `)
        0x30 => plain(0x1B),        // ] }   (on ABNT2: [ {)
        0x31 | 0x32 => plain(0x2B), // \ | and ISO # ~ (on ABNT2: ] })
        0x33 => plain(0x27),        // ; :   (on ABNT2: ç)
        0x34 => plain(0x28),        // ' "   (on ABNT2: ~ ^)
        0x35 => plain(0x29),        // ` ~   (on ABNT2: ' ")
        0x36 => plain(0x33),        // , <
        0x37 => plain(0x34),        // . >
        0x38 => plain(0x35),        // / ?   (on ABNT2: ; :)
        0x39 => plain(0x3A),        // Caps Lock
        // F1–F10 (0x3A..=0x43 -> 0x3B..=0x44), F11, F12.
        #[allow(clippy::cast_possible_truncation, reason = "range bounded by 0x43")]
        0x3A..=0x43 => plain((usage - 0x3A + 0x3B) as u16),
        0x44 => plain(0x57),
        0x45 => plain(0x58),
        0x46 => extended(0x37), // Print Screen
        0x47 => plain(0x46),    // Scroll Lock
        0x49 => extended(0x52), // Insert
        0x4A => extended(0x47), // Home
        0x4B => extended(0x49), // Page Up
        0x4C => extended(0x53), // Delete
        0x4D => extended(0x4F), // End
        0x4E => extended(0x51), // Page Down
        0x4F => extended(0x4D), // Right Arrow
        0x50 => extended(0x4B), // Left Arrow
        0x51 => extended(0x50), // Down Arrow
        0x52 => extended(0x48), // Up Arrow
        0x53 => plain(0x45),    // Num Lock
        0x54 => extended(0x35), // Numpad /
        0x55 => plain(0x37),    // Numpad *
        0x56 => plain(0x4A),    // Numpad -
        0x57 => plain(0x4E),    // Numpad +
        0x58 => extended(0x1C), // Numpad Enter
        0x59 => plain(0x4F),    // Numpad 1
        0x5A => plain(0x50),    // Numpad 2
        0x5B => plain(0x51),    // Numpad 3
        0x5C => plain(0x4B),    // Numpad 4
        0x5D => plain(0x4C),    // Numpad 5
        0x5E => plain(0x4D),    // Numpad 6
        0x5F => plain(0x47),    // Numpad 7
        0x60 => plain(0x48),    // Numpad 8
        0x61 => plain(0x49),    // Numpad 9
        0x62 => plain(0x52),    // Numpad 0
        0x63 => plain(0x53),    // Numpad . (or , on ABNT2)
        0x64 => plain(0x56),    // ISO \ | (ABNT2 key next to Left Shift)
        0x65 => extended(0x5D), // Context Menu
        0x85 => plain(0x7E),    // ABNT2 Numpad .
        0x87 => plain(0x73),    // ABNT2 / ? (key next to Right Shift)
        0x88 => plain(0x70),    // Kana
        0x89 => plain(0x7D),    // Yen
        0xE0 => plain(0x1D),    // Left Ctrl
        0xE1 => plain(0x2A),    // Left Shift
        0xE2 => plain(0x38),    // Left Alt
        0xE3 => extended(0x5B), // Left Super / Windows
        0xE4 => extended(0x1D), // Right Ctrl
        0xE5 => plain(0x36),    // Right Shift
        0xE6 => extended(0x38), // Right Alt (AltGr)
        0xE7 => extended(0x5C), // Right Super / Windows
        _ => return None,
    };
    Some(scancode)
}

#[cfg(test)]
mod tests {
    use super::{Scancode, hid_to_scancode};

    #[test]
    fn letters_digits_and_function_keys() {
        assert_eq!(hid_to_scancode(0x04).map(|s| s.code), Some(0x1E)); // A
        assert_eq!(hid_to_scancode(0x1D).map(|s| s.code), Some(0x2C)); // Z
        assert_eq!(hid_to_scancode(0x1E).map(|s| s.code), Some(0x02)); // 1
        assert_eq!(hid_to_scancode(0x27).map(|s| s.code), Some(0x0B)); // 0
        assert_eq!(hid_to_scancode(0x3A).map(|s| s.code), Some(0x3B)); // F1
        assert_eq!(hid_to_scancode(0x43).map(|s| s.code), Some(0x44)); // F10
        assert_eq!(hid_to_scancode(0x45).map(|s| s.code), Some(0x58)); // F12
    }

    #[test]
    fn extended_keys() {
        assert_eq!(
            hid_to_scancode(0x52),
            Some(Scancode {
                code: 0x48,
                extended: true
            })
        );
        assert_eq!(
            hid_to_scancode(0xE6),
            Some(Scancode {
                code: 0x38,
                extended: true
            })
        );
    }

    #[test]
    fn abnt2_keys() {
        assert_eq!(hid_to_scancode(0x87).map(|s| s.code), Some(0x73));
        assert_eq!(hid_to_scancode(0x85).map(|s| s.code), Some(0x7E));
        assert_eq!(hid_to_scancode(0x64).map(|s| s.code), Some(0x56));
    }

    #[test]
    fn unknown_usage() {
        assert_eq!(hid_to_scancode(0x48), None); // Pause
        assert_eq!(hid_to_scancode(0xFFFF), None);
    }
}
