//! Remote monitor catalog and the display-switch key chord.
//!
//! The agent publishes a `DisplayList` after the handshake and after every
//! switch; the client keeps it in [`DisplayState`] and lets the user switch with
//! `Ctrl+Alt+Shift` plus `1`..`9` (n-th display), `N` (next) or `P`
//! (previous). The chord key itself is never forwarded to the remote machine;
//! the held modifiers are, which is harmless (RustDesk's toolbar offers the same
//! switch through `SwitchDisplay`; FreeRDP uses `Ctrl+Alt+Enter` style chords for
//! client-local actions). Letters rather than arrows: GPU vendor hotkeys
//! (`Ctrl+Alt+Arrow` on Intel) intercept the arrow combinations before any
//! window receives them, which a loopback test on an Intel machine confirmed.

use omegadesk_input::modifiers;
use omegadesk_protocol::v1::{
    DisplayDescriptor, DisplayList, Envelope, SelectDisplay, envelope::Payload,
};

const HID_DIGIT_1: u32 = 0x1E;
const HID_DIGIT_9: u32 = 0x26;
/// `N` (next) on the US layout; physical position, so it is the same key everywhere.
const HID_KEY_N: u32 = 0x11;
/// `P` (previous).
const HID_KEY_P: u32 = 0x13;

/// Modifiers that must all be held for the chord.
const CHORD_MODIFIERS: u32 = modifiers::CTRL | modifiers::ALT | modifiers::SHIFT;

/// A client-local display switch requested from the keyboard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DisplayCommand {
    /// The n-th display of the catalog (0-based position, not the agent index).
    Position(usize),
    /// The display after the active one, wrapping around.
    Next,
    /// The display before the active one, wrapping around.
    Previous,
}

/// Recognizes the display-switch chord from a pressed key and the currently
/// held modifier bits. `Shift` is required so plain `Ctrl+Alt+<digit>` (used by
/// many applications) keeps reaching the remote machine.
pub(crate) fn display_chord(hid_usage: u32, held_modifiers: u32) -> Option<DisplayCommand> {
    if held_modifiers & CHORD_MODIFIERS != CHORD_MODIFIERS {
        return None;
    }
    match hid_usage {
        HID_DIGIT_1..=HID_DIGIT_9 => Some(DisplayCommand::Position(
            usize::try_from(hid_usage - HID_DIGIT_1).unwrap_or(0),
        )),
        HID_KEY_N => Some(DisplayCommand::Next),
        HID_KEY_P => Some(DisplayCommand::Previous),
        _ => None,
    }
}

/// The agent's monitor catalog as last announced.
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct DisplayState {
    displays: Vec<DisplayDescriptor>,
    active: u32,
}

impl DisplayState {
    /// Replaces the catalog with the agent's announcement.
    pub(crate) fn update(&mut self, list: DisplayList) {
        self.displays = list.displays;
        self.active = list.active_display_index;
    }

    /// Agent index of the display currently streamed (`0` before the first announcement).
    pub(crate) const fn active_index(&self) -> u32 {
        self.active
    }

    /// Agent index to request for `command`, or `None` when the catalog is
    /// unknown, the position does not exist, or the result is the active display.
    pub(crate) fn target(&self, command: DisplayCommand) -> Option<u32> {
        if self.displays.is_empty() {
            return None;
        }
        let current = self
            .displays
            .iter()
            .position(|d| d.index == self.active)
            .unwrap_or(0);
        let count = self.displays.len();
        let position = match command {
            DisplayCommand::Position(position) => position,
            DisplayCommand::Next => (current + 1) % count,
            DisplayCommand::Previous => (current + count - 1) % count,
        };
        let target = self.displays.get(position)?.index;
        (target != self.active).then_some(target)
    }

    /// Short title-bar summary (`display 2/3: \\.\DISPLAY2`), `None` with a
    /// single display.
    pub(crate) fn summary(&self) -> Option<String> {
        if self.displays.len() < 2 {
            return None;
        }
        let position = self
            .displays
            .iter()
            .position(|d| d.index == self.active)
            .map_or(0, |p| p + 1);
        let name = self
            .displays
            .iter()
            .find(|d| d.index == self.active)
            .map(|d| d.name.as_str())
            .unwrap_or_default();
        Some(format!(
            "display {position}/{}{}{name}",
            self.displays.len(),
            if name.is_empty() { "" } else { ": " }
        ))
    }
}

/// `SelectDisplay` request for the agent.
pub(crate) fn select_display(display_index: u32) -> Envelope {
    Envelope {
        payload: Some(Payload::SelectDisplay(SelectDisplay { display_index })),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn descriptor(index: u32, name: &str) -> DisplayDescriptor {
        DisplayDescriptor {
            index,
            name: name.to_owned(),
            width: 1920,
            height: 1080,
            origin_x: 0,
            origin_y: 0,
            scale_percent: 100,
            primary: index == 0,
        }
    }

    fn three_displays(active: u32) -> DisplayState {
        let mut state = DisplayState::default();
        state.update(DisplayList {
            displays: vec![
                descriptor(0, "\\\\.\\DISPLAY1"),
                descriptor(1, "\\\\.\\DISPLAY2"),
                descriptor(3, "\\\\.\\DISPLAY4"),
            ],
            active_display_index: active,
        });
        state
    }

    #[test]
    fn chord_needs_ctrl_alt_shift_and_maps_digits_and_letters() {
        let all = modifiers::CTRL | modifiers::ALT | modifiers::SHIFT;
        assert_eq!(
            display_chord(HID_DIGIT_1, all),
            Some(DisplayCommand::Position(0))
        );
        assert_eq!(
            display_chord(HID_DIGIT_9, all),
            Some(DisplayCommand::Position(8))
        );
        assert_eq!(display_chord(HID_KEY_N, all), Some(DisplayCommand::Next));
        assert_eq!(
            display_chord(HID_KEY_P, all),
            Some(DisplayCommand::Previous)
        );
        assert_eq!(display_chord(0x04, all), None, "letters are not a chord");
        assert_eq!(
            display_chord(HID_DIGIT_1, modifiers::CTRL | modifiers::ALT),
            None,
            "Ctrl+Alt+1 belongs to the remote application"
        );
        assert_eq!(
            display_chord(HID_KEY_N, all | modifiers::META),
            Some(DisplayCommand::Next),
            "extra modifiers do not break the chord"
        );
    }

    #[test]
    fn targets_follow_catalog_positions_and_wrap() {
        let state = three_displays(1);
        assert_eq!(state.active_index(), 1);
        assert_eq!(state.target(DisplayCommand::Next), Some(3));
        assert_eq!(state.target(DisplayCommand::Previous), Some(0));
        assert_eq!(state.target(DisplayCommand::Position(2)), Some(3));
        assert_eq!(
            state.target(DisplayCommand::Position(1)),
            None,
            "already active"
        );
        assert_eq!(
            state.target(DisplayCommand::Position(7)),
            None,
            "no such display"
        );

        let last = three_displays(3);
        assert_eq!(last.target(DisplayCommand::Next), Some(0), "wraps around");
        let first = three_displays(0);
        assert_eq!(first.target(DisplayCommand::Previous), Some(3));

        assert_eq!(DisplayState::default().target(DisplayCommand::Next), None);
    }

    #[test]
    fn summary_only_with_several_displays() {
        assert_eq!(DisplayState::default().summary(), None);
        assert_eq!(
            three_displays(3).summary().as_deref(),
            Some("display 3/3: \\\\.\\DISPLAY4")
        );
        let Some(Payload::SelectDisplay(request)) = select_display(3).payload else {
            panic!("not a SelectDisplay");
        };
        assert_eq!(request.display_index, 3);
    }
}
