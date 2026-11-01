//! Nine-digit QuickSupport identifier: the number an end user reads to the
//! technician over the phone (`123 456 789`), in the TeamViewer / AnyDesk /
//! RustDesk tradition.
//!
//! Following RustDesk's `RegisterPk` model (`rustdesk-server/src/rendezvous_server.rs`),
//! the node *proposes* an identifier derived from its [`DeviceId`] and the
//! coordinator keeps the registry: the proposal is honored when the number is
//! free or already belongs to that device, and a random free number is assigned
//! otherwise. The identifier is purely a human-friendly alias; authorization is
//! always decided on the cryptographic [`DeviceId`].

use std::fmt;
use std::str::FromStr;

use crate::DeviceId;

/// Exclusive upper bound of the identifier space (nine decimal digits).
pub const QUICKSUPPORT_ID_SPACE: u32 = 1_000_000_000;

/// Parse error for [`QuickSupportId`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("a QuickSupport ID is nine digits, optionally grouped with spaces or dashes")]
pub struct InvalidQuickSupportId;

/// A nine-digit QuickSupport identifier (`000 000 000`..`999 999 999`).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct QuickSupportId(u32);

impl QuickSupportId {
    /// Builds an identifier from its numeric value; `None` when `value` has
    /// more than nine digits.
    #[must_use]
    pub const fn from_u32(value: u32) -> Option<Self> {
        if value < QUICKSUPPORT_ID_SPACE {
            Some(Self(value))
        } else {
            None
        }
    }

    /// The identifier a device proposes to the coordinator: the first eight
    /// bytes of its [`DeviceId`] reduced to nine digits. Stable across runs,
    /// so the same machine asks for the same number every time.
    #[must_use]
    pub fn proposed_for(device: DeviceId) -> Self {
        let raw = device.as_bytes();
        let mut prefix = [0u8; 8];
        prefix.copy_from_slice(&raw[..8]);
        Self(
            u32::try_from(u64::from_be_bytes(prefix) % u64::from(QUICKSUPPORT_ID_SPACE))
                .unwrap_or(0),
        )
    }

    /// Numeric value.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self.0
    }

    /// Nine digits without separators (`"123456789"`), the wire form.
    #[must_use]
    pub fn digits(self) -> String {
        format!("{:09}", self.0)
    }

    /// Whether `text` looks like a QuickSupport ID rather than a host name or
    /// address: nine digits once spaces and dashes are removed.
    #[must_use]
    pub fn looks_like(text: &str) -> bool {
        text.parse::<Self>().is_ok()
    }
}

impl FromStr for QuickSupportId {
    type Err = InvalidQuickSupportId;

    /// Accepts `123456789`, `123 456 789` and `123-456-789` (any mix of the
    /// separators, surrounding whitespace ignored).
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let mut value = 0u32;
        let mut digits = 0usize;
        for ch in text.trim().chars() {
            match ch {
                '0'..='9' => {
                    digits += 1;
                    if digits > 9 {
                        return Err(InvalidQuickSupportId);
                    }
                    value = value * 10 + ch.to_digit(10).ok_or(InvalidQuickSupportId)?;
                }
                ' ' | '-' => {}
                _ => return Err(InvalidQuickSupportId),
            }
        }
        if digits != 9 {
            return Err(InvalidQuickSupportId);
        }
        Ok(Self(value))
    }
}

impl fmt::Display for QuickSupportId {
    /// Three groups of three digits separated by spaces (`123 456 789`).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let digits = self.digits();
        write!(f, "{} {} {}", &digits[..3], &digits[3..6], &digits[6..])
    }
}

impl fmt::Debug for QuickSupportId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "QuickSupportId({})", self.digits())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_grouped_and_plain_forms() {
        let id: QuickSupportId = "123 456 789".parse().unwrap();
        assert_eq!(id.as_u32(), 123_456_789);
        assert_eq!("123-456-789".parse::<QuickSupportId>(), Ok(id));
        assert_eq!(" 123456789 ".parse::<QuickSupportId>(), Ok(id));
        assert_eq!(id.to_string(), "123 456 789");
        assert_eq!(id.digits(), "123456789");
        assert_eq!(format!("{id:?}"), "QuickSupportId(123456789)");

        let low: QuickSupportId = "000000007".parse().unwrap();
        assert_eq!(low.to_string(), "000 000 007");
        assert_eq!(low.digits(), "000000007");
    }

    #[test]
    fn rejects_anything_that_is_not_nine_digits() {
        for bad in [
            "12345678",
            "1234567890",
            "12a456789",
            "",
            "office-pc.omega",
            "100.64.0.1",
        ] {
            assert_eq!(
                bad.parse::<QuickSupportId>(),
                Err(InvalidQuickSupportId),
                "{bad}"
            );
            assert!(!QuickSupportId::looks_like(bad));
        }
        assert!(QuickSupportId::looks_like("987 654 321"));
        assert_eq!(QuickSupportId::from_u32(QUICKSUPPORT_ID_SPACE), None);
        assert_eq!(
            QuickSupportId::from_u32(QUICKSUPPORT_ID_SPACE - 1).map(QuickSupportId::digits),
            Some("999999999".to_owned())
        );
    }

    #[test]
    fn proposal_is_stable_per_device_and_nine_digits() {
        let device = DeviceId::from_signing_key(&[0x42; 32]);
        let first = QuickSupportId::proposed_for(device);
        assert_eq!(first, QuickSupportId::proposed_for(device));
        assert_eq!(first.digits().len(), 9);
        assert_ne!(
            first,
            QuickSupportId::proposed_for(DeviceId::from_signing_key(&[0x43; 32]))
        );
    }
}
