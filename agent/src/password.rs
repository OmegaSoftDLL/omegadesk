//! Agent access password generation and verification.
//!
//! Without an access password, any host able to reach the UDP port could view
//! the screen and inject keyboard and mouse events. Phase 1 uses a random
//! one-time password generated on each startup (similar to RustDesk's
//! temporary password). In Phase 2 authorization is governed by device
//! identity and coordinator policies.

use rand_core::{OsRng, RngCore};

/// Unambiguous lowercase letters and digits (omits `0`/`o` and `1`/`l`/`i`).
const ALPHABET: &[u8] = b"abcdefghjkmnpqrstuvwxyz23456789";

/// Generated password length: 10 symbols out of 31 (~49.5 bits of entropy).
const LENGTH: usize = 10;

/// Generates a random password using the operating system CSPRNG.
pub(crate) fn generate() -> String {
    let mut password = String::with_capacity(LENGTH);
    while password.len() < LENGTH {
        let mut byte = [0u8; 1];
        OsRng.fill_bytes(&mut byte);
        // Rejection sampling to avoid modulo bias: 248 is the largest multiple of 31 below 256.
        if byte[0] < 248 {
            password.push(char::from(ALPHABET[usize::from(byte[0]) % ALPHABET.len()]));
        }
    }
    password
}

/// Compares two passwords in constant time with respect to character contents
/// so response timing does not leak how many leading characters matched.
pub(crate) fn matches(expected: &str, received: &str) -> bool {
    let (expected, received) = (expected.as_bytes(), received.as_bytes());
    let mut difference = u8::from(expected.len() != received.len());
    for (index, &byte) in expected.iter().enumerate() {
        difference |= byte ^ received.get(index).copied().unwrap_or(0);
    }
    difference == 0
}

#[cfg(test)]
mod tests {
    use super::{ALPHABET, LENGTH, generate, matches};

    #[test]
    fn generated_password_shape() {
        let password = generate();
        assert_eq!(password.len(), LENGTH);
        assert!(password.bytes().all(|byte| ALPHABET.contains(&byte)));
        assert_ne!(generate(), generate());
    }

    #[test]
    fn comparison() {
        assert!(matches("abc23", "abc23"));
        assert!(!matches("abc23", "abc24"));
        assert!(!matches("abc23", "abc2"));
        assert!(!matches("abc23", "abc234"));
        assert!(!matches("abc23", ""));
    }
}
