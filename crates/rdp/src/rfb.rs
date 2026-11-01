//! VNC/RFB compatibility primitives and the `xrdp-sesman` style per-user
//! virtual session allocator for Linux.
//!
//! References: `TigerVNC_tigervnc/common/rfb/{SMsgReaderV3.cxx,Security.h,CConnection.cxx}`
//! and `neutrinolabs_xrdp/sesman/` (session allocation model, `docs/plan.md` §2.6).

use crate::RdpError;

/// 12-byte RFB 3.8 protocol version banner (`"RFB 003.008\n"`, `TigerVNC` `SMsgReaderV3.cxx`).
pub const RFB_VERSION_3_8_BANNER: &[u8; 12] = b"RFB 003.008\n";

/// Negotiated RFB security types (`TigerVNC` `common/rfb/Security.h`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RfbSecurityType {
    /// Invalid / connection failed (`0`).
    Invalid = 0,
    /// Unauthenticated (`1`, only permitted over an already-authenticated mesh tunnel).
    None = 1,
    /// Classic DES challenge-response (`2`).
    VncAuth = 2,
    /// Tight security tunnel (`16`).
    Tight = 16,
    /// `VeNCrypt` TLS/X.509 security extension (`19`).
    VeNCrypt = 19,
}

/// Parses a 12-byte `"RFB MMM.mmm\n"` banner into `(major, minor)` version numbers
/// (`TigerVNC` `CConnection.cxx` / `SConnection.cxx`).
///
/// # Errors
///
/// Returns [`RdpError::InvalidRfbVersionBanner`] if the 12-byte banner does not match `"RFB DDD.DDD\n"`.
pub fn parse_rfb_version_banner(banner: &[u8]) -> Result<(u16, u16), RdpError> {
    if banner.len() != 12 || &banner[0..4] != b"RFB " || banner[7] != b'.' || banner[11] != b'\n' {
        return Err(RdpError::InvalidRfbVersionBanner);
    }
    let major = std::str::from_utf8(&banner[4..7])
        .ok()
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or(RdpError::InvalidRfbVersionBanner)?;
    let minor = std::str::from_utf8(&banner[8..11])
        .ok()
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or(RdpError::InvalidRfbVersionBanner)?;
    Ok((major, minor))
}

/// Per-user virtual display session descriptor on Linux (`xrdp-sesman` model, `docs/plan.md` §2.6 line 101).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxVirtualSession {
    /// Linux POSIX UID owning the isolated session.
    pub uid: u32,
    /// Username owning the session.
    pub username: String,
    /// Allocated X11/Wayland display number (`:10`..`:99`).
    pub display_number: u16,
    /// Environment string `DISPLAY=:<display_number>`.
    pub x11_display_env: String,
    /// Environment string `WAYLAND_DISPLAY=wayland-<display_number>`.
    pub wayland_display_env: String,
}

/// Allocates and reconnects isolated per-user virtual desktop sessions on Linux
/// (`xrdp` `sesman` architecture, `docs/plan.md` §2.6 line 101).
#[derive(Debug, Clone)]
pub struct LinuxVirtualSessionAllocator {
    min_display: u16,
    max_display: u16,
    by_uid: std::collections::HashMap<u32, LinuxVirtualSession>,
}

impl LinuxVirtualSessionAllocator {
    /// Creates an allocator managing display numbers in `min_display..=max_display` (e.g. `10..=99`).
    #[must_use]
    pub fn new(min_display: u16, max_display: u16) -> Self {
        Self {
            min_display: min_display.max(1),
            max_display: max_display.max(min_display.max(1)),
            by_uid: std::collections::HashMap::new(),
        }
    }

    /// Returns the existing virtual session for `uid` (reconnecting seamlessly) or allocates
    /// the lowest unused display number in `min_display..=max_display`.
    ///
    /// # Errors
    ///
    /// Returns [`RdpError::ExhaustedVirtualDisplays`] if all display slots are occupied.
    pub fn acquire_or_reconnect(
        &mut self,
        uid: u32,
        username: &str,
    ) -> Result<LinuxVirtualSession, RdpError> {
        if let Some(existing) = self.by_uid.get(&uid) {
            return Ok(existing.clone());
        }
        let used: std::collections::HashSet<u16> =
            self.by_uid.values().map(|s| s.display_number).collect();
        for display_number in self.min_display..=self.max_display {
            if !used.contains(&display_number) {
                let session = LinuxVirtualSession {
                    uid,
                    username: username.to_owned(),
                    display_number,
                    x11_display_env: format!(":{display_number}"),
                    wayland_display_env: format!("wayland-{display_number}"),
                };
                self.by_uid.insert(uid, session.clone());
                return Ok(session);
            }
        }
        Err(RdpError::ExhaustedVirtualDisplays(
            self.min_display,
            self.max_display,
        ))
    }

    /// Terminates and releases the virtual display session owned by `uid`.
    pub fn terminate_session(&mut self, uid: u32) -> Option<LinuxVirtualSession> {
        self.by_uid.remove(&uid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfb_version_banner_and_linux_virtual_session_allocator() {
        assert_eq!(parse_rfb_version_banner(RFB_VERSION_3_8_BANNER), Ok((3, 8)));
        assert!(parse_rfb_version_banner(b"RFB 003.008").is_err());

        let mut sesman = LinuxVirtualSessionAllocator::new(10, 11);
        let alice = sesman.acquire_or_reconnect(1000, "alice").unwrap();
        assert_eq!(alice.display_number, 10);
        assert_eq!(alice.x11_display_env, ":10");
        // Reconnecting same UID reuses display :10
        assert_eq!(sesman.acquire_or_reconnect(1000, "alice").unwrap(), alice);

        let bob = sesman.acquire_or_reconnect(1001, "bob").unwrap();
        assert_eq!(bob.display_number, 11);
        assert!(sesman.acquire_or_reconnect(1002, "charlie").is_err());
    }
}
