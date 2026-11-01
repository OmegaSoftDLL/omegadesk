//! `IddCx` virtual display at the client's resolution, headless mode, and
//! cross-platform capture backend selection (`PipeWire`/`KMS` on Linux,
//! `ScreenCaptureKit` on macOS).
//!
//! Reference implementations:
//! - `ClassicOldSong_Apollo/src/platform/windows/virtual_display.h` (lines 14–48) &
//!   `virtual_display.cpp` (lines 20–160):
//!   - `DRIVER_STATUS` (`OK = 0`, `UNKNOWN = 1`, `FAILED = -1`, `VERSION_INCOMPATIBLE = -2`,
//!     `WATCHDOG_FAILED = -3`),
//!   - `createVirtualDisplay(s_client_uid, s_client_name, width, height, fps, guid)` &
//!     `removeVirtualDisplay(guid)` with deterministic per-client display identity,
//!   - `rearrangeVirtualDisplayForLowerRight` keeping the primary display anchored at `(0, 0)`
//!     when isolated virtual displays are attached, and headless operation when zero physical
//!     monitors are connected.
//! - `LizardByte_Sunshine/src/platform/linux/` & `src/platform/macos/` (`docs/plan.md` §3
//!   line 209 & §4 Phase 7 line 306): Linux `PipeWire` / `KMS-DRM` `DMA-BUF` capture and macOS
//!   `ScreenCaptureKit` `IOSurface` capture selection.

use std::collections::HashMap;

use sha2::{Digest, Sha256};

/// Status of the Windows `IddCx` virtual display driver, ported from `VDISPLAY::DRIVER_STATUS`
/// (`ClassicOldSong_Apollo/src/platform/windows/virtual_display.h` lines 15–21).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum DriverStatus {
    /// Driver is operational and watchdog ping thread is healthy (`OK = 0`).
    Ok = 0,
    /// Driver state has not been probed yet (`UNKNOWN = 1`).
    Unknown = 1,
    /// Driver failed to open (`FAILED = -1`).
    Failed = -1,
    /// Installed `IddCx` driver version does not match the agent (`VERSION_INCOMPATIBLE = -2`).
    VersionIncompatible = -2,
    /// Driver watchdog keep-alive thread stopped responding (`WATCHDOG_FAILED = -3`).
    WatchdogFailed = -3,
}

/// Derives a deterministic RFC 4122 v5-shaped 16-byte GUID from `client_uid` so a returning
/// client always re-attaches to the same virtual monitor identity and Windows layout
/// (`Apollo` `createVirtualDisplay`).
#[must_use]
pub fn derive_virtual_display_guid(client_uid: &str) -> [u8; 16] {
    let digest = Sha256::digest(format!("omegadesk-iddcx-v1:{client_uid}").as_bytes());
    let mut guid = [0u8; 16];
    guid.copy_from_slice(&digest[..16]);
    guid[6] = (guid[6] & 0x0f) | 0x50; // Version 5
    guid[8] = (guid[8] & 0x3f) | 0x80; // RFC 4122 variant
    guid
}

/// Virtual display mode and placement specification (`positionwidthheight` in
/// `virtual_display.cpp` lines 35–41).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VirtualDisplaySpec {
    /// Deterministic 128-bit GUID derived from the client's UID.
    pub guid: [u8; 16],
    /// Client human-readable name.
    pub client_name: String,
    /// Desktop X coordinate.
    pub x: i32,
    /// Desktop Y coordinate.
    pub y: i32,
    /// Width in pixels at the client's native resolution.
    pub width: u32,
    /// Height in pixels at the client's native resolution.
    pub height: u32,
    /// Refresh rate in Hz matching the client's display (`fps`).
    pub refresh_hz: u32,
    /// Whether HDR / Advanced Color is enabled (`setDisplayHDRByName` in `virtual_display.h` line 31).
    pub hdr_enabled: bool,
}

/// Stateful `IddCx` virtual display and headless mode manager (`Apollo` `virtual_display.cpp`).
#[derive(Debug, Clone)]
pub struct VirtualDisplayManager {
    driver_status: DriverStatus,
    physical_monitor_count: u32,
    active_displays: HashMap<[u8; 16], VirtualDisplaySpec>,
}

impl VirtualDisplayManager {
    /// Creates a new manager with `physical_monitor_count` attached physical displays.
    #[must_use]
    pub fn new(driver_status: DriverStatus, physical_monitor_count: u32) -> Self {
        Self {
            driver_status,
            physical_monitor_count,
            active_displays: HashMap::new(),
        }
    }

    /// Returns the current [`DriverStatus`].
    #[must_use]
    pub const fn driver_status(&self) -> DriverStatus {
        self.driver_status
    }

    /// Returns `true` when the machine has zero physical monitors attached and relies on an
    /// `IddCx` virtual display for headless operation (`docs/plan.md` §2.3 line 65 & §4 Phase 7).
    #[must_use]
    pub const fn is_headless(&self) -> bool {
        self.physical_monitor_count == 0
    }

    /// Creates or updates a virtual display at the client's resolution and refresh rate,
    /// positioning it in the isolated lower-right corner relative to existing displays while
    /// keeping the primary monitor anchored at `(0, 0)` (`createVirtualDisplay` &
    /// `rearrangeVirtualDisplayForLowerRight` in `virtual_display.cpp` lines 86–160).
    pub fn create_virtual_display(
        &mut self,
        client_uid: &str,
        client_name: impl Into<String>,
        width: u32,
        height: u32,
        refresh_hz: u32,
        hdr_enabled: bool,
    ) -> Option<VirtualDisplaySpec> {
        if self.driver_status != DriverStatus::Ok {
            return None;
        }
        let guid = derive_virtual_display_guid(client_uid);
        let (x, y) = if self.is_headless() && self.active_displays.is_empty() {
            (0, 0)
        } else {
            let max_right = self
                .active_displays
                .values()
                .map(|d| d.x.saturating_add(i32::try_from(d.width).unwrap_or(1920)))
                .max()
                .unwrap_or(1920);
            let max_bottom = self
                .active_displays
                .values()
                .map(|d| d.y.saturating_add(i32::try_from(d.height).unwrap_or(1080)))
                .max()
                .unwrap_or(1080);
            (max_right, max_bottom)
        };

        let spec = VirtualDisplaySpec {
            guid,
            client_name: client_name.into(),
            x,
            y,
            width: width.max(640),
            height: height.max(480),
            refresh_hz: refresh_hz.clamp(24, 240),
            hdr_enabled,
        };
        self.active_displays.insert(guid, spec.clone());
        Some(spec)
    }

    /// Removes the virtual display identified by `guid` (`removeVirtualDisplay` in
    /// `virtual_display.h` line 45).
    pub fn remove_virtual_display(&mut self, guid: &[u8; 16]) -> bool {
        self.active_displays.remove(guid).is_some()
    }

    /// Returns the number of currently active virtual displays.
    #[must_use]
    pub fn active_count(&self) -> usize {
        self.active_displays.len()
    }
}

/// Linux screen capture backend (`docs/plan.md` §3 line 209 & §4 Phase 7 line 306).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxCaptureBackend {
    /// `PipeWire` portal capture with `DMA-BUF` zero-copy frames (Wayland / X11 user sessions).
    PipeWireDmaBuf,
    /// Direct `KMS/DRM` framebuffer plane capture (`CAP_SYS_ADMIN` / root console & login screen).
    KmsDrm,
}

/// Selects the optimal [`LinuxCaptureBackend`] based on whether a `PipeWire` Wayland/X11
/// session is active or whether root `KMS/DRM` capability is available (`Sunshine` `src/platform/linux/`).
#[must_use]
pub const fn select_linux_capture_backend(
    has_pipewire_portal: bool,
    has_kms_drm_cap: bool,
) -> Option<LinuxCaptureBackend> {
    if has_pipewire_portal {
        Some(LinuxCaptureBackend::PipeWireDmaBuf)
    } else if has_kms_drm_cap {
        Some(LinuxCaptureBackend::KmsDrm)
    } else {
        None
    }
}

/// macOS screen capture backend (`docs/plan.md` §3 line 209 & §4 Phase 7 line 306).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacOsCaptureBackend {
    /// Apple `ScreenCaptureKit` (`SCStream`) delivering zero-copy `IOSurface` GPU buffers
    /// (macOS 12.3+).
    ScreenCaptureKit,
}

/// Selects the macOS `ScreenCaptureKit` backend when running on macOS 12.3+ with screen
/// recording permission granted (`Sunshine` `src/platform/macos/`).
#[must_use]
pub const fn select_macos_capture_backend(
    macos_version: (u32, u32),
    screen_recording_granted: bool,
) -> Option<MacOsCaptureBackend> {
    if screen_recording_granted
        && (macos_version.0 > 12 || (macos_version.0 == 12 && macos_version.1 >= 3))
    {
        Some(MacOsCaptureBackend::ScreenCaptureKit)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn virtual_display_headless_and_isolated_lower_right_placement() {
        let guid_a = derive_virtual_display_guid("client-laptop-1");
        let guid_b = derive_virtual_display_guid("client-laptop-1");
        assert_eq!(guid_a, guid_b);

        // Headless server (0 physical monitors): first virtual display becomes primary at (0, 0).
        let mut mgr = VirtualDisplayManager::new(DriverStatus::Ok, 0);
        assert!(mgr.is_headless());

        let d1 = mgr
            .create_virtual_display("client-1", "Alice MacBook", 2560, 1440, 120, true)
            .unwrap_or_else(|| unreachable!());
        assert_eq!((d1.x, d1.y), (0, 0));

        // Second concurrent virtual display is isolated at the lower-right corner (2560, 1440).
        let d2 = mgr
            .create_virtual_display("client-2", "Bob Desktop", 1920, 1080, 60, false)
            .unwrap_or_else(|| unreachable!());
        assert_eq!((d2.x, d2.y), (2560, 1440));
        assert!(mgr.remove_virtual_display(&d1.guid));
        assert_eq!(mgr.active_count(), 1);
    }

    #[test]
    fn cross_platform_linux_and_macos_capture_selection() {
        assert_eq!(
            select_linux_capture_backend(true, true),
            Some(LinuxCaptureBackend::PipeWireDmaBuf)
        );
        assert_eq!(
            select_linux_capture_backend(false, true),
            Some(LinuxCaptureBackend::KmsDrm)
        );
        assert_eq!(
            select_macos_capture_backend((14, 5), true),
            Some(MacOsCaptureBackend::ScreenCaptureKit)
        );
        assert_eq!(select_macos_capture_backend((11, 0), true), None);
    }
}
