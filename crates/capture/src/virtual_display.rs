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
//!   - `changeDisplaySettings2` (lines 64–200) enumerating every active display path, physical
//!     and virtual, with `QueryDisplayConfig` before placing the virtual one, and
//!     `rearrangeVirtualDisplayForLowerRight` (lines 914–1180) computing the lower-right corner
//!     from the maxima of all *other* displays (`changeIndex` excluded) while the primary display
//!     stays anchored at `(0, 0)`; headless operation when zero physical monitors are connected.
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

/// Rectangle a display occupies on the virtual desktop, in pixels (`positionwidthheight` in
/// `virtual_display.cpp` lines 35–41). Used both for the physical monitors enumerated by the
/// platform (`QueryDisplayConfig` in `changeDisplaySettings2`) and for virtual displays.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DisplayBounds {
    /// Desktop X coordinate of the left edge.
    pub x: i32,
    /// Desktop Y coordinate of the top edge.
    pub y: i32,
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels.
    pub height: u32,
}

impl DisplayBounds {
    /// Creates a rectangle at `(x, y)` of `width` x `height` pixels.
    #[must_use]
    pub const fn new(x: i32, y: i32, width: u32, height: u32) -> Self {
        Self {
            x,
            y,
            width,
            height,
        }
    }

    /// X coordinate one past the right edge (saturating).
    #[must_use]
    pub fn right(self) -> i32 {
        self.x
            .saturating_add(i32::try_from(self.width).unwrap_or(i32::MAX))
    }

    /// Y coordinate one past the bottom edge (saturating).
    #[must_use]
    pub fn bottom(self) -> i32 {
        self.y
            .saturating_add(i32::try_from(self.height).unwrap_or(i32::MAX))
    }

    /// Returns `true` if the two rectangles share at least one pixel (touching edges do not overlap).
    #[must_use]
    pub fn overlaps(self, other: Self) -> bool {
        self.x < other.right()
            && other.x < self.right()
            && self.y < other.bottom()
            && other.y < self.bottom()
    }
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

impl VirtualDisplaySpec {
    /// Returns the rectangle this display occupies on the virtual desktop.
    #[must_use]
    pub const fn bounds(&self) -> DisplayBounds {
        DisplayBounds::new(self.x, self.y, self.width, self.height)
    }
}

/// Stateful `IddCx` virtual display and headless mode manager (`Apollo` `virtual_display.cpp`).
///
/// Placement works on the union of the physical monitor bounds supplied by the platform and the
/// virtual displays created here, the way `changeDisplaySettings2` feeds every active path from
/// `QueryDisplayConfig` into `rearrangeVirtualDisplayForLowerRight`. An empty physical list means
/// headless operation.
#[derive(Debug, Clone)]
pub struct VirtualDisplayManager {
    driver_status: DriverStatus,
    physical_displays: Vec<DisplayBounds>,
    active_displays: HashMap<[u8; 16], VirtualDisplaySpec>,
}

impl VirtualDisplayManager {
    /// Creates a new manager with the given attached physical displays (empty for headless).
    #[must_use]
    pub fn new(driver_status: DriverStatus, physical_displays: Vec<DisplayBounds>) -> Self {
        Self {
            driver_status,
            physical_displays,
            active_displays: HashMap::new(),
        }
    }

    /// Replaces the physical display list after a monitor is plugged in or removed. Existing
    /// virtual displays keep their position; the new bounds apply to subsequent placements.
    pub fn set_physical_displays(&mut self, physical_displays: Vec<DisplayBounds>) {
        self.physical_displays = physical_displays;
    }

    /// Returns the current [`DriverStatus`].
    #[must_use]
    pub const fn driver_status(&self) -> DriverStatus {
        self.driver_status
    }

    /// Returns the number of attached physical monitors.
    #[must_use]
    pub fn physical_monitor_count(&self) -> u32 {
        u32::try_from(self.physical_displays.len()).unwrap_or(u32::MAX)
    }

    /// Returns `true` when the machine has zero physical monitors attached and relies on an
    /// `IddCx` virtual display for headless operation (`docs/plan.md` §2.3 line 65 & §4 Phase 7).
    #[must_use]
    pub const fn is_headless(&self) -> bool {
        self.physical_displays.is_empty()
    }

    /// Returns the active virtual display identified by `guid`.
    #[must_use]
    pub fn display(&self, guid: &[u8; 16]) -> Option<&VirtualDisplaySpec> {
        self.active_displays.get(guid)
    }

    /// Creates or updates the virtual display of `client_uid` at the client's resolution and
    /// refresh rate (`createVirtualDisplay` & `rearrangeVirtualDisplayForLowerRight` in
    /// `virtual_display.cpp` lines 86–160 and 914–1180).
    ///
    /// A new GUID is placed in the isolated lower-right corner of every other display, physical
    /// and virtual, so it never overlaps a monitor the user already sees; on a headless machine
    /// the first display becomes the primary at `(0, 0)`. An existing GUID is an update: it keeps
    /// its origin (so the sole headless monitor stays the primary at `(0, 0)`) and only the other
    /// virtual displays that a larger size now overlaps are moved to a fresh lower-right corner.
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
        let (x, y) = match self.active_displays.get(&guid) {
            Some(existing) => (existing.x, existing.y),
            None => self.lower_right_corner(&guid),
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
        self.reflow_overlapping(&guid);
        Some(spec)
    }

    /// Lower-right corner of every display other than `exclude`: the maximum right edge and
    /// the maximum bottom edge over the physical monitors and the remaining virtual displays.
    /// This is the `imaxx` / `imaxy` scan of `rearrangeVirtualDisplayForLowerRight`
    /// (`virtual_display.cpp` lines 927–950) with `changeIndex` skipped, taking the two maxima
    /// independently so the placed display cannot overlap anything. With nothing else attached
    /// (headless, no other virtual display) the corner is the primary origin `(0, 0)`.
    fn lower_right_corner(&self, exclude: &[u8; 16]) -> (i32, i32) {
        let others = self.physical_displays.iter().copied().chain(
            self.active_displays
                .iter()
                .filter(|(guid, _)| *guid != exclude)
                .map(|(_, display)| display.bounds()),
        );
        let mut corner: Option<(i32, i32)> = None;
        for bounds in others {
            corner = Some(
                corner.map_or((bounds.right(), bounds.bottom()), |(right, bottom)| {
                    (right.max(bounds.right()), bottom.max(bounds.bottom()))
                }),
            );
        }
        corner.unwrap_or((0, 0))
    }

    /// Moves every other virtual display that now overlaps `updated` to a fresh lower-right
    /// corner, in GUID order so the outcome is deterministic. Displays that do not collide are
    /// left where they are.
    fn reflow_overlapping(&mut self, updated: &[u8; 16]) {
        let Some(updated_bounds) = self
            .active_displays
            .get(updated)
            .map(VirtualDisplaySpec::bounds)
        else {
            return;
        };
        let mut colliding: Vec<[u8; 16]> = self
            .active_displays
            .iter()
            .filter(|(guid, display)| *guid != updated && display.bounds().overlaps(updated_bounds))
            .map(|(guid, _)| *guid)
            .collect();
        colliding.sort_unstable();
        for guid in colliding {
            let (x, y) = self.lower_right_corner(&guid);
            if let Some(display) = self.active_displays.get_mut(&guid) {
                display.x = x;
                display.y = y;
            }
        }
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
        let mut mgr = VirtualDisplayManager::new(DriverStatus::Ok, Vec::new());
        assert!(mgr.is_headless());
        assert_eq!(mgr.physical_monitor_count(), 0);

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

    fn origin(mgr: &VirtualDisplayManager, client_uid: &str) -> (i32, i32) {
        let d = mgr
            .display(&derive_virtual_display_guid(client_uid))
            .unwrap_or_else(|| unreachable!());
        (d.x, d.y)
    }

    /// Regression test for #31 `virtual_display.rs:124`: re-creating an existing client's display
    /// is an update that keeps its origin, and other displays move only when a resize overlaps them.
    #[test]
    fn updating_existing_client_keeps_origin_and_reflows_only_on_overlap() {
        let mut mgr = VirtualDisplayManager::new(DriverStatus::Ok, Vec::new());
        let d1 = mgr
            .create_virtual_display("client-1", "Alice", 2560, 1440, 120, true)
            .unwrap_or_else(|| unreachable!());
        assert_eq!((d1.x, d1.y), (0, 0));

        // The sole headless monitor stays the primary at (0, 0) across repeated updates.
        for (w, h) in [(1920, 1080), (3840, 2160), (1280, 720)] {
            let updated = mgr
                .create_virtual_display("client-1", "Alice", w, h, 60, false)
                .unwrap_or_else(|| unreachable!());
            assert_eq!((updated.x, updated.y), (0, 0));
            assert_eq!((updated.width, updated.height), (w, h));
            assert_eq!(updated.guid, d1.guid);
            assert_eq!(mgr.active_count(), 1);
        }

        // A second client is isolated beyond the (now 1280x720) primary.
        let d2 = mgr
            .create_virtual_display("client-2", "Bob", 1920, 1080, 60, false)
            .unwrap_or_else(|| unreachable!());
        assert_eq!((d2.x, d2.y), (1280, 720));

        // Shrinking or a non-overlapping growth of the primary leaves the other display alone.
        mgr.create_virtual_display("client-1", "Alice", 1024, 768, 60, false);
        assert_eq!(origin(&mgr, "client-2"), (1280, 720));
        mgr.create_virtual_display("client-1", "Alice", 1280, 720, 60, false);
        assert_eq!(origin(&mgr, "client-2"), (1280, 720));

        // Growing the primary over client-2 reflows client-2 to the new lower-right corner,
        // while the primary itself keeps its origin.
        mgr.create_virtual_display("client-1", "Alice", 3840, 2160, 60, false);
        assert_eq!(origin(&mgr, "client-1"), (0, 0));
        assert_eq!(origin(&mgr, "client-2"), (3840, 2160));
        assert_eq!(mgr.active_count(), 2);

        // Updating the secondary display keeps its own origin too.
        let d2_again = mgr
            .create_virtual_display("client-2", "Bob", 2560, 1440, 60, false)
            .unwrap_or_else(|| unreachable!());
        assert_eq!((d2_again.x, d2_again.y), (3840, 2160));
        assert!(
            !d2_again.bounds().overlaps(
                mgr.display(&d1.guid)
                    .unwrap_or_else(|| unreachable!())
                    .bounds()
            )
        );
    }

    /// Regression test for #31 `virtual_display.rs:132`: placement includes the real physical
    /// monitor bounds instead of assuming a single 1920x1080 desktop.
    #[test]
    fn placement_accounts_for_physical_display_bounds() {
        // One 4K primary: the first virtual display lands outside it, at (3840, 2160).
        let mut mgr = VirtualDisplayManager::new(
            DriverStatus::Ok,
            vec![DisplayBounds::new(0, 0, 3840, 2160)],
        );
        assert!(!mgr.is_headless());
        assert_eq!(mgr.physical_monitor_count(), 1);
        let d1 = mgr
            .create_virtual_display("client-1", "Alice", 1920, 1080, 60, false)
            .unwrap_or_else(|| unreachable!());
        assert_eq!((d1.x, d1.y), (3840, 2160));
        assert!(!d1.bounds().overlaps(DisplayBounds::new(0, 0, 3840, 2160)));
        // The next one goes beyond both the physical monitor and the first virtual display.
        let d2 = mgr
            .create_virtual_display("client-2", "Bob", 1920, 1080, 60, false)
            .unwrap_or_else(|| unreachable!());
        assert_eq!((d2.x, d2.y), (5760, 3240));

        // Two side-by-side 1080p monitors: right edge 3840, bottom edge 1080.
        let mut dual = VirtualDisplayManager::new(
            DriverStatus::Ok,
            vec![
                DisplayBounds::new(0, 0, 1920, 1080),
                DisplayBounds::new(1920, 0, 1920, 1080),
            ],
        );
        let d = dual
            .create_virtual_display("client-1", "Alice", 1920, 1080, 60, false)
            .unwrap_or_else(|| unreachable!());
        assert_eq!((d.x, d.y), (3840, 1080));

        // A monitor left of the primary (negative X) does not push the corner left.
        let mut lefty = VirtualDisplayManager::new(
            DriverStatus::Ok,
            vec![
                DisplayBounds::new(-1920, 0, 1920, 1080),
                DisplayBounds::new(0, 0, 2560, 1440),
            ],
        );
        let d = lefty
            .create_virtual_display("client-1", "Alice", 1920, 1080, 60, false)
            .unwrap_or_else(|| unreachable!());
        assert_eq!((d.x, d.y), (2560, 1440));

        // Hot-plugging a monitor into a headless machine changes subsequent placements only.
        let mut hotplug = VirtualDisplayManager::new(DriverStatus::Ok, Vec::new());
        let primary = hotplug
            .create_virtual_display("client-1", "Alice", 1280, 720, 60, false)
            .unwrap_or_else(|| unreachable!());
        assert_eq!((primary.x, primary.y), (0, 0));
        hotplug.set_physical_displays(vec![DisplayBounds::new(0, 0, 3840, 2160)]);
        assert!(!hotplug.is_headless());
        assert_eq!(origin(&hotplug, "client-1"), (0, 0));
        let d = hotplug
            .create_virtual_display("client-2", "Bob", 1920, 1080, 60, false)
            .unwrap_or_else(|| unreachable!());
        assert_eq!((d.x, d.y), (3840, 2160));

        // Geometry helpers.
        let a = DisplayBounds::new(0, 0, 100, 100);
        assert!(a.overlaps(DisplayBounds::new(99, 99, 10, 10)));
        assert!(!a.overlaps(DisplayBounds::new(100, 0, 10, 10)));
        assert!(!a.overlaps(DisplayBounds::new(0, 100, 10, 10)));
        assert_eq!(DisplayBounds::new(i32::MAX, 0, 10, 10).right(), i32::MAX);
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
