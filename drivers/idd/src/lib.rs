//! Safe Rust API over the QuickDesk Windows Indirect Display (IddCx) virtual
//! display driver (`drivers/idd`).
//!
//! The driver is vendored under `vendor/`: the user-mode controller
//! (`vendor/control/IddController.c`, compiled by `build.rs` with the normal
//! Windows SDK) drives the prebuilt, signed kernel driver
//! (`vendor/prebuilt/x64/quickdesk_display.{dll,cat,inf}`), installed and
//! removed with the bundled `nefconw.exe`. See `vendor/README.md` and
//! `THIRD_PARTY.md` for provenance and the MIT license.
//!
//! Everything is Windows-only at runtime: on Linux and macOS the API compiles
//! unchanged and every operation returns [`Error::Unsupported`], so the rest of
//! the workspace builds and tests on all three operating systems.
//!
//! ```no_run
//! use omegadesk_idd::{DisplayMode, VirtualDisplay};
//!
//! # fn main() -> Result<(), omegadesk_idd::Error> {
//! let display = VirtualDisplay::install()?; // needs administrator rights
//! let monitor = display.plug_monitor(DisplayMode::new(1920, 1080, 60)?)?;
//! // ... stream the virtual monitor ...
//! monitor.unplug()?;
//! VirtualDisplay::uninstall()?;
//! # Ok(())
//! # }
//! ```

use std::sync::{Mutex, OnceLock, PoisonError};

use thiserror::Error;

/// Maximum number of virtual monitors the adapter exposes
/// (`QUICKDESK_VD_MAX_MONITORS` in `vendor/driver/Public.h`).
pub const MAX_MONITORS: u32 = 4;

/// Errors returned by the virtual display API.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// The virtual display driver is only available on Windows.
    #[error("virtual display is Windows-only and unavailable on this platform")]
    Unsupported,
    /// Installing or removing the driver requires an elevated (administrator) process.
    #[error("the virtual display driver requires administrator privileges")]
    NotElevated,
    /// An operation needed the driver but it is not installed.
    #[error("the virtual display driver is not installed")]
    NotInstalled,
    /// Every connector is already in use; unplug a monitor before plugging another.
    #[error("all {max} virtual monitor connectors are in use")]
    NoFreeConnector {
        /// The adapter's connector count ([`MAX_MONITORS`]).
        max: u32,
    },
    /// The requested [`DisplayMode`] is outside the supported range.
    #[error("invalid display mode {width}x{height}@{refresh_hz}Hz: {reason}")]
    InvalidMode {
        /// Requested width in pixels.
        width: u32,
        /// Requested height in pixels.
        height: u32,
        /// Requested refresh rate in Hz.
        refresh_hz: u32,
        /// Why the mode was rejected.
        reason: &'static str,
    },
    /// A driver IOCTL or device-management call failed; the string is the
    /// controller's last error message.
    #[error("virtual display driver call failed: {0}")]
    Driver(String),
    /// Running the bundled `nefconw.exe` installer failed.
    #[error("virtual display driver installer failed: {0}")]
    Installer(String),
}

/// Result alias for this crate.
pub type Result<T> = core::result::Result<T, Error>;

/// A validated virtual monitor mode: resolution and refresh rate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DisplayMode {
    width: u32,
    height: u32,
    refresh_hz: u32,
}

impl DisplayMode {
    /// Smallest accepted width/height edge, in pixels.
    pub const MIN_WIDTH: u32 = 640;
    /// Smallest accepted height, in pixels.
    pub const MIN_HEIGHT: u32 = 480;
    /// Largest accepted width or height, in pixels (8K super-ultrawide headroom).
    pub const MAX_EDGE: u32 = 16_384;
    /// Highest accepted refresh rate, in Hz.
    pub const MAX_REFRESH_HZ: u32 = 240;

    /// Validates and builds a [`DisplayMode`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidMode`] when `width` is not in
    /// `MIN_WIDTH..=MAX_EDGE`, `height` is not in `MIN_HEIGHT..=MAX_EDGE`, or
    /// `refresh_hz` is not in `1..=MAX_REFRESH_HZ`.
    pub const fn new(width: u32, height: u32, refresh_hz: u32) -> Result<Self> {
        if width < Self::MIN_WIDTH || width > Self::MAX_EDGE {
            return Err(Error::InvalidMode {
                width,
                height,
                refresh_hz,
                reason: "width out of range",
            });
        }
        if height < Self::MIN_HEIGHT || height > Self::MAX_EDGE {
            return Err(Error::InvalidMode {
                width,
                height,
                refresh_hz,
                reason: "height out of range",
            });
        }
        if refresh_hz == 0 || refresh_hz > Self::MAX_REFRESH_HZ {
            return Err(Error::InvalidMode {
                width,
                height,
                refresh_hz,
                reason: "refresh rate out of range",
            });
        }
        Ok(Self {
            width,
            height,
            refresh_hz,
        })
    }

    /// Width in pixels.
    #[must_use]
    pub const fn width(self) -> u32 {
        self.width
    }

    /// Height in pixels.
    #[must_use]
    pub const fn height(self) -> u32 {
        self.height
    }

    /// Refresh rate in Hz.
    #[must_use]
    pub const fn refresh_hz(self) -> u32 {
        self.refresh_hz
    }
}

/// Bitmask connector allocator for the adapter's [`MAX_MONITORS`] slots.
///
/// This is the pure state machine behind [`VirtualDisplay::plug_monitor`] and
/// [`MonitorHandle`]: a slot is claimed on plug-in and returned on unplug (or on
/// a failed plug-in), so a connector index is never handed out twice.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct ConnectorAllocator {
    mask: u8,
}

impl ConnectorAllocator {
    const fn new() -> Self {
        Self { mask: 0 }
    }

    /// Claims the lowest free connector index, or `None` if all are in use.
    fn allocate(&mut self) -> Option<u32> {
        for index in 0..MAX_MONITORS {
            let bit = 1u8 << index;
            if self.mask & bit == 0 {
                self.mask |= bit;
                return Some(index);
            }
        }
        None
    }

    /// Releases `index`; returns `true` if it had been claimed.
    fn release(&mut self, index: u32) -> bool {
        if index >= MAX_MONITORS {
            return false;
        }
        let bit = 1u8 << index;
        if self.mask & bit == 0 {
            return false;
        }
        self.mask &= !bit;
        true
    }

    #[cfg(test)]
    fn in_use(self, index: u32) -> bool {
        index < MAX_MONITORS && self.mask & (1u8 << index) != 0
    }

    fn count(self) -> u32 {
        self.mask.count_ones()
    }
}

/// Runs `f` against the process-global connector allocator.
///
/// The driver adapter is a single device shared by the whole process, so one
/// allocator tracks every live [`MonitorHandle`]. A poisoned lock is recovered
/// rather than propagated: the allocator holds only a bitmask.
fn with_allocator<R>(f: impl FnOnce(&mut ConnectorAllocator) -> R) -> R {
    static ALLOCATOR: OnceLock<Mutex<ConnectorAllocator>> = OnceLock::new();
    let mutex = ALLOCATOR.get_or_init(|| Mutex::new(ConnectorAllocator::new()));
    let mut guard = mutex.lock().unwrap_or_else(PoisonError::into_inner);
    f(&mut guard)
}

/// Handle to the installed virtual display adapter.
///
/// Obtain one with [`VirtualDisplay::install`] (first run, needs administrator
/// rights) or [`VirtualDisplay::open`] (driver already installed, no elevation
/// needed), then hot-plug monitors with [`VirtualDisplay::plug_monitor`].
#[derive(Debug, Clone, Copy)]
pub struct VirtualDisplay {
    _private: (),
}

impl VirtualDisplay {
    /// Returns whether the virtual display driver is installed and its device
    /// node is present.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Unsupported`] off Windows, or [`Error::Driver`] if the
    /// device enumeration call fails.
    pub fn is_installed() -> Result<bool> {
        imp::is_installed()
    }

    /// Installs the bundled signed driver (idempotent) and returns a handle.
    ///
    /// Creates the `Root\QuickDesk\VDD` device node and installs the driver
    /// package with the bundled `nefconw.exe`. Safe to call repeatedly: an
    /// existing node is reused and the driver package is updated in place.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Unsupported`] off Windows, [`Error::NotElevated`] if the
    /// process is not elevated, or [`Error::Installer`] if `nefconw.exe` fails.
    pub fn install() -> Result<Self> {
        imp::install_driver()?;
        Ok(Self { _private: () })
    }

    /// Returns a handle to an already-installed driver without elevating.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Unsupported`] off Windows, [`Error::NotInstalled`] if the
    /// driver is not installed, or [`Error::Driver`] if enumeration fails.
    pub fn open() -> Result<Self> {
        if imp::is_installed()? {
            Ok(Self { _private: () })
        } else {
            Err(Error::NotInstalled)
        }
    }

    /// Removes the driver's device node (uninstall).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Unsupported`] off Windows, [`Error::NotElevated`] if the
    /// process is not elevated, or [`Error::Installer`] if `nefconw.exe` fails.
    pub fn uninstall() -> Result<()> {
        imp::uninstall_driver()
    }

    /// Returns how many virtual monitors are currently plugged in across the
    /// process (`0..=`[`MAX_MONITORS`]).
    #[must_use]
    pub fn active_monitor_count() -> u32 {
        with_allocator(|allocator| allocator.count())
    }

    /// Hot-plugs a new virtual monitor at `mode` and returns its [`MonitorHandle`].
    ///
    /// The connector index is reserved for the returned handle and released when
    /// it is [`unplugged`](MonitorHandle::unplug) or dropped.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NoFreeConnector`] if all [`MAX_MONITORS`] connectors are
    /// in use, [`Error::Unsupported`] off Windows, or [`Error::Driver`] if the
    /// plug-in IOCTL fails (the reserved connector is released first).
    pub fn plug_monitor(&self, mode: DisplayMode) -> Result<MonitorHandle> {
        let index = with_allocator(ConnectorAllocator::allocate)
            .ok_or(Error::NoFreeConnector { max: MAX_MONITORS })?;
        match imp::plug_in(index, mode) {
            Ok(()) => Ok(MonitorHandle {
                index,
                mode,
                plugged: true,
            }),
            Err(err) => {
                with_allocator(|allocator| allocator.release(index));
                Err(err)
            }
        }
    }
}

/// A plugged-in virtual monitor. Unplugs itself on drop if still plugged.
#[derive(Debug)]
pub struct MonitorHandle {
    index: u32,
    mode: DisplayMode,
    plugged: bool,
}

impl MonitorHandle {
    /// The adapter connector index this monitor occupies (`0..`[`MAX_MONITORS`]).
    #[must_use]
    pub const fn index(&self) -> u32 {
        self.index
    }

    /// The monitor's current [`DisplayMode`].
    #[must_use]
    pub const fn mode(&self) -> DisplayMode {
        self.mode
    }

    /// Changes the monitor's mode (resolution and refresh rate) in place.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Unsupported`] off Windows or [`Error::Driver`] if the
    /// update IOCTL fails; on error the recorded mode is unchanged.
    pub fn set_mode(&mut self, mode: DisplayMode) -> Result<()> {
        imp::update_modes(self.index, mode)?;
        self.mode = mode;
        Ok(())
    }

    /// Unplugs the monitor, freeing its connector.
    ///
    /// The connector is released even if the IOCTL reports an error, so a failed
    /// unplug never leaks a slot.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Unsupported`] off Windows or [`Error::Driver`] if the
    /// plug-out IOCTL fails.
    pub fn unplug(mut self) -> Result<()> {
        let result = imp::plug_out(self.index);
        with_allocator(|allocator| allocator.release(self.index));
        self.plugged = false;
        result
    }
}

impl Drop for MonitorHandle {
    fn drop(&mut self) {
        if self.plugged {
            let _ = imp::plug_out(self.index);
            with_allocator(|allocator| allocator.release(self.index));
        }
    }
}

#[cfg(windows)]
mod imp {
    //! Windows implementation: links the controller compiled by `build.rs` and
    //! drives the signed driver through IOCTLs and `nefconw.exe`.
    #![allow(
        unsafe_code,
        reason = "FFI into the vendored C IddCx controller and Win32 token APIs"
    )]

    use std::ffi::CStr;
    use std::os::raw::{c_char, c_int, c_uint};
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::{fs, mem};

    use tracing::debug;
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::{
        GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    use crate::{DisplayMode, Error, Result};

    /// Root-enumerated hardware ID of the virtual display device node, matching
    /// `vendor/prebuilt/x64/quickdesk_display.inf`.
    const HARDWARE_ID: &str = r"Root\QuickDesk\VDD";
    /// `Display` setup class GUID.
    const CLASS_GUID: &str = "{4D36E968-E325-11CE-BFC1-08002BE10318}";

    const NEFCONW_EXE: &[u8] = include_bytes!("../vendor/prebuilt/x64/nefconw.exe");
    const DRIVER_DLL: &[u8] = include_bytes!("../vendor/prebuilt/x64/quickdesk_display.dll");
    const DRIVER_CAT: &[u8] = include_bytes!("../vendor/prebuilt/x64/quickdesk_display.cat");
    const DRIVER_INF: &[u8] = include_bytes!("../vendor/prebuilt/x64/quickdesk_display.inf");

    /// One entry of the driver's dynamic mode list (`MonitorMode` in
    /// `vendor/control/IddController.h`).
    #[repr(C)]
    struct MonitorMode {
        width: u32,
        height: u32,
        sync: u32,
    }

    // Functions exported by the compiled `IddController.c`. `BOOL` is a C `int`
    // (`TRUE`/`FALSE`). These never take Rust-owned strings, so UNICODE vs ANSI
    // of the C build does not affect the signatures.
    unsafe extern "C" {
        fn MonitorPlugIn(index: c_uint, edid: c_uint, retries: c_int) -> c_int;
        fn MonitorPlugOut(index: c_uint) -> c_int;
        fn MonitorModesUpdate(
            index: c_uint,
            mode_count: c_uint,
            modes: *const MonitorMode,
        ) -> c_int;
        fn IsDeviceCreated(created: *mut c_int) -> c_int;
        fn GetLastMsg() -> *const c_char;
    }

    /// Returns the controller's last error message.
    fn last_msg() -> String {
        // SAFETY: `GetLastMsg` returns a pointer to a static NUL-terminated
        // buffer owned by the C controller; it is never null per its contract.
        let ptr = unsafe { GetLastMsg() };
        if ptr.is_null() {
            return String::new();
        }
        // SAFETY: `ptr` is non-null and points to a NUL-terminated C string.
        let text = unsafe { CStr::from_ptr(ptr) };
        text.to_string_lossy().into_owned()
    }

    /// Whether the current process is running elevated (administrator).
    fn is_elevated() -> Result<bool> {
        let mut token = HANDLE::default();
        // SAFETY: returns the current-process pseudo-handle; no cleanup needed.
        let process = unsafe { GetCurrentProcess() };
        // SAFETY: `process` is valid; `token` receives an owned handle closed below.
        unsafe { OpenProcessToken(process, TOKEN_QUERY, &raw mut token) }
            .map_err(|error| Error::Driver(format!("OpenProcessToken failed: {error}")))?;

        let mut elevation = TOKEN_ELEVATION::default();
        let mut returned = 0u32;
        let size = u32::try_from(mem::size_of::<TOKEN_ELEVATION>()).unwrap_or(0);
        // SAFETY: `elevation` is a `TOKEN_ELEVATION` of `size` bytes, the buffer
        // the `TokenElevation` information class requires.
        let info = unsafe {
            GetTokenInformation(
                token,
                TokenElevation,
                Some((&raw mut elevation).cast()),
                size,
                &raw mut returned,
            )
        };
        // SAFETY: `token` is the open handle returned by `OpenProcessToken`.
        let _ = unsafe { CloseHandle(token) };
        info.map_err(|error| Error::Driver(format!("GetTokenInformation failed: {error}")))?;
        Ok(elevation.TokenIsElevated != 0)
    }

    pub(crate) fn is_installed() -> Result<bool> {
        let mut created: c_int = 0;
        // SAFETY: `IsDeviceCreated` writes a `BOOL` into `created`.
        let ok = unsafe { IsDeviceCreated(&raw mut created) };
        if ok == 0 {
            return Err(Error::Driver(last_msg()));
        }
        Ok(created != 0)
    }

    pub(crate) fn plug_in(index: u32, mode: DisplayMode) -> Result<()> {
        // `edid = 0` selects a built-in base EDID; the mode update below sets the
        // real resolution. `retries = 25` matches the reference controller: the
        // device interface can take a moment to appear after creation.
        // SAFETY: all arguments are plain scalars.
        let ok = unsafe { MonitorPlugIn(index, 0, 25) };
        if ok == 0 {
            return Err(Error::Driver(last_msg()));
        }
        update_modes(index, mode)
    }

    pub(crate) fn update_modes(index: u32, mode: DisplayMode) -> Result<()> {
        let modes = [MonitorMode {
            width: mode.width,
            height: mode.height,
            sync: mode.refresh_hz,
        }];
        // SAFETY: `modes` points to one valid `MonitorMode` that outlives the call.
        let ok = unsafe { MonitorModesUpdate(index, 1, modes.as_ptr()) };
        if ok == 0 {
            return Err(Error::Driver(last_msg()));
        }
        Ok(())
    }

    pub(crate) fn plug_out(index: u32) -> Result<()> {
        // SAFETY: `index` is a plain scalar.
        let ok = unsafe { MonitorPlugOut(index) };
        if ok == 0 {
            return Err(Error::Driver(last_msg()));
        }
        Ok(())
    }

    pub(crate) fn install_driver() -> Result<()> {
        if !is_elevated()? {
            return Err(Error::NotElevated);
        }
        let payload = Payload::extract()?;
        // Idempotent: `--no-duplicates` keeps a single device node, and
        // `--install-driver` updates the package in place.
        run_nefconw(
            &payload.nefconw,
            &[
                "--create-device-node",
                "--class-name",
                "Display",
                "--class-guid",
                CLASS_GUID,
                "--hardware-id",
                HARDWARE_ID,
                "--no-duplicates",
            ],
        )?;
        let inf = payload.inf.to_string_lossy().into_owned();
        run_nefconw(&payload.nefconw, &["--install-driver", "--inf-path", &inf])?;
        debug!("virtual display driver installed");
        Ok(())
    }

    pub(crate) fn uninstall_driver() -> Result<()> {
        if !is_elevated()? {
            return Err(Error::NotElevated);
        }
        let payload = Payload::extract()?;
        run_nefconw(
            &payload.nefconw,
            &[
                "--remove-device-node",
                "--hardware-id",
                HARDWARE_ID,
                "--class-guid",
                CLASS_GUID,
            ],
        )?;
        debug!("virtual display driver removed");
        Ok(())
    }

    /// The bundled installer payload unpacked into a temporary directory.
    struct Payload {
        dir: PathBuf,
        nefconw: PathBuf,
        inf: PathBuf,
    }

    impl Payload {
        fn extract() -> Result<Self> {
            let dir = std::env::temp_dir().join(format!("omegadesk-idd-{}", std::process::id()));
            fs::create_dir_all(&dir)
                .map_err(|error| Error::Installer(format!("create temp dir: {error}")))?;
            let nefconw = write_file(&dir, "nefconw.exe", NEFCONW_EXE)?;
            let inf = write_file(&dir, "quickdesk_display.inf", DRIVER_INF)?;
            write_file(&dir, "quickdesk_display.dll", DRIVER_DLL)?;
            write_file(&dir, "quickdesk_display.cat", DRIVER_CAT)?;
            Ok(Self { dir, nefconw, inf })
        }
    }

    impl Drop for Payload {
        fn drop(&mut self) {
            // The driver store keeps its own copy after install; the temp copy
            // is disposable.
            let _ = fs::remove_dir_all(&self.dir);
        }
    }

    fn write_file(dir: &Path, name: &str, bytes: &[u8]) -> Result<PathBuf> {
        let path = dir.join(name);
        fs::write(&path, bytes)
            .map_err(|error| Error::Installer(format!("write {name}: {error}")))?;
        Ok(path)
    }

    fn run_nefconw(exe: &Path, args: &[&str]) -> Result<()> {
        let output = Command::new(exe)
            .args(args)
            .output()
            .map_err(|error| Error::Installer(format!("launch nefconw.exe: {error}")))?;
        if output.status.success() {
            return Ok(());
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let action = args.first().copied().unwrap_or("nefconw");
        Err(Error::Installer(format!(
            "nefconw {action} exited with {}: {}{}",
            output.status,
            stdout.trim(),
            stderr.trim()
        )))
    }
}

#[cfg(not(windows))]
mod imp {
    //! Non-Windows stub: every operation reports [`Error::Unsupported`].

    use crate::{DisplayMode, Error, Result};

    pub(crate) fn is_installed() -> Result<bool> {
        Err(Error::Unsupported)
    }

    pub(crate) fn install_driver() -> Result<()> {
        Err(Error::Unsupported)
    }

    pub(crate) fn uninstall_driver() -> Result<()> {
        Err(Error::Unsupported)
    }

    pub(crate) fn plug_in(_index: u32, _mode: DisplayMode) -> Result<()> {
        Err(Error::Unsupported)
    }

    pub(crate) fn update_modes(_index: u32, _mode: DisplayMode) -> Result<()> {
        Err(Error::Unsupported)
    }

    pub(crate) fn plug_out(_index: u32) -> Result<()> {
        Err(Error::Unsupported)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_mode_accepts_common_resolutions() {
        for (w, h, hz) in [
            (1920, 1080, 60),
            (2560, 1440, 120),
            (3840, 2160, 60),
            (640, 480, 1),
        ] {
            let mode = DisplayMode::new(w, h, hz).unwrap_or_else(|_| unreachable!());
            assert_eq!((mode.width(), mode.height(), mode.refresh_hz()), (w, h, hz));
        }
    }

    #[test]
    fn display_mode_rejects_out_of_range() {
        assert!(matches!(
            DisplayMode::new(320, 240, 60),
            Err(Error::InvalidMode { .. })
        ));
        assert!(matches!(
            DisplayMode::new(1920, 1080, 0),
            Err(Error::InvalidMode { .. })
        ));
        assert!(matches!(
            DisplayMode::new(1920, 1080, 300),
            Err(Error::InvalidMode { .. })
        ));
        assert!(matches!(
            DisplayMode::new(20_000, 1080, 60),
            Err(Error::InvalidMode { .. })
        ));
    }

    #[test]
    fn connector_allocator_claims_and_releases_every_slot() {
        let mut allocator = ConnectorAllocator::new();
        let mut claimed = Vec::new();
        for _ in 0..MAX_MONITORS {
            let index = allocator.allocate().unwrap_or_else(|| unreachable!());
            assert!(allocator.in_use(index));
            claimed.push(index);
        }
        // Distinct indices, all slots taken.
        claimed.sort_unstable();
        assert_eq!(claimed, (0..MAX_MONITORS).collect::<Vec<_>>());
        assert_eq!(allocator.count(), MAX_MONITORS);

        // Exhausted: no slot until one is released.
        assert_eq!(allocator.allocate(), None);

        assert!(allocator.release(2));
        assert!(!allocator.in_use(2));
        assert!(!allocator.release(2)); // double release is a no-op
        assert_eq!(allocator.allocate(), Some(2)); // freed slot comes back
        assert_eq!(allocator.count(), MAX_MONITORS);
    }

    #[test]
    fn connector_allocator_ignores_out_of_range_release() {
        let mut allocator = ConnectorAllocator::new();
        assert!(!allocator.release(MAX_MONITORS));
        assert!(!allocator.in_use(MAX_MONITORS));
        assert_eq!(allocator.count(), 0);
    }

    #[cfg(not(windows))]
    #[test]
    fn operations_are_windows_only_off_windows() {
        assert!(matches!(
            VirtualDisplay::is_installed(),
            Err(Error::Unsupported)
        ));
        assert!(matches!(VirtualDisplay::install(), Err(Error::Unsupported)));
        assert!(matches!(VirtualDisplay::open(), Err(Error::Unsupported)));
        assert!(matches!(
            VirtualDisplay::uninstall(),
            Err(Error::Unsupported)
        ));
    }

    /// Windows integration test: installs the signed driver, plugs a
    /// 1920x1080@60 monitor, asserts Windows enumerates a new display device,
    /// then unplugs and uninstalls. Ignored by default: it needs administrator
    /// privileges and changes system display devices.
    ///
    /// Run with: `cargo test -p omegadesk-idd -- --ignored --nocapture`
    #[cfg(windows)]
    #[test]
    #[ignore = "needs administrator privileges and modifies system display devices"]
    #[allow(
        unsafe_code,
        reason = "Win32 EnumDisplayDevices probe in an ignored integration test"
    )]
    fn windows_install_plug_enumerate_unplug_uninstall()
    -> core::result::Result<(), Box<dyn std::error::Error>> {
        use std::{thread::sleep, time::Duration};

        use windows::Win32::Graphics::Gdi::{DISPLAY_DEVICEW, EnumDisplayDevicesW};
        use windows::core::PCWSTR;

        fn attached_display_count() -> u32 {
            let mut count = 0u32;
            let mut index = 0u32;
            loop {
                let mut device = DISPLAY_DEVICEW {
                    cb: u32::try_from(size_of::<DISPLAY_DEVICEW>()).unwrap_or(0),
                    ..Default::default()
                };
                // SAFETY: `device.cb` is initialized; `EnumDisplayDevicesW`
                // fills `device` for adapter `index` and returns 0 at the end.
                let ok = unsafe { EnumDisplayDevicesW(PCWSTR::null(), index, &raw mut device, 0) };
                if !ok.as_bool() {
                    break;
                }
                count += 1;
                index += 1;
            }
            count
        }

        let before = attached_display_count();
        let display = VirtualDisplay::install()?;
        assert!(VirtualDisplay::is_installed()?);

        let monitor = display.plug_monitor(DisplayMode::new(1920, 1080, 60)?)?;
        sleep(Duration::from_secs(3)); // let Windows attach the monitor
        let after = attached_display_count();
        assert!(
            after > before,
            "expected a new display device after plug-in"
        );

        monitor.unplug()?;
        VirtualDisplay::uninstall()?;
        Ok(())
    }
}
