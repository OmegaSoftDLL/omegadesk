//! Virtual display wiring for headless hosts and privacy mode.
//!
//! Parses the `--virtual-display <WxH@hz>` flag, plugs a virtual monitor
//! through the signed IddCx driver (`omegadesk-idd`), and tracks its placement
//! with the capture crate's `VirtualDisplayManager` (the placement model lives
//! there; this module backs it with the real driver instead of duplicating it).
//! Privacy mode additionally blanks the physical monitor (RustDesk model): the
//! remote operator sees the virtual display while the local screen goes dark.

use anyhow::{Context, anyhow};
use omegadesk_capture::virtual_display::{DriverStatus, VirtualDisplayManager};
use omegadesk_idd::{DisplayMode, MonitorHandle, VirtualDisplay};
use tracing::{info, warn};

/// Default refresh rate when `--virtual-display` omits `@hz`.
const DEFAULT_REFRESH_HZ: u32 = 60;

/// A parsed `--virtual-display` request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct VirtualDisplayRequest {
    mode: DisplayMode,
}

impl VirtualDisplayRequest {
    /// The requested [`DisplayMode`].
    pub(crate) const fn mode(self) -> DisplayMode {
        self.mode
    }
}

/// Parses `WxH` or `WxH@hz` (e.g. `1920x1080` or `2560x1440@120`) into a
/// validated request. Returns a human-readable message on any error.
pub(crate) fn parse_request(value: &str) -> Result<VirtualDisplayRequest, String> {
    let (resolution, refresh_hz) = match value.split_once('@') {
        Some((resolution, hz)) => {
            let hz = hz
                .trim()
                .parse::<u32>()
                .map_err(|_| format!("invalid refresh rate in `{value}`; expected WxH@hz"))?;
            (resolution, hz)
        }
        None => (value, DEFAULT_REFRESH_HZ),
    };
    let (width, height) = resolution
        .trim()
        .split_once(['x', 'X'])
        .ok_or_else(|| format!("expected WxH[@hz], got `{value}`"))?;
    let width = width
        .trim()
        .parse::<u32>()
        .map_err(|_| format!("invalid width in `{value}`; expected WxH[@hz]"))?;
    let height = height
        .trim()
        .parse::<u32>()
        .map_err(|_| format!("invalid height in `{value}`; expected WxH[@hz]"))?;
    let mode = DisplayMode::new(width, height, refresh_hz).map_err(|error| error.to_string())?;
    Ok(VirtualDisplayRequest { mode })
}

/// An active virtual monitor. Unplugs it (and restores the physical screen when
/// privacy mode was on) when dropped, so the host is left as it was found.
pub(crate) struct ActiveVirtualDisplay {
    monitor: Option<MonitorHandle>,
    privacy: bool,
}

impl ActiveVirtualDisplay {
    /// Ensures the driver is installed, plugs the requested virtual monitor and,
    /// when `privacy` is set, blanks the physical monitor.
    ///
    /// # Errors
    ///
    /// Returns an error if the driver cannot be installed or opened (installing
    /// needs administrator rights) or the monitor cannot be plugged in.
    pub(crate) fn start(request: VirtualDisplayRequest, privacy: bool) -> anyhow::Result<Self> {
        let display = match VirtualDisplay::open() {
            Ok(display) => display,
            Err(_) => VirtualDisplay::install()
                .context("installing the virtual display driver (needs administrator rights)")?,
        };

        let mode = request.mode();
        // Back the capture placement model with the real driver: a headless host
        // has no physical monitors, so the sole virtual display is the primary.
        let mut manager = VirtualDisplayManager::new(DriverStatus::Ok, Vec::new());
        if let Some(spec) = manager.create_virtual_display(
            "local-headless",
            "OmegaDesk headless",
            mode.width(),
            mode.height(),
            mode.refresh_hz(),
            false,
        ) {
            info!(
                "virtual display placed at ({}, {}){}",
                spec.x,
                spec.y,
                if manager.is_headless() {
                    " (headless primary)"
                } else {
                    ""
                }
            );
        }

        let monitor = display
            .plug_monitor(mode)
            .context("plugging the virtual monitor")?;
        info!(
            "virtual display plugged: {}x{}@{}Hz on connector {}",
            mode.width(),
            mode.height(),
            mode.refresh_hz(),
            monitor.index()
        );

        if privacy {
            set_physical_monitor_power(false);
            info!("privacy mode on: physical monitor blanked");
        }

        Ok(Self {
            monitor: Some(monitor),
            privacy,
        })
    }
}

impl Drop for ActiveVirtualDisplay {
    fn drop(&mut self) {
        if self.privacy {
            set_physical_monitor_power(true);
        }
        if let Some(monitor) = self.monitor.take()
            && let Err(error) = monitor.unplug()
        {
            warn!("failed to unplug virtual display: {error}");
        }
    }
}

/// Builds an [`ActiveVirtualDisplay`] from the CLI flag, logging and continuing
/// (best effort) if the host cannot provide one. Keep the returned value alive
/// for as long as the virtual display should exist.
pub(crate) fn activate(value: &str, privacy: bool) -> anyhow::Result<Option<ActiveVirtualDisplay>> {
    let request =
        parse_request(value).map_err(|message| anyhow!("--virtual-display: {message}"))?;
    match ActiveVirtualDisplay::start(request, privacy) {
        Ok(active) => Ok(Some(active)),
        Err(error) => {
            warn!("virtual display unavailable: {error:#}");
            Ok(None)
        }
    }
}

/// Turns the physical monitor off (`on = false`) or on (`on = true`) by
/// broadcasting `WM_SYSCOMMAND`/`SC_MONITORPOWER`. A no-op off Windows.
fn set_physical_monitor_power(on: bool) {
    #[cfg(windows)]
    windows_impl::set_physical_monitor_power(on);
    #[cfg(not(windows))]
    {
        let _ = on;
        warn!("privacy-mode physical-monitor blanking is only available on Windows");
    }
}

#[cfg(windows)]
mod windows_impl {
    #![allow(unsafe_code, reason = "Win32 SendMessage for monitor power control")]

    use windows::Win32::Foundation::{LPARAM, WPARAM};
    use windows::Win32::UI::WindowsAndMessaging::{
        HWND_BROADCAST, SC_MONITORPOWER, SendMessageW, WM_SYSCOMMAND,
    };

    pub(super) fn set_physical_monitor_power(on: bool) {
        // SC_MONITORPOWER: lParam 2 powers the monitor off, -1 powers it on.
        let power_state: isize = if on { -1 } else { 2 };
        // SAFETY: HWND_BROADCAST, WM_SYSCOMMAND and SC_MONITORPOWER are valid
        // system constants; SendMessageW takes no pointers here.
        let _ = unsafe {
            SendMessageW(
                HWND_BROADCAST,
                WM_SYSCOMMAND,
                Some(WPARAM(SC_MONITORPOWER as usize)),
                Some(LPARAM(power_state)),
            )
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_resolution_with_and_without_refresh() {
        let parsed = parse_request("1920x1080").unwrap_or_else(|_| unreachable!());
        assert_eq!(
            (
                parsed.mode().width(),
                parsed.mode().height(),
                parsed.mode().refresh_hz()
            ),
            (1920, 1080, DEFAULT_REFRESH_HZ)
        );

        let parsed = parse_request("2560x1440@120").unwrap_or_else(|_| unreachable!());
        assert_eq!(
            (
                parsed.mode().width(),
                parsed.mode().height(),
                parsed.mode().refresh_hz()
            ),
            (2560, 1440, 120)
        );

        // Case-insensitive separator and surrounding whitespace.
        let parsed = parse_request(" 3840X2160 @ 60 ").unwrap_or_else(|_| unreachable!());
        assert_eq!(
            (parsed.mode().width(), parsed.mode().height()),
            (3840, 2160)
        );
    }

    #[test]
    fn rejects_malformed_or_out_of_range() {
        assert!(parse_request("1920").is_err());
        assert!(parse_request("1920x").is_err());
        assert!(parse_request("axb").is_err());
        assert!(parse_request("1920x1080@xx").is_err());
        assert!(parse_request("320x240").is_err()); // below the driver's minimum
        assert!(parse_request("1920x1080@0").is_err());
    }
}
