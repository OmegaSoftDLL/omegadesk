//! Linux screen capture.
//!
//! Two backends, tried in order by [`open_display`]:
//!
//! 1. [`pipewire`]: the `org.freedesktop.portal.ScreenCast` portal negotiates a PipeWire
//!    stream of the monitor the user picks, which works on Wayland and X11 desktops
//!    (GNOME, KDE, wlroots) and is the only way to capture a Wayland session. Model:
//!    Sunshine `src/platform/linux/portalgrab.cpp` (portal session) and `pipewire.cpp`
//!    (stream negotiation and buffer handling).
//! 2. [`x11`]: plain `GetImage` of the root window through `x11rb`, for X11 sessions
//!    without a portal, nested servers and headless CI under `Xvfb`. Model: Sunshine
//!    `src/platform/linux/x11grab.cpp` (`x11_attr_t::snapshot`, RandR monitor lookup).
//!
//! `OMEGADESK_CAPTURE_BACKEND=portal|x11` forces one backend; anything else (or unset)
//! means automatic.

pub mod pipewire;
pub mod x11;

use tracing::{debug, info, warn};

use crate::{CaptureError, Capturer};

/// Backend selection read from `OMEGADESK_CAPTURE_BACKEND`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendChoice {
    /// Portal first, X11 fallback.
    Auto,
    /// Only the `PipeWire` portal.
    Portal,
    /// Only X11 `GetImage`.
    X11,
}

impl BackendChoice {
    /// Parses the environment variable value (case-insensitive).
    #[must_use]
    pub fn parse(value: Option<&str>) -> Self {
        match value.map(str::trim).map(str::to_ascii_lowercase).as_deref() {
            Some("portal" | "pipewire") => Self::Portal,
            Some("x11") => Self::X11,
            _ => Self::Auto,
        }
    }

    /// Reads `OMEGADESK_CAPTURE_BACKEND`.
    #[must_use]
    pub fn from_env() -> Self {
        Self::parse(std::env::var("OMEGADESK_CAPTURE_BACKEND").ok().as_deref())
    }
}

/// Opens monitor `index` with the first backend that works.
///
/// # Errors
///
/// Returns the combined failure of every backend tried, or
/// [`CaptureError::DisplayNotFound`] when all of them agree the monitor does not exist.
pub fn open_display(index: u32) -> Result<Box<dyn Capturer>, CaptureError> {
    open_display_with(index, BackendChoice::from_env())
}

/// [`open_display`] with an explicit backend choice.
///
/// # Errors
///
/// See [`open_display`].
pub fn open_display_with(
    index: u32,
    choice: BackendChoice,
) -> Result<Box<dyn Capturer>, CaptureError> {
    let portal_error = match choice {
        BackendChoice::X11 => None,
        BackendChoice::Auto | BackendChoice::Portal => {
            match pipewire::PipeWireCapturer::open(index) {
                Ok(capturer) => {
                    info!("screen capture backend: PipeWire portal");
                    return Ok(Box::new(capturer));
                }
                Err(error) if choice == BackendChoice::Portal => return Err(error),
                Err(error) => {
                    debug!("PipeWire portal unavailable ({error}); trying X11");
                    Some(error)
                }
            }
        }
    };
    match x11::X11Capturer::open(index) {
        Ok(capturer) => {
            info!("screen capture backend: X11 GetImage");
            Ok(Box::new(capturer))
        }
        Err(x11_error) => {
            warn!("X11 capture unavailable: {x11_error}");
            Err(match portal_error {
                Some(portal_error) => {
                    crate::resolve_fallback_error(index, &portal_error, &x11_error)
                }
                None => x11_error,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::BackendChoice;

    #[test]
    fn backend_choice_parses_the_environment_value() {
        assert_eq!(BackendChoice::parse(None), BackendChoice::Auto);
        assert_eq!(BackendChoice::parse(Some("auto")), BackendChoice::Auto);
        assert_eq!(BackendChoice::parse(Some(" X11 ")), BackendChoice::X11);
        assert_eq!(BackendChoice::parse(Some("Portal")), BackendChoice::Portal);
        assert_eq!(
            BackendChoice::parse(Some("pipewire")),
            BackendChoice::Portal
        );
        assert_eq!(BackendChoice::parse(Some("kms")), BackendChoice::Auto);
    }
}
