//! X11 `GetImage` capture through `x11rb` (pure Rust, no `libX11`).
//!
//! Model: Sunshine `src/platform/linux/x11grab.cpp`, `x11_attr_t::snapshot`
//! (`XGetImage(display, root, x, y, w, h, AllPlanes, ZPixmap)`) and its RandR monitor
//! lookup. Like GDI on Windows, X11 has no change notification, so the root window is
//! polled at most every [`crate::POLL_INTERVAL`] and identical frames are dropped. The
//! cursor is not part of `GetImage` output; the client renders its own pointer.

use std::time::{Duration, Instant};

use x11rb::connection::Connection;
use x11rb::protocol::randr::{self, ConnectionExt as _};
use x11rb::protocol::xproto::{ConnectionExt as _, ImageFormat, ImageOrder, Window};
use x11rb::rust_connection::RustConnection;

use crate::convert::{PixelLayout, rows_to_bgra};
use crate::{CaptureError, Capturer, DisplayBounds, Frame, PollAction, PollPacer};

/// Root-window capturer for one RandR monitor.
pub struct X11Capturer {
    connection: RustConnection,
    root: Window,
    bounds: DisplayBounds,
    layout: PixelLayout,
    pacer: PollPacer,
    last_frame: Vec<u8>,
}

impl std::fmt::Debug for X11Capturer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("X11Capturer")
            .field("bounds", &self.bounds)
            .field("layout", &self.layout)
            .finish_non_exhaustive()
    }
}

fn os_error(context: &str, error: impl std::fmt::Display) -> CaptureError {
    CaptureError::Os(format!("X11 {context}: {error}"))
}

impl X11Capturer {
    /// Connects to `$DISPLAY` and selects RandR monitor `index` (`0` is the primary one;
    /// without RandR 1.5 the whole screen is monitor `0`).
    ///
    /// # Errors
    ///
    /// Returns [`CaptureError::DisplayNotFound`] when `index` does not exist and
    /// [`CaptureError::Os`] when the server is unreachable or its root visual is not a
    /// 32-bit `TrueColor` layout this crate can convert.
    pub fn open(index: u32) -> Result<Self, CaptureError> {
        let (connection, screen_number) =
            x11rb::connect(None).map_err(|error| os_error("connect", error))?;
        let setup = connection.setup();
        let screen = setup
            .roots
            .get(screen_number)
            .ok_or_else(|| os_error("setup", "screen missing from the setup"))?;
        let format = setup
            .pixmap_formats
            .iter()
            .find(|format| format.depth == screen.root_depth)
            .ok_or_else(|| os_error("setup", "root depth has no pixmap format"))?;
        if format.bits_per_pixel != 32 {
            return Err(os_error(
                "visual",
                format!(
                    "root depth {} uses {} bits per pixel; only 32 is supported",
                    screen.root_depth, format.bits_per_pixel
                ),
            ));
        }
        let visual = screen
            .allowed_depths
            .iter()
            .flat_map(|depth| depth.visuals.iter())
            .find(|visual| visual.visual_id == screen.root_visual)
            .ok_or_else(|| os_error("visual", "root visual not found"))?;
        let layout = PixelLayout::from_x11_masks(
            visual.red_mask,
            visual.blue_mask,
            setup.image_byte_order == ImageOrder::LSB_FIRST,
        )
        .ok_or_else(|| {
            os_error(
                "visual",
                format!(
                    "unsupported channel masks r={:#x} g={:#x} b={:#x}",
                    visual.red_mask, visual.green_mask, visual.blue_mask
                ),
            )
        })?;

        let root = screen.root;
        let bounds = monitor_bounds(&connection, root, screen, index)?;
        Ok(Self {
            connection,
            root,
            bounds,
            layout,
            pacer: PollPacer::new(),
            last_frame: Vec::new(),
        })
    }

    /// Pixel layout of the server's root visual.
    #[must_use]
    pub fn layout(&self) -> PixelLayout {
        self.layout
    }

    fn capture_once(&mut self) -> Result<Option<Frame>, CaptureError> {
        let x = i16::try_from(self.bounds.x).map_err(|_| CaptureError::AccessLost)?;
        let y = i16::try_from(self.bounds.y).map_err(|_| CaptureError::AccessLost)?;
        let width = u16::try_from(self.bounds.width).map_err(|_| CaptureError::AccessLost)?;
        let height = u16::try_from(self.bounds.height).map_err(|_| CaptureError::AccessLost)?;
        let reply = self
            .connection
            .get_image(ImageFormat::Z_PIXMAP, self.root, x, y, width, height, !0)
            .map_err(|error| os_error("GetImage request", error))?
            .reply()
            // `BadMatch` here means the screen geometry changed under us.
            .map_err(|_| CaptureError::AccessLost)?;
        let stride = usize::from(width) * 4;
        let bgra = rows_to_bgra(
            &reply.data,
            usize::from(width),
            usize::from(height),
            stride,
            self.layout,
        )
        .ok_or(CaptureError::AccessLost)?;
        if bgra == self.last_frame {
            return Ok(None);
        }
        self.last_frame.clone_from(&bgra);
        Ok(Some(Frame {
            width: self.bounds.width,
            height: self.bounds.height,
            bgra,
            captured_at: Instant::now(),
        }))
    }
}

/// Bounds of RandR monitor `index`, or the whole screen when the server has no RandR 1.5.
fn monitor_bounds(
    connection: &RustConnection,
    root: Window,
    screen: &x11rb::protocol::xproto::Screen,
    index: u32,
) -> Result<DisplayBounds, CaptureError> {
    let whole_screen = DisplayBounds {
        x: 0,
        y: 0,
        width: u32::from(screen.width_in_pixels),
        height: u32::from(screen.height_in_pixels),
    };
    let randr_present = connection
        .extension_information(randr::X11_EXTENSION_NAME)
        .map_err(|error| os_error("QueryExtension", error))?
        .is_some();
    if !randr_present {
        return if index == 0 {
            Ok(whole_screen)
        } else {
            Err(CaptureError::DisplayNotFound(index))
        };
    }
    let version = connection
        .randr_query_version(1, 5)
        .map_err(|error| os_error("RandR QueryVersion", error))?
        .reply()
        .map_err(|error| os_error("RandR QueryVersion", error))?;
    if (version.major_version, version.minor_version) < (1, 5) {
        return if index == 0 {
            Ok(whole_screen)
        } else {
            Err(CaptureError::DisplayNotFound(index))
        };
    }
    let monitors = connection
        .randr_get_monitors(root, true)
        .map_err(|error| os_error("RandR GetMonitors", error))?
        .reply()
        .map_err(|error| os_error("RandR GetMonitors", error))?;
    if monitors.monitors.is_empty() {
        return if index == 0 {
            Ok(whole_screen)
        } else {
            Err(CaptureError::DisplayNotFound(index))
        };
    }
    // Primary monitor first, then the server's order, like `EnumDisplayDevicesW` on Windows.
    let mut ordered: Vec<&randr::MonitorInfo> = monitors.monitors.iter().collect();
    ordered.sort_by_key(|monitor| !monitor.primary);
    let monitor = ordered
        .get(usize::try_from(index).map_err(|_| CaptureError::DisplayNotFound(index))?)
        .ok_or(CaptureError::DisplayNotFound(index))?;
    if monitor.width == 0 || monitor.height == 0 {
        return Err(CaptureError::DisplayNotFound(index));
    }
    Ok(DisplayBounds {
        x: i32::from(monitor.x),
        y: i32::from(monitor.y),
        width: u32::from(monitor.width),
        height: u32::from(monitor.height),
    })
}

impl Capturer for X11Capturer {
    fn next_frame(&mut self, timeout: Duration) -> Result<Option<Frame>, CaptureError> {
        let deadline = Instant::now() + timeout;
        let mut polled = false;
        loop {
            let now = Instant::now();
            match self.pacer.plan(now, deadline, polled) {
                PollAction::Capture => {
                    self.pacer.mark_polled(now);
                    polled = true;
                    if let Some(frame) = self.capture_once()? {
                        return Ok(Some(frame));
                    }
                }
                PollAction::Wait(wait) => std::thread::sleep(wait),
                PollAction::Timeout => return Ok(None),
            }
        }
    }

    fn size(&self) -> (u32, u32) {
        (self.bounds.width, self.bounds.height)
    }

    fn bounds(&self) -> DisplayBounds {
        self.bounds
    }
}
