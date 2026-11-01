//! GDI `BitBlt` screen capture fallback on Windows.
//!
//! Ported from RustDesk's `CapturerGDI` (`libs/scrap/src/dxgi/gdi.rs`, AGPL-3.0):
//! - Enumerates active monitors with `EnumDisplayDevicesW` and `EnumDisplaySettingsExW`.
//! - Creates a display device context (`CreateDCW`), a compatible memory DC
//!   (`CreateCompatibleDC`), and a compatible bitmap (`CreateCompatibleBitmap`).
//! - Copies desktop pixels via `BitBlt(..., SRCCOPY | CAPTUREBLT)` and extracts
//!   top-down 32-bit BGRA scanlines via `GetDIBits` (`biHeight = -height`).
//! - Used automatically by [`super::open_display`] when DXGI Desktop Duplication
//!   is unavailable (e.g., nested RDP sessions, Hyper-V basic video, or headless GPUs).
//!
//! Differences from RustDesk: GDI has no change notification, so a static
//! desktop is polled at most every [`crate::POLL_INTERVAL`] (paced across calls by
//! [`crate::PollPacer`]) within the timeout given by the caller instead of spinning
//! on `BitBlt`, and the bitmap is deselected from the memory DC before
//! `GetDIBits`, as the Win32 contract requires.

#![allow(
    unsafe_code,
    reason = "Win32 GDI screen capture requires FFI calls to gdi32/user32"
)]

use std::mem::size_of;
use std::time::{Duration, Instant};

use windows::Win32::Foundation::POINT;
use windows::Win32::Graphics::Gdi::{
    BI_RGB, BITMAPINFO, BITMAPINFOHEADER, BitBlt, CAPTUREBLT, CreateCompatibleBitmap,
    CreateCompatibleDC, CreateDCW, DEVMODEW, DIB_RGB_COLORS, DISPLAY_DEVICE_ATTACHED_TO_DESKTOP,
    DISPLAY_DEVICE_STATE_FLAGS, DISPLAY_DEVICEW, DeleteDC, DeleteObject, ENUM_CURRENT_SETTINGS,
    ENUM_DISPLAY_SETTINGS_FLAGS, EnumDisplayDevicesW, EnumDisplaySettingsExW, GetDIBits, HBITMAP,
    HDC, HGDIOBJ, MONITOR_DEFAULTTONULL, MonitorFromPoint, RGBQUAD, SRCCOPY, SelectObject,
};
use windows::core::PCWSTR;

use crate::{
    CaptureError, Capturer, DisplayBounds, DisplayInfo, Frame, PollAction, PollPacer,
    dpi_scale_percent, utf16_device_name,
};

const BYTES_PER_PIXEL: usize = 4;

/// Windows GDI `BitBlt` capturer implementing [`Capturer`], modeled after
/// RustDesk's `CapturerGDI` (`libs/scrap/src/dxgi/gdi.rs`).
pub struct GdiCapturer {
    screen_dc: HDC,
    mem_dc: HDC,
    bitmap: HBITMAP,
    old_obj: HGDIOBJ,
    bounds: DisplayBounds,
    last_frame: Vec<u8>,
    pacer: PollPacer,
}

// SAFETY: Each `GdiCapturer` owns its private GDI device contexts (`screen_dc`, `mem_dc`)
// and `bitmap` handle and is accessed sequentially by the single capture worker thread.
unsafe impl Send for GdiCapturer {}

impl GdiCapturer {
    /// Opens a GDI `BitBlt` capturer for monitor `index` (`0` is the first attached monitor).
    ///
    /// # Errors
    ///
    /// Returns [`CaptureError::DisplayNotFound`] if `index` does not exist, or
    /// [`CaptureError::Os`] if GDI resource creation fails.
    pub fn open(index: u32) -> Result<Self, CaptureError> {
        let (device_name, bounds) = query_monitor(index)?;
        let width_i32 =
            i32::try_from(bounds.width).map_err(|_| CaptureError::Os("invalid width".into()))?;
        let height_i32 =
            i32::try_from(bounds.height).map_err(|_| CaptureError::Os("invalid height".into()))?;

        // SAFETY: `device_name` is a NUL-terminated UTF-16 buffer returned by `EnumDisplayDevicesW`.
        let screen_dc = unsafe {
            CreateDCW(
                PCWSTR(device_name.as_ptr()),
                PCWSTR::null(),
                PCWSTR::null(),
                None,
            )
        };
        if screen_dc.is_invalid() {
            return Err(CaptureError::Os("CreateDCW failed for display".into()));
        }

        // SAFETY: `screen_dc` is a valid device context created above.
        let mem_dc = unsafe { CreateCompatibleDC(Some(screen_dc)) };
        if mem_dc.is_invalid() {
            // SAFETY: `screen_dc` is owned here and must be released on error.
            unsafe {
                let _ = DeleteDC(screen_dc);
            }
            return Err(CaptureError::Os("CreateCompatibleDC failed".into()));
        }

        // SAFETY: `screen_dc` is valid and `width_i32`/`height_i32` are positive monitor dimensions.
        let bitmap = unsafe { CreateCompatibleBitmap(screen_dc, width_i32, height_i32) };
        if bitmap.is_invalid() {
            // SAFETY: Both `mem_dc` and `screen_dc` are valid handles owned by this function.
            unsafe {
                let _ = DeleteDC(mem_dc);
            }
            // SAFETY: `screen_dc` is valid and owned by this function.
            unsafe {
                let _ = DeleteDC(screen_dc);
            }
            return Err(CaptureError::Os("CreateCompatibleBitmap failed".into()));
        }

        // SAFETY: `mem_dc` and `bitmap` are valid GDI handles created above.
        let old_obj = unsafe { SelectObject(mem_dc, bitmap.into()) };
        if old_obj.is_invalid() {
            // SAFETY: Release `bitmap` on failure.
            unsafe {
                let _ = DeleteObject(bitmap.into());
            }
            // SAFETY: Release `mem_dc` on failure.
            unsafe {
                let _ = DeleteDC(mem_dc);
            }
            // SAFETY: Release `screen_dc` on failure.
            unsafe {
                let _ = DeleteDC(screen_dc);
            }
            return Err(CaptureError::Os("SelectObject failed".into()));
        }

        Ok(Self {
            screen_dc,
            mem_dc,
            bitmap,
            old_obj,
            bounds,
            last_frame: Vec::new(),
            pacer: PollPacer::new(),
        })
    }
}

impl Capturer for GdiCapturer {
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

impl GdiCapturer {
    /// Copies the desktop once and returns `Ok(None)` when it is identical to
    /// the previous copy.
    fn capture_once(&mut self) -> Result<Option<Frame>, CaptureError> {
        let width_i32 =
            i32::try_from(self.bounds.width).map_err(|_| CaptureError::Os("bad width".into()))?;
        let height_i32 =
            i32::try_from(self.bounds.height).map_err(|_| CaptureError::Os("bad height".into()))?;

        // SAFETY: `mem_dc` and `screen_dc` are valid GDI contexts with a selected bitmap of
        // size `(width_i32, height_i32)`.
        let blt_res = unsafe {
            BitBlt(
                self.mem_dc,
                0,
                0,
                width_i32,
                height_i32,
                Some(self.screen_dc),
                0,
                0,
                SRCCOPY | CAPTUREBLT,
            )
        };
        if blt_res.is_err() {
            return Err(CaptureError::AccessLost);
        }

        let byte_len =
            (self.bounds.width as usize) * (self.bounds.height as usize) * BYTES_PER_PIXEL;
        let mut bgra = vec![0u8; byte_len];

        #[allow(clippy::cast_possible_truncation)]
        let header_size = size_of::<BITMAPINFOHEADER>() as u32;
        #[allow(clippy::cast_possible_truncation)]
        let image_size = byte_len as u32;

        let mut bmi = BITMAPINFO {
            bmiHeader: BITMAPINFOHEADER {
                biSize: header_size,
                biWidth: width_i32,
                // Negative height requests a top-down DIB so scanlines are in natural order.
                biHeight: -height_i32,
                biPlanes: 1,
                biBitCount: 32,
                biCompression: BI_RGB.0,
                biSizeImage: image_size,
                biXPelsPerMeter: 0,
                biYPelsPerMeter: 0,
                biClrUsed: 0,
                biClrImportant: 0,
            },
            bmiColors: [RGBQUAD::default()],
        };

        // `GetDIBits` requires that the bitmap is not selected into a device
        // context, so restore the original object around the call and select
        // the capture bitmap back for the next `BitBlt`.
        // SAFETY: `mem_dc` and `old_obj` are the handles paired in `open`.
        unsafe {
            let _ = SelectObject(self.mem_dc, self.old_obj);
        }
        // SAFETY: `bgra` is allocated with `byte_len` bytes matching `bmiHeader`, and
        // `self.mem_dc`/`self.bitmap` are valid GDI handles with the bitmap unselected.
        let lines = unsafe {
            GetDIBits(
                self.mem_dc,
                self.bitmap,
                0,
                self.bounds.height,
                Some(bgra.as_mut_ptr().cast()),
                &raw mut bmi,
                DIB_RGB_COLORS,
            )
        };
        // SAFETY: `mem_dc` and `bitmap` are valid handles owned by `self`.
        let reselected = unsafe { SelectObject(self.mem_dc, self.bitmap.into()) };
        if reselected.is_invalid() {
            return Err(CaptureError::Os(
                "SelectObject failed after GetDIBits".into(),
            ));
        }
        if lines == 0 {
            return Err(CaptureError::Os("GetDIBits returned 0 scanlines".into()));
        }

        if bgra == self.last_frame {
            return Ok(None);
        }
        self.last_frame.clone_from(&bgra);

        Ok(Some(Frame {
            width: self.bounds.width,
            height: self.bounds.height,
            bgra,
            captured_at: Instant::now(),
            gpu_texture: None,
        }))
    }
}

impl Drop for GdiCapturer {
    fn drop(&mut self) {
        // SAFETY: Restore the original GDI object before deleting `self.bitmap`.
        unsafe {
            let _ = SelectObject(self.mem_dc, self.old_obj);
        }
        // SAFETY: `self.bitmap` was created by `CreateCompatibleBitmap` and is no longer selected.
        unsafe {
            let _ = DeleteObject(self.bitmap.into());
        }
        // SAFETY: `self.mem_dc` was created by `CreateCompatibleDC`.
        unsafe {
            let _ = DeleteDC(self.mem_dc);
        }
        // SAFETY: `self.screen_dc` was created by `CreateDCW`.
        unsafe {
            let _ = DeleteDC(self.screen_dc);
        }
    }
}

/// Walks the display devices attached to the desktop (`EnumDisplayDevicesW`)
/// in enumeration order, calling `visit(attached_index, device)` for each and
/// stopping early when it returns `false`.
fn for_each_attached_device(mut visit: impl FnMut(u32, &DISPLAY_DEVICEW) -> bool) {
    let mut attached_seen = 0u32;
    let mut dev_num = 0u32;
    loop {
        #[allow(clippy::cast_possible_truncation)]
        let cb = size_of::<DISPLAY_DEVICEW>() as u32;
        let mut dd = DISPLAY_DEVICEW {
            cb,
            ..DISPLAY_DEVICEW::default()
        };
        // SAFETY: `dd` has `cb` initialized to `size_of::<DISPLAY_DEVICEW>()`.
        let found = unsafe { EnumDisplayDevicesW(PCWSTR::null(), dev_num, &raw mut dd, 0) };
        if !found.as_bool() {
            break;
        }
        dev_num += 1;
        if (dd.StateFlags & DISPLAY_DEVICE_ATTACHED_TO_DESKTOP) == DISPLAY_DEVICE_STATE_FLAGS(0) {
            continue;
        }
        let index = attached_seen;
        attached_seen += 1;
        if !visit(index, &dd) {
            break;
        }
    }
}

/// Current mode (`ENUM_CURRENT_SETTINGS`) of the device, as upright desktop
/// bounds, or `None` if the device reports no usable mode.
fn current_bounds(device_name: &[u16; 32]) -> Option<DisplayBounds> {
    #[allow(clippy::cast_possible_truncation)]
    let dm_size = size_of::<DEVMODEW>() as u16;
    let mut dm = DEVMODEW {
        dmSize: dm_size,
        ..DEVMODEW::default()
    };
    // SAFETY: `device_name` is a NUL-terminated UTF-16 string and `dm.dmSize` is initialized.
    let ok = unsafe {
        EnumDisplaySettingsExW(
            PCWSTR(device_name.as_ptr()),
            ENUM_CURRENT_SETTINGS,
            &raw mut dm,
            ENUM_DISPLAY_SETTINGS_FLAGS(0),
        )
    };
    if !ok.as_bool() || dm.dmPelsWidth == 0 || dm.dmPelsHeight == 0 {
        return None;
    }
    // SAFETY: `Anonymous1.Anonymous2.dmPosition` is valid for display devices returned by
    // `EnumDisplaySettingsExW`.
    let pos = unsafe { dm.Anonymous1.Anonymous2.dmPosition };
    Some(DisplayBounds {
        x: pos.x,
        y: pos.y,
        width: dm.dmPelsWidth,
        height: dm.dmPelsHeight,
    })
}

fn query_monitor(target_index: u32) -> Result<([u16; 32], DisplayBounds), CaptureError> {
    let mut result = Err(CaptureError::DisplayNotFound(target_index));
    for_each_attached_device(|index, dd| {
        if index != target_index {
            return true;
        }
        if let Some(bounds) = current_bounds(&dd.DeviceName) {
            result = Ok((dd.DeviceName, bounds));
        }
        false
    });
    result
}

/// Enumerates the monitors attached to the desktop with the same indexing
/// [`GdiCapturer::open`] uses (RustDesk `libs/scrap/src/dxgi/gdi.rs` `Displays`).
/// Devices without a current mode are skipped but still consume their index, so
/// the indexes stay aligned with `open`.
pub(crate) fn list_monitors() -> Result<Vec<DisplayInfo>, CaptureError> {
    let mut displays = Vec::new();
    for_each_attached_device(|index, dd| {
        if let Some(bounds) = current_bounds(&dd.DeviceName) {
            let point = POINT {
                x: bounds.x,
                y: bounds.y,
            };
            // SAFETY: plain value arguments; a point outside every monitor yields a null handle.
            let monitor = unsafe { MonitorFromPoint(point, MONITOR_DEFAULTTONULL) };
            displays.push(DisplayInfo {
                index,
                name: utf16_device_name(&dd.DeviceName),
                bounds,
                scale_percent: dpi_scale_percent(monitor),
                primary: bounds.x == 0 && bounds.y == 0,
            });
        }
        true
    });
    if displays.is_empty() {
        return Err(CaptureError::Os(
            "EnumDisplayDevicesW found no monitor attached to the desktop".into(),
        ));
    }
    Ok(displays)
}
