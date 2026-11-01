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

#![allow(
    unsafe_code,
    reason = "Win32 GDI screen capture requires FFI calls to gdi32/user32"
)]

use std::mem::size_of;
use std::ptr::null_mut;
use std::time::{Duration, Instant};

use windows::Win32::Graphics::Gdi::{
    BI_RGB, BITMAPINFO, BITMAPINFOHEADER, BitBlt, CAPTUREBLT, CreateCompatibleBitmap,
    CreateCompatibleDC, CreateDCW, DEVMODEW, DIB_RGB_COLORS, DISPLAY_DEVICE_ATTACHED_TO_DESKTOP,
    DISPLAY_DEVICE_STATE_FLAGS, DISPLAY_DEVICEW, DeleteDC, DeleteObject, ENUM_CURRENT_SETTINGS,
    ENUM_DISPLAY_SETTINGS_FLAGS, EnumDisplayDevicesW, EnumDisplaySettingsExW, GetDIBits, HBITMAP,
    HDC, HGDIOBJ, RGBQUAD, SRCCOPY, SelectObject,
};
use windows::core::PCWSTR;

use crate::{CaptureError, Capturer, DisplayBounds, Frame};

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
        })
    }
}

impl Capturer for GdiCapturer {
    fn next_frame(&mut self, _timeout: Duration) -> Result<Option<Frame>, CaptureError> {
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

        // SAFETY: `bgra` is allocated with `byte_len` bytes matching `bmiHeader`, and
        // `self.mem_dc`/`self.bitmap` are valid GDI handles.
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

    fn size(&self) -> (u32, u32) {
        (self.bounds.width, self.bounds.height)
    }

    fn bounds(&self) -> DisplayBounds {
        self.bounds
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

fn query_monitor(target_index: u32) -> Result<([u16; 32], DisplayBounds), CaptureError> {
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
        if attached_seen != target_index {
            attached_seen += 1;
            continue;
        }

        #[allow(clippy::cast_possible_truncation)]
        let dm_size = size_of::<DEVMODEW>() as u16;
        let mut dm = DEVMODEW {
            dmSize: dm_size,
            ..DEVMODEW::default()
        };
        // SAFETY: `dd.DeviceName` is a NUL-terminated UTF-16 string and `dm.dmSize` is initialized.
        let ok = unsafe {
            EnumDisplaySettingsExW(
                PCWSTR(dd.DeviceName.as_ptr()),
                ENUM_CURRENT_SETTINGS,
                &raw mut dm,
                ENUM_DISPLAY_SETTINGS_FLAGS(0),
            )
        };
        if !ok.as_bool() || dm.dmPelsWidth == 0 || dm.dmPelsHeight == 0 {
            return Err(CaptureError::DisplayNotFound(target_index));
        }
        // SAFETY: `Anonymous1.Anonymous2.dmPosition` is valid for display devices returned by
        // `EnumDisplaySettingsExW`.
        let pos = unsafe { dm.Anonymous1.Anonymous2.dmPosition };
        let _ = null_mut::<u8>();
        return Ok((
            dd.DeviceName,
            DisplayBounds {
                x: pos.x,
                y: pos.y,
                width: dm.dmPelsWidth,
                height: dm.dmPelsHeight,
            },
        ));
    }

    Err(CaptureError::DisplayNotFound(target_index))
}
