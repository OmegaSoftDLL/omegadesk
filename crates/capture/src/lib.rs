//! Screen capture for OmegaDesk.
//!
//! Implements DXGI Desktop Duplication on Windows, including hardware cursor
//! compositing (`GetFramePointerShape`), rotated monitor support (`90°`, `180°`,
//! `270°`), and a GPU-resident D3D11 texture path (`GpuTexture`) so hardware
//! encoders can convert and encode directly on the GPU without copying full
//! frames through CPU memory.

use std::time::{Duration, Instant};

pub mod cursor;
#[cfg(windows)]
mod dxgi;
#[cfg(windows)]
pub mod gdi;
pub mod rotate;
pub mod service_desktop;
pub mod virtual_display;

/// Screen capture errors.
#[derive(Debug, thiserror::Error)]
pub enum CaptureError {
    /// No capture backend is implemented for this operating system yet.
    #[error("screen capture is not yet supported on this operating system")]
    Unsupported,
    /// The requested display index does not exist.
    #[error("display {0} not found")]
    DisplayNotFound(u32),
    /// Desktop duplication was lost (resolution change, login screen, UAC…).
    /// Recreating the capturer recovers from this state.
    #[error("display access lost; reopen the capturer")]
    AccessLost,
    /// Operating system or graphics API error.
    #[error("operating system error: {0}")]
    Os(String),
}

/// GPU-resident Direct3D 11 texture for zero-copy hardware video encoding on Windows.
#[cfg(windows)]
#[derive(Debug, Clone)]
pub struct GpuTexture {
    /// Direct3D 11 device that owns [`Self::texture`].
    pub device: windows::Win32::Graphics::Direct3D11::ID3D11Device,
    /// Immediate context of [`Self::device`].
    pub context: windows::Win32::Graphics::Direct3D11::ID3D11DeviceContext,
    /// `DXGI_FORMAT_B8G8R8A8_UNORM` 2D texture in VRAM.
    pub texture: windows::Win32::Graphics::Direct3D11::ID3D11Texture2D,
}

#[cfg(windows)]
#[allow(
    unsafe_code,
    reason = "Send impl for multithread-protected D3D11 COM objects"
)]
// SAFETY: `DxgiCapturer` enables `ID3D11Multithread::SetMultithreadProtected(true)`
// on `device` at creation time, and `GpuTexture` is consumed sequentially on the
// dedicated capture/encode thread.
unsafe impl Send for GpuTexture {}

/// A captured video frame in 8-bit-per-channel BGRA, optionally backed by a
/// Direct3D 11 texture in VRAM on Windows.
#[derive(Debug, Clone)]
pub struct Frame {
    /// Width in pixels (upright desktop orientation).
    pub width: u32,
    /// Height in pixels (upright desktop orientation).
    pub height: u32,
    /// Tightly packed BGRA pixels, row by row (`width * 4` bytes per row).
    pub bgra: Vec<u8>,
    /// Monotonic instant when the frame was acquired.
    pub captured_at: Instant,
    /// Optional GPU-resident Direct3D 11 texture for zero-copy hardware encoding.
    #[cfg(windows)]
    pub gpu_texture: Option<GpuTexture>,
}

/// Position and size of a monitor in virtual desktop pixel coordinates.
/// Monitors positioned to the left of or above the primary monitor have
/// negative coordinates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DisplayBounds {
    /// Top-left x coordinate.
    pub x: i32,
    /// Top-left y coordinate.
    pub y: i32,
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels.
    pub height: u32,
}

/// Source of frames for a single monitor.
pub trait Capturer: Send {
    /// Waits up to `timeout` for the next frame.
    ///
    /// Returns `None` if the screen and cursor did not change before `timeout` elapsed.
    ///
    /// # Errors
    ///
    /// Returns [`CaptureError::AccessLost`] when the capturer must be reopened,
    /// or another operating system error.
    fn next_frame(&mut self, timeout: Duration) -> Result<Option<Frame>, CaptureError>;

    /// Width and height of the captured monitor in pixels.
    fn size(&self) -> (u32, u32);

    /// Position of the captured monitor within the virtual desktop so remote
    /// pointer events land on the right monitor.
    fn bounds(&self) -> DisplayBounds;

    /// Returns the underlying Direct3D 11 device on Windows so a hardware
    /// encoder can bind an `IMFDXGIDeviceManager` to the same GPU adapter.
    #[cfg(windows)]
    fn d3d11_device(&self) -> Option<&windows::Win32::Graphics::Direct3D11::ID3D11Device> {
        None
    }
}

/// Opens a capturer for monitor `index` (`0` is the primary monitor).
///
/// # Errors
///
/// Returns an error if the monitor does not exist or if the operating system
/// denies screen capture.
pub fn open_display(index: u32) -> Result<Box<dyn Capturer>, CaptureError> {
    #[cfg(windows)]
    {
        if !service_desktop::input_desktop_selected() {
            let _ = service_desktop::select_input_desktop();
        }
        // `DisplayNotFound` from DXGI only means that no DXGI output with that
        // index is attached to the desktop; GDI-only displays (basic display
        // adapter, nested RDP sessions, some virtual machines) still exist for
        // `EnumDisplayDevicesW`, so the fallback is tried for every DXGI error
        // (matching RustDesk `libs/scrap/src/dxgi/mod.rs` `CapturerGDI` fallback).
        match dxgi::DxgiCapturer::open(index) {
            Ok(capturer) => Ok(Box::new(capturer)),
            Err(dxgi_error) => match gdi::GdiCapturer::open(index) {
                Ok(capturer) => Ok(Box::new(capturer)),
                Err(CaptureError::DisplayNotFound(missing)) => {
                    Err(CaptureError::DisplayNotFound(missing))
                }
                Err(_gdi_error) => Err(dxgi_error),
            },
        }
    }
    #[cfg(not(windows))]
    {
        let _ = index;
        Err(CaptureError::Unsupported)
    }
}

/// Converts an IEEE 754 binary16 (`FP16`, used by `DXGI_FORMAT_R16G16B16A16_FLOAT`
/// HDR Desktop Duplication surfaces via `DuplicateOutput1`) into an `f32`.
#[must_use]
pub fn f16_to_f32(bits: u16) -> f32 {
    let sign = u32::from(bits >> 15) << 31;
    let exp = u32::from((bits >> 10) & 0x1F);
    let mant = u32::from(bits & 0x03FF);

    let f32_bits = if exp == 0 {
        if mant == 0 {
            sign
        } else {
            // Subnormal FP16 -> normalized FP32
            let mut m = mant;
            let mut e = 127u32 - 14;
            while (m & 0x0400) == 0 {
                m <<= 1;
                e -= 1;
            }
            m &= 0x03FF;
            sign | (e << 23) | (m << 13)
        }
    } else if exp == 0x1F {
        // Inf or NaN
        sign | 0x7F80_0000 | (mant << 13)
    } else {
        let e = exp + (127 - 15);
        sign | (e << 23) | (mant << 13)
    };
    f32::from_bits(f32_bits)
}

/// Tone-maps a Windows `DuplicateOutput1` scRGB linear `FP16` (`DXGI_FORMAT_R16G16B16A16_FLOAT`,
/// where `1.0` equals `80.0` nits) scanout buffer into tightly packed 8-bit sRGB `BGRA8` pixels
/// (`docs/plan.md` §2.3 line 56, modeled after `Sunshine` `src/platform/windows/display_base.cpp`).
#[must_use]
pub fn tone_map_hdr_fp16_to_bgra8(rgba_fp16_le: &[u8], sdr_white_nits: f32) -> Vec<u8> {
    let white_scale = (80.0 / sdr_white_nits.max(80.0)).clamp(0.1, 1.0);
    let pixel_count = rgba_fp16_le.len() / 8;
    let mut bgra = Vec::with_capacity(pixel_count * 4);

    for px in rgba_fp16_le.as_chunks::<8>().0 {
        let r_lin = f16_to_f32(u16::from_le_bytes([px[0], px[1]])).max(0.0) * white_scale;
        let g_lin = f16_to_f32(u16::from_le_bytes([px[2], px[3]])).max(0.0) * white_scale;
        let b_lin = f16_to_f32(u16::from_le_bytes([px[4], px[5]])).max(0.0) * white_scale;
        let a_lin = f16_to_f32(u16::from_le_bytes([px[6], px[7]])).clamp(0.0, 1.0);

        // Reinhard tone map followed by the exact sRGB transfer function
        // (IEC 61966-2-1: linear segment below 0.0031308, offset 1/2.4 power
        // curve above it), so dark pixels are not lifted by a plain gamma.
        let map_channel = |c: f32| -> u8 {
            let mapped = c / (1.0 + c);
            let srgb = linear_to_srgb(mapped).clamp(0.0, 1.0);
            #[allow(
                clippy::cast_possible_truncation,
                clippy::cast_sign_loss,
                reason = "srgb is clamped to [0.0, 1.0] before scaling by 255.0"
            )]
            {
                (srgb * 255.0 + 0.5) as u8
            }
        };

        #[allow(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "a_lin is clamped to [0.0, 1.0] before scaling by 255.0"
        )]
        let a_u8 = (a_lin * 255.0 + 0.5) as u8;

        bgra.push(map_channel(b_lin));
        bgra.push(map_channel(g_lin));
        bgra.push(map_channel(r_lin));
        bgra.push(a_u8);
    }

    bgra
}

/// Exact sRGB electro-optical transfer function inverse (IEC 61966-2-1):
/// `12.92 * c` for `c <= 0.0031308`, otherwise `1.055 * c^(1/2.4) - 0.055`.
#[must_use]
pub fn linear_to_srgb(linear: f32) -> f32 {
    let c = linear.max(0.0);
    if c <= 0.003_130_8 {
        12.92 * c
    } else {
        1.055 * c.powf(1.0 / 2.4) - 0.055
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn srgb_transfer_keeps_dark_pixels_dark() {
        // FP16 0x1400 = 2^-10 (about 0.00098 linear): the sRGB linear segment
        // encodes it as 3/255, where a 1/2.2 gamma would have produced 11/255.
        let mut raw = Vec::new();
        for _ in 0..3 {
            raw.extend_from_slice(&0x1400u16.to_le_bytes());
        }
        raw.extend_from_slice(&0x3C00u16.to_le_bytes());
        let bgra = tone_map_hdr_fp16_to_bgra8(&raw, 80.0);
        assert_eq!(&bgra[..3], &[3, 3, 3]);
        assert_eq!(linear_to_srgb(0.0), 0.0);
        assert!((linear_to_srgb(1.0) - 1.0).abs() < 1e-6);
        assert!((linear_to_srgb(0.5) - 0.735_357).abs() < 1e-5);
    }

    #[test]
    fn hdr_fp16_scrgb_tone_maps_to_bgra8() {
        // IEEE 754 FP16 constants: 1.0 = 0x3C00, 0.0 = 0x0000, 4.0 (320 nits HDR peak) = 0x4400
        let mut raw = Vec::new();
        raw.extend_from_slice(&0x4400u16.to_le_bytes()); // R = 4.0 (bright HDR red)
        raw.extend_from_slice(&0x3C00u16.to_le_bytes()); // G = 1.0 (SDR white 80 nits)
        raw.extend_from_slice(&0x0000u16.to_le_bytes()); // B = 0.0
        raw.extend_from_slice(&0x3C00u16.to_le_bytes()); // A = 1.0

        let bgra = tone_map_hdr_fp16_to_bgra8(&raw, 160.0);
        assert_eq!(bgra.len(), 4);
        assert_eq!(bgra[0], 0); // Blue = 0
        assert!(bgra[2] > bgra[1]); // Red channel brighter than Green channel
        assert_eq!(bgra[3], 255); // Alpha = 255
    }
}
