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
pub mod rotate;

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
        Ok(Box::new(dxgi::DxgiCapturer::open(index)?))
    }
    #[cfg(not(windows))]
    {
        let _ = index;
        Err(CaptureError::Unsupported)
    }
}
