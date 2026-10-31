//! Screen capture for OmegaDesk.
//!
//! Currently implements DXGI Desktop Duplication on Windows, copying each
//! captured frame to CPU memory in tightly packed BGRA. The zero-copy GPU path
//! (passing the D3D11 texture directly to the hardware encoder) will be added
//! alongside the GPU texture pipeline.

use std::time::{Duration, Instant};

#[cfg(windows)]
mod dxgi;

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

/// A captured video frame in 8-bit-per-channel BGRA.
#[derive(Debug, Clone)]
pub struct Frame {
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels.
    pub height: u32,
    /// Tightly packed BGRA pixels, row by row (`width * 4` bytes per row).
    pub bgra: Vec<u8>,
    /// Monotonic instant when the frame was acquired.
    pub captured_at: Instant,
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
    /// Returns `None` if the screen did not change before `timeout` elapsed.
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
