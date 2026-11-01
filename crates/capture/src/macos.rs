//! macOS screen capture through CoreGraphics (`CGDisplayCreateImage`).
//!
//! Model: Sunshine `src/platform/macos/display.mm` (`CGGetActiveDisplayList`,
//! `CGDisplayBounds`, capturing a display into a bitmap). `CGDisplayCreateImage` is
//! Apple-deprecated in favor of ScreenCaptureKit but is still the shortest dependency-light
//! path to a `BGRA` frame and works back to macOS 10.x; the frame it returns feeds the same
//! `omegadesk-codec` pipeline as every other backend. Like GDI and X11 it has no change
//! notification, so the display is polled at most every [`crate::POLL_INTERVAL`] and
//! identical frames are dropped.
//!
//! Capturing requires the Screen Recording permission (System Settings → Privacy). Without
//! it CoreGraphics returns a black or empty image; [`MacOsCapturer::open`] detects the empty
//! case and reports [`CaptureError::Os`] so the caller can surface the permission prompt.

#![allow(
    unsafe_code,
    reason = "CGGetActiveDisplayList is a raw-pointer C FFI call"
)]
#![allow(
    deprecated,
    reason = "CGDisplayCreateImage is the dependency-light capture path; a ScreenCaptureKit backend can replace it later without changing the Capturer contract"
)]

use std::time::{Duration, Instant};

use objc2_core_graphics::{
    CGDirectDisplayID, CGDisplayBounds, CGDisplayCreateImage, CGGetActiveDisplayList, CGImage,
    CGImageAlphaInfo, CGImageByteOrderInfo,
};

use crate::convert::{PixelLayout, rows_to_bgra};
use crate::{CaptureError, Capturer, DisplayBounds, Frame, PollAction, PollPacer};

/// Maximum displays queried from `CGGetActiveDisplayList`.
const MAX_DISPLAYS: u32 = 16;

/// CoreGraphics capturer for one active display.
#[derive(Debug)]
pub struct MacOsCapturer {
    display: CGDirectDisplayID,
    bounds: DisplayBounds,
    pacer: PollPacer,
    last_frame: Vec<u8>,
}

fn active_displays() -> Result<Vec<CGDirectDisplayID>, CaptureError> {
    let mut displays = vec![0u32; MAX_DISPLAYS as usize];
    let mut count: u32 = 0;
    // SAFETY: `displays` has `MAX_DISPLAYS` elements and `count` is a valid out-pointer;
    // CGGetActiveDisplayList writes at most `MAX_DISPLAYS` ids and the actual count.
    let error =
        unsafe { CGGetActiveDisplayList(MAX_DISPLAYS, displays.as_mut_ptr(), &raw mut count) };
    if error != objc2_core_graphics::CGError::Success {
        return Err(CaptureError::Os(format!(
            "CGGetActiveDisplayList failed: {error:?}"
        )));
    }
    displays.truncate(count as usize);
    Ok(displays)
}

/// In-memory byte order of a 32-bit CoreGraphics image, from its alpha and byte-order info.
fn layout_of(alpha: CGImageAlphaInfo, order: CGImageByteOrderInfo) -> PixelLayout {
    let alpha_first = matches!(
        alpha,
        CGImageAlphaInfo::PremultipliedFirst
            | CGImageAlphaInfo::First
            | CGImageAlphaInfo::NoneSkipFirst
    );
    let little = matches!(order, CGImageByteOrderInfo::Order32Little);
    // `First` = ARGB word, `Last` = RGBA word; little-endian reverses the bytes in memory.
    match (alpha_first, little) {
        (true, true) => PixelLayout::Bgrx,
        (true, false) => PixelLayout::Xrgb,
        (false, true) => PixelLayout::Xbgr,
        (false, false) => PixelLayout::Rgbx,
    }
}

impl MacOsCapturer {
    /// Opens active display `index` (`0` is the main display) and verifies one capture
    /// succeeds (so a missing Screen Recording permission is reported now, not per frame).
    ///
    /// # Errors
    ///
    /// Returns [`CaptureError::DisplayNotFound`] when `index` names no active display and
    /// [`CaptureError::Os`] when CoreGraphics fails or the capture is empty (no permission).
    pub fn open(index: u32) -> Result<Self, CaptureError> {
        let displays = active_displays()?;
        let display = *displays
            .get(usize::try_from(index).map_err(|_| CaptureError::DisplayNotFound(index))?)
            .ok_or(CaptureError::DisplayNotFound(index))?;
        let rect = CGDisplayBounds(display);
        #[allow(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "display geometry is whole, non-negative pixel counts within i32/u32"
        )]
        let bounds = DisplayBounds {
            x: rect.origin.x as i32,
            y: rect.origin.y as i32,
            width: rect.size.width.max(0.0) as u32,
            height: rect.size.height.max(0.0) as u32,
        };
        let mut capturer = Self {
            display,
            bounds,
            pacer: PollPacer::new(),
            last_frame: Vec::new(),
        };
        // Prime one capture so a denied permission surfaces at open time.
        match capturer.capture_once() {
            Ok(_) => Ok(capturer),
            Err(error) => Err(error),
        }
    }

    fn capture_once(&mut self) -> Result<Option<Frame>, CaptureError> {
        let image = CGDisplayCreateImage(self.display).ok_or_else(|| {
            CaptureError::Os(
                "CGDisplayCreateImage returned no image (grant Screen Recording permission)".into(),
            )
        })?;
        let width = CGImage::width(Some(&image));
        let height = CGImage::height(Some(&image));
        if width == 0 || height == 0 {
            return Err(CaptureError::AccessLost);
        }
        if CGImage::bits_per_pixel(Some(&image)) != 32 {
            return Err(CaptureError::Os(format!(
                "unexpected {}-bit CoreGraphics image",
                CGImage::bits_per_pixel(Some(&image))
            )));
        }
        let stride = CGImage::bytes_per_row(Some(&image));
        let layout = layout_of(
            CGImage::alpha_info(Some(&image)),
            CGImage::byte_order_info(Some(&image)),
        );
        let provider = CGImage::data_provider(Some(&image))
            .ok_or_else(|| CaptureError::Os("CoreGraphics image has no data provider".into()))?;
        let data = objc2_core_graphics::CGDataProvider::data(Some(&provider))
            .ok_or_else(|| CaptureError::Os("CGDataProviderCopyData failed".into()))?;
        let bytes = data.to_vec();
        let bgra = rows_to_bgra(&bytes, width, height, stride, layout)
            .ok_or_else(|| CaptureError::Os("short CoreGraphics image buffer".into()))?;

        #[allow(
            clippy::cast_possible_truncation,
            reason = "display dimensions fit in u32"
        )]
        let (width_u32, height_u32) = (width as u32, height as u32);
        if bgra == self.last_frame {
            return Ok(None);
        }
        self.last_frame.clone_from(&bgra);
        Ok(Some(Frame {
            width: width_u32,
            height: height_u32,
            bgra,
            captured_at: Instant::now(),
        }))
    }
}

impl Capturer for MacOsCapturer {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_follows_alpha_and_byte_order() {
        // CGDisplayCreateImage's usual output: skip-first alpha, 32-bit little-endian.
        assert_eq!(
            layout_of(
                CGImageAlphaInfo::NoneSkipFirst,
                CGImageByteOrderInfo::Order32Little
            ),
            PixelLayout::Bgrx
        );
        assert_eq!(
            layout_of(
                CGImageAlphaInfo::PremultipliedFirst,
                CGImageByteOrderInfo::Order32Big
            ),
            PixelLayout::Xrgb
        );
        assert_eq!(
            layout_of(
                CGImageAlphaInfo::PremultipliedLast,
                CGImageByteOrderInfo::Order32Little
            ),
            PixelLayout::Xbgr
        );
        assert_eq!(
            layout_of(
                CGImageAlphaInfo::NoneSkipLast,
                CGImageByteOrderInfo::Order32Big
            ),
            PixelLayout::Rgbx
        );
    }
}
