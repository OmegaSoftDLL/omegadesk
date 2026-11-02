//! macOS screen capture through `CGDisplayStream`.
//!
//! CoreGraphics delivers complete-display BGRA frames on a serial dispatch queue. Each
//! callback locks its `IOSurface` read-only, copies and tightly packs the pixels, then
//! publishes only the newest frame to the blocking [`Capturer`] interface. Idle callbacks
//! produce no frame; blank displays produce an opaque black frame.
//!
//! `CGDisplayStream` is deprecated in favor of ScreenCaptureKit but remains the native
//! CoreGraphics streaming API available before macOS 12.3. The capture still requires the
//! Screen Recording privacy permission; macOS does not provide a reliable way to distinguish
//! a permission-redacted black image from a genuinely black desktop.

#![allow(
    unsafe_code,
    reason = "CGDisplayStream creation and IOSurface memory access are C FFI operations"
)]
#![allow(
    deprecated,
    reason = "CGDisplayStream supports macOS versions before ScreenCaptureKit and feeds the same Capturer contract"
)]

use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::time::{Duration, Instant};

use block2::RcBlock;
use dispatch2::{DispatchQueue, DispatchQueueAttr};
use objc2_core_foundation::CFRetained;
use objc2_core_graphics::{
    CGDirectDisplayID, CGDisplayBounds, CGDisplayPixelsHigh, CGDisplayPixelsWide, CGDisplayStream,
    CGDisplayStreamFrameStatus, CGDisplayStreamUpdate, CGError, CGGetActiveDisplayList,
    CGMainDisplayID,
};
use objc2_io_surface::{IOSurfaceLockOptions, IOSurfaceRef};

use crate::convert::{PixelLayout, rows_to_bgra};
use crate::{CaptureError, Capturer, DisplayBounds, Frame};

const MAX_DISPLAYS: u32 = 16;
const OPEN_TIMEOUT: Duration = Duration::from_secs(15);
const STOP_TIMEOUT: Duration = Duration::from_secs(5);
const BGRA_PIXEL_FORMAT: i32 = i32::from_be_bytes(*b"BGRA");

#[derive(Default)]
struct FrameSlot {
    state: Mutex<SlotState>,
    ready: Condvar,
}

#[derive(Default)]
struct SlotState {
    frame: Option<Frame>,
    size: (u32, u32),
    closed: Option<String>,
    stopped: bool,
}

impl FrameSlot {
    fn lock(&self) -> std::sync::MutexGuard<'_, SlotState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn publish(&self, frame: Frame) {
        let mut state = self.lock();
        state.size = (frame.width, frame.height);
        state.frame = Some(frame);
        drop(state);
        self.ready.notify_all();
    }

    fn close(&self, reason: String) {
        let mut state = self.lock();
        if state.closed.is_none() {
            state.closed = Some(reason);
        }
        drop(state);
        self.ready.notify_all();
    }

    fn stopped(&self) {
        let mut state = self.lock();
        state.stopped = true;
        if state.closed.is_none() {
            state.closed = Some("CGDisplayStream stopped".to_owned());
        }
        drop(state);
        self.ready.notify_all();
    }

    fn is_stopped(&self) -> bool {
        self.lock().stopped
    }

    fn wait_ready(&self, timeout: Duration) -> Result<(), CaptureError> {
        let deadline = Instant::now() + timeout;
        let mut state = self.lock();
        loop {
            if state.frame.is_some() {
                return Ok(());
            }
            if let Some(reason) = &state.closed {
                return Err(CaptureError::Os(reason.clone()));
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(CaptureError::AccessLost);
            }
            let (guard, _) = self
                .ready
                .wait_timeout(state, deadline - now)
                .unwrap_or_else(PoisonError::into_inner);
            state = guard;
        }
    }

    fn wait_stopped(&self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        let mut state = self.lock();
        loop {
            if state.stopped {
                return true;
            }
            let now = Instant::now();
            if now >= deadline {
                return false;
            }
            let (guard, _) = self
                .ready
                .wait_timeout(state, deadline - now)
                .unwrap_or_else(PoisonError::into_inner);
            state = guard;
        }
    }
}

/// A `CGDisplayStream` capturer for one active display.
pub struct MacOsCapturer {
    stream: Option<CFRetained<CGDisplayStream>>,
    slot: Arc<FrameSlot>,
    bounds: DisplayBounds,
}

// SAFETY: CoreGraphics permits starting and stopping a display stream from any thread.
// Frame callbacks are serialized on their private dispatch queue and share data only
// through `FrameSlot`'s mutex and condition variable.
unsafe impl Send for MacOsCapturer {}

impl std::fmt::Debug for MacOsCapturer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MacOsCapturer")
            .field("bounds", &self.bounds)
            .field("stopped", &self.slot.is_stopped())
            .finish_non_exhaustive()
    }
}

fn active_displays() -> Result<Vec<CGDirectDisplayID>, CaptureError> {
    let mut displays = vec![0u32; MAX_DISPLAYS as usize];
    let mut count: u32 = 0;
    // SAFETY: `displays` has `MAX_DISPLAYS` elements and `count` is a valid out-pointer;
    // CGGetActiveDisplayList writes at most `MAX_DISPLAYS` ids and the actual count.
    let error =
        unsafe { CGGetActiveDisplayList(MAX_DISPLAYS, displays.as_mut_ptr(), &raw mut count) };
    if error != CGError::Success {
        return Err(CaptureError::Os(format!(
            "CGGetActiveDisplayList failed: {error:?}"
        )));
    }
    if count > MAX_DISPLAYS {
        return Err(CaptureError::Os(format!(
            "CGGetActiveDisplayList reported {count} displays; maximum supported is {MAX_DISPLAYS}"
        )));
    }
    displays.truncate(count as usize);
    if let Some(main) = displays
        .iter()
        .position(|display| *display == CGMainDisplayID())
    {
        displays.swap(0, main);
    }
    Ok(displays)
}

fn copy_surface(surface: &IOSurfaceRef) -> Result<Frame, CaptureError> {
    if surface.pixel_format() != BGRA_PIXEL_FORMAT.cast_unsigned() {
        return Err(CaptureError::Os(format!(
            "unexpected IOSurface pixel format {:#x}",
            surface.pixel_format()
        )));
    }
    // SAFETY: `surface` is retained by CoreGraphics for the duration of the callback;
    // null seed is explicitly accepted by IOSurfaceLock.
    let lock = unsafe { surface.lock(IOSurfaceLockOptions::ReadOnly, std::ptr::null_mut()) };
    if lock != 0 {
        return Err(CaptureError::Os(format!("IOSurfaceLock failed: {lock}")));
    }
    let result = (|| {
        let width = surface.width();
        let height = surface.height();
        let stride = surface.bytes_per_row();
        if width == 0 || height == 0 {
            return Err(CaptureError::AccessLost);
        }
        // SAFETY: the surface is locked read-only, its base address is non-null by API
        // contract, and `alloc_size` is the size of that allocation. The slice is dropped
        // before the surface is unlocked.
        let bytes = unsafe {
            std::slice::from_raw_parts(
                surface.base_address().cast::<u8>().as_ptr(),
                surface.alloc_size(),
            )
        };
        let bgra = rows_to_bgra(bytes, width, height, stride, PixelLayout::Bgrx)
            .ok_or_else(|| CaptureError::Os("short CoreGraphics IOSurface buffer".into()))?;
        Ok(Frame {
            width: u32::try_from(width).map_err(|_| CaptureError::AccessLost)?,
            height: u32::try_from(height).map_err(|_| CaptureError::AccessLost)?,
            bgra,
            captured_at: Instant::now(),
        })
    })();
    // SAFETY: this balances the successful read-only lock above; null seed is valid.
    let unlock = unsafe { surface.unlock(IOSurfaceLockOptions::ReadOnly, std::ptr::null_mut()) };
    match (result, unlock) {
        (Ok(frame), 0) => Ok(frame),
        (Ok(_), error) => Err(CaptureError::Os(format!("IOSurfaceUnlock failed: {error}"))),
        (Err(error), _) => Err(error),
    }
}

fn publish_blank(slot: &FrameSlot) {
    let (width, height) = slot.lock().size;
    let Some(len) = (width as usize)
        .checked_mul(height as usize)
        .and_then(|pixels| pixels.checked_mul(4))
    else {
        slot.close("blank display dimensions overflow".to_owned());
        return;
    };
    if len == 0 {
        return;
    }
    let mut bgra = vec![0u8; len];
    for pixel in bgra.as_chunks_mut::<4>().0 {
        pixel[3] = 0xFF;
    }
    slot.publish(Frame {
        width,
        height,
        bgra,
        captured_at: Instant::now(),
    });
}

impl MacOsCapturer {
    /// Opens a `CGDisplayStream` for active display `index` (`0` is the main display) and
    /// waits for its first complete or blank frame.
    ///
    /// # Errors
    ///
    /// Returns [`CaptureError::DisplayNotFound`] when `index` names no active display,
    /// [`CaptureError::Os`] when CoreGraphics cannot create or start the stream, and
    /// [`CaptureError::AccessLost`] when no initial frame arrives.
    pub fn open(index: u32) -> Result<Self, CaptureError> {
        let displays = active_displays()?;
        let display = *displays
            .get(usize::try_from(index).map_err(|_| CaptureError::DisplayNotFound(index))?)
            .ok_or(CaptureError::DisplayNotFound(index))?;
        let rect = CGDisplayBounds(display);
        let width = CGDisplayPixelsWide(display);
        let height = CGDisplayPixelsHigh(display);
        if width == 0 || height == 0 {
            return Err(CaptureError::DisplayNotFound(index));
        }
        #[allow(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "display origins are whole screen coordinates within i32 and dimensions fit u32"
        )]
        let bounds = DisplayBounds {
            x: rect.origin.x as i32,
            y: rect.origin.y as i32,
            width: width as u32,
            height: height as u32,
        };
        let slot = Arc::new(FrameSlot::default());
        slot.lock().size = (bounds.width, bounds.height);
        let callback_slot = slot.clone();
        let handler = RcBlock::new(
            move |status: CGDisplayStreamFrameStatus,
                  _timestamp: u64,
                  surface: *mut IOSurfaceRef,
                  _update: *const CGDisplayStreamUpdate| {
                match status {
                    CGDisplayStreamFrameStatus::FrameComplete => {
                        // SAFETY: CoreGraphics guarantees a valid IOSurface for a complete
                        // frame; a null surface is rejected before creating the reference.
                        let frame = unsafe { surface.as_ref() }
                            .ok_or_else(|| {
                                CaptureError::Os("complete frame has no IOSurface".into())
                            })
                            .and_then(copy_surface);
                        match frame {
                            Ok(frame) => callback_slot.publish(frame),
                            Err(error) => callback_slot.close(error.to_string()),
                        }
                    }
                    CGDisplayStreamFrameStatus::FrameBlank => publish_blank(&callback_slot),
                    CGDisplayStreamFrameStatus::FrameIdle => {}
                    CGDisplayStreamFrameStatus::Stopped => callback_slot.stopped(),
                    _ => callback_slot.close(format!("unknown stream status {status:?}")),
                }
            },
        );
        let queue = DispatchQueue::new("com.omegadesk.capture.display", DispatchQueueAttr::SERIAL);
        // SAFETY: the queue and handler are valid for this call and CoreGraphics retains
        // both for the stream's lifetime. No properties are supplied, and BGRA is a
        // documented output format. Dimensions were checked non-zero above.
        let stream = unsafe {
            CGDisplayStream::with_dispatch_queue(
                display,
                width,
                height,
                BGRA_PIXEL_FORMAT,
                None,
                &queue,
                RcBlock::as_ptr(&handler).cast(),
            )
        }
        .ok_or_else(|| {
            CaptureError::Os(
                "CGDisplayStreamCreateWithDispatchQueue failed (check Screen Recording permission)"
                    .into(),
            )
        })?;
        let error = CGDisplayStream::start(Some(&stream));
        if error != CGError::Success {
            return Err(CaptureError::Os(format!(
                "CGDisplayStreamStart failed: {error:?}"
            )));
        }
        let mut capturer = Self {
            stream: Some(stream),
            slot,
            bounds,
        };
        if let Err(error) = capturer.slot.wait_ready(OPEN_TIMEOUT) {
            capturer.stop();
            return Err(error);
        }
        Ok(capturer)
    }

    fn stop(&mut self) {
        let Some(stream) = self.stream.as_ref() else {
            return;
        };
        if self.slot.is_stopped() {
            return;
        }
        let error = CGDisplayStream::stop(Some(stream));
        if error != CGError::Success {
            self.slot
                .close(format!("CGDisplayStreamStop failed: {error:?}"));
            if let Some(stream) = self.stream.take() {
                std::mem::forget(stream);
            }
            return;
        }
        if !self.slot.wait_stopped(STOP_TIMEOUT) {
            // Apple only permits releasing the stream after the stopped callback. Leaking
            // it on an OS timeout is safer than letting a queued callback access freed state.
            if let Some(stream) = self.stream.take() {
                std::mem::forget(stream);
            }
        }
    }
}

impl Drop for MacOsCapturer {
    fn drop(&mut self) {
        self.stop();
    }
}

impl Capturer for MacOsCapturer {
    fn next_frame(&mut self, timeout: Duration) -> Result<Option<Frame>, CaptureError> {
        let deadline = Instant::now() + timeout;
        let mut state = self.slot.lock();
        loop {
            if let Some(frame) = state.frame.take() {
                return Ok(Some(frame));
            }
            if let Some(reason) = &state.closed {
                return Err(CaptureError::Os(format!("macOS capture: {reason}")));
            }
            let now = Instant::now();
            if now >= deadline {
                return Ok(None);
            }
            let (guard, _) = self
                .slot
                .ready
                .wait_timeout(state, deadline - now)
                .unwrap_or_else(PoisonError::into_inner);
            state = guard;
        }
    }

    fn size(&self) -> (u32, u32) {
        self.slot.lock().size
    }

    fn bounds(&self) -> DisplayBounds {
        let (width, height) = self.size();
        DisplayBounds {
            width,
            height,
            ..self.bounds
        }
    }
}

#[cfg(test)]
mod tests {
    use super::BGRA_PIXEL_FORMAT;

    #[test]
    fn pixel_format_is_core_graphics_bgra_four_cc() {
        assert_eq!(
            BGRA_PIXEL_FORMAT.cast_unsigned(),
            u32::from_be_bytes(*b"BGRA")
        );
    }
}
