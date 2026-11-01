//! Blocking screen capture and video encoding loop running on a dedicated thread.

use std::sync::atomic::Ordering;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use omegadesk_capture::{CaptureError, Capturer, Frame};
use omegadesk_codec::{
    CodecError, EncodedFrame, EncoderSettings, OpenH264Encoder, RawFrame, VideoEncoder,
};
use omegadesk_input::TargetDisplay;
use omegadesk_protocol::v1::{VideoCodec, VideoFrame};
use tokio::sync::mpsc::{self, error::TrySendError};
use tracing::{debug, info, warn};

use crate::session::SessionState;

/// Maximum wait for a new frame before checking whether the session has stopped.
const POLL: Duration = Duration::from_millis(100);

/// Backoff delay before reopening screen capture or the encoder after an error.
const RETRY: Duration = Duration::from_millis(200);

/// Video encoder selection policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum EncoderChoice {
    /// Use hardware encoding when available, falling back to software.
    Auto,
    /// Require hardware encoding (fail if unavailable).
    Hardware,
    /// Use software encoding only (OpenH264).
    Software,
}

fn unix_micros() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_micros()).unwrap_or(u64::MAX))
}

fn open_capturer(monitor: u32, state: &SessionState) -> Option<Box<dyn Capturer>> {
    match omegadesk_capture::open_display(monitor) {
        Ok(capturer) => {
            let bounds = capturer.bounds();
            info!(
                "capturing monitor {monitor}: {}x{} at ({}, {})",
                bounds.width, bounds.height, bounds.x, bounds.y
            );
            state.set_target(TargetDisplay {
                x: bounds.x,
                y: bounds.y,
                width: bounds.width,
                height: bounds.height,
            });
            Some(capturer)
        }
        Err(error) => {
            debug!("capture unavailable: {error}");
            None
        }
    }
}

/// Opens a video encoder for `width`x`height` frames.
fn open_encoder(
    choice: EncoderChoice,
    width: u32,
    height: u32,
    settings: EncoderSettings,
    capturer: &dyn Capturer,
) -> Result<Box<dyn VideoEncoder>, CodecError> {
    #[cfg(windows)]
    if choice != EncoderChoice::Software {
        match omegadesk_codec::MediaFoundationEncoder::new_with_device(
            width,
            height,
            settings,
            capturer.d3d11_device(),
        ) {
            Ok(encoder) => {
                info!(
                    "hardware encoder: {} (zero-copy GPU: {})",
                    encoder.name(),
                    encoder.is_zero_copy()
                );
                return Ok(Box::new(encoder));
            }
            Err(error) if choice == EncoderChoice::Hardware => return Err(error),
            Err(error) => warn!("no hardware encoder ({error}); falling back to software"),
        }
    }
    #[cfg(not(windows))]
    if choice == EncoderChoice::Hardware {
        let _ = capturer;
        return Err(CodecError::HardwareUnavailable);
    }
    #[cfg(not(windows))]
    let _ = capturer;
    let _ = (width, height);
    info!("software encoder: OpenH264");
    Ok(Box::new(OpenH264Encoder::new(settings)?))
}

/// Active encoder paired with the frame dimensions it was configured for.
struct ActiveEncoder {
    encoder: Box<dyn VideoEncoder>,
    size: (u32, u32),
}

/// Captures, encodes, and queues frames until the session stops or the channel closes.
#[allow(
    clippy::too_many_lines,
    reason = "main capture loop handling sequential recovery states"
)]
pub(crate) fn run(
    monitor: u32,
    choice: EncoderChoice,
    settings: EncoderSettings,
    frames: &mpsc::Sender<VideoFrame>,
    state: &SessionState,
) {
    crate::platform::boost_current_thread();
    let mut choice = choice;
    let mut capturer: Option<Box<dyn Capturer>> = None;
    let mut encoder: Option<ActiveEncoder> = None;
    let mut last: Option<Frame> = None;
    let mut sequence = 0u64;
    let mut timing = Timing::default();

    while !state.stop.load(Ordering::Relaxed) {
        let Some(active) = capturer.as_mut() else {
            capturer = open_capturer(monitor, state);
            if capturer.is_none() {
                std::thread::sleep(RETRY);
            }
            continue;
        };

        let force_keyframe = state.keyframe_requested.swap(false, Ordering::Relaxed);

        let frame = match active.next_frame(POLL) {
            Ok(Some(frame)) => frame,
            // Static screen: only re-encode the last frame if the client requested a keyframe.
            Ok(None) => match (&last, force_keyframe) {
                (Some(previous), true) => {
                    let mut resend = previous.clone();
                    // Refresh timestamp so the cached frame does not report stale host delay.
                    resend.captured_at = Instant::now();
                    resend
                }
                (None, true) => {
                    // No frame captured yet: preserve the keyframe request for the first frame.
                    state.keyframe_requested.store(true, Ordering::Relaxed);
                    continue;
                }
                (_, false) => continue,
            },
            Err(CaptureError::AccessLost) => {
                debug!("display access lost; reopening capturer");
                capturer = None;
                // Never resend a pre-lock or pre-UAC frame after losing access
                // (privacy protection, matching CrossDesk).
                last = None;
                state.keyframe_requested.store(true, Ordering::Relaxed);
                continue;
            }
            Err(error) => {
                warn!("capture error: {error}");
                capturer = None;
                last = None;
                std::thread::sleep(RETRY);
                continue;
            }
        };

        // Recreate the encoder whenever the display resolution changes.
        if encoder.as_ref().map(|e| e.size) != Some((frame.width, frame.height)) {
            let Some(active) = capturer.as_deref() else {
                continue;
            };
            match open_encoder(choice, frame.width, frame.height, settings, active) {
                Ok(new_encoder) => {
                    encoder = Some(ActiveEncoder {
                        encoder: new_encoder,
                        size: (frame.width, frame.height),
                    });
                }
                Err(error) => {
                    warn!("encoder unavailable: {error}");
                    std::thread::sleep(RETRY);
                    continue;
                }
            }
        }
        let Some(active_encoder) = encoder.as_mut() else {
            continue;
        };
        if force_keyframe || sequence == 0 {
            active_encoder.encoder.request_keyframe();
        }

        let captured_at_micros = unix_micros();
        let encode_start = Instant::now();
        let encoded = active_encoder.encoder.encode(RawFrame {
            width: frame.width,
            height: frame.height,
            bgra: &frame.bgra,
            #[cfg(windows)]
            d3d11_texture: frame
                .gpu_texture
                .as_ref()
                .map(|gpu| omegadesk_codec::D3d11Texture {
                    device: &gpu.device,
                    context: &gpu.context,
                    texture: &gpu.texture,
                }),
        });
        let encoded = match encoded {
            Ok(encoded) => encoded,
            Err(error) => {
                // Mid-session hardware driver failure: fall back to software encoding
                // like RustDesk (`set_fallback` in `scrap/src/common/codec.rs`).
                warn!("encoding error: {error}; falling back to software encoder");
                choice = EncoderChoice::Software;
                encoder = None;
                state.keyframe_requested.store(true, Ordering::Relaxed);
                continue;
            }
        };
        let host_processing = frame.captured_at.elapsed();
        timing.record(encode_start - frame.captured_at, encode_start.elapsed());

        for EncodedFrame {
            data,
            keyframe,
            width,
            height,
        } in encoded
        {
            sequence += 1;
            let video_frame = VideoFrame {
                sequence,
                captured_at_micros,
                host_processing_micros: u32::try_from(host_processing.as_micros())
                    .unwrap_or(u32::MAX),
                codec: VideoCodec::H264 as i32,
                keyframe,
                display_index: monitor,
                width,
                height,
                data: data.into(),
            };
            match frames.try_send(video_frame) {
                Ok(()) => {}
                // Network is slower than capture: drop the frame instead of
                // accumulating latency, and request a keyframe because subsequent
                // P-frames depend on the dropped one (matching Selkies and Moonlight).
                Err(TrySendError::Full(_)) => {
                    timing.dropped += 1;
                    state.keyframe_requested.store(true, Ordering::Relaxed);
                    break;
                }
                Err(TrySendError::Closed(_)) => return,
            }
        }
        last = Some(frame);
    }
}

/// Per-stage timing accumulator logged every [`TIMING_PERIOD`].
#[derive(Debug, Default)]
struct Timing {
    frames: u32,
    dropped: u32,
    capture: Duration,
    encode: Duration,
    since: Option<Instant>,
}

/// Interval between periodic pipeline timing log lines.
const TIMING_PERIOD: Duration = Duration::from_secs(5);

impl Timing {
    fn record(&mut self, capture: Duration, encode: Duration) {
        let since = *self.since.get_or_insert_with(Instant::now);
        self.frames += 1;
        self.capture += capture;
        self.encode += encode;
        let elapsed = since.elapsed();
        if elapsed >= TIMING_PERIOD {
            let ms = |d: Duration| d.as_secs_f64() * 1000.0 / f64::from(self.frames);
            info!(
                "{:.1} fps · screen copy {:.1} ms · encode {:.1} ms · dropped {}",
                f64::from(self.frames) / elapsed.as_secs_f64(),
                ms(self.capture),
                ms(self.encode),
                self.dropped,
            );
            *self = Self::default();
        }
    }
}
