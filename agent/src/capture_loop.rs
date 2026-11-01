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

/// Host clock used for `VideoFrame::captured_at_micros` and for measuring `FrameAck` delay.
pub(crate) fn unix_micros() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_micros()).unwrap_or(u64::MAX))
}

/// Frame-rate pacing: the capture thread waits out the remainder of one frame
/// period (`spf`, seconds per frame) since the previous encode before grabbing
/// the next frame, exactly as RustDesk `video_service.rs` does with
/// `std::thread::sleep(spf - elapsed)` at the end of every iteration. The
/// period follows the QoS controller's current frame rate.
#[derive(Debug, Default)]
pub(crate) struct FramePacer {
    last_encode: Option<Instant>,
}

impl FramePacer {
    /// Time still to wait before the next frame may be encoded at `fps`
    /// (`None` when a frame may be encoded right away or `fps` is unset).
    pub(crate) fn delay_until_slot(&self, fps: u32, now: Instant) -> Option<Duration> {
        let last = self.last_encode?;
        if fps == 0 {
            return None;
        }
        let spf = Duration::from_secs_f64(1.0 / f64::from(fps));
        let elapsed = now.saturating_duration_since(last);
        (elapsed < spf).then(|| spf.saturating_sub(elapsed))
    }

    /// Sleeps until the next slot at `fps` opens.
    fn wait_for_slot(&self, fps: u32) {
        if let Some(delay) = self.delay_until_slot(fps, Instant::now()) {
            std::thread::sleep(delay);
        }
    }

    pub(crate) fn mark_encoded(&mut self, now: Instant) {
        self.last_encode = Some(now);
    }
}

/// Decides when the QoS controller's recommended bitrate is worth applying to
/// the encoder. The controller moves in small steps on every acknowledgement
/// (RustDesk `video_qos.rs`); applying each one would restart a software
/// encoder many times a second. Cuts of at least [`Self::DECREASE_PERCENT`]
/// apply immediately (congestion must be answered now); increases apply when
/// they reach [`Self::INCREASE_PERCENT`], or any increase of at least
/// [`Self::SETTLE_PERCENT`] once [`Self::INCREASE_HOLD`] has passed since the
/// last change, so the stream still settles at the ceiling.
#[derive(Debug)]
pub(crate) struct BitrateGovernor {
    applied_bps: u32,
    last_change: Option<Instant>,
}

impl BitrateGovernor {
    const DECREASE_PERCENT: u32 = 10;
    const INCREASE_PERCENT: u32 = 20;
    const SETTLE_PERCENT: u32 = 5;
    const INCREASE_HOLD: Duration = Duration::from_secs(2);

    pub(crate) const fn new(applied_bps: u32) -> Self {
        Self {
            applied_bps,
            last_change: None,
        }
    }

    /// Returns `true` (and records the change) if `desired` should replace the
    /// bitrate currently applied to the encoder.
    pub(crate) fn should_apply(&mut self, desired: u32, now: Instant) -> bool {
        let applied = self.applied_bps;
        let apply = match desired.cmp(&applied) {
            std::cmp::Ordering::Less => applied - desired >= applied / 100 * Self::DECREASE_PERCENT,
            std::cmp::Ordering::Greater => {
                let increase = desired - applied;
                increase >= applied / 100 * Self::INCREASE_PERCENT
                    || (increase >= applied / 100 * Self::SETTLE_PERCENT
                        && self.last_change.is_none_or(|at| {
                            now.saturating_duration_since(at) >= Self::INCREASE_HOLD
                        }))
            }
            std::cmp::Ordering::Equal => false,
        };
        if apply {
            self.applied_bps = desired;
            self.last_change = Some(now);
        }
        apply
    }
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
///
/// The display to capture, the frame-rate cap and the encoder bitrate are read
/// from [`SessionState`] on every iteration: `SelectDisplay` retargets the
/// capturer and the QoS controller retunes the encoder while the session runs.
#[allow(
    clippy::too_many_lines,
    reason = "main capture loop handling sequential recovery states"
)]
pub(crate) fn run(
    choice: EncoderChoice,
    settings: EncoderSettings,
    frames: &mpsc::Sender<VideoFrame>,
    state: &SessionState,
) {
    crate::platform::boost_current_thread();
    let mut choice = choice;
    let mut settings = settings;
    if state.bitrate_bps() > 0 {
        settings.bitrate_bps = state.bitrate_bps();
    }
    let mut governor = BitrateGovernor::new(settings.bitrate_bps);
    let mut pacer = FramePacer::default();
    let mut monitor = state.monitor();
    let mut capturer: Option<Box<dyn Capturer>> = None;
    let mut encoder: Option<ActiveEncoder> = None;
    let mut last: Option<Frame> = None;
    let mut sequence = 0u64;
    let mut timing = Timing::default();

    while !state.stop.load(Ordering::Relaxed) {
        // Display switch requested by the client: reopen capture and encoder on
        // the new monitor and never resend a frame of the previous one.
        let wanted = state.monitor();
        if wanted != monitor {
            info!("switching capture from display {monitor} to display {wanted}");
            monitor = wanted;
            capturer = None;
            encoder = None;
            last = None;
            state.request_keyframe();
        }
        let Some(active) = capturer.as_mut() else {
            capturer = open_capturer(monitor, state);
            if capturer.is_none() {
                std::thread::sleep(RETRY);
            }
            continue;
        };

        // QoS: retune the bitrate (live when the encoder supports it, otherwise
        // by recreating it) and pace captures to the current frame rate.
        let desired_bitrate = state.bitrate_bps();
        if desired_bitrate > 0 && governor.should_apply(desired_bitrate, Instant::now()) {
            settings.bitrate_bps = desired_bitrate;
            if let Some(active) = encoder.as_mut() {
                if active.encoder.set_bitrate(desired_bitrate) {
                    debug!("encoder bitrate set to {} kbit/s", desired_bitrate / 1000);
                } else {
                    info!("recreating encoder for {} kbit/s", desired_bitrate / 1000);
                    encoder = None;
                    state.request_keyframe();
                }
            }
        }
        pacer.wait_for_slot(state.fps());

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
        pacer.mark_encoded(encode_start);
        timing.record(
            encode_start - frame.captured_at,
            encode_start.elapsed(),
            settings.bitrate_bps,
            state.fps(),
        );

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
    fn record(&mut self, capture: Duration, encode: Duration, bitrate_bps: u32, fps_cap: u32) {
        let since = *self.since.get_or_insert_with(Instant::now);
        self.frames += 1;
        self.capture += capture;
        self.encode += encode;
        let elapsed = since.elapsed();
        if elapsed >= TIMING_PERIOD {
            let ms = |d: Duration| d.as_secs_f64() * 1000.0 / f64::from(self.frames);
            info!(
                "{:.1} fps (cap {fps_cap}) · {} kbit/s · screen copy {:.1} ms · encode {:.1} ms · dropped {}",
                f64::from(self.frames) / elapsed.as_secs_f64(),
                bitrate_bps / 1000,
                ms(self.capture),
                ms(self.encode),
                self.dropped,
            );
            *self = Self::default();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pacer_waits_out_the_remaining_frame_period() {
        let mut pacer = FramePacer::default();
        let t0 = Instant::now();
        assert_eq!(
            pacer.delay_until_slot(30, t0),
            None,
            "first frame goes out at once"
        );
        pacer.mark_encoded(t0);
        assert_eq!(pacer.delay_until_slot(0, t0), None, "no cap yet: no pacing");
        let remaining = pacer
            .delay_until_slot(30, t0 + Duration::from_millis(13))
            .expect("13 ms into a 33 ms period");
        assert!(
            (Duration::from_millis(19)..=Duration::from_millis(21)).contains(&remaining),
            "{remaining:?}"
        );
        assert_eq!(
            pacer.delay_until_slot(30, t0 + Duration::from_millis(34)),
            None
        );
        // Raising the cap shortens the period immediately.
        assert_eq!(
            pacer.delay_until_slot(60, t0 + Duration::from_millis(17)),
            None
        );
    }

    #[test]
    fn governor_cuts_immediately_and_raises_with_hysteresis() {
        let t0 = Instant::now();
        let mut governor = BitrateGovernor::new(8_000_000);
        assert!(!governor.should_apply(8_000_000, t0), "unchanged");
        assert!(!governor.should_apply(7_500_000, t0), "a 6% cut is noise");
        assert!(
            governor.should_apply(7_000_000, t0),
            "a 12.5% cut applies now"
        );
        assert!(
            governor.should_apply(5_000_000, t0),
            "and so does the next cut"
        );

        // Recovery: +10% steps every ack, like the controller emits them.
        assert!(!governor.should_apply(5_500_000, t0), "10% up is held back");
        assert!(governor.should_apply(6_050_000, t0), "21% up applies");
        assert!(
            !governor.should_apply(6_500_000, t0 + Duration::from_secs(1)),
            "7% up within the hold is held back"
        );
        assert!(
            governor.should_apply(6_500_000, t0 + Duration::from_secs(3)),
            "the same 7% applies once 2 s passed"
        );
        assert!(
            !governor.should_apply(6_600_000, t0 + Duration::from_secs(6)),
            "1.5% up is never worth a restart"
        );
    }
}
