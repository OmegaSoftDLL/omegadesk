//! Video QoS feedback: client `FrameAck`s drive `VideoQosController`
//! (`crates/session/src/qos.rs`, ported from RustDesk `src/server/video_qos.rs`)
//! and the resulting bitrate and frame rate are published to the capture thread
//! through [`SessionState`], the way RustDesk's `video_service.rs` reads
//! `VIDEO_QOS` (`spf()`, `ratio()`) at the top of every capture iteration and
//! calls `encoder.set_quality` in `check_qos`.

use std::time::{Duration, Instant};

use omegadesk_codec::EncoderSettings;
use omegadesk_protocol::v1::FrameAck;
use omegadesk_session::qos::{RecoveryAction, VideoQosController};
use tracing::{debug, info};

use crate::session::SessionState;

/// Lowest bitrate the controller may fall to, as a fraction of the configured
/// maximum (`1/8`: 8 Mbit/s becomes 1 Mbit/s), floored at [`MIN_BITRATE_FLOOR_BPS`].
const MIN_BITRATE_DIVISOR: u32 = 8;

/// Absolute bitrate floor: below this H.264 screen content is unreadable.
const MIN_BITRATE_FLOOR_BPS: u32 = 500_000;

/// An outstanding frame without an ack for this long is a stall (RustDesk
/// `video_qos.rs` rule `c`: `>= 2 s`).
const STALL_AFTER: Duration = Duration::from_secs(2);

/// Agent side of the QoS loop for one session.
#[derive(Debug)]
pub(crate) struct AgentQos {
    controller: VideoQosController,
    last_ack_at: Option<Instant>,
    /// Newest frame sequence the client acknowledged.
    last_acked_sequence: u64,
    /// Stall seconds already reported for the current gap, so each extra second
    /// triggers one more halving instead of re-reporting the same stall.
    stall_seconds_reported: u32,
}

impl AgentQos {
    /// Builds the controller from the encoder settings: the configured bitrate is
    /// the ceiling, `max_fps` the frame-rate cap.
    pub(crate) fn new(settings: EncoderSettings) -> Self {
        let max_kbps = (settings.bitrate_bps / 1000).max(1);
        let min_kbps = (settings.bitrate_bps / MIN_BITRATE_DIVISOR)
            .max(MIN_BITRATE_FLOOR_BPS)
            .min(settings.bitrate_bps)
            / 1000;
        // `max_fps` is a small positive float (CLI `--fps`), rounding is exact enough.
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let fps_cap = settings.max_fps.round().max(1.0) as u32;
        Self {
            controller: VideoQosController::new(min_kbps, max_kbps, fps_cap),
            last_ack_at: None,
            last_acked_sequence: 0,
            stall_seconds_reported: 0,
        }
    }

    /// Initial bitrate and frame rate the capture thread should start with, so
    /// the first encoder already matches the controller (no restart on the first ack).
    pub(crate) fn publish_initial(&self, state: &SessionState) {
        self.publish(state);
        info!(
            "video QoS: starting at {} kbit/s, {} fps (ceiling {} kbit/s)",
            self.controller.current_bitrate_kbps(),
            self.controller.current_fps(),
            self.controller.max_bitrate_kbps()
        );
    }

    /// Feeds one client acknowledgement measured at `now_micros` on the host
    /// clock (same clock as `VideoFrame::captured_at_micros`).
    pub(crate) fn on_frame_ack(&mut self, ack: &FrameAck, now_micros: u64, state: &SessionState) {
        let before = (
            self.controller.current_bitrate_kbps(),
            self.controller.current_fps(),
        );
        let action = self.controller.on_frame_ack(ack, now_micros);
        self.last_ack_at = Some(Instant::now());
        self.last_acked_sequence = self.last_acked_sequence.max(ack.frame_sequence);
        self.stall_seconds_reported = 0;
        match action {
            RecoveryAction::None => {}
            // Neither OpenH264 nor the Media Foundation MFTs expose reference-frame
            // invalidation, so the closest recovery for a lost P-frame is an IDR.
            RecoveryAction::InvalidateRefFrames { .. } | RecoveryAction::RequestIdr => {
                state.request_keyframe();
            }
        }
        self.publish(state);
        let after = (
            self.controller.current_bitrate_kbps(),
            self.controller.current_fps(),
        );
        if before != after {
            debug!(
                "video QoS: {} kbit/s {} fps -> {} kbit/s {} fps (delay {} ms, queue {})",
                before.0,
                before.1,
                after.0,
                after.1,
                now_micros.saturating_sub(ack.captured_at_micros) / 1000,
                ack.queue_depth
            );
        }
    }

    /// Periodic check (about once a second): if a frame newer than the last
    /// acknowledged one was sent (`last_sent_sequence`) and the last
    /// acknowledgement is older than [`STALL_AFTER`], applies the controller's
    /// stall brake once per elapsed second.
    pub(crate) fn on_tick(&mut self, now: Instant, last_sent_sequence: u64, state: &SessionState) {
        let Some(last_ack) = self.last_ack_at else {
            return;
        };
        if last_sent_sequence <= self.last_acked_sequence {
            return;
        }
        let stalled = now.saturating_duration_since(last_ack);
        if stalled < STALL_AFTER {
            return;
        }
        let seconds = u32::try_from(stalled.as_secs()).unwrap_or(u32::MAX);
        if seconds > self.stall_seconds_reported {
            self.stall_seconds_reported = seconds;
            self.controller.on_probe_stall(seconds);
            self.publish(state);
            debug!(
                "video QoS: no ack for {seconds} s, now {} kbit/s {} fps",
                self.controller.current_bitrate_kbps(),
                self.controller.current_fps()
            );
        }
    }

    fn publish(&self, state: &SessionState) {
        state.set_bitrate_bps(self.controller.current_bitrate_kbps().saturating_mul(1000));
        state.set_fps(self.controller.current_fps());
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;

    use super::*;

    fn settings() -> EncoderSettings {
        EncoderSettings {
            bitrate_bps: 8_000_000,
            max_fps: 60.0,
        }
    }

    fn ack(seq: u64, captured_at: u64, queue_depth: u32) -> FrameAck {
        FrameAck {
            frame_sequence: seq,
            captured_at_micros: captured_at,
            decode_micros: 3_000,
            queue_depth,
        }
    }

    #[test]
    fn initial_publish_matches_controller_and_bounds_bitrate_range() {
        let qos = AgentQos::new(settings());
        let state = SessionState::default();
        qos.publish_initial(&state);
        assert_eq!(
            state.bitrate_bps(),
            qos.controller.current_bitrate_kbps() * 1000
        );
        assert_eq!(state.fps(), 30, "RustDesk INIT_FPS");
        assert_eq!(qos.controller.max_bitrate_kbps(), 8_000);
        assert_eq!(qos.controller.min_bitrate_kbps(), 1_000);

        let low = AgentQos::new(EncoderSettings {
            bitrate_bps: 1_000_000,
            max_fps: 30.0,
        });
        assert_eq!(low.controller.min_bitrate_kbps(), 500, "absolute floor");
    }

    #[test]
    fn congested_acks_lower_the_published_bitrate_and_good_acks_raise_fps() {
        let mut qos = AgentQos::new(settings());
        let state = SessionState::default();
        qos.publish_initial(&state);
        let initial_bitrate = state.bitrate_bps();

        // Two prompt acks (20 ms end to end): startup acceleration doubles fps.
        qos.on_frame_ack(&ack(1, 1_000_000, 0), 1_020_000, &state);
        qos.on_frame_ack(&ack(2, 1_030_000, 0), 1_050_000, &state);
        assert_eq!(state.fps(), 60);
        assert!(state.bitrate_bps() > initial_bitrate);

        // Sustained congestion: 400 ms of excess delay with a backlog.
        let congested_from = state.bitrate_bps();
        for seq in 3..=5 {
            qos.on_frame_ack(&ack(seq, 2_000_000, 4), 2_420_000, &state);
        }
        assert!(state.bitrate_bps() < congested_from, "bitrate drops first");
        assert!(!state.keyframe_requested.load(Ordering::Relaxed));
    }

    #[test]
    fn sequence_gaps_request_a_keyframe() {
        let mut qos = AgentQos::new(settings());
        let state = SessionState::default();
        qos.on_frame_ack(&ack(10, 1_000, 0), 20_000, &state);
        assert!(!state.keyframe_requested.load(Ordering::Relaxed));
        qos.on_frame_ack(&ack(13, 2_000, 0), 21_000, &state);
        assert!(
            state.keyframe_requested.swap(false, Ordering::Relaxed),
            "lost frames 11..=12 recover through an IDR"
        );
        qos.on_frame_ack(&ack(60, 3_000, 0), 22_000, &state);
        assert!(
            state.keyframe_requested.load(Ordering::Relaxed),
            "large gap"
        );
    }

    #[test]
    fn stall_halves_fps_once_per_second_only_while_frames_are_outstanding() {
        let mut qos = AgentQos::new(settings());
        let state = SessionState::default();
        qos.on_frame_ack(&ack(1, 1_000_000, 0), 1_020_000, &state);
        qos.on_frame_ack(&ack(2, 1_030_000, 0), 1_050_000, &state);
        let fps = state.fps();
        let bitrate = state.bitrate_bps();
        let t0 = qos.last_ack_at.unwrap();

        // Nothing newer than frame 2 was sent: a quiet screen is not a stall.
        qos.on_tick(t0 + Duration::from_secs(5), 2, &state);
        assert_eq!(state.fps(), fps);

        qos.on_tick(t0 + Duration::from_millis(1_500), 3, &state);
        assert_eq!(state.fps(), fps, "under 2 s is not a stall");
        qos.on_tick(t0 + Duration::from_millis(2_100), 3, &state);
        assert_eq!(state.fps(), fps / 2);
        assert!(state.bitrate_bps() < bitrate);
        qos.on_tick(t0 + Duration::from_millis(2_900), 3, &state);
        assert_eq!(state.fps(), fps / 2, "same second: no second halving");
        qos.on_tick(t0 + Duration::from_millis(3_100), 4, &state);
        assert_eq!(state.fps(), (fps / 4).max(5));

        // An ack ends the stall bookkeeping.
        qos.on_frame_ack(&ack(3, 5_000_000, 0), 5_020_000, &state);
        assert_eq!(qos.stall_seconds_reported, 0);
    }
}
