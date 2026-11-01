//! Adaptive video quality control (`video_qos`), per-frame ACK tracking, and
//! reference-frame invalidation.
//!
//! Combines three reference architectures:
//! - **RustDesk `src/server/video_qos.rs`** (AGPL-3.0):
//!   Tracks baseline path delay over a sliding 20-reply window, lowers **bitrate
//!   first** before lowering FPS when congestion is confirmed (`3` consecutive bad
//!   samples with excess delay `>= 150 ms`), drops FPS by `20%` on ordinary
//!   congestion or `50%` immediately when excess delay reaches `>= 1000 ms`,
//!   and halves FPS down to `MIN_AUTO_FPS = 5` if a frame ACK stalls for `> 2 s`.
//! - **Selkies `websockets_mode.py`** (MPL-2.0):
//!   Per-frame acknowledgement (`FrameAck`) measuring queue depth and end-to-end
//!   frame delay to drop frames for slow clients before buffers bloat.
//! - **Sunshine `src/video.cpp`** (GPL-3.0):
//!   Reference-frame invalidation (`InvalidateReferenceFrames`) over a contiguous
//!   lost sequence range `[first_lost, last_lost]` so the encoder recovers from
//!   packet loss without an IDR bandwidth spike.

use std::collections::VecDeque;

use omegadesk_protocol::v1::{FrameAck, InvalidateReferenceFrames};

/// Initial frame rate when a new viewer joins (matching RustDesk `INIT_FPS` scaled for 60 fps).
pub const INIT_FPS: u32 = 30;

/// Minimum automatic frame rate floor during congestion (`MIN_AUTO_FPS` in RustDesk `video_qos.rs`).
pub const MIN_AUTO_FPS: u32 = 5;

/// Absolute minimum frame rate.
pub const MIN_FPS: u32 = 1;

/// Maximum supported frame rate (`MAX_FPS` in RustDesk `video_qos.rs`).
pub const MAX_FPS: u32 = 120;

/// Excess delay threshold in milliseconds separating good and congested samples
/// (`DELAY_THRESHOLD_150MS` in RustDesk `video_qos.rs`).
pub const DELAY_THRESHOLD_MS: u32 = 150;

/// Severe excess delay threshold in milliseconds that triggers an immediate 50%
/// FPS cut without waiting for 3 consecutive bad samples.
pub const SEVERE_DELAY_THRESHOLD_MS: u32 = 1000;

/// Sliding window size for baseline minimum delay estimation (`20` replies in RustDesk).
const BASELINE_WINDOW_LEN: usize = 20;

/// Number of samples after a fast FPS restore during which re-congestion rolls back
/// the pre-congestion target (`RESTORE_GUARD_SAMPLES` in RustDesk `video_qos.rs`).
const RESTORE_GUARD_SAMPLES: u8 = 5;

/// Maximum number of contiguous lost frames that can be recovered via
/// reference-frame invalidation before falling back to a full IDR keyframe.
pub const MAX_REF_INVALIDATION_SPAN: u64 = 16;

/// Recovery action emitted when the client or host detects lost frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryAction {
    /// No frames were lost; normal P-frame encoding continues.
    None,
    /// Invalidate reference frames `[first_lost_sequence, last_lost_sequence]`
    /// (Sunshine `invalidate_ref_frames`) to recover without an IDR frame spike.
    InvalidateRefFrames {
        /// First lost frame sequence number.
        first_lost_sequence: u64,
        /// Last lost frame sequence number (inclusive).
        last_lost_sequence: u64,
    },
    /// Contiguous loss span exceeded [`MAX_REF_INVALIDATION_SPAN`]; emit a full
    /// IDR keyframe (`RequestKeyframe`).
    RequestIdr,
}

impl RecoveryAction {
    /// Converts an [`InvalidateReferenceFrames`] action into its protobuf wire message.
    #[must_use]
    pub const fn to_proto_invalidation(self) -> Option<InvalidateReferenceFrames> {
        match self {
            Self::InvalidateRefFrames {
                first_lost_sequence,
                last_lost_sequence,
            } => Some(InvalidateReferenceFrames {
                first_lost_sequence,
                last_lost_sequence,
            }),
            Self::None | Self::RequestIdr => None,
        }
    }
}

/// Adaptive video quality controller modeled after RustDesk's `video_qos.rs`
/// and Selkies' per-frame ACK loop.
#[derive(Debug, Clone)]
pub struct VideoQosController {
    min_bitrate_kbps: u32,
    max_bitrate_kbps: u32,
    current_bitrate_kbps: u32,
    target_fps_cap: u32,
    current_fps: u32,
    delay_window_ms: VecDeque<u32>,
    consecutive_bad_samples: u8,
    fps_bad_samples: u8,
    good_samples: u8,
    startup_good_samples: u8,
    replies_after_bitrate_reduction: Option<u8>,
    fps_before_congestion: Option<u32>,
    samples_since_restore: Option<u8>,
    last_acked_sequence: Option<u64>,
}

impl VideoQosController {
    /// Creates a new [`VideoQosController`] with `min_bitrate_kbps..=max_bitrate_kbps`
    /// and a viewer FPS cap (`target_fps_cap`).
    #[must_use]
    pub fn new(min_bitrate_kbps: u32, max_bitrate_kbps: u32, target_fps_cap: u32) -> Self {
        let min_br = min_bitrate_kbps.max(200);
        let max_br = max_bitrate_kbps.max(min_br);
        let cap = target_fps_cap.clamp(MIN_FPS, MAX_FPS);
        let initial_fps = INIT_FPS.min(cap);
        let initial_br = u32::midpoint(min_br, max_br).clamp(min_br, max_br);

        Self {
            min_bitrate_kbps: min_br,
            max_bitrate_kbps: max_br,
            current_bitrate_kbps: initial_br,
            target_fps_cap: cap,
            current_fps: initial_fps,
            delay_window_ms: VecDeque::with_capacity(BASELINE_WINDOW_LEN),
            consecutive_bad_samples: 0,
            fps_bad_samples: 0,
            good_samples: 0,
            startup_good_samples: 0,
            replies_after_bitrate_reduction: None,
            fps_before_congestion: None,
            samples_since_restore: None,
            last_acked_sequence: None,
        }
    }

    /// Current recommended encoder bitrate in kilobits per second.
    #[must_use]
    pub const fn current_bitrate_kbps(&self) -> u32 {
        self.current_bitrate_kbps
    }

    /// Current recommended capture/encode frame rate.
    #[must_use]
    pub const fn current_fps(&self) -> u32 {
        self.current_fps
    }

    /// Lowest bitrate the controller will recommend, in kilobits per second.
    #[must_use]
    pub const fn min_bitrate_kbps(&self) -> u32 {
        self.min_bitrate_kbps
    }

    /// Highest bitrate the controller will recommend, in kilobits per second.
    #[must_use]
    pub const fn max_bitrate_kbps(&self) -> u32 {
        self.max_bitrate_kbps
    }

    /// Frame-rate cap the controller ramps toward, in frames per second.
    #[must_use]
    pub const fn target_fps_cap(&self) -> u32 {
        self.target_fps_cap
    }

    /// Baseline minimum one-way/round-trip delay observed over the recent window.
    #[must_use]
    pub fn baseline_delay_ms(&self) -> u32 {
        self.delay_window_ms.iter().copied().min().unwrap_or(0)
    }

    /// Processes a client [`FrameAck`] measured at `now_micros` on the host clock
    /// and returns any required [`RecoveryAction`] for lost frames.
    pub fn on_frame_ack(&mut self, ack: &FrameAck, now_micros: u64) -> RecoveryAction {
        let recovery = self.detect_sequence_gap(ack.frame_sequence);
        let total_delay_ms =
            u32::try_from(now_micros.saturating_sub(ack.captured_at_micros) / 1_000)
                .unwrap_or(u32::MAX);

        self.record_delay_sample(total_delay_ms, ack.queue_depth);
        recovery
    }

    /// Applies the timeout brake when an outstanding frame probe has not been
    /// acknowledged for `stall_seconds` (`>= 2` seconds halves FPS each second
    /// down to [`MIN_AUTO_FPS`], matching RustDesk `video_qos.rs` rule `c`).
    pub fn on_probe_stall(&mut self, stall_seconds: u32) {
        if stall_seconds < 2 {
            return;
        }
        self.startup_good_samples = u8::MAX;
        let floor = MIN_AUTO_FPS.min(self.target_fps_cap);
        // Lower bitrate by 25% on stall and halve FPS down to `MIN_AUTO_FPS`.
        let reduced_br = self
            .current_bitrate_kbps
            .saturating_sub(self.current_bitrate_kbps / 4);
        self.current_bitrate_kbps = reduced_br.max(self.min_bitrate_kbps);
        self.current_fps = (self.current_fps / 2).max(floor);
    }

    fn detect_sequence_gap(&mut self, seq: u64) -> RecoveryAction {
        let Some(prev) = self.last_acked_sequence else {
            self.last_acked_sequence = Some(seq);
            return RecoveryAction::None;
        };
        if seq <= prev {
            return RecoveryAction::None;
        }
        self.last_acked_sequence = Some(seq);
        let gap = seq - prev - 1;
        if gap == 0 {
            RecoveryAction::None
        } else if gap <= MAX_REF_INVALIDATION_SPAN {
            RecoveryAction::InvalidateRefFrames {
                first_lost_sequence: prev + 1,
                last_lost_sequence: seq - 1,
            }
        } else {
            RecoveryAction::RequestIdr
        }
    }

    fn record_delay_sample(&mut self, total_delay_ms: u32, queue_depth: u32) {
        if self.delay_window_ms.len() >= BASELINE_WINDOW_LEN {
            self.delay_window_ms.pop_front();
        }
        self.delay_window_ms.push_back(total_delay_ms);

        let baseline = self.baseline_delay_ms();
        let excess_ms = total_delay_ms.saturating_sub(baseline);

        if let Some(samples) = &mut self.samples_since_restore {
            *samples = samples.saturating_add(1);
        }

        if excess_ms < DELAY_THRESHOLD_MS && queue_depth <= 2 {
            self.handle_good_sample(excess_ms);
        } else {
            self.handle_bad_sample(excess_ms);
        }
    }

    fn handle_good_sample(&mut self, excess_ms: u32) {
        self.consecutive_bad_samples = 0;
        self.fps_bad_samples = 0;
        self.replies_after_bitrate_reduction = None;
        self.good_samples = (self.good_samples + 1).min(3);

        // Startup acceleration: two consecutive replies with excess < 50 ms permit
        // doubling FPS toward `target_fps_cap` (RustDesk `video_qos.rs` rule `b`).
        if self.startup_good_samples < u8::MAX {
            if excess_ms < 50 {
                self.startup_good_samples += 1;
                if self.startup_good_samples >= 2 {
                    self.current_fps = (self.current_fps * 2).min(self.target_fps_cap);
                }
            } else {
                self.startup_good_samples = u8::MAX;
            }
        }

        // Gradual FPS recovery or restoration to pre-congestion level after 2 good replies
        let gradual_fps =
            (self.current_fps + (self.current_fps / 10).max(1)).min(self.target_fps_cap);
        if self.good_samples >= 2
            && let Some(prev_fps) = self.fps_before_congestion.take()
        {
            self.current_fps = prev_fps.max(gradual_fps).min(self.target_fps_cap);
            self.samples_since_restore = Some(0);
        } else {
            self.current_fps = gradual_fps;
        }

        // Gradually increase bitrate by 10% (at least 150 kbps) up to `max_bitrate_kbps`
        let step = (self.current_bitrate_kbps / 10).max(150);
        self.current_bitrate_kbps = (self.current_bitrate_kbps + step).min(self.max_bitrate_kbps);
    }

    fn handle_bad_sample(&mut self, excess_ms: u32) {
        self.startup_good_samples = u8::MAX;
        self.good_samples = 0;
        self.consecutive_bad_samples = (self.consecutive_bad_samples + 1).min(3);
        self.fps_bad_samples = (self.fps_bad_samples + 1).min(3);

        if let Some(replies) = &mut self.replies_after_bitrate_reduction {
            *replies = (*replies + 1).min(2);
        }

        let failed_restore = excess_ms >= 600
            && self
                .samples_since_restore
                .is_some_and(|s| s <= RESTORE_GUARD_SAMPLES);

        if self
            .samples_since_restore
            .is_some_and(|s| s <= RESTORE_GUARD_SAMPLES)
            && (failed_restore || self.consecutive_bad_samples >= 3)
        {
            self.fps_before_congestion = Some(self.current_fps - self.current_fps / 4);
            self.samples_since_restore = None;
        }

        // Rule: lower bitrate FIRST when confirmed congestion (>= 2 bad samples) occurs
        // and bitrate is still above `min_bitrate_kbps`.
        let can_reduce_bitrate = self.current_bitrate_kbps > self.min_bitrate_kbps;
        if self.consecutive_bad_samples >= 2 && can_reduce_bitrate {
            let cut = (self.current_bitrate_kbps / 5).max(150);
            self.current_bitrate_kbps = self
                .current_bitrate_kbps
                .saturating_sub(cut)
                .max(self.min_bitrate_kbps);
            if self.replies_after_bitrate_reduction.is_none() {
                self.replies_after_bitrate_reduction = Some(0);
            }
        }

        // Only reduce FPS if excess_ms >= 1000 ms, failed_restore, or 3 consecutive bad
        // samples AND bitrate was already reduced at least 2 samples ago (or is at floor).
        let bitrate_first_gate =
            can_reduce_bitrate && self.replies_after_bitrate_reduction.unwrap_or(0) < 2;
        if !failed_restore
            && excess_ms < SEVERE_DELAY_THRESHOLD_MS
            && (self.fps_bad_samples < 3 || bitrate_first_gate)
        {
            return;
        }

        let divisor = if excess_ms >= SEVERE_DELAY_THRESHOLD_MS || failed_restore {
            2
        } else {
            5
        };
        if self.fps_before_congestion.is_none() {
            self.fps_before_congestion = Some(self.current_fps);
        }
        self.fps_bad_samples = 0;
        let floor = MIN_AUTO_FPS.min(self.target_fps_cap);
        let drop = (self.current_fps / divisor).max(1);
        self.current_fps = self.current_fps.saturating_sub(drop).max(floor);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn startup_acceleration_and_bitrate_first_congestion_control() {
        let mut qos = VideoQosController::new(1_000, 10_000, 60);
        assert_eq!(qos.current_fps(), 30);
        let initial_br = qos.current_bitrate_kbps();

        // Two low-delay startup samples (< 50 ms excess) double FPS to 60
        for seq in 1..=2 {
            let act = qos.on_frame_ack(
                &FrameAck {
                    frame_sequence: seq,
                    captured_at_micros: 100_000,
                    decode_micros: 2_000,
                    queue_depth: 0,
                },
                120_000,
            );
            assert_eq!(act, RecoveryAction::None);
        }
        assert_eq!(qos.current_fps(), 60);
        assert!(qos.current_bitrate_kbps() > initial_br);

        // Now inject 2 congested samples (250 ms excess delay): bitrate drops FIRST, FPS stays 60
        let br_before_congestion = qos.current_bitrate_kbps();
        for seq in 3..=4 {
            qos.on_frame_ack(
                &FrameAck {
                    frame_sequence: seq,
                    captured_at_micros: 200_000,
                    decode_micros: 5_000,
                    queue_depth: 3,
                },
                480_000,
            );
        }
        assert!(qos.current_bitrate_kbps() < br_before_congestion);
        assert_eq!(qos.current_fps(), 60);

        // Persistent congestion (2 more bad samples after bitrate reduction) finally lowers FPS by 20%
        for seq in 5..=6 {
            qos.on_frame_ack(
                &FrameAck {
                    frame_sequence: seq,
                    captured_at_micros: 200_000,
                    decode_micros: 5_000,
                    queue_depth: 4,
                },
                490_000,
            );
        }
        assert_eq!(qos.current_fps(), 48);
    }

    #[test]
    fn sequence_gaps_emit_ref_frame_invalidation_or_idr() {
        let mut qos = VideoQosController::new(1_000, 8_000, 60);
        assert_eq!(
            qos.on_frame_ack(
                &FrameAck {
                    frame_sequence: 10,
                    captured_at_micros: 1_000,
                    decode_micros: 1_000,
                    queue_depth: 0,
                },
                15_000
            ),
            RecoveryAction::None
        );

        // Frames 11 and 12 were lost; frame 13 arrives -> InvalidateRefFrames(11..=12)
        let action = qos.on_frame_ack(
            &FrameAck {
                frame_sequence: 13,
                captured_at_micros: 2_000,
                decode_micros: 1_000,
                queue_depth: 0,
            },
            16_000,
        );
        assert_eq!(
            action,
            RecoveryAction::InvalidateRefFrames {
                first_lost_sequence: 11,
                last_lost_sequence: 12,
            }
        );
        assert!(action.to_proto_invalidation().is_some());

        // Huge gap (> 16 frames) -> RequestIdr
        let idr_action = qos.on_frame_ack(
            &FrameAck {
                frame_sequence: 40,
                captured_at_micros: 3_000,
                decode_micros: 1_000,
                queue_depth: 0,
            },
            17_000,
        );
        assert_eq!(idr_action, RecoveryAction::RequestIdr);
    }
}
