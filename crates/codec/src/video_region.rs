//! Dynamic "looks like video" area detector and static lossless paint-over trigger.
//!
//! Ported directly from `kasmtech_KasmVNC/common/rfb/EncodeManager.cxx`
//! (`EncodeManager::updateVideoStats`, lines 940–991, GPL-2.0-or-later) and
//! `selkies-project_selkies` ("paint-over" static refresh):
//! - Maintains a ring buffer `area_percentages` of length `samples = video_time_secs * frame_rate`.
//! - For each frame, sums the bounding areas of changed rectangles, converts to a
//!   percentage `(changed_area * 100) / (screen_width * screen_height)`, and inserts
//!   into `area_percentages[area_cur]`.
//! - When the rolling average exceeds `video_area_threshold_pct` (default 45%),
//!   enters [`ContentCodingMode::VideoMotion`] and starts a hold timer (`video_out_time`,
//!   default 3 s).
//! - When the hold timer expires (`EncodeManager.cxx:941-954`), resets
//!   `area_percentages` to `0`, switches back to [`ContentCodingMode::LosslessStatic`],
//!   and emits `needs_lossless_paint_over = true` so crisp text is restored.

use std::time::{Duration, Instant};

/// Changed rectangle in desktop pixel coordinates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChangedRect {
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels.
    pub height: u32,
}

impl ChangedRect {
    /// Area in pixels (`width * height`).
    #[must_use]
    pub const fn area(self) -> u64 {
        (self.width as u64) * (self.height as u64)
    }
}

/// Content coding mode chosen by [`VideoRegionDetector`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentCodingMode {
    /// High-motion video content (`videoDetected == true` in `EncodeManager.cxx`).
    VideoMotion,
    /// Static/text content encoded at lossless/near-lossless quality.
    LosslessStatic,
}

/// Result of updating [`VideoRegionDetector`] for a frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VideoDetectionStep {
    /// Active coding mode for this frame.
    pub mode: ContentCodingMode,
    /// Rolling average changed area percentage (`0..=100`).
    pub average_area_pct: u32,
    /// `true` on the transition from [`ContentCodingMode::VideoMotion`] back to
    /// [`ContentCodingMode::LosslessStatic`] (`conn->add_changed_all()` in
    /// `EncodeManager.cxx:953`).
    pub needs_lossless_paint_over: bool,
}

/// Rolling-window video region detector ported from `KasmVNC` `EncodeManager.cxx`.
#[derive(Debug, Clone)]
pub struct VideoRegionDetector {
    area_percentages: Vec<u8>,
    area_cur: usize,
    video_area_threshold_pct: u32,
    video_out_time: Duration,
    video_detected: bool,
    video_hold_until: Option<Instant>,
}

impl VideoRegionDetector {
    /// Creates a new detector matching `EncodeManager::EncodeManager`
    /// (`EncodeManager.cxx:170-214`).
    ///
    /// - `video_time_secs`: window duration in seconds (clamped to `>= 1`).
    /// - `frame_rate`: target capture rate in Hz (clamped to `>= 1`).
    /// - `video_area_threshold_pct`: percentage of screen area (`1..=100`, default `45`)
    ///   above which video mode activates.
    /// - `video_out_time`: hold duration before exiting video mode (`videoOutTime`).
    #[must_use]
    pub fn new(
        video_time_secs: u32,
        frame_rate: u32,
        video_area_threshold_pct: u32,
        video_out_time: Duration,
    ) -> Self {
        let samples = (video_time_secs.max(1) as usize) * (frame_rate.max(1) as usize);
        Self {
            area_percentages: vec![0u8; samples],
            area_cur: 0,
            video_area_threshold_pct: video_area_threshold_pct.clamp(1, 100),
            video_out_time,
            video_detected: false,
            video_hold_until: None,
        }
    }

    /// Updates rolling changed-area statistics and returns the active [`VideoDetectionStep`],
    /// ported from `EncodeManager::updateVideoStats` and `EncodeManager::handleTimeout`
    /// (`EncodeManager.cxx:941-991`).
    pub fn update_video_stats(
        &mut self,
        rects: &[ChangedRect],
        screen_width: u32,
        screen_height: u32,
        now: Instant,
    ) -> VideoDetectionStep {
        let mut needs_lossless_paint_over = false;

        // Check if `videoTimer` expired (`EncodeManager.cxx:941-955`).
        if self.video_detected
            && let Some(deadline) = self.video_hold_until
            && now >= deadline
        {
            self.video_detected = false;
            self.video_hold_until = None;
            self.area_percentages.fill(0);
            self.area_cur = 0;
            needs_lossless_paint_over = true;
        }

        let screen_area = u64::from(screen_width.max(1)) * u64::from(screen_height.max(1));
        let changed_area: u64 = rects.iter().map(|r| r.area()).sum();
        let frame_pct = ((changed_area.saturating_mul(100)) / screen_area).min(100);

        let samples = self.area_percentages.len();
        #[allow(clippy::cast_possible_truncation)]
        {
            self.area_percentages[self.area_cur] = frame_pct as u8;
        }
        self.area_cur = (self.area_cur + 1) % samples;

        let sum: u32 = self.area_percentages.iter().map(|&p| u32::from(p)).sum();
        #[allow(clippy::cast_possible_truncation)]
        let avg_area = sum / (samples as u32);

        if avg_area > self.video_area_threshold_pct {
            self.video_detected = true;
            self.video_hold_until = Some(now + self.video_out_time);
            needs_lossless_paint_over = false;
        }

        VideoDetectionStep {
            mode: if self.video_detected {
                ContentCodingMode::VideoMotion
            } else {
                ContentCodingMode::LosslessStatic
            },
            average_area_pct: avg_area,
            needs_lossless_paint_over,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_video_motion_and_triggers_lossless_paint_over_after_hold_timer() {
        let mut detector = VideoRegionDetector::new(1, 5, 45, Duration::from_secs(3));
        let t0 = Instant::now();

        // 5 frames with 60% screen damage -> average reaches 60% > 45%.
        let mut step = VideoDetectionStep {
            mode: ContentCodingMode::LosslessStatic,
            average_area_pct: 0,
            needs_lossless_paint_over: false,
        };
        for i in 0..5 {
            step = detector.update_video_stats(
                &[ChangedRect {
                    width: 1920,
                    height: 648,
                }],
                1920,
                1080,
                t0 + Duration::from_millis(i * 200),
            );
        }
        assert_eq!(step.mode, ContentCodingMode::VideoMotion);
        assert!(step.average_area_pct > 45);
        assert!(!step.needs_lossless_paint_over);

        // After the 3-second hold timer expires on a static screen, transitions back to
        // LosslessStatic and requests a full lossless paint-over (`EncodeManager.cxx:953`).
        let after_hold = detector.update_video_stats(&[], 1920, 1080, t0 + Duration::from_secs(5));
        assert_eq!(after_hold.mode, ContentCodingMode::LosslessStatic);
        assert!(after_hold.needs_lossless_paint_over);
    }
}
