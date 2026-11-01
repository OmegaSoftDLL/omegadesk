//! Low-latency frame pacer and 1-to-3 frame presentation queue (`docs/plan.md` §2.3 line 66).
//!
//! Clean-room implementation modeled after the architecture of Moonlight's
//! `Pacer` (`moonlight-stream_moonlight-qt/app/streaming/video/ffmpeg-renderers/pacer/pacer.h`
//! lines 10–14 and `pacer.cpp` lines 21–31, 209–268, 340–425) and `d3d11va.cpp`
//! flip-model presentation:
//! - [`MAX_QUEUED_FRAMES`] (`3`): maximum frames retained in the pacing or render queue.
//! - [`PACER_MAX_OUTSTANDING_FRAMES`] (`3 + 1 + 1 = 5`): 3 queued + 1 rendering + 1 deferred free.
//! - Rolling `500 ms` queue-depth history (`display_fps / 2` and `max_video_fps / 2`):
//!   allows temporary bursts up to `3` frames (`pacing_drop_target = 3`, `render_drop_target = 2`)
//!   as long as the queue drained to `<= 1` (or `0` for render) within the last `500 ms`,
//!   tightening to `1` (or `0`) when persistently backed up.
//! - [`PresentationMode`]: flip model with optional `DXGI_PRESENT_ALLOW_TEARING` bypass when
//!   V-Sync pacing is disabled.

use std::collections::VecDeque;

/// Maximum number of frames queued in either the pacing queue or render queue (`pacer.cpp` line 21).
pub(crate) const MAX_QUEUED_FRAMES: usize = 3;

/// Maximum outstanding frames across pacing queue (`3`), active render (`1`), and deferred free (`1`)
/// (`pacer.h` line 14).
pub(crate) const PACER_MAX_OUTSTANDING_FRAMES: usize = MAX_QUEUED_FRAMES + 2;

/// Timer slack in milliseconds subtracted from the next V-Sync deadline (`pacer.cpp` line 30).
pub(crate) const TIMER_SLACK_MS: u32 = 3;

/// Swap-chain presentation mode (`d3d11va.cpp` flip model).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PresentationMode {
    /// `DXGI_SWAP_EFFECT_FLIP_DISCARD` synchronized to V-Sync with `FramePacer` queue smoothing.
    FlipVsyncPaced,
    /// `DXGI_SWAP_EFFECT_FLIP_DISCARD` with `DXGI_PRESENT_ALLOW_TEARING` (`SyncInterval = 0`)
    /// for minimum-latency immediate presentation on VRR/high-refresh displays.
    FlipAllowTearing,
}

/// Cumulative frame-pacing telemetry counters.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PacerStats {
    /// Frames dropped by the pacing or render queue to bound latency.
    pub(crate) pacer_dropped_frames: u64,
    /// Frames successfully handed to the renderer.
    pub(crate) rendered_frames: u64,
}

/// Generic 1-to-3 frame pacer state machine (`pacer.cpp`).
#[derive(Debug)]
pub(crate) struct FramePacer<T> {
    mode: PresentationMode,
    max_video_fps: usize,
    display_fps: usize,
    pacing_queue: VecDeque<T>,
    render_queue: VecDeque<T>,
    pacing_queue_history: VecDeque<usize>,
    render_queue_history: VecDeque<usize>,
    deferred_free_frame: Option<T>,
    no_buffering_renderer: bool,
    stats: PacerStats,
}

impl<T> FramePacer<T> {
    /// Creates a new [`FramePacer`] configured for `max_video_fps`, `display_fps`, and `mode`.
    #[must_use]
    pub(crate) fn new(
        max_video_fps: u32,
        display_fps: u32,
        mode: PresentationMode,
        no_buffering_renderer: bool,
    ) -> Self {
        Self {
            mode,
            max_video_fps: (max_video_fps.max(2) as usize),
            display_fps: (display_fps.max(2) as usize),
            pacing_queue: VecDeque::with_capacity(MAX_QUEUED_FRAMES),
            render_queue: VecDeque::with_capacity(MAX_QUEUED_FRAMES),
            pacing_queue_history: VecDeque::new(),
            render_queue_history: VecDeque::new(),
            deferred_free_frame: None,
            no_buffering_renderer,
            stats: PacerStats::default(),
        }
    }

    /// Returns the active [`PresentationMode`].
    #[must_use]
    pub(crate) const fn mode(&self) -> PresentationMode {
        self.mode
    }

    /// Returns cumulative [`PacerStats`].
    #[must_use]
    pub(crate) const fn stats(&self) -> PacerStats {
        self.stats
    }

    /// Number of frames currently waiting in the V-Sync pacing queue.
    #[must_use]
    pub(crate) fn pacing_queue_len(&self) -> usize {
        self.pacing_queue.len()
    }

    /// Number of frames currently waiting in the render queue.
    #[must_use]
    pub(crate) fn render_queue_len(&self) -> usize {
        self.render_queue.len()
    }

    /// Submits a newly decoded frame into the pacer (`Pacer::submitFrame`, `pacer.cpp` lines 409–425).
    pub(crate) fn submit_frame(&mut self, frame: T) {
        match self.mode {
            PresentationMode::FlipVsyncPaced => {
                Self::drop_frame_for_enqueue(&mut self.pacing_queue, &mut self.stats);
                self.pacing_queue.push_back(frame);
            }
            PresentationMode::FlipAllowTearing => {
                self.enqueue_frame_for_rendering(frame);
            }
        }
    }

    /// Advances the V-Sync clock (`Pacer::handleVsync`, `pacer.cpp` lines 209–268),
    /// pruning excess frames from the pacing queue using the rolling `500 ms` history
    /// window and promoting the oldest surviving frame to the render queue.
    pub(crate) fn handle_vsync(&mut self) {
        let mut frame_drop_target = 1usize;

        if self.max_video_fps >= self.display_fps {
            if self.pacing_queue_history.iter().any(|&depth| depth <= 1) {
                frame_drop_target = MAX_QUEUED_FRAMES;
            }
            let history_cap = (self.display_fps / 2).max(1);
            if self.pacing_queue_history.len() >= history_cap {
                self.pacing_queue_history.pop_front();
            }
            self.pacing_queue_history.push_back(self.pacing_queue.len());
        }

        while self.pacing_queue.len() > frame_drop_target {
            self.pacing_queue.pop_front();
            self.stats.pacer_dropped_frames += 1;
        }

        if let Some(frame) = self.pacing_queue.pop_front() {
            self.enqueue_frame_for_rendering(frame);
        }
    }

    /// Dequeues the next frame ready for rendering, rotating the previous rendered frame
    /// into the single deferred-free slot (`Pacer::renderFrame`, `pacer.cpp` lines 340–398)
    /// and trimming the render queue based on the rolling `500 ms` render history.
    pub(crate) fn pop_frame_for_render(&mut self) -> Option<T> {
        let frame = self.render_queue.pop_front()?;
        self.stats.rendered_frames += 1;

        let frame_drop_target = if self.no_buffering_renderer {
            1usize
        } else {
            let target = if self.render_queue_history.iter().any(|&depth| depth == 0) {
                2usize
            } else {
                0usize
            };
            let history_cap = (self.max_video_fps / 2).max(1);
            if self.render_queue_history.len() >= history_cap {
                self.render_queue_history.pop_front();
            }
            self.render_queue_history.push_back(self.render_queue.len());
            target
        };

        while self.render_queue.len() > frame_drop_target {
            self.render_queue.pop_front();
            self.stats.pacer_dropped_frames += 1;
        }

        Some(frame)
    }

    /// Stores the just-rendered frame in the deferred-free slot so its backing surface is
    /// only released after the subsequent frame is presented (`m_DeferredFreeFrame`,
    /// `pacer.cpp` lines 353–357).
    pub(crate) fn retain_until_next_present(&mut self, rendered_frame: T) -> Option<T> {
        self.deferred_free_frame.replace(rendered_frame)
    }

    fn enqueue_frame_for_rendering(&mut self, frame: T) {
        Self::drop_frame_for_enqueue(&mut self.render_queue, &mut self.stats);
        self.render_queue.push_back(frame);
    }

    fn drop_frame_for_enqueue(queue: &mut VecDeque<T>, stats: &mut PacerStats) {
        if queue.len() >= MAX_QUEUED_FRAMES {
            queue.pop_front();
            stats.pacer_dropped_frames += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vsync_pacer_caps_queue_at_three_and_tightens_when_consistently_backed_up() {
        let mut pacer = FramePacer::new(60, 60, PresentationMode::FlipVsyncPaced, false);
        assert_eq!(PACER_MAX_OUTSTANDING_FRAMES, 5);

        // Submitting 4 frames before a VSync drops the oldest so queue never exceeds 3.
        pacer.submit_frame(1u32);
        pacer.submit_frame(2);
        pacer.submit_frame(3);
        pacer.submit_frame(4);
        assert_eq!(pacer.pacing_queue_len(), MAX_QUEUED_FRAMES);
        assert_eq!(pacer.stats().pacer_dropped_frames, 1);

        // First VSync with empty history tightens pacing queue to 1 (drops frames 2 & 3, promotes 4).
        pacer.handle_vsync();
        assert_eq!(pacer.pacing_queue_len(), 0);
        assert_eq!(pacer.render_queue_len(), 1);
        assert_eq!(pacer.pop_frame_for_render(), Some(4));
        assert_eq!(pacer.stats().rendered_frames, 1);

        // Deferred free retains frame 4 until frame 5 is presented.
        assert_eq!(pacer.retain_until_next_present(4), None);
        assert_eq!(pacer.retain_until_next_present(5), Some(4));
    }

    #[test]
    fn tearing_allowed_mode_bypasses_vsync_pacing_queue() {
        let mut pacer = FramePacer::new(120, 60, PresentationMode::FlipAllowTearing, true);
        pacer.submit_frame(10u32);
        assert_eq!(pacer.pacing_queue_len(), 0);
        assert_eq!(pacer.render_queue_len(), 1);
        assert_eq!(pacer.pop_frame_for_render(), Some(10));
    }
}
