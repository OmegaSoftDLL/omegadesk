//! `TigerVNC` TCP-Vegas latency-based congestion control for RFB/VNC and RDP
//! streams carried over reliable transports.
//!
//! Ported from `TigerVNC_tigervnc/common/rfb/Congestion.cxx` (lines 67–503):
//! `INITIAL_WINDOW = 16384`, `MINIMUM_WINDOW = 4096`, `MAXIMUM_WINDOW = 4194304`,
//! `updatePosition`, `sentPing`, `gotPong`, `isCongested`, `getBandwidth` and
//! `updateCongestion`.

use std::collections::VecDeque;

/// Initial congestion window in bytes (`16 KiB`, `Congestion.cxx` line 67).
pub const INITIAL_WINDOW: u32 = 16_384;

/// Minimum congestion window in bytes (`4 KiB`, `Congestion.cxx` line 71).
pub const MINIMUM_WINDOW: u32 = 4_096;

/// Maximum congestion window in bytes (`4 MiB`, `Congestion.cxx` line 75).
pub const MAXIMUM_WINDOW: u32 = 4_194_304;

#[derive(Debug, Clone, Copy, Default)]
struct RttInfo {
    sent_ms: u64,
    pos: u32,
    extra: u32,
    congested: bool,
}

/// Latency-based TCP-Vegas congestion controller for RFB/VNC and RDP streams over reliable
/// transports, ported directly from `TigerVNC_tigervnc/common/rfb/Congestion.cxx` (lines 67–503).
#[derive(Debug, Clone)]
pub struct VncCongestionController {
    last_position: u32,
    extra_buffer: u32,
    base_rtt_ms: Option<u32>,
    safe_base_rtt_ms: Option<u32>,
    cong_window: u32,
    in_slow_start: bool,
    measurements: u32,
    min_rtt_ms: Option<u32>,
    min_congested_rtt_ms: Option<u32>,
    last_update_ms: u64,
    last_sent_ms: u64,
    last_pong: RttInfo,
    last_pong_arrival_ms: u64,
    last_adjustment_ms: u64,
    pings: VecDeque<RttInfo>,
}

impl VncCongestionController {
    /// Creates a new congestion controller initialized to [`INITIAL_WINDOW`] (`16 KiB`) in slow start
    /// (`Congestion::Congestion()` in `Congestion.cxx` lines 84–94).
    #[must_use]
    pub fn new(now_ms: u64) -> Self {
        Self {
            last_position: 0,
            extra_buffer: 0,
            base_rtt_ms: None,
            safe_base_rtt_ms: None,
            cong_window: INITIAL_WINDOW,
            in_slow_start: true,
            measurements: 0,
            min_rtt_ms: None,
            min_congested_rtt_ms: None,
            last_update_ms: now_ms,
            last_sent_ms: now_ms,
            last_pong: RttInfo::default(),
            last_pong_arrival_ms: now_ms,
            last_adjustment_ms: now_ms,
            pings: VecDeque::new(),
        }
    }

    /// Returns the current congestion window in bytes.
    #[must_use]
    pub const fn congestion_window(&self) -> u32 {
        self.cong_window
    }

    /// Returns `true` if the controller is still in the slow-start phase.
    #[must_use]
    pub const fn in_slow_start(&self) -> bool {
        self.in_slow_start
    }

    /// Updates the stream byte position (`Congestion::updatePosition` in `Congestion.cxx` lines 100–147).
    ///
    /// The idle interval is measured against the *previous* send before this call is recorded as
    /// a send. `Congestion.cxx` lines 106–113 record first and measure after, which only detects
    /// an idle gap when a zero-delta `updatePosition` call happens to land during the pause (its
    /// writer polls that way; ours does not). Measuring first means the first bytes sent after a
    /// long pause always close the window and redo the wire latency measurement, as intended.
    pub fn update_position(&mut self, pos: u32, now_ms: u64) {
        let delta = pos.wrapping_sub(self.last_position);
        let idle_ms = u32::try_from(now_ms.saturating_sub(self.last_sent_ms)).unwrap_or(u32::MAX);
        if delta > 0 || self.extra_buffer > 0 {
            self.last_sent_ms = now_ms;
        }

        if let Some(base_rtt) = self.base_rtt_ms
            && idle_ms > 100
            && idle_ms > base_rtt.saturating_mul(2)
        {
            if self.cong_window > INITIAL_WINDOW {
                self.cong_window = INITIAL_WINDOW;
            }
            self.base_rtt_ms = None;
            self.measurements = 0;
            self.last_adjustment_ms = now_ms;
            self.min_rtt_ms = None;
            self.min_congested_rtt_ms = None;
            self.in_slow_start = true;
            // `Congestion.cxx` keeps `extraBuffer` across the reset; after an idle pause the
            // pipe has drained, so stale over-buffering bytes would make the next probes
            // subtract a delay that no longer exists and understate congestion. Drop them.
            self.extra_buffer = 0;
        }

        if let Some(base_rtt) = self.base_rtt_ms {
            self.extra_buffer = self.extra_buffer.saturating_add(delta);
            let elapsed =
                u32::try_from(now_ms.saturating_sub(self.last_update_ms)).unwrap_or(u32::MAX);
            let consumed = elapsed.saturating_mul(self.cong_window) / base_rtt.max(1);
            self.extra_buffer = self.extra_buffer.saturating_sub(consumed);
        }

        self.last_position = pos;
        self.last_update_ms = now_ms;
    }

    /// Records an outbound RTT probe (`Congestion::sentPing` in `Congestion.cxx` lines 149–161).
    pub fn sent_ping(&mut self, now_ms: u64) {
        let rtt_info = RttInfo {
            sent_ms: now_ms,
            pos: self.last_position,
            extra: self.get_extra_buffer(now_ms),
            congested: self.is_congested(now_ms),
        };
        self.pings.push_back(rtt_info);
    }

    /// Processes an inbound RTT probe response (`Congestion::gotPong` in `Congestion.cxx` lines 163–223).
    pub fn got_pong(&mut self, now_ms: u64) {
        let Some(rtt_info) = self.pings.pop_front() else {
            return;
        };

        self.last_pong = rtt_info;
        self.last_pong_arrival_ms = now_ms;

        let mut rtt = u32::try_from(now_ms.saturating_sub(rtt_info.sent_ms))
            .unwrap_or(u32::MAX)
            .max(1);

        if self.base_rtt_ms.is_none_or(|base| rtt < base) {
            self.base_rtt_ms = Some(rtt);
            self.safe_base_rtt_ms = Some(rtt);
        }

        if rtt_info.sent_ms < self.last_adjustment_ms {
            return;
        }

        let base_rtt = self.base_rtt_ms.unwrap_or(rtt).max(1);
        let delay = rtt_info.extra.saturating_mul(base_rtt) / self.cong_window.max(1);
        rtt = rtt.saturating_sub(delay).max(base_rtt);

        if self.min_rtt_ms.is_none_or(|m| rtt < m) {
            self.min_rtt_ms = Some(rtt);
        }
        if rtt_info.congested && self.min_congested_rtt_ms.is_none_or(|m| rtt < m) {
            self.min_congested_rtt_ms = Some(rtt);
        }

        self.measurements += 1;
        self.update_congestion(now_ms);
    }

    /// Returns `true` if in-flight bytes have reached or exceeded `cong_window`
    /// (`Congestion::isCongested` in `Congestion.cxx` lines 225–231).
    #[must_use]
    pub fn is_congested(&self, now_ms: u64) -> bool {
        self.get_in_flight(now_ms) >= self.cong_window
    }

    /// Estimates available bandwidth in bytes per second (`Congestion::getBandwidth` in
    /// `Congestion.cxx` lines 300–316).
    #[must_use]
    pub fn get_bandwidth(&self) -> usize {
        let rtt = self.safe_base_rtt_ms.unwrap_or(60).max(1) as usize;
        let mut bandwidth = (self.cong_window as usize) * 1000 / rtt;
        if self.in_slow_start {
            bandwidth += bandwidth / 2;
        }
        bandwidth
    }

    fn get_extra_buffer(&self, now_ms: u64) -> u32 {
        let Some(base_rtt) = self.base_rtt_ms else {
            return 0;
        };
        let elapsed = u32::try_from(now_ms.saturating_sub(self.last_update_ms)).unwrap_or(u32::MAX);
        let consumed = elapsed.saturating_mul(self.cong_window) / base_rtt.max(1);
        self.extra_buffer.saturating_sub(consumed)
    }

    fn get_in_flight(&self, now_ms: u64) -> u32 {
        if self.last_position == self.last_pong.pos {
            return 0;
        }
        let Some(base_rtt) = self.base_rtt_ms else {
            return self.last_position.wrapping_sub(self.last_pong.pos);
        };

        let next_pong = self.pings.front().copied().unwrap_or(RttInfo {
            sent_ms: self.last_update_ms,
            pos: self.last_position,
            extra: self.extra_buffer,
            congested: false,
        });

        let mut eta_next =
            u32::try_from(next_pong.sent_ms.saturating_sub(self.last_pong.sent_ms)).unwrap_or(0);
        let delay_next = next_pong.extra.saturating_mul(base_rtt) / self.cong_window.max(1);
        eta_next = eta_next.saturating_add(delay_next);
        let delay_prev = self.last_pong.extra.saturating_mul(base_rtt) / self.cong_window.max(1);
        eta_next = eta_next.saturating_sub(delay_prev);

        let elapsed =
            u32::try_from(now_ms.saturating_sub(self.last_pong_arrival_ms)).unwrap_or(u32::MAX);
        let acked = if eta_next <= elapsed || eta_next == 0 {
            next_pong.pos
        } else {
            let pos_delta = next_pong.pos.wrapping_sub(self.last_pong.pos);
            self.last_pong
                .pos
                .wrapping_add(pos_delta.saturating_mul(elapsed) / eta_next)
        };

        self.last_position.wrapping_sub(acked)
    }

    fn update_congestion(&mut self, now_ms: u64) {
        if self.measurements < 3 {
            return;
        }
        let Some(base_rtt) = self.base_rtt_ms else {
            return;
        };
        let min_rtt = self.min_rtt_ms.unwrap_or(base_rtt).max(base_rtt);
        let min_congested_rtt = self.min_congested_rtt_ms.unwrap_or(u32::MAX).max(base_rtt);

        let diff = min_rtt - base_rtt;

        if diff > 100 && diff > base_rtt / 2 {
            self.cong_window = u32::try_from(
                (u64::from(self.cong_window) * u64::from(base_rtt)) / u64::from(min_rtt),
            )
            .unwrap_or(MINIMUM_WINDOW);
            self.in_slow_start = false;
        }

        if self.in_slow_start {
            if diff > 25 {
                self.cong_window = u32::try_from(
                    (u64::from(self.cong_window) * u64::from(base_rtt)) / u64::from(min_rtt),
                )
                .unwrap_or(MINIMUM_WINDOW);
                self.in_slow_start = false;
            } else {
                let congested_diff = min_congested_rtt.saturating_sub(base_rtt);
                if congested_diff < 25 {
                    self.cong_window = self.cong_window.saturating_mul(2);
                }
            }
        } else if diff > 50 {
            self.cong_window = self.cong_window.saturating_sub(4096);
        } else {
            let congested_diff = min_congested_rtt.saturating_sub(base_rtt);
            if congested_diff < 5 {
                self.cong_window = self.cong_window.saturating_add(8192);
            } else if congested_diff < 25 {
                self.cong_window = self.cong_window.saturating_add(4096);
            }
        }

        self.cong_window = self.cong_window.clamp(MINIMUM_WINDOW, MAXIMUM_WINDOW);
        self.measurements = 0;
        self.last_adjustment_ms = now_ms;
        self.min_rtt_ms = None;
        self.min_congested_rtt_ms = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tigervnc_congestion_controller_slow_start_and_vegas_backoff() {
        let mut cc = VncCongestionController::new(1_000);
        assert_eq!(cc.congestion_window(), INITIAL_WINDOW);
        assert!(cc.in_slow_start());

        // Simulate 3 congested pings with low 10 ms RTT -> slow start doubles window to 32 KiB.
        for i in 0..3u32 {
            let t_send = 1_000 + u64::from(i) * 20;
            cc.update_position((i + 1) * 20_000, t_send);
            cc.sent_ping(t_send);
            cc.got_pong(t_send + 10);
        }
        assert_eq!(cc.congestion_window(), INITIAL_WINDOW * 2);

        // Simulate 3 pings with a latency spike (RTT jumps to 150 ms) -> leaves slow start and
        // backs off. Sends stay 50 ms apart (<= 100 ms since the previous send at t=1040) so the
        // idle reset does not fire, and all three pongs arrive 150 ms after their ping, after
        // the last send, so the clock is monotonic.
        for i in 0..3u32 {
            let t_send = 1_100 + u64::from(i) * 50;
            cc.update_position(100_000 + (i + 1) * 40_000, t_send);
            cc.sent_ping(t_send);
        }
        for i in 0..3u64 {
            cc.got_pong(1_250 + i * 50);
        }
        assert!(!cc.in_slow_start());
        assert!(cc.congestion_window() < INITIAL_WINDOW * 2);
    }

    /// Regression test for #31 `rdp/src/lib.rs:458`: the first send after a long pause resets
    /// the window and the RTT baseline, because idle time is measured against the previous send
    /// before the new send is recorded.
    #[test]
    fn congestion_controller_resets_window_when_sending_resumes_after_idle() {
        let mut cc = VncCongestionController::new(1_000);
        for i in 0..3u32 {
            let t_send = 1_000 + u64::from(i) * 20;
            cc.update_position((i + 1) * 20_000, t_send);
            cc.sent_ping(t_send);
            cc.got_pong(t_send + 10);
        }
        assert_eq!(cc.congestion_window(), INITIAL_WINDOW * 2);
        assert!(cc.in_slow_start());

        // Leave slow start with a latency spike so a reset is observable on both fields: three
        // sends 50 ms apart, then their three pongs 150 ms after each ping (monotonic clock).
        // Small sends between the pongs keep the stream from going idle (> 100 ms) while the
        // spike is being measured, as a live stream would.
        for i in 0..3u32 {
            let t_send = 1_100 + u64::from(i) * 50;
            cc.update_position(100_000 + (i + 1) * 40_000, t_send);
            cc.sent_ping(t_send);
        }
        cc.got_pong(1_250);
        cc.update_position(230_000, 1_250);
        cc.got_pong(1_300);
        cc.update_position(240_000, 1_300);
        cc.got_pong(1_350);
        assert!(!cc.in_slow_start());
        let backed_off = cc.congestion_window();

        // A large burst 51 ms after the last send leaves over-buffering bytes in `extra_buffer`.
        cc.update_position(1_250_000, 1_351);
        assert!(cc.extra_buffer > 0);

        // 5 s of silence (> 100 ms and > 2 * base RTT), then data is sent with no zero-byte
        // position update during the pause. This send itself must trigger the idle reset,
        // which also discards the stale over-buffering estimate: the pipe has drained.
        cc.update_position(1_300_000, 6_200);
        assert!(cc.in_slow_start());
        assert_eq!(cc.extra_buffer, 0);
        assert_eq!(cc.congestion_window(), INITIAL_WINDOW.min(backed_off));
        // The RTT baseline was discarded: the next pong re-measures it from scratch (300 ms
        // instead of the 10 ms learned before the pause), which the bandwidth estimate exposes.
        cc.sent_ping(6_200);
        cc.got_pong(6_500);
        let at_300ms_rtt = (cc.congestion_window() as usize) * 1000 / 300;
        assert_eq!(cc.get_bandwidth(), at_300ms_rtt + at_300ms_rtt / 2);

        // A short gap does not reset: the window keeps growing from where it was.
        let mut steady = VncCongestionController::new(0);
        for i in 0..3u32 {
            let t_send = u64::from(i) * 20;
            steady.update_position((i + 1) * 20_000, t_send);
            steady.sent_ping(t_send);
            steady.got_pong(t_send + 10);
        }
        assert_eq!(steady.congestion_window(), INITIAL_WINDOW * 2);
        steady.update_position(80_000, 120);
        assert_eq!(steady.congestion_window(), INITIAL_WINDOW * 2);
    }
}
