//! State shared between the network task, the decoder thread, and the window.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use omegadesk_codec::DecodedImage;
use omegadesk_protocol::v1::DisplayList;

use crate::channels::displays::DisplayState;

/// Most recently decoded video frame along with its per-stage latency measurements.
#[derive(Debug)]
pub(crate) struct LatestFrame {
    pub(crate) image: DecodedImage,
    pub(crate) host_processing: Duration,
    pub(crate) decode: Duration,
    pub(crate) decoded_at: Instant,
}

#[derive(Debug, Default)]
struct Inner {
    latest: Mutex<Option<LatestFrame>>,
    rtt_micros: AtomicU64,
    status: Mutex<String>,
    displays: Mutex<DisplayState>,
}

/// Cheaply cloneable handle to shared client state.
#[derive(Debug, Clone, Default)]
pub(crate) struct Shared(Arc<Inner>);

impl Shared {
    pub(crate) fn publish(&self, frame: LatestFrame) {
        *self.0.latest.lock().unwrap_or_else(PoisonError::into_inner) = Some(frame);
    }

    pub(crate) fn take_latest(&self) -> Option<LatestFrame> {
        self.0
            .latest
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
    }

    pub(crate) fn set_rtt(&self, rtt: Duration) {
        let micros = u64::try_from(rtt.as_micros()).unwrap_or(u64::MAX);
        self.0.rtt_micros.store(micros, Ordering::Relaxed);
    }

    pub(crate) fn rtt(&self) -> Duration {
        Duration::from_micros(self.0.rtt_micros.load(Ordering::Relaxed))
    }

    pub(crate) fn set_status(&self, status: impl Into<String>) {
        *self.0.status.lock().unwrap_or_else(PoisonError::into_inner) = status.into();
    }

    pub(crate) fn status(&self) -> String {
        self.0
            .status
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Stores the agent's latest monitor catalog announcement.
    pub(crate) fn set_displays(&self, list: DisplayList) {
        self.0
            .displays
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .update(list);
    }

    /// Snapshot of the agent's monitor catalog.
    pub(crate) fn displays(&self) -> DisplayState {
        self.0
            .displays
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Agent index of the display being streamed.
    pub(crate) fn active_display(&self) -> u32 {
        self.0
            .displays
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .active_index()
    }
}

/// Sliding window accumulator for latency metrics displayed in the window title bar.
#[derive(Debug, Default)]
pub(crate) struct Meter {
    frames: u32,
    host: Duration,
    decode: Duration,
    render: Duration,
    window_start: Option<Instant>,
}

/// Average latency breakdown over a measurement window.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Summary {
    pub(crate) fps: f64,
    pub(crate) host: Duration,
    pub(crate) network: Duration,
    pub(crate) decode: Duration,
    pub(crate) render: Duration,
}

impl Summary {
    pub(crate) fn total(&self) -> Duration {
        self.host + self.network + self.decode + self.render
    }
}

impl Meter {
    pub(crate) fn record(&mut self, host: Duration, decode: Duration, render: Duration) {
        self.window_start.get_or_insert_with(Instant::now);
        self.frames += 1;
        self.host += host;
        self.decode += decode;
        self.render += render;
    }

    /// Returns the window summary once `period` has elapsed and resets the accumulator.
    pub(crate) fn summary(&mut self, period: Duration, rtt: Duration) -> Option<Summary> {
        let start = self.window_start?;
        let elapsed = start.elapsed();
        if elapsed < period || self.frames == 0 {
            return None;
        }
        let frames = self.frames;
        let summary = Summary {
            fps: f64::from(frames) / elapsed.as_secs_f64(),
            host: self.host / frames,
            network: rtt / 2,
            decode: self.decode / frames,
            render: self.render / frames,
        };
        *self = Self::default();
        Some(summary)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::Meter;

    #[test]
    fn meter_averages() {
        let mut meter = Meter::default();
        meter.record(
            Duration::from_millis(4),
            Duration::from_millis(2),
            Duration::from_millis(1),
        );
        meter.record(
            Duration::from_millis(6),
            Duration::from_millis(4),
            Duration::from_millis(3),
        );
        let summary = meter
            .summary(Duration::ZERO, Duration::from_millis(2))
            .unwrap();
        assert_eq!(summary.host, Duration::from_millis(5));
        assert_eq!(summary.decode, Duration::from_millis(3));
        assert_eq!(summary.render, Duration::from_millis(2));
        assert_eq!(summary.network, Duration::from_millis(1));
        assert_eq!(summary.total(), Duration::from_millis(11));
        assert!(meter.summary(Duration::ZERO, Duration::ZERO).is_none());
    }
}
