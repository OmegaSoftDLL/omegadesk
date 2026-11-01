//! Client half of the video QoS loop: one `FrameAck` per decoded frame
//! carrying the host capture timestamp (so the agent measures end-to-end
//! delay on its own clock), the decode time and the depth of the decode queue
//! behind this frame (Selkies `websockets_mode.py` per-frame ACK, RustDesk
//! `video_qos.rs` `user_delay_response_elapsed`).

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use omegadesk_protocol::v1::{Envelope, FrameAck, VideoFrame, envelope::Payload};

/// Number of frames waiting in the decoder queue, shared between the network
/// task that enqueues and the decoder thread that dequeues.
#[derive(Debug, Clone, Default)]
pub(crate) struct DecodeQueueDepth(Arc<AtomicUsize>);

impl DecodeQueueDepth {
    /// A frame was queued for decoding.
    pub(crate) fn enqueued(&self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }

    /// A frame left the queue; returns the number still waiting behind it.
    pub(crate) fn dequeued(&self) -> usize {
        let mut current = self.0.load(Ordering::Relaxed);
        loop {
            let next = current.saturating_sub(1);
            match self
                .0
                .compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed)
            {
                Ok(_) => return next,
                Err(actual) => current = actual,
            }
        }
    }

    #[cfg(test)]
    fn depth(&self) -> usize {
        self.0.load(Ordering::Relaxed)
    }
}

/// Builds the acknowledgement for `frame`, decoded in `decode` with
/// `queue_depth` frames still waiting behind it.
pub(crate) fn frame_ack(frame: &VideoFrame, decode: Duration, queue_depth: usize) -> Envelope {
    Envelope {
        payload: Some(Payload::FrameAck(FrameAck {
            frame_sequence: frame.sequence,
            captured_at_micros: frame.captured_at_micros,
            decode_micros: u32::try_from(decode.as_micros()).unwrap_or(u32::MAX),
            queue_depth: u32::try_from(queue_depth).unwrap_or(u32::MAX),
        })),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ack_echoes_the_host_timestamp_and_measures_decode_and_queue() {
        let frame = VideoFrame {
            sequence: 42,
            captured_at_micros: 1_700_000_000_000_000,
            ..VideoFrame::default()
        };
        let envelope = frame_ack(&frame, Duration::from_micros(4_321), 2);
        let Some(Payload::FrameAck(ack)) = envelope.payload else {
            panic!("not a FrameAck");
        };
        assert_eq!(ack.frame_sequence, 42);
        assert_eq!(ack.captured_at_micros, 1_700_000_000_000_000);
        assert_eq!(ack.decode_micros, 4_321);
        assert_eq!(ack.queue_depth, 2);
    }

    #[test]
    fn queue_depth_counts_frames_behind_the_one_being_decoded() {
        let depth = DecodeQueueDepth::default();
        assert_eq!(depth.dequeued(), 0, "never negative");
        depth.enqueued();
        depth.enqueued();
        depth.enqueued();
        assert_eq!(depth.depth(), 3);
        assert_eq!(depth.dequeued(), 2);
        assert_eq!(depth.dequeued(), 1);
        assert_eq!(depth.dequeued(), 0);
        assert_eq!(depth.dequeued(), 0);
    }
}
