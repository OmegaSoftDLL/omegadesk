//! Stream message framing: varint length prefix followed by an `Envelope`.

use bytes::{Buf, BytesMut};
use prost::Message;

use crate::v1::Envelope;

/// Maximum encoded size of a single frame. Protects against a peer that
/// advertises an oversized frame to exhaust memory.
pub const MAX_FRAME_LEN: usize = 16 * 1024 * 1024;

/// Framing errors.
#[derive(Debug, thiserror::Error)]
pub enum FramingError {
    /// The peer advertised a frame larger than [`MAX_FRAME_LEN`].
    #[error("frame of {len} bytes exceeds the {MAX_FRAME_LEN}-byte limit")]
    TooLarge {
        /// Advertised byte length.
        len: usize,
    },
    /// The frame payload is not a valid `Envelope`.
    #[error("invalid message: {0}")]
    Decode(#[from] prost::DecodeError),
}

/// Encodes an `Envelope` with its varint length prefix, ready to be written to a stream.
///
/// # Errors
///
/// Returns [`FramingError::TooLarge`] if the encoded message exceeds [`MAX_FRAME_LEN`].
pub fn encode_frame(envelope: &Envelope, dst: &mut BytesMut) -> Result<(), FramingError> {
    let len = envelope.encoded_len();
    if len > MAX_FRAME_LEN {
        return Err(FramingError::TooLarge { len });
    }
    dst.reserve(prost::length_delimiter_len(len) + len);
    envelope
        .encode_length_delimited(dst)
        .map_err(|_| FramingError::TooLarge { len })
}

/// Accumulates received bytes and yields complete `Envelope` frames.
#[derive(Debug, Default)]
pub struct FrameDecoder {
    buffer: BytesMut,
}

impl FrameDecoder {
    /// Creates an empty decoder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends bytes received from the network.
    pub fn extend(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }

    /// Returns the next complete `Envelope`, or `None` if more bytes are needed.
    ///
    /// # Errors
    ///
    /// Returns an error if the advertised length exceeds the limit or if the
    /// payload is malformed. After an error, the connection must be closed.
    pub fn next_frame(&mut self) -> Result<Option<Envelope>, FramingError> {
        let Some((len, prefix_len)) = peek_length(&self.buffer)? else {
            return Ok(None);
        };
        if self.buffer.len() < prefix_len + len {
            return Ok(None);
        }
        self.buffer.advance(prefix_len);
        let frame = self.buffer.split_to(len).freeze();
        Ok(Some(Envelope::decode(frame)?))
    }
}

/// Reads the varint length prefix without consuming the buffer. Returns the
/// decoded payload length and the number of bytes occupied by the varint itself.
fn peek_length(buffer: &[u8]) -> Result<Option<(usize, usize)>, FramingError> {
    // A varint of up to 10 bytes covers u64; wait for more bytes if the varint
    // is not yet terminated.
    let terminated = buffer.iter().take(10).any(|byte| byte & 0x80 == 0);
    if !terminated {
        if buffer.len() >= 10 {
            return Err(prost::DecodeError::new("invalid length varint").into());
        }
        return Ok(None);
    }
    let mut cursor = buffer;
    let len = prost::decode_length_delimiter(&mut cursor)?;
    if len > MAX_FRAME_LEN {
        return Err(FramingError::TooLarge { len });
    }
    Ok(Some((len, buffer.len() - cursor.len())))
}

#[cfg(test)]
mod tests {
    use bytes::BytesMut;

    use super::{FrameDecoder, FramingError, MAX_FRAME_LEN, encode_frame};
    use crate::v1::{Envelope, Ping, envelope::Payload};

    fn ping(sequence: u64) -> Envelope {
        Envelope {
            payload: Some(Payload::Ping(Ping {
                sequence,
                sent_at_micros: 1_000 + sequence,
            })),
        }
    }

    #[test]
    fn round_trip_several_frames() {
        let mut wire = BytesMut::new();
        for sequence in 0..3 {
            encode_frame(&ping(sequence), &mut wire).unwrap();
        }

        let mut decoder = FrameDecoder::new();
        decoder.extend(&wire);
        for sequence in 0..3 {
            assert_eq!(decoder.next_frame().unwrap(), Some(ping(sequence)));
        }
        assert_eq!(decoder.next_frame().unwrap(), None);
    }

    #[test]
    fn waits_for_partial_frame() {
        let mut wire = BytesMut::new();
        encode_frame(&ping(7), &mut wire).unwrap();

        let mut decoder = FrameDecoder::new();
        for byte in &wire[..wire.len() - 1] {
            decoder.extend(std::slice::from_ref(byte));
            assert_eq!(decoder.next_frame().unwrap(), None);
        }
        decoder.extend(&wire[wire.len() - 1..]);
        assert_eq!(decoder.next_frame().unwrap(), Some(ping(7)));
    }

    #[test]
    fn rejects_oversized_length() {
        let mut wire = BytesMut::new();
        prost::encode_length_delimiter(MAX_FRAME_LEN + 1, &mut wire).unwrap();

        let mut decoder = FrameDecoder::new();
        decoder.extend(&wire);
        assert!(matches!(
            decoder.next_frame(),
            Err(FramingError::TooLarge { .. })
        ));
    }

    #[test]
    fn rejects_unterminated_varint() {
        let mut decoder = FrameDecoder::new();
        decoder.extend(&[0xFF; 10]);
        assert!(matches!(decoder.next_frame(), Err(FramingError::Decode(_))));
    }

    mod proptests {
        use bytes::BytesMut;
        use proptest::prelude::*;

        use super::{Envelope, FrameDecoder, Payload, Ping, encode_frame};
        use crate::v1::{KeyEvent, PointerEvent, VideoFrame};

        fn arbitrary_envelope() -> impl Strategy<Value = Envelope> {
            prop_oneof![
                (any::<u64>(), any::<u64>()).prop_map(|(sequence, sent_at_micros)| Envelope {
                    payload: Some(Payload::Ping(Ping {
                        sequence,
                        sent_at_micros,
                    })),
                }),
                (any::<u32>(), any::<u32>(), any::<bool>(), any::<u32>()).prop_map(
                    |(hid_usage, keysym, pressed, modifiers)| Envelope {
                        payload: Some(Payload::KeyEvent(KeyEvent {
                            hid_usage,
                            keysym,
                            pressed,
                            modifiers,
                        })),
                    },
                ),
                (
                    any::<u32>(),
                    any::<u32>(),
                    any::<u32>(),
                    any::<i32>(),
                    any::<i32>(),
                    any::<u32>(),
                )
                    .prop_map(
                        |(x, y, buttons, wheel_x, wheel_y, display_index)| Envelope {
                            payload: Some(Payload::PointerEvent(PointerEvent {
                                x,
                                y,
                                buttons,
                                wheel_x,
                                wheel_y,
                                display_index,
                            })),
                        },
                    ),
                (
                    any::<u64>(),
                    any::<u64>(),
                    any::<bool>(),
                    any::<u32>(),
                    any::<u32>(),
                    proptest::collection::vec(any::<u8>(), 0..512),
                )
                    .prop_map(
                        |(sequence, captured_at_micros, keyframe, width, height, data)| Envelope {
                            payload: Some(Payload::VideoFrame(VideoFrame {
                                sequence,
                                captured_at_micros,
                                host_processing_micros: 0,
                                codec: 1,
                                keyframe,
                                width,
                                height,
                                display_index: 0,
                                data: data.into(),
                            })),
                        },
                    ),
            ]
        }

        proptest! {
            #[test]
            fn round_trip_with_arbitrary_chunk_boundaries(
                frames in proptest::collection::vec(arbitrary_envelope(), 0..16),
                chunk_sizes in proptest::collection::vec(1usize..128, 1..32),
            ) {
                let mut wire = BytesMut::new();
                for frame in &frames {
                    encode_frame(frame, &mut wire).unwrap();
                }

                let mut decoder = FrameDecoder::new();
                let mut decoded = Vec::new();
                let mut offset = 0;
                let mut chunk_index = 0;
                while offset < wire.len() {
                    let size = chunk_sizes[chunk_index % chunk_sizes.len()]
                        .min(wire.len() - offset);
                    decoder.extend(&wire[offset..offset + size]);
                    offset += size;
                    chunk_index += 1;
                    while let Some(envelope) = decoder.next_frame().unwrap() {
                        decoded.push(envelope);
                    }
                }
                prop_assert_eq!(decoded, frames);
                prop_assert_eq!(decoder.next_frame().unwrap(), None);
            }

            #[test]
            fn arbitrary_bytes_never_panic(
                chunks in proptest::collection::vec(
                    proptest::collection::vec(any::<u8>(), 0..256),
                    0..16,
                ),
            ) {
                let mut decoder = FrameDecoder::new();
                'stream: for chunk in &chunks {
                    decoder.extend(chunk);
                    loop {
                        match decoder.next_frame() {
                            Ok(Some(_)) => {}
                            Ok(None) => break,
                            Err(_) => break 'stream,
                        }
                    }
                }
            }
        }
    }
}
