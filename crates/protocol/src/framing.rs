//! Enquadramento de mensagens em streams: tamanho em varint + Envelope.

use bytes::{Buf, BytesMut};
use prost::Message;

use crate::v1::Envelope;

/// Tamanho máximo de um quadro. Protege contra um peer que anuncia um tamanho
/// gigante para esgotar a memória.
pub const MAX_FRAME_LEN: usize = 16 * 1024 * 1024;

/// Erros de enquadramento.
#[derive(Debug, thiserror::Error)]
pub enum FramingError {
    /// O peer anunciou um quadro maior que [`MAX_FRAME_LEN`].
    #[error("quadro de {len} bytes excede o limite de {MAX_FRAME_LEN}")]
    TooLarge {
        /// Tamanho anunciado.
        len: usize,
    },
    /// O conteúdo do quadro não é um `Envelope` válido.
    #[error("mensagem inválida: {0}")]
    Decode(#[from] prost::DecodeError),
}

/// Codifica um `Envelope` com o prefixo de tamanho, pronto para o stream.
///
/// # Errors
///
/// Retorna [`FramingError::TooLarge`] se a mensagem passar de [`MAX_FRAME_LEN`].
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

/// Acumula bytes recebidos e devolve os `Envelope`s completos.
#[derive(Debug, Default)]
pub struct FrameDecoder {
    buffer: BytesMut,
}

impl FrameDecoder {
    /// Cria um decodificador vazio.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adiciona bytes recebidos da rede.
    pub fn extend(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }

    /// Devolve o próximo `Envelope` completo, ou `None` se ainda faltam bytes.
    ///
    /// # Errors
    ///
    /// Retorna erro se o tamanho anunciado passar do limite ou se o conteúdo
    /// for inválido. Depois de um erro, a conexão deve ser encerrada.
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

/// Lê o varint de tamanho sem consumir o buffer. Devolve o tamanho e quantos
/// bytes o próprio varint ocupa.
fn peek_length(buffer: &[u8]) -> Result<Option<(usize, usize)>, FramingError> {
    // Um varint de até 10 bytes cobre u64; esperar mais bytes se o varint
    // ainda não terminou.
    let terminated = buffer.iter().take(10).any(|byte| byte & 0x80 == 0);
    if !terminated {
        if buffer.len() >= 10 {
            return Err(prost::DecodeError::new("varint de tamanho inválido").into());
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
