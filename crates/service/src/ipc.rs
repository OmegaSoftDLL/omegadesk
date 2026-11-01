//! Service <-> worker IPC over a local named pipe with length-delimited
//! protobuf framing.
//!
//! The framing mirrors `omegadesk_protocol::framing` (a protobuf varint length
//! prefix followed by the encoded message), reused here for the
//! [`ServiceEnvelope`] IPC messages generated in `omegadesk-protocol`. The
//! transport choice (a Windows named pipe rather than a loopback QUIC socket)
//! follows the references that solve exactly this problem: RustDesk
//! (`src/ipc.rs`, a `parity-tokio-ipc` named pipe named per role) and Aspia
//! (`source/base/ipc/ipc_channel.cc`, a `\\.\pipe\` channel between the
//! `host_service` and each `desktop_session`/`user_session`). A named pipe
//! needs no TCP/UDP port, is reachable before the network stack is up at the
//! login screen, and is secured by the pipe DACL (SYSTEM and Administrators
//! only) instead of a TLS handshake, which is what a same-machine
//! service-to-worker channel wants.
//!
//! [`IpcConnection`] is generic over any `AsyncRead + AsyncWrite` stream, so the
//! exact same send/receive path is exercised by the Windows named pipe and by
//! the in-memory `tokio::io::duplex` streams used in the cross-platform tests.

use bytes::{Buf, BytesMut};
use omegadesk_protocol::service::v1::ServiceEnvelope;
use prost::Message;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Base name of the service control pipe. The full path is built by
/// [`pipe_path`].
pub const PIPE_BASE_NAME: &str = "omegadesk-service";

/// Maximum encoded size of a single IPC frame. Control messages are tiny; the
/// cap only protects the reader from a corrupt or hostile length prefix.
pub const MAX_IPC_FRAME_LEN: usize = 4 * 1024 * 1024;

/// Builds the full named-pipe path for a control pipe `instance` (so each
/// worker launch can use a unique pipe and old instances cannot be
/// impersonated). Example: `\\.\pipe\omegadesk-service.3`.
#[must_use]
pub fn pipe_path(instance: &str) -> String {
    format!(r"\\.\pipe\{PIPE_BASE_NAME}.{instance}")
}

/// IPC errors.
#[derive(Debug, thiserror::Error)]
pub enum IpcError {
    /// The peer advertised a frame larger than [`MAX_IPC_FRAME_LEN`].
    #[error("IPC frame of {len} bytes exceeds the {MAX_IPC_FRAME_LEN}-byte limit")]
    TooLarge {
        /// Advertised byte length.
        len: usize,
    },
    /// The frame payload is not a valid [`ServiceEnvelope`].
    #[error("invalid IPC message: {0}")]
    Decode(#[from] prost::DecodeError),
    /// The underlying transport failed.
    #[error("IPC transport error: {0}")]
    Io(#[from] std::io::Error),
    /// The peer closed the connection cleanly.
    #[error("the IPC peer closed the connection")]
    Closed,
}

/// Encodes a [`ServiceEnvelope`] with its varint length prefix into `dst`.
///
/// # Errors
///
/// Returns [`IpcError::TooLarge`] if the encoded message exceeds
/// [`MAX_IPC_FRAME_LEN`].
pub fn encode_frame(envelope: &ServiceEnvelope, dst: &mut BytesMut) -> Result<(), IpcError> {
    let len = envelope.encoded_len();
    if len > MAX_IPC_FRAME_LEN {
        return Err(IpcError::TooLarge { len });
    }
    dst.reserve(prost::length_delimiter_len(len) + len);
    envelope
        .encode_length_delimited(dst)
        .map_err(|_| IpcError::TooLarge { len })
}

/// Accumulates received bytes and yields complete [`ServiceEnvelope`] frames,
/// ported from `omegadesk_protocol::framing::FrameDecoder`.
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

    /// Appends bytes received from the pipe.
    pub fn extend(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }

    /// Returns the next complete [`ServiceEnvelope`], or `None` if more bytes
    /// are needed.
    ///
    /// # Errors
    ///
    /// Returns [`IpcError::TooLarge`] if the advertised length exceeds the
    /// limit, or [`IpcError::Decode`] if the payload is malformed. After an
    /// error the connection must be closed.
    pub fn next_frame(&mut self) -> Result<Option<ServiceEnvelope>, IpcError> {
        let Some((len, prefix_len)) = peek_length(&self.buffer)? else {
            return Ok(None);
        };
        if self.buffer.len() < prefix_len + len {
            return Ok(None);
        }
        self.buffer.advance(prefix_len);
        let frame = self.buffer.split_to(len).freeze();
        Ok(Some(ServiceEnvelope::decode(frame)?))
    }
}

/// Reads the varint length prefix without consuming the buffer. Returns the
/// payload length and the number of bytes the varint occupies, or `None` when
/// the prefix is still incomplete.
fn peek_length(buffer: &BytesMut) -> Result<Option<(usize, usize)>, IpcError> {
    // A protobuf varint length delimiter is at most 10 bytes.
    let mut tmp = &buffer[..buffer.len().min(10)];
    let before = tmp.remaining();
    match prost::decode_length_delimiter(&mut tmp) {
        Ok(len) => {
            if len > MAX_IPC_FRAME_LEN {
                return Err(IpcError::TooLarge { len });
            }
            Ok(Some((len, before - tmp.remaining())))
        }
        // Not enough bytes yet for a complete varint.
        Err(_) if buffer.len() < 10 => Ok(None),
        Err(error) => Err(IpcError::Decode(error)),
    }
}

/// The read half of a framed IPC connection.
#[derive(Debug)]
pub struct FramedReader<R> {
    reader: R,
    decoder: FrameDecoder,
    scratch: Vec<u8>,
}

impl<R: AsyncRead + Unpin> FramedReader<R> {
    /// Wraps an async reader.
    pub fn new(reader: R) -> Self {
        Self {
            reader,
            decoder: FrameDecoder::new(),
            scratch: vec![0u8; 16 * 1024],
        }
    }

    /// Receives the next [`ServiceEnvelope`], reading until a full frame is
    /// available.
    ///
    /// # Errors
    ///
    /// Returns [`IpcError::Closed`] if the peer closed the connection,
    /// [`IpcError::Io`] on a transport error, or a framing error on a corrupt
    /// message.
    pub async fn recv(&mut self) -> Result<ServiceEnvelope, IpcError> {
        loop {
            if let Some(envelope) = self.decoder.next_frame()? {
                return Ok(envelope);
            }
            let read = self.reader.read(&mut self.scratch).await?;
            if read == 0 {
                return Err(IpcError::Closed);
            }
            self.decoder.extend(&self.scratch[..read]);
        }
    }
}

/// The write half of a framed IPC connection.
#[derive(Debug)]
pub struct FramedWriter<W> {
    writer: W,
    buffer: BytesMut,
}

impl<W: AsyncWrite + Unpin> FramedWriter<W> {
    /// Wraps an async writer.
    pub fn new(writer: W) -> Self {
        Self {
            writer,
            buffer: BytesMut::new(),
        }
    }

    /// Sends one [`ServiceEnvelope`], flushing it to the stream.
    ///
    /// # Errors
    ///
    /// Returns [`IpcError::TooLarge`] if the message is oversized, or
    /// [`IpcError::Io`] if the write fails.
    pub async fn send(&mut self, envelope: &ServiceEnvelope) -> Result<(), IpcError> {
        self.buffer.clear();
        encode_frame(envelope, &mut self.buffer)?;
        self.writer.write_all(&self.buffer).await?;
        self.writer.flush().await?;
        Ok(())
    }
}

/// A framed, full-duplex IPC connection over any async byte stream (a Windows
/// named pipe in production, an in-memory duplex stream in tests). It can be
/// [`split`](Self::split) into independent reader and writer halves so a
/// reader task and a writer handle can run concurrently.
#[derive(Debug)]
pub struct IpcConnection<S> {
    reader: FramedReader<tokio::io::ReadHalf<S>>,
    writer: FramedWriter<tokio::io::WriteHalf<S>>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> IpcConnection<S> {
    /// Wraps `stream` in a framed full-duplex connection.
    pub fn new(stream: S) -> Self {
        let (read_half, write_half) = tokio::io::split(stream);
        Self {
            reader: FramedReader::new(read_half),
            writer: FramedWriter::new(write_half),
        }
    }

    /// Sends one [`ServiceEnvelope`].
    ///
    /// # Errors
    ///
    /// See [`FramedWriter::send`].
    pub async fn send(&mut self, envelope: &ServiceEnvelope) -> Result<(), IpcError> {
        self.writer.send(envelope).await
    }

    /// Receives the next [`ServiceEnvelope`].
    ///
    /// # Errors
    ///
    /// See [`FramedReader::recv`].
    pub async fn recv(&mut self) -> Result<ServiceEnvelope, IpcError> {
        self.reader.recv().await
    }

    /// Splits the connection into independent reader and writer halves.
    #[must_use]
    pub fn split(
        self,
    ) -> (
        FramedReader<tokio::io::ReadHalf<S>>,
        FramedWriter<tokio::io::WriteHalf<S>>,
    ) {
        (self.reader, self.writer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use omegadesk_protocol::service::v1::{
        DesktopDirective, Heartbeat, WorkerHello, service_envelope::Message as SvcMessage,
    };

    fn directive(name: &str) -> ServiceEnvelope {
        ServiceEnvelope {
            message: Some(SvcMessage::DesktopDirective(DesktopDirective {
                desktop_name: name.to_owned(),
            })),
        }
    }

    #[test]
    fn roundtrip_single_frame() {
        let mut buf = BytesMut::new();
        encode_frame(&directive("Winlogon"), &mut buf).unwrap();
        let mut decoder = FrameDecoder::new();
        decoder.extend(&buf);
        let decoded = decoder.next_frame().unwrap().unwrap();
        assert_eq!(decoded, directive("Winlogon"));
        assert!(decoder.next_frame().unwrap().is_none());
    }

    #[test]
    fn decoder_reassembles_across_byte_boundaries() {
        let mut buf = BytesMut::new();
        encode_frame(&directive("Default"), &mut buf).unwrap();
        encode_frame(
            &ServiceEnvelope {
                message: Some(SvcMessage::Heartbeat(Heartbeat { monotonic_ms: 42 })),
            },
            &mut buf,
        )
        .unwrap();
        let mut decoder = FrameDecoder::new();
        // Feed one byte at a time: frames must reassemble regardless of chunking.
        let mut seen = Vec::new();
        for byte in &buf {
            decoder.extend(std::slice::from_ref(byte));
            while let Some(frame) = decoder.next_frame().unwrap() {
                seen.push(frame);
            }
        }
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[0], directive("Default"));
    }

    #[test]
    fn oversized_length_prefix_is_rejected() {
        // Encode a length delimiter far above the cap followed by no payload.
        let mut buf = BytesMut::new();
        prost::encode_length_delimiter(MAX_IPC_FRAME_LEN + 1, &mut buf).unwrap();
        let mut decoder = FrameDecoder::new();
        decoder.extend(&buf);
        assert!(matches!(
            decoder.next_frame(),
            Err(IpcError::TooLarge { .. })
        ));
    }

    #[test]
    fn pipe_path_is_per_instance() {
        assert_eq!(pipe_path("7"), r"\\.\pipe\omegadesk-service.7");
        assert_ne!(pipe_path("1"), pipe_path("2"));
    }

    #[tokio::test]
    async fn connection_sends_and_receives_over_a_duplex_stream() {
        let (client, server) = tokio::io::duplex(256);
        let mut client = IpcConnection::new(client);
        let mut server = IpcConnection::new(server);

        let hello = ServiceEnvelope {
            message: Some(SvcMessage::WorkerHello(WorkerHello {
                protocol_version: 1,
                session_id: 2,
                pid: 1234,
            })),
        };
        client.send(&hello).await.unwrap();
        assert_eq!(server.recv().await.unwrap(), hello);

        server.send(&directive("Winlogon")).await.unwrap();
        assert_eq!(client.recv().await.unwrap(), directive("Winlogon"));

        // Dropping the writer makes the reader observe a clean close.
        drop(client);
        assert!(matches!(server.recv().await, Err(IpcError::Closed)));
    }
}
