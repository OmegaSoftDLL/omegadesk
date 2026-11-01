//! Session channels: clipboard synchronization (text, HTML, file lists), chunked
//! file transfer with resume and SHA-256 verification, Opus `RESTRICTED_LOWDELAY`
//! audio framing, multi-monitor switching, chat, and terminal streams.
//!
//! Reference architectures:
//! - **Sunshine `src/audio.cpp`** (GPL-3.0): 48 kHz `RESTRICTED_LOWDELAY` Opus
//!   stream configurations (`96 kbps` / `512 kbps` stereo, `256 kbps` 5.1, `450 kbps` 7.1).
//! - **Aspia `source/common/file_packetizer.cc` & RustDesk `libs/hbb_common/src/fs.rs`**:
//!   Chunked file transfer with path-traversal sanitization, byte-offset resume,
//!   and end-to-end SHA-256 verification.

use bytes::Bytes;
use omegadesk_protocol::v1::{
    AudioFrame, ChatMessage, ClipboardEvent, ClipboardFormat, DisplayDescriptor, DisplayList,
    FileTransferAck, FileTransferChunk, FileTransferOffer, SelectDisplay, TerminalData,
    TerminalResize,
};
use sha2::{Digest, Sha256};

/// Standard 48 kHz sample rate required by Opus (`SAMPLE_RATE` in Sunshine `src/audio.cpp`).
pub const OPUS_SAMPLE_RATE: u32 = 48_000;

/// Default file transfer chunk size (`64 KiB`).
pub const DEFAULT_FILE_CHUNK_SIZE: usize = 64 * 1024;

/// Maximum allowed clipboard payload size (`16 MiB`).
pub const MAX_CLIPBOARD_BYTES: usize = 16 * 1024 * 1024;

/// Errors returned by session channel state machines.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ChannelError {
    /// Clipboard payload exceeds [`MAX_CLIPBOARD_BYTES`].
    #[error("clipboard payload size {0} exceeds 16 MiB limit")]
    ClipboardTooLarge(usize),
    /// Clipboard event digest does not match its payload bytes.
    #[error("clipboard SHA-256 digest mismatch")]
    ClipboardDigestMismatch,
    /// Relative path in a file transfer offer is unsafe (contains `..`, leading `/`, or drive letters).
    #[error("unsafe file transfer relative path: {0}")]
    UnsafeRelativePath(String),
    /// File transfer chunk offset does not match the expected write position.
    #[error("unexpected file chunk offset: expected {expected}, got {actual}")]
    UnexpectedFileOffset {
        /// Expected byte offset.
        expected: u64,
        /// Actual chunk byte offset.
        actual: u64,
    },
    /// Assembled file size or SHA-256 digest did not match the offer.
    #[error("file transfer SHA-256 integrity verification failed")]
    FileIntegrityFailed,
    /// A chunk (or the offer's resume offset) would push the received bytes past the
    /// advertised `total_bytes`, so withholding `eof` cannot bypass the size bound.
    #[error("file transfer chunk ends at {attempted} bytes, exceeding advertised {total_bytes}")]
    FileSizeExceeded {
        /// Advertised total file size from the offer.
        total_bytes: u64,
        /// End offset the rejected chunk would have reached.
        attempted: u64,
    },
    /// The transfer already completed (verified) or failed; no further chunks are accepted.
    #[error("file transfer is no longer accepting chunks")]
    TransferClosed,
    /// Requested display index does not exist in the host's [`MonitorCatalog`].
    #[error("unknown display index: {0}")]
    UnknownDisplayIndex(u32),
}

/// Deduplicating bidirectional clipboard synchronization state machine.
///
/// The dedup key is `(format, SHA-256)`: the same bytes copied as `Utf8Text` and
/// then as `Html` are different clipboard contents and both reach the peer, while a
/// true echo (same format, same bytes) is still suppressed.
#[derive(Debug, Default, Clone)]
pub struct ClipboardSync {
    last_content: Option<(i32, [u8; 32])>,
}

impl ClipboardSync {
    /// Creates a new [`ClipboardSync`] tracker.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Prepares an outbound [`ClipboardEvent`] if the local clipboard content has
    /// changed since the last local or remote update (suppressing echo loops).
    ///
    /// # Errors
    ///
    /// Returns [`ChannelError::ClipboardTooLarge`] if `data` exceeds [`MAX_CLIPBOARD_BYTES`].
    pub fn prepare_outbound(
        &mut self,
        format: ClipboardFormat,
        data: &[u8],
    ) -> Result<Option<ClipboardEvent>, ChannelError> {
        if data.len() > MAX_CLIPBOARD_BYTES {
            return Err(ChannelError::ClipboardTooLarge(data.len()));
        }
        let digest = sha256_bytes(data);
        let key = (format as i32, digest);
        if self.last_content == Some(key) {
            return Ok(None);
        }
        self.last_content = Some(key);
        Ok(Some(ClipboardEvent {
            format: format as i32,
            data: Bytes::copy_from_slice(data),
            content_sha256: Bytes::copy_from_slice(&digest),
        }))
    }

    /// Processes an inbound [`ClipboardEvent`] from the remote peer, returning
    /// `Ok(Some((format, bytes)))` if it is new content that should be applied to
    /// the local OS clipboard.
    ///
    /// # Errors
    ///
    /// Returns [`ChannelError`] if the payload is oversized or its SHA-256 digest is invalid.
    pub fn accept_inbound(
        &mut self,
        event: &ClipboardEvent,
    ) -> Result<Option<(ClipboardFormat, Vec<u8>)>, ChannelError> {
        if event.data.len() > MAX_CLIPBOARD_BYTES {
            return Err(ChannelError::ClipboardTooLarge(event.data.len()));
        }
        let computed = sha256_bytes(&event.data);
        if event.content_sha256.as_ref() != computed {
            return Err(ChannelError::ClipboardDigestMismatch);
        }
        let key = (event.format, computed);
        if self.last_content == Some(key) {
            return Ok(None);
        }
        self.last_content = Some(key);
        let format =
            ClipboardFormat::try_from(event.format).unwrap_or(ClipboardFormat::Unspecified);
        Ok(Some((format, event.data.to_vec())))
    }
}

/// Validates that a file transfer relative path contains no directory traversal
/// (`..`), absolute roots, or Windows drive colons.
///
/// # Errors
///
/// Returns [`ChannelError::UnsafeRelativePath`] if the path is unsafe.
pub fn validate_relative_path(path: &str) -> Result<(), ChannelError> {
    if path.is_empty()
        || path.starts_with('/')
        || path.starts_with('\\')
        || path.contains(':')
        || path.contains('\0')
    {
        return Err(ChannelError::UnsafeRelativePath(path.to_owned()));
    }
    for segment in path.split(['/', '\\']) {
        if segment.is_empty() || segment == "." || segment == ".." {
            return Err(ChannelError::UnsafeRelativePath(path.to_owned()));
        }
    }
    Ok(())
}

/// Sender-side state machine for chunked file transfer with byte-offset resume.
#[derive(Debug, Clone)]
pub struct FileTransferSender {
    transfer_id: u64,
    relative_path: String,
    data: Bytes,
    file_sha256: [u8; 32],
    offset: usize,
    chunk_size: usize,
    /// Set once the single `eof` chunk has been produced, independently of `offset`,
    /// so a 0-byte file or a transfer resumed at its full length still emits exactly
    /// one final chunk and then stops.
    eof_sent: bool,
}

impl FileTransferSender {
    /// Creates a new [`FileTransferSender`] for `relative_path` and `data`,
    /// starting at `resume_offset`.
    ///
    /// # Errors
    ///
    /// Returns [`ChannelError::UnsafeRelativePath`] if `relative_path` is unsafe.
    pub fn new(
        transfer_id: u64,
        relative_path: &str,
        data: impl Into<Bytes>,
        resume_offset: usize,
    ) -> Result<Self, ChannelError> {
        validate_relative_path(relative_path)?;
        let bytes = data.into();
        let file_sha256 = sha256_bytes(&bytes);
        let clamped_offset = resume_offset.min(bytes.len());
        Ok(Self {
            transfer_id,
            relative_path: relative_path.to_owned(),
            data: bytes,
            file_sha256,
            offset: clamped_offset,
            chunk_size: DEFAULT_FILE_CHUNK_SIZE,
            eof_sent: false,
        })
    }

    /// Builds the initial [`FileTransferOffer`] message.
    #[must_use]
    pub fn offer(&self) -> FileTransferOffer {
        FileTransferOffer {
            transfer_id: self.transfer_id,
            relative_path: self.relative_path.clone(),
            total_bytes: u64::try_from(self.data.len()).unwrap_or(u64::MAX),
            file_sha256: Bytes::copy_from_slice(&self.file_sha256),
            resume_offset: u64::try_from(self.offset).unwrap_or(0),
        }
    }

    /// Produces the next [`FileTransferChunk`], or `None` once the `eof` chunk has been sent.
    ///
    /// Exactly one chunk carries `eof = true`. For a 0-byte file, or a transfer resumed
    /// at its full length, that is a single empty chunk so the receiver still verifies
    /// completion (mirrors the final `FileTransferDone` that RustDesk's
    /// `src/server/connection.rs` sends after the last block).
    pub fn next_chunk(&mut self) -> Option<FileTransferChunk> {
        if self.eof_sent {
            return None;
        }
        let chunk_offset = u64::try_from(self.offset).unwrap_or(u64::MAX);
        let end = self
            .offset
            .saturating_add(self.chunk_size)
            .min(self.data.len());
        let slice = self.data.slice(self.offset..end);
        self.offset = end;
        let eof = self.offset >= self.data.len();
        self.eof_sent = eof;
        Some(FileTransferChunk {
            transfer_id: self.transfer_id,
            offset: chunk_offset,
            data: slice,
            eof,
        })
    }
}

/// Lifecycle of a [`FileTransferReceiver`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReceiveState {
    /// Chunks are still being appended.
    InProgress,
    /// The `eof` chunk arrived and size + SHA-256 matched the offer.
    Verified,
    /// Size or SHA-256 verification failed; the buffer may only be used for resume.
    Failed,
}

/// Receiver-side state machine for chunked file transfer with resume and SHA-256
/// integrity verification.
///
/// The advertised `total_bytes` is enforced on **every** chunk (not only at `eof`), the
/// way RustDesk's `TransferJob::write` in `libs/base/src/fs.rs` bounds each block by the
/// announced file entry: a peer that offers a tiny file cannot stream unbounded,
/// correctly offset `eof = false` chunks into memory.
#[derive(Debug, Clone)]
pub struct FileTransferReceiver {
    transfer_id: u64,
    relative_path: String,
    total_bytes: u64,
    expected_sha256: [u8; 32],
    buffer: Vec<u8>,
    state: ReceiveState,
}

impl FileTransferReceiver {
    /// Accepts a [`FileTransferOffer`], optionally seeding `existing_partial` bytes
    /// for resumed transfers.
    ///
    /// # Errors
    ///
    /// Returns [`ChannelError`] if the path is unsafe, the SHA-256 field is not 32
    /// bytes, or `resume_offset` already exceeds `total_bytes`.
    pub fn from_offer(
        offer: &FileTransferOffer,
        existing_partial: Vec<u8>,
    ) -> Result<Self, ChannelError> {
        validate_relative_path(&offer.relative_path)?;
        let Ok(expected_sha256) = <[u8; 32]>::try_from(offer.file_sha256.as_ref()) else {
            return Err(ChannelError::FileIntegrityFailed);
        };
        if offer.resume_offset > offer.total_bytes {
            return Err(ChannelError::FileSizeExceeded {
                total_bytes: offer.total_bytes,
                attempted: offer.resume_offset,
            });
        }
        let expected_resume = usize::try_from(offer.resume_offset).unwrap_or(0);
        let mut buffer = existing_partial;
        buffer.truncate(expected_resume);

        Ok(Self {
            transfer_id: offer.transfer_id,
            relative_path: offer.relative_path.clone(),
            total_bytes: offer.total_bytes,
            expected_sha256,
            buffer,
            state: ReceiveState::InProgress,
        })
    }

    /// Relative destination path of this transfer.
    #[must_use]
    pub fn relative_path(&self) -> &str {
        &self.relative_path
    }

    /// Returns `true` once the `eof` chunk arrived and size + SHA-256 verified.
    #[must_use]
    pub fn is_verified(&self) -> bool {
        self.state == ReceiveState::Verified
    }

    /// Bytes received so far (possibly incomplete or unverified), for persisting a
    /// `.partial` file and resuming via [`FileTransferOffer::resume_offset`].
    #[must_use]
    pub fn partial_bytes(&self) -> &[u8] {
        &self.buffer
    }

    /// Appends a [`FileTransferChunk`] and returns a [`FileTransferAck`].
    ///
    /// Every chunk is bounded by the offer's `total_bytes`. When `chunk.eof` is set,
    /// verifies both the total byte count and the full-file SHA-256 digest before
    /// setting `verified = true`.
    ///
    /// # Errors
    ///
    /// Returns [`ChannelError::FileSizeExceeded`] if the chunk would exceed `total_bytes`
    /// (nothing is buffered), [`ChannelError::UnexpectedFileOffset`] if the offset is out
    /// of order, [`ChannelError::FileIntegrityFailed`] if final verification fails, and
    /// [`ChannelError::TransferClosed`] once the transfer has completed or failed.
    pub fn accept_chunk(
        &mut self,
        chunk: &FileTransferChunk,
    ) -> Result<FileTransferAck, ChannelError> {
        if self.state != ReceiveState::InProgress {
            return Err(ChannelError::TransferClosed);
        }
        let expected_offset = u64::try_from(self.buffer.len()).unwrap_or(u64::MAX);
        if chunk.transfer_id != self.transfer_id || chunk.offset != expected_offset {
            return Err(ChannelError::UnexpectedFileOffset {
                expected: expected_offset,
                actual: chunk.offset,
            });
        }
        let chunk_len = u64::try_from(chunk.data.len()).unwrap_or(u64::MAX);
        let end_offset = chunk.offset.saturating_add(chunk_len);
        if end_offset > self.total_bytes {
            return Err(ChannelError::FileSizeExceeded {
                total_bytes: self.total_bytes,
                attempted: end_offset,
            });
        }
        self.buffer.extend_from_slice(&chunk.data);
        let next_offset = u64::try_from(self.buffer.len()).unwrap_or(u64::MAX);

        if chunk.eof {
            if let Err(err) = self.verify_complete() {
                self.state = ReceiveState::Failed;
                return Err(err);
            }
            self.state = ReceiveState::Verified;
            return Ok(FileTransferAck {
                transfer_id: self.transfer_id,
                next_offset,
                completed: true,
                verified: true,
            });
        }

        Ok(FileTransferAck {
            transfer_id: self.transfer_id,
            next_offset,
            completed: false,
            verified: false,
        })
    }

    /// Consumes the receiver and returns the file bytes only if the transfer completed
    /// and both the size and the SHA-256 digest match the offer.
    ///
    /// # Errors
    ///
    /// Returns [`ChannelError::FileIntegrityFailed`] if the transfer is incomplete,
    /// failed verification, or the buffer no longer matches the offer. Use
    /// [`Self::partial_bytes`] to persist incomplete data for resume instead.
    pub fn into_bytes(self) -> Result<Vec<u8>, ChannelError> {
        if self.state != ReceiveState::Verified {
            return Err(ChannelError::FileIntegrityFailed);
        }
        self.verify_complete()?;
        Ok(self.buffer)
    }

    fn verify_complete(&self) -> Result<(), ChannelError> {
        let received = u64::try_from(self.buffer.len()).unwrap_or(u64::MAX);
        if received != self.total_bytes || sha256_bytes(&self.buffer) != self.expected_sha256 {
            return Err(ChannelError::FileIntegrityFailed);
        }
        Ok(())
    }
}

/// Sunshine-style `RESTRICTED_LOWDELAY` Opus audio stream profiles (`src/audio.cpp`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpusStreamProfile {
    /// 48 kHz 2-channel stereo at 96 kbps (`stream_configs[0]` in Sunshine `src/audio.cpp`).
    StereoStandard,
    /// 48 kHz 2-channel stereo at 512 kbps (`stream_configs[1]` in Sunshine `src/audio.cpp`).
    StereoHighQuality,
    /// 48 kHz 6-channel 5.1 surround at 256 kbps (`stream_configs[2]` in Sunshine `src/audio.cpp`).
    Surround51,
    /// 48 kHz 8-channel 7.1 surround at 450 kbps (`stream_configs[4]` in Sunshine `src/audio.cpp`).
    Surround71,
}

impl OpusStreamProfile {
    /// Sample rate in Hz (`48_000`).
    #[must_use]
    pub const fn sample_rate(self) -> u32 {
        OPUS_SAMPLE_RATE
    }

    /// Number of audio channels (`2`, `6`, or `8`).
    #[must_use]
    pub const fn channels(self) -> u32 {
        match self {
            Self::StereoStandard | Self::StereoHighQuality => 2,
            Self::Surround51 => 6,
            Self::Surround71 => 8,
        }
    }

    /// Target Opus encoder bitrate in bits per second.
    #[must_use]
    pub const fn bitrate_bps(self) -> u32 {
        match self {
            Self::StereoStandard => 96_000,
            Self::StereoHighQuality => 512_000,
            Self::Surround51 => 256_000,
            Self::Surround71 => 450_000,
        }
    }

    /// Wraps an encoded Opus packet into a sequenced [`AudioFrame`] protobuf message.
    #[must_use]
    pub fn pack_frame(
        self,
        sequence: u64,
        captured_at_micros: u64,
        opus_packet: &[u8],
    ) -> AudioFrame {
        AudioFrame {
            sequence,
            captured_at_micros,
            sample_rate: self.sample_rate(),
            channels: self.channels(),
            opus_data: Bytes::copy_from_slice(opus_packet),
        }
    }
}

/// Multi-monitor catalog and active display selector for a remote session.
#[derive(Debug, Clone)]
pub struct MonitorCatalog {
    displays: Vec<DisplayDescriptor>,
    active_index: u32,
}

impl MonitorCatalog {
    /// Creates a new [`MonitorCatalog`] from the host's enumerated displays,
    /// selecting the primary monitor by default.
    #[must_use]
    pub fn new(displays: Vec<DisplayDescriptor>) -> Self {
        let active_index = displays
            .iter()
            .find(|d| d.primary)
            .or_else(|| displays.first())
            .map_or(0, |d| d.index);
        Self {
            displays,
            active_index,
        }
    }

    /// Returns the currently active display index.
    #[must_use]
    pub const fn active_index(&self) -> u32 {
        self.active_index
    }

    /// Returns the descriptor of the currently active display.
    #[must_use]
    pub fn active_display(&self) -> Option<&DisplayDescriptor> {
        self.displays.iter().find(|d| d.index == self.active_index)
    }

    /// Builds a [`DisplayList`] protobuf message advertising all monitors and the
    /// active monitor index.
    #[must_use]
    pub fn to_proto_list(&self) -> DisplayList {
        DisplayList {
            displays: self.displays.clone(),
            active_display_index: self.active_index,
        }
    }

    /// Handles a client [`SelectDisplay`] request, switching the active monitor.
    ///
    /// # Errors
    ///
    /// Returns [`ChannelError::UnknownDisplayIndex`] if `req.display_index` is not
    /// present in the catalog.
    pub fn select(&mut self, req: &SelectDisplay) -> Result<&DisplayDescriptor, ChannelError> {
        if !self.displays.iter().any(|d| d.index == req.display_index) {
            return Err(ChannelError::UnknownDisplayIndex(req.display_index));
        }
        self.active_index = req.display_index;
        self.active_display()
            .ok_or(ChannelError::UnknownDisplayIndex(req.display_index))
    }
}

/// Sequenced bidirectional chat channel between the technician and the remote user.
#[derive(Debug, Default, Clone)]
pub struct ChatChannel {
    next_id: u64,
    history: Vec<ChatMessage>,
}

impl ChatChannel {
    /// Creates an empty [`ChatChannel`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends and returns a new outbound [`ChatMessage`].
    pub fn send(&mut self, sender_name: &str, sent_at_micros: u64, body: &str) -> ChatMessage {
        self.next_id += 1;
        let msg = ChatMessage {
            message_id: self.next_id,
            sender_name: sender_name.to_owned(),
            sent_at_micros,
            body: body.to_owned(),
        };
        self.history.push(msg.clone());
        msg
    }

    /// Records an inbound [`ChatMessage`] from the peer.
    pub fn receive(&mut self, msg: ChatMessage) {
        self.next_id = self.next_id.max(msg.message_id);
        self.history.push(msg);
    }

    /// Ordered chat message history for this session.
    #[must_use]
    pub fn history(&self) -> &[ChatMessage] {
        &self.history
    }
}

/// Interactive remote terminal session state (`TerminalData` + `TerminalResize`).
#[derive(Debug, Clone)]
pub struct TerminalChannel {
    session_id: u32,
    cols: u32,
    rows: u32,
}

impl TerminalChannel {
    /// Creates a new [`TerminalChannel`] with initial dimensions `(cols, rows)`.
    #[must_use]
    pub const fn new(session_id: u32, cols: u32, rows: u32) -> Self {
        Self {
            session_id,
            cols,
            rows,
        }
    }

    /// Current terminal dimensions `(cols, rows)`.
    #[must_use]
    pub const fn dimensions(&self) -> (u32, u32) {
        (self.cols, self.rows)
    }

    /// Updates terminal dimensions from a [`TerminalResize`] message.
    pub const fn apply_resize(&mut self, resize: &TerminalResize) {
        if resize.session_id == self.session_id {
            self.cols = if resize.cols == 0 { 1 } else { resize.cols };
            self.rows = if resize.rows == 0 { 1 } else { resize.rows };
        }
    }

    /// Packages raw PTY stdout/stdin bytes into a [`TerminalData`] message.
    #[must_use]
    pub fn pack_data(&self, bytes: &[u8]) -> TerminalData {
        TerminalData {
            session_id: self.session_id,
            data: Bytes::copy_from_slice(bytes),
        }
    }
}

fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clipboard_sync_deduplicates_and_suppresses_echo_loops() {
        let mut host_clip = ClipboardSync::new();
        let mut client_clip = ClipboardSync::new();

        // Host copies "Hello OmegaDesk"
        let ev = host_clip
            .prepare_outbound(ClipboardFormat::Utf8Text, b"Hello OmegaDesk")
            .unwrap()
            .unwrap();

        // Repeating the same local clipboard content produces None
        assert!(
            host_clip
                .prepare_outbound(ClipboardFormat::Utf8Text, b"Hello OmegaDesk")
                .unwrap()
                .is_none()
        );

        // Client receives the event and updates its local OS clipboard
        let (fmt, data) = client_clip.accept_inbound(&ev).unwrap().unwrap();
        assert_eq!(fmt, ClipboardFormat::Utf8Text);
        assert_eq!(data, b"Hello OmegaDesk");

        // When the client's OS clipboard watcher fires with the newly pasted text,
        // `prepare_outbound` suppresses the echo!
        assert!(
            client_clip
                .prepare_outbound(ClipboardFormat::Utf8Text, b"Hello OmegaDesk")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn chunked_file_transfer_supports_resume_and_rejects_traversal() {
        assert!(validate_relative_path("../etc/passwd").is_err());
        assert!(validate_relative_path("C:\\Windows\\System32").is_err());
        assert!(validate_relative_path("docs/report.pdf").is_ok());

        let payload = vec![0x5Au8; DEFAULT_FILE_CHUNK_SIZE * 2 + 123];
        let resume_offset = DEFAULT_FILE_CHUNK_SIZE;

        let mut sender =
            FileTransferSender::new(42, "logs/session.bin", payload.clone(), resume_offset)
                .unwrap();
        let offer = sender.offer();
        assert_eq!(offer.resume_offset, u64::try_from(resume_offset).unwrap());

        let mut receiver =
            FileTransferReceiver::from_offer(&offer, payload[..resume_offset].to_vec()).unwrap();

        let mut last_ack = None;
        while let Some(chunk) = sender.next_chunk() {
            last_ack = Some(receiver.accept_chunk(&chunk).unwrap());
        }
        let final_ack = last_ack.unwrap();
        assert!(final_ack.completed);
        assert!(final_ack.verified);
        assert!(receiver.is_verified());
        assert_eq!(receiver.into_bytes().unwrap(), payload);
    }

    /// Regression for #27 `channels.rs:60`: the dedup key must include the format.
    #[test]
    fn clipboard_dedup_tracks_format_together_with_digest() {
        let mut host = ClipboardSync::new();
        let mut client = ClipboardSync::new();
        let text = host
            .prepare_outbound(ClipboardFormat::Utf8Text, b"<b>same bytes</b>")
            .unwrap()
            .expect("first copy is new content");
        // Same bytes copied again as HTML is a different clipboard content: it must go out.
        let html = host
            .prepare_outbound(ClipboardFormat::Html, b"<b>same bytes</b>")
            .unwrap()
            .expect("format-only change must reach the peer");
        assert_eq!(html.format, ClipboardFormat::Html as i32);
        // A true echo (same format, same bytes) is still suppressed.
        assert!(
            host.prepare_outbound(ClipboardFormat::Html, b"<b>same bytes</b>")
                .unwrap()
                .is_none()
        );

        assert!(client.accept_inbound(&text).unwrap().is_some());
        let (fmt, _) = client
            .accept_inbound(&html)
            .unwrap()
            .expect("inbound format-only change must be applied");
        assert_eq!(fmt, ClipboardFormat::Html);
        assert!(client.accept_inbound(&html).unwrap().is_none());
    }

    /// Regression for #27 `channels.rs:200`: exactly one EOF chunk for a 0-byte file
    /// (the second `next_chunk()` used to slice `1..0` and panic) and for a transfer
    /// resumed at its full length (no EOF chunk used to be sent at all).
    #[test]
    fn file_sender_emits_exactly_one_eof_chunk_for_empty_and_fully_resumed_files() {
        let mut empty = FileTransferSender::new(1, "empty.bin", Vec::new(), 0).unwrap();
        let chunk = empty
            .next_chunk()
            .expect("empty file still sends an EOF chunk");
        assert!(chunk.eof);
        assert!(chunk.data.is_empty());
        assert_eq!(chunk.offset, 0);
        assert!(empty.next_chunk().is_none());
        assert!(empty.next_chunk().is_none());

        let mut receiver = FileTransferReceiver::from_offer(&empty.offer(), Vec::new()).unwrap();
        let ack = receiver.accept_chunk(&chunk).unwrap();
        assert!(ack.completed && ack.verified);
        assert_eq!(receiver.into_bytes().unwrap(), Vec::<u8>::new());

        let payload = vec![0xA5u8; 1000];
        let mut resumed =
            FileTransferSender::new(2, "done.bin", payload.clone(), payload.len()).unwrap();
        let final_chunk = resumed
            .next_chunk()
            .expect("fully resumed transfer must still emit the EOF chunk");
        assert!(final_chunk.eof);
        assert!(final_chunk.data.is_empty());
        assert_eq!(final_chunk.offset, 1000);
        assert!(resumed.next_chunk().is_none());

        let mut receiver =
            FileTransferReceiver::from_offer(&resumed.offer(), payload.clone()).unwrap();
        let ack = receiver.accept_chunk(&final_chunk).unwrap();
        assert!(ack.completed && ack.verified);
        assert_eq!(receiver.into_bytes().unwrap(), payload);
    }

    /// Regression for #27 `channels.rs:285`: chunks past `total_bytes` are rejected
    /// before buffering even when the peer never sets `eof`.
    #[test]
    fn file_receiver_rejects_chunks_beyond_total_bytes_before_eof() {
        let payload = vec![7u8; 16];
        let sender = FileTransferSender::new(3, "small.bin", payload.clone(), 0).unwrap();
        let mut receiver = FileTransferReceiver::from_offer(&sender.offer(), Vec::new()).unwrap();

        // Honest first chunk covering the whole advertised size, but withholding EOF.
        let first = FileTransferChunk {
            transfer_id: 3,
            offset: 0,
            data: Bytes::from(payload),
            eof: false,
        };
        assert!(receiver.accept_chunk(&first).is_ok());

        // Correctly offset extra chunk: must be rejected and must not be retained.
        let overflow = FileTransferChunk {
            transfer_id: 3,
            offset: 16,
            data: Bytes::from_static(&[0xFFu8; 64]),
            eof: false,
        };
        assert_eq!(
            receiver.accept_chunk(&overflow),
            Err(ChannelError::FileSizeExceeded {
                total_bytes: 16,
                attempted: 80,
            })
        );
        assert_eq!(receiver.partial_bytes().len(), 16);

        // An offer whose resume offset already exceeds the file is rejected up front.
        let mut bad_offer = sender.offer();
        bad_offer.resume_offset = 17;
        assert!(matches!(
            FileTransferReceiver::from_offer(&bad_offer, vec![0u8; 17]),
            Err(ChannelError::FileSizeExceeded { .. })
        ));
    }

    /// Regression for #27 `channels.rs:315`: `into_bytes()` is fallible and never hands
    /// out incomplete or corrupt bytes; partial bytes stay available for resume.
    #[test]
    fn file_receiver_extraction_fails_before_eof_and_after_integrity_failure() {
        let payload: Vec<u8> = (0..=255u8).collect();
        let mut sender = FileTransferSender::new(4, "data.bin", payload.clone(), 0).unwrap();
        let offer = sender.offer();

        // Incomplete: no chunk received yet.
        let receiver = FileTransferReceiver::from_offer(&offer, Vec::new()).unwrap();
        assert!(!receiver.is_verified());
        assert_eq!(
            receiver.into_bytes(),
            Err(ChannelError::FileIntegrityFailed)
        );

        // Corrupt: tamper with the only chunk, keep offset/size/eof consistent.
        let mut receiver = FileTransferReceiver::from_offer(&offer, Vec::new()).unwrap();
        let mut chunk = sender.next_chunk().unwrap();
        let mut tampered = chunk.data.to_vec();
        tampered[0] ^= 0xFF;
        chunk.data = Bytes::from(tampered);
        assert_eq!(
            receiver.accept_chunk(&chunk),
            Err(ChannelError::FileIntegrityFailed)
        );
        assert!(!receiver.is_verified());
        // The corrupt buffer is still exposed for resume bookkeeping...
        assert_eq!(receiver.partial_bytes().len(), payload.len());
        // ...but the transfer is closed and extraction refuses to return it.
        assert_eq!(
            receiver.accept_chunk(&chunk),
            Err(ChannelError::TransferClosed)
        );
        assert_eq!(
            receiver.into_bytes(),
            Err(ChannelError::FileIntegrityFailed)
        );
    }

    #[test]
    fn monitor_catalog_and_opus_profiles_work() {
        let mut catalog = MonitorCatalog::new(vec![
            DisplayDescriptor {
                index: 0,
                name: "DELL U2723QE".to_owned(),
                width: 3840,
                height: 2160,
                origin_x: -3840,
                origin_y: 0,
                scale_percent: 150,
                primary: false,
            },
            DisplayDescriptor {
                index: 1,
                name: "LG UltraGear".to_owned(),
                width: 2560,
                height: 1440,
                origin_x: 0,
                origin_y: 0,
                scale_percent: 100,
                primary: true,
            },
        ]);
        assert_eq!(catalog.active_index(), 1);
        catalog.select(&SelectDisplay { display_index: 0 }).unwrap();
        assert_eq!(catalog.active_index(), 0);
        assert!(catalog.select(&SelectDisplay { display_index: 9 }).is_err());

        let frame = OpusStreamProfile::StereoStandard.pack_frame(1, 5000, &[1, 2, 3]);
        assert_eq!(frame.sample_rate, 48_000);
        assert_eq!(frame.channels, 2);
    }
}
