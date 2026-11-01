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
    /// Requested display index does not exist in the host's [`MonitorCatalog`].
    #[error("unknown display index: {0}")]
    UnknownDisplayIndex(u32),
}

/// Deduplicating bidirectional clipboard synchronization state machine.
#[derive(Debug, Default, Clone)]
pub struct ClipboardSync {
    last_digest: Option<[u8; 32]>,
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
        if self.last_digest == Some(digest) {
            return Ok(None);
        }
        self.last_digest = Some(digest);
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
        if self.last_digest == Some(computed) {
            return Ok(None);
        }
        self.last_digest = Some(computed);
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

    /// Produces the next [`FileTransferChunk`], or `None` once all bytes have been sent.
    pub fn next_chunk(&mut self) -> Option<FileTransferChunk> {
        if self.offset >= self.data.len() && !self.data.is_empty() {
            return None;
        }
        let chunk_offset = u64::try_from(self.offset).unwrap_or(0);
        let end = (self.offset + self.chunk_size).min(self.data.len());
        let slice = self.data.slice(self.offset..end);
        self.offset = end;
        let eof = self.offset >= self.data.len();
        if slice.is_empty() && eof {
            // Allow a single empty EOF chunk for 0-byte files, then stop.
            self.offset = 1;
        }
        Some(FileTransferChunk {
            transfer_id: self.transfer_id,
            offset: chunk_offset,
            data: slice,
            eof,
        })
    }
}

/// Receiver-side state machine for chunked file transfer with resume and SHA-256
/// integrity verification.
#[derive(Debug, Clone)]
pub struct FileTransferReceiver {
    transfer_id: u64,
    relative_path: String,
    total_bytes: u64,
    expected_sha256: [u8; 32],
    buffer: Vec<u8>,
}

impl FileTransferReceiver {
    /// Accepts a [`FileTransferOffer`], optionally seeding `existing_partial` bytes
    /// for resumed transfers.
    ///
    /// # Errors
    ///
    /// Returns [`ChannelError`] if the path is unsafe or the SHA-256 field is not 32 bytes.
    pub fn from_offer(
        offer: &FileTransferOffer,
        existing_partial: Vec<u8>,
    ) -> Result<Self, ChannelError> {
        validate_relative_path(&offer.relative_path)?;
        let Ok(expected_sha256) = <[u8; 32]>::try_from(offer.file_sha256.as_ref()) else {
            return Err(ChannelError::FileIntegrityFailed);
        };
        let expected_resume = usize::try_from(offer.resume_offset).unwrap_or(0);
        let mut buffer = existing_partial;
        buffer.truncate(expected_resume);

        Ok(Self {
            transfer_id: offer.transfer_id,
            relative_path: offer.relative_path.clone(),
            total_bytes: offer.total_bytes,
            expected_sha256,
            buffer,
        })
    }

    /// Relative destination path of this transfer.
    #[must_use]
    pub fn relative_path(&self) -> &str {
        &self.relative_path
    }

    /// Appends a [`FileTransferChunk`] and returns a [`FileTransferAck`].
    ///
    /// When `chunk.eof` is set, verifies both the total byte count and the
    /// full-file SHA-256 digest before setting `verified = true`.
    ///
    /// # Errors
    ///
    /// Returns [`ChannelError`] if the chunk offset is out of order or final
    /// SHA-256 verification fails.
    pub fn accept_chunk(
        &mut self,
        chunk: &FileTransferChunk,
    ) -> Result<FileTransferAck, ChannelError> {
        let expected_offset = u64::try_from(self.buffer.len()).unwrap_or(u64::MAX);
        if chunk.transfer_id != self.transfer_id || chunk.offset != expected_offset {
            return Err(ChannelError::UnexpectedFileOffset {
                expected: expected_offset,
                actual: chunk.offset,
            });
        }
        self.buffer.extend_from_slice(&chunk.data);
        let next_offset = u64::try_from(self.buffer.len()).unwrap_or(u64::MAX);

        if chunk.eof {
            if next_offset != self.total_bytes {
                return Err(ChannelError::FileIntegrityFailed);
            }
            let actual_sha256 = sha256_bytes(&self.buffer);
            if actual_sha256 != self.expected_sha256 {
                return Err(ChannelError::FileIntegrityFailed);
            }
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

    /// Consumes the receiver and returns the verified file bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.buffer
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
        assert_eq!(receiver.into_bytes(), payload);
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
