//! Relay-side append-only `.odrec` session recording, keyframe seek index,
//! `asciicast` v2 (`.cast`) terminal recording, and indexed command storage.
//!
//! Reference implementations:
//! - `Ylianst_MeshCentral/meshrelay.js` (lines 134–156): `recordingEntry(fd, type, flags, data, func)`
//!   writes a 16-byte big-endian binary record header (`Type: u16 BE + Flags: u16 BE + Size: u32 BE + TimestampMs: u64 BE`)
//!   followed immediately by the payload bytes.
//! - `apache_guacamole-server/src/libguac/recording.c` (lines 42–159): `guac_recording_create`
//!   tees session output, mouse, touch, key, and clipboard instructions into an append-only stream.
//! - `apache_guacamole-client/guacamole-common-js/src/main/webapp/modules/SessionRecording.js`
//!   (lines 86–175): `KEYFRAME_CHAR_INTERVAL = 16384`, `KEYFRAME_TIME_INTERVAL = 5000`, and
//!   keyframe-indexed seeking across recorded session frames.
//! - `jumpserver_jumpserver/apps/terminal/` (`docs/plan.md` §2.9 & §4 Phase 5): terminal session
//!   recording in `asciicast` v2 (`.cast`) format and indexed typed command storage (`CommandStorage`)
//!   with risk classification and full-text filtering.

use std::fmt::Write as _;
use std::io;

use bytes::{Buf, BufMut, Bytes, BytesMut};
use thiserror::Error;

/// 8-byte magic header prefixing `.odrec` session recording files.
pub const ODREC_MAGIC: [u8; 8] = *b"ODREC001";

/// Length in bytes of each `.odrec` binary record header (`Type(2) + Flags(2) + Size(4) + TimestampMs(8)`),
/// ported from `Ylianst_MeshCentral/meshrelay.js` lines 137–142.
pub const ODREC_HEADER_LEN: usize = 16;

/// Minimum byte distance after which [`OdrecWriter::keyframe_hint_due`] asks the producer for a
/// new recovery point (`16 KiB`), ported from `SessionRecording.js` line 96
/// (`KEYFRAME_CHAR_INTERVAL = 16384`).
///
/// This is advisory only: like `Guacamole.SessionRecording._Frame.keyframe` ("purely advisory",
/// `SessionRecording.js` lines 1291–1299) it never turns a delta frame into an index entry.
pub const KEYFRAME_BYTE_INTERVAL: u64 = 16_384;

/// Minimum time distance in milliseconds after which [`OdrecWriter::keyframe_hint_due`] asks the
/// producer for a new recovery point (`5000 ms`), ported from `SessionRecording.js` line 105
/// (`KEYFRAME_TIME_INTERVAL = 5000`). Advisory only, see [`KEYFRAME_BYTE_INTERVAL`].
pub const KEYFRAME_TIME_INTERVAL_MS: u64 = 5_000;

/// Errors returned while encoding, decoding, or seeking session recordings.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum RecordingError {
    /// Recording stream does not begin with [`ODREC_MAGIC`].
    #[error("invalid .odrec magic header")]
    InvalidMagic,
    /// Record header or payload is truncated.
    #[error("truncated .odrec record: expected {expected} bytes, got {actual}")]
    TruncatedRecord {
        /// Expected byte length.
        expected: usize,
        /// Available byte length.
        actual: usize,
    },
    /// Unknown `.odrec` record type code.
    #[error("unknown .odrec record type: {0}")]
    UnknownRecordType(u16),
    /// Payload exceeds `u32::MAX` bytes.
    #[error("record payload length {0} exceeds u32::MAX")]
    PayloadTooLarge(usize),
}

/// Record type values stored in the first 2 bytes of the 16-byte `.odrec` header,
/// extending `MeshCentral/meshrelay.js` (`type 1 = metadata`, `type 2 = network data`, `type 3 = end`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum RecordType {
    /// Session metadata block (`type = 1` in `meshrelay.js` line 119).
    Metadata = 1,
    /// Video or protocol frame payload (`type = 2` in `meshrelay.js` line 231).
    FrameData = 2,
    /// Clean end-of-recording marker (`type = 3`).
    EndOfStream = 3,
    /// Input event (keyboard/mouse/touch, `recording.c` lines 140–159).
    InputEvent = 4,
    /// Clipboard event (`recording.c` lines 98–101).
    ClipboardEvent = 5,
}

impl RecordType {
    /// Converts a raw `u16` header code into a [`RecordType`].
    ///
    /// # Errors
    ///
    /// Returns [`RecordingError::UnknownRecordType`] if `raw` is not a recognized code.
    pub const fn from_u16(raw: u16) -> Result<Self, RecordingError> {
        match raw {
            1 => Ok(Self::Metadata),
            2 => Ok(Self::FrameData),
            3 => Ok(Self::EndOfStream),
            4 => Ok(Self::InputEvent),
            5 => Ok(Self::ClipboardEvent),
            other => Err(RecordingError::UnknownRecordType(other)),
        }
    }
}

/// Bitflags stored in bytes `2..4` of the 16-byte `.odrec` header (`meshrelay.js` line 138).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(transparent)]
pub struct RecordFlags(u16);

impl RecordFlags {
    /// No flags set (host-to-viewer direction, delta frame).
    pub const NONE: Self = Self(0);
    /// Record originated from the user/viewer rather than the remote device (`0x0001` in `meshrelay.js`).
    pub const FROM_USER: Self = Self(0x0001);
    /// Record contains an independent keyframe / IDR recovery point (`0x0002`).
    pub const KEYFRAME: Self = Self(0x0002);

    /// Creates flags from a raw `u16`.
    #[must_use]
    pub const fn from_bits(bits: u16) -> Self {
        Self(bits)
    }

    /// Returns the raw `u16` representation.
    #[must_use]
    pub const fn bits(self) -> u16 {
        self.0
    }

    /// Combines two flag sets.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Returns `true` if all bits in `other` are set in `self`.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }
}

/// A single entry in an `.odrec` recording stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OdrecRecord {
    /// Entry classification (`Metadata`, `FrameData`, `EndOfStream`, etc.).
    pub record_type: RecordType,
    /// Direction and keyframe flags.
    pub flags: RecordFlags,
    /// Milliseconds since the Unix epoch (or session start) stored in bytes `8..16`.
    pub timestamp_ms: u64,
    /// Raw record payload.
    pub payload: Bytes,
}

impl OdrecRecord {
    /// Encodes this record using the 16-byte `MeshCentral` header layout
    /// (`Type: u16 BE + Flags: u16 BE + Size: u32 BE + TimestampMs: u64 BE`) followed by `payload`.
    ///
    /// # Errors
    ///
    /// Returns [`RecordingError::PayloadTooLarge`] if `payload.len() > u32::MAX`.
    pub fn encode(&self, dst: &mut BytesMut) -> Result<(), RecordingError> {
        let len_u32 = u32::try_from(self.payload.len())
            .map_err(|_| RecordingError::PayloadTooLarge(self.payload.len()))?;
        dst.reserve(ODREC_HEADER_LEN + self.payload.len());
        dst.put_u16(self.record_type as u16);
        dst.put_u16(self.flags.bits());
        dst.put_u32(len_u32);
        dst.put_u64(self.timestamp_ms);
        dst.extend_from_slice(&self.payload);
        Ok(())
    }

    /// Decodes a single [`OdrecRecord`] from `src`, advancing the slice cursor.
    ///
    /// # Errors
    ///
    /// Returns [`RecordingError`] if the header or payload is truncated or the type code is invalid.
    pub fn decode(src: &mut &[u8]) -> Result<Self, RecordingError> {
        if src.len() < ODREC_HEADER_LEN {
            return Err(RecordingError::TruncatedRecord {
                expected: ODREC_HEADER_LEN,
                actual: src.len(),
            });
        }
        let raw_type = src.get_u16();
        let raw_flags = src.get_u16();
        let payload_len = src.get_u32() as usize;
        let timestamp_ms = src.get_u64();

        let record_type = RecordType::from_u16(raw_type)?;
        if src.len() < payload_len {
            return Err(RecordingError::TruncatedRecord {
                expected: payload_len,
                actual: src.len(),
            });
        }
        let payload = Bytes::copy_from_slice(&src[..payload_len]);
        src.advance(payload_len);
        Ok(Self {
            record_type,
            flags: RecordFlags::from_bits(raw_flags),
            timestamp_ms,
            payload,
        })
    }
}

/// Seekable index entry pointing to a keyframe inside an `.odrec` byte stream,
/// ported from `Guacamole.SessionRecording` (`SessionRecording.js` lines 88–123).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyframeIndexEntry {
    /// Zero-based record index within the recording.
    pub record_index: usize,
    /// Timestamp in milliseconds of the keyframe record.
    pub timestamp_ms: u64,
    /// Byte offset from the start of the `.odrec` stream (including the 8-byte file magic).
    pub byte_offset: u64,
}

/// Append-only `.odrec` writer and keyframe indexer.
#[derive(Debug, Clone)]
pub struct OdrecWriter {
    buffer: BytesMut,
    keyframes: Vec<KeyframeIndexEntry>,
    record_count: usize,
    last_keyframe_byte_offset: u64,
    last_keyframe_timestamp_ms: u64,
}

impl Default for OdrecWriter {
    fn default() -> Self {
        Self::new()
    }
}

impl OdrecWriter {
    /// Creates a new `.odrec` writer initialized with [`ODREC_MAGIC`].
    #[must_use]
    pub fn new() -> Self {
        let mut buffer = BytesMut::with_capacity(4096);
        buffer.extend_from_slice(&ODREC_MAGIC);
        Self {
            buffer,
            keyframes: Vec::new(),
            record_count: 0,
            last_keyframe_byte_offset: 0,
            last_keyframe_timestamp_ms: 0,
        }
    }

    /// Appends a record to the `.odrec` stream and adds it to the keyframe index if, and only
    /// if, [`RecordFlags::KEYFRAME`] is set.
    ///
    /// Elapsed time or byte distance never promote a delta frame to the index: a delta frame
    /// still depends on earlier frames, so seeking to it would decode garbage. In
    /// `Guacamole.SessionRecording` (`SessionRecording.js` lines 493–499 and 717–722) the
    /// interval-based `frame.keyframe` flag is only advisory and a frame becomes seekable once
    /// its full `clientState` snapshot has been stored; the equivalent here is the producer
    /// requesting an IDR/recovery frame when [`Self::keyframe_hint_due`] returns `true` and
    /// then flagging that record `KEYFRAME`.
    ///
    /// # Errors
    ///
    /// Returns [`RecordingError::PayloadTooLarge`] if `record.payload` exceeds `u32::MAX` bytes.
    pub fn append(&mut self, record: &OdrecRecord) -> Result<u64, RecordingError> {
        let byte_offset = self.buffer.len() as u64;
        record.encode(&mut self.buffer)?;

        if record.flags.contains(RecordFlags::KEYFRAME) {
            self.keyframes.push(KeyframeIndexEntry {
                record_index: self.record_count,
                timestamp_ms: record.timestamp_ms,
                byte_offset,
            });
            self.last_keyframe_byte_offset = byte_offset;
            self.last_keyframe_timestamp_ms = record.timestamp_ms;
        }

        self.record_count += 1;
        Ok(byte_offset)
    }

    /// Returns `true` when the producer should emit a new recovery point (IDR keyframe or state
    /// snapshot) for a frame stamped `timestamp_ms`: either no keyframe has been indexed yet, or
    /// both [`KEYFRAME_BYTE_INTERVAL`] and [`KEYFRAME_TIME_INTERVAL_MS`] have elapsed since the
    /// last indexed keyframe (`SessionRecording.js` lines 496–497).
    ///
    /// This is a hint for the encoder side only; it never affects the index or
    /// [`Self::seek_keyframe`].
    #[must_use]
    pub fn keyframe_hint_due(&self, timestamp_ms: u64) -> bool {
        if self.keyframes.is_empty() {
            return true;
        }
        let bytes_since = (self.buffer.len() as u64).saturating_sub(self.last_keyframe_byte_offset);
        let millis_since = timestamp_ms.saturating_sub(self.last_keyframe_timestamp_ms);
        bytes_since >= KEYFRAME_BYTE_INTERVAL && millis_since >= KEYFRAME_TIME_INTERVAL_MS
    }

    /// Returns the indexed keyframes accumulated so far.
    #[must_use]
    pub fn keyframes(&self) -> &[KeyframeIndexEntry] {
        &self.keyframes
    }

    /// Returns the total number of records written.
    #[must_use]
    pub const fn record_count(&self) -> usize {
        self.record_count
    }

    /// Finds the nearest keyframe at or before `target_timestamp_ms` using binary search
    /// (`O(log n)`), enabling instant timeline scrubbing (`SessionRecording.js`).
    ///
    /// Every entry returned was explicitly flagged [`RecordFlags::KEYFRAME`] by the producer,
    /// so decoding can start at it without any earlier record. Returns `None` when no keyframe
    /// exists at or before the target (including a target that precedes the first keyframe),
    /// never a later one.
    #[must_use]
    pub fn seek_keyframe(&self, target_timestamp_ms: u64) -> Option<KeyframeIndexEntry> {
        match self
            .keyframes
            .binary_search_by_key(&target_timestamp_ms, |entry| entry.timestamp_ms)
        {
            Ok(idx) => self.keyframes.get(idx).copied(),
            Err(0) => None,
            Err(insert_idx) => self.keyframes.get(insert_idx - 1).copied(),
        }
    }

    /// Returns a view of the underlying `.odrec` byte stream.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.buffer
    }

    /// Consumes the writer and returns the completed `.odrec` byte buffer.
    #[must_use]
    pub fn into_bytes(self) -> Bytes {
        self.buffer.freeze()
    }
}

/// Streaming `.odrec` writer: the same container as [`OdrecWriter`], written record by record
/// to any [`io::Write`] sink (a `BufWriter<File>` at the agent) instead of an in-memory buffer,
/// so an hours-long session costs a bounded amount of memory. The keyframe index is kept in
/// memory exactly like [`OdrecWriter`] and the hint rules are identical.
///
/// MeshCentral writes every record straight to the file descriptor as it is relayed
/// (`recordingEntry` in `Ylianst_MeshCentral/meshrelay.js` lines 134–156, `fs.write(logfile.fd,
/// block, ...)`); this is the typed equivalent.
#[derive(Debug)]
pub struct OdrecStreamWriter<W: io::Write> {
    sink: W,
    scratch: BytesMut,
    keyframes: Vec<KeyframeIndexEntry>,
    record_count: usize,
    bytes_written: u64,
    last_keyframe_byte_offset: u64,
    last_keyframe_timestamp_ms: u64,
}

impl<W: io::Write> OdrecStreamWriter<W> {
    /// Writes [`ODREC_MAGIC`] to `sink` and returns the writer.
    ///
    /// # Errors
    ///
    /// Returns the I/O error of the sink.
    pub fn new(mut sink: W) -> io::Result<Self> {
        sink.write_all(&ODREC_MAGIC)?;
        Ok(Self {
            sink,
            scratch: BytesMut::with_capacity(4096),
            keyframes: Vec::new(),
            record_count: 0,
            bytes_written: ODREC_MAGIC.len() as u64,
            last_keyframe_byte_offset: 0,
            last_keyframe_timestamp_ms: 0,
        })
    }

    /// Appends `record` and returns its byte offset in the stream. Only records flagged
    /// [`RecordFlags::KEYFRAME`] enter the index (see [`OdrecWriter::append`]).
    ///
    /// # Errors
    ///
    /// Returns `InvalidInput` if the payload exceeds `u32::MAX` bytes, or the sink's I/O error.
    pub fn append(&mut self, record: &OdrecRecord) -> io::Result<u64> {
        self.scratch.clear();
        record
            .encode(&mut self.scratch)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        self.sink.write_all(&self.scratch)?;
        let byte_offset = self.bytes_written;
        if record.flags.contains(RecordFlags::KEYFRAME) {
            self.keyframes.push(KeyframeIndexEntry {
                record_index: self.record_count,
                timestamp_ms: record.timestamp_ms,
                byte_offset,
            });
            self.last_keyframe_byte_offset = byte_offset;
            self.last_keyframe_timestamp_ms = record.timestamp_ms;
        }
        self.bytes_written += self.scratch.len() as u64;
        self.record_count += 1;
        Ok(byte_offset)
    }

    /// Same rule as [`OdrecWriter::keyframe_hint_due`]: the producer should emit a recovery
    /// point for a frame stamped `timestamp_ms`.
    #[must_use]
    pub fn keyframe_hint_due(&self, timestamp_ms: u64) -> bool {
        if self.keyframes.is_empty() {
            return true;
        }
        let bytes_since = self
            .bytes_written
            .saturating_sub(self.last_keyframe_byte_offset);
        let millis_since = timestamp_ms.saturating_sub(self.last_keyframe_timestamp_ms);
        bytes_since >= KEYFRAME_BYTE_INTERVAL && millis_since >= KEYFRAME_TIME_INTERVAL_MS
    }

    /// Indexed keyframes so far.
    #[must_use]
    pub fn keyframes(&self) -> &[KeyframeIndexEntry] {
        &self.keyframes
    }

    /// Records written so far (the end-of-stream marker included once written).
    #[must_use]
    pub const fn record_count(&self) -> usize {
        self.record_count
    }

    /// Bytes written so far, magic included.
    #[must_use]
    pub const fn bytes_written(&self) -> u64 {
        self.bytes_written
    }

    /// Appends the [`RecordType::EndOfStream`] marker stamped `timestamp_ms`, flushes and
    /// returns the sink.
    ///
    /// # Errors
    ///
    /// Returns the sink's I/O error.
    pub fn finish(mut self, timestamp_ms: u64) -> io::Result<W> {
        self.append(&OdrecRecord {
            record_type: RecordType::EndOfStream,
            flags: RecordFlags::NONE,
            timestamp_ms,
            payload: Bytes::new(),
        })?;
        self.sink.flush()?;
        Ok(self.sink)
    }
}

/// Parses an entire `.odrec` byte buffer into its sequence of [`OdrecRecord`] entries.
///
/// # Errors
///
/// Returns [`RecordingError`] if the magic header is invalid or any record is truncated.
pub fn parse_odrec_stream(bytes: &[u8]) -> Result<Vec<OdrecRecord>, RecordingError> {
    if bytes.len() < ODREC_MAGIC.len() || bytes[..ODREC_MAGIC.len()] != ODREC_MAGIC {
        return Err(RecordingError::InvalidMagic);
    }
    let mut cursor = &bytes[ODREC_MAGIC.len()..];
    let mut records = Vec::new();
    while !cursor.is_empty() {
        records.push(OdrecRecord::decode(&mut cursor)?);
    }
    Ok(records)
}

/// Terminal event kind in `asciicast` v2 (`.cast`) format (`JumpServer` `apps/terminal/`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AsciicastEventType {
    /// Data written to terminal standard output (`"o"`).
    Output,
    /// Data read from terminal standard input (`"i"`).
    Input,
    /// Terminal window resize event (`"r"`, payload formatted as `"COLSxROWS"`).
    Resize,
}

impl AsciicastEventType {
    /// Returns the `asciicast` v2 single-character event code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Output => "o",
            Self::Input => "i",
            Self::Resize => "r",
        }
    }
}

/// Terminal session recorder producing `asciicast` v2 (`.cast`) newline-delimited JSON
/// (`docs/plan.md` §2.9 & §4 Phase 5).
#[derive(Debug, Clone)]
pub struct AsciicastRecorder {
    width: u16,
    height: u16,
    start_timestamp_secs: u64,
    lines: Vec<String>,
}

impl AsciicastRecorder {
    /// Creates a new `asciicast` v2 recorder and writes the mandatory JSON header line.
    #[must_use]
    pub fn new(width: u16, height: u16, start_timestamp_secs: u64, title: Option<&str>) -> Self {
        let header = if let Some(t) = title {
            format!(
                "{{\"version\":2,\"width\":{width},\"height\":{height},\"timestamp\":{start_timestamp_secs},\"title\":\"{}\"}}",
                escape_json_str(t)
            )
        } else {
            format!(
                "{{\"version\":2,\"width\":{width},\"height\":{height},\"timestamp\":{start_timestamp_secs}}}"
            )
        };
        Self {
            width,
            height,
            start_timestamp_secs,
            lines: vec![header],
        }
    }

    /// Returns the initial terminal dimensions `(width, height)`.
    #[must_use]
    pub const fn dimensions(&self) -> (u16, u16) {
        (self.width, self.height)
    }

    /// Returns the Unix epoch start timestamp in seconds.
    #[must_use]
    pub const fn start_timestamp_secs(&self) -> u64 {
        self.start_timestamp_secs
    }

    /// Appends an `asciicast` v2 event line `[elapsed_secs, "o"|"i"|"r", data]`.
    pub fn record_event(&mut self, elapsed_ms: u64, kind: AsciicastEventType, data: &str) {
        let secs = elapsed_ms / 1_000;
        let millis = elapsed_ms % 1_000;
        let line = format!(
            "[{secs}.{millis:03},\"{}\",\"{}\"]",
            kind.code(),
            escape_json_str(data)
        );
        self.lines.push(line);
    }

    /// Serializes the complete `.cast` document (newline-separated JSON records).
    #[must_use]
    pub fn to_cast_string(&self) -> String {
        let mut out = self.lines.join("\n");
        out.push('\n');
        out
    }
}

/// Escapes special characters in a string for embedding inside a JSON string literal.
fn escape_json_str(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let code = c as u32;
                let _ = write!(out, "\\u{code:04x}");
            }
            c => out.push(c),
        }
    }
    out
}

/// Risk level assigned to an audited shell command (`JumpServer` `apps/terminal/` command storage).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CommandRiskLevel {
    /// Normal interactive command.
    Normal,
    /// Privileged or state-modifying command (`sudo`, `systemctl`, `chmod`, etc.).
    Warning,
    /// Destructive or high-risk command (`rm -rf`, `mkfs`, `dd`, credential exfiltration).
    Critical,
}

/// Audited shell command entry stored in [`CommandStorage`] (`JumpServer` `CommandStorage`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexedCommand {
    /// Session identifier in which the command was executed.
    pub session_id: String,
    /// Authenticated operator identifier.
    pub user_id: String,
    /// Target host or device identifier.
    pub device_id: String,
    /// Command line string executed by the user.
    pub input: String,
    /// Truncated command output snippet captured for audit review.
    pub output_preview: String,
    /// Risk level classification.
    pub risk_level: CommandRiskLevel,
    /// Execution timestamp in milliseconds since the Unix epoch.
    pub timestamp_ms: u64,
}

/// In-memory indexed command audit store (`JumpServer` `apps/terminal/` `CommandStorage`).
#[derive(Debug, Default, Clone)]
pub struct CommandStorage {
    commands: Vec<IndexedCommand>,
}

impl CommandStorage {
    /// Creates an empty command audit store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Classifies the [`CommandRiskLevel`] of a command line and appends it to the audit index.
    pub fn record_command(
        &mut self,
        session_id: impl Into<String>,
        user_id: impl Into<String>,
        device_id: impl Into<String>,
        input: impl Into<String>,
        output_preview: impl Into<String>,
        timestamp_ms: u64,
    ) -> &IndexedCommand {
        let input_str = input.into();
        let risk_level = classify_command_risk(&input_str);
        self.commands.push(IndexedCommand {
            session_id: session_id.into(),
            user_id: user_id.into(),
            device_id: device_id.into(),
            input: input_str,
            output_preview: output_preview.into(),
            risk_level,
            timestamp_ms,
        });
        let idx = self.commands.len() - 1;
        &self.commands[idx]
    }

    /// Returns all recorded commands in chronological order.
    #[must_use]
    pub fn all(&self) -> &[IndexedCommand] {
        &self.commands
    }

    /// Searches commands by case-insensitive substring match on `query`, optionally filtered
    /// by `session_id` and minimum [`CommandRiskLevel`].
    #[must_use]
    pub fn search(
        &self,
        query: &str,
        session_id: Option<&str>,
        min_risk: Option<CommandRiskLevel>,
    ) -> Vec<&IndexedCommand> {
        let needle = query.to_ascii_lowercase();
        self.commands
            .iter()
            .filter(|cmd| {
                if let Some(sid) = session_id
                    && cmd.session_id != sid
                {
                    return false;
                }
                if let Some(min) = min_risk
                    && cmd.risk_level < min
                {
                    return false;
                }
                needle.is_empty() || cmd.input.to_ascii_lowercase().contains(&needle)
            })
            .collect()
    }
}

/// Classifies a shell command into [`CommandRiskLevel`] based on high-risk patterns.
#[must_use]
pub fn classify_command_risk(command: &str) -> CommandRiskLevel {
    let lower = command.trim().to_ascii_lowercase();
    let critical_patterns = [
        "rm -rf /",
        "rm -rf *",
        "mkfs",
        "dd if=",
        ":(){:|:&};:",
        "chmod -r 777 /",
        "shutdown",
        "reboot",
        "init 0",
    ];
    if critical_patterns.iter().any(|pat| lower.contains(pat)) {
        return CommandRiskLevel::Critical;
    }

    let warning_patterns = [
        "sudo ",
        "su -",
        "systemctl ",
        "iptables ",
        "nft ",
        "useradd ",
        "usermod ",
        "passwd",
        "chmod ",
        "chown ",
    ];
    if warning_patterns.iter().any(|pat| lower.contains(pat)) {
        return CommandRiskLevel::Warning;
    }

    CommandRiskLevel::Normal
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn odrec_roundtrip_and_keyframe_seeking() {
        let mut writer = OdrecWriter::new();
        let meta = OdrecRecord {
            record_type: RecordType::Metadata,
            flags: RecordFlags::NONE,
            timestamp_ms: 1_000,
            payload: Bytes::from_static(b"{\"session\":\"s-1\"}"),
        };
        assert!(writer.append(&meta).is_ok());

        for i in 0..5u64 {
            let is_kf = i % 2 == 0;
            let flags = if is_kf {
                RecordFlags::KEYFRAME
            } else {
                RecordFlags::NONE
            };
            let frame = OdrecRecord {
                record_type: RecordType::FrameData,
                flags,
                timestamp_ms: 1_000 + i * 1_000,
                payload: Bytes::from(vec![0xAA; 64]),
            };
            assert!(writer.append(&frame).is_ok());
        }

        assert_eq!(writer.keyframes().len(), 3);
        let seek_mid = writer.seek_keyframe(3_500);
        assert_eq!(seek_mid.map(|k| k.timestamp_ms), Some(3_000));

        let parsed = parse_odrec_stream(writer.as_bytes());
        assert!(parsed.is_ok());
        let records = parsed.unwrap_or_default();
        assert_eq!(records.len(), 6);
        assert_eq!(records[0], meta);
    }

    fn frame(flags: RecordFlags, timestamp_ms: u64, len: usize) -> OdrecRecord {
        OdrecRecord {
            record_type: RecordType::FrameData,
            flags,
            timestamp_ms,
            payload: Bytes::from(vec![0x5A; len]),
        }
    }

    /// Issue #29 `lib.rs:264`: elapsed time or bytes never make a delta frame seekable. Only
    /// records explicitly flagged `KEYFRAME` enter the index; the intervals are a hint only.
    #[test]
    fn delta_frames_are_never_indexed_as_keyframes() {
        let mut writer = OdrecWriter::new();
        assert!(
            writer.keyframe_hint_due(0),
            "no keyframe yet: hint must be due"
        );

        // A delta frame that is the first frame must not be indexed just because it is first.
        assert!(writer.append(&frame(RecordFlags::NONE, 0, 64)).is_ok());
        assert_eq!(writer.keyframes(), []);
        assert_eq!(writer.seek_keyframe(0), None);

        assert!(
            writer
                .append(&frame(RecordFlags::KEYFRAME, 1_000, 64))
                .is_ok()
        );
        assert_eq!(writer.keyframes().len(), 1);
        assert!(!writer.keyframe_hint_due(1_000));
        // "At or before": a target before the first keyframe must not get a future keyframe.
        assert_eq!(writer.seek_keyframe(0), None);
        assert_eq!(writer.seek_keyframe(999), None);
        assert_eq!(writer.seek_keyframe(1_000).map(|k| k.record_index), Some(1));

        // Far beyond both intervals, a delta frame is still a delta frame.
        let big_delta_len = usize::try_from(KEYFRAME_BYTE_INTERVAL).unwrap() * 2;
        let late_ts = 1_000 + KEYFRAME_TIME_INTERVAL_MS * 4;
        assert!(
            writer
                .append(&frame(RecordFlags::NONE, late_ts, big_delta_len))
                .is_ok()
        );
        assert!(
            writer
                .append(&frame(RecordFlags::NONE, late_ts + 1_000, 64))
                .is_ok()
        );

        assert_eq!(writer.keyframes().len(), 1);
        let seek = writer.seek_keyframe(late_ts + 1_000).unwrap();
        assert_eq!(seek.timestamp_ms, 1_000);
        assert_eq!(seek.record_index, 1);
        let records = parse_odrec_stream(writer.as_bytes()).unwrap();
        assert!(
            records[seek.record_index]
                .flags
                .contains(RecordFlags::KEYFRAME)
        );

        // The producer is told to generate a recovery point; once it does, the index grows.
        assert!(writer.keyframe_hint_due(late_ts + 2_000));
        assert!(
            writer
                .append(&frame(RecordFlags::KEYFRAME, late_ts + 2_000, 64))
                .is_ok()
        );
        assert_eq!(writer.keyframes().len(), 2);
        assert_eq!(
            writer
                .seek_keyframe(late_ts + 2_500)
                .map(|k| k.record_index),
            Some(4)
        );
    }

    /// The streaming writer produces byte-for-byte what the in-memory writer produces and
    /// keeps the same keyframe index.
    #[test]
    fn stream_writer_matches_in_memory_writer() {
        let mut memory = OdrecWriter::new();
        let mut stream = OdrecStreamWriter::new(Vec::new()).unwrap();
        let records = [
            OdrecRecord {
                record_type: RecordType::Metadata,
                flags: RecordFlags::NONE,
                timestamp_ms: 10,
                payload: Bytes::from_static(b"{}"),
            },
            frame(RecordFlags::KEYFRAME, 20, 100),
            frame(RecordFlags::NONE, 30, 50),
            frame(RecordFlags::KEYFRAME, 40, 100),
        ];
        for record in &records {
            let a = memory.append(record).unwrap();
            let b = stream.append(record).unwrap();
            assert_eq!(a, b, "byte offsets agree");
        }
        assert_eq!(memory.keyframes(), stream.keyframes());
        assert_eq!(stream.keyframe_hint_due(40), memory.keyframe_hint_due(40));
        assert_eq!(stream.record_count(), 4);
        assert_eq!(stream.bytes_written(), memory.as_bytes().len() as u64);

        let bytes = stream.finish(50).unwrap();
        assert_eq!(&bytes[..memory.as_bytes().len()], memory.as_bytes());
        let parsed = parse_odrec_stream(&bytes).unwrap();
        assert_eq!(parsed.len(), 5);
        assert_eq!(parsed[4].record_type, RecordType::EndOfStream);
        assert_eq!(parsed[4].timestamp_ms, 50);
        assert!(parsed[1].flags.contains(RecordFlags::KEYFRAME));
        assert!(!parsed[2].flags.contains(RecordFlags::KEYFRAME));
    }

    /// Companion to issue #29 `recording-player.ts:57`: the Rust parser rejects a trailing
    /// partial header (1–15 bytes after the last complete record) instead of ignoring it.
    #[test]
    fn parse_odrec_stream_rejects_trailing_partial_header() {
        let mut writer = OdrecWriter::new();
        assert!(writer.append(&frame(RecordFlags::KEYFRAME, 0, 8)).is_ok());
        let mut bytes = writer.as_bytes().to_vec();
        bytes.extend_from_slice(&[0x00, 0x02, 0x00, 0x00, 0x00]);

        assert_eq!(
            parse_odrec_stream(&bytes),
            Err(RecordingError::TruncatedRecord {
                expected: ODREC_HEADER_LEN,
                actual: 5,
            })
        );
    }

    #[test]
    fn asciicast_v2_and_command_storage_indexing() {
        let mut cast = AsciicastRecorder::new(120, 40, 1_700_000_000, Some("Audit Demo"));
        cast.record_event(250, AsciicastEventType::Output, "root@node:~# ");
        cast.record_event(
            1_500,
            AsciicastEventType::Input,
            "sudo systemctl restart sshd\r\n",
        );

        let serialized = cast.to_cast_string();
        assert!(serialized.starts_with("{\"version\":2,\"width\":120,\"height\":40"));
        assert!(serialized.contains("[0.250,\"o\",\"root@node:~# \"]"));
        assert!(serialized.contains("[1.500,\"i\",\"sudo systemctl restart sshd\\r\\n\"]"));

        let mut store = CommandStorage::new();
        store.record_command("sess-1", "alice", "dev-1", "ls -la", "total 8", 100);
        store.record_command(
            "sess-1",
            "alice",
            "dev-1",
            "sudo systemctl stop firewalld",
            "",
            200,
        );
        store.record_command("sess-2", "bob", "dev-2", "rm -rf /tmp/*", "", 300);

        let warnings = store.search("", Some("sess-1"), Some(CommandRiskLevel::Warning));
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].risk_level, CommandRiskLevel::Warning);
    }
}
