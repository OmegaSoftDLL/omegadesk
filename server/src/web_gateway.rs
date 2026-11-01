//! Web client gateway, Origin/Host verification, per-IP rate & connection limits,
//! Selkies per-frame ACK backpressure & binary opcode framing, `WebCodecs` codec
//! ladder, and noVNC/Guacamole scancode + keysym keyboard mapping.
//!
//! Reference implementations:
//! - `zibo-chen_SubnetDesk/src/web_gateway.rs` (lines 66–416, AGPL-3.0):
//!   `DEFAULT_WEB_PORT = 18_123`, `MAX_WEBSOCKET_PAYLOAD_LEN = 32 MiB`,
//!   `MAX_WEBSOCKET_CLIENT_PAYLOAD_LEN = 256 KiB`, `MAX_WEB_CONNECTIONS = 16`,
//!   `MAX_WEB_CONNECTIONS_PER_SOURCE = 4`, `MAX_WEB_REQUESTS_PER_MINUTE = 120`,
//!   `CONTENT_SECURITY_POLICY`, [`ConnectionLimiter`], [`RequestRateBudget`],
//!   [`valid_authority`], [`origin_allowed`], and [`authority_host_allowed`].
//! - `zibo-chen_SubnetDesk/web/src/capabilities.ts`, `video.ts` & `video-worker.ts`:
//!   [`VIDEO_CODEC_CANDIDATES`] (`vp09.00.10.08`, `avc1.42001f`, `av01.0.04M.08`),
//!   [`choose_video_codec`], and `MAX_DECODE_QUEUE_SIZE = 6`.
//! - `selkies-project_selkies/src/selkies/websockets_mode.py` (lines 26–39, 145–196,
//!   MPL-2.0): binary frame opcodes (`0x01` Opus audio, `0x02` mic PCM, `0x03`
//!   lossless paint-over, `0x04` video frame with `u16` frame ID, `0x05` compressed
//!   control text) and [`FrameBackpressureGate`] (`BACKPRESSURE_ALLOWED_DESYNC_MS = 250`,
//!   `RTT_SAMPLE_SANE_MAX_MS = 10_000`, `STALLED_CLIENT_TIMEOUT = 4 s`, stall timed from
//!   the first send after the newest ACK like Selkies' `unacked_since`).
//!   The browser-side contract (`web/src/video.ts`) is the [`WEB_VIDEO_PROTOCOL`]
//!   framing below, verified by shared fixtures ([`WEB_VIDEO_FRAME_FIXTURE`],
//!   [`WEB_FRAME_ACK_FIXTURE`]).
//! - `novnc_noVNC/core/input/keyboard.js`, `core/input/util.js` and
//!   `core/input/domkeytable.js` (MPL-2.0): browser `KeyboardEvent.code` to QEMU
//!   extended scancode + X11 keysym mapping (right-hand modifiers chosen by `code`,
//!   numpad `KP_*` keysyms, ABNT2 `IntlRo` and `IntlBackslash`); HID usages and XT
//!   scancodes follow `crates/input/src/hid.rs`.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Default HTTPS/WebSocket port (`SubnetDesk/src/web_gateway.rs:66`).
pub const DEFAULT_WEB_PORT: u16 = 18_123;

/// Maximum server-to-browser WebSocket payload size (32 MiB, `web_gateway.rs:67`).
pub const MAX_WEBSOCKET_PAYLOAD_LEN: usize = 32 * 1024 * 1024;

/// Maximum browser-to-server WebSocket payload size (256 KiB, `web_gateway.rs:68`).
pub const MAX_WEBSOCKET_CLIENT_PAYLOAD_LEN: usize = 256 * 1024;

/// Default maximum concurrent web sessions (`web_gateway.rs:69`).
pub const MAX_WEB_CONNECTIONS: usize = 16;

/// Default maximum concurrent web sessions per source IP (`web_gateway.rs:70`).
pub const MAX_WEB_CONNECTIONS_PER_SOURCE: usize = 4;

/// Default maximum HTTP/WebSocket upgrade requests per IP per minute (`web_gateway.rs:71`).
pub const MAX_WEB_REQUESTS_PER_MINUTE: usize = 120;

/// Maximum queued frames inside the browser `VideoDecoder` before dropping delta frames
/// and awaiting a keyframe (`SubnetDesk/web/src/video.ts:29`).
pub const MAX_DECODE_QUEUE_SIZE: u32 = 6;

/// Strict Content-Security-Policy header (`SubnetDesk/src/web_gateway.rs:91`).
pub const CONTENT_SECURITY_POLICY: &str = "default-src 'self'; base-uri 'none'; connect-src 'self'; frame-ancestors 'none'; img-src 'self' data:; object-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; worker-src 'self' blob:";

/// Allowed queuing desync beyond smoothed path RTT before gating delta frames
/// (`Selkies/websockets_mode.py:145`).
pub const BACKPRESSURE_ALLOWED_DESYNC_MS: u64 = 250;

/// Maximum sane per-frame ACK round-trip sample (`Selkies/websockets_mode.py:156`).
pub const RTT_SAMPLE_SANE_MAX_MS: u64 = 10_000;

/// Unanswered frame timeout marking a browser client stalled (`Selkies/websockets_mode.py:196`).
pub const STALLED_CLIENT_TIMEOUT: Duration = Duration::from_secs(4);

/// Wrap-around half-range threshold for `u16` frame IDs (`Selkies/websockets_mode.py:192`).
pub const FRAME_ID_SUSPICIOUS_GAP_THRESHOLD: u16 = u16::MAX / 2;

/// Web gateway errors.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WebGatewayError {
    /// Global concurrent connection limit reached (`ConnectionLimitError::Global`).
    #[error("global web connection limit reached")]
    GlobalConnectionLimit,
    /// Per-source IP connection limit reached (`ConnectionLimitError::Source`).
    #[error("per-IP web connection limit reached")]
    SourceConnectionLimit,
    /// Per-IP request rate limit exceeded.
    #[error("per-IP request rate budget exceeded")]
    RateLimited,
    /// Invalid or mismatched `Origin` / `Host` header.
    #[error("forbidden origin or authority")]
    ForbiddenOrigin,
    /// Empty or oversized WebSocket payload (`validate_websocket_payload_len`).
    #[error("invalid websocket payload length: {0}")]
    InvalidPayloadLength(usize),
    /// Unknown binary frame opcode byte.
    #[error("unknown binary websocket opcode: 0x{0:02x}")]
    UnknownBinaryOpcode(u8),
    /// Binary frame is shorter than its opcode's fixed header or has the wrong length.
    #[error("malformed binary frame for opcode 0x{opcode:02x}: {len} bytes")]
    MalformedBinaryFrame {
        /// Leading opcode byte.
        opcode: u8,
        /// Total frame length received.
        len: usize,
    },
}

/// Global and per-IP connection limiter ported from `zibo-chen_SubnetDesk/src/web_gateway.rs`
/// (`ConnectionLimiter` & `ConnectionPermit`, lines 120–181).
#[derive(Clone, Debug)]
pub struct ConnectionLimiter {
    global: Arc<Semaphore>,
    per_source: Arc<Mutex<HashMap<IpAddr, usize>>>,
    max_per_source: usize,
}

/// RAII permit releasing both the global semaphore and the per-source IP counter on drop
/// (`SubnetDesk/src/web_gateway.rs:133-181`).
#[derive(Debug)]
pub struct ConnectionPermit {
    _global: OwnedSemaphorePermit,
    source: IpAddr,
    per_source: Arc<Mutex<HashMap<IpAddr, usize>>>,
}

impl ConnectionLimiter {
    /// Creates a new limiter with `max_global` total permits and `max_per_source` permits per IP.
    #[must_use]
    pub fn new(max_global: usize, max_per_source: usize) -> Self {
        Self {
            global: Arc::new(Semaphore::new(max_global)),
            per_source: Arc::new(Mutex::new(HashMap::new())),
            max_per_source,
        }
    }

    /// Attempts to acquire a connection slot for `source` (`web_gateway.rs:148-167`).
    ///
    /// # Errors
    ///
    /// Returns [`WebGatewayError::GlobalConnectionLimit`] or [`WebGatewayError::SourceConnectionLimit`].
    pub fn try_acquire(&self, source: IpAddr) -> Result<ConnectionPermit, WebGatewayError> {
        let global = self
            .global
            .clone()
            .try_acquire_owned()
            .map_err(|_| WebGatewayError::GlobalConnectionLimit)?;
        let Ok(mut sources) = self.per_source.lock() else {
            return Err(WebGatewayError::SourceConnectionLimit);
        };
        let count = sources.entry(source).or_default();
        if *count >= self.max_per_source {
            return Err(WebGatewayError::SourceConnectionLimit);
        }
        *count += 1;
        drop(sources);
        Ok(ConnectionPermit {
            _global: global,
            source,
            per_source: Arc::clone(&self.per_source),
        })
    }
}

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        if let Ok(mut sources) = self.per_source.lock()
            && let Some(count) = sources.get_mut(&self.source)
        {
            *count = count.saturating_sub(1);
            if *count == 0 {
                sources.remove(&self.source);
            }
        }
    }
}

/// Sliding-window per-IP request rate limiter, derived from `RequestRateBudget` in
/// `zibo-chen_SubnetDesk/src/web_gateway.rs` (lines 269–302).
///
/// SubnetDesk keeps `(window_start, count)` per IP and resets the counter when the
/// first request ages out, which is a *fixed* window: 1 request at `t = 0`, 119 at
/// `t = 59.9 s` and 120 more at `t = 60.1 s` are all accepted (239 within 0.2 s). Here
/// every accepted request's timestamp is kept and expired individually, so any
/// trailing `window` holds at most `max_requests` accepted requests.
#[derive(Debug)]
pub struct RequestRateBudget {
    max_requests: usize,
    window: Duration,
    sources: HashMap<IpAddr, VecDeque<Instant>>,
}

impl RequestRateBudget {
    /// Creates a new per-IP request rate budget (`web_gateway.rs:276`).
    #[must_use]
    pub fn new(max_requests: usize, window: Duration) -> Self {
        Self {
            max_requests,
            window,
            sources: HashMap::new(),
        }
    }

    /// Evaluates whether a request from `source` at `now` is within budget: accepted
    /// timestamps older than `window` are expired one by one, and the request is
    /// admitted only if fewer than `max_requests` accepted requests remain in the window.
    pub fn allow_at(&mut self, source: IpAddr, now: Instant) -> bool {
        let window = self.window;
        self.sources.retain(|_, accepted| {
            while accepted
                .front()
                .is_some_and(|&at| now.saturating_duration_since(at) >= window)
            {
                accepted.pop_front();
            }
            !accepted.is_empty()
        });
        let accepted = self.sources.entry(source).or_default();
        if accepted.len() >= self.max_requests {
            return false;
        }
        accepted.push_back(now);
        true
    }
}

/// Validates an HTTP `Host` / authority string (`SubnetDesk/src/web_gateway.rs:330-349`).
#[must_use]
pub fn valid_authority(authority: &str) -> bool {
    if authority.is_empty()
        || authority.len() > 512
        || authority.chars().any(char::is_whitespace)
        || authority
            .chars()
            .any(|c| matches!(c, '@' | '/' | '\\' | '?' | '#'))
    {
        return false;
    }
    let Some((host, port_opt)) = split_authority_host_port(authority) else {
        return false;
    };
    if host.is_empty() {
        return false;
    }
    if let Some(port_str) = port_opt
        && port_str.parse::<u16>().map_or(true, |p| p == 0)
    {
        return false;
    }
    true
}

/// Checks whether the `Origin` header matches `authority` and scheme (`secure` -> `https`),
/// ported from `origin_allowed` in `SubnetDesk/src/web_gateway.rs:366-388`.
#[must_use]
pub fn origin_allowed(origin: Option<&str>, authority: &str, secure: bool) -> bool {
    if !valid_authority(authority) {
        return false;
    }
    let Some(origin) = origin else {
        return false;
    };
    let expected_scheme = if secure { "https" } else { "http" };
    let default_port: u16 = if secure { 443 } else { 80 };

    let Some((scheme, rest)) = origin.split_once("://") else {
        return false;
    };
    if !scheme.eq_ignore_ascii_case(expected_scheme) {
        return false;
    }
    let origin_authority = rest.strip_suffix('/').unwrap_or(rest);
    if !valid_authority(origin_authority) {
        return false;
    }

    let Some((actual_host, actual_port)) = split_authority_host_port(origin_authority) else {
        return false;
    };
    let Some((expected_host, expected_port)) = split_authority_host_port(authority) else {
        return false;
    };

    let actual_port_num = actual_port
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(default_port);
    let expected_port_num = expected_port
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(default_port);

    actual_host.eq_ignore_ascii_case(expected_host) && actual_port_num == expected_port_num
}

/// Checks whether `authority`'s normalized host is in `allowed_hosts`
/// (`SubnetDesk/src/web_gateway.rs:390-406`).
#[must_use]
pub fn authority_host_allowed<S: std::hash::BuildHasher>(
    authority: &str,
    allowed_hosts: &HashSet<String, S>,
) -> bool {
    if !valid_authority(authority) {
        return false;
    }
    let Some((host, _)) = split_authority_host_port(authority) else {
        return false;
    };
    let normalized = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase();
    allowed_hosts.contains(&normalized)
}

/// Validates WebSocket payload length (`SubnetDesk/src/web_gateway.rs:408-416`).
///
/// # Errors
///
/// Returns [`WebGatewayError::InvalidPayloadLength`] if `len == 0` or `len > max_len`.
pub const fn validate_websocket_payload_len(
    len: usize,
    max_len: usize,
) -> Result<(), WebGatewayError> {
    if len == 0 || len > max_len {
        return Err(WebGatewayError::InvalidPayloadLength(len));
    }
    Ok(())
}

fn split_authority_host_port(authority: &str) -> Option<(&str, Option<&str>)> {
    if let Some(rest) = authority.strip_prefix('[') {
        let (ipv6_host, after_bracket) = rest.split_once(']')?;
        if after_bracket.is_empty() {
            return Some((ipv6_host, None));
        }
        let port = after_bracket.strip_prefix(':')?;
        return Some((ipv6_host, Some(port)));
    }
    if let Some((host, port)) = authority.rsplit_once(':') {
        if host.contains(':') {
            return None;
        }
        Some((host, Some(port)))
    } else {
        Some((authority, None))
    }
}

/// `WebCodecs` protocol video codec identifier (`SubnetDesk/web/src/capabilities.ts:1`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebVideoCodec {
    /// VP9 Profile 0 (`vp09.00.10.08`).
    Vp9,
    /// H.264 Constrained Baseline Level 3.1 (`avc1.42001f`).
    H264,
    /// AV1 Main Profile Level 3.0 (`av01.0.04M.08`).
    Av1,
}

/// `WebCodecs` `VideoDecoder.isConfigSupported` candidate entry
/// (`SubnetDesk/web/src/capabilities.ts:3-14`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WebCodecCandidate {
    /// `WebCodecs` codec string passed to `VideoDecoder.configure`.
    pub codec_string: &'static str,
    /// Protocol codec enum.
    pub protocol: WebVideoCodec,
}

/// Ordered codec ladder probed via `VideoDecoder.isConfigSupported`
/// (`SubnetDesk/web/src/capabilities.ts:10-14`).
pub const VIDEO_CODEC_CANDIDATES: &[WebCodecCandidate] = &[
    WebCodecCandidate {
        codec_string: "vp09.00.10.08",
        protocol: WebVideoCodec::Vp9,
    },
    WebCodecCandidate {
        codec_string: "avc1.42001f",
        protocol: WebVideoCodec::H264,
    },
    WebCodecCandidate {
        codec_string: "av01.0.04M.08",
        protocol: WebVideoCodec::Av1,
    },
];

/// Selects the highest-priority `WebCodecs` codec supported by the browser
/// (`chooseVideoCodec` in `SubnetDesk/web/src/capabilities.ts:16-23`).
pub fn choose_video_codec<F>(mut is_supported: F) -> Option<WebCodecCandidate>
where
    F: FnMut(&str) -> bool,
{
    VIDEO_CODEC_CANDIDATES
        .iter()
        .copied()
        .find(|candidate| is_supported(candidate.codec_string))
}

/// First-byte binary frame opcode used over WebTransport / WebSocket
/// (`Selkies/src/selkies/websockets_mode.py:26-35`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BinaryFrameOpcode {
    /// `0x01`: Opus audio frame (`pcmflux` / `AudioFrame`).
    OpusAudio = 0x01,
    /// `0x02`: Client microphone PCM uplink.
    ClientMicPcm = 0x02,
    /// `0x03`: Lossless static region / JPEG paint-over tile.
    LosslessTile = 0x03,
    /// `0x04`: Encoded video frame, see [`WEB_VIDEO_PROTOCOL`].
    VideoFrame = 0x04,
    /// `0x05`: Compressed control message (`_gz,1`).
    CompressedControl = 0x05,
    /// `0x06`: Browser-to-gateway per-frame ACK (binary form of Selkies'
    /// `CLIENT_FRAME_ACK <id> <heldMs>` text verb), see [`WEB_VIDEO_PROTOCOL`].
    ClientFrameAck = 0x06,
}

impl BinaryFrameOpcode {
    /// Decodes the leading opcode byte (`Selkies/websockets_mode.py:26-30` plus `0x06`).
    ///
    /// # Errors
    ///
    /// Returns [`WebGatewayError::UnknownBinaryOpcode`] if `byte` is not in `0x01..=0x06`.
    pub const fn from_byte(byte: u8) -> Result<Self, WebGatewayError> {
        match byte {
            0x01 => Ok(Self::OpusAudio),
            0x02 => Ok(Self::ClientMicPcm),
            0x03 => Ok(Self::LosslessTile),
            0x04 => Ok(Self::VideoFrame),
            0x05 => Ok(Self::CompressedControl),
            0x06 => Ok(Self::ClientFrameAck),
            other => Err(WebGatewayError::UnknownBinaryOpcode(other)),
        }
    }
}

/// Binary video / ACK protocol shared with the browser client. **This Rust definition is
/// the source of truth**; `web/src/video.ts` mirrors it byte for byte and both sides
/// decode the same fixtures ([`WEB_VIDEO_FRAME_FIXTURE`], [`WEB_FRAME_ACK_FIXTURE`]).
///
/// ```text
/// Video frame (gateway -> browser), opcode 0x04, 12-byte header, big-endian:
///   [0]      0x04                      BinaryFrameOpcode::VideoFrame
///   [1]      flags                     bit0 = keyframe (IDR / sync sample), other bits 0
///   [2..4]   frame_id    u16           wraps at 65535; the id the browser ACKs
///   [4..12]  timestamp   u64           capture timestamp in microseconds (EncodedVideoChunk.timestamp)
///   [12..]   payload                   codec bitstream (Annex-B H.264 / VP9 / AV1 OBUs)
///
/// Frame ACK (browser -> gateway), opcode 0x06, exactly 5 bytes, big-endian:
///   [0]      0x06                      BinaryFrameOpcode::ClientFrameAck
///   [1..3]   frame_id    u16           newest frame the browser has *rendered* (or discarded)
///   [3..5]   held_ms     u16           ms between arrival and this ACK (decode + render), capped
/// ```
///
/// The frame layout follows Selkies' `0x04` chunks (`websockets_mode.py`: typed first
/// byte, `u16` frame id acknowledged by the client) and the ACK is the binary form of
/// Selkies' `CLIENT_FRAME_ACK <id> <heldMs>` text verb (`selkies-ws-core.js`).
pub const WEB_VIDEO_PROTOCOL: &str = "omegadesk-web-video/1";

/// Length of the fixed video frame header (opcode + flags + `u16` id + `u64` timestamp).
pub const WEB_VIDEO_FRAME_HEADER_LEN: usize = 12;

/// Exact length of a browser frame ACK (opcode + `u16` id + `u16` held ms).
pub const WEB_FRAME_ACK_LEN: usize = 5;

/// `flags` bit marking a keyframe in the video frame header.
pub const WEB_VIDEO_FLAG_KEYFRAME: u8 = 0x01;

/// Shared fixture: keyframe `frame_id = 0x1234`, `timestamp_us = 1_000_000`, payload
/// `DE AD BE`. `web/src/video.ts` (`VIDEO_FRAME_FIXTURE`) decodes the same bytes.
pub const WEB_VIDEO_FRAME_FIXTURE: [u8; 15] = [
    0x04, 0x01, 0x12, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x42, 0x40, 0xDE, 0xAD, 0xBE,
];

/// Shared fixture: ACK for `frame_id = 0x1234` held for `42 ms`. `web/src/video.ts`
/// (`FRAME_ACK_FIXTURE`) encodes the same bytes.
pub const WEB_FRAME_ACK_FIXTURE: [u8; 5] = [0x06, 0x12, 0x34, 0x00, 0x2A];

/// Decoded header of an opcode `0x04` video frame (see [`WEB_VIDEO_PROTOCOL`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WebVideoFrameHeader {
    /// Wrapping `u16` frame identifier acknowledged by the browser.
    pub frame_id: u16,
    /// `true` if the payload is a keyframe.
    pub keyframe: bool,
    /// Capture timestamp in microseconds.
    pub timestamp_us: u64,
}

/// Decoded opcode `0x06` browser frame ACK (see [`WEB_VIDEO_PROTOCOL`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WebFrameAck {
    /// Newest frame the browser rendered or deliberately discarded.
    pub frame_id: u16,
    /// Milliseconds the frame was held in the browser before this ACK.
    pub held_ms: u16,
}

/// Encodes a video chunk with the [`WEB_VIDEO_PROTOCOL`] `0x04` header.
#[must_use]
pub fn pack_web_video_frame(
    frame_id: u16,
    keyframe: bool,
    timestamp_us: u64,
    bitstream: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(WEB_VIDEO_FRAME_HEADER_LEN + bitstream.len());
    out.push(BinaryFrameOpcode::VideoFrame as u8);
    out.push(if keyframe { WEB_VIDEO_FLAG_KEYFRAME } else { 0 });
    out.extend_from_slice(&frame_id.to_be_bytes());
    out.extend_from_slice(&timestamp_us.to_be_bytes());
    out.extend_from_slice(bitstream);
    out
}

/// Decodes a [`WEB_VIDEO_PROTOCOL`] `0x04` video frame into its header and payload.
///
/// # Errors
///
/// Returns [`WebGatewayError::UnknownBinaryOpcode`] if the first byte is not `0x04` and
/// [`WebGatewayError::MalformedBinaryFrame`] if the frame is shorter than the header.
pub fn parse_web_video_frame(
    frame: &[u8],
) -> Result<(WebVideoFrameHeader, &[u8]), WebGatewayError> {
    let Some(&opcode) = frame.first() else {
        return Err(WebGatewayError::MalformedBinaryFrame { opcode: 0, len: 0 });
    };
    if opcode != BinaryFrameOpcode::VideoFrame as u8 {
        return Err(WebGatewayError::UnknownBinaryOpcode(opcode));
    }
    let (Some(flags), Some(id), Some(ts), Some(payload)) = (
        frame.get(1),
        frame.get(2..4),
        frame.get(4..12),
        frame.get(WEB_VIDEO_FRAME_HEADER_LEN..),
    ) else {
        return Err(WebGatewayError::MalformedBinaryFrame {
            opcode,
            len: frame.len(),
        });
    };
    let frame_id = u16::from_be_bytes(id.try_into().unwrap_or([0; 2]));
    let timestamp_us = u64::from_be_bytes(ts.try_into().unwrap_or([0; 8]));
    Ok((
        WebVideoFrameHeader {
            frame_id,
            keyframe: flags & WEB_VIDEO_FLAG_KEYFRAME != 0,
            timestamp_us,
        },
        payload,
    ))
}

/// Encodes a [`WEB_VIDEO_PROTOCOL`] `0x06` browser frame ACK.
#[must_use]
pub fn pack_web_frame_ack(frame_id: u16, held_ms: u16) -> [u8; WEB_FRAME_ACK_LEN] {
    let id = frame_id.to_be_bytes();
    let held = held_ms.to_be_bytes();
    [
        BinaryFrameOpcode::ClientFrameAck as u8,
        id[0],
        id[1],
        held[0],
        held[1],
    ]
}

/// Decodes a [`WEB_VIDEO_PROTOCOL`] `0x06` browser frame ACK.
///
/// # Errors
///
/// Returns [`WebGatewayError::UnknownBinaryOpcode`] if the first byte is not `0x06` and
/// [`WebGatewayError::MalformedBinaryFrame`] if the frame is not exactly
/// [`WEB_FRAME_ACK_LEN`] bytes.
pub fn parse_web_frame_ack(frame: &[u8]) -> Result<WebFrameAck, WebGatewayError> {
    let Some(&opcode) = frame.first() else {
        return Err(WebGatewayError::MalformedBinaryFrame { opcode: 0, len: 0 });
    };
    if opcode != BinaryFrameOpcode::ClientFrameAck as u8 {
        return Err(WebGatewayError::UnknownBinaryOpcode(opcode));
    }
    match frame {
        [_, id_hi, id_lo, held_hi, held_lo] => Ok(WebFrameAck {
            frame_id: u16::from_be_bytes([*id_hi, *id_lo]),
            held_ms: u16::from_be_bytes([*held_hi, *held_lo]),
        }),
        _ => Err(WebGatewayError::MalformedBinaryFrame {
            opcode,
            len: frame.len(),
        }),
    }
}

/// Per-frame ACK backpressure and smoothed RTT tracker ported from
/// `selkies-project_selkies/src/selkies/websockets_mode.py` (`_run_frame_backpressure_logic`,
/// lines 145–196).
#[derive(Debug)]
pub struct FrameBackpressureGate {
    in_flight: VecDeque<(u16, Instant)>,
    last_acked_id: Option<u16>,
    last_ack_at: Option<Instant>,
    smoothed_rtt_ms: u64,
}

impl Default for FrameBackpressureGate {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameBackpressureGate {
    /// Creates a new per-frame ACK backpressure tracker.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            in_flight: VecDeque::new(),
            last_acked_id: None,
            last_ack_at: None,
            smoothed_rtt_ms: 20,
        }
    }

    /// Returns the exponentially smoothed RTT in milliseconds.
    #[must_use]
    pub const fn smoothed_rtt_ms(&self) -> u64 {
        self.smoothed_rtt_ms
    }

    /// Records that `frame_id` was transmitted at `now`.
    ///
    /// When the in-flight queue goes from empty to non-empty the stall timer restarts:
    /// like Selkies' `unacked_since` ("timed from the first send after the newest
    /// ack", `websockets_mode.py` `_run_frame_backpressure_logic`), a client that was
    /// idle while the desktop was still is not judged stalled the moment the next
    /// frame goes out.
    pub fn record_frame_sent(&mut self, frame_id: u16, now: Instant) {
        if self.in_flight.is_empty() {
            self.last_ack_at = Some(now);
        } else if self.in_flight.len() >= 128 {
            self.in_flight.pop_front();
        }
        self.in_flight.push_back((frame_id, now));
    }

    /// Number of transmitted frames not yet acknowledged.
    #[must_use]
    pub fn in_flight_len(&self) -> usize {
        self.in_flight.len()
    }

    /// Processes a browser frame ACK (`0x06`, see [`WEB_VIDEO_PROTOCOL`]) for `acked_id` at `now`.
    ///
    /// ACKs are **per frame**, not cumulative: `web/src/video-worker.ts` acknowledges every
    /// frame it receives, after rendering it or immediately when it discards it. Only the
    /// matching in-flight entry is removed, so a discard ACK for frame 7 while frames 1–6
    /// are still inside the decoder leaves that backlog visible to
    /// [`Self::should_drop_delta_frame`] (Selkies' newest-id cumulative ACK would hide it).
    /// The RTT sample comes from the matched send time (`websockets_mode.py:156`); an ACK
    /// for an unknown id still counts as a liveness signal.
    pub fn record_frame_ack(&mut self, acked_id: u16, now: Instant) {
        self.last_ack_at = Some(now);
        self.last_acked_id = Some(acked_id);

        let Some(index) = self
            .in_flight
            .iter()
            .position(|&(sent_id, _)| sent_id == acked_id)
        else {
            return;
        };
        if let Some((_, sent_at)) = self.in_flight.remove(index) {
            #[allow(clippy::cast_possible_truncation)]
            let sample_ms = now.saturating_duration_since(sent_at).as_millis() as u64;
            if sample_ms <= RTT_SAMPLE_SANE_MAX_MS {
                // EWMA smoothing (7/8 old + 1/8 new).
                self.smoothed_rtt_ms = (self.smoothed_rtt_ms * 7 + sample_ms) / 8;
            }
        }
    }

    /// Returns `true` if delta frames should be dropped because the oldest unacknowledged
    /// frame exceeds `smoothed_rtt_ms + BACKPRESSURE_ALLOWED_DESYNC_MS` (`websockets_mode.py:145`).
    #[must_use]
    pub fn should_drop_delta_frame(&self, now: Instant) -> bool {
        let Some(&(_, oldest_sent_at)) = self.in_flight.front() else {
            return false;
        };
        #[allow(clippy::cast_possible_truncation)]
        let oldest_age_ms = now.saturating_duration_since(oldest_sent_at).as_millis() as u64;
        oldest_age_ms
            > self
                .smoothed_rtt_ms
                .saturating_add(BACKPRESSURE_ALLOWED_DESYNC_MS)
    }

    /// Returns `true` if the client has not acknowledged any frame within
    /// [`STALLED_CLIENT_TIMEOUT`] (`4.0 s`, `websockets_mode.py:196`).
    #[must_use]
    pub fn is_client_stalled(&self, now: Instant) -> bool {
        !self.in_flight.is_empty()
            && self
                .last_ack_at
                .is_some_and(|last| now.saturating_duration_since(last) >= STALLED_CLIENT_TIMEOUT)
    }
}

/// Translated keyboard event combining physical QEMU extended scancode and X11 keysym
/// (`docs/plan.md` §2.5 line 88: `noVNC (QEMU ext key), Guacamole Keyboard.js`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WebKeyMapping {
    /// USB HID usage page `0x07` code (for `omegadesk-input`).
    pub usb_hid_usage: u16,
    /// QEMU extended XT scancode (`0xE0` prefix encoded as `0x100 | scancode`).
    pub qemu_scancode: u16,
    /// X11 keysym (`XK_*`) or Unicode codepoint keysym (`0x0100_0000 | cp`).
    pub keysym: u32,
}

/// Maps a browser `KeyboardEvent.code` and `KeyboardEvent.key` to a [`WebKeyMapping`]
/// (USB HID usage + QEMU extended scancode + X11 keysym), supporting international
/// layouts including Brazilian ABNT2 (`IntlRo` and `IntlBackslash`),
/// ported from `noVNC/core/input/keyboard.js`, `util.js` (`getKeysym`) and
/// `domkeytable.js`, plus `Guacamole/Keyboard.js`.
///
/// Browsers report the same `key` for both modifiers of a pair (`"Shift"`,
/// `"Control"`, `"Alt"`, `"Meta"`), so the right-hand X11 keysyms are chosen from
/// `code` the way noVNC derives `location` from `code`; `AltGraph` keeps
/// `XK_ISO_Level3_Shift`. Numpad keys get `XK_KP_*` keysyms (`addNumpad` in
/// `domkeytable.js`).
#[must_use]
pub fn map_browser_key_event(code: &str, key: &str) -> Option<WebKeyMapping> {
    let (usb_hid_usage, qemu_scancode) = physical_key_mapping(code)?;
    let keysym = named_keysym(code, key).unwrap_or_else(|| character_keysym(key));
    Some(WebKeyMapping {
        usb_hid_usage,
        qemu_scancode,
        keysym,
    })
}

/// `KeyboardEvent.code` to `(USB HID usage, QEMU extended XT scancode)`. HID usages and
/// Set 1 scancodes mirror `hid_to_scancode` in `crates/input/src/hid.rs` (extended
/// `0xE0`-prefixed keys encoded as `0x100 | scancode`).
#[allow(clippy::too_many_lines, reason = "flat physical key table")]
fn physical_key_mapping(code: &str) -> Option<(u16, u16)> {
    let mapping = match code {
        "KeyA" => (0x04, 0x1E),
        "KeyB" => (0x05, 0x30),
        "KeyC" => (0x06, 0x2E),
        "KeyD" => (0x07, 0x20),
        "KeyE" => (0x08, 0x12),
        "KeyF" => (0x09, 0x21),
        "KeyG" => (0x0A, 0x22),
        "KeyH" => (0x0B, 0x23),
        "KeyI" => (0x0C, 0x17),
        "KeyJ" => (0x0D, 0x24),
        "KeyK" => (0x0E, 0x25),
        "KeyL" => (0x0F, 0x26),
        "KeyM" => (0x10, 0x32),
        "KeyN" => (0x11, 0x31),
        "KeyO" => (0x12, 0x18),
        "KeyP" => (0x13, 0x19),
        "KeyQ" => (0x14, 0x10),
        "KeyR" => (0x15, 0x13),
        "KeyS" => (0x16, 0x1F),
        "KeyT" => (0x17, 0x14),
        "KeyU" => (0x18, 0x16),
        "KeyV" => (0x19, 0x2F),
        "KeyW" => (0x1A, 0x11),
        "KeyX" => (0x1B, 0x2D),
        "KeyY" => (0x1C, 0x15),
        "KeyZ" => (0x1D, 0x2C),
        "Digit1" => (0x1E, 0x02),
        "Digit2" => (0x1F, 0x03),
        "Digit3" => (0x20, 0x04),
        "Digit4" => (0x21, 0x05),
        "Digit5" => (0x22, 0x06),
        "Digit6" => (0x23, 0x07),
        "Digit7" => (0x24, 0x08),
        "Digit8" => (0x25, 0x09),
        "Digit9" => (0x26, 0x0A),
        "Digit0" => (0x27, 0x0B),
        "Enter" => (0x28, 0x1C),
        "Escape" => (0x29, 0x01),
        "Backspace" => (0x2A, 0x0E),
        "Tab" => (0x2B, 0x0F),
        "Space" => (0x2C, 0x39),
        "Minus" => (0x2D, 0x0C),
        "Equal" => (0x2E, 0x0D),
        "BracketLeft" => (0x2F, 0x1A),
        "BracketRight" => (0x30, 0x1B),
        "Backslash" => (0x31, 0x2B),
        "Semicolon" => (0x33, 0x27),
        "Quote" => (0x34, 0x28),
        "Backquote" => (0x35, 0x29),
        "Comma" => (0x36, 0x33),
        "Period" => (0x37, 0x34),
        "Slash" => (0x38, 0x35),
        "CapsLock" => (0x39, 0x3A),
        "F1" => (0x3A, 0x3B),
        "F2" => (0x3B, 0x3C),
        "F3" => (0x3C, 0x3D),
        "F4" => (0x3D, 0x3E),
        "F5" => (0x3E, 0x3F),
        "F6" => (0x3F, 0x40),
        "F7" => (0x40, 0x41),
        "F8" => (0x41, 0x42),
        "F9" => (0x42, 0x43),
        "F10" => (0x43, 0x44),
        "F11" => (0x44, 0x57),
        "F12" => (0x45, 0x58),
        "PrintScreen" => (0x46, 0x137),
        "ScrollLock" => (0x47, 0x46),
        "Insert" => (0x49, 0x152),
        "Home" => (0x4A, 0x147),
        "PageUp" => (0x4B, 0x149),
        "Delete" => (0x4C, 0x153),
        "End" => (0x4D, 0x14F),
        "PageDown" => (0x4E, 0x151),
        "ArrowRight" => (0x4F, 0x14D),
        "ArrowLeft" => (0x50, 0x14B),
        "ArrowDown" => (0x51, 0x150),
        "ArrowUp" => (0x52, 0x148),
        "NumLock" => (0x53, 0x45),
        "NumpadDivide" => (0x54, 0x135),
        "NumpadMultiply" => (0x55, 0x37),
        "NumpadSubtract" => (0x56, 0x4A),
        "NumpadAdd" => (0x57, 0x4E),
        "NumpadEnter" => (0x58, 0x11C),
        "Numpad1" => (0x59, 0x4F),
        "Numpad2" => (0x5A, 0x50),
        "Numpad3" => (0x5B, 0x51),
        "Numpad4" => (0x5C, 0x4B),
        "Numpad5" => (0x5D, 0x4C),
        "Numpad6" => (0x5E, 0x4D),
        "Numpad7" => (0x5F, 0x47),
        "Numpad8" => (0x60, 0x48),
        "Numpad9" => (0x61, 0x49),
        "Numpad0" => (0x62, 0x52),
        "NumpadDecimal" => (0x63, 0x53),
        // ABNT2 international keys (`IntlBackslash` = 0x64 / XT 0x56, `IntlRo` = 0x87 / XT 0x73,
        // `NumpadComma` = 0x85 / XT 0x7E), `IntlYen` = 0x89 / XT 0x7D, `KanaMode` = 0x88 / XT 0x70.
        "IntlBackslash" => (0x64, 0x56),
        "ContextMenu" => (0x65, 0x15D),
        "NumpadComma" => (0x85, 0x7E),
        "IntlRo" => (0x87, 0x73),
        "KanaMode" => (0x88, 0x70),
        "IntlYen" => (0x89, 0x7D),
        "ControlLeft" => (0xE0, 0x1D),
        "ShiftLeft" => (0xE1, 0x2A),
        "AltLeft" => (0xE2, 0x38),
        "MetaLeft" => (0xE3, 0x15B),
        "ControlRight" => (0xE4, 0x11D),
        "ShiftRight" => (0xE5, 0x36),
        "AltRight" => (0xE6, 0x138),
        "MetaRight" => (0xE7, 0x15C),
        _ => return None,
    };
    Some(mapping)
}

/// X11 keysym for named (non-printable) `KeyboardEvent.key` values, following noVNC's
/// `domkeytable.js` / `util.js getKeysym`: right-hand modifiers are picked by `code`,
/// and keys on the numeric keypad (`code` starting with `Numpad`) use `XK_KP_*`.
fn named_keysym(code: &str, key: &str) -> Option<u32> {
    let right = code.ends_with("Right");
    let numpad = code.starts_with("Numpad");
    let keysym = match key {
        "Enter" if numpad => 0xFF8D, // XK_KP_Enter
        "Enter" => 0xFF0D,
        "Escape" => 0xFF1B,
        "Backspace" => 0xFF08,
        "Tab" => 0xFF09,
        "Pause" => 0xFF13,
        "ScrollLock" => 0xFF14,
        "CapsLock" => 0xFFE5,
        "NumLock" => 0xFF7F,
        "PrintScreen" => 0xFF61,
        "ContextMenu" => 0xFF67,
        "KanaMode" => 0xFF2E, // XK_Kana_Shift (noVNC `domkeytable.js`)
        "Home" if numpad => 0xFF95,
        "Home" => 0xFF50,
        "ArrowLeft" if numpad => 0xFF96,
        "ArrowLeft" => 0xFF51,
        "ArrowUp" if numpad => 0xFF97,
        "ArrowUp" => 0xFF52,
        "ArrowRight" if numpad => 0xFF98,
        "ArrowRight" => 0xFF53,
        "ArrowDown" if numpad => 0xFF99,
        "ArrowDown" => 0xFF54,
        "PageUp" if numpad => 0xFF9A,
        "PageUp" => 0xFF55,
        "PageDown" if numpad => 0xFF9B,
        "PageDown" => 0xFF56,
        "End" if numpad => 0xFF9C,
        "End" => 0xFF57,
        "Clear" if numpad => 0xFF9D, // XK_KP_Begin (numpad 5 without NumLock)
        "Insert" if numpad => 0xFF9E,
        "Insert" => 0xFF63,
        "Delete" if numpad => 0xFF9F,
        "Delete" => 0xFFFF,
        "F1" => 0xFFBE,
        "F2" => 0xFFBF,
        "F3" => 0xFFC0,
        "F4" => 0xFFC1,
        "F5" => 0xFFC2,
        "F6" => 0xFFC3,
        "F7" => 0xFFC4,
        "F8" => 0xFFC5,
        "F9" => 0xFFC6,
        "F10" => 0xFFC7,
        "F11" => 0xFFC8,
        "F12" => 0xFFC9,
        "Shift" if right => 0xFFE2,   // XK_Shift_R
        "Shift" => 0xFFE1,            // XK_Shift_L
        "Control" if right => 0xFFE4, // XK_Control_R
        "Control" => 0xFFE3,          // XK_Control_L
        "Alt" if right => 0xFFEA,     // XK_Alt_R
        "Alt" => 0xFFE9,              // XK_Alt_L
        "AltGraph" => ISO_LEVEL3_SHIFT_KEYSYM,
        "Meta" if right => 0xFFEC, // XK_Super_R (noVNC maps Meta to Super)
        "Meta" => 0xFFEB,          // XK_Super_L
        _ => {
            if !numpad {
                return None;
            }
            // Printable keypad characters -> XK_KP_* (`addNumpad` in noVNC `domkeytable.js`).
            match key {
                "0" => 0xFFB0,
                "1" => 0xFFB1,
                "2" => 0xFFB2,
                "3" => 0xFFB3,
                "4" => 0xFFB4,
                "5" => 0xFFB5,
                "6" => 0xFFB6,
                "7" => 0xFFB7,
                "8" => 0xFFB8,
                "9" => 0xFFB9,
                "*" => 0xFFAA,
                "+" => 0xFFAB,
                "," => 0xFFAC,
                "-" => 0xFFAD,
                "." => 0xFFAE,
                "/" => 0xFFAF,
                _ => return None,
            }
        }
    };
    Some(keysym)
}

/// Keysym for a single printable character: Latin-1 maps directly, everything else
/// uses the Unicode keysym range (`0x0100_0000 | codepoint`). Multi-character or empty
/// `key` values (e.g. `"Dead"`, `"Unidentified"`) yield `0`.
fn character_keysym(key: &str) -> u32 {
    let mut chars = key.chars();
    match (chars.next(), chars.next()) {
        (Some(ch), None) => {
            let cp = u32::from(ch);
            if (0x20..=0xFF).contains(&cp) {
                cp
            } else {
                0x0100_0000 | cp
            }
        }
        _ => 0,
    }
}

const ISO_LEVEL3_SHIFT_KEYSYM: u32 = 0xFE03;

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn subnetdesk_origin_and_connection_limiter_enforce_security_policy() {
        assert!(origin_allowed(
            Some("https://desk.omega.local:18123"),
            "desk.omega.local:18123",
            true
        ));
        assert!(!origin_allowed(
            Some("http://desk.omega.local:18123"),
            "desk.omega.local:18123",
            true
        ));
        assert!(!origin_allowed(
            Some("https://evil.example:18123"),
            "desk.omega.local:18123",
            true
        ));

        let limiter = ConnectionLimiter::new(2, 1);
        let ip1 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));
        let ip2 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 11));
        let ip3 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 12));

        let p1 = limiter.try_acquire(ip1);
        assert!(p1.is_ok());
        // 2nd connection from ip1 hits per-source cap (1).
        assert_eq!(
            limiter.try_acquire(ip1).unwrap_err(),
            WebGatewayError::SourceConnectionLimit
        );

        let p2 = limiter.try_acquire(ip2);
        assert!(p2.is_ok());
        // 3rd total connection hits global cap (2).
        assert_eq!(
            limiter.try_acquire(ip3).unwrap_err(),
            WebGatewayError::GlobalConnectionLimit
        );

        drop(p1);
        assert!(limiter.try_acquire(ip1).is_ok());
    }

    #[test]
    fn selkies_per_frame_ack_tracks_rtt_and_gates_backpressure() {
        let mut gate = FrameBackpressureGate::new();
        let t0 = Instant::now();

        gate.record_frame_sent(1, t0);
        gate.record_frame_ack(1, t0 + Duration::from_millis(12));
        assert!(gate.smoothed_rtt_ms() <= 20);
        assert!(!gate.should_drop_delta_frame(t0 + Duration::from_millis(20)));

        // Unacknowledged frame older than smoothed_rtt + 250ms triggers delta drop.
        gate.record_frame_sent(2, t0 + Duration::from_millis(30));
        assert!(gate.should_drop_delta_frame(t0 + Duration::from_millis(350)));
        assert!(!gate.is_client_stalled(t0 + Duration::from_millis(350)));
        assert!(gate.is_client_stalled(t0 + Duration::from_secs(5)));
    }

    #[test]
    fn codec_ladder_and_abnt2_keyboard_mapping_work() {
        let chosen = choose_video_codec(|codec| codec == "avc1.42001f");
        assert_eq!(
            chosen,
            Some(WebCodecCandidate {
                codec_string: "avc1.42001f",
                protocol: WebVideoCodec::H264,
            })
        );

        let abnt2_slash = map_browser_key_event("IntlRo", "/");
        assert_eq!(
            abnt2_slash,
            Some(WebKeyMapping {
                usb_hid_usage: 0x87,
                qemu_scancode: 0x73,
                keysym: u32::from(b'/'),
            })
        );

        let c_cedilla = map_browser_key_event("Semicolon", "ç");
        assert_eq!(
            c_cedilla,
            Some(WebKeyMapping {
                usb_hid_usage: 0x33,
                qemu_scancode: 0x27,
                keysym: 0x00E7,
            })
        );
    }

    /// Regression for #28 `web_gateway.rs:186`: the budget must be a true sliding
    /// window. With the fixed window, 1 request at t=0, 119 at t=59.9 s and 120 at
    /// t=60.1 s were all accepted (239 within 0.2 s).
    #[test]
    fn request_rate_budget_is_a_sliding_window() {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let other = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let t0 = Instant::now();
        let mut budget =
            RequestRateBudget::new(MAX_WEB_REQUESTS_PER_MINUTE, Duration::from_secs(60));

        assert!(budget.allow_at(ip, t0));
        let t_late = t0 + Duration::from_millis(59_900);
        for _ in 0..119 {
            assert!(budget.allow_at(ip, t_late));
        }
        // Window full: the 121st request within 60 s is rejected.
        assert!(!budget.allow_at(ip, t_late));
        // Another IP has its own budget.
        assert!(budget.allow_at(other, t_late));

        // At t=60.1 s only the t=0 request has expired: exactly one more is allowed.
        let t_after = t0 + Duration::from_millis(60_100);
        assert!(budget.allow_at(ip, t_after));
        assert!(!budget.allow_at(ip, t_after));

        // Once the 119 late requests expire, the budget frees up again.
        let t_free = t_late + Duration::from_secs(60);
        for _ in 0..(MAX_WEB_REQUESTS_PER_MINUTE - 1) {
            assert!(budget.allow_at(ip, t_free));
        }
        assert!(!budget.allow_at(ip, t_free));
    }

    /// Regression for #28 `web_gateway.rs:459`: after an idle period the next frame
    /// must restart the stall timer instead of being judged stalled immediately.
    #[test]
    fn stall_timer_restarts_when_in_flight_queue_becomes_non_empty() {
        let mut gate = FrameBackpressureGate::new();
        let t0 = Instant::now();

        gate.record_frame_sent(1, t0);
        gate.record_frame_ack(1, t0 + Duration::from_millis(15));
        assert!(!gate.is_client_stalled(t0 + Duration::from_secs(10)));

        // Desktop idle for 10 s, then a new frame goes out.
        let resume = t0 + Duration::from_secs(10);
        gate.record_frame_sent(2, resume);
        assert!(
            !gate.is_client_stalled(resume + Duration::from_millis(100)),
            "a fresh frame after idle must get the full STALLED_CLIENT_TIMEOUT"
        );
        assert!(!gate.is_client_stalled(
            resume + STALLED_CLIENT_TIMEOUT.saturating_sub(Duration::from_millis(1))
        ));
        assert!(gate.is_client_stalled(resume + STALLED_CLIENT_TIMEOUT));

        // While frames are already in flight, sending more does not reset the timer.
        gate.record_frame_sent(3, resume + Duration::from_secs(3));
        assert!(gate.is_client_stalled(resume + STALLED_CLIENT_TIMEOUT));
    }

    /// Regression for the PR #38 review: a discard ACK for a newer frame must not clear
    /// the older frames still inside the browser decoder from the in-flight queue.
    #[test]
    fn frame_acks_are_per_frame_and_keep_decoder_backlog_visible() {
        let mut gate = FrameBackpressureGate::new();
        let t0 = Instant::now();
        for id in 1..=7u16 {
            gate.record_frame_sent(id, t0 + Duration::from_millis(u64::from(id) * 10));
        }
        assert_eq!(gate.in_flight_len(), 7);

        // Frame 7 is discarded by the worker (queue overflow) and ACKed at once.
        gate.record_frame_ack(7, t0 + Duration::from_millis(75));
        assert_eq!(
            gate.in_flight_len(),
            6,
            "frames 1-6 are still decoding and must stay in flight"
        );
        assert!(gate.should_drop_delta_frame(t0 + Duration::from_secs(1)));

        // Out-of-order and duplicate ACKs only touch their own entry.
        gate.record_frame_ack(3, t0 + Duration::from_millis(80));
        gate.record_frame_ack(3, t0 + Duration::from_millis(81));
        assert_eq!(gate.in_flight_len(), 5);
        gate.record_frame_ack(42, t0 + Duration::from_millis(82)); // unknown id: liveness only
        assert_eq!(gate.in_flight_len(), 5);
        assert!(!gate.is_client_stalled(t0 + Duration::from_secs(4)));

        for id in [1u16, 2, 4, 5, 6] {
            gate.record_frame_ack(id, t0 + Duration::from_millis(90));
        }
        assert_eq!(gate.in_flight_len(), 0);
        assert!(!gate.should_drop_delta_frame(t0 + Duration::from_secs(1)));
    }

    /// Regression for #28 `video.ts:68`: one video/ACK contract for both sides, pinned
    /// by fixtures that `web/src/video.ts` (`VIDEO_FRAME_FIXTURE`, `FRAME_ACK_FIXTURE`)
    /// decodes and encodes identically.
    #[test]
    fn web_video_protocol_fixtures_match_the_browser_contract() {
        assert_eq!(
            pack_web_video_frame(0x1234, true, 1_000_000, &[0xDE, 0xAD, 0xBE]),
            WEB_VIDEO_FRAME_FIXTURE.to_vec()
        );
        let (header, payload) = parse_web_video_frame(&WEB_VIDEO_FRAME_FIXTURE).unwrap();
        assert_eq!(
            header,
            WebVideoFrameHeader {
                frame_id: 0x1234,
                keyframe: true,
                timestamp_us: 1_000_000,
            }
        );
        assert_eq!(payload, &[0xDE, 0xAD, 0xBE]);
        assert_eq!(
            WEB_VIDEO_FRAME_FIXTURE.len(),
            WEB_VIDEO_FRAME_HEADER_LEN + 3
        );

        // Delta frame with an empty payload round-trips too.
        let delta = pack_web_video_frame(u16::MAX, false, u64::MAX, &[]);
        let (header, payload) = parse_web_video_frame(&delta).unwrap();
        assert_eq!(header.frame_id, u16::MAX);
        assert!(!header.keyframe);
        assert_eq!(header.timestamp_us, u64::MAX);
        assert_eq!(payload, &[0u8; 0][..]);

        assert_eq!(pack_web_frame_ack(0x1234, 42), WEB_FRAME_ACK_FIXTURE);
        assert_eq!(
            parse_web_frame_ack(&WEB_FRAME_ACK_FIXTURE),
            Ok(WebFrameAck {
                frame_id: 0x1234,
                held_ms: 42,
            })
        );
        assert_eq!(
            BinaryFrameOpcode::from_byte(WEB_FRAME_ACK_FIXTURE[0]),
            Ok(BinaryFrameOpcode::ClientFrameAck)
        );

        // Malformed input is rejected, never sliced out of bounds.
        assert_eq!(
            parse_web_video_frame(&WEB_VIDEO_FRAME_FIXTURE[..11]),
            Err(WebGatewayError::MalformedBinaryFrame {
                opcode: 0x04,
                len: 11,
            })
        );
        assert_eq!(
            parse_web_video_frame(&[]),
            Err(WebGatewayError::MalformedBinaryFrame { opcode: 0, len: 0 })
        );
        assert_eq!(
            parse_web_video_frame(&WEB_FRAME_ACK_FIXTURE),
            Err(WebGatewayError::UnknownBinaryOpcode(0x06))
        );
        assert_eq!(
            parse_web_frame_ack(&[0x06, 0x12, 0x34, 0x00]),
            Err(WebGatewayError::MalformedBinaryFrame {
                opcode: 0x06,
                len: 4,
            })
        );
        assert_eq!(
            parse_web_frame_ack(&WEB_VIDEO_FRAME_FIXTURE),
            Err(WebGatewayError::UnknownBinaryOpcode(0x04))
        );
    }

    /// Regression for #28 `web_gateway.rs:594`: punctuation, function keys, navigation,
    /// lock keys and the numpad must translate (HID usages from `crates/input/src/hid.rs`).
    #[test]
    fn browser_key_translation_covers_punctuation_function_navigation_lock_and_numpad_keys() {
        let expect = |code: &str, key: &str, hid: u16, scancode: u16, keysym: u32| {
            assert_eq!(
                map_browser_key_event(code, key),
                Some(WebKeyMapping {
                    usb_hid_usage: hid,
                    qemu_scancode: scancode,
                    keysym,
                }),
                "{code} / {key}"
            );
        };
        // Punctuation that used to return None.
        expect("Minus", "-", 0x2D, 0x0C, u32::from(b'-'));
        expect("Equal", "=", 0x2E, 0x0D, u32::from(b'='));
        expect("Backslash", "\\", 0x31, 0x2B, u32::from(b'\\'));
        // Function keys (`hid_to_scancode`: 0x3A..=0x43 -> 0x3B..=0x44, F11 0x57, F12 0x58).
        expect("F1", "F1", 0x3A, 0x3B, 0xFFBE);
        expect("F10", "F10", 0x43, 0x44, 0xFFC7);
        expect("F11", "F11", 0x44, 0x57, 0xFFC8);
        expect("F12", "F12", 0x45, 0x58, 0xFFC9);
        // Navigation (extended `0xE0` scancodes encoded as `0x100 | code`).
        expect("Delete", "Delete", 0x4C, 0x153, 0xFFFF);
        expect("Home", "Home", 0x4A, 0x147, 0xFF50);
        expect("End", "End", 0x4D, 0x14F, 0xFF57);
        expect("PageUp", "PageUp", 0x4B, 0x149, 0xFF55);
        expect("PageDown", "PageDown", 0x4E, 0x151, 0xFF56);
        expect("Insert", "Insert", 0x49, 0x152, 0xFF63);
        // Lock keys and PrintScreen / ContextMenu.
        expect("CapsLock", "CapsLock", 0x39, 0x3A, 0xFFE5);
        expect("NumLock", "NumLock", 0x53, 0x45, 0xFF7F);
        expect("ScrollLock", "ScrollLock", 0x47, 0x46, 0xFF14);
        expect("PrintScreen", "PrintScreen", 0x46, 0x137, 0xFF61);
        expect("ContextMenu", "ContextMenu", 0x65, 0x15D, 0xFF67);
        expect("KanaMode", "KanaMode", 0x88, 0x70, 0xFF2E);
        // Numpad: XK_KP_* keysyms (noVNC `domkeytable.js` addNumpad).
        expect("Numpad0", "0", 0x62, 0x52, 0xFFB0);
        expect("Numpad9", "9", 0x61, 0x49, 0xFFB9);
        expect("NumpadEnter", "Enter", 0x58, 0x11C, 0xFF8D);
        expect("NumpadAdd", "+", 0x57, 0x4E, 0xFFAB);
        expect("NumpadSubtract", "-", 0x56, 0x4A, 0xFFAD);
        expect("NumpadMultiply", "*", 0x55, 0x37, 0xFFAA);
        expect("NumpadDivide", "/", 0x54, 0x135, 0xFFAF);
        expect("NumpadDecimal", ".", 0x63, 0x53, 0xFFAE);
        expect("NumpadComma", ",", 0x85, 0x7E, 0xFFAC);
        // Numpad without NumLock reports navigation keys: KP_* variants.
        expect("Numpad7", "Home", 0x5F, 0x47, 0xFF95);
        expect("Numpad5", "Clear", 0x5D, 0x4C, 0xFF9D);
        expect("NumpadDecimal", "Delete", 0x63, 0x53, 0xFF9F);
        // Main-row digit on the top row keeps its character keysym.
        expect("Digit1", "1", 0x1E, 0x02, u32::from(b'1'));
        // Dead keys / unidentified produce no keysym but still a scancode.
        assert_eq!(
            map_browser_key_event("Quote", "Dead").map(|m| m.keysym),
            Some(0)
        );
        assert!(map_browser_key_event("Unidentified", "a").is_none());
    }

    /// Regression for #28 `web_gateway.rs:610`: right-hand modifiers must map to the
    /// right-side X11 keysyms (chosen from `code`), while `AltGraph` stays
    /// `XK_ISO_Level3_Shift`.
    #[test]
    fn right_hand_modifiers_use_right_side_keysyms() {
        let keysym = |code: &str, key: &str| map_browser_key_event(code, key).map(|m| m.keysym);
        assert_eq!(keysym("ShiftLeft", "Shift"), Some(0xFFE1));
        assert_eq!(keysym("ShiftRight", "Shift"), Some(0xFFE2));
        assert_eq!(keysym("ControlLeft", "Control"), Some(0xFFE3));
        assert_eq!(keysym("ControlRight", "Control"), Some(0xFFE4));
        assert_eq!(keysym("AltLeft", "Alt"), Some(0xFFE9));
        assert_eq!(keysym("AltRight", "Alt"), Some(0xFFEA));
        assert_eq!(keysym("MetaLeft", "Meta"), Some(0xFFEB));
        assert_eq!(keysym("MetaRight", "Meta"), Some(0xFFEC));
        // AltGr reported as AltGraph keeps the ISO level-3 shift keysym.
        assert_eq!(
            keysym("AltRight", "AltGraph"),
            Some(ISO_LEVEL3_SHIFT_KEYSYM)
        );
        // Scancodes stay side-specific too.
        assert_eq!(
            map_browser_key_event("ControlRight", "Control")
                .map(|m| (m.usb_hid_usage, m.qemu_scancode)),
            Some((0xE4, 0x11D))
        );
    }
}
