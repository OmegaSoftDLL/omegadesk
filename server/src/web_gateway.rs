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
//!   `RTT_SAMPLE_SANE_MAX_MS = 10_000`, `STALLED_CLIENT_TIMEOUT = 4 s`).
//! - `novnc_noVNC/core/input/keyboard.js` (MPL-2.0): browser `KeyboardEvent.code`
//!   to QEMU extended scancode + X11 keysym mapping (including ABNT2 `IntlRo` and
//!   `IntlBackslash`).

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

/// Sliding-window per-IP request rate limiter ported from `zibo-chen_SubnetDesk/src/web_gateway.rs`
/// (`RequestRateBudget`, lines 269–302).
#[derive(Debug)]
pub struct RequestRateBudget {
    max_requests: usize,
    window: Duration,
    sources: HashMap<IpAddr, (Instant, usize)>,
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

    /// Evaluates whether a request from `source` at `now` is within budget (`web_gateway.rs:288`).
    pub fn allow_at(&mut self, source: IpAddr, now: Instant) -> bool {
        self.sources
            .retain(|_, (started, _)| now.saturating_duration_since(*started) < self.window);
        let (started, count) = self.sources.entry(source).or_insert((now, 0));
        if now.saturating_duration_since(*started) >= self.window {
            *started = now;
            *count = 0;
        }
        if *count >= self.max_requests {
            return false;
        }
        *count += 1;
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
    /// `0x04`: Encoded video frame prefixed with a big-endian `u16` frame ID.
    VideoFrame = 0x04,
    /// `0x05`: Compressed control message (`_gz,1`).
    CompressedControl = 0x05,
}

impl BinaryFrameOpcode {
    /// Decodes the leading opcode byte (`Selkies/websockets_mode.py:26-30`).
    ///
    /// # Errors
    ///
    /// Returns [`WebGatewayError::UnknownBinaryOpcode`] if `byte` is not in `0x01..=0x05`.
    pub const fn from_byte(byte: u8) -> Result<Self, WebGatewayError> {
        match byte {
            0x01 => Ok(Self::OpusAudio),
            0x02 => Ok(Self::ClientMicPcm),
            0x03 => Ok(Self::LosslessTile),
            0x04 => Ok(Self::VideoFrame),
            0x05 => Ok(Self::CompressedControl),
            other => Err(WebGatewayError::UnknownBinaryOpcode(other)),
        }
    }
}

/// Encodes a video chunk with the Selkies `0x04` binary header (`[0x04, frame_id_hi, frame_id_lo, key_flag, ..payload]`).
#[must_use]
pub fn pack_web_video_frame(frame_id: u16, keyframe: bool, bitstream: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + bitstream.len());
    out.push(BinaryFrameOpcode::VideoFrame as u8);
    out.extend_from_slice(&frame_id.to_be_bytes());
    out.push(u8::from(keyframe));
    out.extend_from_slice(bitstream);
    out
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
    pub fn record_frame_sent(&mut self, frame_id: u16, now: Instant) {
        if self.in_flight.len() >= 128 {
            self.in_flight.pop_front();
        }
        self.in_flight.push_back((frame_id, now));
        if self.last_ack_at.is_none() {
            self.last_ack_at = Some(now);
        }
    }

    /// Processes a `CLIENT_FRAME_ACK` for `acked_id` at `now` (`websockets_mode.py:34-39, 156`).
    pub fn record_frame_ack(&mut self, acked_id: u16, now: Instant) {
        self.last_ack_at = Some(now);
        self.last_acked_id = Some(acked_id);

        while let Some(&(sent_id, sent_at)) = self.in_flight.front() {
            let diff = acked_id.wrapping_sub(sent_id);
            if diff > FRAME_ID_SUSPICIOUS_GAP_THRESHOLD {
                break;
            }
            self.in_flight.pop_front();
            if sent_id == acked_id {
                #[allow(clippy::cast_possible_truncation)]
                let sample_ms = now.saturating_duration_since(sent_at).as_millis() as u64;
                if sample_ms <= RTT_SAMPLE_SANE_MAX_MS {
                    // EWMA smoothing (7/8 old + 1/8 new).
                    self.smoothed_rtt_ms = (self.smoothed_rtt_ms * 7 + sample_ms) / 8;
                }
                break;
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
/// ported from `noVNC/core/input/keyboard.js` and `Guacamole/Keyboard.js`.
#[must_use]
pub fn map_browser_key_event(code: &str, key: &str) -> Option<WebKeyMapping> {
    let (usb_hid_usage, qemu_scancode) = match code {
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
        "BracketLeft" => (0x2F, 0x1A),
        "BracketRight" => (0x30, 0x1B),
        "Semicolon" => (0x33, 0x27),
        "Quote" => (0x34, 0x28),
        "Backquote" => (0x35, 0x29),
        "Comma" => (0x36, 0x33),
        "Period" => (0x37, 0x34),
        "Slash" => (0x38, 0x35),
        // ABNT2 international keys (`IntlBackslash` = 0x64 / XT 0x56, `IntlRo` = 0x87 / XT 0x73)
        "IntlBackslash" => (0x64, 0x56),
        "IntlRo" => (0x87, 0x73),
        "ArrowRight" => (0x4F, 0x14D),
        "ArrowLeft" => (0x50, 0x14B),
        "ArrowDown" => (0x51, 0x150),
        "ArrowUp" => (0x52, 0x148),
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

    let keysym = match key {
        "Enter" => 0xFF0D,
        "Escape" => 0xFF1B,
        "Backspace" => 0xFF08,
        "Tab" => 0xFF09,
        "ArrowLeft" => 0xFF51,
        "ArrowUp" => 0xFF52,
        "ArrowRight" => 0xFF53,
        "ArrowDown" => 0xFF54,
        "Shift" => 0xFFE1,
        "Control" => 0xFFE3,
        "Alt" => 0xFFE9,
        "AltGraph" => ISO_LEVEL3_SHIFT_KEYSYM,
        "Meta" => 0xFFEB,
        _ => {
            let mut chars = key.chars();
            if let (Some(ch), None) = (chars.next(), chars.next()) {
                let cp = u32::from(ch);
                if (0x20..=0xFF).contains(&cp) {
                    cp
                } else {
                    0x0100_0000 | cp
                }
            } else {
                0
            }
        }
    };

    Some(WebKeyMapping {
        usb_hid_usage,
        qemu_scancode,
        keysym,
    })
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
}
