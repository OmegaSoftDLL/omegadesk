//! RDP over the mesh (`IronRDP`), browser `RDCleanPath` proxy framing, dynamic
//! `DisplayControl` monitor layout PDUs (`[MS-RDPEDISP]`), and `TigerVNC` TCP-Vegas
//! latency-based congestion control.
//!
//! Reference implementations:
//! - `Devolutions_IronRDP/crates/ironrdp-rdcleanpath/src/lib.rs` (lines 12–180):
//!   `BASE_VERSION = 3389`, `VERSION_1 = 3390`, `RDCleanPathErr` (with HTTP, Winsock `WSA`,
//!   and TLS alert descriptions), and `RDCleanPathPdu` for browser-to-mesh RDP tunneling.
//! - `Devolutions_IronRDP/crates/ironrdp-displaycontrol/src/pdu/mod.rs` (lines 12–140):
//!   `DISPLAYCONTROL_PDU_TYPE_CAPS (0x0000_0005)`, `DISPLAYCONTROL_PDU_TYPE_MONITOR_LAYOUT (0x0000_0002)`,
//!   `DISPLAYCONTROL_MONITOR_PRIMARY (0x0000_0001)`, `MAX_SUPPORTED_MONITORS (1024)`, and
//!   8-byte `DISPLAYCONTROL_HEADER` framing.
//! - `TigerVNC_tigervnc/common/rfb/Congestion.cxx` (lines 67–503): `INITIAL_WINDOW = 16384`,
//!   `MINIMUM_WINDOW = 4096`, `MAXIMUM_WINDOW = 4194304`, `updatePosition`, `sentPing`,
//!   `gotPong`, `isCongested`, `getBandwidth`, and `updateCongestion` (TCP Vegas latency-based
//!   window adjustment over reliable streams).

use std::collections::VecDeque;
use std::fmt;

use bytes::{Buf, BufMut, BytesMut};
use thiserror::Error;

/// Base `RDCleanPath` protocol version (`ironrdp-rdcleanpath/src/lib.rs` line 12).
pub const RDCLEANPATH_BASE_VERSION: u64 = 3389;

/// `RDCleanPath` version 1 (`BASE_VERSION + 1`, `ironrdp-rdcleanpath/src/lib.rs` line 13).
pub const RDCLEANPATH_VERSION_1: u64 = RDCLEANPATH_BASE_VERSION + 1;

/// General proxy error code (`ironrdp-rdcleanpath/src/lib.rs` line 15).
pub const GENERAL_ERROR_CODE: u16 = 1;

/// Negotiation error code (`ironrdp-rdcleanpath/src/lib.rs` line 16).
pub const NEGOTIATION_ERROR_CODE: u16 = 2;

/// `[MS-RDPEDISP]` `DISPLAYCONTROL_PDU_TYPE_MONITOR_LAYOUT` (`pdu/mod.rs` line 13).
pub const DISPLAYCONTROL_PDU_TYPE_MONITOR_LAYOUT: u32 = 0x0000_0002;

/// `[MS-RDPEDISP]` `DISPLAYCONTROL_PDU_TYPE_CAPS` (`pdu/mod.rs` line 12).
pub const DISPLAYCONTROL_PDU_TYPE_CAPS: u32 = 0x0000_0005;

/// `[MS-RDPEDISP]` `DISPLAYCONTROL_MONITOR_PRIMARY` flag (`pdu/mod.rs` line 15).
pub const DISPLAYCONTROL_MONITOR_PRIMARY: u32 = 0x0000_0001;

/// Maximum supported monitor count in a `DisplayControl` PDU (`pdu/mod.rs` line 20).
pub const MAX_SUPPORTED_MONITORS: u16 = 1024;

/// Size in bytes of each `[MS-RDPEDISP]` `DISPLAYCONTROL_MONITOR_LAYOUT` entry (`40` bytes).
pub const MONITOR_LAYOUT_ENTRY_SIZE: usize = 40;

/// Smallest monitor width or height accepted by `[MS-RDPEDISP]` 2.2.2.2.1 (`200` pixels).
pub const MIN_MONITOR_DIMENSION: u32 = 200;

/// Largest monitor width or height accepted by `[MS-RDPEDISP]` 2.2.2.2.1 (`8192` pixels).
pub const MAX_MONITOR_DIMENSION: u32 = 8192;

/// Initial congestion window in bytes (`16 KiB`, `Congestion.cxx` line 67).
pub const INITIAL_WINDOW: u32 = 16_384;

/// Minimum congestion window in bytes (`4 KiB`, `Congestion.cxx` line 71).
pub const MINIMUM_WINDOW: u32 = 4_096;

/// Maximum congestion window in bytes (`4 MiB`, `Congestion.cxx` line 75).
pub const MAXIMUM_WINDOW: u32 = 4_194_304;

/// Errors returned by RDP/VNC protocol framing or validation.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum RdpError {
    /// Unsupported `RDCleanPath` protocol version.
    #[error("unsupported RDCleanPath version: {0}")]
    UnsupportedCleanPathVersion(u64),
    /// Truncated or ill-formed `[MS-RDPEDISP]` `DisplayControl` PDU.
    #[error("invalid DisplayControl PDU: {0}")]
    InvalidDisplayControlPdu(&'static str),
    /// Malformed or unsupported VNC/RFB 12-byte protocol version banner.
    #[error("invalid RFB protocol version banner")]
    InvalidRfbVersionBanner,
    /// No free X11/Wayland virtual display slots remain in the configured range.
    #[error("exhausted virtual display slots in range {0}..={1}")]
    ExhaustedVirtualDisplays(u16, u16),
}

/// 12-byte RFB 3.8 protocol version banner (`"RFB 003.008\n"`, `TigerVNC` `SMsgReaderV3.cxx`).
pub const RFB_VERSION_3_8_BANNER: &[u8; 12] = b"RFB 003.008\n";

/// Negotiated RFB security types (`TigerVNC` `common/rfb/Security.h`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RfbSecurityType {
    /// Invalid / connection failed (`0`).
    Invalid = 0,
    /// Unauthenticated (`1`, only permitted over an already-authenticated mesh tunnel).
    None = 1,
    /// Classic DES challenge-response (`2`).
    VncAuth = 2,
    /// Tight security tunnel (`16`).
    Tight = 16,
    /// `VeNCrypt` TLS/X.509 security extension (`19`).
    VeNCrypt = 19,
}

/// Parses a 12-byte `"RFB MMM.mmm\n"` banner into `(major, minor)` version numbers
/// (`TigerVNC` `CConnection.cxx` / `SConnection.cxx`).
///
/// # Errors
///
/// Returns [`RdpError::InvalidRfbVersionBanner`] if the 12-byte banner does not match `"RFB DDD.DDD\n"`.
pub fn parse_rfb_version_banner(banner: &[u8]) -> Result<(u16, u16), RdpError> {
    if banner.len() != 12 || &banner[0..4] != b"RFB " || banner[7] != b'.' || banner[11] != b'\n' {
        return Err(RdpError::InvalidRfbVersionBanner);
    }
    let major = std::str::from_utf8(&banner[4..7])
        .ok()
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or(RdpError::InvalidRfbVersionBanner)?;
    let minor = std::str::from_utf8(&banner[8..11])
        .ok()
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or(RdpError::InvalidRfbVersionBanner)?;
    Ok((major, minor))
}

/// Per-user virtual display session descriptor on Linux (`xrdp-sesman` model, `docs/plan.md` §2.6 line 101).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxVirtualSession {
    /// Linux POSIX UID owning the isolated session.
    pub uid: u32,
    /// Username owning the session.
    pub username: String,
    /// Allocated X11/Wayland display number (`:10`..`:99`).
    pub display_number: u16,
    /// Environment string `DISPLAY=:<display_number>`.
    pub x11_display_env: String,
    /// Environment string `WAYLAND_DISPLAY=wayland-<display_number>`.
    pub wayland_display_env: String,
}

/// Allocates and reconnects isolated per-user virtual desktop sessions on Linux
/// (`xrdp` `sesman` architecture, `docs/plan.md` §2.6 line 101).
#[derive(Debug, Clone)]
pub struct LinuxVirtualSessionAllocator {
    min_display: u16,
    max_display: u16,
    by_uid: std::collections::HashMap<u32, LinuxVirtualSession>,
}

impl LinuxVirtualSessionAllocator {
    /// Creates an allocator managing display numbers in `min_display..=max_display` (e.g. `10..=99`).
    #[must_use]
    pub fn new(min_display: u16, max_display: u16) -> Self {
        Self {
            min_display: min_display.max(1),
            max_display: max_display.max(min_display.max(1)),
            by_uid: std::collections::HashMap::new(),
        }
    }

    /// Returns the existing virtual session for `uid` (reconnecting seamlessly) or allocates
    /// the lowest unused display number in `min_display..=max_display`.
    ///
    /// # Errors
    ///
    /// Returns [`RdpError::ExhaustedVirtualDisplays`] if all display slots are occupied.
    pub fn acquire_or_reconnect(
        &mut self,
        uid: u32,
        username: &str,
    ) -> Result<LinuxVirtualSession, RdpError> {
        if let Some(existing) = self.by_uid.get(&uid) {
            return Ok(existing.clone());
        }
        let used: std::collections::HashSet<u16> =
            self.by_uid.values().map(|s| s.display_number).collect();
        for display_number in self.min_display..=self.max_display {
            if !used.contains(&display_number) {
                let session = LinuxVirtualSession {
                    uid,
                    username: username.to_owned(),
                    display_number,
                    x11_display_env: format!(":{display_number}"),
                    wayland_display_env: format!("wayland-{display_number}"),
                };
                self.by_uid.insert(uid, session.clone());
                return Ok(session);
            }
        }
        Err(RdpError::ExhaustedVirtualDisplays(
            self.min_display,
            self.max_display,
        ))
    }

    /// Terminates and releases the virtual display session owned by `uid`.
    pub fn terminate_session(&mut self, uid: u32) -> Option<LinuxVirtualSession> {
        self.by_uid.remove(&uid)
    }
}

/// Structured proxy error carried in an [`RdCleanPathPdu`], ported directly from
/// `Devolutions_IronRDP/crates/ironrdp-rdcleanpath/src/lib.rs` (lines 18–161).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RdCleanPathErr {
    /// Proxy error code (`1 = general error`, `2 = negotiation error`).
    pub error_code: u16,
    /// Optional HTTP status code (`200`, `401`, `403`, `502`, etc.).
    pub http_status_code: Option<u16>,
    /// Optional Windows Sockets (`WSA`) error code (`10060`, `10061`, etc.).
    pub wsa_last_error: Option<u16>,
    /// Optional TLS alert code (`40`, `42`, `48`, etc.).
    pub tls_alert_code: Option<u8>,
}

impl fmt::Display for RdCleanPathErr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let error_description = match self.error_code {
            GENERAL_ERROR_CODE => "general error",
            NEGOTIATION_ERROR_CODE => "negotiation error",
            _ => "unknown error",
        };
        write!(f, "{error_description} (code {})", self.error_code)?;

        if let Some(http_status_code) = self.http_status_code {
            let description = match http_status_code {
                200 => "OK",
                400 => "bad request",
                401 => "unauthorized",
                403 => "forbidden",
                404 => "not found",
                500 => "internal server error",
                502 => "bad gateway",
                503 => "service unavailable",
                504 => "gateway timeout",
                _ => "unknown HTTP status",
            };
            write!(f, "; HTTP {http_status_code} {description}")?;
        }

        if let Some(wsa_last_error) = self.wsa_last_error {
            let description = match wsa_last_error {
                10013 => "permission denied",
                10051 => "network is unreachable",
                10054 => "connection reset by peer",
                10060 => "connection timed out",
                10061 => "connection refused",
                10065 => "no route to host",
                11001 => "host not found",
                _ => "unknown WSA error",
            };
            write!(f, "; WSA {wsa_last_error} {description}")?;
        }

        if let Some(tls_alert_code) = self.tls_alert_code {
            let description = match tls_alert_code {
                0 => "close notify",
                40 => "handshake failure",
                42 => "bad certificate",
                45 => "certificate expired",
                48 => "unknown CA",
                _ => "unknown TLS alert",
            };
            write!(f, "; TLS alert {tls_alert_code} {description}")?;
        }

        Ok(())
    }
}

impl std::error::Error for RdCleanPathErr {}

/// Browser-to-mesh `RDCleanPath` tunnel handshake PDU, ported from
/// `Devolutions_IronRDP/crates/ironrdp-rdcleanpath/src/lib.rs` (lines 165–220).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RdCleanPathPdu {
    /// Protocol version (`RDCLEANPATH_VERSION_1 = 3390`).
    pub version: u64,
    /// Proxy error, present only in server-to-client error responses.
    pub error: Option<RdCleanPathErr>,
    /// Target RDP host or `*.omega` mesh DNS name (`"srv-erp.omega:3389"`).
    pub destination: Option<String>,
    /// Bearer token or session ticket authorizing the proxy tunnel.
    pub proxy_auth: Option<String>,
    /// Initial `X.224` connection request/confirm bytes.
    pub x224_connection_pdu: Vec<u8>,
    /// DER-encoded TLS leaf and intermediate certificates of the RDP server.
    pub server_cert_chain: Vec<Vec<u8>>,
}

impl RdCleanPathPdu {
    /// Creates a client-to-proxy `RDCleanPath` request targeting `destination` over the mesh.
    #[must_use]
    pub fn new_request(
        destination: impl Into<String>,
        proxy_auth: impl Into<String>,
        x224_connection_pdu: Vec<u8>,
    ) -> Self {
        Self {
            version: RDCLEANPATH_VERSION_1,
            error: None,
            destination: Some(destination.into()),
            proxy_auth: Some(proxy_auth.into()),
            x224_connection_pdu,
            server_cert_chain: Vec::new(),
        }
    }

    /// Creates a proxy-to-client `RDCleanPath` response carrying the server's `X.224` confirm
    /// and TLS certificate chain for client-side pinning.
    #[must_use]
    pub const fn new_response(
        x224_connection_pdu: Vec<u8>,
        server_cert_chain: Vec<Vec<u8>>,
    ) -> Self {
        Self {
            version: RDCLEANPATH_VERSION_1,
            error: None,
            destination: None,
            proxy_auth: None,
            x224_connection_pdu,
            server_cert_chain,
        }
    }

    /// Validates that `version == RDCLEANPATH_VERSION_1`.
    ///
    /// # Errors
    ///
    /// Returns [`RdpError::UnsupportedCleanPathVersion`] if `self.version != RDCLEANPATH_VERSION_1`.
    pub const fn validate_version(&self) -> Result<(), RdpError> {
        if self.version != RDCLEANPATH_VERSION_1 {
            return Err(RdpError::UnsupportedCleanPathVersion(self.version));
        }
        Ok(())
    }
}

/// `[MS-RDPEDISP]` `DISPLAYCONTROL_CAPS_PDU` (`ironrdp-displaycontrol/src/pdu/mod.rs` line 134).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DisplayControlCapabilities {
    /// Maximum number of monitors supported (`<= MAX_SUPPORTED_MONITORS`).
    pub max_num_monitors: u32,
    /// Maximum monitor area factor A.
    pub max_monitor_area_factor_a: u32,
    /// Maximum monitor area factor B.
    pub max_monitor_area_factor_b: u32,
}

/// Single monitor descriptor in a `[MS-RDPEDISP]` `DISPLAYCONTROL_MONITOR_LAYOUT_PDU`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MonitorLayoutEntry {
    /// Flags (`DISPLAYCONTROL_MONITOR_PRIMARY = 1` or `0`).
    pub flags: u32,
    /// Virtual desktop left X coordinate.
    pub left: i32,
    /// Virtual desktop top Y coordinate.
    pub top: i32,
    /// Monitor width in pixels (`200..=8192`, must be even per `[MS-RDPEDISP]`).
    pub width: u32,
    /// Monitor height in pixels (`200..=8192`).
    pub height: u32,
    /// Physical width in millimeters.
    pub physical_width_mm: u32,
    /// Physical height in millimeters.
    pub physical_height_mm: u32,
    /// Orientation in degrees (`0`, `90`, `180`, `270`).
    pub orientation: u32,
    /// Desktop scale factor (`100..=500`).
    pub desktop_scale_factor: u32,
    /// Device scale factor (`100`, `140`, `180`).
    pub device_scale_factor: u32,
}

impl MonitorLayoutEntry {
    /// Validates `width` and `height` against `[MS-RDPEDISP]` 2.2.2.2.1: both in
    /// `200..=8192` and the width even. Shared by the encoder and the decoder, like the
    /// `validate_dimensions!` macro in `ironrdp-displaycontrol/src/pdu/mod.rs` lines 239–252,
    /// so a layout that a conforming server would reject can neither be sent nor decoded.
    ///
    /// # Errors
    ///
    /// Returns [`RdpError::InvalidDisplayControlPdu`] naming the violated constraint.
    pub const fn validate_dimensions(&self) -> Result<(), RdpError> {
        if self.width < MIN_MONITOR_DIMENSION || self.width > MAX_MONITOR_DIMENSION {
            return Err(RdpError::InvalidDisplayControlPdu(
                "monitor width out of range 200..=8192",
            ));
        }
        if !self.width.is_multiple_of(2) {
            return Err(RdpError::InvalidDisplayControlPdu(
                "monitor width must be even",
            ));
        }
        if self.height < MIN_MONITOR_DIMENSION || self.height > MAX_MONITOR_DIMENSION {
            return Err(RdpError::InvalidDisplayControlPdu(
                "monitor height out of range 200..=8192",
            ));
        }
        Ok(())
    }
}

/// `[MS-RDPEDISP]` `DisplayControlPdu` ported from `Devolutions_IronRDP/crates/ironrdp-displaycontrol/src/pdu/mod.rs` (lines 28–120).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DisplayControlPdu {
    /// Server-to-client capabilities advertisement (`DISPLAYCONTROL_PDU_TYPE_CAPS`).
    Caps(DisplayControlCapabilities),
    /// Client-to-server monitor layout update (`DISPLAYCONTROL_PDU_TYPE_MONITOR_LAYOUT`).
    MonitorLayout(Vec<MonitorLayoutEntry>),
}

impl DisplayControlPdu {
    /// Fixed 8-byte header size (`Type: u32 LE + Length: u32 LE`, `pdu/mod.rs` line 35).
    pub const FIXED_HEADER_SIZE: usize = 8;

    /// Encodes this PDU into little-endian `[MS-RDPEDISP]` wire format (`pdu/mod.rs` lines 38–61).
    ///
    /// # Errors
    ///
    /// Returns [`RdpError::InvalidDisplayControlPdu`] if a `MonitorLayout` has 0 or more than
    /// [`MAX_SUPPORTED_MONITORS`] monitors, or a monitor fails
    /// [`MonitorLayoutEntry::validate_dimensions`].
    pub fn encode(&self, dst: &mut BytesMut) -> Result<(), RdpError> {
        match self {
            Self::Caps(caps) => {
                if caps.max_num_monitors > u32::from(MAX_SUPPORTED_MONITORS) {
                    return Err(RdpError::InvalidDisplayControlPdu(
                        "max_num_monitors exceeds MAX_SUPPORTED_MONITORS",
                    ));
                }
                let pdu_size = u32::try_from(Self::FIXED_HEADER_SIZE + 12).unwrap_or(20);
                dst.put_u32_le(DISPLAYCONTROL_PDU_TYPE_CAPS);
                dst.put_u32_le(pdu_size);
                dst.put_u32_le(caps.max_num_monitors);
                dst.put_u32_le(caps.max_monitor_area_factor_a);
                dst.put_u32_le(caps.max_monitor_area_factor_b);
                Ok(())
            }
            Self::MonitorLayout(monitors) => {
                if monitors.is_empty() || monitors.len() > usize::from(MAX_SUPPORTED_MONITORS) {
                    return Err(RdpError::InvalidDisplayControlPdu(
                        "monitor count out of range 1..=1024",
                    ));
                }
                for m in monitors {
                    m.validate_dimensions()?;
                }
                let payload_len = 8 + monitors.len() * MONITOR_LAYOUT_ENTRY_SIZE;
                let pdu_size = u32::try_from(Self::FIXED_HEADER_SIZE + payload_len)
                    .map_err(|_| RdpError::InvalidDisplayControlPdu("PDU length overflow"))?;
                dst.put_u32_le(DISPLAYCONTROL_PDU_TYPE_MONITOR_LAYOUT);
                dst.put_u32_le(pdu_size);
                dst.put_u32_le(u32::try_from(MONITOR_LAYOUT_ENTRY_SIZE).unwrap_or(40));
                dst.put_u32_le(u32::try_from(monitors.len()).unwrap_or(0));
                for m in monitors {
                    dst.put_u32_le(m.flags);
                    dst.put_i32_le(m.left);
                    dst.put_i32_le(m.top);
                    dst.put_u32_le(m.width);
                    dst.put_u32_le(m.height);
                    dst.put_u32_le(m.physical_width_mm);
                    dst.put_u32_le(m.physical_height_mm);
                    dst.put_u32_le(m.orientation);
                    dst.put_u32_le(m.desktop_scale_factor);
                    dst.put_u32_le(m.device_scale_factor);
                }
                Ok(())
            }
        }
    }

    /// Decodes a `[MS-RDPEDISP]` `DisplayControlPdu` from `src` (`pdu/mod.rs` lines 82–120).
    ///
    /// # Errors
    ///
    /// Returns [`RdpError::InvalidDisplayControlPdu`] if the header or body is malformed, or a
    /// decoded monitor fails [`MonitorLayoutEntry::validate_dimensions`]: a well-framed PDU
    /// carrying a `1x1` or odd-width monitor is rejected rather than returned as valid.
    pub fn decode(mut src: &[u8]) -> Result<Self, RdpError> {
        if src.len() < Self::FIXED_HEADER_SIZE {
            return Err(RdpError::InvalidDisplayControlPdu(
                "truncated DISPLAYCONTROL_HEADER",
            ));
        }
        let kind = src.get_u32_le();
        let pdu_length = src.get_u32_le() as usize;
        if pdu_length != src.len() + Self::FIXED_HEADER_SIZE {
            return Err(RdpError::InvalidDisplayControlPdu(
                "DisplayControl PDU length mismatch",
            ));
        }

        match kind {
            DISPLAYCONTROL_PDU_TYPE_CAPS => {
                if src.len() != 12 {
                    return Err(RdpError::InvalidDisplayControlPdu(
                        "invalid DISPLAYCONTROL_CAPS_PDU size",
                    ));
                }
                Ok(Self::Caps(DisplayControlCapabilities {
                    max_num_monitors: src.get_u32_le(),
                    max_monitor_area_factor_a: src.get_u32_le(),
                    max_monitor_area_factor_b: src.get_u32_le(),
                }))
            }
            DISPLAYCONTROL_PDU_TYPE_MONITOR_LAYOUT => {
                if src.len() < 8 {
                    return Err(RdpError::InvalidDisplayControlPdu(
                        "truncated DISPLAYCONTROL_MONITOR_LAYOUT_PDU",
                    ));
                }
                let entry_size = src.get_u32_le() as usize;
                let num_monitors = src.get_u32_le() as usize;
                if entry_size != MONITOR_LAYOUT_ENTRY_SIZE
                    || num_monitors == 0
                    || num_monitors > usize::from(MAX_SUPPORTED_MONITORS)
                    || src.len() != num_monitors * MONITOR_LAYOUT_ENTRY_SIZE
                {
                    return Err(RdpError::InvalidDisplayControlPdu(
                        "invalid monitor layout count or entry size",
                    ));
                }
                let mut monitors = Vec::with_capacity(num_monitors);
                for _ in 0..num_monitors {
                    let entry = MonitorLayoutEntry {
                        flags: src.get_u32_le(),
                        left: src.get_i32_le(),
                        top: src.get_i32_le(),
                        width: src.get_u32_le(),
                        height: src.get_u32_le(),
                        physical_width_mm: src.get_u32_le(),
                        physical_height_mm: src.get_u32_le(),
                        orientation: src.get_u32_le(),
                        desktop_scale_factor: src.get_u32_le(),
                        device_scale_factor: src.get_u32_le(),
                    };
                    // Same check as the encoder (`MonitorLayoutEntry::decode` in IronRDP's
                    // `pdu/mod.rs` validates every decoded entry the same way).
                    entry.validate_dimensions()?;
                    monitors.push(entry);
                }
                Ok(Self::MonitorLayout(monitors))
            }
            _ => Err(RdpError::InvalidDisplayControlPdu(
                "unknown DisplayControl PDU type",
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct RttInfo {
    sent_ms: u64,
    pos: u32,
    extra: u32,
    congested: bool,
}

/// Latency-based TCP-Vegas congestion controller for RFB/VNC and RDP streams over reliable
/// transports, ported directly from `TigerVNC_tigervnc/common/rfb/Congestion.cxx` (lines 67–503).
#[derive(Debug, Clone)]
pub struct VncCongestionController {
    last_position: u32,
    extra_buffer: u32,
    base_rtt_ms: Option<u32>,
    safe_base_rtt_ms: Option<u32>,
    cong_window: u32,
    in_slow_start: bool,
    measurements: u32,
    min_rtt_ms: Option<u32>,
    min_congested_rtt_ms: Option<u32>,
    last_update_ms: u64,
    last_sent_ms: u64,
    last_pong: RttInfo,
    last_pong_arrival_ms: u64,
    last_adjustment_ms: u64,
    pings: VecDeque<RttInfo>,
}

impl VncCongestionController {
    /// Creates a new congestion controller initialized to [`INITIAL_WINDOW`] (`16 KiB`) in slow start
    /// (`Congestion::Congestion()` in `Congestion.cxx` lines 84–94).
    #[must_use]
    pub fn new(now_ms: u64) -> Self {
        Self {
            last_position: 0,
            extra_buffer: 0,
            base_rtt_ms: None,
            safe_base_rtt_ms: None,
            cong_window: INITIAL_WINDOW,
            in_slow_start: true,
            measurements: 0,
            min_rtt_ms: None,
            min_congested_rtt_ms: None,
            last_update_ms: now_ms,
            last_sent_ms: now_ms,
            last_pong: RttInfo::default(),
            last_pong_arrival_ms: now_ms,
            last_adjustment_ms: now_ms,
            pings: VecDeque::new(),
        }
    }

    /// Returns the current congestion window in bytes.
    #[must_use]
    pub const fn congestion_window(&self) -> u32 {
        self.cong_window
    }

    /// Returns `true` if the controller is still in the slow-start phase.
    #[must_use]
    pub const fn in_slow_start(&self) -> bool {
        self.in_slow_start
    }

    /// Updates the stream byte position (`Congestion::updatePosition` in `Congestion.cxx` lines 100–147).
    ///
    /// The idle interval is measured against the *previous* send before this call is recorded as
    /// a send. `Congestion.cxx` lines 106–113 record first and measure after, which only detects
    /// an idle gap when a zero-delta `updatePosition` call happens to land during the pause (its
    /// writer polls that way; ours does not). Measuring first means the first bytes sent after a
    /// long pause always close the window and redo the wire latency measurement, as intended.
    pub fn update_position(&mut self, pos: u32, now_ms: u64) {
        let delta = pos.wrapping_sub(self.last_position);
        let idle_ms = u32::try_from(now_ms.saturating_sub(self.last_sent_ms)).unwrap_or(u32::MAX);
        if delta > 0 || self.extra_buffer > 0 {
            self.last_sent_ms = now_ms;
        }

        if let Some(base_rtt) = self.base_rtt_ms
            && idle_ms > 100
            && idle_ms > base_rtt.saturating_mul(2)
        {
            if self.cong_window > INITIAL_WINDOW {
                self.cong_window = INITIAL_WINDOW;
            }
            self.base_rtt_ms = None;
            self.measurements = 0;
            self.last_adjustment_ms = now_ms;
            self.min_rtt_ms = None;
            self.min_congested_rtt_ms = None;
            self.in_slow_start = true;
        }

        if let Some(base_rtt) = self.base_rtt_ms {
            self.extra_buffer = self.extra_buffer.saturating_add(delta);
            let elapsed =
                u32::try_from(now_ms.saturating_sub(self.last_update_ms)).unwrap_or(u32::MAX);
            let consumed = elapsed.saturating_mul(self.cong_window) / base_rtt.max(1);
            self.extra_buffer = self.extra_buffer.saturating_sub(consumed);
        }

        self.last_position = pos;
        self.last_update_ms = now_ms;
    }

    /// Records an outbound RTT probe (`Congestion::sentPing` in `Congestion.cxx` lines 149–161).
    pub fn sent_ping(&mut self, now_ms: u64) {
        let rtt_info = RttInfo {
            sent_ms: now_ms,
            pos: self.last_position,
            extra: self.get_extra_buffer(now_ms),
            congested: self.is_congested(now_ms),
        };
        self.pings.push_back(rtt_info);
    }

    /// Processes an inbound RTT probe response (`Congestion::gotPong` in `Congestion.cxx` lines 163–223).
    pub fn got_pong(&mut self, now_ms: u64) {
        let Some(rtt_info) = self.pings.pop_front() else {
            return;
        };

        self.last_pong = rtt_info;
        self.last_pong_arrival_ms = now_ms;

        let mut rtt = u32::try_from(now_ms.saturating_sub(rtt_info.sent_ms))
            .unwrap_or(u32::MAX)
            .max(1);

        if self.base_rtt_ms.is_none_or(|base| rtt < base) {
            self.base_rtt_ms = Some(rtt);
            self.safe_base_rtt_ms = Some(rtt);
        }

        if rtt_info.sent_ms < self.last_adjustment_ms {
            return;
        }

        let base_rtt = self.base_rtt_ms.unwrap_or(rtt).max(1);
        let delay = rtt_info.extra.saturating_mul(base_rtt) / self.cong_window.max(1);
        rtt = rtt.saturating_sub(delay).max(base_rtt);

        if self.min_rtt_ms.is_none_or(|m| rtt < m) {
            self.min_rtt_ms = Some(rtt);
        }
        if rtt_info.congested && self.min_congested_rtt_ms.is_none_or(|m| rtt < m) {
            self.min_congested_rtt_ms = Some(rtt);
        }

        self.measurements += 1;
        self.update_congestion(now_ms);
    }

    /// Returns `true` if in-flight bytes have reached or exceeded `cong_window`
    /// (`Congestion::isCongested` in `Congestion.cxx` lines 225–231).
    #[must_use]
    pub fn is_congested(&self, now_ms: u64) -> bool {
        self.get_in_flight(now_ms) >= self.cong_window
    }

    /// Estimates available bandwidth in bytes per second (`Congestion::getBandwidth` in
    /// `Congestion.cxx` lines 300–316).
    #[must_use]
    pub fn get_bandwidth(&self) -> usize {
        let rtt = self.safe_base_rtt_ms.unwrap_or(60).max(1) as usize;
        let mut bandwidth = (self.cong_window as usize) * 1000 / rtt;
        if self.in_slow_start {
            bandwidth += bandwidth / 2;
        }
        bandwidth
    }

    fn get_extra_buffer(&self, now_ms: u64) -> u32 {
        let Some(base_rtt) = self.base_rtt_ms else {
            return 0;
        };
        let elapsed = u32::try_from(now_ms.saturating_sub(self.last_update_ms)).unwrap_or(u32::MAX);
        let consumed = elapsed.saturating_mul(self.cong_window) / base_rtt.max(1);
        self.extra_buffer.saturating_sub(consumed)
    }

    fn get_in_flight(&self, now_ms: u64) -> u32 {
        if self.last_position == self.last_pong.pos {
            return 0;
        }
        let Some(base_rtt) = self.base_rtt_ms else {
            return self.last_position.wrapping_sub(self.last_pong.pos);
        };

        let next_pong = self.pings.front().copied().unwrap_or(RttInfo {
            sent_ms: self.last_update_ms,
            pos: self.last_position,
            extra: self.extra_buffer,
            congested: false,
        });

        let mut eta_next =
            u32::try_from(next_pong.sent_ms.saturating_sub(self.last_pong.sent_ms)).unwrap_or(0);
        let delay_next = next_pong.extra.saturating_mul(base_rtt) / self.cong_window.max(1);
        eta_next = eta_next.saturating_add(delay_next);
        let delay_prev = self.last_pong.extra.saturating_mul(base_rtt) / self.cong_window.max(1);
        eta_next = eta_next.saturating_sub(delay_prev);

        let elapsed =
            u32::try_from(now_ms.saturating_sub(self.last_pong_arrival_ms)).unwrap_or(u32::MAX);
        let acked = if eta_next <= elapsed || eta_next == 0 {
            next_pong.pos
        } else {
            let pos_delta = next_pong.pos.wrapping_sub(self.last_pong.pos);
            self.last_pong
                .pos
                .wrapping_add(pos_delta.saturating_mul(elapsed) / eta_next)
        };

        self.last_position.wrapping_sub(acked)
    }

    fn update_congestion(&mut self, now_ms: u64) {
        if self.measurements < 3 {
            return;
        }
        let Some(base_rtt) = self.base_rtt_ms else {
            return;
        };
        let min_rtt = self.min_rtt_ms.unwrap_or(base_rtt).max(base_rtt);
        let min_congested_rtt = self.min_congested_rtt_ms.unwrap_or(u32::MAX).max(base_rtt);

        let diff = min_rtt - base_rtt;

        if diff > 100 && diff > base_rtt / 2 {
            self.cong_window = u32::try_from(
                (u64::from(self.cong_window) * u64::from(base_rtt)) / u64::from(min_rtt),
            )
            .unwrap_or(MINIMUM_WINDOW);
            self.in_slow_start = false;
        }

        if self.in_slow_start {
            if diff > 25 {
                self.cong_window = u32::try_from(
                    (u64::from(self.cong_window) * u64::from(base_rtt)) / u64::from(min_rtt),
                )
                .unwrap_or(MINIMUM_WINDOW);
                self.in_slow_start = false;
            } else {
                let congested_diff = min_congested_rtt.saturating_sub(base_rtt);
                if congested_diff < 25 {
                    self.cong_window = self.cong_window.saturating_mul(2);
                }
            }
        } else if diff > 50 {
            self.cong_window = self.cong_window.saturating_sub(4096);
        } else {
            let congested_diff = min_congested_rtt.saturating_sub(base_rtt);
            if congested_diff < 5 {
                self.cong_window = self.cong_window.saturating_add(8192);
            } else if congested_diff < 25 {
                self.cong_window = self.cong_window.saturating_add(4096);
            }
        }

        self.cong_window = self.cong_window.clamp(MINIMUM_WINDOW, MAXIMUM_WINDOW);
        self.measurements = 0;
        self.last_adjustment_ms = now_ms;
        self.min_rtt_ms = None;
        self.min_congested_rtt_ms = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rdcleanpath_and_displaycontrol_pdu_roundtrip() {
        let req = RdCleanPathPdu::new_request("srv-sql.omega:3389", "ticket-1", vec![0x03, 0x00]);
        assert!(req.validate_version().is_ok());

        let err = RdCleanPathErr {
            error_code: NEGOTIATION_ERROR_CODE,
            http_status_code: Some(502),
            wsa_last_error: Some(10061),
            tls_alert_code: Some(42),
        };
        assert_eq!(
            err.to_string(),
            "negotiation error (code 2); HTTP 502 bad gateway; WSA 10061 connection refused; TLS alert 42 bad certificate"
        );

        let pdu = DisplayControlPdu::MonitorLayout(vec![MonitorLayoutEntry {
            flags: DISPLAYCONTROL_MONITOR_PRIMARY,
            left: 0,
            top: 0,
            width: 1920,
            height: 1080,
            physical_width_mm: 520,
            physical_height_mm: 290,
            orientation: 0,
            desktop_scale_factor: 100,
            device_scale_factor: 100,
        }]);
        let mut buf = BytesMut::new();
        assert!(pdu.encode(&mut buf).is_ok());
        let decoded = DisplayControlPdu::decode(&buf);
        assert_eq!(decoded, Ok(pdu));
    }

    fn monitor(width: u32, height: u32) -> MonitorLayoutEntry {
        MonitorLayoutEntry {
            flags: DISPLAYCONTROL_MONITOR_PRIMARY,
            left: 0,
            top: 0,
            width,
            height,
            physical_width_mm: 520,
            physical_height_mm: 290,
            orientation: 0,
            desktop_scale_factor: 100,
            device_scale_factor: 100,
        }
    }

    /// Regression test for #31 `rdp/src/lib.rs:290`: the encoder enforces the `[MS-RDPEDISP]`
    /// upper bound of 8192 pixels on both dimensions, not only the lower bound.
    #[test]
    fn monitor_layout_encoder_rejects_dimensions_above_8192() {
        let mut buf = BytesMut::new();
        let too_wide = DisplayControlPdu::MonitorLayout(vec![monitor(8194, 1080)]);
        assert_eq!(
            too_wide.encode(&mut buf),
            Err(RdpError::InvalidDisplayControlPdu(
                "monitor width out of range 200..=8192"
            ))
        );
        let too_tall = DisplayControlPdu::MonitorLayout(vec![monitor(1920, 9000)]);
        assert_eq!(
            too_tall.encode(&mut buf),
            Err(RdpError::InvalidDisplayControlPdu(
                "monitor height out of range 200..=8192"
            ))
        );
        // A valid primary followed by one oversized secondary fails as a whole.
        let mixed = DisplayControlPdu::MonitorLayout(vec![monitor(1920, 1080), monitor(200, 8193)]);
        assert!(mixed.encode(&mut buf).is_err());
        assert_eq!(buf.len(), 0, "nothing is written for a rejected layout");

        // Both bounds inclusive, and the pre-existing lower-bound / even-width rules still hold.
        let max = DisplayControlPdu::MonitorLayout(vec![monitor(8192, 8192)]);
        assert!(max.encode(&mut buf).is_ok());
        assert_eq!(DisplayControlPdu::decode(&buf), Ok(max));
        buf.clear();
        assert!(
            DisplayControlPdu::MonitorLayout(vec![monitor(200, 200)])
                .encode(&mut buf)
                .is_ok()
        );
        buf.clear();
        assert!(
            DisplayControlPdu::MonitorLayout(vec![monitor(198, 1080)])
                .encode(&mut buf)
                .is_err()
        );
        assert_eq!(
            DisplayControlPdu::MonitorLayout(vec![monitor(1921, 1080)]).encode(&mut buf),
            Err(RdpError::InvalidDisplayControlPdu(
                "monitor width must be even"
            ))
        );
    }

    /// Builds a correctly framed `DISPLAYCONTROL_MONITOR_LAYOUT_PDU` without going through the
    /// encoder's validation, the way a misbehaving peer would.
    fn raw_monitor_layout_pdu(monitors: &[MonitorLayoutEntry]) -> BytesMut {
        let mut buf = BytesMut::new();
        buf.put_u32_le(DISPLAYCONTROL_PDU_TYPE_MONITOR_LAYOUT);
        buf.put_u32_le(
            u32::try_from(
                DisplayControlPdu::FIXED_HEADER_SIZE
                    + 8
                    + monitors.len() * MONITOR_LAYOUT_ENTRY_SIZE,
            )
            .unwrap(),
        );
        buf.put_u32_le(u32::try_from(MONITOR_LAYOUT_ENTRY_SIZE).unwrap());
        buf.put_u32_le(u32::try_from(monitors.len()).unwrap());
        for m in monitors {
            buf.put_u32_le(m.flags);
            buf.put_i32_le(m.left);
            buf.put_i32_le(m.top);
            buf.put_u32_le(m.width);
            buf.put_u32_le(m.height);
            buf.put_u32_le(m.physical_width_mm);
            buf.put_u32_le(m.physical_height_mm);
            buf.put_u32_le(m.orientation);
            buf.put_u32_le(m.desktop_scale_factor);
            buf.put_u32_le(m.device_scale_factor);
        }
        buf
    }

    /// Regression test for #31 `rdp/src/lib.rs:378`: the decoder validates monitor dimensions
    /// and the even-width rule instead of accepting any well-framed layout verbatim.
    #[test]
    fn monitor_layout_decoder_rejects_invalid_monitor_dimensions() {
        let tiny = raw_monitor_layout_pdu(&[monitor(1, 1)]);
        assert_eq!(
            DisplayControlPdu::decode(&tiny),
            Err(RdpError::InvalidDisplayControlPdu(
                "monitor width out of range 200..=8192"
            ))
        );
        let odd = raw_monitor_layout_pdu(&[monitor(1921, 1080)]);
        assert_eq!(
            DisplayControlPdu::decode(&odd),
            Err(RdpError::InvalidDisplayControlPdu(
                "monitor width must be even"
            ))
        );
        let huge = raw_monitor_layout_pdu(&[monitor(1920, 1080), monitor(1920, 8194)]);
        assert_eq!(
            DisplayControlPdu::decode(&huge),
            Err(RdpError::InvalidDisplayControlPdu(
                "monitor height out of range 200..=8192"
            ))
        );
        // The raw builder and the real encoder agree on a valid layout.
        let valid = vec![monitor(1920, 1080)];
        let raw = raw_monitor_layout_pdu(&valid);
        let mut encoded = BytesMut::new();
        DisplayControlPdu::MonitorLayout(valid.clone())
            .encode(&mut encoded)
            .unwrap();
        assert_eq!(raw, encoded);
        assert_eq!(
            DisplayControlPdu::decode(&raw),
            Ok(DisplayControlPdu::MonitorLayout(valid))
        );
    }

    #[test]
    fn tigervnc_congestion_controller_slow_start_and_vegas_backoff() {
        let mut cc = VncCongestionController::new(1_000);
        assert_eq!(cc.congestion_window(), INITIAL_WINDOW);
        assert!(cc.in_slow_start());

        // Simulate 3 congested pings with low 10 ms RTT -> slow start doubles window to 32 KiB.
        for i in 0..3u32 {
            let t_send = 1_000 + u64::from(i) * 20;
            cc.update_position((i + 1) * 20_000, t_send);
            cc.sent_ping(t_send);
            cc.got_pong(t_send + 10);
        }
        assert_eq!(cc.congestion_window(), INITIAL_WINDOW * 2);

        // Simulate 3 pings with a latency spike (RTT jumps to 150 ms) -> leaves slow start and
        // backs off. Sends stay 50 ms apart (<= 100 ms since the previous send at t=1040) so the
        // idle reset does not fire and the back-off is exercised on its own.
        for i in 0..3u32 {
            let t_send = 1_100 + u64::from(i) * 50;
            cc.update_position(100_000 + (i + 1) * 40_000, t_send);
            cc.sent_ping(t_send);
            cc.got_pong(t_send + 150);
        }
        assert!(!cc.in_slow_start());
        assert!(cc.congestion_window() < INITIAL_WINDOW * 2);
    }

    /// Regression test for #31 `rdp/src/lib.rs:458`: the first send after a long pause resets
    /// the window and the RTT baseline, because idle time is measured against the previous send
    /// before the new send is recorded.
    #[test]
    fn congestion_controller_resets_window_when_sending_resumes_after_idle() {
        let mut cc = VncCongestionController::new(1_000);
        for i in 0..3u32 {
            let t_send = 1_000 + u64::from(i) * 20;
            cc.update_position((i + 1) * 20_000, t_send);
            cc.sent_ping(t_send);
            cc.got_pong(t_send + 10);
        }
        assert_eq!(cc.congestion_window(), INITIAL_WINDOW * 2);
        assert!(cc.in_slow_start());

        // Leave slow start with a mild RTT increase so a reset is observable on both fields.
        for i in 0..3u32 {
            let t_send = 1_100 + u64::from(i) * 50;
            cc.update_position(100_000 + (i + 1) * 40_000, t_send);
            cc.sent_ping(t_send);
            cc.got_pong(t_send + 150);
        }
        assert!(!cc.in_slow_start());
        let backed_off = cc.congestion_window();

        // 5 s of silence (> 100 ms and > 2 * base RTT), then data is sent with no zero-byte
        // position update during the pause. This send itself must trigger the idle reset.
        cc.update_position(300_000, 6_200);
        assert!(cc.in_slow_start());
        assert_eq!(cc.congestion_window(), INITIAL_WINDOW.min(backed_off));
        // The RTT baseline was discarded: the next pong re-measures it from scratch (300 ms
        // instead of the 10 ms learned before the pause), which the bandwidth estimate exposes.
        cc.sent_ping(6_200);
        cc.got_pong(6_500);
        let at_300ms_rtt = (cc.congestion_window() as usize) * 1000 / 300;
        assert_eq!(cc.get_bandwidth(), at_300ms_rtt + at_300ms_rtt / 2);

        // A short gap does not reset: the window keeps growing from where it was.
        let mut steady = VncCongestionController::new(0);
        for i in 0..3u32 {
            let t_send = u64::from(i) * 20;
            steady.update_position((i + 1) * 20_000, t_send);
            steady.sent_ping(t_send);
            steady.got_pong(t_send + 10);
        }
        assert_eq!(steady.congestion_window(), INITIAL_WINDOW * 2);
        steady.update_position(80_000, 120);
        assert_eq!(steady.congestion_window(), INITIAL_WINDOW * 2);
    }

    #[test]
    fn rfb_version_banner_and_linux_virtual_session_allocator() {
        assert_eq!(parse_rfb_version_banner(RFB_VERSION_3_8_BANNER), Ok((3, 8)));
        assert!(parse_rfb_version_banner(b"RFB 003.008").is_err());

        let mut sesman = LinuxVirtualSessionAllocator::new(10, 11);
        let alice = sesman.acquire_or_reconnect(1000, "alice").unwrap();
        assert_eq!(alice.display_number, 10);
        assert_eq!(alice.x11_display_env, ":10");
        // Reconnecting same UID reuses display :10
        assert_eq!(sesman.acquire_or_reconnect(1000, "alice").unwrap(), alice);

        let bob = sesman.acquire_or_reconnect(1001, "bob").unwrap();
        assert_eq!(bob.display_number, 11);
        assert!(sesman.acquire_or_reconnect(1002, "charlie").is_err());
    }
}
