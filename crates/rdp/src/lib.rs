//! RDP compatibility for OmegaDesk, built on [IronRDP](https://github.com/Devolutions/IronRDP).
//!
//! - [`bridge`]: the **RDP bridge**. The agent side terminates an RDP connection to an
//!   existing server (Windows Remote Desktop, xrdp, an `ironrdp-server`) with
//!   `ironrdp-connector` and `ironrdp-session`, and exposes the decoded framebuffer as an
//!   [`omegadesk_capture::Capturer`], so the regular capture → encode → QUIC pipeline streams
//!   a machine that only speaks RDP.
//! - [`rdcleanpath`] and [`displaycontrol`]: IronRDP's own `RDCleanPath` (DER) and
//!   `[MS-RDPEDISP]` encoders, re-exported so every PDU on the wire is produced by the same
//!   code Devolutions Gateway and the IronRDP web client use.
//! - [`congestion`]: `TigerVNC`'s TCP-Vegas congestion controller for reliable streams.
//! - [`rfb`]: RFB banner/security-type primitives and the `xrdp-sesman` style per-user
//!   virtual session allocator.
//!
//! Reference implementations studied: `Devolutions_IronRDP/crates/ironrdp-client/src/rdp.rs`
//! (connection sequence, TLS upgrade, CredSSP, active session loop and the
//! Deactivation-Reactivation Sequence), `Devolutions_IronRDP/crates/ironrdp-tls/src/rustls.rs`
//! (TLS upgrade; our verifier pins the server certificate instead of accepting any), and
//! `TigerVNC_tigervnc/common/rfb/Congestion.cxx`.

pub mod bridge;
pub mod congestion;
pub mod rfb;
pub mod tls;

/// IronRDP `RDCleanPath` PDUs (`ironrdp-rdcleanpath`): DER encoding shared with
/// Devolutions Gateway and the IronRDP web client.
pub mod rdcleanpath {
    pub use ironrdp_rdcleanpath::*;
}

/// IronRDP `[MS-RDPEDISP]` Display Control virtual channel (`ironrdp-displaycontrol`).
pub mod displaycontrol {
    pub use ironrdp_displaycontrol::*;
}

pub use bridge::{
    CertificatePolicy, RdpBridge, RdpBridgeCapturer, RdpBridgeConfig, RdpBridgeError,
    RdpDesktopSize,
};
pub use congestion::{INITIAL_WINDOW, MAXIMUM_WINDOW, MINIMUM_WINDOW, VncCongestionController};
pub use ironrdp_session::GracefulDisconnectReason;
pub use rfb::{
    LinuxVirtualSession, LinuxVirtualSessionAllocator, RFB_VERSION_3_8_BANNER, RfbSecurityType,
    parse_rfb_version_banner,
};

/// Errors returned by the VNC/RFB compatibility primitives.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RdpError {
    /// Malformed or unsupported VNC/RFB 12-byte protocol version banner.
    #[error("invalid RFB protocol version banner")]
    InvalidRfbVersionBanner,
    /// No free X11/Wayland virtual display slots remain in the configured range.
    #[error("exhausted virtual display slots in range {0}..={1}")]
    ExhaustedVirtualDisplays(u16, u16),
}

#[cfg(test)]
mod tests {
    use ironrdp_core::{decode, encode_vec};
    use ironrdp_displaycontrol::pdu::{DisplayControlMonitorLayout, DisplayControlPdu};

    /// The `RDCleanPath` PDU is DER (ASN.1), produced by IronRDP's own encoder: this is what
    /// Devolutions Gateway and the IronRDP web client exchange. The old hand-rolled
    /// little-endian framing in this crate could not interoperate with either.
    #[test]
    fn rdcleanpath_request_round_trips_through_der() {
        use crate::rdcleanpath::RDCleanPathPdu;

        let request = RDCleanPathPdu::new_request(
            vec![
                0x03, 0x00, 0x00, 0x0b, 0x06, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00,
            ],
            "office-pc.omega:3389".to_owned(),
            "token".to_owned(),
            None,
        )
        .unwrap();
        let der = request.to_der().unwrap();
        // ASN.1 SEQUENCE tag.
        assert_eq!(der[0], 0x30);
        let decoded = RDCleanPathPdu::from_der(&der).unwrap();
        assert_eq!(decoded.destination.as_deref(), Some("office-pc.omega:3389"));
        assert_eq!(decoded.version, crate::rdcleanpath::VERSION_1);
    }

    /// `[MS-RDPEDISP]` monitor layouts are encoded by `ironrdp-displaycontrol`, which
    /// validates the `200..=8192` range and the even-width rule for us.
    #[test]
    fn displaycontrol_monitor_layout_is_encoded_by_ironrdp() {
        let layout = DisplayControlMonitorLayout::new_single_primary_monitor(
            1920,
            1080,
            None,
            Some((527, 296)),
        )
        .unwrap();
        let pdu = DisplayControlPdu::MonitorLayout(layout);
        let bytes = encode_vec(&pdu).unwrap();
        // DISPLAYCONTROL_HEADER: type (4 bytes LE) then length (4 bytes LE).
        assert_eq!(&bytes[..4], &0x0000_0002u32.to_le_bytes());
        assert_eq!(
            u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) as usize,
            bytes.len()
        );
        let decoded: DisplayControlPdu = decode(&bytes).unwrap();
        assert!(matches!(decoded, DisplayControlPdu::MonitorLayout(_)));

        assert!(
            DisplayControlMonitorLayout::new_single_primary_monitor(8194, 1080, None, None)
                .is_err()
        );
        assert!(
            DisplayControlMonitorLayout::new_single_primary_monitor(1920, 199, None, None).is_err()
        );
        // IronRDP rounds an odd width down to the even value the protocol requires.
        let rounded =
            DisplayControlMonitorLayout::new_single_primary_monitor(1921, 1080, None, None)
                .unwrap();
        assert_eq!(rounded.monitors()[0].dimensions(), (1920, 1080));
    }
}
