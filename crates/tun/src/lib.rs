//! Virtual network adapter (`TUN`) abstraction and batched IP packet channels.
//!
//! Modeled after Firezone's `libs/connlib/tun/src/lib.rs`:
//! - Packets are exchanged between the TUN device worker and the mesh engine in
//!   [`PacketBatch`] chunks (up to [`MAX_BATCH_SIZE`] packets per batch) so channel
//!   send/receive and task wake-up overhead is paid once per batch rather than once
//!   per packet.
//! - [`IpPacket`] validates IPv4 and IPv6 headers before entering the mesh tunnel.
//! - [`InMemoryTun::pair`] provides a deterministic full-duplex virtual link for
//!   testing without OS root/administrator privileges.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ops::Deref;

use bytes::Bytes;
use tokio::sync::mpsc;

/// Maximum number of packets held in a single [`PacketBatch`], matching Firezone's
/// `libs/connlib/tun/src/lib.rs` (96 on macOS to align with `3 * quinn_udp::BATCH_SIZE`,
/// 100 on Windows and Linux).
#[cfg(target_os = "macos")]
pub const MAX_BATCH_SIZE: usize = 96;

/// Maximum number of packets held in a single [`PacketBatch`], matching Firezone's
/// `libs/connlib/tun/src/lib.rs`.
#[cfg(not(target_os = "macos"))]
pub const MAX_BATCH_SIZE: usize = 100;

/// Capacity (in [`PacketBatch`] items) of the channels connecting the TUN device
/// to the mesh event loop.
pub const CHANNEL_CAPACITY: usize = 100;

/// Default inner MTU of the OmegaDesk mesh TUN interface (1280 bytes, the IPv6
/// minimum link MTU, leaving headroom for WireGuard + disco/UDP encapsulation).
pub const DEFAULT_MESH_MTU: u16 = 1280;

/// Minimum valid IPv4 header size in bytes.
const IPV4_MIN_HEADER_LEN: usize = 20;

/// Fixed IPv6 header size in bytes.
const IPV6_HEADER_LEN: usize = 40;

/// Errors returned when parsing or validating an [`IpPacket`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TunError {
    /// Packet is shorter than the minimum IPv4/IPv6 header.
    #[error("packet too short: {0} bytes")]
    PacketTooShort(usize),
    /// IP version nibble is neither 4 nor 6.
    #[error("unsupported IP version: {0}")]
    UnsupportedVersion(u8),
    /// Declared total length in the IP header does not match the slice length.
    #[error("IP total length mismatch: header declares {declared}, slice has {actual}")]
    LengthMismatch {
        /// Byte length declared in the IPv4/IPv6 header.
        declared: usize,
        /// Actual byte length of the buffer.
        actual: usize,
    },
    /// IPv4 header length (`IHL * 4`) is invalid.
    #[error("invalid IPv4 header length: {0} bytes")]
    InvalidIpv4HeaderLength(usize),
    /// IPv4 header checksum verification failed.
    #[error("invalid IPv4 header checksum")]
    InvalidChecksum,
}

/// Validated IPv4 or IPv6 packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpPacket {
    raw: Bytes,
}

impl IpPacket {
    /// Validates raw IPv4 or IPv6 bytes and constructs an [`IpPacket`].
    ///
    /// # Errors
    ///
    /// Returns [`TunError`] if the header version, length, or IPv4 checksum is invalid.
    pub fn parse(bytes: impl Into<Bytes>) -> Result<Self, TunError> {
        let raw = bytes.into();
        let Some(&first) = raw.first() else {
            return Err(TunError::PacketTooShort(0));
        };
        let version = first >> 4;
        match version {
            4 => {
                if raw.len() < IPV4_MIN_HEADER_LEN {
                    return Err(TunError::PacketTooShort(raw.len()));
                }
                let ihl_bytes = usize::from(first & 0x0F) * 4;
                if ihl_bytes < IPV4_MIN_HEADER_LEN || ihl_bytes > raw.len() {
                    return Err(TunError::InvalidIpv4HeaderLength(ihl_bytes));
                }
                let total_len = usize::from(u16::from_be_bytes([raw[2], raw[3]]));
                if total_len != raw.len() {
                    return Err(TunError::LengthMismatch {
                        declared: total_len,
                        actual: raw.len(),
                    });
                }
                if ipv4_checksum(&raw[..ihl_bytes]) != 0 {
                    return Err(TunError::InvalidChecksum);
                }
                Ok(Self { raw })
            }
            6 => {
                if raw.len() < IPV6_HEADER_LEN {
                    return Err(TunError::PacketTooShort(raw.len()));
                }
                let payload_len = usize::from(u16::from_be_bytes([raw[4], raw[5]]));
                let expected_total = IPV6_HEADER_LEN + payload_len;
                if expected_total != raw.len() {
                    return Err(TunError::LengthMismatch {
                        declared: expected_total,
                        actual: raw.len(),
                    });
                }
                Ok(Self { raw })
            }
            other => Err(TunError::UnsupportedVersion(other)),
        }
    }

    /// Builds a valid IPv4 UDP packet (useful for unit tests and internal DNS replies).
    #[must_use]
    pub fn ipv4_udp(
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> Self {
        let udp_len = 8 + payload.len();
        let total_len = IPV4_MIN_HEADER_LEN + udp_len;
        let mut buf = vec![0u8; total_len];
        buf[0] = 0x45; // IPv4, IHL = 5 (20 bytes)
        buf[1] = 0x00;
        let total_u16 = u16::try_from(total_len).unwrap_or(u16::MAX);
        buf[2..4].copy_from_slice(&total_u16.to_be_bytes());
        buf[8] = 64; // TTL
        buf[9] = 17; // UDP
        buf[12..16].copy_from_slice(&src_ip.octets());
        buf[16..20].copy_from_slice(&dst_ip.octets());

        let csum = ipv4_checksum(&buf[..IPV4_MIN_HEADER_LEN]);
        buf[10..12].copy_from_slice(&csum.to_be_bytes());

        let udp_u16 = u16::try_from(udp_len).unwrap_or(u16::MAX);
        buf[20..22].copy_from_slice(&src_port.to_be_bytes());
        buf[22..24].copy_from_slice(&dst_port.to_be_bytes());
        buf[24..26].copy_from_slice(&udp_u16.to_be_bytes());
        // UDP checksum 0 is valid in IPv4
        buf[26..28].copy_from_slice(&0u16.to_be_bytes());
        buf[28..].copy_from_slice(payload);

        Self {
            raw: Bytes::from(buf),
        }
    }

    /// IP version (`4` or `6`).
    #[must_use]
    pub fn version(&self) -> u8 {
        self.raw[0] >> 4
    }

    /// Source IP address.
    #[must_use]
    pub fn source(&self) -> IpAddr {
        if self.version() == 4 {
            IpAddr::V4(Ipv4Addr::new(
                self.raw[12],
                self.raw[13],
                self.raw[14],
                self.raw[15],
            ))
        } else {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&self.raw[8..24]);
            IpAddr::V6(Ipv6Addr::from(octets))
        }
    }

    /// Destination IP address.
    #[must_use]
    pub fn destination(&self) -> IpAddr {
        if self.version() == 4 {
            IpAddr::V4(Ipv4Addr::new(
                self.raw[16],
                self.raw[17],
                self.raw[18],
                self.raw[19],
            ))
        } else {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&self.raw[24..40]);
            IpAddr::V6(Ipv6Addr::from(octets))
        }
    }

    /// Upper-layer protocol number (e.g., `6` for TCP, `17` for UDP).
    #[must_use]
    pub fn protocol(&self) -> u8 {
        if self.version() == 4 {
            self.raw[9]
        } else {
            self.raw[6]
        }
    }

    /// Raw packet bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.raw
    }

    /// Consumes the packet and returns the underlying [`Bytes`].
    #[must_use]
    pub fn into_bytes(self) -> Bytes {
        self.raw
    }
}

/// Computes the RFC 1071 one's-complement checksum over `header`.
#[must_use]
pub fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum = 0u32;
    let (pairs, remainder) = header.as_chunks::<2>();
    for &pair in pairs {
        sum += u32::from(u16::from_be_bytes(pair));
    }
    if let Some(&rem) = remainder.first() {
        sum += u32::from(u16::from_be_bytes([rem, 0]));
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    #[allow(clippy::cast_possible_truncation)]
    let folded = sum as u16;
    !folded
}

/// A bounded batch of [`IpPacket`]s exchanged over TUN channels as a single unit,
/// modeled after Firezone's `PacketBatch` (`libs/connlib/tun/src/lib.rs`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketBatch {
    inner: Vec<IpPacket>,
}

impl Default for PacketBatch {
    fn default() -> Self {
        Self {
            inner: Vec::with_capacity(MAX_BATCH_SIZE),
        }
    }
}

impl PacketBatch {
    /// Starts a new batch containing `first`.
    #[must_use]
    pub fn new(first: IpPacket) -> Self {
        let mut batch = Self::default();
        batch.inner.push(first);
        batch
    }

    /// Appends `packet` to the batch, returning `Err(packet)` if the batch has
    /// reached [`MAX_BATCH_SIZE`].
    ///
    /// # Errors
    ///
    /// Hands back the original [`IpPacket`] if the batch is already full.
    pub fn try_push(&mut self, packet: IpPacket) -> Result<(), IpPacket> {
        if self.inner.len() >= MAX_BATCH_SIZE {
            return Err(packet);
        }
        self.inner.push(packet);
        Ok(())
    }

    /// Removes and returns all packets from the batch in order.
    pub fn drain(&mut self) -> std::vec::Drain<'_, IpPacket> {
        self.inner.drain(..)
    }
}

impl Deref for PacketBatch {
    type Target = [IpPacket];

    fn deref(&self) -> &[IpPacket] {
        &self.inner
    }
}

/// Sender half for outbound [`PacketBatch`]es injected into the TUN interface.
pub type OutboundTx = mpsc::Sender<PacketBatch>;

/// Receiver half for inbound [`PacketBatch`]es read from the TUN interface.
pub type InboundRx = mpsc::Receiver<PacketBatch>;

/// Platform-agnostic virtual network interface trait, modeled after Firezone's
/// `Tun` trait (`libs/connlib/tun/src/lib.rs`).
pub trait Tun: Send + Sync + 'static {
    /// Mutable reference to the sender for outbound packets going into the TUN device.
    fn sender(&mut self) -> &mut OutboundTx;

    /// Mutable reference to the receiver for inbound packets coming from the TUN device.
    fn receiver(&mut self) -> &mut InboundRx;

    /// Interface name (e.g., `"omegadesk0"` or `"utun7"`).
    fn name(&self) -> &str;

    /// Interface MTU in bytes.
    fn mtu(&self) -> u16 {
        DEFAULT_MESH_MTU
    }
}

/// Deterministic in-memory virtual TUN adapter for sans-I/O and integration testing.
pub struct InMemoryTun {
    name: String,
    mtu: u16,
    outbound_tx: OutboundTx,
    inbound_rx: InboundRx,
}

impl InMemoryTun {
    /// Creates a connected full-duplex pair of virtual TUN interfaces (`left` <-> `right`).
    ///
    /// Batches sent on `left.sender()` arrive on `right.receiver()`, and vice versa.
    #[must_use]
    pub fn pair(left_name: &str, right_name: &str) -> (Self, Self) {
        let (left_tx, right_rx) = mpsc::channel(CHANNEL_CAPACITY);
        let (right_tx, left_rx) = mpsc::channel(CHANNEL_CAPACITY);
        (
            Self {
                name: left_name.to_owned(),
                mtu: DEFAULT_MESH_MTU,
                outbound_tx: left_tx,
                inbound_rx: left_rx,
            },
            Self {
                name: right_name.to_owned(),
                mtu: DEFAULT_MESH_MTU,
                outbound_tx: right_tx,
                inbound_rx: right_rx,
            },
        )
    }
}

impl Tun for InMemoryTun {
    fn sender(&mut self) -> &mut OutboundTx {
        &mut self.outbound_tx
    }

    fn receiver(&mut self) -> &mut InboundRx {
        &mut self.inbound_rx
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn mtu(&self) -> u16 {
        self.mtu
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_udp_round_trip_and_checksum_validation() {
        let src = Ipv4Addr::new(100, 64, 0, 1);
        let dst = Ipv4Addr::new(100, 64, 0, 2);
        let pkt = IpPacket::ipv4_udp(src, dst, 51820, 4433, b"hello-mesh");

        let parsed = IpPacket::parse(pkt.as_bytes().to_vec()).unwrap();
        assert_eq!(parsed.version(), 4);
        assert_eq!(parsed.source(), IpAddr::V4(src));
        assert_eq!(parsed.destination(), IpAddr::V4(dst));
        assert_eq!(parsed.protocol(), 17);

        let mut corrupted = pkt.as_bytes().to_vec();
        corrupted[15] ^= 0xFF;
        assert_eq!(IpPacket::parse(corrupted), Err(TunError::InvalidChecksum));
    }

    #[test]
    fn packet_batch_enforces_max_batch_size() {
        let sample = IpPacket::ipv4_udp(
            Ipv4Addr::new(100, 64, 0, 1),
            Ipv4Addr::new(100, 64, 0, 2),
            1000,
            2000,
            b"x",
        );
        let mut batch = PacketBatch::new(sample.clone());
        for _ in 1..MAX_BATCH_SIZE {
            assert!(batch.try_push(sample.clone()).is_ok());
        }
        assert_eq!(batch.len(), MAX_BATCH_SIZE);
        assert!(batch.try_push(sample).is_err());
        assert_eq!(batch.drain().count(), MAX_BATCH_SIZE);
        assert!(batch.is_empty());
    }

    #[tokio::test]
    async fn in_memory_tun_pair_exchanges_batches() {
        let (mut left, mut right) = InMemoryTun::pair("omega0", "omega1");
        assert_eq!(left.name(), "omega0");
        assert_eq!(right.name(), "omega1");
        assert_eq!(left.mtu(), DEFAULT_MESH_MTU);

        let pkt = IpPacket::ipv4_udp(
            Ipv4Addr::new(100, 64, 0, 10),
            Ipv4Addr::new(100, 64, 0, 20),
            1234,
            5678,
            b"ping",
        );
        left.sender()
            .send(PacketBatch::new(pkt.clone()))
            .await
            .unwrap();
        let received = right.receiver().recv().await.unwrap();
        assert_eq!(received.len(), 1);
        assert_eq!(received[0], pkt);
    }
}
