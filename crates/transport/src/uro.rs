//! Process-wide kill switch for Windows UDP Receive Segment Coalescing (URO).
//!
//! Reference: Firezone (`rust/libs/connlib/socket-factory/src/uro.rs` and
//! `pool.rs`, Apache-2.0) and <https://github.com/quinn-rs/quinn/issues/2041>.
//!
//! Some Windows network interface drivers coalesce incoming UDP datagrams into
//! a single buffer without attaching the `UDP_COALESCED_INFO` control message
//! required by `quinn-udp` to split the buffer back into individual datagrams
//! (reporting `stride == len` for a multi-packet train), or report a nonsensical
//! `stride == 0` that panics `step_by(0)` in `quinn-proto`.
//!
//! When such a receive is observed on any QUIC socket, this module:
//! 1. Latches a process-wide [`is_broken`] kill switch so all current and
//!    future sockets disable URO (`UDP_RECV_MAX_COALESCED_SIZE = 0`).
//! 2. Salvages the receive metadata (`RecvMeta::stride`) so `quinn-proto` never
//!    panics on a zero stride and can recover standard 1200-byte initial QUIC
//!    trains.

use std::fmt;
use std::io::{self, IoSliceMut};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};

use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, Runtime, UdpPoller};
use tracing::warn;

/// Maximum uncoalesced UDP payload size expected by Quinn (standard Ethernet
/// MTU 1500 minus IPv4/UDP headers is 1472 bytes; Quinn caps path MTU discovery
/// at 1452 bytes by default). A single receive larger than this with
/// `stride == len` or `stride > MAX_QUIC_DATAGRAM` proves broken URO coalescing.
pub(crate) const MAX_QUIC_DATAGRAM: usize = 1500;

/// Standard QUIC Initial datagram size (RFC 9000 §14.1), used to salvage
/// coalesced handshake trains when `UDP_COALESCED_INFO` is missing.
const QUIC_INITIAL_MTU: usize = 1200;

/// Process-wide latch set once broken URO coalescing is detected.
static BROKEN: AtomicBool = AtomicBool::new(false);

/// Returns `true` if broken URO coalescing has been observed in this process or
/// if `OMEGADESK_DISABLE_URO` is set in the environment.
#[must_use]
pub fn is_broken() -> bool {
    BROKEN.load(Ordering::Relaxed)
        || std::env::var_os("OMEGADESK_DISABLE_URO").is_some_and(|v| v != "0" && !v.is_empty())
}

/// Reason why a UDP receive proved that URO coalescing is broken.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Reason {
    /// `RecvMeta::stride` was zero for a non-empty datagram.
    ZeroSizedSegment,
    /// `RecvMeta::stride` exceeded [`MAX_QUIC_DATAGRAM`].
    OversizedSegment,
    /// Multiple QUIC datagrams were merged with `stride == len` (`UDP_COALESCED_INFO` missing).
    MergedDatagramTrain,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Detection {
    reason: Reason,
    salvaged_stride: usize,
}

fn classify(len: usize, stride: usize) -> Option<Detection> {
    if len == 0 {
        return None;
    }
    if stride == 0 {
        return Some(Detection {
            reason: Reason::ZeroSizedSegment,
            salvaged_stride: len.min(MAX_QUIC_DATAGRAM),
        });
    }
    if stride == len && len > MAX_QUIC_DATAGRAM {
        // `quinn-udp` sets `stride = len` when `UDP_COALESCED_INFO` is absent.
        // If `len` is an exact multiple of the 1200-byte QUIC Initial MTU,
        // recover the 1200-byte segment boundaries; otherwise clamp to one
        // segment so Quinn parses the leading packet without panicking.
        let salvaged_stride = if len.is_multiple_of(QUIC_INITIAL_MTU) {
            QUIC_INITIAL_MTU
        } else {
            len
        };
        return Some(Detection {
            reason: Reason::MergedDatagramTrain,
            salvaged_stride,
        });
    }
    if stride > MAX_QUIC_DATAGRAM {
        return Some(Detection {
            reason: Reason::OversizedSegment,
            salvaged_stride: len,
        });
    }
    None
}

/// Inspects a batch of completed receives (`meta[..count]`), rewriting broken
/// `stride` values in place and returning `true` if any entry proved broken
/// URO coalescing.
pub(crate) fn detect_broken_coalescing<'a>(
    receives: impl Iterator<Item = &'a mut RecvMeta>,
) -> bool {
    let mut any_broken = false;
    for meta in receives {
        let Some(detection) = classify(meta.len, meta.stride) else {
            continue;
        };
        any_broken = true;
        if !BROKEN.swap(true, Ordering::Relaxed) {
            warn!(
                stride = meta.stride,
                len = meta.len,
                reason = ?detection.reason,
                salvaged_stride = detection.salvaged_stride,
                "received UDP datagram proving broken Windows URO coalescing; disabling URO for process"
            );
        }
        meta.stride = detection.salvaged_stride;
    }
    any_broken
}

/// Wraps a `std::net::UdpSocket` into a Quinn [`AsyncUdpSocket`] guarded by the
/// Windows URO kill switch.
///
/// # Errors
///
/// Returns an error if the runtime cannot register the socket.
pub fn wrap_udp_socket(
    socket: std::net::UdpSocket,
    runtime: &Arc<dyn Runtime>,
) -> io::Result<Arc<dyn AsyncUdpSocket>> {
    #[cfg(windows)]
    let raw_socket = {
        use std::os::windows::io::AsRawSocket;
        socket.as_raw_socket()
    };

    let inner = runtime.wrap_udp_socket(socket)?;

    #[cfg(windows)]
    if is_broken() {
        disable_uro_raw(raw_socket);
    }

    Ok(Arc::new(UroSafeUdpSocket {
        inner,
        #[cfg(windows)]
        raw_socket,
        #[cfg(windows)]
        uro_disabled: AtomicBool::new(is_broken()),
    }))
}

struct UroSafeUdpSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    #[cfg(windows)]
    raw_socket: std::os::windows::io::RawSocket,
    #[cfg(windows)]
    uro_disabled: AtomicBool,
}

impl fmt::Debug for UroSafeUdpSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UroSafeUdpSocket")
            .field("inner", &self.inner)
            .finish_non_exhaustive()
    }
}

impl AsyncUdpSocket for UroSafeUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        self.inner.try_send(transmit)
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let poll = self.inner.poll_recv(cx, bufs, meta);
        if let Poll::Ready(Ok(count)) = &poll {
            let count = (*count).min(meta.len());
            if detect_broken_coalescing(meta[..count].iter_mut()) {
                #[cfg(windows)]
                if !self.uro_disabled.swap(true, Ordering::Relaxed) {
                    disable_uro_raw(self.raw_socket);
                }
            }
        }
        poll
    }

    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.inner.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        self.inner.max_transmit_segments()
    }

    fn max_receive_segments(&self) -> usize {
        if is_broken() {
            1
        } else {
            self.inner.max_receive_segments()
        }
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

#[cfg(windows)]
#[allow(
    unsafe_code,
    reason = "setsockopt to disable UDP_RECV_MAX_COALESCED_SIZE"
)]
fn disable_uro_raw(raw_socket: std::os::windows::io::RawSocket) {
    use windows::Win32::Networking::WinSock::{
        IPPROTO_UDP, SOCKET, UDP_RECV_MAX_COALESCED_SIZE, setsockopt,
    };

    let zero: u32 = 0;
    let optval: &[u8] =
        // SAFETY: `zero` is a valid initialized `u32` on the stack (`4` bytes).
        unsafe { std::slice::from_raw_parts((&raw const zero).cast::<u8>(), size_of::<u32>()) };
    #[allow(clippy::cast_possible_truncation, reason = "SOCKET fits in usize")]
    let sock = SOCKET(raw_socket as usize);
    // SAFETY: `sock` is owned by `self.inner` for the lifetime of `UroSafeUdpSocket`,
    // and `UDP_RECV_MAX_COALESCED_SIZE` expects a `DWORD` (`u32`) option value.
    let result = unsafe {
        setsockopt(
            sock,
            IPPROTO_UDP.0,
            UDP_RECV_MAX_COALESCED_SIZE,
            Some(optval),
        )
    };
    if result != 0 {
        warn!(
            "failed to disable URO via setsockopt: {}",
            io::Error::last_os_error()
        );
    }
}

#[cfg(test)]
mod tests {
    use quinn::udp::RecvMeta;

    use super::{MAX_QUIC_DATAGRAM, QUIC_INITIAL_MTU, Reason, classify, detect_broken_coalescing};

    #[test]
    fn normal_single_and_split_datagrams_pass_through() {
        assert_eq!(classify(1200, 1200), None);
        assert_eq!(classify(3600, 1200), None);
        assert_eq!(classify(MAX_QUIC_DATAGRAM, MAX_QUIC_DATAGRAM), None);
    }

    #[test]
    fn zero_stride_is_detected_and_salvaged() {
        let mut metas = [RecvMeta {
            len: 420,
            stride: 0,
            ..RecvMeta::default()
        }];
        assert!(detect_broken_coalescing(metas.iter_mut()));
        assert_eq!(metas[0].stride, 420);
    }

    #[test]
    fn coalesced_initial_train_without_metadata_is_salvaged() {
        let detection = classify(QUIC_INITIAL_MTU * 3, QUIC_INITIAL_MTU * 3).unwrap();
        assert_eq!(detection.reason, Reason::MergedDatagramTrain);
        assert_eq!(detection.salvaged_stride, QUIC_INITIAL_MTU);
    }

    #[test]
    fn oversized_stride_is_detected() {
        let detection = classify(2400, 2000).unwrap();
        assert_eq!(detection.reason, Reason::OversizedSegment);
        assert_eq!(detection.salvaged_stride, 2400);
    }
}
