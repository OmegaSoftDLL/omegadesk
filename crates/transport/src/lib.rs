//! QUIC transport for OmegaDesk.
//!
//! In Phase 1 the agent generates a fresh self-signed TLS certificate on
//! startup and displays its SHA-256 fingerprint. The client only accepts a
//! connection whose server certificate matches that exact fingerprint. In
//! Phase 2 peer authentication is bound to `omegadesk-identity` device keys
//! and the coordination server.

mod pinned;
pub mod race;
mod uro;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::BytesMut;
use omegadesk_protocol::v1::Envelope;
use omegadesk_protocol::{FrameDecoder, FramingError, encode_frame};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256};

pub use quinn::{Connection, Endpoint, RecvStream, SendStream};
pub use uro::is_broken as is_uro_disabled;

/// Application-Layer Protocol Negotiation identifier.
pub const ALPN: &[u8] = b"omegadesk/1";

/// Default UDP port used by the agent.
pub const DEFAULT_PORT: u16 = 7070;

/// Transport errors.
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    /// Failed to generate the self-signed certificate.
    #[error("certificate: {0}")]
    Certificate(#[from] rcgen::Error),
    /// Invalid TLS configuration or handshake error.
    #[error("TLS: {0}")]
    Tls(#[from] rustls::Error),
    /// Invalid QUIC configuration.
    #[error("QUIC: {0}")]
    QuicConfig(String),
    /// Socket I/O error.
    #[error("socket: {0}")]
    Io(#[from] std::io::Error),
    /// Failed to initiate the QUIC connection.
    #[error("connect: {0}")]
    Connect(#[from] quinn::ConnectError),
    /// The connection was lost or rejected.
    #[error("connection: {0}")]
    Connection(#[from] quinn::ConnectionError),
    /// Failed to write to a QUIC stream.
    #[error("write: {0}")]
    Write(#[from] quinn::WriteError),
    /// Failed to read from a QUIC stream.
    #[error("read: {0}")]
    Read(#[from] quinn::ReadError),
    /// Malformed protocol frame.
    #[error(transparent)]
    Framing(#[from] FramingError),
    /// The provided certificate fingerprint string is malformed.
    #[error("invalid certificate fingerprint")]
    InvalidFingerprint,
}

/// Formats the SHA-256 digest of a DER certificate as colon-separated lowercase
/// hex bytes (the format printed by the agent).
#[must_use]
pub fn fingerprint(certificate: &[u8]) -> String {
    let digest = Sha256::digest(certificate);
    data_encoding::HEXLOWER
        .encode(&digest)
        .as_bytes()
        .chunks(2)
        .filter_map(|pair| std::str::from_utf8(pair).ok())
        .collect::<Vec<_>>()
        .join(":")
}

fn parse_fingerprint(text: &str) -> Result<[u8; 32], TransportError> {
    let hex: String = text
        .chars()
        .filter(char::is_ascii_hexdigit)
        .map(|c| c.to_ascii_lowercase())
        .collect();
    let bytes = data_encoding::HEXLOWER
        .decode(hex.as_bytes())
        .map_err(|_| TransportError::InvalidFingerprint)?;
    bytes
        .try_into()
        .map_err(|_| TransportError::InvalidFingerprint)
}

fn crypto_provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn transport_config() -> quinn::TransportConfig {
    let mut config = quinn::TransportConfig::default();
    config.keep_alive_interval(Some(Duration::from_secs(2)));
    // Keep Quinn's 30 s default idle timeout so bursty packet loss does not tear down the session.
    if let Ok(timeout) = Duration::from_secs(30).try_into() {
        config.max_idle_timeout(Some(timeout));
    }
    // Intentionally small flow-control windows: backpressure stays in the agent,
    // which drops stale frames and requests a fresh keyframe instead of queueing
    // seconds of delayed video inside QUIC buffers. 4 MiB fits a 4K keyframe.
    config.stream_receive_window(quinn::VarInt::from_u32(4 * 1024 * 1024));
    config.receive_window(quinn::VarInt::from_u32(8 * 1024 * 1024));
    config.send_window(4 * 1024 * 1024);
    config
}

/// Creates a server QUIC endpoint bound to `bind` with a fresh self-signed certificate.
///
/// Returns the endpoint and the certificate fingerprint that the client must pin.
///
/// # Errors
///
/// Returns an error if certificate generation fails or the UDP socket cannot be bound.
pub fn server_endpoint(bind: SocketAddr) -> Result<(Endpoint, String), TransportError> {
    let certified = rcgen::generate_simple_self_signed(vec!["omegadesk".to_owned()])?;
    let certificate: CertificateDer<'static> = certified.cert.der().clone();
    let fingerprint = fingerprint(&certificate);
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        certified.signing_key.serialize_der(),
    ));

    let mut tls = rustls::ServerConfig::builder_with_provider(crypto_provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(vec![certificate], key)?;
    tls.alpn_protocols = vec![ALPN.to_vec()];

    let crypto =
        QuicServerConfig::try_from(tls).map_err(|e| TransportError::QuicConfig(e.to_string()))?;
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    config.transport_config(Arc::new(transport_config()));

    let std_socket = std::net::UdpSocket::bind(bind)?;
    let runtime = quinn::default_runtime().ok_or_else(|| {
        TransportError::Io(std::io::Error::other("no async runtime found for quinn"))
    })?;
    let socket = uro::wrap_udp_socket(std_socket, &runtime)?;
    let endpoint = Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        Some(config),
        socket,
        runtime,
    )?;

    Ok((endpoint, fingerprint))
}

/// Connects to the agent at `address`, accepting only a server certificate
/// whose SHA-256 fingerprint matches `expected_fingerprint`.
///
/// # Errors
///
/// Returns an error if the fingerprint is malformed, the connection fails, or
/// the server's certificate does not match `expected_fingerprint`.
pub async fn connect(
    address: SocketAddr,
    expected_fingerprint: &str,
) -> Result<(Endpoint, Connection), TransportError> {
    let expected = parse_fingerprint(expected_fingerprint)?;
    let provider = crypto_provider();

    let mut tls = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(pinned::PinnedVerifier::new(expected, provider)))
        .with_no_client_auth();
    tls.alpn_protocols = vec![ALPN.to_vec()];

    let crypto =
        QuicClientConfig::try_from(tls).map_err(|e| TransportError::QuicConfig(e.to_string()))?;
    let mut config = quinn::ClientConfig::new(Arc::new(crypto));
    config.transport_config(Arc::new(transport_config()));

    let bind: SocketAddr = if address.is_ipv6() {
        (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
    } else {
        (std::net::Ipv4Addr::UNSPECIFIED, 0).into()
    };
    let std_socket = std::net::UdpSocket::bind(bind)?;
    let runtime = quinn::default_runtime().ok_or_else(|| {
        TransportError::Io(std::io::Error::other("no async runtime found for quinn"))
    })?;
    let socket = uro::wrap_udp_socket(std_socket, &runtime)?;
    let mut endpoint = Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        None,
        socket,
        runtime,
    )?;
    endpoint.set_default_client_config(config);
    let connection = endpoint.connect(address, "omegadesk")?.await?;
    Ok((endpoint, connection))
}

/// Writes a length-prefixed `Envelope` to `stream`.
///
/// # Errors
///
/// Returns an error if the message exceeds the maximum frame size or the stream closes.
pub async fn send_envelope(
    stream: &mut SendStream,
    envelope: &Envelope,
) -> Result<(), TransportError> {
    let mut buffer = BytesMut::new();
    encode_frame(envelope, &mut buffer)?;
    stream.write_chunk(buffer.freeze()).await?;
    Ok(())
}

/// Reads length-prefixed `Envelope` frames from a QUIC receive stream.
#[derive(Debug)]
pub struct EnvelopeReader {
    stream: RecvStream,
    decoder: FrameDecoder,
    chunk: Vec<u8>,
}

impl EnvelopeReader {
    /// Wraps a QUIC receive stream in a framed `Envelope` reader.
    #[must_use]
    pub fn new(stream: RecvStream) -> Self {
        Self {
            stream,
            decoder: FrameDecoder::new(),
            chunk: vec![0; 64 * 1024],
        }
    }

    /// Reads the next `Envelope`, or returns `None` when the peer cleanly finishes the stream.
    ///
    /// # Errors
    ///
    /// Returns an error if reading from the stream fails or the frame is malformed.
    pub async fn next(&mut self) -> Result<Option<Envelope>, TransportError> {
        loop {
            if let Some(envelope) = self.decoder.next_frame()? {
                return Ok(Some(envelope));
            }
            match self.stream.read(&mut self.chunk).await? {
                Some(read) => self.decoder.extend(&self.chunk[..read]),
                None => return Ok(None),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};

    use omegadesk_protocol::v1::{Envelope, Ping, envelope::Payload};

    use super::{EnvelopeReader, TransportError, connect, send_envelope, server_endpoint};

    fn localhost() -> SocketAddr {
        (Ipv4Addr::LOCALHOST, 0).into()
    }

    #[tokio::test]
    async fn round_trip_over_quic() {
        let (server, fingerprint) = server_endpoint(localhost()).unwrap();
        let address = server.local_addr().unwrap();

        let accept = tokio::spawn(async move {
            let connection = server.accept().await.unwrap().await.unwrap();
            let (mut send, recv) = connection.accept_bi().await.unwrap();
            let mut reader = EnvelopeReader::new(recv);
            let envelope = reader.next().await.unwrap().unwrap();
            send_envelope(&mut send, &envelope).await.unwrap();
            send.finish().unwrap();
            connection.closed().await;
        });

        let (_endpoint, connection) = connect(address, &fingerprint).await.unwrap();
        let (mut send, recv) = connection.open_bi().await.unwrap();
        let ping = Envelope {
            payload: Some(Payload::Ping(Ping {
                sequence: 42,
                sent_at_micros: 7,
            })),
        };
        send_envelope(&mut send, &ping).await.unwrap();

        let mut reader = EnvelopeReader::new(recv);
        assert_eq!(reader.next().await.unwrap(), Some(ping));
        connection.close(0u32.into(), b"done");
        accept.await.unwrap();
    }

    #[tokio::test]
    async fn rejects_wrong_fingerprint() {
        let (server, _) = server_endpoint(localhost()).unwrap();
        let address = server.local_addr().unwrap();
        tokio::spawn(async move {
            if let Some(incoming) = server.accept().await {
                let _ = incoming.await;
            }
        });

        let wrong = "00".repeat(32);
        let result = connect(address, &wrong).await;
        assert!(matches!(result, Err(TransportError::Connection(_))));
    }

    #[tokio::test]
    async fn rejects_malformed_fingerprint() {
        let result = connect(localhost(), "abc").await;
        assert!(matches!(result, Err(TransportError::InvalidFingerprint)));
    }
}
