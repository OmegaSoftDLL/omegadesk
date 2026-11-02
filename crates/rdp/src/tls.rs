//! TLS upgrade for the RDP bridge with server certificate pinning.
//!
//! RDP servers almost always present a self-signed certificate, so the classic PKI check is
//! useless and IronRDP's own helper (`Devolutions_IronRDP/crates/ironrdp-tls/src/rustls.rs`,
//! `danger::NoCertificateVerification`) accepts anything. The bridge instead pins the
//! SHA-256 of the server's end-entity certificate ([`CertificatePolicy::Pinned`]), exactly
//! like the Phase 1 client pins the agent certificate, or records it on first use
//! ([`CertificatePolicy::TrustOnFirstUse`]) so the caller can pin it for the next session.
//! Signatures are still verified for real with the `ring` provider.
//!
//! TLS session resumption is disabled because CredSSP forbids it
//! (`[MS-CSSP]` 2.1: "TLS session resumption is not supported").

use std::sync::{Arc, Mutex};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

use crate::bridge::{CertificatePolicy, RdpBridgeError};

/// SHA-256 digest of a DER-encoded certificate.
#[must_use]
pub fn certificate_sha256(der: &[u8]) -> [u8; 32] {
    Sha256::digest(der).into()
}

/// Verifier that pins the end-entity certificate digest and delegates signature checks to
/// the `ring` provider.
#[derive(Debug)]
struct PinnedCertificateVerifier {
    policy: CertificatePolicy,
    observed: Mutex<Option<[u8; 32]>>,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for PinnedCertificateVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let digest = certificate_sha256(end_entity);
        if let Ok(mut observed) = self.observed.lock() {
            *observed = Some(digest);
        }
        match self.policy {
            CertificatePolicy::Pinned(expected) if expected != digest => {
                Err(rustls::Error::InvalidCertificate(
                    rustls::CertificateError::ApplicationVerificationFailure,
                ))
            }
            CertificatePolicy::Pinned(_) | CertificatePolicy::TrustOnFirstUse => {
                Ok(ServerCertVerified::assertion())
            }
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Result of a successful TLS upgrade.
pub struct UpgradedTls<S> {
    /// The encrypted stream.
    pub stream: TlsStream<S>,
    /// DER end-entity certificate presented by the server.
    pub certificate: CertificateDer<'static>,
    /// SHA-256 of [`Self::certificate`].
    pub certificate_sha256: [u8; 32],
}

/// Upgrades `stream` to TLS against `server_name`, enforcing `policy` on the server
/// certificate.
///
/// # Errors
///
/// Returns [`RdpBridgeError::CertificateMismatch`] when a pinned digest does not match,
/// [`RdpBridgeError::Tls`] for other handshake failures and [`RdpBridgeError::Io`] for
/// transport errors.
pub async fn upgrade<S>(
    stream: S,
    server_name: &str,
    policy: CertificatePolicy,
) -> Result<UpgradedTls<S>, RdpBridgeError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = Arc::new(PinnedCertificateVerifier {
        policy,
        observed: Mutex::new(None),
        provider: provider.clone(),
    });
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(verifier.clone())
        .with_no_client_auth();
    config.resumption = rustls::client::Resumption::disabled();

    let domain = ServerName::try_from(server_name.to_owned())
        .map_err(|_| RdpBridgeError::InvalidServerName(server_name.to_owned()))?;
    let connector = TlsConnector::from(Arc::new(config));
    let stream = match connector.connect(domain, stream).await {
        Ok(stream) => stream,
        Err(error) => {
            let observed = verifier.observed.lock().ok().and_then(|o| *o);
            if let (CertificatePolicy::Pinned(expected), Some(observed)) = (policy, observed)
                && expected != observed
            {
                return Err(RdpBridgeError::CertificateMismatch { expected, observed });
            }
            return Err(RdpBridgeError::Io(error));
        }
    };

    let certificate = stream
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|chain| chain.first())
        .cloned()
        .ok_or(RdpBridgeError::MissingServerCertificate)?
        .into_owned();
    let certificate_sha256 = certificate_sha256(&certificate);

    Ok(UpgradedTls {
        stream,
        certificate,
        certificate_sha256,
    })
}

/// Extracts the raw `subjectPublicKey` bytes of a DER certificate, which CredSSP binds the
/// credentials to (`[MS-CSSP]` 3.1.5, `pubKeyAuth`).
///
/// # Errors
///
/// Returns [`RdpBridgeError::InvalidServerCertificate`] when the DER cannot be parsed.
pub fn subject_public_key(certificate_der: &[u8]) -> Result<Vec<u8>, RdpBridgeError> {
    use x509_cert::der::Decode as _;

    let certificate = x509_cert::Certificate::from_der(certificate_der)
        .map_err(|error| RdpBridgeError::InvalidServerCertificate(error.to_string()))?;
    certificate
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes()
        .map(<[u8]>::to_vec)
        .ok_or_else(|| {
            RdpBridgeError::InvalidServerCertificate("subjectPublicKey has unused bits".into())
        })
}
