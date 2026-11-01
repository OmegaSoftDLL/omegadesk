//! TLS bound to the OmegaDesk device identity.
//!
//! In Phase 1 the agent showed a random certificate fingerprint that the user
//! had to paste into the client. On the mesh, the coordinator already tells
//! every node the Ed25519 signing key of every peer (`NodeInfo.signing_key`),
//! so the agent's QUIC certificate is simply **signed by that same key**: the
//! certificate carries the identity key as its `SubjectPublicKeyInfo`, and the
//! client accepts a connection only when the certificate key equals the key it
//! learned from the netmap. No fingerprint, no trust-on-first-use, and the
//! TLS 1.3 handshake proves possession of the identity's private key.
//!
//! This mirrors how Tailscale binds WireGuard to the node key distributed by
//! the control plane, applied to QUIC/TLS (RFC 8410 Ed25519 certificates).

use std::sync::Arc;

use omegadesk_identity::DeviceIdentity;
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error, SignatureScheme};

use crate::{ALPN, TransportError, crypto_provider, transport_config};

/// Server name used in the identity-bound certificates (the client never
/// validates it; the key is what matters).
pub const MESH_SERVER_NAME: &str = "omegadesk";

/// DER-encoded `AlgorithmIdentifier` for Ed25519 (`id-Ed25519`, RFC 8410 §3):
/// `SEQUENCE { OID 1.3.101.112 }`.
const ED25519_ALGORITHM_IDENTIFIER: [u8; 7] = [0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70];

/// Builds the QUIC server configuration whose certificate is signed by, and
/// carries, the device's Ed25519 identity key.
///
/// # Errors
///
/// Returns an error if the key cannot be converted or the certificate cannot be issued.
pub fn identity_server_config(
    identity: &DeviceIdentity,
) -> Result<quinn::ServerConfig, TransportError> {
    let pkcs8 = identity.signing_key_pkcs8_der();
    let key_der = PrivatePkcs8KeyDer::from(pkcs8.as_slice());
    let key_pair = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(&key_der, &rcgen::PKCS_ED25519)?;
    let params = rcgen::CertificateParams::new(vec![MESH_SERVER_NAME.to_owned()])?;
    let certificate = params.self_signed(&key_pair)?;
    let cert_der: CertificateDer<'static> = certificate.der().clone();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8.to_vec()));

    let mut tls = rustls::ServerConfig::builder_with_provider(crypto_provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key)?;
    tls.alpn_protocols = vec![ALPN.to_vec()];
    let crypto =
        QuicServerConfig::try_from(tls).map_err(|e| TransportError::QuicConfig(e.to_string()))?;
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    config.transport_config(Arc::new(transport_config()));
    Ok(config)
}

/// Builds the QUIC client configuration that accepts only a server whose
/// certificate key is `expected_signing_key` (the peer's identity from the netmap).
///
/// # Errors
///
/// Returns an error if the TLS configuration is invalid.
pub fn identity_client_config(
    expected_signing_key: [u8; 32],
) -> Result<quinn::ClientConfig, TransportError> {
    let provider = crypto_provider();
    let mut tls = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(IdentityVerifier {
            expected_signing_key,
            provider,
        }))
        .with_no_client_auth();
    tls.alpn_protocols = vec![ALPN.to_vec()];
    let crypto =
        QuicClientConfig::try_from(tls).map_err(|e| TransportError::QuicConfig(e.to_string()))?;
    let mut config = quinn::ClientConfig::new(Arc::new(crypto));
    config.transport_config(Arc::new(transport_config()));
    Ok(config)
}

/// Extracts the raw Ed25519 public key from the `SubjectPublicKeyInfo` of a
/// DER X.509 certificate by walking the ASN.1 structure
/// (`Certificate -> tbsCertificate -> ... -> subjectPublicKeyInfo`), so a
/// decoy key placed in an extension can never be mistaken for the real one.
///
/// Returns `None` if the certificate is malformed or does not use Ed25519.
#[must_use]
pub fn ed25519_key_from_certificate(der: &[u8]) -> Option<[u8; 32]> {
    let (certificate, _) = der_tlv(der, 0x30)?;
    let (tbs, _) = der_tlv(certificate, 0x30)?;
    let mut rest = tbs;
    // Optional explicit [0] version.
    if rest.first() == Some(&0xa0) {
        let (_, after) = der_skip(rest)?;
        rest = after;
    }
    // serialNumber, signature, issuer, validity, subject.
    for _ in 0..5 {
        let (_, after) = der_skip(rest)?;
        rest = after;
    }
    let (spki, _) = der_tlv(rest, 0x30)?;
    let (algorithm, after_alg) = der_tlv(spki, 0x30)?;
    let (alg_oid_len, _) = der_tlv(algorithm, 0x06).map(|(oid, _)| (oid.len(), oid))?;
    if algorithm.len() != alg_oid_len + 2
        || spki.get(..ED25519_ALGORITHM_IDENTIFIER.len()) != Some(&ED25519_ALGORITHM_IDENTIFIER[..])
    {
        return None;
    }
    let (bits, _) = der_tlv(after_alg, 0x03)?;
    // BIT STRING: first byte is the number of unused bits (0), then 32 key bytes.
    if bits.len() != 33 || bits[0] != 0 {
        return None;
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bits[1..]);
    Some(key)
}

/// Parses one DER TLV with the expected `tag`, returning `(value, rest)`.
fn der_tlv(input: &[u8], tag: u8) -> Option<(&[u8], &[u8])> {
    if input.first() != Some(&tag) {
        return None;
    }
    let (len, header) = der_length(&input[1..])?;
    let start = 1 + header;
    let end = start.checked_add(len)?;
    if end > input.len() {
        return None;
    }
    Some((&input[start..end], &input[end..]))
}

/// Skips one DER TLV of any tag, returning `(value, rest)`.
fn der_skip(input: &[u8]) -> Option<(&[u8], &[u8])> {
    let tag = *input.first()?;
    der_tlv(input, tag)
}

/// Decodes a DER length, returning `(length, bytes consumed by the length field)`.
fn der_length(input: &[u8]) -> Option<(usize, usize)> {
    let first = *input.first()?;
    if first < 0x80 {
        return Some((usize::from(first), 1));
    }
    let count = usize::from(first & 0x7f);
    if count == 0 || count > 4 || input.len() < 1 + count {
        return None;
    }
    let mut len = 0usize;
    for &b in &input[1..=count] {
        len = (len << 8) | usize::from(b);
    }
    Some((len, 1 + count))
}

/// Accepts only a certificate whose Ed25519 key equals the expected identity key.
#[derive(Debug)]
struct IdentityVerifier {
    expected_signing_key: [u8; 32],
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for IdentityVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        match ed25519_key_from_certificate(end_entity) {
            // Public keys are not secret, so a constant-time comparison is not needed.
            Some(key) if key == self.expected_signing_key => Ok(ServerCertVerified::assertion()),
            _ => Err(Error::General(
                "peer certificate key does not match the identity from the netmap".into(),
            )),
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Err(Error::General("TLS 1.2 is not accepted".into()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature(
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

#[cfg(test)]
mod tests {
    use super::*;

    fn certificate_for(identity: &DeviceIdentity) -> Vec<u8> {
        let pkcs8 = identity.signing_key_pkcs8_der();
        let key_der = PrivatePkcs8KeyDer::from(pkcs8.as_slice());
        let key_pair =
            rcgen::KeyPair::from_pkcs8_der_and_sign_algo(&key_der, &rcgen::PKCS_ED25519).unwrap();
        let params = rcgen::CertificateParams::new(vec![MESH_SERVER_NAME.to_owned()]).unwrap();
        params.self_signed(&key_pair).unwrap().der().to_vec()
    }

    #[test]
    fn certificate_carries_the_identity_key() {
        let identity = DeviceIdentity::generate();
        let der = certificate_for(&identity);
        assert_eq!(
            ed25519_key_from_certificate(&der),
            Some(identity.public().signing_key_bytes())
        );
        let other = DeviceIdentity::generate();
        assert_ne!(
            ed25519_key_from_certificate(&certificate_for(&other)),
            Some(identity.public().signing_key_bytes())
        );
        assert_eq!(ed25519_key_from_certificate(b"not a certificate"), None);
        // A truncated certificate never panics.
        assert_eq!(ed25519_key_from_certificate(&der[..der.len() / 2]), None);
    }

    #[test]
    fn der_length_forms() {
        assert_eq!(der_length(&[0x05]), Some((5, 1)));
        assert_eq!(der_length(&[0x81, 0x80]), Some((128, 2)));
        assert_eq!(der_length(&[0x82, 0x01, 0x00]), Some((256, 3)));
        assert_eq!(der_length(&[0x85, 0, 0, 0, 0, 0]), None);
        assert_eq!(der_length(&[]), None);
    }

    /// Minimal DER TLV encoder for hand-built malformed certificates.
    fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        match body.len() {
            len if len < 0x80 => out.push(u8::try_from(len).unwrap()),
            len if len < 0x100 => out.extend_from_slice(&[0x81, u8::try_from(len).unwrap()]),
            len => {
                out.push(0x82);
                out.extend_from_slice(&u16::try_from(len).unwrap().to_be_bytes());
            }
        }
        out.extend_from_slice(body);
        out
    }

    #[test]
    fn malformed_certificates_never_panic() {
        // An SPKI whose AlgorithmIdentifier holds a one-byte OID is only five
        // bytes long: shorter than the Ed25519 identifier it is compared with.
        let short_alg = tlv(0x30, &tlv(0x06, &[0x2b]));
        let spki = tlv(0x30, &[short_alg, tlv(0x03, &[0u8; 33])].concat());
        let tbs_body = [
            tlv(0xa0, &tlv(0x02, &[0x02])),
            tlv(0x02, &[0x01]),
            tlv(0x30, &[]),
            tlv(0x30, &[]),
            tlv(0x30, &[]),
            tlv(0x30, &[]),
            spki,
        ]
        .concat();
        let cert = tlv(0x30, &tlv(0x30, &tbs_body));
        assert_eq!(ed25519_key_from_certificate(&cert), None);

        // Every truncation and every single-byte corruption of a real
        // certificate is rejected or parsed, never a panic (this runs on
        // untrusted peer input before signature verification).
        let identity = DeviceIdentity::generate();
        let der = certificate_for(&identity);
        for cut in 0..der.len() {
            let _ = ed25519_key_from_certificate(&der[..cut]);
        }
        for i in 0..der.len() {
            for flip in [0x00u8, 0x7f, 0x80, 0xff] {
                let mut mutated = der.clone();
                mutated[i] = flip;
                let _ = ed25519_key_from_certificate(&mutated);
            }
        }
    }
}
