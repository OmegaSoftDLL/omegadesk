//! Tailscale-style discovery and NAT hole-punching messages (`disco`).
//!
//! Modeled after `tailscale/disco/disco.go` (BSD-3-Clause):
//! - Every disco packet begins with the 6-byte magic header `b"TS\xf0\x9f\x92\xac"`
//!   (`"TS💬"`), allowing a single UDP socket ("magicsock") to demultiplex
//!   discovery frames from encrypted WireGuard/tunnel data packets.
//! - Followed by the sender's 32-byte X25519 key, a 12-byte nonce, and the
//!   ChaCha20-Poly1305 authenticated payload (`Ping`, `Pong`, or `CallMeMaybe`).

use std::net::{IpAddr, Ipv6Addr, SocketAddr};

use rand_core::{OsRng, RngCore};
use ring::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};

/// Six-byte header (`"TS💬"`) identifying a discovery packet on the wire,
/// matching `disco.Magic` in `tailscale/disco/disco.go`.
pub const MAGIC: [u8; 6] = [0x54, 0x53, 0xf0, 0x9f, 0x92, 0xac];

/// Current disco wire protocol version (`v0`, matching `tailscale/disco/disco.go`).
pub const PROTOCOL_VERSION: u8 = 0;

const TYPE_PING: u8 = 0x01;
const TYPE_PONG: u8 = 0x02;
const TYPE_CALL_ME_MAYBE: u8 = 0x03;

/// Length of a random Ping/Pong transaction identifier (`[u8; 12]`).
pub const TX_ID_LEN: usize = 12;

/// Encoded address length (`16B IPv6/IPv4-mapped + 2B little-endian port`),
/// matching `endpointLen` in `tailscale/disco/disco.go`.
const ADDR_LEN: usize = 18;

const HEADER_LEN: usize = MAGIC.len() + 32 + 12;
const TAG_LEN: usize = 16;

/// Random 12-byte transaction identifier correlating a [`DiscoMessage::Ping`]
/// with its [`DiscoMessage::Pong`].
pub type TxId = [u8; TX_ID_LEN];

/// Generates a fresh random 12-byte [`TxId`].
#[must_use]
pub fn random_tx_id() -> TxId {
    let mut id = [0u8; TX_ID_LEN];
    OsRng.fill_bytes(&mut id);
    id
}

/// Discovery message payloads exchanged during NAT hole-punching and direct-path
/// liveness probing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscoMessage {
    /// Direct or relayed probe carrying a 12-byte transaction ID, the sender's
    /// 32-byte public key, and optional MTU padding bytes.
    Ping {
        /// Random 12-byte correlation ID echoed in [`DiscoMessage::Pong`].
        tx_id: TxId,
        /// Sender's 32-byte X25519 public key.
        node_key: [u8; 32],
        /// Number of zero padding bytes appended for path MTU probing.
        padding: u16,
    },
    /// Response to a [`DiscoMessage::Ping`], echoing `tx_id` and reporting the
    /// observed source [`SocketAddr`] (acting as built-in STUN).
    Pong {
        /// Echoed 12-byte transaction ID from the [`DiscoMessage::Ping`].
        tx_id: TxId,
        /// Observed source address of the `Ping` packet.
        src: SocketAddr,
    },
    /// Sent over the relay to invite a peer to simultaneously hole-punch all of
    /// the sender's candidate endpoints.
    CallMeMaybe {
        /// Candidate local and STUN-reflexive endpoints of the sender.
        my_numbers: Vec<SocketAddr>,
    },
}

/// Errors returned when encoding or decoding a disco packet.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DiscoError {
    /// Packet does not start with [`MAGIC`] or is shorter than the header.
    #[error("not a valid disco packet")]
    InvalidHeader,
    /// Unsupported disco message type or protocol version.
    #[error("unsupported disco message type {msg_type:#04x} (version {version})")]
    UnsupportedType {
        /// Message type byte.
        msg_type: u8,
        /// Version byte.
        version: u8,
    },
    /// Message payload length does not match its type definition.
    #[error("malformed disco message payload")]
    MalformedPayload,
    /// AEAD authentication failed or peer X25519 key is invalid.
    #[error("disco packet authentication failed")]
    CryptoFailed,
}

impl DiscoMessage {
    /// Serializes this disco message into its cleartext wire representation
    /// (`1B type + 1B version + type-specific body`).
    #[must_use]
    pub fn to_plaintext(&self) -> Vec<u8> {
        match self {
            Self::Ping {
                tx_id,
                node_key,
                padding,
            } => {
                let pad_len = usize::from(*padding);
                let mut out = Vec::with_capacity(2 + TX_ID_LEN + 32 + pad_len);
                out.push(TYPE_PING);
                out.push(PROTOCOL_VERSION);
                out.extend_from_slice(tx_id);
                out.extend_from_slice(node_key);
                out.resize(out.len() + pad_len, 0);
                out
            }
            Self::Pong { tx_id, src } => {
                let mut out = Vec::with_capacity(2 + TX_ID_LEN + ADDR_LEN);
                out.push(TYPE_PONG);
                out.push(PROTOCOL_VERSION);
                out.extend_from_slice(tx_id);
                append_addr(&mut out, *src);
                out
            }
            Self::CallMeMaybe { my_numbers } => {
                let mut out = Vec::with_capacity(2 + my_numbers.len() * ADDR_LEN);
                out.push(TYPE_CALL_ME_MAYBE);
                out.push(PROTOCOL_VERSION);
                for addr in my_numbers {
                    append_addr(&mut out, *addr);
                }
                out
            }
        }
    }

    /// Parses a cleartext disco payload produced by [`Self::to_plaintext`].
    ///
    /// # Errors
    ///
    /// Returns [`DiscoError`] if the message type, version, or length is invalid.
    pub fn from_plaintext(bytes: &[u8]) -> Result<Self, DiscoError> {
        if bytes.len() < 2 {
            return Err(DiscoError::MalformedPayload);
        }
        let msg_type = bytes[0];
        let version = bytes[1];
        if version != PROTOCOL_VERSION {
            return Err(DiscoError::UnsupportedType { msg_type, version });
        }
        let body = &bytes[2..];
        match msg_type {
            TYPE_PING => {
                if body.len() < TX_ID_LEN + 32 {
                    return Err(DiscoError::MalformedPayload);
                }
                let mut tx_id = [0u8; TX_ID_LEN];
                tx_id.copy_from_slice(&body[..TX_ID_LEN]);
                let mut node_key = [0u8; 32];
                node_key.copy_from_slice(&body[TX_ID_LEN..TX_ID_LEN + 32]);
                let padding = u16::try_from(body.len() - (TX_ID_LEN + 32))
                    .map_err(|_| DiscoError::MalformedPayload)?;
                Ok(Self::Ping {
                    tx_id,
                    node_key,
                    padding,
                })
            }
            TYPE_PONG => {
                if body.len() != TX_ID_LEN + ADDR_LEN {
                    return Err(DiscoError::MalformedPayload);
                }
                let mut tx_id = [0u8; TX_ID_LEN];
                tx_id.copy_from_slice(&body[..TX_ID_LEN]);
                let src = parse_addr(&body[TX_ID_LEN..])?;
                Ok(Self::Pong { tx_id, src })
            }
            TYPE_CALL_ME_MAYBE => {
                let (addrs, rem) = body.as_chunks::<ADDR_LEN>();
                if !rem.is_empty() {
                    return Err(DiscoError::MalformedPayload);
                }
                let mut my_numbers = Vec::with_capacity(addrs.len());
                for chunk in addrs {
                    my_numbers.push(parse_addr(chunk)?);
                }
                Ok(Self::CallMeMaybe { my_numbers })
            }
            other => Err(DiscoError::UnsupportedType {
                msg_type: other,
                version,
            }),
        }
    }

    /// Encrypts and seals this disco message from `sender_secret` to `recipient_public`.
    ///
    /// Wire layout: `6B MAGIC + 32B sender_public + 12B nonce + ChaCha20Poly1305(payload)`.
    ///
    /// # Errors
    ///
    /// Returns [`DiscoError::CryptoFailed`] if the recipient public key is a low-order point.
    pub fn seal(
        &self,
        sender_secret: &StaticSecret,
        recipient_public: &[u8; 32],
    ) -> Result<Vec<u8>, DiscoError> {
        let sender_public = X25519Public::from(sender_secret).to_bytes();
        let sym_key = derive_disco_key(sender_secret, recipient_public)?;
        let unbound =
            UnboundKey::new(&CHACHA20_POLY1305, &sym_key).map_err(|_| DiscoError::CryptoFailed)?;
        let key = LessSafeKey::new(unbound);

        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);

        let mut header = Vec::with_capacity(HEADER_LEN);
        header.extend_from_slice(&MAGIC);
        header.extend_from_slice(&sender_public);
        header.extend_from_slice(&nonce_bytes);

        let mut ciphertext = self.to_plaintext();
        key.seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce_bytes),
            Aad::from(&header),
            &mut ciphertext,
        )
        .map_err(|_| DiscoError::CryptoFailed)?;

        let mut packet = Vec::with_capacity(HEADER_LEN + ciphertext.len());
        packet.extend_from_slice(&header);
        packet.extend_from_slice(&ciphertext);
        Ok(packet)
    }

    /// Returns `true` if `datagram` starts with the 6-byte disco [`MAGIC`] prefix.
    #[must_use]
    pub fn looks_like_disco(datagram: &[u8]) -> bool {
        datagram.len() >= HEADER_LEN + TAG_LEN && datagram[..MAGIC.len()] == MAGIC
    }

    /// Decrypts and authenticates a sealed disco packet using `recipient_secret`.
    ///
    /// Returns the sender's 32-byte X25519 public key and the decoded [`DiscoMessage`].
    ///
    /// # Errors
    ///
    /// Returns [`DiscoError`] if the header, AEAD tag, or inner payload is invalid.
    pub fn open(
        datagram: &[u8],
        recipient_secret: &StaticSecret,
    ) -> Result<([u8; 32], Self), DiscoError> {
        if !Self::looks_like_disco(datagram) {
            return Err(DiscoError::InvalidHeader);
        }
        let header = &datagram[..HEADER_LEN];
        let mut sender_public = [0u8; 32];
        sender_public.copy_from_slice(&datagram[MAGIC.len()..MAGIC.len() + 32]);
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes.copy_from_slice(&datagram[MAGIC.len() + 32..HEADER_LEN]);

        let sym_key = derive_disco_key(recipient_secret, &sender_public)?;
        let unbound =
            UnboundKey::new(&CHACHA20_POLY1305, &sym_key).map_err(|_| DiscoError::CryptoFailed)?;
        let key = LessSafeKey::new(unbound);

        let mut buf = datagram[HEADER_LEN..].to_vec();
        let plaintext = key
            .open_in_place(
                Nonce::assume_unique_for_key(nonce_bytes),
                Aad::from(header),
                &mut buf,
            )
            .map_err(|_| DiscoError::CryptoFailed)?;
        let msg = Self::from_plaintext(plaintext)?;
        Ok((sender_public, msg))
    }
}

fn derive_disco_key(
    local_secret: &StaticSecret,
    peer_public: &[u8; 32],
) -> Result<[u8; 32], DiscoError> {
    let pub_key = X25519Public::from(*peer_public);
    let shared = local_secret.diffie_hellman(&pub_key);
    if shared.as_bytes().iter().all(|&b| b == 0) {
        return Err(DiscoError::CryptoFailed);
    }
    let digest = Sha256::new()
        .chain_update(b"omegadesk-disco-v1:")
        .chain_update(shared.as_bytes())
        .finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&digest);
    Ok(key)
}

fn append_addr(out: &mut Vec<u8>, addr: SocketAddr) {
    let ipv6 = match addr.ip() {
        IpAddr::V4(v4) => v4.to_ipv6_mapped(),
        IpAddr::V6(v6) => v6,
    };
    out.extend_from_slice(&ipv6.octets());
    out.extend_from_slice(&addr.port().to_le_bytes());
}

fn parse_addr(bytes: &[u8]) -> Result<SocketAddr, DiscoError> {
    if bytes.len() != ADDR_LEN {
        return Err(DiscoError::MalformedPayload);
    }
    let mut octets = [0u8; 16];
    octets.copy_from_slice(&bytes[..16]);
    let v6 = Ipv6Addr::from(octets);
    let ip = v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4);
    let port = u16::from_le_bytes([bytes[16], bytes[17]]);
    Ok(SocketAddr::new(ip, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disco_ping_pong_and_call_me_maybe_round_trip() {
        let alice = StaticSecret::random_from_rng(OsRng);
        let bob = StaticSecret::random_from_rng(OsRng);
        let alice_pub = X25519Public::from(&alice).to_bytes();
        let bob_pub = X25519Public::from(&bob).to_bytes();

        let ping = DiscoMessage::Ping {
            tx_id: [7u8; TX_ID_LEN],
            node_key: alice_pub,
            padding: 16,
        };
        let sealed = ping.seal(&alice, &bob_pub).unwrap();
        assert!(DiscoMessage::looks_like_disco(&sealed));
        let (sender, opened) = DiscoMessage::open(&sealed, &bob).unwrap();
        assert_eq!(sender, alice_pub);
        assert_eq!(opened, ping);

        let pong = DiscoMessage::Pong {
            tx_id: [7u8; TX_ID_LEN],
            src: "203.0.113.42:51820".parse().unwrap(),
        };
        let sealed_pong = pong.seal(&bob, &alice_pub).unwrap();
        let (_, opened_pong) = DiscoMessage::open(&sealed_pong, &alice).unwrap();
        assert_eq!(opened_pong, pong);

        let cmm = DiscoMessage::CallMeMaybe {
            my_numbers: vec![
                "192.168.1.10:51820".parse().unwrap(),
                "[2001:db8::1]:51820".parse().unwrap(),
            ],
        };
        let sealed_cmm = cmm.seal(&alice, &bob_pub).unwrap();
        let (_, opened_cmm) = DiscoMessage::open(&sealed_cmm, &bob).unwrap();
        assert_eq!(opened_cmm, cmm);
    }
}
