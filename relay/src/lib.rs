//! Stateless DERP-style packet relay with single-use HMAC tickets (`omegadesk-relay`).
//!
//! Combines two reference architectures:
//! - **Tailscale DERP** (`tailscale/derp/derp.go`, `derp_client.go`, BSD-3-Clause):
//!   8-byte `DERP🔑` server key greeting, 5-byte frame header
//!   (`1B FrameType + 4B BE length`), `MaxPacketSize = 64 KiB`, routing packets
//!   strictly by 32-byte X25519 public key (`FrameSendPacket` -> `FrameRecvPacket`),
//!   `FramePeerGone` notifications, and a login frame whose body is **sealed by
//!   the client's private key to the relay's public key** (`sendClientKey` boxes
//!   `ClientInfo` with `privateKey.SealTo(serverKey, ...)`), so presenting a
//!   public key proves possession of its private half.
//! - **Aspia relay key pool** (`dchapyshev/aspia/source/relay/shared_key_pool.h`,
//!   GPL-3.0-or-later): single-use tickets issued by the coordinator and verified
//!   statelessly via HMAC-SHA256 + a bounded replay cache (`TicketValidator`).
//!
//! Improvements over the references: every ticket names the relay it is valid
//! for (`relay_exchange_key`), so a ticket redeemed on one relay of a fleet
//! cannot be replayed on another, and client registrations carry a generation
//! so a late disconnect of an old connection never evicts its replacement.

pub mod service;

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use omegadesk_identity::{DeviceIdentity, DevicePublic};
use rand_core::{OsRng, RngCore};
use ring::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey};
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};

/// Eight-byte magic header sent in `FrameServerKey` (`"DERP🔑"`), matching
/// `derp.Magic` in `tailscale/derp/derp.go`.
pub const MAGIC: [u8; 8] = [0x44, 0x45, 0x52, 0x50, 0xf0, 0x9f, 0x94, 0x91];

/// Relay protocol version (`3`: sealed `ClientInfo` login with relay-bound tickets).
pub const PROTOCOL_VERSION: u8 = 3;

/// Maximum packet payload size forwarded over the relay (64 KiB), matching
/// `derp.MaxPacketSize` in `tailscale/derp/derp.go`.
pub const MAX_PACKET_SIZE: usize = 64 << 10;

/// Largest frame body the relay accepts on the wire (`32B key + MAX_PACKET_SIZE`
/// plus slack for the login frame). Readers must check the declared length
/// against this limit **before** allocating.
pub const MAX_FRAME_BODY_LEN: usize = MAX_PACKET_SIZE + 256;

/// Frame header length (`1B frame_type + 4B big-endian length`).
pub const FRAME_HEADER_LEN: usize = 5;

/// Default keep-alive interval (60 seconds), matching `derp.KeepAlive`.
pub const KEEP_ALIVE: Duration = Duration::from_secs(60);

/// Serialized byte length of a [`RelayTicket`]:
/// `16B ticket_id + 32B client key + 32B relay key + 8B expiry + 32B HMAC-SHA256 = 120 bytes`.
pub const TICKET_WIRE_LEN: usize = 16 + 32 + 32 + 8 + 32;

/// Nonce length of the sealed login box.
pub const LOGIN_NONCE_LEN: usize = 12;

/// Length of the random challenge the relay puts in its greeting; the login
/// box binds to it, so a sealed login captured on one connection cannot be
/// replayed on another.
pub const LOGIN_CHALLENGE_LEN: usize = 16;
const TAG_LEN: usize = 16;
/// Sealed login body: `32B client key + 12B nonce + (120B ticket + 1B version + 16B tag)`.
pub const CLIENT_INFO_WIRE_LEN: usize = 32 + LOGIN_NONCE_LEN + TICKET_WIRE_LEN + 1 + TAG_LEN;

const FRAME_SERVER_KEY: u8 = 0x01;
const FRAME_CLIENT_INFO: u8 = 0x02;
const FRAME_SERVER_INFO: u8 = 0x03;
const FRAME_SEND_PACKET: u8 = 0x04;
const FRAME_RECV_PACKET: u8 = 0x05;
const FRAME_KEEP_ALIVE: u8 = 0x06;
const FRAME_NOTE_PREFERRED: u8 = 0x07;
const FRAME_PEER_GONE: u8 = 0x08;
const FRAME_PING: u8 = 0x12;
const FRAME_PONG: u8 = 0x13;

/// Reason code carried inside [`RelayFrame::PeerGone`], matching Tailscale DERP's
/// `PeerGoneReasonType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PeerGoneReason {
    /// Peer disconnected from this relay server.
    Disconnected = 0x00,
    /// Target peer is not connected to this relay node.
    NotHere = 0x01,
}

impl PeerGoneReason {
    const fn from_byte(b: u8) -> Self {
        match b {
            0x00 => Self::Disconnected,
            _ => Self::NotHere,
        }
    }
}

/// Wire frames exchanged between a client and an `omegadesk-relay` server,
/// modeled after `tailscale/derp/derp.go`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayFrame {
    /// `0x01`: Server greeting carrying [`MAGIC`], the relay's 32-byte X25519 key
    /// and a fresh per-connection challenge the login must be bound to.
    ServerKey {
        /// Relay node's 32-byte X25519 public key.
        server_public_key: [u8; 32],
        /// Random per-connection challenge (see [`seal_client_login`]).
        challenge: [u8; LOGIN_CHALLENGE_LEN],
    },
    /// `0x02`: Client login: the client's 32-byte X25519 key followed by a box
    /// sealed from the client's private key to the relay's public key, holding
    /// the single-use [`RelayTicket`] (see [`seal_client_login`]).
    ClientInfo {
        /// Client's 32-byte X25519 public key.
        client_public_key: [u8; 32],
        /// `12B nonce + ChaCha20-Poly1305(ticket || version)`.
        sealed: Vec<u8>,
    },
    /// `0x03`: Server acknowledgement of client login (`PROTOCOL_VERSION`).
    ServerInfo {
        /// Negotiated relay protocol version.
        protocol_version: u8,
    },
    /// `0x04`: Client requests forwarding `packet` to `dst_key`.
    SendPacket {
        /// Recipient's 32-byte X25519 public key.
        dst_key: [u8; 32],
        /// Encrypted tunnel/disco/QUIC packet bytes.
        packet: Vec<u8>,
    },
    /// `0x05`: Server delivers `packet` from `src_key` to the connected recipient.
    RecvPacket {
        /// Sender's 32-byte X25519 public key.
        src_key: [u8; 32],
        /// Encrypted tunnel/disco/QUIC packet bytes.
        packet: Vec<u8>,
    },
    /// `0x06`: Periodic server heartbeat frame.
    KeepAlive,
    /// `0x07`: Client indicates whether this relay is its preferred home region.
    NotePreferred {
        /// `true` if this relay is the client's home node.
        preferred: bool,
    },
    /// `0x08`: Server notifies client that `peer_key` is no longer reachable here.
    PeerGone {
        /// 32-byte X25519 public key of the peer that disconnected or is absent.
        peer_key: [u8; 32],
        /// Reason the peer is unreachable.
        reason: PeerGoneReason,
    },
    /// `0x12`: 8-byte latency probe echoed back in [`RelayFrame::Pong`].
    Ping([u8; 8]),
    /// `0x13`: 8-byte response to [`RelayFrame::Ping`].
    Pong([u8; 8]),
}

/// Errors returned by relay frame parsing, ticket verification, or packet routing.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RelayError {
    /// Frame is shorter than [`FRAME_HEADER_LEN`] or truncated.
    #[error("truncated relay frame")]
    TruncatedFrame,
    /// Frame type byte is unknown.
    #[error("unknown relay frame type: {0:#04x}")]
    UnknownFrameType(u8),
    /// Packet payload exceeds [`MAX_PACKET_SIZE`].
    #[error("relay packet size {0} exceeds 64 KiB limit")]
    PacketTooLarge(usize),
    /// Server key frame does not start with [`MAGIC`].
    #[error("invalid DERP server key magic")]
    InvalidMagic,
    /// Frame body length is invalid for its type.
    #[error("malformed relay frame body")]
    MalformedFrame,
    /// Single-use relay ticket failed HMAC verification.
    #[error("invalid relay ticket signature")]
    InvalidTicketSignature,
    /// Single-use relay ticket has expired.
    #[error("relay ticket expired at {expired_at}, current time is {now}")]
    TicketExpired {
        /// Ticket expiration UNIX timestamp (seconds).
        expired_at: u64,
        /// Current UNIX timestamp (seconds).
        now: u64,
    },
    /// Single-use relay ticket was already redeemed (replay attempt).
    #[error("relay ticket already used")]
    TicketReplayed,
    /// Ticket was issued for a different client X25519 public key.
    #[error("relay ticket public key mismatch")]
    TicketKeyMismatch,
    /// Ticket was issued for a different relay node.
    #[error("relay ticket was issued for another relay")]
    TicketWrongRelay,
    /// The login box did not authenticate: the client does not hold the
    /// private key of the public key it presented, or the frame was tampered.
    #[error("relay login proof failed")]
    LoginProofFailed,
    /// The client speaks an unsupported protocol version.
    #[error("unsupported relay protocol version {0}")]
    UnsupportedVersion(u8),
}

impl RelayFrame {
    /// Encodes this frame into its wire format (`1B type + 4B BE len + body`).
    ///
    /// # Errors
    ///
    /// Returns [`RelayError::PacketTooLarge`] if a packet payload exceeds [`MAX_PACKET_SIZE`].
    pub fn encode(&self) -> Result<Vec<u8>, RelayError> {
        let (frame_type, body) = match self {
            Self::ServerKey {
                server_public_key,
                challenge,
            } => {
                let mut b = Vec::with_capacity(MAGIC.len() + 32 + LOGIN_CHALLENGE_LEN);
                b.extend_from_slice(&MAGIC);
                b.extend_from_slice(server_public_key);
                b.extend_from_slice(challenge);
                (FRAME_SERVER_KEY, b)
            }
            Self::ClientInfo {
                client_public_key,
                sealed,
            } => {
                let mut b = Vec::with_capacity(32 + sealed.len());
                b.extend_from_slice(client_public_key);
                b.extend_from_slice(sealed);
                (FRAME_CLIENT_INFO, b)
            }
            Self::ServerInfo { protocol_version } => (FRAME_SERVER_INFO, vec![*protocol_version]),
            Self::SendPacket { dst_key, packet } => {
                if packet.len() > MAX_PACKET_SIZE {
                    return Err(RelayError::PacketTooLarge(packet.len()));
                }
                let mut b = Vec::with_capacity(32 + packet.len());
                b.extend_from_slice(dst_key);
                b.extend_from_slice(packet);
                (FRAME_SEND_PACKET, b)
            }
            Self::RecvPacket { src_key, packet } => {
                if packet.len() > MAX_PACKET_SIZE {
                    return Err(RelayError::PacketTooLarge(packet.len()));
                }
                let mut b = Vec::with_capacity(32 + packet.len());
                b.extend_from_slice(src_key);
                b.extend_from_slice(packet);
                (FRAME_RECV_PACKET, b)
            }
            Self::KeepAlive => (FRAME_KEEP_ALIVE, Vec::new()),
            Self::NotePreferred { preferred } => (FRAME_NOTE_PREFERRED, vec![u8::from(*preferred)]),
            Self::PeerGone { peer_key, reason } => {
                let mut b = Vec::with_capacity(33);
                b.extend_from_slice(peer_key);
                b.push(*reason as u8);
                (FRAME_PEER_GONE, b)
            }
            Self::Ping(data) => (FRAME_PING, data.to_vec()),
            Self::Pong(data) => (FRAME_PONG, data.to_vec()),
        };

        let len_u32 =
            u32::try_from(body.len()).map_err(|_| RelayError::PacketTooLarge(body.len()))?;
        let mut out = Vec::with_capacity(FRAME_HEADER_LEN + body.len());
        out.push(frame_type);
        out.extend_from_slice(&len_u32.to_be_bytes());
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Parses a 5-byte frame header, returning `(frame_type, body_len)` after
    /// checking `body_len <= MAX_FRAME_BODY_LEN`, so callers can reject a
    /// hostile length before allocating or reading the body.
    ///
    /// # Errors
    ///
    /// Returns [`RelayError::PacketTooLarge`] when the declared body exceeds the limit.
    pub fn parse_header(header: &[u8; FRAME_HEADER_LEN]) -> Result<(u8, usize), RelayError> {
        let body_len = usize::try_from(u32::from_be_bytes([
            header[1], header[2], header[3], header[4],
        ]))
        .map_err(|_| RelayError::MalformedFrame)?;
        if body_len > MAX_FRAME_BODY_LEN {
            return Err(RelayError::PacketTooLarge(body_len));
        }
        Ok((header[0], body_len))
    }

    /// Decodes a wire frame produced by [`Self::encode`].
    ///
    /// # Errors
    ///
    /// Returns [`RelayError`] if the header, magic, or body is malformed.
    pub fn decode(bytes: &[u8]) -> Result<Self, RelayError> {
        if bytes.len() < FRAME_HEADER_LEN {
            return Err(RelayError::TruncatedFrame);
        }
        let mut header = [0u8; FRAME_HEADER_LEN];
        header.copy_from_slice(&bytes[..FRAME_HEADER_LEN]);
        let (frame_type, body_len) = Self::parse_header(&header)?;
        let body = &bytes[FRAME_HEADER_LEN..];
        if body.len() != body_len {
            return Err(RelayError::TruncatedFrame);
        }
        Self::decode_body(frame_type, body)
    }

    /// Decodes a frame whose header was already parsed with [`Self::parse_header`].
    ///
    /// # Errors
    ///
    /// Returns [`RelayError`] if the body is malformed for `frame_type`.
    pub fn decode_body(frame_type: u8, body: &[u8]) -> Result<Self, RelayError> {
        match frame_type {
            FRAME_SERVER_KEY => {
                if body.len() < MAGIC.len() + 32 + LOGIN_CHALLENGE_LEN {
                    return Err(RelayError::MalformedFrame);
                }
                if body[..MAGIC.len()] != MAGIC {
                    return Err(RelayError::InvalidMagic);
                }
                let mut server_public_key = [0u8; 32];
                server_public_key.copy_from_slice(&body[MAGIC.len()..MAGIC.len() + 32]);
                let mut challenge = [0u8; LOGIN_CHALLENGE_LEN];
                challenge.copy_from_slice(
                    &body[MAGIC.len() + 32..MAGIC.len() + 32 + LOGIN_CHALLENGE_LEN],
                );
                Ok(Self::ServerKey {
                    server_public_key,
                    challenge,
                })
            }
            FRAME_CLIENT_INFO => {
                if body.len() != CLIENT_INFO_WIRE_LEN {
                    return Err(RelayError::MalformedFrame);
                }
                let mut client_public_key = [0u8; 32];
                client_public_key.copy_from_slice(&body[..32]);
                Ok(Self::ClientInfo {
                    client_public_key,
                    sealed: body[32..].to_vec(),
                })
            }
            FRAME_SERVER_INFO => {
                let Some(&protocol_version) = body.first() else {
                    return Err(RelayError::MalformedFrame);
                };
                Ok(Self::ServerInfo { protocol_version })
            }
            FRAME_SEND_PACKET => {
                let (dst_key, packet) = decode_keyed_packet(body)?;
                Ok(Self::SendPacket { dst_key, packet })
            }
            FRAME_RECV_PACKET => {
                let (src_key, packet) = decode_keyed_packet(body)?;
                Ok(Self::RecvPacket { src_key, packet })
            }
            FRAME_KEEP_ALIVE => Ok(Self::KeepAlive),
            FRAME_NOTE_PREFERRED => {
                if body.len() != 1 {
                    return Err(RelayError::MalformedFrame);
                }
                Ok(Self::NotePreferred {
                    preferred: body[0] != 0,
                })
            }
            FRAME_PEER_GONE => {
                if body.len() < 33 {
                    return Err(RelayError::MalformedFrame);
                }
                let mut peer_key = [0u8; 32];
                peer_key.copy_from_slice(&body[..32]);
                Ok(Self::PeerGone {
                    peer_key,
                    reason: PeerGoneReason::from_byte(body[32]),
                })
            }
            FRAME_PING => Ok(Self::Ping(decode_8_bytes(body)?)),
            FRAME_PONG => Ok(Self::Pong(decode_8_bytes(body)?)),
            other => Err(RelayError::UnknownFrameType(other)),
        }
    }
}

fn decode_keyed_packet(body: &[u8]) -> Result<([u8; 32], Vec<u8>), RelayError> {
    if body.len() < 32 {
        return Err(RelayError::MalformedFrame);
    }
    let packet_len = body.len() - 32;
    if packet_len > MAX_PACKET_SIZE {
        return Err(RelayError::PacketTooLarge(packet_len));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&body[..32]);
    Ok((key, body[32..].to_vec()))
}

fn decode_8_bytes(body: &[u8]) -> Result<[u8; 8], RelayError> {
    if body.len() != 8 {
        return Err(RelayError::MalformedFrame);
    }
    let mut data = [0u8; 8];
    data.copy_from_slice(body);
    Ok(data)
}

/// Single-use HMAC-SHA256 authenticated relay ticket issued by the coordinator,
/// modeled after Aspia's `SharedKeyPool` / `SessionKey` (`source/relay/shared_key_pool.h`)
/// and bound to one relay node (`relay_exchange_key`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayTicket {
    /// Unique 128-bit ticket identifier used to prevent replay.
    pub ticket_id: [u8; 16],
    /// Client's 32-byte X25519 public key authorized to bind this session.
    pub client_exchange_key: [u8; 32],
    /// X25519 public key of the relay this ticket may be redeemed on.
    pub relay_exchange_key: [u8; 32],
    /// Expiration timestamp (UNIX seconds).
    pub expires_at_unix_secs: u64,
    /// 32-byte HMAC-SHA256 tag over all fields above.
    pub signature: [u8; 32],
}

impl RelayTicket {
    /// Serializes the ticket into its fixed 120-byte wire representation.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; TICKET_WIRE_LEN] {
        let mut out = [0u8; TICKET_WIRE_LEN];
        out[..16].copy_from_slice(&self.ticket_id);
        out[16..48].copy_from_slice(&self.client_exchange_key);
        out[48..80].copy_from_slice(&self.relay_exchange_key);
        out[80..88].copy_from_slice(&self.expires_at_unix_secs.to_be_bytes());
        out[88..120].copy_from_slice(&self.signature);
        out
    }

    /// Parses a 120-byte serialized [`RelayTicket`].
    ///
    /// # Errors
    ///
    /// Returns [`RelayError::MalformedFrame`] if `bytes.len() != 120`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, RelayError> {
        if bytes.len() != TICKET_WIRE_LEN {
            return Err(RelayError::MalformedFrame);
        }
        let mut ticket_id = [0u8; 16];
        ticket_id.copy_from_slice(&bytes[..16]);
        let mut client_exchange_key = [0u8; 32];
        client_exchange_key.copy_from_slice(&bytes[16..48]);
        let mut relay_exchange_key = [0u8; 32];
        relay_exchange_key.copy_from_slice(&bytes[48..80]);
        let mut exp_bytes = [0u8; 8];
        exp_bytes.copy_from_slice(&bytes[80..88]);
        let mut signature = [0u8; 32];
        signature.copy_from_slice(&bytes[88..120]);
        Ok(Self {
            ticket_id,
            client_exchange_key,
            relay_exchange_key,
            expires_at_unix_secs: u64::from_be_bytes(exp_bytes),
            signature,
        })
    }

    fn mac_input(&self) -> [u8; 88] {
        let mut msg = [0u8; 88];
        msg[..16].copy_from_slice(&self.ticket_id);
        msg[16..48].copy_from_slice(&self.client_exchange_key);
        msg[48..80].copy_from_slice(&self.relay_exchange_key);
        msg[80..88].copy_from_slice(&self.expires_at_unix_secs.to_be_bytes());
        msg
    }
}

/// Issues HMAC-SHA256 signed single-use [`RelayTicket`]s on the coordinator.
pub struct TicketIssuer {
    shared_secret: [u8; 32],
}

impl TicketIssuer {
    /// Creates a new [`TicketIssuer`] sharing `shared_secret` with the relay fleet.
    #[must_use]
    pub const fn new(shared_secret: [u8; 32]) -> Self {
        Self { shared_secret }
    }

    /// Issues a signed single-use [`RelayTicket`] for `client_exchange_key`,
    /// redeemable only on the relay whose X25519 key is `relay_exchange_key`.
    #[must_use]
    pub fn issue(
        &self,
        ticket_id: [u8; 16],
        client_exchange_key: [u8; 32],
        relay_exchange_key: [u8; 32],
        expires_at_unix_secs: u64,
    ) -> RelayTicket {
        let mut ticket = RelayTicket {
            ticket_id,
            client_exchange_key,
            relay_exchange_key,
            expires_at_unix_secs,
            signature: [0u8; 32],
        };
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &self.shared_secret);
        let tag = ring::hmac::sign(&key, &ticket.mac_input());
        ticket.signature.copy_from_slice(&tag.as_ref()[..32]);
        ticket
    }

    /// Issues a ticket with a random identifier.
    #[must_use]
    pub fn issue_random(
        &self,
        client_exchange_key: [u8; 32],
        relay_exchange_key: [u8; 32],
        expires_at_unix_secs: u64,
    ) -> RelayTicket {
        let mut ticket_id = [0u8; 16];
        OsRng.fill_bytes(&mut ticket_id);
        self.issue(
            ticket_id,
            client_exchange_key,
            relay_exchange_key,
            expires_at_unix_secs,
        )
    }
}

/// Validates single-use [`RelayTicket`]s on the relay without database access,
/// modeled after Aspia's `SharedKeyPool` (`source/relay/shared_key_pool.h`).
pub struct TicketValidator {
    shared_secret: [u8; 32],
    relay_exchange_key: [u8; 32],
    redeemed: HashMap<[u8; 16], u64>,
}

impl TicketValidator {
    /// Creates a validator for the relay whose X25519 key is `relay_exchange_key`.
    #[must_use]
    pub fn new(shared_secret: [u8; 32], relay_exchange_key: [u8; 32]) -> Self {
        Self {
            shared_secret,
            relay_exchange_key,
            redeemed: HashMap::new(),
        }
    }

    /// Verifies and consumes a single-use `ticket` for `claimed_client_key` at
    /// `now_unix_secs`.
    ///
    /// # Errors
    ///
    /// Returns [`RelayError`] if the key or relay mismatches, the ticket is
    /// expired, the HMAC tag is invalid, or the ticket was already redeemed.
    pub fn redeem(
        &mut self,
        ticket: &RelayTicket,
        claimed_client_key: &[u8; 32],
        now_unix_secs: u64,
    ) -> Result<(), RelayError> {
        // Evict expired ticket IDs so memory remains bounded.
        self.redeemed.retain(|_, &mut exp| exp > now_unix_secs);

        if &ticket.client_exchange_key != claimed_client_key {
            return Err(RelayError::TicketKeyMismatch);
        }
        if ticket.relay_exchange_key != self.relay_exchange_key {
            return Err(RelayError::TicketWrongRelay);
        }
        if now_unix_secs >= ticket.expires_at_unix_secs {
            return Err(RelayError::TicketExpired {
                expired_at: ticket.expires_at_unix_secs,
                now: now_unix_secs,
            });
        }
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &self.shared_secret);
        ring::hmac::verify(&key, &ticket.mac_input(), &ticket.signature)
            .map_err(|_| RelayError::InvalidTicketSignature)?;
        if self.redeemed.contains_key(&ticket.ticket_id) {
            return Err(RelayError::TicketReplayed);
        }
        self.redeemed
            .insert(ticket.ticket_id, ticket.expires_at_unix_secs);
        Ok(())
    }
}

fn login_key(secret: &StaticSecret, peer_public: &[u8; 32]) -> Result<LessSafeKey, RelayError> {
    let shared = secret.diffie_hellman(&X25519Public::from(*peer_public));
    if shared.as_bytes().iter().all(|&b| b == 0) {
        return Err(RelayError::LoginProofFailed);
    }
    let digest = Sha256::new()
        .chain_update(b"omegadesk-relay-login-v1:")
        .chain_update(shared.as_bytes())
        .finalize();
    let unbound =
        UnboundKey::new(&CHACHA20_POLY1305, &digest).map_err(|_| RelayError::LoginProofFailed)?;
    Ok(LessSafeKey::new(unbound))
}

/// Seals the login body for [`RelayFrame::ClientInfo`]: `12B nonce ||
/// ChaCha20-Poly1305_{DH(client, relay)}(ticket || PROTOCOL_VERSION)`, with the
/// client key, the relay key **and the relay's per-connection challenge** as
/// associated data. Only the holder of the client's private key can produce
/// it (DERP `sendClientKey` model), and it is valid on this connection only.
///
/// # Errors
///
/// Returns [`RelayError::LoginProofFailed`] if the relay key is a low-order point.
pub fn seal_client_login(
    client: &DeviceIdentity,
    relay_public_key: &[u8; 32],
    challenge: &[u8; LOGIN_CHALLENGE_LEN],
    ticket: &RelayTicket,
) -> Result<Vec<u8>, RelayError> {
    let client_public = client.public().exchange_key_bytes();
    let key = login_key(client.exchange_secret(), relay_public_key)?;
    let mut nonce = [0u8; LOGIN_NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let mut aad = Vec::with_capacity(64 + LOGIN_CHALLENGE_LEN);
    aad.extend_from_slice(&client_public);
    aad.extend_from_slice(relay_public_key);
    aad.extend_from_slice(challenge);
    let mut body = Vec::with_capacity(TICKET_WIRE_LEN + 1 + TAG_LEN);
    body.extend_from_slice(&ticket.to_bytes());
    body.push(PROTOCOL_VERSION);
    key.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(nonce),
        Aad::from(&aad),
        &mut body,
    )
    .map_err(|_| RelayError::LoginProofFailed)?;
    let mut out = Vec::with_capacity(LOGIN_NONCE_LEN + body.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&body);
    Ok(out)
}

/// Opens a [`RelayFrame::ClientInfo`] login on the relay, proving that the
/// presenter holds the private key of `client_public_key` and answered this
/// connection's `challenge`.
///
/// # Errors
///
/// Returns [`RelayError::LoginProofFailed`] if the box does not authenticate,
/// or [`RelayError::UnsupportedVersion`] for a foreign protocol version.
pub fn open_client_login(
    relay: &DeviceIdentity,
    client_public_key: &[u8; 32],
    challenge: &[u8; LOGIN_CHALLENGE_LEN],
    sealed: &[u8],
) -> Result<RelayTicket, RelayError> {
    if sealed.len() != CLIENT_INFO_WIRE_LEN - 32 {
        return Err(RelayError::MalformedFrame);
    }
    let key = login_key(relay.exchange_secret(), client_public_key)?;
    let mut nonce = [0u8; LOGIN_NONCE_LEN];
    nonce.copy_from_slice(&sealed[..LOGIN_NONCE_LEN]);
    let mut aad = Vec::with_capacity(64 + LOGIN_CHALLENGE_LEN);
    aad.extend_from_slice(client_public_key);
    aad.extend_from_slice(&relay.public().exchange_key_bytes());
    aad.extend_from_slice(challenge);
    let mut buf = sealed[LOGIN_NONCE_LEN..].to_vec();
    let plain = key
        .open_in_place(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(&aad),
            &mut buf,
        )
        .map_err(|_| RelayError::LoginProofFailed)?;
    if plain.len() != TICKET_WIRE_LEN + 1 {
        return Err(RelayError::MalformedFrame);
    }
    let version = plain[TICKET_WIRE_LEN];
    if version != PROTOCOL_VERSION {
        return Err(RelayError::UnsupportedVersion(version));
    }
    RelayTicket::from_bytes(&plain[..TICKET_WIRE_LEN])
}

/// A client accepted by [`RelayRouter::register_client`].
pub struct RegisteredClient {
    /// Client's X25519 public key.
    pub key: [u8; 32],
    /// Connection generation; pass it to [`RelayRouter::unregister_client`].
    pub generation: u64,
    /// Frame to send back to the client (`ServerInfo`).
    pub server_info: RelayFrame,
    /// Frames the connection handler must write to the client.
    pub outbound: mpsc::Receiver<RelayFrame>,
    /// Sender for frames the handler itself wants delivered to the client
    /// (for example `Pong`); shares the queue with the router.
    pub outbound_tx: mpsc::Sender<RelayFrame>,
}

/// In-memory DERP packet router mapping 32-byte X25519 public keys to active client
/// frame channels and tracking peer-to-peer communication graphs for `FramePeerGone`
/// notifications (matching `tailscale/derp/derp_server.go`).
pub struct RelayRouter {
    identity: DeviceIdentity,
    validator: TicketValidator,
    next_generation: u64,
    clients: HashMap<[u8; 32], (u64, mpsc::Sender<RelayFrame>)>,
    /// Maps `sender_key -> set of recipient_keys` so when `sender_key` disconnects
    /// every peer it previously sent packets to receives `FramePeerGone`.
    sent_to: HashMap<[u8; 32], HashSet<[u8; 32]>>,
}

impl RelayRouter {
    /// Creates a new [`RelayRouter`] for the relay `identity` sharing
    /// `shared_ticket_secret` with the coordinator.
    #[must_use]
    pub fn new(identity: DeviceIdentity, shared_ticket_secret: [u8; 32]) -> Self {
        let relay_key = identity.public().exchange_key_bytes();
        Self {
            identity,
            validator: TicketValidator::new(shared_ticket_secret, relay_key),
            next_generation: 1,
            clients: HashMap::new(),
            sent_to: HashMap::new(),
        }
    }

    /// Public identity of this relay node.
    #[must_use]
    pub fn public(&self) -> DevicePublic {
        self.identity.public()
    }

    /// Returns a `FrameServerKey` greeting with a fresh challenge for a new
    /// connection; keep the challenge to verify that connection's login.
    #[must_use]
    pub fn server_key_frame(&self) -> (RelayFrame, [u8; LOGIN_CHALLENGE_LEN]) {
        let mut challenge = [0u8; LOGIN_CHALLENGE_LEN];
        OsRng.fill_bytes(&mut challenge);
        (
            RelayFrame::ServerKey {
                server_public_key: self.identity.public().exchange_key_bytes(),
                challenge,
            },
            challenge,
        )
    }

    /// Authenticates a client login (`ClientInfo` body) against the challenge
    /// sent in this connection's greeting and registers the client's outbound
    /// channel. A second live registration for the same key replaces the
    /// previous one; the old connection's later `unregister_client` call is
    /// ignored because its generation no longer matches.
    ///
    /// # Errors
    ///
    /// Returns [`RelayError`] if the login proof, ticket, or version is invalid.
    pub fn register_client(
        &mut self,
        client_public_key: [u8; 32],
        challenge: &[u8; LOGIN_CHALLENGE_LEN],
        sealed: &[u8],
        now_unix_secs: u64,
    ) -> Result<RegisteredClient, RelayError> {
        let ticket = open_client_login(&self.identity, &client_public_key, challenge, sealed)?;
        self.validator
            .redeem(&ticket, &client_public_key, now_unix_secs)?;
        let generation = self.next_generation;
        self.next_generation += 1;
        let (tx, rx) = mpsc::channel(256);
        self.clients
            .insert(client_public_key, (generation, tx.clone()));
        Ok(RegisteredClient {
            key: client_public_key,
            generation,
            server_info: RelayFrame::ServerInfo {
                protocol_version: PROTOCOL_VERSION,
            },
            outbound: rx,
            outbound_tx: tx,
        })
    }

    /// Routes an encrypted packet from `src_key` to `dst_key`.
    ///
    /// If `dst_key` is not connected to this relay, sends [`RelayFrame::PeerGone`]
    /// (`PeerGoneReason::NotHere`) back to `src_key`, matching Tailscale DERP.
    ///
    /// # Errors
    ///
    /// Returns [`RelayError::PacketTooLarge`] if `packet` exceeds [`MAX_PACKET_SIZE`].
    pub fn forward_packet(
        &mut self,
        src_key: [u8; 32],
        dst_key: [u8; 32],
        packet: Vec<u8>,
    ) -> Result<(), RelayError> {
        if packet.len() > MAX_PACKET_SIZE {
            return Err(RelayError::PacketTooLarge(packet.len()));
        }
        if let Some((_, dst_tx)) = self.clients.get(&dst_key) {
            self.sent_to.entry(src_key).or_default().insert(dst_key);
            let _ = dst_tx.try_send(RelayFrame::RecvPacket { src_key, packet });
        } else if let Some((_, src_tx)) = self.clients.get(&src_key) {
            let _ = src_tx.try_send(RelayFrame::PeerGone {
                peer_key: dst_key,
                reason: PeerGoneReason::NotHere,
            });
        }
        Ok(())
    }

    /// Removes the registration of `client_key` **only if** it still belongs to
    /// `generation`, then notifies all peers it previously communicated with via
    /// [`RelayFrame::PeerGone`] (`PeerGoneReason::Disconnected`).
    pub fn unregister_client(&mut self, client_key: &[u8; 32], generation: u64) {
        match self.clients.get(client_key) {
            Some((current, _)) if *current == generation => {}
            _ => return,
        }
        self.clients.remove(client_key);
        if let Some(recipients) = self.sent_to.remove(client_key) {
            for peer_key in recipients {
                if let Some((_, peer_tx)) = self.clients.get(&peer_key) {
                    let _ = peer_tx.try_send(RelayFrame::PeerGone {
                        peer_key: *client_key,
                        reason: PeerGoneReason::Disconnected,
                    });
                }
            }
        }
    }

    /// Number of currently connected clients on this relay.
    #[must_use]
    pub fn connected_clients(&self) -> usize {
        self.clients.len()
    }
}

/// Minimum RTT improvement in milliseconds required to switch away from an established
/// preferred ("home") relay region (`Tailscale` `net/netcheck/netcheck.go` hysteresis).
pub const DERP_HOME_STICKINESS_MS: u32 = 15;

/// Descriptor for a geographic relay region over HTTPS port 443 (`docs/plan.md` §2.2 line 40,
/// modeled after `Tailscale` `tailcfg.DERPRegion`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerpRegion {
    /// Numeric region identifier (e.g., `1` for `"gru"`).
    pub region_id: u16,
    /// Short IATA-style code (e.g., `"gru"`, `"iad"`, `"fra"`).
    pub region_code: String,
    /// Human-readable geographic name.
    pub region_name: String,
    /// HTTPS relay port (defaults to `443`).
    pub https_port: u16,
    /// Whether this region is marked for drain/avoidance unless no other region responds.
    pub avoid: bool,
}

/// Nearest-region selector with home-region hysteresis (`docs/plan.md` §2.2 line 40,
/// modeled after `Tailscale` `net/netcheck`).
#[derive(Debug, Clone, Default)]
pub struct DerpRegionSelector {
    regions: Vec<DerpRegion>,
    preferred_region: Option<u16>,
}

impl DerpRegionSelector {
    /// Creates a new [`DerpRegionSelector`] from the configured [`DerpRegion`] catalog.
    #[must_use]
    pub const fn new(regions: Vec<DerpRegion>) -> Self {
        Self {
            regions,
            preferred_region: None,
        }
    }

    /// Returns the currently selected preferred ("home") region ID, if any.
    #[must_use]
    pub const fn preferred_region_id(&self) -> Option<u16> {
        self.preferred_region
    }

    /// Selects the lowest-latency relay region from `measured_rtts_ms` (`region_id -> rtt_ms`),
    /// applying [`DERP_HOME_STICKINESS_MS`] hysteresis so a node does not flap between
    /// regions on minor latency jitter before emitting [`RelayFrame::NotePreferred`].
    ///
    /// Avoided regions are only used when no other region responded, and stickiness
    /// never keeps an avoided home once a non-avoided region is available.
    pub fn pick_nearest_region(&mut self, measured_rtts_ms: &HashMap<u16, u32>) -> Option<u16> {
        let measured = |r: &DerpRegion| {
            measured_rtts_ms
                .get(&r.region_id)
                .map(|&rtt| (r.region_id, rtt))
        };
        let preferred_pool_has_candidates = self
            .regions
            .iter()
            .filter(|r| !r.avoid)
            .any(|r| measured_rtts_ms.contains_key(&r.region_id));
        let best_candidate = if preferred_pool_has_candidates {
            self.regions
                .iter()
                .filter(|r| !r.avoid)
                .filter_map(measured)
                .min_by_key(|&(_, rtt)| rtt)
        } else {
            self.regions
                .iter()
                .filter_map(measured)
                .min_by_key(|&(_, rtt)| rtt)
        };
        let (candidate_id, candidate_rtt) = best_candidate?;

        if let Some(current_id) = self.preferred_region
            && current_id != candidate_id
        {
            let current_eligible = self
                .regions
                .iter()
                .any(|r| r.region_id == current_id && (!r.avoid || !preferred_pool_has_candidates));
            if current_eligible
                && let Some(&current_rtt) = measured_rtts_ms.get(&current_id)
                && current_rtt.saturating_sub(candidate_rtt) < DERP_HOME_STICKINESS_MS
            {
                return Some(current_id);
            }
        }

        self.preferred_region = Some(candidate_id);
        Some(candidate_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fleet() -> (DeviceIdentity, TicketIssuer, RelayRouter) {
        let secret = [0x42u8; 32];
        let relay_id = DeviceIdentity::generate();
        let issuer = TicketIssuer::new(secret);
        let relay_secret = relay_id.to_secret_bytes();
        let router = RelayRouter::new(
            DeviceIdentity::from_secret_bytes(&relay_secret).unwrap(),
            secret,
        );
        (relay_id, issuer, router)
    }

    const CHALLENGE: [u8; LOGIN_CHALLENGE_LEN] = [0xC7; LOGIN_CHALLENGE_LEN];

    fn login(
        client: &DeviceIdentity,
        relay: &DeviceIdentity,
        issuer: &TicketIssuer,
        ticket_id: [u8; 16],
        expires: u64,
    ) -> ([u8; 32], Vec<u8>) {
        let relay_key = relay.public().exchange_key_bytes();
        let ticket = issuer.issue(
            ticket_id,
            client.public().exchange_key_bytes(),
            relay_key,
            expires,
        );
        (
            client.public().exchange_key_bytes(),
            seal_client_login(client, &relay_key, &CHALLENGE, &ticket).unwrap(),
        )
    }

    #[test]
    fn single_use_ticket_prevents_replay_enforces_expiry_and_relay_binding() {
        let secret = [0x42u8; 32];
        let issuer = TicketIssuer::new(secret);
        let relay_key = [0x77u8; 32];
        let mut validator = TicketValidator::new(secret, relay_key);
        let client_key = [0x11u8; 32];

        let ticket = issuer.issue([0xAAu8; 16], client_key, relay_key, 1000);
        validator.redeem(&ticket, &client_key, 900).unwrap();
        assert_eq!(
            validator.redeem(&ticket, &client_key, 901),
            Err(RelayError::TicketReplayed)
        );
        let expired = issuer.issue([0xBBu8; 16], client_key, relay_key, 500);
        assert_eq!(
            validator.redeem(&expired, &client_key, 500),
            Err(RelayError::TicketExpired {
                expired_at: 500,
                now: 500
            })
        );
        // A ticket for another relay of the fleet is rejected here.
        let other_relay = issuer.issue([0xCCu8; 16], client_key, [0x78u8; 32], 1000);
        assert_eq!(
            validator.redeem(&other_relay, &client_key, 900),
            Err(RelayError::TicketWrongRelay)
        );
        // A forged tag is rejected.
        let mut forged = issuer.issue([0xDDu8; 16], client_key, relay_key, 1000);
        forged.signature[0] ^= 1;
        assert_eq!(
            validator.redeem(&forged, &client_key, 900),
            Err(RelayError::InvalidTicketSignature)
        );
        assert_eq!(RelayTicket::from_bytes(&ticket.to_bytes()).unwrap(), ticket);
    }

    #[test]
    fn login_requires_the_client_private_key() {
        let (relay_id, issuer, mut router) = fleet();
        let alice = DeviceIdentity::generate();
        let relay_key = relay_id.public().exchange_key_bytes();
        let ticket = issuer.issue(
            [1u8; 16],
            alice.public().exchange_key_bytes(),
            relay_key,
            2000,
        );

        // An eavesdropper who copied Alice's public key and ticket cannot log in.
        let mallory = DeviceIdentity::generate();
        let forged = seal_client_login(&mallory, &relay_key, &CHALLENGE, &ticket).unwrap();
        assert_eq!(
            router
                .register_client(
                    alice.public().exchange_key_bytes(),
                    &CHALLENGE,
                    &forged,
                    1000
                )
                .err(),
            Some(RelayError::LoginProofFailed)
        );
        // Alice herself can, but only on the connection whose challenge she answered:
        // the same sealed login replayed on another connection (other challenge) fails.
        let sealed = seal_client_login(&alice, &relay_key, &CHALLENGE, &ticket).unwrap();
        let other_challenge = [0x11u8; LOGIN_CHALLENGE_LEN];
        assert_eq!(
            router
                .register_client(
                    alice.public().exchange_key_bytes(),
                    &other_challenge,
                    &sealed,
                    1000
                )
                .err(),
            Some(RelayError::LoginProofFailed)
        );
        let frame = RelayFrame::ClientInfo {
            client_public_key: alice.public().exchange_key_bytes(),
            sealed: sealed.clone(),
        };
        let wire = frame.encode().unwrap();
        assert_eq!(RelayFrame::decode(&wire).unwrap(), frame);
        let (greeting, challenge) = router.server_key_frame();
        assert!(matches!(greeting, RelayFrame::ServerKey { challenge: c, .. } if c == challenge));
        let registered = router
            .register_client(
                alice.public().exchange_key_bytes(),
                &CHALLENGE,
                &sealed,
                1000,
            )
            .unwrap();
        assert_eq!(
            registered.server_info,
            RelayFrame::ServerInfo {
                protocol_version: PROTOCOL_VERSION
            }
        );
        // Replaying the same login (same ticket) fails.
        assert_eq!(
            router
                .register_client(
                    alice.public().exchange_key_bytes(),
                    &CHALLENGE,
                    &sealed,
                    1001
                )
                .err(),
            Some(RelayError::TicketReplayed)
        );
    }

    #[test]
    fn header_limit_rejects_hostile_lengths_before_allocation() {
        let mut header = [0u8; FRAME_HEADER_LEN];
        header[0] = FRAME_SEND_PACKET;
        header[1..5].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(matches!(
            RelayFrame::parse_header(&header),
            Err(RelayError::PacketTooLarge(_))
        ));
        header[1..5].copy_from_slice(&u32::try_from(MAX_FRAME_BODY_LEN).unwrap().to_be_bytes());
        assert_eq!(
            RelayFrame::parse_header(&header).unwrap(),
            (FRAME_SEND_PACKET, MAX_FRAME_BODY_LEN)
        );
    }

    #[tokio::test]
    async fn relay_router_forwards_packets_emits_peer_gone_and_respects_generations() {
        let (relay_id, issuer, mut router) = fleet();
        let alice = DeviceIdentity::generate();
        let bob = DeviceIdentity::generate();
        let absent_key = [0x03u8; 32];

        let (alice_key, alice_login) = login(&alice, &relay_id, &issuer, [1u8; 16], 2000);
        let (bob_key, bob_login) = login(&bob, &relay_id, &issuer, [2u8; 16], 2000);
        let mut alice_reg = router
            .register_client(alice_key, &CHALLENGE, &alice_login, 1000)
            .unwrap();
        let mut bob_reg = router
            .register_client(bob_key, &CHALLENGE, &bob_login, 1000)
            .unwrap();
        assert_eq!(router.connected_clients(), 2);

        router
            .forward_packet(alice_key, bob_key, b"encrypted-frame".to_vec())
            .unwrap();
        assert_eq!(
            bob_reg.outbound.recv().await.unwrap(),
            RelayFrame::RecvPacket {
                src_key: alice_key,
                packet: b"encrypted-frame".to_vec()
            }
        );
        router
            .forward_packet(alice_key, absent_key, b"probe".to_vec())
            .unwrap();
        assert_eq!(
            alice_reg.outbound.recv().await.unwrap(),
            RelayFrame::PeerGone {
                peer_key: absent_key,
                reason: PeerGoneReason::NotHere
            }
        );

        // Alice reconnects (new ticket) before her old connection cleans up.
        let (_, alice_login2) = login(&alice, &relay_id, &issuer, [9u8; 16], 2000);
        let alice_reg2 = router
            .register_client(alice_key, &CHALLENGE, &alice_login2, 1001)
            .unwrap();
        assert_ne!(alice_reg2.generation, alice_reg.generation);
        router.unregister_client(&alice_key, alice_reg.generation);
        assert_eq!(
            router.connected_clients(),
            2,
            "stale unregister must be ignored"
        );

        // The real disconnect notifies Bob.
        router.unregister_client(&alice_key, alice_reg2.generation);
        assert_eq!(router.connected_clients(), 1);
        assert_eq!(
            bob_reg.outbound.recv().await.unwrap(),
            RelayFrame::PeerGone {
                peer_key: alice_key,
                reason: PeerGoneReason::Disconnected
            }
        );
    }

    #[test]
    fn derp_region_selector_picks_nearest_with_hysteresis_and_honors_avoid() {
        let mut selector = DerpRegionSelector::new(vec![
            DerpRegion {
                region_id: 1,
                region_code: "gru".to_owned(),
                region_name: "Sao Paulo".to_owned(),
                https_port: 443,
                avoid: false,
            },
            DerpRegion {
                region_id: 2,
                region_code: "iad".to_owned(),
                region_name: "Ashburn".to_owned(),
                https_port: 443,
                avoid: false,
            },
            DerpRegion {
                region_id: 3,
                region_code: "drain".to_owned(),
                region_name: "Draining".to_owned(),
                https_port: 443,
                avoid: true,
            },
        ]);

        let mut rtts = HashMap::from([(1u16, 40u32), (2u16, 110u32)]);
        assert_eq!(selector.pick_nearest_region(&rtts), Some(1));
        rtts.insert(2, 32);
        assert_eq!(
            selector.pick_nearest_region(&rtts),
            Some(1),
            "8 ms is within hysteresis"
        );
        rtts.insert(2, 20);
        assert_eq!(selector.pick_nearest_region(&rtts), Some(2));

        // Only the avoided region answers: it becomes home...
        let only_avoided = HashMap::from([(3u16, 20u32)]);
        assert_eq!(selector.pick_nearest_region(&only_avoided), Some(3));
        // ...but stickiness never retains it once a normal region responds,
        // even when the normal region is slower.
        let normal_back = HashMap::from([(3u16, 20u32), (2u16, 30u32)]);
        assert_eq!(selector.pick_nearest_region(&normal_back), Some(2));
    }

    #[test]
    fn relay_frames_encode_and_decode_round_trip() {
        let frames = vec![
            RelayFrame::ServerKey {
                server_public_key: [3u8; 32],
                challenge: [0x5a; LOGIN_CHALLENGE_LEN],
            },
            RelayFrame::ServerInfo {
                protocol_version: PROTOCOL_VERSION,
            },
            RelayFrame::SendPacket {
                dst_key: [4u8; 32],
                packet: b"hello".to_vec(),
            },
            RelayFrame::RecvPacket {
                src_key: [5u8; 32],
                packet: b"world".to_vec(),
            },
            RelayFrame::KeepAlive,
            RelayFrame::NotePreferred { preferred: true },
            RelayFrame::PeerGone {
                peer_key: [6u8; 32],
                reason: PeerGoneReason::Disconnected,
            },
            RelayFrame::Ping(*b"12345678"),
            RelayFrame::Pong(*b"12345678"),
        ];
        for frame in frames {
            let wire = frame.encode().unwrap();
            assert_eq!(RelayFrame::decode(&wire).unwrap(), frame);
        }
    }
}
