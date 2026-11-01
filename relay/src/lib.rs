//! Stateless DERP-style packet relay with single-use HMAC tickets (`omegadesk-relay`).
//!
//! Combines two reference architectures:
//! - **Tailscale DERP** (`tailscale/derp/derp.go`, BSD-3-Clause):
//!   8-byte `DERP🔑` server key greeting (`0x44 45 52 50 f0 9f 94 91`), 5-byte frame
//!   header (`1B FrameType + 4B BE length`), `MaxPacketSize = 64 KiB`, routing
//!   packets strictly by 32-byte X25519 public key (`FrameSendPacket` -> `FrameRecvPacket`),
//!   and notifying peers with `FramePeerGone` when a previous sender disconnects or
//!   is not present on this relay node.
//! - **Aspia Relay Key Pool** (`dchapyshev/aspia/source/relay/shared_key_pool.h`,
//!   `session_key.h`, GPL-3.0-or-later):
//!   Single-use tickets issued by the coordinator (`omegadesk-server`) and verified
//!   statelessly via HMAC-SHA256 + a bounded replay cache (`TicketValidator`), so
//!   relay nodes require no database connection and scale horizontally.

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use tokio::sync::mpsc;

/// Eight-byte magic header sent in `FrameServerKey` (`"DERP🔑"`), matching
/// `derp.Magic` in `tailscale/derp/derp.go`.
pub const MAGIC: [u8; 8] = [0x44, 0x45, 0x52, 0x50, 0xf0, 0x9f, 0x94, 0x91];

/// DERP protocol version (`2`: `FrameRecvPacket` carries the 32-byte source public key).
pub const PROTOCOL_VERSION: u8 = 2;

/// Maximum packet payload size forwarded over the relay (64 KiB), matching
/// `derp.MaxPacketSize` in `tailscale/derp/derp.go`.
pub const MAX_PACKET_SIZE: usize = 64 << 10;

/// Frame header length (`1B frame_type + 4B big-endian length`).
pub const FRAME_HEADER_LEN: usize = 5;

/// Default keep-alive interval (60 seconds), matching `derp.KeepAlive`.
pub const KEEP_ALIVE: Duration = Duration::from_secs(60);

/// Serialized byte length of a [`RelayTicket`]:
/// `16B ticket_id + 32B client_exchange_key + 8B expires_at_unix_secs + 32B HMAC-SHA256 = 88 bytes`.
pub const TICKET_WIRE_LEN: usize = 16 + 32 + 8 + 32;

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
    /// `0x01`: Server greeting carrying [`MAGIC`] and the relay's 32-byte X25519 key.
    ServerKey {
        /// Relay node's 32-byte X25519 public key.
        server_public_key: [u8; 32],
    },
    /// `0x02`: Client authentication carrying the client's 32-byte X25519 key and
    /// its single-use [`RelayTicket`].
    ClientInfo {
        /// Client's 32-byte X25519 public key.
        client_public_key: [u8; 32],
        /// Single-use HMAC ticket issued by the coordinator.
        ticket: RelayTicket,
    },
    /// `0x03`: Server acknowledgement of client login (`PROTOCOL_VERSION`).
    ServerInfo {
        /// Negotiated DERP protocol version.
        protocol_version: u8,
    },
    /// `0x04`: Client requests forwarding `packet` to `dst_key`.
    SendPacket {
        /// Recipient's 32-byte X25519 public key.
        dst_key: [u8; 32],
        /// Encrypted WireGuard/disco packet bytes.
        packet: Vec<u8>,
    },
    /// `0x05`: Server delivers `packet` from `src_key` to the connected recipient.
    RecvPacket {
        /// Sender's 32-byte X25519 public key.
        src_key: [u8; 32],
        /// Encrypted WireGuard/disco packet bytes.
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
}

impl RelayFrame {
    /// Encodes this frame into its wire format (`1B type + 4B BE len + body`).
    ///
    /// # Errors
    ///
    /// Returns [`RelayError::PacketTooLarge`] if a packet payload exceeds [`MAX_PACKET_SIZE`].
    pub fn encode(&self) -> Result<Vec<u8>, RelayError> {
        let (frame_type, body) = match self {
            Self::ServerKey { server_public_key } => {
                let mut b = Vec::with_capacity(MAGIC.len() + 32);
                b.extend_from_slice(&MAGIC);
                b.extend_from_slice(server_public_key);
                (FRAME_SERVER_KEY, b)
            }
            Self::ClientInfo {
                client_public_key,
                ticket,
            } => {
                let mut b = Vec::with_capacity(32 + TICKET_WIRE_LEN);
                b.extend_from_slice(client_public_key);
                b.extend_from_slice(&ticket.to_bytes());
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

    /// Decodes a wire frame produced by [`Self::encode`].
    ///
    /// # Errors
    ///
    /// Returns [`RelayError`] if the header, magic, or body is malformed.
    pub fn decode(bytes: &[u8]) -> Result<Self, RelayError> {
        if bytes.len() < FRAME_HEADER_LEN {
            return Err(RelayError::TruncatedFrame);
        }
        let frame_type = bytes[0];
        let body_len =
            usize::try_from(u32::from_be_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]))
                .map_err(|_| RelayError::MalformedFrame)?;
        if body_len > MAX_PACKET_SIZE + 64 {
            return Err(RelayError::PacketTooLarge(body_len));
        }
        let body = &bytes[FRAME_HEADER_LEN..];
        if body.len() != body_len {
            return Err(RelayError::TruncatedFrame);
        }
        Self::decode_body(frame_type, body)
    }

    fn decode_body(frame_type: u8, body: &[u8]) -> Result<Self, RelayError> {
        match frame_type {
            FRAME_SERVER_KEY => {
                if body.len() < MAGIC.len() + 32 {
                    return Err(RelayError::MalformedFrame);
                }
                if body[..MAGIC.len()] != MAGIC {
                    return Err(RelayError::InvalidMagic);
                }
                let mut server_public_key = [0u8; 32];
                server_public_key.copy_from_slice(&body[MAGIC.len()..MAGIC.len() + 32]);
                Ok(Self::ServerKey { server_public_key })
            }
            FRAME_CLIENT_INFO => {
                if body.len() != 32 + TICKET_WIRE_LEN {
                    return Err(RelayError::MalformedFrame);
                }
                let mut client_public_key = [0u8; 32];
                client_public_key.copy_from_slice(&body[..32]);
                let ticket = RelayTicket::from_bytes(&body[32..])?;
                Ok(Self::ClientInfo {
                    client_public_key,
                    ticket,
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
/// modeled after Aspia's `SharedKeyPool` / `SessionKey` (`source/relay/shared_key_pool.h`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayTicket {
    /// Unique 128-bit ticket identifier used to prevent replay.
    pub ticket_id: [u8; 16],
    /// Client's 32-byte X25519 public key authorized to bind this session.
    pub client_exchange_key: [u8; 32],
    /// Expiration timestamp (UNIX seconds).
    pub expires_at_unix_secs: u64,
    /// 32-byte HMAC-SHA256 tag over `ticket_id || client_exchange_key || expires_at_unix_secs`.
    pub signature: [u8; 32],
}

impl RelayTicket {
    /// Serializes the ticket into its fixed 88-byte wire representation.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; TICKET_WIRE_LEN] {
        let mut out = [0u8; TICKET_WIRE_LEN];
        out[..16].copy_from_slice(&self.ticket_id);
        out[16..48].copy_from_slice(&self.client_exchange_key);
        out[48..56].copy_from_slice(&self.expires_at_unix_secs.to_be_bytes());
        out[56..88].copy_from_slice(&self.signature);
        out
    }

    /// Parses an 88-byte serialized [`RelayTicket`].
    ///
    /// # Errors
    ///
    /// Returns [`RelayError::MalformedFrame`] if `bytes.len() != 88`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, RelayError> {
        if bytes.len() != TICKET_WIRE_LEN {
            return Err(RelayError::MalformedFrame);
        }
        let mut ticket_id = [0u8; 16];
        ticket_id.copy_from_slice(&bytes[..16]);
        let mut client_exchange_key = [0u8; 32];
        client_exchange_key.copy_from_slice(&bytes[16..48]);
        let mut exp_bytes = [0u8; 8];
        exp_bytes.copy_from_slice(&bytes[48..56]);
        let expires_at_unix_secs = u64::from_be_bytes(exp_bytes);
        let mut signature = [0u8; 32];
        signature.copy_from_slice(&bytes[56..88]);
        Ok(Self {
            ticket_id,
            client_exchange_key,
            expires_at_unix_secs,
            signature,
        })
    }
}

fn compute_ticket_mac(
    secret: &[u8; 32],
    ticket_id: &[u8; 16],
    client_exchange_key: &[u8; 32],
    expires_at_unix_secs: u64,
) -> [u8; 32] {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret);
    let mut msg = [0u8; 16 + 32 + 8];
    msg[..16].copy_from_slice(ticket_id);
    msg[16..48].copy_from_slice(client_exchange_key);
    msg[48..56].copy_from_slice(&expires_at_unix_secs.to_be_bytes());
    let tag = ring::hmac::sign(&key, &msg);
    let mut out = [0u8; 32];
    out.copy_from_slice(&tag.as_ref()[..32]);
    out
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

    /// Issues a signed single-use [`RelayTicket`] for `client_exchange_key`.
    #[must_use]
    pub fn issue(
        &self,
        ticket_id: [u8; 16],
        client_exchange_key: [u8; 32],
        expires_at_unix_secs: u64,
    ) -> RelayTicket {
        let signature = compute_ticket_mac(
            &self.shared_secret,
            &ticket_id,
            &client_exchange_key,
            expires_at_unix_secs,
        );
        RelayTicket {
            ticket_id,
            client_exchange_key,
            expires_at_unix_secs,
            signature,
        }
    }
}

/// Validates single-use [`RelayTicket`]s on the relay without database access,
/// modeled after Aspia's `SharedKeyPool` (`source/relay/shared_key_pool.h`).
pub struct TicketValidator {
    shared_secret: [u8; 32],
    redeemed: HashMap<[u8; 16], u64>,
}

impl TicketValidator {
    /// Creates a new [`TicketValidator`] using `shared_secret`.
    #[must_use]
    pub fn new(shared_secret: [u8; 32]) -> Self {
        Self {
            shared_secret,
            redeemed: HashMap::new(),
        }
    }

    /// Verifies and consumes a single-use `ticket` for `claimed_client_key` at
    /// `now_unix_secs`.
    ///
    /// # Errors
    ///
    /// Returns [`RelayError`] if the key mismatches, the ticket is expired, the
    /// HMAC tag is invalid, or the ticket was already redeemed.
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
        if now_unix_secs >= ticket.expires_at_unix_secs {
            return Err(RelayError::TicketExpired {
                expired_at: ticket.expires_at_unix_secs,
                now: now_unix_secs,
            });
        }

        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &self.shared_secret);
        let mut msg = [0u8; 16 + 32 + 8];
        msg[..16].copy_from_slice(&ticket.ticket_id);
        msg[16..48].copy_from_slice(&ticket.client_exchange_key);
        msg[48..56].copy_from_slice(&ticket.expires_at_unix_secs.to_be_bytes());
        ring::hmac::verify(&key, &msg, &ticket.signature)
            .map_err(|_| RelayError::InvalidTicketSignature)?;

        if self.redeemed.contains_key(&ticket.ticket_id) {
            return Err(RelayError::TicketReplayed);
        }
        self.redeemed
            .insert(ticket.ticket_id, ticket.expires_at_unix_secs);
        Ok(())
    }
}

/// In-memory DERP packet router mapping 32-byte X25519 public keys to active client
/// frame channels and tracking peer-to-peer communication graphs for `FramePeerGone`
/// notifications (matching `tailscale/derp/derp_server.go`).
pub struct RelayRouter {
    server_public_key: [u8; 32],
    validator: TicketValidator,
    clients: HashMap<[u8; 32], mpsc::Sender<RelayFrame>>,
    /// Maps `sender_key -> set of recipient_keys` so when `sender_key` disconnects
    /// every peer it previously sent packets to receives `FramePeerGone`.
    sent_to: HashMap<[u8; 32], HashSet<[u8; 32]>>,
}

impl RelayRouter {
    /// Creates a new [`RelayRouter`] with `server_public_key` and `shared_ticket_secret`.
    #[must_use]
    pub fn new(server_public_key: [u8; 32], shared_ticket_secret: [u8; 32]) -> Self {
        Self {
            server_public_key,
            validator: TicketValidator::new(shared_ticket_secret),
            clients: HashMap::new(),
            sent_to: HashMap::new(),
        }
    }

    /// Returns the `FrameServerKey` greeting frame for newly connected clients.
    #[must_use]
    pub const fn server_key_frame(&self) -> RelayFrame {
        RelayFrame::ServerKey {
            server_public_key: self.server_public_key,
        }
    }

    /// Authenticates a client via its [`RelayTicket`] and registers its outbound
    /// channel `(RelayFrame::ServerInfo, mpsc::Receiver<RelayFrame>)`.
    ///
    /// # Errors
    ///
    /// Returns [`RelayError`] if the ticket is invalid, expired, or replayed.
    pub fn register_client(
        &mut self,
        client_public_key: [u8; 32],
        ticket: &RelayTicket,
        now_unix_secs: u64,
    ) -> Result<(RelayFrame, mpsc::Receiver<RelayFrame>), RelayError> {
        self.validator
            .redeem(ticket, &client_public_key, now_unix_secs)?;
        let (tx, rx) = mpsc::channel(256);
        self.clients.insert(client_public_key, tx);
        Ok((
            RelayFrame::ServerInfo {
                protocol_version: PROTOCOL_VERSION,
            },
            rx,
        ))
    }

    /// Routes an encrypted packet from `src_key` to `dst_key`.
    ///
    /// If `dst_key` is not connected to this relay, sends [`RelayFrame::PeerGone`]
    /// (`PeerGoneReason::NotHere`) back to `src_key`, matching Tailscale DERP's
    /// behavior in `derp/derp.go`.
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
        if let Some(dst_tx) = self.clients.get(&dst_key) {
            self.sent_to.entry(src_key).or_default().insert(dst_key);
            let _ = dst_tx.try_send(RelayFrame::RecvPacket { src_key, packet });
        } else if let Some(src_tx) = self.clients.get(&src_key) {
            let _ = src_tx.try_send(RelayFrame::PeerGone {
                peer_key: dst_key,
                reason: PeerGoneReason::NotHere,
            });
        }
        Ok(())
    }

    /// Removes `client_key` and notifies all peers it previously communicated with
    /// via [`RelayFrame::PeerGone`] (`PeerGoneReason::Disconnected`).
    pub fn unregister_client(&mut self, client_key: &[u8; 32]) {
        self.clients.remove(client_key);
        if let Some(recipients) = self.sent_to.remove(client_key) {
            for peer_key in recipients {
                if let Some(peer_tx) = self.clients.get(&peer_key) {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_use_ticket_prevents_replay_and_enforces_expiry() {
        let secret = [0x42u8; 32];
        let issuer = TicketIssuer::new(secret);
        let mut validator = TicketValidator::new(secret);

        let client_key = [0x11u8; 32];
        let ticket = issuer.issue([0xAAu8; 16], client_key, 1000);

        // Valid redemption at t = 900
        validator.redeem(&ticket, &client_key, 900).unwrap();

        // Second redemption of the same ticket must fail with TicketReplayed
        assert_eq!(
            validator.redeem(&ticket, &client_key, 901),
            Err(RelayError::TicketReplayed)
        );

        // Expired ticket must fail with TicketExpired
        let expired_ticket = issuer.issue([0xBBu8; 16], client_key, 500);
        assert_eq!(
            validator.redeem(&expired_ticket, &client_key, 500),
            Err(RelayError::TicketExpired {
                expired_at: 500,
                now: 500
            })
        );
    }

    #[tokio::test]
    async fn relay_router_forwards_packets_and_emits_peer_gone() {
        let secret = [0x99u8; 32];
        let issuer = TicketIssuer::new(secret);
        let mut router = RelayRouter::new([0x77u8; 32], secret);

        let alice_key = [0x01u8; 32];
        let bob_key = [0x02u8; 32];
        let absent_key = [0x03u8; 32];

        let t_alice = issuer.issue([1u8; 16], alice_key, 2000);
        let t_bob = issuer.issue([2u8; 16], bob_key, 2000);

        let (_, mut alice_rx) = router.register_client(alice_key, &t_alice, 1000).unwrap();
        let (_, mut bob_rx) = router.register_client(bob_key, &t_bob, 1000).unwrap();
        assert_eq!(router.connected_clients(), 2);

        // Alice forwards a packet to Bob
        router
            .forward_packet(alice_key, bob_key, b"encrypted-wg-frame".to_vec())
            .unwrap();
        let recv = bob_rx.recv().await.unwrap();
        assert_eq!(
            recv,
            RelayFrame::RecvPacket {
                src_key: alice_key,
                packet: b"encrypted-wg-frame".to_vec()
            }
        );

        // Alice tries to forward to an absent peer -> receives PeerGone(NotHere)
        router
            .forward_packet(alice_key, absent_key, b"probe".to_vec())
            .unwrap();
        let gone_absent = alice_rx.recv().await.unwrap();
        assert_eq!(
            gone_absent,
            RelayFrame::PeerGone {
                peer_key: absent_key,
                reason: PeerGoneReason::NotHere
            }
        );

        // Alice disconnects -> Bob receives PeerGone(Disconnected)
        router.unregister_client(&alice_key);
        let gone_alice = bob_rx.recv().await.unwrap();
        assert_eq!(
            gone_alice,
            RelayFrame::PeerGone {
                peer_key: alice_key,
                reason: PeerGoneReason::Disconnected
            }
        );
    }

    #[test]
    fn derp_region_selector_picks_nearest_with_hysteretic_home_stickiness() {
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
        ]);

        // Initial probe: GRU is 40 ms, IAD is 110 ms -> GRU becomes preferred home region.
        let mut rtts = HashMap::from([(1u16, 40u32), (2u16, 110u32)]);
        assert_eq!(selector.pick_nearest_region(&rtts), Some(1));
        assert_eq!(selector.preferred_region_id(), Some(1));

        // Slight jitter: Region 2 drops to 32 ms (only 8 ms faster than GRU's 40 ms).
        // Hysteresis (requires >= 15 ms improvement) keeps GRU as home region.
        rtts.insert(2, 32);
        assert_eq!(selector.pick_nearest_region(&rtts), Some(1));

        // Major route change: Region 2 drops to 20 ms (20 ms faster than GRU's 40 ms) -> switches!
        rtts.insert(2, 20);
        assert_eq!(selector.pick_nearest_region(&rtts), Some(2));
        assert_eq!(selector.preferred_region_id(), Some(2));
    }

    #[test]
    fn relay_frames_encode_and_decode_round_trip() {
        let frames = vec![
            RelayFrame::ServerKey {
                server_public_key: [3u8; 32],
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
            let decoded = RelayFrame::decode(&wire).unwrap();
            assert_eq!(decoded, frame);
        }
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
    pub fn pick_nearest_region(&mut self, measured_rtts_ms: &HashMap<u16, u32>) -> Option<u16> {
        let best_candidate = self
            .regions
            .iter()
            .filter(|r| !r.avoid)
            .filter_map(|r| {
                measured_rtts_ms
                    .get(&r.region_id)
                    .map(|&rtt| (r.region_id, rtt))
            })
            .min_by_key(|&(_, rtt)| rtt)
            .or_else(|| {
                self.regions
                    .iter()
                    .filter_map(|r| {
                        measured_rtts_ms
                            .get(&r.region_id)
                            .map(|&rtt| (r.region_id, rtt))
                    })
                    .min_by_key(|&(_, rtt)| rtt)
            });

        let (candidate_id, candidate_rtt) = best_candidate?;

        if let Some(current_id) = self.preferred_region
            && current_id != candidate_id
            && let Some(&current_rtt) = measured_rtts_ms.get(&current_id)
            && current_rtt.saturating_sub(candidate_rtt) < DERP_HOME_STICKINESS_MS
        {
            return Some(current_id);
        }

        self.preferred_region = Some(candidate_id);
        Some(candidate_id)
    }
}
