//! Minimal STUN (RFC 5389) binding request/response codec used to discover the
//! node's public (reflexive) UDP endpoint through NAT.
//!
//! Ported to Rust from `tailscale/net/stun/stun.go` (BSD-3-Clause): the same
//! fixed-layout request (`SOFTWARE` + `FINGERPRINT` attributes), the same
//! response parser (`XOR-MAPPED-ADDRESS`, its common `0x8020` misnumbering, and
//! `MAPPED-ADDRESS` as fallback), and the same top-two-bits/magic-cookie
//! detection so STUN packets can share a UDP socket with disco and QUIC traffic.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use rand_core::{OsRng, RngCore};

/// Random 96-bit STUN transaction identifier (RFC 5389 §6).
pub type TxId = [u8; 12];

/// STUN magic cookie (RFC 5389 §6).
pub const MAGIC_COOKIE: [u8; 4] = [0x21, 0x12, 0xa4, 0x42];

const HEADER_LEN: usize = 20;
const BINDING_REQUEST: [u8; 2] = [0x00, 0x01];
const BINDING_SUCCESS: [u8; 2] = [0x01, 0x01];
const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
/// Comprehension-optional misnumbering of `XOR-MAPPED-ADDRESS` that some
/// servers send (`attrXorMappedAddressAlt` in Tailscale).
const ATTR_XOR_MAPPED_ADDRESS_ALT: u16 = 0x8020;
const ATTR_SOFTWARE: u16 = 0x8022;
const ATTR_FINGERPRINT: u16 = 0x8028;
const FINGERPRINT_XOR: u32 = 0x5354_554e;
/// `SOFTWARE` value advertised in requests. Twelve bytes, so no padding is needed.
const SOFTWARE: &[u8; 12] = b"omegadesk-v1";

/// STUN parsing errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum StunError {
    /// The datagram is not a STUN message (wrong first bits or cookie).
    #[error("not a STUN packet")]
    NotStun,
    /// The message is a STUN message but not a binding success response.
    #[error("STUN packet is not a binding success response")]
    NotSuccessResponse,
    /// Attribute framing is inconsistent with the declared lengths.
    #[error("malformed STUN attributes")]
    MalformedAttributes,
}

/// Generates a fresh random transaction identifier.
#[must_use]
pub fn new_tx_id() -> TxId {
    let mut id = [0u8; 12];
    OsRng.fill_bytes(&mut id);
    id
}

/// Returns `true` if `datagram` is a STUN message: top two bits zero and the
/// magic cookie in bytes 4..8 (`stun.Is` in Tailscale).
#[must_use]
pub fn is_stun(datagram: &[u8]) -> bool {
    datagram.len() >= HEADER_LEN && datagram[0] & 0b1100_0000 == 0 && datagram[4..8] == MAGIC_COOKIE
}

/// Builds a binding request with `SOFTWARE` and `FINGERPRINT` attributes.
#[must_use]
pub fn binding_request(tx_id: &TxId) -> Vec<u8> {
    let software_attr_len = 4 + SOFTWARE.len();
    let fingerprint_len = 8;
    let mut b = Vec::with_capacity(HEADER_LEN + software_attr_len + fingerprint_len);
    b.extend_from_slice(&BINDING_REQUEST);
    b.extend_from_slice(
        &u16::try_from(software_attr_len + fingerprint_len)
            .unwrap_or(0)
            .to_be_bytes(),
    );
    b.extend_from_slice(&MAGIC_COOKIE);
    b.extend_from_slice(tx_id);
    b.extend_from_slice(&ATTR_SOFTWARE.to_be_bytes());
    b.extend_from_slice(&u16::try_from(SOFTWARE.len()).unwrap_or(0).to_be_bytes());
    b.extend_from_slice(SOFTWARE);
    let fp = fingerprint(&b);
    b.extend_from_slice(&ATTR_FINGERPRINT.to_be_bytes());
    b.extend_from_slice(&4u16.to_be_bytes());
    b.extend_from_slice(&fp.to_be_bytes());
    b
}

/// Parses a binding request and returns its transaction ID (used by relays
/// acting as STUN servers). The `FINGERPRINT`, when present, must be valid.
///
/// # Errors
///
/// Returns [`StunError`] if the datagram is not a well-formed binding request.
pub fn parse_binding_request(datagram: &[u8]) -> Result<TxId, StunError> {
    if !is_stun(datagram) {
        return Err(StunError::NotStun);
    }
    if datagram[..2] != BINDING_REQUEST {
        return Err(StunError::NotSuccessResponse);
    }
    let attrs_len = usize::from(u16::from_be_bytes([datagram[2], datagram[3]]));
    if attrs_len > datagram.len() - HEADER_LEN {
        return Err(StunError::MalformedAttributes);
    }
    let mut tx_id = [0u8; 12];
    tx_id.copy_from_slice(&datagram[8..20]);
    let mut attrs = &datagram[HEADER_LEN..HEADER_LEN + attrs_len];
    let mut offset = HEADER_LEN;
    while !attrs.is_empty() {
        if attrs.len() < 4 {
            return Err(StunError::MalformedAttributes);
        }
        let attr_type = u16::from_be_bytes([attrs[0], attrs[1]]);
        let attr_len = usize::from(u16::from_be_bytes([attrs[2], attrs[3]]));
        let padded = (attr_len + 3) & !3;
        if padded > attrs.len() - 4 {
            return Err(StunError::MalformedAttributes);
        }
        if attr_type == ATTR_FINGERPRINT {
            if attr_len != 4 {
                return Err(StunError::MalformedAttributes);
            }
            let got = u32::from_be_bytes([attrs[4], attrs[5], attrs[6], attrs[7]]);
            if got != fingerprint(&datagram[..offset]) {
                return Err(StunError::MalformedAttributes);
            }
        }
        attrs = &attrs[4 + padded..];
        offset += 4 + padded;
    }
    Ok(tx_id)
}

/// Builds a binding success response reporting `addr` in `XOR-MAPPED-ADDRESS`
/// (used by tests and by relays acting as STUN servers).
#[must_use]
pub fn binding_response(tx_id: &TxId, addr: SocketAddr) -> Vec<u8> {
    let (family, octets): (u8, Vec<u8>) = match addr.ip() {
        IpAddr::V4(v4) => (1, v4.octets().to_vec()),
        IpAddr::V6(v6) => (2, v6.octets().to_vec()),
    };
    let attr_len = 4 + octets.len();
    let mut b = Vec::with_capacity(HEADER_LEN + 4 + attr_len);
    b.extend_from_slice(&BINDING_SUCCESS);
    b.extend_from_slice(&u16::try_from(4 + attr_len).unwrap_or(0).to_be_bytes());
    b.extend_from_slice(&MAGIC_COOKIE);
    b.extend_from_slice(tx_id);
    b.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
    b.extend_from_slice(&u16::try_from(attr_len).unwrap_or(0).to_be_bytes());
    b.push(0);
    b.push(family);
    b.extend_from_slice(&(addr.port() ^ 0x2112).to_be_bytes());
    for (i, o) in octets.iter().enumerate() {
        let x = if i < 4 {
            o ^ MAGIC_COOKIE[i]
        } else {
            o ^ tx_id[i - 4]
        };
        b.push(x);
    }
    b
}

/// Parses a binding success response, returning its transaction ID and the
/// reflexive address (`XOR-MAPPED-ADDRESS`, or `MAPPED-ADDRESS` as fallback).
///
/// # Errors
///
/// Returns [`StunError`] if the datagram is not a well-formed success response.
pub fn parse_binding_response(datagram: &[u8]) -> Result<(TxId, SocketAddr), StunError> {
    if !is_stun(datagram) {
        return Err(StunError::NotStun);
    }
    let mut tx_id = [0u8; 12];
    tx_id.copy_from_slice(&datagram[8..20]);
    if datagram[..2] != BINDING_SUCCESS {
        return Err(StunError::NotSuccessResponse);
    }
    let attrs_len = usize::from(u16::from_be_bytes([datagram[2], datagram[3]]));
    let body = &datagram[HEADER_LEN..];
    if attrs_len > body.len() {
        return Err(StunError::MalformedAttributes);
    }
    let mut attrs = &body[..attrs_len];
    let mut xor_addr = None;
    let mut mapped_addr = None;
    while !attrs.is_empty() {
        if attrs.len() < 4 {
            return Err(StunError::MalformedAttributes);
        }
        let attr_type = u16::from_be_bytes([attrs[0], attrs[1]]);
        let attr_len = usize::from(u16::from_be_bytes([attrs[2], attrs[3]]));
        let padded = (attr_len + 3) & !3;
        attrs = &attrs[4..];
        if padded > attrs.len() {
            return Err(StunError::MalformedAttributes);
        }
        let value = &attrs[..attr_len];
        match attr_type {
            ATTR_XOR_MAPPED_ADDRESS | ATTR_XOR_MAPPED_ADDRESS_ALT => {
                xor_addr = Some(decode_address(value, Some(&tx_id))?);
            }
            ATTR_MAPPED_ADDRESS => {
                mapped_addr = Some(decode_address(value, None)?);
            }
            _ => {}
        }
        attrs = &attrs[padded..];
    }
    xor_addr
        .or(mapped_addr)
        .map(|addr| (tx_id, addr))
        .ok_or(StunError::MalformedAttributes)
}

/// Decodes a `(XOR-)MAPPED-ADDRESS` value; `xor` is `Some(tx_id)` for the XOR variant.
fn decode_address(value: &[u8], xor: Option<&TxId>) -> Result<SocketAddr, StunError> {
    if value.len() < 4 {
        return Err(StunError::MalformedAttributes);
    }
    let family = value[1];
    let raw_port = u16::from_be_bytes([value[2], value[3]]);
    let port = if xor.is_some() {
        raw_port ^ 0x2112
    } else {
        raw_port
    };
    let addr_bytes = &value[4..];
    let unmask = |i: usize, o: u8| -> u8 {
        match xor {
            Some(_) if i < 4 => o ^ MAGIC_COOKIE[i],
            Some(tx_id) => o ^ tx_id[i - 4],
            None => o,
        }
    };
    match family {
        0x01 if addr_bytes.len() >= 4 => {
            let mut o = [0u8; 4];
            for (i, b) in o.iter_mut().enumerate() {
                *b = unmask(i, addr_bytes[i]);
            }
            Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(o)), port))
        }
        0x02 if addr_bytes.len() >= 16 => {
            let mut o = [0u8; 16];
            for (i, b) in o.iter_mut().enumerate() {
                *b = unmask(i, addr_bytes[i]);
            }
            let v6 = Ipv6Addr::from(o);
            let ip = v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4);
            Ok(SocketAddr::new(ip, port))
        }
        _ => Err(StunError::MalformedAttributes),
    }
}

/// CRC-32 (IEEE) of `b` `XOR`ed with `0x5354554e` (RFC 5389 §15.5).
fn fingerprint(b: &[u8]) -> u32 {
    crc32_ieee(b) ^ FINGERPRINT_XOR
}

fn crc32_ieee(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = (!(crc & 1)).wrapping_add(1);
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_has_fingerprint_and_is_detected_as_stun() {
        let tx = new_tx_id();
        let req = binding_request(&tx);
        assert!(is_stun(&req));
        assert_eq!(req.len(), HEADER_LEN + 16 + 8);
        // FINGERPRINT covers everything before it.
        let fp = u32::from_be_bytes([req[40], req[41], req[42], req[43]]);
        assert_eq!(fp, fingerprint(&req[..36]));
        assert_eq!(crc32_ieee(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn request_round_trips_through_the_responder_path() {
        let tx = new_tx_id();
        let req = binding_request(&tx);
        assert_eq!(parse_binding_request(&req).unwrap(), tx);
        let mut tampered = req.clone();
        tampered[25] ^= 0x01; // inside SOFTWARE: fingerprint no longer matches
        assert_eq!(
            parse_binding_request(&tampered),
            Err(StunError::MalformedAttributes)
        );
        assert_eq!(
            parse_binding_request(&binding_response(&tx, "1.2.3.4:5".parse().unwrap())),
            Err(StunError::NotSuccessResponse)
        );
    }

    #[test]
    fn response_round_trips_ipv4_and_ipv6() {
        let tx = new_tx_id();
        for addr in [
            "203.0.113.9:40000".parse::<SocketAddr>().unwrap(),
            "[2001:db8::1]:51820".parse::<SocketAddr>().unwrap(),
        ] {
            let resp = binding_response(&tx, addr);
            assert!(is_stun(&resp));
            let (got_tx, got_addr) = parse_binding_response(&resp).unwrap();
            assert_eq!(got_tx, tx);
            assert_eq!(got_addr, addr);
        }
    }

    #[test]
    fn rejects_requests_and_garbage() {
        let tx = new_tx_id();
        assert_eq!(
            parse_binding_response(&binding_request(&tx)),
            Err(StunError::NotSuccessResponse)
        );
        assert_eq!(
            parse_binding_response(b"TS\xf0\x9f\x92\xac..."),
            Err(StunError::NotStun)
        );
        assert!(!is_stun(&[0xC0; 20]));
    }

    #[test]
    fn falls_back_to_mapped_address() {
        let tx = new_tx_id();
        let addr: SocketAddr = "198.51.100.7:5555".parse().unwrap();
        let mut b = Vec::new();
        b.extend_from_slice(&BINDING_SUCCESS);
        b.extend_from_slice(&12u16.to_be_bytes());
        b.extend_from_slice(&MAGIC_COOKIE);
        b.extend_from_slice(&tx);
        b.extend_from_slice(&ATTR_MAPPED_ADDRESS.to_be_bytes());
        b.extend_from_slice(&8u16.to_be_bytes());
        b.push(0);
        b.push(1);
        b.extend_from_slice(&addr.port().to_be_bytes());
        b.extend_from_slice(&[198, 51, 100, 7]);
        assert_eq!(parse_binding_response(&b).unwrap().1, addr);
    }
}
