//! OmegaDesk session protocol.
//!
//! Messages are defined in `proto/omegadesk/v1/session.proto` and generated
//! with `prost`. This crate also defines stream framing: each
//! [`Envelope`](v1::Envelope) is prefixed by its byte length encoded as a
//! protobuf varint.

mod framing;

pub use framing::{FrameDecoder, FramingError, MAX_FRAME_LEN, encode_frame};

/// Current wire protocol version sent in `Hello` and `HelloAck`.
pub const PROTOCOL_VERSION: u32 = 1;

/// Version 1 protocol messages.
#[allow(
    missing_docs,
    unreachable_pub,
    clippy::pedantic,
    clippy::wildcard_enum_match_arm
)]
pub mod v1 {
    include!(concat!(env!("OUT_DIR"), "/omegadesk.v1.rs"));
}

/// Selects the session codec: the first entry in the host's preference list
/// that the client is able to decode.
#[must_use]
pub fn negotiate_codec(
    host_encoders: &[v1::VideoCodec],
    client_decoders: &[v1::VideoCodec],
) -> Option<v1::VideoCodec> {
    host_encoders
        .iter()
        .copied()
        .filter(|codec| *codec != v1::VideoCodec::Unspecified)
        .find(|codec| client_decoders.contains(codec))
}

#[cfg(test)]
mod tests {
    use super::negotiate_codec;
    use super::v1::VideoCodec;

    #[test]
    fn negotiate_follows_host_preference() {
        let host = [VideoCodec::Av1, VideoCodec::H265, VideoCodec::H264];
        let client = [VideoCodec::H264, VideoCodec::H265];
        assert_eq!(negotiate_codec(&host, &client), Some(VideoCodec::H265));
    }

    #[test]
    fn negotiate_without_common_codec() {
        let host = [VideoCodec::Av1];
        let client = [VideoCodec::H264];
        assert_eq!(negotiate_codec(&host, &client), None);
    }

    #[test]
    fn negotiate_ignores_unspecified() {
        let host = [VideoCodec::Unspecified, VideoCodec::H264];
        let client = [VideoCodec::Unspecified, VideoCodec::H264];
        assert_eq!(negotiate_codec(&host, &client), Some(VideoCodec::H264));
    }
}
