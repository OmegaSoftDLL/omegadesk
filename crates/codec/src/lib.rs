//! Video encoding and decoding for OmegaDesk.
//!
//! All codecs implement the [`VideoEncoder`] and [`VideoDecoder`] traits.
//! Software H.264 is provided via OpenH264, and hardware H.264 on Windows is
//! provided via Media Foundation (Intel Quick Sync, NVIDIA NVENC, AMD AMF)
//! without changing callers of this crate.

mod color;
#[cfg(windows)]
mod media_foundation;
mod openh264_codec;
pub mod video_region;

pub use color::{bgra_to_i420, bgra_to_nv12};
#[cfg(windows)]
pub use media_foundation::MediaFoundationEncoder;
pub use openh264_codec::{OpenH264Decoder, OpenH264Encoder};

/// Codec errors.
#[derive(Debug, thiserror::Error)]
pub enum CodecError {
    /// Frame dimensions rejected by the codec (zero, odd-sized below 2, or too large).
    #[error("invalid dimensions: {width}x{height}")]
    InvalidDimensions {
        /// Width received.
        width: u32,
        /// Height received.
        height: u32,
    },
    /// Input buffer length does not match `width * height * 4`.
    #[error("buffer of {got} bytes; expected {expected}")]
    BufferSize {
        /// Actual buffer size in bytes.
        got: usize,
        /// Expected buffer size in bytes.
        expected: usize,
    },
    /// OpenH264 error.
    #[error("OpenH264: {0}")]
    OpenH264(#[from] openh264::Error),
    /// No hardware video encoder is available on this machine.
    #[error("no hardware video encoder available")]
    HardwareUnavailable,
    /// Platform media API error (Media Foundation, VA-API…).
    #[error("{0}")]
    Platform(String),
}

/// Borrowed Direct3D 11 BGRA texture and device for zero-copy hardware encoding.
#[cfg(windows)]
#[derive(Debug, Clone, Copy)]
pub struct D3d11Texture<'a> {
    /// Direct3D 11 device that owns [`Self::texture`].
    pub device: &'a windows::Win32::Graphics::Direct3D11::ID3D11Device,
    /// Immediate context of [`Self::device`].
    pub context: &'a windows::Win32::Graphics::Direct3D11::ID3D11DeviceContext,
    /// Captured `DXGI_FORMAT_B8G8R8A8_UNORM` 2D texture in VRAM.
    pub texture: &'a windows::Win32::Graphics::Direct3D11::ID3D11Texture2D,
}

/// Uncompressed input frame for an encoder, in tightly packed BGRA and
/// optionally backed by a Direct3D 11 texture in VRAM on Windows.
#[derive(Debug, Clone, Copy)]
pub struct RawFrame<'a> {
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels.
    pub height: u32,
    /// `width * height * 4` bytes of BGRA pixel data.
    pub bgra: &'a [u8],
    /// Optional GPU-resident Direct3D 11 texture for zero-copy hardware encoding.
    #[cfg(windows)]
    pub d3d11_texture: Option<D3d11Texture<'a>>,
}

impl<'a> RawFrame<'a> {
    /// Constructs a [`RawFrame`] backed by CPU BGRA pixels only.
    #[must_use]
    pub const fn from_bgra(width: u32, height: u32, bgra: &'a [u8]) -> Self {
        Self {
            width,
            height,
            bgra,
            #[cfg(windows)]
            d3d11_texture: None,
        }
    }
}

/// Encoded video frame.
#[derive(Debug, Clone)]
pub struct EncodedFrame {
    /// Encoded bitstream (Annex B for H.264).
    pub data: Vec<u8>,
    /// Whether this frame can be decoded independently (IDR keyframe).
    pub keyframe: bool,
    /// Effective encoded width in pixels (may be 1 pixel smaller than an odd input width).
    pub width: u32,
    /// Effective encoded height in pixels.
    pub height: u32,
}

/// Decoded image ready to be drawn to a window surface.
#[derive(Debug, Clone)]
pub struct DecodedImage {
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels.
    pub height: u32,
    /// One `u32` per pixel in `0x00RRGGBB` format.
    pub xrgb: Vec<u32>,
}

/// Video encoder trait.
pub trait VideoEncoder: Send {
    /// Encodes a single raw frame and returns, in order, all encoded frames that
    /// became ready (which may be empty or contain multiple frames on a queued
    /// hardware encoder). Callers must transmit every returned frame in order,
    /// as dropping an inter-frame corrupts subsequent P-frames.
    ///
    /// # Errors
    ///
    /// Returns an error if the input frame is invalid or the underlying codec fails.
    fn encode(&mut self, frame: RawFrame<'_>) -> Result<Vec<EncodedFrame>, CodecError>;

    /// Forces the next encoded frame to be an IDR keyframe (used when a new
    /// client joins or after packet/frame loss).
    fn request_keyframe(&mut self);

    /// Changes the target bitrate of a running encoder without interrupting the
    /// stream (RustDesk `Encoder::set_quality` / Sunshine dynamic bitrate).
    ///
    /// Returns `true` if the encoder applied the new bitrate live. The default
    /// returns `false`, meaning the encoder cannot be retuned in place and the
    /// caller must recreate it with new [`EncoderSettings`] (and send a keyframe).
    fn set_bitrate(&mut self, bitrate_bps: u32) -> bool {
        let _ = bitrate_bps;
        false
    }
}

/// Video decoder trait.
pub trait VideoDecoder: Send {
    /// Decodes a bitstream packet. Returns `None` if a complete frame is not yet ready.
    ///
    /// # Errors
    ///
    /// Returns an error if the bitstream is malformed.
    fn decode(&mut self, data: &[u8]) -> Result<Option<DecodedImage>, CodecError>;
}

/// Encoder target settings.
#[derive(Debug, Clone, Copy)]
pub struct EncoderSettings {
    /// Target bitrate in bits per second.
    pub bitrate_bps: u32,
    /// Maximum frame rate in frames per second.
    pub max_fps: f32,
}

impl Default for EncoderSettings {
    fn default() -> Self {
        Self {
            bitrate_bps: 8_000_000,
            max_fps: 60.0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        EncoderSettings, OpenH264Decoder, OpenH264Encoder, RawFrame, VideoDecoder, VideoEncoder,
    };

    /// Encodes and decodes a color gradient and checks that the reconstructed
    /// pixels stay close to the original.
    #[test]
    fn round_trip_gradient() {
        let (width, height) = (320_u32, 240_u32);
        let mut bgra = Vec::with_capacity((width * height * 4) as usize);
        for y in 0..height {
            for x in 0..width {
                let b = u8::try_from(x * 255 / width).unwrap();
                let g = u8::try_from(y * 255 / height).unwrap();
                bgra.extend_from_slice(&[b, g, 128, 255]);
            }
        }

        let mut encoder = OpenH264Encoder::new(EncoderSettings::default()).unwrap();
        let mut decoder = OpenH264Decoder::new().unwrap();

        let frame = RawFrame::from_bgra(width, height, &bgra);
        let bitstream = encoder.encode(frame).unwrap().remove(0);
        assert!(bitstream.keyframe);

        let image = decoder
            .decode(&bitstream.data)
            .unwrap()
            .expect("decoded image");
        assert_eq!((image.width, image.height), (width, height));

        // Check the center pixel within lossy compression tolerance.
        let (col, row) = (width / 2, height / 2);
        let pixel = image.xrgb[(row * width + col) as usize];
        let [_, red, green, blue] = pixel.to_be_bytes();
        let expected_blue = col * 255 / width;
        let expected_green = row * 255 / height;
        assert!(
            u32::from(blue).abs_diff(expected_blue) < 24,
            "blue {blue} vs {expected_blue}"
        );
        assert!(
            u32::from(green).abs_diff(expected_green) < 24,
            "green {green} vs {expected_green}"
        );
        assert!(u32::from(red).abs_diff(128) < 24, "red {red}");
    }
}
