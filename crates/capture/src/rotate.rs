//! Frame rotation for monitors configured in portrait or inverted landscape modes.
//!
//! DXGI Desktop Duplication (`IDXGIOutputDuplication`) delivers the desktop
//! texture in the physical scanout orientation of the panel and reports the
//! desktop rotation in `DXGI_OUTDUPL_DESC::Rotation`. Like `RustDesk`
//! (`libs/scrap/src/dxgi/mod.rs`), we rotate captured frames into desktop
//! orientation before encoding so the client receives an upright image whose
//! dimensions match [`crate::DisplayBounds`].

/// Clockwise rotation of the desktop relative to the physical panel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Rotation {
    /// Landscape (`0°`, `DXGI_MODE_ROTATION_IDENTITY` or `UNSPECIFIED`).
    #[default]
    Identity,
    /// Rotated `90°` clockwise (`DXGI_MODE_ROTATION_ROTATE90`).
    Rotate90,
    /// Rotated `180°` (`DXGI_MODE_ROTATION_ROTATE180`).
    Rotate180,
    /// Rotated `270°` clockwise / `90°` counter-clockwise (`DXGI_MODE_ROTATION_ROTATE270`).
    Rotate270,
}

impl Rotation {
    /// Returns the upright desktop dimensions `(width, height)` produced by
    /// rotating an unrotated scanout buffer of `(raw_width, raw_height)`.
    #[must_use]
    pub const fn output_size(self, raw_width: u32, raw_height: u32) -> (u32, u32) {
        match self {
            Self::Identity | Self::Rotate180 => (raw_width, raw_height),
            Self::Rotate90 | Self::Rotate270 => (raw_height, raw_width),
        }
    }
}

/// Rotates a tightly packed 4-byte-per-pixel BGRA image `src` of dimensions
/// `src_width` × `src_height` by `rotation`, writing the upright image into `dst`
/// and returning its `(dst_width, dst_height)`.
pub fn rotate_bgra(
    src: &[u8],
    src_width: u32,
    src_height: u32,
    rotation: Rotation,
    dst: &mut Vec<u8>,
) -> (u32, u32) {
    let (w, h) = (src_width as usize, src_height as usize);
    let total_bytes = w * h * 4;
    debug_assert_eq!(src.len(), total_bytes);

    let (dst_w, dst_h) = rotation.output_size(src_width, src_height);
    if rotation == Rotation::Identity {
        dst.clear();
        dst.extend_from_slice(&src[..total_bytes]);
        return (dst_w, dst_h);
    }

    dst.resize(total_bytes, 0);
    let (dw, dh) = (dst_w as usize, dst_h as usize);
    for dy in 0..dh {
        let dst_row = dy * dw;
        for dx in 0..dw {
            let (sx, sy) = match rotation {
                Rotation::Identity => (dx, dy),
                Rotation::Rotate90 => (dy, h - 1 - dx),
                Rotation::Rotate180 => (w - 1 - dx, h - 1 - dy),
                Rotation::Rotate270 => (w - 1 - dy, dx),
            };
            let src_idx = (sy * w + sx) * 4;
            let dst_idx = (dst_row + dx) * 4;
            dst[dst_idx..dst_idx + 4].copy_from_slice(&src[src_idx..src_idx + 4]);
        }
    }
    (dst_w, dst_h)
}

#[cfg(test)]
mod tests {
    use super::{Rotation, rotate_bgra};

    /// Builds a 3x2 test image with distinct 4-byte pixels `[x, y, 0, 255]`.
    fn sample_3x2() -> Vec<u8> {
        let mut buf = Vec::with_capacity(3 * 2 * 4);
        for y in 0..2u8 {
            for x in 0..3u8 {
                buf.extend_from_slice(&[x, y, 0, 255]);
            }
        }
        buf
    }

    #[test]
    fn rotate_90_and_270_are_inverses() {
        let original = sample_3x2();
        let mut rotated_90 = Vec::new();
        let (w90, h90) = rotate_bgra(&original, 3, 2, Rotation::Rotate90, &mut rotated_90);
        assert_eq!((w90, h90), (2, 3));
        // Top-left (0, 0) of rotated_90 comes from bottom-left (0, 1) of original.
        assert_eq!(&rotated_90[0..4], &[0, 1, 0, 255]);
        // Top-right (1, 0) of rotated_90 comes from top-left (0, 0) of original.
        assert_eq!(&rotated_90[4..8], &[0, 0, 0, 255]);

        let mut restored = Vec::new();
        let (w, h) = rotate_bgra(&rotated_90, w90, h90, Rotation::Rotate270, &mut restored);
        assert_eq!((w, h), (3, 2));
        assert_eq!(restored, original);
    }

    #[test]
    fn rotate_180_twice_restores_original() {
        let original = sample_3x2();
        let mut once = Vec::new();
        let (w1, h1) = rotate_bgra(&original, 3, 2, Rotation::Rotate180, &mut once);
        assert_eq!((w1, h1), (3, 2));
        // Top-left (0, 0) of 180-rotated comes from bottom-right (2, 1) of original.
        assert_eq!(&once[0..4], &[2, 1, 0, 255]);

        let mut twice = Vec::new();
        let (w2, h2) = rotate_bgra(&once, w1, h1, Rotation::Rotate180, &mut twice);
        assert_eq!((w2, h2), (3, 2));
        assert_eq!(twice, original);
    }
}
