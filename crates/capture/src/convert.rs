//! Pixel layout conversion shared by the Linux and macOS backends: X11 `ZPixmap`,
//! PipeWire raw video and CoreGraphics bitmaps all deliver 32-bit pixels, but in four
//! possible byte orders and with padded rows. [`Frame`](crate::Frame) wants tightly packed
//! `BGRA` with an opaque alpha channel.

/// Byte order of a 32-bit pixel in memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PixelLayout {
    /// `[B, G, R, X]`: X11 little-endian `TrueColor` with `0x00ff_0000` red mask, PipeWire
    /// `BGRx`/`BGRA`, CoreGraphics `kCGBitmapByteOrder32Little` with alpha first.
    Bgrx,
    /// `[R, G, B, X]`: PipeWire `RGBx`/`RGBA`, CoreGraphics big-endian with alpha last.
    Rgbx,
    /// `[X, R, G, B]`: X11 big-endian servers, CoreGraphics big-endian with alpha first.
    Xrgb,
    /// `[X, B, G, R]`: CoreGraphics little-endian with alpha last.
    Xbgr,
}

impl PixelLayout {
    /// Positions of the blue, green and red bytes inside a pixel.
    #[must_use]
    pub const fn bgr_offsets(self) -> (usize, usize, usize) {
        match self {
            Self::Bgrx => (0, 1, 2),
            Self::Rgbx => (2, 1, 0),
            Self::Xrgb => (3, 2, 1),
            Self::Xbgr => (1, 2, 3),
        }
    }

    /// Layout of an X11 `TrueColor` visual from its channel masks and the server's image
    /// byte order (`true` for LSB-first). Only 8-bit contiguous masks are supported.
    #[must_use]
    pub fn from_x11_masks(red_mask: u32, blue_mask: u32, lsb_first: bool) -> Option<Self> {
        match (red_mask, blue_mask, lsb_first) {
            (0x00ff_0000, 0x0000_00ff, true) => Some(Self::Bgrx),
            (0x0000_00ff, 0x00ff_0000, true) => Some(Self::Rgbx),
            (0x00ff_0000, 0x0000_00ff, false) => Some(Self::Xrgb),
            (0x0000_00ff, 0x00ff_0000, false) => Some(Self::Xbgr),
            _ => None,
        }
    }
}

/// Converts `height` rows of `width` 32-bit pixels laid out as `layout`, `stride` bytes
/// apart, into tightly packed opaque `BGRA`.
///
/// Returns `None` when `src` is too short for the described image.
#[must_use]
pub fn rows_to_bgra(
    src: &[u8],
    width: usize,
    height: usize,
    stride: usize,
    layout: PixelLayout,
) -> Option<Vec<u8>> {
    let row_bytes = width.checked_mul(4)?;
    if stride < row_bytes {
        return None;
    }
    if height > 0 {
        let needed = height
            .checked_sub(1)
            .and_then(|rows| rows.checked_mul(stride))
            .and_then(|full_rows| full_rows.checked_add(row_bytes))?;
        if src.len() < needed {
            return None;
        }
    }
    let (b, g, r) = layout.bgr_offsets();
    let mut out = vec![0u8; row_bytes * height];
    for (row, dst_row) in out.chunks_exact_mut(row_bytes).enumerate() {
        let src_row = &src[row * stride..row * stride + row_bytes];
        let (dst_pixels, _) = dst_row.as_chunks_mut::<4>();
        let (src_pixels, _) = src_row.as_chunks::<4>();
        for (dst, px) in dst_pixels.iter_mut().zip(src_pixels) {
            dst[0] = px[b];
            dst[1] = px[g];
            dst[2] = px[r];
            dst[3] = 0xFF;
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_layout_lands_in_bgra_with_opaque_alpha() {
        // One pixel: B=0x10 G=0x20 R=0x30, X=0x00 wherever the layout puts it.
        let cases = [
            (PixelLayout::Bgrx, [0x10, 0x20, 0x30, 0x00]),
            (PixelLayout::Rgbx, [0x30, 0x20, 0x10, 0x00]),
            (PixelLayout::Xrgb, [0x00, 0x30, 0x20, 0x10]),
            (PixelLayout::Xbgr, [0x00, 0x10, 0x20, 0x30]),
        ];
        for (layout, px) in cases {
            let out = rows_to_bgra(&px, 1, 1, 4, layout).unwrap();
            assert_eq!(out, [0x10, 0x20, 0x30, 0xFF], "{layout:?}");
        }
    }

    #[test]
    fn padded_rows_are_tightened() {
        // 2x2 image, stride 12 (4 bytes of padding per row).
        let mut src = Vec::new();
        for row in 0..2u8 {
            for col in 0..2u8 {
                src.extend_from_slice(&[row, col, 0xAA, 0]);
            }
            src.extend_from_slice(&[0xEE; 4]);
        }
        let out = rows_to_bgra(&src, 2, 2, 12, PixelLayout::Bgrx).unwrap();
        assert_eq!(out.len(), 16);
        assert_eq!(&out[..4], &[0, 0, 0xAA, 0xFF]);
        assert_eq!(&out[4..8], &[0, 1, 0xAA, 0xFF]);
        assert_eq!(&out[8..12], &[1, 0, 0xAA, 0xFF]);
        assert_eq!(&out[12..], &[1, 1, 0xAA, 0xFF]);
        // The last row may omit the padding.
        assert!(rows_to_bgra(&src[..20], 2, 2, 12, PixelLayout::Bgrx).is_some());
        assert!(rows_to_bgra(&src[..19], 2, 2, 12, PixelLayout::Bgrx).is_none());
        assert!(rows_to_bgra(&src, 2, 2, 4, PixelLayout::Bgrx).is_none());
    }

    #[test]
    fn x11_masks_select_the_layout() {
        assert_eq!(
            PixelLayout::from_x11_masks(0x00ff_0000, 0x0000_00ff, true),
            Some(PixelLayout::Bgrx)
        );
        assert_eq!(
            PixelLayout::from_x11_masks(0x00ff_0000, 0x0000_00ff, false),
            Some(PixelLayout::Xrgb)
        );
        assert_eq!(
            PixelLayout::from_x11_masks(0x0000_00ff, 0x00ff_0000, true),
            Some(PixelLayout::Rgbx)
        );
        assert_eq!(PixelLayout::from_x11_masks(0xf800, 0x001f, true), None);
    }
}
