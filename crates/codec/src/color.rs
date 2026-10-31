//! Integer BGRA → YUV 4:2:0 color conversion using BT.601 limited range (16–235),
//! matching what OpenH264's `write_rgba8` decoder expects.

/// Converts BGRA into planar I420 (separate Y, U, and V planes).
///
/// `source_width` is the stride in pixels of the input BGRA buffer; `width` and
/// `height` (both even) are the converted dimensions starting from the top-left
/// corner, so an odd-sized capture simply drops its last column or row.
#[must_use]
pub fn bgra_to_i420(
    bgra: &[u8],
    source_width: usize,
    width: usize,
    height: usize,
) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let mut y_plane = vec![0u8; width * height];
    let mut u_plane = vec![0u8; width * height / 4];
    let mut v_plane = vec![0u8; width * height / 4];
    convert(
        bgra,
        source_width,
        width,
        height,
        &mut y_plane,
        |index, u, v| {
            u_plane[index] = u;
            v_plane[index] = v;
        },
    );
    (y_plane, u_plane, v_plane)
}

/// Converts BGRA into semi-planar NV12 (Y plane followed by interleaved U/V)
/// directly inside `destination`, which must be `width * height * 3 / 2` bytes long.
pub fn bgra_to_nv12(
    bgra: &[u8],
    source_width: usize,
    width: usize,
    height: usize,
    destination: &mut [u8],
) {
    let (y_plane, uv_plane) = destination.split_at_mut(width * height);
    convert(bgra, source_width, width, height, y_plane, |index, u, v| {
        uv_plane[index * 2] = u;
        uv_plane[index * 2 + 1] = v;
    });
}

fn convert(
    bgra: &[u8],
    source_width: usize,
    width: usize,
    height: usize,
    y_plane: &mut [u8],
    mut put_chroma: impl FnMut(usize, u8, u8),
) {
    debug_assert!(width.is_multiple_of(2) && height.is_multiple_of(2));
    let stride = source_width * 4;
    for row in (0..height).step_by(2) {
        let top = &bgra[row * stride..][..width * 4];
        let bottom = &bgra[(row + 1) * stride..][..width * 4];
        let (y_top, y_bottom) = y_plane[row * width..(row + 2) * width].split_at_mut(width);
        let chroma_row = row / 2 * (width / 2);

        for col in (0..width).step_by(2) {
            let mut sum_r = 0i32;
            let mut sum_g = 0i32;
            let mut sum_b = 0i32;
            for (line, y_line) in [(top, &mut *y_top), (bottom, &mut *y_bottom)] {
                for dx in 0..2 {
                    let px = (col + dx) * 4;
                    let b = i32::from(line[px]);
                    let g = i32::from(line[px + 1]);
                    let r = i32::from(line[px + 2]);
                    y_line[col + dx] = luma(r, g, b);
                    sum_r += r;
                    sum_g += g;
                    sum_b += b;
                }
            }
            // Average of the 2x2 pixel block with rounding.
            let (r, g, b) = ((sum_r + 2) >> 2, (sum_g + 2) >> 2, (sum_b + 2) >> 2);
            put_chroma(
                chroma_row + col / 2,
                clamp_u8(((-38 * r - 74 * g + 112 * b + 128) >> 8) + 128),
                clamp_u8(((112 * r - 94 * g - 18 * b + 128) >> 8) + 128),
            );
        }
    }
}

fn luma(r: i32, g: i32, b: i32) -> u8 {
    clamp_u8(((66 * r + 129 * g + 25 * b + 128) >> 8) + 16)
}

fn clamp_u8(value: i32) -> u8 {
    u8::try_from(value.clamp(0, 255)).unwrap_or(u8::MAX)
}

#[cfg(test)]
mod tests {
    use super::{bgra_to_i420, bgra_to_nv12};

    #[test]
    fn black_and_white() {
        let white = [255u8; 2 * 2 * 4];
        let (y, u, v) = bgra_to_i420(&white, 2, 2, 2);
        assert!(y.iter().all(|&l| l == 235));
        assert_eq!((u[0], v[0]), (128, 128));

        let black = [0u8, 0, 0, 255].repeat(4);
        let (y, u, v) = bgra_to_i420(&black, 2, 2, 2);
        assert!(y.iter().all(|&l| l == 16));
        assert_eq!((u[0], v[0]), (128, 128));
    }

    #[test]
    fn plane_sizes() {
        let frame = vec![0u8; 8 * 4 * 4];
        let (y, u, v) = bgra_to_i420(&frame, 8, 8, 4);
        assert_eq!((y.len(), u.len(), v.len()), (32, 8, 8));
    }

    #[test]
    fn nv12_matches_i420() {
        let (width, height) = (6, 4);
        let bgra: Vec<u8> = (0..width * height * 4)
            .map(|i| u8::try_from(i * 37 % 256).unwrap())
            .collect();
        let (y, u, v) = bgra_to_i420(&bgra, width, width, height);
        let mut nv12 = vec![0u8; width * height * 3 / 2];
        bgra_to_nv12(&bgra, width, width, height, &mut nv12);
        assert_eq!(&nv12[..y.len()], &y[..]);
        let interleaved: Vec<u8> = u.iter().zip(&v).flat_map(|(a, b)| [*a, *b]).collect();
        assert_eq!(&nv12[y.len()..], &interleaved[..]);
    }

    #[test]
    fn crops_odd_source() {
        // 3x2 image: only the first 2 columns are converted.
        let mut bgra = [0u8; 3 * 2 * 4].to_vec();
        for row in 0..2 {
            bgra[(row * 3 + 2) * 4..][..4].copy_from_slice(&[255, 255, 255, 255]);
        }
        let (y, _, _) = bgra_to_i420(&bgra, 3, 2, 2);
        assert!(
            y.iter().all(|&l| l == 16),
            "cropped white column leaked into output"
        );
    }
}
