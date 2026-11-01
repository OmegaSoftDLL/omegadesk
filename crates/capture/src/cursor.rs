//! Software cursor compositing for DXGI Desktop Duplication frames.
//!
//! DXGI Desktop Duplication does not draw the hardware mouse cursor into the
//! desktop texture by default; instead, it reports cursor position and shape
//! updates in `DXGI_OUTDUPL_FRAME_INFO` and `IDXGIOutputDuplication::GetFramePointerShape`.
//!
//! Following Sunshine (`src/platform/windows/display_ram.cpp`), we cache the
//! latest cursor shape and position and composite all three DXGI pointer shape
//! formats (`MONOCHROME`, `COLOR`, and `MASKED_COLOR`) onto the captured BGRA
//! frame, clipping cleanly at screen edges.

/// Pixel format of a cursor shape reported by DXGI Desktop Duplication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CursorKind {
    /// 1-bit per pixel AND mask stacked above a 1-bit per pixel XOR mask
    /// (`DXGI_OUTDUPL_POINTER_SHAPE_TYPE_MONOCHROME`). `height` is the height
    /// of a single mask (half of the raw `DXGI_OUTDUPL_POINTER_SHAPE_INFO::Height`).
    Monochrome,
    /// 32-bit per pixel premultiplied BGRA (`DXGI_OUTDUPL_POINTER_SHAPE_TYPE_COLOR`).
    Color,
    /// 32-bit per pixel BGRA where the alpha byte acts as a replace/XOR mask
    /// (`DXGI_OUTDUPL_POINTER_SHAPE_TYPE_MASKED_COLOR`).
    MaskedColor,
}

/// Cached cursor image obtained from `GetFramePointerShape`.
#[derive(Debug, Clone)]
pub struct CursorShape {
    /// Cursor pixel format.
    pub kind: CursorKind,
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels (already halved for [`CursorKind::Monochrome`]).
    pub height: u32,
    /// Row stride in bytes.
    pub pitch: u32,
    /// Raw shape buffer from DXGI.
    pub data: Vec<u8>,
}

/// Latest cursor state (position, visibility, and shape) for a monitor.
#[derive(Debug, Clone, Default)]
pub struct CursorState {
    /// Top-left x coordinate of the cursor image in desktop-rotated monitor coordinates.
    pub x: i32,
    /// Top-left y coordinate of the cursor image in desktop-rotated monitor coordinates.
    pub y: i32,
    /// Whether the cursor is currently visible on this monitor.
    pub visible: bool,
    /// Most recently received cursor shape, if any.
    pub shape: Option<CursorShape>,
}

/// Composites a single cursor pixel `(cx, cy)` onto `dst_pixel`.
fn blend_cursor_pixel(shape: &CursorShape, cx: usize, cy: usize, dst_pixel: &mut [u8]) {
    let pitch = shape.pitch as usize;
    match shape.kind {
        CursorKind::Monochrome => {
            let and_row = cy * pitch;
            let xor_row = (cy + shape.height as usize) * pitch;
            let byte_idx = cx >> 3;
            let mask = 1u8 << (7 - (cx & 7));
            let Some(&and_byte) = shape.data.get(and_row + byte_idx) else {
                return;
            };
            let Some(&xor_byte) = shape.data.get(xor_row + byte_idx) else {
                return;
            };
            match ((and_byte & mask) != 0, (xor_byte & mask) != 0) {
                (false, false) => dst_pixel.copy_from_slice(&[0, 0, 0, 255]),
                (false, true) => dst_pixel.copy_from_slice(&[255, 255, 255, 255]),
                (true, false) => {}
                (true, true) => {
                    dst_pixel[0] ^= 0xFF;
                    dst_pixel[1] ^= 0xFF;
                    dst_pixel[2] ^= 0xFF;
                }
            }
        }
        CursorKind::Color => {
            let src_idx = cy * pitch + cx * 4;
            let Some(src_pixel) = shape.data.get(src_idx..src_idx + 4) else {
                return;
            };
            let alpha = u16::from(src_pixel[3]);
            if alpha == 255 {
                dst_pixel.copy_from_slice(src_pixel);
            } else if alpha > 0 {
                let inv = 255 - alpha;
                for c in 0..3 {
                    let bg = (u16::from(dst_pixel[c]) * inv + 127) / 255;
                    #[allow(clippy::cast_possible_truncation)]
                    let blended = src_pixel[c].saturating_add(bg as u8);
                    dst_pixel[c] = blended;
                }
                dst_pixel[3] = 255;
            }
        }
        CursorKind::MaskedColor => {
            let src_idx = cy * pitch + cx * 4;
            let Some(src_pixel) = shape.data.get(src_idx..src_idx + 4) else {
                return;
            };
            if src_pixel[3] != 0 {
                dst_pixel[0] ^= src_pixel[0];
                dst_pixel[1] ^= src_pixel[1];
                dst_pixel[2] ^= src_pixel[2];
            } else {
                dst_pixel[0] = src_pixel[0];
                dst_pixel[1] = src_pixel[1];
                dst_pixel[2] = src_pixel[2];
                dst_pixel[3] = 255;
            }
        }
    }
}

/// Composites `cursor` onto a tightly packed `frame_width` × `frame_height`
/// BGRA buffer (`bgra`). Does nothing if the cursor is hidden, has no shape,
/// or lies completely outside the frame.
pub fn blend_cursor(bgra: &mut [u8], frame_width: u32, frame_height: u32, cursor: &CursorState) {
    if !cursor.visible {
        return;
    }
    let Some(shape) = &cursor.shape else {
        return;
    };
    if shape.width == 0
        || shape.height == 0
        || shape.pitch == 0
        || frame_width == 0
        || frame_height == 0
    {
        return;
    }

    let fw = i64::from(frame_width);
    let fh = i64::from(frame_height);
    let cx0 = i64::from(cursor.x);
    let cy0 = i64::from(cursor.y);
    let dst_x0 = cx0.max(0);
    let dst_y0 = cy0.max(0);
    let dst_x1 = (cx0 + i64::from(shape.width)).min(fw);
    let dst_y1 = (cy0 + i64::from(shape.height)).min(fh);
    if dst_x0 >= dst_x1 || dst_y0 >= dst_y1 {
        return;
    }

    let frame_stride = frame_width as usize * 4;
    for dst_y in dst_y0..dst_y1 {
        let (Ok(cy), Ok(dy)) = (usize::try_from(dst_y - cy0), usize::try_from(dst_y)) else {
            continue;
        };
        for dst_x in dst_x0..dst_x1 {
            let (Ok(cx), Ok(dx)) = (usize::try_from(dst_x - cx0), usize::try_from(dst_x)) else {
                continue;
            };
            let dst_idx = dy * frame_stride + dx * 4;
            if let Some(dst_pixel) = bgra.get_mut(dst_idx..dst_idx + 4) {
                blend_cursor_pixel(shape, cx, cy, dst_pixel);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{CursorKind, CursorShape, CursorState, blend_cursor};

    #[test]
    fn blends_color_cursor_with_clipping() {
        let mut frame = vec![100u8; 4 * 4 * 4];
        let cursor = CursorState {
            x: -1,
            y: -1,
            visible: true,
            shape: Some(CursorShape {
                kind: CursorKind::Color,
                width: 2,
                height: 2,
                pitch: 8,
                // 2x2 opaque blue cursor; only bottom-right pixel (1,1) lands at frame (0,0).
                data: vec![
                    255, 0, 0, 255, 255, 0, 0, 255, // row 0
                    255, 0, 0, 255, 200, 10, 20, 255, // row 1
                ],
            }),
        };
        blend_cursor(&mut frame, 4, 4, &cursor);
        assert_eq!(&frame[0..4], &[200, 10, 20, 255]);
        assert_eq!(&frame[4..8], &[100, 100, 100, 100]);
    }

    #[test]
    fn blends_monochrome_and_xor_masks() {
        // 4x1 frame initialized to gray [128, 128, 128, 255].
        let mut frame = [128, 128, 128, 255].repeat(4);
        // 4x1 monochrome cursor:
        // pixel 0: AND=0, XOR=0 -> black
        // pixel 1: AND=0, XOR=1 -> white
        // pixel 2: AND=1, XOR=0 -> transparent
        // pixel 3: AND=1, XOR=1 -> invert (128 ^ 255 = 127)
        let cursor = CursorState {
            x: 0,
            y: 0,
            visible: true,
            shape: Some(CursorShape {
                kind: CursorKind::Monochrome,
                width: 4,
                height: 1,
                pitch: 1,
                data: vec![
                    0b0011_0000, // AND mask row
                    0b0101_0000, // XOR mask row
                ],
            }),
        };
        blend_cursor(&mut frame, 4, 1, &cursor);
        assert_eq!(&frame[0..4], &[0, 0, 0, 255]);
        assert_eq!(&frame[4..8], &[255, 255, 255, 255]);
        assert_eq!(&frame[8..12], &[128, 128, 128, 255]);
        assert_eq!(&frame[12..16], &[127, 127, 127, 255]);
    }

    #[test]
    fn blends_masked_color_cursor() {
        let mut frame = vec![0x0A, 0x14, 0x1E, 255, 0x0A, 0x14, 0x1E, 255];
        let cursor = CursorState {
            x: 0,
            y: 0,
            visible: true,
            shape: Some(CursorShape {
                kind: CursorKind::MaskedColor,
                width: 2,
                height: 1,
                pitch: 8,
                data: vec![
                    40, 50, 60, 0, // alpha=0 -> replace
                    0xFF, 0x00, 0xFF, 0xFF, // alpha=0xFF -> XOR
                ],
            }),
        };
        blend_cursor(&mut frame, 2, 1, &cursor);
        assert_eq!(&frame[0..4], &[40, 50, 60, 255]);
        assert_eq!(&frame[4..8], &[0x0A ^ 0xFF, 0x14, 0x1E ^ 0xFF, 255]);
    }
}
