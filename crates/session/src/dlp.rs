//! Data Loss Prevention (`DLP`), clipboard direction/size controls, keystroke rate
//! limiting, screen region redaction, and dynamic session watermarking.
//!
//! Reference implementations:
//! - `kasmtech_KasmVNC` (`docs/plan.md` §2.10 & §4 Phase 5): outbound/inbound clipboard
//!   byte limits, keystroke rate limiting (`DLP_ClipDelay` / token bucket), blacked-out
//!   screen bounding boxes (`DLP_Region`), and dynamic session watermarking (`user + IP + timestamp`).

use thiserror::Error;

/// Clipboard data flow direction governed by [`DlpPolicy`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClipboardDirection {
    /// Client viewer copying data from the remote host (`server -> client`).
    HostToClient,
    /// Client viewer pasting data into the remote host (`client -> server`).
    ClientToHost,
}

/// Rectangular screen region (`x, y, width, height`) to redact before encoding (`KasmVNC` `DLP_Region`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RedactedRegion {
    /// Left X coordinate in pixels.
    pub x: u32,
    /// Top Y coordinate in pixels.
    pub y: u32,
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels.
    pub height: u32,
}

/// Policy violation reported by [`DlpEnforcer`].
#[derive(Debug, Error, PartialEq, Eq)]
pub enum DlpViolation {
    /// Clipboard transfer in the given direction is disabled by policy.
    #[error("clipboard direction {0:?} is blocked by DLP policy")]
    ClipboardDirectionBlocked(ClipboardDirection),
    /// Clipboard payload exceeds the maximum permitted byte count for this direction.
    #[error("clipboard payload of {actual} bytes exceeds DLP limit of {max_bytes} bytes")]
    ClipboardSizeExceeded {
        /// Allowed byte count.
        max_bytes: usize,
        /// Attempted byte count.
        actual: usize,
    },
    /// Keystroke injection rate exceeded the token-bucket limit.
    #[error("keystroke rate limit exceeded")]
    KeystrokeRateLimited,
}

/// Per-session Data Loss Prevention policy (`KasmVNC` DLP settings).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DlpPolicy {
    /// Maximum bytes allowed per `HostToClient` clipboard copy (`0` blocks completely).
    pub max_copy_from_host_bytes: usize,
    /// Maximum bytes allowed per `ClientToHost` clipboard paste (`0` blocks completely).
    pub max_paste_to_host_bytes: usize,
    /// Maximum keystrokes permitted per second (`0` disables rate limiting).
    pub max_keystrokes_per_sec: u32,
    /// Screen regions that must be zeroed/blacked out prior to frame encoding.
    pub redacted_regions: Vec<RedactedRegion>,
}

impl Default for DlpPolicy {
    fn default() -> Self {
        Self {
            max_copy_from_host_bytes: 65_536,
            max_paste_to_host_bytes: 65_536,
            max_keystrokes_per_sec: 50,
            redacted_regions: Vec::new(),
        }
    }
}

/// Stateful DLP enforcer tracking clipboard transfers and keystroke token buckets.
#[derive(Debug, Clone)]
pub struct DlpEnforcer {
    policy: DlpPolicy,
    window_start_ms: u64,
    keystrokes_in_window: u32,
}

impl DlpEnforcer {
    /// Creates a new [`DlpEnforcer`] for `policy`.
    #[must_use]
    pub const fn new(policy: DlpPolicy) -> Self {
        Self {
            policy,
            window_start_ms: 0,
            keystrokes_in_window: 0,
        }
    }

    /// Returns a reference to the active [`DlpPolicy`].
    #[must_use]
    pub const fn policy(&self) -> &DlpPolicy {
        &self.policy
    }

    /// Validates a clipboard transfer of `payload_len` bytes in `direction`.
    ///
    /// # Errors
    ///
    /// Returns [`DlpViolation`] if the direction is disabled or `payload_len` exceeds the limit.
    pub const fn check_clipboard(
        &self,
        direction: ClipboardDirection,
        payload_len: usize,
    ) -> Result<(), DlpViolation> {
        let limit = match direction {
            ClipboardDirection::HostToClient => self.policy.max_copy_from_host_bytes,
            ClipboardDirection::ClientToHost => self.policy.max_paste_to_host_bytes,
        };
        if limit == 0 {
            return Err(DlpViolation::ClipboardDirectionBlocked(direction));
        }
        if payload_len > limit {
            return Err(DlpViolation::ClipboardSizeExceeded {
                max_bytes: limit,
                actual: payload_len,
            });
        }
        Ok(())
    }

    /// Validates and records a keystroke event at `now_ms`.
    ///
    /// # Errors
    ///
    /// Returns [`DlpViolation::KeystrokeRateLimited`] if the 1-second window budget is exhausted.
    pub fn check_keystroke(&mut self, now_ms: u64) -> Result<(), DlpViolation> {
        if self.policy.max_keystrokes_per_sec == 0 {
            return Ok(());
        }
        if now_ms.saturating_sub(self.window_start_ms) >= 1_000 {
            self.window_start_ms = now_ms;
            self.keystrokes_in_window = 0;
        }
        if self.keystrokes_in_window >= self.policy.max_keystrokes_per_sec {
            return Err(DlpViolation::KeystrokeRateLimited);
        }
        self.keystrokes_in_window += 1;
        Ok(())
    }
}

/// Blanks out `region` in a `BGRA8` frame buffer (`frame_width x frame_height`) with opaque black
/// pixels (`[0, 0, 0, 255]`) so restricted on-screen areas never leave the host (`KasmVNC` `DLP_Region`).
pub fn redact_bgra_region(
    bgra_frame: &mut [u8],
    frame_width: u32,
    frame_height: u32,
    region: RedactedRegion,
) {
    let x_start = region.x.min(frame_width);
    let y_start = region.y.min(frame_height);
    let x_end = region.x.saturating_add(region.width).min(frame_width);
    let y_end = region.y.saturating_add(region.height).min(frame_height);

    let stride = (frame_width as usize) * 4;
    for row in y_start..y_end {
        let row_offset = (row as usize) * stride;
        for col in x_start..x_end {
            let px = row_offset + (col as usize) * 4;
            if px + 4 <= bgra_frame.len() {
                bgra_frame[px] = 0;
                bgra_frame[px + 1] = 0;
                bgra_frame[px + 2] = 0;
                bgra_frame[px + 3] = 255;
            }
        }
    }
}

/// Configuration for dynamic forensic session watermarks (`KasmVNC` & `JumpServer`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatermarkConfig {
    /// Authenticated operator identifier.
    pub user_id: String,
    /// Operator source IP address.
    pub client_ip: String,
    /// Session identifier.
    pub session_id: String,
    /// Opacity alpha (`0..=255`).
    pub opacity: u8,
}

/// Rendered watermark overlay metadata for a specific video frame timestamp.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatermarkOverlay {
    /// Formatted multi-field watermark text (`"user | ip | session | timestamp"`).
    pub text: String,
    /// Opacity alpha (`0..=255`).
    pub opacity: u8,
}

impl WatermarkConfig {
    /// Generates the dynamic [`WatermarkOverlay`] for `timestamp_ms`.
    #[must_use]
    pub fn build_overlay(&self, timestamp_ms: u64) -> WatermarkOverlay {
        WatermarkOverlay {
            text: format!(
                "{} | {} | {} | {}",
                self.user_id, self.client_ip, self.session_id, timestamp_ms
            ),
            opacity: self.opacity,
        }
    }
}

/// Width of a glyph of the built-in watermark font, in font pixels.
pub const WATERMARK_GLYPH_WIDTH: u32 = 5;
/// Height of a glyph of the built-in watermark font, in font pixels.
pub const WATERMARK_GLYPH_HEIGHT: u32 = 7;
/// Horizontal advance per glyph (one pixel of spacing), in font pixels.
const WATERMARK_GLYPH_ADVANCE: u32 = WATERMARK_GLYPH_WIDTH + 1;
/// Distance of the overlay from the frame edges, in frame pixels.
const WATERMARK_MARGIN: u32 = 8;

/// 5x7 bitmap glyph: one row per entry, bit 4 is the leftmost pixel.
///
/// KasmVNC renders `DLP_WatermarkText` with FreeType (`common/rfb/Watermark.cxx`) and
/// repeats the rendered bitmap across the frame; a fixed bitmap font keeps the dependency
/// surface and the per-frame cost minimal while remaining legible after H.264 encoding.
#[allow(clippy::too_many_lines, reason = "one match arm per supported glyph")]
const fn glyph(ch: char) -> Option<[u8; 7]> {
    Some(match ch {
        '0' => [
            0b01110, 0b10001, 0b10011, 0b10101, 0b11001, 0b10001, 0b01110,
        ],
        '1' => [
            0b00100, 0b01100, 0b00100, 0b00100, 0b00100, 0b00100, 0b01110,
        ],
        '2' => [
            0b01110, 0b10001, 0b00001, 0b00010, 0b00100, 0b01000, 0b11111,
        ],
        '3' => [
            0b11111, 0b00010, 0b00100, 0b00010, 0b00001, 0b10001, 0b01110,
        ],
        '4' => [
            0b00010, 0b00110, 0b01010, 0b10010, 0b11111, 0b00010, 0b00010,
        ],
        '5' => [
            0b11111, 0b10000, 0b11110, 0b00001, 0b00001, 0b10001, 0b01110,
        ],
        '6' => [
            0b00110, 0b01000, 0b10000, 0b11110, 0b10001, 0b10001, 0b01110,
        ],
        '7' => [
            0b11111, 0b00001, 0b00010, 0b00100, 0b01000, 0b01000, 0b01000,
        ],
        '8' => [
            0b01110, 0b10001, 0b10001, 0b01110, 0b10001, 0b10001, 0b01110,
        ],
        '9' => [
            0b01110, 0b10001, 0b10001, 0b01111, 0b00001, 0b00010, 0b01100,
        ],
        'A' => [
            0b01110, 0b10001, 0b10001, 0b11111, 0b10001, 0b10001, 0b10001,
        ],
        'B' => [
            0b11110, 0b10001, 0b10001, 0b11110, 0b10001, 0b10001, 0b11110,
        ],
        'C' => [
            0b01110, 0b10001, 0b10000, 0b10000, 0b10000, 0b10001, 0b01110,
        ],
        'D' => [
            0b11100, 0b10010, 0b10001, 0b10001, 0b10001, 0b10010, 0b11100,
        ],
        'E' => [
            0b11111, 0b10000, 0b10000, 0b11110, 0b10000, 0b10000, 0b11111,
        ],
        'F' => [
            0b11111, 0b10000, 0b10000, 0b11110, 0b10000, 0b10000, 0b10000,
        ],
        'G' => [
            0b01110, 0b10001, 0b10000, 0b10111, 0b10001, 0b10001, 0b01111,
        ],
        'H' => [
            0b10001, 0b10001, 0b10001, 0b11111, 0b10001, 0b10001, 0b10001,
        ],
        'I' => [
            0b01110, 0b00100, 0b00100, 0b00100, 0b00100, 0b00100, 0b01110,
        ],
        'J' => [
            0b00111, 0b00010, 0b00010, 0b00010, 0b00010, 0b10010, 0b01100,
        ],
        'K' => [
            0b10001, 0b10010, 0b10100, 0b11000, 0b10100, 0b10010, 0b10001,
        ],
        'L' => [
            0b10000, 0b10000, 0b10000, 0b10000, 0b10000, 0b10000, 0b11111,
        ],
        'M' => [
            0b10001, 0b11011, 0b10101, 0b10101, 0b10001, 0b10001, 0b10001,
        ],
        'N' => [
            0b10001, 0b10001, 0b11001, 0b10101, 0b10011, 0b10001, 0b10001,
        ],
        'O' => [
            0b01110, 0b10001, 0b10001, 0b10001, 0b10001, 0b10001, 0b01110,
        ],
        'P' => [
            0b11110, 0b10001, 0b10001, 0b11110, 0b10000, 0b10000, 0b10000,
        ],
        'Q' => [
            0b01110, 0b10001, 0b10001, 0b10001, 0b10101, 0b10010, 0b01101,
        ],
        'R' => [
            0b11110, 0b10001, 0b10001, 0b11110, 0b10100, 0b10010, 0b10001,
        ],
        'S' => [
            0b01111, 0b10000, 0b10000, 0b01110, 0b00001, 0b00001, 0b11110,
        ],
        'T' => [
            0b11111, 0b00100, 0b00100, 0b00100, 0b00100, 0b00100, 0b00100,
        ],
        'U' => [
            0b10001, 0b10001, 0b10001, 0b10001, 0b10001, 0b10001, 0b01110,
        ],
        'V' => [
            0b10001, 0b10001, 0b10001, 0b10001, 0b10001, 0b01010, 0b00100,
        ],
        'W' => [
            0b10001, 0b10001, 0b10001, 0b10101, 0b10101, 0b10101, 0b01010,
        ],
        'X' => [
            0b10001, 0b10001, 0b01010, 0b00100, 0b01010, 0b10001, 0b10001,
        ],
        'Y' => [
            0b10001, 0b10001, 0b10001, 0b01010, 0b00100, 0b00100, 0b00100,
        ],
        'Z' => [
            0b11111, 0b00001, 0b00010, 0b00100, 0b01000, 0b10000, 0b11111,
        ],
        ' ' => [0; 7],
        '|' => [0b00100; 7],
        '.' => [0, 0, 0, 0, 0, 0b01100, 0b01100],
        ':' => [0, 0b01100, 0b01100, 0, 0b01100, 0b01100, 0],
        '-' => [0, 0, 0, 0b11111, 0, 0, 0],
        '_' => [0, 0, 0, 0, 0, 0, 0b11111],
        '@' => [
            0b01110, 0b10001, 0b00001, 0b01101, 0b10101, 0b10101, 0b01110,
        ],
        '/' => [
            0b00001, 0b00010, 0b00010, 0b00100, 0b01000, 0b01000, 0b10000,
        ],
        _ => return None,
    })
}

/// Width in frame pixels of `text` rendered at `scale`.
#[must_use]
pub fn watermark_text_width(text: &str, scale: u32) -> u32 {
    let glyphs = u32::try_from(text.chars().count()).unwrap_or(u32::MAX);
    glyphs
        .saturating_mul(WATERMARK_GLYPH_ADVANCE)
        .saturating_sub(1)
        .saturating_mul(scale.max(1))
}

/// Composes `overlay` into a `BGRA8` frame (`width x height`, tightly packed) before encoding:
/// the text is drawn twice, in the top-left and bottom-right corners, as white pixels blended
/// with `overlay.opacity` (KasmVNC `DLP_WatermarkText`, `common/rfb/Watermark.cxx`). Lowercase
/// letters are drawn as capitals and characters outside the font as a dotted box.
///
/// Cost: the text covers `len * 6 * 7 * scale²` frame pixels per copy (about 17 000 pixels for
/// a 60-character overlay at `scale = 2`, under 0.1 % of a 1080p frame), each a 4-byte
/// read-modify-write. The expensive part is upstream: when a frame carries a GPU texture the
/// agent must drop it so the watermarked CPU pixels are what gets encoded, giving up the
/// zero-copy encode path for watermarked sessions.
pub fn render_watermark_bgra(
    bgra_frame: &mut [u8],
    width: u32,
    height: u32,
    overlay: &WatermarkOverlay,
    scale: u32,
) {
    let scale = scale.max(1);
    let text_width = watermark_text_width(&overlay.text, scale);
    let text_height = WATERMARK_GLYPH_HEIGHT * scale;
    if overlay.opacity == 0 || width < text_width + 2 * WATERMARK_MARGIN || height < text_height {
        return;
    }
    let origins = [
        (WATERMARK_MARGIN, WATERMARK_MARGIN),
        (
            width - text_width - WATERMARK_MARGIN,
            height.saturating_sub(text_height + WATERMARK_MARGIN),
        ),
    ];
    for (origin_x, origin_y) in origins {
        let mut pen_x = origin_x;
        for ch in overlay.text.chars() {
            let rows = glyph(ch.to_ascii_uppercase())
                .unwrap_or([0b10101, 0, 0b10001, 0, 0b10001, 0, 0b10101]);
            for (row_index, row) in rows.iter().enumerate() {
                for col in 0..WATERMARK_GLYPH_WIDTH {
                    if row & (1 << (WATERMARK_GLYPH_WIDTH - 1 - col)) == 0 {
                        continue;
                    }
                    let px = pen_x + col * scale;
                    let py = origin_y + u32::try_from(row_index).unwrap_or(0) * scale;
                    for dy in 0..scale {
                        for dx in 0..scale {
                            blend_white(
                                bgra_frame,
                                width,
                                height,
                                px + dx,
                                py + dy,
                                overlay.opacity,
                            );
                        }
                    }
                }
            }
            pen_x += WATERMARK_GLYPH_ADVANCE * scale;
        }
    }
}

/// Pixels a watermark overwrote, so the frame can be restored after encoding and reused
/// (the capture loop keeps the last frame to re-encode it on a keyframe request; without the
/// restore, each re-encode would stamp a second, differently timestamped text on top).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatermarkPatch {
    rects: Vec<SavedRect>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SavedRect {
    x: u32,
    y: u32,
    width: u32,
    height: u32,
    bgra: Vec<u8>,
}

impl WatermarkPatch {
    /// Writes the saved pixels back into `bgra_frame` (`frame_width` pixels per row).
    pub fn restore(&self, bgra_frame: &mut [u8], frame_width: u32) {
        let stride = frame_width as usize * 4;
        for rect in &self.rects {
            let row_bytes = rect.width as usize * 4;
            for row in 0..rect.height as usize {
                let dst = (rect.y as usize + row) * stride + rect.x as usize * 4;
                let src = row * row_bytes;
                if let (Some(dst), Some(src)) = (
                    bgra_frame.get_mut(dst..dst + row_bytes),
                    rect.bgra.get(src..src + row_bytes),
                ) {
                    dst.copy_from_slice(src);
                }
            }
        }
    }
}

/// [`render_watermark_bgra`] that first saves the pixels under both text boxes and returns
/// them as a [`WatermarkPatch`]. The saved area is `2 * text width * text height` pixels
/// (about 80 KiB for a 60-character overlay at `scale = 2`).
#[must_use]
pub fn apply_watermark_bgra(
    bgra_frame: &mut [u8],
    width: u32,
    height: u32,
    overlay: &WatermarkOverlay,
    scale: u32,
) -> WatermarkPatch {
    let scale = scale.max(1);
    let text_width = watermark_text_width(&overlay.text, scale);
    let text_height = WATERMARK_GLYPH_HEIGHT * scale;
    let mut rects = Vec::new();
    if overlay.opacity != 0 && width >= text_width + 2 * WATERMARK_MARGIN && height >= text_height {
        let origins = [
            (WATERMARK_MARGIN, WATERMARK_MARGIN),
            (
                width - text_width - WATERMARK_MARGIN,
                height.saturating_sub(text_height + WATERMARK_MARGIN),
            ),
        ];
        let stride = width as usize * 4;
        for (x, y) in origins {
            let row_bytes = text_width as usize * 4;
            let mut saved = Vec::with_capacity(row_bytes * text_height as usize);
            for row in 0..text_height as usize {
                let start = (y as usize + row) * stride + x as usize * 4;
                if let Some(pixels) = bgra_frame.get(start..start + row_bytes) {
                    saved.extend_from_slice(pixels);
                }
            }
            rects.push(SavedRect {
                x,
                y,
                width: text_width,
                height: text_height,
                bgra: saved,
            });
        }
    }
    render_watermark_bgra(bgra_frame, width, height, overlay, scale);
    WatermarkPatch { rects }
}

/// Blends an opaque white pixel with `alpha` into `(x, y)`; out-of-range coordinates are ignored.
fn blend_white(bgra_frame: &mut [u8], width: u32, height: u32, x: u32, y: u32, alpha: u8) {
    if x >= width || y >= height {
        return;
    }
    let offset = (y as usize * width as usize + x as usize) * 4;
    let Some(pixel) = bgra_frame.get_mut(offset..offset + 4) else {
        return;
    };
    let alpha = u16::from(alpha);
    for channel in &mut pixel[..3] {
        let value = u16::from(*channel);
        // value + (255 - value) * alpha / 255, rounded.
        *channel = u8::try_from(value + ((255 - value) * alpha + 127) / 255).unwrap_or(255);
    }
    pixel[3] = 255;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dlp_enforces_clipboard_keystrokes_redaction_and_watermark() {
        let policy = DlpPolicy {
            max_copy_from_host_bytes: 0,
            max_paste_to_host_bytes: 16,
            max_keystrokes_per_sec: 2,
            redacted_regions: vec![RedactedRegion {
                x: 0,
                y: 0,
                width: 2,
                height: 2,
            }],
        };
        let mut enforcer = DlpEnforcer::new(policy);

        assert_eq!(
            enforcer.check_clipboard(ClipboardDirection::HostToClient, 4),
            Err(DlpViolation::ClipboardDirectionBlocked(
                ClipboardDirection::HostToClient
            ))
        );
        assert!(
            enforcer
                .check_clipboard(ClipboardDirection::ClientToHost, 12)
                .is_ok()
        );
        assert!(
            enforcer
                .check_clipboard(ClipboardDirection::ClientToHost, 32)
                .is_err()
        );

        assert!(enforcer.check_keystroke(1_000).is_ok());
        assert!(enforcer.check_keystroke(1_100).is_ok());
        assert_eq!(
            enforcer.check_keystroke(1_200),
            Err(DlpViolation::KeystrokeRateLimited)
        );
        assert!(enforcer.check_keystroke(2_100).is_ok());

        let mut frame = vec![200u8; 4 * 4 * 4];
        redact_bgra_region(
            &mut frame,
            4,
            4,
            RedactedRegion {
                x: 0,
                y: 0,
                width: 2,
                height: 1,
            },
        );
        assert_eq!(&frame[0..4], &[0, 0, 0, 255]);
        assert_eq!(&frame[8..12], &[200, 200, 200, 200]);

        let wm = WatermarkConfig {
            user_id: "alice".to_owned(),
            client_ip: "100.64.0.5".to_owned(),
            session_id: "sess-42".to_owned(),
            opacity: 64,
        };
        let overlay = wm.build_overlay(99_000);
        assert_eq!(overlay.text, "alice | 100.64.0.5 | sess-42 | 99000");
    }

    /// The watermark lands in both corners, only where glyph pixels are set, and blends with
    /// the configured opacity; a frame too small for the text is left untouched.
    #[test]
    fn watermark_renders_in_both_corners_with_opacity() {
        let overlay = WatermarkOverlay {
            text: "A".to_owned(),
            opacity: 255,
        };
        let (width, height) = (64u32, 32u32);
        let mut frame = vec![0u8; (width * height * 4) as usize];
        render_watermark_bgra(&mut frame, width, height, &overlay, 1);
        let pixel = |x: u32, y: u32| {
            let offset = ((y * width + x) * 4) as usize;
            frame[offset..offset + 4].to_vec()
        };
        // Top-left copy at the 8-pixel margin: glyph 'A' row 0 is `01110`.
        assert_eq!(
            pixel(8, 8),
            vec![0, 0, 0, 0],
            "corner of the glyph box is empty"
        );
        assert_eq!(pixel(9, 8), vec![255, 255, 255, 255]);
        assert_eq!(pixel(10, 8), vec![255, 255, 255, 255]);
        assert_eq!(pixel(12, 8), vec![0, 0, 0, 0]);
        // Row 3 is `11111`.
        assert_eq!(pixel(8, 11), vec![255, 255, 255, 255]);
        // Bottom-right copy: x = 64 - 5 - 8 = 51, y = 32 - 7 - 8 = 17.
        assert_eq!(pixel(52, 17), vec![255, 255, 255, 255]);
        assert_eq!(pixel(51, 20), vec![255, 255, 255, 255]);
        // Nothing elsewhere.
        assert_eq!(pixel(30, 15), vec![0, 0, 0, 0]);

        // Half opacity over mid-grey blends instead of overwriting.
        let half = WatermarkOverlay {
            text: "|".to_owned(),
            opacity: 128,
        };
        let mut grey = vec![100u8; (width * height * 4) as usize];
        render_watermark_bgra(&mut grey, width, height, &half, 2);
        let offset = ((8 * width + (8 + 2 * 2)) * 4) as usize;
        assert_eq!(&grey[offset..offset + 3], &[178, 178, 178]);
        assert_eq!(grey[offset + 3], 255);
        assert_eq!(watermark_text_width("abc", 2), (3 * 6 - 1) * 2);

        // Too narrow for the text: untouched.
        let mut tiny = vec![7u8; 16 * 16 * 4];
        render_watermark_bgra(&mut tiny, 16, 16, &overlay, 1);
        assert!(tiny.iter().all(|b| *b == 7));

        // apply + restore leaves the frame exactly as it was.
        let original: Vec<u8> = (0..(width * height * 4)).map(|i| (i % 251) as u8).collect();
        let mut frame = original.clone();
        let patch = apply_watermark_bgra(&mut frame, width, height, &overlay, 2);
        assert_ne!(frame, original, "the watermark changed pixels");
        patch.restore(&mut frame, width);
        assert_eq!(frame, original);
    }
}
