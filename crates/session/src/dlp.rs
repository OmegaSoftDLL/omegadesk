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
}
