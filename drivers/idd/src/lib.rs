//! Windows `IddCx` 1.4 Indirect Display Driver (UMDF 2) device contract, IOCTL
//! framing, and VESA E-EDID 1.4 128-byte block synthesizer (`drivers/idd`).
//!
//! Reference implementations:
//! - `ClassicOldSong_Apollo/src/platform/windows/virtual_display.h` &
//!   `virtual_display.cpp` (`docs/plan.md` §2.3 line 65 & §3 line 223): hardware ID
//!   `Root\OmegaDeskIdd`, device interface GUID, monitor plug-in/plug-out IOCTLs,
//!   and dynamic EDID synthesis for arbitrary client resolutions and refresh rates.

use thiserror::Error;

/// Hardware ID matched by `drivers/idd/omegadesk-idd.inf`.
pub const OMEGADESK_IDD_HARDWARE_ID: &str = r"Root\OmegaDeskIdd";

/// `FILE_DEVICE_VIDEO` (`0x0000_0023`) device type used for `CTL_CODE` definitions.
pub const FILE_DEVICE_VIDEO: u32 = 0x0000_0023;

/// `METHOD_BUFFERED` (`0`) transfer type for UMDF `DeviceIoControl` requests.
pub const METHOD_BUFFERED: u32 = 0;

/// `FILE_WRITE_ACCESS` (`0x0002`) required to mutate virtual monitors.
pub const FILE_WRITE_ACCESS: u32 = 0x0002;

/// Computes a Windows `CTL_CODE(DeviceType, Function, Method, Access)` constant.
#[must_use]
pub const fn ctl_code(device_type: u32, function: u32, method: u32, access: u32) -> u32 {
    (device_type << 16) | (access << 14) | (function << 2) | method
}

/// IOCTL to hot-plug a virtual monitor with a 128-byte VESA EDID block (`Function = 0x801`).
pub const IOCTL_OMEGADESK_IDD_PLUG_IN: u32 =
    ctl_code(FILE_DEVICE_VIDEO, 0x801, METHOD_BUFFERED, FILE_WRITE_ACCESS);

/// IOCTL to hot-unplug a virtual monitor by connector index (`Function = 0x802`).
pub const IOCTL_OMEGADESK_IDD_PLUG_OUT: u32 =
    ctl_code(FILE_DEVICE_VIDEO, 0x802, METHOD_BUFFERED, FILE_WRITE_ACCESS);

/// IOCTL to update the mode list (`width`, `height`, `refresh_millihz`) on an active connector (`Function = 0x803`).
pub const IOCTL_OMEGADESK_IDD_UPDATE_MODES: u32 =
    ctl_code(FILE_DEVICE_VIDEO, 0x803, METHOD_BUFFERED, FILE_WRITE_ACCESS);

/// Size in bytes of a standard VESA E-EDID 1.4 base block.
pub const EDID_BLOCK_SIZE: usize = 128;

/// Errors returned when synthesizing an EDID block or validating an `IddCx` IOCTL payload.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum IddError {
    /// Requested resolution or refresh rate is outside the valid VESA Detailed Timing range.
    #[error("invalid virtual monitor timing: {width}x{height} @ {refresh_hz} Hz")]
    InvalidTiming {
        /// Width in pixels.
        width: u16,
        /// Height in pixels.
        height: u16,
        /// Refresh rate in Hz.
        refresh_hz: u16,
    },
    /// Connector index exceeds the adapter's maximum connector count (`0..16`).
    #[error("connector index {0} exceeds maximum adapter connectors (16)")]
    InvalidConnectorIndex(u32),
}

/// Payload sent with [`IOCTL_OMEGADESK_IDD_PLUG_IN`] to attach a virtual monitor
/// with a synthesized 128-byte VESA E-EDID 1.4 block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IddPlugInRequest {
    /// Adapter connector slot (`0..16`).
    pub connector_index: u32,
    /// Deterministic RFC 4122 v5 per-client monitor UUID bytes (`Apollo` `virtual_display.cpp`).
    pub container_id: [u8; 16],
    /// Synthesized 128-byte VESA E-EDID 1.4 base block.
    pub edid: [u8; EDID_BLOCK_SIZE],
}

impl IddPlugInRequest {
    /// Builds a validated [`IddPlugInRequest`] with a synthesized EDID block for
    /// `width x height @ refresh_hz` and `serial_number`.
    ///
    /// # Errors
    ///
    /// Returns [`IddError`] if `connector_index >= 16` or timing values are out of range.
    pub fn new(
        connector_index: u32,
        container_id: [u8; 16],
        width: u16,
        height: u16,
        refresh_hz: u16,
        serial_number: u32,
    ) -> Result<Self, IddError> {
        if connector_index >= 16 {
            return Err(IddError::InvalidConnectorIndex(connector_index));
        }
        let edid = synthesize_edid_128(width, height, refresh_hz, serial_number)?;
        Ok(Self {
            connector_index,
            container_id,
            edid,
        })
    }
}

/// Synthesizes a standards-compliant 128-byte VESA E-EDID 1.4 base block for an
/// arbitrary client resolution (`width` x `height` in `200..=4095`) and refresh
/// rate (`refresh_hz` in `15..=240` Hz) so Windows `IddCx` exposes the exact
/// native client mode without registry overrides.
///
/// # Errors
///
/// Returns [`IddError::InvalidTiming`] if `width` or `height` is outside `200..=4095`
/// (12-bit Detailed Timing Descriptor limit) or `refresh_hz` is outside `15..=240`.
pub fn synthesize_edid_128(
    width: u16,
    height: u16,
    refresh_hz: u16,
    serial_number: u32,
) -> Result<[u8; EDID_BLOCK_SIZE], IddError> {
    if !(200..=4095).contains(&width)
        || !(200..=4095).contains(&height)
        || !(15..=240).contains(&refresh_hz)
    {
        return Err(IddError::InvalidTiming {
            width,
            height,
            refresh_hz,
        });
    }

    let mut edid = [0u8; EDID_BLOCK_SIZE];

    // 1. Fixed 8-byte VESA EDID 1.4 header (`00 FF FF FF FF FF FF 00`).
    edid[1..7].fill(0xFF);

    // 2. ISA 3-letter Plug-and-Play Manufacturer ID `"OMD"` (`O`=15, `M`=13, `D`=4):
    //    `(15 << 10) | (13 << 5) | 4 = 0x3DA4` big-endian.
    edid[8] = 0x3D;
    edid[9] = 0xA4;

    // Product code (`0x0001` LE) & 32-bit serial number (LE).
    edid[10] = 0x01;
    edid[11] = 0x00;
    edid[12..16].copy_from_slice(&serial_number.to_le_bytes());

    // Manufactured week 44, year 2026 (`2026 - 1990 = 36`).
    edid[16] = 44;
    edid[17] = 36;

    // EDID version 1, revision 4.
    edid[18] = 1;
    edid[19] = 4;

    // Digital input (`0xA5`: DisplayPort, 8 bits per color, RGB444, sRGB, preferred timing in DTD 1).
    edid[20] = 0xA5;
    edid[21] = 52; // 52 cm horizontal
    edid[22] = 29; // 29 cm vertical
    edid[23] = 120; // Gamma 2.20 (`(2.20 * 100) - 100 = 120`)
    edid[24] = 0x06; // Preferred timing mode includes native pixel format

    // 3. Detailed Timing Descriptor #1 at bytes 54..72 (18 bytes).
    // Use reduced blanking (`h_blank = 160`, `v_blank = 45`) to compute pixel clock in 10 kHz units.
    let h_blank: u16 = 160;
    let v_blank: u16 = 45;
    let h_total = u32::from(width) + u32::from(h_blank);
    let v_total = u32::from(height) + u32::from(v_blank);
    let pixel_clock_hz = h_total * v_total * u32::from(refresh_hz);
    let pixel_clock_10khz = u16::try_from((pixel_clock_hz / 10_000).clamp(1, 65_535)).unwrap_or(1);

    let dtd = &mut edid[54..72];
    dtd[0..2].copy_from_slice(&pixel_clock_10khz.to_le_bytes());
    dtd[2] = u8::try_from(width & 0xFF).unwrap_or(0);
    dtd[3] = u8::try_from(h_blank & 0xFF).unwrap_or(0);
    dtd[4] = u8::try_from(((width >> 8) & 0x0F) << 4 | ((h_blank >> 8) & 0x0F)).unwrap_or(0);
    dtd[5] = u8::try_from(height & 0xFF).unwrap_or(0);
    dtd[6] = u8::try_from(v_blank & 0xFF).unwrap_or(0);
    dtd[7] = u8::try_from(((height >> 8) & 0x0F) << 4 | ((v_blank >> 8) & 0x0F)).unwrap_or(0);
    dtd[8] = 48; // H sync offset
    dtd[9] = 32; // H sync pulse width
    dtd[10] = (3 << 4) | 5; // V sync offset = 3, V sync pulse width = 5
    dtd[11] = 0;
    dtd[12] = 0x08; // 520 mm width low bits
    dtd[13] = 0x22; // 290 mm height low bits
    dtd[14] = 0x21; // High bits of mm size
    dtd[17] = 0x1E; // Digital separate sync, positive H/V

    // 4. Monitor Name Descriptor (`0xFC`) at bytes 72..90 (`"OmegaDesk IDD"`).
    let name_desc = &mut edid[72..90];
    name_desc[3] = 0xFC;
    let name_bytes = b"OmegaDesk IDD";
    name_desc[5..5 + name_bytes.len()].copy_from_slice(name_bytes);

    // 5. Modulo-256 checksum at byte 127 so `sum(edid[0..128]) & 0xFF == 0`.
    let sum: u8 = edid[..127].iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
    edid[127] = 0u8.wrapping_sub(sum);

    Ok(edid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synthesizes_valid_edid_with_zero_modulo_256_checksum() {
        let req = IddPlugInRequest::new(0, [0x42u8; 16], 2560, 1440, 120, 0x1234_5678).unwrap();
        assert_eq!(
            &req.edid[0..8],
            &[0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00]
        );
        let checksum: u8 = req.edid.iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
        assert_eq!(checksum, 0);

        // Decode width and height from Detailed Timing Descriptor #1 (bytes 54..72).
        let dtd = &req.edid[54..72];
        let decoded_w = u16::from(dtd[2]) | (u16::from(dtd[4] >> 4) << 8);
        let decoded_h = u16::from(dtd[5]) | (u16::from(dtd[7] >> 4) << 8);
        assert_eq!(decoded_w, 2560);
        assert_eq!(decoded_h, 1440);
    }
}
