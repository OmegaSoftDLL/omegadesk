//! Adaptive Reed-Solomon forward error correction (`GF(2^8)`) for low-latency
//! video frames over UDP.
//!
//! Modeled after Sunshine (`src/stream.cpp`, `fec.cpp`) and Apollo:
//! - Splits an encoded video frame into `k` equal-sized data shards and appends
//!   `m` systematic Cauchy parity shards over `GF(2^8)` (primitive polynomial
//!   `x^8 + x^4 + x^3 + x^2 + 1 = 0x11d`).
//! - Any `k` received shards out of `k + m` reconstruct the original frame in a
//!   single pass without waiting for a network retransmission.
//! - [`adaptive_parity_count`] scales the FEC overhead dynamically from the
//!   observed packet loss percentage.

/// Default shard payload size in bytes (fits comfortably inside the 1280-byte
/// mesh MTU after WireGuard/QUIC headers).
pub const DEFAULT_SHARD_SIZE: usize = 1024;

/// Maximum total shards (`data + parity`) in a single FEC block (`<= 128` for
/// Cauchy matrix construction over `GF(2^8)`).
pub const MAX_TOTAL_SHARDS: usize = 128;

/// Errors returned by Reed-Solomon encoding or reconstruction.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FecError {
    /// Invalid shard count configuration.
    #[error("invalid FEC shard configuration: data={data_shards}, parity={parity_shards}")]
    InvalidConfiguration {
        /// Number of data shards (`k`).
        data_shards: usize,
        /// Number of parity shards (`m`).
        parity_shards: usize,
    },
    /// Fewer than `data_shards` shards arrived, so the block cannot be reconstructed.
    #[error("insufficient shards to reconstruct block: need {needed}, got {available}")]
    InsufficientShards {
        /// Minimum shards required (`k`).
        needed: usize,
        /// Shards actually received.
        available: usize,
    },
    /// Shards in the block do not all share the same byte length.
    #[error("inconsistent shard byte length")]
    InconsistentShardLength,
}

/// Computes the recommended number of parity shards `m` for `data_shards` (`k`)
/// given `observed_loss_percent` (`0..=100`), modeled after Sunshine's adaptive
/// FEC percentage (`fecPercentage`).
#[must_use]
pub fn adaptive_parity_count(data_shards: usize, observed_loss_percent: u8) -> usize {
    if data_shards == 0 || observed_loss_percent == 0 {
        return 0;
    }
    // Add a 25% safety margin on top of the observed loss rate, clamped to 50% overhead.
    let target_pct = usize::from(observed_loss_percent.min(40)) + 10;
    let parity = (data_shards * target_pct).div_ceil(100).max(1);
    parity.min(MAX_TOTAL_SHARDS.saturating_sub(data_shards))
}

/// Encodes `payload` into `data_shards` data shards followed by `parity_shards`
/// systematic Reed-Solomon parity shards over `GF(2^8)`.
///
/// Returns `(shard_len, shards)` where `shards.len() == data_shards + parity_shards`.
///
/// # Errors
///
/// Returns [`FecError::InvalidConfiguration`] if `data_shards == 0` or
/// `data_shards + parity_shards > MAX_TOTAL_SHARDS`.
pub fn encode_fec_block(
    payload: &[u8],
    data_shards: usize,
    parity_shards: usize,
) -> Result<(usize, Vec<Vec<u8>>), FecError> {
    if data_shards == 0 || data_shards + parity_shards > MAX_TOTAL_SHARDS {
        return Err(FecError::InvalidConfiguration {
            data_shards,
            parity_shards,
        });
    }

    // Prefix payload with its 4-byte big-endian length so padding zeros are stripped on decode.
    let total_with_len = 4 + payload.len();
    let shard_len = total_with_len.div_ceil(data_shards).max(1);
    let mut padded = Vec::with_capacity(data_shards * shard_len);
    let payload_len_u32 = u32::try_from(payload.len()).unwrap_or(u32::MAX);
    padded.extend_from_slice(&payload_len_u32.to_be_bytes());
    padded.extend_from_slice(payload);
    padded.resize(data_shards * shard_len, 0);

    let mut shards: Vec<Vec<u8>> = padded.chunks_exact(shard_len).map(<[u8]>::to_vec).collect();

    for p in 0..parity_shards {
        let mut parity = vec![0u8; shard_len];
        for (d, data_shard) in shards.iter().take(data_shards).enumerate() {
            let coeff = cauchy_coeff(p, d, parity_shards);
            gf_mul_add_slice(&mut parity, data_shard, coeff);
        }
        shards.push(parity);
    }

    Ok((shard_len, shards))
}

/// Reconstructs the original payload from a partial set of shards (`Some(shard)`
/// for received shards, `None` for lost shards).
///
/// # Errors
///
/// Returns [`FecError`] if fewer than `data_shards` shards are present or shard
/// lengths are inconsistent.
pub fn reconstruct_fec_block(
    received: &[Option<Vec<u8>>],
    data_shards: usize,
    parity_shards: usize,
) -> Result<Vec<u8>, FecError> {
    if data_shards == 0
        || data_shards + parity_shards > MAX_TOTAL_SHARDS
        || received.len() != data_shards + parity_shards
    {
        return Err(FecError::InvalidConfiguration {
            data_shards,
            parity_shards,
        });
    }

    let available: Vec<(usize, &[u8])> = received
        .iter()
        .enumerate()
        .filter_map(|(i, opt)| opt.as_deref().map(|s| (i, s)))
        .collect();

    if available.len() < data_shards {
        return Err(FecError::InsufficientShards {
            needed: data_shards,
            available: available.len(),
        });
    }

    let shard_len = available[0].1.len();
    if shard_len == 0 || available.iter().any(|(_, s)| s.len() != shard_len) {
        return Err(FecError::InconsistentShardLength);
    }

    // Fast path: all `data_shards` arrived intact.
    if available
        .iter()
        .take(data_shards)
        .enumerate()
        .all(|(idx, (shard_idx, _))| idx == *shard_idx)
    {
        let mut raw = Vec::with_capacity(data_shards * shard_len);
        for (_, shard) in available.iter().take(data_shards) {
            raw.extend_from_slice(shard);
        }
        return extract_framed_payload(&raw);
    }

    // Build the `k x k` submatrix from the first `data_shards` available shards.
    let chosen = &available[..data_shards];
    let mut matrix = vec![vec![0u8; data_shards]; data_shards];
    for (row_idx, &(shard_idx, _)) in chosen.iter().enumerate() {
        if shard_idx < data_shards {
            matrix[row_idx][shard_idx] = 1;
        } else {
            let p = shard_idx - data_shards;
            for (d, cell) in matrix[row_idx].iter_mut().enumerate() {
                *cell = cauchy_coeff(p, d, parity_shards);
            }
        }
    }

    let inv = invert_gf_matrix(&mut matrix)?;

    let mut raw = Vec::with_capacity(data_shards * shard_len);
    for inv_row in inv.iter().take(data_shards) {
        let mut recovered = vec![0u8; shard_len];
        for (col, &(_, src_shard)) in chosen.iter().enumerate() {
            let factor = inv_row[col];
            gf_mul_add_slice(&mut recovered, src_shard, factor);
        }
        raw.extend_from_slice(&recovered);
    }

    extract_framed_payload(&raw)
}

fn extract_framed_payload(raw: &[u8]) -> Result<Vec<u8>, FecError> {
    if raw.len() < 4 {
        return Err(FecError::InconsistentShardLength);
    }
    let declared_len = usize::try_from(u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]))
        .map_err(|_| FecError::InconsistentShardLength)?;
    if 4 + declared_len > raw.len() {
        return Err(FecError::InconsistentShardLength);
    }
    Ok(raw[4..4 + declared_len].to_vec())
}

/// Cauchy element `1 / (x_p ^ y_d)` in `GF(2^8)` where `x_p = p` and `y_d = parity_shards + d`.
/// Because `x_p` and `y_d` are disjoint, every square submatrix is guaranteed invertible.
fn cauchy_coeff(p: usize, d: usize, parity_shards: usize) -> u8 {
    let x = u8::try_from(p).unwrap_or(0);
    let y = u8::try_from(parity_shards + d).unwrap_or(1);
    gf_inv(x ^ y)
}

const fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    let mut i = 0;
    while i < 8 {
        if (b & 1) != 0 {
            p ^= a;
        }
        let hi = (a & 0x80) != 0;
        a <<= 1;
        if hi {
            a ^= 0x1d; // 0x11d primitive polynomial
        }
        b >>= 1;
        i += 1;
    }
    p
}

fn gf_inv(a: u8) -> u8 {
    if a == 0 {
        return 0;
    }
    // In GF(2^8), a^254 = a^(-1) by Fermat's Little Theorem.
    let mut result = 1u8;
    let mut base = a;
    let mut exp = 254u8;
    while exp > 0 {
        if (exp & 1) != 0 {
            result = gf_mul(result, base);
        }
        base = gf_mul(base, base);
        exp >>= 1;
    }
    result
}

fn gf_mul_add_slice(dst: &mut [u8], src: &[u8], coeff: u8) {
    if coeff == 0 {
        return;
    }
    if coeff == 1 {
        for (d, &s) in dst.iter_mut().zip(src.iter()) {
            *d ^= s;
        }
        return;
    }
    for (d, &s) in dst.iter_mut().zip(src.iter()) {
        *d ^= gf_mul(s, coeff);
    }
}

fn invert_gf_matrix(mat: &mut [Vec<u8>]) -> Result<Vec<Vec<u8>>, FecError> {
    let n = mat.len();
    let mut inv = vec![vec![0u8; n]; n];
    for (i, row) in inv.iter_mut().enumerate() {
        row[i] = 1;
    }

    for col in 0..n {
        if mat[col][col] == 0 {
            let Some(swap_row) = ((col + 1)..n).find(|&r| mat[r][col] != 0) else {
                return Err(FecError::InsufficientShards {
                    needed: n,
                    available: 0,
                });
            };
            mat.swap(col, swap_row);
            inv.swap(col, swap_row);
        }

        let pivot_inv = gf_inv(mat[col][col]);
        for c in 0..n {
            mat[col][c] = gf_mul(mat[col][c], pivot_inv);
            inv[col][c] = gf_mul(inv[col][c], pivot_inv);
        }

        let pivot_mat_row = mat[col].clone();
        let pivot_inv_row = inv[col].clone();
        for r in 0..n {
            if r != col && mat[r][col] != 0 {
                let factor = mat[r][col];
                gf_mul_add_slice(&mut mat[r], &pivot_mat_row, factor);
                gf_mul_add_slice(&mut inv[r], &pivot_inv_row, factor);
            }
        }
    }

    Ok(inv)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn adaptive_parity_scales_with_loss_rate() {
        assert_eq!(adaptive_parity_count(10, 0), 0);
        assert_eq!(adaptive_parity_count(10, 5), 2);
        assert_eq!(adaptive_parity_count(10, 20), 3);
    }

    #[test]
    fn reconstructs_frame_after_erasing_multiple_data_shards() {
        let original = b"OmegaDesk low-latency H.264 slice payload with Reed-Solomon FEC recovery";
        let data_shards = 6;
        let parity_shards = 3;

        let (_, shards) = encode_fec_block(original, data_shards, parity_shards).unwrap();
        let mut received: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();

        // Erase 3 data shards (shards 0, 2, and 5) -> recover using the 3 parity shards!
        received[0] = None;
        received[2] = None;
        received[5] = None;

        let recovered = reconstruct_fec_block(&received, data_shards, parity_shards).unwrap();
        assert_eq!(recovered, original);

        // Erasing one more shard leaves only 5 shards (< 6 needed) -> InsufficientShards
        received[1] = None;
        assert!(matches!(
            reconstruct_fec_block(&received, data_shards, parity_shards),
            Err(FecError::InsufficientShards {
                needed: 6,
                available: 5
            })
        ));
    }

    proptest! {
        #[test]
        fn prop_reed_solomon_recovers_any_k_of_n_shards(
            payload in prop::collection::vec(any::<u8>(), 1..1500),
            erased_a in 0usize..4,
            erased_b in 4usize..8,
        ) {
            let data_shards = 6;
            let parity_shards = 2;
            let (_, shards) = encode_fec_block(&payload, data_shards, parity_shards).unwrap();
            let mut received: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();
            received[erased_a] = None;
            received[erased_b] = None;

            let recovered = reconstruct_fec_block(&received, data_shards, parity_shards).unwrap();
            prop_assert_eq!(recovered, payload);
        }
    }
}
