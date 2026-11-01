//! `DeskHub` multi-desktop live grid, preview subscription negotiation, weighted
//! video bandwidth allocation, and synchronized group-control fan-out (`docs/plan.md` §2.12 line 167).
//!
//! Clean-room implementation modeled after CrossDesk's `DeskHub` specification and wire
//! contract (`kunkundi_crossdesk/libs/wire/include/preview_subscription.h` lines 16–127
//! and `kunkundi_crossdesk/docs/deskhub.md` lines 30 & 48–68):
//! - [`PreviewSubscription`]: versioned (`v1` / `v2`) `deskhub_preview` subscription with
//!   32-bit wrap-around `request_id` (`is_newer_than`), `fps` (`0 | 1 | 8 | 15 | 60`),
//!   physical-pixel bounds (`width`, `height` in `0` or `2..=16_384`), optional
//!   `max_bitrate_bps` (`0..=100_000_000`), and spatial-detail `encoder_preference` (`1`
//!   when `fps` is `1`, `8`, or `15`).
//! - [`DeskHubBandwidthAllocator`]: shares a total video budget (default `20 Mbps`) across
//!   all visible grid tiles by reserving up to `100 Kbps` base share per visible tile and
//!   distributing the remainder with a `4x` weight for expanded/focused desktops vs `1x`
//!   for `16:9` thumbnail tiles (`320x320` 30 FPS thumbnail demand cap = `500 Kbps`),
//!   while pausing (`fps = 0`) hidden/off-page tiles.
//! - [`GroupControlState`]: synchronizes keyboard and pointer input from the primary
//!   focused desktop across all other connected machines in the grid.

use omegadesk_identity::DeviceId;
use thiserror::Error;

/// Default total video bandwidth budget across all `DeskHub` sessions (`20 Mbps`, `docs/deskhub.md` line 50).
pub const DEFAULT_DESKHUB_TOTAL_BUDGET_BPS: u32 = 20_000_000;

/// Maximum configurable `DeskHub` video bitrate budget (`100 Mbps`, `preview_subscription.h` line 119).
pub const MAX_DESKHUB_BITRATE_BPS: u32 = 100_000_000;

/// Base bitrate share reserved per visible `DeskHub` tile (`100 Kbps`, `docs/deskhub.md` line 52).
pub const BASE_VISIBLE_TILE_SHARE_BPS: u32 = 100_000;

/// Default demand cap for a `320x320` 30 FPS thumbnail tile (`500 Kbps`, `docs/deskhub.md` line 52).
pub const DEFAULT_THUMBNAIL_DEMAND_CAP_BPS: u32 = 500_000;

/// Weight multiplier for an expanded/focused desktop relative to a thumbnail tile (`4x`, `docs/deskhub.md` line 52).
pub const FOCUSED_TILE_WEIGHT: u32 = 4;

/// Maximum concurrent batch connection/file-distribution tasks (`4`, `docs/deskhub.md` line 72).
pub const MAX_CONCURRENT_BATCH_TASKS: usize = 4;

/// Validation errors for `DeskHub` preview subscriptions.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum DeskHubError {
    /// Protocol version must be `1` or `2`.
    #[error("unsupported deskhub_preview version: {0}")]
    UnsupportedVersion(u8),
    /// `request_id` must be non-zero (`preview_subscription.h` line 84).
    #[error("deskhub_preview request_id must be non-zero")]
    ZeroRequestId,
    /// `fps` must be one of `0`, `1`, `8`, `15`, or `60` (`preview_subscription.h` line 94).
    #[error("unsupported deskhub_preview fps: {0}")]
    InvalidFps(u8),
    /// `frame_rate` must be `30` or `60` (`preview_subscription.h` line 97).
    #[error("unsupported deskhub_preview frame_rate: {0}")]
    InvalidFrameRate(u8),
    /// `quality` or `preference` must be in `0..=2` (`preview_subscription.h` lines 96–98).
    #[error("deskhub_preview quality and preference must be in 0..=2")]
    InvalidQualityOrPreference,
    /// `width` and `height` must both be `0` or both be in `2..=16384` (`preview_subscription.h` line 32).
    #[error("invalid deskhub_preview resolution {width}x{height}")]
    InvalidResolution {
        /// Width in physical pixels.
        width: u16,
        /// Height in physical pixels.
        height: u16,
    },
    /// `max_bitrate_bps` exceeds `100_000_000` (`preview_subscription.h` line 119).
    #[error("deskhub_preview max_bitrate_bps {0} exceeds 100 Mbps")]
    InvalidBitrate(u32),
}

/// Versioned `deskhub_preview` subscription message (`preview_subscription.h` lines 16–127).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreviewSubscription {
    /// Non-zero monotonically advancing request ID (32-bit wrap-around).
    pub request_id: u32,
    /// Target capture/preview rate (`0` pauses video; `1 | 8` legacy; `15` negotiated preview; `60` interactive).
    pub fps: u8,
    /// Quality preset (`0..=2`).
    pub quality: u8,
    /// Interactive encoder reference frame rate (`30` or `60`).
    pub frame_rate: u8,
    /// User encoder preference (`0..=2`).
    pub preference: u8,
    /// Whether audio is enabled for this tile (muted by default in `DeskHub`).
    pub audio: bool,
    /// Physical pixel width cap (`0` restores source limit, or `2..=16384`).
    pub width: u16,
    /// Physical pixel height cap (`0` restores source limit, or `2..=16384`).
    pub height: u16,
    /// Subscription schema version (`1` or `2`).
    pub version: u8,
    /// Optional total video bitrate budget in bps (`0..=100_000_000`).
    pub max_bitrate_bps: Option<u32>,
}

impl PreviewSubscription {
    /// Returns `true` if `(width, height)` is either `(0, 0)` or both are in `2..=16_384`
    /// (`PreviewSubscription::ValidResolution`, `preview_subscription.h` lines 32–35).
    #[must_use]
    pub const fn valid_resolution(width: u16, height: u16) -> bool {
        (width == 0 && height == 0)
            || (width >= 2 && height >= 2 && width <= 16_384 && height <= 16_384)
    }

    /// Validates all fields against the `deskhub_preview` v1/v2 specification
    /// (`PreviewSubscription::Parse`, `preview_subscription.h` lines 73–126).
    ///
    /// # Errors
    ///
    /// Returns [`DeskHubError`] if any field violates the wire constraints.
    pub const fn validate(&self) -> Result<(), DeskHubError> {
        if self.version != 1 && self.version != 2 {
            return Err(DeskHubError::UnsupportedVersion(self.version));
        }
        if self.request_id == 0 {
            return Err(DeskHubError::ZeroRequestId);
        }
        if !matches!(self.fps, 0 | 1 | 8 | 15 | 60) {
            return Err(DeskHubError::InvalidFps(self.fps));
        }
        if self.frame_rate != 30 && self.frame_rate != 60 {
            return Err(DeskHubError::InvalidFrameRate(self.frame_rate));
        }
        if self.quality > 2 || self.preference > 2 {
            return Err(DeskHubError::InvalidQualityOrPreference);
        }
        if self.version == 2 && !Self::valid_resolution(self.width, self.height) {
            return Err(DeskHubError::InvalidResolution {
                width: self.width,
                height: self.height,
            });
        }
        if let Some(bps) = self.max_bitrate_bps
            && bps > MAX_DESKHUB_BITRATE_BPS
        {
            return Err(DeskHubError::InvalidBitrate(bps));
        }
        Ok(())
    }

    /// Wrap-around 32-bit sequence comparison (`PreviewSubscription::IsNewerThan`,
    /// `preview_subscription.h` lines 42–44).
    #[must_use]
    #[allow(clippy::cast_possible_wrap)]
    pub const fn is_newer_than(&self, other: &Self) -> bool {
        (self.request_id.wrapping_sub(other.request_id) as i32) > 0
    }

    /// Effective encoder preference (`PreviewSubscription::EncoderPreference`,
    /// `preview_subscription.h` lines 55–59): preserves spatial detail (`1`) when sparse
    /// preview FPS (`1`, `8`, or `15`) is active.
    #[must_use]
    pub const fn encoder_preference(&self) -> u8 {
        if matches!(self.fps, 1 | 8 | 15) {
            1
        } else {
            self.preference
        }
    }
}

/// Visibility and focus state of a single remote machine tile inside `DeskHub`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TileVisibility {
    /// Tile is on another page, in another group, or the `DeskHub` window is minimized (`fps = 0`).
    Hidden,
    /// Tile is visible in the `16:9` thumbnail grid (`weight = 1`).
    Thumbnail,
    /// Tile is expanded in the focused main view or open in a standalone stream window (`weight = 4`).
    FocusedOrExpanded,
}

/// Input descriptor for a machine tile participating in `DeskHub` bandwidth allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeskHubTileDemand {
    /// Device identifier.
    pub device_id: DeviceId,
    /// Current visibility/focus state.
    pub visibility: TileVisibility,
    /// Estimated maximum bitrate demand in bps for the tile's requested resolution and FPS.
    pub demand_cap_bps: u32,
}

/// Per-tile allocation decision computed by [`DeskHubBandwidthAllocator`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeskHubTileAllocation {
    /// Device identifier.
    pub device_id: DeviceId,
    /// Target FPS (`0` when [`TileVisibility::Hidden`], otherwise `15` or `60`).
    pub target_fps: u8,
    /// Allocated video bitrate budget in bps (`0` when paused).
    pub allocated_bitrate_bps: u32,
}

/// Weighted video bandwidth allocator across multiple live desktops (`docs/deskhub.md` lines 48–56).
pub struct DeskHubBandwidthAllocator;

impl DeskHubBandwidthAllocator {
    /// Allocates `total_budget_bps` across `tiles`:
    /// 1. Hidden tiles receive `target_fps = 0` and `allocated_bitrate_bps = 0`.
    /// 2. Visible tiles first receive a base share of up to [`BASE_VISIBLE_TILE_SHARE_BPS`] (`100 Kbps`,
    ///    or an equal fraction of `total_budget_bps` if the budget is smaller).
    /// 3. Remaining budget is distributed proportionally by weight (`4` for
    ///    [`TileVisibility::FocusedOrExpanded`], `1` for [`TileVisibility::Thumbnail`]), capped
    ///    at each tile's `demand_cap_bps`.
    #[must_use]
    pub fn allocate(
        total_budget_bps: u32,
        tiles: &[DeskHubTileDemand],
    ) -> Vec<DeskHubTileAllocation> {
        let visible_count = u32::try_from(
            tiles
                .iter()
                .filter(|t| t.visibility != TileVisibility::Hidden)
                .count(),
        )
        .unwrap_or(0);

        if visible_count == 0 || total_budget_bps == 0 {
            return tiles
                .iter()
                .map(|t| DeskHubTileAllocation {
                    device_id: t.device_id,
                    target_fps: 0,
                    allocated_bitrate_bps: 0,
                })
                .collect();
        }

        let base_per_tile = (total_budget_bps / visible_count).min(BASE_VISIBLE_TILE_SHARE_BPS);
        let mut remaining_budget = total_budget_bps;
        let mut allocations: Vec<u32> = Vec::with_capacity(tiles.len());

        for tile in tiles {
            if tile.visibility == TileVisibility::Hidden {
                allocations.push(0);
            } else {
                let grant = base_per_tile.min(tile.demand_cap_bps);
                allocations.push(grant);
                remaining_budget = remaining_budget.saturating_sub(grant);
            }
        }

        // Iteratively distribute remaining budget by weight (4x focused, 1x thumbnail)
        // among visible tiles that have not yet reached `demand_cap_bps`.
        for _ in 0..4 {
            let total_weight: u32 = tiles
                .iter()
                .zip(allocations.iter())
                .filter_map(|(t, &alloc)| {
                    if t.visibility != TileVisibility::Hidden && alloc < t.demand_cap_bps {
                        Some(match t.visibility {
                            TileVisibility::FocusedOrExpanded => FOCUSED_TILE_WEIGHT,
                            TileVisibility::Thumbnail => 1,
                            TileVisibility::Hidden => 0,
                        })
                    } else {
                        None
                    }
                })
                .sum();

            if total_weight == 0 || remaining_budget == 0 {
                break;
            }

            let pool = remaining_budget;
            for (tile, alloc) in tiles.iter().zip(allocations.iter_mut()) {
                if tile.visibility == TileVisibility::Hidden || *alloc >= tile.demand_cap_bps {
                    continue;
                }
                let weight = match tile.visibility {
                    TileVisibility::FocusedOrExpanded => FOCUSED_TILE_WEIGHT,
                    TileVisibility::Thumbnail => 1,
                    TileVisibility::Hidden => 0,
                };
                let share =
                    u32::try_from((u64::from(pool) * u64::from(weight)) / u64::from(total_weight))
                        .unwrap_or(0);
                let room = tile.demand_cap_bps.saturating_sub(*alloc);
                let add = share.min(room).min(remaining_budget);
                *alloc += add;
                remaining_budget = remaining_budget.saturating_sub(add);
            }
        }

        tiles
            .iter()
            .zip(allocations)
            .map(|(tile, alloc)| DeskHubTileAllocation {
                device_id: tile.device_id,
                target_fps: match tile.visibility {
                    TileVisibility::Hidden => 0,
                    TileVisibility::Thumbnail => 15,
                    TileVisibility::FocusedOrExpanded => 60,
                },
                allocated_bitrate_bps: alloc,
            })
            .collect()
    }
}

/// Synchronized multi-desktop group control (`开启群控`, `docs/deskhub.md` line 30):
/// broadcasts keyboard and normalized pointer events from the primary controlled desktop
/// to all other connected peers in the `DeskHub` session.
#[derive(Debug, Default, Clone)]
pub struct GroupControlState {
    primary_device: Option<DeviceId>,
    connected_peers: Vec<DeviceId>,
}

impl GroupControlState {
    /// Creates an inactive [`GroupControlState`].
    #[must_use]
    pub const fn new() -> Self {
        Self {
            primary_device: None,
            connected_peers: Vec::new(),
        }
    }

    /// Starts group control with `primary` as the master desktop and `connected_peers`
    /// as the set of active sessions.
    pub fn enable(&mut self, primary: DeviceId, connected_peers: Vec<DeviceId>) {
        self.primary_device = Some(primary);
        self.connected_peers = connected_peers;
    }

    /// Disables group control (e.g., on focus loss, page switch, or primary disconnect)
    /// and returns the list of peer devices that must receive a `release_all` key/button reset.
    pub fn disable(&mut self) -> Vec<DeviceId> {
        self.primary_device = None;
        std::mem::take(&mut self.connected_peers)
    }

    /// Returns the list of target [`DeviceId`]s (primary + all connected peers) that should
    /// receive an input event when group control is active.
    #[must_use]
    pub fn broadcast_targets(&self) -> Vec<DeviceId> {
        let Some(primary) = self.primary_device else {
            return Vec::new();
        };
        let mut targets = vec![primary];
        for &peer in &self.connected_peers {
            if peer != primary {
                targets.push(peer);
            }
        }
        targets
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use omegadesk_identity::DeviceIdentity;

    #[test]
    fn preview_subscription_validation_and_weighted_bandwidth_allocation() {
        let sub_v2 = PreviewSubscription {
            request_id: 1,
            fps: 15,
            quality: 1,
            frame_rate: 30,
            preference: 0,
            audio: false,
            width: 320,
            height: 180,
            version: 2,
            max_bitrate_bps: Some(DEFAULT_THUMBNAIL_DEMAND_CAP_BPS),
        };
        assert!(sub_v2.validate().is_ok());
        assert_eq!(sub_v2.encoder_preference(), 1);

        let newer = PreviewSubscription {
            request_id: 2,
            ..sub_v2.clone()
        };
        assert!(newer.is_newer_than(&sub_v2));

        let d1 = DeviceIdentity::generate().id();
        let d2 = DeviceIdentity::generate().id();
        let d3 = DeviceIdentity::generate().id();

        let tiles = [
            DeskHubTileDemand {
                device_id: d1,
                visibility: TileVisibility::FocusedOrExpanded,
                demand_cap_bps: 8_000_000,
            },
            DeskHubTileDemand {
                device_id: d2,
                visibility: TileVisibility::Thumbnail,
                demand_cap_bps: DEFAULT_THUMBNAIL_DEMAND_CAP_BPS,
            },
            DeskHubTileDemand {
                device_id: d3,
                visibility: TileVisibility::Hidden,
                demand_cap_bps: DEFAULT_THUMBNAIL_DEMAND_CAP_BPS,
            },
        ];

        let allocs = DeskHubBandwidthAllocator::allocate(5_000_000, &tiles);
        assert_eq!(allocs[2].target_fps, 0);
        assert_eq!(allocs[2].allocated_bitrate_bps, 0);
        assert_eq!(allocs[1].target_fps, 15);
        assert_eq!(
            allocs[1].allocated_bitrate_bps,
            DEFAULT_THUMBNAIL_DEMAND_CAP_BPS
        );
        assert_eq!(allocs[0].target_fps, 60);
        assert_eq!(allocs[0].allocated_bitrate_bps, 4_500_000);

        let mut group = GroupControlState::new();
        group.enable(d1, vec![d2, d3]);
        assert_eq!(group.broadcast_targets(), vec![d1, d2, d3]);
        assert_eq!(group.disable().len(), 2);
    }
}
