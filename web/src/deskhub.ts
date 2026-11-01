/**
 * DeskHub multi-desktop live grid controller for the OmegaDesk web dashboard (`docs/plan.md` §2.12 line 167).
 *
 * Clean-room TypeScript implementation modeled after CrossDesk's `DeskHub`
 * (`kunkundi_crossdesk/libs/wire/include/preview_subscription.h` and `docs/deskhub.md`):
 * - 16:9 thumbnail grid (`184..960` logical px cell width) with `fps=15` preview subscriptions
 *   and `fps=0` automatic video pause for off-page or minimized tiles.
 * - Weighted video bandwidth allocation (`100 Kbps` base share per visible tile + `4x` weight
 *   for expanded/focused desktop vs `1x` for thumbnail tiles).
 */

export type TileVisibility = "hidden" | "thumbnail" | "focused";

export interface DeskHubTile {
  readonly deviceId: string;
  readonly displayName: string;
  readonly online: boolean;
  readonly visibility: TileVisibility;
  readonly muted: boolean;
  readonly demandCapBps: number;
}

export interface DeskHubPreviewSubscriptionMsg {
  readonly type: "deskhub_preview";
  readonly version: 1 | 2;
  readonly request_id: number;
  readonly fps: 0 | 1 | 8 | 15 | 60;
  readonly quality: 0 | 1 | 2;
  readonly frame_rate: 30 | 60;
  readonly preference: 0 | 1 | 2;
  readonly audio: boolean;
  readonly width?: number;
  readonly height?: number;
  readonly max_bitrate_bps?: number;
}

const BASE_VISIBLE_SHARE_BPS = 100_000;
const FOCUSED_WEIGHT = 4;

/**
 * Builds a `deskhub_preview` v2 subscription message (`preview_subscription.h` lines 61–72).
 */
export function buildPreviewSubscription(
  requestId: number,
  tile: DeskHubTile,
  width: number,
  height: number,
  allocatedBitrateBps: number,
): DeskHubPreviewSubscriptionMsg {
  const fps: 0 | 15 | 60 =
    tile.visibility === "hidden"
      ? 0
      : tile.visibility === "Thumbnail".toLowerCase()
        ? 15
        : 60;
  return {
    type: "deskhub_preview",
    version: 2,
    request_id: requestId >>> 0,
    fps,
    quality: 1,
    frame_rate: 30,
    preference: fps === 15 ? 1 : 0,
    audio: !tile.muted,
    width,
    height,
    max_bitrate_bps: allocatedBitrateBps,
  };
}

/**
 * Allocates `totalBudgetBps` across visible DeskHub tiles (`docs/deskhub.md` lines 48–56).
 */
export function allocateDeskHubBandwidth(
  totalBudgetBps: number,
  tiles: readonly DeskHubTile[],
): Map<string, number> {
  const result = new Map<string, number>();
  const visible = tiles.filter((t) => t.visibility !== "hidden" && t.online);
  if (visible.length === 0 || totalBudgetBps <= 0) {
    for (const t of tiles) {
      result.set(t.deviceId, 0);
    }
    return result;
  }

  const basePerTile = Math.min(
    Math.floor(totalBudgetBps / visible.length),
    BASE_VISIBLE_SHARE_BPS,
  );
  let remaining = totalBudgetBps;

  for (const t of tiles) {
    if (t.visibility === "hidden" || !t.online) {
      result.set(t.deviceId, 0);
    } else {
      const grant = Math.min(basePerTile, t.demandCapBps);
      result.set(t.deviceId, grant);
      remaining -= grant;
    }
  }

  const totalWeight = visible.reduce(
    (sum, t) => sum + (t.visibility === "focused" ? FOCUSED_WEIGHT : 1),
    0,
  );
  if (totalWeight > 0 && remaining > 0) {
    const pool = remaining;
    for (const t of visible) {
      const current = result.get(t.deviceId) ?? 0;
      const weight = t.visibility === "focused" ? FOCUSED_WEIGHT : 1;
      const share = Math.floor((pool * weight) / totalWeight);
      const add = Math.min(share, Math.max(0, t.demandCapBps - current), remaining);
      result.set(t.deviceId, current + add);
      remaining -= add;
    }
  }

  return result;
}
