/**
 * Pointer and keyboard helpers for the browser client.
 *
 * Bit values mirror `crates/input/src/lib.rs` (`buttons`, `modifiers`, `WHEEL_STEP`)
 * and `PointerEvent` in `crates/protocol/proto/omegadesk/v1/session.proto`
 * (position normalized to `0..=65535`, wheel in 1/120-notch units, positive = up /
 * right). The physical key translation (`KeyboardEvent.code` -> HID usage + keysym)
 * lives in the gateway (`map_browser_key_event` in `server/src/web_gateway.rs`,
 * ported from noVNC); the browser only ships `code`, `key` and the modifier state.
 *
 * `mapCanvasPoint` is ported from `zibo-chen_SubnetDesk/web/src/protocol.ts`
 * (letterboxed canvas to remote coordinates); the scroll accumulator follows
 * `ScrollAccumulator` in `client/src/window.rs` (fractional deltas add up until a
 * whole 1/120 unit is available).
 */

/** `omegadesk_input::WHEEL_STEP`: one wheel notch. */
export const WHEEL_STEP = 120;

/** `omegadesk_input::buttons`. The DOM `MouseEvent.buttons` bits use the same values. */
export const buttons = {
  LEFT: 1,
  RIGHT: 1 << 1,
  MIDDLE: 1 << 2,
  BACK: 1 << 3,
  FORWARD: 1 << 4,
} as const;

/** `omegadesk_input::modifiers`. */
export const modifiers = {
  SHIFT: 1,
  CTRL: 1 << 1,
  ALT: 1 << 2,
  META: 1 << 3,
  CAPS_LOCK: 1 << 4,
  NUM_LOCK: 1 << 5,
  LOCK_STATE_VALID: 1 << 7,
} as const;

const KNOWN_BUTTONS =
  buttons.LEFT | buttons.RIGHT | buttons.MIDDLE | buttons.BACK | buttons.FORWARD;

/** Largest normalized coordinate (`PointerEvent.x/y` are `0..=65535`). */
export const POINTER_MAX = 0xffff;

/** The part of `KeyboardEvent` / `MouseEvent` the modifier mask needs. */
export interface ModifierSource {
  getModifierState(key: string): boolean;
}

/**
 * Modifier bitmask for a key or pointer event. Lock states are always reported with
 * `LOCK_STATE_VALID`, so the agent can synchronize `CapsLock` / `NumLock`
 * (`client/src/window.rs` does the same from `winit`).
 */
export function modifierMask(event: ModifierSource): number {
  let mask = modifiers.LOCK_STATE_VALID;
  if (event.getModifierState("Shift")) mask |= modifiers.SHIFT;
  if (event.getModifierState("Control")) mask |= modifiers.CTRL;
  if (event.getModifierState("Alt")) mask |= modifiers.ALT;
  if (event.getModifierState("Meta")) mask |= modifiers.META;
  if (event.getModifierState("CapsLock")) mask |= modifiers.CAPS_LOCK;
  if (event.getModifierState("NumLock")) mask |= modifiers.NUM_LOCK;
  return mask;
}

/** Keeps only the buttons the protocol knows from a DOM `buttons` bitmask. */
export function buttonMask(domButtons: number): number {
  return (domButtons >>> 0) & KNOWN_BUTTONS;
}

/** Rectangle of the canvas on the page (`getBoundingClientRect()`). */
export interface CanvasRect {
  left: number;
  top: number;
  width: number;
  height: number;
}

/**
 * Maps a page coordinate on a letterboxed canvas (`object-fit: contain`) to the
 * remote frame, clamped to its edges, then normalizes to `0..=65535`. Returns `null`
 * when the canvas or the remote size is degenerate.
 */
export function mapCanvasPoint(
  clientX: number,
  clientY: number,
  rect: CanvasRect,
  remoteWidth: number,
  remoteHeight: number,
): { x: number; y: number } | null {
  if (
    rect.width <= 0 ||
    rect.height <= 0 ||
    remoteWidth <= 0 ||
    remoteHeight <= 0
  ) {
    return null;
  }
  const scale = Math.min(rect.width / remoteWidth, rect.height / remoteHeight);
  const renderedWidth = remoteWidth * scale;
  const renderedHeight = remoteHeight * scale;
  const offsetX = rect.left + (rect.width - renderedWidth) / 2;
  const offsetY = rect.top + (rect.height - renderedHeight) / 2;
  const fx = clamp((clientX - offsetX) / renderedWidth, 0, 1);
  const fy = clamp((clientY - offsetY) / renderedHeight, 0, 1);
  return { x: Math.round(fx * POINTER_MAX), y: Math.round(fy * POINTER_MAX) };
}

function clamp(value: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, value));
}

/** `WheelEvent.deltaMode` values. */
export const DELTA_PIXEL = 0;
export const DELTA_LINE = 1;
export const DELTA_PAGE = 2;

/** Pixels per wheel notch in pixel mode (Chromium's default). */
export const PIXELS_PER_NOTCH = 100;
/** Lines per wheel notch in line mode (Firefox's default). */
export const LINES_PER_NOTCH = 3;

/**
 * Converts `WheelEvent` deltas into whole 1/120-notch protocol units, carrying the
 * fractional remainder to the next event (high-resolution trackpads report many tiny
 * deltas). DOM `deltaY` is positive when scrolling down; the protocol is positive up.
 */
export class ScrollAccumulator {
  private restX = 0;
  private restY = 0;

  accumulate(
    deltaX: number,
    deltaY: number,
    deltaMode: number,
  ): { x: number; y: number } {
    const unitsPerDelta = unitsPerDeltaUnit(deltaMode);
    this.restX += deltaX * unitsPerDelta;
    this.restY += -deltaY * unitsPerDelta;
    // `|| 0` turns `Math.trunc(-0.4) === -0` into a plain zero.
    const x = Math.trunc(this.restX) || 0;
    const y = Math.trunc(this.restY) || 0;
    this.restX -= x;
    this.restY -= y;
    return { x, y };
  }

  reset(): void {
    this.restX = 0;
    this.restY = 0;
  }
}

function unitsPerDeltaUnit(deltaMode: number): number {
  switch (deltaMode) {
    case DELTA_LINE:
      return WHEEL_STEP / LINES_PER_NOTCH;
    case DELTA_PAGE:
      return WHEEL_STEP;
    default:
      return WHEEL_STEP / PIXELS_PER_NOTCH;
  }
}

/**
 * Keys the browser must keep for itself even while the canvas has focus: the
 * `F11` fullscreen toggle and `Escape` exit are handled by the page.
 */
export function isLocalShortcut(code: string): boolean {
  return code === "F11";
}
