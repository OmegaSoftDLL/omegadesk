import assert from "node:assert/strict";
import { test } from "node:test";

import {
  DELTA_LINE,
  DELTA_PAGE,
  DELTA_PIXEL,
  POINTER_MAX,
  ScrollAccumulator,
  buttonMask,
  buttons,
  isLocalShortcut,
  mapCanvasPoint,
  modifierMask,
  modifiers,
} from "../src/input.ts";

function modifierSource(active: string[]): { getModifierState(key: string): boolean } {
  return { getModifierState: (key) => active.includes(key) };
}

test("modifier mask uses the omegadesk-input bits and always validates lock state", () => {
  assert.equal(modifierMask(modifierSource([])), modifiers.LOCK_STATE_VALID);
  assert.equal(
    modifierMask(modifierSource(["Shift", "Control", "Alt", "Meta", "CapsLock", "NumLock"])),
    modifiers.SHIFT |
      modifiers.CTRL |
      modifiers.ALT |
      modifiers.META |
      modifiers.CAPS_LOCK |
      modifiers.NUM_LOCK |
      modifiers.LOCK_STATE_VALID,
  );
  assert.equal(modifiers.LOCK_STATE_VALID, 128);
});

test("button mask keeps only the five known buttons", () => {
  assert.equal(buttonMask(1), buttons.LEFT);
  assert.equal(buttonMask(2), buttons.RIGHT);
  assert.equal(buttonMask(4), buttons.MIDDLE);
  assert.equal(buttonMask(8 | 16), buttons.BACK | buttons.FORWARD);
  assert.equal(buttonMask(0xffff_ffff), 31);
  assert.equal(buttonMask(-1), 31);
});

test("canvas points map through letterboxing and clamp to the frame", () => {
  // 16:9 frame inside a 1000x1000 canvas: rendered 1000x562.5, offset y = 218.75.
  const rect = { left: 100, top: 50, width: 1000, height: 1000 };
  assert.deepEqual(mapCanvasPoint(100, 50 + 218.75, rect, 1920, 1080), { x: 0, y: 0 });
  assert.deepEqual(mapCanvasPoint(1100, 50 + 218.75 + 562.5, rect, 1920, 1080), {
    x: POINTER_MAX,
    y: POINTER_MAX,
  });
  assert.deepEqual(mapCanvasPoint(600, 50 + 500, rect, 1920, 1080), {
    x: Math.round(POINTER_MAX / 2),
    y: Math.round(POINTER_MAX / 2),
  });
  // Outside the rendered area (in the letterbox band) clamps to the edge.
  assert.deepEqual(mapCanvasPoint(600, 60, rect, 1920, 1080), {
    x: Math.round(POINTER_MAX / 2),
    y: 0,
  });
  assert.equal(mapCanvasPoint(1, 1, { ...rect, width: 0 }, 1920, 1080), null);
  assert.equal(mapCanvasPoint(1, 1, rect, 0, 1080), null);
});

test("scroll accumulator converts pixels, lines and pages into 1/120 notches", () => {
  const scroll = new ScrollAccumulator();
  // One Chromium notch down (100 px) is -120 (protocol positive is up).
  assert.deepEqual(scroll.accumulate(0, 100, DELTA_PIXEL), { x: 0, y: -120 });
  // Fractions carry over: 3 x 33.3 px adds up to one notch minus rounding.
  let total = 0;
  for (let i = 0; i < 3; i += 1) {
    total += scroll.accumulate(0, -33.3, DELTA_PIXEL).y;
  }
  assert.ok(total >= 119 && total <= 120, `${total}`);
  scroll.reset();
  // Firefox lines: 3 lines = 1 notch; horizontal keeps its sign.
  assert.deepEqual(scroll.accumulate(3, -3, DELTA_LINE), { x: 120, y: 120 });
  assert.deepEqual(scroll.accumulate(0, 1, DELTA_PAGE), { x: 0, y: -120 });
  // Tiny trackpad deltas emit nothing until a whole unit is available.
  scroll.reset();
  assert.deepEqual(scroll.accumulate(0, 0.4, DELTA_PIXEL), { x: 0, y: 0 });
  assert.deepEqual(scroll.accumulate(0, 0.5, DELTA_PIXEL), { x: 0, y: -1 });
});

test("only F11 stays with the browser", () => {
  assert.equal(isLocalShortcut("F11"), true);
  assert.equal(isLocalShortcut("F5"), false);
  assert.equal(isLocalShortcut("Escape"), false);
});
