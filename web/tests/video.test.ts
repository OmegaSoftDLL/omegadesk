import assert from "node:assert/strict";
import { test } from "node:test";

import {
  FRAME_ACK_FIXTURE,
  MAX_ACK_HELD_MS,
  VIDEO_FRAME_FIXTURE,
  VIDEO_FRAME_HEADER_LEN,
  decodeVideoFrame,
  encodeFrameAck,
  verifyProtocolFixtures,
} from "../src/video.ts";

test("decodes the shared video frame fixture byte for byte", () => {
  const frame = decodeVideoFrame(Uint8Array.from(VIDEO_FRAME_FIXTURE).buffer);
  assert.ok(frame !== null);
  assert.equal(frame.frameId, 0x1234);
  assert.equal(frame.keyframe, true);
  assert.equal(frame.timestampUs, 1_000_000);
  assert.deepEqual(Array.from(new Uint8Array(frame.payload)), [0xde, 0xad, 0xbe]);
});

test("decodes a delta frame with the largest ids and an empty payload", () => {
  const bytes = new Uint8Array(VIDEO_FRAME_HEADER_LEN);
  const view = new DataView(bytes.buffer);
  view.setUint8(0, 0x04);
  view.setUint8(1, 0x00);
  view.setUint16(2, 0xffff, false);
  view.setBigUint64(4, 2n ** 53n - 1n, false);
  const frame = decodeVideoFrame(bytes.buffer);
  assert.ok(frame !== null);
  assert.equal(frame.frameId, 0xffff);
  assert.equal(frame.keyframe, false);
  assert.equal(frame.timestampUs, Number.MAX_SAFE_INTEGER);
  assert.equal(frame.payload.byteLength, 0);
});

test("rejects short frames and other opcodes", () => {
  assert.equal(decodeVideoFrame(Uint8Array.from(VIDEO_FRAME_FIXTURE.slice(0, 11)).buffer), null);
  assert.equal(decodeVideoFrame(Uint8Array.from(FRAME_ACK_FIXTURE).buffer), null);
  assert.equal(decodeVideoFrame(new ArrayBuffer(0)), null);
});

test("encodes the shared ACK fixture and clamps held time", () => {
  assert.deepEqual(Array.from(encodeFrameAck(0x1234, 42)), FRAME_ACK_FIXTURE);
  assert.deepEqual(Array.from(encodeFrameAck(0x1_0005, 42.4)), [0x06, 0x00, 0x05, 0x00, 0x2a]);
  assert.deepEqual(Array.from(encodeFrameAck(1, 1e9)).slice(3), [0xff, 0xff]);
  assert.deepEqual(Array.from(encodeFrameAck(1, -5)).slice(3), [0, 0]);
  assert.deepEqual(Array.from(encodeFrameAck(1, Number.NaN)).slice(3), [0, 0]);
  assert.equal(MAX_ACK_HELD_MS, 0xffff);
});

test("startup self-check passes against the fixtures", () => {
  assert.doesNotThrow(() => verifyProtocolFixtures());
});
