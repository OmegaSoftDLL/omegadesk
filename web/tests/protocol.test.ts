import assert from "node:assert/strict";
import { test } from "node:test";

import {
  CONNECT_FIXTURE,
  ProtocolError,
  VIDEO_CONFIG_FIXTURE,
  encodeClientMessage,
  parseServerMessage,
  validateLogin,
} from "../src/protocol.ts";

test("the connect message matches the gateway fixture", () => {
  assert.equal(
    encodeClientMessage({ type: "connect", agent: "office-pc", password: "correct horse" }),
    CONNECT_FIXTURE,
  );
});

test("client messages carry the gateway's field names", () => {
  assert.equal(
    encodeClientMessage({ type: "key", code: "KeyA", key: "a", pressed: true, modifiers: 129 }),
    '{"type":"key","code":"KeyA","key":"a","pressed":true,"modifiers":129}',
  );
  assert.equal(
    encodeClientMessage({ type: "pointer", x: 1, y: 2, buttons: 1, wheel_x: 0, wheel_y: -120 }),
    '{"type":"pointer","x":1,"y":2,"buttons":1,"wheel_x":0,"wheel_y":-120}',
  );
  assert.equal(
    encodeClientMessage({ type: "request-keyframe", reason: "decode-queue-overflow" }),
    '{"type":"request-keyframe","reason":"decode-queue-overflow"}',
  );
  assert.equal(
    encodeClientMessage({ type: "ping", sent_at_ms: 12.5 }),
    '{"type":"ping","sent_at_ms":12.5}',
  );
});

test("parses the video-config fixture and every server message", () => {
  assert.deepEqual(parseServerMessage(VIDEO_CONFIG_FIXTURE), {
    type: "video-config",
    codec: "avc1.42001f",
    width: 1920,
    height: 1080,
  });
  assert.deepEqual(
    parseServerMessage('{"type":"connected","agent":"office-pc","device_id":"abcd"}'),
    { type: "connected", agent: "office-pc", device_id: "abcd" },
  );
  assert.deepEqual(parseServerMessage('{"type":"pong","sent_at_ms":3}'), {
    type: "pong",
    sent_at_ms: 3,
  });
  assert.deepEqual(
    parseServerMessage(
      '{"type":"stats","agent_rtt_ms":5,"browser_rtt_ms":6,"host_processing_ms":7,"frames_sent":8,"frames_dropped":9,"in_flight":1}',
    ),
    {
      type: "stats",
      agent_rtt_ms: 5,
      browser_rtt_ms: 6,
      host_processing_ms: 7,
      frames_sent: 8,
      frames_dropped: 9,
      in_flight: 1,
    },
  );
  assert.deepEqual(parseServerMessage('{"type":"error","message":"invalid password"}'), {
    type: "error",
    message: "invalid password",
  });
});

test("rejects malformed server messages", () => {
  for (const bad of [
    "not json",
    "[]",
    '{"type":"nope"}',
    '{"type":"connected","agent":"x"}',
    '{"type":"video-config","codec":"avc1","width":"1920","height":1080}',
    '{"type":"pong","sent_at_ms":"soon"}',
  ]) {
    assert.throws(() => parseServerMessage(bad), ProtocolError, bad);
  }
});

test("login validation mirrors the gateway limits", () => {
  assert.equal(validateLogin("office-pc", "pw"), null);
  assert.equal(validateLogin("office-pc.omega", ""), null);
  assert.notEqual(validateLogin("", "pw"), null);
  assert.notEqual(validateLogin("office pc", "pw"), null);
  assert.notEqual(validateLogin("a".repeat(254), "pw"), null);
  assert.notEqual(validateLogin("ok", "ç".repeat(129)), null);
  assert.equal(validateLogin("ok", "ç".repeat(128)), null);
});
