/**
 * JSON control protocol `omegadesk-web-control/1` shared with the gateway.
 *
 * **The Rust side is the source of truth**: this file mirrors `WebClientMessage` and
 * `WebServerMessage` in `server/src/web_gateway.rs` field by field, and the fixtures
 * below are the same strings as `WEB_CONTROL_CONNECT_FIXTURE` /
 * `WEB_CONTROL_VIDEO_CONFIG_FIXTURE` there. Text frames carry one JSON object with a
 * `type` discriminator (Selkies types its text verbs the same way in
 * `websockets_mode.py`); binary frames are the video/ACK protocol in `video.ts`.
 */

export const CONTROL_PROTOCOL = "omegadesk-web-control/1";

/** Browser -> gateway (`WebClientMessage`). */
export type ClientMessage =
  | { type: "connect"; agent: string; password: string }
  | {
      type: "key";
      code: string;
      key: string;
      pressed: boolean;
      modifiers: number;
    }
  | {
      type: "pointer";
      x: number;
      y: number;
      buttons: number;
      wheel_x: number;
      wheel_y: number;
    }
  | { type: "request-keyframe"; reason: string }
  | { type: "ping"; sent_at_ms: number };

/** Gateway -> browser (`WebServerMessage`). */
export type ServerMessage =
  | { type: "connected"; agent: string; device_id: string }
  | { type: "video-config"; codec: string; width: number; height: number }
  | { type: "pong"; sent_at_ms: number }
  | {
      type: "stats";
      agent_rtt_ms: number;
      browser_rtt_ms: number;
      host_processing_ms: number;
      frames_sent: number;
      frames_dropped: number;
      in_flight: number;
    }
  | { type: "error"; message: string };

/** Same string as `WEB_CONTROL_CONNECT_FIXTURE` in `server/src/web_gateway.rs`. */
export const CONNECT_FIXTURE =
  '{"type":"connect","agent":"office-pc","password":"correct horse"}';

/** Same string as `WEB_CONTROL_VIDEO_CONFIG_FIXTURE` in `server/src/web_gateway.rs`. */
export const VIDEO_CONFIG_FIXTURE =
  '{"type":"video-config","codec":"avc1.42001f","width":1920,"height":1080}';

/** Longest agent name the gateway accepts (`MAX_AGENT_NAME_LEN`). */
export const MAX_AGENT_NAME_LEN = 253;
/** Longest password the gateway accepts (`MAX_PASSWORD_LEN`). */
export const MAX_PASSWORD_LEN = 256;

/** Serializes a client message as one text frame (`type` first, then the fields). */
export function encodeClientMessage(message: ClientMessage): string {
  return JSON.stringify(message);
}

/** Thrown by {@link parseServerMessage} for anything the gateway would not send. */
export class ProtocolError extends Error {
  constructor(message: string) {
    super(`${CONTROL_PROTOCOL}: ${message}`);
    this.name = "ProtocolError";
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function str(record: Record<string, unknown>, field: string): string {
  const value = record[field];
  if (typeof value !== "string") {
    throw new ProtocolError(`field "${field}" must be a string`);
  }
  return value;
}

function num(record: Record<string, unknown>, field: string): number {
  const value = record[field];
  if (typeof value !== "number" || !Number.isFinite(value)) {
    throw new ProtocolError(`field "${field}" must be a finite number`);
  }
  return value;
}

/**
 * Parses one text frame from the gateway, validating every field so a protocol
 * drift fails loudly instead of as `undefined` in the UI.
 */
export function parseServerMessage(text: string): ServerMessage {
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    throw new ProtocolError("text frame is not JSON");
  }
  if (!isRecord(value)) {
    throw new ProtocolError("text frame is not an object");
  }
  const type = value["type"];
  switch (type) {
    case "connected":
      return {
        type,
        agent: str(value, "agent"),
        device_id: str(value, "device_id"),
      };
    case "video-config":
      return {
        type,
        codec: str(value, "codec"),
        width: num(value, "width"),
        height: num(value, "height"),
      };
    case "pong":
      return { type, sent_at_ms: num(value, "sent_at_ms") };
    case "stats":
      return {
        type,
        agent_rtt_ms: num(value, "agent_rtt_ms"),
        browser_rtt_ms: num(value, "browser_rtt_ms"),
        host_processing_ms: num(value, "host_processing_ms"),
        frames_sent: num(value, "frames_sent"),
        frames_dropped: num(value, "frames_dropped"),
        in_flight: num(value, "in_flight"),
      };
    case "error":
      return { type, message: str(value, "message") };
    default:
      throw new ProtocolError(`unknown message type ${JSON.stringify(type)}`);
  }
}

/** Validates the login form the way the gateway will (`WebClientMessage::parse`). */
export function validateLogin(agent: string, password: string): string | null {
  if (agent.length === 0 || agent.length > MAX_AGENT_NAME_LEN) {
    return "Enter the agent name (for example office-pc).";
  }
  if (!/^[A-Za-z0-9._-]+$/.test(agent)) {
    return "Agent names contain only letters, digits, '.', '-' and '_'.";
  }
  if (new TextEncoder().encode(password).length > MAX_PASSWORD_LEN) {
    return "The password is too long.";
  }
  return null;
}
