/**
 * Main-thread bridge between the WebSocket/WebTransport binary stream and the
 * `video-worker.ts` OffscreenCanvas decoder worker.
 *
 * Ported from `zibo-chen_SubnetDesk/web/src/video.ts` (worker hand-off, ACK relay)
 * and `selkies-project_selkies/addons/selkies-web-core/selkies-ws-core.js`
 * (`0x04` video chunk header, `CLIENT_FRAME_ACK <id> <heldMs>`, `requestKeyframe()`).
 *
 * Binary wire protocol `omegadesk-web-video/1`. **The Rust side is the source of
 * truth**: this file mirrors `WEB_VIDEO_PROTOCOL` in `server/src/web_gateway.rs`
 * byte for byte, and `VIDEO_FRAME_FIXTURE` / `FRAME_ACK_FIXTURE` below are the same
 * bytes as `WEB_VIDEO_FRAME_FIXTURE` / `WEB_FRAME_ACK_FIXTURE` there.
 *
 * ```text
 * Video frame (gateway -> browser), opcode 0x04, 12-byte header, big-endian:
 *   [0]      0x04                      BinaryFrameOpcode::VideoFrame
 *   [1]      flags                     bit0 = keyframe, other bits 0
 *   [2..4]   frame_id    u16           wraps at 65535; the id the browser ACKs
 *   [4..12]  timestamp   u64           capture timestamp in microseconds (EncodedVideoChunk.timestamp)
 *   [12..]   payload                   codec bitstream (Annex-B H.264 / VP9 / AV1 OBUs)
 *
 * Frame ACK (browser -> gateway), opcode 0x06, exactly 5 bytes, big-endian:
 *   [0]      0x06                      BinaryFrameOpcode::ClientFrameAck
 *   [1..3]   frame_id    u16           newest frame the browser has rendered (or discarded)
 *   [3..5]   held_ms     u16           ms between arrival and this ACK (decode + render), capped
 * ```
 */

import type {
  FrameWorkerMessage,
  InitWorkerMessage,
  ReconfigureWorkerMessage,
  VideoWorkerOutbound,
} from "./video-worker.ts";

/** Opcode `0x04`: encoded video frame (`BinaryFrameOpcode::VideoFrame`). */
export const OPCODE_VIDEO_FRAME = 0x04;
/** Opcode `0x06`: browser frame ACK (`BinaryFrameOpcode::ClientFrameAck`). */
export const OPCODE_CLIENT_FRAME_ACK = 0x06;
/** `WEB_VIDEO_FRAME_HEADER_LEN` in `web_gateway.rs`. */
export const VIDEO_FRAME_HEADER_LEN = 12;
/** `WEB_FRAME_ACK_LEN` in `web_gateway.rs`. */
export const FRAME_ACK_LEN = 5;
/** `WEB_VIDEO_FLAG_KEYFRAME` in `web_gateway.rs`. */
export const VIDEO_FLAG_KEYFRAME = 0x01;
/** Largest `held_ms` the 16-bit ACK field can carry. */
export const MAX_ACK_HELD_MS = 0xffff;

/**
 * Same bytes as `WEB_VIDEO_FRAME_FIXTURE` in `server/src/web_gateway.rs`:
 * keyframe, `frame_id = 0x1234`, `timestamp_us = 1_000_000`, payload `DE AD BE`.
 */
export const VIDEO_FRAME_FIXTURE: readonly number[] = [
  0x04, 0x01, 0x12, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x42, 0x40, 0xde,
  0xad, 0xbe,
];

/** Same bytes as `WEB_FRAME_ACK_FIXTURE`: ACK for `frame_id = 0x1234` held 42 ms. */
export const FRAME_ACK_FIXTURE: readonly number[] = [0x06, 0x12, 0x34, 0x00, 0x2a];

/** Decoded `0x04` video frame header plus its payload. */
export interface DecodedVideoFrame {
  frameId: number;
  keyframe: boolean;
  timestampUs: number;
  payload: ArrayBuffer;
}

/** Control message forwarded over the session control channel (text / `0x05`). */
export interface KeyframeRequestControl {
  type: "request-keyframe";
  reason: string;
}

export type SessionControlMessage = KeyframeRequestControl;

export interface VideoPipelineOptions {
  canvas: HTMLCanvasElement;
  worker: Worker;
  codec: string;
  width: number;
  height: number;
  /** Sends a binary frame (the `0x06` ACK) back to the gateway. */
  sendBinary: (frame: Uint8Array) => void;
  /** Sends a control message over the session control channel (keyframe requests). */
  sendControl: (message: SessionControlMessage) => void;
  /** Called when the worker gives up (unsupported codec configuration, repeated failures). */
  onFatal?: (reason: string) => void;
  /** Called after each rendered frame with the arrival-to-render time (decode + draw). */
  onFrameRendered?: (heldMs: number) => void;
}

export class VideoPipeline {
  private readonly worker: Worker;
  private readonly sendBinary: (frame: Uint8Array) => void;
  private readonly sendControl: (message: SessionControlMessage) => void;
  private readonly onFatal: ((reason: string) => void) | undefined;
  private readonly onFrameRendered: ((heldMs: number) => void) | undefined;

  constructor(options: VideoPipelineOptions) {
    this.worker = options.worker;
    this.sendBinary = options.sendBinary;
    this.sendControl = options.sendControl;
    this.onFatal = options.onFatal;
    this.onFrameRendered = options.onFrameRendered;

    const offscreen = options.canvas.transferControlToOffscreen();
    const initMsg: InitWorkerMessage = {
      type: "init",
      canvas: offscreen,
      codec: options.codec,
      width: options.width,
      height: options.height,
    };
    this.worker.postMessage(initMsg, [offscreen]);

    this.worker.onmessage = (ev: MessageEvent<VideoWorkerOutbound>) => {
      const msg = ev.data;
      switch (msg.type) {
        case "ack":
          // Sent by the worker only after the frame was rendered (or deliberately
          // discarded), so the gateway's in-flight queue reflects real decode backlog.
          this.sendBinary(encodeFrameAck(msg.frameId, msg.heldMs));
          if (!msg.discarded) {
            this.onFrameRendered?.(msg.heldMs);
          }
          break;
        case "request-keyframe":
          // Selkies `requestKeyframeInternal()`: the encoder only learns about a lost
          // or unusable reference if the request reaches it over the control channel.
          this.sendControl({ type: "request-keyframe", reason: msg.reason });
          break;
        case "fatal":
          this.onFatal?.(msg.reason);
          break;
      }
    };
  }

  /**
   * Demultiplexes an incoming binary WebSocket/WebTransport datagram or stream
   * frame and transfers video payloads zero-copy to the WebCodecs worker.
   */
  public handleBinaryPacket(packet: ArrayBuffer): void {
    const decoded = decodeVideoFrame(packet);
    if (decoded === null) {
      return;
    }
    const frameMsg: FrameWorkerMessage = {
      type: "frame",
      frameId: decoded.frameId,
      timestampUs: decoded.timestampUs,
      keyframe: decoded.keyframe,
      payload: decoded.payload,
    };
    this.worker.postMessage(frameMsg, [decoded.payload]);
  }

  /** Rebuilds the decoder for a new codec or frame size (`video-config` from the gateway). */
  public reconfigure(codec: string, width: number, height: number): void {
    const msg: ReconfigureWorkerMessage = {
      type: "reconfigure",
      codec,
      width,
      height,
    };
    this.worker.postMessage(msg);
  }

  /** Stops the worker; the canvas it drew to is left as is. */
  public close(): void {
    this.worker.onmessage = null;
    this.worker.terminate();
  }
}

/**
 * Decodes a `0x04` video frame (`parse_web_video_frame` in `web_gateway.rs`).
 * Returns `null` for other opcodes or a frame shorter than its 12-byte header.
 */
export function decodeVideoFrame(packet: ArrayBuffer): DecodedVideoFrame | null {
  if (packet.byteLength < VIDEO_FRAME_HEADER_LEN) {
    return null;
  }
  const view = new DataView(packet);
  if (view.getUint8(0) !== OPCODE_VIDEO_FRAME) {
    return null;
  }
  const flags = view.getUint8(1);
  return {
    frameId: view.getUint16(2, false),
    keyframe: (flags & VIDEO_FLAG_KEYFRAME) !== 0,
    // Microsecond timestamps stay far below 2^53, so Number is exact.
    timestampUs: Number(view.getBigUint64(4, false)),
    payload: packet.slice(VIDEO_FRAME_HEADER_LEN),
  };
}

/**
 * Encodes the 5-byte `0x06` frame ACK (`pack_web_frame_ack` in `web_gateway.rs`).
 * `heldMs` is clamped to the 16-bit field.
 */
export function encodeFrameAck(frameId: number, heldMs: number): Uint8Array {
  const buf = new ArrayBuffer(FRAME_ACK_LEN);
  const view = new DataView(buf);
  view.setUint8(0, OPCODE_CLIENT_FRAME_ACK);
  view.setUint16(1, frameId & 0xffff, false);
  const held = Number.isFinite(heldMs)
    ? Math.min(MAX_ACK_HELD_MS, Math.max(0, Math.round(heldMs)))
    : 0;
  view.setUint16(3, held, false);
  return new Uint8Array(buf);
}

/**
 * Self-check mirroring the Rust test `web_video_protocol_fixtures_match_the_browser_contract`:
 * decodes `VIDEO_FRAME_FIXTURE` and re-encodes `FRAME_ACK_FIXTURE`. Throws on any
 * disagreement so a protocol drift is caught at startup instead of as a silent black screen.
 */
export function verifyProtocolFixtures(): void {
  const frame = decodeVideoFrame(Uint8Array.from(VIDEO_FRAME_FIXTURE).buffer);
  if (
    frame === null ||
    frame.frameId !== 0x1234 ||
    !frame.keyframe ||
    frame.timestampUs !== 1_000_000 ||
    !bytesEqual(new Uint8Array(frame.payload), [0xde, 0xad, 0xbe])
  ) {
    throw new Error("omegadesk-web-video/1: video frame fixture mismatch");
  }
  if (!bytesEqual(encodeFrameAck(0x1234, 42), FRAME_ACK_FIXTURE)) {
    throw new Error("omegadesk-web-video/1: frame ACK fixture mismatch");
  }
}

function bytesEqual(actual: Uint8Array, expected: readonly number[]): boolean {
  if (actual.length !== expected.length) {
    return false;
  }
  for (let i = 0; i < expected.length; i += 1) {
    if (actual[i] !== expected[i]) {
      return false;
    }
  }
  return true;
}
