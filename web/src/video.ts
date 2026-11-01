/**
 * Main-thread bridge between the WebSocket/WebTransport binary stream and the
 * `video-worker.ts` OffscreenCanvas decoder worker.
 *
 * Ported from `zibo-chen_SubnetDesk/web/src/video.ts` and
 * `selkies-project_selkies/src/selkies/websockets_mode.py`.
 *
 * Binary wire framing (matches `server/src/web_gateway.rs` `GatewayFrame`):
 * - `0x01` VideoFrame: `[0x01, flags(1), seq(4 BE), timestamp_us(8 BE), ...payload]`
 * - `0x03` FrameAck:   `[0x03, seq(4 BE), render_time_us(4 BE)]`
 */

import type {
  FrameWorkerMessage,
  InitWorkerMessage,
  VideoWorkerOutbound,
} from "./video-worker";

export const OPCODE_VIDEO_FRAME = 0x01;
export const OPCODE_AUDIO_FRAME = 0x02;
export const OPCODE_FRAME_ACK = 0x03;

export class VideoPipeline {
  private readonly worker: Worker;
  private readonly sendBinary: (frame: Uint8Array) => void;

  constructor(
    canvasElement: HTMLCanvasElement,
    worker: Worker,
    codec: string,
    width: number,
    height: number,
    sendBinary: (frame: Uint8Array) => void,
  ) {
    this.worker = worker;
    this.sendBinary = sendBinary;

    const offscreen = canvasElement.transferControlToOffscreen();
    const initMsg: InitWorkerMessage = {
      type: "init",
      canvas: offscreen,
      codec,
      width,
      height,
    };
    this.worker.postMessage(initMsg, [offscreen]);

    this.worker.onmessage = (ev: MessageEvent<VideoWorkerOutbound>) => {
      const msg = ev.data;
      if (msg.type === "ack") {
        const ackFrame = encodeFrameAck(msg.sequence, 0);
        this.sendBinary(ackFrame);
      }
    };
  }

  /**
   * Demultiplexes an incoming binary WebSocket/WebTransport datagram or stream
   * frame and transfers video payloads zero-copy to the WebCodecs worker.
   */
  public handleBinaryPacket(packet: ArrayBuffer): void {
    const view = new DataView(packet);
    if (view.byteLength < 1) {
      return;
    }
    const opcode = view.getUint8(0);
    if (opcode === OPCODE_VIDEO_FRAME) {
      if (view.byteLength < 14) {
        return;
      }
      const flags = view.getUint8(1);
      const keyframe = (flags & 0x01) !== 0;
      const sequence = view.getUint32(2, false);
      const timestampUs = Number(view.getBigUint64(6, false));
      const payload = packet.slice(14);

      const frameMsg: FrameWorkerMessage = {
        type: "frame",
        sequence,
        timestampUs,
        keyframe,
        payload,
      };
      this.worker.postMessage(frameMsg, [payload]);
    }
  }
}

/**
 * Encodes a 9-byte `OPCODE_FRAME_ACK` binary frame matching
 * `GatewayFrame::FrameAck` in `server/src/web_gateway.rs`.
 */
export function encodeFrameAck(
  sequence: number,
  renderTimeUs: number,
): Uint8Array {
  const buf = new ArrayBuffer(9);
  const view = new DataView(buf);
  view.setUint8(0, OPCODE_FRAME_ACK);
  view.setUint32(1, sequence, false);
  view.setUint32(5, renderTimeUs, false);
  return new Uint8Array(buf);
}
