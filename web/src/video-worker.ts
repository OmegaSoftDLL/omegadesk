/**
 * Dedicated WebCodecs video decoding & OffscreenCanvas rendering worker.
 *
 * Ported from `zibo-chen_SubnetDesk/web/src/video-worker.ts` and
 * `selkies-project_selkies/src/selkies/websockets_mode.py`:
 * - Runs `VideoDecoder` off the main UI thread with `optimizeForLatency: true`
 *   and `hardwareAcceleration: "prefer-hardware"`.
 * - Enforces `MAX_DECODE_QUEUE_SIZE = 6` (`decodeQueueSize` backpressure guard)
 *   and posts per-frame `ack` messages back to the main thread so the gateway's
 *   `FrameBackpressureGate` never overflows browser buffers.
 * - Renders decoded `VideoFrame`s to an `OffscreenCanvas` via `2d` context with
 *   `desynchronized: true` and immediately calls `frame.close()`.
 */

export interface InitWorkerMessage {
  type: "init";
  canvas: OffscreenCanvas;
  codec: string;
  width: number;
  height: number;
}

export interface FrameWorkerMessage {
  type: "frame";
  sequence: number;
  timestampUs: number;
  keyframe: boolean;
  payload: ArrayBuffer;
}

export interface ReconfigureWorkerMessage {
  type: "reconfigure";
  codec: string;
  width: number;
  height: number;
}

export type VideoWorkerInbound =
  | InitWorkerMessage
  | FrameWorkerMessage
  | ReconfigureWorkerMessage;

export interface AckWorkerOutbound {
  type: "ack";
  sequence: number;
  decodeQueueSize: number;
}

export interface RequestKeyframeOutbound {
  type: "request-keyframe";
  reason: string;
}

export type VideoWorkerOutbound = AckWorkerOutbound | RequestKeyframeOutbound;

/** Maximum queued frames inside `VideoDecoder` before dropping delta frames. */
export const MAX_DECODE_QUEUE_SIZE = 6;

let canvas: OffscreenCanvas | null = null;
let ctx: OffscreenCanvasRenderingContext2D | null = null;
let decoder: VideoDecoder | null = null;
let waitingForKeyframe = true;

function configureDecoder(codec: string, width: number, height: number): void {
  if (decoder && decoder.state !== "closed") {
    decoder.close();
  }

  decoder = new VideoDecoder({
    output: (frame: VideoFrame) => {
      try {
        if (canvas && ctx) {
          if (
            canvas.width !== frame.displayWidth ||
            canvas.height !== frame.displayHeight
          ) {
            canvas.width = frame.displayWidth;
            canvas.height = frame.displayHeight;
          }
          ctx.drawImage(frame, 0, 0);
        }
      } finally {
        frame.close();
      }
    },
    error: (err: DOMException) => {
      waitingForKeyframe = true;
      const msg: RequestKeyframeOutbound = {
        type: "request-keyframe",
        reason: err.message,
      };
      self.postMessage(msg);
    },
  });

  decoder.configure({
    codec,
    codedWidth: width,
    codedHeight: height,
    optimizeForLatency: true,
    hardwareAcceleration: "prefer-hardware",
  });
  waitingForKeyframe = true;
}

self.onmessage = (event: MessageEvent<VideoWorkerInbound>) => {
  const msg = event.data;

  switch (msg.type) {
    case "init": {
      canvas = msg.canvas;
      ctx = canvas.getContext("2d", {
        alpha: false,
        desynchronized: true,
      });
      configureDecoder(msg.codec, msg.width, msg.height);
      break;
    }

    case "reconfigure": {
      configureDecoder(msg.codec, msg.width, msg.height);
      break;
    }

    case "frame": {
      if (!decoder || decoder.state !== "configured") {
        return;
      }

      if (waitingForKeyframe) {
        if (!msg.keyframe) {
          const req: RequestKeyframeOutbound = {
            type: "request-keyframe",
            reason: "waiting-for-initial-keyframe",
          };
          self.postMessage(req);
          return;
        }
        waitingForKeyframe = false;
      }

      if (decoder.decodeQueueSize >= MAX_DECODE_QUEUE_SIZE && !msg.keyframe) {
        waitingForKeyframe = true;
        const req: RequestKeyframeOutbound = {
          type: "request-keyframe",
          reason: "decode-queue-overflow",
        };
        self.postMessage(req);
        return;
      }

      const chunk = new EncodedVideoChunk({
        type: msg.keyframe ? "key" : "delta",
        timestamp: msg.timestampUs,
        data: msg.payload,
      });
      decoder.decode(chunk);

      const ack: AckWorkerOutbound = {
        type: "ack",
        sequence: msg.sequence,
        decodeQueueSize: decoder.decodeQueueSize,
      };
      self.postMessage(ack);
      break;
    }
  }
};
