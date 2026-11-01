/**
 * Dedicated WebCodecs video decoding & OffscreenCanvas rendering worker.
 *
 * Ported from `zibo-chen_SubnetDesk/web/src/video-worker.ts` (ACK from the decoder
 * `output` callback, `pendingAcks`, immediate ACK for dropped frames) and
 * `selkies-project_selkies/addons/selkies-web-core/selkies-ws-core.js`
 * (`configureDecoder` recreating the decoder from the captured config after a
 * decoder error, `gate.configured()` requiring a keyframe after (re)configure,
 * `CLIENT_FRAME_ACK <id> <heldMs>`):
 * - Runs `VideoDecoder` off the main UI thread with `optimizeForLatency: true`
 *   and `hardwareAcceleration: "prefer-hardware"`.
 * - Enforces `MAX_DECODE_QUEUE_SIZE = 6` (`decodeQueueSize` backpressure guard).
 * - ACK policy: a frame is ACKed from the decoder `output` callback **after** it was
 *   drawn, carrying `heldMs` (arrival to render). A frame the worker discards
 *   (waiting for a keyframe, decode-queue overflow, decoder not configured, decoder
 *   reset) is ACKed **immediately** with `discarded: true` so it leaves the
 *   gateway's in-flight queue instead of being counted as decode backlog or
 *   mistaken for a stalled client.
 * - A recoverable decoder error recreates and configures the decoder from the
 *   captured configuration and asks for a keyframe; an unsupported configuration
 *   (or repeated failures without a single decoded frame) is reported as `fatal`.
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
  /** `u16` frame id from the `0x04` header; echoed in the ACK. */
  frameId: number;
  /** Capture timestamp in microseconds; also keys the decoder output back to the frame. */
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
  frameId: number;
  /** Milliseconds between the frame's arrival in the worker and this ACK. */
  heldMs: number;
  decodeQueueSize: number;
  /** `true` if the frame was never decoded (see the ACK policy above). */
  discarded: boolean;
}

export interface RequestKeyframeOutbound {
  type: "request-keyframe";
  reason: string;
}

export interface FatalWorkerOutbound {
  type: "fatal";
  reason: string;
}

export type VideoWorkerOutbound =
  | AckWorkerOutbound
  | RequestKeyframeOutbound
  | FatalWorkerOutbound;

/** Maximum queued frames inside `VideoDecoder` before dropping delta frames. */
export const MAX_DECODE_QUEUE_SIZE = 6;

/**
 * Consecutive decoder re-creations tolerated without a single decoded frame in
 * between (SubnetDesk `requestDecoderRecovery` / `maxAttempts`).
 */
export const MAX_DECODER_RECOVERY_ATTEMPTS = 3;

interface PendingFrame {
  frameId: number;
  receivedAt: number;
}

let canvas: OffscreenCanvas | null = null;
let ctx: OffscreenCanvasRenderingContext2D | null = null;
let decoder: VideoDecoder | null = null;
/** Configuration captured at (re)configure time so a failed decoder can be rebuilt. */
let decoderConfig: VideoDecoderConfig | null = null;
let waitingForKeyframe = true;
let keyframeRequested = false;
let recoveryAttempts = 0;
let fatal = false;
/** Frames handed to `decoder.decode()` that have not come out of `output` yet, by timestamp. */
const pending = new Map<number, PendingFrame>();

function post(message: VideoWorkerOutbound): void {
  self.postMessage(message);
}

function queueSize(): number {
  return decoder && decoder.state === "configured" ? decoder.decodeQueueSize : 0;
}

function ackDiscarded(frameId: number, receivedAt: number): void {
  post({
    type: "ack",
    frameId,
    heldMs: Math.max(0, Math.round(performance.now() - receivedAt)),
    decodeQueueSize: queueSize(),
    discarded: true,
  });
}

/** Frames still inside a decoder that is being torn down will never render: ACK them as discarded. */
function discardPending(): void {
  for (const entry of pending.values()) {
    ackDiscarded(entry.frameId, entry.receivedAt);
  }
  pending.clear();
}

function requestKeyframe(reason: string): void {
  waitingForKeyframe = true;
  if (keyframeRequested) {
    return;
  }
  keyframeRequested = true;
  post({ type: "request-keyframe", reason });
}

function failFatal(reason: string): void {
  fatal = true;
  discardPending();
  if (decoder && decoder.state !== "closed") {
    decoder.close();
  }
  decoder = null;
  post({ type: "fatal", reason });
}

function render(frame: VideoFrame): void {
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
}

function onDecodedFrame(frame: VideoFrame): void {
  const timestamp = frame.timestamp;
  render(frame);
  recoveryAttempts = 0;
  const entry = pending.get(timestamp);
  if (entry === undefined) {
    return;
  }
  pending.delete(timestamp);
  post({
    type: "ack",
    frameId: entry.frameId,
    heldMs: Math.max(0, Math.round(performance.now() - entry.receivedAt)),
    decodeQueueSize: queueSize(),
    discarded: false,
  });
}

/**
 * Selkies `configureDecoder()` error path: a closed decoder cannot decode the
 * recovery keyframe, so rebuild it from the captured config before asking for one.
 */
function onDecoderError(err: DOMException): void {
  if (fatal) {
    return;
  }
  discardPending();
  if (err.name === "NotSupportedError" || decoderConfig === null) {
    failFatal(`unsupported decoder configuration: ${err.message}`);
    return;
  }
  if (recoveryAttempts >= MAX_DECODER_RECOVERY_ATTEMPTS) {
    failFatal(
      `decoder failed ${recoveryAttempts} times without output: ${err.message}`,
    );
    return;
  }
  recoveryAttempts += 1;
  if (configureDecoder(decoderConfig)) {
    requestKeyframe(`decoder-error: ${err.message}`);
  }
}

/** Creates and configures a fresh decoder; returns `false` after reporting a fatal error. */
function configureDecoder(config: VideoDecoderConfig): boolean {
  if (decoder && decoder.state !== "closed") {
    decoder.close();
  }
  decoder = null;
  discardPending();

  const fresh = new VideoDecoder({
    output: onDecodedFrame,
    error: onDecoderError,
  });
  try {
    // configure() is synchronous; an invalid config throws here and an unsupported
    // one surfaces through the error callback as NotSupportedError.
    fresh.configure(config);
  } catch (err) {
    fresh.close();
    failFatal(
      `decoder configure failed: ${err instanceof Error ? err.message : String(err)}`,
    );
    return false;
  }
  decoder = fresh;
  decoderConfig = config;
  fatal = false;
  // A keyframe is required after (re)configure (Selkies `gate.configured()`).
  waitingForKeyframe = true;
  keyframeRequested = false;
  return true;
}

function handleFrame(msg: FrameWorkerMessage): void {
  const receivedAt = performance.now();

  if (fatal || !decoder || decoder.state !== "configured") {
    ackDiscarded(msg.frameId, receivedAt);
    return;
  }

  if (waitingForKeyframe) {
    if (!msg.keyframe) {
      ackDiscarded(msg.frameId, receivedAt);
      requestKeyframe("waiting-for-keyframe");
      return;
    }
    waitingForKeyframe = false;
    keyframeRequested = false;
  }

  if (decoder.decodeQueueSize >= MAX_DECODE_QUEUE_SIZE && !msg.keyframe) {
    ackDiscarded(msg.frameId, receivedAt);
    requestKeyframe("decode-queue-overflow");
    return;
  }

  const chunk = new EncodedVideoChunk({
    type: msg.keyframe ? "key" : "delta",
    timestamp: msg.timestampUs,
    data: msg.payload,
  });
  pending.set(msg.timestampUs, { frameId: msg.frameId, receivedAt });
  try {
    decoder.decode(chunk);
  } catch (err) {
    pending.delete(msg.timestampUs);
    ackDiscarded(msg.frameId, receivedAt);
    onDecoderError(
      err instanceof DOMException
        ? err
        : new DOMException(String(err), "OperationError"),
    );
  }
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
      recoveryAttempts = 0;
      configureDecoder({
        codec: msg.codec,
        codedWidth: msg.width,
        codedHeight: msg.height,
        optimizeForLatency: true,
        hardwareAcceleration: "prefer-hardware",
      });
      break;
    }

    case "reconfigure": {
      recoveryAttempts = 0;
      configureDecoder({
        codec: msg.codec,
        codedWidth: msg.width,
        codedHeight: msg.height,
        optimizeForLatency: true,
        hardwareAcceleration: "prefer-hardware",
      });
      break;
    }

    case "frame": {
      handleFrame(msg);
      break;
    }
  }
};
