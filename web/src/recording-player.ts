/**
 * Seekable `.odrec` browser session recording player.
 *
 * Reference implementations:
 * - `apache_guacamole-client/guacamole-common-js/src/main/webapp/modules/SessionRecording.js`
 *   (lines 42–290): `Guacamole.SessionRecording` keyframe index construction
 *   (`KEYFRAME_CHAR_INTERVAL = 16384`, `KEYFRAME_TIME_INTERVAL = 5000`) and
 *   `seek(positionMs)` via the nearest preceding keyframe; (lines 857–930, 1128–1146,
 *   1237–1260): `continuePlayback()` timestamp-based frame scheduling anchored on the
 *   wall-clock time at which `play()` was called, `pause()` cancelling the pending timer,
 *   and the end-of-stream transition when no frame follows the current one.
 * - `Ylianst_MeshCentral/meshrelay.js` (lines 134–156): 16-byte big-endian record header
 *   (`Type: u16 BE + Flags: u16 BE + Size: u32 BE + TimestampMs: u64 BE`).
 * - `crates/recording/src/lib.rs` (`parse_odrec_stream`, `OdrecRecord::decode`,
 *   `RecordType::from_u16`): the Rust parser this player must agree with byte for byte.
 */

export const ODREC_MAGIC = "ODREC001";
export const ODREC_HEADER_LEN = 16;
export const KEYFRAME_FLAG = 0x0002;

export enum OdrecRecordType {
  Metadata = 1,
  FrameData = 2,
  EndOfStream = 3,
  InputEvent = 4,
  ClipboardEvent = 5,
}

export interface ParsedOdrecFrame {
  readonly index: number;
  readonly recordType: OdrecRecordType;
  readonly flags: number;
  readonly timestampMs: number;
  readonly keyframe: boolean;
  readonly payload: Uint8Array;
}

/**
 * Clock and one-shot timer used to schedule frame delivery. Injected so playback can be
 * driven deterministically in tests; production code uses {@link REAL_TIME_TIMER}.
 */
export interface PlaybackTimer {
  /** Monotonic-enough wall clock in milliseconds (`Date.now()` semantics). */
  now(): number;
  /** Schedules `callback` after `delayMs` and returns an opaque handle. */
  setTimeout(callback: () => void, delayMs: number): unknown;
  /** Cancels a timer previously returned by {@link PlaybackTimer.setTimeout}. */
  clearTimeout(handle: unknown): void;
}

/** Default {@link PlaybackTimer} backed by the host's `setTimeout`/`clearTimeout`/`Date.now`. */
export const REAL_TIME_TIMER: PlaybackTimer = {
  now: () => Date.now(),
  setTimeout: (callback, delayMs) => globalThis.setTimeout(callback, delayMs),
  clearTimeout: (handle) => {
    if (typeof handle === "number") {
      globalThis.clearTimeout(handle);
    }
  },
};

/** Optional playback hooks (`onplay`, `onpause`, `onseek` in `SessionRecording.js`). */
export interface SessionRecordingPlayerOptions {
  readonly timer?: PlaybackTimer;
  /** Receives every frame the moment its recorded timestamp is reached during playback. */
  readonly onFrame?: (frame: ParsedOdrecFrame) => void;
  readonly onPlay?: () => void;
  readonly onPause?: () => void;
  /** Receives the new relative position after a `seek()`. */
  readonly onSeek?: (positionMs: number) => void;
  /** Fires once when the last frame has been delivered; `isPlaying()` is `false` afterwards. */
  readonly onEnd?: () => void;
}

function toRecordType(raw: number): OdrecRecordType {
  switch (raw) {
    case OdrecRecordType.Metadata:
    case OdrecRecordType.FrameData:
    case OdrecRecordType.EndOfStream:
    case OdrecRecordType.InputEvent:
    case OdrecRecordType.ClipboardEvent:
      return raw;
    default:
      throw new Error(`Unknown .odrec record type: ${raw}`);
  }
}

/**
 * Stateful browser player for `.odrec` session recordings (`SessionRecording.js`).
 *
 * Playback is initially paused. `play()` schedules each following frame at
 * `frame.timestampMs - firstFrame.timestampMs` relative to the position at which playback
 * started, measured against the injected {@link PlaybackTimer}; frames are handed to
 * `onFrame`. `pause()` cancels the pending timer. When the final frame has been delivered the
 * player stops and calls `onEnd`; call `seek(0)` to rewind before playing again.
 */
export class SessionRecordingPlayer {
  private readonly frames: ParsedOdrecFrame[] = [];
  private readonly timer: PlaybackTimer;
  private readonly options: SessionRecordingPlayerOptions;
  /** Index of the last frame delivered or reached by `seek()`; `-1` before the first frame. */
  private currentFrameIndex = -1;
  private currentPositionMs = 0;
  private playing = false;
  private timerHandle: unknown = null;
  /** Recording position when `play()` was called (`startVideoPosition` in Guacamole). */
  private startVideoPositionMs = 0;
  /** Wall-clock time when `play()` was called (`startRealTimestamp` in Guacamole). */
  private startRealTimeMs = 0;

  public constructor(buffer: ArrayBuffer, options: SessionRecordingPlayerOptions = {}) {
    this.options = options;
    this.timer = options.timer ?? REAL_TIME_TIMER;
    this.parseStream(new Uint8Array(buffer));
  }

  /**
   * Parses the whole stream. Mirrors `parse_odrec_stream` in `crates/recording/src/lib.rs`:
   * every byte after the magic must belong to a complete record, so a trailing 1–15 byte
   * header fragment is a truncated recording and is rejected, never silently dropped.
   */
  private parseStream(bytes: Uint8Array): void {
    const magic = new TextDecoder().decode(bytes.subarray(0, ODREC_MAGIC.length));
    if (bytes.byteLength < ODREC_MAGIC.length || magic !== ODREC_MAGIC) {
      throw new Error("Invalid .odrec recording header");
    }

    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    let offset = ODREC_MAGIC.length;
    let index = 0;

    while (offset < bytes.byteLength) {
      const remaining = bytes.byteLength - offset;
      if (remaining < ODREC_HEADER_LEN) {
        throw new Error(
          `Truncated .odrec record header: expected ${ODREC_HEADER_LEN} bytes, got ${remaining}`,
        );
      }

      const recordType = toRecordType(view.getUint16(offset, false));
      const flags = view.getUint16(offset + 2, false);
      const payloadLen = view.getUint32(offset + 4, false);
      const timestampMs = Number(view.getBigUint64(offset + 8, false));
      offset += ODREC_HEADER_LEN;

      const available = bytes.byteLength - offset;
      if (payloadLen > available) {
        throw new Error(
          `Truncated .odrec frame payload: expected ${payloadLen} bytes, got ${available}`,
        );
      }

      const payload = bytes.subarray(offset, offset + payloadLen);
      offset += payloadLen;

      this.frames.push({
        index,
        recordType,
        flags,
        timestampMs,
        keyframe: (flags & KEYFRAME_FLAG) !== 0 || index === 0,
        payload,
      });
      index += 1;
    }
  }

  public getFrameCount(): number {
    return this.frames.length;
  }

  public getDurationMs(): number {
    const first = this.frames[0];
    const last = this.frames[this.frames.length - 1];
    if (first === undefined || last === undefined) {
      return 0;
    }
    return Math.max(0, last.timestampMs - first.timestampMs);
  }

  /** Current playback position relative to the first frame, in milliseconds. */
  public getPositionMs(): number {
    if (!this.playing) {
      return this.currentPositionMs;
    }
    const elapsed = this.timer.now() - this.startRealTimeMs;
    const live = this.startVideoPositionMs + Math.max(0, elapsed);
    return Math.min(this.getDurationMs(), Math.max(this.currentPositionMs, live));
  }

  /** Index of the last frame delivered or reached by `seek()`, or `-1` if none yet. */
  public getCurrentFrameIndex(): number {
    return this.currentFrameIndex;
  }

  public isPlaying(): boolean {
    return this.playing;
  }

  /**
   * Starts (or resumes) playback. No effect while already playing or when no frame follows
   * the current one (`SessionRecording.js` `play()`, lines 1128–1146).
   */
  public play(): void {
    if (this.playing || this.currentFrameIndex + 1 >= this.frames.length) {
      return;
    }
    this.playing = true;
    this.startVideoPositionMs = this.currentPositionMs;
    this.startRealTimeMs = this.timer.now();
    this.options.onPlay?.();
    this.scheduleNextFrame();
  }

  /**
   * Pauses playback, cancelling the pending frame timer and advancing the position by the
   * wall-clock time elapsed since `play()` (`SessionRecording.js` `pause()`, lines 1237–1260).
   */
  public pause(): void {
    this.cancelTimer();
    if (!this.playing) {
      return;
    }
    this.currentPositionMs = this.getPositionMs();
    this.playing = false;
    this.options.onPause?.();
  }

  /**
   * Seeks to `relativeOffsetMs` from the start of the recording by locating the
   * nearest preceding keyframe and returning the frames to replay up to the target frame
   * (`SessionRecording.js` `seek()`). If playback is in progress it continues from the new
   * position; if paused it stays paused.
   */
  public seek(relativeOffsetMs: number): ParsedOdrecFrame[] {
    const first = this.frames[0];
    if (first === undefined) {
      this.currentFrameIndex = -1;
      this.currentPositionMs = 0;
      return [];
    }

    const wasPlaying = this.playing;
    this.cancelTimer();

    const targetTimestamp = first.timestampMs + Math.max(0, relativeOffsetMs);

    let targetIndex = 0;
    for (let i = 0; i < this.frames.length; i += 1) {
      const candidate = this.frames[i];
      if (candidate !== undefined && candidate.timestampMs <= targetTimestamp) {
        targetIndex = i;
      } else {
        break;
      }
    }

    let keyframeIndex = targetIndex;
    while (keyframeIndex > 0 && this.frames[keyframeIndex]?.keyframe !== true) {
      keyframeIndex -= 1;
    }

    this.currentFrameIndex = targetIndex;
    this.currentPositionMs = this.toRelativeMs(this.frames[targetIndex]?.timestampMs ?? first.timestampMs);
    this.options.onSeek?.(this.currentPositionMs);

    if (wasPlaying) {
      // Re-anchor the schedule on the new position (Guacamole restarts continuePlayback()
      // after a seek while playing).
      this.startVideoPositionMs = this.currentPositionMs;
      this.startRealTimeMs = this.timer.now();
      this.scheduleNextFrame();
    }

    return this.frames.slice(keyframeIndex, targetIndex + 1);
  }

  private toRelativeMs(timestampMs: number): number {
    const first = this.frames[0];
    return first === undefined ? 0 : Math.max(0, timestampMs - first.timestampMs);
  }

  private cancelTimer(): void {
    if (this.timerHandle !== null) {
      this.timer.clearTimeout(this.timerHandle);
      this.timerHandle = null;
    }
  }

  /**
   * Schedules delivery of the frame after `currentFrameIndex` at its recorded offset from the
   * playback anchor, compensating for time already spent (`continuePlayback()` in
   * `SessionRecording.js`, lines 857–930). Ends playback when no frame remains. A no-op while
   * a frame timer is already pending, so an `onFrame` handler that calls `seek()` cannot cause
   * the same frame to be scheduled twice.
   */
  private scheduleNextFrame(): void {
    if (!this.playing || this.timerHandle !== null) {
      return;
    }
    const next = this.frames[this.currentFrameIndex + 1];
    if (next === undefined) {
      this.finishPlayback();
      return;
    }

    const elapsedReal = this.timer.now() - this.startRealTimeMs;
    const targetOffset = this.toRelativeMs(next.timestampMs) - this.startVideoPositionMs;
    const delayMs = Math.max(0, targetOffset - elapsedReal);

    this.timerHandle = this.timer.setTimeout(() => {
      this.timerHandle = null;
      if (!this.playing) {
        return;
      }
      this.currentFrameIndex += 1;
      this.currentPositionMs = this.toRelativeMs(next.timestampMs);
      this.options.onFrame?.(next);
      this.scheduleNextFrame();
    }, delayMs);
  }

  private finishPlayback(): void {
    this.cancelTimer();
    this.playing = false;
    this.currentPositionMs = this.getDurationMs();
    this.options.onEnd?.();
  }
}
