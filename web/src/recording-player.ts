/**
 * Seekable `.odrec` browser session recording player.
 *
 * Reference implementations:
 * - `apache_guacamole-client/guacamole-common-js/src/main/webapp/modules/SessionRecording.js`
 *   (lines 42–290): `Guacamole.SessionRecording` keyframe index construction
 *   (`KEYFRAME_CHAR_INTERVAL = 16384`, `KEYFRAME_TIME_INTERVAL = 5000`), playback timer,
 *   and `seek(positionMs)` via the nearest preceding keyframe.
 * - `Ylianst_MeshCentral/meshrelay.js` (lines 134–156): 16-byte big-endian record header
 *   (`Type: u16 BE + Flags: u16 BE + Size: u32 BE + TimestampMs: u64 BE`).
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
 * Stateful browser player for `.odrec` session recordings (`SessionRecording.js`).
 */
export class SessionRecordingPlayer {
  private readonly frames: ParsedOdrecFrame[] = [];
  private currentFrameIndex = -1;
  private currentPositionMs = 0;
  private playing = false;

  public constructor(buffer: ArrayBuffer) {
    this.parseStream(new Uint8Array(buffer));
  }

  private parseStream(bytes: Uint8Array): void {
    const magic = new TextDecoder().decode(bytes.subarray(0, 8));
    if (magic !== ODREC_MAGIC) {
      throw new Error("Invalid .odrec recording header");
    }

    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    let offset = 8;
    let index = 0;

    while (offset + ODREC_HEADER_LEN <= bytes.byteLength) {
      const recordType = view.getUint16(offset, false) as OdrecRecordType;
      const flags = view.getUint16(offset + 2, false);
      const payloadLen = view.getUint32(offset + 4, false);
      const timestampMs = Number(view.getBigUint64(offset + 8, false));
      offset += ODREC_HEADER_LEN;

      if (offset + payloadLen > bytes.byteLength) {
        throw new Error("Truncated .odrec frame payload");
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
    if (this.frames.length === 0) {
      return 0;
    }
    const first = this.frames[0].timestampMs;
    const last = this.frames[this.frames.length - 1].timestampMs;
    return Math.max(0, last - first);
  }

  public getPositionMs(): number {
    return this.currentPositionMs;
  }

  public isPlaying(): boolean {
    return this.playing;
  }

  public play(): void {
    this.playing = true;
  }

  public pause(): void {
    this.playing = false;
  }

  /**
   * Seeks to `relativeOffsetMs` from the start of the recording by locating the
   * nearest preceding keyframe and replaying up to the target frame
   * (`SessionRecording.js` `seek()`).
   */
  public seek(relativeOffsetMs: number): ParsedOdrecFrame[] {
    if (this.frames.length === 0) {
      this.currentFrameIndex = -1;
      this.currentPositionMs = 0;
      return [];
    }

    const baseTimestamp = this.frames[0].timestampMs;
    const targetTimestamp = baseTimestamp + Math.max(0, relativeOffsetMs);

    let targetIndex = 0;
    for (let i = 0; i < this.frames.length; i += 1) {
      if (this.frames[i].timestampMs <= targetTimestamp) {
        targetIndex = i;
      } else {
        break;
      }
    }

    let keyframeIndex = targetIndex;
    while (keyframeIndex > 0 && !this.frames[keyframeIndex].keyframe) {
      keyframeIndex -= 1;
    }

    this.currentFrameIndex = targetIndex;
    this.currentPositionMs = this.frames[targetIndex].timestampMs - baseTimestamp;
    return this.frames.slice(keyframeIndex, targetIndex + 1);
  }
}
