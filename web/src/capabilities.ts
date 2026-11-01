/**
 * Browser media capabilities detection for OmegaDesk Web Client.
 *
 * Ported from `zibo-chen_SubnetDesk/web/src/capabilities.ts`:
 * Probes WebCodecs (`VideoDecoder`, `AudioDecoder`), WebTransport, OffscreenCanvas,
 * and hardware-accelerated decode support across VP9, H.264, and AV1.
 */

export interface CodecProbeResult {
  codec: string;
  supported: boolean;
  hardwareAccelerated: boolean;
}

export interface ClientCapabilities {
  webTransport: boolean;
  webCodecsVideo: boolean;
  webCodecsAudio: boolean;
  offscreenCanvas: boolean;
  codecs: CodecProbeResult[];
}

/**
 * Ordered codec ladder matching `omegadesk-server::web_gateway::DEFAULT_WEB_CODEC_LADDER`
 * and `SubnetDesk/web/src/capabilities.ts`.
 */
export const CODEC_LADDER: readonly string[] = [
  "vp09.00.10.08",
  "avc1.42001f",
  "av01.0.04M.08",
];

/**
 * Probes the current browser environment for WebTransport, WebCodecs, OffscreenCanvas,
 * and hardware-accelerated video decoding support.
 */
export async function detectCapabilities(): Promise<ClientCapabilities> {
  const webTransport = typeof globalThis.WebTransport !== "undefined";
  const webCodecsVideo = typeof globalThis.VideoDecoder !== "undefined";
  const webCodecsAudio = typeof globalThis.AudioDecoder !== "undefined";
  const offscreenCanvas = typeof globalThis.OffscreenCanvas !== "undefined";

  const codecs: CodecProbeResult[] = [];

  if (webCodecsVideo) {
    for (const codec of CODEC_LADDER) {
      try {
        const hwSupport = await VideoDecoder.isConfigSupported({
          codec,
          optimizeForLatency: true,
          hardwareAcceleration: "prefer-hardware",
        });
        if (hwSupport.supported) {
          codecs.push({
            codec,
            supported: true,
            hardwareAccelerated: true,
          });
          continue;
        }
        const swSupport = await VideoDecoder.isConfigSupported({
          codec,
          optimizeForLatency: true,
          hardwareAcceleration: "no-preference",
        });
        codecs.push({
          codec,
          supported: Boolean(swSupport.supported),
          hardwareAccelerated: false,
        });
      } catch {
        codecs.push({
          codec,
          supported: false,
          hardwareAccelerated: false,
        });
      }
    }
  }

  return {
    webTransport,
    webCodecsVideo,
    webCodecsAudio,
    offscreenCanvas,
    codecs,
  };
}
