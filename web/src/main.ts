/**
 * OmegaDesk browser client: login (agent name + password), one WebSocket to the
 * gateway (`/ws` on the same origin), WebCodecs video through `video.ts` /
 * `video-worker.ts`, keyboard and pointer forwarding, latency readout.
 *
 * Structure after `zibo-chen_SubnetDesk/web/src/main.ts` (connect panel / viewer
 * panel, pointer mapping, worker hand-off) and `novnc_noVNC/app/ui.js` (canvas
 * focus owns the keyboard, `contextmenu` suppressed, fullscreen toggle).
 */

import { detectCapabilities } from "./capabilities.ts";
import {
  ScrollAccumulator,
  buttonMask,
  isLocalShortcut,
  mapCanvasPoint,
  modifierMask,
} from "./input.ts";
import {
  type ClientMessage,
  type ServerMessage,
  encodeClientMessage,
  parseServerMessage,
  validateLogin,
} from "./protocol.ts";
import { VideoPipeline, verifyProtocolFixtures } from "./video.ts";

const PING_INTERVAL_MS = 1000;

function requiredElement<T extends HTMLElement>(id: string): T {
  const element = document.getElementById(id);
  if (element === null) {
    throw new Error(`missing page element: ${id}`);
  }
  return element as T;
}

const connectPanel = requiredElement<HTMLElement>("connect-panel");
const viewerPanel = requiredElement<HTMLElement>("viewer-panel");
const loginForm = requiredElement<HTMLFormElement>("login-form");
const agentInput = requiredElement<HTMLInputElement>("agent");
const passwordInput = requiredElement<HTMLInputElement>("password");
const connectButton = requiredElement<HTMLButtonElement>("connect");
const disconnectButton = requiredElement<HTMLButtonElement>("disconnect");
const fullscreenButton = requiredElement<HTMLButtonElement>("fullscreen");
const statusElement = requiredElement<HTMLElement>("status");
const viewerStatus = requiredElement<HTMLElement>("viewer-status");
const latencyElement = requiredElement<HTMLElement>("latency");
const screenHost = requiredElement<HTMLElement>("screen-host");

interface Session {
  socket: WebSocket;
  canvas: HTMLCanvasElement;
  pipeline: VideoPipeline | null;
  remoteWidth: number;
  remoteHeight: number;
  scroll: ScrollAccumulator;
  pingTimer: number | null;
  browserRttMs: number;
  heldMs: number;
  agentRttMs: number;
  hostMs: number;
  framesSent: number;
  framesDropped: number;
  pressedCodes: Set<string>;
  teardown: Array<() => void>;
}

let session: Session | null = null;

function setStatus(message: string, error = false): void {
  statusElement.textContent = message;
  statusElement.dataset["error"] = error ? "true" : "false";
}

function send(message: ClientMessage): void {
  if (session !== null && session.socket.readyState === WebSocket.OPEN) {
    session.socket.send(encodeClientMessage(message));
  }
}

function sendBinary(frame: Uint8Array): void {
  if (session !== null && session.socket.readyState === WebSocket.OPEN) {
    session.socket.send(frame);
  }
}

function websocketUrl(): string {
  const scheme = location.protocol === "https:" ? "wss" : "ws";
  return `${scheme}://${location.host}/ws`;
}

function renderLatency(): void {
  if (session === null) {
    latencyElement.textContent = "";
    return;
  }
  const { hostMs, agentRttMs, browserRttMs, heldMs, framesSent, framesDropped } =
    session;
  // The two clocks (agent and browser) are not comparable, so the glass-to-glass
  // figure is an estimate: host capture+encode, half of each round trip, decode+render.
  const estimate = hostMs + agentRttMs / 2 + browserRttMs / 2 + heldMs;
  latencyElement.textContent =
    `~${estimate.toFixed(0)} ms (host ${hostMs} · mesh RTT ${agentRttMs} · ` +
    `web RTT ${browserRttMs.toFixed(0)} · decode+render ${heldMs}) · ` +
    `${framesSent} frames, ${framesDropped} dropped`;
}

function closeSession(message: string, error = false): void {
  const current = session;
  session = null;
  if (current !== null) {
    if (current.pingTimer !== null) {
      clearInterval(current.pingTimer);
    }
    for (const undo of current.teardown) {
      undo();
    }
    current.pipeline?.close();
    if (
      current.socket.readyState === WebSocket.OPEN ||
      current.socket.readyState === WebSocket.CONNECTING
    ) {
      current.socket.close();
    }
    current.canvas.remove();
  }
  viewerPanel.hidden = true;
  connectPanel.hidden = false;
  connectButton.disabled = false;
  viewerStatus.textContent = "";
  renderLatency();
  setStatus(message, error);
}

function releaseKeys(current: Session): void {
  // Keys never stay pressed on the remote machine when focus is lost
  // (`client/src/window.rs` releases every pressed key on blur).
  for (const code of current.pressedCodes) {
    send({ type: "key", code, key: "", pressed: false, modifiers: 0 });
  }
  current.pressedCodes.clear();
}

function attachInput(current: Session): void {
  const { canvas } = current;
  const pointer = (event: MouseEvent, wheelX = 0, wheelY = 0): void => {
    const point = mapCanvasPoint(
      event.clientX,
      event.clientY,
      canvas.getBoundingClientRect(),
      current.remoteWidth,
      current.remoteHeight,
    );
    if (point === null) {
      return;
    }
    send({
      type: "pointer",
      x: point.x,
      y: point.y,
      buttons: buttonMask(event.buttons),
      wheel_x: wheelX,
      wheel_y: wheelY,
    });
  };
  const listen = <K extends keyof HTMLElementEventMap>(
    target: HTMLElement | Window,
    type: K,
    handler: (event: HTMLElementEventMap[K]) => void,
    options?: AddEventListenerOptions,
  ): void => {
    target.addEventListener(type, handler as EventListener, options);
    current.teardown.push(() =>
      target.removeEventListener(type, handler as EventListener, options),
    );
  };

  listen(canvas, "pointermove", (event) => pointer(event));
  listen(canvas, "pointerdown", (event) => {
    canvas.focus();
    canvas.setPointerCapture(event.pointerId);
    pointer(event);
  });
  listen(canvas, "pointerup", (event) => {
    pointer(event);
    canvas.releasePointerCapture(event.pointerId);
  });
  listen(canvas, "contextmenu", (event) => event.preventDefault());
  listen(
    canvas,
    "wheel",
    (event) => {
      event.preventDefault();
      const { x, y } = current.scroll.accumulate(
        event.deltaX,
        event.deltaY,
        event.deltaMode,
      );
      if (x !== 0 || y !== 0) {
        pointer(event, x, y);
      }
    },
    { passive: false },
  );
  const key = (event: KeyboardEvent, pressed: boolean): void => {
    if (isLocalShortcut(event.code)) {
      return;
    }
    event.preventDefault();
    if (pressed) {
      current.pressedCodes.add(event.code);
    } else {
      current.pressedCodes.delete(event.code);
    }
    send({
      type: "key",
      code: event.code,
      key: event.key,
      pressed,
      modifiers: modifierMask(event),
    });
  };
  listen(canvas, "keydown", (event) => key(event, true));
  listen(canvas, "keyup", (event) => key(event, false));
  listen(canvas, "blur", () => releaseKeys(current));
  listen(window, "blur", () => releaseKeys(current));
}

function handleServerMessage(current: Session, message: ServerMessage): void {
  switch (message.type) {
    case "connected":
      viewerStatus.textContent = `${message.agent} (${message.device_id})`;
      setStatus(`connected to ${message.agent}`);
      connectPanel.hidden = true;
      viewerPanel.hidden = false;
      current.canvas.focus();
      break;
    case "video-config":
      current.remoteWidth = message.width;
      current.remoteHeight = message.height;
      if (current.pipeline === null) {
        current.pipeline = new VideoPipeline({
          canvas: current.canvas,
          worker: new Worker(new URL("./video-worker.js", import.meta.url), {
            type: "module",
          }),
          codec: message.codec,
          width: message.width,
          height: message.height,
          sendBinary,
          sendControl: (control) =>
            send({ type: "request-keyframe", reason: control.reason }),
          onFrameRendered: (heldMs) => {
            current.heldMs = heldMs;
          },
          onFatal: (reason) => closeSession(`video decoder failed: ${reason}`, true),
        });
      } else {
        current.pipeline.reconfigure(message.codec, message.width, message.height);
      }
      break;
    case "pong":
      current.browserRttMs = Math.max(0, performance.now() - message.sent_at_ms);
      renderLatency();
      break;
    case "stats":
      current.agentRttMs = message.agent_rtt_ms;
      current.hostMs = message.host_processing_ms;
      current.framesSent = message.frames_sent;
      current.framesDropped = message.frames_dropped;
      renderLatency();
      break;
    case "error":
      closeSession(message.message, true);
      break;
  }
}

async function connect(agent: string, password: string): Promise<void> {
  const invalid = validateLogin(agent, password);
  if (invalid !== null) {
    setStatus(invalid, true);
    return;
  }
  const capabilities = await detectCapabilities();
  if (!capabilities.webCodecsVideo || !capabilities.offscreenCanvas) {
    setStatus(
      "This browser lacks WebCodecs or OffscreenCanvas; use a current Chromium, Edge or Safari over https.",
      true,
    );
    return;
  }
  if (!capabilities.codecs.some((c) => c.codec === "avc1.42001f" && c.supported)) {
    setStatus("This browser cannot decode H.264 (avc1.42001f).", true);
    return;
  }

  connectButton.disabled = true;
  setStatus("connecting…");
  const canvas = document.createElement("canvas");
  canvas.id = "screen";
  canvas.tabIndex = 0;
  screenHost.replaceChildren(canvas);
  const socket = new WebSocket(websocketUrl());
  socket.binaryType = "arraybuffer";
  const current: Session = {
    socket,
    canvas,
    pipeline: null,
    remoteWidth: 0,
    remoteHeight: 0,
    scroll: new ScrollAccumulator(),
    pingTimer: null,
    browserRttMs: 0,
    heldMs: 0,
    agentRttMs: 0,
    hostMs: 0,
    framesSent: 0,
    framesDropped: 0,
    pressedCodes: new Set(),
    teardown: [],
  };
  session = current;
  attachInput(current);

  socket.onopen = () => {
    send({ type: "connect", agent, password });
    current.pingTimer = window.setInterval(
      () => send({ type: "ping", sent_at_ms: performance.now() }),
      PING_INTERVAL_MS,
    );
  };
  socket.onmessage = (event: MessageEvent<ArrayBuffer | string>) => {
    if (session !== current) {
      return;
    }
    if (typeof event.data === "string") {
      try {
        handleServerMessage(current, parseServerMessage(event.data));
      } catch (error) {
        closeSession(error instanceof Error ? error.message : String(error), true);
      }
      return;
    }
    current.pipeline?.handleBinaryPacket(event.data);
  };
  socket.onerror = () => {
    if (session === current) {
      closeSession("connection failed", true);
    }
  };
  socket.onclose = (event) => {
    if (session === current) {
      closeSession(
        event.wasClean ? "disconnected" : `connection lost (${event.code})`,
        !event.wasClean,
      );
    }
  };
}

loginForm.addEventListener("submit", (event) => {
  event.preventDefault();
  void connect(agentInput.value.trim(), passwordInput.value);
});
disconnectButton.addEventListener("click", () => closeSession("disconnected"));
fullscreenButton.addEventListener("click", () => {
  if (document.fullscreenElement === null) {
    void viewerPanel.requestFullscreen();
  } else {
    void document.exitFullscreen();
  }
});

try {
  verifyProtocolFixtures();
  // WebCodecs exists only in secure contexts (https, localhost, 127.0.0.1).
  setStatus(window.isSecureContext ? "ready" : "ready (WebCodecs needs https or localhost)");
} catch (error) {
  setStatus(error instanceof Error ? error.message : String(error), true);
  connectButton.disabled = true;
}
