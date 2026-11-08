# Architecture & QUIC Transport

## 1. End-to-End Pipeline

```text
  omegadesk-agent                                       omegadesk-client
 ┌──────────────────────────────┐    QUIC (TLS 1.3)   ┌───────────────────────────┐
 │ capture -> codec -> transport├─── video stream ───>│ transport -> decode -> UI │
 │ (DXGI)     (MF / OpenH264)   │                     │              (OpenH264)   │
 │ input <──────── control stream: ping, keys, mouse, keyframe requests ──────────┤
 │ (SendInput)                  │                     │ keyboard & mouse (winit)  │
 └──────────────────────────────┘                     └───────────────────────────┘
```

---

## 2. The 17 Modular Workspace Crates

| Crate | Responsibility |
| :--- | :--- |
| `omegadesk-protocol` | Protobuf session messages, framing, and codec capability negotiation |
| `omegadesk-identity` | Ed25519 signing keys, X25519 Diffie-Hellman keys, device IDs, and OS keychain storage |
| `omegadesk-capture` | Screen capture (`DXGI Desktop Duplication -> WGC -> GDI` fallback chain) + hardware cursor compositing |
| `omegadesk-codec` | Hardware H.264 encoding (Media Foundation `NVENC`/`QuickSync`/`AMF`) and `OpenH264` software encode/decode |
| `omegadesk-input` | Physical USB HID scancode keyboard injection (layout-independent, including ABNT2) and multi-monitor mouse mapping |
| `omegadesk-transport` | Multiplexed QUIC (TLS 1.3) streams with certificate fingerprint pinning or mesh identity-bound TLS |
| `omegadesk-noise` | Noise `IK` cryptographic handshake bound to coordinator/device identities |
| `omegadesk-mesh` | Sans-I/O NAT traversal state machine (`STUN`, `disco` probes, relay tickets, tunnel encryption) |
| `omegadesk-control` | Coordinator client for node enrollment, streaming netmap updates, and relay ticket issuance |
| `omegadesk-magicsock` | Virtual `AsyncUdpSocket` presenting direct UDP or DERP-relayed paths seamlessly to Quinn QUIC |
| `omegadesk-relay` | Stateless DERP-style encrypted packet relay with single-use tickets and integrated STUN responder |
| `omegadesk-server` | Central coordinator (`*.omega` DNS, `HuJSON` policy compiler, WebCodecs gateway, and RMM server) |
| `omegadesk-rmm-agent` | System inventory collector, heartbeat reporter, and sandboxed script runner |
| `omegadesk-service` | Windows `LocalSystem` service and per-session `winlogon.exe` worker for UAC and lock-screen capture |
| `omegadesk-agent` | Host daemon sharing displays, clipboard, and files |
| `omegadesk-quicksupport` | Zero-install 9-digit ID ad-hoc support binary with interactive console consent |
| `omegadesk-client` | Native low-latency desktop viewer with live title-bar telemetry |
