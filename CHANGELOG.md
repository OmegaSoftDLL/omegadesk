# Changelog

All notable changes to OmegaDesk are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project will follow [Semantic Versioning](https://semver.org/) once it has releases.

## [Unreleased]

### Added

- Phase 4 web dashboard, browser client, and connection manager: `omegadesk-policy` (`Tenant` → `DeviceGroup` → `Device` hierarchy, `UserGroup` memberships, SNI tenant resolution, explicit `AdminRole` separated from `SiteRights` and `MeshRights` bitflags, and 4-layer remote-user consent ported from MeshCentral), `omegadesk-server::web_gateway` + `web/` TypeScript client (WebTransport/WebSocket gateway with Origin/Host validation, per-IP `ConnectionLimiter` and `RequestRateBudget` ported from SubnetDesk, WebCodecs `VideoDecoder` Worker with `OffscreenCanvas`, `vp09.00.10.08`/`avc1.42001f`/`av01.0.04M.08` codec negotiation, Selkies binary framing with `FrameBackpressureGate` per-frame ACK, and noVNC browser `KeyboardEvent.code` to QEMU scancode + X11 keysym mapping including ABNT2 `IntlRo`/`IntlBackslash`), `omegadesk-session::connection_manager` (mRemoteNG folder property inheritance, 1Remote `#tag`/`-#tag` and direct/initials/discrete-subsequence keyword launcher, and `.rdp`, RDCMan `.rdg`, and PuTTY XML importers), `omegadesk-transport::race` (`race_transports_prefer_direct` with 500 ms direct priority window ported from RustDesk), and `omegadesk-codec::video_region` (`VideoRegionDetector` with 500 ms lossless paint-over refresh ported from KasmVNC and Selkies).
- Phase 3 remote access product: Windows `SYSTEM` service desktop switching (`Winlogon` / UAC Secure Desktop detection via `OpenInputDesktop` / `GetUserObjectInformationW` / `SetThreadDesktop`, RDP session handoff monitor via `WTSGetActiveConsoleSessionId`, `DXGI -> WGC -> GDI` fallback with `BitBlt(..., SRCCOPY | CAPTUREBLT)`, and connection-scoped `WDA_EXCLUDEFROMCAPTURE` privacy mode), `omegadesk-session` (clipboard sync with SHA-256 loop suppression, resumable chunked file transfer with SHA-256 verification, Opus `RESTRICTED_LOWDELAY` 48 kHz profiles, multi-monitor switching, chat, terminal, RustDesk-derived `VideoQosController`, `InvalidateReferenceFrames`, systematic `GF(2^8)` Reed-Solomon FEC, and SubnetDesk-derived mDNS + TOFU serverless LAN handshake), and `omegadesk-quicksupport` (9-digit formatted ID, auto-rotating temporary password after 10 failures, Apollo `PERM` bitflags, and MeshCentral 4-layer remote-user consent).
- Phase 2 mesh network and coordinator: `omegadesk-noise` (Noise `IK` control channel bound to Ed25519/X25519 device identities), `omegadesk-tun` (validated IPv4/IPv6 packets, `PacketBatch` channel batching, and `InMemoryTun`), `omegadesk-mesh` (sans-I/O connectivity engine with Tailscale-style `disco` hole-punching, 1.5 s relay fallback, and automatic direct-path upgrade), `omegadesk-relay` (stateless DERP-style public-key packet relay with single-use HMAC-SHA256 tickets), and `omegadesk-server` (pre-authorized/ephemeral machine keys, `NetmapBatcher` delta stream, and `*.omega` MagicDNS resolver).
- Automated release workflow (`release-plz` + `git-cliff` + multiplatform archives with `.sha256` sidecars) and OpenSSF Scorecard supply-chain security workflow and badge.
- Per-Monitor V2 DPI awareness (`SetProcessDpiAwarenessContext`), `CapsLock`/`NumLock` toggle state synchronization, `Ctrl+Alt+Del` (`SendSAS` / `Ctrl+Alt+End` shortcut), Windows URO (UDP Receive Segment Coalescing) kill switch in `omegadesk-transport`, Windows low-level keyboard hook (`WH_KEYBOARD_LL`) for `Alt+Tab`/`Alt+Esc`/`LWin`/`RWin`, `AltGr` synthetic `ControlLeft` suppression, fractional scroll accumulation (`ScrollAccumulator`), and aspect-ratio preserving bilinear scaling in `omegadesk-client`.
- Zero-copy D3D11 GPU encoding path in `omegadesk-codec` (`ID3D11VideoProcessor` BGRA→NV12 + `MFCreateDXGISurfaceBuffer` + `IMFDXGIDeviceManager`).
- Hardware cursor capture and compositing (`MONOCHROME`, `COLOR`, `MASKED_COLOR`) and rotated monitor support (`90°`, `180°`, `270°`) in `omegadesk-capture`.
- Hardware H.264 encoding through Media Foundation (Intel Quick Sync, NVIDIA NVENC, AMD AMF), with automatic fallback to OpenH264. Measured 60 fps and 24.5 ms end-to-end latency at 1080p.
- Mandatory access password, generated at every start of the agent.
- Keyframe requests: the client asks for a keyframe after a dropped frame or a decode error.
- Agent and client binaries: DXGI screen capture, QUIC transport with certificate pinning, keyboard and mouse with physical scancodes, latency breakdown in the client title bar.
- Crates `omegadesk-capture`, `omegadesk-codec`, `omegadesk-input` and `omegadesk-transport`.
- Foundation: Rust workspace, CI on Windows, Linux and macOS, dependency license policy (`cargo deny`), `omegadesk-protocol` and `omegadesk-identity`.

### Fixed

- Horizontal mouse wheel direction in the Windows client (`winit` sign inversion relative to `MOUSEEVENTF_HWHEEL`).
- Keys and mouse buttons no longer stay pressed on the remote machine when the session drops or the client loses focus.
- The agent never re-sends an old screen image after losing access to the display (lock screen, UAC).
- The Windows 11 power throttling (EcoQoS) no longer slows the agent down.

[Unreleased]: https://github.com/OmegaSoftDLL/omegadesk/commits/main
