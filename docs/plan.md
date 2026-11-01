# OmegaDesk build plan


This plan brings together the code analysis of the 39 reference repositories (listed in [references.md](references.md)). Each decision notes where the idea came from. Ideas and architecture are free to reuse; **code is only copied when the license allows it**, and with attribution.

---

## 1. Principles

1. **Latency first.** Capture, encode and send without going through the CPU whenever a GPU is available. Every frame carries its own processing time, and the client displays the total delay.
2. **Our own network.** Every machine joins an encrypted private mesh. Nobody opens ports on their router; the relay is ours.
3. **Zero trust.** Strong per-device identity, central policy, consent from the remote user, recording and auditing.
4. **One product.** Remote access, quick support, RMM, PAM and VPN in the same agent, the same server and the same dashboard.
5. **Clean code.** Small crates, a *sans-I/O* network core (testable without a network), no 5,000-line files, no static global configuration. These are the flaws we found in RustDesk, MeshCentral and EasyTier.

---

## 2. The best of each repository

### 2.1 Connection and protocol

| What to adopt | Source | How it lands in OmegaDesk |
|---|---|---|
| Protobuf envelope with `oneof` and a negotiated codec (`SupportedEncoding`) | RustDesk `libs/base/protos/message.proto` | Same design, in `crates/protocol`, with an explicit protocol version |
| Transport race: tries TCP, hole-punched UDP, IPv6 and WebRTC at the same time and keeps the first one that works | RustDesk `src/client.rs` (`race_transports_prefer_webrtc`) | Race between the direct mesh path, the relay and WebSocket |
| Stateless relay with single-use tickets issued by the coordinator | Aspia (`RelayKeyPool`, `ConnectionOffer`) | Relays with no database, horizontally scalable |
| LAN-only mode: mDNS, handshake with a signed transcript, trust on first use (TOFU) | SubnetDesk (`lan_mdns.rs`, `lan_protocol.rs`, `lan_identity.rs`) | Works without internet and without a server |
| Single-executable quick support with consent | UltraVNC SingleClick, Remotely | "OmegaDesk QuickSupport": download, run, show the ID, the user accepts |

**Do not copy:** RustDesk's cryptography (`sodiumoxide` is deprecated and the nonce is fixed at zero) and rustdesk-server's global "license key".

### 2.2 Mesh network (Tailscale-style)

| What to adopt | Source | How it lands in OmegaDesk |
|---|---|---|
| WireGuard cryptography in Rust, only the `noise::Tunn` core | boringtun 0.7 (BSD-3) | **Direct dependency**, with our own I/O on tokio |
| *Sans-I/O* connection library: ICE + WireGuard | Firezone `snownet` (Apache-2.0) | Model for `crates/mesh`; `str0m`/`is` crates for ICE |
| Per-platform virtual network adapter (wintun with offload) | Firezone `tun-windows`, `tun-apple`, `tun-linux` | One crate per platform |
| Discovery messages (Ping, Pong, CallMeMaybe) and continuous upgrade from the relay to the direct path | Tailscale `disco/`, `wgengine/magicsock/` | Our own "magicsock", on a single UDP socket |
| Relay addressed by public key, over HTTPS on port 443, picking the nearest region | Tailscale DERP | `omegadesk-relay` |
| Network map pushed over a stream with deltas and batched changes | Headscale `hscontrol/mapper/batcher.go` | Netmap stream in the coordinator |
| HuJSON policies (groups, tags, grants) compiled into a per-node filter | Tailscale/Headscale `policy/v2` | Same format, for people who already know Tailscale |
| Posture checks (OS, version, geolocation, process) and on-demand connections | NetBird `posture/`, `lazyconn/` | Policy only grants access if the machine is compliant |
| Groups and identity signed into the certificate; any node can act as a relay | Nebula | Phase 2 |
| Peer-to-peer routing without a central server (OSPF) | EasyTier | Phase 2, as inspiration only (LGPL license) |
| Internal DNS (MagicDNS) | Tailscale `net/dns`, EasyTier, Firezone | `machine-name.omega` |

**Decision:** our **own** control protocol, with semantics inspired by `tailcfg`. Compatibility with the Tailscale app comes later, as a separate gateway, because their protocol is undocumented and changes with every release.

**Do not copy:** the ZeroTier controller (`nonfree/`), NetBird server code (AGPL), Netmaker's `pro/`, EasyTier's `xor` cipher, and innernet's sequential "NAT traversal".

### 2.3 Video and low latency

| What to adopt | Source | How it lands in OmegaDesk |
|---|---|---|
| Windows capture: Desktop Duplication (`DuplicateOutput1`, FP16 for HDR), with WGC and GDI as fallbacks | Sunshine `display_base.cpp`, CrossDesk | `crates/capture` with a fallback order |
| `SetMaximumFrameLatency(1)` and high GPU priority | Sunshine | On by default |
| Color conversion in a shader, handing the texture straight to the encoder | Sunshine `display_vram.cpp`, RustDesk `hwcodec` (vram mode) | Zero-copy path |
| NVENC `ULTRA_LOW_LATENCY`, no B-frames, no lookahead; AMF ULTRA_LOW_LATENCY; QSV `async_depth=1`; VAAPI or Vulkan Video on Linux | Sunshine `nvenc_base.cpp`, `video.cpp`, `vulkan_encode.cpp` | Hardware encoder behind a trait |
| On packet loss, invalidate reference frames or use intra-refresh instead of sending a full frame (IDR) | Sunshine `invalidate_ref_frames` | Recovery without bandwidth spikes |
| Adaptive Reed-Solomon forward error correction over UDP | Sunshine, Apollo (AVX2/AVX512) | `reed-solomon-simd` crate |
| Processing time in every frame header and a latency panel in the client | Sunshine `frame_processing_latency`, Moonlight `ffmpeg.cpp` | Overlay: host, network, decode and render |
| Quality control: measures delay, lowers bitrate first and then fps | RustDesk `video_qos.rs` | Combined with per-frame acknowledgements (from Selkies) |
| Detects "looks like video" from the changed area; static content at lossless quality | KasmVNC `EncodeManager.cxx`, Selkies "paint-over" | Sharp text and smooth video |
| Virtual display at the client's resolution and FPS, stable identity and headless mode | Apollo `virtual_display.cpp` | Our own IddCx driver (SudoVDA is GPL) |
| Low-latency presentation: flip model, tearing allowed, 1 to 3 frame queue | Moonlight `d3d11va.cpp`, `pacer.cpp` | Native client |
| Opus audio in `RESTRICTED_LOWDELAY` | Sunshine `audio.cpp` | Default |

**Do not copy:** the GameStream protocol, PIN pairing and the session-as-"app" concept (Sunshine/Apollo); p2p's `CopyFromScreen` capture and JPEG codec; UltraVNC's mirror driver.

### 2.4 Windows: service, login screen and UAC

| What to adopt | Source |
|---|---|
| SYSTEM service that launches the capture process in the active session with the `winlogon.exe` token (`CreateProcessAsUserW`), which allows capturing the login screen and UAC | RustDesk `src/platform/windows.rs`, `windows.cc` |
| Explicit handling of the switch to the Secure Desktop and of RDP session handoff | CrossDesk `secure_desktop_dxgi_capture.h`, `rdp_session_handoff.cpp` |
| Separation between the agent service and the per-user-session process | Remotely, CrossDesk |
| Privacy mode (black screen for whoever is sitting at the machine) | RustDesk `src/privacy_mode/` |

### 2.5 Browser (web client)

| What to adopt | Source |
|---|---|
| H.264/H.265/AV1 decoded with WebCodecs inside a Worker + OffscreenCanvas, no MSE and no jitter buffer | Selkies `selkies-ws-core.js`, noVNC `core/decoders/h264.js`, SubnetDesk `video-worker.ts` |
| Codec ladder based on `VideoDecoder.isConfigSupported` | Selkies |
| Per-frame acknowledgement (ACK) to measure round-trip time and drop frames for slow clients | Selkies `websockets_mode.py` |
| WebTransport or WebRTC DataChannel, falling back to WebSocket; binary messages typed by the first byte | Selkies, KasmVNC `webudp` |
| Keyboard: send scancode + keysym, which handles international layouts (ABNT2 included) | noVNC (QEMU ext key), Guacamole `Keyboard.js` |
| WebSocket gateway in Rust (Axum + rustls) with Origin checking and per-IP limits | SubnetDesk `web_gateway.rs` |
| RDP in the browser via WASM | IronRDP `ironrdp-web` + RDCleanPath |

**Do not copy:** Guacamole's model of decoding and re-encoding into images (it doubles latency), the Java/Tomcat layer in the middle, and uncompressed PCM audio.

### 2.6 RDP and VNC compatibility

| What to adopt | Source |
|---|---|
| **RDP client** for existing Windows machines, reached through the mesh | IronRDP as a dependency: `ironrdp-connector`, `-session`, `-tokio`, `-graphics`, `-egfx`, `-cliprdr`, `-rdpdr`, `-rdpsnd`, `-displaycontrol` |
| **RDP server** fed by our own capture (later phase) | `ironrdp-server` (`egfx` feature) + `ironrdp-acceptor` |
| Interoperability testing | FreeRDP (conformance reference, not a dependency) |
| Per-user virtual session on Linux | xrdp (model) |
| Congestion algorithm and per-region encoder selection | TigerVNC `Congestion.cxx`, `EncodeManager.cxx` |
| VNC/RFB compatibility mode | TigerVNC (later phase) |

IronRDP versions are pinned exactly (the API is still 0.x).

### 2.7 Management, permissions and multi-tenancy

| What to adopt | Source |
|---|---|
| Tenant > device group > device hierarchy, plus user groups | MeshCentral (domains), Remotely, Tactical RMM (Client > Site > Agent) |
| Bitflag permissions (view only, no terminal, no files, limited input, share with guest…) in a single crate | MeshCentral `MESHRIGHT_*` and `SITERIGHT_*` |
| "Admin" as an explicit role, never "all bits set" | Fixes a MeshCentral flaw (`0xFFFFFFFF`) |
| Layered remote-user consent: tenant > group > machine > user | MeshCentral |
| Per-client permissions: clipboard, upload, commands, view only | Apollo `PERM` |
| Roles with `can_*` flags and client/site scoping | Tactical RMM (idea only) |
| Multiple domains and certificates (SNI) per tenant | MeshCentral `webserver.js` |

### 2.8 RMM (machine management)

| What to adopt | Source |
|---|---|
| Inheritable policies applied to a client, site or machine | Tactical RMM (idea only) |
| Checks → alerts → alert templates with failure and resolution actions | Tactical RMM (idea only) |
| Per-site deployment links with an expiring token | Tactical RMM (idea only), MeshCentral |
| Inventory, custom fields, Windows Update, scheduled scripts | Tactical RMM, Remotely `ScriptScheduler.cs` |
| Agent auto-update: the agent sends its binary hash and the server streams the new one in chunks, with a concurrency limit | MeshCentral `meshagent.js` |
| Message bus with topics bound to the agent's identity | Tactical RMM (NATS) → in OmegaDesk, over QUIC on the mesh |

### 2.9 Auditing, recording and privileged access (PAM)

| What to adopt | Source |
|---|---|
| Recording done at the relay, independent of the agent, in an append-only format with a TLV + timestamp header and a keyframe index for seeking forward and back | MeshCentral `.mcrec`, `meshrelay.js`; Guacamole `recording.c` |
| Terminal recorded as asciicast `.cast`, to reuse existing players | JumpServer |
| Typed commands indexed separately, with search | JumpServer `CommandStorage` |
| Recording player in the browser | Guacamole `SessionRecording.js` |
| Access requests with multi-level approval (Ticket with steps) | JumpServer `apps/tickets/` |
| Login, command and clipboard rules with graded actions: accept, reject, review, warn | JumpServer `apps/acls/` |
| Join a live session with a code, an expiry and read-only mode; lock or terminate a session | JumpServer `sharing.py`, MeshCentral `meshdesktopmultiplex.js` |
| Data loss prevention (clipboard limits, keystroke rate, region) and watermarking | KasmVNC DLP |

### 2.10 Authentication

| What to adopt | Source |
|---|---|
| OIDC, SAML, LDAP, TOTP, passkeys/WebAuthn, brute-force lockout | Guacamole `extensions/`, JumpServer `authentication/`, defguard (idea only) |
| Per-connection MFA, not just per login | defguard (idea only) |
| Pre-authorized and ephemeral keys for deploying machines | Headscale `preauth_keys.go` |
| The password never goes over the wire: SRP or OPAQUE for the unattended access password | Aspia (SRP) |
| Persistent machine key + node key with rotation and expiry | Tailscale |

### 2.11 Connection manager and vault

| What to adopt | Source |
|---|---|
| Folder tree with property inheritance **and** filterable tags | mRemoteNG, 1Remote |
| Keyboard search launcher | 1Remote `KeywordMatchService.cs` |
| Import from RDCMan, `.rdp`, PuTTY and Active Directory | mRemoteNG `MiscSerializers/`, IronRDP `ironrdp-rdpfile` |
| A real credential vault (envelope encryption, Argon2id) and the system keyring in the desktop client | Remmina (keyring); fixes 1Remote's `UnSafeStringEncipher` |

### 2.12 New differentiators

| What to adopt | Source |
|---|---|
| **MCP** server for AI agents (screenshot, click, typing) with per-machine trust control | QuickDesk `quickdesk-mcp/` (`rmcp` crate) |
| Grid of multiple live desktops | CrossDesk DeskHub |
| Dashboard with webhooks and auditing | QuickDesk `SignalingServer/internal/models/` |

---

## 3. Architecture

```
                        ┌──────────────────────────────────────────┐
                        │            omegadesk-server              │
                        │  coordinator: accounts, tenants, policy, │
                        │  netmap, relay tickets, RMM, PAM, API    │
                        │  (Axum + PostgreSQL/SQLite)              │
                        └──────┬──────────────────────┬────────────┘
                 netmap stream │ (Noise IK over QUIC) │ dashboard / API
                               │                      │
   ┌───────────────────┐  ┌────┴───────────────┐   ┌──┴──────────────────┐
   │  omegadesk-relay  │  │  omegadesk-agent   │   │   web (TypeScript)  │
   │  stateless,       │  │  SYSTEM service    │   │  dashboard + client │
   │  by public key,   │◄─┤  + session worker  │   │   WebCodecs/Worker  │
   │  HTTPS 443,       │  │  capture, encoder, │   └─────────────────────┘
   │  records sessions │  │  input, RMM, mesh  │
   └───────────────────┘  └────────────────────┘
            ▲                      ▲  WireGuard (boringtun) + disco + relay
            └──────────┬───────────┘
              ┌────────┴─────────┐
              │ omegadesk-client │  desktop app (Tauri) with hardware
              │ + QuickSupport   │  decoding, connection manager
              └──────────────────┘
```

### Rust workspace

```
omegadesk/
├── crates/
│   ├── protocol/      # protobuf (prost), versions, oneof envelope
│   ├── identity/      # ed25519/x25519 keys, machine and node keys, TOFU
│   ├── noise/         # Noise IK control channel (snow)
│   ├── mesh/          # sans-I/O: WireGuard (boringtun), disco, ICE (str0m), relay
│   ├── tun/           # wintun / utun / tun-linux
│   ├── transport/     # QUIC (quinn), route racing, Reed-Solomon FEC
│   ├── capture/       # DXGI → WGC → GDI; PipeWire/KMS; ScreenCaptureKit
│   ├── codec/         # Encoder/Decoder trait: NVENC, AMF, QSV, VAAPI, VideoToolbox, software
│   ├── input/         # keyboard, mouse, touch and pen injection
│   ├── session/       # video, audio, clipboard, files, chat, terminal
│   ├── recording/     # .odrec format (TLV + index), asciicast
│   ├── policy/        # HuJSON → per-node filter; bitflag permissions
│   ├── rdp/           # IronRDP integration
│   └── mcp/           # MCP server (rmcp)
├── agent/             # agent binary (service + session worker)
├── client/            # Tauri app
├── quicksupport/      # single-executable quick support
├── server/            # coordinator
├── relay/             # stateless relay
├── drivers/
│   └── idd/           # IddCx virtual display (Windows)
└── web/               # dashboard + web client (TypeScript)
```

### Main dependencies

| Role | Crate | Notes |
|---|---|---|
| Async | `tokio` | |
| WireGuard | `boringtun` 0.7, `noise::Tunn` only | without the `device` module |
| ICE | `str0m` / `is` | Firezone `snownet` design |
| QUIC | `quinn` + `quinn-udp` | GSO/GRO |
| Noise | `snow` | control channel |
| Windows TUN | `wintun` | |
| Protobuf | `prost` | |
| HTTP/Web | `axum`, `rustls`, `tokio-tungstenite` | |
| Database | `sqlx` (PostgreSQL and SQLite) | |
| FEC | `reed-solomon-simd` | |
| Audio | `opus` | |
| RDP | `ironrdp-*` | pinned versions |
| MCP | `rmcp` | |
| Desktop UI | `tauri` | |
| Permissions | `bitflags` | |

---

## 4. Build phases

Each phase ends with something that runs and can be demoed. ✅ marks what is done.

### Phase 0: Foundation (1–2 weeks) ✅
- ✅ Rust workspace, CI (Windows, Linux and macOS builds; `clippy` with strict lints in the Firezone style; `cargo deny` for licenses).
- ✅ `protocol` with the first messages; `identity` with keys and secure storage.
- ✅ **Done when:** CI is green on all three platforms and `cargo deny` blocks incompatible licenses.

### Phase 1: First image on screen (3–4 weeks) ✅
- ✅ First image on screen: the agent captures the Windows screen (DXGI) and the image shows up on the other side, including hardware cursor compositing (`MONOCHROME`, `COLOR`, `MASKED_COLOR`) and rotated monitors (`90°`, `180°`, `270°`).
- ✅ Hardware encoder (Media Foundation: Quick Sync/NVENC/AMF) with zero-copy GPU texture pipeline (`ID3D11VideoProcessor` BGRA→NV12 + `MFCreateDXGISurfaceBuffer` + `IMFDXGIDeviceManager`).
- ✅ Software encoder fallback (`OpenH264`) and sending over direct QUIC.
- ✅ Native client decodes and displays; mouse (including horizontal and vertical wheel) and keyboard working.
- ✅ Latency overlay (host, network, decode and render).
- ✅ **Done when:** controlling another machine on the same local network, with latency **≤ 30 ms** on the LAN at 1080p60.
- ✅ **Measured so far:** 60 fps and 24.5 ms total latency at 1080p (Intel Core Ultra 5 135U), below the 30 ms target.

### Phase 2: Mesh network and server (4–6 weeks) ✅
- ✅ Coordinator (`omegadesk-server`): machine enrollment with pre-authorized and ephemeral keys (`odk_<prefix>_<secret>` with SHA-256 secret hashing and `tag:` ACL validation), coalesced netmap delta stream (`NetmapBatcher`), and Noise `IK` control channel (`omegadesk-noise`).
- ✅ `mesh` (`omegadesk-mesh`) and `tun` (`omegadesk-tun`): sans-I/O connectivity engine (`MeshNode`), Tailscale-style `disco` (`Ping`, `Pong`, `CallMeMaybe`), built-in STUN reflexive endpoint discovery, automatic upgrade from the relay to a direct UDP path, and batched virtual adapter packets (`PacketBatch`).
- ✅ Stateless relay (`omegadesk-relay`) on port 443 with single-use HMAC-SHA256 tickets (`RelayTicket`, `TicketValidator`) and DERP-style public-key routing (`FrameSendPacket` / `FrameRecvPacket` / `FramePeerGone`).
- ✅ Internal DNS `*.omega` (`MagicDnsResolver` mapping `<hostname>.omega` to `100.64.0.0/10` and `fd7a:115c:a1e0::/48` with reverse `PTR` lookup).
- ✅ **Done when:** two machines behind different NATs connect without opening ports; when the direct connection fails, it falls back to the relay in under 2 s (`RELAY_FALLBACK_TIMEOUT = 1.5 s`).

### Phase 3: Remote access product (4–6 weeks) ✅
- ✅ Windows `SYSTEM` service desktop management (`crates/capture/src/service_desktop.rs` & `gdi.rs`): `Winlogon` / UAC Secure Desktop detection and switching (`OpenInputDesktop` / `GetUserObjectInformationW` / `SetThreadDesktop`), session target process lookup (`winlogon.exe` / `explorer.exe` / `sihost.exe`), RDP session handoff monitor (`WTSGetActiveConsoleSessionId`), `DXGI -> WGC -> GDI` capture fallback chain (`BitBlt(..., SRCCOPY | CAPTUREBLT)`), and connection-scoped privacy mode (`WDA_EXCLUDEFROMCAPTURE`).
- ✅ Session channels (`crates/session/src/channels.rs` & `crates/protocol`): clipboard sync (`TextUtf8`, `HtmlUtf8`, `FileList` with SHA-256 loop suppression), chunked file transfer with resume offset and end-to-end SHA-256 verification, Opus `RESTRICTED_LOWDELAY` 48 kHz audio profiles (stereo, 5.1, 7.1), multi-monitor enumeration & runtime switching, chat, and terminal resize/data channels.
- ✅ Adaptive quality control (`crates/session/src/qos.rs` & `fec.rs`): RustDesk-derived `VideoQosController` (bitrate-first reduction, 150 ms RTT knee, 20-sample restore guard), per-frame ACK with `InvalidateReferenceFrames` before IDR fallback, and systematic `GF(2^8)` Reed-Solomon FEC (`encode_fec_block` / `reconstruct_fec_block` with adaptive parity sizing).
- ✅ QuickSupport (`quicksupport/`): single executable with 9-digit formatted ID (`NNN-NNN-NNN`), brute-force-resistant temporary password (`MAX_CONSECUTIVE_FAILURES = 10` auto-rotation), Apollo `PERM` 3-group bitflag permissions (`ClientPermissions`), and MeshCentral 4-layer remote-user consent (`tenant | group | machine | user` with 30 s prompt timeout and 5-minute grace timer).
- ✅ Serverless LAN mode (`crates/session/src/lan.rs`): mDNS `_omegadesk._udp.local.` announcement/discovery, SubnetDesk-derived `omegadesk-lan-v1` Ed25519 transcript signature verification, and Trust On First Use (`TofuStore`) fingerprint pinning.
- ✅ **Done when:** it replaces RustDesk/AnyDesk for Omega's day-to-day support.

### Phase 4: Web dashboard and browser client (4–6 weeks) ✅
- ✅ Dashboard (`crates/policy` / `omegadesk-policy`): `Tenant` → `DeviceGroup` → `Device` hierarchy, `UserGroup` memberships, SNI domain-to-tenant routing (`resolve_tenant_by_sni`), explicit `AdminRole` separated from `SiteRights` (`SITERIGHT_*`) and `MeshRights` (`MESHRIGHT_*` bitflags without MeshCentral's `0xFFFFFFFF` superadmin overload), and 4-layer remote-user consent (`tenant | group | machine | user`, ported from MeshCentral `apprelays.js`, `meshrelay.js`, `meshuser.js`, and `webserver.js`).
- ✅ Web client & gateway (`server/src/web_gateway.rs` + `web/src/`): WebCodecs `VideoDecoder` in a dedicated Worker (`web/src/video-worker.ts`) rendering to `OffscreenCanvas`, WebCodecs capability negotiation (`vp09.00.10.08`, `avc1.42001f`, `av01.0.04M.08` from SubnetDesk `web/src/capabilities.ts`), Selkies binary framing (`0x01`..`0x05`) with per-frame ACK backpressure (`FrameBackpressureGate`), Origin/Host validation and per-IP connection & sliding-window rate limits (`ConnectionLimiter`, `RequestRateBudget` from SubnetDesk `src/web_gateway.rs`), and browser `KeyboardEvent.code` / `key` to QEMU scancode + X11 keysym mapping including ABNT2 `IntlRo` and `IntlBackslash` (from noVNC `core/input/keyboard.js`).
- ✅ Connection manager (`crates/session/src/connection_manager.rs`): hierarchical folder tree with property inheritance (`InheritanceFlags` from mRemoteNG `ConnectionInfoInheritance.cs`), `#tag` / `+#tag` / `-#tag` filterable tags and direct/initials/discrete-subsequence keyword launcher (from 1Remote `TagAndKeywordEncodeHelper.cs`, `TagFilter.cs`, and `KeywordMatchService.cs`), and `.rdp` (IronRDP `ironrdp-rdpfile` + mRemoteNG `RemoteDesktopConnectionDeserializer.cs`), RDCMan `.rdg` (`RemoteDesktopConnectionManagerDeserializer.cs`), and PuTTY XML (`PuttyConnectionManagerDeserializer.cs`) importers.
- ✅ Reference enrichments for Phases 1 & 2: preferred-direct vs relay transport racer with `500 ms` priority window (`crates/transport/src/race.rs`, ported from RustDesk `src/client.rs` `race_transports_prefer_webrtc`) and dynamic video-region detector with `500 ms` lossless paint-over refresh (`crates/codec/src/video_region.rs`, ported from KasmVNC `common/rfb/EncodeManager.cxx` `updateVideoStats` and Selkies).
- ✅ **Done when:** full access from the browser with latency at most 15 ms above the native client.

### Phase 5: Security, auditing and PAM (4 weeks)
- Session recording at the relay (`.odrec` + asciicast) and a player in the browser.
- HuJSON policies, posture checks, per-connection MFA.
- Access requests with approval, joining live sessions, locking and terminating sessions.
- DLP and watermarking; credential vault.
- **Done when:** every session is recorded and searchable, and access to a critical server requires approval.

### Phase 6: RMM (4–6 weeks)
- Inventory, scheduled scripts (PowerShell/bash), checks → alerts → templates.
- Inheritable policies, per-site deployment links, agent auto-update.
- **Done when:** it can manage a customer's entire fleet without any other tool.

### Phase 7: Compatibility and differentiators (ongoing)
- RDP client over the mesh (IronRDP) and RDP in the browser.
- IddCx virtual display at the client's resolution; headless mode.
- MCP server for AI agents.
- Linux (PipeWire/KMS) and macOS (ScreenCaptureKit) capture; Android and iOS apps.
- RDP and VNC server; peer relaying and coordinator-free routing.

---

## 5. Targets for being "better than all the rest"

| Metric | Target | Current reference |
|---|---|---|
| LAN latency, 1080p60, end to end | ≤ 30 ms | Moonlight/Sunshine ~20–40 ms |
| Browser latency | ≤ native + 15 ms | Guacamole/noVNC well above that |
| Time to connect (P2P) | ≤ 1 s | |
| Fallback from direct to relay | ≤ 2 s | |
| Agent size | ≤ 15 MB | |
| Agent CPU on a static screen | ≈ 0 % | |
| Server installation | 1 command, 1 binary + database | |

---

## 6. Risks and caveats

- **H.264/H.265 patents.** Prefer hardware encoders (the license comes with the GPU) and offer AV1 and VP9 as royalty-free alternatives.
- **Windows drivers.** The IddCx virtual display, and drivers in general, need Microsoft signing (EV + attestation). Plan for it early.
- **Antivirus.** Remote access software is a target. Sign every binary from day one and avoid techniques that look like malware, such as loading DLLs from memory (UltraVNC does this).
- **0.x dependencies.** IronRDP, `str0m` and `rmcp` change their APIs. Pin versions and isolate each one behind its own crate.
- **Scope.** Seven phases is a lot of work. Phases 1 to 3 already deliver a product that replaces RustDesk; the rest can follow in order of commercial priority.
- **Licenses.** `cargo deny` in CI blocks incompatible dependencies. Never open the proprietary folders (`enterprise/`, `nonfree/`, `pro/`, Tactical RMM) as a source.

---

## 7. Gaps in this analysis

- The submodules `libs/hbb_common` (RustDesk), `moonlight-common-c` (Moonlight), `kasmweb` (KasmVNC) and `proto/` (defguard) came empty in the clones. RustDesk's rendezvous protocol was inferred from the server code.
- The license of the `rustdesk-org/hwcodec` fork has not been checked yet.
- At the time of this analysis nothing had been built or measured; the targets in section 5 need to be validated in Phase 1 (the LAN latency target has since been met, see [section 4](#4-build-phases)).
