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
| Virtual display at the client's resolution and FPS, stable identity and headless mode | Apollo `virtual_display.cpp`, QuickDesk IddCx driver (MIT) | Vendored signed QuickDesk IddCx driver in `drivers/idd` (SudoVDA is GPL) |
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
| Recording in an append-only format with a TLV + timestamp header and a keyframe index for seeking forward and back. MeshCentral records at the relay because it sees plaintext; OmegaDesk's relay forwards tunnel ciphertext, so the agent records (it holds the encoded frames and the keyframe flags) | MeshCentral `.mcrec`, `meshrelay.js`; Guacamole `recording.c` |
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

Each phase ends with something that runs and can be demoed.

Status legend:

- ✅ implemented, wired into a binary and verified;
- 🧩 library code exists but is not wired into any binary, or has the known defects listed below;
- ⬜ not started.

A phase is only ✅ when its **Done when** line is ✅.

Phases 2–7 were marked complete on 2026-11-01 by an automated agent; the audit of the same day (see `CHANGELOG.md`) reverted those marks. The open findings from Copilot Code Review on PRs #17–#24 are tracked in issues [#26](https://github.com/OmegaSoftDLL/omegadesk/issues/26) to [#33](https://github.com/OmegaSoftDLL/omegadesk/issues/33); each must be fixed, with a regression test, before the corresponding item becomes ✅.

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

### Phase 2: Mesh network and server (4–6 weeks) 🔶
- ✅ Coordinator (`omegadesk-server`): pre-authorized and ephemeral keys (`odk_<prefix>_<secret>`, SHA-256 secret hashing, `tag:` validation), tenant-scoped coalesced netmap deltas (`NetmapBatcher`), the Noise `IK` control channel (`omegadesk-noise`) and the `omegadesk.control.v1` protobuf control protocol. One control stream per node for its whole life: `EnrollRequest` → `EnrollResponse` (self node, same-tenant peers, one ticket per relay), then `NetmapBatch` pushes, `EndpointUpdate`, `RelayTicketRequest` and `Keepalive`; snapshots and batches are chunked to fit one Noise frame, writes time out, enrollment generations make late disconnects harmless, and a registered node reconnects with its original key even after it was consumed or expired (Headscale model). Persistent identity; the server key is printed for nodes.
- ✅ Node side (`omegadesk-control`, `omegadesk-magicsock`): the control client (enrollment, netmap stream, ticket refresh, endpoint updates, automatic re-enrollment with back-off and full resync) and the mesh socket: one UDP socket multiplexing STUN, `disco` and encrypted tunnel data, DERP-style relay connections (login sealed to the per-connection challenge, reconnect with fresh single-use tickets, `PeerGone` steering), and a [`quinn::AsyncUdpSocket`] that gives every peer a stable virtual address (`<mesh IPv4>:7070`), so the QUIC session never notices a switch between direct and relayed paths. TLS is bound to the device identity (`identity_tls`: Ed25519 certificate carrying the node key, verified against the netmap), so there is no fingerprint to copy.
- ✅ `mesh` (`omegadesk-mesh`) and `tun` (`omegadesk-tun`): sans-I/O engine (`MeshNode`) with RFC 5389 STUN client (ported from Tailscale `net/stun`), `disco` v1 (`Ping`, `Pong`, `CallMeMaybe` carrying session epochs), relay fallback in 1.5 s, direct-path trust and heartbeats (Tailscale `trustUDPAddrDuration` 6.5 s / `heartbeatInterval` 3 s), active-traffic liveness (probe after 500 ms of silence, fallback after 1.5 s), exchange-key rotation handling, and tunnel keys bound to both peers' epochs (`H(dh, sender, receiver, sender_epoch, receiver_epoch)`): a restart or re-add on either side rekeys and retires recorded ciphertext.
- ✅ Relay (`omegadesk-relay`): DERP-style frames, tickets bound to one relay, login sealed with the client's private key and the relay's per-connection challenge (no replay across connections), frame lengths validated before allocation, registration guard that always cleans up, supervised reader/writer, required HMAC secret, persistent identity, STUN responder on UDP.
- ✅ Internal names `*.omega` (`MagicDnsResolver` + netmap): the client connects with `omegadesk-client office-pc.omega --server … --server-key … --preauth-key …`; names resolve from the netmap on the node (no DNS server to configure). Serving the zone over real DNS for other programs remains ⬜.
- ✅ Agent and client: `--server`, `--server-key`, `--preauth-key` and `--relay-only` put both binaries on the mesh; without them they keep the Phase 1 LAN mode (IP + fingerprint + password). The access password is still required on the mesh (device-level policies arrive in Phase 5).
- 🔶 **Done when:** two machines behind different NATs connect without opening ports; when the direct connection fails, it falls back to the relay in under 2 s. Verified in-process (`crates/magicsock/tests/mesh_e2e.rs`: coordinator + relay + two nodes, direct-path upgrade and relay-only QUIC sessions; unit tests cover the 1.5 s fallback and the liveness timers) and across two machines over Tailscale on 2026-11-01 (coordinator + relay + agent on a second Windows host, client here): enrollment, `*.omega` lookup, relay login, STUN + `disco` hole punching and the QUIC session all worked, and the receiving side held a direct path with no fallback. Known issue: a heavily multi-homed *sender* (a host with several active adapters whose OS varies the source address per packet) can still see brief direct/relay churn, because the liveness `Ping` is answered from one address while traffic leaves from another; pinning the send source to the validated path is tracked for a follow-up. A clean test across two distinct public NATs is still pending.

### Phase 3: Remote access product (4–6 weeks) 🧩
- 🔶 Windows unattended access (`omegadesk-agent service install|uninstall|start|stop|run`, crate `omegadesk-service`): a `LocalSystem` SCM service (via the `windows-service` crate, ported from RustDesk `run_service`) launches a per-session capture/input **worker** in the active console session with the session's `winlogon.exe` SYSTEM token (`OpenProcessToken` + `DuplicateTokenEx` + `CreateProcessAsUserW`, `winsta0\default`), relaunches it on `WTS_CONSOLE_CONNECT`/`SESSION_LOGON`/RDP handoff and on crash, and asks it to stop on `SERVICE_CONTROL_STOP`/`SHUTDOWN`. The worker runs as SYSTEM, follows the input desktop (`SetThreadDesktop` onto `winsta0\winlogon` for the login screen, UAC secure desktop and lock screen), captures through the real `DXGI -> WGC -> GDI` fallback chain (Windows Graphics Capture is now implemented in `crates/capture/src/wgc.rs`), injects remote input on whichever desktop is in front, and blanks the local screen in privacy mode with a fullscreen `WDA_EXCLUDEFROMCAPTURE` overlay (visible on the monitor, absent from the capture the remote sees). Service and worker talk over a named pipe (`\\.\pipe\omegadesk-service.*`) with length-delimited `ServiceEnvelope` protobuf framing (`omegadesk-protocol`). The supervisor/desktop/IPC state machines, framing and argument parsing are unit-tested; an `#[ignore]`d Windows integration test drives install/start/stop/uninstall with admin rights. **Remaining:** the worker captures and counts frames but the QUIC video stream is not yet routed through it (it stays in `agent/src/session.rs`), so a remote client still connects to the user-session agent, not the service worker; wiring the session into the worker is the next step. `crates/capture/src/service_desktop.rs` keeps the `OpenInputDesktop`/`SetThreadDesktop`/PID-lookup/handoff helpers the worker and supervisor build on.
- 🔶 QuickSupport (`quicksupport/`): `omegadesk-quicksupport` joins the mesh as an ephemeral node (`omegadesk_magicsock::Node`) and proposes a nine-digit ID derived from its device identity; the coordinator keeps a tenant-scoped ID registry (RustDesk `RegisterPk` model: the proposal is kept when free or already owned by that device, replaced by a random free number otherwise, released the moment the node disconnects) and answers `QuickSupportLookupRequest`, while the netmap carries `NodeInfo.quicksupport_id`. The end user reads ID and temporary password to the technician, who connects with `omegadesk-client 123 456 789 --server …`; the host runs the agent's own session code (`omegadesk-agent` is now a library plus a binary) with a `SessionGate` consulted after the password check, so the user is asked for consent on the console (MeshCentral layered consent, 30 s timeout, "always for 5 minutes") only about technicians who know the password. Ten wrong passwords rotate the password (RustDesk). Verified in-process (`quicksupport/tests/quicksupport_e2e.rs`: coordinator + relay + host + technician, ID lookup, tenant scope, expiry, QUIC session handshake with wrong password, declined and accepted consent). What is missing: a graphical consent dialog and ID/password window (the prompt is a console prompt), stable IDs across runs (the identity is ephemeral by design, so the proposed ID changes every run), and the field test across two real NATs.
- 🔶 Session channels (`crates/session` with the `io` feature, `agent/src/channels/`, `client/src/channels/`), wired through `agent/src/session.rs` and `client/src/network.rs`:
  - ✅ **Clipboard**: text is synchronized in both directions with the SHA-256 echo suppression of `ClipboardSync`. The OS clipboard goes through `arboard` (text only, polled every 333 ms on a worker thread like RustDesk `clipboard_service.rs`); `--no-clipboard` turns it off. HTML, images and file lists are not synchronized.
  - ✅ **File transfer** in both directions: one QUIC bidirectional stream per file, 64 KiB chunks, up to 16 in flight, resume from a `<name>.<sha8>.odpart` partial negotiated through the first `FileTransferAck` (RustDesk `OffsetBlk`), SHA-256 verified before the final rename, and an existing destination is never overwritten (`report (1).pdf`). Client: `--send-file`, drag-and-drop onto the window; agent: `--send-file` pushes to every client; `--receive-dir` on both (default `Downloads/OmegaDesk`). The sender holds the whole file in memory (1 GiB cap); there is no file browser or directory transfer.
  - ✅ **Multi-monitor**: the agent enumerates the desktop (`omegadesk_capture::list_displays`, DXGI with GDI fallback, same indexes as `open_display`) and publishes a `DisplayList`; the client switches with `Ctrl+Alt+Shift` + `1`..`9`, `N` (next) or `P` (previous), the agent retargets capture, re-sends the catalog and answers pointer events on the new monitor.
  - 🧩 Chat and terminal are still data types with no I/O.
- 🔶 `crates/session/src/qos.rs`: the client acknowledges every decoded frame (`FrameAck` with host capture time, decode time and decode-queue depth); the agent feeds `VideoQosController`, paces capture to the controller's frame rate (RustDesk `video_service.rs` `spf`) and retunes the encoder bitrate (live through `ICodecAPI` `AVEncCommonMeanBitRate` on Media Foundation, by encoder restart on OpenH264, with hysteresis in `BitrateGovernor`); a stall of 2 s halves the frame rate. `--bitrate-mbps` and `--fps` are the ceilings. Lost frames recover with an IDR because neither encoder exposes reference-frame invalidation. `fec.rs` is still not applied to any stream.
- ⬜ **Audio**: `AudioFrame` and the Opus `RESTRICTED_LOWDELAY` profiles exist, but no capture or encoder is wired. Every Opus binding on crates.io (`opus` 0.4 via `opus-sys`, `audiopus` 0.3 via `audiopus_sys`, RustDesk's `magnum-opus`) builds libopus from source with CMake, which is not part of this project's toolchain (absent from the development machine; CI would need `cmake` on all three runners) and there is no pure-Rust Opus encoder. Licensing is not the obstacle (`audiopus_sys` is ISC, libopus BSD-3-Clause). Putting raw WASAPI PCM in `AudioFrame.opus_data` would misreport the format, so audio stays unwired until CMake is adopted or libopus is vendored.
- 🧩 Serverless LAN mode (`crates/session/src/lan.rs`): mDNS record building, transcript signatures and TOFU store exist; nothing announces, discovers or connects.
- ⬜ **Done when:** it replaces RustDesk/AnyDesk for Omega's day-to-day support.

### Phase 4: Web dashboard and browser client (4–6 weeks) 🧩
- 🧩 `crates/policy`: tenant/group/device hierarchy, SNI routing, admin role and rights bitflags, consent layers. Those directory and consent models are not consulted by any binary; the `HuJSON` session-policy compiler is wired into the coordinator as described in Phase 5.
- 🔶 Browser client and web gateway (`omegadesk-server --web-listen`, `server/src/web_server.rs`, `web_session.rs`, `web_gateway.rs`, `web/`): the coordinator joins the mesh as `web-gateway.omega` (own identity, a reusable pre-auth key it issues itself) and proxies each browser `WebSocket` to an agent chosen by name: `Hello` with the password typed in the browser, `HelloAck`, the video unidirectional stream re-framed as `omegadesk-web-video/1` (`0x04` frame, `0x06` per-frame ACK) under Selkies' `FrameBackpressureGate`, keyboard (`KeyboardEvent.code` → HID usage + keysym in the gateway, noVNC tables), pointer and keyframe requests relayed on the control stream, `Ping`/`Pong` and per-second `stats`. The page (`web/public/index.html`, `web/src/main.ts`) logs in with agent name + password, decodes H.264 (`avc1.42001f`) in a `WebCodecs` worker on an `OffscreenCanvas`, and shows an estimated glass-to-glass latency. Served from `web/dist` (`npm run build`) with SubnetDesk's `Host`/`Origin` checks, per-IP limiters and CSP. Verified in-process (`server/tests/web_gateway_e2e.rs`: coordinator + relay + agent node speaking the real protobuf session protocol + gateway + `WebSocket` client) and in CI for the TypeScript (`npm run check`, `node --test`, build). Remaining: TLS must come from a reverse proxy (`--web-behind-tls`), WebTransport is not offered (WebSocket only), no coordinator-issued session token (password only), no audio/clipboard, and the gateway's own `--web-listen` path has not been exercised against a real Windows agent yet.
- 🧩 Connection manager (`crates/session/src/connection_manager.rs`): tree, tags, search and importers exist as a library; the RDCMan and PuTTY importers lose folder structure and do not decode XML entities.
- 🧩 `crates/transport/src/race.rs` (direct-preferred transport race) and `crates/codec/src/video_region.rs` (video-area detector) are implemented and tested; neither is called by the agent or client yet.
- 🔶 **Done when:** full access from the browser with latency at most 15 ms above the native client. Keyboard, mouse and video work end to end in-process; the latency difference against `omegadesk-client` has not been measured.

### Phase 5: Security, auditing and PAM (4 weeks) 🔶
- ✅ Policy at the coordinator: `omegadesk-server --policy <file>` loads a `HuJSON` `policy/v2` document (`PolicyV2::parse_hujson`: the Headscale/Tailscale `groups`, `tagOwners`, `hosts`, `acls` and `ssh` blocks plus the OmegaDesk `sessions` block with `action: accept|check`, `record`, `clipboard.copy/paste`, `watermark` and `posture.minOs/networks`; unknown keys and undefined groups are rejected at load time), re-reads it when the file changes (the last good policy stays in force on a parse error), and builds every node's netmap from it (`NetmapBatcher::reconcile`, Headscale `BuildPeerMap` model: two nodes see each other when either can reach the other under the ACLs or a session rule; each visible peer carries the compiled `SessionGrant` for a session towards the recipient in `NodeInfo.session`). A policy change reconciles every connected node's view and pushes the resulting `PeerUpserted`/`PeerRemoved` deltas. Pre-auth keys carry an owner user (`--bootstrap-user`, `create_preauth_key_for_user`, `NodeInfo.user`) so user, `group:` and `autogroup:self` selectors work. Verified by unit tests and an in-process coordinator test over the real control protocol (`crates/control`).
- ✅ Agent-side authorization (`agent/src/access.rs`, one call from the handshake): on the mesh the connecting peer is the netmap entry owning the authenticated mesh address and the `Hello` device key must match it; the grant is enforced (denied peers get `POLICY_DENIED`; posture compares the client's self-reported OS version with `minOs` and the verified source address with `networks`, `POSTURE_REJECTED`); `"action": "check"` runs a per-connection TOTP step-up (`MfaRequired`/`MfaResponse`, RFC 6238 HMAC-SHA256, the secret stays on the agent as in RustDesk 2FA: `--totp-secret`, `--generate-totp-secret`) under `ConnectionMfaVerifier` (single-use challenge, no code replay) and `BruteForceGuard` (3 codes per challenge, lockout after 5 failures for 5 minutes, `MFA_FAILED`); the client answers with `--totp` or a terminal prompt and reports its posture in `Hello.posture`. Without a coordinator policy (LAN mode, or a server without `--policy`) the Phase 1 password rule is unchanged. Verified through the real QUIC handshake in-process (wrong code, right code, lockout, denial, posture, key mismatch).
- ✅ Recording and audit: sessions with `record: true` are written by the agent to `--recordings-dir` as `.odrec` (`OdrecStreamWriter`, streamed to disk: metadata record, every encoded `omegadesk.v1.VideoFrame` with the `KEYFRAME` flag the seek index relies on, input and clipboard messages flagged `FROM_USER`, end-of-stream); the recorder asks the encoder for a keyframe when the Guacamole intervals elapse. The agent records, not the relay: OmegaDesk's relay only forwards tunnel ciphertext between two identity keys, so it never sees a frame (MeshCentral's relay could record because it terminated the WebSocket). A policy that requires recording is refused when `--recordings-dir` is missing or the file cannot be opened; a write failure mid-session is audited (`recording_finished` with outcome `failed`) and the session continues. Both binaries write JSON Lines audit events (`omegadesk-policy::audit`, `--audit-log`): enrollment, disconnect, enrollment denied, policy loaded or rejected at the coordinator; session connected, disconnected, denied, MFA challenged, ok and failed, DLP blocked, recording started and finished at the agent. The produced files parse with `omegadesk-recording` (tested) and follow the byte rules `web/src/recording-player.ts` implements; the browser still lacks a decoder for the `VideoFrame` protobuf payload, although the TypeScript player is type-checked, tested and built in CI.
- ✅ DLP: the grant's clipboard limits are enforced on every `ClipboardEvent` the agent receives (a blocked paste is audited and left out of the recording; the clipboard channel itself still lands with Phase 3); the watermark (`user | client IP | session | time`) is composed into the BGRA frame right before encoding and removed after it, so the cached frame stays clean (`apply_watermark_bgra`: about 17 000 blended pixels and an 80 KiB save/restore per frame for a 60-character text at scale 2, under 0.1 % of a 1080p frame; on Windows a watermarked frame is encoded from its CPU pixels, giving up the zero-copy GPU path for those sessions).
- 🧩 Still library-only: `AccessTicket` approval chains and `LiveSessionController` session sharing (`crates/policy/src/pam.rs`), `CommandStorage` and the asciicast recorder (no terminal channel exists yet), geolocation and running-process posture rules (the agent has no source of truth for them, so the `HuJSON` schema deliberately omits them), screen redaction regions, and `crates/identity/src/vault.rs` (CodeQL still flags a hard-coded cryptographic value).
- 🔶 **Done when:** every session is recorded and searchable, and access to a critical server requires approval. Desktop sessions are recorded and MFA-gated by policy; approval tickets, session search and the browser player's payload decoding are the remaining steps.

### Phase 6: RMM (4–6 weeks) 🔶
- 🔶 **Inventory and heartbeat** (`crates/rmm-agent`, `agent/src/rmm.rs`): in mesh mode the agent collects hostname, OS version and build, CPU model and utilization, memory, drives, NICs, logged-on user (Win32 terminal services), uptime, running processes, Windows services and the pending-reboot state of Windows Update (registry, MeshCentral `win-info.js` model) with the `sysinfo` crate, and sends an `InventoryReport` on the control connection at enrollment, every `--inventory-interval-minutes` (default 15) and when a stable field changes. Linux and macOS report what `sysinfo` provides (no services, no Windows Update). Pending-update *counts* need a Windows Update Agent search the agent does not run; the report says `scanned = false`.
- 🔶 **Coordinator** (`server/src/rmm_service.rs`, `server/src/control_server.rs`): stores one `DeviceInventory` per device, evaluates the effective `Tenant -> Site -> Device` checks (`cpu`, `memory`, `disk`, `process`, `service`, `script`, `offline`) on every report and tick, opens and resolves alerts with `failures_before_alert`, runs alert-template remediation scripts, dispatches saved scripts and schedules (`run_on_next_connect` queue drained on reconnect), stores results, and persists everything to `--state-file` (atomic JSON; no database exists yet). `WebhookNotify` actions are recorded in the alert history but not delivered: the coordinator has no HTTP client.
- 🔶 **Operator CLI**: `omegadesk-server admin ...` (devices, device show/set, alerts, scripts, run, schedules, results, checks, templates, links, preauth) over a loopback admin API with a bearer token (Headscale's local-socket CLI model). No web dashboard yet.
- 🔶 **Deployment links**: `admin links create` issues an `odl_...` token bound to a reusable pre-auth key; `omegadesk-agent --deployment-token` enrolls into the link's tenant and site; links expire, count uses and verify in constant time. Enrolled devices reconnect through their link after it expires.
- 🧩 `AgentUpdateManager` (chunked binary self-update) and `AgentTopic` remain libraries: no update transfer runs on the control channel yet.
- ✅ Tests: inventory serialization round trip (proto and JSON), check evaluation, state file round trip, admin API, control-crate test enrolling with a deployment token and exchanging inventory and scripts, and an in-process end-to-end test (coordinator + admin API + real RMM task) that reports inventory, runs a script, queues one for an offline device and trips a check.
- ⬜ Field validation on a real fleet, Windows Update counts, webhook delivery, agent self-update over the mesh.
- ⬜ **Done when:** it can manage a customer's entire fleet without any other tool.

### Phase 7: Compatibility and differentiators (ongoing) ⬜
- 🧩 `crates/rdp`: `RDCleanPath` and `DisplayControl` structures were re-typed from IronRDP with a custom byte encoding instead of IronRDP's DER, so they do not interoperate with Devolutions Gateway; `omegadesk-rdp` does not depend on any `ironrdp-*` crate and there is no RDP client or server.
- ✅ `drivers/idd`: a real, working IddCx virtual display. The MIT-licensed QuickDesk driver is vendored under `drivers/idd/vendor/` — the kernel driver ships **prebuilt and signed** (`quickdesk_display.dll/.cat/.inf`, not built in CI since it needs the WDK) and `build.rs` compiles the user-mode controller with the normal Windows SDK. `omegadesk-idd` exposes a safe API (`VirtualDisplay::install`/`open`/`is_installed`/`uninstall`, `plug_monitor`, `MonitorHandle::set_mode`/`unplug`) installed via the bundled `nefconw.exe`; Windows-only, with a clear `Unsupported` error elsewhere. Wired into the agent as `--virtual-display <WxH@hz>` (headless hosts) and a `--privacy` mode that blanks the physical monitor, backing the `crates/capture/src/virtual_display.rs` placement model with the driver.
- 🧩 `crates/mcp`: only QuickDesk's trust policy was ported; there is no MCP server, transport or JSON-RPC.
- ⬜ Linux (PipeWire/KMS) and macOS (ScreenCaptureKit) capture: only backend-selection enums exist; `open_display` returns `Unsupported` off Windows.
- 🧩 `crates/mesh/src/peer_routing.rs` (link-state routing, relay certificates) and `VncCongestionController` are libraries with no consumer.
- ⬜ Mobile apps, VNC/RFB compatibility mode and coordinator-free operation are not started.
- 🧩 Items added by the 2026-11-01 "audit" PRs (`NodeKeyCertificate`, `UnattendedVerifier`, SSO/WebAuthn records, LDIF import, `DeskHub`, webhooks, touch/pen types, DERP region selector, lazy connections, HDR tone mapping, SSH ACL rules, hierarchical CIDRs) are unwired library code. The dead `client/src/pacer.rs` was removed: the client already bounds latency with a 3-frame decode queue and latest-frame presentation (`client/src/network.rs`).

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
