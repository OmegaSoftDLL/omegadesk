<div align="center">

# OmegaDesk

**Open source, self-hosted remote desktop. Low latency, end-to-end encrypted, written in Rust.**

[![CI](https://github.com/OmegaSoftDLL/omegadesk/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/OmegaSoftDLL/omegadesk/actions/workflows/ci.yml)
[![CodeQL](https://github.com/OmegaSoftDLL/omegadesk/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/OmegaSoftDLL/omegadesk/actions/workflows/codeql.yml)
[![Release](https://github.com/OmegaSoftDLL/omegadesk/actions/workflows/release.yml/badge.svg)](https://github.com/OmegaSoftDLL/omegadesk/actions/workflows/release.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/OmegaSoftDLL/omegadesk/badge)](https://scorecard.dev/viewer/?uri=github.com/OmegaSoftDLL/omegadesk)
[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](LICENSE)
[![MSRV](https://img.shields.io/badge/rustc-1.90%2B-orange.svg)](Cargo.toml)

[Status](#status) · [Quick start](#quick-start) · [Architecture](#architecture) · [Roadmap](docs/plan.md) · [Contributing](CONTRIBUTING.md) · [Security](SECURITY.md)


</div>

---

OmegaDesk is a remote desktop you run on your own infrastructure, as an alternative to TeamViewer and AnyDesk. It is written from scratch in Rust and brings together the best ideas of the open source remote access ecosystem: RustDesk's connection model, Sunshine's low-latency video pipeline, Tailscale's mesh networking, MeshCentral's device management and JumpServer's auditing. [docs/references.md](docs/references.md) lists the projects we study and what we take from each one.

## Status

> [!WARNING]
> OmegaDesk is in early development. **Phases 0 and 1** of the [roadmap](docs/plan.md) are done: it works on a local network today, connecting by IP address, certificate fingerprint and password. **Phase 2** (coordinator, relay and mesh) is implemented end to end: agent and client enroll with a coordinator and connect by name through NAT traversal or the relay, verified in-process and in a two-machine test over Tailscale (a clean test across two distinct public NATs is still pending). From **Phase 3**, QuickSupport works end to end (nine-digit ID, temporary password, console consent prompt), and the native agent and client synchronize text clipboards, transfer files, switch monitors and adapt video quality. The **browser client** (Phase 4) connects through the coordinator's web gateway with keyboard, mouse and H.264 video, verified in-process; its latency against the native client is not measured yet. Audio, chat, terminal and LAN mode remain unwired, and the recording, RMM and compatibility layers (Phases 5–7) exist only as library crates that no binary uses yet; the plan lists their known defects. It is not ready for production use.

What works today:

- **Screen capture** with DXGI Desktop Duplication on Windows, including hardware cursor compositing and rotated monitor support (`90°`, `180°`, `270°`).
- **Hardware H.264 encoding** through Media Foundation (Intel Quick Sync, NVIDIA NVENC, AMD AMF) with a zero-copy D3D11 GPU texture pipeline (`ID3D11VideoProcessor` + `MFCreateDXGISurfaceBuffer`), plus automatic fallback to OpenH264 in software.
- **QUIC transport** (TLS 1.3) with certificate pinning and a mandatory access password.
- **Remote keyboard and mouse** using physical scancodes, so any keyboard layout works (ABNT2 included). Multi-monitor aware.
- **Native client** that shows a live latency breakdown in the title bar.
- **Mesh mode**: a self-hosted coordinator (`omegadesk-server`) hands out addresses and names (`office-pc.omega`), nodes find each other with STUN and `disco` hole punching, fall back to a DERP-style relay (`omegadesk-relay`) in 1.5 s and upgrade to a direct path as soon as one validates. TLS is bound to the device identity the coordinator distributes, so there is no fingerprint to copy.
- **QuickSupport**: the person who needs help runs one executable, reads a nine-digit ID and a temporary password to the technician and accepts a consent prompt; the technician connects with `omegadesk-client 123 456 789`. The ID lives in the coordinator only while the program runs, and ten wrong passwords rotate the password.
- **Clipboard** text synchronized in both directions (SHA-256 echo suppression; `--no-clipboard` to disable).
- **File transfer** in both directions on dedicated QUIC streams: `--send-file`, drag a file onto the client window, `--receive-dir` on either side. Transfers resume from a partial file and are SHA-256 verified before the file gets its final name; nothing is ever overwritten.
- **Multi-monitor**: the agent lists its monitors; in the client press `Ctrl+Alt+Shift` + `1`..`9`, `N` (next) or `P` (previous) to switch the streamed display.
- **Adaptive video quality**: the client acknowledges every frame and the agent lowers the bitrate first, then the frame rate, when the path congests (RustDesk `video_qos` model); `--bitrate-mbps` and `--fps` are the ceilings.

First measurement (Intel Core Ultra 5 135U, 1920×1080, agent and client on the same machine): **60 fps and 24.5 ms end-to-end latency**. Host processing takes 15 ms (11 ms of it encoding), plus 0.2 ms network, 6 ms decode and 3 ms draw.

## Quick start

You need [Rust](https://rustup.rs) 1.90 or newer. On Windows you also need the Visual Studio C++ Build Tools.

On the machine you want to access (Windows for now):

```sh
cargo run --release -p omegadesk-agent -- --listen 0.0.0.0:7070
```

The agent prints a **certificate fingerprint** and a one-time **access password**. On the machine you connect from:

```sh
cargo run --release -p omegadesk-client -- 192.168.0.10:7070 --fingerprint <fingerprint> --password <password>
```

Useful flags:

| Flag | Where | Effect |
|---|---|---|
| `--encoder auto\|hardware\|software` | agent | Choose the video encoder (default: hardware with software fallback) |
| `--display N` | agent | Share monitor `N` (0 is the primary one) |
| `--bitrate-mbps N` / `--fps N` | agent | Video bitrate and frame rate cap |
| `--no-input` | agent | Share the screen only; ignore keyboard and mouse |
| `--password` / `OMEGADESK_PASSWORD` | agent, client | Fixed password (agent) or the password to send (client) |
| `--view-only` | client | Watch only; do not send keyboard and mouse |
| `--no-clipboard` | agent, client | Do not synchronize the text clipboard |
| `--send-file PATH` | agent, client | Send a file to the peer right after connecting (repeatable); the client also sends files dropped on its window |
| `--receive-dir DIR` | agent, client | Where received files are stored (default: `Downloads/OmegaDesk` under the user profile) |
| `--server`, `--server-key`, `--preauth-key` | agent, client | Join the mesh through a coordinator (see below) |
| `--relay-only` | agent, client | Mesh mode: never attempt direct paths |
| `--web-listen`, `--web-root`, `--web-allowed-host`, `--web-behind-tls` | server | Serve the browser client and proxy browsers to agents (see below) |

Keyboard shortcuts in the client window: `Ctrl+Alt+End` or `Ctrl+Alt+Delete` sends the Secure Attention Sequence to the remote machine; `Ctrl+Alt+Shift` + `1`..`9` streams the n-th remote monitor, `Ctrl+Alt+Shift+N` / `P` the next or previous one (the title bar shows `display 2/3`). Letters rather than arrows, because GPU vendor hotkeys (`Ctrl+Alt+Arrow` on Intel) intercept the arrow combinations before any window sees them.

### Mesh mode (coordinator and relay)

Run a relay (any machine with a public address; it answers STUN on the same UDP port) and a coordinator. Both need the same 32-byte ticket secret:

```sh
cargo run --release -p omegadesk-relay -- --listen 0.0.0.0:8443 --ticket-secret-hex <64 hex>
# prints the relay public key
cargo run --release -p omegadesk-server -- --listen 0.0.0.0:8080 --ticket-secret-hex <64 hex> \
    --relay "relay.example:8443=<relay key>;stun=relay.example:8443"
# prints server_key (128 hex) and bootstrap_preauth_key (odk_...)
```

Then enroll the agent and connect from the client by name:

```sh
cargo run --release -p omegadesk-agent -- --name office-pc --server coord.example:8080 --server-key <128 hex> --preauth-key odk_...
cargo run --release -p omegadesk-client -- office-pc.omega --server coord.example:8080 --server-key <128 hex> --preauth-key odk_... --password <password>
```

### Browser (web gateway)

The coordinator can also serve a browser client and proxy it to an agent over the mesh. Build the page once ([Node 22](https://nodejs.org) or newer), then start the server with `--web-listen`:

```sh
cd web && npm ci && npm run build && cd ..
cargo run --release -p omegadesk-server -- --listen 0.0.0.0:8080 --ticket-secret-hex <64 hex> \
    --relay "relay.example:8443=<relay key>;stun=relay.example:8443" \
    --web-listen 127.0.0.1:18123
```

Open `http://localhost:18123`, type the agent name (`office-pc`) and its access password. The gateway joins the mesh as `web-gateway.omega`, sends the agent the same `Hello` the native client would, and streams H.264 to a `WebCodecs` decoder in the page; keyboard and mouse go back the same way. `WebCodecs` requires a secure context, so for anything other than `localhost` put the gateway behind a TLS-terminating reverse proxy (Caddy, nginx) and pass `--web-behind-tls --web-allowed-host desk.example`. The browser part is WebSocket-only for now.
### Windows unattended access (service)

On Windows the agent can install itself as a `LocalSystem` service so remote
access keeps working at the login screen, across the UAC secure desktop, the
lock screen and session switches, with no one logged in. From an **elevated**
(Administrator) prompt:

```powershell
# Register the auto-start service (points at this executable).
omegadesk-agent service install
omegadesk-agent service start
# ... later ...
omegadesk-agent service stop
omegadesk-agent service uninstall
```

The service (SYSTEM) launches a capture/input worker in the active console
session using that session's `winlogon.exe` token, follows the input desktop so
it can capture and inject on the secure desktop, and offers a privacy mode that
blanks the local screen (a fullscreen `WDA_EXCLUDEFROMCAPTURE` overlay) while
the remote operator keeps working. `service run` is the Service Control Manager
entry point and is invoked by Windows, not manually. On Linux and macOS these
subcommands report that the service is Windows-only.

### QuickSupport (help someone once, TeamViewer style)

The coordinator also prints a `quicksupport_preauth_key`: a reusable, ephemeral key for the support tenant. The person who needs help runs (the three values can also come from `OMEGADESK_SERVER`, `OMEGADESK_SERVER_KEY` and `OMEGADESK_PREAUTH_KEY`, so they can be baked into a wrapper or installer):

```sh
cargo run --release -p omegadesk-quicksupport -- --server coord.example:8080 --server-key <128 hex> --preauth-key odk_<quicksupport key>
```

It prints `Your ID: 123 456 789` and `Password: abc123`. The technician connects with the ID (digits with or without spaces) and the password; the end user is asked on the console to allow the session (`y`, `n`, or `a` to allow that technician for five minutes without asking again):

```sh
cargo run --release -p omegadesk-client -- 123 456 789 --server coord.example:8080 --server-key <128 hex> --preauth-key odk_... --password abc123
```

Closing QuickSupport ends the session and frees the ID. `--view-only` lets the technician watch without controlling the mouse and keyboard.

## Architecture

```
  omegadesk-agent                                       omegadesk-client
 ┌──────────────────────────────┐    QUIC (TLS 1.3)   ┌───────────────────────────┐
 │ capture → codec → transport  ├─── video stream ───►│ transport → decode → draw │
 │ (DXGI)   (MF / OpenH264)     │                     │             (OpenH264)    │
 │ input ◄──────── control stream: ping, keys, mouse, keyframe requests ──────────┤
 │ (SendInput)                  │                     │ keyboard and mouse (winit)│
 └──────────────────────────────┘                     └───────────────────────────┘
```

| Crate | What it does |
|---|---|
| [`omegadesk-protocol`](crates/protocol) | Session messages (protobuf), framing, codec negotiation |
| [`omegadesk-identity`](crates/identity) | Device keys (ed25519/x25519), device ID, OS keychain storage |
| [`omegadesk-capture`](crates/capture) | Screen capture (`DXGI -> WGC -> GDI` fallback chain) |
| [`omegadesk-codec`](crates/codec) | H.264 encoders (Media Foundation, OpenH264) and decoder |
| [`omegadesk-input`](crates/input) | Keyboard and mouse injection (USB HID → scancodes) |
| [`omegadesk-transport`](crates/transport) | QUIC transport with certificate pinning or identity-bound TLS |
| [`omegadesk-noise`](crates/noise) | Noise `IK` control channel bound to device identities |
| [`omegadesk-mesh`](crates/mesh) | Sans-I/O NAT traversal: STUN, `disco`, relay fallback, tunnel encryption |
| [`omegadesk-control`](crates/control) | Node-side client of the coordinator (enrollment, netmap, tickets) |
| [`omegadesk-magicsock`](crates/magicsock) | The mesh as a QUIC socket: direct or relayed, virtual peer addresses |
| [`omegadesk-relay`](relay) | DERP-style packet relay with single-use tickets and STUN |
| [`omegadesk-server`](server) | Coordinator: keys, tenants, netmap stream, `*.omega` names |
| [`omegadesk-agent`](agent) | The service that shares a machine (also a library: the session reused by QuickSupport) |
| [`omegadesk-service`](crates/service) | Windows `LocalSystem` service and per-session worker (unattended access across the login screen and UAC) |
| [`omegadesk-quicksupport`](quicksupport) | Single-executable quick support: nine-digit ID, temporary password, consent prompt |
| [`omegadesk-client`](client) | The app you use to connect |

The full design, from the WireGuard mesh to the web client, is in [docs/plan.md](docs/plan.md). [docs/language.md](docs/language.md) explains why we chose Rust.

## Roadmap

| Phase | Deliverable | Status (✅ done · 🔶 implemented, field validation pending · 🧩 library only · ⬜ not started) |
|---|---|---|
| 0 | Foundation: workspace, CI on three platforms, license policy, protocol, identity | ✅ Done |
| 1 | First image on screen: capture, hardware encoding, QUIC, input, ≤ 30 ms on LAN | ✅ Done |
| 2 | Mesh network and coordination server: NAT traversal, relay, internal DNS | 🔶 Agent and client join the mesh (`--server`), connect by `name.omega`, traverse NAT with STUN + `disco` and fall back to the relay in 1.5 s; verified in-process and in a two-machine test, clean two-public-NAT test pending |
| 3 | Remote access product: Windows service, login/UAC screens, clipboard, files, audio | 🔶 QuickSupport, text clipboard, resumable file transfer, multi-monitor switching and adaptive video QoS are wired end to end; Windows service and privacy mode exist but the service worker does not yet route the QUIC session; audio, chat, terminal, FEC and LAN mode remain unwired; open findings: [#27](https://github.com/OmegaSoftDLL/omegadesk/issues/27) |
| 4 | Web dashboard and browser client | 🔶 Browser client works end to end through `omegadesk-server --web-listen` (WebSocket gateway on the mesh, WebCodecs H.264, keyboard and mouse, latency readout), verified in-process and in CI; the policy model and connection manager are still library only, no dashboard, no WebTransport, latency against the native client not measured; open findings: [#28](https://github.com/OmegaSoftDLL/omegadesk/issues/28) |
| 5 | Security, session recording and privileged access | 🧩 Library only: recording, HuJSON policies, MFA, PAM, DLP and vault exist; no handshake consults them; open findings: [#29](https://github.com/OmegaSoftDLL/omegadesk/issues/29) |
| 6 | Remote monitoring and management (RMM) | 🧩 Library only: in-memory RMM models; the agent reports nothing; open findings: [#30](https://github.com/OmegaSoftDLL/omegadesk/issues/30) |
| 7 | RDP/VNC compatibility, virtual displays, MCP server, Linux/macOS/mobile | 🔶 A real IddCx virtual display driver (`drivers/idd`, vendored signed QuickDesk driver) is wired into the agent (`--virtual-display <WxH@hz>`, `--privacy`); still no IronRDP dependency, no MCP server, no Linux/macOS capture; open findings: [#31](https://github.com/OmegaSoftDLL/omegadesk/issues/31), [#33](https://github.com/OmegaSoftDLL/omegadesk/issues/33) |

## Contributing

Contributions are welcome. Every change goes through a pull request and is reviewed by the maintainer. Read [CONTRIBUTING.md](CONTRIBUTING.md) before you start. It covers the workflow, the commit sign-off (DCO) and the code standards. Please follow our [Code of Conduct](CODE_OF_CONDUCT.md).

## Security

Please do **not** open public issues for security problems. Report them privately as described in [SECURITY.md](SECURITY.md).

## License

OmegaDesk is licensed under the [GNU Affero General Public License v3.0](LICENSE). The license allows code under AGPL-3.0, GPL-3.0, GPL-2.0-or-later, Apache-2.0, MPL-2.0, MIT and similar licenses to be incorporated. Code under GPL-2.0-only or proprietary licenses must not be copied into this repository. [`deny.toml`](deny.toml) enforces the dependency policy in CI.
