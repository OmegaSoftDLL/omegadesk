<div align="center">

# OmegaDesk

**Open source, self-hosted remote desktop. Low latency, end-to-end encrypted, written in Rust.**

[![CI](https://github.com/OmegaSoftDLL/omegadesk/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/OmegaSoftDLL/omegadesk/actions/workflows/ci.yml)
[![CodeQL](https://github.com/OmegaSoftDLL/omegadesk/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/OmegaSoftDLL/omegadesk/actions/workflows/codeql.yml)
[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](LICENSE)
[![MSRV](https://img.shields.io/badge/rustc-1.90%2B-orange.svg)](Cargo.toml)

[Status](#status) · [Quick start](#quick-start) · [Architecture](#architecture) · [Roadmap](docs/plan.md) · [Contributing](CONTRIBUTING.md) · [Security](SECURITY.md)


</div>

---

OmegaDesk is a remote desktop you run on your own infrastructure, as an alternative to TeamViewer and AnyDesk. It is written from scratch in Rust and brings together the best ideas of the open source remote access ecosystem: RustDesk's connection model, Sunshine's low-latency video pipeline, Tailscale's mesh networking, MeshCentral's device management and JumpServer's auditing. [docs/references.md](docs/references.md) lists the projects we study and what we take from each one.

## Status

> [!WARNING]
> OmegaDesk is in early development (**Phase 1** of the [roadmap](docs/plan.md)). It works on a local network today, but it is not ready for production use.

What works today:

- **Screen capture** with DXGI Desktop Duplication on Windows, including hardware cursor compositing and rotated monitor support (`90°`, `180°`, `270°`).
- **Hardware H.264 encoding** through Media Foundation (Intel Quick Sync, NVIDIA NVENC, AMD AMF) with a zero-copy D3D11 GPU texture pipeline (`ID3D11VideoProcessor` + `MFCreateDXGISurfaceBuffer`), plus automatic fallback to OpenH264 in software.
- **QUIC transport** (TLS 1.3) with certificate pinning and a mandatory access password.
- **Remote keyboard and mouse** using physical scancodes, so any keyboard layout works (ABNT2 included). Multi-monitor aware.
- **Native client** that shows a live latency breakdown in the title bar.

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
| [`omegadesk-capture`](crates/capture) | Screen capture (DXGI Desktop Duplication) |
| [`omegadesk-codec`](crates/codec) | H.264 encoders (Media Foundation, OpenH264) and decoder |
| [`omegadesk-input`](crates/input) | Keyboard and mouse injection (USB HID → scancodes) |
| [`omegadesk-transport`](crates/transport) | QUIC transport with certificate pinning |
| [`omegadesk-agent`](agent) | The service that shares a machine |
| [`omegadesk-client`](client) | The app you use to connect |

The full design, from the WireGuard mesh to the web client, is in [docs/plan.md](docs/plan.md). [docs/language.md](docs/language.md) explains why we chose Rust.

## Roadmap

| Phase | Deliverable | Status |
|---|---|---|
| 0 | Foundation: workspace, CI on three platforms, license policy, protocol, identity | ✅ Done |
| 1 | First image on screen: capture, hardware encoding, QUIC, input, ≤ 30 ms on LAN | ✅ Done |
| 2 | Mesh network and coordination server: NAT traversal, relay, internal DNS | Planned |
| 3 | Remote access product: Windows service, login/UAC screens, clipboard, files, audio | Planned |
| 4 | Web dashboard and browser client | Planned |
| 5 | Security, session recording and privileged access | Planned |
| 6 | Remote monitoring and management (RMM) | Planned |
| 7 | RDP/VNC compatibility, virtual displays, MCP server, Linux/macOS/mobile | Planned |

## Contributing

Contributions are welcome. Every change goes through a pull request and is reviewed by the maintainer. Read [CONTRIBUTING.md](CONTRIBUTING.md) before you start. It covers the workflow, the commit sign-off (DCO) and the code standards. Please follow our [Code of Conduct](CODE_OF_CONDUCT.md).

## Security

Please do **not** open public issues for security problems. Report them privately as described in [SECURITY.md](SECURITY.md).

## License

OmegaDesk is licensed under the [GNU Affero General Public License v3.0](LICENSE). The license allows code under AGPL-3.0, GPL-3.0, GPL-2.0-or-later, Apache-2.0, MPL-2.0, MIT and similar licenses to be incorporated. Code under GPL-2.0-only or proprietary licenses must not be copied into this repository. [`deny.toml`](deny.toml) enforces the dependency policy in CI.
