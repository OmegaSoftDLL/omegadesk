# Reference projects


OmegaDesk is written from scratch, in Rust (see [language.md](language.md)). The projects below are studied to learn about architecture, protocols and solutions.

Ideas and architecture are not subject to licenses. **Copying code** is: a copied snippet may only be included if its license is compatible with AGPL-3.0, it is credited, and the original copyright notice is kept.

Licenses verified against each repository's files on 2026-10-24.

| Project | What to study | License | Copy code? |
|---|---|---|---|
| [rustdesk/rustdesk](https://github.com/rustdesk/rustdesk) | Client architecture, NAT traversal, codecs, Windows service | AGPL-3.0 | ✅ |
| [rustdesk/rustdesk-server](https://github.com/rustdesk/rustdesk-server) | ID server (hbbs) and relay (hbbr) | AGPL-3.0 | ✅ |
| [zibo-chen/SubnetDesk](https://github.com/zibo-chen/SubnetDesk) | LAN-only mode, no server | AGPL-3.0 | ✅ |
| [Ylianst/MeshCentral](https://github.com/Ylianst/MeshCentral) | Web dashboard, agent management, groups and permissions | Apache-2.0 | ✅ |
| [amidaware/tacticalrmm](https://github.com/amidaware/tacticalrmm) | RMM features (scripts, alerts, inventory) | Tactical RMM License (proprietary) | ❌ ideas only |
| [kunkundi/crossdesk](https://github.com/kunkundi/crossdesk) | Lightweight web client | GPL-3.0 | ✅ |
| [galaxy-s10/billd-desk](https://github.com/galaxy-s10/billd-desk) | WebRTC pipeline | MIT | ✅ |
| [miroslavpejic85/p2p](https://github.com/miroslavpejic85/p2p) | Portable mode, no installation | MIT | ✅ |
| [dchapyshev/aspia](https://github.com/dchapyshev/aspia) | Relay, file transfer, address book | GPL-3.0 | ✅ |
| [barry-ran/QuickDesk](https://github.com/barry-ran/QuickDesk) | AI integration via MCP | MIT | ✅ |
| [immense/Remotely](https://github.com/immense/Remotely) | Remote support without installation (inactive since 12/2024) | GPL-3.0 | ✅ |
| [apache/guacamole-server](https://github.com/apache/guacamole-server) + [client](https://github.com/apache/guacamole-client) | Browser gateway, session recording | Apache-2.0 | ✅ |
| [jumpserver/jumpserver](https://github.com/jumpserver/jumpserver) | Privileged access management (PAM), auditing, access approval | GPL-3.0 | ✅ |
| [kasmtech/KasmVNC](https://github.com/kasmtech/KasmVNC) | High-performance VNC in the browser | GPL-2.0-or-later | ✅ |
| [novnc/noVNC](https://github.com/novnc/noVNC) | VNC client in JavaScript | MPL-2.0 | ✅ |
| [selkies-project/selkies](https://github.com/selkies-project/selkies) | GPU-accelerated WebRTC streaming, containers | MPL-2.0 | ✅ |
| [FreeRDP/FreeRDP](https://github.com/FreeRDP/FreeRDP) | Complete RDP protocol | Apache-2.0 | ✅ |
| [Devolutions/IronRDP](https://github.com/Devolutions/IronRDP) | RDP in Rust; **used as a dependency** by `omegadesk-rdp` (`ironrdp-connector`, `-session`, `-tokio`, `-pdu`, `-core`, `-graphics`, `-bulk`, `-rdcleanpath`, `-displaycontrol`, and `ironrdp-server` as a dev-dependency for the loopback test) | MIT/Apache-2.0 | ✅ |
| [neutrinolabs/xrdp](https://github.com/neutrinolabs/xrdp) | RDP server for Linux | Apache-2.0 | ✅ |
| [TigerVNC/tigervnc](https://github.com/TigerVNC/tigervnc) | VNC/RFB protocol | GPL-2.0-or-later | ✅ |
| [ultravnc/UltraVNC](https://github.com/ultravnc/UltraVNC) | VNC features on Windows | GPL-3.0 | ✅ |
| [mRemoteNG/mRemoteNG](https://github.com/mRemoteNG/mRemoteNG) | Tabbed connection manager | GPL-2.0-or-later | ✅ |
| [FreeRDP/Remmina](https://github.com/FreeRDP/Remmina) | Multi-protocol client for Linux | GPL-2.0-or-later | ✅ |
| [1Remote/1Remote](https://github.com/1Remote/1Remote) | Quick connection launcher | GPL-3.0 | ✅ |
| [LizardByte/Sunshine](https://github.com/LizardByte/Sunshine) | Low-latency hardware encoding | GPL-3.0 | ✅ |
| [moonlight-stream/moonlight-qt](https://github.com/moonlight-stream/moonlight-qt) | Low-latency decoding and display | GPL-3.0 | ✅ |
| [ClassicOldSong/Apollo](https://github.com/ClassicOldSong/Apollo) | Virtual display at the client's resolution | GPL-3.0 | ✅ |

## Crate dependencies added for Phase 7

These crates.io dependencies were added to make Phase 7 real (all use licenses
accepted by `cargo deny`):

| Crate | Role | License |
|---|---|---|
| `ironrdp-*` | RDP bridge on IronRDP (`crates/rdp`); versions pinned exactly (the API is 0.x) | MIT OR Apache-2.0 |
| `rmcp` | Model Context Protocol server over stdio (`crates/mcp`) | Apache-2.0 |
| `pipewire` + `libspa` | Linux PipeWire screen capture (`crates/capture`, Linux only) | MIT |
| `ashpd` | `xdg-desktop-portal` ScreenCast negotiation (Linux only) | MIT |
| `x11rb` | Pure-Rust X11 capture fallback (Linux only) | MIT OR Apache-2.0 |
| `objc2-core-graphics`, `objc2-core-foundation`, `objc2-io-surface`, `block2`, `dispatch2` | macOS `CGDisplayStream` screen capture and frame delivery (macOS only) | MIT OR Apache-2.0 OR Zlib |

## Local copies

Shallow clones (`--depth 1`) in `C:\Users\Ricardo.Bueno\omegadesk-ref\`. They are kept outside this repository on purpose.

## Mesh network (Tailscale-style)

Goal: every OmegaDesk agent and client joins an encrypted private network, reaching any machine by its internal IP or name, traversing NAT without opening ports, with our own relay when a direct connection fails.

| Project | What to study | Language | License | Copy code? |
|---|---|---|---|---|
| [tailscale/tailscale](https://github.com/tailscale/tailscale) | The market reference: DERP (relay), disco (path discovery), MagicDNS, ACLs, SSH | Go | BSD-3 | ✅ |
| [juanfont/headscale](https://github.com/juanfont/headscale) | Self-hosted Tailscale control server | Go | BSD-3 | ✅ |
| [netbirdio/netbird](https://github.com/netbirdio/netbird) | Separate management, signal and relay; ICE; policies and posture checks | Go | BSD-3 for the client, AGPL-3.0 for the server | ✅ |
| [EasyTier/EasyTier](https://github.com/EasyTier/EasyTier) | **Decentralized mesh in Rust**, no mandatory central server, WireGuard, QUIC, KCP | Rust | LGPL-3.0 | ✅ |
| [cloudflare/boringtun](https://github.com/cloudflare/boringtun) | **Userspace WireGuard in Rust**; can be a direct dependency | Rust | BSD-3 | ✅ |
| [tonarino/innernet](https://github.com/tonarino/innernet) | Private network over WireGuard with hierarchical CIDRs | Rust | MIT | ✅ |
| [DefGuard/defguard](https://github.com/DefGuard/defguard) | WireGuard with MFA and zero-trust access | Rust | AGPL-3.0 (core), `enterprise/` proprietary | ✅ except `enterprise/` |
| [slackhq/nebula](https://github.com/slackhq/nebula) | Certificate-based overlay with lighthouses | Go | MIT | ✅ |
| [zerotier/ZeroTierOne](https://github.com/zerotier/ZeroTierOne) | Virtual Ethernet network (layer 2) | C++ | MPL-2.0, `nonfree/` proprietary | ✅ except `nonfree/` |
| [firezone/firezone](https://github.com/firezone/firezone) | Zero-trust remote access; the connection core (connlib) is in Rust | Elixir + Rust | Apache-2.0 | ✅ |
| [gravitl/netmaker](https://github.com/gravitl/netmaker) | WireGuard network automation | Go | Apache-2.0, `pro/` proprietary | ✅ except `pro/` |

Note: headscale was extracted without `hscontrol/testdata/apiv1_golden/`, which contains file names that are invalid on Windows.
