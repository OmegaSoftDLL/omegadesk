# Changelog

All notable changes to OmegaDesk are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project will follow [Semantic Versioning](https://semver.org/) once it has releases.

## [Unreleased]

### Added

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
