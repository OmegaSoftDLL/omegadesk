# Hardware Encoding, Zero-Copy Capture & Virtual Displays

## 1. Zero-Copy D3D11 Capture-to-Encode Pipeline

OmegaDesk eliminates CPU-to-GPU memory roundtrips on Windows:

1. **DXGI Desktop Duplication (`omegadesk-capture`):** Acquires the desktop frame directly as an `ID3D11Texture2D` on the GPU, composites hardware cursors, and handles rotated displays (`90°`, `180°`, `270°`).
2. **GPU Color Conversion (`ID3D11VideoProcessor`):** Converts `BGRA8` desktop textures to `NV12` entirely on the GPU.
3. **Media Foundation Hardware H.264 (`omegadesk-codec`):** Wraps the `NV12` texture via `MFCreateDXGISurfaceBuffer` and feeds it directly into **Intel Quick Sync**, **NVIDIA NVENC**, or **AMD AMF** hardware encoders (`--encoder auto|hardware|software`), falling back to `OpenH264` when no GPU encoder is available.

---

## 2. Adaptive Video QoS (Congestion Control)

Every video frame is acknowledged by `omegadesk-client`. When RTT rises or frame acknowledgments lag:
1. The agent dynamically lowers the target H.264 bitrate first.
2. If congestion persists, it reduces frame rate while respecting `--bitrate-mbps` and `--fps` ceilings.
3. As soon as network congestion clears, bitrate and FPS ramp back up smoothly.

---

## 3. Signed `IddCx` Virtual Display Driver & Privacy Screen Blanking

- **Virtual Monitors (`drivers/idd`):** Pass `--virtual-display 1920x1080@60` to create headless virtual displays on machines without physical monitors attached.
- **Privacy Mode (`--privacy`):** Renders a fullscreen `WDA_EXCLUDEFROMCAPTURE` blackout overlay on the physical monitor so local bystanders cannot view or control the screen while the remote operator works.
