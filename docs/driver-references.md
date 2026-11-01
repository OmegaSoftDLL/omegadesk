# Driver references (from the studied projects)

OmegaDesk needs two kinds of OS drivers: a **virtual display** (to add a monitor
on a headless or privacy-mode host) and a **virtual network interface** (the TUN
device the mesh routes through). Both already exist, fully working, inside the
reference projects cloned under `omegadesk-ref/`. We do not write these from
scratch — we vendor a permissively licensed one and wrap it from Rust. This file
records every source found, its license, and what OmegaDesk uses.

## Virtual display (Windows Indirect Display Driver, IddCx)

| Source (in `omegadesk-ref/`) | License | What it is |
|---|---|---|
| `barry-ran_QuickDesk/quickdesk-virtual-display/` | **MIT** | Full IddCx driver **with prebuilt SIGNED binaries**. `control/IddController.c`+`.h` (user-mode: create/destroy the software device, plug/unplug monitors via `swdevice`/`cfgmgr32`), `driver/Driver.cpp`+`Public.h`+`quickdesk_display.inf`+`.vcxproj`, and `prebuilt/x64/{quickdesk_display.dll,.cat,.inf, nefconw.exe}` (`.cat` = signed catalog; `nefconw.exe` is Nefarius' device-console installer). See its `prebuilt/x64/README.md`. |
| `rustdesk_rustdesk/libs/virtual_display/dylib/src/win10/IddController.c` + `.h` | AGPL-3.0 | The same control API, wrapped from Rust by RustDesk. Study the FFI shape; do not copy the AGPL code into a permissive crate. |
| `zibo-chen_SubnetDesk/libs/virtual_display/dylib/` | AGPL-3.0 | RustDesk fork, same control library. |
| `ClassicOldSong_Apollo/src_assets/windows/drivers/sudovda/SudoVDA.inf` | GPL-3.0 | SudoVDA, the virtual display Apollo/Sunshine use. |
| `dchapyshev_aspia/source/drivers/virtual_display/` (`driver.cpp`, `aspia_virtual_display.inf`) + `source/host/win/virtual_display.h`, `swdevice_defines.h` | GPL-3.0 | Aspia's IddCx driver and its host-side control. |
| `kunkundi_crossdesk/apps/desktop/resources/windows/usbmmidd_v2/` (`usbmmIdd.inf`) | GPL-3.0 | usbmmidd_v2, a prebuilt USB-mirror indirect display. |
| `ultravnc_UltraVNC/winvnc/winvnc/VirtualDisplay.cpp`+`.h`, `videodriver.cpp` | GPL-3.0 | UltraVNC's virtual display / legacy mirror driver. |
| `FreeRDP_FreeRDP/server/Windows/wf_mirage.c` | Apache-2.0 | Legacy XP/7 mirror-driver capture (historical, not IddCx). |

**OmegaDesk uses QuickDesk** (`drivers/idd/`): it is MIT (fits our AGPL-3.0
project and can be redistributed), ships a **signed** driver so it installs
without test-signing, and its `IddController.c` is a clean user-mode control
library we compile with `cc` on Windows and wrap in the `omegadesk-idd` crate.
The kernel/IddCx driver itself (`Driver.cpp`) is shipped prebuilt+signed and is
never built in CI (it needs the Windows WDK). On Linux/macOS the crate compiles
to a clear "Windows-only" error. Attribution lives in `drivers/idd/` and
`THIRD_PARTY`.

## Virtual network interface (TUN)

| Source (in `omegadesk-ref/`) | License | What it is |
|---|---|---|
| `tailscale_tailscale/tsconst/wintun/`, `slackhq_nebula/dist/windows/wintun/` (`wintun.dll`+`wintun.h`), `firezone_firezone/rust/libs/bin-shared/src/wintun/` | wintun: **"Prebuilt Binaries" BSD-like** (WireGuard) | WinTUN, the modern user-mode TUN for Windows used by Tailscale, Nebula and Firezone. The `.dll` is loaded at runtime; `wintun.h` is the API. This is the TUN OmegaDesk should use on Windows. |
| `zerotier_ZeroTierOne/ext/bin/tap-windows-ndis6/` + `windows/TapDriver6/` (`zttap300.sys`/`.inf`) | GPL-2.0 (ext is separate) | Older NDIS6 TAP driver; WinTUN supersedes it. |
| `EasyTier_EasyTier/easytier/third_party/*/WinDivert*.sys` | WinDivert (LGPL/GPL dual) | WinDivert packet interception — not a TUN; avoid (license). |
| Linux/macOS | kernel built-in | `/dev/net/tun` (Linux) and `utun` (macOS) need no shipped driver; `crates/tun` targets them directly. |

**OmegaDesk uses WinTUN on Windows** (runtime-loaded `wintun.dll`, header in
`crates/tun`), and the kernel TUN/utun devices on Linux/macOS. This is a planned
follow-up: today `crates/tun` validates packets in memory (`InMemoryTun`) and
the mesh carries QUIC datagrams with a virtual address, so a real OS TUN is only
needed for the system-wide "route all traffic" mode, not for the remote-desktop
session.

## Rule
Everything above is already in the reference packages. When a phase needs a
driver, vendor the permissive one from this table into the project folder and
wrap it in Rust — never hand-roll a driver or assume one is missing.
