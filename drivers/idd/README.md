# omegadesk-idd

A safe Rust API over a real Windows Indirect Display (IddCx) virtual-display
driver, so OmegaDesk can add and remove virtual monitors on a host — for
headless / unattended machines and for privacy mode.

## What it does

- Installs and removes the bundled **signed** driver with the vendored
  `nefconw.exe` (idempotent; requires administrator privileges).
- Hot-plugs and unplugs virtual monitors and changes their mode (resolution and
  refresh rate) through the driver's IOCTLs.
- Windows-only at runtime. On Linux and macOS the API compiles unchanged and
  every operation returns `Error::Unsupported`, so the whole workspace builds
  and tests on all three operating systems.

```rust,no_run
use omegadesk_idd::{DisplayMode, VirtualDisplay};

# fn main() -> Result<(), omegadesk_idd::Error> {
let display = VirtualDisplay::install()?;                 // needs admin, idempotent
let monitor = display.plug_monitor(DisplayMode::new(1920, 1080, 60)?)?;
// ... stream the virtual monitor ...
monitor.unplug()?;
VirtualDisplay::uninstall()?;
# Ok(())
# }
```

## How it is built

`build.rs` compiles the vendored user-mode controller
(`vendor/control/IddController.c`) with the **normal Windows SDK** (no WDK) via
the `cc` crate and links `swdevice`/`cfgmgr32`/`setupapi`/`newdev`/`ole32`. The
kernel driver (`vendor/driver/Driver.cpp`) is **not** built here — it ships
prebuilt and signed under `vendor/prebuilt/x64/`.

## Attribution

The driver is vendored from [barry-ran/QuickDesk](https://github.com/barry-ran/QuickDesk)
under the MIT license. See [`vendor/README.md`](vendor/README.md),
[`vendor/LICENSE`](vendor/LICENSE) and the repository `THIRD_PARTY.md`.

## Tests

`cargo test -p omegadesk-idd` runs the cross-platform unit tests (mode
validation and connector allocation). The Windows end-to-end test (install →
plug 1920x1080@60 → assert via `EnumDisplayDevices` → unplug → uninstall) is
`#[ignore]`d because it needs administrator privileges and changes system
display devices:

```
cargo test -p omegadesk-idd -- --ignored --nocapture
```
