# Vendored QuickDesk virtual display driver

This directory is a vendored copy of the Windows Indirect Display (IddCx)
virtual-display driver from [barry-ran/QuickDesk](https://github.com/barry-ran/QuickDesk)
(`quickdesk-virtual-display/`), used under the MIT license (see [`LICENSE`](LICENSE)).
`docs/references.md` catalogues it as the virtual-display source.

QuickDesk's driver itself derives from Microsoft's IndirectDisplay sample and
`RustDeskIddDriver` (MS-PL); the MIT grant and provenance are preserved here.

## Layout

| Path | What it is | Built in CI? |
|---|---|---|
| `control/IddController.c`, `.h` | User-mode controller: creates/opens the device and issues the plug-in / plug-out / update-mode IOCTLs. Compiled by `../build.rs` with the normal Windows SDK. | Yes (Windows) |
| `driver/` | Kernel-mode IddCx driver source (`Driver.cpp`, `Public.h`, INF, `.vcxproj`). Reference only. | **No** — needs the Windows WDK/IddCx and Microsoft attestation signing. |
| `prebuilt/x64/` | The **prebuilt, EV-signed** driver: `quickdesk_display.dll`, `quickdesk_display.cat`, `quickdesk_display.inf`, plus `nefconw.exe` (Nefarius device-node installer). | Shipped as-is. |

The driver is shipped prebuilt and signed so CI stays green on Windows, Linux
and macOS without a WDK toolchain, and so the signed catalog loads on end-user
machines.

## OmegaDesk modifications

QuickDesk ships `control/IddController.c` as the older RustDesk-era controller,
which no longer matches QuickDesk's own driver contract. Two minimal edits
reconcile it with the prebuilt `quickdesk_display.dll`:

1. `control/IddController.c`: the stale `#include "../RustDeskIddDriver/Public.h"`
   now points at the vendored `driver/Public.h`.
2. `driver/Public.h`: aliases the controller's legacy `IOCTL_CHANGER_IDD_*`
   names onto the `IOCTL_QUICKDESK_VD_*` codes the prebuilt driver dispatches.

Both edits are marked inline with an `OmegaDesk:` comment.

## Updating

Rebuild and re-sign following `prebuilt/x64/README.md`, then replace the files
in `prebuilt/x64/`. The `.cat` signs the exact bytes of the `.dll` and `.inf`,
so `prebuilt/x64/.gitattributes` keeps them byte-for-byte (no EOL normalization).
