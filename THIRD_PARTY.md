# Third-party code

OmegaDesk is written from scratch (see `docs/references.md`). Ideas and
architecture are not subject to licenses; **copied code** is credited here with
its original license, which is kept with the copy.

## QuickDesk virtual display driver (MIT)

`drivers/idd/vendor/` is a vendored copy of the Windows Indirect Display (IddCx)
virtual-display driver from [barry-ran/QuickDesk](https://github.com/barry-ran/QuickDesk)
(`quickdesk-virtual-display/`): the user-mode controller source, the kernel
driver source (reference only), and the prebuilt, EV-signed driver binaries
(`quickdesk_display.dll/.cat/.inf`) plus the `nefconw.exe` installer.

- License: MIT — see `drivers/idd/vendor/LICENSE`.
- Copyright (c) 2026 Barry.
- QuickDesk's driver derives in turn from Microsoft's IndirectDisplay sample and
  `RustDeskIddDriver` (MS-PL); that provenance is preserved in the vendored tree.
- OmegaDesk's modifications to the vendored sources (an include path and IOCTL
  name aliases, to reconcile the shipped controller with the shipped driver) are
  marked inline with `OmegaDesk:` comments and described in
  `drivers/idd/vendor/README.md`.

`nefconw.exe` is the [Nefarius Device Node management tool](https://github.com/nefarius/nefcon)
(MIT), redistributed as a build/runtime tool alongside the driver.
