//! Build script for `omegadesk-idd`.
//!
//! On a Windows host it compiles QuickDesk's user-mode IddCx controller
//! (`vendor/control/IddController.c`) into a static library with the normal
//! Windows SDK (no WDK required) and links the device-management import
//! libraries its `swdevice`/`cfgmgr32`/`setupapi`/`newdev` calls need. The
//! kernel-mode driver (`vendor/driver/Driver.cpp`) is never built here; it is
//! shipped prebuilt and signed under `vendor/prebuilt/x64/`.
//!
//! Off Windows the crate is pure Rust and this script does nothing, so the
//! workspace still builds on Linux and macOS.

fn main() {
    #[cfg(windows)]
    windows_build::compile();
}

#[cfg(windows)]
mod windows_build {
    pub(super) fn compile() {
        let controller = "vendor/control/IddController.c";
        println!("cargo:rerun-if-changed={controller}");
        println!("cargo:rerun-if-changed=vendor/control/IddController.h");
        println!("cargo:rerun-if-changed=vendor/driver/Public.h");

        let mut build = cc::Build::new();
        build
            .file(controller)
            .include("vendor/control")
            .include("vendor/driver")
            .define("WIN32", None)
            .define("UNICODE", None)
            .define("_UNICODE", None);
        // Match QuickDesk/RustDesk: C controller, no C++ RTTI.
        if build.get_compiler().is_like_msvc() {
            build.flag("-GR-");
        }
        build.compile("omegadesk_idd_controller");

        // Import libraries for the Win32 device-management APIs the controller
        // calls: SwDevice* (swdevice), CM_* (cfgmgr32), SetupDi* (setupapi),
        // UpdateDriverForPlugAndPlayDevices/DiUninstallDriver (newdev) and
        // CoCreateGuid (ole32).
        for lib in ["swdevice", "cfgmgr32", "setupapi", "newdev", "ole32"] {
            println!("cargo:rustc-link-lib=dylib={lib}");
        }
    }
}
