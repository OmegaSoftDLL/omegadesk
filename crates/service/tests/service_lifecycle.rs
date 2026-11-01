//! Windows-only, ignored-by-default integration test for the full Service
//! Control Manager lifecycle, driven through the real `omegadesk-agent` binary.
//!
//! It is `#[ignore]` because it needs Administrator rights (the SCM rejects
//! `CreateServiceW`/`StartServiceW` otherwise) and it mutates machine state, so
//! it never runs in ordinary `cargo test` or CI. Run it deliberately from an
//! elevated prompt after building the workspace:
//!
//! ```text
//! cargo build
//! cargo test -p omegadesk-service --test service_lifecycle -- --ignored --nocapture
//! ```
//!
//! It installs the service, starts it, confirms the SCM reports it `Running`,
//! stops it, and uninstalls it, always cleaning up even if an assertion fails.

#![cfg(windows)]
#![allow(
    clippy::expect_used,
    clippy::panic,
    reason = "integration-test helpers assert via expect/panic outside #[test] functions"
)]

use std::path::PathBuf;
use std::process::Command;

/// Locates the built `omegadesk-agent.exe` next to this test executable
/// (`target/<profile>/omegadesk-agent.exe`).
fn agent_binary() -> PathBuf {
    let test_exe = std::env::current_exe().expect("test executable path");
    // .../target/<profile>/deps/service_lifecycle-<hash>.exe
    let profile_dir = test_exe
        .parent()
        .and_then(|deps| deps.parent())
        .expect("target/<profile> directory");
    let agent = profile_dir.join("omegadesk-agent.exe");
    assert!(
        agent.exists(),
        "build the workspace first: {} not found",
        agent.display()
    );
    agent
}

/// Runs `omegadesk-agent service <action>` and returns whether it succeeded.
fn service_action(agent: &PathBuf, action: &str) -> std::process::Output {
    Command::new(agent)
        .args(["service", action])
        .output()
        .unwrap_or_else(|error| panic!("failed to run `service {action}`: {error}"))
}

#[test]
#[ignore = "requires Administrator and mutates machine state; run manually"]
fn install_start_stop_uninstall() {
    let agent = agent_binary();

    let install = service_action(&agent, "install");
    assert!(
        install.status.success(),
        "install failed (are you elevated?): {}",
        String::from_utf8_lossy(&install.stderr)
    );

    // From here on, always uninstall, even if a later step fails.
    let outcome = std::panic::catch_unwind(|| {
        let start = service_action(&agent, "start");
        assert!(
            start.status.success(),
            "start failed: {}",
            String::from_utf8_lossy(&start.stderr)
        );

        let query = Command::new("sc")
            .args(["query", omegadesk_service::SERVICE_NAME])
            .output()
            .expect("sc query");
        let text = String::from_utf8_lossy(&query.stdout);
        assert!(text.contains("RUNNING"), "service not RUNNING:\n{text}");

        let stop = service_action(&agent, "stop");
        assert!(
            stop.status.success(),
            "stop failed: {}",
            String::from_utf8_lossy(&stop.stderr)
        );
    });

    let uninstall = service_action(&agent, "uninstall");
    assert!(
        uninstall.status.success(),
        "uninstall failed: {}",
        String::from_utf8_lossy(&uninstall.stderr)
    );

    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
}
