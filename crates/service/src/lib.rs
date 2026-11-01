//! Windows unattended-access service for OmegaDesk.
//!
//! The agent runs as a `LocalSystem` Windows service (the SCM-managed
//! *supervisor*) that launches a capture/input *worker* in the active console
//! session, so remote access keeps working across the login screen, the UAC
//! secure desktop, the lock screen and fast user / RDP session switches. The
//! split follows Aspia (`source/host/host_service` + `desktop_session_*` /
//! `user_session_*`) and RustDesk (`src/platform/windows.rs::run_service`
//! launching `--server` via `CreateProcessAsUserW`): a long-lived SYSTEM
//! supervisor plus a short-lived, respawnable per-session worker, talking over
//! a named pipe (`ipc`).
//!
//! Module map:
//! - [`cli`]: the `install|uninstall|start|stop|run` subcommands (and the
//!   internal `worker` subcommand), parsed on every platform.
//! - [`ipc`]: length-delimited protobuf framing and the named-pipe connection.
//! - [`state`]: the platform-independent supervisor state machine.
//! - Windows-only internals: service registration, the SCM dispatcher, the
//!   supervisor loop, token acquisition, privacy-mode blanking and the worker.
//!
//! Everything compiles on Linux and macOS; the Windows-only commands return a
//! clear "only available on Windows" error there so the workspace builds and
//! tests on every target.

pub mod cli;
pub mod ipc;
pub mod state;

pub use cli::{
    SERVICE_DESCRIPTION, SERVICE_DISPLAY_NAME, SERVICE_NAME, ServiceCommand, WorkerArgs,
};

#[cfg(windows)]
mod control;
#[cfg(windows)]
mod dispatch;
#[cfg(windows)]
mod privacy;
#[cfg(windows)]
mod supervisor;
#[cfg(windows)]
mod token;
#[cfg(windows)]
mod worker;

/// Runs an `omegadesk-agent service <action>` command.
///
/// `run` blocks for the lifetime of the service (it is the SCM entry point);
/// the other actions return once the SCM operation completes.
///
/// # Errors
///
/// Returns an error if the Service Control Manager operation fails, if the
/// worker cannot start, or — on non-Windows platforms — because the service is
/// Windows-only.
#[cfg(windows)]
pub fn run_command(command: ServiceCommand) -> anyhow::Result<()> {
    match command {
        ServiceCommand::Install => control::install(),
        ServiceCommand::Uninstall => control::uninstall(),
        ServiceCommand::Start => control::start(),
        ServiceCommand::Stop => control::stop(),
        ServiceCommand::Run => dispatch::run_from_scm(),
        ServiceCommand::Worker(args) => worker::run(&args),
    }
}

/// Non-Windows stub: the OmegaDesk service is only available on Windows.
///
/// # Errors
///
/// Always returns an error explaining that the service is Windows-only.
#[cfg(not(windows))]
#[allow(
    clippy::needless_pass_by_value,
    reason = "signature matches the Windows build, which consumes the command"
)]
pub fn run_command(command: ServiceCommand) -> anyhow::Result<()> {
    let _ = command;
    anyhow::bail!("the OmegaDesk unattended-access service is only available on Windows")
}
