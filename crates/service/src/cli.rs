//! Service subcommand definitions, shared across platforms so argument parsing
//! is unit-tested on Linux, macOS and Windows alike.

/// Windows Service Control Manager key name for the OmegaDesk agent service.
pub const SERVICE_NAME: &str = "OmegaDeskAgent";

/// Human-readable name shown in `services.msc`.
pub const SERVICE_DISPLAY_NAME: &str = "OmegaDesk Remote Access Agent";

/// Service description shown in `services.msc`.
pub const SERVICE_DESCRIPTION: &str = "Provides unattended remote access, including the Windows login screen, \
     UAC secure desktop and lock screen, by launching a capture/input worker \
     in the active user session.";

/// `omegadesk-agent service <action>` subcommands.
///
/// `install`/`uninstall`/`start`/`stop` manage the Service Control Manager
/// registration; `run` is the SCM entry point (invoked by Windows, not by a
/// user); `worker` is an internal, hidden subcommand the service uses to spawn
/// the per-session capture/input process.
#[derive(Debug, Clone, PartialEq, Eq, clap::Subcommand)]
pub enum ServiceCommand {
    /// Register the `LocalSystem` service with the Service Control Manager.
    Install,
    /// Stop (if running) and unregister the service.
    Uninstall,
    /// Start the registered service.
    Start,
    /// Stop the running service.
    Stop,
    /// Service Control Manager entry point (invoked by Windows, not manually).
    Run,
    /// Internal: run the per-session capture/input worker (spawned by the
    /// service in the active console session; not for manual use).
    #[command(name = "worker", hide = true)]
    Worker(WorkerArgs),
}

/// Arguments passed by the service to the per-session worker process.
#[derive(Debug, Clone, PartialEq, Eq, clap::Args)]
pub struct WorkerArgs {
    /// Named-pipe instance the worker connects back to the service on.
    #[arg(long)]
    pub pipe: String,
    /// Windows session id the worker was launched into (for the hello check).
    #[arg(long)]
    pub session: Option<u32>,
    /// Monitor index to capture (`0` is the primary monitor).
    #[arg(long, default_value_t = 0)]
    pub display: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct TestCli {
        #[command(subcommand)]
        command: ServiceCommand,
    }

    fn parse(args: &[&str]) -> Result<ServiceCommand, clap::Error> {
        TestCli::try_parse_from(args).map(|cli| cli.command)
    }

    #[test]
    fn parses_management_subcommands() {
        assert_eq!(parse(&["svc", "install"]).unwrap(), ServiceCommand::Install);
        assert_eq!(
            parse(&["svc", "uninstall"]).unwrap(),
            ServiceCommand::Uninstall
        );
        assert_eq!(parse(&["svc", "start"]).unwrap(), ServiceCommand::Start);
        assert_eq!(parse(&["svc", "stop"]).unwrap(), ServiceCommand::Stop);
        assert_eq!(parse(&["svc", "run"]).unwrap(), ServiceCommand::Run);
    }

    #[test]
    fn parses_worker_with_pipe_session_and_display() {
        let parsed = parse(&[
            "svc",
            "worker",
            "--pipe",
            "omegadesk-service.3",
            "--session",
            "2",
            "--display",
            "1",
        ])
        .unwrap();
        assert_eq!(
            parsed,
            ServiceCommand::Worker(WorkerArgs {
                pipe: "omegadesk-service.3".to_owned(),
                session: Some(2),
                display: 1,
            })
        );
    }

    #[test]
    fn worker_display_defaults_to_primary_monitor() {
        let parsed = parse(&["svc", "worker", "--pipe", "p"]).unwrap();
        assert_eq!(
            parsed,
            ServiceCommand::Worker(WorkerArgs {
                pipe: "p".to_owned(),
                session: None,
                display: 0,
            })
        );
    }

    #[test]
    fn worker_requires_pipe() {
        assert!(parse(&["svc", "worker"]).is_err());
    }

    #[test]
    fn unknown_subcommand_is_rejected() {
        assert!(parse(&["svc", "frobnicate"]).is_err());
    }
}
