//! OmegaDesk QuickSupport: the single executable an end user runs to get help.
//!
//! ```text
//! omegadesk-quicksupport --server coord.example:8080 --server-key <128 hex> --preauth-key odk_...
//! ```
//!
//! It joins the mesh as an ephemeral node, prints a nine-digit ID and a
//! temporary password for the user to read to the technician, asks the user
//! for consent when the technician connects (`omegadesk-client 123 456 789
//! --server ... --password ...`) and then shares the screen exactly like
//! `omegadesk-agent`. Closing the program ends the session and frees the ID.

use std::io::Write;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use clap::Parser;
use omegadesk_agent::capture_loop::EncoderChoice;
use omegadesk_agent::platform;
use omegadesk_codec::EncoderSettings;
use omegadesk_control::{ControlConfig, parse_server_key};
use omegadesk_identity::{DeviceIdentity, QuickSupportId};
use omegadesk_quicksupport::host::{
    ConsoleConsent, DEFAULT_PASSWORD_LENGTH, HostConfig, QuickSupportHost, SessionOutcome,
};
use omegadesk_quicksupport::{ClientPermissions, ConsentPolicy, DEFAULT_CONSENT_TIMEOUT_SECS};
use tracing::{info, warn};

/// How often the banner task checks whether a coordinator reconnect changed the ID.
const ID_CHECK_INTERVAL: Duration = Duration::from_secs(2);

#[derive(Debug, Parser)]
#[command(version, about = "OmegaDesk QuickSupport: get help on this computer")]
struct Args {
    /// Coordinator `host:port`.
    #[arg(long, env = "OMEGADESK_SERVER")]
    server: String,

    /// Coordinator public key (128 hex characters printed by `omegadesk-server`).
    #[arg(long, env = "OMEGADESK_SERVER_KEY")]
    server_key: String,

    /// Pre-authorized key of the support tenant (`odk_...`, the
    /// `quicksupport_preauth_key` printed by `omegadesk-server`).
    #[arg(long, env = "OMEGADESK_PREAUTH_KEY")]
    preauth_key: String,

    /// Local UDP address of the mesh socket.
    #[arg(long, default_value = "0.0.0.0:0")]
    listen: SocketAddr,

    /// Never attempt direct paths, send everything via the relays.
    #[arg(long)]
    relay_only: bool,

    /// Name shown to the technician. Defaults to this computer's name.
    #[arg(long)]
    name: Option<String>,

    /// Monitor index to share (`0` is the primary monitor).
    #[arg(long, default_value_t = 0)]
    display: u32,

    /// Video encoder selection.
    #[arg(long, value_enum, default_value_t = EncoderChoice::Auto)]
    encoder: EncoderChoice,

    /// Target video bitrate in megabits per second.
    #[arg(long, default_value_t = 8)]
    bitrate_mbps: u32,

    /// Maximum frame rate in frames per second.
    #[arg(long, default_value_t = 60.0)]
    fps: f32,

    /// Let the technician watch only; ignore remote keyboard and mouse.
    #[arg(long)]
    view_only: bool,

    /// Seconds the consent prompt waits for an answer before declining.
    #[arg(long, default_value_t = DEFAULT_CONSENT_TIMEOUT_SECS)]
    consent_timeout_secs: u64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stderr()))
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let args = Args::parse();
    platform::prefer_performance();

    // QuickSupport leaves nothing behind: a fresh identity per run, never stored.
    let identity = Arc::new(DeviceIdentity::generate());
    let server_public = parse_server_key(&args.server_key).context("invalid --server-key")?;
    let permissions = if args.view_only {
        ClientPermissions::DEFAULT
    } else {
        ClientPermissions::DEFAULT.union(ClientPermissions::ALL_INPUTS)
    };
    let config = HostConfig {
        control: ControlConfig {
            server_addr: args.server,
            server_public,
            preauth_key: args.preauth_key,
            hostname: args.name.unwrap_or_else(machine_name),
            endpoints: Vec::new(),
            quicksupport_id: None,
        },
        bind: args.listen,
        relay_only: args.relay_only,
        monitor: args.display,
        encoder: args.encoder,
        settings: EncoderSettings {
            bitrate_bps: args.bitrate_mbps.saturating_mul(1_000_000),
            max_fps: args.fps,
        },
        permissions,
        password_length: DEFAULT_PASSWORD_LENGTH,
    };

    let host = Arc::new(
        QuickSupportHost::join(identity, config)
            .await
            .context("failed to join the support mesh")?,
    );
    banner(host.id(), &host.password());

    // A coordinator reconnect can hand out a different ID: tell the user.
    let watcher = {
        let host = Arc::clone(&host);
        tokio::spawn(async move {
            let mut shown = host.id();
            let mut ticker = tokio::time::interval(ID_CHECK_INTERVAL);
            loop {
                ticker.tick().await;
                let current = host.id();
                if current != shown {
                    warn!("QuickSupport ID changed from {shown} to {current}");
                    banner(current, &host.password());
                    shown = current;
                }
            }
        })
    };

    let gate = Arc::new(ConsoleConsent::new(ConsentPolicy {
        timeout_secs: args.consent_timeout_secs,
        ..ConsentPolicy::default()
    }));
    loop {
        match host.serve_one(Arc::clone(&gate) as Arc<_>).await? {
            SessionOutcome::Served { peer } => {
                info!(
                    "session ended ({})",
                    peer.map_or_else(|| "unknown peer".to_owned(), |p| p.fqdn)
                );
                banner(host.id(), &host.password());
            }
            SessionOutcome::WrongPassword { rotated } => {
                if rotated {
                    warn!("ten wrong passwords in a row: the temporary password was replaced");
                    banner(host.id(), &host.password());
                }
            }
            SessionOutcome::Failed(error) => {
                warn!("session did not start: {error:#}");
                banner(host.id(), &host.password());
            }
        }
        if watcher.is_finished() {
            anyhow::bail!("the ID watcher stopped unexpectedly");
        }
    }
}

/// Prints the ID and password for the end user to read to the technician.
/// This is the program's user interface, so it goes to stdout (logs go to stderr).
fn banner(id: QuickSupportId, password: &str) {
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out);
    let _ = writeln!(out, "  OmegaDesk QuickSupport");
    let _ = writeln!(out, "  Give the technician these two values:");
    let _ = writeln!(out, "    Your ID:   {id}");
    let _ = writeln!(out, "    Password:  {password}");
    let _ = writeln!(
        out,
        "  You will be asked before anyone sees your screen. Close this window to end support."
    );
    let _ = writeln!(out);
    let _ = out.flush();
}

/// This computer's name, as shown to the technician.
fn machine_name() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "quicksupport".to_owned())
}
