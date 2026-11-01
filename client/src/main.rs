//! OmegaDesk client: renders the agent's screen and forwards keyboard and mouse input.
//!
//! Usage:
//!
//! ```text
//! # Local network (Phase 1): IP address plus the agent's certificate fingerprint.
//! omegadesk-client 192.168.0.10:7070 --fingerprint ab:cd:… --password <password>
//!
//! # Mesh (Phase 2): the agent's name, through the coordinator and relays.
//! omegadesk-client office-pc.omega --server coord.example:8080 --server-key <128 hex> \
//!     --preauth-key odk_... --password <password>
//!
//! # QuickSupport (Phase 3): the nine-digit ID the end user read aloud.
//! omegadesk-client 123 456 789 --server coord.example:8080 --server-key <128 hex> \
//!     --preauth-key odk_... --password <temporary password>
//! ```
//!
//! The window title bar displays a live latency breakdown: host processing,
//! network (half RTT), decoding, and drawing.

mod channels;
mod keymap;
mod network;
mod stats;
mod win_hook;
mod window;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use clap::Parser;
use omegadesk_control::{ControlConfig, parse_server_key};
use omegadesk_identity::QuickSupportId;
use omegadesk_magicsock::NodeConfig;
use winit::event_loop::EventLoop;

#[derive(Debug, Parser)]
#[command(version, about = "OmegaDesk remote desktop client")]
struct Args {
    /// Agent to connect to: `ip:port` on the local network; with `--server`,
    /// the agent's mesh name (`office-pc`, `office-pc.omega`), its mesh address,
    /// or a nine-digit QuickSupport ID (`123456789`, `123 456 789`, `123-456-789`).
    #[arg(required = true, num_args = 1.., value_name = "TARGET")]
    target: Vec<String>,

    /// Certificate fingerprint printed by the agent on startup (local network only).
    #[arg(long, required_unless_present = "server")]
    fingerprint: Option<String>,

    /// Coordinator `host:port` (mesh mode).
    #[arg(long, env = "OMEGADESK_SERVER", requires_all = ["server_key", "preauth_key"])]
    server: Option<String>,

    /// Coordinator public key (128 hex characters printed by `omegadesk-server`).
    #[arg(long, env = "OMEGADESK_SERVER_KEY")]
    server_key: Option<String>,

    /// Pre-authorized key issued by the coordinator (`odk_...`).
    #[arg(long, env = "OMEGADESK_PREAUTH_KEY")]
    preauth_key: Option<String>,

    /// Mesh mode only: never attempt direct paths, send everything via the relays.
    #[arg(long)]
    relay_only: bool,

    /// File holding the client's persistent device identity. Defaults to the
    /// operating system credential store, falling back to
    /// `<config>/omegadesk/client.key` when that store is unavailable.
    #[arg(long, env = "OMEGADESK_CLIENT_KEY_FILE")]
    key_file: Option<std::path::PathBuf>,

    /// Access password printed by the agent on startup.
    #[arg(long, env = "OMEGADESK_PASSWORD")]
    password: String,

    /// Watch only; do not send keyboard or mouse events.
    #[arg(long)]
    view_only: bool,

    /// Do not synchronize the text clipboard with the agent.
    #[arg(long)]
    no_clipboard: bool,

    /// Directory where files sent by the agent are stored
    /// (default: `Downloads/OmegaDesk` under the user profile).
    #[arg(long, default_value_os_t = omegadesk_session::file_io::default_receive_dir())]
    receive_dir: PathBuf,

    /// File to send to the agent right after connecting (repeatable). Files
    /// dropped on the window during the session are sent the same way.
    #[arg(long, action = clap::ArgAction::Append)]
    send_file: Vec<PathBuf>,
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stderr()))
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let args = Args::parse();
    win_hook::enable_dpi_awareness();

    let event_loop = EventLoop::<window::UserEvent>::with_user_event()
        .build()
        .context("failed to create window event loop")?;
    let (store, fallback) = omegadesk_identity::resolve_store("client", args.key_file.as_deref())
        .context("failed to open device key store")?;
    if let Some(note) = fallback {
        tracing::warn!("{note}");
    }
    let identity = omegadesk_identity::DeviceIdentity::load_or_create(store.as_ref())
        .context("failed to load or create device identity")?;
    tracing::info!("device ID: {}", identity.id());
    let device_public_key = identity.public().signing_key_bytes();
    let target = args.target.join(" ");
    let route = if let (Some(server), Some(server_key), Some(preauth_key)) =
        (&args.server, &args.server_key, &args.preauth_key)
    {
        {
            let server_public = parse_server_key(server_key).context("invalid --server-key")?;
            let mut node_config = NodeConfig::new(ControlConfig {
                server_addr: server.clone(),
                server_public,
                preauth_key: preauth_key.clone(),
                hostname: client_hostname(),
                endpoints: Vec::new(),
                quicksupport_id: None,
            });
            node_config.relay_only = args.relay_only;
            network::Route::Mesh(Box::new(network::MeshRoute {
                identity: Arc::new(identity),
                node_config,
                target: mesh_target(&target)?,
            }))
        }
    } else {
        let address: SocketAddr = target
            .parse()
            .context("without --server the target must be an `ip:port` address")?;
        network::Route::Lan {
            address,
            fingerprint: args.fingerprint.clone().unwrap_or_default(),
        }
    };
    let shared = stats::Shared::default();
    let handles = network::start(
        network::Target {
            device_public_key,
            route,
            password: args.password,
            clipboard: !args.no_clipboard,
            receive_dir: args.receive_dir,
            send_files: args.send_file,
        },
        shared.clone(),
        event_loop.create_proxy(),
    );

    let mut app = window::App::new(shared, handles.control, handles.files, args.view_only);
    event_loop.run_app(&mut app)?;
    app.into_result()
}

/// Interprets the positional target in mesh mode: nine digits (with or
/// without spaces or dashes) are a QuickSupport ID, anything else a name or
/// mesh address. Several words that are not an ID are a usage error.
fn mesh_target(target: &str) -> anyhow::Result<network::MeshTarget> {
    if let Ok(id) = target.parse::<QuickSupportId>() {
        return Ok(network::MeshTarget::QuickSupport(id));
    }
    if target.contains(char::is_whitespace) {
        anyhow::bail!(
            "`{target}` is neither a nine-digit QuickSupport ID nor a single mesh name or address"
        );
    }
    Ok(network::MeshTarget::Name(target.to_owned()))
}

/// Name this client enrolls under: `<machine name>-client`, or `omegadesk-client`.
fn client_hostname() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .map_or_else(
            |_| "omegadesk-client".to_owned(),
            |name| format!("{name}-client"),
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mesh_target_tells_ids_from_names() {
        let id: QuickSupportId = "123456789".parse().unwrap();
        for spelling in ["123456789", "123 456 789", "123-456-789"] {
            assert_eq!(
                mesh_target(spelling).unwrap(),
                network::MeshTarget::QuickSupport(id),
                "{spelling}"
            );
        }
        assert_eq!(
            mesh_target("office-pc.omega").unwrap(),
            network::MeshTarget::Name("office-pc.omega".to_owned())
        );
        assert_eq!(
            mesh_target("100.64.0.7").unwrap(),
            network::MeshTarget::Name("100.64.0.7".to_owned())
        );
        // Eight digits are not an ID, and two words are not a name.
        assert_eq!(
            mesh_target("12345678").unwrap(),
            network::MeshTarget::Name("12345678".to_owned())
        );
        assert!(mesh_target("office pc").is_err());
    }
}
