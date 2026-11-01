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
//! ```
//!
//! The window title bar displays a live latency breakdown: host processing,
//! network (half RTT), decoding, and drawing.

mod keymap;
mod network;
mod stats;
mod win_hook;
mod window;

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context;
use clap::Parser;
use omegadesk_control::{ControlConfig, parse_server_key};
use omegadesk_magicsock::NodeConfig;
use winit::event_loop::EventLoop;

#[derive(Debug, Parser)]
#[command(version, about = "OmegaDesk remote desktop client")]
struct Args {
    /// Agent to connect to: `ip:port` on the local network, or the agent's
    /// mesh name (`office-pc`, `office-pc.omega`) or mesh address with `--server`.
    target: String,

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
            });
            node_config.relay_only = args.relay_only;
            network::Route::Mesh(Box::new(network::MeshRoute {
                identity: Arc::new(identity),
                node_config,
                name: args.target.clone(),
            }))
        }
    } else {
        let address: SocketAddr = args
            .target
            .parse()
            .context("without --server the target must be an `ip:port` address")?;
        network::Route::Lan {
            address,
            fingerprint: args.fingerprint.clone().unwrap_or_default(),
        }
    };
    let shared = stats::Shared::default();
    let input = network::start(
        network::Target {
            device_public_key,
            route,
            password: args.password,
        },
        shared.clone(),
        event_loop.create_proxy(),
    );

    let mut app = window::App::new(shared, input, args.view_only);
    event_loop.run_app(&mut app)?;
    app.into_result()
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
