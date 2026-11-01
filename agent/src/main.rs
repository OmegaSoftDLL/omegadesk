//! OmegaDesk agent: captures the screen, encodes video, and streams it to the
//! client; receives remote keyboard and pointer events and injects them into
//! the local session.
//!
//! Two ways to reach it:
//!
//! ```text
//! # Local network (Phase 1): the client pins the printed certificate fingerprint.
//! omegadesk-agent --listen 0.0.0.0:7070
//!
//! # Mesh (Phase 2): enroll with the coordinator; clients connect by name
//! # (`<name>.omega`) through NAT traversal or the relay, and TLS is bound to
//! # the device identity the coordinator distributes.
//! omegadesk-agent --server coord.example:8080 --server-key <128 hex> --preauth-key odk_...
//! ```
//!
//! On startup the agent prints its access password (and, on the local
//! network, its TLS certificate fingerprint); the client requires it to connect.

mod capture_loop;
mod password;
mod platform;
mod session;

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context;
use clap::Parser;
use omegadesk_codec::EncoderSettings;
use omegadesk_control::{ControlConfig, parse_server_key};
use omegadesk_magicsock::{Node, NodeConfig};
use omegadesk_transport::server_endpoint;
use tracing::{info, warn};

use crate::capture_loop::EncoderChoice;
use crate::session::SessionConfig;

#[derive(Debug, Parser)]
#[command(version, about = "OmegaDesk remote desktop agent")]
struct Args {
    /// Address and UDP port on which the agent listens for connections.
    #[arg(long, default_value = "0.0.0.0:7070")]
    listen: SocketAddr,

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

    /// Fixed access password. If omitted, a random one-time password is generated on startup.
    #[arg(long, env = "OMEGADESK_PASSWORD")]
    password: Option<String>,

    /// Share the screen only; ignore remote keyboard and mouse input.
    #[arg(long)]
    no_input: bool,

    /// Machine name displayed to the connected client and, on the mesh, the
    /// name clients connect to (`<name>.omega`).
    #[arg(long, default_value = "omegadesk-agent")]
    name: String,

    /// Coordinator `host:port`. Enables mesh mode: the agent enrolls, is
    /// reachable as `<name>.omega` and does not print a fingerprint.
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

    let password = match args.password {
        Some(password) if password.len() >= 8 => password,
        Some(_) => anyhow::bail!("the access password must be at least 8 characters long"),
        None => password::generate(),
    };
    // Persistent device identity: keeps the same DeviceId across restarts.
    let store =
        omegadesk_identity::default_store("agent").context("failed to open device key store")?;
    let identity = omegadesk_identity::DeviceIdentity::load_or_create(store.as_ref())
        .context("failed to load or create device identity")?;
    info!("device ID: {}", identity.id());

    let config = Arc::new(SessionConfig {
        device_public_key: identity.public().signing_key_bytes(),
        name: args.name,
        password,
        monitor: args.display,
        encoder: args.encoder,
        settings: EncoderSettings {
            bitrate_bps: args.bitrate_mbps.saturating_mul(1_000_000),
            max_fps: args.fps,
        },
        input: !args.no_input,
    });

    // Mesh mode keeps the `Node` alive for the whole run: dropping it stops
    // the control, relay and driver tasks.
    let mut mesh_node: Option<Node> = None;
    let endpoint = if let (Some(server), Some(server_key), Some(preauth_key)) =
        (&args.server, &args.server_key, &args.preauth_key)
    {
        {
            let server_public = parse_server_key(server_key).context("invalid --server-key")?;
            let mut node_config = NodeConfig::new(ControlConfig {
                server_addr: server.clone(),
                server_public,
                preauth_key: preauth_key.clone(),
                hostname: config.name.clone(),
                endpoints: Vec::new(),
            });
            node_config.bind = args.listen;
            node_config.relay_only = args.relay_only;
            let node = Node::start(Arc::new(identity), node_config)
                .await
                .context("failed to join the mesh")?;
            info!(
                "mesh address: {} ({}); clients connect with `omegadesk-client {}`",
                node.self_info().fqdn,
                node.self_info().ipv4,
                node.self_info().fqdn
            );
            let endpoint = node.endpoint().clone();
            mesh_node = Some(node);
            endpoint
        }
    } else {
        let (endpoint, fingerprint) =
            server_endpoint(args.listen).context("failed to bind agent QUIC endpoint")?;
        info!("agent listening on {}", endpoint.local_addr()?);
        info!("certificate fingerprint: {fingerprint}");
        endpoint
    };
    info!("access password: {}", config.password);

    // Phase 1 serves one session at a time; concurrent session multiplexing lands in Phase 3.
    while let Some(incoming) = endpoint.accept().await {
        let connection = match incoming.await {
            Ok(connection) => connection,
            Err(error) => {
                warn!("connection rejected: {error}");
                continue;
            }
        };
        let remote = connection.remote_address();
        if let Some(peer) = mesh_node.as_ref().and_then(|node| node.peer_at(remote)) {
            info!("client connected: {} ({remote})", peer.fqdn);
        } else {
            info!("client connected: {remote}");
        }
        match session::run(connection, config.clone()).await {
            Ok(()) => info!("session ended: {remote}"),
            Err(error) => warn!("session with {remote} ended with error: {error:#}"),
        }
    }
    drop(mesh_node);
    Ok(())
}
