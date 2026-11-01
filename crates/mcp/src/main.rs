//! `omegadesk-mcp`: Model Context Protocol server over stdio for AI agents.
//!
//! ```text
//! # Devices from the coordinator; start_session launches omegadesk-client on the mesh.
//! omegadesk-mcp --server coord.example:8080 --server-key <128 hex> --preauth-key odk_...
//!
//! # Without a coordinator: this machine only (run_script, status, audit).
//! omegadesk-mcp
//! ```
//!
//! Register the command in the MCP host (Claude Desktop `claude_desktop_config.json`,
//! Claude Code `claude mcp add omegadesk -- omegadesk-mcp ...`). Logs go to stderr because
//! stdout carries the protocol.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use clap::Parser;
use omegadesk_control::{ControlConfig, parse_server_key};
use omegadesk_magicsock::{Node, NodeConfig};
use omegadesk_mcp::{
    LocalOnlyDirectory, McpTrustEngine, MeshDirectory, MeshLaunchArgs, MeshNodeDirectory,
    OmegaDeskMcpServer, ScriptRunner, ServerOptions, SessionLauncher, TrustPolicy,
};
use rmcp::ServiceExt;
use tracing::info;

#[derive(Debug, Parser)]
#[command(version, about = "OmegaDesk Model Context Protocol server (stdio)")]
struct Args {
    /// Coordinator `host:port`. Enables the mesh: devices come from the netmap and
    /// `start_session` can reach them.
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

    /// Name of this node on the mesh (`<name>.omega`).
    #[arg(long, default_value = "omegadesk-mcp")]
    name: String,

    /// UDP bind address of the mesh socket.
    #[arg(long, default_value = "0.0.0.0:0")]
    listen: std::net::SocketAddr,

    /// `omegadesk-client` executable used by `start_session` (default: next to this binary,
    /// then `PATH`).
    #[arg(long, env = "OMEGADESK_CLIENT_BINARY")]
    client_binary: Option<PathBuf>,

    /// Default timeout for `run_script` in seconds.
    #[arg(long, default_value_t = 60)]
    script_timeout_secs: u64,

    /// Longest timeout a `run_script` call may request, in seconds.
    #[arg(long, default_value_t = 600)]
    script_max_timeout_secs: u64,

    /// Seconds the operator has to answer a confirmation request.
    #[arg(long, default_value_t = 120)]
    confirmation_timeout_secs: u64,

    /// Let medium-risk actions (`start_session`, `stop_session`) run without asking the
    /// operator. High-risk actions always ask.
    #[arg(long)]
    no_confirm_medium: bool,

    /// Tool that must never run (repeatable), e.g. `--block-tool run_script`.
    #[arg(long = "block-tool")]
    blocked_tools: Vec<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let args = Args::parse();

    let store = omegadesk_identity::default_store("mcp").context("failed to open the key store")?;
    let identity = omegadesk_identity::DeviceIdentity::load_or_create(store.as_ref())
        .context("failed to load or create the device identity")?;
    info!("device ID: {}", identity.id());

    let mut policy = TrustPolicy {
        confirm_medium: !args.no_confirm_medium,
        ..TrustPolicy::default()
    };
    policy
        .blocked_tools
        .extend(args.blocked_tools.iter().cloned());
    let mut trust = McpTrustEngine::new();
    trust.set_device_policy(identity.id(), policy);

    // Mesh mode keeps the node alive for the whole run.
    let mut mesh_node: Option<Arc<Node>> = None;
    let (directory, launch): (Arc<dyn MeshDirectory>, Option<MeshLaunchArgs>) =
        if let (Some(server), Some(server_key), Some(preauth_key)) =
            (&args.server, &args.server_key, &args.preauth_key)
        {
            let server_public = parse_server_key(server_key).context("invalid --server-key")?;
            let mut node_config = NodeConfig::new(ControlConfig {
                server_addr: server.clone(),
                server_public,
                preauth_key: preauth_key.clone(),
                hostname: args.name.clone(),
                endpoints: Vec::new(),
                quicksupport_id: None,
            });
            node_config.bind = args.listen;
            node_config.relay_only = args.relay_only;
            let node = Arc::new(
                Node::start(Arc::new(identity), node_config)
                    .await
                    .context("failed to join the mesh")?,
            );
            info!(
                "mesh address: {} ({}); {} peer(s) in the netmap",
                node.self_info().fqdn,
                node.self_info().ipv4,
                node.peers().len()
            );
            let directory = Arc::new(MeshNodeDirectory::new(node.clone(), server.clone()));
            mesh_node = Some(node);
            (
                directory,
                Some(MeshLaunchArgs {
                    server: server.clone(),
                    server_key: server_key.clone(),
                    preauth_key: preauth_key.clone(),
                    relay_only: args.relay_only,
                }),
            )
        } else {
            info!("no coordinator configured: list_devices reports this machine only");
            (
                Arc::new(LocalOnlyDirectory::new(&identity, args.name.clone())),
                None,
            )
        };

    let client_binary = args
        .client_binary
        .unwrap_or_else(SessionLauncher::default_client_binary);
    let sessions = Arc::new(SessionLauncher::new(client_binary, launch));
    let options = ServerOptions {
        scripts: ScriptRunner {
            default_timeout: Duration::from_secs(args.script_timeout_secs),
            max_timeout: Duration::from_secs(args.script_max_timeout_secs),
            ..ScriptRunner::default()
        },
        confirmation_timeout: Duration::from_secs(args.confirmation_timeout_secs),
    };
    let server = OmegaDeskMcpServer::new(trust, directory, sessions, options)
        .map_err(|_| anyhow::anyhow!("failed to generate the confirmation state key"))?;

    info!("MCP server ready on stdio");
    let running = server
        .serve(rmcp::transport::stdio())
        .await
        .context("MCP handshake failed")?;
    running
        .waiting()
        .await
        .context("MCP session ended with an error")?;
    drop(mesh_node);
    Ok(())
}
