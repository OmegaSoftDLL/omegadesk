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
//!
//! # Mesh with a deployment link (Phase 6): the token issued by
//! # `omegadesk-server admin links create` enrolls the device into its tenant
//! # and site; the agent then reports inventory and runs RMM scripts.
//! omegadesk-agent --server coord.example:8080 --server-key <128 hex> --deployment-token odl_...
//! ```
//!
//! On startup the agent prints its access password (and, on the local
//! network, its TLS certificate fingerprint); the client requires it to connect.
//!
//! On the mesh the coordinator's policy decides, per connecting device, whether a
//! session may open and whether it needs a TOTP step-up (`--totp-secret`), is
//! recorded (`--recordings-dir`), watermarked or clipboard-limited; every
//! decision is written to `--audit-log` as JSON Lines.

mod rmm;
mod virtual_display;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use clap::{Parser, Subcommand};
use omegadesk_agent::access::{self, AccessConfig, AccessControl};
use omegadesk_agent::capture_loop::EncoderChoice;
use omegadesk_agent::session::SessionConfig;
use omegadesk_agent::{password, platform, session};
use omegadesk_codec::EncoderSettings;
use omegadesk_control::{ControlConfig, parse_server_key};
use omegadesk_magicsock::{Node, NodeConfig};
use omegadesk_policy::AuditLog;
use omegadesk_transport::server_endpoint;
use tracing::{info, warn};

#[derive(Debug, Parser)]
#[command(version, about = "OmegaDesk remote desktop agent")]
#[allow(
    clippy::struct_excessive_bools,
    reason = "independent CLI on/off flags"
)]
struct Args {
    /// Manage the Windows unattended-access service (install, start, ...).
    #[command(subcommand)]
    command: Option<Command>,

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

    /// Do not synchronize the text clipboard with the client.
    #[arg(long)]
    no_clipboard: bool,

    /// Directory where files sent by the client are stored
    /// (default: `Downloads/OmegaDesk` under the user profile).
    #[arg(long, default_value_os_t = omegadesk_session::file_io::default_receive_dir())]
    receive_dir: PathBuf,

    /// File to send to every client right after it connects (repeatable).
    #[arg(long, action = clap::ArgAction::Append)]
    send_file: Vec<PathBuf>,

    /// Machine name displayed to the connected client and, on the mesh, the
    /// name clients connect to (`<name>.omega`).
    #[arg(long, default_value = "omegadesk-agent")]
    name: String,

    /// Coordinator `host:port`. Enables mesh mode: the agent enrolls, is
    /// reachable as `<name>.omega` and does not print a fingerprint.
    #[arg(long, env = "OMEGADESK_SERVER", requires_all = ["server_key", "credential"])]
    server: Option<String>,

    /// Coordinator public key (128 hex characters printed by `omegadesk-server`).
    #[arg(long, env = "OMEGADESK_SERVER_KEY")]
    server_key: Option<String>,

    /// Pre-authorized key issued by the coordinator (`odk_...`).
    #[arg(long, env = "OMEGADESK_PREAUTH_KEY", group = "credential")]
    preauth_key: Option<String>,

    /// Deployment-link token issued by `omegadesk-server admin links create`
    /// (`odl_...`): enrolls without copying a pre-auth key and places the
    /// device in the link's tenant and site.
    #[arg(long, env = "OMEGADESK_DEPLOYMENT_TOKEN", group = "credential")]
    deployment_token: Option<String>,

    /// Mesh mode only: never attempt direct paths, send everything via the relays.
    #[arg(long)]
    relay_only: bool,

    /// Plug a virtual monitor at this mode (`WxH` or `WxH@hz`, e.g.
    /// `1920x1080@60`) on startup, for headless or unattended hosts. Installs
    /// the signed IddCx driver on first use (needs administrator rights).
    #[arg(long, value_name = "WxH@hz")]
    virtual_display: Option<String>,

    /// Privacy mode: with `--virtual-display`, blank the physical monitor so
    /// only the remote operator sees the screen (restored on exit).
    #[arg(long, requires = "virtual_display")]
    privacy: bool,

    /// File holding the agent's persistent device identity. Defaults to the
    /// operating system credential store, falling back to
    /// `<config>/omegadesk/agent.key` when that store is unavailable (SSH or
    /// service sessions).
    #[arg(long, env = "OMEGADESK_AGENT_KEY_FILE")]
    key_file: Option<std::path::PathBuf>,

    /// Base32 TOTP secret (RFC 6238, HMAC-SHA256, 6 digits, 30 s) enrolled in the
    /// operators' authenticator apps. Required for sessions the policy marks
    /// `"action": "check"`; such sessions are refused without it.
    #[arg(long, env = "OMEGADESK_TOTP_SECRET")]
    totp_secret: Option<String>,

    /// Print a freshly generated TOTP secret and its `otpauth://` URI, then exit.
    #[arg(long, conflicts_with = "totp_secret")]
    generate_totp_secret: bool,

    /// Directory for `.odrec` session recordings. Required for sessions the policy
    /// marks `"record": true`; such sessions are refused without it.
    #[arg(long, env = "OMEGADESK_RECORDINGS_DIR")]
    recordings_dir: Option<PathBuf>,

    /// Append security audit events (connections, denials, MFA, DLP, recordings)
    /// as JSON Lines to this file.
    #[arg(long, env = "OMEGADESK_AUDIT_LOG")]
    audit_log: Option<PathBuf>,

    /// Mesh mode only: minutes between RMM inventory reports (a report is also
    /// sent at enrollment and when the inventory changes).
    #[arg(
        long,
        env = "OMEGADESK_INVENTORY_INTERVAL_MINUTES",
        default_value_t = 15
    )]
    inventory_interval_minutes: u64,
}

/// Binds the QUIC endpoint: on the mesh it enrolls a [`Node`] (kept alive for the whole run)
/// and uses its endpoint; otherwise it opens a Phase 1 LAN endpoint with a pinned fingerprint.
async fn build_endpoint(
    args: &Args,
    identity: omegadesk_identity::DeviceIdentity,
    hostname: &str,
) -> anyhow::Result<(omegadesk_transport::Endpoint, Option<Arc<Node>>)> {
    let credential = args.preauth_key.clone().or(args.deployment_token.clone());
    let (Some(server), Some(server_key), Some(credential)) =
        (&args.server, &args.server_key, credential)
    else {
        let (endpoint, fingerprint) =
            server_endpoint(args.listen).context("failed to bind agent QUIC endpoint")?;
        info!("agent listening on {}", endpoint.local_addr()?);
        info!("certificate fingerprint: {fingerprint}");
        return Ok((endpoint, None));
    };
    let server_public = parse_server_key(server_key).context("invalid --server-key")?;
    let mut node_config = NodeConfig::new(ControlConfig {
        server_addr: server.clone(),
        server_public,
        preauth_key: credential,
        hostname: hostname.to_owned(),
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
        "mesh address: {} ({}); clients connect with `omegadesk-client {}`",
        node.self_info().fqdn,
        node.self_info().ipv4,
        node.self_info().fqdn
    );
    let endpoint = node.endpoint().clone();
    Ok((endpoint, Some(node)))
}

/// Builds the policy/MFA/recording/audit enforcement from the command line.
fn build_access(
    args: &Args,
    agent_id: omegadesk_identity::DeviceId,
) -> anyhow::Result<Arc<AccessControl>> {
    let totp_secret = match &args.totp_secret {
        Some(text) => {
            let secret = access::decode_totp_secret(text)
                .context("--totp-secret must be a base32 secret of at least 80 bits")?;
            info!(
                "per-connection MFA enabled; enroll authenticators with {}",
                access::totp_uri(&args.name, text.trim())
            );
            Some(secret)
        }
        None => None,
    };
    let audit = match &args.audit_log {
        Some(path) => {
            let log = AuditLog::open(path)
                .with_context(|| format!("failed to open audit log {}", path.display()))?;
            info!("audit log: {}", path.display());
            Some(Arc::new(log))
        }
        None => None,
    };
    if let Some(dir) = &args.recordings_dir {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("failed to create {}", dir.display()))?;
        info!("session recordings: {}", dir.display());
    }
    Ok(Arc::new(AccessControl::new(AccessConfig {
        agent_name: args.name.clone(),
        agent_id,
        totp_secret,
        recordings_dir: args.recordings_dir.clone(),
        audit,
    })))
}

/// Agent subcommands.
#[derive(Debug, Subcommand)]
enum Command {
    /// Install, remove, start, stop or run the Windows unattended-access
    /// service (unattended remote access across the login screen and UAC).
    Service {
        /// Service action.
        #[command(subcommand)]
        action: omegadesk_service::ServiceCommand,
    },
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stderr()))
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let mut args = Args::parse();
    if args.generate_totp_secret {
        let secret = access::generate_totp_secret();
        let stdout = std::io::stdout();
        access::write_line(stdout.lock(), &secret)?;
        access::write_line(stdout.lock(), &access::totp_uri(&args.name, &secret))?;
        return Ok(());
    }

    // The service subcommands (including the SCM `run` entry point, which blocks
    // for the service's lifetime) must not run under a pre-built async runtime,
    // so they are dispatched before the agent's own runtime is created.
    if let Some(Command::Service { action }) = args.command.take() {
        return omegadesk_service::run_command(action);
    }

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to build the agent runtime")?;
    runtime.block_on(run_share(args))
}

/// Runs the screen-sharing agent (the default, no-subcommand behaviour).
async fn run_share(args: Args) -> anyhow::Result<()> {
    platform::prefer_performance();

    let password = match &args.password {
        Some(password) if password.len() >= 8 => password.clone(),
        Some(_) => anyhow::bail!("the access password must be at least 8 characters long"),
        None => password::generate(),
    };
    // Persistent device identity: keeps the same DeviceId across restarts.
    let (store, fallback) = omegadesk_identity::resolve_store("agent", args.key_file.as_deref())
        .context("failed to open device key store")?;
    if let Some(note) = fallback {
        warn!("{note}");
    }
    let identity = omegadesk_identity::DeviceIdentity::load_or_create(store.as_ref())
        .context("failed to load or create device identity")?;
    info!("device ID: {}", identity.id());

    let access = build_access(&args, identity.id())?;

    let config = Arc::new(SessionConfig {
        device_public_key: identity.public().signing_key_bytes(),
        name: args.name.clone(),
        password,
        monitor: args.display,
        encoder: args.encoder,
        settings: EncoderSettings {
            bitrate_bps: args.bitrate_mbps.saturating_mul(1_000_000),
            max_fps: args.fps,
        },
        input: !args.no_input,
        gate: None,
        clipboard: !args.no_clipboard,
        file_transfer: true,
        receive_dir: args.receive_dir.clone(),
        send_files: args.send_file.clone(),
        access,
    });

    // Mesh mode keeps the `Node` alive for the whole run: dropping it stops
    // the control, relay, driver and RMM tasks.
    let (endpoint, mesh_node) = build_endpoint(&args, identity, &config.name).await?;
    if let Some(node) = &mesh_node {
        rmm::spawn(node, args.inventory_interval_minutes);
    }
    info!("access password: {}", config.password);

    // Optional virtual monitor for headless hosts / privacy mode. Kept alive for
    // the whole run: dropping it unplugs the monitor and restores the screen.
    let _virtual_display = match args.virtual_display.as_deref() {
        Some(value) => virtual_display::activate(value, args.privacy)?,
        None => None,
    };

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
        // On the mesh the remote address identifies the peer: it is only reachable
        // through the tunnel keyed to that peer's identity, and its netmap entry
        // carries the coordinator's session decision for it.
        let peer = mesh_node.as_ref().and_then(|node| node.peer_at(remote));
        if let Some(peer) = &peer {
            info!("client connected: {} ({remote})", peer.fqdn);
        } else {
            info!("client connected: {remote}");
        }
        match session::run(connection, config.clone(), peer).await {
            Ok(()) => info!("session ended: {remote}"),
            Err(error) => warn!("session with {remote} ended with error: {error:#}"),
        }
    }
    drop(mesh_node);
    Ok(())
}
