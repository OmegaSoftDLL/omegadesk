//! OmegaDesk mesh coordinator binary (`omegadesk-server`).
//!
//! ```text
//! # Run the coordinator (control plane, local admin API, optional web gateway).
//! omegadesk-server --ticket-secret-hex <64 hex> --state-file /var/lib/omegadesk/rmm.json
//!
//! # Operate the fleet from the same host (Headscale-style local CLI).
//! omegadesk-server admin devices
//! omegadesk-server admin device show office-pc
//! omegadesk-server admin scripts add --name "Disk cleanup" --shell powershell --file clean.ps1
//! omegadesk-server admin run office-pc --script disk-cleanup
//! omegadesk-server admin checks add --id disk-c --kind disk --target 'C:' --max-percent 85 --tenant default
//! omegadesk-server admin links create --tenant default --site sp --expires-in 86400
//! ```

use std::collections::HashSet;
use std::io::Write as _;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use omegadesk_control::ControlConfig;
use omegadesk_identity::{DeviceIdentity, FileStore, KeyStore, default_store};
use omegadesk_magicsock::{Node, NodeConfig};
use omegadesk_policy::{AuditKind, AuditOutcome};
use omegadesk_protocol::control::v1 as control;
use omegadesk_protocol::control::v1::admin_request::Request;
use omegadesk_protocol::control::v1::admin_response::Response;
use omegadesk_server::admin_api::{self, AdminState};
use omegadesk_server::control_server::{self, unix_now};
use omegadesk_server::rmm_service::{RmmService, RmmServiceConfig};
use omegadesk_server::{
    AuditLog, Coordinator, RelayNode, load_policy_file, web_server, web_session,
};
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(
    name = "omegadesk-server",
    version,
    about = "OmegaDesk mesh coordinator server"
)]
struct Args {
    /// Address to listen on for Noise IK control connections.
    #[arg(long, env = "OMEGADESK_SERVER_LISTEN", default_value = "0.0.0.0:8080")]
    listen: SocketAddr,

    /// Loopback address of the local admin API used by `omegadesk-server admin`.
    #[arg(long, env = "OMEGADESK_ADMIN_LISTEN", default_value = "127.0.0.1:8081")]
    admin_listen: SocketAddr,

    /// Bearer token of the admin API. Generated and logged at startup when absent.
    #[arg(long, env = "OMEGADESK_ADMIN_TOKEN")]
    admin_token: Option<String>,

    /// JSON file persisting the RMM state (inventory, scripts, schedules,
    /// checks, alerts, deployment links). Memory only when absent.
    #[arg(long, env = "OMEGADESK_STATE_FILE")]
    state_file: Option<PathBuf>,

    /// Default tenant name for the bootstrap pre-auth key.
    #[arg(long, env = "OMEGADESK_TENANT", default_value = "default")]
    tenant: String,

    /// Hex-encoded 32-byte shared HMAC secret used to issue relay tickets.
    /// Required to serve: there is no default, so tickets can never be forged
    /// with a publicly known key.
    #[arg(long, env = "OMEGADESK_RELAY_TICKET_SECRET")]
    ticket_secret_hex: Option<String>,

    /// Relay node to issue tickets for, as `host:port=<relay public key hex>`
    /// optionally followed by `;stun=host:port`. Repeatable.
    #[arg(long = "relay", env = "OMEGADESK_RELAYS", value_delimiter = ' ')]
    relays: Vec<String>,

    /// File holding the coordinator's persistent identity. Defaults to the
    /// operating system credential store (account `server`).
    #[arg(long, env = "OMEGADESK_SERVER_KEY_FILE")]
    key_file: Option<PathBuf>,

    /// Owner recorded for machines enrolled with the bootstrap key (a user
    /// selector in the policy, e.g. `alice@example.com`). Empty: tagged machines.
    #[arg(long, env = "OMEGADESK_BOOTSTRAP_USER", default_value = "")]
    bootstrap_user: String,

    /// `HuJSON` `policy/v2` file (Headscale/Tailscale format plus the OmegaDesk
    /// `sessions` block). Each node then receives only the peers it may reach,
    /// with its session grants; the file is re-read when it changes on disk.
    /// Without it every node of a tenant sees every other node.
    #[arg(long, env = "OMEGADESK_POLICY")]
    policy: Option<PathBuf>,

    /// Append security audit events (enrollments, policy reloads) as JSON Lines.
    #[arg(long, env = "OMEGADESK_AUDIT_LOG")]
    audit_log: Option<PathBuf>,

    /// Generate a bootstrap pre-auth key, print the server public key, verify
    /// the configuration, and exit immediately.
    #[arg(long)]
    check_only: bool,

    /// Address to serve the browser client and its WebSocket gateway on. When
    /// set, the server also joins the mesh as `web-gateway.omega` (with a
    /// reusable pre-auth key it issues itself) to reach agents by name.
    #[arg(long, env = "OMEGADESK_WEB_LISTEN")]
    web_listen: Option<SocketAddr>,

    /// Directory with the built browser client (`npm run build` in `web/`).
    #[arg(long, env = "OMEGADESK_WEB_ROOT", default_value = "web/dist")]
    web_root: PathBuf,

    /// Host name browsers use to reach the gateway (the `Host` header); repeatable.
    /// `localhost`, `127.0.0.1`, `::1` and the `--web-listen` address are always allowed.
    #[arg(
        long = "web-allowed-host",
        env = "OMEGADESK_WEB_ALLOWED_HOSTS",
        value_delimiter = ','
    )]
    web_allowed_hosts: Vec<String>,

    /// The gateway sits behind a TLS-terminating reverse proxy: browsers present an
    /// `https` Origin. (`X-Forwarded-Proto: https` from the proxy has the same effect.)
    #[arg(long, env = "OMEGADESK_WEB_BEHIND_TLS")]
    web_behind_tls: bool,

    /// File holding the gateway node's identity. Defaults to the operating system
    /// credential store (account `web-gateway`).
    #[arg(long, env = "OMEGADESK_WEB_KEY_FILE")]
    web_key_file: Option<PathBuf>,

    /// UDP bind address of the gateway's mesh socket.
    #[arg(long, env = "OMEGADESK_WEB_MESH_BIND", default_value = "0.0.0.0:0")]
    web_mesh_bind: SocketAddr,

    /// Gateway mesh node: never attempt direct paths, send everything via the relays.
    #[arg(long)]
    web_relay_only: bool,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Operate a running coordinator through its local admin API.
    Admin(AdminArgs),
}

#[derive(Debug, Parser)]
struct AdminArgs {
    /// Address of the coordinator's admin API.
    #[arg(long, env = "OMEGADESK_ADMIN_ADDR", default_value = "127.0.0.1:8081")]
    addr: String,

    /// Admin token printed by the coordinator at startup.
    #[arg(long, env = "OMEGADESK_ADMIN_TOKEN")]
    token: String,

    #[command(subcommand)]
    command: AdminCommand,
}

#[derive(Debug, Subcommand)]
enum AdminCommand {
    /// List enrolled devices with status, utilization and open alerts.
    Devices {
        /// Only devices of this tenant.
        #[arg(long)]
        tenant: Option<String>,
    },
    /// Inspect or edit one device.
    Device {
        #[command(subcommand)]
        command: DeviceCommand,
    },
    /// List alerts.
    Alerts {
        /// Include resolved alerts.
        #[arg(long)]
        all: bool,
    },
    /// Manage saved scripts.
    Scripts {
        #[command(subcommand)]
        command: ScriptCommand,
    },
    /// Run a saved or ad-hoc script on a device (queued if it is offline).
    Run {
        /// Device id, hostname or alias.
        device: String,
        /// Saved script id.
        #[arg(long, conflicts_with_all = ["shell", "content", "file"])]
        script: Option<String>,
        /// Shell for an ad-hoc script: `powershell`, `pwsh`, `sh`, `cmd`.
        #[arg(long, requires = "adhoc")]
        shell: Option<String>,
        /// Ad-hoc script body.
        #[arg(long, group = "adhoc")]
        content: Option<String>,
        /// File with the ad-hoc script body.
        #[arg(long, group = "adhoc")]
        file: Option<PathBuf>,
        /// Kill the interpreter after this many seconds (0 = server default).
        #[arg(long, default_value_t = 0)]
        timeout: u32,
    },
    /// Manage recurring schedules.
    Schedules {
        #[command(subcommand)]
        command: ScheduleCommand,
    },
    /// Show script results, newest first.
    Results {
        /// Device id, hostname or alias.
        #[arg(long)]
        device: Option<String>,
        /// Maximum number of results (0 = all).
        #[arg(long, default_value_t = 20)]
        limit: u32,
    },
    /// Manage health checks.
    Checks {
        #[command(subcommand)]
        command: CheckCommand,
    },
    /// Manage alert templates (scripts run when alerts open or resolve).
    Templates {
        #[command(subcommand)]
        command: TemplateCommand,
    },
    /// Manage deployment links.
    Links {
        #[command(subcommand)]
        command: LinkCommand,
    },
    /// Manage pre-auth keys.
    Preauth {
        #[command(subcommand)]
        command: PreauthCommand,
    },
}

#[derive(Debug, Subcommand)]
enum DeviceCommand {
    /// Full inventory, alerts and recent script results of a device.
    Show {
        /// Device id, hostname or alias.
        device: String,
    },
    /// Set the site and alias of a device (`-` clears a value).
    Set {
        /// Device id, hostname or alias.
        device: String,
        /// Site (device group) id.
        #[arg(long)]
        site: Option<String>,
        /// Human alias.
        #[arg(long)]
        alias: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum ScriptCommand {
    /// List saved scripts.
    List,
    /// Save (or replace) a script.
    Add {
        /// Script id (derived from the name when omitted).
        #[arg(long)]
        id: Option<String>,
        /// Human name.
        #[arg(long)]
        name: String,
        /// `powershell`, `pwsh`, `sh` or `cmd`.
        #[arg(long)]
        shell: String,
        /// Script body.
        #[arg(long, group = "body")]
        content: Option<String>,
        /// File with the script body.
        #[arg(long, group = "body")]
        file: Option<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
enum ScheduleCommand {
    /// List schedules.
    List,
    /// Add (or replace) a schedule.
    Add {
        /// Schedule id (derived from the name when omitted).
        #[arg(long)]
        id: Option<String>,
        /// Human name.
        #[arg(long)]
        name: String,
        /// Tenant owning the schedule.
        #[arg(long)]
        tenant: String,
        /// Saved script id.
        #[arg(long)]
        script: String,
        /// `hourly`, `daily`, `weekly` or `monthly`.
        #[arg(long)]
        interval: String,
        /// First run as Unix seconds (now when omitted).
        #[arg(long)]
        start_at: Option<u64>,
        /// Target devices (id, hostname or alias). Repeatable.
        #[arg(long = "device")]
        devices: Vec<String>,
        /// Target sites. Repeatable.
        #[arg(long = "site")]
        sites: Vec<String>,
        /// Do not queue the run for offline devices.
        #[arg(long)]
        no_queue: bool,
    },
}

#[derive(Debug, Subcommand)]
enum CheckCommand {
    /// List checks.
    List,
    /// Add (or replace) a check on a tenant, site or device layer.
    Add(Box<CheckAddArgs>),
}

#[derive(Debug, clap::Args)]
struct CheckAddArgs {
    /// Check id.
    #[arg(long)]
    id: String,
    /// Human name (defaults to the id).
    #[arg(long)]
    name: Option<String>,
    /// `cpu`, `memory`, `disk`, `process`, `service`, `script` or `offline`.
    #[arg(long)]
    kind: String,
    /// Tenant whose policy layer receives the check.
    #[arg(long)]
    tenant: String,
    /// Attach to this site layer instead of the tenant layer.
    #[arg(long)]
    site: Option<String>,
    /// Attach to this device layer (id, hostname or alias).
    #[arg(long)]
    device: Option<String>,
    /// Threshold for `cpu`, `memory` and `disk`.
    #[arg(long)]
    max_percent: Option<u32>,
    /// Mount point (`disk`), process name, service name or script id.
    #[arg(long)]
    target: Option<String>,
    /// Expected exit code for `script` checks.
    #[arg(long, default_value_t = 0)]
    exit_code: i32,
    /// Tolerated offline time for `offline` checks.
    #[arg(long)]
    max_offline_secs: Option<u64>,
    /// `info`, `warning` or `critical`.
    #[arg(long, default_value = "warning")]
    severity: String,
    /// Consecutive failures before the alert opens.
    #[arg(long, default_value_t = 1)]
    failures: u32,
}

#[derive(Debug, Subcommand)]
enum TemplateCommand {
    /// Add (or replace) the alert template of a tenant.
    Add {
        /// Template id.
        #[arg(long)]
        id: String,
        /// Human name.
        #[arg(long)]
        name: Option<String>,
        /// Tenant whose alerts use the template.
        #[arg(long)]
        tenant: String,
        /// Saved script to run on the device when an alert opens.
        #[arg(long)]
        on_failure_script: Option<String>,
        /// Saved script to run on the device when an alert resolves.
        #[arg(long)]
        on_resolution_script: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum LinkCommand {
    /// Create a deployment link: prints the token for `omegadesk-agent --deployment-token`.
    Create {
        /// Tenant the enrolled devices join.
        #[arg(long)]
        tenant: String,
        /// Site assigned to the enrolled devices.
        #[arg(long)]
        site: String,
        /// Lifetime in seconds (default 7 days).
        #[arg(long, default_value_t = 7 * 24 * 3_600)]
        expires_in: u64,
        /// Maximum enrollments (0 = unlimited).
        #[arg(long, default_value_t = 0)]
        max_uses: u32,
        /// ACL tags for the enrolled devices (`tag:...`). Repeatable.
        #[arg(long = "tag")]
        tags: Vec<String>,
        /// Enrolled devices are removed when they disconnect.
        #[arg(long)]
        ephemeral: bool,
    },
}

#[derive(Debug, Subcommand)]
enum PreauthCommand {
    /// Create a pre-auth key.
    Create {
        /// Tenant the key enrolls into.
        #[arg(long)]
        tenant: String,
        /// The key may enroll many devices.
        #[arg(long)]
        reusable: bool,
        /// Enrolled devices are removed when they disconnect.
        #[arg(long)]
        ephemeral: bool,
        /// ACL tags (`tag:...`). Repeatable.
        #[arg(long = "tag")]
        tags: Vec<String>,
        /// Lifetime in seconds (0 = never expires).
        #[arg(long, default_value_t = 0)]
        expires_in: u64,
    },
}

/// Hosts accepted in the `Host` header: loopback names, the listen address when it
/// is specific, and the operator's own names.
fn web_allowed_hosts(listen: SocketAddr, extra: &[String]) -> HashSet<String> {
    let mut hosts: HashSet<String> = ["localhost", "127.0.0.1", "::1"]
        .into_iter()
        .map(str::to_owned)
        .collect();
    if !listen.ip().is_unspecified() {
        hosts.insert(listen.ip().to_string());
    }
    for host in extra {
        let host = host
            .trim()
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_ascii_lowercase();
        if !host.is_empty() {
            hosts.insert(host);
        }
    }
    hosts
}

/// Address the gateway node uses to reach the coordinator running in this
/// process: loopback when the control listener is bound to every interface.
fn control_loopback_addr(listen: SocketAddr) -> SocketAddr {
    if listen.ip().is_unspecified() {
        let ip: IpAddr = if listen.is_ipv6() {
            Ipv6Addr::LOCALHOST.into()
        } else {
            Ipv4Addr::LOCALHOST.into()
        };
        SocketAddr::new(ip, listen.port())
    } else {
        listen
    }
}

/// Joins the mesh as the gateway node and starts the HTTP front door.
async fn start_web_gateway(
    args: &Args,
    web_listen: SocketAddr,
    server_identity: &DeviceIdentity,
    control_addr: SocketAddr,
    coordinator: &Arc<Mutex<Coordinator>>,
) -> Result<Arc<web_server::WebState>> {
    if !args.web_root.join("index.html").is_file() {
        anyhow::bail!(
            "{} has no index.html: run `npm ci && npm run build` in web/ or pass --web-root",
            args.web_root.display()
        );
    }
    let preauth_key = coordinator
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .create_preauth_key(
            &args.tenant,
            true,
            false,
            vec!["tag:web-gateway".to_owned()],
            None,
        )?;
    let store: Box<dyn KeyStore> = match &args.web_key_file {
        Some(path) => Box::new(FileStore::new(path.clone())),
        None => default_store("web-gateway").context("failed to open the gateway key store")?,
    };
    let identity = Arc::new(
        DeviceIdentity::load_or_create(store.as_ref())
            .context("failed to load the gateway identity")?,
    );
    let mut node_config = NodeConfig::new(ControlConfig {
        server_addr: control_addr.to_string(),
        server_public: server_identity.public(),
        preauth_key,
        hostname: "web-gateway".to_owned(),
        endpoints: Vec::new(),
        quicksupport_id: None,
    });
    node_config.bind = args.web_mesh_bind;
    node_config.relay_only = args.web_relay_only;
    let node = Node::start(Arc::clone(&identity), node_config)
        .await
        .context("the web gateway failed to join the mesh")?;
    info!(
        fqdn = %node.self_info().fqdn,
        ipv4 = %node.self_info().ipv4,
        id = %identity.id(),
        "web gateway enrolled in the mesh"
    );
    let mut config =
        web_server::WebGatewayConfig::new(web_allowed_hosts(web_listen, &args.web_allowed_hosts));
    config.web_root = Some(args.web_root.clone());
    config.behind_tls = args.web_behind_tls;
    let dialer = Arc::new(web_session::MeshDialer::new(Arc::new(node)));
    Ok(web_server::WebState::new(
        config,
        dialer,
        web_session::GatewayIdentity {
            device_public_key: identity.public().signing_key_bytes(),
            device_name: "omegadesk-web".to_owned(),
        },
    ))
}

/// How often the policy file's modification time is checked.
const POLICY_POLL_INTERVAL: Duration = Duration::from_secs(2);

fn policy_mtime(path: &Path) -> Option<SystemTime> {
    std::fs::metadata(path).and_then(|m| m.modified()).ok()
}

/// Re-reads the policy whenever the file changes (modification time or size); a
/// document that fails to parse is reported and the previous policy stays in
/// force, as Headscale keeps serving the last good policy on a reload error.
async fn watch_policy(
    path: PathBuf,
    mut last_seen: Option<SystemTime>,
    coordinator: Arc<Mutex<Coordinator>>,
) {
    loop {
        tokio::time::sleep(POLICY_POLL_INTERVAL).await;
        let current = policy_mtime(&path);
        if current == last_seen {
            continue;
        }
        last_seen = current;
        let (event, outcome) = match load_policy_file(&path) {
            Ok(policy) => {
                let Ok(mut guard) = coordinator.lock() else {
                    continue;
                };
                let deltas = guard.set_policy(Some(policy));
                info!(path = %path.display(), deltas, "policy reloaded");
                (
                    Coordinator::audit_event(AuditKind::PolicyLoaded, AuditOutcome::Ok)
                        .detail(format!("reloaded, {deltas} netmap deltas")),
                    guard,
                )
            }
            Err(error) => {
                let Ok(guard) = coordinator.lock() else {
                    continue;
                };
                warn!(path = %path.display(), %error, "policy reload rejected; previous policy kept");
                (
                    Coordinator::audit_event(AuditKind::PolicyRejected, AuditOutcome::Failed)
                        .detail(error.to_string()),
                    guard,
                )
            }
        };
        outcome.audit(&event.target(path.display().to_string()));
    }
}

fn decode_hex_32(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    let (pairs, _) = hex.as_bytes().as_chunks::<2>();
    for (i, pair) in pairs.iter().enumerate() {
        let s = std::str::from_utf8(pair).ok()?;
        out[i] = u8::from_str_radix(s, 16).ok()?;
    }
    Some(out)
}

/// Parses `host:port=<hex key>[;stun=host:port]`.
fn parse_relay(spec: &str) -> Result<RelayNode> {
    let (main, stun) = match spec.split_once(";stun=") {
        Some((main, stun)) => (main, Some(stun.to_owned())),
        None => (spec, None),
    };
    let (address, key_hex) = main
        .split_once('=')
        .context("relay must be host:port=<relay public key hex>")?;
    let exchange_key =
        decode_hex_32(key_hex.trim()).context("relay public key must be 64 hex characters")?;
    Ok(RelayNode {
        address: address.trim().to_owned(),
        exchange_key,
        stun_address: stun,
    })
}

fn load_identity(key_file: Option<&PathBuf>) -> Result<DeviceIdentity> {
    let store: Box<dyn KeyStore> = match key_file {
        Some(path) => Box::new(FileStore::new(path.clone())),
        None => default_store("server").context("failed to open the server key store")?,
    };
    DeviceIdentity::load_or_create(store.as_ref()).context("failed to load the server identity")
}

/// Formats the coordinator public identity as `<signing hex><exchange hex>`
/// (128 hex characters), the value nodes pass as `--server-key`.
fn public_key_hex(identity: &DeviceIdentity) -> String {
    let public = identity.public();
    let mut bytes = Vec::with_capacity(64);
    bytes.extend_from_slice(&public.signing_key_bytes());
    bytes.extend_from_slice(&public.exchange_key_bytes());
    data_encoding::HEXLOWER.encode(&bytes)
}

/// Deployment-link signing key derived from the ticket secret, so links keep
/// verifying across restarts without a second secret to configure.
fn deployment_key_material(ticket_secret: &[u8; 32]) -> Vec<u8> {
    Sha256::new()
        .chain_update(b"omegadesk-deployment-links-v1")
        .chain_update(ticket_secret)
        .finalize()
        .to_vec()
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();
    if let Some(Command::Admin(admin)) = args.command {
        return run_admin(admin).await;
    }
    run_server(args).await
}

fn configure_coordinator(
    args: &Args,
    secret: &[u8; 32],
) -> Result<(Coordinator, Option<std::time::SystemTime>)> {
    let mut coord = Coordinator::new(*secret);
    for spec in &args.relays {
        let relay = parse_relay(spec)?;
        info!(address = %relay.address, "relay registered");
        coord.add_relay(relay);
    }
    let bootstrap_key = coord.create_preauth_key_for_user(
        &args.tenant,
        &args.bootstrap_user,
        true,
        false,
        vec!["tag:default".to_owned()],
        None,
    )?;
    // Key shipped with the QuickSupport executable of this tenant: reusable
    // (every end user runs the same binary), ephemeral (a QuickSupport host
    // and its ID vanish when the program exits), tagged for later ACLs.
    let quicksupport_key = coord.create_preauth_key(
        &args.tenant,
        true,
        true,
        vec!["tag:quicksupport".to_owned()],
        None,
    )?;
    if let Some(path) = &args.audit_log {
        let log = AuditLog::open(path)
            .with_context(|| format!("failed to open audit log {}", path.display()))?;
        info!(path = %path.display(), "audit log enabled");
        coord.set_audit_log(Arc::new(log));
    }
    let policy_mtime = if let Some(path) = &args.policy {
        let policy = load_policy_file(path)
            .with_context(|| format!("failed to load policy {}", path.display()))?;
        info!(
            path = %path.display(),
            acls = policy.acls.len(),
            sessions = policy.sessions.len(),
            "policy loaded; netmaps are filtered per node"
        );
        coord.set_policy(Some(policy));
        coord.audit(
            &Coordinator::audit_event(AuditKind::PolicyLoaded, AuditOutcome::Ok)
                .target(path.display().to_string())
                .detail("loaded at startup"),
        );
        policy_mtime(path)
    } else {
        None
    };
    info!(
        bootstrap_preauth_key = %bootstrap_key,
        quicksupport_preauth_key = %quicksupport_key,
        "coordinator credentials created"
    );
    Ok((coord, policy_mtime))
}

async fn run_server(args: Args) -> Result<()> {
    let secret_hex = args
        .ticket_secret_hex
        .as_deref()
        .context("--ticket-secret-hex (or OMEGADESK_RELAY_TICKET_SECRET) is required to serve")?;
    let secret = decode_hex_32(secret_hex)
        .context("ticket_secret_hex must be exactly 64 hex characters (32 bytes)")?;
    let server_identity = Arc::new(load_identity(args.key_file.as_ref())?);
    let (coord, policy_mtime) = configure_coordinator(&args, &secret)?;
    let admin_token = args
        .admin_token
        .clone()
        .unwrap_or_else(admin_api::generate_token);

    info!(
        id = %server_identity.id(),
        tenant = %args.tenant,
        server_key = %public_key_hex(&server_identity),
        admin_token = %admin_token,
        "omegadesk-server initialized; nodes need --server-key and --preauth-key (or a deployment token)"
    );
    let rmm = RmmService::load(RmmServiceConfig {
        state_file: args.state_file.clone(),
        deployment_key_material: deployment_key_material(&secret),
        ..RmmServiceConfig::default()
    })?;
    if args.check_only {
        return Ok(());
    }

    let coordinator = Arc::new(Mutex::new(coord));
    if let Some(path) = args.policy.clone() {
        tokio::spawn(watch_policy(path, policy_mtime, Arc::clone(&coordinator)));
    }
    let rmm = Arc::new(Mutex::new(rmm));
    let admin_listener = TcpListener::bind(args.admin_listen).await?;
    info!(listen = %args.admin_listen, "admin API listening (use `omegadesk-server admin --token ...`)");
    tokio::spawn(admin_api::serve(
        admin_listener,
        AdminState {
            token: Arc::new(admin_token),
            coordinator: Arc::clone(&coordinator),
            rmm: Arc::clone(&rmm),
        },
    ));
    let listener = TcpListener::bind(args.listen).await?;
    info!(listen = %args.listen, "omegadesk-server listening for Noise IK connections");
    let control = tokio::spawn(control_server::serve_with(
        listener,
        Arc::clone(&server_identity),
        Arc::clone(&coordinator),
        rmm,
    ));

    let Some(web_listen) = args.web_listen else {
        return control.await?;
    };
    let web_listener = TcpListener::bind(web_listen)
        .await
        .with_context(|| format!("failed to bind the web gateway on {web_listen}"))?;
    let state = start_web_gateway(
        &args,
        web_listen,
        &server_identity,
        control_loopback_addr(args.listen),
        &coordinator,
    )
    .await?;
    let web = tokio::spawn(web_server::serve(web_listener, state));
    tokio::select! {
        result = control => result?,
        result = web => Ok(result??),
    }
}

fn read_body(content: Option<String>, file: Option<PathBuf>) -> Result<String> {
    match (content, file) {
        (Some(content), _) => Ok(content),
        (None, Some(path)) => {
            std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))
        }
        (None, None) => anyhow::bail!("give --content or --file"),
    }
}

fn shell_proto(name: &str) -> Result<i32> {
    omegadesk_server::rmm::ScriptingShell::parse(name)
        .map(|shell| shell.to_proto() as i32)
        .with_context(|| format!("unknown shell `{name}` (powershell, pwsh, sh, cmd)"))
}

fn interval_proto(name: &str) -> Result<i32> {
    Ok(match name.to_ascii_lowercase().as_str() {
        "hourly" => control::ScheduleInterval::Hourly,
        "daily" => control::ScheduleInterval::Daily,
        "weekly" => control::ScheduleInterval::Weekly,
        "monthly" => control::ScheduleInterval::Monthly,
        other => anyhow::bail!("unknown interval `{other}` (hourly, daily, weekly, monthly)"),
    } as i32)
}

fn check_kind_proto(name: &str) -> Result<i32> {
    Ok(match name.to_ascii_lowercase().as_str() {
        "cpu" => control::CheckKind::Cpu,
        "memory" | "mem" => control::CheckKind::Memory,
        "disk" => control::CheckKind::Disk,
        "process" => control::CheckKind::ProcessRunning,
        "service" => control::CheckKind::ServiceRunning,
        "script" => control::CheckKind::ScriptExitCode,
        "offline" => control::CheckKind::Offline,
        other => anyhow::bail!(
            "unknown check kind `{other}` (cpu, memory, disk, process, service, script, offline)"
        ),
    } as i32)
}

fn severity_proto(name: &str) -> Result<i32> {
    Ok(match name.to_ascii_lowercase().as_str() {
        "info" => control::CheckSeverity::Info,
        "warning" | "warn" => control::CheckSeverity::Warning,
        "critical" | "crit" => control::CheckSeverity::Critical,
        other => anyhow::bail!("unknown severity `{other}` (info, warning, critical)"),
    } as i32)
}

/// Translates a CLI command into an admin request.
fn build_request(command: AdminCommand) -> Result<Request> {
    Ok(match command {
        AdminCommand::Devices { tenant } => Request::ListDevices(control::ListDevicesRequest {
            tenant: tenant.unwrap_or_default(),
        }),
        AdminCommand::Device {
            command: DeviceCommand::Show { device },
        } => Request::ShowDevice(control::ShowDeviceRequest { device }),
        AdminCommand::Device {
            command:
                DeviceCommand::Set {
                    device,
                    site,
                    alias,
                },
        } => Request::UpdateDevice(control::UpdateDeviceRequest {
            device,
            site_id: site.unwrap_or_default(),
            alias: alias.unwrap_or_default(),
        }),
        AdminCommand::Alerts { all } => Request::ListAlerts(control::ListAlertsRequest {
            include_resolved: all,
        }),
        AdminCommand::Scripts { command } => script_request(command)?,
        AdminCommand::Run {
            device,
            script,
            shell,
            content,
            file,
            timeout,
        } => run_request(device, script, shell, read_body(content, file), timeout)?,
        AdminCommand::Schedules { command } => schedule_request(command)?,
        AdminCommand::Results { device, limit } => {
            Request::ListScriptResults(control::ListScriptResultsRequest {
                device: device.unwrap_or_default(),
                limit,
            })
        }
        AdminCommand::Checks { command } => check_request(command)?,
        AdminCommand::Templates {
            command:
                TemplateCommand::Add {
                    id,
                    name,
                    tenant,
                    on_failure_script,
                    on_resolution_script,
                },
        } => Request::AddAlertTemplate(control::AddAlertTemplateRequest {
            template_id: id,
            name: name.unwrap_or_default(),
            tenant,
            on_failure_script_id: on_failure_script.unwrap_or_default(),
            on_resolution_script_id: on_resolution_script.unwrap_or_default(),
        }),
        AdminCommand::Links {
            command:
                LinkCommand::Create {
                    tenant,
                    site,
                    expires_in,
                    max_uses,
                    tags,
                    ephemeral,
                },
        } => Request::CreateDeploymentLink(control::CreateDeploymentLinkRequest {
            tenant,
            site_id: site,
            expires_in_secs: expires_in,
            max_uses,
            tags,
            ephemeral,
        }),
        AdminCommand::Preauth {
            command:
                PreauthCommand::Create {
                    tenant,
                    reusable,
                    ephemeral,
                    tags,
                    expires_in,
                },
        } => Request::CreatePreauthKey(control::CreatePreauthKeyRequest {
            tenant,
            reusable,
            ephemeral,
            tags,
            expires_in_secs: expires_in,
        }),
    })
}

fn run_request(
    device: String,
    script: Option<String>,
    shell: Option<String>,
    body: Result<String>,
    timeout_secs: u32,
) -> Result<Request> {
    let (shell, content) = if script.is_some() {
        (control::ScriptShell::Unspecified as i32, String::new())
    } else {
        let shell = shell.context("an ad-hoc run needs --shell")?;
        (shell_proto(&shell)?, body?)
    };
    Ok(Request::RunScript(control::RunScriptRequest {
        device,
        script_id: script.unwrap_or_default(),
        shell,
        content,
        timeout_secs,
    }))
}

fn script_request(command: ScriptCommand) -> Result<Request> {
    Ok(match command {
        ScriptCommand::List => Request::ListScripts(control::ListScriptsRequest {}),
        ScriptCommand::Add {
            id,
            name,
            shell,
            content,
            file,
        } => Request::SaveScript(control::SaveScriptRequest {
            script_id: id.unwrap_or_default(),
            name,
            shell: shell_proto(&shell)?,
            content: read_body(content, file)?,
        }),
    })
}

fn schedule_request(command: ScheduleCommand) -> Result<Request> {
    Ok(match command {
        ScheduleCommand::List => Request::ListSchedules(control::ListSchedulesRequest {}),
        ScheduleCommand::Add {
            id,
            name,
            tenant,
            script,
            interval,
            start_at,
            devices,
            sites,
            no_queue,
        } => Request::AddSchedule(control::AddScheduleRequest {
            schedule_id: id.unwrap_or_default(),
            name,
            tenant,
            script_id: script,
            interval: interval_proto(&interval)?,
            start_at_unix_secs: start_at.unwrap_or(0),
            run_on_next_connect: !no_queue,
            device_ids: devices,
            site_ids: sites,
        }),
    })
}

fn check_request(command: CheckCommand) -> Result<Request> {
    Ok(match command {
        CheckCommand::List => Request::ListChecks(control::ListChecksRequest {}),
        CheckCommand::Add(args) => Request::AddCheck(control::AddCheckRequest {
            check: Some(control::CheckInfo {
                check_id: args.id,
                name: args.name.unwrap_or_default(),
                kind: check_kind_proto(&args.kind)?,
                max_percent: args.max_percent.unwrap_or(0),
                target: args.target.unwrap_or_default(),
                expected_exit_code: args.exit_code,
                max_offline_secs: args.max_offline_secs.unwrap_or(0),
                severity: severity_proto(&args.severity)?,
                failures_before_alert: args.failures,
                tenant: args.tenant,
                site_id: args.site.unwrap_or_default(),
                device_id: args.device.unwrap_or_default(),
            }),
        }),
    })
}

/// Renders an admin response for the terminal.
fn render_response(response: &Response, now: u64) -> String {
    match response {
        Response::Devices(list) => admin_api::render_devices(list, now),
        Response::Device(detail) => admin_api::render_device(detail, now),
        Response::Alerts(list) => admin_api::render_alerts(list, now),
        Response::Scripts(list) => admin_api::render_scripts(list),
        Response::Script(script) => format!(
            "saved script {} ({}, {} lines)\n",
            script.script_id,
            script.name,
            script.content.lines().count()
        ),
        Response::Run(run) => {
            if run.queued {
                format!(
                    "device {} is offline; the script runs on its next connection\n",
                    run.device_id
                )
            } else {
                format!(
                    "run {} dispatched to {}; see `admin results --device {}`\n",
                    run.run_id, run.device_id, run.device_id
                )
            }
        }
        Response::Schedule(schedule) => format!(
            "schedule {} added; next run at unix {}\n",
            schedule.schedule_id, schedule.next_run_unix_secs
        ),
        Response::Schedules(list) => admin_api::render_schedules(list, now),
        Response::ScriptResults(list) => admin_api::render_results(list, now),
        Response::Check(check) => format!("check {} added\n", check.check_id),
        Response::Checks(list) => admin_api::render_checks(list),
        Response::DeploymentLink(link) => format!(
            "deployment link {} for tenant {} site {} (expires at unix {}, max uses {})\n\
             omegadesk-agent --server <host:port> --server-key <key> --deployment-token {}\n",
            link.link_id,
            link.tenant,
            link.site_id,
            link.expires_at_unix_secs,
            if link.max_uses == 0 {
                "unlimited".to_owned()
            } else {
                link.max_uses.to_string()
            },
            link.token
        ),
        Response::PreauthKey(key) => format!("{}\n", key.key),
        Response::AlertTemplate(template) => format!(
            "alert template {} set for tenant {} (on failure: {}; on resolution: {})\n",
            template.template_id,
            template.tenant,
            if template.on_failure_actions.is_empty() {
                "nothing".to_owned()
            } else {
                template.on_failure_actions.join(", ")
            },
            if template.on_resolution_actions.is_empty() {
                "nothing".to_owned()
            } else {
                template.on_resolution_actions.join(", ")
            }
        ),
        Response::Error(error) => format!("error: {}\n", error.message),
    }
}

async fn run_admin(admin: AdminArgs) -> Result<()> {
    let request = build_request(admin.command)?;
    let response = admin_api::call(&admin.addr, &admin.token, request)
        .await
        .context("admin request failed")?;
    let text = render_response(&response, unix_now());
    let mut stdout = std::io::stdout().lock();
    stdout.write_all(text.as_bytes())?;
    stdout.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_relay_specs() {
        let key = "ab".repeat(32);
        let relay =
            parse_relay(&format!("relay.example:443={key};stun=relay.example:3478")).unwrap();
        assert_eq!(relay.address, "relay.example:443");
        assert_eq!(relay.exchange_key, [0xab; 32]);
        assert_eq!(relay.stun_address.as_deref(), Some("relay.example:3478"));
        let plain = parse_relay(&format!("10.0.0.1:8443={key}")).unwrap();
        assert_eq!(plain.stun_address, None);
        assert!(parse_relay("relay.example:443").is_err());
        assert!(parse_relay("relay.example:443=zz").is_err());
    }

    #[test]
    fn web_allowed_hosts_include_loopback_listen_and_operator_names() {
        let hosts = web_allowed_hosts(
            "0.0.0.0:18123".parse().unwrap(),
            &[
                "Desk.Example".to_owned(),
                " [fd00::1] ".to_owned(),
                String::new(),
            ],
        );
        for expected in ["localhost", "127.0.0.1", "::1", "desk.example", "fd00::1"] {
            assert!(hosts.contains(expected), "{expected}");
        }
        assert!(!hosts.contains("0.0.0.0"));
        let specific = web_allowed_hosts("192.168.1.5:18123".parse().unwrap(), &[]);
        assert!(specific.contains("192.168.1.5"));
    }

    #[test]
    fn gateway_reaches_the_coordinator_over_loopback_when_bound_to_any() {
        assert_eq!(
            control_loopback_addr("0.0.0.0:8080".parse().unwrap()),
            "127.0.0.1:8080".parse().unwrap()
        );
        assert_eq!(
            control_loopback_addr("[::]:8080".parse().unwrap()),
            "[::1]:8080".parse().unwrap()
        );
        assert_eq!(
            control_loopback_addr("10.0.0.2:8080".parse().unwrap()),
            "10.0.0.2:8080".parse().unwrap()
        );
    }

    #[test]
    fn server_key_is_signing_then_exchange() {
        let id = DeviceIdentity::generate();
        let hex = public_key_hex(&id);
        assert_eq!(hex.len(), 128);
        let bytes = data_encoding::HEXLOWER.decode(hex.as_bytes()).unwrap();
        assert_eq!(&bytes[..32], &id.public().signing_key_bytes());
        assert_eq!(&bytes[32..], &id.public().exchange_key_bytes());
        assert_ne!(
            deployment_key_material(&[1u8; 32]),
            deployment_key_material(&[2u8; 32])
        );
    }

    #[test]
    fn admin_cli_builds_requests_and_renders_replies() {
        let args = Args::parse_from([
            "omegadesk-server",
            "admin",
            "--token",
            "t",
            "checks",
            "add",
            "--id",
            "disk-c",
            "--kind",
            "disk",
            "--target",
            "C:",
            "--max-percent",
            "85",
            "--tenant",
            "acme",
            "--severity",
            "critical",
        ]);
        let Some(Command::Admin(admin)) = args.command else {
            panic!("expected the admin subcommand");
        };
        let Request::AddCheck(add) = build_request(admin.command).unwrap() else {
            panic!("expected AddCheck");
        };
        let check = add.check.unwrap();
        assert_eq!(check.kind, control::CheckKind::Disk as i32);
        assert_eq!(check.target, "C:");
        assert_eq!(check.severity, control::CheckSeverity::Critical as i32);

        let args = Args::parse_from([
            "omegadesk-server",
            "admin",
            "--token",
            "t",
            "run",
            "office-pc",
            "--shell",
            "powershell",
            "--content",
            "Get-Date",
        ]);
        let Some(Command::Admin(admin)) = args.command else {
            panic!("expected the admin subcommand");
        };
        let Request::RunScript(run) = build_request(admin.command).unwrap() else {
            panic!("expected RunScript");
        };
        assert_eq!(run.shell, control::ScriptShell::Powershell as i32);
        assert_eq!(run.content, "Get-Date");
        assert!(
            Args::try_parse_from([
                "omegadesk-server",
                "admin",
                "--token",
                "t",
                "run",
                "pc",
                "--script",
                "x",
                "--content",
                "y"
            ])
            .is_err()
        );

        assert!(shell_proto("zsh").is_err());
        assert!(interval_proto("fortnightly").is_err());
        assert!(check_kind_proto("ping").is_err());
        assert!(severity_proto("meh").is_err());

        let text = render_response(
            &Response::Run(control::RunScriptResponse {
                device_id: "dev".to_owned(),
                run_id: 0,
                queued: true,
            }),
            0,
        );
        assert!(text.contains("offline"));
        let text = render_response(
            &Response::DeploymentLink(control::DeploymentLinkInfo {
                link_id: "l".to_owned(),
                token: "odl_l_ff".to_owned(),
                tenant: "acme".to_owned(),
                site_id: "sp".to_owned(),
                expires_at_unix_secs: 9,
                max_uses: 0,
            }),
            0,
        );
        assert!(text.contains("--deployment-token odl_l_ff"));
        assert!(text.contains("unlimited"));
    }
}
