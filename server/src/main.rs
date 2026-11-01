//! OmegaDesk mesh coordinator binary (`omegadesk-server`).

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};
use clap::Parser;
use omegadesk_control::ControlConfig;
use omegadesk_identity::{DeviceIdentity, FileStore, KeyStore, default_store};
use omegadesk_magicsock::{Node, NodeConfig};
use omegadesk_policy::{AuditKind, AuditOutcome};
use omegadesk_server::{
    AuditLog, Coordinator, RelayNode, control_server, load_policy_file, web_server, web_session,
};
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

    /// Default tenant name for the bootstrap pre-auth key.
    #[arg(long, env = "OMEGADESK_TENANT", default_value = "default")]
    tenant: String,

    /// Hex-encoded 32-byte shared HMAC secret used to issue relay tickets.
    /// Required: there is no default, so tickets can never be forged with a
    /// publicly known key.
    #[arg(long, env = "OMEGADESK_RELAY_TICKET_SECRET")]
    ticket_secret_hex: String,

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

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();
    let secret = decode_hex_32(&args.ticket_secret_hex)
        .context("ticket_secret_hex must be exactly 64 hex characters (32 bytes)")?;
    let server_identity = Arc::new(load_identity(args.key_file.as_ref())?);
    let mut coord = Coordinator::new(secret);
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
        id = %server_identity.id(),
        tenant = %args.tenant,
        server_key = %public_key_hex(&server_identity),
        bootstrap_preauth_key = %bootstrap_key,
        quicksupport_preauth_key = %quicksupport_key,
        "omegadesk-server initialized; nodes need --server-key and --preauth-key"
    );
    if args.check_only {
        return Ok(());
    }

    let coordinator = Arc::new(Mutex::new(coord));
    if let Some(path) = args.policy.clone() {
        tokio::spawn(watch_policy(path, policy_mtime, Arc::clone(&coordinator)));
    }
    let listener = TcpListener::bind(args.listen).await?;
    info!(listen = %args.listen, "omegadesk-server listening for Noise IK connections");
    let control = tokio::spawn(control_server::serve(
        listener,
        Arc::clone(&server_identity),
        Arc::clone(&coordinator),
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
    }
}
