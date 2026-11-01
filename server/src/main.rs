//! OmegaDesk mesh coordinator binary (`omegadesk-server`).

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use clap::Parser;
use omegadesk_identity::DeviceIdentity;
use omegadesk_noise::{HANDSHAKE_INIT_LEN, ResponderHandshake};
use omegadesk_server::Coordinator;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
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
    #[arg(
        long,
        env = "OMEGADESK_RELAY_TICKET_SECRET",
        default_value = "4f6d6567614465736b52656c61795469636b6574536563726574563130303030"
    )]
    ticket_secret_hex: String,

    /// Generate a bootstrap pre-auth key, verify configuration, and exit immediately.
    #[arg(long)]
    check_only: bool,
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

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

async fn handle_noise_connection(
    mut stream: TcpStream,
    server_id: Arc<DeviceIdentity>,
    coordinator: Arc<Mutex<Coordinator>>,
) -> Result<()> {
    let mut init_msg = vec![0u8; HANDSHAKE_INIT_LEN];
    stream.read_exact(&mut init_msg).await?;

    let (mut session, reply) =
        ResponderHandshake::accept(&server_id, b"omegadesk-control-v1", &init_msg)?;
    stream.write_all(&reply).await?;

    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let body_len = usize::try_from(u32::from_be_bytes(len_buf))?;
    let mut frame = vec![0u8; 4 + body_len];
    frame[..4].copy_from_slice(&len_buf);
    stream.read_exact(&mut frame[4..]).await?;

    let plain = session.read_frame(&frame)?;
    let req_str = String::from_utf8(plain)?;
    let mut parts = req_str.splitn(2, '\n');
    let token = parts.next().unwrap_or("");
    let hostname = parts.next().unwrap_or("node");

    let peer_pub = *session.peer_public();
    let response_text = {
        let mut guard = coordinator
            .lock()
            .map_err(|_| anyhow::anyhow!("coordinator mutex poisoned"))?;
        let bundle = guard.enroll_machine(token, peer_pub, hostname, Vec::new(), unix_now())?;
        format!(
            "fqdn={}\nipv4={}\nipv6={}",
            bundle.node.fqdn, bundle.node.ipv4, bundle.node.ipv6
        )
    };

    let resp_frame = session.write_frame(response_text.as_bytes())?;
    stream.write_all(&resp_frame).await?;
    Ok(())
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

    let server_identity = Arc::new(DeviceIdentity::generate());
    let mut coord = Coordinator::new(secret);
    let bootstrap_key = coord.create_preauth_key(
        &args.tenant,
        true,
        false,
        vec!["tag:default".to_owned()],
        None,
    )?;

    info!(
        id = %server_identity.id(),
        tenant = %args.tenant,
        bootstrap_preauth_key = %bootstrap_key,
        "omegadesk-server initialized"
    );

    if args.check_only {
        return Ok(());
    }

    let coordinator = Arc::new(Mutex::new(coord));
    let listener = TcpListener::bind(args.listen).await?;
    info!(listen = %args.listen, "omegadesk-server listening for Noise IK connections");

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let id_clone = Arc::clone(&server_identity);
        let coord_clone = Arc::clone(&coordinator);
        tokio::spawn(async move {
            if let Err(err) = handle_noise_connection(stream, id_clone, coord_clone).await {
                warn!(%peer_addr, error = %err, "control connection closed");
            }
        });
    }
}
