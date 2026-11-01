//! Stateless DERP-style packet relay binary (`omegadesk-relay`).

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use clap::Parser;
use omegadesk_identity::DeviceIdentity;
use omegadesk_relay::{FRAME_HEADER_LEN, RelayFrame, RelayRouter};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(
    name = "omegadesk-relay",
    version,
    about = "Stateless OmegaDesk packet relay"
)]
struct Args {
    /// Address to listen on (defaults to 0.0.0.0:8443 for unprivileged startup;
    /// use 0.0.0.0:443 in production).
    #[arg(long, env = "OMEGADESK_RELAY_LISTEN", default_value = "0.0.0.0:8443")]
    listen: SocketAddr,

    /// Hex-encoded 32-byte shared HMAC secret used to verify coordinator tickets.
    #[arg(
        long,
        env = "OMEGADESK_RELAY_TICKET_SECRET",
        default_value = "4f6d6567614465736b52656c61795469636b6574536563726574563130303030"
    )]
    ticket_secret_hex: String,

    /// Check configuration and exit immediately (used for smoke tests).
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

async fn read_wire_frame(stream: &mut TcpStream) -> Result<RelayFrame> {
    let mut header = [0u8; FRAME_HEADER_LEN];
    stream.read_exact(&mut header).await?;
    let body_len = usize::try_from(u32::from_be_bytes([
        header[1], header[2], header[3], header[4],
    ]))?;
    let mut buf = vec![0u8; FRAME_HEADER_LEN + body_len];
    buf[..FRAME_HEADER_LEN].copy_from_slice(&header);
    stream.read_exact(&mut buf[FRAME_HEADER_LEN..]).await?;
    Ok(RelayFrame::decode(&buf)?)
}

async fn handle_client(mut stream: TcpStream, router: Arc<Mutex<RelayRouter>>) -> Result<()> {
    let greeting = {
        let guard = router
            .lock()
            .map_err(|_| anyhow::anyhow!("relay router mutex poisoned"))?;
        guard.server_key_frame().encode()?
    };
    stream.write_all(&greeting).await?;

    let login = read_wire_frame(&mut stream).await?;
    let RelayFrame::ClientInfo {
        client_public_key,
        ticket,
    } = login
    else {
        anyhow::bail!("expected FrameClientInfo as first client frame");
    };

    let (server_info_bytes, mut rx) = {
        let mut guard = router
            .lock()
            .map_err(|_| anyhow::anyhow!("relay router mutex poisoned"))?;
        let (info_frame, rx) = guard.register_client(client_public_key, &ticket, unix_now())?;
        (info_frame.encode()?, rx)
    };
    stream.write_all(&server_info_bytes).await?;

    loop {
        tokio::select! {
            outbound = rx.recv() => {
                let Some(frame) = outbound else { break };
                stream.write_all(&frame.encode()?).await?;
            }
            inbound = read_wire_frame(&mut stream) => {
                let Ok(frame) = inbound else { break };
                match frame {
                    RelayFrame::SendPacket { dst_key, packet } => {
                        if let Ok(mut guard) = router.lock() {
                            let _ = guard.forward_packet(client_public_key, dst_key, packet);
                        }
                    }
                    RelayFrame::Ping(data) => {
                        let pong = RelayFrame::Pong(data).encode()?;
                        stream.write_all(&pong).await?;
                    }
                    RelayFrame::ServerKey { .. }
                    | RelayFrame::ClientInfo { .. }
                    | RelayFrame::ServerInfo { .. }
                    | RelayFrame::RecvPacket { .. }
                    | RelayFrame::KeepAlive
                    | RelayFrame::NotePreferred { .. }
                    | RelayFrame::PeerGone { .. }
                    | RelayFrame::Pong(_) => {}
                }
            }
        }
    }

    if let Ok(mut guard) = router.lock() {
        guard.unregister_client(&client_public_key);
    }
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

    let relay_identity = DeviceIdentity::generate();
    let router = Arc::new(Mutex::new(RelayRouter::new(
        relay_identity.public().exchange_key_bytes(),
        secret,
    )));

    if args.check_only {
        info!(id = %relay_identity.id(), "relay configuration verified");
        return Ok(());
    }

    let listener = TcpListener::bind(args.listen).await?;
    info!(listen = %args.listen, id = %relay_identity.id(), "omegadesk-relay listening");

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let router_clone = Arc::clone(&router);
        tokio::spawn(async move {
            if let Err(err) = handle_client(stream, router_clone).await {
                warn!(%peer_addr, error = %err, "relay client session ended");
            }
        });
    }
}
