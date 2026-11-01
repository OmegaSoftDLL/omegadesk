//! Stateless DERP-style packet relay binary (`omegadesk-relay`).
//!
//! Serves two things, like a Tailscale DERP node (`cmd/derper`):
//! - the relay itself over TCP (`--listen`), where clients log in with a ticket
//!   issued by the coordinator and sealed with their private key;
//! - a STUN binding responder over UDP (`--stun-listen`) so mesh nodes behind
//!   NAT can learn their public endpoint for hole punching.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use clap::Parser;
use omegadesk_identity::{DeviceIdentity, FileStore, KeyStore, default_store};
use omegadesk_mesh::stun;
use omegadesk_relay::{
    CLIENT_INFO_WIRE_LEN, FRAME_HEADER_LEN, KEEP_ALIVE, RegisteredClient, RelayFrame, RelayRouter,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

/// Time a connection has to complete its login before it is dropped.
const LOGIN_TIMEOUT: Duration = Duration::from_secs(10);

/// A client that sends nothing (not even a `Ping`) for this long is dropped.
const IDLE_TIMEOUT: Duration = Duration::from_secs(150);

#[derive(Debug, Parser)]
#[command(
    name = "omegadesk-relay",
    version,
    about = "Stateless OmegaDesk packet relay and STUN responder"
)]
struct Args {
    /// TCP address to listen on for relay clients (use 0.0.0.0:443 in production).
    #[arg(long, env = "OMEGADESK_RELAY_LISTEN", default_value = "0.0.0.0:8443")]
    listen: SocketAddr,

    /// UDP address for the STUN binding responder (RFC 5389). Defaults to the
    /// relay port on UDP; pass `--no-stun` to disable it.
    #[arg(long, env = "OMEGADESK_RELAY_STUN_LISTEN")]
    stun_listen: Option<SocketAddr>,

    /// Disables the STUN responder.
    #[arg(long)]
    no_stun: bool,

    /// Hex-encoded 32-byte shared HMAC secret used to verify coordinator tickets.
    /// Required: there is no default, so a relay can never accept tickets forged
    /// with a publicly known key.
    #[arg(long, env = "OMEGADESK_RELAY_TICKET_SECRET")]
    ticket_secret_hex: String,

    /// File holding the relay's persistent identity. Defaults to the operating
    /// system credential store (account `relay`).
    #[arg(long, env = "OMEGADESK_RELAY_KEY_FILE")]
    key_file: Option<PathBuf>,

    /// Check configuration, print the relay public key, and exit.
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

fn hex(bytes: &[u8]) -> String {
    data_encoding::HEXLOWER.encode(bytes)
}

/// Reads one frame, validating the declared length against the protocol limit
/// before allocating the body (an unauthenticated peer cannot make the relay
/// allocate gigabytes by announcing a huge frame).
async fn read_frame(reader: &mut OwnedReadHalf, max_body: usize) -> Result<RelayFrame> {
    let mut header = [0u8; FRAME_HEADER_LEN];
    reader.read_exact(&mut header).await?;
    let (frame_type, body_len) = RelayFrame::parse_header(&header)?;
    if body_len > max_body {
        anyhow::bail!("frame body of {body_len} bytes exceeds the {max_body}-byte limit");
    }
    let mut body = vec![0u8; body_len];
    reader.read_exact(&mut body).await?;
    Ok(RelayFrame::decode_body(frame_type, &body)?)
}

async fn write_frame(writer: &mut OwnedWriteHalf, frame: &RelayFrame) -> Result<()> {
    writer.write_all(&frame.encode()?).await?;
    Ok(())
}

async fn login(
    reader: &mut OwnedReadHalf,
    writer: &mut OwnedWriteHalf,
    router: &Arc<Mutex<RelayRouter>>,
) -> Result<RegisteredClient> {
    let greeting = {
        let guard = router
            .lock()
            .map_err(|_| anyhow::anyhow!("relay router mutex poisoned"))?;
        guard.server_key_frame()
    };
    write_frame(writer, &greeting).await?;

    let frame = read_frame(reader, CLIENT_INFO_WIRE_LEN).await?;
    let RelayFrame::ClientInfo {
        client_public_key,
        sealed,
    } = frame
    else {
        anyhow::bail!("expected FrameClientInfo as first client frame");
    };
    let registered = {
        let mut guard = router
            .lock()
            .map_err(|_| anyhow::anyhow!("relay router mutex poisoned"))?;
        guard.register_client(client_public_key, &sealed, unix_now())?
    };
    write_frame(writer, &registered.server_info).await?;
    Ok(registered)
}

/// Drains frames queued for this client (relayed packets, `PeerGone`, `Pong`)
/// and emits keep-alives, owning the write half exclusively.
async fn writer_loop(mut writer: OwnedWriteHalf, mut outbound: mpsc::Receiver<RelayFrame>) {
    let mut keepalive = tokio::time::interval(KEEP_ALIVE);
    keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    keepalive.tick().await;
    loop {
        let frame = tokio::select! {
            outbound = outbound.recv() => match outbound {
                Some(frame) => frame,
                None => break,
            },
            _ = keepalive.tick() => RelayFrame::KeepAlive,
        };
        if write_frame(&mut writer, &frame).await.is_err() {
            break;
        }
    }
    let _ = writer.shutdown().await;
}

/// Reads client frames, owning the read half exclusively, so a cancelled
/// write can never corrupt an in-progress read.
async fn reader_loop(
    mut reader: OwnedReadHalf,
    client_key: [u8; 32],
    router: Arc<Mutex<RelayRouter>>,
    outbound_tx: mpsc::Sender<RelayFrame>,
) -> Result<()> {
    loop {
        let frame = tokio::time::timeout(
            IDLE_TIMEOUT,
            read_frame(&mut reader, omegadesk_relay::MAX_FRAME_BODY_LEN),
        )
        .await
        .context("client idle timeout")??;
        match frame {
            RelayFrame::SendPacket { dst_key, packet } => {
                let mut guard = router
                    .lock()
                    .map_err(|_| anyhow::anyhow!("relay router mutex poisoned"))?;
                guard.forward_packet(client_key, dst_key, packet)?;
            }
            RelayFrame::Ping(data) => {
                if outbound_tx.try_send(RelayFrame::Pong(data)).is_err() {
                    warn!("client outbound queue full; dropping pong");
                }
            }
            RelayFrame::KeepAlive
            | RelayFrame::NotePreferred { .. }
            | RelayFrame::Pong(_)
            | RelayFrame::ServerKey { .. }
            | RelayFrame::ClientInfo { .. }
            | RelayFrame::ServerInfo { .. }
            | RelayFrame::RecvPacket { .. }
            | RelayFrame::PeerGone { .. } => {}
        }
    }
}

async fn handle_client(stream: TcpStream, router: Arc<Mutex<RelayRouter>>) -> Result<()> {
    stream.set_nodelay(true)?;
    let (mut reader, mut writer) = stream.into_split();
    let registered = tokio::time::timeout(LOGIN_TIMEOUT, login(&mut reader, &mut writer, &router))
        .await
        .context("login timeout")??;
    let RegisteredClient {
        key,
        generation,
        outbound,
        outbound_tx,
        ..
    } = registered;
    info!(client = %hex(&key[..8]), generation, "relay client registered");

    let writer_task = tokio::spawn(writer_loop(writer, outbound));
    let result = reader_loop(reader, key, Arc::clone(&router), outbound_tx).await;
    writer_task.abort();

    // Always unregister, whatever ended the session; a stale generation is a no-op.
    if let Ok(mut guard) = router.lock() {
        guard.unregister_client(&key, generation);
    }
    result
}

/// RFC 5389 binding responder: answers every well-formed binding request with
/// the sender's reflexive address (`stun.Response` in Tailscale's `derper`).
async fn stun_loop(socket: UdpSocket) {
    let mut buf = vec![0u8; 1500];
    loop {
        let Ok((len, from)) = socket.recv_from(&mut buf).await else {
            continue;
        };
        if let Ok(tx_id) = stun::parse_binding_request(&buf[..len]) {
            let _ = socket
                .send_to(&stun::binding_response(&tx_id, from), from)
                .await;
        }
    }
}

fn load_identity(key_file: Option<&PathBuf>) -> Result<DeviceIdentity> {
    let store: Box<dyn KeyStore> = match key_file {
        Some(path) => Box::new(FileStore::new(path.clone())),
        None => default_store("relay").context("failed to open the relay key store")?,
    };
    DeviceIdentity::load_or_create(store.as_ref()).context("failed to load the relay identity")
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
    let identity = load_identity(args.key_file.as_ref())?;
    let public = identity.public();
    info!(
        id = %identity.id(),
        relay_public_key = %hex(&public.exchange_key_bytes()),
        "relay identity loaded; pass this key to the coordinator with --relay"
    );
    let router = Arc::new(Mutex::new(RelayRouter::new(identity, secret)));

    if args.check_only {
        info!("relay configuration verified");
        return Ok(());
    }

    if !args.no_stun {
        let stun_addr = args
            .stun_listen
            .unwrap_or(SocketAddr::new(args.listen.ip(), args.listen.port()));
        match UdpSocket::bind(stun_addr).await {
            Ok(socket) => {
                info!(listen = %stun_addr, "STUN responder listening");
                tokio::spawn(stun_loop(socket));
            }
            Err(error) => warn!(listen = %stun_addr, %error, "STUN responder disabled"),
        }
    }

    let listener = TcpListener::bind(args.listen).await?;
    info!(listen = %args.listen, "omegadesk-relay listening");
    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let router_clone = Arc::clone(&router);
        tokio::spawn(async move {
            if let Err(err) = handle_client(stream, router_clone).await {
                info!(%peer_addr, error = %err, "relay client session ended");
            }
        });
    }
}
