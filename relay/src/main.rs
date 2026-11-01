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

use anyhow::{Context, Result};
use clap::Parser;
use omegadesk_identity::{DeviceIdentity, FileStore, KeyStore, default_store};
use omegadesk_relay::{RelayRouter, service};
use tokio::net::{TcpListener, UdpSocket};
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

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
        relay_public_key = %data_encoding::HEXLOWER.encode(&public.exchange_key_bytes()),
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
                tokio::spawn(service::serve_stun(socket));
            }
            Err(error) => warn!(listen = %stun_addr, %error, "STUN responder disabled"),
        }
    }

    let listener = TcpListener::bind(args.listen).await?;
    info!(listen = %args.listen, "omegadesk-relay listening");
    service::serve_relay(listener, router).await
}
