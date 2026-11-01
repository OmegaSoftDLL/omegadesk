//! OmegaDesk mesh coordinator binary (`omegadesk-server`).

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use clap::Parser;
use omegadesk_identity::{DeviceIdentity, FileStore, KeyStore, default_store};
use omegadesk_server::{Coordinator, RelayNode, control_server};
use tokio::net::TcpListener;
use tracing::info;
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

    /// Generate a bootstrap pre-auth key, print the server public key, verify
    /// the configuration, and exit immediately.
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
        server_key = %public_key_hex(&server_identity),
        bootstrap_preauth_key = %bootstrap_key,
        "omegadesk-server initialized; nodes need --server-key and --preauth-key"
    );
    if args.check_only {
        return Ok(());
    }

    let coordinator = Arc::new(Mutex::new(coord));
    let listener = TcpListener::bind(args.listen).await?;
    info!(listen = %args.listen, "omegadesk-server listening for Noise IK connections");
    control_server::serve(listener, server_identity, coordinator).await
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
    fn server_key_is_signing_then_exchange() {
        let id = DeviceIdentity::generate();
        let hex = public_key_hex(&id);
        assert_eq!(hex.len(), 128);
        let bytes = data_encoding::HEXLOWER.decode(hex.as_bytes()).unwrap();
        assert_eq!(&bytes[..32], &id.public().signing_key_bytes());
        assert_eq!(&bytes[32..], &id.public().exchange_key_bytes());
    }
}
