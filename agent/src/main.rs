//! OmegaDesk agent: captures the screen, encodes video, and streams it to the
//! client; receives remote keyboard and pointer events and injects them into
//! the local session.
//!
//! Usage (Phase 1, local network):
//!
//! ```text
//! omegadesk-agent --listen 0.0.0.0:7070
//! ```
//!
//! On startup the agent prints its TLS certificate fingerprint and access
//! password; the client requires both to connect.

mod capture_loop;
mod password;
mod platform;
mod session;

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context;
use clap::Parser;
use omegadesk_codec::EncoderSettings;
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

    /// Machine name displayed to the connected client.
    #[arg(long, default_value = "omegadesk-agent")]
    name: String,
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

    let (endpoint, fingerprint) =
        server_endpoint(args.listen).context("failed to bind agent QUIC endpoint")?;
    info!("agent listening on {}", endpoint.local_addr()?);
    info!("certificate fingerprint: {fingerprint}");
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
        info!("client connected: {remote}");
        match session::run(connection, config.clone()).await {
            Ok(()) => info!("session ended: {remote}"),
            Err(error) => warn!("session with {remote} ended with error: {error:#}"),
        }
    }
    Ok(())
}
