//! OmegaDesk client: renders the agent's screen and forwards keyboard and mouse input.
//!
//! Usage (Phase 1, local network):
//!
//! ```text
//! omegadesk-client 192.168.0.10:7070 --fingerprint ab:cd:… --password <password>
//! ```
//!
//! The window title bar displays a live latency breakdown: host processing,
//! network (half RTT), decoding, and drawing.

mod keymap;
mod network;
mod stats;
mod win_hook;
mod window;

use std::net::SocketAddr;

use anyhow::Context;
use clap::Parser;
use winit::event_loop::EventLoop;

#[derive(Debug, Parser)]
#[command(version, about = "OmegaDesk remote desktop client")]
struct Args {
    /// Agent socket address, e.g. `192.168.0.10:7070`.
    address: SocketAddr,

    /// Certificate fingerprint printed by the agent on startup.
    #[arg(long)]
    fingerprint: String,

    /// Access password printed by the agent on startup.
    #[arg(long, env = "OMEGADESK_PASSWORD")]
    password: String,

    /// Watch only; do not send keyboard or mouse events.
    #[arg(long)]
    view_only: bool,
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stderr()))
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let args = Args::parse();
    win_hook::enable_dpi_awareness();

    let event_loop = EventLoop::<window::UserEvent>::with_user_event()
        .build()
        .context("failed to create window event loop")?;
    let store =
        omegadesk_identity::default_store("client").context("failed to open device key store")?;
    let identity = omegadesk_identity::DeviceIdentity::load_or_create(store.as_ref())
        .context("failed to load or create device identity")?;
    tracing::info!("device ID: {}", identity.id());
    let shared = stats::Shared::default();
    let input = network::start(
        network::Target {
            device_public_key: identity.public().signing_key_bytes(),
            address: args.address,
            fingerprint: args.fingerprint,
            password: args.password,
        },
        shared.clone(),
        event_loop.create_proxy(),
    );

    let mut app = window::App::new(shared, input, args.view_only);
    event_loop.run_app(&mut app)?;
    app.into_result()
}
