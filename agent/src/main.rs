//! Agente do OmegaDesk: captura a tela, codifica e envia ao cliente; recebe
//! teclado e mouse e injeta na sessão local.
//!
//! Uso (Fase 1, rede local):
//!
//! ```text
//! omegadesk-agent --listen 0.0.0.0:7070
//! ```
//!
//! O agente mostra a impressão digital do certificado e a senha de acesso; o
//! cliente precisa das duas para conectar.

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
#[command(version, about = "Agente do OmegaDesk")]
struct Args {
    /// Endereço e porta em que o agente aceita conexões.
    #[arg(long, default_value = "0.0.0.0:7070")]
    listen: SocketAddr,

    /// Monitor a compartilhar (0 é o principal).
    #[arg(long, default_value_t = 0)]
    display: u32,

    /// Encoder de vídeo.
    #[arg(long, value_enum, default_value_t = EncoderChoice::Auto)]
    encoder: EncoderChoice,

    /// Taxa de vídeo em megabits por segundo.
    #[arg(long, default_value_t = 8)]
    bitrate_mbps: u32,

    /// Quadros por segundo máximos.
    #[arg(long, default_value_t = 60.0)]
    fps: f32,

    /// Senha de acesso fixa. Sem ela, uma senha aleatória é gerada a cada início.
    #[arg(long, env = "OMEGADESK_PASSWORD")]
    password: Option<String>,

    /// Não injeta teclado e mouse (só compartilha a tela).
    #[arg(long)]
    no_input: bool,

    /// Nome desta máquina mostrado ao cliente.
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
        Some(_) => anyhow::bail!("a senha precisa ter pelo menos 8 caracteres"),
        None => password::generate(),
    };
    // Identidade persistente do dispositivo: o mesmo ID a cada início.
    let store = omegadesk_identity::default_store("agent")
        .context("não foi possível abrir o cofre de chaves")?;
    let identity = omegadesk_identity::DeviceIdentity::load_or_create(store.as_ref())
        .context("não foi possível carregar a identidade do dispositivo")?;
    info!("ID do dispositivo: {}", identity.id());

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
        server_endpoint(args.listen).context("não foi possível abrir a porta do agente")?;
    info!("agente ouvindo em {}", endpoint.local_addr()?);
    info!("impressão digital: {fingerprint}");
    info!("senha de acesso: {}", config.password);

    // Fase 1: uma sessão por vez. Sessões simultâneas entram com o multiplexador.
    while let Some(incoming) = endpoint.accept().await {
        let connection = match incoming.await {
            Ok(connection) => connection,
            Err(error) => {
                warn!("conexão recusada: {error}");
                continue;
            }
        };
        let remote = connection.remote_address();
        info!("cliente conectado: {remote}");
        match session::run(connection, config.clone()).await {
            Ok(()) => info!("sessão encerrada: {remote}"),
            Err(error) => warn!("sessão com {remote} terminou: {error:#}"),
        }
    }
    Ok(())
}
