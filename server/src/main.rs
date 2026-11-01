//! OmegaDesk mesh coordinator binary (`omegadesk-server`).
//!
//! Each node opens one Noise `IK` connection and keeps it for the life of its
//! enrollment (Headscale `/machine/map` long-poll model): enrollment, relay
//! tickets, endpoint updates and the batched netmap stream all travel on it.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use clap::Parser;
use omegadesk_identity::{DeviceId, DeviceIdentity, FileStore, KeyStore, default_store};
use omegadesk_noise::{
    HANDSHAKE_INIT_LEN, MAX_FRAME_CIPHERTEXT_LEN, NoiseReceiver, NoiseSender, ResponderHandshake,
};
use omegadesk_protocol::control::CONTROL_PROTOCOL_VERSION;
use omegadesk_protocol::control::v1 as control;
use omegadesk_server::{
    Coordinator, CoordinatorError, EnrollmentBundle, NetmapDelta, RelayNode, parse_endpoints,
};
use prost::Message;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

/// Prologue mixed into every control-channel Noise handshake.
pub const CONTROL_PROLOGUE: &[u8] = b"omegadesk-control-v1";

/// Time a connection has to finish the handshake and enroll.
const ENROLL_TIMEOUT: Duration = Duration::from_secs(15);

/// A node that stays silent for this long is considered gone.
const IDLE_TIMEOUT: Duration = Duration::from_secs(120);

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

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
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

fn envelope(payload: control::control_envelope::Payload) -> control::ControlEnvelope {
    control::ControlEnvelope {
        payload: Some(payload),
    }
}

fn error_envelope(
    code: control::ControlErrorCode,
    message: impl Into<String>,
) -> control::ControlEnvelope {
    envelope(control::control_envelope::Payload::Error(
        control::ControlError {
            code: code as i32,
            message: message.into(),
        },
    ))
}

/// Reads one encrypted control frame, validating the length before allocating.
async fn read_control(
    reader: &mut OwnedReadHalf,
    rx: &mut NoiseReceiver,
) -> Result<control::ControlEnvelope> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await?;
    let body_len = usize::try_from(u32::from_be_bytes(len_buf))?;
    if body_len > MAX_FRAME_CIPHERTEXT_LEN {
        anyhow::bail!("control frame of {body_len} bytes exceeds the limit");
    }
    let mut body = vec![0u8; body_len];
    reader.read_exact(&mut body).await?;
    let plain = rx.read_body(&body)?;
    Ok(control::ControlEnvelope::decode(plain.as_slice())?)
}

/// Owns the write half and the Noise send state; everything the connection
/// sends goes through this task so frames are never interleaved.
async fn writer_loop(
    mut writer: OwnedWriteHalf,
    mut tx: NoiseSender,
    mut outbound: mpsc::Receiver<control::ControlEnvelope>,
) {
    while let Some(msg) = outbound.recv().await {
        let Ok(frame) = tx.write_frame(&msg.encode_to_vec()) else {
            break;
        };
        if writer.write_all(&frame).await.is_err() {
            break;
        }
    }
    let _ = writer.shutdown().await;
}

/// Forwards batched netmap deltas from the coordinator to the node.
async fn netmap_forwarder(
    mut netmap_rx: mpsc::Receiver<Vec<NetmapDelta>>,
    outbound: mpsc::Sender<control::ControlEnvelope>,
) {
    while let Some(batch) = netmap_rx.recv().await {
        let deltas: Vec<control::NetmapDelta> =
            batch.iter().filter_map(NetmapDelta::to_proto).collect();
        if deltas.is_empty() {
            continue;
        }
        let msg = envelope(control::control_envelope::Payload::NetmapBatch(
            control::NetmapBatch { deltas },
        ));
        if outbound.send(msg).await.is_err() {
            break;
        }
    }
}

fn enroll(
    coordinator: &Arc<Mutex<Coordinator>>,
    request: &control::EnrollRequest,
    peer: omegadesk_identity::DevicePublic,
) -> Result<EnrollmentBundle, Box<control::ControlEnvelope>> {
    if request.protocol_version != CONTROL_PROTOCOL_VERSION {
        return Err(Box::new(error_envelope(
            control::ControlErrorCode::UnsupportedVersion,
            format!(
                "unsupported control protocol version {}",
                request.protocol_version
            ),
        )));
    }
    let mut guard = coordinator.lock().map_err(|_| {
        Box::new(error_envelope(
            control::ControlErrorCode::Internal,
            "coordinator unavailable",
        ))
    })?;
    guard
        .enroll_machine(
            &request.preauth_key,
            peer,
            &request.hostname,
            parse_endpoints(&request.endpoints),
            unix_now(),
        )
        .map_err(|error| {
            let code = match error {
                CoordinatorError::MalformedPreAuthKey
                | CoordinatorError::InvalidPreAuthKey
                | CoordinatorError::PreAuthKeyAlreadyUsed
                | CoordinatorError::PreAuthKeyExpired => {
                    control::ControlErrorCode::InvalidPreauthKey
                }
                CoordinatorError::InvalidAclTag(_)
                | CoordinatorError::UnknownNode(_)
                | CoordinatorError::AddressPoolExhausted
                | CoordinatorError::MalformedControlMessage(_) => {
                    control::ControlErrorCode::Internal
                }
            };
            Box::new(error_envelope(code, error.to_string()))
        })
}

async fn handle_connection(
    stream: TcpStream,
    server_id: Arc<DeviceIdentity>,
    coordinator: Arc<Mutex<Coordinator>>,
) -> Result<()> {
    stream.set_nodelay(true)?;
    let (mut reader, mut writer) = stream.into_split();

    let (session, request) = tokio::time::timeout(ENROLL_TIMEOUT, async {
        let mut init_msg = vec![0u8; HANDSHAKE_INIT_LEN];
        reader.read_exact(&mut init_msg).await?;
        let (session, reply) = ResponderHandshake::accept(&server_id, CONTROL_PROLOGUE, &init_msg)?;
        writer.write_all(&reply).await?;
        let (tx, mut rx) = session.split();
        let first = read_control(&mut reader, &mut rx).await?;
        Ok::<_, anyhow::Error>(((tx, rx), first))
    })
    .await
    .context("enrollment timeout")??;
    let (tx, mut rx) = session;
    let peer = *tx.peer_public();
    let node_id: DeviceId = peer.id();

    let (outbound_tx, outbound_rx) = mpsc::channel(64);
    let writer_task = tokio::spawn(writer_loop(writer, tx, outbound_rx));

    let Some(control::control_envelope::Payload::EnrollRequest(enroll_request)) = request.payload
    else {
        let _ = outbound_tx
            .send(error_envelope(
                control::ControlErrorCode::NotEnrolled,
                "first message must be EnrollRequest",
            ))
            .await;
        drop(outbound_tx);
        let _ = writer_task.await;
        anyhow::bail!("first control message was not EnrollRequest");
    };

    let bundle = match enroll(&coordinator, &enroll_request, peer) {
        Ok(bundle) => bundle,
        Err(error) => {
            let _ = outbound_tx.send(*error).await;
            drop(outbound_tx);
            let _ = writer_task.await;
            anyhow::bail!("enrollment rejected for {node_id}");
        }
    };
    info!(node = %node_id, fqdn = %bundle.node.fqdn, ipv4 = %bundle.node.ipv4, "node enrolled");
    let response = envelope(control::control_envelope::Payload::EnrollResponse(
        bundle.to_proto(),
    ));
    outbound_tx.send(response).await?;
    let forwarder = tokio::spawn(netmap_forwarder(bundle.netmap_rx, outbound_tx.clone()));

    let result = serve_node(&mut reader, &mut rx, node_id, &coordinator, &outbound_tx).await;

    forwarder.abort();
    drop(outbound_tx);
    writer_task.abort();
    if let Ok(mut guard) = coordinator.lock() {
        guard.handle_disconnect(node_id);
    }
    info!(node = %node_id, "node disconnected");
    result
}

async fn serve_node(
    reader: &mut OwnedReadHalf,
    rx: &mut NoiseReceiver,
    node_id: DeviceId,
    coordinator: &Arc<Mutex<Coordinator>>,
    outbound: &mpsc::Sender<control::ControlEnvelope>,
) -> Result<()> {
    loop {
        let msg = tokio::time::timeout(IDLE_TIMEOUT, read_control(reader, rx))
            .await
            .context("node idle timeout")??;
        match msg.payload {
            Some(control::control_envelope::Payload::EndpointUpdate(update)) => {
                let mut guard = coordinator
                    .lock()
                    .map_err(|_| anyhow::anyhow!("coordinator mutex poisoned"))?;
                guard.update_endpoints(node_id, parse_endpoints(&update.endpoints))?;
                guard.flush_netmap();
            }
            Some(control::control_envelope::Payload::RelayTicketRequest(_)) => {
                let grants = {
                    let guard = coordinator
                        .lock()
                        .map_err(|_| anyhow::anyhow!("coordinator mutex poisoned"))?;
                    guard.issue_relay_grants(node_id, unix_now())?
                };
                let reply = envelope(control::control_envelope::Payload::RelayTicketResponse(
                    control::RelayTicketResponse {
                        relays: grants
                            .iter()
                            .map(omegadesk_server::RelayGrant::to_proto)
                            .collect(),
                    },
                ));
                outbound.send(reply).await?;
            }
            Some(control::control_envelope::Payload::Keepalive(keepalive)) => {
                let reply = envelope(control::control_envelope::Payload::Keepalive(keepalive));
                outbound.send(reply).await?;
            }
            Some(control::control_envelope::Payload::Error(error)) => {
                anyhow::bail!("node reported error: {}", error.message);
            }
            Some(
                control::control_envelope::Payload::EnrollRequest(_)
                | control::control_envelope::Payload::EnrollResponse(_)
                | control::control_envelope::Payload::NetmapBatch(_)
                | control::control_envelope::Payload::RelayTicketResponse(_),
            )
            | None => {}
        }
    }
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
    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let id_clone = Arc::clone(&server_identity);
        let coord_clone = Arc::clone(&coordinator);
        tokio::spawn(async move {
            if let Err(err) = handle_connection(stream, id_clone, coord_clone).await {
                warn!(%peer_addr, error = %err, "control connection closed");
            }
        });
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
    fn server_key_is_signing_then_exchange() {
        let id = DeviceIdentity::generate();
        let hex = public_key_hex(&id);
        assert_eq!(hex.len(), 128);
        let bytes = data_encoding::HEXLOWER.decode(hex.as_bytes()).unwrap();
        assert_eq!(&bytes[..32], &id.public().signing_key_bytes());
        assert_eq!(&bytes[32..], &id.public().exchange_key_bytes());
    }
}
