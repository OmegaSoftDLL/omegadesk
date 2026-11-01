//! Relay and STUN services as library functions so the binary stays thin and
//! integration tests can run a relay in-process.

use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use omegadesk_mesh::stun;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::{
    CLIENT_INFO_WIRE_LEN, FRAME_HEADER_LEN, KEEP_ALIVE, MAX_FRAME_BODY_LEN, RegisteredClient,
    RelayFrame, RelayRouter,
};

/// Time a connection has to complete its login before it is dropped.
pub const LOGIN_TIMEOUT: Duration = Duration::from_secs(10);

/// A client that sends nothing (not even a `Ping`) for this long is dropped.
/// Clients ping every [`KEEP_ALIVE`], so this tolerates two lost pings.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(150);

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Reads one frame, validating the declared length against `max_body` **before**
/// allocating the body, so an unauthenticated peer cannot make the relay
/// allocate gigabytes by announcing a huge frame.
///
/// # Errors
///
/// Returns an error on I/O failure, oversized frames or malformed bodies.
pub async fn read_frame(reader: &mut OwnedReadHalf, max_body: usize) -> Result<RelayFrame> {
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

/// Encodes and writes one frame.
///
/// # Errors
///
/// Returns an error if encoding or writing fails.
pub async fn write_frame(writer: &mut OwnedWriteHalf, frame: &RelayFrame) -> Result<()> {
    writer.write_all(&frame.encode()?).await?;
    Ok(())
}

/// Unregisters a client when dropped, so every exit path (errors, timeouts,
/// task cancellation) cleans up exactly once. A stale generation is a no-op.
struct RegistrationGuard {
    router: Arc<Mutex<RelayRouter>>,
    key: [u8; 32],
    generation: u64,
}

impl Drop for RegistrationGuard {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.router.lock() {
            guard.unregister_client(&self.key, self.generation);
        }
    }
}

async fn login(
    reader: &mut OwnedReadHalf,
    writer: &mut OwnedWriteHalf,
    router: &Arc<Mutex<RelayRouter>>,
) -> Result<(RegisteredClient, RegistrationGuard)> {
    let (greeting, challenge) = {
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
        guard.register_client(client_public_key, &challenge, &sealed, unix_now())?
    };
    // From here on the client is in the router: the guard makes the cleanup
    // unconditional, including when the acknowledgement below fails or the
    // login timeout cancels this future.
    let cleanup = RegistrationGuard {
        router: Arc::clone(router),
        key: registered.key,
        generation: registered.generation,
    };
    write_frame(writer, &registered.server_info).await?;
    Ok((registered, cleanup))
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
        let frame = tokio::time::timeout(IDLE_TIMEOUT, read_frame(&mut reader, MAX_FRAME_BODY_LEN))
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

/// Serves one relay client connection from login to disconnect.
///
/// # Errors
///
/// Returns the error that ended the session; the client is always unregistered.
pub async fn handle_client(stream: TcpStream, router: Arc<Mutex<RelayRouter>>) -> Result<()> {
    stream.set_nodelay(true)?;
    let (mut reader, mut writer) = stream.into_split();
    let (registered, _cleanup) =
        tokio::time::timeout(LOGIN_TIMEOUT, login(&mut reader, &mut writer, &router))
            .await
            .context("login timeout")??;
    let RegisteredClient {
        key,
        generation,
        outbound,
        outbound_tx,
        ..
    } = registered;
    info!(client = %data_encoding::HEXLOWER.encode(&key[..8]), generation, "relay client registered");

    // The session ends when EITHER half ends: a failed write (closed outbound)
    // must not leave a registration alive just because the client keeps sending.
    let mut writer_task = tokio::spawn(writer_loop(writer, outbound));
    let reader_task = reader_loop(reader, key, Arc::clone(&router), outbound_tx);
    let result = tokio::select! {
        result = reader_task => result,
        _ = &mut writer_task => Err(anyhow::anyhow!("outbound writer ended")),
    };
    writer_task.abort();
    // `_cleanup` unregisters here.
    result
}

/// Accepts relay clients forever.
///
/// # Errors
///
/// Returns an error when `accept` fails.
pub async fn serve_relay(listener: TcpListener, router: Arc<Mutex<RelayRouter>>) -> Result<()> {
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

/// RFC 5389 binding responder: answers every well-formed binding request with
/// the sender's reflexive address (`stun.Response` in Tailscale's `derper`).
pub async fn serve_stun(socket: UdpSocket) {
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
