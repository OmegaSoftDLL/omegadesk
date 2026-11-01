//! Client side of the DERP-style relay protocol: login with a single-use
//! ticket bound to the relay key and the per-connection challenge, keepalive
//! pings, and reconnection with a fresh ticket from the coordinator.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use omegadesk_control::{RelayGrant, TicketSource};
use omegadesk_identity::DeviceIdentity;
use omegadesk_relay::service::{read_frame, write_frame};
use omegadesk_relay::{
    KEEP_ALIVE, MAX_FRAME_BODY_LEN, PROTOCOL_VERSION, RelayFrame, seal_client_login,
};
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::driver::DriverMsg;

/// Time allowed for TCP connect plus login.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Reconnect back-off bounds.
const BACKOFF_MIN: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(30);
/// `ServerKey` body: 32-byte key + 16-byte challenge.
const SERVER_KEY_MAX_BODY: usize = 64;
/// A relay that sends nothing (not even `KeepAlive`) for this long is dead.
const READ_IDLE_TIMEOUT: Duration = Duration::from_secs(150);

/// Keeps one relay connection alive forever, re-logging in with a fresh
/// ticket after every disconnect.
pub(crate) async fn run_relay(
    index: usize,
    mut grant: RelayGrant,
    identity: Arc<DeviceIdentity>,
    tickets: Arc<dyn TicketSource>,
    driver: mpsc::Sender<DriverMsg>,
) {
    let mut backoff = BACKOFF_MIN;
    loop {
        let started = tokio::time::Instant::now();
        match session(index, &grant, &identity, &driver).await {
            Ok(()) => info!(relay = %grant.address, "relay connection closed"),
            Err(error) => warn!(relay = %grant.address, %error, "relay connection failed"),
        }
        if driver
            .send(DriverMsg::RelayDisconnected { index })
            .await
            .is_err()
        {
            return;
        }
        // A session that lasted a while resets the back-off.
        if started.elapsed() > BACKOFF_MAX {
            backoff = BACKOFF_MIN;
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(BACKOFF_MAX);
        // Tickets are single-use: fetch a fresh one for this relay.
        match tickets.fresh_grants().await {
            Ok(grants) => {
                if let Some(fresh) = grants
                    .into_iter()
                    .find(|g| g.exchange_key == grant.exchange_key)
                {
                    grant = fresh;
                } else {
                    warn!(relay = %grant.address, "coordinator no longer offers this relay");
                }
            }
            Err(error) => warn!(%error, "could not refresh relay ticket"),
        }
    }
}

async fn session(
    index: usize,
    grant: &RelayGrant,
    identity: &DeviceIdentity,
    driver: &mpsc::Sender<DriverMsg>,
) -> Result<()> {
    let (reader, writer) = tokio::time::timeout(CONNECT_TIMEOUT, login(grant, identity))
        .await
        .context("relay login timeout")??;
    let (tx, rx) = mpsc::channel(256);
    driver
        .send(DriverMsg::RelayConnected { index, tx })
        .await
        .map_err(|_| anyhow::anyhow!("mesh driver stopped"))?;
    info!(relay = %grant.address, "relay connected");
    let mut writer_task = tokio::spawn(writer_loop(writer, rx));
    let result = tokio::select! {
        result = reader_loop(reader, index, driver) => result,
        _ = &mut writer_task => Err(anyhow::anyhow!("relay writer ended")),
    };
    writer_task.abort();
    result
}

async fn login(
    grant: &RelayGrant,
    identity: &DeviceIdentity,
) -> Result<(OwnedReadHalf, OwnedWriteHalf)> {
    let stream = TcpStream::connect(&grant.address)
        .await
        .with_context(|| format!("connect to relay {}", grant.address))?;
    stream.set_nodelay(true)?;
    let (mut reader, mut writer) = stream.into_split();
    let RelayFrame::ServerKey {
        server_public_key,
        challenge,
    } = read_frame(&mut reader, SERVER_KEY_MAX_BODY).await?
    else {
        anyhow::bail!("relay did not start with ServerKey");
    };
    if server_public_key != grant.exchange_key {
        anyhow::bail!("relay key does not match the coordinator's record");
    }
    let sealed = seal_client_login(identity, &server_public_key, &challenge, &grant.ticket)?;
    write_frame(
        &mut writer,
        &RelayFrame::ClientInfo {
            client_public_key: identity.public().exchange_key_bytes(),
            sealed,
        },
    )
    .await?;
    let RelayFrame::ServerInfo { protocol_version } = read_frame(&mut reader, 16).await? else {
        anyhow::bail!("relay rejected the login");
    };
    if protocol_version != PROTOCOL_VERSION {
        anyhow::bail!("unsupported relay protocol version {protocol_version}");
    }
    Ok((reader, writer))
}

async fn writer_loop(mut writer: OwnedWriteHalf, mut outbound: mpsc::Receiver<RelayFrame>) {
    let mut ping = tokio::time::interval(KEEP_ALIVE);
    ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ping.tick().await;
    let mut sequence = 0u64;
    loop {
        let frame = tokio::select! {
            frame = outbound.recv() => match frame {
                Some(frame) => frame,
                None => break,
            },
            _ = ping.tick() => {
                sequence += 1;
                RelayFrame::Ping(sequence.to_be_bytes())
            }
        };
        if write_frame(&mut writer, &frame).await.is_err() {
            break;
        }
    }
}

async fn reader_loop(
    mut reader: OwnedReadHalf,
    index: usize,
    driver: &mpsc::Sender<DriverMsg>,
) -> Result<()> {
    loop {
        let frame = tokio::time::timeout(
            READ_IDLE_TIMEOUT,
            read_frame(&mut reader, MAX_FRAME_BODY_LEN),
        )
        .await
        .context("relay idle timeout")??;
        let message = match frame {
            RelayFrame::RecvPacket { src_key, packet } => DriverMsg::RelayPacket {
                index,
                src_key,
                packet,
            },
            RelayFrame::PeerGone { peer_key, .. } => DriverMsg::RelayPeerGone { index, peer_key },
            RelayFrame::KeepAlive
            | RelayFrame::Pong(_)
            | RelayFrame::Ping(_)
            | RelayFrame::ServerKey { .. }
            | RelayFrame::ClientInfo { .. }
            | RelayFrame::ServerInfo { .. }
            | RelayFrame::SendPacket { .. }
            | RelayFrame::NotePreferred { .. } => continue,
        };
        driver
            .send(message)
            .await
            .map_err(|_| anyhow::anyhow!("mesh driver stopped"))?;
    }
}
