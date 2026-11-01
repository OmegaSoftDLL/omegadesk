//! The mesh driver task: the only place that performs real UDP receives and
//! advances the sans-I/O mesh timers.

use std::sync::Arc;
use std::time::Instant;

use omegadesk_control::{NetmapEvent, PeerInfo};
use omegadesk_relay::RelayFrame;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{debug, warn};

use crate::socket::MagicSocket;

/// Messages from the relay and control tasks to the driver.
#[derive(Debug)]
pub(crate) enum DriverMsg {
    /// Recompute timers (the socket queued transmits or changed state).
    Wake,
    /// A relay connection logged in; packets for it go to `tx`.
    RelayConnected {
        index: usize,
        tx: mpsc::Sender<RelayFrame>,
    },
    /// A relay connection ended.
    RelayDisconnected { index: usize },
    /// A relay delivered a packet from `src_key`.
    RelayPacket {
        index: usize,
        src_key: [u8; 32],
        packet: Vec<u8>,
    },
    /// A relay reported `peer_key` unreachable through it.
    RelayPeerGone { index: usize, peer_key: [u8; 32] },
    /// A netmap change from the coordinator.
    Netmap(NetmapEvent),
    /// Complete snapshot after a re-enrollment: the node's own record and
    /// every peer.
    Resync {
        self_node: Box<PeerInfo>,
        peers: Vec<PeerInfo>,
    },
}

/// Runs until the message channel closes.
pub(crate) async fn run(
    socket: Arc<MagicSocket>,
    udp: Arc<UdpSocket>,
    mut messages: mpsc::Receiver<DriverMsg>,
) {
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let deadline = socket.poll_timeout();
        let timer = async {
            match deadline {
                Some(at) => tokio::time::sleep_until(tokio::time::Instant::from_std(at)).await,
                None => std::future::pending::<()>().await,
            }
        };
        tokio::select! {
            received = udp.recv_from(&mut buf) => match received {
                Ok((len, from)) => socket.handle_receive(Some(from), &buf[..len], Instant::now()),
                Err(error) => {
                    // Windows reports ICMP port-unreachable of a previous send
                    // as a receive error; the socket itself is fine.
                    debug!(%error, "udp receive error");
                }
            },
            message = messages.recv() => {
                let Some(message) = message else {
                    debug!("mesh driver stopping");
                    return;
                };
                handle_message(&socket, message);
            },
            () = timer => socket.handle_timeout(Instant::now()),
        }
    }
}

fn handle_message(socket: &MagicSocket, message: DriverMsg) {
    match message {
        DriverMsg::Wake => {}
        DriverMsg::RelayConnected { index, tx } => socket.relay_connected(index, tx),
        DriverMsg::RelayDisconnected { index } => socket.relay_disconnected(index),
        DriverMsg::RelayPacket {
            index,
            src_key,
            packet,
        } => {
            socket.relay_peer_present(index, src_key);
            socket.handle_receive(None, &packet, Instant::now());
        }
        DriverMsg::RelayPeerGone { index, peer_key } => socket.relay_peer_gone(index, peer_key),
        DriverMsg::Netmap(event) => apply_netmap(socket, event),
        DriverMsg::Resync { self_node, peers } => socket.apply_snapshot(&self_node, &peers),
    }
}

fn apply_netmap(socket: &MagicSocket, event: NetmapEvent) {
    match event {
        NetmapEvent::PeerUpserted(peer) => socket.upsert_peer(*peer),
        NetmapEvent::EndpointsUpdated {
            signing_key,
            endpoints,
        } => socket.update_endpoints(signing_key, endpoints),
        NetmapEvent::PeerRemoved { signing_key } => socket.remove_peer_by_signing(signing_key),
        NetmapEvent::Disconnected(reason) => {
            warn!(%reason, "control connection lost; re-enrolling in the background");
        }
    }
}
