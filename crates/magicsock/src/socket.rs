//! [`MagicSocket`]: the [`quinn::AsyncUdpSocket`] over the mesh, plus the
//! shared [`State`] (mesh node, netmap, relay links, pending datagrams).

use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{self, IoSliceMut};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll};
use std::time::Instant;

use omegadesk_control::PeerInfo;
use omegadesk_identity::{DeviceId, QuickSupportId};
use omegadesk_mesh::{ConnectionPath, MeshError, MeshEvent, MeshNode, Transmit, TransmitTarget};
use omegadesk_relay::RelayFrame;
use omegadesk_tun::IpPacket;
use quinn::udp::{RecvMeta, Transmit as QuicTransmit};
use quinn::{AsyncUdpSocket, UdpPoller};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::driver::DriverMsg;
use crate::{MESH_PORT, PENDING_PER_PEER};

/// One decrypted datagram ready for QUIC.
#[derive(Debug)]
pub(crate) struct Datagram {
    /// Virtual address of the sender (`<peer mesh IPv4>:<inner UDP port>`).
    pub(crate) from: SocketAddr,
    pub(crate) payload: Vec<u8>,
}

/// A relay connection as seen by the mesh: where to queue `SendPacket` frames
/// and which peers the relay reported absent (`PeerGone`), so the next packet
/// for them tries another relay.
#[derive(Default)]
pub(crate) struct RelaySlot {
    pub(crate) tx: Option<mpsc::Sender<RelayFrame>>,
    pub(crate) gone: HashSet<[u8; 32]>,
}

/// Mesh state shared between the QUIC-facing socket and the driver task.
pub(crate) struct State {
    pub(crate) mesh: MeshNode,
    pub(crate) peers: HashMap<DeviceId, PeerInfo>,
    pub(crate) by_ipv4: HashMap<Ipv4Addr, DeviceId>,
    pub(crate) by_signing: HashMap<[u8; 32], DeviceId>,
    /// QUIC datagrams waiting for the peer's epoch exchange.
    pub(crate) pending: HashMap<DeviceId, VecDeque<Vec<u8>>>,
    pub(crate) relays: Vec<RelaySlot>,
}

impl State {
    /// Picks the relay used to reach `exchange_key`: the first connected relay
    /// that has not reported the peer gone; if every relay did, the marks are
    /// cleared and the first connected relay is retried.
    fn relay_for(&mut self, exchange_key: &[u8; 32]) -> Option<&mpsc::Sender<RelayFrame>> {
        let connected = |slot: &RelaySlot| slot.tx.is_some();
        let index = self
            .relays
            .iter()
            .position(|slot| connected(slot) && !slot.gone.contains(exchange_key));
        let index = if let Some(index) = index {
            index
        } else {
            for slot in &mut self.relays {
                slot.gone.remove(exchange_key);
            }
            self.relays.iter().position(connected)?
        };
        self.relays[index].tx.as_ref()
    }
}

/// Counters exposed for diagnostics.
#[derive(Debug, Default)]
pub struct SocketStats {
    /// Datagrams dropped because the real socket or a relay queue was full.
    pub dropped_tx: AtomicU64,
    /// Inbound packets that failed authentication or address checks.
    pub rejected_rx: AtomicU64,
    /// Datagrams dropped because QUIC was not draining the receive queue.
    pub dropped_rx: AtomicU64,
}

/// [`quinn::AsyncUdpSocket`] whose "network" is the OmegaDesk mesh.
pub struct MagicSocket {
    /// This node's record; replaced when a re-enrollment assigns a new address.
    self_info: Mutex<PeerInfo>,
    udp: Arc<UdpSocket>,
    state: Mutex<State>,
    inbound_tx: mpsc::Sender<Datagram>,
    inbound_rx: Mutex<mpsc::Receiver<Datagram>>,
    endpoint_updates: mpsc::UnboundedSender<Vec<SocketAddr>>,
    driver: mpsc::Sender<DriverMsg>,
    stats: SocketStats,
}

impl std::fmt::Debug for MagicSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MagicSocket")
            .field("local_ipv4", &self.local_ipv4())
            .finish_non_exhaustive()
    }
}

impl MagicSocket {
    #[allow(
        clippy::too_many_arguments,
        reason = "constructor wiring, called once by Node"
    )]
    pub(crate) fn new(
        self_info: PeerInfo,
        udp: Arc<UdpSocket>,
        mesh: MeshNode,
        relay_count: usize,
        inbound_tx: mpsc::Sender<Datagram>,
        inbound_rx: mpsc::Receiver<Datagram>,
        endpoint_updates: mpsc::UnboundedSender<Vec<SocketAddr>>,
        driver: mpsc::Sender<DriverMsg>,
    ) -> Self {
        let relays = (0..relay_count).map(|_| RelaySlot::default()).collect();
        Self {
            self_info: Mutex::new(self_info),
            udp,
            state: Mutex::new(State {
                mesh,
                peers: HashMap::new(),
                by_ipv4: HashMap::new(),
                by_signing: HashMap::new(),
                pending: HashMap::new(),
                relays,
            }),
            inbound_tx,
            inbound_rx: Mutex::new(inbound_rx),
            endpoint_updates,
            driver,
            stats: SocketStats::default(),
        }
    }

    /// Diagnostic counters.
    #[must_use]
    pub fn stats(&self) -> &SocketStats {
        &self.stats
    }

    /// This node's record as assigned by the coordinator (current enrollment).
    #[must_use]
    pub fn self_info(&self) -> PeerInfo {
        match self.self_info.lock() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    /// Mesh IPv4 address of this node (current enrollment).
    #[must_use]
    pub fn local_ipv4(&self) -> Ipv4Addr {
        match self.self_info.lock() {
            Ok(guard) => guard.ipv4,
            Err(poisoned) => poisoned.into_inner().ipv4,
        }
    }

    pub(crate) fn lock(&self) -> MutexGuard<'_, State> {
        match self.state.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// Current peers.
    #[must_use]
    pub fn peers(&self) -> Vec<PeerInfo> {
        self.lock().peers.values().cloned().collect()
    }

    /// Resolves `hostname`, `hostname.omega` or a mesh IPv4 address.
    #[must_use]
    pub fn resolve(&self, target: &str) -> Option<PeerInfo> {
        let state = self.lock();
        if let Ok(ip) = target.parse::<Ipv4Addr>() {
            return state
                .by_ipv4
                .get(&ip)
                .and_then(|id| state.peers.get(id))
                .cloned();
        }
        let wanted = target.trim_end_matches('.').to_ascii_lowercase();
        state
            .peers
            .values()
            .find(|p| p.fqdn == wanted || p.hostname == wanted)
            .cloned()
    }

    /// Peer that currently holds the QuickSupport ID `id`, if the netmap knows one.
    #[must_use]
    pub fn resolve_quicksupport(&self, id: QuickSupportId) -> Option<PeerInfo> {
        self.lock()
            .peers
            .values()
            .find(|p| p.quicksupport_id == Some(id))
            .cloned()
    }

    /// Peer that owns a mesh IPv4 address.
    #[must_use]
    pub fn peer_by_ipv4(&self, ip: Ipv4Addr) -> Option<PeerInfo> {
        let state = self.lock();
        state
            .by_ipv4
            .get(&ip)
            .and_then(|id| state.peers.get(id))
            .cloned()
    }

    /// Active path towards `peer`.
    #[must_use]
    pub fn peer_path(&self, peer: DeviceId) -> Option<ConnectionPath> {
        self.lock().mesh.peer_path(peer)
    }

    /// Applies a complete (re-)enrollment: adopts the node's own record (a
    /// re-enrolled ephemeral node may get a new address, which existing
    /// sessions cannot survive, so pending datagrams are dropped), upserts every
    /// listed peer and removes the ones that vanished.
    pub(crate) fn apply_snapshot(&self, self_node: &PeerInfo, peers: &[PeerInfo]) {
        let now = Instant::now();
        let address_changed = {
            let mut current = match self.self_info.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            let changed = current.ipv4 != self_node.ipv4;
            if changed {
                warn!(
                    old = %current.ipv4,
                    new = %self_node.ipv4,
                    "re-enrollment assigned a new mesh address; open sessions will drop"
                );
            }
            *current = self_node.clone();
            changed
        };
        let mut state = self.lock();
        if address_changed {
            state.pending.clear();
        }
        let keep: HashSet<DeviceId> = peers.iter().map(PeerInfo::id).collect();
        let stale: Vec<DeviceId> = state
            .peers
            .keys()
            .filter(|id| !keep.contains(id))
            .copied()
            .collect();
        for id in stale {
            Self::remove_peer_locked(&mut state, id);
        }
        for peer in peers {
            Self::upsert_peer_locked(&mut state, peer.clone(), now);
        }
        drop(state);
        self.flush();
    }

    pub(crate) fn upsert_peer(&self, peer: PeerInfo) {
        let now = Instant::now();
        {
            let mut state = self.lock();
            Self::upsert_peer_locked(&mut state, peer, now);
        }
        self.flush();
    }

    pub(crate) fn update_endpoints(&self, signing_key: [u8; 32], endpoints: Vec<SocketAddr>) {
        let now = Instant::now();
        {
            let mut state = self.lock();
            let Some(&id) = state.by_signing.get(&signing_key) else {
                return;
            };
            let Some(peer) = state.peers.get_mut(&id) else {
                return;
            };
            peer.endpoints = endpoints;
            let public = peer.public;
            let endpoints = peer.endpoints.clone();
            state.mesh.upsert_peer(public, endpoints, now);
        }
        self.flush();
    }

    pub(crate) fn remove_peer_by_signing(&self, signing_key: [u8; 32]) {
        let mut state = self.lock();
        if let Some(&id) = state.by_signing.get(&signing_key) {
            Self::remove_peer_locked(&mut state, id);
        }
    }

    fn upsert_peer_locked(state: &mut State, peer: PeerInfo, now: Instant) {
        let id = peer.id();
        if let Some(previous) = state.peers.get(&id)
            && previous.ipv4 != peer.ipv4
        {
            state.by_ipv4.remove(&previous.ipv4);
        }
        state.by_ipv4.insert(peer.ipv4, id);
        state.by_signing.insert(peer.public.signing_key_bytes(), id);
        state
            .mesh
            .upsert_peer(peer.public, peer.endpoints.clone(), now);
        state.peers.insert(id, peer);
    }

    fn remove_peer_locked(state: &mut State, id: DeviceId) {
        if let Some(peer) = state.peers.remove(&id) {
            state.by_ipv4.remove(&peer.ipv4);
            state.by_signing.remove(&peer.public.signing_key_bytes());
            info!(peer = %peer.fqdn, "peer left the mesh");
        }
        state.pending.remove(&id);
        state.mesh.remove_peer(id);
    }

    /// Feeds an inbound datagram (direct UDP or relay) to the mesh and
    /// delivers any decrypted QUIC payload.
    pub(crate) fn handle_receive(
        &self,
        from_udp: Option<SocketAddr>,
        datagram: &[u8],
        now: Instant,
    ) {
        let mut state = self.lock();
        match state.mesh.handle_receive(from_udp, datagram, now) {
            Ok(Some((peer_id, packet))) => {
                if let Some(datagram) = self.unwrap_datagram(&state, peer_id, &packet) {
                    self.deliver(datagram);
                } else {
                    self.stats.rejected_rx.fetch_add(1, Ordering::Relaxed);
                }
            }
            Err(
                MeshError::TunnelAuthFailed | MeshError::Disco(_) | MeshError::InvalidIpPacket(_),
            ) => {
                self.stats.rejected_rx.fetch_add(1, Ordering::Relaxed);
            }
            Ok(None)
            | Err(
                MeshError::UnknownPeer(_)
                | MeshError::PeerEpochUnknown(_)
                | MeshError::CounterExhausted,
            ) => {}
        }
        Self::flush_locked(self, &mut state);
    }

    /// Validates the inner IPv4/UDP packet: it must come from the peer's own
    /// mesh address and be addressed to this node.
    fn unwrap_datagram(
        &self,
        state: &State,
        peer_id: DeviceId,
        packet: &IpPacket,
    ) -> Option<Datagram> {
        let peer = state.peers.get(&peer_id)?;
        let (src, dst, payload) = udp_payload(packet)?;
        if *src.ip() != peer.ipv4 || *dst.ip() != self.local_ipv4() || dst.port() != MESH_PORT {
            return None;
        }
        Some(Datagram {
            from: SocketAddr::V4(src),
            payload: payload.to_vec(),
        })
    }

    fn deliver(&self, datagram: Datagram) {
        if self.inbound_tx.try_send(datagram).is_err() {
            self.stats.dropped_rx.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub(crate) fn handle_timeout(&self, now: Instant) {
        let mut state = self.lock();
        state.mesh.handle_timeout(now);
        Self::flush_locked(self, &mut state);
    }

    pub(crate) fn poll_timeout(&self) -> Option<Instant> {
        self.lock().mesh.poll_timeout()
    }

    pub(crate) fn relay_connected(&self, index: usize, tx: mpsc::Sender<RelayFrame>) {
        let mut state = self.lock();
        if let Some(slot) = state.relays.get_mut(index) {
            slot.tx = Some(tx);
            slot.gone.clear();
        }
        Self::flush_locked(self, &mut state);
    }

    pub(crate) fn relay_disconnected(&self, index: usize) {
        let mut state = self.lock();
        if let Some(slot) = state.relays.get_mut(index) {
            slot.tx = None;
        }
    }

    pub(crate) fn relay_peer_gone(&self, index: usize, peer_key: [u8; 32]) {
        let mut state = self.lock();
        if let Some(slot) = state.relays.get_mut(index) {
            slot.gone.insert(peer_key);
        }
    }

    pub(crate) fn relay_peer_present(&self, index: usize, peer_key: [u8; 32]) {
        let mut state = self.lock();
        if let Some(slot) = state.relays.get_mut(index) {
            slot.gone.remove(&peer_key);
        }
    }

    /// Drains mesh transmits and events and flushes queued datagrams of peers
    /// whose epoch exchange just completed.
    pub(crate) fn flush(&self) {
        let mut state = self.lock();
        Self::flush_locked(self, &mut state);
    }

    fn flush_locked(&self, state: &mut State) {
        let now = Instant::now();
        loop {
            while let Some(transmit) = state.mesh.poll_transmit() {
                self.send_transmit(state, transmit);
            }
            let mut endpoints_changed = None;
            while let Some(event) = state.mesh.poll_event() {
                match event {
                    MeshEvent::Connected { peer, path } => {
                        debug!(%peer, ?path, "mesh peer connected");
                    }
                    MeshEvent::PathUpgraded { peer, remote, rtt } => {
                        info!(%peer, %remote, ?rtt, "direct path established");
                    }
                    MeshEvent::FallbackToRelay { peer } => {
                        info!(%peer, "using relay path");
                    }
                    MeshEvent::LocalEndpointsChanged(endpoints) => {
                        endpoints_changed = Some(endpoints);
                    }
                    MeshEvent::PeerKeyRotated { peer } => {
                        warn!(%peer, "peer exchange key rotated; tunnel reset");
                        state.pending.remove(&peer);
                    }
                }
            }
            if let Some(endpoints) = endpoints_changed {
                let _ = self.endpoint_updates.send(endpoints);
            }
            let ready: Vec<DeviceId> = state
                .pending
                .keys()
                .filter(|id| state.mesh.peer_ready(**id))
                .copied()
                .collect();
            if ready.is_empty() {
                break;
            }
            for id in ready {
                let Some(queue) = state.pending.remove(&id) else {
                    continue;
                };
                for datagram in queue {
                    self.encapsulate_locked(state, id, &datagram, now);
                }
            }
        }
    }

    fn send_transmit(&self, state: &mut State, transmit: Transmit) {
        match transmit.target {
            TransmitTarget::DirectUdp(addr) => {
                if let Err(error) = self.udp.try_send_to(&transmit.payload, addr) {
                    if error.kind() != io::ErrorKind::WouldBlock {
                        debug!(%addr, %error, "direct send failed");
                    }
                    self.stats.dropped_tx.fetch_add(1, Ordering::Relaxed);
                }
            }
            TransmitTarget::Relay(exchange_key) => {
                let frame = RelayFrame::SendPacket {
                    dst_key: exchange_key,
                    packet: transmit.payload,
                };
                match state.relay_for(&exchange_key) {
                    Some(tx) if tx.try_send(frame).is_ok() => {}
                    Some(_) | None => {
                        self.stats.dropped_tx.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }
    }

    /// Wraps one QUIC datagram in IPv4/UDP, encrypts it for `peer` and queues
    /// the transmit (or parks it until the epoch exchange completes).
    fn encapsulate_locked(
        &self,
        state: &mut State,
        peer_id: DeviceId,
        datagram: &[u8],
        now: Instant,
    ) {
        let Some(peer_ipv4) = state.peers.get(&peer_id).map(|p| p.ipv4) else {
            return;
        };
        let dst_port = MESH_PORT;
        let Ok(packet) =
            IpPacket::ipv4_udp(self.local_ipv4(), peer_ipv4, MESH_PORT, dst_port, datagram)
        else {
            return;
        };
        match state.mesh.encapsulate(peer_id, &packet, now) {
            Ok(()) => {}
            Err(MeshError::PeerEpochUnknown(_)) => {
                let queue = state.pending.entry(peer_id).or_default();
                if queue.len() >= PENDING_PER_PEER {
                    queue.pop_front();
                    self.stats.dropped_tx.fetch_add(1, Ordering::Relaxed);
                }
                queue.push_back(datagram.to_vec());
            }
            Err(error) => {
                debug!(%peer_id, %error, "cannot encapsulate datagram");
                self.stats.dropped_tx.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    fn wake_driver(&self) {
        let _ = self.driver.try_send(DriverMsg::Wake);
    }
}

/// Extracts `(src, dst, payload)` from an IPv4/UDP packet.
pub(crate) fn udp_payload(packet: &IpPacket) -> Option<(SocketAddrV4, SocketAddrV4, &[u8])> {
    let raw = packet.as_bytes();
    if packet.version() != 4 || packet.protocol() != 17 {
        return None;
    }
    let ihl = usize::from(raw[0] & 0x0F) * 4;
    let udp = raw.get(ihl..)?;
    if udp.len() < 8 {
        return None;
    }
    let src_port = u16::from_be_bytes([udp[0], udp[1]]);
    let dst_port = u16::from_be_bytes([udp[2], udp[3]]);
    let udp_len = usize::from(u16::from_be_bytes([udp[4], udp[5]]));
    if udp_len < 8 || udp_len > udp.len() {
        return None;
    }
    let (IpAddr::V4(src), IpAddr::V4(dst)) = (packet.source(), packet.destination()) else {
        return None;
    };
    Some((
        SocketAddrV4::new(src, src_port),
        SocketAddrV4::new(dst, dst_port),
        &udp[8..udp_len],
    ))
}

/// The socket never reports `WouldBlock` (full buffers drop the datagram, as
/// Tailscale does), so it is always writable.
#[derive(Debug)]
struct AlwaysWritable;

impl UdpPoller for AlwaysWritable {
    fn poll_writable(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncUdpSocket for MagicSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(AlwaysWritable)
    }

    fn try_send(&self, transmit: &QuicTransmit<'_>) -> io::Result<()> {
        let IpAddr::V4(dst_ip) = transmit.destination.ip() else {
            return Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "mesh peers have IPv4 virtual addresses",
            ));
        };
        if transmit.destination.port() != MESH_PORT {
            return Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "mesh peers listen on the mesh port only",
            ));
        }
        let now = Instant::now();
        let mut state = self.lock();
        let Some(&peer_id) = state.by_ipv4.get(&dst_ip) else {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "destination is not a mesh peer",
            ));
        };
        let segment = transmit
            .segment_size
            .unwrap_or(transmit.contents.len())
            .max(1);
        for datagram in transmit.contents.chunks(segment) {
            self.encapsulate_locked(&mut state, peer_id, datagram, now);
        }
        Self::flush_locked(self, &mut state);
        drop(state);
        self.wake_driver();
        Ok(())
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let mut rx = match self.inbound_rx.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let local_ipv4 = self.local_ipv4();
        let slots = bufs.len().min(meta.len());
        // Successful receives always occupy the prefix `0..filled`: an
        // oversized datagram is dropped without consuming a slot.
        let mut filled = 0;
        while filled < slots {
            let datagram = if filled == 0 {
                match rx.poll_recv(cx) {
                    Poll::Ready(Some(datagram)) => datagram,
                    Poll::Ready(None) => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            "mesh driver stopped",
                        )));
                    }
                    Poll::Pending => return Poll::Pending,
                }
            } else {
                match rx.try_recv() {
                    Ok(datagram) => datagram,
                    Err(_) => break,
                }
            };
            let len = datagram.payload.len();
            if len > bufs[filled].len() {
                self.stats.dropped_rx.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            bufs[filled][..len].copy_from_slice(&datagram.payload);
            meta[filled] = RecvMeta {
                addr: datagram.from,
                len,
                stride: len,
                ecn: None,
                dst_ip: Some(IpAddr::V4(local_ipv4)),
            };
            filled += 1;
        }
        Poll::Ready(Ok(filled))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(SocketAddr::new(IpAddr::V4(self.local_ipv4()), MESH_PORT))
    }

    fn max_transmit_segments(&self) -> usize {
        1
    }

    fn max_receive_segments(&self) -> usize {
        1
    }

    fn may_fragment(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn udp_payload_round_trips_and_rejects_short_packets() {
        let packet = IpPacket::ipv4_udp(
            Ipv4Addr::new(100, 64, 0, 1),
            Ipv4Addr::new(100, 64, 0, 2),
            7070,
            7070,
            b"quic",
        )
        .unwrap();
        let (src, dst, payload) = udp_payload(&packet).unwrap();
        assert_eq!(src, SocketAddrV4::new(Ipv4Addr::new(100, 64, 0, 1), 7070));
        assert_eq!(dst, SocketAddrV4::new(Ipv4Addr::new(100, 64, 0, 2), 7070));
        assert_eq!(payload, b"quic");

        // Not UDP (protocol 6) -> rejected even though the IPv4 header is valid.
        let mut raw = packet.as_bytes().to_vec();
        raw[9] = 6;
        let csum = omegadesk_tun::ipv4_checksum(&{
            let mut h = raw[..20].to_vec();
            h[10] = 0;
            h[11] = 0;
            h
        });
        raw[10..12].copy_from_slice(&csum.to_be_bytes());
        let tcp = IpPacket::parse(raw).unwrap();
        assert!(udp_payload(&tcp).is_none());
    }

    fn peer(ipv4: Ipv4Addr, name: &str) -> PeerInfo {
        PeerInfo {
            public: omegadesk_identity::DeviceIdentity::generate().public(),
            tenant: "t".into(),
            hostname: name.into(),
            fqdn: format!("{name}.omega"),
            ipv4,
            ipv6: std::net::Ipv6Addr::LOCALHOST,
            endpoints: vec![],
            tags: vec![],
            ephemeral: true,
            quicksupport_id: None,
        }
    }

    async fn test_socket() -> (MagicSocket, mpsc::Sender<Datagram>) {
        let udp = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let mesh = MeshNode::new(
            omegadesk_identity::DeviceIdentity::generate(),
            vec![],
            vec![],
        );
        let (inbound_tx, inbound_rx) = mpsc::channel(16);
        let (updates_tx, _updates_rx) = mpsc::unbounded_channel();
        let (driver_tx, _driver_rx) = mpsc::channel(16);
        let socket = MagicSocket::new(
            peer(Ipv4Addr::new(100, 64, 0, 1), "me"),
            udp,
            mesh,
            0,
            inbound_tx.clone(),
            inbound_rx,
            updates_tx,
            driver_tx,
        );
        (socket, inbound_tx)
    }

    #[tokio::test]
    async fn oversized_datagrams_never_leave_holes_in_the_returned_prefix() {
        let (socket, inbound) = test_socket().await;
        let from = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 2)), MESH_PORT);
        inbound
            .try_send(Datagram {
                from,
                payload: vec![1u8; 64],
            })
            .unwrap();
        inbound
            .try_send(Datagram {
                from,
                payload: vec![2u8; 8],
            })
            .unwrap();
        let mut storage = [[0u8; 16], [0u8; 16]];
        let [first, second] = &mut storage;
        let mut bufs = [IoSliceMut::new(first), IoSliceMut::new(second)];
        let mut meta = [RecvMeta::default(), RecvMeta::default()];
        let waker = std::task::Waker::noop();
        let mut cx = Context::from_waker(waker);
        let polled = socket.poll_recv(&mut cx, &mut bufs, &mut meta);
        assert!(matches!(polled, Poll::Ready(Ok(1))), "{polled:?}");
        assert_eq!(meta[0].len, 8);
        assert_eq!(&bufs[0][..8], &[2u8; 8]);
        assert_eq!(socket.stats().dropped_rx.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn re_enrollment_with_a_new_address_updates_the_self_record() {
        let (socket, _inbound) = test_socket().await;
        let bob = peer(Ipv4Addr::new(100, 64, 0, 2), "bob");
        socket.apply_snapshot(
            &peer(Ipv4Addr::new(100, 64, 0, 1), "me"),
            std::slice::from_ref(&bob),
        );
        assert_eq!(socket.local_ipv4(), Ipv4Addr::new(100, 64, 0, 1));
        let moved = peer(Ipv4Addr::new(100, 64, 0, 9), "me");
        socket.apply_snapshot(&moved, std::slice::from_ref(&bob));
        assert_eq!(socket.local_ipv4(), Ipv4Addr::new(100, 64, 0, 9));
        assert_eq!(
            socket.local_addr().unwrap(),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 9)), MESH_PORT)
        );
        assert_eq!(socket.self_info().fqdn, "me.omega");
        // Peers missing from the snapshot are gone, listed ones stay.
        socket.apply_snapshot(&moved, &[]);
        assert!(socket.peer_by_ipv4(bob.ipv4).is_none());
    }
}
