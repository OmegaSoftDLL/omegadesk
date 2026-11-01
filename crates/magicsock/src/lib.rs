//! Mesh socket for OmegaDesk nodes (`omegadesk-magicsock`).
//!
//! Design after Tailscale's `wgengine/magicsock`: one process-wide UDP socket
//! multiplexes **three** kinds of traffic, telling them apart by their first
//! bytes exactly like `magicsock.receiveIP` does:
//!
//! - STUN responses (RFC 5389 magic cookie) feed the reflexive-endpoint
//!   discovery of [`omegadesk_mesh::MeshNode`];
//! - `disco` messages (hole punching, path validation, epoch exchange);
//! - encrypted tunnel data packets carrying the QUIC datagrams of the
//!   remote-desktop session.
//!
//! The same packets flow through DERP-style relays when no direct path exists,
//! and the sans-I/O [`MeshNode`] decides, per peer, whether to send directly or
//! via the relay (relay within 1.5 s, upgrade to direct as soon as a `Pong`
//! validates a candidate, fall back again when the direct path dies).
//!
//! Towards QUIC the whole mesh looks like a plain UDP socket
//! ([`quinn::AsyncUdpSocket`]) on which every peer has a **virtual address**:
//! its mesh IPv4 (`100.64.0.0/10`, assigned by the coordinator) and the
//! session port [`MESH_PORT`]. A datagram for `100.64.0.7:7070` is wrapped in a
//! minimal IPv4/UDP header (so the data plane is identical to what a TUN
//! device would carry), encrypted for the peer that owns that address and sent
//! on the peer's current path. Inbound packets are authenticated by the mesh,
//! checked against the sender's assigned address (a peer cannot impersonate
//! another peer's virtual address) and handed to QUIC with the sender's
//! virtual address, so QUIC connection migration between direct and relayed
//! paths is invisible: the address never changes.
//!
//! [`Node`] ties it together: the control connection to the coordinator
//! (enrollment, netmap stream, relay tickets, endpoint updates, automatic
//! re-enrollment), the relay connections (DERP login with single-use tickets,
//! reconnect with fresh tickets), the mesh driver task and the QUIC endpoint
//! whose TLS is bound to the device identity ([`omegadesk_transport::identity_tls`]).

mod control_link;
mod driver;
mod relay_client;
mod socket;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use omegadesk_control::{ControlClient, ControlConfig, ControlError, Enrollment, PeerInfo};
use omegadesk_identity::{DeviceId, DeviceIdentity};
use omegadesk_mesh::{ConnectionPath, MeshNode};
use omegadesk_relay::RelayError;
use omegadesk_transport::identity_tls::{
    MESH_SERVER_NAME, identity_client_config, identity_server_config,
};
use omegadesk_transport::{TransportError, mesh_transport_config};
use omegadesk_tun::TunError;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::info;

pub use socket::MagicSocket;

/// UDP port of every node's QUIC endpoint on the mesh (virtual addresses are
/// `<mesh IPv4>:MESH_PORT`).
pub const MESH_PORT: u16 = omegadesk_transport::DEFAULT_PORT;

/// Datagrams queued for a peer while its tunnel epoch is still unknown (the
/// first QUIC Initial packets are sent before the disco exchange completes).
pub(crate) const PENDING_PER_PEER: usize = 32;

/// Errors returned by [`Node`].
#[derive(Debug, thiserror::Error)]
pub enum NodeError {
    /// The coordinator rejected or dropped the control connection.
    #[error(transparent)]
    Control(#[from] ControlError),
    /// QUIC/TLS configuration failed.
    #[error(transparent)]
    Transport(#[from] TransportError),
    /// Socket I/O failed.
    #[error("mesh socket: {0}")]
    Io(#[from] std::io::Error),
    /// A relay frame or ticket was malformed.
    #[error(transparent)]
    Relay(#[from] RelayError),
    /// Inner IP packet construction failed.
    #[error(transparent)]
    Packet(#[from] TunError),
    /// QUIC connection setup failed.
    #[error("quic connect: {0}")]
    Connect(#[from] quinn::ConnectError),
    /// QUIC connection failed.
    #[error("quic connection: {0}")]
    Connection(#[from] quinn::ConnectionError),
    /// No peer matches the requested name or address.
    #[error("no mesh peer matches `{0}`")]
    UnknownPeer(String),
    /// No async runtime is available for QUIC.
    #[error("no async runtime found for quinn")]
    NoRuntime,
}

/// How a node joins the mesh.
#[derive(Debug, Clone)]
pub struct NodeConfig {
    /// Coordinator connection and enrollment parameters. `endpoints` is
    /// filled in by the node from its interfaces and STUN.
    pub control: ControlConfig,
    /// Local UDP bind address for the mesh socket (`0.0.0.0:0` picks a port).
    pub bind: SocketAddr,
    /// Never attempt direct paths: advertise no endpoints, skip STUN and send
    /// everything through the relays (corporate "relay only" policy, tests).
    pub relay_only: bool,
}

impl NodeConfig {
    /// Default configuration: direct paths enabled, ephemeral UDP port.
    #[must_use]
    pub fn new(control: ControlConfig) -> Self {
        Self {
            control,
            bind: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            relay_only: false,
        }
    }
}

/// A node connected to the mesh: owns the socket, the control and relay links
/// and the QUIC endpoint bound to the device identity.
pub struct Node {
    socket: Arc<MagicSocket>,
    endpoint: quinn::Endpoint,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Node {
    /// Enrolls with the coordinator, connects to the relays and starts the
    /// mesh driver. Returns once enrollment succeeded; relay and direct paths
    /// are established in the background.
    ///
    /// # Errors
    ///
    /// Returns [`NodeError`] if the socket cannot be bound, enrollment fails
    /// or the QUIC endpoint cannot be created.
    pub async fn start(
        identity: Arc<DeviceIdentity>,
        config: NodeConfig,
    ) -> Result<Self, NodeError> {
        let udp = Arc::new(UdpSocket::bind(config.bind).await?);
        let local_port = udp.local_addr()?.port();
        let local_candidates = if config.relay_only {
            Vec::new()
        } else {
            local_ipv4_candidates(config.bind.ip(), local_port)
        };

        let mut control_config = config.control.clone();
        control_config.endpoints.clone_from(&local_candidates);
        let (client, enrollment) =
            ControlClient::connect(Arc::clone(&identity), control_config.clone()).await?;
        let Enrollment {
            self_node,
            peers,
            relays,
            total_peers,
        } = enrollment;
        info!(
            fqdn = %self_node.fqdn,
            ipv4 = %self_node.ipv4,
            peers = peers.len(),
            total_peers,
            relays = relays.len(),
            "enrolled in the mesh"
        );

        let stun_servers = if config.relay_only {
            Vec::new()
        } else {
            resolve_stun_servers(&relays).await
        };
        let mut mesh = MeshNode::new(
            DeviceIdentity::from_secret_bytes(&identity.to_secret_bytes())
                .map_err(|_| ControlError::Malformed("device identity"))?,
            local_candidates,
            stun_servers,
        );
        mesh.set_relay_only(config.relay_only);

        let (inbound_tx, inbound_rx) = mpsc::channel(1024);
        let (endpoint_updates_tx, endpoint_updates_rx) = mpsc::unbounded_channel();
        let (driver_tx, driver_rx) = mpsc::channel(256);
        let control_link = Arc::new(control_link::SharedControl::new(client.handle()));
        let socket = Arc::new(MagicSocket::new(
            self_node.clone(),
            Arc::clone(&udp),
            mesh,
            relays.len(),
            inbound_tx,
            inbound_rx,
            endpoint_updates_tx,
            driver_tx.clone(),
        ));
        // The first chunk of the snapshot; any remainder arrives as deltas.
        socket.apply_snapshot(&self_node, &peers);

        let mut tasks = Vec::new();
        for (index, grant) in relays.iter().cloned().enumerate() {
            tasks.push(tokio::spawn(relay_client::run_relay(
                index,
                grant,
                Arc::clone(&identity),
                Arc::clone(&control_link) as Arc<dyn omegadesk_control::TicketSource>,
                driver_tx.clone(),
            )));
        }
        tasks.push(tokio::spawn(control_link::supervise(
            Arc::clone(&identity),
            control_config,
            Arc::clone(&control_link),
            client,
            driver_tx,
            endpoint_updates_rx,
        )));
        tasks.push(tokio::spawn(driver::run(
            Arc::clone(&socket),
            udp,
            driver_rx,
        )));

        let mut server_config = identity_server_config(&identity)?;
        server_config.transport_config(Arc::new(mesh_transport_config()));
        let runtime = quinn::default_runtime().ok_or(NodeError::NoRuntime)?;
        let endpoint = quinn::Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            Some(server_config),
            Arc::clone(&socket) as Arc<dyn quinn::AsyncUdpSocket>,
            runtime,
        )?;

        Ok(Self {
            socket,
            endpoint,
            tasks,
        })
    }

    /// This node's record as assigned by the coordinator (current enrollment;
    /// a re-enrolled ephemeral node may receive a new address).
    #[must_use]
    pub fn self_info(&self) -> PeerInfo {
        self.socket.self_info()
    }

    /// Virtual address of this node on the mesh (`<mesh IPv4>:7070`).
    #[must_use]
    pub fn virtual_addr(&self) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(self.socket.local_ipv4()), MESH_PORT)
    }

    /// The QUIC endpoint running over the mesh. It accepts incoming
    /// connections (identity-bound certificate) and is used by [`Self::connect`].
    #[must_use]
    pub fn endpoint(&self) -> &quinn::Endpoint {
        &self.endpoint
    }

    /// The underlying mesh socket.
    #[must_use]
    pub fn socket(&self) -> Arc<MagicSocket> {
        Arc::clone(&self.socket)
    }

    /// Current peers of the tenant.
    #[must_use]
    pub fn peers(&self) -> Vec<PeerInfo> {
        self.socket.peers()
    }

    /// Resolves a peer by `hostname`, `hostname.omega` or mesh IPv4 address.
    #[must_use]
    pub fn resolve(&self, target: &str) -> Option<PeerInfo> {
        self.socket.resolve(target)
    }

    /// Peer that owns a virtual address, if any.
    #[must_use]
    pub fn peer_at(&self, addr: SocketAddr) -> Option<PeerInfo> {
        match addr.ip() {
            IpAddr::V4(ipv4) => self.socket.peer_by_ipv4(ipv4),
            IpAddr::V6(_) => None,
        }
    }

    /// Active path towards `peer` (`None` if unknown).
    #[must_use]
    pub fn peer_path(&self, peer: DeviceId) -> Option<ConnectionPath> {
        self.socket.peer_path(peer)
    }

    /// Opens a QUIC connection to the peer named `target` (`hostname`,
    /// `hostname.omega` or mesh IPv4), accepting only a certificate carrying
    /// that peer's identity key from the netmap.
    ///
    /// # Errors
    ///
    /// Returns [`NodeError::UnknownPeer`] if the name does not resolve, or the
    /// QUIC error that aborted the connection.
    pub async fn connect(&self, target: &str) -> Result<quinn::Connection, NodeError> {
        let peer = self
            .resolve(target)
            .ok_or_else(|| NodeError::UnknownPeer(target.to_owned()))?;
        let mut client_config = identity_client_config(peer.public.signing_key_bytes())?;
        client_config.transport_config(Arc::new(mesh_transport_config()));
        let addr = SocketAddr::new(IpAddr::V4(peer.ipv4), MESH_PORT);
        let connecting = self
            .endpoint
            .connect_with(client_config, addr, MESH_SERVER_NAME)?;
        Ok(connecting.await?)
    }

    /// Stops every background task and closes the endpoint.
    pub fn shutdown(&self) {
        self.endpoint.close(0u32.into(), b"shutdown");
        for task in &self.tasks {
            task.abort();
        }
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        self.shutdown();
    }
}

impl std::fmt::Debug for Node {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let info = self.self_info();
        f.debug_struct("Node")
            .field("fqdn", &info.fqdn)
            .field("ipv4", &info.ipv4)
            .finish_non_exhaustive()
    }
}

/// Local IPv4 unicast addresses (non-loopback) paired with the mesh UDP port:
/// the LAN candidates advertised to peers (Tailscale `netmon` interface walk).
/// When bound to one specific address, only that address is advertised.
#[must_use]
pub fn local_ipv4_candidates(bind_ip: IpAddr, port: u16) -> Vec<SocketAddr> {
    if let IpAddr::V4(ip) = bind_ip
        && !ip.is_unspecified()
    {
        return vec![SocketAddr::new(IpAddr::V4(ip), port)];
    }
    let mut out = Vec::new();
    if let Ok(interfaces) = if_addrs::get_if_addrs() {
        for interface in interfaces {
            if let IpAddr::V4(ip) = interface.ip()
                && !ip.is_loopback()
                && !ip.is_link_local()
                && !ip.is_unspecified()
                && !is_mesh_address(ip)
            {
                let addr = SocketAddr::new(IpAddr::V4(ip), port);
                if !out.contains(&addr) {
                    out.push(addr);
                }
            }
        }
    }
    out
}

/// Whether `ip` lies in the mesh range (`100.64.0.0/10`), which must never be
/// advertised as a direct candidate.
#[must_use]
pub fn is_mesh_address(ip: Ipv4Addr) -> bool {
    let [a, b, _, _] = ip.octets();
    a == 100 && (64..128).contains(&b)
}

async fn resolve_stun_servers(relays: &[omegadesk_control::RelayGrant]) -> Vec<SocketAddr> {
    let mut out = Vec::new();
    for relay in relays {
        let Some(stun) = &relay.stun_address else {
            continue;
        };
        let lookup = tokio::time::timeout(Duration::from_secs(5), tokio::net::lookup_host(stun));
        if let Ok(Ok(addrs)) = lookup.await {
            for addr in addrs.filter(SocketAddr::is_ipv4) {
                if !out.contains(&addr) {
                    out.push(addr);
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mesh_range_is_never_a_candidate() {
        assert!(is_mesh_address(Ipv4Addr::new(100, 64, 0, 1)));
        assert!(is_mesh_address(Ipv4Addr::new(100, 127, 255, 254)));
        assert!(!is_mesh_address(Ipv4Addr::new(100, 128, 0, 1)));
        assert!(!is_mesh_address(Ipv4Addr::new(192, 168, 1, 10)));
    }

    #[test]
    fn specific_bind_address_is_the_only_candidate() {
        let candidates = local_ipv4_candidates(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)), 4242);
        assert_eq!(candidates, vec!["192.168.1.10:4242".parse().unwrap()]);
        for candidate in local_ipv4_candidates(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 1) {
            assert!(!candidate.ip().is_loopback());
        }
    }
}
