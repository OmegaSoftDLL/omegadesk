//! End-to-end: coordinator + relay + two nodes, QUIC over the mesh.
//!
//! Everything runs in-process on loopback. The first test lets the nodes
//! discover each other directly (LAN candidates + STUN served by the relay);
//! the second forces the relay-only path and checks that QUIC still flows.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "integration test"
)]

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use omegadesk_control::ControlConfig;
use omegadesk_identity::DeviceIdentity;
use omegadesk_magicsock::{Node, NodeConfig};
use omegadesk_mesh::ConnectionPath;
use omegadesk_relay::RelayRouter;
use omegadesk_relay::service::{serve_relay, serve_stun};
use omegadesk_server::control_server;
use omegadesk_server::{Coordinator, RelayNode};
use tokio::net::{TcpListener, UdpSocket};

struct Testbed {
    control: ControlConfig,
}

async fn testbed() -> Testbed {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "omegadesk=debug".into()),
        )
        .with_test_writer()
        .try_init();
    let secret = [0x5a; 32];

    // Relay with STUN on loopback.
    let relay_id = DeviceIdentity::generate();
    let relay_key = relay_id.public().exchange_key_bytes();
    let router = Arc::new(Mutex::new(RelayRouter::new(relay_id, secret)));
    let relay_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_addr = relay_listener.local_addr().unwrap();
    tokio::spawn(serve_relay(relay_listener, router));
    let stun_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let stun_addr = stun_socket.local_addr().unwrap();
    tokio::spawn(serve_stun(stun_socket));

    // Coordinator.
    let server_id = Arc::new(DeviceIdentity::generate());
    let mut coord = Coordinator::new(secret);
    coord.add_relay(RelayNode {
        address: relay_addr.to_string(),
        exchange_key: relay_key,
        stun_address: Some(stun_addr.to_string()),
    });
    let preauth_key = coord
        .create_preauth_key("acme", true, false, vec!["tag:test".into()], None)
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let control_addr = listener.local_addr().unwrap();
    let server_public = server_id.public();
    tokio::spawn(control_server::serve(
        listener,
        server_id,
        Arc::new(Mutex::new(coord)),
    ));

    Testbed {
        control: ControlConfig {
            server_addr: control_addr.to_string(),
            server_public,
            preauth_key,
            hostname: String::new(),
            endpoints: Vec::new(),
        },
    }
}

async fn start_node(testbed: &Testbed, hostname: &str, relay_only: bool) -> Node {
    let identity = Arc::new(DeviceIdentity::generate());
    let mut control = testbed.control.clone();
    control.hostname = hostname.to_owned();
    let mut config = NodeConfig::new(control);
    // Loopback only: the LAN candidates of this machine are not needed and a
    // firewall could make them flaky in CI.
    config.bind = "127.0.0.1:0".parse().unwrap();
    config.relay_only = relay_only;
    Node::start(identity, config).await.unwrap()
}

async fn wait_for_peer(node: &Node, name: &str) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while node.resolve(name).is_none() {
        assert!(
            Instant::now() < deadline,
            "{name} never appeared in the netmap"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Opens a bidirectional stream from `client` to `server`, sends `payload`
/// and expects the uppercase echo.
async fn echo_round_trip(client: &Node, server: &Node, payload: &[u8]) -> ConnectionPath {
    let server_endpoint = server.endpoint().clone();
    let server_task = tokio::spawn(async move {
        let incoming = server_endpoint.accept().await.unwrap();
        let connection = incoming.await.unwrap();
        let (mut send, mut recv) = connection.accept_bi().await.unwrap();
        let mut buf = Vec::new();
        recv.read_to_end(1024 * 1024)
            .await
            .map(|b| buf = b)
            .unwrap();
        let upper: Vec<u8> = buf.iter().map(u8::to_ascii_uppercase).collect();
        send.write_all(&upper).await.unwrap();
        send.finish().unwrap();
        // Keep the connection alive until the client has read the echo:
        // dropping the last handle closes it immediately.
        send.stopped().await.ok();
        (connection.remote_address(), connection)
    });

    let target = server.self_info().fqdn.clone();
    let connection = tokio::time::timeout(Duration::from_secs(20), client.connect(&target))
        .await
        .expect("connect timed out")
        .unwrap();
    assert_eq!(connection.remote_address(), server.virtual_addr());
    let (mut send, mut recv) = connection.open_bi().await.unwrap();
    send.write_all(payload).await.unwrap();
    send.finish().unwrap();
    let echoed = recv.read_to_end(1024 * 1024).await.unwrap();
    let expected: Vec<u8> = payload.iter().map(u8::to_ascii_uppercase).collect();
    assert_eq!(echoed.len(), expected.len());
    assert!(echoed == expected, "echoed payload differs");
    connection.close(0u32.into(), b"done");
    let (seen_from, server_connection) = server_task.await.unwrap();
    assert_eq!(seen_from, client.virtual_addr());
    drop(server_connection);
    client
        .peer_path(server.self_info().id())
        .expect("server is a known peer")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn quic_flows_over_the_mesh_and_upgrades_to_a_direct_path() {
    let testbed = testbed().await;
    let alice = start_node(&testbed, "Alice Desk", false).await;
    let bob = start_node(&testbed, "Bob Laptop", false).await;
    assert_eq!(alice.self_info().fqdn, "alice-desk.omega");
    wait_for_peer(&bob, "alice-desk.omega").await;
    wait_for_peer(&alice, "bob-laptop").await;
    assert_eq!(
        bob.resolve(&alice.self_info().ipv4.to_string())
            .map(|p| p.fqdn),
        Some("alice-desk.omega".to_owned())
    );

    let payload = vec![b'x'; 200 * 1024];
    echo_round_trip(&bob, &alice, &payload).await;

    // On loopback the disco exchange validates a direct candidate quickly.
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let path = bob.peer_path(alice.self_info().id());
        if matches!(path, Some(ConnectionPath::Direct { .. })) {
            break;
        }
        assert!(Instant::now() < deadline, "no direct path: {path:?}");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    // A second round trip rides the direct path.
    let path = echo_round_trip(&bob, &alice, b"second session").await;
    assert!(matches!(path, ConnectionPath::Direct { .. }), "{path:?}");
    assert_eq!(
        bob.socket()
            .stats()
            .rejected_rx
            .load(std::sync::atomic::Ordering::Relaxed),
        0
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn relay_only_nodes_still_carry_quic() {
    let testbed = testbed().await;
    let alice = start_node(&testbed, "agent", true).await;
    let bob = start_node(&testbed, "viewer", true).await;
    wait_for_peer(&bob, "agent").await;
    wait_for_peer(&alice, "viewer").await;

    let path = echo_round_trip(&bob, &alice, b"through the relay").await;
    assert!(matches!(path, ConnectionPath::Relayed { .. }), "{path:?}");
    // The relay-only nodes advertise no endpoints at all.
    assert_eq!(bob.resolve("agent").unwrap().endpoints.len(), 0);

    // Unknown names are rejected before any network activity.
    let error = bob.connect("nobody.omega").await.err().unwrap();
    assert!(matches!(
        error,
        omegadesk_magicsock::NodeError::UnknownPeer(_)
    ));
    let _: SocketAddr = bob.virtual_addr();
}
