//! End-to-end QuickSupport: coordinator + relay + a QuickSupport host + a
//! technician's node, all in-process on loopback.
//!
//! Proves the ID registry (lookup through the coordinator and through the
//! netmap, tenant scope, expiry when the host leaves), the QUIC connection to
//! the host over the mesh, and the session handshake the agent code runs on
//! top of it: wrong temporary password rejected and counted, consent gate
//! consulted after the password check, right password accepted. The screen
//! pipeline itself is exercised only on Windows (the capture thread retries
//! quietly elsewhere), so this test stays green on every CI platform.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "integration test"
)]

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use omegadesk_agent::capture_loop::EncoderChoice;
use omegadesk_agent::session::{PeerDescriptor, SessionGate};
use omegadesk_codec::EncoderSettings;
use omegadesk_control::ControlConfig;
use omegadesk_identity::{DeviceIdentity, QuickSupportId};
use omegadesk_magicsock::{Node, NodeConfig, NodeError};
use omegadesk_protocol::PROTOCOL_VERSION;
use omegadesk_protocol::v1::{Capabilities, Envelope, Hello, VideoCodec, envelope::Payload};
use omegadesk_quicksupport::host::{HostConfig, QuickSupportHost, SessionOutcome};
use omegadesk_quicksupport::{ClientPermissions, MAX_CONSECUTIVE_FAILURES};
use omegadesk_relay::RelayRouter;
use omegadesk_relay::service::{serve_relay, serve_stun};
use omegadesk_server::control_server;
use omegadesk_server::{Coordinator, RelayNode};
use omegadesk_transport::{Connection, EnvelopeReader, send_envelope};
use tokio::net::{TcpListener, UdpSocket};
use tokio::task::JoinHandle;

struct Testbed {
    control: ControlConfig,
    /// Reusable ephemeral key of another tenant.
    other_tenant_key: String,
}

async fn testbed() -> Testbed {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "omegadesk=debug".into()),
        )
        .with_test_writer()
        .try_init();
    let secret = [0x3c; 32];

    let relay_id = DeviceIdentity::generate();
    let relay_key = relay_id.public().exchange_key_bytes();
    let router = Arc::new(Mutex::new(RelayRouter::new(relay_id, secret)));
    let relay_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_addr = relay_listener.local_addr().unwrap();
    tokio::spawn(serve_relay(relay_listener, router));
    let stun_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let stun_addr = stun_socket.local_addr().unwrap();
    tokio::spawn(serve_stun(stun_socket));

    let server_id = Arc::new(DeviceIdentity::generate());
    let mut coord = Coordinator::new(secret);
    coord.add_relay(RelayNode {
        address: relay_addr.to_string(),
        exchange_key: relay_key,
        stun_address: Some(stun_addr.to_string()),
    });
    let preauth_key = coord
        .create_preauth_key("acme", true, true, vec!["tag:quicksupport".into()], None)
        .unwrap();
    let other_tenant_key = coord
        .create_preauth_key("globex", true, true, vec![], None)
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
            quicksupport_id: None,
        },
        other_tenant_key,
    }
}

async fn start_host(testbed: &Testbed, name: &str) -> Arc<QuickSupportHost> {
    let mut control = testbed.control.clone();
    control.hostname = name.to_owned();
    let config = HostConfig {
        control,
        bind: "127.0.0.1:0".parse().unwrap(),
        relay_only: false,
        monitor: 0,
        encoder: EncoderChoice::Software,
        settings: EncoderSettings {
            bitrate_bps: 2_000_000,
            max_fps: 30.0,
        },
        permissions: ClientPermissions::DEFAULT.union(ClientPermissions::ALL_INPUTS),
        password_length: 6,
    };
    Arc::new(
        QuickSupportHost::join(Arc::new(DeviceIdentity::generate()), config)
            .await
            .unwrap(),
    )
}

async fn start_technician(testbed: &Testbed, name: &str, preauth_key: Option<&str>) -> Node {
    let mut control = testbed.control.clone();
    control.hostname = name.to_owned();
    if let Some(key) = preauth_key {
        control.preauth_key = key.to_owned();
    }
    let mut config = NodeConfig::new(control);
    config.bind = "127.0.0.1:0".parse().unwrap();
    Node::start(Arc::new(DeviceIdentity::generate()), config)
        .await
        .unwrap()
}

/// A consent gate that answers from a fixed decision and remembers who asked.
#[derive(Debug)]
struct ScriptedGate {
    accept: bool,
    asked: Mutex<Vec<PeerDescriptor>>,
}

impl ScriptedGate {
    fn new(accept: bool) -> Arc<Self> {
        Arc::new(Self {
            accept,
            asked: Mutex::new(Vec::new()),
        })
    }

    fn asked(&self) -> Vec<PeerDescriptor> {
        self.asked.lock().unwrap().clone()
    }
}

impl SessionGate for ScriptedGate {
    fn authorize<'a>(
        &'a self,
        peer: &'a PeerDescriptor,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            self.asked.lock().unwrap().push(peer.clone());
            if self.accept {
                Ok(())
            } else {
                Err("the user declined the session".to_owned())
            }
        })
    }
}

/// Serves the next connection of `host` on a task.
fn serve_once(
    host: &Arc<QuickSupportHost>,
    gate: &Arc<ScriptedGate>,
) -> JoinHandle<SessionOutcome> {
    let host = Arc::clone(host);
    let gate = Arc::clone(gate);
    tokio::spawn(async move { host.serve_one(gate).await.unwrap() })
}

async fn outcome(serving: JoinHandle<SessionOutcome>) -> SessionOutcome {
    tokio::time::timeout(Duration::from_secs(15), serving)
        .await
        .expect("session did not end")
        .unwrap()
}

async fn connect(tech: &Node, id: QuickSupportId) -> Connection {
    tokio::time::timeout(Duration::from_secs(20), tech.connect_quicksupport(id))
        .await
        .expect("connect timed out")
        .unwrap()
}

/// Runs the technician's half of the handshake and returns the host's reply.
async fn hello(connection: &Connection, password: &str) -> Envelope {
    let (mut send, recv) = connection.open_bi().await.unwrap();
    send_envelope(
        &mut send,
        &Envelope {
            payload: Some(Payload::Hello(Hello {
                protocol_version: PROTOCOL_VERSION,
                device_public_key: vec![7u8; 32].into(),
                device_name: "tech-client".to_owned(),
                capabilities: Some(Capabilities {
                    decoders: vec![VideoCodec::H264 as i32],
                    encoders: Vec::new(),
                }),
                access_password: password.to_owned(),
            })),
        },
    )
    .await
    .unwrap();
    let mut reader = EnvelopeReader::new(recv);
    tokio::time::timeout(Duration::from_secs(10), reader.next())
        .await
        .expect("host reply timed out")
        .unwrap()
        .expect("host closed the control stream")
}

fn error_message(reply: &Envelope) -> &str {
    match &reply.payload {
        Some(Payload::Error(error)) => &error.message,
        other => panic!("expected an Error reply, got {other:?}"),
    }
}

/// A password derived from `real` that is guaranteed not to equal it, so the
/// handshake rejects it. Derived at runtime rather than hard-coded, so it is
/// never a credential constant.
fn mismatch_of(real: &str) -> String {
    format!("{real}.")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn technician_resolves_the_id_within_the_tenant_and_it_expires_with_the_host() {
    let testbed = testbed().await;
    let host = start_host(&testbed, "Reception PC").await;
    let id = host.id();
    assert_eq!(id.digits().len(), 9);
    assert!(host.node().self_info().ephemeral);
    assert_eq!(host.password().len(), 6);

    // The technician enrolls afterwards and resolves the ID: the netmap
    // snapshot already carries the host, so the local path answers first...
    let tech = start_technician(&testbed, "tech", None).await;
    let peer = tech
        .lookup_quicksupport(id)
        .await
        .unwrap()
        .expect("the host owns the ID");
    assert_eq!(peer.id(), host.identity().id());
    assert_eq!(peer.hostname, "reception-pc");
    assert_eq!(peer.quicksupport_id, Some(id));
    // ...and an ID nobody holds is answered by the coordinator with `None`.
    let nobody = QuickSupportId::from_u32((id.as_u32() + 1) % 1_000_000_000).unwrap();
    assert_eq!(tech.lookup_quicksupport(nobody).await.unwrap(), None);
    let error = tech.connect_quicksupport(nobody).await.err().unwrap();
    assert!(matches!(error, NodeError::UnknownPeer(_)), "{error:?}");

    // Another tenant cannot see the ID at all.
    let outsider = start_technician(&testbed, "outsider", Some(&testbed.other_tenant_key)).await;
    assert_eq!(outsider.lookup_quicksupport(id).await.unwrap(), None);
    drop(outsider);

    // A QUIC connection reaches the host over the mesh (the host must be
    // accepting: QUIC handshakes complete only while a session is served).
    let gate = ScriptedGate::new(true);
    let serving = serve_once(&host, &gate);
    let connection = connect(&tech, id).await;
    assert_eq!(connection.remote_address(), host.node().virtual_addr());
    // Closing without a `Hello` ends that session as a failed handshake.
    connection.close(0u32.into(), b"done");
    let result = outcome(serving).await;
    assert!(matches!(result, SessionOutcome::Failed(_)), "{result:?}");
    assert_eq!(gate.asked(), Vec::<PeerDescriptor>::new());

    // The host leaves: the ID expires for the coordinator and in the netmap.
    drop(host);
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if tech.lookup_quicksupport(id).await.unwrap().is_none() {
            break;
        }
        assert!(Instant::now() < deadline, "the ID never expired");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(tech.resolve("reception-pc").is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn host_checks_the_password_then_asks_for_consent() {
    let testbed = testbed().await;
    let host = start_host(&testbed, "Reception PC").await;
    let id = host.id();
    let password = host.password();
    let tech = start_technician(&testbed, "tech", None).await;

    // Wrong password: rejected, counted, nobody is asked for consent.
    let gate = ScriptedGate::new(true);
    let serving = serve_once(&host, &gate);
    let connection = connect(&tech, id).await;
    let reply = hello(&connection, &mismatch_of(&password)).await;
    assert_eq!(error_message(&reply), "invalid password");
    let result = outcome(serving).await;
    assert!(
        matches!(result, SessionOutcome::WrongPassword { rotated: false }),
        "{result:?}"
    );
    assert_eq!(gate.asked(), Vec::<PeerDescriptor>::new());
    assert_eq!(host.password(), password, "one failure does not rotate");
    drop(connection);

    // Right password but the user declines: the technician learns why.
    let declining = ScriptedGate::new(false);
    let serving = serve_once(&host, &declining);
    let connection = connect(&tech, id).await;
    let reply = hello(&connection, &password).await;
    assert_eq!(error_message(&reply), "the user declined the session");
    let result = outcome(serving).await;
    assert!(matches!(result, SessionOutcome::Failed(_)), "{result:?}");
    assert_eq!(declining.asked().len(), 1);
    drop(connection);

    // Right password and consent: `HelloAck` carries the host's identity.
    let serving = serve_once(&host, &gate);
    let connection = connect(&tech, id).await;
    let reply = hello(&connection, &password).await;
    let Some(Payload::HelloAck(ack)) = reply.payload else {
        panic!("expected HelloAck, got {reply:?}");
    };
    assert_eq!(ack.device_name, "Reception PC");
    assert_eq!(
        ack.device_public_key.as_ref(),
        &host.identity().public().signing_key_bytes()
    );
    assert_eq!(ack.selected_codec, VideoCodec::H264 as i32);
    let asked = gate.asked();
    assert_eq!(asked.len(), 1);
    assert_eq!(asked[0].device_name, "tech-client");
    assert!(asked[0].device_id.is_some());
    // The video stream is opened by the host once the session is accepted.
    let _video = tokio::time::timeout(Duration::from_secs(10), connection.accept_uni())
        .await
        .expect("no video stream")
        .unwrap();
    connection.close(0u32.into(), b"done");
    let result = outcome(serving).await;
    assert!(
        matches!(result, SessionOutcome::Served { .. }),
        "{result:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ten_wrong_passwords_rotate_the_temporary_password() {
    let testbed = testbed().await;
    let host = start_host(&testbed, "kiosk").await;
    let id = host.id();
    let initial = host.password();
    let tech = start_technician(&testbed, "tech", None).await;
    let gate = ScriptedGate::new(true);
    // A value the password can never equal (its charset excludes '.'), so it
    // stays wrong across the rotation on the tenth attempt.
    let wrong = mismatch_of(&initial);

    for attempt in 1..=MAX_CONSECUTIVE_FAILURES {
        let serving = serve_once(&host, &gate);
        let connection = connect(&tech, id).await;
        let reply = hello(&connection, &wrong).await;
        assert_eq!(error_message(&reply), "invalid password");
        let result = outcome(serving).await;
        let expected_rotation = attempt == MAX_CONSECUTIVE_FAILURES;
        assert!(
            matches!(result, SessionOutcome::WrongPassword { rotated } if rotated == expected_rotation),
            "attempt {attempt}: {result:?}"
        );
        drop(connection);
    }
    assert_ne!(
        host.password(),
        initial,
        "the tenth failure rotated the password"
    );
    assert_eq!(gate.asked(), Vec::<PeerDescriptor>::new());
}
