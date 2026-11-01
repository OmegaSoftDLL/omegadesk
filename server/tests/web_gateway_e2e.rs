//! End to end: a browser-side `WebSocket` client reaches an agent through the web
//! gateway over the mesh.
//!
//! Everything runs in-process on loopback: coordinator, relay, an agent node that
//! speaks the real protobuf session protocol (`Hello` / `HelloAck`, video
//! unidirectional stream, control stream), the gateway node and the HTTP front door.
//! The browser is a `tokio-tungstenite` client exchanging the same JSON and binary
//! frames `web/src/*.ts` does.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    clippy::wildcard_enum_match_arm,
    clippy::match_wildcard_for_single_variants,
    reason = "integration test"
)]

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use omegadesk_control::ControlConfig;
use omegadesk_identity::DeviceIdentity;
use omegadesk_magicsock::{Node, NodeConfig};
use omegadesk_protocol::PROTOCOL_VERSION;
use omegadesk_protocol::v1::{
    Capabilities, Envelope, Error as ProtocolError, ErrorCode, HelloAck, Pong, VideoCodec,
    VideoFrame, envelope::Payload,
};
use omegadesk_relay::RelayRouter;
use omegadesk_relay::service::{serve_relay, serve_stun};
use omegadesk_server::control_server;
use omegadesk_server::web_gateway::{
    CONTENT_SECURITY_POLICY, WebServerMessage, pack_web_frame_ack, parse_web_video_frame,
};
use omegadesk_server::web_server::{WebGatewayConfig, WebState};
use omegadesk_server::web_session::{GatewayIdentity, MeshDialer};
use omegadesk_server::{Coordinator, RelayNode};
use omegadesk_transport::{EnvelopeReader, send_envelope};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::{self, Message};

const PASSWORD: &str = "correct horse";
const KEYFRAME: [u8; 8] = [0x00, 0x00, 0x00, 0x01, 0x65, 0xDE, 0xAD, 0xBE];
const DELTA: [u8; 6] = [0x00, 0x00, 0x00, 0x01, 0x41, 0xEF];
const TIMEOUT: Duration = Duration::from_secs(20);

/// What the in-test agent observed on its control stream.
#[derive(Debug)]
enum AgentEvent {
    Hello {
        device_name: String,
        password: String,
    },
    Control(Payload),
}

struct Harness {
    web_addr: SocketAddr,
    agent_events: mpsc::UnboundedReceiver<AgentEvent>,
    nodes: Vec<Node>,
    _web_root: tempfile::TempDir,
}

async fn harness() -> Harness {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "omegadesk=debug".into()),
        )
        .with_test_writer()
        .try_init();
    let secret = [0x5a; 32];

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
    let agent_key = coord
        .create_preauth_key("acme", true, false, vec!["tag:agent".into()], None)
        .unwrap();
    // The gateway's own key, as `omegadesk-server --web-listen` issues it.
    let gateway_key = coord
        .create_preauth_key("acme", true, false, vec!["tag:web-gateway".into()], None)
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let control_addr = listener.local_addr().unwrap();
    let server_public = server_id.public();
    tokio::spawn(control_server::serve(
        listener,
        server_id,
        Arc::new(Mutex::new(coord)),
    ));

    let start_node = |hostname: &str, preauth_key: String| {
        let hostname = hostname.to_owned();
        async move {
            let mut config = NodeConfig::new(ControlConfig {
                server_addr: control_addr.to_string(),
                server_public,
                preauth_key,
                hostname,
                endpoints: Vec::new(),
                quicksupport_id: None,
            });
            config.bind = "127.0.0.1:0".parse().unwrap();
            Node::start(Arc::new(DeviceIdentity::generate()), config)
                .await
                .unwrap()
        }
    };

    let agent = start_node("office-pc", agent_key).await;
    let (events_tx, agent_events) = mpsc::unbounded_channel();
    tokio::spawn(fake_agent(
        agent.endpoint().clone(),
        agent.self_info().public.signing_key_bytes(),
        events_tx,
    ));

    let gateway = start_node("web-gateway", gateway_key).await;
    let gateway_key_bytes = gateway.self_info().public.signing_key_bytes();

    let web_root = tempfile::tempdir().unwrap();
    std::fs::write(
        web_root.path().join("index.html"),
        "<!doctype html><title>OmegaDesk</title>",
    )
    .unwrap();
    std::fs::write(web_root.path().join("main.js"), "export {};").unwrap();
    let mut config = WebGatewayConfig::new(HashSet::from(["127.0.0.1".to_owned()]));
    config.web_root = Some(web_root.path().to_path_buf());
    let dialer =
        Arc::new(MeshDialer::new(Arc::new(gateway)).with_netmap_wait(Duration::from_secs(3)));
    let state = WebState::new(
        config,
        dialer,
        GatewayIdentity {
            device_public_key: gateway_key_bytes,
            device_name: "omegadesk-web".to_owned(),
        },
    );
    let web_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let web_addr = web_listener.local_addr().unwrap();
    tokio::spawn(omegadesk_server::web_server::serve(web_listener, state));

    Harness {
        web_addr,
        agent_events,
        nodes: vec![agent],
        _web_root: web_root,
    }
}

/// Minimal agent: the handshake of `agent/src/session.rs` and a scripted video
/// stream, reporting every control message it receives.
async fn fake_agent(
    endpoint: omegadesk_transport::Endpoint,
    device_public_key: [u8; 32],
    events: mpsc::UnboundedSender<AgentEvent>,
) {
    while let Some(incoming) = endpoint.accept().await {
        let Ok(connection) = incoming.await else {
            continue;
        };
        let (mut control_send, control_recv) = connection.accept_bi().await.unwrap();
        let mut control = EnvelopeReader::new(control_recv);
        let Some(Envelope {
            payload: Some(Payload::Hello(hello)),
        }) = control.next().await.unwrap()
        else {
            panic!("client did not start with Hello");
        };
        assert_eq!(hello.protocol_version, PROTOCOL_VERSION);
        assert_eq!(hello.device_public_key.len(), 32);
        events
            .send(AgentEvent::Hello {
                device_name: hello.device_name.clone(),
                password: hello.access_password.clone(),
            })
            .unwrap();
        if hello.access_password != PASSWORD {
            send_envelope(
                &mut control_send,
                &Envelope {
                    payload: Some(Payload::Error(ProtocolError {
                        code: ErrorCode::Unauthorized as i32,
                        message: "invalid password".to_owned(),
                    })),
                },
            )
            .await
            .unwrap();
            let _ = control_send.finish();
            let _ = tokio::time::timeout(Duration::from_secs(2), connection.closed()).await;
            connection.close(1u32.into(), b"rejected");
            continue;
        }
        send_envelope(
            &mut control_send,
            &Envelope {
                payload: Some(Payload::HelloAck(HelloAck {
                    protocol_version: PROTOCOL_VERSION,
                    device_public_key: device_public_key.to_vec().into(),
                    device_name: "office-pc".to_owned(),
                    capabilities: Some(Capabilities {
                        decoders: Vec::new(),
                        encoders: vec![VideoCodec::H264 as i32],
                    }),
                    selected_codec: VideoCodec::H264 as i32,
                })),
            },
        )
        .await
        .unwrap();

        let mut video = connection.open_uni().await.unwrap();
        let mut sequence = 0u64;
        let mut send_frame = |keyframe: bool| {
            sequence += 1;
            let data: Vec<u8> = if keyframe {
                KEYFRAME.to_vec()
            } else {
                DELTA.to_vec()
            };
            Envelope {
                payload: Some(Payload::VideoFrame(VideoFrame {
                    sequence,
                    captured_at_micros: 1_000_000 * sequence,
                    host_processing_micros: 4_200,
                    codec: VideoCodec::H264 as i32,
                    keyframe,
                    display_index: 0,
                    width: 640,
                    height: 360,
                    data: data.into(),
                })),
            }
        };
        send_envelope(&mut video, &send_frame(true)).await.unwrap();
        send_envelope(&mut video, &send_frame(false)).await.unwrap();

        while let Ok(Some(envelope)) = control.next().await {
            match envelope.payload {
                Some(Payload::Ping(ping)) => {
                    send_envelope(
                        &mut control_send,
                        &Envelope {
                            payload: Some(Payload::Pong(Pong {
                                sequence: ping.sequence,
                                ping_sent_at_micros: ping.sent_at_micros,
                            })),
                        },
                    )
                    .await
                    .unwrap();
                }
                Some(payload) => {
                    let keyframe = matches!(payload, Payload::RequestKeyframe(_));
                    events.send(AgentEvent::Control(payload)).unwrap();
                    if keyframe {
                        send_envelope(&mut video, &send_frame(true)).await.unwrap();
                    }
                }
                None => {}
            }
        }
    }
}

type WsClient =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn connect_ws(
    addr: SocketAddr,
    origin: Option<&str>,
) -> Result<WsClient, tungstenite::Error> {
    let mut request = format!("ws://{addr}/ws").into_client_request()?;
    if let Some(origin) = origin {
        request
            .headers_mut()
            .insert("Origin", HeaderValue::from_str(origin).unwrap());
    }
    let (socket, _) = tokio::time::timeout(TIMEOUT, tokio_tungstenite::connect_async(request))
        .await
        .expect("websocket connect timed out")?;
    Ok(socket)
}

async fn next_message(ws: &mut WsClient) -> Message {
    tokio::time::timeout(TIMEOUT, ws.next())
        .await
        .expect("websocket read timed out")
        .expect("websocket closed")
        .expect("websocket error")
}

/// Next JSON message, skipping periodic `stats` and `pong` chatter.
async fn next_server_message(ws: &mut WsClient) -> WebServerMessage {
    loop {
        match next_message(ws).await {
            Message::Text(text) => {
                let message: WebServerMessage = serde_json::from_str(text.as_str()).unwrap();
                if matches!(message, WebServerMessage::Stats { .. }) {
                    continue;
                }
                return message;
            }
            other => panic!("expected a text message, got {other:?}"),
        }
    }
}

/// Next binary video frame, skipping text chatter.
async fn next_video_frame(ws: &mut WsClient) -> (u16, bool, u64, Vec<u8>) {
    loop {
        match next_message(ws).await {
            Message::Binary(bytes) => {
                let (header, payload) = parse_web_video_frame(&bytes).unwrap();
                return (
                    header.frame_id,
                    header.keyframe,
                    header.timestamp_us,
                    payload.to_vec(),
                );
            }
            Message::Text(text) => {
                let message: WebServerMessage = serde_json::from_str(text.as_str()).unwrap();
                assert!(
                    matches!(message, WebServerMessage::Stats { .. }),
                    "unexpected {message:?}"
                );
            }
            other => panic!("expected a binary frame, got {other:?}"),
        }
    }
}

async fn next_agent_event(events: &mut mpsc::UnboundedReceiver<AgentEvent>) -> AgentEvent {
    tokio::time::timeout(TIMEOUT, events.recv())
        .await
        .expect("agent event timed out")
        .expect("agent gone")
}

async fn http_get(addr: SocketAddr, path: &str, host: &str) -> (u16, String, String) {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(
            format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes(),
        )
        .await
        .unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    let response = String::from_utf8(response).unwrap();
    let (head, body) = response.split_once("\r\n\r\n").unwrap();
    let status: u16 = head
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap();
    (status, head.to_owned(), body.to_owned())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn browser_hello_reaches_the_agent_and_video_flows_back() {
    let mut harness = harness().await;
    let addr = harness.web_addr;
    let origin = format!("http://{addr}");

    // The static client is served with the strict security headers.
    let (status, head, body) = http_get(addr, "/", &addr.to_string()).await;
    assert_eq!(status, 200, "{head}");
    assert!(body.contains("OmegaDesk"));
    assert!(head.contains(CONTENT_SECURITY_POLICY));
    assert!(head.to_ascii_lowercase().contains("x-frame-options: deny"));
    let (status, head, _) = http_get(addr, "/main.js", &addr.to_string()).await;
    assert_eq!(status, 200);
    assert!(head.contains("text/javascript"));
    let (status, _, _) = http_get(addr, "/../Cargo.toml", &addr.to_string()).await;
    assert_eq!(status, 404);

    let mut ws = connect_ws(addr, Some(&origin)).await.unwrap();
    ws.send(Message::text(
        r#"{"type":"connect","agent":"office-pc","password":"correct horse"}"#,
    ))
    .await
    .unwrap();

    // The agent sees the browser's Hello with the typed password.
    match next_agent_event(&mut harness.agent_events).await {
        AgentEvent::Hello {
            device_name,
            password,
        } => {
            assert!(device_name.starts_with("omegadesk-web"), "{device_name}");
            assert_eq!(password, PASSWORD);
        }
        other => panic!("expected Hello, got {other:?}"),
    }
    assert_eq!(
        next_server_message(&mut ws).await,
        WebServerMessage::Connected {
            agent: "office-pc".to_owned(),
            device_id: harness.nodes[0].self_info().id().to_string(),
        }
    );
    assert_eq!(
        next_server_message(&mut ws).await,
        WebServerMessage::VideoConfig {
            codec: "avc1.42001f".to_owned(),
            width: 640,
            height: 360,
        }
    );

    // Video: keyframe then delta, framed as omegadesk-web-video/1.
    let (id, keyframe, timestamp, payload) = next_video_frame(&mut ws).await;
    assert_eq!((id, keyframe, timestamp), (0, true, 1_000_000));
    assert_eq!(payload, KEYFRAME);
    let (id, keyframe, timestamp, payload) = next_video_frame(&mut ws).await;
    assert_eq!((id, keyframe, timestamp), (1, false, 2_000_000));
    assert_eq!(payload, DELTA);
    for id in [0u16, 1] {
        ws.send(Message::binary(pack_web_frame_ack(id, 7).to_vec()))
            .await
            .unwrap();
    }

    // Keyboard and pointer reach the agent as protobuf events.
    ws.send(Message::text(
        r#"{"type":"key","code":"KeyA","key":"a","pressed":true,"modifiers":1}"#,
    ))
    .await
    .unwrap();
    match next_agent_event(&mut harness.agent_events).await {
        AgentEvent::Control(Payload::KeyEvent(key)) => {
            assert_eq!(key.hid_usage, 0x04);
            assert_eq!(key.keysym, u32::from(b'a'));
            assert!(key.pressed);
            assert_eq!(key.modifiers, 1);
        }
        other => panic!("expected KeyEvent, got {other:?}"),
    }
    ws.send(Message::text(
        r#"{"type":"pointer","x":32768,"y":100,"buttons":1,"wheel_y":-120}"#,
    ))
    .await
    .unwrap();
    match next_agent_event(&mut harness.agent_events).await {
        AgentEvent::Control(Payload::PointerEvent(pointer)) => {
            assert_eq!((pointer.x, pointer.y), (32768, 100));
            assert_eq!(pointer.buttons, 1);
            assert_eq!(pointer.wheel_y, -120);
        }
        other => panic!("expected PointerEvent, got {other:?}"),
    }

    // A keyframe request from the worker reaches the agent, which answers with an IDR.
    ws.send(Message::text(
        r#"{"type":"request-keyframe","reason":"decode-queue-overflow"}"#,
    ))
    .await
    .unwrap();
    match next_agent_event(&mut harness.agent_events).await {
        AgentEvent::Control(Payload::RequestKeyframe(_)) => {}
        other => panic!("expected RequestKeyframe, got {other:?}"),
    }
    let (id, keyframe, _, payload) = next_video_frame(&mut ws).await;
    assert_eq!((id, keyframe), (2, true));
    assert_eq!(payload, KEYFRAME);

    // Browser round trip and statistics.
    ws.send(Message::text(r#"{"type":"ping","sent_at_ms":1234.5}"#))
        .await
        .unwrap();
    assert_eq!(
        next_server_message(&mut ws).await,
        WebServerMessage::Pong { sent_at_ms: 1234.5 }
    );
    let stats = loop {
        if let Message::Text(text) = next_message(&mut ws).await
            && let Ok(message @ WebServerMessage::Stats { .. }) =
                serde_json::from_str::<WebServerMessage>(text.as_str())
        {
            break message;
        }
    };
    let WebServerMessage::Stats {
        frames_sent,
        host_processing_ms,
        in_flight,
        ..
    } = stats
    else {
        unreachable!()
    };
    assert_eq!(frames_sent, 3);
    assert_eq!(host_processing_ms, 4);
    assert_eq!(in_flight, 1, "frame 2 was never acknowledged");

    ws.close(None).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rejections_reach_the_browser_or_never_upgrade() {
    let mut harness = harness().await;
    let addr = harness.web_addr;
    let origin = format!("http://{addr}");

    // Wrong password: the agent's rejection is relayed and the socket closes.
    let mut ws = connect_ws(addr, Some(&origin)).await.unwrap();
    ws.send(Message::text(
        r#"{"type":"connect","agent":"office-pc.omega","password":"wrong"}"#,
    ))
    .await
    .unwrap();
    assert!(matches!(
        next_agent_event(&mut harness.agent_events).await,
        AgentEvent::Hello { password, .. } if password == "wrong"
    ));
    match next_server_message(&mut ws).await {
        WebServerMessage::Error { message } => {
            assert!(message.contains("invalid password"), "{message}");
        }
        other => panic!("expected error, got {other:?}"),
    }
    assert!(matches!(next_message(&mut ws).await, Message::Close(_)));

    // Unknown agent.
    let mut ws = connect_ws(addr, Some(&origin)).await.unwrap();
    ws.send(Message::text(
        r#"{"type":"connect","agent":"nobody","password":"x"}"#,
    ))
    .await
    .unwrap();
    match next_server_message(&mut ws).await {
        WebServerMessage::Error { message } => assert!(message.contains("nobody"), "{message}"),
        other => panic!("expected error, got {other:?}"),
    }

    // Malformed first message.
    let mut ws = connect_ws(addr, Some(&origin)).await.unwrap();
    ws.send(Message::text(
        r#"{"type":"key","code":"KeyA","key":"a","pressed":true}"#,
    ))
    .await
    .unwrap();
    match next_server_message(&mut ws).await {
        WebServerMessage::Error { message } => {
            assert!(message.contains("expected connect"), "{message}");
        }
        other => panic!("expected error, got {other:?}"),
    }

    // Origin checks happen before the upgrade: cross-origin and missing Origin get 403.
    for origin in [Some("http://evil.example"), Some("https://127.0.0.1"), None] {
        match connect_ws(addr, origin).await {
            Err(tungstenite::Error::Http(response)) => assert_eq!(response.status(), 403),
            other => panic!("origin {origin:?} must be rejected, got {other:?}"),
        }
    }
    // A Host outside the allow-list never reaches the router.
    let (status, _, _) = http_get(addr, "/", "attacker.example").await;
    assert_eq!(status, 403);
}
