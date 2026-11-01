//! Loopback test of the RDP bridge against IronRDP's own server (`ironrdp-server`).
//!
//! The server runs in-process with TLS + CredSSP (`Hybrid` security, the Windows default)
//! and a static credential validator; the bridge connects through the real
//! `[MS-RDPBCGR]` connection sequence, receives a bitmap update and delivers it as an
//! OmegaDesk capture frame, and forwards fast-path mouse input back to the server.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "integration test"
)]

use std::num::{NonZeroU16, NonZeroUsize};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use ironrdp_server::{
    BitmapUpdate, Credentials, DesktopSize, DisplayUpdate, ExactMatchCredentialValidator,
    KeyboardEvent, MouseEvent, PixelFormat, RdpServer, RdpServerDisplay, RdpServerDisplayUpdates,
    RdpServerInputHandler,
};
use omegadesk_capture::Capturer;
use omegadesk_rdp::bridge::{PointerFlags, mouse_button, mouse_move};
use omegadesk_rdp::tls::{certificate_sha256, subject_public_key};
use omegadesk_rdp::{
    CertificatePolicy, RdpBridge, RdpBridgeConfig, RdpBridgeError, RdpDesktopSize,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_rustls::TlsAcceptor;

const WIDTH: u16 = 320;
const HEIGHT: u16 = 240;
const USERNAME: &str = "omega";
const PASSWORD: &str = "correct horse battery staple";
/// Solid BGRA color of the test bitmap.
const COLOR: [u8; 4] = [0x40, 0x80, 0xC0, 0xFF];

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "omegadesk=debug,ironrdp=info".into()),
        )
        .with_test_writer()
        .try_init();
}

struct TestDisplay {
    updates: Option<mpsc::Receiver<DisplayUpdate>>,
}

struct TestUpdates {
    updates: mpsc::Receiver<DisplayUpdate>,
}

#[async_trait::async_trait]
impl RdpServerDisplayUpdates for TestUpdates {
    async fn next_update(&mut self) -> anyhow::Result<Option<DisplayUpdate>> {
        Ok(self.updates.recv().await)
    }
}

#[async_trait::async_trait]
impl RdpServerDisplay for TestDisplay {
    async fn size(&mut self) -> DesktopSize {
        DesktopSize {
            width: WIDTH,
            height: HEIGHT,
        }
    }

    async fn updates(&mut self) -> anyhow::Result<Box<dyn RdpServerDisplayUpdates>> {
        let updates = self
            .updates
            .take()
            .ok_or_else(|| anyhow::anyhow!("display updates already taken"))?;
        Ok(Box::new(TestUpdates { updates }))
    }
}

struct TestInput {
    events: mpsc::UnboundedSender<MouseEvent>,
}

impl RdpServerInputHandler for TestInput {
    fn keyboard(&mut self, _event: KeyboardEvent) {}

    fn mouse(&mut self, event: MouseEvent) {
        let _ = self.events.send(event);
    }
}

struct Server {
    addr: std::net::SocketAddr,
    certificate_sha256: [u8; 32],
    display: mpsc::Sender<DisplayUpdate>,
    mouse: mpsc::UnboundedReceiver<MouseEvent>,
    /// Result of `RdpServer::run_connection`, delivered when the connection ends.
    done: std::sync::mpsc::Receiver<anyhow::Result<()>>,
}

/// Starts an `ironrdp-server` on loopback with a fresh self-signed certificate and serves
/// exactly one connection (`RdpServer::run_connection`).
///
/// `ironrdp-server` keeps `Rc` state across await points, so it runs on its own
/// current-thread runtime instead of the test's multi-thread runtime.
fn start_server() -> Server {
    init_tracing();
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let certificate: CertificateDer<'static> = certified.cert.der().clone();
    let certificate_sha256 = certificate_sha256(&certificate);
    let public_key = subject_public_key(&certificate).unwrap();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        certified.signing_key.serialize_der(),
    ));
    let tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![certificate], key)
    .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(tls));

    let std_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    std_listener.set_nonblocking(true).unwrap();
    let addr = std_listener.local_addr().unwrap();
    let (display_tx, display_rx) = mpsc::channel(8);
    let (mouse_tx, mouse_rx) = mpsc::unbounded_channel();
    let (done_tx, done_rx) = std::sync::mpsc::channel();

    std::thread::Builder::new()
        .name("ironrdp-server".to_owned())
        .spawn(move || {
            let result = (|| -> anyhow::Result<()> {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()?;
                runtime.block_on(async move {
                    let mut server = RdpServer::builder()
                        .with_addr(addr)
                        .with_hybrid(acceptor, public_key)
                        .with_input_handler(TestInput { events: mouse_tx })
                        .with_display_handler(TestDisplay {
                            updates: Some(display_rx),
                        })
                        .with_credential_validator(Some(Arc::new(
                            ExactMatchCredentialValidator::new(Credentials {
                                username: USERNAME.to_owned(),
                                password: PASSWORD.to_owned(),
                                domain: None,
                            }),
                        )))
                        .build();
                    // The CredSSP acceptor authenticates NTLM against these credentials;
                    // the validator above is the policy check IronRDP runs afterwards.
                    server.set_credentials(Some(Credentials {
                        username: USERNAME.to_owned(),
                        password: PASSWORD.to_owned(),
                        domain: None,
                    }));
                    let listener = TcpListener::from_std(std_listener)?;
                    let (stream, _) = listener.accept().await?;
                    server.run_connection(stream).await
                })
            })();
            let _ = done_tx.send(result);
        })
        .unwrap();

    Server {
        addr,
        certificate_sha256,
        display: display_tx,
        mouse: mouse_rx,
        done: done_rx,
    }
}

fn bridge_config(server: &Server, policy: CertificatePolicy) -> RdpBridgeConfig {
    let mut config = RdpBridgeConfig::new(server.addr.to_string(), USERNAME, PASSWORD);
    "localhost".clone_into(&mut config.server_name);
    config.desktop_size = RdpDesktopSize {
        width: WIDTH,
        height: HEIGHT,
    };
    config.certificate = policy;
    config.connect_timeout = Duration::from_secs(30);
    config
}

fn solid_bitmap() -> DisplayUpdate {
    let mut data = Vec::with_capacity(usize::from(WIDTH) * usize::from(HEIGHT) * 4);
    for _ in 0..u32::from(WIDTH) * u32::from(HEIGHT) {
        data.extend_from_slice(&COLOR);
    }
    DisplayUpdate::Bitmap(BitmapUpdate {
        x: 0,
        y: 0,
        width: NonZeroU16::new(WIDTH).unwrap(),
        height: NonZeroU16::new(HEIGHT).unwrap(),
        format: PixelFormat::BgrA32,
        data: Bytes::from(data),
        stride: NonZeroUsize::new(usize::from(WIDTH) * 4).unwrap(),
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bridge_streams_an_ironrdp_server_framebuffer_and_forwards_input() {
    let mut server = start_server();

    let mut bridge = RdpBridge::connect(bridge_config(
        &server,
        CertificatePolicy::Pinned(server.certificate_sha256),
    ))
    .await
    .expect("connection sequence with TLS + CredSSP against ironrdp-server");
    assert_eq!(
        bridge.server_certificate_sha256(),
        server.certificate_sha256
    );
    assert_eq!(bridge.desktop_size().width, WIDTH);
    assert_eq!(bridge.desktop_size().height, HEIGHT);
    assert!(bridge.is_connected());

    let mut capturer = bridge.take_capturer().expect("capturer available once");
    assert!(bridge.take_capturer().is_none());
    assert_eq!(capturer.size(), (u32::from(WIDTH), u32::from(HEIGHT)));

    server.display.send(solid_bitmap()).await.unwrap();

    // The capturer is a blocking `Capturer`; poll it off the runtime like the agent does.
    let frame = tokio::task::spawn_blocking(move || {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            let frame = capturer
                .next_frame(Duration::from_millis(500))
                .expect("session alive");
            if let Some(frame) = frame {
                let index = (150 * usize::from(WIDTH) + 200) * 4;
                if frame.bgra[index..index + 4] == COLOR {
                    return frame;
                }
            }
            assert!(Instant::now() < deadline, "no bitmap frame within 20 s");
        }
    })
    .await
    .unwrap();
    assert_eq!(
        (frame.width, frame.height),
        (u32::from(WIDTH), u32::from(HEIGHT))
    );
    assert_eq!(
        frame.bgra.len(),
        usize::from(WIDTH) * usize::from(HEIGHT) * 4
    );
    // The whole frame is the solid color: every pixel came through the lossless path.
    assert!(frame.bgra.as_chunks::<4>().0.iter().all(|px| *px == COLOR));

    bridge
        .send_input(vec![
            mouse_move(100, 50),
            mouse_button(100, 50, PointerFlags::LEFT_BUTTON, true),
        ])
        .unwrap();
    let event = tokio::time::timeout(Duration::from_secs(10), server.mouse.recv())
        .await
        .expect("server received input")
        .expect("input channel open");
    assert!(
        matches!(event, MouseEvent::Move { x: 100, y: 50 }),
        "unexpected first mouse event: {event:?}"
    );

    let reason = tokio::time::timeout(Duration::from_secs(10), bridge.shutdown())
        .await
        .expect("shutdown completes");
    match reason {
        Ok(reason) => tracing::info!(reason = %reason.description(), "bridge shut down"),
        Err(RdpBridgeError::Io(error)) => {
            tracing::info!(%error, "server closed the transport during shutdown");
        }
        Err(other) => panic!("unexpected shutdown error: {other}"),
    }
    drop(server.display);
    let done = server.done;
    let server_result =
        tokio::task::spawn_blocking(move || done.recv_timeout(Duration::from_secs(15)))
            .await
            .unwrap()
            .expect("ironrdp-server noticed the disconnect");
    tracing::info!(?server_result, "ironrdp-server connection finished");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bridge_rejects_a_server_whose_certificate_is_not_the_pinned_one() {
    let server = start_server();
    let mut wrong = server.certificate_sha256;
    wrong[0] ^= 0xFF;

    let Err(error) =
        RdpBridge::connect(bridge_config(&server, CertificatePolicy::Pinned(wrong))).await
    else {
        panic!("mismatching pin must fail");
    };
    let RdpBridgeError::CertificateMismatch { expected, observed } = error else {
        panic!("expected a certificate mismatch, got {error}");
    };
    assert_eq!(expected, wrong);
    assert_eq!(observed, server.certificate_sha256);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bridge_trust_on_first_use_reports_the_certificate_to_pin() {
    let server = start_server();
    let bridge = RdpBridge::connect(bridge_config(&server, CertificatePolicy::TrustOnFirstUse))
        .await
        .expect("TOFU connection");
    assert_eq!(
        bridge.server_certificate_sha256(),
        server.certificate_sha256
    );
    let _ = tokio::time::timeout(Duration::from_secs(10), bridge.shutdown()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bridge_fails_cleanly_on_wrong_credentials() {
    let server = start_server();
    let mut config = bridge_config(
        &server,
        CertificatePolicy::Pinned(server.certificate_sha256),
    );
    config.password = "wrong".to_owned();
    let Err(error) = RdpBridge::connect(config).await else {
        panic!("wrong password must fail");
    };
    assert!(
        matches!(
            error,
            RdpBridgeError::Connector(_) | RdpBridgeError::Io(_) | RdpBridgeError::Timeout(_)
        ),
        "unexpected error: {error}"
    );
}
