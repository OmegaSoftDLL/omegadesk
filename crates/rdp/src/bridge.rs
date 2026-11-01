//! The RDP bridge: an IronRDP client whose framebuffer is an OmegaDesk capture source.
//!
//! An OmegaDesk client reaches a machine that only speaks RDP (Windows Remote Desktop,
//! xrdp, Hyper-V consoles) through the mesh: the agent side opens a TCP connection to the
//! RDP server, runs the `[MS-RDPBCGR]` connection sequence with `ironrdp-connector`
//! (X.224 negotiation, TLS upgrade with a pinned certificate, CredSSP/NLA with NTLM,
//! capability exchange, licensing and finalization), then drives `ironrdp-session`'s
//! `ActiveStage` on a tokio task. Every graphics update is composited into a
//! [`DecodedImage`] and published, latest frame wins, to an [`RdpBridgeCapturer`] that
//! implements [`omegadesk_capture::Capturer`]. The agent's capture loop therefore encodes
//! RDP sessions exactly like a local monitor, with the same encoders and QUIC transport.
//!
//! Model: `Devolutions_IronRDP/crates/ironrdp-client/src/rdp.rs` (`connect_direct`,
//! `active_session`, the `DeactivateAll` branch running the Deactivation-Reactivation
//! Sequence through `ConnectionActivationFactory`) and
//! `Devolutions_IronRDP/crates/ironrdp-async/src/connector.rs` (`connect_begin`,
//! `mark_as_upgraded`, `connect_finalize`).
//!
//! Scope of this version: output (framebuffer) and fast-path input (keyboard, mouse) over
//! TLS + CredSSP. Kerberos (a KDC round trip during CredSSP), RemoteFX/EGFX codecs, audio,
//! clipboard and drive redirection are not negotiated; the bridge asks for plain 32-bit
//! bitmap updates, which the server sends with the lossless interleaved/planar encoders.

use std::fmt;
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::time::{Duration, Instant};

use ironrdp_connector::connection_activation::{
    ConnectionActivationFactory, ConnectionActivationState,
};
use ironrdp_connector::sspi::generator::NetworkRequest;
use ironrdp_connector::{
    BitmapConfig, ClientConnector, ConnectionResult, ConnectorError, ConnectorResult, Credentials,
    ServerName, general_err,
};
use ironrdp_core::WriteBuf;
use ironrdp_graphics::image_processing::PixelFormat;
use ironrdp_pdu::input::fast_path::FastPathInputEvent;
use ironrdp_pdu::input::mouse::MousePdu;
use ironrdp_pdu::rdp::capability_sets::{BitmapCodecs, MajorPlatformType};
use ironrdp_pdu::rdp::client_info::{
    CompressionType as PduCompressionType, PerformanceFlags, TimezoneInfo,
};
use ironrdp_session::image::DecodedImage;
use ironrdp_session::{
    ActiveStage, ActiveStageBuilder, ActiveStageOutput, GracefulDisconnectReason, SessionError,
    fast_path,
};
use ironrdp_tokio::{FramedWrite as _, NetworkClient, TokioFramed, single_sequence_step};
use omegadesk_capture::{CaptureError, Capturer, DisplayBounds, Frame};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_rustls::client::TlsStream;
use tracing::{debug, info, warn};

use crate::tls;

pub use ironrdp_connector::DesktopSize as RdpDesktopSize;
pub use ironrdp_pdu::input::fast_path::{FastPathInputEvent as InputEvent, KeyboardFlags};
pub use ironrdp_pdu::input::mouse::{MousePdu as MouseInput, PointerFlags};

/// Smallest desktop accepted by `[MS-RDPEDISP]` and by this bridge.
pub const MIN_DESKTOP_DIMENSION: u16 = 200;
/// Largest desktop accepted by `[MS-RDPEDISP]` and by this bridge.
pub const MAX_DESKTOP_DIMENSION: u16 = 8192;

/// Number of input batches that may wait for the session task before
/// [`RdpBridge::send_input`] reports [`RdpBridgeError::InputQueueFull`].
const INPUT_QUEUE: usize = 256;

/// How the bridge validates the RDP server's TLS certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertificatePolicy {
    /// Only accept the certificate whose SHA-256 digest is this one.
    Pinned([u8; 32]),
    /// Accept any certificate and report its digest through
    /// [`RdpBridge::server_certificate_sha256`], so the caller can pin it next time
    /// (the same trust-on-first-use model as the Phase 1 client fingerprint).
    TrustOnFirstUse,
}

/// Connection parameters of an [`RdpBridge`].
#[derive(Clone)]
pub struct RdpBridgeConfig {
    /// `host:port` of the RDP server (port `3389` for Windows Remote Desktop).
    pub destination: String,
    /// Name used for TLS (SNI) and as the CredSSP target; usually the host part of
    /// [`Self::destination`].
    pub server_name: String,
    /// Windows user name.
    pub username: String,
    /// Windows password (CredSSP transports it inside TLS, never in clear).
    pub password: String,
    /// Windows domain, if any.
    pub domain: Option<String>,
    /// Desktop size requested from the server.
    pub desktop_size: RdpDesktopSize,
    /// Server certificate validation.
    pub certificate: CertificatePolicy,
    /// Bound on the whole connection sequence (TCP, TLS, CredSSP, capabilities, licensing).
    pub connect_timeout: Duration,
    /// Client name sent in the Client Core Data (`[MS-RDPBCGR]` 2.2.1.3.2), at most 15
    /// characters.
    pub client_name: String,
}

impl fmt::Debug for RdpBridgeConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RdpBridgeConfig")
            .field("destination", &self.destination)
            .field("server_name", &self.server_name)
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .field("domain", &self.domain)
            .field("desktop_size", &self.desktop_size)
            .field("certificate", &self.certificate)
            .field("connect_timeout", &self.connect_timeout)
            .field("client_name", &self.client_name)
            .finish()
    }
}

impl RdpBridgeConfig {
    /// Parameters for `destination` with the server name taken from its host part, a
    /// 1280x800 desktop, trust-on-first-use certificate handling and a 20 s timeout.
    #[must_use]
    pub fn new(
        destination: impl Into<String>,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Self {
        let destination = destination.into();
        let server_name = destination
            .rsplit_once(':')
            .map_or(destination.as_str(), |(host, _)| host)
            .trim_matches(['[', ']'])
            .to_owned();
        Self {
            destination,
            server_name,
            username: username.into(),
            password: password.into(),
            domain: None,
            desktop_size: RdpDesktopSize {
                width: 1280,
                height: 800,
            },
            certificate: CertificatePolicy::TrustOnFirstUse,
            connect_timeout: Duration::from_secs(20),
            client_name: "omegadesk".to_owned(),
        }
    }

    fn validate(&self) -> Result<(), RdpBridgeError> {
        let RdpDesktopSize { width, height } = self.desktop_size;
        let in_range =
            |value: u16| (MIN_DESKTOP_DIMENSION..=MAX_DESKTOP_DIMENSION).contains(&value);
        if !in_range(width) || !in_range(height) {
            return Err(RdpBridgeError::InvalidDesktopSize(width, height));
        }
        Ok(())
    }

    fn connector_config(&self) -> ironrdp_connector::Config {
        ironrdp_connector::Config {
            desktop_size: self.desktop_size,
            desktop_scale_factor: 0,
            enable_tls: true,
            enable_credssp: true,
            credentials: Credentials::UsernamePassword {
                username: self.username.clone(),
                password: self.password.clone(),
            },
            domain: self.domain.clone(),
            client_build: 0,
            client_name: self.client_name.chars().take(15).collect(),
            keyboard_type: ironrdp_pdu::gcc::KeyboardType::IbmEnhanced,
            keyboard_subtype: 0,
            keyboard_functional_keys_count: 12,
            keyboard_layout: 0,
            ime_file_name: String::new(),
            // No RemoteFX/NSCodec: the server falls back to the lossless 32-bit
            // interleaved/planar bitmap encoders, which `ironrdp-session` decodes.
            bitmap: Some(BitmapConfig {
                lossy_compression: false,
                color_depth: 32,
                codecs: BitmapCodecs(Vec::new()),
            }),
            dig_product_id: String::new(),
            client_dir: String::new(),
            alternate_shell: String::new(),
            work_dir: String::new(),
            platform: MajorPlatformType::UNSPECIFIED,
            hardware_id: None,
            request_data: None,
            autologon: false,
            enable_audio_playback: false,
            performance_flags: PerformanceFlags::default(),
            license_cache: None,
            timezone_info: TimezoneInfo::default(),
            compression_type: None,
            // The pointer is composited into the framebuffer by `DecodedImage`, so the
            // encoded video carries it like a local capture does.
            enable_server_pointer: true,
            pointer_software_rendering: true,
            multitransport_flags: None,
        }
    }
}

/// Errors of the RDP bridge.
#[derive(Debug, thiserror::Error)]
pub enum RdpBridgeError {
    /// Transport error.
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    /// The connection sequence did not finish in time.
    #[error("connection to the RDP server timed out after {0:?}")]
    Timeout(Duration),
    /// TLS configuration or handshake error.
    #[error("TLS: {0}")]
    Tls(#[from] rustls::Error),
    /// The configured server name is not a valid DNS name or IP address.
    #[error("invalid TLS server name {0:?}")]
    InvalidServerName(String),
    /// The server completed the handshake without a certificate.
    #[error("the RDP server presented no certificate")]
    MissingServerCertificate,
    /// The server certificate does not match [`CertificatePolicy::Pinned`].
    #[error(
        "RDP server certificate SHA-256 {} does not match the pinned {}",
        hex(.observed),
        hex(.expected)
    )]
    CertificateMismatch {
        /// Pinned digest.
        expected: [u8; 32],
        /// Digest the server presented.
        observed: [u8; 32],
    },
    /// The server certificate could not be parsed.
    #[error("invalid RDP server certificate: {0}")]
    InvalidServerCertificate(String),
    /// `[MS-RDPBCGR]` connection sequence failure (negotiation, CredSSP, licensing…).
    #[error("RDP connection sequence: {0}")]
    Connector(#[from] ConnectorError),
    /// Active session failure (malformed PDU, unsupported update…).
    #[error("RDP session: {0}")]
    Session(#[from] SessionError),
    /// The session task is gone.
    #[error("RDP session ended: {0}")]
    Disconnected(String),
    /// More than `INPUT_QUEUE` input batches are waiting for the session task.
    #[error("too many pending RDP input events")]
    InputQueueFull,
    /// Desktop size outside `200..=8192` on either axis.
    #[error("desktop size {0}x{1} is outside 200..=8192")]
    InvalidDesktopSize(u16, u16),
}

fn hex(digest: &[u8; 32]) -> String {
    data_encoding::HEXLOWER.encode(digest)
}

/// CredSSP network client for the bridge: NTLM needs no network round trip, and a
/// Kerberos KDC exchange is reported as unsupported instead of being attempted.
struct NoKdcNetworkClient;

impl NetworkClient for NoKdcNetworkClient {
    fn send(
        &mut self,
        network_request: &NetworkRequest,
    ) -> impl Future<Output = ConnectorResult<Vec<u8>>> {
        warn!(
            protocol = ?network_request.protocol,
            "CredSSP asked for a KDC exchange; the RDP bridge only supports NTLM"
        );
        std::future::ready(Err(general_err!(
            "Kerberos KDC exchange is not available in the OmegaDesk RDP bridge; use NTLM credentials"
        )))
    }
}

/// Latest decoded frame shared between the session task and the capturer.
#[derive(Debug, Default)]
struct FrameSlot {
    state: Mutex<SlotState>,
    ready: Condvar,
}

#[derive(Debug, Default)]
struct SlotState {
    frame: Option<Frame>,
    size: (u32, u32),
    closed: Option<String>,
}

impl FrameSlot {
    fn lock(&self) -> std::sync::MutexGuard<'_, SlotState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn set_size(&self, width: u16, height: u16) {
        self.lock().size = (u32::from(width), u32::from(height));
    }

    /// Converts the RGBA framebuffer to the BGRA [`Frame`] the capture pipeline expects
    /// and replaces any frame the capturer has not consumed yet (latest frame wins, like
    /// the client's presentation queue).
    fn publish(&self, image: &DecodedImage) {
        let source = image.data();
        let mut bgra = vec![0u8; source.len()];
        let (dst_pixels, _) = bgra.as_chunks_mut::<4>();
        let (src_pixels, _) = source.as_chunks::<4>();
        for (dst, src) in dst_pixels.iter_mut().zip(src_pixels) {
            dst[0] = src[2];
            dst[1] = src[1];
            dst[2] = src[0];
            dst[3] = 0xFF;
        }
        let frame = Frame {
            width: u32::from(image.width()),
            height: u32::from(image.height()),
            bgra,
            captured_at: Instant::now(),
            #[cfg(windows)]
            gpu_texture: None,
        };
        let mut state = self.lock();
        state.size = (frame.width, frame.height);
        state.frame = Some(frame);
        drop(state);
        self.ready.notify_all();
    }

    fn close(&self, reason: String) {
        self.lock().closed = Some(reason);
        self.ready.notify_all();
    }
}

/// Capture source fed by an [`RdpBridge`]; drop-in for a monitor capturer in the agent's
/// capture loop.
#[derive(Debug)]
pub struct RdpBridgeCapturer {
    slot: Arc<FrameSlot>,
}

impl Capturer for RdpBridgeCapturer {
    fn next_frame(&mut self, timeout: Duration) -> Result<Option<Frame>, CaptureError> {
        let deadline = Instant::now() + timeout;
        let mut state = self.slot.lock();
        loop {
            if let Some(frame) = state.frame.take() {
                return Ok(Some(frame));
            }
            if let Some(reason) = &state.closed {
                return Err(CaptureError::Os(format!("RDP bridge: {reason}")));
            }
            let now = Instant::now();
            if now >= deadline {
                return Ok(None);
            }
            let (guard, _) = self
                .slot
                .ready
                .wait_timeout(state, deadline - now)
                .unwrap_or_else(PoisonError::into_inner);
            state = guard;
        }
    }

    fn size(&self) -> (u32, u32) {
        self.slot.lock().size
    }

    fn bounds(&self) -> DisplayBounds {
        let (width, height) = self.size();
        DisplayBounds {
            x: 0,
            y: 0,
            width,
            height,
        }
    }
}

enum Command {
    Input(Vec<FastPathInputEvent>),
    Shutdown,
}

type UpgradedFramed = TokioFramed<TlsStream<TcpStream>>;

/// A live RDP session terminated by IronRDP on behalf of an OmegaDesk client.
pub struct RdpBridge {
    commands: mpsc::Sender<Command>,
    task: JoinHandle<Result<GracefulDisconnectReason, RdpBridgeError>>,
    slot: Arc<FrameSlot>,
    capturer: Option<RdpBridgeCapturer>,
    certificate_sha256: [u8; 32],
    desktop_size: RdpDesktopSize,
}

impl fmt::Debug for RdpBridge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RdpBridge")
            .field("desktop_size", &self.desktop_size)
            .field("certificate_sha256", &hex(&self.certificate_sha256))
            .finish_non_exhaustive()
    }
}

impl RdpBridge {
    /// Runs the full connection sequence against `config.destination` and starts the
    /// session task.
    ///
    /// # Errors
    ///
    /// Returns [`RdpBridgeError::Timeout`] when the sequence exceeds
    /// `config.connect_timeout`, [`RdpBridgeError::CertificateMismatch`] when the pinned
    /// digest does not match, and the connector's own error for negotiation, CredSSP or
    /// licensing failures (wrong password included).
    pub async fn connect(config: RdpBridgeConfig) -> Result<Self, RdpBridgeError> {
        config.validate()?;
        let timeout = config.connect_timeout;
        tokio::time::timeout(timeout, Self::connect_inner(config))
            .await
            .map_err(|_| RdpBridgeError::Timeout(timeout))?
    }

    async fn connect_inner(config: RdpBridgeConfig) -> Result<Self, RdpBridgeError> {
        let tcp = TcpStream::connect(config.destination.as_str()).await?;
        tcp.set_nodelay(true)?;
        let client_addr = tcp.local_addr()?;
        info!(destination = %config.destination, "RDP bridge: TCP connected");

        let mut connector = ClientConnector::new(config.connector_config(), client_addr);
        let mut framed = TokioFramed::new(tcp);
        let should_upgrade = ironrdp_tokio::connect_begin(&mut framed, &mut connector).await?;

        let (tcp, leftover) = framed.into_inner();
        let upgraded_tls = tls::upgrade(tcp, &config.server_name, config.certificate).await?;
        let certificate_sha256 = upgraded_tls.certificate_sha256;
        let server_public_key = tls::subject_public_key(&upgraded_tls.certificate)?;
        debug!(
            certificate_sha256 = %hex(&certificate_sha256),
            "RDP bridge: TLS established"
        );
        let mut framed: UpgradedFramed =
            TokioFramed::new_with_leftover(upgraded_tls.stream, leftover);
        let upgraded = ironrdp_tokio::mark_as_upgraded(should_upgrade, &mut connector);

        let mut network_client = NoKdcNetworkClient;
        let connection_result = ironrdp_tokio::connect_finalize(
            upgraded,
            connector,
            &mut framed,
            &mut network_client,
            ServerName::new(config.server_name.clone()),
            server_public_key,
            None,
        )
        .await?;
        let desktop_size = connection_result.desktop_size;
        info!(
            width = desktop_size.width,
            height = desktop_size.height,
            "RDP bridge: connected"
        );

        let slot = Arc::new(FrameSlot::default());
        slot.set_size(desktop_size.width, desktop_size.height);
        let (commands, receiver) = mpsc::channel(INPUT_QUEUE);
        let session_slot = slot.clone();
        let task = tokio::spawn(async move {
            let result = run_session(framed, connection_result, &session_slot, receiver).await;
            let closing = match &result {
                Ok(reason) => format!("disconnected ({})", reason.description()),
                Err(error) => error.to_string(),
            };
            session_slot.close(closing);
            result
        });

        Ok(Self {
            commands,
            task,
            capturer: Some(RdpBridgeCapturer { slot: slot.clone() }),
            slot,
            certificate_sha256,
            desktop_size,
        })
    }

    /// Takes the capture source (once); hand it to the capture loop.
    pub fn take_capturer(&mut self) -> Option<RdpBridgeCapturer> {
        self.capturer.take()
    }

    /// SHA-256 of the certificate the server presented; pin it with
    /// [`CertificatePolicy::Pinned`] on the next connection.
    #[must_use]
    pub fn server_certificate_sha256(&self) -> [u8; 32] {
        self.certificate_sha256
    }

    /// Desktop size negotiated with the server.
    #[must_use]
    pub fn desktop_size(&self) -> RdpDesktopSize {
        self.desktop_size
    }

    /// Current framebuffer size (changes after a server-driven reactivation).
    #[must_use]
    pub fn framebuffer_size(&self) -> (u32, u32) {
        self.slot.lock().size
    }

    /// Whether the session task is still running.
    #[must_use]
    pub fn is_connected(&self) -> bool {
        !self.task.is_finished()
    }

    /// Queues fast-path input events (keyboard scancodes, mouse) for the server.
    ///
    /// # Errors
    ///
    /// Returns [`RdpBridgeError::Disconnected`] once the session ended and
    /// [`RdpBridgeError::InputQueueFull`] when the session task is not keeping up.
    pub fn send_input(&self, events: Vec<FastPathInputEvent>) -> Result<(), RdpBridgeError> {
        self.commands
            .try_send(Command::Input(events))
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => RdpBridgeError::InputQueueFull,
                mpsc::error::TrySendError::Closed(_) => {
                    RdpBridgeError::Disconnected("session task is not running".to_owned())
                }
            })
    }

    /// Sends the `[MS-RDPBCGR]` Shutdown Request and waits for the session to end.
    ///
    /// # Errors
    ///
    /// Returns the session error when the connection failed before the shutdown completed.
    pub async fn shutdown(self) -> Result<GracefulDisconnectReason, RdpBridgeError> {
        let _ = self.commands.send(Command::Shutdown).await;
        match self.task.await {
            Ok(result) => result,
            Err(join) => Err(RdpBridgeError::Disconnected(join.to_string())),
        }
    }
}

/// Builds a fast-path mouse move to absolute desktop coordinates.
#[must_use]
pub fn mouse_move(x: u16, y: u16) -> FastPathInputEvent {
    FastPathInputEvent::MouseEvent(MousePdu {
        flags: PointerFlags::MOVE,
        number_of_wheel_rotation_units: 0,
        x_position: x,
        y_position: y,
    })
}

/// Builds a fast-path mouse button transition at absolute desktop coordinates; `button` is
/// one of [`PointerFlags::LEFT_BUTTON`], [`PointerFlags::RIGHT_BUTTON`] or
/// [`PointerFlags::MIDDLE_BUTTON_OR_WHEEL`].
#[must_use]
pub fn mouse_button(x: u16, y: u16, button: PointerFlags, pressed: bool) -> FastPathInputEvent {
    let mut flags = button;
    if pressed {
        flags |= PointerFlags::DOWN;
    }
    FastPathInputEvent::MouseEvent(MousePdu {
        flags,
        number_of_wheel_rotation_units: 0,
        x_position: x,
        y_position: y,
    })
}

/// Builds a fast-path keyboard event for a PC/AT scancode (`extended` for the `0xE0` set).
#[must_use]
pub fn key_event(scancode: u8, extended: bool, pressed: bool) -> FastPathInputEvent {
    let mut flags = KeyboardFlags::empty();
    if extended {
        flags |= KeyboardFlags::EXTENDED;
    }
    if !pressed {
        flags |= KeyboardFlags::RELEASE;
    }
    FastPathInputEvent::KeyboardEvent(flags, scancode)
}

fn bulk_compression(kind: PduCompressionType) -> ironrdp_bulk::CompressionType {
    match kind {
        PduCompressionType::K8 => ironrdp_bulk::CompressionType::Rdp4,
        PduCompressionType::K64 => ironrdp_bulk::CompressionType::Rdp5,
        PduCompressionType::Rdp6 => ironrdp_bulk::CompressionType::Rdp6,
        PduCompressionType::Rdp61 => ironrdp_bulk::CompressionType::Rdp61,
    }
}

/// Drives the active session until the server or the bridge ends it.
async fn run_session(
    mut framed: UpgradedFramed,
    connection_result: ConnectionResult,
    slot: &FrameSlot,
    mut commands: mpsc::Receiver<Command>,
) -> Result<GracefulDisconnectReason, RdpBridgeError> {
    let desktop_size = connection_result.desktop_size;
    let compression_type = connection_result.compression_type;
    let activation_factory = connection_result.activation_factory;
    let mut image = DecodedImage::new(PixelFormat::RgbA32, desktop_size.width, desktop_size.height);
    let mut active_stage = ActiveStageBuilder {
        static_channels: connection_result.static_channels,
        user_channel_id: connection_result.user_channel_id,
        io_channel_id: connection_result.io_channel_id,
        message_channel_id: connection_result.message_channel_id,
        share_id: connection_result.share_id,
        compression_type,
        enable_server_pointer: connection_result.enable_server_pointer,
        pointer_software_rendering: connection_result.pointer_software_rendering,
    }
    .build();

    let mut shutdown_requested = false;
    loop {
        let outputs = tokio::select! {
            command = commands.recv(), if !shutdown_requested => match command {
                Some(Command::Input(events)) => {
                    active_stage.process_fastpath_input(&mut image, &events)?
                }
                Some(Command::Shutdown) | None => {
                    shutdown_requested = true;
                    active_stage.graceful_shutdown()?
                }
            },
            frame = framed.read_pdu() => {
                let (action, payload) = match frame {
                    Ok(frame) => frame,
                    Err(error) if shutdown_requested
                        && error.kind() == std::io::ErrorKind::UnexpectedEof =>
                    {
                        return Ok(GracefulDisconnectReason::UserInitiated);
                    }
                    Err(error) => return Err(error.into()),
                };
                active_stage.process(&mut image, action, &payload)?
            }
        };

        let mut dirty = false;
        let mut terminate = None;
        for output in outputs {
            match output {
                ActiveStageOutput::ResponseFrame(frame) => framed.write_all(&frame).await?,
                // Software pointer rendering changes `image` even when there is no bitmap
                // update, so cursor-only movement must also wake the capture pipeline.
                ActiveStageOutput::GraphicsUpdate(_)
                | ActiveStageOutput::PointerDefault
                | ActiveStageOutput::PointerHidden
                | ActiveStageOutput::PointerPosition { .. }
                | ActiveStageOutput::PointerBitmap(_) => dirty = true,
                ActiveStageOutput::Terminate(reason) => terminate = Some(reason),
                ActiveStageOutput::DeactivateAll => {
                    reactivate(
                        &mut framed,
                        &activation_factory,
                        &mut active_stage,
                        &mut image,
                        compression_type,
                        slot,
                    )
                    .await?;
                    dirty = true;
                }
                // Not negotiated by the bridge (no multitransport flags, no autodetect
                // response): the server continues over the main TCP connection.
                ActiveStageOutput::MultitransportRequest(_) => {
                    debug!("ignoring server multitransport request");
                }
                ActiveStageOutput::AutoDetect(_) => {
                    debug!("ignoring server connect-time autodetect request");
                }
            }
        }
        if dirty {
            slot.publish(&image);
        }
        if let Some(reason) = terminate {
            info!(reason = %reason.description(), "RDP bridge: session terminated");
            return Ok(reason);
        }
    }
}

/// Runs the Deactivation-Reactivation Sequence (`[MS-RDPBCGR]` 1.3.1.3) after a Server
/// Deactivate All PDU: a new capability exchange and finalization, typically because the
/// desktop was resized. The framebuffer and the fast-path processor are rebuilt for the new
/// share.
async fn reactivate(
    framed: &mut UpgradedFramed,
    factory: &ConnectionActivationFactory,
    active_stage: &mut ActiveStage,
    image: &mut DecodedImage,
    compression_type: Option<PduCompressionType>,
    slot: &FrameSlot,
) -> Result<(), RdpBridgeError> {
    debug!("RDP bridge: running the Deactivation-Reactivation Sequence");
    let mut sequence = factory.create();
    let mut buf = WriteBuf::new();
    loop {
        single_sequence_step(framed, &mut sequence, &mut buf).await?;
        if let ConnectionActivationState::Finalized {
            desktop_size,
            share_id,
            enable_server_pointer,
            pointer_software_rendering,
        } = sequence.connection_activation_state()
        {
            *image =
                DecodedImage::new(PixelFormat::RgbA32, desktop_size.width, desktop_size.height);
            let bulk_decompressor = compression_type.and_then(|kind| {
                ironrdp_bulk::BulkCompressor::new(bulk_compression(kind))
                    .map_err(
                        |error| warn!(%error, "bulk decompressor unavailable after reactivation"),
                    )
                    .ok()
            });
            active_stage.set_fastpath_processor(
                fast_path::ProcessorBuilder {
                    io_channel_id: sequence.io_channel_id(),
                    user_channel_id: sequence.user_channel_id(),
                    share_id,
                    enable_server_pointer,
                    pointer_software_rendering,
                    bulk_decompressor,
                }
                .build(),
            );
            active_stage.set_share_id(share_id);
            active_stage.set_enable_server_pointer(enable_server_pointer);
            slot.set_size(desktop_size.width, desktop_size.height);
            info!(
                width = desktop_size.width,
                height = desktop_size.height,
                "RDP bridge: reactivated"
            );
            return Ok(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_defaults_derive_the_server_name_from_the_destination() {
        let config = RdpBridgeConfig::new("office-pc.omega:3389", "alice", "pw");
        assert_eq!(config.server_name, "office-pc.omega");
        assert_eq!(
            RdpBridgeConfig::new("[fd7a::1]:3389", "a", "b").server_name,
            "fd7a::1"
        );
        assert_eq!(
            RdpBridgeConfig::new("10.0.0.5", "a", "b").server_name,
            "10.0.0.5"
        );
        assert!(config.validate().is_ok());
        let debug = format!("{config:?}");
        assert!(!debug.contains("pw"));
        assert!(debug.contains("<redacted>"));
    }

    #[test]
    fn config_rejects_desktop_sizes_outside_the_rdpedisp_range() {
        let mut config = RdpBridgeConfig::new("h:3389", "a", "b");
        config.desktop_size = RdpDesktopSize {
            width: 199,
            height: 800,
        };
        assert!(matches!(
            config.validate(),
            Err(RdpBridgeError::InvalidDesktopSize(199, 800))
        ));
        config.desktop_size = RdpDesktopSize {
            width: 1280,
            height: 8193,
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn input_helpers_set_the_fast_path_flags() {
        assert!(matches!(
            mouse_move(10, 20),
            FastPathInputEvent::MouseEvent(MousePdu { flags, x_position: 10, y_position: 20, .. })
                if flags == PointerFlags::MOVE
        ));
        assert!(matches!(
            mouse_button(1, 2, PointerFlags::LEFT_BUTTON, true),
            FastPathInputEvent::MouseEvent(MousePdu { flags, .. })
                if flags == PointerFlags::LEFT_BUTTON | PointerFlags::DOWN
        ));
        assert!(matches!(
            key_event(0x1C, false, false),
            FastPathInputEvent::KeyboardEvent(flags, 0x1C) if flags == KeyboardFlags::RELEASE
        ));
        assert!(matches!(
            key_event(0x48, true, true),
            FastPathInputEvent::KeyboardEvent(flags, 0x48) if flags == KeyboardFlags::EXTENDED
        ));
    }

    #[test]
    fn frame_slot_converts_rgba_to_bgra_and_keeps_only_the_latest_frame() {
        let slot = FrameSlot::default();
        let mut image = DecodedImage::new(PixelFormat::RgbA32, 2, 1);
        assert_eq!(image.data().len(), 8);
        slot.publish(&image);
        // Overwrite with a second frame before anyone consumed the first one.
        image = DecodedImage::new(PixelFormat::RgbA32, 4, 2);
        slot.publish(&image);
        let mut capturer = RdpBridgeCapturer {
            slot: Arc::new(FrameSlot::default()),
        };
        capturer.slot = Arc::new(slot);
        let frame = capturer
            .next_frame(Duration::from_millis(10))
            .unwrap()
            .unwrap();
        assert_eq!((frame.width, frame.height), (4, 2));
        assert_eq!(capturer.size(), (4, 2));
        assert!(frame.bgra.as_chunks::<4>().0.iter().all(|px| px[3] == 0xFF));
        // Nothing new: times out without a frame.
        assert!(
            capturer
                .next_frame(Duration::from_millis(5))
                .unwrap()
                .is_none()
        );
        capturer.slot.close("server went away".to_owned());
        assert!(matches!(
            capturer.next_frame(Duration::from_millis(5)),
            Err(CaptureError::Os(reason)) if reason.contains("server went away")
        ));
    }
}
