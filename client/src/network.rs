//! Conexão com o agente, numa thread com runtime tokio, e decodificação numa
//! thread própria.

use std::net::SocketAddr;
use std::sync::mpsc as std_mpsc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, bail};
use omegadesk_codec::{OpenH264Decoder, VideoDecoder};
use omegadesk_protocol::PROTOCOL_VERSION;
use omegadesk_protocol::v1::{
    Capabilities, Envelope, Hello, Ping, RequestKeyframe, VideoCodec, VideoFrame, envelope::Payload,
};
use omegadesk_transport::{Connection, EnvelopeReader, SendStream, connect, send_envelope};
use tokio::sync::mpsc;
use tracing::{info, warn};
use winit::event_loop::EventLoopProxy;

use crate::stats::{LatestFrame, Shared};
use crate::window::UserEvent;

/// Intervalo entre pings de medição de latência.
const PING_INTERVAL: Duration = Duration::from_millis(500);

/// Quadros esperando o decoder. Mais que isso vira atraso: descarta e pede
/// keyframe (o Moonlight usa uma fila de 3, `pacer.cpp`).
const DECODE_QUEUE: usize = 3;

/// Intervalo mínimo entre pedidos de keyframe, para não inundar o agente.
const KEYFRAME_REQUEST_INTERVAL: Duration = Duration::from_millis(250);

fn unix_micros() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_micros()).unwrap_or(u64::MAX))
}

/// Dados para conectar ao agente.
#[derive(Debug, Clone)]
pub(crate) struct Target {
    /// Chave pública de assinatura deste dispositivo, enviada no `Hello`.
    pub(crate) device_public_key: [u8; 32],
    pub(crate) address: SocketAddr,
    pub(crate) fingerprint: String,
    pub(crate) password: String,
}

/// Inicia a conexão em segundo plano. Devolve o canal para enviar mensagens
/// de controle (teclado, mouse) ao agente.
pub(crate) fn start(
    target: Target,
    shared: Shared,
    proxy: EventLoopProxy<UserEvent>,
) -> mpsc::UnboundedSender<Envelope> {
    let (control_tx, control_rx) = mpsc::unbounded_channel();
    let requests = control_tx.clone();
    std::thread::spawn(move || {
        let runtime = match tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
        {
            Ok(runtime) => runtime,
            Err(error) => {
                shared.set_status(format!("erro: {error}"));
                let _ = proxy.send_event(UserEvent::Disconnected);
                return;
            }
        };
        let result = runtime.block_on(run(
            target,
            shared.clone(),
            proxy.clone(),
            control_rx,
            requests,
        ));
        let status = match result {
            Ok(()) => "desconectado".to_owned(),
            Err(error) => format!("erro: {error:#}"),
        };
        warn!("{status}");
        shared.set_status(status);
        let _ = proxy.send_event(UserEvent::Disconnected);
    });
    control_tx
}

async fn run(
    target: Target,
    shared: Shared,
    proxy: EventLoopProxy<UserEvent>,
    mut control_rx: mpsc::UnboundedReceiver<Envelope>,
    requests: mpsc::UnboundedSender<Envelope>,
) -> anyhow::Result<()> {
    shared.set_status(format!("conectando a {}…", target.address));
    let _ = proxy.send_event(UserEvent::Status);
    let (_endpoint, connection) = connect(target.address, &target.fingerprint)
        .await
        .context("não foi possível conectar ao agente")?;

    let result = session(
        &connection,
        &target,
        &shared,
        &proxy,
        &mut control_rx,
        requests,
    )
    .await;
    connection.close(0u32.into(), b"fim");
    log_connection(&connection);
    result
}

/// Registra por que a conexão terminou e como estava a rede.
fn log_connection(connection: &Connection) {
    if let Some(reason) = connection.close_reason() {
        info!("conexão encerrada: {reason}");
    }
    let stats = connection.stats();
    info!(
        "rede: rtt {:?}, {} pacotes perdidos de {}, {} eventos de congestionamento, MTU {}",
        stats.path.rtt,
        stats.path.lost_packets,
        stats.path.sent_packets,
        stats.path.congestion_events,
        stats.path.current_mtu,
    );
}

async fn session(
    connection: &Connection,
    target: &Target,
    shared: &Shared,
    proxy: &EventLoopProxy<UserEvent>,
    control_rx: &mut mpsc::UnboundedReceiver<Envelope>,
    requests: mpsc::UnboundedSender<Envelope>,
) -> anyhow::Result<()> {
    let (mut control_send, control_recv) = connection.open_bi().await?;
    let mut control = EnvelopeReader::new(control_recv);
    send_envelope(
        &mut control_send,
        &Envelope {
            payload: Some(Payload::Hello(Hello {
                protocol_version: PROTOCOL_VERSION,
                device_public_key: target.device_public_key.to_vec().into(),
                device_name: "omegadesk-client".to_owned(),
                capabilities: Some(Capabilities {
                    decoders: vec![VideoCodec::H264 as i32],
                    encoders: Vec::new(),
                }),
                access_password: target.password.clone(),
            })),
        },
    )
    .await?;

    let ack = match control.next().await? {
        Some(Envelope {
            payload: Some(Payload::HelloAck(ack)),
        }) => ack,
        Some(Envelope {
            payload: Some(Payload::Error(error)),
        }) => bail!("o agente recusou: {}", error.message),
        _ => bail!("resposta inesperada do agente"),
    };
    let agent_id = <[u8; 32]>::try_from(ack.device_public_key.as_ref()).map_or_else(
        |_| "sem identidade".to_owned(),
        |key| omegadesk_identity::DeviceId::from_signing_key(&key).to_string(),
    );
    info!("conectado a \"{}\" (ID {agent_id})", ack.device_name);
    shared.set_status(format!("conectado a {}", ack.device_name));
    let _ = proxy.send_event(UserEvent::Status);

    let video_recv = connection.accept_uni().await?;
    let decoder = Decoder::spawn(shared.clone(), proxy.clone(), requests);

    let video = tokio::spawn(async move {
        let mut reader = EnvelopeReader::new(video_recv);
        loop {
            match reader.next().await {
                Ok(Some(envelope)) => {
                    if let Some(Payload::VideoFrame(frame)) = envelope.payload
                        && !decoder.submit(frame)
                    {
                        warn!("decoder parou; encerrando o vídeo");
                        break;
                    }
                }
                Ok(None) => {
                    warn!("o agente encerrou o stream de vídeo");
                    break;
                }
                Err(error) => {
                    warn!("erro no stream de vídeo: {error}");
                    break;
                }
            }
        }
    });

    let control_task = control_loop(&mut control_send, &mut control, control_rx, shared);
    tokio::select! {
        result = control_task => result,
        _ = video => Ok(()),
    }
}

/// Envia pings e as mensagens de controle; recebe os pongs.
async fn control_loop(
    send: &mut SendStream,
    control: &mut EnvelopeReader,
    control_rx: &mut mpsc::UnboundedReceiver<Envelope>,
    shared: &Shared,
) -> anyhow::Result<()> {
    let started = Instant::now();
    let mut ticker = tokio::time::interval(PING_INTERVAL);
    let mut sequence = 0u64;
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                sequence += 1;
                let ping = Envelope {
                    payload: Some(Payload::Ping(Ping {
                        sequence,
                        sent_at_micros: u64::try_from(started.elapsed().as_micros())
                            .unwrap_or(u64::MAX),
                    })),
                };
                send_envelope(send, &ping).await?;
            }
            event = control_rx.recv() => {
                let Some(event) = event else { return Ok(()) };
                send_envelope(send, &event).await?;
            }
            envelope = control.next() => {
                match envelope? {
                    Some(Envelope { payload: Some(Payload::Pong(pong)) }) => {
                        let now = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
                        shared.set_rtt(Duration::from_micros(
                            now.saturating_sub(pong.ping_sent_at_micros),
                        ));
                    }
                    Some(_) => {}
                    None => return Ok(()),
                }
            }
        }
    }
}

/// Fila curta até a thread de decodificação.
struct Decoder {
    queue: std_mpsc::SyncSender<VideoFrame>,
    requests: mpsc::UnboundedSender<Envelope>,
}

impl Decoder {
    fn spawn(
        shared: Shared,
        proxy: EventLoopProxy<UserEvent>,
        requests: mpsc::UnboundedSender<Envelope>,
    ) -> Self {
        let (queue, rx) = std_mpsc::sync_channel::<VideoFrame>(DECODE_QUEUE);
        let thread_requests = requests.clone();
        std::thread::spawn(move || decode_loop(&rx, &shared, &proxy, &thread_requests));
        Self { queue, requests }
    }

    /// Entrega um quadro ao decoder. Com a fila cheia, descarta e pede
    /// keyframe. Devolve `false` se o decoder parou.
    fn submit(&self, frame: VideoFrame) -> bool {
        match self.queue.try_send(frame) {
            Ok(()) => true,
            Err(std_mpsc::TrySendError::Full(_)) => {
                // O decoder vai pular os P-frames até o keyframe pedido aqui.
                let _ = self.requests.send(keyframe_request());
                true
            }
            Err(std_mpsc::TrySendError::Disconnected(_)) => false,
        }
    }
}

fn keyframe_request() -> Envelope {
    Envelope {
        payload: Some(Payload::RequestKeyframe(RequestKeyframe {})),
    }
}

/// Decodifica e publica só o quadro mais recente. Enquanto não houver um
/// keyframe válido (início, quadro perdido ou erro), pula os P-frames e pede
/// keyframe, como o Moonlight (`ffmpeg.cpp`) e o `RustDesk` (`refresh_video`).
fn decode_loop(
    rx: &std_mpsc::Receiver<VideoFrame>,
    shared: &Shared,
    proxy: &EventLoopProxy<UserEvent>,
    requests: &mpsc::UnboundedSender<Envelope>,
) {
    let mut decoder = match OpenH264Decoder::new() {
        Ok(decoder) => decoder,
        Err(error) => {
            shared.set_status(format!("decoder indisponível: {error}"));
            return;
        }
    };
    let mut expected_sequence: Option<u64> = None;
    let mut waiting_keyframe = true;
    let mut last_request: Option<Instant> = None;
    let mut request_keyframe = |reason: &str| {
        if last_request.is_none_or(|at| at.elapsed() >= KEYFRAME_REQUEST_INTERVAL) {
            info!("pedindo keyframe: {reason}");
            let _ = requests.send(keyframe_request());
            last_request = Some(Instant::now());
        }
    };
    let mut logged_clock_skew = false;

    while let Ok(frame) = rx.recv() {
        // Buraco na sequência: algum quadro foi descartado no caminho.
        if expected_sequence.is_some_and(|expected| frame.sequence != expected) && !frame.keyframe {
            waiting_keyframe = true;
        }
        expected_sequence = Some(frame.sequence + 1);
        if frame.keyframe {
            waiting_keyframe = false;
        } else if waiting_keyframe {
            request_keyframe("aguardando keyframe");
            continue;
        }

        let start = Instant::now();
        match decoder.decode(&frame.data) {
            Ok(Some(image)) => {
                shared.publish(LatestFrame {
                    image,
                    host_processing: Duration::from_micros(u64::from(frame.host_processing_micros)),
                    decode: start.elapsed(),
                    decoded_at: Instant::now(),
                });
                if proxy.send_event(UserEvent::Frame).is_err() {
                    break;
                }
            }
            Ok(None) => {}
            Err(error) => {
                warn!("quadro {} não decodificado: {error}", frame.sequence);
                waiting_keyframe = true;
                request_keyframe("erro de decodificação");
            }
        }
        if !logged_clock_skew {
            let skew = unix_micros().abs_diff(frame.captured_at_micros);
            info!(
                "diferença de relógio host/cliente + rede: {} ms",
                skew / 1000
            );
            logged_clock_skew = true;
        }
    }
}
