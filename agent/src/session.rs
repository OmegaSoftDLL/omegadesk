//! Uma sessão de acesso remoto: handshake, vídeo e controle.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use anyhow::bail;
use omegadesk_codec::EncoderSettings;
use omegadesk_input::{InputInjector, TargetDisplay};
use omegadesk_protocol::v1::{
    Capabilities, Envelope, Error as ProtocolError, ErrorCode, HelloAck, Pong, VideoCodec,
    envelope::Payload,
};
use omegadesk_protocol::{PROTOCOL_VERSION, negotiate_codec};
use omegadesk_transport::{Connection, EnvelopeReader, SendStream, send_envelope};
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::capture_loop::{self, EncoderChoice};

/// Codecs que este agente sabe codificar, em ordem de preferência.
const ENCODERS: [VideoCodec; 1] = [VideoCodec::H264];

/// Atraso antes de responder a uma senha errada, contra tentativa e erro.
const WRONG_PASSWORD_DELAY: Duration = Duration::from_secs(1);

/// Tempo para o cliente ler a mensagem de recusa antes de a conexão fechar.
const REJECT_GRACE: Duration = Duration::from_secs(2);

/// Quadros de vídeo prontos esperando a rede. Pequeno de propósito: o que
/// não couber é descartado na captura (ver `capture_loop`).
const VIDEO_QUEUE: usize = 2;

/// Códigos de encerramento da conexão QUIC.
mod close_code {
    pub(super) const NORMAL: u32 = 0;
    pub(super) const REJECTED: u32 = 1;
}

/// Configuração da sessão, vinda da linha de comando.
#[derive(Debug, Clone)]
pub(crate) struct SessionConfig {
    pub(crate) name: String,
    /// Chave pública de assinatura deste dispositivo, enviada no `HelloAck`.
    pub(crate) device_public_key: [u8; 32],
    pub(crate) password: String,
    pub(crate) monitor: u32,
    pub(crate) encoder: EncoderChoice,
    pub(crate) settings: EncoderSettings,
    pub(crate) input: bool,
}

/// Estado compartilhado entre a thread de captura e a tarefa de controle.
#[derive(Debug, Default)]
pub(crate) struct SessionState {
    pub(crate) stop: AtomicBool,
    pub(crate) keyframe_requested: AtomicBool,
    target: Mutex<Option<TargetDisplay>>,
}

impl SessionState {
    pub(crate) fn set_target(&self, target: TargetDisplay) {
        *self.target.lock().unwrap_or_else(PoisonError::into_inner) = Some(target);
    }

    fn target(&self) -> Option<TargetDisplay> {
        *self.target.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Atende uma conexão do começo ao fim.
pub(crate) async fn run(connection: Connection, config: Arc<SessionConfig>) -> anyhow::Result<()> {
    let result = serve(&connection, &config).await;
    let reason: &[u8] = if result.is_ok() { b"fim" } else { b"erro" };
    connection.close(close_code::NORMAL.into(), reason);
    let stats = connection.stats();
    info!(
        "rede: rtt {:?}, {} pacotes perdidos de {}, {} eventos de congestionamento",
        stats.path.rtt,
        stats.path.lost_packets,
        stats.path.sent_packets,
        stats.path.congestion_events,
    );
    result
}

async fn serve(connection: &Connection, config: &Arc<SessionConfig>) -> anyhow::Result<()> {
    let (mut control_send, control_recv) = connection.accept_bi().await?;
    let mut control = EnvelopeReader::new(control_recv);
    if let Err(error) = handshake(&mut control_send, &mut control, config).await {
        // Garante que o motivo chegue ao cliente antes de fechar: termina o
        // stream e dá ao cliente um tempo para ler e fechar do lado dele.
        let _ = control_send.finish();
        let _ = tokio::time::timeout(REJECT_GRACE, connection.closed()).await;
        connection.close(close_code::REJECTED.into(), b"recusado");
        return Err(error);
    }

    // Vídeo num stream próprio, para não atrasar as mensagens de controle.
    let mut video_send = connection.open_uni().await?;
    let state = Arc::new(SessionState {
        keyframe_requested: AtomicBool::new(true),
        ..SessionState::default()
    });
    let (frame_tx, mut frame_rx) = mpsc::channel(VIDEO_QUEUE);

    let capture = {
        let state = state.clone();
        let config = config.clone();
        std::thread::Builder::new()
            .name("captura".into())
            .spawn(move || {
                capture_loop::run(
                    config.monitor,
                    config.encoder,
                    config.settings,
                    &frame_tx,
                    &state,
                );
            })?
    };

    let video = tokio::spawn(async move {
        while let Some(frame) = frame_rx.recv().await {
            let envelope = Envelope {
                payload: Some(Payload::VideoFrame(frame)),
            };
            if send_envelope(&mut video_send, &envelope).await.is_err() {
                break;
            }
        }
    });

    let injector = if config.input {
        match omegadesk_input::open() {
            Ok(injector) => Some(injector),
            Err(error) => {
                warn!("sem controle remoto de teclado e mouse: {error}");
                None
            }
        }
    } else {
        None
    };

    let result = serve_control(&mut control_send, &mut control, injector, &state).await;

    state.stop.store(true, Ordering::Relaxed);
    video.abort();
    // `join` bloqueia: fora das threads do runtime.
    if tokio::task::spawn_blocking(move || capture.join().is_err())
        .await
        .unwrap_or(true)
    {
        warn!("a thread de captura terminou com pânico");
    }
    result
}

/// Recebe o `Hello`, confere a senha, escolhe o codec e responde com `HelloAck`.
async fn handshake(
    control_send: &mut SendStream,
    control: &mut EnvelopeReader,
    config: &SessionConfig,
) -> anyhow::Result<VideoCodec> {
    let Some(Envelope {
        payload: Some(Payload::Hello(hello)),
    }) = control.next().await?
    else {
        bail!("o cliente não começou com Hello");
    };
    if hello.protocol_version != PROTOCOL_VERSION {
        reject(
            control_send,
            ErrorCode::UnsupportedVersion,
            "versão do protocolo diferente",
        )
        .await;
        bail!(
            "cliente usa a versão {} do protocolo",
            hello.protocol_version
        );
    }
    if !crate::password::matches(&config.password, &hello.access_password) {
        tokio::time::sleep(WRONG_PASSWORD_DELAY).await;
        reject(control_send, ErrorCode::Unauthorized, "senha incorreta").await;
        bail!("senha incorreta");
    }
    let client_decoders: Vec<VideoCodec> = hello
        .capabilities
        .as_ref()
        .map(|caps| caps.decoders().collect())
        .unwrap_or_default();
    let Some(codec) = negotiate_codec(&ENCODERS, &client_decoders) else {
        reject(
            control_send,
            ErrorCode::NoCommonCodec,
            "nenhum codec em comum",
        )
        .await;
        bail!("nenhum codec em comum com o cliente");
    };
    info!(
        "cliente \"{}\" ({}) autorizado, usando {codec:?}",
        hello.device_name,
        describe_device(&hello.device_public_key),
    );

    send_envelope(
        control_send,
        &Envelope {
            payload: Some(Payload::HelloAck(HelloAck {
                protocol_version: PROTOCOL_VERSION,
                device_public_key: config.device_public_key.to_vec().into(),
                device_name: config.name.clone(),
                capabilities: Some(Capabilities {
                    decoders: Vec::new(),
                    encoders: ENCODERS.iter().map(|c| *c as i32).collect(),
                }),
                selected_codec: codec as i32,
            })),
        },
    )
    .await?;
    Ok(codec)
}

/// Atende o stream de controle: ping, keyframe, teclado e mouse.
async fn serve_control(
    control_send: &mut SendStream,
    control: &mut EnvelopeReader,
    mut injector: Option<Box<dyn InputInjector>>,
    state: &SessionState,
) -> anyhow::Result<()> {
    let mut target = None;
    while let Some(envelope) = control.next().await? {
        match envelope.payload {
            Some(Payload::Ping(ping)) => {
                let reply = Envelope {
                    payload: Some(Payload::Pong(Pong {
                        sequence: ping.sequence,
                        ping_sent_at_micros: ping.sent_at_micros,
                    })),
                };
                send_envelope(control_send, &reply).await?;
            }
            Some(Payload::RequestKeyframe(_)) => {
                state.keyframe_requested.store(true, Ordering::Relaxed);
            }
            Some(Payload::KeyEvent(key)) => {
                if let Some(injector) = injector.as_mut()
                    && let Err(error) = injector.key(&key)
                {
                    warn!("tecla não injetada: {error}");
                }
            }
            Some(Payload::PointerEvent(pointer)) => {
                if let Some(injector) = injector.as_mut() {
                    // O monitor capturado pode mudar (reabertura, troca de modo).
                    let current = state.target();
                    if current != target
                        && let Some(display) = current
                    {
                        injector.set_target(display);
                        target = current;
                    }
                    if let Err(error) = injector.pointer(&pointer) {
                        warn!("mouse não injetado: {error}");
                    }
                }
            }
            Some(Payload::Error(error)) => {
                bail!("cliente reportou erro: {}", error.message);
            }
            Some(
                Payload::Hello(_)
                | Payload::HelloAck(_)
                | Payload::Pong(_)
                | Payload::VideoFrame(_),
            )
            | None => {}
        }
    }
    Ok(())
}

async fn reject(stream: &mut SendStream, code: ErrorCode, message: &str) {
    let envelope = Envelope {
        payload: Some(Payload::Error(ProtocolError {
            code: code as i32,
            message: message.to_owned(),
        })),
    };
    let _ = send_envelope(stream, &envelope).await;
}

/// ID do dispositivo a partir da chave pública recebida, para os logs. Na
/// Fase 2 o coordenador passa a autorizar por essa identidade.
fn describe_device(public_key: &[u8]) -> String {
    <[u8; 32]>::try_from(public_key).map_or_else(
        |_| "sem identidade".to_owned(),
        |key| {
            format!(
                "ID {}",
                omegadesk_identity::DeviceId::from_signing_key(&key)
            )
        },
    )
}
