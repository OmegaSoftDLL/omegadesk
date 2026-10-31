//! H.264 por hardware com Media Foundation (Windows): Intel Quick Sync,
//! NVIDIA NVENC e AMD AMF, pelo MFT de hardware que o driver registra.
//!
//! MFTs de hardware são assíncronos: avisam por eventos quando querem um
//! quadro (`METransformNeedInput`) e quando há saída (`METransformHaveOutput`).
//! Referências usadas:
//! - `IronRDP` (`ironrdp-rdpecam-native` e `ironrdp-egfx-native`, MIT/Apache-2.0):
//!   tipos de mídia, `ProcessOutput`, cabeçalho SPS/PPS, `STREAM_CHANGE`;
//! - Sunshine (`src/nvenc/nvenc_base.cpp`): CBR com buffer de um quadro, sem
//!   B-frames, cor sinalizada na VUI.

#![allow(unsafe_code, reason = "APIs COM da Media Foundation")]

use std::collections::VecDeque;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use windows::Win32::Media::MediaFoundation::{
    CODECAPI_AVEncCommonBufferSize, CODECAPI_AVEncCommonRateControlMode,
    CODECAPI_AVEncMPVDefaultBPictureCount, CODECAPI_AVEncMPVGOPSize,
    CODECAPI_AVEncVideoForceKeyFrame, CODECAPI_AVLowLatencyMode, ICodecAPI, IMFActivate,
    IMFMediaEventGenerator, IMFMediaType, IMFSample, IMFTransform, MEError, METransformHaveOutput,
    METransformNeedInput, MF_E_NO_EVENTS_AVAILABLE, MF_E_TRANSFORM_NEED_MORE_INPUT,
    MF_E_TRANSFORM_STREAM_CHANGE, MF_EVENT_FLAG_NO_WAIT, MF_LOW_LATENCY, MF_MT_AVG_BITRATE,
    MF_MT_FRAME_RATE, MF_MT_FRAME_SIZE, MF_MT_INTERLACE_MODE, MF_MT_MAJOR_TYPE,
    MF_MT_MPEG_SEQUENCE_HEADER, MF_MT_MPEG2_PROFILE, MF_MT_PIXEL_ASPECT_RATIO, MF_MT_SUBTYPE,
    MF_MT_VIDEO_NOMINAL_RANGE, MF_MT_YUV_MATRIX, MF_TRANSFORM_ASYNC_UNLOCK, MF_VERSION,
    MFCreateMediaType, MFCreateMemoryBuffer, MFCreateSample, MFMediaType_Video,
    MFNominalRange_16_235, MFSTARTUP_FULL, MFSampleExtension_CleanPoint, MFStartup,
    MFT_CATEGORY_VIDEO_ENCODER, MFT_ENUM_FLAG_HARDWARE, MFT_ENUM_FLAG_SORTANDFILTER,
    MFT_FRIENDLY_NAME_Attribute, MFT_MESSAGE_NOTIFY_BEGIN_STREAMING,
    MFT_MESSAGE_NOTIFY_END_OF_STREAM, MFT_MESSAGE_NOTIFY_END_STREAMING,
    MFT_MESSAGE_NOTIFY_START_OF_STREAM, MFT_OUTPUT_DATA_BUFFER, MFT_OUTPUT_STREAM_PROVIDES_SAMPLES,
    MFT_REGISTER_TYPE_INFO, MFTEnumEx, MFVideoFormat_H264, MFVideoFormat_NV12,
    MFVideoInterlace_Progressive, MFVideoTransferMatrix_BT601, eAVEncCommonRateControlMode_CBR,
    eAVEncH264VProfile_Base,
};
use windows::Win32::System::Com::{COINIT_MULTITHREADED, CoInitializeEx, CoTaskMemFree};
use windows::Win32::System::Variant::VARIANT;
use windows::core::{GUID, Interface};

use crate::{CodecError, EncodedFrame, EncoderSettings, RawFrame, VideoEncoder, bgra_to_nv12};

/// Prazo para o MFT pedir um quadro ou devolver a saída. Um driver travado
/// (TDR, GPU removida) vira erro em vez de travar a captura para sempre.
const EVENT_DEADLINE: Duration = Duration::from_millis(250);

/// Pausa entre consultas de eventos enquanto espera.
const POLL_INTERVAL: Duration = Duration::from_micros(250);

/// GOP longo: keyframes só quando pedidos.
const GOP_SIZE: u32 = 0xFFFF;

fn mf_error(context: &str, error: &windows::core::Error) -> CodecError {
    CodecError::Platform(format!("{context}: {error}"))
}

fn startup() -> Result<(), CodecError> {
    static STARTED: OnceLock<Result<(), String>> = OnceLock::new();
    STARTED
        .get_or_init(|| {
            // SAFETY: sem ponteiros; o OnceLock garante uma única chamada por
            // processo, e a Media Foundation fica ligada até o processo sair
            // (MFShutdown nunca é chamado, então nada a desfazer).
            unsafe { MFStartup(MF_VERSION, MFSTARTUP_FULL) }.map_err(|e| format!("MFStartup: {e}"))
        })
        .clone()
        .map_err(CodecError::Platform)
}

const fn join_u64(high: u32, low: u32) -> u64 {
    ((high as u64) << 32) | low as u64
}

/// Lista os encoders H.264 de hardware, do preferido ao menos preferido.
fn hardware_encoders() -> Result<Vec<IMFActivate>, CodecError> {
    let input = MFT_REGISTER_TYPE_INFO {
        guidMajorType: MFMediaType_Video,
        guidSubtype: MFVideoFormat_NV12,
    };
    let output = MFT_REGISTER_TYPE_INFO {
        guidMajorType: MFMediaType_Video,
        guidSubtype: MFVideoFormat_H264,
    };
    let mut array: *mut Option<IMFActivate> = std::ptr::null_mut();
    let mut count = 0u32;
    // SAFETY: `input` e `output` são structs locais vivas durante a chamada;
    // `array` e `count` são variáveis locais onde a função escreve o vetor
    // alocado com CoTaskMemAlloc e o número de elementos.
    unsafe {
        MFTEnumEx(
            MFT_CATEGORY_VIDEO_ENCODER,
            MFT_ENUM_FLAG_HARDWARE | MFT_ENUM_FLAG_SORTANDFILTER,
            Some(&raw const input),
            Some(&raw const output),
            &raw mut array,
            &raw mut count,
        )
    }
    .map_err(|e| mf_error("MFTEnumEx", &e))?;
    if array.is_null() {
        return Ok(Vec::new());
    }
    // SAFETY: com sucesso e ponteiro não nulo, `array` aponta para `count`
    // ponteiros IMFActivate (`Option<IMFActivate>` tem o mesmo layout de um
    // ponteiro anulável), alocados para nós e sem outro dono. `take` move
    // cada referência para o Vec, deixando None no lugar, então liberar o
    // vetor depois não solta nenhum objeto duas vezes.
    let entries = unsafe { std::slice::from_raw_parts_mut(array, count as usize) };
    let activates = entries.iter_mut().filter_map(Option::take).collect();
    // SAFETY: o vetor foi alocado pelo MFTEnumEx com CoTaskMemAlloc, é
    // liberado uma única vez e `entries` não é mais usado.
    unsafe { CoTaskMemFree(Some(array.cast_const().cast())) };
    Ok(activates)
}

fn friendly_name(activate: &IMFActivate) -> String {
    let mut buffer = [0u16; 256];
    let mut length = 0u32;
    // SAFETY: `activate` é um IMFActivate válido; o windows-rs passa ponteiro
    // e tamanho de `buffer` juntos, então a função não escreve além dele (se
    // o nome não couber, devolve erro), e `length` é uma variável local.
    let result = unsafe {
        activate.GetString(
            &MFT_FRIENDLY_NAME_Attribute,
            &mut buffer,
            Some(&raw mut length),
        )
    };
    if result.is_ok() {
        String::from_utf16_lossy(&buffer[..length as usize])
    } else {
        "encoder de hardware".to_owned()
    }
}

/// Atributos comuns aos tipos de entrada e saída.
fn set_video_attributes(
    media_type: &IMFMediaType,
    frame_size: u64,
    frame_rate: u64,
) -> windows::core::Result<()> {
    // SAFETY: `media_type` é um IMFMediaType válido; chave estática e valor copiado.
    unsafe { media_type.SetGUID(&MF_MT_MAJOR_TYPE, &MFMediaType_Video) }?;
    // SAFETY: `media_type` é um IMFMediaType válido; chave estática e valor copiado.
    unsafe { media_type.SetUINT64(&MF_MT_FRAME_SIZE, frame_size) }?;
    // SAFETY: `media_type` é um IMFMediaType válido; chave estática e valor copiado.
    unsafe { media_type.SetUINT64(&MF_MT_FRAME_RATE, frame_rate) }?;
    // SAFETY: `media_type` é um IMFMediaType válido; chave estática e valor copiado.
    unsafe { media_type.SetUINT64(&MF_MT_PIXEL_ASPECT_RATIO, join_u64(1, 1)) }?;
    // SAFETY: `media_type` é um IMFMediaType válido; chave estática e valor copiado.
    unsafe {
        media_type.SetUINT32(
            &MF_MT_INTERLACE_MODE,
            MFVideoInterlace_Progressive.0.cast_unsigned(),
        )
    }?;
    // Cor sinalizada na VUI: BT.601 faixa limitada, igual à conversão.
    // SAFETY: `media_type` é um IMFMediaType válido; chave estática e valor copiado.
    unsafe {
        media_type.SetUINT32(
            &MF_MT_YUV_MATRIX,
            MFVideoTransferMatrix_BT601.0.cast_unsigned(),
        )
    }?;
    // SAFETY: `media_type` é um IMFMediaType válido; chave estática e valor copiado.
    unsafe {
        media_type.SetUINT32(
            &MF_MT_VIDEO_NOMINAL_RANGE,
            MFNominalRange_16_235.0.cast_unsigned(),
        )
    }?;
    Ok(())
}

/// Encoder H.264 por hardware via Media Foundation.
pub struct MediaFoundationEncoder {
    activate: IMFActivate,
    transform: IMFTransform,
    events: IMFMediaEventGenerator,
    codec_api: Option<ICodecAPI>,
    name: String,
    width: u32,
    height: u32,
    frame_duration_100ns: i64,
    started: Instant,
    pending_input: u32,
    sequence_header: Option<Vec<u8>>,
    ready: VecDeque<EncodedFrame>,
}

// SAFETY: todo uso passa por `&mut self`, então nunca há duas threads no MFT
// ao mesmo tempo. O construtor entra no apartamento multithread (MTA), e os
// MFTs de hardware assíncronos e os objetos de atributos/amostras da Media
// Foundation são free-threaded; enquanto alguma thread mantiver o MTA, eles
// podem ser chamados de outra thread do processo. Na prática o encoder é
// criado e usado pela thread de captura.
unsafe impl Send for MediaFoundationEncoder {}

impl std::fmt::Debug for MediaFoundationEncoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MediaFoundationEncoder")
            .field("name", &self.name)
            .field("width", &self.width)
            .field("height", &self.height)
            .finish_non_exhaustive()
    }
}

impl MediaFoundationEncoder {
    /// Abre o primeiro encoder H.264 de hardware disponível para quadros de
    /// `width`x`height`. Dimensões ímpares perdem a última coluna/linha.
    ///
    /// Precisa ser criado na thread que vai codificar.
    ///
    /// # Errors
    ///
    /// Retorna [`CodecError::HardwareUnavailable`] se não houver encoder de
    /// hardware, ou outro erro se a configuração falhar.
    pub fn new(width: u32, height: u32, settings: EncoderSettings) -> Result<Self, CodecError> {
        let (even_width, even_height) = (width & !1, height & !1);
        if even_width < 2 || even_height < 2 {
            return Err(CodecError::InvalidDimensions { width, height });
        }
        // Pode já estar inicializado nesta thread; qualquer modo serve.
        // SAFETY: o reservado é None, como a API exige; o resultado (inclusive
        // RPC_E_CHANGED_MODE) é ignorado de propósito e o COM fica ligado até
        // a thread terminar, então nenhum objeto sobrevive ao CoUninitialize.
        let _ = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
        startup()?;

        let mut last_error = CodecError::HardwareUnavailable;
        for activate in hardware_encoders()? {
            let name = friendly_name(&activate);
            match Self::open(activate, name.clone(), even_width, even_height, settings) {
                Ok(encoder) => return Ok(encoder),
                Err(error) => last_error = CodecError::Platform(format!("{name}: {error}")),
            }
        }
        Err(last_error)
    }

    /// Nome do encoder escolhido (por exemplo, "Intel® Quick Sync Video H.264 Encoder MFT").
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    fn open(
        activate: IMFActivate,
        name: String,
        width: u32,
        height: u32,
        settings: EncoderSettings,
    ) -> Result<Self, CodecError> {
        #[allow(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "fps entre 1 e 240"
        )]
        let fps = settings.max_fps.clamp(1.0, 240.0).round() as u32;
        let frame_size = join_u64(width, height);
        let frame_rate = join_u64(fps, 1);

        // SAFETY: `activate` é um IMFActivate válido devolvido pelo MFTEnumEx;
        // o objeto criado é de nossa posse e o ShutdownObject fica no Drop.
        let transform: IMFTransform =
            unsafe { activate.ActivateObject() }.map_err(|e| mf_error("ActivateObject", &e))?;
        // SAFETY: `transform` é o MFT recém-ativado.
        let attributes =
            unsafe { transform.GetAttributes() }.map_err(|e| mf_error("GetAttributes", &e))?;
        // SAFETY: `attributes` é o repositório de atributos do MFT; chave estática.
        unsafe { attributes.SetUINT32(&MF_TRANSFORM_ASYNC_UNLOCK, 1) }
            .map_err(|e| mf_error("ASYNC_UNLOCK", &e))?;
        // SAFETY: mesmo repositório de atributos; chave estática.
        let _ = unsafe { attributes.SetUINT32(&MF_LOW_LATENCY, 1) };
        let events: IMFMediaEventGenerator = transform
            .cast()
            .map_err(|e| mf_error("IMFMediaEventGenerator", &e))?;

        let codec_api: Option<ICodecAPI> = transform.cast().ok();
        if let Some(api) = &codec_api {
            // Ajustes opcionais: cada driver aceita um subconjunto.
            // SAFETY: `api` é a ICodecAPI do MFT; GUID estático e VARIANT
            // local vivo durante a chamada (o MFT só lê o valor).
            let _ = unsafe { api.SetValue(&CODECAPI_AVLowLatencyMode, &VARIANT::from(true)) };
            // SAFETY: como acima.
            let _ = unsafe {
                api.SetValue(
                    &CODECAPI_AVEncCommonRateControlMode,
                    &VARIANT::from(eAVEncCommonRateControlMode_CBR.0.cast_unsigned()),
                )
            };
            // Buffer de um quadro: sem picos que atrasem a rede (Sunshine).
            // SAFETY: como acima.
            let _ = unsafe {
                api.SetValue(
                    &CODECAPI_AVEncCommonBufferSize,
                    &VARIANT::from(settings.bitrate_bps / fps.max(1)),
                )
            };
            // SAFETY: como acima.
            let _ = unsafe {
                api.SetValue(&CODECAPI_AVEncMPVDefaultBPictureCount, &VARIANT::from(0u32))
            };
            // SAFETY: como acima.
            let _ = unsafe { api.SetValue(&CODECAPI_AVEncMPVGOPSize, &VARIANT::from(GOP_SIZE)) };
        }

        // SAFETY: sem argumentos; devolve um tipo de mídia vazio, de nossa posse.
        let output =
            unsafe { MFCreateMediaType() }.map_err(|e| mf_error("MFCreateMediaType", &e))?;
        let output_error = |e: windows::core::Error| mf_error("tipo de saída", &e);
        set_video_attributes(&output, frame_size, frame_rate).map_err(output_error)?;
        // SAFETY: `output` é o tipo de mídia criado acima; GUIDs estáticos.
        unsafe { output.SetGUID(&MF_MT_SUBTYPE, &MFVideoFormat_H264) }.map_err(output_error)?;
        // SAFETY: mesmo tipo de mídia; chave estática e valor copiado.
        unsafe { output.SetUINT32(&MF_MT_AVG_BITRATE, settings.bitrate_bps) }
            .map_err(output_error)?;
        // Baseline: sem B-frames e decodificável pelo OpenH264 (como o IronRDP).
        // SAFETY: mesmo tipo de mídia; chave estática e valor copiado.
        unsafe {
            output.SetUINT32(
                &MF_MT_MPEG2_PROFILE,
                eAVEncH264VProfile_Base.0.cast_unsigned(),
            )
        }
        .map_err(output_error)?;
        // SAFETY: `transform` é válido, tem um único stream de saída (id 0) e
        // `output` é um tipo de mídia completo; o MFT guarda a própria referência.
        unsafe { transform.SetOutputType(0, &output, 0) }
            .map_err(|e| mf_error("SetOutputType", &e))?;

        // SAFETY: sem argumentos; devolve um tipo de mídia vazio, de nossa posse.
        let input =
            unsafe { MFCreateMediaType() }.map_err(|e| mf_error("MFCreateMediaType", &e))?;
        set_video_attributes(&input, frame_size, frame_rate)
            .map_err(|e| mf_error("tipo de entrada", &e))?;
        // SAFETY: `input` é o tipo de mídia criado acima; GUIDs estáticos.
        unsafe { input.SetGUID(&MF_MT_SUBTYPE, &MFVideoFormat_NV12) }
            .map_err(|e| mf_error("tipo de entrada", &e))?;
        // SAFETY: `transform` é válido, stream de entrada 0, `input` completo.
        unsafe { transform.SetInputType(0, &input, 0) }
            .map_err(|e| mf_error("SetInputType", &e))?;

        // SAFETY: `transform` válido com tipos de entrada e saída já definidos;
        // a mensagem não usa o parâmetro (0).
        unsafe { transform.ProcessMessage(MFT_MESSAGE_NOTIFY_BEGIN_STREAMING, 0) }
            .map_err(|e| mf_error("início do stream", &e))?;
        // SAFETY: como acima, depois do BEGIN_STREAMING.
        unsafe { transform.ProcessMessage(MFT_MESSAGE_NOTIFY_START_OF_STREAM, 0) }
            .map_err(|e| mf_error("início do stream", &e))?;

        // SAFETY: `transform` válido com tipo de saída definido no stream 0.
        let sequence_header = unsafe { transform.GetOutputCurrentType(0) }
            .ok()
            .and_then(|current| blob(&current, &MF_MT_MPEG_SEQUENCE_HEADER));

        Ok(Self {
            activate,
            transform,
            events,
            codec_api,
            name,
            width,
            height,
            frame_duration_100ns: 10_000_000 / i64::from(fps),
            started: Instant::now(),
            pending_input: 0,
            sequence_header,
            ready: VecDeque::new(),
        })
    }

    /// Processa todos os eventos pendentes, sem bloquear. Saídas vão para
    /// `self.ready`, pedidos de entrada para `self.pending_input`.
    fn drain_events(&mut self) -> Result<(), CodecError> {
        loop {
            // SAFETY: `events` é o gerador de eventos do MFT; com NO_WAIT a
            // chamada não bloqueia e o evento devolvido é de nossa posse.
            let event = match unsafe { self.events.GetEvent(MF_EVENT_FLAG_NO_WAIT) } {
                Ok(event) => event,
                Err(e) if e.code() == MF_E_NO_EVENTS_AVAILABLE => return Ok(()),
                Err(e) => return Err(mf_error("GetEvent", &e)),
            };
            // SAFETY: `event` é um IMFMediaEvent válido; o tipo volta por valor.
            let kind = unsafe { event.GetType() }.map_err(|e| mf_error("GetType", &e))?;
            if kind == METransformNeedInput.0.cast_unsigned() {
                self.pending_input += 1;
            } else if kind == METransformHaveOutput.0.cast_unsigned() {
                self.collect_output()?;
            } else if kind == MEError.0.cast_unsigned() {
                // SAFETY: `event` é um IMFMediaEvent válido; o HRESULT volta por valor.
                let status = unsafe { event.GetStatus() }.unwrap_or_default();
                return Err(CodecError::Platform(format!(
                    "o encoder de hardware reportou erro {status:?}"
                )));
            }
        }
    }

    /// Espera, com prazo, até `done` ficar verdadeiro.
    fn wait_until(&mut self, done: impl Fn(&Self) -> bool) -> Result<bool, CodecError> {
        let deadline = Instant::now() + EVENT_DEADLINE;
        loop {
            self.drain_events()?;
            if done(self) {
                return Ok(true);
            }
            if Instant::now() >= deadline {
                return Ok(false);
            }
            std::thread::sleep(POLL_INTERVAL);
        }
    }

    fn collect_output(&mut self) -> Result<(), CodecError> {
        // SAFETY: `transform` é válido e tem o stream de saída 0; a info volta por valor.
        let info = unsafe { self.transform.GetOutputStreamInfo(0) }
            .map_err(|e| mf_error("GetOutputStreamInfo", &e))?;
        let provides_samples =
            info.dwFlags & MFT_OUTPUT_STREAM_PROVIDES_SAMPLES.0.cast_unsigned() != 0;
        let sample = if provides_samples {
            None
        } else {
            // SAFETY: sem argumentos; devolve uma amostra vazia, de nossa posse.
            let sample = unsafe { MFCreateSample() }.map_err(|e| mf_error("MFCreateSample", &e))?;
            // SAFETY: só recebe o tamanho (pelo menos 1 byte); o buffer é de nossa posse.
            let buffer = unsafe { MFCreateMemoryBuffer(info.cbSize.max(1)) }
                .map_err(|e| mf_error("MFCreateMemoryBuffer", &e))?;
            // SAFETY: `sample` e `buffer` são objetos válidos criados acima; a
            // amostra guarda a própria referência ao buffer.
            unsafe { sample.AddBuffer(&buffer) }.map_err(|e| mf_error("AddBuffer", &e))?;
            Some(sample)
        };
        let mut output = [MFT_OUTPUT_DATA_BUFFER {
            dwStreamID: 0,
            pSample: std::mem::ManuallyDrop::new(sample),
            dwStatus: 0,
            pEvents: std::mem::ManuallyDrop::new(None),
        }];
        let mut status = 0u32;
        // SAFETY: `output` tem exatamente um elemento, para o único stream de
        // saída, com `pSample` nulo quando o MFT fornece as amostras ou com a
        // nossa amostra caso contrário; `status` é uma variável local. Logo
        // abaixo `pSample` e `pEvents` são retirados dos ManuallyDrop, então a
        // referência que o MFT escreve neles é liberada uma única vez.
        let result = unsafe {
            self.transform
                .ProcessOutput(0, &mut output, &raw mut status)
        };
        let [output] = output;
        let picture = std::mem::ManuallyDrop::into_inner(output.pSample);
        drop(std::mem::ManuallyDrop::into_inner(output.pEvents));
        match result {
            Ok(()) => {}
            Err(e) if e.code() == MF_E_TRANSFORM_NEED_MORE_INPUT => return Ok(()),
            Err(e) if e.code() == MF_E_TRANSFORM_STREAM_CHANGE => {
                // O driver ajustou o formato de saída (Quick Sync faz isso no
                // primeiro quadro). Como no IronRDP, escolhe de novo o tipo
                // disponível; a saída volta com um novo METransformHaveOutput.
                return self.renegotiate_output();
            }
            Err(e) => return Err(mf_error("ProcessOutput", &e)),
        }
        if let Some(picture) = picture {
            let frame = self.frame_from_sample(&picture)?;
            self.ready.push_back(frame);
        }
        Ok(())
    }

    fn renegotiate_output(&mut self) -> Result<(), CodecError> {
        for index in 0u32.. {
            // SAFETY: `transform` é válido; um índice além do último só
            // devolve MF_E_NO_MORE_TYPES, que vira erro aqui.
            let candidate = unsafe { self.transform.GetOutputAvailableType(0, index) }
                .map_err(|e| mf_error("GetOutputAvailableType", &e))?;
            // SAFETY: `candidate` é um tipo de mídia válido; GUID estático.
            if unsafe { candidate.GetGUID(&MF_MT_SUBTYPE) }.ok() != Some(MFVideoFormat_H264) {
                continue;
            }
            // SAFETY: `transform` válido, stream 0, e `candidate` é um tipo que
            // o próprio MFT ofereceu.
            unsafe { self.transform.SetOutputType(0, &candidate, 0) }
                .map_err(|e| mf_error("SetOutputType", &e))?;
            // SAFETY: `transform` válido com tipo de saída recém-definido.
            self.sequence_header = unsafe { self.transform.GetOutputCurrentType(0) }
                .ok()
                .and_then(|current| blob(&current, &MF_MT_MPEG_SEQUENCE_HEADER));
            return Ok(());
        }
        Err(CodecError::Platform(
            "nenhum tipo de saída H.264 após a mudança de formato".into(),
        ))
    }

    fn frame_from_sample(&mut self, sample: &IMFSample) -> Result<EncodedFrame, CodecError> {
        // SAFETY: `sample` é uma amostra de saída válida do MFT; o buffer
        // contíguo devolvido é de nossa posse.
        let buffer = unsafe { sample.ConvertToContiguousBuffer() }
            .map_err(|e| mf_error("ConvertToContiguousBuffer", &e))?;
        let mut pointer = std::ptr::null_mut();
        let mut length = 0u32;
        // SAFETY: `buffer` é válido; `pointer` e `length` são variáveis locais
        // que recebem o início e o tamanho atual dos dados (o máximo não é pedido).
        unsafe { buffer.Lock(&raw mut pointer, None, Some(&raw mut length)) }
            .map_err(|e| mf_error("Lock", &e))?;
        let mut data = if pointer.is_null() {
            Vec::new()
        } else {
            // SAFETY: com o Lock bem-sucedido, `pointer` aponta para `length`
            // bytes inicializados do buffer, que ficam válidos até o Unlock
            // abaixo; o slice é copiado para um Vec antes disso.
            unsafe { std::slice::from_raw_parts(pointer, length as usize) }.to_vec()
        };
        // SAFETY: desfaz o Lock bem-sucedido acima; nada mais aponta para os dados.
        let _ = unsafe { buffer.Unlock() };

        // SAFETY: `sample` é válido; chave estática e valor devolvido por valor.
        let keyframe = unsafe { sample.GetUINT32(&MFSampleExtension_CleanPoint) }
            .is_ok_and(|clean| clean != 0);
        if keyframe && !contains_sps(&data) {
            if self.sequence_header.is_none() {
                // SAFETY: `transform` válido com tipo de saída definido no stream 0.
                self.sequence_header = unsafe { self.transform.GetOutputCurrentType(0) }
                    .ok()
                    .and_then(|current| blob(&current, &MF_MT_MPEG_SEQUENCE_HEADER));
            }
            if let Some(header) = &self.sequence_header {
                let mut with_header = Vec::with_capacity(header.len() + data.len());
                with_header.extend_from_slice(header);
                with_header.extend_from_slice(&data);
                data = with_header;
            }
        }
        Ok(EncodedFrame {
            data,
            keyframe,
            width: self.width,
            height: self.height,
        })
    }

    /// Cria a amostra NV12, convertendo direto no buffer da Media Foundation.
    fn input_sample(&self, frame: RawFrame<'_>) -> Result<IMFSample, CodecError> {
        let (width, height) = (self.width as usize, self.height as usize);
        let nv12_len = width * height * 3 / 2;
        let length = u32::try_from(nv12_len).map_err(|_| CodecError::InvalidDimensions {
            width: self.width,
            height: self.height,
        })?;

        // SAFETY: só recebe o tamanho máximo; o buffer é de nossa posse.
        let buffer = unsafe { MFCreateMemoryBuffer(length) }
            .map_err(|e| mf_error("MFCreateMemoryBuffer", &e))?;
        let mut pointer = std::ptr::null_mut();
        // SAFETY: `buffer` é válido e `pointer` é uma variável local que recebe
        // o início da memória; tamanhos não são pedidos (None).
        unsafe { buffer.Lock(&raw mut pointer, None, None) }.map_err(|e| mf_error("Lock", &e))?;
        // SAFETY: com o Lock bem-sucedido, `pointer` aponta para pelo menos
        // `length` (= `nv12_len`) bytes graváveis, só nossos até o Unlock. A
        // memória vem do alocador da Media Foundation, sem garantia de estar
        // zerada; `bgra_to_nv12` só escreve nela (cada byte uma vez) e o slice
        // não sobrevive ao Unlock.
        let destination = unsafe { std::slice::from_raw_parts_mut(pointer, nv12_len) };
        bgra_to_nv12(frame.bgra, frame.width as usize, width, height, destination);
        // SAFETY: desfaz o Lock acima; `destination` não é mais usado.
        unsafe { buffer.Unlock() }.map_err(|e| mf_error("Unlock", &e))?;
        // SAFETY: `length` é igual ao tamanho máximo do buffer e todos os bytes
        // foram escritos pela conversão.
        unsafe { buffer.SetCurrentLength(length) }.map_err(|e| mf_error("SetCurrentLength", &e))?;

        // SAFETY: sem argumentos; devolve uma amostra vazia, de nossa posse.
        let sample = unsafe { MFCreateSample() }.map_err(|e| mf_error("MFCreateSample", &e))?;
        // SAFETY: `sample` e `buffer` são válidos; a amostra guarda a própria
        // referência ao buffer.
        unsafe { sample.AddBuffer(&buffer) }.map_err(|e| mf_error("AddBuffer", &e))?;
        let time = i64::try_from(self.started.elapsed().as_nanos() / 100).unwrap_or(i64::MAX);
        // SAFETY: `sample` é válido; o tempo vai por valor.
        unsafe { sample.SetSampleTime(time) }.map_err(|e| mf_error("tempo da amostra", &e))?;
        // SAFETY: `sample` é válido; a duração vai por valor.
        unsafe { sample.SetSampleDuration(self.frame_duration_100ns) }
            .map_err(|e| mf_error("tempo da amostra", &e))?;
        Ok(sample)
    }
}

impl VideoEncoder for MediaFoundationEncoder {
    fn encode(&mut self, frame: RawFrame<'_>) -> Result<Vec<EncodedFrame>, CodecError> {
        if frame.width & !1 != self.width || frame.height & !1 != self.height {
            return Err(CodecError::InvalidDimensions {
                width: frame.width,
                height: frame.height,
            });
        }
        let expected = frame.width as usize * frame.height as usize * 4;
        if frame.bgra.len() != expected {
            return Err(CodecError::BufferSize {
                got: frame.bgra.len(),
                expected,
            });
        }

        if !self.wait_until(|encoder| encoder.pending_input > 0)? {
            return Err(CodecError::Platform(
                "o encoder de hardware parou de pedir quadros".into(),
            ));
        }
        let sample = self.input_sample(frame)?;
        // SAFETY: `transform` está em streaming e pediu entrada
        // (`pending_input > 0`); `sample` é uma amostra NV12 completa, da qual
        // o MFT guarda a própria referência.
        unsafe { self.transform.ProcessInput(0, &sample, 0) }
            .map_err(|e| mf_error("ProcessInput", &e))?;
        self.pending_input -= 1;

        // Espera a saída deste quadro. Se o driver segurar o quadro além do
        // prazo, ele sai na próxima chamada, junto com o seguinte.
        self.wait_until(|encoder| !encoder.ready.is_empty())?;
        Ok(self.ready.drain(..).collect())
    }

    fn request_keyframe(&mut self) {
        if let Some(api) = &self.codec_api {
            // SAFETY: `api` é a ICodecAPI do MFT; GUID estático e VARIANT local
            // vivo durante a chamada.
            let _ =
                unsafe { api.SetValue(&CODECAPI_AVEncVideoForceKeyFrame, &VARIANT::from(1u32)) };
        }
    }
}

impl Drop for MediaFoundationEncoder {
    fn drop(&mut self) {
        // Libera a sessão de hardware: placas de consumo limitam quantas
        // sessões de encoder podem existir ao mesmo tempo.
        // SAFETY: `transform` ainda é válido; a mensagem não usa o parâmetro.
        let _ = unsafe {
            self.transform
                .ProcessMessage(MFT_MESSAGE_NOTIFY_END_OF_STREAM, 0)
        };
        // SAFETY: como acima.
        let _ = unsafe {
            self.transform
                .ProcessMessage(MFT_MESSAGE_NOTIFY_END_STREAMING, 0)
        };
        // SAFETY: `activate` é o objeto que criou o MFT; depois disto nenhum
        // método do MFT é chamado, os campos só soltam suas referências.
        let _ = unsafe { self.activate.ShutdownObject() };
    }
}

fn blob(attributes: &IMFMediaType, key: &GUID) -> Option<Vec<u8>> {
    // SAFETY: `attributes` é um tipo de mídia válido e `key` um GUID vivo.
    let size = unsafe { attributes.GetBlobSize(key) }.ok()?;
    let mut data = vec![0u8; size as usize];
    // SAFETY: o windows-rs passa ponteiro e tamanho de `data` juntos, e
    // `data` tem exatamente o tamanho informado pelo GetBlobSize.
    unsafe { attributes.GetBlob(key, &mut data, None) }.ok()?;
    Some(data)
}

/// Procura uma NAL SPS (tipo 7) no bitstream Annex B. A prevenção de emulação
/// do H.264 impede `00 00 01` dentro de uma NAL, então a busca é segura.
fn contains_sps(data: &[u8]) -> bool {
    data.windows(4)
        .any(|w| w[..3] == [0, 0, 1] && w[3] & 0x1F == 7)
}

#[cfg(test)]
mod tests {
    use super::contains_sps;
    use crate::{
        CodecError, EncoderSettings, OpenH264Decoder, RawFrame, VideoDecoder, VideoEncoder,
    };

    #[test]
    fn finds_sps() {
        assert!(contains_sps(&[0, 0, 0, 1, 0x67, 0x42]));
        assert!(!contains_sps(&[0, 0, 0, 1, 0x65, 0x88]));
    }

    /// Codifica no hardware e decodifica com OpenH264: todo quadro enviado
    /// precisa sair e ser decodificado, e a imagem precisa bater. Sem GPU
    /// (como no CI), o teste só confere que o erro é "hardware indisponível".
    #[test]
    fn hardware_round_trip_when_available() {
        // 641x361: dimensões ímpares de propósito.
        let (width, height) = (641_u32, 361_u32);
        let encoder = super::MediaFoundationEncoder::new(width, height, EncoderSettings::default());
        let mut encoder = match encoder {
            Ok(encoder) => encoder,
            Err(CodecError::HardwareUnavailable) => return,
            Err(error) => panic!("encoder de hardware falhou: {error}"),
        };
        let mut decoder = OpenH264Decoder::new().unwrap();
        let mut bgra = vec![0u8; (width * height * 4) as usize];
        let mut sent = 0;
        let mut decoded = 0;
        let mut last_image = None;
        for round in 0..60u32 {
            // Uma faixa vertical que anda: todo quadro muda.
            for (index, pixel) in bgra.as_chunks_mut::<4>().0.iter_mut().enumerate() {
                let x = u32::try_from(index).unwrap() % width;
                let value = if (x + round * 8) % 128 < 64 { 230 } else { 30 };
                pixel.copy_from_slice(&[value, value, value, 255]);
            }
            let frames = encoder
                .encode(RawFrame {
                    width,
                    height,
                    bgra: &bgra,
                })
                .unwrap();
            sent += 1;
            for frame in frames {
                assert_eq!((frame.width, frame.height), (640, 360));
                if let Some(image) = decoder.decode(&frame.data).unwrap() {
                    decoded += 1;
                    last_image = Some(image);
                }
            }
        }
        assert!(
            decoded + 2 >= sent,
            "só {decoded} de {sent} quadros saíram decodificados"
        );
        let image = last_image.unwrap();
        // Pixel no meio de uma faixa clara ou escura: conferir que não virou cinza.
        let [_, red, _, _] = image.xrgb[(180 * 640 + 10) as usize].to_be_bytes();
        assert!(!(60..200).contains(&red), "imagem degradada: {red}");
    }
}
