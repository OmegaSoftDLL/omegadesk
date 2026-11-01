//! Hardware H.264 encoder via Windows Media Foundation: Intel Quick Sync,
//! NVIDIA NVENC, and AMD AMF, using the hardware MFT registered by the GPU driver.
//!
//! Hardware MFTs are asynchronous: they signal via events when they accept an
//! input frame (`METransformNeedInput`) and when encoded output is ready
//! (`METransformHaveOutput`).
//!
//! When a Direct3D 11 device and texture are supplied ([`crate::D3d11Texture`]),
//! the encoder binds an `IMFDXGIDeviceManager` to the MFT (`MFT_MESSAGE_SET_D3D_MANAGER`),
//! converts the captured `BGRA` texture into an `NV12` texture on the GPU via
//! `ID3D11VideoProcessor::VideoProcessorBlt`, and wraps the `NV12` surface in an
//! `IMFMediaBuffer` via `MFCreateDXGISurfaceBuffer` for zero-copy GPU encoding.
//!
//! References:
//! - `IronRDP` (`ironrdp-rdpecam-native` and `ironrdp-egfx-native`, MIT/Apache-2.0):
//!   media types, `ProcessOutput`, SPS/PPS sequence header, `STREAM_CHANGE`;
//! - Sunshine (`src/nvenc/nvenc_base.cpp`, `src/platform/windows/display_vram.cpp`):
//!   single-frame VBV buffer CBR, zero B-frames, color space signaled in the VUI;
//! - `RustDesk` (`libs/scrap/src/dxgi/mod.rs`): `ID3D11VideoProcessor` setup.

#![allow(unsafe_code, reason = "Media Foundation and Direct3D 11 COM APIs")]

use std::collections::VecDeque;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use windows::Win32::Foundation::RECT;
use windows::Win32::Graphics::Direct3D11::{
    D3D11_BIND_RENDER_TARGET, D3D11_BIND_SHADER_RESOURCE, D3D11_TEX2D_VPIV, D3D11_TEX2D_VPOV,
    D3D11_TEXTURE2D_DESC, D3D11_USAGE_DEFAULT, D3D11_VIDEO_FRAME_FORMAT_PROGRESSIVE,
    D3D11_VIDEO_PROCESSOR_CONTENT_DESC, D3D11_VIDEO_PROCESSOR_INPUT_VIEW_DESC,
    D3D11_VIDEO_PROCESSOR_OUTPUT_VIEW_DESC, D3D11_VIDEO_PROCESSOR_OUTPUT_VIEW_DESC_0,
    D3D11_VIDEO_PROCESSOR_STREAM, D3D11_VIDEO_USAGE_OPTIMAL_SPEED, D3D11_VPIV_DIMENSION_TEXTURE2D,
    D3D11_VPOV_DIMENSION_TEXTURE2D, ID3D11Device, ID3D11Texture2D, ID3D11VideoContext,
    ID3D11VideoDevice, ID3D11VideoProcessor, ID3D11VideoProcessorEnumerator,
    ID3D11VideoProcessorInputView, ID3D11VideoProcessorOutputView,
};
use windows::Win32::Graphics::Dxgi::Common::{DXGI_FORMAT_NV12, DXGI_RATIONAL, DXGI_SAMPLE_DESC};
use windows::Win32::Media::MediaFoundation::{
    CODECAPI_AVEncCommonBufferSize, CODECAPI_AVEncCommonMeanBitRate,
    CODECAPI_AVEncCommonRateControlMode, CODECAPI_AVEncMPVDefaultBPictureCount,
    CODECAPI_AVEncMPVGOPSize, CODECAPI_AVEncVideoForceKeyFrame, CODECAPI_AVLowLatencyMode,
    ICodecAPI, IMF2DBuffer, IMFActivate, IMFDXGIDeviceManager, IMFMediaBuffer,
    IMFMediaEventGenerator, IMFMediaType, IMFSample, IMFTransform, MEError, METransformHaveOutput,
    METransformNeedInput, MF_E_NO_EVENTS_AVAILABLE, MF_E_TRANSFORM_NEED_MORE_INPUT,
    MF_E_TRANSFORM_STREAM_CHANGE, MF_EVENT_FLAG_NO_WAIT, MF_LOW_LATENCY, MF_MT_AVG_BITRATE,
    MF_MT_FRAME_RATE, MF_MT_FRAME_SIZE, MF_MT_INTERLACE_MODE, MF_MT_MAJOR_TYPE,
    MF_MT_MPEG_SEQUENCE_HEADER, MF_MT_MPEG2_PROFILE, MF_MT_PIXEL_ASPECT_RATIO, MF_MT_SUBTYPE,
    MF_MT_VIDEO_NOMINAL_RANGE, MF_MT_YUV_MATRIX, MF_TRANSFORM_ASYNC_UNLOCK, MF_VERSION,
    MFCreateDXGIDeviceManager, MFCreateDXGISurfaceBuffer, MFCreateMediaType, MFCreateMemoryBuffer,
    MFCreateSample, MFMediaType_Video, MFNominalRange_16_235, MFSTARTUP_FULL,
    MFSampleExtension_CleanPoint, MFStartup, MFT_CATEGORY_VIDEO_ENCODER, MFT_ENUM_FLAG_HARDWARE,
    MFT_ENUM_FLAG_SORTANDFILTER, MFT_FRIENDLY_NAME_Attribute, MFT_MESSAGE_NOTIFY_BEGIN_STREAMING,
    MFT_MESSAGE_NOTIFY_END_OF_STREAM, MFT_MESSAGE_NOTIFY_END_STREAMING,
    MFT_MESSAGE_NOTIFY_START_OF_STREAM, MFT_MESSAGE_SET_D3D_MANAGER, MFT_OUTPUT_DATA_BUFFER,
    MFT_OUTPUT_STREAM_PROVIDES_SAMPLES, MFT_REGISTER_TYPE_INFO, MFTEnumEx, MFVideoFormat_H264,
    MFVideoFormat_NV12, MFVideoInterlace_Progressive, MFVideoTransferMatrix_BT601,
    eAVEncCommonRateControlMode_CBR, eAVEncH264VProfile_Base,
};
use windows::Win32::System::Com::{COINIT_MULTITHREADED, CoInitializeEx, CoTaskMemFree};
use windows::Win32::System::Variant::VARIANT;
use windows::core::{GUID, Interface};

use crate::{CodecError, EncodedFrame, EncoderSettings, RawFrame, VideoEncoder, bgra_to_nv12};

/// Deadline for the MFT to request input or produce output. A wedged driver
/// (TDR or GPU removal) becomes an error instead of hanging capture forever.
const EVENT_DEADLINE: Duration = Duration::from_millis(250);

/// Sleep interval between non-blocking event polls while waiting.
const POLL_INTERVAL: Duration = Duration::from_micros(250);

/// Long GOP: keyframes are generated when explicitly requested.
const GOP_SIZE: u32 = 0xFFFF;

fn mf_error(context: &str, error: &windows::core::Error) -> CodecError {
    CodecError::Platform(format!("{context}: {error}"))
}

fn startup() -> Result<(), CodecError> {
    static STARTED: OnceLock<Result<(), String>> = OnceLock::new();
    STARTED
        .get_or_init(|| {
            // SAFETY: takes no pointers; `OnceLock` guarantees a single call
            // per process, and Media Foundation remains initialized until
            // process exit (`MFShutdown` is never called).
            unsafe { MFStartup(MF_VERSION, MFSTARTUP_FULL) }.map_err(|e| format!("MFStartup: {e}"))
        })
        .clone()
        .map_err(CodecError::Platform)
}

const fn join_u64(high: u32, low: u32) -> u64 {
    ((high as u64) << 32) | low as u64
}

/// Lists available hardware H.264 encoders in priority order.
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
    // SAFETY: `input` and `output` are local structs alive for the call, and
    // `array`/`count` are local out-parameters receiving the `CoTaskMemAlloc`
    // buffer and element count.
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
    // SAFETY: on success with a non-null pointer, `array` points to `count`
    // `IMFActivate` pointers (`Option<IMFActivate>` has the same layout as a
    // nullable interface pointer) owned by us. `Option::take` moves each COM
    // reference into the `Vec` leaving `None` in place, so freeing the array
    // afterwards does not double-release any interface.
    let entries = unsafe { std::slice::from_raw_parts_mut(array, count as usize) };
    let activates = entries.iter_mut().filter_map(Option::take).collect();
    // SAFETY: `array` was allocated by `MFTEnumEx` via `CoTaskMemAlloc`, is
    // freed exactly once here, and `entries` is not used afterwards.
    unsafe { CoTaskMemFree(Some(array.cast_const().cast())) };
    Ok(activates)
}

fn friendly_name(activate: &IMFActivate) -> String {
    let mut buffer = [0u16; 256];
    let mut length = 0u32;
    // SAFETY: `activate` is a valid `IMFActivate`; `windows-rs` passes both the
    // pointer and length of `buffer`, and `length` is a local out-parameter.
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
        "hardware encoder".to_owned()
    }
}

/// Sets attributes shared by both input and output media types.
fn set_video_attributes(
    media_type: &IMFMediaType,
    frame_size: u64,
    frame_rate: u64,
) -> windows::core::Result<()> {
    // SAFETY: `media_type` is a valid `IMFMediaType`; static GUID key and value copied by value.
    unsafe { media_type.SetGUID(&MF_MT_MAJOR_TYPE, &MFMediaType_Video) }?;
    // SAFETY: `media_type` is a valid `IMFMediaType`; static GUID key and value copied by value.
    unsafe { media_type.SetUINT64(&MF_MT_FRAME_SIZE, frame_size) }?;
    // SAFETY: `media_type` is a valid `IMFMediaType`; static GUID key and value copied by value.
    unsafe { media_type.SetUINT64(&MF_MT_FRAME_RATE, frame_rate) }?;
    // SAFETY: `media_type` is a valid `IMFMediaType`; static GUID key and value copied by value.
    unsafe { media_type.SetUINT64(&MF_MT_PIXEL_ASPECT_RATIO, join_u64(1, 1)) }?;
    // SAFETY: `media_type` is a valid `IMFMediaType`; static GUID key and value copied by value.
    unsafe {
        media_type.SetUINT32(
            &MF_MT_INTERLACE_MODE,
            MFVideoInterlace_Progressive.0.cast_unsigned(),
        )
    }?;
    // Signal BT.601 limited range in the VUI to match our BGRA → NV12 conversion.
    // SAFETY: `media_type` is a valid `IMFMediaType`; static GUID key and value copied by value.
    unsafe {
        media_type.SetUINT32(
            &MF_MT_YUV_MATRIX,
            MFVideoTransferMatrix_BT601.0.cast_unsigned(),
        )
    }?;
    // SAFETY: `media_type` is a valid `IMFMediaType`; static GUID key and value copied by value.
    unsafe {
        media_type.SetUINT32(
            &MF_MT_VIDEO_NOMINAL_RANGE,
            MFNominalRange_16_235.0.cast_unsigned(),
        )
    }?;
    Ok(())
}

/// GPU-side `BGRA` → `NV12` converter and `IMFDXGIDeviceManager` binding for
/// zero-copy hardware encoding.
struct D3d11Pipeline {
    _manager: IMFDXGIDeviceManager,
    video_device: ID3D11VideoDevice,
    video_context: ID3D11VideoContext,
    enumerator: ID3D11VideoProcessorEnumerator,
    processor: ID3D11VideoProcessor,
    surfaces: [(ID3D11Texture2D, ID3D11VideoProcessorOutputView); 2],
    next_slot: usize,
}

impl D3d11Pipeline {
    fn new(
        device: &ID3D11Device,
        transform: &IMFTransform,
        width: u32,
        height: u32,
        fps: u32,
    ) -> windows::core::Result<Self> {
        let video_device: ID3D11VideoDevice = device.cast()?;
        // SAFETY: `device` is a valid `ID3D11Device` and returns its immediate context.
        let immediate_context = unsafe { device.GetImmediateContext() }?;
        let video_context: ID3D11VideoContext = immediate_context.cast()?;

        let mut reset_token = 0u32;
        let mut manager = None;
        // SAFETY: `reset_token` and `manager` are local out-parameters.
        unsafe { MFCreateDXGIDeviceManager(&raw mut reset_token, &raw mut manager) }?;
        let manager: IMFDXGIDeviceManager = manager.ok_or_else(windows::core::Error::empty)?;
        // SAFETY: `manager` and `device` are valid COM interfaces and `reset_token`
        // is the token returned by `MFCreateDXGIDeviceManager`.
        unsafe { manager.ResetDevice(device, reset_token) }?;

        let content_desc = D3D11_VIDEO_PROCESSOR_CONTENT_DESC {
            InputFrameFormat: D3D11_VIDEO_FRAME_FORMAT_PROGRESSIVE,
            InputFrameRate: DXGI_RATIONAL {
                Numerator: fps,
                Denominator: 1,
            },
            InputWidth: width,
            InputHeight: height,
            OutputFrameRate: DXGI_RATIONAL {
                Numerator: fps,
                Denominator: 1,
            },
            OutputWidth: width,
            OutputHeight: height,
            Usage: D3D11_VIDEO_USAGE_OPTIMAL_SPEED,
        };
        // SAFETY: `video_device` is valid and `content_desc` is a local struct.
        let enumerator =
            unsafe { video_device.CreateVideoProcessorEnumerator(&raw const content_desc) }?;
        // SAFETY: `video_device` and `enumerator` are valid; rate conversion index 0.
        let processor = unsafe { video_device.CreateVideoProcessor(&enumerator, 0) }?;

        let rect = RECT {
            left: 0,
            top: 0,
            right: i32::try_from(width).unwrap_or(i32::MAX),
            bottom: i32::try_from(height).unwrap_or(i32::MAX),
        };
        // SAFETY: `video_context` and `processor` are valid; disables driver auto-postprocessing.
        unsafe { video_context.VideoProcessorSetStreamAutoProcessingMode(&processor, 0, false) };
        // SAFETY: `video_context` and `processor` are valid; progressive frames.
        unsafe {
            video_context.VideoProcessorSetStreamFrameFormat(
                &processor,
                0,
                D3D11_VIDEO_FRAME_FORMAT_PROGRESSIVE,
            );
        };
        // SAFETY: `video_context`, `processor`, and `rect` are valid.
        unsafe {
            video_context.VideoProcessorSetStreamSourceRect(
                &processor,
                0,
                true,
                Some(&raw const rect),
            );
        };
        // SAFETY: `video_context`, `processor`, and `rect` are valid.
        unsafe {
            video_context.VideoProcessorSetStreamDestRect(
                &processor,
                0,
                true,
                Some(&raw const rect),
            );
        };

        let surface0 =
            Self::create_nv12_surface(device, &video_device, &enumerator, width, height)?;
        let surface1 =
            Self::create_nv12_surface(device, &video_device, &enumerator, width, height)?;

        // Bind the DXGI device manager to the MFT so it accepts DXGI surface samples directly.
        let raw_manager = manager.as_raw() as usize;
        // SAFETY: `transform` is valid and `raw_manager` is the `IUnknown` pointer
        // of `manager`, which outlives streaming on `transform`.
        unsafe { transform.ProcessMessage(MFT_MESSAGE_SET_D3D_MANAGER, raw_manager) }?;

        Ok(Self {
            _manager: manager,
            video_device,
            video_context,
            enumerator,
            processor,
            surfaces: [surface0, surface1],
            next_slot: 0,
        })
    }

    fn create_nv12_surface(
        device: &ID3D11Device,
        video_device: &ID3D11VideoDevice,
        enumerator: &ID3D11VideoProcessorEnumerator,
        width: u32,
        height: u32,
    ) -> windows::core::Result<(ID3D11Texture2D, ID3D11VideoProcessorOutputView)> {
        let desc = D3D11_TEXTURE2D_DESC {
            Width: width,
            Height: height,
            MipLevels: 1,
            ArraySize: 1,
            Format: DXGI_FORMAT_NV12,
            SampleDesc: DXGI_SAMPLE_DESC {
                Count: 1,
                Quality: 0,
            },
            Usage: D3D11_USAGE_DEFAULT,
            BindFlags: (D3D11_BIND_RENDER_TARGET.0 | D3D11_BIND_SHADER_RESOURCE.0).cast_unsigned(),
            CPUAccessFlags: 0,
            MiscFlags: 0,
        };
        let mut texture = None;
        // SAFETY: `desc` is a valid `NV12` texture description and `texture` is a local out-parameter.
        unsafe { device.CreateTexture2D(&raw const desc, None, Some(&raw mut texture)) }?;
        let texture = texture.ok_or_else(windows::core::Error::empty)?;

        let view_desc = D3D11_VIDEO_PROCESSOR_OUTPUT_VIEW_DESC {
            ViewDimension: D3D11_VPOV_DIMENSION_TEXTURE2D,
            Anonymous: D3D11_VIDEO_PROCESSOR_OUTPUT_VIEW_DESC_0 {
                Texture2D: D3D11_TEX2D_VPOV { MipSlice: 0 },
            },
        };
        let mut output_view = None;
        // SAFETY: `texture` and `enumerator` are valid and `view_desc` selects mip 0.
        unsafe {
            video_device.CreateVideoProcessorOutputView(
                &texture,
                enumerator,
                &raw const view_desc,
                Some(&raw mut output_view),
            )
        }?;
        let output_view = output_view.ok_or_else(windows::core::Error::empty)?;
        Ok((texture, output_view))
    }

    /// Converts `bgra_texture` into the next `NV12` GPU surface and wraps it in
    /// an [`IMFSample`] via `MFCreateDXGISurfaceBuffer`.
    fn convert_to_sample(
        &mut self,
        bgra_texture: &ID3D11Texture2D,
        sample_time: i64,
        sample_duration: i64,
    ) -> windows::core::Result<IMFSample> {
        let input_desc = D3D11_VIDEO_PROCESSOR_INPUT_VIEW_DESC {
            FourCC: 0,
            ViewDimension: D3D11_VPIV_DIMENSION_TEXTURE2D,
            Anonymous:
                windows::Win32::Graphics::Direct3D11::D3D11_VIDEO_PROCESSOR_INPUT_VIEW_DESC_0 {
                    Texture2D: D3D11_TEX2D_VPIV {
                        MipSlice: 0,
                        ArraySlice: 0,
                    },
                },
        };
        let mut input_view: Option<ID3D11VideoProcessorInputView> = None;
        // SAFETY: `bgra_texture` and `self.enumerator` belong to the same
        // `ID3D11Device` and `input_view` is a local out-parameter.
        unsafe {
            self.video_device.CreateVideoProcessorInputView(
                bgra_texture,
                &self.enumerator,
                &raw const input_desc,
                Some(&raw mut input_view),
            )
        }?;
        let input_view = input_view.ok_or_else(windows::core::Error::empty)?;

        let slot = self.next_slot;
        self.next_slot ^= 1;
        let (nv12_texture, output_view) = &self.surfaces[slot];

        let streams = [D3D11_VIDEO_PROCESSOR_STREAM {
            Enable: true.into(),
            OutputIndex: 0,
            InputFrameOrField: 0,
            PastFrames: 0,
            FutureFrames: 0,
            ppPastSurfaces: std::ptr::null_mut(),
            pInputSurface: std::mem::ManuallyDrop::new(Some(input_view)),
            ppFutureSurfaces: std::ptr::null_mut(),
            ppPastSurfacesRight: std::ptr::null_mut(),
            pInputSurfaceRight: std::mem::ManuallyDrop::new(None),
            ppFutureSurfacesRight: std::ptr::null_mut(),
        }];
        // SAFETY: `self.processor`, `output_view`, and `streams[0].pInputSurface`
        // are valid interfaces on the same `ID3D11Device`.
        let blt_result = unsafe {
            self.video_context
                .VideoProcessorBlt(&self.processor, output_view, 0, &streams)
        };
        let [stream] = streams;
        drop(std::mem::ManuallyDrop::into_inner(stream.pInputSurface));
        drop(std::mem::ManuallyDrop::into_inner(
            stream.pInputSurfaceRight,
        ));
        blt_result?;

        // SAFETY: `nv12_texture` is a valid `ID3D11Texture2D` subresource 0.
        let buffer: IMFMediaBuffer =
            unsafe { MFCreateDXGISurfaceBuffer(&ID3D11Texture2D::IID, nv12_texture, 0, false) }?;
        if let Ok(buffer_2d) = buffer.cast::<IMF2DBuffer>() {
            // SAFETY: `buffer_2d` is a valid 2D surface buffer; returns byte length by value.
            if let Ok(len) = unsafe { buffer_2d.GetContiguousLength() } {
                // SAFETY: `buffer` is valid and `len` is its contiguous 2D byte length.
                let _ = unsafe { buffer.SetCurrentLength(len) };
            }
        }

        // SAFETY: takes no arguments and returns an owned empty sample.
        let sample = unsafe { MFCreateSample() }?;
        // SAFETY: `sample` and `buffer` are valid COM objects.
        unsafe { sample.AddBuffer(&buffer) }?;
        // SAFETY: `sample` is valid; timestamp passed by value.
        unsafe { sample.SetSampleTime(sample_time) }?;
        // SAFETY: `sample` is valid; duration passed by value.
        unsafe { sample.SetSampleDuration(sample_duration) }?;
        Ok(sample)
    }
}

/// Hardware H.264 encoder backed by Windows Media Foundation.
pub struct MediaFoundationEncoder {
    activate: IMFActivate,
    transform: IMFTransform,
    events: IMFMediaEventGenerator,
    codec_api: Option<ICodecAPI>,
    d3d11: Option<D3d11Pipeline>,
    name: String,
    width: u32,
    height: u32,
    frame_duration_100ns: i64,
    started: Instant,
    pending_input: u32,
    sequence_header: Option<Vec<u8>>,
    ready: VecDeque<EncodedFrame>,
}

// SAFETY: all access goes through `&mut self`, so two threads never call into
// the MFT concurrently. `new` initializes the multithreaded COM apartment
// (MTA), and asynchronous hardware MFTs and Media Foundation attribute/sample
// objects are free-threaded; as long as the MTA remains active in the process,
// they may be invoked from another thread. In practice the encoder is created
// and used on the dedicated capture thread.
unsafe impl Send for MediaFoundationEncoder {}

impl std::fmt::Debug for MediaFoundationEncoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MediaFoundationEncoder")
            .field("name", &self.name)
            .field("width", &self.width)
            .field("height", &self.height)
            .field("zero_copy_gpu", &self.d3d11.is_some())
            .finish_non_exhaustive()
    }
}

impl MediaFoundationEncoder {
    /// Opens the first available hardware H.264 encoder for `width`x`height`
    /// frames. Odd dimensions drop their trailing column/row.
    ///
    /// Should be constructed on the thread that will encode frames.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError::HardwareUnavailable`] if no hardware encoder is
    /// present, or another [`CodecError`] if configuration fails.
    pub fn new(width: u32, height: u32, settings: EncoderSettings) -> Result<Self, CodecError> {
        Self::new_with_device(width, height, settings, None)
    }

    /// Opens the first available hardware H.264 encoder for `width`x`height`
    /// frames, optionally binding `d3d11_device` via `IMFDXGIDeviceManager` for
    /// zero-copy GPU texture encoding.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError::HardwareUnavailable`] if no hardware encoder is
    /// present, or another [`CodecError`] if configuration fails.
    pub fn new_with_device(
        width: u32,
        height: u32,
        settings: EncoderSettings,
        d3d11_device: Option<&ID3D11Device>,
    ) -> Result<Self, CodecError> {
        let (even_width, even_height) = (width & !1, height & !1);
        if even_width < 2 || even_height < 2 {
            return Err(CodecError::InvalidDimensions { width, height });
        }
        // COM may already be initialized on this thread; any apartment mode works.
        // SAFETY: reserved first argument is `None` as required; the return
        // value (including `RPC_E_CHANGED_MODE`) is intentionally ignored and
        // COM stays initialized for the lifetime of the thread.
        let _ = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
        startup()?;

        let mut last_error = CodecError::HardwareUnavailable;
        for activate in hardware_encoders()? {
            let name = friendly_name(&activate);
            match Self::open(
                activate,
                name.clone(),
                even_width,
                even_height,
                settings,
                d3d11_device,
            ) {
                Ok(encoder) => return Ok(encoder),
                Err(error) => last_error = CodecError::Platform(format!("{name}: {error}")),
            }
        }
        Err(last_error)
    }

    /// Friendly name of the selected hardware encoder (e.g. "Intel® Quick Sync Video H.264 Encoder MFT").
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Whether the encoder is bound to a Direct3D 11 device for zero-copy GPU encoding.
    #[must_use]
    pub const fn is_zero_copy(&self) -> bool {
        self.d3d11.is_some()
    }

    fn open(
        activate: IMFActivate,
        name: String,
        width: u32,
        height: u32,
        settings: EncoderSettings,
        d3d11_device: Option<&ID3D11Device>,
    ) -> Result<Self, CodecError> {
        #[allow(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "fps clamped to 1..=240"
        )]
        let fps = settings.max_fps.clamp(1.0, 240.0).round() as u32;
        let frame_size = join_u64(width, height);
        let frame_rate = join_u64(fps, 1);

        // SAFETY: `activate` is a valid `IMFActivate` returned by `MFTEnumEx`;
        // the activated object is owned by us and shut down in `Drop`.
        let transform: IMFTransform =
            unsafe { activate.ActivateObject() }.map_err(|e| mf_error("ActivateObject", &e))?;
        // SAFETY: `transform` is the newly activated MFT.
        let attributes =
            unsafe { transform.GetAttributes() }.map_err(|e| mf_error("GetAttributes", &e))?;
        // SAFETY: `attributes` is the MFT attribute store; static GUID key.
        unsafe { attributes.SetUINT32(&MF_TRANSFORM_ASYNC_UNLOCK, 1) }
            .map_err(|e| mf_error("ASYNC_UNLOCK", &e))?;
        // SAFETY: same attribute store; static GUID key.
        let _ = unsafe { attributes.SetUINT32(&MF_LOW_LATENCY, 1) };
        let events: IMFMediaEventGenerator = transform
            .cast()
            .map_err(|e| mf_error("IMFMediaEventGenerator", &e))?;

        let d3d11 = d3d11_device
            .and_then(|device| D3d11Pipeline::new(device, &transform, width, height, fps).ok());

        let codec_api: Option<ICodecAPI> = transform.cast().ok();
        if let Some(api) = &codec_api {
            // Optional low-latency tuning: each vendor driver accepts a subset.
            // SAFETY: `api` is the MFT's `ICodecAPI`; static GUID and local
            // `VARIANT` alive for the duration of the call.
            let _ = unsafe { api.SetValue(&CODECAPI_AVLowLatencyMode, &VARIANT::from(true)) };
            // SAFETY: same as above.
            let _ = unsafe {
                api.SetValue(
                    &CODECAPI_AVEncCommonRateControlMode,
                    &VARIANT::from(eAVEncCommonRateControlMode_CBR.0.cast_unsigned()),
                )
            };
            // Single-frame VBV buffer: avoids frame-size spikes that add network queueing (Sunshine).
            // SAFETY: same as above.
            let _ = unsafe {
                api.SetValue(
                    &CODECAPI_AVEncCommonBufferSize,
                    &VARIANT::from(settings.bitrate_bps / fps.max(1)),
                )
            };
            // SAFETY: same as above.
            let _ = unsafe {
                api.SetValue(&CODECAPI_AVEncMPVDefaultBPictureCount, &VARIANT::from(0u32))
            };
            // SAFETY: same as above.
            let _ = unsafe { api.SetValue(&CODECAPI_AVEncMPVGOPSize, &VARIANT::from(GOP_SIZE)) };
        }

        // SAFETY: takes no arguments and returns a newly owned empty media type.
        let output =
            unsafe { MFCreateMediaType() }.map_err(|e| mf_error("MFCreateMediaType", &e))?;
        let output_error = |e: windows::core::Error| mf_error("output media type", &e);
        set_video_attributes(&output, frame_size, frame_rate).map_err(output_error)?;
        // SAFETY: `output` is the media type created above; static GUIDs.
        unsafe { output.SetGUID(&MF_MT_SUBTYPE, &MFVideoFormat_H264) }.map_err(output_error)?;
        // SAFETY: same media type; static key and value copied by value.
        unsafe { output.SetUINT32(&MF_MT_AVG_BITRATE, settings.bitrate_bps) }
            .map_err(output_error)?;
        // Baseline profile: zero B-frames and compatible with OpenH264 (like IronRDP).
        // SAFETY: same media type; static key and value copied by value.
        unsafe {
            output.SetUINT32(
                &MF_MT_MPEG2_PROFILE,
                eAVEncH264VProfile_Base.0.cast_unsigned(),
            )
        }
        .map_err(output_error)?;
        // SAFETY: `transform` is valid, has a single output stream (id 0), and
        // `output` is a complete media type; the MFT retains its own reference.
        unsafe { transform.SetOutputType(0, &output, 0) }
            .map_err(|e| mf_error("SetOutputType", &e))?;

        // SAFETY: takes no arguments and returns a newly owned empty media type.
        let input =
            unsafe { MFCreateMediaType() }.map_err(|e| mf_error("MFCreateMediaType", &e))?;
        set_video_attributes(&input, frame_size, frame_rate)
            .map_err(|e| mf_error("input media type", &e))?;
        // SAFETY: `input` is the media type created above; static GUIDs.
        unsafe { input.SetGUID(&MF_MT_SUBTYPE, &MFVideoFormat_NV12) }
            .map_err(|e| mf_error("input media type", &e))?;
        // SAFETY: `transform` is valid, input stream 0, and `input` is complete.
        unsafe { transform.SetInputType(0, &input, 0) }
            .map_err(|e| mf_error("SetInputType", &e))?;

        // SAFETY: `transform` is valid with both input and output types set;
        // the message does not use its parameter (`0`).
        unsafe { transform.ProcessMessage(MFT_MESSAGE_NOTIFY_BEGIN_STREAMING, 0) }
            .map_err(|e| mf_error("stream start", &e))?;
        // SAFETY: same as above, following `BEGIN_STREAMING`.
        unsafe { transform.ProcessMessage(MFT_MESSAGE_NOTIFY_START_OF_STREAM, 0) }
            .map_err(|e| mf_error("stream start", &e))?;

        // SAFETY: `transform` is valid with output type configured on stream 0.
        let sequence_header = unsafe { transform.GetOutputCurrentType(0) }
            .ok()
            .and_then(|current| blob(&current, &MF_MT_MPEG_SEQUENCE_HEADER));

        Ok(Self {
            activate,
            transform,
            events,
            codec_api,
            d3d11,
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

    /// Drains all pending MFT events without blocking. Encoded frames are
    /// pushed into `self.ready` and input requests increment `self.pending_input`.
    fn drain_events(&mut self) -> Result<(), CodecError> {
        loop {
            // SAFETY: `events` is the MFT event generator; with `NO_WAIT` the
            // call does not block and returns an owned event reference.
            let event = match unsafe { self.events.GetEvent(MF_EVENT_FLAG_NO_WAIT) } {
                Ok(event) => event,
                Err(e) if e.code() == MF_E_NO_EVENTS_AVAILABLE => return Ok(()),
                Err(e) => return Err(mf_error("GetEvent", &e)),
            };
            // SAFETY: `event` is a valid `IMFMediaEvent`; type is returned by value.
            let kind = unsafe { event.GetType() }.map_err(|e| mf_error("GetType", &e))?;
            if kind == METransformNeedInput.0.cast_unsigned() {
                self.pending_input += 1;
            } else if kind == METransformHaveOutput.0.cast_unsigned() {
                self.collect_output()?;
            } else if kind == MEError.0.cast_unsigned() {
                // SAFETY: `event` is a valid `IMFMediaEvent`; HRESULT is returned by value.
                let status = unsafe { event.GetStatus() }.unwrap_or_default();
                return Err(CodecError::Platform(format!(
                    "hardware encoder reported error {status:?}"
                )));
            }
        }
    }

    /// Waits up to [`EVENT_DEADLINE`] until `done` returns `true`.
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
        // SAFETY: `transform` is valid and has output stream 0; info is returned by value.
        let info = unsafe { self.transform.GetOutputStreamInfo(0) }
            .map_err(|e| mf_error("GetOutputStreamInfo", &e))?;
        let provides_samples =
            info.dwFlags & MFT_OUTPUT_STREAM_PROVIDES_SAMPLES.0.cast_unsigned() != 0;
        let sample = if provides_samples {
            None
        } else {
            // SAFETY: takes no arguments and returns an owned empty sample.
            let sample = unsafe { MFCreateSample() }.map_err(|e| mf_error("MFCreateSample", &e))?;
            // SAFETY: takes only the buffer size (at least 1 byte) and returns an owned buffer.
            let buffer = unsafe { MFCreateMemoryBuffer(info.cbSize.max(1)) }
                .map_err(|e| mf_error("MFCreateMemoryBuffer", &e))?;
            // SAFETY: `sample` and `buffer` are valid objects created above;
            // the sample retains its own reference to the buffer.
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
        // SAFETY: `output` has a single element for output stream 0, with
        // `pSample` set to `None` when the MFT allocates samples or to our
        // preallocated sample otherwise; `status` is a local out-parameter.
        // Immediately below, `pSample` and `pEvents` are unwrapped from
        // `ManuallyDrop` so any COM references written by the MFT are released once.
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
                // The driver renegotiated its output format (Quick Sync does
                // this on the first frame). Select the updated available output
                // type like IronRDP; the frame will follow on the next
                // `METransformHaveOutput` event.
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
            // SAFETY: `transform` is valid; an index past the end returns
            // `MF_E_NO_MORE_TYPES`, which terminates the loop as an error.
            let candidate = unsafe { self.transform.GetOutputAvailableType(0, index) }
                .map_err(|e| mf_error("GetOutputAvailableType", &e))?;
            // SAFETY: `candidate` is a valid media type; static GUID key.
            if unsafe { candidate.GetGUID(&MF_MT_SUBTYPE) }.ok() != Some(MFVideoFormat_H264) {
                continue;
            }
            // SAFETY: `transform` is valid, stream 0, and `candidate` was
            // offered by the MFT itself.
            unsafe { self.transform.SetOutputType(0, &candidate, 0) }
                .map_err(|e| mf_error("SetOutputType", &e))?;
            // SAFETY: `transform` is valid with output type just configured.
            self.sequence_header = unsafe { self.transform.GetOutputCurrentType(0) }
                .ok()
                .and_then(|current| blob(&current, &MF_MT_MPEG_SEQUENCE_HEADER));
            return Ok(());
        }
        Err(CodecError::Platform(
            "no H.264 output media type after stream change".into(),
        ))
    }

    fn frame_from_sample(&mut self, sample: &IMFSample) -> Result<EncodedFrame, CodecError> {
        // SAFETY: `sample` is a valid output sample from the MFT; returns an owned contiguous buffer.
        let buffer = unsafe { sample.ConvertToContiguousBuffer() }
            .map_err(|e| mf_error("ConvertToContiguousBuffer", &e))?;
        let mut pointer = std::ptr::null_mut();
        let mut length = 0u32;
        // SAFETY: `buffer` is valid; `pointer` and `length` are local
        // out-parameters receiving the start pointer and current data length.
        unsafe { buffer.Lock(&raw mut pointer, None, Some(&raw mut length)) }
            .map_err(|e| mf_error("Lock", &e))?;
        let mut data = if pointer.is_null() {
            Vec::new()
        } else {
            // SAFETY: after a successful `Lock`, `pointer` points to `length`
            // initialized bytes valid until `Unlock` below; the slice is copied
            // into a `Vec` before unlocking.
            unsafe { std::slice::from_raw_parts(pointer, length as usize) }.to_vec()
        };
        // SAFETY: pairs with the successful `Lock` above; no slice references the buffer anymore.
        let _ = unsafe { buffer.Unlock() };

        // SAFETY: `sample` is valid; static GUID key and value returned by value.
        let keyframe = unsafe { sample.GetUINT32(&MFSampleExtension_CleanPoint) }
            .is_ok_and(|clean| clean != 0);
        if keyframe && !contains_sps(&data) {
            if self.sequence_header.is_none() {
                // SAFETY: `transform` is valid with output type configured on stream 0.
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

    /// Creates an NV12 input sample, using the zero-copy GPU `ID3D11VideoProcessor`
    /// path when `frame.d3d11_texture` is available and falling back to CPU conversion.
    fn input_sample(&mut self, frame: RawFrame<'_>) -> Result<IMFSample, CodecError> {
        let time = i64::try_from(self.started.elapsed().as_nanos() / 100).unwrap_or(i64::MAX);
        if frame.width == self.width
            && frame.height == self.height
            && let (Some(d3d11), Some(gpu)) = (&mut self.d3d11, frame.d3d11_texture)
        {
            if let Ok(sample) =
                d3d11.convert_to_sample(gpu.texture, time, self.frame_duration_100ns)
            {
                return Ok(sample);
            }
            // Unbind D3D manager and fall back to CPU buffers if GPU conversion fails.
            // SAFETY: `transform` is valid; passing `0` detaches the D3D manager.
            let _ = unsafe {
                self.transform
                    .ProcessMessage(MFT_MESSAGE_SET_D3D_MANAGER, 0)
            };
            self.d3d11 = None;
        }
        self.cpu_input_sample(frame, time)
    }

    fn cpu_input_sample(&self, frame: RawFrame<'_>, time: i64) -> Result<IMFSample, CodecError> {
        let (width, height) = (self.width as usize, self.height as usize);
        let nv12_len = width * height * 3 / 2;
        let length = u32::try_from(nv12_len).map_err(|_| CodecError::InvalidDimensions {
            width: self.width,
            height: self.height,
        })?;

        // SAFETY: takes only the maximum byte length and returns an owned buffer.
        let buffer = unsafe { MFCreateMemoryBuffer(length) }
            .map_err(|e| mf_error("MFCreateMemoryBuffer", &e))?;
        let mut pointer = std::ptr::null_mut();
        // SAFETY: `buffer` is valid and `pointer` is a local out-parameter receiving the buffer start.
        unsafe { buffer.Lock(&raw mut pointer, None, None) }.map_err(|e| mf_error("Lock", &e))?;
        // SAFETY: after a successful `Lock`, `pointer` points to at least
        // `length` (`== nv12_len`) writable bytes exclusively owned by us until
        // `Unlock`. `bgra_to_nv12` writes every byte before `Unlock`, and
        // `destination` does not outlive `Unlock`.
        let destination = unsafe { std::slice::from_raw_parts_mut(pointer, nv12_len) };
        bgra_to_nv12(frame.bgra, frame.width as usize, width, height, destination);
        // SAFETY: pairs with `Lock` above; `destination` is not used after this point.
        unsafe { buffer.Unlock() }.map_err(|e| mf_error("Unlock", &e))?;
        // SAFETY: `length` equals the buffer capacity and all `length` bytes were initialized above.
        unsafe { buffer.SetCurrentLength(length) }.map_err(|e| mf_error("SetCurrentLength", &e))?;

        // SAFETY: takes no arguments and returns an owned empty sample.
        let sample = unsafe { MFCreateSample() }.map_err(|e| mf_error("MFCreateSample", &e))?;
        // SAFETY: `sample` and `buffer` are valid; the sample retains its own reference to `buffer`.
        unsafe { sample.AddBuffer(&buffer) }.map_err(|e| mf_error("AddBuffer", &e))?;
        // SAFETY: `sample` is valid; timestamp passed by value.
        unsafe { sample.SetSampleTime(time) }.map_err(|e| mf_error("sample time", &e))?;
        // SAFETY: `sample` is valid; duration passed by value.
        unsafe { sample.SetSampleDuration(self.frame_duration_100ns) }
            .map_err(|e| mf_error("sample duration", &e))?;
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
                "hardware encoder stopped requesting input frames".into(),
            ));
        }
        let sample = self.input_sample(frame)?;
        // SAFETY: `transform` is streaming and requested input
        // (`pending_input > 0`); `sample` is a complete NV12 sample and the MFT
        // retains its own reference.
        unsafe { self.transform.ProcessInput(0, &sample, 0) }
            .map_err(|e| mf_error("ProcessInput", &e))?;
        self.pending_input -= 1;

        // Wait for this frame's output. If the driver holds the frame past the
        // deadline, it will be drained on the next `encode` call.
        self.wait_until(|encoder| !encoder.ready.is_empty())?;
        Ok(self.ready.drain(..).collect())
    }

    fn request_keyframe(&mut self) {
        if let Some(api) = &self.codec_api {
            // SAFETY: `api` is the MFT's `ICodecAPI`; static GUID and local
            // `VARIANT` alive for the duration of the call.
            let _ =
                unsafe { api.SetValue(&CODECAPI_AVEncVideoForceKeyFrame, &VARIANT::from(1u32)) };
        }
    }

    /// `CODECAPI_AVEncCommonMeanBitRate` is a dynamic property on the NVENC, Quick
    /// Sync and AMF H.264 MFTs, so the rate controller follows the new target
    /// on the next frame without a stream restart. A driver that rejects the
    /// property reports `false` and the caller recreates the encoder.
    fn set_bitrate(&mut self, bitrate_bps: u32) -> bool {
        let Some(api) = &self.codec_api else {
            return false;
        };
        // SAFETY: `api` is the MFT's `ICodecAPI`; static GUID and local
        // `VARIANT` alive for the duration of the call.
        let applied = unsafe {
            api.SetValue(
                &CODECAPI_AVEncCommonMeanBitRate,
                &VARIANT::from(bitrate_bps),
            )
        };
        if applied.is_err() {
            return false;
        }
        // Keep the single-frame VBV window proportional to the new bitrate; this
        // one is best effort (not every vendor exposes it dynamically).
        let fps = u32::try_from(10_000_000i64 / self.frame_duration_100ns.max(1)).unwrap_or(60);
        // SAFETY: same as above.
        let _ = unsafe {
            api.SetValue(
                &CODECAPI_AVEncCommonBufferSize,
                &VARIANT::from(bitrate_bps / fps.max(1)),
            )
        };
        true
    }
}

impl Drop for MediaFoundationEncoder {
    fn drop(&mut self) {
        // Release the hardware encoding session: consumer GPUs cap how many
        // concurrent encoder sessions can exist at the same time.
        // SAFETY: `transform` is still valid; the message does not use its parameter.
        let _ = unsafe {
            self.transform
                .ProcessMessage(MFT_MESSAGE_NOTIFY_END_OF_STREAM, 0)
        };
        // SAFETY: same as above.
        let _ = unsafe {
            self.transform
                .ProcessMessage(MFT_MESSAGE_NOTIFY_END_STREAMING, 0)
        };
        // SAFETY: `activate` created the MFT; no MFT methods are called after
        // this point, and struct fields only release their COM references.
        let _ = unsafe { self.activate.ShutdownObject() };
    }
}

fn blob(attributes: &IMFMediaType, key: &GUID) -> Option<Vec<u8>> {
    // SAFETY: `attributes` is a valid media type and `key` is a valid GUID.
    let size = unsafe { attributes.GetBlobSize(key) }.ok()?;
    let mut data = vec![0u8; size as usize];
    // SAFETY: `windows-rs` passes both the pointer and length of `data`, which
    // matches the exact byte size returned by `GetBlobSize`.
    unsafe { attributes.GetBlob(key, &mut data, None) }.ok()?;
    Some(data)
}

/// Checks whether an Annex B bitstream contains an SPS NAL unit (type 7).
/// H.264 emulation prevention forbids `00 00 01` inside a NAL payload, so a
/// byte-window scan is exact.
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

    /// Encodes on hardware and decodes with OpenH264: every submitted frame
    /// must come out and decode cleanly. On machines without a hardware GPU
    /// (such as CI runners), verifies that [`CodecError::HardwareUnavailable`]
    /// is returned.
    #[test]
    fn hardware_round_trip_when_available() {
        // 641x361: intentionally odd dimensions.
        let (width, height) = (641_u32, 361_u32);
        let encoder = super::MediaFoundationEncoder::new(width, height, EncoderSettings::default());
        let mut encoder = match encoder {
            Ok(encoder) => encoder,
            Err(CodecError::HardwareUnavailable) => return,
            Err(error) => panic!("hardware encoder failed: {error}"),
        };
        let mut decoder = OpenH264Decoder::new().unwrap();
        let mut bgra = vec![0u8; (width * height * 4) as usize];
        let mut sent = 0;
        let mut decoded = 0;
        let mut last_image = None;
        for round in 0..60u32 {
            // Moving vertical stripe so every frame changes.
            for (index, pixel) in bgra.as_chunks_mut::<4>().0.iter_mut().enumerate() {
                let x = u32::try_from(index).unwrap() % width;
                let value = if (x + round * 8) % 128 < 64 { 230 } else { 30 };
                pixel.copy_from_slice(&[value, value, value, 255]);
            }
            let frames = encoder
                .encode(RawFrame::from_bgra(width, height, &bgra))
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
            "only {decoded} of {sent} frames were decoded"
        );
        let image = last_image.unwrap();
        // Pixel inside a bright or dark stripe: verify it did not wash out to gray.
        let [_, red, _, _] = image.xrgb[(180 * 640 + 10) as usize].to_be_bytes();
        assert!(!(60..200).contains(&red), "degraded image: {red}");
    }

    /// Exercises the zero-copy D3D11 texture -> `ID3D11VideoProcessor` (BGRA->NV12)
    /// -> `MFCreateDXGISurfaceBuffer` hardware encoding path when a hardware GPU is
    /// available.
    #[test]
    #[allow(unsafe_code)]
    fn hardware_zero_copy_d3d11_round_trip() {
        use windows::Win32::Foundation::HMODULE;
        use windows::Win32::Graphics::Direct3D::D3D_DRIVER_TYPE_HARDWARE;
        use windows::Win32::Graphics::Direct3D11::{
            D3D11_BIND_SHADER_RESOURCE, D3D11_CREATE_DEVICE_BGRA_SUPPORT,
            D3D11_CREATE_DEVICE_VIDEO_SUPPORT, D3D11_SDK_VERSION, D3D11_SUBRESOURCE_DATA,
            D3D11_TEXTURE2D_DESC, D3D11_USAGE_DEFAULT, D3D11CreateDevice,
        };
        use windows::Win32::Graphics::Dxgi::Common::{
            DXGI_FORMAT_B8G8R8A8_UNORM, DXGI_SAMPLE_DESC,
        };

        let (width, height) = (640_u32, 360_u32);
        let (mut device, mut context) = (None, None);
        let flags = D3D11_CREATE_DEVICE_BGRA_SUPPORT | D3D11_CREATE_DEVICE_VIDEO_SUPPORT;
        // SAFETY: standard D3D11 hardware device creation with video support.
        let hr = unsafe {
            D3D11CreateDevice(
                None,
                D3D_DRIVER_TYPE_HARDWARE,
                HMODULE::default(),
                flags,
                None,
                D3D11_SDK_VERSION,
                Some(&raw mut device),
                None,
                Some(&raw mut context),
            )
        };
        let (Some(device), Some(context)) = (hr.ok().and(device), context) else {
            return;
        };

        let settings = EncoderSettings::default();
        let mut encoder = match super::MediaFoundationEncoder::new_with_device(
            width,
            height,
            settings,
            Some(&device),
        ) {
            Ok(encoder) => encoder,
            Err(CodecError::HardwareUnavailable) => return,
            Err(error) => panic!("hardware zero-copy encoder failed: {error}"),
        };

        let bgra = vec![200u8; (width * height * 4) as usize];
        let desc = D3D11_TEXTURE2D_DESC {
            Width: width,
            Height: height,
            MipLevels: 1,
            ArraySize: 1,
            Format: DXGI_FORMAT_B8G8R8A8_UNORM,
            SampleDesc: DXGI_SAMPLE_DESC {
                Count: 1,
                Quality: 0,
            },
            Usage: D3D11_USAGE_DEFAULT,
            BindFlags: D3D11_BIND_SHADER_RESOURCE.0.cast_unsigned(),
            CPUAccessFlags: 0,
            MiscFlags: 0,
        };
        let init = D3D11_SUBRESOURCE_DATA {
            pSysMem: bgra.as_ptr().cast(),
            SysMemPitch: width * 4,
            SysMemSlicePitch: 0,
        };
        let mut texture = None;
        // SAFETY: `desc` and `init` are valid and backed by `bgra`.
        unsafe {
            device.CreateTexture2D(
                &raw const desc,
                Some(&raw const init),
                Some(&raw mut texture),
            )
        }
        .unwrap();
        let texture = texture.unwrap();

        let mut decoder = OpenH264Decoder::new().unwrap();
        let mut decoded = 0;
        for _ in 0..20 {
            let gpu = crate::D3d11Texture {
                device: &device,
                context: &context,
                texture: &texture,
            };
            let frames = encoder
                .encode(RawFrame {
                    width,
                    height,
                    bgra: &bgra,
                    d3d11_texture: Some(gpu),
                })
                .unwrap();
            for frame in frames {
                if decoder.decode(&frame.data).unwrap().is_some() {
                    decoded += 1;
                }
            }
        }
        assert!(
            decoded >= 15,
            "only {decoded} frames decoded in zero-copy path"
        );
    }
}
