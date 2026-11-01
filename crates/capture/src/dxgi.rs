//! DXGI Desktop Duplication backend (Windows 8 and newer).
//!
//! Pipeline modeled after Sunshine (`src/platform/windows/display_base.cpp`,
//! `display_ram.cpp`, and `display_vram.cpp`) and `RustDesk` (`libs/scrap/src/dxgi/mod.rs`):
//! - `IDXGIOutput1::DuplicateOutput` → `AcquireNextFrame`
//! - Hardware cursor capture and compositing (`GetFramePointerShape`, `PointerPosition`)
//! - Upright rotation (`90°`, `180°`, `270°`) for portrait/inverted monitors
//! - GPU-resident D3D11 texture copy (`D3D11_USAGE_DEFAULT`) for zero-copy
//!   Media Foundation hardware encoding, alongside CPU staging readback.

#![allow(unsafe_code, reason = "Direct3D/DXGI COM calls")]

use std::time::{Duration, Instant};

use windows::Win32::Foundation::{E_ACCESSDENIED, HMODULE};
use windows::Win32::Graphics::Direct3D::{D3D_DRIVER_TYPE_UNKNOWN, D3D_FEATURE_LEVEL_11_0};
use windows::Win32::Graphics::Direct3D11::{
    D3D11_BIND_RENDER_TARGET, D3D11_BIND_SHADER_RESOURCE, D3D11_BOX, D3D11_CPU_ACCESS_READ,
    D3D11_CREATE_DEVICE_BGRA_SUPPORT, D3D11_CREATE_DEVICE_VIDEO_SUPPORT, D3D11_MAP_READ,
    D3D11_MAPPED_SUBRESOURCE, D3D11_SDK_VERSION, D3D11_TEXTURE2D_DESC, D3D11_USAGE_DEFAULT,
    D3D11_USAGE_STAGING, D3D11CreateDevice, ID3D11Device, ID3D11DeviceContext, ID3D11Multithread,
    ID3D11Texture2D,
};
use windows::Win32::Graphics::Dxgi::Common::{
    DXGI_FORMAT_B8G8R8A8_UNORM, DXGI_MODE_ROTATION, DXGI_MODE_ROTATION_ROTATE90,
    DXGI_MODE_ROTATION_ROTATE180, DXGI_MODE_ROTATION_ROTATE270,
};
use windows::Win32::Graphics::Dxgi::{
    CreateDXGIFactory1, DXGI_ERROR_ACCESS_DENIED, DXGI_ERROR_ACCESS_LOST,
    DXGI_ERROR_DEVICE_REMOVED, DXGI_ERROR_INVALID_CALL, DXGI_ERROR_NOT_CURRENTLY_AVAILABLE,
    DXGI_ERROR_NOT_FOUND, DXGI_ERROR_SESSION_DISCONNECTED, DXGI_ERROR_WAIT_TIMEOUT,
    DXGI_OUTDUPL_FRAME_INFO, DXGI_OUTDUPL_POINTER_SHAPE_INFO,
    DXGI_OUTDUPL_POINTER_SHAPE_TYPE_COLOR, DXGI_OUTDUPL_POINTER_SHAPE_TYPE_MASKED_COLOR,
    DXGI_OUTDUPL_POINTER_SHAPE_TYPE_MONOCHROME, IDXGIAdapter1, IDXGIDevice1, IDXGIFactory1,
    IDXGIOutput1, IDXGIOutputDuplication, IDXGIResource,
};
use windows::core::Interface;

use crate::cursor::{CursorKind, CursorShape, CursorState, blend_cursor};
use crate::rotate::{Rotation, rotate_bgra};
use crate::{CaptureError, Capturer, DisplayBounds, Frame, GpuTexture};

/// Highest GPU thread priority allowed without special privileges (Sunshine uses 7).
const GPU_THREAD_PRIORITY: i32 = 7;

pub(crate) struct DxgiCapturer {
    device: ID3D11Device,
    context: ID3D11DeviceContext,
    duplication: IDXGIOutputDuplication,
    staging: Option<ID3D11Texture2D>,
    gpu_frame: Option<ID3D11Texture2D>,
    /// The first frame after opening is always copied even if `LastPresentTime == 0`.
    first_frame: bool,
    /// Unrotated physical dimensions of the duplicated scanout texture.
    raw_width: u32,
    raw_height: u32,
    /// Upright desktop dimensions after applying `rotation`.
    width: u32,
    height: u32,
    rotation: Rotation,
    bounds: DisplayBounds,
    /// Cached upright desktop BGRA frame without the cursor, reused when only
    /// the mouse moves (`LastPresentTime == 0`, matching Sunshine `display_ram.cpp`).
    last_desktop: Vec<u8>,
    /// Scratch buffer for unrotated BGRA readback when `rotation != Rotation::Identity`.
    unrotated_scratch: Vec<u8>,
    cursor: CursorState,
    /// Clipped cursor rectangle `(x0, y0, x1, y1)` drawn onto `gpu_frame` on the
    /// previous frame so it can be restored before drawing the new cursor position.
    prev_gpu_cursor_box: Option<(u32, u32, u32, u32)>,
}

// SAFETY: the COM objects are owned by this struct and only accessed through
// `&mut self`, so they are never used concurrently from multiple threads. The
// D3D11 device is created with multithread protection enabled (`ID3D11Multithread`)
// and DXGI objects are free-threaded.
unsafe impl Send for DxgiCapturer {}

/// Maps DXGI errors that require reopening desktop duplication: display mode
/// switch, login/UAC secure desktop switch, disconnected session, or GPU reset
/// (matching Sunshine's `display_base.cpp` and `RustDesk`'s `scrap/src/dxgi/mod.rs`).
fn os_error(error: &windows::core::Error) -> CaptureError {
    let code = error.code();
    if code == DXGI_ERROR_ACCESS_LOST
        || code == DXGI_ERROR_ACCESS_DENIED
        || code == E_ACCESSDENIED
        || code == DXGI_ERROR_SESSION_DISCONNECTED
        || code == DXGI_ERROR_NOT_CURRENTLY_AVAILABLE
        || code == DXGI_ERROR_DEVICE_REMOVED
    {
        CaptureError::AccessLost
    } else {
        CaptureError::Os(error.to_string())
    }
}

const fn map_rotation(dxgi_rotation: DXGI_MODE_ROTATION) -> Rotation {
    match dxgi_rotation {
        DXGI_MODE_ROTATION_ROTATE90 => Rotation::Rotate90,
        DXGI_MODE_ROTATION_ROTATE180 => Rotation::Rotate180,
        DXGI_MODE_ROTATION_ROTATE270 => Rotation::Rotate270,
        _ => Rotation::Identity,
    }
}

/// Computes the clipped cursor rectangle `(x0, y0, x1, y1)` within a
/// `frame_width` × `frame_height` image.
fn clipped_cursor_box(
    cursor: &CursorState,
    frame_width: u32,
    frame_height: u32,
) -> Option<(u32, u32, u32, u32)> {
    if !cursor.visible {
        return None;
    }
    let shape = cursor.shape.as_ref()?;
    if shape.width == 0 || shape.height == 0 {
        return None;
    }
    let x0 = i64::from(cursor.x).max(0);
    let y0 = i64::from(cursor.y).max(0);
    let x1 = (i64::from(cursor.x) + i64::from(shape.width)).min(i64::from(frame_width));
    let y1 = (i64::from(cursor.y) + i64::from(shape.height)).min(i64::from(frame_height));
    if x0 >= x1 || y0 >= y1 {
        return None;
    }
    Some((
        u32::try_from(x0).ok()?,
        u32::try_from(y0).ok()?,
        u32::try_from(x1).ok()?,
        u32::try_from(y1).ok()?,
    ))
}

/// Creates a Direct3D 11 device and immediate context on `adapter` with video
/// support, multithread protection, and maximum GPU priority.
fn create_d3d11_device(
    adapter: &IDXGIAdapter1,
) -> Result<(ID3D11Device, ID3D11DeviceContext), CaptureError> {
    let mut device = None;
    let mut context = None;
    let video_flags = D3D11_CREATE_DEVICE_BGRA_SUPPORT | D3D11_CREATE_DEVICE_VIDEO_SUPPORT;
    // SAFETY: `adapter` is valid (so `D3D_DRIVER_TYPE_UNKNOWN` is required),
    // the feature-level slice lives for the duration of the call, and
    // `device`/`context` are local `Option<Interface>` out-parameters
    // populated with owned references.
    let created = unsafe {
        D3D11CreateDevice(
            adapter,
            D3D_DRIVER_TYPE_UNKNOWN,
            HMODULE::default(),
            video_flags,
            Some(&[D3D_FEATURE_LEVEL_11_0]),
            D3D11_SDK_VERSION,
            Some(&raw mut device),
            None,
            Some(&raw mut context),
        )
    };
    if created.is_err() {
        // Fall back to BGRA support only if the adapter driver does not expose D3D11 video.
        // SAFETY: same as above, with `D3D11_CREATE_DEVICE_BGRA_SUPPORT` only.
        unsafe {
            D3D11CreateDevice(
                adapter,
                D3D_DRIVER_TYPE_UNKNOWN,
                HMODULE::default(),
                D3D11_CREATE_DEVICE_BGRA_SUPPORT,
                Some(&[D3D_FEATURE_LEVEL_11_0]),
                D3D11_SDK_VERSION,
                Some(&raw mut device),
                None,
                Some(&raw mut context),
            )
        }
        .map_err(|e| os_error(&e))?;
    }
    let device: ID3D11Device =
        device.ok_or_else(|| CaptureError::Os("D3D11 returned no device".into()))?;
    let context: ID3D11DeviceContext =
        context.ok_or_else(|| CaptureError::Os("D3D11 returned no context".into()))?;

    // Enable multithread protection so Media Foundation's asynchronous
    // hardware encoder worker threads and `ID3D11VideoProcessor` can safely
    // share this D3D11 device via `IMFDXGIDeviceManager`.
    if let Ok(multithread) = device.cast::<ID3D11Multithread>() {
        // SAFETY: `multithread` is a valid interface on `device`; takes a boolean by value.
        let _ = unsafe { multithread.SetMultithreadProtected(true) };
    }

    // Minimize GPU frame queueing and raise GPU thread priority (Sunshine):
    // without this, heavy 3D workloads can stall staging copies and `Map`.
    if let Ok(dxgi_device) = device.cast::<IDXGIDevice1>() {
        // SAFETY: `dxgi_device` is valid and `1` is within the valid range `1..=16`.
        let _ = unsafe { dxgi_device.SetMaximumFrameLatency(1) };
        // SAFETY: `dxgi_device` is valid and `7` is within the valid range `-7..=7`.
        let _ = unsafe { dxgi_device.SetGPUThreadPriority(GPU_THREAD_PRIORITY) };
    }
    Ok((device, context))
}

impl DxgiCapturer {
    pub(crate) fn open(index: u32) -> Result<Self, CaptureError> {
        // SAFETY: takes no arguments and returns a newly owned DXGI factory.
        let factory: IDXGIFactory1 = unsafe { CreateDXGIFactory1() }.map_err(|e| os_error(&e))?;

        // Find monitor `index` among outputs attached to the desktop across all
        // adapters (Sunshine and CrossDesk filter `AttachedToDesktop` the same way).
        let mut remaining = index;
        let mut adapter_index = 0;
        let (adapter, output, description) = loop {
            // SAFETY: `factory` is a valid DXGI factory; an out-of-range index
            // simply returns `DXGI_ERROR_NOT_FOUND`.
            let adapter = match unsafe { factory.EnumAdapters1(adapter_index) } {
                Ok(adapter) => adapter,
                Err(e) if e.code() == DXGI_ERROR_NOT_FOUND => {
                    return Err(CaptureError::DisplayNotFound(index));
                }
                Err(e) => return Err(os_error(&e)),
            };
            let mut output_index = 0;
            let found = loop {
                // SAFETY: `adapter` is a valid adapter returned by `factory`;
                // an out-of-range index returns `DXGI_ERROR_NOT_FOUND`.
                let output = match unsafe { adapter.EnumOutputs(output_index) } {
                    Ok(output) => output,
                    Err(e) if e.code() == DXGI_ERROR_NOT_FOUND => break None,
                    Err(e) => return Err(os_error(&e)),
                };
                output_index += 1;
                // SAFETY: `output` is a valid output and the description is returned by value.
                let description = unsafe { output.GetDesc() }.map_err(|e| os_error(&e))?;
                if !description.AttachedToDesktop.as_bool() {
                    continue;
                }
                if remaining == 0 {
                    break Some((output, description));
                }
                remaining -= 1;
            };
            if let Some((output, description)) = found {
                break (adapter, output, description);
            }
            adapter_index += 1;
        };

        let (device, context) = create_d3d11_device(&adapter)?;

        let output: IDXGIOutput1 = output.cast().map_err(|e| os_error(&e))?;
        // SAFETY: `output` is attached to the desktop and `device` was created
        // on the same adapter, as required by `DuplicateOutput`.
        let duplication = unsafe { output.DuplicateOutput(&device) }.map_err(|e| os_error(&e))?;
        // SAFETY: `duplication` is valid and the description is returned by value.
        let duplication_description = unsafe { duplication.GetDesc() };
        let rotation = map_rotation(duplication_description.Rotation);

        let rect = description.DesktopCoordinates;
        let rect_width = (rect.right - rect.left).unsigned_abs();
        let rect_height = (rect.bottom - rect.top).unsigned_abs();
        let width = if rect_width > 0 {
            rect_width
        } else {
            duplication_description.ModeDesc.Width
        };
        let height = if rect_height > 0 {
            rect_height
        } else {
            duplication_description.ModeDesc.Height
        };
        // The physical scanout texture returned by `AcquireNextFrame` has
        // swapped dimensions when the desktop is rotated by 90° or 270°.
        let (raw_width, raw_height) = rotation.output_size(width, height);

        Ok(Self {
            device,
            context,
            duplication,
            staging: None,
            gpu_frame: None,
            first_frame: true,
            raw_width,
            raw_height,
            width,
            height,
            rotation,
            bounds: DisplayBounds {
                x: rect.left,
                y: rect.top,
                width,
                height,
            },
            last_desktop: Vec::new(),
            unrotated_scratch: Vec::new(),
            cursor: CursorState::default(),
            prev_gpu_cursor_box: None,
        })
    }

    /// Returns a CPU-readable staging texture matching the captured frame description.
    fn staging_for(
        &mut self,
        description: &D3D11_TEXTURE2D_DESC,
    ) -> Result<ID3D11Texture2D, CaptureError> {
        if let Some(staging) = &self.staging {
            return Ok(staging.clone());
        }
        let mut staging_description = *description;
        staging_description.Usage = D3D11_USAGE_STAGING;
        staging_description.CPUAccessFlags = D3D11_CPU_ACCESS_READ.0.cast_unsigned();
        staging_description.BindFlags = 0;
        staging_description.MiscFlags = 0;

        let mut staging = None;
        // SAFETY: `staging_description` is a valid local texture description
        // adjusted for CPU readback, initial data is `None` (allowed for
        // non-immutable textures), and `staging` is a local out-parameter.
        unsafe {
            self.device.CreateTexture2D(
                &raw const staging_description,
                None,
                Some(&raw mut staging),
            )
        }
        .map_err(|e| os_error(&e))?;
        let staging =
            staging.ok_or_else(|| CaptureError::Os("failed to create staging texture".into()))?;
        self.staging = Some(staging.clone());
        Ok(staging)
    }

    /// Returns a GPU-resident `D3D11_USAGE_DEFAULT` texture bound for video
    /// processor input so `MediaFoundationEncoder` can convert BGRA → NV12 and
    /// encode on the GPU without uploading from system memory.
    fn gpu_frame_for(&mut self, description: &D3D11_TEXTURE2D_DESC) -> Option<ID3D11Texture2D> {
        if let Some(gpu_frame) = &self.gpu_frame {
            return Some(gpu_frame.clone());
        }
        let mut gpu_desc = *description;
        gpu_desc.Usage = D3D11_USAGE_DEFAULT;
        gpu_desc.BindFlags =
            (D3D11_BIND_RENDER_TARGET.0 | D3D11_BIND_SHADER_RESOURCE.0).cast_unsigned();
        gpu_desc.CPUAccessFlags = 0;
        gpu_desc.MiscFlags = 0;

        let mut texture = None;
        // SAFETY: `gpu_desc` is a valid local `D3D11_TEXTURE2D_DESC`, initial
        // data is `None`, and `texture` is a local out-parameter.
        unsafe {
            self.device
                .CreateTexture2D(&raw const gpu_desc, None, Some(&raw mut texture))
        }
        .ok()?;
        let texture = texture?;
        self.gpu_frame = Some(texture.clone());
        Some(texture)
    }

    /// Reads the latest cursor shape from `IDXGIOutputDuplication::GetFramePointerShape`.
    fn update_cursor_shape(&mut self, buffer_size: u32) -> Result<(), CaptureError> {
        let mut data = vec![0u8; buffer_size as usize];
        let mut required = 0u32;
        let mut shape_info = DXGI_OUTDUPL_POINTER_SHAPE_INFO::default();
        // SAFETY: `data` has `buffer_size` writable bytes, and `required` and
        // `shape_info` are local out-parameters.
        unsafe {
            self.duplication.GetFramePointerShape(
                buffer_size,
                data.as_mut_ptr().cast(),
                &raw mut required,
                &raw mut shape_info,
            )
        }
        .map_err(|e| os_error(&e))?;

        let (kind, height) = match shape_info.Type {
            t if t == DXGI_OUTDUPL_POINTER_SHAPE_TYPE_MONOCHROME.0.cast_unsigned() => {
                (CursorKind::Monochrome, shape_info.Height / 2)
            }
            t if t == DXGI_OUTDUPL_POINTER_SHAPE_TYPE_COLOR.0.cast_unsigned() => {
                (CursorKind::Color, shape_info.Height)
            }
            t if t
                == DXGI_OUTDUPL_POINTER_SHAPE_TYPE_MASKED_COLOR
                    .0
                    .cast_unsigned() =>
            {
                (CursorKind::MaskedColor, shape_info.Height)
            }
            _ => return Ok(()),
        };
        data.truncate(required as usize);
        self.cursor.shape = Some(CursorShape {
            kind,
            width: shape_info.Width,
            height,
            pitch: shape_info.Pitch,
            data,
        });
        Ok(())
    }

    /// Copies a sub-rectangle `(x0, y0)..(x1, y1)` from a tightly packed BGRA
    /// buffer `pixels` into `gpu_texture` via `UpdateSubresource`.
    fn update_gpu_box(
        &self,
        gpu_texture: &ID3D11Texture2D,
        pixels: &[u8],
        (x0, y0, x1, y1): (u32, u32, u32, u32),
    ) {
        let row_pitch = self.width * 4;
        let offset = (y0 as usize * self.width as usize + x0 as usize) * 4;
        let min_bytes = ((y1 - y0 - 1) as usize * self.width as usize + (x1 - x0) as usize) * 4;
        let Some(slice) = pixels.get(offset..offset + min_bytes) else {
            return;
        };
        let region = D3D11_BOX {
            left: x0,
            top: y0,
            front: 0,
            right: x1,
            bottom: y1,
            back: 1,
        };
        // SAFETY: `gpu_texture` is a `D3D11_USAGE_DEFAULT` 2D texture of
        // `width` x `height` BGRA pixels, `region` is clamped to `0..width` and
        // `0..height`, and `slice` contains `(y1 - y0)` rows at stride `row_pitch`.
        unsafe {
            self.context.UpdateSubresource(
                gpu_texture,
                0,
                Some(&raw const region),
                slice.as_ptr().cast(),
                row_pitch,
                0,
            );
        }
    }

    fn copy_desktop(&mut self, resource: &IDXGIResource) -> Result<(), CaptureError> {
        let texture: ID3D11Texture2D = resource.cast().map_err(|e| os_error(&e))?;
        let mut description = D3D11_TEXTURE2D_DESC::default();
        // SAFETY: `texture` is valid until `ReleaseFrame` and `description` is a
        // local struct out-parameter.
        unsafe { texture.GetDesc(&raw mut description) };

        // Row-by-row copy relies on `raw_width`/`raw_height`; if the texture no
        // longer matches (mode change in progress or HDR switch), reading the
        // mapped buffer would be unsound. Request a reopen like Sunshine (`display_ram.cpp`).
        if description.Width != self.raw_width
            || description.Height != self.raw_height
            || description.Format != DXGI_FORMAT_B8G8R8A8_UNORM
        {
            return Err(CaptureError::AccessLost);
        }

        // Keep an unrotated GPU copy in VRAM so `MediaFoundationEncoder` can
        // convert BGRA -> NV12 on the GPU via `ID3D11VideoProcessor`.
        if self.rotation == Rotation::Identity
            && let Some(gpu_frame) = self.gpu_frame_for(&description)
        {
            // SAFETY: `gpu_frame` and `texture` belong to `self.device` and have
            // identical dimensions and format.
            unsafe { self.context.CopyResource(&gpu_frame, &texture) };
            self.prev_gpu_cursor_box = None;
        }

        let staging = self.staging_for(&description)?;
        // SAFETY: `staging` and `texture` belong to the same device and have
        // identical dimensions and format; the immediate context is accessed
        // exclusively through `&mut self`.
        unsafe { self.context.CopyResource(&staging, &texture) };

        let mut mapped = D3D11_MAPPED_SUBRESOURCE::default();
        // SAFETY: `staging` was created with `D3D11_USAGE_STAGING` and
        // `D3D11_CPU_ACCESS_READ`, allowing `Map` on subresource 0; `mapped` is
        // a local out-parameter receiving the data pointer and row pitch.
        unsafe {
            self.context
                .Map(&staging, 0, D3D11_MAP_READ, 0, Some(&raw mut mapped))
        }
        .map_err(|e| os_error(&e))?;

        let row_bytes = self.raw_width as usize * 4;
        let pitch = mapped.RowPitch as usize;
        let total_bytes = row_bytes * self.raw_height as usize;
        let target = if self.rotation == Rotation::Identity {
            &mut self.last_desktop
        } else {
            &mut self.unrotated_scratch
        };
        let base = mapped.pData.cast::<u8>().cast_const();
        if pitch == row_bytes {
            target.resize(total_bytes, 0);
            // SAFETY: `Map` succeeded and `pitch == row_bytes`, so `base` points
            // to `total_bytes` contiguous BGRA bytes valid until `Unmap` below.
            let slice = unsafe { std::slice::from_raw_parts(base, total_bytes) };
            target.copy_from_slice(slice);
        } else {
            target.clear();
            target.reserve(total_bytes);
            for row in 0..self.raw_height as usize {
                // SAFETY: `Map` succeeded, so `base` points to `raw_height` rows of
                // `RowPitch` bytes valid until `Unmap` below, and `row < raw_height`.
                let start = unsafe { base.add(row * pitch) };
                // SAFETY: the texture has `raw_width` x `raw_height` BGRA pixels
                // (4 bytes each), so `RowPitch >= row_bytes` and `row_bytes` starting
                // at `start` lie within the mapped subresource and are copied before `Unmap`.
                let line = unsafe { std::slice::from_raw_parts(start, row_bytes) };
                target.extend_from_slice(line);
            }
        }

        // SAFETY: pairs with the successful `Map` on subresource 0 above, after
        // all slices referencing the mapped memory have gone out of scope.
        unsafe { self.context.Unmap(&staging, 0) };

        if self.rotation != Rotation::Identity {
            rotate_bgra(
                &self.unrotated_scratch,
                self.raw_width,
                self.raw_height,
                self.rotation,
                &mut self.last_desktop,
            );
        }
        Ok(())
    }
}

impl Capturer for DxgiCapturer {
    fn next_frame(&mut self, timeout: Duration) -> Result<Option<Frame>, CaptureError> {
        let timeout_ms = u32::try_from(timeout.as_millis()).unwrap_or(u32::MAX);
        let mut info = DXGI_OUTDUPL_FRAME_INFO::default();
        let mut resource: Option<IDXGIResource> = None;

        // SAFETY: `duplication` is valid, `info` and `resource` are local
        // out-parameters, and any previously acquired frame was released before
        // returning from `next_frame`.
        let acquired = unsafe {
            self.duplication
                .AcquireNextFrame(timeout_ms, &raw mut info, &raw mut resource)
        };
        match acquired {
            Ok(()) => {}
            Err(e) if e.code() == DXGI_ERROR_WAIT_TIMEOUT => return Ok(None),
            Err(e) => return Err(os_error(&e)),
        }
        let captured_at = Instant::now();

        let mouse_updated = info.LastMouseUpdateTime != 0 || info.PointerShapeBufferSize > 0;
        let frame_updated =
            info.LastPresentTime != 0 || info.AccumulatedFrames != 0 || self.first_frame;

        let step_result = (|| -> Result<Option<Frame>, CaptureError> {
            if info.PointerShapeBufferSize > 0 {
                self.update_cursor_shape(info.PointerShapeBufferSize)?;
            }
            if info.LastMouseUpdateTime != 0 {
                self.cursor.x = info.PointerPosition.Position.x;
                self.cursor.y = info.PointerPosition.Position.y;
                self.cursor.visible = info.PointerPosition.Visible.as_bool();
            }

            if frame_updated && let Some(res) = &resource {
                self.copy_desktop(res)?;
                self.first_frame = false;
            }

            if self.last_desktop.is_empty() || (!frame_updated && !mouse_updated) {
                return Ok(None);
            }

            let mut bgra = self.last_desktop.clone();
            if self.cursor.visible && self.cursor.shape.is_some() {
                blend_cursor(&mut bgra, self.width, self.height, &self.cursor);
            }

            let gpu_texture = if self.rotation == Rotation::Identity
                && let Some(gpu_frame) = self.gpu_frame.clone()
            {
                if let Some(prev_box) = self.prev_gpu_cursor_box.take() {
                    self.update_gpu_box(&gpu_frame, &self.last_desktop, prev_box);
                }
                if let Some(cur_box) = clipped_cursor_box(&self.cursor, self.width, self.height) {
                    self.update_gpu_box(&gpu_frame, &bgra, cur_box);
                    self.prev_gpu_cursor_box = Some(cur_box);
                }
                Some(GpuTexture {
                    device: self.device.clone(),
                    context: self.context.clone(),
                    texture: gpu_frame,
                })
            } else {
                None
            };

            Ok(Some(Frame {
                width: self.width,
                height: self.height,
                bgra,
                captured_at,
                gpu_texture,
            }))
        })();

        // SAFETY: reached only after a successful `AcquireNextFrame`; the GPU
        // resource is no longer read after this point.
        match unsafe { self.duplication.ReleaseFrame() } {
            // `INVALID_CALL`: frame was already released (Sunshine ignores this too).
            Err(e) if e.code() != DXGI_ERROR_INVALID_CALL => return Err(os_error(&e)),
            Ok(()) | Err(_) => {}
        }
        step_result
    }

    fn size(&self) -> (u32, u32) {
        (self.width, self.height)
    }

    fn bounds(&self) -> DisplayBounds {
        self.bounds
    }

    fn d3d11_device(&self) -> Option<&ID3D11Device> {
        Some(&self.device)
    }
}
