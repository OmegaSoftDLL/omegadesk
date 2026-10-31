//! DXGI Desktop Duplication backend (Windows 8 and newer).
//!
//! Pipeline modeled after Sunshine (`src/platform/windows/display_base.cpp` and
//! `display_ram.cpp`): `IDXGIOutput1::DuplicateOutput` → `AcquireNextFrame` →
//! copy into a staging texture → `Map` → tightly packed BGRA in CPU memory,
//! row by row respecting `RowPitch`.

#![allow(unsafe_code, reason = "Direct3D/DXGI COM calls")]

use std::time::{Duration, Instant};

use windows::Win32::Foundation::HMODULE;
use windows::Win32::Graphics::Direct3D::{D3D_DRIVER_TYPE_UNKNOWN, D3D_FEATURE_LEVEL_11_0};
use windows::Win32::Graphics::Direct3D11::{
    D3D11_CPU_ACCESS_READ, D3D11_CREATE_DEVICE_BGRA_SUPPORT, D3D11_MAP_READ,
    D3D11_MAPPED_SUBRESOURCE, D3D11_SDK_VERSION, D3D11_TEXTURE2D_DESC, D3D11_USAGE_STAGING,
    D3D11CreateDevice, ID3D11Device, ID3D11DeviceContext, ID3D11Texture2D,
};
use windows::Win32::Graphics::Dxgi::Common::{
    DXGI_FORMAT_B8G8R8A8_UNORM, DXGI_MODE_ROTATION_IDENTITY, DXGI_MODE_ROTATION_UNSPECIFIED,
};
use windows::Win32::Graphics::Dxgi::{
    CreateDXGIFactory1, DXGI_ERROR_ACCESS_DENIED, DXGI_ERROR_ACCESS_LOST,
    DXGI_ERROR_DEVICE_REMOVED, DXGI_ERROR_INVALID_CALL, DXGI_ERROR_NOT_CURRENTLY_AVAILABLE,
    DXGI_ERROR_NOT_FOUND, DXGI_ERROR_SESSION_DISCONNECTED, DXGI_ERROR_WAIT_TIMEOUT,
    DXGI_OUTDUPL_FRAME_INFO, IDXGIDevice1, IDXGIFactory1, IDXGIOutput1, IDXGIOutputDuplication,
    IDXGIResource,
};
use windows::core::Interface;

use crate::{CaptureError, Capturer, DisplayBounds, Frame};

/// Highest GPU thread priority allowed without special privileges (Sunshine uses 7).
const GPU_THREAD_PRIORITY: i32 = 7;

pub(crate) struct DxgiCapturer {
    device: ID3D11Device,
    context: ID3D11DeviceContext,
    duplication: IDXGIOutputDuplication,
    staging: Option<ID3D11Texture2D>,
    /// The first frame after opening is always copied even if `LastPresentTime == 0`.
    first_frame: bool,
    width: u32,
    height: u32,
    bounds: DisplayBounds,
}

// SAFETY: the COM objects are owned by this struct and only accessed through
// `&mut self`, so they are never used concurrently from multiple threads. The
// D3D11 device is created without `D3D11_CREATE_DEVICE_SINGLETHREADED` and
// DXGI objects are free-threaded; although the immediate context is not
// thread-safe, moving the struct across threads does not create concurrent
// access to it.
unsafe impl Send for DxgiCapturer {}

/// Maps DXGI errors that require reopening desktop duplication: display mode
/// switch, login/UAC secure desktop switch, disconnected session, or GPU reset
/// (matching Sunshine's `display_base.cpp` and `RustDesk`'s `scrap/src/dxgi/mod.rs`).
fn os_error(error: &windows::core::Error) -> CaptureError {
    let code = error.code();
    if code == DXGI_ERROR_ACCESS_LOST
        || code == DXGI_ERROR_ACCESS_DENIED
        || code == DXGI_ERROR_SESSION_DISCONNECTED
        || code == DXGI_ERROR_NOT_CURRENTLY_AVAILABLE
        || code == DXGI_ERROR_DEVICE_REMOVED
    {
        CaptureError::AccessLost
    } else {
        CaptureError::Os(error.to_string())
    }
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

        let mut device = None;
        let mut context = None;
        // SAFETY: `adapter` is valid (so `D3D_DRIVER_TYPE_UNKNOWN` is required),
        // the feature-level slice lives for the duration of the call, and
        // `device`/`context` are local `Option<Interface>` out-parameters
        // populated with owned references.
        unsafe {
            D3D11CreateDevice(
                &adapter,
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
        let device: ID3D11Device =
            device.ok_or_else(|| CaptureError::Os("D3D11 returned no device".into()))?;
        let context: ID3D11DeviceContext =
            context.ok_or_else(|| CaptureError::Os("D3D11 returned no context".into()))?;

        // Minimize GPU frame queueing and raise GPU thread priority (Sunshine):
        // without this, heavy 3D workloads can stall staging copies and `Map`.
        if let Ok(dxgi_device) = device.cast::<IDXGIDevice1>() {
            // SAFETY: `dxgi_device` is valid and `1` is within the valid range `1..=16`.
            let _ = unsafe { dxgi_device.SetMaximumFrameLatency(1) };
            // SAFETY: `dxgi_device` is valid and `7` is within the valid range `-7..=7`.
            let _ = unsafe { dxgi_device.SetGPUThreadPriority(GPU_THREAD_PRIORITY) };
        }

        let output: IDXGIOutput1 = output.cast().map_err(|e| os_error(&e))?;
        // SAFETY: `output` is attached to the desktop and `device` was created
        // on the same adapter, as required by `DuplicateOutput`.
        let duplication = unsafe { output.DuplicateOutput(&device) }.map_err(|e| os_error(&e))?;
        // SAFETY: `duplication` is valid and the description is returned by value.
        let duplication_description = unsafe { duplication.GetDesc() };
        let rotation = duplication_description.Rotation;
        if rotation != DXGI_MODE_ROTATION_IDENTITY && rotation != DXGI_MODE_ROTATION_UNSPECIFIED {
            // Phase 3: rotate the captured frame like RustDesk (`ARGBRotate`).
            return Err(CaptureError::Os(
                "rotated monitors are not supported yet".into(),
            ));
        }

        let rect = description.DesktopCoordinates;
        Ok(Self {
            device,
            context,
            duplication,
            staging: None,
            first_frame: true,
            width: duplication_description.ModeDesc.Width,
            height: duplication_description.ModeDesc.Height,
            bounds: DisplayBounds {
                x: rect.left,
                y: rect.top,
                width: duplication_description.ModeDesc.Width,
                height: duplication_description.ModeDesc.Height,
            },
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

    fn copy_to_cpu(&mut self, resource: &IDXGIResource) -> Result<Vec<u8>, CaptureError> {
        let texture: ID3D11Texture2D = resource.cast().map_err(|e| os_error(&e))?;
        let mut description = D3D11_TEXTURE2D_DESC::default();
        // SAFETY: `texture` is valid until `ReleaseFrame` and `description` is a
        // local struct out-parameter.
        unsafe { texture.GetDesc(&raw mut description) };

        // Row-by-row copy relies on `width`/`height`; if the texture no longer
        // matches (mode change in progress or HDR switch), reading the mapped
        // buffer would be unsound. Request a reopen like Sunshine (`display_ram.cpp`).
        if description.Width != self.width
            || description.Height != self.height
            || description.Format != DXGI_FORMAT_B8G8R8A8_UNORM
        {
            return Err(CaptureError::AccessLost);
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

        let row_bytes = self.width as usize * 4;
        let pitch = mapped.RowPitch as usize;
        let mut bgra = Vec::with_capacity(row_bytes * self.height as usize);
        let base = mapped.pData.cast::<u8>().cast_const();
        for row in 0..self.height as usize {
            // SAFETY: `Map` succeeded, so `base` points to `height` rows of
            // `RowPitch` bytes valid until `Unmap` below, and `row < height`.
            let start = unsafe { base.add(row * pitch) };
            // SAFETY: the texture has `width` x `height` BGRA pixels (4 bytes
            // each), so `RowPitch >= row_bytes` and `row_bytes` starting at
            // `start` lie within the mapped subresource and are copied before `Unmap`.
            let line = unsafe { std::slice::from_raw_parts(start, row_bytes) };
            bgra.extend_from_slice(line);
        }

        // SAFETY: pairs with the successful `Map` on subresource 0 above, after
        // all slices referencing the mapped memory have gone out of scope.
        unsafe { self.context.Unmap(&staging, 0) };
        Ok(bgra)
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

        // Only the cursor moved (`LastPresentTime == 0`), so the desktop image
        // is unchanged. We still copy the very first frame so the client gets an
        // initial image immediately.
        let result = if info.LastPresentTime == 0 && !self.first_frame {
            Ok(None)
        } else {
            match &resource {
                Some(resource) => self.copy_to_cpu(resource).map(|bgra| {
                    self.first_frame = false;
                    Some(Frame {
                        width: self.width,
                        height: self.height,
                        bgra,
                        captured_at,
                    })
                }),
                None => Ok(None),
            }
        };

        // SAFETY: reached only after a successful `AcquireNextFrame`; the GPU
        // resource is no longer read after this point.
        match unsafe { self.duplication.ReleaseFrame() } {
            // `INVALID_CALL`: frame was already released (Sunshine ignores this too).
            Err(e) if e.code() != DXGI_ERROR_INVALID_CALL => return Err(os_error(&e)),
            Ok(()) | Err(_) => {}
        }
        result
    }

    fn size(&self) -> (u32, u32) {
        (self.width, self.height)
    }

    fn bounds(&self) -> DisplayBounds {
        self.bounds
    }
}
