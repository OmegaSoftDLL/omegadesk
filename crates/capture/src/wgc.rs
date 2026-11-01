//! Windows Graphics Capture (WGC) backend: the middle step of the
//! `DXGI -> WGC -> GDI` fallback chain.
//!
//! WGC (`Windows.Graphics.Capture`, Windows 10 1903+) composites a monitor
//! through DWM and hands back `Direct3D11` textures, so it keeps working in
//! cases where `IDXGIOutputDuplication` refuses to start (some RDP sessions,
//! mixed-GPU laptops, certain protected/overlay surfaces) while still being
//! GPU-accelerated, unlike the GDI `BitBlt` last resort. Ported from Sunshine
//! `src/platform/windows/display_wgc.cpp` (monitor capture item, free-threaded
//! frame pool, BGRA staging copy) using the `windows` crate's `WinRT` bindings.
//!
//! Frames are pulled by polling `TryGetNextFrame` on the single capture thread
//! (no `FrameArrived` event handler and no `DispatcherQueue`), which keeps every
//! COM/`WinRT` object on one apartment and avoids cross-thread marshalling.

#![allow(
    unsafe_code,
    reason = "WGC requires Direct3D11 and WinRT interop FFI (CreateForMonitor, DXGI interface access, texture map)"
)]

use std::time::{Duration, Instant};

use windows::Graphics::Capture::{
    Direct3D11CaptureFramePool, GraphicsCaptureItem, GraphicsCaptureSession,
};
use windows::Graphics::DirectX::Direct3D11::IDirect3DDevice;
use windows::Graphics::DirectX::DirectXPixelFormat;
use windows::Graphics::SizeInt32;
use windows::Win32::Foundation::HMODULE;
use windows::Win32::Graphics::Direct3D::{D3D_DRIVER_TYPE_HARDWARE, D3D_DRIVER_TYPE_WARP};
use windows::Win32::Graphics::Direct3D11::{
    D3D11_CPU_ACCESS_READ, D3D11_CREATE_DEVICE_BGRA_SUPPORT, D3D11_MAP_READ,
    D3D11_MAPPED_SUBRESOURCE, D3D11_SDK_VERSION, D3D11_TEXTURE2D_DESC, D3D11_USAGE_STAGING,
    D3D11CreateDevice, ID3D11Device, ID3D11DeviceContext, ID3D11Texture2D,
};
use windows::Win32::Graphics::Dxgi::{
    CreateDXGIFactory1, DXGI_ERROR_NOT_FOUND, IDXGIDevice, IDXGIFactory1,
};
use windows::Win32::Graphics::Gdi::HMONITOR;
use windows::Win32::System::WinRT::Direct3D11::{
    CreateDirect3D11DeviceFromDXGIDevice, IDirect3DDxgiInterfaceAccess,
};
use windows::Win32::System::WinRT::Graphics::Capture::IGraphicsCaptureItemInterop;
use windows::core::Interface;

use crate::{CaptureError, Capturer, DisplayBounds, Frame};

/// Captures one monitor through Windows Graphics Capture.
pub(crate) struct WgcCapturer {
    device: ID3D11Device,
    context: ID3D11DeviceContext,
    d3d_device: IDirect3DDevice,
    frame_pool: Direct3D11CaptureFramePool,
    session: GraphicsCaptureSession,
    _item: GraphicsCaptureItem,
    pool_size: SizeInt32,
    bounds: DisplayBounds,
    staging: Option<StagingTexture>,
}

struct StagingTexture {
    texture: ID3D11Texture2D,
    width: u32,
    height: u32,
}

// SAFETY: every method keeps the Direct3D11/WinRT objects on the single capture
// thread that created the capturer; the capturer is moved to that thread once
// (as a `Box<dyn Capturer>`) and never shared, so no concurrent access occurs.
unsafe impl Send for WgcCapturer {}

impl WgcCapturer {
    /// Opens monitor `index` with WGC, mirroring the DXGI output ordering so
    /// `--display N` selects the same monitor across backends.
    pub(crate) fn open(index: u32) -> Result<Self, CaptureError> {
        if !GraphicsCaptureSession::IsSupported().unwrap_or(false) {
            return Err(CaptureError::Os(
                "Windows Graphics Capture is not supported on this system".to_owned(),
            ));
        }
        let (hmonitor, bounds) = monitor_for_index(index)?;
        let (device, context) = create_device()?;

        // Wrap the D3D11 device as a WinRT IDirect3DDevice for the frame pool.
        let dxgi_device: IDXGIDevice = device.cast().map_err(|error| os_error(&error))?;
        // SAFETY: `dxgi_device` is a valid DXGI device; the call returns an
        // IInspectable we immediately cast to IDirect3DDevice.
        let inspectable = unsafe { CreateDirect3D11DeviceFromDXGIDevice(&dxgi_device) }
            .map_err(|error| os_error(&error))?;
        let d3d_device: IDirect3DDevice = inspectable.cast().map_err(|error| os_error(&error))?;

        // Create the capture item for the monitor.
        let interop: IGraphicsCaptureItemInterop =
            windows::core::factory::<GraphicsCaptureItem, IGraphicsCaptureItemInterop>()
                .map_err(|error| os_error(&error))?;
        // SAFETY: `hmonitor` is a valid monitor handle from the DXGI output desc.
        let item: GraphicsCaptureItem =
            unsafe { interop.CreateForMonitor(hmonitor) }.map_err(|error| os_error(&error))?;

        let pool_size = item.Size().map_err(|error| os_error(&error))?;
        let frame_pool = Direct3D11CaptureFramePool::CreateFreeThreaded(
            &d3d_device,
            DirectXPixelFormat::B8G8R8A8UIntNormalized,
            2,
            pool_size,
        )
        .map_err(|error| os_error(&error))?;
        let session = frame_pool
            .CreateCaptureSession(&item)
            .map_err(|error| os_error(&error))?;
        // Hide the yellow capture border where the OS and policy allow it
        // (Windows 11; best effort, older builds simply ignore it).
        let _ = session.SetIsBorderRequired(false);
        session.StartCapture().map_err(|error| os_error(&error))?;

        Ok(Self {
            device,
            context,
            d3d_device,
            frame_pool,
            session,
            _item: item,
            pool_size,
            bounds,
            staging: None,
        })
    }

    /// Copies a WGC frame's texture into CPU memory as tightly packed BGRA.
    fn read_frame(&mut self) -> Result<Option<Frame>, CaptureError> {
        // `TryGetNextFrame` returns an error (null frame) when none is ready.
        let Ok(frame) = self.frame_pool.TryGetNextFrame() else {
            return Ok(None);
        };
        let content = frame.ContentSize().map_err(|error| os_error(&error))?;
        if content.Width != self.pool_size.Width || content.Height != self.pool_size.Height {
            // The monitor resolution changed: resize the pool and skip this frame.
            self.pool_size = content;
            self.frame_pool
                .Recreate(
                    &self.d3d_device,
                    DirectXPixelFormat::B8G8R8A8UIntNormalized,
                    2,
                    content,
                )
                .map_err(|error| os_error(&error))?;
            self.bounds.width = content.Width.unsigned_abs();
            self.bounds.height = content.Height.unsigned_abs();
            return Ok(None);
        }

        let surface = frame.Surface().map_err(|error| os_error(&error))?;
        let access: IDirect3DDxgiInterfaceAccess =
            surface.cast().map_err(|error| os_error(&error))?;
        // SAFETY: `access` wraps the frame's Direct3D surface; `GetInterface`
        // returns its underlying ID3D11Texture2D.
        let texture: ID3D11Texture2D =
            unsafe { access.GetInterface() }.map_err(|error| os_error(&error))?;

        let mut desc = D3D11_TEXTURE2D_DESC::default();
        // SAFETY: `texture` is valid; `desc` is a valid out-pointer.
        unsafe { texture.GetDesc(&raw mut desc) };
        let width = desc.Width;
        let height = desc.Height;

        self.ensure_staging(&desc, width, height)?;
        let Some(staging) = self.staging.as_ref() else {
            return Ok(None);
        };

        // SAFETY: both resources are valid ID3D11Texture2D of matching size and
        // format; CopyResource is the documented GPU->staging copy.
        unsafe {
            self.context.CopyResource(&staging.texture, &texture);
        }

        let mut mapped = D3D11_MAPPED_SUBRESOURCE::default();
        // SAFETY: `staging.texture` is a STAGING texture with CPU read access;
        // subresource 0 exists; `mapped` is a valid out-pointer.
        unsafe {
            self.context
                .Map(
                    &staging.texture,
                    0,
                    D3D11_MAP_READ,
                    0,
                    Some(&raw mut mapped),
                )
                .map_err(|error| os_error(&error))?;
        }

        let row_bytes = (width as usize) * 4;
        let mut bgra = vec![0u8; row_bytes * height as usize];
        let pitch = mapped.RowPitch as usize;
        let src = mapped.pData.cast::<u8>();
        for row in 0..height as usize {
            let dst = &mut bgra[row * row_bytes..row * row_bytes + row_bytes];
            // SAFETY: `src` points at `pitch * height` readable bytes for the
            // map's duration and `row < height`, so `row * pitch` stays inside.
            let src_row = unsafe { src.add(row * pitch) };
            // SAFETY: `src_row` begins a readable `row_bytes` run and `dst` is a
            // distinct `row_bytes` slice of our freshly allocated buffer.
            unsafe { std::ptr::copy_nonoverlapping(src_row, dst.as_mut_ptr(), row_bytes) };
        }
        // SAFETY: `staging.texture` was mapped above; it is unmapped exactly once.
        unsafe {
            self.context.Unmap(&staging.texture, 0);
        }

        Ok(Some(Frame {
            width,
            height,
            bgra,
            captured_at: Instant::now(),
            gpu_texture: None,
        }))
    }

    /// (Re)creates the CPU-readable staging texture when the size changes.
    fn ensure_staging(
        &mut self,
        source: &D3D11_TEXTURE2D_DESC,
        width: u32,
        height: u32,
    ) -> Result<(), CaptureError> {
        if matches!(&self.staging, Some(s) if s.width == width && s.height == height) {
            return Ok(());
        }
        let desc = D3D11_TEXTURE2D_DESC {
            Width: width,
            Height: height,
            MipLevels: 1,
            ArraySize: 1,
            Format: source.Format,
            SampleDesc: windows::Win32::Graphics::Dxgi::Common::DXGI_SAMPLE_DESC {
                Count: 1,
                Quality: 0,
            },
            Usage: D3D11_USAGE_STAGING,
            BindFlags: 0,
            CPUAccessFlags: D3D11_CPU_ACCESS_READ.0 as u32,
            MiscFlags: 0,
        };
        let mut texture: Option<ID3D11Texture2D> = None;
        // SAFETY: `desc` is a valid staging-texture description; `texture` is a
        // valid out-pointer; no initial data is provided.
        unsafe {
            self.device
                .CreateTexture2D(&raw const desc, None, Some(&raw mut texture))
                .map_err(|error| os_error(&error))?;
        }
        let texture =
            texture.ok_or_else(|| CaptureError::Os("CreateTexture2D returned null".into()))?;
        self.staging = Some(StagingTexture {
            texture,
            width,
            height,
        });
        Ok(())
    }
}

impl Drop for WgcCapturer {
    fn drop(&mut self) {
        let _ = self.session.Close();
        let _ = self.frame_pool.Close();
    }
}

impl Capturer for WgcCapturer {
    fn next_frame(&mut self, timeout: Duration) -> Result<Option<Frame>, CaptureError> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(frame) = self.read_frame()? {
                return Ok(Some(frame));
            }
            if Instant::now() >= deadline {
                return Ok(None);
            }
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    fn size(&self) -> (u32, u32) {
        (self.bounds.width, self.bounds.height)
    }

    fn bounds(&self) -> DisplayBounds {
        self.bounds
    }

    fn d3d11_device(&self) -> Option<&ID3D11Device> {
        Some(&self.device)
    }
}

/// Finds the `HMONITOR` and desktop bounds for monitor `index`, matching the
/// DXGI output ordering used by [`crate::dxgi`].
fn monitor_for_index(index: u32) -> Result<(HMONITOR, DisplayBounds), CaptureError> {
    // SAFETY: returns a newly owned DXGI factory.
    let factory: IDXGIFactory1 =
        unsafe { CreateDXGIFactory1() }.map_err(|error| os_error(&error))?;
    let mut remaining = index;
    let mut adapter_index = 0;
    loop {
        // SAFETY: `factory` is valid; an out-of-range index returns NOT_FOUND.
        let adapter = match unsafe { factory.EnumAdapters1(adapter_index) } {
            Ok(adapter) => adapter,
            Err(error) if error.code() == DXGI_ERROR_NOT_FOUND => {
                return Err(CaptureError::DisplayNotFound(index));
            }
            Err(error) => return Err(os_error(&error)),
        };
        let mut output_index = 0;
        loop {
            // SAFETY: `adapter` is valid; an out-of-range index returns NOT_FOUND.
            let output = match unsafe { adapter.EnumOutputs(output_index) } {
                Ok(output) => output,
                Err(error) if error.code() == DXGI_ERROR_NOT_FOUND => break,
                Err(error) => return Err(os_error(&error)),
            };
            output_index += 1;
            // SAFETY: `output` is valid; the description is returned by value.
            let desc = unsafe { output.GetDesc() }.map_err(|error| os_error(&error))?;
            if !desc.AttachedToDesktop.as_bool() {
                continue;
            }
            if remaining == 0 {
                let rect = desc.DesktopCoordinates;
                let bounds = DisplayBounds {
                    x: rect.left,
                    y: rect.top,
                    width: (rect.right - rect.left).unsigned_abs(),
                    height: (rect.bottom - rect.top).unsigned_abs(),
                };
                return Ok((desc.Monitor, bounds));
            }
            remaining -= 1;
        }
        adapter_index += 1;
    }
}

/// Creates a BGRA-capable `D3D11` device (hardware, falling back to WARP).
fn create_device() -> Result<(ID3D11Device, ID3D11DeviceContext), CaptureError> {
    for driver in [D3D_DRIVER_TYPE_HARDWARE, D3D_DRIVER_TYPE_WARP] {
        let mut device: Option<ID3D11Device> = None;
        let mut context: Option<ID3D11DeviceContext> = None;
        // SAFETY: all pointers are valid out-parameters; no adapter or feature
        // level list is supplied, so the default is used.
        let result = unsafe {
            D3D11CreateDevice(
                None,
                driver,
                HMODULE::default(),
                D3D11_CREATE_DEVICE_BGRA_SUPPORT,
                None,
                D3D11_SDK_VERSION,
                Some(&raw mut device),
                None,
                Some(&raw mut context),
            )
        };
        if result.is_ok()
            && let (Some(device), Some(context)) = (device, context)
        {
            return Ok((device, context));
        }
    }
    Err(CaptureError::Os(
        "D3D11CreateDevice failed for WGC".to_owned(),
    ))
}

/// Maps a Windows error into a [`CaptureError`].
fn os_error(error: &windows::core::Error) -> CaptureError {
    CaptureError::Os(error.message())
}
