//! PipeWire screen capture negotiated through the `xdg-desktop-portal` ScreenCast portal.
//!
//! Model: Sunshine `src/platform/linux/portalgrab.cpp` (the portal `CreateSession` →
//! `SelectSources` → `Start` → `OpenPipeWireRemote` sequence) and `pipewire.cpp` (stream
//! format negotiation and buffer handling). The portal negotiation uses `ashpd`; the
//! PipeWire stream uses the `pipewire` crate. Both the portal and the PipeWire loop run on
//! a dedicated thread; [`PipeWireCapturer::open`] blocks until the stream format is known
//! or an error is reported, and [`PipeWireCapturer`] hands frames to the agent through the
//! same blocking [`Capturer`] interface the Windows and X11 backends use.
//!
//! The portal requires a user session with `xdg-desktop-portal` running (and, the first
//! time, the user's approval). On a headless machine (CI) there is no portal, so
//! [`PipeWireCapturer::open`] fails quickly and the caller falls back to X11.

use std::os::fd::OwnedFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use ashpd::desktop::PersistMode;
use ashpd::desktop::screencast::{CursorMode, Screencast, SelectSourcesOptions, SourceType};
use pipewire as pw;
use pw::spa::param::video::{VideoFormat, VideoInfoRaw};
use pw::{properties::properties, spa};
use tracing::{debug, warn};

use crate::convert::{PixelLayout, rows_to_bgra};
use crate::{CaptureError, Capturer, DisplayBounds, Frame};

/// How long to wait for the portal dialog and the first negotiated frame.
const NEGOTIATION_TIMEOUT: Duration = Duration::from_secs(30);

/// Latest frame shared between the PipeWire loop and the capturer.
#[derive(Default)]
struct FrameSlot {
    state: Mutex<SlotState>,
    ready: Condvar,
}

#[derive(Default)]
struct SlotState {
    frame: Option<Frame>,
    last: Vec<u8>,
    size: (u32, u32),
    closed: Option<String>,
}

impl FrameSlot {
    fn lock(&self) -> std::sync::MutexGuard<'_, SlotState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Stores `frame` unless it is identical to the previous one (static screen), so the
    /// agent re-encodes only on change.
    fn publish(&self, width: u32, height: u32, bgra: Vec<u8>) {
        let mut state = self.lock();
        state.size = (width, height);
        if state.last == bgra {
            return;
        }
        state.last.clone_from(&bgra);
        state.frame = Some(Frame {
            width,
            height,
            bgra,
            captured_at: Instant::now(),
        });
        drop(state);
        self.ready.notify_all();
    }

    fn close(&self, reason: String) {
        self.lock().closed = Some(reason);
        self.ready.notify_all();
    }
}

/// PipeWire screen capturer for one portal-selected monitor.
pub struct PipeWireCapturer {
    slot: Arc<FrameSlot>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    bounds: DisplayBounds,
}

impl std::fmt::Debug for PipeWireCapturer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PipeWireCapturer")
            .field("bounds", &self.bounds)
            .finish_non_exhaustive()
    }
}

/// Signal sent from the PipeWire thread once the stream format is known or negotiation
/// failed.
type Ready = Result<DisplayBounds, CaptureError>;

impl PipeWireCapturer {
    /// Negotiates a ScreenCast stream for monitor `index` (`0` is the first stream the
    /// portal returns) and starts the PipeWire loop.
    ///
    /// # Errors
    ///
    /// Returns [`CaptureError::Os`] when the portal is unavailable or the user cancels,
    /// [`CaptureError::DisplayNotFound`] when `index` names no portal stream, and
    /// [`CaptureError::AccessLost`] when the negotiation times out.
    pub fn open(index: u32) -> Result<Self, CaptureError> {
        let slot = Arc::new(FrameSlot::default());
        let stop = Arc::new(AtomicBool::new(false));
        let (ready_tx, ready_rx) = std::sync::mpsc::channel::<Ready>();

        let thread_slot = slot.clone();
        let thread_stop = stop.clone();
        let thread = std::thread::Builder::new()
            .name("pipewire-capture".to_owned())
            .spawn(move || run_capture(index, &thread_slot, &thread_stop, &ready_tx))
            .map_err(|error| CaptureError::Os(format!("spawn PipeWire thread: {error}")))?;

        match ready_rx.recv_timeout(NEGOTIATION_TIMEOUT) {
            Ok(Ok(bounds)) => Ok(Self {
                slot,
                stop,
                thread: Some(thread),
                bounds,
            }),
            Ok(Err(error)) => {
                stop.store(true, Ordering::SeqCst);
                let _ = thread.join();
                Err(error)
            }
            Err(_) => {
                stop.store(true, Ordering::SeqCst);
                Err(CaptureError::AccessLost)
            }
        }
    }
}

impl Drop for PipeWireCapturer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Capturer for PipeWireCapturer {
    fn next_frame(&mut self, timeout: Duration) -> Result<Option<Frame>, CaptureError> {
        let deadline = Instant::now() + timeout;
        let mut state = self.slot.lock();
        loop {
            if let Some(frame) = state.frame.take() {
                return Ok(Some(frame));
            }
            if let Some(reason) = &state.closed {
                return Err(CaptureError::Os(format!("PipeWire capture: {reason}")));
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
        self.bounds
    }
}

/// Portal result: the PipeWire node id to connect to, the remote fd, and the monitor size
/// the portal reported (when it did).
struct PortalStream {
    node_id: u32,
    fd: OwnedFd,
    size: Option<(i32, i32)>,
    position: Option<(i32, i32)>,
}

/// Runs the ScreenCast portal negotiation on a current-thread Tokio runtime.
#[allow(
    clippy::default_trait_access,
    reason = "ashpd's per-call option structs are private; only `Default::default()` can name them"
)]
async fn negotiate_portal(index: u32) -> Result<PortalStream, CaptureError> {
    let proxy = Screencast::new()
        .await
        .map_err(|error| CaptureError::Os(format!("ScreenCast portal unavailable: {error}")))?;
    let session = proxy
        .create_session(Default::default())
        .await
        .map_err(|error| CaptureError::Os(format!("portal CreateSession: {error}")))?;
    proxy
        .select_sources(
            &session,
            SelectSourcesOptions::default()
                .set_cursor_mode(CursorMode::Hidden)
                .set_sources(Some(SourceType::Monitor.into()))
                .set_multiple(true)
                .set_persist_mode(PersistMode::DoNot),
        )
        .await
        .map_err(|error| CaptureError::Os(format!("portal SelectSources: {error}")))?;
    let response = proxy
        .start(&session, None, Default::default())
        .await
        .map_err(|error| CaptureError::Os(format!("portal Start: {error}")))?
        .response()
        .map_err(|error| CaptureError::Os(format!("portal declined: {error}")))?;
    let stream = response
        .streams()
        .get(usize::try_from(index).map_err(|_| CaptureError::DisplayNotFound(index))?)
        .ok_or(CaptureError::DisplayNotFound(index))?;
    let node_id = stream.pipe_wire_node_id();
    let size = stream.size();
    let position = stream.position();
    let fd = proxy
        .open_pipe_wire_remote(&session, Default::default())
        .await
        .map_err(|error| CaptureError::Os(format!("portal OpenPipeWireRemote: {error}")))?;
    Ok(PortalStream {
        node_id,
        fd,
        size,
        position,
    })
}

/// User data of the PipeWire stream listener.
struct StreamData {
    slot: Arc<FrameSlot>,
    format: VideoInfoRaw,
    layout: Option<PixelLayout>,
    position: Option<(i32, i32)>,
    ready: Option<std::sync::mpsc::Sender<Ready>>,
}

/// Maps a negotiated SPA video format to the in-memory byte order [`rows_to_bgra`] expects.
fn layout_of(format: VideoFormat) -> Option<PixelLayout> {
    let raw = format.as_raw();
    if raw == VideoFormat::BGRx.as_raw() || raw == VideoFormat::BGRA.as_raw() {
        Some(PixelLayout::Bgrx)
    } else if raw == VideoFormat::RGBx.as_raw() || raw == VideoFormat::RGBA.as_raw() {
        Some(PixelLayout::Rgbx)
    } else if raw == VideoFormat::xRGB.as_raw() || raw == VideoFormat::ARGB.as_raw() {
        Some(PixelLayout::Xrgb)
    } else if raw == VideoFormat::xBGR.as_raw() || raw == VideoFormat::ABGR.as_raw() {
        Some(PixelLayout::Xbgr)
    } else {
        None
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "one function owns the whole PipeWire loop lifecycle: portal, stream, run"
)]
fn run_capture(
    index: u32,
    slot: &Arc<FrameSlot>,
    stop: &Arc<AtomicBool>,
    ready: &std::sync::mpsc::Sender<Ready>,
) {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            let _ = ready.send(Err(CaptureError::Os(format!("tokio runtime: {error}"))));
            return;
        }
    };
    let portal = match runtime.block_on(async {
        tokio::time::timeout(NEGOTIATION_TIMEOUT, negotiate_portal(index)).await
    }) {
        Ok(Ok(portal)) => portal,
        Ok(Err(error)) => {
            let _ = ready.send(Err(error));
            return;
        }
        Err(_) => {
            let _ = ready.send(Err(CaptureError::AccessLost));
            return;
        }
    };

    pw::init();
    let result = (|| -> Result<(), CaptureError> {
        let mainloop = pw::main_loop::MainLoopRc::new(None)
            .map_err(|error| CaptureError::Os(format!("PipeWire main loop: {error}")))?;
        let context = pw::context::ContextRc::new(&mainloop, None)
            .map_err(|error| CaptureError::Os(format!("PipeWire context: {error}")))?;
        let core = context
            .connect_fd_rc(portal.fd, None)
            .map_err(|error| CaptureError::Os(format!("PipeWire connect: {error}")))?;

        let stream = pw::stream::StreamRc::new(
            core,
            "omegadesk-capture",
            properties! {
                *pw::keys::MEDIA_TYPE => "Video",
                *pw::keys::MEDIA_CATEGORY => "Capture",
                *pw::keys::MEDIA_ROLE => "Screen",
            },
        )
        .map_err(|error| CaptureError::Os(format!("PipeWire stream: {error}")))?;

        let data = StreamData {
            slot: slot.clone(),
            format: VideoInfoRaw::default(),
            layout: None,
            position: portal.position,
            ready: Some(ready.clone()),
        };
        let _listener = stream
            .add_local_listener_with_user_data(data)
            .state_changed(move |_, data, old, new| {
                debug!("PipeWire stream state: {old:?} -> {new:?}");
                if let pw::stream::StreamState::Error(message) = new {
                    data.slot.close(format!("stream error: {message}"));
                    if let Some(ready) = data.ready.take() {
                        let _ =
                            ready.send(Err(CaptureError::Os(format!("stream error: {message}"))));
                    }
                } else if old == pw::stream::StreamState::Streaming
                    && new == pw::stream::StreamState::Unconnected
                {
                    data.slot.close("stream disconnected".to_owned());
                    if let Some(ready) = data.ready.take() {
                        let _ = ready.send(Err(CaptureError::AccessLost));
                    }
                }
            })
            .param_changed(|_, data, id, param| {
                let Some(param) = param else { return };
                if id != pw::spa::param::ParamType::Format.as_raw() {
                    return;
                }
                let Ok((media_type, media_subtype)) =
                    pw::spa::param::format_utils::parse_format(param)
                else {
                    return;
                };
                if media_type != pw::spa::param::format::MediaType::Video
                    || media_subtype != pw::spa::param::format::MediaSubtype::Raw
                {
                    return;
                }
                if data.format.parse(param).is_err() {
                    return;
                }
                let Some(layout) = layout_of(data.format.format()) else {
                    warn!(
                        "unsupported PipeWire video format {:?}",
                        data.format.format()
                    );
                    data.slot
                        .close(format!("unsupported format {:?}", data.format.format()));
                    if let Some(ready) = data.ready.take() {
                        let _ =
                            ready.send(Err(CaptureError::Os("unsupported PipeWire format".into())));
                    }
                    return;
                };
                data.layout = Some(layout);
                let size = data.format.size();
                if let Some(ready) = data.ready.take() {
                    let (x, y) = data.position.unwrap_or((0, 0));
                    let _ = ready.send(Ok(DisplayBounds {
                        x,
                        y,
                        width: size.width,
                        height: size.height,
                    }));
                }
            })
            .process(|stream, data| {
                let Some(layout) = data.layout else { return };
                let Some(mut buffer) = stream.dequeue_buffer() else {
                    return;
                };
                let planes = buffer.datas_mut();
                let Some(plane) = planes.first_mut() else {
                    return;
                };
                let chunk = plane.chunk();
                let width = data.format.size().width as usize;
                let height = data.format.size().height as usize;
                let stride = usize::try_from(chunk.stride())
                    .unwrap_or(width * 4)
                    .max(width * 4);
                let Some(pixels) = plane.data() else { return };
                if let Some(bgra) = rows_to_bgra(pixels, width, height, stride, layout) {
                    data.slot
                        .publish(data.format.size().width, data.format.size().height, bgra);
                }
            })
            .register()
            .map_err(|error| CaptureError::Os(format!("PipeWire listener: {error}")))?;

        let obj = pw::spa::pod::object!(
            pw::spa::utils::SpaTypes::ObjectParamFormat,
            pw::spa::param::ParamType::EnumFormat,
            pw::spa::pod::property!(
                pw::spa::param::format::FormatProperties::MediaType,
                Id,
                pw::spa::param::format::MediaType::Video
            ),
            pw::spa::pod::property!(
                pw::spa::param::format::FormatProperties::MediaSubtype,
                Id,
                pw::spa::param::format::MediaSubtype::Raw
            ),
            pw::spa::pod::property!(
                pw::spa::param::format::FormatProperties::VideoFormat,
                Choice,
                Enum,
                Id,
                VideoFormat::BGRx,
                VideoFormat::BGRx,
                VideoFormat::BGRA,
                VideoFormat::RGBx,
                VideoFormat::RGBA,
                VideoFormat::xRGB,
                VideoFormat::ARGB,
            ),
            pw::spa::pod::property!(
                pw::spa::param::format::FormatProperties::VideoSize,
                Choice,
                Range,
                Rectangle,
                spa::utils::Rectangle {
                    width: 1920,
                    height: 1080,
                },
                spa::utils::Rectangle {
                    width: 1,
                    height: 1,
                },
                spa::utils::Rectangle {
                    width: 8192,
                    height: 8192,
                }
            ),
            pw::spa::pod::property!(
                pw::spa::param::format::FormatProperties::VideoFramerate,
                Choice,
                Range,
                Fraction,
                spa::utils::Fraction { num: 60, denom: 1 },
                spa::utils::Fraction { num: 0, denom: 1 },
                spa::utils::Fraction { num: 120, denom: 1 }
            ),
        );
        let values = pw::spa::pod::serialize::PodSerializer::serialize(
            std::io::Cursor::new(Vec::new()),
            &pw::spa::pod::Value::Object(obj),
        )
        .map(|(cursor, _)| cursor.into_inner())
        .map_err(|error| CaptureError::Os(format!("serialize SPA pod: {error}")))?;
        let mut params = [pw::spa::pod::Pod::from_bytes(&values)
            .ok_or_else(|| CaptureError::Os("invalid SPA pod".into()))?];

        stream
            .connect(
                spa::utils::Direction::Input,
                Some(portal.node_id),
                pw::stream::StreamFlags::AUTOCONNECT | pw::stream::StreamFlags::MAP_BUFFERS,
                &mut params,
            )
            .map_err(|error| CaptureError::Os(format!("PipeWire connect stream: {error}")))?;

        // A 100 ms timer lets the capturer's Drop stop the loop without a PipeWire channel.
        let quit_loop = mainloop.clone();
        let quit_stop = stop.clone();
        let timer = mainloop.loop_().add_timer(move |_| {
            if quit_stop.load(Ordering::SeqCst) {
                quit_loop.quit();
            }
        });
        timer
            .update_timer(
                Some(Duration::from_millis(100)),
                Some(Duration::from_millis(100)),
            )
            .into_result()
            .map_err(|error| CaptureError::Os(format!("arm PipeWire timer: {error}")))?;

        let _ = portal.size;
        mainloop.run();
        Ok(())
    })();

    if let Err(error) = result {
        let _ = ready.send(Err(error.clone()));
        slot.close(error.to_string());
    } else {
        slot.close("PipeWire loop ended".to_owned());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negotiated_formats_map_to_their_in_memory_layout() {
        for format in [VideoFormat::BGRx, VideoFormat::BGRA] {
            assert_eq!(layout_of(format), Some(PixelLayout::Bgrx));
        }
        for format in [VideoFormat::RGBx, VideoFormat::RGBA] {
            assert_eq!(layout_of(format), Some(PixelLayout::Rgbx));
        }
        for format in [VideoFormat::xRGB, VideoFormat::ARGB] {
            assert_eq!(layout_of(format), Some(PixelLayout::Xrgb));
        }
        for format in [VideoFormat::xBGR, VideoFormat::ABGR] {
            assert_eq!(layout_of(format), Some(PixelLayout::Xbgr));
        }
        assert_eq!(layout_of(VideoFormat::I420), None);
    }
}
