//! Client window: presents the latest decoded frame and captures keyboard and pointer input.

use std::num::NonZeroU32;
use std::rc::Rc;
use std::time::Duration;

use anyhow::anyhow;
use omegadesk_input::{WHEEL_STEP, buttons};
use omegadesk_protocol::v1::{Envelope, KeyEvent, PointerEvent, envelope::Payload};
use softbuffer::{Context, Surface};
use tokio::sync::mpsc;
use tracing::warn;
use winit::application::ApplicationHandler;
use winit::dpi::LogicalSize;
use winit::event::{ElementState, MouseButton, MouseScrollDelta, WindowEvent};
use winit::event_loop::ActiveEventLoop;
use winit::keyboard::{Key, PhysicalKey};
use winit::window::{Window, WindowId};

use crate::keymap::keycode_to_hid;
use crate::stats::{LatestFrame, Meter, Shared};

/// Title bar latency summary refresh interval.
const TITLE_PERIOD: Duration = Duration::from_millis(500);

/// Custom events sent to the window event loop by background threads.
#[derive(Debug, Clone, Copy)]
pub(crate) enum UserEvent {
    /// A newly decoded frame is ready to be drawn.
    Frame,
    /// The connection status string changed.
    Status,
    /// The session ended.
    Disconnected,
}

struct Graphics {
    window: Rc<Window>,
    surface: Surface<Rc<Window>, Rc<Window>>,
}

pub(crate) struct App {
    shared: Shared,
    input: mpsc::UnboundedSender<Envelope>,
    view_only: bool,
    graphics: Option<Graphics>,
    current: Option<LatestFrame>,
    meter: Meter,
    cursor: (f64, f64),
    pressed_buttons: u32,
    pressed_keys: std::collections::BTreeSet<u32>,
    error: Option<anyhow::Error>,
}

impl App {
    pub(crate) fn new(
        shared: Shared,
        input: mpsc::UnboundedSender<Envelope>,
        view_only: bool,
    ) -> Self {
        Self {
            shared,
            input,
            view_only,
            graphics: None,
            current: None,
            meter: Meter::default(),
            cursor: (0.0, 0.0),
            pressed_buttons: 0,
            pressed_keys: std::collections::BTreeSet::new(),
            error: None,
        }
    }

    pub(crate) fn into_result(self) -> anyhow::Result<()> {
        self.error.map_or(Ok(()), Err)
    }

    fn release_all(&mut self) {
        for hid_usage in std::mem::take(&mut self.pressed_keys) {
            self.send(Payload::KeyEvent(KeyEvent {
                hid_usage,
                keysym: 0,
                pressed: false,
                modifiers: 0,
            }));
        }
        if self.pressed_buttons != 0 {
            self.pressed_buttons = 0;
            self.send_pointer(0, 0);
        }
    }

    fn send(&self, payload: Payload) {
        if !self.view_only {
            let _ = self.input.send(Envelope {
                payload: Some(payload),
            });
        }
    }

    fn send_pointer(&self, wheel_x: i32, wheel_y: i32) {
        let Some(graphics) = &self.graphics else {
            return;
        };
        let size = graphics.window.inner_size();
        if size.width == 0 || size.height == 0 {
            return;
        }
        let normalize = |position: f64, extent: u32| -> u32 {
            let ratio = (position / f64::from(extent)).clamp(0.0, 1.0);
            // `0.0..=1.0 * 65535.0` fits in `u32` without sign or precision loss.
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let scaled = (ratio * 65_535.0).round() as u32;
            scaled
        };
        self.send(Payload::PointerEvent(PointerEvent {
            display_index: 0,
            x: normalize(self.cursor.0, size.width),
            y: normalize(self.cursor.1, size.height),
            buttons: self.pressed_buttons,
            wheel_x,
            wheel_y,
        }));
    }

    fn update_title(&self, extra: &str) {
        if let Some(graphics) = &self.graphics {
            let status = self.shared.status();
            graphics
                .window
                .set_title(&format!("OmegaDesk — {status}{extra}"));
        }
    }

    fn redraw(&mut self) {
        if let Some(latest) = self.shared.take_latest() {
            self.current = Some(latest);
        }
        let (Some(graphics), Some(frame)) = (&mut self.graphics, &self.current) else {
            return;
        };
        let size = graphics.window.inner_size();
        let (Some(width), Some(height)) =
            (NonZeroU32::new(size.width), NonZeroU32::new(size.height))
        else {
            return;
        };
        if let Err(error) = graphics.surface.resize(width, height) {
            warn!("failed to resize window surface: {error}");
            return;
        }
        let mut buffer = match graphics.surface.buffer_mut() {
            Ok(buffer) => buffer,
            Err(error) => {
                warn!("window surface buffer unavailable: {error}");
                return;
            }
        };
        scale_nearest(&frame.image, &mut buffer, size.width, size.height);
        if let Err(error) = buffer.present() {
            warn!("failed to present frame: {error}");
            return;
        }

        self.meter.record(
            frame.host_processing,
            frame.decode,
            frame.decoded_at.elapsed(),
        );
        if let Some(summary) = self.meter.summary(TITLE_PERIOD, self.shared.rtt()) {
            let ms = |d: Duration| d.as_secs_f64() * 1000.0;
            let image = &frame.image;
            self.update_title(&format!(
                " — {}x{} {:.0} fps — host {:.1} ms · net {:.1} ms · decode {:.1} ms · draw {:.1} ms · total {:.1} ms",
                image.width,
                image.height,
                summary.fps,
                ms(summary.host),
                ms(summary.network),
                ms(summary.decode),
                ms(summary.render),
                ms(summary.total()),
            ));
        }
    }
}

/// Nearest-neighbor scaling of `image` into the `width`x`height` window buffer.
fn scale_nearest(
    image: &omegadesk_codec::DecodedImage,
    target: &mut [u32],
    width: u32,
    height: u32,
) {
    if image.width == 0 || image.height == 0 {
        return;
    }
    let (src_w, src_h) = (image.width as usize, image.height as usize);
    let (dst_w, dst_h) = (width as usize, height as usize);
    if (src_w, src_h) == (dst_w, dst_h) {
        target.copy_from_slice(&image.xrgb[..dst_w * dst_h]);
        return;
    }
    let columns: Vec<usize> = (0..dst_w).map(|x| x * src_w / dst_w).collect();
    for (y, row) in target.chunks_exact_mut(dst_w).enumerate().take(dst_h) {
        let src_row = &image.xrgb[(y * src_h / dst_h) * src_w..][..src_w];
        for (pixel, &column) in row.iter_mut().zip(&columns) {
            *pixel = src_row[column];
        }
    }
}

fn button_bit(button: MouseButton) -> u32 {
    match button {
        MouseButton::Left => buttons::LEFT,
        MouseButton::Right => buttons::RIGHT,
        MouseButton::Middle => buttons::MIDDLE,
        MouseButton::Back => buttons::BACK,
        MouseButton::Forward => buttons::FORWARD,
        MouseButton::Other(_) => 0,
    }
}

/// Converts a `winit` scroll delta into protocol `1/120`-notch units (`WHEEL_STEP`).
///
/// `winit` reports positive horizontal deltas when scrolling left (matching
/// vertical deltas where positive is up, i.e. the direction content moves),
/// whereas [`PointerEvent`] and Win32 `MOUSEEVENTF_HWHEEL` use positive values
/// for scrolling right and up, so horizontal `x` is negated.
fn scroll_deltas(delta: MouseScrollDelta) -> (i32, i32) {
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_precision_loss,
        reason = "scroll deltas are small"
    )]
    match delta {
        MouseScrollDelta::LineDelta(x, y) => (
            (-x * WHEEL_STEP as f32).round() as i32,
            (y * WHEEL_STEP as f32).round() as i32,
        ),
        MouseScrollDelta::PixelDelta(position) => {
            ((-position.x).round() as i32, position.y.round() as i32)
        }
    }
}

impl ApplicationHandler<UserEvent> for App {
    fn resumed(&mut self, event_loop: &ActiveEventLoop) {
        if self.graphics.is_some() {
            return;
        }
        let attributes = Window::default_attributes()
            .with_title("OmegaDesk")
            .with_inner_size(LogicalSize::new(1280.0, 720.0));
        let created = event_loop
            .create_window(attributes)
            .map_err(|e| anyhow!("window: {e}"))
            .and_then(|window| {
                let window = Rc::new(window);
                let context =
                    Context::new(window.clone()).map_err(|e| anyhow!("surface context: {e}"))?;
                let surface =
                    Surface::new(&context, window.clone()).map_err(|e| anyhow!("surface: {e}"))?;
                Ok(Graphics { window, surface })
            });
        match created {
            Ok(graphics) => {
                self.graphics = Some(graphics);
                self.update_title("");
            }
            Err(error) => {
                self.error = Some(error);
                event_loop.exit();
            }
        }
    }

    fn user_event(&mut self, event_loop: &ActiveEventLoop, event: UserEvent) {
        match event {
            UserEvent::Frame => {
                if let Some(graphics) = &self.graphics {
                    graphics.window.request_redraw();
                }
            }
            UserEvent::Status => self.update_title(""),
            UserEvent::Disconnected => {
                let status = self.shared.status();
                if status.starts_with("error") {
                    self.error = Some(anyhow!(status));
                }
                event_loop.exit();
            }
        }
    }

    #[allow(
        clippy::wildcard_enum_match_arm,
        reason = "winit emits dozens of window events that the client does not handle"
    )]
    fn window_event(&mut self, event_loop: &ActiveEventLoop, _id: WindowId, event: WindowEvent) {
        match event {
            WindowEvent::CloseRequested => event_loop.exit(),
            WindowEvent::RedrawRequested => self.redraw(),
            WindowEvent::Resized(_) => {
                if let Some(graphics) = &self.graphics {
                    graphics.window.request_redraw();
                }
            }
            WindowEvent::CursorMoved { position, .. } => {
                self.cursor = (position.x, position.y);
                self.send_pointer(0, 0);
            }
            WindowEvent::MouseInput { state, button, .. } => {
                let bit = button_bit(button);
                match state {
                    ElementState::Pressed => self.pressed_buttons |= bit,
                    ElementState::Released => self.pressed_buttons &= !bit,
                }
                self.send_pointer(0, 0);
            }
            WindowEvent::MouseWheel { delta, .. } => {
                let (x, y) = scroll_deltas(delta);
                self.send_pointer(x, y);
            }
            WindowEvent::KeyboardInput { event, .. } => {
                let PhysicalKey::Code(code) = event.physical_key else {
                    return;
                };
                let Some(hid_usage) = keycode_to_hid(code) else {
                    return;
                };
                let keysym = match &event.logical_key {
                    Key::Character(text) => text.chars().next().map_or(0, u32::from),
                    _ => 0,
                };
                let pressed = event.state == ElementState::Pressed;
                if pressed {
                    self.pressed_keys.insert(hid_usage);
                } else {
                    self.pressed_keys.remove(&hid_usage);
                }
                self.send(Payload::KeyEvent(KeyEvent {
                    hid_usage,
                    keysym,
                    pressed,
                    modifiers: 0,
                }));
            }
            // When the window loses focus (Alt+Tab or clicking outside), release
            // every held key and button (matching Moonlight's `raiseAllKeys`) so
            // modifiers like Alt or Ctrl never get stuck on the remote machine.
            WindowEvent::Focused(false) => self.release_all(),
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use omegadesk_input::WHEEL_STEP;
    use winit::dpi::PhysicalPosition;
    use winit::event::MouseScrollDelta;

    use super::scroll_deltas;

    #[test]
    fn horizontal_scroll_sign_is_inverted_for_win32_hwheel() {
        // winit reports -1.0 horizontal line delta when scrolling right on Windows;
        // PointerEvent/MOUSEEVENTF_HWHEEL expects +WHEEL_STEP for scrolling right.
        assert_eq!(
            scroll_deltas(MouseScrollDelta::LineDelta(-1.0, 1.0)),
            (WHEEL_STEP, WHEEL_STEP)
        );
        assert_eq!(
            scroll_deltas(MouseScrollDelta::LineDelta(1.0, -1.0)),
            (-WHEEL_STEP, -WHEEL_STEP)
        );
        assert_eq!(
            scroll_deltas(MouseScrollDelta::PixelDelta(PhysicalPosition::new(
                -45.0, 60.0
            ))),
            (45, 60)
        );
    }
}
