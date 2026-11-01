//! Client window: presents the latest decoded frame and captures keyboard and pointer input.

use std::num::NonZeroU32;
use std::rc::Rc;
use std::time::{Duration, Instant};

use anyhow::anyhow;
use omegadesk_input::{WHEEL_STEP, buttons, modifiers};
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
use crate::win_hook::{self, KeyboardHook};

/// Title bar latency summary refresh interval.
const TITLE_PERIOD: Duration = Duration::from_millis(500);

/// Maximum delay between a synthetic `ControlLeft` press and the corresponding
/// `AltRight` press on `AltGr` layouts (`TigerVNC` `KeyboardWin32.cxx`).
const ALTGR_SYNTHETIC_WINDOW: Duration = Duration::from_millis(50);

const HID_DELETE: u32 = 0x4C;
const HID_END: u32 = 0x4D;
const HID_LEFT_CTRL: u32 = 0xE0;
const HID_LEFT_SHIFT: u32 = 0xE1;
const HID_LEFT_ALT: u32 = 0xE2;
const HID_LEFT_META: u32 = 0xE3;
const HID_RIGHT_CTRL: u32 = 0xE4;
const HID_RIGHT_SHIFT: u32 = 0xE5;
const HID_RIGHT_ALT: u32 = 0xE6;
const HID_RIGHT_META: u32 = 0xE7;

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

/// Destination rectangle inside the client window that preserves the remote
/// display's aspect ratio (letterbox or pillarbox).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Viewport {
    pub(crate) x: u32,
    pub(crate) y: u32,
    pub(crate) width: u32,
    pub(crate) height: u32,
}

impl Viewport {
    /// Computes the largest centered rectangle inside `dst_w`x`dst_h` that
    /// preserves the aspect ratio `src_w:src_h`.
    #[must_use]
    pub(crate) fn fit(src_w: u32, src_h: u32, dst_w: u32, dst_h: u32) -> Self {
        if src_w == 0 || src_h == 0 || dst_w == 0 || dst_h == 0 {
            return Self {
                x: 0,
                y: 0,
                width: dst_w,
                height: dst_h,
            };
        }
        let lhs = u64::from(dst_w) * u64::from(src_h);
        let rhs = u64::from(dst_h) * u64::from(src_w);
        #[allow(
            clippy::cast_possible_truncation,
            reason = "scaled dimensions are bounded by dst_w and dst_h which fit in u32"
        )]
        let (width, height) = if lhs <= rhs {
            let h = ((u64::from(dst_w) * u64::from(src_h)) / u64::from(src_w)).max(1) as u32;
            (dst_w, h.min(dst_h))
        } else {
            let w = ((u64::from(dst_h) * u64::from(src_w)) / u64::from(src_h)).max(1) as u32;
            (w.min(dst_w), dst_h)
        };
        Self {
            x: (dst_w - width) / 2,
            y: (dst_h - height) / 2,
            width,
            height,
        }
    }
}

/// Maps window-space cursor coordinates `(cursor_x, cursor_y)` into normalized
/// `0..=65535` remote display coordinates relative to the aspect-ratio
/// preserving [`Viewport`].
#[must_use]
pub(crate) fn cursor_to_remote(
    cursor_x: f64,
    cursor_y: f64,
    dst_w: u32,
    dst_h: u32,
    src_w: u32,
    src_h: u32,
) -> (u32, u32) {
    let vp = Viewport::fit(src_w, src_h, dst_w, dst_h);
    if vp.width == 0 || vp.height == 0 {
        return (0, 0);
    }
    let normalize = |pos: f64, start: u32, extent: u32| -> u32 {
        let ratio = ((pos - f64::from(start)) / f64::from(extent)).clamp(0.0, 1.0);
        // `0.0..=1.0 * 65535.0` fits in `u32` without sign or precision loss.
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let scaled = (ratio * 65_535.0).round() as u32;
        scaled
    };
    (
        normalize(cursor_x, vp.x, vp.width),
        normalize(cursor_y, vp.y, vp.height),
    )
}

/// Accumulates fractional scroll deltas across high-frequency trackpad events
/// so sub-pixel movements are not lost to integer rounding.
#[derive(Debug, Default)]
pub(crate) struct ScrollAccumulator {
    accum_x: f64,
    accum_y: f64,
}

impl ScrollAccumulator {
    /// Converts a `winit` scroll delta into integer protocol `1/120`-notch
    /// steps, retaining the fractional remainder for subsequent events.
    ///
    /// `winit` reports positive horizontal deltas when scrolling left (matching
    /// vertical deltas where positive is up, i.e. the direction content moves),
    /// whereas [`PointerEvent`] and Win32 `MOUSEEVENTF_HWHEEL` use positive
    /// values for scrolling right and up, so horizontal `x` is negated.
    pub(crate) fn accumulate(&mut self, delta: MouseScrollDelta) -> (i32, i32) {
        let (dx, dy) = match delta {
            MouseScrollDelta::LineDelta(x, y) => (
                f64::from(-x) * f64::from(WHEEL_STEP),
                f64::from(y) * f64::from(WHEEL_STEP),
            ),
            MouseScrollDelta::PixelDelta(position) => (-position.x, position.y),
        };
        self.accum_x += dx;
        self.accum_y += dy;
        #[allow(
            clippy::cast_possible_truncation,
            reason = "clamped to i32::MIN..=i32::MAX before casting"
        )]
        let step_x = self
            .accum_x
            .trunc()
            .clamp(f64::from(i32::MIN), f64::from(i32::MAX)) as i32;
        #[allow(
            clippy::cast_possible_truncation,
            reason = "clamped to i32::MIN..=i32::MAX before casting"
        )]
        let step_y = self
            .accum_y
            .trunc()
            .clamp(f64::from(i32::MIN), f64::from(i32::MAX)) as i32;
        self.accum_x -= f64::from(step_x);
        self.accum_y -= f64::from(step_y);
        (step_x, step_y)
    }
}

/// Filters synthetic `ControlLeft` key events generated immediately before
/// `AltRight` on international `AltGr` keyboard layouts when the OS or window
/// system does not strip them in a low-level hook.
#[derive(Debug, Default)]
pub(crate) struct AltGrFilter {
    last_lctrl_press: Option<Instant>,
    suppress_lctrl_release: bool,
}

impl AltGrFilter {
    /// Inspects `(hid_usage, pressed)` at `now`.
    ///
    /// Returns `(cancel_prior_lctrl, forward_event)`:
    /// - `cancel_prior_lctrl == true` means a synthetic `ControlLeft` press was
    ///   already sent and the caller should emit a `ControlLeft` release before
    ///   forwarding `AltRight`.
    /// - `forward_event == false` means the event is the matching synthetic
    ///   `ControlLeft` release and must be dropped.
    pub(crate) fn filter(&mut self, hid_usage: u32, pressed: bool, now: Instant) -> (bool, bool) {
        if hid_usage == HID_LEFT_CTRL {
            if pressed {
                if self.suppress_lctrl_release {
                    // Auto-repeat of synthetic ControlLeft while AltGr is held.
                    return (false, false);
                }
                self.last_lctrl_press = Some(now);
                return (false, true);
            }
            self.last_lctrl_press = None;
            if self.suppress_lctrl_release {
                self.suppress_lctrl_release = false;
                return (false, false);
            }
            return (false, true);
        }
        if hid_usage == HID_RIGHT_ALT
            && pressed
            && let Some(t0) = self.last_lctrl_press.take()
            && now.saturating_duration_since(t0) <= ALTGR_SYNTHETIC_WINDOW
        {
            self.suppress_lctrl_release = true;
            return (true, true);
        }
        (false, true)
    }

    pub(crate) fn reset(&mut self) {
        self.last_lctrl_press = None;
        self.suppress_lctrl_release = false;
    }
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
    #[allow(dead_code, reason = "RAII guard keeps WH_KEYBOARD_LL installed")]
    hook: Option<KeyboardHook>,
    current: Option<LatestFrame>,
    meter: Meter,
    cursor: (f64, f64),
    pressed_buttons: u32,
    pressed_keys: std::collections::BTreeSet<u32>,
    scroll: ScrollAccumulator,
    altgr: AltGrFilter,
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
            hook: None,
            current: None,
            meter: Meter::default(),
            cursor: (0.0, 0.0),
            pressed_buttons: 0,
            pressed_keys: std::collections::BTreeSet::new(),
            scroll: ScrollAccumulator::default(),
            altgr: AltGrFilter::default(),
            error: None,
        }
    }

    pub(crate) fn into_result(self) -> anyhow::Result<()> {
        self.error.map_or(Ok(()), Err)
    }

    fn active_modifiers(&self) -> u32 {
        let mut bits = win_hook::lock_modifiers();
        if self.pressed_keys.contains(&HID_LEFT_SHIFT)
            || self.pressed_keys.contains(&HID_RIGHT_SHIFT)
        {
            bits |= modifiers::SHIFT;
        }
        if self.pressed_keys.contains(&HID_LEFT_CTRL) || self.pressed_keys.contains(&HID_RIGHT_CTRL)
        {
            bits |= modifiers::CTRL;
        }
        if self.pressed_keys.contains(&HID_LEFT_ALT) || self.pressed_keys.contains(&HID_RIGHT_ALT) {
            bits |= modifiers::ALT;
        }
        if self.pressed_keys.contains(&HID_LEFT_META) || self.pressed_keys.contains(&HID_RIGHT_META)
        {
            bits |= modifiers::META;
        }
        bits
    }

    fn release_all(&mut self) {
        self.altgr.reset();
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
        let (src_w, src_h) = self
            .current
            .as_ref()
            .map_or((size.width, size.height), |f| {
                (f.image.width, f.image.height)
            });
        let (x, y) = cursor_to_remote(
            self.cursor.0,
            self.cursor.1,
            size.width,
            size.height,
            src_w,
            src_h,
        );
        self.send(Payload::PointerEvent(PointerEvent {
            display_index: 0,
            x,
            y,
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
        scale_bilinear(&frame.image, &mut buffer, size.width, size.height);
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

/// Aspect-ratio preserving bilinear scaling of `image` into the `width`x`height`
/// window buffer, filling letterbox/pillarbox regions with black (`0x0000_0000`).
fn scale_bilinear(
    image: &omegadesk_codec::DecodedImage,
    target: &mut [u32],
    width: u32,
    height: u32,
) {
    if image.width == 0 || image.height == 0 || width == 0 || height == 0 {
        return;
    }
    let (src_w, src_h) = (image.width as usize, image.height as usize);
    let (dst_w, dst_h) = (width as usize, height as usize);
    if (src_w, src_h) == (dst_w, dst_h) {
        target[..dst_w * dst_h].copy_from_slice(&image.xrgb[..dst_w * dst_h]);
        return;
    }

    let vp = Viewport::fit(image.width, image.height, width, height);
    let (vp_x, vp_y, vp_w, vp_h) = (
        vp.x as usize,
        vp.y as usize,
        vp.width as usize,
        vp.height as usize,
    );
    if vp_w < dst_w || vp_h < dst_h {
        target[..dst_w * dst_h].fill(0);
    }
    if vp_w == 0 || vp_h == 0 {
        return;
    }
    if (vp_w, vp_h) == (src_w, src_h) {
        for row in 0..vp_h {
            let dst_row = &mut target[(vp_y + row) * dst_w + vp_x..][..vp_w];
            let src_row = &image.xrgb[row * src_w..][..src_w];
            dst_row.copy_from_slice(src_row);
        }
        return;
    }

    // Precompute horizontal 8-bit fixed-point source indices and weights.
    let max_x = src_w.saturating_sub(1);
    let max_y = src_h.saturating_sub(1);
    let x_samples: Vec<(usize, usize, u32)> = (0..vp_w)
        .map(|dx| {
            let pos = ((dx * 2 + 1) * src_w * 128) / vp_w;
            let center = pos.saturating_sub(128);
            let x0 = (center >> 8).min(max_x);
            let x1 = (x0 + 1).min(max_x);
            #[allow(clippy::cast_possible_truncation, reason = "masked to 0..=255")]
            let wx = (center & 0xFF) as u32;
            (x0, x1, wx)
        })
        .collect();

    for dy in 0..vp_h {
        let pos_y = ((dy * 2 + 1) * src_h * 128) / vp_h;
        let center_y = pos_y.saturating_sub(128);
        let y0 = (center_y >> 8).min(max_y);
        let y1 = (y0 + 1).min(max_y);
        #[allow(clippy::cast_possible_truncation, reason = "masked to 0..=255")]
        let wy = (center_y & 0xFF) as u32;
        let inv_wy = 256 - wy;

        let row0 = &image.xrgb[y0 * src_w..][..src_w];
        let row1 = &image.xrgb[y1 * src_w..][..src_w];
        let dst_row = &mut target[(vp_y + dy) * dst_w + vp_x..][..vp_w];

        for (pixel, &(x0, x1, wx)) in dst_row.iter_mut().zip(&x_samples) {
            let inv_wx = 256 - wx;
            let w00 = inv_wx * inv_wy;
            let w10 = wx * inv_wy;
            let w01 = inv_wx * wy;
            let w11 = wx * wy;
            let p00 = row0[x0];
            let p10 = row0[x1];
            let p01 = row1[x0];
            let p11 = row1[x1];
            let r = (((p00 >> 16) & 0xFF) * w00
                + ((p10 >> 16) & 0xFF) * w10
                + ((p01 >> 16) & 0xFF) * w01
                + ((p11 >> 16) & 0xFF) * w11)
                >> 16;
            let g = (((p00 >> 8) & 0xFF) * w00
                + ((p10 >> 8) & 0xFF) * w10
                + ((p01 >> 8) & 0xFF) * w01
                + ((p11 >> 8) & 0xFF) * w11)
                >> 16;
            let b =
                ((p00 & 0xFF) * w00 + (p10 & 0xFF) * w10 + (p01 & 0xFF) * w01 + (p11 & 0xFF) * w11)
                    >> 16;
            *pixel = (r << 16) | (g << 8) | b;
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
                win_hook::set_focused(true);
                self.hook = Some(KeyboardHook::install(self.input.clone(), self.view_only));
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
                let (x, y) = self.scroll.accumulate(delta);
                if x != 0 || y != 0 {
                    self.send_pointer(x, y);
                }
            }
            WindowEvent::KeyboardInput { event, .. } => {
                let PhysicalKey::Code(code) = event.physical_key else {
                    return;
                };
                let Some(hid_usage) = keycode_to_hid(code) else {
                    return;
                };
                let pressed = event.state == ElementState::Pressed;
                let (cancel_prior_lctrl, forward) =
                    self.altgr.filter(hid_usage, pressed, Instant::now());
                if cancel_prior_lctrl {
                    self.pressed_keys.remove(&HID_LEFT_CTRL);
                    self.send(Payload::KeyEvent(KeyEvent {
                        hid_usage: HID_LEFT_CTRL,
                        keysym: 0,
                        pressed: false,
                        modifiers: self.active_modifiers(),
                    }));
                }
                if !forward {
                    self.pressed_keys.remove(&hid_usage);
                    return;
                }
                if pressed {
                    self.pressed_keys.insert(hid_usage);
                } else {
                    self.pressed_keys.remove(&hid_usage);
                }
                let mut mods = self.active_modifiers();
                // Translate `Ctrl+Alt+End` (standard RDP/RustDesk shortcut) or
                // `Ctrl+Alt+Delete` into Secure Attention Sequence on the host.
                let is_ctrl_alt = (mods & (modifiers::CTRL | modifiers::ALT))
                    == (modifiers::CTRL | modifiers::ALT);
                let effective_hid = if pressed
                    && is_ctrl_alt
                    && (hid_usage == HID_END || hid_usage == HID_DELETE)
                {
                    mods |= modifiers::CTRL_ALT_DEL;
                    HID_DELETE
                } else {
                    hid_usage
                };
                let keysym = match &event.logical_key {
                    Key::Character(text) => text.chars().next().map_or(0, u32::from),
                    _ => 0,
                };
                self.send(Payload::KeyEvent(KeyEvent {
                    hid_usage: effective_hid,
                    keysym,
                    pressed,
                    modifiers: mods,
                }));
            }
            WindowEvent::Focused(true) => win_hook::set_focused(true),
            // When the window loses focus (Alt+Tab or clicking outside), release
            // every held key and button (matching Moonlight's `raiseAllKeys`) so
            // modifiers like Alt or Ctrl never get stuck on the remote machine.
            WindowEvent::Focused(false) => {
                win_hook::set_focused(false);
                self.release_all();
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use omegadesk_codec::DecodedImage;
    use omegadesk_input::WHEEL_STEP;
    use winit::dpi::PhysicalPosition;
    use winit::event::MouseScrollDelta;

    use super::{
        AltGrFilter, HID_LEFT_CTRL, HID_RIGHT_ALT, ScrollAccumulator, Viewport, cursor_to_remote,
        scale_bilinear,
    };

    #[test]
    fn horizontal_scroll_sign_is_inverted_for_win32_hwheel() {
        let mut acc = ScrollAccumulator::default();
        // winit reports -1.0 horizontal line delta when scrolling right on Windows;
        // PointerEvent/MOUSEEVENTF_HWHEEL expects +WHEEL_STEP for scrolling right.
        assert_eq!(
            acc.accumulate(MouseScrollDelta::LineDelta(-1.0, 1.0)),
            (WHEEL_STEP, WHEEL_STEP)
        );
        assert_eq!(
            acc.accumulate(MouseScrollDelta::LineDelta(1.0, -1.0)),
            (-WHEEL_STEP, -WHEEL_STEP)
        );
        assert_eq!(
            acc.accumulate(MouseScrollDelta::PixelDelta(PhysicalPosition::new(
                -45.0, 60.0
            ))),
            (45, 60)
        );
    }

    #[test]
    fn scroll_accumulator_preserves_subpixel_remainder() {
        let mut acc = ScrollAccumulator::default();
        assert_eq!(
            acc.accumulate(MouseScrollDelta::PixelDelta(PhysicalPosition::new(
                0.0, 0.4
            ))),
            (0, 0)
        );
        assert_eq!(
            acc.accumulate(MouseScrollDelta::PixelDelta(PhysicalPosition::new(
                0.0, 0.4
            ))),
            (0, 0)
        );
        assert_eq!(
            acc.accumulate(MouseScrollDelta::PixelDelta(PhysicalPosition::new(
                0.0, 0.4
            ))),
            (0, 1)
        );
    }

    #[test]
    fn viewport_preserves_aspect_ratio_and_maps_cursor() {
        // 16:9 source inside a 16:10 window -> letterboxed vertically (bars top/bottom).
        let vp = Viewport::fit(1920, 1080, 1920, 1200);
        assert_eq!(
            vp,
            Viewport {
                x: 0,
                y: 60,
                width: 1920,
                height: 1080
            }
        );
        // Cursor in top black bar clamps to y = 0; bottom bar clamps to y = 65535.
        assert_eq!(cursor_to_remote(960.0, 10.0, 1920, 1200, 1920, 1080).1, 0);
        assert_eq!(
            cursor_to_remote(960.0, 1180.0, 1920, 1200, 1920, 1080).1,
            65_535
        );
    }

    #[test]
    fn bilinear_scaler_fills_black_bars_and_interpolates() {
        let image = DecodedImage {
            width: 2,
            height: 2,
            xrgb: vec![0x00FF_0000, 0x0000_FF00, 0x0000_00FF, 0x00FF_FFFF],
        };
        // 2x2 (1:1) inside a 4x2 window -> pillarboxed at x=1..3, width=2, height=2.
        let mut target = vec![0xDEAD_BEEFu32; 8];
        scale_bilinear(&image, &mut target, 4, 2);
        assert_eq!(target[0], 0);
        assert_eq!(target[1], 0x00FF_0000);
        assert_eq!(target[2], 0x0000_FF00);
        assert_eq!(target[3], 0);
    }

    #[test]
    fn altgr_filter_cancels_synthetic_left_ctrl() {
        let mut filter = AltGrFilter::default();
        let t0 = Instant::now();
        assert_eq!(filter.filter(HID_LEFT_CTRL, true, t0), (false, true));
        assert_eq!(
            filter.filter(HID_RIGHT_ALT, true, t0 + Duration::from_millis(5)),
            (true, true)
        );
        // Synthetic ControlLeft release is suppressed.
        assert_eq!(
            filter.filter(HID_LEFT_CTRL, false, t0 + Duration::from_millis(50)),
            (false, false)
        );
        assert_eq!(
            filter.filter(HID_RIGHT_ALT, false, t0 + Duration::from_millis(60)),
            (false, true)
        );
    }
}
