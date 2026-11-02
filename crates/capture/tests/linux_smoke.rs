//! Linux capture smoke test: open the X11 backend and grab one frame.
//!
//! Runs on Linux CI under `xvfb-run`, which provides a virtual X server on `$DISPLAY`.
//! Without `$DISPLAY` the test skips; with a display configured, connection and capture
//! failures are real test failures rather than silent skips.

#![cfg(target_os = "linux")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stderr,
    reason = "integration test: prints a skip reason when no display is available"
)]

use std::time::Duration;

use omegadesk_capture::Capturer;
use omegadesk_capture::linux::{BackendChoice, open_display_with, x11::X11Capturer};

#[test]
fn x11_backend_grabs_a_frame_under_xvfb() {
    if std::env::var_os("DISPLAY").is_none() {
        eprintln!("skipping: no $DISPLAY (run under xvfb-run)");
        return;
    }
    let mut capturer = X11Capturer::open(0).expect("X11 capture opens with $DISPLAY");
    let (width, height) = capturer.size();
    assert!(
        width > 0 && height > 0,
        "non-empty desktop: {width}x{height}"
    );

    // The first poll always returns the current screen (the dedup baseline is empty).
    let frame = capturer
        .next_frame(Duration::from_secs(2))
        .expect("capture succeeds")
        .expect("first frame is delivered");
    assert_eq!(frame.width, width);
    assert_eq!(frame.height, height);
    assert_eq!(
        frame.bgra.len(),
        width as usize * height as usize * 4,
        "tightly packed BGRA"
    );
    // Opaque alpha on every pixel, whatever the server's visual was.
    assert!(frame.bgra.as_chunks::<4>().0.iter().all(|px| px[3] == 0xFF));
}

#[test]
fn open_display_auto_falls_back_to_x11_without_a_portal() {
    if std::env::var_os("DISPLAY").is_none() {
        eprintln!("skipping: no $DISPLAY (run under xvfb-run)");
        return;
    }
    // Under Xvfb there is no xdg-desktop-portal, so Auto must fall through to X11.
    let capturer = open_display_with(0, BackendChoice::Auto)
        .expect("automatic capture falls back to X11 with $DISPLAY");
    let (width, height) = capturer.size();
    assert!(width > 0 && height > 0);
}
