//! Measures color conversion and 1080p frame encoding latency.
//!
//! `cargo run --release -p omegadesk-codec --example bench`

use std::time::Instant;

use omegadesk_codec::{EncoderSettings, OpenH264Encoder, RawFrame, VideoEncoder, bgra_to_i420};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (width, height) = (1920_u32, 1080_u32);
    let mut bgra = vec![0u8; (width * height * 4) as usize];
    for (i, byte) in bgra.iter_mut().enumerate() {
        *byte = u8::try_from((i * 7 + i / 7919) % 251).unwrap_or(0);
    }

    let start = Instant::now();
    for _ in 0..10 {
        std::hint::black_box(bgra_to_i420(
            &bgra,
            width as usize,
            width as usize,
            height as usize,
        ));
    }
    tracing_line("BGRA->I420 conversion", start.elapsed() / 10);

    let mut encoder = OpenH264Encoder::new(EncoderSettings::default())?;
    for round in 0..5 {
        bgra[round * 4096] ^= 0xFF;
        let start = Instant::now();
        let frame = encoder.encode(RawFrame {
            width,
            height,
            bgra: &bgra,
        })?;
        tracing_line(
            &format!(
                "software encode #{round} ({} bytes)",
                frame.iter().map(|f| f.data.len()).sum::<usize>()
            ),
            start.elapsed(),
        );
    }
    #[cfg(windows)]
    {
        let mut hardware = omegadesk_codec::MediaFoundationEncoder::new(
            width,
            height,
            EncoderSettings::default(),
        )?;
        tracing_line(
            &format!("hardware: {}", hardware.name()),
            std::time::Duration::ZERO,
        );
        for round in 0..10 {
            bgra[round * 4096] ^= 0xFF;
            let start = Instant::now();
            let frames = hardware.encode(RawFrame {
                width,
                height,
                bgra: &bgra,
            })?;
            tracing_line(
                &format!(
                    "hardware #{round} ({} frames, {} bytes)",
                    frames.len(),
                    frames.iter().map(|f| f.data.len()).sum::<usize>()
                ),
                start.elapsed(),
            );
        }
    }
    Ok(())
}

#[allow(clippy::print_stderr)]
fn tracing_line(label: &str, elapsed: std::time::Duration) {
    eprintln!("{label}: {:.1} ms", elapsed.as_secs_f64() * 1000.0);
}
