#![no_main]

use bytes::BytesMut;
use libfuzzer_sys::fuzz_target;
use omegadesk_protocol::{FrameDecoder, encode_frame};

fuzz_target!(|data: &[u8]| {
    let Some((&stride_byte, payload)) = data.split_first() else {
        return;
    };
    let stride = usize::from(stride_byte).max(1);

    let mut decoder = FrameDecoder::new();
    for chunk in payload.chunks(stride) {
        decoder.extend(chunk);
        loop {
            match decoder.next_frame() {
                Ok(Some(envelope)) => {
                    let mut wire = BytesMut::new();
                    if encode_frame(&envelope, &mut wire).is_ok() {
                        let mut round_trip = FrameDecoder::new();
                        round_trip.extend(&wire);
                        assert_eq!(round_trip.next_frame().ok().flatten(), Some(envelope));
                    }
                }
                Ok(None) => break,
                Err(_) => return,
            }
        }
    }
});
