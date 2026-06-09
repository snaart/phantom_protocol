#![no_main]
//! Fuzz target: `EmbeddedLeg` length-prefix framing decoder.
//!
//! Properties under test:
//!
//! 1. **No panic / no OOM on any input.** `decode_header` is called against
//!    arbitrary 4-byte slices with several representative `capacity` values;
//!    both `Ok` and `Err` are acceptable outcomes.
//!
//! 2. **Encode/decode round-trip.** If `encode_header(len, cap)` returns
//!    `Ok(header)`, then `decode_header(&header, cap)` must return `Ok(len)`.
//!    A violation here would mean the framer could produce headers that its
//!    own reader rejects — a framing-desync bug.

use libfuzzer_sys::fuzz_target;
use phantom_protocol::transport::legs::embedded::framing::{decode_header, encode_header, HEADER_LEN};

fuzz_target!(|input: &[u8]| {
    // ---- Property 1: decode_header is total on any 4-byte input ----
    if input.len() < HEADER_LEN {
        return;
    }

    let raw: &[u8; HEADER_LEN] = input[..HEADER_LEN].try_into().expect("slice is 4 bytes");

    // Exercise several capacity values spanning the full range.
    for cap in [0_usize, 16, 1024, 65536, usize::MAX] {
        // Any result is fine; what must never happen is a panic.
        let _ = decode_header(raw, cap);
    }

    // ---- Property 2: encode/decode round-trip ----
    // Derive a payload length from bytes [4..8] (or as many as we have).
    let len_bytes: [u8; 4] = {
        let mut b = [0u8; 4];
        for (i, byte) in input.iter().skip(HEADER_LEN).take(4).enumerate() {
            b[i] = *byte;
        }
        b
    };
    // Clamp to a sane range so we don't generate pathologically large sizes
    // that would always exceed the capacity and make the round-trip trivially
    // unreachable.
    let payload_len = (u32::from_le_bytes(len_bytes) as usize) % 131_073;

    for cap in [0_usize, 16, 1024, 65536, usize::MAX] {
        if let Ok(header) = encode_header(payload_len, cap) {
            // Round-trip invariant: decode must recover the same length.
            let recovered = decode_header(&header, cap)
                .expect("encode succeeded so decode with same cap must succeed");
            assert_eq!(
                recovered, payload_len,
                "round-trip failed: encode({payload_len}, {cap}) then decode gave {recovered}"
            );
        }
    }
});
