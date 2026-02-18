#![no_main]
//! Fuzz target: AEAD decrypt with arbitrary AAD + ciphertext.
//!
//! Invariant: `Session::decrypt_packet` must never panic on arbitrary
//! input — it must return `Err` for tampered ciphertext, mismatched AAD,
//! invalid lengths, etc.
//!
//! The fuzzer derives a stable session from a fixed shared secret and feeds
//! it arbitrary `(header_bits, ciphertext_bits)` slices. We don't expect
//! decryption to succeed; we only require the function to be total.

use libfuzzer_sys::fuzz_target;
use phantom_core::transport::session::{CryptoState, Session};
use phantom_core::transport::types::{PacketFlags, PacketHeader, SchedulerMode, SessionId};

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }

    // Construct a deterministic session (in real use the secret comes from
    // the handshake — for fuzz we just need _some_ keys to drive the AEAD).
    let shared = [0x42u8; 32];
    let id = SessionId::from_bytes([0u8; 32]);
    let crypto = match CryptoState::new(&shared, true) {
        Ok(c) => c,
        Err(_) => return,
    };
    let session = Session::from_derived(id, crypto, SchedulerMode::LowLatency);

    // Synthesize a header from the first 4 bytes (stream_id) and 4 bytes of
    // sequence, with deterministic flags. The rest is treated as ciphertext.
    let stream_id = u16::from_be_bytes([data[0], data[1]]);
    let sequence = u32::from_be_bytes([
        data.get(2).copied().unwrap_or(0),
        data.get(3).copied().unwrap_or(0),
        data.get(4).copied().unwrap_or(0),
        data.get(5).copied().unwrap_or(0),
    ]);
    let header = PacketHeader::new(
        id,
        stream_id,
        sequence,
        PacketFlags::new(PacketFlags::ENCRYPTED | PacketFlags::RELIABLE),
    );

    let ct = data.get(6..).unwrap_or(&[]);
    let _ = session.decrypt_packet(&header, ct);
});
