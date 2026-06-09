#![no_main]
//! Fuzz target: PATH_VALIDATION frame parsing.
//!
//! Invariant: the multi-path receive path runs `parse_path_validation` on
//! decrypted frames whose `PATH_VALIDATION` flag is set. It must be total —
//! `Ok(None)` / `Ok(Some)` / `Err(WrongPayloadLength)`, never a panic — for any
//! flag/payload-length combination an attacker can place on the wire.

use libfuzzer_sys::fuzz_target;
use phantom_protocol::transport::path_validation_codec::parse_path_validation;
use phantom_protocol::transport::types::{PacketFlags, PacketHeader, PhantomPacket, SessionId};

fuzz_target!(|data: &[u8]| {
    // (1) Wire parser: a hostile inbound frame is decoded with `from_wire`
    // before anything else looks at it.
    let _ = PhantomPacket::from_wire(data);

    // (2) PATH_VALIDATION decoder: build the packet directly so the fuzzer
    // controls the flag bit and the payload length without first having to
    // guess a `from_wire`-valid 45-byte header. This reaches both the
    // wrong-length error arm (payload != 32) and the success arm (== 32).
    if data.len() < 2 {
        return;
    }
    let set_flag = data[0] & 1 == 1;
    let payload = data[1..].to_vec();
    let flags = if set_flag {
        PacketFlags::new(PacketFlags::PATH_VALIDATION)
    } else {
        PacketFlags::new(0)
    };
    let header = PacketHeader::new(SessionId::from_bytes([0u8; 32]), 0, 0, flags);
    let packet = PhantomPacket::new(header, payload);
    let _ = parse_path_validation(&packet);
});
