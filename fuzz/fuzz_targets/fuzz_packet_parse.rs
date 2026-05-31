#![no_main]
//! Fuzz target: `PhantomPacket` wire parsing.
//!
//! Invariant: the data-plane receive loop calls `PhantomPacket::from_wire(bytes)`
//! on every inbound frame. Random bytes must produce `Err`, never panic (and no
//! out-of-bounds read from a hostile length prefix).

use libfuzzer_sys::fuzz_target;
use phantom_core::transport::types::PhantomPacket;

fuzz_target!(|data: &[u8]| {
    // Random bytes must parse to `Err`, never panic.
    let _ = PhantomPacket::from_wire(data);
});
