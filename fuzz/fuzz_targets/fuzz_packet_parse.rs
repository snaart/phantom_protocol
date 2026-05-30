#![no_main]
//! Fuzz target: `PhantomPacket` alkahest deserialization.
//!
//! Invariant: the data-plane receive loop calls
//! `alkahest::deserialize::<PhantomPacket, PhantomPacket>(bytes)` on every
//! inbound frame. Random bytes must produce `Err`, never panic.

use libfuzzer_sys::fuzz_target;
use phantom_core::transport::types::PhantomPacket;

fuzz_target!(|data: &[u8]| {
    // Random bytes must deserialize to `Err`, never panic.
    let _ = alkahest::deserialize::<PhantomPacket, PhantomPacket>(data);
});
