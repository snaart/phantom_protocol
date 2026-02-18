#![no_main]
//! Fuzz target: `VersionedPacket` alkahest deserialization.
//!
//! Invariant: the data-plane receive loop calls
//! `alkahest::deserialize::<VersionedPacket, VersionedPacket>(bytes)` on every
//! inbound frame. Random bytes must produce `Err`, never panic.

use libfuzzer_sys::fuzz_target;
use phantom_core::transport::types::VersionedPacket;

fuzz_target!(|data: &[u8]| {
    if let Ok(versioned) = alkahest::deserialize::<VersionedPacket, VersionedPacket>(data) {
        // Walking into V1 should also be panic-free.
        let _ = versioned.into_v1();
    }
});
