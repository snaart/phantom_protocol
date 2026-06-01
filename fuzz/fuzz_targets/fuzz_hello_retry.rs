#![no_main]
//! Fuzz target: `HelloRetryRequest` borsh deserialization.
//!
//! Invariant: the client distinguishes a `ServerHello` from a
//! `HelloRetryRequest` by deserialization (size), so the client side runs
//! `borsh::from_slice::<HelloRetryRequest>` on attacker-influenced bytes during
//! the handshake. Arbitrary input must return `Err`, never panic, never loop.

use libfuzzer_sys::fuzz_target;
use phantom_core::transport::handshake::HelloRetryRequest;

fuzz_target!(|data: &[u8]| {
    let _ = borsh::from_slice::<HelloRetryRequest>(data);
});
