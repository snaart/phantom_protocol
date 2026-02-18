#![no_main]
//! Fuzz target: `ServerHello` borsh deserialization.
//!
//! Invariant: client side must not panic on arbitrary `ServerHello` input.

use libfuzzer_sys::fuzz_target;
use phantom_core::transport::handshake::ServerHello;

fuzz_target!(|data: &[u8]| {
    let _ = borsh::from_slice::<ServerHello>(data);
});
