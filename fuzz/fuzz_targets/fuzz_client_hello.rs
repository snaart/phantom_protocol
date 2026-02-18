#![no_main]
//! Fuzz target: `ClientHello` borsh deserialization.
//!
//! Invariant under test: feeding arbitrary bytes to `borsh::from_slice::<ClientHello>`
//! must return `Err`, never panic, never enter an infinite loop. A panic
//! source here is a direct DoS vector — the server side of the handshake
//! reads bytes from the network and runs this parser unconditionally.

use libfuzzer_sys::fuzz_target;
use phantom_core::transport::handshake::ClientHello;

fuzz_target!(|data: &[u8]| {
    let _ = borsh::from_slice::<ClientHello>(data);
});
