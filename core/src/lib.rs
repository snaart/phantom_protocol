//! # Phantom Core SDK
//!
//! Post-quantum secure L4/L6 universal transport framework.
//!
//! Provides:
//! - Hybrid key exchange (X25519 + Kyber768)
//! - Hybrid signatures (Ed25519 + Dilithium3)
//! - Multi-path transport (KCP, TCP, FakeTLS)
//! - Connection migration and fallback
//! - Stream multiplexing (reliable + unreliable)
//!
//! The core transmits only `Vec<u8>` / `Bytes`.
//! Serialization (JSON, Protobuf, etc.) is the user's responsibility.

// Security-friendly lints. Initially `warn` (not `deny`) so the codebase can
// drift toward zero panics without breaking existing call sites. A follow-up
// PR (Production Readiness, Phase 1.3) will tighten these to `deny` and audit
// the remaining sites.
//
// `clippy::indexing_slicing` is deliberately omitted at this stage — it fires
// on every constant-bounded array index and would generate too much noise.
// It is tracked as a separate phase 1.13 item (bounds-check audit).
#![warn(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::unreachable,
    clippy::todo,
    clippy::unimplemented,
    clippy::missing_safety_doc
)]
// Deny `unsafe` by default at the crate root. The two modules that genuinely
// require `unsafe` (PQC key-bytes zeroing in `crypto::keys`, libc GSO/recvmmsg
// syscalls in `transport::udp_transport`) opt back in with a module-level
// `#![allow(unsafe_code)]` and per-block `// SAFETY:` comments. Audit lens:
// any future PR touching `unsafe` outside those two modules will fail this
// lint and must justify itself explicitly.
#![deny(unsafe_code)]

pub mod config;
mod errors;
pub mod security;
pub mod validation;

// Crypto module (hybrid KEM, hybrid sign)
pub mod crypto;

// Transport module (Universal Transport Core)
pub mod transport;

// Networks module (transport trait, pipeline, engine, tls)
pub mod networks;

// Async runtime abstraction (Phase 3.1). `TokioRuntime` is the default
// implementation; the trait surface is in place for follow-up commits
// that introduce WASM / embedded backends.
pub mod runtime;

// Public API facade
pub mod api;

// Test harness for network simulation
#[cfg(test)]
pub mod test_harness;

// Public exports
pub use config::PhantomConfig;
pub use errors::CoreError;

uniffi::setup_scaffolding!();
