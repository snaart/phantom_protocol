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
// `#[forbid(unsafe_code)]` would be appropriate for most modules; the few
// that require `unsafe` (crypto FFI key wrapping, libc syscalls for UDP GSO)
// opt in via module-level `#[allow]` and `// SAFETY:` comments.

mod errors;
pub mod config;
pub mod validation;
pub mod security;

// Crypto module (hybrid KEM, hybrid sign)
pub mod crypto;

// Transport module (Universal Transport Core)
pub mod transport;

// Networks module (transport trait, pipeline, engine, tls)
pub mod networks;

// Public API facade
pub mod api;

// Test harness for network simulation
#[cfg(test)]
pub mod test_harness;

// Public exports
pub use errors::CoreError;
pub use config::PhantomConfig;

uniffi::setup_scaffolding!();