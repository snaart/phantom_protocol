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

// Security-friendly lints. Now `deny` (was `warn` until the codebase drove the
// remaining unannotated sites to zero). Every surviving panic-shaped call in
// production code carries an inline `// PANIC-SAFETY:` comment and a narrow
// `#[allow(clippy::unwrap_used)]` / `#[allow(clippy::expect_used)]` at the
// statement scope; the canonical inventory lives in `docs/security/panic-sites.md`.
// Tests opt in to `expect_used` for readable failure diagnostics. Phase 1.3
// (Production Readiness) — closed.
//
// `clippy::indexing_slicing` is deliberately omitted at this stage — it fires
// on every constant-bounded array index and would generate too much noise.
// It is tracked as a separate phase 1.13 item (bounds-check audit).
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::unreachable,
    clippy::todo,
    clippy::unimplemented,
    clippy::missing_safety_doc
)]
// Tests use `expect()` / `unwrap()` / `panic!()` freely so failures surface as
// readable diagnostics rather than swallowed `Result`s. The `deny` above only
// governs the production code path; this `cfg_attr(test, allow(...))` flips
// the same lints back to permissive for `cargo test` builds.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented,
        clippy::missing_safety_doc,
        // Same rationale: tests call `.unwrap()` on `Result` / `Option`
        // routinely; the disallowed-methods list in `.clippy.toml` is
        // for production code, not the test harness.
        clippy::disallowed_methods
    )
)]
// Deny `unsafe` by default at the crate root. The two modules that genuinely
// require `unsafe` (libc GSO/recvmmsg syscalls in `transport::udp_transport`,
// native-only; wasm-bindgen-generated JS-boundary glue in
// `transport::legs::websocket`, wasm32-only) opt back in with a module-level
// `#![allow(unsafe_code)]` and per-block `// SAFETY:` comments. Audit lens:
// any future PR touching `unsafe` outside those two modules will fail this
// lint and must justify itself explicitly.
#![deny(unsafe_code)]
// Phase 3.6: when neither `std` nor any std-implying feature is on, drop std
// from the crate root so a bare-metal `--no-default-features --features
// embedded,no-std` build links only `core` + `alloc`. The std build (the
// default) is unchanged.
#![cfg_attr(not(feature = "std"), no_std)]

// Phase 5.5 — `fips` feature scaffold. The flag exists in `Cargo.toml` so
// downstream tooling can pin it in advance, but the primitive-swap PR
// (X25519 → ECDH-P-256, ring → aws-lc-rs, blake3 → HKDF-SHA256, drop
// ChaCha20-Poly1305, CTR_DRBG RNG, POST hook) has not landed yet. Fail
// the build loudly if a consumer enables the feature today rather than
// silently shipping a non-FIPS binary that pretends to be FIPS.
// During the FIPS primitive-swap rollout (commits A2–A7 of the plan),
// pass `--cfg fips_rollout_in_progress` via RUSTFLAGS to bypass this
// scaffold and exercise the in-flight fips code paths. The cfg flag is
// removed alongside this scaffold in A8.
#[cfg(all(feature = "fips", not(fips_rollout_in_progress)))]
compile_error!(
    "The `fips` Cargo feature is a scaffold only — the FIPS 140-3 primitive \
     swap (ring → aws-lc-rs, X25519 → ECDH-P-256, blake3 → HKDF-SHA256, \
     drop ChaCha20-Poly1305, CTR_DRBG RNG) has not yet landed. See \
     `docs/compliance/fips-readiness.md` for current status. Build without \
     `--features fips` until the follow-up PR ships."
);

#[cfg(not(feature = "std"))]
extern crate alloc;

// `errors` and the `transport::session_transport` / `transport::legs::embedded`
// subtree are no_std-clean and compile under both feature configurations.
mod errors;

// ── std-only top-level modules ─────────────────────────────────────────
// The bare-metal subset (Phase 3.6) compiles only `errors` and the embedded
// transport subset. Everything below is gated behind `std`: it either uses
// `tokio`, `parking_lot`, `dashmap`, raw sockets, `std::time::Instant`,
// `std::sync::*`, or a std-bound dep (e.g. `ring`, `ml-kem`, `x25519-dalek`)
// that is itself only compiled when `std` is on.

#[cfg(feature = "std")]
pub mod config;
#[cfg(feature = "std")]
pub mod observability;
#[cfg(feature = "std")]
pub mod security;
#[cfg(feature = "std")]
pub mod validation;

// Crypto module (hybrid KEM, hybrid sign) — std-only: pulls `ring`,
// `x25519-dalek`, `ed25519-dalek`, `ml-kem`, `ml-dsa`, `chacha20poly1305`.
#[cfg(feature = "std")]
pub mod crypto;

// Transport module (Universal Transport Core). The module itself has a
// no_std-clean subset (`session_transport`, `legs::embedded`). The rest of the
// sub-modules opt into `std` from within `transport/mod.rs`.
pub mod transport;

// Networks module (transport trait, pipeline, engine, tls) — std-only.
#[cfg(feature = "std")]
pub mod networks;

// Async runtime abstraction (Phase 3.1). `TokioRuntime` is the default
// implementation; the trait surface is in place for follow-up commits
// that introduce WASM / embedded backends.
#[cfg(feature = "std")]
pub mod runtime;

// Public API facade — std-only: every entry point (`PhantomSession`,
// `PhantomListener`, `TcpSessionTransport`) depends on `tokio`.
#[cfg(feature = "std")]
pub mod api;

// Test harness for network simulation
#[cfg(all(test, feature = "std"))]
pub mod test_harness;

// Public exports
#[cfg(feature = "std")]
pub use config::PhantomConfig;
pub use errors::CoreError;

// UniFFI scaffolding is std-bound (the `uniffi` crate pulls `std`). Gated so
// the bare-metal build does not see it.
#[cfg(feature = "std")]
uniffi::setup_scaffolding!();
