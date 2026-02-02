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