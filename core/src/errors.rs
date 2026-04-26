// Phase 3.6: `CoreError` is part of the embedded-friendly subset (the
// `SessionTransport` trait and `EmbeddedLeg` both surface it). Under the
// `no-std` audit feature the module compiles without `std`; `String` comes
// from `alloc`, and the std-only `From<std::io::Error>` / `From<anyhow::Error>`
// converters are cfg-gated off. `thiserror` 1.x stays std-bound, so its
// derive is also gated and a hand-rolled `Display` / `core::error::Error`
// impl steps in for the no-std path.
#[cfg(feature = "no-std")]
extern crate alloc;
#[cfg(feature = "no-std")]
use alloc::string::{String, ToString};

#[cfg(not(feature = "no-std"))]
use thiserror::Error;

/// Universal Core Error Enum compatible with FFI exports
#[cfg_attr(not(feature = "no-std"), derive(Error))]
#[derive(Debug, uniffi::Error)]
pub enum CoreError {
    #[cfg_attr(not(feature = "no-std"), error("Network I/O Error: {0}"))]
    NetworkError(String),

    #[cfg_attr(not(feature = "no-std"), error("Serialization Error: {0}"))]
    SerializationError(String),

    #[cfg_attr(not(feature = "no-std"), error("System Busy"))]
    Busy,

    #[cfg_attr(not(feature = "no-std"), error("Invalid Configuration: {0}"))]
    ConfigError(String),

    #[cfg_attr(not(feature = "no-std"), error("Cryptography Error: {0}"))]
    CryptoError(String),

    #[cfg_attr(not(feature = "no-std"), error("Validation Error: {0}"))]
    ValidationError(String),

    #[cfg_attr(not(feature = "no-std"), error("Runtime initialization failed: {0}"))]
    RuntimeError(String),

    #[cfg_attr(not(feature = "no-std"), error("Key derivation failed"))]
    KeyDerivationError,

    #[cfg_attr(not(feature = "no-std"), error("Random number generation failed: {0}"))]
    RngError(String),

    #[cfg_attr(not(feature = "no-std"), error("Internal concurrency error: {0}"))]
    InternalError(String),

    #[cfg_attr(not(feature = "no-std"), error("Handshake failed: {0}"))]
    HandshakeError(String),

    #[cfg_attr(not(feature = "no-std"), error("Stream error: {0}"))]
    StreamError(String),

    #[cfg_attr(not(feature = "no-std"), error("Session not found: {0}"))]
    SessionNotFound(String),

    #[cfg_attr(not(feature = "no-std"), error("Connection closed"))]
    ConnectionClosed,

    #[cfg_attr(not(feature = "no-std"), error("Timeout"))]
    Timeout,

    /// Sliding-window replay protection rejected a packet. The AEAD layer
    /// already cryptographically prevents replay (strict-counter nonces), but
    /// the explicit window catches duplicates earlier and gives operators a
    /// metric signal (`replay_rejected_total`).
    #[cfg_attr(
        not(feature = "no-std"),
        error("replay protection rejected packet: {0}")
    )]
    ReplayDetected(String),
}

// --- Converters for internal errors ---

// `std::io::Error` and `anyhow::Error` are std-only; gate them off the no-std
// audit path. `getrandom::Error` is no_std-safe.
#[cfg(not(feature = "no-std"))]
impl core::convert::From<std::io::Error> for CoreError {
    fn from(e: std::io::Error) -> Self {
        CoreError::NetworkError(e.to_string())
    }
}

impl From<getrandom::Error> for CoreError {
    fn from(e: getrandom::Error) -> Self {
        CoreError::RngError(e.to_string())
    }
}

#[cfg(not(feature = "no-std"))]
impl From<anyhow::Error> for CoreError {
    fn from(e: anyhow::Error) -> Self {
        CoreError::InternalError(e.to_string())
    }
}

// Hand-rolled Display + (core::error::Error) impls for the no-std path —
// `thiserror` 1.x is std-bound, so its derive is gated off above. The format
// strings mirror the `#[error("…")]` attributes exactly.
#[cfg(feature = "no-std")]
impl core::fmt::Display for CoreError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NetworkError(s) => write!(f, "Network I/O Error: {s}"),
            Self::SerializationError(s) => write!(f, "Serialization Error: {s}"),
            Self::Busy => write!(f, "System Busy"),
            Self::ConfigError(s) => write!(f, "Invalid Configuration: {s}"),
            Self::CryptoError(s) => write!(f, "Cryptography Error: {s}"),
            Self::ValidationError(s) => write!(f, "Validation Error: {s}"),
            Self::RuntimeError(s) => write!(f, "Runtime initialization failed: {s}"),
            Self::KeyDerivationError => write!(f, "Key derivation failed"),
            Self::RngError(s) => write!(f, "Random number generation failed: {s}"),
            Self::InternalError(s) => write!(f, "Internal concurrency error: {s}"),
            Self::HandshakeError(s) => write!(f, "Handshake failed: {s}"),
            Self::StreamError(s) => write!(f, "Stream error: {s}"),
            Self::SessionNotFound(s) => write!(f, "Session not found: {s}"),
            Self::ConnectionClosed => write!(f, "Connection closed"),
            Self::Timeout => write!(f, "Timeout"),
            Self::ReplayDetected(s) => write!(f, "replay protection rejected packet: {s}"),
        }
    }
}

// `core::error::Error` requires Rust 1.81; MSRV is 1.75. Gate the impl on the
// `error_in_core` feature being available (compile-time check via cfg of the
// rust version is not possible here, so simply omit — `Display` + `Debug` are
// sufficient for the embedded subset's error-propagation needs).
