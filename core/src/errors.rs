// Phase 3.6: `CoreError` is part of the embedded-friendly subset (the
// `SessionTransport` trait and `EmbeddedLeg` both surface it). Under a
// bare-metal `--no-default-features --features embedded,no-std` build the
// module compiles without `std`; `String` comes from `alloc`, and the std-only
// `From<std::io::Error>` / `From<anyhow::Error>` converters plus the
// `uniffi::Error` / `thiserror::Error` derives are cfg-gated off. A hand-rolled
// `Display` impl steps in for the no-std path.
#[cfg(not(feature = "std"))]
use alloc::string::String;

#[cfg(feature = "std")]
use thiserror::Error;

/// Universal Core Error Enum compatible with FFI exports
#[cfg_attr(feature = "std", derive(Error))]
#[cfg_attr(feature = "bindings", derive(uniffi::Error))]
#[derive(Debug)]
pub enum CoreError {
    #[cfg_attr(feature = "std", error("Network I/O Error: {0}"))]
    NetworkError(String),

    #[cfg_attr(feature = "std", error("Serialization Error: {0}"))]
    SerializationError(String),

    #[cfg_attr(feature = "std", error("System Busy"))]
    Busy,

    #[cfg_attr(feature = "std", error("Invalid Configuration: {0}"))]
    ConfigError(String),

    #[cfg_attr(feature = "std", error("Cryptography Error: {0}"))]
    CryptoError(String),

    #[cfg_attr(feature = "std", error("Validation Error: {0}"))]
    ValidationError(String),

    #[cfg_attr(feature = "std", error("Runtime initialization failed: {0}"))]
    RuntimeError(String),

    #[cfg_attr(feature = "std", error("Key derivation failed"))]
    KeyDerivationError,

    #[cfg_attr(feature = "std", error("Random number generation failed: {0}"))]
    RngError(String),

    #[cfg_attr(feature = "std", error("Internal concurrency error: {0}"))]
    InternalError(String),

    #[cfg_attr(feature = "std", error("Handshake failed: {0}"))]
    HandshakeError(String),

    #[cfg_attr(feature = "std", error("Stream error: {0}"))]
    StreamError(String),

    #[cfg_attr(feature = "std", error("Session not found: {0}"))]
    SessionNotFound(String),

    #[cfg_attr(feature = "std", error("Connection closed"))]
    ConnectionClosed,

    #[cfg_attr(feature = "std", error("Timeout"))]
    Timeout,

    /// Sliding-window replay protection rejected a packet. The AEAD layer
    /// already cryptographically prevents replay (strict-counter nonces), but
    /// the explicit window catches duplicates earlier and gives operators a
    /// metric signal (`replay_rejected_total`).
    #[cfg_attr(feature = "std", error("replay protection rejected packet: {0}"))]
    ReplayDetected(String),

    /// A requested cipher suite is not available in the current build.
    /// Emitted under `--features fips` when a caller asks for a
    /// non-FIPS-approved primitive (today: `ChaCha20-Poly1305`). The
    /// variant is always compiled so error matching stays stable across
    /// feature configurations.
    #[cfg_attr(feature = "std", error("cipher suite unavailable: {0}"))]
    CipherSuiteUnavailable(String),

    /// FIPS 140-3 §7.7 power-on self-test failed at process start.
    /// Surfaced by [`crate::api::PhantomListener::bind`] /
    /// [`crate::api::PhantomSession::connect_with_transport`] under
    /// `--features fips` when
    /// [`crate::crypto::self_tests::ensure_post_passed`] returns an
    /// error — refusing to stand up a session / listener over broken
    /// primitives.
    ///
    /// Gated on `fips`. The payload is a `String` (not the typed
    /// `SelfTestError`) so the variant stays UniFFI-exportable — the
    /// `Debug` rendering of `SelfTestError` is sufficient diagnostic
    /// signal for a fatal POST failure.
    #[cfg(feature = "fips")]
    #[error("FIPS POST self-test failed: {0}")]
    FipsSelfTestFailure(String),
}

// --- Converters for internal errors ---

// `std::io::Error`, `anyhow::Error`, and `getrandom::Error` are all only in
// the dep graph when the `std` feature is on; gate the converters accordingly.
#[cfg(feature = "std")]
impl core::convert::From<std::io::Error> for CoreError {
    fn from(e: std::io::Error) -> Self {
        CoreError::NetworkError(e.to_string())
    }
}

#[cfg(feature = "std")]
impl From<getrandom::Error> for CoreError {
    fn from(e: getrandom::Error) -> Self {
        CoreError::RngError(e.to_string())
    }
}

#[cfg(feature = "std")]
impl From<anyhow::Error> for CoreError {
    fn from(e: anyhow::Error) -> Self {
        CoreError::InternalError(e.to_string())
    }
}

// Hand-rolled Display impl for the no-std path — `thiserror` 1.x is std-bound
// so its derive is gated off above. The format strings mirror the
// `#[error("…")]` attributes exactly.
#[cfg(not(feature = "std"))]
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
            Self::CipherSuiteUnavailable(s) => write!(f, "cipher suite unavailable: {s}"),
        }
    }
}

// `core::error::Error` requires Rust 1.81; MSRV is 1.75. Gate the impl on the
// `error_in_core` feature being available (compile-time check via cfg of the
// rust version is not possible here, so simply omit — `Display` + `Debug` are
// sufficient for the embedded subset's error-propagation needs).
