use thiserror::Error;

/// Universal Core Error Enum compatible with FFI exports
#[derive(Debug, Error, uniffi::Error)]
pub enum CoreError {
    #[error("Network I/O Error: {0}")]
    NetworkError(String),

    #[error("Serialization Error: {0}")]
    SerializationError(String),

    #[error("System Busy")]
    Busy,

    #[error("Invalid Configuration: {0}")]
    ConfigError(String),

    #[error("Cryptography Error: {0}")]
    CryptoError(String),

    #[error("Validation Error: {0}")]
    ValidationError(String),

    #[error("Runtime initialization failed: {0}")]
    RuntimeError(String),

    #[error("Key derivation failed")]
    KeyDerivationError,

    #[error("Random number generation failed: {0}")]
    RngError(String),

    #[error("Internal concurrency error: {0}")]
    InternalError(String),

    #[error("Handshake failed: {0}")]
    HandshakeError(String),

    #[error("Stream error: {0}")]
    StreamError(String),

    #[error("Session not found: {0}")]
    SessionNotFound(String),

    #[error("Connection closed")]
    ConnectionClosed,

    #[error("Timeout")]
    Timeout,

    /// Sliding-window replay protection rejected a packet. The AEAD layer
    /// already cryptographically prevents replay (strict-counter nonces), but
    /// the explicit window catches duplicates earlier and gives operators a
    /// metric signal (`replay_rejected_total`).
    #[error("replay protection rejected packet: {0}")]
    ReplayDetected(String),
}

// --- Converters for internal errors ---

impl std::convert::From<std::io::Error> for CoreError {
    fn from(e: std::io::Error) -> Self {
        CoreError::NetworkError(e.to_string())
    }
}

impl From<getrandom::Error> for CoreError {
    fn from(e: getrandom::Error) -> Self {
        CoreError::RngError(e.to_string())
    }
}

impl From<anyhow::Error> for CoreError {
    fn from(e: anyhow::Error) -> Self {
        CoreError::InternalError(e.to_string())
    }
}