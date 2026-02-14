use openmls::prelude::*;
use thiserror::Error;

/// Universal Core Error Enum compatible with FFI exports
#[derive(Debug, Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum CoreError {
    #[error("MLS Protocol Error: {0}")]
    MlsError(String),

    #[error("Storage Provider Error: {0}")]
    StorageError(String),

    #[error("Network I/O Error: {0}")]
    NetworkError(String),

    #[error("Serialization Error: {0}")]
    SerializationError(String),

    #[error("Group with ID {0} not found")]
    GroupNotFound(String),

    #[error("System Busy")]
    Busy,

    #[error("Invalid Configuration: {0}")]
    ConfigError(String),

    #[error("Cryptography Error: {0}")]
    CryptoError(String),
}

// --- Converters for internal errors ---

impl From<openmls::error::LibraryError> for CoreError {
    fn from(e: openmls::error::LibraryError) -> Self {
        CoreError::MlsError(format!("{:?}", e))
    }
}

impl From<tls_codec::Error> for CoreError {
    fn from(e: tls_codec::Error) -> Self {
        CoreError::SerializationError(format!("TLS Codec: {:?}", e))
    }
}

// Explicit std::convert::From to avoid ambiguity
impl std::convert::From<std::io::Error> for CoreError {
    fn from(e: std::io::Error) -> Self {
        CoreError::NetworkError(e.to_string())
    }
}

// --- OpenMLS Specific Errors ---

impl<E: std::fmt::Debug> From<openmls::group::NewGroupError<E>> for CoreError {
    fn from(e: openmls::group::NewGroupError<E>) -> Self {
        CoreError::MlsError(format!("NewGroupError: {:?}", e))
    }
}

impl<E: std::fmt::Debug> From<openmls::group::ExternalCommitError<E>> for CoreError {
    fn from(e: openmls::group::ExternalCommitError<E>) -> Self {
        CoreError::MlsError(format!("ExternalCommitError: {:?}", e))
    }
}

impl<E: std::fmt::Debug> From<openmls::prelude::ExternalCommitBuilderError<E>> for CoreError {
    fn from(e: openmls::prelude::ExternalCommitBuilderError<E>) -> Self {
        CoreError::MlsError(format!("BuilderError: {:?}", e))
    }
}

impl<E: std::fmt::Debug> From<openmls::group::ExternalCommitBuilderFinalizeError<E>> for CoreError {
    fn from(e: openmls::group::ExternalCommitBuilderFinalizeError<E>) -> Self {
        CoreError::MlsError(format!("FinalizeError: {:?}", e))
    }
}

impl<E: std::fmt::Debug> From<openmls::group::ProcessMessageError<E>> for CoreError {
    fn from(e: openmls::group::ProcessMessageError<E>) -> Self {
        CoreError::MlsError(format!("ProcessMessageError: {:?}", e))
    }
}

impl<E: std::fmt::Debug> From<openmls::group::MergeCommitError<E>> for CoreError {
    fn from(e: openmls::group::MergeCommitError<E>) -> Self {
        CoreError::MlsError(format!("MergeCommitError: {:?}", e))
    }
}

impl From<openmls::group::CreateMessageError> for CoreError {
    fn from(e: openmls::group::CreateMessageError) -> Self {
        CoreError::MlsError(format!("CreateMessageError: {:?}", e))
    }
}

impl From<openmls::group::CreateCommitError> for CoreError {
    fn from(e: openmls::group::CreateCommitError) -> Self {
        CoreError::MlsError(format!("CreateCommitError: {:?}", e))
    }
}