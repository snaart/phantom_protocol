//! OpenMLS Integration Bridge
//!
//! Connects MLS group keys with the transport CryptoState.
//! Uses MLS exporter secret to derive encryption keys.

use crate::transport::session::{Session, CryptoState, SessionState};
use crate::transport::types::SessionId;
use crate::transport::scheduler::{Scheduler, SchedulerMode};
use crate::provider::UniversalProvider;

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::AtomicU32;
use tokio::sync::RwLock;

use openmls::prelude::*;
use openmls_traits::OpenMlsProvider;

/// Transport key derivation labels
pub mod labels {
    /// Label for deriving session encryption key
    pub const SESSION_KEY: &str = "phantom-transport-session";
    /// Label for deriving resumption secret
    pub const RESUMPTION_SECRET: &str = "phantom-transport-resumption";
    /// Label for deriving handshake key
    pub const HANDSHAKE_KEY: &str = "phantom-transport-handshake";
}

/// MLS Session Builder
/// 
/// Creates transport Sessions from MLS groups.
pub struct MlsSessionBuilder<'a> {
    /// Provider for crypto operations
    provider: &'a UniversalProvider,
    /// Scheduler mode
    scheduler_mode: SchedulerMode,
}

impl<'a> MlsSessionBuilder<'a> {
    /// Create a new builder with provider
    pub fn new(provider: &'a UniversalProvider) -> Self {
        Self {
            provider,
            scheduler_mode: SchedulerMode::LowLatency,
        }
    }

    /// Set scheduler mode
    pub fn scheduler_mode(mut self, mode: SchedulerMode) -> Self {
        self.scheduler_mode = mode;
        self
    }

    /// Build Session from MLS group
    /// 
    /// Derives transport encryption key using MLS exporter.
    pub fn build_from_group(&self, group: &MlsGroup) -> Result<Session, MlsBridgeError> {
        // Export session key from MLS group (32 bytes for ChaCha20)
        let session_key = group
            .export_secret(self.provider.crypto(), labels::SESSION_KEY, &[], 32)
            .map_err(|e| MlsBridgeError::ExportFailed(format!("{:?}", e)))?;
        
        // Export resumption secret
        let resumption_secret = group
            .export_secret(self.provider.crypto(), labels::RESUMPTION_SECRET, &[], 32)
            .map_err(|e| MlsBridgeError::ExportFailed(format!("{:?}", e)))?;
        
        // Generate session ID from group ID
        let session_id = derive_session_id_from_group(group);
        
        // Create crypto state
        let shared_secret: [u8; 32] = session_key
            .try_into()
            .map_err(|_| MlsBridgeError::InvalidKeyLength)?;
        
        let crypto = Arc::new(CryptoState::new(&shared_secret, &session_id));
        
        // Build session
        let resumption: [u8; 32] = resumption_secret
            .try_into()
            .map_err(|_| MlsBridgeError::InvalidKeyLength)?;
        
        Ok(Session::from_mls_derived(
            session_id,
            crypto,
            Some(resumption),
            self.scheduler_mode,
        ))
    }
}

/// Derive SessionId from MLS group ID
fn derive_session_id_from_group(group: &MlsGroup) -> SessionId {
    use sha2::{Sha256, Digest};
    
    let group_id = group.group_id().as_slice();
    
    // Hash group ID to 32 bytes for SessionId
    let mut hasher = Sha256::new();
    hasher.update(b"phantom-session-id");
    hasher.update(group_id);
    let hash = hasher.finalize();
    
    SessionId::from_bytes(hash.into())
}

/// Errors from MLS bridge operations
#[derive(Debug, Clone, thiserror::Error)]
pub enum MlsBridgeError {
    #[error("Failed to export MLS secret: {0}")]
    ExportFailed(String),
    
    #[error("Invalid key length")]
    InvalidKeyLength,
    
    #[error("Group not ready")]
    GroupNotReady,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_labels() {
        assert!(!labels::SESSION_KEY.is_empty());
        assert!(!labels::RESUMPTION_SECRET.is_empty());
    }
}
