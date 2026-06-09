//! Phantom Protocol - Public API
//!
//! Post-quantum secure transport layer with:
//! - Hybrid key exchange (X25519 + Kyber768)
//! - Hybrid signatures (Ed25519 + Dilithium3)  
//! - Multi-path transport (KCP, TCP, FakeTLS)
//! - Connection migration and fallback
//!
//! # Quick Start
//!
//! ```rust,ignore
//! use phantom_protocol::transport::api::*;
//!
//! // Server
//! let server = PhantomListener::bind("0.0.0.0:8080").await?;
//! while let Ok(session) = server.accept().await {
//!     // Session established with PQC keys
//!     session.send(b"Hello, Phantom Protocol!").await?;
//! }
//!
//! // Client
//! let session = PhantomClient::connect("server:8080").await?;
//! let data = session.recv().await?;
//! ```

// Re-export core types
pub use crate::transport::scheduler::Scheduler;
pub use crate::transport::session::{CryptoState, Session};
pub use crate::transport::stream::Stream;
pub use crate::transport::types::{LegType, PacketFlags, PacketHeader, SchedulerMode, SessionId};

// Re-export Handshake
pub use crate::transport::handshake::{
    ClientHello, HandshakeClient, HandshakeError, HandshakeServer, ServerHello,
};

// Re-export crypto primitives
pub use crate::crypto::hybrid_kem::{HybridCiphertext, HybridKeyPackage, HybridSecretKey};
pub use crate::crypto::hybrid_sign::{
    HybridSignError, HybridSignature, HybridSigningKey, HybridVerifyingKey,
};

/// Configuration for Phantom Protocol transport
#[derive(Debug, Clone)]
pub struct TransportConfig {
    /// Enable post-quantum cryptography (default: true)
    pub pqc_enabled: bool,
    /// Scheduler mode for path selection
    pub scheduler_mode: SchedulerMode,
    /// Maximum packet size (default: 1400 bytes for KCP)
    pub max_packet_size: usize,
    /// Enable stealth mode for anti-DPI (default: false)
    pub stealth_mode: bool,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            pqc_enabled: true,
            scheduler_mode: SchedulerMode::LowLatency,
            max_packet_size: 1400,
            stealth_mode: false,
        }
    }
}

impl TransportConfig {
    /// Create a config optimized for latency
    pub fn low_latency() -> Self {
        Self {
            scheduler_mode: SchedulerMode::LowLatency,
            ..Default::default()
        }
    }

    /// Create a config optimized for high throughput
    pub fn high_throughput() -> Self {
        Self {
            scheduler_mode: SchedulerMode::HighThroughput,
            ..Default::default()
        }
    }

    /// Create a config for stealth operation
    pub fn stealth() -> Self {
        Self {
            stealth_mode: true,
            scheduler_mode: SchedulerMode::Stealth,
            ..Default::default()
        }
    }
}

/// Builder for establishing Phantom Protocol connections
pub struct PhantomBuilder {
    config: TransportConfig,
    server_key: Option<HybridVerifyingKey>,
}

impl PhantomBuilder {
    /// Create a new builder with default config
    pub fn new() -> Self {
        Self {
            config: TransportConfig::default(),
            server_key: None,
        }
    }

    /// Set configuration
    pub fn config(mut self, config: TransportConfig) -> Self {
        self.config = config;
        self
    }

    /// Pin a server's public key for verification (TOFU alternative)
    pub fn pin_server_key(mut self, key: HybridVerifyingKey) -> Self {
        self.server_key = Some(key);
        self
    }

    /// Get the expected server key
    pub fn server_key(&self) -> Option<&HybridVerifyingKey> {
        self.server_key.as_ref()
    }

    /// Get the configuration
    pub fn get_config(&self) -> &TransportConfig {
        &self.config
    }

    /// Initiate a PQC handshake as client. Returns an error if the OS RNG
    /// cannot be read.
    pub fn create_client_handshake(
        &self,
    ) -> Result<HandshakeClient, crate::transport::handshake::HandshakeError> {
        HandshakeClient::new()
    }

    /// Create a server handshake handler. Returns an error if RNG / keygen
    /// fails.
    pub fn create_server_handshake(
    ) -> Result<HandshakeServer, crate::transport::handshake::HandshakeError> {
        HandshakeServer::new()
    }
}

impl Default for PhantomBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_presets() {
        let low_lat = TransportConfig::low_latency();
        assert!(matches!(low_lat.scheduler_mode, SchedulerMode::LowLatency));

        let high_throughput = TransportConfig::high_throughput();
        assert!(matches!(
            high_throughput.scheduler_mode,
            SchedulerMode::HighThroughput
        ));

        let stealth = TransportConfig::stealth();
        assert!(stealth.stealth_mode);
        assert!(matches!(stealth.scheduler_mode, SchedulerMode::Stealth));
    }

    #[test]
    fn test_builder_flow() {
        let builder = PhantomBuilder::new().config(TransportConfig::stealth());

        assert!(builder.get_config().stealth_mode);

        // Create handshake components
        let client_hs = builder
            .create_client_handshake()
            .expect("create_client_handshake");
        let _client_hello = client_hs.create_client_hello();

        let server_hs = PhantomBuilder::create_server_handshake().expect("create_server_handshake");
        let _server_pk = server_hs.verifying_key();
    }
}
