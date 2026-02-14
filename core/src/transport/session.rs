//! Phantom Transport - Session Management
//!
//! Virtual association that persists across IP changes.
//! Manages streams, encryption state, and multi-path scheduling.

use crate::transport::{
    types::{SessionId, StreamId, SequenceNumber, PacketHeader, PacketFlags, PhantomPacket, ControlMessage},
    stream::Stream,
    scheduler::{Scheduler, SchedulerMode},
};

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, aead::Aead, KeyInit};

/// Session state machine
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// Initial state, handshake in progress
    Connecting,
    /// Fully established, data can flow
    Connected,
    /// Migrating to new IP address
    Migrating,
    /// Graceful shutdown in progress
    Closing,
    /// Session is closed
    Closed,
}

/// Crypto state for session encryption
pub struct CryptoState {
    /// Symmetric cipher (ChaCha20-Poly1305)
    cipher: ChaCha20Poly1305,
    /// Nonce counter for encryption
    nonce_counter: AtomicU32,
}

impl CryptoState {
    /// Create new crypto state from shared secret
    /// 
    /// The session_id is used as salt for key derivation.
    pub fn new(shared_secret: &[u8; 32], session_id: &SessionId) -> Self {
        use hkdf::Hkdf;
        use sha2::Sha256;
        
        // Derive key using HKDF with session_id as salt
        let hk = Hkdf::<Sha256>::new(Some(session_id.as_bytes()), shared_secret);
        let mut key_bytes = [0u8; 32];
        hk.expand(b"phantom-transport-key", &mut key_bytes)
            .expect("HKDF expand failed");
        
        let key = Key::from_slice(&key_bytes);
        let cipher = ChaCha20Poly1305::new(key);
        
        Self {
            cipher,
            nonce_counter: AtomicU32::new(0),
        }
    }

    /// Encrypt data with AEAD
    pub fn encrypt(&self, plaintext: &[u8], associated_data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let nonce_val = self.nonce_counter.fetch_add(1, Ordering::SeqCst);
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[..4].copy_from_slice(&nonce_val.to_le_bytes());
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        // Prepend nonce to ciphertext for transmission
        let ciphertext = self.cipher
            .encrypt(nonce, plaintext)
            .map_err(|_| CryptoError::EncryptionFailed)?;
        
        let mut result = Vec::with_capacity(12 + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    /// Decrypt data with AEAD
    pub fn decrypt(&self, ciphertext_with_nonce: &[u8], associated_data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if ciphertext_with_nonce.len() < 12 {
            return Err(CryptoError::InvalidNonce);
        }
        
        let (nonce_bytes, ciphertext) = ciphertext_with_nonce.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);
        
        self.cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| CryptoError::DecryptionFailed)
    }
}

/// Crypto errors
#[derive(Debug, Clone, Copy, thiserror::Error)]
pub enum CryptoError {
    #[error("Encryption failed")]
    EncryptionFailed,
    #[error("Decryption failed")]
    DecryptionFailed,
    #[error("Invalid nonce")]
    InvalidNonce,
}

/// Session - virtual association between two endpoints
pub struct Session {
    /// Unique session identifier (256-bit)
    id: SessionId,
    /// Current state
    state: RwLock<SessionState>,
    /// Crypto state for encryption/decryption
    crypto: Arc<CryptoState>,
    /// Active streams
    streams: RwLock<HashMap<StreamId, Arc<Stream>>>,
    /// Next stream ID counter
    next_stream_id: AtomicU32,
    /// Control sequence number
    control_sequence: AtomicU32,
    /// Multi-path scheduler
    scheduler: Arc<Scheduler>,
    /// Resumption secret for 0-RTT
    resumption_secret: Option<[u8; 32]>,
}

impl Session {
    /// Create a new session with given shared secret
    pub fn new(shared_secret: &[u8; 32]) -> Self {
        let session_id = SessionId::random();
        let crypto = Arc::new(CryptoState::new(shared_secret, &session_id));
        
        Self {
            id: session_id,
            state: RwLock::new(SessionState::Connecting),
            crypto,
            streams: RwLock::new(HashMap::new()),
            next_stream_id: AtomicU32::new(1), // 0 is reserved for control
            control_sequence: AtomicU32::new(0),
            scheduler: Arc::new(Scheduler::new(SchedulerMode::LowLatency)),
            resumption_secret: None,
        }
    }

    /// Create session from MLS-derived crypto state
    /// 
    /// Used by MlsSessionBuilder to create sessions from MLS groups.
    pub fn from_mls_derived(
        session_id: SessionId,
        crypto: Arc<CryptoState>,
        resumption_secret: Option<[u8; 32]>,
        scheduler_mode: SchedulerMode,
    ) -> Self {
        Self {
            id: session_id,
            state: RwLock::new(SessionState::Connecting),
            crypto,
            streams: RwLock::new(HashMap::new()),
            next_stream_id: AtomicU32::new(1),
            control_sequence: AtomicU32::new(0),
            scheduler: Arc::new(Scheduler::new(scheduler_mode)),
            resumption_secret,
        }
    }

    /// Resume a session using resumption secret (0-RTT)
    pub fn resume(session_id: SessionId, resumption_secret: &[u8; 32]) -> Self {
        let crypto = Arc::new(CryptoState::new(resumption_secret, &session_id));
        
        Self {
            id: session_id,
            state: RwLock::new(SessionState::Connecting),
            crypto,
            streams: RwLock::new(HashMap::new()),
            next_stream_id: AtomicU32::new(1),
            control_sequence: AtomicU32::new(0),
            scheduler: Arc::new(Scheduler::new(SchedulerMode::LowLatency)),
            resumption_secret: Some(*resumption_secret),
        }
    }

    /// Get session ID
    pub fn id(&self) -> &SessionId {
        &self.id
    }

    /// Get current state
    pub async fn state(&self) -> SessionState {
        *self.state.read().await
    }

    /// Transition to a new state
    pub async fn set_state(&self, new_state: SessionState) {
        *self.state.write().await = new_state;
    }

    /// Open a new stream
    pub async fn open_stream(&self) -> Arc<Stream> {
        let stream_id = self.next_stream_id.fetch_add(1, Ordering::SeqCst) as StreamId;
        let stream = Arc::new(Stream::new(stream_id));
        
        self.streams.write().await.insert(stream_id, stream.clone());
        stream
    }

    /// Get an existing stream
    pub async fn get_stream(&self, stream_id: StreamId) -> Option<Arc<Stream>> {
        self.streams.read().await.get(&stream_id).cloned()
    }

    /// Close a stream
    pub async fn close_stream(&self, stream_id: StreamId) -> bool {
        self.streams.write().await.remove(&stream_id).is_some()
    }

    /// Get number of active streams
    pub async fn stream_count(&self) -> usize {
        self.streams.read().await.len()
    }

    /// Encrypt a packet payload
    pub fn encrypt_packet(&self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.crypto.encrypt(plaintext, self.id.as_bytes())
    }

    /// Decrypt a packet payload
    pub fn decrypt_packet(&self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.crypto.decrypt(ciphertext, self.id.as_bytes())
    }

    /// Create a control packet
    pub fn create_control_packet(&self, message: ControlMessage, payload: Vec<u8>) -> PhantomPacket {
        let seq = self.control_sequence.fetch_add(1, Ordering::SeqCst);
        let header = PacketHeader::control(self.id, seq);
        PhantomPacket::new(header, payload)
    }

    /// Get the scheduler
    pub fn scheduler(&self) -> &Arc<Scheduler> {
        &self.scheduler
    }

    /// Check if session can be resumed (has resumption secret)
    pub fn can_resume(&self) -> bool {
        self.resumption_secret.is_some()
    }

    /// Derive resumption secret for 0-RTT
    pub fn derive_resumption_secret(&self) -> [u8; 32] {
        use hkdf::Hkdf;
        use sha2::Sha256;
        
        // Derive resumption secret from current crypto state
        let hk = Hkdf::<Sha256>::new(Some(self.id.as_bytes()), &[0u8; 32]); // TODO: use actual key
        let mut secret = [0u8; 32];
        hk.expand(b"phantom-resumption", &mut secret)
            .expect("HKDF expand failed");
        secret
    }
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("id", &self.id)
            .field("can_resume", &self.can_resume())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_session_creation() {
        let secret = [42u8; 32];
        let session = Session::new(&secret);
        
        assert_eq!(session.state().await, SessionState::Connecting);
        assert!(!session.can_resume());
    }

    #[tokio::test]
    async fn test_session_streams() {
        let secret = [42u8; 32];
        let session = Session::new(&secret);
        
        let stream1 = session.open_stream().await;
        let stream2 = session.open_stream().await;
        
        assert_ne!(stream1.id(), stream2.id());
        assert_eq!(session.stream_count().await, 2);
        
        session.close_stream(stream1.id()).await;
        assert_eq!(session.stream_count().await, 1);
    }

    #[test]
    fn test_crypto_encrypt_decrypt() {
        let secret = [42u8; 32];
        let session_id = SessionId::random();
        let crypto = CryptoState::new(&secret, &session_id);
        
        let plaintext = b"Hello, Phantom!";
        let ciphertext = crypto.encrypt(plaintext, &[]).unwrap();
        let decrypted = crypto.decrypt(&ciphertext, &[]).unwrap();
        
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }
}
