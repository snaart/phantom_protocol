//! Phantom Transport - Session Management
//!
//! Virtual association that persists across IP changes.
//! Manages streams, encryption state, and multi-path scheduling.

use crate::transport::{
    types::{SessionId, StreamId, PacketHeader, PhantomPacket, ControlMessage, SchedulerMode},
    stream::Stream,
    scheduler::Scheduler,
    fallback::FallbackStateMachine,
};
use crate::crypto::adaptive_crypto::{CryptoSession};
use crate::errors::CoreError;
use crate::security::ReplayWindow;

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Instant, Duration};
use dashmap::DashMap;
use parking_lot::{Mutex, RwLock};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Session state machine
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// Initial state, handshake in progress
    Handshaking,
    /// Fully established, data can flow
    Connected,
    /// Migrating to new IP address
    Migrating,
    /// Graceful shutdown in progress
    Closing,
    /// Session is closed
    Closed,
}

/// Crypto state for session encryption.
///
/// On drop, `session_key` is zeroed. The wrapped [`CryptoSession`] holds AEAD
/// keys in ring's opaque `LessSafeKey` (which cannot be zeroed directly — we
/// rely on the OS reclaiming memory and on the `Arc<CryptoSessionInner>` going
/// out of scope alongside this struct).
#[derive(ZeroizeOnDrop)]
pub struct CryptoState {
    /// Bidirectional crypto session
    #[zeroize(skip)]
    pub session: CryptoSession,
    /// Shared session key (for additional derivations)
    pub session_key: [u8; 32],
}

impl CryptoState {
    /// Create new crypto state from shared secret
    pub fn new(shared_secret: &[u8; 32], peer_side: bool) -> Result<Self, CoreError> {
        let session = if peer_side {
            CryptoSession::from_shared_secret_peer(shared_secret)?
        } else {
            CryptoSession::from_shared_secret(shared_secret)?
        };

        // Derive additional session keys using HKDF
        let hk = hkdf::Hkdf::<sha2::Sha256>::from_prk(shared_secret)
            .map_err(|_| CoreError::CryptoError("HKDF PRK failed".into()))?;
        
        let mut key_bytes = [0u8; 32];
        hk.expand(b"phantom-transport-key", &mut key_bytes)
            .map_err(|_| CoreError::KeyDerivationError)?;

        Ok(Self {
            session,
            session_key: key_bytes,
        })
    }

    /// Encrypt data
    pub fn encrypt(&self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CoreError> {
        self.session.encrypt(aad, plaintext)
            .map_err(|e| CoreError::CryptoError(e.to_string()))
    }

    /// Decrypt data
    pub fn decrypt(&self, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CoreError> {
        self.session.decrypt(aad, ciphertext)
            .map_err(|e| CoreError::CryptoError(e.to_string()))
    }
}

/// Session - virtual association between two endpoints
pub struct Session {
    /// Unique session identifier (256-bit)
    id: SessionId,
    /// Current state
    state: RwLock<SessionState>,
    /// Crypto state for encryption/decryption
    crypto: RwLock<CryptoState>,
    /// Active streams
    streams: RwLock<HashMap<StreamId, Arc<Stream>>>,
    /// Next stream ID counter
    next_stream_id: AtomicU32,
    /// Control sequence number
    control_sequence: AtomicU32,
    /// Multi-path scheduler
    scheduler: Arc<Scheduler>,
    /// Resumption secret for 0-RTT
    resumption_secret: RwLock<Option<[u8; 32]>>,
    /// Last activity timestamp
    last_activity: RwLock<Instant>,
    /// Fallback state machine
    #[allow(dead_code)]
    fallback: Arc<FallbackStateMachine>,
    /// Per-stream sliding-window replay protection. Lazily populated as
    /// streams appear on the wire. Sits alongside (not in place of) the AEAD
    /// strict-counter replay protection — see `decrypt_packet`.
    replay_windows: DashMap<StreamId, Mutex<ReplayWindow>>,
    /// Cumulative count of replay rejections (across all streams) — exposed
    /// for metrics/telemetry.
    replay_rejected_total: AtomicU64,
}

impl Session {
    /// Create a new session with given shared secret
    pub fn new(session_id: SessionId, shared_secret: &[u8; 32], peer_side: bool) -> Result<Self, CoreError> {
        let crypto = CryptoState::new(shared_secret, peer_side)?;

        Ok(Self {
            id: session_id,
            state: RwLock::new(SessionState::Handshaking),
            crypto: RwLock::new(crypto),
            streams: RwLock::new(HashMap::new()),
            next_stream_id: AtomicU32::new(1),
            control_sequence: AtomicU32::new(0),
            scheduler: Arc::new(Scheduler::new(SchedulerMode::LowLatency)),
            resumption_secret: RwLock::new(None),
            last_activity: RwLock::new(Instant::now()),
            fallback: Arc::new(FallbackStateMachine::with_defaults()),
            replay_windows: DashMap::new(),
            replay_rejected_total: AtomicU64::new(0),
        })
    }

    /// Create session from a pre-derived crypto state (e.g., after handshake).
    pub fn from_derived(
        session_id: SessionId,
        crypto: CryptoState,
        scheduler_mode: SchedulerMode,
    ) -> Self {
        Self {
            id: session_id,
            state: RwLock::new(SessionState::Connected),
            crypto: RwLock::new(crypto),
            streams: RwLock::new(HashMap::new()),
            next_stream_id: AtomicU32::new(1),
            control_sequence: AtomicU32::new(0),
            scheduler: Arc::new(Scheduler::new(scheduler_mode)),
            resumption_secret: RwLock::new(None),
            last_activity: RwLock::new(Instant::now()),
            fallback: Arc::new(FallbackStateMachine::with_defaults()),
            replay_windows: DashMap::new(),
            replay_rejected_total: AtomicU64::new(0),
        }
    }

    /// Resume a session using resumption secret (0-RTT)
    pub fn resume(session_id: SessionId, resumption_secret: &[u8; 32], peer_side: bool) -> Result<Self, CoreError> {
        let crypto = CryptoState::new(resumption_secret, peer_side)?;

        Ok(Self {
            id: session_id,
            state: RwLock::new(SessionState::Connected),
            crypto: RwLock::new(crypto),
            streams: RwLock::new(HashMap::new()),
            next_stream_id: AtomicU32::new(1),
            control_sequence: AtomicU32::new(0),
            scheduler: Arc::new(Scheduler::new(SchedulerMode::LowLatency)),
            resumption_secret: RwLock::new(Some(*resumption_secret)),
            last_activity: RwLock::new(Instant::now()),
            fallback: Arc::new(FallbackStateMachine::with_defaults()),
            replay_windows: DashMap::new(),
            replay_rejected_total: AtomicU64::new(0),
        })
    }

    /// Get session ID
    pub fn id(&self) -> &SessionId {
        &self.id
    }

    /// Get current state
    pub fn state(&self) -> SessionState {
        *self.state.read()
    }

    /// Transition to a new state
    pub fn set_state(&self, new_state: SessionState) {
        *self.state.write() = new_state;
    }

    /// Open a new stream
    pub fn open_stream(&self) -> Arc<Stream> {
        let stream_id = self.next_stream_id.fetch_add(1, Ordering::SeqCst) as StreamId;
        let stream = Arc::new(Stream::new(stream_id));
        
        self.streams.write().insert(stream_id, stream.clone());
        stream
    }

    /// Get an existing stream
    pub fn get_stream(&self, stream_id: StreamId) -> Option<Arc<Stream>> {
        self.streams.read().get(&stream_id).cloned()
    }

    /// Close a stream
    pub fn close_stream(&self, stream_id: StreamId) -> bool {
        self.streams.write().remove(&stream_id).is_some()
    }

    /// Get number of active streams
    pub fn stream_count(&self) -> u32 {
        self.streams.read().len() as u32
    }

    /// Encrypt a packet payload
    pub fn encrypt_packet(&self, header: &PacketHeader, plaintext: &[u8]) -> Result<Vec<u8>, CoreError> {
        let mut header_bytes = Vec::new();
        alkahest::serialize_to_vec::<PacketHeader, _>(header, &mut header_bytes);
        self.crypto.read().encrypt(&header_bytes, plaintext)
    }

    /// Decrypt a packet payload.
    ///
    /// **Replay protection (defense in depth).** The AEAD layer already
    /// cryptographically prevents replay: each `decrypt` call advances the
    /// per-direction `recv_counter`, and a replayed ciphertext was sealed
    /// against an earlier counter — the derived nonce no longer matches,
    /// AEAD authentication fails. On top of that, this function consults
    /// a per-stream sliding-window replay table keyed on `header.sequence`
    /// (which is authenticated by the AEAD AAD), giving operators an
    /// observable `ReplayDetected` error and a `replay_rejected_total`
    /// counter for telemetry.
    ///
    /// The window check runs **after** successful AEAD verification so we
    /// never key off un-authenticated sequence numbers.
    pub fn decrypt_packet(&self, header: &PacketHeader, ciphertext: &[u8]) -> Result<Vec<u8>, CoreError> {
        let mut header_bytes = Vec::new();
        alkahest::serialize_to_vec::<PacketHeader, _>(header, &mut header_bytes);
        let plaintext = self.crypto.read().decrypt(&header_bytes, ciphertext)?;

        // Sliding-window replay check. Lazily create the per-stream window.
        let window_entry = self
            .replay_windows
            .entry(header.stream_id)
            .or_insert_with(|| Mutex::new(ReplayWindow::new()));
        let accepted = window_entry.lock().accept(header.sequence);
        if !accepted {
            self.replay_rejected_total.fetch_add(1, Ordering::Relaxed);
            return Err(CoreError::ReplayDetected(format!(
                "stream {} sequence {} already seen (within window) or beyond window",
                header.stream_id, header.sequence
            )));
        }
        Ok(plaintext)
    }

    /// Total number of replayed packets rejected by the sliding-window check
    /// across all streams in this session. Intended for the
    /// `replay_rejected_total` metric.
    pub fn replay_rejected_total(&self) -> u64 {
        self.replay_rejected_total.load(Ordering::Relaxed)
    }

    /// Create a control packet
    pub fn create_control_packet(&self, _message: ControlMessage, payload: Vec<u8>) -> PhantomPacket {
        let seq = self.control_sequence.fetch_add(1, Ordering::SeqCst);
        let header = PacketHeader::control(self.id, seq);
        // Note: Real implementation would also encrypt control packet
        PhantomPacket::new(header, payload)
    }

    /// Get the scheduler
    pub fn scheduler(&self) -> &Arc<Scheduler> {
        &self.scheduler
    }

    /// Set resumption secret for 0-RTT.
    ///
    /// If a secret was already set, the previous bytes are explicitly zeroed
    /// before being replaced — defense in depth in case `set_resumption_secret`
    /// is called multiple times within a session.
    pub fn set_resumption_secret(&self, secret: [u8; 32]) {
        let mut guard = self.resumption_secret.write();
        if let Some(mut old) = guard.take() {
            old.zeroize();
        }
        *guard = Some(secret);
    }

    /// Check if session can be resumed (has resumption secret)
    pub fn can_resume(&self) -> bool {
        self.resumption_secret.read().is_some()
    }

    /// Update last activity timestamp
    pub fn update_activity(&self) {
        *self.last_activity.write() = Instant::now();
    }

    /// Check if session is expired
    pub fn is_expired(&self, timeout: Duration) -> bool {
        self.last_activity.read().elapsed() > timeout
    }
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("id", &self.id)
            .finish()
    }
}

impl Drop for Session {
    /// On session drop, explicitly zero the resumption secret. The
    /// `CryptoState` inside `crypto` is itself `ZeroizeOnDrop`, so its
    /// `session_key` is handled there.
    fn drop(&mut self) {
        if let Some(mut secret) = self.resumption_secret.write().take() {
            secret.zeroize();
        }
    }
}
