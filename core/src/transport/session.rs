//! Phantom Transport - Session Management
//!
//! Virtual association that persists across IP changes.
//! Manages streams, encryption state, and multi-path scheduling.

use crate::transport::{
    types::{
        ControlMessage, PacketHeader, PacketHeaderV2, PhantomPacket, SchedulerMode, SessionId,
        StreamId,
    },
    stream::Stream,
    scheduler::Scheduler,
    fallback::FallbackStateMachine,
};
use crate::crypto::adaptive_crypto::{CryptoSession};
use crate::errors::CoreError;
use crate::security::ReplayWindow;

use std::collections::HashMap;
use std::sync::atomic::{AtomicU8, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Instant, Duration};
use arc_swap::ArcSwap;
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

    /// V2-path encrypt: caller supplies the 12-byte nonce explicitly. Used
    /// by `Session::encrypt_packet_v2`, which constructs the nonce from the
    /// authenticated `(epoch, stream_id, sequence)` of the V2 header — this
    /// removes the V1 dependency on an internal monotonic counter and lets
    /// the receiver survive failed decrypts without desyncing.
    pub fn encrypt_with_nonce(
        &self,
        nonce: [u8; 12],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CoreError> {
        self.session
            .encrypt_with_nonce(nonce, aad, plaintext)
            .map_err(|e| CoreError::CryptoError(e.to_string()))
    }

    /// V2-path decrypt: caller supplies the 12-byte nonce explicitly.
    pub fn decrypt_with_nonce(
        &self,
        nonce: [u8; 12],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CoreError> {
        self.session
            .decrypt_with_nonce(nonce, aad, ciphertext)
            .map_err(|e| CoreError::CryptoError(e.to_string()))
    }

    /// Borrow the 4-byte nonce prefix derived at session establishment.
    pub fn nonce_prefix(&self) -> [u8; 4] {
        self.session.nonce_prefix()
    }
}

/// Session - virtual association between two endpoints
pub struct Session {
    /// Unique session identifier (256-bit)
    id: SessionId,
    /// Current state
    state: RwLock<SessionState>,
    /// Active `CryptoState` — wrapped in `ArcSwap` so `rekey()` can swap it
    /// in lock-free (Phase 1.5 + Phase 2.7).
    ///
    /// Encrypt/decrypt callsites do `self.crypto.load()` which is an atomic
    /// pointer load + deref to the inner `CryptoState`. No lock acquisition
    /// per packet. `rekey()` is a single `store()` of a freshly-derived
    /// `Arc<CryptoState>`.
    crypto: ArcSwap<CryptoState>,
    /// Per-direction traffic secret. Initial value is the hybrid handshake's
    /// shared secret; each `rekey()` derives the next via
    /// `HKDF-Expand(current, "phantom-rekey-v1", 32)` (Phase 1.5).
    traffic_secret: RwLock<[u8; 32]>,
    /// Rekey generation counter. Starts at 0 at session establishment; each
    /// successful `rekey()` increments it. Wire-emitted in
    /// `PacketHeaderV2.epoch` so the peer can match the right key.
    epoch: AtomicU8,
    /// Which side of the handshake we are. Carried into every
    /// `CryptoState::new(...)` re-derivation so the per-direction keys are
    /// laid out the same way they were at session establishment.
    is_server: bool,
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
            crypto: ArcSwap::new(Arc::new(crypto)),
            traffic_secret: RwLock::new(*shared_secret),
            epoch: AtomicU8::new(0),
            is_server: peer_side,
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
    ///
    /// `traffic_secret` is the master from which the supplied `crypto` was
    /// derived — it seeds the [`rekey`](Self::rekey) HKDF chain. `is_server`
    /// records which side of the handshake we are; rekey re-derives keys
    /// with the same side so per-direction layout is preserved.
    pub fn from_derived(
        session_id: SessionId,
        crypto: CryptoState,
        scheduler_mode: SchedulerMode,
        traffic_secret: [u8; 32],
        is_server: bool,
    ) -> Self {
        Self {
            id: session_id,
            state: RwLock::new(SessionState::Connected),
            crypto: ArcSwap::new(Arc::new(crypto)),
            traffic_secret: RwLock::new(traffic_secret),
            epoch: AtomicU8::new(0),
            is_server,
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
            crypto: ArcSwap::new(Arc::new(crypto)),
            traffic_secret: RwLock::new(*resumption_secret),
            epoch: AtomicU8::new(0),
            is_server: peer_side,
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
        self.crypto.load().encrypt(&header_bytes, plaintext)
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
        let plaintext = self.crypto.load().decrypt(&header_bytes, ciphertext)?;

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

    /// Current rekey generation (Phase 1.5). Starts at 0; each successful
    /// [`rekey`](Self::rekey) increments by one. Carried on the wire in
    /// `PacketHeaderV2.epoch` so the peer can match the right derived key.
    pub fn current_epoch(&self) -> u8 {
        self.epoch.load(Ordering::Relaxed)
    }

    /// Whether this session is acting as the server side. Determined at
    /// construction; required for re-deriving per-direction keys on rekey.
    pub fn is_server(&self) -> bool {
        self.is_server
    }

    /// Mid-session key rotation (Phase 1.5).
    ///
    /// Derives the next traffic secret from the current one via
    /// `HKDF-Expand(current, "phantom-rekey-v1", 32)` and builds a fresh
    /// [`CryptoState`] under that secret. The new state is installed via
    /// an atomic `ArcSwap::store`, so concurrent encrypt/decrypt calls
    /// observe either the old or the new state — never a partially-written
    /// in-between. The previous traffic secret is explicitly zeroed before
    /// being overwritten.
    ///
    /// Returns the new epoch (1, 2, 3, ...). Wraps an error if the epoch
    /// counter has saturated `u8::MAX` (after 255 successful rekeys —
    /// equivalent to ~5 days at the default 30-minute cadence; long-lived
    /// sessions are expected to reconnect rather than wrap).
    ///
    /// Wire signalling: callers that want the peer to follow this rekey
    /// emit a V2 packet whose header carries the new epoch (and optionally
    /// the `PacketFlagsV2::REKEY` flag). Receivers respond by calling
    /// `rekey()` themselves once they see the bump — keeping both ends in
    /// lockstep.
    pub fn rekey(&self) -> Result<u8, CoreError> {
        let current_epoch = self.epoch.load(Ordering::Relaxed);
        if current_epoch == u8::MAX {
            return Err(CoreError::CryptoError(
                "session epoch saturated (u8::MAX); reconnect required".into(),
            ));
        }
        let mut current = self.traffic_secret.write();

        // HKDF chain step. We use `HKDF-Expand` over the current traffic
        // secret as the PRK with a distinct info string per generation —
        // any rekey-related primitive label change would be a wire-breaking
        // change tracked under the V2 KDF label inventory.
        let mut next_secret = [0u8; 32];
        let hk = hkdf::Hkdf::<sha2::Sha256>::from_prk(&*current)
            .map_err(|_| CoreError::KeyDerivationError)?;
        hk.expand(b"phantom-rekey-v1", &mut next_secret)
            .map_err(|_| CoreError::KeyDerivationError)?;

        // Build new per-direction AEAD state under the new secret.
        let new_crypto = CryptoState::new(&next_secret, self.is_server)?;
        self.crypto.store(Arc::new(new_crypto));

        // Zero the old secret before overwriting it so the previous-epoch
        // key material does not survive in memory.
        current.zeroize();
        *current = next_secret;

        let new_epoch = current_epoch + 1;
        self.epoch.store(new_epoch, Ordering::SeqCst);
        Ok(new_epoch)
    }

    /// Advance to a specific target epoch by repeatedly applying the rekey
    /// HKDF chain. Used by the receive path to "catch up" when it sees a
    /// packet from a higher epoch than the locally known one. Refuses to go
    /// backwards (a lower target than current returns Ok without changes).
    pub fn ratchet_to_epoch(&self, target: u8) -> Result<(), CoreError> {
        let mut current = self.epoch.load(Ordering::Relaxed);
        while current < target {
            self.rekey()?;
            current = self.epoch.load(Ordering::Relaxed);
        }
        Ok(())
    }

    /// Build the V2 AEAD nonce from the authenticated header fields.
    ///
    /// Layout (12 bytes total):
    /// ```text
    ///   [0..4]  : nonce_prefix (from CryptoState; identical for the lifetime
    ///             of a session, freshly derived per rekey)
    ///   [4]     : epoch
    ///   [5..7]  : stream_id (big-endian)
    ///   [7..11] : sequence  (big-endian)
    ///   [11]    : path_id
    /// ```
    ///
    /// Uniqueness argument: senders never reuse `(stream_id, sequence)`
    /// within a single epoch. The path_id distinguishes the same logical
    /// packet replayed across paths (Phase 4.2 multi-path). Together the
    /// 12-byte nonce is unique for every `seal_in_place_*` invocation
    /// under the given key.
    fn build_v2_nonce(prefix: [u8; 4], header: &PacketHeaderV2) -> [u8; 12] {
        let mut n = [0u8; 12];
        n[..4].copy_from_slice(&prefix);
        n[4] = header.epoch;
        n[5..7].copy_from_slice(&header.stream_id.to_be_bytes());
        n[7..11].copy_from_slice(&header.sequence.to_be_bytes());
        n[11] = header.path_id;
        n
    }

    /// Encrypt a V2 packet payload (wire format V2).
    ///
    /// The AEAD nonce is derived from the authenticated `(epoch, stream_id,
    /// sequence, path_id)` fields of the V2 header rather than from an
    /// internal monotonic counter — this is the key behavioural difference
    /// versus the V1 path. The AAD is the alkahest-serialised
    /// `PacketHeaderV2`, so any wire-level mutation invalidates the tag.
    ///
    /// A V1 ciphertext cannot be replayed against `decrypt_packet_v2`: the
    /// header layouts differ in serialised length and content, so the AAD
    /// bytes are distinct even for "the same" stream/sequence combination.
    pub fn encrypt_packet_v2(
        &self,
        header: &PacketHeaderV2,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CoreError> {
        let crypto = self.crypto.load();
        let nonce = Self::build_v2_nonce(crypto.nonce_prefix(), header);
        let mut header_bytes = Vec::new();
        alkahest::serialize_to_vec::<PacketHeaderV2, _>(header, &mut header_bytes);
        crypto.encrypt_with_nonce(nonce, &header_bytes, plaintext)
    }

    /// Decrypt a V2 packet payload (wire format V2). Performs AEAD verify
    /// + per-stream sliding-window replay rejection.
    ///
    /// Unlike the V1 path, a failed decrypt does NOT desync future
    /// decrypts: the AEAD nonce is derived from this packet's authenticated
    /// header fields, so the receiver state stays in lock-step with the
    /// sender regardless of intervening bad packets.
    pub fn decrypt_packet_v2(
        &self,
        header: &PacketHeaderV2,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CoreError> {
        let crypto = self.crypto.load();
        let nonce = Self::build_v2_nonce(crypto.nonce_prefix(), header);
        let mut header_bytes = Vec::new();
        alkahest::serialize_to_vec::<PacketHeaderV2, _>(header, &mut header_bytes);
        let plaintext = crypto.decrypt_with_nonce(nonce, &header_bytes, ciphertext)?;

        // Sliding-window guard. ReplayWindow keys on `(stream_id, sequence)`
        // only — the V2 `epoch` / `path_id` fields do NOT contribute to the
        // replay identity because replay is a property of "is this sequence
        // a duplicate", independent of which path it arrived over or which
        // rekey generation produced it.
        let window_entry = self
            .replay_windows
            .entry(header.stream_id)
            .or_insert_with(|| Mutex::new(ReplayWindow::new()));
        let accepted = window_entry.lock().accept(header.sequence);
        if !accepted {
            self.replay_rejected_total.fetch_add(1, Ordering::Relaxed);
            return Err(CoreError::ReplayDetected(format!(
                "stream {} sequence {} (V2) already seen or beyond window",
                header.stream_id, header.sequence
            )));
        }
        Ok(plaintext)
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
