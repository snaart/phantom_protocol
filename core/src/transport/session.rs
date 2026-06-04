//! Phantom Transport - Session Management
//!
//! Virtual association that persists across IP changes.
//! Manages streams, encryption state, and multi-path scheduling.

use crate::crypto::adaptive_crypto::{CryptoSession, AEAD_MAX_INVOCATIONS};
use crate::errors::CoreError;
use crate::security::ReplayWindow;
use crate::transport::{
    bandwidth_estimator::{BandwidthEstimator, DeliverySample},
    fallback::FallbackStateMachine,
    pacer::Pacer,
    path::{PathRegistry, PathStateKind, PATH_CHALLENGE_LEN},
    scheduler::Scheduler,
    stream::Stream,
    types::{
        ControlMessage, PacketFlags, PacketHeader, PhantomPacket, SchedulerMode, SessionId,
        StreamId,
    },
};

use arc_swap::ArcSwap;
use dashmap::DashMap;
use parking_lot::{Mutex, RwLock};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
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

/// Soft high-watermark for automatic mid-session rekey (C1). Once a direction's
/// AEAD invocation count crosses this, the data pump rotates to a fresh key
/// *before* the hard [`AEAD_MAX_INVOCATIONS`] ceiling (Invariant 8) so a
/// long-lived session ratchets keys instead of failing with `NonceExhausted`.
///
/// Default is half the ceiling — `2^47` invocations — which leaves a `2^47`
/// headroom for in-flight packets from the old epoch. It is far larger than any
/// realistic session lifetime, so production sessions essentially never hit it;
/// it is a correctness backstop. Tests lower it via
/// [`Session::set_rekey_threshold`] to exercise the path.
pub const REKEY_SOFT_LIMIT: u64 = AEAD_MAX_INVOCATIONS / 2;

/// How many epochs the receive path will catch up in one packet when accepting
/// an authenticated forward rekey (C1). A small bound caps the HKDF work an
/// attacker can force per spoofed packet (each step is a trial that commits
/// nothing unless AEAD verifies) while comfortably absorbing the small epoch
/// divergence that arises when both directions rekey at slightly different
/// cadences. A gap larger than this is rejected; over a reliable transport the
/// sender retransmits at the then-current epoch, so no data is lost. In
/// practice (production `REKEY_SOFT_LIMIT` of `2^47`) the gap is essentially
/// always 0 or 1.
pub const MAX_REKEY_CATCHUP: u8 = 16;

/// Per-stream sequence-space high-watermark that forces a mid-session rekey
/// (C1). The AEAD nonce is `(epoch, stream_id, sequence, path_id)`; `sequence`
/// is a per-stream `u32` that wraps at `2^32`. A single hot stream would wrap —
/// reusing a nonce under a fixed key (the Forbidden Attack on AES-GCM) — long
/// before the *direction-wide* [`REKEY_SOFT_LIMIT`] (`2^47`) could fire. So once
/// *any* stream's sequence advances this far within the current epoch, the send
/// path forces a rekey: the epoch bump gives every subsequent packet a fresh
/// nonce prefix, and no stream can traverse the full `2^32` sequence space
/// within a single epoch. `2^31` leaves a full `2^31` of headroom below the wrap
/// to absorb reordered / in-flight packets from the old epoch. Tests lower it
/// via [`Session::set_seq_rekey_watermark`].
pub const SEQ_REKEY_WATERMARK: u32 = 1 << 31;

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

    /// Encrypt with a caller-supplied 12-byte nonce. Used by
    /// `Session::encrypt_packet`, which constructs the nonce from the
    /// authenticated `(epoch, stream_id, sequence, path_id)` of the packet
    /// header — so the receiver survives failed decrypts without desyncing.
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

    /// Per-direction send-side AEAD invocation count for this epoch. Resets to
    /// 0 on rekey (a fresh `CryptoState` is installed). Drives the C1
    /// automatic-rekey trigger.
    pub fn send_invocations(&self) -> u64 {
        self.session.send_invocations()
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
    /// `PacketHeader.epoch` so the peer can match the right key.
    epoch: AtomicU8,
    /// Send-side AEAD-invocation high-watermark that triggers an automatic
    /// mid-session rekey (C1). Defaults to [`REKEY_SOFT_LIMIT`]; tests/embedders
    /// lower it via [`set_rekey_threshold`](Self::set_rekey_threshold).
    rekey_after: AtomicU64,
    /// Per-stream sequence high-watermark that forces a rekey for AEAD nonce
    /// uniqueness (C1). Defaults to [`SEQ_REKEY_WATERMARK`] (`2^31`); tests lower
    /// it via [`set_seq_rekey_watermark`](Self::set_seq_rekey_watermark).
    seq_rekey_watermark: AtomicU32,
    /// Per-stream `(epoch, base_sequence)` checkpoint bounding how far a stream's
    /// sequence may advance within one epoch (C1). `base_sequence` is the stream's
    /// sequence when it entered the current epoch; the send path forces a rekey
    /// once `sequence - base_sequence` crosses
    /// [`seq_rekey_watermark`](Self::seq_rekey_watermark). Rebased lazily, per
    /// stream, on the first send after an epoch change.
    seq_epoch_base: DashMap<StreamId, (u8, u32)>,
    /// Serialises every epoch transition (C1). The data pump runs the send loop
    /// and the receive task concurrently over one `Arc<Session>`, so a send-side
    /// `rekey()` can race a receive-side ratchet. Both hold this mutex across
    /// their derive→install→epoch-bump so the installed key depth and the epoch
    /// counter never diverge (the bug would otherwise wedge the session).
    rekey_lock: Mutex<()>,
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
    /// Per-path validation state (Phase 4.2). Each `path_id` referenced in a
    /// `PacketHeader.path_id` must transit through `Unvalidated →
    /// Validating → Validated` (via a challenge-response round trip)
    /// before the data pump treats it as authoritative. Defaults to a
    /// pre-populated entry for `path_id = 0` (the implicit single-path)
    /// in the `Validated` state so legacy single-leg sessions keep
    /// working without any explicit setup.
    path_registry: Arc<PathRegistry>,
    /// Outbound rate-limiter (Phase 2.6). Defaults to
    /// [`Pacer::unlimited`] so the historical no-pacing behavior is
    /// unchanged unless the caller explicitly sets a rate via
    /// [`Session::pacer`]. The data pump consults this before every
    /// outbound packet — the existing implementation just calls
    /// `try_consume` and falls through if the pacer is disabled, so the
    /// integration is zero-overhead in the default configuration.
    pacer: Arc<Pacer>,
    /// BBR-style bandwidth + RTT estimator (Phase 2.6 / Phase 4.4
    /// foundation). The data pump feeds it via [`Session::on_packet_sent`]
    /// and [`Session::on_packet_acked`]; the resulting `pacing_rate()`
    /// feeds back into the `pacer` to close the loop.
    bandwidth_estimator: parking_lot::Mutex<BandwidthEstimator>,
    /// Outbound-ready signal (Phase 2.4). Streams or the application
    /// can `notify_one()` this to wake the data pump immediately
    /// instead of waiting for the next 10 ms `poll_interval` tick.
    /// The pump keeps the tick as a retransmit-timer fallback.
    send_notify: Arc<tokio::sync::Notify>,
}

impl Session {
    /// Create a new session with given shared secret
    pub fn new(
        session_id: SessionId,
        shared_secret: &[u8; 32],
        peer_side: bool,
    ) -> Result<Self, CoreError> {
        let crypto = CryptoState::new(shared_secret, peer_side)?;
        let path_registry = Arc::new(PathRegistry::new());
        // Pre-register `path_id = 0` as the implicit default path — the
        // handshake itself proved reachability over this path, so no
        // additional PATH_CHALLENGE is needed (Phase 4.2).
        path_registry.register_validated(0);

        Ok(Self {
            id: session_id,
            state: RwLock::new(SessionState::Handshaking),
            crypto: ArcSwap::new(Arc::new(crypto)),
            traffic_secret: RwLock::new(*shared_secret),
            epoch: AtomicU8::new(0),
            rekey_after: AtomicU64::new(REKEY_SOFT_LIMIT),
            seq_rekey_watermark: AtomicU32::new(SEQ_REKEY_WATERMARK),
            seq_epoch_base: DashMap::new(),
            rekey_lock: Mutex::new(()),
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
            path_registry,
            pacer: Arc::new(Pacer::unlimited()),
            bandwidth_estimator: parking_lot::Mutex::new(BandwidthEstimator::new()),
            send_notify: Arc::new(tokio::sync::Notify::new()),
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
        let path_registry = Arc::new(PathRegistry::new());
        path_registry.register_validated(0);
        Self {
            id: session_id,
            state: RwLock::new(SessionState::Connected),
            crypto: ArcSwap::new(Arc::new(crypto)),
            traffic_secret: RwLock::new(traffic_secret),
            epoch: AtomicU8::new(0),
            rekey_after: AtomicU64::new(REKEY_SOFT_LIMIT),
            seq_rekey_watermark: AtomicU32::new(SEQ_REKEY_WATERMARK),
            seq_epoch_base: DashMap::new(),
            rekey_lock: Mutex::new(()),
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
            path_registry,
            pacer: Arc::new(Pacer::unlimited()),
            bandwidth_estimator: parking_lot::Mutex::new(BandwidthEstimator::new()),
            send_notify: Arc::new(tokio::sync::Notify::new()),
        }
    }

    /// Resume a session using resumption secret (0-RTT)
    pub fn resume(
        session_id: SessionId,
        resumption_secret: &[u8; 32],
        peer_side: bool,
    ) -> Result<Self, CoreError> {
        let crypto = CryptoState::new(resumption_secret, peer_side)?;
        let path_registry = Arc::new(PathRegistry::new());
        path_registry.register_validated(0);

        Ok(Self {
            id: session_id,
            state: RwLock::new(SessionState::Connected),
            crypto: ArcSwap::new(Arc::new(crypto)),
            traffic_secret: RwLock::new(*resumption_secret),
            epoch: AtomicU8::new(0),
            rekey_after: AtomicU64::new(REKEY_SOFT_LIMIT),
            seq_rekey_watermark: AtomicU32::new(SEQ_REKEY_WATERMARK),
            seq_epoch_base: DashMap::new(),
            rekey_lock: Mutex::new(()),
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
            path_registry,
            pacer: Arc::new(Pacer::unlimited()),
            bandwidth_estimator: parking_lot::Mutex::new(BandwidthEstimator::new()),
            send_notify: Arc::new(tokio::sync::Notify::new()),
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

    /// Total number of replayed packets rejected by the sliding-window check
    /// across all streams in this session. Intended for the
    /// `replay_rejected_total` metric.
    pub fn replay_rejected_total(&self) -> u64 {
        self.replay_rejected_total.load(Ordering::Relaxed)
    }

    /// Current rekey generation (Phase 1.5). Starts at 0; each successful
    /// [`rekey`](Self::rekey) increments by one. Carried on the wire in
    /// `PacketHeader.epoch` so the peer can match the right derived key.
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
    /// the `PacketFlags::REKEY` flag). Receivers respond by calling
    /// `rekey()` themselves once they see the bump — keeping both ends in
    /// lockstep.
    #[tracing::instrument(name = "phantom.session.rekey", skip_all)]
    pub fn rekey(&self) -> Result<u8, CoreError> {
        // Serialise the whole transition (C1): the send loop and the receive
        // task share this `Session`, so derive+install+epoch-bump must be atomic
        // w.r.t. a concurrent receive-side ratchet, or the installed key depth
        // and the epoch counter diverge and wedge the session.
        let _rekey = self.rekey_lock.lock();
        let current_epoch = self.epoch.load(Ordering::Relaxed);
        if current_epoch == u8::MAX {
            return Err(CoreError::CryptoError(
                "session epoch saturated (u8::MAX); reconnect required".into(),
            ));
        }
        let (next_secret, new_crypto) = self.derive_forward_crypto(1)?;
        self.commit_forward_crypto(1, next_secret, new_crypto);
        Ok(current_epoch + 1)
    }

    /// Derive the next epoch's traffic secret + [`CryptoState`] from the current
    /// secret WITHOUT installing them. The HKDF chain step is
    /// `HKDF-Expand(current, "phantom-rekey-v1", 32)` (Invariant 5 — the label is
    /// load-bearing; it must match the committing path in `rekey`). Returns the
    /// derived secret and a fresh per-direction AEAD state under it.
    ///
    /// This is the non-committing half used by the receive path to verify a
    /// claimed-next-epoch packet (trial decrypt) before trusting the epoch bump,
    /// so a forged, unauthenticated `header.epoch` cannot desync the session.
    ///
    /// `steps` ≥ 1 applies the chain that many times (the receive path may need
    /// to catch up several epochs when both directions rekey at slightly
    /// different cadences). Intermediate secrets are zeroed as the walk
    /// proceeds; only the final-epoch secret is returned for the caller to
    /// commit.
    fn derive_forward_crypto(&self, steps: u8) -> Result<([u8; 32], CryptoState), CoreError> {
        use zeroize::Zeroizing;
        debug_assert!(steps >= 1, "derive_forward_crypto needs at least one step");
        // `Zeroizing` so every intermediate secret — and the working copy of the
        // current secret — is wiped on *every* exit path, including the early
        // `?` returns (an attacker can force this derivation merely by setting
        // `header.epoch`, so the candidate is genuinely sensitive).
        let mut secret: Zeroizing<[u8; 32]> = Zeroizing::new(*self.traffic_secret.read());
        for _ in 0..steps {
            let mut next: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);
            let hk = hkdf::Hkdf::<sha2::Sha256>::from_prk(&*secret)
                .map_err(|_| CoreError::KeyDerivationError)?;
            // Invariant 5 — the `phantom-rekey-v1` label is load-bearing and must
            // match the committing path in `rekey`.
            hk.expand(b"phantom-rekey-v1", &mut *next)
                .map_err(|_| CoreError::KeyDerivationError)?;
            secret = next; // previous-step secret drops → zeroed
        }
        let new_crypto = CryptoState::new(&secret, self.is_server)?;
        // Copy the bytes out for the caller; the `Zeroizing` working copy is
        // wiped when it drops here. The caller is responsible for the returned
        // secret (committed into `traffic_secret`, or zeroed on a failed trial).
        Ok((*secret, new_crypto))
    }

    /// Install a [`derive_forward_crypto`](Self::derive_forward_crypto)d epoch:
    /// swap in the new `CryptoState` via the lock-free `ArcSwap`, zero+replace
    /// the traffic secret under the write lock, and saturatingly advance the
    /// epoch by `steps` (Invariant 5 — epoch never wraps). The caller MUST have
    /// authenticated the transition (a successful trial decrypt, or its own
    /// send-side rekey) — this routine verifies nothing itself.
    fn commit_forward_crypto(&self, steps: u8, final_secret: [u8; 32], new_crypto: CryptoState) {
        let mut current = self.traffic_secret.write();
        // Install the new AEAD state, then the new epoch (SeqCst) so the wire
        // header the send path stamps matches the key it encrypts under.
        self.crypto.store(Arc::new(new_crypto));
        // Zero the old secret before overwriting it so the previous-epoch key
        // material does not survive in memory.
        current.zeroize();
        *current = final_secret;
        let cur = self.epoch.load(Ordering::Relaxed);
        self.epoch
            .store(cur.saturating_add(steps), Ordering::SeqCst);
    }

    /// Send-side AEAD invocation count for the current epoch (resets to 0 on
    /// each rekey). Drives [`send_needs_rekey`](Self::send_needs_rekey).
    pub fn send_invocations(&self) -> u64 {
        self.crypto.load().send_invocations()
    }

    /// The send-invocation high-watermark at which the pump auto-rekeys.
    pub fn rekey_threshold(&self) -> u64 {
        self.rekey_after.load(Ordering::Relaxed)
    }

    /// Override the auto-rekey high-watermark (default [`REKEY_SOFT_LIMIT`]).
    /// Clamped to `>= 1`. Rust-only — primarily for tests/soak harnesses that
    /// need to exercise mid-session rekey without sending `2^47` packets.
    pub fn set_rekey_threshold(&self, n: u64) {
        self.rekey_after.store(n.max(1), Ordering::Relaxed);
    }

    /// Override the per-stream sequence rekey watermark (default
    /// [`SEQ_REKEY_WATERMARK`], `2^31`). Clamped to `>= 1`. Rust-only — primarily
    /// for tests/soak harnesses that need to exercise the per-stream forced rekey
    /// (C1) without driving a single stream through `2^31` sequence numbers.
    pub fn set_seq_rekey_watermark(&self, n: u32) {
        self.seq_rekey_watermark.store(n.max(1), Ordering::Relaxed);
    }

    /// True once `stream_id`'s sequence has advanced past the per-stream
    /// watermark within the current epoch (C1). The send path checks this before
    /// stamping each packet and, when set, forces a [`rekey`](Self::rekey) so a
    /// per-stream `u32` sequence can never wrap within one epoch — which would
    /// otherwise repeat the AEAD nonce `(epoch, stream_id, sequence, path_id)`
    /// under a fixed key (Invariant 8).
    ///
    /// The per-stream `(epoch, base)` checkpoint is rebased lazily on the first
    /// call after an epoch change, so the measured span is always relative to
    /// where the stream entered the *current* epoch.
    pub fn stream_seq_needs_rekey(&self, stream_id: StreamId, seq: u32) -> bool {
        let epoch = self.current_epoch();
        let mut entry = self.seq_epoch_base.entry(stream_id).or_insert((epoch, seq));
        let (base_epoch, base_seq) = *entry;
        if base_epoch != epoch {
            // First send on this stream since a rekey — rebase to the current
            // sequence and measure this epoch's span from here.
            *entry = (epoch, seq);
            return false;
        }
        seq.wrapping_sub(base_seq) >= self.seq_rekey_watermark.load(Ordering::Relaxed)
    }

    /// True once the send direction has crossed the rekey high-watermark and the
    /// epoch has room to advance. The data pump checks this before each
    /// application send and, when set, rekeys + flags the packet `REKEY` so the
    /// peer follows via the authenticated epoch bump.
    pub fn send_needs_rekey(&self) -> bool {
        self.current_epoch() < u8::MAX
            && self.send_invocations() >= self.rekey_after.load(Ordering::Relaxed)
    }

    /// Decrypt a packet, transparently following an **authenticated** forward
    /// rekey of up to [`MAX_REKEY_CATCHUP`] epochs (C1).
    ///
    /// - `header.epoch == current`: ordinary [`decrypt_packet`](Self::decrypt_packet).
    /// - `current < header.epoch <= current + MAX_REKEY_CATCHUP`: derive the
    ///   candidate key that many epochs ahead and *trial*-decrypt. Only on AEAD
    ///   success — i.e. once the epoch bump is proven authentic — is the rekey
    ///   committed and the replay window consulted (Invariant 4 ordering
    ///   preserved). A forged `header.epoch` fails the AEAD open, nothing is
    ///   committed, and the session does not desync. The bound caps an attacker
    ///   to at most `MAX_REKEY_CATCHUP` HKDF steps per spoofed packet.
    /// - anything else (behind current, more than `MAX_REKEY_CATCHUP` ahead, or
    ///   epoch saturated): rejected. Over a reliable transport the sender
    ///   retransmits at the then-current epoch, so no data is lost.
    pub fn decrypt_packet_accepting_rekey(
        &self,
        header: &PacketHeader,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CoreError> {
        // Fast paths that need no epoch transition (no lock).
        let cur = self.current_epoch();
        if header.epoch == cur {
            return self.decrypt_packet(header, ciphertext);
        }
        if header.epoch < cur {
            return Err(CoreError::CryptoError(format!(
                "packet epoch {} is behind the current epoch {}",
                header.epoch, cur
            )));
        }

        // A forward ratchet mutates the epoch + key, so it must be serialised
        // against a concurrent send-side `rekey()` (C1 — both tasks share this
        // `Session`). Hold the rekey lock across the re-check, derive, trial
        // decrypt, and commit so the installed key depth and the epoch stay in
        // lockstep.
        let _rekey = self.rekey_lock.lock();
        // Re-read under the lock: a concurrent rekey may have already advanced us.
        let cur = self.current_epoch();
        if header.epoch == cur {
            drop(_rekey);
            return self.decrypt_packet(header, ciphertext);
        }
        if header.epoch < cur {
            return Err(CoreError::CryptoError(format!(
                "packet epoch {} is behind the current epoch {}",
                header.epoch, cur
            )));
        }
        let steps = header.epoch - cur; // > 0, both u8 → no underflow
        if steps > MAX_REKEY_CATCHUP {
            return Err(CoreError::CryptoError(format!(
                "packet epoch {} is more than {} epochs ahead of current {}",
                header.epoch, MAX_REKEY_CATCHUP, cur
            )));
        }

        // Candidate key `steps` epochs ahead — derived but NOT installed.
        let (mut final_secret, final_crypto) = self.derive_forward_crypto(steps)?;
        let nonce = Self::build_packet_nonce(final_crypto.nonce_prefix(), header);
        let header_bytes = header.to_wire();
        // AEAD gate: a forged epoch bump fails here and we return without
        // committing — the live epoch is untouched. Zero the (valid, sensitive)
        // candidate secret we are not going to install.
        let plaintext = match final_crypto.decrypt_with_nonce(nonce, &header_bytes, ciphertext) {
            Ok(pt) => pt,
            Err(e) => {
                final_secret.zeroize();
                return Err(e);
            }
        };

        // Authentic forward rekey — commit (still under the rekey lock; `cur` was
        // read under it, so `cur + steps == header.epoch` is the absolute, race-
        // free target), then drop the lock and apply the replay window AFTER the
        // AEAD open (Invariant 4 — the window is per-(stream,sequence) and
        // epoch-independent, so it needs no rekey serialisation).
        self.commit_forward_crypto(steps, final_secret, final_crypto);
        drop(_rekey);
        let window_entry = self
            .replay_windows
            .entry(header.stream_id)
            .or_insert_with(|| Mutex::new(ReplayWindow::new()));
        let accepted = window_entry.lock().accept(header.sequence);
        if !accepted {
            self.replay_rejected_total.fetch_add(1, Ordering::Relaxed);
            return Err(CoreError::ReplayDetected(format!(
                "stream {} sequence {} already seen or beyond window",
                header.stream_id, header.sequence
            )));
        }
        Ok(plaintext)
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

    // ── Multi-path / migration (Phase 4.2) ────────────────────────────

    /// Snapshot of currently `Validated` path ids. Useful for the
    /// scheduler when picking an outbound path.
    pub fn validated_paths(&self) -> Vec<u8> {
        self.path_registry.validated_paths()
    }

    /// State of a specific path within this session. Returns `None` for
    /// path ids the session has never observed.
    pub fn path_state(&self, path_id: u8) -> Option<PathStateKind> {
        self.path_registry.state(path_id)
    }

    /// Register a new path id and immediately issue a 32-byte
    /// PATH_CHALLENGE for it. Returns the challenge bytes; the caller
    /// must transmit them in a V2 packet with `PacketFlags::PATH_VALIDATION`
    /// set on the new path. Subsequent calls on an already-Validating
    /// path re-issue a fresh challenge.
    ///
    /// Returns `None` if the path is in a terminal state (`Validated`
    /// or `Failed`).
    #[tracing::instrument(name = "phantom.path.begin_validation", skip_all, fields(path_id = path_id))]
    pub fn begin_path_validation(&self, path_id: u8) -> Option<[u8; PATH_CHALLENGE_LEN]> {
        self.path_registry.register(path_id);
        self.path_registry.issue_challenge(path_id)
    }

    /// Register `path_id` as `Unvalidated` if the session has never observed it
    /// (PATH-001). Used by the receive-side gate to start tracking a fresh path
    /// id seen on inbound (AEAD-authenticated) data, so a later
    /// challenge/response can promote it to `Validated`. Idempotent — never
    /// resets an already-known path (e.g. the pre-validated path 0).
    pub(crate) fn register_unvalidated_path(&self, path_id: u8) {
        if self.path_registry.state(path_id).is_none() {
            self.path_registry.register(path_id);
        }
    }

    /// Verify a peer's `PATH_VALIDATION` response. Returns `true` if
    /// the response matches the in-flight challenge (path is now
    /// `Validated`). Returns `false` otherwise — the path may have
    /// transitioned to `Failed`.
    #[tracing::instrument(name = "phantom.path.complete_validation", skip(response), fields(path_id = path_id))]
    pub fn complete_path_validation(&self, path_id: u8, response: &[u8]) -> bool {
        self.path_registry.verify_response(path_id, response)
    }

    /// Record that a packet was observed on the path. Cheap to call
    /// per-packet — used by the data pump to keep `last_packet_seen`
    /// fresh for the timeout sweep.
    pub fn mark_path_seen(&self, path_id: u8) {
        self.path_registry.mark_seen(path_id);
    }

    // ── Pacer / BandwidthEstimator (Phase 2.6) ─────────────────────────

    /// Shared handle to this session's outbound rate-limiter. Cheap to
    /// clone (`Arc`). The data pump consults this before every outbound
    /// packet; idle by default ([`Pacer::unlimited`]).
    pub fn pacer(&self) -> Arc<Pacer> {
        self.pacer.clone()
    }

    /// Record that a packet of `bytes` length is going on the wire.
    /// Feeds the BBR-style bandwidth estimator. Cheap (one mutex lock
    /// + a counter increment).
    pub fn on_packet_sent(&self, bytes: u64) {
        self.bandwidth_estimator.lock().on_send(bytes);
    }

    /// Record that an ACK arrived with delivery sample `sample`. The
    /// returned `u64` is the updated bottleneck bandwidth estimate; we
    /// reflect it into the pacer so the outbound rate tracks the
    /// peer's actual receive throughput.
    pub fn on_packet_acked(&self, sample: DeliverySample) -> u64 {
        let bw = self.bandwidth_estimator.lock().on_ack(sample);
        // Mirror the estimator's pacing decision onto the pacer so the
        // two stay in lock-step.
        let rate = self.bandwidth_estimator.lock().pacing_rate();
        if rate > 0 {
            self.pacer.set_rate(rate);
        }
        bw
    }

    /// Record that a packet of `bytes` length was lost (no ACK before
    /// retransmit timer fired). Drives BBR's loss-based feedback.
    pub fn on_packet_lost(&self, bytes: u64) {
        self.bandwidth_estimator.lock().on_loss(bytes);
    }

    /// Current BBR congestion-control state. Observability / test hook — lets
    /// callers confirm a loss drove the estimator into `FastRecovery`.
    pub fn bbr_state(&self) -> crate::transport::bandwidth_estimator::BbrState {
        self.bandwidth_estimator.lock().state()
    }

    /// Read a snapshot of the bandwidth / pacing estimator. Cheap; held
    /// over a single mutex lock.
    pub fn bandwidth_snapshot(&self) -> BandwidthSnapshot {
        let est = self.bandwidth_estimator.lock();
        BandwidthSnapshot {
            bottleneck_bw_bps: est.bottleneck_bandwidth(),
            min_rtt: est.min_rtt(),
            pacing_rate_bps: est.pacing_rate(),
            cwnd_bytes: est.cwnd(),
            inflight_bytes: est.inflight_bytes(),
        }
    }

    // ── Event-driven send-loop wake-up (Phase 2.4) ─────────────────────

    /// Shared handle to the outbound-ready notify. The API-layer data
    /// pump awaits this via `Notify::notified()`; any task with the
    /// handle can wake it instantly via [`Self::notify_outbound_ready`].
    pub fn send_notifier(&self) -> Arc<tokio::sync::Notify> {
        self.send_notify.clone()
    }

    /// Wake the data pump's send loop immediately so it can drain newly-
    /// queued packets instead of waiting for the next 10 ms tick. Cheap
    /// (a single `notify_one()`); duplicate calls collapse to one wake.
    pub fn notify_outbound_ready(&self) {
        self.send_notify.notify_one();
    }

    /// Build the AEAD nonce from the authenticated header fields.
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
    fn build_packet_nonce(prefix: [u8; 4], header: &PacketHeader) -> [u8; 12] {
        let mut n = [0u8; 12];
        n[..4].copy_from_slice(&prefix);
        n[4] = header.epoch;
        n[5..7].copy_from_slice(&header.stream_id.to_be_bytes());
        n[7..11].copy_from_slice(&header.sequence.to_be_bytes());
        n[11] = header.path_id;
        n
    }

    /// Encrypt a packet payload.
    ///
    /// The AEAD nonce is derived from the authenticated `(epoch, stream_id,
    /// sequence, path_id)` fields of the packet header rather than from an
    /// internal monotonic counter, so a failed peer decrypt never desyncs the
    /// receiver. The AAD is the 45-byte wire image of the header
    /// ([`PacketHeader::to_wire`]), so any wire-level mutation invalidates the tag.
    pub fn encrypt_packet(
        &self,
        header: &PacketHeader,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CoreError> {
        let crypto = self.crypto.load();
        let nonce = Self::build_packet_nonce(crypto.nonce_prefix(), header);
        let header_bytes = header.to_wire();
        crypto.encrypt_with_nonce(nonce, &header_bytes, plaintext)
    }

    /// Decrypt a packet payload. Performs AEAD verify + per-stream
    /// sliding-window replay rejection (the window check runs **after** a
    /// successful AEAD open — Invariant 4 — so we never key off
    /// un-authenticated sequence numbers).
    ///
    /// A failed decrypt does NOT desync future decrypts: the AEAD nonce is
    /// derived from this packet's authenticated header fields, so the receiver
    /// stays in lock-step with the sender regardless of intervening bad
    /// packets.
    pub fn decrypt_packet(
        &self,
        header: &PacketHeader,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CoreError> {
        let crypto = self.crypto.load();
        let nonce = Self::build_packet_nonce(crypto.nonce_prefix(), header);
        let header_bytes = header.to_wire();
        let plaintext = crypto.decrypt_with_nonce(nonce, &header_bytes, ciphertext)?;

        // Sliding-window guard. ReplayWindow keys on `(stream_id, sequence)`
        // only — the `epoch` / `path_id` fields do NOT contribute to the
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
                "stream {} sequence {} already seen or beyond window",
                header.stream_id, header.sequence
            )));
        }
        Ok(plaintext)
    }

    /// Create a control packet
    pub fn create_control_packet(
        &self,
        _message: ControlMessage,
        payload: Vec<u8>,
    ) -> PhantomPacket {
        let seq = self.control_sequence.fetch_add(1, Ordering::SeqCst);
        let header = PacketHeader::new(
            self.id,
            0, // control stream
            seq,
            PacketFlags::new(PacketFlags::CONTROL | PacketFlags::RELIABLE),
        );
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

    /// The resumption secret for 0-RTT, if one has been installed. Rust-only —
    /// the FFI surface exposes this via `PhantomSession::resumption_hint()`.
    pub fn resumption_secret(&self) -> Option<[u8; 32]> {
        *self.resumption_secret.read()
    }

    /// Check if session can be resumed (has resumption secret)
    pub fn can_resume(&self) -> bool {
        self.resumption_secret.read().is_some()
    }

    /// Extract the resumption hint needed to attempt 0-RTT resume on
    /// a future connect (Phase 4.1). Returns `Some((session_id_bytes,
    /// resumption_secret))` only after a successful handshake — the
    /// resumption_secret is set by `process_client_hello` /
    /// `process_server_hello` once shared key material is in place.
    ///
    /// The caller is responsible for storing the tuple alongside the
    /// pinned `HybridVerifyingKey` of the server it was negotiated
    /// with. Mixing tickets across servers is a configuration bug —
    /// the resumption_secret is server-pinned.
    pub fn resumption_hint(&self) -> Option<([u8; 32], [u8; 32])> {
        let secret = (*self.resumption_secret.read())?;
        Some((self.id.0, secret))
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

/// Read-only snapshot of the session's pacing / bandwidth state
/// (Phase 2.6). Returned by [`Session::bandwidth_snapshot`] for
/// telemetry / debugging without exposing the mutable estimator.
#[derive(Debug, Clone, Copy)]
pub struct BandwidthSnapshot {
    pub bottleneck_bw_bps: u64,
    pub min_rtt: Duration,
    pub pacing_rate_bps: u64,
    pub cwnd_bytes: u64,
    pub inflight_bytes: u64,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session").field("id", &self.id).finish()
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
