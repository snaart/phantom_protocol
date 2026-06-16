//! Phantom Protocol - Session Management
//!
//! Virtual association that persists across IP changes.
//! Manages streams, encryption state, and multi-path scheduling.

use crate::crypto::adaptive_crypto::{CryptoSession, AEAD_MAX_INVOCATIONS};
use crate::crypto::cid_chain::{CidChain, CID_LEN, CID_WINDOW_LEADING, CID_WINDOW_TRAILING};
use crate::crypto::header_protection::{HeaderProtector, HP_SAMPLE_LEN};
use crate::errors::CoreError;
use crate::security::ReplayWindow;
use crate::transport::{
    bandwidth_estimator::{BandwidthEstimator, DeliverySample},
    fallback::FallbackStateMachine,
    liveness::LivenessConfig,
    pacer::Pacer,
    path::{PathRegistry, PathStateKind, PATH_CHALLENGE_LEN},
    scheduler::Scheduler,
    stream::Stream,
    types::{
        PacketFlags, PacketHeader, PacketNumber, PhantomPacket, RawPacket, SchedulerMode,
        SessionId, StreamId,
    },
};

use arc_swap::ArcSwap;
use parking_lot::{Mutex, RwLock};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, Ordering};
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
/// Set to `2^32`, far below the hard [`AEAD_MAX_INVOCATIONS`] (`2^48`) ceiling — clean
/// standards alignment (T5.3): the AES-256-GCM IND-CPA advantage at `2^32` records is
/// ~`2^-33`, comfortably inside the CFRG / QUIC confidentiality margins (the prior `2^47`
/// gave ~`2^-27`), so this is defense-in-depth, not a real exposure. It still dwarfs any
/// realistic session's packet count — a session sending `2^32` packets re-keys roughly
/// hourly even at 1 M pps — leaving ample headroom for in-flight old-epoch packets, so
/// production sessions ratchet a fresh key rather than approaching the ceiling. Tests lower
/// it via [`Session::set_rekey_threshold`] to exercise the path.
pub const REKEY_SOFT_LIMIT: u64 = 1 << 32;

// The soft rekey watermark must stay below the hard nonce-exhaustion ceiling so a session
// always rotates keys before it would fail with `NonceExhausted` (Invariant 8).
const _: () = assert!(REKEY_SOFT_LIMIT < AEAD_MAX_INVOCATIONS);

/// How many epochs the receive path will catch up in one packet when accepting
/// an authenticated forward rekey (C1). A small bound caps the HKDF work an
/// attacker can force per spoofed packet (each step is a trial that commits
/// nothing unless AEAD verifies) while comfortably absorbing the small epoch
/// divergence that arises when both directions rekey at slightly different
/// cadences. A gap larger than this is rejected; over a reliable transport the
/// sender retransmits at the then-current epoch, so no data is lost. In
/// practice (production `REKEY_SOFT_LIMIT` of `2^32`) the gap is essentially
/// always 0 or 1.
pub const MAX_REKEY_CATCHUP: u8 = 16;

/// Reserved `path_id` for validating a **passive** NAT rebind (M-3).
///
/// A passive rebind (the peer's source address changes without it calling
/// `migrate()`) keeps `path_id = 0` — the implicit, permanently-`Validated`
/// handshake path. Because path 0 is always Validated, the path-id-gated
/// challenge logic would skip it and the new source would never be validated,
/// promoted, or used for the downstream direction (a stall). The server detects
/// the rebind by *address* (an AEAD-authenticated frame whose source differs
/// from the established peer) and challenges that candidate on this dedicated
/// reserved id, which the registry can take through `Validating → Validated`
/// independently of the always-Validated path 0.
///
/// This id is carved permanently out of the active-migration id space:
/// [`Session::next_migration_path_id`] never returns it (it wraps `254 → 1`,
/// skipping both `0` and `255`), so a client-driven migration and a passive
/// rebind can never share this registry slot.
pub const REBIND_VALIDATION_PATH_ID: u8 = 255;

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

/// A one-step slide of the inbound CID demux window (ε / WIRE v5, P4b), produced
/// by [`Session::note_migration_path`] when the peer migrates. The demux applies
/// it: `add` are the CIDs to register at the new leading edge, `remove` the CIDs
/// that fell past the trailing edge, and `anchor` is a CID still routed for this
/// session (the demux resolves the session's channel through it).
#[derive(Clone, Debug)]
pub struct CidSlide {
    /// CIDs to register at the new leading edge.
    pub add: Vec<[u8; CID_LEN]>,
    /// CIDs to drop past the trailing edge.
    pub remove: Vec<[u8; CID_LEN]>,
    /// A CID currently routed for this session — the demux looks the channel up by it.
    pub anchor: [u8; CID_LEN],
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
    /// Per-session, per-direction header-protection keys (T4.6, QUIC RFC 9001
    /// §5.4). Derived ONCE from the initial session secret + the negotiated
    /// cipher suite and held stable for the session's lifetime — it does NOT
    /// rotate with `crypto`/`epoch` (QUIC §6.1: the hp key must be constant
    /// across key updates because `epoch` lives inside the masked header region;
    /// see [`HeaderProtector`]). Masks the 14-byte `[33..47]` header span on the
    /// wire via [`Self::protect_packet`] / unmasks it via [`Self::parse_protected`].
    header_protection: HeaderProtector,
    /// Per-direction, **session-stable** rotating connection-ID chain (ε / WIRE
    /// v5). Derived ONCE from the initial session secret (mirroring
    /// `header_protection`, same `is_server` swap); it does NOT rotate with
    /// `crypto`/`epoch`. The outbound chain stamps this peer's envelope `ConnId`
    /// ([`Self::current_outbound_cid`]); the inbound chain is what the peer's
    /// demux routes on ([`Self::inbound_window_cids`]). Zeroized on drop.
    cid_chain: CidChain,
    /// This peer's outbound CID migration index (ε / WIRE v5). Starts at 0;
    /// advances on `migrate()` (P4) so the stamped `ConnId` rotates to an
    /// independent-random value an observer cannot link across a migration.
    outbound_cid_index: AtomicU64,
    /// Highest inbound CID migration index observed (ε / WIRE v5). Centers the
    /// inbound demux window [`Self::inbound_window_cids`]. Starts at 0; advances
    /// post-AEAD when the peer migrates (P4). Tracked separately from
    /// `outbound_cid_index` — the two directions migrate independently.
    inbound_cid_highest_seen: AtomicU64,
    /// The highest peer `path_id` observed (ε / WIRE v5, P4b). The peer bumps its
    /// `path_id` in lock-step with its outbound CID index on each `migrate()`, so a
    /// NEW (forward, mod-256) `path_id` signals a migration → the inbound CID demux
    /// window slides one step. Tracked here so a reordered-old / duplicate
    /// `path_id` — or a passive rebind, which never bumps `path_id` — does not
    /// falsely slide.
    last_seen_path_id: AtomicU8,
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
    /// Serialises every epoch transition (C1). The data pump runs the send loop
    /// and the receive task concurrently over one `Arc<Session>`, so a send-side
    /// `rekey()` can race a receive-side ratchet. Both hold this mutex across
    /// their derive→install→epoch-bump so the installed key depth and the epoch
    /// counter never diverge (the bug would otherwise wedge the session).
    rekey_lock: Mutex<()>,
    /// T5.5(b) — "our locally-initiated rekey is not yet acknowledged by the
    /// peer". SET by [`rekey`](Self::rekey) and CLEARED by
    /// [`confirm_rekey_caught_up`](Self::confirm_rekey_caught_up) when an
    /// authenticated inbound packet arrives at our current epoch (proof the peer
    /// caught up). While set, the send path OR-s `PacketFlags::REKEY` into EVERY
    /// outbound header (not just the trigger packet), so losing the first
    /// new-epoch packet cannot strand a receiver behind the catch-up gate in
    /// [`decrypt_packet_accepting_rekey`](Self::decrypt_packet_accepting_rekey).
    /// A best-effort hint (Relaxed): over-advertising one extra packet or
    /// stopping one packet early is harmless — the security gate is the
    /// AEAD-authenticated REKEY flag + epoch check, not this bit.
    rekey_unconfirmed: AtomicBool,
    /// Which side of the handshake we are. Carried into every
    /// `CryptoState::new(...)` re-derivation so the per-direction keys are
    /// laid out the same way they were at session establishment.
    is_server: bool,
    /// Active streams
    streams: RwLock<HashMap<StreamId, Arc<Stream>>>,
    /// Next stream ID counter
    next_stream_id: AtomicU32,
    /// Multi-path scheduler
    scheduler: Arc<Scheduler>,
    /// Resumption secret for 0-RTT
    resumption_secret: RwLock<Option<[u8; 32]>>,
    /// Last activity timestamp. Refreshed on every authenticated inbound packet;
    /// the liveness sweep (P4.3) measures inbound silence from here.
    last_activity: RwLock<Instant>,
    /// Path-liveness thresholds (Phase 4 / P4.3). Read each pump heartbeat to decide
    /// path-down / recovery / death; lowerable via [`set_liveness_config`] for tests.
    ///
    /// [`set_liveness_config`]: Self::set_liveness_config
    liveness_config: RwLock<LivenessConfig>,
    /// Fallback state machine
    #[allow(dead_code)]
    fallback: Arc<FallbackStateMachine>,
    /// Per-direction monotonic AEAD packet number (① — Phase 4). Every outbound
    /// packet draws the next value here at send time, so the AEAD nonce is never
    /// reused. Replaces the deleted per-stream `send_sequence` + the C1 watermark.
    send_packet_number: AtomicU64,
    /// Client-owned send-side `path_id` stamped on every outbound packet (D5 —
    /// Phase 4). Defaults to 0 (the implicit handshake path, pre-validated on both
    /// peers). [`next_migration_path_id`](Self::next_migration_path_id) bumps it on
    /// each `migrate()` so the peer's source-change detector sees a new path label
    /// and challenges it; reuse is nonce-safe because ① took `path_id` out of the
    /// AEAD nonce. Never set to 0 by the bump — 0 is reserved for the
    /// always-Validated handshake path. (Field name differs from the
    /// [`current_send_path_id`](Self::current_send_path_id) accessor, mirroring the
    /// `send_packet_number` / `next_send_pn` split.)
    send_path_id: AtomicU8,
    /// Per-direction sliding-window replay protection on the packet number
    /// (① — Phase 4, Inv-4). One window per direction (the PN is unique across all
    /// streams), replacing the per-`StreamId` `DashMap<…, ReplayWindow>`.
    recv_replay: Mutex<ReplayWindow>,
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
    /// Optional channel to the UDP demux for sliding this session's inbound CID
    /// window (ε / WIRE v5, P4b). Set once post-handshake by the server's accept
    /// path ([`Self::set_cid_slide_tx`]); `None` on the client and on socket-routed
    /// transports (which have no CID demux). `handle_packet` signals a slide
    /// through it when [`Self::note_migration_path`] reports the peer migrated.
    cid_slide_tx: Mutex<Option<tokio::sync::mpsc::UnboundedSender<CidSlide>>>,
    /// An idle keep-alive PING is in flight, awaiting the peer's PONG (Direction
    /// #3 — download-only liveness). Set when the pump emits a `KEEPALIVE` ping on
    /// an idle path; cleared when the peer's `KEEPALIVE | ACK` echo arrives (or any
    /// authenticated inbound packet refreshes liveness). While set it makes the
    /// liveness sweep treat the path as having an outstanding probe, so a
    /// silently-dead downstream on a download-only path is detected exactly like an
    /// active one. A plain `AtomicBool` — the ping is a single outstanding probe, so
    /// a richer counter buys nothing.
    keepalive_outstanding: AtomicBool,
}

impl Session {
    /// Create a new session with given shared secret
    pub fn new(
        session_id: SessionId,
        shared_secret: &[u8; 32],
        peer_side: bool,
    ) -> Result<Self, CoreError> {
        let crypto = CryptoState::new(shared_secret, peer_side)?;
        // HP keys derive from the INITIAL secret + the negotiated suite and stay
        // stable for the session (QUIC §6.1) — see the `header_protection` field.
        let header_protection =
            HeaderProtector::derive(crypto.session.cipher_suite(), shared_secret, peer_side);
        let path_registry = Arc::new(PathRegistry::new());
        // Pre-register `path_id = 0` as the implicit default path — the
        // handshake itself proved reachability over this path, so no
        // additional PATH_CHALLENGE is needed (Phase 4.2).
        path_registry.register_validated(0);

        Ok(Self {
            id: session_id,
            state: RwLock::new(SessionState::Handshaking),
            crypto: ArcSwap::new(Arc::new(crypto)),
            header_protection,
            cid_chain: CidChain::derive(shared_secret, peer_side),
            outbound_cid_index: AtomicU64::new(0),
            inbound_cid_highest_seen: AtomicU64::new(0),
            last_seen_path_id: AtomicU8::new(0),
            traffic_secret: RwLock::new(*shared_secret),
            epoch: AtomicU8::new(0),
            rekey_after: AtomicU64::new(REKEY_SOFT_LIMIT),
            rekey_lock: Mutex::new(()),
            rekey_unconfirmed: AtomicBool::new(false),
            is_server: peer_side,
            streams: RwLock::new(HashMap::new()),
            next_stream_id: AtomicU32::new(1),
            scheduler: Arc::new(Scheduler::new(SchedulerMode::LowLatency)),
            resumption_secret: RwLock::new(None),
            last_activity: RwLock::new(Instant::now()),
            liveness_config: RwLock::new(LivenessConfig::default()),
            fallback: Arc::new(FallbackStateMachine::with_defaults()),
            send_packet_number: AtomicU64::new(0),
            send_path_id: AtomicU8::new(0),
            recv_replay: Mutex::new(ReplayWindow::new()),
            replay_rejected_total: AtomicU64::new(0),
            path_registry,
            pacer: Arc::new(Pacer::unlimited()),
            bandwidth_estimator: parking_lot::Mutex::new(BandwidthEstimator::new()),
            send_notify: Arc::new(tokio::sync::Notify::new()),
            cid_slide_tx: Mutex::new(None),
            keepalive_outstanding: AtomicBool::new(false),
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
        let header_protection =
            HeaderProtector::derive(crypto.session.cipher_suite(), &traffic_secret, is_server);
        let path_registry = Arc::new(PathRegistry::new());
        path_registry.register_validated(0);
        Self {
            id: session_id,
            state: RwLock::new(SessionState::Connected),
            crypto: ArcSwap::new(Arc::new(crypto)),
            header_protection,
            cid_chain: CidChain::derive(&traffic_secret, is_server),
            outbound_cid_index: AtomicU64::new(0),
            inbound_cid_highest_seen: AtomicU64::new(0),
            last_seen_path_id: AtomicU8::new(0),
            traffic_secret: RwLock::new(traffic_secret),
            epoch: AtomicU8::new(0),
            rekey_after: AtomicU64::new(REKEY_SOFT_LIMIT),
            rekey_lock: Mutex::new(()),
            rekey_unconfirmed: AtomicBool::new(false),
            is_server,
            streams: RwLock::new(HashMap::new()),
            next_stream_id: AtomicU32::new(1),
            scheduler: Arc::new(Scheduler::new(scheduler_mode)),
            resumption_secret: RwLock::new(None),
            last_activity: RwLock::new(Instant::now()),
            liveness_config: RwLock::new(LivenessConfig::default()),
            fallback: Arc::new(FallbackStateMachine::with_defaults()),
            send_packet_number: AtomicU64::new(0),
            send_path_id: AtomicU8::new(0),
            recv_replay: Mutex::new(ReplayWindow::new()),
            replay_rejected_total: AtomicU64::new(0),
            path_registry,
            pacer: Arc::new(Pacer::unlimited()),
            bandwidth_estimator: parking_lot::Mutex::new(BandwidthEstimator::new()),
            send_notify: Arc::new(tokio::sync::Notify::new()),
            cid_slide_tx: Mutex::new(None),
            keepalive_outstanding: AtomicBool::new(false),
        }
    }

    /// Resume a session using resumption secret (0-RTT)
    pub fn resume(
        session_id: SessionId,
        resumption_secret: &[u8; 32],
        peer_side: bool,
    ) -> Result<Self, CoreError> {
        let crypto = CryptoState::new(resumption_secret, peer_side)?;
        let header_protection =
            HeaderProtector::derive(crypto.session.cipher_suite(), resumption_secret, peer_side);
        let path_registry = Arc::new(PathRegistry::new());
        path_registry.register_validated(0);

        Ok(Self {
            id: session_id,
            state: RwLock::new(SessionState::Connected),
            crypto: ArcSwap::new(Arc::new(crypto)),
            header_protection,
            cid_chain: CidChain::derive(resumption_secret, peer_side),
            outbound_cid_index: AtomicU64::new(0),
            inbound_cid_highest_seen: AtomicU64::new(0),
            last_seen_path_id: AtomicU8::new(0),
            traffic_secret: RwLock::new(*resumption_secret),
            epoch: AtomicU8::new(0),
            rekey_after: AtomicU64::new(REKEY_SOFT_LIMIT),
            rekey_lock: Mutex::new(()),
            rekey_unconfirmed: AtomicBool::new(false),
            is_server: peer_side,
            streams: RwLock::new(HashMap::new()),
            next_stream_id: AtomicU32::new(1),
            scheduler: Arc::new(Scheduler::new(SchedulerMode::LowLatency)),
            resumption_secret: RwLock::new(Some(*resumption_secret)),
            last_activity: RwLock::new(Instant::now()),
            liveness_config: RwLock::new(LivenessConfig::default()),
            fallback: Arc::new(FallbackStateMachine::with_defaults()),
            send_packet_number: AtomicU64::new(0),
            send_path_id: AtomicU8::new(0),
            recv_replay: Mutex::new(ReplayWindow::new()),
            replay_rejected_total: AtomicU64::new(0),
            path_registry,
            pacer: Arc::new(Pacer::unlimited()),
            bandwidth_estimator: parking_lot::Mutex::new(BandwidthEstimator::new()),
            send_notify: Arc::new(tokio::sync::Notify::new()),
            cid_slide_tx: Mutex::new(None),
            keepalive_outstanding: AtomicBool::new(false),
        })
    }

    /// The envelope `ConnId` this peer currently stamps on outbound UDP datagrams
    /// (ε / WIRE v5). At the current outbound CID index (0 until the first
    /// `migrate()`) this is `CID_0` of the outbound chain — and it is exactly
    /// `inbound_window_cids()[0]` for the peer, which is how the demux routes it.
    /// TCP/embedded transports are socket-routed and ignore this.
    pub fn current_outbound_cid(&self) -> [u8; CID_LEN] {
        self.cid_chain
            .outbound_cid(self.outbound_cid_index.load(Ordering::Relaxed))
    }

    /// This peer's current outbound CID migration index (ε / WIRE v5). 0 until the
    /// first `migrate()`; exposed for the migration wiring (P4) and diagnostics.
    pub fn outbound_cid_index(&self) -> u64 {
        self.outbound_cid_index.load(Ordering::Relaxed)
    }

    /// Rotate the outbound CID one step (ε / WIRE v5; called on `migrate()`):
    /// advance the outbound index and return the new `CID_{i+1}` for the transport
    /// to stamp. The new CID is independent-random vs the previous one, so an
    /// observer cannot link the pre- and post-migration flows; it stays inside the
    /// peer's pre-registered inbound window for up to K migrations (the demux
    /// window slides post-AEAD beyond that).
    pub fn advance_outbound_cid(&self) -> [u8; CID_LEN] {
        let i = self.outbound_cid_index.fetch_add(1, Ordering::Relaxed) + 1;
        self.cid_chain.outbound_cid(i)
    }

    /// Track the peer's migration via its `path_id` and, on a NEW (forward) path,
    /// slide the inbound CID demux window one step (ε / WIRE v5, P4b). Returns the
    /// [`CidSlide`] to apply at the demux, or `None` if `path_id` is not newer — a
    /// reordered-old or duplicate packet, or a passive rebind that did not rotate
    /// the CID, none of which advance the index. Call **post-AEAD only** (the
    /// `path_id` is then authenticated). The single-step advance keeps the window
    /// tracking the peer's outbound index (both bump once per `migrate()`); the
    /// leading window K absorbs any transient lag from a multi-hop jump.
    pub fn note_migration_path(&self, path_id: u8) -> Option<CidSlide> {
        let last = self.last_seen_path_id.load(Ordering::Relaxed);
        // "Newer" = a forward distance in (0, 128] mod 256 — a reordered-old
        // path_id is > 128 behind, and the 255 -> 1 migrate wrap is distance 2.
        let fwd = path_id.wrapping_sub(last);
        if fwd == 0 || fwd > 128 {
            return None;
        }
        // CAS so concurrent recv handling slides exactly once per migration.
        if self
            .last_seen_path_id
            .compare_exchange(last, path_id, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            return None;
        }
        // EPS-01 — advance by the FULL forward delta `d`, not +1. The peer bumps
        // its path_id and CID index in lock-step on each `migrate()`, so a forward
        // path_id distance of `d` means it migrated `d` times; sliding the window by
        // `d` recenters it on the peer's *actual* migration index. The pre-fix +1
        // step let lost intermediate migrations cumulatively erode the leading
        // window until the peer's CID fell out of it and the session stranded. The
        // triggering packet's CID (= `inbound_cid(new_high)`) was inside the pre-slide
        // window (else it would have been dropped pre-AEAD and we would never run
        // here), so `d <= CID_WINDOW_LEADING` and the widened K bounds the per-slide
        // churn; `anchor` is therefore in the demux route table for `apply_slide`.
        let d = fwd as u64;
        let old_high = self
            .inbound_cid_highest_seen
            .fetch_add(d, Ordering::Relaxed);
        let new_high = old_high + d;
        let anchor = self.cid_chain.inbound_cid(new_high);
        // Register the `d` new leading-edge CIDs `(old_high+K, new_high+K]`.
        let add: Vec<[u8; CID_LEN]> = ((old_high + CID_WINDOW_LEADING + 1)
            ..=(new_high + CID_WINDOW_LEADING))
            .map(|i| self.cid_chain.inbound_cid(i))
            .collect();
        // Drop the trailing CIDs that fell past the window `[old_lo, new_lo)`
        // (saturating at index 0 — indices below 0 were never registered).
        let old_lo = old_high.saturating_sub(CID_WINDOW_TRAILING);
        let new_lo = new_high.saturating_sub(CID_WINDOW_TRAILING);
        let remove: Vec<[u8; CID_LEN]> = (old_lo..new_lo)
            .map(|i| self.cid_chain.inbound_cid(i))
            .collect();
        Some(CidSlide {
            add,
            remove,
            anchor,
        })
    }

    /// Install the demux slide channel (ε / WIRE v5, P4b) — called once by the
    /// server's accept path so `handle_packet` can signal inbound-window slides.
    pub fn set_cid_slide_tx(&self, tx: tokio::sync::mpsc::UnboundedSender<CidSlide>) {
        *self.cid_slide_tx.lock() = Some(tx);
    }

    /// Signal the demux to apply a [`CidSlide`] (ε / WIRE v5, P4b). A no-op when no
    /// slide channel is installed (the client and socket-routed transports).
    pub fn signal_cid_slide(&self, slide: CidSlide) {
        if let Some(tx) = self.cid_slide_tx.lock().as_ref() {
            let _ = tx.send(slide);
        }
    }

    /// The inbound CIDs the demux should route to this session (ε / WIRE v5): the
    /// window `[highest_seen − T, highest_seen + K]` over this peer's inbound
    /// chain. At session establishment (`highest_seen = 0`, trailing saturates)
    /// this is the leading lookahead `[CID_0 .. CID_K]` (K + 1 entries). The
    /// server registers these in its `RouteTable`; a datagram whose `ConnId` is in
    /// the set routes to this session. The window slide on `migrate()` is P4.
    pub fn inbound_window_cids(&self) -> Vec<[u8; CID_LEN]> {
        self.cid_chain
            .inbound_window(
                self.inbound_cid_highest_seen.load(Ordering::Relaxed),
                CID_WINDOW_TRAILING,
                CID_WINDOW_LEADING,
            )
            .map(|(_, cid)| cid)
            .collect()
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
        // T5.5(b): mark this locally-initiated rekey "unconfirmed" so the send
        // path re-advertises `PacketFlags::REKEY` on EVERY new-epoch packet until
        // the peer is seen at the new epoch. A lost trigger packet then no longer
        // strands the peer behind the catch-up gate. Cleared in
        // `confirm_rekey_caught_up` from the recv path. NOTE: a receive-side
        // forward catch-up (`decrypt_packet_accepting_rekey` → `commit_forward_crypto`)
        // deliberately does NOT set this — following the peer's rekey is not OUR
        // rekey, so we owe no re-advertise.
        self.rekey_unconfirmed.store(true, Ordering::Relaxed);
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

    /// True once the send direction has crossed the rekey high-watermark and the
    /// epoch has room to advance. The data pump checks this before each
    /// application send and, when set, rekeys + flags the packet `REKEY` so the
    /// peer follows via the authenticated epoch bump.
    pub fn send_needs_rekey(&self) -> bool {
        self.current_epoch() < u8::MAX
            && self.send_invocations() >= self.rekey_after.load(Ordering::Relaxed)
    }

    /// T5.5(b) — true while a locally-initiated [`rekey`](Self::rekey) is still
    /// unacknowledged by the peer. The send path OR-s `PacketFlags::REKEY` into
    /// every outbound header while this holds, so the catch-up gate in
    /// [`decrypt_packet_accepting_rekey`](Self::decrypt_packet_accepting_rekey)
    /// can safely reject an unflagged forward epoch: an honest not-yet-confirmed
    /// sender always re-advertises the flag. See the field doc for the relaxed
    /// ordering rationale.
    pub fn rekey_unconfirmed(&self) -> bool {
        self.rekey_unconfirmed.load(Ordering::Relaxed)
    }

    /// Clear the [`rekey_unconfirmed`](Self::rekey_unconfirmed) re-advertise flag.
    /// Called from the receive path on a successful authenticated decrypt of an
    /// inbound packet at our current epoch (after any forward catch-up that packet
    /// drove) — proof the peer has reached our epoch, so we stop re-advertising
    /// `REKEY` (T5.5b). A no-op when the flag is already clear.
    fn confirm_rekey_caught_up(&self) {
        self.rekey_unconfirmed.store(false, Ordering::Relaxed);
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
        extensions: &[u8],
    ) -> Result<Vec<u8>, CoreError> {
        // Fast paths that need no epoch transition (no lock).
        let cur = self.current_epoch();
        if header.epoch == cur {
            let pt = self.decrypt_packet(header, ciphertext, extensions)?;
            // T5.5(b): an authenticated peer packet at our current epoch proves
            // the peer caught up to any rekey we initiated — stop re-advertising.
            self.confirm_rekey_caught_up();
            return Ok(pt);
        }
        if header.epoch < cur {
            return Err(CoreError::CryptoError(format!(
                "packet epoch {} is behind the current epoch {}",
                header.epoch, cur
            )));
        }

        // T5.5(b) catch-up GATE: a forward epoch must carry `PacketFlags::REKEY`.
        // An honest sender that rekeyed re-advertises REKEY on EVERY new-epoch
        // packet until we confirm (see `rekey_unconfirmed`), so an unflagged
        // forward epoch is forged/corrupt — reject it cheaply HERE, before taking
        // the rekey lock and running the HKDF catch-up walk. This tightens the DoS
        // bound (a spoofed forward epoch with the flag cleared forces zero key
        // derivation; with the flag set it still costs at most MAX_REKEY_CATCHUP
        // HKDF steps + a failing trial decrypt). A genuine not-yet-caught-up sender
        // is unaffected: it always sets the flag. NB this read is race-free against
        // a concurrent send-side rekey — for `header.epoch` to be forward here our
        // epoch is < header.epoch, and an honest sender only stops flagging once we
        // have already reached its epoch (it saw our packet there), at which point
        // header.epoch would not be forward. See the field doc.
        if !header.flags.contains(PacketFlags::REKEY) {
            return Err(CoreError::CryptoError(format!(
                "forward epoch {} without the REKEY flag; rejected before catch-up (current {})",
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
            let pt = self.decrypt_packet(header, ciphertext, extensions)?;
            self.confirm_rekey_caught_up();
            return Ok(pt);
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
        // AEAD gate: a forged epoch bump fails here and we return without
        // committing — the live epoch is untouched. Zero the (valid, sensitive)
        // candidate secret we are not going to install.
        let plaintext = match Self::with_packet_aad(header, extensions, |aad| {
            final_crypto.decrypt_with_nonce(nonce, aad, ciphertext)
        }) {
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
        let accepted = self.recv_replay.lock().accept(header.packet_number);
        if !accepted {
            self.replay_rejected_total.fetch_add(1, Ordering::Relaxed);
            return Err(CoreError::ReplayDetected(format!(
                "packet_number {} already seen or beyond window",
                header.packet_number
            )));
        }
        // T5.5(b): we just followed the peer forward and committed — the peer is
        // now at our (new) current epoch, which is >= any epoch we rekeyed to, so
        // our own pending rekey (if any) is confirmed. Stop re-advertising.
        self.confirm_rekey_caught_up();
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

    /// Remove a path from the registry so its id becomes re-registerable (D5 —
    /// Phase 4). Used by the M-3 passive-rebind flow to retire the reserved
    /// validation id after a successful promotion, so a later rebind can re-issue a
    /// fresh challenge on it (a `Validated` path would otherwise refuse a new
    /// challenge). No-op for unknown ids. Reuse is nonce-safe because ① took
    /// `path_id` out of the AEAD nonce.
    pub(crate) fn retire_path(&self, path_id: u8) {
        self.path_registry.retire(path_id);
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

    /// Reset the congestion controller + pacer to startup (Phase 4 / QUIC §9.4):
    /// a migration path switch lands on a different network, so the old
    /// bottleneck-bandwidth / cwnd estimate must not carry over — inheriting a low
    /// RTT/cwnd would trigger a spurious-retransmit storm on the first packets of
    /// the new path. Wired by the P4.2 migration switch.
    pub fn reset_congestion(&self) {
        let mut est = self.bandwidth_estimator.lock();
        *est = BandwidthEstimator::new();
        let rate = est.pacing_rate();
        drop(est);
        // Drop the dead path's stale pacing rate; BBR re-paces on the first ACK.
        self.pacer.set_rate(rate);
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

    /// Reserve the next outbound packet number for this direction (① — Phase 4).
    /// Strictly monotonic; never reused within a session. Drawn by the data pump
    /// for every outbound packet (data, control, path-validation, retransmit) at
    /// send time, so the AEAD nonce is never reused.
    pub fn next_send_pn(&self) -> PacketNumber {
        self.send_packet_number.fetch_add(1, Ordering::SeqCst)
    }

    /// The client-owned send-side `path_id` currently stamped on outbound packets
    /// (D5 — Phase 4). Defaults to 0 (the implicit handshake path). Bumped by
    /// [`next_migration_path_id`](Self::next_migration_path_id) on a migration.
    pub fn current_send_path_id(&self) -> u8 {
        self.send_path_id.load(Ordering::SeqCst)
    }

    /// Bump the send-side `path_id` to a fresh value and return it (D5 — Phase 4).
    /// Called on each `migrate()`/rebind so the peer's source-change detector sees a
    /// new path label and issues a PATH_CHALLENGE. Never returns 0 — that id is
    /// permanently the always-Validated handshake path, so reusing it would make the
    /// peer skip the challenge and the switch could never fire. Also never returns
    /// [`REBIND_VALIDATION_PATH_ID`] (`255`), reserved for the M-3 passive-rebind
    /// challenge — sharing that slot would let an active-migration echo and a
    /// passive-rebind echo resolve each other's registry entry. Wraps `254 → 1`.
    /// Reuse of a retired id is nonce-safe because ① took `path_id` out of the AEAD
    /// nonce (`nonce = nonce_prefix ‖ packet_number`).
    pub fn next_migration_path_id(&self) -> u8 {
        // migrate() is embedder-driven and not concurrent, but a CAS loop keeps the
        // "never 0 / never reserved" invariant correct even under a racing caller.
        loop {
            let cur = self.send_path_id.load(Ordering::SeqCst);
            // Skip 0 (handshake path) and REBIND_VALIDATION_PATH_ID (reserved).
            let next = match cur.wrapping_add(1) {
                0 | REBIND_VALIDATION_PATH_ID => 1,
                n => n,
            };
            if self
                .send_path_id
                .compare_exchange(cur, next, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                return next;
            }
        }
    }

    /// Build the AEAD nonce (① — Phase 4): `prefix(4) ‖ packet_number(8)` = 12 B.
    ///
    /// `epoch` / `stream_id` / `path_id` are authenticated in the 47-byte AAD but
    /// NOT in the nonce — a `u64` packet number is unique per direction within an
    /// epoch (and the prefix is fresh per epoch), so the nonce is never reused.
    /// `epoch` is still read from the header to select the key. Audit anchor: "PN
    /// strictly monotonic, used once per direction → nonce never reused, full stop."
    fn build_packet_nonce(prefix: [u8; 4], header: &PacketHeader) -> [u8; 12] {
        let mut n = [0u8; 12];
        n[..4].copy_from_slice(&prefix);
        n[4..12].copy_from_slice(&header.packet_number.to_be_bytes());
        n
    }

    /// Run `f` with the AEAD AAD for a packet: the 47-byte header AAD image
    /// (`PacketHeader::to_aad_image` — `version ‖ session_id ‖ packet_number ‖
    /// flags ‖ stream_id ‖ epoch ‖ path_id`) followed by the packet's
    /// `extensions` TLV.
    ///
    /// ε / WIRE v5 — `session_id` is off-wire (the on-wire header is 15 bytes),
    /// but the AAD stays the byte-identical 47-byte v4 image so the AEAD security
    /// argument is unchanged; the recv path reconstructs `header.session_id` from
    /// the session context before calling this (see [`Self::parse_protected`]).
    ///
    /// T4.1 — `extensions` (the forward-compat TLV headroom) is authenticated
    /// here, closing the prior malleability where it sat *outside* the AAD and an
    /// on-path attacker could rewrite the trailing bytes without breaking the tag.
    /// When `extensions` is empty — the data-plane default — the AAD is exactly
    /// the 47-byte header image and no allocation occurs, so the hot path stays
    /// alloc-free.
    #[inline]
    fn with_packet_aad<R>(
        header: &PacketHeader,
        extensions: &[u8],
        f: impl FnOnce(&[u8]) -> R,
    ) -> R {
        let header_bytes = header.to_aad_image();
        if extensions.is_empty() {
            f(&header_bytes)
        } else {
            let mut aad = Vec::with_capacity(header_bytes.len() + extensions.len());
            aad.extend_from_slice(&header_bytes);
            aad.extend_from_slice(extensions);
            f(&aad)
        }
    }

    /// Encrypt a packet payload.
    ///
    /// The AEAD nonce is `prefix || packet_number` (① — Phase 4), derived from the
    /// authenticated header rather than an internal counter, so a failed peer
    /// decrypt never desyncs the receiver. The AAD is the 47-byte AAD image of the
    /// header ([`PacketHeader::to_aad_image`]) — which still binds `session_id` /
    /// `epoch` / `stream_id` / `path_id` even though the wire header is 15 bytes —
    /// followed by the packet's `extensions` TLV (T4.1), so any
    /// wire-level mutation of the header *or* the extensions invalidates the tag.
    pub fn encrypt_packet(
        &self,
        header: &PacketHeader,
        plaintext: &[u8],
        extensions: &[u8],
    ) -> Result<Vec<u8>, CoreError> {
        let crypto = self.crypto.load();
        let nonce = Self::build_packet_nonce(crypto.nonce_prefix(), header);
        Self::with_packet_aad(header, extensions, |aad| {
            crypto.encrypt_with_nonce(nonce, aad, plaintext)
        })
    }

    /// Decrypt a packet payload. Performs AEAD verify + per-direction
    /// sliding-window replay rejection on the packet number (the window check runs
    /// **after** a successful AEAD open — Invariant 4 — so we never key off
    /// un-authenticated packet numbers).
    ///
    /// A failed decrypt does NOT desync future decrypts: the AEAD nonce is
    /// derived from this packet's authenticated header fields, so the receiver
    /// stays in lock-step with the sender regardless of intervening bad
    /// packets.
    pub fn decrypt_packet(
        &self,
        header: &PacketHeader,
        ciphertext: &[u8],
        extensions: &[u8],
    ) -> Result<Vec<u8>, CoreError> {
        let crypto = self.crypto.load();
        let nonce = Self::build_packet_nonce(crypto.nonce_prefix(), header);
        let plaintext = Self::with_packet_aad(header, extensions, |aad| {
            crypto.decrypt_with_nonce(nonce, aad, ciphertext)
        })?;

        // Sliding-window guard. ReplayWindow keys on `(stream_id, sequence)`
        // only — the `epoch` / `path_id` fields do NOT contribute to the
        // replay identity because replay is a property of "is this sequence
        // a duplicate", independent of which path it arrived over or which
        // rekey generation produced it.
        let accepted = self.recv_replay.lock().accept(header.packet_number);
        if !accepted {
            self.replay_rejected_total.fetch_add(1, Ordering::Relaxed);
            return Err(CoreError::ReplayDetected(format!(
                "packet_number {} already seen or beyond window",
                header.packet_number
            )));
        }
        Ok(plaintext)
    }

    // ── Header protection (T4.6, QUIC RFC 9001 §5.4) ──────────────────────────

    /// Serialise a packet to its **header-protected** on-wire bytes: the
    /// `[1..15]` header span is XOR-masked with this session's send-direction HP
    /// key, keyed by the packet's ciphertext sample (the first 16 bytes of
    /// `packet.payload`). The data plane calls this instead of `to_wire` for
    /// every post-handshake packet. `packet.payload` must be AEAD ciphertext
    /// (>= the 16-byte tag) — always true for the output of
    /// [`encrypt_packet`](Self::encrypt_packet).
    pub fn protect_packet(&self, packet: &PhantomPacket) -> Result<Vec<u8>, CoreError> {
        let sample = Self::hp_sample(&packet.payload)?;
        let mask = self.header_protection.mask_send(&sample)?;
        Ok(packet.to_wire_masked(&mask))
    }

    /// Parse a **header-protected** wire packet: recover the cleartext header by
    /// unmasking the `[1..15]` span with this session's recv-direction HP key
    /// (keyed by the cleartext ciphertext sample), reconstruct the off-wire
    /// `session_id` from this session's id (ε / WIRE v5), then reassemble the
    /// `PhantomPacket`. The caller still gates on `version` and runs AEAD on the
    /// result — a wire mutation of the masked region unmasks to a wrong header, so
    /// the subsequent AEAD open fails (no new oracle). A short / malformed frame
    /// returns `Err` and is dropped by the recv loop.
    pub fn parse_protected(&self, bytes: &[u8]) -> Result<PhantomPacket, CoreError> {
        let raw = RawPacket::from_wire(bytes)
            .map_err(|e| CoreError::CryptoError(format!("HP: malformed wire packet: {e}")))?;
        let sample = Self::hp_sample(&raw.payload)?;
        let mask = self.header_protection.mask_recv(&sample)?;
        let mut header = raw
            .unmask_header(&mask)
            .map_err(|e| CoreError::CryptoError(format!("HP: header unmask failed: {e}")))?;
        // ε / WIRE v5: session_id is off-wire — reconstruct it from the routed
        // session context so the AAD image matches what the sender authenticated
        // (the 47-byte `to_aad_image`). A wrong session here → wrong AAD → AEAD
        // fail; this is the off-wire analogue of the v4 cleartext-session_id bind.
        header.session_id = *self.id();
        Ok(raw.into_packet(header))
    }

    /// The 16-byte HP sample = the first [`HP_SAMPLE_LEN`] bytes of the AEAD
    /// ciphertext. The tag is always present, so this exists even for an
    /// empty-plaintext packet (sample = tag). A payload shorter than the tag is a
    /// malformed / never-encrypted frame → typed error, never a panic.
    #[inline]
    fn hp_sample(payload: &[u8]) -> Result<[u8; HP_SAMPLE_LEN], CoreError> {
        payload
            .get(..HP_SAMPLE_LEN)
            .and_then(|s| <[u8; HP_SAMPLE_LEN]>::try_from(s).ok())
            .ok_or_else(|| {
                CoreError::CryptoError("HP: packet payload shorter than the AEAD tag".into())
            })
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

    /// Update last activity timestamp.
    ///
    /// Called on every authenticated inbound packet. Any such packet — the
    /// keep-alive PONG, an ACK, or application data — proves the path is alive, so
    /// it also clears an outstanding idle keep-alive probe (Direction #3): the
    /// probe has been answered, so the liveness sweep no longer needs to treat the
    /// path as awaiting a response.
    pub fn update_activity(&self) {
        *self.last_activity.write() = Instant::now();
        self.keepalive_outstanding.store(false, Ordering::Relaxed);
    }

    /// Mark that an idle keep-alive PING was just emitted and is awaiting the
    /// peer's PONG (Direction #3). While outstanding, the liveness sweep treats
    /// the path as having a probe in flight even with no reliable data queued, so a
    /// download-only path can detect a silently-dead downstream.
    pub fn mark_keepalive_outstanding(&self) {
        self.keepalive_outstanding.store(true, Ordering::Relaxed);
    }

    /// Whether an idle keep-alive PING is currently awaiting a PONG (Direction #3).
    /// `false` once any authenticated inbound packet refreshes activity.
    pub fn keepalive_outstanding(&self) -> bool {
        self.keepalive_outstanding.load(Ordering::Relaxed)
    }

    /// Check if session is expired
    pub fn is_expired(&self, timeout: Duration) -> bool {
        self.last_activity.read().elapsed() > timeout
    }

    /// Elapsed time since the last authenticated inbound packet — the inbound-silence
    /// signal the liveness sweep evaluates (Phase 4 / P4.3).
    pub fn last_activity_elapsed(&self) -> Duration {
        self.last_activity.read().elapsed()
    }

    /// Current path-liveness thresholds (P4.3).
    pub fn liveness_config(&self) -> LivenessConfig {
        *self.liveness_config.read()
    }

    /// Override the path-liveness thresholds (P4.3). Rust-only test/advanced hook,
    /// mirroring [`set_rekey_threshold`](Self::set_rekey_threshold).
    pub fn set_liveness_config(&self, cfg: LivenessConfig) {
        *self.liveness_config.write() = cfg;
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
    /// On session drop, explicitly zero the master secrets. The
    /// `CryptoState` inside `crypto` is itself `ZeroizeOnDrop`, so its
    /// `session_key` is handled there.
    fn drop(&mut self) {
        // T5.1 — the rekey master (`traffic_secret`) seeds the HKDF ratchet for the
        // whole session; zero it on drop so it does not linger in freed memory
        // (rekey already zeroizes each *superseded* epoch secret; this covers the
        // final live one). The `CipherSuite`/`Instant`-free `[u8; 32]` is `Zeroize`.
        self.traffic_secret.write().zeroize();
        if let Some(mut secret) = self.resumption_secret.write().take() {
            secret.zeroize();
        }
    }
}
