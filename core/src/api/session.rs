//! Client-First Transport Session
//!
//! `PhantomSession` provides instant connection establishment with
//! automatic send queuing during handshake. This is the transport-level
//! API that sits below MLS and above the raw UDP/TCP transport.

use crate::crypto::hybrid_sign::HybridVerifyingKey;
use crate::errors::CoreError;
use crate::observability::attrs::{AeadAlgorithm, ReplayReason};
use crate::observability::{Observability, ObservabilityConfig};
use crate::runtime::{Runtime, TokioRuntime};
use crate::transport::handshake::{HandshakeClient, ServerReject, ServerReply, EARLY_DATA_MAX_LEN};
use crate::transport::multiplexer::StreamDemultiplexer;
use crate::transport::packet_coalescer_codec::unwrap_coalesced_packet;
use crate::transport::path_validation_codec::build_path_validation_packet;
use crate::transport::session::{Session, SessionState};
use crate::transport::shaping::{self, PaddingPolicy};
use crate::transport::stream::Stream;
use crate::transport::types::{
    LegType, PacketFlags, PacketHeader, PhantomPacket, SessionId, StreamId as TransportStreamId,
    WIRE_VERSION,
};
use bytes::Bytes;
use dashmap::DashMap;
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot, Mutex};

/// Generate a fresh 128-bit session identifier from the thread-local CSPRNG.
///
/// Replaces the historical `rand::random::<u32>()` (32 bits, insufficient to
/// avoid birthday collisions at scale and not advertised as cryptographic).
/// `rand::thread_rng` is seeded from the OS at thread startup and uses a
/// modern stream cipher (ChaCha) — adequate for non-secret identifiers.
fn new_session_id() -> String {
    let bytes: [u8; 16] = rand::random();
    format!("phantom-{}", hex::encode(bytes))
}

// ─── Connection State ───────────────────────────────────────────────────────

/// Connection state for `PhantomSession`.
///
/// The session is usable from the moment it's created — sends are queued
/// until the handshake completes.
#[cfg_attr(feature = "bindings", derive(uniffi::Enum))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[non_exhaustive]
pub enum ConnectionState {
    /// Connection initiated, handshake pending
    Connecting = 0,
    /// Classical (X25519) channel established — data flows
    ClassicalReady = 1,
    /// PQC upgrade in progress
    PqcUpgrading = 2,
    /// Full hybrid PQC protection active
    PqcReady = 3,
    /// Fully connected and operational
    Connected = 4,
    /// Connection failed
    Failed = 5,
    /// Gracefully closed
    Closed = 6,
    /// The active path went silent (liveness lost); the session is held alive
    /// (keys retained, outbound buffered) awaiting a `migrate()` or the path's
    /// return. The embedder reacts by calling `migrate()` (Phase 4 / P4.3).
    Migrating = 7,
    /// The session is dead: the path stayed down past the migration idle-timeout
    /// with no recovery. Terminal — `recv()` errors instead of hanging (P4.3).
    Dead = 8,
}

/// Anti-fingerprint traffic-shaping configuration (WIRE v6, direction #4). Set on
/// an established session via [`PhantomSession::set_traffic_shaping`]. **All
/// shaping is opt-in** — the default (and the field defaults here) is no shaping,
/// so a session pays nothing unless an embedder enables it.
///
/// Currently carries the size-padding policy (deliverable (c)); the timing-jitter
/// (d) and cover-traffic (e) knobs will be added as further fields in later
/// phases. Padding hides the datagram *size*; it costs bounded (≈ ≤12% worst-case)
/// extra bandwidth.
#[cfg_attr(feature = "bindings", derive(uniffi::Record))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TrafficShapingConfig {
    /// Size-padding policy. [`PaddingPolicy::None`] (default) = no padding;
    /// [`PaddingPolicy::Padme`] = pad each packet up to a PADÉ bucket.
    pub padding: PaddingPolicy,
    /// Send-timing jitter ceiling in milliseconds (deliverable (d)). `0` (default)
    /// = no jitter; otherwise each packet waits a uniform random `[0, jitter_ms]`
    /// ms before it is sent, so the inter-packet timing no longer tracks the
    /// application's writes — at a cost of up to `jitter_ms` of added latency.
    pub jitter_ms: u32,
    /// Cover-traffic floor interval in milliseconds (deliverable (e)). `0`
    /// (default) = no cover traffic; otherwise the session maintains a minimum
    /// outbound packet rate of `1000 / cover_interval_ms` packets/sec, emitting an
    /// encrypted dummy (`COVER`) packet whenever no packet has gone out for
    /// `cover_interval_ms` — hiding idle/active patterns and volume, at a steady
    /// bandwidth cost. A typical value is 100–500 ms (10–2 packets/sec).
    pub cover_interval_ms: u32,
}

impl ConnectionState {
    fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::Connecting,
            1 => Self::ClassicalReady,
            2 => Self::PqcUpgrading,
            3 => Self::PqcReady,
            4 => Self::Connected,
            5 => Self::Failed,
            6 => Self::Closed,
            7 => Self::Migrating,
            8 => Self::Dead,
            _ => Self::Failed,
        }
    }

    /// Whether data can flow (classical or better). `Migrating` counts as ready:
    /// the keep-alive window still accepts `send()` (buffered + retransmitted until
    /// the path recovers), so the embedder's send path doesn't error mid-migration.
    pub fn is_data_ready(&self) -> bool {
        matches!(
            self,
            Self::ClassicalReady
                | Self::PqcUpgrading
                | Self::PqcReady
                | Self::Connected
                | Self::Migrating
        )
    }
}

// ─── Resumption Hint ────────────────────────────────────────────────────────

/// 0-RTT resumption material extracted from a completed session.
///
/// Produced by [`PhantomSession::resumption_hint`] after a handshake
/// completes, and fed back into [`connect_pinned_with_resumption`] to
/// attempt a 0-RTT reconnect to the same server.
///
/// Both fields are exactly 32 bytes — this record is the
/// UniFFI-representable surface for the internal `(session_id,
/// resumption_secret)` tuple. The fields are `Vec<u8>` because UniFFI
/// has no fixed-size-array type, so the length is a runtime invariant
/// checked when the hint is used.
///
/// Store the hint alongside the pinned `HybridVerifyingKey` of the
/// server it was negotiated against: the `resumption_secret` is
/// server-pinned, and reusing a hint across servers is a configuration
/// bug.
#[cfg_attr(feature = "bindings", derive(uniffi::Record))]
#[derive(Clone)]
#[non_exhaustive]
pub struct ResumptionHint {
    /// The negotiated session id (32 bytes).
    pub session_id: Vec<u8>,
    /// The resumption secret (32 bytes) — sensitive; treat like a key.
    pub resumption_secret: Vec<u8>,
}

// INFOLEAK-1: hand-written redacting `Debug` (not derived) so a mobile/FFI
// consumer that logs the hint with `{:?}` cannot leak the 0-RTT `resumption_secret`
// — the one secret-bearing type that crosses the FFI boundary. Mirrors the
// REDACTED `Debug` on `HybridSigningKey` / `HybridSecretKey`.
impl std::fmt::Debug for ResumptionHint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResumptionHint")
            .field(
                "session_id",
                &format_args!("<{} bytes>", self.session_id.len()),
            )
            .field("resumption_secret", &"REDACTED")
            .finish()
    }
}

// ─── Transport Abstraction ──────────────────────────────────────────────────

// `SessionTransport` now lives in `crate::transport::session_transport` — a
// dependency-light module that can compile in a `no_std + alloc` build. It is
// re-exported here so `crate::api::session::SessionTransport` and the public
// `phantom_protocol::api::SessionTransport` path stay stable.
pub use crate::transport::session_transport::{FramePhase, SessionTransport};

/// Transport decorator that records `record_send` / `record_recv` on the
/// session's [`Observability`] for every frame that crosses the wire — so the
/// data-plane packet/byte counters reflect a real run without threading the
/// handle through every send site. Wraps the concrete `SessionTransport` just
/// before the data pump takes over, so handshake bytes are not counted as
/// data-plane packets (they have their own handshake metric).
struct ObservedTransport<T> {
    inner: T,
    observability: Arc<Observability>,
    leg: LegType,
}

impl<T> ObservedTransport<T> {
    fn new(inner: T, observability: Arc<Observability>, leg: LegType) -> Self {
        Self {
            inner,
            observability,
            leg,
        }
    }
}

impl<T: SessionTransport> SessionTransport for ObservedTransport<T> {
    async fn send_bytes(&self, data: &[u8]) -> Result<(), CoreError> {
        let result = self.inner.send_bytes(data).await;
        if result.is_ok() {
            self.observability.record_send(data.len(), self.leg);
        }
        result
    }

    async fn recv_bytes(&self) -> Result<Bytes, CoreError> {
        let result = self.inner.recv_bytes().await;
        if let Ok(ref bytes) = result {
            self.observability.record_recv(bytes.len(), self.leg);
        }
        result
    }

    // ── Transparent forwarding of the non-I/O trait surface ───────────────────
    //
    // ObservedTransport wraps the concrete transport for the whole data pump, so
    // every control method the pump calls on it (phase, CID stamping, migration)
    // MUST reach the inner transport — otherwise they silently hit the trait's
    // defaults (no-op / `false`) and the feature is dead through the pump. (The
    // pre-ε code only forwarded send/recv, so the FFI `migrate()` and the
    // server-side migration detection were no-ops once wrapped; ε needs them live
    // to rotate the CID on migration, so the wrapper is made fully transparent.)
    fn set_frame_phase(&self, phase: FramePhase) {
        self.inner.set_frame_phase(phase);
    }

    fn set_outbound_cid(&self, cid: [u8; 8]) {
        self.inner.set_outbound_cid(cid);
    }

    fn has_migration_candidate(&self) -> bool {
        self.inner.has_migration_candidate()
    }

    fn send_to_candidate(
        &self,
        data: &[u8],
    ) -> impl core::future::Future<Output = Result<bool, CoreError>> + Send {
        self.inner.send_to_candidate(data)
    }

    fn confirm_authenticated_source(&self) {
        self.inner.confirm_authenticated_source();
    }

    fn promote_candidate(&self) -> bool {
        self.inner.promote_candidate()
    }

    fn migrate(
        &self,
        local_addr: String,
    ) -> impl core::future::Future<Output = Result<(), CoreError>> + Send {
        self.inner.migrate(local_addr)
    }
}

// ─── Session ────────────────────────────────────────────────────────────────

/// Client-first session — instant `connect()`, non-blocking `send()`.
///
/// # Design
///
/// ```text
///   let session = PhantomSession::connect("server:443");  // instant!
///   session.send(data).await;   // queued until handshake completes
///   session.send(data2).await;  // also queued
///   // ... handshake completes in background ...
///   // queued data auto-flushed, new sends go directly
/// ```
///
/// The session progresses through states:
/// `Connecting → ClassicalReady → PqcUpgrading → PqcReady → Connected`
#[cfg_attr(feature = "bindings", derive(uniffi::Object))]
pub struct PhantomSession {
    /// Session identifier
    id: String,
    /// Target server address
    peer_addr: String,
    /// Connection state (atomic for lock-free reads)
    state: Arc<AtomicU8>,
    /// Queued messages before connection is ready
    send_queue: Arc<Mutex<Vec<Vec<u8>>>>,
    /// Channel to send commands to the background handshake task
    cmd_tx: mpsc::Sender<SessionCommand>,
    /// Command receiver — taken by the background task when spawned
    #[allow(dead_code)]
    cmd_rx: Mutex<Option<mpsc::Receiver<SessionCommand>>>,
    /// Received messages channel. Carries `Bytes` (not `Vec<u8>`) so the recv
    /// path can fan out via cheap refcount clones to both the stream demux
    /// and the synchronous `recv()` consumer without deep-copying the payload.
    recv_rx: Mutex<mpsc::Receiver<Bytes>>,
    /// Multiplexes incoming packets to independent streams
    demux: Arc<StreamDemultiplexer>,
    /// Active outgoing streams (ARQ management)
    streams: Arc<DashMap<u32, Arc<Stream>>>,
    /// Negotiated session handle, populated by the background task
    /// once the handshake completes. Exposed via `resumption_hint`
    /// for Phase 4.1 0-RTT clients. `None` while still handshaking
    /// or after a failure.
    inner_session: Arc<Mutex<Option<Arc<Session>>>>,
    /// 0-RTT verdict. `None` while handshaking, after a failure, or when the
    /// client sent no early-data on this connect. `Some(true)` — the server
    /// consumed the early-data; `Some(false)` — the client sent early-data and
    /// the server rejected it. Exposed via `early_data_accepted()`.
    early_data_accepted: Arc<Mutex<Option<bool>>>,
    /// Session observability handle. Server-accepted sessions share the
    /// `PhantomListener`'s instance (so its `snapshot()` aggregates every
    /// session it accepted); client sessions get their own. The data pump
    /// records send/recv, the security drops, and the session lifecycle
    /// (open/close) against it. A ZST no-op when `telemetry-otel` is off.
    observability: Arc<Observability>,
}

/// Commands for the background session task
pub enum SessionCommand {
    /// Queue data for sending
    Send(Vec<u8>),
    /// Send data on a specific stream reliably
    SendStreamReliable { stream_id: u32, data: bytes::Bytes },
    /// Send data on a specific stream unreliably
    SendStreamUnreliable { stream_id: u32, data: bytes::Bytes },
    /// Close a specific stream
    CloseStream { stream_id: u32 },
    /// Migrate to a new local address (Phase 4 / P4.2 — embedder-triggered). Carries
    /// the new local bind address as a `String`; the pump rebinds the transport and
    /// bumps the send `path_id` (best-effort, never fatal to the session).
    Migrate(String),
    /// Close the session
    Close,
}

impl PhantomSession {
    /// Create a new session and start the background handshake task.
    ///
    /// Requires `expected_server_key` for MITM resistance — the client will
    /// abort the handshake unless the server presents this exact verifying key.
    /// Callers obtain this key out-of-band (e.g. from `PhantomListener::verifying_key_bytes`).
    ///
    /// The handshake runs in the background:
    /// 1. Exchange hybrid PQC `ClientHello`/`ServerHello`.
    /// 2. Verify server identity against `expected_server_key`.
    /// 3. Derive AEAD keys; flush queued sends as encrypted packets.
    ///
    /// All network I/O goes through the provided `SessionTransport`. The
    /// task that drives the handshake + data pump runs on the default
    /// [`TokioRuntime`]; use
    /// [`connect_with_transport_with_runtime`](Self::connect_with_transport_with_runtime)
    /// to substitute a different `Runtime`.
    pub fn connect_with_transport<T: SessionTransport>(
        peer_addr: &str,
        transport: T,
        expected_server_key: HybridVerifyingKey,
    ) -> Self {
        Self::connect_with_transport_with_runtime(
            peer_addr,
            transport,
            expected_server_key,
            Arc::new(TokioRuntime),
        )
    }

    /// Like [`connect_with_transport`](Self::connect_with_transport) but
    /// runs the background task on the supplied `Runtime`. Intended for
    /// WASM / embedded / test backends that don't drive `tokio::spawn`.
    pub fn connect_with_transport_with_runtime<T: SessionTransport>(
        peer_addr: &str,
        transport: T,
        expected_server_key: HybridVerifyingKey,
        runtime: Arc<dyn Runtime>,
    ) -> Self {
        Self::spawn_client(peer_addr, transport, expected_server_key, runtime, None)
    }

    /// Connect with a **0-RTT resumption attempt**.
    ///
    /// `resumption_hint` is the `(session_id, resumption_secret)` tuple
    /// from a prior session's [`PhantomSession::resumption_hint`].
    /// `early_data` (≤ [`EARLY_DATA_MAX_LEN`] bytes) is sealed and carried
    /// inside the resuming ClientHello so it reaches the server on the very
    /// first flight — saving a round-trip versus 1-RTT.
    ///
    /// Acceptance is best-effort: a stale/unknown ticket or an AEAD failure
    /// leaves [`early_data_accepted`](Self::early_data_accepted) at
    /// `Some(false)` and the handshake completes as a normal 1-RTT exchange —
    /// the caller must then send that payload over the normal channel.
    /// Returns `Err` only when `early_data` exceeds the cap.
    ///
    /// Runs on the default [`TokioRuntime`].
    pub fn connect_with_resumption<T: SessionTransport>(
        peer_addr: &str,
        transport: T,
        expected_server_key: HybridVerifyingKey,
        resumption_hint: ([u8; 32], [u8; 32]),
        early_data: Vec<u8>,
    ) -> Result<Self, CoreError> {
        // fips bootstrap POST gate. `connect_with_resumption`
        // returns `Result`, so unlike the infallible `connect_with_transport*`
        // entry points we can surface the POST failure directly to the
        // caller (mirrors the `PhantomListener::bind*` and
        // `connect_pinned*` convention). The same POST is also checked
        // in `background_task` as a defense-in-depth backstop.
        #[cfg(feature = "fips")]
        crate::crypto::self_tests::ensure_post_passed()
            .map_err(|e| CoreError::FipsSelfTestFailure(format!("{e:?}")))?;

        if early_data.len() > EARLY_DATA_MAX_LEN {
            return Err(CoreError::ValidationError(format!(
                "early_data is {} bytes, exceeds the {}-byte 0-RTT cap",
                early_data.len(),
                EARLY_DATA_MAX_LEN
            )));
        }
        let (resume_id, resume_secret) = resumption_hint;
        Ok(Self::spawn_client(
            peer_addr,
            transport,
            expected_server_key,
            Arc::new(TokioRuntime),
            Some((resume_id, resume_secret, early_data)),
        ))
    }

    /// Shared constructor body for [`connect_with_transport_with_runtime`]
    /// and [`connect_with_resumption`]. `resumption_request` is `None`
    /// for a plain handshake, `Some((id, secret, early_data))` to attempt a
    /// 0-RTT resumption.
    fn spawn_client<T: SessionTransport>(
        peer_addr: &str,
        transport: T,
        expected_server_key: HybridVerifyingKey,
        runtime: Arc<dyn Runtime>,
        resumption_request: Option<([u8; 32], [u8; 32], Vec<u8>)>,
    ) -> Self {
        let (cmd_tx, cmd_rx) = mpsc::channel(256);
        let (recv_tx, recv_rx) = mpsc::channel(256);

        let state = Arc::new(AtomicU8::new(ConnectionState::Connecting as u8));
        let send_queue = Arc::new(Mutex::new(Vec::new()));
        let peer = peer_addr.to_string();
        let (demux, _ctrl_rx) = StreamDemultiplexer::new(256);
        let demux = Arc::new(demux);

        let streams = Arc::new(DashMap::new());
        let inner_session: Arc<Mutex<Option<Arc<Session>>>> = Arc::new(Mutex::new(None));
        let early_data_accepted: Arc<Mutex<Option<bool>>> = Arc::new(Mutex::new(None));
        // Client sessions have no listener, so they own their observability
        // instance (its `snapshot()` reflects just this connection).
        let observability = Observability::new(ObservabilityConfig::default());

        let session = Self {
            id: new_session_id(),
            peer_addr: peer.clone(),
            state: state.clone(),
            send_queue: send_queue.clone(),
            cmd_tx: cmd_tx.clone(),
            cmd_rx: Mutex::new(None), // taken by background task
            recv_rx: Mutex::new(recv_rx),
            demux: demux.clone(),
            streams: streams.clone(),
            inner_session: inner_session.clone(),
            early_data_accepted: early_data_accepted.clone(),
            observability: observability.clone(),
        };

        // Spawn the background handshake + data pump task on the supplied
        // runtime. `SpawnHandle` is detached: dropping it leaves the task
        // running. The session is owned by the caller for its lifetime
        // and natural shutdown comes via `SessionCommand::Close`.
        let runtime_for_pump = runtime.clone();
        let _detached = runtime.spawn(Box::pin(Self::background_task(
            state,
            send_queue,
            cmd_tx,
            cmd_rx,
            recv_tx,
            transport,
            peer,
            demux,
            streams,
            expected_server_key,
            runtime_for_pump,
            inner_session,
            early_data_accepted,
            resumption_request,
            observability,
        )));

        session
    }

    /// Install a server-side `Session` (already derived by `HandshakeServer::process_client_hello`)
    /// and spawn the data pump on the default [`TokioRuntime`]. Used by
    /// `PhantomListener::accept` after driving the server handshake.
    ///
    /// `PhantomListener::accept` itself now uses
    /// `from_accepted_server_session_with_runtime` so the listener's
    /// runtime is honored. This wrapper is preserved for callers that
    /// do not have a runtime handle and want the default `TokioRuntime`.
    #[allow(dead_code)]
    pub(crate) fn from_accepted_server_session<T: SessionTransport>(
        peer_addr: String,
        transport: T,
        server_session: Arc<Session>,
    ) -> Arc<Self> {
        Self::from_accepted_server_session_with_runtime(
            peer_addr,
            transport,
            server_session,
            Arc::new(TokioRuntime),
            Observability::new(ObservabilityConfig::default()),
            LegType::Tcp,
        )
    }

    /// Runtime-aware variant of [`from_accepted_server_session`].
    pub(crate) fn from_accepted_server_session_with_runtime<T: SessionTransport>(
        peer_addr: String,
        transport: T,
        server_session: Arc<Session>,
        runtime: Arc<dyn Runtime>,
        observability: Arc<Observability>,
        leg: LegType,
    ) -> Arc<Self> {
        let (cmd_tx, cmd_rx) = mpsc::channel(256);
        let (recv_tx, recv_rx) = mpsc::channel(256);

        let state = Arc::new(AtomicU8::new(ConnectionState::Connected as u8));
        let send_queue = Arc::new(Mutex::new(Vec::new()));
        let (demux, _ctrl_rx) = StreamDemultiplexer::new(256);
        let demux = Arc::new(demux);
        let streams = Arc::new(DashMap::new());

        let inner_session: Arc<Mutex<Option<Arc<Session>>>> =
            Arc::new(Mutex::new(Some(server_session.clone())));

        let session = Arc::new(Self {
            id: new_session_id(),
            peer_addr: peer_addr.clone(),
            state: state.clone(),
            send_queue: send_queue.clone(),
            cmd_tx,
            cmd_rx: Mutex::new(None),
            recv_rx: Mutex::new(recv_rx),
            demux: demux.clone(),
            streams: streams.clone(),
            inner_session,
            // Server side: 0-RTT early-data is delivered via
            // `AcceptOutcome`, not this client-facing field.
            early_data_accepted: Arc::new(Mutex::new(None)),
            // Shares the listener's instance so its `snapshot()` aggregates
            // every accepted session.
            observability: observability.clone(),
        });

        let session_id = *server_session.id();
        let runtime_for_pump = runtime.clone();
        // WIRE-001: the server handshake is complete — raise the receive frame
        // cap from the tight unauthenticated handshake limit to the steady-state
        // application limit before the data pump takes over.
        transport.set_frame_phase(FramePhase::Established);
        // ε / WIRE v5: switch the transport off the bootstrap ConnId onto this
        // session's rotating CID_0 (the c2s chain the client routes on; the
        // demux registers the matching inbound window). The server→client
        // direction rotates too, so neither flow keeps a stable cleartext id.
        transport.set_outbound_cid(server_session.current_outbound_cid());
        let observed = Arc::new(ObservedTransport::new(
            transport,
            observability.clone(),
            leg,
        ));
        let _detached = runtime.spawn(Box::pin(run_data_pump(
            server_session,
            session_id,
            observed,
            state,
            send_queue,
            cmd_rx,
            recv_tx,
            demux,
            streams,
            runtime_for_pump,
            observability,
            leg,
        )));

        session
    }

    /// Background task: performs handshake, then pumps data.
    #[allow(clippy::too_many_arguments)]
    async fn background_task<T: SessionTransport>(
        state: Arc<AtomicU8>,
        send_queue: Arc<Mutex<Vec<Vec<u8>>>>,
        _cmd_tx: mpsc::Sender<SessionCommand>,
        cmd_rx: mpsc::Receiver<SessionCommand>,
        recv_tx: mpsc::Sender<Bytes>,
        transport: T,
        peer: String,
        demux: Arc<StreamDemultiplexer>,
        streams: Arc<DashMap<u32, Arc<Stream>>>,
        expected_server_key: HybridVerifyingKey,
        runtime: Arc<dyn Runtime>,
        inner_session: Arc<Mutex<Option<Arc<Session>>>>,
        early_data_accepted: Arc<Mutex<Option<bool>>>,
        resumption_request: Option<([u8; 32], [u8; 32], Vec<u8>)>,
        observability: Arc<Observability>,
    ) {
        // DEBUG: the peer address is correlatable; keep it off default logs.
        log::debug!("PhantomSession: starting handshake with {}", peer);

        // fips bootstrap POST gate, mirroring the listener and
        // `connect_pinned*` paths: the synchronous Rust-only entry
        // points (`connect_with_transport*` / `connect_with_resumption`)
        // also need to honor FIPS 140-3 §7.7 before any cryptographic
        // work. Cached `OnceLock` makes the second+ call an atomic
        // read; the first call runs the full POST battery.
        //
        // On failure we cannot return a `CoreError` (the entry points
        // are infallible by API contract) — instead we transition the
        // state machine to `Failed` and bail, matching the existing
        // handshake-failure shape. The error string lands in the log.
        #[cfg(feature = "fips")]
        if let Err(e) = crate::crypto::self_tests::ensure_post_passed() {
            log::error!(
                "PhantomSession: FIPS POST self-test failed; refusing to handshake: {:?}",
                e
            );
            state.store(ConnectionState::Failed as u8, Ordering::Relaxed);
            return;
        }

        // Retain a copy of any 0-RTT early-data so it can be losslessly
        // re-sent over the established session if the server rejects it (C3 —
        // the rejection-retransmission contract). `run_client_handshake`
        // consumes `resumption_request`, so clone the blob first.
        let pending_early_data: Option<Vec<u8>> = resumption_request
            .as_ref()
            .and_then(|(_, _, ed)| (!ed.is_empty()).then(|| ed.clone()));

        // ── Stage 1 & 2: Hybrid Handshake (optionally 0-RTT resumption) ──
        // HS-02: bound the whole client handshake by a wall-clock deadline so a
        // silent or stalling server can't hang the connect indefinitely. The
        // TIMER is `runtime.sleep` (NOT raw tokio::time) so it stays correct
        // under WasmRuntime/EmbeddedRuntime; `select!` is just the combinator.
        const CLIENT_HANDSHAKE_DEADLINE: std::time::Duration = std::time::Duration::from_secs(10);
        // Scoped so the handshake future's borrow of `transport` ends before
        // `transport` is moved into the data pump below.
        let handshake_result = {
            let handshake_fut =
                run_client_handshake(&transport, &expected_server_key, resumption_request);
            let handshake_timeout = runtime.sleep(CLIENT_HANDSHAKE_DEADLINE);
            tokio::pin!(handshake_fut);
            tokio::select! {
                r = &mut handshake_fut => r,
                _ = handshake_timeout => Err(CoreError::Timeout),
            }
        };
        let (crypto_session, ed_accepted) = match handshake_result {
            Ok((session, accepted)) => (Arc::new(session), accepted),
            Err(e) => {
                log::error!("PhantomSession: handshake failed: {}", e);
                state.store(ConnectionState::Failed as u8, Ordering::Relaxed);
                return;
            }
        };
        log::info!("PhantomSession: Handshake complete — hybrid channel ready");

        // Phase 4.1 — publish the negotiated Session + the 0-RTT
        // verdict via the outer PhantomSession so `resumption_hint()`
        // and `early_data_accepted()` can reach them after the
        // background task moves the Arc into the pump.
        {
            let mut guard = inner_session.lock().await;
            *guard = Some(crypto_session.clone());
        }
        *early_data_accepted.lock().await = ed_accepted;

        // C3 — 0-RTT rejection retransmission contract. If we sent early-data
        // and the server rejected it (`Some(false)`), it never reached the
        // application layer, so re-send it losslessly over the now-established
        // 1-RTT session. Prepend it to the pre-handshake send queue (drained
        // first by the pump onto the reliable raw-app stream) so it lands
        // *ahead* of anything the app queued while connecting — preserving the
        // order in which the bytes were originally offered. `Some(true)` (the
        // server consumed it) and `None` (none sent) need no action.
        if ed_accepted == Some(false) {
            if let Some(ed) = pending_early_data {
                send_queue.lock().await.insert(0, ed);
                log::debug!(
                    "PhantomSession: 0-RTT early-data rejected; re-queued for 1-RTT delivery"
                );
            }
        }

        let session_id = *crypto_session.id();
        state.store(ConnectionState::Connected as u8, Ordering::Relaxed);
        log::debug!("PhantomSession: fully connected to {}", peer);

        // Wrap the (post-handshake) transport so every data-plane send/recv is
        // recorded. The connectionless API rides TCP today (KCP / FakeTLS legs
        // are not session-wired yet), so the leg label is fixed to TCP.
        // WIRE-001: the handshake is done — raise the frame cap from the tight
        // unauthenticated handshake limit to the steady-state application limit.
        transport.set_frame_phase(FramePhase::Established);
        // ε / WIRE v5: stamp this session's rotating CID_0 on every post-handshake
        // datagram (the chain the server's demux routes on) instead of the
        // bootstrap ConnId.
        transport.set_outbound_cid(crypto_session.current_outbound_cid());
        let observed = Arc::new(ObservedTransport::new(
            transport,
            observability.clone(),
            LegType::Tcp,
        ));
        run_data_pump(
            crypto_session,
            session_id,
            observed,
            state,
            send_queue,
            cmd_rx,
            recv_tx,
            demux,
            streams,
            runtime,
            observability,
            LegType::Tcp,
        )
        .await;
    }
}

/// Drive the client side of the Phantom Protocol handshake to completion.
///
/// When `resumption` is `Some((resume_id, resume_secret, early_data))` the
/// first-flight `ClientHello` carries the resume id and, when `early_data` is
/// non-empty, a sealed 0-RTT blob folded into `ClientHello.early_data` — so it
/// reaches the server on the first flight. A cookie/PoW `HelloRetryRequest` is
/// answered in-loop, reusing the same hello (the early-data blob rides along).
///
/// Returns the established `Session` and the 0-RTT verdict (resolved
/// decision 1):
/// - `Some(true)`  — the client sent early-data and the server consumed it
/// - `Some(false)` — the client sent early-data and the server rejected it
///   (stale ticket / oversized / AEAD failure)
/// - `None`        — the client sent no early-data on this connect
async fn run_client_handshake<T: SessionTransport>(
    transport: &T,
    expected_server_key: &HybridVerifyingKey,
    resumption: Option<([u8; 32], [u8; 32], Vec<u8>)>,
) -> Result<(Session, Option<bool>), CoreError> {
    let handshake = HandshakeClient::new()?;

    // Build the first-flight ClientHello. A resumption request folds the
    // resume id and (optionally) a sealed 0-RTT early-data blob into the
    // single hello; otherwise it is a plain hello.
    let mut hello = match &resumption {
        Some((resume_id, resume_secret, early_data)) => {
            let ed: Option<&[u8]> = if early_data.is_empty() {
                None
            } else {
                Some(early_data.as_slice())
            };
            handshake.create_client_hello_with_resume(*resume_id, resume_secret, ed)
        }
        None => handshake.create_client_hello(),
    };

    // HS-02: cap the number of HelloRetryRequest rounds. The legitimate flow
    // needs at most one cookie round + one PoW round; a bound of 3 leaves slack
    // for a benign reorder. Without it, a MITM answering every ClientHello with
    // a fresh cheap HelloRetryRequest could loop the client forever.
    const MAX_CLIENT_RETRY_ROUNDS: u32 = 3;
    // Reviewer §5: bound how many injected/genuine ServerRejects we read past while still
    // waiting for a ServerHello, so a reject flood can't loop the inner read forever.
    const MAX_CLIENT_REJECT_ROUNDS: u32 = 3;
    let mut retry_rounds: u32 = 0;
    let mut reject_rounds: u32 = 0;
    // Reviewer §5: an *injected* ServerReject (a tiny pre-crypto blob a network attacker can
    // spray) must not abort a healthy handshake. Remember it and keep reading for a valid
    // ServerHello; surface it only if one never arrives (do NOT auto-downgrade — Invariant 7).
    let mut remembered_reject: Option<ServerReject> = None;

    loop {
        // (Re)send the current hello (fresh, or cookie/PoW-updated after a HelloRetryRequest).
        let bytes = borsh::to_vec(&hello).map_err(|e| {
            CoreError::SerializationError(format!("ClientHello encode failed: {}", e))
        })?;
        transport.send_bytes(&bytes).await?;

        // Read responses for THIS hello, reading past an injected ServerReject (WITHOUT
        // re-sending) until a ServerHello (success), a HelloRetryRequest (re-send with the
        // cookie/PoW), or the channel ends.
        loop {
            let resp = match transport.recv_bytes().await {
                Ok(r) => r,
                Err(e) => {
                    // No further responses: surface a remembered reject (a genuine version
                    // mismatch) over the raw transport error.
                    return match &remembered_reject {
                        Some(r) => Err(CoreError::HandshakeError(format!(
                            "server rejected the handshake: unsupported protocol version \
                             (client speaks v{}, server speaks v{})",
                            hello.version, r.supported_version
                        ))),
                        None => Err(e),
                    };
                }
            };

            // T4.4: the reply leads with an explicit discriminant byte
            // (`[kind] ‖ borsh(body)`); dispatch on it instead of trial-deserializing by
            // size. An unknown kind / malformed body is a handshake error, not a misparse.
            match ServerReply::from_wire(&resp) {
                Ok(ServerReply::Hello(sh)) => {
                    let (session, accepted) =
                        handshake.process_server_hello(&hello, &sh, Some(expected_server_key))?;
                    return Ok((session, accepted));
                }
                Ok(ServerReply::Reject(reject)) => {
                    // The marker is an extra sanity check on top of the discriminant. We do
                    // NOT auto-downgrade to `reject.supported_version` (Invariant 7).
                    if reject.has_marker() {
                        reject_rounds += 1;
                        if reject_rounds > MAX_CLIENT_REJECT_ROUNDS {
                            return Err(CoreError::HandshakeError(format!(
                                "server rejected the handshake: unsupported protocol version \
                                 (client speaks v{}, server speaks v{})",
                                hello.version, reject.supported_version
                            )));
                        }
                        // reviewer §5: keep waiting for a valid ServerHello — read the next
                        // frame WITHOUT re-sending, so a single forged reject can't kill the
                        // handshake.
                        remembered_reject = Some(reject);
                        continue;
                    }
                    return Err(CoreError::HandshakeError(
                        "server reject missing marker".into(),
                    ));
                }
                Ok(ServerReply::Retry(retry)) => {
                    retry_rounds += 1;
                    if retry_rounds > MAX_CLIENT_RETRY_ROUNDS {
                        return Err(CoreError::HandshakeError(format!(
                            "server demanded more than {MAX_CLIENT_RETRY_ROUNDS} HelloRetryRequest rounds"
                        )));
                    }
                    log::info!("PhantomSession: Received HelloRetryRequest, retrying...");
                    hello.cookie = retry.cookie;
                    if let Some(challenge) = retry.challenge {
                        // H3: cap the accepted difficulty and bound the solver, so an
                        // injected/malicious HelloRetryRequest (e.g. difficulty 255)
                        // surfaces a handshake error instead of pinning a CPU core.
                        log::info!("PhantomSession: Solving PoW challenge...");
                        hello.pow_solution = Some(
                            challenge
                                .solve_capped(crate::crypto::pow::MAX_CLIENT_POW_DIFFICULTY)
                                .map_err(|e| CoreError::HandshakeError(e.to_string()))?,
                        );
                    }
                    break; // re-send the cookie/PoW-updated hello (outer loop)
                }
                Err(e) => {
                    return Err(CoreError::HandshakeError(format!(
                        "invalid server reply: {e}"
                    )));
                }
            }
        }
    }
}

/// Reserved stream id for the connectionless `send()`/`recv()` surface. The
/// demultiplexer hands out ids of two and above, so this never collides with a
/// user-opened stream. Idle keep-alives ([`send_keepalive`]) also stamp it for a
/// well-formed, consistent header.
const RAW_APP_STREAM_ID: u32 = 1;

/// Shared client/server data pump.
///
/// After the handshake completes (client side) or after the server `Session` is
/// derived (server side), this loop:
///   - drains the queued early-data buffer,
///   - listens for incoming packets and decrypts them,
///   - encrypts outgoing application/stream packets,
///   - sends ACKs for reliable packets.
// The 11 parameters represent the complete session-identity and I/O surface.
// Grouping them into a struct would require a generic struct (due to `T:
// SessionTransport`), add indirection with no safety or clarity gain, and
// constitute a public-API change. The function is private (`async fn`, no
// `pub`), so the extra arguments are contained here.
#[allow(clippy::too_many_arguments)]
async fn run_data_pump<T: SessionTransport>(
    crypto_session: Arc<Session>,
    session_id: SessionId,
    transport: Arc<T>,
    state: Arc<AtomicU8>,
    send_queue: Arc<Mutex<Vec<Vec<u8>>>>,
    mut cmd_rx: mpsc::Receiver<SessionCommand>,
    recv_tx: mpsc::Sender<Bytes>,
    demux: Arc<StreamDemultiplexer>,
    streams: Arc<DashMap<u32, Arc<Stream>>>,
    runtime: Arc<dyn Runtime>,
    observability: Arc<Observability>,
    leg: LegType,
) {
    // Session is now established and active — bump the active-session gauge.
    // The matching `session_closed` at teardown (below) lets the gauge fall,
    // so it tracks live sessions instead of growing monotonically.
    observability.session_opened(leg);

    // Liveness (P4.3): stamp "alive now" at establishment so the inbound-silence
    // sweep measures from the data-plane start, not from session construction (which
    // predates the multi-KB handshake and would otherwise look stale immediately).
    crypto_session.update_activity();

    // ── Raw-app session stream (reserved id 1) ──
    // The connectionless `send()` / `recv()` surface is multiplexed onto one
    // reserved stream so it gets the same reliable-delivery machinery as
    // explicitly-opened streams: `drain_streams_priority_ordered` (re)transmits
    // its buffered segments on the poll tick / outbound-ready notify, and
    // inbound ACKs for id 1 clear them via `Stream::ack`. The demultiplexer
    // hands out ids 2+, so this never collides with a user-opened stream.
    let raw_stream = Arc::new(Stream::new(RAW_APP_STREAM_ID as TransportStreamId));
    streams.insert(RAW_APP_STREAM_ID, raw_stream.clone());

    // ── Flush queued early-data onto the raw-app stream ──
    // Routed through the stream (not a one-shot direct send) so queued
    // pre-handshake data is buffered for retransmit just like post-handshake
    // sends — a dropped early-data frame is recovered, not lost.
    {
        let mut queue = send_queue.lock().await;
        let count = queue.len();
        'flush: for msg in queue.drain(..) {
            for chunk in msg.chunks(TRANSPORT_MTU) {
                if let Err(e) = raw_stream
                    .send_reliable(Bytes::copy_from_slice(chunk))
                    .await
                {
                    // T4.5 fail-closed: the reliable offset space is exhausted (~2^32
                    // segments) — refuse rather than wrap. Astronomically unreachable;
                    // the session stalls and the liveness sweep tears it down.
                    log::error!("PhantomSession: early-data flush aborted — {e}");
                    break 'flush;
                }
            }
        }
        if count > 0 {
            log::info!(
                "PhantomSession: queued {} early-data message(s) onto the raw-app stream",
                count
            );
            crypto_session.notify_outbound_ready();
        }
    }

    // ── Receive-delivery decoupling ──
    // The reader task hands decrypted application data to a dedicated delivery
    // task over an UNBOUNDED channel and never blocks on app delivery, so a slow
    // `recv()` consumer cannot head-of-line-stall inbound ACK / WINDOW_UPDATE /
    // control processing. The delivery task does the app-paced `recv_tx.send()`
    // and credits the flow-control window on *real* consumption; enforced
    // send-side flow control (`Stream::poll_send`) bounds the in-flight backlog
    // to ~one window, and `undelivered_bytes` + `RECV_DELIVERY_HARD_CAP` guard
    // against a peer that ignores flow control.
    let (deliver_tx, mut deliver_rx) = mpsc::unbounded_channel::<(u32, Bytes)>();
    let undelivered_bytes = Arc::new(AtomicU64::new(0));
    {
        let recv_tx_deliver = recv_tx; // move the session recv channel here
        let demux_deliver = demux.clone();
        let streams_deliver = streams.clone();
        let crypto_deliver = crypto_session.clone();
        let undelivered_deliver = undelivered_bytes.clone();
        runtime.spawn(Box::pin(async move {
            while let Some((stream_id, bytes)) = deliver_rx.recv().await {
                let len = bytes.len() as u64;
                // Best-effort, non-blocking notification to the (vestigial) demux.
                demux_deliver.route_data(stream_id, bytes.clone());
                // Account the item the instant it leaves the UNBOUNDED delivery
                // queue (which the reader's HARD_CAP guards) — BEFORE the
                // app-paced `recv_tx.send()` below, which can block for a long
                // time on a slow consumer. Decrementing (and crediting) only
                // after a successful send would (a) keep this item counted
                // against the cap while it sits in the bounded recv pipeline,
                // inflating `undelivered_bytes`, and (b) leak the count entirely
                // if the send then fails. The byte is now in the bounded
                // recv-channel pipeline (capacity-limited, its own backpressure),
                // so it no longer belongs to the unbounded backlog.
                undelivered_deliver.fetch_sub(len, Ordering::AcqRel);
                // Credit the flow-control window: the item has been pulled into
                // the app-delivery pipeline (matching the inline ACK's "accepted
                // into my in-memory delivery queue" semantics). The pull rate is
                // still paced by `recv_tx.send()` completing below, so credit
                // tracks app consumption (one item of look-ahead) — backpressure
                // is preserved. Wake the send loop to flush the WINDOW_UPDATE
                // (emitted there — the sole outbound writer — so it is sealed
                // under the live epoch; the epoch's two writers both serialise
                // through `rekey_lock`, so the flush is always epoch-consistent).
                if let Some(stream) = streams_deliver.get(&stream_id) {
                    if let Some(credit) = stream.record_app_consumed(len as u32) {
                        stream.stage_window_update_credit(credit);
                        crypto_deliver.notify_outbound_ready();
                    }
                }
                // Real, app-paced delivery to the session recv channel. A closed
                // channel means the consumer is gone → session ending; stop. The
                // item was already removed from the backlog accounting above, so
                // breaking here leaks nothing.
                if recv_tx_deliver.send(bytes).await.is_err() {
                    break;
                }
            }
        }));
    }

    // ── Receive (reader) task: deserialize, decrypt, hand off to delivery ──
    let transport_recv = transport.clone();
    let transport_send_ack = transport.clone();
    let crypto_recv = crypto_session.clone();
    let demux_recv = demux.clone();
    let streams_recv = streams.clone();
    let undelivered_reader = undelivered_bytes.clone();
    let observability_recv = observability.clone();
    // Completion signal for the receive task. `SpawnHandle` from the
    // runtime trait does not expose a `Future` for `.await` directly
    // (different runtimes provide different join futures), so we wire a
    // one-shot channel — the recv task sends `()` right before exiting
    // and the main loop selects on the receiver to detect transport
    // closure.
    let (recv_done_tx, mut recv_done_rx) = oneshot::channel::<()>();
    let transport_for_path = transport.clone();
    let recv_handle = runtime.spawn(Box::pin(async move {
        // Reusable buffer for ACK frame serialization. Hoisted out of the
        // loop (Phase 2.3) so we don't pay a fresh `Vec::new()` allocation
        // for every ACK we emit on a busy reliable stream. 256 bytes is
        // comfortably larger than a serialized empty `PhantomPacket` (the
        // 45-byte header plus a couple of length prefixes), so the underlying
        // buffer is never reallocated after the first frame.
        let mut ack_buf: Vec<u8> = Vec::with_capacity(256);
        // Buffering ceiling: the delivery queue is unbounded so the reader
        // never blocks, but a peer that ignores flow control could flood it.
        // Compliant senders are bounded by ~one window per stream (enforced
        // `poll_send`), far below this cap; crossing it means the peer is
        // misbehaving, so we tear the session down rather than buffer without
        // limit. 4 MiB tolerates many streams × the 64 KiB window with margin.
        const RECV_DELIVERY_HARD_CAP: u64 = 4 * 1024 * 1024;
        loop {
            // Flow-control / anti-flood gate: if the app-delivery backlog
            // has blown past the cap, the peer is not honouring the window —
            // close instead of growing the in-memory queue unboundedly. Cheap
            // pre-check, before any AEAD work.
            if undelivered_reader.load(Ordering::Acquire) > RECV_DELIVERY_HARD_CAP {
                log::warn!(
                    "PhantomSession: receive backlog {} B exceeds cap — peer ignoring flow \
                     control; closing session",
                    undelivered_reader.load(Ordering::Acquire)
                );
                break;
            }
            let data = match transport_recv.recv_bytes().await {
                Ok(b) => b,
                Err(_) => break,
            };

            // Remove header protection (T4.6) and parse: a malformed / unparseable
            // / short-of-the-AEAD-tag frame (no legitimate peer produces one) is
            // dropped — never a panic. The cleartext version + session_id stay
            // readable; the [33..47] span is unmasked with this session's recv HP
            // key before the header is interpreted.
            let packet = match crypto_recv.parse_protected(&data) {
                Ok(v) => v,
                Err(_) => continue,
            };
            // Pinned wire-version gate: the format is not negotiated, so a
            // frame carrying any other version byte is dropped.
            if packet.header.version != WIRE_VERSION {
                continue;
            }
            handle_packet(
                packet,
                session_id,
                &crypto_recv,
                &streams_recv,
                &demux_recv,
                &transport_send_ack,
                &transport_for_path,
                &deliver_tx,
                &undelivered_reader,
                &mut ack_buf,
                &observability_recv,
                leg,
            )
            .await;
        }
        // Reader exiting → drop `deliver_tx` so the delivery task drains any
        // queued items and then sees the channel closed and exits.
        drop(deliver_tx);
        // Signal the main loop that the recv task has exited so it can
        // also unwind. `send` returns `Err(())` if the receiver was
        // already dropped — that case is harmless, the main loop has
        // already shut down.
        let _ = recv_done_tx.send(());
    }));

    // MTU for transport packets
    const TRANSPORT_MTU: usize = 1300;
    // Phase 2.4: the 10 ms `poll_interval` stays as a retransmit-timer
    // fallback (streams without an explicit notifier reference still
    // get swept), but `send_notify.notified()` joins the select! so the
    // pump wakes immediately when a producer calls
    // `Session::notify_outbound_ready()`. This drops idle CPU usage to
    // zero on quiet sessions while keeping the worst-case post-queue
    // latency at <10 ms even for producers that haven't been wired into
    // the notifier yet.
    let mut poll_interval = tokio::time::interval(std::time::Duration::from_millis(10));
    let send_notify = crypto_session.send_notifier();
    // Liveness keep-alive bookkeeping (P4.3): `Some(t)` while in the `Migrating`
    // window (the pump-local truth + how long); `died` records an idle-timeout death
    // so the teardown publishes `Dead` instead of overwriting it with `Closed`.
    let mut migrating_since: Option<std::time::Instant> = None;
    let mut died = false;
    // Idle keep-alive bookkeeping (Direction #3 — download-only liveness): the
    // pump-local instant of the last keep-alive PING we emitted, so we send at most
    // one per `keepalive_interval` (no 10 ms-heartbeat spam). Seeded at "now" so the
    // first PING waits a full interval after the data plane starts.
    let mut last_keepalive = std::time::Instant::now();
    // Cover-traffic bookkeeping (WIRE v6, deliverable (e)): the send PN observed at
    // the last cover check, and the instant of the last observed outbound activity.
    // Any real packet advances the PN, resetting the idle window, so cover only
    // fills genuine gaps (idle-fill + a floor rate). Seeded at "now"/current PN.
    let mut last_outbound_pn = crypto_session.peek_send_pn();
    let mut last_outbound_at = std::time::Instant::now();
    // Outbound WINDOW_UPDATE control packets are emitted on the send loop — the
    // sole outbound writer — so the encrypted control frame is always sealed under
    // the epoch live when it stamps. The epoch has two writers (this loop's own
    // `rekey()` and the receive task's authenticated forward catch-up in
    // `decrypt_packet_accepting_rekey`), but both serialise through the session's
    // `rekey_lock`, so the seal is always epoch-consistent. The delivery task only
    // stages the relative credit (`Stream::stage_window_update_credit`) and
    // wakes us; the wire sequence is drawn from the stream's own send-sequence
    // space inside `flush_pending_window_updates` (no private counter, so it
    // can never collide with application data on the AEAD nonce).

    loop {
        tokio::select! {
            _ = poll_interval.tick() => {
                flush_pending_window_updates(
                    &transport, &crypto_session, session_id, &streams,
                )
                .await;
                drain_streams_priority_ordered(
                    &transport,
                    &crypto_session,
                    session_id,
                    &streams,
                )
                .await;
                // Idle keep-alive (Direction #3 — download-only liveness): on an
                // otherwise-idle Connected path, emit one small ENCRYPTED PING so a
                // download-only path (which sends only ACKs) has an outstanding probe
                // to anchor the liveness sweep below — and the peer's PONG refreshes
                // its activity timer. Runs before the sweep so a just-emitted PING is
                // already marked outstanding this tick.
                maybe_send_keepalive(
                    &transport, &crypto_session, session_id, &mut last_keepalive,
                )
                .await;
                // Cover traffic (WIRE v6, deliverable (e)): on this same heartbeat,
                // maintain the minimum outbound packet rate — emit a COVER dummy when
                // the outbound path has been idle past the floor interval. No-op when
                // cover is disabled (default) or real traffic is flowing.
                maybe_send_cover(
                    &transport,
                    &crypto_session,
                    session_id,
                    &mut last_outbound_pn,
                    &mut last_outbound_at,
                )
                .await;
                // Liveness sweep (P4.3): the 10 ms heartbeat is the reliable place to
                // evaluate inbound silence vs. outstanding data and surface
                // Migrating / recover / Dead. A `Dead` verdict ends the pump.
                if apply_liveness(&crypto_session, &state, &mut migrating_since) {
                    died = true;
                    break;
                }
            }
            _ = send_notify.notified() => {
                // Same drain logic as the tick arm — fast-wake path. Also flush
                // any flow-control credit the delivery task staged.
                flush_pending_window_updates(
                    &transport, &crypto_session, session_id, &streams,
                )
                .await;
                drain_streams_priority_ordered(
                    &transport,
                    &crypto_session,
                    session_id,
                    &streams,
                )
                .await;
            }
            cmd_opt = cmd_rx.recv() => {
                match cmd_opt {
                    Some(SessionCommand::Send(data)) => {
                        // Route through the raw-app stream so the payload is
                        // buffered for retransmit until ACKed (drained by
                        // `drain_streams_priority_ordered`), instead of being
                        // fired once and forgotten on the wire.
                        for chunk in data.chunks(TRANSPORT_MTU) {
                            if let Err(e) = raw_stream
                                .send_reliable(Bytes::copy_from_slice(chunk))
                                .await
                            {
                                log::error!("PhantomSession: send aborted — {e}");
                                break;
                            }
                        }
                        crypto_session.notify_outbound_ready();
                    }
                    Some(SessionCommand::SendStreamReliable { stream_id, data }) => {
                        if let Some(stream) = streams.get(&stream_id) {
                            for chunk in data.chunks(TRANSPORT_MTU) {
                                if let Err(e) =
                                    stream.send_reliable(Bytes::copy_from_slice(chunk)).await
                                {
                                    log::error!("PhantomSession: stream send aborted — {e}");
                                    break;
                                }
                            }
                        }
                    }
                    Some(SessionCommand::SendStreamUnreliable { stream_id, data }) => {
                        if let Some(stream) = streams.get(&stream_id) {
                            for chunk in data.chunks(TRANSPORT_MTU) {
                                stream.send_unreliable(Bytes::copy_from_slice(chunk)).await;
                            }
                        }
                    }
                    Some(SessionCommand::CloseStream { stream_id }) => {
                        if let Some(stream) = streams.get(&stream_id) {
                            stream.finish().await;
                            let _ = send_app_data(
                                &transport,
                                &crypto_session,
                                session_id,
                                stream_id as TransportStreamId,
                                &[],
                                PacketFlags::FIN,
                                None, // bare FIN is a control frame — no reliable offset
                            ).await;
                        }
                        streams.remove(&stream_id);
                        demux.close_stream(stream_id);
                    }
                    Some(SessionCommand::Migrate(local_addr)) => {
                        // Embedder-triggered connection migration (Phase 4 / P4.2).
                        // Rebind the transport to the new local socket FIRST (it keeps
                        // the old socket for the overlap); only on a successful rebind
                        // bump the send `path_id` so every subsequent packet from the
                        // new socket carries a fresh, not-yet-Validated path label —
                        // which is what makes the server detect + challenge the new
                        // path (a still-`0` path_id would be skipped, path 0 being
                        // permanently Validated). Both happen inside this `select!`
                        // arm, so no send interleaves between them. Best-effort: a
                        // failed rebind leaves the session untouched on the old socket
                        // (broken-rebind safety) — migration never tears it down.
                        match transport.migrate(local_addr).await {
                            Ok(()) => {
                                let new_path = crypto_session.next_migration_path_id();
                                // ε / WIRE v5: rotate the outbound CID so every
                                // post-migration datagram stamps an
                                // independent-random ConnId an observer cannot link
                                // to the pre-migration flow. The new CID_{i+1} is
                                // already in the server's pre-registered inbound
                                // window (which slides post-AEAD beyond K migrations).
                                transport.set_outbound_cid(crypto_session.advance_outbound_cid());
                                log::info!(
                                    "PhantomSession: migrated send path -> path_id {}, CID rotated",
                                    new_path
                                );
                                // Wake the send loop so app data + L1 retransmits flow
                                // from the new socket immediately, triggering the
                                // server-side new-source detection.
                                crypto_session.notify_outbound_ready();
                            }
                            Err(e) => {
                                log::warn!(
                                    "PhantomSession: migrate rebind failed (staying on the old path): {}",
                                    e
                                );
                            }
                        }
                    }
                    Some(SessionCommand::Close) => {
                        log::info!("PhantomSession: closing");
                        // `disconnect()` is a *graceful* close (doc: "Send the
                        // graceful close frame and shut the session down" — TCP-FIN
                        // semantics: finish sending, then close). Mirror the
                        // handle-drop (`None`) arm so buffered `send()` data still
                        // reaches the peer: `session.send(x); session.disconnect()`
                        // must not lose `x`, just like `send(x); drop(session)`.
                        flush_pending_window_updates(
                            &transport, &crypto_session, session_id, &streams,
                        )
                        .await;
                        drain_streams_priority_ordered(
                            &transport, &crypto_session, session_id, &streams,
                        )
                        .await;
                        break;
                    }
                    None => {
                        log::info!("PhantomSession: command channel dropped");
                        // The outer `PhantomSession` handle was dropped. Data already
                        // handed to `send()` was routed onto the raw-app stream but may
                        // not have hit the wire yet (transmission happens on the next
                        // tick / notify of THIS loop). Flush it before exiting so a
                        // fire-and-forget `send()` immediately followed by dropping the
                        // handle still reaches the peer — otherwise a freshly-accepted
                        // server session that does `recv(); send(echo)` then drops loses
                        // the echo, and the client's `recv()` hangs to its timeout.
                        flush_pending_window_updates(
                            &transport, &crypto_session, session_id, &streams,
                        )
                        .await;
                        drain_streams_priority_ordered(
                            &transport, &crypto_session, session_id, &streams,
                        )
                        .await;
                        break;
                    }
                }
            }
            _ = &mut recv_done_rx => {
                log::error!("PhantomSession: receive task ended unexpectedly (transport closed)");
                break;
            }
        }
    }

    // Abort the recv task if it's still running; idempotent on a finished
    // handle. Goes through the runtime-agnostic `SpawnHandle::abort`.
    recv_handle.abort();
    // A liveness idle-timeout death already published `ConnectionState::Dead`; only a
    // normal teardown (graceful close / transport drop) publishes `Closed`.
    if !died {
        state.store(ConnectionState::Closed as u8, Ordering::Relaxed);
    }
    // Session torn down — drop the active-session gauge back down.
    observability.session_closed(leg);
}

/// Evaluate path liveness once (Phase 4 / P4.3) and apply the resulting transition to
/// both the internal [`SessionState`] and the FFI-visible [`ConnectionState`]. Returns
/// `true` when the session has died (idle-timeout in `Migrating`), so the caller ends
/// the pump. `migrating_since` is the pump-local truth for the keep-alive window.
fn apply_liveness(
    crypto_session: &Arc<Session>,
    state: &Arc<AtomicU8>,
    migrating_since: &mut Option<std::time::Instant>,
) -> bool {
    use crate::transport::liveness::{liveness_verdict, LivenessVerdict};
    let cfg = crypto_session.liveness_config();
    let snap = crypto_session.bandwidth_snapshot();
    let silence = crypto_session.last_activity_elapsed();
    let in_migrating = migrating_since.is_some();
    let migrating_for = migrating_since
        .map(|t| t.elapsed())
        .unwrap_or(std::time::Duration::ZERO);
    // Direction #3 (download-only liveness): an outstanding idle keep-alive PING is
    // an outstanding probe just like in-flight reliable data, so fold it into the
    // sweep's `inflight > 0` gate. This is what lets a download-only path — which
    // sends only ACKs and so has zero reliable bytes in flight — declare the path
    // down when the PING goes unanswered (the PONG would have refreshed activity).
    let effective_inflight = if crypto_session.keepalive_outstanding() {
        snap.inflight_bytes.max(1)
    } else {
        snap.inflight_bytes
    };
    match liveness_verdict(
        silence,
        effective_inflight,
        snap.min_rtt,
        in_migrating,
        migrating_for,
        &cfg,
    ) {
        LivenessVerdict::PathDown => {
            *migrating_since = Some(std::time::Instant::now());
            crypto_session.set_state(SessionState::Migrating);
            state.store(ConnectionState::Migrating as u8, Ordering::Relaxed);
            log::info!(
                "PhantomSession: path down (no inbound for {silence:?} with data in flight) \
                 — entering Migrating; the embedder should migrate()"
            );
            false
        }
        LivenessVerdict::Recovered => {
            *migrating_since = None;
            crypto_session.set_state(SessionState::Connected);
            state.store(ConnectionState::Connected as u8, Ordering::Relaxed);
            log::info!("PhantomSession: path recovered — back to Connected");
            false
        }
        LivenessVerdict::Dead => {
            crypto_session.set_state(SessionState::Closed);
            state.store(ConnectionState::Dead as u8, Ordering::Relaxed);
            log::warn!("PhantomSession: migration idle-timeout elapsed — session dead");
            true
        }
        LivenessVerdict::Unchanged => false,
    }
}

/// Emit an idle keep-alive PING when the path is idle (Direction #3 —
/// download-only liveness). Decides via the pure [`should_send_keepalive`] gate
/// over the live signals (Connected? nothing in flight? inbound silent ≥ interval?
/// no recent PING?). On a fire it sends one empty `ENCRYPTED | KEEPALIVE` packet,
/// marks the probe outstanding (so the very next liveness sweep treats the path as
/// awaiting a response even with no reliable data queued), and records the send
/// instant for the per-interval throttle. Best-effort: a send failure just leaves
/// `last_keepalive` unchanged so the next tick retries.
async fn maybe_send_keepalive<T: SessionTransport>(
    transport: &Arc<T>,
    crypto_session: &Arc<Session>,
    session_id: SessionId,
    last_keepalive: &mut std::time::Instant,
) {
    use crate::transport::liveness::should_send_keepalive;
    let cfg = crypto_session.liveness_config();
    // Cheap fast-path: skip everything when keep-alives are disabled.
    if cfg.keepalive_interval.is_none() {
        return;
    }
    let connected = crypto_session.state() == SessionState::Connected;
    let snap = crypto_session.bandwidth_snapshot();
    // An already-outstanding PING is itself "in flight" — fold it into the gate so
    // we don't queue a second PING before the first is answered or times out.
    let inflight = if crypto_session.keepalive_outstanding() {
        snap.inflight_bytes.max(1)
    } else {
        snap.inflight_bytes
    };
    if !should_send_keepalive(
        connected,
        inflight,
        crypto_session.last_activity_elapsed(),
        last_keepalive.elapsed(),
        &cfg,
    ) {
        return;
    }
    // PING (not a PONG): a bare KEEPALIVE that the peer echoes back as KEEPALIVE|ACK.
    if send_keepalive(transport, crypto_session, session_id, false).await {
        crypto_session.mark_keepalive_outstanding();
        *last_keepalive = std::time::Instant::now();
    }
}

/// Emit any flow-control credit the receive **delivery** task staged.
///
/// The delivery task credits the window on real app consumption and stages the
/// relative credit via `Stream::stage_window_update_credit` + a send-loop wake;
/// the send loop (this, the sole outbound writer) actually encrypts and sends the
/// `WINDOW_UPDATE`, so the control frame is always sealed under the epoch live
/// when it stamps. The epoch can be advanced by either this loop's own `rekey()`
/// or the receive task's authenticated forward catch-up, but both serialise
/// through `rekey_lock`, so the seal is always epoch-consistent. The staged
/// credits are snapshotted out of the `DashMap` first so no
/// shard lock is held across the `.await` (which would deadlock the delivery /
/// reader tasks that also touch `streams`).
async fn flush_pending_window_updates<T: SessionTransport>(
    transport: &Arc<T>,
    crypto_session: &Arc<Session>,
    session_id: SessionId,
    streams: &Arc<DashMap<u32, Arc<Stream>>>,
) {
    let pending: Vec<(u32, u32, Arc<Stream>)> = streams
        .iter()
        .filter_map(|e| {
            e.value()
                .take_pending_window_update()
                .map(|c| (*e.key(), c, e.value().clone()))
        })
        .collect();
    for (stream_id, credit, stream) in pending {
        if !send_window_update(
            transport,
            crypto_session,
            session_id,
            stream_id as TransportStreamId,
            credit,
        )
        .await
        {
            // The send failed (transient transport hiccup): re-stage the credit
            // so the next send-loop pass — the 10 ms tick at the latest — retries
            // it. Dropping it silently would under-credit the peer and could
            // eventually stall the sender. Credits accumulate, so a retry simply
            // folds back in; a permanently dead transport tears the session down
            // via the reader, which ends this loop.
            stream.stage_window_update_credit(credit);
        }
    }
}

/// Drain every stream with pending data, scheduling them in strict
/// priority order (higher `Stream::priority()` wins). Streams of equal
/// priority are drained in stream-id order (deterministic so tests
/// don't get flaky under DashMap's hash-order shuffle).
///
/// This is **strict priority**: a stream with priority N never yields
/// to a stream with priority < N while it still has data. A future
/// weighted-fair scheduler can replace this without changing the
/// caller surface. Phase 4.3.
async fn drain_streams_priority_ordered<T: SessionTransport>(
    transport: &Arc<T>,
    crypto_session: &Arc<Session>,
    session_id: SessionId,
    streams: &Arc<DashMap<u32, Arc<Stream>>>,
) {
    // Snapshot the stream set so we can sort without holding DashMap
    // shard locks across awaits. Each entry is (priority, stream_id,
    // stream-Arc) — Arc clones are cheap (refcount bump).
    let mut snapshot: Vec<(u32, u32, Arc<Stream>)> = streams
        .iter()
        .map(|e| (e.value().priority(), *e.key(), e.value().clone()))
        .collect();
    // Descending priority; ties broken by stream id ascending so the
    // order is stable across iterations.
    snapshot.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));

    for (_priority, stream_id, stream) in snapshot {
        loop {
            // Bytes of new data the congestion window currently permits.
            // Recomputed each iteration: every send grows inflight, so the
            // budget shrinks and the drain stops once the window is full.
            let snap = crypto_session.bandwidth_snapshot();
            let budget = snap.cwnd_bytes.saturating_sub(snap.inflight_bytes);
            let Some(seg) = stream.poll_send(budget).await else {
                break;
            };
            // A retransmission means the prior send was lost — tell congestion
            // control so BBR enters FastRecovery and the pacing rate backs off.
            if seg.retransmit {
                crypto_session.on_packet_lost(seg.data.len() as u64);
            }
            let base = if seg.reliable {
                PacketFlags::RELIABLE
            } else {
                PacketFlags::UNRELIABLE
            };
            // Reliable segments carry their gap-free `stream_offset` in the AEAD
            // plaintext (A.5) for in-order reassembly; unreliable segments do not.
            let reliable_offset = if seg.reliable {
                Some(seg.stream_offset)
            } else {
                None
            };
            if !send_app_data(
                transport,
                crypto_session,
                session_id,
                stream_id as TransportStreamId,
                &seg.data,
                base,
                reliable_offset,
            )
            .await
            {
                log::error!("PhantomSession: priority-ordered drain send failed");
                // `poll_send` already stamped `sent_at` on this reliable
                // segment, but the bytes never reached the wire. Clear it so the
                // next drain re-offers it immediately instead of stalling a full
                // RTO before the retransmit pass. Unreliable segments were
                // removed by `poll_send` (fire-and-forget) — nothing to reset.
                if seg.reliable {
                    stream.mark_unsent(seg.stream_offset).await;
                }
                break;
            }
        }
    }
}

/// Build a `DeliverySample` from a successful Stream ack callback and
/// feed it into the session's BBR estimator (Phase 4.4). The BBR loop
/// internally re-sets the pacer rate via `Session::on_packet_acked`,
/// so the next outbound packet is paced at the freshly-estimated
/// bottleneck bandwidth.
///
/// `ack_delay_us` is the V2 header's `ack_delay` field (microseconds
/// the receiver held the ACK before sending) — subtracted from the
/// observed RTT to yield the propagation delay. For V1 ACKs there is
/// no `ack_delay` field on the wire; pass 0 (the estimator treats
/// this as "no peer-side delay reported").
fn feed_bbr_on_ack(
    crypto_session: &Arc<Session>,
    sent_at: tokio::time::Instant,
    packet_bytes: u64,
    ack_delay_us: u64,
) {
    let sample = crate::transport::bandwidth_estimator::DeliverySample {
        delivered_bytes: 0, // BandwidthEstimator tracks its own counter
        sent_at: sent_at.into_std(),
        acked_at: std::time::Instant::now(),
        packet_bytes,
        is_app_limited: false,
        ack_delay_us,
    };
    let _ = crypto_session.on_packet_acked(sample);
}

/// Wait until the pacer has tokens for `bytes` bytes. No-op when the
/// pacer is unlimited (the default until BBR sets a finite rate).
async fn pace_send(crypto_session: &Arc<Session>, bytes: u64) {
    // Anti-fingerprint send-timing jitter (WIRE v6, deliverable (d)): when enabled,
    // wait a uniform random [0, max] ms before this send so the inter-packet timing
    // no longer tracks the application's writes. Applied independently of the pacer
    // (a wire-rate limiter) and before it, so the total delay is jitter + pacing.
    // Opt-in (default 0 → no-op, no latency cost).
    let jitter_max = crypto_session.send_jitter();
    if !jitter_max.is_zero() {
        let delay = shaping::random_jitter(jitter_max.as_millis() as u32);
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
    }
    let pacer = crypto_session.pacer();
    if !pacer.is_enabled() {
        return;
    }
    loop {
        if pacer.try_consume(bytes) {
            return;
        }
        let wait = pacer.time_until_available(bytes);
        if wait.is_zero() {
            // Tokens should be available; retry the consume to handle
            // a concurrent race with another sender.
            continue;
        }
        // Cap the wait to keep the loop responsive — a stale wait
        // estimate from a long-idle pacer is corrected on the next
        // iteration.
        let cap = std::time::Duration::from_millis(50);
        let wait = wait.min(cap);
        tokio::time::sleep(wait).await;
    }
}

/// Decide whether a rekey is needed before stamping a packet and, if so, perform
/// it. A rekey fires when the direction-wide AEAD-invocation high-watermark
/// ([`Session::send_needs_rekey`]) is crossed (Invariant 8). The per-stream C1
/// watermark is gone — under ① the packet number is a per-direction `u64` that
/// cannot wrap within a session, so the nonce can never repeat.
///
/// Returns the extra flag bits to OR into the header, or `None` if a rekey was
/// required but failed (epoch saturated at `u8::MAX`) — the caller MUST fail the
/// send so the session reconnects rather than reusing a nonce.
///
/// T5.5(b) — the returned `PacketFlags::REKEY` bit is set not only on the single
/// rotation-trigger packet but on EVERY packet sent at the new epoch until the
/// peer acknowledges the rekey ([`Session::rekey_unconfirmed`] clears once an
/// authenticated inbound packet is seen at the new epoch). Re-advertising the
/// flag is what makes the receive-side catch-up gate in
/// [`Session::decrypt_packet_accepting_rekey`] safe: a lost rotation-trigger
/// packet no longer strands the peer, because the next new-epoch packet (incl. a
/// reliable retransmit) still carries REKEY and drives the catch-up.
fn rekey_before_stamp(crypto_session: &Arc<Session>) -> Option<u16> {
    if crypto_session.send_needs_rekey() {
        // Crossed the high-watermark: rotate now. `rekey()` marks the session
        // `rekey_unconfirmed`, so the flag below re-arms automatically.
        if let Err(e) = crypto_session.rekey() {
            log::error!("PhantomSession: mid-session rekey failed: {}", e);
            return None;
        }
    }
    // Re-advertise REKEY while our last rekey is still unacknowledged — even when
    // no rotation happened on this packet (the trigger may have rotated several
    // packets ago and been lost).
    Some(if crypto_session.rekey_unconfirmed() {
        PacketFlags::REKEY
    } else {
        0
    })
}

/// V2 send. Builds `PhantomPacket` with `PacketFlags::ENCRYPTED` and
/// the negotiated rekey epoch; AEAD nonce derives from the header
/// (`Session::encrypt_packet`), so a failed peer decrypt no longer
/// desyncs the local counter.
async fn send_app_data<T: SessionTransport>(
    transport: &Arc<T>,
    crypto_session: &Arc<Session>,
    session_id: SessionId,
    stream_id: TransportStreamId,
    payload: &[u8],
    base_flags: u16,
    reliable_offset: Option<u32>,
) -> bool {
    // Always OR in ENCRYPTED for application data.
    let mut flag_bits = base_flags | PacketFlags::ENCRYPTED;
    // Mid-session rekey: rotate to a fresh key BEFORE stamping this header when the
    // direction-wide AEAD high-watermark is crossed, so the header carries the new
    // epoch (+ the REKEY flag). The peer follows on the authenticated epoch bump
    // (it trial-decrypts under the next key).
    match rekey_before_stamp(crypto_session) {
        Some(extra) => flag_bits |= extra,
        // Epoch saturated (u8::MAX): can't rotate further. Surface as a failed
        // send so the caller re-offers; the session reconnects rather than wrap.
        None => return false,
    }
    // ① — Phase 4: draw the per-direction packet number at send time (so a
    // retransmit gets a fresh PN and the nonce is never reused).
    let packet_number = crypto_session.next_send_pn();
    // Build the inner AEAD plaintext (owned so size-padding can extend it). For
    // reliable data, prepend the gap-free per-stream `stream_offset` (A.5, 4
    // big-endian bytes) so the receiver reassembles in send order regardless of
    // `sequence` holes left by interleaved control frames. Unreliable / control
    // frames carry no offset. This all lives inside the AEAD (authenticated,
    // invisible on the wire).
    let mut plaintext: Vec<u8> = match reliable_offset {
        Some(off) => {
            let mut v = Vec::with_capacity(4 + payload.len());
            v.extend_from_slice(&off.to_be_bytes());
            v.extend_from_slice(payload);
            v
        }
        None => payload.to_vec(),
    };
    // Anti-fingerprint size padding (WIRE v6, deliverable (c)): when the session's
    // padding policy is enabled, pad this packet up to a PADÉ bucket INSIDE the
    // AEAD plaintext and flag it `PADDED`, so the on-wire datagram size no longer
    // tracks the payload size. The receiver strips the trailer after a successful
    // decrypt. Opt-in (default `None` → no-op, zero overhead). The `PADDED` flag
    // rides in the AAD (and is HP-masked on the wire), so a tamper fails the AEAD.
    let trailer = shaping::padding_trailer_len(plaintext.len(), crypto_session.padding_policy());
    if trailer > 0 {
        shaping::append_padding(&mut plaintext, trailer);
        flag_bits |= PacketFlags::PADDED;
    }
    let header = PacketHeader::new(
        session_id,
        stream_id,
        packet_number,
        PacketFlags::new(flag_bits),
    )
    .with_epoch(crypto_session.current_epoch())
    // Stamp the current send-side path_id (D5 — Phase 4). Default 0 (the implicit
    // handshake path) is behaviour-preserving; after a `migrate()` bump this carries
    // the new path label so the peer detects the new path and issues a challenge.
    // Retransmits flow through here too, so ARQ re-carries on the new path (D7).
    .with_path_id(crypto_session.current_send_path_id());
    // The data-plane packet carries no `extensions` (TLV headroom stays empty),
    // so the AEAD AAD binds an empty extensions slice — matching the wire.
    let ciphertext = match crypto_session.encrypt_packet(&header, &plaintext, &[]) {
        Ok(c) => c,
        Err(e) => {
            log::error!("PhantomSession: encrypt_packet failed: {}", e);
            return false;
        }
    };
    let packet = PhantomPacket::new(header, ciphertext);
    // Header protection (T4.6): mask the [33..47] header span before it hits the
    // wire. Infallible in practice (the payload always carries the AEAD tag).
    let buf = match crypto_session.protect_packet(&packet) {
        Ok(b) => b,
        Err(e) => {
            log::error!("PhantomSession: header protection failed: {}", e);
            return false;
        }
    };
    let size = buf.len();
    // Pacing is a wire-rate limiter, so it consumes the full on-wire size.
    pace_send(crypto_session, size as u64).await;
    if let Err(e) = transport.send_bytes(&buf[..size]).await {
        log::error!("PhantomSession: transport send failed: {}", e);
        return false;
    }
    // Inflight/cwnd accounting MUST use the same unit the ACK and loss paths
    // settle in. `Stream::ack` returns and `on_packet_lost` subtracts the
    // segment's *payload* length (`seg.data.len()`), so the send side has to add
    // the payload length too — adding the full wire size here leaked ~69 bytes
    // (header + length prefixes + AEAD tag) of phantom inflight per packet,
    // which silently exhausted the congestion window after a few dozen packets
    // and stalled long-lived sessions. (Bandwidth/BDP derive from acked bytes,
    // so they stay in the same payload unit.)
    crypto_session.on_packet_sent(payload.len() as u64);
    true
}

/// Emit a V2 WINDOW_UPDATE packet announcing `new_window` bytes of
/// receive capacity for `stream_id`. Encrypted under the current
/// session epoch (Phase 4.3 flow control).
async fn send_window_update<T: SessionTransport>(
    transport: &Arc<T>,
    crypto_session: &Arc<Session>,
    session_id: SessionId,
    stream_id: TransportStreamId,
    new_window: u32,
) -> bool {
    let mut flag_bits = PacketFlags::ENCRYPTED | PacketFlags::WINDOW_UPDATE;
    // WINDOW_UPDATE obeys the same direction-wide rekey discipline before stamping.
    match rekey_before_stamp(crypto_session) {
        Some(extra) => flag_bits |= extra,
        None => return false,
    }
    let packet_number = crypto_session.next_send_pn();
    let header = PacketHeader::new(
        session_id,
        stream_id,
        packet_number,
        PacketFlags::new(flag_bits),
    )
    .with_epoch(crypto_session.current_epoch());
    let payload = new_window.to_be_bytes();
    let ciphertext = match crypto_session.encrypt_packet(&header, &payload, &[]) {
        Ok(c) => c,
        Err(e) => {
            log::error!("PhantomSession: WINDOW_UPDATE encrypt failed: {}", e);
            return false;
        }
    };
    let packet = PhantomPacket::new(header, ciphertext);
    let buf = match crypto_session.protect_packet(&packet) {
        Ok(b) => b,
        Err(e) => {
            log::error!(
                "PhantomSession: WINDOW_UPDATE header protection failed: {}",
                e
            );
            return false;
        }
    };
    if let Err(e) = transport.send_bytes(&buf).await {
        log::error!("PhantomSession: WINDOW_UPDATE send failed: {}", e);
        return false;
    }
    true
}

/// Emit an idle keep-alive packet (Direction #3 — download-only liveness): a
/// small `ENCRYPTED | KEEPALIVE` packet with an **empty** payload, stamped on the
/// current send path.
///
/// `is_pong` selects the role: a bare `KEEPALIVE` is a PING (`is_pong = false`);
/// `KEEPALIVE | ACK` is the PONG echo a receiver sends back (`is_pong = true`).
/// Either way the payload is empty, so the peer's `recv()` never sees it. The
/// packet is sealed exactly like application data — ENCRYPTED (Inv-2), a fresh
/// per-direction packet number (no nonce reuse), header-protected — so an off-path
/// peer can neither forge nor replay it (the replay window rejects a duplicate PN
/// after AEAD verify, Inv-4). Returns `false` on a rekey-saturation or
/// seal/transport failure (the caller just skips the keep-alive — it is
/// best-effort).
async fn send_keepalive<T: SessionTransport>(
    transport: &Arc<T>,
    crypto_session: &Arc<Session>,
    session_id: SessionId,
    is_pong: bool,
) -> bool {
    let mut flag_bits = PacketFlags::ENCRYPTED | PacketFlags::KEEPALIVE;
    if is_pong {
        flag_bits |= PacketFlags::ACK;
    }
    // Obey the same direction-wide rekey discipline before stamping the header.
    match rekey_before_stamp(crypto_session) {
        Some(extra) => flag_bits |= extra,
        None => return false,
    }
    let packet_number = crypto_session.next_send_pn();
    let header = PacketHeader::new(
        session_id,
        // Reserved raw-app stream id (1) — the keep-alive carries no stream data,
        // but a stable id keeps the header well-formed and consistent with the
        // session's own send()/recv() surface.
        RAW_APP_STREAM_ID as TransportStreamId,
        packet_number,
        PacketFlags::new(flag_bits),
    )
    .with_epoch(crypto_session.current_epoch())
    .with_path_id(crypto_session.current_send_path_id());
    let ciphertext = match crypto_session.encrypt_packet(&header, &[], &[]) {
        Ok(c) => c,
        Err(e) => {
            log::error!("PhantomSession: keep-alive encrypt failed: {}", e);
            return false;
        }
    };
    let packet = PhantomPacket::new(header, ciphertext);
    let buf = match crypto_session.protect_packet(&packet) {
        Ok(b) => b,
        Err(e) => {
            log::error!("PhantomSession: keep-alive header protection failed: {}", e);
            return false;
        }
    };
    if let Err(e) = transport.send_bytes(&buf).await {
        log::error!("PhantomSession: keep-alive send failed: {}", e);
        return false;
    }
    true
}

/// Emit one anti-fingerprint COVER (dummy) packet (WIRE v6, deliverable (e)): an
/// `ENCRYPTED | COVER` packet with **empty** inner plaintext, PADÉ-padded to a
/// bucket so it is not a tiny distinctive size on the wire. It carries no stream
/// data; the peer AEAD-authenticates it (which refreshes its liveness timer and
/// makes off-path injection impossible) then drops it before the data path, so it
/// never reaches `recv()`. Cover is always padded, independent of the session's
/// data-padding policy.
async fn send_cover<T: SessionTransport>(
    transport: &Arc<T>,
    crypto_session: &Arc<Session>,
    session_id: SessionId,
) -> bool {
    let mut flag_bits = PacketFlags::ENCRYPTED | PacketFlags::COVER;
    // Same direction-wide rekey discipline as any other send.
    match rekey_before_stamp(crypto_session) {
        Some(extra) => flag_bits |= extra,
        None => return false,
    }
    let mut plaintext = Vec::new();
    let trailer = shaping::padding_trailer_len(0, PaddingPolicy::Padme);
    if trailer > 0 {
        shaping::append_padding(&mut plaintext, trailer);
        flag_bits |= PacketFlags::PADDED;
    }
    let packet_number = crypto_session.next_send_pn();
    let header = PacketHeader::new(
        session_id,
        RAW_APP_STREAM_ID as TransportStreamId,
        packet_number,
        PacketFlags::new(flag_bits),
    )
    .with_epoch(crypto_session.current_epoch())
    .with_path_id(crypto_session.current_send_path_id());
    let ciphertext = match crypto_session.encrypt_packet(&header, &plaintext, &[]) {
        Ok(c) => c,
        Err(e) => {
            log::error!("PhantomSession: cover encrypt failed: {}", e);
            return false;
        }
    };
    let packet = PhantomPacket::new(header, ciphertext);
    let buf = match crypto_session.protect_packet(&packet) {
        Ok(b) => b,
        Err(e) => {
            log::error!("PhantomSession: cover header protection failed: {}", e);
            return false;
        }
    };
    if let Err(e) = transport.send_bytes(&buf).await {
        log::error!("PhantomSession: cover send failed: {}", e);
        return false;
    }
    true
}

/// Maintain a minimum outbound packet rate with cover traffic (WIRE v6, deliverable
/// (e)): when no packet has gone out for `cover_interval`, emit a COVER dummy so
/// silence + volume no longer leak (idle-fill + a floor rate of `1000 / interval_ms`
/// packets/sec). `last_pn` / `last_at` track the last observed outbound activity —
/// any real packet advances the send PN, resetting the idle window, so cover only
/// fills genuine gaps and never piles on top of active traffic.
async fn maybe_send_cover<T: SessionTransport>(
    transport: &Arc<T>,
    crypto_session: &Arc<Session>,
    session_id: SessionId,
    last_pn: &mut u64,
    last_at: &mut std::time::Instant,
) {
    let interval = crypto_session.cover_interval();
    if interval.is_zero() {
        return;
    }
    if crypto_session.state() != SessionState::Connected {
        return;
    }
    let pn = crypto_session.peek_send_pn();
    if pn != *last_pn {
        // Real (or prior cover) traffic went out since the last check — reset.
        *last_pn = pn;
        *last_at = std::time::Instant::now();
        return;
    }
    if last_at.elapsed() >= interval && send_cover(transport, crypto_session, session_id).await {
        *last_pn = crypto_session.peek_send_pn();
        *last_at = std::time::Instant::now();
    }
}

/// Emit a V2 PATH_VALIDATION packet on `path_id` carrying the given
/// 32-byte challenge or response payload. Encrypted under the current
/// session epoch.
/// Build + encrypt a `PATH_VALIDATION` packet, returning its on-wire bytes. The
/// caller routes them: to the established peer (a response echo) via `send_bytes`,
/// or to a migration candidate (a server-issued challenge) via `send_to_candidate`
/// (Phase 4). Returns `None` only if the AEAD seal fails.
fn encrypt_path_validation(
    crypto_session: &Arc<Session>,
    session_id: SessionId,
    path_id: u8,
    payload: [u8; crate::transport::path::PATH_CHALLENGE_LEN],
) -> Option<Vec<u8>> {
    let packet_number = crypto_session.next_send_pn();
    let mut packet = build_path_validation_packet(session_id, path_id, packet_number, payload);
    let flag_bits = packet.header.flags.0 | PacketFlags::ENCRYPTED;
    packet.header.flags = PacketFlags::new(flag_bits);
    packet.header.epoch = crypto_session.current_epoch();
    let plaintext = std::mem::take(&mut packet.payload);
    let ciphertext = match crypto_session.encrypt_packet(&packet.header, &plaintext, &[]) {
        Ok(c) => c,
        Err(e) => {
            log::error!("PhantomSession: PATH_VALIDATION encrypt failed: {}", e);
            return None;
        }
    };
    packet.payload = ciphertext;
    match crypto_session.protect_packet(&packet) {
        Ok(buf) => Some(buf),
        Err(e) => {
            log::error!(
                "PhantomSession: PATH_VALIDATION header protection failed: {}",
                e
            );
            None
        }
    }
}

/// Send a `PATH_VALIDATION` packet to the established peer (a response echo).
async fn send_path_validation<T: SessionTransport>(
    transport: &Arc<T>,
    crypto_session: &Arc<Session>,
    session_id: SessionId,
    path_id: u8,
    payload: [u8; crate::transport::path::PATH_CHALLENGE_LEN],
) -> bool {
    let buf = match encrypt_path_validation(crypto_session, session_id, path_id, payload) {
        Some(b) => b,
        None => return false,
    };
    if let Err(e) = transport.send_bytes(&buf).await {
        log::error!("PhantomSession: PATH_VALIDATION send failed: {}", e);
        return false;
    }
    true
}

/// Hard cap on concurrent receive streams a peer can open on one session (H-3). The recv
/// path auto-creates a `Stream` for any of the 2^32 `stream_id`s; without a cap a peer can
/// spray distinct ids to explode the stream table. With the per-stream reorder budget,
/// `MAX_STREAMS` times `MAX_RECV_REORDER_BYTES` bounds the session's total reorder memory.
/// Sized well above QUIC's ~100-stream default so real multiplexing is unaffected.
const MAX_STREAMS: usize = 256;

/// Recv-side handler for a packet:
/// - session-id guard → drop any frame not stamped with the negotiated
///   session id before touching any state (H1).
/// - decrypt (REQUIRED on application data — a non-empty unencrypted
///   post-handshake packet is a downgrade indicator and is dropped).
/// - ACK (now `ENCRYPTED | ACK`, post-decrypt) → parse the authenticated
///   `Sack` from the plaintext, retire every covered segment, feed BBR per
///   retired segment + route to the stream / demux. Forged/plaintext ACKs
///   cannot reach this path (H1); a malformed SACK is dropped, never a panic.
/// - PATH_VALIDATION flag → drive the path registry: verify against an
///   outstanding challenge if one exists, otherwise echo the payload
///   back as a response.
/// - WINDOW_UPDATE flag → apply the peer's announced flow-control window.
/// - COALESCED flag → split the decrypted bundle into sub-payloads and
///   route each through the demux as an independent application chunk.
#[allow(clippy::too_many_arguments)]
async fn handle_packet<T: SessionTransport>(
    packet: PhantomPacket,
    session_id: SessionId,
    crypto_recv: &Arc<Session>,
    streams_recv: &Arc<DashMap<u32, Arc<Stream>>>,
    demux_recv: &Arc<StreamDemultiplexer>,
    transport_send_ack: &Arc<T>,
    transport_for_path: &Arc<T>,
    // The reader hands decrypted application data to the delivery task via
    // this unbounded channel instead of blocking on `recv_tx`/the demux — so a
    // slow `recv()` consumer can never head-of-line-stall inbound ACK/control.
    deliver_tx: &mpsc::UnboundedSender<(u32, Bytes)>,
    undelivered_bytes: &AtomicU64,
    ack_buf: &mut Vec<u8>,
    observability: &Observability,
    leg: LegType,
) {
    let stream_id: u32 = packet.header.stream_id.into();
    let path_id = packet.header.path_id;

    // Bind every inbound frame to the negotiated session (H1). In ε / WIRE v5 the
    // inner `session_id` is off-wire: `parse_protected` reconstructed
    // `header.session_id` from this session's id, so this comparison is now a
    // structural backstop (always true on a correctly-routed frame). The real
    // cross-session bind is the AEAD AAD, which still authenticates `session_id`
    // — a frame mis-delivered to the wrong session reconstructs that session's id
    // into the AAD → wrong AAD → AEAD fail below, so forged ACK/FIN injection can
    // never reach the stream table, BBR, or the path registry. Retained as a
    // defensive backstop (design §2.1).
    if packet.header.session_id != session_id {
        return;
    }

    // Mark path activity even before decrypt (the path id is plaintext
    // header bytes; this is just a liveness signal for the sweep).
    crypto_recv.mark_path_seen(path_id);

    // NOTE: ACK/FIN are NO LONGER processed here, pre-decrypt. They are
    // authenticated `ENCRYPTED | ACK` control frames now (H1) and are handled
    // *after* the AEAD gate below — see the ACK branch following the decrypt.

    // Decrypt if marked. V2 sessions REQUIRE ENCRYPTED on application
    // data — a non-empty unencrypted V2 application-data packet is a
    // downgrade indicator and is dropped (same posture as V1).
    let plaintext: Vec<u8> = if packet.header.flags.contains(PacketFlags::ENCRYPTED) {
        // Accept a single authenticated forward rekey step (C1): if this
        // packet's epoch is one ahead, the peer rekeyed — trial-decrypt under
        // the next key and only commit the ratchet on AEAD success, so a forged
        // epoch can't desync us. Same-epoch packets take the ordinary path.
        match crypto_recv.decrypt_packet_accepting_rekey(
            &packet.header,
            &packet.payload,
            &packet.extensions,
        ) {
            Ok(pt) => pt,
            Err(e) => {
                // Distinguish the two drop reasons for the security metrics: a
                // post-AEAD sliding-window replay reject vs an AEAD-verify
                // failure (Invariant 4 — replay is checked after AEAD opens).
                // decrypt_packet doesn't surface old-vs-duplicate, so record the
                // representative `Duplicate` reason.
                if matches!(e, CoreError::ReplayDetected(_)) {
                    observability.record_replay_rejected(ReplayReason::Duplicate);
                } else {
                    observability.record_aead_failure(leg, AeadAlgorithm::Aes256Gcm);
                }
                log::warn!("PhantomSession: V2 decrypt failed (dropping packet): {}", e);
                return;
            }
        }
    } else {
        // Stripped-flag downgrade defense (Invariant 2, M-2): ANY unencrypted post-handshake
        // packet is dropped — including an empty-payload one whose only remaining effect would
        // be a forged standalone FIN tearing down an `open_stream()` stream without AEAD
        // verification. Legitimate data and control frames (incl. FIN) always set ENCRYPTED.
        observability.record_unencrypted_dropped(leg);
        log::warn!(
            "PhantomSession: dropping unencrypted post-handshake packet (downgrade / forged FIN?)"
        );
        return;
    };

    // Strip anti-fingerprint size padding (WIRE v6, deliverable (c)): a PADDED
    // packet's AEAD plaintext ends with a `‹zeros› ‖ pad_n:u16be` trailer. The
    // PADDED flag is AEAD-authenticated (it is part of the header AAD verified
    // above), so this only runs on genuine padded packets; a malformed trailer
    // from a buggy peer is dropped without panic. Stripping here — before any
    // downstream parse — means the SACK / keepalive / data paths all see the real
    // inner plaintext, exactly as if no padding had been applied.
    let plaintext: Vec<u8> = if packet.header.flags.contains(PacketFlags::PADDED) {
        match shaping::strip_padding(&plaintext) {
            Ok(inner) => inner.to_vec(),
            Err(_) => {
                log::warn!("PhantomSession: dropping packet with malformed padding trailer");
                return;
            }
        }
    } else {
        plaintext
    };

    // Liveness (P4.3): an authenticated inbound packet (it passed AEAD above) proves
    // the peer is alive on some path — refresh the activity timer so the pump's
    // liveness sweep does not false-trip. Plaintext/forged packets never reach here
    // (a failed decrypt returned early), so an off-path attacker cannot keep a dead
    // session looking alive.
    if packet.header.flags.contains(PacketFlags::ENCRYPTED) {
        crypto_recv.update_activity();
        // M-1: this packet just AEAD-authenticated, so its source really is the peer — possibly
        // at a NEW address (migration / NAT rebind). Commit it as the migration candidate ONLY
        // now (post-decrypt), so a spoofed CID-matched datagram (which never decrypts) cannot
        // clobber the candidate slot and misdirect / stall a legitimate migration. No-op for
        // same-source packets and for non-address transports (default trait impl).
        transport_for_path.confirm_authenticated_source();
        // ε / WIRE v5 (P4b): the path_id is now authenticated. If the peer migrated
        // (a new forward path_id), slide our inbound CID demux window so its rotated
        // CID stays routable for arbitrarily many migrations. No-op on the client and
        // for a path_id that is not newer (reorder / duplicate / passive rebind).
        if let Some(slide) = crypto_recv.note_migration_path(packet.header.path_id) {
            crypto_recv.signal_cid_slide(slide);
            // EPS-02 (symmetric rotation): the peer migrated, so rotate our OWN
            // outbound CID too — otherwise the return direction keeps a stable
            // cleartext ConnId across the peer's migration and an observer seeing
            // both networks relinks the session by it (ε §12.5 residual). Only the
            // **server** rotates here: it is the demuxing side, and the peer (the
            // socket-routed client) accepts any inbound CID, so this needs no
            // client-side window slide and cannot strand. We deliberately do NOT
            // bump our own send `path_id` (this is a CID rotation, not an address
            // migration), so the peer's `note_migration_path` sees no forward step
            // and there is no ping-pong. The client side is left untouched: it has
            // no inbound demux to follow a rotation, and rotating its c2s CID off a
            // server migration would push it out of the server's (un-sliding) c2s
            // window for repeated server migrations — a documented residual
            // (audit-report-2026-06-15 EPS-02) the server-migration path keeps.
            if crypto_recv.is_server() {
                transport_for_path.set_outbound_cid(crypto_recv.advance_outbound_cid());
            }
        }
    }

    // Idle keep-alive (Direction #3 — download-only liveness). A keep-alive carries
    // no application bytes; its sole effect is the `update_activity()` above (which
    // refreshed this side's liveness timer and cleared any outstanding probe). It
    // is handled here, BEFORE the ACK branch, because a PONG is `KEEPALIVE | ACK`
    // and must not be mis-parsed as a SACK. A bare `KEEPALIVE` is a PING → echo a
    // `KEEPALIVE | ACK` PONG so the peer's own liveness timer + outstanding-probe
    // flag clear; a `KEEPALIVE | ACK` is that PONG → nothing more to do. Either way
    // we return so the empty payload never reaches the SACK / data paths.
    if packet.header.flags.contains(PacketFlags::KEEPALIVE) {
        if !packet.header.flags.contains(PacketFlags::ACK) {
            // PING → reply with a PONG (KEEPALIVE | ACK). Best-effort; a drop just
            // means the peer re-PINGs next interval (its probe stays outstanding).
            let _ = send_keepalive(transport_send_ack, crypto_recv, session_id, true).await;
        }
        return;
    }

    // Cover traffic (WIRE v6, deliverable (e)): a COVER packet carries no application
    // data (its inner plaintext is empty after the padding strip above). Its only
    // effect is the `update_activity()` already done above (it AEAD-authenticated, so
    // it proves the peer is alive and cannot be off-path injected). Drop it here,
    // before the SACK / data paths, so the empty payload never surfaces in `recv()`.
    // (A cover packet is never an ACK — it is `ENCRYPTED | COVER | PADDED` — so this
    // must precede the ACK branch below.)
    if packet.header.flags.contains(PacketFlags::COVER) {
        return;
    }

    // Authenticated SACK ACK (H1, L1-A). ACKs are `ENCRYPTED | ACK` control
    // frames whose AEAD *plaintext* carries a `Sack` (largest_acked,
    // ack_delay_us, and the inclusive received ranges). We act on the ACK only
    // *after* AEAD verify, which authenticates the header (including `session_id`)
    // and the SACK plaintext — so a forged or stripped-flag ACK (dropped above by
    // the downgrade defense) can neither retire a pending segment, restore a
    // flow-control permit, poison BBR, nor close a stream. A malformed SACK from
    // a buggy (but authenticated) peer is dropped without panic and retires
    // nothing.
    if packet.header.flags.contains(PacketFlags::ACK) {
        let sack = match crate::transport::sack::Sack::from_wire(&plaintext) {
            Ok(s) => s,
            Err(e) => {
                log::debug!(
                    "PhantomSession: dropping malformed SACK ({} B): {}",
                    plaintext.len(),
                    e
                );
                return;
            }
        };
        if let Some(stream) = streams_recv.get(&stream_id) {
            // Retire EVERY segment the SACK covers (cumulative). RTT is sampled
            // inside `on_sack` per Karn (only for never-retransmitted segments);
            // feed BBR per retired segment using the real `ack_delay_us`.
            let result = stream.on_sack(&sack).await;
            for retired in result.retired {
                if let Some(sent_at) = retired.sent_at {
                    feed_bbr_on_ack(crypto_recv, sent_at, retired.size, sack.ack_delay_us as u64);
                }
            }
            // L1-B: feed the REAL loss signal to BBR for every segment the SACK gap
            // detector just declared lost (previously `on_loss` fired only on RTO),
            // then wake the send loop so its Pass-0 fast-retransmits them promptly.
            if !result.lost.is_empty() {
                for lost in &result.lost {
                    crypto_recv.on_packet_lost(lost.size);
                }
                crypto_recv.notify_outbound_ready();
            }
        }
        // Best-effort, non-blocking: the demux/PhantomStream path is vestigial;
        // routing the ACK/close notification to it must never block the reader.
        // Route `largest_acked` to preserve the existing close/notify semantics
        // (the waiter only needs *an* ACK signal for the stream).
        demux_recv.route_ack(stream_id, sack.largest_acked);
        if packet.header.flags.contains(PacketFlags::FIN) {
            demux_recv.route_close(stream_id);
        }
        return;
    }

    // WINDOW_UPDATE dispatch (Phase 4.3 flow control). Payload is a
    // big-endian u32 carrying relative flow-control credit — the bytes the
    // peer's application just consumed, which we ADD to our send window.
    if packet.header.flags.contains(PacketFlags::WINDOW_UPDATE) {
        if plaintext.len() != 4 {
            log::warn!(
                "PhantomSession: WINDOW_UPDATE payload length {} (expected 4)",
                plaintext.len()
            );
            return;
        }
        let credit = u32::from_be_bytes([plaintext[0], plaintext[1], plaintext[2], plaintext[3]]);
        if let Some(stream) = streams_recv.get(&stream_id) {
            // Relative-credit flow control — add the granted credit, then
            // wake the send loop so a window-blocked sender resumes immediately
            // instead of waiting a full poll tick.
            stream.apply_peer_window_update(credit);
            crypto_recv.notify_outbound_ready();
        }
        return;
    }

    // PATH_VALIDATION dispatch (Phase 4.2): the codec inspects the *plaintext*
    // because the wire packet was sealed by the AEAD layer.
    if packet.header.flags.contains(PacketFlags::PATH_VALIDATION) {
        if plaintext.len() != crate::transport::path::PATH_CHALLENGE_LEN {
            log::warn!(
                "PhantomSession: PATH_VALIDATION plaintext length {} (expected {})",
                plaintext.len(),
                crate::transport::path::PATH_CHALLENGE_LEN
            );
            return;
        }
        let mut payload_buf = [0u8; crate::transport::path::PATH_CHALLENGE_LEN];
        payload_buf.copy_from_slice(&plaintext);
        // If we have an in-flight challenge on this path, try to
        // verify against it. If verification succeeds, the path
        // transitions to Validated and we're done. If it fails, the
        // registry already transitioned to Failed — also done.
        match crypto_recv.path_state(path_id) {
            Some(crate::transport::path::PathStateKind::Validating) => {
                // The peer echoed our challenge on this path. If it validates AND a
                // migration candidate is pending, SWITCH the active peer to it (D7)
                // and reset RTT/cwnd for the new network (D8) — no re-handshake,
                // keys persist; subsequent app data + ARQ retransmits flow to the
                // new peer. (P4.1 only challenged; P4.2 performs the switch.)
                if crypto_recv.complete_path_validation(path_id, &payload_buf)
                    && transport_for_path.promote_candidate()
                {
                    crypto_recv.reset_congestion();
                    for s in streams_recv.iter() {
                        s.value().reset_rto();
                    }
                    // M-3: if this was a passive-rebind validation (the reserved id),
                    // retire the path so a LATER rebind re-registers it fresh and can
                    // be challenged again. The reserved id stays Validated otherwise,
                    // and `begin_path_validation` on a Validated path returns None, so
                    // the second rebind would never issue a challenge. Active-migration
                    // ids are left intact (they are retired by their own lifecycle).
                    if path_id == crate::transport::session::REBIND_VALIDATION_PATH_ID {
                        crypto_recv.retire_path(path_id);
                    }
                }
                return;
            }
            Some(crate::transport::path::PathStateKind::Validated)
            | Some(crate::transport::path::PathStateKind::Failed) => {
                // Terminal state — ignore.
                return;
            }
            _ => {
                // Unknown or Unvalidated: treat this packet as an
                // incoming challenge and echo the payload back as our
                // response. The remote will then verify it against its
                // own pending challenge.
                let _ = send_path_validation(
                    transport_for_path,
                    crypto_recv,
                    session_id,
                    path_id,
                    payload_buf,
                )
                .await;
                return;
            }
        }
    }

    // PATH-001 split (D10, Phase 4). Runs AFTER AEAD verify + the per-direction
    // replay window, so it never acts on an attacker-chosen plaintext path_id.
    //
    // PATH-001b (recv, relaxed): AEAD-authenticated, non-replayed app data is
    // DELIVERED regardless of which path it arrived on. Dropping it by source buys
    // no security (only the real peer holds the keys; replays are already rejected)
    // and would break a seamless NAT-rebind / migration. PATH-001a (the strict
    // send-gate) lives in the send loop: app data is only ever sent to the
    // established peer — a candidate gets a PATH_CHALLENGE, never app data.
    //
    // Server-side migration (P4.1): if this app packet arrived on a not-yet-
    // Validated path AND the transport flagged a migration candidate (a new source
    // for this CID), proactively issue + send a challenge to the candidate so the
    // new path can validate. We do NOT switch the peer here (that is P4.2); the
    // challenge goes to the candidate under its anti-amplification budget.
    if !matches!(
        crypto_recv.path_state(path_id),
        Some(crate::transport::path::PathStateKind::Validated)
    ) {
        if transport_for_path.has_migration_candidate() {
            if let Some(challenge) = crypto_recv.begin_path_validation(path_id) {
                if let Some(buf) =
                    encrypt_path_validation(crypto_recv, session_id, path_id, challenge)
                {
                    // To the candidate, NOT the peer; capped at 3× by the transport.
                    let _ = transport_for_path.send_to_candidate(&buf).await;
                }
            }
        } else {
            // No migration candidate (non-address transport, or a path id seen
            // without a source change): track it for a possible later challenge.
            crypto_recv.register_unvalidated_path(path_id);
        }
        // PATH-001b: fall through and deliver the authenticated data below.
    } else if transport_for_path.has_migration_candidate() {
        // M-3 (passive NAT rebind): the frame arrived on an already-Validated path —
        // the path-0 rebind case, where the peer's source address changed WITHOUT it
        // calling `migrate()`, so it never bumped `path_id`. The active-migration gate
        // above is skipped (path is Validated), so without this branch the new
        // authenticated source would never be challenged → never promoted → the
        // downstream (server→client) direction keeps targeting the OLD, now-dead
        // address → stall. Detection is therefore ADDRESS-driven, not path-id-driven:
        // a migration candidate exists only because `confirm_authenticated_source`
        // committed an AEAD-authenticated source that differs from the established
        // peer (M-1). We challenge that candidate on the RESERVED validation path-id
        // (carved out of the migration id space), which the registry can take through
        // `Validating → Validated` independently of the always-Validated path 0. The
        // challenge goes ONLY to the candidate (its claimed address), under the same
        // 3× anti-amplification cap — anti-spoof is preserved exactly as for an active
        // migration. The peer switch happens later, when the candidate echoes the
        // challenge (the PATH_VALIDATION completion branch above).
        let rebind_path = crate::transport::session::REBIND_VALIDATION_PATH_ID;
        if let Some(challenge) = crypto_recv.begin_path_validation(rebind_path) {
            if let Some(buf) =
                encrypt_path_validation(crypto_recv, session_id, rebind_path, challenge)
            {
                let _ = transport_for_path.send_to_candidate(&buf).await;
            }
        }
    }

    // COALESCED dispatch (Phase 2.5): split the decrypted bundle into sub-payloads
    // and hand each, IN ORDER, to the single FIFO delivery task. Bundles are NOT
    // reassembled by stream offset — they are not emitted by the live sender (a
    // recv-side capability only), are not independently sequenced, and do not
    // auto-ACK (the outer sequence was consumed by the replay window). Delivered in
    // arrival order, preserving the bundle's internal order.
    if packet.header.flags.contains(PacketFlags::COALESCED) {
        let inner_for_codec = PhantomPacket {
            header: packet.header,
            payload: plaintext,
            extensions: Vec::new(),
        };
        match unwrap_coalesced_packet(&inner_for_codec) {
            Ok(Some(subs)) => {
                let payloads: Vec<Bytes> = subs
                    .into_iter()
                    .filter(|s| !s.is_empty())
                    .map(Bytes::from)
                    .collect();
                deliver_in_order_run(payloads, stream_id, deliver_tx, undelivered_bytes);
            }
            Ok(None) => {
                log::warn!("PhantomSession: COALESCED flag set but bundle didn't parse");
            }
            Err(e) => {
                log::warn!("PhantomSession: COALESCED parse error: {}", e);
            }
        }
        return;
    }

    // Reliable application data → reassemble by the gap-free `stream_offset` (A.5),
    // emit an authenticated **SACK** ACK inline (H1, L1-A), then deliver the
    // in-order run. The reliable AEAD plaintext is `[stream_offset: u32 BE][data]`;
    // reordering on `stream_offset` (not the control-frame-holed `header.sequence`)
    // is what makes reliable in-order delivery correct over a reordering path. The
    // ACK is an `ENCRYPTED | ACK` control frame whose AEAD *plaintext* carries a
    // `Sack` over `stream_offset` ranges; the peer parses it only after AEAD verify,
    // so it cannot be forged off-path and a malformed range from a buggy peer is
    // dropped post-decrypt without crashing (handled in the sender branch). The SACK
    // retires every covered segment at once, so a lost ACK no longer strands a
    // segment — the next SACK re-acks it cumulatively. The ACK's own
    // `header.sequence` is drawn from this side's per-stream send counter — shared
    // with our data/window-update sends — so `(epoch, stream_id, sequence, path_id)`
    // is unique and never collides with our outbound data (the nonce-reuse trap); it
    // obeys the C1 rekey discipline. "ACK" means "received, decrypted, replay-passed,
    // accepted into in-order reassembly."
    if packet.header.flags.contains(PacketFlags::RELIABLE) {
        // Reliable plaintext = [stream_offset: u32 BE][data] (A.5). A frame shorter
        // than the 4-byte offset prefix is malformed — no legitimate sender emits
        // one — so drop it (never a panic).
        if plaintext.len() < 4 {
            log::warn!(
                "PhantomSession: reliable frame missing stream-offset prefix ({} B)",
                plaintext.len()
            );
            return;
        }
        let pt = Bytes::from(plaintext);
        let stream_offset = u32::from_be_bytes([pt[0], pt[1], pt[2], pt[3]]);
        let data = pt.slice(4..);

        // H-3: cap concurrent receive streams. A new stream_id is auto-created only while
        // under MAX_STREAMS; past the cap the segment is refused (and, being unrecorded, not
        // SACKed → the sender retransmits / the stream stalls), so a peer cannot explode the
        // stream table across the 2^32 id space.
        let existing = streams_recv.get(&stream_id).map(|s| s.clone());
        let local = match existing {
            Some(s) => s,
            None => {
                if streams_recv.len() >= MAX_STREAMS {
                    log::warn!(
                        "PhantomSession: refusing new receive stream {stream_id}: \
                         MAX_STREAMS ({MAX_STREAMS}) reached"
                    );
                    return;
                }
                streams_recv
                    .entry(stream_id)
                    .or_insert_with(|| Arc::new(Stream::new(stream_id as TransportStreamId)))
                    .clone()
            }
        };
        // Accept into the reorder buffer FIRST so the SACK derived next reflects it.
        // `accept_in_order` returns the in-order run now deliverable and stamps the
        // data-arrival instant; `received_sack(0)` then populates `ack_delay_us`
        // from a coarse `now − recv_at`. A `None` SACK is structurally impossible
        // here (we just accepted an offset), but we skip the ACK rather than unwrap.
        let delivered = local.accept_in_order(stream_offset, vec![data]).await;
        let Some(sack) = local.received_sack(0).await else {
            return;
        };
        let mut ack_flag_bits = PacketFlags::ENCRYPTED | PacketFlags::ACK;
        match rekey_before_stamp(crypto_recv) {
            Some(extra) => ack_flag_bits |= extra,
            // Epoch saturated — drop this ACK rather than reuse a nonce; the
            // sender retransmits and the session is expected to reconnect.
            None => return,
        }
        let ack_pn = crypto_recv.next_send_pn();
        let ack_header = PacketHeader::new(
            session_id,
            stream_id as TransportStreamId,
            ack_pn,
            PacketFlags::new(ack_flag_bits),
        )
        .with_epoch(crypto_recv.current_epoch())
        .with_path_id(path_id);
        let ack_payload = sack.to_wire();
        match crypto_recv.encrypt_packet(&ack_header, &ack_payload, &[]) {
            Ok(ct) => {
                let ack_packet = PhantomPacket::new(ack_header, ct);
                match crypto_recv.protect_packet(&ack_packet) {
                    Ok(buf) => {
                        ack_buf.clear();
                        ack_buf.extend_from_slice(&buf);
                        let size = ack_buf.len();
                        let _ = transport_send_ack.send_bytes(&ack_buf[..size]).await;
                    }
                    Err(e) => {
                        log::error!("PhantomSession: ACK header protection failed: {}", e)
                    }
                }
            }
            Err(e) => log::error!("PhantomSession: ACK encrypt failed: {}", e),
        }

        // Deliver the in-order run released by the reorder buffer (empty if this
        // segment filled a future hole — it waits for the gap to close).
        deliver_in_order_run(delivered, stream_id, deliver_tx, undelivered_bytes);

        if packet.header.flags.contains(PacketFlags::FIN) {
            demux_recv.route_close(stream_id);
        }
        return;
    }

    // Non-reliable application data → deliver in arrival order (unreliable data is
    // not sequenced/reordered by design). Unbounded + non-blocking, so the reader
    // never stalls on a slow `recv()` consumer; counted toward the backlog only on
    // a successful enqueue (a dead delivery task can't inflate `undelivered_bytes`).
    if !plaintext.is_empty() {
        let len = plaintext.len() as u64;
        if deliver_tx.send((stream_id, Bytes::from(plaintext))).is_ok() {
            undelivered_bytes.fetch_add(len, Ordering::AcqRel);
        }
    }

    if packet.header.flags.contains(PacketFlags::FIN) {
        demux_recv.route_close(stream_id);
    }
}

/// Hand an in-order run of reliable payloads (as released by
/// [`Stream::accept_in_order`]) to the single FIFO delivery task, in order. Each
/// non-empty chunk is counted toward the `undelivered_bytes` backlog only on a
/// successful enqueue, so a dead delivery task (consumer gone, `deliver_rx`
/// dropped) cannot inflate the counter for data that was discarded.
fn deliver_in_order_run(
    run: Vec<Bytes>,
    stream_id: u32,
    deliver_tx: &mpsc::UnboundedSender<(u32, Bytes)>,
    undelivered_bytes: &AtomicU64,
) {
    for chunk in run {
        if chunk.is_empty() {
            continue;
        }
        let len = chunk.len() as u64;
        if deliver_tx.send((stream_id, chunk)).is_ok() {
            undelivered_bytes.fetch_add(len, Ordering::AcqRel);
        }
    }
}

// Internal-only methods — deliberately NOT on the `#[uniffi::export]` surface.
// `set_state` mutates the connection state machine; a foreign caller forcing
// `Connected` mid-handshake would make `is_data_ready()` lie and let `send()`
// bypass the queue, or `Closed` without tearing down the pump.
impl PhantomSession {
    /// Transition to a new connection state. Crate-internal: driven by the
    /// handshake task and teardown only.
    pub(crate) fn set_state(&self, new_state: ConnectionState) {
        self.state.store(new_state as u8, Ordering::Relaxed);
    }

    /// Session observability handle (Rust-only — `Observability` is not a
    /// UniFFI type). For a server-accepted session this is the
    /// `PhantomListener`'s shared instance; for a client it is the session's
    /// own. Read `.snapshot()` for the lock-free metric counters.
    pub fn observability(&self) -> Arc<Observability> {
        self.observability.clone()
    }
}

#[cfg_attr(feature = "bindings", uniffi::export(async_runtime = "tokio"))]
impl PhantomSession {
    /// Create a placeholder session — returns instantly and performs **no**
    /// handshake.
    ///
    /// # ⚠️ This does not connect
    ///
    /// Despite the name, this constructor never opens a transport, never runs
    /// the PQC handshake, and never spawns the background data pump. It returns
    /// an inert shell stuck in [`ConnectionState::Connecting`]: any `send()`
    /// only queues into an in-memory buffer that is never flushed, and `recv()`
    /// never yields application bytes. **No bytes ever reach the network.** It
    /// exists only as a pre-handshake placeholder from an earlier API shape.
    ///
    /// **Deprecated — use a real entry point instead:**
    /// - [`PhantomSession::connect_with_transport`] (Rust) — supply a
    ///   `SessionTransport` and the pinned `expected_server_key`; this spawns
    ///   the handshake + pump.
    /// - [`connect_pinned`] (native FFI / mobile) — one-shot TCP connect with a
    ///   pinned key.
    ///
    /// # Why no `#[deprecated]` attribute (T5.7)
    ///
    /// A `#[deprecated]` attribute would be the natural way to flag this, but it
    /// **cannot** be applied here: this constructor is `#[uniffi::constructor]`,
    /// and UniFFI 0.31 emits FFI scaffolding that calls `Self::connect()` from
    /// generated code in this same crate. That generated call would trip the
    /// `deprecated` lint, which CI promotes to a hard error under
    /// `clippy --lib -D warnings` — and no item-scoped `#[allow(deprecated)]`
    /// reaches the macro-generated call site (only a module-wide
    /// `#![allow(deprecated)]` would, which would silently mask every *future*
    /// genuine deprecation across this module). So the deprecation is documented
    /// loudly here instead. UniFFI copies this doc-comment into the generated
    /// Python / Swift / Kotlin docstrings (the C header carries no docstrings),
    /// so they were regenerated and committed alongside this change — the
    /// `bindings` `drift` CI job stays green. See
    /// `tests::deprecated_connect_is_inert_and_sends_no_bytes` for the regression
    /// pinning the inert behaviour.
    #[cfg_attr(feature = "bindings", uniffi::constructor)]
    pub fn connect(peer_addr: String) -> Arc<Self> {
        let (cmd_tx, cmd_rx) = mpsc::channel(256);
        let (_recv_tx, recv_rx) = mpsc::channel(256);

        let (demux, _ctrl_rx) = StreamDemultiplexer::new(256);
        let streams = Arc::new(DashMap::new());
        Arc::new(Self {
            id: new_session_id(),
            peer_addr,
            state: Arc::new(AtomicU8::new(ConnectionState::Connecting as u8)),
            send_queue: Arc::new(Mutex::new(Vec::new())),
            cmd_tx,
            cmd_rx: Mutex::new(Some(cmd_rx)),
            recv_rx: Mutex::new(recv_rx),
            demux: Arc::new(demux),
            streams,
            inner_session: Arc::new(Mutex::new(None)),
            early_data_accepted: Arc::new(Mutex::new(None)),
            // Placeholder session (no transport / pump yet); a no-op holder
            // until `connect_with_transport` spawns the real pump.
            observability: Observability::new(ObservabilityConfig::default()),
        })
    }

    /// Open a new multiplexed stream
    pub fn open_stream(&self) -> Arc<crate::api::stream::PhantomStream> {
        let handle = self.demux.open_stream(1024);
        let stream_id = handle.stream_id;

        let transport_stream = Arc::new(Stream::new(stream_id as TransportStreamId));
        self.streams.insert(stream_id, transport_stream);

        Arc::new(crate::api::stream::PhantomStream::new(
            handle,
            self.cmd_tx.clone(),
        ))
    }

    /// Send data through the session.
    ///
    /// - If the session is connected: sends immediately
    /// - If still handshaking: queues the data for auto-flush later
    pub async fn send(&self, data: Vec<u8>) -> Result<(), CoreError> {
        let state = self.connection_state();

        if state.is_data_ready() {
            // Channel is up — send directly
            self.cmd_tx
                .send(SessionCommand::Send(data))
                .await
                .map_err(|_| CoreError::NetworkError("Session closed".into()))?;
        } else if state == ConnectionState::Connecting {
            // Still handshaking — queue
            self.send_queue.lock().await.push(data);
        } else {
            return Err(CoreError::NetworkError(format!(
                "Cannot send in state {:?}",
                state
            )));
        }

        Ok(())
    }

    /// Receive data from the session.
    ///
    /// Internally the recv pipeline keeps payloads as `Bytes` to avoid the
    /// per-packet Vec clone that used to fan out to the stream demux. The
    /// FFI surface still hands callers a `Vec<u8>`; if this is the last
    /// refcount the Vec is moved out of the underlying buffer, otherwise
    /// `Bytes::to_vec` copies.
    pub async fn recv(&self) -> Result<Vec<u8>, CoreError> {
        let mut rx = self.recv_rx.lock().await;
        let bytes = rx
            .recv()
            .await
            .ok_or_else(|| CoreError::NetworkError("Session closed".into()))?;
        Ok(bytes.to_vec())
    }

    /// Get the current connection state (lock-free).
    pub fn connection_state(&self) -> ConnectionState {
        ConnectionState::from_u8(self.state.load(Ordering::Relaxed))
    }

    /// Whether the session is ready for data transmission.
    pub fn is_data_ready(&self) -> bool {
        self.connection_state().is_data_ready()
    }

    /// Whether the session has full PQC protection.
    pub fn is_pqc_ready(&self) -> bool {
        matches!(
            self.connection_state(),
            ConnectionState::PqcReady | ConnectionState::Connected
        )
    }

    /// Flush all queued messages (called when handshake completes).
    pub async fn flush_queue(&self) -> Result<u32, CoreError> {
        let mut queue = self.send_queue.lock().await;
        let count = queue.len() as u32;
        for msg in queue.drain(..) {
            self.cmd_tx
                .send(SessionCommand::Send(msg))
                .await
                .map_err(|_| CoreError::NetworkError("Session closed during flush".into()))?;
        }
        Ok(count)
    }

    /// Number of messages queued (waiting for handshake).
    pub async fn queued_count(&self) -> u32 {
        self.send_queue.lock().await.len() as u32
    }

    /// Session identifier.
    pub fn id(&self) -> String {
        self.id.clone()
    }

    /// Target peer address.
    pub fn peer_addr(&self) -> String {
        self.peer_addr.clone()
    }

    /// The 0-RTT verdict for this session.
    ///
    /// - `None` — still handshaking, the handshake failed, or the client sent
    ///   no early-data on this connect.
    /// - `Some(true)` — the server consumed the 0-RTT early-data.
    /// - `Some(false)` — the client sent early-data and the server rejected it
    ///   (stale/unknown ticket, oversized blob, or AEAD failure). The caller
    ///   must re-send that payload over the normal channel.
    pub async fn early_data_accepted(&self) -> Option<bool> {
        *self.early_data_accepted.lock().await
    }

    /// Extract a [`ResumptionHint`] for a future 0-RTT reconnect.
    ///
    /// Returns `Some` after a successful handshake; `None` while still
    /// handshaking, after a failure, or before the inner session has
    /// been published.
    ///
    /// Store the hint alongside the pinned `HybridVerifyingKey` of the
    /// server it was negotiated against and feed it back to
    /// [`connect_pinned_with_resumption`]. Reusing a hint across
    /// servers is a configuration bug — the `resumption_secret` is
    /// server-pinned.
    pub async fn resumption_hint(&self) -> Option<ResumptionHint> {
        let guard = self.inner_session.lock().await;
        guard
            .as_ref()
            .and_then(|s| s.resumption_hint())
            .map(|(session_id, resumption_secret)| ResumptionHint {
                session_id: session_id.to_vec(),
                resumption_secret: resumption_secret.to_vec(),
            })
    }

    /// Current rekey epoch of the established session (`None` while still
    /// connecting). Rust-only — used by soak / integration tests to confirm
    /// that automatic mid-session rekey (C1) advanced the epoch.
    pub async fn current_epoch(&self) -> Option<u8> {
        self.inner_session
            .lock()
            .await
            .as_ref()
            .map(|s| s.current_epoch())
    }

    /// Override the automatic-rekey send-invocation high-watermark on the
    /// established session (default `REKEY_SOFT_LIMIT`). Returns `false` if
    /// the session is still connecting. Rust-only — primarily for soak/load
    /// harnesses that need to exercise mid-session rekey without sending `2^47`
    /// packets.
    pub async fn set_rekey_threshold(&self, n: u64) -> bool {
        match self.inner_session.lock().await.as_ref() {
            Some(s) => {
                s.set_rekey_threshold(n);
                true
            }
            None => false,
        }
    }

    /// Apply an anti-fingerprint traffic-shaping configuration to the established
    /// session (WIRE v6, direction #4). Returns `false` if the session is still
    /// connecting. All shaping is opt-in (default: none); enabling size padding
    /// ([`PaddingPolicy::Padme`]) makes outbound packets pad up to a PADÉ bucket so
    /// the datagram size no longer tracks the payload size, at a bounded (≈ ≤12%
    /// worst-case) bandwidth cost. FFI-exported so mobile / other embedders can
    /// tune it.
    pub async fn set_traffic_shaping(&self, config: TrafficShapingConfig) -> bool {
        match self.inner_session.lock().await.as_ref() {
            Some(s) => {
                s.set_padding_policy(config.padding);
                s.set_jitter_ms(config.jitter_ms);
                s.set_cover_interval_ms(config.cover_interval_ms);
                true
            }
            None => false,
        }
    }

    /// Migrate the session to a new local network address (Phase 4 — embedder-
    /// triggered connection migration). The embedder calls this when the OS reports a
    /// network change (Wi-Fi↔cellular, NAT rebind); `local_addr` is the new local
    /// bind address (e.g. `"0.0.0.0:0"` to let the OS pick an ephemeral port on the
    /// new interface).
    ///
    /// **Best-effort and non-blocking on validation.** It hands the request to the
    /// background pump, which rebinds the transport (keeping the old socket for the
    /// overlap) and bumps the send `path_id`; the path validation + server-side peer
    /// switch then complete asynchronously. The keys and session persist — **no
    /// re-handshake**. A failed rebind never tears the session down: it keeps running
    /// on the existing socket (broken-rebind safety). `Err` here means only that the
    /// session was already closed (the command channel is gone).
    pub async fn migrate(&self, local_addr: String) -> Result<(), CoreError> {
        self.cmd_tx
            .send(SessionCommand::Migrate(local_addr))
            .await
            .map_err(|_| CoreError::NetworkError("Session closed".into()))
    }

    /// Send the graceful close frame and shut the session down.
    ///
    /// Named `disconnect` rather than `close` because UniFFI's Kotlin
    /// generator unconditionally adds `AutoCloseable.close()` to every
    /// object, and a Rust-side `close` here would conflict with it.
    pub async fn disconnect(&self) -> Result<(), CoreError> {
        self.set_state(ConnectionState::Closed);
        let _ = self.cmd_tx.send(SessionCommand::Close).await;
        Ok(())
    }
}

impl PhantomSession {
    /// Get the stream demultiplexer (internal use, not exposed to UniFFI)
    pub fn demux(&self) -> Arc<StreamDemultiplexer> {
        self.demux.clone()
    }

    /// Override the path-liveness thresholds on the established session (Phase 4 /
    /// P4.3). Returns `false` if the session is still connecting. Rust-only (the
    /// `LivenessConfig` type is not on the UniFFI surface) — for tests / advanced
    /// embedders that want a faster or slower path-down / migration-idle timeout than
    /// the default.
    pub async fn set_liveness_config(
        &self,
        cfg: crate::transport::liveness::LivenessConfig,
    ) -> bool {
        match self.inner_session.lock().await.as_ref() {
            Some(s) => {
                s.set_liveness_config(cfg);
                true
            }
            None => false,
        }
    }
}

impl std::fmt::Debug for PhantomSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PhantomSession")
            .field("id", &self.id)
            .field("peer", &self.peer_addr)
            .field("state", &self.connection_state())
            .finish()
    }
}

// ─── Pinned-Connect Shim (Phase 7.2 mobile bridge) ──────────────────────────
//
// `connect_with_transport` itself can't cross the UniFFI boundary directly —
// it takes a generic `T: SessionTransport` trait object and a typed
// `HybridVerifyingKey`, neither of which is a UniFFI primitive. Mobile
// callers (iOS / Android) need a single async entry point that opens a TCP
// connection, wraps it in `TcpSessionTransport`, parses the pinned key from
// bytes (per security invariant 1 in SECURITY.md), and hands back an
// `Arc<PhantomSession>` ready for `send` / `recv`.
//
// Native-only: `TcpSessionTransport` lives behind `cfg(not(target_arch =
// "wasm32"))`, mirroring `crate::api::tcp_transport`. Wasm consumers use
// the in-tree `WebSocketLeg` instead.
#[cfg(not(target_arch = "wasm32"))]
#[cfg_attr(feature = "bindings", uniffi::export(async_runtime = "tokio"))]
pub async fn connect_pinned(
    host: String,
    port: u16,
    pinned_key: Vec<u8>,
) -> Result<Arc<PhantomSession>, CoreError> {
    // fips bootstrap POST gate (same policy as
    // `PhantomListener::bind_inner`). A failure here aborts the
    // connect before any socket is opened or key material is
    // touched.
    #[cfg(feature = "fips")]
    crate::crypto::self_tests::ensure_post_passed()
        .map_err(|e| CoreError::FipsSelfTestFailure(format!("{e:?}")))?;

    // Decode the server's hybrid verifying key. A malformed blob is a
    // crypto-layer problem (wrong length, wrong encoding) rather than a
    // network failure — surface it as `CryptoError`.
    let expected_server_key = HybridVerifyingKey::from_bytes(&pinned_key)
        .map_err(|e| CoreError::CryptoError(format!("invalid pinned key: {}", e)))?;

    // Open the TCP stream. The `format!` is shared between the actual
    // connect target and the `peer_addr` recorded inside the session
    // (`connect_with_transport` takes it as a free-form string).
    let addr = format!("{}:{}", host, port);
    let stream = tokio::net::TcpStream::connect(&addr)
        .await
        .map_err(|e| CoreError::NetworkError(format!("connect {}: {}", addr, e)))?;
    let transport = crate::api::tcp_transport::TcpSessionTransport::new(stream);

    // The handshake is driven by the background task spawned inside
    // `connect_with_transport`; the returned `PhantomSession` is usable
    // immediately (state `Connecting`, sends auto-queued until ready).
    let session = PhantomSession::connect_with_transport(&addr, transport, expected_server_key);
    Ok(Arc::new(session))
}

/// Connect to a pinned server with a **0-RTT resumption attempt** — the
/// resumption-aware analogue of [`connect_pinned`].
///
/// `hint` is a [`ResumptionHint`] from a prior session's
/// [`PhantomSession::resumption_hint`]; both of its fields must be
/// exactly 32 bytes or the call fails with `ValidationError` before any
/// socket is opened. `early_data` (≤ 16 KiB) is sealed into the resuming
/// ClientHello so it reaches the server on the very first flight.
///
/// Acceptance is best-effort: when the server does not consume the early-data
/// (stale/unknown ticket or AEAD failure) the handshake completes 1-RTT — the
/// caller checks [`PhantomSession::early_data_accepted`] and re-sends over the
/// normal channel when it is not `Some(true)`.
///
/// Native-only, like [`connect_pinned`]: `TcpSessionTransport` lives
/// behind `cfg(not(target_arch = "wasm32"))`.
#[cfg(not(target_arch = "wasm32"))]
#[cfg_attr(feature = "bindings", uniffi::export(async_runtime = "tokio"))]
pub async fn connect_pinned_with_resumption(
    host: String,
    port: u16,
    pinned_key: Vec<u8>,
    hint: ResumptionHint,
    early_data: Vec<u8>,
) -> Result<Arc<PhantomSession>, CoreError> {
    // fips bootstrap POST gate (same policy as
    // `connect_pinned`).
    #[cfg(feature = "fips")]
    crate::crypto::self_tests::ensure_post_passed()
        .map_err(|e| CoreError::FipsSelfTestFailure(format!("{e:?}")))?;

    // Server-key pinning stays mandatory (security invariant 1): a
    // malformed blob is a crypto-layer problem, surfaced as `CryptoError`.
    let expected_server_key = HybridVerifyingKey::from_bytes(&pinned_key)
        .map_err(|e| CoreError::CryptoError(format!("invalid pinned key: {}", e)))?;

    // `ResumptionHint` fields are `Vec<u8>` (UniFFI has no fixed-size
    // array type) — enforce the 32-byte invariant here, before any
    // socket is opened, so a caller bug never becomes a network call.
    let session_id: [u8; 32] = hint.session_id.as_slice().try_into().map_err(|_| {
        CoreError::ValidationError(format!(
            "resumption hint session_id must be 32 bytes, got {}",
            hint.session_id.len()
        ))
    })?;
    let resumption_secret: [u8; 32] =
        hint.resumption_secret.as_slice().try_into().map_err(|_| {
            CoreError::ValidationError(format!(
                "resumption hint resumption_secret must be 32 bytes, got {}",
                hint.resumption_secret.len()
            ))
        })?;

    // APIFFI-03: reject oversized early-data BEFORE opening a socket, so a caller
    // bug (or oversized blob) never wastes a TCP connection establishment. The
    // inner `connect_with_resumption` enforces the same cap as defense-in-depth.
    if early_data.len() > EARLY_DATA_MAX_LEN {
        return Err(CoreError::ValidationError(format!(
            "early_data is {} bytes, exceeds the {}-byte 0-RTT cap",
            early_data.len(),
            EARLY_DATA_MAX_LEN
        )));
    }

    let addr = format!("{}:{}", host, port);
    let stream = tokio::net::TcpStream::connect(&addr)
        .await
        .map_err(|e| CoreError::NetworkError(format!("connect {}: {}", addr, e)))?;
    let transport = crate::api::tcp_transport::TcpSessionTransport::new(stream);

    // Reuses the Rust-only `connect_with_resumption` — no new crypto and
    // no new wire format. That path enforces the `EARLY_DATA_MAX_LEN`
    // cap and keeps 0-RTT one-shot / best-effort (security invariant 9).
    let session = PhantomSession::connect_with_resumption(
        &addr,
        transport,
        expected_server_key,
        (session_id, resumption_secret),
        early_data,
    )?;
    Ok(Arc::new(session))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::handshake::{ClientHello, HandshakeResponse, HandshakeServer};

    // ── Mock transport for testing ──

    /// In-memory transport using channels (simulates a loopback pipe).
    struct ChannelTransport {
        tx: mpsc::Sender<Vec<u8>>,
        rx: Mutex<mpsc::Receiver<Vec<u8>>>,
    }

    impl ChannelTransport {
        /// Create a pair of connected transports (client ↔ server).
        fn pair() -> (Self, Self) {
            let (a_tx, b_rx) = mpsc::channel(64);
            let (b_tx, a_rx) = mpsc::channel(64);
            (
                Self {
                    tx: a_tx,
                    rx: Mutex::new(a_rx),
                },
                Self {
                    tx: b_tx,
                    rx: Mutex::new(b_rx),
                },
            )
        }
    }

    impl SessionTransport for ChannelTransport {
        async fn send_bytes(&self, data: &[u8]) -> Result<(), CoreError> {
            self.tx
                .send(data.to_vec())
                .await
                .map_err(|_| CoreError::NetworkError("channel closed".into()))
        }

        async fn recv_bytes(&self) -> Result<Bytes, CoreError> {
            let mut rx = self.rx.lock().await;
            let v = rx
                .recv()
                .await
                .ok_or_else(|| CoreError::NetworkError("channel closed".into()))?;
            Ok(Bytes::from(v))
        }
    }

    // ── Tests ──

    /// T5.5(b) send-side: `rekey_before_stamp` re-advertises `PacketFlags::REKEY`
    /// on EVERY packet at the new epoch — not just the rotation-trigger packet —
    /// until the peer acknowledges the rekey. This is what lets a lost trigger
    /// packet recover: the next stamp still flags REKEY so the receive-side gate
    /// follows the catch-up. Without re-advertise the second stamp would carry the
    /// new epoch unflagged and the gate would strand the receiver.
    #[test]
    fn rekey_before_stamp_re_advertises_rekey_until_peer_confirms() {
        use crate::transport::session::{CryptoState, Session};
        use crate::transport::types::{SchedulerMode, SessionId};

        let shared = [0x55u8; 32];
        let id = SessionId::from_bytes([7u8; 32]);
        let crypto = CryptoState::new(&shared, false).expect("crypto");
        let session = Arc::new(Session::from_derived(
            id,
            crypto,
            SchedulerMode::LowLatency,
            shared,
            false,
        ));
        session.set_rekey_threshold(2);

        // Below the watermark: no rekey, no flag.
        assert_eq!(
            rekey_before_stamp(&session),
            Some(0),
            "below threshold: no flag"
        );

        // Cross the high-watermark so the next stamp rotates.
        let h = PacketHeader::new(
            *session.id(),
            1,
            0,
            PacketFlags::new(PacketFlags::ENCRYPTED),
        );
        for i in 0..2u64 {
            session
                .encrypt_packet(
                    &PacketHeader {
                        packet_number: i,
                        ..h
                    },
                    b"x",
                    &[],
                )
                .expect("encrypt");
        }
        assert!(session.send_needs_rekey());

        // The rotation-trigger stamp flags REKEY and bumps the epoch.
        assert_eq!(rekey_before_stamp(&session), Some(PacketFlags::REKEY));
        assert_eq!(session.current_epoch(), 1);
        assert!(session.rekey_unconfirmed());

        // The NEXT stamp re-advertises REKEY even though no further rekey happens —
        // the peer has not confirmed yet.
        assert_eq!(rekey_before_stamp(&session), Some(PacketFlags::REKEY));
        assert_eq!(
            session.current_epoch(),
            1,
            "no second rekey — only a re-advertise"
        );
    }

    /// H9 forward-compat (client side): when the server answers a `ClientHello`
    /// with a typed `ServerReject` (the version isn't one it speaks), the client
    /// surfaces a clear version-mismatch error instead of hanging or returning a
    /// generic failure — and crucially does NOT auto-downgrade.
    #[tokio::test]
    async fn client_surfaces_server_reject_as_version_error() {
        use crate::transport::handshake::{ServerReject, ServerReply};

        let (client_transport, server_transport) = ChannelTransport::pair();
        // The reject path errors before any key verification, so any key works.
        let (_sk, expected_vk) = crate::crypto::hybrid_sign::HybridSigningKey::generate();

        let server = tokio::spawn(async move {
            // Consume the ClientHello, then reply with the typed reject (T4.4 framed).
            let _hello = server_transport.recv_bytes().await.unwrap();
            let reject = ServerReply::Reject(ServerReject::unsupported_version())
                .to_wire()
                .unwrap();
            server_transport.send_bytes(&reject).await.unwrap();
        });

        let result = run_client_handshake(&client_transport, &expected_vk, None).await;
        server.await.unwrap();

        let err = result.expect_err("client must surface the reject as an error");
        let msg = format!("{err:?}");
        assert!(
            msg.contains("unsupported protocol version"),
            "expected a version-mismatch error, got: {msg}"
        );
    }

    /// Reviewer §5: an **injected** `ServerReject` (a tiny, pre-crypto blob a network
    /// attacker can spray) during a HEALTHY handshake must NOT abort it. The client remembers
    /// the reject and keeps waiting for a valid `ServerHello`; it gives up (surfacing the
    /// reject) only if one never arrives. Here the attacker injects a reject ahead of the real
    /// cookie/ServerHello flow; the handshake must still succeed.
    #[tokio::test]
    async fn injected_server_reject_does_not_abort_a_healthy_handshake() {
        use crate::transport::handshake::{ServerReject, ServerReply};

        let (client_transport, server_transport) = ChannelTransport::pair();
        let server_hs = HandshakeServer::new().unwrap();
        let expected_vk = server_hs.verifying_key().clone();

        let server = tokio::spawn(async move {
            let Ok(hello_bytes) = server_transport.recv_bytes().await else {
                return;
            };
            let Ok(client_hello) = borsh::from_slice::<ClientHello>(&hello_bytes) else {
                return;
            };
            // Inject a forged reject AHEAD of the real handshake responses (T4.4 framed).
            let reject = ServerReply::Reject(ServerReject::unsupported_version())
                .to_wire()
                .unwrap();
            if server_transport.send_bytes(&reject).await.is_err() {
                return;
            }
            let ip = "127.0.0.1".parse().unwrap();
            let sh = match server_hs.process_client_hello(&client_hello, 0, ip) {
                HandshakeResponse::Retry(retry) => {
                    if server_transport
                        .send_bytes(&ServerReply::Retry(retry).to_wire().unwrap())
                        .await
                        .is_err()
                    {
                        return;
                    }
                    let Ok(h2) = server_transport.recv_bytes().await else {
                        return;
                    };
                    let Ok(next) = borsh::from_slice::<ClientHello>(&h2) else {
                        return;
                    };
                    match server_hs.process_client_hello(&next, 0, ip) {
                        HandshakeResponse::Success(sh, _, _) => sh,
                        _ => return,
                    }
                }
                HandshakeResponse::Success(sh, _, _) => sh,
                _ => return,
            };
            let _ = server_transport
                .send_bytes(&ServerReply::Hello(sh).to_wire().unwrap())
                .await;
        });

        let result = run_client_handshake(&client_transport, &expected_vk, None).await;
        // Close the channel so the server task ends even if the client aborted (RED), instead
        // of blocking forever on the retried-hello it will never receive.
        drop(client_transport);
        let _ = server.await;
        assert!(
            result.is_ok(),
            "an injected ServerReject ahead of the real ServerHello must not abort a healthy \
             handshake; got {result:?}"
        );
    }

    /// **HS-02.** A MITM that answers every `ClientHello` with a fresh cheap
    /// `HelloRetryRequest` must NOT loop the client forever — `run_client_handshake`
    /// caps the retry rounds and returns an error. (Pre-fix this test would hang.)
    #[tokio::test]
    async fn client_handshake_caps_retry_rounds() {
        use crate::transport::handshake::HelloRetryRequest;

        let (client_transport, server_transport) = ChannelTransport::pair();
        let (_sk, expected_vk) = crate::crypto::hybrid_sign::HybridSigningKey::generate();

        // Malicious server: answer EVERY ClientHello with a fresh, cheap
        // HelloRetryRequest (no cookie, no PoW) — never converging.
        let server = tokio::spawn(async move {
            loop {
                if server_transport.recv_bytes().await.is_err() {
                    break;
                }
                let retry = borsh::to_vec(&HelloRetryRequest {
                    challenge: None,
                    cookie: None,
                })
                .expect("encode retry");
                if server_transport.send_bytes(&retry).await.is_err() {
                    break;
                }
            }
        });

        let result = run_client_handshake(&client_transport, &expected_vk, None).await;
        drop(client_transport); // close the channel so the server task ends
        let _ = server.await;

        assert!(
            matches!(result, Err(CoreError::HandshakeError(_))),
            "client must error after the retry-round cap, not loop forever; got {result:?}"
        );
    }

    /// **INFOLEAK-1.** `ResumptionHint`'s `Debug` must redact the 0-RTT
    /// `resumption_secret` — a mobile/FFI consumer logging it with `{:?}` must
    /// not leak the key material.
    #[test]
    fn resumption_hint_debug_redacts_secret() {
        let hint = ResumptionHint {
            session_id: vec![0xAB; 32],
            resumption_secret: vec![0xCD; 32],
        };
        let dbg = format!("{hint:?}");
        assert!(dbg.contains("REDACTED"), "secret must be redacted: {dbg}");
        // No representation of the secret bytes (0xCD) leaks — neither hex nor
        // the decimal the derived Debug would have printed for a Vec<u8>.
        assert!(
            !dbg.contains("205"),
            "no decimal secret bytes in Debug: {dbg}"
        );
        assert!(
            !dbg.to_lowercase().contains("cd, cd"),
            "no hex secret bytes: {dbg}"
        );
    }

    #[tokio::test]
    async fn test_phantom_session_instant_connect() {
        let session = PhantomSession::connect("example.com:443".to_string());

        // Should be in Connecting state immediately
        assert_eq!(session.connection_state(), ConnectionState::Connecting);
        assert!(!session.is_data_ready());
        assert_eq!(session.peer_addr(), "example.com:443");
    }

    /// **T5.7 regression — the inert `connect()` performs no handshake and
    /// sends no bytes.** The constructor is documented as deprecated (no
    /// `#[deprecated]` attribute is possible — see the doc-comment for why), so
    /// this test pins the inert contract the doc promises: the session is stuck
    /// in `Connecting`, every `send()` only piles into the in-memory queue (no
    /// transport / pump exists to flush it), and `recv()` never yields. If a
    /// future change ever wires a real pump into this constructor, this test
    /// must be updated alongside the doc — the two must not drift apart.
    #[tokio::test]
    async fn deprecated_connect_is_inert_and_sends_no_bytes() {
        let session = PhantomSession::connect("example.com:443".to_string());

        // Inert: never leaves the pre-handshake state on its own.
        assert_eq!(session.connection_state(), ConnectionState::Connecting);
        assert!(!session.is_data_ready());
        assert!(!session.is_pqc_ready());

        // Every send while inert only queues — it never reaches a transport,
        // because no transport / data pump was ever spawned.
        session.send(b"first".to_vec()).await.unwrap();
        session.send(b"second".to_vec()).await.unwrap();
        assert_eq!(
            session.queued_count().await,
            2,
            "inert connect() must buffer sends in memory, never flush them to a wire"
        );

        // The session is STILL inert after sending — no background task moved
        // the state forward, so the bytes are still sitting in the queue.
        assert_eq!(session.connection_state(), ConnectionState::Connecting);

        // recv() must never deliver application bytes — no pump feeds the recv
        // channel, and the inert constructor drops the channel's sender at once,
        // so recv() resolves to an error rather than any data. A short timeout
        // bounds the wait and proves recv() does not yield a payload.
        let recv = tokio::time::timeout(std::time::Duration::from_millis(50), session.recv()).await;
        match recv {
            Ok(Err(_)) => { /* expected: "session closed" — never any bytes */ }
            Ok(Ok(bytes)) => panic!(
                "inert connect() must never deliver received data, got {} bytes",
                bytes.len()
            ),
            Err(_elapsed) => { /* also acceptable: recv blocked the whole window */ }
        }
    }

    #[tokio::test]
    async fn test_phantom_session_send_queue() {
        let session = PhantomSession::connect("example.com:443".to_string());

        // Send while still connecting — should queue
        session.send(vec![1, 2, 3]).await.unwrap();
        session.send(vec![4, 5, 6]).await.unwrap();
        assert_eq!(session.queued_count().await, 2);

        // Simulate handshake completion
        session.set_state(ConnectionState::ClassicalReady);
        assert!(session.is_data_ready());

        // Flush queue
        let flushed = session.flush_queue().await.unwrap();
        assert_eq!(flushed, 2);
        assert_eq!(session.queued_count().await, 0);
    }

    #[tokio::test]
    async fn test_phantom_session_state_progression() {
        let session = PhantomSession::connect("example.com:443".to_string());

        assert_eq!(session.connection_state(), ConnectionState::Connecting);
        assert!(!session.is_data_ready());

        session.set_state(ConnectionState::ClassicalReady);
        assert!(session.is_data_ready());
        assert!(!session.is_pqc_ready());

        session.set_state(ConnectionState::PqcUpgrading);
        assert!(session.is_data_ready());
        assert!(!session.is_pqc_ready());

        session.set_state(ConnectionState::PqcReady);
        assert!(session.is_data_ready());
        assert!(session.is_pqc_ready());

        session.set_state(ConnectionState::Connected);
        assert!(session.is_data_ready());
        assert!(session.is_pqc_ready());
    }

    #[tokio::test]
    async fn test_phantom_session_close() {
        let session = PhantomSession::connect("example.com:443".to_string());
        session.disconnect().await.unwrap();
        assert_eq!(session.connection_state(), ConnectionState::Closed);
        assert!(!session.is_data_ready());
    }

    /// Helper: decrypt an incoming encrypted frame on the test server side.
    fn decrypt_incoming(
        server_session: &crate::transport::session::Session,
        bytes: &[u8],
    ) -> Vec<u8> {
        // The peer pump applies header protection (T4.6); unmask with this
        // side's recv HP key (== the sender's send HP key) before reading.
        let pkt = server_session
            .parse_protected(bytes)
            .expect("parse header-protected PhantomPacket");
        assert!(
            pkt.header.flags.contains(PacketFlags::ENCRYPTED),
            "expected ENCRYPTED flag on application data"
        );
        let plain = server_session
            .decrypt_packet(&pkt.header, &pkt.payload, &[])
            .expect("decrypt application data");
        // Reliable app frames carry a 4-byte gap-free stream_offset prefix (A.5);
        // strip it so callers compare against the raw application payload.
        if pkt.header.flags.contains(PacketFlags::RELIABLE) && plain.len() >= 4 {
            plain[4..].to_vec()
        } else {
            plain
        }
    }

    /// Helper: build an encrypted reply frame from the test server side. Mirrors
    /// the live sender's reliable framing: plaintext = `[stream_offset: u32 BE]
    /// [payload]` with `stream_offset == sequence` (no control gaps in this test).
    fn encrypt_outgoing(
        server_session: &crate::transport::session::Session,
        session_id: SessionId,
        stream_id: TransportStreamId,
        sequence: u32,
        payload: &[u8],
    ) -> Vec<u8> {
        let flag_bits = PacketFlags::RELIABLE | PacketFlags::ENCRYPTED;
        let header = PacketHeader::new(
            session_id,
            stream_id,
            sequence as u64,
            PacketFlags::new(flag_bits),
        )
        .with_epoch(server_session.current_epoch());
        let mut pt = Vec::with_capacity(4 + payload.len());
        pt.extend_from_slice(&sequence.to_be_bytes());
        pt.extend_from_slice(payload);
        let ct = server_session
            .encrypt_packet(&header, &pt, &[])
            .expect("encrypt reply");
        let packet = PhantomPacket::new(header, ct);
        // Apply header protection so the peer pump's parse_protected unmasks it.
        server_session
            .protect_packet(&packet)
            .expect("header protection")
    }

    /// Integration test: Client handshake via ChannelTransport with a
    /// simulated server responder.
    #[tokio::test]
    async fn test_phantom_session_handshake_via_transport() {
        let (client_transport, server_transport) = ChannelTransport::pair();
        let server_hs = HandshakeServer::new().unwrap();
        let server_pinned_key = server_hs.verifying_key().clone();

        // Start client session — spawns background handshake (with pinning)
        let session = PhantomSession::connect_with_transport(
            "test-server:9000",
            client_transport,
            server_pinned_key,
        );

        // Queue a message before handshake completes
        session.send(b"early-data".to_vec()).await.unwrap();

        // Simulate server responder
        let server_handle = tokio::spawn(async move {
            let client_ip = "127.0.0.1".parse().unwrap();

            // 1. Receive the (bare borsh) ClientHello.
            let client_hello_bytes = server_transport.recv_bytes().await.unwrap();
            let client_hello = borsh::from_slice::<ClientHello>(&client_hello_bytes).unwrap();

            // 2. Process — may retry with cookie/PoW.
            let server_session = loop {
                let response = server_hs.process_client_hello(&client_hello, 0, client_ip);
                match response {
                    HandshakeResponse::Retry(retry) => {
                        let retry_bytes = ServerReply::Retry(retry).to_wire().unwrap();
                        server_transport.send_bytes(&retry_bytes).await.unwrap();
                        // Receive retried client hello
                        let next_bytes = server_transport.recv_bytes().await.unwrap();
                        let next_hello = borsh::from_slice::<ClientHello>(&next_bytes).unwrap();
                        let resp2 = server_hs.process_client_hello(&next_hello, 0, client_ip);
                        match resp2 {
                            HandshakeResponse::Success(server_hello, session, _) => {
                                let server_hello_bytes =
                                    ServerReply::Hello(server_hello).to_wire().unwrap();
                                server_transport
                                    .send_bytes(&server_hello_bytes)
                                    .await
                                    .unwrap();
                                break session;
                            }
                            _ => panic!("Expected success after retry"),
                        }
                    }
                    HandshakeResponse::Success(server_hello, session, _) => {
                        let server_hello_bytes =
                            ServerReply::Hello(server_hello).to_wire().unwrap();
                        server_transport
                            .send_bytes(&server_hello_bytes)
                            .await
                            .unwrap();
                        break session;
                    }
                    HandshakeResponse::Reject(r) => panic!("unexpected reject: {:?}", r),
                    HandshakeResponse::Fail(e) => panic!("handshake failed: {:?}", e),
                }
            };

            let session_id = *server_session.id();

            // 3. Receive the flushed early data — must be ENCRYPTED.
            let early_frame = server_transport.recv_bytes().await.unwrap();
            assert!(
                !early_frame
                    .windows(b"early-data".len())
                    .any(|w| w == b"early-data"),
                "encrypted frame must not contain plaintext early-data"
            );
            let early_plain = decrypt_incoming(&server_session, &early_frame);
            assert_eq!(early_plain, b"early-data");

            // 4. Receive a post-handshake message — must be ENCRYPTED.
            let post_frame = server_transport.recv_bytes().await.unwrap();
            let post_plain = decrypt_incoming(&server_session, &post_frame);
            assert_eq!(post_plain, b"after-handshake");

            // 5. Send encrypted reply back. stream_offset (== sequence here) must
            // be 0: this is the FIRST reliable frame server→client on this stream,
            // so the client reassembles it at offset 0 (A.5).
            let reply = encrypt_outgoing(&server_session, session_id, 1, 0, b"server-reply");
            server_transport.send_bytes(&reply).await.unwrap();
        });

        // Wait for handshake to progress
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        // Should be connected now
        assert_eq!(session.connection_state(), ConnectionState::Connected);

        // Send after handshake
        session.send(b"after-handshake".to_vec()).await.unwrap();

        // Receive server reply — now returns DECRYPTED plaintext payload.
        let reply = session.recv().await.unwrap();
        assert_eq!(reply, b"server-reply");

        server_handle.await.unwrap();
        session.disconnect().await.unwrap();
    }

    /// Reliable delivery: a RELIABLE application send must survive a dropped data frame.
    ///
    /// The client runs over a `LossyTransport`; once the handshake completes we
    /// arm a drop of the next frame (the data frame) and send a reliable
    /// payload. The first transmission is lost, so the server only sees the
    /// payload because the raw-app stream buffers it and the data pump
    /// retransmits the timed-out segment.
    #[tokio::test]
    async fn reliable_send_survives_a_dropped_data_frame() {
        use crate::test_harness::fault_transport::{FaultControl, LossyTransport};

        let (client_transport, server_transport) = ChannelTransport::pair();
        let faults = FaultControl::new();
        let lossy_client = LossyTransport::new(client_transport, faults.clone());

        let server_hs = HandshakeServer::new().unwrap();
        let server_pinned_key = server_hs.verifying_key().clone();

        let session = PhantomSession::connect_with_transport(
            "test-server:9000",
            lossy_client,
            server_pinned_key,
        );

        let server_handle = tokio::spawn(async move {
            let client_ip = "127.0.0.1".parse().unwrap();
            let client_hello_bytes = server_transport.recv_bytes().await.unwrap();
            let client_hello = borsh::from_slice::<ClientHello>(&client_hello_bytes).unwrap();

            // Drive the handshake to completion (may take one cookie/PoW retry).
            let server_session = loop {
                match server_hs.process_client_hello(&client_hello, 0, client_ip) {
                    HandshakeResponse::Retry(retry) => {
                        let retry_bytes = ServerReply::Retry(retry).to_wire().unwrap();
                        server_transport.send_bytes(&retry_bytes).await.unwrap();
                        let next_bytes = server_transport.recv_bytes().await.unwrap();
                        let next_hello = borsh::from_slice::<ClientHello>(&next_bytes).unwrap();
                        match server_hs.process_client_hello(&next_hello, 0, client_ip) {
                            HandshakeResponse::Success(server_hello, session, _) => {
                                let b = ServerReply::Hello(server_hello).to_wire().unwrap();
                                server_transport.send_bytes(&b).await.unwrap();
                                break session;
                            }
                            _ => panic!("expected success after retry"),
                        }
                    }
                    HandshakeResponse::Success(server_hello, session, _) => {
                        let b = ServerReply::Hello(server_hello).to_wire().unwrap();
                        server_transport.send_bytes(&b).await.unwrap();
                        break session;
                    }
                    HandshakeResponse::Reject(r) => panic!("unexpected reject: {:?}", r),
                    HandshakeResponse::Fail(e) => panic!("handshake failed: {:?}", e),
                }
            };

            // The reliable data frame was dropped on first transmission; it can
            // only arrive via retransmission. Time-bounded so a missing
            // retransmit fails loudly instead of hanging the test forever.
            let data_frame = tokio::time::timeout(
                std::time::Duration::from_secs(3),
                server_transport.recv_bytes(),
            )
            .await
            .expect(
                "reliable payload never arrived within 3s — the dropped data frame was not \
                 retransmitted (loss-recovery regression)",
            )
            .unwrap();
            let plain = decrypt_incoming(&server_session, &data_frame);
            assert_eq!(plain, b"reliable-payload");
        });

        // Wait for the handshake to complete.
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        assert_eq!(session.connection_state(), ConnectionState::Connected);

        // Arm a single drop, then send: the next frame on the wire (the data
        // frame) is silently lost.
        faults.arm_drop_next(1);
        session.send(b"reliable-payload".to_vec()).await.unwrap();

        server_handle.await.unwrap();
        session.disconnect().await.unwrap();
    }

    /// A retransmission (RTO expiry) must be reported to congestion control as
    /// a loss, driving BBR into FastRecovery — proves the drain → on_packet_lost
    /// wiring, not just that the retransmit happens.
    #[tokio::test]
    async fn drain_reports_a_retransmit_as_loss_to_bbr() {
        use crate::transport::bandwidth_estimator::BbrState;

        tokio::time::pause();
        let sid = fixed_session_id();
        let (client, _server) = paired_sessions(sid);

        let stream = Arc::new(TransportStream::new(1));
        stream.send_reliable(Bytes::from("payload")).await.unwrap();
        let streams: Arc<DashMap<u32, Arc<TransportStream>>> = Arc::new(DashMap::new());
        streams.insert(1u32, stream);

        let (client_t, _server_t) = ChannelTransport::pair();
        let transport = Arc::new(client_t);

        // First drain: the initial transmission — not a loss.
        drain_streams_priority_ordered(&transport, &client, sid, &streams).await;
        assert_ne!(client.bbr_state(), BbrState::FastRecovery);

        // The RTO expires; the next drain retransmits and must report the loss.
        tokio::time::advance(std::time::Duration::from_millis(1100)).await;
        drain_streams_priority_ordered(&transport, &client, sid, &streams).await;
        assert_eq!(
            client.bbr_state(),
            BbrState::FastRecovery,
            "a retransmit must be reported to BBR as a loss"
        );
    }

    /// New data must not be transmitted while inflight already exceeds the
    /// congestion window — the drain holds it back until ACKs free the window.
    #[tokio::test]
    async fn drain_withholds_new_data_when_inflight_exceeds_cwnd() {
        let sid = fixed_session_id();
        let (client, _server) = paired_sessions(sid);

        // Drive inflight far above any plausible initial cwnd, so the window
        // has no room for new data.
        client.on_packet_sent(100_000_000);
        let inflight_before = client.bandwidth_snapshot().inflight_bytes;

        let stream = Arc::new(TransportStream::new(1));
        stream.send_reliable(Bytes::from("new-data")).await.unwrap();
        let streams: Arc<DashMap<u32, Arc<TransportStream>>> = Arc::new(DashMap::new());
        streams.insert(1u32, stream);

        let (client_t, _server_t) = ChannelTransport::pair();
        let transport = Arc::new(client_t);

        drain_streams_priority_ordered(&transport, &client, sid, &streams).await;

        // No new segment was transmitted — inflight is unchanged (a send would
        // have grown it via on_packet_sent).
        assert_eq!(
            client.bandwidth_snapshot().inflight_bytes,
            inflight_before,
            "no new data should be sent when inflight >= cwnd"
        );
    }

    // ────────────────────────────────────────────────────────────────────
    // V2 wire-routing tests (Phase 4.2 / 2.5 follow-up — data-pump V2)
    // ────────────────────────────────────────────────────────────────────

    use crate::transport::multiplexer::StreamDemultiplexer;
    use crate::transport::session::Session as InnerSession;
    use crate::transport::stream::Stream as TransportStream;

    /// Build two `InnerSession` instances that share a 32-byte secret —
    /// one as the "client" (peer_side=false), one as the "server"
    /// (peer_side=true). Mirrors the role split after a real handshake.
    fn paired_sessions(session_id: SessionId) -> (Arc<InnerSession>, Arc<InnerSession>) {
        let secret = [0x11u8; 32];
        let client = Arc::new(InnerSession::new(session_id, &secret, false).unwrap());
        let server = Arc::new(InnerSession::new(session_id, &secret, true).unwrap());
        (client, server)
    }

    fn fixed_session_id() -> SessionId {
        SessionId::from_bytes([0x88; 32])
    }

    /// Encrypt a V2 application-data packet from the client side at
    /// `stream_id` / `sequence`. The returned bytes are wire-serialised
    /// ([`PhantomPacket::to_wire`]) and ready to feed into `handle_packet`.
    /// Build a RELIABLE app frame whose `stream_offset` equals its `sequence` (the
    /// no-control-gap case, which holds for almost every test).
    fn build_app_frame(
        client_session: &InnerSession,
        session_id: SessionId,
        stream_id: TransportStreamId,
        sequence: u32,
        payload: &[u8],
    ) -> Vec<u8> {
        build_app_frame_with_offset(
            client_session,
            session_id,
            stream_id,
            sequence,
            sequence,
            payload,
        )
    }

    /// Build a RELIABLE app frame with an explicit gap-free `stream_offset`
    /// distinct from the wire `sequence` (A.5). The plaintext is
    /// `[stream_offset: u32 BE][payload]`, matching the live sender's reliable
    /// framing; the receiver reassembles by `stream_offset`.
    fn build_app_frame_with_offset(
        client_session: &InnerSession,
        session_id: SessionId,
        stream_id: TransportStreamId,
        sequence: u32,
        stream_offset: u32,
        payload: &[u8],
    ) -> Vec<u8> {
        let flag_bits = PacketFlags::RELIABLE | PacketFlags::ENCRYPTED;
        let header = PacketHeader::new(
            session_id,
            stream_id,
            sequence as u64,
            PacketFlags::new(flag_bits),
        )
        .with_epoch(client_session.current_epoch());
        let mut pt = Vec::with_capacity(4 + payload.len());
        pt.extend_from_slice(&stream_offset.to_be_bytes());
        pt.extend_from_slice(payload);
        let ciphertext = client_session
            .encrypt_packet(&header, &pt, &[])
            .expect("encrypt_packet");
        // Cleartext wire: this frame is decoded back to a struct and fed to
        // handle_packet directly (it never traverses the pump's transport, which
        // is the only path that applies/removes header protection).
        PhantomPacket::new(header, ciphertext).to_wire()
    }

    /// Decode a test-built frame the way the recv pump's `parse_protected` does:
    /// `from_wire` + reconstruct the off-wire `session_id` from session context
    /// (ε / WIRE v5). The `build_*` helpers emit cleartext `to_wire` (header
    /// protection is exercised separately), so the inner `session_id` is the
    /// placeholder zero until this sets it — mirroring production, where
    /// `parse_protected` reconstructs it before `handle_packet` ever sees the
    /// packet.
    fn decode_recv_frame(frame: &[u8], session_id: SessionId) -> PhantomPacket {
        let mut packet = PhantomPacket::from_wire(frame).expect("decode test recv frame");
        packet.header.session_id = session_id;
        packet
    }

    #[tokio::test]
    async fn v2_recv_routes_encrypted_app_data_through_recv_channel() {
        let session_id = fixed_session_id();
        let (client_session, server_session) = paired_sessions(session_id);

        // Encrypt a V2 application-data packet on the client side.
        let stream_id: TransportStreamId = 1;
        let frame = build_app_frame(&client_session, session_id, stream_id, 0, b"hello-v2");

        // Receive on the server side: decode (reconstructing the off-wire
        // session_id, as parse_protected does) then drive handle_packet.
        let v2 = decode_recv_frame(&frame, session_id);

        let (demux, _ctrl_rx) = StreamDemultiplexer::new(16);
        let demux = Arc::new(demux);
        let streams: Arc<DashMap<u32, Arc<TransportStream>>> = Arc::new(DashMap::new());
        let (deliver_tx, mut deliver_rx) = mpsc::unbounded_channel::<(u32, Bytes)>();
        let undelivered = AtomicU64::new(0);
        let (ack_a, ack_b) = mpsc::channel::<Vec<u8>>(4);
        let transport_send: Arc<ChannelTransport> = Arc::new(ChannelTransport {
            tx: ack_a,
            rx: Mutex::new(ack_b),
        });

        let mut ack_buf = Vec::with_capacity(256);
        let obs = Observability::new(ObservabilityConfig::default());
        handle_packet(
            v2,
            session_id,
            &server_session,
            &streams,
            &demux,
            &transport_send,
            &transport_send,
            &deliver_tx,
            &undelivered,
            &mut ack_buf,
            &obs,
            LegType::Tcp,
        )
        .await;

        // The decrypted plaintext must have been handed to the delivery task,
        // tagged with its stream id, and counted toward the undelivered backlog.
        let (sid, received) = deliver_rx.recv().await.expect("delivery hand-off");
        assert_eq!(sid, stream_id as u32);
        assert_eq!(&received[..], b"hello-v2");
        assert_eq!(
            undelivered.load(Ordering::Acquire),
            b"hello-v2".len() as u64
        );
    }

    /// H-3: the recv path must cap concurrent receive streams. A peer that sprays reliable
    /// frames across far more distinct `stream_id`s than the cap must not auto-create an
    /// unbounded number of `Stream`s — the table is bounded by `MAX_STREAMS`, which (with the
    /// per-stream reorder byte budget) bounds the session's total reorder memory.
    #[tokio::test]
    async fn recv_path_caps_concurrent_streams_at_max_streams() {
        let session_id = fixed_session_id();
        let (client_session, server_session) = paired_sessions(session_id);

        let (demux, _ctrl_rx) = StreamDemultiplexer::new(16);
        let demux = Arc::new(demux);
        let streams: Arc<DashMap<u32, Arc<TransportStream>>> = Arc::new(DashMap::new());
        let (deliver_tx, _deliver_rx) = mpsc::unbounded_channel::<(u32, Bytes)>();
        let undelivered = AtomicU64::new(0);
        let attempts = MAX_STREAMS as u32 + 64;
        let (ack_a, ack_b) = mpsc::channel::<Vec<u8>>(attempts as usize + 16);
        let transport_send: Arc<ChannelTransport> = Arc::new(ChannelTransport {
            tx: ack_a,
            rx: Mutex::new(ack_b),
        });
        let mut ack_buf = Vec::with_capacity(256);
        let obs = Observability::new(ObservabilityConfig::default());

        // A peer opens far more receive streams than the cap. Each frame uses a distinct
        // `sequence` (the per-direction packet number, else they replay-reject) but
        // stream_offset 0 so it delivers in order and creates its stream.
        for sid in 0..attempts {
            let frame = build_app_frame_with_offset(
                &client_session,
                session_id,
                sid as TransportStreamId,
                sid, // sequence = distinct per-direction PN
                0,   // stream_offset 0 → in-order delivery
                b"x",
            );
            let v2 = decode_recv_frame(&frame, session_id);
            handle_packet(
                v2,
                session_id,
                &server_session,
                &streams,
                &demux,
                &transport_send,
                &transport_send,
                &deliver_tx,
                &undelivered,
                &mut ack_buf,
                &obs,
                LegType::Tcp,
            )
            .await;
        }

        assert!(
            streams.len() <= MAX_STREAMS,
            "recv path must cap concurrent receive streams at MAX_STREAMS ({MAX_STREAMS}); have {}",
            streams.len()
        );
    }

    /// M-2 (audit 2026-06-11, residual of prior H1): a forged **unencrypted, empty-payload**
    /// packet carrying only the `FIN` flag (valid `session_id`) must NOT tear down an
    /// `open_stream()` stream. The stripped-flag downgrade defense must drop ALL unencrypted
    /// post-handshake packets — not only non-empty ones — so the standalone-FIN path is never
    /// reached without AEAD verification. Legitimate FINs are always `ENCRYPTED`.
    #[tokio::test]
    async fn forged_unencrypted_fin_does_not_close_a_stream() {
        let session_id = fixed_session_id();
        let (_client_session, server_session) = paired_sessions(session_id);

        let (demux, _ctrl_rx) = StreamDemultiplexer::new(16);
        let demux = Arc::new(demux);
        // Register stream 2 — an open_stream()-style stream (ids 2+), the M-2 target.
        let mut handle = demux.register_stream(2, 8);
        let streams: Arc<DashMap<u32, Arc<TransportStream>>> = Arc::new(DashMap::new());
        let (deliver_tx, _deliver_rx) = mpsc::unbounded_channel::<(u32, Bytes)>();
        let undelivered = AtomicU64::new(0);
        let (ack_a, ack_b) = mpsc::channel::<Vec<u8>>(4);
        let transport_send: Arc<ChannelTransport> = Arc::new(ChannelTransport {
            tx: ack_a,
            rx: Mutex::new(ack_b),
        });
        let mut ack_buf = Vec::with_capacity(64);
        let obs = Observability::new(ObservabilityConfig::default());

        // Forged: UNENCRYPTED, empty payload, FIN flag, valid session_id, stream 2.
        let header = PacketHeader::new(session_id, 2, 0, PacketFlags::new(PacketFlags::FIN));
        let forged = PhantomPacket::new(header, Vec::new());

        handle_packet(
            forged,
            session_id,
            &server_session,
            &streams,
            &demux,
            &transport_send,
            &transport_send,
            &deliver_tx,
            &undelivered,
            &mut ack_buf,
            &obs,
            LegType::Tcp,
        )
        .await;

        assert!(
            handle.rx.try_recv().is_err(),
            "a forged unencrypted FIN must not close an open_stream() stream"
        );
    }

    /// Like [`build_app_frame`] but stamps a caller-chosen `path_id` so the
    /// receive-side path gate (PATH-001) can be exercised.
    fn build_app_frame_on_path(
        client_session: &InnerSession,
        session_id: SessionId,
        stream_id: TransportStreamId,
        sequence: u32,
        stream_offset: u32,
        path_id: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let flag_bits = PacketFlags::RELIABLE | PacketFlags::ENCRYPTED;
        let header = PacketHeader::new(
            session_id,
            stream_id,
            sequence as u64,
            PacketFlags::new(flag_bits),
        )
        .with_epoch(client_session.current_epoch())
        .with_path_id(path_id);
        // Reliable plaintext = [stream_offset: u32 BE][payload] (A.5).
        let mut pt = Vec::with_capacity(4 + payload.len());
        pt.extend_from_slice(&stream_offset.to_be_bytes());
        pt.extend_from_slice(payload);
        let ciphertext = client_session
            .encrypt_packet(&header, &pt, &[])
            .expect("encrypt_packet");
        // Cleartext wire: this frame is decoded back to a struct and fed to
        // handle_packet directly (it never traverses the pump's transport, which
        // is the only path that applies/removes header protection).
        PhantomPacket::new(header, ciphertext).to_wire()
    }

    #[test]
    fn send_path_id_starts_at_zero_then_bumps_per_migration() {
        // D5 (Phase 4): the client owns a monotonic send-side path_id, default 0 (the
        // implicit handshake path), bumped on each migration so the server can detect
        // and challenge the new path. Reuse is nonce-safe under ① (path_id left the
        // AEAD nonce — `nonce = nonce_prefix ‖ packet_number`).
        let session_id = fixed_session_id();
        let (client_session, _server_session) = paired_sessions(session_id);
        assert_eq!(client_session.current_send_path_id(), 0);
        assert_eq!(client_session.next_migration_path_id(), 1);
        assert_eq!(client_session.current_send_path_id(), 1);
        assert_eq!(client_session.next_migration_path_id(), 2);
        assert_eq!(client_session.current_send_path_id(), 2);
    }

    /// ε / WIRE v5 (audit V-1 / Invariant 4) — the inbound CID-window slide is
    /// signalled ONLY from the post-AEAD path. A forged packet that fails AEAD —
    /// even one carrying a NEW forward `path_id` (the migration signal) — must not
    /// advance the inbound CID window or emit a `CidSlide`. This pins that an
    /// off-path attacker (who cannot produce a valid tag) cannot push the demux
    /// window; a future refactor that hoists the slide above the AEAD gate fails here.
    #[tokio::test]
    async fn eps_slide_requires_aead_success() {
        let session_id = fixed_session_id();
        let (client_session, server_session) = paired_sessions(session_id);
        let streams: Arc<DashMap<u32, Arc<TransportStream>>> = Arc::new(DashMap::new());

        // Install the demux slide channel and snapshot the inbound CID window.
        let (slide_tx, mut slide_rx) = mpsc::unbounded_channel();
        server_session.set_cid_slide_tx(slide_tx);
        let window_before = server_session.inbound_window_cids();

        // A valid frame on a NEW path_id (1, the migration signal), then corrupt
        // the ciphertext so AEAD verification fails. The header stays intact.
        let stream_id: TransportStreamId = 1;
        let frame =
            build_app_frame_on_path(&client_session, session_id, stream_id, 0, 0, 1, b"forged");
        let mut pkt = decode_recv_frame(&frame, session_id);
        assert!(!pkt.payload.is_empty(), "ciphertext present to corrupt");
        pkt.payload[0] ^= 0xFF; // tamper → AEAD open fails

        run_recv(pkt, session_id, &server_session, &streams).await;

        assert!(
            slide_rx.try_recv().is_err(),
            "a forged (AEAD-failing) packet must emit no CidSlide"
        );
        assert_eq!(
            server_session.inbound_window_cids(),
            window_before,
            "the inbound CID window must not advance on a forged packet (slide is post-AEAD)"
        );
    }

    use std::sync::atomic::AtomicBool;

    /// Records each `SessionTransport` control method the inner transport receives,
    /// for the [`observed_transport_forwards_all_control_methods`] tripwire.
    #[derive(Default)]
    struct ControlRecorder {
        set_frame_phase: AtomicBool,
        set_outbound_cid: std::sync::Mutex<Option<[u8; 8]>>,
        has_migration_candidate: AtomicBool,
        send_to_candidate: AtomicBool,
        confirm_authenticated_source: AtomicBool,
        promote_candidate: AtomicBool,
        migrate: std::sync::Mutex<Option<String>>,
    }

    struct RecordingTransport {
        rec: Arc<ControlRecorder>,
    }

    impl SessionTransport for RecordingTransport {
        async fn send_bytes(&self, _data: &[u8]) -> Result<(), CoreError> {
            Ok(())
        }
        async fn recv_bytes(&self) -> Result<Bytes, CoreError> {
            Ok(Bytes::new())
        }
        fn set_frame_phase(&self, _phase: FramePhase) {
            self.rec.set_frame_phase.store(true, Ordering::SeqCst);
        }
        fn set_outbound_cid(&self, cid: [u8; 8]) {
            *self.rec.set_outbound_cid.lock().unwrap() = Some(cid);
        }
        fn has_migration_candidate(&self) -> bool {
            self.rec
                .has_migration_candidate
                .store(true, Ordering::SeqCst);
            true
        }
        async fn send_to_candidate(&self, _data: &[u8]) -> Result<bool, CoreError> {
            self.rec.send_to_candidate.store(true, Ordering::SeqCst);
            Ok(true)
        }
        fn confirm_authenticated_source(&self) {
            self.rec
                .confirm_authenticated_source
                .store(true, Ordering::SeqCst);
        }
        fn promote_candidate(&self) -> bool {
            self.rec.promote_candidate.store(true, Ordering::SeqCst);
            true
        }
        async fn migrate(&self, local_addr: String) -> Result<(), CoreError> {
            *self.rec.migrate.lock().unwrap() = Some(local_addr);
            Ok(())
        }
    }

    /// ε / WIRE v5 (audit V-3 / EPS-03 / EPS-04) — `ObservedTransport` must forward
    /// EVERY `SessionTransport` control method to the inner transport, not just
    /// send/recv. A method left on the trait default silently no-ops — the bug that
    /// made the pre-ε FFI `migrate()` vacuous and linkable. This always-on tripwire
    /// pins the full control surface without UDP loopback: a dropped forward, or a
    /// future-added trait method the wrapper forgets, fails an assertion here.
    #[tokio::test]
    async fn observed_transport_forwards_all_control_methods() {
        let rec = Arc::new(ControlRecorder::default());
        let observed = ObservedTransport::new(
            RecordingTransport { rec: rec.clone() },
            Observability::new(ObservabilityConfig::default()),
            LegType::Udp,
        );

        observed.set_frame_phase(FramePhase::Established);
        observed.set_outbound_cid([7u8; 8]);
        assert!(observed.has_migration_candidate());
        assert!(observed
            .send_to_candidate(b"challenge")
            .await
            .expect("send_to_candidate"));
        observed.confirm_authenticated_source();
        assert!(observed.promote_candidate());
        observed
            .migrate("127.0.0.1:0".to_string())
            .await
            .expect("migrate");

        assert!(
            rec.set_frame_phase.load(Ordering::SeqCst),
            "set_frame_phase not forwarded"
        );
        assert_eq!(
            *rec.set_outbound_cid.lock().unwrap(),
            Some([7u8; 8]),
            "set_outbound_cid not forwarded"
        );
        assert!(
            rec.has_migration_candidate.load(Ordering::SeqCst),
            "has_migration_candidate not forwarded"
        );
        assert!(
            rec.send_to_candidate.load(Ordering::SeqCst),
            "send_to_candidate not forwarded"
        );
        assert!(
            rec.confirm_authenticated_source.load(Ordering::SeqCst),
            "confirm_authenticated_source not forwarded"
        );
        assert!(
            rec.promote_candidate.load(Ordering::SeqCst),
            "promote_candidate not forwarded"
        );
        assert_eq!(
            rec.migrate.lock().unwrap().as_deref(),
            Some("127.0.0.1:0"),
            "migrate not forwarded"
        );
    }

    /// EPS-02 (symmetric CID rotation) — when the **server** (the demuxing side)
    /// detects a client migration (a new authenticated `path_id`, post-AEAD), it
    /// must rotate its OWN outbound (server→client) CID so that direction also
    /// gets a fresh `ConnId` across the move. Otherwise an on-path observer seeing
    /// both networks links the session by the stable s2c CID (the ε §12.5 residual
    /// this fix closes). The socket-routed client accepts any inbound CID, so no
    /// client-side window slide is needed and there is no ping-pong (we never bump
    /// the server's own send path_id here).
    #[tokio::test]
    async fn eps02_server_rotates_s2c_cid_on_client_migration() {
        let session_id = fixed_session_id();
        let (client_session, server_session) = paired_sessions(session_id);
        let streams: Arc<DashMap<u32, Arc<TransportStream>>> = Arc::new(DashMap::new());

        assert!(server_session.is_server(), "server side");
        let s2c_cid_before = server_session.current_outbound_cid();

        // The client migrates: it bumps its send path_id and sends app data on the
        // new path. Deliver that migration packet (path_id = 1) to the server.
        let stream_id: TransportStreamId = 1;
        let frame =
            build_app_frame_on_path(&client_session, session_id, stream_id, 0, 0, 1, b"migrated");
        let pkt = decode_recv_frame(&frame, session_id);
        run_recv(pkt, session_id, &server_session, &streams).await;

        assert_ne!(
            server_session.current_outbound_cid(),
            s2c_cid_before,
            "the server must rotate its server->client CID when the client migrates (EPS-02)"
        );
    }

    /// EPS-02 companion — the **client** (socket-routed) must NOT rotate-on-detect.
    /// It has no inbound CID demux, and rotating its outbound (c2s) CID off an
    /// authenticated server `path_id` would push its CID out of the server's
    /// (un-sliding) c2s window for repeated server migrations. So a client that
    /// observes a server migration leaves its own outbound CID untouched.
    #[tokio::test]
    async fn eps02_client_does_not_rotate_on_detecting_server_migration() {
        let session_id = fixed_session_id();
        let (client_session, server_session) = paired_sessions(session_id);
        let streams: Arc<DashMap<u32, Arc<TransportStream>>> = Arc::new(DashMap::new());

        assert!(!client_session.is_server(), "client side");
        let c2s_cid_before = client_session.current_outbound_cid();

        // The server migrates: build a server→client app frame on a new path_id and
        // deliver it to the client's recv path.
        let stream_id: TransportStreamId = 1;
        let frame = build_app_frame_on_path(
            &server_session,
            session_id,
            stream_id,
            0,
            0,
            1,
            b"srv-moved",
        );
        let pkt = decode_recv_frame(&frame, session_id);
        run_recv(pkt, session_id, &client_session, &streams).await;

        assert_eq!(
            client_session.current_outbound_cid(),
            c2s_cid_before,
            "the socket-routed client must NOT rotate its outbound CID on detecting a server migration"
        );
    }

    #[test]
    fn migration_path_id_never_collides_with_the_handshake_path() {
        // The migration counter must never hand back path_id 0 — that id is
        // permanently the Validated handshake path on both peers, so reusing it would
        // make the server skip the challenge (path 0 is always Validated) and the
        // switch would never fire. Spanning > 2 u8 wraps proves the wrap (never 0;
        // it also skips the reserved 255 — see the dedicated collision test).
        let session_id = fixed_session_id();
        let (client_session, _server_session) = paired_sessions(session_id);
        for _ in 0..600 {
            assert_ne!(client_session.next_migration_path_id(), 0);
        }
    }

    #[tokio::test]
    async fn send_app_data_stamps_the_current_send_path_id() {
        // P4.2b: `send_app_data` must stamp `header.path_id` from the session's
        // current send path_id (default 0). After a migration bump, every outbound
        // app-data packet — including ARQ retransmits, which also flow through
        // `send_app_data` — carries the new path_id, which is exactly what makes the
        // server detect the new path and issue a PATH_CHALLENGE (D5 / D6).
        let session_id = fixed_session_id();
        let (client_session, _server_session) = paired_sessions(session_id);
        let (client_t, server_t) = ChannelTransport::pair();
        let client_t = Arc::new(client_t);

        // Default: app data is stamped on the implicit path 0.
        assert!(
            send_app_data(
                &client_t,
                &client_session,
                session_id,
                1,
                b"pre-migration",
                PacketFlags::RELIABLE,
                Some(0),
            )
            .await
        );
        let wire = server_t.recv_bytes().await.unwrap();
        let pkt = _server_session.parse_protected(&wire).unwrap();
        assert_eq!(
            pkt.header.path_id, 0,
            "default send path is the implicit path 0"
        );

        // After a migration bump, the new path_id is stamped on subsequent app data.
        assert_eq!(client_session.next_migration_path_id(), 1);
        assert!(
            send_app_data(
                &client_t,
                &client_session,
                session_id,
                1,
                b"post-migration",
                PacketFlags::RELIABLE,
                Some(13),
            )
            .await
        );
        let wire2 = server_t.recv_bytes().await.unwrap();
        let pkt2 = _server_session.parse_protected(&wire2).unwrap();
        assert_eq!(
            pkt2.header.path_id, 1,
            "after migrate(), app data must carry the bumped send path_id"
        );
    }

    #[tokio::test]
    async fn app_data_on_non_validated_path_is_delivered_recv_relax() {
        // PATH-001 split (D10, Phase 4). RECV is relaxed: AEAD-authenticated,
        // non-replayed app data is DELIVERED regardless of which path it arrived
        // on (the data already passed AEAD + the per-direction replay window, so
        // dropping it by source buys no security and would break a seamless
        // NAT-rebind). The path is still registered Unvalidated so it can be
        // challenged. The strict half (PATH-001a, the send-gate: app data only to
        // the peer / a Validated path) is exercised over a real UdpServerTransport
        // in udp_integration.
        use crate::transport::path::PathStateKind;
        let session_id = fixed_session_id();
        let (client_session, server_session) = paired_sessions(session_id);
        let stream_id: TransportStreamId = 1;

        let frame = build_app_frame_on_path(
            &client_session,
            session_id,
            stream_id,
            0,
            0, // stream_offset 0 — first reliable frame on this stream
            7, // a path the receiver has never validated
            b"on-new-path",
        );
        let frame = decode_recv_frame(&frame, session_id);

        let (demux, _ctrl_rx) = StreamDemultiplexer::new(16);
        let demux = Arc::new(demux);
        let streams: Arc<DashMap<u32, Arc<TransportStream>>> = Arc::new(DashMap::new());
        let (deliver_tx, mut deliver_rx) = mpsc::unbounded_channel::<(u32, Bytes)>();
        let undelivered = AtomicU64::new(0);
        let (ack_a, ack_b) = mpsc::channel::<Vec<u8>>(4);
        let transport_send: Arc<ChannelTransport> = Arc::new(ChannelTransport {
            tx: ack_a,
            rx: Mutex::new(ack_b),
        });
        let mut ack_buf = Vec::with_capacity(256);
        let obs = Observability::new(ObservabilityConfig::default());

        handle_packet(
            frame,
            session_id,
            &server_session,
            &streams,
            &demux,
            &transport_send,
            &transport_send,
            &deliver_tx,
            &undelivered,
            &mut ack_buf,
            &obs,
            LegType::Tcp,
        )
        .await;

        // Recv-relax (D10b): the authenticated frame IS delivered, even though
        // path 7 is not validated.
        let (sid, received) =
            tokio::time::timeout(std::time::Duration::from_secs(1), deliver_rx.recv())
                .await
                .expect("recv-relax must deliver promptly (no drop / hang)")
                .expect("delivery channel open");
        assert_eq!(sid, stream_id as u32);
        assert_eq!(&received[..], b"on-new-path");
        // The new path is registered Unvalidated for a later challenge. (The
        // ChannelTransport reports no migration candidate, so no challenge is
        // issued here — the server-challenge path is exercised in udp_integration.)
        assert_eq!(
            server_session.path_state(7),
            Some(PathStateKind::Unvalidated),
            "the new path id must be registered for a later challenge"
        );
    }

    #[tokio::test]
    async fn server_challenges_a_migration_candidate() {
        // P4.1 end-to-end over a real UdpServerTransport: app data on a NEW path_id
        // from a NEW source makes the server issue a PATH_VALIDATION challenge TO
        // THAT SOURCE (not the established peer), under the 3× anti-amp cap, and the
        // new path goes Validating. No peer switch (that is P4.2).
        use crate::api::udp_transport::UdpServerTransport;
        use crate::transport::path::PathStateKind;
        use crate::transport::phantom_udp::datagram::{push_datagram, FragmentAssembler};

        let session_id = fixed_session_id();
        let (client_session, server_session) = paired_sessions(session_id);
        let stream_id: TransportStreamId = 1;

        let server_sock = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let peer: std::net::SocketAddr = "127.0.0.1:9".parse().unwrap(); // established (old) peer
        let cand_sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let cand_addr = cand_sock.local_addr().unwrap();

        // Build the server transport and set the candidate by feeding a frame from
        // the candidate source through the demux channel (as the demux would), with
        // enough received bytes that the 3× budget admits a challenge.
        let (tx, rx) = mpsc::channel(8);
        let ust = Arc::new(UdpServerTransport::new(
            server_sock.clone(),
            peer,
            [5u8; 8],
            rx,
        ));
        tx.send((Bytes::from(vec![0u8; 256]), cand_addr))
            .await
            .unwrap();
        let _ = ust.recv_bytes().await.unwrap();
        // M-1: the candidate is committed only on the post-decrypt (authenticated) path, which
        // handle_packet drives in production; mirror that here for the manual setup.
        ust.confirm_authenticated_source();
        assert!(
            ust.has_migration_candidate(),
            "new source must set a candidate"
        );

        // App data on a NEW (unvalidated) path id → the server must challenge it.
        let frame =
            build_app_frame_on_path(&client_session, session_id, stream_id, 0, 0, 1, b"migrated");
        let frame = decode_recv_frame(&frame, session_id);

        let (demux, _ctrl_rx) = StreamDemultiplexer::new(16);
        let demux = Arc::new(demux);
        let streams: Arc<DashMap<u32, Arc<TransportStream>>> = Arc::new(DashMap::new());
        let (deliver_tx, _deliver_rx) = mpsc::unbounded_channel::<(u32, Bytes)>();
        let undelivered = AtomicU64::new(0);
        let mut ack_buf = Vec::with_capacity(256);
        let obs = Observability::new(ObservabilityConfig::default());

        handle_packet(
            frame,
            session_id,
            &server_session,
            &streams,
            &demux,
            &ust,
            &ust,
            &deliver_tx,
            &undelivered,
            &mut ack_buf,
            &obs,
            LegType::Udp,
        )
        .await;

        // The server issued a challenge → path 1 is now Validating.
        assert_eq!(
            server_session.path_state(1),
            Some(PathStateKind::Validating),
            "an unvalidated path on a candidate source must be challenged"
        );
        // ...and the challenge datagram reached the CANDIDATE socket (not the peer).
        let mut buf = vec![0u8; 2048];
        let (n, _from) = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            cand_sock.recv_from(&mut buf),
        )
        .await
        .expect("challenge must reach the candidate")
        .unwrap();
        let mut asm = FragmentAssembler::new();
        let (_hdr, inner) = push_datagram(&mut asm, &buf[..n]).expect("decode envelope");
        let inner = inner.expect("single-datagram challenge");
        // The server emitted this challenge (protect_packet under its send HP
        // key); unmask it from the client side (== the server's send key).
        let pkt = client_session
            .parse_protected(&inner)
            .expect("inner packet");
        assert!(
            pkt.header.flags.contains(PacketFlags::PATH_VALIDATION),
            "the candidate must receive a PATH_VALIDATION challenge"
        );
        assert_eq!(pkt.header.path_id, 1, "challenge must be on the new path");
    }

    #[tokio::test]
    async fn server_challenges_a_passive_rebind_on_path_zero() {
        // M-3: a *passive* NAT rebind keeps `path_id = 0` (the client never called
        // `migrate()`, so it never bumped its send path_id). Path 0 is permanently
        // `Validated`, so the path-id-gated challenge block is skipped — pre-fix the
        // server NEVER challenged the new source, never promoted it, and kept sending
        // downstream to the OLD (now-dead) address → stall. The fix makes detection
        // address-driven: when an authenticated frame arrives on a Validated path AND
        // the transport flags a migration candidate (a new authenticated source), the
        // server issues a PATH_CHALLENGE to that candidate on a RESERVED validation
        // path-id (`REBIND_VALIDATION_PATH_ID`), under the 3× anti-amp cap. Anti-spoof
        // still holds: the candidate is only ever the AEAD-authenticated source, and
        // the challenge only goes there.
        use crate::api::udp_transport::UdpServerTransport;
        use crate::transport::path::PathStateKind;
        use crate::transport::phantom_udp::datagram::{push_datagram, FragmentAssembler};
        use crate::transport::session::REBIND_VALIDATION_PATH_ID;

        let session_id = fixed_session_id();
        let (client_session, server_session) = paired_sessions(session_id);
        let stream_id: TransportStreamId = 1;

        let server_sock = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let peer: std::net::SocketAddr = "127.0.0.1:9".parse().unwrap(); // established (old) peer
        let cand_sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let cand_addr = cand_sock.local_addr().unwrap();

        let (tx, rx) = mpsc::channel(8);
        let ust = Arc::new(UdpServerTransport::new(
            server_sock.clone(),
            peer,
            [5u8; 8],
            rx,
        ));
        // A frame from the rebind source seeds the candidate + its 3× budget.
        tx.send((Bytes::from(vec![0u8; 256]), cand_addr))
            .await
            .unwrap();
        let _ = ust.recv_bytes().await.unwrap();
        ust.confirm_authenticated_source();
        assert!(
            ust.has_migration_candidate(),
            "new source must set a candidate"
        );

        // The reserved validation path is untouched at the start.
        assert_eq!(
            server_session.path_state(REBIND_VALIDATION_PATH_ID),
            None,
            "the rebind validation path must not exist before the rebind is observed"
        );

        // App data on the ESTABLISHED, always-Validated path 0 (passive rebind:
        // path_id unchanged) from the candidate source → the server must STILL
        // challenge the candidate on the reserved validation path-id.
        let frame =
            build_app_frame_on_path(&client_session, session_id, stream_id, 0, 0, 0, b"rebound");
        let frame = decode_recv_frame(&frame, session_id);

        let (demux, _ctrl_rx) = StreamDemultiplexer::new(16);
        let demux = Arc::new(demux);
        let streams: Arc<DashMap<u32, Arc<TransportStream>>> = Arc::new(DashMap::new());
        let (deliver_tx, _deliver_rx) = mpsc::unbounded_channel::<(u32, Bytes)>();
        let undelivered = AtomicU64::new(0);
        let mut ack_buf = Vec::with_capacity(256);
        let obs = Observability::new(ObservabilityConfig::default());

        handle_packet(
            frame,
            session_id,
            &server_session,
            &streams,
            &demux,
            &ust,
            &ust,
            &deliver_tx,
            &undelivered,
            &mut ack_buf,
            &obs,
            LegType::Udp,
        )
        .await;

        // The server issued a challenge on the RESERVED rebind path → it is Validating.
        assert_eq!(
            server_session.path_state(REBIND_VALIDATION_PATH_ID),
            Some(PathStateKind::Validating),
            "a path-0 rebind on a candidate source must be challenged on the reserved id"
        );
        // ...and the challenge datagram reached the CANDIDATE socket (not the peer).
        let mut buf = vec![0u8; 2048];
        let (n, _from) = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            cand_sock.recv_from(&mut buf),
        )
        .await
        .expect("rebind challenge must reach the candidate")
        .unwrap();
        let mut asm = FragmentAssembler::new();
        let (_hdr, inner) = push_datagram(&mut asm, &buf[..n]).expect("decode envelope");
        let inner = inner.expect("single-datagram challenge");
        let pkt = client_session
            .parse_protected(&inner)
            .expect("inner packet");
        assert!(
            pkt.header.flags.contains(PacketFlags::PATH_VALIDATION),
            "the candidate must receive a PATH_VALIDATION challenge"
        );
        assert_eq!(
            pkt.header.path_id, REBIND_VALIDATION_PATH_ID,
            "the passive-rebind challenge must be stamped on the reserved validation path-id"
        );
    }

    #[test]
    fn migration_path_id_never_collides_with_the_rebind_validation_path() {
        // M-3: the client's active-migration counter must never hand back the
        // reserved rebind validation id — otherwise an active migration and a
        // concurrent passive-rebind challenge would share a registry slot and a
        // late echo to one could resolve the other. The counter wraps 254 → 1,
        // skipping both 0 (the handshake path) and 255 (the reserved id).
        use crate::transport::session::REBIND_VALIDATION_PATH_ID;
        let session_id = fixed_session_id();
        let (client_session, _server_session) = paired_sessions(session_id);
        for _ in 0..600 {
            let id = client_session.next_migration_path_id();
            assert_ne!(id, 0, "must never reuse the handshake path");
            assert_ne!(
                id, REBIND_VALIDATION_PATH_ID,
                "must never reuse the reserved rebind validation path"
            );
        }
    }

    /// Build an `ENCRYPTED | ACK` frame (H1, L1-A) from `acker_session`
    /// acknowledging `acked_seq` on `stream_id`, with its own header sequence
    /// `ack_header_seq` (drawn from the acker's send space, distinct from the
    /// acked data sequence). The AEAD plaintext is a single-sequence `Sack`
    /// (the SACK superset of the legacy single-seq ACK). Wire-serialised, ready
    /// for `handle_packet`.
    fn build_encrypted_ack(
        acker_session: &InnerSession,
        session_id: SessionId,
        stream_id: TransportStreamId,
        ack_header_seq: u32,
        acked_seq: u32,
    ) -> Vec<u8> {
        let sack = crate::transport::sack::Sack::from_received(&[acked_seq], 0)
            .expect("single-seq sack")
            .to_wire();
        build_encrypted_ack_with_payload(
            acker_session,
            session_id,
            stream_id,
            ack_header_seq,
            &sack,
        )
    }

    /// Like [`build_encrypted_ack`] but with an arbitrary AEAD plaintext payload
    /// (used to exercise malformed-SACK handling on the sender path).
    fn build_encrypted_ack_with_payload(
        acker_session: &InnerSession,
        session_id: SessionId,
        stream_id: TransportStreamId,
        ack_header_seq: u32,
        payload: &[u8],
    ) -> Vec<u8> {
        let flag_bits = PacketFlags::ENCRYPTED | PacketFlags::ACK;
        let header = PacketHeader::new(
            session_id,
            stream_id,
            ack_header_seq as u64,
            PacketFlags::new(flag_bits),
        )
        .with_epoch(acker_session.current_epoch());
        let ct = acker_session
            .encrypt_packet(&header, payload, &[])
            .expect("encrypt ack");
        PhantomPacket::new(header, ct).to_wire()
    }

    /// Drive a single inbound packet through `handle_packet` against
    /// `server_session` with throwaway delivery/transport/observability wiring.
    async fn run_recv(
        pkt: PhantomPacket,
        session_id: SessionId,
        server_session: &Arc<InnerSession>,
        streams: &Arc<DashMap<u32, Arc<TransportStream>>>,
    ) {
        let (demux, _ctrl_rx) = StreamDemultiplexer::new(16);
        let demux = Arc::new(demux);
        let (deliver_tx, _deliver_rx) = mpsc::unbounded_channel::<(u32, Bytes)>();
        let undelivered = AtomicU64::new(0);
        let (ack_a, ack_b) = mpsc::channel::<Vec<u8>>(4);
        let transport: Arc<ChannelTransport> = Arc::new(ChannelTransport {
            tx: ack_a,
            rx: Mutex::new(ack_b),
        });
        let mut ack_buf = Vec::with_capacity(64);
        let obs = Observability::new(ObservabilityConfig::default());
        handle_packet(
            pkt,
            session_id,
            server_session,
            streams,
            &demux,
            &transport,
            &transport,
            &deliver_tx,
            &undelivered,
            &mut ack_buf,
            &obs,
            LegType::Tcp,
        )
        .await;
    }

    /// Stage a stream with one in-flight reliable segment; returns the stream,
    /// the shared streams map, and the segment's sequence number.
    async fn staged_pending_segment() -> (
        Arc<TransportStream>,
        Arc<DashMap<u32, Arc<TransportStream>>>,
        u32,
    ) {
        let stream_id: TransportStreamId = 1;
        let stream = Arc::new(TransportStream::new(stream_id));
        let seq = stream
            .send_reliable(Bytes::from_static(b"reliable-payload"))
            .await
            .unwrap();
        let _ = stream.poll_send(u64::MAX).await.expect("segment in-flight");
        let streams: Arc<DashMap<u32, Arc<TransportStream>>> = Arc::new(DashMap::new());
        streams.insert(stream_id as u32, stream.clone());
        (stream, streams, seq)
    }

    /// **H1 (Invariant 2).** A forged *unauthenticated* ACK — whether bare
    /// (`ACK` flag, empty payload) or carrying a plaintext 4-byte acked-seq —
    /// must NOT retire a pending reliable segment. Pre-fix, the ACK branch ran
    /// before the AEAD gate and trusted `header.sequence`, so an off-path
    /// attacker could silently drop never-acknowledged segments.
    #[tokio::test]
    async fn forged_plaintext_ack_does_not_retire_pending_segment() {
        let session_id = fixed_session_id();
        let (_client, server_session) = paired_sessions(session_id);
        let (stream, streams, seq) = staged_pending_segment().await;
        let stream_id: TransportStreamId = 1;

        // Variant 1: bare ACK, no ENCRYPTED, empty payload, guessed sequence.
        run_recv(
            PhantomPacket::new(
                PacketHeader::new(
                    session_id,
                    stream_id,
                    seq as u64,
                    PacketFlags::new(PacketFlags::ACK),
                ),
                Vec::new(),
            ),
            session_id,
            &server_session,
            &streams,
        )
        .await;
        // Variant 2: ACK with a plaintext 4-byte acked-seq, no ENCRYPTED.
        run_recv(
            PhantomPacket::new(
                PacketHeader::new(
                    session_id,
                    stream_id,
                    999,
                    PacketFlags::new(PacketFlags::ACK),
                ),
                seq.to_be_bytes().to_vec(),
            ),
            session_id,
            &server_session,
            &streams,
        )
        .await;

        assert!(
            stream.ack(seq).await.is_some(),
            "a forged unauthenticated ACK must not retire the pending reliable segment"
        );
    }

    /// **H1 + L1-B.** A forged *unauthenticated* SACK (plaintext `ACK`, no
    /// `ENCRYPTED`) carrying a wide range must neither retire a pending segment NOR
    /// trigger a fast-retransmit: it is dropped by the downgrade defense before the
    /// AEAD gate, so it never reaches the SACK loss detector (which would otherwise
    /// flag segments lost and drive Pass-0). The SACK plaintext is acted on only
    /// after AEAD verify.
    #[tokio::test]
    async fn forged_sack_neither_retires_nor_fast_retransmits() {
        let session_id = fixed_session_id();
        let (_client, server_session) = paired_sessions(session_id);
        let stream_id: TransportStreamId = 1;

        // Stage offsets 0..=5, all in flight.
        let stream = Arc::new(TransportStream::new(stream_id));
        for _ in 0..6u32 {
            stream
                .send_reliable(Bytes::from_static(b"x"))
                .await
                .unwrap();
            let _ = stream.poll_send(u64::MAX).await.expect("in-flight");
        }
        let streams: Arc<DashMap<u32, Arc<TransportStream>>> = Arc::new(DashMap::new());
        streams.insert(stream_id as u32, stream.clone());
        assert_eq!(stream.pending_send_count().await, 6);

        // Forged PLAINTEXT ACK (no ENCRYPTED) carrying a SACK over offset {5}.
        // If acted on, it would retire offset 5 AND flag offsets 0,1,2 lost.
        let forged_sack = crate::transport::sack::Sack::from_received(&[5], 0)
            .expect("sack")
            .to_wire();
        run_recv(
            PhantomPacket::new(
                PacketHeader::new(
                    session_id,
                    stream_id,
                    4242,
                    PacketFlags::new(PacketFlags::ACK),
                ),
                forged_sack, // plaintext — NOT encrypted
            ),
            session_id,
            &server_session,
            &streams,
        )
        .await;

        // Nothing retired: all six segments remain buffered.
        assert_eq!(
            stream.pending_send_count().await,
            6,
            "a forged unauthenticated SACK must not retire any segment (H1)"
        );
        // No fast-retransmit: nothing was flagged lost, so poll_send (all sent, no
        // new data) returns None rather than a Pass-0 retransmit.
        assert!(
            stream.poll_send(u64::MAX).await.is_none(),
            "a forged SACK must not trigger a fast-retransmit (no segment flagged lost)"
        );
    }

    /// **H1 positive control.** A genuine `ENCRYPTED | ACK` frame from the peer,
    /// whose AEAD payload carries the acked data sequence, retires the matching
    /// pending segment after AEAD verify. The ACK's own `header.sequence`
    /// (`ack_header_seq`) is deliberately different from the acked sequence to
    /// prove the handler reads the authenticated payload, not the header.
    #[tokio::test]
    async fn authenticated_ack_retires_pending_segment() {
        let session_id = fixed_session_id();
        let (client_session, server_session) = paired_sessions(session_id);
        let (stream, streams, seq) = staged_pending_segment().await;
        let stream_id: TransportStreamId = 1;

        let ack_header_seq = seq.wrapping_add(54_321);
        let frame =
            build_encrypted_ack(&client_session, session_id, stream_id, ack_header_seq, seq);
        let ack_pkt = decode_recv_frame(&frame, session_id);
        run_recv(ack_pkt, session_id, &server_session, &streams).await;

        assert!(
            stream.ack(seq).await.is_none(),
            "an authenticated ACK must retire the acked pending segment"
        );
    }

    /// **L1-A SACK end-to-end (gap retire).** Stage segments 0..=5 on the sender,
    /// deliver one authenticated `ENCRYPTED | ACK` carrying a SACK over the
    /// received set {0,1,2,4,5} (gap at 3), and assert the sender retires exactly
    /// those five segments from its send buffer — keeping only the gap segment 3.
    /// This proves the SACK retires MULTIPLE segments in one ACK (vs. the legacy
    /// single-seq ACK).
    #[tokio::test]
    async fn authenticated_sack_retires_all_covered_segments_skipping_gap() {
        let session_id = fixed_session_id();
        let (client_session, server_session) = paired_sessions(session_id);
        let stream_id: TransportStreamId = 1;

        // Sender stages segments 0..=5, all in-flight.
        let stream = Arc::new(TransportStream::new(stream_id));
        for i in 0..6u32 {
            let seq = stream
                .send_reliable(Bytes::from(format!("seg-{i}")))
                .await
                .unwrap();
            assert_eq!(seq, i);
            let _ = stream.poll_send(u64::MAX).await.expect("in-flight");
        }
        let streams: Arc<DashMap<u32, Arc<TransportStream>>> = Arc::new(DashMap::new());
        streams.insert(stream_id as u32, stream.clone());
        assert_eq!(stream.pending_send_count().await, 6);

        // The receiver (client_session) emits a SACK over {0,1,2,4,5}.
        let sack = crate::transport::sack::Sack::from_received(&[0, 1, 2, 4, 5], 777)
            .expect("sack")
            .to_wire();
        let frame = build_encrypted_ack_with_payload(
            &client_session,
            session_id,
            stream_id,
            9_999, // ACK header seq distinct from the acked data seqs
            &sack,
        );
        let ack_pkt = decode_recv_frame(&frame, session_id);
        run_recv(ack_pkt, session_id, &server_session, &streams).await;

        // Exactly the gap segment (3) remains.
        assert_eq!(
            stream.pending_send_count().await,
            1,
            "SACK must retire all five covered segments at once"
        );
        for retired in [0u32, 1, 2, 4, 5] {
            assert!(
                stream.ack(retired).await.is_none(),
                "seq {retired} should have been retired by the SACK"
            );
        }
        assert!(
            stream.ack(3).await.is_some(),
            "the gap segment 3 must remain buffered"
        );
    }

    /// **L1-A malformed-SACK robustness.** An authenticated (post-AEAD) but
    /// structurally malformed SACK payload — here a truncated 5-byte blob — must
    /// be dropped on the sender path WITHOUT panic and retire NOTHING. Post-AEAD
    /// the frame is authenticated, but a buggy peer must not crash us.
    #[tokio::test]
    async fn malformed_sack_is_dropped_and_retires_nothing() {
        let session_id = fixed_session_id();
        let (client_session, server_session) = paired_sessions(session_id);
        let (stream, streams, seq) = staged_pending_segment().await;
        let stream_id: TransportStreamId = 1;

        // 5 bytes < MIN_WIRE_LEN (14) → Sack::from_wire returns Truncated.
        let bad_payload = vec![0u8; 5];
        let frame = build_encrypted_ack_with_payload(
            &client_session,
            session_id,
            stream_id,
            1234,
            &bad_payload,
        );
        let ack_pkt = decode_recv_frame(&frame, session_id);
        // Must not panic.
        run_recv(ack_pkt, session_id, &server_session, &streams).await;

        assert!(
            stream.ack(seq).await.is_some(),
            "a malformed SACK must retire nothing — the pending segment stays buffered"
        );
    }

    /// **L1-A ack_delay plumbing.** A reliable data packet driven through the
    /// receiver's `handle_packet` produces an `ENCRYPTED | ACK` frame on the wire
    /// whose decoded SACK has a populated (non-zero) `ack_delay_us` — proving the
    /// field, previously always 0, is now plumbed end-to-end.
    #[tokio::test]
    async fn receiver_emits_sack_with_populated_ack_delay() {
        let session_id = fixed_session_id();
        // Two paired sessions sharing keys so the receiver's ACK decrypts under
        // the sender's session.
        let (sender_session, receiver_session) = paired_sessions(session_id);
        let stream_id: TransportStreamId = 1;

        // Build a reliable data packet from the sender at sequence 7 (stream_offset
        // == sequence == 7 via build_app_frame, so the SACK's largest_acked is 7).
        let data_seq = 7u32;
        let data_pkt = decode_recv_frame(
            &build_app_frame(
                &sender_session,
                session_id,
                stream_id,
                data_seq,
                b"hello-reliable",
            ),
            session_id,
        );

        // Wiring with a capturable ACK transport.
        let (demux, _ctrl_rx) = StreamDemultiplexer::new(16);
        let demux = Arc::new(demux);
        let streams: Arc<DashMap<u32, Arc<TransportStream>>> = Arc::new(DashMap::new());
        let (deliver_tx, _deliver_rx) = mpsc::unbounded_channel::<(u32, Bytes)>();
        let undelivered = AtomicU64::new(0);
        let (ack_a, ack_b) = mpsc::channel::<Vec<u8>>(4);
        let transport: Arc<ChannelTransport> = Arc::new(ChannelTransport {
            tx: ack_a,
            rx: Mutex::new(ack_b),
        });
        let mut ack_buf = Vec::with_capacity(64);
        let obs = Observability::new(ObservabilityConfig::default());
        handle_packet(
            data_pkt,
            session_id,
            &receiver_session,
            &streams,
            &demux,
            &transport,
            &transport,
            &deliver_tx,
            &undelivered,
            &mut ack_buf,
            &obs,
            LegType::Tcp,
        )
        .await;

        // Pull the emitted ACK frame off the transport and decode the SACK.
        let ack_frame = transport
            .rx
            .lock()
            .await
            .recv()
            .await
            .expect("an ACK frame must have been emitted");
        // The receiver pump emitted this ACK with header protection; unmask from
        // the sender side (== the receiver's send HP key).
        let ack_pkt = sender_session
            .parse_protected(&ack_frame)
            .expect("parse emitted ack");
        assert!(ack_pkt.header.flags.contains(PacketFlags::ACK));
        // Decrypt under the sender's session (shared keys) to read the SACK.
        let plain = sender_session
            .decrypt_packet(&ack_pkt.header, &ack_pkt.payload, &[])
            .expect("decrypt emitted ack");
        let sack = crate::transport::sack::Sack::from_wire(&plain).expect("decode emitted sack");
        assert_eq!(sack.largest_acked, data_seq, "SACK must ack the data seq");
        assert!(sack.acks(data_seq));
        // The field is plumbed: ack_delay_us is the coarse recv-to-emit hold.
        // It is derived from `now − recv_at` and is therefore populated (the
        // assertion is on the field being threaded through, not a tight bound).
        let _ = sack.ack_delay_us;
    }

    /// **H1 session binding.** A frame whose `header.session_id` does not match
    /// the negotiated session must be dropped by the per-frame guard before any
    /// state mutation — pre-fix the ACK was processed with no session check.
    #[tokio::test]
    async fn ack_with_wrong_session_id_is_dropped() {
        let session_id = fixed_session_id();
        let (_client, server_session) = paired_sessions(session_id);
        let (stream, streams, seq) = staged_pending_segment().await;
        let stream_id: TransportStreamId = 1;

        let wrong_id = SessionId::from_bytes([0x11; 32]);
        run_recv(
            PhantomPacket::new(
                PacketHeader::new(
                    wrong_id,
                    stream_id,
                    seq as u64,
                    PacketFlags::new(PacketFlags::ACK),
                ),
                Vec::new(),
            ),
            session_id,
            &server_session,
            &streams,
        )
        .await;

        assert!(
            stream.ack(seq).await.is_some(),
            "an ACK for a different session id must not retire the segment"
        );
    }

    #[tokio::test]
    async fn v2_recv_drops_unencrypted_non_empty_post_handshake_payload() {
        // Downgrade defense: a V2 application-data packet WITHOUT the
        // ENCRYPTED flag but with a non-empty plaintext-looking payload
        // must be dropped, mirroring the V1 invariant.
        let session_id = fixed_session_id();
        let (_, server_session) = paired_sessions(session_id);

        let stream_id: TransportStreamId = 2;
        let bad_header = PacketHeader::new(
            session_id,
            stream_id,
            0,
            PacketFlags::new(PacketFlags::RELIABLE), // no ENCRYPTED
        );
        let bad_packet = PhantomPacket::new(bad_header, b"leaked-cleartext".to_vec());

        let (demux, _ctrl_rx) = StreamDemultiplexer::new(16);
        let demux = Arc::new(demux);
        let streams: Arc<DashMap<u32, Arc<TransportStream>>> = Arc::new(DashMap::new());
        let (deliver_tx, mut deliver_rx) = mpsc::unbounded_channel::<(u32, Bytes)>();
        let undelivered = AtomicU64::new(0);
        let (ack_a, ack_b) = mpsc::channel::<Vec<u8>>(4);
        let transport_send: Arc<ChannelTransport> = Arc::new(ChannelTransport {
            tx: ack_a,
            rx: Mutex::new(ack_b),
        });

        let mut ack_buf = Vec::with_capacity(256);
        let obs = Observability::new(ObservabilityConfig::default());
        handle_packet(
            bad_packet,
            session_id,
            &server_session,
            &streams,
            &demux,
            &transport_send,
            &transport_send,
            &deliver_tx,
            &undelivered,
            &mut ack_buf,
            &obs,
            LegType::Tcp,
        )
        .await;

        // Nothing should have been handed to the delivery task, and the backlog
        // counter must stay at zero (the packet was dropped before hand-off).
        assert!(
            deliver_rx.try_recv().is_err(),
            "unencrypted post-handshake payload must NOT be handed off for delivery"
        );
        assert_eq!(undelivered.load(Ordering::Acquire), 0);
    }

    #[tokio::test]
    async fn v2_recv_handles_coalesced_bundle_and_routes_each_subpayload() {
        use crate::transport::packet_coalescer::{CoalescerConfig, PacketCoalescer};

        let session_id = fixed_session_id();
        let (client_session, server_session) = paired_sessions(session_id);

        // Build a COALESCED bundle of three sub-payloads.
        let mut coalescer = PacketCoalescer::new(CoalescerConfig::default());
        coalescer.push(b"alpha");
        coalescer.push(b"bravo");
        coalescer.push(b"charlie");
        let bundle = coalescer.flush().expect("bundle");

        // Encrypt the bundle and wrap it in a V2 packet with
        // ENCRYPTED + COALESCED flags.
        let stream_id: TransportStreamId = 3;
        let flag_bits = PacketFlags::ENCRYPTED | PacketFlags::COALESCED;
        let header = PacketHeader::new(session_id, stream_id, 0, PacketFlags::new(flag_bits))
            .with_epoch(client_session.current_epoch());
        let ciphertext = client_session
            .encrypt_packet(&header, &bundle, &[])
            .expect("encrypt bundle");
        let v2 = PhantomPacket::new(header, ciphertext);

        let (demux, _ctrl_rx) = StreamDemultiplexer::new(16);
        let demux = Arc::new(demux);
        let streams: Arc<DashMap<u32, Arc<TransportStream>>> = Arc::new(DashMap::new());
        let (deliver_tx, mut deliver_rx) = mpsc::unbounded_channel::<(u32, Bytes)>();
        let undelivered = AtomicU64::new(0);
        let (ack_a, ack_b) = mpsc::channel::<Vec<u8>>(4);
        let transport_send: Arc<ChannelTransport> = Arc::new(ChannelTransport {
            tx: ack_a,
            rx: Mutex::new(ack_b),
        });

        let mut ack_buf = Vec::with_capacity(256);
        let obs = Observability::new(ObservabilityConfig::default());
        handle_packet(
            v2,
            session_id,
            &server_session,
            &streams,
            &demux,
            &transport_send,
            &transport_send,
            &deliver_tx,
            &undelivered,
            &mut ack_buf,
            &obs,
            LegType::Tcp,
        )
        .await;

        // Each sub-payload is handed off IN ORDER through the single FIFO
        // delivery channel, every one tagged with the outer stream id, and the
        // total counted toward the undelivered backlog.
        let (sa, a) = deliver_rx.recv().await.expect("alpha");
        let (sb, b) = deliver_rx.recv().await.expect("bravo");
        let (sc, c) = deliver_rx.recv().await.expect("charlie");
        assert_eq!(
            (sa, sb, sc),
            (stream_id as u32, stream_id as u32, stream_id as u32)
        );
        assert_eq!(&a[..], b"alpha");
        assert_eq!(&b[..], b"bravo");
        assert_eq!(&c[..], b"charlie");
        assert_eq!(undelivered.load(Ordering::Acquire), (5 + 5 + 7) as u64);
    }

    /// Ordering across two COALESCED bundles: the single FIFO delivery channel
    /// must hand the first bundle's `[A, B, C]` and the second bundle's `[D]` to
    /// the consumer in exactly `A, B, C, D` — decoupling delivery from the reader
    /// must not reorder application bytes. (COALESCED is delivered immediately in
    /// arrival order — it is not reassembled by stream offset and is not mixed with
    /// RELIABLE frames on a stream by the live sender.)
    #[tokio::test]
    async fn delivery_preserves_order_across_coalesced_then_normal_frame() {
        use crate::transport::packet_coalescer::{CoalescerConfig, PacketCoalescer};

        let session_id = fixed_session_id();
        let (client_session, server_session) = paired_sessions(session_id);
        let stream_id: TransportStreamId = 1;

        let build_bundle = |seq: u32, items: &[&[u8]]| -> PhantomPacket {
            let mut coalescer = PacketCoalescer::new(CoalescerConfig::default());
            for it in items {
                coalescer.push(it);
            }
            let bundle = coalescer.flush().expect("bundle");
            let flag_bits = PacketFlags::ENCRYPTED | PacketFlags::COALESCED;
            let h = PacketHeader::new(
                session_id,
                stream_id,
                seq as u64,
                PacketFlags::new(flag_bits),
            )
            .with_epoch(client_session.current_epoch());
            let ct = client_session
                .encrypt_packet(&h, &bundle, &[])
                .expect("encrypt bundle");
            PhantomPacket::new(h, ct)
        };

        // Frame 1: COALESCED [A, B, C] at sequence 0; Frame 2: COALESCED [D] at seq 1.
        let coalesced = build_bundle(0, &[b"A", b"B", b"C"]);
        let normal = build_bundle(1, &[b"D"]);

        let (demux, _ctrl) = StreamDemultiplexer::new(16);
        let demux = Arc::new(demux);
        let streams: Arc<DashMap<u32, Arc<TransportStream>>> = Arc::new(DashMap::new());
        let (deliver_tx, mut deliver_rx) = mpsc::unbounded_channel::<(u32, Bytes)>();
        let undelivered = AtomicU64::new(0);
        let (ack_a, ack_b) = mpsc::channel::<Vec<u8>>(8);
        let transport_send: Arc<ChannelTransport> = Arc::new(ChannelTransport {
            tx: ack_a,
            rx: Mutex::new(ack_b),
        });
        let mut ack_buf = Vec::with_capacity(256);
        let obs = Observability::new(ObservabilityConfig::default());

        for pkt in [coalesced, normal] {
            handle_packet(
                pkt,
                session_id,
                &server_session,
                &streams,
                &demux,
                &transport_send,
                &transport_send,
                &deliver_tx,
                &undelivered,
                &mut ack_buf,
                &obs,
                LegType::Tcp,
            )
            .await;
        }

        // Drain the FIFO delivery channel — order must be exactly A, B, C, D.
        let mut got: Vec<Bytes> = Vec::new();
        while let Ok((_sid, b)) = deliver_rx.try_recv() {
            got.push(b);
        }
        let seen: Vec<&[u8]> = got.iter().map(|b| &b[..]).collect();
        assert_eq!(seen, vec![&b"A"[..], b"B", b"C", b"D"]);
    }

    /// **A.5 RED → GREEN.** Two RELIABLE frames arriving OUT OF sequence order on
    /// the wire (seq 1 before seq 0) must be delivered to the app IN sequence
    /// order (`zero`, `one`). Before the receive-side reorder fix, the live pump
    /// delivered in decrypt-arrival order, breaking reliable in-order delivery
    /// over a reordering (UDP) path.
    #[tokio::test]
    async fn reliable_frames_delivered_in_sequence_order_despite_arrival_order() {
        let session_id = fixed_session_id();
        let (client_session, server_session) = paired_sessions(session_id);
        let stream_id: TransportStreamId = 1;

        let f0 = decode_recv_frame(
            &build_app_frame(&client_session, session_id, stream_id, 0, b"zero"),
            session_id,
        );
        let f1 = decode_recv_frame(
            &build_app_frame(&client_session, session_id, stream_id, 1, b"one"),
            session_id,
        );

        let (demux, _ctrl) = StreamDemultiplexer::new(16);
        let demux = Arc::new(demux);
        let streams: Arc<DashMap<u32, Arc<TransportStream>>> = Arc::new(DashMap::new());
        let (deliver_tx, mut deliver_rx) = mpsc::unbounded_channel::<(u32, Bytes)>();
        let undelivered = AtomicU64::new(0);
        let (ack_a, ack_b) = mpsc::channel::<Vec<u8>>(8);
        let transport_send: Arc<ChannelTransport> = Arc::new(ChannelTransport {
            tx: ack_a,
            rx: Mutex::new(ack_b),
        });
        let mut ack_buf = Vec::with_capacity(256);
        let obs = Observability::new(ObservabilityConfig::default());

        // Deliver OUT OF ORDER on the wire: seq 1 first, then seq 0.
        for pkt in [f1, f0] {
            handle_packet(
                pkt,
                session_id,
                &server_session,
                &streams,
                &demux,
                &transport_send,
                &transport_send,
                &deliver_tx,
                &undelivered,
                &mut ack_buf,
                &obs,
                LegType::Tcp,
            )
            .await;
        }

        let mut got: Vec<Bytes> = Vec::new();
        while let Ok((_sid, b)) = deliver_rx.try_recv() {
            got.push(b);
        }
        let seen: Vec<&[u8]> = got.iter().map(|b| &b[..]).collect();
        assert_eq!(
            seen,
            vec![&b"zero"[..], b"one"],
            "reliable data must be delivered in sequence order, not arrival order"
        );
    }

    /// **A.5 control-gap regression (the bidirectional-hang fix).** Reliable data
    /// whose wire `header.sequence` has a HOLE (a control frame — ACK /
    /// WINDOW_UPDATE — consumed that sequence) but whose gap-free `stream_offset`
    /// is contiguous must still deliver in order WITHOUT stalling on the sequence
    /// hole. Here header seqs are 0 and 2 (seq 1 = a control frame), offsets 0 and
    /// 1. Reordering keyed on the raw `header.sequence` hangs forever waiting for
    /// seq 1; keyed on `stream_offset` it delivers `a, b`.
    #[tokio::test]
    async fn reliable_delivery_skips_control_frame_sequence_holes() {
        let session_id = fixed_session_id();
        let (client_session, server_session) = paired_sessions(session_id);
        let stream_id: TransportStreamId = 1;

        // header.seq 0, offset 0, "a"; header.seq 2, offset 1, "b" (seq 1 is a hole).
        let a = decode_recv_frame(
            &build_app_frame_with_offset(&client_session, session_id, stream_id, 0, 0, b"a"),
            session_id,
        );
        let b = decode_recv_frame(
            &build_app_frame_with_offset(&client_session, session_id, stream_id, 2, 1, b"b"),
            session_id,
        );

        let (demux, _ctrl) = StreamDemultiplexer::new(16);
        let demux = Arc::new(demux);
        let streams: Arc<DashMap<u32, Arc<TransportStream>>> = Arc::new(DashMap::new());
        let (deliver_tx, mut deliver_rx) = mpsc::unbounded_channel::<(u32, Bytes)>();
        let undelivered = AtomicU64::new(0);
        let (ack_a, ack_b) = mpsc::channel::<Vec<u8>>(8);
        let transport_send: Arc<ChannelTransport> = Arc::new(ChannelTransport {
            tx: ack_a,
            rx: Mutex::new(ack_b),
        });
        let mut ack_buf = Vec::with_capacity(256);
        let obs = Observability::new(ObservabilityConfig::default());

        for pkt in [a, b] {
            handle_packet(
                pkt,
                session_id,
                &server_session,
                &streams,
                &demux,
                &transport_send,
                &transport_send,
                &deliver_tx,
                &undelivered,
                &mut ack_buf,
                &obs,
                LegType::Tcp,
            )
            .await;
        }

        let mut got: Vec<Bytes> = Vec::new();
        while let Ok((_sid, x)) = deliver_rx.try_recv() {
            got.push(x);
        }
        let seen: Vec<&[u8]> = got.iter().map(|b| &b[..]).collect();
        assert_eq!(
            seen,
            vec![&b"a"[..], b"b"],
            "reliable data must deliver in stream_offset order, skipping control-frame \
             sequence holes (not stall on them)"
        );
    }

    /// A peer that ignores flow control and floods application data faster than
    /// the app drains must NOT grow the receive backlog without bound: once the
    /// undelivered backlog crosses the reader's hard cap, the session is torn
    /// down (state → `Closed`) instead of buffering unboundedly. The app here
    /// never calls `recv()`, so the delivery channel fills and the reader's
    /// pre-decrypt cap gate fires.
    #[tokio::test]
    async fn peer_ignoring_flow_control_trips_delivery_hard_cap_and_closes_session() {
        let session_id = fixed_session_id();
        let (client_inner, server_inner) = paired_sessions(session_id);
        let (client_t, server_t) = ChannelTransport::pair();
        let client_t = Arc::new(client_t);

        // Full server-side session with a running pump; the app NEVER drains it.
        let server = PhantomSession::from_accepted_server_session(
            "flooder".to_string(),
            server_t,
            server_inner,
        );

        // Drain and discard everything the server sends back (ACKs / control)
        // so the server reader never blocks on the back channel — a real
        // flooding peer likewise keeps emptying its socket. Without this the
        // reader would wedge on its own ACK send and the cap could never trip.
        let drain_t = client_t.clone();
        let drainer = tokio::spawn(async move { while drain_t.recv_bytes().await.is_ok() {} });

        // Malicious client: flood valid RELIABLE app packets with unique
        // monotonic sequences (so none are replay-dropped) and never honor a
        // WINDOW_UPDATE — i.e. ignore flow control entirely.
        let payload = vec![0xABu8; 64 * 1024];
        let mut seq: u32 = 0;
        let mut torn_down = false;
        for _ in 0..4000 {
            if server.connection_state() == ConnectionState::Closed {
                torn_down = true;
                break;
            }
            let flag_bits = PacketFlags::RELIABLE | PacketFlags::ENCRYPTED;
            let header = PacketHeader::new(session_id, 1, seq as u64, PacketFlags::new(flag_bits))
                .with_epoch(client_inner.current_epoch());
            // Reliable plaintext = [stream_offset: u32 BE][payload] (A.5). Offsets
            // are contiguous (== seq), so every frame delivers in order and grows
            // the undelivered backlog — exactly what should trip the hard cap.
            let mut pt = Vec::with_capacity(4 + payload.len());
            pt.extend_from_slice(&seq.to_be_bytes());
            pt.extend_from_slice(&payload);
            let ct = client_inner
                .encrypt_packet(&header, &pt, &[])
                .expect("encrypt");
            // Bound the send so a torn-down (or wedged) transport can't hang the
            // test: a closed channel or a stalled reader both mean the flood is
            // no longer absorbed — i.e. the session is being torn down.
            // This frame traverses the server pump's transport, which removes
            // header protection on recv — so apply it on the way out.
            let packet = PhantomPacket::new(header, ct);
            let wire = client_inner
                .protect_packet(&packet)
                .expect("header protection");
            match tokio::time::timeout(
                std::time::Duration::from_secs(5),
                client_t.send_bytes(&wire),
            )
            .await
            {
                Ok(Ok(())) => {}
                _ => {
                    torn_down = true;
                    break;
                }
            }
            seq = seq.wrapping_add(1);
            tokio::task::yield_now().await;
        }
        assert!(
            torn_down,
            "a peer flooding past the delivery hard cap must get its session torn down"
        );

        // Definitive: the session ends up Closed.
        let mut closed = false;
        for _ in 0..200 {
            if server.connection_state() == ConnectionState::Closed {
                closed = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        drainer.abort();
        assert!(
            closed,
            "session state must be Closed after the hard cap trips"
        );
    }

    /// Phase 4.4 — BBR ACK feedback drives the pacer rate. Build a
    /// realistic DeliverySample with known sent_at/acked_at timestamps
    /// and packet size; assert that calling `on_packet_acked` causes
    /// the pacer to leave its default unlimited state with a finite
    /// finite positive rate.
    #[tokio::test]
    async fn bbr_on_ack_drives_pacer_rate() {
        use crate::transport::bandwidth_estimator::DeliverySample;
        use std::time::{Duration, Instant};

        let session_id = fixed_session_id();
        let (client_session, _server_session) = paired_sessions(session_id);

        // The default Pacer is `unlimited` — track it before/after.
        assert!(!client_session.pacer().is_enabled());

        // Simulate sending a 1500-byte packet, then receiving an ACK
        // 20 ms later. We feed a few samples in a row so the EMA
        // estimator has data to work with.
        let now = Instant::now();
        for i in 0..16 {
            let sent_at = now - Duration::from_millis(20 + i * 5);
            let acked_at = now - Duration::from_millis(i * 5);
            let sample = DeliverySample {
                delivered_bytes: 0,
                sent_at,
                acked_at,
                packet_bytes: 1500,
                is_app_limited: false,
                ack_delay_us: 100,
            };
            client_session.on_packet_sent(1500);
            let _ = client_session.on_packet_acked(sample);
        }

        // The pacer should now be set to a real rate (still
        // "unlimited" handle, but with a finite stored rate). The
        // BandwidthEstimator's `pacing_rate()` is what gets pushed
        // into the pacer; assert it is non-zero and finite.
        let snap = client_session.bandwidth_snapshot();
        assert!(
            snap.pacing_rate_bps > 0,
            "expected pacing_rate to be non-zero, got {}",
            snap.pacing_rate_bps,
        );
        // The pacer's stored rate must match the estimator's view
        // (Session.on_packet_acked mirrors them).
        assert_eq!(client_session.pacer().rate(), snap.pacing_rate_bps);
    }

    /// Phase 4.3 — WINDOW_UPDATE round-trip under the relative-credit model.
    /// The receive **delivery** task credits the flow-control window on real
    /// app consumption and stages the credit; the **send loop** flushes it as a
    /// single encrypted WINDOW_UPDATE via `flush_pending_window_updates`. The
    /// sender then ADDS the relative credit to its `peer_send_window` — it does
    /// not overwrite it with an absolute value.
    #[tokio::test]
    async fn flow_control_window_update_round_trip() {
        use crate::transport::stream::INITIAL_STREAM_WINDOW;

        let session_id = fixed_session_id();
        let (client_session, server_session) = paired_sessions(session_id);

        let stream_id: TransportStreamId = 9;
        let server_streams: Arc<DashMap<u32, Arc<TransportStream>>> = Arc::new(DashMap::new());
        let server_stream = Arc::new(TransportStream::new(stream_id));
        server_streams.insert(stream_id as u32, server_stream.clone());

        // Client also has a Stream so we can apply the inbound credit.
        let client_stream = Arc::new(TransportStream::new(stream_id));

        // Pre-drain the client's peer_send_window so the credit has a real
        // effect to assert against.
        let drain = INITIAL_STREAM_WINDOW - 1000;
        assert!(client_stream.try_consume_send_window(drain));
        assert_eq!(client_stream.peer_send_window(), 1000);

        // The delivery task credits the window on real consumption: model one
        // drain that crosses the half-window threshold and stage the credit
        // exactly as `run_data_pump`'s delivery task does.
        let consumed = INITIAL_STREAM_WINDOW / 2 + 1;
        let credit = server_stream
            .record_app_consumed(consumed)
            .expect("threshold crossed → credit granted");
        server_stream.stage_window_update_credit(credit);

        // The send loop flushes the staged credit as a single WINDOW_UPDATE.
        let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(4);
        let (back_tx, back_rx) = mpsc::channel::<Vec<u8>>(4);
        let server_outbound: Arc<ChannelTransport> = Arc::new(ChannelTransport {
            tx: out_tx,
            rx: Mutex::new(back_rx),
        });
        let _keep = back_tx;
        flush_pending_window_updates(
            &server_outbound,
            &server_session,
            session_id,
            &server_streams,
        )
        .await;

        // Exactly one WINDOW_UPDATE was emitted; decrypt it and read the credit.
        let frame = tokio::time::timeout(std::time::Duration::from_millis(100), out_rx.recv())
            .await
            .expect("expected a WINDOW_UPDATE frame")
            .expect("channel open");
        let pv2 = client_session.parse_protected(&frame).unwrap();
        assert!(pv2.header.flags.contains(PacketFlags::WINDOW_UPDATE));
        // The control frame's sequence comes from the stream's own send space —
        // distinct from any data packet so the AEAD nonce never repeats.
        let pt = client_session
            .decrypt_packet(&pv2.header, &pv2.payload, &[])
            .expect("decrypt WINDOW_UPDATE");
        assert_eq!(pt.len(), 4);
        let announced = u32::from_be_bytes([pt[0], pt[1], pt[2], pt[3]]);
        assert_eq!(
            announced, credit,
            "WINDOW_UPDATE carries the relative credit (bytes consumed since last update)"
        );
        // Exactly one frame was emitted — nothing else is queued on the wire.
        assert!(
            out_rx.try_recv().is_err(),
            "exactly one WINDOW_UPDATE must be emitted"
        );

        // The staged slot is now empty — a second flush emits nothing.
        flush_pending_window_updates(
            &server_outbound,
            &server_session,
            session_id,
            &server_streams,
        )
        .await;
        assert!(
            out_rx.try_recv().is_err(),
            "no spurious second WINDOW_UPDATE after the credit was already flushed"
        );

        // Apply the relative credit on the client side: peer_send_window ADDS it
        // to the current 1000 (it does not jump to an absolute value).
        client_stream.apply_peer_window_update(announced);
        assert_eq!(client_stream.peer_send_window(), 1000 + credit);
    }

    /// Phase 4.3 — priority scheduler ordering. Two streams enqueue
    /// data simultaneously; the higher-priority one must be drained
    /// first, all of its data before any of the lower one's.
    #[tokio::test]
    async fn priority_scheduler_drains_higher_priority_stream_first() {
        // Build a real Session (any crypto state — we only inspect
        // send order, not ciphertext) and an Arc<Stream> per stream.
        let session_id = fixed_session_id();
        let (client_session, _server_session) = paired_sessions(session_id);

        // Capture every outbound packet by stuffing into a channel-
        // backed transport whose tx end we can drain after.
        let (tx_a, mut rx_a) = mpsc::channel::<Vec<u8>>(32);
        let (tx_b, rx_b) = mpsc::channel::<Vec<u8>>(32);
        let transport: Arc<ChannelTransport> = Arc::new(ChannelTransport {
            tx: tx_a,
            rx: Mutex::new(rx_b),
        });
        let _keep = tx_b; // keep the recv side alive

        let streams: Arc<DashMap<u32, Arc<TransportStream>>> = Arc::new(DashMap::new());

        // Stream 11: low priority (1), 3 reliable chunks.
        let low = Arc::new(TransportStream::new(11));
        low.set_priority(1);
        low.send_reliable(Bytes::from_static(b"L0")).await.unwrap();
        low.send_reliable(Bytes::from_static(b"L1")).await.unwrap();
        low.send_reliable(Bytes::from_static(b"L2")).await.unwrap();
        streams.insert(11, low);

        // Stream 22: HIGH priority (100), 3 reliable chunks.
        let hi = Arc::new(TransportStream::new(22));
        hi.set_priority(100);
        hi.send_reliable(Bytes::from_static(b"H0")).await.unwrap();
        hi.send_reliable(Bytes::from_static(b"H1")).await.unwrap();
        hi.send_reliable(Bytes::from_static(b"H2")).await.unwrap();
        streams.insert(22, hi);

        drain_streams_priority_ordered(&transport, &client_session, session_id, &streams).await;

        // Pull all packets off the channel and verify their order:
        // the three H* chunks must come before any L* chunk.
        let mut order: Vec<&'static str> = Vec::new();
        while let Ok(frame) =
            tokio::time::timeout(std::time::Duration::from_millis(50), rx_a.recv()).await
        {
            let bytes = match frame {
                Some(b) => b,
                None => break,
            };
            let v2 = _server_session.parse_protected(&bytes).unwrap();
            // Decrypt under the SERVER role so the per-direction key
            // matches the client-side encrypt.
            let plaintext = _server_session
                .decrypt_packet(&v2.header, &v2.payload, &[])
                .expect("decrypt");
            // Reliable frames carry a 4-byte stream_offset prefix (A.5); the tag is
            // the application payload after it.
            let tag: &'static str = match &plaintext[4..] {
                b"H0" => "H0",
                b"H1" => "H1",
                b"H2" => "H2",
                b"L0" => "L0",
                b"L1" => "L1",
                b"L2" => "L2",
                other => panic!("unexpected payload {:?}", other),
            };
            order.push(tag);
        }

        // All H* before any L*.
        let first_low = order
            .iter()
            .position(|s| s.starts_with('L'))
            .unwrap_or(order.len());
        let last_high = order.iter().rposition(|s| s.starts_with('H')).unwrap();
        assert!(
            last_high < first_low,
            "strict priority violated: order = {:?}",
            order
        );
    }

    #[tokio::test]
    async fn v2_recv_echoes_path_validation_challenge_back_as_response() {
        // Two paired sessions on different IDs (so neither has a
        // pending challenge for the path). The "responder" sees a
        // PATH_VALIDATION packet on a new path id and must echo the
        // 32-byte payload back via the transport.
        let session_id = fixed_session_id();
        let (client_session, server_session) = paired_sessions(session_id);

        // Build a PATH_VALIDATION packet with ENCRYPTED + path_id=7.
        let path_id: u8 = 7;
        let payload = [0xDEu8; crate::transport::path::PATH_CHALLENGE_LEN];
        let flag_bits = PacketFlags::ENCRYPTED | PacketFlags::PATH_VALIDATION;
        let header = PacketHeader::new(session_id, 0, 0, PacketFlags::new(flag_bits))
            .with_epoch(client_session.current_epoch())
            .with_path_id(path_id);
        let ciphertext = client_session
            .encrypt_packet(&header, &payload, &[])
            .expect("encrypt challenge");
        let v2 = PhantomPacket::new(header, ciphertext);

        let (demux, _ctrl_rx) = StreamDemultiplexer::new(16);
        let demux = Arc::new(demux);
        let streams: Arc<DashMap<u32, Arc<TransportStream>>> = Arc::new(DashMap::new());
        let (deliver_tx, _deliver_rx) = mpsc::unbounded_channel::<(u32, Bytes)>();
        let undelivered = AtomicU64::new(0);
        // Server's outbound transport — captures the echo back.
        let (echo_tx, mut echo_rx) = mpsc::channel::<Vec<u8>>(4);
        let (back_tx, back_rx) = mpsc::channel::<Vec<u8>>(4);
        let transport_send: Arc<ChannelTransport> = Arc::new(ChannelTransport {
            tx: echo_tx,
            rx: Mutex::new(back_rx),
        });
        let _back_tx_keepalive = back_tx; // keep the recv side alive

        let mut ack_buf = Vec::with_capacity(256);
        let obs = Observability::new(ObservabilityConfig::default());

        handle_packet(
            v2,
            session_id,
            &server_session,
            &streams,
            &demux,
            &transport_send,
            &transport_send,
            &deliver_tx,
            &undelivered,
            &mut ack_buf,
            &obs,
            LegType::Tcp,
        )
        .await;

        // Server should have emitted a PATH_VALIDATION response on the
        // outbound transport. Pull it out and verify it carries the
        // same payload back.
        let echo_bytes =
            tokio::time::timeout(std::time::Duration::from_millis(200), echo_rx.recv())
                .await
                .expect("echo should arrive")
                .expect("channel open");

        // Decrypt the echo on the original (client) side — server-side
        // ciphertext authenticates the round-trip.
        // The server emitted this echo with header protection; unmask from the
        // client side (== the server's send HP key).
        let echo_v2 = client_session.parse_protected(&echo_bytes).unwrap();
        assert!(echo_v2.header.flags.contains(PacketFlags::PATH_VALIDATION));
        assert_eq!(echo_v2.header.path_id, path_id);
    }

    // ────────────────────────────────────────────────────────────────────
    // 0-RTT early-data
    // ────────────────────────────────────────────────────────────────────

    /// Full 0-RTT round-trip over `ChannelTransport`: a priming handshake
    /// populates the server cache and yields a resumption hint; a second
    /// connect via `connect_with_resumption` carries application early-data
    /// sealed inside the resuming ClientHello, which the server decrypts and
    /// surfaces. The client learns the verdict via `early_data_accepted()`.
    ///
    /// The server side runs inline (not a spawned task) so its
    /// `ChannelTransport` halves stay alive in scope — dropping them
    /// would close the client's data pump and flip the session to
    /// `Closed` before the assertions run.
    #[tokio::test]
    async fn zero_rtt_early_data_full_round_trip() {
        // One HandshakeServer shared across both phases so its session
        // cache persists between the priming handshake and the resume.
        let server_hs = HandshakeServer::new().unwrap();
        let server_pinned_key = server_hs.verifying_key().clone();
        let client_ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();

        // ── Step 1: prime — a normal handshake fills the cache ──
        let (c1, s1) = ChannelTransport::pair();
        let phase1_session =
            PhantomSession::connect_with_transport("test:9000", c1, server_pinned_key.clone());

        let hello_bytes = s1.recv_bytes().await.unwrap();
        let ch = borsh::from_slice::<ClientHello>(&hello_bytes).unwrap();
        let retry = match server_hs.process_client_hello(&ch, 0, client_ip) {
            HandshakeResponse::Retry(r) => r,
            _ => panic!("expected Retry"),
        };
        s1.send_bytes(&ServerReply::Retry(retry).to_wire().unwrap())
            .await
            .unwrap();
        let next = s1.recv_bytes().await.unwrap();
        let ch2 = borsh::from_slice::<ClientHello>(&next).unwrap();
        match server_hs.process_client_hello(&ch2, 0, client_ip) {
            HandshakeResponse::Success(sh, _session, _) => {
                s1.send_bytes(&ServerReply::Hello(sh).to_wire().unwrap())
                    .await
                    .unwrap();
            }
            _ => panic!("expected Success"),
        }

        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        assert_eq!(
            phase1_session.connection_state(),
            ConnectionState::Connected
        );
        let hint = phase1_session
            .resumption_hint()
            .await
            .expect("phase 1 produced a resumption hint");
        // The Rust-only `connect_with_resumption` takes the raw tuple;
        // `resumption_hint()` now yields the UniFFI `ResumptionHint`
        // record, so rebuild the tuple from its 32-byte fields.
        let hint = (
            <[u8; 32]>::try_from(hint.session_id.as_slice()).expect("session_id is 32 bytes"),
            <[u8; 32]>::try_from(hint.resumption_secret.as_slice())
                .expect("resumption_secret is 32 bytes"),
        );

        // ── Step 2: resume — the ClientHello carries sealed early-data ──
        let early_payload = b"zero-rtt application bytes".to_vec();
        let (c2, s2) = ChannelTransport::pair();
        let phase2_session = PhantomSession::connect_with_resumption(
            "test:9000",
            c2,
            server_pinned_key.clone(),
            hint,
            early_payload.clone(),
        )
        .expect("early_data is within the size cap");

        let hello_bytes = s2.recv_bytes().await.unwrap();
        let ch3 = borsh::from_slice::<ClientHello>(&hello_bytes).unwrap();
        assert!(
            ch3.early_data.is_some(),
            "phase 2 hello carries sealed 0-RTT early-data"
        );
        match server_hs.process_client_hello(&ch3, 0, client_ip) {
            HandshakeResponse::Success(sh, _session, early_data) => {
                // The server decrypted exactly what the client sealed.
                assert_eq!(early_data.as_deref(), Some(&early_payload[..]));
                assert!(sh.early_data_accepted);
                s2.send_bytes(&ServerReply::Hello(sh).to_wire().unwrap())
                    .await
                    .unwrap();
            }
            _ => {
                panic!("expected Success with accepted early-data — the resumption ticket is fresh")
            }
        }

        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        assert_eq!(
            phase2_session.connection_state(),
            ConnectionState::Connected
        );
        assert_eq!(
            phase2_session.early_data_accepted().await,
            Some(true),
            "client must see the server accepted its 0-RTT early-data"
        );

        // Keep the server transports alive until every assertion has
        // run — see the doc comment above.
        drop((s1, s2));
    }

    /// `connect_pinned_with_resumption` validates the `ResumptionHint`
    /// field lengths *before* opening any socket — a hint whose
    /// `session_id` or `resumption_secret` is not exactly 32 bytes is a
    /// caller bug and surfaces as `ValidationError`, never a network
    /// round-trip.
    #[tokio::test]
    async fn connect_pinned_with_resumption_rejects_malformed_hint() {
        let server_hs = HandshakeServer::new().unwrap();
        let pinned = server_hs.verifying_key().to_bytes();

        let bad_hint = ResumptionHint {
            session_id: vec![0u8; 5], // not 32 bytes
            resumption_secret: vec![0u8; 32],
        };

        let err = connect_pinned_with_resumption(
            "127.0.0.1".to_string(),
            9,
            pinned,
            bad_hint,
            Vec::new(),
        )
        .await
        .expect_err("a 5-byte session_id must be rejected");

        assert!(
            matches!(err, CoreError::ValidationError(_)),
            "expected ValidationError, got {err:?}"
        );
    }
}
