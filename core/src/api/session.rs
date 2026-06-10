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
use crate::transport::handshake::{
    HandshakeClient, HelloRetryRequest, ServerHello, ServerReject, EARLY_DATA_MAX_LEN,
};
use crate::transport::multiplexer::StreamDemultiplexer;
use crate::transport::packet_coalescer_codec::unwrap_coalesced_packet;
use crate::transport::path_validation_codec::build_path_validation_packet;
use crate::transport::session::Session;
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
            _ => Self::Failed,
        }
    }

    /// Whether data can flow (classical or better).
    pub fn is_data_ready(&self) -> bool {
        matches!(
            self,
            Self::ClassicalReady | Self::PqcUpgrading | Self::PqcReady | Self::Connected
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
    let mut retry_rounds: u32 = 0;

    loop {
        let bytes = borsh::to_vec(&hello).map_err(|e| {
            CoreError::SerializationError(format!("ClientHello encode failed: {}", e))
        })?;
        transport.send_bytes(&bytes).await?;
        let resp = transport.recv_bytes().await?;

        // The reply is one of three shapes: a `ServerHello` (success), a
        // `HelloRetryRequest` (cookie/PoW demand), or a `ServerReject` (the
        // server cannot speak our version). Try the success shape first — a
        // retry/reject blob is far too small to deserialize as a multi-KiB
        // ServerHello, so the disambiguation is unambiguous.
        if let Ok(sh) = borsh::from_slice::<ServerHello>(&resp) {
            let (session, accepted) =
                handshake.process_server_hello(&hello, &sh, Some(expected_server_key))?;
            return Ok((session, accepted));
        } else if let Ok(reject) = borsh::from_slice::<ServerReject>(&resp) {
            // The marker guard keeps a same-sized non-reject blob from being
            // mistaken for a reject. We surface this as a hard error and do
            // NOT auto-downgrade to `reject.supported_version` — a forced
            // downgrade on an injected reject would defeat the transcript-bound
            // version pin (Invariant 7).
            if reject.has_marker() {
                return Err(CoreError::HandshakeError(format!(
                    "server rejected the handshake: unsupported protocol version \
                     (client speaks v{}, server speaks v{})",
                    hello.version, reject.supported_version
                )));
            }
            return Err(CoreError::HandshakeError(
                "invalid ServerHello, Retry, or Reject received".into(),
            ));
        } else if let Ok(retry) = borsh::from_slice::<HelloRetryRequest>(&resp) {
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
            continue;
        } else {
            return Err(CoreError::HandshakeError(
                "invalid ServerHello, Retry, or Reject received".into(),
            ));
        }
    }
}

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

    // ── Raw-app session stream (reserved id 1) ──
    // The connectionless `send()` / `recv()` surface is multiplexed onto one
    // reserved stream so it gets the same reliable-delivery machinery as
    // explicitly-opened streams: `drain_streams_priority_ordered` (re)transmits
    // its buffered segments on the poll tick / outbound-ready notify, and
    // inbound ACKs for id 1 clear them via `Stream::ack`. The demultiplexer
    // hands out ids 2+, so this never collides with a user-opened stream.
    const RAW_APP_STREAM_ID: u32 = 1;
    let raw_stream = Arc::new(Stream::new(RAW_APP_STREAM_ID as TransportStreamId));
    streams.insert(RAW_APP_STREAM_ID, raw_stream.clone());

    // ── Flush queued early-data onto the raw-app stream ──
    // Routed through the stream (not a one-shot direct send) so queued
    // pre-handshake data is buffered for retransmit just like post-handshake
    // sends — a dropped early-data frame is recovered, not lost.
    {
        let mut queue = send_queue.lock().await;
        let count = queue.len();
        for msg in queue.drain(..) {
            for chunk in msg.chunks(TRANSPORT_MTU) {
                raw_stream
                    .send_reliable(Bytes::copy_from_slice(chunk))
                    .await;
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
                // (emitted there, under rekey ownership, so it is epoch-safe).
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
        // Monotonic sequence space for outbound PATH_VALIDATION packets.
        // Local to the recv task because that's where
        // path-validation echoes are emitted in response to incoming
        // challenges. Wraps via `wrapping_add` — sequence space is the
        // session's overall stream-0 control space.
        let mut path_validation_seq: u32 = 0;
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

            // A malformed / unparseable frame (no legitimate peer produces
            // one) is dropped — never a panic.
            let packet = match PhantomPacket::from_wire(&data) {
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
                &mut path_validation_seq,
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
    // Outbound WINDOW_UPDATE control packets are emitted on the send loop — the
    // single writer that also owns the rekey lock — so the encrypted control
    // frame is always sealed under a consistent epoch. The delivery task only
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
                            raw_stream
                                .send_reliable(Bytes::copy_from_slice(chunk))
                                .await;
                        }
                        crypto_session.notify_outbound_ready();
                    }
                    Some(SessionCommand::SendStreamReliable { stream_id, data }) => {
                        if let Some(stream) = streams.get(&stream_id) {
                            for chunk in data.chunks(TRANSPORT_MTU) {
                                stream.send_reliable(Bytes::copy_from_slice(chunk)).await;
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
                            // Same per-stream sequence space as the stream's data
                            // (and its WINDOW_UPDATEs) so this bare FIN cannot
                            // collide on the AEAD nonce / replay window.
                            let seq = stream.next_send_sequence();
                            let _ = send_app_data(
                                &transport,
                                &crypto_session,
                                session_id,
                                stream_id as TransportStreamId,
                                seq,
                                &[],
                                PacketFlags::FIN,
                            ).await;
                        }
                        streams.remove(&stream_id);
                        demux.close_stream(stream_id);
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
    state.store(ConnectionState::Closed as u8, Ordering::Relaxed);
    // Session torn down — drop the active-session gauge back down.
    observability.session_closed(leg);
}

/// Emit any flow-control credit the receive **delivery** task staged.
///
/// The delivery task credits the window on real app consumption and stages the
/// relative credit via `Stream::stage_window_update_credit` + a send-loop wake;
/// the send loop (this, the single rekey owner) actually encrypts and sends the
/// `WINDOW_UPDATE`, so the control frame is always sealed under a consistent
/// epoch. The staged credits are snapshotted out of the `DashMap` first so no
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
        // Draw the control-frame sequence from the SAME per-stream outbound
        // space as application data (`Stream::next_send_sequence`) so a
        // WINDOW_UPDATE never collides with a data packet on (stream_id,
        // sequence) — a collision would reuse an AEAD nonce within the epoch and
        // be dropped by the peer's replay window, silently starving flow control.
        let seq = stream.next_send_sequence();
        if !send_window_update(
            transport,
            crypto_session,
            session_id,
            stream_id as TransportStreamId,
            seq,
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
            if !send_app_data(
                transport,
                crypto_session,
                session_id,
                stream_id as TransportStreamId,
                seg.seq,
                &seg.data,
                base,
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
                    stream.mark_unsent(seg.seq).await;
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

/// C1: decide whether a rekey is needed before stamping a packet for
/// `(stream_id, sequence)` and, if so, perform it. A rekey fires when either the
/// direction-wide AEAD high-watermark ([`Session::send_needs_rekey`]) or this
/// stream's sequence watermark ([`Session::stream_seq_needs_rekey`]) is crossed
/// — the latter prevents a per-stream `u32` sequence from wrapping within one
/// epoch and reusing the AEAD nonce `(epoch, stream_id, sequence, path_id)`
/// under a fixed key (Invariant 8).
///
/// Returns the extra flag bits to OR into the header (`PacketFlags::REKEY` on a
/// successful rotation, `0` when no rekey was needed), or `None` if a rekey was
/// required but failed (epoch saturated at `u8::MAX`) — the caller MUST fail the
/// send so the session reconnects rather than reusing a nonce.
fn rekey_before_stamp(
    crypto_session: &Arc<Session>,
    stream_id: TransportStreamId,
    sequence: u32,
) -> Option<u16> {
    if crypto_session.send_needs_rekey()
        || crypto_session.stream_seq_needs_rekey(stream_id, sequence)
    {
        match crypto_session.rekey() {
            Ok(_) => Some(PacketFlags::REKEY),
            Err(e) => {
                log::error!("PhantomSession: mid-session rekey failed: {}", e);
                None
            }
        }
    } else {
        Some(0)
    }
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
    sequence: u32,
    payload: &[u8],
    base_flags: u16,
) -> bool {
    // Always OR in ENCRYPTED for application data.
    let mut flag_bits = base_flags | PacketFlags::ENCRYPTED;
    // Mid-session rekey (C1): rotate to a fresh key BEFORE stamping this header
    // when either the direction-wide AEAD high-watermark or this stream's
    // sequence watermark is crossed, so the header carries the new epoch (+ the
    // REKEY flag) and no per-stream sequence can wrap within an epoch and reuse a
    // nonce (Invariant 8). The peer follows on the authenticated epoch bump (it
    // trial-decrypts under the next key).
    match rekey_before_stamp(crypto_session, stream_id, sequence) {
        Some(extra) => flag_bits |= extra,
        // Epoch saturated (u8::MAX): can't rotate further. Surface as a failed
        // send so the caller re-offers; the session reconnects rather than wrap.
        None => return false,
    }
    let header = PacketHeader::new(session_id, stream_id, sequence, PacketFlags::new(flag_bits))
        .with_epoch(crypto_session.current_epoch());
    let ciphertext = match crypto_session.encrypt_packet(&header, payload) {
        Ok(c) => c,
        Err(e) => {
            log::error!("PhantomSession: encrypt_packet failed: {}", e);
            return false;
        }
    };
    let packet = PhantomPacket::new(header, ciphertext);
    let buf = packet.to_wire();
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
    sequence: u32,
    new_window: u32,
) -> bool {
    let mut flag_bits = PacketFlags::ENCRYPTED | PacketFlags::WINDOW_UPDATE;
    // WINDOW_UPDATE shares the per-stream sequence space with application data,
    // so it must obey the same C1 rekey discipline before stamping (Invariant 8).
    match rekey_before_stamp(crypto_session, stream_id, sequence) {
        Some(extra) => flag_bits |= extra,
        None => return false,
    }
    let header = PacketHeader::new(session_id, stream_id, sequence, PacketFlags::new(flag_bits))
        .with_epoch(crypto_session.current_epoch());
    let payload = new_window.to_be_bytes();
    let ciphertext = match crypto_session.encrypt_packet(&header, &payload) {
        Ok(c) => c,
        Err(e) => {
            log::error!("PhantomSession: WINDOW_UPDATE encrypt failed: {}", e);
            return false;
        }
    };
    let packet = PhantomPacket::new(header, ciphertext);
    let buf = packet.to_wire();
    if let Err(e) = transport.send_bytes(&buf).await {
        log::error!("PhantomSession: WINDOW_UPDATE send failed: {}", e);
        return false;
    }
    true
}

/// Emit a V2 PATH_VALIDATION packet on `path_id` carrying the given
/// 32-byte challenge or response payload. Encrypted under the current
/// session epoch.
async fn send_path_validation<T: SessionTransport>(
    transport: &Arc<T>,
    crypto_session: &Arc<Session>,
    session_id: SessionId,
    path_id: u8,
    sequence: u32,
    payload: [u8; crate::transport::path::PATH_CHALLENGE_LEN],
) -> bool {
    // Build the packet skeleton via the codec, then layer ENCRYPTED
    // and epoch on top before the actual encrypt.
    let mut packet = build_path_validation_packet(session_id, path_id, sequence, payload);
    let flag_bits = packet.header.flags.0 | PacketFlags::ENCRYPTED;
    packet.header.flags = PacketFlags::new(flag_bits);
    packet.header.epoch = crypto_session.current_epoch();
    let plaintext = std::mem::take(&mut packet.payload);
    let ciphertext = match crypto_session.encrypt_packet(&packet.header, &plaintext) {
        Ok(c) => c,
        Err(e) => {
            log::error!("PhantomSession: PATH_VALIDATION encrypt failed: {}", e);
            return false;
        }
    };
    packet.payload = ciphertext;
    let buf = packet.to_wire();
    if let Err(e) = transport.send_bytes(&buf).await {
        log::error!("PhantomSession: PATH_VALIDATION send failed: {}", e);
        return false;
    }
    true
}

/// Recv-side handler for a packet:
/// - session-id guard → drop any frame not stamped with the negotiated
///   session id before touching any state (H1).
/// - decrypt (REQUIRED on application data — a non-empty unencrypted
///   post-handshake packet is a downgrade indicator and is dropped).
/// - ACK (now `ENCRYPTED | ACK`, post-decrypt) → read the authenticated
///   4-byte acked sequence from the payload, feed BBR + route to the
///   stream / demux. Forged/plaintext ACKs cannot reach this path (H1).
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
    path_validation_seq: &mut u32,
    observability: &Observability,
    leg: LegType,
) {
    let stream_id: u32 = packet.header.stream_id.into();
    let path_id = packet.header.path_id;

    // Bind every inbound frame to the negotiated session (H1). A frame stamped
    // with a different session id is dropped before any state mutation, so
    // cross-session / off-path control injection (forged ACK/FIN) can never
    // reach the stream table, BBR, or the path registry. Application data also
    // binds session_id through the AEAD AAD; this guard extends the same
    // protection to the non-AEAD header inspection that follows.
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
        match crypto_recv.decrypt_packet_accepting_rekey(&packet.header, &packet.payload) {
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
    } else if !packet.payload.is_empty() {
        // Stripped-flag downgrade defense (Invariant 2): a non-empty unencrypted
        // post-handshake application packet is dropped.
        observability.record_unencrypted_dropped(leg);
        log::warn!(
            "PhantomSession: dropping unencrypted V2 post-handshake data packet (downgrade?)"
        );
        return;
    } else {
        Vec::new()
    };

    // Authenticated ACK (H1). ACKs are `ENCRYPTED | ACK` control frames whose
    // AEAD payload carries the acked data sequence as 4 big-endian bytes. We act
    // on the ACK only *after* AEAD verify, which authenticates the header
    // (including `session_id` and `ack_delay`) and the acked-seq payload — so a
    // forged or stripped-flag ACK (dropped above by the downgrade defense, or
    // failing this length check) can neither retire a pending segment, restore a
    // flow-control permit, poison BBR, nor close a stream.
    if packet.header.flags.contains(PacketFlags::ACK) {
        if plaintext.len() != 4 {
            log::warn!(
                "PhantomSession: ACK payload length {} (expected 4)",
                plaintext.len()
            );
            return;
        }
        let acked_seq =
            u32::from_be_bytes([plaintext[0], plaintext[1], plaintext[2], plaintext[3]]);
        if let Some(stream) = streams_recv.get(&stream_id) {
            if let Some((sent_at, bytes)) = stream.ack(acked_seq).await {
                feed_bbr_on_ack(crypto_recv, sent_at, bytes, packet.header.ack_delay as u64);
            }
        }
        // Best-effort, non-blocking: the demux/PhantomStream path is vestigial;
        // routing the ACK/close notification to it must never block the reader.
        demux_recv.route_ack(stream_id, acked_seq);
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
                let _ = crypto_recv.complete_path_validation(path_id, &payload_buf);
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
                let seq = *path_validation_seq;
                *path_validation_seq = path_validation_seq.wrapping_add(1);
                let _ = send_path_validation(
                    transport_for_path,
                    crypto_recv,
                    session_id,
                    path_id,
                    seq,
                    payload_buf,
                )
                .await;
                return;
            }
        }
    }

    // PATH-001 (Invariant 6): application data is delivered only on a Validated
    // path. Path 0 is pre-validated at session establishment; any other path_id
    // must complete a PATH_VALIDATION challenge/response first. The control
    // frames (ACK / WINDOW_UPDATE / PATH_VALIDATION) were handled above and
    // returned; this gates the app-data delivery branches below. It runs AFTER
    // AEAD verify, so it never acts on an attacker-chosen plaintext path_id that
    // fails decryption.
    if !matches!(
        crypto_recv.path_state(path_id),
        Some(crate::transport::path::PathStateKind::Validated)
    ) {
        // Track a first-seen path id so a future challenge/response can promote
        // it; drop the data until then.
        crypto_recv.register_unvalidated_path(path_id);
        log::warn!(
            "PhantomSession: dropping application data on non-validated path_id {}",
            path_id
        );
        return;
    }

    // COALESCED dispatch (Phase 2.5): split the decrypted bundle into
    // sub-payloads and hand each, IN ORDER, to the single FIFO delivery task.
    // The delivery task drains them in this order, so the bundle's internal
    // ordering (and its order relative to later frames) is preserved —
    // the reader never blocks on application delivery.
    if packet.header.flags.contains(PacketFlags::COALESCED) {
        let inner_for_codec = PhantomPacket {
            header: packet.header,
            payload: plaintext,
            extensions: Vec::new(),
        };
        match unwrap_coalesced_packet(&inner_for_codec) {
            Ok(Some(subs)) => {
                for sub in subs {
                    if sub.is_empty() {
                        continue;
                    }
                    // Count toward the backlog only once the item is actually
                    // enqueued. If the delivery task has exited (consumer gone,
                    // `deliver_rx` dropped) the send fails and we must not inflate
                    // `undelivered_bytes` for data that was discarded.
                    let len = sub.len() as u64;
                    if deliver_tx.send((stream_id, Bytes::from(sub))).is_ok() {
                        undelivered_bytes.fetch_add(len, Ordering::AcqRel);
                    }
                }
            }
            Ok(None) => {
                log::warn!("PhantomSession: COALESCED flag set but bundle didn't parse");
            }
            Err(e) => {
                log::warn!("PhantomSession: COALESCED parse error: {}", e);
            }
        }
        // Bundles do not auto-ACK at the outer level — sub-packets are not
        // independently sequenced and the outer sequence has already been
        // consumed by the replay window.
        return;
    }

    // Reliable application data → emit an authenticated ACK **inline in the
    // reader** (H1). The ACK is an `ENCRYPTED | ACK` control frame whose AEAD
    // payload carries the acked data sequence (4 big-endian bytes); the peer
    // acts on it only after AEAD verify, so it cannot be forged off-path. The
    // ACK's own `header.sequence` is drawn from this side's per-stream send
    // counter — shared with our data/window-update sends on the same stream — so
    // `(epoch, stream_id, sequence, path_id)` is unique and never collides with
    // our outbound data (the nonce-reuse trap). It obeys the C1 rekey discipline
    // and stays prompt even when the app consumer is slow (encrypt is a lock-free
    // ArcSwap load). "ACK" means "received, decrypted, replay-passed, accepted."
    if packet.header.flags.contains(PacketFlags::RELIABLE) {
        let local = streams_recv
            .entry(stream_id)
            .or_insert_with(|| Arc::new(Stream::new(stream_id as TransportStreamId)))
            .clone();
        let ack_seq = local.next_send_sequence();
        let mut ack_flag_bits = PacketFlags::ENCRYPTED | PacketFlags::ACK;
        match rekey_before_stamp(crypto_recv, stream_id as TransportStreamId, ack_seq) {
            Some(extra) => ack_flag_bits |= extra,
            // Epoch saturated — drop this ACK rather than reuse a nonce; the
            // sender retransmits and the session is expected to reconnect.
            None => return,
        }
        let ack_header = PacketHeader::new(
            session_id,
            stream_id as TransportStreamId,
            ack_seq,
            PacketFlags::new(ack_flag_bits),
        )
        .with_epoch(crypto_recv.current_epoch())
        .with_path_id(path_id);
        let ack_payload = packet.header.sequence.to_be_bytes();
        match crypto_recv.encrypt_packet(&ack_header, &ack_payload) {
            Ok(ct) => {
                let ack_packet = PhantomPacket::new(ack_header, ct);
                ack_buf.clear();
                ack_buf.extend_from_slice(&ack_packet.to_wire());
                let size = ack_buf.len();
                let _ = transport_send_ack.send_bytes(&ack_buf[..size]).await;
            }
            Err(e) => log::error!("PhantomSession: ACK encrypt failed: {}", e),
        }
    }

    // Hand the decrypted application data to the delivery task: unbounded +
    // non-blocking, so the reader never stalls on a slow `recv()` consumer. The
    // delivery task drains the app-paced `recv_tx.send()` and credits the
    // flow-control window. `undelivered_bytes` is the backlog counter the
    // reader's HARD_CAP gate watches — counted only on a successful enqueue, so
    // a dead delivery task (consumer gone) can't inflate it for discarded data.
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
    /// Create a new session — returns instantly.
    ///
    /// Handshake is not started until a transport is provided.
    /// Use `connect_with_transport()` for full integration.
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

    /// H9 forward-compat (client side): when the server answers a `ClientHello`
    /// with a typed `ServerReject` (the version isn't one it speaks), the client
    /// surfaces a clear version-mismatch error instead of hanging or returning a
    /// generic failure — and crucially does NOT auto-downgrade.
    #[tokio::test]
    async fn client_surfaces_server_reject_as_version_error() {
        use crate::transport::handshake::ServerReject;

        let (client_transport, server_transport) = ChannelTransport::pair();
        // The reject path errors before any key verification, so any key works.
        let (_sk, expected_vk) = crate::crypto::hybrid_sign::HybridSigningKey::generate();

        let server = tokio::spawn(async move {
            // Consume the ClientHello, then reply with the typed reject.
            let _hello = server_transport.recv_bytes().await.unwrap();
            let reject = borsh::to_vec(&ServerReject::unsupported_version()).unwrap();
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
        let pkt = PhantomPacket::from_wire(bytes).expect("deserialize PhantomPacket");
        assert!(
            pkt.header.flags.contains(PacketFlags::ENCRYPTED),
            "expected ENCRYPTED flag on application data"
        );
        server_session
            .decrypt_packet(&pkt.header, &pkt.payload)
            .expect("decrypt application data")
    }

    /// Helper: build an encrypted reply frame from the test server side.
    fn encrypt_outgoing(
        server_session: &crate::transport::session::Session,
        session_id: SessionId,
        stream_id: TransportStreamId,
        sequence: u32,
        payload: &[u8],
    ) -> Vec<u8> {
        let flag_bits = PacketFlags::RELIABLE | PacketFlags::ENCRYPTED;
        let header =
            PacketHeader::new(session_id, stream_id, sequence, PacketFlags::new(flag_bits))
                .with_epoch(server_session.current_epoch());
        let ct = server_session
            .encrypt_packet(&header, payload)
            .expect("encrypt reply");
        let packet = PhantomPacket::new(header, ct);
        packet.to_wire()
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
                        let retry_bytes = borsh::to_vec(&retry).unwrap();
                        server_transport.send_bytes(&retry_bytes).await.unwrap();
                        // Receive retried client hello
                        let next_bytes = server_transport.recv_bytes().await.unwrap();
                        let next_hello = borsh::from_slice::<ClientHello>(&next_bytes).unwrap();
                        let resp2 = server_hs.process_client_hello(&next_hello, 0, client_ip);
                        match resp2 {
                            HandshakeResponse::Success(server_hello, session, _) => {
                                let server_hello_bytes = borsh::to_vec(&server_hello).unwrap();
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
                        let server_hello_bytes = borsh::to_vec(&server_hello).unwrap();
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

            // 5. Send encrypted reply back.
            let reply = encrypt_outgoing(&server_session, session_id, 1, 1, b"server-reply");
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
                        let retry_bytes = borsh::to_vec(&retry).unwrap();
                        server_transport.send_bytes(&retry_bytes).await.unwrap();
                        let next_bytes = server_transport.recv_bytes().await.unwrap();
                        let next_hello = borsh::from_slice::<ClientHello>(&next_bytes).unwrap();
                        match server_hs.process_client_hello(&next_hello, 0, client_ip) {
                            HandshakeResponse::Success(server_hello, session, _) => {
                                let b = borsh::to_vec(&server_hello).unwrap();
                                server_transport.send_bytes(&b).await.unwrap();
                                break session;
                            }
                            _ => panic!("expected success after retry"),
                        }
                    }
                    HandshakeResponse::Success(server_hello, session, _) => {
                        let b = borsh::to_vec(&server_hello).unwrap();
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
        stream.send_reliable(Bytes::from("payload")).await;
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
        stream.send_reliable(Bytes::from("new-data")).await;
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
    fn build_app_frame(
        client_session: &InnerSession,
        session_id: SessionId,
        stream_id: TransportStreamId,
        sequence: u32,
        payload: &[u8],
    ) -> Vec<u8> {
        let flag_bits = PacketFlags::RELIABLE | PacketFlags::ENCRYPTED;
        let header =
            PacketHeader::new(session_id, stream_id, sequence, PacketFlags::new(flag_bits))
                .with_epoch(client_session.current_epoch());
        let ciphertext = client_session
            .encrypt_packet(&header, payload)
            .expect("encrypt_packet");
        let packet = PhantomPacket::new(header, ciphertext);
        packet.to_wire()
    }

    #[tokio::test]
    async fn v2_recv_routes_encrypted_app_data_through_recv_channel() {
        let session_id = fixed_session_id();
        let (client_session, server_session) = paired_sessions(session_id);

        // Encrypt a V2 application-data packet on the client side.
        let stream_id: TransportStreamId = 1;
        let frame = build_app_frame(&client_session, session_id, stream_id, 0, b"hello-v2");

        // Receive on the server side: deserialize then drive
        // handle_packet, which is the recv-path entry point.
        let v2 = PhantomPacket::from_wire(&frame).unwrap();

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
        let mut path_validation_seq: u32 = 0;
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
            &mut path_validation_seq,
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

    /// Like [`build_app_frame`] but stamps a caller-chosen `path_id` so the
    /// receive-side path gate (PATH-001) can be exercised.
    fn build_app_frame_on_path(
        client_session: &InnerSession,
        session_id: SessionId,
        stream_id: TransportStreamId,
        sequence: u32,
        path_id: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let flag_bits = PacketFlags::RELIABLE | PacketFlags::ENCRYPTED;
        let header =
            PacketHeader::new(session_id, stream_id, sequence, PacketFlags::new(flag_bits))
                .with_epoch(client_session.current_epoch())
                .with_path_id(path_id);
        let ciphertext = client_session
            .encrypt_packet(&header, payload)
            .expect("encrypt_packet");
        PhantomPacket::new(header, ciphertext).to_wire()
    }

    #[tokio::test]
    async fn app_data_on_non_validated_path_is_dropped() {
        // PATH-001 (Invariant 6): application data is delivered only on a
        // Validated path. Path 0 is pre-validated; any other path_id must
        // complete a PATH_VALIDATION challenge first. A frame on an unvalidated
        // path is dropped (even though it decrypts cleanly) and the path is
        // registered Unvalidated so a later challenge can promote it.
        use crate::transport::path::PathStateKind;
        let session_id = fixed_session_id();
        let (client_session, server_session) = paired_sessions(session_id);
        let stream_id: TransportStreamId = 1;

        let bad = build_app_frame_on_path(
            &client_session,
            session_id,
            stream_id,
            0,
            7, // never validated on the receiver
            b"on-bad-path",
        );
        let bad = PhantomPacket::from_wire(&bad).unwrap();

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
        let mut path_validation_seq: u32 = 0;
        let obs = Observability::new(ObservabilityConfig::default());

        handle_packet(
            bad,
            session_id,
            &server_session,
            &streams,
            &demux,
            &transport_send,
            &transport_send,
            &deliver_tx,
            &undelivered,
            &mut ack_buf,
            &mut path_validation_seq,
            &obs,
            LegType::Tcp,
        )
        .await;

        assert!(
            deliver_rx.try_recv().is_err(),
            "application data on a non-validated path must be dropped"
        );
        assert_eq!(
            undelivered.load(Ordering::Acquire),
            0,
            "dropped data must not count toward the backlog"
        );
        assert_eq!(
            server_session.path_state(7),
            Some(PathStateKind::Unvalidated),
            "the unseen path id must be registered for a later challenge"
        );

        // Positive control: the SAME stream on the pre-validated path 0 IS
        // delivered, proving the gate only blocks non-validated paths.
        let good = build_app_frame_on_path(
            &client_session,
            session_id,
            stream_id,
            1,
            0,
            b"on-good-path",
        );
        let good = PhantomPacket::from_wire(&good).unwrap();
        handle_packet(
            good,
            session_id,
            &server_session,
            &streams,
            &demux,
            &transport_send,
            &transport_send,
            &deliver_tx,
            &undelivered,
            &mut ack_buf,
            &mut path_validation_seq,
            &obs,
            LegType::Tcp,
        )
        .await;
        let (sid, received) = deliver_rx.recv().await.expect("path-0 delivery");
        assert_eq!(sid, stream_id as u32);
        assert_eq!(&received[..], b"on-good-path");
    }

    /// Build an `ENCRYPTED | ACK` frame (H1) from `acker_session` acknowledging
    /// `acked_seq` on `stream_id`, with its own header sequence `ack_header_seq`
    /// (drawn from the acker's send space, distinct from the acked data
    /// sequence). Wire-serialised, ready for `handle_packet`.
    fn build_encrypted_ack(
        acker_session: &InnerSession,
        session_id: SessionId,
        stream_id: TransportStreamId,
        ack_header_seq: u32,
        acked_seq: u32,
    ) -> Vec<u8> {
        let flag_bits = PacketFlags::ENCRYPTED | PacketFlags::ACK;
        let header = PacketHeader::new(
            session_id,
            stream_id,
            ack_header_seq,
            PacketFlags::new(flag_bits),
        )
        .with_epoch(acker_session.current_epoch());
        let ct = acker_session
            .encrypt_packet(&header, &acked_seq.to_be_bytes())
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
        let mut path_validation_seq: u32 = 0;
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
            &mut path_validation_seq,
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
            .await;
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
                    seq,
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
        let ack_pkt = PhantomPacket::from_wire(&frame).expect("parse ack");
        run_recv(ack_pkt, session_id, &server_session, &streams).await;

        assert!(
            stream.ack(seq).await.is_none(),
            "an authenticated ACK must retire the acked pending segment"
        );
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
                PacketHeader::new(wrong_id, stream_id, seq, PacketFlags::new(PacketFlags::ACK)),
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
        let mut path_validation_seq: u32 = 0;
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
            &mut path_validation_seq,
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
            .encrypt_packet(&header, &bundle)
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
        let mut path_validation_seq: u32 = 0;
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
            &mut path_validation_seq,
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

    /// Ordering across a COALESCED bundle followed by a normal frame: the single
    /// FIFO delivery channel must hand the bundle's `[A, B, C]` AND the later
    /// `D` to the consumer in exactly `A, B, C, D` — decoupling delivery from
    /// the reader must not reorder application bytes.
    #[tokio::test]
    async fn delivery_preserves_order_across_coalesced_then_normal_frame() {
        use crate::transport::packet_coalescer::{CoalescerConfig, PacketCoalescer};

        let session_id = fixed_session_id();
        let (client_session, server_session) = paired_sessions(session_id);
        let stream_id: TransportStreamId = 1;

        // Frame 1: COALESCED [A, B, C] at sequence 0.
        let mut coalescer = PacketCoalescer::new(CoalescerConfig::default());
        coalescer.push(b"A");
        coalescer.push(b"B");
        coalescer.push(b"C");
        let bundle = coalescer.flush().expect("bundle");
        let flag_bits = PacketFlags::ENCRYPTED | PacketFlags::COALESCED;
        let h1 = PacketHeader::new(session_id, stream_id, 0, PacketFlags::new(flag_bits))
            .with_epoch(client_session.current_epoch());
        let ct1 = client_session
            .encrypt_packet(&h1, &bundle)
            .expect("encrypt bundle");
        let coalesced = PhantomPacket::new(h1, ct1);

        // Frame 2: a normal RELIABLE "D" at sequence 1.
        let d_wire = build_app_frame(&client_session, session_id, stream_id, 1, b"D");
        let normal = PhantomPacket::from_wire(&d_wire).unwrap();

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
        let mut pv_seq: u32 = 0;
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
                &mut pv_seq,
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
            let header = PacketHeader::new(session_id, 1, seq, PacketFlags::new(flag_bits))
                .with_epoch(client_inner.current_epoch());
            let ct = client_inner
                .encrypt_packet(&header, &payload)
                .expect("encrypt");
            // Bound the send so a torn-down (or wedged) transport can't hang the
            // test: a closed channel or a stalled reader both mean the flood is
            // no longer absorbed — i.e. the session is being torn down.
            let wire = PhantomPacket::new(header, ct).to_wire();
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
        let pv2 = PhantomPacket::from_wire(&frame).unwrap();
        assert!(pv2.header.flags.contains(PacketFlags::WINDOW_UPDATE));
        // The control frame's sequence comes from the stream's own send space —
        // distinct from any data packet so the AEAD nonce never repeats.
        let pt = client_session
            .decrypt_packet(&pv2.header, &pv2.payload)
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
        low.send_reliable(Bytes::from_static(b"L0")).await;
        low.send_reliable(Bytes::from_static(b"L1")).await;
        low.send_reliable(Bytes::from_static(b"L2")).await;
        streams.insert(11, low);

        // Stream 22: HIGH priority (100), 3 reliable chunks.
        let hi = Arc::new(TransportStream::new(22));
        hi.set_priority(100);
        hi.send_reliable(Bytes::from_static(b"H0")).await;
        hi.send_reliable(Bytes::from_static(b"H1")).await;
        hi.send_reliable(Bytes::from_static(b"H2")).await;
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
            let v2 = PhantomPacket::from_wire(&bytes).unwrap();
            // Decrypt under the SERVER role so the per-direction key
            // matches the client-side encrypt.
            let plaintext = _server_session
                .decrypt_packet(&v2.header, &v2.payload)
                .expect("decrypt");
            let tag: &'static str = match &plaintext[..] {
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
            .encrypt_packet(&header, &payload)
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
        let mut path_validation_seq: u32 = 100;
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
            &mut path_validation_seq,
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
        let echo_v2 = PhantomPacket::from_wire(&echo_bytes).unwrap();
        assert!(echo_v2.header.flags.contains(PacketFlags::PATH_VALIDATION));
        assert_eq!(echo_v2.header.path_id, path_id);

        // Sequence space advanced by exactly one (we sent one echo).
        assert_eq!(path_validation_seq, 101);
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
        s1.send_bytes(&borsh::to_vec(&retry).unwrap())
            .await
            .unwrap();
        let next = s1.recv_bytes().await.unwrap();
        let ch2 = borsh::from_slice::<ClientHello>(&next).unwrap();
        match server_hs.process_client_hello(&ch2, 0, client_ip) {
            HandshakeResponse::Success(sh, _session, _) => {
                s1.send_bytes(&borsh::to_vec(&sh).unwrap()).await.unwrap();
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
                s2.send_bytes(&borsh::to_vec(&sh).unwrap()).await.unwrap();
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
