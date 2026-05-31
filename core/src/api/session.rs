//! Client-First Transport Session
//!
//! `PhantomSession` provides instant connection establishment with
//! automatic send queuing during handshake. This is the transport-level
//! API that sits below MLS and above the raw UDP/TCP transport.

use crate::crypto::hybrid_sign::HybridVerifyingKey;
use crate::errors::CoreError;
use crate::runtime::{Runtime, TokioRuntime};
use crate::transport::handshake::{
    HandshakeClient, HelloRetryRequest, ServerHello, EARLY_DATA_MAX_LEN,
};
use crate::transport::multiplexer::StreamDemultiplexer;
use crate::transport::packet_coalescer_codec::unwrap_coalesced_packet;
use crate::transport::path_validation_codec::build_path_validation_packet;
use crate::transport::session::Session;
use crate::transport::stream::Stream;
use crate::transport::types::{
    PacketFlags, PacketHeader, PhantomPacket, SessionId, StreamId as TransportStreamId,
    WIRE_VERSION,
};
use bytes::Bytes;
use dashmap::DashMap;
use std::sync::atomic::{AtomicU32, AtomicU8, Ordering};
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
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ResumptionHint {
    /// The negotiated session id (32 bytes).
    pub session_id: Vec<u8>,
    /// The resumption secret (32 bytes) — sensitive; treat like a key.
    pub resumption_secret: Vec<u8>,
}

// ─── Transport Abstraction ──────────────────────────────────────────────────

// `SessionTransport` now lives in `crate::transport::session_transport` — a
// dependency-light module that can compile in a `no_std + alloc` build. It is
// re-exported here so `crate::api::session::SessionTransport` and the public
// `phantom_core::api::SessionTransport` path stay stable.
pub use crate::transport::session_transport::SessionTransport;

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
        )
    }

    /// Runtime-aware variant of [`from_accepted_server_session`].
    pub(crate) fn from_accepted_server_session_with_runtime<T: SessionTransport>(
        peer_addr: String,
        transport: T,
        server_session: Arc<Session>,
        runtime: Arc<dyn Runtime>,
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
        });

        let session_id = *server_session.id();
        let next_app_seq = Arc::new(AtomicU32::new(1));
        let runtime_for_pump = runtime.clone();
        let _detached = runtime.spawn(Box::pin(run_data_pump(
            server_session,
            session_id,
            Arc::new(transport),
            state,
            send_queue,
            cmd_rx,
            recv_tx,
            demux,
            streams,
            next_app_seq,
            runtime_for_pump,
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
    ) {
        log::info!("PhantomSession: starting handshake with {}", peer);

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

        // ── Stage 1 & 2: Hybrid Handshake (optionally 0-RTT resumption) ──
        let (crypto_session, ed_accepted) = match run_client_handshake(
            &transport,
            &expected_server_key,
            resumption_request,
        )
        .await
        {
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

        let session_id = *crypto_session.id();
        state.store(ConnectionState::Connected as u8, Ordering::Relaxed);
        log::info!("PhantomSession: fully connected to {}", peer);

        let next_app_seq = Arc::new(AtomicU32::new(1));
        run_data_pump(
            crypto_session,
            session_id,
            Arc::new(transport),
            state,
            send_queue,
            cmd_rx,
            recv_tx,
            demux,
            streams,
            next_app_seq,
            runtime,
        )
        .await;
    }
}

/// Drive the client side of the Phantom handshake to completion.
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

    loop {
        let bytes = borsh::to_vec(&hello).map_err(|e| {
            CoreError::SerializationError(format!("ClientHello encode failed: {}", e))
        })?;
        transport.send_bytes(&bytes).await?;
        let resp = transport.recv_bytes().await?;

        // The reply is either a `ServerHello` (success) or a
        // `HelloRetryRequest` (cookie/PoW demand). Try the success shape
        // first — a retry blob is far too small to deserialize as a
        // ServerHello, so the disambiguation is unambiguous.
        if let Ok(sh) = borsh::from_slice::<ServerHello>(&resp) {
            let (session, accepted) =
                handshake.process_server_hello(&hello, &sh, Some(expected_server_key))?;
            return Ok((session, accepted));
        } else if let Ok(retry) = borsh::from_slice::<HelloRetryRequest>(&resp) {
            log::info!("PhantomSession: Received HelloRetryRequest, retrying...");
            hello.cookie = retry.cookie;
            if let Some(challenge) = retry.challenge {
                log::info!("PhantomSession: Solving PoW challenge...");
                hello.pow_solution = Some(challenge.solve());
            }
            continue;
        } else {
            return Err(CoreError::HandshakeError(
                "invalid ServerHello or Retry received".into(),
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
    next_app_seq: Arc<AtomicU32>,
    runtime: Arc<dyn Runtime>,
) {
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

    // ── Receive task: deserialize, decrypt, route to streams / recv_tx ──
    let transport_recv = transport.clone();
    let transport_send_ack = transport.clone();
    let crypto_recv = crypto_session.clone();
    let demux_recv = demux.clone();
    let streams_recv = streams.clone();
    let recv_tx_for_task = recv_tx.clone();
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
        // Monotonic sequence space for outbound WINDOW_UPDATE control
        // packets emitted by the recv path (Phase 4.3).
        let mut window_update_seq: u32 = 0;
        loop {
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
                &recv_tx_for_task,
                &mut ack_buf,
                &mut path_validation_seq,
                &mut window_update_seq,
            )
            .await;
        }
        // Signal the main loop that the recv task has exited so it can
        // also unwind. `send` returns `Err(())` if the receiver was
        // already dropped — that case is harmless, the main loop has
        // already shut down.
        let _ = recv_done_tx.send(());
    }));

    drop(recv_tx); // drop the parent clone so the channel closes when recv_handle exits

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

    loop {
        tokio::select! {
            _ = poll_interval.tick() => {
                drain_streams_priority_ordered(
                    &transport,
                    &crypto_session,
                    session_id,
                    &streams,
                )
                .await;
            }
            _ = send_notify.notified() => {
                // Same drain logic as the tick arm — fast-wake path.
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
                            let seq = next_app_seq.fetch_add(1, Ordering::Relaxed);
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
                        break;
                    }
                    None => {
                        log::info!("PhantomSession: command channel dropped");
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
    let flag_bits = base_flags | PacketFlags::ENCRYPTED;
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
    pace_send(crypto_session, size as u64).await;
    if let Err(e) = transport.send_bytes(&buf[..size]).await {
        log::error!("PhantomSession: transport send failed (V2): {}", e);
        return false;
    }
    crypto_session.on_packet_sent(size as u64);
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
    let flag_bits = PacketFlags::ENCRYPTED | PacketFlags::WINDOW_UPDATE;
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
/// - ACK → feed BBR + route to the stream / demux.
/// - decrypt (REQUIRED on application data — a non-empty unencrypted
///   post-handshake packet is a downgrade indicator and is dropped).
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
    recv_tx: &mpsc::Sender<Bytes>,
    ack_buf: &mut Vec<u8>,
    path_validation_seq: &mut u32,
    window_update_seq: &mut u32,
) {
    let stream_id: u32 = packet.header.stream_id.into();
    let path_id = packet.header.path_id;

    // Mark path activity even before decrypt (the path id is plaintext
    // header bytes; this is just a liveness signal for the sweep).
    crypto_recv.mark_path_seen(path_id);

    if packet.header.flags.contains(PacketFlags::ACK) {
        if let Some(stream) = streams_recv.get(&stream_id) {
            if let Some((sent_at, bytes)) = stream.ack(packet.header.sequence).await {
                feed_bbr_on_ack(crypto_recv, sent_at, bytes, packet.header.ack_delay as u64);
            }
        }
        demux_recv
            .route_ack_async(stream_id, packet.header.sequence)
            .await;
        if packet.header.flags.contains(PacketFlags::FIN) {
            demux_recv.route_close_async(stream_id).await;
        }
        return;
    }

    // Decrypt if marked. V2 sessions REQUIRE ENCRYPTED on application
    // data — a non-empty unencrypted V2 application-data packet is a
    // downgrade indicator and is dropped (same posture as V1).
    let plaintext: Vec<u8> = if packet.header.flags.contains(PacketFlags::ENCRYPTED) {
        match crypto_recv.decrypt_packet(&packet.header, &packet.payload) {
            Ok(pt) => pt,
            Err(e) => {
                log::warn!("PhantomSession: V2 decrypt failed (dropping packet): {}", e);
                return;
            }
        }
    } else if !packet.payload.is_empty() {
        log::warn!(
            "PhantomSession: dropping unencrypted V2 post-handshake data packet (downgrade?)"
        );
        return;
    } else {
        Vec::new()
    };

    // WINDOW_UPDATE dispatch (Phase 4.3 flow control). Payload is a
    // big-endian u32 carrying the peer's new absolute send-window
    // for this stream_id.
    if packet.header.flags.contains(PacketFlags::WINDOW_UPDATE) {
        if plaintext.len() != 4 {
            log::warn!(
                "PhantomSession: WINDOW_UPDATE payload length {} (expected 4)",
                plaintext.len()
            );
            return;
        }
        let new_window =
            u32::from_be_bytes([plaintext[0], plaintext[1], plaintext[2], plaintext[3]]);
        if let Some(stream) = streams_recv.get(&stream_id) {
            stream.apply_peer_window_update(new_window);
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

    // COALESCED dispatch (Phase 2.5): split the decrypted bundle into
    // sub-payloads and route each one through the demux as an
    // application chunk on the outer header's stream_id.
    if packet.header.flags.contains(PacketFlags::COALESCED) {
        // Reconstruct a temporary V2 packet whose payload IS the
        // decrypted bundle so the codec can parse it.
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
                    let bytes = Bytes::from(sub);
                    demux_recv.route_data_async(stream_id, bytes.clone()).await;
                    let _ = recv_tx.send(bytes).await;
                }
            }
            Ok(None) => {
                // COALESCED flag was set but the codec disagreed —
                // treat as a malformed bundle. Drop.
                log::warn!("PhantomSession: COALESCED flag set but bundle didn't parse");
            }
            Err(e) => {
                log::warn!("PhantomSession: COALESCED parse error: {}", e);
            }
        }
        // Bundles do not auto-ACK at the outer level — sub-packets
        // are not independently sequenced and the outer sequence has
        // already been consumed by the replay window.
        return;
    }

    // Reliable application data → emit an ACK.
    if packet.header.flags.contains(PacketFlags::RELIABLE) {
        let ack_flag_bits = PacketFlags::ACK;
        let ack_header = PacketHeader::new(
            session_id,
            stream_id as TransportStreamId,
            packet.header.sequence,
            PacketFlags::new(ack_flag_bits),
        )
        .with_epoch(crypto_recv.current_epoch())
        .with_path_id(path_id);
        let ack_packet = PhantomPacket::new(ack_header, Vec::new());
        ack_buf.clear();
        ack_buf.extend_from_slice(&ack_packet.to_wire());
        let size = ack_buf.len();
        let _ = transport_send_ack.send_bytes(&ack_buf[..size]).await;
    }

    // Track bytes received for the stream's flow-control accounting
    // (Phase 4.3). The pump treats "received and routed to the recv
    // channel" as consumed — slow consumers experience some over-
    // budget queueing on the FFI receive channel, but the wire-level
    // window stays in lockstep with the pump's view.
    let consumed_bytes = plaintext.len() as u32;
    let window_update_to_emit = if consumed_bytes > 0 {
        if let Some(stream) = streams_recv.get(&stream_id) {
            stream.record_app_consumed(consumed_bytes)
        } else {
            None
        }
    } else {
        None
    };

    if !plaintext_into_router(plaintext, stream_id, demux_recv, recv_tx).await {
        return;
    }

    if let Some(new_window) = window_update_to_emit {
        let seq = *window_update_seq;
        *window_update_seq = window_update_seq.wrapping_add(1);
        let _ = send_window_update(
            transport_send_ack,
            crypto_recv,
            session_id,
            stream_id as TransportStreamId,
            seq,
            new_window,
        )
        .await;
    }

    if packet.header.flags.contains(PacketFlags::FIN) {
        demux_recv.route_close_async(stream_id).await;
    }
}

/// Fan a single plaintext into the demux + session-recv channel. Returns
/// `false` only when the channel is closed (so the caller can decide to
/// break out of its loop).
async fn plaintext_into_router(
    plaintext: Vec<u8>,
    stream_id: u32,
    demux: &Arc<StreamDemultiplexer>,
    recv_tx: &mpsc::Sender<Bytes>,
) -> bool {
    if plaintext.is_empty() {
        return true;
    }
    let bytes = Bytes::from(plaintext);
    demux.route_data_async(stream_id, bytes.clone()).await;
    recv_tx.send(bytes).await.is_ok()
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
        let (recv_tx, mut recv_rx) = mpsc::channel::<Bytes>(4);
        let (ack_a, ack_b) = mpsc::channel::<Vec<u8>>(4);
        let transport_send: Arc<ChannelTransport> = Arc::new(ChannelTransport {
            tx: ack_a,
            rx: Mutex::new(ack_b),
        });

        let mut ack_buf = Vec::with_capacity(256);
        let mut path_validation_seq: u32 = 0;
        let mut window_update_seq: u32 = 0;
        handle_packet(
            v2,
            session_id,
            &server_session,
            &streams,
            &demux,
            &transport_send,
            &transport_send,
            &recv_tx,
            &mut ack_buf,
            &mut path_validation_seq,
            &mut window_update_seq,
        )
        .await;

        // The decrypted plaintext must have been routed through the
        // session-recv channel.
        let received = recv_rx.recv().await.expect("recv on session channel");
        assert_eq!(&received[..], b"hello-v2");
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
        let (recv_tx, mut recv_rx) = mpsc::channel::<Bytes>(4);
        let (ack_a, ack_b) = mpsc::channel::<Vec<u8>>(4);
        let transport_send: Arc<ChannelTransport> = Arc::new(ChannelTransport {
            tx: ack_a,
            rx: Mutex::new(ack_b),
        });

        let mut ack_buf = Vec::with_capacity(256);
        let mut path_validation_seq: u32 = 0;
        let mut window_update_seq: u32 = 0;
        handle_packet(
            bad_packet,
            session_id,
            &server_session,
            &streams,
            &demux,
            &transport_send,
            &transport_send,
            &recv_tx,
            &mut ack_buf,
            &mut path_validation_seq,
            &mut window_update_seq,
        )
        .await;

        // Nothing should have made it through the recv channel.
        let try_recv =
            tokio::time::timeout(std::time::Duration::from_millis(50), recv_rx.recv()).await;
        assert!(
            try_recv.is_err(),
            "unencrypted post-handshake payload must NOT be routed"
        );
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
        let (recv_tx, mut recv_rx) = mpsc::channel::<Bytes>(4);
        let (ack_a, ack_b) = mpsc::channel::<Vec<u8>>(4);
        let transport_send: Arc<ChannelTransport> = Arc::new(ChannelTransport {
            tx: ack_a,
            rx: Mutex::new(ack_b),
        });

        let mut ack_buf = Vec::with_capacity(256);
        let mut path_validation_seq: u32 = 0;
        let mut window_update_seq: u32 = 0;
        handle_packet(
            v2,
            session_id,
            &server_session,
            &streams,
            &demux,
            &transport_send,
            &transport_send,
            &recv_tx,
            &mut ack_buf,
            &mut path_validation_seq,
            &mut window_update_seq,
        )
        .await;

        let a = recv_rx.recv().await.expect("alpha");
        let b = recv_rx.recv().await.expect("bravo");
        let c = recv_rx.recv().await.expect("charlie");
        assert_eq!(&a[..], b"alpha");
        assert_eq!(&b[..], b"bravo");
        assert_eq!(&c[..], b"charlie");
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

    /// Phase 4.3 — WINDOW_UPDATE round-trip. After the receive side
    /// has crossed the half-window threshold, it emits a V2
    /// WINDOW_UPDATE packet announcing its absolute window. The
    /// sender-side `Stream::apply_peer_window_update` lifts its
    /// `peer_send_window` to that value.
    #[tokio::test]
    async fn flow_control_window_update_round_trip() {
        use crate::transport::stream::INITIAL_STREAM_WINDOW;

        let session_id = fixed_session_id();
        let (client_session, server_session) = paired_sessions(session_id);

        // Register a stream on the server side so handle_packet
        // can record the bytes-consumed accounting. The stream id
        // matches the packet header.
        let stream_id: TransportStreamId = 9;
        let server_streams: Arc<DashMap<u32, Arc<TransportStream>>> = Arc::new(DashMap::new());
        server_streams.insert(stream_id as u32, Arc::new(TransportStream::new(stream_id)));

        // Client also has a Stream so we can apply the inbound update.
        let client_stream = Arc::new(TransportStream::new(stream_id));
        let client_streams: Arc<DashMap<u32, Arc<TransportStream>>> = Arc::new(DashMap::new());
        client_streams.insert(stream_id as u32, client_stream.clone());

        // Pre-drain client's peer_send_window so the WINDOW_UPDATE
        // has a real effect to assert against.
        let drain = INITIAL_STREAM_WINDOW - 1000;
        assert!(client_stream.try_consume_send_window(drain));
        assert_eq!(client_stream.peer_send_window(), 1000);

        // Build a single large app-data packet that crosses the
        // server's half-window threshold in one shot.
        let big = vec![0u8; (INITIAL_STREAM_WINDOW / 2 + 1) as usize];
        let frame = build_app_frame(&client_session, session_id, stream_id, 0, &big);

        // Server processes the packet via handle_packet. We
        // capture its outbound transport so we can intercept the
        // WINDOW_UPDATE it emits.
        let v2 = PhantomPacket::from_wire(&frame).unwrap();

        let (demux, _ctrl) = StreamDemultiplexer::new(16);
        let demux = Arc::new(demux);
        let (recv_tx, mut _recv_rx) = mpsc::channel::<Bytes>(4);
        let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(4);
        let (back_tx, back_rx) = mpsc::channel::<Vec<u8>>(4);
        let server_outbound: Arc<ChannelTransport> = Arc::new(ChannelTransport {
            tx: out_tx,
            rx: Mutex::new(back_rx),
        });
        let _keep = back_tx;

        let mut ack_buf = Vec::with_capacity(256);
        let mut path_validation_seq: u32 = 0;
        let mut window_update_seq: u32 = 0;
        handle_packet(
            v2,
            session_id,
            &server_session,
            &server_streams,
            &demux,
            &server_outbound,
            &server_outbound,
            &recv_tx,
            &mut ack_buf,
            &mut path_validation_seq,
            &mut window_update_seq,
        )
        .await;

        // The server's recv path should have crossed the threshold
        // and emitted exactly one WINDOW_UPDATE. (There will be an
        // ACK first because the inbound was RELIABLE.) Pull frames
        // until we find the WINDOW_UPDATE.
        let mut announced: Option<u32> = None;
        for _ in 0..3 {
            let frame = tokio::time::timeout(std::time::Duration::from_millis(100), out_rx.recv())
                .await
                .expect("expected an outbound frame")
                .expect("channel open");
            let pv2 = PhantomPacket::from_wire(&frame).unwrap();
            if pv2.header.flags.contains(PacketFlags::WINDOW_UPDATE) {
                // Decrypt the payload to read the new window.
                let pt = client_session
                    .decrypt_packet(&pv2.header, &pv2.payload)
                    .expect("decrypt WINDOW_UPDATE");
                assert_eq!(pt.len(), 4);
                announced = Some(u32::from_be_bytes([pt[0], pt[1], pt[2], pt[3]]));
                break;
            }
        }
        let announced = announced.expect("WINDOW_UPDATE must have been emitted");

        // Apply the update on the client side; peer_send_window
        // jumps to the announced value (it's larger than the
        // current 1000).
        client_stream.apply_peer_window_update(announced);
        assert_eq!(client_stream.peer_send_window(), announced);
        // Sanity: announced window is the receiver-side replenished
        // total — at least the initial window's size.
        assert!(announced >= INITIAL_STREAM_WINDOW);
        // Exactly one WINDOW_UPDATE was emitted.
        assert_eq!(window_update_seq, 1);
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
        let (recv_tx, _recv_rx) = mpsc::channel::<Bytes>(4);
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
        let mut window_update_seq: u32 = 0;

        handle_packet(
            v2,
            session_id,
            &server_session,
            &streams,
            &demux,
            &transport_send,
            &transport_send,
            &recv_tx,
            &mut ack_buf,
            &mut path_validation_seq,
            &mut window_update_seq,
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
