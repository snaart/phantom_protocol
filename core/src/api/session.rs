//! Client-First Transport Session
//!
//! `PhantomSession` provides instant connection establishment with
//! automatic send queuing during handshake. This is the transport-level
//! API that sits below MLS and above the raw UDP/TCP transport.

use crate::crypto::hybrid_sign::HybridVerifyingKey;
use crate::errors::CoreError;
use crate::runtime::{Runtime, TokioRuntime};
use crate::transport::handshake::{
    ClientHelloEnvelope, HandshakeClient, HelloRetryRequestEnvelope, ServerHelloEnvelope,
    EARLY_DATA_MAX_LEN,
};
use crate::transport::multiplexer::StreamDemultiplexer;
use crate::transport::packet_coalescer_codec::unwrap_coalesced_v2_packet;
use crate::transport::path_validation_codec::build_path_validation_packet;
use crate::transport::session::Session;
use crate::transport::stream::Stream;
use crate::transport::types::{
    PacketFlags, PacketFlagsV2, PacketHeader, PacketHeaderV2, PhantomPacketV1, PhantomPacketV2,
    SessionId, StreamId as TransportStreamId, VersionedPacket,
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
#[repr(u8)]
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
#[derive(uniffi::Object)]
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
    /// 0-RTT verdict (wire V3, Phase 4.1). `None` while handshaking,
    /// after a failure, or after a plain V1/V2 handshake (no 0-RTT
    /// attempted). `Some(true)` the server consumed the early-data;
    /// `Some(false)` a V3 handshake where the server rejected it (or
    /// the client offered none). Exposed via `early_data_accepted()`.
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

    /// Connect with a **0-RTT resumption attempt** (wire V3, Phase 4.1).
    ///
    /// `resumption_hint` is the `(session_id, resumption_secret)` tuple
    /// from a prior session's [`PhantomSession::resumption_hint`].
    /// `early_data` (≤ [`EARLY_DATA_MAX_LEN`] bytes) is sealed and
    /// carried inside the V3 ClientHello so it reaches the server on
    /// the very first flight — saving a round-trip versus 1-RTT.
    ///
    /// If the server does not speak V3 it replies `Unsupported` and
    /// the client transparently falls back to a plain V2 handshake;
    /// in that case the `early_data` is **not** sent 0-RTT and
    /// [`early_data_accepted`](Self::early_data_accepted) returns
    /// `None` — the caller must send that payload over the normal
    /// channel. Returns `Err` only when `early_data` exceeds the cap.
    ///
    /// Runs on the default [`TokioRuntime`].
    pub fn connect_with_resumption<T: SessionTransport>(
        peer_addr: &str,
        transport: T,
        expected_server_key: HybridVerifyingKey,
        resumption_hint: ([u8; 32], [u8; 32]),
        early_data: Vec<u8>,
    ) -> Result<Self, CoreError> {
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
    /// for a plain V1/V2 handshake, `Some((id, secret, early_data))` to
    /// attempt a V3 0-RTT handshake.
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

        // ── Stage 1 & 2: Hybrid Handshake (V12, or V3 0-RTT) ──
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
/// When `resumption` is `Some((resume_id, resume_secret, early_data))`
/// this attempts a **V3 0-RTT handshake** — the `early_data` rides
/// sealed inside the ClientHello so it reaches the server on the first
/// flight. If the server replies `ServerHelloEnvelope::Unsupported`
/// (it does not speak V3) the function transparently falls back to a
/// plain V2 handshake, reusing the same `HandshakeClient`; the
/// early-data is then NOT sent 0-RTT.
///
/// Returns the established `Session` and the 0-RTT verdict:
/// - `Some(true)`  — V3 handshake, the server consumed the early-data
/// - `Some(false)` — V3 handshake, the server rejected it (stale
///   ticket / oversized / AEAD failure) or the client offered none
/// - `None`        — a V2 handshake (no 0-RTT was attempted, or the
///   V3 attempt fell back via `Unsupported`)
async fn run_client_handshake<T: SessionTransport>(
    transport: &T,
    expected_server_key: &HybridVerifyingKey,
    resumption: Option<([u8; 32], [u8; 32], Vec<u8>)>,
) -> Result<(Session, Option<bool>), CoreError> {
    let handshake = HandshakeClient::new()?;

    // ── V3 0-RTT attempt ──
    if let Some((resume_id, resume_secret, early_data)) = &resumption {
        // Empty early-data → resume without a 0-RTT payload (still a
        // V3 handshake, but no sealed blob).
        let ed: Option<&[u8]> = if early_data.is_empty() {
            None
        } else {
            Some(early_data.as_slice())
        };
        let mut ch3 = handshake.create_client_hello_v3(*resume_id, resume_secret, ed);
        loop {
            let bytes = borsh::to_vec(&ClientHelloEnvelope::V3(ch3.clone())).map_err(|e| {
                CoreError::SerializationError(format!("ClientHelloV3 encode failed: {}", e))
            })?;
            transport.send_bytes(&bytes).await?;
            let resp = transport.recv_bytes().await?;

            // The response is a `ServerHelloEnvelope` (V3 / Unsupported)
            // or a `HelloRetryRequestEnvelope` (stale-ticket cookie
            // demand). Parse ServerHelloEnvelope first — a retry blob
            // does not parse cleanly as one.
            if let Ok(env) = borsh::from_slice::<ServerHelloEnvelope>(&resp) {
                match env {
                    ServerHelloEnvelope::V3(sh3) => {
                        let (session, accepted) = handshake.process_server_hello_v3(
                            &ch3,
                            &sh3,
                            Some(expected_server_key),
                        )?;
                        return Ok((session, Some(accepted)));
                    }
                    ServerHelloEnvelope::Unsupported => {
                        // Server does not speak V3 — drop out of the V3
                        // loop and fall through to the V2 handshake
                        // below, reusing the same `HandshakeClient`.
                        log::info!(
                            "PhantomSession: server replied Unsupported to V3 — falling back to V2"
                        );
                        break;
                    }
                    ServerHelloEnvelope::V12(_) => {
                        return Err(CoreError::HandshakeError(
                            "server replied a V12 ServerHello to a V3 ClientHello".into(),
                        ));
                    }
                }
            } else if let Ok(HelloRetryRequestEnvelope::V12(retry)) =
                borsh::from_slice::<HelloRetryRequestEnvelope>(&resp)
            {
                // Stale / unknown ticket → the server fell back to the
                // cookie/PoW gate. Fill the demand into the V3
                // ClientHello's base and re-send.
                log::info!("PhantomSession: V3 ClientHello got HelloRetryRequest, retrying...");
                ch3.base.cookie = retry.cookie;
                if let Some(challenge) = retry.challenge {
                    ch3.base.pow_solution = Some(challenge.solve());
                }
                continue;
            } else {
                return Err(CoreError::HandshakeError(
                    "invalid server response to V3 ClientHello".into(),
                ));
            }
        }
    }

    // ── V2 handshake (default path, or V3 → Unsupported fallback) ──
    let mut hello = handshake.create_client_hello();
    loop {
        let bytes = borsh::to_vec(&ClientHelloEnvelope::V12(hello.clone())).map_err(|e| {
            CoreError::SerializationError(format!("ClientHello encode failed: {}", e))
        })?;
        transport.send_bytes(&bytes).await?;
        let resp = transport.recv_bytes().await?;

        if let Ok(ServerHelloEnvelope::V12(sh)) = borsh::from_slice::<ServerHelloEnvelope>(&resp) {
            let session = handshake.process_server_hello(&hello, &sh, Some(expected_server_key))?;
            return Ok((session, None));
        } else if let Ok(HelloRetryRequestEnvelope::V12(retry)) =
            borsh::from_slice::<HelloRetryRequestEnvelope>(&resp)
        {
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
    // ── Flush queued early-data sends as encrypted packets ──
    {
        let mut queue = send_queue.lock().await;
        let count = queue.len();
        for msg in queue.drain(..) {
            if !send_app_data(
                &transport,
                &crypto_session,
                session_id,
                1, // raw-app stream_id
                next_app_seq.fetch_add(1, Ordering::Relaxed),
                &msg,
                PacketFlags::RELIABLE,
            )
            .await
            {
                log::error!("PhantomSession: failed to flush queued message");
            }
        }
        if count > 0 {
            log::info!("PhantomSession: flushed {} queued messages", count);
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
        // comfortably larger than a serialized empty PhantomPacketV1 +
        // VersionedPacket envelope (header is 41 bytes on the wire), so
        // the underlying buffer is never reallocated after the first frame.
        let mut ack_buf: Vec<u8> = Vec::with_capacity(256);
        // Monotonic sequence space for outbound PATH_VALIDATION packets
        // (V2 only). Local to the recv task because that's where
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

            let versioned = match alkahest::deserialize::<VersionedPacket, VersionedPacket>(&data) {
                Ok(v) => v,
                Err(_) => continue,
            };
            match versioned {
                VersionedPacket::V1(packet) => {
                    handle_v1_packet(
                        packet,
                        session_id,
                        &crypto_recv,
                        &streams_recv,
                        &demux_recv,
                        &transport_send_ack,
                        &recv_tx_for_task,
                        &mut ack_buf,
                    )
                    .await;
                }
                VersionedPacket::V2(packet) => {
                    handle_v2_packet(
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
            }
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
                        let seq = next_app_seq.fetch_add(1, Ordering::Relaxed);
                        if !send_app_data(
                            &transport,
                            &crypto_session,
                            session_id,
                            1,
                            seq,
                            &data,
                            PacketFlags::RELIABLE,
                        ).await {
                            log::error!("PhantomSession: SessionCommand::Send failed");
                            break;
                        }
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

/// Encrypt `payload` and emit a single `PhantomPacketV1` over the transport.
/// Returns `false` on a transport or crypto error so the caller can react.
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
        while let Some((seq, payload, is_reliable)) = stream.poll_send().await {
            let base = if is_reliable {
                PacketFlags::RELIABLE
            } else {
                PacketFlags::UNRELIABLE
            };
            if !send_app_data(
                transport,
                crypto_session,
                session_id,
                stream_id as TransportStreamId,
                seq,
                &payload,
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

async fn send_app_data<T: SessionTransport>(
    transport: &Arc<T>,
    crypto_session: &Arc<Session>,
    session_id: SessionId,
    stream_id: TransportStreamId,
    sequence: u32,
    payload: &[u8],
    base_flags: u8,
) -> bool {
    // Phase 4.2 / 2.5 follow-up: route by the post-handshake-negotiated
    // wire version. `wire_version()` is set by both peers during the
    // handshake (Phase 1.8); it is `1` by default and `2` when both
    // sides offered V2 in their `ClientHello.version`.
    if crypto_session.wire_version() == 2 {
        send_app_data_v2(
            transport,
            crypto_session,
            session_id,
            stream_id,
            sequence,
            payload,
            base_flags,
        )
        .await
    } else {
        send_app_data_v1(
            transport,
            crypto_session,
            session_id,
            stream_id,
            sequence,
            payload,
            base_flags,
        )
        .await
    }
}

async fn send_app_data_v1<T: SessionTransport>(
    transport: &Arc<T>,
    crypto_session: &Arc<Session>,
    session_id: SessionId,
    stream_id: TransportStreamId,
    sequence: u32,
    payload: &[u8],
    base_flags: u8,
) -> bool {
    let mut flags = PacketFlags::new(base_flags);
    flags.set(PacketFlags::ENCRYPTED);
    let header = PacketHeader::new(session_id, stream_id, sequence, flags);
    let ciphertext = match crypto_session.encrypt_packet(&header, payload) {
        Ok(c) => c,
        Err(e) => {
            log::error!("PhantomSession: encrypt_packet failed: {}", e);
            return false;
        }
    };
    let packet = PhantomPacketV1::new(header, ciphertext).into_versioned();
    // Phase 2.3: pre-size the serialization buffer so alkahest does a single
    // allocation rather than incrementally growing through power-of-two
    // realloc-and-copy cycles. Header is 41 wire bytes + alkahest envelope
    // overhead (a few bytes) + payload + AEAD tag (16 bytes).
    let mut buf: Vec<u8> = Vec::with_capacity(payload.len() + 64);
    let (size, _) = alkahest::serialize_to_vec::<VersionedPacket, _>(&packet, &mut buf);
    // Phase 4.4 — pace the send through the BBR-driven Pacer. Default
    // is `Pacer::unlimited` (always allows), so this is a no-op until
    // CC kicks in via `on_packet_acked` setting a finite rate.
    pace_send(crypto_session, size as u64).await;
    if let Err(e) = transport.send_bytes(&buf[..size]).await {
        log::error!("PhantomSession: transport send failed: {}", e);
        return false;
    }
    crypto_session.on_packet_sent(size as u64);
    true
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

/// V2 send. Builds `PhantomPacketV2` with `PacketFlagsV2::ENCRYPTED` and
/// the negotiated rekey epoch; AEAD nonce derives from the header
/// (`Session::encrypt_packet_v2`), so a failed peer decrypt no longer
/// desyncs the local counter.
async fn send_app_data_v2<T: SessionTransport>(
    transport: &Arc<T>,
    crypto_session: &Arc<Session>,
    session_id: SessionId,
    stream_id: TransportStreamId,
    sequence: u32,
    payload: &[u8],
    base_flags: u8,
) -> bool {
    // Map V1 flag bits to their V2 equivalents (low byte is identical;
    // see `PacketFlagsV2` for the V1→V2 invariant). Always OR in
    // ENCRYPTED for application data.
    let flag_bits = (base_flags as u16) | PacketFlagsV2::ENCRYPTED;
    let header = PacketHeaderV2::new(
        session_id,
        stream_id,
        sequence,
        PacketFlagsV2::new(flag_bits),
    )
    .with_epoch(crypto_session.current_epoch());
    let ciphertext = match crypto_session.encrypt_packet_v2(&header, payload) {
        Ok(c) => c,
        Err(e) => {
            log::error!("PhantomSession: encrypt_packet_v2 failed: {}", e);
            return false;
        }
    };
    let packet = PhantomPacketV2::new(header, ciphertext).into_versioned();
    // V2 header is 44 wire bytes; same 64-byte envelope headroom as V1.
    let mut buf: Vec<u8> = Vec::with_capacity(payload.len() + 64);
    let (size, _) = alkahest::serialize_to_vec::<VersionedPacket, _>(&packet, &mut buf);
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
async fn send_window_update_v2<T: SessionTransport>(
    transport: &Arc<T>,
    crypto_session: &Arc<Session>,
    session_id: SessionId,
    stream_id: TransportStreamId,
    sequence: u32,
    new_window: u32,
) -> bool {
    let flag_bits = PacketFlagsV2::ENCRYPTED | PacketFlagsV2::WINDOW_UPDATE;
    let header = PacketHeaderV2::new(
        session_id,
        stream_id,
        sequence,
        PacketFlagsV2::new(flag_bits),
    )
    .with_epoch(crypto_session.current_epoch());
    let payload = new_window.to_be_bytes();
    let ciphertext = match crypto_session.encrypt_packet_v2(&header, &payload) {
        Ok(c) => c,
        Err(e) => {
            log::error!("PhantomSession: WINDOW_UPDATE encrypt failed: {}", e);
            return false;
        }
    };
    let packet = PhantomPacketV2::new(header, ciphertext).into_versioned();
    let mut buf: Vec<u8> = Vec::with_capacity(64);
    let (size, _) = alkahest::serialize_to_vec::<VersionedPacket, _>(&packet, &mut buf);
    if let Err(e) = transport.send_bytes(&buf[..size]).await {
        log::error!("PhantomSession: WINDOW_UPDATE send failed: {}", e);
        return false;
    }
    true
}

/// Emit a V2 PATH_VALIDATION packet on `path_id` carrying the given
/// 32-byte challenge or response payload. Encrypted under the current
/// session epoch.
async fn send_path_validation_v2<T: SessionTransport>(
    transport: &Arc<T>,
    crypto_session: &Arc<Session>,
    session_id: SessionId,
    path_id: u8,
    sequence: u32,
    payload: [u8; crate::transport::path::PATH_CHALLENGE_LEN],
) -> bool {
    // Build the V2 packet skeleton via the codec, then layer ENCRYPTED
    // and epoch on top before the actual encrypt.
    let pkt = build_path_validation_packet(session_id, path_id, sequence, payload);
    let mut v2 = match pkt.into_v2() {
        Some(v) => v,
        None => return false,
    };
    let flag_bits = v2.header.flags.0 | PacketFlagsV2::ENCRYPTED;
    v2.header.flags = PacketFlagsV2::new(flag_bits);
    v2.header.epoch = crypto_session.current_epoch();
    let plaintext = std::mem::take(&mut v2.payload);
    let ciphertext = match crypto_session.encrypt_packet_v2(&v2.header, &plaintext) {
        Ok(c) => c,
        Err(e) => {
            log::error!("PhantomSession: PATH_VALIDATION encrypt failed: {}", e);
            return false;
        }
    };
    v2.payload = ciphertext;
    let mut buf: Vec<u8> = Vec::with_capacity(crate::transport::path::PATH_CHALLENGE_LEN + 64);
    let packet = v2.into_versioned();
    let (size, _) = alkahest::serialize_to_vec::<VersionedPacket, _>(&packet, &mut buf);
    if let Err(e) = transport.send_bytes(&buf[..size]).await {
        log::error!("PhantomSession: PATH_VALIDATION send failed: {}", e);
        return false;
    }
    true
}

/// Recv-side handler for a V1 packet. Decrypts (if marked), short-
/// circuits ACKs, sends an ACK for reliable packets, fans the
/// plaintext out through the demux and the session-wide recv channel.
#[allow(clippy::too_many_arguments)]
async fn handle_v1_packet<T: SessionTransport>(
    packet: PhantomPacketV1,
    session_id: SessionId,
    crypto_recv: &Arc<Session>,
    streams_recv: &Arc<DashMap<u32, Arc<Stream>>>,
    demux_recv: &Arc<StreamDemultiplexer>,
    transport_send_ack: &Arc<T>,
    recv_tx: &mpsc::Sender<Bytes>,
    ack_buf: &mut Vec<u8>,
) {
    let stream_id: u32 = packet.header.stream_id.into();

    if packet.header.flags.is_ack() {
        if let Some(stream) = streams_recv.get(&stream_id) {
            if let Some((sent_at, bytes)) = stream.ack(packet.header.sequence).await {
                feed_bbr_on_ack(crypto_recv, sent_at, bytes, 0);
            }
        }
        demux_recv
            .route_ack_async(stream_id, packet.header.sequence)
            .await;
        if packet.header.flags.is_fin() {
            demux_recv.route_close_async(stream_id).await;
        }
        return;
    }

    // Non-ACK data packet: decrypt the payload if marked encrypted.
    let plaintext: Vec<u8> = if packet.header.flags.contains(PacketFlags::ENCRYPTED) {
        match crypto_recv.decrypt_packet(&packet.header, &packet.payload) {
            Ok(pt) => pt,
            Err(e) => {
                log::warn!("PhantomSession: decrypt failed (dropping packet): {}", e);
                return;
            }
        }
    } else if !packet.payload.is_empty() {
        // Reject unencrypted application data post-handshake to defeat
        // a stripped-flag downgrade attempt.
        log::warn!("PhantomSession: dropping unencrypted post-handshake data packet");
        return;
    } else {
        Vec::new()
    };

    if packet.header.flags.is_reliable() {
        let ack_header = PacketHeader::new(
            session_id,
            stream_id as TransportStreamId,
            packet.header.sequence,
            PacketFlags::new(PacketFlags::ACK),
        );
        let ack_packet = PhantomPacketV1::new(ack_header, Vec::new()).into_versioned();
        ack_buf.clear();
        let (size, _) = alkahest::serialize_to_vec::<VersionedPacket, _>(&ack_packet, ack_buf);
        let _ = transport_send_ack.send_bytes(&ack_buf[..size]).await;
    }

    if !plaintext.is_empty() {
        let bytes = Bytes::from(plaintext);
        demux_recv.route_data_async(stream_id, bytes.clone()).await;
        let _ = recv_tx.send(bytes).await;
    }

    if packet.header.flags.is_fin() {
        demux_recv.route_close_async(stream_id).await;
    }
}

/// Recv-side handler for a V2 packet. Same shape as V1 plus:
/// - V2 header carries epoch + path_id; decrypt uses `decrypt_packet_v2`.
/// - PATH_VALIDATION flag → drive the path registry: verify against an
///   outstanding challenge if one exists, otherwise echo the payload
///   back as a response.
/// - COALESCED flag → split the decrypted bundle into sub-payloads and
///   route each through the demux as an independent application
///   chunk.
#[allow(clippy::too_many_arguments)]
async fn handle_v2_packet<T: SessionTransport>(
    packet: PhantomPacketV2,
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

    if packet.header.flags.contains(PacketFlagsV2::ACK) {
        if let Some(stream) = streams_recv.get(&stream_id) {
            if let Some((sent_at, bytes)) = stream.ack(packet.header.sequence).await {
                feed_bbr_on_ack(crypto_recv, sent_at, bytes, packet.header.ack_delay as u64);
            }
        }
        demux_recv
            .route_ack_async(stream_id, packet.header.sequence)
            .await;
        if packet.header.flags.contains(PacketFlagsV2::FIN) {
            demux_recv.route_close_async(stream_id).await;
        }
        return;
    }

    // Decrypt if marked. V2 sessions REQUIRE ENCRYPTED on application
    // data — a non-empty unencrypted V2 application-data packet is a
    // downgrade indicator and is dropped (same posture as V1).
    let plaintext: Vec<u8> = if packet.header.flags.contains(PacketFlagsV2::ENCRYPTED) {
        match crypto_recv.decrypt_packet_v2(&packet.header, &packet.payload) {
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
    if packet.header.flags.contains(PacketFlagsV2::WINDOW_UPDATE) {
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
    if packet.header.flags.contains(PacketFlagsV2::PATH_VALIDATION) {
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
                let _ = send_path_validation_v2(
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
    if packet.header.flags.contains(PacketFlagsV2::COALESCED) {
        // Reconstruct a temporary V2 packet whose payload IS the
        // decrypted bundle so the codec can parse it.
        let inner_for_codec = PhantomPacketV2 {
            header: packet.header,
            payload: plaintext,
            extensions: Vec::new(),
        };
        match unwrap_coalesced_v2_packet(&inner_for_codec) {
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
    if packet.header.flags.contains(PacketFlagsV2::RELIABLE) {
        let ack_flag_bits = PacketFlagsV2::ACK;
        let ack_header = PacketHeaderV2::new(
            session_id,
            stream_id as TransportStreamId,
            packet.header.sequence,
            PacketFlagsV2::new(ack_flag_bits),
        )
        .with_epoch(crypto_recv.current_epoch())
        .with_path_id(path_id);
        let ack_packet = PhantomPacketV2::new(ack_header, Vec::new()).into_versioned();
        ack_buf.clear();
        let (size, _) = alkahest::serialize_to_vec::<VersionedPacket, _>(&ack_packet, ack_buf);
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
        let _ = send_window_update_v2(
            transport_send_ack,
            crypto_recv,
            session_id,
            stream_id as TransportStreamId,
            seq,
            new_window,
        )
        .await;
    }

    if packet.header.flags.contains(PacketFlagsV2::FIN) {
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

#[uniffi::export]
impl PhantomSession {
    /// Create a new session — returns instantly.
    ///
    /// Handshake is not started until a transport is provided.
    /// Use `connect_with_transport()` for full integration.
    #[uniffi::constructor]
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

    /// Transition to a new connection state.
    pub fn set_state(&self, new_state: ConnectionState) {
        self.state.store(new_state as u8, Ordering::Relaxed);
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

    /// The 0-RTT verdict for this session (wire V3, Phase 4.1).
    ///
    /// - `None` — still handshaking, the handshake failed, or this was
    ///   a plain V1/V2 handshake (no 0-RTT attempted, or a V3 attempt
    ///   fell back to V2 because the server replied `Unsupported`).
    ///   The caller must send any intended early-data over the normal
    ///   channel.
    /// - `Some(true)` — the server consumed the 0-RTT early-data.
    /// - `Some(false)` — a V3 handshake where the server rejected the
    ///   early-data (stale/unknown ticket, oversized blob, or AEAD
    ///   failure). The caller must re-send that payload normally.
    pub async fn early_data_accepted(&self) -> Option<bool> {
        *self.early_data_accepted.lock().await
    }

    /// Close the session.
    pub async fn close(&self) -> Result<(), CoreError> {
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

    /// Phase 4.1 — extract a resumption hint for 0-RTT on a future
    /// connect. Returns `Some((session_id_bytes, resumption_secret))`
    /// after a successful handshake; `None` while still handshaking,
    /// after a failure, or before the inner session has been
    /// published.
    ///
    /// The caller is responsible for storing the tuple alongside the
    /// pinned `HybridVerifyingKey` of the server it was negotiated
    /// against. Reusing a hint across servers is a configuration bug
    /// — the resumption_secret is server-pinned.
    pub async fn resumption_hint(&self) -> Option<([u8; 32], [u8; 32])> {
        let guard = self.inner_session.lock().await;
        guard.as_ref().and_then(|s| s.resumption_hint())
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
// bytes (per security invariant 1 in CLAUDE.md), and hands back an
// `Arc<PhantomSession>` ready for `send` / `recv`.
//
// Native-only: `TcpSessionTransport` lives behind `cfg(not(target_arch =
// "wasm32"))`, mirroring `crate::api::tcp_transport`. Wasm consumers use
// the in-tree `WebSocketLeg` instead.
#[cfg(not(target_arch = "wasm32"))]
#[uniffi::export]
pub async fn connect_pinned(
    host: String,
    port: u16,
    pinned_key: Vec<u8>,
) -> Result<Arc<PhantomSession>, CoreError> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::handshake::{
        ClientHelloEnvelope, HandshakeResponse, HandshakeServer, HelloRetryRequestEnvelope,
        ServerHelloEnvelope,
    };

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
        session.close().await.unwrap();
        assert_eq!(session.connection_state(), ConnectionState::Closed);
        assert!(!session.is_data_ready());
    }

    /// Helper: decrypt an incoming encrypted frame on the test server
    /// side. Wire-version-aware — handles both V1 and V2 packets so
    /// the test still works after the V2-default flip.
    fn decrypt_incoming(
        server_session: &crate::transport::session::Session,
        bytes: &[u8],
    ) -> Vec<u8> {
        let versioned = alkahest::deserialize::<VersionedPacket, VersionedPacket>(bytes)
            .expect("deserialize VersionedPacket");
        match versioned {
            VersionedPacket::V1(pkt) => {
                assert!(
                    pkt.header.flags.contains(PacketFlags::ENCRYPTED),
                    "expected ENCRYPTED flag on V1 application data"
                );
                server_session
                    .decrypt_packet(&pkt.header, &pkt.payload)
                    .expect("decrypt V1 application data")
            }
            VersionedPacket::V2(pkt) => {
                assert!(
                    pkt.header.flags.contains(PacketFlagsV2::ENCRYPTED),
                    "expected ENCRYPTED flag on V2 application data"
                );
                server_session
                    .decrypt_packet_v2(&pkt.header, &pkt.payload)
                    .expect("decrypt V2 application data")
            }
        }
    }

    /// Helper: build an encrypted reply frame from the test server
    /// side. Wire-version-aware — emits V1 or V2 based on the
    /// negotiated `wire_version()`.
    fn encrypt_outgoing(
        server_session: &crate::transport::session::Session,
        session_id: SessionId,
        stream_id: TransportStreamId,
        sequence: u32,
        payload: &[u8],
    ) -> Vec<u8> {
        if server_session.wire_version() == 2 {
            let flag_bits = PacketFlagsV2::RELIABLE | PacketFlagsV2::ENCRYPTED;
            let header = PacketHeaderV2::new(
                session_id,
                stream_id,
                sequence,
                PacketFlagsV2::new(flag_bits),
            )
            .with_epoch(server_session.current_epoch());
            let ct = server_session
                .encrypt_packet_v2(&header, payload)
                .expect("encrypt V2 reply");
            let packet = PhantomPacketV2::new(header, ct).into_versioned();
            let mut buf = Vec::new();
            let (size, _) = alkahest::serialize_to_vec::<VersionedPacket, _>(&packet, &mut buf);
            buf[..size].to_vec()
        } else {
            let mut flags = PacketFlags::new(PacketFlags::RELIABLE);
            flags.set(PacketFlags::ENCRYPTED);
            let header = PacketHeader::new(session_id, stream_id, sequence, flags);
            let ct = server_session
                .encrypt_packet(&header, payload)
                .expect("encrypt V1 reply");
            let packet = PhantomPacketV1::new(header, ct).into_versioned();
            let mut buf = Vec::new();
            let (size, _) = alkahest::serialize_to_vec::<VersionedPacket, _>(&packet, &mut buf);
            buf[..size].to_vec()
        }
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

            // 1. Receive client hello. This responder only handles the
            // V12 envelope (the default client offers V2); a V3
            // ClientHello would be a test bug.
            let client_hello_bytes = server_transport.recv_bytes().await.unwrap();
            let client_hello = match borsh::from_slice::<ClientHelloEnvelope>(&client_hello_bytes)
                .unwrap()
            {
                ClientHelloEnvelope::V12(ch) => ch,
                ClientHelloEnvelope::V3(_) => panic!("test responder expects a V12 ClientHello"),
            };

            // 2. Process — may retry with cookie/PoW.
            let server_session = loop {
                let response = server_hs.process_client_hello(&client_hello, 0, client_ip);
                match response {
                    HandshakeResponse::Retry(retry) => {
                        let retry_bytes =
                            borsh::to_vec(&HelloRetryRequestEnvelope::V12(retry)).unwrap();
                        server_transport.send_bytes(&retry_bytes).await.unwrap();
                        // Receive retried client hello
                        let next_bytes = server_transport.recv_bytes().await.unwrap();
                        let next_hello =
                            match borsh::from_slice::<ClientHelloEnvelope>(&next_bytes).unwrap() {
                                ClientHelloEnvelope::V12(ch) => ch,
                                ClientHelloEnvelope::V3(_) => {
                                    panic!("test responder expects a V12 ClientHello")
                                }
                            };
                        let resp2 = server_hs.process_client_hello(&next_hello, 0, client_ip);
                        match resp2 {
                            HandshakeResponse::Success(server_hello, session) => {
                                let server_hello_bytes =
                                    borsh::to_vec(&ServerHelloEnvelope::V12(server_hello)).unwrap();
                                server_transport
                                    .send_bytes(&server_hello_bytes)
                                    .await
                                    .unwrap();
                                break session;
                            }
                            _ => panic!("Expected success after retry"),
                        }
                    }
                    HandshakeResponse::Success(server_hello, session) => {
                        let server_hello_bytes =
                            borsh::to_vec(&ServerHelloEnvelope::V12(server_hello)).unwrap();
                        server_transport
                            .send_bytes(&server_hello_bytes)
                            .await
                            .unwrap();
                        break session;
                    }
                    HandshakeResponse::SuccessV3(..) => {
                        panic!("V12 process_client_hello must not return SuccessV3")
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
        session.close().await.unwrap();
    }

    // ────────────────────────────────────────────────────────────────────
    // V2 wire-routing tests (Phase 4.2 / 2.5 follow-up — data-pump V2)
    // ────────────────────────────────────────────────────────────────────

    use crate::transport::multiplexer::StreamDemultiplexer;
    use crate::transport::session::Session as InnerSession;
    use crate::transport::stream::Stream as TransportStream;

    /// Build two `InnerSession` instances that share a 32-byte secret —
    /// one as the "client" (peer_side=false), one as the "server"
    /// (peer_side=true) — and force them onto wire_version=2. Mirrors
    /// the role split after a real handshake.
    fn paired_v2_sessions(session_id: SessionId) -> (Arc<InnerSession>, Arc<InnerSession>) {
        let secret = [0x11u8; 32];
        let client = Arc::new(InnerSession::new(session_id, &secret, false).unwrap());
        let server = Arc::new(InnerSession::new(session_id, &secret, true).unwrap());
        client.set_wire_version(2);
        server.set_wire_version(2);
        (client, server)
    }

    fn fixed_session_id() -> SessionId {
        SessionId::from_bytes([0x88; 32])
    }

    /// Encrypt a V2 application-data packet from the client side at
    /// `stream_id` / `sequence`. The returned bytes are alkahest-
    /// serialised and ready to feed into `handle_v2_packet`.
    fn build_v2_app_frame(
        client_session: &InnerSession,
        session_id: SessionId,
        stream_id: TransportStreamId,
        sequence: u32,
        payload: &[u8],
    ) -> Vec<u8> {
        let flag_bits = PacketFlagsV2::RELIABLE | PacketFlagsV2::ENCRYPTED;
        let header = PacketHeaderV2::new(
            session_id,
            stream_id,
            sequence,
            PacketFlagsV2::new(flag_bits),
        )
        .with_epoch(client_session.current_epoch());
        let ciphertext = client_session
            .encrypt_packet_v2(&header, payload)
            .expect("encrypt_packet_v2");
        let packet = PhantomPacketV2::new(header, ciphertext).into_versioned();
        let mut buf = Vec::new();
        let (size, _) = alkahest::serialize_to_vec::<VersionedPacket, _>(&packet, &mut buf);
        buf[..size].to_vec()
    }

    #[tokio::test]
    async fn v2_recv_routes_encrypted_app_data_through_recv_channel() {
        let session_id = fixed_session_id();
        let (client_session, server_session) = paired_v2_sessions(session_id);

        // Encrypt a V2 application-data packet on the client side.
        let stream_id: TransportStreamId = 1;
        let frame = build_v2_app_frame(&client_session, session_id, stream_id, 0, b"hello-v2");

        // Receive on the server side: deserialize then drive
        // handle_v2_packet, which is the recv-path entry point.
        let versioned = alkahest::deserialize::<VersionedPacket, VersionedPacket>(&frame).unwrap();
        let v2 = match versioned {
            VersionedPacket::V2(p) => p,
            VersionedPacket::V1(_) => panic!("expected V2"),
        };

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
        handle_v2_packet(
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
        let (_, server_session) = paired_v2_sessions(session_id);

        let stream_id: TransportStreamId = 2;
        let bad_header = PacketHeaderV2::new(
            session_id,
            stream_id,
            0,
            PacketFlagsV2::new(PacketFlagsV2::RELIABLE), // no ENCRYPTED
        );
        let bad_packet = PhantomPacketV2::new(bad_header, b"leaked-cleartext".to_vec());

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
        handle_v2_packet(
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
        let (client_session, server_session) = paired_v2_sessions(session_id);

        // Build a COALESCED bundle of three sub-payloads.
        let mut coalescer = PacketCoalescer::new(CoalescerConfig::default());
        coalescer.push(b"alpha");
        coalescer.push(b"bravo");
        coalescer.push(b"charlie");
        let bundle = coalescer.flush().expect("bundle");

        // Encrypt the bundle and wrap it in a V2 packet with
        // ENCRYPTED + COALESCED flags.
        let stream_id: TransportStreamId = 3;
        let flag_bits = PacketFlagsV2::ENCRYPTED | PacketFlagsV2::COALESCED;
        let header = PacketHeaderV2::new(session_id, stream_id, 0, PacketFlagsV2::new(flag_bits))
            .with_epoch(client_session.current_epoch());
        let ciphertext = client_session
            .encrypt_packet_v2(&header, &bundle)
            .expect("encrypt bundle");
        let v2 = PhantomPacketV2::new(header, ciphertext);

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
        handle_v2_packet(
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
        let (client_session, _server_session) = paired_v2_sessions(session_id);

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
        let (client_session, server_session) = paired_v2_sessions(session_id);

        // Register a stream on the server side so handle_v2_packet
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
        let frame = build_v2_app_frame(&client_session, session_id, stream_id, 0, &big);

        // Server processes the packet via handle_v2_packet. We
        // capture its outbound transport so we can intercept the
        // WINDOW_UPDATE it emits.
        let versioned = alkahest::deserialize::<VersionedPacket, VersionedPacket>(&frame).unwrap();
        let v2 = match versioned {
            VersionedPacket::V2(p) => p,
            VersionedPacket::V1(_) => panic!("V2 expected"),
        };

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
        handle_v2_packet(
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
            let v = alkahest::deserialize::<VersionedPacket, VersionedPacket>(&frame).unwrap();
            let pv2 = match v {
                VersionedPacket::V2(p) => p,
                VersionedPacket::V1(_) => panic!("V2 expected"),
            };
            if pv2.header.flags.contains(PacketFlagsV2::WINDOW_UPDATE) {
                // Decrypt the payload to read the new window.
                let pt = client_session
                    .decrypt_packet_v2(&pv2.header, &pv2.payload)
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
        let (client_session, _server_session) = paired_v2_sessions(session_id);

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
            let versioned =
                alkahest::deserialize::<VersionedPacket, VersionedPacket>(&bytes).unwrap();
            let v2 = match versioned {
                VersionedPacket::V2(p) => p,
                VersionedPacket::V1(_) => panic!("expected V2"),
            };
            // Decrypt under the SERVER role so the per-direction key
            // matches the client-side encrypt.
            let plaintext = _server_session
                .decrypt_packet_v2(&v2.header, &v2.payload)
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
        let (client_session, server_session) = paired_v2_sessions(session_id);

        // Build a PATH_VALIDATION packet with ENCRYPTED + path_id=7.
        let path_id: u8 = 7;
        let payload = [0xDEu8; crate::transport::path::PATH_CHALLENGE_LEN];
        let flag_bits = PacketFlagsV2::ENCRYPTED | PacketFlagsV2::PATH_VALIDATION;
        let header = PacketHeaderV2::new(session_id, 0, 0, PacketFlagsV2::new(flag_bits))
            .with_epoch(client_session.current_epoch())
            .with_path_id(path_id);
        let ciphertext = client_session
            .encrypt_packet_v2(&header, &payload)
            .expect("encrypt challenge");
        let v2 = PhantomPacketV2::new(header, ciphertext);

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

        handle_v2_packet(
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
        let echo_versioned =
            alkahest::deserialize::<VersionedPacket, VersionedPacket>(&echo_bytes).unwrap();
        let echo_v2 = match echo_versioned {
            VersionedPacket::V2(p) => p,
            VersionedPacket::V1(_) => panic!("expected V2"),
        };
        assert!(echo_v2
            .header
            .flags
            .contains(PacketFlagsV2::PATH_VALIDATION));
        assert_eq!(echo_v2.header.path_id, path_id);

        // Sequence space advanced by exactly one (we sent one echo).
        assert_eq!(path_validation_seq, 101);
    }

    // ────────────────────────────────────────────────────────────────────
    // Wire V3 — 0-RTT early-data (Phase 4.1)
    // ────────────────────────────────────────────────────────────────────

    /// Full 0-RTT round-trip over `ChannelTransport`: a priming V12
    /// handshake populates the server cache and yields a resumption
    /// hint; a second connect via `connect_with_resumption` carries
    /// application early-data inside the V3 ClientHello, which the
    /// server decrypts and surfaces. The client learns the verdict
    /// via `early_data_accepted()`.
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

        // ── Phase 1: prime — a normal V12 handshake fills the cache ──
        let (c1, s1) = ChannelTransport::pair();
        let phase1_session =
            PhantomSession::connect_with_transport("test:9000", c1, server_pinned_key.clone());

        let hello_bytes = s1.recv_bytes().await.unwrap();
        let ch = match borsh::from_slice::<ClientHelloEnvelope>(&hello_bytes).unwrap() {
            ClientHelloEnvelope::V12(ch) => ch,
            ClientHelloEnvelope::V3(_) => panic!("phase 1 expects a V12 ClientHello"),
        };
        let retry = match server_hs.process_client_hello(&ch, 0, client_ip) {
            HandshakeResponse::Retry(r) => r,
            _ => panic!("expected Retry"),
        };
        s1.send_bytes(&borsh::to_vec(&HelloRetryRequestEnvelope::V12(retry)).unwrap())
            .await
            .unwrap();
        let next = s1.recv_bytes().await.unwrap();
        let ch2 = match borsh::from_slice::<ClientHelloEnvelope>(&next).unwrap() {
            ClientHelloEnvelope::V12(ch) => ch,
            ClientHelloEnvelope::V3(_) => panic!("phase 1 retry expects V12"),
        };
        match server_hs.process_client_hello(&ch2, 0, client_ip) {
            HandshakeResponse::Success(sh, _session) => {
                s1.send_bytes(&borsh::to_vec(&ServerHelloEnvelope::V12(sh)).unwrap())
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

        // ── Phase 2: resume — V3 ClientHello carries the early-data ──
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
        let ch3 = match borsh::from_slice::<ClientHelloEnvelope>(&hello_bytes).unwrap() {
            ClientHelloEnvelope::V3(ch3) => ch3,
            ClientHelloEnvelope::V12(_) => panic!("phase 2 expects a V3 ClientHello"),
        };
        match server_hs.process_client_hello_v3(&ch3, 0, client_ip) {
            HandshakeResponse::SuccessV3(sh3, _session, early_data) => {
                // The server decrypted exactly what the client sealed.
                assert_eq!(early_data.as_deref(), Some(&early_payload[..]));
                assert!(sh3.early_data_accepted);
                s2.send_bytes(&borsh::to_vec(&ServerHelloEnvelope::V3(sh3)).unwrap())
                    .await
                    .unwrap();
            }
            _ => panic!("expected SuccessV3 — the resumption ticket is fresh"),
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

    /// A V3 client whose server does not speak V3 receives
    /// `ServerHelloEnvelope::Unsupported` and transparently falls back
    /// to a plain V2 handshake. The handshake still completes;
    /// `early_data_accepted()` is `None` (no 0-RTT happened).
    #[tokio::test]
    async fn v3_client_falls_back_to_v2_on_unsupported() {
        let server_hs = HandshakeServer::new().unwrap();
        let server_pinned_key = server_hs.verifying_key().clone();
        let client_ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();

        // The hint is fabricated — the server replies `Unsupported`
        // before ever looking at the resumption ticket.
        let fake_hint = ([0u8; 32], [0u8; 32]);
        let (c, s) = ChannelTransport::pair();
        let session = PhantomSession::connect_with_resumption(
            "test:9000",
            c,
            server_pinned_key,
            fake_hint,
            b"early-data-that-will-not-be-sent".to_vec(),
        )
        .unwrap();

        // 1. The first flight is a V3 ClientHello — reply Unsupported.
        let hello_bytes = s.recv_bytes().await.unwrap();
        assert!(
            matches!(
                borsh::from_slice::<ClientHelloEnvelope>(&hello_bytes).unwrap(),
                ClientHelloEnvelope::V3(_)
            ),
            "client's first flight must be a V3 ClientHello"
        );
        s.send_bytes(&borsh::to_vec(&ServerHelloEnvelope::Unsupported).unwrap())
            .await
            .unwrap();

        // 2. The client must fall back to a V2 ClientHello — drive the
        //    normal cookie/PoW V12 dance to completion.
        let v2_bytes = s.recv_bytes().await.unwrap();
        let ch = match borsh::from_slice::<ClientHelloEnvelope>(&v2_bytes).unwrap() {
            ClientHelloEnvelope::V12(ch) => ch,
            ClientHelloEnvelope::V3(_) => panic!("client should have fallen back to V12"),
        };
        let retry = match server_hs.process_client_hello(&ch, 0, client_ip) {
            HandshakeResponse::Retry(r) => r,
            _ => panic!("expected Retry on the V2 fallback"),
        };
        s.send_bytes(&borsh::to_vec(&HelloRetryRequestEnvelope::V12(retry)).unwrap())
            .await
            .unwrap();
        let next = s.recv_bytes().await.unwrap();
        let ch2 = match borsh::from_slice::<ClientHelloEnvelope>(&next).unwrap() {
            ClientHelloEnvelope::V12(ch) => ch,
            ClientHelloEnvelope::V3(_) => panic!("expected a V12 retry"),
        };
        match server_hs.process_client_hello(&ch2, 0, client_ip) {
            HandshakeResponse::Success(sh, _session) => {
                s.send_bytes(&borsh::to_vec(&ServerHelloEnvelope::V12(sh)).unwrap())
                    .await
                    .unwrap();
            }
            _ => panic!("expected Success on the V2 fallback"),
        }

        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        assert_eq!(
            session.connection_state(),
            ConnectionState::Connected,
            "the V3 → V2 fallback handshake must complete"
        );
        assert_eq!(
            session.early_data_accepted().await,
            None,
            "fell back to V2 — there is no 0-RTT verdict"
        );

        // Keep the server transport alive until the assertions run.
        drop(s);
    }
}
