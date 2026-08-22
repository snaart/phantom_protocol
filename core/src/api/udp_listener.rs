//! PhantomUDP server listener: one bound `UdpSocket`, a central demux task routing datagrams by the
//! 8-byte connection-ID into per-session channels, and a decoupled accept queue mirroring
//! `PhantomListener`. Exposed through UniFFI via `bind_udp` / `accept` / `verifying_key_bytes` /
//! `metrics_snapshot` / `local_addr` / `shutdown` / `is_shutting_down`.
//!
//! Phase 1 uses a single shared `FragmentAssembler` for reassembly across all CIDs (bounded by the
//! assembler's own anti-DoS caps); per-CID isolation is a Phase-2 refinement — see `run_udp_demux`.

use crate::api::listener::{drive_server_handshake, AcceptOutcome};
use crate::api::session::PhantomSession;
use crate::api::udp_transport::{HandshakeFlight, UdpServerTransport};
use crate::crypto::hybrid_sign::HybridSigningKey;
use crate::errors::CoreError;
use crate::observability::attrs::{AeadAlgorithm, HandshakeOutcome, ProtocolVersion};
use crate::observability::{Observability, ObservabilityConfig};
use crate::runtime::{Runtime, SpawnHandle, TokioRuntime};
use crate::transport::handshake::{
    client_hello_lengths_within_bounds, ClientHello, HandshakeServer, HelloRetryRequest,
    ServerReply, UdpAdmit,
};
use crate::transport::phantom_udp::datagram::{encode_datagrams, push_datagram, FragmentAssembler};
use crate::transport::phantom_udp::envelope::{ConnId, PacketType};
use crate::transport::session::{CidSlide, DemuxLink, DemuxRouteOwner};
use crate::transport::types::LegType;
use bytes::Bytes;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex, Notify, Semaphore};

/// In-library handshake deadline, routed through the `Runtime` clock. The PQ
/// handshake completes in single-digit ms on a real link, so 10s absorbs
/// mobile/satellite RTT + a cookie/PoW round while still bounding a slowloris.
const HANDSHAKE_DEADLINE: Duration = Duration::from_secs(10);
/// Max concurrent in-flight (accepted-but-not-yet-established) handshakes the
/// demux admits at once — a DoS bound on unauthenticated work. Also the depth
/// of the completed-handshake hand-off queue.
const MAX_INFLIGHT_HANDSHAKES: usize = 256;
/// Per-session inbound-frame channel depth — back-pressures a slow pump without
/// unbounded buffering; a full channel drops the datagram (the peer retransmits).
const SESSION_CHANNEL_DEPTH: usize = 256;

/// UDP server listener — one bound `UdpSocket`, a central demux task routing
/// datagrams by the 8-byte connection-ID into per-session channels, and a
/// decoupled accept queue mirroring `PhantomListener`.
///
/// Prefer this over the TCP `PhantomListener` when clients need seamless
/// connection migration (`migrate()` returns `Err(Unsupported)` on TCP-backed
/// sessions but performs a real path-switch on UDP-backed ones).
///
/// # Example
///
/// ```rust,no_run
/// # #[tokio::main]
/// # async fn main() -> Result<(), phantom_protocol::CoreError> {
/// use std::sync::Arc;
/// use phantom_protocol::api::PhantomUdpListener;
///
/// let listener = PhantomUdpListener::builder("0.0.0.0:4242").bind().await?;
/// let pinned_key = listener.verifying_key_bytes();   // share out-of-band
///
/// loop {
///     let outcome = Arc::clone(&listener).accept().await?;
///     let session = outcome.session();
///     tokio::spawn(async move {
///         let _req = session.recv().await?;
///         session.send(b"pong".to_vec()).await?;
///         Ok::<_, phantom_protocol::CoreError>(())
///     });
/// }
/// # }
/// ```
#[cfg_attr(feature = "bindings", derive(uniffi::Object))]
pub struct PhantomUdpListener {
    socket: Arc<UdpSocket>,
    handshake_server: Arc<HandshakeServer>,
    local_addr: SocketAddr,
    shutting_down: Arc<AtomicBool>,
    shutdown_notify: Arc<Notify>,
    runtime: Arc<dyn Runtime>,
    observability: Arc<Observability>,
    inflight: Arc<Semaphore>,
    accepted_tx: mpsc::Sender<Arc<AcceptOutcome>>,
    accepted_rx: Mutex<mpsc::Receiver<Arc<AcceptOutcome>>>,
    demux: parking_lot::Mutex<Option<SpawnHandle>>,
    /// Live gauge mirroring the demux `routes` table size (H-1 observability). The
    /// demux owns the table; this lets `active_route_count()` read it without a lock.
    active_routes: Arc<AtomicUsize>,
    /// Live gauge mirroring the demux `flights` table size (PROTOCOL § 6.1). Same
    /// arrangement as `active_routes`: the demux task owns the table and nothing outside it
    /// can look, so without this the only evidence that a retained reply was ever released
    /// would be the absence of a repeat — which is also what a working repair looks like.
    retained_flights: Arc<AtomicUsize>,
    /// Optional liveness config derived from a `PhantomConfig` supplied at bind time.
    /// When `Some`, applied to every accepted session immediately after the handshake.
    liveness: Option<crate::transport::liveness::LivenessConfig>,
}

impl PhantomUdpListener {
    /// Like [`bind_udp`](Self::bind_udp) but uses the caller-supplied long-lived
    /// [`HybridSigningKey`] as the server's signing identity instead of generating a
    /// fresh one per process — so the verifying-key material clients pin survives
    /// restarts. [`verifying_key_bytes`](Self::verifying_key_bytes) returns the
    /// verifying half of `signing_key`. Rust-only (not UniFFI-exported because
    /// `HybridSigningKey` is not a UniFFI type; the FFI analogue is
    /// [`bind_udp_with_signing_key_bytes`](Self::bind_udp_with_signing_key_bytes)).
    ///
    /// Thin shim over [`PhantomUdpListener::builder`] + `.signing_key(key).bind()`.
    pub async fn bind_udp_with_signing_key(
        addr: String,
        signing_key: HybridSigningKey,
    ) -> Result<Arc<Self>, CoreError> {
        Self::builder(addr).signing_key(signing_key).bind().await
    }

    async fn bind_inner(
        addr: String,
        runtime: Arc<dyn Runtime>,
        signing_key: Option<HybridSigningKey>,
        config: Option<crate::config::PhantomConfig>,
    ) -> Result<Arc<Self>, CoreError> {
        #[cfg(feature = "fips")]
        crate::crypto::self_tests::ensure_post_passed()
            .map_err(|e| CoreError::FipsSelfTestFailure(format!("{e:?}")))?;
        let socket = UdpSocket::bind(&addr)
            .await
            .map_err(|e| CoreError::NetworkError(format!("udp bind: {e}")))?;
        let local_addr = socket
            .local_addr()
            .map_err(|e| CoreError::NetworkError(format!("local_addr: {e}")))?;
        // Built before the `HandshakeServer` so the same shared handle can be installed
        // as its metrics sink. On UDP this also covers `udp_admit`, the stateless
        // cookie pre-gate that runs on the demux thread.
        let observability = Observability::new(ObservabilityConfig::default());
        let hs = match (signing_key, config.as_ref()) {
            (Some(sk), Some(cfg)) => {
                HandshakeServer::with_signing_key_and_cache(sk, cfg.session_cache())
            }
            (Some(sk), None) => HandshakeServer::with_signing_key(sk),
            // Fresh per-process identity WITH a config-sized cache. Use new_with_cache
            // (not an inline generate) so the FIPS pairwise-consistency check `new()`
            // runs is preserved on the auto-generated signing key.
            (None, Some(cfg)) => HandshakeServer::new_with_cache(cfg.session_cache()),
            (None, None) => HandshakeServer::new(),
        }
        .map_err(|e| CoreError::InternalError(e.to_string()))?
        .with_observability(observability.clone());
        let (accepted_tx, accepted_rx) = mpsc::channel(MAX_INFLIGHT_HANDSHAKES);
        Ok(Arc::new(Self {
            socket: Arc::new(socket),
            handshake_server: Arc::new(hs),
            local_addr,
            shutting_down: Arc::new(AtomicBool::new(false)),
            shutdown_notify: Arc::new(Notify::new()),
            runtime,
            observability,
            inflight: Arc::new(Semaphore::new(MAX_INFLIGHT_HANDSHAKES)),
            accepted_tx,
            accepted_rx: Mutex::new(accepted_rx),
            demux: parking_lot::Mutex::new(None),
            active_routes: Arc::new(AtomicUsize::new(0)),
            retained_flights: Arc::new(AtomicUsize::new(0)),
            liveness: config.map(|c| c.liveness()),
        }))
    }

    /// Install a distributed 0-RTT anti-replay store (A2b) for replay-safe 0-RTT in a
    /// horizontally-scaled deployment — see [`ZeroRttAntiReplay`]. The default (none) is
    /// correct for a single node / sticky routing.
    ///
    /// [`ZeroRttAntiReplay`]: crate::transport::handshake::ZeroRttAntiReplay
    pub fn set_zero_rtt_anti_replay(
        &self,
        store: Arc<dyn crate::transport::handshake::ZeroRttAntiReplay>,
    ) {
        self.handshake_server.set_zero_rtt_anti_replay(store);
    }

    /// Number of live demux routes (one per in-flight handshake or established
    /// session). Bounded by reaping + a hard cap (H-1); exposed so a fresh-CID
    /// spray's failure to grow this without bound is observable/testable.
    pub fn active_route_count(&self) -> usize {
        self.active_routes.load(Ordering::Relaxed)
    }

    fn ensure_demux(self: &Arc<Self>) {
        let mut guard = self.demux.lock();
        if guard.is_some() {
            return;
        }
        let handle = self.runtime.spawn(Box::pin(run_udp_demux(self.clone())));
        *guard = Some(handle);
    }

    /// Create a [`UdpListenerBuilder`] for constructing a PhantomUDP listener.
    ///
    /// The builder collects configuration (optional signing key, runtime, config)
    /// and then `.bind().await` stands up the listener.
    pub fn builder(addr: impl Into<String>) -> UdpListenerBuilder {
        UdpListenerBuilder {
            addr: addr.into(),
            signing_key: None,
            config: None,
            runtime: None,
        }
    }
}

#[cfg_attr(feature = "bindings", uniffi::export(async_runtime = "tokio"))]
impl PhantomUdpListener {
    /// Bind a PhantomUDP listener on `addr` with a fresh per-process signing
    /// identity. For a persistent pinned identity across restarts use
    /// [`bind_udp_with_signing_key`](Self::bind_udp_with_signing_key) (Rust-only)
    /// or [`bind_udp_with_signing_key_bytes`](Self::bind_udp_with_signing_key_bytes) (FFI).
    #[cfg_attr(feature = "bindings", uniffi::constructor)]
    pub async fn bind_udp(addr: String) -> Result<Arc<Self>, CoreError> {
        Self::bind_inner(addr, Arc::new(TokioRuntime), None, None).await
    }

    /// Bind a PhantomUDP listener using a persisted 64-byte signing seed (from
    /// [`generate_signing_key`](crate::api::identity::generate_signing_key)) as the
    /// server's long-lived identity, so `verifying_key_bytes()` stays stable across
    /// restarts. FFI analogue of the Rust-only
    /// [`bind_udp_with_signing_key`](Self::bind_udp_with_signing_key).
    #[cfg_attr(feature = "bindings", uniffi::constructor)]
    pub async fn bind_udp_with_signing_key_bytes(
        addr: String,
        signing_key: Vec<u8>,
    ) -> Result<Arc<Self>, CoreError> {
        let sk = HybridSigningKey::from_bytes(&signing_key)
            .map_err(|e| CoreError::CryptoError(format!("invalid signing key seed: {e}")))?;
        Self::bind_inner(addr, Arc::new(TokioRuntime), Some(sk), None).await
    }

    /// Bind a PhantomUDP listener using a persisted 64-byte signing seed and a
    /// [`PhantomConfig`](crate::config::PhantomConfig) that controls liveness settings
    /// and session-cache sizing. FFI analogue of the Rust-only
    /// [`bind_udp_with_signing_key`](Self::bind_udp_with_signing_key) + config combination.
    #[cfg_attr(feature = "bindings", uniffi::constructor)]
    pub async fn bind_udp_with_config_bytes(
        addr: String,
        signing_key: Vec<u8>,
        config: crate::config::PhantomConfig,
    ) -> Result<Arc<Self>, CoreError> {
        let sk = HybridSigningKey::from_bytes(&signing_key)
            .map_err(|e| CoreError::CryptoError(format!("invalid signing key seed: {e}")))?;
        Self::bind_inner(addr, Arc::new(TokioRuntime), Some(sk), Some(config)).await
    }

    /// The server's long-lived hybrid verifying key (`HybridVerifyingKey::to_bytes`).
    /// Clients MUST pin this before completing a handshake (security invariant 1).
    pub fn verifying_key_bytes(&self) -> Vec<u8> {
        self.handshake_server.verifying_key().to_bytes()
    }

    /// Flat snapshot of the listener's aggregated connection metrics (all
    /// accepted sessions share this counter set). Lock-free read; available
    /// with or without `telemetry-otel`.
    ///
    /// Identical in shape and meaning to
    /// [`PhantomListener::metrics_snapshot`](crate::api::listener::PhantomListener::metrics_snapshot),
    /// so an embedder can swap the TCP listener for this one without touching its
    /// monitoring code. It is the only way to read handshake counters,
    /// `replay_rejected_total` and `aead_failure_total` while no session is in
    /// hand — reaching them through an accepted session's snapshot requires a
    /// session, and a server that is being probed but not connected to has none.
    pub fn metrics_snapshot(&self) -> crate::observability::MetricsSnapshotFfi {
        self.observability.snapshot().into()
    }

    /// Local socket address the listener is actually bound to (resolved at bind
    /// time) — useful when the caller passed `"host:0"`.
    pub fn local_addr(&self) -> String {
        self.local_addr.to_string()
    }

    /// Accept the next inbound connection and complete its handshake, returning the
    /// established session plus any 0-RTT early-data (see [`AcceptOutcome`]).
    ///
    /// Receiver is `self: Arc<Self>` (not `&self`): the lazily-spawned demux task
    /// needs an owned `Arc<Self>` to drive `run_udp_demux`, so an owned receiver is
    /// required here. FFI bindings clone the object handle and can loop `accept()`
    /// freely; a Rust caller that accepts more than once in the same scope must call
    /// `listener.clone().accept()`.
    pub async fn accept(self: Arc<Self>) -> Result<Arc<AcceptOutcome>, CoreError> {
        if self.shutting_down.load(Ordering::Acquire) {
            return Err(CoreError::ConnectionClosed);
        }
        self.ensure_demux();
        let mut rx = self.accepted_rx.lock().await;
        let shutdown_fut = self.shutdown_notify.notified();
        tokio::pin!(shutdown_fut);
        tokio::select! {
            biased;
            _ = &mut shutdown_fut => Err(CoreError::ConnectionClosed),
            item = rx.recv() => item.ok_or(CoreError::ConnectionClosed),
        }
    }

    /// Signal graceful shutdown: wakes any parked `accept()` so it unwinds with
    /// `ConnectionClosed`. Idempotent. Already-accepted sessions are unaffected.
    pub fn shutdown(&self) {
        self.shutting_down.store(true, Ordering::Release);
        self.shutdown_notify.notify_waiters();
        if let Some(h) = self.demux.lock().as_ref() {
            h.abort();
        }
    }

    /// Whether [`shutdown`](Self::shutdown) has been called.
    pub fn is_shutting_down(&self) -> bool {
        self.shutting_down.load(Ordering::Acquire)
    }

    /// Enable or disable 0-RTT early-data acceptance (default: enabled). When
    /// disabled, resuming clients' early-data is rejected and resent in a 1-RTT
    /// exchange — the zero-infrastructure defence against 0-RTT replay for a
    /// deployment that cannot guarantee a single coherent resumption cache. See
    /// [`HandshakeServer::set_early_data_enabled`].
    pub fn set_early_data_enabled(&self, enabled: bool) {
        self.handshake_server.set_early_data_enabled(enabled);
    }
}

impl Drop for PhantomUdpListener {
    fn drop(&mut self) {
        self.shutting_down.store(true, Ordering::Release);
        self.shutdown_notify.notify_waiters();
        if let Some(h) = self.demux.lock().take() {
            h.abort();
        }
    }
}

/// Hard upper bound on concurrent demux routes (H-1 backstop). One route exists per
/// in-flight handshake, plus — once established — a session's rotating-CID **window**
/// of `CID_WINDOW_TRAILING + CID_WINDOW_LEADING + 1` (= 19) routes (ε / WIRE v5).
/// Reaping keeps the steady-state size near the in-flight ceiling, and this cap bounds
/// memory even if reaping ever lagged. A fresh-CID spray cannot grow the map past this —
/// excess `Initial`s are dropped (the peer retransmits). `1 << 18` (raised from `1 << 16`
/// when EPS-01 widened the per-session window 7→19) preserves the concurrent-session
/// capacity: `(1 << 18) / 19 ≈ 13.8k` live sessions, above the prior `(1 << 16) / 7 ≈ 9.4k`.
const MAX_ROUTES: usize = 1 << 18;

/// What a handshake task hands the demux when it establishes a session.
///
/// ε / WIRE v5: a session's inbound rotating-CID window paired with its inbound channel and
/// the identity of its routes, so the demux can install the window CIDs (N:1) and the
/// client's `CID_0..` datagrams route to the session.
///
/// PROTOCOL § 6.1: and, when there is one, the reply flight to retain against a repeated
/// client hello. It rides the same message as the window rather than a channel of its own
/// because it is produced at the same instant, by the same task, for the same session — and
/// because the demux drains this queue ahead of the socket, which is what puts the retention
/// in place before a repeat could arrive on it.
struct SessionRegistration {
    cids: Vec<ConnId>,
    tx: mpsc::Sender<(Bytes, SocketAddr)>,
    owner: RouteOwner,
    /// The bootstrap CID the handshake ran under — the key a repeated hello arrives on,
    /// because a client that has not seen the reply has nothing to rotate its CID from.
    bootstrap_cid: ConnId,
    flight: Option<HandshakeFlight>,
}

/// Depth of the end-of-session route-retire queue (WIRE v8).
///
/// The demux drains this queue ahead of every datagram read, so its length is how
/// much work a peer population can put in front of the socket, and a peer decides
/// when its own session ends. Bounded, the worst a coordinated departure can insert
/// before the next `recv_from` is this many retirements of at most
/// `CID_WINDOW_TRAILING + CID_WINDOW_LEADING + 2` map removals each.
///
/// Measured in-crate at exactly that shape — a full queue of 1024 sessions each
/// holding its whole 20-CID window, drained back to back on an optimised build — one
/// full queue costs **1.2 ms** against a table holding only those routes and **2.0 ms**
/// against a table an order of magnitude larger, or roughly 1–2 µs per retirement.
/// That is a bounded pause, not a stall, and it is what the bound is for; it is also
/// two orders of magnitude above the "tens of microseconds" this comment used to
/// claim, which is worth stating plainly because the figure is the whole argument for
/// the number.
///
/// Past the bound the excess is dropped rather than queued.
/// [`Session::signal_route_retire`] carries what a dropped one costs, and
/// [`ROUTE_SWEEP_INTERVAL`] is what makes that cost a deferral.
const RETIRE_QUEUE_DEPTH: usize = 1024;

/// How often the demux sweeps its own route table for entries nothing will come back
/// for (WIRE v8).
///
/// Every other reclaim this table has is driven by a *peer*: a datagram that arrives
/// for a dead route, a handshake task finishing, a once-per-256-connections sweep at
/// accept, and the end-of-session retire signal. A departed peer population produces
/// none of those, and neither does anything else once the last client has gone — so
/// without a timer of its own, a retire signal dropped at
/// [`RETIRE_QUEUE_DEPTH`] is not a deferred reclaim, it is a permanent one. That is
/// the whole reason this exists: it is what makes the bound on that queue a
/// *deferral* rather than a leak, and it is the only reclaim path on this table whose
/// clock is not held by someone else.
///
/// One second is chosen against what the sweep costs rather than against how quickly
/// a route ought to go: the routes it reclaims are memory and nothing else — a dead
/// route routes nothing — so holding one for a second is not a correctness question.
/// The pass is [`RouteTable::reap_dead`], which is not new work; it is the same pass
/// the every-256th-connection trigger already runs, given a clock that does not
/// depend on connections arriving.
///
/// Measured in-crate on an optimised build, at the realistic shape of one inbound
/// channel per session and a full CID window of routes pointing at it: a sweep with
/// nothing to reclaim costs **73 µs** over 1,000 sessions (20k routes) and **1.4 ms**
/// at the `MAX_ROUTES` ceiling (13k sessions, 260k routes) — 0.14% of a second at a
/// capacity no deployment here has reached. The expensive case is the one where every
/// route is dead, **42 ms** at that ceiling, and it happens once: after an entire
/// population has departed, which is exactly when no datagram is waiting behind it.
/// On an idle listener it is a walk of an empty map.
const ROUTE_SWEEP_INTERVAL: Duration = Duration::from_secs(1);

/// Which session a demux route belongs to — a local name for the identity this
/// listener hands each accepted session in its `DemuxLink`, so the table's own code
/// reads as being about routes rather than about sessions.
type RouteOwner = DemuxRouteOwner;

/// One demux route: the session's inbound channel and which session it is.
struct RouteEntry {
    tx: mpsc::Sender<(Bytes, SocketAddr)>,
    owner: RouteOwner,
}

/// Bounded, self-reaping demux route table keyed on the unauthenticated 8-byte CID (H-1).
/// A route's liveness is exactly its inbound channel's: a closed `Sender` (`is_closed()`)
/// means the handshake task failed or the established session was dropped, so the entry is
/// reclaimable. The `gauge` mirrors `len()` so `active_route_count()` can read the size
/// without a lock. A live session's route is never evicted to admit a new connection.
///
/// `owned` is the reverse index: every CID currently routed to a given session. It is
/// what makes releasing a whole session's routes cost the size of that session's own
/// window rather than the size of the table, and it is also what makes the operation
/// safe — the released set is the set that was inserted under that identity, so a
/// session cannot reach another's routes even in principle. It is maintained by
/// [`Self::insert_route`] and [`Self::remove_route`], which every mutator funnels
/// through, and it holds no entry for a session with no routes.
struct RouteTable {
    routes: HashMap<ConnId, RouteEntry>,
    owned: HashMap<RouteOwner, Vec<ConnId>>,
    gauge: Arc<AtomicUsize>,
}

impl RouteTable {
    fn new(gauge: Arc<AtomicUsize>) -> Self {
        gauge.store(0, Ordering::Relaxed);
        Self {
            routes: HashMap::new(),
            owned: HashMap::new(),
            gauge,
        }
    }

    fn sync(&self) {
        self.gauge.store(self.routes.len(), Ordering::Relaxed);
    }

    fn get(&self, cid: &ConnId) -> Option<&mpsc::Sender<(Bytes, SocketAddr)>> {
        self.routes.get(cid).map(|e| &e.tx)
    }

    /// Record `cid → (tx, owner)` in both directions. The single insertion point, so
    /// the reverse index cannot fall behind the forward one.
    fn insert_route(
        &mut self,
        cid: ConnId,
        tx: mpsc::Sender<(Bytes, SocketAddr)>,
        owner: RouteOwner,
    ) {
        if let Some(previous) = self.routes.insert(cid, RouteEntry { tx, owner }) {
            self.forget_owned(previous.owner, &cid);
        }
        self.owned.entry(owner).or_default().push(cid);
    }

    /// Drop `cid` from `owner`'s reverse-index entry, and the entry itself once it is
    /// empty, so a session that has lost its last route leaves nothing behind.
    fn forget_owned(&mut self, owner: RouteOwner, cid: &ConnId) {
        if let Some(cids) = self.owned.get_mut(&owner) {
            cids.retain(|c| c != cid);
            if cids.is_empty() {
                self.owned.remove(&owner);
            }
        }
    }

    /// Drop one route from both directions. The single removal point.
    fn remove_route(&mut self, cid: &ConnId) {
        if let Some(entry) = self.routes.remove(cid) {
            self.forget_owned(entry.owner, cid);
        }
    }

    /// Reclaim every route whose receiver was dropped (failed handshake / gone session).
    fn reap_dead(&mut self) {
        let dead: Vec<ConnId> = self
            .routes
            .iter()
            .filter(|(_, entry)| entry.tx.is_closed())
            .map(|(cid, _)| *cid)
            .collect();
        for cid in &dead {
            self.remove_route(cid);
        }
        self.sync();
    }

    /// Insert a fresh route, enforcing `MAX_ROUTES`. Reaps dead entries first when at the
    /// cap; returns `false` (inserting nothing) only if still full of *live* routes, so the
    /// caller drops the new `Initial`. A live route is never evicted to admit a new one.
    ///
    /// That last sentence is checked here as well as at the cap. The key is a connection
    /// id chosen by whoever sent the datagram, so an unconditional insert would let one
    /// party silently repoint a route a live session is being reached through; a slot
    /// already held by *another* live session is refused instead. Re-inserting a CID this
    /// same session already holds is a no-op, which is the ordinary case — its bootstrap
    /// CID arrives again as part of its window.
    fn try_insert(
        &mut self,
        cid: ConnId,
        tx: mpsc::Sender<(Bytes, SocketAddr)>,
        owner: RouteOwner,
    ) -> bool {
        match self.routes.get(&cid) {
            Some(entry) if entry.owner == owner => return true,
            Some(entry) if !entry.tx.is_closed() => return false,
            _ => {}
        }
        if self.routes.len() >= MAX_ROUTES {
            self.reap_dead();
            if self.routes.len() >= MAX_ROUTES {
                return false;
            }
        }
        self.insert_route(cid, tx, owner);
        self.sync();
        true
    }

    /// Hand a reassembled frame to the session `cid` routes to, reclaiming the route if that
    /// session has gone. Gives the frame back when nothing routes for the CID, which is the
    /// caller's cue that this may be a new connection.
    ///
    /// Returning the frame rather than a flag is what keeps the common path to a single
    /// lookup: the alternative is asking whether a route exists and then asking again to use
    /// it, on every datagram a busy listener carries.
    fn deliver(&mut self, cid: &ConnId, frame: Vec<u8>, peer: SocketAddr) -> Option<Vec<u8>> {
        let Some(tx) = self.get(cid) else {
            return Some(frame);
        };
        if tx.try_send((Bytes::from(frame), peer)).is_err() && tx.is_closed() {
            self.remove_if_dead(cid);
        }
        None
    }

    /// Remove a CID iff its route is dead. Safe for any CID — a live session's route (its
    /// `Sender` still held by the running session) is left untouched.
    fn remove_if_dead(&mut self, cid: &ConnId) {
        if self.routes.get(cid).is_some_and(|e| e.tx.is_closed()) {
            self.remove_route(cid);
            self.sync();
        }
    }

    /// ε / WIRE v5: register the rotating-CID demux window — insert each window
    /// CID → the session's inbound channel (N:1), so a datagram stamped with any
    /// CID in the window routes to this session. `try_insert` reaps dead entries
    /// at the cap; a CID that can't be inserted (table full of *live* routes) is
    /// skipped — the peer retransmits, and the window stays bounded by MAX_ROUTES.
    /// The bootstrap CID (registered separately at Initial accept) stays alongside
    /// the window until the whole session's routes are released on disconnect.
    fn register_window(
        &mut self,
        cids: &[ConnId],
        tx: &mpsc::Sender<(Bytes, SocketAddr)>,
        owner: RouteOwner,
    ) {
        for &cid in cids {
            self.try_insert(cid, tx.clone(), owner);
        }
    }

    /// ε / WIRE v5: apply a one-step inbound-window slide — register the new
    /// leading-edge CIDs and drop the trailing ones — resolving the session's
    /// channel through `anchor` (a CID still routed for it). A no-op if `anchor` is
    /// gone (the session ended), so a late slide for a dead session does nothing.
    fn apply_slide(&mut self, slide: &CidSlide) {
        let Some(entry) = self.routes.get(&slide.anchor) else {
            return;
        };
        let (tx, owner) = (entry.tx.clone(), entry.owner);
        for &cid in &slide.add {
            self.try_insert(cid, tx.clone(), owner);
        }
        for cid in &slide.remove {
            self.remove_route(cid);
        }
        self.sync();
    }

    /// Drop every route belonging to `owner` (WIRE v8): its bootstrap CID, its whole
    /// rotating window, and any leading-edge CID a slide added — released together the
    /// moment the session ends, rather than one at a time as datagrams that will never
    /// arrive would have released them.
    ///
    /// The cost is the size of that session's own route set, at most
    /// `CID_WINDOW_TRAILING + CID_WINDOW_LEADING + 2`, and never the size of the table.
    /// That distinction is the whole reason the reverse index exists: this runs on the
    /// demux task, ahead of the next datagram read, at a moment a peer chooses, so a
    /// version of it that scanned the table would let a coordinated departure decide how
    /// long every other session's traffic waits.
    ///
    /// `owner` is an identity this listener assigned and never put on the wire, and the
    /// released set is exactly the set inserted under it, so this can only ever release
    /// the routes of the session that asked. A no-op if the session has none left.
    fn retire_session(&mut self, owner: RouteOwner) {
        let Some(cids) = self.owned.remove(&owner) else {
            return;
        };
        for cid in &cids {
            self.routes.remove(cid);
        }
        self.sync();
    }
}

/// How many times one retained reply flight will be repeated (PROTOCOL § 6.1).
///
/// Not chosen — it is the number of times the *client* repeats its own flight before giving
/// up, and the coupling is checked by
/// [`the_repeat_budget_matches_the_clients_retransmit_schedule`]. Fewer would leave the
/// client's last question unanswered on a path that lost more than one reply; more would be
/// capacity offered for a question that will never be asked, and every repeat is work an
/// on-path attacker can trigger by replaying a captured hello.
///
/// [`the_repeat_budget_matches_the_clients_retransmit_schedule`]: self::tests::the_repeat_budget_matches_the_clients_retransmit_schedule
const MAX_FLIGHT_REPEATS: u32 = 3;

/// How long a reply flight is retained before it is dropped unanswered (PROTOCOL § 6.1).
///
/// Derived from the client's own budget rather than picked: [`HANDSHAKE_RETRANSMIT_BUDGET`]
/// is the total time a client spends waiting for this reply before it abandons the connect,
/// so retaining for exactly that long is retaining for exactly as long as anyone can still
/// be asking. A shorter window would drop the answer while the question was still in flight;
/// a longer one would hold kilobytes for a peer that has already gone.
///
/// The coupling is checked by [`the_retention_window_matches_how_long_the_client_keeps_asking`],
/// against the client's schedule walked interval by interval rather than against the budget
/// constant this is defined as — which would assert nothing.
///
/// [`HANDSHAKE_RETRANSMIT_BUDGET`]: crate::api::udp_transport::HANDSHAKE_RETRANSMIT_BUDGET
/// [`the_retention_window_matches_how_long_the_client_keeps_asking`]: self::tests::the_retention_window_matches_how_long_the_client_keeps_asking
const HANDSHAKE_FLIGHT_RETENTION: Duration = crate::api::udp_transport::HANDSHAKE_RETRANSMIT_BUDGET;

/// How much memory a listener's retained reply flights may occupy at once (PROTOCOL § 6.1).
///
/// A count would be the obvious bound and it would be the wrong one, because what is being
/// bounded is bytes and a flight's size is a property of the crypto, not of this file: a
/// `ServerHello` is 6555 bytes of borsh in six datagrams, 6657 bytes on the wire once the
/// outer envelope is counted, and a future parameter set moves that without touching
/// anything here. Stated as bytes, the budget admits **8 MiB ÷ 6657 B ≈ 1260** of today's
/// flights and keeps meaning the same thing when that figure changes.
///
/// 8 MiB for a whole listener is what one session may raise its receive windows by
/// (`SESSION_RECV_WINDOW_GROWTH_BUDGET`), so the entire repair costs a server what a single
/// busy connection is already allowed to advertise. As always it is a floor on what the host
/// must have, not a ceiling on what the process will use — a listener also holds the
/// in-flight copy of each reply until its handshake finishes.
///
/// What the budget buys is *time*, and that is the honest way to read it. An entry is
/// released the moment its client sends anything authenticated, which on a healthy path is
/// one round trip, so the table holds the sessions established in roughly the last
/// `budget ÷ completion rate` seconds. A listener completing a thousand handshakes a second
/// covers about the last second — which is the client's first retransmit interval, the one
/// that matters most. Past that the oldest answers go first: see [`FlightTable::retain`] for
/// why that is the opposite of the earlier behaviour and not merely a different one.
const RETAINED_FLIGHT_BUDGET: usize = 8 * 1024 * 1024;

/// The most a repeat may send for what triggered it (RFC 9000 § 8.2).
///
/// Checked once, when the flight is retained, so every entry in the table satisfies it by
/// construction and the check costs nothing per repeat.
///
/// **Wire bytes on both sides**, which is the only reading under which the number means
/// anything: a reply's datagrams against the datagrams the hello arrived in. The receiving
/// side is handed a reassembled frame and never sees its datagrams, so the question's wire
/// size is computed with [`wire_len`] — exact for a sender that chunks as this implementation
/// does, and a lower bound for any other, which is the safe direction for a bound on what the
/// asker paid.
///
/// Today's ratio is **6657 out for 3350 in — 1.99×**, measured by
/// [`the_real_reply_is_well_inside_the_amplification_limit`] against the *smallest* hello
/// that can ever draw a repeat: the minimal `ClientHello` plus the cookie that `udp_admit`
/// makes unconditional over UDP. Every other optional field only enlarges the denominator, so
/// that is the worst case rather than a typical one. It is also the ratio the first exchange
/// already had, because a repeat is only ever owed to a peer that sent the whole hello again.
/// The bound is here for the case where that stops being true: a reply that grew, or a hello
/// that shrank, past the point where answering it twice would make this listener a useful
/// amplifier is refused retention instead.
///
/// [`wire_len`]: crate::transport::phantom_udp::datagram::wire_len
/// [`the_real_reply_is_well_inside_the_amplification_limit`]: self::tests::the_real_reply_is_well_inside_the_amplification_limit
const FLIGHT_AMPLIFICATION_LIMIT: usize = 3;

/// Max concurrent in-flight (un-established) handshakes one source IP may hold (H-2). Bounds
/// a single address-validated source from monopolising the `inflight` permits; sized below
/// `MAX_INFLIGHT_HANDSHAKES` so several distinct sources always share, yet generous for a
/// busy NAT.
const MAX_PENDING_PER_IP: u32 = 64;

/// One retained server reply flight, with the two things that end its life besides the
/// client hearing it: a repeat budget and a deadline.
struct RetainedFlight {
    flight: HandshakeFlight,
    repeats_left: u32,
    expires_at: Instant,
}

/// The listener's retained reply flights, keyed on the bootstrap connection id a repeated
/// hello arrives under (PROTOCOL § 6.1).
///
/// Everything here is about what an entry costs and how it ends. An entry is several
/// kilobytes committed on behalf of a peer that has passed the cookie round but has not yet
/// proved it received anything, so it is bounded three ways — by [`RETAINED_FLIGHT_BUDGET`],
/// by [`HANDSHAKE_FLIGHT_RETENTION`], and by the peer's own first authenticated packet — and
/// the three are independent: none of them can be held open by anything the peer does.
struct FlightTable {
    flights: HashMap<ConnId, RetainedFlight>,
    /// Wire bytes currently retained. Maintained rather than recomputed because the budget
    /// is consulted on every completed handshake and a sum over the table is not.
    retained_bytes: usize,
    /// Live gauge of `flights.len()`, mirrored to the listener so the demux's own reclaim
    /// can be observed from outside the task that owns the table.
    occupancy: Arc<AtomicUsize>,
    observability: Arc<Observability>,
}

impl FlightTable {
    fn new(occupancy: Arc<AtomicUsize>, observability: Arc<Observability>) -> Self {
        Self {
            flights: HashMap::new(),
            retained_bytes: 0,
            occupancy,
            observability,
        }
    }

    fn sync(&self) {
        self.occupancy.store(self.flights.len(), Ordering::Relaxed);
    }

    /// Drop one entry, giving its bytes back to the budget. The only way an entry leaves.
    fn forget(&mut self, cid: &ConnId) {
        if let Some(e) = self.flights.remove(cid) {
            self.retained_bytes = self.retained_bytes.saturating_sub(e.flight.wire_bytes);
        }
    }

    /// Retain `flight` under `cid`, or decline to.
    ///
    /// Declining happens for exactly one reason — the flight would make this listener an
    /// amplifier — and it is not a failure path: it costs what the server did before this
    /// mechanism existed, a lost reply being a lost connect for that one client. Returns
    /// whether the flight was kept, which is what the tests assert against.
    ///
    /// **A full table evicts, it does not refuse.** Refusing the newcomer was the first
    /// shape of this and it is a peer-reachable off-switch: once enough established-but-silent
    /// sessions occupy the budget, every session established after them has no repair, and
    /// the population that fills it is exactly the burst of concurrent connects the repair
    /// was built for. Evicting instead bounds the same memory while keeping the mechanism on,
    /// and the entry that goes is the oldest — every entry carries the same retention, so the
    /// oldest is both nearest its own deadline and the one whose client has had longest to
    /// give up, while the newcomer's client is by construction still connecting. An eviction
    /// is counted (`handshake_flight_evicted_total`), because an evicted session is back to
    /// the pre-repair behaviour and nothing else on either side of that connect would say so.
    ///
    /// Scoping the budget per source address was the other candidate and it is worse here, in
    /// both directions. It does not tighten the global bound — it multiplies it, since the
    /// ceiling becomes sources × per-source allowance — and there is no source to protect
    /// against: an entry exists only for a peer that echoed an IP-bound cookie and then
    /// completed a full post-quantum handshake, so the work of filling this table is already
    /// far above the work of holding it. What per-source keying would actually do is charge a
    /// busy NAT for its own clients, which is the population most likely to be on the lossy
    /// path this repair exists for.
    fn retain(&mut self, cid: ConnId, flight: HandshakeFlight, now: Instant) -> bool {
        // RFC 9000 § 8.2, checked once so no repeat has to. A flight larger than the limit
        // allows is refused rather than truncated: half a `ServerHello` is not an answer.
        if flight.wire_bytes
            > flight
                .question_wire_bytes
                .saturating_mul(FLIGHT_AMPLIFICATION_LIMIT)
        {
            return false;
        }
        // A second handshake under the same bootstrap id replaces the first; give the old
        // entry's bytes back before charging the new one, or the budget leaks by the
        // difference and the table shrinks for reasons no counter explains.
        self.forget(&cid);
        // Free what has genuinely ended before taking anything from a live entry.
        if self.retained_bytes + flight.wire_bytes > RETAINED_FLIGHT_BUDGET {
            self.sweep(now);
        }
        // A flight is at most `MAX_TOTAL_CHUNKS` datagrams (~253 KiB), far inside the budget,
        // so this empties the table only if the budget is ever set below one flight — and the
        // emptiness guard is what keeps that a single over-budget entry rather than a spin.
        while !self.flights.is_empty()
            && self.retained_bytes + flight.wire_bytes > RETAINED_FLIGHT_BUDGET
        {
            let Some(oldest) = self
                .flights
                .iter()
                .min_by_key(|(_, e)| e.expires_at)
                .map(|(k, _)| *k)
            else {
                break;
            };
            self.forget(&oldest);
            self.observability.record_handshake_flight_evicted();
        }
        self.retained_bytes += flight.wire_bytes;
        self.flights.insert(
            cid,
            RetainedFlight {
                flight,
                repeats_left: MAX_FLIGHT_REPEATS,
                expires_at: now + HANDSHAKE_FLIGHT_RETENTION,
            },
        );
        self.sync();
        true
    }

    /// The flight owed in answer to `question`, if one is: the datagrams to repeat and the
    /// only address they may go to.
    ///
    /// `question` is the reassembled inbound frame. It is answered only when it is the same
    /// frame the retained reply was computed over, which is both the security gate and a
    /// correctness requirement — the reply's signature covers the whole hello, so it is not a
    /// valid answer to any other one. An unrecognised frame leaves the entry exactly as it
    /// was, budget included, so a third party cannot spend the repair on noise.
    fn repeat(
        &mut self,
        cid: &ConnId,
        question: &[u8],
        now: Instant,
    ) -> Option<(Arc<Vec<Vec<u8>>>, SocketAddr)> {
        let entry = self.flights.get_mut(cid)?;
        // The client has demonstrably heard us, or has run out of time to ask. Either way the
        // bytes are dead weight and the reclaim happens here rather than waiting for a sweep.
        if entry.flight.delivered.load(Ordering::Relaxed) || now >= entry.expires_at {
            self.forget(cid);
            self.sync();
            return None;
        }
        let mut hasher = Sha256::new();
        hasher.update(question);
        let asked: [u8; 32] = hasher.finalize().into();
        // Constant-time, though neither side of this comparison is a secret: it is a digest
        // of a message that crossed the wire in clear. It costs nothing here and it keeps the
        // rule — comparisons on inbound material are constant-time — from needing an
        // exception that a later reader has to re-derive.
        if !bool::from(asked.ct_eq(&entry.flight.question)) {
            return None;
        }
        let datagrams = entry.flight.datagrams.clone();
        let peer = entry.flight.peer;
        entry.repeats_left -= 1;
        if entry.repeats_left == 0 {
            self.forget(cid);
        }
        self.sync();
        // Counted here rather than where the repeated hello arrived, so the artifact
        // separates "the listener answered" from "the listener had nothing to answer with".
        self.observability.record_handshake_flight_repeated();
        Some((datagrams, peer))
    }

    /// Drop every entry whose client has been heard from or whose window has closed.
    ///
    /// Runs on the demux's own clock, because both of those things happen without any
    /// datagram arriving for the entry in question — a client that hears the reply sends its
    /// next packet under a rotated connection id, and one that gives up sends nothing at all.
    fn sweep(&mut self, now: Instant) {
        let mut kept = 0usize;
        self.flights.retain(|_, e| {
            let keep = !e.flight.delivered.load(Ordering::Relaxed) && now < e.expires_at;
            if keep {
                kept += e.flight.wire_bytes;
            }
            keep
        });
        self.retained_bytes = kept;
        self.sync();
    }
}

/// Per-source-IP in-flight handshake counter (H-2 defense-in-depth). Bounds how many
/// concurrent un-established handshakes a single source IP can hold once it has cleared the
/// cookie address-validation gate, so one (address-validated) source cannot monopolise the
/// `inflight` permits — most relevant under load, where a post-cookie PoW round leaves a
/// validated source's slots pending. Entries are removed at zero, so the map is bounded by
/// the live in-flight count (itself <= the inflight permit ceiling).
struct PendingByIp {
    counts: HashMap<IpAddr, u32>,
}

impl PendingByIp {
    fn new() -> Self {
        Self {
            counts: HashMap::new(),
        }
    }

    fn count(&self, ip: IpAddr) -> u32 {
        self.counts.get(&ip).copied().unwrap_or(0)
    }

    fn admit(&mut self, ip: IpAddr) {
        *self.counts.entry(ip).or_insert(0) += 1;
    }

    fn release(&mut self, ip: IpAddr) {
        if let Some(c) = self.counts.get_mut(&ip) {
            *c -= 1;
            if *c == 0 {
                self.counts.remove(&ip);
            }
        }
    }
}

/// Central demux: own the socket, route each datagram by its connection-ID.
async fn run_udp_demux(listener: Arc<PhantomUdpListener>) {
    // Bounded, self-reaping route table (H-1). Dead routes (failed handshakes / dropped
    // sessions) are reclaimed promptly via `reap_rx`, on the end-of-session retire signal,
    // on the `% 256` cadence, and on this task's own `ROUTE_SWEEP_INTERVAL` timer — the last
    // being the only one that still fires when the peers have all gone — with the hard
    // `MAX_ROUTES` cap as a backstop, so a fresh-CID spray cannot grow it unboundedly.
    let mut routes = RouteTable::new(listener.active_routes.clone());
    // PROTOCOL § 6.1: the reply flights this listener can still repeat. Bounded by count, by
    // time, and by each client's own first authenticated packet — see [`FlightTable`].
    let mut flights = FlightTable::new(
        listener.retained_flights.clone(),
        listener.observability.clone(),
    );
    // Per-source-IP in-flight handshake counter (H-2). Incremented when a slot is committed
    // to an address-validated source, decremented when that handshake task finishes.
    let mut pending = PendingByIp::new();
    // Each handshake task signals its `(CID, source IP)` here when it finishes; the demux then
    // releases the per-IP pending count and reaps the route iff it is dead (a live established
    // session keeps its inbound channel open, so its route survives the signal untouched).
    let (reap_tx, mut reap_rx) = mpsc::unbounded_channel::<(ConnId, IpAddr)>();
    // ε / WIRE v5: a handshake task that established a session signals its inbound
    // CID window here (its per-direction rotating chain). The demux registers
    // every window CID → the session's channel so the client's post-handshake
    // CID_0.. datagrams route to it (N:1). Same fire-and-forget pattern as the
    // reap channel above.
    let (register_tx, mut register_rx) = mpsc::unbounded_channel::<SessionRegistration>();
    // ε / WIRE v5: a session whose peer migrated signals a one-step inbound
    // CID-window slide here (post-AEAD, from handle_packet via the session's
    // slide channel). The demux registers the new leading-edge CID and drops the
    // trailing one, keeping the window tracking the peer's outbound index.
    let (slide_tx, mut slide_rx) = mpsc::unbounded_channel::<CidSlide>();
    // WIRE v8: a session that has ended signals it here so its whole route set goes at
    // once. Bounded, unlike the slide channel above, because when a session ends is a
    // decision its peer makes and this queue is drained ahead of the socket.
    let (retire_tx, mut retire_rx) = mpsc::channel::<DemuxRouteOwner>(RETIRE_QUEUE_DEPTH);
    // Identity assigned to each accepted session's routes. Monotonic and never on the
    // wire, so it names a session in the route table without a peer being able to.
    let mut next_route_owner: u64 = 0;
    // NOTE (Phase 1): one assembler shared across ALL CIDs. Its key includes the cid, but a fragment
    // spray shares the single 256-slot assembly table with every live session's in-flight
    // reassemblies. Bounded — the assembler self-caps at MAX_CONCURRENT_ASSEMBLIES with
    // stalest-eviction, so no memory blowup — but a cross-connection isolation weakness the
    // per-socket client side does not have. A per-CID / per-route assembler is the Phase-2 fix.
    let mut asm = FragmentAssembler::new();
    let mut new_conn_count: u64 = 0;
    let mut buf = vec![0u8; crate::transport::phantom_udp::envelope::PATH_MTU + 64];
    // WIRE v8: the demux's own reclaim clock. Every other trigger on the route table
    // is reactive to traffic, and the case this table has to survive is precisely the
    // one where there is none — see `ROUTE_SWEEP_INTERVAL`. `Delay` rather than the
    // default burst behaviour: a demux that was busy for several intervals owes one
    // sweep, not one per interval it missed, and running them back to back would put
    // the catch-up in front of the socket at the moment the socket is busiest.
    let mut route_sweep = tokio::time::interval(ROUTE_SWEEP_INTERVAL);
    route_sweep.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        if listener.shutting_down.load(Ordering::Acquire) {
            break;
        }
        let shutdown_fut = listener.shutdown_notify.notified();
        tokio::pin!(shutdown_fut);
        let (n, peer) = tokio::select! {
            biased;
            _ = &mut shutdown_fut => break,
            // Reap dead routes (and release the per-IP pending count) before reading more
            // datagrams so neither table can grow faster than finished handshakes are reclaimed.
            Some((cid, ip)) = reap_rx.recv() => {
                pending.release(ip);
                routes.remove_if_dead(&cid);
                continue;
            }
            // ε / WIRE v5: register a newly-established session's rotating-CID
            // window so its client's CID_0.. datagrams route to it. Processed
            // before reading more datagrams (biased select) so the window is in
            // place by the time the client's first CID_0 frame could arrive.
            Some(reg) = register_rx.recv() => {
                routes.register_window(&reg.cids, &reg.tx, reg.owner);
                // PROTOCOL § 6.1: and retain this session's reply, so a client whose copy
                // was lost gets the same bytes back when it asks again. Same arm as the
                // window for the same reason — both must be in place before the next
                // datagram for this connection is read.
                if let Some(flight) = reg.flight {
                    flights.retain(reg.bootstrap_cid, flight, Instant::now());
                }
                continue;
            }
            // ε / WIRE v5: slide a session's inbound CID window as its peer
            // migrates (add the new leading CID, drop the trailing one). Processed
            // ahead of reading more datagrams (biased select) so the window is in
            // place before the next frame could arrive on it.
            Some(slide) = slide_rx.recv() => {
                routes.apply_slide(&slide);
                continue;
            }
            // WIRE v8: an ended session's whole route set goes at once. Also ahead of
            // the socket, so a departed peer's routes are gone before the table is
            // consulted again — which is affordable precisely because each one costs
            // that session's own window and not a pass over the table.
            Some(owner) = retire_rx.recv() => {
                routes.retire_session(owner);
                continue;
            }
            // WIRE v8: the backstop that makes the bound on the queue above a
            // deferral. A retire signal dropped at that bound leaves the session's
            // routes behind, and every other way this table sheds an entry needs a
            // datagram that a departed peer is by definition not going to send — so
            // this is the one reclaim whose clock the peer does not hold, and without
            // it a queue bound added to stop a stall would have installed a leak.
            _ = route_sweep.tick() => {
                routes.reap_dead();
                // PROTOCOL § 6.1: the same argument, for the same reason. A retained flight
                // ends when its client is heard from or when its window closes, and neither
                // of those arrives as a datagram on that connection — the client that heard
                // us moves to a rotated CID, and the one that gave up sends nothing.
                flights.sweep(Instant::now());
                continue;
            }
            r = listener.socket.recv_from(&mut buf) => match r {
                Ok(v) => v,
                Err(e) => { log::warn!("PhantomUdpListener: recv_from: {e}"); continue; }
            },
        };
        let (hdr, assembled) = match push_datagram(&mut asm, &buf[..n]) {
            Ok(v) => v,
            Err(_) => continue, // malformed; drop (anti-DoS noise floor)
        };
        // A handshake-type datagram arriving on a route that is already committed is a client
        // repeating its flight — the thing this demux used to swallow. Counting it is the
        // observability an investigation into lost connects could not get: it is what
        // separates "one reply flight went missing downstream" from "the path fell silent
        // both ways", and no artifact on either side could tell those apart. Unlabeled and
        // per-listener, never per peer (the cardinality contract in `observability/attrs.rs`).
        //
        // Counted per datagram and before reassembly completes, because a flight that arrives
        // in pieces is still a flight that arrived; and only for `Initial`, so the data path
        // pays one comparison rather than a second hash lookup.
        let on_committed_route = hdr.ty == PacketType::Initial && routes.get(&hdr.cid).is_some();
        if on_committed_route {
            listener.observability.record_initial_on_committed_route();
        }
        let Some(frame) = assembled else {
            continue; // partial fragment buffered
        };
        // PROTOCOL § 6.1: if this is the same question the retained reply answers, send that
        // reply again, byte for byte, to the address it went to the first time. Ahead of
        // route delivery because the session's pump does not parse handshake messages and
        // would drop it — which is precisely how a single lost reply used to cost a connect.
        if on_committed_route {
            if let Some((datagrams, dst)) = flights.repeat(&hdr.cid, &frame, Instant::now()) {
                send_flight_repeat(&listener.socket, &datagrams, dst).await;
                continue;
            }
        }
        // Existing connection: deliver the inner frame.
        let Some(frame) = routes.deliver(&hdr.cid, frame, peer) else {
            continue;
        };
        // New connection: only an Initial (handshake) starts one.
        if hdr.ty != PacketType::Initial {
            continue; // unknown OneRtt/Retry -> drop
        }
        // M-7: structurally bound the ClientHello's variable fields BEFORE borsh, so a forged
        // length prefix can't force borsh's `vec![0u8; len.min(1 MiB)]` eager allocate+memset
        // on the demux thread (a ~45-byte → 1 MiB amplifier). Also bounds the frame size.
        if !client_hello_lengths_within_bounds(&frame) {
            continue;
        }
        // H-2: on the connectionless UDP path the source is unverified. Run the stateless
        // cookie/address-validation round on the demux thread BEFORE committing any
        // per-connection slot — a spoofed source never echoes the cookie, so it can never
        // pin a permit/route/task and lock out legitimate connects (QUIC Retry shape).
        let client_hello = match borsh::from_slice::<ClientHello>(&frame) {
            Ok(ch) => ch,
            Err(_) => continue, // malformed Initial; drop (anti-DoS noise floor)
        };
        match listener
            .handshake_server
            .udp_admit(&client_hello, peer.ip())
        {
            UdpAdmit::Admit => {} // address-validated; allocate a slot below
            UdpAdmit::Retry(hrr) => {
                send_demux_retry(&listener.socket, &hdr.cid, peer, &hrr).await;
                continue;
            }
            UdpAdmit::Drop => continue,
        }
        // H-2: bound concurrent in-flight handshakes per source IP so one (address-validated)
        // source cannot monopolise the inflight permits — most relevant under load, where a
        // post-cookie PoW round keeps a validated source's slots pending.
        if pending.count(peer.ip()) >= MAX_PENDING_PER_IP {
            continue;
        }
        let permit = match listener.inflight.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => continue, // at capacity -> drop new handshakes (DoS bound)
        };
        let (tx, rx) = mpsc::channel(SESSION_CHANNEL_DEPTH);
        // The transport gets a `tx` clone too (alongside the demux's route-table clone): a
        // server migration spawns a recv loop on the new socket that feeds this same channel,
        // so c2s frames arriving on the migrated address reach `recv_bytes` transparently.
        let st = UdpServerTransport::new(listener.socket.clone(), peer, hdr.cid, tx.clone(), rx);
        next_route_owner = next_route_owner.wrapping_add(1);
        let owner = DemuxRouteOwner(next_route_owner);
        // H-1: refuse the route (and the slot) when the table is full of *live* routes.
        if !routes.try_insert(hdr.cid, tx.clone(), owner) {
            drop(permit);
            drop(st);
            continue;
        }
        pending.admit(peer.ip());
        let _ = tx.try_send((Bytes::from(frame), peer));
        spawn_handshake_task(
            listener.clone(),
            st,
            peer,
            hdr.cid,
            permit,
            reap_tx.clone(),
            tx,
            register_tx.clone(),
            DemuxLink {
                slide_tx: slide_tx.clone(),
                retire_tx: retire_tx.clone(),
                owner,
            },
        );
        // DoS-hardening parity with the TCP acceptor: periodically drop expired reputation
        // entries AND reap dead routes so both bounded maps stay small under churn.
        new_conn_count = new_conn_count.wrapping_add(1);
        if new_conn_count.is_multiple_of(256) {
            listener.handshake_server.gc_reputation();
            routes.reap_dead();
        }
    }
}

/// Repeat a retained reply flight to `dst` (PROTOCOL § 6.1).
///
/// The datagrams are sent exactly as they were built the first time — same fragment ids,
/// same chunk indices, same bytes — because that is what makes this a repeat rather than a
/// second answer. Re-deriving the reply would draw fresh KEM randomness and a fresh session
/// id, producing a valid `ServerHello` for a session this server never committed.
///
/// `dst` comes from the retained flight, never from the datagram that triggered the repeat,
/// which is what keeps this off the list of things that can be pointed at a third party.
/// Best-effort: a socket error is dropped, and the client's next repetition asks again.
async fn send_flight_repeat(socket: &UdpSocket, datagrams: &[Vec<u8>], dst: SocketAddr) {
    for d in datagrams {
        let _ = socket.send_to(d, dst).await;
    }
}

/// Send a stateless `HelloRetryRequest` (a cookie demand) to `peer` for `cid` without
/// committing any per-connection state (H-2). Handshake messages ride the `Initial`
/// (long-header) envelope, exactly as the per-connection task's Retry does; an HRR is small,
/// so this is a single datagram. Best-effort — a borsh/socket error is dropped.
async fn send_demux_retry(
    socket: &UdpSocket,
    cid: &ConnId,
    peer: SocketAddr,
    hrr: &HelloRetryRequest,
) {
    // T4.4: frame with the explicit discriminant byte (`[kind] ‖ borsh`), same as the
    // per-connection `drive_server_handshake` retry — the client dispatches on it.
    let bytes = match ServerReply::Retry(hrr.clone()).to_wire() {
        Ok(b) => b,
        Err(_) => return,
    };
    if let Ok(dgrams) = encode_datagrams(PacketType::Initial, cid, 0, &bytes) {
        for d in &dgrams {
            let _ = socket.send_to(d, peer).await;
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn spawn_handshake_task(
    listener: Arc<PhantomUdpListener>,
    transport: UdpServerTransport,
    peer: SocketAddr,
    cid: ConnId,
    permit: tokio::sync::OwnedSemaphorePermit,
    reap_tx: mpsc::UnboundedSender<(ConnId, IpAddr)>,
    // ε / WIRE v5: the session's inbound channel (the demux holds a sibling
    // clone for the bootstrap route); on success the task hands it to the demux
    // paired with the rotating-CID window so those CIDs route to this session.
    tx: mpsc::Sender<(Bytes, SocketAddr)>,
    register_tx: mpsc::UnboundedSender<SessionRegistration>,
    // Handed to the established session so it can signal inbound-window slides as the
    // peer migrates (ε / WIRE v5) and release its routes when it ends (WIRE v8).
    // Carries the identity this listener assigned those routes.
    demux_link: DemuxLink,
) {
    let hs = listener.handshake_server.clone();
    let runtime = listener.runtime.clone();
    let observability = listener.observability.clone();
    let accepted_tx = listener.accepted_tx.clone();
    let liveness = listener.liveness;
    let task_runtime = runtime.clone();
    runtime.spawn(Box::pin(async move {
        let _permit = permit;
        let started = Instant::now();
        let result = {
            let fut = drive_server_handshake(&transport, &hs, peer.ip());
            let deadline = task_runtime.sleep(HANDSHAKE_DEADLINE);
            tokio::pin!(fut);
            tokio::select! {
                r = &mut fut => r,
                _ = deadline => Err(CoreError::Timeout),
            }
        };
        match result {
            Ok((server_session, early_data)) => {
                observability.record_handshake(
                    started.elapsed(),
                    HandshakeOutcome::Success,
                    LegType::Udp,
                    AeadAlgorithm::Aes256Gcm,
                    ProtocolVersion::Current,
                );
                // ε / WIRE v5: register this session's inbound CID window so the
                // client's post-handshake rotating CID_0.. datagrams route to it
                // (sent BEFORE moving `server_session` into the API session). The
                // bootstrap CID stays until the route is reaped on disconnect.
                //
                // PROTOCOL § 6.1: the reply this handshake sent rides along, so the demux can
                // repeat it if the client's copy was lost. Taken from the transport here, on
                // the success arm only — a handshake that failed sent no answer worth
                // repeating, and one that is still running is still reading its own channel.
                let _ = register_tx.send(SessionRegistration {
                    cids: server_session.inbound_window_cids(),
                    tx,
                    owner: demux_link.owner,
                    bootstrap_cid: cid,
                    flight: transport.take_handshake_flight(),
                });
                // ε / WIRE v5 + WIRE v8: give the session its end of the demux
                // so it can advance its inbound CID window as the peer migrates, and
                // release its routes when it ends.
                server_session.set_demux_link(demux_link);
                let arc_session = Arc::new(server_session);
                if let Some(live) = liveness {
                    arc_session.set_liveness_config(live);
                }
                let session = PhantomSession::from_accepted_server_session_with_runtime(
                    peer.to_string(),
                    transport,
                    arc_session,
                    task_runtime.clone(),
                    observability.clone(),
                    LegType::Udp,
                );
                let outcome = AcceptOutcome::new(session, early_data, peer);
                let _ = accepted_tx.send(outcome).await;
                // Success: the live session now owns the inbound channel, so the demux
                // keeps this route — the reap signal below is a no-op (route not dead).
            }
            Err(e) => {
                observability.record_handshake(
                    started.elapsed(),
                    HandshakeOutcome::Failure,
                    LegType::Udp,
                    AeadAlgorithm::Aes256Gcm,
                    ProtocolVersion::Current,
                );
                // H-1: drop the transport (and its inbound channel) before signalling, so
                // the demux observes this route as dead and reclaims it promptly.
                drop(transport);
                log::debug!("PhantomUdpListener: handshake failed: {e}");
            }
        }
        // Signal the demux to release this source's pending count and reap this CID. The
        // route is removed only if it is dead, so this is safe on both the success (live,
        // kept) and failure (dead, reclaimed) paths.
        let _ = reap_tx.send((cid, peer.ip()));
    }));
}

// ─── UdpListenerBuilder ─────────────────────────────────────────────────────

/// Builder for [`PhantomUdpListener`].
///
/// Created via [`PhantomUdpListener::builder`]. Collects configuration, then
/// `.bind().await` stands up the listener.
pub struct UdpListenerBuilder {
    addr: String,
    signing_key: Option<HybridSigningKey>,
    config: Option<crate::config::PhantomConfig>,
    runtime: Option<Arc<dyn Runtime>>,
}

impl UdpListenerBuilder {
    /// Use a long-lived [`HybridSigningKey`] so the server's verifying identity
    /// persists across restarts.
    pub fn signing_key(mut self, key: HybridSigningKey) -> Self {
        self.signing_key = Some(key);
        self
    }

    /// Apply a [`PhantomConfig`](crate::config::PhantomConfig) (liveness, session-cache).
    pub fn config(mut self, config: crate::config::PhantomConfig) -> Self {
        self.config = Some(config);
        self
    }

    /// Use a custom [`Runtime`] instead of the default [`TokioRuntime`].
    pub fn runtime(mut self, runtime: Arc<dyn Runtime>) -> Self {
        self.runtime = Some(runtime);
        self
    }

    /// Bind the listener and return it.
    pub async fn bind(self) -> Result<Arc<PhantomUdpListener>, CoreError> {
        let runtime = self
            .runtime
            .unwrap_or_else(|| Arc::new(TokioRuntime) as Arc<dyn Runtime>);
        PhantomUdpListener::bind_inner(self.addr, runtime, self.signing_key, self.config).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A live inbound channel for a demux route. The receiver is returned so the caller
    /// can keep it alive: a route's liveness *is* its channel's, so dropping it would
    /// silently make the route reclaimable and change what every assertion below means.
    #[allow(clippy::type_complexity)]
    fn live_route() -> (
        mpsc::Sender<(Bytes, SocketAddr)>,
        mpsc::Receiver<(Bytes, SocketAddr)>,
    ) {
        mpsc::channel(4)
    }

    fn cid(n: u8) -> ConnId {
        [n; crate::crypto::cid_chain::CID_LEN]
    }

    fn empty_table() -> RouteTable {
        RouteTable::new(Arc::new(AtomicUsize::new(0)))
    }

    /// A retention table with its own gauge and metrics sink, so a unit test sees exactly
    /// the counters its own operations produced.
    fn flight_table() -> FlightTable {
        FlightTable::new(
            Arc::new(AtomicUsize::new(0)),
            Observability::new(ObservabilityConfig::default()),
        )
    }

    /// A retained reply flight standing in for a real `ServerHello`: an answer of `answer`'s
    /// datagrams to a `question`-byte hello, both measured in wire bytes exactly as the
    /// production path measures them, so a test that trips the amplification bound trips the
    /// one production enforces.
    fn test_flight(question: &[u8], answer: Vec<Vec<u8>>) -> HandshakeFlight {
        let mut hasher = Sha256::new();
        hasher.update(question);
        let digest: [u8; 32] = hasher.finalize().into();
        let wire_bytes = answer.iter().map(Vec::len).sum();
        HandshakeFlight {
            datagrams: Arc::new(answer),
            peer: "203.0.113.7:41000".parse().expect("a peer address"),
            question: digest,
            wire_bytes,
            question_wire_bytes: crate::transport::phantom_udp::datagram::wire_len(question.len()),
            delivered: Arc::new(AtomicBool::new(false)),
        }
    }

    /// The server repeats its reply exactly as many times as the client repeats its
    /// question, and that is a coupling rather than a coincidence.
    ///
    /// The two constants live in different files: the client's retransmission schedule is in
    /// the transport, the server's repeat budget is in the listener, and neither can see the
    /// other. A budget below the client's count leaves its last questions unanswered on
    /// exactly the paths the repair exists for; a budget above it offers work nobody will
    /// ask for, and every repeat is something an on-path attacker can trigger by replaying a
    /// captured hello. So the count is walked out of the schedule itself and compared, and a
    /// later edit to either side turns this red rather than showing up as a connect that
    /// fails only when a datagram goes missing.
    #[test]
    fn the_repeat_budget_matches_the_clients_retransmit_schedule() {
        let client_repeats = crate::api::udp_transport::handshake_retransmit_count();
        assert_eq!(
            MAX_FLIGHT_REPEATS, client_repeats,
            "the server answers {MAX_FLIGHT_REPEATS} repeats while the client sends \
             {client_repeats}; the two must be the same number, derived from the client's \
             schedule and not restated"
        );
    }

    /// The server retains its answer for exactly as long as the client keeps asking, and
    /// that is a coupling rather than a coincidence.
    ///
    /// The sibling of the test above, for the other end of the same window. The client's
    /// retransmission schedule is in the transport and the server's retention deadline is in
    /// the listener, neither can see the other, and the failure from a disagreement is
    /// invisible on a clean path: retain for too little and the answer is dropped while the
    /// question is still in flight, retain for too long and the listener holds kilobytes for
    /// a peer that abandoned the connect. So the window is walked out of the client's own
    /// schedule — the total time it waits before giving up — and compared. Asserting against
    /// `HANDSHAKE_RETRANSMIT_BUDGET` instead would be no assertion at all, since the
    /// listener's constant is defined as that budget; what makes this a test is that the walk
    /// is over the intervals a client actually spends, so a schedule that stopped landing on
    /// its own ceiling turns this red rather than moving the give-up point in silence.
    #[test]
    fn the_retention_window_matches_how_long_the_client_keeps_asking() {
        let client_gives_up_after = crate::api::udp_transport::handshake_retransmit_total_wait();
        assert_eq!(
            HANDSHAKE_FLIGHT_RETENTION, client_gives_up_after,
            "the listener holds a reply for {HANDSHAKE_FLIGHT_RETENTION:?} while the client \
             asks for {client_gives_up_after:?}; the two must be the same duration, derived \
             from the client's schedule and not restated"
        );
    }

    /// A repeat is owed to the question the reply was computed for, and to no other.
    ///
    /// This is the security gate and a correctness requirement at once. The reply's signature
    /// covers the whole `ClientHello` (Invariant 7), so the retained bytes are a valid answer
    /// to that hello and would be rejected by the client's own transcript check if sent in
    /// answer to a different one. And requiring the exact frame means a peer that wants a
    /// repeat has to possess the hello that produced it — which it can only have by being the
    /// client, or by being on the path and having captured it. Neither of those is a source
    /// an unrepeated reply would have protected against.
    ///
    /// Deleting the comparison — repeating for any handshake datagram that lands on a
    /// committed route — is the naive version of this mechanism, and it is what the second
    /// half fails against.
    #[test]
    fn a_repeat_answers_only_the_question_its_reply_was_computed_for() {
        let now = Instant::now();
        let mut table = flight_table();
        let question = vec![0xA5u8; 3000];
        let answer = vec![vec![0x11u8; 1200], vec![0x22u8; 1200]];
        assert!(table.retain(cid(1), test_flight(&question, answer.clone()), now));

        let (repeated, dst) = table
            .repeat(&cid(1), &question, now)
            .expect("the same question is answered");
        assert_eq!(
            *repeated, answer,
            "a repeat must be the bytes that were already sent — re-deriving the reply would \
             draw fresh KEM randomness and a fresh session id, producing a valid ServerHello \
             for a session this server never committed"
        );
        assert_eq!(
            dst,
            "203.0.113.7:41000".parse::<SocketAddr>().expect("addr"),
            "a repeat goes to the address the original went to, which is why it cannot be \
             pointed at a third party: the destination comes from the server's own record of \
             a completed handshake and never from the datagram that triggered it"
        );

        let mut altered = question.clone();
        altered[0] ^= 0x01;
        assert!(
            table.repeat(&cid(1), &altered, now).is_none(),
            "a hello that differs by one byte is a different question; answering it with \
             this reply would send a signature the client is obliged to reject"
        );
        assert!(
            table.repeat(&cid(1), b"not a hello at all", now).is_none(),
            "and arbitrary bytes on the connection draw nothing"
        );
        assert!(
            table.repeat(&cid(2), &question, now).is_none(),
            "nor does the right question on the wrong connection"
        );
    }

    /// An unrecognised frame must not spend the repair.
    ///
    /// The budget exists to bound what a replayed hello can cost; if a mismatched frame
    /// consumed it, anyone able to send datagrams at a guessed connection id could exhaust
    /// the repair with noise and leave the real client's question unanswered — turning a
    /// defence against amplification into a way to suppress the repair.
    #[test]
    fn a_question_that_does_not_match_leaves_the_budget_untouched() {
        let now = Instant::now();
        let mut table = flight_table();
        let question = vec![0x5Au8; 2000];
        assert!(table.retain(cid(3), test_flight(&question, vec![vec![0u8; 1000]]), now));

        for _ in 0..(MAX_FLIGHT_REPEATS * 10) {
            assert!(table.repeat(&cid(3), b"noise", now).is_none());
        }
        for n in 1..=MAX_FLIGHT_REPEATS {
            assert!(
                table.repeat(&cid(3), &question, now).is_some(),
                "repeat {n} of {MAX_FLIGHT_REPEATS} must survive the noise before it"
            );
        }
    }

    /// The repeat budget is spent, and then the flight is gone.
    ///
    /// Both halves matter and they are the same statement about a bound: the listener answers
    /// a fixed number of repeats, and having answered them it stops holding the kilobytes.
    /// A budget that was enforced but never released the entry would leave the memory bound
    /// resting on the deadline alone.
    #[test]
    fn the_repeat_budget_is_spent_and_the_flight_released() {
        let now = Instant::now();
        let mut table = flight_table();
        let question = vec![0x3Cu8; 2000];
        assert!(table.retain(cid(4), test_flight(&question, vec![vec![0u8; 1500]]), now));

        for n in 1..=MAX_FLIGHT_REPEATS {
            assert!(
                table.repeat(&cid(4), &question, now).is_some(),
                "repeat {n} is inside the budget of {MAX_FLIGHT_REPEATS}"
            );
        }
        assert!(
            table.repeat(&cid(4), &question, now).is_none(),
            "the {}th repeat is past the budget and must not be sent",
            MAX_FLIGHT_REPEATS + 1
        );
        assert!(
            table.flights.is_empty(),
            "a spent flight must be released, not merely refused: otherwise the memory bound \
             rests on the deadline alone"
        );
    }

    /// The client has been heard from, so the answer it was owed is dead weight.
    ///
    /// An inbound packet that AEAD-opens can only have been produced from the session keys
    /// the reply carried, so the latch is proof of receipt that nothing off-path can forge —
    /// which is why it is allowed to end the retention early. Both routes out are checked:
    /// the next repeat request, and the demux's own sweep, because a client that heard the
    /// reply sends its next datagram under a rotated connection id and so never touches this
    /// entry again.
    #[test]
    fn an_authenticated_inbound_packet_releases_the_retained_flight() {
        let now = Instant::now();
        let question = vec![0x77u8; 2000];

        let mut table = flight_table();
        let flight = test_flight(&question, vec![vec![0u8; 1500]]);
        let latch = flight.delivered.clone();
        assert!(table.retain(cid(5), flight, now));
        latch.store(true, Ordering::Relaxed);
        assert!(
            table.repeat(&cid(5), &question, now).is_none(),
            "a client that has proved it received the reply is not owed another copy"
        );
        assert!(table.flights.is_empty(), "and the bytes go with the answer");

        let mut table = flight_table();
        let flight = test_flight(&question, vec![vec![0u8; 1500]]);
        let latch = flight.delivered.clone();
        assert!(table.retain(cid(6), flight, now));
        latch.store(true, Ordering::Relaxed);
        table.sweep(now);
        assert!(
            table.flights.is_empty(),
            "the sweep must reclaim it too — the client that heard us moves to a rotated \
             connection id, so nothing will ever arrive on this entry to reclaim it lazily"
        );
    }

    /// A retained flight outlives the client's last question by nothing.
    ///
    /// The window is the client's own retransmission budget, so at its far end there is by
    /// construction nobody left to answer. Both the repeat path and the sweep enforce it,
    /// because a peer that has gone produces neither.
    #[test]
    fn a_retained_flight_expires_on_its_own_deadline() {
        let now = Instant::now();
        let question = vec![0x11u8; 2000];
        let mut table = flight_table();
        assert!(table.retain(cid(7), test_flight(&question, vec![vec![0u8; 1500]]), now));

        let just_inside = now + HANDSHAKE_FLIGHT_RETENTION - Duration::from_millis(1);
        assert!(
            table.repeat(&cid(7), &question, just_inside).is_some(),
            "a question that arrives inside the window is still answered"
        );

        let past = now + HANDSHAKE_FLIGHT_RETENTION;
        assert!(
            table.repeat(&cid(7), &question, past).is_none(),
            "past the window the client has already abandoned the connect; an answer sent \
             then is pure waste"
        );
        assert!(table.flights.is_empty());

        let mut table = flight_table();
        assert!(table.retain(cid(8), test_flight(&question, vec![vec![0u8; 1500]]), now));
        table.sweep(past);
        assert!(
            table.flights.is_empty(),
            "and the sweep expires it with no datagram of any kind arriving"
        );
    }

    /// A full retention table evicts its oldest answer; it never stops answering.
    ///
    /// This is the whole difference between a bound and an off-switch. A retained flight is
    /// several kilobytes committed for a peer that has cleared the cookie round but has not
    /// yet proved it received anything, and how many such peers exist at once is not
    /// something this listener chooses — so the budget binds, and what it does when it binds
    /// decides whether the repair survives load. Refusing the newcomer, which is what this
    /// did first, means a population of established-but-silent sessions filling the budget
    /// turns the repair off for every session established after them, silently and globally,
    /// under exactly the burst of concurrent connects it exists for. Evicting the oldest
    /// bounds the same memory and keeps the mechanism on: the entry that goes is nearest its
    /// own deadline and belongs to the client that has had longest to give up, while the
    /// newcomer's client is by construction still connecting.
    ///
    /// The assertions are the halves of that, and each fails against a different wrong
    /// version: the budget is enforced (a table that never evicts is unbounded memory), the
    /// newcomer is kept (a table that refuses is the off-switch), and the eviction is counted
    /// (an operator whose repair has quietly stopped covering a session has nothing else to
    /// read).
    #[test]
    fn a_full_retention_table_evicts_its_oldest_answer_rather_than_refusing_the_newcomer() {
        let now = Instant::now();
        let mut table = flight_table();
        let question = vec![0x2Bu8; 4000];
        // About the size of a real reply flight, so what fills the budget here is what
        // fills it in production — without this test having to know today's exact figure.
        let flight_bytes = 8 * 1024;
        let fits = RETAINED_FLIGHT_BUDGET / flight_bytes;
        let answer = || vec![vec![0u8; flight_bytes]];

        // A millisecond apart, so "oldest" names one entry rather than a tie. Production
        // ties are possible and any of the tied entries is the right one to drop.
        for i in 0..fits {
            let key = (i as u64).to_be_bytes();
            assert!(
                table.retain(
                    key,
                    test_flight(&question, answer()),
                    now + Duration::from_millis(i as u64)
                ),
                "entry {i} is inside the budget of {RETAINED_FLIGHT_BUDGET} bytes"
            );
        }
        assert_eq!(table.flights.len(), fits);
        assert_eq!(
            table
                .observability
                .snapshot()
                .handshake_flight_evicted_total,
            0,
            "nothing has been displaced yet"
        );

        let later = now + Duration::from_millis(fits as u64);
        let newcomer = u64::MAX.to_be_bytes();
        assert!(
            table.retain(newcomer, test_flight(&question, answer()), later),
            "a full table must still take the newcomer: refusing it is a peer-reachable \
             off-switch, since the sessions that fill the budget are the ones that have gone \
             quiet and the one being refused is the one still connecting"
        );
        assert!(
            table.flights.contains_key(&newcomer),
            "and it must actually be retained, not merely accepted"
        );
        assert!(
            !table.flights.contains_key(&0u64.to_be_bytes()),
            "the entry that goes is the oldest — nearest its own deadline, and the client \
             that has had longest to give up"
        );
        assert_eq!(
            table.flights.len(),
            fits,
            "the budget still binds: an eviction makes room, it does not raise the ceiling"
        );
        assert_eq!(
            table
                .observability
                .snapshot()
                .handshake_flight_evicted_total,
            1,
            "an evicted session is back to losing a connect to one lost reply datagram, and \
             this counter is the only thing that says so"
        );
        assert_eq!(
            table.occupancy.load(Ordering::Relaxed),
            table.flights.len(),
            "the gauge must track the table, or the demux's own reclaim is unobservable"
        );
    }

    /// Retained bytes are given back, so the budget bounds what is held rather than how many
    /// sessions this listener may ever repair.
    ///
    /// Every way an entry can leave has to return its bytes: the sweep, a spent repeat
    /// budget, a client that has been heard from, and a second handshake replacing the first
    /// under the same bootstrap id. Miss any one of them and the accounting drifts upward
    /// until the table evicts on every insertion — which looks exactly like healthy
    /// operation, except that no session gets a repair and the eviction counter climbs with
    /// nothing to explain it.
    #[test]
    fn every_way_a_flight_ends_gives_its_bytes_back() {
        let now = Instant::now();
        let mut table = flight_table();
        let question = vec![0x4Du8; 4000];
        let answer = || vec![vec![0u8; 2000]];

        // Replaced by a second handshake on the same bootstrap id.
        assert!(table.retain(cid(1), test_flight(&question, answer()), now));
        assert!(table.retain(cid(1), test_flight(&question, answer()), now));
        assert_eq!(
            table.retained_bytes, 2000,
            "a replacement is one flight's worth of bytes, not two"
        );

        // Spent by its repeat budget.
        for _ in 0..MAX_FLIGHT_REPEATS {
            assert!(table.repeat(&cid(1), &question, now).is_some());
        }
        assert_eq!(
            table.retained_bytes, 0,
            "a spent flight gives its bytes back"
        );

        // Released by the client being heard from, through the sweep.
        let flight = test_flight(&question, answer());
        let latch = flight.delivered.clone();
        assert!(table.retain(cid(2), flight, now));
        latch.store(true, Ordering::Relaxed);
        table.sweep(now);
        assert_eq!(table.retained_bytes, 0, "so does one the sweep reclaims");

        // Released by its own deadline, on the repeat path.
        assert!(table.retain(cid(3), test_flight(&question, answer()), now));
        assert!(table
            .repeat(&cid(3), &question, now + HANDSHAKE_FLIGHT_RETENTION)
            .is_none());
        assert_eq!(table.retained_bytes, 0, "and so does an expired one");
        assert_eq!(table.occupancy.load(Ordering::Relaxed), 0);
    }

    /// A reply large enough to make this listener a useful amplifier is never retained, and
    /// the limit is a ratio of wire bytes to wire bytes.
    ///
    /// RFC 9000 § 8.2 in one line, checked once at retention so no repeat has to carry it.
    /// Today the real ratio is far inside the limit — a repeat is only ever owed to a peer
    /// that sent the whole hello again, so it is the same ratio the first exchange already
    /// had — and this is what keeps that true if the reply grows or the hello shrinks.
    ///
    /// Walked exactly to the boundary, in the same quantity production compares: the
    /// question's wire size, envelope included, is what the reply is allowed three of. A
    /// version that divided by the reassembled frame length instead would put the boundary
    /// nine bytes further out for an unfragmented hello and seventeen per fragment beyond
    /// that, which is a bound nobody stated and no test would have noticed.
    #[test]
    fn a_reply_that_would_amplify_is_never_retained() {
        use crate::transport::phantom_udp::datagram::wire_len;

        let now = Instant::now();
        let mut table = flight_table();
        let question = vec![0u8; 1000];
        let allowed = wire_len(question.len()) * FLIGHT_AMPLIFICATION_LIMIT;

        assert!(
            table.retain(
                cid(9),
                test_flight(&question, vec![vec![0u8; allowed]]),
                now
            ),
            "exactly {FLIGHT_AMPLIFICATION_LIMIT}× the {} wire bytes that triggered it is \
             inside the limit",
            wire_len(question.len())
        );

        assert!(
            !table.retain(
                cid(10),
                test_flight(&question, vec![vec![0u8; allowed + 1]]),
                now
            ),
            "one byte past it is refused: a listener that answers a small datagram with a \
             large one is a reflector, whoever asked"
        );
        assert!(!table.flights.contains_key(&cid(10)));
    }

    /// The reply this build sends is well inside the amplification limit, measured against
    /// the *smallest* hello that can ever draw one.
    ///
    /// The bound in `retain` is a runtime refusal, which means a reply that outgrew it would
    /// stop being retained and the repair would quietly stop working — green tests, connects
    /// failing on lossy paths exactly as before. So the real messages are measured here.
    ///
    /// Which hello is the right denominator is the whole of it, and the answer is the
    /// smallest one that can reach a retained reply, because the ratio is worst there. Over
    /// UDP that is not the minimal `ClientHello`: `udp_admit` is unconditional, so every
    /// hello that leads to a committed session carries a cookie, and every *other* optional
    /// field only makes the hello larger. A PoW solution, a resumption id and binder, an
    /// early-data blob — the frozen `client_hello_full` vector carries all four, and using it
    /// would flatter the ratio by a few hundred bytes of denominator that a real client
    /// need not send. The minimal vector with a cookie added back is the honest floor.
    ///
    /// Both sides are wire bytes, which is what an amplification bound is about and what the
    /// production check now compares: `wire_len` counts the envelope and fragment sub-headers
    /// that the reassembled frame no longer shows.
    ///
    /// Default build only, for the reason `core/tests/wire_vectors.rs` carries the same gate:
    /// the frozen vectors are default-build bytes, and `HybridKeyPackage.classical_pk` is a
    /// 32-byte X25519 key there against a 65-byte P-256 one under `fips`, so decoding one in
    /// the other build is not a smaller measurement — it is a different message. The fips
    /// build's own ratio is a separate figure and would need its own frozen pair.
    #[cfg(not(feature = "fips"))]
    #[test]
    fn the_real_reply_is_well_inside_the_amplification_limit() {
        use crate::transport::handshake::ClientHello;
        use crate::transport::phantom_udp::datagram::wire_len;

        let minimal = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/wire_vectors/client_hello_minimal.bin"
        ))
        .expect("the frozen minimal ClientHello vector");
        let mut hello: ClientHello =
            borsh::from_slice(&minimal).expect("the frozen vector decodes as a ClientHello");
        // The one field a committed session's hello must carry, and the only one.
        hello.cookie = Some([0x5Au8; 32]);
        let question = borsh::to_vec(&hello).expect("re-encode the cookie-bearing hello");

        let reply = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/wire_vectors/server_hello.bin"
        ))
        .expect("the frozen ServerHello vector");
        // The reply carries the discriminant byte of `ServerReply` ahead of the borsh body.
        let answer_frame_len = reply.len() + 1;

        let question_wire = wire_len(question.len());
        let answer_wire = wire_len(answer_frame_len);

        assert!(
            answer_wire <= question_wire * FLIGHT_AMPLIFICATION_LIMIT,
            "the reply this build sends ({answer_wire} wire bytes) must stay inside \
             {FLIGHT_AMPLIFICATION_LIMIT}× the smallest hello that can trigger it \
             ({question_wire} wire bytes), or it stops being retained and the repair silently \
             stops working"
        );

        // The figures the constant's documentation states, so a change in either message
        // turns the published ratio red rather than leaving it a recollection.
        assert_eq!(
            (question_wire, answer_wire),
            (3350, 6657),
            "the published amplification arithmetic is {answer_wire}/{question_wire} = {:.2}×, \
             not the 6657/3350 = 1.99× documented on FLIGHT_AMPLIFICATION_LIMIT",
            answer_wire as f64 / question_wire as f64
        );
    }

    /// A UDP relay between a client and `server_addr` that swallows the **first**
    /// fragmented server→client flight and forwards everything else untouched.
    ///
    /// Only one message in this handshake fragments — the `ServerHello` is thousands of
    /// bytes against a `HelloRetryRequest`'s tens — so "the first fragmented downstream
    /// flight" names the reply the connect turns on, without the relay having to parse a
    /// handshake message or hold a key. The drop is addressed by fragment identity rather
    /// than by a clock or a coin: the count comes from the flight's own `total_chunks`
    /// field, so exactly one flight goes missing however many datagrams it is made of, and
    /// every later flight — including the repair — arrives.
    ///
    /// `speak_in_the_gap` puts a single short-header datagram on the wire towards the client
    /// in place of the flight it just swallowed — the shape of a server that has committed
    /// its session and started using it (an application greeting on accept, a keepalive)
    /// while the client is still waiting for a reply it never received. The client cannot
    /// open it, so what it does with it decides whether the repair holds against a server
    /// that speaks or only against one that stays silent.
    ///
    /// Returns the address a client should connect to and how many datagrams were
    /// swallowed, so a test can assert the loss it asked for actually happened rather than
    /// passing because the path was clean.
    async fn spawn_flight_swallowing_relay(
        server_addr: SocketAddr,
        speak_in_the_gap: bool,
    ) -> (SocketAddr, Arc<AtomicUsize>) {
        use crate::transport::phantom_udp::datagram::encode_datagrams;
        use crate::transport::phantom_udp::envelope::{decode_header, FRAG_SUBHDR_LEN};

        let downstream = UdpSocket::bind("127.0.0.1:0").await.expect("relay socket");
        let relay_addr = downstream.local_addr().expect("relay addr");
        let upstream = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("relay upstream");
        upstream
            .connect(server_addr)
            .await
            .expect("relay upstream connect");
        let swallowed = Arc::new(AtomicUsize::new(0));
        let counter = swallowed.clone();
        tokio::spawn(async move {
            let mut c2s = vec![0u8; crate::transport::phantom_udp::envelope::PATH_MTU + 64];
            let mut s2c = vec![0u8; crate::transport::phantom_udp::envelope::PATH_MTU + 64];
            let mut client: Option<SocketAddr> = None;
            // Datagrams of the doomed flight still to be swallowed. `None` until the first
            // fragmented downstream datagram names the size of its own flight.
            let mut owed: Option<usize> = None;
            loop {
                tokio::select! {
                    r = downstream.recv_from(&mut c2s) => {
                        let Ok((n, from)) = r else { continue };
                        client = Some(from);
                        let _ = upstream.send(&c2s[..n]).await;
                    }
                    r = upstream.recv(&mut s2c) => {
                        let Ok(n) = r else { continue };
                        let datagram = &s2c[..n];
                        if let Ok((hdr, rest)) = decode_header(datagram) {
                            if hdr.fragmented && rest.len() >= FRAG_SUBHDR_LEN {
                                let total = u16::from_be_bytes([rest[6], rest[7]]) as usize;
                                let left = owed.get_or_insert(total);
                                if *left > 0 {
                                    *left -= 1;
                                    counter.fetch_add(1, Ordering::Relaxed);
                                    // The last piece of the doomed flight is the moment the
                                    // server has finished replying and, as far as it knows,
                                    // has a session. Speak here and the client is holding an
                                    // unopenable datagram with no keys and no reply.
                                    if *left == 0 && speak_in_the_gap {
                                        if let (Some(c), Ok(dgrams)) = (
                                            client,
                                            encode_datagrams(
                                                PacketType::OneRtt,
                                                &hdr.cid,
                                                0,
                                                b"committed-session-traffic",
                                            ),
                                        ) {
                                            for d in &dgrams {
                                                let _ = downstream.send_to(d, c).await;
                                            }
                                        }
                                    }
                                    continue;
                                }
                            }
                        }
                        if let Some(c) = client {
                            let _ = downstream.send_to(datagram, c).await;
                        }
                    }
                }
            }
        });
        (relay_addr, swallowed)
    }

    /// A UDP relay that forwards both directions untouched and keeps a copy of every
    /// client→server handshake datagram, grouped by the fragment id that identifies the
    /// flight it belongs to.
    ///
    /// It exists so a test can play the part of an on-path attacker with perfect capture:
    /// the strongest position anyone can be in against this mechanism, since the repeat gate
    /// is possession of the exact hello.
    #[allow(clippy::type_complexity)]
    async fn spawn_recording_relay(
        server_addr: SocketAddr,
    ) -> (
        SocketAddr,
        Arc<parking_lot::Mutex<HashMap<u32, Vec<Vec<u8>>>>>,
    ) {
        use crate::transport::phantom_udp::envelope::{decode_header, FRAG_SUBHDR_LEN};

        let downstream = UdpSocket::bind("127.0.0.1:0").await.expect("relay socket");
        let relay_addr = downstream.local_addr().expect("relay addr");
        let upstream = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("relay upstream");
        upstream
            .connect(server_addr)
            .await
            .expect("relay upstream connect");
        let captured: Arc<parking_lot::Mutex<HashMap<u32, Vec<Vec<u8>>>>> =
            Arc::new(parking_lot::Mutex::new(HashMap::new()));
        let sink = captured.clone();
        tokio::spawn(async move {
            let mut c2s = vec![0u8; crate::transport::phantom_udp::envelope::PATH_MTU + 64];
            let mut s2c = vec![0u8; crate::transport::phantom_udp::envelope::PATH_MTU + 64];
            let mut client: Option<SocketAddr> = None;
            loop {
                tokio::select! {
                    r = downstream.recv_from(&mut c2s) => {
                        let Ok((n, from)) = r else { continue };
                        client = Some(from);
                        let datagram = &c2s[..n];
                        if let Ok((hdr, rest)) = decode_header(datagram) {
                            if hdr.ty == PacketType::Initial
                                && hdr.fragmented
                                && rest.len() >= FRAG_SUBHDR_LEN
                            {
                                let pid = u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]);
                                sink.lock().entry(pid).or_default().push(datagram.to_vec());
                            }
                        }
                        let _ = upstream.send(datagram).await;
                    }
                    r = upstream.recv(&mut s2c) => {
                        let Ok(n) = r else { continue };
                        if let Some(c) = client {
                            let _ = downstream.send_to(&s2c[..n], c).await;
                        }
                    }
                }
            }
        });
        (relay_addr, captured)
    }

    /// A repeat never goes to whoever triggered it.
    ///
    /// This is the whole amplification argument in one test. The gate on repeating is
    /// possession of the exact hello, so the strongest attacker against it is one that sat on
    /// the path and captured the flight verbatim — and even that attacker gets nothing back,
    /// because the destination of a repeat comes from the server's record of a completed
    /// handshake and not from the datagram that asked for it. The address in that record
    /// belongs to a peer that echoed an IP-bound cookie (`udp_admit` is unconditional over
    /// UDP), which is exactly what proves it is a real source rather than a spoofed one.
    ///
    /// The counter is what stops this being vacuous. Without it the test would pass equally
    /// against a listener that dropped the replay on the floor for some entirely different
    /// reason — a mistyped connection id, a relay that never forwarded. A non-zero count says
    /// the datagrams reached the branch that decides whether to repeat, and chose not to send
    /// anything here.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_repeat_is_never_sent_to_the_source_that_triggered_it() {
        let listener = PhantomUdpListener::bind_udp("127.0.0.1:0".to_string())
            .await
            .expect("bind a loopback PhantomUDP listener");
        let server_addr: SocketAddr = listener.local_addr().parse().expect("the bound address");
        let pinned = listener.verifying_key_bytes();

        let acceptor = listener.clone();
        let accepted = tokio::spawn(async move { acceptor.accept().await });

        let (relay_addr, captured) = spawn_recording_relay(server_addr).await;
        let client = crate::api::session::connect_pinned_udp(
            "127.0.0.1".to_string(),
            relay_addr.port(),
            pinned,
        )
        .await
        .expect("the client socket binds");
        client.await_ready().await.expect("the handshake completes");
        let outcome = accepted
            .await
            .expect("the accept task")
            .expect("an accepted session");

        // The last flight the client sent is the cookie-bearing hello the reply answers;
        // fragment ids are allocated in order, so the highest is the most recent.
        let flight = {
            let seen = captured.lock();
            let newest = seen
                .keys()
                .copied()
                .max()
                .expect("a captured client flight");
            seen.get(&newest).cloned().expect("its datagrams")
        };
        assert!(
            flight.len() > 1,
            "the captured hello must be the fragmented one — a single datagram would mean the \
             recording caught the wrong message"
        );

        let before = listener.metrics_snapshot().initial_on_committed_route_total;
        let attacker = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("attacker socket");
        attacker
            .connect(server_addr)
            .await
            .expect("attacker connect");
        for d in &flight {
            attacker.send(d).await.expect("replay a captured datagram");
        }

        // Nothing may come back to this socket. A generous window, because the assertion is
        // "never" and the only way to get that wrong is to wait too little.
        let mut buf = vec![0u8; crate::transport::phantom_udp::envelope::PATH_MTU + 64];
        let heard = tokio::time::timeout(Duration::from_secs(2), attacker.recv(&mut buf)).await;
        assert!(
            heard.is_err(),
            "a source that replayed a captured hello received {:?} back; a repeat must only \
             ever go to the address the original reply went to",
            heard.map(|r| r.map(|n| format!("{n} bytes")))
        );

        let deadline = Instant::now() + Duration::from_secs(5);
        while listener.metrics_snapshot().initial_on_committed_route_total == before
            && Instant::now() < deadline
        {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(
            listener.metrics_snapshot().initial_on_committed_route_total > before,
            "the replayed datagrams must have reached the branch that decides whether to \
             repeat; if they did not, this test asserts nothing about that branch"
        );

        // And the session the attacker was aiming at is undisturbed.
        let server = outcome.session();
        client.send(b"ping".to_vec()).await.expect("client write");
        let echoed = tokio::time::timeout(Duration::from_secs(10), server.recv())
            .await
            .expect("the session still carries data")
            .expect("a frame");
        assert_eq!(echoed, b"ping".to_vec());

        listener.shutdown();
    }

    /// A `ServerHello` flight lost on the way down costs a retransmit, not the connect.
    ///
    /// Nothing under the handshake is reliable and the reply is the largest thing in it —
    /// six datagrams of the thirteen a PhantomUDP handshake spends — so the reply flight is
    /// where a lossy path most often takes the exchange. The client already repairs its own
    /// half: it repeats its flight on a 1 s / 3 s / 7 s schedule. What that repetition used
    /// to buy was nothing, because the demux routes by connection id before it looks at a
    /// datagram's type, so a repeated hello landed in the established session's inbound
    /// channel and was dropped by a pump that does not parse handshake messages. The server
    /// had no trigger to answer again, and one lost datagram out of six was an
    /// unrecoverable connect.
    ///
    /// The assertion is the connect completing, and the swallowed count is what makes it
    /// mean something: a version of this test whose relay forwarded everything would pass
    /// against a server with no repair at all.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_lost_server_hello_flight_is_repaired_by_the_repeated_client_flight() {
        let listener = PhantomUdpListener::bind_udp("127.0.0.1:0".to_string())
            .await
            .expect("bind a loopback PhantomUDP listener");
        let server_addr: SocketAddr = listener.local_addr().parse().expect("the bound address");
        let pinned = listener.verifying_key_bytes();

        let acceptor = listener.clone();
        let accepted = tokio::spawn(async move { acceptor.accept().await });

        let (relay_addr, swallowed) = spawn_flight_swallowing_relay(server_addr, false).await;
        let client = crate::api::session::connect_pinned_udp(
            "127.0.0.1".to_string(),
            relay_addr.port(),
            pinned,
        )
        .await
        .expect("the client socket binds");

        client
            .await_ready()
            .await
            .expect("the handshake completes even though its reply flight was lost");

        let lost = swallowed.load(Ordering::Relaxed);
        assert!(
            lost > 0,
            "the relay must actually have swallowed a flight; against a clean path this \
             test asserts nothing"
        );
        assert!(
            listener.metrics_snapshot().initial_on_committed_route_total > 0,
            "the repeated client flight must be visible to an operator: this counter is the \
             only thing that distinguishes a reply lost on the way down from a path that \
             went silent in both directions"
        );

        let outcome = accepted
            .await
            .expect("the accept task")
            .expect("an accepted session");
        let server = outcome.session();
        client.send(b"ping".to_vec()).await.expect("client write");
        let echoed = tokio::time::timeout(Duration::from_secs(10), server.recv())
            .await
            .expect("the repaired session carries data")
            .expect("a frame");
        assert_eq!(echoed, b"ping".to_vec());

        listener.shutdown();
    }

    /// The repair must hold against a server that starts using the session it committed,
    /// not only against one that happens to stay silent until the client's timer fires.
    ///
    /// Between the moment a server establishes a session and the moment the client repeats
    /// the hello it never got an answer to, the server is free to send short-header traffic:
    /// an application greeting written on `accept()`, a keepalive, cover traffic. The client
    /// has no keys for any of it — the reply that carried them is the flight that went
    /// missing — and whatever it does with that datagram decides the connect. Handing it up
    /// as a reply ends the attempt with `invalid server reply` before the retransmit timer
    /// ever expires, and the whole repair is then conditional on server silence, which is
    /// not a property anything guarantees. Nothing else in the suite covers that window,
    /// because every other relay here forwards or drops and none of them speaks.
    ///
    /// Same shape as the test above, so what it adds is exactly the one datagram.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_repair_survives_a_server_that_speaks_before_the_client_has_the_keys() {
        let listener = PhantomUdpListener::bind_udp("127.0.0.1:0".to_string())
            .await
            .expect("bind a loopback PhantomUDP listener");
        let server_addr: SocketAddr = listener.local_addr().parse().expect("the bound address");
        let pinned = listener.verifying_key_bytes();

        let acceptor = listener.clone();
        let accepted = tokio::spawn(async move { acceptor.accept().await });

        let (relay_addr, swallowed) = spawn_flight_swallowing_relay(server_addr, true).await;
        let client = crate::api::session::connect_pinned_udp(
            "127.0.0.1".to_string(),
            relay_addr.port(),
            pinned,
        )
        .await
        .expect("the client socket binds");

        client.await_ready().await.expect(
            "the handshake must survive an unopenable datagram arriving while its reply is \
             still missing",
        );
        assert!(
            swallowed.load(Ordering::Relaxed) > 0,
            "the relay must actually have swallowed a flight, or the client was never in the \
             window this test is about"
        );

        let outcome = accepted
            .await
            .expect("the accept task")
            .expect("an accepted session");
        let server = outcome.session();
        client.send(b"ping".to_vec()).await.expect("client write");
        let echoed = tokio::time::timeout(Duration::from_secs(10), server.recv())
            .await
            .expect("the repaired session carries data")
            .expect("a frame");
        assert_eq!(echoed, b"ping".to_vec());

        listener.shutdown();
    }

    /// Anyone who saw a hello can spend that connection's repair budget, and this is what
    /// that costs — stated, bounded, and accepted rather than left to be discovered.
    ///
    /// The gate on a repeat is possession of the exact hello, so the party that can trigger
    /// one is the client or someone who was on the path when the hello crossed it. Rule 3 of
    /// PROTOCOL § 6.1 makes the repeat itself worthless to that observer: the bytes go to the
    /// address the original went to, never to whoever asked, so the amplification factor
    /// towards it is zero. What is left is this — the budget of rule 4 is finite, and a
    /// replay spends it. Three matching replays and the real client's own repetition draws
    /// nothing.
    ///
    /// It is accepted, and the reasoning is that the attacker who can do it already has a
    /// strictly stronger move. Being on the path is what supplies the hello, and a party on
    /// the path can simply drop the reply — which suppresses the connect completely instead
    /// of suppressing a repair for one, and needs no timing and no captured bytes. Spending
    /// the budget also *delivers* the reply to the client three more times on the way, which
    /// is the opposite of what an attacker wants. There is no bound to add that the position
    /// itself does not already defeat, so the honest thing is to write the extent down and
    /// pin it here rather than imply a gate that is not there. The threat model records it in
    /// the same terms.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_on_path_observer_can_spend_a_connections_repair_budget() {
        use crate::transport::phantom_udp::envelope::decode_header;

        let listener = PhantomUdpListener::bind_udp("127.0.0.1:0".to_string())
            .await
            .expect("bind a loopback PhantomUDP listener");
        let server_addr: SocketAddr = listener.local_addr().parse().expect("the bound address");
        let pinned = listener.verifying_key_bytes();

        let acceptor = listener.clone();
        let accepted = tokio::spawn(async move { acceptor.accept().await });
        let (relay_addr, captured) = spawn_recording_relay(server_addr).await;
        let client = crate::api::session::connect_pinned_udp(
            "127.0.0.1".to_string(),
            relay_addr.port(),
            pinned,
        )
        .await
        .expect("the client socket binds");
        client.await_ready().await.expect("the handshake completes");
        let _outcome = accepted
            .await
            .expect("the accept task")
            .expect("an accepted session");

        // What an on-path observer holds: the flight exactly as it crossed the path.
        let flight = {
            let seen = captured.lock();
            let newest = seen
                .keys()
                .copied()
                .max()
                .expect("a captured client flight");
            seen.get(&newest).cloned().expect("its datagrams")
        };
        let cid = decode_header(&flight[0]).expect("a captured header").0.cid;
        assert_eq!(
            cid,
            decode_header(flight.last().expect("a datagram"))
                .expect("a captured header")
                .0
                .cid,
            "the captured datagrams must all belong to one flight"
        );

        let observer = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("observer socket");
        observer
            .connect(server_addr)
            .await
            .expect("observer connect");

        // Every replay inside the budget is answered — and answered to the client, never
        // here, which is what makes this an accepted cost rather than a reflector.
        for n in 1..=MAX_FLIGHT_REPEATS {
            let before = listener.metrics_snapshot().handshake_flight_repeated_total;
            for d in &flight {
                observer.send(d).await.expect("replay a captured datagram");
            }
            let deadline = Instant::now() + Duration::from_secs(5);
            while listener.metrics_snapshot().handshake_flight_repeated_total == before
                && Instant::now() < deadline
            {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            assert_eq!(
                listener.metrics_snapshot().handshake_flight_repeated_total,
                before + 1,
                "replay {n} of {MAX_FLIGHT_REPEATS} must be answered: a repeat is owed to \
                 whoever presents the exact hello, and the listener cannot tell which of them \
                 that is"
            );
        }

        // Past the budget the repair for this connection is gone, which is the whole extent
        // of what the observer achieved.
        let spent = listener.metrics_snapshot();
        for d in &flight {
            observer.send(d).await.expect("replay past the budget");
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        while listener.metrics_snapshot().initial_on_committed_route_total
            < spent.initial_on_committed_route_total + flight.len() as u64
            && Instant::now() < deadline
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let after = listener.metrics_snapshot();
        assert!(
            after.initial_on_committed_route_total > spent.initial_on_committed_route_total,
            "the replay must have reached the branch that decides whether to repeat, or the \
             assertion below is about routing rather than about the budget"
        );
        assert_eq!(
            after.handshake_flight_repeated_total, spent.handshake_flight_repeated_total,
            "the budget is finite and this is what spending it looks like: the real client's \
             own repetition now draws nothing. Accepted — the position that supplies the hello \
             can drop the reply outright, which is strictly stronger — but it must be a \
             property this suite states rather than one a reader has to derive"
        );

        // And the session it all happened around is undisturbed.
        listener.shutdown();
    }

    /// The two handshake-repair counters answer different questions, and one of them cannot
    /// answer either question alone.
    ///
    /// The counter that says "a client asked again" is bumped when the datagram arrives,
    /// before anything has decided whether an answer is owed — which is the only place it can
    /// be, since a flight that arrives in pieces is still a flight that arrived. On its own it
    /// therefore reads identically whether the listener repaired the connect or had nothing
    /// retained for it, and telling those apart is the entire reason it was added: an
    /// investigation into failed connects could not determine, from either side, whether the
    /// client's repeated hellos reached the server at all.
    ///
    /// So the repeat is counted separately, where the decision is made. Arrivals without
    /// repeats is a listener whose retention did not cover that session — evicted, expired, or
    /// its budget already spent — and it is a different fault from a path that never carried
    /// the question, needing a different remedy. This drives both halves through the real
    /// demux: noise on a committed connection id, which is an arrival and nothing more, then
    /// the exact hello, which is both.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_arrival_counter_and_the_repeat_counter_answer_different_questions() {
        use crate::transport::phantom_udp::datagram::encode_datagrams;
        use crate::transport::phantom_udp::envelope::decode_header;

        let listener = PhantomUdpListener::bind_udp("127.0.0.1:0".to_string())
            .await
            .expect("bind a loopback PhantomUDP listener");
        let server_addr: SocketAddr = listener.local_addr().parse().expect("the bound address");
        let pinned = listener.verifying_key_bytes();

        let acceptor = listener.clone();
        let accepted = tokio::spawn(async move { acceptor.accept().await });
        let (relay_addr, captured) = spawn_recording_relay(server_addr).await;
        let client = crate::api::session::connect_pinned_udp(
            "127.0.0.1".to_string(),
            relay_addr.port(),
            pinned,
        )
        .await
        .expect("the client socket binds");
        client.await_ready().await.expect("the handshake completes");
        let _outcome = accepted
            .await
            .expect("the accept task")
            .expect("an accepted session");

        // The last flight the client sent is the cookie-bearing hello the reply answers;
        // fragment ids are allocated in order, so the highest is the most recent.
        let flight = {
            let seen = captured.lock();
            let newest = seen
                .keys()
                .copied()
                .max()
                .expect("a captured client flight");
            seen.get(&newest).cloned().expect("its datagrams")
        };
        let cid = decode_header(&flight[0]).expect("a captured header").0.cid;

        let probe = UdpSocket::bind("127.0.0.1:0").await.expect("probe socket");
        probe.connect(server_addr).await.expect("probe connect");
        let before = listener.metrics_snapshot();

        // Noise on the committed connection id: a handshake-type datagram that is not the
        // hello the retained reply answers.
        const NOISE: u64 = 4;
        for i in 0..NOISE {
            for d in encode_datagrams(PacketType::Initial, &cid, i as u32, b"not-the-hello")
                .expect("encode")
            {
                probe.send(&d).await.expect("send noise");
            }
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        while listener.metrics_snapshot().initial_on_committed_route_total
            < before.initial_on_committed_route_total + NOISE
            && Instant::now() < deadline
        {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let after_noise = listener.metrics_snapshot();
        assert_eq!(
            after_noise.initial_on_committed_route_total,
            before.initial_on_committed_route_total + NOISE,
            "every handshake datagram on a committed connection is an arrival, whatever it \
             turns out to contain"
        );
        assert_eq!(
            after_noise.handshake_flight_repeated_total, before.handshake_flight_repeated_total,
            "and none of it was answered — a counter that rose here could not tell a repaired \
             connect from a listener with nothing to send"
        );

        // The exact hello: an answer is owed, and one repeat goes out for the whole flight.
        for d in &flight {
            probe.send(d).await.expect("replay the captured flight");
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        while listener.metrics_snapshot().handshake_flight_repeated_total
            == after_noise.handshake_flight_repeated_total
            && Instant::now() < deadline
        {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let after_hello = listener.metrics_snapshot();
        assert_eq!(
            after_hello.handshake_flight_repeated_total,
            after_noise.handshake_flight_repeated_total + 1,
            "one repeat is owed per repeated flight, not per datagram of it"
        );
        assert_eq!(
            after_hello.initial_on_committed_route_total,
            after_noise.initial_on_committed_route_total + flight.len() as u64,
            "while arrivals are counted per datagram, which is what makes a partially \
             delivered flight visible at all"
        );

        listener.shutdown();
    }

    /// The demux's own clock is what releases a retained reply, and deleting that one call
    /// must not leave the suite green.
    ///
    /// A healthy session never touches its retention entry again. It is keyed on the
    /// bootstrap connection id, and a client that received the reply rotates off that id
    /// immediately — so no datagram will ever arrive to reclaim the entry lazily, and no
    /// unit test of the table can tell whether anything calls `sweep` in production. Without
    /// the timer the table fills with answers to questions nobody is asking and stays full,
    /// which is worse than the bound it looks like: the retention budget then belongs
    /// permanently to sessions that have long since finished, and every new session displaces
    /// one of them instead of a genuinely live entry.
    ///
    /// So this drives the real demux and watches the real gauge. One session establishes (an
    /// answer is retained), one application byte crosses (the server's inbound packet
    /// AEAD-opens, which latches the client's proof of receipt), and the entry must then go
    /// on its own — with nothing arriving on that connection id to prompt it. The generous
    /// deadline is deliberate: the assertion is that the reclaim happens at all, and
    /// `ROUTE_SWEEP_INTERVAL` is the rate it happens at.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_retained_reply_is_released_by_the_demux_clock_alone() {
        let listener = PhantomUdpListener::bind_udp("127.0.0.1:0".to_string())
            .await
            .expect("bind a loopback PhantomUDP listener");
        let port: u16 = listener
            .local_addr()
            .parse::<SocketAddr>()
            .expect("the bound address")
            .port();
        let pinned = listener.verifying_key_bytes();

        let acceptor = listener.clone();
        let accepted = tokio::spawn(async move { acceptor.accept().await });
        let client = crate::api::session::connect_pinned_udp("127.0.0.1".to_string(), port, pinned)
            .await
            .expect("the client socket binds");
        client.await_ready().await.expect("the handshake completes");
        let outcome = accepted
            .await
            .expect("the accept task")
            .expect("an accepted session");

        let deadline = Instant::now() + Duration::from_secs(5);
        while listener.retained_flights.load(Ordering::Relaxed) == 0 && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(
            listener.retained_flights.load(Ordering::Relaxed),
            1,
            "the reply this handshake sent must be retained, or the rest of this test is \
             about an empty table"
        );

        // One authenticated byte is the client's proof that it received the reply, which is
        // what makes the retained copy dead weight. Nothing else happens on this connection.
        let server = outcome.session();
        client
            .send(b"heard-you".to_vec())
            .await
            .expect("client write");
        let echoed = tokio::time::timeout(Duration::from_secs(10), server.recv())
            .await
            .expect("the session carries data")
            .expect("a frame");
        assert_eq!(echoed, b"heard-you".to_vec());

        let deadline = Instant::now() + Duration::from_secs(10);
        while listener.retained_flights.load(Ordering::Relaxed) > 0 && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(
            listener.retained_flights.load(Ordering::Relaxed),
            0,
            "a reply whose client has been heard from was still held after {:?}; nothing will \
             ever arrive on its connection id to reclaim it, so the demux's periodic sweep is \
             the only thing that can — and without it the retention budget is permanently \
             owned by sessions that finished long ago",
            Duration::from_secs(10)
        );

        listener.shutdown();
    }

    /// One retirement costs one session's own route set, and that set has a ceiling
    /// that does not grow with how long the session lives.
    ///
    /// The ceiling is the quantity [`RETIRE_QUEUE_DEPTH`]'s cost figure is derived
    /// from — a full queue is that many retirements of at most this many removals
    /// each — so if a session could accumulate routes without bound, the measured
    /// worst case in front of the socket would be a number about the past rather than
    /// a constant. The way that would happen is a slide that adds a leading CID
    /// without dropping a trailing one, which is a one-line change in `apply_slide`
    /// and reads like a safe one, so it is driven here: a hundred migrations, more
    /// than any real session performs, and the set must be the same size at the end
    /// as it was after the first.
    ///
    /// The background of other sessions' routes is not scenery. It is what
    /// distinguishes "released this session's set" from "released everything that
    /// looked dead", and it is what makes the removal count meaningful.
    #[test]
    fn a_session_route_set_has_a_ceiling_that_a_long_life_cannot_raise() {
        let window = (crate::crypto::cid_chain::CID_WINDOW_TRAILING
            + crate::crypto::cid_chain::CID_WINDOW_LEADING) as usize
            + 2;
        let mut table = empty_table();
        let mut keep = Vec::new();
        let mut next: u64 = 0;
        let mut fresh_cid = move || {
            next += 1;
            next.to_be_bytes()
        };

        let subject = DemuxRouteOwner(1);
        let (tx, rx) = live_route();
        keep.push(rx);
        // Bootstrap CID plus the rotating window, exactly as the accept path installs
        // them.
        let bootstrap = fresh_cid();
        table.try_insert(bootstrap, tx.clone(), subject);
        let mut edge: Vec<ConnId> = (0..window - 1).map(|_| fresh_cid()).collect();
        table.register_window(&edge, &tx, subject);
        let settled = table.owned.get(&subject).map(Vec::len).unwrap_or(0);

        // Other sessions, so a whole-table pass and a per-session release are
        // distinguishable by their effect and not merely by their implementation.
        for i in 0..64u64 {
            let (other_tx, other_rx) = live_route();
            keep.push(other_rx);
            let cids: Vec<ConnId> = (0..window).map(|_| fresh_cid()).collect();
            table.register_window(&cids, &other_tx, DemuxRouteOwner(100 + i));
        }
        let table_before = table.routes.len();

        // A hundred migrations. Each slides the window one step: a new leading CID
        // arrives and the oldest trailing one goes.
        for _ in 0..100 {
            let add = fresh_cid();
            let remove = edge.remove(0);
            let anchor = *edge.last().unwrap_or(&bootstrap);
            table.apply_slide(&CidSlide {
                add: vec![add],
                remove: vec![remove],
                anchor,
            });
            edge.push(add);
        }

        let held = table.owned.get(&subject).map(Vec::len).unwrap_or(0);
        assert_eq!(
            held, settled,
            "a session's route set must not grow with the number of migrations it has \
             made; a slide that adds without dropping turns the retire cost from a \
             constant into a number about the session's history"
        );
        assert!(
            held <= window,
            "a session holds at most its bootstrap CID and its rotating window ({window} \
             routes); got {held}, which is the figure the retire-queue cost is derived \
             from"
        );

        table.retire_session(subject);
        assert_eq!(
            table_before - table.routes.len(),
            held,
            "a retirement must remove exactly this session's routes — no more, which \
             would reach another session's, and no fewer, which would leave a leak the \
             signal was supposed to close"
        );
        assert!(
            !table.owned.contains_key(&subject),
            "and it must leave no reverse-index entry behind"
        );
    }

    /// A retire signal the bounded queue dropped is reclaimed anyway, by the demux's
    /// own timer, with **no inbound datagram of any kind** to drive it.
    ///
    /// This is what makes the bound on that queue a deferral rather than a leak, and
    /// it was not true when the bound was added. Every other reclaim on the route
    /// table is reactive to traffic — a datagram for a dead route, a handshake task
    /// finishing, the every-256th-connection sweep at accept — and the population that
    /// produces a dropped retire signal is precisely the one that has stopped sending
    /// anything at all. A session whose signal was dropped kept all of its routes for
    /// as long as the listener ran.
    ///
    /// The drop is induced rather than waited for: the queue the session signals over
    /// is replaced with one that is already full, so `signal_route_retire` finds no
    /// room and discards, which is exactly what happens at `RETIRE_QUEUE_DEPTH` under a
    /// correlated departure. Inducing it is the only way to make the case
    /// deterministic — reproducing it by saturation would need a thousand simultaneous
    /// departures racing a demux that drains the queue ahead of every read.
    ///
    /// Nothing connects after the client leaves, and that is the assertion as much as
    /// the count is: a reclaim that needed one more connection would pass a version of
    /// this test that made one.
    #[tokio::test]
    async fn a_dropped_retire_signal_is_reclaimed_without_any_new_inbound_connection() {
        let listener = PhantomUdpListener::bind_udp("127.0.0.1:0".to_string())
            .await
            .expect("bind a loopback PhantomUDP listener");
        let port: u16 = listener
            .local_addr()
            .rsplit(':')
            .next()
            .and_then(|p| p.parse().ok())
            .expect("the bound port");
        let pinned = listener.verifying_key_bytes();

        let acceptor = listener.clone();
        let accepted = tokio::spawn(async move { acceptor.accept().await });
        let client = crate::api::session::connect_pinned_udp("127.0.0.1".to_string(), port, pinned)
            .await
            .expect("connect");
        client.await_ready().await.expect("the handshake completes");
        let outcome = accepted
            .await
            .expect("the accept task")
            .expect("an accepted session");
        let server = outcome.session();

        // One exchange each way, so the session is genuinely established and its
        // rotating-CID window is registered rather than merely its bootstrap CID.
        client.send(b"ping".to_vec()).await.expect("client write");
        let deadline = Instant::now() + Duration::from_secs(10);
        while listener.active_route_count() < 2 && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let established = listener.active_route_count();
        assert!(
            established > 1,
            "an established session holds its whole CID window, not one route; got \
             {established}"
        );

        // Sabotage the retire signal exactly as a full queue does: point the session's
        // link at a queue with no room. `try_send` fails and the signal is discarded,
        // so the routes are left to whatever else can reclaim them.
        let inner = server
            .inner_session_handle()
            .await
            .expect("an established session has an inner session");
        let (dead_slide_tx, _dead_slide_rx) = mpsc::unbounded_channel();
        let (full_retire_tx, _full_retire_rx) = mpsc::channel::<DemuxRouteOwner>(1);
        full_retire_tx
            .try_send(DemuxRouteOwner(u64::MAX))
            .expect("fill the one slot");
        inner.set_demux_link(DemuxLink {
            slide_tx: dead_slide_tx,
            retire_tx: full_retire_tx,
            owner: DemuxRouteOwner(u64::MAX),
        });

        drop(client);
        drop(server);
        drop(outcome);

        // No further connect, no further datagram — the only thing left that can move
        // this count is the demux's own clock. The cap is generous against
        // `ROUTE_SWEEP_INTERVAL` so the assertion is "it converges", not "it converges
        // at time T".
        let deadline = Instant::now() + Duration::from_secs(20);
        while listener.active_route_count() > 0 && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert_eq!(
            listener.active_route_count(),
            0,
            "a dropped retire signal must cost one deferred reclaim and not a permanent \
             one; without a sweep on the demux's own timer these {established} routes \
             are held for the life of the listener, because the peer that would have \
             triggered every other reclaim path has left"
        );

        listener.shutdown();
    }

    /// Retiring a session releases that session's routes and **only** that session's,
    /// and it releases them by the identity this listener assigned — not by which
    /// channel the entries happen to point at.
    ///
    /// The two halves are one claim looked at from both sides. Two ordinary sessions
    /// with their own channels cover the normal case; the pair that *shares* a channel
    /// is the discriminator, because deciding membership by channel identity — which is
    /// what a whole-table scan for matching senders does — cannot tell them apart and
    /// would take both. Membership has to be the thing that was assigned, or a table-wide
    /// delete is authorised by a lookup nothing owns.
    #[test]
    fn retire_releases_only_the_asking_sessions_routes() {
        let mut table = empty_table();
        let (tx_a, _rx_a) = live_route();
        let (tx_b, _rx_b) = live_route();
        let a = DemuxRouteOwner(1);
        let b = DemuxRouteOwner(2);
        // A third session sharing A's channel: distinct identity, same `Sender`.
        let shared = DemuxRouteOwner(3);

        table.register_window(&[cid(1), cid(2), cid(3)], &tx_a, a);
        table.register_window(&[cid(10), cid(11)], &tx_b, b);
        table.register_window(&[cid(20)], &tx_a, shared);
        assert_eq!(table.routes.len(), 6);

        table.retire_session(a);

        assert!(
            table.get(&cid(1)).is_none() && table.get(&cid(2)).is_none(),
            "the retiring session's own routes must go"
        );
        assert!(
            table.get(&cid(10)).is_some() && table.get(&cid(11)).is_some(),
            "another session's routes must survive"
        );
        assert!(
            table.get(&cid(20)).is_some(),
            "a route belonging to a different session must survive even when it shares \
             the retiring session's channel — membership is identity, not channel"
        );
        assert_eq!(table.routes.len(), 3);
        assert_eq!(
            table.gauge.load(Ordering::Relaxed),
            3,
            "the gauge the operator reads must track the table"
        );
        assert!(
            !table.owned.contains_key(&a),
            "a retired session must leave no reverse-index entry behind"
        );
        // Idempotent: a second retire (a duplicate signal, or one that raced the reap)
        // finds nothing and does nothing.
        table.retire_session(a);
        assert_eq!(table.routes.len(), 3);
    }

    /// The reverse index is the only thing that keeps a retire off the size of the
    /// table, so it must not be able to drift from the routes it describes. Every
    /// mutator is exercised here — insert, window register, slide (which both adds and
    /// removes), the dead-route reclaim and the periodic sweep — and afterwards the two
    /// directions must agree exactly.
    ///
    /// Drift in the cheap direction leaks routes past a retire; drift in the expensive
    /// direction has a retire delete a CID that has since been re-registered to somebody
    /// else, which is the failure the identity check exists to prevent.
    #[test]
    fn the_reverse_index_never_drifts_from_the_routes() {
        let mut table = empty_table();
        let (tx_a, _rx_a) = live_route();
        let (tx_b, rx_b) = live_route();
        let a = DemuxRouteOwner(1);
        let b = DemuxRouteOwner(2);

        table.register_window(&[cid(1), cid(2), cid(3)], &tx_a, a);
        table.register_window(&[cid(10), cid(11)], &tx_b, b);
        table.apply_slide(&CidSlide {
            add: vec![cid(4), cid(5)],
            remove: vec![cid(1)],
            anchor: cid(2),
        });
        // B's session goes away without signalling: its channel closes, and the lazy
        // reclaim paths are what notice.
        drop(rx_b);
        table.remove_if_dead(&cid(10));
        table.reap_dead();

        let mut indexed: Vec<(RouteOwner, ConnId)> = table
            .owned
            .iter()
            .flat_map(|(owner, cids)| cids.iter().map(move |c| (*owner, *c)))
            .collect();
        let mut actual: Vec<(RouteOwner, ConnId)> = table
            .routes
            .iter()
            .map(|(c, entry)| (entry.owner, *c))
            .collect();
        indexed.sort();
        actual.sort();
        assert_eq!(
            indexed, actual,
            "the reverse index and the route table must describe the same set"
        );
        assert!(
            !table.owned.contains_key(&b),
            "a session whose every route was reclaimed must leave no index entry"
        );

        // And the retire that rides on it still takes exactly A's set.
        table.retire_session(a);
        assert!(table.routes.is_empty() && table.owned.is_empty());
    }

    /// A route's key is a connection id chosen by whoever sent the datagram, so an
    /// unconditional insert would let one party repoint a route a *live* session is
    /// being reached through — the table promises the opposite in as many words. The
    /// slot is refused instead, and refused without disturbing what is already there.
    ///
    /// The same-session case is the one that must still succeed: a session's bootstrap
    /// CID is registered at accept and arrives again inside its own window, and treating
    /// that as a collision would leave the window a CID short.
    #[test]
    fn a_live_route_is_never_repointed_to_another_session() {
        let mut table = empty_table();
        let (tx_a, _rx_a) = live_route();
        let (tx_b, _rx_b) = live_route();
        let a = DemuxRouteOwner(1);
        let b = DemuxRouteOwner(2);

        assert!(table.try_insert(cid(7), tx_a.clone(), a));
        assert!(
            !table.try_insert(cid(7), tx_b.clone(), b),
            "a live route must not be handed to another session"
        );
        assert!(
            table.get(&cid(7)).is_some_and(|tx| tx.same_channel(&tx_a)),
            "the refused insert must leave the live route pointing where it did"
        );
        assert!(
            !table.owned.contains_key(&b),
            "a refused insert must record no ownership"
        );

        assert!(
            table.try_insert(cid(7), tx_a.clone(), a),
            "re-registering a CID this session already owns is a no-op, not a collision"
        );
        assert_eq!(
            table.owned.get(&a).map(Vec::len),
            Some(1),
            "the no-op must not double-count the CID in the reverse index"
        );

        // A *dead* route is not a live one: the slot is reclaimable and admits the
        // newcomer, which is what keeps a failed handshake from parking a CID.
        let (tx_c, rx_c) = live_route();
        let c = DemuxRouteOwner(3);
        assert!(table.try_insert(cid(8), tx_c, c));
        drop(rx_c);
        let (tx_d, _rx_d) = live_route();
        assert!(
            table.try_insert(cid(8), tx_d.clone(), DemuxRouteOwner(4)),
            "a dead route must not hold its slot against a new connection"
        );
        assert!(
            !table.owned.contains_key(&c),
            "the displaced session must lose its claim on the CID"
        );
    }

    /// The retire signal is dropped, not queued, when the demux is behind.
    ///
    /// A session ends when its peer decides it does, so an unbounded queue here would
    /// let a correlated departure choose how much work sits in front of the demux's next
    /// datagram read. The bound is what refuses that, and the cost of the refusal is one
    /// lazy reclaim — exactly the reclaim path that existed before the signal did. What
    /// this pins is that the overflow is silent and non-blocking rather than a wait, a
    /// panic, or an unbounded backlog.
    #[test]
    fn a_full_retire_queue_drops_the_signal_instead_of_waiting() {
        let session = crate::transport::session::Session::new(
            crate::transport::types::SessionId::from_bytes([0x5A; 32]),
            &[0x11u8; 32],
            true,
        )
        .expect("session");
        let (slide_tx, _slide_rx) = mpsc::unbounded_channel();
        let (retire_tx, mut retire_rx) = mpsc::channel::<DemuxRouteOwner>(1);
        let owner = DemuxRouteOwner(42);
        session.set_demux_link(DemuxLink {
            slide_tx,
            retire_tx,
            owner,
        });

        // Fills the one slot, then overflows. Neither call may block or panic.
        session.signal_route_retire();
        session.signal_route_retire();

        assert_eq!(
            retire_rx.try_recv().ok(),
            Some(owner),
            "the signal names the identity the demux assigned, and nothing from the wire"
        );
        assert!(
            retire_rx.try_recv().is_err(),
            "the overflowing signal must be dropped rather than queued behind the first"
        );
    }

    /// H-2: the per-source-IP pending counter tracks admit/release symmetrically, so the
    /// demux's `count(ip) >= MAX_PENDING_PER_IP` gate bounds one source's in-flight slots and
    /// frees the entry when its last handshake finishes (the map can never leak per IP).
    #[test]
    fn pending_by_ip_counts_admit_release_and_frees_at_zero() {
        let a: IpAddr = "10.0.0.1".parse().unwrap();
        let b: IpAddr = "10.0.0.2".parse().unwrap();
        let mut p = PendingByIp::new();
        assert_eq!(p.count(a), 0);

        // Admit drives the count toward the cap; distinct IPs are independent.
        for n in 1..=MAX_PENDING_PER_IP {
            p.admit(a);
            assert_eq!(p.count(a), n);
        }
        assert_eq!(p.count(b), 0, "a different source IP is unaffected");
        assert!(
            p.count(a) >= MAX_PENDING_PER_IP,
            "one source can reach but not be silently waved past the cap"
        );

        // Release is symmetric; the entry is dropped at zero so the map cannot leak per IP.
        for _ in 0..MAX_PENDING_PER_IP {
            p.release(a);
        }
        assert_eq!(p.count(a), 0);
        assert!(
            !p.counts.contains_key(&a),
            "a fully-released IP leaves no residual entry"
        );
        // Releasing an unknown IP is a no-op (never underflows).
        p.release(b);
        assert_eq!(p.count(b), 0);
    }

    /// A bound listener with no client: accept() is pending until shutdown(), then ConnectionClosed.
    #[tokio::test]
    async fn shutdown_unblocks_accept() {
        let listener = PhantomUdpListener::bind_udp("127.0.0.1:0".to_string())
            .await
            .expect("bind_udp");
        let l2 = listener.clone();
        let accept = tokio::spawn(async move { l2.accept().await });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        listener.shutdown();
        let res = tokio::time::timeout(std::time::Duration::from_secs(2), accept)
            .await
            .expect("join")
            .expect("task");
        assert!(matches!(res, Err(CoreError::ConnectionClosed)));
    }

    /// The listener exposes a stable verifying identity for client pinning.
    #[tokio::test]
    async fn exposes_verifying_key() {
        let listener = PhantomUdpListener::bind_udp("127.0.0.1:0".to_string())
            .await
            .unwrap();
        assert!(!listener.verifying_key_bytes().is_empty());
        assert!(listener.local_addr().starts_with("127.0.0.1:"));
    }

    // ── UdpListenerBuilder tests ──────────────────────────────────────────────

    /// Verify `PhantomUdpListener::builder` can bind a listener.
    #[tokio::test]
    async fn udp_listener_builder_binds_successfully() {
        let listener = PhantomUdpListener::builder("127.0.0.1:0")
            .bind()
            .await
            .expect("builder bind should succeed");
        assert!(listener.local_addr().starts_with("127.0.0.1:"));
    }
}
