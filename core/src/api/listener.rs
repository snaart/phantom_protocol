use crate::api::session::{PhantomSession, SessionTransport};
use crate::api::tcp_transport::TcpSessionTransport;
use crate::crypto::hybrid_sign::HybridSigningKey;
use crate::errors::CoreError;
use crate::observability::attrs::{AeadAlgorithm, HandshakeOutcome, ProtocolVersion};
use crate::observability::{Observability, ObservabilityConfig};
use crate::runtime::{Runtime, SpawnHandle, TokioRuntime};
use crate::transport::handshake::{ClientHello, HandshakeResponse, HandshakeServer};
use crate::transport::types::LegType;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, Mutex, Notify, Semaphore};

/// In-library overall deadline for one server-side handshake (H4/DOS-1). A
/// stalled or byte-trickling peer can no longer hang `accept()`: the handshake
/// is abandoned with `CoreError::Timeout` past this budget. A full hybrid
/// X25519+ML-KEM-768 / Ed25519+ML-DSA-65 handshake completes in single-digit ms
/// on a real link, so 10s comfortably absorbs mobile/satellite RTT + a cookie/PoW
/// round while still bounding a slowloris. Routed through the `Runtime` clock so
/// a custom `bind_with_runtime` runtime (incl. tests) is honored.
const HANDSHAKE_DEADLINE: Duration = Duration::from_secs(10);

/// Max cookie/PoW `Retry` rounds the server drives for one connection (DOS-4).
/// One cookie round + one PoW round is the legitimate maximum; a peer that keeps
/// triggering `Retry` without ever satisfying the gate is dropped rather than
/// allowed to occupy the handshake indefinitely.
const MAX_SERVER_RETRY_ROUNDS: u32 = 2;

/// Max concurrent in-flight (accepted-but-not-yet-established) handshakes the
/// listener drives at once (H4 decouple) — a dedicated bound distinct from any
/// established-session cap the embedder applies. Also the depth of the
/// completed-handshake hand-off queue, so at most ~2× this many sessions buffer
/// before the listener back-pressures to not accepting new TCP.
const MAX_INFLIGHT_HANDSHAKES: usize = 256;

#[cfg_attr(feature = "bindings", derive(uniffi::Object))]
pub struct PhantomListener {
    /// Listening socket, owned by the background acceptor task (H4 decouple).
    /// `tokio::net::TcpListener::accept` takes `&self`, so an `Arc` (no mutex)
    /// suffices — only the single acceptor task accepts.
    listener: Arc<TcpListener>,
    handshake_server: Arc<HandshakeServer>,
    /// The local socket address the listener is actually bound to.
    /// Cached so callers can read it without acquiring the listener mutex.
    /// Useful when `bind("0.0.0.0:0")` is used and the OS chose the port.
    local_addr: SocketAddr,
    /// Graceful-shutdown signal (Phase 4.6). `shutdown()` flips
    /// `shutting_down` and wakes the acceptor + any `accept()` calls so they
    /// unwind cleanly. `Arc` so the background acceptor task shares it.
    shutting_down: Arc<AtomicBool>,
    shutdown_notify: Arc<Notify>,
    /// Async runtime used for spawning the acceptor, per-connection handshake
    /// tasks, and accepted-session data pumps (Phase 3.1). Defaults to
    /// [`TokioRuntime`] via [`bind`]; [`bind_with_runtime`] overrides it.
    runtime: Arc<dyn Runtime>,
    /// Listener-wide observability (Phase 8 — OTel refactor). Wraps the
    /// lock-free hot-path atomics and (when the `telemetry-otel` feature is
    /// on) the OTel instrument holders. Exposed via [`observability`].
    observability: Arc<Observability>,
    /// Bounds concurrent in-flight handshakes (H4 decouple) — see
    /// [`MAX_INFLIGHT_HANDSHAKES`]. Distinct from any established-session cap.
    inflight: Arc<Semaphore>,
    /// Completed-handshake hand-off: the background acceptor pushes each
    /// established [`AcceptOutcome`] here and `accept()` drains it, so a slow or
    /// stalled handshake never blocks accepting (or `accept()`-ing) others.
    /// Bounded, so a non-draining embedder back-pressures to not accepting TCP.
    accepted_tx: mpsc::Sender<Arc<AcceptOutcome>>,
    accepted_rx: Mutex<mpsc::Receiver<Arc<AcceptOutcome>>>,
    /// The background acceptor task — lazily started on the first `accept()`,
    /// aborted on `Drop`. `Mutex<Option<_>>` makes the start one-shot.
    acceptor: parking_lot::Mutex<Option<SpawnHandle>>,
}

// Rust-only constructors that take a non-UniFFI type (`Arc<dyn Runtime>`).
// UniFFI doesn't support associated functions with non-UniFFI parameters
// inside an `#[uniffi::export]` block, so this `impl` block stays plain.
impl PhantomListener {
    /// Like [`bind`](Self::bind) but spawns accepted-session pumps on the
    /// supplied [`Runtime`]. Rust-only (not UniFFI-exported because
    /// `Arc<dyn Runtime>` is not a UniFFI type).
    pub async fn bind_with_runtime(
        addr: String,
        runtime: Arc<dyn Runtime>,
    ) -> Result<Arc<Self>, CoreError> {
        Self::bind_inner(addr, runtime, None).await
    }

    /// Like [`bind`](Self::bind) but uses the caller-supplied long-lived
    /// [`HybridSigningKey`] as the server's signing identity instead of
    /// generating a fresh one on every bind.
    ///
    /// This is the entry point for production embedders that persist
    /// the server's signing key across restarts so the verifying-key
    /// material clients pin does not change on every boot. The
    /// listener's [`verifying_key_bytes`](Self::verifying_key_bytes)
    /// will return the verifying half of `signing_key`.
    ///
    /// Rust-only (not UniFFI-exported because `HybridSigningKey` is
    /// not in the UniFFI surface).
    pub async fn bind_with_signing_key(
        addr: String,
        signing_key: HybridSigningKey,
    ) -> Result<Arc<Self>, CoreError> {
        Self::bind_inner(addr, Arc::new(TokioRuntime), Some(signing_key)).await
    }

    /// Composition of [`bind_with_signing_key`](Self::bind_with_signing_key)
    /// and [`bind_with_runtime`](Self::bind_with_runtime): supply both a
    /// long-lived signing key and a non-tokio [`Runtime`]. Rust-only.
    pub async fn bind_with_signing_key_with_runtime(
        addr: String,
        signing_key: HybridSigningKey,
        runtime: Arc<dyn Runtime>,
    ) -> Result<Arc<Self>, CoreError> {
        Self::bind_inner(addr, runtime, Some(signing_key)).await
    }

    /// Shared bind path. If `signing_key` is `Some`, the resulting
    /// [`HandshakeServer`] uses that long-lived key. Otherwise the
    /// historical generate-internal-key behavior is preserved.
    async fn bind_inner(
        addr: String,
        runtime: Arc<dyn Runtime>,
        signing_key: Option<HybridSigningKey>,
    ) -> Result<Arc<Self>, CoreError> {
        // Under `--features fips`, run the FIPS 140-3 §7.7 POST
        // before standing up the listener. A failure short-circuits
        // here with `CoreError::FipsSelfTestFailure` rather than
        // serving traffic over broken primitives. Cached after the
        // first call so subsequent binds in the same process pay
        // only an atomic read.
        #[cfg(feature = "fips")]
        crate::crypto::self_tests::ensure_post_passed()
            .map_err(|e| CoreError::FipsSelfTestFailure(format!("{e:?}")))?;

        let listener = Self::bind_with_optional_reuseport(&addr).await?;
        let local_addr = listener
            .local_addr()
            .map_err(|e| CoreError::NetworkError(format!("local_addr: {}", e)))?;
        let hs = match signing_key {
            Some(sk) => HandshakeServer::with_signing_key(sk),
            None => HandshakeServer::new(),
        }
        .map_err(|e| CoreError::InternalError(e.to_string()))?;
        let (accepted_tx, accepted_rx) = mpsc::channel(MAX_INFLIGHT_HANDSHAKES);
        Ok(Arc::new(Self {
            listener: Arc::new(listener),
            handshake_server: Arc::new(hs),
            local_addr,
            shutting_down: Arc::new(AtomicBool::new(false)),
            shutdown_notify: Arc::new(Notify::new()),
            runtime,
            observability: Observability::new(ObservabilityConfig::default()),
            inflight: Arc::new(Semaphore::new(MAX_INFLIGHT_HANDSHAKES)),
            accepted_tx,
            accepted_rx: Mutex::new(accepted_rx),
            acceptor: parking_lot::Mutex::new(None),
        }))
    }

    /// Bind a `TcpListener` with `SO_REUSEPORT` on Linux (Phase 2.9) so
    /// multiple listeners can share the same `(addr, port)` and the
    /// kernel load-balances incoming SYNs across them. Equivalent to
    /// running N independent accept-loops on the same port without a
    /// userspace dispatcher.
    ///
    /// On non-Linux targets `SO_REUSEPORT` is a no-op: macOS supports
    /// the option but with different semantics (no LB), Windows lacks
    /// it entirely. The fallback in both cases is a plain
    /// `TcpListener::bind`, which preserves the historical single-
    /// listener behavior.
    async fn bind_with_optional_reuseport(addr: &str) -> Result<TcpListener, CoreError> {
        #[cfg(target_os = "linux")]
        {
            use socket2::{Domain, Protocol, Socket, Type};
            let parsed: SocketAddr = addr
                .parse()
                .map_err(|e| CoreError::NetworkError(format!("invalid addr: {}", e)))?;
            let domain = if parsed.is_ipv4() {
                Domain::IPV4
            } else {
                Domain::IPV6
            };
            let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))
                .map_err(|e| CoreError::NetworkError(format!("socket: {}", e)))?;
            socket
                .set_reuse_address(true)
                .map_err(|e| CoreError::NetworkError(format!("SO_REUSEADDR: {}", e)))?;
            // Best-effort: SO_REUSEPORT requires Linux 3.9+. If the
            // kernel rejects it we still complete the bind without
            // load-balancing — degraded but functional.
            if let Err(e) = socket.set_reuse_port(true) {
                log::warn!("SO_REUSEPORT unsupported on this kernel: {}", e);
            }
            socket
                .set_nonblocking(true)
                .map_err(|e| CoreError::NetworkError(format!("set_nonblocking: {}", e)))?;
            socket
                .bind(&parsed.into())
                .map_err(|e| CoreError::NetworkError(format!("bind: {}", e)))?;
            socket
                .listen(1024)
                .map_err(|e| CoreError::NetworkError(format!("listen: {}", e)))?;
            let std_listener: std::net::TcpListener = socket.into();
            // Tail expression of the `cfg(linux)` block (which is the whole
            // function body after cfg-stripping on Linux) — no `return` needed.
            TcpListener::from_std(std_listener)
                .map_err(|e| CoreError::NetworkError(format!("from_std: {}", e)))
        }
        #[cfg(not(target_os = "linux"))]
        {
            TcpListener::bind(addr)
                .await
                .map_err(|e| CoreError::NetworkError(e.to_string()))
        }
    }
}

#[cfg_attr(feature = "bindings", uniffi::export(async_runtime = "tokio"))]
impl PhantomListener {
    #[cfg_attr(feature = "bindings", uniffi::constructor)]
    #[tracing::instrument(name = "phantom.listener.bind", skip_all, fields(addr = %addr))]
    pub async fn bind(addr: String) -> Result<Arc<Self>, CoreError> {
        Self::bind_inner(addr, Arc::new(TokioRuntime), None).await
    }

    /// The server's long-lived hybrid verifying key, serialized via
    /// `HybridVerifyingKey::to_bytes`. Clients MUST pin this value before
    /// completing a handshake to defeat MITM (see Vuln 1 in security review).
    pub fn verifying_key_bytes(&self) -> Vec<u8> {
        self.handshake_server.verifying_key().to_bytes()
    }

    /// Local socket address the listener is actually bound to (resolved at
    /// bind time). Useful when the caller passed `"host:0"` and needs to
    /// learn which port the OS assigned.
    pub fn local_addr(&self) -> String {
        self.local_addr.to_string()
    }

    /// Accept the next inbound connection and complete its handshake.
    ///
    /// Returns an [`AcceptOutcome`] — the established session plus any
    /// 0-RTT early-data the client carried on a V3 ClientHello. Use
    /// `.session()` for the session and `.take_early_data()` for the
    /// early-data (the latter is `None` for a plain V1/V2 handshake or
    /// when the server rejected the early-data).
    #[tracing::instrument(name = "phantom.listener.accept", skip_all)]
    pub async fn accept(&self) -> Result<Arc<AcceptOutcome>, CoreError> {
        // Cheap fast-path: if shutdown was already signalled before this
        // accept was even called, return immediately.
        if self.shutting_down.load(Ordering::Acquire) {
            return Err(CoreError::ConnectionClosed);
        }
        // Decoupled accept (H4): a background acceptor task owns the socket and
        // drives each handshake in its own deadline-bounded task, pushing the
        // established session here. `accept()` just returns the next completed
        // one — so a slow or stalled peer's handshake never blocks accepting (or
        // returning) other clients. Lazily start the acceptor on first use.
        self.ensure_acceptor();
        let mut rx = self.accepted_rx.lock().await;
        let shutdown_fut = self.shutdown_notify.notified();
        tokio::pin!(shutdown_fut);
        tokio::select! {
            biased;
            _ = &mut shutdown_fut => Err(CoreError::ConnectionClosed),
            item = rx.recv() => item.ok_or(CoreError::ConnectionClosed),
        }
    }

    /// Signal graceful shutdown (Phase 4.6).
    ///
    /// Sets the `shutting_down` flag and wakes any `accept()` call currently
    /// parked on the listener so it can unwind with
    /// `CoreError::ConnectionClosed`. Idempotent — calling more than once is
    /// safe. Already-accepted sessions are NOT affected; they continue
    /// serving until their owning task closes them.
    #[tracing::instrument(name = "phantom.listener.shutdown", skip_all)]
    pub fn shutdown(&self) {
        self.shutting_down.store(true, Ordering::Release);
        self.shutdown_notify.notify_waiters();
        // Stop the background acceptor promptly (idempotent; `Drop` also aborts).
        if let Some(handle) = self.acceptor.lock().as_ref() {
            handle.abort();
        }
    }

    /// Whether `shutdown()` has been called.
    pub fn is_shutting_down(&self) -> bool {
        self.shutting_down.load(Ordering::Acquire)
    }
}

// Rust-only accessors (not UniFFI-exported because the return type
// is not a UniFFI primitive).
impl PhantomListener {
    /// Borrow the underlying observability handle. Allows callers that need
    /// to plumb additional recordings (e.g., per-session aggregations)
    /// to share the listener's counter set.
    pub fn observability(&self) -> Arc<Observability> {
        self.observability.clone()
    }

    /// Lazily spawn the single background acceptor task (idempotent). It owns the
    /// listening socket; for each inbound connection it acquires an in-flight
    /// permit (bounding concurrent handshakes) and spawns a deadline-bounded
    /// handshake task whose established [`AcceptOutcome`] is pushed to
    /// `accepted_tx`. This decoupling is the H4 fix — the serial accept loop no
    /// longer blocks on any one handshake.
    ///
    /// Deliberately lives in this NON-`#[uniffi::export]` block: it is an
    /// internal lazy-init helper driven by `accept()`, not part of the public
    /// FFI surface. UniFFI 0.29 exports every method of an `#[uniffi::export]`
    /// impl block regardless of Rust visibility, so keeping it here is what
    /// keeps it out of the generated bindings.
    fn ensure_acceptor(&self) {
        let mut guard = self.acceptor.lock();
        if guard.is_some() {
            return;
        }
        let handle = self.runtime.spawn(Box::pin(run_acceptor(
            self.listener.clone(),
            self.handshake_server.clone(),
            self.inflight.clone(),
            self.accepted_tx.clone(),
            self.shutting_down.clone(),
            self.shutdown_notify.clone(),
            self.runtime.clone(),
            self.observability.clone(),
        )));
        *guard = Some(handle);
    }
}

/// Outcome of a successful [`PhantomListener::accept`] — the accepted
/// session plus any 0-RTT early-data the client carried on its V3
/// ClientHello (wire V3, Phase 4.1).
///
/// A `uniffi::Object` rather than a record: it returns an
/// `Arc<PhantomSession>` (itself a `uniffi::Object`) from a method,
/// the same known-good pattern `accept()` used before V3. `take_*`
/// is take-once so a ≤16 KiB blob is moved out, not cloned.
#[cfg_attr(feature = "bindings", derive(uniffi::Object))]
pub struct AcceptOutcome {
    session: Arc<PhantomSession>,
    early_data: parking_lot::Mutex<Option<Vec<u8>>>,
    peer_addr: SocketAddr,
}

#[cfg_attr(feature = "bindings", uniffi::export)]
impl AcceptOutcome {
    /// The accepted, fully-established session.
    pub fn session(&self) -> Arc<PhantomSession> {
        self.session.clone()
    }

    /// Take the 0-RTT early-data the client sent on its ClientHello.
    /// Take-once — a second call returns `None`. `None` also means the
    /// client sent no early-data, or the server rejected it (unknown /
    /// expired ticket, oversized blob, AEAD failure).
    pub fn take_early_data(&self) -> Option<Vec<u8>> {
        self.early_data.lock().take()
    }

    /// Whether 0-RTT early-data is present and not yet taken.
    pub fn has_early_data(&self) -> bool {
        self.early_data.lock().is_some()
    }
}

impl AcceptOutcome {
    pub(crate) fn new(
        session: Arc<PhantomSession>,
        early_data: Option<Vec<u8>>,
        peer_addr: SocketAddr,
    ) -> Arc<Self> {
        Arc::new(Self {
            session,
            early_data: parking_lot::Mutex::new(early_data),
            peer_addr,
        })
    }

    /// The remote socket address this session was accepted from. Rust-only
    /// (kept off the UniFFI surface, which avoids `SocketAddr`); embedders use
    /// it for per-peer admission control / connection accounting.
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }
}

/// Drive the server side of the Phantom hybrid PQC handshake on a freshly
/// accepted transport, handling the optional cookie / PoW retry round.
///
/// Returns the established `Session` plus any decrypted 0-RTT early-data
/// (`Some` only when the client carried a valid early-data blob).
async fn drive_server_handshake(
    transport: &TcpSessionTransport,
    hs: &HandshakeServer,
    client_ip: IpAddr,
) -> Result<(crate::transport::session::Session, Option<Vec<u8>>), CoreError> {
    let mut retry_rounds: u32 = 0;
    loop {
        let hello_bytes = transport.recv_bytes().await?;
        let client_hello = borsh::from_slice::<ClientHello>(&hello_bytes)
            .map_err(|e| CoreError::NetworkError(format!("ClientHello parse failed: {}", e)))?;

        // Adaptive PoW difficulty: the global load tier (idle => 0) raised to the
        // per-IP reputation escalation (DOS-2). A clean IP / ticket holder adds
        // nothing; an IP with recent handshake violations pays escalating PoW
        // even when the server is idle, so an abusive source is singled out.
        let has_ticket = client_hello.resume_session_id.is_some();
        let difficulty = hs
            .adaptive_difficulty()
            .max(hs.reputation_difficulty(client_ip, has_ticket));
        match hs.process_client_hello(&client_hello, difficulty, client_ip) {
            HandshakeResponse::Retry(retry) => {
                // DOS-4: bound the Retry rounds so a peer that keeps triggering
                // Retry without satisfying the cookie/PoW gate can't occupy the
                // handshake indefinitely.
                retry_rounds += 1;
                if retry_rounds > MAX_SERVER_RETRY_ROUNDS {
                    // A peer that never satisfies the gate is a genuine violation.
                    hs.record_violation(client_ip);
                    return Err(CoreError::HandshakeError(format!(
                        "client exceeded {MAX_SERVER_RETRY_ROUNDS} cookie/PoW retry rounds"
                    )));
                }
                let bytes = borsh::to_vec(&retry)
                    .map_err(|e| CoreError::NetworkError(format!("Retry encode failed: {}", e)))?;
                transport.send_bytes(&bytes).await?;
                // Loop back and read the retried hello.
            }
            HandshakeResponse::Success(server_hello, session, early_data) => {
                let bytes = borsh::to_vec(&server_hello).map_err(|e| {
                    CoreError::NetworkError(format!("ServerHello encode failed: {}", e))
                })?;
                transport.send_bytes(&bytes).await?;
                // DOS-2: a successful handshake clears this IP's escalation.
                hs.reset_violations(client_ip);
                return Ok((session, early_data));
            }
            HandshakeResponse::Reject(reject) => {
                // Forward-compat (H9): the client spoke a version we can't
                // satisfy. Hand back a typed reject so it gets an actionable
                // signal — the version we DO speak — instead of a silent drop,
                // then close. Best-effort: if the send fails the client just
                // sees the close, same as before.
                if let Ok(bytes) = borsh::to_vec(&reject) {
                    let _ = transport.send_bytes(&bytes).await;
                }
                // DOS-2: a structurally-unspeakable hello (e.g. wrong version /
                // build-variant) is a genuine protocol violation.
                hs.record_violation(client_ip);
                return Err(CoreError::InternalError(format!(
                    "handshake rejected: unsupported client version (server speaks v{})",
                    reject.supported_version
                )));
            }
            HandshakeResponse::Fail(e) => {
                hs.record_violation(client_ip);
                return Err(CoreError::InternalError(format!(
                    "handshake rejected: {}",
                    e
                )));
            }
        }
    }
}

/// Background acceptor loop (H4 decouple). Owns the listening socket; for each
/// inbound connection it bounds concurrency via `inflight`, then spawns a
/// deadline-bounded handshake task that pushes the established [`AcceptOutcome`]
/// to `accepted_tx`. A slow/stalled/failed handshake therefore never blocks
/// accepting other connections, and failed handshakes are dropped (logged +
/// recorded) rather than surfaced to `accept()`.
#[allow(clippy::too_many_arguments)]
async fn run_acceptor(
    listener: Arc<TcpListener>,
    hs: Arc<HandshakeServer>,
    inflight: Arc<Semaphore>,
    accepted_tx: mpsc::Sender<Arc<AcceptOutcome>>,
    shutting_down: Arc<AtomicBool>,
    shutdown_notify: Arc<Notify>,
    runtime: Arc<dyn Runtime>,
    observability: Arc<Observability>,
) {
    let mut accept_count: u64 = 0;
    loop {
        if shutting_down.load(Ordering::Acquire) {
            break;
        }
        let shutdown_fut = shutdown_notify.notified();
        tokio::pin!(shutdown_fut);
        let (stream, peer) = tokio::select! {
            biased;
            _ = &mut shutdown_fut => break,
            res = listener.accept() => match res {
                Ok(pair) => pair,
                Err(e) => {
                    log::warn!("PhantomListener: accept failed: {}", e);
                    continue;
                }
            },
        };
        // DOS-2: periodically drop expired reputation entries so the bounded map
        // stays small under churn (the cap already prevents unbounded growth).
        accept_count = accept_count.wrapping_add(1);
        if accept_count % 256 == 0 {
            hs.gc_reputation();
        }
        // Bound concurrent in-flight handshakes. The permit is held for the
        // handshake's lifetime AND until its result is queued, so a non-draining
        // embedder back-pressures all the way to not accepting new TCP.
        let permit = match inflight.clone().acquire_owned().await {
            Ok(p) => p,
            Err(_) => break, // semaphore closed — listener going away
        };
        let hs = hs.clone();
        let accepted_tx = accepted_tx.clone();
        let task_runtime = runtime.clone();
        let observability = observability.clone();
        // Drive THIS handshake in its own task so a stall never blocks the loop.
        runtime.spawn(Box::pin(async move {
            let _permit = permit; // released when this task ends
            let transport = TcpSessionTransport::new(stream);
            let started = Instant::now();
            // (A) In-library handshake deadline via the Runtime clock — a stalled
            // or byte-trickling peer is abandoned, never hanging a task forever.
            // Scoped so the borrow of `transport` ends before it is moved into
            // the session below.
            let result = {
                let hs_fut = drive_server_handshake(&transport, &hs, peer.ip());
                let deadline = task_runtime.sleep(HANDSHAKE_DEADLINE);
                tokio::pin!(hs_fut);
                tokio::select! {
                    r = &mut hs_fut => r,
                    _ = deadline => Err(CoreError::Timeout),
                }
            };
            match result {
                Ok((server_session, early_data)) => {
                    observability.record_handshake(
                        started.elapsed(),
                        HandshakeOutcome::Success,
                        LegType::Tcp,
                        AeadAlgorithm::Aes256Gcm,
                        ProtocolVersion::Current,
                    );
                    let session = PhantomSession::from_accepted_server_session_with_runtime(
                        peer.to_string(),
                        transport,
                        Arc::new(server_session),
                        task_runtime.clone(),
                        observability.clone(),
                    );
                    let outcome = AcceptOutcome::new(session, early_data, peer);
                    // Bounded hand-off; a send error means the listener was dropped.
                    let _ = accepted_tx.send(outcome).await;
                }
                Err(e) => {
                    observability.record_handshake(
                        started.elapsed(),
                        HandshakeOutcome::Failure,
                        LegType::Tcp,
                        AeadAlgorithm::Aes256Gcm,
                        ProtocolVersion::Current,
                    );
                    // Dropped, not surfaced to accept(): DoS noise from a bad/
                    // stalled peer must not block the embedder's accept loop.
                    log::debug!("PhantomListener: server handshake failed: {}", e);
                }
            }
        }));
    }
}

impl Drop for PhantomListener {
    /// Stop the background acceptor when the listener is dropped, so it does not
    /// outlive its owner accepting connections into a queue no one drains.
    fn drop(&mut self) {
        self.shutting_down.store(true, Ordering::Release);
        self.shutdown_notify.notify_waiters();
        if let Some(handle) = self.acceptor.lock().take() {
            handle.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hybrid_sign::HybridSigningKey;

    /// `bind_with_signing_key` pins the listener's verifying identity to
    /// the supplied long-lived signing key — exactly the contract
    /// production embedders that persist a key file rely on.
    #[tokio::test]
    async fn bind_with_signing_key_pins_verifying_identity() {
        // Serialise vs. the fips fault-injection test that flips
        // POST_RESULT. Harmless overhead on non-fips builds.
        let _guard = crate::crypto::self_tests::tests_serial_guard()
            .lock()
            .unwrap();
        crate::crypto::self_tests::set_force_post_fail(false);
        let (signing_key, verifying_key) = HybridSigningKey::generate();
        let expected_vk_bytes = verifying_key.to_bytes();

        let listener =
            PhantomListener::bind_with_signing_key("127.0.0.1:0".to_string(), signing_key)
                .await
                .expect("bind_with_signing_key should succeed on a free port");

        assert_eq!(
            listener.verifying_key_bytes(),
            expected_vk_bytes,
            "listener must expose the verifying half of the supplied signing key"
        );
    }

    /// Round-trip through `to_bytes`/`from_bytes` mimics the production
    /// "load from disk" flow and proves the listener pins the *same*
    /// identity the on-disk key encodes.
    #[tokio::test]
    async fn bind_with_signing_key_round_trips_via_bytes() {
        let _guard = crate::crypto::self_tests::tests_serial_guard()
            .lock()
            .unwrap();
        crate::crypto::self_tests::set_force_post_fail(false);
        let (orig_signing_key, orig_verifying_key) = HybridSigningKey::generate();
        let on_disk = orig_signing_key.to_bytes();
        // `HybridSigningKey` is not `Clone`; reload from bytes as a
        // server restart would.
        let reloaded =
            HybridSigningKey::from_bytes(&on_disk).expect("from_bytes round-trip should succeed");

        let listener = PhantomListener::bind_with_signing_key("127.0.0.1:0".to_string(), reloaded)
            .await
            .expect("bind_with_signing_key should succeed on a free port");

        assert_eq!(
            listener.verifying_key_bytes(),
            orig_verifying_key.to_bytes(),
            "reloaded-from-bytes signing key must yield the original verifying key"
        );
    }

    /// The plain `bind` constructor must keep its historical
    /// generate-internal-key semantics — every call produces a different
    /// verifying key. Pins the back-compat guarantee.
    #[tokio::test]
    async fn bind_still_generates_fresh_key_per_call() {
        let _guard = crate::crypto::self_tests::tests_serial_guard()
            .lock()
            .unwrap();
        crate::crypto::self_tests::set_force_post_fail(false);
        let l1 = PhantomListener::bind("127.0.0.1:0".to_string())
            .await
            .expect("first bind should succeed");
        let l2 = PhantomListener::bind("127.0.0.1:0".to_string())
            .await
            .expect("second bind should succeed");
        assert_ne!(
            l1.verifying_key_bytes(),
            l2.verifying_key_bytes(),
            "two independent binds must produce distinct verifying keys"
        );
    }

    /// Under `--features fips`, a POST failure short-circuits
    /// `bind*` with `CoreError::FipsSelfTestFailure`. Uses the
    /// `set_force_post_fail` test seam to inject the failure.
    #[cfg(feature = "fips")]
    #[tokio::test]
    async fn fips_post_failure_aborts_bind() {
        // Serialise with sibling fault-injection tests via the same
        // mutex they use.
        let _guard = crate::crypto::self_tests::tests_serial_guard()
            .lock()
            .unwrap();
        crate::crypto::self_tests::set_force_post_fail(true);
        let result = PhantomListener::bind("127.0.0.1:0".to_string()).await;
        crate::crypto::self_tests::set_force_post_fail(false);
        match result {
            Err(CoreError::FipsSelfTestFailure(msg)) => {
                assert!(
                    msg.contains("AES-256-GCM") || msg.contains("Aead"),
                    "expected message to mention the injected AEAD failure; got {msg}"
                );
            }
            Ok(_) => panic!("expected FipsSelfTestFailure, got Ok"),
            Err(other) => panic!("expected FipsSelfTestFailure, got {other:?}"),
        }
    }
}
