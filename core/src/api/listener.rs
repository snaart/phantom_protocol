use crate::api::session::{PhantomSession, SessionTransport};
use crate::api::tcp_transport::TcpSessionTransport;
use crate::crypto::hybrid_sign::HybridSigningKey;
use crate::errors::CoreError;
use crate::runtime::{Runtime, TokioRuntime};
use crate::transport::handshake::{
    ClientHelloEnvelope, HandshakeResponse, HandshakeServer, HelloRetryRequestEnvelope,
    ServerHelloEnvelope,
};
use crate::observability::{Observability, ObservabilityConfig};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::net::TcpListener;
use tokio::sync::{Mutex, Notify};

#[derive(uniffi::Object)]
pub struct PhantomListener {
    listener: Mutex<TcpListener>,
    handshake_server: Arc<HandshakeServer>,
    /// The local socket address the listener is actually bound to.
    /// Cached so callers can read it without acquiring the listener mutex.
    /// Useful when `bind("0.0.0.0:0")` is used and the OS chose the port.
    local_addr: SocketAddr,
    /// Graceful-shutdown signal (Phase 4.6). `shutdown()` flips
    /// `shutting_down` and wakes all `accept()` calls currently parked
    /// on the listener so they can unwind cleanly.
    shutting_down: AtomicBool,
    shutdown_notify: Arc<Notify>,
    /// Async runtime used for spawning accepted-session data pumps
    /// (Phase 3.1). Defaults to [`TokioRuntime`] via [`bind`]; callers
    /// that need a non-tokio runtime use [`bind_with_runtime`].
    runtime: Arc<dyn Runtime>,
    /// Listener-wide observability (Phase 8 — OTel refactor). Wraps the
    /// lock-free hot-path atomics and (when the `telemetry-otel` feature is
    /// on) the OTel instrument holders. Exposed via [`observability`].
    observability: Arc<Observability>,
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
        // A7 — under `--features fips`, run the FIPS 140-3 §7.7 POST
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
        Ok(Arc::new(Self {
            listener: Mutex::new(listener),
            handshake_server: Arc::new(hs),
            local_addr,
            shutting_down: AtomicBool::new(false),
            shutdown_notify: Arc::new(Notify::new()),
            runtime,
            observability: Observability::new(ObservabilityConfig::default()),
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
            return TcpListener::from_std(std_listener)
                .map_err(|e| CoreError::NetworkError(format!("from_std: {}", e)));
        }
        #[cfg(not(target_os = "linux"))]
        {
            TcpListener::bind(addr)
                .await
                .map_err(|e| CoreError::NetworkError(e.to_string()))
        }
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl PhantomListener {
    #[uniffi::constructor]
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
        let listener_guard = self.listener.lock().await;
        let shutdown_fut = self.shutdown_notify.notified();
        tokio::pin!(shutdown_fut);
        let (stream, peer) = tokio::select! {
            result = listener_guard.accept() => {
                result.map_err(|e| CoreError::NetworkError(e.to_string()))?
            }
            _ = &mut shutdown_fut => {
                return Err(CoreError::ConnectionClosed);
            }
        };
        // Release the listener lock before driving the handshake, so other
        // tasks can call accept again concurrently.
        drop(listener_guard);
        let transport = TcpSessionTransport::new(stream);
        // Phase 4.5 metrics: time the full handshake from accept to
        // session-installed; account success vs failure separately.
        let started = Instant::now();
        let (server_session, early_data) =
            match drive_server_handshake(&transport, &self.handshake_server, peer.ip()).await {
                Ok(pair) => pair,
                Err(e) => {
                    self.observability.record_handshake_failure();
                    return Err(e);
                }
            };
        let elapsed_ns = started.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64;
        self.observability.record_handshake_success(elapsed_ns);
        // Reference server accepts over TCP today; tighten when WebSocket /
        // KCP variants land.
        self.observability
            .session_opened(crate::transport::types::LegType::Tcp);
        let session = PhantomSession::from_accepted_server_session_with_runtime(
            peer.to_string(),
            transport,
            Arc::new(server_session),
            self.runtime.clone(),
        );
        Ok(AcceptOutcome::new(session, early_data))
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
}

/// Outcome of a successful [`PhantomListener::accept`] — the accepted
/// session plus any 0-RTT early-data the client carried on its V3
/// ClientHello (wire V3, Phase 4.1).
///
/// A `uniffi::Object` rather than a record: it returns an
/// `Arc<PhantomSession>` (itself a `uniffi::Object`) from a method,
/// the same known-good pattern `accept()` used before V3. `take_*`
/// is take-once so a ≤16 KiB blob is moved out, not cloned.
#[derive(uniffi::Object)]
pub struct AcceptOutcome {
    session: Arc<PhantomSession>,
    early_data: parking_lot::Mutex<Option<Vec<u8>>>,
}

#[uniffi::export]
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
    pub(crate) fn new(session: Arc<PhantomSession>, early_data: Option<Vec<u8>>) -> Arc<Self> {
        Arc::new(Self {
            session,
            early_data: parking_lot::Mutex::new(early_data),
        })
    }
}

/// Drive the server side of the Phantom hybrid PQC handshake on a freshly
/// accepted transport, handling the optional cookie / PoW retry round.
///
/// Returns the established `Session` plus any decrypted 0-RTT
/// early-data (`Some` only on a V3 handshake where the client carried
/// a valid early-data blob).
async fn drive_server_handshake(
    transport: &TcpSessionTransport,
    hs: &HandshakeServer,
    client_ip: IpAddr,
) -> Result<(crate::transport::session::Session, Option<Vec<u8>>), CoreError> {
    loop {
        let hello_bytes = transport.recv_bytes().await?;
        // Wire V3: hello messages are version-prefixed envelopes.
        // `V12` and `V3` dispatch to their respective server paths; an
        // unknown / future discriminant surfaces as a borsh parse error.
        let envelope = borsh::from_slice::<ClientHelloEnvelope>(&hello_bytes)
            .map_err(|e| CoreError::NetworkError(format!("ClientHello parse failed: {}", e)))?;

        // Adaptive PoW difficulty (Phase 1.14): under load the listener
        // automatically requires more proof-of-work from each new client.
        // At idle (<100 handshakes/min) this stays at 0 and PoW is skipped
        // entirely.
        let difficulty = hs.adaptive_difficulty();
        let response = match &envelope {
            ClientHelloEnvelope::V12(ch) => hs.process_client_hello(ch, difficulty, client_ip),
            ClientHelloEnvelope::V3(ch3) => hs.process_client_hello_v3(ch3, difficulty, client_ip),
        };
        match response {
            HandshakeResponse::Retry(retry) => {
                let bytes = borsh::to_vec(&HelloRetryRequestEnvelope::V12(retry))
                    .map_err(|e| CoreError::NetworkError(format!("Retry encode failed: {}", e)))?;
                transport.send_bytes(&bytes).await?;
                // Loop back and read the retried hello.
            }
            HandshakeResponse::Success(server_hello, session) => {
                let bytes =
                    borsh::to_vec(&ServerHelloEnvelope::V12(server_hello)).map_err(|e| {
                        CoreError::NetworkError(format!("ServerHello encode failed: {}", e))
                    })?;
                transport.send_bytes(&bytes).await?;
                return Ok((session, None));
            }
            HandshakeResponse::SuccessV3(server_hello_v3, session, early_data) => {
                let bytes =
                    borsh::to_vec(&ServerHelloEnvelope::V3(server_hello_v3)).map_err(|e| {
                        CoreError::NetworkError(format!("ServerHelloV3 encode failed: {}", e))
                    })?;
                transport.send_bytes(&bytes).await?;
                return Ok((session, early_data));
            }
            HandshakeResponse::Fail(e) => {
                return Err(CoreError::InternalError(format!(
                    "handshake rejected: {}",
                    e
                )));
            }
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

    /// A7 — under `--features fips`, a POST failure short-circuits
    /// `bind*` with `CoreError::FipsSelfTestFailure`. Uses the
    /// `set_force_post_fail` test seam to inject the failure.
    #[cfg(feature = "fips")]
    #[tokio::test]
    async fn fips_post_failure_aborts_bind() {
        // Serialise with sibling fault-injection tests via the same
        // mutex they use.
        let _guard = crate::crypto::self_tests::tests_serial_guard().lock().unwrap();
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
