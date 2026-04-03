use crate::api::session::{PhantomSession, SessionTransport};
use crate::api::tcp_transport::TcpSessionTransport;
use crate::errors::CoreError;
use crate::runtime::{Runtime, TokioRuntime};
use crate::transport::handshake::{
    ClientHelloEnvelope, HandshakeResponse, HandshakeServer, HelloRetryRequestEnvelope,
    ServerHelloEnvelope,
};
use crate::transport::metrics::TransportMetrics;
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
    /// Listener-wide metrics (Phase 4.5). Tracks accept-side counters
    /// — handshake success/failure, latency histogram, active-session
    /// gauge. Exposed via [`metrics_prometheus_text`].
    metrics: Arc<TransportMetrics>,
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
        Self::bind_inner(addr, runtime).await
    }

    async fn bind_inner(addr: String, runtime: Arc<dyn Runtime>) -> Result<Arc<Self>, CoreError> {
        let listener = Self::bind_with_optional_reuseport(&addr).await?;
        let local_addr = listener
            .local_addr()
            .map_err(|e| CoreError::NetworkError(format!("local_addr: {}", e)))?;
        let hs = HandshakeServer::new().map_err(|e| CoreError::InternalError(e.to_string()))?;
        Ok(Arc::new(Self {
            listener: Mutex::new(listener),
            handshake_server: Arc::new(hs),
            local_addr,
            shutting_down: AtomicBool::new(false),
            shutdown_notify: Arc::new(Notify::new()),
            runtime,
            metrics: Arc::new(TransportMetrics::new()),
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

#[uniffi::export]
impl PhantomListener {
    #[uniffi::constructor]
    #[tracing::instrument(name = "phantom.listener.bind", skip_all, fields(addr = %addr))]
    pub async fn bind(addr: String) -> Result<Arc<Self>, CoreError> {
        Self::bind_inner(addr, Arc::new(TokioRuntime)).await
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

    #[tracing::instrument(name = "phantom.listener.accept", skip_all)]
    pub async fn accept(&self) -> Result<Arc<PhantomSession>, CoreError> {
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
        let server_session =
            match drive_server_handshake(&transport, &self.handshake_server, peer.ip()).await {
                Ok(s) => s,
                Err(e) => {
                    self.metrics.record_handshake_failure();
                    return Err(e);
                }
            };
        let elapsed_ns = started.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64;
        self.metrics.record_handshake_success(elapsed_ns);
        self.metrics.session_opened();
        Ok(PhantomSession::from_accepted_server_session_with_runtime(
            peer.to_string(),
            transport,
            Arc::new(server_session),
            self.runtime.clone(),
        ))
    }

    /// Return the listener's metrics rendered in Prometheus text
    /// exposition format (Phase 4.5). Suitable for serving from a
    /// `/metrics` HTTP endpoint — the SDK does not bundle an HTTP
    /// server, downstream applications wire one up.
    pub fn metrics_prometheus_text(&self) -> String {
        self.metrics.snapshot().to_prometheus_text()
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
    /// Borrow the underlying metrics handle. Allows callers that need
    /// to plumb additional recordings (e.g., per-session aggregations)
    /// to share the listener's counter set.
    pub fn metrics(&self) -> Arc<TransportMetrics> {
        self.metrics.clone()
    }
}

/// Drive the server side of the Phantom hybrid PQC handshake on a freshly
/// accepted transport, handling the optional cookie / PoW retry round.
async fn drive_server_handshake(
    transport: &TcpSessionTransport,
    hs: &HandshakeServer,
    client_ip: IpAddr,
) -> Result<crate::transport::session::Session, CoreError> {
    loop {
        let hello_bytes = transport.recv_bytes().await?;
        // Wire V3: hello messages are version-prefixed envelopes. Only the
        // `V12` arm is decodable today; a future / unknown discriminant
        // surfaces as a borsh parse error.
        let hello = match borsh::from_slice::<ClientHelloEnvelope>(&hello_bytes) {
            Ok(ClientHelloEnvelope::V12(ch)) => ch,
            Err(e) => {
                return Err(CoreError::NetworkError(format!(
                    "ClientHello parse failed: {}",
                    e
                )))
            }
        };
        // Adaptive PoW difficulty (Phase 1.14): under load the listener
        // automatically requires more proof-of-work from each new client.
        // At idle (<100 handshakes/min) this stays at 0 and PoW is skipped
        // entirely.
        let difficulty = hs.adaptive_difficulty();
        match hs.process_client_hello(&hello, difficulty, client_ip) {
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
                return Ok(session);
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
