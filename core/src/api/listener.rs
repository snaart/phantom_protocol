use crate::api::session::{PhantomSession, SessionTransport};
use crate::api::tcp_transport::TcpSessionTransport;
use crate::errors::CoreError;
use crate::transport::handshake::{
    ClientHello, HandshakeResponse, HandshakeServer,
};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
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
}

#[uniffi::export]
impl PhantomListener {
    #[uniffi::constructor]
    #[tracing::instrument(name = "phantom.listener.bind", skip_all, fields(addr = %addr))]
    pub async fn bind(addr: String) -> Result<Arc<Self>, CoreError> {
        let listener = TcpListener::bind(&addr)
            .await
            .map_err(|e| CoreError::NetworkError(e.to_string()))?;
        let local_addr = listener
            .local_addr()
            .map_err(|e| CoreError::NetworkError(format!("local_addr: {}", e)))?;
        let hs = HandshakeServer::new()
            .map_err(|e| CoreError::InternalError(e.to_string()))?;
        Ok(Arc::new(Self {
            listener: Mutex::new(listener),
            handshake_server: Arc::new(hs),
            local_addr,
            shutting_down: AtomicBool::new(false),
            shutdown_notify: Arc::new(Notify::new()),
        }))
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
        let server_session =
            drive_server_handshake(&transport, &self.handshake_server, peer.ip()).await?;
        Ok(PhantomSession::from_accepted_server_session(
            peer.to_string(),
            transport,
            Arc::new(server_session),
        ))
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

/// Drive the server side of the Phantom hybrid PQC handshake on a freshly
/// accepted transport, handling the optional cookie / PoW retry round.
async fn drive_server_handshake(
    transport: &TcpSessionTransport,
    hs: &HandshakeServer,
    client_ip: IpAddr,
) -> Result<crate::transport::session::Session, CoreError> {
    loop {
        let hello_bytes = transport.recv_bytes().await?;
        let hello = borsh::from_slice::<ClientHello>(&hello_bytes).map_err(|e| {
            CoreError::NetworkError(format!("ClientHello parse failed: {}", e))
        })?;
        // Adaptive PoW difficulty (Phase 1.14): under load the listener
        // automatically requires more proof-of-work from each new client.
        // At idle (<100 handshakes/min) this stays at 0 and PoW is skipped
        // entirely.
        let difficulty = hs.adaptive_difficulty();
        match hs.process_client_hello(&hello, difficulty, client_ip) {
            HandshakeResponse::Retry(retry) => {
                let bytes = borsh::to_vec(&retry).map_err(|e| {
                    CoreError::NetworkError(format!("Retry encode failed: {}", e))
                })?;
                transport.send_bytes(&bytes).await?;
                // Loop back and read the retried hello.
            }
            HandshakeResponse::Success(server_hello, session) => {
                let bytes = borsh::to_vec(&server_hello).map_err(|e| {
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
