//! PhantomUDP server listener: one bound `UdpSocket`, a central demux task routing datagrams by the
//! 8-byte connection-ID into per-session channels, and a decoupled accept queue mirroring
//! `PhantomListener`. Rust-only in Phase 1 (no UniFFI surface yet).
//!
//! Phase 1 uses a single shared `FragmentAssembler` for reassembly across all CIDs (bounded by the
//! assembler's own anti-DoS caps); per-CID isolation is a Phase-2 refinement — see `run_udp_demux`.

use crate::api::listener::{drive_server_handshake, AcceptOutcome};
use crate::api::session::PhantomSession;
use crate::api::udp_transport::UdpServerTransport;
use crate::crypto::hybrid_sign::HybridSigningKey;
use crate::errors::CoreError;
use crate::observability::attrs::{AeadAlgorithm, HandshakeOutcome, ProtocolVersion};
use crate::observability::{Observability, ObservabilityConfig};
use crate::runtime::{Runtime, SpawnHandle, TokioRuntime};
use crate::transport::handshake::HandshakeServer;
use crate::transport::phantom_udp::datagram::{push_datagram, FragmentAssembler};
use crate::transport::phantom_udp::envelope::{ConnId, PacketType};
use crate::transport::types::LegType;
use bytes::Bytes;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
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
}

impl PhantomUdpListener {
    pub async fn bind_udp(addr: String) -> Result<Arc<Self>, CoreError> {
        Self::bind_inner(addr, Arc::new(TokioRuntime), None).await
    }

    pub async fn bind_udp_with_signing_key(
        addr: String,
        signing_key: HybridSigningKey,
    ) -> Result<Arc<Self>, CoreError> {
        Self::bind_inner(addr, Arc::new(TokioRuntime), Some(signing_key)).await
    }

    async fn bind_inner(
        addr: String,
        runtime: Arc<dyn Runtime>,
        signing_key: Option<HybridSigningKey>,
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
        let hs = match signing_key {
            Some(sk) => HandshakeServer::with_signing_key(sk),
            None => HandshakeServer::new(),
        }
        .map_err(|e| CoreError::InternalError(e.to_string()))?;
        let (accepted_tx, accepted_rx) = mpsc::channel(MAX_INFLIGHT_HANDSHAKES);
        Ok(Arc::new(Self {
            socket: Arc::new(socket),
            handshake_server: Arc::new(hs),
            local_addr,
            shutting_down: Arc::new(AtomicBool::new(false)),
            shutdown_notify: Arc::new(Notify::new()),
            runtime,
            observability: Observability::new(ObservabilityConfig::default()),
            inflight: Arc::new(Semaphore::new(MAX_INFLIGHT_HANDSHAKES)),
            accepted_tx,
            accepted_rx: Mutex::new(accepted_rx),
            demux: parking_lot::Mutex::new(None),
        }))
    }

    pub fn verifying_key_bytes(&self) -> Vec<u8> {
        self.handshake_server.verifying_key().to_bytes()
    }
    pub fn local_addr(&self) -> String {
        self.local_addr.to_string()
    }

    pub async fn accept(self: &Arc<Self>) -> Result<Arc<AcceptOutcome>, CoreError> {
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

    pub fn shutdown(&self) {
        self.shutting_down.store(true, Ordering::Release);
        self.shutdown_notify.notify_waiters();
        if let Some(h) = self.demux.lock().as_ref() {
            h.abort();
        }
    }

    fn ensure_demux(self: &Arc<Self>) {
        let mut guard = self.demux.lock();
        if guard.is_some() {
            return;
        }
        let handle = self.runtime.spawn(Box::pin(run_udp_demux(self.clone())));
        *guard = Some(handle);
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

/// Central demux: own the socket, route each datagram by its connection-ID.
async fn run_udp_demux(listener: Arc<PhantomUdpListener>) {
    let mut routes: HashMap<ConnId, mpsc::Sender<(Bytes, SocketAddr)>> = HashMap::new();
    // NOTE (Phase 1): one assembler shared across ALL CIDs. Its key includes the cid, but a fragment
    // spray shares the single 256-slot assembly table with every live session's in-flight
    // reassemblies. Bounded — the assembler self-caps at MAX_CONCURRENT_ASSEMBLIES with
    // stalest-eviction, so no memory blowup — but a cross-connection isolation weakness the
    // per-socket client side does not have. A per-CID / per-route assembler is the Phase-2 fix.
    let mut asm = FragmentAssembler::new();
    let mut new_conn_count: u64 = 0;
    let mut buf = vec![0u8; crate::transport::phantom_udp::envelope::PATH_MTU + 64];
    loop {
        if listener.shutting_down.load(Ordering::Acquire) {
            break;
        }
        let shutdown_fut = listener.shutdown_notify.notified();
        tokio::pin!(shutdown_fut);
        let (n, peer) = tokio::select! {
            biased;
            _ = &mut shutdown_fut => break,
            r = listener.socket.recv_from(&mut buf) => match r {
                Ok(v) => v,
                Err(e) => { log::warn!("PhantomUdpListener: recv_from: {e}"); continue; }
            },
        };
        let (hdr, frame) = match push_datagram(&mut asm, &buf[..n]) {
            Ok((h, Some(f))) => (h, f),
            Ok((_h, None)) => continue, // partial fragment buffered
            Err(_) => continue,         // malformed; drop (anti-DoS noise floor)
        };
        // Existing connection: deliver the inner frame.
        if let Some(tx) = routes.get(&hdr.cid) {
            if tx.try_send((Bytes::from(frame), peer)).is_err() && tx.is_closed() {
                routes.remove(&hdr.cid);
            }
            continue;
        }
        // New connection: only an Initial (handshake) starts one.
        if hdr.ty != PacketType::Initial {
            continue; // unknown OneRtt/Retry -> drop
        }
        let permit = match listener.inflight.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => continue, // at capacity -> drop new handshakes (DoS bound)
        };
        let (tx, rx) = mpsc::channel(SESSION_CHANNEL_DEPTH);
        let st = UdpServerTransport::new(listener.socket.clone(), peer, hdr.cid, rx);
        routes.insert(hdr.cid, tx.clone());
        let _ = tx.try_send((Bytes::from(frame), peer));
        spawn_handshake_task(listener.clone(), st, peer, permit);
        // DoS-hardening parity with the TCP acceptor: periodically drop expired
        // reputation entries so the bounded map stays small under new-connection churn.
        new_conn_count = new_conn_count.wrapping_add(1);
        if new_conn_count % 256 == 0 {
            listener.handshake_server.gc_reputation();
        }
    }
}

fn spawn_handshake_task(
    listener: Arc<PhantomUdpListener>,
    transport: UdpServerTransport,
    peer: SocketAddr,
    permit: tokio::sync::OwnedSemaphorePermit,
) {
    let hs = listener.handshake_server.clone();
    let runtime = listener.runtime.clone();
    let observability = listener.observability.clone();
    let accepted_tx = listener.accepted_tx.clone();
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
                let session = PhantomSession::from_accepted_server_session_with_runtime(
                    peer.to_string(),
                    transport,
                    Arc::new(server_session),
                    task_runtime.clone(),
                    observability.clone(),
                    LegType::Udp,
                );
                let outcome = AcceptOutcome::new(session, early_data, peer);
                let _ = accepted_tx.send(outcome).await;
            }
            Err(e) => {
                observability.record_handshake(
                    started.elapsed(),
                    HandshakeOutcome::Failure,
                    LegType::Udp,
                    AeadAlgorithm::Aes256Gcm,
                    ProtocolVersion::Current,
                );
                log::debug!("PhantomUdpListener: handshake failed: {e}");
            }
        }
    }));
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
