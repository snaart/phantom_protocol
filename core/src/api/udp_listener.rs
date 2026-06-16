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
use crate::transport::handshake::{
    client_hello_lengths_within_bounds, ClientHello, HandshakeServer, HelloRetryRequest,
    ServerReply, UdpAdmit,
};
use crate::transport::phantom_udp::datagram::{encode_datagrams, push_datagram, FragmentAssembler};
use crate::transport::phantom_udp::envelope::{ConnId, PacketType};
use crate::transport::session::CidSlide;
use crate::transport::types::LegType;
use bytes::Bytes;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
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
    /// Live gauge mirroring the demux `routes` table size (H-1 observability). The
    /// demux owns the table; this lets `active_route_count()` read it without a lock.
    active_routes: Arc<AtomicUsize>,
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
            active_routes: Arc::new(AtomicUsize::new(0)),
        }))
    }

    pub fn verifying_key_bytes(&self) -> Vec<u8> {
        self.handshake_server.verifying_key().to_bytes()
    }
    pub fn local_addr(&self) -> String {
        self.local_addr.to_string()
    }

    /// Number of live demux routes (one per in-flight handshake or established
    /// session). Bounded by reaping + a hard cap (H-1); exposed so a fresh-CID
    /// spray's failure to grow this without bound is observable/testable.
    pub fn active_route_count(&self) -> usize {
        self.active_routes.load(Ordering::Relaxed)
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

/// Hard upper bound on concurrent demux routes (H-1 backstop). One route exists per
/// in-flight handshake, plus — once established — a session's rotating-CID **window**
/// of `CID_WINDOW_TRAILING + CID_WINDOW_LEADING + 1` (= 19) routes (ε / WIRE v5).
/// Reaping keeps the steady-state size near the in-flight ceiling, and this cap bounds
/// memory even if reaping ever lagged. A fresh-CID spray cannot grow the map past this —
/// excess `Initial`s are dropped (the peer retransmits). `1 << 18` (raised from `1 << 16`
/// when EPS-01 widened the per-session window 7→19) preserves the concurrent-session
/// capacity: `(1 << 18) / 19 ≈ 13.8k` live sessions, above the prior `(1 << 16) / 7 ≈ 9.4k`.
const MAX_ROUTES: usize = 1 << 18;

/// ε / WIRE v5: a session's inbound rotating-CID window paired with its inbound
/// channel — the payload the handshake task sends the demux to install the
/// window CIDs (N:1) so the client's `CID_0..` datagrams route to the session.
type CidWindowRegistration = (Vec<ConnId>, mpsc::Sender<(Bytes, SocketAddr)>);

/// Bounded, self-reaping demux route table keyed on the unauthenticated 8-byte CID (H-1).
/// A route's liveness is exactly its inbound channel's: a closed `Sender` (`is_closed()`)
/// means the handshake task failed or the established session was dropped, so the entry is
/// reclaimable. The `gauge` mirrors `len()` so `active_route_count()` can read the size
/// without a lock. A live session's route is never evicted to admit a new connection.
struct RouteTable {
    routes: HashMap<ConnId, mpsc::Sender<(Bytes, SocketAddr)>>,
    gauge: Arc<AtomicUsize>,
}

impl RouteTable {
    fn new(gauge: Arc<AtomicUsize>) -> Self {
        gauge.store(0, Ordering::Relaxed);
        Self {
            routes: HashMap::new(),
            gauge,
        }
    }

    fn sync(&self) {
        self.gauge.store(self.routes.len(), Ordering::Relaxed);
    }

    fn get(&self, cid: &ConnId) -> Option<&mpsc::Sender<(Bytes, SocketAddr)>> {
        self.routes.get(cid)
    }

    /// Reclaim every route whose receiver was dropped (failed handshake / gone session).
    fn reap_dead(&mut self) {
        self.routes.retain(|_, tx| !tx.is_closed());
        self.sync();
    }

    /// Insert a fresh route, enforcing `MAX_ROUTES`. Reaps dead entries first when at the
    /// cap; returns `false` (inserting nothing) only if still full of *live* routes, so the
    /// caller drops the new `Initial`. A live route is never evicted to admit a new one.
    fn try_insert(&mut self, cid: ConnId, tx: mpsc::Sender<(Bytes, SocketAddr)>) -> bool {
        if self.routes.len() >= MAX_ROUTES {
            self.reap_dead();
            if self.routes.len() >= MAX_ROUTES {
                return false;
            }
        }
        self.routes.insert(cid, tx);
        self.sync();
        true
    }

    /// Remove a CID iff its route is dead. Safe for any CID — a live session's route (its
    /// `Sender` still held by the running session) is left untouched.
    fn remove_if_dead(&mut self, cid: &ConnId) {
        if self.routes.get(cid).is_some_and(|tx| tx.is_closed()) {
            self.routes.remove(cid);
            self.sync();
        }
    }

    /// ε / WIRE v5: register the rotating-CID demux window — insert each window
    /// CID → the session's inbound channel (N:1), so a datagram stamped with any
    /// CID in the window routes to this session. `try_insert` reaps dead entries
    /// at the cap; a CID that can't be inserted (table full of *live* routes) is
    /// skipped — the peer retransmits, and the window stays bounded by MAX_ROUTES.
    /// The bootstrap CID (registered separately at Initial accept) stays alongside
    /// the window until the whole session's routes are reaped on disconnect.
    fn register_window(&mut self, cids: &[ConnId], tx: &mpsc::Sender<(Bytes, SocketAddr)>) {
        for &cid in cids {
            self.try_insert(cid, tx.clone());
        }
    }

    /// ε / WIRE v5 (P4b): apply a one-step inbound-window slide — register the new
    /// leading-edge CIDs and drop the trailing ones — resolving the session's
    /// channel through `anchor` (a CID still routed for it). A no-op if `anchor` is
    /// gone (the session ended), so a late slide for a dead session does nothing.
    fn apply_slide(&mut self, slide: &CidSlide) {
        let Some(tx) = self.routes.get(&slide.anchor).cloned() else {
            return;
        };
        for &cid in &slide.add {
            self.try_insert(cid, tx.clone());
        }
        for cid in &slide.remove {
            self.routes.remove(cid);
        }
        self.sync();
    }
}

/// Max concurrent in-flight (un-established) handshakes one source IP may hold (H-2). Bounds
/// a single address-validated source from monopolising the `inflight` permits; sized below
/// `MAX_INFLIGHT_HANDSHAKES` so several distinct sources always share, yet generous for a
/// busy NAT.
const MAX_PENDING_PER_IP: u32 = 64;

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
    // sessions) are reclaimed promptly via `reap_rx` and on the `% 256` cadence, with the
    // hard `MAX_ROUTES` cap as a backstop, so a fresh-CID spray cannot grow it unboundedly.
    let mut routes = RouteTable::new(listener.active_routes.clone());
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
    let (register_tx, mut register_rx) = mpsc::unbounded_channel::<CidWindowRegistration>();
    // ε / WIRE v5 (P4b): a session whose peer migrated signals a one-step inbound
    // CID-window slide here (post-AEAD, from handle_packet via the session's
    // slide channel). The demux registers the new leading-edge CID and drops the
    // trailing one, keeping the window tracking the peer's outbound index.
    let (slide_tx, mut slide_rx) = mpsc::unbounded_channel::<CidSlide>();
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
            Some((cids, tx)) = register_rx.recv() => {
                routes.register_window(&cids, &tx);
                continue;
            }
            // ε / WIRE v5 (P4b): slide a session's inbound CID window as its peer
            // migrates (add the new leading CID, drop the trailing one).
            Some(slide) = slide_rx.recv() => {
                routes.apply_slide(&slide);
                continue;
            }
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
            let dead = tx.try_send((Bytes::from(frame), peer)).is_err() && tx.is_closed();
            if dead {
                routes.remove_if_dead(&hdr.cid);
            }
            continue;
        }
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
        // H-1: refuse the route (and the slot) when the table is full of *live* routes.
        if !routes.try_insert(hdr.cid, tx.clone()) {
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
            slide_tx.clone(),
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
    register_tx: mpsc::UnboundedSender<CidWindowRegistration>,
    // ε / WIRE v5 (P4b): handed to the established session so it can signal
    // inbound-window slides as the peer migrates.
    slide_tx: mpsc::UnboundedSender<CidSlide>,
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
                // ε / WIRE v5: register this session's inbound CID window so the
                // client's post-handshake rotating CID_0.. datagrams route to it
                // (sent BEFORE moving `server_session` into the API session). The
                // bootstrap CID stays until the route is reaped on disconnect.
                let _ = register_tx.send((server_session.inbound_window_cids(), tx));
                // ε / WIRE v5 (P4b): give the session the demux slide channel so
                // it can advance its inbound CID window as the peer migrates.
                server_session.set_cid_slide_tx(slide_tx);
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
