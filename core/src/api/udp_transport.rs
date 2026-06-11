//! `SessionTransport` impls over raw UDP (PhantomUDP). `UdpClientTransport` is a connected-socket
//! client; a later task adds `UdpServerTransport` (a per-session shim fed by the listener demux). Both
//! add / strip the outer `[flags][cid]` envelope exactly as `TcpSessionTransport` adds / strips its
//! 4-byte length prefix, so `run_data_pump` / `run_client_handshake` / `drive_server_handshake` are reused.

use crate::api::session::{FramePhase, SessionTransport};
use crate::errors::CoreError;
use crate::transport::phantom_udp::datagram::{encode_datagrams, push_datagram, FragmentAssembler};
use crate::transport::phantom_udp::envelope::{ConnId, PacketType, PATH_MTU};
// `HDR_LEN` is referenced only by the test module (`super::HDR_LEN`); a plain top-level
// import trips clippy's `--lib` unused-import check, which excludes `#[cfg(test)]` code.
#[cfg(test)]
use crate::transport::phantom_udp::envelope::HDR_LEN;
use arc_swap::ArcSwap;
use bytes::Bytes;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex};

/// Retransmit timeout for the Handshake phase stop-and-wait shim.
const HANDSHAKE_RTO: Duration = Duration::from_millis(400);
/// Max Handshake-phase retransmits before giving up (the outer 10s connect deadline still applies).
const MAX_HANDSHAKE_RETX: u32 = 6;

const PHASE_HANDSHAKE: u8 = 0;
const PHASE_ESTABLISHED: u8 = 1;

pub struct UdpClientTransport {
    /// Active send/recv socket. `ArcSwap` so `migrate()` can atomically rebind to a
    /// new local socket (Phase 4 / P4.2b) without re-handshake; `send_bytes` and the
    /// recv loop reload it per call.
    socket: ArcSwap<UdpSocket>,
    /// The previous socket, retained during a migration overlap so the client keeps
    /// receiving downstream data on the old path until the new path shows life
    /// (D7 / broken-rebind safety). `None` outside an overlap; dropped on the first
    /// frame received on the new socket.
    prev_socket: ArcSwap<Option<Arc<UdpSocket>>>,
    /// The pinned server remote, captured at connect so `migrate()` can `connect` the
    /// freshly-bound socket to the same destination.
    server: SocketAddr,
    cid: ConnId,
    phase: AtomicU8,
    next_packet_id: AtomicU32,
    /// Datagrams of the most recently sent frame, retransmitted on RTO during Handshake.
    last_sent: Mutex<Vec<Vec<u8>>>,
    reasm: Mutex<FragmentAssembler>,
}

impl UdpClientTransport {
    /// Connect a fresh UDP socket to `server`, choosing a random lifetime connection-ID.
    pub async fn connect(server: SocketAddr) -> Result<Self, CoreError> {
        let bind = if server.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let socket = UdpSocket::bind(bind)
            .await
            .map_err(|e| CoreError::NetworkError(format!("udp bind: {e}")))?;
        socket
            .connect(server)
            .await
            .map_err(|e| CoreError::NetworkError(format!("udp connect: {e}")))?;
        let mut cid = [0u8; 8];
        getrandom::getrandom(&mut cid).map_err(|e| CoreError::RngError(e.to_string()))?;
        Ok(Self {
            socket: ArcSwap::from_pointee(socket),
            prev_socket: ArcSwap::from_pointee(None),
            server,
            cid,
            phase: AtomicU8::new(PHASE_HANDSHAKE),
            next_packet_id: AtomicU32::new(0),
            last_sent: Mutex::new(Vec::new()),
            reasm: Mutex::new(FragmentAssembler::new()),
        })
    }

    /// Rebind to a fresh local socket and route subsequent traffic through it
    /// (Phase 4 / P4.2b — embedder-triggered migration). Best-effort and
    /// non-blocking on validation: it binds + `connect`s the new socket to the same
    /// server, then atomically swaps it in as the active socket while KEEPING the old
    /// one for the overlap (the recv loop listens on both until the new path shows
    /// life, then drops the old — broken-rebind safety / D7). Subsequent app data +
    /// L1 retransmits go out the new socket, so the server detects the new source
    /// (P4.1) and challenges → validates → swaps its peer. The caller is responsible
    /// for bumping the session send `path_id` ([`Session::next_migration_path_id`]).
    ///
    /// A bind/connect failure returns `Err` WITHOUT touching the active socket, so a
    /// migration to a dead/invalid address never tears the session down — the session
    /// keeps running on the old socket.
    ///
    /// [`Session::next_migration_path_id`]: crate::transport::session::Session::next_migration_path_id
    pub async fn migrate(&self, new_local_addr: SocketAddr) -> Result<(), CoreError> {
        let new_sock = UdpSocket::bind(new_local_addr)
            .await
            .map_err(|e| CoreError::NetworkError(format!("udp migrate bind: {e}")))?;
        new_sock
            .connect(self.server)
            .await
            .map_err(|e| CoreError::NetworkError(format!("udp migrate connect: {e}")))?;
        let new_sock = Arc::new(new_sock);
        // Retain the old socket FIRST (so the recv loop never sees a gap), then swap
        // the active socket. The recv loop drops the retained socket on the first
        // frame it receives on the new one.
        let old = self.socket.load_full();
        self.prev_socket.store(Arc::new(Some(old)));
        self.socket.store(new_sock);
        Ok(())
    }

    /// The connection-ID this client stamps on every datagram (test/inspection helper).
    // Only called from the `#[cfg(test)]` module; `--lib` clippy excludes test code, so the
    // dead-code lint would fire without this allow.
    #[allow(dead_code)]
    pub(crate) fn cid(&self) -> ConnId {
        self.cid
    }

    fn pkt_id(&self) -> u32 {
        self.next_packet_id.fetch_add(1, Ordering::Relaxed)
    }
}

impl SessionTransport for UdpClientTransport {
    async fn send_bytes(&self, data: &[u8]) -> Result<(), CoreError> {
        // Handshake frames are Initial (long header); post-handshake frames are OneRtt (short header).
        let ty = if self.phase.load(Ordering::Relaxed) == PHASE_HANDSHAKE {
            PacketType::Initial
        } else {
            PacketType::OneRtt
        };
        let dgrams = encode_datagrams(ty, &self.cid, self.pkt_id(), data)
            .map_err(|e| CoreError::NetworkError(format!("frame too large to fragment: {e}")))?;
        // Snapshot the active socket (owned `Arc`, not a `Guard`) so we never hold an
        // `ArcSwap` guard across `.await` — `migrate()` can swap it concurrently.
        let sock = self.socket.load_full();
        for d in &dgrams {
            sock.send(d)
                .await
                .map_err(|e| CoreError::NetworkError(format!("udp send: {e}")))?;
        }
        // Remember for Handshake-phase retransmit (ignored once Established).
        *self.last_sent.lock().await = dgrams;
        Ok(())
    }

    async fn recv_bytes(&self) -> Result<Bytes, CoreError> {
        // Sized at PATH_MTU + slack. We only ever emit datagrams <= PATH_MTU, so a legitimate peer
        // never exceeds this; an oversized datagram is truncated by `recv` and then dropped by the
        // `decode_header`/reassembly failure path below — intentional.
        let mut buf = vec![0u8; PATH_MTU + 64];
        // Second recv buffer, lazily sized only during a migration overlap; the common
        // no-migration path keeps the single `buf`.
        let mut buf_prev: Vec<u8> = Vec::new();
        let mut retx = 0u32;
        loop {
            let in_handshake = self.phase.load(Ordering::Relaxed) == PHASE_HANDSHAKE;
            // Snapshot both sockets as owned `Arc`s (never hold an `ArcSwap` guard
            // across `.await`). `prev_opt` is `Some` only during a post-handshake
            // migration overlap; we then listen on BOTH the new (active) socket and the
            // retained old one (D7 / broken-rebind safety) until the new path shows
            // life, then drop the old.
            let active = self.socket.load_full();
            let prev_arc = self.prev_socket.load_full();
            let prev_opt: Option<Arc<UdpSocket>> = (*prev_arc).clone();

            // `from_prev` records which buffer the datagram landed in, so we slice the
            // right one AFTER the select — the recv future's `&mut buf` borrow is
            // released when its arm wins, exactly as the single-socket path relied on.
            let (n, from_prev): (usize, bool) = if in_handshake {
                // Migration is post-handshake only, so there is never a `prev` socket
                // here; keep the original single-socket + RTO-retransmit logic.
                tokio::select! {
                    // `biased;` polls the recv arm first: the RTO must be a true
                    // "no data arrived for HANDSHAKE_RTO" timer, not a coin-flip against an
                    // already-queued datagram. With the default unbiased select, when BOTH a datagram
                    // is ready AND the sleep has elapsed (common under contention from concurrent PQ
                    // handshakes), the recv arm is starved ~50% of the time, so the client spuriously
                    // retransmits instead of processing the already-arrived ServerHello — exhausting
                    // MAX_HANDSHAKE_RETX and timing the handshake out. Biasing toward received data
                    // makes the RTO fire only when recv is genuinely pending.
                    biased;
                    r = active.recv(&mut buf) =>
                        (r.map_err(|e| CoreError::NetworkError(format!("udp recv: {e}")))?, false),
                    _ = tokio::time::sleep(HANDSHAKE_RTO) => {
                        retx += 1;
                        if retx > MAX_HANDSHAKE_RETX {
                            return Err(CoreError::Timeout);
                        }
                        for d in self.last_sent.lock().await.iter() {
                            let _ = active.send(d).await;
                        }
                        continue;
                    }
                }
            } else if let Some(prev_sock) = &prev_opt {
                if buf_prev.len() < PATH_MTU + 64 {
                    buf_prev.resize(PATH_MTU + 64, 0);
                }
                tokio::select! {
                    r = active.recv(&mut buf) => {
                        let n = r.map_err(|e| CoreError::NetworkError(format!("udp recv: {e}")))?;
                        // First life on the new path: the server is now reaching us on
                        // the new socket → drop the retained old socket (overlap done).
                        self.prev_socket.store(Arc::new(None));
                        (n, false)
                    }
                    r = prev_sock.recv(&mut buf_prev) =>
                        (r.map_err(|e| CoreError::NetworkError(format!("udp recv: {e}")))?, true),
                }
            } else {
                (
                    active
                        .recv(&mut buf)
                        .await
                        .map_err(|e| CoreError::NetworkError(format!("udp recv: {e}")))?,
                    false,
                )
            };
            retx = 0; // progress: reset the RTO budget
            let datagram = if from_prev { &buf_prev[..n] } else { &buf[..n] };
            let mut asm = self.reasm.lock().await;
            match push_datagram(&mut asm, datagram) {
                Ok((_hdr, Some(frame))) => return Ok(Bytes::from(frame)),
                Ok((_hdr, None)) => continue, // partial fragment; keep receiving
                Err(_) => continue,           // malformed datagram; drop and keep receiving
            }
        }
    }

    fn set_frame_phase(&self, phase: FramePhase) {
        let v = match phase {
            FramePhase::Handshake => PHASE_HANDSHAKE,
            FramePhase::Established => PHASE_ESTABLISHED,
        };
        self.phase.store(v, Ordering::Relaxed);
    }
}

/// Per-session server transport. The listener's demux task reassembles inbound datagrams and pushes
/// the inner frames to `rx`; outbound frames are enveloped and sent to the captured `peer`.
pub struct UdpServerTransport {
    socket: Arc<UdpSocket>,
    /// Established peer. `ArcSwap` so the session can atomically switch it to a
    /// validated migration candidate (Phase 4 / P4.2) without re-handshake.
    peer: ArcSwap<SocketAddr>,
    cid: ConnId,
    phase: AtomicU8,
    next_packet_id: AtomicU32,
    rx: Mutex<mpsc::Receiver<(Bytes, SocketAddr)>>,
    /// Migration candidate (Phase 4, P4.1): a source address other than `peer`
    /// observed for this CID. The session challenges it before any switch; the
    /// switch itself (changing `peer`) is P4.2. `None` until a new source appears.
    candidate: ArcSwap<Option<SocketAddr>>,
    /// Anti-amplification budget for the candidate (D9, RFC 9000 §8.2): bytes
    /// received from / sent to the candidate, so a challenge to a possibly-spoofed
    /// address never exceeds 3× what it sent us.
    cand_recv: AtomicU64,
    cand_sent: AtomicU64,
}

impl UdpServerTransport {
    pub fn new(
        socket: Arc<UdpSocket>,
        peer: SocketAddr,
        cid: ConnId,
        rx: mpsc::Receiver<(Bytes, SocketAddr)>,
    ) -> Self {
        Self {
            socket,
            peer: ArcSwap::from_pointee(peer),
            cid,
            phase: AtomicU8::new(PHASE_HANDSHAKE),
            next_packet_id: AtomicU32::new(0),
            rx: Mutex::new(rx),
            candidate: ArcSwap::from_pointee(None),
            cand_recv: AtomicU64::new(0),
            cand_sent: AtomicU64::new(0),
        }
    }
}

impl SessionTransport for UdpServerTransport {
    async fn send_bytes(&self, data: &[u8]) -> Result<(), CoreError> {
        let ty = if self.phase.load(Ordering::Relaxed) == PHASE_HANDSHAKE {
            PacketType::Initial
        } else {
            PacketType::OneRtt
        };
        let pid = self.next_packet_id.fetch_add(1, Ordering::Relaxed);
        let dgrams = encode_datagrams(ty, &self.cid, pid, data)
            .map_err(|e| CoreError::NetworkError(format!("frame too large to fragment: {e}")))?;
        let peer = **self.peer.load();
        for d in &dgrams {
            self.socket
                .send_to(d, peer)
                .await
                .map_err(|e| CoreError::NetworkError(format!("udp send_to: {e}")))?;
        }
        Ok(())
    }

    async fn recv_bytes(&self) -> Result<Bytes, CoreError> {
        let (frame, src) = self
            .rx
            .lock()
            .await
            .recv()
            .await
            .ok_or(CoreError::ConnectionClosed)?;
        // Migration source-detection (Phase 4, P4.1). A frame from a source other
        // than the established `peer` marks a candidate path. We do NOT switch the
        // peer here (that is P4.2) — only record the candidate + (re)seed its
        // anti-amplification budget so the session can challenge it.
        if src != **self.peer.load() {
            if self.candidate.load().as_ref() == &Some(src) {
                self.cand_recv
                    .fetch_add(frame.len() as u64, Ordering::Relaxed);
            } else {
                self.candidate.store(Arc::new(Some(src)));
                self.cand_recv.store(frame.len() as u64, Ordering::Relaxed);
                self.cand_sent.store(0, Ordering::Relaxed);
            }
        }
        Ok(frame)
    }

    fn has_migration_candidate(&self) -> bool {
        self.candidate.load().is_some()
    }

    async fn send_to_candidate(&self, data: &[u8]) -> Result<bool, CoreError> {
        let cand = self.candidate.load();
        let addr = match cand.as_ref() {
            Some(a) => *a,
            None => return Ok(false),
        };
        let pid = self.next_packet_id.fetch_add(1, Ordering::Relaxed);
        let dgrams = encode_datagrams(PacketType::OneRtt, &self.cid, pid, data)
            .map_err(|e| CoreError::NetworkError(format!("challenge too large: {e}")))?;
        let wire: u64 = dgrams.iter().map(|d| d.len() as u64).sum();
        // Anti-amplification (D9, RFC 9000 §8.2): never send > 3× what the
        // candidate sent us. Drop the challenge rather than become a reflector.
        let recv = self.cand_recv.load(Ordering::Relaxed);
        if self.cand_sent.load(Ordering::Relaxed).saturating_add(wire) > recv.saturating_mul(3) {
            return Ok(false);
        }
        for d in &dgrams {
            self.socket
                .send_to(d, addr)
                .await
                .map_err(|e| CoreError::NetworkError(format!("udp send_to candidate: {e}")))?;
        }
        self.cand_sent.fetch_add(wire, Ordering::Relaxed);
        Ok(true)
    }

    fn promote_candidate(&self) -> bool {
        let cand = self.candidate.load();
        match cand.as_ref() {
            Some(addr) => {
                // Switch the active peer to the validated candidate; clear the
                // candidate + its anti-amp budget. Subsequent send_bytes + ARQ
                // retransmits now target the new address.
                self.peer.store(Arc::new(*addr));
                self.candidate.store(Arc::new(None));
                self.cand_recv.store(0, Ordering::Relaxed);
                self.cand_sent.store(0, Ordering::Relaxed);
                true
            }
            None => false,
        }
    }

    fn set_frame_phase(&self, phase: FramePhase) {
        let v = match phase {
            FramePhase::Handshake => PHASE_HANDSHAKE,
            FramePhase::Established => PHASE_ESTABLISHED,
        };
        self.phase.store(v, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::phantom_udp::datagram::{push_datagram, FragmentAssembler};
    use crate::transport::phantom_udp::envelope::PacketType;
    use tokio::net::UdpSocket;

    /// A framed frame round-trips client -> raw peer -> client, including a >MTU
    /// (fragmented) reply that `recv_bytes` reassembles.
    #[tokio::test]
    async fn client_send_recv_with_fragmented_reply() {
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = peer.local_addr().unwrap();
        let client = UdpClientTransport::connect(peer_addr).await.unwrap();

        // Client sends a small frame.
        client.send_bytes(b"hello").await.unwrap();
        let mut buf = vec![0u8; 2048];
        let (n, from) = peer.recv_from(&mut buf).await.unwrap();
        let mut asm = FragmentAssembler::new();
        let (_h, got) = push_datagram(&mut asm, &buf[..n]).unwrap();
        assert_eq!(got.as_deref(), Some(&b"hello"[..]));

        // Peer replies with a >MTU frame (fragments); client reassembles via recv_bytes.
        let big: Vec<u8> = (0..5000u32).map(|i| i as u8).collect();
        for d in encode_datagrams(PacketType::OneRtt, &client.cid(), 1, &big).expect("encode") {
            peer.send_to(&d, from).await.unwrap();
        }
        let recv = tokio::time::timeout(std::time::Duration::from_secs(2), client.recv_bytes())
            .await
            .expect("no timeout")
            .expect("recv");
        assert_eq!(&recv[..], &big[..]);
    }

    /// While in Handshake phase, a dropped first datagram is retransmitted on RTO.
    #[tokio::test]
    async fn client_retransmits_handshake_on_rto() {
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = peer.local_addr().unwrap();
        let client = UdpClientTransport::connect(peer_addr).await.unwrap();
        // default phase is Handshake.
        let send = async {
            client.send_bytes(b"flight1").await.unwrap();
        };
        let mut buf = vec![0u8; 2048];
        // Peer ignores the first datagram, reads the retransmit.
        let recv = async {
            let _ = peer.recv_from(&mut buf).await.unwrap(); // drop #1
            let (n, from) = peer.recv_from(&mut buf).await.unwrap(); // retransmit
                                                                     // Reply so client's recv_bytes completes.
            for d in
                encode_datagrams(PacketType::Initial, &client.cid(), 0, b"reply").expect("encode")
            {
                peer.send_to(&d, from).await.unwrap();
            }
            n
        };
        let recv_client = async {
            tokio::time::timeout(std::time::Duration::from_secs(3), client.recv_bytes()).await
        };
        let (_s, n, r) = tokio::join!(send, recv, recv_client);
        assert!(n >= super::HDR_LEN);
        assert_eq!(&r.unwrap().unwrap()[..], &b"reply"[..]);
    }

    #[tokio::test]
    async fn server_transport_send_and_recv() {
        use tokio::sync::mpsc;
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = peer.local_addr().unwrap();
        let (tx, rx) = mpsc::channel(8);
        let st = UdpServerTransport::new(sock.clone(), peer_addr, [3u8; 8], rx);

        // recv_bytes returns frames pushed to the channel (as the demux would),
        // tagged with the source address (here the established peer).
        tx.send((Bytes::from_static(b"from-demux"), peer_addr))
            .await
            .unwrap();
        assert_eq!(&st.recv_bytes().await.unwrap()[..], b"from-demux");

        // send_bytes writes an enveloped datagram the raw peer can decode.
        st.set_frame_phase(FramePhase::Established);
        st.send_bytes(b"to-peer").await.unwrap();
        let mut buf = vec![0u8; 2048];
        let (n, _from) = peer.recv_from(&mut buf).await.unwrap();
        let mut asm = FragmentAssembler::new();
        let (hdr, got) = push_datagram(&mut asm, &buf[..n]).unwrap();
        assert_eq!(hdr.cid, [3u8; 8]);
        assert_eq!(got.as_deref(), Some(&b"to-peer"[..]));
    }

    /// P4.1: a frame from a source other than the established peer registers a
    /// migration candidate; `send_to_candidate` reaches it under the 3×
    /// anti-amplification cap (D9). No peer switch happens here (that is P4.2).
    #[tokio::test]
    async fn server_detects_candidate_and_caps_amplification() {
        use tokio::sync::mpsc;
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let peer = UdpSocket::bind("127.0.0.1:0")
            .await
            .unwrap()
            .local_addr()
            .unwrap();
        let (tx, rx) = mpsc::channel(16);
        let st = UdpServerTransport::new(sock.clone(), peer, [9u8; 8], rx);

        // The established peer is not a candidate, and there is nothing to send to.
        tx.send((Bytes::from_static(b"hi"), peer)).await.unwrap();
        let _ = st.recv_bytes().await.unwrap();
        assert!(!st.has_migration_candidate(), "the peer is not a candidate");
        assert!(
            !st.send_to_candidate(b"x").await.unwrap(),
            "no candidate => Ok(false)"
        );

        // A frame from a NEW source registers a candidate + seeds the 3× budget
        // (10 received bytes here).
        let cand_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let cand_addr = cand_sock.local_addr().unwrap();
        tx.send((Bytes::from_static(b"0123456789"), cand_addr))
            .await
            .unwrap();
        let _ = st.recv_bytes().await.unwrap();
        assert!(
            st.has_migration_candidate(),
            "a new source must set a candidate"
        );

        // A challenge within budget is delivered to the candidate address.
        assert!(
            st.send_to_candidate(b"chal").await.unwrap(),
            "first challenge is within the 3× budget"
        );
        let mut buf = vec![0u8; 2048];
        let (n, _from) = cand_sock.recv_from(&mut buf).await.unwrap();
        assert!(n > 0, "the challenge must reach the candidate socket");

        // Keep challenging until the 3× anti-amplification cap blocks.
        let mut blocked = false;
        for _ in 0..50 {
            if !st.send_to_candidate(b"chal").await.unwrap() {
                blocked = true;
                break;
            }
        }
        assert!(
            blocked,
            "the 3× anti-amplification cap must eventually block"
        );
    }

    /// P4.2: promote_candidate atomically switches the established peer to the
    /// validated candidate; subsequent send_bytes targets the new address.
    #[tokio::test]
    async fn promote_candidate_switches_the_peer() {
        use tokio::sync::mpsc;
        let server_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let old_peer_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let old_peer = old_peer_sock.local_addr().unwrap();
        let new_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let new_addr = new_sock.local_addr().unwrap();

        let (tx, rx) = mpsc::channel(8);
        let ust = UdpServerTransport::new(server_sock.clone(), old_peer, [7u8; 8], rx);
        ust.set_frame_phase(FramePhase::Established);

        assert!(
            !ust.promote_candidate(),
            "no candidate => nothing to promote"
        );

        // A frame from a new source sets the candidate.
        tx.send((Bytes::from_static(b"hi"), new_addr))
            .await
            .unwrap();
        let _ = ust.recv_bytes().await.unwrap();
        assert!(ust.has_migration_candidate());

        // Pre-switch: send_bytes goes to the OLD peer.
        ust.send_bytes(b"before").await.unwrap();
        let mut buf = vec![0u8; 512];
        let (n, _) =
            tokio::time::timeout(Duration::from_secs(1), old_peer_sock.recv_from(&mut buf))
                .await
                .expect("pre-switch data reaches the old peer")
                .unwrap();
        assert!(n > 0);

        // Switch.
        assert!(ust.promote_candidate(), "candidate must be promoted");
        assert!(
            !ust.has_migration_candidate(),
            "candidate cleared after promotion"
        );

        // Post-switch: send_bytes now goes to the NEW peer.
        ust.send_bytes(b"after").await.unwrap();
        let (n2, _) = tokio::time::timeout(Duration::from_secs(1), new_sock.recv_from(&mut buf))
            .await
            .expect("post-switch data reaches the new peer")
            .unwrap();
        assert!(n2 > 0);
    }

    /// P4.2b: `migrate()` rebinds the client to a fresh local socket and `connect`s
    /// it to the same server, so the client's source address changes — which is what
    /// makes the server detect the new path (P4.1). The new socket becomes the active
    /// send/recv socket; a reply to the new source is received.
    #[tokio::test]
    async fn migrate_rebinds_to_a_new_local_socket() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();
        let client = UdpClientTransport::connect(server_addr).await.unwrap();
        client.set_frame_phase(FramePhase::Established);

        // Pre-migration: the server sees the original source.
        client.send_bytes(b"pre").await.unwrap();
        let mut buf = vec![0u8; 2048];
        let (_n, src_old) = server.recv_from(&mut buf).await.unwrap();

        // Migrate to a fresh ephemeral local socket.
        client
            .migrate("127.0.0.1:0".parse().unwrap())
            .await
            .expect("migrate binds a new socket");

        // Post-migration: the server sees a DIFFERENT source (the new socket).
        client.send_bytes(b"post").await.unwrap();
        let (_n2, src_new) = server.recv_from(&mut buf).await.unwrap();
        assert_ne!(
            src_old, src_new,
            "migrate() must change the client's source address"
        );

        // A reply to the new source is received on the new (active) socket.
        for d in encode_datagrams(PacketType::OneRtt, &client.cid(), 7, b"reply-new").unwrap() {
            server.send_to(&d, src_new).await.unwrap();
        }
        let got = tokio::time::timeout(Duration::from_secs(2), client.recv_bytes())
            .await
            .expect("no timeout")
            .expect("recv");
        assert_eq!(&got[..], b"reply-new");
    }

    /// P4.2b: during the migration overlap the client keeps the OLD socket and still
    /// receives on it (broken-rebind safety / D7) — the server, until it validates +
    /// swaps, keeps sending downstream app data to the old address. The session must
    /// not lose that data.
    #[tokio::test]
    async fn migrate_keeps_receiving_on_the_old_socket_during_overlap() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();
        let client = UdpClientTransport::connect(server_addr).await.unwrap();
        client.set_frame_phase(FramePhase::Established);

        client.send_bytes(b"hi").await.unwrap();
        let mut buf = vec![0u8; 2048];
        let (_n, src_old) = server.recv_from(&mut buf).await.unwrap();

        client
            .migrate("127.0.0.1:0".parse().unwrap())
            .await
            .expect("migrate binds a new socket");

        // The server has NOT yet validated/swapped, so it still sends downstream to
        // the OLD source. The client must still receive it on the retained old socket.
        for d in encode_datagrams(PacketType::OneRtt, &client.cid(), 1, b"downstream-old").unwrap()
        {
            server.send_to(&d, src_old).await.unwrap();
        }
        let got = tokio::time::timeout(Duration::from_secs(2), client.recv_bytes())
            .await
            .expect("no timeout")
            .expect("recv on retained old socket");
        assert_eq!(&got[..], b"downstream-old");
    }
}
