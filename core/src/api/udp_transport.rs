//! `SessionTransport` impls over raw UDP (PhantomUDP). `UdpClientTransport` is an
//! unconnected-socket client (it `send_to`s a tracked server address and `recv_from`s any
//! source, so it can hear — and later follow — a server that migrates to a new address);
//! `UdpServerTransport` is a per-session shim fed by the listener demux that can migrate its
//! own send socket. Both add / strip the outer `[flags][cid]` envelope exactly as
//! `TcpSessionTransport` adds / strips its 4-byte length prefix, so `run_data_pump` /
//! `run_client_handshake` / `drive_server_handshake` are reused.

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
use tokio::sync::{mpsc, Mutex, Notify};

/// Retransmit timeout for the Handshake phase stop-and-wait shim.
const HANDSHAKE_RTO: Duration = Duration::from_millis(400);
/// Max Handshake-phase retransmits before giving up (the outer 10s connect deadline still applies).
const MAX_HANDSHAKE_RETX: u32 = 6;

const PHASE_HANDSHAKE: u8 = 0;
const PHASE_ESTABLISHED: u8 = 1;

/// Outcome of classifying a UDP `recv_from` result (M-6).
enum RecvAction {
    /// A datagram of this many bytes arrived from this source (the source is needed for
    /// server-migration candidate detection — M-1).
    Got(usize, SocketAddr),
    /// An ICMP-induced *advisory* error — retry, do not tear the session down.
    Retry,
    /// A genuine, fatal socket error.
    Fatal(std::io::Error),
}

/// Whether a UDP `recv` error is an ICMP-induced *advisory* condition (RFC 8085 §5.5 /
/// RFC 9000 §14.2). The client socket is unconnected, so the kernel rarely attributes an
/// ICMP error to a `recv_from` (it cannot map it to a specific unconnected send) — this
/// handling is mostly dormant there but retained for the platforms that do surface one. A
/// single such error — which an off-path attacker can forge (the UDP analogue of a forged
/// RST) — must NOT kill the session.
fn is_advisory_recv_error(e: &std::io::Error) -> bool {
    use std::io::ErrorKind;
    // ConnectionRefused (ICMP port-unreachable — the audit's M-6 case) and ConnectionReset are
    // matched via the portable `ErrorKind`. Host/network-unreachable are matched by raw errno
    // instead, so the check stays uniform across platforms regardless of whether the OS maps
    // them to the named `ErrorKind`s (Linux: EHOSTUNREACH = 113, ENETUNREACH = 101).
    if matches!(
        e.kind(),
        ErrorKind::ConnectionRefused | ErrorKind::ConnectionReset
    ) {
        return true;
    }
    #[cfg(target_os = "linux")]
    if let Some(errno) = e.raw_os_error() {
        return errno == 113 || errno == 101;
    }
    false
}

/// Classify a `recv_from` result: an advisory ICMP error is retried, a genuine error is
/// fatal (M-6); a datagram carries its source for migration-candidate detection.
fn classify_recv(r: std::io::Result<(usize, SocketAddr)>) -> RecvAction {
    match r {
        Ok((n, src)) => RecvAction::Got(n, src),
        Err(e) if is_advisory_recv_error(&e) => RecvAction::Retry,
        Err(e) => RecvAction::Fatal(e),
    }
}

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
    /// The server remote this client `send_to`s. `ArcSwap` because the socket is
    /// unconnected (the destination is explicit per send rather than a kernel-pinned connect
    /// peer) AND because a server-migration *follow* re-points it to a validated new server
    /// address without a re-handshake: when the server moves, the client path-validates the
    /// new source and [`promote_candidate`](SessionTransport::promote_candidate) stores it
    /// here, so subsequent c2s flows to the new address. Read on every `send_bytes`.
    server_addr: ArcSwap<SocketAddr>,
    /// The bootstrap (handshake) ConnId — a random lifetime id stamped until the
    /// session sets the rotating chain via [`set_outbound_cid`](SessionTransport::set_outbound_cid).
    cid: ConnId,
    /// The rotating routing CID set at the handshake → data-pump boundary (ε /
    /// WIRE v5). `None` during the handshake (the bootstrap `cid` is stamped);
    /// `Some(CID_0)` once the session sets it, after which every datagram stamps it.
    established_cid: ArcSwap<Option<ConnId>>,
    phase: AtomicU8,
    next_packet_id: AtomicU32,
    /// Datagrams of the most recently sent frame, retransmitted on RTO during Handshake.
    last_sent: Mutex<Vec<Vec<u8>>>,
    reasm: Mutex<FragmentAssembler>,
    /// Server-migration candidate (the mirror of the server's client-migration candidate): a
    /// NEW server source (≠ `server_addr`) observed for this session. The session
    /// path-validates it before any switch; `promote_candidate` then stores it as the new
    /// `server_addr`. `None` until a migrated server's source appears.
    candidate: ArcSwap<Option<SocketAddr>>,
    /// Anti-amplification budget for the candidate (D9, RFC 9000 §8.2): bytes received from /
    /// sent to the candidate, so a `PATH_CHALLENGE` to a possibly-spoofed new server source
    /// never exceeds 3× what it sent us. Bounds the redirection/reflection an on-path
    /// attacker (replaying a fresh frame with a spoofed source) could induce.
    cand_recv: AtomicU64,
    cand_sent: AtomicU64,
    /// Source + byte length of the most recent `recv_bytes` frame (M-1). The candidate is
    /// committed from this ONLY by `confirm_authenticated_source` on the post-decrypt path,
    /// so a spoofed / replayed datagram (which fails AEAD or the replay window before
    /// `confirm_authenticated_source` runs) can never clobber the candidate slot.
    last_recv_src: ArcSwap<Option<SocketAddr>>,
    last_frame_len: AtomicU64,
    /// Notified by `migrate_to` after swapping the active socket, so a `recv_bytes` call
    /// blocked on the OLD socket's `recv_from` wakes up and re-enters the loop on the new one
    /// rather than staying stuck indefinitely.
    migrate_notify: Arc<Notify>,
}

impl UdpClientTransport {
    /// Bind a fresh UNCONNECTED UDP socket for talking to `server`, choosing a random
    /// lifetime connection-ID. The socket is left unconnected (no `socket.connect`) so the
    /// client can `recv_from` any source — the precondition for hearing, and later
    /// following, a server that migrates to a new address. Datagrams are sent with
    /// `send_to(server_addr)`.
    pub async fn connect(server: SocketAddr) -> Result<Self, CoreError> {
        let bind = if server.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let socket = UdpSocket::bind(bind)
            .await
            .map_err(|e| CoreError::NetworkError(format!("udp bind: {e}")))?;
        let mut cid = [0u8; 8];
        getrandom::fill(&mut cid).map_err(|e| CoreError::RngError(e.to_string()))?;
        Ok(Self {
            socket: ArcSwap::from_pointee(socket),
            prev_socket: ArcSwap::from_pointee(None),
            server_addr: ArcSwap::from_pointee(server),
            cid,
            established_cid: ArcSwap::from_pointee(None),
            phase: AtomicU8::new(PHASE_HANDSHAKE),
            next_packet_id: AtomicU32::new(0),
            last_sent: Mutex::new(Vec::new()),
            reasm: Mutex::new(FragmentAssembler::new()),
            candidate: ArcSwap::from_pointee(None),
            cand_recv: AtomicU64::new(0),
            cand_sent: AtomicU64::new(0),
            last_recv_src: ArcSwap::from_pointee(None),
            last_frame_len: AtomicU64::new(0),
            migrate_notify: Arc::new(Notify::new()),
        })
    }

    /// Rebind to a fresh local socket and route subsequent traffic through it
    /// (Phase 4 / P4.2b — embedder-triggered migration). Best-effort and
    /// non-blocking on validation: it binds a fresh unconnected socket (sends still
    /// `send_to` the tracked `server_addr`), then atomically swaps it in as the active
    /// socket while KEEPING the old one for the overlap (the recv loop listens on both
    /// until the new path shows
    /// life, then drops the old — broken-rebind safety / D7). Subsequent app data +
    /// L1 retransmits go out the new socket, so the server detects the new source
    /// (P4.1) and challenges → validates → swaps its peer. The caller is responsible
    /// for bumping the session send `path_id` ([`Session::next_migration_path_id`]).
    ///
    /// A bind/connect failure returns `Err` WITHOUT touching the active socket, so a
    /// migration to a dead/invalid address never tears the session down — the session
    /// keeps running on the old socket.
    ///
    /// Typed core of the migration; the SocketAddr-free [`SessionTransport::migrate`]
    /// trait entry parses a `String` and delegates here.
    ///
    /// [`Session::next_migration_path_id`]: crate::transport::session::Session::next_migration_path_id
    pub async fn migrate_to(&self, new_local_addr: SocketAddr) -> Result<(), CoreError> {
        let new_sock = UdpSocket::bind(new_local_addr)
            .await
            .map_err(|e| CoreError::NetworkError(format!("udp migrate bind: {e}")))?;
        // The socket stays UNCONNECTED (sends use `send_to(server_addr)`), so there is no
        // `connect` step — the send target is the tracked `server_addr`, unchanged by a
        // local rebind.
        let new_sock = Arc::new(new_sock);
        // Retain the old socket FIRST (so the recv loop never sees a gap), then swap
        // the active socket. The recv loop drops the retained socket on the first
        // frame it receives on the new one.
        let old = self.socket.load_full();
        self.prev_socket.store(Arc::new(Some(old)));
        self.socket.store(new_sock);
        // Wake any `recv_bytes` call that is blocked on `recv_from` on the OLD socket,
        // so it re-enters the loop and picks up the new socket and `prev_opt`.
        self.migrate_notify.notify_one();
        Ok(())
    }

    /// The connection-ID this client stamps on every datagram (test/inspection helper).
    // Only called from the `#[cfg(test)]` module; `--lib` clippy excludes test code, so the
    // dead-code lint would fire without this allow.
    #[allow(dead_code)]
    pub(crate) fn cid(&self) -> ConnId {
        self.cid
    }

    /// Whether a post-migration dual-socket overlap is currently active (test/inspection
    /// helper): `true` between a `migrate_to` and the first well-formed datagram on the new
    /// socket that retires the old one.
    #[cfg(test)]
    pub(crate) fn in_migration_overlap(&self) -> bool {
        self.prev_socket.load().is_some()
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
        // ε / WIRE v5: stamp the rotating CID once the handshake set it; the
        // bootstrap `cid` is stamped until then.
        let cid = (**self.established_cid.load()).unwrap_or(self.cid);
        let dgrams = encode_datagrams(ty, &cid, self.pkt_id(), data)
            .map_err(|e| CoreError::NetworkError(format!("frame too large to fragment: {e}")))?;
        // Snapshot the active socket (owned `Arc`, not a `Guard`) so we never hold an
        // `ArcSwap` guard across `.await` — `migrate()` can swap it concurrently.
        let sock = self.socket.load_full();
        // Unconnected socket: the destination is explicit. `server_addr` is the tracked
        // server remote (a later server-migration follow can re-point it without rebinding).
        let dst = **self.server_addr.load();
        for d in &dgrams {
            sock.send_to(d, dst)
                .await
                .map_err(|e| CoreError::NetworkError(format!("udp send: {e}")))?;
        }
        // Remember for Handshake-phase retransmit (ignored once Established).
        *self.last_sent.lock().await = dgrams;
        Ok(())
    }

    async fn recv_bytes(&self) -> Result<Bytes, CoreError> {
        // Sized at PATH_MTU + slack. We only ever emit datagrams <= PATH_MTU, so a legitimate peer
        // never exceeds this; an oversized datagram is truncated by `recv_from` and then dropped by
        // the `decode_header`/reassembly failure path below — intentional.
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
            // The socket is unconnected, so `recv_from` returns the source of every datagram;
            // we deliver from ANY source (the inner AEAD + replay window are the real guards,
            // exactly as the server delivers any CID-matched datagram via its demux). During a
            // migration overlap, ANY well-formed datagram on the NEW socket means the path is
            // up — the overlap-drop after `push_datagram` (below) retires the old socket then.

            // `from_prev` records which buffer the datagram landed in, so we slice the
            // right one AFTER the select — the recv future's `&mut buf` borrow is
            // released when its arm wins, exactly as the single-socket path relied on.
            let (n, from_prev, src): (usize, bool, SocketAddr) = if in_handshake {
                // Migration is post-handshake only, so there is never a `prev` socket
                // here; keep the original single-socket + RTO-retransmit logic.
                let server = **self.server_addr.load();
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
                    r = active.recv_from(&mut buf) => match classify_recv(r) {
                        RecvAction::Got(n, src) => (n, false, src),
                        RecvAction::Retry => {
                            log::debug!("PhantomUDP: advisory recv error (ignored, RFC 8085 §5.5)");
                            continue;
                        }
                        RecvAction::Fatal(e) => {
                            return Err(CoreError::NetworkError(format!("udp recv: {e}")))
                        }
                    },
                    _ = tokio::time::sleep(HANDSHAKE_RTO) => {
                        retx += 1;
                        if retx > MAX_HANDSHAKE_RETX {
                            return Err(CoreError::Timeout);
                        }
                        for d in self.last_sent.lock().await.iter() {
                            let _ = active.send_to(d, server).await;
                        }
                        continue;
                    }
                }
            } else if let Some(prev_sock) = &prev_opt {
                if buf_prev.len() < PATH_MTU + 64 {
                    buf_prev.resize(PATH_MTU + 64, 0);
                }
                // Also wake on a migration that happens while we are parked in the
                // overlap select. This covers (a) a SECOND migrate_to() during an
                // existing overlap, and (b) a torn read at the loop top that snapshotted
                // a stale (active, prev) pair across migrate_to()'s two ArcSwap stores —
                // both would otherwise block on stale/silent sockets. migrate_to()'s
                // Notify permit (stored before we reach this select) lets us re-enter the
                // loop and re-snapshot both sockets instead of hanging.
                let migrate_notified = self.migrate_notify.notified();
                tokio::select! {
                    r = active.recv_from(&mut buf) => match classify_recv(r) {
                        RecvAction::Got(n, src) => (n, false, src),
                        RecvAction::Retry => {
                            log::debug!("PhantomUDP: advisory recv error on new path (ignored)");
                            continue;
                        }
                        RecvAction::Fatal(e) => {
                            return Err(CoreError::NetworkError(format!("udp recv: {e}")))
                        }
                    },
                    r = prev_sock.recv_from(&mut buf_prev) => match classify_recv(r) {
                        RecvAction::Got(n, src) => (n, true, src),
                        RecvAction::Retry => {
                            log::debug!("PhantomUDP: advisory recv error on old path (ignored)");
                            continue;
                        }
                        RecvAction::Fatal(e) => {
                            return Err(CoreError::NetworkError(format!("udp recv: {e}")))
                        }
                    },
                    _ = migrate_notified => {
                        // Re-snapshot active/prev on the next iteration (closes the
                        // overlap-arm migration hang and the loop-top torn-read race).
                        continue;
                    }
                }
            } else {
                let migrate_notified = self.migrate_notify.notified();
                tokio::select! {
                    biased;
                    r = active.recv_from(&mut buf) => match classify_recv(r) {
                        RecvAction::Got(n, src) => (n, false, src),
                        RecvAction::Retry => {
                            log::debug!("PhantomUDP: advisory recv error (ignored, RFC 8085 §5.5)");
                            continue;
                        }
                        RecvAction::Fatal(e) => {
                            return Err(CoreError::NetworkError(format!("udp recv: {e}")))
                        }
                    },
                    _ = migrate_notified => {
                        // migrate_to() swapped the active socket — re-enter the loop
                        // so the next iteration picks up the new socket and prev_opt.
                        continue;
                    }
                }
            };
            retx = 0; // progress: reset the RTO budget
            let datagram = if from_prev { &buf_prev[..n] } else { &buf[..n] };
            let mut asm = self.reasm.lock().await;
            let decoded = push_datagram(&mut asm, datagram);
            // Overlap-drop (D7): a well-formed datagram on the NEW (active) socket means the
            // path is up, so retire the retained old socket — regardless of source, so it
            // works whether the server is reaching us at the established address OR has
            // itself migrated to a new one (a `src == server_addr` check would never fire in
            // the latter case and strand the overlap). Garbage spray (a decode `Err`) does
            // NOT end the overlap; data on the OLD socket (`from_prev`) never does either.
            if !from_prev && prev_opt.is_some() && decoded.is_ok() {
                self.prev_socket.store(Arc::new(None));
            }
            match decoded {
                Ok((_hdr, Some(frame))) => {
                    // M-1 (server-migration candidate detection): record the source + frame
                    // length of this still-AEAD-pending frame. The candidate is committed ONLY
                    // by the post-decrypt `confirm_authenticated_source`, so a spoofed / replayed
                    // datagram (rejected by AEAD or the replay window before that runs) can never
                    // clobber the candidate slot. Mirrors `UdpServerTransport::recv_bytes`.
                    self.last_recv_src.store(Arc::new(Some(src)));
                    self.last_frame_len
                        .store(frame.len() as u64, Ordering::Relaxed);
                    return Ok(Bytes::from(frame));
                }
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

    fn set_outbound_cid(&self, cid: [u8; 8]) {
        self.established_cid.store(Arc::new(Some(cid)));
    }

    /// SocketAddr-free trait entry for connection migration (Phase 4 / P4.2c). Parses
    /// the embedder-supplied local bind address and delegates to the typed
    /// [`migrate_to`](Self::migrate_to). A malformed address is a clean `Err` that
    /// leaves the session on its existing socket (best-effort, never fatal).
    async fn migrate(&self, local_addr: String) -> Result<(), CoreError> {
        let addr: SocketAddr = local_addr.parse().map_err(|e| {
            CoreError::NetworkError(format!("migrate: bad local addr '{local_addr}': {e}"))
        })?;
        self.migrate_to(addr).await
    }

    // ── Server-migration follow (the client side of A2a) ──────────────────────
    //
    // The exact mirror of `UdpServerTransport`'s client-migration candidate machinery,
    // with the roles flipped: here the candidate is a NEW SERVER source, and a promotion
    // re-points `server_addr` (the c2s send target). The shared recv-path
    // (`handle_packet`) drives these the same way for both peers — it commits the
    // candidate post-AEAD (`confirm_authenticated_source`), challenges it under the 3×
    // anti-amplification cap (`send_to_candidate`), and promotes it on a valid
    // PATH_RESPONSE (`promote_candidate`). Anti-spoof holds exactly as on the server: a
    // spoofed / replayed datagram is rejected by AEAD or the replay window BEFORE
    // `confirm_authenticated_source` runs, so it can never become the candidate; and the
    // switch happens only after the candidate echoes a path-validation challenge, so an
    // on-path attacker that rewrites a fresh frame's source to a victim can at most induce
    // a bounded (≤3×) PATH_CHALLENGE to that victim, never a c2s redirection.

    fn confirm_authenticated_source(&self) {
        // M-1: the frame from `last_recv_src` just authenticated (AEAD-opened, non-replayed),
        // so it really is the server — possibly at a NEW address (the server migrated). Commit
        // it as the candidate the session path-validates before switching, and (re)seed its
        // anti-amplification budget. A spoofed source never reaches here.
        let src = match **self.last_recv_src.load() {
            Some(s) => s,
            None => return,
        };
        if src == **self.server_addr.load() {
            return; // already the established server — not a new path
        }
        let len = self.last_frame_len.load(Ordering::Relaxed);
        if self.candidate.load().as_ref() == &Some(src) {
            self.cand_recv.fetch_add(len, Ordering::Relaxed);
        } else {
            self.candidate.store(Arc::new(Some(src)));
            self.cand_recv.store(len, Ordering::Relaxed);
            self.cand_sent.store(0, Ordering::Relaxed);
        }
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
        // Bootstrap cid (not the rotating `established_cid`): a challenge to a possibly-spoofed
        // address must not leak the keyed rotating CID, mirroring the server.
        let dgrams = encode_datagrams(PacketType::OneRtt, &self.cid, pid, data)
            .map_err(|e| CoreError::NetworkError(format!("challenge too large: {e}")))?;
        let wire: u64 = dgrams.iter().map(|d| d.len() as u64).sum();
        // Anti-amplification (D9, RFC 9000 §8.2): never send > 3× what the candidate sent us.
        let recv = self.cand_recv.load(Ordering::Relaxed);
        if self.cand_sent.load(Ordering::Relaxed).saturating_add(wire) > recv.saturating_mul(3) {
            return Ok(false);
        }
        let sock = self.socket.load_full();
        for d in &dgrams {
            sock.send_to(d, addr)
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
                // The candidate's path validated: re-point the c2s send target to the new
                // server address + clear the candidate / anti-amp budget. Subsequent
                // `send_bytes` (and L1 retransmits) now flow to the migrated server.
                self.server_addr.store(Arc::new(*addr));
                self.candidate.store(Arc::new(None));
                self.cand_recv.store(0, Ordering::Relaxed);
                self.cand_sent.store(0, Ordering::Relaxed);
                true
            }
            None => false,
        }
    }
}

/// Per-session server transport. The listener's demux task reassembles inbound datagrams and pushes
/// the inner frames to `rx`; outbound frames are enveloped and sent to the captured `peer` from
/// `send_socket`. A server migration ([`migrate_to`](Self::migrate_to)) swaps `send_socket` to a
/// freshly-bound local socket (so the client sees a new s2c source) and spawns a recv loop on it
/// that feeds the SAME `rx` channel via `tx`, so the client's c2s frames are delivered transparently
/// once it switches its send target — while the listener demux keeps feeding `rx` on the old address
/// during the overlap.
pub struct UdpServerTransport {
    /// Active send socket. Starts as the shared listener socket (so all sessions egress
    /// the listen address) and is atomically swapped to a freshly-bound dedicated socket on
    /// a server migration (`migrate_to`), changing this session's s2c source address.
    send_socket: ArcSwap<UdpSocket>,
    /// Sender half of this session's inbound channel (the demux holds a sibling clone for
    /// the listener-routed path). A server migration's recv loop forwards frames it receives
    /// on the new socket through this, so `recv_bytes` (reading `rx`) sees both the
    /// listener-demuxed old path and the migrated new path during the overlap.
    tx: mpsc::Sender<(Bytes, SocketAddr)>,
    /// Handle to the current server-migration recv loop, if any. Aborted when a newer
    /// migration replaces it (a stale socket from an earlier move) and on drop, so the
    /// task and its socket do not leak across repeated migrations.
    migrate_task: parking_lot::Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// Established peer. `ArcSwap` so the session can atomically switch it to a
    /// validated migration candidate (Phase 4 / P4.2) without re-handshake.
    peer: ArcSwap<SocketAddr>,
    /// The bootstrap (handshake) ConnId, stamped until the session sets the
    /// rotating chain via [`set_outbound_cid`](SessionTransport::set_outbound_cid).
    cid: ConnId,
    /// The rotating routing CID set at the handshake → data-pump boundary (ε /
    /// WIRE v5). `None` during the handshake; `Some(CID_0)` once the session sets
    /// it. Stamped on server→client datagrams so that direction also rotates.
    established_cid: ArcSwap<Option<ConnId>>,
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
    /// Source + byte length of the most recent `recv_bytes` frame (M-1). The candidate is
    /// committed from this ONLY by `confirm_authenticated_source` on the post-decrypt path, so
    /// a spoofed (never-decrypting) datagram cannot clobber the candidate slot.
    last_recv_src: ArcSwap<Option<SocketAddr>>,
    last_frame_len: AtomicU64,
}

impl UdpServerTransport {
    pub fn new(
        socket: Arc<UdpSocket>,
        peer: SocketAddr,
        cid: ConnId,
        tx: mpsc::Sender<(Bytes, SocketAddr)>,
        rx: mpsc::Receiver<(Bytes, SocketAddr)>,
    ) -> Self {
        Self {
            send_socket: ArcSwap::new(socket),
            tx,
            migrate_task: parking_lot::Mutex::new(None),
            peer: ArcSwap::from_pointee(peer),
            cid,
            established_cid: ArcSwap::from_pointee(None),
            phase: AtomicU8::new(PHASE_HANDSHAKE),
            next_packet_id: AtomicU32::new(0),
            rx: Mutex::new(rx),
            candidate: ArcSwap::from_pointee(None),
            cand_recv: AtomicU64::new(0),
            cand_sent: AtomicU64::new(0),
            last_recv_src: ArcSwap::from_pointee(None),
            last_frame_len: AtomicU64::new(0),
        }
    }

    /// Migrate the server's send path to a fresh local socket (the server-side mirror of
    /// the client's [`UdpClientTransport::migrate_to`]). Binds a new unconnected socket,
    /// swaps it in as the active send socket (so subsequent server→client datagrams egress
    /// the new local address — the client sees a new s2c source and follows it), and spawns
    /// a recv loop on it that reassembles datagrams and forwards complete frames into the
    /// SAME inbound channel `recv_bytes` reads. The listener demux keeps feeding that channel
    /// on the old (listen) address during the overlap, so c2s never drops; once the client
    /// switches its send target to the new address (path validation, a later step), its
    /// frames arrive on the new socket and flow through transparently.
    ///
    /// A bind failure returns `Err` WITHOUT touching the active send socket — a server
    /// migration to an invalid address never tears the session down (best-effort, like the
    /// client side). Typed core; the `SocketAddr`-free [`SessionTransport::migrate_server`]
    /// trait entry parses a `String` and delegates here.
    pub async fn migrate_to(&self, new_local_addr: SocketAddr) -> Result<(), CoreError> {
        let new_sock = UdpSocket::bind(new_local_addr)
            .await
            .map_err(|e| CoreError::NetworkError(format!("udp server migrate bind: {e}")))?;
        let new_sock = Arc::new(new_sock);
        // The recv loop and the send path share the same socket: the client sends c2s to
        // the new server address (where the loop listens) and the server's s2c egress that
        // same socket, so the client's source filter sees a single new server source.
        let recv_sock = new_sock.clone();
        let tx = self.tx.clone();
        let task = tokio::spawn(async move {
            Self::run_migration_recv(recv_sock, tx).await;
        });
        // Abort any prior migration recv loop (a stale socket from an earlier move) before
        // publishing the new one, so tasks/sockets do not accumulate across migrations.
        if let Some(old) = self.migrate_task.lock().replace(task) {
            old.abort();
        }
        self.send_socket.store(new_sock);
        Ok(())
    }

    /// Recv loop for a migrated server send socket: reassemble datagrams and forward complete
    /// frames into the session's inbound channel (tagged with the source, M-1), exactly as the
    /// listener demux does for the old path. Exits when the channel is closed (session gone)
    /// or on a fatal socket error; an advisory ICMP error is retried.
    async fn run_migration_recv(sock: Arc<UdpSocket>, tx: mpsc::Sender<(Bytes, SocketAddr)>) {
        let mut asm = FragmentAssembler::new();
        let mut buf = vec![0u8; PATH_MTU + 64];
        loop {
            let (n, src) = match sock.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(e) if is_advisory_recv_error(&e) => continue,
                Err(_) => return, // fatal socket error — stop this migration recv loop
            };
            match push_datagram(&mut asm, &buf[..n]) {
                Ok((_hdr, Some(frame))) => {
                    // A full channel drops the datagram (the peer retransmits); a closed
                    // channel means the session ended → stop the loop.
                    if tx.try_send((Bytes::from(frame), src)).is_err() && tx.is_closed() {
                        return;
                    }
                }
                Ok((_hdr, None)) => {} // partial fragment buffered
                Err(_) => {}           // malformed datagram — drop and keep receiving
            }
        }
    }
}

impl Drop for UdpServerTransport {
    fn drop(&mut self) {
        // Stop any in-flight server-migration recv loop so its task + socket are reclaimed
        // even if no further datagram ever arrives to trip the channel-closed check.
        if let Some(h) = self.migrate_task.get_mut().take() {
            h.abort();
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
        // ε / WIRE v5: stamp the rotating CID once the handshake set it.
        let cid = (**self.established_cid.load()).unwrap_or(self.cid);
        let dgrams = encode_datagrams(ty, &cid, pid, data)
            .map_err(|e| CoreError::NetworkError(format!("frame too large to fragment: {e}")))?;
        let peer = **self.peer.load();
        // Snapshot the active send socket (owned `Arc`) so we never hold an `ArcSwap` guard
        // across `.await` — a server `migrate_to` can swap it concurrently.
        let sock = self.send_socket.load_full();
        for d in &dgrams {
            sock.send_to(d, peer)
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
        // M-1: record the source + length but do NOT register a migration candidate here — this
        // frame has not been AEAD-verified yet, and a spoofed CID-matched datagram looks
        // identical at this point. The candidate is committed only from the post-decrypt
        // `confirm_authenticated_source`, so a spoofed source cannot clobber the candidate slot
        // and misdirect / stall a legitimate migration (Phase 4, P4.1 — detect-only, no switch).
        self.last_recv_src.store(Arc::new(Some(src)));
        self.last_frame_len
            .store(frame.len() as u64, Ordering::Relaxed);
        Ok(frame)
    }

    fn confirm_authenticated_source(&self) {
        // M-1: the frame from `last_recv_src` just authenticated (AEAD-opened), so it really is
        // the established peer — possibly at a NEW address (migration / NAT rebind). Register it
        // as the candidate the session challenges before switching, and (re)seed its
        // anti-amplification budget. A spoofed source never reaches here (its frame fails
        // decrypt), so it can never become the candidate.
        let src = match **self.last_recv_src.load() {
            Some(s) => s,
            None => return,
        };
        if src == **self.peer.load() {
            return; // already the established peer — not a new path
        }
        let len = self.last_frame_len.load(Ordering::Relaxed);
        if self.candidate.load().as_ref() == &Some(src) {
            self.cand_recv.fetch_add(len, Ordering::Relaxed);
        } else {
            self.candidate.store(Arc::new(Some(src)));
            self.cand_recv.store(len, Ordering::Relaxed);
            self.cand_sent.store(0, Ordering::Relaxed);
        }
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
        let sock = self.send_socket.load_full();
        for d in &dgrams {
            sock.send_to(d, addr)
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

    fn set_outbound_cid(&self, cid: [u8; 8]) {
        self.established_cid.store(Arc::new(Some(cid)));
    }

    /// SocketAddr-free trait entry for server-side migration. Parses the new local bind
    /// address and delegates to the typed [`migrate_to`](Self::migrate_to). A malformed
    /// address is a clean `Err` that leaves the session on its existing send socket
    /// (best-effort, never fatal).
    async fn migrate_server(&self, local_addr: String) -> Result<(), CoreError> {
        let addr: SocketAddr = local_addr.parse().map_err(|e| {
            CoreError::NetworkError(format!(
                "migrate_server: bad local addr '{local_addr}': {e}"
            ))
        })?;
        self.migrate_to(addr).await
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

    /// D1 (server migration): the client uses an UNCONNECTED socket, so it can hear a
    /// datagram from a source *other* than its original connect target — the precondition
    /// for following a server that has migrated its send address to a new socket. A
    /// connected socket drops such a datagram at the kernel (wrong source); the unconnected
    /// client must deliver it (the inner AEAD + replay window are the real guards).
    #[tokio::test]
    async fn client_hears_a_datagram_from_a_new_server_source() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();
        let client = UdpClientTransport::connect(server_addr).await.unwrap();
        client.set_frame_phase(FramePhase::Established);

        // The server learns the client's local address (so the new source can target it).
        client.send_bytes(b"hello").await.unwrap();
        let mut buf = vec![0u8; 2048];
        let (_n, client_addr) = server.recv_from(&mut buf).await.unwrap();

        // A DIFFERENT source (a migrated server's freshly-bound socket) sends a framed
        // datagram to the client. On a connected socket the kernel drops it; the
        // unconnected client must deliver it up through `recv_bytes`.
        let migrated = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        for d in encode_datagrams(PacketType::OneRtt, &client.cid(), 1, b"from-new-source").unwrap()
        {
            migrated.send_to(&d, client_addr).await.unwrap();
        }
        let got = tokio::time::timeout(Duration::from_secs(2), client.recv_bytes())
            .await
            .expect("client must hear a new server source (unconnected socket)")
            .expect("recv");
        assert_eq!(&got[..], b"from-new-source");
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
        let st = UdpServerTransport::new(sock.clone(), peer_addr, [3u8; 8], tx.clone(), rx);

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
        let st = UdpServerTransport::new(sock.clone(), peer, [9u8; 8], tx.clone(), rx);

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
        // M-1: the candidate is committed only on the post-decrypt (authenticated) path.
        st.confirm_authenticated_source();
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
        let ust = UdpServerTransport::new(server_sock.clone(), old_peer, [7u8; 8], tx.clone(), rx);
        ust.set_frame_phase(FramePhase::Established);

        assert!(
            !ust.promote_candidate(),
            "no candidate => nothing to promote"
        );

        // A frame from a new source sets the candidate (once it authenticates — M-1).
        tx.send((Bytes::from_static(b"hi"), new_addr))
            .await
            .unwrap();
        let _ = ust.recv_bytes().await.unwrap();
        ust.confirm_authenticated_source();
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

    /// D2 (server migration): `migrate_to` binds a fresh local socket, switches the server's
    /// SEND socket to it (so server→client datagrams egress a new source the client follows),
    /// and spawns a recv loop on it feeding the SAME inbound channel `recv_bytes` reads — so
    /// once the peer sends c2s to the new server address, its frames are delivered
    /// transparently (the listener demux keeps the old path alive during the overlap).
    #[tokio::test]
    async fn server_migrate_to_switches_send_socket_and_receives_on_it() {
        use tokio::sync::mpsc;
        let listener_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let listen_addr = listener_sock.local_addr().unwrap();
        let peer_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer = peer_sock.local_addr().unwrap();
        let (tx, rx) = mpsc::channel(16);
        let st = UdpServerTransport::new(listener_sock.clone(), peer, [4u8; 8], tx.clone(), rx);
        st.set_frame_phase(FramePhase::Established);

        // Pre-migration: the server's s2c egresses the (shared) listener socket.
        st.send_bytes(b"pre").await.unwrap();
        let mut buf = vec![0u8; 2048];
        let (_n, src_pre) = peer_sock.recv_from(&mut buf).await.unwrap();
        assert_eq!(
            src_pre, listen_addr,
            "pre-migration s2c egresses the listener socket"
        );

        // Migrate the server's send path to a fresh local socket.
        st.migrate_to("127.0.0.1:0".parse().unwrap())
            .await
            .expect("server migrate binds a new socket");

        // Post-migration: the server's s2c egresses the NEW socket — a different source the
        // client's unconnected socket (D1) can hear and follow.
        st.send_bytes(b"post").await.unwrap();
        let (_n2, src_post) = peer_sock.recv_from(&mut buf).await.unwrap();
        assert_ne!(
            src_post, src_pre,
            "server migration changes the s2c source address"
        );

        // The peer now sends c2s to the new server address; the migration recv loop must
        // forward it into the same channel `recv_bytes` reads.
        for d in
            encode_datagrams(PacketType::OneRtt, &[4u8; 8], 1, b"c2s-after-server-move").unwrap()
        {
            peer_sock.send_to(&d, src_post).await.unwrap();
        }
        let got = tokio::time::timeout(Duration::from_secs(2), st.recv_bytes())
            .await
            .expect("c2s on the migrated server socket reaches recv_bytes")
            .expect("recv");
        assert_eq!(&got[..], b"c2s-after-server-move");
    }

    /// D3 (server-migration follow): the CLIENT mirrors the server's candidate machinery — a
    /// NEW server source becomes a candidate ONLY post-authentication (M-1), a `PATH_CHALLENGE`
    /// reaches it under the 3× anti-amplification cap, and `promote_candidate` re-points
    /// `server_addr` so subsequent c2s flows to the migrated server.
    #[tokio::test]
    async fn client_detects_server_candidate_and_promotes_to_new_server_addr() {
        let orig_server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let orig_addr = orig_server.local_addr().unwrap();
        let client = UdpClientTransport::connect(orig_addr).await.unwrap();
        client.set_frame_phase(FramePhase::Established);

        assert!(!client.has_migration_candidate());
        assert!(
            !client.send_to_candidate(b"x").await.unwrap(),
            "no candidate => Ok(false)"
        );

        // Learn the client's local address so the migrated server can target it.
        client.send_bytes(b"hi").await.unwrap();
        let mut buf = vec![0u8; 2048];
        let (_n, client_addr) = orig_server.recv_from(&mut buf).await.unwrap();

        // A migrated server (a new source) sends a framed datagram; recv_bytes records it.
        let new_server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        for d in encode_datagrams(PacketType::OneRtt, &client.cid(), 1, b"0123456789").unwrap() {
            new_server.send_to(&d, client_addr).await.unwrap();
        }
        let _ = tokio::time::timeout(Duration::from_secs(2), client.recv_bytes())
            .await
            .expect("no timeout")
            .expect("recv");
        // M-1: a recv alone must NOT commit a candidate (it is not yet AEAD-verified).
        assert!(
            !client.has_migration_candidate(),
            "recv alone must NOT commit a candidate (M-1)"
        );
        client.confirm_authenticated_source();
        assert!(
            client.has_migration_candidate(),
            "an authenticated new server source sets the candidate"
        );

        // A challenge reaches the candidate (the migrated server) within the 3× budget.
        assert!(
            client.send_to_candidate(b"chal").await.unwrap(),
            "first challenge is within the 3× budget"
        );
        let (cn, _) = new_server.recv_from(&mut buf).await.unwrap();
        assert!(cn > 0, "the challenge must reach the new server socket");

        // Promote → `server_addr` switches to the new server; subsequent send_bytes go there.
        assert!(client.promote_candidate(), "candidate must be promoted");
        assert!(
            !client.has_migration_candidate(),
            "candidate cleared after promotion"
        );
        client.send_bytes(b"after").await.unwrap();
        let (an, _) = tokio::time::timeout(Duration::from_secs(1), new_server.recv_from(&mut buf))
            .await
            .expect("post-promote c2s reaches the migrated server")
            .unwrap();
        assert!(an > 0);
    }

    /// Review finding (overlap-drop robustness): a client mid-(local)-migration overlap must
    /// retire its old socket on the first well-formed datagram on the NEW socket REGARDLESS
    /// of source — including from a server that has itself migrated to a new address. A
    /// `src == server_addr` check would never fire for a migrated server and strand the
    /// overlap (an idle extra socket for the session's life).
    #[tokio::test]
    async fn overlap_ends_on_data_from_a_migrated_server_source() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();
        let client = UdpClientTransport::connect(server_addr).await.unwrap();
        client.set_frame_phase(FramePhase::Established);

        client.send_bytes(b"hi").await.unwrap();
        let mut buf = vec![0u8; 2048];
        let (_n, _src_old) = server.recv_from(&mut buf).await.unwrap();

        // Enter a (client-local) migration overlap.
        client
            .migrate_to("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        assert!(
            client.in_migration_overlap(),
            "migrate_to enters the dual-socket overlap"
        );

        // Learn the new client socket's address (so a third party can target it).
        client.send_bytes(b"probe").await.unwrap();
        let (_n2, client_new_addr) = server.recv_from(&mut buf).await.unwrap();

        // A datagram from a DIFFERENT source than the original server (a migrated server's
        // fresh socket) arrives on the new socket — it must be delivered AND end the overlap.
        let migrated_server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        for d in encode_datagrams(
            PacketType::OneRtt,
            &client.cid(),
            1,
            b"from-migrated-server",
        )
        .unwrap()
        {
            migrated_server.send_to(&d, client_new_addr).await.unwrap();
        }
        let got = tokio::time::timeout(Duration::from_secs(2), client.recv_bytes())
            .await
            .expect("no timeout")
            .expect("recv");
        assert_eq!(&got[..], b"from-migrated-server");
        assert!(
            !client.in_migration_overlap(),
            "a well-formed datagram on the new socket (even from a migrated server source) \
             must end the overlap"
        );
    }

    /// Review finding (H-1 reaping, refutation + guard): adding a `tx` clone to
    /// `UdpServerTransport` (so a server migration's recv loop can feed the same channel)
    /// does NOT break the demux's route reaping. `mpsc::Sender::is_closed()` tracks the
    /// RECEIVER being dropped, not the sender-clone count — so when the transport (which owns
    /// the `rx`) is dropped at session end, a sibling `tx` clone the demux retains for routing
    /// immediately observes `is_closed() == true` and the route is reclaimed.
    #[tokio::test]
    async fn dropping_the_transport_closes_the_demux_tx_clone() {
        use tokio::sync::mpsc;
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let peer = UdpSocket::bind("127.0.0.1:0")
            .await
            .unwrap()
            .local_addr()
            .unwrap();
        let (tx, rx) = mpsc::channel(8);
        // The RouteTable retains a sibling clone for routing; the transport gets another.
        let demux_clone = tx.clone();
        let st = UdpServerTransport::new(sock, peer, [1u8; 8], tx.clone(), rx);
        assert!(
            !demux_clone.is_closed(),
            "a live session's route stays open"
        );
        // Session ends: the transport (holding `rx` + its own `tx` clone) is dropped.
        drop(st);
        assert!(
            demux_clone.is_closed(),
            "the demux's tx clone observes the dropped receiver (is_closed tracks the \
             receiver, not the sender-clone count), so the route is reaped — the transport's \
             extra tx clone does not strand it"
        );
    }

    /// P4.2b: `migrate()` rebinds the client to a fresh (still unconnected) local socket
    /// that keeps `send_to`-ing the same `server_addr`, so the client's source address
    /// changes — which is what makes the server detect the new path (P4.1). The new socket
    /// becomes the active send/recv socket; a reply to the new source is received.
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
            .migrate_to("127.0.0.1:0".parse().unwrap())
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
            .migrate_to("127.0.0.1:0".parse().unwrap())
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

    /// P4.2c: the SocketAddr-free `migrate(String)` trait entry parses the address; a
    /// malformed address is a clean `Err` and leaves the session untouched on the old
    /// socket (best-effort, never fatal). The session keeps working afterwards.
    #[tokio::test]
    async fn migrate_with_a_bad_local_addr_is_a_clean_error() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();
        let client = UdpClientTransport::connect(server_addr).await.unwrap();
        client.set_frame_phase(FramePhase::Established);

        // Unparseable address → Err, no rebind (the SocketAddr-free trait entry).
        let err = client.migrate("not-an-address".to_string()).await;
        assert!(err.is_err(), "a malformed local addr must be a clean Err");

        // The session still works on the original socket.
        client.send_bytes(b"still-alive").await.unwrap();
        let mut buf = vec![0u8; 2048];
        let (n, _from) = tokio::time::timeout(Duration::from_secs(2), server.recv_from(&mut buf))
            .await
            .expect("no timeout")
            .unwrap();
        assert!(
            n > 0,
            "data still flows on the original socket after a failed migrate"
        );
    }

    /// M-1 (audit 2026-06-11): the migration candidate (the server's PATH_CHALLENGE target)
    /// must be registered only from an AEAD-AUTHENTICATED frame, not from any CID-matched
    /// datagram's raw source — else a spoofed source can clobber the single candidate slot and
    /// misdirect / stall a legitimate migration. `recv_bytes` records but does not commit; the
    /// post-decrypt `confirm_authenticated_source` commits.
    #[tokio::test]
    async fn candidate_is_set_only_from_an_authenticated_source() {
        use tokio::sync::mpsc;
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let peer = UdpSocket::bind("127.0.0.1:0")
            .await
            .unwrap()
            .local_addr()
            .unwrap();
        let (tx, rx) = mpsc::channel(8);
        let st = UdpServerTransport::new(sock.clone(), peer, [5u8; 8], tx.clone(), rx);

        // A frame from a NEW source arrives but has not yet been AEAD-verified (pre-decrypt) —
        // exactly what a spoofed CID-matched datagram looks like at recv time.
        let other = UdpSocket::bind("127.0.0.1:0")
            .await
            .unwrap()
            .local_addr()
            .unwrap();
        tx.send((Bytes::from_static(b"pre-decrypt-source"), other))
            .await
            .unwrap();
        let _ = st.recv_bytes().await.unwrap();
        assert!(
            !st.has_migration_candidate(),
            "a pre-decrypt (possibly spoofed) source must NOT set the migration candidate (M-1)"
        );

        // Once that frame authenticates (AEAD-opens), the post-decrypt path commits it.
        st.confirm_authenticated_source();
        assert!(
            st.has_migration_candidate(),
            "an AEAD-authenticated new source sets the migration candidate"
        );
    }

    /// M-6 (audit 2026-06-11): an ICMP-induced recv error (the forged-RST analogue — a spoofed
    /// "port unreachable") must be treated as ADVISORY and retried, never mapped to a fatal
    /// `NetworkError` that tears the session down bypassing the liveness machinery (RFC 8085
    /// §5.5 / RFC 9000 §14.2). A genuine error stays fatal; a datagram carries its source.
    #[test]
    fn advisory_icmp_recv_errors_are_retried_not_fatal() {
        use std::io::{Error, ErrorKind};
        assert!(matches!(
            classify_recv(Err(Error::from(ErrorKind::ConnectionRefused))),
            RecvAction::Retry
        ));
        assert!(matches!(
            classify_recv(Err(Error::from(ErrorKind::ConnectionReset))),
            RecvAction::Retry
        ));
        assert!(matches!(
            classify_recv(Err(Error::from(ErrorKind::PermissionDenied))),
            RecvAction::Fatal(_)
        ));
        let addr: SocketAddr = "127.0.0.1:9".parse().unwrap();
        assert!(matches!(
            classify_recv(Ok((42, addr))),
            RecvAction::Got(42, s) if s == addr
        ));
    }
}
