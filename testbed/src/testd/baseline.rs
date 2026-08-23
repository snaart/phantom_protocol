//! Raw TCP / UDP servers — the control group.
//!
//! No Phantom, no handshake, no crypto: just the path itself. Without this,
//! "PhantomUDP sustained X Mbit/s at Y ms" is uninterpretable, because the
//! link's own ceiling and jitter floor are unknown. Every protocol number in
//! the report is meant to be read as a ratio against these.
//!
//! The TCP baseline uses the same 4-byte big-endian length prefix as
//! `TcpSessionTransport`, so the framing cost is matched and the difference
//! measured is the protocol's, not the framing's.
//!
//! **"Raw" here means no Phantom, not no protocol — and for TCP those are
//! different things.** A UDP socket adds nothing to the path, which is what
//! makes the datagram ladders a denominator. A TCP socket adds congestion
//! control, reliability and flow control: the very mechanisms under test. So
//! the TCP echo's *throughput* is what a kernel TCP achieves here, which is a
//! yardstick of the same kind as the QUIC leg and not a floor beneath anything.
//! Its *latency* sweep is a different matter and remains the path's own
//! round-trip floor. The probe's scenario states this beside its number.
//!
//! Four controls, and they answer different questions. The echoes are round
//! trips, so neither direction is isolated in them; the two one-way controls
//! are what put a number under a single direction. The **downstream source**
//! ([`serve_udp_source`]) sends server → client, under every leg's `download`.
//! The **uplink sink** ([`serve_udp_sink`]) receives client → server, under
//! every leg's `upload` — and that one is the receiver, so the account it keeps
//! is the honest one: a sender counts what it handed to a socket.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

use crate::downlink::{
    Challenge, CookieMinter, DataHeader, Report, Request, SeqTracker, Stamps, MAX_PAYLOAD,
    MIN_PAYLOAD,
};
use crate::pacing::{Pacer, MISSED_TICK, TICK};
use crate::proto::PayloadGen;
use crate::report::unix_nanos;
use crate::uplink;

/// Matches the established-phase frame cap of `TcpSessionTransport`.
const MAX_FRAME: u32 = 4 * 1024 * 1024;

/// Room the echo's reusable frame buffer keeps between frames.
///
/// Large frames are still served — the buffer grows for them — but it is
/// released afterwards, because this port is public and unauthenticated: a peer
/// that declares one `MAX_FRAME` frame would otherwise leave four megabytes
/// resident for as long as it holds the connection open. The reuse exists to
/// keep an allocation out of the turnaround loop, and only ordinary frame sizes
/// are in that loop.
const ECHO_BUF_BYTES: usize = 4 + 64 * 1024;

/// What this side asks the kernel for in each direction, matching the probe's
/// own request so that neither end is the smaller of the pair.
const SOCKET_BUFFER: usize = 1024 * 1024;

/// Request larger socket buffers; the kernel may clamp, and that is fine — the
/// point is not to be the bottleneck, not to hit an exact number.
///
/// Generic over anything holding a socket because it is applied twice: once to
/// the **listening** socket and once to each accepted one. The listener is the
/// load-bearing call — an accepted connection's window scale is chosen when the
/// SYN-ACK is built, from the buffer the listener held, so sizing only the
/// accepted socket raises the buffer while leaving the advertised window capped
/// by a factor derived from the default.
fn size_socket_buffers<S: std::os::fd::AsFd>(sock: &S, want: usize) {
    let s2 = socket2::SockRef::from(sock);
    let _ = s2.set_send_buffer_size(want);
    let _ = s2.set_recv_buffer_size(want);
}

#[derive(Default)]
pub struct BaselineStats {
    pub tcp_conns: AtomicU64,
    pub tcp_frames: AtomicU64,
    pub tcp_bytes: AtomicU64,
    pub udp_datagrams: AtomicU64,
    pub udp_bytes: AtomicU64,
    /// Downstream source: rungs started, datagrams and bytes actually sent, and
    /// requests turned away. The last one is the interesting counter — a
    /// non-zero `down_refused` on a run with sparse results says the daemon
    /// declined to send, which looks identical to a lossy path from the
    /// client's side and is not.
    pub down_rungs: AtomicU64,
    pub down_datagrams: AtomicU64,
    pub down_bytes: AtomicU64,
    pub down_challenges: AtomicU64,
    pub down_refused: AtomicU64,
    /// Uplink sink: rungs armed, datagrams and bytes observed, requests turned
    /// away, and accounts sent back. `up_reports` is the one to read against a
    /// client that reported no denominator — a report the sink says it sent and
    /// the probe never saw is a loss on the way *down*, which is a different
    /// finding from a rung that was never observed.
    pub up_rungs: AtomicU64,
    pub up_datagrams: AtomicU64,
    pub up_bytes: AtomicU64,
    pub up_challenges: AtomicU64,
    pub up_refused: AtomicU64,
    pub up_reports: AtomicU64,
}

/// Length-prefixed TCP echo.
pub async fn run_tcp(addr: String, stats: Arc<BaselineStats>) -> std::io::Result<()> {
    let listener = TcpListener::bind(&addr).await?;
    tracing::info!(addr = %addr, "raw TCP echo baseline listening");
    serve_tcp(listener, stats).await
}

/// Serve on an already-bound listener.
///
/// Split out from [`run_tcp`] so a caller that needs to know the port before
/// the server starts (a test on port 0) can bind once and hand the socket over,
/// rather than binding, closing, and racing to rebind the same port.
pub async fn serve_tcp(listener: TcpListener, stats: Arc<BaselineStats>) -> std::io::Result<()> {
    // Before the first accept, so that every connection's SYN-ACK carries a
    // window scale chosen from this size rather than from the default. Doing it
    // only on the accepted socket, as this did, raises the buffer after the
    // factor that caps the advertised window has already been fixed.
    size_socket_buffers(&listener, SOCKET_BUFFER);
    loop {
        let (mut sock, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "raw tcp accept failed");
                continue;
            }
        };
        // Nagle off: the baseline measures the path, and coalescing small
        // frames would flatter it relative to a protocol that paces explicitly.
        let _ = sock.set_nodelay(true);
        // Size the buffers for the bandwidth-delay product. A control that
        // leaves them at the OS default measures `default / rtt` and reports it
        // as the link — which is how this probe once produced a "path ceiling"
        // that was really the kernel's. The accepted socket is sized as well as
        // the listener because inheritance covers the window scale, and this
        // covers the buffer itself on systems that do not carry it over.
        size_socket_buffers(&sock, SOCKET_BUFFER);
        stats.tcp_conns.fetch_add(1, Ordering::Relaxed);
        let stats = stats.clone();

        // One task per connection turning each frame around in lockstep: read a
        // whole frame, then write it back. That is what an echo is, but it also
        // couples the two directions — when the return path backs up, the write
        // parks and this task stops reading, so the forward direction cannot
        // stay full while the reverse is congested. Together with both
        // directions sharing one connection's ack clock it is why the echo's
        // throughput bounds the two directions together and neither alone; the
        // probe's own scenario says so beside the number rather than leaving it
        // to be rediscovered.
        tokio::spawn(async move {
            // The frame's whole wire form, header included, in one buffer that
            // survives between frames. The body used to be a fresh allocation
            // per frame, which put an allocator call inside the turnaround this
            // control is measuring; and the header and body used to be two
            // writes, which with Nagle off puts a four-byte segment on the wire
            // ahead of every frame whenever the send buffer had drained, so the
            // control's packet rate was twice its frame rate for nothing.
            let mut frame = vec![0u8; ECHO_BUF_BYTES];
            loop {
                if sock.read_exact(&mut frame[..4]).await.is_err() {
                    break;
                }
                let len = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]);
                if len > MAX_FRAME {
                    tracing::warn!(%peer, len, "raw tcp frame over cap; closing");
                    break;
                }
                let total = 4 + len as usize;
                if frame.len() < total {
                    frame.resize(total, 0);
                }
                if sock.read_exact(&mut frame[4..total]).await.is_err() {
                    break;
                }
                if sock.write_all(&frame[..total]).await.is_err() {
                    break;
                }
                if frame.len() > ECHO_BUF_BYTES {
                    frame = vec![0u8; ECHO_BUF_BYTES];
                }
                stats.tcp_frames.fetch_add(1, Ordering::Relaxed);
                stats.tcp_bytes.fetch_add(len as u64, Ordering::Relaxed);
            }
        });
    }
}

/// Datagram echo. One socket, no per-peer state — the path is the only thing
/// under measurement.
pub async fn run_udp(addr: String, stats: Arc<BaselineStats>) -> std::io::Result<()> {
    let sock = UdpSocket::bind(&addr).await?;
    tracing::info!(addr = %addr, "raw UDP echo baseline listening");
    serve_udp(sock, stats).await
}

/// Serve on an already-bound socket. See [`serve_tcp`] for why this split exists.
pub async fn serve_udp(sock: UdpSocket, stats: Arc<BaselineStats>) -> std::io::Result<()> {
    // 64 KiB covers the largest datagram IPv4 permits; the path itself tops out
    // far lower (measured ~1392 B payload), which is one of the things the
    // client's size sweep is there to discover rather than assume.
    let mut buf = vec![0u8; 65_536];
    loop {
        let (n, peer) = match sock.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "raw udp recv failed");
                continue;
            }
        };
        if sock.send_to(&buf[..n], peer).await.is_ok() {
            stats.udp_datagrams.fetch_add(1, Ordering::Relaxed);
            stats.udp_bytes.fetch_add(n as u64, Ordering::Relaxed);
        }
    }
}

// ── Downstream source ───────────────────────────────────────────────────────

/// Concurrent bursts the daemon will run at once.
///
/// A downstream rung saturates the box's uplink by design, so running several
/// means none of them measures anything. Four is enough that a probe retrying
/// after a lost request is not blocked by its own abandoned rung.
const MAX_CONCURRENT_BURSTS: usize = 4;

/// Hard ceilings on what a single request may ask for.
///
/// The duration cap is the load-bearing one: it is what guarantees a client
/// that vanishes mid-rung cannot leave the daemon sending. Nothing else in this
/// path depends on hearing from the client again, so the burst has to be
/// self-terminating or it is unbounded.
const MAX_RUNG: Duration = Duration::from_secs(60);
const MAX_RUNG_KBPS: u32 = 1_000_000;
const MAX_RUNG_BYTES: u64 = 512 * 1024 * 1024;

/// Consecutive send failures that end a rung early.
///
/// Transient `ENOBUFS` under a saturated uplink is expected and must not abort
/// the measurement; a socket that has stopped accepting anything at all is a
/// different thing, and continuing to spin on it would burn the rung's whole
/// window producing nothing.
const MAX_CONSECUTIVE_SEND_ERRORS: u32 = 256;

/// Quiet period before the sender states its own account.
///
/// The report follows a burst that has just filled the path's queues; sending
/// it immediately puts it at the back of that queue, where it is most likely to
/// be the datagram that gets dropped. Letting the queue drain first is what
/// makes a rung's sender-side account usually arrive.
const REPORT_SETTLE: Duration = Duration::from_millis(100);

/// Copies of the report, and the gap between them.
///
/// The report is a single unacknowledged datagram carrying the denominator for
/// the entire rung: lose it and the rung has no admissible reading at all. Four
/// spaced copies cost 184 bytes and remove that failure mode; the receiver
/// takes the first and ignores the rest.
const REPORT_COPIES: usize = 4;
const REPORT_SPACING: Duration = Duration::from_millis(50);

/// One-way paced datagram source: the server → client capacity control.
pub async fn run_udp_source(addr: String, stats: Arc<BaselineStats>) -> std::io::Result<()> {
    let sock = UdpSocket::bind(&addr).await?;
    tracing::info!(addr = %addr, "raw UDP downstream source listening");
    serve_udp_source(sock, stats).await
}

/// Serve on an already-bound socket. See [`serve_tcp`] for why this split
/// exists.
pub async fn serve_udp_source(sock: UdpSocket, stats: Arc<BaselineStats>) -> std::io::Result<()> {
    let sock = Arc::new(sock);
    let minter = Arc::new(CookieMinter::new());
    let slots = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_BURSTS));
    // One rung per peer at a time. Without it a client that retries a lost
    // request would have two bursts interleaved on the same path, and the
    // rung's own traffic would be its confound.
    let busy: Arc<StdMutex<HashSet<std::net::SocketAddr>>> = Arc::default();

    // Requests are fixed-width; anything longer is not one, so a small buffer
    // is not a truncation risk. It also means this listener cannot be made to
    // read a large datagram on an attacker's say-so.
    let mut buf = [0u8; 128];
    loop {
        let (n, peer) = match sock.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "raw udp source recv failed");
                continue;
            }
        };

        // Unrecognised traffic gets no reply whatsoever. A public UDP port that
        // answers scans is a reflector, and this one exists to measure a path,
        // not to be aimed at one.
        let Some(req) = Request::decode(&buf[..n]) else {
            continue;
        };

        let now_secs = unix_nanos() / 1_000_000_000;
        if !req.has_cookie() || !minter.verify(&req.cookie, peer, now_secs) {
            let ch = Challenge {
                run_nonce: req.run_nonce,
                cookie: minter.mint(peer, now_secs),
            };
            let _ = sock.send_to(&ch.encode(), peer).await;
            stats.down_challenges.fetch_add(1, Ordering::Relaxed);
            continue;
        }

        let plan = RungPlan::from_request(&req);
        let permit = match slots.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                refuse(&sock, peer, &plan, &stats, "no burst slot free");
                continue;
            }
        };
        {
            let mut g = busy.lock().unwrap_or_else(|e| e.into_inner());
            if !g.insert(peer) {
                drop(g);
                refuse(&sock, peer, &plan, &stats, "a rung is already running");
                continue;
            }
        }

        stats.down_rungs.fetch_add(1, Ordering::Relaxed);
        let sock2 = sock.clone();
        let stats2 = stats.clone();
        let busy2 = busy.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let sent = send_rung(&sock2, peer, &plan, &stats2).await;
            send_report(&sock2, peer, &plan, sent).await;
            busy2
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&peer);
        });
    }
}

/// A request, clamped to what the daemon is willing to do.
#[derive(Debug, Clone, Copy)]
struct RungPlan {
    run_nonce: u64,
    rung: u16,
    offered_kbps: u32,
    duration: Duration,
    payload_len: usize,
}

impl RungPlan {
    fn from_request(r: &Request) -> Self {
        Self {
            run_nonce: r.run_nonce,
            rung: r.rung,
            offered_kbps: r.offered_kbps.clamp(1, MAX_RUNG_KBPS),
            duration: Duration::from_millis(r.duration_ms.max(1) as u64).min(MAX_RUNG),
            payload_len: (r.payload_len as usize).clamp(MIN_PAYLOAD, MAX_PAYLOAD),
        }
    }
}

/// What a rung actually put on the wire.
#[derive(Debug, Clone, Copy, Default)]
struct Sent {
    datagrams: u64,
    bytes: u64,
    elapsed_ns: u64,
}

/// Decline a rung by reporting that nothing was sent.
///
/// Deliberately not a new message kind. A refusal *is* a sender that achieved
/// zero against its offer, and the client's existing "did the sender reach its
/// offer" test already renders that as an inadmissible rung — which is exactly
/// the right reading, and one fewer thing on the wire to get wrong.
///
/// Spawned rather than awaited: the report is deliberately spread over a few
/// hundred milliseconds, and sending it from the accept loop would let a stream
/// of refusable requests stall the listener for as long as the sender liked.
fn refuse(
    sock: &Arc<UdpSocket>,
    peer: std::net::SocketAddr,
    plan: &RungPlan,
    stats: &Arc<BaselineStats>,
    why: &'static str,
) {
    stats.down_refused.fetch_add(1, Ordering::Relaxed);
    tracing::debug!(%peer, rung = plan.rung, why, "declining a downstream rung");
    let sock = sock.clone();
    let plan = *plan;
    tokio::spawn(async move {
        send_report(&sock, peer, &plan, Sent::default()).await;
    });
}

/// Pace one rung at the offered rate for its bounded interval.
async fn send_rung(
    sock: &UdpSocket,
    peer: std::net::SocketAddr,
    plan: &RungPlan,
    stats: &BaselineStats,
) -> Sent {
    let mut pacer = Pacer::new(plan.offered_kbps as u64, plan.payload_len);
    let mut tick = tokio::time::interval(TICK);
    tick.set_missed_tick_behavior(MISSED_TICK);

    // One buffer for the whole rung, filled once with pseudo-random bytes and
    // rewritten in place per datagram. Deterministic filler rather than zeroes
    // so nothing downstream can benefit from compressibility, matching the
    // reasoning in `proto::PayloadGen`.
    let mut buf = PayloadGen::new(plan.run_nonce ^ plan.rung as u64).fill(plan.payload_len);

    let started = Instant::now();
    let deadline = started + plan.duration;
    let mut sent = Sent::default();
    let mut consecutive_errors = 0u32;

    'rung: while Instant::now() < deadline {
        tick.tick().await;
        for _ in 0..pacer.on_tick() {
            if Instant::now() >= deadline || sent.bytes >= MAX_RUNG_BYTES {
                break 'rung;
            }
            DataHeader {
                run_nonce: plan.run_nonce,
                rung: plan.rung,
                seq: sent.datagrams,
                send_unix_ns: unix_nanos(),
            }
            .write_into(&mut buf);

            match sock.send_to(&buf, peer).await {
                Ok(n) => {
                    consecutive_errors = 0;
                    sent.datagrams += 1;
                    sent.bytes += n as u64;
                }
                Err(_) => {
                    consecutive_errors += 1;
                    if consecutive_errors >= MAX_CONSECUTIVE_SEND_ERRORS {
                        break 'rung;
                    }
                }
            }
        }
    }

    sent.elapsed_ns = started.elapsed().as_nanos() as u64;
    stats
        .down_datagrams
        .fetch_add(sent.datagrams, Ordering::Relaxed);
    stats.down_bytes.fetch_add(sent.bytes, Ordering::Relaxed);
    sent
}

async fn send_report(sock: &UdpSocket, peer: std::net::SocketAddr, plan: &RungPlan, sent: Sent) {
    let bytes = Report {
        run_nonce: plan.run_nonce,
        rung: plan.rung,
        offered_kbps: plan.offered_kbps,
        datagrams: sent.datagrams,
        bytes: sent.bytes,
        elapsed_ns: sent.elapsed_ns,
    }
    .encode();

    tokio::time::sleep(REPORT_SETTLE).await;
    for i in 0..REPORT_COPIES {
        if i > 0 {
            tokio::time::sleep(REPORT_SPACING).await;
        }
        let _ = sock.send_to(&bytes, peer).await;
    }
}

// ── Uplink sink ─────────────────────────────────────────────────────────────

/// Rungs the sink will observe at once.
///
/// Not a bandwidth bound — inbound rungs do not contend for the daemon's uplink
/// the way outbound bursts do — but a memory one, and a bound on what a
/// measurement is worth. Each armed rung holds a [`SeqTracker`]: a fixed
/// 4096-slot window plus the individual reorder measurements behind its
/// percentiles, which its own cap keeps finite. Four of those is a bound a
/// 2 GB host does not notice, and two probes measuring at once would each be
/// measuring the other anyway.
const MAX_CONCURRENT_UPLINK_RUNGS: usize = 4;

/// How long past a rung's own length the sink keeps counting.
///
/// Datagrams the client put on the wire at the end of its interval are still in
/// flight when that interval ends, and a window that closed with them still
/// crossing would book them as loss the path never caused. Two seconds clears
/// any plausible path delay plus a reordering tail. It is deliberately a fixed
/// wait rather than an early close on silence: closing on a quiet period would
/// turn a stalled sender into a shortened observation, and a shortened
/// observation reads as loss.
const UPLINK_RUNG_GRACE: Duration = Duration::from_secs(2);

/// How often expired rungs are swept out and their accounts sent.
const UPLINK_SWEEP: Duration = Duration::from_millis(100);

/// Receive buffer asked for on the sink socket.
///
/// The instrument must not measure itself, and on a receiver the way it does
/// that is by dropping datagrams in the kernel during a scheduling gap and
/// reporting them as the path's loss. The top of the default ladder is
/// 200 Mbit/s — about 25 MB/s in 1200 B datagrams — so 4 MiB is roughly 160 ms
/// of cover. The kernel may clamp, which is why the grant is logged rather than
/// the request.
const UPLINK_RECV_BUFFER: usize = 4 * 1024 * 1024;

/// One-way paced datagram sink: the client → server capacity control.
pub async fn run_udp_sink(addr: String, stats: Arc<BaselineStats>) -> std::io::Result<()> {
    let sock = UdpSocket::bind(&addr).await?;
    tracing::info!(addr = %addr, "raw UDP uplink sink listening");
    serve_udp_sink(sock, stats).await
}

/// Serve on an already-bound socket. See [`serve_tcp`] for why this split
/// exists.
pub async fn serve_udp_sink(sock: UdpSocket, stats: Arc<BaselineStats>) -> std::io::Result<()> {
    let granted = size_udp_recv_buffer(&sock, UPLINK_RECV_BUFFER);
    tracing::debug!(
        granted,
        asked = UPLINK_RECV_BUFFER,
        "uplink sink receive buffer"
    );

    let sock = Arc::new(sock);
    let minter = CookieMinter::new();
    let mut rungs: HashMap<SocketAddr, UpRung> = HashMap::new();

    // Every uplink datagram is at most `MAX_PAYLOAD`, so a fixed buffer of that
    // size is not a truncation risk — and it means this listener cannot be made
    // to read a large datagram on a sender's say-so.
    let mut buf = vec![0u8; MAX_PAYLOAD];
    let mut sweep = tokio::time::interval(UPLINK_SWEEP);
    sweep.set_missed_tick_behavior(MISSED_TICK);

    loop {
        // The received bytes are handled after the `select!` rather than inside
        // an arm: the receive future holds `buf` mutably for as long as the
        // expression lasts, and the handler needs to read it.
        let woke = tokio::select! {
            r = sock.recv_from(&mut buf) => match r {
                Ok((n, peer)) => Some((n, peer)),
                Err(e) => {
                    tracing::warn!(error = %e, "raw udp sink recv failed");
                    None
                }
            },
            _ = sweep.tick() => None,
        };

        match woke {
            Some((n, peer)) => {
                on_uplink_datagram(&sock, &minter, &stats, &mut rungs, peer, &buf[..n]).await
            }
            None => expire_uplink_rungs(&sock, &stats, &mut rungs),
        }
    }
}

/// Ask the kernel for a larger receive buffer and report what it granted.
///
/// The grant matters more than the request: operating systems clamp, and a
/// silently clamped buffer is exactly how a control comes to measure itself.
fn size_udp_recv_buffer(sock: &UdpSocket, want: usize) -> usize {
    use std::os::fd::{AsRawFd, BorrowedFd};
    // SAFETY: the fd is owned by `sock` and outlives this borrow; socket2 only
    // reads and sets options on it, and does not take ownership.
    let borrowed = unsafe { BorrowedFd::borrow_raw(sock.as_raw_fd()) };
    let s2 = socket2::SockRef::from(&borrowed);
    let _ = s2.set_recv_buffer_size(want);
    s2.recv_buffer_size().unwrap_or(0)
}

/// One rung being observed: the receiver's ledger and the window it covers.
struct UpRung {
    run_nonce: u64,
    rung: u16,
    tracker: SeqTracker,
    /// Zero of this rung's receive clock. Reorder displacements are differences
    /// within it, so where it starts does not matter — only that it is
    /// monotonic and that the sender's stamps are never subtracted from it.
    base: Instant,
    deadline: Instant,
    /// The first arrival and how many bytes it carried. The bytes are reported
    /// so the client can measure over the interval the arrivals span: `n`
    /// datagrams span `n - 1` gaps.
    first: Option<(Instant, u64)>,
    last: Option<Instant>,
    received_bytes: u64,
}

impl UpRung {
    /// Arm a rung for a request that has already passed the cookie gate.
    fn armed(req: &uplink::Request) -> Self {
        // A request is not permission to keep a ledger for as long as the asker
        // likes. The same clamp the downstream source puts on a burst, for the
        // same reason: nothing in this path ever hears from the client again,
        // so the rung has to be self-terminating or it is unbounded.
        let duration = Duration::from_millis(req.duration_ms.max(1) as u64).min(MAX_RUNG);
        let now = Instant::now();
        Self {
            run_nonce: req.run_nonce,
            rung: req.rung,
            tracker: SeqTracker::new(),
            base: now,
            deadline: now + duration + UPLINK_RUNG_GRACE,
            first: None,
            last: None,
            received_bytes: 0,
        }
    }

    fn account(&self) -> uplink::Report {
        // First arrival to last arrival: the receiver's own observation
        // interval, which excludes the request's round trip and the client's
        // start-up. The same definition the downstream ladder's receiver uses.
        let observed_window_ns = match (self.first, self.last) {
            (Some((a, _)), Some(b)) if b > a => b.duration_since(a).as_nanos() as u64,
            _ => 0,
        };
        uplink::Report {
            run_nonce: self.run_nonce,
            rung: self.rung,
            received_datagrams: self.tracker.received(),
            received_bytes: self.received_bytes,
            first_datagram_bytes: self.first.map(|(_, n)| n).unwrap_or(0),
            reordered_datagrams: self.tracker.reordered(),
            duplicate_datagrams: self.tracker.duplicates(),
            observed_window_ns,
            // Taken here, after the grace period has drained the tail: it is
            // this call that draws the line between a gap still open and one a
            // late arrival filled.
            reorder: self.tracker.profile(),
        }
    }
}

async fn on_uplink_datagram(
    sock: &Arc<UdpSocket>,
    minter: &CookieMinter,
    stats: &Arc<BaselineStats>,
    rungs: &mut HashMap<SocketAddr, UpRung>,
    peer: SocketAddr,
    datagram: &[u8],
) {
    let len = datagram.len();
    // Data first: at the top of the ladder it is twenty thousand datagrams a
    // second against one request per rung, and the cheap branch belongs where
    // the traffic is.
    if let Some(h) = uplink::DataHeader::decode(datagram) {
        // No armed rung means no ledger to put it in, and answering would make
        // a public port a reflector. Silence.
        let Some(r) = rungs.get_mut(&peer) else {
            return;
        };
        if h.run_nonce != r.run_nonce || h.rung != r.rung {
            return;
        }
        let now = Instant::now();
        let stamps = Stamps {
            recv_ns: now.saturating_duration_since(r.base).as_nanos() as u64,
            send_ns: h.send_unix_ns,
        };
        if r.tracker.observe_stamped(h.seq, stamps) {
            r.received_bytes += len as u64;
            if r.first.is_none() {
                r.first = Some((now, len as u64));
            }
        }
        // Updated even for a duplicate: it still arrived, and the window is
        // about when arrivals stopped rather than about which were distinct.
        r.last = Some(now);
        stats.up_datagrams.fetch_add(1, Ordering::Relaxed);
        stats.up_bytes.fetch_add(len as u64, Ordering::Relaxed);
        return;
    }

    // Unrecognised traffic gets no reply whatsoever. A public UDP port that
    // answers scans is a reflector, and this one exists to measure a path.
    let Some(req) = uplink::Request::decode(datagram) else {
        return;
    };

    let now_secs = unix_nanos() / 1_000_000_000;
    if !req.has_cookie() || !minter.verify(&req.cookie, peer, now_secs) {
        let ch = uplink::Challenge {
            run_nonce: req.run_nonce,
            cookie: minter.mint(peer, now_secs),
        };
        let _ = sock.send_to(&ch.encode(), peer).await;
        stats.up_challenges.fetch_add(1, Ordering::Relaxed);
        return;
    }

    // A request replaces that peer's rung rather than being refused as a
    // duplicate. A repeated request means the client never saw the `Ready` and
    // has therefore sent nothing yet, so re-arming is idempotent — and refusing
    // it would strand a rung the client is still waiting to start.
    if !rungs.contains_key(&peer) && rungs.len() >= MAX_CONCURRENT_UPLINK_RUNGS {
        let _ = sock
            .send_to(
                &uplink::Ready {
                    run_nonce: req.run_nonce,
                    rung: req.rung,
                    accepted: false,
                }
                .encode(),
                peer,
            )
            .await;
        stats.up_refused.fetch_add(1, Ordering::Relaxed);
        tracing::debug!(%peer, rung = req.rung, "declining an uplink rung: no slot free");
        return;
    }

    rungs.insert(peer, UpRung::armed(&req));
    stats.up_rungs.fetch_add(1, Ordering::Relaxed);
    let _ = sock
        .send_to(
            &uplink::Ready {
                run_nonce: req.run_nonce,
                rung: req.rung,
                accepted: true,
            }
            .encode(),
            peer,
        )
        .await;
}

/// Close out every rung whose window has ended and send its account back.
fn expire_uplink_rungs(
    sock: &Arc<UdpSocket>,
    stats: &Arc<BaselineStats>,
    rungs: &mut HashMap<SocketAddr, UpRung>,
) {
    let now = Instant::now();
    let due: Vec<SocketAddr> = rungs
        .iter()
        .filter(|(_, r)| now >= r.deadline)
        .map(|(p, _)| *p)
        .collect();

    for peer in due {
        let Some(r) = rungs.remove(&peer) else {
            continue;
        };
        let bytes = r.account().encode();
        stats.up_reports.fetch_add(1, Ordering::Relaxed);
        let sock = sock.clone();
        // Spawned, and without the settling pause the downstream report takes
        // first: that pause exists because a burst has just filled the sender's
        // own send queue, and this rung filled the queue in the other
        // direction. Spaced copies are kept for the reason they were
        // introduced — the report is a single unacknowledged datagram carrying
        // the denominator for the whole rung.
        tokio::spawn(async move {
            for i in 0..REPORT_COPIES {
                if i > 0 {
                    tokio::time::sleep(REPORT_SPACING).await;
                }
                let _ = sock.send_to(&bytes, peer).await;
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn tcp_baseline_echoes_framed_payloads_byte_for_byte() {
        let stats = Arc::new(BaselineStats::default());
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let s = stats.clone();
        tokio::spawn(async move {
            let _ = serve_tcp(listener, s).await;
        });

        let mut c = tokio::net::TcpStream::connect(addr).await.expect("connect");
        for len in [1usize, 64, 1500, 60_000] {
            let payload: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            c.write_all(&(len as u32).to_be_bytes()).await.expect("len");
            c.write_all(&payload).await.expect("body");

            let mut lb = [0u8; 4];
            c.read_exact(&mut lb).await.expect("read len");
            assert_eq!(u32::from_be_bytes(lb) as usize, len);
            let mut back = vec![0u8; len];
            c.read_exact(&mut back).await.expect("read body");
            assert_eq!(back, payload, "echo must be byte-exact at {len} bytes");
        }
        assert_eq!(stats.tcp_frames.load(Ordering::Relaxed), 4);
    }

    /// An oversized declared length must close the connection, not allocate.
    #[tokio::test]
    async fn tcp_baseline_rejects_an_oversized_frame() {
        let stats = Arc::new(BaselineStats::default());
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let _ = serve_tcp(listener, stats).await;
        });

        let mut c = tokio::net::TcpStream::connect(addr).await.expect("connect");
        c.write_all(&u32::MAX.to_be_bytes()).await.expect("len");
        let mut b = [0u8; 1];
        // The server closes rather than waiting for 4 GiB.
        let r = tokio::time::timeout(std::time::Duration::from_secs(3), c.read(&mut b)).await;
        assert!(
            matches!(r, Ok(Ok(0)) | Ok(Err(_))),
            "connection should be closed, got {r:?}"
        );
    }

    #[tokio::test]
    async fn udp_baseline_echoes_datagrams() {
        let stats = Arc::new(BaselineStats::default());
        let probe = UdpSocket::bind("127.0.0.1:0").await.expect("bind probe");
        let server = UdpSocket::bind("127.0.0.1:0").await.expect("bind server");
        let addr = server.local_addr().expect("addr");
        let s = stats.clone();
        tokio::spawn(async move {
            let _ = serve_udp(server, s).await;
        });

        for len in [1usize, 512, 1200] {
            let payload: Vec<u8> = (0..len).map(|i| (i % 253) as u8).collect();
            probe.send_to(&payload, addr).await.expect("send");
            let mut buf = vec![0u8; 65_536];
            let (n, _) =
                tokio::time::timeout(std::time::Duration::from_secs(3), probe.recv_from(&mut buf))
                    .await
                    .expect("no timeout")
                    .expect("recv");
            assert_eq!(&buf[..n], &payload[..], "datagram echo must be exact");
        }
        assert_eq!(stats.udp_datagrams.load(Ordering::Relaxed), 3);
    }

    // ── Downstream source ───────────────────────────────────────────────────

    /// Bind a source on loopback and return a client socket already pointed at
    /// it. `connect` on the client side means only the daemon's datagrams reach
    /// it, which is what a real probe does too.
    async fn source_pair(stats: Arc<BaselineStats>) -> UdpSocket {
        let server = UdpSocket::bind("127.0.0.1:0").await.expect("bind server");
        let addr = server.local_addr().expect("addr");
        tokio::spawn(async move {
            let _ = serve_udp_source(server, stats).await;
        });
        let client = UdpSocket::bind("127.0.0.1:0").await.expect("bind client");
        client.connect(addr).await.expect("connect");
        client
    }

    async fn recv_within(sock: &UdpSocket, buf: &mut [u8], budget: Duration) -> Option<usize> {
        tokio::time::timeout(budget, sock.recv(buf))
            .await
            .ok()?
            .ok()
    }

    /// The datagram size every test request asks for. Named because the rung
    /// ceiling below is arithmetic over it, and a silent change to one without
    /// the other would leave the bound wrong rather than failing.
    const PAYLOAD_LEN: u32 = 1200;

    /// The offer the full-round test places, kbit/s.
    const OFFER_KBPS: u32 = 8_000;

    fn request(
        nonce: u64,
        cookie: [u8; crate::downlink::COOKIE_LEN],
        kbps: u32,
        ms: u32,
    ) -> Request {
        Request {
            run_nonce: nonce,
            cookie,
            rung: 0,
            offered_kbps: kbps,
            duration_ms: ms,
            payload_len: PAYLOAD_LEN as u16,
        }
    }

    /// The whole round: challenge, cookie, paced burst, sender's own account.
    #[tokio::test]
    async fn the_downstream_source_challenges_then_sends_and_reports() {
        let stats = Arc::new(BaselineStats::default());
        let client = source_pair(stats.clone()).await;
        let mut buf = vec![0u8; 2048];

        // No cookie: a challenge, and not a single byte of data.
        client
            .send(&request(0xA1, [0; crate::downlink::COOKIE_LEN], OFFER_KBPS, 500).encode())
            .await
            .expect("send");
        let n = recv_within(&client, &mut buf, Duration::from_secs(3)).await;
        let n = n.expect("a request without a cookie must draw a challenge");
        let ch = Challenge::decode(&buf[..n]).expect("challenge");
        assert_eq!(ch.run_nonce, 0xA1, "the challenge echoes the run nonce");
        assert!(
            n < crate::downlink::REQUEST_LEN,
            "the unauthenticated reply must be smaller than what provoked it, \
             or this control is an amplifier"
        );

        // With the cookie: the burst runs.
        client
            .send(&request(0xA1, ch.cookie, OFFER_KBPS, 500).encode())
            .await
            .expect("send");

        let mut data = 0u64;
        let mut bytes = 0u64;
        let mut seqs = Vec::new();
        let mut report = None;
        while let Some(n) = recv_within(&client, &mut buf, Duration::from_secs(2)).await {
            if let Some(h) = DataHeader::decode(&buf[..n]) {
                assert_eq!(h.run_nonce, 0xA1);
                assert_eq!(h.rung, 0);
                data += 1;
                bytes += n as u64;
                seqs.push(h.seq);
            } else if let Some(r) = Report::decode(&buf[..n]) {
                report.get_or_insert(r);
                break;
            }
        }

        assert!(data > 0, "the burst produced no datagrams");
        assert!(
            seqs.windows(2).all(|w| w[0] < w[1]),
            "sequence numbers must be issued once each, in order: {seqs:?}"
        );

        let r = report.expect("the sender must state its own account");
        assert_eq!(r.run_nonce, 0xA1);
        assert_eq!(r.offered_kbps, OFFER_KBPS);
        assert!(
            data <= r.datagrams && bytes <= r.bytes,
            "more arrived ({data} datagrams, {bytes} B) than the sender says it sent \
             ({} datagrams, {} B)",
            r.datagrams,
            r.bytes
        );
        assert!(
            data * 100 >= r.datagrams * 95,
            "loopback lost {}% of the rung, which is a harness problem rather than a path one",
            100 - data * 100 / r.datagrams.max(1)
        );
        assert!(r.elapsed_ns > 0);

        // A rung may not exceed the rate it asked for. This is the direction
        // that is the sender's own doing: the credit bucket earns one tick's
        // worth per tick and nothing else can release a datagram, so a loop
        // that ignored the pacer — or one that repaid a scheduling gap at line
        // speed — shows up here and nowhere else. It is also the direction that
        // matters operationally: a control that overshoots its offer queues the
        // path at a rate nobody asked for and the loss it provokes gets read as
        // the link's.
        //
        // The ceiling is computed from the offer and the sender's own elapsed
        // interval rather than from `Pacer`, so a fault in the pacer's
        // arithmetic cannot move both sides of the comparison together. One
        // datagram of slack covers the tick that `interval` fires immediately
        // on entry, whose credit (1000 B at this offer) is earned before any
        // measurable time has passed.
        let ceiling =
            OFFER_KBPS as u128 * 125 * r.elapsed_ns as u128 / 1_000_000_000 + PAYLOAD_LEN as u128;
        let bps = crate::pacing::bits_per_sec(r.bytes, r.elapsed_ns);
        assert!(
            r.bytes as u128 <= ceiling,
            "offered {OFFER_KBPS} kbit/s for {} ms and sent {} B — above the {ceiling} B \
             that offer allows ({:.2} Mbit/s achieved)",
            r.elapsed_ns / 1_000_000,
            r.bytes,
            bps / 1e6
        );

        // The other direction — that the sender got *close* to its offer — is
        // deliberately not asserted here. At 8 Mbit/s in 1200 B datagrams the
        // pacer needs 0.83 datagrams per tick, so what reaches the wire is the
        // offer scaled by 1 ms over the host's real tick period, and on a
        // loaded or coarse-timer machine that lands anywhere from 40% to 90% of
        // the ask. Such an assertion measures the host, which is the mistake
        // this whole control group exists to avoid making about a link. That
        // the pacer aims at the ask rather than at its own timer is pinned
        // without a clock or a socket in `pacing::tests`.

        assert_eq!(stats.down_rungs.load(Ordering::Relaxed), 1);
        assert_eq!(stats.down_challenges.load(Ordering::Relaxed), 1);
        assert_eq!(stats.down_datagrams.load(Ordering::Relaxed), data);
    }

    /// A cookie minted for one address must not start a burst aimed at another,
    /// or the control becomes an amplifier pointed wherever an attacker likes.
    #[tokio::test]
    async fn a_cookie_from_another_peer_only_earns_another_challenge() {
        let stats = Arc::new(BaselineStats::default());
        let server = UdpSocket::bind("127.0.0.1:0").await.expect("bind server");
        let addr = server.local_addr().expect("addr");
        let s = stats.clone();
        tokio::spawn(async move {
            let _ = serve_udp_source(server, s).await;
        });

        let a = UdpSocket::bind("127.0.0.1:0").await.expect("bind a");
        a.connect(addr).await.expect("connect a");
        let b = UdpSocket::bind("127.0.0.1:0").await.expect("bind b");
        b.connect(addr).await.expect("connect b");

        let mut buf = vec![0u8; 2048];
        a.send(&request(1, [0; crate::downlink::COOKIE_LEN], 4_000, 300).encode())
            .await
            .expect("send");
        let n = recv_within(&a, &mut buf, Duration::from_secs(3))
            .await
            .expect("challenge");
        let stolen = Challenge::decode(&buf[..n]).expect("challenge").cookie;

        b.send(&request(2, stolen, 4_000, 300).encode())
            .await
            .expect("send");
        let n = recv_within(&b, &mut buf, Duration::from_secs(3))
            .await
            .expect("reply");
        assert!(
            Challenge::decode(&buf[..n]).is_some(),
            "a stolen cookie must earn a challenge, not a burst"
        );
        assert!(
            DataHeader::decode(&buf[..n]).is_none(),
            "no data may be sent to an address that has not proved it can receive"
        );
        assert_eq!(stats.down_rungs.load(Ordering::Relaxed), 0);
    }

    /// A public UDP port that answers anything it is sent is a reflector. This
    /// one must stay silent for traffic it does not recognise.
    #[tokio::test]
    async fn unrecognised_traffic_draws_no_reply_at_all() {
        let stats = Arc::new(BaselineStats::default());
        let client = source_pair(stats.clone()).await;
        let mut buf = vec![0u8; 2048];

        for junk in [
            b"GET / HTTP/1.1\r\n\r\n".to_vec(),
            vec![0u8; 40],
            vec![0xFFu8; 512],
            b"PHRAWDQ".to_vec(),
        ] {
            client.send(&junk).await.expect("send");
        }
        assert!(
            recv_within(&client, &mut buf, Duration::from_millis(600))
                .await
                .is_none(),
            "the source replied to traffic it did not recognise"
        );
        assert_eq!(stats.down_challenges.load(Ordering::Relaxed), 0);
        assert_eq!(stats.down_rungs.load(Ordering::Relaxed), 0);
    }

    /// A request is not permission to send for as long as it likes. The clamp
    /// is what guarantees a client that disappears cannot leave the daemon
    /// sending, since nothing else in this path ever hears from it again.
    #[test]
    fn a_rung_plan_is_clamped_to_what_the_daemon_will_do() {
        let p = RungPlan::from_request(&Request {
            run_nonce: 1,
            cookie: [1; crate::downlink::COOKIE_LEN],
            rung: 9,
            offered_kbps: u32::MAX,
            duration_ms: u32::MAX,
            payload_len: u16::MAX,
        });
        assert_eq!(p.offered_kbps, MAX_RUNG_KBPS);
        assert_eq!(p.duration, MAX_RUNG);
        assert_eq!(p.payload_len, MAX_PAYLOAD);

        // And upward, so a zero-valued field cannot produce a rung that sends
        // forever or a datagram too small to carry its own header.
        let p = RungPlan::from_request(&Request {
            run_nonce: 1,
            cookie: [1; crate::downlink::COOKIE_LEN],
            rung: 0,
            offered_kbps: 0,
            duration_ms: 0,
            payload_len: 0,
        });
        assert_eq!(p.offered_kbps, 1);
        assert_eq!(p.duration, Duration::from_millis(1));
        assert_eq!(p.payload_len, MIN_PAYLOAD);
    }

    /// A refusal has to reach the client as a sender that achieved nothing,
    /// because silence is indistinguishable from a path that swallowed the
    /// whole rung — and those two call for opposite conclusions.
    #[tokio::test]
    async fn a_refused_rung_reports_zero_rather_than_going_quiet() {
        let stats = Arc::new(BaselineStats::default());
        let server = UdpSocket::bind("127.0.0.1:0").await.expect("bind server");
        let addr = server.local_addr().expect("addr");
        let s = stats.clone();
        tokio::spawn(async move {
            let _ = serve_udp_source(server, s).await;
        });

        let client = UdpSocket::bind("127.0.0.1:0").await.expect("bind client");
        client.connect(addr).await.expect("connect");
        let mut buf = vec![0u8; 2048];

        client
            .send(&request(7, [0; crate::downlink::COOKIE_LEN], 1_000, 2_000).encode())
            .await
            .expect("send");
        let n = recv_within(&client, &mut buf, Duration::from_secs(3))
            .await
            .expect("challenge");
        let cookie = Challenge::decode(&buf[..n]).expect("challenge").cookie;

        // First rung takes the peer's only slot; the second is refused.
        client
            .send(&request(7, cookie, 1_000, 2_000).encode())
            .await
            .expect("send");
        tokio::time::sleep(Duration::from_millis(200)).await;
        let mut second = request(7, cookie, 1_000, 2_000);
        second.rung = 1;
        client.send(&second.encode()).await.expect("send");

        let mut refusal = None;
        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline {
            let Some(n) = recv_within(&client, &mut buf, Duration::from_secs(1)).await else {
                break;
            };
            if let Some(r) = Report::decode(&buf[..n]) {
                if r.rung == 1 {
                    refusal = Some(r);
                    break;
                }
            }
        }

        let r = refusal.expect("a declined rung must still be reported");
        assert_eq!(r.datagrams, 0);
        assert_eq!(r.bytes, 0);
        assert_eq!(r.elapsed_ns, 0);
        assert_eq!(
            r.offered_kbps, 1_000,
            "the refusal names the rate it declined, so the rung reads as unreached"
        );
        assert!(stats.down_refused.load(Ordering::Relaxed) >= 1);
    }

    // ── Uplink sink ─────────────────────────────────────────────────────────

    /// The rung length every uplink test asks for. Short: what these pin is the
    /// bookkeeping, and the sink's window closes a fixed grace period after the
    /// rung's own end whatever that end was.
    const UP_RUNG_MS: u32 = 200;

    async fn sink_pair(stats: Arc<BaselineStats>) -> UdpSocket {
        let server = UdpSocket::bind("127.0.0.1:0").await.expect("bind server");
        let addr = server.local_addr().expect("addr");
        tokio::spawn(async move {
            let _ = serve_udp_sink(server, stats).await;
        });
        let client = UdpSocket::bind("127.0.0.1:0").await.expect("bind client");
        client.connect(addr).await.expect("connect");
        client
    }

    fn up_request(
        nonce: u64,
        cookie: [u8; crate::downlink::COOKIE_LEN],
        rung: u16,
        ms: u32,
    ) -> uplink::Request {
        uplink::Request {
            run_nonce: nonce,
            cookie,
            rung,
            offered_kbps: 1_000,
            duration_ms: ms,
            payload_len: PAYLOAD_LEN as u16,
        }
    }

    fn up_datagram(nonce: u64, rung: u16, seq: u64) -> Vec<u8> {
        let mut b = vec![0u8; PAYLOAD_LEN as usize];
        uplink::DataHeader {
            run_nonce: nonce,
            rung,
            seq,
            send_unix_ns: unix_nanos(),
        }
        .write_into(&mut b);
        b
    }

    /// Get past the challenge and arm a rung, returning the cookie.
    async fn arm_uplink(client: &UdpSocket, nonce: u64, rung: u16, ms: u32) -> [u8; 12] {
        let mut buf = vec![0u8; 2048];
        client
            .send(&up_request(nonce, [0; crate::downlink::COOKIE_LEN], rung, ms).encode())
            .await
            .expect("send");
        let n = recv_within(client, &mut buf, Duration::from_secs(3))
            .await
            .expect("a request without a cookie must draw a challenge");
        let cookie = uplink::Challenge::decode(&buf[..n])
            .expect("challenge")
            .cookie;

        client
            .send(&up_request(nonce, cookie, rung, ms).encode())
            .await
            .expect("send");
        let n = recv_within(client, &mut buf, Duration::from_secs(3))
            .await
            .expect("a cookie-bearing request must be answered");
        let r = uplink::Ready::decode(&buf[..n]).expect("ready");
        assert!(r.accepted, "the sink declined a rung it had a slot for");
        assert_eq!(r.rung, rung);
        cookie
    }

    /// Wait out the sink's own window and take its account of the rung.
    async fn wait_for_account(client: &UdpSocket, nonce: u64, rung: u16) -> uplink::Report {
        let mut buf = vec![0u8; 2048];
        let deadline = Instant::now() + UPLINK_RUNG_GRACE + Duration::from_secs(3);
        while Instant::now() < deadline {
            let Some(n) = recv_within(client, &mut buf, Duration::from_millis(500)).await else {
                continue;
            };
            if let Some(r) = uplink::Report::decode(&buf[..n]) {
                if r.run_nonce == nonce && r.rung == rung {
                    return r;
                }
            }
        }
        panic!("the sink never sent an account of the rung");
    }

    /// The whole round: challenge, cookie, arm, count, and the receiver's own
    /// account of what arrived — which on an upload is the only honest one,
    /// because a sender counts what it handed to a socket.
    #[tokio::test]
    async fn the_uplink_sink_challenges_arms_counts_and_reports() {
        let stats = Arc::new(BaselineStats::default());
        let client = sink_pair(stats.clone()).await;
        arm_uplink(&client, 0xB1, 0, UP_RUNG_MS).await;

        for seq in 0..10u64 {
            client
                .send(&up_datagram(0xB1, 0, seq))
                .await
                .expect("send data");
        }

        let r = wait_for_account(&client, 0xB1, 0).await;
        assert_eq!(r.received_datagrams, 10);
        assert_eq!(r.received_bytes, 10 * PAYLOAD_LEN as u64);
        assert_eq!(r.first_datagram_bytes, PAYLOAD_LEN as u64);
        assert_eq!(r.reordered_datagrams, 0);
        assert_eq!(r.duplicate_datagrams, 0);
        assert!(
            r.observed_window_ns > 0,
            "ten arrivals span an interval, and a zero one makes the rate infinite"
        );
        assert_eq!(
            r.reorder.horizon, 4096,
            "the ledger must say how far back it can see"
        );
        assert_eq!(r.reorder.gaps_lost, 0);
        assert_eq!(r.reorder.gaps_filled, 0);

        assert_eq!(stats.up_rungs.load(Ordering::Relaxed), 1);
        assert_eq!(stats.up_challenges.load(Ordering::Relaxed), 1);
        assert_eq!(stats.up_datagrams.load(Ordering::Relaxed), 10);
        assert_eq!(stats.up_reports.load(Ordering::Relaxed), 1);

        // And the rung is gone: a client that keeps sending after its window
        // closed is not counted into anything, which is what makes the rung
        // self-terminating rather than dependent on hearing from the client.
        client
            .send(&up_datagram(0xB1, 0, 99))
            .await
            .expect("send data");
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(
            stats.up_datagrams.load(Ordering::Relaxed),
            10,
            "a datagram after the window closed was still counted"
        );
    }

    /// The account is of what arrived, not of what was promised — and a gap the
    /// window never slid past is neither loss nor reordering. Whether those
    /// missing datagrams are the path's loss is a question only the sender's
    /// count can answer, which is why it is answered on the other side.
    #[tokio::test]
    async fn the_sinks_account_reports_arrivals_and_leaves_loss_to_the_sender() {
        let stats = Arc::new(BaselineStats::default());
        let client = sink_pair(stats.clone()).await;
        arm_uplink(&client, 0xB2, 1, UP_RUNG_MS).await;

        // Ten sent, two never posted: exactly the shape a lossy path produces.
        for seq in 0..10u64 {
            if seq == 3 || seq == 7 {
                continue;
            }
            client
                .send(&up_datagram(0xB2, 1, seq))
                .await
                .expect("send data");
        }

        let r = wait_for_account(&client, 0xB2, 1).await;
        assert_eq!(r.received_datagrams, 8);
        assert_eq!(
            r.reorder.gaps_open_at_end, 2,
            "a gap the horizon never reached is not a measured loss"
        );
        assert_eq!(r.reorder.gaps_lost, 0);
        assert_eq!(r.reordered_datagrams, 0);

        // The fraction is the client's to compute, and it needs both halves:
        // the receiver's arrivals and the sender's own count.
        let loss = crate::downlink::loss_fraction(r.received_datagrams, Some(10))
            .expect("both counts known");
        assert!((loss - 0.2).abs() < 1e-9, "got {loss}");
        assert_eq!(
            crate::downlink::loss_fraction(r.received_datagrams, None),
            None,
            "without the sender's count there is no denominator"
        );
    }

    /// Reordering and duplication are separate quantities from loss, measured
    /// with the same code that measures them downstream — the whole reason the
    /// bookkeeping lives in one module.
    #[tokio::test]
    async fn the_sink_counts_reordering_and_duplication_apart_from_loss() {
        let stats = Arc::new(BaselineStats::default());
        let client = sink_pair(stats.clone()).await;
        arm_uplink(&client, 0xB3, 2, UP_RUNG_MS).await;

        // 0, 1, 3, 2, 4 — one datagram overtaken — then 2 again.
        for seq in [0u64, 1, 3, 2, 4, 2] {
            client
                .send(&up_datagram(0xB3, 2, seq))
                .await
                .expect("send data");
        }

        let r = wait_for_account(&client, 0xB3, 2).await;
        assert_eq!(
            r.received_datagrams, 5,
            "a duplicate is not a second arrival"
        );
        assert_eq!(r.duplicate_datagrams, 1);
        assert_eq!(r.reordered_datagrams, 1);
        assert_eq!(r.reorder.gaps_filled, 1, "the overtaken one filled its gap");
        assert_eq!(r.reorder.gaps_lost, 0);
        assert_eq!(r.reorder.distance.count, 1);
        assert_eq!(
            r.reorder.distance.max, 1.0,
            "seq 2 arrived one sequence number behind the highest seen"
        );
        assert_eq!(
            r.received_bytes,
            5 * PAYLOAD_LEN as u64,
            "a duplicate's bytes are not credited"
        );
    }

    /// A cookie minted for one address must not arm a rung for another. Nothing
    /// here amplifies, but an armed rung costs the daemon a receiver ledger, and
    /// a ledger any spoofed source can allocate is a table an attacker fills.
    #[tokio::test]
    async fn a_cookie_from_another_peer_only_earns_another_challenge_at_the_sink() {
        let stats = Arc::new(BaselineStats::default());
        let server = UdpSocket::bind("127.0.0.1:0").await.expect("bind server");
        let addr = server.local_addr().expect("addr");
        let s = stats.clone();
        tokio::spawn(async move {
            let _ = serve_udp_sink(server, s).await;
        });

        let a = UdpSocket::bind("127.0.0.1:0").await.expect("bind a");
        a.connect(addr).await.expect("connect a");
        let b = UdpSocket::bind("127.0.0.1:0").await.expect("bind b");
        b.connect(addr).await.expect("connect b");

        let mut buf = vec![0u8; 2048];
        a.send(&up_request(1, [0; crate::downlink::COOKIE_LEN], 0, UP_RUNG_MS).encode())
            .await
            .expect("send");
        let n = recv_within(&a, &mut buf, Duration::from_secs(3))
            .await
            .expect("challenge");
        let stolen = uplink::Challenge::decode(&buf[..n])
            .expect("challenge")
            .cookie;

        b.send(&up_request(2, stolen, 0, UP_RUNG_MS).encode())
            .await
            .expect("send");
        let n = recv_within(&b, &mut buf, Duration::from_secs(3))
            .await
            .expect("reply");
        assert!(
            uplink::Challenge::decode(&buf[..n]).is_some(),
            "a stolen cookie must earn a challenge, not an armed rung"
        );
        assert!(uplink::Ready::decode(&buf[..n]).is_none());
        assert_eq!(stats.up_rungs.load(Ordering::Relaxed), 0);
    }

    /// A public UDP port that answers anything it is sent is a reflector. Data
    /// for a peer with no armed rung is in that category too: there is no
    /// ledger to put it in, and answering would be a reply to whatever address
    /// the sender cared to forge.
    #[tokio::test]
    async fn the_sink_answers_neither_junk_nor_data_it_never_armed() {
        let stats = Arc::new(BaselineStats::default());
        let client = sink_pair(stats.clone()).await;
        let mut buf = vec![0u8; 2048];

        for junk in [
            b"GET / HTTP/1.1\r\n\r\n".to_vec(),
            vec![0u8; 40],
            vec![0xFFu8; 512],
            b"PHRAWUQ".to_vec(),
            // A downstream request: the right shape on the wrong control.
            request(9, [1; crate::downlink::COOKIE_LEN], 1_000, 500)
                .encode()
                .to_vec(),
            up_datagram(0xB4, 0, 0),
        ] {
            client.send(&junk).await.expect("send");
        }
        assert!(
            recv_within(&client, &mut buf, Duration::from_millis(600))
                .await
                .is_none(),
            "the sink replied to traffic it did not recognise"
        );
        assert_eq!(stats.up_challenges.load(Ordering::Relaxed), 0);
        assert_eq!(stats.up_rungs.load(Ordering::Relaxed), 0);
        assert_eq!(
            stats.up_datagrams.load(Ordering::Relaxed),
            0,
            "data with no armed rung must not be counted into one"
        );
    }

    /// A repeated request means the client never saw the answer and has
    /// therefore sent nothing yet. Refusing it as a duplicate would strand a
    /// rung the client is still waiting to start, so it re-arms instead.
    #[tokio::test]
    async fn a_repeated_request_re_arms_the_rung_rather_than_being_refused() {
        let stats = Arc::new(BaselineStats::default());
        let client = sink_pair(stats.clone()).await;
        let cookie = arm_uplink(&client, 0xB5, 0, UP_RUNG_MS).await;

        let mut buf = vec![0u8; 2048];
        client
            .send(&up_request(0xB5, cookie, 0, UP_RUNG_MS).encode())
            .await
            .expect("send");
        let n = recv_within(&client, &mut buf, Duration::from_secs(3))
            .await
            .expect("the repeat must be answered");
        let r = uplink::Ready::decode(&buf[..n]).expect("ready");
        assert!(r.accepted, "a repeated request must not be refused");

        for seq in 0..4u64 {
            client
                .send(&up_datagram(0xB5, 0, seq))
                .await
                .expect("send data");
        }
        let acct = wait_for_account(&client, 0xB5, 0).await;
        assert_eq!(acct.received_datagrams, 4);
        assert_eq!(stats.up_refused.load(Ordering::Relaxed), 0);
    }

    /// Past the concurrency bound the sink says no rather than going quiet.
    /// Silence there is indistinguishable from a path that swallowed the whole
    /// rung, and those two call for opposite conclusions.
    #[tokio::test]
    async fn a_rung_past_the_concurrency_bound_is_declined_rather_than_ignored() {
        let stats = Arc::new(BaselineStats::default());
        let server = UdpSocket::bind("127.0.0.1:0").await.expect("bind server");
        let addr = server.local_addr().expect("addr");
        let s = stats.clone();
        tokio::spawn(async move {
            let _ = serve_udp_sink(server, s).await;
        });

        // Long enough that the earlier rungs are still armed when the last one
        // asks. Every client is a distinct peer, which is what the bound counts.
        let held_ms = 10_000;
        let mut clients = Vec::new();
        for i in 0..MAX_CONCURRENT_UPLINK_RUNGS {
            let c = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
            c.connect(addr).await.expect("connect");
            arm_uplink(&c, 0xC0 + i as u64, 0, held_ms).await;
            clients.push(c);
        }

        let extra = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        extra.connect(addr).await.expect("connect");
        let mut buf = vec![0u8; 2048];
        extra
            .send(&up_request(0xCF, [0; crate::downlink::COOKIE_LEN], 0, held_ms).encode())
            .await
            .expect("send");
        let n = recv_within(&extra, &mut buf, Duration::from_secs(3))
            .await
            .expect("challenge");
        let cookie = uplink::Challenge::decode(&buf[..n])
            .expect("challenge")
            .cookie;
        extra
            .send(&up_request(0xCF, cookie, 0, held_ms).encode())
            .await
            .expect("send");
        let n = recv_within(&extra, &mut buf, Duration::from_secs(3))
            .await
            .expect("a declined rung must still be answered");
        let r = uplink::Ready::decode(&buf[..n]).expect("ready");
        assert!(!r.accepted, "the bound must be enforced");
        assert_eq!(r.run_nonce, 0xCF);
        assert!(stats.up_refused.load(Ordering::Relaxed) >= 1);
        assert_eq!(
            stats.up_rungs.load(Ordering::Relaxed),
            MAX_CONCURRENT_UPLINK_RUNGS as u64
        );
    }

    /// A request is not permission to keep a ledger for as long as the asker
    /// likes: the clamp is what guarantees a client that disappears cannot
    /// leave the sink holding one, since nothing in this path hears from it
    /// again.
    #[test]
    fn an_uplink_rung_is_clamped_to_what_the_sink_will_hold() {
        let armed = UpRung::armed(&uplink::Request {
            run_nonce: 1,
            cookie: [1; crate::downlink::COOKIE_LEN],
            rung: 9,
            offered_kbps: u32::MAX,
            duration_ms: u32::MAX,
            payload_len: u16::MAX,
        });
        let held = armed.deadline.saturating_duration_since(armed.base);
        assert!(
            held <= MAX_RUNG + UPLINK_RUNG_GRACE,
            "a rung asking for forever was held {held:?}"
        );

        // And a zero-length request still opens a window rather than one that
        // has already closed.
        let tiny = UpRung::armed(&uplink::Request {
            run_nonce: 1,
            cookie: [1; crate::downlink::COOKIE_LEN],
            rung: 0,
            offered_kbps: 0,
            duration_ms: 0,
            payload_len: 0,
        });
        assert!(tiny.deadline > tiny.base);
        assert_eq!(tiny.account().received_datagrams, 0);
        assert_eq!(
            tiny.account().observed_window_ns,
            0,
            "no arrivals span no interval, and a made-up one would divide into a rate"
        );
    }
}
