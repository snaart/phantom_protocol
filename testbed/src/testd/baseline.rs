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
//! Three controls, and they answer different questions. The echoes are round
//! trips, so neither direction is isolated in them; the **downstream source**
//! ([`serve_udp_source`]) sends one way, server → client, which is the only one
//! of the three that puts a number under every leg's `download`.

use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

use crate::downlink::{
    Challenge, CookieMinter, DataHeader, Report, Request, MAX_PAYLOAD, MIN_PAYLOAD,
};
use crate::pacing::{Pacer, MISSED_TICK, TICK};
use crate::proto::PayloadGen;
use crate::report::unix_nanos;

/// Matches the established-phase frame cap of `TcpSessionTransport`.
const MAX_FRAME: u32 = 4 * 1024 * 1024;

/// Request larger socket buffers; the kernel may clamp, and that is fine — the
/// point is not to be the bottleneck, not to hit an exact number.
fn size_socket_buffers(sock: &tokio::net::TcpStream, want: usize) {
    use std::os::fd::{AsRawFd, BorrowedFd};
    // SAFETY: the fd is owned by `sock` and outlives this borrow; socket2 only
    // sets options on it and never takes ownership.
    let borrowed = unsafe { BorrowedFd::borrow_raw(sock.as_raw_fd()) };
    let s2 = socket2::SockRef::from(&borrowed);
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
        // that was really the kernel's.
        size_socket_buffers(&sock, 1024 * 1024);
        stats.tcp_conns.fetch_add(1, Ordering::Relaxed);
        let stats = stats.clone();

        tokio::spawn(async move {
            let mut len_buf = [0u8; 4];
            loop {
                if sock.read_exact(&mut len_buf).await.is_err() {
                    break;
                }
                let len = u32::from_be_bytes(len_buf);
                if len > MAX_FRAME {
                    tracing::warn!(%peer, len, "raw tcp frame over cap; closing");
                    break;
                }
                let mut body = vec![0u8; len as usize];
                if sock.read_exact(&mut body).await.is_err() {
                    break;
                }
                if sock.write_all(&len_buf).await.is_err() || sock.write_all(&body).await.is_err() {
                    break;
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
            payload_len: 1200,
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
            .send(&request(0xA1, [0; crate::downlink::COOKIE_LEN], 8_000, 500).encode())
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
            .send(&request(0xA1, ch.cookie, 8_000, 500).encode())
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
        assert_eq!(r.offered_kbps, 8_000);
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

        // 8 Mbit/s for half a second is ~500 KB. Loopback should reach the
        // offer comfortably; the point of the assertion is that the pacer aims
        // at the ask rather than at its own timer.
        let bps = crate::pacing::bits_per_sec(r.bytes, r.elapsed_ns);
        assert!(
            crate::pacing::reached_offer(8_000_000.0, bps),
            "offered 8 Mbit/s, sender achieved {:.2} Mbit/s",
            bps / 1e6
        );

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
}
