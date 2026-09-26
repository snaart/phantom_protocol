//! Length-prefixed `SessionTransport` over `tokio::net::TcpStream`.
//!
//! `SessionTransport` is message-oriented (returns one frame per `recv_bytes`),
//! while TCP is a stream. This adapter inserts a 4-byte big-endian length prefix
//! before each frame so the trait contract is preserved.
//!
//! Phase 2.1: the receive path keeps a single persistent `BytesMut`
//! accumulator across `recv_bytes` calls. Each frame is `split_to`-ed off
//! into an owned `Bytes` which the caller takes — zero-copy from the
//! accumulator to the returned frame, no per-packet `Vec::new` alloc.
//!
//! # What this leg is for
//!
//! **Compatibility and reach, not speed.** Use it where PhantomUDP cannot go —
//! a network that blocks or throttles UDP, a corporate proxy, a platform whose
//! sandbox offers only stream sockets — and use PhantomUDP everywhere else. A
//! deployment that has the choice and picks this leg is paying for something it
//! does not need.
//!
//! The reason is structural rather than a defect awaiting a fix. Phantom's own
//! reliability layer — the ARQ, SACK loss detection and BBR-style congestion
//! control of `transport::stream` and `transport::bandwidth_estimator` — runs
//! unchanged on every leg, including this one. Over a datagram socket it is the
//! only such layer. Over TCP it is the *second*: the kernel already retransmits,
//! already sequences, already has a congestion window, and our loop sits on top
//! of it with no visibility into it. The two controllers then interact through
//! the only channel they share, which is the queue between them. What our side
//! measures as the path's round trip includes however long the kernel's send
//! buffer held the bytes, so a growing queue reads to us as a longer path and
//! sizes our window accordingly — and a retransmission the kernel has already
//! performed is invisible to us, so a loss the path recovered from is one we may
//! recover from a second time.
//!
//! The measurement, from the WAN harness in `testbed/`: **min-RTT on this leg has
//! been observed as high as 4112 ms**, which is not a property of any route the
//! harness runs over — it is queueing delay under our own sender. Application
//! throughput across campaign runs spans **0.75–4.33 Mbit/s**; the figure with a
//! same-run control beside it is run `20260822-062705`, where the server received
//! **4.83 Mbit/s** from this leg while raw UDP echo on the same path in the same
//! run measured 13.26 Mbit/s round-trip. The harness records the equivalent
//! PhantomUDP numbers the same way, each beside its own control and the run's
//! caveats; do not quote any of them without the control from the same run.
//!
//! None of this affects correctness. The leg is fully conformant, carries the
//! identical inner wire (`docs/protocol/PROTOCOL.md`), and has the same security
//! properties as any other — the AEAD, the pinning and the replay window are
//! above the transport and do not know which one they are on. What it does not
//! have is PhantomUDP's latency under load, and it cannot migrate: `migrate()`
//! returns `CoreError::Unsupported` here, because a TCP connection cannot change
//! its 5-tuple.
//!
//! # A peer that stops reading
//!
//! A write on this leg can wait on the peer, which a datagram send never does.
//! Once the peer stops reading its socket — a frozen process, or a client that
//! has decided to keep a server's session open — the kernel's buffers between the
//! two ends fill and the next write waits for room that only the peer can make.
//! The session's data pump is the writer, so without a bound the peer would be
//! holding the pump: no liveness sweep, no acknowledgements, and no local close,
//! because `disconnect()` and dropping the handle are both requests the pump reads
//! between writes. On a server that is a client choosing how long it occupies a
//! slot.
//!
//! So a write that makes **no progress** for
//! [`DEFAULT_WRITE_STALL_TIMEOUT`](TcpSessionTransport::DEFAULT_WRITE_STALL_TIMEOUT)
//! — thirty seconds, adjustable with
//! [`with_write_stall_timeout`](TcpSessionTransport::with_write_stall_timeout) —
//! fails with [`CoreError::Timeout`]. The deadline restarts with every byte the
//! socket accepts, so a link is never cut off for being slow, only for having
//! stopped.
//!
//! Most callers never build this transport themselves: `PhantomListener` builds one
//! per accepted connection, and the `connect_pinned*` functions build theirs. Those
//! take the deadline from
//! [`PhantomConfig::write_stall_timeout`](crate::config::PhantomConfig::write_stall_timeout)
//! when they are given a config, and use the thirty seconds otherwise. That field's
//! documentation says how coarsely the socket reports progress, which is what decides
//! how long a deadline a slow path needs. After a stall every further `send_bytes` fails the same way without
//! touching the socket, because the stalled frame may be cut part-way through on
//! the wire and anything written after it would be read as garbage; and the
//! connection is set to end with a reset rather than an orderly close, so the
//! bytes the peer declined are discarded instead of being offered to it by the
//! kernel for minutes more.
//!
//! A session treats that `Timeout` as final. Its pump stops using the transport,
//! the session ends in [`ConnectionState::Dead`], and `last_error()` and `recv()`
//! report [`CoreError::Timeout`]. `disconnect()` and dropping the handle take
//! effect within the same deadline — the pump reads them as soon as the stalled
//! write gives up — and a close requested while the socket is stuck is not
//! announced, since there is no longer any way to get it to the peer. What the
//! deadline does not do is bound a peer that keeps taking bytes slowly: that is a
//! slow link, and how long to put up with one is the application's call.
//!
//! [`ConnectionState::Dead`]: crate::api::session::ConnectionState::Dead

use crate::api::session::{FramePhase, SessionTransport};
use crate::errors::CoreError;
use crate::transport::write_stall::{
    reset_on_close, write_all_making_progress, WriteFailure, DEFAULT_WRITE_STALL_TIMEOUT,
};
use bytes::{Bytes, BytesMut};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::sync::Mutex;

/// Receive frame cap during the unauthenticated handshake (WIRE-001). A
/// `ClientHello` — even carrying a 16 KiB 0-RTT blob — is well under this, so an
/// oversized DECLARED frame is rejected right after the 4-byte length prefix,
/// before any body is buffered. This bounds the memory a single unauthenticated
/// peer can make the server allocate.
const HANDSHAKE_FRAME_CAP: usize = 64 * 1024; // 64 KiB

/// Receive/send frame cap once the session is established — matches the
/// application-layer delivery cap. Lowered from the historical 16 MiB.
const STEADY_STATE_FRAME_CAP: usize = 4 * 1024 * 1024; // 4 MiB

/// Initial (and shrink-target) capacity for the persistent recv accumulator.
/// Sized to a generous MTU so the typical workload never reallocates.
const RECV_BUF_INITIAL_CAPACITY: usize = 64 * 1024;

/// Incremental-read chunk: the accumulator grows by at most this per read, so a
/// peer that DECLARES a large frame but then stalls cannot make us pre-commit
/// the full declared length (WIRE-001 amplification fix).
const RECV_CHUNK: usize = 64 * 1024;

/// After a frame larger than `RECV_BUF_INITIAL_CAPACITY * SHRINK_SLACK_MULT`, the
/// accumulator is reset to baseline (LEGS-003) so one big frame does not pin a
/// large buffer for the connection's life. Steady-state ~MTU frames stay well
/// under the threshold and never pay a realloc.
const SHRINK_SLACK_MULT: usize = 4;

pub struct TcpSessionTransport {
    write_half: Mutex<tokio::net::tcp::OwnedWriteHalf>,
    /// Read half + the per-direction accumulator. Held together under
    /// one mutex so the buffer lifetime tracks the reader's exactly
    /// (Phase 2.1).
    read_half: Mutex<(tokio::net::tcp::OwnedReadHalf, BytesMut)>,
    /// Current receive frame-size cap (WIRE-001). Starts at the tight handshake
    /// cap and rises to the steady-state cap via [`set_frame_phase`].
    frame_cap: AtomicUsize,
    /// How long one write may wait without the socket accepting a byte.
    write_stall_timeout: Duration,
    /// Set by the first write that stalls out, and never cleared: that write may
    /// have left a frame cut part-way through on the wire, so nothing may follow it.
    write_stalled: AtomicBool,
}

impl TcpSessionTransport {
    /// How long a write may go without the socket accepting a byte before the
    /// transport gives up on its peer, unless
    /// [`with_write_stall_timeout`](Self::with_write_stall_timeout) says otherwise.
    /// Thirty seconds — the session's default liveness idle timeout. See the
    /// [module documentation](self) for what happens when it fires.
    pub const DEFAULT_WRITE_STALL_TIMEOUT: Duration = DEFAULT_WRITE_STALL_TIMEOUT;

    pub fn new(stream: TcpStream) -> Self {
        let _ = stream.set_nodelay(true);
        let (r, w) = stream.into_split();
        Self {
            write_half: Mutex::new(w),
            read_half: Mutex::new((r, BytesMut::with_capacity(RECV_BUF_INITIAL_CAPACITY))),
            frame_cap: AtomicUsize::new(HANDSHAKE_FRAME_CAP),
            write_stall_timeout: Self::DEFAULT_WRITE_STALL_TIMEOUT,
            write_stalled: AtomicBool::new(false),
        }
    }

    /// Replace the write-stall deadline: how long a single write may wait without
    /// the socket accepting a byte before `send_bytes` fails with
    /// [`CoreError::Timeout`] and the transport gives up on its peer.
    ///
    /// The clock restarts with every byte accepted, so this is a bound on how long
    /// the peer may stop reading, not on how slowly it may read. Choose it no
    /// shorter than the longest pause a legitimate peer takes: a figure below the
    /// time the kernel needs to drain a third of a full send buffer on the slowest
    /// expected path cuts off links that are still moving. A zero deadline gives up
    /// on the first write the socket cannot take at once.
    ///
    /// For a transport handed to `PhantomSession::builder`, this is the only way to
    /// set it: the builder's `.config(...)` does not reach a transport it did not
    /// build. The entry points that build their own take it from
    /// [`PhantomConfig::write_stall_timeout`](crate::config::PhantomConfig::write_stall_timeout).
    pub fn with_write_stall_timeout(mut self, timeout: Duration) -> Self {
        self.write_stall_timeout = timeout;
        self
    }

    /// Current receive accumulator capacity — test-only accessor for the
    /// LEGS-003 shrink behavior.
    #[cfg(test)]
    pub(crate) async fn accum_capacity(&self) -> usize {
        self.read_half.lock().await.1.capacity()
    }
}

impl SessionTransport for TcpSessionTransport {
    async fn send_bytes(&self, data: &[u8]) -> Result<(), CoreError> {
        if data.len() > STEADY_STATE_FRAME_CAP {
            return Err(CoreError::NetworkError(format!(
                "frame too large: {} > {}",
                data.len(),
                STEADY_STATE_FRAME_CAP
            )));
        }
        if self.write_stalled.load(Ordering::Acquire) {
            return Err(CoreError::Timeout);
        }
        let mut w = self.write_half.lock().await;
        // Checked again under the lock: the write this one queued behind may be the
        // one that stalled, and what it left on the wire is not a frame boundary.
        if self.write_stalled.load(Ordering::Acquire) {
            return Err(CoreError::Timeout);
        }
        let len = (data.len() as u32).to_be_bytes();
        match write_all_making_progress(&mut *w, &[&len, data], self.write_stall_timeout).await {
            Ok(()) => Ok(()),
            Err(WriteFailure::Io(e)) => Err(CoreError::NetworkError(e.to_string())),
            Err(WriteFailure::Stalled) => {
                self.write_stalled.store(true, Ordering::Release);
                reset_on_close((*w).as_ref());
                log::warn!(
                    "TcpSessionTransport: the peer accepted no bytes for {:?}; giving up on it",
                    self.write_stall_timeout
                );
                Err(CoreError::Timeout)
            }
        }
    }

    async fn recv_bytes(&self) -> Result<Bytes, CoreError> {
        let cap = self.frame_cap.load(Ordering::Relaxed);
        let mut guard = self.read_half.lock().await;
        let (r, buf) = &mut *guard;

        // Read the 4-byte big-endian length prefix.
        let mut len_buf = [0u8; 4];
        r.read_exact(&mut len_buf)
            .await
            .map_err(|e| CoreError::NetworkError(e.to_string()))?;
        let len = u32::from_be_bytes(len_buf) as usize;
        // WIRE-001: reject an oversized DECLARED length up front (phase-gated
        // cap), BEFORE buffering any body bytes.
        if len > cap {
            return Err(CoreError::NetworkError(format!(
                "oversized frame from peer: {} > {}",
                len, cap
            )));
        }

        // Incremental read (WIRE-001): grow the accumulator by at most
        // `RECV_CHUNK` per read, so a peer that declares a large frame but then
        // stalls makes us commit at most one chunk — not the full declared
        // length (no 4-byte → big-alloc amplification). `read_exact` reads
        // exactly the requested bytes, so no subsequent frame leaks into `buf`.
        buf.clear();
        let mut filled = 0usize;
        while filled < len {
            let chunk = (len - filled).min(RECV_CHUNK);
            buf.resize(filled + chunk, 0);
            r.read_exact(&mut buf[filled..filled + chunk])
                .await
                .map_err(|e| CoreError::NetworkError(e.to_string()))?;
            filled += chunk;
        }

        // `split_to(len)` hands the caller an owned `BytesMut` view over the
        // frame; `freeze` makes it an immutable refcounted `Bytes`.
        let frame = buf.split_to(len).freeze();

        // LEGS-003: a single large frame must not pin a large accumulator for
        // the connection's life. After one, reset to baseline (the old large
        // allocation is reclaimed once the frozen frame is also dropped).
        if len > RECV_BUF_INITIAL_CAPACITY * SHRINK_SLACK_MULT {
            *buf = BytesMut::with_capacity(RECV_BUF_INITIAL_CAPACITY);
        }
        Ok(frame)
    }

    fn set_frame_phase(&self, phase: FramePhase) {
        let cap = match phase {
            FramePhase::Handshake => HANDSHAKE_FRAME_CAP,
            FramePhase::Established => STEADY_STATE_FRAME_CAP,
        };
        self.frame_cap.store(cap, Ordering::Relaxed);
    }
}

/// Loopback fixtures shared by this module's tests and the session-level tests that
/// need a real socket underneath a running pump.
#[cfg(test)]
pub(crate) mod test_support {
    use tokio::net::{TcpListener, TcpSocket, TcpStream};

    /// Both buffers between the two ends — this end's send buffer and the far end's
    /// receive buffer — are asked for this size, so a few tens of kibibytes fill the
    /// connection instead of the several mebibytes a default loopback socket absorbs.
    /// The kernel rounds the request (Linux doubles it); what matters is only that it
    /// is far below what the tests write.
    pub(crate) const SMALL_SOCKET_BUFFER: u32 = 8 * 1024;

    /// A loopback connection whose far end never reads. Returns this end and the far
    /// end; the caller keeps the far end alive for as long as the test needs the
    /// connection open, and never reads from it.
    pub(crate) async fn connection_whose_far_end_never_reads() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let far = TcpSocket::new_v4().expect("far socket");
        far.set_recv_buffer_size(SMALL_SOCKET_BUFFER)
            .expect("shrink the far end's receive buffer");
        let (far, accepted) = tokio::join!(far.connect(addr), listener.accept());
        let far = far.expect("connect");
        let (near, _) = accepted.expect("accept");
        socket2::SockRef::from(&near)
            .set_send_buffer_size(SMALL_SOCKET_BUFFER as usize)
            .expect("shrink this end's send buffer");
        (near, far)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::net::{TcpListener, TcpStream};

    async fn tcp_pair() -> (TcpSessionTransport, TcpSessionTransport) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let (client, accepted) = tokio::join!(TcpStream::connect(addr), listener.accept());
        let client = client.expect("connect");
        let (server, _) = accepted.expect("accept");
        (
            TcpSessionTransport::new(client),
            TcpSessionTransport::new(server),
        )
    }

    /// The framing bytes themselves, in both directions, against a raw socket
    /// rather than against the other half of this type.
    ///
    /// `docs/protocol/INTEROP.md` Rung 1b tells a second implementation that
    /// every stream leg but WebSocket prefixes each message with a 4-byte
    /// big-endian length — it is the one interop-load-bearing byte format with
    /// no committed vector behind it, because it sits outside the frozen wire.
    /// A round-trip through two `TcpSessionTransport`s would pass just as
    /// happily on little-endian or on a 2-byte prefix, so this drives one side
    /// with a plain `TcpStream` and reads the bytes.
    #[tokio::test]
    async fn message_framing_is_a_four_byte_big_endian_length_prefix() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let (raw, accepted) = tokio::join!(TcpStream::connect(addr), listener.accept());
        let mut raw = raw.expect("connect");
        let (framed, _) = accepted.expect("accept");
        let framed = TcpSessionTransport::new(framed);

        // Send side: 0x0102_0304 chosen so a byte-order slip cannot alias.
        let payload: Vec<u8> = (0..258u32).map(|i| i as u8).collect();
        assert_eq!(payload.len(), 0x0102, "the length must span two bytes");
        framed.send_bytes(&payload).await.expect("send");

        let mut on_the_wire = vec![0u8; 4 + payload.len()];
        raw.read_exact(&mut on_the_wire).await.expect("read frame");
        assert_eq!(
            &on_the_wire[..4],
            &[0x00, 0x00, 0x01, 0x02],
            "the length prefix must be 4 bytes, big-endian"
        );
        assert_eq!(&on_the_wire[4..], &payload[..], "payload follows verbatim");

        // Receive side: a peer that framed by hand must be understood.
        let reply = b"the responder speaks the same framing".to_vec();
        let mut hand_framed = (reply.len() as u32).to_be_bytes().to_vec();
        hand_framed.extend_from_slice(&reply);
        raw.write_all(&hand_framed).await.expect("write frame");
        raw.flush().await.expect("flush");
        let got = framed.recv_bytes().await.expect("recv");
        assert_eq!(&got[..], &reply[..]);
    }

    /// **WIRE-001.** During the unauthenticated handshake phase the recv cap is
    /// tight (64 KiB): an oversized DECLARED frame is rejected right after the
    /// 4-byte prefix, before any body is buffered — no 4-byte → big-alloc
    /// amplification.
    #[tokio::test]
    async fn handshake_phase_rejects_oversized_frame() {
        let (client, server) = tcp_pair().await; // server defaults to handshake phase
        let big = vec![0u8; 100 * 1024]; // 100 KiB > 64 KiB handshake cap
        client
            .send_bytes(&big)
            .await
            .expect("send is within the 4 MiB send cap");
        let err = server
            .recv_bytes()
            .await
            .expect_err("oversized handshake-phase frame must be rejected");
        assert!(matches!(err, CoreError::NetworkError(_)));
    }

    /// After establishment the cap rises to 4 MiB, a large frame round-trips, and
    /// (LEGS-003) the accumulator is reset to baseline afterward.
    #[tokio::test]
    async fn established_phase_accepts_large_frame_and_resets_accumulator() {
        let (client, server) = tcp_pair().await;
        server.set_frame_phase(FramePhase::Established);
        let payload = vec![7u8; 1024 * 1024]; // 1 MiB, within the 4 MiB cap

        // Drive send and recv CONCURRENTLY. A 1 MiB `write_all` does not complete
        // until the peer starts draining (the kernel socket buffer is far
        // smaller than 1 MiB once it is contended — e.g. when the parallel test
        // suite saturates loopback), so doing send-then-recv sequentially on one
        // task deadlocks on TCP flow control. `join!` lets the reader drain while
        // the writer fills.
        let (send_res, recv_res) = tokio::join!(client.send_bytes(&payload), server.recv_bytes());
        send_res.expect("send 1 MiB");
        let got = recv_res.expect("recv 1 MiB");
        assert_eq!(got.len(), payload.len());
        assert_eq!(&got[..8], &payload[..8]);
        let cap = server.accum_capacity().await;
        assert!(
            cap <= RECV_BUF_INITIAL_CAPACITY * SHRINK_SLACK_MULT,
            "accumulator must reset to baseline after a large frame (LEGS-003); capacity = {cap}"
        );
        // A small follow-up frame still works.
        client.send_bytes(b"small").await.expect("send small");
        let got = server.recv_bytes().await.expect("recv small");
        assert_eq!(&got[..], b"small");
    }

    /// The send path enforces the 4 MiB steady-state cap (down from 16 MiB).
    #[tokio::test]
    async fn send_rejects_over_steady_state_cap() {
        let (client, _server) = tcp_pair().await;
        let too_big = vec![0u8; STEADY_STATE_FRAME_CAP + 1];
        assert!(client.send_bytes(&too_big).await.is_err());
    }

    /// Short enough to keep these tests quick, long enough that a loopback write
    /// which is merely scheduled late is never mistaken for a stalled one.
    const TEST_STALL: Duration = Duration::from_millis(250);

    /// A frame far larger than the shrunken buffers of
    /// `connection_whose_far_end_never_reads`, so writing it has to wait on the peer.
    const LARGE_FRAME: usize = 1024 * 1024;

    /// Read `far` until the peer's writes stop arriving; returns how many bytes came.
    async fn drain_what_arrived(far: &mut TcpStream) -> usize {
        use tokio::io::AsyncReadExt;
        let mut total = 0usize;
        let mut buf = vec![0u8; 64 * 1024];
        while let Ok(Ok(n)) =
            tokio::time::timeout(Duration::from_millis(300), far.read(&mut buf)).await
        {
            if n == 0 {
                break;
            }
            total += n;
        }
        total
    }

    /// The transport starts with the documented default, and the builder replaces it.
    #[tokio::test]
    async fn the_write_stall_deadline_defaults_to_thirty_seconds_and_can_be_replaced() {
        let (client, _server) = tcp_pair().await;
        assert_eq!(client.write_stall_timeout, Duration::from_secs(30));
        assert_eq!(
            TcpSessionTransport::DEFAULT_WRITE_STALL_TIMEOUT,
            Duration::from_secs(30)
        );
        let client = client.with_write_stall_timeout(TEST_STALL);
        assert_eq!(client.write_stall_timeout, TEST_STALL);
    }

    /// A write the peer never takes fails with `Timeout` instead of waiting forever.
    ///
    /// Before the deadline existed this call never returned: the far end's receive
    /// buffer and this end's send buffer fill, and the rest of the frame waits for
    /// room that only a read on the far end can make.
    #[tokio::test]
    async fn a_write_the_peer_never_takes_fails_instead_of_waiting_forever() {
        let (near, _far) = test_support::connection_whose_far_end_never_reads().await;
        let transport = TcpSessionTransport::new(near).with_write_stall_timeout(TEST_STALL);
        let frame = vec![0x3C_u8; LARGE_FRAME];
        let outcome =
            tokio::time::timeout(Duration::from_secs(10), transport.send_bytes(&frame)).await;
        assert!(
            matches!(outcome, Ok(Err(CoreError::Timeout))),
            "a write the peer never takes must fail with Timeout; got {outcome:?}"
        );
    }

    /// Once a write has stalled out, nothing more is written — even after the peer
    /// makes room again.
    ///
    /// The stalled frame stopped part-way through, so the far end's parser is inside
    /// it: the next bytes on the wire would be read as the rest of that frame. The
    /// far end here drains everything that reached it, which leaves the socket with
    /// room to spare, and the next send must still be refused rather than written.
    #[tokio::test]
    async fn nothing_is_written_after_a_stall_even_once_the_peer_makes_room() {
        let (near, mut far) = test_support::connection_whose_far_end_never_reads().await;
        let transport = TcpSessionTransport::new(near).with_write_stall_timeout(TEST_STALL);
        let stalled = transport.send_bytes(&vec![0x5A_u8; LARGE_FRAME]).await;
        assert!(matches!(stalled, Err(CoreError::Timeout)), "{stalled:?}");

        let arrived = drain_what_arrived(&mut far).await;
        assert!(
            arrived > 0 && arrived < 4 + LARGE_FRAME,
            "the stalled frame should have stopped part-way; {arrived} bytes arrived"
        );

        let next = transport.send_bytes(b"after the stall").await;
        assert!(
            matches!(next, Err(CoreError::Timeout)),
            "a send after a stall must be refused, not written behind a cut-off frame; got \
             {next:?}"
        );
        assert_eq!(
            drain_what_arrived(&mut far).await,
            0,
            "a refused send must not have reached the wire"
        );
    }

    /// A write queued behind the one that stalls is refused, not appended to the frame
    /// the stall cut off — even when the peer makes room the moment it gets the socket.
    ///
    /// A session has two writers on one transport: the send loop and the receive task,
    /// which sends acknowledgements. The second can pass the first latch check while
    /// the first is still waiting, queue on the write-half lock, and take it the moment
    /// the stalled write lets go. The far end here starts draining as soon as the first
    /// write has failed, so the queued frame would find all the room it needs and go
    /// out behind the cut-off one, where the far end reads it as the rest of that frame.
    /// Only the check made again under the lock stops it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_write_queued_behind_a_stalled_one_is_refused_rather_than_appended() {
        const QUEUED: &[u8] = b"queued behind the stalled frame";
        const FILL: u8 = 0x5A;
        // Longer than `TEST_STALL`: the steps below have to land inside the first
        // write's deadline, and a loaded test runner can wake a short sleep late.
        const STALL: Duration = Duration::from_secs(1);
        let (near, mut far) = test_support::connection_whose_far_end_never_reads().await;
        let transport =
            std::sync::Arc::new(TcpSessionTransport::new(near).with_write_stall_timeout(STALL));

        let stalling = {
            let transport = transport.clone();
            tokio::spawn(async move { transport.send_bytes(&vec![FILL; LARGE_FRAME]).await })
        };
        // Long enough for the large write to take the lock and fill the buffers, well
        // short of its deadline, so the second write passes the first latch check and
        // queues on the lock behind a write that has not given up yet.
        tokio::time::sleep(STALL / 10).await;
        assert!(
            !stalling.is_finished(),
            "the large write finished before the second one queued behind it"
        );
        let queued = {
            let transport = transport.clone();
            tokio::spawn(async move { transport.send_bytes(QUEUED).await })
        };
        tokio::time::sleep(STALL / 20).await;
        assert!(
            !queued.is_finished(),
            "the second write did not queue behind the stalled one"
        );

        let stalled = stalling.await.expect("stalling writer");
        assert!(matches!(stalled, Err(CoreError::Timeout)), "{stalled:?}");
        // The peer makes room at once, so a queued write that went ahead would complete.
        let arrived = tokio::spawn(async move {
            use tokio::io::AsyncReadExt;
            let mut got = Vec::new();
            let mut buf = vec![0u8; 64 * 1024];
            while let Ok(Ok(n)) =
                tokio::time::timeout(Duration::from_millis(500), far.read(&mut buf)).await
            {
                if n == 0 {
                    break;
                }
                got.extend_from_slice(&buf[..n]);
            }
            got
        });
        let queued = queued.await.expect("queued writer");
        assert!(
            matches!(queued, Err(CoreError::Timeout)),
            "a write queued behind a stalled one must be refused; got {queued:?}"
        );

        let arrived = arrived.await.expect("reader");
        assert!(
            arrived.len() > 4 && arrived.len() < 4 + LARGE_FRAME,
            "the stalled frame should have stopped part-way; {} bytes arrived",
            arrived.len()
        );
        assert_eq!(
            &arrived[..4],
            &(LARGE_FRAME as u32).to_be_bytes(),
            "the stalled frame's prefix"
        );
        assert!(
            arrived[4..].iter().all(|&b| b == FILL),
            "bytes other than the stalled frame's reached the wire after it was cut off"
        );
    }

    /// A peer that reads slowly but steadily is never cut off, however long the
    /// write takes in total: the deadline is on the gaps, not on the sum.
    ///
    /// The far end reads in small pieces with a pause between them far shorter than
    /// the deadline, so the whole frame takes several deadlines to get through.
    #[tokio::test]
    async fn a_peer_that_keeps_reading_slowly_is_not_cut_off() {
        use tokio::io::AsyncReadExt;
        const PAUSE: Duration = Duration::from_millis(10);

        let (near, mut far) = test_support::connection_whose_far_end_never_reads().await;
        let transport = TcpSessionTransport::new(near).with_write_stall_timeout(TEST_STALL);
        let frame = vec![0x77_u8; LARGE_FRAME];
        let reader = tokio::spawn(async move {
            let mut got = 0usize;
            let mut buf = vec![0u8; 16 * 1024];
            while got < 4 + LARGE_FRAME {
                match far.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => got += n,
                }
                tokio::time::sleep(PAUSE).await;
            }
            got
        });

        let started = std::time::Instant::now();
        let sent = transport.send_bytes(&frame).await;
        let took = started.elapsed();
        assert!(
            sent.is_ok(),
            "a peer that never paused for {TEST_STALL:?} was cut off: {sent:?}"
        );
        assert!(
            took > TEST_STALL,
            "the write finished in {took:?}, inside one deadline, so it says nothing about \
             whether the deadline bounds the total"
        );
        assert_eq!(reader.await.expect("reader"), 4 + LARGE_FRAME);
    }

    /// A connection given up on ends in a reset, not an orderly close.
    ///
    /// What the peer declined to take is still in this end's send buffer, and an
    /// orderly close would keep it there — and the connection's kernel state with it —
    /// while the kernel went on offering it to a closed window. The far end sees the
    /// difference: an orderly close reads as a clean end-of-stream once the data is
    /// drained, a reset as an error.
    #[tokio::test]
    async fn a_connection_given_up_on_is_reset_rather_than_closed() {
        use tokio::io::AsyncReadExt;
        let (near, mut far) = test_support::connection_whose_far_end_never_reads().await;
        let transport = TcpSessionTransport::new(near).with_write_stall_timeout(TEST_STALL);
        let stalled = transport.send_bytes(&vec![0x1F_u8; LARGE_FRAME]).await;
        assert!(matches!(stalled, Err(CoreError::Timeout)), "{stalled:?}");
        drop(transport);

        let mut buf = vec![0u8; 64 * 1024];
        let ending = loop {
            match tokio::time::timeout(Duration::from_secs(5), far.read(&mut buf)).await {
                Ok(Ok(0)) => break Ok(()),
                Ok(Ok(_)) => continue,
                Ok(Err(e)) => break Err(e.kind()),
                Err(_) => panic!("the far end saw neither an end nor an error within 5 s"),
            }
        };
        assert!(
            matches!(ending, Err(std::io::ErrorKind::ConnectionReset)),
            "the far end should see the connection reset; it saw {ending:?}"
        );
    }
}
