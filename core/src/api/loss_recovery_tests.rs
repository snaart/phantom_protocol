//! Session-survives-loss tests (Phase 1.5) — test-only.
//!
//! The core test: a REAL end-to-end exchange where the client
//! transport is wrapped in a **seeded, deterministic** [`LossyTransport`],
//! proving that the existing RTO-based loss recovery actually recovers
//! application data under reproducible packet loss — not just over a reliable
//! pipe.
//!
//! ## Why this is needed
//!
//! Before this test, every loss-recovery code path (RTO retransmit, reliable
//! stream buffering) had only ever run over loss-free in-memory / loopback
//! transports. Loss recovery that has never seen a dropped packet is unproven.
//! [`LossyTransport`]'s seeded stochastic mode gives us reproducible loss: the
//! same seed always drops the same frames, so a green run is green for everyone
//! and a CI flake is impossible by construction.
//!
//! ## Harness shape
//!
//! In-memory `ChannelTransport` pair (mirrors the harness in
//! `crate::api::session` tests): both client and server use a
//! [`crate::transport::handshake::HandshakeServer`] to complete the handshake,
//! then the server side is built into a full [`PhantomSession`] via
//! [`PhantomSession::from_accepted_server_session`] so it runs the real data
//! pump and can echo messages. The client wraps its half of the channel in a
//! seeded [`LossyTransport`].
//!
//! The exchange is **synchronous request/response** (client sends message `i`,
//! server echoes it, client receives it, repeat) so message ordering is
//! unambiguous and a single dropped data frame must be recovered by the RTO
//! retransmit before the next message proceeds. Each message is distinct
//! (`loss-msg-{i:05}`) so the assertion catches loss, truncation, duplication,
//! and reordering — not just a length match.
//!
//! ## Why loss is armed *after* the handshake
//!
//! The client handshake sends a single `ClientHello` and then blocks on the
//! reply with **no handshake-level retransmit** — a dropped hello would wedge
//! the handshake forever. So we build the [`LossyTransport`] with its stochastic
//! config **disarmed**, let the handshake complete cleanly, then
//! `arm_stochastic(true)` and run the lossy data phase. This isolates the
//! property under test: *data-phase* loss recovery.
//!
//! ## The measured ceiling
//!
//! The current loss recovery is **RTO-only** — no SACK, no fast-retransmit.
//! `RtoEstimator` (`transport/stream.rs`): `INITIAL_RTO = 1s`, `MIN_RTO = 200ms`,
//! exponential backoff (doubling) per consecutive timeout on the *same* segment.
//! So the first loss of a segment costs ~1s to recover, and a run of B
//! back-to-back losses of the same segment costs ~1 + 2 + 4 + … s — the cost
//! grows geometrically, not linearly, with loss.
//!
//! Measured on this machine over a seeded loss sweep (40 synchronous
//! round-trips, 4–5 seeds per rate, 2% reorder; data phase only — the handshake
//! is loss-free). Every result below RECOVERED data byte-exact; the figure is
//! the worst-seed wall-clock for the whole 40-message exchange:
//!
//! | loss | recovers? | worst-seed time |
//! |------|-----------|-----------------|
//! |  5%  | yes       | ~0.8 s          |
//! | 10%  | yes       | ~2.1 s          |
//! | 15%  | yes       | ~4.3 s          |
//! | 20%  | yes       | ~9.5 s          |
//! | 30%  | yes       | ~6.2 s          |
//! | 40%  | yes       | ~19 s           |
//! | 50%  | flaky     | one seed blew the 120 s budget |
//! | 60%  | flaky     | one seed blew the 120 s budget |
//!
//! What the sweep shows:
//!   - **Correctness ceiling ≈ 40% loss.** Up to ~40%, RTO-only recovery is
//!     *lossless* — every message arrives byte-exact and in order. There is no
//!     data-loss failure mode in the tested range; the only failure is *timeout*.
//!   - **Latency degrades geometrically and with high variance.** Sub-second at
//!     5%, but a single unlucky seed at 20% already hit ~9.5 s and at 40% ~19 s
//!     — the compounding 1s→2s→4s→… backoff whenever a retransmit is itself
//!     dropped. **~50% loss is where it stops reliably finishing in a sane CI
//!     budget** (a long run of consecutive same-segment drops pushes past 120 s).
//!   - **Robustly-green CI config: ≤ 5% loss.** That's the PASSING test below
//!     (3% + 1% reorder, sub-2s, zero flakes over 20 runs).
//!
//! The geometric latency cliff is exactly what the **SACK + fast-retransmit pass
//! (L1)** lifts: with SACK, a dropped segment is recovered in ~1 RTT on the next
//! ACK instead of waiting out a (backed-off) RTO.
//!
//! ## L1 RESULT (A.5 in-order delivery + L1-B SACK fast-retransmit — SHIPPED)
//!
//! The cliff above is the RTO-only **synchronous** baseline (1 packet in flight,
//! so loss is recovered only by RTO). With reliable in-order delivery (A.5) the
//! exchange can **pipeline** (many in flight), so L1-B's SACK fast-retransmit
//! recovers a mid-stream loss in ~1 RTT. Measured on the seeded
//! [`run_pipelined_echo`] rig (40 messages, worst of 3 seeds, light reorder):
//!
//! | loss | RTO-only synchronous | A.5 + L1-B pipelined |
//! |------|----------------------|----------------------|
//! |  5%  | ~0.8 s               | ~0.20 s              |
//! | 10%  | ~2.1 s               | ~0.40 s              |
//! | 15%  | ~4.3 s               | ~0.41 s              |
//! | 20%  | ~9.5 s               | ~0.41 s              |
//! | 30%  | ~6.2 s               | ~0.62 s              |
//!
//! The curve is now **flat** (sub-second to 30% loss) rather than a geometric
//! cliff — every result still recovers byte-exact and IN ORDER. The robustly-green
//! ceiling rises from ≤5% to ≥20% (gated by `pipelined_recovers_at_*` below); the
//! residual ~0.2–0.6 s is the MIN_RTO=200ms floor on *tail* losses (the last few
//! pipelined packets have no successor to SACK-reveal the gap, so they fall back
//! to the RTO). A PTO/tail-loss probe (RFC 9002 §6.2) could shave that floor — it
//! was measured as NOT required to meet the L1 ceiling/cliff goal and is left as a
//! future optimisation. `loss_recovery_high_loss_recovers_but_is_slow` keeps the
//! RTO-only synchronous baseline as an `#[ignore]`d reference.
//!
//! The module is declared `#[cfg(test)]` in `api/mod.rs`, so it carries no
//! inner `#![cfg(test)]` of its own.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use tokio::sync::{mpsc, Mutex};
use tokio::time::timeout;

use crate::api::session::{ConnectionState, PhantomSession, SessionTransport};
use crate::errors::CoreError;
use crate::test_harness::fault_transport::{FaultControl, LossyTransport};
use crate::transport::handshake::{ClientHello, HandshakeResponse, HandshakeServer, ServerReply};

// ── Local in-memory transport (mirrors the one in session::tests) ────────────

struct ChannelTransport {
    tx: mpsc::Sender<Vec<u8>>,
    rx: Mutex<mpsc::Receiver<Vec<u8>>>,
}

impl ChannelTransport {
    fn pair() -> (Self, Self) {
        let (a_tx, b_rx) = mpsc::channel(64);
        let (b_tx, a_rx) = mpsc::channel(64);
        (
            Self {
                tx: a_tx,
                rx: Mutex::new(a_rx),
            },
            Self {
                tx: b_tx,
                rx: Mutex::new(b_rx),
            },
        )
    }
}

impl SessionTransport for ChannelTransport {
    async fn send_bytes(&self, data: &[u8]) -> Result<(), CoreError> {
        self.tx
            .send(data.to_vec())
            .await
            .map_err(|_| CoreError::NetworkError("channel closed".into()))
    }

    async fn recv_bytes(&self) -> Result<Bytes, CoreError> {
        let mut rx = self.rx.lock().await;
        let v = rx
            .recv()
            .await
            .ok_or_else(|| CoreError::NetworkError("channel closed".into()))?;
        Ok(Bytes::from(v))
    }
}

/// A [`ChannelTransport`] whose *send* side behaves like a link rather than a
/// function call: a fixed one-way propagation delay, and a minimum spacing
/// between consecutive frames.
///
/// Both halves are load-bearing for anything that reasons about acknowledgement
/// *timing*, and an in-memory channel has neither.
///
/// The delay must be a delay **line**, not a `sleep` inside `send_bytes`. An
/// inline sleep blocks the pump that called it, which stalls acknowledgement
/// processing as well as emission: the round trip a sender then measures swings
/// by up to a whole delay depending on what else that pump had queued, and
/// RACK's time threshold — `srtt·9/8`, an eighth of a round trip of margin —
/// disappears into that noise. Here `send_bytes` stamps a release deadline and
/// returns; one forwarding task releases frames at their deadlines.
///
/// The spacing is what makes a receiver's acknowledgements arrive *spread out*.
/// Without it, everything a peer emits in one scheduling slice is released in
/// one burst, the far pump drains its whole inbound queue before it next looks
/// at its send path, and no acknowledgement can ever land in the interval
/// between a retransmission and its answer — the interval where SACK-driven loss
/// detection actually lives. A real bottleneck serialises frames; this is that,
/// with the link rate expressed as time per frame.
struct DelayLine {
    line: mpsc::Sender<(tokio::time::Instant, Vec<u8>)>,
    delay: Duration,
    spacing: Duration,
    /// Release deadline of the previously accepted frame, so the next is placed
    /// at least `spacing` after it. Deadlines stay monotonic, which is what lets
    /// the single forwarding task preserve order with a plain `sleep_until`.
    last_release: std::sync::Mutex<Option<tokio::time::Instant>>,
    rx: Mutex<mpsc::Receiver<Vec<u8>>>,
}

impl DelayLine {
    fn new(inner: ChannelTransport, delay: Duration, spacing: Duration) -> Self {
        let (line_tx, mut line_rx) = mpsc::channel::<(tokio::time::Instant, Vec<u8>)>(256);
        let out = inner.tx;
        tokio::spawn(async move {
            while let Some((release_at, frame)) = line_rx.recv().await {
                tokio::time::sleep_until(release_at).await;
                if out.send(frame).await.is_err() {
                    break;
                }
            }
        });
        Self {
            line: line_tx,
            delay,
            spacing,
            last_release: std::sync::Mutex::new(None),
            rx: inner.rx,
        }
    }

    fn schedule(&self) -> tokio::time::Instant {
        let mut last = self
            .last_release
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let earliest = tokio::time::Instant::now() + self.delay;
        let release_at = match *last {
            Some(prev) => earliest.max(prev + self.spacing),
            None => earliest,
        };
        *last = Some(release_at);
        release_at
    }
}

impl SessionTransport for DelayLine {
    async fn send_bytes(&self, data: &[u8]) -> Result<(), CoreError> {
        let release_at = self.schedule();
        self.line
            .send((release_at, data.to_vec()))
            .await
            .map_err(|_| CoreError::NetworkError("delay line closed".into()))
    }

    async fn recv_bytes(&self) -> Result<Bytes, CoreError> {
        let mut rx = self.rx.lock().await;
        let v = rx
            .recv()
            .await
            .ok_or_else(|| CoreError::NetworkError("channel closed".into()))?;
        Ok(Bytes::from(v))
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Drive one full session-survives-loss exchange and assert byte-exact, in-order
/// delivery of every message each way.
///
/// `seed` / `loss_prob` / `reorder_prob` parameterise the seeded loss applied to
/// the client transport's *data phase* (the handshake runs loss-free). `n` is the
/// number of synchronous round-trips. `budget` bounds the whole exchange so a
/// failure to recover fails loudly instead of hanging.
async fn run_lossy_round_trips(
    seed: u64,
    loss_prob: f64,
    reorder_prob: f64,
    n: usize,
    budget: Duration,
) {
    let server_hs = HandshakeServer::new().expect("HandshakeServer::new");
    let server_pinned_key = server_hs.verifying_key().clone();

    let (client_channel, server_channel) = ChannelTransport::pair();

    // Wrap the client side in a SEEDED LossyTransport, DISARMED for the
    // handshake (a dropped ClientHello has no retransmit and would wedge it).
    let faults = FaultControl::with_seed(seed, loss_prob, 0.0, reorder_prob, 0);
    faults.arm_stochastic(false);
    let lossy_client = LossyTransport::new(client_channel, faults.clone());

    // Kick off the client session; handshake completes in the background.
    let client =
        PhantomSession::connect_with_transport("test-server:9000", lossy_client, server_pinned_key);

    // Server: drive the handshake manually via HandshakeServer, then hand the
    // negotiated Session to a real PhantomSession (full data pump) so it can
    // echo messages back without manual encrypt/decrypt.
    let server_session_handle = tokio::spawn(async move {
        let client_ip = "127.0.0.1".parse().expect("parse IP");

        // Receive ClientHello (bare borsh).
        let hello_bytes = server_channel
            .recv_bytes()
            .await
            .expect("server recv ClientHello");
        let client_hello =
            borsh::from_slice::<ClientHello>(&hello_bytes).expect("deserialize ClientHello");

        // Process. The DoS gate may answer the first hello with a cookie/PoW
        // `Retry`; the client then re-sends with the cookie and that second
        // hello is admitted. That is at most ONE retry round — the gate never
        // challenges a cookie-bearing hello again — so this is a straight-line
        // match, not a loop.
        let inner_session = match server_hs.process_client_hello(&client_hello, 0, client_ip) {
            HandshakeResponse::Retry(retry) => {
                let retry_bytes = ServerReply::Retry(retry)
                    .to_wire()
                    .expect("serialize retry");
                server_channel
                    .send_bytes(&retry_bytes)
                    .await
                    .expect("server send retry");
                let next_bytes = server_channel
                    .recv_bytes()
                    .await
                    .expect("server recv retry ClientHello");
                let next_hello = borsh::from_slice::<ClientHello>(&next_bytes)
                    .expect("deserialize retry ClientHello");
                match server_hs.process_client_hello(&next_hello, 0, client_ip) {
                    HandshakeResponse::Success(server_hello, session, _) => {
                        let b = ServerReply::Hello(server_hello)
                            .to_wire()
                            .expect("serialize ServerHello");
                        server_channel
                            .send_bytes(&b)
                            .await
                            .expect("server send ServerHello");
                        session
                    }
                    other => panic!("expected Success after retry, got {other:?}"),
                }
            }
            HandshakeResponse::Success(server_hello, session, _) => {
                let b = ServerReply::Hello(server_hello)
                    .to_wire()
                    .expect("serialize ServerHello");
                server_channel
                    .send_bytes(&b)
                    .await
                    .expect("server send ServerHello");
                session
            }
            HandshakeResponse::Reject(r) => panic!("unexpected Reject: {r:?}"),
            HandshakeResponse::Fail(e) => panic!("handshake failed: {e:?}"),
        };

        // Wrap the negotiated inner Session in a full PhantomSession so the real
        // data pump handles encrypt/decrypt and ACKs for us.
        let server_phantom = PhantomSession::from_accepted_server_session(
            "test-client".into(),
            server_channel,
            Arc::new(inner_session),
        );

        // Echo exactly `n` messages back, in order.
        for _ in 0..n {
            let msg = timeout(budget, server_phantom.recv())
                .await
                .expect("server recv timed out — client retransmit never arrived")
                .expect("server recv error");
            server_phantom.send(msg).await.expect("server echo");
        }

        // Keep the session alive briefly so the client can drain the last echo.
        tokio::time::sleep(Duration::from_millis(200)).await;
        server_phantom
    });

    // Wait for the handshake to establish (loss-free), then arm the loss so the
    // DATA phase exercises retransmission.
    let mut established = false;
    for _ in 0..200 {
        if client.connection_state() == ConnectionState::Connected {
            established = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(established, "client session never became established");
    faults.arm_stochastic(true);

    // Synchronous request/response. Each message is distinct; a dropped data
    // frame must be RTO-recovered before this message's echo can return.
    for i in 0..n {
        let payload = format!("loss-msg-{i:05}").into_bytes();
        client.send(payload.clone()).await.expect("client send");
        let reply = timeout(budget, client.recv())
            .await
            .unwrap_or_else(|_| {
                panic!("client recv timed out on message {i} — loss not recovered within budget")
            })
            .expect("client recv error");
        assert_eq!(
            reply,
            Bytes::from(payload),
            "echo {i} must round-trip byte-exact and in order under seeded loss"
        );
    }

    let server = server_session_handle.await.expect("server task panicked");
    server.disconnect().await.expect("server clean disconnect");
    client.disconnect().await.expect("client clean disconnect");
}

/// Pipelined echo over seeded loss + reorder on the client→server path: the
/// client fires `n` distinct messages back-to-back (MANY in flight at once), a
/// full-pump server echoes each, and the client collects `n` echoes. Asserts
/// every echo arrives byte-exact and **in send order** — proving reliable
/// in-order delivery (A.5) plus loss recovery (RTO + L1-B fast-retransmit) under
/// *multi-packet* reorder, which the synchronous `run_lossy_round_trips` (1 in
/// flight) cannot exercise. Returns the data-phase wall-clock (latency-vs-loss
/// measurement). The handshake runs loss-free.
async fn run_pipelined_echo(
    seed: u64,
    loss_prob: f64,
    reorder_prob: f64,
    n: usize,
    budget: Duration,
) -> Duration {
    let server_hs = HandshakeServer::new().expect("HandshakeServer::new");
    let server_pinned_key = server_hs.verifying_key().clone();
    let (client_channel, server_channel) = ChannelTransport::pair();

    let faults = FaultControl::with_seed(seed, loss_prob, 0.0, reorder_prob, 0);
    faults.arm_stochastic(false);
    let lossy_client = LossyTransport::new(client_channel, faults.clone());
    let client =
        PhantomSession::connect_with_transport("test-server:9000", lossy_client, server_pinned_key);

    let server_handle = tokio::spawn(async move {
        let client_ip = "127.0.0.1".parse().expect("parse IP");
        let hello_bytes = server_channel
            .recv_bytes()
            .await
            .expect("server recv ClientHello");
        let client_hello =
            borsh::from_slice::<ClientHello>(&hello_bytes).expect("deserialize ClientHello");
        // The server's DoS gate may answer the first hello with a cookie Retry;
        // handle that one round before Success (mirrors `run_lossy_round_trips`).
        // At most one retry is possible, so this is a match, not a loop.
        let inner = match server_hs.process_client_hello(&client_hello, 0, client_ip) {
            HandshakeResponse::Retry(retry) => {
                let retry_bytes = ServerReply::Retry(retry)
                    .to_wire()
                    .expect("serialize retry");
                server_channel
                    .send_bytes(&retry_bytes)
                    .await
                    .expect("server send retry");
                let next_bytes = server_channel
                    .recv_bytes()
                    .await
                    .expect("server recv retry ClientHello");
                let next_hello = borsh::from_slice::<ClientHello>(&next_bytes)
                    .expect("deserialize retry ClientHello");
                match server_hs.process_client_hello(&next_hello, 0, client_ip) {
                    HandshakeResponse::Success(server_hello, session, _) => {
                        let b = ServerReply::Hello(server_hello)
                            .to_wire()
                            .expect("serialize ServerHello");
                        server_channel
                            .send_bytes(&b)
                            .await
                            .expect("server send ServerHello");
                        session
                    }
                    other => panic!("expected Success after retry, got {other:?}"),
                }
            }
            HandshakeResponse::Success(server_hello, session, _) => {
                let b = ServerReply::Hello(server_hello)
                    .to_wire()
                    .expect("serialize ServerHello");
                server_channel
                    .send_bytes(&b)
                    .await
                    .expect("server send ServerHello");
                session
            }
            HandshakeResponse::Reject(r) => panic!("unexpected Reject: {r:?}"),
            HandshakeResponse::Fail(e) => panic!("handshake failed: {e:?}"),
        };
        let server = PhantomSession::from_accepted_server_session(
            "test-client".into(),
            server_channel,
            Arc::new(inner),
        );
        for _ in 0..n {
            let m = timeout(budget, server.recv())
                .await
                .expect("server recv timed out — client retransmit never arrived")
                .expect("server recv error");
            server.send(m).await.expect("server echo");
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
        server
    });

    let mut established = false;
    for _ in 0..200 {
        if client.connection_state() == ConnectionState::Connected {
            established = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(established, "client session never became established");
    faults.arm_stochastic(true);

    let start = tokio::time::Instant::now();
    // Fire all n messages WITHOUT waiting for echoes → many packets in flight,
    // so reorder actually reorders DATA and B's fast-retransmit can trigger.
    let mut sent: Vec<Vec<u8>> = Vec::with_capacity(n);
    for i in 0..n {
        let payload = format!("pipe-{i:05}").into_bytes();
        client.send(payload.clone()).await.expect("client send");
        sent.push(payload);
    }
    // Collect n echoes — must arrive in send order, byte-exact.
    let mut got: Vec<Vec<u8>> = Vec::with_capacity(n);
    for i in 0..n {
        let echo = timeout(budget, client.recv())
            .await
            .unwrap_or_else(|_| panic!("client recv timed out on echo {i} — loss not recovered"))
            .expect("client recv error");
        got.push(echo);
    }
    let elapsed = start.elapsed();
    assert_eq!(
        got, sent,
        "every echo must round-trip byte-exact and IN ORDER under pipelined loss+reorder"
    );

    let server = server_handle.await.expect("server task panicked");
    server.disconnect().await.expect("server clean disconnect");
    client.disconnect().await.expect("client clean disconnect");
    elapsed
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// **One drop, one loss report.** The end-to-end form of the unit tests in
/// `transport::stream`: a real session, a real data pump, a real SACK-driven
/// loss detector, and exactly one segment removed from the wire.
///
/// The detector's packet threshold compares `largest_acked` against the hole's
/// offset, and `largest_acked` only grows — so once it has fired for an offset
/// it would fire for that offset on every acknowledgement thereafter, and this
/// implementation acknowledges every packet it receives. Each firing is a fresh
/// `Session::on_packet_lost`, and each is also a fresh Pass-0 copy on the wire.
/// `bbr_bytes_lost()` is the counter that makes that visible from outside: on a
/// path that dropped 1300 bytes it must read 1300 bytes, not a multiple of them.
///
/// The drop is armed immediately before the application write, so the frame
/// removed is the payload's first chunk. If that ever stopped being true the
/// assertion would read zero rather than silently passing.
///
/// The acknowledgement path runs through a [`DelayLine`] and not a bare channel,
/// because the defect is a *timing* one and an in-memory channel has no timing:
/// with everything released in one burst the receiving pump drains its whole
/// inbound queue before it looks at its send path, so no acknowledgement ever
/// lands in the window between a retransmission and its answer, which is the
/// only window in which the re-declaration can happen. With a round trip and a
/// per-frame spacing the storm reproduces: one 1300-byte drop was reported as
/// 3900 bytes of loss, on every run.
#[tokio::test]
async fn a_single_dropped_segment_is_reported_to_congestion_control_once() {
    /// `PhantomSession::send` splits at this boundary, so the payload below is
    /// exactly `CHUNKS` reliable segments and the assertion can name a size.
    const CHUNK: usize = 1300;
    /// Enough segments that the packet threshold (three offsets past the hole)
    /// is reached from the acknowledgements of the surviving chunks alone, with
    /// a long tail of further acknowledgements behind it — the tail is what a
    /// re-declaring detector turns into a storm.
    const CHUNKS: usize = 40;
    /// One-way delay on the acknowledgement path, and so the round trip the
    /// server measures. It has to be large against the pumps' scheduling jitter:
    /// the RACK time threshold sits at `srtt·9/8`, so the margin between "the
    /// retransmission's acknowledgement came back" and "the retransmission looks
    /// lost too" is an eighth of a round trip, and at single-digit milliseconds
    /// that margin *is* the jitter.
    const ACK_PATH_DELAY: Duration = Duration::from_millis(80);
    /// Minimum spacing between acknowledgements on that path — the link rate,
    /// expressed as time per frame.
    const ACK_SPACING: Duration = Duration::from_millis(3);

    let server_hs = HandshakeServer::new().expect("HandshakeServer::new");
    let server_pinned_key = server_hs.verifying_key().clone();
    let (client_channel, server_channel) = ChannelTransport::pair();

    // The client's pump runs in the background from here; the server handshake
    // is driven inline so the negotiated `Session` stays in reach.
    let client = PhantomSession::connect_with_transport(
        "test-server:9000",
        DelayLine::new(client_channel, ACK_PATH_DELAY, ACK_SPACING),
        server_pinned_key,
    );

    let client_ip = "127.0.0.1".parse().expect("parse IP");
    let hello_bytes = server_channel
        .recv_bytes()
        .await
        .expect("server recv ClientHello");
    let client_hello =
        borsh::from_slice::<ClientHello>(&hello_bytes).expect("deserialize ClientHello");
    let inner_session = match server_hs.process_client_hello(&client_hello, 0, client_ip) {
        HandshakeResponse::Retry(retry) => {
            let retry_bytes = ServerReply::Retry(retry)
                .to_wire()
                .expect("serialize retry");
            server_channel
                .send_bytes(&retry_bytes)
                .await
                .expect("server send retry");
            let next_bytes = server_channel
                .recv_bytes()
                .await
                .expect("server recv retry ClientHello");
            let next_hello =
                borsh::from_slice::<ClientHello>(&next_bytes).expect("deserialize retry hello");
            match server_hs.process_client_hello(&next_hello, 0, client_ip) {
                HandshakeResponse::Success(server_hello, session, _) => {
                    let b = ServerReply::Hello(server_hello)
                        .to_wire()
                        .expect("serialize ServerHello");
                    server_channel
                        .send_bytes(&b)
                        .await
                        .expect("server send ServerHello");
                    session
                }
                other => panic!("expected Success after retry, got {other:?}"),
            }
        }
        HandshakeResponse::Success(server_hello, session, _) => {
            let b = ServerReply::Hello(server_hello)
                .to_wire()
                .expect("serialize ServerHello");
            server_channel
                .send_bytes(&b)
                .await
                .expect("server send ServerHello");
            session
        }
        HandshakeResponse::Reject(r) => panic!("unexpected Reject: {r:?}"),
        HandshakeResponse::Fail(e) => panic!("handshake failed: {e:?}"),
    };

    let inner = Arc::new(inner_session);
    let congestion = inner.clone();
    let faults = FaultControl::new();
    let server = PhantomSession::from_accepted_server_session(
        "test-client".into(),
        LossyTransport::new(server_channel, faults.clone()),
        inner,
    );

    let mut established = false;
    for _ in 0..200 {
        if client.connection_state() == ConnectionState::Connected {
            established = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(established, "client session never became established");

    // Distinct bytes throughout, so a truncation or a reordering shows up as a
    // mismatch rather than as a length that happens to agree.
    let payload: Vec<u8> = (0..CHUNK * CHUNKS).map(|i| (i % 251) as u8).collect();
    // Take exactly one frame off the wire — the first chunk, since the write
    // below is the next thing this pump sends.
    faults.arm_drop_next(1);
    server.send(payload.clone()).await.expect("server send");

    let mut received = Vec::with_capacity(payload.len());
    for i in 0..CHUNKS {
        let chunk = timeout(Duration::from_secs(30), client.recv())
            .await
            .unwrap_or_else(|_| panic!("client recv timed out on chunk {i} — loss not recovered"))
            .expect("client recv error");
        received.extend_from_slice(&chunk);
    }
    assert_eq!(
        received, payload,
        "the dropped segment must be recovered byte-exact and in order"
    );

    assert_eq!(
        congestion.bbr_bytes_lost(),
        CHUNK as u64,
        "one dropped segment of {CHUNK} B must reach congestion control as exactly \
         {CHUNK} B of loss; a larger figure is the same segment re-reported once \
         per acknowledgement"
    );

    server.disconnect().await.expect("server clean disconnect");
    client.disconnect().await.expect("client clean disconnect");
}

/// **Seeded-loss survival.** A real session survives seeded packet loss + light
/// reorder on every application send, recovering every message byte-exact and in
/// order via the existing RTO retransmit path. Seeded ⇒ fully deterministic:
/// this run is reproducible (verified flake-free over 20 consecutive runs).
///
/// Rate: 3% loss + 1% reorder over 40 synchronous round-trips. This is the
/// robustly-green configuration the RTO-only recovery survives well inside the
/// 60s budget. See the module docs for the empirically-found ceiling.
#[tokio::test]
async fn session_survives_seeded_loss_and_reorder() {
    run_lossy_round_trips(
        0x0A11_CE5E_ED0F_F00D,
        0.03, // 3% per-send loss on the data phase
        0.01, // 1% per-send reorder (adjacent swap)
        40,
        Duration::from_secs(60),
    )
    .await;
}

/// A second, independent seed at the same rate — guards against a single lucky
/// seed. Still deterministic and green.
#[tokio::test]
async fn session_survives_seeded_loss_second_seed() {
    run_lossy_round_trips(
        0x1234_5678_9ABC_DEF0,
        0.03,
        0.01,
        40,
        Duration::from_secs(60),
    )
    .await;
}

/// **RTO-only latency-cliff reference (intentionally `#[ignore]`d).**
///
/// Demonstrates the RTO-only latency cliff. At **20% loss** the recovery is still
/// *lossless* (correctness holds — this asserts byte-exact, in-order delivery),
/// but the wall-clock cost is already an order of magnitude higher than the 5%
/// gate (measured up to ~9.5 s here vs. sub-second at 5%) because every time a
/// retransmit is itself dropped the RTO backs off geometrically (1s → 2s → 4s …).
/// The measured table in the module docs shows correctness holds up to ~40% and
/// only *times out* (never loses data) at ~50%+.
///
/// This is NOT a correctness failure — it is the latency ceiling a future SACK /
/// fast-retransmit pass (**Phase 2 / L1**) must lift: SACK recovers a dropped
/// segment in ~1 RTT off the next ACK instead of waiting out a backed-off RTO.
/// We keep it `#[ignore]`d (and out of the always-green gate) precisely because
/// its wall-clock is high-variance under RTO-only recovery; the generous 90s
/// budget keeps even an unlucky 20% seed asserting *correctness* rather than
/// flaking. Run it to reproduce the slow path:
///   `cargo test --lib -- loss_recovery --ignored`
#[tokio::test]
#[ignore = "documents the RTO-only latency cliff: 20% loss recovers losslessly but \
            slowly (geometric 1s/2s/4s backoff). Phase 2/L1 SACK + fast-retransmit \
            must flatten it. High-variance wall-clock — not an always-green gate."]
async fn loss_recovery_high_loss_recovers_but_is_slow() {
    // 20% loss: the regime where the RTO-only cost cliff is clearly visible while
    // recovery is still lossless. Generous budget so we assert byte-exact
    // recovery (correctness), not a tight latency bound.
    run_lossy_round_trips(
        0xDEAD_BEEF_F00D_CAFE,
        0.20, // 20% per-send loss
        0.02,
        30,
        Duration::from_secs(90),
    )
    .await;
}

/// **Measurement (ignored): pipelined loss sweep (L1).** Prints data-phase
/// wall-clock at increasing client→server loss with light reorder, to compare
/// against the RTO-only synchronous baseline (module docs table) and confirm
/// A.5 (in-order delivery) + L1-B (SACK fast-retransmit) lift the ceiling and
/// flatten the cliff. Run:
///   `cargo test --lib -- pipelined_loss_sweep --ignored --nocapture`
#[tokio::test]
#[ignore = "measurement: prints pipelined recovery latency across loss rates"]
async fn pipelined_loss_sweep() {
    for (loss, reorder) in [
        (0.05, 0.02),
        (0.10, 0.03),
        (0.15, 0.05),
        (0.20, 0.05),
        (0.30, 0.05),
    ] {
        let mut worst = Duration::ZERO;
        for seed in [
            0x1111_2222_3333_4444u64,
            0xAAAA_BBBB_CCCC_DDDD,
            0x0F0F_0F0F_0F0F_0F0F,
        ] {
            let t = run_pipelined_echo(seed, loss, reorder, 40, Duration::from_secs(90)).await;
            if t > worst {
                worst = t;
            }
        }
        println!(
            "PIPELINED loss={:>2.0}% reorder={:>2.0}% n=40 → worst-seed {:?}",
            loss * 100.0,
            reorder * 100.0,
            worst
        );
    }
}

/// **L1 acceptance (D): ≥15% loss, pipelined, in order.** A real session with
/// MANY messages in flight survives 15% client→server loss + 5% reorder,
/// recovering every echo byte-exact and IN ORDER. This is the robustly-green
/// ceiling lifted from ≤5% (RTO-only synchronous) to ≥15% by A.5 (in-order
/// delivery) + L1-B (SACK fast-retransmit). Seeded ⇒ deterministic. Measured
/// worst-seed ≈ 0.4 s vs ~4.3 s for the RTO-only baseline (module-doc table);
/// the 30 s budget is huge margin for CI contention.
#[tokio::test]
async fn pipelined_recovers_at_15pct_loss_with_reorder() {
    run_pipelined_echo(
        0xACCE_5515_0000_0001,
        0.15,
        0.05,
        30,
        Duration::from_secs(30),
    )
    .await;
}

/// Independent second seed at 15% — guards against a single lucky seed.
#[tokio::test]
async fn pipelined_recovers_at_15pct_loss_second_seed() {
    run_pipelined_echo(
        0x5EED_0015_2222_3333,
        0.15,
        0.05,
        30,
        Duration::from_secs(30),
    )
    .await;
}

/// Stretch target: 20% loss + 5% reorder still recovers byte-exact and in order
/// (measured worst-seed ≈ 0.4 s — the latency curve is flat, not the RTO-only
/// geometric cliff).
#[tokio::test]
async fn pipelined_recovers_at_20pct_loss() {
    run_pipelined_echo(
        0x2020_2020_ABCD_0001,
        0.20,
        0.05,
        30,
        Duration::from_secs(30),
    )
    .await;
}
