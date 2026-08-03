//! The scenario matrix.
//!
//! Each scenario is a self-contained async function that returns its raw
//! samples plus a derived summary. Scenarios never abort the run: a failure is
//! recorded as data and the matrix continues, because a run that stops at the
//! first error over a real WAN produces almost no information about the rest of
//! the surface.
//!
//! Scenarios come in two shapes. Those that compare the protocol under test
//! against the QUIC reference (`handshake`, `rtt_sweep`, `upload`, `download`,
//! `bidir`, `concurrency`) are written against [`MsgLink`], so both legs run
//! the *same* measurement code over the same application protocol. Those that
//! probe something only Phantom has (`message_integrity`, `zero_rtt`, `rekey`,
//! `migration`, `streams`, `negative`, `liveness_soak`) hold the concrete
//! session, and the reference leg records a [`skipped`] note saying why.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use phantom_protocol::CoreError;
use tokio::net::{TcpStream, UdpSocket};

use crate::clock::{self, ClockSample};
use crate::framing::{Framed, MsgLink};
use crate::probe::conn::{
    self, connect_framed, connect_leg, connect_leg_resumed, connect_link, connect_link_staged,
    echo_once, error_kind, mark, Endpoints, DRAIN_TIMEOUT, OP_TIMEOUT,
};
use crate::proto::{Msg, PayloadGen};
use crate::report::{
    unix_nanos, ConcurrencySample, ErrorRecord, HandshakeSample, Leg, MessageIntegritySample,
    MigrationSample, NegativeSample, RekeySample, RttSample, SampleSink, ScenarioSummary,
    SoakSample, StreamSample, ThroughputSample, ZeroRttSample,
};
use crate::stats::{Summary, Throughput};

/// What one scenario produced.
pub struct ScenarioOutput {
    pub file: String,
    pub sink: SampleSink,
    /// Congestion-window time series, written alongside the scenario's own
    /// samples as `<scenario>.window.jsonl`. Kept in its own file because it is
    /// a different record shape sampled on a different clock.
    pub window: SampleSink,
    pub summary: ScenarioSummary,
    pub errors: Vec<ErrorRecord>,
    /// Only `clock_sync` fills this.
    pub clock: Option<crate::report::ClockEstimate>,
}

impl ScenarioOutput {
    fn new(leg: Leg, scenario: &str) -> Self {
        Self {
            file: format!("{scenario}.jsonl"),
            sink: SampleSink::new(),
            window: SampleSink::new(),
            summary: ScenarioSummary {
                leg,
                scenario: scenario.to_string(),
                ok_count: 0,
                error_count: 0,
                latency_ns: None,
                throughput: None,
                notes: Vec::new(),
            },
            errors: Vec::new(),
            clock: None,
        }
    }

    fn note(&mut self, s: impl Into<String>) {
        self.summary.notes.push(s.into());
    }

    fn error(&mut self, leg: Leg, scenario: &str, context: &str, e: &CoreError) {
        self.summary.error_count += 1;
        self.errors.push(ErrorRecord {
            t_unix_ns: unix_nanos(),
            leg: Some(leg),
            scenario: scenario.to_string(),
            context: context.to_string(),
            error: format!("{e:?}"),
            error_kind: error_kind(e),
        });
    }
}

/// A scenario that does not apply to this leg.
///
/// Recorded rather than omitted: an empty row in `summary.json` carrying the
/// reason is a statement about coverage, while a missing row is indistinguishable
/// from a scenario that ran and produced nothing. It is deliberately not an
/// error — nothing failed.
pub fn skipped(leg: Leg, scenario: &str, why: &str) -> ScenarioOutput {
    let mut out = ScenarioOutput::new(leg, scenario);
    out.note(format!("skipped on this leg: {why}"));
    out
}

/// Samples the sender's congestion-control state on its own clock while a
/// transfer runs.
///
/// A separate task rather than an inline sample per frame: the send loop is the
/// thing being measured, and reading a mutex inside it would perturb exactly
/// the timing under observation.
struct WindowRecorder {
    stop: Arc<AtomicBool>,
    task: tokio::task::JoinHandle<Vec<crate::report::WindowSample>>,
}

impl WindowRecorder {
    /// Sample every 200 ms — fine enough to see a window open over a handful of
    /// round trips on a ~200 ms path, coarse enough to cost nothing.
    const INTERVAL: Duration = Duration::from_millis(200);

    /// Records whatever the link's own stack exposes. On the QUIC leg most of
    /// the record is zero by design — see [`crate::quic`].
    fn start(link: Arc<dyn MsgLink>, leg: Leg, phase: &str) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let stop2 = stop.clone();
        let phase = phase.to_string();
        let task = tokio::spawn(async move {
            let started = Instant::now();
            let mut out = Vec::new();
            while !stop2.load(Ordering::Relaxed) {
                let elapsed_ms = started.elapsed().as_millis() as u64;
                if let Some(w) = link.window_sample(leg, phase.clone(), elapsed_ms).await {
                    out.push(w);
                }
                tokio::time::sleep(Self::INTERVAL).await;
            }
            out
        });
        Self { stop, task }
    }

    async fn finish(self) -> Vec<crate::report::WindowSample> {
        self.stop.store(true, Ordering::Relaxed);
        self.task.await.unwrap_or_default()
    }
}

/// Summarise a window series into notes: where it started, where it got to, and
/// which phase it ended in.
fn note_window(out: &mut ScenarioOutput, samples: &[crate::report::WindowSample]) {
    note_window_as(out, samples, true)
}

/// `is_sender` says whether this series belongs to the side actually sending
/// the bulk data. On a download it does not: the client transmits almost
/// nothing, so its window sitting at the floor is the expected shape and says
/// nothing about the transfer. Drawing a "sender-bound" conclusion from it
/// would be a confident statement about the wrong endpoint.
fn note_window_as(
    out: &mut ScenarioOutput,
    samples: &[crate::report::WindowSample],
    is_sender: bool,
) {
    for w in samples {
        out.window.push(w);
    }
    let Some(last) = samples.last() else {
        out.note("no congestion-window samples (session never established)");
        return;
    };
    let first = &samples[0];
    let peak = samples.iter().map(|w| w.cwnd_bytes).max().unwrap_or(0);
    let peak_bw = samples
        .iter()
        .map(|w| w.bottleneck_bw_bps)
        .max()
        .unwrap_or(0);
    if out.summary.leg.is_phantom() {
        out.note(format!(
            "congestion window {} B -> {} B (peak {} B); bottleneck estimate peaked at {:.2} Mbit/s; ended in {}{}",
            first.cwnd_bytes,
            last.cwnd_bytes,
            peak,
            peak_bw as f64 * 8.0 / 1e6,
            last.state,
            if last.app_limited { ", app-limited" } else { "" }
        ));
    } else {
        // Reporting a zeroed field as "peaked at 0.00 Mbit/s" would read as a
        // measurement of a stalled link rather than as an absent instrument.
        out.note(format!(
            "congestion window {} B -> {} B (peak {} B), controller {}; this stack reports no bandwidth estimate, pacing rate, bytes in flight or app-limited flag, so those are absent rather than zero",
            first.cwnd_bytes, last.cwnd_bytes, peak, last.state,
        ));
    }
    if !is_sender {
        out.note(
            "this is the receiving side's own window — near-idle by design; the window that governs this transfer is the server's, reported separately",
        );
        return;
    }
    // 5600 B is `PROBE_RTT_CWND_PACKETS * MIN_PACKET_SIZE` — the floor a
    // Phantom window sits on when the bandwidth estimate never rises. It is a
    // constant of the protocol under test, so the conclusion it supports is
    // only drawn on a leg that actually has it.
    if out.summary.leg.is_phantom() && peak <= 5600 {
        out.note(
            "the window never left its 5600 B floor: throughput here is bounded by the sender, not the link",
        );
    }
}

/// Per-frame bytes a `SINK` costs on top of its payload: the framing length
/// prefix plus the verb and sequence number.
const SINK_FRAME_OVERHEAD: u64 = 4 + 1 + 8;

/// Rolling one-second throughput window.
///
/// Reporting only a run-level average would hide a stall entirely — a 10-second
/// freeze inside a 60-second transfer still yields a respectable-looking mean.
/// A per-second series makes the freeze visible as a hole.
struct WindowTracker {
    leg: Leg,
    direction: &'static str,
    started: Instant,
    window_start: Instant,
    window_bytes: u64,
    window_frames: u64,
    cumulative: u64,
    total_frames: u64,
}

impl WindowTracker {
    fn new(leg: Leg, direction: &'static str) -> Self {
        let now = Instant::now();
        Self {
            leg,
            direction,
            started: now,
            window_start: now,
            window_bytes: 0,
            window_frames: 0,
            cumulative: 0,
            total_frames: 0,
        }
    }

    fn add(&mut self, bytes: usize) -> Option<ThroughputSample> {
        self.window_bytes += bytes as u64;
        self.window_frames += 1;
        self.cumulative += bytes as u64;
        self.total_frames += 1;

        let elapsed = self.window_start.elapsed();
        if elapsed >= Duration::from_secs(1) {
            let s = ThroughputSample {
                leg: self.leg,
                direction: self.direction.to_string(),
                t_unix_ns: unix_nanos(),
                window_bytes: self.window_bytes,
                window_frames: self.window_frames,
                window_ns: elapsed.as_nanos() as u64,
                cumulative_bytes: self.cumulative,
            };
            self.window_start = Instant::now();
            self.window_bytes = 0;
            self.window_frames = 0;
            return Some(s);
        }
        None
    }

    fn finish(&self) -> Throughput {
        Throughput::new(
            self.cumulative,
            self.total_frames,
            self.started.elapsed().as_nanos() as u64,
        )
    }
}

// ── 1. clock_sync ───────────────────────────────────────────────────────────

pub async fn clock_sync(ep: &Endpoints, pin: &[u8], leg: Leg, probes: usize) -> ScenarioOutput {
    let mut out = ScenarioOutput::new(leg, "clock_sync");
    let framed = match connect_framed(leg, ep, pin).await {
        Ok(s) => s,
        Err(e) => {
            out.error(leg, "clock_sync", "connect", &e);
            return out;
        }
    };
    mark(&framed, "clock_sync:begin").await;

    let mut gen = PayloadGen::new(1);
    let mut samples = Vec::with_capacity(probes);
    let mut rtts = Vec::with_capacity(probes);

    for i in 0..probes as u64 {
        let t1 = unix_nanos();
        match echo_once(&framed, i, gen.fill(32)).await {
            Ok(o) => {
                let t4 = unix_nanos();
                samples.push(ClockSample {
                    t1,
                    t2: o.server_recv_ns,
                    t3: o.server_send_ns,
                    t4,
                });
                rtts.push(o.rtt_ns);
                out.summary.ok_count += 1;
                out.sink.push(&RttSample {
                    seq: i,
                    leg,
                    payload_bytes: 32,
                    t_unix_ns: t1,
                    rtt_ns: o.rtt_ns,
                    server_recv_unix_ns: Some(o.server_recv_ns),
                    server_send_unix_ns: Some(o.server_send_ns),
                    server_turnaround_ns: Some(o.server_send_ns.saturating_sub(o.server_recv_ns)),
                });
            }
            Err(e) => out.error(leg, "clock_sync", "echo", &e),
        }
    }

    out.clock = clock::estimate(&samples);
    if let Some(c) = &out.clock {
        out.note(format!(
            "clock offset {} ns, dispersion {} ns over {} probes — one-way splits carry an error bar of that magnitude",
            c.offset_ns, c.dispersion_ns, c.samples
        ));
    }
    out.summary.latency_ns = Some(Summary::of_u64(&rtts));
    mark(&framed, "clock_sync:end").await;
    conn::close_session(framed.session()).await;
    out
}

// ── 2. handshake ────────────────────────────────────────────────────────────

pub async fn handshake(ep: &Endpoints, pin: &[u8], leg: Leg, count: usize) -> ScenarioOutput {
    let mut out = ScenarioOutput::new(leg, "handshake");
    let mut connect_ns = Vec::with_capacity(count);
    let mut gen = PayloadGen::new(2);

    for i in 0..count as u64 {
        let t0 = Instant::now();
        // Measure the two phases separately: `connect_pinned*` returns before
        // the handshake runs, so a single number would conflate a socket setup
        // with a post-quantum key exchange.
        let staged = connect_link_staged(leg, ep, pin).await;

        match staged {
            Ok((framed, setup_ns)) => {
                let c_ns = t0.elapsed().as_nanos() as u64;
                let first = echo_once(framed.as_ref(), 0, gen.fill(32)).await;
                let (first_rtt, ok, err, kind) = match first {
                    Ok(o) => (Some(o.rtt_ns), true, None, None),
                    Err(e) => {
                        out.error(leg, "handshake", "first echo", &e);
                        (None, false, Some(format!("{e:?}")), Some(error_kind(&e)))
                    }
                };
                if ok {
                    out.summary.ok_count += 1;
                    connect_ns.push(c_ns);
                }
                out.sink.push(&HandshakeSample {
                    seq: i,
                    leg,
                    t_unix_ns: unix_nanos(),
                    setup_ns: Some(setup_ns),
                    connect_ns: Some(c_ns),
                    first_rtt_ns: first_rtt,
                    ok,
                    error: err,
                    error_kind: kind,
                });
                framed.close().await;
            }
            Err(e) => {
                out.error(leg, "handshake", "connect", &e);
                out.sink.push(&HandshakeSample {
                    seq: i,
                    leg,
                    t_unix_ns: unix_nanos(),
                    setup_ns: None,
                    connect_ns: None,
                    first_rtt_ns: None,
                    ok: false,
                    error: Some(format!("{e:?}")),
                    error_kind: Some(error_kind(&e)),
                });
            }
        }
    }

    out.summary.latency_ns = Some(Summary::of_u64(&connect_ns));
    if leg.is_reference() {
        out.note("connect_ns spans quinn's TLS 1.3 handshake with classical primitives, including one network round trip; setup_ns is the endpoint-and-socket prefix before it starts");
        out.note("this number is NOT comparable like-for-like with the Phantom legs': they exchange a hybrid post-quantum key and carry a ~4 KB hybrid signature, and the difference between the two is expected rather than a finding");
    } else {
        out.note("connect_ns spans the full hybrid X25519+ML-KEM-768 / Ed25519+ML-DSA-65 handshake including one network round trip; setup_ns is the socket-and-allocation prefix before the handshake starts");
    }
    out
}

// ── 3. rtt_sweep ────────────────────────────────────────────────────────────

pub async fn rtt_sweep(
    ep: &Endpoints,
    pin: &[u8],
    leg: Leg,
    sizes: &[usize],
    per_size: usize,
) -> ScenarioOutput {
    let mut out = ScenarioOutput::new(leg, "rtt_sweep");
    let framed = match connect_link(leg, ep, pin).await {
        Ok(s) => s,
        Err(e) => {
            out.error(leg, "rtt_sweep", "connect", &e);
            return out;
        }
    };
    mark(framed.as_ref(), "rtt_sweep:begin").await;

    let mut gen = PayloadGen::new(3);
    let mut all = Vec::new();
    let mut seq = 0u64;

    // A payload size that is failing outright costs `OP_TIMEOUT` per probe. Once
    // enough consecutive probes have timed out, the size has answered the
    // question — continuing only burns wall clock that the remaining sizes and
    // scenarios need. The abort is recorded, so a short bucket is never mistaken
    // for a healthy one.
    const MAX_CONSECUTIVE_FAILURES: u32 = 5;

    for &size in sizes {
        let mut per: Vec<u64> = Vec::with_capacity(per_size);
        let mut consecutive_failures = 0u32;
        let mut aborted = false;
        let mut attempted = 0usize;
        for _ in 0..per_size {
            attempted += 1;
            let payload = gen.fill(size);
            let t_send = unix_nanos();
            match echo_once(framed.as_ref(), seq, payload).await {
                Ok(o) => {
                    consecutive_failures = 0;
                    per.push(o.rtt_ns);
                    all.push(o.rtt_ns);
                    out.summary.ok_count += 1;
                    out.sink.push(&RttSample {
                        seq,
                        leg,
                        payload_bytes: size,
                        t_unix_ns: t_send,
                        rtt_ns: o.rtt_ns,
                        server_recv_unix_ns: Some(o.server_recv_ns),
                        server_send_unix_ns: Some(o.server_send_ns),
                        server_turnaround_ns: Some(
                            o.server_send_ns.saturating_sub(o.server_recv_ns),
                        ),
                    });
                }
                Err(e) => {
                    consecutive_failures += 1;
                    out.error(leg, "rtt_sweep", &format!("size {size}"), &e);
                    out.sink.push(&RttSample {
                        seq,
                        leg,
                        payload_bytes: size,
                        t_unix_ns: t_send,
                        rtt_ns: 0,
                        server_recv_unix_ns: None,
                        server_send_unix_ns: None,
                        server_turnaround_ns: None,
                    });
                }
            }
            seq += 1;
            if consecutive_failures >= MAX_CONSECUTIVE_FAILURES {
                aborted = true;
                break;
            }
        }

        if !per.is_empty() {
            let s = Summary::of_u64(&per);
            out.note(format!(
                "{size} B: {}/{} succeeded, p50 {:.2} ms, p99 {:.2} ms",
                per.len(),
                attempted,
                s.p50 / 1e6,
                s.p99 / 1e6
            ));
        } else {
            out.note(format!("{size} B: every probe failed"));
        }
        if aborted {
            out.note(format!(
                "{size} B: stopped after {MAX_CONSECUTIVE_FAILURES} consecutive failures — this size is not merely slow, it is not getting through"
            ));
        }
    }

    out.summary.latency_ns = Some(Summary::of_u64(&all));
    if let Some(n) = framed.transport_note() {
        out.note(n);
    }
    mark(framed.as_ref(), "rtt_sweep:end").await;
    framed.close().await;
    out
}

// ── 3b. message_integrity ───────────────────────────────────────────────────

/// Measure whether `PhantomSession` preserves application message boundaries.
///
/// The data pump splits any payload above its internal `TRANSPORT_MTU`
/// (1300 B) into chunks and writes each as a separate reliable-stream write, so
/// the peer's `recv()` returns them one at a time. Nothing on `send`/`recv`
/// documents this, and the failure is silent: a structured message's first
/// chunk still parses, with the tail quietly gone.
///
/// This scenario walks payload sizes across that boundary and records, for each,
/// how many `recv()` results one logical message arrived in. It is a
/// measurement of documented-vs-actual behaviour, not a pass/fail test — the
/// harness reassembles correctly either way.
pub async fn message_integrity(
    ep: &Endpoints,
    pin: &[u8],
    leg: Leg,
    sizes: &[usize],
) -> ScenarioOutput {
    let mut out = ScenarioOutput::new(leg, "message_integrity");
    let framed = match connect_framed(leg, ep, pin).await {
        Ok(s) => s,
        Err(e) => {
            out.error(leg, "message_integrity", "connect", &e);
            return out;
        }
    };
    mark(&framed, "message_integrity:begin").await;

    let mut gen = PayloadGen::new(31);
    let mut first_split: Option<usize> = None;
    let mut max_intact = 0usize;

    for (i, &size) in sizes.iter().enumerate() {
        let payload = gen.fill(size);
        let message_bytes = Msg::Echo {
            seq: 0,
            client_send_ns: 0,
            payload: payload.clone(),
        }
        .encode()
        .len();

        match echo_once(&framed, i as u64, payload).await {
            Ok(o) => {
                out.summary.ok_count += 1;
                if o.arrival.chunks > 1 && first_split.is_none() {
                    first_split = Some(size);
                }
                max_intact = max_intact.max(size);
                out.sink.push(&MessageIntegritySample {
                    leg,
                    t_unix_ns: unix_nanos(),
                    payload_bytes: size,
                    message_bytes,
                    recv_chunks: o.arrival.chunks,
                    chunk_sizes: o.arrival.chunk_sizes.clone(),
                    payload_intact: true,
                    rtt_ns: Some(o.rtt_ns),
                    error: None,
                });
            }
            Err(e) => {
                // `ProtocolRejected` here specifically means the echoed payload
                // came back different from what was sent — the corruption this
                // scenario exists to catch, as distinct from a lost round trip.
                let corrupted = matches!(e, CoreError::ProtocolRejected(_));
                out.error(leg, "message_integrity", &format!("size {size}"), &e);
                out.sink.push(&MessageIntegritySample {
                    leg,
                    t_unix_ns: unix_nanos(),
                    payload_bytes: size,
                    message_bytes,
                    recv_chunks: 0,
                    chunk_sizes: Vec::new(),
                    payload_intact: !corrupted,
                    rtt_ns: None,
                    error: Some(format!("{e:?}")),
                });
            }
        }
    }

    match first_split {
        Some(sz) => out.note(format!(
            "message boundaries stop being preserved at {sz} B of payload: above that, one send() arrives as several recv() results and the harness reassembles it"
        )),
        None => out.note("every probed size arrived as a single recv() result"),
    }
    out.note(format!(
        "largest payload round-tripped byte-exact after reassembly: {max_intact} B"
    ));

    mark(&framed, "message_integrity:end").await;
    conn::close_session(framed.session()).await;
    out
}

// ── 4. upload ───────────────────────────────────────────────────────────────

pub async fn upload(
    ep: &Endpoints,
    pin: &[u8],
    leg: Leg,
    duration: Duration,
    frame_size: usize,
) -> ScenarioOutput {
    let mut out = ScenarioOutput::new(leg, "upload");
    let framed = match connect_link(leg, ep, pin).await {
        Ok(s) => s,
        Err(e) => {
            out.error(leg, "upload", "connect", &e);
            return out;
        }
    };
    mark(framed.as_ref(), "upload:begin").await;
    let recorder = WindowRecorder::start(framed.clone(), leg, "upload");

    let mut gen = PayloadGen::new(4);
    let payload = gen.fill(frame_size.saturating_sub(9));
    let mut win = WindowTracker::new(leg, "upload");
    let deadline = Instant::now() + duration;
    let mut seq = 0u64;
    let mut stalled = false;

    while Instant::now() < deadline {
        let wire = crate::framing::encode_framed(&Msg::Sink {
            seq,
            payload: payload.clone(),
        });
        let n = wire.len();
        match tokio::time::timeout(OP_TIMEOUT, framed.send_encoded(wire)).await {
            Ok(Ok(())) => {
                if let Some(s) = win.add(n) {
                    out.sink.push(&s);
                }
                out.summary.ok_count += 1;
            }
            Ok(Err(e)) => {
                out.error(leg, "upload", "send", &e);
                break;
            }
            Err(_) => {
                // Not a fault: `send()` blocked longer than an operation budget
                // because the session is already saturated. That is the
                // transport applying backpressure, and it is the end of the
                // measurement window, not an error in it.
                stalled = true;
                break;
            }
        }
        seq += 1;
    }

    let local = win.finish();
    out.summary.throughput = Some(local.clone());
    if stalled {
        out.note(
            "the send path applied backpressure before the window elapsed — the offered rate exceeded what the session would accept, which is the point at which this number saturates",
        );
    }

    // Cross-check against what the server actually received and decrypted. A
    // gap between the two is the difference between "we handed bytes to the
    // API" and "bytes crossed the network" — the number that matters.
    // The session's own byte counter, captured before the close, bounds how much
    // was still unacknowledged when the burst ended. The reference leg has no
    // such counter; `(0, 0)` there means "not instrumented", not "nothing sent",
    // and the note below says which leg it came from.
    let client_metrics = framed
        .phantom()
        .map(|s| s.metrics_snapshot())
        .map(|m| (m.bytes_sent, m.packets_sent))
        .unwrap_or((0, 0));
    match sink_end_and_report(framed.as_ref(), seq, win.cumulative).await {
        Ok((frames, bytes, first_ns, last_ns)) => {
            let server_span = last_ns.saturating_sub(first_ns);
            let server_tp = Throughput::new(bytes, frames, server_span);
            out.note(format!(
                "client sent {} B in {} frames ({:.2} Mbit/s); server received {} B in {} frames ({:.2} Mbit/s over its own {} ms observation span)",
                local.bytes, local.frames, local.megabits_per_sec,
                bytes, frames, server_tp.megabits_per_sec, server_span / 1_000_000
            ));
            // Compare like with like. The client counts wire bytes (length
            // prefix + verb + seq + payload); the server counts payload only.
            // Subtracting the known per-frame header is what makes a real
            // shortfall visible — without it every clean run looked like it had
            // lost a few kilobytes.
            let client_payload = win
                .cumulative
                .saturating_sub(win.total_frames.saturating_mul(SINK_FRAME_OVERHEAD));
            match client_payload.checked_sub(bytes) {
                Some(0) | None => out.note(format!(
                    "no loss: every one of the {frames} frames arrived, {bytes} B of payload"
                )),
                Some(missing) => out.note(format!(
                    "{missing} B of payload never reached the server — in flight at teardown, or lost"
                )),
            }
        }
        Err((why, e)) => {
            out.error(leg, "upload", why.context(), &e);
            out.note(format!(
                "upload could not be closed cleanly ({}); client enqueued {} B in {} frames, session counters report {} B / {} packets sent",
                match why {
                    SinkEndFailure::SendBlocked =>
                        "the session never accepted the closing frame — its send buffer did not drain",
                    SinkEndFailure::NoReport =>
                        "the closing frame was handed to the session but no report came back — the tail of the transfer was not delivered",
                },
                win.cumulative,
                seq,
                client_metrics.0,
                client_metrics.1
            ));
        }
    }

    note_window(&mut out, &recorder.finish().await);
    if let Some(n) = framed.transport_note() {
        out.note(n);
    }
    mark(framed.as_ref(), "upload:end").await;
    framed.close().await;
    out
}

/// Why closing an upload burst failed, when it does.
///
/// The two cases have completely different causes and the distinction is not
/// recoverable after the fact: either the session would not accept the closing
/// frame (its send buffer never drained), or it accepted it and no answer ever
/// came back (the frame was lost and nothing retransmitted it — the tail of a
/// transfer has no following packet to trigger fast retransmit). Reporting a
/// bare `Timeout` for both would throw that away.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SinkEndFailure {
    /// `send()` never accepted the closing frame.
    SendBlocked,
    /// The frame was handed off; no `SINK_REPORT` came back.
    NoReport,
}

impl SinkEndFailure {
    fn context(self) -> &'static str {
        match self {
            Self::SendBlocked => "sink_end send blocked",
            Self::NoReport => "sink_end sent, no report",
        }
    }
}

async fn sink_end_and_report(
    framed: &dyn MsgLink,
    frames: u64,
    bytes: u64,
) -> Result<(u64, u64, u64, u64), (SinkEndFailure, CoreError)> {
    match tokio::time::timeout(DRAIN_TIMEOUT, framed.send(&Msg::SinkEnd { frames, bytes })).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Err((SinkEndFailure::SendBlocked, e)),
        Err(_) => return Err((SinkEndFailure::SendBlocked, CoreError::Timeout)),
    }
    let deadline = Instant::now() + DRAIN_TIMEOUT;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err((SinkEndFailure::NoReport, CoreError::Timeout));
        }
        let got = tokio::time::timeout(remaining, framed.recv()).await;
        let (msg, _) = match got {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => return Err((SinkEndFailure::NoReport, e)),
            Err(_) => return Err((SinkEndFailure::NoReport, CoreError::Timeout)),
        };
        if let Msg::SinkReport {
            frames,
            bytes,
            first_recv_ns,
            last_recv_ns,
        } = msg
        {
            return Ok((frames, bytes, first_recv_ns, last_recv_ns));
        }
    }
}

// ── 5. download ─────────────────────────────────────────────────────────────

pub async fn download(
    ep: &Endpoints,
    pin: &[u8],
    leg: Leg,
    total_bytes: u64,
    frame_size: u32,
    cap: Duration,
) -> ScenarioOutput {
    let mut out = ScenarioOutput::new(leg, "download");
    let framed = match connect_link(leg, ep, pin).await {
        Ok(s) => s,
        Err(e) => {
            out.error(leg, "download", "connect", &e);
            return out;
        }
    };
    mark(framed.as_ref(), "download:begin").await;
    // The *server* is the sender here, so this series is the client's own
    // window — near-idle by design. The server's side comes back in STATS.
    let recorder = WindowRecorder::start(framed.clone(), leg, "download");

    if let Err(e) = conn::send_msg(
        framed.as_ref(),
        Msg::SourceReq {
            total_bytes,
            frame_size,
            pace_kbps: 0,
        },
    )
    .await
    {
        out.error(leg, "download", "source request", &e);
        framed.close().await;
        return out;
    }

    let mut win = WindowTracker::new(leg, "download");
    let overall_deadline = Instant::now() + cap;
    let mut capped = false;

    loop {
        if Instant::now() > overall_deadline {
            // Not a failure: the measurement window closed before the byte
            // budget did. Throughput over that window is still exactly what was
            // being measured; only the total is short.
            capped = true;
            break;
        }
        let b = match tokio::time::timeout(OP_TIMEOUT, framed.recv()).await {
            Ok(Ok((m, _))) => m,
            Ok(Err(e)) => {
                out.error(leg, "download", "recv", &e);
                break;
            }
            Err(_) => {
                out.error(leg, "download", "recv", &CoreError::Timeout);
                break;
            }
        };
        match b {
            Msg::SourceData { payload, .. } => {
                out.summary.ok_count += 1;
                if let Some(s) = win.add(payload.len()) {
                    out.sink.push(&s);
                }
            }
            Msg::SourceEnd { frames, bytes } => {
                out.note(format!(
                    "server reports it sent {bytes} B in {frames} frames"
                ));
                if bytes > win.cumulative {
                    out.note(format!(
                        "{} B the server sent never arrived at the application",
                        bytes - win.cumulative
                    ));
                }
                break;
            }
            _ => continue,
        }
    }

    let tp = win.finish();
    if capped {
        out.note(format!(
            "measurement window ({} s) closed before the {} B budget: {} B transferred, throughput is over the window",
            cap.as_secs(),
            total_bytes,
            tp.bytes
        ));
    }
    out.summary.throughput = Some(tp);
    note_window_as(&mut out, &recorder.finish().await, false);
    // The window that governs a download is the server's, and the daemon records
    // its own into `windows.jsonl` — sampled there rather than polled from here,
    // so nothing this scenario does can perturb the transfer it is measuring.
    // Join on the `download:*` marks in the server journal.
    out.note(
        "the sending side here is the server: its window is in the daemon's windows.jsonl, joinable via the download:begin/end marks",
    );
    if let Some(n) = framed.transport_note() {
        out.note(n);
    }
    mark(framed.as_ref(), "download:end").await;
    framed.close().await;
    out
}

// ── 6. bidir ────────────────────────────────────────────────────────────────

pub async fn bidir(
    ep: &Endpoints,
    pin: &[u8],
    leg: Leg,
    total_bytes: u64,
    frame_size: u32,
    cap: Duration,
) -> ScenarioOutput {
    let mut out = ScenarioOutput::new(leg, "bidir");
    let framed = match connect_link(leg, ep, pin).await {
        Ok(s) => s,
        Err(e) => {
            out.error(leg, "bidir", "connect", &e);
            return out;
        }
    };
    mark(framed.as_ref(), "bidir:begin").await;
    let recorder = WindowRecorder::start(framed.clone(), leg, "bidir");

    if let Err(e) = conn::send_msg(
        framed.as_ref(),
        Msg::SourceReq {
            total_bytes,
            frame_size,
            pace_kbps: 0,
        },
    )
    .await
    {
        out.error(leg, "bidir", "source request", &e);
        framed.close().await;
        return out;
    }

    // Upload runs in its own task so both directions are genuinely concurrent.
    let stop = Arc::new(AtomicBool::new(false));
    let up_framed = framed.clone();
    let up_stop = stop.clone();
    let up_frame = frame_size as usize;
    // Send the same volume the download carries. An unbounded blast would not
    // measure full duplex — it would measure which direction starves the other,
    // and would never terminate on a fast path.
    let up_budget = total_bytes;
    let uploader = tokio::spawn(async move {
        let mut gen = PayloadGen::new(6);
        let payload = gen.fill(up_frame.saturating_sub(9));
        let mut seq = 0u64;
        let mut bytes = 0u64;
        while !up_stop.load(Ordering::Relaxed) && bytes < up_budget {
            let wire = crate::framing::encode_framed(&Msg::Sink {
                seq,
                payload: payload.clone(),
            });
            let n = wire.len() as u64;
            match tokio::time::timeout(OP_TIMEOUT, up_framed.send_encoded(wire)).await {
                Ok(Ok(())) => {
                    bytes += n;
                    seq += 1;
                }
                _ => break,
            }
        }
        (seq, bytes)
    });

    let mut down = WindowTracker::new(leg, "bidir_download");
    let deadline = Instant::now() + cap;
    let mut capped = false;
    loop {
        if Instant::now() > deadline {
            capped = true;
            break;
        }
        let b = match tokio::time::timeout(OP_TIMEOUT, framed.recv()).await {
            Ok(Ok((m, _))) => m,
            Ok(Err(e)) => {
                out.error(leg, "bidir", "recv", &e);
                break;
            }
            Err(_) => {
                out.error(leg, "bidir", "recv", &CoreError::Timeout);
                break;
            }
        };
        match b {
            Msg::SourceData { payload, .. } => {
                out.summary.ok_count += 1;
                if let Some(s) = down.add(payload.len()) {
                    out.sink.push(&s);
                }
            }
            Msg::SourceEnd { .. } => break,
            _ => continue,
        }
    }

    stop.store(true, Ordering::Relaxed);
    let (up_frames, up_bytes) = uploader.await.unwrap_or((0, 0));
    let down_tp = down.finish();
    if capped {
        out.note(format!(
            "measurement window ({} s) closed before the byte budget",
            cap.as_secs()
        ));
    }
    out.summary.throughput = Some(down_tp.clone());
    out.note(format!(
        "full duplex: down {:.2} Mbit/s ({} B), up {} B in {} frames over the same interval",
        down_tp.megabits_per_sec, down_tp.bytes, up_bytes, up_frames
    ));

    match sink_end_and_report(framed.as_ref(), up_frames, up_bytes).await {
        Ok((f, b, _, _)) => out.note(format!("server received {b} B in {f} upload frames")),
        Err((why, e)) => out.error(leg, "bidir", why.context(), &e),
    }

    note_window(&mut out, &recorder.finish().await);
    if let Some(n) = framed.transport_note() {
        out.note(n);
    }
    mark(framed.as_ref(), "bidir:end").await;
    framed.close().await;
    out
}

// ── 7. streams ──────────────────────────────────────────────────────────────

pub async fn streams(
    ep: &Endpoints,
    pin: &[u8],
    leg: Leg,
    stream_count: usize,
    frames_each: usize,
    frame_size: usize,
) -> ScenarioOutput {
    let mut out = ScenarioOutput::new(leg, "streams");
    let framed = match connect_framed(leg, ep, pin).await {
        Ok(s) => s,
        Err(e) => {
            out.error(leg, "streams", "connect", &e);
            return out;
        }
    };
    mark(&framed, "streams:begin").await;

    let mut handles = Vec::with_capacity(stream_count);
    for i in 0..stream_count {
        let stream = framed.session().open_stream();
        // Spread priorities so the scheduler has something to differentiate.
        let priority = (i as u32 % 4) * 8;
        let _ = stream.set_priority(priority).await;
        let sid = stream.stream_id();

        handles.push(tokio::spawn(async move {
            let mut gen = PayloadGen::new(70 + i as u64);
            let mut samples = Vec::with_capacity(frames_each);
            for seq in 0..frames_each as u64 {
                let payload = gen.fill(frame_size);
                let t0 = Instant::now();
                let send = tokio::time::timeout(OP_TIMEOUT, stream.send_reliable(payload)).await;
                if !matches!(send, Ok(Ok(()))) {
                    samples.push((
                        sid,
                        priority,
                        seq,
                        None,
                        frame_size,
                        false,
                        Some("send".to_string()),
                    ));
                    break;
                }
                match tokio::time::timeout(OP_TIMEOUT, stream.recv()).await {
                    Ok(Ok(Some(data))) => samples.push((
                        sid,
                        priority,
                        seq,
                        Some(t0.elapsed().as_nanos() as u64),
                        data.len(),
                        true,
                        None,
                    )),
                    // `Ok(None)` is a clean peer FIN — the stream half-closed,
                    // which is an outcome, not an error.
                    Ok(Ok(None)) => {
                        samples.push((sid, priority, seq, None, 0, false, Some("peer_fin".into())));
                        break;
                    }
                    Ok(Err(e)) => {
                        samples.push((sid, priority, seq, None, 0, false, Some(format!("{e:?}"))));
                        break;
                    }
                    Err(_) => {
                        samples.push((sid, priority, seq, None, 0, false, Some("timeout".into())));
                        break;
                    }
                }
            }
            let _ = stream.disconnect().await;
            samples
        }));
    }

    let mut rtts = Vec::new();
    for h in handles {
        let Ok(samples) = h.await else { continue };
        for (sid, priority, seq, rtt, bytes, ok, err) in samples {
            if ok {
                out.summary.ok_count += 1;
                if let Some(r) = rtt {
                    rtts.push(r);
                }
            } else {
                out.summary.error_count += 1;
            }
            out.sink.push(&StreamSample {
                leg,
                stream_id: sid,
                priority,
                t_unix_ns: unix_nanos(),
                seq,
                rtt_ns: rtt,
                bytes,
                ok,
                error: err,
            });
        }
    }

    out.summary.latency_ns = Some(Summary::of_u64(&rtts));
    out.note(format!(
        "{stream_count} concurrent streams; client-opened ids are odd (QUIC-style parity split)"
    ));
    mark(&framed, "streams:end").await;
    conn::close_session(framed.session()).await;
    out
}

// ── 8. zero_rtt ─────────────────────────────────────────────────────────────

pub async fn zero_rtt(
    ep: &Endpoints,
    pin: &[u8],
    leg: Leg,
    rounds: usize,
    early_data_bytes: usize,
) -> ScenarioOutput {
    let mut out = ScenarioOutput::new(leg, "zero_rtt");
    let mut cold_ns = Vec::new();
    let mut warm_ns = Vec::new();
    let mut accepted = 0usize;
    let mut gen = PayloadGen::new(8);

    for i in 0..rounds as u64 {
        // Cold connect purely to obtain a ticket.
        let t0 = Instant::now();
        let cold = match connect_framed(leg, ep, pin).await {
            Ok(s) => s,
            Err(e) => {
                out.error(leg, "zero_rtt", "cold connect", &e);
                out.sink.push(&ZeroRttSample {
                    seq: i,
                    leg,
                    t_unix_ns: unix_nanos(),
                    cold_connect_ns: None,
                    resumed_connect_ns: None,
                    early_data_accepted: None,
                    got_hint: false,
                    ok: false,
                    error: Some(format!("{e:?}")),
                });
                continue;
            }
        };
        let cold_elapsed = t0.elapsed().as_nanos() as u64;
        cold_ns.push(cold_elapsed);

        let hint = cold.session().resumption_hint().await;
        conn::close_session(cold.session()).await;

        let Some(hint) = hint else {
            out.sink.push(&ZeroRttSample {
                seq: i,
                leg,
                t_unix_ns: unix_nanos(),
                cold_connect_ns: Some(cold_elapsed),
                resumed_connect_ns: None,
                early_data_accepted: None,
                got_hint: false,
                ok: false,
                error: Some("server issued no resumption hint".into()),
            });
            out.summary.error_count += 1;
            continue;
        };

        let early = gen.fill(early_data_bytes);
        let t1 = Instant::now();
        match connect_leg_resumed(leg, ep, pin, hint, early)
            .await
            .map(Framed::new)
        {
            Ok(warm) => {
                let warm_elapsed = t1.elapsed().as_nanos() as u64;
                warm_ns.push(warm_elapsed);
                let verdict = warm.session().early_data_accepted().await;
                if verdict == Some(true) {
                    accepted += 1;
                }
                // The session must still work regardless of the 0-RTT verdict —
                // rejection falls back to a normal 1-RTT handshake, and the
                // client re-queues the rejected early data.
                let usable = echo_once(&warm, 0, vec![1, 2, 3]).await.is_ok();
                if usable {
                    out.summary.ok_count += 1;
                }
                out.sink.push(&ZeroRttSample {
                    seq: i,
                    leg,
                    t_unix_ns: unix_nanos(),
                    cold_connect_ns: Some(cold_elapsed),
                    resumed_connect_ns: Some(warm_elapsed),
                    early_data_accepted: verdict,
                    got_hint: true,
                    ok: usable,
                    error: if usable {
                        None
                    } else {
                        Some("resumed session did not carry application data".into())
                    },
                });
                conn::close_session(warm.session()).await;
            }
            Err(e) => {
                out.error(leg, "zero_rtt", "resumed connect", &e);
                out.sink.push(&ZeroRttSample {
                    seq: i,
                    leg,
                    t_unix_ns: unix_nanos(),
                    cold_connect_ns: Some(cold_elapsed),
                    resumed_connect_ns: None,
                    early_data_accepted: None,
                    got_hint: true,
                    ok: false,
                    error: Some(format!("{e:?}")),
                });
            }
        }
    }

    let cold_s = Summary::of_u64(&cold_ns);
    let warm_s = Summary::of_u64(&warm_ns);
    out.summary.latency_ns = Some(warm_s.clone());
    out.note(format!(
        "cold p50 {:.2} ms vs resumed p50 {:.2} ms; early data accepted in {}/{} rounds",
        cold_s.p50 / 1e6,
        warm_s.p50 / 1e6,
        accepted,
        rounds
    ));
    out.note("a rejected ticket is a correct outcome, not a failure: the client falls back to 1-RTT and re-queues the early data");
    out
}

// ── 9. migration ────────────────────────────────────────────────────────────

pub async fn migration(
    ep: &Endpoints,
    pin: &[u8],
    leg: Leg,
    rounds: usize,
    echoes_per_round: usize,
) -> ScenarioOutput {
    let mut out = ScenarioOutput::new(leg, "migration");

    if !leg.supports_migration() {
        // Assert the documented contract rather than skipping quietly: every
        // non-UDP leg must answer `Unsupported`, and a silent no-op here was a
        // real regression once.
        match connect_framed(leg, ep, pin).await {
            Ok(framed) => {
                let r = framed.session().migrate("0.0.0.0:0".to_string()).await;
                let passed = matches!(r, Err(CoreError::Unsupported(_)));
                out.sink.push(&MigrationSample {
                    seq: 0,
                    leg,
                    t_unix_ns: unix_nanos(),
                    old_local_addr: None,
                    new_local_addr: "0.0.0.0:0".into(),
                    migrate_call_ns: None,
                    data_gap_ns: None,
                    failed_rtts: 0,
                    recovered: false,
                    state_after: format!("{:?}", framed.session().connection_state()),
                    ok: passed,
                    error: Some(format!("{r:?}")),
                });
                if passed {
                    out.summary.ok_count += 1;
                    out.note("migrate() correctly reports Unsupported on this leg");
                } else {
                    out.summary.error_count += 1;
                    out.note(format!(
                        "migrate() should be Unsupported on {leg} but returned {r:?}"
                    ));
                }
                conn::close_session(framed.session()).await;
            }
            Err(e) => out.error(leg, "migration", "connect", &e),
        }
        return out;
    }

    let mut gaps = Vec::new();
    for round in 0..rounds as u64 {
        let framed = match connect_framed(leg, ep, pin).await {
            Ok(s) => s,
            Err(e) => {
                out.error(leg, "migration", "connect", &e);
                continue;
            }
        };
        mark(&framed, format!("migration:{round}:begin")).await;

        let mut gen = PayloadGen::new(90 + round);
        let switch_at = echoes_per_round / 2;
        let mut last_ok_before: Option<Instant> = None;
        let mut first_ok_after: Option<Instant> = None;
        let mut migrate_call_ns = None;
        let mut failed = 0u64;
        let mut migrated = false;
        let mut migrate_err = None;

        for i in 0..echoes_per_round {
            if i == switch_at {
                mark(&framed, format!("migration:{round}:migrate")).await;
                let t0 = Instant::now();
                // Port 0 asks the OS for a fresh ephemeral port: a genuine local
                // rebind, and the trigger for the server's path-validation
                // challenge over the new 4-tuple.
                match framed.session().migrate("0.0.0.0:0".to_string()).await {
                    Ok(()) => {
                        migrate_call_ns = Some(t0.elapsed().as_nanos() as u64);
                        migrated = true;
                    }
                    Err(e) => {
                        migrate_err = Some(format!("{e:?}"));
                        out.error(leg, "migration", "migrate", &e);
                    }
                }
            }

            match echo_once(&framed, i as u64, gen.fill(64)).await {
                Ok(_) => {
                    if migrated {
                        if first_ok_after.is_none() {
                            first_ok_after = Some(Instant::now());
                        }
                    } else {
                        last_ok_before = Some(Instant::now());
                    }
                }
                Err(_) => failed += 1,
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }

        let gap = match (last_ok_before, first_ok_after) {
            (Some(a), Some(b)) if b > a => {
                let g = b.duration_since(a).as_nanos() as u64;
                gaps.push(g);
                Some(g)
            }
            _ => None,
        };
        let recovered = first_ok_after.is_some();
        if recovered {
            out.summary.ok_count += 1;
        } else {
            out.summary.error_count += 1;
        }

        mark(&framed, format!("migration:{round}:end")).await;
        out.sink.push(&MigrationSample {
            seq: round,
            leg,
            t_unix_ns: unix_nanos(),
            old_local_addr: None,
            new_local_addr: "0.0.0.0:0".into(),
            migrate_call_ns,
            data_gap_ns: gap,
            failed_rtts: failed,
            recovered,
            state_after: format!("{:?}", framed.session().connection_state()),
            ok: recovered && migrated,
            error: migrate_err,
        });
        conn::close_session(framed.session()).await;
    }

    out.summary.latency_ns = Some(Summary::of_u64(&gaps));
    out.note("migration is a local UDP port rebind: it exercises the full migration path and the server's path-validation challenge, but the external NAT mapping may or may not change, and the client cannot observe which");
    out
}

// ── 10. rekey ───────────────────────────────────────────────────────────────

pub async fn rekey(
    ep: &Endpoints,
    pin: &[u8],
    leg: Leg,
    threshold: u64,
    exchanges: usize,
) -> ScenarioOutput {
    let mut out = ScenarioOutput::new(leg, "rekey");
    let framed = match connect_framed(leg, ep, pin).await {
        Ok(s) => s,
        Err(e) => {
            out.error(leg, "rekey", "connect", &e);
            return out;
        }
    };
    mark(&framed, "rekey:begin").await;

    // Force epochs to rotate every few packets. Waiting for the production
    // REKEY_SOFT_LIMIT of 2^32 invocations is not a test that finishes.
    let applied = framed.session().set_rekey_threshold(threshold).await;
    if !applied {
        out.note(
            "set_rekey_threshold was not applied; epochs will not rotate within this scenario",
        );
    }

    let start_epoch = framed.session().current_epoch().await;
    let mut gen = PayloadGen::new(10);
    let mut rtts = Vec::new();
    let mut bytes = 0u64;

    for seq in 0..exchanges as u64 {
        let payload = gen.fill(512);
        let n = payload.len() as u64;
        match echo_once(&framed, seq, payload).await {
            Ok(o) => {
                bytes += n;
                rtts.push(o.rtt_ns);
                out.summary.ok_count += 1;
                out.sink.push(&RekeySample {
                    leg,
                    seq,
                    t_unix_ns: unix_nanos(),
                    rtt_ns: Some(o.rtt_ns),
                    bytes_sent: bytes,
                    ok: true,
                    error: None,
                });
            }
            Err(e) => {
                out.error(leg, "rekey", "echo", &e);
                out.sink.push(&RekeySample {
                    leg,
                    seq,
                    t_unix_ns: unix_nanos(),
                    rtt_ns: None,
                    bytes_sent: bytes,
                    ok: false,
                    error: Some(format!("{e:?}")),
                });
            }
        }
    }

    let end_epoch = framed.session().current_epoch().await;
    out.summary.latency_ns = Some(Summary::of_u64(&rtts));
    out.note(format!(
        "epoch {start_epoch:?} -> {end_epoch:?} across {exchanges} exchanges at threshold {threshold}"
    ));
    match (start_epoch, end_epoch) {
        (Some(a), Some(b)) if b > a => out.note(format!(
            "{} epoch rotations completed with the session carrying data throughout",
            b - a
        )),
        _ => out.note("no epoch rotation observed — treat continuity here as untested"),
    }

    mark(&framed, "rekey:end").await;
    conn::close_session(framed.session()).await;
    out
}

// ── 11. liveness_soak ───────────────────────────────────────────────────────

pub async fn liveness_soak(
    ep: &Endpoints,
    pin: &[u8],
    leg: Leg,
    duration: Duration,
    interval: Duration,
) -> ScenarioOutput {
    let mut out = ScenarioOutput::new(leg, "liveness_soak");
    let framed = match connect_framed(leg, ep, pin).await {
        Ok(s) => s,
        Err(e) => {
            out.error(leg, "liveness_soak", "connect", &e);
            return out;
        }
    };
    mark(&framed, "liveness_soak:begin").await;

    let started = Instant::now();
    let mut gen = PayloadGen::new(11);
    let mut rtts = Vec::new();
    let mut seq = 0u64;
    let mut states = Vec::new();

    while started.elapsed() < duration {
        let state = format!("{:?}", framed.session().connection_state());
        if states.last().map(|s: &String| s != &state).unwrap_or(true) {
            states.push(state.clone());
        }

        let r = echo_once(&framed, seq, gen.fill(16)).await;
        let (rtt, ok, err) = match r {
            Ok(o) => {
                rtts.push(o.rtt_ns);
                out.summary.ok_count += 1;
                (Some(o.rtt_ns), true, None)
            }
            Err(e) => {
                out.error(leg, "liveness_soak", "echo", &e);
                (None, false, Some(format!("{e:?}")))
            }
        };

        out.sink.push(&SoakSample {
            leg,
            t_unix_ns: unix_nanos(),
            elapsed_s: started.elapsed().as_secs(),
            state,
            rtt_ns: rtt,
            ok,
            error: err,
            metrics: Some(framed.session().metrics_snapshot().into()),
        });

        // A session declared Dead will not recover; recording that and stopping
        // is the finding, and burning the rest of the window on a corpse would
        // only delay the remaining scenarios.
        if framed.session().connection_state()
            == phantom_protocol::api::session::ConnectionState::Dead
        {
            out.note(format!(
                "session reached Dead after {} s — liveness gave up on the path",
                started.elapsed().as_secs()
            ));
            break;
        }

        seq += 1;
        tokio::time::sleep(interval).await;
    }

    out.summary.latency_ns = Some(Summary::of_u64(&rtts));
    out.note(format!(
        "held for {} s across {} probes; state transitions: {}",
        started.elapsed().as_secs(),
        seq,
        states.join(" -> ")
    ));
    mark(&framed, "liveness_soak:end").await;
    conn::close_session(framed.session()).await;
    out
}

// ── 12. concurrency ─────────────────────────────────────────────────────────

pub async fn concurrency(
    ep: &Endpoints,
    pin: &[u8],
    leg: Leg,
    sessions: usize,
    ops_each: usize,
) -> ScenarioOutput {
    let mut out = ScenarioOutput::new(leg, "concurrency");
    let mut handles = Vec::with_capacity(sessions);

    for idx in 0..sessions {
        let ep = ep.clone();
        let pin = pin.to_vec();
        handles.push(tokio::spawn(async move {
            let t0 = Instant::now();
            let framed = match connect_link(leg, &ep, &pin).await {
                Ok(s) => s,
                Err(e) => return (idx, None, Vec::new(), 0u64, Some(format!("{e:?}"))),
            };
            let connect_ns = t0.elapsed().as_nanos() as u64;
            let mut gen = PayloadGen::new(120 + idx as u64);
            let mut rtts = Vec::with_capacity(ops_each);
            let mut err = None;
            for seq in 0..ops_each as u64 {
                match echo_once(framed.as_ref(), seq, gen.fill(128)).await {
                    Ok(o) => rtts.push(o.rtt_ns),
                    Err(e) => {
                        err = Some(format!("{e:?}"));
                        break;
                    }
                }
            }
            let ops = rtts.len() as u64;
            framed.close().await;
            (idx, Some(connect_ns), rtts, ops, err)
        }));
    }

    let mut all_rtts = Vec::new();
    let mut connects = Vec::new();
    for h in handles {
        let Ok((idx, connect_ns, rtts, ops, err)) = h.await else {
            out.summary.error_count += 1;
            continue;
        };
        if let Some(c) = connect_ns {
            connects.push(c);
        }
        let ok = err.is_none() && ops > 0;
        if ok {
            out.summary.ok_count += 1;
        } else {
            out.summary.error_count += 1;
        }
        let median = if rtts.is_empty() {
            None
        } else {
            Some(Summary::of_u64(&rtts).p50 as u64)
        };
        all_rtts.extend_from_slice(&rtts);
        out.sink.push(&ConcurrencySample {
            leg,
            session_index: idx,
            t_unix_ns: unix_nanos(),
            connect_ns,
            rtt_ns: median,
            ops,
            ok,
            error: err,
        });
    }

    let c = Summary::of_u64(&connects);
    out.summary.latency_ns = Some(Summary::of_u64(&all_rtts));
    out.note(format!(
        "{sessions} concurrent sessions; handshake p50 {:.2} ms, p99 {:.2} ms under that load",
        c.p50 / 1e6,
        c.p99 / 1e6
    ));
    out
}

// ── 13. negative ────────────────────────────────────────────────────────────

pub async fn negative(ep: &Endpoints, pin: &[u8], leg: Leg) -> ScenarioOutput {
    let mut out = ScenarioOutput::new(leg, "negative");

    // (a) A pin that does not match must be rejected as a typed identity
    //     mismatch — the single most important guarantee the API makes.
    {
        let mut bad = pin.to_vec();
        if let Some(b) = bad.first_mut() {
            *b ^= 0xFF;
        }
        let t0 = Instant::now();
        let r = connect_leg(leg, ep, &bad).await;
        let observed = match &r {
            Ok(_) => "connected".to_string(),
            Err(e) => error_kind(e),
        };
        let passed = matches!(r, Err(CoreError::ServerIdentityMismatch));
        record_negative(
            &mut out,
            leg,
            "wrong_pin",
            "ServerIdentityMismatch",
            &observed,
            passed,
            t0,
        );
        if let Ok(s) = r {
            conn::close_session(&s).await;
        }
    }

    // (b) A closed port must fail promptly and typed, not hang.
    {
        let mut closed = ep.clone();
        closed.tcp_port = 1;
        closed.udp_port = 1;
        closed.mimic_port = 1;
        let t0 = Instant::now();
        let r = connect_leg(leg, &closed, pin).await;
        let observed = match &r {
            Ok(_) => "connected".to_string(),
            Err(e) => error_kind(e),
        };
        // UDP has no connection refused: an unreachable port surfaces as a
        // timeout, and that is the correct behaviour, not a defect.
        let passed = r.is_err();
        record_negative(
            &mut out,
            leg,
            "closed_port",
            "any typed error, no hang",
            &observed,
            passed,
            t0,
        );
        if let Ok(s) = r {
            conn::close_session(&s).await;
        }
    }

    // (c) Unauthenticated junk at the listener must not disturb it. The
    //     assertion is not "the junk was rejected" — it is that a legitimate
    //     client still completes a handshake afterwards.
    {
        let t0 = Instant::now();
        let flooded = flood_junk(ep, leg).await;
        let after = connect_leg(leg, ep, pin).await;
        let ok = after.is_ok();
        if let Ok(s) = after {
            conn::close_session(&s).await;
        }
        record_negative(
            &mut out,
            leg,
            "junk_flood",
            "listener still serves legitimate clients",
            if ok { "served" } else { "refused" },
            ok,
            t0,
        );
        out.note(format!(
            "sent {flooded} junk payloads before re-testing the listener"
        ));
    }

    out
}

fn record_negative(
    out: &mut ScenarioOutput,
    leg: Leg,
    case: &str,
    expected: &str,
    observed: &str,
    passed: bool,
    t0: Instant,
) {
    if passed {
        out.summary.ok_count += 1;
    } else {
        out.summary.error_count += 1;
        out.note(format!(
            "{case}: expected {expected}, observed {observed} — this is a finding"
        ));
    }
    out.sink.push(&NegativeSample {
        case: case.to_string(),
        leg,
        t_unix_ns: unix_nanos(),
        expected: expected.to_string(),
        observed: observed.to_string(),
        passed,
        elapsed_ns: t0.elapsed().as_nanos() as u64,
    });
}

/// Throw unauthenticated garbage at the listener for the leg under test.
async fn flood_junk(ep: &Endpoints, leg: Leg) -> usize {
    let mut gen = PayloadGen::new(0xBADF00D);
    let mut sent = 0usize;
    match leg {
        Leg::Udp => {
            let Ok(sock) = UdpSocket::bind("0.0.0.0:0").await else {
                return 0;
            };
            let addr = ep.addr_for(Leg::Udp);
            // Sizes chosen around the protocol's own boundaries: shorter than a
            // header, exactly a header, and larger than the measured path MTU.
            for len in [1usize, 8, 15, 16, 64, 1200, 1400] {
                for _ in 0..20 {
                    if sock.send_to(&gen.fill(len), &addr).await.is_ok() {
                        sent += 1;
                    }
                }
            }
        }
        Leg::Tcp | Leg::Mimic => {
            let addr = ep.addr_for(leg);
            for _ in 0..10 {
                let Ok(mut s) = TcpStream::connect(&addr).await else {
                    continue;
                };
                use tokio::io::AsyncWriteExt;
                // A plausible-looking oversized length prefix followed by
                // nothing, then raw noise.
                let _ = s.write_all(&u32::MAX.to_be_bytes()).await;
                let _ = s.write_all(&gen.fill(512)).await;
                let _ = s.shutdown().await;
                sent += 1;
            }
        }
        // The QUIC reference leg is not asked to defend itself: `negative` is a
        // Phantom scenario and the probe skips it there with a note.
        Leg::Quic | Leg::RawTcp | Leg::RawUdp => {}
    }
    sent
}

// ── 14. raw baselines ───────────────────────────────────────────────────────

/// Raw TCP echo round trips, length-prefixed to match `TcpSessionTransport`.
pub async fn raw_tcp_rtt(ep: &Endpoints, sizes: &[usize], per_size: usize) -> ScenarioOutput {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let leg = Leg::RawTcp;
    let mut out = ScenarioOutput::new(leg, "rtt_sweep");

    let addr = ep.addr_for(leg);
    let mut sock =
        match tokio::time::timeout(conn::CONNECT_TIMEOUT, TcpStream::connect(&addr)).await {
            Ok(Ok(s)) => s,
            _ => {
                out.summary.error_count += 1;
                out.note(format!("could not reach the raw TCP control at {addr}"));
                return out;
            }
        };
    let _ = sock.set_nodelay(true);

    let mut gen = PayloadGen::new(140);
    let mut all = Vec::new();
    let mut seq = 0u64;

    for &size in sizes {
        let mut per = Vec::with_capacity(per_size);
        for _ in 0..per_size {
            let payload = gen.fill(size);
            let t0 = Instant::now();
            let io = async {
                sock.write_all(&(size as u32).to_be_bytes()).await?;
                sock.write_all(&payload).await?;
                let mut lb = [0u8; 4];
                sock.read_exact(&mut lb).await?;
                let n = u32::from_be_bytes(lb) as usize;
                let mut back = vec![0u8; n];
                sock.read_exact(&mut back).await?;
                std::io::Result::Ok(back)
            };
            match tokio::time::timeout(OP_TIMEOUT, io).await {
                Ok(Ok(back)) if back == payload => {
                    let rtt = t0.elapsed().as_nanos() as u64;
                    per.push(rtt);
                    all.push(rtt);
                    out.summary.ok_count += 1;
                    out.sink.push(&RttSample {
                        seq,
                        leg,
                        payload_bytes: size,
                        t_unix_ns: unix_nanos(),
                        rtt_ns: rtt,
                        server_recv_unix_ns: None,
                        server_send_unix_ns: None,
                        server_turnaround_ns: None,
                    });
                }
                _ => out.summary.error_count += 1,
            }
            seq += 1;
        }
        if !per.is_empty() {
            let s = Summary::of_u64(&per);
            out.note(format!("{size} B: p50 {:.2} ms", s.p50 / 1e6));
        }
    }

    out.summary.latency_ns = Some(Summary::of_u64(&all));
    out.note("no Phantom: this is the path's own round-trip floor, the denominator for every protocol latency number");
    out
}

/// Ask the kernel for larger socket buffers and report what it granted.
///
/// The grant matters more than the request: operating systems clamp, and a
/// silently clamped buffer is exactly how a control measures itself.
fn set_socket_buffers(sock: &TcpStream, want: usize) -> (usize, usize) {
    use std::os::fd::{AsRawFd, BorrowedFd};
    // SAFETY: the fd is owned by `sock` and outlives the borrow; socket2 only
    // reads and sets options on it, and does not take ownership.
    let borrowed = unsafe { BorrowedFd::borrow_raw(sock.as_raw_fd()) };
    let s2 = socket2::SockRef::from(&borrowed);
    let _ = s2.set_send_buffer_size(want);
    let _ = s2.set_recv_buffer_size(want);
    (
        s2.send_buffer_size().unwrap_or(0),
        s2.recv_buffer_size().unwrap_or(0),
    )
}

/// Raw TCP bulk throughput — the capacity denominator.
///
/// Saturates the length-prefixed echo control while draining it concurrently,
/// so the number is the path's own bidirectional ceiling with no Phantom in the
/// way. Without this, a protocol throughput figure cannot be attributed: a slow
/// result might be the transport or might be the link, and the two are not
/// distinguishable from the protocol leg alone.
pub async fn raw_tcp_throughput(
    ep: &Endpoints,
    cap: Duration,
    frame_size: usize,
) -> ScenarioOutput {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let leg = Leg::RawTcp;
    let mut out = ScenarioOutput::new(leg, "throughput");

    let addr = ep.addr_for(leg);
    let sock = match tokio::time::timeout(conn::CONNECT_TIMEOUT, TcpStream::connect(&addr)).await {
        Ok(Ok(s)) => s,
        _ => {
            out.summary.error_count += 1;
            out.note(format!("could not reach the raw TCP control at {addr}"));
            return out;
        }
    };
    let _ = sock.set_nodelay(true);
    // Size the socket buffers for the bandwidth-delay product. TCP cannot keep
    // more in flight than its send buffer holds, so with the OS default this
    // probe measures `buffer / rtt` — on a 200 ms path a 128 KB default caps it
    // near 5 Mbit/s regardless of the link. An earlier version of this control
    // reported 4.65 Mbit/s as "the path", which was the kernel's default.
    // A few bandwidth-delay products, not "as much as the kernel will give".
    // At 8 MiB on a path that loses 6% at 19 Mbit/s, TCP fills the buffer, the
    // queue becomes the round trip, and the control collapses — it measured
    // 1.34 Mbit/s on a link carrying 9.5. That is bufferbloat, and a control
    // measuring its own queue is no better than one measuring its own timer.
    // 1 MiB is ~3x the product at 9.5 Mbit/s and 250 ms.
    let (snd, rcv) = set_socket_buffers(&sock, 1024 * 1024);
    out.note(format!(
        "socket buffers: send {} KiB, receive {} KiB (asked for 1024 KiB) — this bounds TCP at buffer/RTT, so it must exceed the path's bandwidth-delay product for the number below to mean anything",
        snd / 1024,
        rcv / 1024
    ));
    let (mut rd, mut wr) = sock.into_split();

    let payload = PayloadGen::new(160).fill(frame_size);
    let deadline = tokio::time::Instant::now() + cap;

    // Writer and reader run concurrently: a send-then-receive loop would
    // measure one round trip at a time and report the bandwidth-delay product
    // rather than the link.
    let writer = tokio::spawn(async move {
        let mut sent = 0u64;
        loop {
            if tokio::time::Instant::now() >= deadline {
                break;
            }
            if wr
                .write_all(&(payload.len() as u32).to_be_bytes())
                .await
                .is_err()
                || wr.write_all(&payload).await.is_err()
            {
                break;
            }
            sent += payload.len() as u64;
        }
        let _ = wr.shutdown().await;
        sent
    });

    let mut win = WindowTracker::new(leg, "raw_echo");
    let mut lb = [0u8; 4];
    loop {
        if tokio::time::Instant::now() >= deadline + Duration::from_secs(5) {
            break;
        }
        match tokio::time::timeout(Duration::from_secs(10), rd.read_exact(&mut lb)).await {
            Ok(Ok(_)) => {}
            _ => break,
        }
        let n = u32::from_be_bytes(lb) as usize;
        if n == 0 || n > 4 * 1024 * 1024 {
            break;
        }
        let mut body = vec![0u8; n];
        match tokio::time::timeout(Duration::from_secs(10), rd.read_exact(&mut body)).await {
            Ok(Ok(_)) => {}
            _ => break,
        }
        out.summary.ok_count += 1;
        if let Some(sample) = win.add(n) {
            out.sink.push(&sample);
        }
    }

    let sent = writer.await.unwrap_or(0);
    let tp = win.finish();
    out.note(format!(
        "raw TCP, no Phantom: {} B offered, {} B echoed back in {:.1} s — {:.2} Mbit/s each way",
        sent,
        tp.bytes,
        tp.duration_ns as f64 / 1e9,
        tp.megabits_per_sec
    ));
    out.note("this is the path's own ceiling; every protocol throughput figure should be read against it");
    out.summary.throughput = Some(tp);
    out
}

/// Raw UDP one-way capacity and loss — the datagram denominator.
///
/// Sends at a series of offered rates and counts how much comes back. TCP's
/// control cannot answer this: its congestion control hides where the datagram
/// path actually starts losing, which is exactly what a UDP-based protocol runs
/// into.
pub async fn raw_udp_throughput(ep: &Endpoints, per_rate: Duration) -> ScenarioOutput {
    let leg = Leg::RawUdp;
    let mut out = ScenarioOutput::new(leg, "throughput");

    let Ok(sock) = UdpSocket::bind("0.0.0.0:0").await else {
        out.summary.error_count += 1;
        out.note("could not bind a local UDP socket");
        return out;
    };
    let addr = ep.addr_for(leg);
    if sock.connect(&addr).await.is_err() {
        out.summary.error_count += 1;
        out.note(format!("could not associate with {addr}"));
        return out;
    }
    let sock = Arc::new(sock);

    let payload = PayloadGen::new(170).fill(1200);
    let mut best = 0.0f64;
    let mut ceiling_suspected = false;

    for &kbps in &[1_000u64, 5_000, 20_000, 60_000, 200_000] {
        // Pace in bursts on a 1 ms tick rather than sleeping between frames.
        // A per-frame sleep cannot outrun the timer's granularity: at 1200 B
        // per frame a ~1 ms floor caps the offered rate near 9.6 Mbit/s, so
        // the "path ceiling" such a loop reports is really its own clock. That
        // is exactly what an earlier version of this probe measured.
        const TICK: Duration = Duration::from_millis(1);
        let bytes_per_tick = (kbps * 1000 / 8) / 1000; // bytes per millisecond
        let per_burst = ((bytes_per_tick as usize) / payload.len()).max(1);

        let deadline = tokio::time::Instant::now() + per_rate;
        let rx = sock.clone();
        let reader = tokio::spawn(async move {
            let mut buf = vec![0u8; 65_536];
            let mut got = 0u64;
            let stop = deadline + Duration::from_secs(2);
            while tokio::time::Instant::now() < stop {
                match tokio::time::timeout(Duration::from_millis(500), rx.recv(&mut buf)).await {
                    Ok(Ok(n)) => got += n as u64,
                    Ok(Err(_)) => break,
                    Err(_) => continue,
                }
            }
            got
        });

        let mut sent = 0u64;
        let started = Instant::now();
        let mut tick = tokio::time::interval(TICK);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Burst);
        while tokio::time::Instant::now() < deadline {
            tick.tick().await;
            for _ in 0..per_burst {
                if sock.send(&payload).await.is_ok() {
                    sent += payload.len() as u64;
                }
            }
        }
        let elapsed = started.elapsed().as_secs_f64().max(1e-9);
        let got = reader.await.unwrap_or(0);

        let offered = sent as f64 * 8.0 / elapsed / 1e6;
        let returned = got as f64 * 8.0 / elapsed / 1e6;
        let loss = if sent > 0 {
            100.0 * (1.0 - (got as f64 / sent as f64)).max(0.0)
        } else {
            100.0
        };
        best = best.max(returned);
        out.summary.ok_count += 1;
        out.note(format!(
            "asked {} kbit/s -> actually offered {offered:.2} Mbit/s, echoed back {returned:.2} Mbit/s, round-trip loss {loss:.1}%",
            kbps
        ));
        out.sink.push(&ThroughputSample {
            leg,
            direction: format!("raw_udp_offered_{kbps}kbps"),
            t_unix_ns: unix_nanos(),
            window_bytes: got,
            window_frames: got / payload.len() as u64,
            window_ns: (elapsed * 1e9) as u64,
            cumulative_bytes: sent,
        });

        // Only a rate the sender genuinely reached, met by loss, indicates the
        // path's limit. Falling short of the ask means the *sender* ran out of
        // room, which says nothing about the link.
        if offered >= kbps as f64 / 1000.0 * 0.8 && loss > 2.0 {
            ceiling_suspected = true;
        }
    }

    out.note(format!(
        "best sustained datagram echo: {best:.2} Mbit/s{}",
        if ceiling_suspected {
            " — met loss at a rate the sender did reach, so this is the path"
        } else {
            " — NOT confirmed as the path's limit: no offered rate was both reached and met with loss, so this may still be the sender's own ceiling"
        }
    ));
    out
}

/// Raw UDP echo round trips. Also the direct path-MTU probe.
pub async fn raw_udp_rtt(ep: &Endpoints, sizes: &[usize], per_size: usize) -> ScenarioOutput {
    let leg = Leg::RawUdp;
    let mut out = ScenarioOutput::new(leg, "rtt_sweep");

    let Ok(sock) = UdpSocket::bind("0.0.0.0:0").await else {
        out.summary.error_count += 1;
        out.note("could not bind a local UDP socket");
        return out;
    };
    let addr = ep.addr_for(leg);
    if sock.connect(&addr).await.is_err() {
        out.summary.error_count += 1;
        out.note(format!("could not associate with {addr}"));
        return out;
    }

    let mut gen = PayloadGen::new(150);
    let mut all = Vec::new();
    let mut seq = 0u64;
    let mut buf = vec![0u8; 65_536];

    for &size in sizes {
        let mut per = Vec::with_capacity(per_size);
        let mut lost = 0usize;
        for _ in 0..per_size {
            let payload = gen.fill(size);
            let t0 = Instant::now();
            let ok = if sock.send(&payload).await.is_ok() {
                match tokio::time::timeout(Duration::from_secs(3), sock.recv(&mut buf)).await {
                    Ok(Ok(n)) => n == size && buf[..n] == payload[..],
                    _ => false,
                }
            } else {
                false
            };
            if ok {
                let rtt = t0.elapsed().as_nanos() as u64;
                per.push(rtt);
                all.push(rtt);
                out.summary.ok_count += 1;
                out.sink.push(&RttSample {
                    seq,
                    leg,
                    payload_bytes: size,
                    t_unix_ns: unix_nanos(),
                    rtt_ns: rtt,
                    server_recv_unix_ns: None,
                    server_send_unix_ns: None,
                    server_turnaround_ns: None,
                });
            } else {
                lost += 1;
                out.summary.error_count += 1;
            }
            seq += 1;
        }
        let s = Summary::of_u64(&per);
        out.note(format!(
            "{size} B: {}/{} echoed, p50 {:.2} ms",
            per_size - lost,
            per_size,
            s.p50 / 1e6
        ));
        // A size that loses everything while a smaller one succeeds is the path
        // MTU announcing itself — worth naming explicitly in the artifact.
        if lost == per_size && !all.is_empty() {
            out.note(format!(
                "{size} B never came back while smaller sizes did: the path MTU is below this",
            ));
        }
    }

    out.summary.latency_ns = Some(Summary::of_u64(&all));
    out.note("datagram loss and the size at which it starts are the path's own properties, measured without Phantom in the way");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_tracker_emits_one_sample_per_elapsed_second() {
        let mut w = WindowTracker::new(Leg::Udp, "upload");
        // Nothing emitted before a second has passed.
        for _ in 0..100 {
            assert!(w.add(1000).is_none());
        }
        assert_eq!(w.cumulative, 100_000);
        assert_eq!(w.total_frames, 100);
    }

    #[test]
    fn window_tracker_totals_survive_into_the_summary() {
        let mut w = WindowTracker::new(Leg::Tcp, "download");
        for _ in 0..10 {
            w.add(512);
        }
        let t = w.finish();
        assert_eq!(t.bytes, 5120);
        assert_eq!(t.frames, 10);
        assert!(t.duration_ns > 0);
        assert!(t.megabits_per_sec >= 0.0);
    }

    #[test]
    fn scenario_output_tracks_errors_with_typed_kinds() {
        let mut o = ScenarioOutput::new(Leg::Udp, "demo");
        assert_eq!(o.summary.error_count, 0);
        o.error(Leg::Udp, "demo", "connect", &CoreError::Timeout);
        o.error(Leg::Udp, "demo", "pin", &CoreError::ServerIdentityMismatch);
        assert_eq!(o.summary.error_count, 2);
        assert_eq!(o.errors.len(), 2);
        assert_eq!(o.errors[0].error_kind, "Timeout");
        assert_eq!(o.errors[1].error_kind, "ServerIdentityMismatch");
        assert_eq!(o.file, "demo.jsonl");
    }

    #[test]
    fn negative_records_carry_the_verdict_both_ways() {
        let mut o = ScenarioOutput::new(Leg::Tcp, "negative");
        record_negative(
            &mut o,
            Leg::Tcp,
            "wrong_pin",
            "ServerIdentityMismatch",
            "ServerIdentityMismatch",
            true,
            Instant::now(),
        );
        record_negative(
            &mut o,
            Leg::Tcp,
            "closed_port",
            "typed error",
            "connected",
            false,
            Instant::now(),
        );
        assert_eq!(o.summary.ok_count, 1);
        assert_eq!(o.summary.error_count, 1);
        assert!(
            o.summary
                .notes
                .iter()
                .any(|n| n.contains("this is a finding")),
            "a failed negative case must be called out, not buried in counts"
        );
    }
}
