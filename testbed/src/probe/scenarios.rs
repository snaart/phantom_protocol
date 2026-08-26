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

use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use phantom_protocol::transport::handshake::PROTOCOL_VARIANT;
use phantom_protocol::CoreError;
use tokio::net::{TcpStream, UdpSocket};

use crate::clock::{self, ClockSample};
use crate::framing::{Framed, MsgLink};
use crate::probe::conn::{
    self, connect_framed, connect_leg, connect_leg_resumed, connect_link, connect_link_staged,
    echo_once, error_kind, Endpoints, DRAIN_TIMEOUT, OP_TIMEOUT,
};
use crate::probe::converge;
use crate::probe::relay::{Relay, RelayStats};
use crate::proto::{Msg, PayloadGen};
use crate::report::{
    unix_nanos, BuildId, ClientMetrics, ConcurrencySample, ErrorRecord, HandshakeRepairSample,
    HandshakeSample, Leg, MessageIntegritySample, MigrationSample, NegativeSample, RekeySample,
    RttSample, SampleSink, ScenarioSummary, ServerStats, SoakSample, StreamSample,
    ThroughputSample, TransferReceiptSample, WireCheckSample, ZeroRttSample,
};
use crate::stats::{Summary, Throughput};
use crate::wirecheck::{
    self, filter_for, needles_for, probe_marker, tcpdump_args, Capture, CaptureRequest, Needle,
    Polarity, PROBE_PAYLOAD_BYTES,
};
use crate::{downlink, pacing, uplink};

/// What one scenario produced.
pub struct ScenarioOutput {
    pub file: String,
    pub sink: SampleSink,
    /// Congestion-window time series, written alongside the scenario's own
    /// samples as `<scenario>.window.jsonl`. Kept in its own file because it is
    /// a different record shape sampled on a different clock.
    pub window: SampleSink,
    /// What the receiving side counted for the whole transfer, written as
    /// `<scenario>.receipt.jsonl`. One record per transfer rather than a series,
    /// and it can only be filled once the transfer has been closed and its far
    /// end has reported — so it cannot ride in the per-window rows, which are
    /// already on disk by then.
    pub receipt: SampleSink,
    pub summary: ScenarioSummary,
    pub errors: Vec<ErrorRecord>,
    /// Only `clock_sync` fills this.
    pub clock: Option<crate::report::ClockEstimate>,
    /// The daemon's build, read out of its `STATS` reply.
    ///
    /// Filled by `clock_sync` because it already holds an established session
    /// at the start of every run; opening a second one purely to ask would cost
    /// a post-quantum handshake for one string.
    pub daemon_build: Option<BuildId>,
}

impl ScenarioOutput {
    fn new(leg: Leg, scenario: &str) -> Self {
        Self {
            file: format!("{scenario}.jsonl"),
            sink: SampleSink::new(),
            window: SampleSink::new(),
            receipt: SampleSink::new(),
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
            daemon_build: None,
        }
    }

    fn note(&mut self, s: impl Into<String>) {
        self.summary.notes.push(s.into());
    }

    /// Mark the server's journal for this scenario, filing a mark that did not
    /// land as an error of the run.
    ///
    /// The mark stays best-effort — the scenario runs on either way, and the
    /// measurement never depends on an annotation. What changes is that losing
    /// one is no longer invisible. A pair of marks is what bounds the interval
    /// the daemon's window series is joined against, so a `download:end` that
    /// never arrived leaves an interval with no end and a join with no rows,
    /// and that is indistinguishable from a sender whose window was never
    /// sampled at all. Recording the loss beside the leg, the scenario and the
    /// label turns an unanswerable gap into a one-line fact in `errors.jsonl`.
    async fn mark(&mut self, framed: &dyn MsgLink, label: impl Into<String>) {
        let label = label.into();
        let t0 = Instant::now();
        if let Err(e) = conn::mark(framed, label.clone()).await {
            let leg = self.summary.leg;
            let scenario = self.summary.scenario.clone();
            self.error_after(leg, &scenario, &format!("mark {label}"), &e, t0);
        }
    }

    fn error(&mut self, leg: Leg, scenario: &str, context: &str, e: &CoreError) {
        self.push_error(leg, scenario, context, e, None)
    }

    /// As [`Self::error`], additionally recording how long the failed operation
    /// ran before it failed.
    ///
    /// Preferred wherever the start of the operation is in hand — see
    /// [`ErrorRecord::elapsed_ns`] for why a bare timestamp is not enough to
    /// attribute a `Timeout` to the timer that produced it.
    fn error_after(&mut self, leg: Leg, scenario: &str, context: &str, e: &CoreError, t0: Instant) {
        let took = t0.elapsed().as_nanos().min(u64::MAX as u128) as u64;
        self.error_lasting(leg, scenario, context, e, took)
    }

    /// As [`Self::error_after`], for a caller that measured the duration itself
    /// — a concurrent task, whose own elapsed time is not the elapsed time of
    /// the loop that collects it.
    fn error_lasting(
        &mut self,
        leg: Leg,
        scenario: &str,
        context: &str,
        e: &CoreError,
        took_ns: u64,
    ) {
        self.push_error(leg, scenario, context, e, Some(took_ns))
    }

    fn push_error(
        &mut self,
        leg: Leg,
        scenario: &str,
        context: &str,
        e: &CoreError,
        elapsed_ns: Option<u64>,
    ) {
        self.summary.error_count += 1;
        self.errors.push(ErrorRecord {
            t_unix_ns: unix_nanos(),
            leg: Some(leg),
            scenario: scenario.to_string(),
            context: context.to_string(),
            error: format!("{e:?}"),
            error_kind: error_kind(e),
            elapsed_ns,
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
const SINK_FRAME_OVERHEAD: u64 = crate::framing::LEN_PREFIX as u64 + 1 + 8;

/// Payload bytes a `SINK` gives up to its own verb and sequence number.
///
/// Held back so that a scenario driven at `n` bytes per frame offers `n` bytes
/// of application message, not `n` plus a header. What that costs on the wire is
/// [`sink_wire_bytes`], and the two differ by the length prefix alone.
const SINK_PAYLOAD_HOLDBACK: usize = 1 + 8;

/// What one `SINK` frame driven at `frame_size` costs on the wire.
///
/// The byte-ceiling sweep turns on this arithmetic — both candidate ceilings are
/// stated in wire bytes, and one of them is stated in segments of wire bytes —
/// so it is derived here and pinned against the encoder by a test rather than
/// carried as a remembered constant.
pub fn sink_wire_bytes(frame_size: usize) -> usize {
    crate::framing::LEN_PREFIX + 1 + 8 + frame_size.saturating_sub(SINK_PAYLOAD_HOLDBACK)
}

/// The frame size whose wire form is exactly `segments` application chunks.
///
/// The ARQ send buffer is bounded in segments, and a frame is split into
/// `ceil(wire_bytes / MAX_APP_CHUNK)` of them. A frame that fills its segments
/// exactly is therefore the one that states the buffer's byte ceiling without a
/// remainder, which is what makes a sweep rung's arithmetic exact rather than
/// approximate.
pub fn frame_filling_segments(segments: usize) -> u32 {
    let wire = segments.max(1) * phantom_protocol::transport::mtu::MAX_APP_CHUNK;
    // The inverse of `sink_wire_bytes`: the two differ by the length prefix.
    (wire.saturating_sub(crate::framing::LEN_PREFIX)) as u32
}

/// Outcome of pouring frames into a session until a deadline.
struct PourOutcome {
    frames: u64,
    /// The session refused a frame for longer than an operation budget. Not a
    /// fault — it is the transport applying backpressure, and the point at which
    /// an offered rate stops being offered.
    stalled: bool,
    error: Option<CoreError>,
}

/// Pour frames for `duration` with the congestion-window sampler running over
/// exactly that interval, and stop it with the transfer.
///
/// The pairing is the point, and it is why the two calls are not left to the
/// scenarios. A transfer's teardown asks the peer for its tally and waits, which
/// on a full send buffer takes seconds; sampling through it appends rows where
/// outstanding bytes are collapsing towards zero. Every reading taken over the
/// tail of such a series — where a saturated sender sits, which is the one place
/// a byte ceiling shows — is then partly a reading of the drain. The throughput
/// figure covers the pour interval, so the window series must too.
async fn burst_with_window(
    link: Arc<dyn MsgLink>,
    leg: Leg,
    phase: &str,
    frame_size: usize,
    duration: Duration,
    win: &mut WindowTracker,
    sink: &mut SampleSink,
) -> (PourOutcome, Vec<crate::report::WindowSample>) {
    let recorder = WindowRecorder::start(link.clone(), leg, phase);
    let poured = pour_frames(
        link.as_ref(),
        frame_size,
        Instant::now() + duration,
        win,
        sink,
    )
    .await;
    (poured, recorder.finish().await)
}

/// Offer fixed-size frames as fast as the session will take them, until the
/// deadline.
///
/// Shared by `upload` and by the byte-ceiling sweep so that the two measure the
/// same thing: a rung of the sweep is an upload at a different frame size, and a
/// second copy of this loop would make that sentence false in whichever detail
/// the copies came to differ by.
async fn pour_frames(
    link: &dyn MsgLink,
    frame_size: usize,
    deadline: Instant,
    win: &mut WindowTracker,
    sink: &mut SampleSink,
) -> PourOutcome {
    let mut gen = PayloadGen::new(4);
    let payload = gen.fill(frame_size.saturating_sub(SINK_PAYLOAD_HOLDBACK));
    let mut seq = 0u64;

    while Instant::now() < deadline {
        let wire = crate::framing::encode_framed(&Msg::Sink {
            seq,
            payload: payload.clone(),
        });
        let n = wire.len();
        match tokio::time::timeout(OP_TIMEOUT, link.send_encoded(wire)).await {
            Ok(Ok(())) => {
                if let Some(s) = win.add(n) {
                    sink.push(&s);
                }
            }
            Ok(Err(e)) => {
                return PourOutcome {
                    frames: seq,
                    stalled: false,
                    error: Some(e),
                }
            }
            Err(_) => {
                return PourOutcome {
                    frames: seq,
                    stalled: true,
                    error: None,
                }
            }
        }
        seq += 1;
    }
    PourOutcome {
        frames: seq,
        stalled: false,
        error: None,
    }
}

/// Rolling one-second throughput window.
///
/// Reporting only a run-level average would hide a stall entirely — a 10-second
/// freeze inside a 60-second transfer still yields a respectable-looking mean.
/// A per-second series makes the freeze visible as a hole.
struct WindowTracker {
    leg: Leg,
    /// Owned rather than `&'static str` because the byte-ceiling sweep runs
    /// several transfers within one scenario and each has to be separable in the
    /// per-second series: its direction names the rung's frame size.
    direction: String,
    started: Instant,
    window_start: Instant,
    window_bytes: u64,
    window_frames: u64,
    cumulative: u64,
    total_frames: u64,
}

impl WindowTracker {
    fn new(leg: Leg, direction: impl Into<String>) -> Self {
        let now = Instant::now();
        Self {
            leg,
            direction: direction.into(),
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
                direction: self.direction.clone(),
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
    let t0 = Instant::now();
    let framed = match connect_framed(leg, ep, pin).await {
        Ok(s) => s,
        Err(e) => {
            out.error_after(leg, "clock_sync", "connect", &e, t0);
            return out;
        }
    };
    out.mark(&framed, "clock_sync:begin").await;

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

    // Ask the daemon which build it is while a session is already up. Without
    // this the artifact names only the probe's code, and a comparison between
    // two runs cannot show that the *server* changed — which, for every
    // download figure in the set, is the half that matters.
    out.daemon_build = read_daemon_build(&framed).await;
    match &out.daemon_build {
        Some(b) => out.note(format!("daemon build {} ({})", b.label(), b.version)),
        None => out.note(
            "the daemon did not report its build: this run cannot state which server code produced it",
        ),
    }

    out.summary.latency_ns = Some(Summary::of_u64(&rtts));
    out.mark(&framed, "clock_sync:end").await;
    conn::close_session(framed.session()).await;
    out
}

/// Pull the daemon's build stamp out of a `STATS` reply.
///
/// Best-effort: an older daemon has no such field and a failure here must not
/// cost the run its clock estimate. `None` is recorded as an absence rather
/// than papered over, so the artifact never implies it knows something it does
/// not.
async fn read_daemon_build(framed: &Framed) -> Option<BuildId> {
    let stats = conn::fetch_server_stats(framed).await.ok()?;
    serde_json::from_value(stats.get("build")?.clone()).ok()
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
                out.error_after(leg, "handshake", "connect", &e, t0);
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

// ── 2b. handshake_repair ────────────────────────────────────────────────────

/// The client's first handshake-retransmit interval, and the whole budget it sits in.
///
/// Mirrors `HANDSHAKE_RETRANSMIT_BUDGET` and the `[1 s, 2 s, 4 s, 1 s]` interval walk in
/// `core/src/api/udp_transport.rs` — both `pub(crate)` there, so these are copies rather than
/// imports. That is exactly why every sample carries them as fields: a reader comparing an
/// elapsed connect against the schedule reads the numbers this run was judged by, instead of
/// trusting that a copy made here is still true of the library.
const FIRST_RETRANSMIT: Duration = Duration::from_secs(1);
const RETRANSMIT_BUDGET: Duration = Duration::from_secs(8);

/// Movement in the listener's four repair counters across one attempt.
///
/// `asked` and `answered` are both **per flight**, and that is load-bearing rather than
/// incidental: they are compared with each other, and the listener also publishes the same
/// arrivals per datagram. Reading the per-datagram figure here would put three questions
/// against every answer on today's messages and report a working repair as a broken one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RepairDeltas {
    /// `initial_flights_on_committed_route_total` — the client's repeated flight arriving,
    /// once per flight however many datagrams carried it.
    asked: u64,
    /// `handshake_flight_repeated_total` — an answer going back, also once per flight.
    answered: u64,
    /// `handshake_flight_evicted_total` / `handshake_flight_refused_total` — the two ways
    /// retention fails to cover a session: by running out of budget, and by never arming.
    evicted: u64,
    refused: u64,
}

/// What one attempt established.
#[derive(Debug, Clone, PartialEq, Eq)]
enum RepairVerdict {
    Repaired,
    Inconclusive(String),
    Failed(String),
}

impl RepairVerdict {
    fn label(&self) -> String {
        match self {
            Self::Repaired => "repaired".to_string(),
            Self::Inconclusive(why) => format!("inconclusive: {why}"),
            Self::Failed(why) => format!("failed: {why}"),
        }
    }

    fn is_pass(&self) -> bool {
        matches!(self, Self::Repaired)
    }

    fn is_failure(&self) -> bool {
        matches!(self, Self::Failed(_))
    }
}

/// The rule that separates a pass from a vacuous one, as a function of the facts an attempt
/// produces and nothing else.
///
/// It is a free function so the rule is checkable without a network, and because the rule is
/// the whole scenario: a connect that completed is not evidence unless a flight was actually
/// lost first, and even then it says nothing about *this* mechanism unless the listener
/// recorded both halves — a question arriving and an answer going back. Everything short of
/// that is inconclusive rather than a pass, and inconclusive is not a failure either: the path
/// declining to cooperate is not the protocol misbehaving.
fn classify_repair(swallowed: u64, connected: bool, deltas: Option<RepairDeltas>) -> RepairVerdict {
    if swallowed == 0 {
        return RepairVerdict::Inconclusive(
            "the relay swallowed no flight, so this connect crossed an undamaged path and is \
             evidence about nothing"
                .to_string(),
        );
    }
    if !connected {
        return RepairVerdict::Failed(
            "the connect did not complete after its reply flight was lost — this is the shape a \
             listener with no retained flight produces, a timeout at the client's retransmit \
             budget"
                .to_string(),
        );
    }
    let Some(d) = deltas else {
        return RepairVerdict::Inconclusive(
            "the daemon did not report its counters, so a completed connect cannot be attributed \
             to the repeat rather than to something else"
                .to_string(),
        );
    };
    if d.asked == 0 {
        return RepairVerdict::Inconclusive(
            "the connect completed but the listener recorded no repeated client flight, so \
             whatever carried it was not this mechanism"
                .to_string(),
        );
    }
    if d.answered == 0 {
        return RepairVerdict::Inconclusive(
            "the repeated flight reached the listener and nothing went back, so the retention did \
             not cover this session and the connect completed by some other means"
                .to_string(),
        );
    }
    RepairVerdict::Repaired
}

/// One connect through a local relay, timed end to end, with the relay's account of what it did.
struct RelayConnect {
    outcome: Result<(), CoreError>,
    elapsed_ns: u64,
    stats: Arc<RelayStats>,
}

async fn relay_connect(server: SocketAddr, pin: &[u8], armed: bool) -> RelayConnect {
    let relay = match Relay::spawn(server, armed).await {
        Ok(r) => r,
        Err(e) => {
            return RelayConnect {
                outcome: Err(CoreError::NetworkError(format!("relay setup: {e}"))),
                elapsed_ns: 0,
                stats: Arc::new(RelayStats::default()),
            }
        }
    };

    let t0 = Instant::now();
    let outcome = async {
        let session = phantom_protocol::connect_pinned_udp(
            relay.addr().ip().to_string(),
            relay.addr().port(),
            pin.to_vec(),
        )
        .await?;
        // The handshake has not run yet at this point — see `conn::connect_leg` for what
        // measuring without this wait would report instead. The wait is deliberately the
        // harness's 30 s ceiling and not something tighter: the failure this scenario is
        // watching for is the library's own 8 s retransmit budget expiring, and a shorter wait
        // here would replace that answer with this harness's.
        match tokio::time::timeout(conn::CONNECT_TIMEOUT, session.await_ready()).await {
            Ok(Ok(())) => Ok(session),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(CoreError::Timeout),
        }
    }
    .await;
    let elapsed_ns = t0.elapsed().as_nanos() as u64;
    let stats = relay.stats().clone();

    match outcome {
        Ok(session) => {
            conn::close_session(&session).await;
            RelayConnect {
                outcome: Ok(()),
                elapsed_ns,
                stats,
            }
        }
        Err(e) => RelayConnect {
            outcome: Err(e),
            elapsed_ns,
            stats,
        },
    }
}

/// The listener's own counters, read over a session that is not the one under test.
///
/// `None` where the daemon did not answer or predates the fields. Recorded as an absence
/// rather than as zero, because a counter that was never reported and a counter that did not
/// move are different statements and only one of them is evidence.
async fn server_repair_counters(link: &dyn MsgLink) -> Option<ClientMetrics> {
    let v = conn::fetch_server_stats(link).await.ok()?;
    let stats: ServerStats = serde_json::from_value(v).ok()?;
    Some(stats.metrics)
}

/// Lose exactly one datagram flight of the server's reply, on the real path, and see whether
/// the connect survives it.
///
/// PhantomUDP spends thirteen datagrams on a handshake and six of them are the `ServerHello`
/// — the one flight that, until recently, had no retransmission of its own. The listener now
/// retains the flight it sent and repeats it byte for byte when the same question arrives
/// again. That repair is pinned by the library's own tests and has never been seen working on
/// a real path: four measurement runs across two days produced 76 consecutive successful UDP
/// handshakes and `initial_flights_on_committed_route_total = 0`, because the path did not
/// happen to lose a handshake datagram. Waiting for a lossy day is not a test strategy, so the loss is
/// manufactured — locally, deterministically, and on one flight only — while everything else
/// about the exchange stays real.
///
/// **What this looks like against a listener without the repair, which is the whole point.**
/// The client repeats its flight at 1 s, 3 s and 7 s; the demux routes those repeats by
/// connection id onto a route it has already committed, where a pump that does not parse
/// handshake messages drops them; nothing triggers a second reply. Every attempt therefore
/// ends `failed`, with `ready_ns` at the client's 8 s retransmit budget and `asked_delta`
/// non-zero (the questions did arrive) against `answered_delta` of zero. A reader who sees
/// that shape is looking at the defect this scenario exists to catch, not at a bad path.
///
/// **What a vacuous pass looks like, and why it is not reported as a pass.** If the relay
/// swallows nothing — a run against a leg that does not fragment its reply, a daemon whose
/// message sizes moved — the connect completes exactly as it always does, and a scenario that
/// asserted only on success would report a green result for a mechanism it never exercised.
/// So `swallowed_datagrams` is checked first, and an attempt that lost nothing is
/// `inconclusive` regardless of how well it went. The same rule applies to the counters: a
/// connect that completed while the listener recorded no repeat was carried by something
/// else, and saying so is worth more than claiming the credit.
pub async fn handshake_repair(
    ep: &Endpoints,
    pin: &[u8],
    leg: Leg,
    attempts: usize,
) -> ScenarioOutput {
    // PhantomUDP only, and not by preference. The mechanism is a datagram flight and its
    // repeat; on a byte-pipe leg the handshake rides TCP's own retransmission and no datagram
    // of it can go missing on its own, so there is nothing here to damage.
    if leg != Leg::Udp {
        return skipped(
            leg,
            "handshake_repair",
            "the reply flight and the listener's repeat of it are PhantomUDP's: on a byte-pipe \
             leg the handshake is carried by the stream underneath, which retransmits it, so no \
             single datagram of the reply can be lost and there is nothing for a listener to \
             repeat",
        );
    }

    let mut out = ScenarioOutput::new(leg, "handshake_repair");
    let server = match conn::resolve(ep, leg).await {
        Ok(a) => a,
        Err(e) => {
            out.error(leg, "handshake_repair", "resolve", &e);
            return out;
        }
    };

    // A second session, straight to the daemon, held open across the whole scenario: it is how
    // the listener's counters are read. It deliberately does not go through the relay, because
    // a session on the damaged path could not be relied on to answer while the damage is being
    // done.
    let t0 = Instant::now();
    let control = match connect_framed(leg, ep, pin).await {
        Ok(s) => s,
        Err(e) => {
            out.error_after(leg, "handshake_repair", "control connect", &e, t0);
            return out;
        }
    };
    out.mark(&control, "handshake_repair:begin").await;

    // The denominator, and the instrument's own positive control in one: the same connect
    // through the same relay with the swallow disarmed. It pays the same loopback hop and
    // crosses the same WAN, so the difference between it and an armed attempt is the loss and
    // nothing else — and if it does not complete, nothing measured afterwards is a statement
    // about the protocol.
    let baseline = relay_connect(server, pin, false).await;
    let baseline_ready_ns = match &baseline.outcome {
        Ok(()) => {
            out.note(format!(
                "baseline: the same connect through the same relay with nothing swallowed completed in {:.0} ms",
                baseline.elapsed_ns as f64 / 1e6
            ));
            Some(baseline.elapsed_ns)
        }
        Err(e) => {
            out.error_lasting(
                leg,
                "handshake_repair",
                "baseline connect",
                e,
                baseline.elapsed_ns,
            );
            out.note(
                "the undamaged connect through the relay failed, so every attempt below is a statement about the relay rather than about the protocol",
            );
            None
        }
    };

    let mut repaired_ns = Vec::with_capacity(attempts);
    let (mut passed, mut inconclusive, mut failed) = (0usize, 0usize, 0usize);

    for seq in 0..attempts as u64 {
        let before = server_repair_counters(&control).await;
        let attempt = relay_connect(server, pin, true).await;
        let after = server_repair_counters(&control).await;

        let deltas = match (&before, &after) {
            (Some(b), Some(a)) => Some(RepairDeltas {
                asked: a
                    .initial_flights_on_committed_route_total
                    .saturating_sub(b.initial_flights_on_committed_route_total),
                answered: a
                    .handshake_flight_repeated_total
                    .saturating_sub(b.handshake_flight_repeated_total),
                evicted: a
                    .handshake_flight_evicted_total
                    .saturating_sub(b.handshake_flight_evicted_total),
                refused: a
                    .handshake_flight_refused_total
                    .saturating_sub(b.handshake_flight_refused_total),
            }),
            _ => None,
        };

        let swallowed = attempt.stats.swallowed() as u64;
        let connected = attempt.outcome.is_ok();
        let verdict = classify_repair(swallowed, connected, deltas);

        if let Err(e) = &attempt.outcome {
            out.error_lasting(leg, "handshake_repair", "connect", e, attempt.elapsed_ns);
        }
        if verdict.is_pass() {
            passed += 1;
            out.summary.ok_count += 1;
            repaired_ns.push(attempt.elapsed_ns);
        } else if verdict.is_failure() {
            failed += 1;
        } else {
            inconclusive += 1;
        }

        out.sink.push(&HandshakeRepairSample {
            seq,
            leg,
            t_unix_ns: unix_nanos(),
            swallowed_datagrams: swallowed,
            flight_total_chunks: attempt.stats.flight_chunks(),
            ready_ns: connected.then_some(attempt.elapsed_ns),
            baseline_ready_ns,
            first_retransmit_ns: FIRST_RETRANSMIT.as_nanos() as u64,
            retransmit_budget_ns: RETRANSMIT_BUDGET.as_nanos() as u64,
            asked_delta: deltas.map(|d| d.asked),
            answered_delta: deltas.map(|d| d.answered),
            evicted_delta: deltas.map(|d| d.evicted),
            refused_delta: deltas.map(|d| d.refused),
            server_counters: after,
            ok: verdict.is_pass(),
            verdict: verdict.label(),
            error: attempt.outcome.as_ref().err().map(|e| format!("{e:?}")),
            error_kind: attempt.outcome.as_ref().err().map(error_kind),
        });
    }

    out.note(format!(
        "{attempts} attempt(s): {passed} repaired, {inconclusive} inconclusive, {failed} failed"
    ));
    if passed == 0 && failed == 0 {
        out.note(
            "no attempt lost a flight and completed, so this run has not exercised the reply-flight repair at all — read the per-attempt verdicts before quoting anything about it",
        );
    }

    if !repaired_ns.is_empty() {
        let s = Summary::of_u64(&repaired_ns);
        let median = s.p50 as u64;
        out.summary.latency_ns = Some(s);
        match baseline_ready_ns {
            Some(base) if median > base => out.note(format!(
                "a repaired connect took {:.0} ms against a {:.0} ms undamaged baseline through the same relay — an excess of {:.0} ms. The client repeats its flight after {:.0} ms and abandons the attempt at {:.0} ms, so an excess near the first interval is the listener's repeat carrying the connect, and an excess near the budget is a later retransmit carrying it instead.",
                median as f64 / 1e6,
                base as f64 / 1e6,
                (median - base) as f64 / 1e6,
                FIRST_RETRANSMIT.as_secs_f64() * 1e3,
                RETRANSMIT_BUDGET.as_secs_f64() * 1e3,
            )),
            Some(base) => out.note(format!(
                "a repaired connect took {:.0} ms against a {:.0} ms undamaged baseline, so the loss cost no measurable time in this run and the two cannot be separated on a path this variable",
                median as f64 / 1e6,
                base as f64 / 1e6,
            )),
            None => out.note(format!(
                "a repaired connect took {:.0} ms, but with no undamaged baseline to subtract there is nothing to attribute it to",
                median as f64 / 1e6,
            )),
        }
    }

    out.note(
        "the four counters are the listener's aggregate over every peer it serves, so a delta measured across one attempt could in principle carry another peer's repeat. The independent half of the evidence is the connect completing at all while a flight was swallowed, which on a listener with no retained flight it cannot.",
    );

    out.mark(&control, "handshake_repair:end").await;
    conn::close_session(control.session()).await;
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
    let t0 = Instant::now();
    let framed = match connect_link(leg, ep, pin).await {
        Ok(s) => s,
        Err(e) => {
            out.error_after(leg, "rtt_sweep", "connect", &e, t0);
            return out;
        }
    };
    out.mark(framed.as_ref(), "rtt_sweep:begin").await;

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
    out.mark(framed.as_ref(), "rtt_sweep:end").await;
    framed.close().await;
    out
}

// ── 3b. message_integrity ───────────────────────────────────────────────────

/// Measure whether `PhantomSession` preserves application message boundaries.
///
/// The data pump splits any payload above its internal chunk size
/// (`MAX_APP_CHUNK`, 1156 B) into chunks and writes each as a separate reliable-stream write, so
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
    let t0 = Instant::now();
    let framed = match connect_framed(leg, ep, pin).await {
        Ok(s) => s,
        Err(e) => {
            out.error_after(leg, "message_integrity", "connect", &e, t0);
            return out;
        }
    };
    out.mark(&framed, "message_integrity:begin").await;

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

    out.mark(&framed, "message_integrity:end").await;
    conn::close_session(framed.session()).await;
    out
}

// ── 4. upload ───────────────────────────────────────────────────────────────

pub async fn upload(
    ep: &Endpoints,
    pin: &[u8],
    leg: Leg,
    window: &converge::UploadWindow,
    frame_size: usize,
) -> ScenarioOutput {
    let mut out = ScenarioOutput::new(leg, "upload");
    // First note on the scenario, ahead of any rate it produces: whether this
    // window can hold a convergence decides whether the rate below is a capacity
    // or a convergence time, and the two are not the same number wearing
    // different words.
    out.note(window.note());
    let t0 = Instant::now();
    let framed = match connect_link(leg, ep, pin).await {
        Ok(s) => s,
        Err(e) => {
            out.error_after(leg, "upload", "connect", &e, t0);
            return out;
        }
    };
    out.mark(framed.as_ref(), "upload:begin").await;

    let mut win = WindowTracker::new(leg, "upload");
    let (poured, window_samples) = burst_with_window(
        framed.clone(),
        leg,
        "upload",
        frame_size,
        window.duration,
        &mut win,
        &mut out.sink,
    )
    .await;
    let seq = poured.frames;
    out.summary.ok_count += seq as usize;
    if let Some(e) = &poured.error {
        out.error(leg, "upload", "send", e);
    }

    let local = win.finish();
    out.summary.throughput = Some(local.clone());
    if poured.stalled {
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
    let report = sink_end_and_report(framed.as_ref(), seq, win.cumulative).await;
    // The honest upload figure, in fields, on both branches and before either
    // is read. It is stated below in prose as well, but prose is not a
    // denominator: the leg comparison divides a rate by a control, and until
    // this record existed the only machine-readable rate for this direction was
    // the sending side's own count of how full its own buffer got.
    out.receipt.push(&upload_receipt(leg, &local, &report));
    match report {
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

    note_window(&mut out, &window_samples);
    if let Some(n) = framed.transport_note() {
        out.note(n);
    }
    out.mark(framed.as_ref(), "upload:end").await;
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

/// What the closing report said, as the record an analysis reads.
///
/// Separated from the scenario so that both outcomes are reachable without a
/// network. The branch that matters is the failing one: a transfer whose report
/// never came back still has to leave a receipt, or "this run predates the
/// record" and "this transfer could not be counted" arrive at the reader as the
/// same silence and get described in the words of whichever was guessed.
fn upload_receipt(
    leg: Leg,
    client: &Throughput,
    report: &Result<(u64, u64, u64, u64), (SinkEndFailure, CoreError)>,
) -> TransferReceiptSample {
    match report {
        Ok((frames, bytes, first_ns, last_ns)) => TransferReceiptSample::counted(
            leg,
            "upload",
            client,
            *frames,
            *bytes,
            last_ns.saturating_sub(*first_ns),
        ),
        Err((why, e)) => TransferReceiptSample::uncounted(
            leg,
            "upload",
            client,
            &format!("{}: {e:?}", why.context()),
        ),
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
    let t0 = Instant::now();
    let framed = match connect_link(leg, ep, pin).await {
        Ok(s) => s,
        Err(e) => {
            out.error_after(leg, "download", "connect", &e, t0);
            return out;
        }
    };
    out.mark(framed.as_ref(), "download:begin").await;
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
    out.mark(framed.as_ref(), "download:end").await;
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
    let t0 = Instant::now();
    let framed = match connect_link(leg, ep, pin).await {
        Ok(s) => s,
        Err(e) => {
            out.error_after(leg, "bidir", "connect", &e, t0);
            return out;
        }
    };
    out.mark(framed.as_ref(), "bidir:begin").await;
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
    // Both halves of the exchange have stopped, so the transfer is over and the
    // rest is teardown; a series that keeps sampling through the drain reports
    // outstanding bytes collapsing as though the transfer had ended that way.
    let window_samples = recorder.finish().await;
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

    note_window(&mut out, &window_samples);
    if let Some(n) = framed.transport_note() {
        out.note(n);
    }
    out.mark(framed.as_ref(), "bidir:end").await;
    framed.close().await;
    out
}

// ── 6b. send_ceiling ────────────────────────────────────────────────────────

/// Segments one stream's ARQ send buffer holds outstanding.
///
/// `transport::stream::MAX_PENDING_PACKETS`. It is the one term of this
/// scenario's arithmetic that cannot be read from the library — the constant is
/// `pub(crate)` — so it is stated here once, with its address, and written into
/// every sample so that a reading is against the number this run used rather
/// than against a copy kept in whatever tool is doing the reading.
const SEND_BUFFER_SEGMENTS: u32 = 1024;

/// Which byte ceiling holds a saturated sender, by moving the one term that
/// separates them.
///
/// A sender with everything else out of the way sits against the lower of two
/// bounds: the ARQ send buffer (`MAX_PENDING_PACKETS` **segments**) and the
/// peer's advertised flow-control window (`MAX_SEND_WINDOW` **bytes**). The
/// second was deliberately set just under what the first can hold, so at the
/// frame size the rest of the matrix runs at they are 1.004x apart and no
/// recorded field can say which of them a sender was held by.
///
/// The frame size is what tells them apart, because the buffer's byte figure
/// scales with it and the window's does not. Each rung here is a saturating
/// transfer at one frame size, and the rungs at the two ends are the ones that
/// carry evidence: far below one application chunk the buffer binds by a factor
/// of four, and at an exact multiple of a chunk the peer's window binds by 13%.
/// A rung that settles on its own lower bound makes that bound real; two such
/// rungs, one of each kind, make both real, and the ambiguous middle then
/// follows from arithmetic rather than from a measurement that cannot resolve
/// it. A rung that settles well below its own lower bound is the more
/// interesting outcome: whatever stopped that sender was neither ceiling.
///
/// Each rung runs on a fresh session, so the controller starts from the same
/// place in every one of them — reusing a session would hand the later rungs a
/// bandwidth estimate the earlier ones had to climb to.
pub async fn send_ceiling(
    ep: &Endpoints,
    pin: &[u8],
    leg: Leg,
    frames: &[u32],
    window: &converge::UploadWindow,
) -> ScenarioOutput {
    let mut out = ScenarioOutput::new(leg, "send_ceiling");
    // The rungs run for the upload's window because a rung is an upload: a
    // sender that never saturates never reaches a ceiling, and then the sweep
    // measures the climb instead of the bound.
    out.note(format!(
        "each rung is a saturating transfer at one frame size, over the same window as upload; {}",
        window.note()
    ));
    out.note(format!(
        "the two candidates: the ARQ send buffer, {SEND_BUFFER_SEGMENTS} segments (transport::stream::MAX_PENDING_PACKETS), and the peer's flow-control window, {} B (transport::stream::MAX_SEND_WINDOW); a frame occupies ceil(wire bytes / {} B) segments",
        phantom_protocol::transport::stream::MAX_SEND_WINDOW,
        phantom_protocol::transport::mtu::MAX_APP_CHUNK,
    ));

    for (idx, &frame) in frames.iter().enumerate() {
        let rung = idx.min(u16::MAX as usize) as u16;
        let sample = send_ceiling_rung(ep, pin, leg, rung, frame, window.duration, &mut out).await;
        out.note(rung_reading(&sample));
        out.sink.push(&sample);
    }
    out
}

/// One rung: connect, saturate, and record where the outstanding bytes settled.
async fn send_ceiling_rung(
    ep: &Endpoints,
    pin: &[u8],
    leg: Leg,
    rung: u16,
    frame: u32,
    duration: Duration,
    out: &mut ScenarioOutput,
) -> crate::report::SendCeilingSample {
    let frame_size = frame as usize;
    let wire = sink_wire_bytes(frame_size);
    let chunk = phantom_protocol::transport::mtu::MAX_APP_CHUNK;
    let segments_per_frame = wire.div_ceil(chunk).max(1);
    // The buffer holds whole segments, so a frame that does not fill its last
    // one wastes the remainder — which is why the ceiling is stated in whole
    // frames' worth of bytes rather than in `segments × chunk`.
    let frames_buffered = (SEND_BUFFER_SEGMENTS as usize / segments_per_frame).max(1);
    let arq_buffer_bytes = (frames_buffered * wire) as u64;

    let mut sample = crate::report::SendCeilingSample {
        leg,
        t_unix_ns: unix_nanos(),
        rung,
        frame_bytes: frame,
        wire_frame_bytes: wire as u32,
        segments_per_frame: segments_per_frame as u32,
        send_buffer_segments: SEND_BUFFER_SEGMENTS,
        app_chunk_bytes: chunk as u32,
        arq_buffer_bytes,
        peer_window_bytes: phantom_protocol::transport::stream::MAX_SEND_WINDOW as u64,
        window_ns: 0,
        client_bytes: 0,
        client_frames: 0,
        megabits_per_sec: 0.0,
        server_bytes: None,
        server_frames: None,
        window_samples: 0,
        tail_samples: 0,
        tail_share: converge::PLATEAU_SHARE,
        inflight_tail: Summary::default(),
        cwnd_tail: Summary::default(),
        stalled: false,
        error: None,
    };

    let t0 = Instant::now();
    let link = match connect_link(leg, ep, pin).await {
        Ok(l) => l,
        Err(e) => {
            out.error_after(
                leg,
                "send_ceiling",
                &format!("connect at {frame} B"),
                &e,
                t0,
            );
            sample.error = Some(format!("{e:?}"));
            return sample;
        }
    };

    let phase = format!("send_ceiling:{frame}");
    out.mark(link.as_ref(), format!("{phase}:begin")).await;

    let mut win = WindowTracker::new(leg, phase.clone());
    // The sampler covers the burst and stops with it. The tail statistic below
    // is where a saturated sender sat, and the drain is precisely the interval
    // in which outstanding bytes fall away from whatever bound was holding
    // them — see [`burst_with_window`].
    let (poured, samples) = burst_with_window(
        link.clone(),
        leg,
        &phase,
        frame_size,
        duration,
        &mut win,
        &mut out.sink,
    )
    .await;
    out.summary.ok_count += poured.frames as usize;
    if let Some(e) = &poured.error {
        out.error(leg, "send_ceiling", &format!("send at {frame} B"), e);
        sample.error = Some(format!("{e:?}"));
    }
    sample.stalled = poured.stalled;

    let local = win.finish();
    sample.client_bytes = local.bytes;
    sample.client_frames = local.frames;
    sample.window_ns = local.duration_ns;
    sample.megabits_per_sec = local.megabits_per_sec;

    match sink_end_and_report(link.as_ref(), poured.frames, win.cumulative).await {
        Ok((frames, bytes, _, _)) => {
            sample.server_frames = Some(frames);
            sample.server_bytes = Some(bytes);
        }
        Err((why, e)) => {
            out.error(leg, "send_ceiling", why.context(), &e);
        }
    }

    let (infl, cwnd, taken) = tail_of(&samples, converge::PLATEAU_SHARE);
    sample.window_samples = samples.len();
    sample.tail_samples = taken;
    sample.inflight_tail = infl;
    sample.cwnd_tail = cwnd;
    note_window(out, &samples);

    out.mark(link.as_ref(), format!("{phase}:end")).await;
    link.close().await;
    sample
}

/// Bytes outstanding and congestion window over the last `share` of a window
/// series, plus how many samples that was.
///
/// The tail rather than the whole: every transfer begins with a controller that
/// has no estimate yet, and a distribution taken across that describes the climb.
/// The share is the same quarter a converged transfer's capacity is read over, so
/// the two statements are about the same part of the same transfer.
fn tail_of(samples: &[crate::report::WindowSample], share: f64) -> (Summary, Summary, usize) {
    if samples.is_empty() {
        return (Summary::default(), Summary::default(), 0);
    }
    let want = ((samples.len() as f64 * share).ceil() as usize).clamp(1, samples.len());
    let tail = &samples[samples.len() - want..];
    let infl: Vec<u64> = tail.iter().map(|w| w.inflight_bytes).collect();
    let cwnd: Vec<u64> = tail.iter().map(|w| w.cwnd_bytes).collect();
    (Summary::of_u64(&infl), Summary::of_u64(&cwnd), want)
}

/// The rung restated in one line: its two candidates, which of them is the lower
/// bound at this frame size, and where the outstanding bytes actually settled.
///
/// Deliberately no verdict. Which ceiling the *sweep* shows binding is a reading
/// across rungs, and it lives in `analyze.py` — the tool that re-derives every
/// number in a run from the raw records and is checked by its own self-test. A
/// second implementation of that rule here would be a second definition, and
/// this project has already had two tools disagree about a median on identical
/// data.
fn rung_reading(s: &crate::report::SendCeilingSample) -> String {
    if let Some(e) = &s.error {
        return format!("{} B frames: no reading — {e}", s.frame_bytes);
    }
    let (binding, which) = if s.arq_buffer_bytes <= s.peer_window_bytes {
        (s.arq_buffer_bytes, "send buffer")
    } else {
        (s.peer_window_bytes, "peer window")
    };
    let other = s.arq_buffer_bytes.max(s.peer_window_bytes);
    let reached = if binding > 0 {
        s.inflight_tail.p90 / binding as f64
    } else {
        0.0
    };
    format!(
        "{frame} B frames ({wire} B on the wire, {seg} segment(s) each): send buffer {arq} B, peer window {peer} B — the lower is the {which}, by {sep:.2}x; outstanding bytes over the last quarter p50 {p50:.0} B, p90 {p90:.0} B, max {max:.0} B ({reached:.2} of that bound), congestion window p50 {cwnd:.0} B",
        frame = s.frame_bytes,
        wire = s.wire_frame_bytes,
        seg = s.segments_per_frame,
        arq = s.arq_buffer_bytes,
        peer = s.peer_window_bytes,
        sep = if binding > 0 {
            other as f64 / binding as f64
        } else {
            0.0
        },
        p50 = s.inflight_tail.p50,
        p90 = s.inflight_tail.p90,
        max = s.inflight_tail.max,
        cwnd = s.cwnd_tail.p50,
    )
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
    let t0 = Instant::now();
    let framed = match connect_framed(leg, ep, pin).await {
        Ok(s) => s,
        Err(e) => {
            out.error_after(leg, "streams", "connect", &e, t0);
            return out;
        }
    };
    out.mark(&framed, "streams:begin").await;

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
    out.mark(&framed, "streams:end").await;
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
                out.error_after(leg, "zero_rtt", "cold connect", &e, t0);
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
        let t0 = Instant::now();
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
            Err(e) => out.error_after(leg, "migration", "connect", &e, t0),
        }
        return out;
    }

    let mut gaps = Vec::new();
    for round in 0..rounds as u64 {
        let t0 = Instant::now();
        let framed = match connect_framed(leg, ep, pin).await {
            Ok(s) => s,
            Err(e) => {
                out.error_after(leg, "migration", "connect", &e, t0);
                continue;
            }
        };
        out.mark(&framed, format!("migration:{round}:begin")).await;

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
                out.mark(&framed, format!("migration:{round}:migrate"))
                    .await;
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

        out.mark(&framed, format!("migration:{round}:end")).await;
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
    let t0 = Instant::now();
    let framed = match connect_framed(leg, ep, pin).await {
        Ok(s) => s,
        Err(e) => {
            out.error_after(leg, "rekey", "connect", &e, t0);
            return out;
        }
    };
    out.mark(&framed, "rekey:begin").await;

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

    out.mark(&framed, "rekey:end").await;
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
    let t0 = Instant::now();
    let framed = match connect_framed(leg, ep, pin).await {
        Ok(s) => s,
        Err(e) => {
            out.error_after(leg, "liveness_soak", "connect", &e, t0);
            return out;
        }
    };
    out.mark(&framed, "liveness_soak:begin").await;

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
    out.mark(&framed, "liveness_soak:end").await;
    conn::close_session(framed.session()).await;
    out
}

// ── 12. concurrency ─────────────────────────────────────────────────────────

/// What one of the concurrent sessions did.
///
/// The failure is carried as the typed `CoreError` rather than a formatted
/// string so the join below can file it exactly as every other scenario files a
/// connect failure — with a leg, a context and a stable `error_kind`. Collapsing
/// it to a string at the task boundary is what kept these failures out of the
/// run's error log.
struct ConcurrentAttempt {
    idx: usize,
    connect_ns: Option<u64>,
    rtts: Vec<u64>,
    /// `Some` iff this session did not complete its work: the stage that failed,
    /// the error it failed with, and how long that stage had been running.
    ///
    /// The duration is measured inside the task. Timing the join instead would
    /// report how long the slowest sibling took, which is a different quantity
    /// and would make every failure in a burst look like it lasted as long as
    /// the burst.
    failure: Option<(&'static str, CoreError, u64)>,
}

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
                Err(e) => {
                    return ConcurrentAttempt {
                        idx,
                        connect_ns: None,
                        rtts: Vec::new(),
                        failure: Some(("connect", e, t0.elapsed().as_nanos() as u64)),
                    }
                }
            };
            let connect_ns = t0.elapsed().as_nanos() as u64;
            let mut gen = PayloadGen::new(120 + idx as u64);
            let mut rtts = Vec::with_capacity(ops_each);
            let mut failure = None;
            let ops_started = Instant::now();
            for seq in 0..ops_each as u64 {
                let t_op = Instant::now();
                match echo_once(framed.as_ref(), seq, gen.fill(128)).await {
                    Ok(o) => rtts.push(o.rtt_ns),
                    Err(e) => {
                        failure = Some(("echo", e, t_op.elapsed().as_nanos() as u64));
                        break;
                    }
                }
            }
            // A session that connected and then attempted nothing is not a
            // success: it contributes no round trip to the number this scenario
            // exists to produce, so it is counted and named rather than folded
            // into the ok tally by the absence of an error.
            if failure.is_none() && rtts.is_empty() {
                failure = Some((
                    "echo",
                    CoreError::InternalError("session performed no operations".into()),
                    ops_started.elapsed().as_nanos() as u64,
                ));
            }
            framed.close().await;
            ConcurrentAttempt {
                idx,
                connect_ns: Some(connect_ns),
                rtts,
                failure,
            }
        }));
    }

    let mut all_rtts = Vec::new();
    let mut connects = Vec::new();
    for (idx, h) in handles.into_iter().enumerate() {
        let t_join = Instant::now();
        let a = match h.await {
            Ok(a) => a,
            // A task that did not return at all still cost the run a session.
            // Recording it keeps the error log's count equal to the summary's.
            Err(e) => {
                out.error_after(
                    leg,
                    "concurrency",
                    "join",
                    &CoreError::InternalError(format!("session task {idx} did not return: {e}")),
                    t_join,
                );
                continue;
            }
        };
        if let Some(c) = a.connect_ns {
            connects.push(c);
        }
        let error = match &a.failure {
            Some((context, e, took_ns)) => {
                out.error_lasting(leg, "concurrency", context, e, *took_ns);
                Some(format!("{e:?}"))
            }
            None => {
                out.summary.ok_count += 1;
                None
            }
        };
        let median = if a.rtts.is_empty() {
            None
        } else {
            Some(Summary::of_u64(&a.rtts).p50 as u64)
        };
        all_rtts.extend_from_slice(&a.rtts);
        out.sink.push(&ConcurrencySample {
            leg,
            session_index: a.idx,
            t_unix_ns: unix_nanos(),
            connect_ns: a.connect_ns,
            rtt_ns: median,
            ops: a.rtts.len() as u64,
            ok: a.failure.is_none(),
            error,
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

// ── 14. wire_capture ────────────────────────────────────────────────────────

/// Take a packet capture while driving a session whose application payloads
/// this probe generated, then search the captured bytes for them.
///
/// The search looks for two things at once, and that is the whole design. The
/// payloads must not be there — a hit is plaintext on the wire. The build's
/// `PROTOCOL_VARIANT` tag must be there, because the handshake is signed rather
/// than encrypted and carries it in the clear. Without the second, a clean
/// first result is indistinguishable from a search that could not find anything
/// at all, and [`crate::wirecheck::analyze`] reports that case as a failure
/// rather than a pass.
///
/// Capture is privileged. When this host cannot take one the scenario records a
/// skip with the reason — the same shape the reference leg uses for a missing
/// certificate — because a security check that quietly did not run is worse
/// than one that is plainly absent.
///
/// One thing this cannot reach, and the record says so in full: whether every
/// post-handshake packet carries the `ENCRYPTED` flag. Header protection masks
/// the whole packet header, so no capture can read that field. See
/// [`crate::wirecheck::ENCRYPTED_FLAG_STATEMENT`].
pub async fn wire_capture(
    ep: &Endpoints,
    pin: &[u8],
    leg: Leg,
    interface: &str,
    messages: usize,
    run_dir: &Path,
) -> ScenarioOutput {
    let mut out = ScenarioOutput::new(leg, "wire_capture");

    // Alongside the scenario's own samples, so the raw evidence and the numbers
    // derived from it travel together.
    let pcap_path = run_dir
        .join("samples")
        .join(leg.as_str())
        .join("wire_capture.pcap");

    // Resolve the peer here rather than handing tcpdump a hostname: tcpdump
    // would resolve it itself, possibly to a wider set than the one address the
    // session uses, and would put a DNS lookup on the wire mid-capture.
    let addr = ep.addr_for(leg);
    let Some(peer) = tokio::net::lookup_host(&addr)
        .await
        .ok()
        .and_then(|mut it| it.next())
        .map(|a| a.ip().to_string())
    else {
        record_wire_check(
            &mut out,
            skipped_sample(
                leg,
                String::new(),
                format!("{addr} did not resolve, so no capture filter could be built"),
            ),
        );
        return out;
    };

    let req = CaptureRequest {
        interface: interface.to_string(),
        filter: filter_for(&peer, ep.port_for(leg)),
        path: pcap_path.clone(),
    };
    let command = format!("tcpdump {}", tcpdump_args(&req).join(" "));

    let capture = match Capture::start(&req).await {
        Ok(c) => c,
        Err(why) => {
            record_wire_check(&mut out, skipped_sample(leg, command, why));
            return out;
        }
    };

    // Build every payload before any of them touches the network, so the bytes
    // searched for are exactly the bytes sent rather than a regeneration of
    // them.
    let nonce = unix_nanos();
    let mut gen = PayloadGen::new(nonce);
    let probes: Vec<(String, Vec<u8>)> = (0..messages)
        .map(|i| {
            let marker = probe_marker(nonce, i);
            let mut payload = marker.as_bytes().to_vec();
            payload.extend_from_slice(&gen.fill(PROBE_PAYLOAD_BYTES.saturating_sub(marker.len())));
            (marker, payload)
        })
        .collect();

    let mut needles = needles_for(&probes, PROTOCOL_VARIANT);
    if leg == Leg::Mimic {
        // The mimicry leg's outer TLS ClientHello presents an SNI in the clear.
        // That is the leg's entire purpose and no secret rides in it, so it is
        // recorded either way rather than being made a verdict: its presence is
        // by design and its absence would be a change worth seeing, but neither
        // is a defect.
        needles.push(Needle::new(
            "mimic_sni",
            ep.sni.as_bytes().to_vec(),
            Polarity::Observed,
        ));
    }

    let t0 = Instant::now();
    let framed = match connect_framed(leg, ep, pin).await {
        Ok(f) => f,
        Err(e) => {
            out.error_after(leg, "wire_capture", "connect", &e, t0);
            let _ = capture.finish().await;
            let _ = std::fs::remove_file(&pcap_path);
            record_wire_check(
                &mut out,
                skipped_sample(
                    leg,
                    command,
                    format!(
                        "no session could be established on this leg ({}), so nothing was sent \
                         for the capture to be searched for",
                        error_kind(&e)
                    ),
                ),
            );
            return out;
        }
    };

    // The instant that splits the capture. Taken after `await_ready()` and
    // before the first application byte, on the same host clock the capture is
    // stamped with.
    let established_unix_ns = unix_nanos();
    out.mark(&framed, "wire_capture:established").await;

    let mut echo_ok = 0usize;
    let mut echo_failed = 0usize;
    for (i, (_, payload)) in probes.iter().enumerate() {
        match echo_once(&framed, i as u64, payload.clone()).await {
            Ok(_) => echo_ok += 1,
            Err(e) => {
                echo_failed += 1;
                out.error(leg, "wire_capture", "echo", &e);
            }
        }
    }

    let counters = Some(framed.session().metrics_snapshot().into());
    conn::close_session(framed.session()).await;
    // Let the closing frames land before the capture stops. Without this the
    // tail of the exchange is missing from exactly the phase being searched.
    tokio::time::sleep(Duration::from_millis(300)).await;

    // A capture that was written but could not be read is still evidence about
    // why, so its path is reported whenever the file exists — not only when the
    // analysis got something out of it.
    let (findings, capture_path) = match capture.finish().await {
        Ok(bytes) => (
            match wirecheck::analyze(&bytes, &needles, established_unix_ns) {
                Ok(f) => f,
                Err(e) => {
                    wirecheck::Findings::skipped(format!("the capture could not be read: {e}"))
                }
            },
            Some(pcap_path.display().to_string()),
        ),
        Err(why) => (wirecheck::Findings::skipped(why), None),
    };

    record_wire_check(
        &mut out,
        WireCheckSample {
            leg,
            t_unix_ns: unix_nanos(),
            established_unix_ns,
            probe_messages: probes.len(),
            probe_payload_bytes: PROBE_PAYLOAD_BYTES,
            echo_ok,
            echo_failed,
            capture_command: command,
            capture_path,
            findings,
            session_counters: counters,
        },
    );
    out
}

/// A run where no capture was taken, with the reason that will be recorded.
fn skipped_sample(leg: Leg, command: String, why: String) -> WireCheckSample {
    WireCheckSample {
        leg,
        t_unix_ns: unix_nanos(),
        established_unix_ns: 0,
        probe_messages: 0,
        probe_payload_bytes: PROBE_PAYLOAD_BYTES,
        echo_ok: 0,
        echo_failed: 0,
        capture_command: command,
        capture_path: None,
        findings: wirecheck::Findings::skipped(why),
        session_counters: None,
    }
}

/// Turn one check into its sample record and the notes a reader sees.
///
/// The lines themselves come from [`wirecheck::report_lines`], which the
/// unprivileged loopback runner also renders through, so the same capture reads
/// the same way whoever took it. What is decided here is what the verdict does
/// to the scenario's counts: a pass is an ok, a failure is an error, and a skip
/// is neither — an absence with a stated cause is not a result in either
/// direction.
fn record_wire_check(out: &mut ScenarioOutput, sample: WireCheckSample) {
    match sample.findings.verdict {
        wirecheck::Verdict::Pass => out.summary.ok_count += 1,
        wirecheck::Verdict::Failed => out.summary.error_count += 1,
        wirecheck::Verdict::Skipped => {}
    }
    for line in wirecheck::report_lines(&sample) {
        out.note(line);
    }
    out.sink.push(&sample);
}

// ── 15. raw baselines ───────────────────────────────────────────────────────

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

/// What the raw TCP echo asks the kernel for in each direction.
///
/// Size the socket buffers for the bandwidth-delay product. TCP cannot keep
/// more in flight than its send buffer holds, so with the OS default this probe
/// measures `buffer / rtt` — on a 200 ms path a 128 KB default caps it near
/// 5 Mbit/s regardless of the link, and an earlier version of this control
/// reported 4.65 Mbit/s as "the path", which was the kernel's default.
///
/// A few bandwidth-delay products, not "as much as the kernel will give". At
/// 8 MiB on a path losing 6% at 19 Mbit/s, TCP fills the buffer, the queue
/// becomes the round trip, and the control collapses — it measured 1.34 Mbit/s
/// on a link carrying 9.5. That is bufferbloat, and a control measuring its own
/// queue is no better than one measuring its own timer. 1 MiB is about three
/// times the product at 9.5 Mbit/s and 250 ms.
const TCP_ECHO_SOCKET_BUFFER: usize = 1024 * 1024;

/// A local socket sized for the echo, handed back **before** it has dialled,
/// with the grant the kernel actually gave.
///
/// Unconnected on purpose, and that is the whole point of the function
/// existing. TCP chooses its window scale in the SYN from the receive buffer it
/// holds at that moment, so a size set on an already-connected stream raises
/// the buffer while leaving the advertised window capped by a factor derived
/// from the default — the control then still measures part of its own socket,
/// which is the fault this sizing exists to remove. Returning a socket that has
/// not dialled makes the ordering a property of the type rather than of the
/// order two lines happen to be written in.
///
/// The grant is read here rather than after the connect because an explicit
/// request locks the size: this is both the figure the window scale was chosen
/// from and the figure that persists.
fn prepare_echo_socket(peer: SocketAddr) -> std::io::Result<(tokio::net::TcpSocket, usize, usize)> {
    let sock = match peer {
        SocketAddr::V4(_) => tokio::net::TcpSocket::new_v4()?,
        SocketAddr::V6(_) => tokio::net::TcpSocket::new_v6()?,
    };
    // A refused request is not fatal — the grant below is what the rest of the
    // scenario reasons from, and a clamped or ignored one shows up there.
    let _ = sock.set_send_buffer_size(TCP_ECHO_SOCKET_BUFFER as u32);
    let _ = sock.set_recv_buffer_size(TCP_ECHO_SOCKET_BUFFER as u32);
    let snd = sock.send_buffer_size().unwrap_or(0) as usize;
    let rcv = sock.recv_buffer_size().unwrap_or(0) as usize;
    Ok((sock, snd, rcv))
}

/// How close to a locally-derived ceiling a reading has to sit before it is
/// read as being held there.
///
/// The same bargain `CEILING_PROXIMITY` makes in `analyze.py`: a sender
/// retiring and refilling continuously never sits exactly on a bound, and a
/// threshold tight enough to demand that would never fire.
const TCP_ECHO_CEILING_PROXIMITY: f64 = 0.95;

/// What the raw TCP echo's own sender runs into, and at what rate each of them
/// starts to matter.
///
/// The instrument is a system too, and this control in particular has twice
/// reported itself as the path — first the kernel's default socket buffer,
/// then its own bufferbloat.
/// So the quantities that would produce a third such reading are derived from
/// what the socket actually granted, stated before the transfer runs, and
/// checked against the result after it.
///
/// One bound cannot be sized away and is therefore stated unconditionally: this
/// is an **echo**. Every byte it counts crossed the path twice, both directions
/// share one connection's ack clock, and the daemon turns each frame around in
/// lockstep — so when the return path backs up the daemon stops reading, and
/// the forward direction cannot stay full while the reverse is congested. The
/// figure bounds the two directions together and neither of them alone.
#[derive(Debug, Clone, Copy)]
struct TcpEchoBounds {
    /// The TCP handshake's own round trip, measured on this connection.
    ///
    /// One SYN / SYN-ACK exchange, so it carries the daemon's accept latency as
    /// well as the path and is an estimate rather than a measurement. It is
    /// used for one thing only — turning a buffer size into a rate — and an
    /// estimate is enough for that.
    connect_ns: u64,
    /// What `getsockopt` reported after the request, not what was asked for.
    send_buf: usize,
    recv_buf: usize,
    frame_bytes: usize,
    /// `None` when the option could not be read back. An assumed Nagle setting
    /// is one of the ways a control measures itself, so an unverifiable one is
    /// reported as unknown rather than as off.
    nodelay: Option<bool>,
}

/// What a finished raw TCP echo reading turned out to be sitting on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TcpEchoBound {
    /// The writer never filled even its own send buffer, so the figure is this
    /// client's send loop rather than anything about the path.
    SendLoop,
    /// The reading is at the rate the socket buffer alone permits over the
    /// measured round trip. Raise the buffer and measure again before quoting
    /// it as anything but the buffer.
    SocketBuffer,
    /// Neither local bound accounts for it. That leaves the path, the peer, and
    /// the echo's own turnaround — and the echo still bounds no single
    /// direction.
    NeitherLocal,
    /// The socket refused to report its buffers, so the buffer bound cannot be
    /// ruled in or out and the reading is unattributable.
    Unreadable,
}

impl TcpEchoBounds {
    /// The rate the socket buffers alone permit: what is certainly available,
    /// and what was reported.
    ///
    /// TCP keeps no more outstanding than the smaller of its own send buffer
    /// and its peer's advertised window, and that amount drains once per round
    /// trip, so `buffer / rtt` caps this connection whatever the link carries.
    /// Two figures rather than one because the grant does not mean the same
    /// thing on every system: Linux reports double what was asked for and
    /// spends part of it on socket-buffer overhead rather than on payload,
    /// while macOS reports what it set. Half the reported figure is what is
    /// certainly available, and a verdict is taken against that one so the
    /// check errs towards flagging a buffer-bound reading rather than missing
    /// it.
    ///
    /// Only this side's buffers are visible. The daemon asks for the same size,
    /// so this stands in for the pair; a run where it did not would show as a
    /// reading below this ceiling, which is the safe direction.
    fn buffer_ceiling_bps(&self) -> Option<(f64, f64)> {
        let rtt = self.connect_ns as f64 / 1e9;
        let win = self.send_buf.min(self.recv_buf) as f64;
        if rtt <= 0.0 || win <= 0.0 {
            return None;
        }
        let reported = win * 8.0 / rtt;
        Some((reported / 2.0, reported))
    }

    /// What bounds this sender, stated in the artifact before the transfer runs.
    fn note(&self) -> String {
        let nagle = match self.nodelay {
            Some(true) => "Nagle off, read back from the socket".to_string(),
            Some(false) => {
                "Nagle is ON: the request did not take, and this reading is the algorithm's coalescing, not the path's".to_string()
            }
            None => {
                "Nagle state could not be read back, so it is unknown rather than off".to_string()
            }
        };
        let buffers = match self.buffer_ceiling_bps() {
            Some((low, high)) => format!(
                "socket buffers granted send {} KiB / receive {} KiB against a {:.0} ms connect round trip, so the window alone caps this connection between {:.2} and {:.2} Mbit/s (the lower figure is what is certainly payload; Linux reports twice the request and spends part of it on overhead). A reading at that number is the buffer and not the link — this control once reported the kernel's 128 KiB default as \"the path\", and once its own queue at 8 MiB",
                self.send_buf / 1024,
                self.recv_buf / 1024,
                self.connect_ns as f64 / 1e6,
                low / 1e6,
                high / 1e6,
            ),
            None => format!(
                "socket buffers or the connect round trip could not be read (send {} B, receive {} B, connect {} ns), so the buffer bound cannot be computed and this reading is unattributable",
                self.send_buf, self.recv_buf, self.connect_ns
            ),
        };
        let writes = match self.buffer_ceiling_bps() {
            Some((_, high)) if self.frame_bytes > 0 => format!(
                "; at {} B frames, saturating that ceiling would take {:.0} writes a second on this side and the same number of read-write turnarounds on the daemon's",
                self.frame_bytes,
                high / 8.0 / self.frame_bytes as f64,
            ),
            _ => String::new(),
        };
        format!(
            "what bounds this sender: {buffers}{writes}. {nagle}. And one that no sizing removes — this is an echo, so every byte counted crossed the path twice, both directions ride one connection's ack clock, and the daemon turns each frame around in lockstep, parking its reads whenever the return direction backs up. The number below bounds the two directions together and neither alone, and is not a denominator for any one-way figure"
        )
    }

    /// Which bound, if any, the finished reading turned out to be sitting on.
    ///
    /// `ahead_at_deadline` is how far the writer had run ahead of the echo at
    /// the moment it stopped — everything it had handed to the socket that had
    /// not come back. A writer being metered by the connection is parked on a
    /// full send buffer and so is at least a buffer ahead; a writer that never
    /// filled its own send buffer was metered by its own loop, and then the
    /// figure is this client's and says nothing about the path. Measured at the
    /// deadline rather than at the end, because by the end everything has
    /// drained and the difference is zero either way.
    ///
    /// The send-loop question is asked first: a buffer that never filled cannot
    /// be what limited the rate.
    fn classify(&self, echoed_bps: f64, ahead_at_deadline: u64) -> TcpEchoBound {
        let Some((low, _)) = self.buffer_ceiling_bps() else {
            return TcpEchoBound::Unreadable;
        };
        // Half the reported grant, for the same reason the ceiling uses half:
        // on Linux that is the part of it a payload can occupy.
        if ahead_at_deadline < (self.send_buf / 2) as u64 {
            return TcpEchoBound::SendLoop;
        }
        if echoed_bps >= TCP_ECHO_CEILING_PROXIMITY * low {
            return TcpEchoBound::SocketBuffer;
        }
        TcpEchoBound::NeitherLocal
    }

    /// The verdict as the line a reader sees.
    fn verdict(&self, echoed_bps: f64, ahead_at_deadline: u64) -> String {
        match self.classify(echoed_bps, ahead_at_deadline) {
            TcpEchoBound::SendLoop => format!(
                "what bound it: this side's own send loop. At the deadline the writer was only {ahead_at_deadline} B ahead of the echo, less than half the {} B send buffer it was granted, so it never filled its own socket — the figure is this client's loop and is not evidence about the path",
                self.send_buf
            ),
            TcpEchoBound::SocketBuffer => format!(
                "what bound it: the socket buffer. {:.2} Mbit/s is at or above {:.0}% of the {:.2} Mbit/s the granted window certainly permits over a {:.0} ms round trip, so this reading is the buffer rather than the link — raise it and measure again before quoting the number",
                echoed_bps / 1e6,
                TCP_ECHO_CEILING_PROXIMITY * 100.0,
                self.buffer_ceiling_bps().map_or(0.0, |(low, _)| low) / 1e6,
                self.connect_ns as f64 / 1e6,
            ),
            TcpEchoBound::NeitherLocal => format!(
                "what bound it: neither local bound. The writer was {ahead_at_deadline} B ahead at the deadline, so it was parked on a full socket, and {:.2} Mbit/s is below what the granted window permits — what remains is the path, the peer, and this echo's own turnaround, which are not separable from here",
                echoed_bps / 1e6,
            ),
            TcpEchoBound::Unreadable => {
                "what bound it: cannot say. The socket did not report its buffers or the connect round trip, so the buffer bound is neither ruled in nor out and this reading is unattributable".to_string()
            }
        }
    }
}

/// Raw TCP bulk echo — kernel TCP on this path, both directions at once.
///
/// Saturates the length-prefixed echo while draining it concurrently, so the
/// number is not one round trip at a time. What it is *not* is a denominator,
/// and two separate things make it so.
///
/// It is a **round trip**: every byte counted crossed the path twice, both
/// directions ride one connection's ack clock so each meters the other's
/// acknowledgements, and the daemon turns each frame around in lockstep. A
/// one-way rate is not bounded by a two-way one — on a shared bottleneck the
/// echo gets at most half of what one direction alone gets — so a one-way leg
/// figure coming in above this is expected and is not evidence of an instrument
/// fault.
///
/// And "raw" here means no Phantom, not no protocol. A UDP socket adds nothing
/// to the path, which is what makes the datagram ladders denominators; a TCP
/// socket adds congestion control, reliability and flow control, which are the
/// mechanisms under test. So this figure is what a kernel TCP achieves here — a
/// yardstick of the same kind as the QUIC leg, not a floor beneath a
/// TCP-substrate leg. The one-way capacity every leg's upload and download must
/// be read against is the raw UDP ladder for that direction, which measures the
/// path both substrates ride.
///
/// A real one-way TCP control would need a source port and a sink port on the
/// daemon counting arrivals at the receiving end, one connection per direction
/// so the measured direction's acknowledgements are not queued behind the
/// other's data, and buffers verified by grant at both ends. It would still be
/// a reference and not a control, for the reason in the paragraph above.
pub async fn raw_tcp_throughput(
    ep: &Endpoints,
    cap: Duration,
    frame_size: usize,
) -> ScenarioOutput {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let leg = Leg::RawTcp;
    let mut out = ScenarioOutput::new(leg, "throughput");

    let addr = ep.addr_for(leg);
    // Resolved before anything is timed, so that a slow name lookup does not
    // land in the round trip every buffer figure below is divided by.
    let peer =
        match tokio::time::timeout(conn::CONNECT_TIMEOUT, tokio::net::lookup_host(&addr)).await {
            Ok(Ok(mut it)) => it.next(),
            _ => None,
        };
    let Some(peer) = peer else {
        out.summary.error_count += 1;
        out.note(format!("could not resolve the raw TCP control at {addr}"));
        return out;
    };
    let Ok((prepared, snd, rcv)) = prepare_echo_socket(peer) else {
        out.summary.error_count += 1;
        out.note("could not open a local TCP socket for the raw control");
        return out;
    };
    let dialled = Instant::now();
    let sock = match tokio::time::timeout(conn::CONNECT_TIMEOUT, prepared.connect(peer)).await {
        Ok(Ok(s)) => s,
        _ => {
            out.summary.error_count += 1;
            out.note(format!("could not reach the raw TCP control at {addr}"));
            return out;
        }
    };
    // The handshake is one round trip, and it is the only measurement of the
    // path this scenario makes on its own. Everything that turns a buffer into
    // a rate needs it, and taking it from another scenario would mean quoting a
    // number from a connection this one never had.
    let connect_ns = dialled.elapsed().as_nanos() as u64;
    let nodelay = match sock.set_nodelay(true) {
        // Read back rather than assumed: a request that silently did not take
        // would leave the algorithm's coalescing in the reading.
        Ok(()) => sock.nodelay().ok(),
        Err(_) => Some(false),
    };
    let bounds = TcpEchoBounds {
        connect_ns,
        send_buf: snd,
        recv_buf: rcv,
        frame_bytes: frame_size,
        nodelay,
    };
    out.note(bounds.note());
    let (mut rd, mut wr) = sock.into_split();

    // Published by the reader so the writer can ask, at the instant it stops,
    // how far ahead of the echo it had got. Sampled then and not at the end,
    // because by the end the connection has drained and the answer is zero
    // whatever bound the transfer.
    let echoed = Arc::new(AtomicU64::new(0));

    // Header and payload in one buffer, written once. Two writes with Nagle off
    // put a four-byte segment on the wire ahead of every frame whenever the
    // send buffer had drained, which is the control paying twice the packet
    // rate for its own framing.
    let mut frame = (frame_size as u32).to_be_bytes().to_vec();
    frame.extend_from_slice(&PayloadGen::new(160).fill(frame_size));
    let deadline = tokio::time::Instant::now() + cap;

    // Writer and reader run concurrently: a send-then-receive loop would
    // measure one round trip at a time and report the bandwidth-delay product
    // rather than the link.
    let writer = {
        let echoed = echoed.clone();
        tokio::spawn(async move {
            let mut sent = 0u64;
            loop {
                if tokio::time::Instant::now() >= deadline {
                    break;
                }
                if wr.write_all(&frame).await.is_err() {
                    break;
                }
                sent += frame_size as u64;
            }
            let ahead = sent.saturating_sub(echoed.load(Ordering::Relaxed));
            let _ = wr.shutdown().await;
            (sent, ahead)
        })
    };

    let mut win = WindowTracker::new(leg, "raw_echo");
    // Reused across frames for the same reason the daemon's is: an allocation
    // per frame would sit inside the loop whose rate is being measured.
    let mut body = vec![0u8; frame_size];
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
        if body.len() < n {
            body.resize(n, 0);
        }
        match tokio::time::timeout(Duration::from_secs(10), rd.read_exact(&mut body[..n])).await {
            Ok(Ok(_)) => {}
            _ => break,
        }
        out.summary.ok_count += 1;
        echoed.fetch_add(n as u64, Ordering::Relaxed);
        if let Some(sample) = win.add(n) {
            out.sink.push(&sample);
        }
    }

    let (sent, ahead) = writer.await.unwrap_or((0, 0));
    let tp = win.finish();
    out.note(format!(
        "raw TCP, no Phantom: {} B offered, {} B echoed back in {:.1} s — {:.2} Mbit/s carried in both directions at once",
        sent,
        tp.bytes,
        tp.duration_ns as f64 / 1e9,
        tp.megabits_per_sec
    ));
    out.note(bounds.verdict(tp.megabits_per_sec * 1e6, ahead));
    out.note(
        "this is a round trip and it is kernel TCP: it bounds the two directions together, normalises neither, and a one-way leg figure above it is expected rather than an instrument fault. The one-way denominator for either direction is the raw UDP ladder for that direction",
    );
    out.summary.throughput = Some(tp);
    out
}

/// Raw UDP echo capacity and loss — the datagram denominator, round trip.
///
/// Sends at a series of offered rates and counts how much comes back. TCP's
/// control cannot answer this: its congestion control hides where the datagram
/// path actually starts losing, which is exactly what a UDP-based protocol runs
/// into.
///
/// What it cannot answer is *which direction* lost anything. Every datagram
/// counted here has crossed the path twice, so a shortfall could be either way
/// and the two have different consequences for a protocol. That is
/// [`raw_udp_downstream`]'s job.
///
/// Each datagram carries a sequence number and a send stamp — the daemon echoes
/// bytes and knows nothing about either — so this direction reports the same
/// reorder-distance distribution the downstream control does, in the same
/// record shape. Read as a round trip: a distance measured here bounds the two
/// directions together and neither of them alone.
pub async fn raw_udp_throughput(
    ep: &Endpoints,
    rungs: &[u64],
    per_rate: Duration,
) -> ScenarioOutput {
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

    // The datagram this control sends is unchanged in size and still filler as
    // far as the daemon is concerned — it echoes bytes and keeps no state — but
    // the first 34 of them now carry a sequence number and a send stamp. That
    // is what lets this direction be counted by the same code as the downstream
    // one, and reordering measured only one way sizes nothing for a protocol
    // that has to tolerate it in both.
    let mut payload = PayloadGen::new(170).fill(downlink::DEFAULT_PAYLOAD);
    let run_nonce = unix_nanos() ^ ((std::process::id() as u64) << 40);
    let mut best = 0.0f64;
    let mut ceiling_suspected = false;

    for (i, &kbps) in rungs.iter().enumerate() {
        let rung = i as u16;
        // The shared credit-bucket pacer, driven from a 1 ms tick — the same
        // one the downstream control uses, so the two directions are offering
        // identically shaped traffic and their rungs line up.
        let mut pacer = pacing::Pacer::new(kbps, payload.len());

        let deadline = tokio::time::Instant::now() + per_rate;
        let rx = sock.clone();
        let clock_base = Instant::now();
        let reader = tokio::spawn(async move {
            let mut buf = vec![0u8; 65_536];
            let mut got = 0u64;
            let mut matched_bytes = 0u64;
            let mut tracker = downlink::SeqTracker::new();
            let stop = deadline + Duration::from_secs(2);
            while tokio::time::Instant::now() < stop {
                match tokio::time::timeout(Duration::from_millis(500), rx.recv(&mut buf)).await {
                    Ok(Ok(n)) => {
                        // The byte count stays deliberately unfiltered, because
                        // it is the figure the ladder's own prose and its
                        // throughput sample have always reported and changing
                        // it would break comparison with runs already taken.
                        got += n as u64;
                        let now = Instant::now();
                        if let Some(h) = downlink::EchoHeader::decode(&buf[..n]) {
                            if h.run_nonce == run_nonce
                                && h.rung == rung
                                && tracker
                                    .observe_stamped(h.seq, stamps_at(clock_base, now, h.send_ns))
                            {
                                matched_bytes += n as u64;
                            }
                        }
                    }
                    Ok(Err(_)) => break,
                    Err(_) => continue,
                }
            }
            (got, matched_bytes, tracker)
        });

        let mut sent = 0u64;
        let mut sent_datagrams = 0u64;
        let started = Instant::now();
        let mut tick = tokio::time::interval(pacing::TICK);
        tick.set_missed_tick_behavior(pacing::MISSED_TICK);
        while tokio::time::Instant::now() < deadline {
            tick.tick().await;
            for _ in 0..pacer.on_tick() {
                downlink::EchoHeader {
                    run_nonce,
                    rung,
                    seq: sent_datagrams,
                    // The same zero the reader dates arrivals from, so a
                    // datagram's own two stamps subtract into its round trip.
                    send_ns: clock_base.elapsed().as_nanos() as u64,
                }
                .write_into(&mut payload);
                if sock.send(&payload).await.is_ok() {
                    sent += payload.len() as u64;
                    sent_datagrams += 1;
                }
            }
        }
        let elapsed_ns = started.elapsed().as_nanos() as u64;
        let (got, matched_bytes, tracker) =
            reader.await.unwrap_or((0, 0, downlink::SeqTracker::new()));

        let achieved = pacing::bits_per_sec(sent, elapsed_ns);
        let returned = pacing::bits_per_sec(got, elapsed_ns);
        let reached = pacing::reached_offer(pacer.offered_bps(), achieved);
        let loss = if sent > 0 {
            100.0 * (1.0 - (got as f64 / sent as f64)).max(0.0)
        } else {
            100.0
        };
        best = best.max(returned);
        out.summary.ok_count += 1;
        let profile = tracker.profile();
        out.note(format!(
            "asked {kbps} kbit/s -> sender achieved {:.2} Mbit/s{}, echoed back {:.2} Mbit/s, round-trip loss {loss:.1}%{}",
            achieved / 1e6,
            if reached { "" } else { " (SHORT OF ITS OWN OFFER — this rung says nothing about the path)" },
            returned / 1e6,
            reorder_note(&profile),
        ));
        out.sink.push(&ThroughputSample {
            leg,
            direction: format!("raw_udp_offered_{kbps}kbps"),
            t_unix_ns: unix_nanos(),
            window_bytes: got,
            window_frames: got / payload.len() as u64,
            window_ns: elapsed_ns,
            cumulative_bytes: sent,
        });
        // The same record shape the downstream control writes, so the two
        // directions' reordering can be read side by side rather than by eye
        // across two formats. Everything in it is round-trip: a datagram
        // counted here crossed the path twice, so a distance measured here
        // bounds the sum of the two directions, never either alone.
        out.sink.push(&crate::report::RungSample {
            leg,
            direction: "raw_udp_echo_roundtrip".to_string(),
            t_unix_ns: unix_nanos(),
            rung,
            offered_bps: pacer.offered_bps(),
            payload_bytes: payload.len(),
            requested_ns: per_rate.as_nanos() as u64,
            sender_datagrams: Some(sent_datagrams),
            sender_bytes: Some(sent),
            sender_elapsed_ns: Some(elapsed_ns),
            sender_bps: Some(achieved),
            sender_reached_offer: Some(reached),
            received_datagrams: tracker.received(),
            received_bytes: matched_bytes,
            reordered_datagrams: tracker.reordered(),
            duplicate_datagrams: tracker.duplicates(),
            reorder: profile,
            observed_window_ns: elapsed_ns,
            receiver_bps: pacing::bits_per_sec(matched_bytes, elapsed_ns),
            loss_fraction: tracker.loss_fraction(Some(sent_datagrams)),
            admissible: reached && tracker.received() >= 2,
            note: if reached {
                String::new()
            } else {
                "the sender fell short of its own offer: this rung measures the client, not the path".to_string()
            },
        });

        // Only a rate the sender genuinely reached, met by loss, indicates the
        // path's limit. Falling short of the ask means the *sender* ran out of
        // room, which says nothing about the link.
        if reached && loss > 2.0 {
            ceiling_suspected = true;
        }
    }

    out.note(format!(
        "best sustained datagram echo: {:.2} Mbit/s{}",
        best / 1e6,
        if ceiling_suspected {
            " — met loss at a rate the sender did reach, so this is the path"
        } else {
            " — NOT confirmed as the path's limit: no offered rate was both reached and met with loss, so this may still be the sender's own ceiling"
        }
    ));
    out.note("this is a round trip: a datagram counted here crossed the path twice, so it bounds neither direction on its own — see the downstream scenario for the server → client half");
    out.note("the reorder distances and displacements recorded here are round-trip too: they bound the sum of the two directions, so a transport's reordering tolerance sized against them is sized generously");
    out
}

/// Raw UDP one-way capacity, server → client — the download denominator.
///
/// Every leg reports a `download` figure, and until this scenario existed none
/// of them could be attributed: a run where the protocol under test managed
/// 3.7 Mbit/s downstream and the mature reference managed 2.1 was equally
/// consistent with a slow receive path and with a server uplink of three
/// megabits, and those call for opposite work. This measures the direction
/// directly, with nothing in the way.
///
/// The daemon paces datagrams at each offered rate and afterwards states how
/// many it actually managed; this side counts what arrived. A rung where the
/// sender fell short of its own offer is recorded as such and marked
/// inadmissible, because it measures the sender rather than the link — the same
/// mistake, in the other direction, once had this harness reporting its own
/// timer as a path ceiling.
///
/// Each rung also records how far back and how long after the path brings a
/// late datagram, and splits gap by gap what was reordering from what was loss.
/// A count of reorderings says the path reorders; it does not size a
/// transport's tolerance for it, which is a distance and a duration.
pub async fn raw_udp_downstream(
    ep: &Endpoints,
    rungs: &[u64],
    per_rung: Duration,
) -> ScenarioOutput {
    let leg = Leg::RawUdp;
    let mut out = ScenarioOutput::new(leg, "downstream");

    let Ok(sock) = UdpSocket::bind("0.0.0.0:0").await else {
        out.summary.error_count += 1;
        out.note("could not bind a local UDP socket");
        return out;
    };
    let addr = ep.raw_downstream_addr();
    if sock.connect(&addr).await.is_err() {
        out.summary.error_count += 1;
        out.note(format!("could not associate with {addr}"));
        return out;
    }

    // Distinguishes this run's traffic from a previous probe's on the same
    // port, so a burst that outlived its requester cannot be counted in here.
    let run_nonce = unix_nanos() ^ ((std::process::id() as u64) << 40);
    let mut cookie = [0u8; downlink::COOKIE_LEN];
    let mut best: Option<Throughput> = None;
    let mut buf = vec![0u8; 65_536];
    // Whether anything on the path ever pushed back — the difference between a
    // measured ceiling and a ladder that simply ran out of rungs. A rung counts
    // as pushback if the sender fell short of its own offer (it was the sender
    // that saturated, which is an instrument limit and is recorded as such) or
    // if datagrams went missing (the path dropped them). Without pushback the
    // best rate is a *lower bound* on the path and calling it a ceiling would
    // be the same overclaim the uplink control was once guilty of.
    let mut saw_pushback = false;

    for (i, &kbps) in rungs.iter().enumerate() {
        let rung = i as u16;
        let (sample, reached) = measure_rung(
            &sock,
            &mut buf,
            &mut cookie,
            run_nonce,
            rung,
            kbps,
            per_rung,
            &mut out,
        )
        .await;

        if sample.admissible
            && best
                .as_ref()
                .is_none_or(|b| sample.receiver_bps > b.megabits_per_sec * 1e6)
        {
            // Built from the rung's own arrivals rather than from a rounded
            // rate, so the headline in `summary.json` is recomputable from the
            // JSONL like every other number here.
            best = Some(Throughput::new(
                sample.received_bytes,
                sample.received_datagrams,
                sample.observed_window_ns,
            ));
        }
        // A rung that never reported (`None`) says nothing either way and must
        // not be read as pushback — it is a missing measurement, not a full path.
        if sample.sender_reached_offer == Some(false)
            || sample.loss_fraction.is_some_and(|l| l > 0.001)
        {
            saw_pushback = true;
        }
        out.note(rung_note(&sample));
        out.sink.push(&sample);

        // A daemon that answered nothing at all will answer nothing on the next
        // rung either, and each attempt costs its own timeouts. Say so once and
        // stop rather than spending the ladder discovering it four more times.
        if !reached {
            out.note(format!(
                "the downstream source at {addr} answered nothing — the remaining {} rung(s) were not attempted",
                rungs.len() - i - 1
            ));
            break;
        }
    }

    match &best {
        Some(t) if saw_pushback => {
            out.note(format!(
                "downstream ceiling {:.2} Mbit/s — the path pushed back at or below this rate (loss appeared, or the sender could not reach its own offer), so it is a measured ceiling and every leg's download must be read against it",
                t.megabits_per_sec
            ));
        }
        Some(t) => {
            out.note(format!(
                "downstream carries AT LEAST {:.2} Mbit/s — the ladder ran out of rungs before the path did: nothing was lost and the sender reached every offer, so this is a lower bound, not a ceiling. A download below it is attributable to the transport; a download near it is not yet distinguishable from the path",
                t.megabits_per_sec
            ));
        }
        None => out.note(
            "no rung was admissible: on every rate the daemon either fell short of its own offer or never reported, so this run has NO downstream denominator and its download figures cannot be attributed",
        ),
    }
    out.summary.throughput = best;
    out
}

/// Pair the receiver's own clock with the stamp the datagram carried.
///
/// The two are on unrelated clocks and the tracker never subtracts one from the
/// other; `base` exists only so the receiver's side is a small monotonic number
/// rather than an [`Instant`], which does not subtract into a `u64` on its own.
fn stamps_at(base: Instant, now: Instant, sender_stamp_ns: u64) -> downlink::Stamps {
    downlink::Stamps {
        recv_ns: now.saturating_duration_since(base).as_nanos() as u64,
        send_ns: sender_stamp_ns,
    }
}

/// Prose for one rung, written so the console transcript alone is readable.
///
/// Shared by both one-way ladders. Which end is local differs between them and
/// nothing else does, so the reason an inadmissible rung is inadmissible comes
/// from the rung's own `note` rather than being restated here — restating it
/// once meant every uplink rung the receiver failed to report on was announced
/// as a sender that fell short, which it was not.
fn rung_note(s: &crate::report::RungSample) -> String {
    let offered = s.offered_bps / 1e6;
    let Some(sender) = s.sender_bps else {
        return format!(
            "asked {offered:.0} Mbit/s -> the sender never reported: {} datagrams arrived, but with no sender-side count there is no denominator and this rung is not evidence",
            s.received_datagrams
        );
    };
    let loss = s
        .loss_fraction
        .map(|l| format!("{:.1}%", l * 100.0))
        .unwrap_or_else(|| "unknown".to_string());
    let verdict = if s.admissible {
        String::new()
    } else if s.note.is_empty() {
        " — NOT ADMISSIBLE".to_string()
    } else {
        format!(" — NOT ADMISSIBLE: {}", s.note)
    };
    format!(
        "asked {offered:.0} Mbit/s -> sender achieved {:.2}, receiver saw {:.2} Mbit/s, loss {loss}, reordered {}, duplicated {}{}{verdict}",
        sender / 1e6,
        s.receiver_bps / 1e6,
        s.reordered_datagrams,
        s.duplicate_datagrams,
        reorder_note(&s.reorder),
    )
}

/// The part of a rung's prose that sizes the reordering rather than announcing
/// it. Empty when nothing arrived late, so a clean rung stays one line.
fn reorder_note(r: &crate::downlink::ReorderProfile) -> String {
    if r.late_datagrams == 0 {
        return String::new();
    }
    // An empty distribution means every late arrival fell outside the window,
    // and printing its zeroed percentiles would read as "reordered by nothing"
    // — the opposite of what happened.
    let mut s = if r.distance.count == 0 {
        "; none of them close enough to the highest seen to measure a distance".to_string()
    } else {
        format!(
            "; late by p50 {:.0} / p90 {:.0} / p99 {:.0} / max {:.0} datagrams and p50 {:.1} / p99 {:.1} / max {:.1} ms",
            r.distance.p50,
            r.distance.p90,
            r.distance.p99,
            r.distance.max,
            r.displacement_ns.p50 / 1e6,
            r.displacement_ns.p99 / 1e6,
            r.displacement_ns.max / 1e6,
        )
    };
    // The classification, and — deliberately — what it could not classify.
    s.push_str(&format!(
        "; gaps {} filled / {} lost / {} still open at the end",
        r.gaps_filled, r.gaps_lost, r.gaps_open_at_end
    ));
    if r.late_beyond_horizon > 0 || r.gaps_beyond_horizon > 0 {
        s.push_str(&format!(
            "; {} arrival(s) and {} gap(s) fell outside the {}-datagram window and are unattributed",
            r.late_beyond_horizon, r.gaps_beyond_horizon, r.horizon
        ));
    }
    s
}

/// Drive one rung: ask, collect, and fold both accounts into a record.
///
/// The second half of the return says whether the daemon answered *anything*,
/// which is a different failure from a rung that ran badly and is what lets the
/// ladder abandon an unreachable source instead of timing out five times.
#[allow(clippy::too_many_arguments)]
async fn measure_rung(
    sock: &UdpSocket,
    buf: &mut [u8],
    cookie: &mut [u8; downlink::COOKIE_LEN],
    run_nonce: u64,
    rung: u16,
    kbps: u64,
    per_rung: Duration,
    out: &mut ScenarioOutput,
) -> (crate::report::RungSample, bool) {
    /// Attempts at getting past the return-routability challenge. Two is enough
    /// for the expected case (no cookie yet, or one that just expired); a third
    /// covers a lost request datagram.
    const ATTEMPTS: usize = 3;
    /// How long to wait for the daemon's first datagram before giving up on the
    /// rung. Generous against a ~230 ms path plus the daemon's own scheduling.
    const FIRST_REPLY: Duration = Duration::from_secs(5);
    /// Quiet period after the last datagram that ends a rung early once the
    /// sender's report is in hand.
    const QUIET: Duration = Duration::from_millis(500);
    /// Slack past the rung's own length, covering propagation plus the spaced
    /// copies of the report.
    const TAIL: Duration = Duration::from_secs(3);

    let mut tracker = downlink::SeqTracker::new();
    let mut received_bytes = 0u64;
    let mut first_len = 0u64;
    let mut first_at: Option<Instant> = None;
    let mut last_at: Option<Instant> = None;
    let mut report: Option<downlink::Report> = None;
    // Zero of the receiver's clock for this rung. The reorder displacements are
    // differences within it, so where it starts does not matter — only that it
    // is monotonic and that the sender's stamps are never subtracted from it.
    let clock_base = Instant::now();

    let request = |cookie: [u8; downlink::COOKIE_LEN]| downlink::Request {
        run_nonce,
        cookie,
        rung,
        offered_kbps: kbps.min(u32::MAX as u64) as u32,
        duration_ms: per_rung.as_millis().min(u32::MAX as u128) as u32,
        payload_len: downlink::DEFAULT_PAYLOAD as u16,
    };

    let mut reached_the_daemon = false;

    'attempt: for _ in 0..ATTEMPTS {
        if sock.send(&request(*cookie).encode()).await.is_err() {
            continue;
        }
        let hard_deadline = Instant::now() + per_rung + TAIL;

        loop {
            let budget = if first_at.is_none() {
                FIRST_REPLY.min(hard_deadline.saturating_duration_since(Instant::now()))
            } else {
                hard_deadline.saturating_duration_since(Instant::now())
            };
            if budget.is_zero() {
                break 'attempt;
            }
            let Ok(Ok(n)) = tokio::time::timeout(budget, sock.recv(buf)).await else {
                // Nothing more is coming. If the rung already produced data
                // this is simply its end; if not, retry the request.
                if first_at.is_some() || report.is_some() {
                    break 'attempt;
                }
                continue 'attempt;
            };
            let datagram = &buf[..n];

            if let Some(ch) = downlink::Challenge::decode(datagram) {
                if ch.run_nonce == run_nonce {
                    *cookie = ch.cookie;
                    reached_the_daemon = true;
                    continue 'attempt;
                }
                continue;
            }
            if let Some(h) = downlink::DataHeader::decode(datagram) {
                if h.run_nonce != run_nonce || h.rung != rung {
                    continue;
                }
                reached_the_daemon = true;
                let now = Instant::now();
                if tracker.observe_stamped(h.seq, stamps_at(clock_base, now, h.send_unix_ns)) {
                    received_bytes += n as u64;
                    if first_at.is_none() {
                        first_at = Some(now);
                        first_len = n as u64;
                    }
                }
                last_at = Some(now);
                continue;
            }
            if let Some(r) = downlink::Report::decode(datagram) {
                if r.run_nonce != run_nonce || r.rung != rung {
                    continue;
                }
                reached_the_daemon = true;
                report.get_or_insert(r);
                // Copies of the report follow, and data may still be draining
                // out of the receive queue behind it. Wait out a quiet period
                // rather than cutting the rung short at the first copy.
                let quiet_until = Instant::now() + QUIET;
                while let Some(rest) = quiet_until.checked_duration_since(Instant::now()) {
                    let Ok(Ok(n)) = tokio::time::timeout(rest, sock.recv(buf)).await else {
                        break;
                    };
                    if let Some(h) = downlink::DataHeader::decode(&buf[..n]) {
                        let now = Instant::now();
                        if h.run_nonce == run_nonce
                            && h.rung == rung
                            && tracker
                                .observe_stamped(h.seq, stamps_at(clock_base, now, h.send_unix_ns))
                        {
                            received_bytes += n as u64;
                            last_at = Some(now);
                        }
                    }
                }
                break 'attempt;
            }
        }
    }

    if !reached_the_daemon {
        out.summary.error_count += 1;
    } else {
        out.summary.ok_count += 1;
    }

    // First-to-last arrival, not the whole exchange: the request's round trip
    // and the daemon's start-up are not part of the path's send rate.
    let observed_window_ns = match (first_at, last_at) {
        (Some(a), Some(b)) if b > a => b.duration_since(a).as_nanos() as u64,
        _ => 0,
    };
    // The first datagram's bytes are excluded because they arrived at the start
    // of the window, not during it: `n` datagrams span `n - 1` gaps, and
    // counting all `n` over that span overstates the rate at low counts.
    let receiver_bps =
        pacing::bits_per_sec(received_bytes.saturating_sub(first_len), observed_window_ns);

    let offered_bps = kbps as f64 * 1000.0;
    let sender_bps = report.map(|r| pacing::bits_per_sec(r.bytes, r.elapsed_ns));
    let sender_reached_offer = sender_bps.map(|b| pacing::reached_offer(offered_bps, b));
    let admissible = sender_reached_offer == Some(true) && tracker.received() >= 2;

    let note = if report.is_none() {
        "the sender never reported what it managed, so there is no denominator for this rung"
    } else if sender_reached_offer != Some(true) {
        "the sender fell short of its own offer: this rung measures the daemon, not the path"
    } else if tracker.received() < 2 {
        "too few datagrams arrived to measure an interval"
    } else {
        ""
    };

    let sample = crate::report::RungSample {
        leg: Leg::RawUdp,
        direction: "raw_udp_downstream".to_string(),
        t_unix_ns: unix_nanos(),
        rung,
        offered_bps,
        payload_bytes: downlink::DEFAULT_PAYLOAD,
        requested_ns: per_rung.as_nanos() as u64,
        sender_datagrams: report.map(|r| r.datagrams),
        sender_bytes: report.map(|r| r.bytes),
        sender_elapsed_ns: report.map(|r| r.elapsed_ns),
        sender_bps,
        sender_reached_offer,
        received_datagrams: tracker.received(),
        received_bytes,
        reordered_datagrams: tracker.reordered(),
        duplicate_datagrams: tracker.duplicates(),
        // Taken here, after the rung's tail has drained: it is this call that
        // draws the line between a gap that was still open and one a late
        // arrival filled.
        reorder: tracker.profile(),
        observed_window_ns,
        receiver_bps,
        loss_fraction: tracker.loss_fraction(report.map(|r| r.datagrams)),
        admissible,
        note: note.to_string(),
    };
    (sample, reached_the_daemon)
}

/// Raw UDP one-way capacity, client → server — the upload denominator.
///
/// The mirror of [`raw_udp_downstream`], and it exists because the direction it
/// covers had no control at all. Every campaign this harness has run had to say
/// so in its caveats: the two echoes are round trips, so a byte counted in
/// either crossed the path twice and bounds neither direction alone, and the
/// only one-way control ran the other way. An `upload` figure was therefore
/// quoted against nothing, which is the one thing a protocol number may not be.
///
/// This side paces datagrams at each offered rate and states what it actually
/// managed; the daemon counts what arrived and sends back its own account —
/// arrivals, duplicates, and the same reorder distribution the downstream
/// ladder records. The receiver's account is the honest one: `send()` buffers,
/// so a sender counting its own socket writes is measuring itself.
///
/// A rung where this side fell short of its own offer is marked inadmissible,
/// because it measures the client's scheduler rather than the link. What bounds
/// the client is named in the scenario's own notes rather than left to be
/// discovered — see [`uplink_sender_bound_note`].
pub async fn raw_udp_upstream(ep: &Endpoints, rungs: &[u64], per_rung: Duration) -> ScenarioOutput {
    let leg = Leg::RawUdp;
    let mut out = ScenarioOutput::new(leg, "upstream");

    let Ok(sock) = UdpSocket::bind("0.0.0.0:0").await else {
        out.summary.error_count += 1;
        out.note("could not bind a local UDP socket");
        return out;
    };
    let addr = ep.raw_upstream_addr();
    if sock.connect(&addr).await.is_err() {
        out.summary.error_count += 1;
        out.note(format!("could not associate with {addr}"));
        return out;
    }

    let mut ladder = UplinkLadder::new(sock, downlink::DEFAULT_PAYLOAD);
    out.note(uplink_sender_bound_note(ladder.payload.len(), rungs));

    let mut best: Option<Throughput> = None;
    // Whether anything on the path ever pushed back — the difference between a
    // measured ceiling and a ladder that simply ran out of rungs. Read exactly
    // as the downstream ladder reads it, and for the same reason: without
    // pushback the best rate is a lower bound, and calling it a ceiling is the
    // overclaim this control group exists to prevent.
    let mut saw_pushback = false;

    for (i, &kbps) in rungs.iter().enumerate() {
        let rung = i as u16;
        let (sample, reached) = ladder.measure(rung, kbps, per_rung, &mut out).await;

        if sample.admissible
            && best
                .as_ref()
                .is_none_or(|b| sample.receiver_bps > b.megabits_per_sec * 1e6)
        {
            // Built from the rung's own arrivals rather than from a rounded
            // rate, so the headline in `summary.json` is recomputable from the
            // JSONL like every other number here.
            best = Some(Throughput::new(
                sample.received_bytes,
                sample.received_datagrams,
                sample.observed_window_ns,
            ));
        }
        // A rung the receiver never reported on (`None`) says nothing either
        // way and must not be read as pushback — it is a missing measurement,
        // not a full path.
        if sample.sender_reached_offer == Some(false)
            || sample.loss_fraction.is_some_and(|l| l > 0.001)
        {
            saw_pushback = true;
        }
        out.note(rung_note(&sample));
        out.sink.push(&sample);

        // A sink that answered nothing at all will answer nothing on the next
        // rung either, and each attempt costs its own timeouts. Say so once and
        // stop rather than spending the ladder discovering it four more times.
        if !reached {
            out.note(format!(
                "the uplink sink at {addr} answered nothing — the remaining {} rung(s) were not attempted",
                rungs.len() - i - 1
            ));
            break;
        }
    }

    match &best {
        Some(t) if saw_pushback => {
            out.note(format!(
                "upstream ceiling {:.2} Mbit/s — the path pushed back at or below this rate (loss appeared, or this side could not reach its own offer), so it is a measured ceiling and every leg's upload must be read against it",
                t.megabits_per_sec
            ));
        }
        Some(t) => {
            out.note(format!(
                "upstream carries AT LEAST {:.2} Mbit/s — the ladder ran out of rungs before the path did: nothing was lost and the sender reached every offer, so this is a lower bound, not a ceiling. An upload below it is attributable to the transport; an upload near it is not yet distinguishable from the path",
                t.megabits_per_sec
            ));
        }
        None => out.note(
            "no rung was admissible: on every rate this side either fell short of its own offer or the receiver never reported, so this run has NO upstream denominator and its upload figures cannot be attributed",
        ),
    }
    out.summary.throughput = best;
    out
}

/// What bounds the sender on this ladder, stated in the artifact.
///
/// The instrument is a system too, and both raw controls have at some point
/// measured themselves. The UDP pacer once reported `tokio::time::sleep`'s
/// ~1 ms granularity as the path's ceiling, and the TCP control measured first
/// its own socket buffer and then its own bufferbloat. So this says what the
/// sender runs into and at what rate it starts to matter, derived from the
/// constants rather than remembered.
fn uplink_sender_bound_note(payload_len: usize, rungs: &[u64]) -> String {
    // The rate at which a sender that could not batch within a tick would stop
    // tracking its offer. The credit-bucket pacer does batch, so this is the
    // bound that was removed rather than one that remains — but it is the exact
    // number an earlier version of this harness reported as a path ceiling.
    let one_per_tick = payload_len as f64 * 8.0 / pacing::TICK.as_secs_f64();
    let top = rungs.iter().copied().max().unwrap_or(0);
    let datagrams_per_sec = top as f64 * 125.0 / payload_len as f64;
    format!(
        "what bounds this sender: a {:.0} ms pacing tick, batched, so the timer stops mattering above one datagram per tick ({:.1} Mbit/s at {payload_len} B — the figure a non-batching version of this loop once reported as the path's own); above that the limit is one sendto per datagram, {datagrams_per_sec:.0} a second at the top rung of this ladder, plus whatever the socket's send buffer refuses. Every one of those shows up as a rung short of its own offer, which is recorded per rung and marks it inadmissible — never as a path ceiling",
        pacing::TICK.as_secs_f64() * 1e3,
        one_per_tick / 1e6,
    )
}

/// Consecutive send failures that end an uplink rung early.
///
/// `ENOBUFS` under a saturated uplink is expected and must not abort the
/// measurement — that is the path pushing back and is exactly what the rung is
/// for. A socket that has stopped accepting anything at all is a different
/// thing, and spinning on it would burn the rung's whole window producing
/// nothing. The daemon's own send loop is bounded the same way.
const UPLINK_MAX_SEND_ERRORS: u32 = 256;

/// The client's end of the uplink ladder: one socket, its buffers, and the
/// cookie it earned.
struct UplinkLadder {
    sock: UdpSocket,
    /// Distinguishes this run's traffic from a previous probe's on the same
    /// port, so a rung that outlived its requester cannot be counted in here.
    run_nonce: u64,
    cookie: [u8; downlink::COOKIE_LEN],
    payload: Vec<u8>,
    buf: Vec<u8>,
}

/// What answering a request told us.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Armed {
    /// The sink is counting; send.
    Yes,
    /// The sink declined, and said so rather than going quiet — which is the
    /// whole reason [`uplink::Ready`] exists: silence here would read as a path
    /// that swallowed the rung.
    Declined,
    /// The sink answered — a challenge came back — but never armed the rung.
    NoReady,
    /// Nothing came back at all.
    Silent,
}

/// What one rung actually put on the wire, by this side's own account.
#[derive(Debug, Clone, Copy, Default)]
struct SentRung {
    datagrams: u64,
    bytes: u64,
    elapsed_ns: u64,
}

impl UplinkLadder {
    fn new(sock: UdpSocket, payload_len: usize) -> Self {
        Self {
            sock,
            run_nonce: unix_nanos() ^ ((std::process::id() as u64) << 40),
            cookie: [0u8; downlink::COOKIE_LEN],
            // Deterministic filler of the same shape the other two controls
            // send, so nothing on the path can benefit from compressibility and
            // the three are offering identically shaped traffic.
            payload: PayloadGen::new(180).fill(payload_len),
            buf: vec![0u8; 65_536],
        }
    }

    /// Drive one rung: arm it, pace it, and fold both accounts into a record.
    ///
    /// The second half of the return says whether the sink answered *anything*,
    /// which is a different failure from a rung that ran badly and is what lets
    /// the ladder abandon an unreachable sink instead of timing out five times.
    async fn measure(
        &mut self,
        rung: u16,
        kbps: u64,
        per_rung: Duration,
        out: &mut ScenarioOutput,
    ) -> (crate::report::RungSample, bool) {
        let offered_bps = kbps as f64 * 1000.0;
        let armed = self.arm(rung, kbps, per_rung).await;
        let reached_the_daemon = armed != Armed::Silent;
        if reached_the_daemon {
            out.summary.ok_count += 1;
        } else {
            out.summary.error_count += 1;
        }

        if armed != Armed::Yes {
            let note = match armed {
                Armed::Declined => {
                    "the sink declined to observe this rung, so nothing was sent and nothing about the path can be read from it"
                }
                Armed::NoReady => {
                    "the sink answered the request but never armed the rung, so nothing was sent"
                }
                _ => "the sink never answered the request, so nothing was sent",
            };
            return (
                self.sample(rung, offered_bps, per_rung, SentRung::default(), None, note),
                reached_the_daemon,
            );
        }

        let sent = self.send_rung(rung, kbps, per_rung).await;
        let report = self.collect_report(rung).await;
        (
            self.sample(rung, offered_bps, per_rung, sent, report, ""),
            true,
        )
    }

    /// Ask the sink to start counting, earning a cookie if it has none.
    ///
    /// Nothing is sent until this returns [`Armed::Yes`]. The receiver's ledger
    /// opens the sequence numbers below its first arrival as gaps, so datagrams
    /// that reached the sink before it knew a rung existed would be booked as
    /// loss the path never caused.
    async fn arm(&mut self, rung: u16, kbps: u64, per_rung: Duration) -> Armed {
        /// Attempts at getting a rung armed. Two covers the expected case (no
        /// cookie yet, or one that just expired); a third covers a lost
        /// request or a lost answer.
        const ATTEMPTS: usize = 3;
        /// How long to wait for the sink's answer. Generous against a ~230 ms
        /// path plus the daemon's own scheduling.
        const REPLY: Duration = Duration::from_secs(5);

        // Built from locals rather than from `self`, so the closure holds no
        // borrow while the receive below needs the buffer mutably.
        let run_nonce = self.run_nonce;
        let payload_len = self.payload.len().min(u16::MAX as usize) as u16;
        let request = |cookie: [u8; downlink::COOKIE_LEN]| uplink::Request {
            run_nonce,
            cookie,
            rung,
            offered_kbps: kbps.min(u32::MAX as u64) as u32,
            duration_ms: per_rung.as_millis().min(u32::MAX as u128) as u32,
            payload_len,
        };

        let mut heard = false;
        for _ in 0..ATTEMPTS {
            if self
                .sock
                .send(&request(self.cookie).encode())
                .await
                .is_err()
            {
                continue;
            }
            let deadline = Instant::now() + REPLY;
            loop {
                let budget = deadline.saturating_duration_since(Instant::now());
                if budget.is_zero() {
                    break;
                }
                let Ok(Ok(n)) = tokio::time::timeout(budget, self.sock.recv(&mut self.buf)).await
                else {
                    break;
                };
                let datagram = &self.buf[..n];
                if let Some(ch) = uplink::Challenge::decode(datagram) {
                    if ch.run_nonce == self.run_nonce {
                        self.cookie = ch.cookie;
                        heard = true;
                        break;
                    }
                    continue;
                }
                if let Some(r) = uplink::Ready::decode(datagram) {
                    if r.run_nonce != self.run_nonce || r.rung != rung {
                        continue;
                    }
                    return if r.accepted {
                        Armed::Yes
                    } else {
                        Armed::Declined
                    };
                }
                // A late report from the previous rung, or something else
                // entirely. Neither answers this question.
            }
        }
        // A challenge is an answer: the sink is reachable and simply never
        // armed the rung. Silence is a different finding and the ladder acts on
        // it differently, so the two do not collapse into one verdict.
        if heard {
            Armed::NoReady
        } else {
            Armed::Silent
        }
    }

    /// Pace one rung at the offered rate for its bounded interval.
    async fn send_rung(&mut self, rung: u16, kbps: u64, per_rung: Duration) -> SentRung {
        let mut pacer = pacing::Pacer::new(kbps, self.payload.len());
        let mut tick = tokio::time::interval(pacing::TICK);
        tick.set_missed_tick_behavior(pacing::MISSED_TICK);

        let started = Instant::now();
        let deadline = tokio::time::Instant::now() + per_rung;
        let mut sent = SentRung::default();
        let mut consecutive_errors = 0u32;

        'rung: while tokio::time::Instant::now() < deadline {
            tick.tick().await;
            for _ in 0..pacer.on_tick() {
                if tokio::time::Instant::now() >= deadline {
                    break 'rung;
                }
                uplink::DataHeader {
                    run_nonce: self.run_nonce,
                    rung,
                    seq: sent.datagrams,
                    send_unix_ns: unix_nanos(),
                }
                .write_into(&mut self.payload);
                match self.sock.send(&self.payload).await {
                    Ok(n) => {
                        consecutive_errors = 0;
                        sent.datagrams += 1;
                        sent.bytes += n as u64;
                    }
                    Err(_) => {
                        consecutive_errors += 1;
                        if consecutive_errors >= UPLINK_MAX_SEND_ERRORS {
                            break 'rung;
                        }
                    }
                }
            }
        }
        sent.elapsed_ns = started.elapsed().as_nanos() as u64;
        sent
    }

    /// Wait for the receiver's account of the rung just sent.
    async fn collect_report(&mut self, rung: u16) -> Option<uplink::Report> {
        /// Slack past the rung's own length for the account to come back: the
        /// sink holds its window open for its grace period, then spaces four
        /// copies of the report.
        const WAIT: Duration = Duration::from_secs(6);

        let deadline = Instant::now() + WAIT;
        loop {
            let budget = deadline.saturating_duration_since(Instant::now());
            if budget.is_zero() {
                return None;
            }
            let Ok(Ok(n)) = tokio::time::timeout(budget, self.sock.recv(&mut self.buf)).await
            else {
                return None;
            };
            if let Some(r) = uplink::Report::decode(&self.buf[..n]) {
                if r.run_nonce == self.run_nonce && r.rung == rung {
                    return Some(r);
                }
            }
        }
    }

    /// Fold this side's account and the receiver's into one record.
    fn sample(
        &self,
        rung: u16,
        offered_bps: f64,
        per_rung: Duration,
        sent: SentRung,
        report: Option<uplink::Report>,
        note: &str,
    ) -> crate::report::RungSample {
        let sender_bps = pacing::bits_per_sec(sent.bytes, sent.elapsed_ns);
        let reached = pacing::reached_offer(offered_bps, sender_bps);
        let received_datagrams = report.as_ref().map(|r| r.received_datagrams).unwrap_or(0);

        // The first arrival's bytes are excluded because they landed at the
        // start of the window rather than during it: `n` datagrams span `n - 1`
        // gaps, and counting all `n` over that span overstates the rate at low
        // counts. The same arithmetic the downstream ladder does, on figures
        // the receiver measured.
        let receiver_bps = report
            .as_ref()
            .map(|r| {
                pacing::bits_per_sec(
                    r.received_bytes.saturating_sub(r.first_datagram_bytes),
                    r.observed_window_ns,
                )
            })
            .unwrap_or(0.0);

        // Same precedence as the downstream ladder's, with the sides swapped:
        // the far end's account is the one that can go missing, and without it
        // nothing else about the rung can be said.
        let note = if !note.is_empty() {
            note
        } else if report.is_none() {
            "the receiver never reported what it saw, so there is no account of this rung but this side's own — and a sender's account of an upload is not one"
        } else if !reached {
            "this side fell short of its own offer: the rung measures the client, not the path"
        } else if received_datagrams < 2 {
            "too few datagrams arrived to measure an interval"
        } else {
            ""
        };

        crate::report::RungSample {
            leg: Leg::RawUdp,
            direction: "raw_udp_upstream".to_string(),
            t_unix_ns: unix_nanos(),
            rung,
            offered_bps,
            payload_bytes: self.payload.len(),
            requested_ns: per_rung.as_nanos() as u64,
            // On this ladder the sender is local, so its account is always
            // known — the optional half of the record is the receiver's, and it
            // is the one that can go missing. The downstream ladder holds the
            // same pair the other way round.
            sender_datagrams: Some(sent.datagrams),
            sender_bytes: Some(sent.bytes),
            sender_elapsed_ns: Some(sent.elapsed_ns),
            sender_bps: Some(sender_bps),
            sender_reached_offer: Some(reached),
            received_datagrams,
            received_bytes: report.as_ref().map(|r| r.received_bytes).unwrap_or(0),
            reordered_datagrams: report.as_ref().map(|r| r.reordered_datagrams).unwrap_or(0),
            duplicate_datagrams: report.as_ref().map(|r| r.duplicate_datagrams).unwrap_or(0),
            reorder: report
                .as_ref()
                .map(|r| r.reorder.clone())
                .unwrap_or_default(),
            observed_window_ns: report.as_ref().map(|r| r.observed_window_ns).unwrap_or(0),
            receiver_bps,
            // Without the receiver's count there is no numerator, and reading
            // the zero above as "nothing arrived" would report a rung nobody
            // observed as a path that swallowed it whole.
            loss_fraction: report
                .as_ref()
                .and_then(|r| downlink::loss_fraction(r.received_datagrams, Some(sent.datagrams))),
            admissible: reached && report.is_some() && received_datagrams >= 2,
            note: note.to_string(),
        }
    }
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
    use phantom_protocol::crypto::hybrid_sign::HybridSigningKey;

    use super::*;
    use crate::framing::testing::ScriptedLink;

    /// Endpoints whose Phantom ports are all closed on loopback, so a connect
    /// fails for a reason the test controls and without a network.
    fn closed_endpoints() -> Endpoints {
        Endpoints {
            host: "127.0.0.1".into(),
            tcp_port: 1,
            udp_port: 1,
            mimic_port: 1,
            quic_port: 1,
            raw_tcp_port: 1,
            raw_udp_port: 1,
            raw_udp_down_port: 1,
            raw_udp_up_port: 1,
            sni: "www.example.com".into(),
            quic_cert: None,
        }
    }

    /// A well-formed pin for an identity no listener holds. Well-formed matters:
    /// a malformed one is refused before the connect is attempted, which would
    /// exercise argument validation instead of the connect path.
    fn unused_pin() -> Vec<u8> {
        let (_sk, vk) = HybridSigningKey::generate();
        vk.to_bytes()
    }

    /// A raw TCP echo whose buffers and round trip are the ones this control
    /// asks for on a real path: 1 MiB granted, 240 ms, 1024 B frames.
    fn tcp_echo_bounds() -> TcpEchoBounds {
        TcpEchoBounds {
            connect_ns: 240_000_000,
            send_buf: 1024 * 1024,
            recv_buf: 1024 * 1024,
            frame_bytes: 1024,
            nodelay: Some(true),
        }
    }

    /// The buffer ceiling is the arithmetic that catches this control measuring
    /// its own socket, so it has to be the arithmetic and not a description of
    /// it: the window drains once per round trip, and half the reported grant
    /// is the part a payload can certainly occupy.
    #[test]
    fn the_buffer_ceiling_is_the_window_over_the_measured_round_trip() {
        let b = tcp_echo_bounds();
        let (low, high) = b.buffer_ceiling_bps().expect("both figures readable");
        assert!(
            (high - (1024.0 * 1024.0 * 8.0 / 0.240)).abs() < 1.0,
            "reported ceiling is buffer/rtt, got {high}"
        );
        assert!(
            (low - high / 2.0).abs() < 1.0,
            "the certain half, got {low}"
        );

        // A socket that reported nothing leaves the bound neither ruled in nor
        // out, which is a different answer from "the buffer was not it".
        let unreadable = TcpEchoBounds { send_buf: 0, ..b };
        assert!(unreadable.buffer_ceiling_bps().is_none());
        assert_eq!(
            unreadable.classify(1e6, 4 * 1024 * 1024),
            TcpEchoBound::Unreadable
        );
        let no_rtt = TcpEchoBounds { connect_ns: 0, ..b };
        assert!(no_rtt.buffer_ceiling_bps().is_none());
    }

    /// The three readings this control can produce, and which one each is. The
    /// send-loop case is asked first on purpose: a buffer that never filled
    /// cannot be what held the rate down, and answering "socket buffer" there
    /// would send the next campaign to raise a buffer that was never touched.
    #[test]
    fn a_finished_echo_reading_names_the_bound_it_sat_on() {
        let b = tcp_echo_bounds();
        let (low, _) = b.buffer_ceiling_bps().expect("readable");

        // Parked on a full socket and well under the window's ceiling: nothing
        // local accounts for it. This is the shape of the readings that started
        // this — 2.32 Mbit/s against a 17 Mbit/s window ceiling.
        assert_eq!(
            b.classify(2.32e6, 2 * 1024 * 1024),
            TcpEchoBound::NeitherLocal
        );

        // At the window ceiling: the buffer, not the link.
        assert_eq!(b.classify(low, 2 * 1024 * 1024), TcpEchoBound::SocketBuffer);
        assert_eq!(
            b.classify(low * TCP_ECHO_CEILING_PROXIMITY, 2 * 1024 * 1024),
            TcpEchoBound::SocketBuffer
        );

        // Never filled its own send buffer: the figure is this client's loop,
        // and it stays that answer even at a rate that would otherwise read as
        // buffer-bound.
        assert_eq!(b.classify(2.32e6, 1024), TcpEchoBound::SendLoop);
        assert_eq!(b.classify(low, 1024), TcpEchoBound::SendLoop);
    }

    /// The instrument is a system too. Every reading this control can produce
    /// has to carry the sentence that stops it being read as a one-way
    /// denominator, because that reading is the one it has invited twice — and
    /// the verdict has to name a bound in every case, including the case where
    /// it cannot name one.
    #[test]
    fn the_echo_states_what_bounds_it_before_and_after_it_runs() {
        let b = tcp_echo_bounds();
        let note = b.note();
        assert!(note.contains("what bounds this sender"), "{note}");
        assert!(note.contains("socket buffers granted"), "{note}");
        assert!(note.contains("Nagle off"), "{note}");
        assert!(
            note.contains("crossed the path twice") && note.contains("lockstep"),
            "the bound no sizing removes must be named: {note}"
        );
        assert!(
            note.contains("not a denominator for any one-way figure"),
            "{note}"
        );

        for (bps, ahead, want) in [
            (2.32e6, 2 * 1024 * 1024, "neither local bound"),
            (20.0e6, 2 * 1024 * 1024, "the socket buffer"),
            (2.32e6, 1024, "this side's own send loop"),
        ] {
            let v = b.verdict(bps, ahead);
            assert!(v.contains(want), "wanted {want:?} in {v}");
        }
        let blind = TcpEchoBounds { send_buf: 0, ..b };
        assert!(
            blind.verdict(2.32e6, 0).contains("cannot say"),
            "an unreadable socket must not be reported as a measured bound"
        );

        // A request that did not take must be visible in the note, because the
        // reading would then be the algorithm's coalescing.
        let nagling = TcpEchoBounds {
            nodelay: Some(false),
            ..b
        };
        assert!(nagling.note().contains("Nagle is ON"), "{}", nagling.note());
        let unknown = TcpEchoBounds { nodelay: None, ..b };
        assert!(
            unknown.note().contains("unknown rather than off"),
            "an unverifiable setting is not a verified one: {}",
            unknown.note()
        );
    }

    /// The socket has to be sized before it dials, and the request has to be
    /// shown to have done something.
    ///
    /// Both halves matter. The ordering is what the buffer request is *for*:
    /// TCP fixes its window scale from the receive buffer it holds when it
    /// builds the SYN, so a size set afterwards raises the buffer and leaves
    /// the advertised window capped by a factor taken from the default. And the
    /// effect is asserted against this machine's own unconfigured default,
    /// which is the positive control such a check needs: an assertion that
    /// the grant is "large" would pass on a system that grants that much
    /// anyway, and would then be evidence of nothing.
    #[tokio::test]
    async fn the_echos_socket_is_sized_before_it_dials() {
        let peer: std::net::SocketAddr = "127.0.0.1:9".parse().expect("literal address");

        let plain = tokio::net::TcpSocket::new_v4().expect("a bare socket");
        let default_snd = plain.send_buffer_size().expect("readable") as usize;
        let default_rcv = plain.recv_buffer_size().expect("readable") as usize;

        // The returned socket is a `TcpSocket`, which `connect` consumes by
        // value to produce a `TcpStream`. So a caller cannot hold this and have
        // already dialled it: the ordering is carried by the signature, and
        // what is left for a test to establish is that the request took.
        let (_sized, snd, rcv) = prepare_echo_socket(peer).expect("a sized socket");

        assert!(
            snd >= default_snd && rcv >= default_rcv,
            "the request must never shrink the buffer: got {snd}/{rcv} against a default of {default_snd}/{default_rcv}"
        );
        assert!(
            snd > default_snd || default_snd >= TCP_ECHO_SOCKET_BUFFER,
            "the send request had no effect and the default was already below it: {snd} against {default_snd}, asking {TCP_ECHO_SOCKET_BUFFER}"
        );
        assert!(
            rcv > default_rcv || default_rcv >= TCP_ECHO_SOCKET_BUFFER,
            "the receive request had no effect and the default was already below it: {rcv} against {default_rcv}, asking {TCP_ECHO_SOCKET_BUFFER}"
        );
    }

    /// End to end against the daemon's own echo, on loopback: the control has
    /// to carry its sender's bounds and its round-trip disclaimer into the
    /// notes a reader actually sees, not merely be able to render them.
    ///
    /// Loopback is the right place for this and the wrong place for the number:
    /// what is asserted is the shape of the record and that the echo returns
    /// bytes at all under the single-write framing both ends now use. The rate
    /// on a microsecond path is not a measurement of anything and is not
    /// asserted.
    #[tokio::test]
    async fn the_raw_tcp_echo_records_its_own_bounds_and_refuses_to_be_a_denominator() {
        use crate::testd::baseline::{serve_tcp, BaselineStats};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let stats = Arc::new(BaselineStats::default());
        let s = stats.clone();
        tokio::spawn(async move {
            let _ = serve_tcp(listener, s).await;
        });

        let ep = Endpoints {
            raw_tcp_port: port,
            ..closed_endpoints()
        };
        let out = raw_tcp_throughput(&ep, Duration::from_millis(300), 1024).await;
        let notes = out.summary.notes.join("\n");

        assert_eq!(out.summary.error_count, 0, "{notes}");
        assert!(
            out.summary.ok_count > 0,
            "the echo returned nothing: {notes}"
        );
        assert!(
            stats.tcp_frames.load(std::sync::atomic::Ordering::Relaxed) > 0,
            "the daemon side counted no frames: {notes}"
        );
        assert!(notes.contains("what bounds this sender"), "{notes}");
        assert!(notes.contains("what bound it:"), "{notes}");
        assert!(
            notes.contains("carried in both directions at once"),
            "the headline must not read as a per-direction rate: {notes}"
        );
        assert!(
            notes.contains("normalises neither"),
            "a control that does not bound a direction has to say so: {notes}"
        );
        assert!(
            notes.contains("one-way leg figure above it is expected"),
            "the inversion this control produces must be pre-empted, not left to be read as a fault: {notes}"
        );
    }

    /// The frame arithmetic the byte-ceiling sweep rests on has to be the
    /// encoder's, not a description of it. Both ceilings are stated in wire
    /// bytes, and one of them in segments of wire bytes, so a frame that is one
    /// byte off the encoder puts a rung on the wrong side of a segment boundary.
    #[test]
    fn a_frames_wire_cost_is_taken_from_the_encoder_and_not_described() {
        for frame in [64usize, 256, 1024, 2308, 4620] {
            let mut gen = PayloadGen::new(4);
            let wire = crate::framing::encode_framed(&Msg::Sink {
                seq: 0,
                payload: gen.fill(frame.saturating_sub(SINK_PAYLOAD_HOLDBACK)),
            });
            assert_eq!(
                sink_wire_bytes(frame),
                wire.len(),
                "the sweep's arithmetic disagrees with the encoder at {frame} B"
            );
        }
    }

    /// A rung whose wire frame fills its segments exactly is what makes the send
    /// buffer's byte ceiling an exact figure rather than one with a remainder,
    /// and the remainder is the whole margin the sweep works in.
    #[test]
    fn a_frame_sized_to_fill_segments_fills_them_exactly() {
        let chunk = phantom_protocol::transport::mtu::MAX_APP_CHUNK;
        for segments in 1..=4usize {
            let frame = frame_filling_segments(segments) as usize;
            let wire = sink_wire_bytes(frame);
            assert_eq!(wire, segments * chunk, "{segments} segments");
            assert_eq!(
                wire.div_ceil(chunk),
                segments,
                "no partial trailing segment"
            );
        }
        // And the two ends of a sweep must actually separate the ceilings: far
        // below a chunk the send buffer binds, at a whole multiple of one the
        // peer's window does. A ladder where both ends fell on the same side
        // would run for the same wall clock and settle nothing.
        let peer = phantom_protocol::transport::stream::MAX_SEND_WINDOW as u64;
        let small = sink_wire_bytes(256) as u64 * SEND_BUFFER_SEGMENTS as u64;
        assert!(small * 3 < peer, "a small frame must bind on the buffer");
        let big_frames = SEND_BUFFER_SEGMENTS as u64 / 2;
        let big = big_frames * sink_wire_bytes(frame_filling_segments(2) as usize) as u64;
        assert!(
            big > peer,
            "a two-segment frame must bind on the peer window"
        );
    }

    /// The tail statistic is where a saturated sender sits. Taken over the whole
    /// series it would describe the climb, which is the error the whole
    /// convergence work exists to stop.
    #[test]
    fn the_tail_statistic_covers_the_last_quarter_and_nothing_earlier() {
        let series: Vec<crate::report::WindowSample> = (0..20)
            .map(|i| window_row(i, if i < 15 { 1000 } else { 500_000 }))
            .collect();

        let (infl, cwnd, taken) = tail_of(&series, 0.25);
        assert_eq!(taken, 5, "a quarter of twenty samples");
        assert_eq!(infl.min, 500_000.0, "nothing from the climb may enter it");
        assert_eq!(infl.p50, 500_000.0);
        assert_eq!(cwnd.count, 5);

        // Degenerate shapes must not panic or report a tail they did not have.
        assert_eq!(tail_of(&[], 0.25).2, 0);
        assert_eq!(
            tail_of(&series[..1], 0.25).2,
            1,
            "one sample is its own tail"
        );
    }

    /// The rung's line has to name both candidates, which is lower, and where
    /// the bytes settled — but never which one the sweep shows binding. That is
    /// a reading across rungs and lives in one place, `analyze.py`, because two
    /// implementations of one definition have already disagreed here.
    #[test]
    fn a_rungs_line_states_both_candidates_and_claims_no_verdict() {
        let mut s = ceiling_sample(256);
        s.inflight_tail = Summary::of_u64(&[260_000, 264_000, 266_000]);
        s.cwnd_tail = Summary::of_u64(&[900_000]);

        let line = rung_reading(&s);
        assert!(line.contains("send buffer 266240 B"), "{line}");
        assert!(line.contains("peer window 1048576 B"), "{line}");
        assert!(line.contains("the lower is the send buffer"), "{line}");
        assert!(
            line.contains("3.94x"),
            "the separation must be stated: {line}"
        );
        for banned in ["binds", "bound by", "verdict"] {
            assert!(
                !line.contains(banned),
                "a single rung must not claim the sweep's reading: {line}"
            );
        }

        // A rung that could not run says so instead of reporting zeroes as a
        // measurement of a sender that sent nothing.
        let mut failed = ceiling_sample(256);
        failed.error = Some("Timeout".into());
        assert!(rung_reading(&failed).contains("no reading"));
    }

    /// A rung driven at a frame larger than one application chunk states the
    /// buffer's ceiling in whole frames, because the buffer holds whole segments
    /// and a frame that straddles two of them cannot be half-buffered.
    #[test]
    fn the_buffer_ceiling_is_whole_frames_of_whole_segments() {
        let two = ceiling_sample(frame_filling_segments(2));
        assert_eq!(two.segments_per_frame, 2);
        assert_eq!(
            two.arq_buffer_bytes,
            (SEND_BUFFER_SEGMENTS as u64 / 2) * two.wire_frame_bytes as u64
        );
        assert!(
            two.arq_buffer_bytes > two.peer_window_bytes,
            "at this frame the peer's window is the lower bound — that is the point of the rung"
        );
    }

    /// A window row with the two fields the tail statistic reads.
    fn window_row(i: u64, inflight: u64) -> crate::report::WindowSample {
        crate::report::WindowSample {
            leg: Leg::Udp,
            phase: "send_ceiling:256".into(),
            t_unix_ns: 1_000_000_000 + i * 200_000_000,
            elapsed_ms: i * 200,
            cwnd_bytes: 2_000_000,
            inflight_bytes: inflight,
            bottleneck_bw_bps: 1_000_000,
            last_delivery_rate_bps: 1_000_000,
            bw_filter_window_ms: 10_000,
            pacing_rate_bps: 1_000_000,
            min_rtt_us: 200_000,
            drain_outcomes: Vec::new(),
            smoothed_rtt_us: 0,
            rtt_variation_us: 0,
            delivered_bytes: i * 100_000,
            state: "probe_bw".into(),
            app_limited: false,
            // Not read by the tail statistic under test; zero rather than a
            // plausible-looking figure, so nothing here can be mistaken for a
            // fixture the assertions depend on.
            bytes_retransmitted: 0,
            bytes_lost: 0,
            loss_declarations: 0,
            repairs_attributed: 0,
            declared_by_packet_threshold: 0,
            declared_by_time_threshold: 0,
            declared_by_rto: 0,
            inflight_hi_bytes: 0,
        }
    }

    /// A rung record with the ceiling arithmetic filled in exactly as the
    /// scenario fills it, and nothing measured yet.
    fn ceiling_sample(frame: u32) -> crate::report::SendCeilingSample {
        let wire = sink_wire_bytes(frame as usize);
        let chunk = phantom_protocol::transport::mtu::MAX_APP_CHUNK;
        let seg = wire.div_ceil(chunk).max(1);
        crate::report::SendCeilingSample {
            leg: Leg::Udp,
            t_unix_ns: 0,
            rung: 0,
            frame_bytes: frame,
            wire_frame_bytes: wire as u32,
            segments_per_frame: seg as u32,
            send_buffer_segments: SEND_BUFFER_SEGMENTS,
            app_chunk_bytes: chunk as u32,
            arq_buffer_bytes: ((SEND_BUFFER_SEGMENTS as usize / seg).max(1) * wire) as u64,
            peer_window_bytes: phantom_protocol::transport::stream::MAX_SEND_WINDOW as u64,
            window_ns: 0,
            client_bytes: 0,
            client_frames: 0,
            megabits_per_sec: 0.0,
            server_bytes: None,
            server_frames: None,
            window_samples: 0,
            tail_samples: 0,
            tail_share: 0.25,
            inflight_tail: Summary::default(),
            cwnd_tail: Summary::default(),
            stalled: false,
            error: None,
        }
    }

    /// The send loop `upload` and every sweep rung share. A deadline already
    /// past must offer nothing rather than one frame: a rung of one frame is a
    /// measurement of the loop's own structure.
    #[tokio::test]
    async fn the_shared_send_loop_offers_nothing_after_its_deadline() {
        let link = ScriptedLink::default();
        let mut win = WindowTracker::new(Leg::Udp, "upload");
        let mut sink = SampleSink::new();
        let out = pour_frames(&link, 256, Instant::now(), &mut win, &mut sink).await;
        assert_eq!(out.frames, 0);
        assert!(out.error.is_none() && !out.stalled);
        assert_eq!(win.cumulative, 0);
    }

    /// And a link that refuses reports the refusal rather than counting the
    /// frame it could not send.
    #[tokio::test]
    async fn the_shared_send_loop_reports_a_refusal_without_counting_the_frame() {
        let link = ScriptedLink::failing_sends();
        let mut win = WindowTracker::new(Leg::Udp, "send_ceiling:256");
        let mut sink = SampleSink::new();
        let out = pour_frames(
            &link,
            256,
            Instant::now() + Duration::from_secs(5),
            &mut win,
            &mut sink,
        )
        .await;
        assert_eq!(out.frames, 0);
        assert_eq!(
            win.cumulative, 0,
            "a refused frame is not bytes on the wire"
        );
        assert!(matches!(out.error, Some(CoreError::ConnectionClosed)));
    }

    /// The sampler has to stop with the transfer, not with the session.
    ///
    /// Teardown asks the peer for its tally and waits behind everything still
    /// in the send buffer, which on a saturated transfer is seconds. Rows taken
    /// through that show outstanding bytes collapsing towards zero, and the tail
    /// of the series — the one place a byte ceiling is visible, and where the
    /// convergence reading is taken — becomes partly a reading of the drain.
    // Two threads deliberately: the scripted link answers a send without ever
    // awaiting anything, so on a single-threaded runtime the pour loop never
    // yields and the sampler task — which is the thing under test — would not
    // get to run at all. A real link awaits its socket.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_window_sampler_stops_with_the_transfer_and_not_with_the_session() {
        let link = Arc::new(ScriptedLink::default());
        let calls = link.window_calls.clone();
        let mut win = WindowTracker::new(Leg::Udp, "upload");
        let mut sink = SampleSink::new();

        let (poured, samples) = burst_with_window(
            link.clone(),
            Leg::Udp,
            "upload",
            256,
            Duration::from_millis(500),
            &mut win,
            &mut sink,
        )
        .await;

        assert!(poured.frames > 0, "the burst must have offered something");
        let last = samples.last().expect("the sampler must have run at all");
        // No row may lie past the burst. The bound is the burst plus one sample
        // interval, and it is not timing-sensitive in the direction that
        // matters: the sampler reads its elapsed time immediately after testing
        // the stop flag, so a late wake-up finds the flag set and takes no
        // sample at all. A drain folded into this series would put rows seconds
        // past the burst, which is what this excludes.
        assert!(
            last.elapsed_ms <= 500 + WindowRecorder::INTERVAL.as_millis() as u64,
            "a row {} ms into a 500 ms burst is a row from the teardown",
            last.elapsed_ms
        );
        let served = calls.load(Ordering::Relaxed);
        // Whatever the scenario does next — and what it does next is wait out a
        // drain — no further row may join the series.
        tokio::time::sleep(Duration::from_millis(600)).await;
        assert_eq!(
            calls.load(Ordering::Relaxed),
            served,
            "the sampler kept running past the transfer it was sampling"
        );
    }

    /// Frames that land are counted at their wire cost, which is the unit both
    /// byte ceilings are stated in.
    #[tokio::test]
    async fn the_shared_send_loop_counts_frames_at_their_wire_cost() {
        let link = ScriptedLink::default();
        let mut win = WindowTracker::new(Leg::Udp, "upload");
        let mut sink = SampleSink::new();
        let out = pour_frames(
            &link,
            256,
            Instant::now() + Duration::from_millis(30),
            &mut win,
            &mut sink,
        )
        .await;
        assert!(out.frames > 0, "a live link must have taken some frames");
        assert_eq!(
            win.cumulative,
            out.frames * sink_wire_bytes(256) as u64,
            "the byte tally must be frames at their wire cost"
        );
    }

    /// A concurrent session that never connected is a session the run intended
    /// to have and did not get — the same event every other scenario files as a
    /// `connect` error. This was the one connect path in the harness that
    /// counted its failures into the summary and wrote them nowhere: a run whose
    /// `errors.jsonl` held a single row had in fact lost four sessions, and the
    /// three that were missing were the ones that failed together and so said
    /// the most about why.
    #[tokio::test]
    async fn concurrent_sessions_that_never_connected_are_recorded_as_run_errors() {
        let out = concurrency(&closed_endpoints(), &unused_pin(), Leg::Tcp, 3, 1).await;

        assert_eq!(out.summary.ok_count, 0, "nothing could have succeeded");
        assert_eq!(out.summary.error_count, 3, "all three sessions failed");
        assert_eq!(
            out.errors.len(),
            3,
            "every failure the summary counted must be findable in the error log: {:?}",
            out.errors
        );
        for r in &out.errors {
            assert_eq!(r.leg, Some(Leg::Tcp), "the leg must be named");
            assert_eq!(r.scenario, "concurrency", "the scenario must be named");
            assert_eq!(r.context, "connect", "the stage that failed must be named");
            // The refusal came from the socket, so the connect really was
            // attempted rather than rejected by argument validation before it.
            assert_eq!(r.error_kind, "NetworkError", "{r:?}");
        }
    }

    /// The count in the summary and the rows in the error log are two views of
    /// one quantity. They disagreed for a whole scenario, which is how three
    /// failed handshakes reached an analysis that reported one.
    #[tokio::test]
    async fn the_concurrency_summary_and_its_error_log_agree() {
        let out = concurrency(&closed_endpoints(), &unused_pin(), Leg::Tcp, 4, 2).await;
        assert_eq!(out.summary.error_count, out.errors.len());
    }

    /// A `Timeout` reaching this log could have come from the UDP transport's
    /// handshake-retransmission budget, from the session's whole-handshake
    /// deadline, or from this harness's own wait around `await_ready()`. They
    /// are three different diagnoses and the record carried no way to tell them
    /// apart; the duration of the failed operation does tell them apart.
    #[tokio::test]
    async fn a_failed_connect_records_how_long_it_ran() {
        let out = concurrency(&closed_endpoints(), &unused_pin(), Leg::Tcp, 1, 1).await;

        let e = out.errors.first().expect("the connect failed");
        let took = e
            .elapsed_ns
            .expect("a connect failure must say how long it took");
        assert!(
            took < conn::CONNECT_TIMEOUT.as_nanos() as u64,
            "a refused connect cannot have outlasted the connect budget: {took} ns"
        );
    }

    /// The same field, on the path every other scenario takes.
    #[tokio::test]
    async fn a_marks_failure_records_how_long_it_ran() {
        let link = ScriptedLink::failing_sends();
        let mut out = ScenarioOutput::new(Leg::Udp, "download");

        out.mark(&link, "download:end").await;

        assert!(out.errors[0].elapsed_ns.is_some());
    }

    /// The upload's numerator is the server's count, and it has to reach the
    /// artifact as fields. It was stated only in a note, so the leg comparison
    /// published the sending side's own book for a direction whose honest figure
    /// is the receiving side's, and said so in a footnote.
    #[test]
    fn a_closed_upload_records_what_the_server_counted_and_over_what_span() {
        let client = Throughput::new(3_100_000, 3100, 12_000_000_000);
        let r = upload_receipt(
            Leg::Udp,
            &client,
            &Ok((3059, 3_059_210, 1_000_000_000, 13_476_000_000)),
        );

        assert_eq!(r.direction, "upload");
        assert_eq!(r.server_frames, Some(3059));
        assert_eq!(r.server_bytes, Some(3_059_210));
        assert_eq!(
            r.server_observed_ns,
            Some(12_476_000_000),
            "the span is first arrival to last, not the client's window"
        );
        assert_ne!(
            r.server_observed_ns,
            Some(r.client_window_ns),
            "the two ends do not observe the same interval, and the record must not imply they do"
        );
    }

    /// The failing branch is the one that decides whether an analysis can tell
    /// an artifact that predates this record from a transfer that tried to count
    /// and could not. Both are silence in the file unless the second writes.
    #[test]
    fn an_upload_whose_report_never_came_back_still_leaves_a_receipt() {
        let client = Throughput::new(3_100_000, 3100, 12_000_000_000);
        let r = upload_receipt(
            Leg::Tcp,
            &client,
            &Err((SinkEndFailure::NoReport, CoreError::Timeout)),
        );

        assert_eq!(r.server_bytes, None, "nothing was counted");
        assert_eq!(r.client_bytes, 3_100_000, "the sender's book survives");
        let why = r.error.clone().unwrap_or_default();
        assert!(
            why.contains("no report") && why.contains("Timeout"),
            "the receipt must name which half failed and how: {why}"
        );

        let blocked = upload_receipt(
            Leg::Tcp,
            &client,
            &Err((SinkEndFailure::SendBlocked, CoreError::Timeout)),
        );
        assert_ne!(
            blocked.error, r.error,
            "the two closing failures have different causes and must not read alike"
        );
    }

    /// The receipt is a different record shape from the per-second series and
    /// arrives after the last of them is already on disk, so it gets its own
    /// sink rather than a row in theirs.
    #[test]
    fn a_scenario_starts_with_no_receipt_and_keeps_it_out_of_the_sample_series() {
        let mut out = ScenarioOutput::new(Leg::Udp, "upload");
        assert!(out.receipt.is_empty());

        let client = Throughput::new(1, 1, 1);
        out.receipt
            .push(&upload_receipt(Leg::Udp, &client, &Ok((1, 2, 0, 3))));

        assert_eq!(out.receipt.len(), 1);
        assert!(
            out.sink.is_empty(),
            "a receipt in the throughput series would be summed as a window"
        );
        assert!(out.window.is_empty());
    }

    /// A mark is best-effort, but its loss is not free: `download:begin` and
    /// `download:end` bracket the interval the server's window series is joined
    /// against, so a missing `end` collapses that interval and the join comes
    /// back empty — reading as a series that was never sampled. Seven sessions
    /// across two runs lost their `download:end` and neither artifact said so.
    #[tokio::test]
    async fn a_mark_that_never_reached_the_server_is_recorded_as_a_run_error() {
        let link = ScriptedLink::failing_sends();
        let mut out = ScenarioOutput::new(Leg::Udp, "download");

        out.mark(&link, "download:end").await;

        assert_eq!(
            out.errors.len(),
            1,
            "a mark that could not be sent left no trace in the run's errors"
        );
        let e = &out.errors[0];
        assert_eq!(e.leg, Some(Leg::Udp), "the leg must be named");
        assert_eq!(e.scenario, "download", "the scenario must be named");
        assert!(
            e.context.contains("download:end"),
            "the mark itself must be named: {}",
            e.context
        );
        assert_eq!(e.error_kind, "ConnectionClosed");
        assert_eq!(
            out.summary.error_count, 1,
            "the run's error tally must count it too"
        );
    }

    /// And the converse, or the counter would just be a second name for "a
    /// mark was attempted": a mark that lands is not an error.
    #[tokio::test]
    async fn a_mark_that_lands_records_nothing() {
        let link = ScriptedLink::default();
        let mut out = ScenarioOutput::new(Leg::Udp, "download");

        out.mark(&link, "download:begin").await;

        assert!(out.errors.is_empty(), "{:?}", out.errors);
        assert_eq!(out.summary.error_count, 0);
    }

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

    /// The console transcript is what an operator reads first, and "reordered
    /// 4271" was exactly the number that could not size anything. The prose has
    /// to carry the distribution and has to say what it could not classify.
    #[test]
    fn a_rungs_prose_sizes_the_reordering_rather_than_announcing_it() {
        let mut t = downlink::SeqTracker::new();
        for seq in 0..200u64 {
            if seq == 100 {
                continue;
            }
            t.observe_stamped(
                seq,
                downlink::Stamps {
                    recv_ns: seq * 1_000_000,
                    send_ns: seq * 1_000,
                },
            );
        }
        t.observe_stamped(
            100,
            downlink::Stamps {
                recv_ns: 250_000_000,
                send_ns: 100_000,
            },
        );
        let note = reorder_note(&t.profile());
        assert!(note.contains("p99"), "the tail has to be in it: {note}");
        assert!(note.contains("ms"), "and the time as well as the count");
        assert!(
            note.contains("filled") && note.contains("lost") && note.contains("still open"),
            "the classification is the point: {note}"
        );

        // A clean rung stays one line.
        let mut clean = downlink::SeqTracker::new();
        for seq in 0..10u64 {
            clean.observe(seq);
        }
        assert_eq!(reorder_note(&clean.profile()), "");

        // A rung whose only late arrivals fell outside the window has no
        // distribution, and a zeroed one would read as "reordered by nothing".
        let mut wild = downlink::SeqTracker::new();
        wild.observe(0);
        wild.observe(1_000_000);
        wild.observe(1);
        let note = reorder_note(&wild.profile());
        assert!(
            !note.contains("p50 0"),
            "an unmeasured distance must not print as zero: {note}"
        );
        assert!(note.contains("fell outside"), "{note}");
    }

    /// The receiver's clock and the sender's stamp are paired but never
    /// subtracted from each other. A `stamps_at` that mixed them would make
    /// every displacement a clock-offset estimate instead of a measurement.
    #[test]
    fn the_two_clocks_are_carried_side_by_side_not_reconciled() {
        let base = Instant::now();
        let later = base + Duration::from_millis(250);
        let s = stamps_at(base, later, 1_700_000_000_000_000_000);
        assert_eq!(s.recv_ns, 250_000_000);
        assert_eq!(
            s.send_ns, 1_700_000_000_000_000_000,
            "the sender's stamp is carried through untouched"
        );
        // An arrival dated before the base cannot produce a negative interval.
        assert_eq!(stamps_at(later, base, 7).recv_ns, 0);
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

    // ── wire_capture reporting ──────────────────────────────────────────────
    //
    // The scenario itself needs a network and a privileged capture; everything
    // between the capture and the artifact does not, and that is where a wrong
    // result would be written. These drive it with constructed captures.

    /// Deterministic non-repeating bytes, so a constructed payload is
    /// unstructured without depending on an RNG.
    fn filler(len: usize, seed: u64) -> Vec<u8> {
        let mut s = seed | 1;
        (0..len)
            .map(|_| {
                s = s.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
                (s >> 33) as u8
            })
            .collect()
    }

    /// A minimal classic-pcap file over Ethernet/IPv4/UDP frames.
    fn capture_of(frames: &[(u64, Vec<u8>)]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&0xa1b2_c3d4u32.to_le_bytes());
        out.extend_from_slice(&[2, 0, 4, 0]);
        out.extend_from_slice(&[0u8; 8]);
        out.extend_from_slice(&65_535u32.to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes());
        for (ns, body) in frames {
            let mut f = vec![0u8; 14];
            f[12] = 0x08;
            let mut ip = vec![0u8; 20];
            ip[0] = 0x45;
            ip[2..4].copy_from_slice(&((20 + 8 + body.len()) as u16).to_be_bytes());
            ip[9] = 17;
            f.extend_from_slice(&ip);
            let mut udp = vec![0u8; 8];
            udp[4..6].copy_from_slice(&((8 + body.len()) as u16).to_be_bytes());
            f.extend_from_slice(&udp);
            f.extend_from_slice(body);
            out.extend_from_slice(&((ns / 1_000_000_000) as u32).to_le_bytes());
            out.extend_from_slice(&((ns % 1_000_000_000 / 1_000) as u32).to_le_bytes());
            out.extend_from_slice(&(f.len() as u32).to_le_bytes());
            out.extend_from_slice(&(f.len() as u32).to_le_bytes());
            out.extend_from_slice(&f);
        }
        out
    }

    fn probe_messages(count: usize) -> Vec<(String, Vec<u8>)> {
        (0..count)
            .map(|i| {
                let m = probe_marker(0xFEED, i);
                let mut p = m.as_bytes().to_vec();
                p.extend_from_slice(&filler(PROBE_PAYLOAD_BYTES - m.len(), i as u64 + 1));
                (m, p)
            })
            .collect()
    }

    fn sample_for(findings: wirecheck::Findings, messages: usize) -> WireCheckSample {
        WireCheckSample {
            leg: Leg::Udp,
            t_unix_ns: 1,
            established_unix_ns: 2_000_000_000,
            probe_messages: messages,
            probe_payload_bytes: PROBE_PAYLOAD_BYTES,
            echo_ok: messages,
            echo_failed: 0,
            capture_command: "tcpdump -i any -n -s 0 -U -w x.pcap host 10.0.0.1".to_string(),
            capture_path: Some("x.pcap".to_string()),
            findings,
            session_counters: None,
        }
    }

    /// A capture where the control is present and the payloads are not: the
    /// only shape that may be reported as a pass, and the notes have to state
    /// the sample size the entropy figures rest on.
    #[test]
    fn a_clean_check_reports_a_pass_with_its_sample_size() {
        let msgs = probe_messages(3);
        let needles = needles_for(&msgs, PROTOCOL_VARIANT);
        let mut hello = PROTOCOL_VARIANT.to_vec();
        hello.extend_from_slice(&filler(1000, 11));
        let cap = capture_of(&[
            (1_000_000_000, hello),
            (3_000_000_000, filler(1100, 12)),
            (3_100_000_000, filler(1100, 13)),
        ]);
        let findings = wirecheck::analyze(&cap, &needles, 2_000_000_000).expect("analyze");
        assert_eq!(findings.verdict, wirecheck::Verdict::Pass, "{findings:?}");

        let mut out = ScenarioOutput::new(Leg::Udp, "wire_capture");
        record_wire_check(&mut out, sample_for(findings, msgs.len()));

        assert_eq!(out.summary.ok_count, 1);
        assert_eq!(out.summary.error_count, 0);
        assert_eq!(out.sink.len(), 1, "the record reaches the artifact");
        let notes = out.summary.notes.join("\n");
        assert!(notes.contains("VERDICT pass"), "{notes}");
        assert!(
            notes.contains("positive control `protocol_variant`"),
            "the control must be reported, not merely consulted: {notes}"
        );
        assert!(
            notes.contains("2 payloads, 2 of them at least 256 B"),
            "the entropy sample size must travel with the figure: {notes}"
        );
        assert!(
            notes.contains("arithmetic ceiling"),
            "and so must the reason short packets score low: {notes}"
        );
    }

    /// The rule the design turns on, at the reporting layer: a clean negative
    /// search whose control failed is an error in the summary, not an ok.
    #[test]
    fn a_search_that_proved_nothing_is_counted_as_a_failure_not_a_pass() {
        let msgs = probe_messages(3);
        let needles = needles_for(&msgs, PROTOCOL_VARIANT);
        // Nothing in this capture is a payload — and nothing is the control.
        let cap = capture_of(&[
            (1_000_000_000, filler(1000, 21)),
            (3_000_000_000, filler(1100, 22)),
        ]);
        let findings = wirecheck::analyze(&cap, &needles, 2_000_000_000).expect("analyze");

        let mut out = ScenarioOutput::new(Leg::Udp, "wire_capture");
        record_wire_check(&mut out, sample_for(findings, msgs.len()));

        assert_eq!(out.summary.ok_count, 0);
        assert_eq!(out.summary.error_count, 1);
        let notes = out.summary.notes.join("\n");
        assert!(notes.contains("VERDICT failed"), "{notes}");
        assert!(notes.contains("positive control"), "{notes}");
        assert!(notes.contains("worth nothing"), "{notes}");
    }

    /// A payload on the wire has to name the message it belongs to, or the
    /// finding cannot be chased.
    #[test]
    fn a_leaked_payload_is_reported_as_a_failure_naming_the_message() {
        let msgs = probe_messages(3);
        let needles = needles_for(&msgs, PROTOCOL_VARIANT);
        let mut hello = PROTOCOL_VARIANT.to_vec();
        hello.extend_from_slice(&filler(1000, 31));
        let cap = capture_of(&[(1_000_000_000, hello), (3_000_000_000, msgs[2].1.clone())]);
        let findings = wirecheck::analyze(&cap, &needles, 2_000_000_000).expect("analyze");

        let mut out = ScenarioOutput::new(Leg::Udp, "wire_capture");
        record_wire_check(&mut out, sample_for(findings, msgs.len()));
        assert_eq!(out.summary.error_count, 1);
        let notes = out.summary.notes.join("\n");
        assert!(notes.contains("plaintext on the wire"), "{notes}");
        assert!(
            notes.contains(&msgs[2].0),
            "the message must be named: {notes}"
        );
    }

    /// The skip path, which is the one an operator without capture rights will
    /// actually hit. It must read as an absence with a cause — never as a pass,
    /// and never as a silent omission.
    #[test]
    fn a_run_that_could_not_capture_records_the_reason_and_counts_neither_way() {
        let why = "capturing needs elevated rights on this host and the probe has none";
        let mut out = ScenarioOutput::new(Leg::Udp, "wire_capture");
        record_wire_check(
            &mut out,
            skipped_sample(Leg::Udp, "tcpdump -i any ...".to_string(), why.to_string()),
        );

        assert_eq!(out.summary.ok_count, 0, "a skip is not a pass");
        assert_eq!(out.summary.error_count, 0, "and it is not a failure either");
        assert_eq!(out.sink.len(), 1, "but it is recorded");
        let notes = out.summary.notes.join("\n");
        assert!(notes.contains("VERDICT skipped"), "{notes}");
        assert!(
            notes.contains(why),
            "the reason must reach the artifact: {notes}"
        );
        assert!(
            notes.contains("the wire was not examined at all"),
            "and it must say what was not done: {notes}"
        );
        assert!(
            !notes.contains("negative search"),
            "a skip must not report figures it never computed: {notes}"
        );
    }

    /// Whatever the verdict, the record has to carry the statement about the
    /// one question a capture cannot reach — including on a skip, where it is
    /// the only thing the scenario has to say.
    #[test]
    fn every_outcome_carries_the_encrypted_flag_statement() {
        for sample in [
            skipped_sample(Leg::Udp, String::new(), "no tcpdump".to_string()),
            sample_for(
                wirecheck::analyze(&capture_of(&[]), &[], 1).expect("analyze"),
                0,
            ),
        ] {
            let mut out = ScenarioOutput::new(Leg::Udp, "wire_capture");
            record_wire_check(&mut out, sample);
            let notes = out.summary.notes.join("\n");
            assert!(
                notes.contains("Answered from the source, not from the capture"),
                "{notes}"
            );
            assert!(
                notes.contains("core/tests/security_invariants.rs"),
                "{notes}"
            );
        }
    }

    /// The mimic leg's SNI is open by design. Recording it must not move the
    /// verdict in either direction, or a deliberate property of that leg would
    /// read as a defect.
    #[test]
    fn an_observed_string_is_reported_without_becoming_a_verdict() {
        let msgs = probe_messages(2);
        let mut needles = needles_for(&msgs, PROTOCOL_VARIANT);
        needles.push(Needle::new(
            "mimic_sni",
            b"www.example.com".to_vec(),
            Polarity::Observed,
        ));
        let mut hello = PROTOCOL_VARIANT.to_vec();
        hello.extend_from_slice(b"www.example.com");
        hello.extend_from_slice(&filler(1000, 41));
        let cap = capture_of(&[(1_000_000_000, hello), (3_000_000_000, filler(1100, 42))]);
        let findings = wirecheck::analyze(&cap, &needles, 2_000_000_000).expect("analyze");
        assert_eq!(findings.verdict, wirecheck::Verdict::Pass, "{findings:?}");

        let mut out = ScenarioOutput::new(Leg::Udp, "wire_capture");
        record_wire_check(&mut out, sample_for(findings, msgs.len()));
        let notes = out.summary.notes.join("\n");
        assert!(
            notes.contains("observed (open by design, not a verdict) `mimic_sni`"),
            "{notes}"
        );
        assert_eq!(out.summary.ok_count, 1);
    }

    fn deltas(asked: u64, answered: u64) -> Option<RepairDeltas> {
        Some(RepairDeltas {
            asked,
            answered,
            evicted: 0,
            refused: 0,
        })
    }

    /// A connect that lost nothing is not evidence, however well it went.
    ///
    /// This is the failure mode the whole scenario is built against. A relay that swallowed no
    /// flight leaves an ordinary connect, and an ordinary connect succeeds — so a version of
    /// this scenario that asserted only on success would report a green result for a mechanism
    /// it never exercised, on every clean path, forever. The counters cannot rescue it either:
    /// on a busy listener another peer's repeat would move them inside the same window.
    #[test]
    fn a_connect_that_lost_nothing_is_never_a_pass() {
        for d in [deltas(0, 0), deltas(3, 3), None] {
            let v = classify_repair(0, true, d);
            assert!(!v.is_pass(), "{v:?}");
            assert!(
                !v.is_failure(),
                "a clean path is not a protocol failure: {v:?}"
            );
            assert!(v.label().contains("swallowed no flight"), "{}", v.label());
        }
    }

    /// A repaired connect takes both halves of the counter pair, because either alone is
    /// ambiguous between the two things it has to tell apart: a question arriving says the
    /// client asked again, an answer going back says the listener had something to send.
    #[test]
    fn a_repair_is_claimed_only_when_the_question_and_the_answer_are_both_recorded() {
        assert_eq!(
            classify_repair(6, true, deltas(1, 1)),
            RepairVerdict::Repaired
        );

        let no_question = classify_repair(6, true, deltas(0, 5));
        assert!(!no_question.is_pass());
        assert!(
            no_question.label().contains("no repeated client flight"),
            "{}",
            no_question.label()
        );

        let no_answer = classify_repair(6, true, deltas(1, 0));
        assert!(!no_answer.is_pass());
        assert!(
            no_answer.label().contains("nothing went back"),
            "{}",
            no_answer.label()
        );

        // A daemon that did not report at all is an absence, not a zero.
        let silent = classify_repair(6, true, None);
        assert!(!silent.is_pass() && !silent.is_failure());
        assert!(
            silent.label().contains("did not report its counters"),
            "{}",
            silent.label()
        );
    }

    /// The one shape that is a finding: a flight really went missing and the connect never
    /// came back. That is what a listener with no retained flight produces on every attempt,
    /// so it must count against the run rather than beside it.
    #[test]
    fn a_connect_lost_to_a_real_loss_is_counted_as_a_failure() {
        for d in [deltas(0, 0), deltas(3, 0), None] {
            let v = classify_repair(6, false, d);
            assert!(v.is_failure(), "{v:?}");
            assert!(!v.is_pass());
            assert!(v.label().starts_with("failed: "), "{}", v.label());
            assert!(
                v.label().contains("retransmit budget"),
                "the reader has to be told which timer produced it: {}",
                v.label()
            );
        }
    }

    /// The scenario's whole shape, minus the path: a real PhantomUDP handshake against a
    /// listener in this process, with one reply flight taken out of it by the relay the
    /// scenario uses, timed by the connect the scenario times, and judged by the rule the
    /// scenario judges by.
    ///
    /// It is a test of the instrument and not of the protocol — the library pins the repair
    /// itself, over loopback, from the other side. What it guards is the failure that would
    /// otherwise be silent: a relay that stopped identifying the reply flight, a connect helper
    /// that stopped waiting for the handshake, or a classifier that stopped asking for both
    /// counters would go on reporting `inconclusive` against a WAN nobody can rerun on demand,
    /// and nothing in the artifact would say which of them broke.
    ///
    /// Loopback is enough here for the same reason it is not enough elsewhere: the quantity
    /// under test is a decision about a datagram, not a rate.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_swallowed_reply_flight_is_repaired_against_a_listener_in_this_process() {
        use phantom_protocol::api::udp_listener::PhantomUdpListener;

        let listener = PhantomUdpListener::bind_udp("127.0.0.1:0".to_string())
            .await
            .expect("bind a loopback PhantomUDP listener");
        let server: SocketAddr = listener.local_addr().parse().expect("the bound address");
        let pin = listener.verifying_key_bytes();

        let acceptor = listener.clone();
        let accept = tokio::spawn(async move { acceptor.accept().await });

        let attempt = relay_connect(server, &pin, true).await;
        assert!(
            attempt.outcome.is_ok(),
            "the connect must survive a lost reply flight, got {:?} after {:.0} ms",
            attempt.outcome,
            attempt.elapsed_ns as f64 / 1e6
        );

        let swallowed = attempt.stats.swallowed() as u64;
        assert!(
            swallowed > 0,
            "the relay must have taken a flight, or this asserts nothing"
        );
        assert_eq!(
            attempt.stats.flight_chunks(),
            u16::try_from(swallowed).ok(),
            "one whole flight and no more: the repeat that follows has to arrive intact"
        );

        // Read exactly what the scenario reads on the far end — the listener's own
        // `MetricsSnapshotFfi`, which an accepted session shares.
        let m = listener.metrics_snapshot();
        let observed = RepairDeltas {
            asked: m.initial_flights_on_committed_route_total,
            answered: m.handshake_flight_repeated_total,
            evicted: m.handshake_flight_evicted_total,
            refused: m.handshake_flight_refused_total,
        };
        assert!(
            observed.asked > 0 && observed.answered > 0,
            "the question and the answer both have to be visible to an operator, saw {observed:?}"
        );
        // `asked` is compared with `answered`, so it has to be the flight-unit counter and not
        // the datagram-unit one the listener publishes beside it. The repeated hello is
        // fragmented, so the two differ here by the fragment count — reading the wrong one
        // would report this repaired connect as a listener that ignored two questions out of
        // three, which is a reading a live run actually produced.
        assert!(
            observed.asked < m.initial_datagrams_on_committed_route_total,
            "the arrivals of one fragmented repeat must count as fewer flights than datagrams; \
             {observed:?} against {} datagrams means the deltas are being read in datagrams",
            m.initial_datagrams_on_committed_route_total
        );
        assert_eq!(
            classify_repair(swallowed, true, Some(observed)),
            RepairVerdict::Repaired
        );

        accept.abort();
        listener.shutdown();
    }

    /// A reply that never comes ends at the library's own budget, not at this harness's ceiling.
    ///
    /// The scenario's documentation says an attempt against a listener with no retained flight
    /// times out after the client's 8 s retransmit budget, well inside the 30 s the harness is
    /// willing to wait — and until this test nothing had ever produced that shape. If the two
    /// ever crossed, by a shorter harness ceiling or a longer library budget, every failed
    /// attempt would be the harness giving up instead and the finding would be lost inside it.
    ///
    /// It also pins the order the classifier asks its questions in. Here nothing was swallowed
    /// *and* nothing came back, and that is a silent path rather than an absent repair: the
    /// verdict has to be inconclusive, because the mechanism was never reached.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_reply_that_never_comes_ends_at_the_libraries_budget_not_the_harnesss() {
        // A bound socket nobody reads. The kernel accepts every datagram the relay forwards and
        // answers none of them; a closed port would answer with ICMP, which is a different
        // fault from the silence this is about.
        let blackhole = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("a socket to swallow everything");
        let addr = blackhole.local_addr().expect("its address");

        let attempt = relay_connect(addr, &unused_pin(), true).await;
        assert_eq!(
            attempt.outcome.as_ref().err().map(error_kind).as_deref(),
            Some("Timeout"),
            "a handshake nothing answers must end as a typed timeout, got {:?}",
            attempt.outcome
        );

        let elapsed = Duration::from_nanos(attempt.elapsed_ns);
        assert!(
            elapsed >= RETRANSMIT_BUDGET / 2,
            "ending in {elapsed:?} means something other than the retransmit schedule stopped it"
        );
        assert!(
            elapsed < conn::CONNECT_TIMEOUT,
            "the library has to give up first, or every failed attempt reads as this harness's own \
             ceiling: {elapsed:?} against {:?}",
            conn::CONNECT_TIMEOUT
        );

        let v = classify_repair(attempt.stats.swallowed() as u64, false, None);
        assert!(
            !v.is_failure() && !v.is_pass(),
            "a path that carried nothing in either direction is not evidence about the repair: {v:?}"
        );
    }

    /// Legs whose handshake rides a byte pipe have no flight to lose, and the artifact has to
    /// say so — an omitted row is indistinguishable from a scenario that ran and found nothing.
    #[tokio::test]
    async fn the_repair_scenario_declines_legs_with_no_flight_to_lose() {
        for leg in [Leg::Tcp, Leg::Mimic] {
            let out = handshake_repair(&closed_endpoints(), &unused_pin(), leg, 1).await;
            assert_eq!(out.summary.ok_count, 0);
            assert_eq!(out.summary.error_count, 0, "a skip is not a failure");
            assert!(out.sink.is_empty(), "{leg}: a skip records no samples");
            let notes = out.summary.notes.join("\n");
            assert!(notes.contains("PhantomUDP"), "{leg}: {notes}");
            assert!(
                notes.contains("retransmits it"),
                "{leg}: the reason has to name why the loss cannot occur there: {notes}"
            );
        }
    }

    /// The control this scenario relies on has to be a string that is really on
    /// the wire in the clear, and really this build's. If the tag ever became
    /// something a peer could not read before the AEAD, the positive control
    /// would start failing every run and the reason would not be obvious.
    #[test]
    fn the_positive_control_is_the_builds_own_protocol_variant_tag() {
        assert!(!PROTOCOL_VARIANT.is_empty());
        assert!(
            PROTOCOL_VARIANT.starts_with(b"phantom-"),
            "{:?}",
            std::str::from_utf8(PROTOCOL_VARIANT)
        );
        assert!(
            PROTOCOL_VARIANT.len() >= 12,
            "a short tag would match by chance somewhere in a capture"
        );
        assert!(
            PROTOCOL_VARIANT.iter().all(|b| b.is_ascii_graphic()),
            "the control has to be findable as a literal byte string"
        );
    }

    // ── The upstream ladder ─────────────────────────────────────────────────

    /// A ladder whose socket is bound but pointed nowhere in particular, so its
    /// record-building can be exercised without a path.
    async fn idle_ladder() -> UplinkLadder {
        let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        UplinkLadder::new(sock, downlink::DEFAULT_PAYLOAD)
    }

    fn account(received: u64, bytes: u64, window_ns: u64) -> uplink::Report {
        uplink::Report {
            run_nonce: 1,
            rung: 0,
            received_datagrams: received,
            received_bytes: bytes,
            first_datagram_bytes: downlink::DEFAULT_PAYLOAD as u64,
            reordered_datagrams: 0,
            duplicate_datagrams: 0,
            observed_window_ns: window_ns,
            reorder: downlink::ReorderProfile::default(),
        }
    }

    /// The property the whole scenario exists for: an upload rate is what the
    /// *receiver* saw over the receiver's own window, not what this side handed
    /// to a socket. The two are recorded side by side and the second is never
    /// substituted for the first.
    #[tokio::test]
    async fn an_upstream_rung_is_rated_on_the_receivers_account_not_the_senders() {
        let l = idle_ladder().await;
        // A second of sending, of which the receiver saw four fifths.
        let sent = SentRung {
            datagrams: 1000,
            bytes: 1_200_000,
            elapsed_ns: 1_000_000_000,
        };
        let s = l.sample(
            0,
            9_600_000.0,
            Duration::from_secs(1),
            sent,
            Some(account(800, 960_000, 1_000_000_000)),
            "",
        );

        assert_eq!(s.direction, "raw_udp_upstream");
        assert_eq!(s.sender_bps, Some(9_600_000.0));
        assert!(
            (s.receiver_bps - (960_000.0 - 1200.0) * 8.0).abs() < 1.0,
            "the rate must come from the receiver's bytes over the receiver's window, got {}",
            s.receiver_bps
        );
        assert!(
            s.receiver_bps < s.sender_bps.unwrap_or(0.0),
            "a fifth of the rung went missing and the record must show it"
        );
        let loss = s.loss_fraction.expect("both counts are known");
        assert!((loss - 0.2).abs() < 1e-9, "got {loss}");
        assert!(s.admissible, "the sender reached its offer and 800 arrived");
        assert!(s.note.is_empty());
    }

    /// A rung the receiver never reported on is not a lossless rung and not a
    /// total loss either — it is a missing measurement, and both of the other
    /// two readings are wrong in a way that would reach a conclusion.
    #[tokio::test]
    async fn a_rung_with_no_receiver_account_is_a_missing_measurement() {
        let l = idle_ladder().await;
        let sent = SentRung {
            datagrams: 1000,
            bytes: 1_200_000,
            elapsed_ns: 1_000_000_000,
        };
        let s = l.sample(0, 9_600_000.0, Duration::from_secs(1), sent, None, "");

        assert_eq!(
            s.loss_fraction, None,
            "zero arrivals with no account is not 100% loss"
        );
        assert!(!s.admissible);
        assert_eq!(s.receiver_bps, 0.0);
        assert!(
            s.note.contains("never reported"),
            "the reason must reach the artifact: {}",
            s.note
        );
        // The sender's half is still there: it is what says the rung ran at all.
        assert_eq!(s.sender_datagrams, Some(1000));
        assert_eq!(s.sender_reached_offer, Some(true));
    }

    /// A rung this side never reached measures this side. Reading a loss figure
    /// from it as though it were the link's is precisely the mistake the whole
    /// control group exists to prevent.
    #[tokio::test]
    async fn a_rung_short_of_its_own_offer_is_marked_inadmissible() {
        let l = idle_ladder().await;
        let sent = SentRung {
            datagrams: 500,
            bytes: 600_000,
            elapsed_ns: 1_000_000_000,
        };
        let s = l.sample(
            0,
            9_600_000.0,
            Duration::from_secs(1),
            sent,
            Some(account(500, 600_000, 1_000_000_000)),
            "",
        );
        assert_eq!(s.sender_reached_offer, Some(false));
        assert!(!s.admissible);
        assert!(s.note.contains("not the path"), "{}", s.note);
        // And the console line names that reason rather than guessing at one.
        let line = rung_note(&s);
        assert!(line.contains("NOT ADMISSIBLE"), "{line}");
        assert!(line.contains("measures the client"), "{line}");
    }

    /// An instrument is a system too. What bounds this sender has to be in the
    /// artifact, and derived from the constants rather than remembered — a
    /// remembered figure is right until the tick moves.
    #[test]
    fn the_scenario_states_what_bounds_its_own_sender() {
        let note = uplink_sender_bound_note(1200, crate::pacing::DEFAULT_RUNGS_KBPS);
        assert!(note.contains("1 ms pacing tick"), "{note}");
        // 1200 B once per millisecond is 9.6 Mbit/s — the exact figure a
        // non-batching version of this loop reported as a path ceiling.
        assert!(note.contains("9.6 Mbit/s"), "{note}");
        // 200 Mbit/s in 1200 B datagrams is 20 833 sendto calls a second.
        assert!(note.contains("20833"), "{note}");
        assert!(note.contains("inadmissible"), "{note}");

        // Derived, not written down: a different datagram size moves both.
        let other = uplink_sender_bound_note(600, crate::pacing::DEFAULT_RUNGS_KBPS);
        assert!(other.contains("4.8 Mbit/s"), "{other}");
        assert!(!other.contains("9.6 Mbit/s"), "{other}");
    }

    /// End to end against a sink in this process: request, challenge, arm,
    /// pace, and the receiver's account coming back. Loopback proves the
    /// exchange rather than anything about a path — no rate assertion is made,
    /// and none would mean anything at microsecond RTT.
    #[tokio::test]
    async fn the_upstream_ladder_completes_a_rung_and_records_both_accounts() {
        let sink = UdpSocket::bind("127.0.0.1:0").await.expect("bind sink");
        let port = sink.local_addr().expect("addr").port();
        let stats = Arc::new(crate::testd::baseline::BaselineStats::default());
        let served = stats.clone();
        tokio::spawn(async move {
            let _ = crate::testd::baseline::serve_udp_sink(sink, served).await;
        });

        let mut ep = closed_endpoints();
        ep.raw_udp_up_port = port;
        let out = raw_udp_upstream(&ep, &[1_000], Duration::from_millis(300)).await;

        assert_eq!(out.summary.error_count, 0, "{:?}", out.summary.notes);
        assert_eq!(out.sink.len(), 1, "one rung, one record");
        let rec: serde_json::Value =
            serde_json::from_str(&out.sink.lines()[0]).expect("the record must be JSON");
        assert_eq!(rec["direction"], "raw_udp_upstream");
        assert_eq!(rec["leg"], "raw_udp");
        assert!(
            rec["received_datagrams"].as_u64().unwrap_or(0) > 0,
            "the sink counted nothing: {rec}"
        );
        assert!(
            rec["sender_datagrams"].as_u64().unwrap_or(0) > 0,
            "this side sent nothing: {rec}"
        );
        assert!(
            rec["observed_window_ns"].as_u64().unwrap_or(0) > 0,
            "the receiver's window has to be an interval it measured: {rec}"
        );
        assert_eq!(
            rec["reorder"]["horizon"].as_u64(),
            Some(4096),
            "the receiver's ledger must travel with its counts"
        );
        assert!(
            !rec["loss_fraction"].is_null(),
            "both counts are known: {rec}"
        );
        assert_eq!(
            stats.up_reports.load(std::sync::atomic::Ordering::Relaxed),
            1
        );
    }

    /// A ladder that reached no sink must say it has no denominator, not fall
    /// back on a number. The whole scenario exists to stop an upload figure
    /// being quoted against nothing, and quoting it against a rung nobody
    /// observed would be the same fault wearing a control's name.
    #[tokio::test]
    async fn an_upstream_ladder_that_reached_no_sink_reports_no_denominator() {
        // Port 1 on loopback: nothing listens, and a connected UDP socket makes
        // the refusal visible as an error rather than a silent black hole.
        let out = raw_udp_upstream(&closed_endpoints(), &[1_000], Duration::from_millis(100)).await;

        assert!(out.summary.throughput.is_none(), "no rung was admissible");
        assert!(out.summary.error_count > 0);
        let notes = out.summary.notes.join("\n");
        assert!(
            notes.contains("NO upstream denominator"),
            "the artifact must say the direction is unnormalised: {notes}"
        );
        assert!(
            !notes.contains("upstream ceiling") && !notes.contains("carries AT LEAST"),
            "a ladder that measured nothing must claim neither a ceiling nor a floor: {notes}"
        );
        // And it gives up rather than spending the whole ladder discovering the
        // same silence, which is why only the first rung was attempted.
        assert!(
            notes.contains("answered nothing"),
            "the reason for stopping has to be recorded: {notes}"
        );
    }
}
