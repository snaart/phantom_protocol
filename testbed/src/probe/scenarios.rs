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

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
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
use crate::proto::{Msg, PayloadGen};
use crate::report::{
    unix_nanos, BuildId, ConcurrencySample, ErrorRecord, HandshakeSample, Leg,
    MessageIntegritySample, MigrationSample, NegativeSample, RekeySample, RttSample, SampleSink,
    ScenarioSummary, SoakSample, StreamSample, ThroughputSample, WireCheckSample, ZeroRttSample,
};
use crate::stats::{Summary, Throughput};
use crate::wirecheck::{
    self, filter_for, needles_for, probe_marker, tcpdump_args, Capture, CaptureRequest, Needle,
    Polarity, PROBE_PAYLOAD_BYTES,
};
use crate::{downlink, pacing};

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
    duration: Duration,
    frame_size: usize,
) -> ScenarioOutput {
    let mut out = ScenarioOutput::new(leg, "upload");
    let t0 = Instant::now();
    let framed = match connect_link(leg, ep, pin).await {
        Ok(s) => s,
        Err(e) => {
            out.error_after(leg, "upload", "connect", &e, t0);
            return out;
        }
    };
    out.mark(framed.as_ref(), "upload:begin").await;
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
    out.mark(framed.as_ref(), "bidir:end").await;
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
        out.sink.push(&crate::report::DownstreamSample {
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
fn rung_note(s: &crate::report::DownstreamSample) -> String {
    let offered = s.offered_bps / 1e6;
    let Some(sender) = s.sender_bps else {
        return format!(
            "asked {offered:.0} Mbit/s -> the daemon never reported: {} datagrams arrived, but with no sender-side count there is no denominator and this rung is not evidence",
            s.received_datagrams
        );
    };
    let loss = s
        .loss_fraction
        .map(|l| format!("{:.1}%", l * 100.0))
        .unwrap_or_else(|| "unknown".to_string());
    format!(
        "asked {offered:.0} Mbit/s -> sender achieved {:.2}, receiver saw {:.2} Mbit/s, loss {loss}, reordered {}, duplicated {}{}{}",
        sender / 1e6,
        s.receiver_bps / 1e6,
        s.reordered_datagrams,
        s.duplicate_datagrams,
        reorder_note(&s.reorder),
        if s.admissible {
            ""
        } else {
            " — NOT ADMISSIBLE, the sender never reached its own offer"
        }
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
) -> (crate::report::DownstreamSample, bool) {
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

    let sample = crate::report::DownstreamSample {
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
}
