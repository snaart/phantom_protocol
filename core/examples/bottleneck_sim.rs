//! A bottleneck-link simulation driven by the real congestion controller, so a
//! claim about `BandwidthEstimator` can be checked rather than argued.
//!
//! # Why this is in the tree
//!
//! Every loopback test in this crate runs at a round trip of microseconds, and
//! at that round trip a congestion window of five kilobytes still yields a
//! hundred megabits per second. A whole class of control-loop defect is
//! therefore invisible to a green suite: it shows up as "slow" on a real path
//! and as nothing at all on a fast one. The measurement harness under
//! `testbed/` answers that properly, over a real WAN, and it is what any
//! published performance number comes from — but it needs two hosts and a
//! campaign, so it is the wrong instrument for "does this one-line change to a
//! filter cost throughput".
//!
//! This fills that gap and nothing wider. It is a model, not a measurement: a
//! fixed-rate link with a FIFO queue and a fixed propagation delay, ticked a
//! millisecond at a time, with the sender's window and pacing rate taken from
//! the estimator itself on every acknowledgement. What it can settle is a
//! *comparison* — the same scripted demand against two builds of this file —
//! and that is the only thing any number it prints should be used for. Nothing
//! here observes a real path, so no figure from it belongs in a document that
//! describes one.
//!
//! # Running it
//!
//! ```text
//! cargo run --manifest-path core/Cargo.toml --release --example bottleneck_sim
//! cargo run --manifest-path core/Cargo.toml --release --example bottleneck_sim -- thin
//! ```
//!
//! With no argument it runs all three scenarios. Each prints one block of
//! labelled figures; to compare two revisions, run it on both and read the
//! blocks side by side.
//!
//! # The scenarios
//!
//! - **`resume`** — bulk, then longer than one filter horizon of small
//!   request/response writes, then bulk again. The shape a messenger or a VPN
//!   client has between screens, and the one that asks whether an
//!   application-limited stretch costs the connection its estimate.
//! - **`degrade`** — the same, with the link losing three quarters of its
//!   capacity while the application is quiet. The case *for* forgetting an old
//!   estimate: whatever a run says about `resume` has to be read against this.
//! - **`thin`** — a steep fall in capacity, held past one horizon, then
//!   restored. This is the shape that engages the filters' length rules: a
//!   falling run dominates nothing, so every sample is appended, and the deque
//!   fills within a fraction of a second at these cadences. It is the only one
//!   of the three that can see a length rule at all.
//!
//! # The instrument
//!
//! Beside the throughput figures each scenario reports `estimate/windowed max`.
//! The denominator is an unbounded maximum over the same horizon, kept here,
//! fed the same samples the estimator's own gate admits. A filter with no
//! length rule reads 1.00 by construction; anything below it is the length rule
//! conceding, and how far below is what the concession costs.
//!
//! The same line reports how many candidates that unbounded filter held at its
//! longest. It is the run's only evidence that a length rule was engaged at
//! all: below the bound the two filters cannot disagree, so a shape that never
//! reaches it says nothing about what happens there, however long it ran.
//!
//! `PHANTOM_SIM_TRACE=1` adds a quarter-second trace of every figure the model
//! and the controller each hold, plus a self-check on the link: a delivery-rate
//! sample above twice the link's rate is the model inventing capacity, and it
//! reads from the summary line exactly like a controller over-stating a path.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use phantom_protocol::transport::bandwidth_estimator::{
    BandwidthEstimator, DeliverySample, BW_FILTER_WINDOW,
};

/// One application segment, matching the transport's own MTU budget closely
/// enough that the window floor (four packets) means the same thing here.
const SEGMENT: u64 = 1400;
/// Simulation granularity. Everything below this is invisible to the model.
const TICK: Duration = Duration::from_millis(1);
/// One-way propagation, so the modelled round trip is twice this — inside the
/// range the reference WAN path measures.
const PROPAGATION: Duration = Duration::from_millis(100);

fn main() {
    let mut args = std::env::args().skip(1);
    let which = args.next();
    match which.as_deref() {
        None | Some("all") => {
            run_resume();
            run_degrade();
            run_thin();
        }
        Some("resume") => run_resume(),
        Some("degrade") => run_degrade(),
        Some("thin") => run_thin(),
        Some(other) => {
            eprintln!("unknown scenario {other:?}; expected resume, degrade, thin or all");
        }
    }
}

// ─── The model ──────────────────────────────────────────────────────────────

/// A segment on the wire or in the bottleneck's queue.
struct InFlight {
    bytes: u64,
    sent_at: Instant,
    /// The connection's delivered counter as of this segment's send, and when
    /// it last advanced — the near end of the interval its acknowledgement
    /// measures a rate over. The transport stamps exactly these two.
    delivered_bytes: u64,
    delivered_at: Instant,
    app_limited: bool,
}

/// A queued segment that has left the bottleneck and is on its way back as an
/// acknowledgement.
struct Returning {
    seg: InFlight,
    ack_at: Instant,
}

/// What the application wants to write, as a function of time.
enum Demand {
    /// Always more.
    Bulk,
    /// `bytes` every `every`, and nothing in between — an application-limited
    /// flow, which is what the estimator's gate exists to recognise.
    RequestResponse { bytes: u64, every: Duration },
}

/// One leg of the scripted run: how long, how fast the link is, and what the
/// application is doing.
struct Phase {
    name: &'static str,
    duration: Duration,
    link_start_bps: f64,
    link_end_bps: f64,
    demand: Demand,
}

/// An unbounded windowed maximum, kept here so the estimator's reading has
/// something to be compared against that does not share its implementation.
struct WindowedMax {
    window: VecDeque<(Instant, u64)>,
    horizon: Duration,
}

impl WindowedMax {
    fn new(horizon: Duration) -> Self {
        Self {
            window: VecDeque::new(),
            horizon,
        }
    }

    fn push(&mut self, now: Instant, value: u64) {
        while self
            .window
            .front()
            .is_some_and(|&(ts, _)| now.duration_since(ts) > self.horizon)
        {
            self.window.pop_front();
        }
        while self.window.back().is_some_and(|&(_, v)| v <= value) {
            self.window.pop_back();
        }
        self.window.push_back((now, value));
    }

    fn head(&self) -> u64 {
        self.window.front().map_or(0, |&(_, v)| v)
    }

    /// How many candidates an unbounded filter is holding — the figure that
    /// says whether a run engaged a length rule at all. A shape that never
    /// reaches the bound proves nothing about what happens at it.
    fn retained(&self) -> usize {
        self.window.len()
    }
}

/// What one run of the model recorded.
#[derive(Default)]
struct Recorded {
    /// Bytes delivered, per phase index.
    delivered_per_phase: Vec<u64>,
    /// Bytes delivered in the first and second seconds of the final phase.
    first_second: u64,
    second_second: u64,
    /// Milliseconds from the final phase opening to the first tick whose
    /// trailing-second delivery rate reached nine tenths of the link's.
    ms_to_ninety_percent: Option<u64>,
    /// The estimator's reading and window at the instant the final phase opened.
    btl_bw_at_resume: u64,
    cwnd_at_resume: u64,
    /// Widest round trip observed during the final phase — the queue the sender
    /// built for itself, which is what an over-stated estimate costs.
    max_rtt_in_final_ms: u64,
    /// Ratio of the estimator's reading to the unbounded windowed maximum over
    /// the same samples: the smallest seen, and the mean, over every tick at
    /// which the reference had a reading at all.
    worst_fidelity: f64,
    mean_fidelity: f64,
    /// The most candidates an unbounded filter held at once over the run.
    max_reference_entries: usize,
}

fn run(phases: &[Phase]) -> Recorded {
    let start = Instant::now();
    let mut est = BandwidthEstimator::new();
    let mut queue: VecDeque<InFlight> = VecDeque::new();
    let mut returning: VecDeque<Returning> = VecDeque::new();
    let mut reference = WindowedMax::new(BW_FILTER_WINDOW);

    let mut rec = Recorded {
        worst_fidelity: f64::INFINITY,
        ..Default::default()
    };
    let mut fidelity_sum = 0.0f64;
    let mut fidelity_n = 0u64;

    // Bytes serialised onto the link but not yet a whole segment's worth.
    let mut link_credit = 0.0f64;
    // Bytes the pacer has released but not yet spent.
    let mut pace_credit = 0.0f64;
    // Outstanding application demand, bytes.
    let mut owed = 0u64;
    // A trailing second of deliveries, for the time-to-ninety-percent reading.
    let mut recent: VecDeque<(Instant, u64)> = VecDeque::new();

    let final_index = phases.len().saturating_sub(1);
    let mut elapsed = Duration::ZERO;
    // A quarter-second trace of every figure the model and the controller each
    // hold, because a summary line cannot say where a runaway started.
    let trace = std::env::var_os("PHANTOM_SIM_TRACE").is_some();

    for (index, phase) in phases.iter().enumerate() {
        let phase_start = elapsed;
        let mut phase_delivered = 0u64;
        let mut next_request = Duration::ZERO;
        if index == final_index {
            rec.btl_bw_at_resume = est.bottleneck_bandwidth();
            rec.cwnd_at_resume = est.cwnd();
        }

        let mut into_phase = Duration::ZERO;
        while into_phase < phase.duration {
            let now = start + elapsed;
            let fraction = into_phase.as_secs_f64() / phase.duration.as_secs_f64().max(1e-9);
            let link_bps =
                phase.link_start_bps + (phase.link_end_bps - phase.link_start_bps) * fraction;

            // ── Acknowledgements first: the window they open is what the
            // sender below is allowed to use this tick.
            while returning.front().is_some_and(|r| r.ack_at <= now) {
                let Some(r) = returning.pop_front() else {
                    break;
                };
                let before = est.bottleneck_bandwidth();
                let sample = DeliverySample {
                    delivered_bytes: r.seg.delivered_bytes,
                    delivered_at: r.seg.delivered_at,
                    sent_at: r.seg.sent_at,
                    acked_at: r.ack_at,
                    packet_bytes: r.seg.bytes,
                    is_app_limited: r.seg.app_limited,
                    ack_delay_us: 0,
                    rtt_sampled: true,
                };
                // A self-check on the model, not on the estimator. No sample can
                // honestly measure a rate above the link's, so one that does
                // means the link handed out capacity it never had — which is
                // what an idle bottleneck banking credit looks like, and it
                // reads from the outside exactly like a controller over-stating
                // a path — and the summary line alone would not say so.
                if trace {
                    let delivered_during =
                        est.delivered_bytes() + r.seg.bytes - r.seg.delivered_bytes;
                    let send_elapsed = r.ack_at.duration_since(r.seg.sent_at);
                    let ack_elapsed = r.ack_at.saturating_duration_since(r.seg.delivered_at);
                    let interval = send_elapsed.max(ack_elapsed);
                    let rate = delivered_during as f64 / interval.as_secs_f64().max(1e-9);
                    if rate > 2.0 * link_bps {
                        println!(
                            "      model check at {} ms: a sample reads {rate:.0} B/s on a \
                             {link_bps:.0} B/s link ({delivered_during} B over {interval:?})",
                            elapsed.as_millis()
                        );
                    }
                }
                est.on_ack(sample);
                phase_delivered += r.seg.bytes;
                recent.push_back((r.ack_at, r.seg.bytes));

                // The reference sees exactly what the estimator's gate admits,
                // read back through the published raw-sample accessor rather
                // than recomputed here.
                let raw = est.last_delivery_rate();
                if raw > 0 && (!r.seg.app_limited || raw >= before) {
                    reference.push(r.ack_at, raw);
                    rec.max_reference_entries = rec.max_reference_entries.max(reference.retained());
                }

                let rtt = r.ack_at.duration_since(r.seg.sent_at);
                if index == final_index {
                    rec.max_rtt_in_final_ms = rec.max_rtt_in_final_ms.max(rtt.as_millis() as u64);
                }
            }

            // ── The application offers work.
            match phase.demand {
                Demand::Bulk => owed = owed.max(SEGMENT * 64),
                Demand::RequestResponse { bytes, every } => {
                    if into_phase >= next_request {
                        owed = owed.saturating_add(bytes);
                        next_request += every;
                    }
                }
            }

            // ── The sender: bounded by the window, and by the pacer once the
            // estimator has measured a rate to pace to, which is when
            // `Session::on_packet_acked` switches the pacer on.
            let paced = est.bottleneck_bandwidth() > 0;
            if paced {
                pace_credit += est.pacing_rate() as f64 * TICK.as_secs_f64();
                // A pacer that banked credit while the application was quiet
                // would release the whole backlog as one burst the moment it
                // spoke again, which is the one thing pacing exists to stop.
                // The real one carries at most a small burst, so this does too.
                pace_credit = pace_credit.min(4.0 * SEGMENT as f64);
            } else {
                pace_credit = 0.0;
            }
            let mut ran_dry = false;
            loop {
                let window_room = est.cwnd().saturating_sub(est.inflight_bytes()) >= SEGMENT;
                if !window_room {
                    break;
                }
                if paced && pace_credit < SEGMENT as f64 {
                    break;
                }
                if owed < SEGMENT {
                    ran_dry = true;
                    break;
                }
                owed -= SEGMENT;
                if paced {
                    pace_credit -= SEGMENT as f64;
                }
                est.on_send(SEGMENT);
                queue.push_back(InFlight {
                    bytes: SEGMENT,
                    sent_at: now,
                    delivered_bytes: est.delivered_bytes(),
                    delivered_at: est.delivered_time(),
                    app_limited: est.is_app_limited(),
                });
            }
            if ran_dry {
                // The send pass ended with window to spare and nothing to give,
                // which is the condition `apply_drain_outcome` reports.
                est.note_app_limited_drain();
            }

            // ── The bottleneck serialises whatever it can this tick.
            link_credit += link_bps * TICK.as_secs_f64();
            while queue.front().is_some_and(|s| link_credit >= s.bytes as f64) {
                let Some(seg) = queue.pop_front() else { break };
                link_credit -= seg.bytes as f64;
                let ack_at = now + PROPAGATION + PROPAGATION;
                returning.push_back(Returning { seg, ack_at });
            }
            // An idle link does not bank the capacity it went unused for. Left
            // to accumulate, the credit lets the next burst leave instantly and
            // the model then reports a delivery rate no link ever carried —
            // which reads exactly like an estimator over-stating a path, and is
            // the model doing it instead.
            if queue.is_empty() {
                link_credit = link_credit.min(SEGMENT as f64);
            }

            // ── Readings.
            while recent
                .front()
                .is_some_and(|&(ts, _)| now.duration_since(ts) > Duration::from_secs(1))
            {
                recent.pop_front();
            }
            if index == final_index {
                let into_ms = into_phase.as_millis() as u64;
                if into_ms == 1000 {
                    rec.first_second = phase_delivered;
                }
                if into_ms == 2000 {
                    rec.second_second = phase_delivered;
                }
                if rec.ms_to_ninety_percent.is_none() && into_phase >= Duration::from_secs(1) {
                    let trailing: u64 = recent.iter().map(|&(_, b)| b).sum();
                    if trailing as f64 >= 0.9 * link_bps {
                        rec.ms_to_ninety_percent = Some(into_ms);
                    }
                }
            }
            if trace && into_phase.as_millis().is_multiple_of(250) {
                println!(
                    "   trace {:>6} ms  link {:>8.0}  btl {:>8}  raw {:>8}  cwnd {:>8}  \
                     inflight {:>8}  min_rtt {:>5} ms  ref {:>8}  {}",
                    elapsed.as_millis(),
                    link_bps,
                    est.bottleneck_bandwidth(),
                    est.last_delivery_rate(),
                    est.cwnd(),
                    est.inflight_bytes(),
                    est.min_rtt().as_millis(),
                    reference.head(),
                    est.state()
                );
            }
            let reference_head = reference.head();
            if reference_head > 0 {
                let ratio = est.bottleneck_bandwidth() as f64 / reference_head as f64;
                rec.worst_fidelity = rec.worst_fidelity.min(ratio);
                fidelity_sum += ratio;
                fidelity_n += 1;
            }

            into_phase += TICK;
            elapsed = phase_start + into_phase;
        }

        rec.delivered_per_phase.push(phase_delivered);
    }

    rec.mean_fidelity = if fidelity_n > 0 {
        fidelity_sum / fidelity_n as f64
    } else {
        0.0
    };
    if !rec.worst_fidelity.is_finite() {
        rec.worst_fidelity = 0.0;
    }
    rec
}

fn report(scenario: &str, phases: &[Phase], rec: &Recorded, link_at_resume_bps: f64) {
    println!("── {scenario} ──");
    for (phase, delivered) in phases.iter().zip(rec.delivered_per_phase.iter()) {
        println!(
            "   {:<24} {:>6.1}s  delivered {:>10} B",
            phase.name,
            phase.duration.as_secs_f64(),
            delivered
        );
    }
    println!(
        "   at the final phase's open: btl_bw {} B/s (link {:.0} B/s), cwnd {} B",
        rec.btl_bw_at_resume, link_at_resume_bps, rec.cwnd_at_resume
    );
    println!(
        "   after it opened: +1s {} B, +2s {} B, reached 90% of the link at {}",
        rec.first_second,
        rec.second_second,
        match rec.ms_to_ninety_percent {
            Some(ms) => format!("{ms} ms"),
            None => "never".to_string(),
        }
    );
    println!(
        "   widest round trip in the final phase: {} ms",
        rec.max_rtt_in_final_ms
    );
    println!(
        "   estimate/windowed max: worst {:.2}, mean {:.2}; an unbounded filter \
         held up to {} candidates",
        rec.worst_fidelity, rec.mean_fidelity, rec.max_reference_entries
    );
    println!();
}

// ─── The scenarios ──────────────────────────────────────────────────────────

const MEGABYTE: f64 = 1_000_000.0;

fn run_resume() {
    let phases = [
        Phase {
            name: "bulk",
            duration: Duration::from_secs(6),
            link_start_bps: MEGABYTE,
            link_end_bps: MEGABYTE,
            demand: Demand::Bulk,
        },
        Phase {
            name: "request/response",
            duration: Duration::from_secs(16),
            link_start_bps: MEGABYTE,
            link_end_bps: MEGABYTE,
            demand: Demand::RequestResponse {
                bytes: 4096,
                every: Duration::from_millis(200),
            },
        },
        Phase {
            name: "bulk again",
            duration: Duration::from_secs(12),
            link_start_bps: MEGABYTE,
            link_end_bps: MEGABYTE,
            demand: Demand::Bulk,
        },
    ];
    let rec = run(&phases);
    report(
        "resume: steady link, quiet longer than one horizon",
        &phases,
        &rec,
        MEGABYTE,
    );
}

fn run_degrade() {
    let phases = [
        Phase {
            name: "bulk",
            duration: Duration::from_secs(6),
            link_start_bps: MEGABYTE,
            link_end_bps: MEGABYTE,
            demand: Demand::Bulk,
        },
        Phase {
            name: "request/response",
            duration: Duration::from_secs(16),
            link_start_bps: MEGABYTE,
            link_end_bps: 0.25 * MEGABYTE,
            demand: Demand::RequestResponse {
                bytes: 4096,
                every: Duration::from_millis(200),
            },
        },
        Phase {
            name: "bulk on a slower link",
            duration: Duration::from_secs(12),
            link_start_bps: 0.25 * MEGABYTE,
            link_end_bps: 0.25 * MEGABYTE,
            demand: Demand::Bulk,
        },
    ];
    let rec = run(&phases);
    report(
        "degrade: the link loses three quarters while the application is quiet",
        &phases,
        &rec,
        0.25 * MEGABYTE,
    );
}

fn run_thin() {
    let phases = [
        Phase {
            name: "bulk at full rate",
            duration: Duration::from_secs(2),
            link_start_bps: 4.0 * MEGABYTE,
            link_end_bps: 4.0 * MEGABYTE,
            demand: Demand::Bulk,
        },
        Phase {
            name: "capacity falling",
            duration: Duration::from_secs(3),
            link_start_bps: 4.0 * MEGABYTE,
            link_end_bps: 0.4 * MEGABYTE,
            demand: Demand::Bulk,
        },
        Phase {
            name: "held low",
            duration: Duration::from_secs(9),
            link_start_bps: 0.4 * MEGABYTE,
            link_end_bps: 0.4 * MEGABYTE,
            demand: Demand::Bulk,
        },
        Phase {
            name: "capacity restored",
            duration: Duration::from_secs(8),
            link_start_bps: 4.0 * MEGABYTE,
            link_end_bps: 4.0 * MEGABYTE,
            demand: Demand::Bulk,
        },
    ];
    let rec = run(&phases);
    report(
        "thin: a falling run long enough to fill the filters, held past one horizon",
        &phases,
        &rec,
        4.0 * MEGABYTE,
    );
}
