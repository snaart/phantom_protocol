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
//! With no argument it runs every scenario. Each prints one block of labelled
//! figures; to compare two revisions, run it on both and read the blocks side
//! by side.
//!
//! `PHANTOM_SIM_LOSS_SEED=n` re-runs the scenarios that lose (`noisy`,
//! `collapse`) with independently drawn holes instead of evenly spaced ones.
//! Even spacing is one arrival pattern out of many with the same mean and a
//! controller is sensitive to which it gets, so a figure worth quoting is one
//! that survives a few seeds. It is a check to run, not a default to change:
//! switching it would make every before-and-after comparison noisier.
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
//!   fills within a fraction of a second at these cadences. It is the only
//!   scenario here that can see a length rule at all.
//! - **`noisy`** — a link that drops a fixed fraction of what it carries no
//!   matter how gently it is driven, swept from none to a fifth, against a
//!   bounded queue. The other three lose nothing at all, so nothing in them
//!   ever reaches the loss response; this is the only scenario that exercises
//!   it. The shape is the reference WAN path's, whose raw-UDP control drops
//!   between one and eight percent at rates far below the ceiling it later
//!   establishes — loss that is a property of the path rather than a report on
//!   the sender's rate. Read the rung's percentage of the link and the round
//!   trip at which it reached nine tenths: a controller that ends a rung far
//!   under the link, or never reaches it, is being held down by its own loss
//!   response rather than by the path.
//! - **`collapse`** — capacity falls fourfold behind a one-BDP buffer and stays
//!   down. The opposite of `noisy` and the reason both exist: there the loss
//!   says nothing about the sender's rate, here every loss is the queue
//!   overflowing and says everything. A change that relaxes the loss response
//!   has to be read against this before its improvement on `noisy` counts.
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

/// Which arrival pattern the noise term uses, for every phase in this run.
///
/// A process-wide reading of `PHANTOM_SIM_LOSS_SEED` rather than a per-scenario
/// argument, because the question it answers is about a whole sweep: "does the
/// figure I am about to quote survive a different draw of the same rate?". A
/// seed makes every phase independent-with-that-seed; absent, everything is
/// evenly spaced and the run is the reproducible one.
fn loss_model() -> LossModel {
    match std::env::var("PHANTOM_SIM_LOSS_SEED") {
        Ok(v) => match v.trim().parse::<u64>() {
            Ok(seed) => LossModel::Independent(seed),
            Err(_) => {
                eprintln!(
                    "PHANTOM_SIM_LOSS_SEED={v:?} is not a number; using the even \
                     spacing this run would have had without it"
                );
                LossModel::Even
            }
        },
        Err(_) => LossModel::Even,
    }
}

fn main() {
    let mut args = std::env::args().skip(1);
    let which = args.next();
    match which.as_deref() {
        None | Some("all") => {
            run_resume();
            run_degrade();
            run_thin();
            run_noisy();
            run_collapse();
        }
        Some("resume") => run_resume(),
        Some("degrade") => run_degrade(),
        Some("thin") => run_thin(),
        Some("noisy") => run_noisy(),
        Some("collapse") => run_collapse(),
        Some(other) => {
            eprintln!("unknown scenario {other:?}; expected resume, degrade, thin, noisy, collapse or all");
        }
    }
}

/// SplitMix64, so an `Independent` run is reproducible from its seed alone and
/// this file still needs no dependency. The same generator the crate's own
/// fault-injection harness uses, for the same reason.
fn split_mix_64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

// ─── The model ──────────────────────────────────────────────────────────────

/// A segment on the wire or in the bottleneck's queue.
struct InFlight {
    bytes: u64,
    sent_at: Instant,
    /// This transmission repairs an earlier one. The congestion signal is
    /// raised once per *hole*, so losing a repair must not raise it a second
    /// time — the transport gates `on_packet_lost` on `seg.first_retransmit`
    /// for exactly this reason, and `on_loss`'s own documentation says why:
    /// counting copies reads a stalled path as a maximally congested one.
    is_repair: bool,
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
    /// The link dropped this one. It still travels the return path, because a
    /// sender learns of a hole from the acknowledgement that names its
    /// successors — declaring the loss the instant the model drops the segment
    /// would hand the controller knowledge no real one has until a round trip
    /// has passed, and the whole question here is how the controller behaves
    /// over round trips.
    lost: bool,
}

/// How a phase's noise term decides which segments to drop.
#[derive(Clone, Copy, PartialEq, Eq)]
enum LossModel {
    /// Every `1/p`-th segment, remainder carried so the rate is exact. The
    /// default: reproducible, and the harshest honest reading of a fixed rate
    /// because it never clusters and so never hands the controller a quiet
    /// stretch to recover in.
    Even,
    /// Independent draws at probability `p`, from a seeded generator. Same mean,
    /// clustered arrivals, and a different answer — which is the point of
    /// having it.
    Independent(u64),
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
    /// Segments in a thousand the link drops for reasons that have nothing to
    /// do with how hard it is being driven — a radio's error rate, a middlebox
    /// under someone else's load. Dropped *after* the queue admits them, so the
    /// fraction stays what it says it is at every offered rate, which is the
    /// whole point: a loss that does not vary with the sender's rate carries no
    /// information about where the knee is.
    ///
    /// Zero on every scenario that predates it, so their figures are unchanged.
    loss_permille: u64,
    /// Bytes the bottleneck will hold before it starts dropping. `None` is an
    /// unbounded queue — which is what the first three scenarios ran against,
    /// and keeping it lets their readings stay comparable across this change.
    queue_limit_bytes: Option<u64>,
    /// How the noise is spread over the segments it drops.
    ///
    /// Even spacing is the reproducible choice and the default, but it is *one*
    /// arrival pattern out of many that share a mean, and a controller can be
    /// sensitive to which one it gets — a burst of four consecutive drops and
    /// four drops spread over four hundred segments are the same rate and not
    /// the same event. `PHANTOM_SIM_LOSS_SEED=n` re-runs the sweep with
    /// independent draws instead, so a figure can be checked for whether it
    /// survives the choice. It is a check to run, not a default to change:
    /// switching the default would make every before-and-after comparison
    /// noisier for no gain.
    loss_model: LossModel,
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
    /// Segments the link dropped, and how many of those the queue dropped for
    /// being full rather than the noise term dropping them. The split matters
    /// because only the second kind is a signal about the sender's rate.
    segments_dropped: u64,
    segments_dropped_by_a_full_queue: u64,
    /// Segments handed to the link, counting each copy of a repaired one.
    segments_sent: u64,
    /// Mean bytes standing in the bottleneck's queue over the final phase, and
    /// the widest it got. This is what a loss response is *for*: a window held
    /// above what the path can carry shows up here first and as latency second.
    final_phase_queue_mean: f64,
    final_phase_queue_max: u64,
    /// The estimator's reading at the end of the run, and the window it implies
    /// as a multiple of the bandwidth-delay product. A window pinned at exactly
    /// `INFLIGHT_HI_FLOOR_GAIN` is the loss response holding it there.
    final_btl_bw: u64,
    final_cwnd_over_bdp: f64,
}

fn run(phases: &[Phase]) -> Recorded {
    let mut est = BandwidthEstimator::new();
    // One clock read for the whole model, taken from the estimator rather than
    // beside it. Two reads put a sub-microsecond gap between the two origins,
    // and that gap is not inert: it lands in the first segments' delivery
    // timestamps, enters the first rate samples through the interval those
    // samples divide by, and perturbs the trajectory from there. Three
    // consecutive runs of one binary produced three different outputs. A model
    // whose own documentation calls the unseeded run the reproducible one has
    // to be reproducible, and this is the whole of what it took.
    let start = est.delivered_time();
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
    // Segments whose loss has been declared and which are waiting to go out
    // again. The model repairs everything it loses, exactly as the ARQ does;
    // without that the flight arithmetic never gives the bytes back and the
    // window closes on segments nobody is still waiting for.
    let mut awaiting_repair = 0u64;
    // Carries the remainder of the per-mille loss rate between segments, so the
    // rung is the rate it says it is rather than the rate integer division
    // rounds it to.
    let mut noise_accumulator = 0u64;
    // Generator state for `LossModel::Independent`, seeded per run.
    let mut loss_rng = 0u64;
    // Bytes queued at the bottleneck, tracked alongside the queue so a limit can
    // be enforced without walking it.
    let mut queued_bytes = 0u64;
    // Time-average of that, over the final phase only.
    let mut queue_sum = 0.0f64;
    let mut queue_ticks = 0u64;
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
                if r.lost {
                    // A hole, learned about a round trip after the drop. The
                    // copy that repairs it is sent from the loop below; the
                    // congestion signal is raised only for a segment's *first*
                    // transmission, matching the transport's own
                    // `seg.first_retransmit` gate. A lost repair still has to be
                    // repaired — it just is not counted as a second hole.
                    if !r.seg.is_repair {
                        est.on_loss(r.seg.bytes);
                    }
                    awaiting_repair += 1;
                    continue;
                }
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
                // A repair goes before new data, which is what the drain does:
                // an unrepaired hole blocks the receiver's in-order delivery, so
                // new bytes sent past it buy nothing until it is filled.
                let repairing = awaiting_repair > 0;
                // Repairs are exempt from the window, exactly as the transport
                // has them: a copy replaces a transmission that is already
                // counted against the window, so charging it again would let a
                // closed window block the very send that reopens it. Modelling
                // it the other way deadlocks — outstanding bytes that only a
                // repair can retire, and a window too small to send one — and
                // the deadlock is the model's, not the controller's.
                let window_room = est.cwnd().saturating_sub(est.inflight_bytes()) >= SEGMENT;
                if !window_room && !repairing {
                    break;
                }
                if paced && pace_credit < SEGMENT as f64 {
                    break;
                }
                if !repairing && owed < SEGMENT {
                    ran_dry = true;
                    break;
                }
                if repairing {
                    awaiting_repair -= 1;
                } else {
                    owed -= SEGMENT;
                }
                if paced {
                    pace_credit -= SEGMENT as f64;
                }
                est.on_send(SEGMENT);
                if repairing {
                    // The copy's own `on_send` above added its bytes; the
                    // transmission it replaces is no longer outstanding. The
                    // congestion signal was raised when the hole was declared,
                    // not here.
                    est.on_retransmit(SEGMENT);
                }
                rec.segments_sent += 1;
                let seg = InFlight {
                    bytes: SEGMENT,
                    sent_at: now,
                    is_repair: repairing,
                    delivered_bytes: est.delivered_bytes(),
                    delivered_at: est.delivered_time(),
                    app_limited: est.is_app_limited(),
                };
                let queue_full = phase
                    .queue_limit_bytes
                    .is_some_and(|limit| queued_bytes + SEGMENT > limit);
                if queue_full {
                    rec.segments_dropped += 1;
                    rec.segments_dropped_by_a_full_queue += 1;
                    returning.push_back(Returning {
                        seg,
                        ack_at: now + PROPAGATION + PROPAGATION,
                        lost: true,
                    });
                } else {
                    queue.push_back(seg);
                    queued_bytes += SEGMENT;
                }
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
                queued_bytes = queued_bytes.saturating_sub(seg.bytes);
                // Bresenham rather than a stride, so the rung runs at the rate
                // it is labelled with. `admitted % (1000 / permille)` truncates
                // the divisor — at 150 per mille that is one segment in six,
                // 16.7%, under a heading that says 15% — and the difference
                // moves the answer materially. The accumulator carries the
                // remainder instead, reproducing any per-mille figure exactly.
                //
                // Still deterministic and still evenly spaced. Even spacing is
                // not neutral: it is one draw from a distribution whose spread
                // across arrival patterns is wide, so a rung's figure is a
                // comparison between two builds and never a reading about a
                // path.
                let noise_dropped = match phase.loss_model {
                    LossModel::Even => {
                        noise_accumulator += phase.loss_permille;
                        let hit = noise_accumulator >= 1000;
                        if hit {
                            noise_accumulator -= 1000;
                        }
                        hit
                    }
                    LossModel::Independent(seed) => {
                        if loss_rng == 0 {
                            // Only a zero state is degenerate for
                            // SplitMix64, so that is the only value that needs
                            // moving. Forcing the low bit instead would fold
                            // every even seed onto its odd neighbour and leave
                            // a sweep of 1..8 sampling four processes while
                            // reporting eight.
                            loss_rng = if seed == 0 { 1 } else { seed };
                        }
                        phase.loss_permille > 0
                            && split_mix_64(&mut loss_rng) % 1000 < phase.loss_permille
                    }
                };
                if noise_dropped {
                    rec.segments_dropped += 1;
                }
                let ack_at = now + PROPAGATION + PROPAGATION;
                returning.push_back(Returning {
                    seg,
                    ack_at,
                    lost: noise_dropped,
                });
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
                // Sampled once a tick, so the mean below is a time average of
                // the standing queue rather than an average over arrivals.
                queue_sum += queued_bytes as f64;
                queue_ticks += 1;
                rec.final_phase_queue_max = rec.final_phase_queue_max.max(queued_bytes);
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

    rec.final_phase_queue_mean = if queue_ticks > 0 {
        queue_sum / queue_ticks as f64
    } else {
        0.0
    };
    rec.final_btl_bw = est.bottleneck_bandwidth();
    rec.final_cwnd_over_bdp = est.cwnd() as f64 / est.bdp().max(1) as f64;
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
    if rec.segments_dropped > 0 {
        println!(
            "   link dropped {} of {} segments ({:.1}%), {} of them for a full queue; \
             the run ended holding {} B/s with cwnd at {:.2} BDP",
            rec.segments_dropped,
            rec.segments_sent,
            100.0 * rec.segments_dropped as f64 / rec.segments_sent.max(1) as f64,
            rec.segments_dropped_by_a_full_queue,
            rec.final_btl_bw,
            rec.final_cwnd_over_bdp,
        );
    }
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
            loss_permille: 0,
            queue_limit_bytes: None,
            loss_model: loss_model(),
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
            loss_permille: 0,
            queue_limit_bytes: None,
            loss_model: loss_model(),
        },
        Phase {
            name: "bulk again",
            duration: Duration::from_secs(12),
            link_start_bps: MEGABYTE,
            link_end_bps: MEGABYTE,
            demand: Demand::Bulk,
            loss_permille: 0,
            queue_limit_bytes: None,
            loss_model: loss_model(),
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
            loss_permille: 0,
            queue_limit_bytes: None,
            loss_model: loss_model(),
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
            loss_permille: 0,
            queue_limit_bytes: None,
            loss_model: loss_model(),
        },
        Phase {
            name: "bulk on a slower link",
            duration: Duration::from_secs(12),
            link_start_bps: 0.25 * MEGABYTE,
            link_end_bps: 0.25 * MEGABYTE,
            demand: Demand::Bulk,
            loss_permille: 0,
            queue_limit_bytes: None,
            loss_model: loss_model(),
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

/// A link that drops a fixed fraction no matter how gently it is driven, swept
/// from none to a fifth.
///
/// The shape comes from the reference WAN path, where the raw-UDP control drops
/// between one and eight percent at rates far below the ceiling it later
/// establishes — loss that is a property of the path rather than a report on
/// the sender's rate. What a run has to answer is whether the controller finds
/// the link's capacity anyway, and how long it takes: a rung that ends far
/// under the link, or that never reaches it, is the loss response holding the
/// window down rather than the path refusing to carry.
///
/// The queue is bounded here, unlike the first three scenarios, but **it does
/// not bind and is not what makes this scenario work.** Every rung from one per
/// mille upward reports zero queue-full drops, and depths from twenty
/// milliseconds to four hundred give the same figures: a sender this bound is
/// already holding below the link never fills the buffer. The limit is kept
/// because a scenario about loss should not have an infinite queue hiding
/// behind it, not because it is doing anything. Nor does it let the sweep tell a
/// controller that ignores real congestion from one that handles it: there is no
/// real congestion here to ignore. That job belongs to `collapse`, and that is
/// why `collapse` exists.
///
/// **The top rung is degenerate.** At a fifth the estimate settles at a small
/// multiple of `pacing_rate_floor` — four packets per minimum round trip, the
/// bootstrap floor under the pacer — with the connection delivering a few dozen
/// segments a second. Both builds report one per cent of the link there, and
/// what the rung says is "this run fell into that attractor", not how the two
/// compare. Read the two to ten per cent band, which is where the reference
/// path's own control sits.
fn run_noisy() {
    const LINK: f64 = 4.0 * MEGABYTE;
    for permille in [0u64, 10, 20, 50, 100, 150, 200] {
        let phases = [Phase {
            name: "bulk against a lossy link",
            duration: Duration::from_secs(60),
            link_start_bps: LINK,
            link_end_bps: LINK,
            demand: Demand::Bulk,
            loss_permille: permille,
            queue_limit_bytes: Some((LINK * 0.2) as u64),
            loss_model: loss_model(),
        }];
        let rec = run(&phases);
        let delivered = rec.delivered_per_phase.first().copied().unwrap_or(0);
        let goodput = delivered as f64 / 60.0;
        println!(
            "── noisy {:>4.1}% ── goodput {:>9.0} B/s ({:>3.0}% of the link), \
             estimate {:>9} B/s, cwnd {:.2} BDP, dropped {:>5} ({:>4.1}%, {} queue-full), \
             reached 90% at {}",
            permille as f64 / 10.0,
            goodput,
            100.0 * goodput / LINK,
            rec.final_btl_bw,
            rec.final_cwnd_over_bdp,
            rec.segments_dropped,
            100.0 * rec.segments_dropped as f64 / rec.segments_sent.max(1) as f64,
            rec.segments_dropped_by_a_full_queue,
            match rec.ms_to_ninety_percent {
                Some(ms) => format!("{ms} ms"),
                None => "never".to_string(),
            }
        );
    }
    println!();
}

/// Capacity falls fourfold behind a real buffer and stays down.
///
/// Every loss here is the queue overflowing, which makes this the opposite of
/// `noisy` and the reason both have to exist: there the loss says nothing about
/// the sender's rate, here it says everything. A loss response is bought to
/// handle *this* shape, so any change that relaxes it has to be read against
/// what this scenario reports — the standing queue over the low phase, and how
/// many segments the buffer refused — before its improvement on `noisy` counts
/// for anything.
///
/// The buffer is one bandwidth-delay product at the low rate, which is the
/// conventional sizing and the depth at which a window held above the path
/// shows up as loss rather than only as latency.
fn run_collapse() {
    const HIGH: f64 = 4.0 * MEGABYTE;
    const LOW: f64 = MEGABYTE;
    // One BDP at the low rate: 1 MB/s over the modelled 200 ms round trip.
    const BUFFER: u64 = 200_000;
    let phases = [
        Phase {
            name: "bulk at full rate",
            duration: Duration::from_secs(6),
            link_start_bps: HIGH,
            link_end_bps: HIGH,
            demand: Demand::Bulk,
            loss_permille: 0,
            queue_limit_bytes: Some(BUFFER),
            loss_model: loss_model(),
        },
        Phase {
            name: "capacity down fourfold",
            duration: Duration::from_secs(40),
            link_start_bps: LOW,
            link_end_bps: LOW,
            demand: Demand::Bulk,
            loss_permille: 0,
            queue_limit_bytes: Some(BUFFER),
            loss_model: loss_model(),
        },
    ];
    let rec = run(&phases);
    let low_bdp = LOW * 0.2;
    println!("── collapse: capacity falls fourfold behind a {BUFFER} B buffer ──");
    println!(
        "   low phase: delivered {} B ({:.0}% of the link), standing queue mean {:.0} B \
         ({:.2} BDP), max {} B",
        rec.delivered_per_phase.get(1).copied().unwrap_or(0),
        100.0 * rec.delivered_per_phase.get(1).copied().unwrap_or(0) as f64 / (40.0 * LOW),
        rec.final_phase_queue_mean,
        rec.final_phase_queue_mean / low_bdp,
        rec.final_phase_queue_max
    );
    println!(
        "   the buffer refused {} of {} segments ({:.1}%); widest round trip {} ms; \
         the run ended holding {} B/s with cwnd at {:.2} BDP",
        rec.segments_dropped_by_a_full_queue,
        rec.segments_sent,
        100.0 * rec.segments_dropped_by_a_full_queue as f64 / rec.segments_sent.max(1) as f64,
        rec.max_rtt_in_final_ms,
        rec.final_btl_bw,
        rec.final_cwnd_over_bdp
    );
    println!();
}

fn run_thin() {
    let phases = [
        Phase {
            name: "bulk at full rate",
            duration: Duration::from_secs(2),
            link_start_bps: 4.0 * MEGABYTE,
            link_end_bps: 4.0 * MEGABYTE,
            demand: Demand::Bulk,
            loss_permille: 0,
            queue_limit_bytes: None,
            loss_model: loss_model(),
        },
        Phase {
            name: "capacity falling",
            duration: Duration::from_secs(3),
            link_start_bps: 4.0 * MEGABYTE,
            link_end_bps: 0.4 * MEGABYTE,
            demand: Demand::Bulk,
            loss_permille: 0,
            queue_limit_bytes: None,
            loss_model: loss_model(),
        },
        Phase {
            name: "held low",
            duration: Duration::from_secs(9),
            link_start_bps: 0.4 * MEGABYTE,
            link_end_bps: 0.4 * MEGABYTE,
            demand: Demand::Bulk,
            loss_permille: 0,
            queue_limit_bytes: None,
            loss_model: loss_model(),
        },
        Phase {
            name: "capacity restored",
            duration: Duration::from_secs(8),
            link_start_bps: 4.0 * MEGABYTE,
            link_end_bps: 4.0 * MEGABYTE,
            demand: Demand::Bulk,
            loss_permille: 0,
            queue_limit_bytes: None,
            loss_model: loss_model(),
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
