//! BBR-like Bandwidth Estimator
//!
//! Implements a simplified BBR (Bottleneck Bandwidth and Round-trip propagation time)
//! congestion-control state machine. It consumes a `DeliverySample` per ACKed packet
//! (fed from the PhantomUDP reliable-stream ACK path) and produces a recommended pacing
//! rate (bytes/sec) plus a congestion window — the inputs the [`Pacer`](super::pacer)
//! and the send loop use to decide how fast to put bytes on the wire.
//!
//! # BBR States
//!
//! ```text
//!   ┌─────────┐        ┌──────────┐        ┌────────┐
//!   │ Startup │───────▶│  Drain   │───────▶│ ProbeBW│
//!   └─────────┘        └──────────┘        └────────┘
//!                         ▲    │              │
//!                         │    └──────────────┘
//!                         │       ▲
//!                      ┌──┴───────┴──┐
//!                      │  ProbeRTT   │  (every 10s for 200ms)
//!                      └─────────────┘
//! ```
//!
//! - **Startup:** Double sending rate exponentially until bottleneck bandwidth is found —
//!   i.e. until three consecutive *round trips* fail to grow the estimate by 25%
//! - **Drain:** Reduce rate until inflight ≤ BDP (drain queues built during Startup)
//! - **ProbeBW:** Cycle through pacing gains (1.25, 0.75, 1.0, 1.0) to probe bandwidth,
//!   one gain per *round trip*
//!
//! Both of those are measured in round trips, and a round trip here is BBR's
//! packet-timed one: it closes when an acknowledgement arrives for a packet that
//! was sent at or beyond the delivered-bytes mark taken when the round opened
//! (`BandwidthEstimator::update_round` carries the rule). Nothing in this file counts
//! acknowledgements as a proxy for it — dozens land inside one round trip, and a
//! controller scaled that way leaves Startup and spins its gain cycle before it
//! has probed anything at all.
//! - **ProbeRTT:** Every 10s, reduce CWND to 4 packets for 200ms to measure true min RTT
//! - **FastRecovery:** Entered on explicit packet loss (BBRv3-style) — back off pacing to
//!   0.5x and tighten CWND to 1x BDP until the pipe drains; not shown in the diagram above
//!   because any state except Startup/ProbeRTT can enter it on loss.
//!
//! # Integration
//!
//! The estimator feeds the [`Pacer`](super::pacer::Pacer) with target rates; the pacer
//! then meters bytes onto the PhantomUDP socket:
//! ```text
//!   BandwidthEstimator ──rate──▶ Pacer ──paced_send──▶ UdpClientTransport / UdpServerTransport
//! ```

use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// BBR state machine states
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BbrState {
    /// Exponentially probe for bandwidth
    Startup,
    /// Probe for more bandwidth (cycle through pacing gains)
    ProbeBW,
    /// Drain queues that built up during Startup
    Drain,
    /// Probe for shorter RTT (reduce CWND to 4 packets for 200ms)
    ProbeRTT,
    /// Explicit packet loss detected — reduce rate and CWND proportionally
    FastRecovery,
}

impl BbrState {
    /// Stable lowercase name, for logs and recorded artifacts.
    ///
    /// Deliberately not `Debug`: a recorded time series outlives the enum's
    /// formatting, and a derive change should not silently rename a column.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Startup => "startup",
            Self::ProbeBW => "probe_bw",
            Self::Drain => "drain",
            Self::ProbeRTT => "probe_rtt",
            Self::FastRecovery => "fast_recovery",
        }
    }
}

impl core::fmt::Display for BbrState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A single delivery sample (attached to each ACKed packet)
#[derive(Debug, Clone, Copy)]
pub struct DeliverySample {
    /// Bytes delivered at time of sending
    pub delivered_bytes: u64,
    /// When [`Self::delivered_bytes`] was reached — i.e. the instant the
    /// connection's delivered counter last advanced, as of this packet's send.
    ///
    /// Together with the counter value above this pins down *both* ends of the
    /// interval the sample measures: `delivered_bytes` bytes had been delivered
    /// by `delivered_at`, and the total has since grown to whatever it is when
    /// this acknowledgement lands. Without the timestamp only the numerator of
    /// the rate is known and the denominator has to be guessed from the packet's
    /// own round trip — which is how a burst of acknowledgements ends up read as
    /// a whole window delivered inside one packet's RTT.
    pub delivered_at: Instant,
    /// Timestamp when packet was sent
    pub sent_at: Instant,
    /// Timestamp when ACK was received
    pub acked_at: Instant,
    /// Bytes in this packet
    pub packet_bytes: u64,
    /// Whether the sender was application-limited when this packet was sent
    pub is_app_limited: bool,
    /// ACK delay reported by the receiver (microseconds) — the time it says it
    /// spent between receiving the packet and sending this acknowledgement.
    ///
    /// This is the one figure in the sample the local endpoint did not measure,
    /// so [`BandwidthEstimator::on_ack`] treats it as untrusted input rather
    /// than as a measurement: it is bounded by the observed round trip, and
    /// subtracted only where RFC 9002 §5.3 allows, which is where the result
    /// still lands at or above the running `min_rtt`. See the commentary there
    /// for why an unconditional subtraction let a peer choose the local
    /// congestion window.
    pub ack_delay_us: u64,
    /// Whether this sample's round trip is a usable RTT measurement — Karn's
    /// algorithm. `false` for a segment that had been retransmitted before this
    /// acknowledgement arrived.
    ///
    /// The sender restamps `sent_at` when it resends, so an acknowledgement for
    /// the *original* transmission that lands just after the copy went out is
    /// measured from the copy and reads as microseconds. Nothing in the
    /// acknowledgement identifies which of the two it answers, so the figure is
    /// not a round trip at all. [`BandwidthEstimator::on_ack`] keeps it out of
    /// the min-RTT filter; the delivery-rate half of the sample is unaffected
    /// (its numerator and denominator are restamped together, so it still
    /// measures bytes delivered since the resend over the time since the resend).
    pub rtt_sampled: bool,
}

/// Sliding window to track min/max of a value
#[derive(Debug)]
struct WindowFilter {
    window: VecDeque<(Instant, u64)>,
    window_size: Duration,
}

impl WindowFilter {
    fn new(window_size: Duration) -> Self {
        Self {
            window: VecDeque::new(),
            window_size,
        }
    }

    fn update_max(&mut self, now: Instant, value: u64) -> u64 {
        // Remove expired entries
        while let Some(&(ts, _)) = self.window.front() {
            if now.duration_since(ts) > self.window_size {
                self.window.pop_front();
            } else {
                break;
            }
        }
        // Remove entries smaller than the new value (they're dominated)
        while let Some(&(_, v)) = self.window.back() {
            if v <= value {
                self.window.pop_back();
            } else {
                break;
            }
        }
        self.window.push_back((now, value));
        // The maximum is always at the front
        self.window.front().map(|&(_, v)| v).unwrap_or(value)
    }

    fn update_min(&mut self, now: Instant, value: u64) -> u64 {
        while let Some(&(ts, _)) = self.window.front() {
            if now.duration_since(ts) > self.window_size {
                self.window.pop_front();
            } else {
                break;
            }
        }
        while let Some(&(_, v)) = self.window.back() {
            if v >= value {
                self.window.pop_back();
            } else {
                break;
            }
        }
        self.window.push_back((now, value));
        self.window.front().map(|&(_, v)| v).unwrap_or(value)
    }
}

// ─── Constants ──────────────────────────────────────────────────────────────

/// Probe cycle gains for ProbeBW phase (BBR cycle: 1.25, 0.75, 1.0, 1.0)
const PROBE_BW_GAINS: [f64; 4] = [1.25, 0.75, 1.0, 1.0];

/// Startup growth threshold — if BW growth < 25%, consider pipe filled
const STARTUP_GROWTH_THRESHOLD: f64 = 0.25;

/// Rounds without growth before exiting Startup
const STARTUP_ROUNDS_LIMIT: u32 = 3;

/// ProbeRTT interval — enter ProbeRTT every 10 seconds
const PROBE_RTT_INTERVAL: Duration = Duration::from_secs(10);

/// ProbeRTT duration — stay in ProbeRTT for 200ms
const PROBE_RTT_DURATION: Duration = Duration::from_millis(200);

/// Minimum CWND in ProbeRTT mode (4 packets)
const PROBE_RTT_CWND_PACKETS: u64 = 4;

/// Minimum packet size assumption (bytes)
const MIN_PACKET_SIZE: u64 = 1400;

/// FastRecovery: pacing gain during loss recovery (BBRv3: backs off to 0.5)
const FAST_RECOVERY_PACING_GAIN: f64 = 0.5;

/// FastRecovery: exit when inflight < BDP * this fraction  
const FAST_RECOVERY_EXIT_FRACTION: f64 = 1.0;

// ─── Estimator ──────────────────────────────────────────────────────────────

/// BBR-like Bandwidth Estimator
pub struct BandwidthEstimator {
    /// Current BBR state
    state: BbrState,
    /// Estimated bottleneck bandwidth (bytes/sec)
    btl_bw: u64,
    /// Minimum observed RTT
    min_rtt: Duration,
    /// Sliding-window max filter for bandwidth (10-second window — see `new`)
    bw_filter: WindowFilter,
    /// Sliding-window min filter for RTT (10-second window — see `new`)
    rtt_filter: WindowFilter,
    /// Whether [`Self::rtt_filter`] has ever been fed a sample — i.e. whether
    /// [`Self::min_rtt`] reflects an observation rather than the opening guess.
    ///
    /// RFC 9002 §5.2: "min_rtt MUST be set to the latest_rtt on the first RTT
    /// sample." The ack-delay guard in [`Self::on_ack`] compares against
    /// `min_rtt`, and until a round trip has actually been timed that value is
    /// a 100 ms placeholder nobody measured — a guard anchored on it would be
    /// defending a number the peer could subtract its way down to on the very
    /// first acknowledgement.
    rtt_filter_seeded: bool,
    /// Total bytes delivered (monotonically increasing)
    delivered_bytes: u64,
    /// When [`Self::delivered_bytes`] last advanced. Read back out through
    /// [`Self::delivered_time`] and stamped onto every outgoing segment, so the
    /// acknowledgement can be divided by the interval the delivery actually
    /// took rather than by the acknowledged packet's own round trip.
    last_delivery: Instant,
    /// Pacing gain multiplier (1.0 = 100%, 1.25 = probe, 0.75 = drain)
    pacing_gain: f64,
    /// CWND gain multiplier
    cwnd_gain: f64,
    /// Packet-timed round trips elapsed. Advances in [`Self::update_round`] and
    /// nowhere else, so every consumer of it — the Startup exit test, the
    /// ProbeBW gain cycle — is measured in round trips.
    round_count: u32,
    /// The delivered-bytes mark that closes the current round trip. An
    /// acknowledgement for a packet that was *sent* at or beyond this mark is
    /// answering data put on the wire after the round opened, which means a
    /// full round trip has elapsed. See [`Self::update_round`].
    next_round_delivered: u64,
    /// Whether the acknowledgement currently being processed opened a new round
    /// trip. Read by the state machine, which must judge the connection once per
    /// round rather than once per packet.
    round_start: bool,
    /// Whether we've found the bottleneck bandwidth
    filled_pipe: bool,
    /// The bandwidth plateau Startup is trying to beat — BBR's `full_bw`. Raised
    /// only when a round delivers at least [`STARTUP_GROWTH_THRESHOLD`] more
    /// than it, so a path that keeps growing steadily but by less than a quarter
    /// per round is not mistaken for one that has stopped growing.
    full_bw: u64,
    /// Consecutive round trips whose bandwidth failed to beat [`Self::full_bw`]
    /// by the growth threshold — BBR's `full_bw_count`, the Startup exit
    /// condition.
    rounds_without_growth: u32,

    // ── Inflight tracking ──
    /// Current bytes in flight
    inflight_bytes: u64,

    // ── ProbeRTT timer ──
    /// Timestamp of last ProbeRTT exit (or Startup start)
    last_probe_rtt_time: Instant,
    /// When we entered ProbeRTT (for duration tracking)
    probe_rtt_entered: Option<Instant>,
    /// State to return to after ProbeRTT
    prior_state: BbrState,

    // ── App-limited detection ──
    /// Whether the sender is currently application-limited
    app_limited: bool,
    /// Delivered bytes at the time app-limited was last set
    app_limited_at_delivered: u64,

    // ── FastRecovery ──
    /// When we entered FastRecovery (for duration-based exit)
    fast_recovery_entered: Option<Instant>,
    /// Total bytes lost during this recovery window
    recovery_lost_bytes: u64,
}

impl BandwidthEstimator {
    /// Create a new estimator starting in Startup state.
    pub fn new() -> Self {
        let now = Instant::now();
        Self {
            state: BbrState::Startup,
            btl_bw: 0,
            min_rtt: Duration::from_millis(100), // Conservative initial RTT
            bw_filter: WindowFilter::new(Duration::from_secs(10)),
            rtt_filter: WindowFilter::new(Duration::from_secs(10)),
            rtt_filter_seeded: false,
            delivered_bytes: 0,
            last_delivery: now,
            pacing_gain: 2.0, // Startup: double the rate
            cwnd_gain: 2.0,
            round_count: 0,
            next_round_delivered: 0,
            round_start: false,
            filled_pipe: false,
            full_bw: 0,
            rounds_without_growth: 0,
            inflight_bytes: 0,
            last_probe_rtt_time: now,
            probe_rtt_entered: None,
            prior_state: BbrState::ProbeBW,
            app_limited: false,
            app_limited_at_delivered: 0,
            fast_recovery_entered: None,
            recovery_lost_bytes: 0,
        }
    }

    // ── Public API ──────────────────────────────────────────────────────────

    /// Notify the estimator that `bytes` were sent (increases inflight).
    pub fn on_send(&mut self, bytes: u64) {
        self.inflight_bytes = self.inflight_bytes.saturating_add(bytes);
    }

    /// Process an ACK and update bandwidth estimates.
    ///
    /// Returns the new recommended pacing rate (bytes/sec).
    pub fn on_ack(&mut self, sample: DeliverySample) -> u64 {
        let now = sample.acked_at;

        // Update inflight tracking
        self.inflight_bytes = self.inflight_bytes.saturating_sub(sample.packet_bytes);

        // Update delivered bytes counter
        self.delivered_bytes += sample.packet_bytes;
        self.last_delivery = now;

        // Has a round trip elapsed? Everything the state machine decides is
        // scaled in round trips, so this has to be answered before it runs.
        self.update_round(sample.delivered_bytes);

        // `send_elapsed` is the full round trip, timed entirely by this
        // endpoint's own clock: `sent_at` and `acked_at` are both its own
        // readings. It doubles as the lower bound on the delivery-rate interval
        // further down.
        let send_elapsed = sample.acked_at.duration_since(sample.sent_at);

        // ── The peer's reported ack delay ───────────────────────────────────
        //
        // `sample.ack_delay_us` rides in `Sack`, inside the AEAD plaintext — it
        // is the receiver's claim about how long it held the acknowledgement
        // before sending it, and it is the only figure in this sample the local
        // side did not measure.
        //
        // Subtracting it unconditionally, which is what this used to do, put
        // the peer in charge of the local congestion window. `cwnd = 2 × btl_bw
        // × min_rtt`, floored at 5600 bytes, and the consumer below is a
        // *minimum* filter: `update_min` back-pops every entry at or above a
        // new value, so one poisoned sample does not merely sit at the head for
        // the window duration — it discards the accumulated honest history and
        // restarts the expiry clock. A peer reporting 199.9 ms of delay on a
        // 200 ms path drives the sample to 100 µs and pins the window on its
        // floor for as long as it keeps reporting. Being inside the AEAD means
        // an on-path attacker cannot reach it, but the authenticated peer can,
        // and "a malicious or defective server throttles every client it
        // serves" is a real hazard rather than a theoretical one.
        //
        // RFC 9002 §5.2 states the rule for the minimum plainly: an endpoint
        // "uses only locally observed times in computing the min_rtt and does
        // not adjust for acknowledgment delays reported by the peer", and
        // "min_rtt MUST be set to the latest_rtt on the first RTT sample".
        // §5.3 then permits the adjustment only where it cannot undercut that
        // minimum — "MUST NOT subtract the acknowledgment delay from the RTT
        // sample if the resulting value is smaller than the min_rtt" — which is
        // the published pseudocode:
        //
        //     adjusted_rtt = latest_rtt
        //     if (latest_rtt >= min_rtt + ack_delay):
        //       adjusted_rtt = latest_rtt - ack_delay
        //
        // The invariant that buys, inductively: every value entering the filter
        // is either a raw locally observed round trip, or a value at or above
        // the filter's current minimum. A peer-supplied number can therefore
        // never lower `min_rtt` below what this endpoint's own clock saw. The
        // worst a hostile report achieves is declining to lower it further —
        // exactly what reporting nothing at all would achieve.
        let latest_rtt = send_elapsed;

        // §5.3 also says to use "the lesser of the acknowledgment delay and the
        // peer's max_ack_delay". Phantom negotiates no max_ack_delay; there is
        // no transport parameter to compare against, so the only ceiling this
        // endpoint can know for itself is the round trip it just timed — a peer
        // cannot have spent longer holding the acknowledgement than the entire
        // trip took, so anything above that is nonsense on its face.
        //
        // The guard below already renders an absurd value harmless (it simply
        // fails, and the raw sample is used), so this clamp is defence in depth
        // rather than the load-bearing check. It is kept for two reasons: it
        // makes the bound local to the arithmetic instead of an emergent
        // property of a comparison someone might later refactor, and it stops a
        // nonsense report from *suppressing* an honest measurement — the old
        // `saturating_sub` turned any delay past the round trip into a zero
        // sample, which the `rtt_us > 0` check below then dropped, discarding a
        // perfectly good local RTT on the peer's say-so.
        let observed_us = u64::try_from(latest_rtt.as_micros()).unwrap_or(u64::MAX);
        let ack_delay = Duration::from_micros(sample.ack_delay_us.min(observed_us));

        let adjusted_rtt = if !self.rtt_filter_seeded {
            // §5.2, first sample: seed the minimum from the raw round trip. The
            // 100 ms this estimator opens with is a guess, not an observation,
            // and using it as the guard's reference would let a peer on a
            // slower path subtract down to it before any measurement existed.
            latest_rtt
        } else if latest_rtt >= self.min_rtt.saturating_add(ack_delay) {
            latest_rtt.saturating_sub(ack_delay)
        } else {
            latest_rtt
        };

        // Update min RTT using that adjusted sample, but only from a
        // sample whose round trip is unambiguous — Karn's algorithm.
        //
        // A retransmitted segment carries the send time of its *latest* copy,
        // because that is what the sender restamped it with. An acknowledgement
        // for the original then measures from the copy and reads as microseconds
        // on a path that is orders of magnitude slower. Averaging estimators
        // survive the odd bad sample; a minimum filter does not — the poisoned
        // value evicts every honest measurement in the window and governs the
        // BDP until it ages out, and on a lossy path the next retransmit renews
        // it. `cwnd = 2 × btl_bw × min_rtt` then sits on its floor for the life
        // of the connection.
        //
        // The delivery-rate half of the sample below is deliberately *not*
        // gated: `sent_at`, `delivered_bytes` and `delivered_at` are restamped
        // together, so the rate still measures bytes delivered since the resend
        // over the time since the resend — a short interval, but an honest one.
        let rtt_us = u64::try_from(adjusted_rtt.as_micros()).unwrap_or(u64::MAX);
        if sample.rtt_sampled && rtt_us > 0 {
            let min_rtt_us = self.rtt_filter.update_min(now, rtt_us);
            self.min_rtt = Duration::from_micros(min_rtt_us);
            self.rtt_filter_seeded = true;
        }

        // Delivery rate over the interval this packet spanned, per BBR: the
        // bytes the connection delivered between the packet leaving and its
        // acknowledgement arriving, divided by that elapsed time.
        //
        // Dividing this packet's own size by its own RTT instead would make
        // every sample "one packet per round trip" by construction, whatever is
        // actually in flight. The BDP would then collapse to a single packet
        // (`bytes/rtt × rtt ≡ bytes`), the window would sit on its floor, and a
        // session would be capped near `cwnd_floor / rtt` on any real path —
        // invisible on loopback, where an RTT near zero makes even that floor
        // look fast.
        let delivered_during = self.delivered_bytes.saturating_sub(sample.delivered_bytes);

        // The interval is bounded from below by BOTH ends of the sample, which
        // is the half that was missing. `send_elapsed` measures from when the
        // packet left; `ack_elapsed` measures from when the delivered counter
        // last stood at the value the packet was stamped with — that is, from
        // the moment the bytes in the numerator actually started accumulating.
        //
        // Those bytes began accruing at `delivered_at`, which is at or before
        // the send, so the acknowledgement interval is the wider of the two and
        // in practice the one that governs. Measuring a numerator over the wide
        // interval and a denominator over the narrow one is what let an ack
        // burst read high: acknowledgements do not arrive spread out the way
        // the data was sent, so when a cumulative SACK retires a window at once
        // the last packet in it contributes the whole window's bytes against
        // its own short round trip. Taking the max is canonical BBR (and the
        // same guard RFC 9002-era stacks use), and it is what keeps a sample
        // from claiming a rate no interval in the connection ever sustained.
        let ack_elapsed = sample
            .acked_at
            .saturating_duration_since(sample.delivered_at);
        let interval = send_elapsed.max(ack_elapsed);

        let delivery_rate = if !interval.is_zero() && delivered_during > 0 {
            (delivered_during as f64 / interval.as_secs_f64()) as u64
        } else {
            0
        };

        // App-limited filtering: only update BW filter with non-app-limited samples.
        // App-limited samples underestimate the true available bandwidth because
        // the sender wasn't sending at line rate.
        if delivery_rate > 0 && !sample.is_app_limited {
            self.btl_bw = self.bw_filter.update_max(now, delivery_rate);
        }

        // Check if we've exited app-limited phase
        if self.app_limited && self.delivered_bytes > self.app_limited_at_delivered {
            self.app_limited = false;
        }

        // Run state machine
        self.update_state(now, sample.is_app_limited);

        // Return pacing rate
        self.pacing_rate()
    }

    /// Notify a packet loss — triggers BBRv3 Fast Recovery.
    ///
    /// Unlike earlier BBR versions that ignored loss, BBRv3 immediately
    /// backs off pacing rate and CWND relative to the lost bytes fraction.
    pub fn on_loss(&mut self, bytes: u64) {
        self.inflight_bytes = self.inflight_bytes.saturating_sub(bytes);
        self.recovery_lost_bytes = self.recovery_lost_bytes.saturating_add(bytes);

        // Only enter FastRecovery if not already in it or ProbeRTT
        if self.state != BbrState::FastRecovery && self.state != BbrState::ProbeRTT {
            self.prior_state = self.state;
            self.fast_recovery_entered = Some(Instant::now());
            self.transition_to(BbrState::FastRecovery);
        }
    }

    /// Mark the sender as application-limited (not sending at line rate).
    ///
    /// Call this when there is no data to send but the CWND has room.
    /// Samples produced during app-limited periods won't update the BW filter,
    /// preventing bandwidth underestimation.
    pub fn set_app_limited(&mut self) {
        self.app_limited = true;
        self.app_limited_at_delivered = self.delivered_bytes;
    }

    /// Whether the sender is currently considered application-limited.
    pub fn is_app_limited(&self) -> bool {
        self.app_limited
    }

    /// Get current recommended pacing rate (bytes/sec).
    pub fn pacing_rate(&self) -> u64 {
        let base = self.btl_bw.max(1);
        (base as f64 * self.pacing_gain) as u64
    }

    /// Get recommended congestion window size (bytes).
    pub fn cwnd(&self) -> u64 {
        if self.state == BbrState::ProbeRTT {
            // During ProbeRTT, reduce CWND to minimum
            return PROBE_RTT_CWND_PACKETS * MIN_PACKET_SIZE;
        }
        let bdp = self.bdp();
        (bdp as f64 * self.cwnd_gain).max((PROBE_RTT_CWND_PACKETS * MIN_PACKET_SIZE) as f64) as u64
    }

    /// Get the Bandwidth-Delay Product (BDP) in bytes.
    pub fn bdp(&self) -> u64 {
        (self.btl_bw as f64 * self.min_rtt.as_secs_f64()) as u64
    }

    /// Get current bytes in flight.
    pub fn inflight_bytes(&self) -> u64 {
        self.inflight_bytes
    }

    /// Get estimated bottleneck bandwidth (bytes/sec).
    pub fn bottleneck_bandwidth(&self) -> u64 {
        self.btl_bw
    }

    /// Get minimum observed RTT.
    pub fn min_rtt(&self) -> Duration {
        self.min_rtt
    }

    /// Get current BBR state.
    pub fn state(&self) -> BbrState {
        self.state
    }

    /// Get total bytes delivered.
    pub fn delivered_bytes(&self) -> u64 {
        self.delivered_bytes
    }

    /// When [`Self::delivered_bytes`] last advanced — the companion timestamp to
    /// that counter. Both are stamped onto an outgoing segment so its
    /// acknowledgement carries the two ends of the interval it measures.
    ///
    /// Before the first acknowledgement this is the estimator's creation time,
    /// which makes the first sample's interval the age of the connection — an
    /// under-estimate of the rate, never an over-estimate.
    pub fn delivered_time(&self) -> Instant {
        self.last_delivery
    }

    /// Packet-timed round trips elapsed since the connection opened.
    ///
    /// Round trips, not acknowledgements: `update_round` carries the
    /// delivered-counter rule that advances this.
    pub fn round_count(&self) -> u32 {
        self.round_count
    }

    // ── State Machine ───────────────────────────────────────────────────────

    /// Detect the end of a packet-timed round trip — BBR's `BBRUpdateRound`:
    ///
    /// ```text
    /// BBRUpdateRound():
    ///   if (packet.delivered >= BBR.next_round_delivered)
    ///     BBRStartRound()          # BBR.next_round_delivered = C.delivered
    ///     BBR.round_count++
    ///     BBR.round_start = true
    ///   else
    ///     BBR.round_start = false
    /// ```
    ///
    /// `packet_delivered` is the connection's delivered counter *at the moment
    /// this packet was sent* — `DeliverySample::delivered_bytes`, stamped in
    /// `Stream::poll_send`. When an acknowledgement comes back for a packet that
    /// left at or after the mark taken when the round opened, every packet that
    /// was in flight at the start of the round has been answered: a round trip
    /// has elapsed. The new mark is the counter as it stands now, which is the
    /// last packet of *this* flight.
    ///
    /// The definition is deliberately in delivered bytes rather than in wall
    /// clock. It costs nothing to compute, it needs no RTT estimate to be
    /// correct first, and it stays right across an idle application or an RTT
    /// that moves — "virtual time" in the draft's words. A timer would have to
    /// be re-derived from `min_rtt`, which is itself a filtered guess this
    /// endpoint is still refining.
    ///
    /// `wrapping_add` rather than `+=`: nothing downstream reads the absolute
    /// count, only its parity against the four-entry gain cycle (and 2^32 is
    /// divisible by four, so even the wrap keeps the cycle in phase).
    fn update_round(&mut self, packet_delivered: u64) {
        if packet_delivered >= self.next_round_delivered {
            self.next_round_delivered = self.delivered_bytes;
            self.round_count = self.round_count.wrapping_add(1);
            self.round_start = true;
        } else {
            self.round_start = false;
        }
    }

    /// BBR's `BBRCheckStartupFullBandwidth`: has the pipe stopped filling?
    ///
    /// ```text
    /// if BBR.filled_pipe or !BBR.round_start or rs.is_app_limited
    ///   return
    /// if (BBR.max_bw >= BBR.full_bw * 1.25)
    ///   BBR.full_bw = BBR.max_bw
    ///   BBR.full_bw_count = 0
    ///   return
    /// BBR.full_bw_count++
    /// if (BBR.full_bw_count >= 3)
    ///   BBR.filled_pipe = true
    /// ```
    ///
    /// Three points the previous version got wrong, all of which end Startup
    /// early, and Startup is the connection's only exponential-growth phase:
    ///
    /// - **`round_start`.** The judgement is per round trip. Run per
    ///   acknowledgement it is meaningless: between two acks microseconds apart
    ///   a max-filtered estimate has not grown a quarter, and it never could,
    ///   so the three-strike counter runs out inside the first flight.
    /// - **`full_bw` is a plateau, not the previous round.** Comparing each
    ///   round against only the one before it reads steady 20%-per-round growth
    ///   as a plateau and quits while the path is still opening up. Held against
    ///   a high-water mark, cumulative growth clears the 25% bar and resets the
    ///   counter.
    /// - **`is_app_limited`.** A round in which the application had nothing to
    ///   send delivers less through no fault of the path, and its sample never
    ///   reached the bandwidth filter in the first place — so its "growth" is
    ///   flat by construction. Counting it as evidence the pipe is full lets an
    ///   idle moment end Startup.
    fn check_startup_full_bandwidth(&mut self, is_app_limited: bool) {
        if self.filled_pipe || !self.round_start || is_app_limited {
            return;
        }

        if self.btl_bw as f64 >= self.full_bw as f64 * (1.0 + STARTUP_GROWTH_THRESHOLD) {
            self.full_bw = self.btl_bw;
            self.rounds_without_growth = 0;
            return;
        }

        self.rounds_without_growth = self.rounds_without_growth.saturating_add(1);
        if self.rounds_without_growth >= STARTUP_ROUNDS_LIMIT {
            self.filled_pipe = true;
            self.transition_to(BbrState::Drain);
        }
    }

    /// Run BBR state machine transitions.
    fn update_state(&mut self, now: Instant, is_app_limited: bool) {
        // ── ProbeRTT check: global timer, any state can enter except Startup and FastRecovery ──
        //
        // Both ProbeRTT bounds below are wall clock — `Instant` differences
        // against `sample.acked_at`, which is a real timestamp — and the draft
        // is explicit that this is right: ProbeRTTInterval and ProbeRTTDuration
        // "are explicitly wall-clock measurements", unlike the round counting
        // above. They are not a second instance of the per-acknowledgement
        // confusion and are deliberately left alone.
        //
        // Two honest divergences from the draft remain here, neither of which
        // is that defect. Canonical BBR starts the 200 ms clock only once
        // inflight has drained to the minimum window, and holds ProbeRTT for at
        // least one round trip on top of the duration; this starts the clock on
        // entry, which if anything leaves ProbeRTT sooner. And the trigger is
        // "10 s since the last ProbeRTT" rather than the draft's "the min-RTT
        // filter has gone stale", so a flow whose filter is being refreshed by
        // every acknowledgement still pays a 200 ms window at the floor cwnd
        // every 10 s. Both are behaviour changes rather than corrections, and
        // are left for a change that measures them.
        if self.state != BbrState::ProbeRTT
            && self.state != BbrState::Startup
            && self.state != BbrState::FastRecovery
            && now.duration_since(self.last_probe_rtt_time) >= PROBE_RTT_INTERVAL
        {
            self.prior_state = self.state;
            self.transition_to(BbrState::ProbeRTT);
            self.probe_rtt_entered = Some(now);
            return;
        }

        match self.state {
            BbrState::Startup => {
                self.check_startup_full_bandwidth(is_app_limited);
            }
            BbrState::Drain => {
                // Stay in Drain until inflight ≤ BDP
                let bdp = self.bdp();
                if self.inflight_bytes <= bdp || bdp == 0 {
                    self.transition_to(BbrState::ProbeBW);
                }
            }
            BbrState::ProbeBW => {
                // One gain phase per round trip, which is what the gains mean:
                // 1.25 asks the path for a quarter more than the estimate and
                // 0.75 gives back whatever queue that built. A phase has to
                // outlast a round trip for its result to come back and be
                // measured at all — advanced per acknowledgement, the probe
                // covers one packet in four and the estimate can never climb
                // above whatever Startup handed it.
                //
                // `round_count` only moves on a round boundary now, so the
                // index below is constant for the whole round; no separate
                // "advance" step is needed, and none may be added.
                let cycle_idx = (self.round_count as usize) % PROBE_BW_GAINS.len();
                self.pacing_gain = PROBE_BW_GAINS[cycle_idx];
                self.cwnd_gain = 2.0;
            }
            BbrState::ProbeRTT => {
                // Stay for PROBE_RTT_DURATION, then exit
                if let Some(entered) = self.probe_rtt_entered {
                    if now.duration_since(entered) >= PROBE_RTT_DURATION {
                        self.last_probe_rtt_time = now;
                        self.probe_rtt_entered = None;
                        self.transition_to(self.prior_state);
                    }
                } else {
                    // Safety: shouldn't happen, but exit gracefully
                    self.transition_to(BbrState::ProbeBW);
                }
            }
            BbrState::FastRecovery => {
                // Exit FastRecovery once inflight has drained to ≤ BDP (the pipe is no
                // longer over-filled), or when BDP is still unknown (== 0). The exit is
                // purely inflight-driven; `fast_recovery_entered` is recorded only for
                // diagnostics, not consulted here.
                let bdp = self.bdp();
                let should_exit = self.inflight_bytes
                    <= (bdp as f64 * FAST_RECOVERY_EXIT_FRACTION) as u64
                    || bdp == 0;

                if should_exit {
                    self.recovery_lost_bytes = 0;
                    self.fast_recovery_entered = None;
                    self.transition_to(self.prior_state);
                }
            }
        }
    }

    /// Transition to a new BBR state.
    fn transition_to(&mut self, new_state: BbrState) {
        match new_state {
            BbrState::Startup => {
                self.pacing_gain = 2.0;
                self.cwnd_gain = 2.0;
            }
            BbrState::Drain => {
                self.pacing_gain = 0.75;
                self.cwnd_gain = 2.0;
            }
            BbrState::ProbeBW => {
                self.pacing_gain = 1.0;
                self.cwnd_gain = 2.0;
            }
            BbrState::ProbeRTT => {
                self.pacing_gain = 1.0;
                self.cwnd_gain = 1.0;
            }
            BbrState::FastRecovery => {
                // BBRv3 recovery: drop pacing to 50% of bottleneck bandwidth,
                // and tighten CWND to 1x BDP instead of 2x (no inflating).
                self.pacing_gain = FAST_RECOVERY_PACING_GAIN;
                self.cwnd_gain = 1.0;
            }
        }
        self.state = new_state;
    }
}

impl Default for BandwidthEstimator {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for BandwidthEstimator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BandwidthEstimator")
            .field("state", &self.state)
            .field("btl_bw_kbps", &(self.btl_bw / 1024))
            .field("min_rtt_ms", &self.min_rtt.as_millis())
            .field("round_count", &self.round_count)
            .field("pacing_gain", &self.pacing_gain)
            .field("inflight_bytes", &self.inflight_bytes)
            .field("delivered_bytes", &self.delivered_bytes)
            .field("app_limited", &self.app_limited)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_sample(sent_at: Instant, rtt_ms: u64, packet_bytes: u64) -> DeliverySample {
        DeliverySample {
            delivered_bytes: 0,
            // Nothing delivered yet as of the send, and the counter was last at
            // that value when the packet left — so the interval is the packet's
            // own round trip, which is what these single-packet tests intend.
            delivered_at: sent_at,
            sent_at,
            acked_at: sent_at + Duration::from_millis(rtt_ms),
            packet_bytes,
            is_app_limited: false,
            ack_delay_us: 0, // No ACK delay in tests
            rtt_sampled: true,
        }
    }

    fn make_app_limited_sample(sent_at: Instant, rtt_ms: u64, packet_bytes: u64) -> DeliverySample {
        DeliverySample {
            delivered_bytes: 0,
            delivered_at: sent_at,
            sent_at,
            acked_at: sent_at + Duration::from_millis(rtt_ms),
            packet_bytes,
            is_app_limited: true,
            ack_delay_us: 0,
            rtt_sampled: true,
        }
    }

    /// Send a whole window of packets, then acknowledge them one round trip
    /// later — the shape of any bulk transfer.
    ///
    /// The bandwidth estimate must reflect the aggregate delivered over the
    /// interval. Deriving it from a single packet's size over that packet's own
    /// RTT is structurally "one packet per round trip": the BDP then collapses
    /// to one packet's worth no matter how many are in flight, and the window
    /// pins to its floor. On a 200 ms path that caps a session at roughly
    /// `cwnd_floor / rtt` regardless of the link — which is exactly what a real
    /// WAN run measured (0.19 Mbit/s against a 6.7 Mbit/s path).
    #[test]
    fn bandwidth_reflects_a_full_window_not_a_single_packet() {
        const PACKETS: u64 = 100;
        const PACKET: u64 = 1200;
        const RTT_MS: u64 = 200;

        let mut est = BandwidthEstimator::new();
        let start = Instant::now();

        // A window's worth goes out back-to-back...
        for _ in 0..PACKETS {
            est.on_send(PACKET);
        }
        // ...and is acknowledged one RTT later. Every one of them left before
        // anything came back, so the connection had delivered nothing when each
        // was sent — that zero is what makes the interval span the whole window
        // rather than a single packet.
        for _ in 0..PACKETS {
            est.on_ack(DeliverySample {
                delivered_bytes: 0,
                delivered_at: start,
                sent_at: start,
                acked_at: start + Duration::from_millis(RTT_MS),
                packet_bytes: PACKET,
                is_app_limited: false,
                ack_delay_us: 0,
                rtt_sampled: true,
            });
        }

        // The delivered-over-interval rate is ~600 KB/s here; a per-packet rate
        // would be 6 KB/s, a hundred times lower.
        assert!(
            est.bottleneck_bandwidth() > 10 * (PACKET * 1000 / RTT_MS),
            "bandwidth estimate {} B/s is still near one packet per RTT ({} B/s)",
            est.bottleneck_bandwidth(),
            PACKET * 1000 / RTT_MS
        );

        // And the window must open well past its floor, or the estimate is moot.
        let floor = PROBE_RTT_CWND_PACKETS * MIN_PACKET_SIZE;
        assert!(
            est.cwnd() > 10 * floor,
            "cwnd {} B is still pinned near the {} B floor",
            est.cwnd(),
            floor
        );
    }

    /// The mirror image of the test above. Counting a whole window's bytes is
    /// only half of a delivery-rate sample; the other half is the interval they
    /// were delivered over, and a packet's own round trip is not that interval.
    ///
    /// Acknowledgements do not arrive spread out the way the data was sent —
    /// receivers batch them, and one cumulative SACK retires everything it
    /// covers at once. When that burst lands, the last packet in it has a short
    /// round trip while the delivered counter has just jumped by the whole
    /// window, so dividing one by the other reads a full window as having been
    /// delivered inside a single packet's flight time. Here that misreads a
    /// 4 Mbit/s transfer as roughly 24 Mbit/s, and the window opens to match a
    /// path that was never there.
    #[test]
    fn an_aggregated_ack_burst_does_not_outrun_the_interval_it_spans() {
        const PACKETS: u64 = 500;
        const PACKET: u64 = 1200;
        // Spacing between sends: 500 × 1200 B over a second is ~4.8 Mbit/s.
        const SEND_GAP_MS: u64 = 2;
        const RTT_MS: u64 = 200;

        let start = Instant::now();
        let send_spread_ms = PACKETS * SEND_GAP_MS;
        let burst_at = start + Duration::from_millis(send_spread_ms + RTT_MS);

        let mut est = BandwidthEstimator::new();
        for _ in 0..PACKETS {
            est.on_send(PACKET);
        }
        // Every packet left before anything came back, so all of them carry the
        // same delivery mark: nothing delivered, as of the start.
        for i in 0..PACKETS {
            est.on_ack(DeliverySample {
                delivered_bytes: 0,
                delivered_at: start,
                sent_at: start + Duration::from_millis(i * SEND_GAP_MS),
                acked_at: burst_at,
                packet_bytes: PACKET,
                is_app_limited: false,
                ack_delay_us: 0,
                rtt_sampled: true,
            });
        }

        // The connection put PACKETS × PACKET bytes on the wire and had them all
        // acknowledged by `burst_at`. Nothing about that run supports a rate
        // above that many bytes over that much time, whatever any single
        // packet's round trip looked like.
        let supported = PACKETS * PACKET * 1000 / (send_spread_ms + RTT_MS);
        assert!(
            est.bottleneck_bandwidth() <= supported + supported / 10,
            "bandwidth estimate {} B/s exceeds the {} B/s the ack interval supports",
            est.bottleneck_bandwidth(),
            supported
        );
        // ...and it must still find the rate, or a controller that simply
        // refused to estimate anything would pass the assertion above.
        assert!(
            est.bottleneck_bandwidth() >= supported - supported / 10,
            "bandwidth estimate {} B/s undershoots the {} B/s actually delivered",
            est.bottleneck_bandwidth(),
            supported
        );
    }

    /// Karn's algorithm, applied to the min-RTT filter.
    ///
    /// A sender restamps a segment's send time when it resends it, so an
    /// acknowledgement for the *original* transmission — already in flight when
    /// the copy went out — is measured from the copy and reads as microseconds
    /// on a path whose real round trip is a fifth of a second. Nothing in the
    /// acknowledgement says which of the two it answers; the figure is not a
    /// round-trip measurement at all.
    ///
    /// Feeding it to a *minimum* filter is what makes it expensive. A minimum is
    /// not averaged away: one sample evicts every honest measurement in the
    /// window and governs until it ages out, and on a lossy path the next
    /// retransmit re-poisons the filter and restarts its clock, so it never
    /// does. `cwnd = 2 × btl_bw × min_rtt`, so a min RTT three orders of
    /// magnitude too small drags the bandwidth-delay product down with it and
    /// pins the window on its 5600-byte floor for the life of the connection.
    /// A real 200 ms WAN run collapsed from a 128 KB peak to exactly that floor
    /// and averaged 7.7 KB in flight where filling the pipe needed ~165 KB.
    ///
    /// `Stream`'s own SRTT estimator already skips these samples. This holds the
    /// bandwidth estimator to the same rule.
    #[test]
    fn a_retransmits_ambiguous_ack_does_not_collapse_the_min_rtt() {
        const PACKETS: u64 = 100;
        const PACKET: u64 = 1200;
        const RTT_MS: u64 = 200;

        let mut est = BandwidthEstimator::new();
        let start = Instant::now();
        let floor = PROBE_RTT_CWND_PACKETS * MIN_PACKET_SIZE;

        // A window's worth goes out and is acknowledged one round trip later —
        // an ordinary bulk transfer on a 200 ms path.
        for _ in 0..PACKETS {
            est.on_send(PACKET);
        }
        for _ in 0..PACKETS {
            est.on_ack(DeliverySample {
                delivered_bytes: 0,
                delivered_at: start,
                sent_at: start,
                acked_at: start + Duration::from_millis(RTT_MS),
                packet_bytes: PACKET,
                is_app_limited: false,
                ack_delay_us: 0,
                rtt_sampled: true,
            });
        }

        let healthy_rtt = est.min_rtt();
        assert_eq!(healthy_rtt, Duration::from_millis(RTT_MS));
        assert!(
            est.cwnd() > 10 * floor,
            "precondition: the window should be open before the retransmit ({} B)",
            est.cwnd()
        );

        // Now a segment is declared lost and resent. `Stream::poll_send`
        // restamps its send time (and its delivery mark, in lock-step) to the
        // instant of the resend. The original's acknowledgement was already on
        // the wire and lands 200 µs later, so the elapsed time reads 200 µs
        // against a path that is a thousand times slower than that.
        let resent_at = start + Duration::from_millis(RTT_MS);
        est.on_send(PACKET);
        est.on_ack(DeliverySample {
            delivered_bytes: est.delivered_bytes(),
            delivered_at: resent_at,
            sent_at: resent_at,
            acked_at: resent_at + Duration::from_micros(200),
            packet_bytes: PACKET,
            is_app_limited: false,
            ack_delay_us: 0,
            rtt_sampled: false,
        });

        assert_eq!(
            est.min_rtt(),
            healthy_rtt,
            "an ack for a retransmitted segment is ambiguous (Karn) and must not \
             enter the min-RTT filter; it dropped min_rtt to {:?}",
            est.min_rtt()
        );
        assert!(
            est.cwnd() > 10 * floor,
            "cwnd collapsed to {} B (floor {} B) on one retransmit's ack",
            est.cwnd(),
            floor
        );

        // ...and the gate is Karn's condition, not a blanket refusal to measure:
        // an unambiguous sample must still move the filter, or a controller that
        // simply stopped tracking RTT would satisfy the assertions above.
        let clean_at = start + Duration::from_millis(RTT_MS + 100);
        est.on_send(PACKET);
        est.on_ack(DeliverySample {
            delivered_bytes: est.delivered_bytes(),
            delivered_at: clean_at,
            sent_at: clean_at,
            acked_at: clean_at + Duration::from_millis(150),
            packet_bytes: PACKET,
            is_app_limited: false,
            ack_delay_us: 0,
            rtt_sampled: true,
        });
        assert_eq!(
            est.min_rtt(),
            Duration::from_millis(150),
            "a never-retransmitted segment's round trip must still lower min_rtt"
        );
    }

    /// A peer must not get to choose the local congestion window.
    ///
    /// `Sack::ack_delay_us` is the receiver's own claim about how long it held
    /// an acknowledgement before sending it, and the sender subtracts it from
    /// the round trip it measured. Subtracting it unconditionally hands the
    /// peer a dial on `min_rtt`, and through `cwnd = 2 × btl_bw × min_rtt` a
    /// dial on the window.
    ///
    /// The lever is not subtle, because the consumer is a *minimum* filter.
    /// `WindowFilter::update_min` back-pops every entry at or above a new
    /// value, so one sample does not merely sit at the head for the window
    /// duration — it discards the accumulated honest history and restarts the
    /// expiry clock. A peer reporting 199.9 ms of "ack delay" on a 200 ms path
    /// drives the sample to 100 µs, wipes the filter, and pins the window on
    /// its 5600-byte floor for as long as it keeps reporting. A real WAN
    /// transfer that peaked near a 128 KB window fell to exactly that floor and
    /// then sustained 4.7–7.6% of a link whose raw-socket control measured
    /// 6.63 Mbit/s at zero loss.
    ///
    /// The `Sack` rides inside the AEAD plaintext, so an on-path attacker
    /// cannot reach this — it needs the authenticated peer. That is less of a
    /// mitigation than it sounds: a malicious or merely defective server can
    /// throttle every client it serves for the life of each connection, and a
    /// client can do the same to a server. A reported delay is untrusted input
    /// to be bounded, not a measurement to be believed.
    #[test]
    fn a_peers_reported_ack_delay_cannot_collapse_the_min_rtt() {
        const PACKETS: u64 = 100;
        const PACKET: u64 = 1200;
        const RTT_MS: u64 = 200;

        let mut est = BandwidthEstimator::new();
        let start = Instant::now();
        let floor = PROBE_RTT_CWND_PACKETS * MIN_PACKET_SIZE;

        // An ordinary bulk transfer on a 200 ms path, the peer reporting no
        // delay at all.
        for _ in 0..PACKETS {
            est.on_send(PACKET);
        }
        for _ in 0..PACKETS {
            est.on_ack(DeliverySample {
                delivered_bytes: 0,
                delivered_at: start,
                sent_at: start,
                acked_at: start + Duration::from_millis(RTT_MS),
                packet_bytes: PACKET,
                is_app_limited: false,
                ack_delay_us: 0,
                rtt_sampled: true,
            });
        }

        let healthy_rtt = est.min_rtt();
        assert_eq!(healthy_rtt, Duration::from_millis(RTT_MS));
        assert!(
            est.cwnd() > 10 * floor,
            "precondition: the window should be open before the peer starts \
             reporting ({} B)",
            est.cwnd()
        );

        // The peer now claims it sat on the acknowledgement for 199.9 ms of the
        // 200 ms round trip. Believed, that leaves a 100 µs "propagation
        // delay" — a path three orders of magnitude faster than the one this
        // endpoint just timed with its own clock, twice.
        let attack_at = start + Duration::from_millis(RTT_MS);
        est.on_send(PACKET);
        est.on_ack(DeliverySample {
            delivered_bytes: est.delivered_bytes(),
            delivered_at: attack_at,
            sent_at: attack_at,
            acked_at: attack_at + Duration::from_millis(RTT_MS),
            packet_bytes: PACKET,
            is_app_limited: false,
            ack_delay_us: 199_900,
            rtt_sampled: true,
        });

        assert_eq!(
            est.min_rtt(),
            healthy_rtt,
            "a peer-reported ack delay must not lower min_rtt below what the \
             local clock observed; it dropped min_rtt to {:?}",
            est.min_rtt()
        );
        assert!(
            est.cwnd() > 10 * floor,
            "cwnd collapsed to {} B (floor {} B) on one peer-reported ack delay",
            est.cwnd(),
            floor
        );

        // And it does not become true by repetition — a peer that keeps
        // reporting it must not get anywhere either.
        for i in 0..20u64 {
            let at = start + Duration::from_millis(2 * RTT_MS + i);
            est.on_send(PACKET);
            est.on_ack(DeliverySample {
                delivered_bytes: est.delivered_bytes(),
                delivered_at: at,
                sent_at: at,
                acked_at: at + Duration::from_millis(RTT_MS),
                packet_bytes: PACKET,
                is_app_limited: false,
                ack_delay_us: 199_900,
                rtt_sampled: true,
            });
        }
        assert_eq!(
            est.min_rtt(),
            healthy_rtt,
            "a sustained ack-delay report collapsed min_rtt to {:?}",
            est.min_rtt()
        );
        assert!(
            est.cwnd() > 10 * floor,
            "cwnd collapsed to {} B (floor {} B) under a sustained ack-delay report",
            est.cwnd(),
            floor
        );

        // A report larger than the whole round trip is nonsense on its face,
        // and must be bounded rather than either believed or allowed to
        // suppress the sample: the 150 ms elapsed here is a genuine local
        // observation of a faster path and has to land. This is also the
        // two-sided half of the test — a controller that simply stopped
        // tracking RTT to dodge the assertions above would fail here.
        let absurd_at = start + Duration::from_millis(700);
        est.on_send(PACKET);
        est.on_ack(DeliverySample {
            delivered_bytes: est.delivered_bytes(),
            delivered_at: absurd_at,
            sent_at: absurd_at,
            acked_at: absurd_at + Duration::from_millis(150),
            packet_bytes: PACKET,
            is_app_limited: false,
            ack_delay_us: 2_000_000, // ten times the round trip it rides on
            rtt_sampled: true,
        });
        assert_eq!(
            est.min_rtt(),
            Duration::from_millis(150),
            "an ack delay past the round trip must neither be subtracted nor \
             discard the honest 150 ms the local clock measured"
        );

        // ...and an ordinary clean sample still moves the filter.
        let clean_at = start + Duration::from_millis(900);
        est.on_send(PACKET);
        est.on_ack(DeliverySample {
            delivered_bytes: est.delivered_bytes(),
            delivered_at: clean_at,
            sent_at: clean_at,
            acked_at: clean_at + Duration::from_millis(120),
            packet_bytes: PACKET,
            is_app_limited: false,
            ack_delay_us: 0,
            rtt_sampled: true,
        });
        assert_eq!(
            est.min_rtt(),
            Duration::from_millis(120),
            "a clean round trip must still lower min_rtt"
        );
    }

    /// Acknowledge `packets` segments that all went out inside the same round
    /// trip.
    ///
    /// Every one of them left before any acknowledgement came back, so they all
    /// carry the same delivery mark: the connection's delivered counter, and the
    /// instant it last advanced, as of the send. That shared mark is exactly what
    /// a real sender stamps in `Stream::poll_send` from the estimator's own
    /// snapshot, and it is what BBR's round detection keys on — a packet whose
    /// mark is at or beyond the round's opening mark closes the round.
    fn ack_one_round_trip(
        est: &mut BandwidthEstimator,
        packets: u64,
        packet_bytes: u64,
        sent_at: Instant,
        rtt: Duration,
    ) {
        let mark = est.delivered_bytes();
        let mark_time = est.delivered_time();
        for _ in 0..packets {
            est.on_send(packet_bytes);
        }
        for i in 0..packets {
            est.on_ack(DeliverySample {
                delivered_bytes: mark,
                delivered_at: mark_time,
                sent_at,
                // Acknowledgements for one flight land close together — they do
                // not arrive spread out the way the data was sent.
                acked_at: sent_at + rtt + Duration::from_micros(i * 20),
                packet_bytes,
                is_app_limited: false,
                ack_delay_us: 0,
                rtt_sampled: true,
            });
        }
    }

    /// Pacing gains are copies of the same `f64` constants, so an exact compare
    /// would be sound — but a tolerance says what is meant and keeps the
    /// assertion honest if a gain ever becomes computed rather than tabulated.
    fn same_gain(a: f64, b: f64) -> bool {
        (a - b).abs() < 1e-9
    }

    /// A "round" in BBR is a round *trip*, not an acknowledgement.
    ///
    /// The Startup exit rule — three consecutive rounds whose bandwidth grew by
    /// less than 25% — is canonical, and it is the only thing that ends the
    /// connection's one exponential-growth phase. Counting each arriving
    /// acknowledgement as a round makes it fire almost immediately: dozens of
    /// acknowledgements land within a single round trip, and between two of them
    /// microseconds apart a max-filtered bandwidth estimate essentially never
    /// grows a quarter. Three of those in a row arrive long before the window
    /// has doubled once, so the sender leaves Startup having never probed
    /// anything, and the estimate it carries out is whatever the opening window
    /// happened to deliver.
    ///
    /// Here a whole window's worth of segments goes out and is acknowledged one
    /// round trip later — the shape of the first flight of any bulk transfer.
    /// That is *one* round trip, and Startup must still be running at the end
    /// of it.
    #[test]
    fn startup_survives_a_whole_window_of_acks_inside_one_round_trip() {
        const PACKETS: u64 = 60;
        const PACKET: u64 = 1200;
        const RTT: Duration = Duration::from_millis(200);

        let mut est = BandwidthEstimator::new();
        let start = Instant::now();
        let opening_cwnd = est.cwnd();

        ack_one_round_trip(&mut est, PACKETS, PACKET, start, RTT);

        assert_eq!(
            est.round_count(),
            1,
            "{PACKETS} acknowledgements for one flight are one round trip, not \
             {} of them",
            est.round_count()
        );
        assert_eq!(
            est.state(),
            BbrState::Startup,
            "the connection left Startup inside its first round trip, before the \
             window had doubled even once"
        );
        // ...and it must have used the round: a controller that stayed in
        // Startup by refusing to estimate anything would satisfy the above.
        assert!(
            est.cwnd() > 10 * opening_cwnd,
            "cwnd {} B has not grown past the {} B it opened at",
            est.cwnd(),
            opening_cwnd
        );
    }

    /// The other direction, which is what stops the fix above from being
    /// "never leave Startup".
    ///
    /// Startup is exponential growth; staying in it forever would keep the
    /// window inflating against a bottleneck that has already been found and
    /// standing queues in front of it. When the pipe genuinely fills — several
    /// consecutive *round trips* delivering the same rate — the sender has to
    /// notice and move on to Drain.
    #[test]
    fn startup_still_exits_once_the_pipe_stops_filling_over_several_round_trips() {
        const PACKETS: u64 = 20;
        const PACKET: u64 = 1200;
        const RTT: Duration = Duration::from_millis(200);
        const ROUNDS: u32 = 12;

        let mut est = BandwidthEstimator::new();
        let start = Instant::now();

        // A fixed window per round trip: the rate never grows, so from the
        // second round on every round is a no-growth round.
        let mut left_after: Option<u32> = None;
        for round in 0..ROUNDS {
            ack_one_round_trip(&mut est, PACKETS, PACKET, start + RTT * round, RTT);
            if left_after.is_none() && est.state() != BbrState::Startup {
                left_after = Some(round + 1);
            }
        }

        assert_eq!(
            est.round_count(),
            ROUNDS,
            "{ROUNDS} flights are {ROUNDS} round trips"
        );
        let window = STARTUP_ROUNDS_LIMIT..=STARTUP_ROUNDS_LIMIT + 5;
        assert!(
            matches!(left_after, Some(r) if window.contains(&r)),
            "Startup should end within a few round trips of the rate flattening \
             (expected somewhere in {window:?}); it ended after {left_after:?}"
        );
    }

    /// The ProbeBW gain cycle is the only thing that lets the estimate climb
    /// once Startup is over: three of its four phases pace at or below the
    /// current estimate, and the 1.25 phase is the one that asks the path for
    /// more. In BBR each phase lasts one `min_rtt`.
    ///
    /// Indexing the cycle with a counter that ticks per acknowledgement spins it
    /// at ack rate, so the probe phase covers roughly one packet in four and
    /// never lasts long enough to probe anything. The estimate then cannot climb
    /// after Startup either — whatever it left Startup with is what it keeps.
    #[test]
    fn the_probe_bw_gain_cycle_advances_once_per_round_trip_not_once_per_ack() {
        const PACKETS: u64 = 40;
        const PACKET: u64 = 1200;
        const RTT: Duration = Duration::from_millis(200);
        const ROUNDS: u32 = 8;

        let mut est = BandwidthEstimator::new();
        let start = Instant::now();
        // Park it in ProbeBW directly. Startup's exit rule is the previous
        // test's subject; reaching ProbeBW through it would only make this test
        // fail for that test's reasons.
        est.state = BbrState::ProbeBW;

        let mut per_round: Vec<f64> = Vec::new();
        for round in 0..ROUNDS {
            let sent_at = start + RTT * round;
            let mark = est.delivered_bytes();
            let mark_time = est.delivered_time();
            let mut within: Vec<f64> = Vec::new();
            for i in 0..PACKETS {
                est.on_send(PACKET);
                est.on_ack(DeliverySample {
                    delivered_bytes: mark,
                    delivered_at: mark_time,
                    sent_at,
                    acked_at: sent_at + RTT + Duration::from_micros(i * 20),
                    packet_bytes: PACKET,
                    is_app_limited: false,
                    ack_delay_us: 0,
                    rtt_sampled: true,
                });
                within.push(est.pacing_gain);
            }
            let changes = within.windows(2).filter(|w| !same_gain(w[0], w[1])).count();
            assert_eq!(
                changes, 0,
                "round {round}: the pacing gain changed {changes} times inside a \
                 single round trip — a phase that turns over every \
                 acknowledgement never probes anything: {within:?}"
            );
            per_round.push(within[0]);
        }

        // Four gains, one round trip each: the cycle's period is four *round
        // trips*.
        let period = PROBE_BW_GAINS.len();
        for r in 0..(ROUNDS as usize - period) {
            assert!(
                same_gain(per_round[r], per_round[r + period]),
                "the gain cycle is not periodic in round trips: {per_round:?}"
            );
        }
        // ...and every phase must actually run, or a controller that pinned one
        // gain forever would satisfy the assertions above.
        for gain in PROBE_BW_GAINS {
            assert!(
                per_round.iter().any(|g| same_gain(*g, gain)),
                "the {gain} phase never ran across {ROUNDS} round trips: \
                 {per_round:?}"
            );
        }
    }

    /// The estimator opens with a conservative 100 ms *guess* for `min_rtt`,
    /// which is not a measurement of anything. Anchoring RFC 9002 §5.3's guard
    /// on that guess would let a peer on a slower path subtract its way down to
    /// it on the very first acknowledgement and hold the window at half the
    /// bandwidth-delay product the path can actually carry — the guard would
    /// be defending a number the peer got to pick the moment the connection
    /// opened.
    ///
    /// §5.2 says what to do instead: "min_rtt MUST be set to the latest_rtt on
    /// the first RTT sample" — raw, unadjusted. From then on the running
    /// minimum is something this endpoint has seen, and the guard has real
    /// ground to stand on.
    #[test]
    fn the_first_round_trip_is_measured_raw_not_against_the_opening_guess() {
        let mut est = BandwidthEstimator::new();
        let start = Instant::now();

        // A 200 ms path. The peer claims a hold of exactly the estimator's
        // 100 ms opening guess, which is the largest claim a guard anchored on
        // that guess would still accept.
        est.on_send(1200);
        est.on_ack(DeliverySample {
            delivered_bytes: 0,
            delivered_at: start,
            sent_at: start,
            acked_at: start + Duration::from_millis(200),
            packet_bytes: 1200,
            is_app_limited: false,
            ack_delay_us: 100_000,
            rtt_sampled: true,
        });

        assert_eq!(
            est.min_rtt(),
            Duration::from_millis(200),
            "the first RTT sample must seed min_rtt from the raw round trip; \
             it came out as {:?}",
            est.min_rtt()
        );
    }

    /// The guard is RFC 9002's condition, not a blanket refusal to use the
    /// peer's figure — dropping the correction outright would break the feature
    /// rather than fix it.
    ///
    /// Receivers really do batch acknowledgements, and a reported hold that
    /// fits inside the round trip is a real correction. It earns its keep
    /// exactly where a minimum filter is weakest: once the old measurement ages
    /// out of the ten-second window the next sample sets the minimum on its
    /// own, and without the subtraction the receiver's own delay would be
    /// baked into the path's propagation time and inflate the BDP from there.
    #[test]
    fn a_genuine_ack_delay_is_still_subtracted_from_the_round_trip() {
        let mut est = BandwidthEstimator::new();
        let start = Instant::now();

        // A 100 ms path, measured cleanly.
        est.on_send(1200);
        est.on_ack(DeliverySample {
            delivered_bytes: 0,
            delivered_at: start,
            sent_at: start,
            acked_at: start + Duration::from_millis(100),
            packet_bytes: 1200,
            is_app_limited: false,
            ack_delay_us: 0,
            rtt_sampled: true,
        });
        assert_eq!(est.min_rtt(), Duration::from_millis(100));

        // Eleven seconds on, that measurement has aged out of the ten-second
        // filter window, so whatever arrives next sets the minimum by itself.
        // The round trip reads 150 ms, of which the receiver reports it spent
        // 30 ms holding the acknowledgement. 150 ms clears `min_rtt +
        // ack_delay` (130 ms), so §5.3 permits the subtraction: the path
        // propagates in 120 ms, and recording 150 would overstate it forever
        // after.
        let later = start + Duration::from_secs(11);
        est.on_send(1200);
        est.on_ack(DeliverySample {
            delivered_bytes: est.delivered_bytes(),
            delivered_at: later,
            sent_at: later,
            acked_at: later + Duration::from_millis(150),
            packet_bytes: 1200,
            is_app_limited: false,
            ack_delay_us: 30_000,
            rtt_sampled: true,
        });

        assert_eq!(
            est.min_rtt(),
            Duration::from_millis(120),
            "a reported ack delay that leaves the sample at or above min_rtt \
             must still be subtracted; min_rtt came out as {:?}",
            est.min_rtt()
        );
    }

    /// The floor is what a session falls back to when nothing has been
    /// estimated yet; on a long path it is also the throughput ceiling, so its
    /// value is worth pinning explicitly.
    #[test]
    fn a_fresh_estimator_starts_at_the_cwnd_floor() {
        let est = BandwidthEstimator::new();
        assert_eq!(est.cwnd(), PROBE_RTT_CWND_PACKETS * MIN_PACKET_SIZE);
        assert_eq!(est.cwnd(), 5600);
    }

    #[test]
    fn test_estimator_starts_in_startup() {
        let est = BandwidthEstimator::new();
        assert_eq!(est.state(), BbrState::Startup);
        assert_eq!(est.delivered_bytes(), 0);
        assert_eq!(est.inflight_bytes(), 0);
        assert!(!est.is_app_limited());
    }

    #[test]
    fn test_bandwidth_increases_with_acks() {
        let mut est = BandwidthEstimator::new();
        let now = Instant::now();

        // Simulate several ACKs at 10ms RTT, 1400 byte packets
        for i in 0..10 {
            let sent = now + Duration::from_millis(i * 10);
            est.on_send(1400);
            let sample = make_sample(sent, 10, 1400);
            est.on_ack(sample);
        }

        // Should have positive bandwidth estimate
        assert!(
            est.bottleneck_bandwidth() > 0,
            "btl_bw = {} should be > 0",
            est.bottleneck_bandwidth()
        );
        assert_eq!(est.delivered_bytes(), 14_000);
    }

    #[test]
    fn test_min_rtt_tracking() {
        let mut est = BandwidthEstimator::new();
        let now = Instant::now();

        // RTT high first, then low
        let s1 = make_sample(now, 100, 1400);
        est.on_ack(s1);
        assert!(est.min_rtt() <= Duration::from_millis(101));

        let s2 = make_sample(now + Duration::from_millis(200), 5, 1400);
        est.on_ack(s2);
        assert!(
            est.min_rtt() <= Duration::from_millis(6),
            "min_rtt = {:?}",
            est.min_rtt()
        );
    }

    #[test]
    fn test_pacing_rate_positive() {
        let mut est = BandwidthEstimator::new();
        let now = Instant::now();

        let sample = make_sample(now, 20, 1400);
        est.on_ack(sample);

        // Pacing rate should be positive
        assert!(est.pacing_rate() > 0);
    }

    #[test]
    fn test_cwnd_at_least_minimum() {
        let est = BandwidthEstimator::new();
        // Even with zero BW, CWND should have a minimum floor
        let cwnd = est.cwnd();
        assert!(
            cwnd >= 4 * 1400,
            "cwnd = {} should be >= {}",
            cwnd,
            4 * 1400
        );
    }

    #[test]
    fn test_startup_to_drain_transition() {
        let mut est = BandwidthEstimator::new();
        let now = Instant::now();
        let rtt = Duration::from_millis(10);

        // Constant bandwidth over many *round trips* triggers pipe-filled
        // detection. Twenty acknowledgements would not, and must not: between
        // them they are a single round trip.
        for round in 0..20u32 {
            ack_one_round_trip(&mut est, 10, 1400, now + rtt * round, rtt);
        }

        assert_ne!(
            est.state(),
            BbrState::Startup,
            "expected startup exit after {} round trips at a flat rate",
            est.round_count()
        );
    }

    // ── New tests for Phase 5 improvements ──

    #[test]
    fn test_inflight_tracking() {
        let mut est = BandwidthEstimator::new();

        // Send 3 packets
        est.on_send(1400);
        est.on_send(1400);
        est.on_send(1400);
        assert_eq!(est.inflight_bytes(), 4200);

        // ACK 1
        let now = Instant::now();
        est.on_ack(make_sample(now, 10, 1400));
        assert_eq!(est.inflight_bytes(), 2800);

        // Loss 1
        est.on_loss(1400);
        assert_eq!(est.inflight_bytes(), 1400);

        // ACK last
        est.on_ack(make_sample(now + Duration::from_millis(10), 10, 1400));
        assert_eq!(est.inflight_bytes(), 0);
    }

    #[test]
    fn test_inflight_cant_go_negative() {
        let mut est = BandwidthEstimator::new();
        est.on_loss(5000);
        assert_eq!(est.inflight_bytes(), 0); // saturating_sub
    }

    #[test]
    fn test_app_limited_filtering() {
        let mut est = BandwidthEstimator::new();
        let now = Instant::now();

        // Feed real bandwidth samples first (1Mbps)
        for i in 0..5 {
            let sent = now + Duration::from_millis(i * 10);
            est.on_send(1400);
            est.on_ack(make_sample(sent, 10, 1400));
        }
        let real_bw = est.bottleneck_bandwidth();
        assert!(real_bw > 0);

        // Now feed app-limited samples with very low bandwidth
        // These should NOT reduce the BW estimate
        est.set_app_limited();
        assert!(est.is_app_limited());

        for i in 5..10 {
            let sent = now + Duration::from_millis(i * 1000);
            est.on_ack(make_app_limited_sample(sent, 1000, 100)); // very slow
        }

        // BW should NOT have decreased
        assert!(
            est.bottleneck_bandwidth() >= real_bw,
            "BW should not decrease from app-limited samples: {} < {}",
            est.bottleneck_bandwidth(),
            real_bw
        );
    }

    #[test]
    fn test_drain_waits_for_bdp() {
        const PACKET: u64 = 1400;
        let mut est = BandwidthEstimator::new();
        let now = Instant::now();
        let rtt = Duration::from_millis(10);

        // Four round trips at a steady rate, so the BDP below is a real number
        // rather than the zero a fresh estimator carries (which would let Drain
        // exit for the wrong reason).
        for round in 0..4u32 {
            ack_one_round_trip(&mut est, 10, PACKET, now + rtt * round, rtt);
        }
        assert!(est.bdp() > 0, "precondition: the BDP must be known");

        // Drain holds while the queue Startup built is still in the pipe. The
        // probe acknowledgement carries the current delivery mark, so it adds
        // one packet over a long interval and cannot move the bandwidth
        // estimate — the BDP under test stays put.
        est.state = BbrState::Drain;
        est.inflight_bytes = est.bdp() * 3;
        let (mark, mark_time) = (est.delivered_bytes(), est.delivered_time());
        est.on_ack(DeliverySample {
            delivered_bytes: mark,
            delivered_at: mark_time,
            sent_at: now + Duration::from_millis(100),
            acked_at: now + Duration::from_millis(110),
            packet_bytes: PACKET,
            is_app_limited: false,
            ack_delay_us: 0,
            rtt_sampled: true,
        });
        assert_eq!(
            est.state(),
            BbrState::Drain,
            "should stay in Drain while inflight ({}) > BDP ({})",
            est.inflight_bytes(),
            est.bdp()
        );

        // ...and releases once it has drained back inside the BDP.
        est.inflight_bytes = est.bdp() / 2;
        let (mark, mark_time) = (est.delivered_bytes(), est.delivered_time());
        est.on_ack(DeliverySample {
            delivered_bytes: mark,
            delivered_at: mark_time,
            sent_at: now + Duration::from_millis(120),
            acked_at: now + Duration::from_millis(130),
            packet_bytes: PACKET,
            is_app_limited: false,
            ack_delay_us: 0,
            rtt_sampled: true,
        });
        assert_eq!(
            est.state(),
            BbrState::ProbeBW,
            "Drain must release once inflight ({}) is back inside the BDP ({})",
            est.inflight_bytes(),
            est.bdp()
        );
    }

    #[test]
    fn test_bdp_calculation() {
        let mut est = BandwidthEstimator::new();
        let now = Instant::now();

        // Feed samples: 1400 bytes / 10ms = 140,000 bytes/sec
        for i in 0..5 {
            let sent = now + Duration::from_millis(i * 10);
            est.on_send(1400);
            est.on_ack(make_sample(sent, 10, 1400));
        }

        let bdp = est.bdp();
        // BDP = btl_bw * min_rtt
        // btl_bw ≈ 140,000 B/s, min_rtt ≈ 10ms
        // BDP ≈ 140,000 * 0.01 = 1,400 bytes
        assert!(bdp > 0, "BDP should be positive, got {}", bdp);
    }

    #[test]
    fn test_cwnd_minimum_in_probe_rtt() {
        let mut est = BandwidthEstimator::new();
        // Force ProbeRTT state
        est.state = BbrState::ProbeRTT;
        let cwnd = est.cwnd();
        assert_eq!(
            cwnd,
            PROBE_RTT_CWND_PACKETS * MIN_PACKET_SIZE,
            "ProbeRTT CWND should be {} (4 packets), got {}",
            PROBE_RTT_CWND_PACKETS * MIN_PACKET_SIZE,
            cwnd
        );
    }
}
