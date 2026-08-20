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
//!                      │  ProbeRTT   │  (every 10s: drain, then hold)
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
//! - **ProbeRTT:** Every 10s, reduce CWND to 4 packets, wait for the pipe to actually
//!   drain, and only then hold long enough for a packet to cross the emptied path and
//!   be acknowledged. Timing the window from entry instead measures the standing queue
//!   the sender built, which is the one thing the measurement must exclude.
//!
//! Loss is deliberately *not* a state. BBRv2 and BBRv3 respond to it with a
//! volume bound — `inflight_hi` — that the congestion window is capped by
//! (`BandwidthEstimator::adapt_inflight_bound` carries the reasoning); the
//! phase the connection is in never changes because a packet went missing.
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
    /// the min-RTT filter.
    ///
    /// It does **not** gate the delivery-rate half of the sample, which stays
    /// honest for a different reason: [`Self::delivered_bytes`] and
    /// [`Self::delivered_at`] are *not* restamped on a resend, so the rate is
    /// measured over an interval that spans the original transmission whichever
    /// copy is being acknowledged. That can only widen the denominator — an
    /// under-estimate, which a maximum filter discards.
    pub rtt_sampled: bool,
}

/// Sliding window to track min/max of a value
#[derive(Debug)]
struct WindowFilter {
    window: VecDeque<(Instant, u64)>,
    window_size: Duration,
    /// Smallest gap in time the minimum filter keeps between two retained
    /// entries — the rule that bounds its length, in place of the truncation
    /// the maximum filter uses. Derived from the horizon in [`Self::new`] so
    /// that the resulting entry count is [`WINDOW_FILTER_MAX_ENTRIES`] whatever
    /// horizon a filter is built with; see [`Self::push_separated`] for why the
    /// two filters cannot share one rule.
    min_separation: Duration,
}

impl WindowFilter {
    fn new(window_size: Duration) -> Self {
        Self {
            window: VecDeque::new(),
            window_size,
            // Entries are at least this far apart and none is older than the
            // horizon, so at most `WINDOW_FILTER_MAX_ENTRIES - 1` gaps fit
            // inside the window and at most that many entries plus one sit in
            // the deque. Dividing by one less than the ceiling is what makes the
            // bound exactly the ceiling rather than one past it.
            min_separation: window_size / (WINDOW_FILTER_MAX_ENTRIES as u32 - 1),
        }
    }

    /// Drop every entry older than the horizon.
    ///
    /// Named rather than written out twice, because both update paths open with
    /// it. **It has no caller outside them, and acquiring one is a design change
    /// rather than a refactor.** Ageing on every acknowledgement instead of on
    /// the ones a filter admits sounds like the stricter reading of "ten
    /// seconds", and for the bandwidth maximum it is the opposite: the
    /// app-limited gate in [`BandwidthEstimator::on_ack`] compares an incoming
    /// sample against the maximum this window is *currently holding*, so a
    /// window aged first can be an empty one, and a comparison against nothing
    /// admits everything. Expiry reached only through admission is what makes
    /// that gate mean something, and it is the shape the algorithm this file
    /// implements uses for the same reason.
    fn expire(&mut self, now: Instant) {
        while let Some(&(ts, _)) = self.window.front() {
            if now.duration_since(ts) > self.window_size {
                self.window.pop_front();
            } else {
                break;
            }
        }
    }

    /// The extremum currently retained — the front of the deque, which is the
    /// maximum for a filter driven by [`Self::update_max`] and the minimum for
    /// one driven by [`Self::update_min`] — or `None` once the horizon has
    /// emptied.
    fn head(&self) -> Option<u64> {
        self.window.front().map(|&(_, v)| v)
    }

    /// Append a sample to the **maximum** filter, evicting from the back first
    /// if the deque is at its ceiling.
    ///
    /// The maximum filter's deque runs largest at the front to smallest at the
    /// back, so the back is the least of everything retained: an entry smaller
    /// than every one ahead of it, which could only ever have been promoted to
    /// the top once all of those had expired. Discarding it leaves a set of real
    /// unexpired observations whose maximum is at or below the unbounded one, so
    /// the ceiling under-states the path and never over-states it. The back is
    /// also, after the domination loop above, strictly on the far side of the
    /// incoming sample, so dropping it and pushing keeps the newest observation
    /// — which is what stops a full filter from becoming one that cannot respond
    /// to fresh data at all.
    ///
    /// **The minimum filter must not use this**, and the reason is in
    /// [`Self::push_separated`]. See [`WINDOW_FILTER_MAX_ENTRIES`] for the
    /// ceiling's derivation.
    fn push_bounded(&mut self, now: Instant, value: u64) {
        if self.window.len() >= WINDOW_FILTER_MAX_ENTRIES {
            self.window.pop_back();
        }
        self.window.push_back((now, value));
    }

    /// Append a sample to the **minimum** filter, unless a smaller and more
    /// recent entry already makes it redundant for the next
    /// [`Self::min_separation`] — the length bound that replaces truncation
    /// there.
    ///
    /// **A minimum filter cannot be truncated safely at either end.** Its
    /// reading is the minimum of the retained set, and removing an element from
    /// a set can only raise its minimum; there is no end to evict from that
    /// escapes that. Evicting the front discards the current minimum outright.
    /// Evicting the back is worse than it looks: the deque runs smallest at the
    /// front to largest at the back, so the back is the *newest* surviving
    /// entry, and repeatedly dropping it leaves "the oldest entries plus the
    /// newest one". Once that old prefix ages out the sole survivor is the
    /// newest sample, which on a path building a queue is the largest round trip
    /// in the window. `min_rtt` is a multiplicand of
    /// `cwnd = cwnd_gain × btl_bw × min_rtt`, so that reading inflates the
    /// window, which deepens the queue, which raises the next round of samples.
    /// The maximum filter's truncation errs downward and costs throughput; this
    /// one errs upward and pays for it in a queue of the sender's own making.
    ///
    /// So nothing retained is ever discarded here. What is declined is an
    /// *incoming* sample, and only in the one case where declining it cannot
    /// move the reading: this runs after the domination loop, so the deque's
    /// back is strictly smaller than the incoming value, and a sample larger
    /// than everything held cannot be the minimum until every one of those has
    /// expired. Its whole window of relevance is the gap between its own
    /// timestamp and the back's — under one separation, by the test below — so
    /// declining it can shorten the horizon over which the reading is a minimum
    /// by at most that, and can never raise the reading above a round trip this
    /// endpoint actually timed. A sample that would *lower* the reading never
    /// reaches this test at all: it dominates, the loop above clears the entries
    /// it is smaller than, and if it is below everything the deque is emptied
    /// and the push is unconditional.
    ///
    /// The length that follows is arithmetic rather than a cap to be checked:
    /// retained timestamps are at least one separation apart and none is older
    /// than the horizon, so there are at most `horizon / separation` gaps and
    /// one more entry than that.
    fn push_separated(&mut self, now: Instant, value: u64) {
        if let Some(&(newest, _)) = self.window.back() {
            if now.duration_since(newest) < self.min_separation {
                return;
            }
        }
        self.window.push_back((now, value));
    }

    fn update_max(&mut self, now: Instant, value: u64) -> u64 {
        self.expire(now);
        // Remove entries smaller than the new value (they're dominated)
        while let Some(&(_, v)) = self.window.back() {
            if v <= value {
                self.window.pop_back();
            } else {
                break;
            }
        }
        self.push_bounded(now, value);
        // The maximum is always at the front
        self.head().unwrap_or(value)
    }

    fn update_min(&mut self, now: Instant, value: u64) -> u64 {
        self.expire(now);
        while let Some(&(_, v)) = self.window.back() {
            if v >= value {
                self.window.pop_back();
            } else {
                break;
            }
        }
        self.push_separated(now, value);
        self.head().unwrap_or(value)
    }
}

// ─── Constants ──────────────────────────────────────────────────────────────

/// Most entries either sliding-window filter retains, and the reason it is
/// bounded at all rather than "however many arrive".
///
/// The deque is pruned from the front by the horizon and from the back by
/// domination — a new sample evicts every retained entry it dominates. That
/// second rule is what normally keeps it short, and it is exactly the rule a
/// monotone sequence defeats: a strictly falling run of delivery rates dominates
/// nothing, so every one of its samples is appended and none is removed until
/// the horizon reaches it. At 40 Mbit/s with 1156-byte segments that is on the
/// order of forty thousand entries per direction per session, and the cadence
/// shaping the sequence is the peer's — it chooses when to acknowledge, and so
/// what interval each sample is divided by and therefore what rate it works out
/// to. The min-RTT filter has the same shape through a strictly rising run, and
/// a peer holds that end too: it cannot lower a round trip below the path's, but
/// it can raise every one of them by sitting on its acknowledgements a little
/// longer each time. An allocation whose length a remote party picks is the
/// shape this transport removes rather than defends, so both deques are bounded
/// at this many entries.
///
/// **They reach it by different rules, because one rule is safe in a maximum
/// filter and dangerous in a minimum one.** The maximum filter is truncated: at
/// the ceiling it evicts its own back, which is the least of everything
/// retained, so what is discarded is a candidate smaller than every entry ahead
/// of it and whatever remains is still a real, unexpired observation. A bounded
/// maximum therefore sits at or below the unbounded one at every instant. It
/// under-states the path and never over-states it, which is the side of the
/// error that matters: an under-stated bottleneck costs throughput, an
/// over-stated one paces into a queue of the sender's own making.
///
/// The minimum filter is **not** truncated, at either end. Its reading is the
/// minimum of the retained set, and removing an element from a set can only
/// raise that minimum — there is no end to evict from which escapes it, so no
/// truncation of a minimum filter errs in the safe direction. Back-eviction in
/// particular is not the mirror image of the maximum filter's: that deque runs
/// smallest at the front to largest at the back, so its back is the newest
/// entry, and dropping the newest repeatedly leaves the oldest entries plus one
/// recent one. When the old prefix ages out, the survivor is the largest round
/// trip in the window rather than the smallest — and `min_rtt` multiplies
/// `btl_bw` in `cwnd = cwnd_gain × btl_bw × min_rtt`, so the sender would size
/// its window from a queue it built and then add to the queue. That filter is
/// bounded by [`WindowFilter::push_separated`] instead, which declines incoming
/// samples that cannot move the reading rather than discarding retained ones,
/// and which reaches this same length because that is what its separation is
/// derived from.
///
/// The tests hold both directions rather than leaving them as arguments in a
/// comment: `a_bounded_filter_never_reports_a_higher_maximum_than_the_unbounded_one`
/// and `the_ceiling_evicts_the_least_of_a_maximum_filter_not_the_greatest` for
/// the first, `a_rising_round_trip_run_cannot_inflate_the_minimum_it_is_read_from`
/// for the second.
///
/// 1024 because that is the ARQ send buffer's segment cap
/// ([`MAX_PENDING_PACKETS`](crate::transport::stream)): the most segments one
/// stream can have outstanding, hence the most acknowledgements a single round
/// trip can return, hence the longest monotone run one round trip can produce. A
/// filter that holds a full flight's worth of candidates represents any one
/// round trip exactly, and what it declines to hold is cross-round-trip history
/// — which is the horizon's job, not the length's. The assertion below is what
/// keeps that a derivation rather than a coincidence: `MAX_PENDING_PACKETS` is a
/// live tuning dial, already const-asserted against the receive window, and
/// raising it to widen the send buffer would otherwise leave this ceiling
/// silently holding a fraction of a flight while the sentence above went on
/// claiming it held one. An entry is at most three machine words, so the two
/// filters together cost tens of kilobytes per session, against the 8 MiB of
/// receive-window growth (`SESSION_RECV_WINDOW_GROWTH_BUDGET`) a single session
/// may already draw.
const WINDOW_FILTER_MAX_ENTRIES: usize = 1024;

const _: () = assert!(
    WINDOW_FILTER_MAX_ENTRIES == crate::transport::stream::MAX_PENDING_PACKETS,
    "the filter ceiling is one round trip's worth of candidates, which is the ARQ \
     send buffer's segment cap: the two are one figure, and a send buffer widened \
     without this would leave the filters holding a fraction of a flight"
);

const _: () = assert!(
    WINDOW_FILTER_MAX_ENTRIES >= 2,
    "the minimum filter's separation is the horizon divided by one less than this \
     ceiling, so a ceiling of one divides by zero and a ceiling of zero describes a \
     filter that cannot hold the sample it was just given"
);

/// Probe cycle gains for ProbeBW phase (BBR cycle: 1.25, 0.75, 1.0, 1.0)
///
/// The average is exactly 1.0, so a converged flow paces at the bottleneck
/// rate. The 1.25 phase is not decoration: once the sender is paced, its own
/// delivery-rate samples are bounded by the rate it is pacing at, so a maximum
/// filter fed only by 1.0-gain rounds can never rise. This quarter, one round in
/// four, is the entire mechanism by which the estimate discovers that the path
/// got faster.
///
/// Four phases rather than the draft's eight is a deliberate trade, and it is
/// paid for in utilisation. The 0.75 round genuinely under-runs the link, while
/// the 1.25 round cannot over-run it — a link-limited path just queues the
/// excess — so the achieved average is `(1 + 0.75 + 1 + 1)/4` ≈ 94%, against
/// ≈ 97% for eight. What the shorter cycle buys is probing twice as often, and
/// probing is now the only route upward: the sender lost the ability to
/// discover bandwidth by overshooting the moment the pacer started governing.
/// Recovering three points of a link the sender might be measuring 35% low is
/// the wrong side of that trade.
const PROBE_BW_GAINS: [f64; 4] = [1.25, 0.75, 1.0, 1.0];

/// Pacing gain for Startup.
///
/// The draft's `high_gain` is `2/ln 2` ≈ 2.885, on the argument that a *paced*
/// sender needs that to double its delivery rate each round where a purely
/// window-clocked one doubles with 2.0. Once pacing became live that argument
/// applies here for the first time, so it was tried: eight measured runs at
/// each value on the in-crate 2 MiB/s, 200 ms harness were indistinguishable
/// (1.92–2.02 MB/s at 2.885 against 1.87–2.03 MB/s at 2.0). It is left at 2.0
/// because nothing measured says otherwise, and because the cwnd gain is also
/// 2.0 — with the two equal, one round trip of pacing at this gain delivers
/// exactly one congestion window, so pacing cannot slow the ramp it governs.
/// That equality is the load-bearing part; change one and check the other.
const STARTUP_PACING_GAIN: f64 = 2.0;

/// Startup growth threshold — if BW growth < 25%, consider pipe filled
const STARTUP_GROWTH_THRESHOLD: f64 = 0.25;

/// Rounds without growth before exiting Startup
const STARTUP_ROUNDS_LIMIT: u32 = 3;

/// The round trip a fresh estimator assumes before it has measured one.
///
/// A guess, not an observation, and the distinction matters wherever the figure
/// is treated as a bound: nothing prevents the true path from being slower.
const INITIAL_MIN_RTT: Duration = Duration::from_millis(100);

/// ProbeRTT interval — enter ProbeRTT every 10 seconds
const PROBE_RTT_INTERVAL: Duration = Duration::from_secs(10);

/// How long a delivery-rate sample is retained in [`BandwidthEstimator::bw_filter`]
/// — the horizon over which `btl_bw` is a maximum.
///
/// **The unit is the interesting part, and it is not the draft's.** Linux BBR
/// ages this filter in *round trips*: `bbr_bw_rtts` is `CYCLE_LEN + 2` = 10, so
/// a peak survives ten round trips and no longer. Ten wall-clock seconds is a
/// different quantity on every path — about forty-two round trips on the 235 ms
/// route this transport is measured over, four times the canonical residency,
/// and only ten on a 1 s satellite hop. Measured against the draft, this
/// endpoint retains a peak far longer than intended on any fast path, and that
/// over-retention is real rather than notional.
///
/// It is still wall clock, and the reason is what a round trip is counted by.
/// `update_round` closes a round when an acknowledgement arrives for a packet
/// that was *sent* at or beyond the mark taken when the round opened. A sender
/// that cannot send — congestion window full, acknowledgements trickling back —
/// puts no new packet on the wire, so no acknowledgement can carry a mark past
/// the round's, and the round count simply stops. That is not a corner case; it
/// is precisely the state the worst recorded over-estimates came out of, where
/// one leg sat on 684 KB in flight while its acknowledgement rate collapsed to
/// 6–12 KB/s and the advertised estimate stood unchanged across four
/// consecutive half-second samples. A horizon counted in round trips would have
/// stopped ageing exactly there — it would lengthen the freeze it was adopted to
/// shorten. A wall clock ages through a stall; a round counter is gated by the
/// peer's acknowledgements and does not.
///
/// So the unit stays, and the length is left where it is until there are numbers
/// to move it against: the raw per-acknowledgement sample now recorded beside
/// the filtered maximum is what will say how much of the gap between the
/// estimate and the delivered rate is this horizon retaining a peak and how much
/// is the arithmetic of the samples themselves. Changing a value later is cheap;
/// changing the unit is not, which is why the unit is argued here and the value
/// is not yet.
const BW_FILTER_WINDOW: Duration = Duration::from_secs(10);

/// How long an RTT sample is retained in [`BandwidthEstimator::rtt_filter`] —
/// the horizon over which `min_rtt` is a minimum. BBR's `MinRTTFilterLen`.
///
/// This one is wall clock in the draft too, and it is tied to
/// [`PROBE_RTT_INTERVAL`] rather than chosen independently: ProbeRTT exists to
/// put a fresh sample into this filter, taken across a pipe it has deliberately
/// emptied. A refresh interval longer than the horizon would leave the filter
/// with nothing in it between refreshes; one shorter would pay the floored
/// window more often than the measurement it is buying needs. The two are the
/// same figure in the draft for that reason, and the assertion below keeps them
/// the same figure here — a divergence between them is not a tuning choice, it
/// is one of those two failures.
const RTT_FILTER_WINDOW: Duration = Duration::from_secs(10);

const _: () = assert!(
    RTT_FILTER_WINDOW.as_secs() == PROBE_RTT_INTERVAL.as_secs(),
    "ProbeRTT refreshes the min-RTT filter, so its interval and that filter's \
     horizon are one figure: a longer interval empties the filter between \
     refreshes, a shorter one floors the window more often than the measurement \
     needs"
);

/// How long ProbeRTT holds the floored window **after the pipe has drained**,
/// or one round trip if that is longer.
///
/// Not measured from entry. Entry cuts the congestion window; it does not
/// retire the bytes already sitting in the bottleneck's queue, and until those
/// have been served every round trip the sender times still includes them. A
/// clock started on entry therefore times exactly the inflated path ProbeRTT
/// exists to escape, and — because the min-RTT filter is a ten-second
/// *minimum* — an unrefreshed filter can only ratchet upward, taking
/// `bdp = btl_bw × min_rtt` and `cwnd = 2 × bdp` with it, which grows the queue
/// that caused the problem.
const PROBE_RTT_DURATION: Duration = Duration::from_millis(200);

/// How long the *drain* half of ProbeRTT is allowed to take, in round trips,
/// before the sender leaves anyway.
///
/// ProbeRTT cuts the congestion window to the floor and then waits for the pipe
/// to empty, which is the only condition under which the round trip it times is
/// the path's own. Waiting for that unconditionally is a way to be pinned at the
/// floor forever: retransmissions bypass the congestion window entirely
/// (`Stream::poll_send`'s Pass 0 and Pass 1), so a path losing enough to keep the
/// sender resending keeps `inflight_bytes` above the floor no matter what the
/// window says.
///
/// Two round trips, and the figure is derived rather than chosen. Inflight at
/// entry is at most the window the previous phase allowed, `cwnd_gain × BDP`
/// with `cwnd_gain` = 2: one bandwidth-delay product in the path itself and at
/// most one more queued in front of it. A queue of one BDP costs one round trip
/// of bottleneck service to clear, and the last packet's acknowledgement needs
/// one propagation delay on top of that. Anything still outstanding after those
/// two is not a queue this sender can drain by waiting.
///
/// Being expressed in `min_rtt` rather than in milliseconds is what makes it
/// self-scaling in the right direction: the flows that need the longest drain
/// are exactly the ones whose `min_rtt` has been inflated by the standing queue,
/// so they are granted proportionally more time to clear it.
const PROBE_RTT_MAX_DRAIN_ROUND_TRIPS: u32 = 2;

/// Minimum CWND in ProbeRTT mode (4 packets)
const PROBE_RTT_CWND_PACKETS: u64 = 4;

/// Minimum packet size assumption (bytes)
const MIN_PACKET_SIZE: u64 = 1400;

/// Loss rate over one round trip past which the round counts as congested —
/// BBRv2/v3's `BBRLossThresh`, and the same 2% they use.
///
/// Below it, loss is treated as the path's own noise and the sender does not
/// react at all. That is the whole point of a threshold: a link that drops a
/// couple of percent independently of how hard it is driven gives no
/// information about where its knee is, and a sender that backs off for it
/// simply hands the capacity away.
const LOSS_THRESH: f64 = 0.02;

/// Multiplicative decrease applied to [`BandwidthEstimator::inflight_hi`] on a
/// round that lost more than `LOSS_THRESH` — BBRv2/v3's `BBRBeta`, and the
/// same 0.7.
const INFLIGHT_HI_BETA: f64 = 0.7;

/// Floor on [`BandwidthEstimator::inflight_hi`], as a multiple of the
/// bandwidth-delay product. **Load-bearing, and the reason this file changed.**
///
/// A sender's measurable delivery rate is bounded by what it has in flight:
/// `rate ≤ inflight / rtt`. Cap inflight at exactly one BDP — `btl_bw ×
/// min_rtt` — and the best sample it can ever produce is `btl_bw`, which a
/// maximum filter discards as no news. Any cap at or below the BDP is therefore
/// not a back-off but an absorbing state: it removes the mechanism by which the
/// sender could discover that the path is faster than it thinks.
///
/// 1.25 rather than some arbitrary margin because that is [`PROBE_BW_GAINS`]'s
/// probe phase — the phase whose entire job is to ask the path for a quarter
/// more than the current estimate. A bound that squeezed below it would leave
/// the probe unable to probe.
const INFLIGHT_HI_FLOOR_GAIN: f64 = 1.25;

/// Multiplicative increase applied to [`BandwidthEstimator::inflight_hi`] on a
/// round that stayed under `LOSS_THRESH`, until it clears the window the
/// gains alone would allow and is dropped entirely.
///
/// Without it the bound is a one-way ratchet and a connection that saw one bad
/// minute carries the cap for the rest of its life.
const INFLIGHT_HI_RELAX_GAIN: f64 = 1.25;

/// Turn a locally timed round trip and the peer's claimed acknowledgement delay
/// into the RTT sample this endpoint is willing to believe.
///
/// `latest_rtt` is measured end to end by this endpoint's own clock.
/// `ack_delay_us` is the `Sack::ack_delay_us` the *peer* wrote — the only term
/// in the sample nobody local observed. `rtt_floor` is the smallest round trip
/// this endpoint has actually timed on the path, or `None` before it has timed
/// any; see [`BandwidthEstimator::rtt_floor`].
///
/// One bound, from RFC 9002 §5.3: "MUST NOT subtract the acknowledgment delay
/// from the RTT sample if the resulting value is smaller than the min_rtt",
/// with §5.2's first-sample rule as the `None` arm. It is all-or-nothing — a
/// claim that would land the sample under the floor is dropped whole rather
/// than trimmed to fit — which is what makes a nonsensical claim harmless
/// without a separate guard against nonsense: a delay exceeding the round trip
/// it rides on exceeds `floor + delay` too, so the test fails and the
/// endpoint's own measurement stands. An earlier revision also clamped the
/// claim to `latest_rtt` first, in the spirit of §5.3's "lesser of the
/// acknowledgment delay and the peer's max_ack_delay". That clamp changed the
/// answer for exactly one input this crate cannot produce — a floor of zero,
/// which the seeding rule below forbids — and changed it for the worse, to the
/// zero it was supposed to prevent. A redundant guard that is wrong wherever it
/// is not redundant is worse than none, so it is gone and the function is
/// crate-private, which is what makes "cannot produce" a statement about the
/// whole program rather than about this file.
///
/// The invariant that buys, inductively: the returned value is either the raw
/// locally observed round trip or a value at or above `rtt_floor`. Read it as
/// exactly what it is — one bound, and a *lower* one. Anywhere inside
/// `[rtt_floor, latest_rtt]` the peer still picks the answer, because a claim of
/// `latest_rtt - rtt_floor` is subtracted in full and lands exactly on the
/// floor. What the peer cannot do is invent a path faster than one this
/// endpoint's own clock timed; what it can do is choose any point of that
/// interval, on every acknowledgement, forever.
///
/// "Forever" is not a figure of speech, and it is the part a reader is most
/// likely to assume away. A sample landing exactly on the floor does not merely
/// fail to lower it: `WindowFilter::update_min` back-pops every entry at or
/// above the new value — the incumbent minimum included, since the comparison is
/// `>=` — and pushes the new pair with the current timestamp. The floor is
/// therefore re-dated by the very sample that ties it, so the ten-second window
/// whose job is to let `min_rtt` rise when the path degrades never expires it.
///
/// For the minimum filter itself that residue is tolerable: the peer's best play
/// is to keep the minimum where it is, which is also what reporting nothing
/// would achieve, and a `min_rtt` held low only shrinks `cwnd = 2 × btl_bw ×
/// min_rtt`. It is a peer conceding bandwidth to itself, not taking any. For a
/// gauge reporting the *latest* round trip it is a real limitation and belongs
/// in the operator's hands rather than in a footnote: a peer claiming
/// `latest_rtt - rtt_floor` every time pins the published reading at the best
/// round trip the path ever had and hides every degradation since.
///
/// One acknowledgement has two consumers — `min_rtt`, which sizes the
/// congestion window, and the per-path RTT gauge an operator reads — and this
/// is called exactly once for the pair, from [`BandwidthEstimator::on_ack`],
/// which hands the result back for the gauge to publish. It is a free function
/// so that the arithmetic can be stated and tested without a clock or an
/// estimator, but the single call site is the load-bearing part: two
/// subtractions written separately is exactly how the gauge came to accept one
/// the window already refused, and giving the gauge its own call to this
/// function would only have made the two agree until the next edit.
pub(crate) fn ack_delay_adjusted_rtt(
    latest_rtt: Duration,
    rtt_floor: Option<Duration>,
    ack_delay_us: u64,
) -> Duration {
    let ack_delay = Duration::from_micros(ack_delay_us);

    match rtt_floor {
        // No round trip has been timed yet, so there is no measurement to
        // protect and nothing trustworthy to compare against — the opening
        // `min_rtt` is a guess, and anchoring the guard on it would let a peer
        // on a slower path subtract its way down to that guess on the very
        // first acknowledgement.
        None => latest_rtt,
        Some(floor) if latest_rtt >= floor.saturating_add(ack_delay) => {
            latest_rtt.saturating_sub(ack_delay)
        }
        Some(_) => latest_rtt,
    }
}

// ─── Estimator ──────────────────────────────────────────────────────────────

/// BBR-like Bandwidth Estimator
pub struct BandwidthEstimator {
    /// Current BBR state
    state: BbrState,
    /// Estimated bottleneck bandwidth (bytes/sec)
    btl_bw: u64,
    /// Minimum observed RTT
    min_rtt: Duration,
    /// Sliding-window max filter for bandwidth, over [`BW_FILTER_WINDOW`].
    bw_filter: WindowFilter,
    /// Sliding-window min filter for RTT, over [`RTT_FILTER_WINDOW`].
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
    /// Upper bound on inflight imposed by observed loss — BBRv2/v3's
    /// `inflight_hi`. `None` means the path has given no reason for one and the
    /// window is whatever `cwnd_gain` asks for.
    ///
    /// This, not the gain, is where the loss response belongs. See
    /// `adapt_inflight_bound`.
    inflight_hi: Option<u64>,

    // ── ProbeRTT timer ──
    /// Timestamp of last ProbeRTT exit (or Startup start)
    last_probe_rtt_time: Instant,
    /// When we entered ProbeRTT — the origin of the ceiling in
    /// [`Self::probe_rtt_ceiling`], and nothing else.
    probe_rtt_entered: Option<Instant>,
    /// [`Self::min_rtt`] as it stood when ProbeRTT was entered. Both the hold
    /// and the ceiling are derived from this one figure rather than from the
    /// live filter, so the relation between them holds for the whole episode.
    ///
    /// Reading the live filter instead made the ceiling movable *by the
    /// measurement ProbeRTT was in the middle of taking*: a successful drain
    /// lowers `min_rtt`, which shrinks a live ceiling, which can then fire
    /// before the hold it is supposed to sit above — ending the window at the
    /// instant the pipe emptied, with no packet yet across the drained path.
    probe_rtt_reference_rtt: Duration,
    /// When [`Self::inflight_bytes`] fell to the ProbeRTT window, and so the
    /// first instant at which a packet this sender puts on the wire crosses a
    /// path it is no longer queueing behind itself.
    ///
    /// `None` while the pipe is full, and cleared again if it refills:
    /// retransmissions bypass the congestion window entirely, so a lossy path
    /// can put the queue back after the mark was taken, and a hold timed across
    /// that is a hold across a full pipe. Re-evaluating keeps the field's meaning
    /// literal at every instant it is read; the ceiling is what stops the
    /// re-evaluation from becoming an unbounded wait.
    probe_rtt_drained_at: Option<Instant>,
    /// State to return to after ProbeRTT
    prior_state: BbrState,

    // ── App-limited detection ──
    /// Whether the sender is currently application-limited
    app_limited: bool,
    /// Delivered bytes at the time app-limited was last set
    app_limited_at_delivered: u64,

    // ── Loss accounting ──
    /// Bytes reported lost since the current round trip opened. Reset by
    /// `adapt_inflight_bound` once the round has been judged.
    round_bytes_lost: u64,
    /// [`Self::delivered_bytes`] as it stood when the current round opened —
    /// the denominator half of the round's loss rate.
    round_delivered_mark: u64,
    /// Bytes reported lost over the life of the connection. Diagnostics, and
    /// the observable that proves the send path reports loss at all.
    bytes_lost: u64,

    /// The most recent per-acknowledgement delivery rate this endpoint
    /// computed, before the filter had any say in it. Diagnostics only —
    /// nothing in this file reads it back.
    ///
    /// It exists because [`Self::btl_bw`] answers a different question than a
    /// recorded series usually needs. `btl_bw` is a *maximum* over a
    /// ten-second horizon; the throughput a run is compared against is a *mean*
    /// over a much shorter observation interval. A maximum over the longer
    /// window exceeds a mean over the shorter one by construction, and with the
    /// probe gain in [`PROBE_BW_GAINS`] applied one round trip in four the
    /// probing round genuinely delivers about a quarter more than the cycle's
    /// own mean. So a recorded ratio of estimate to delivered bytes that sits
    /// modestly above one is, in part, an artefact of comparing two different
    /// statistics — and there is no way to tell how much of it is that from
    /// the filtered figure alone. With the raw sample beside it the two
    /// hypotheses come apart: a raw sample tracking the delivered rate while
    /// the estimate sits far above it is the filter retaining a peak, and a raw
    /// sample that itself reads high is the sample arithmetic.
    ///
    /// This is an observable and not an input. It is derived from quantities
    /// the estimator already consumes, it feeds no decision, and reading it
    /// hands a peer no new influence over anything — which is what keeps it
    /// outside the rule that no control-loop quantity may be under the peer's
    /// control.
    last_delivery_rate: u64,
}

impl BandwidthEstimator {
    /// Create a new estimator starting in Startup state.
    pub fn new() -> Self {
        let now = Instant::now();
        Self {
            state: BbrState::Startup,
            btl_bw: 0,
            min_rtt: INITIAL_MIN_RTT,
            bw_filter: WindowFilter::new(BW_FILTER_WINDOW),
            rtt_filter: WindowFilter::new(RTT_FILTER_WINDOW),
            rtt_filter_seeded: false,
            delivered_bytes: 0,
            last_delivery: now,
            pacing_gain: STARTUP_PACING_GAIN,
            cwnd_gain: 2.0,
            round_count: 0,
            next_round_delivered: 0,
            round_start: false,
            filled_pipe: false,
            full_bw: 0,
            rounds_without_growth: 0,
            inflight_bytes: 0,
            inflight_hi: None,
            last_probe_rtt_time: now,
            probe_rtt_entered: None,
            probe_rtt_reference_rtt: INITIAL_MIN_RTT,
            probe_rtt_drained_at: None,
            prior_state: BbrState::ProbeBW,
            app_limited: false,
            app_limited_at_delivered: 0,
            round_bytes_lost: 0,
            round_delivered_mark: 0,
            bytes_lost: 0,
            last_delivery_rate: 0,
        }
    }

    // ── Public API ──────────────────────────────────────────────────────────

    /// Notify the estimator that `bytes` were sent (increases inflight).
    pub fn on_send(&mut self, bytes: u64) {
        self.inflight_bytes = self.inflight_bytes.saturating_add(bytes);
    }

    /// Process an ACK and update bandwidth estimates.
    ///
    /// Returns the new recommended pacing rate (bytes/sec) and the RTT sample
    /// this acknowledgement yielded — the round trip this endpoint timed, less
    /// as much of the peer's claimed ack delay as the `ack_delay_adjusted_rtt`
    /// guard permits (RFC 9002 §5.2/§5.3). The sample is handed back rather than
    /// left for a caller to reconstruct because the floor bounding it lives
    /// behind the same lock as the filter: fetching that floor separately meant
    /// a second acquisition per retired segment, and a cumulative
    /// acknowledgement retires a whole flight at once. It is also the only way
    /// the figure stays *one* figure — the per-path RTT gauge publishes exactly
    /// what the filter was offered, and two subtractions written separately is
    /// how the gauge came to accept one the window already refused.
    pub fn on_ack(&mut self, sample: DeliverySample) -> (u64, Duration) {
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

        // The arithmetic that turns those two into a usable sample lives in
        // [`ack_delay_adjusted_rtt`], because the observability path samples the
        // same round trip and must not reach its own, second conclusion about
        // what the peer's claim is worth.
        let adjusted_rtt =
            ack_delay_adjusted_rtt(latest_rtt, self.rtt_floor(), sample.ack_delay_us);

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
        // gated, and it does not need to be: `delivered_bytes` and
        // `delivered_at` stay with the segment's *original* transmission across
        // a resend (`Stream::poll_send` moves only `sent_at`), so the rate
        // measures bytes delivered since those bytes were first entrusted to
        // the path, over the time since then. Both ends of that interval are
        // this endpoint's own readings and neither depends on which copy the
        // acknowledgement answers. The interval is at least as wide as the
        // truth, so the rate is at most as high — and a maximum filter is
        // indifferent to a low sample, where a single high one governs the
        // window for the whole ten-second window.
        //
        // Gating it on Karn's condition as well would be the stricter rule and
        // the wrong one: a path losing enough that most segments get resent
        // would stop feeding the filter entirely, `btl_bw` would decay to zero
        // as the window emptied, and `cwnd` would pin to its floor.
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

        // Publish the raw sample before the filter gets a say in it, so a
        // recorded series can tell a retained peak from a high sample. Guarded
        // on there being a sample at all: an acknowledgement that retired no
        // bytes is not a rate of zero, it is the absence of a rate, and writing
        // it down as zero would put a reading in the series that no measurement
        // supports. See the field for what the pair is for.
        if delivery_rate > 0 {
            self.last_delivery_rate = delivery_rate;
        }

        // An app-limited sample measures how fast the application wrote, not how
        // fast the path carries, so it must not be allowed to *set* the maximum
        // the window is sized from.
        //
        // The escape is the other half of the same argument and is not optional.
        // Such a sample can only ever under-state the path, so one that comes in
        // at or above the current maximum is still a valid lower bound on
        // capacity — and admitting it is the only thing that lets a connection
        // whose every write is smaller than a window measure anything at all.
        // Without it, a request/response flow leaves `btl_bw` at zero forever,
        // `bdp` with it, and the window pinned on its floor. This is canonical
        // (`bbr_update_bw`: `if (!rs->is_app_limited || bw >= bbr_max_bw(sk))`).
        //
        // **The operand of that comparison is the retained maximum, and the
        // horizon must not be aged before it is read.** Ageing on every
        // acknowledgement rather than on the admitted ones was tried, on the
        // argument that "ten seconds" should mean ten seconds however the
        // samples in between are labelled. It defeats this gate rather than
        // tightening it. A flow that is application-limited for one whole
        // horizon empties the window, `btl_bw` reads zero, and the next
        // app-limited sample clears `delivery_rate >= 0` and becomes the
        // maximum — the application's own write rate installed as the path's
        // capacity, which is precisely what the gate exists to refuse. Measured
        // on a 1 MB/s, 200 ms bottleneck simulation driven by this estimator's
        // own window and pacing rate, a bulk phase followed by sixteen seconds
        // of request/response left `btl_bw` at 33,740 B/s against the 1,000,000
        // the path was offering, delivered a quarter as much in the first second
        // after the application resumed, and never recovered the shortfall.
        // Expiry stays where the filter puts it — inside `update_max`, reached
        // only by a sample this test admitted — which is also where the
        // algorithm this file implements puts it.
        if delivery_rate > 0 && (!sample.is_app_limited || delivery_rate >= self.btl_bw) {
            self.btl_bw = self.bw_filter.update_max(now, delivery_rate);
        }

        // The app-limited phase ends once everything that was outstanding when
        // it opened has been retired — see `note_app_limited_drain` for why the
        // watermark includes inflight.
        if self.app_limited && self.delivered_bytes > self.app_limited_at_delivered {
            self.app_limited = false;
        }

        // A round trip has closed, so the loss booked against it is now a rate
        // and can be judged. This runs after the filters above so the bound is
        // sized against the freshest bandwidth-delay product this endpoint has.
        if self.round_start {
            self.adapt_inflight_bound(sample.is_app_limited);
        }

        // Run state machine
        self.update_state(now, sample.is_app_limited);

        // Return pacing rate, and the sample the filter above was offered — the
        // one figure this acknowledgement is worth, reached once.
        (self.pacing_rate(), adjusted_rtt)
    }

    /// Notify a packet loss — BBRv2/v3's `BBRHandleLostPacket`.
    ///
    /// This books the loss against the round trip in progress and does nothing
    /// else. In particular it does not change the state machine's phase, does
    /// not touch a gain, and does not move the congestion window: the response
    /// is decided once per round trip, over the round's *loss rate*, in
    /// `adapt_inflight_bound`.
    ///
    /// The granularity matters more than it looks. `drain_streams_priority_ordered`
    /// calls this once per retransmitted segment, and on a path losing a few
    /// percent with a few hundred segments in flight that is several calls per
    /// round trip, every round trip, forever. A response scaled per call fires
    /// continuously and carries no information; the draft's `BBRLossThresh`
    /// exists precisely so that a rate — not an event — is what the sender
    /// reacts to.
    pub fn on_loss(&mut self, bytes: u64) {
        self.inflight_bytes = self.inflight_bytes.saturating_sub(bytes);
        self.round_bytes_lost = self.round_bytes_lost.saturating_add(bytes);
        self.bytes_lost = self.bytes_lost.saturating_add(bytes);
    }

    /// A send pass ended because the application had nothing more to give.
    ///
    /// Opens an application-limited phase, but only if the congestion window
    /// still had room: a stream can run dry with the window *already* full — the
    /// last segment it had fitted exactly — and that pass was bounded by the
    /// window, not by the application. Requiring room left over is what keeps
    /// "ran out of data" from quietly covering "ran out of window", and it is
    /// canonical (Linux's `tcp_rate_check_app_limited` carries the same
    /// `packets_in_flight < cwnd` term).
    ///
    /// The check lives here rather than at the call site because both figures
    /// are behind this lock; asking for them first meant a snapshot and two
    /// further acquisitions per pass, on every session, on every heartbeat.
    ///
    /// The phase covers everything **outstanding at this moment**, which is why
    /// the watermark is `delivered + inflight` and not `delivered` alone. Those
    /// in-flight bytes are precisely the ones that were on the wire while the
    /// sender had nothing more to give; marking at `delivered` would end the
    /// phase on the very next acknowledgement and leave the guard covering one
    /// sample instead of a flight. This is BBR's
    /// `BBRMarkConnectionAppLimited`.
    pub fn note_app_limited_drain(&mut self) {
        if self.inflight_bytes >= self.cwnd() {
            return;
        }
        self.app_limited = true;
        self.app_limited_at_delivered = self.delivered_bytes.saturating_add(self.inflight_bytes);
    }

    /// Whether the sender is currently considered application-limited.
    pub fn is_app_limited(&self) -> bool {
        self.app_limited
    }

    /// Get current recommended pacing rate (bytes/sec).
    ///
    /// `btl_bw × pacing_gain` — the estimate scaled by whatever the current
    /// phase is trying to do to it. In ProbeBW the four gains average to
    /// exactly 1.0, so a converged flow paces at the bottleneck rate and the
    /// 1.25 phase is the mechanism by which it finds out the path got faster.
    ///
    /// Floored at `pacing_rate_floor`, which is what makes it safe to
    /// hand this to a live rate limiter. Two ways the unfloored figure is not a
    /// rate anyone should be metered against: before the first acknowledgement
    /// `btl_bw` is zero, and the old `btl_bw.max(1)` turned that into two bytes
    /// per second; and a single early under-estimate would otherwise meter the
    /// sender below what its own congestion window already permits, which is a
    /// throttle no measurement asked for.
    pub fn pacing_rate(&self) -> u64 {
        let base = (self.btl_bw as f64 * self.pacing_gain) as u64;
        base.max(self.pacing_rate_floor())
    }

    /// The rate below which pacing would be stricter than the congestion window
    /// already is: the smallest window this controller will ever use, released
    /// once per minimum round trip.
    ///
    /// A window of `W` bytes admits `W / rtt` bytes per second by construction —
    /// that is what a window *is*. So a pacer set below `cwnd_floor / min_rtt`
    /// is not shaping the window's release, it is refusing to release a window
    /// the controller has already decided is safe. Pacing may smooth what
    /// congestion control permits; it may not overrule it downward.
    ///
    /// This never binds on a flow with a real estimate — `btl_bw × gain` is
    /// far above it the moment Startup has a sample — which is the point: it is
    /// a floor under the bootstrap, not a term in the steady state.
    fn pacing_rate_floor(&self) -> u64 {
        let rtt = self.min_rtt.as_secs_f64();
        if rtt <= 0.0 {
            return u64::MAX;
        }
        let floor_window = (PROBE_RTT_CWND_PACKETS * MIN_PACKET_SIZE) as f64;
        (floor_window / rtt) as u64
    }

    /// Get recommended congestion window size (bytes).
    ///
    /// Two separate things decide it, and keeping them separate is the point:
    ///
    /// - `cwnd_gain` governs *growth*. It is the headroom above the
    ///   bandwidth-delay product that lets a delivery-rate sample come back
    ///   larger than the current estimate, which is the only way the estimate
    ///   ever rises. Loss must not touch it.
    /// - [`Self::inflight_hi`] governs the *level*. It is where the loss
    ///   response lives, and it is floored above the BDP so that backing off
    ///   never costs the sender its ability to probe.
    pub fn cwnd(&self) -> u64 {
        if self.state == BbrState::ProbeRTT {
            // During ProbeRTT, reduce CWND to minimum
            return PROBE_RTT_CWND_PACKETS * MIN_PACKET_SIZE;
        }
        let target = (self.bdp() as f64 * self.cwnd_gain) as u64;
        let bounded = match self.inflight_hi {
            Some(hi) => target.min(hi),
            None => target,
        };
        bounded.max(PROBE_RTT_CWND_PACKETS * MIN_PACKET_SIZE)
    }

    /// Get the Bandwidth-Delay Product (BDP) in bytes.
    pub fn bdp(&self) -> u64 {
        (self.btl_bw as f64 * self.min_rtt.as_secs_f64()) as u64
    }

    /// Get current bytes in flight.
    pub fn inflight_bytes(&self) -> u64 {
        self.inflight_bytes
    }

    /// The loss-imposed upper bound on inflight, if the path has earned one.
    /// `None` means no round trip has yet lost more than `LOSS_THRESH` (or the
    /// bound has since been relaxed away).
    pub fn inflight_hi(&self) -> Option<u64> {
        self.inflight_hi
    }

    /// Bytes reported lost over the life of the connection.
    ///
    /// This is the observable for "the send path told congestion control about
    /// a retransmission". It is deliberately a counter and not a state: loss no
    /// longer moves the state machine, so asking which phase the connection is
    /// in answers a different question.
    pub fn bytes_lost(&self) -> u64 {
        self.bytes_lost
    }

    /// Get estimated bottleneck bandwidth (bytes/sec).
    pub fn bottleneck_bandwidth(&self) -> u64 {
        self.btl_bw
    }

    /// The most recent delivery-rate sample (bytes/sec), as computed, before
    /// the filter decided whether to keep it.
    ///
    /// Read this next to [`Self::bottleneck_bandwidth`], never instead of it.
    /// That one is the maximum the controller acts on; this one is the single
    /// observation the last acknowledgement yielded, and the gap between them
    /// is the only direct evidence of how much of a high-looking estimate is
    /// the filter holding a peak and how much is the samples themselves. Zero
    /// until the connection has produced a sample that delivered something.
    ///
    /// A caller sampling this on a timer is reading whichever acknowledgement
    /// arrived last before the instant it asked, so a series of these has a
    /// meaningful central value and a meaningless spread: the tail describes the
    /// sampling cadence, not the path. That distinction is the point of the
    /// figure — comparing a maximum over a horizon with a mean over an interval
    /// is what it exists to disentangle, and taking a percentile of a point
    /// sample would be the same mistake one size down.
    pub fn last_delivery_rate(&self) -> u64 {
        self.last_delivery_rate
    }

    /// Get minimum observed RTT.
    pub fn min_rtt(&self) -> Duration {
        self.min_rtt
    }

    /// [`Self::min_rtt`] when it reflects a round trip this endpoint actually
    /// timed, and `None` while it is still the opening guess.
    ///
    /// This is the reference [`ack_delay_adjusted_rtt`] guards against, so the
    /// distinction is the whole point: handing out the placeholder as though it
    /// were a measurement would give a peer a number to subtract down to before
    /// any measurement existed.
    ///
    /// The filter is seeded only from a sample of at least one microsecond
    /// (`on_ack`, at the `rtt_us > 0` gate), so a returned `Some` is never zero
    /// — which is what lets the guard above carry a single comparison instead of
    /// a second one against the round trip.
    pub(crate) fn rtt_floor(&self) -> Option<Duration> {
        self.rtt_filter_seeded.then_some(self.min_rtt)
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

    /// The loss response, run once per round trip — BBRv2/v3's
    /// `BBRAdaptLowerBounds` / `BBRHandleInflightTooHigh`, reduced to the part
    /// that earns its keep here.
    ///
    /// Three decisions, each of which the previous version got wrong:
    ///
    /// **Loss is a rate, judged per round trip.** The draft compares the bytes
    /// lost in a round against the bytes that round put in flight, and reacts
    /// only past `BBRLossThresh` (2%). Reacting per lost segment instead is not
    /// a stricter version of the same rule, it is a different rule: on a path
    /// losing a few percent the sender retransmits several times per round trip
    /// and so is permanently in the reacting condition, which conveys nothing.
    ///
    /// **The response is a bound on the volume, not a change to the gain.** The
    /// two are not interchangeable. A gain of 1.0 holds inflight at exactly the
    /// bandwidth-delay product, and a sender holding a BDP delivers `btl_bw ×
    /// min_rtt` bytes per round trip by construction — so every sample it takes
    /// reports exactly the rate it already believes, and `btl_bw`, a maximum
    /// filter, never moves. The connection stops being able to find out that
    /// the path is faster than it thinks, and no amount of running gives it back:
    /// growth needs headroom, and the back-off consumed the headroom. Capping
    /// the *level* while leaving the gain alone backs the sender off without
    /// taking away the instrument.
    ///
    /// **The bound is floored above the BDP, and it relaxes.** The floor is
    /// [`INFLIGHT_HI_FLOOR_GAIN`] — strictly above one BDP, so the fixed point
    /// above cannot be reached by the bound either. The relaxation is what stops
    /// it being a ratchet: rounds that stay under the threshold lift it back
    /// until it no longer binds, and it is dropped entirely.
    ///
    /// The two constants are the draft's: decrease by `BBRBeta` (0.7) on a
    /// congested round, at most once per round.
    ///
    /// What this deliberately does not implement: `bw_lo`/`bw_hi`, the
    /// short-term *bandwidth* bounds. They bound the pacing rate on a shorter
    /// horizon than `btl_bw`'s max filter, and the drain now does consult the
    /// pacer, so unlike the inflight bound they would be wired to something.
    /// They are still left out: this controller already answers loss with a
    /// volume bound, and adding a second, faster response to the same signal
    /// without a measurement to size it against is how a controller acquires
    /// two knobs that fight. The congestion window remains the bound that
    /// decides how much may be outstanding; the pacer decides how fast it
    /// leaves.
    fn adapt_inflight_bound(&mut self, is_app_limited: bool) {
        let round_delivered = self
            .delivered_bytes
            .saturating_sub(self.round_delivered_mark);
        let round_lost = self.round_bytes_lost;

        // Open the next round's accounting before any early return, or a round
        // that declined to judge would fold its bytes into its successor.
        self.round_delivered_mark = self.delivered_bytes;
        self.round_bytes_lost = 0;

        let round_total = round_delivered.saturating_add(round_lost);
        if round_total == 0 {
            return;
        }

        // Two kinds of round say nothing about where the path's knee is, and
        // the draft skips both.
        //
        // An app-limited round delivered less because the application had
        // nothing to send, so its loss *rate* has a small denominator it did
        // not earn — one retransmit against a nearly idle round reads as
        // heavy congestion. ProbeRTT is worse: the window there is pinned to
        // four packets on purpose, so both halves of the ratio are the
        // controller's own doing rather than the path's.
        if is_app_limited || self.state == BbrState::ProbeRTT {
            return;
        }

        // The window the gains alone would allow, and the floor the bound may
        // not go under. Both track the current estimate, so a bound set when
        // the path looked slow does not stay tight once it opens up.
        let target = (self.bdp() as f64 * self.cwnd_gain) as u64;
        let floor = (self.bdp() as f64 * INFLIGHT_HI_FLOOR_GAIN) as u64;

        if (round_lost as f64) > (round_total as f64) * LOSS_THRESH {
            let base = self.inflight_hi.unwrap_or(target);
            let reduced = (base as f64 * INFLIGHT_HI_BETA) as u64;
            self.inflight_hi = Some(reduced.max(floor));
        } else if let Some(hi) = self.inflight_hi {
            let relaxed = (hi as f64 * INFLIGHT_HI_RELAX_GAIN) as u64;
            self.inflight_hi = if relaxed >= target {
                None
            } else {
                Some(relaxed.max(floor))
            };
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

    /// Whether the pipe is empty enough that the next packet out crosses a path
    /// this sender is no longer queueing behind itself.
    ///
    /// The comparison is against the ProbeRTT window rather than against zero
    /// because the window *is* the definition of empty here: the sender is
    /// allowed that much outstanding throughout, so requiring less would be
    /// requiring a condition ProbeRTT itself prevents.
    fn pipe_is_drained(&self) -> bool {
        self.inflight_bytes <= PROBE_RTT_CWND_PACKETS * MIN_PACKET_SIZE
    }

    /// How long the floored window is held once the pipe has drained.
    ///
    /// Canonical BBR's `max(ProbeRTTDuration, one round trip)`. The round-trip
    /// term is what gives a packet sent over the emptied path time to be
    /// acknowledged; without it the window can end before the sample it exists
    /// to take could possibly have arrived. The reference is the round trip as
    /// it stood at entry — which on a queueing path is the inflated figure, and
    /// so generous — but it is a measurement of a path, not a guarantee about
    /// one: a route that lengthened inside the last filter window, or a filter
    /// still sitting on its opening guess because every acknowledgement so far
    /// was ambiguous under Karn, both leave it short. A ProbeRTT that ends
    /// before its sample lands simply takes none and retries in ten seconds,
    /// which is what the pre-drain code did on every cycle.
    fn probe_rtt_hold(&self) -> Duration {
        PROBE_RTT_DURATION.max(self.probe_rtt_reference_rtt)
    }

    /// Longest ProbeRTT may run, measured from entry.
    ///
    /// The drain allowance ([`PROBE_RTT_MAX_DRAIN_ROUND_TRIPS`] round trips)
    /// plus the hold that follows a successful drain. Both terms come from the
    /// same entry-time round trip as [`Self::probe_rtt_hold`], which is what
    /// makes the ceiling strictly greater than any completion whose drain
    /// finished inside the allowance: it can only ever end a ProbeRTT whose pipe
    /// took longer than that to empty.
    fn probe_rtt_ceiling(&self) -> Duration {
        self.probe_rtt_reference_rtt
            .saturating_mul(PROBE_RTT_MAX_DRAIN_ROUND_TRIPS)
            .saturating_add(self.probe_rtt_hold())
    }

    /// Run BBR state machine transitions.
    fn update_state(&mut self, now: Instant, is_app_limited: bool) {
        // ── ProbeRTT check: global timer, any state can enter except Startup ──
        //
        // Both ProbeRTT bounds below are wall clock — `Instant` differences
        // against `sample.acked_at`, which is a real timestamp — and the draft
        // is explicit that this is right: ProbeRTTInterval and ProbeRTTDuration
        // "are explicitly wall-clock measurements", unlike the round counting
        // above. They are not a second instance of the per-acknowledgement
        // confusion and are deliberately left alone.
        //
        // One divergence from the draft remains, deliberately. The trigger is
        // "10 s since the last ProbeRTT" rather than the draft's "the min-RTT
        // filter has gone stale", so a flow whose filter is fresh still pays a
        // window at the floor cwnd every 10 s. Under a *windowed* minimum filter
        // that trade is much smaller than it looks: the filter's minimum is
        // re-confirmed only by a sample at or below it, so on a path with a
        // steady round trip the stamp goes stale on almost every cycle anyway
        // and the staleness trigger degenerates to this timer while adding a
        // second way for a flow to talk itself out of measuring. The cost of
        // paying it unnecessarily is bounded below; the cost of skipping it
        // wrongly is the ratchet this function exists to break.
        if self.state != BbrState::ProbeRTT
            && self.state != BbrState::Startup
            && now.duration_since(self.last_probe_rtt_time) >= PROBE_RTT_INTERVAL
        {
            self.prior_state = self.state;
            self.transition_to(BbrState::ProbeRTT);
            self.probe_rtt_entered = Some(now);
            self.probe_rtt_reference_rtt = self.min_rtt;
            // A flow that was already running an empty pipe has nothing to
            // wait for, and must not be charged the drain allowance for it.
            self.probe_rtt_drained_at = self.pipe_is_drained().then_some(now);
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
                let Some(entered) = self.probe_rtt_entered else {
                    // No entry stamp means no clock to run, and a state with no
                    // way out is worse than an early exit.
                    self.probe_rtt_drained_at = None;
                    self.transition_to(BbrState::ProbeBW);
                    return;
                };
                // Re-evaluated rather than latched: a retransmission bypasses
                // the congestion window, so the queue can come back after the
                // mark was taken, and a hold timed across a refilled pipe is a
                // hold across the very thing ProbeRTT is trying to get out from
                // behind. Clearing the mark restarts the hold from whenever the
                // pipe next empties; the ceiling bounds the retrying.
                if !self.pipe_is_drained() {
                    self.probe_rtt_drained_at = None;
                } else if self.probe_rtt_drained_at.is_none() {
                    self.probe_rtt_drained_at = Some(now);
                }

                // The measurement is complete once the pipe has emptied *and*
                // the hold has elapsed since it did.
                let hold = self.probe_rtt_hold();
                let measured = self
                    .probe_rtt_drained_at
                    .is_some_and(|drained| now.duration_since(drained) >= hold);
                // ...and the ceiling, for the pipe that never empties.
                let expired = now.duration_since(entered) >= self.probe_rtt_ceiling();

                if measured || expired {
                    self.last_probe_rtt_time = now;
                    self.probe_rtt_entered = None;
                    self.probe_rtt_drained_at = None;
                    self.transition_to(self.prior_state);
                }
            }
        }
    }

    /// Transition to a new BBR state.
    fn transition_to(&mut self, new_state: BbrState) {
        match new_state {
            BbrState::Startup => {
                // The pacing gain deliberately exceeds the cwnd gain here. That
                // makes the *window* the binding constraint during the ramp and
                // leaves the pacer doing what it is good at — spreading the
                // window across the round trip instead of releasing it in one
                // piece — which is the right division of labour for a phase
                // whose whole job is to grow the window as fast as the path
                // will tolerate. Raising the cwnd gain to match would widen the
                // volume bound, and the volume bound is what decides how much a
                // burst can be if pacing ever stops governing.
                self.pacing_gain = STARTUP_PACING_GAIN;
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
                // The only state that legitimately runs at a gain of 1.0, and
                // only because `cwnd()` short-circuits it to the four-packet
                // floor anyway: ProbeRTT is not trying to measure bandwidth, it
                // is deliberately emptying the pipe to time the path.
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
            .field("inflight_hi", &self.inflight_hi)
            .field("delivered_bytes", &self.delivered_bytes)
            .field("bytes_lost", &self.bytes_lost)
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

    /// Karn's gate stops at the RTT filter. The delivery-rate half of a sample
    /// from a retransmitted segment is still a measurement and must still be
    /// taken.
    ///
    /// The tempting stricter rule — drop the whole sample whenever the segment
    /// had been resent — is safe only while retransmissions are rare. On a path
    /// losing enough that most segments are resent at least once it starves the
    /// filter: `btl_bw` decays to zero as the ten-second window empties, `cwnd
    /// = 2 × btl_bw × min_rtt` collapses onto its 5600-byte floor, and the
    /// sender is pinned there for the rest of the connection — precisely the
    /// failure the floor and the inflight bound exist to avoid.
    ///
    /// So this feeds nothing but ambiguous samples (`rtt_sampled: false`) and
    /// requires that the estimator both finds the rate and *raises* it when the
    /// path genuinely speeds up. A rate sample stays honest under Fix 2 for a
    /// different reason than Karn's: the interval and the bytes are both
    /// measured from the original transmission, so the worst it can be is an
    /// under-estimate, and a maximum filter is indifferent to those.
    #[test]
    fn a_resent_segments_delivery_rate_still_reaches_the_filter() {
        const PACKET: u64 = 1200;
        const ROUND: u64 = 100;
        const SLOW_RTT_MS: u64 = 200;
        // Four times the delivery in the same interval — a path that opened up.
        const FAST_RTT_MS: u64 = 50;

        let mut est = BandwidthEstimator::new();
        let start = Instant::now();

        // Round one, every segment a retransmission: 100 × 1200 B delivered over
        // 200 ms is 600 KB/s.
        for _ in 0..ROUND {
            est.on_send(PACKET);
        }
        for _ in 0..ROUND {
            est.on_ack(DeliverySample {
                delivered_bytes: 0,
                delivered_at: start,
                sent_at: start,
                acked_at: start + Duration::from_millis(SLOW_RTT_MS),
                packet_bytes: PACKET,
                is_app_limited: false,
                ack_delay_us: 0,
                rtt_sampled: false,
            });
        }

        let slow = ROUND * PACKET * 1000 / SLOW_RTT_MS;
        assert!(
            est.bottleneck_bandwidth() >= slow - slow / 10,
            "an ambiguous round trip is still a delivery-rate measurement; the \
             estimate is {} B/s against {} B/s delivered",
            est.bottleneck_bandwidth(),
            slow
        );

        // Round two, also all retransmissions, on a path that now carries the
        // same window in a quarter of the time.
        let second = start + Duration::from_millis(SLOW_RTT_MS);
        let mark = est.delivered_bytes();
        for _ in 0..ROUND {
            est.on_send(PACKET);
        }
        for _ in 0..ROUND {
            est.on_ack(DeliverySample {
                delivered_bytes: mark,
                delivered_at: second,
                sent_at: second,
                acked_at: second + Duration::from_millis(FAST_RTT_MS),
                packet_bytes: PACKET,
                is_app_limited: false,
                ack_delay_us: 0,
                rtt_sampled: false,
            });
        }

        let fast = ROUND * PACKET * 1000 / FAST_RTT_MS;
        assert!(
            est.bottleneck_bandwidth() >= fast - fast / 10,
            "the estimator must still discover a genuine speed-up from resent \
             segments; the estimate is {} B/s against {} B/s delivered",
            est.bottleneck_bandwidth(),
            fast
        );
    }

    /// The bound the two consumers of an acknowledgement share, stated on its
    /// own and without a clock.
    ///
    /// `ack_delay_adjusted_rtt` is called from two places — the min-RTT filter
    /// here and, by way of the sample `on_ack` hands back, the per-path RTT
    /// gauge in the data pump — and the property both rely on is a single
    /// sentence: once this endpoint has timed a round trip, no value the peer
    /// can put in `Sack::ack_delay_us` returns a sample below that floor. The
    /// sweep below is exhaustive in spirit rather than in number: it walks the
    /// delay from nothing, through the honest range, past the whole round trip,
    /// to `u64::MAX`, which is where the arithmetic would wrap or saturate to
    /// zero if the comparison against the floor were dropped or written as a
    /// subtraction.
    ///
    /// The companion half is that an honest delay is still subtracted — a guard
    /// that simply ignored the field would pass the bound above and quietly
    /// turn the estimator's propagation delay back into a queuing delay.
    #[test]
    fn no_reported_ack_delay_drives_the_shared_sample_below_the_timed_floor() {
        let floor = Duration::from_millis(200);
        let latest = Duration::from_millis(260);

        for delay_us in [
            0,
            1_000,
            59_000,
            60_000,
            60_001,
            199_000,
            259_999,
            260_000,
            260_001,
            4_000_000,
            u64::MAX,
        ] {
            let adjusted = ack_delay_adjusted_rtt(latest, Some(floor), delay_us);
            assert!(
                adjusted >= floor,
                "a claimed ack delay of {delay_us} µs pulled the sample to {adjusted:?}, \
                 below the {floor:?} this endpoint timed itself"
            );
            assert!(
                adjusted <= latest,
                "a claimed ack delay of {delay_us} µs inflated the sample to {adjusted:?}, \
                 above the {latest:?} round trip actually observed"
            );
        }

        // 60 ms of the 260 ms trip leaves 200 ms, which is exactly the floor and
        // therefore the largest subtraction §5.3 permits here — the boundary the
        // sweep straddles above.
        assert_eq!(
            ack_delay_adjusted_rtt(latest, Some(floor), 60_000),
            floor,
            "a delay that lands the sample exactly on the floor must still be subtracted"
        );

        // Before any round trip has been timed there is nothing to protect and
        // no trustworthy reference, so the raw local measurement stands whatever
        // the peer says — RFC 9002 §5.2's first-sample rule.
        assert_eq!(
            ack_delay_adjusted_rtt(latest, None, u64::MAX),
            latest,
            "the first sample must be the round trip this endpoint observed"
        );
    }

    /// The premise the guard above rests on, pinned separately from the guard.
    ///
    /// `ack_delay_adjusted_rtt` carries one comparison, and one is enough only
    /// because a floor it is handed is never zero: at a zero floor the test
    /// `latest_rtt >= 0 + ack_delay` admits any claim up to the whole round trip
    /// and the sample lands on zero — the outcome the floor exists to prevent.
    /// Nothing in the function can see that, so the property lives here, where
    /// the floor is made.
    ///
    /// Two ways an acknowledgement could produce one, and both are exercised: a
    /// round trip that measures under a microsecond, which is ordinary on
    /// loopback, and one that measures exactly nothing, which two clock readings
    /// in the same tick give. The `rtt_us > 0` gate in `on_ack` is what refuses
    /// both, so this fails the moment that gate is relaxed — including by
    /// someone who has just proved to their own satisfaction that a zero sample
    /// is harmless to a minimum filter, which it is, and who has no reason to be
    /// looking at a subtraction in the observability path.
    #[test]
    fn a_sub_microsecond_round_trip_does_not_seed_a_zero_floor() {
        let mut est = BandwidthEstimator::new();
        let start = Instant::now();

        assert_eq!(
            est.rtt_floor(),
            None,
            "an estimator that has acknowledged nothing has timed no round trip"
        );

        for elapsed in [
            Duration::ZERO,
            Duration::from_nanos(1),
            Duration::from_nanos(999),
        ] {
            est.on_send(1200);
            est.on_ack(DeliverySample {
                delivered_bytes: 0,
                delivered_at: start,
                sent_at: start,
                acked_at: start + elapsed,
                packet_bytes: 1200,
                is_app_limited: false,
                ack_delay_us: 0,
                rtt_sampled: true,
            });
            assert_eq!(
                est.rtt_floor(),
                None,
                "a round trip of {elapsed:?} rounds to zero microseconds and must leave the \
                 filter unseeded — a zero floor is a floor that bounds nothing"
            );
        }

        // And once a round trip does measure, the floor it publishes is that
        // measurement rather than the opening guess.
        est.on_send(1200);
        est.on_ack(make_sample(start, 50, 1200));
        assert_eq!(
            est.rtt_floor(),
            Some(Duration::from_millis(50)),
            "the first sample of at least a microsecond must seed the filter with itself"
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
        est.note_app_limited_drain();
        assert!(est.is_app_limited());

        // The tail has to cross the horizon rather than stop short of it. Each
        // of these is stamped a second later than the last and acknowledged a
        // second after that, so the run is carried to the first sample landing
        // strictly beyond [`BW_FILTER_WINDOW`] — the instant at which the
        // retained peak would age out if anything but an admitted sample were
        // allowed to age it, and therefore the only instant at which the
        // assertion below is about the gate rather than about the schedule.
        // Derived from the horizon so that moving the horizon moves the guard
        // with it.
        let past_horizon = BW_FILTER_WINDOW.as_secs();
        for i in 5..=past_horizon {
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

    // ── ProbeRTT ────────────────────────────────────────────────────────────

    /// One flight in the closed-loop path model below.
    struct PathFlight {
        bytes: u64,
        sent_at: Instant,
        acked_at: Instant,
        delivered_mark: u64,
        delivered_time: Instant,
    }

    /// A closed loop just detailed enough to make ProbeRTT's premise real.
    ///
    /// The round trip a packet measures is the path's propagation delay plus
    /// the time the bottleneck needs to clear whatever was already queued when
    /// that packet was sent — `prop + inflight/bw`. The only way that queue
    /// shrinks is by being served at `bw`. That is the whole mechanism ProbeRTT
    /// exists to exploit, and a test that simply hands the estimator a low RTT
    /// sample it could never have taken proves nothing about it.
    ///
    /// The sender offers whatever the congestion window has room for, metered
    /// at the bottleneck rate, so a window cut to the ProbeRTT floor stops new
    /// data going out but does not retire the bytes already in the queue.
    ///
    /// `trace` collects `(state, inflight)` after every acknowledgement, which
    /// is what lets a test ask the question that matters: what was still in
    /// flight at the moment ProbeRTT decided it was done.
    fn run_bottlenecked_path(
        est: &mut BandwidthEstimator,
        start: Instant,
        prop: Duration,
        bw: u64,
        span: Duration,
        step: Duration,
        trace: &mut Vec<(BbrState, u64)>,
    ) {
        let mut queue: VecDeque<PathFlight> = VecDeque::new();
        let mut now = start;
        let deadline = start + span;
        let per_step = (bw as f64 * step.as_secs_f64()) as u64;

        while now < deadline {
            while queue.front().is_some_and(|f| f.acked_at <= now) {
                let Some(flight) = queue.pop_front() else {
                    break;
                };
                est.on_ack(DeliverySample {
                    delivered_bytes: flight.delivered_mark,
                    delivered_at: flight.delivered_time,
                    sent_at: flight.sent_at,
                    acked_at: flight.acked_at,
                    packet_bytes: flight.bytes,
                    is_app_limited: false,
                    ack_delay_us: 0,
                    rtt_sampled: true,
                });
                trace.push((est.state(), est.inflight_bytes()));
            }

            let room = est.cwnd().saturating_sub(est.inflight_bytes());
            let bytes = room.min(per_step);
            if bytes > 0 {
                // Queueing delay is what is already in the pipe, served at the
                // bottleneck rate; the propagation delay is on top of it.
                let rtt = prop + Duration::from_secs_f64(est.inflight_bytes() as f64 / bw as f64);
                let delivered_mark = est.delivered_bytes();
                let delivered_time = est.delivered_time();
                est.on_send(bytes);
                queue.push_back(PathFlight {
                    bytes,
                    sent_at: now,
                    acked_at: now + rtt,
                    delivered_mark,
                    delivered_time,
                });
            }
            now += step;
        }
    }

    /// **ProbeRTT must empty the pipe before it times it.**
    ///
    /// Cutting the congestion window to `PROBE_RTT_CWND_PACKETS × MIN_PACKET_SIZE`
    /// (5600 B) stops *new* data going out. It does not remove the bytes already
    /// sitting in the bottleneck's queue, and those bytes are exactly what makes
    /// every round trip long. So a ProbeRTT window whose clock starts on entry
    /// measures the same inflated path it was trying to escape.
    ///
    /// The arithmetic, for the path simulated here — 600 KB/s, 200 ms
    /// propagation. A converged flow runs at `cwnd = 2 × btl_bw × min_rtt`, so
    /// inflight is two bandwidth-delay products and the queue in front of the
    /// path holds one of them: `queue = inflight/bw = 2 × min_rtt`, and the
    /// round trip a packet measures is `prop + 2 × min_rtt`. The min-RTT filter
    /// is a *ten-second minimum*, so once the last drained-path sample ages out
    /// it can only take the smallest inflated sample available and `min_rtt`
    /// becomes `prop + 2 × min_rtt_old` — 200 ms → 600 ms on the first ratchet.
    /// `bdp = btl_bw × min_rtt` grows with it, `cwnd = 2 × bdp` grows with that,
    /// and the queue grows again. The loop is closed and self-reinforcing, and a
    /// 200 ms window at the floor never breaks it: at 600 KB/s a 240 KB backlog
    /// needs 400 ms of bottleneck service before a single packet crosses an
    /// empty path.
    ///
    /// Two assertions, both of which the entry-clocked version fails: ProbeRTT
    /// must not report itself done while the pipe is still full, and the low
    /// sample it exists to collect must actually reach the filter.
    #[test]
    fn probe_rtt_holds_until_the_pipe_has_actually_drained() {
        const PROP: Duration = Duration::from_millis(200);
        const BW: u64 = 600_000;
        const STEP: Duration = Duration::from_millis(10);
        // Long enough for the first two ProbeRTT windows (due 10 s apart) and
        // for the ten-second RTT filter to have turned over once behind them.
        const SPAN: Duration = Duration::from_millis(24_000);

        let mut est = BandwidthEstimator::new();
        let mut trace: Vec<(BbrState, u64)> = Vec::new();
        run_bottlenecked_path(&mut est, Instant::now(), PROP, BW, SPAN, STEP, &mut trace);

        let floor = PROBE_RTT_CWND_PACKETS * MIN_PACKET_SIZE;

        // The run has to have contained a ProbeRTT episode at all, or the rest
        // asserts nothing.
        assert!(
            trace.iter().any(|(s, _)| *s == BbrState::ProbeRTT),
            "the {} s run never entered ProbeRTT — the fixture, not the \
             controller, is what this would be testing",
            SPAN.as_secs()
        );

        // Find every ProbeRTT → not-ProbeRTT boundary and ask what was still
        // outstanding when the controller decided it had timed a drained path.
        for pair in trace.windows(2) {
            let (before, _) = pair[0];
            let (after, inflight_after) = pair[1];
            if before == BbrState::ProbeRTT && after != BbrState::ProbeRTT {
                assert!(
                    inflight_after <= floor,
                    "ProbeRTT ended with {inflight_after} B still in flight against a \
                     {floor} B window — the queue was never served, so no packet \
                     crossed an empty path and the sample it took is the inflated \
                     one it already had"
                );
            }
        }

        // ...and the point of the exercise: the filter has to come out holding
        // the propagation delay, not the queued round trip. A quarter of margin
        // covers the fluid model's step quantisation.
        assert!(
            est.min_rtt() <= PROP + PROP / 4,
            "min_rtt is {:?} on a path whose propagation delay is {:?} — the \
             ten-second minimum filter only ever ratcheted upward",
            est.min_rtt(),
            PROP
        );
    }

    /// One acknowledgement on a path whose backlog is held fixed.
    ///
    /// Pinning `inflight_bytes` models the one thing that genuinely keeps the
    /// pipe from emptying under a floored window: retransmissions bypass the
    /// congestion window entirely (`Stream::poll_send`'s Pass 0 and Pass 1), so
    /// a path losing enough to keep the sender resending keeps putting bytes on
    /// the wire no matter what `cwnd()` says.
    fn ack_holding_backlog(
        est: &mut BandwidthEstimator,
        sent_at: Instant,
        rtt: Duration,
        inflight: u64,
    ) {
        const PACKET: u64 = 1200;
        est.inflight_bytes = inflight;
        let delivered_mark = est.delivered_bytes();
        let delivered_time = est.delivered_time();
        est.on_send(PACKET);
        est.on_ack(DeliverySample {
            delivered_bytes: delivered_mark,
            delivered_at: delivered_time,
            sent_at,
            acked_at: sent_at + rtt,
            packet_bytes: PACKET,
            is_app_limited: false,
            ack_delay_us: 0,
            rtt_sampled: true,
        });
    }

    /// Drive a flow to a converged estimate on a `rtt` path, then park it in
    /// ProbeBW with its ProbeRTT timer due.
    fn ready_for_probe_rtt(rtt: Duration) -> (BandwidthEstimator, Instant) {
        const PACKETS: u64 = 100;
        const PACKET: u64 = 1200;

        let mut est = BandwidthEstimator::new();
        let start = Instant::now();
        let mut t = start;
        for _ in 0..4 {
            ack_one_round_trip(&mut est, PACKETS, PACKET, t, rtt);
            t += rtt;
        }
        est.state = BbrState::ProbeBW;
        est.last_probe_rtt_time = t - PROBE_RTT_INTERVAL;
        (est, t)
    }

    /// **The bound.** "Wait until the pipe has drained" without a ceiling is a
    /// way for a peer to pin the connection at the 5600-byte floor for the rest
    /// of its life: retransmissions bypass the congestion window, so a lossy or
    /// unresponsive path can keep `inflight_bytes` above the floor indefinitely
    /// while acknowledgements keep arriving to drive the state machine.
    ///
    /// The ceiling is expressed in the path's own units — the drain allowance is
    /// [`PROBE_RTT_MAX_DRAIN_ROUND_TRIPS`] round trips, because inflight at entry
    /// is at most `cwnd_gain × BDP` = two bandwidth-delay products, one of which
    /// is queue that costs one round trip of bottleneck service to clear and one
    /// of which is the path itself — plus the hold that follows a successful
    /// drain. On this 200 ms path that is 2 × 200 ms + max(200 ms, 200 ms) =
    /// 600 ms, and the sender must be out by then.
    ///
    /// This is the two-sided half of the test above: it rejects a fix that
    /// simply waits for a drain that never comes.
    #[test]
    fn probe_rtt_is_bounded_when_the_backlog_never_clears() {
        const RTT: Duration = Duration::from_millis(200);
        const BACKLOG: u64 = 500_000;

        let (mut est, mut t) = ready_for_probe_rtt(RTT);

        ack_holding_backlog(&mut est, t, RTT, BACKLOG);
        assert_eq!(
            est.state(),
            BbrState::ProbeRTT,
            "precondition: the ProbeRTT timer was due and should have fired"
        );
        let entered = t;

        // Two round trips of drain allowance plus the post-drain hold. Nothing
        // ever drains here, so this is the ceiling and nothing else.
        let bound = RTT * PROBE_RTT_MAX_DRAIN_ROUND_TRIPS + PROBE_RTT_DURATION.max(RTT);

        // Acknowledgements keep arriving — the peer is answering, it is the
        // backlog that will not clear — well past the ceiling.
        let mut left_after: Option<Duration> = None;
        for _ in 0..40 {
            t += RTT / 4;
            ack_holding_backlog(&mut est, t, RTT, BACKLOG);
            if left_after.is_none() && est.state() != BbrState::ProbeRTT {
                left_after = Some(t.duration_since(entered));
            }
        }

        let left = left_after.unwrap_or_else(|| {
            panic!(
                "the sender is still in ProbeRTT {:?} after entry with a backlog that \
                 never clears — its window is pinned at {} B for the life of the \
                 connection",
                t.duration_since(entered),
                PROBE_RTT_CWND_PACKETS * MIN_PACKET_SIZE
            )
        });
        assert!(
            left <= bound + RTT / 4,
            "ProbeRTT ran {left:?} against a {bound:?} ceiling"
        );
    }

    /// **The other side of the bound.** A flow whose pipe is already empty must
    /// not be held for the ceiling — the ceiling is a safety valve, not the
    /// duration. Canonical BBR holds for `max(ProbeRTTDuration, one round trip)`
    /// measured from the drain, and a drained flow drains at entry.
    ///
    /// This rejects "always wait the maximum", which would turn a 200 ms
    /// measurement into a 600 ms one on every cycle and cost three times the
    /// throughput it needed to.
    #[test]
    fn probe_rtt_ends_promptly_on_a_path_with_no_queue() {
        const RTT: Duration = Duration::from_millis(200);

        let (mut est, mut t) = ready_for_probe_rtt(RTT);

        // Nothing outstanding: this path carries no standing queue at all.
        ack_holding_backlog(&mut est, t, RTT, 0);
        assert_eq!(
            est.state(),
            BbrState::ProbeRTT,
            "precondition: the ProbeRTT timer was due and should have fired"
        );
        let entered = t;

        let hold = PROBE_RTT_DURATION.max(RTT);
        let ceiling = RTT * PROBE_RTT_MAX_DRAIN_ROUND_TRIPS + hold;

        let mut left_after: Option<Duration> = None;
        for _ in 0..40 {
            t += RTT / 8;
            ack_holding_backlog(&mut est, t, RTT, 0);
            if left_after.is_none() && est.state() != BbrState::ProbeRTT {
                left_after = Some(t.duration_since(entered));
            }
        }

        let left = left_after.expect("ProbeRTT never ended on an already-drained path");
        assert!(
            left < ceiling,
            "an already-drained path was held in ProbeRTT for {left:?}, up against the \
             {ceiling:?} ceiling that exists for paths that never drain"
        );
        assert!(
            left >= hold,
            "ProbeRTT ended after {left:?}, short of the {hold:?} a packet needs to \
             cross the drained path and come back — the sample it exists to take \
             cannot have arrived"
        );
    }

    /// **A pipe that refilled after it emptied has to be waited out again.**
    ///
    /// The drain mark is not a milestone the episode passes once. Retransmissions
    /// bypass the congestion window entirely, so a burst of loss can put the
    /// queue back after the mark was taken — and a hold timed across that period
    /// is a hold across a full pipe, which is the exact measurement ProbeRTT
    /// exists to avoid. Latching the mark makes the field's own description
    /// ("the first instant at which a packet crosses a path this sender is no
    /// longer queueing behind itself") false for every instant after the refill.
    ///
    /// The ceiling is what keeps the re-evaluation from becoming an unbounded
    /// wait; `probe_rtt_is_bounded_when_the_backlog_never_clears` is its side of
    /// the same coin.
    #[test]
    fn probe_rtt_does_not_time_a_pipe_that_refilled_after_it_drained() {
        const RTT: Duration = Duration::from_millis(200);
        const BACKLOG: u64 = 500_000;

        let (mut est, mut t) = ready_for_probe_rtt(RTT);

        // Enter with the pipe already empty, so the mark is taken at entry.
        ack_holding_backlog(&mut est, t, RTT, 0);
        assert_eq!(
            est.state(),
            BbrState::ProbeRTT,
            "precondition: the ProbeRTT timer was due and should have fired"
        );
        let entered = t;

        let hold = PROBE_RTT_DURATION.max(RTT);
        let ceiling = RTT * PROBE_RTT_MAX_DRAIN_ROUND_TRIPS + hold;

        // ...and then the queue comes back, well before the hold would have
        // elapsed, and stays.
        t += RTT / 8;
        while t.duration_since(entered) < ceiling - RTT / 8 {
            ack_holding_backlog(&mut est, t, RTT, BACKLOG);
            assert_eq!(
                est.state(),
                BbrState::ProbeRTT,
                "ProbeRTT declared itself done {:?} after entry with {BACKLOG} B in \
                 flight — it timed the hold from a drain the pipe had long since \
                 undone, so the round trip it measured is the queued one",
                t.duration_since(entered)
            );
            t += RTT / 8;
        }

        // The ceiling still ends it, and the other ProbeRTT tests pin that.
        for _ in 0..8 {
            t += RTT / 8;
            ack_holding_backlog(&mut est, t, RTT, BACKLOG);
        }
        assert_ne!(
            est.state(),
            BbrState::ProbeRTT,
            "the ceiling did not end an episode whose pipe never re-emptied"
        );
    }

    /// **The ceiling may not pre-empt the measurement it exists to bound.**
    ///
    /// It is derived as "the drain allowance plus the hold that follows a
    /// successful drain", which only holds together if both terms are the same
    /// round trip. Recomputed from the live filter they are not: a successful
    /// ProbeRTT *lowers* `min_rtt` — that is the entire point of it — and a
    /// shrinking ceiling can then fire before the hold it is supposed to sit
    /// above, ending the window at the instant the pipe emptied with no packet
    /// yet across the drained path. A slow drain plus an honest low sample is
    /// enough; no adversary is required.
    #[test]
    fn probe_rtt_holds_its_measurement_even_as_the_measurement_lowers_min_rtt() {
        const ENTRY_RTT: Duration = Duration::from_millis(600);
        const DRAINED_RTT: Duration = Duration::from_millis(200);
        const BACKLOG: u64 = 500_000;
        /// Long enough that a ceiling recomputed from `DRAINED_RTT`
        /// (2 × 200 ms + 200 ms = 600 ms) would already have fired.
        const DRAIN_TAKES: Duration = Duration::from_millis(1_000);

        let (mut est, mut t) = ready_for_probe_rtt(ENTRY_RTT);

        ack_holding_backlog(&mut est, t, ENTRY_RTT, BACKLOG);
        assert_eq!(
            est.state(),
            BbrState::ProbeRTT,
            "precondition: the ProbeRTT timer was due and should have fired"
        );
        let entered = t;

        // The queue drains slowly, and the acknowledgements arriving meanwhile
        // report the shorter round trip of a path that is emptying.
        while t.duration_since(entered) < DRAIN_TAKES {
            t += DRAINED_RTT / 4;
            ack_holding_backlog(&mut est, t, DRAINED_RTT, BACKLOG);
        }
        assert!(
            est.min_rtt() <= DRAINED_RTT,
            "precondition: the filter should have taken the lower samples ({:?})",
            est.min_rtt()
        );
        assert_eq!(
            est.state(),
            BbrState::ProbeRTT,
            "precondition: the episode must still be running — a ceiling taken from \
             the entry-time round trip is {:?}",
            ENTRY_RTT * PROBE_RTT_MAX_DRAIN_ROUND_TRIPS + PROBE_RTT_DURATION.max(ENTRY_RTT)
        );

        // ...and now it empties.
        let drained_at = t;
        let mut left_after: Option<Duration> = None;
        for _ in 0..40 {
            t += DRAINED_RTT / 4;
            ack_holding_backlog(&mut est, t, DRAINED_RTT, 0);
            if left_after.is_none() && est.state() != BbrState::ProbeRTT {
                left_after = Some(t.duration_since(drained_at));
                break;
            }
        }

        let held = left_after.expect("ProbeRTT never ended after the pipe emptied");
        let hold = PROBE_RTT_DURATION.max(ENTRY_RTT);
        assert!(
            held >= hold,
            "ProbeRTT ended {held:?} after the pipe emptied, short of the {hold:?} hold \
             — the ceiling shrank underneath the episode as its own measurement lowered \
             min_rtt, and ended the window before a packet could cross the drained path"
        );
    }

    /// The filter must still be able to move *up*.
    ///
    /// A route change genuinely lengthens the path, and a min-RTT filter that
    /// refused upward movement would size the bandwidth-delay product — and so
    /// the congestion window — against a path that no longer exists, then
    /// under-run the new one forever. The ten-second window is what allows the
    /// rise; nothing about draining the pipe before timing it may interfere
    /// with that.
    #[test]
    fn min_rtt_still_rises_when_the_path_genuinely_gets_longer() {
        const PACKETS: u64 = 40;
        const PACKET: u64 = 1200;
        const SHORT: Duration = Duration::from_millis(100);
        const LONG: Duration = Duration::from_millis(400);

        let mut est = BandwidthEstimator::new();
        let start = Instant::now();

        let mut t = start;
        for _ in 0..4 {
            ack_one_round_trip(&mut est, PACKETS, PACKET, t, SHORT);
            t += SHORT;
        }
        assert_eq!(
            est.min_rtt(),
            SHORT,
            "precondition: the short path should be measured"
        );

        // The route changes. Every subsequent round trip is four times as long,
        // and after the filter window has turned over the old measurement is no
        // longer evidence about this path.
        t = start + Duration::from_millis(11_000);
        for _ in 0..6 {
            ack_one_round_trip(&mut est, PACKETS, PACKET, t, LONG);
            t += LONG;
        }

        assert_eq!(
            est.min_rtt(),
            LONG,
            "the path is {LONG:?} long now; a filter stuck at {:?} sizes the window \
             for a path that no longer exists",
            est.min_rtt()
        );
    }

    // ── The loss response ───────────────────────────────────────────────────

    /// Segment size for the closed-loop simulations below.
    const SIM_PACKET: u64 = 1200;

    /// One round trip of a closed-loop bulk transfer over a path with a fixed
    /// bottleneck rate and a fixed loss fraction.
    ///
    /// This is the shape the estimator actually runs in and the shape the tests
    /// above do not have: the window it produces is fed straight back to it as
    /// the next flight's size. An open-loop test can assert what a controller
    /// *says*; only a closed loop can catch it saying something that stops it
    /// from ever learning better.
    ///
    /// One round: the sender puts a full congestion window on the wire at `t0`,
    /// the path clocks it out at no more than `true_bw` bytes per second,
    /// `loss_per_mille` of the segments never arrive, and the survivors are
    /// acknowledged together — receivers batch, and the estimator's own
    /// interval bound (`send_elapsed.max(ack_elapsed)`) is what keeps that
    /// honest.
    ///
    /// The bytes that were lost are *returned* rather than reported here: the
    /// live drain loop reports a loss at the point it retransmits, which is the
    /// top of the next pass, and that one round of lag is exactly what makes the
    /// difference between a response that clamps the window the sender is about
    /// to use and one that does not.
    fn closed_loop_round(
        est: &mut BandwidthEstimator,
        t0: Instant,
        rtt: Duration,
        true_bw: u64,
        loss_per_mille: u64,
        carry_lost: u64,
    ) -> (u64, Duration) {
        // Retransmissions go out first, and `drain_streams_priority_ordered`
        // reports each of them to congestion control as it does.
        if carry_lost > 0 {
            est.on_loss(carry_lost);
        }

        let window = est.cwnd();
        let packets = (window / SIM_PACKET).max(1);
        let sent = packets * SIM_PACKET;
        for _ in 0..packets {
            est.on_send(SIM_PACKET);
        }

        // Round to nearest, so a few-percent loss fraction is not quantised
        // away on a small flight.
        let lost_packets = ((packets * loss_per_mille + 500) / 1000).min(packets);
        let delivered_packets = packets - lost_packets;

        // The bottleneck needs `sent / true_bw` to clock the flight out, and no
        // acknowledgement can come back sooner than one propagation delay. Past
        // that point the window is buying queue, not throughput — which is the
        // physical fact that makes the delivery rate saturate.
        let round = rtt.max(Duration::from_secs_f64(sent as f64 / true_bw as f64));
        let acked_at = t0 + round;

        let mark = est.delivered_bytes();
        let mark_time = est.delivered_time();
        for _ in 0..delivered_packets {
            est.on_ack(DeliverySample {
                delivered_bytes: mark,
                delivered_at: mark_time,
                sent_at: t0,
                acked_at,
                packet_bytes: SIM_PACKET,
                is_app_limited: false,
                ack_delay_us: 0,
                rtt_sampled: true,
            });
        }

        (lost_packets * SIM_PACKET, round)
    }

    /// A sender on a lossy path must still be able to find out that the path is
    /// faster than it currently believes.
    ///
    /// This is the fixed point, and it is worth stating as arithmetic rather
    /// than as a state name. The delivery rate a sender can measure is bounded
    /// by what it has in flight: `rate ≤ inflight / rtt`. Hold inflight at
    /// exactly one bandwidth-delay product — `cwnd = btl_bw × min_rtt`, which is
    /// what a congestion-window gain of 1.0 means — and the best rate any sample
    /// can report is `btl_bw` itself. `btl_bw` is a *maximum* filter, so a
    /// sample that merely equals it changes nothing. The estimate becomes its
    /// own ceiling: the only mechanism by which it could discover more bandwidth
    /// is the very headroom that was just taken away, and no amount of time on
    /// the path recovers it.
    ///
    /// That is not a back-off, it is an absorbing state, and on a path that
    /// loses continuously the sender re-enters it on every retransmitted
    /// segment. The path this came from carries 9.34 Mbit/s at 2.7% loss
    /// measured with raw sockets; the protocol sustained 1.2 Mbit/s on it, with
    /// a window that had room for roughly 13 Mbit/s at the measured 200 ms round
    /// trip. The window was not the limit. The estimate was, and it was pinned
    /// by its own output.
    ///
    /// Here the estimate is walked up a clean path to a fraction of the truth,
    /// and then the path starts losing. It has to keep climbing.
    #[test]
    fn a_lossy_path_can_still_discover_bandwidth_above_its_own_estimate() {
        const RTT: Duration = Duration::from_millis(200);
        // 9.34 Mbit/s and 2.7%: both measured on the path this change came from.
        const TRUE_BW: u64 = 1_167_500;
        const LOSS_PER_MILLE: u64 = 27;
        const WARMUP_ROUNDS: u32 = 4;
        const LOSSY_ROUNDS: u32 = 18;

        let mut est = BandwidthEstimator::new();
        let mut t = Instant::now();

        // A clean start, stopped well short of the path's real rate.
        for _ in 0..WARMUP_ROUNDS {
            let (_, took) = closed_loop_round(&mut est, t, RTT, TRUE_BW, 0, 0);
            t += took;
        }
        let bw_onset = est.bottleneck_bandwidth();
        let cwnd_onset = est.cwnd();
        assert!(
            bw_onset > 0 && bw_onset < TRUE_BW / 4,
            "precondition: the warm-up should leave the estimate ({bw_onset} B/s) \
             well below the path's {TRUE_BW} B/s, with room left to discover"
        );

        // Now the path loses 2.7% of everything, round after round.
        let mut carry = 0;
        for _ in 0..LOSSY_ROUNDS {
            let (lost, took) = closed_loop_round(&mut est, t, RTT, TRUE_BW, LOSS_PER_MILLE, carry);
            carry = lost;
            t += took;
        }

        let bw = est.bottleneck_bandwidth();
        assert!(
            bw >= bw_onset * 3,
            "the estimate went into the lossy stretch at {bw_onset} B/s and came \
             out at {bw} B/s — it is pinned by its own output, not by the path"
        );
        assert!(
            bw >= TRUE_BW * 3 / 4,
            "after {LOSSY_ROUNDS} round trips the estimate is {bw} B/s on a path \
             that carries {TRUE_BW} B/s"
        );
        assert!(
            est.cwnd() >= cwnd_onset * 3,
            "the window went in at {cwnd_onset} B and came out at {} B — an \
             estimate that cannot climb takes the window with it",
            est.cwnd()
        );
    }

    /// The other direction, and the one that stops the fix above from being
    /// "delete the loss response".
    ///
    /// Loss still has to cost the sender something. A path that loses steadily
    /// must end up operating at a materially smaller window than the same path
    /// operating cleanly — and then, when the loss stops, must get that window
    /// back. A one-way ratchet would satisfy the first half and quietly cap
    /// every connection that ever saw a bad minute.
    #[test]
    fn sustained_loss_shrinks_the_window_and_a_clean_path_gives_it_back() {
        const RTT: Duration = Duration::from_millis(100);
        const TRUE_BW: u64 = 1_167_500;
        const LOSS_PER_MILLE: u64 = 27;

        let mut est = BandwidthEstimator::new();
        let mut t = Instant::now();

        // Fill the pipe on a clean path.
        for _ in 0..9 {
            let (_, took) = closed_loop_round(&mut est, t, RTT, TRUE_BW, 0, 0);
            t += took;
        }
        let clean_cwnd = est.cwnd();
        assert!(
            clean_cwnd > 100_000,
            "precondition: the pipe should be open before loss starts ({clean_cwnd} B)"
        );

        // The path starts losing 2.7%.
        let mut carry = 0;
        for _ in 0..8 {
            let (lost, took) = closed_loop_round(&mut est, t, RTT, TRUE_BW, LOSS_PER_MILLE, carry);
            carry = lost;
            t += took;
        }
        let lossy_cwnd = est.cwnd();
        assert!(
            lossy_cwnd * 4 <= clean_cwnd * 3,
            "sustained loss left the window at {lossy_cwnd} B against {clean_cwnd} B \
             on the clean path — the loss response is not costing the sender anything"
        );

        // ...and the loss stops.
        for _ in 0..6 {
            let (_, took) = closed_loop_round(&mut est, t, RTT, TRUE_BW, 0, 0);
            t += took;
        }
        let recovered_cwnd = est.cwnd();
        assert!(
            recovered_cwnd * 10 >= clean_cwnd * 9,
            "the window came back to {recovered_cwnd} B against the {clean_cwnd} B \
             it held before — a loss response that never releases is a ratchet"
        );
    }

    /// One lost segment is not a congestion signal.
    ///
    /// Loss on a real path is a rate, not an event: at 2.7% a sender with a few
    /// hundred segments in flight retransmits several times per round trip, and
    /// a response scaled per segment fires continuously and means nothing. BBRv2
    /// and v3 both judge loss over a round trip and against a threshold
    /// (`BBRLossThresh`, 2%) for exactly that reason.
    ///
    /// Here a healthy flight loses a single segment — a loss rate of a fraction
    /// of a percent. The window the sender gets to use for its next flight must
    /// be unchanged.
    #[test]
    fn a_single_lost_segment_is_not_a_congestion_signal() {
        const RTT: Duration = Duration::from_millis(100);
        const TRUE_BW: u64 = 1_167_500;

        let mut est = BandwidthEstimator::new();
        let mut t = Instant::now();
        for _ in 0..9 {
            let (_, took) = closed_loop_round(&mut est, t, RTT, TRUE_BW, 0, 0);
            t += took;
        }

        let healthy = est.cwnd();
        let in_flight = healthy / SIM_PACKET;
        assert!(
            in_flight > 100,
            "precondition: the flight should be big enough for one segment to be \
             a fraction of a percent of it ({in_flight} segments)"
        );

        // The drain retransmits one segment and reports it.
        est.on_loss(SIM_PACKET);

        assert_eq!(
            est.cwnd(),
            healthy,
            "one lost segment out of {in_flight} took the window from {healthy} B \
             to {} B",
            est.cwnd()
        );
    }

    // ── The bandwidth horizon ───────────────────────────────────────────────
    //
    // Everything below drives the estimator on synthetic `Instant`s, which is
    // what lets a test cover half a minute of estimator time in microseconds of
    // real time. No wall clock is read and none is paused: `on_ack` takes its
    // notion of "now" from `sample.acked_at`, so the schedule the test writes is
    // the schedule the estimator sees. Pausing tokio's clock instead would zero
    // `min_rtt` and make several of these assertions true for reasons that have
    // nothing to do with what they claim to test.

    /// One acknowledgement that delivers exactly `bytes` over exactly `span`.
    ///
    /// The sample's delivery mark is the connection's counter as it stands
    /// *before* this acknowledgement, so the estimator's numerator is `bytes`
    /// and nothing else; both the send stamp and the delivery stamp sit one
    /// `span` in the past, so `max(send_elapsed, ack_elapsed)` — the interval
    /// the estimator divides by — is exactly `span`. The rate a test asks for is
    /// therefore the rate the estimator computes, with no arithmetic left
    /// implicit for a reader to reconstruct.
    fn ack_delivering(
        est: &BandwidthEstimator,
        at: Instant,
        span: Duration,
        bytes: u64,
        app_limited: bool,
    ) -> DeliverySample {
        DeliverySample {
            delivered_bytes: est.delivered_bytes(),
            delivered_at: at - span,
            sent_at: at - span,
            acked_at: at,
            packet_bytes: bytes,
            is_app_limited: app_limited,
            ack_delay_us: 0,
            rtt_sampled: true,
        }
    }

    /// A burst nobody could sustain, used by the horizon tests below as the peak
    /// that has to be released: one megabyte acknowledged inside ten
    /// milliseconds is 100 MB/s, four orders of magnitude above the 10 KB/s the
    /// tails then run at. The separation is chosen by the test rather than tuned
    /// against the code, so no assertion below has to name a threshold.
    const HORIZON_BURST_BYTES: u64 = 1_000_000;
    const HORIZON_BURST_SPAN: Duration = Duration::from_millis(10);
    /// The honest rate the tails run at: 5 KB per half second.
    const HORIZON_TAIL_BYTES: u64 = 5_000;
    const HORIZON_TAIL_SPAN: Duration = Duration::from_millis(500);
    /// Enough tail acknowledgements to carry the run twice past the horizon,
    /// derived from the horizon rather than written down beside it so that
    /// moving [`BW_FILTER_WINDOW`] moves the tests with it instead of quietly
    /// turning them into assertions about a boundary they no longer straddle.
    const HORIZON_TAIL_ACKS: u32 =
        2 * (BW_FILTER_WINDOW.as_millis() / HORIZON_TAIL_SPAN.as_millis()) as u32;
    /// ...and enough to stop a full second short of it, for the test that has to
    /// stay inside.
    const IN_HORIZON_TAIL_ACKS: u32 = HORIZON_TAIL_ACKS / 2 - 2;

    /// Raise the estimate with one unsustainable burst and hand back both the
    /// estimator and the peak it now reports.
    fn estimator_holding_a_burst_peak(start: Instant) -> (BandwidthEstimator, u64) {
        let mut est = BandwidthEstimator::new();
        est.on_send(HORIZON_BURST_BYTES);
        let sample = ack_delivering(
            &est,
            start + HORIZON_BURST_SPAN,
            HORIZON_BURST_SPAN,
            HORIZON_BURST_BYTES,
            false,
        );
        est.on_ack(sample);
        let peak = est.bottleneck_bandwidth();
        assert!(
            peak > 0,
            "precondition: the burst should have set a maximum to release"
        );
        (est, peak)
    }

    /// The horizon does what it says: a peak the path cannot sustain is released
    /// once it is older than the window, and the estimate settles on what the
    /// path is actually delivering.
    ///
    /// This is the positive control for the two tests after it. Both of those
    /// assert that a peak is *held* under conditions where ageing would have
    /// released it, and an assertion of that shape is worthless until it has
    /// been shown that the horizon ages at all when it is fed samples it takes.
    #[test]
    fn a_burst_peak_is_released_once_the_horizon_has_passed() {
        let start = Instant::now();
        let (mut est, peak) = estimator_holding_a_burst_peak(start);

        // Twice the horizon in half-second acknowledgements, each carrying an
        // honest, slow delivery rate.
        for i in 1..=HORIZON_TAIL_ACKS {
            let at = start + HORIZON_TAIL_SPAN * i;
            let sample = ack_delivering(&est, at, HORIZON_TAIL_SPAN, HORIZON_TAIL_BYTES, false);
            est.on_ack(sample);
        }

        let settled = est.bottleneck_bandwidth();
        assert!(
            settled * 1000 < peak,
            "twice the horizon later the estimate is {settled} B/s against a burst \
             peak of {peak} B/s — the peak was never released"
        );
        assert!(
            settled > 0,
            "the estimate collapsed to zero while acknowledgements were still \
             carrying {HORIZON_TAIL_BYTES} B every {HORIZON_TAIL_SPAN:?}"
        );
    }

    /// The same run with the tail labelled application-limited — and here the
    /// peak must be **kept**, for as long as the application stays quiet.
    ///
    /// This is the shape a messenger or a VPN client spends most of its life in:
    /// one burst, then request/response for minutes. Every acknowledgement in
    /// that tail carries a rate, and every one of those rates measures how fast
    /// the *application* wrote — 10 KB/s because that is what the application
    /// had, on a path that just demonstrated four orders of magnitude more.
    /// Letting any of them near the maximum installs the application's write
    /// rate as the path's capacity, which is what the admission gate exists to
    /// refuse.
    ///
    /// Ageing the horizon on every acknowledgement rather than on the admitted
    /// ones defeats that gate without touching its text. The window empties one
    /// horizon into the quiet period, the maximum reads zero, and the escape
    /// clause `delivery_rate >= btl_bw` — there so that a flow whose every write
    /// is smaller than a window can measure *something* — becomes vacuously
    /// true. The tail rate is then the estimate, `bdp` collapses with it, and
    /// the pacer this estimator drives meters the next bulk phase at the floor.
    /// The loop below runs a full horizon past the boundary precisely so that it
    /// is the emptying that gets tested and not the schedule stopping short of
    /// it.
    #[test]
    fn an_app_limited_tail_may_not_install_its_own_rate_as_the_maximum() {
        let start = Instant::now();
        let (mut est, peak) = estimator_holding_a_burst_peak(start);
        let bdp_at_peak = (peak as f64 * est.min_rtt().as_secs_f64()) as u64;

        est.note_app_limited_drain();
        for i in 1..=HORIZON_TAIL_ACKS {
            let at = start + HORIZON_TAIL_SPAN * i;
            let sample = ack_delivering(&est, at, HORIZON_TAIL_SPAN, HORIZON_TAIL_BYTES, true);
            est.on_ack(sample);
        }

        let tail_rate = HORIZON_TAIL_BYTES * 1000 / HORIZON_TAIL_SPAN.as_millis() as u64;
        assert_eq!(
            est.bottleneck_bandwidth(),
            peak,
            "twice the horizon of application-limited acknowledgements at \
             {tail_rate} B/s moved the maximum off {peak} B/s to {} B/s — the \
             application's write rate has become the path's capacity",
            est.bottleneck_bandwidth()
        );
        // ...and the window that figure sizes has to have come with it. Reading
        // the estimate alone would pass on a build that kept `btl_bw` and lost
        // the window some other way, and the window is what meters the sender.
        assert!(
            est.cwnd() >= bdp_at_peak,
            "the maximum survived the quiet period but the window did not: \
             cwnd {} B against one bandwidth-delay product at the retained peak \
             of {bdp_at_peak} B",
            est.cwnd()
        );
    }

    /// The other way an acknowledgement reaches the estimator without a usable
    /// rate: it retires no bytes.
    ///
    /// A zero-length reliable segment is not hypothetical — stream close sends
    /// exactly one, the FIN sentinel that rides the ARQ path — and any
    /// acknowledgement whose delivery mark equals the current counter yields a
    /// numerator of zero. That is the *absence* of a measurement, not a
    /// measurement of nothing, and the two are different in the direction that
    /// matters: treating a silent connection as evidence that the path stopped
    /// carrying anything is how a stream close ends up resizing a congestion
    /// window. The horizon here is fed nothing but such acknowledgements for
    /// twice its length and must come out the far side unchanged.
    #[test]
    fn acknowledgements_carrying_no_delivery_leave_the_estimate_alone() {
        let start = Instant::now();
        let (mut est, peak) = estimator_holding_a_burst_peak(start);

        for i in 1..=HORIZON_TAIL_ACKS {
            let at = start + HORIZON_TAIL_SPAN * i;
            let sample = ack_delivering(&est, at, HORIZON_TAIL_SPAN, 0, false);
            est.on_ack(sample);
        }

        assert_eq!(
            est.bottleneck_bandwidth(),
            peak,
            "twice the horizon of acknowledgements that delivered nothing took \
             the estimate from {peak} B/s to {} B/s, on a connection that \
             measured nothing at all in between",
            est.bottleneck_bandwidth()
        );
    }

    /// The counter-test, and the reason the three above are a fix rather than a
    /// deletion.
    ///
    /// A maximum filter exists to hold a peak *across* the samples that follow
    /// it, because a sender whose estimate tracked its latest sample would
    /// abandon a rate the path can carry the moment one acknowledgement came
    /// back slow — and one acknowledgement always eventually comes back slow.
    /// Inside the horizon the high sample must still govern, whatever arrives
    /// afterwards. Replacing the filter with a direct assignment, with an
    /// exponential average, or with a reset-on-drop rule each satisfies the
    /// ageing tests above and fails this one.
    #[test]
    fn a_high_sample_still_governs_for_the_whole_horizon() {
        let start = Instant::now();
        let (mut est, peak) = estimator_holding_a_burst_peak(start);

        // Slow, honest samples stopping a full second inside the horizon, so
        // nothing here is a question about expiry timing.
        for i in 1..=IN_HORIZON_TAIL_ACKS {
            let at = start + HORIZON_TAIL_SPAN * i;
            let sample = ack_delivering(&est, at, HORIZON_TAIL_SPAN, HORIZON_TAIL_BYTES, false);
            est.on_ack(sample);
        }

        assert_eq!(
            est.bottleneck_bandwidth(),
            peak,
            "a second short of the horizon the estimate has already fallen from \
             {peak} B/s to {} B/s — the peak is not being retained, it is being \
             tracked",
            est.bottleneck_bandwidth()
        );
    }

    /// A strictly falling run of delivery rates dominates nothing, so every
    /// sample in it is appended and none is removed until the horizon reaches
    /// it — and the peer picks the acknowledgement cadence that shapes the run.
    ///
    /// The length of that deque is a local memory commitment sized by a remote
    /// party, which is the shape this transport removes rather than defends. The
    /// assertion is on the retained length rather than on any reported value,
    /// because the value is the subject of the test after this one.
    #[test]
    fn a_strictly_falling_run_cannot_grow_the_bandwidth_filter_without_bound() {
        // Four times the ceiling, so the test fails by a wide margin if the
        // ceiling is absent rather than merely by the last few entries.
        const SAMPLES: u64 = 4 * WINDOW_FILTER_MAX_ENTRIES as u64;

        let mut est = BandwidthEstimator::new();
        let start = Instant::now();
        let span = Duration::from_millis(1);

        // Each acknowledgement lands one millisecond after the last and carries
        // one byte less than the one before it, so no sample ever dominates its
        // predecessor and the whole run stays inside the horizon.
        for i in 1..=SAMPLES {
            let at = start + span * (i as u32);
            let bytes = SAMPLES + 1 - i;
            let sample = ack_delivering(&est, at, span, bytes, false);
            est.on_ack(sample);
        }

        assert!(
            est.bw_filter.window.len() <= WINDOW_FILTER_MAX_ENTRIES,
            "{SAMPLES} strictly falling acknowledgements left {} entries in the \
             bandwidth filter, against a ceiling of {WINDOW_FILTER_MAX_ENTRIES} — \
             the deque is as long as the peer cares to make it",
            est.bw_filter.window.len()
        );
    }

    /// The ceiling must cost accuracy in one direction only.
    ///
    /// A bounded filter that could report a *higher* maximum than the unbounded
    /// one would be worse than no bound: an over-stated bottleneck is what paces
    /// a sender into a queue of its own making. Here the same sequence is fed to
    /// the real filter and to a brute-force reference — the maximum over every
    /// sample still inside the horizon — and the two are compared at every step.
    ///
    /// The last assertion is the positive control. Without it the test would
    /// pass on a filter whose ceiling never engaged, which proves the direction
    /// of a truncation that never happened.
    #[test]
    fn a_bounded_filter_never_reports_a_higher_maximum_than_the_unbounded_one() {
        const HORIZON: Duration = BW_FILTER_WINDOW;
        const STEP: Duration = Duration::from_millis(5);
        // Long enough that the horizon rolls twice over a run that fills the
        // ceiling, which is what puts truncated entries inside the window.
        const SAMPLES: usize = 8 * WINDOW_FILTER_MAX_ENTRIES;

        let base = Instant::now();
        let mut filter = WindowFilter::new(HORIZON);
        let mut history: Vec<(Instant, u64)> = Vec::with_capacity(SAMPLES);
        let mut saw_truncation = false;

        for i in 0..SAMPLES {
            // Strictly falling, so nothing is ever dominated and the deque grows
            // by one per sample until something stops it.
            let value = (SAMPLES - i) as u64;
            let at = base + STEP * (i as u32);
            history.push((at, value));

            let reported = filter.update_max(at, value);
            let reference = history
                .iter()
                .filter(|(ts, _)| at.duration_since(*ts) <= HORIZON)
                .map(|&(_, v)| v)
                .max()
                .unwrap_or(0);

            assert!(
                filter.window.len() <= WINDOW_FILTER_MAX_ENTRIES,
                "sample {i}: the filter holds {} entries, past the \
                 {WINDOW_FILTER_MAX_ENTRIES} ceiling",
                filter.window.len()
            );
            assert!(
                reported <= reference,
                "sample {i}: the bounded filter reports {reported} where the \
                 unbounded one reports {reference} — the ceiling is inventing \
                 bandwidth, not conceding it"
            );
            saw_truncation |= reported < reference;
        }

        assert!(
            saw_truncation,
            "the ceiling never actually discarded anything over {SAMPLES} samples, \
             so this run proves nothing about the direction it errs in"
        );
    }

    /// Which end the ceiling evicts from, asserted so that reversing it fails.
    ///
    /// The test above compares a bounded filter against an unbounded one and
    /// requires the bounded reading to be no higher. That is a one-sided bound
    /// and it cannot tell "concedes a little" from "throws the answer away":
    /// front-eviction — discarding the largest retained entry, the maximum
    /// itself — satisfies it trivially at every step, and the whole lib suite
    /// stays green under the one-word change. So the direction needs an
    /// assertion of its own, and it needs a shape in which the two evictions
    /// disagree by orders of magnitude rather than by an entry.
    ///
    /// That shape is one peak followed by a long strictly falling run, all
    /// inside the horizon: nothing is ever dominated, so the deque fills, and
    /// from the ceiling onward every further sample forces an eviction. Evicting
    /// the back discards the smallest retained candidate and the peak — at the
    /// front, the oldest and the largest — governs for its whole horizon, which
    /// is what a maximum filter is for. Evicting the front discards the peak on
    /// the very first sample past the ceiling and hands the reading to a run of
    /// values the path is no longer offering.
    #[test]
    fn the_ceiling_evicts_the_least_of_a_maximum_filter_not_the_greatest() {
        const PEAK: u64 = 100_000_000;
        // Four times the ceiling, so eviction is forced for three quarters of
        // the run rather than for its last few entries.
        const FALLING: usize = 4 * WINDOW_FILTER_MAX_ENTRIES;
        const STEP: Duration = Duration::from_millis(1);

        let base = Instant::now();
        let mut filter = WindowFilter::new(BW_FILTER_WINDOW);
        assert_eq!(filter.update_max(base, PEAK), PEAK);

        // Strictly falling and an order of magnitude below the peak, so the run
        // dominates nothing and any reading taken from it is unmistakable.
        for i in 1..=FALLING {
            let at = base + STEP * (i as u32);
            assert!(
                at.duration_since(base) <= BW_FILTER_WINDOW,
                "the run left the horizon at sample {i}, so what follows would be \
                 an expiry test rather than an eviction one"
            );
            filter.update_max(at, (FALLING - i + 1) as u64);
        }

        assert!(
            filter.window.len() <= WINDOW_FILTER_MAX_ENTRIES,
            "precondition: the ceiling has to have engaged for this to be about \
             eviction at all, and the filter holds {} entries",
            filter.window.len()
        );
        assert_eq!(
            filter.head(),
            Some(PEAK),
            "{FALLING} falling samples inside the horizon took the maximum off \
             {PEAK} — the ceiling is evicting the front of the deque, which in a \
             maximum filter is the maximum itself"
        );
    }

    /// The minimum filter's length bound must not be able to raise the round
    /// trip the congestion window is sized from.
    ///
    /// `cwnd = cwnd_gain × btl_bw × min_rtt` takes this reading as a
    /// multiplicand, so an over-stated minimum inflates the window — and a
    /// sender that inflates its window builds a queue, whose round trips are the
    /// next samples this filter sees. That is a loop the maximum filter's
    /// truncation cannot enter and this one can, which is why the two are
    /// bounded by different rules.
    ///
    /// The shape is the one that produces it: a strictly rising run of round
    /// trips, which is what a filling bottleneck queue looks like from the
    /// sender, carried far enough that the horizon rolls and the run's own
    /// prefix ages out. Under back-eviction the deque degenerates to "the oldest
    /// entries plus the newest", and once the prefix expires the sole survivor is
    /// the newest — the *largest* round trip in the window, reported as its
    /// minimum.
    ///
    /// The reference is what a filter with no length bound at all would report,
    /// over a horizon one separation shorter: declining an incoming sample can
    /// cost the reading at most the gap between that sample and the smaller
    /// entry that stood in for it, which is under one separation by the test
    /// that declined it. Anything above that reference is truncation inventing a
    /// round trip.
    #[test]
    fn a_rising_round_trip_run_cannot_inflate_the_minimum_it_is_read_from() {
        const HORIZON: Duration = RTT_FILTER_WINDOW;
        // Faster than the separation, so most samples are declined and the rule
        // under test is engaged continuously rather than incidentally.
        const STEP: Duration = Duration::from_millis(5);
        // The run has to outlive the prefix a count-truncating filter would
        // strand, or it measures the prefix instead of the rule. Such a filter
        // fills after [`WINDOW_FILTER_MAX_ENTRIES`] samples and holds "that
        // prefix plus the newest" from then on; the prefix expires one horizon
        // after it is complete, and only past *that* instant is the newest
        // sample all that is left to report. Everything before it agrees with an
        // unbounded filter, which is exactly how a run that stops short passes
        // while reporting the largest round trip in the window.
        const SAMPLES: usize = WINDOW_FILTER_MAX_ENTRIES
            + (HORIZON.as_millis() / STEP.as_millis()) as usize
            + WINDOW_FILTER_MAX_ENTRIES / 2;

        let base = Instant::now();
        let mut filter = WindowFilter::new(HORIZON);
        let separation = filter.min_separation;
        assert!(
            STEP < separation,
            "precondition: samples arriving slower than the separation are never \
             declined, and this run would prove nothing"
        );
        // One step of slack absorbs the nanosecond rounding in the separation.
        let reference_horizon = HORIZON - separation - STEP;

        let mut history: VecDeque<(Instant, u64)> = VecDeque::new();
        let mut worst_overshoot = 0u64;
        let mut declined = 0usize;
        let mut longest = 0usize;

        for i in 0..SAMPLES {
            // Strictly rising, so nothing is ever dominated: every sample either
            // lengthens the deque or is declined by the separation rule.
            let value = (i + 1) as u64;
            let at = base + STEP * (i as u32);
            history.push_back((at, value));
            while history
                .front()
                .is_some_and(|(ts, _)| at.duration_since(*ts) > reference_horizon)
            {
                history.pop_front();
            }

            let reported = filter.update_min(at, value);
            // Whether this sample was taken, read off the deque directly: a
            // length comparison would confuse a decline with an expiry that
            // happened in the same call.
            if filter.window.back().is_none_or(|&(ts, _)| ts != at) {
                declined += 1;
            }

            let reference = history.iter().map(|&(_, v)| v).min().unwrap_or(value);
            worst_overshoot = worst_overshoot.max(reported.saturating_sub(reference));
            assert!(
                reported <= reference,
                "sample {i}: the bounded minimum filter reports {reported} where an \
                 unbounded one over a horizon one separation shorter reports \
                 {reference} — the length bound is inventing a round trip, and \
                 `cwnd` multiplies by it"
            );
            assert!(
                filter.window.len() <= WINDOW_FILTER_MAX_ENTRIES,
                "sample {i}: the minimum filter holds {} entries, past the \
                 {WINDOW_FILTER_MAX_ENTRIES} the separation is derived to bound it \
                 to",
                filter.window.len()
            );
            longest = longest.max(filter.window.len());
        }

        // Positive controls. Without the first two the run never engaged the
        // rule, and the assertions above would be about a deque that had room
        // to spare; without the third the horizon never rolled, so the old
        // prefix that back-eviction strands was never put to the test.
        assert!(
            declined >= SAMPLES / 2,
            "only {declined} of {SAMPLES} samples were declined, so the length \
             bound was barely exercised"
        );
        assert!(
            longest * 10 > WINDOW_FILTER_MAX_ENTRIES * 9,
            "the filter never grew past {longest} entries against a bound of \
             {WINDOW_FILTER_MAX_ENTRIES}, so this run says nothing about what \
             happens at it"
        );
        assert!(
            STEP * (SAMPLES as u32) > HORIZON,
            "the run finished inside one horizon, so nothing ever expired"
        );
        assert_eq!(
            worst_overshoot, 0,
            "the reading rose above the unbounded reference by {worst_overshoot} \
             at its worst"
        );
    }

    /// The retained maximum and the raw sample must be separately readable, and
    /// the raw one must be published even when the filter declines it.
    ///
    /// This is the whole point of the observable. A recorded series carrying
    /// only the filtered figure cannot distinguish "the filter is holding a peak
    /// the path has stopped offering" from "the samples themselves are reading
    /// high", and those two want opposite fixes. The moment the two readings
    /// diverge is exactly the moment a sample was refused admission, so a field
    /// that only updated on admitted samples would answer the question by
    /// definition and never by measurement.
    #[test]
    fn the_raw_delivery_rate_is_published_even_when_the_filter_declines_it() {
        let start = Instant::now();
        let (mut est, peak) = estimator_holding_a_burst_peak(start);
        assert_eq!(
            est.last_delivery_rate(),
            peak,
            "the burst's own sample set the maximum, so the two readings should \
             agree before anything has been refused"
        );

        // One app-limited sample, well inside the horizon and far below the
        // maximum: refused admission, and correctly so.
        est.note_app_limited_drain();
        let at = start + HORIZON_TAIL_SPAN;
        let sample = ack_delivering(&est, at, HORIZON_TAIL_SPAN, HORIZON_TAIL_BYTES, true);
        est.on_ack(sample);

        assert_eq!(
            est.bottleneck_bandwidth(),
            peak,
            "the app-limited sample was allowed to lower the maximum"
        );
        assert_eq!(
            est.last_delivery_rate(),
            HORIZON_TAIL_BYTES * 1000 / HORIZON_TAIL_SPAN.as_millis() as u64,
            "the refused sample never reached the published reading, so a \
             recorded series cannot tell a retained peak from a high sample"
        );

        // An acknowledgement that retires nothing is not a rate of zero, it is
        // the absence of a rate — publishing it as zero would put a reading in
        // the series that no measurement supports.
        let quiet = ack_delivering(
            &est,
            start + HORIZON_TAIL_SPAN * 2,
            HORIZON_TAIL_SPAN,
            0,
            false,
        );
        est.on_ack(quiet);
        assert_eq!(
            est.last_delivery_rate(),
            HORIZON_TAIL_BYTES * 1000 / HORIZON_TAIL_SPAN.as_millis() as u64,
            "an acknowledgement that delivered nothing overwrote the last real \
             delivery-rate sample with a zero"
        );
    }
}
