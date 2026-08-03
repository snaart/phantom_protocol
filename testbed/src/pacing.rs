//! Rate pacing for the raw capacity controls.
//!
//! Both raw UDP controls — client → server and server → client — walk a ladder
//! of offered rates and ask what arrived at the other end. They have to pace
//! identically or the two directions are not comparable, so there is exactly one
//! pacer in this crate and both sides drive it.
//!
//! The shape of it is load-bearing, and both ends of the ladder have already
//! produced a wrong answer here.
//!
//! At the top: an early client loop slept between datagrams, which cannot
//! outrun `tokio::time::sleep`'s ~1 ms granularity. At 1200 B per datagram that
//! caps the offer near 9.6 Mbit/s, so the "path ceiling" such a loop reports is
//! really its own clock — it reported 6.5 Mbit/s on a link that carries far
//! more. Sending in per-tick batches is what fixed it.
//!
//! At the bottom: the batching version computed `bytes_per_millisecond /
//! datagram_size`, which truncates to zero below one datagram per tick, and
//! clamped that up to one. An offer of 1 Mbit/s therefore went out at 9.6, and
//! the low half of the ladder measured a rate nobody had asked for. A credit
//! bucket fixes both ends at once: it batches when the rate needs more than one
//! datagram per tick and spreads across ticks when it needs less.

use std::time::Duration;

/// Pacing granularity.
///
/// One millisecond is the floor a tokio timer can hold on a general-purpose
/// kernel; asking for less does not go faster, it only makes the loop spin.
/// Everything above that rate is served by sending more per tick, which is the
/// property that keeps the timer out of the measurement.
pub const TICK: Duration = Duration::from_millis(1);

/// How a driver's tick timer must behave when the send loop overruns.
///
/// Deliberately `Delay` rather than `Burst`. A sender that fell behind — a
/// scheduler gap, a full socket buffer — must resume at the offered rate, not
/// repay the backlog at line speed: the catch-up burst would queue the path at a
/// rate nobody offered, and the loss it provoked would be read as the link's.
/// Falling behind instead shows up as an achieved rate under the offer, which
/// every rung already records and the analysis already knows how to discount.
pub const MISSED_TICK: tokio::time::MissedTickBehavior = tokio::time::MissedTickBehavior::Delay;

/// How much of its own offer a sender must actually put on the wire before the
/// rung says anything about the path.
///
/// A rung the sender never reached measures the *sender* — its scheduler, its
/// socket buffer, its CPU — and reading a loss figure from it as though it were
/// the link's is precisely the mistake these controls exist to prevent. Both
/// directions use the same threshold so a shortfall means the same thing
/// whichever way the bytes were going.
pub const SENDER_REACHED_OFFER_RATIO: f64 = 0.9;

/// The default rate ladder, kbit/s.
///
/// Wide enough to bracket anything a consumer path is likely to do, and shared
/// by both directions so uplink and downlink rungs line up one for one.
pub const DEFAULT_RUNGS_KBPS: &[u64] = &[1_000, 5_000, 20_000, 60_000, 200_000];

/// Credit is carried in thousandths of a byte so the whole ladder stays exact
/// in integer arithmetic: at 1 kbit/s a tick earns 125 milli-bytes, and nothing
/// in the range rounds away.
const MILLI: u64 = 1000;

/// Paces a fixed-size datagram stream at an offered bit rate.
///
/// Drive it from a [`TICK`]-period timer and send exactly what
/// [`Pacer::on_tick`] returns. The pacer knows nothing about sockets, which is
/// what makes it testable without one — and what lets the two directions share
/// it.
#[derive(Debug, Clone)]
pub struct Pacer {
    offered_kbps: u64,
    payload_len: usize,
    /// Datagram cost, milli-bytes.
    threshold: u64,
    /// Credit earned per tick, milli-bytes.
    per_tick: u64,
    /// Unspent credit, milli-bytes. Always below `threshold` between calls, so
    /// the fractional part of a rate is carried rather than discarded.
    credit: u64,
}

impl Pacer {
    /// A pacer offering `offered_kbps` kbit/s in `payload_len`-byte datagrams.
    ///
    /// Both arguments are clamped to at least one: a zero rate or a zero-length
    /// datagram is a caller bug, and the useful failure is a pacer that still
    /// makes progress rather than one that divides by zero inside a send loop.
    pub fn new(offered_kbps: u64, payload_len: usize) -> Self {
        let offered_kbps = offered_kbps.max(1);
        let payload_len = payload_len.max(1);
        // kbit/s → bytes/s is × 125, and a tick is a thousandth of a second, so
        // milli-bytes per tick is × 125 again with the two thousands cancelling.
        let per_tick = offered_kbps.saturating_mul(125);
        Self {
            offered_kbps,
            payload_len,
            threshold: (payload_len as u64).saturating_mul(MILLI),
            per_tick,
            credit: 0,
        }
    }

    /// How many datagrams to send for the tick that just fired.
    pub fn on_tick(&mut self) -> u32 {
        self.credit = self.credit.saturating_add(self.per_tick);
        let n = self.credit / self.threshold;
        self.credit -= n * self.threshold;
        // One tick's credit divided by one datagram is far inside u32 for every
        // rate these controls accept; the clamp is here so it stays true if the
        // ceiling is ever raised.
        n.min(u32::MAX as u64) as u32
    }

    pub fn offered_kbps(&self) -> u64 {
        self.offered_kbps
    }

    /// The offer in bits per second — the denominator every "did the sender
    /// reach it" judgement is made against.
    pub fn offered_bps(&self) -> f64 {
        self.offered_kbps as f64 * 1000.0
    }

    pub fn payload_len(&self) -> usize {
        self.payload_len
    }
}

/// Bits per second from a byte count and an elapsed interval.
///
/// Zero for a zero-length interval rather than an infinity: a rung that
/// recorded no time is missing data, and an infinite rate in the artifact would
/// be read as a measurement.
pub fn bits_per_sec(bytes: u64, elapsed_ns: u64) -> f64 {
    if elapsed_ns == 0 {
        return 0.0;
    }
    bytes as f64 * 8.0 / (elapsed_ns as f64 / 1e9)
}

/// Whether a sender actually delivered the rate it offered.
///
/// The single place this judgement is made, so the uplink and downlink controls
/// cannot drift into disagreeing about what a reached rung is.
pub fn reached_offer(offered_bps: f64, achieved_bps: f64) -> bool {
    offered_bps > 0.0 && achieved_bps >= offered_bps * SENDER_REACHED_OFFER_RATIO
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Run a pacer for `ticks` ticks and report the bit rate it produced.
    fn simulate(kbps: u64, payload: usize, ticks: u64) -> f64 {
        let mut p = Pacer::new(kbps, payload);
        let mut datagrams = 0u64;
        for _ in 0..ticks {
            datagrams += p.on_tick() as u64;
        }
        let elapsed_ns = ticks * TICK.as_nanos() as u64;
        bits_per_sec(datagrams * payload as u64, elapsed_ns)
    }

    /// The property the whole ladder rests on: what goes on the wire is what
    /// was asked for, at every rung and on both sides of one datagram per tick.
    #[test]
    fn the_pacer_hits_its_offer_across_the_whole_ladder() {
        for &kbps in DEFAULT_RUNGS_KBPS {
            for payload in [64usize, 512, 1200, 1400] {
                let got = simulate(kbps, payload, 5_000);
                let want = kbps as f64 * 1000.0;
                let err = (got - want).abs() / want;
                assert!(
                    err < 0.01,
                    "{kbps} kbit/s at {payload} B: offered {want:.0} bit/s, paced {got:.0} bit/s ({:.2}% off)",
                    err * 100.0
                );
            }
        }
    }

    /// The low rungs are where the previous arithmetic failed: one datagram per
    /// tick was the floor, so 1 Mbit/s went out at nearly ten times the ask.
    #[test]
    fn a_rate_below_one_datagram_per_tick_is_not_rounded_up_to_one() {
        let mut p = Pacer::new(1_000, 1200);
        let mut datagrams = 0u64;
        let mut idle_ticks = 0u64;
        for _ in 0..1_000 {
            let n = p.on_tick();
            if n == 0 {
                idle_ticks += 1;
            }
            datagrams += n as u64;
        }
        assert!(
            idle_ticks > 800,
            "1 Mbit/s at 1200 B needs ~104 datagrams a second, so most ticks send nothing; \
             {idle_ticks} of 1000 were idle"
        );
        // 125_000 B/s ÷ 1200 B ≈ 104 datagrams in a second. The old clamp put
        // 1000 here.
        assert!(
            (103..=105).contains(&datagrams),
            "expected ~104 datagrams in one second, got {datagrams}"
        );
    }

    /// The high rungs are where the sleep-per-datagram version failed: it could
    /// not exceed one datagram per timer tick whatever the offer.
    #[test]
    fn a_rate_above_one_datagram_per_tick_batches_within_the_tick() {
        let mut p = Pacer::new(200_000, 1200);
        // 25_000_000 milli-bytes of credit a tick against a 1_200_000 threshold.
        let n = p.on_tick();
        assert!(
            n >= 20,
            "200 Mbit/s at 1200 B is ~20.8 datagrams per millisecond, got {n}"
        );
        // And the fractional part is carried rather than discarded: over many
        // ticks the average lands on 20.83, not on 20.
        let mut total = n as u64;
        for _ in 0..999 {
            total += p.on_tick() as u64;
        }
        assert!(
            (20_800..=20_850).contains(&total),
            "1000 ticks should carry ~20833 datagrams, got {total}"
        );
    }

    /// A rung's whole point is that the offer is a *rate*, not a burst. However
    /// many ticks the driver delivers, one tick may only ever release its own
    /// tick's worth.
    #[test]
    fn one_tick_releases_only_one_tick_of_credit() {
        for &kbps in DEFAULT_RUNGS_KBPS {
            let mut p = Pacer::new(kbps, 1200);
            let ceiling = (kbps * 125).div_ceil(1200 * MILLI) as u32;
            for _ in 0..10_000 {
                assert!(
                    p.on_tick() <= ceiling,
                    "{kbps} kbit/s released more than one tick's worth ({ceiling} datagrams)"
                );
            }
        }
    }

    #[test]
    fn degenerate_inputs_do_not_divide_by_zero() {
        let mut p = Pacer::new(0, 0);
        assert_eq!(p.payload_len(), 1);
        assert_eq!(p.offered_kbps(), 1);
        // 1 kbit/s is 125 B/s: 125 one-byte datagrams a second.
        let mut sent = 0u64;
        for _ in 0..1000 {
            sent += p.on_tick() as u64;
        }
        assert_eq!(sent, 125, "1 kbit/s in 1-byte datagrams is 125 a second");
    }

    #[test]
    fn bits_per_sec_is_zero_for_a_zero_interval() {
        assert_eq!(bits_per_sec(1_000_000, 0), 0.0);
        assert!((bits_per_sec(1_000_000, 1_000_000_000) - 8e6).abs() < 1e-6);
    }

    /// The flag that decides whether a rung is evidence about the path.
    #[test]
    fn reaching_the_offer_is_judged_against_one_shared_threshold() {
        let offer = 60e6;
        assert!(reached_offer(offer, 60e6));
        assert!(reached_offer(offer, offer * SENDER_REACHED_OFFER_RATIO));
        assert!(!reached_offer(offer, offer * 0.89));
        assert!(!reached_offer(offer, 0.0));
        // A rung with no offer cannot have been reached — this is what keeps a
        // missing sender report from reading as a satisfied one.
        assert!(!reached_offer(0.0, 0.0));
    }
}
