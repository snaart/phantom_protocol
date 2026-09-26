//! Clock-offset estimation between the probe and the daemon.
//!
//! The two hosts keep independent clocks, so a raw one-way delay (`server_recv
//! - client_send`) is the true delay plus an unknown offset. This module runs
//! the NTP four-timestamp algorithm over the `ECHO`/`ECHO_REPLY` exchange to
//!   estimate that offset, and — just as importantly — how much to trust it.
//!
//! RTT remains the primary latency metric throughout the harness: it is derived
//! from a single clock and needs none of this. The offset exists so one-way
//! asymmetry can be *examined*, with its own error bar attached.

use crate::report::ClockEstimate;

/// One four-timestamp exchange.
#[derive(Debug, Clone, Copy)]
pub struct ClockSample {
    /// Client send (client clock).
    pub t1: u64,
    /// Server receive (server clock).
    pub t2: u64,
    /// Server send (server clock).
    pub t3: u64,
    /// Client receive (client clock).
    pub t4: u64,
}

impl ClockSample {
    /// Round-trip delay, excluding the server's turnaround. Single-clock on
    /// each side, so this is exact regardless of offset.
    pub fn delay_ns(&self) -> i64 {
        (self.t4 as i64 - self.t1 as i64) - (self.t3 as i64 - self.t2 as i64)
    }

    /// Estimated client→server clock offset for this exchange.
    pub fn offset_ns(&self) -> i64 {
        ((self.t2 as i64 - self.t1 as i64) + (self.t3 as i64 - self.t4 as i64)) / 2
    }
}

/// Reduce a set of exchanges to a single offset estimate.
///
/// The estimate is taken from the **minimum-delay** sample, the standard NTP
/// choice: the shortest round trip is the one least contaminated by queueing,
/// and queueing is exactly what makes the two path directions asymmetric.
///
/// `dispersion_ns` is the full spread of per-sample offsets. On this reference
/// path — ~100 ms of jitter — dispersion is expected to be large, and that is
/// the point: it tells a reader that one-way splits derived from this offset
/// carry an error bar of that magnitude, and should not be read as precise.
pub fn estimate(samples: &[ClockSample]) -> Option<ClockEstimate> {
    if samples.is_empty() {
        return None;
    }

    let best = samples
        .iter()
        .min_by_key(|s| s.delay_ns().max(0))
        .copied()?;

    let offsets: Vec<i64> = samples.iter().map(|s| s.offset_ns()).collect();
    let (lo, hi) = offsets
        .iter()
        .fold((i64::MAX, i64::MIN), |(lo, hi), &o| (lo.min(o), hi.max(o)));
    let dispersion = hi.saturating_sub(lo).unsigned_abs();

    let min_rtt = samples
        .iter()
        .map(|s| s.delay_ns().max(0) as u64)
        .min()
        .unwrap_or(0);

    Some(ClockEstimate {
        samples: samples.len(),
        offset_ns: best.offset_ns(),
        dispersion_ns: dispersion,
        min_rtt_ns: min_rtt,
        method: "ntp-4ts-min-delay".to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A symmetric path with a known offset must be recovered exactly.
    #[test]
    fn recovers_a_known_offset_on_a_symmetric_path() {
        // True one-way delay 100 ms each way, server clock +5 s ahead.
        let offset = 5_000_000_000i64;
        let owd = 100_000_000i64;
        let t1 = 1_000_000_000_000u64;
        let t2 = (t1 as i64 + owd + offset) as u64;
        let t3 = t2 + 1_000_000; // 1 ms turnaround
        let t4 = (t3 as i64 - offset + owd) as u64;

        let s = ClockSample { t1, t2, t3, t4 };
        assert_eq!(s.offset_ns(), offset);
        assert_eq!(s.delay_ns(), 2 * owd);

        let est = estimate(&[s]).expect("one sample is enough");
        assert_eq!(est.offset_ns, offset);
        assert_eq!(est.min_rtt_ns, 2 * owd as u64);
        assert_eq!(est.dispersion_ns, 0, "a single sample has no spread");
    }

    /// The minimum-delay sample must win — a queued outlier must not drag the
    /// estimate, which is the whole reason for choosing min-delay over a mean.
    #[test]
    fn picks_the_minimum_delay_sample() {
        let mk = |owd: i64, offset: i64| {
            let t1 = 1_000_000_000_000u64;
            let t2 = (t1 as i64 + owd + offset) as u64;
            let t3 = t2 + 1_000;
            let t4 = (t3 as i64 - offset + owd) as u64;
            ClockSample { t1, t2, t3, t4 }
        };
        let clean = mk(50_000_000, 7_000_000_000);
        let queued = mk(400_000_000, 7_000_000_000);

        let est = estimate(&[queued, clean, queued]).expect("estimate");
        assert_eq!(est.offset_ns, clean.offset_ns());
        assert_eq!(est.min_rtt_ns, 100_000_000);
        assert_eq!(est.samples, 3, "all samples are still counted");
    }

    /// Asymmetric queueing biases the per-sample offset; dispersion must expose
    /// that rather than hide it behind a confident-looking single number.
    #[test]
    fn dispersion_reports_the_spread() {
        let base = ClockSample {
            t1: 1_000,
            t2: 2_000,
            t3: 2_100,
            t4: 3_000,
        };
        // Second sample with a delayed reply path -> different offset estimate.
        let skewed = ClockSample {
            t1: 1_000,
            t2: 2_000,
            t3: 2_100,
            t4: 4_000,
        };
        let est = estimate(&[base, skewed]).expect("estimate");
        let spread = (base.offset_ns() - skewed.offset_ns()).unsigned_abs();
        assert_eq!(est.dispersion_ns, spread);
        assert!(est.dispersion_ns > 0);
    }

    #[test]
    fn empty_input_yields_no_estimate() {
        assert!(estimate(&[]).is_none());
    }

    /// Clock stepping backwards mid-exchange yields a negative delay; it must
    /// clamp rather than wrap into an enormous u64.
    #[test]
    fn negative_delay_is_clamped_not_wrapped() {
        let s = ClockSample {
            t1: 5_000,
            t2: 1_000,
            t3: 9_000,
            t4: 6_000,
        };
        assert!(s.delay_ns() < 0);
        let est = estimate(&[s]).expect("estimate");
        assert_eq!(est.min_rtt_ns, 0, "clamped, not wrapped to ~2^64");
    }
}
