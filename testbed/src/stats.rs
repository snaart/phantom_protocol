//! Sample accumulation and derived statistics.
//!
//! Raw samples are the primary data — this module never discards them. Every
//! summary here is a *derived* artifact computed at report time, so a later
//! analysis can recompute anything from the JSONL and is never limited to the
//! questions this harness happened to anticipate.

use serde::{Deserialize, Serialize};

/// A distribution summary over a set of samples.
///
/// All latency fields are nanoseconds, matching the raw sample records, so no
/// unit conversion happens between collection and analysis.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Summary {
    pub count: usize,
    pub min: f64,
    pub max: f64,
    pub mean: f64,
    pub stddev: f64,
    pub p50: f64,
    pub p90: f64,
    pub p95: f64,
    pub p99: f64,
    pub p999: f64,
}

impl Summary {
    /// Summarize a slice of samples. Non-finite values (a NaN from a bad
    /// division) are dropped rather than silently poisoning the sort, and the
    /// drop is visible because `count` reflects only what survived.
    pub fn of(samples: &[f64]) -> Self {
        let mut v: Vec<f64> = samples.iter().copied().filter(|x| x.is_finite()).collect();
        if v.is_empty() {
            return Self::default();
        }
        v.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

        let n = v.len();
        let sum: f64 = v.iter().sum();
        let mean = sum / n as f64;
        let var = if n > 1 {
            v.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / (n - 1) as f64
        } else {
            0.0
        };

        Self {
            count: n,
            min: v[0],
            max: v[n - 1],
            mean,
            stddev: var.sqrt(),
            p50: percentile_sorted(&v, 0.50),
            p90: percentile_sorted(&v, 0.90),
            p95: percentile_sorted(&v, 0.95),
            p99: percentile_sorted(&v, 0.99),
            p999: percentile_sorted(&v, 0.999),
        }
    }

    pub fn of_u64(samples: &[u64]) -> Self {
        let v: Vec<f64> = samples.iter().map(|&x| x as f64).collect();
        Self::of(&v)
    }
}

/// Nearest-rank percentile over an already-sorted, non-empty slice.
///
/// Nearest-rank (rather than an interpolating definition) is chosen so every
/// reported percentile is an *observed* value. On a link with ~100 ms of
/// jitter, an interpolated p99 can name a latency that never occurred, which is
/// exactly the wrong property when the number is being used to hunt for stalls.
fn percentile_sorted(sorted: &[f64], q: f64) -> f64 {
    debug_assert!(!sorted.is_empty());
    if sorted.is_empty() {
        return 0.0;
    }
    let rank = (q * sorted.len() as f64).ceil() as usize;
    let idx = rank.saturating_sub(1).min(sorted.len() - 1);
    sorted[idx]
}

/// Throughput over a measured interval.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Throughput {
    pub bytes: u64,
    pub frames: u64,
    pub duration_ns: u64,
    pub megabits_per_sec: f64,
    pub frames_per_sec: f64,
}

impl Throughput {
    pub fn new(bytes: u64, frames: u64, duration_ns: u64) -> Self {
        let secs = duration_ns as f64 / 1e9;
        let (mbps, fps) = if secs > 0.0 {
            ((bytes as f64 * 8.0) / secs / 1e6, frames as f64 / secs)
        } else {
            (0.0, 0.0)
        };
        Self {
            bytes,
            frames,
            duration_ns,
            megabits_per_sec: mbps,
            frames_per_sec: fps,
        }
    }
}

/// Running accumulator used while a scenario is in flight.
#[derive(Debug, Default)]
pub struct Accumulator {
    samples: Vec<f64>,
}

impl Accumulator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, v: f64) {
        self.samples.push(v);
    }

    pub fn len(&self) -> usize {
        self.samples.len()
    }

    pub fn is_empty(&self) -> bool {
        self.samples.is_empty()
    }

    pub fn samples(&self) -> &[f64] {
        &self.samples
    }

    pub fn summary(&self) -> Summary {
        Summary::of(&self.samples)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_of_empty_is_zeroed_not_a_panic() {
        let s = Summary::of(&[]);
        assert_eq!(s.count, 0);
        assert_eq!(s.p50, 0.0);
        assert_eq!(s.max, 0.0);
    }

    #[test]
    fn summary_of_single_sample() {
        let s = Summary::of(&[42.0]);
        assert_eq!(s.count, 1);
        assert_eq!(s.min, 42.0);
        assert_eq!(s.max, 42.0);
        assert_eq!(s.mean, 42.0);
        assert_eq!(s.p50, 42.0);
        assert_eq!(s.p999, 42.0);
        assert_eq!(s.stddev, 0.0, "a single sample has no dispersion");
    }

    #[test]
    fn percentiles_are_observed_values_on_a_known_distribution() {
        let v: Vec<f64> = (1..=100).map(|x| x as f64).collect();
        let s = Summary::of(&v);
        assert_eq!(s.count, 100);
        assert_eq!(s.min, 1.0);
        assert_eq!(s.max, 100.0);
        assert_eq!(s.p50, 50.0);
        assert_eq!(s.p90, 90.0);
        assert_eq!(s.p95, 95.0);
        assert_eq!(s.p99, 99.0);
        assert_eq!(s.p999, 100.0);
        // Every reported percentile must be a value that actually occurred.
        for q in [s.p50, s.p90, s.p95, s.p99, s.p999] {
            assert!(v.contains(&q), "{q} is not an observed sample");
        }
    }

    #[test]
    fn summary_is_order_independent() {
        let a = Summary::of(&[5.0, 1.0, 3.0, 2.0, 4.0]);
        let b = Summary::of(&[1.0, 2.0, 3.0, 4.0, 5.0]);
        assert_eq!(a, b);
    }

    #[test]
    fn non_finite_samples_are_dropped_not_propagated() {
        let s = Summary::of(&[1.0, f64::NAN, 2.0, f64::INFINITY, 3.0]);
        assert_eq!(s.count, 3, "only the finite samples are counted");
        assert_eq!(s.min, 1.0);
        assert_eq!(s.max, 3.0);
        assert!(s.mean.is_finite());
    }

    #[test]
    fn stddev_matches_the_sample_definition() {
        // Population {2,4,4,4,5,5,7,9}: sample stddev (n-1) is exactly 2.13809...
        let s = Summary::of(&[2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0]);
        assert_eq!(s.mean, 5.0);
        assert!(
            (s.stddev - 2.138_089_935_299_395).abs() < 1e-12,
            "got {}",
            s.stddev
        );
    }

    #[test]
    fn throughput_math() {
        // 1 MB in 1 s = 8 Mbit/s.
        let t = Throughput::new(1_000_000, 1000, 1_000_000_000);
        assert!((t.megabits_per_sec - 8.0).abs() < 1e-9);
        assert!((t.frames_per_sec - 1000.0).abs() < 1e-9);
    }

    #[test]
    fn throughput_with_zero_duration_does_not_divide_by_zero() {
        let t = Throughput::new(1000, 10, 0);
        assert_eq!(t.megabits_per_sec, 0.0);
        assert_eq!(t.frames_per_sec, 0.0);
    }

    #[test]
    fn accumulator_round_trips_into_a_summary() {
        let mut a = Accumulator::new();
        assert!(a.is_empty());
        for i in 1..=10 {
            a.push(i as f64);
        }
        assert_eq!(a.len(), 10);
        assert_eq!(a.summary().p50, 5.0);
        assert_eq!(a.samples().len(), 10, "raw samples are never discarded");
    }
}
