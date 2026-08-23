// SPDX-License-Identifier: Apache-2.0

//! Intervals during which the probe's own host was not running.
//!
//! A run whose host suspends mid-scenario produces artifacts that are
//! indistinguishable, field by field, from a run against a path that went
//! silent: connects record `Timeout`, sessions the daemon completed show zero
//! frames from the client, and the throughput controls fall. Nothing in the
//! record says which happened, so every number in it is read as a measurement
//! of the network — including the ones that measure a sleeping laptop.
//!
//! The signal that separates them is already on the host and costs nothing to
//! read. [`Instant`] is the monotonic clock, and on every platform this probe
//! runs on it excludes time the machine spent suspended: `CLOCK_UPTIME_RAW` on
//! macOS, `CLOCK_MONOTONIC` on Linux. [`SystemTime`] does not exclude it. So
//! over any interval the probe measures with both, the wall clock advancing
//! further than the monotonic one is the host having stopped executing, and the
//! difference is how long for.
//!
//! That is the whole mechanism, and it is deliberately not a platform API: an
//! `IOKit` power-assertion query would answer for macOS only, and the question
//! — "was this artifact recorded by a process that was running?" — is one every
//! host can be asked.

use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};

/// One interval during which this host was suspended.
///
/// `started_unix_ns` is when the host stopped executing, not when the probe
/// noticed: the watcher only regains the CPU on wake, so the near end of the
/// interval is reconstructed from the last sample that did run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Suspension {
    pub started_unix_ns: u64,
    pub duration_ns: u64,
}

/// How often the watcher compares the two clocks.
///
/// Short enough that the reconstructed start of a suspension is accurate to
/// about this much, and cheap enough to leave running for a whole campaign:
/// one pair of clock reads a second is not measurable against a run that moves
/// megabits.
const SAMPLE_INTERVAL: Duration = Duration::from_secs(1);

/// How far the two clocks may diverge over one sample before it is called a
/// suspension.
///
/// Not zero, and not a guess about scheduler jitter. Two things move these
/// clocks apart without the host stopping: a runtime that does not get to the
/// timer on time, which is bounded by scheduling and is milliseconds; and an
/// NTP correction stepping the wall clock, which is unbounded in principle but
/// is a step rather than a stall — `chronyd` and macOS both slew corrections of
/// this size rather than jumping them. Five seconds is above both and two
/// orders of magnitude below the shortest suspension worth recording, so the
/// choice is not delicate in either direction. A divergence this small also
/// cannot change how a run is read: it is shorter than one handshake's
/// retransmit budget.
const DIVERGENCE_TOLERANCE: Duration = Duration::from_secs(5);

/// How much of `wall` the host did not run for, given that the monotonic clock
/// advanced by `mono` over the same interval.
///
/// The pure half of the mechanism, so the arithmetic can be checked without a
/// host that sleeps on demand. `None` means the two clocks agree inside
/// `tolerance` — including the case where the wall clock went *backwards*,
/// which is an NTP step and not a suspension, and which saturates to zero here
/// rather than wrapping into a spurious multi-century interval.
pub fn suspended_for(mono: Duration, wall: Duration, tolerance: Duration) -> Option<Duration> {
    let divergence = wall.checked_sub(mono).unwrap_or(Duration::ZERO);
    (divergence > tolerance).then_some(divergence)
}

/// A background sampler that records every interval this host was suspended.
///
/// Cloneable and cheap; the collected intervals are read back with
/// [`SuspendWatch::take`] once the run is over.
#[derive(Debug, Clone, Default)]
pub struct SuspendWatch {
    found: Arc<Mutex<Vec<Suspension>>>,
}

impl SuspendWatch {
    pub fn new() -> Self {
        Self::default()
    }

    /// Start sampling in the background. The returned handle collects into the
    /// same storage as `self`; dropping the task stops the sampling and leaves
    /// what it found intact.
    pub fn spawn(&self) -> tokio::task::JoinHandle<()> {
        let watch = self.clone();
        tokio::spawn(async move {
            let mut prev = (Instant::now(), SystemTime::now());
            loop {
                tokio::time::sleep(SAMPLE_INTERVAL).await;
                let now = (Instant::now(), SystemTime::now());
                let mono = now.0.duration_since(prev.0);
                let wall = now.1.duration_since(prev.1).unwrap_or(Duration::ZERO);
                if let Some(gap) = suspended_for(mono, wall, DIVERGENCE_TOLERANCE) {
                    // The host stopped executing after the previous sample plus
                    // whatever monotonic time it did get, which is where the
                    // suspension begins.
                    let started = prev
                        .1
                        .checked_add(mono)
                        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                        .map(|d| d.as_nanos() as u64)
                        .unwrap_or(0);
                    watch.record(Suspension {
                        started_unix_ns: started,
                        duration_ns: gap.as_nanos() as u64,
                    });
                }
                prev = now;
            }
        })
    }

    fn record(&self, s: Suspension) {
        if let Ok(mut v) = self.found.lock() {
            v.push(s);
        }
    }

    /// Every suspension seen so far, oldest first, leaving the watch empty.
    pub fn take(&self) -> Vec<Suspension> {
        self.found
            .lock()
            .map(|mut v| std::mem::take(&mut *v))
            .unwrap_or_default()
    }
}

/// The line a reader needs before treating any number in this run as a
/// measurement of the network.
///
/// Returns `None` when the host ran throughout, so a clean run carries no
/// note — a caveat that appears on every run is one nobody reads.
pub fn verdict(suspensions: &[Suspension], run_span: Duration) -> Option<String> {
    if suspensions.is_empty() {
        return None;
    }
    let total: u64 = suspensions.iter().map(|s| s.duration_ns).sum();
    let total_s = total as f64 / 1e9;
    let span_s = run_span.as_secs_f64().max(1e-9);
    let longest = suspensions.iter().map(|s| s.duration_ns).max().unwrap_or(0) as f64 / 1e9;
    Some(format!(
        "this host was suspended {} time(s) during the run, for {:.0} s in all \
         ({:.0}% of the {:.0} s span; longest {:.0} s). A connect that spans a \
         suspension records Timeout and a transfer that spans one records a \
         rate, and neither is a measurement of the path — the daemon may well \
         have completed the handshake and counted it a success while this \
         process was not running to hear the reply. Treat every figure whose \
         window overlaps a suspension as absent, not as slow.",
        suspensions.len(),
        total_s,
        100.0 * total_s / span_s,
        span_s,
        longest,
    ))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    const TOL: Duration = Duration::from_secs(5);

    /// The ordinary case: both clocks advance together and nothing is claimed.
    #[test]
    fn clocks_that_agree_report_no_suspension() {
        assert_eq!(
            suspended_for(Duration::from_secs(1), Duration::from_secs(1), TOL),
            None
        );
    }

    /// Scheduling jitter moves the wall clock ahead by milliseconds. That must
    /// not be recorded, or every run carries a note and the note stops meaning
    /// anything.
    #[test]
    fn jitter_inside_the_tolerance_is_not_a_suspension() {
        assert_eq!(
            suspended_for(Duration::from_secs(1), Duration::from_millis(1_400), TOL),
            None
        );
        // Right at the boundary is still not one: the comparison is strict, so
        // the tolerance is the largest divergence that stays silent.
        assert_eq!(
            suspended_for(Duration::from_secs(1), Duration::from_secs(6), TOL),
            None
        );
    }

    /// The case this module exists for, at the scale actually observed: a
    /// clamshell sleep of about a quarter of an hour, during which the
    /// monotonic clock advanced by one sampling interval's worth at most.
    #[test]
    fn a_clamshell_sleep_is_reported_with_its_length() {
        let gap = suspended_for(Duration::from_secs(1), Duration::from_secs(1_016), TOL)
            .expect("a 1015 s divergence is a suspension");
        assert_eq!(gap, Duration::from_secs(1_015));
    }

    /// An NTP step backwards is not a suspension, and must not underflow into
    /// one. `Duration` subtraction panics on underflow, so this pins that the
    /// saturating path is the one taken.
    #[test]
    fn a_backwards_wall_clock_step_is_not_a_suspension() {
        assert_eq!(
            suspended_for(Duration::from_secs(10), Duration::from_secs(1), TOL),
            None
        );
    }

    /// A monotonic clock that ran while the wall clock did not is likewise not
    /// a suspension — it is the same NTP step in the other direction.
    #[test]
    fn a_stalled_wall_clock_is_not_a_suspension() {
        assert_eq!(
            suspended_for(Duration::from_secs(60), Duration::ZERO, TOL),
            None
        );
    }

    /// A clean run says nothing, so the note keeps its force on the run that
    /// needs it.
    #[test]
    fn a_run_that_stayed_awake_carries_no_verdict() {
        assert_eq!(verdict(&[], Duration::from_secs(1_000)), None);
    }

    /// The verdict has to carry the three numbers a reader needs to decide
    /// which scenarios to discard: how much time was lost, what share of the
    /// run that was, and how long the worst single gap ran.
    #[test]
    fn the_verdict_states_the_share_of_the_run_that_was_lost() {
        let s = vec![
            Suspension {
                started_unix_ns: 1_000,
                duration_ns: 900 * 1_000_000_000,
            },
            Suspension {
                started_unix_ns: 2_000,
                duration_ns: 5_300 * 1_000_000_000,
            },
        ];
        let v = verdict(&s, Duration::from_secs(19_566)).expect("two suspensions get a verdict");
        assert!(v.contains("2 time(s)"), "{v}");
        assert!(v.contains("6200 s in all"), "{v}");
        assert!(v.contains("32%"), "{v}");
        assert!(v.contains("longest 5300 s"), "{v}");
    }

    /// The watch is the collecting half; taking drains it so a second read of
    /// the same run cannot double-count.
    #[test]
    fn taking_the_findings_drains_the_watch() {
        let w = SuspendWatch::new();
        assert!(w.take().is_empty());
        w.record(Suspension {
            started_unix_ns: 7,
            duration_ns: 11,
        });
        assert_eq!(
            w.take(),
            vec![Suspension {
                started_unix_ns: 7,
                duration_ns: 11
            }]
        );
        assert!(
            w.take().is_empty(),
            "a second take must not repeat the first"
        );
    }

    /// Clones share one storage, so the sampling task and the run that reads it
    /// are looking at the same list.
    #[test]
    fn clones_share_one_set_of_findings() {
        let w = SuspendWatch::new();
        let c = w.clone();
        c.record(Suspension {
            started_unix_ns: 1,
            duration_ns: 2,
        });
        assert_eq!(w.take().len(), 1);
    }

    /// End to end over the real clocks: a watch that runs while the host does
    /// must find nothing. This is the half the pure function cannot check —
    /// that the sampler's own arithmetic does not manufacture a suspension out
    /// of an ordinary tokio timer.
    #[tokio::test(flavor = "current_thread")]
    async fn a_running_host_produces_no_findings() {
        let w = SuspendWatch::new();
        let h = w.spawn();
        tokio::time::sleep(Duration::from_millis(2_200)).await;
        h.abort();
        assert!(
            w.take().is_empty(),
            "two sampling intervals on a running host must record nothing"
        );
    }
}
