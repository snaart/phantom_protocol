//! How long a bulk transfer has to run before its mean rate is a capacity.
//!
//! A BBR-style controller does not begin a transfer knowing what the path
//! carries; it climbs towards it. Startup is the only exponential phase, and
//! everything after it rises at the gain cycle's quarter per four round trips.
//! So a transfer that ends while the estimate is still rising has measured how
//! fast the controller converges — a property of the controller and the path's
//! round trip — and its mean rate is that convergence time wearing the name of a
//! capacity. Six measured uploads in one campaign delivered 12–19% of their
//! bytes in the first half and 44–62% in the last quarter, which is the shape of
//! a ramp and not of a transfer that ever reached a rate.
//!
//! The window that avoids this is not a number of seconds, because none of the
//! terms above is measured in seconds: they are all round trips. Fixing the
//! window in seconds means a path with twice the round trip gets half the
//! convergence, which is the wrong direction — a longer path needs *longer*.
//! Everything here is therefore counted in round trips and multiplied by the
//! round trip the run itself measured.

use std::time::Duration;

/// Round trips in one ProbeBW gain cycle.
///
/// The cycle asks the path for more than the estimate on one round in four; the
/// other three are the pace at the estimate and the drain of whatever queue the
/// probing round built.
pub const GAIN_CYCLE_ROUNDS: f64 = 4.0;

/// What one cycle is worth, as a multiplier on the bandwidth estimate.
///
/// A **lower** bound, deliberately: the probing round runs at `cwnd_gain` 2.0,
/// so it can deliver more than a quarter over. A lower bound on the climb is an
/// upper bound on the rounds a climb needs, which is the conservative direction
/// for sizing a measurement window.
pub const GAIN_PER_CYCLE: f64 = 1.25;

/// The factor the estimate has to climb after Startup ends.
///
/// Measured, not chosen. In the six-run campaign of 2026-08-23 the four
/// transfers that left Startup did so with estimates of 1.18–1.76 Mbit/s, while
/// the reference leg on the same path in the same run carried 17–42; the worst
/// pair is 42.07 against 1.18, a climb of 35.7×. Forty covers it with margin.
pub const CONVERGENCE_CLIMB: f64 = 40.0;

/// Round trips allowed for Startup itself.
///
/// Observed at 1.81–2.42 s on a path whose minimum round trip was 191 ms, which
/// is 9.5–12.7 rounds. Sixteen clears the worst of them by a quarter.
pub const STARTUP_ROUNDS: f64 = 16.0;

/// Share of the transfer that must lie past convergence.
///
/// The capacity figure a converged transfer yields is the rate over its last
/// quarter, so the last quarter has to be plateau rather than the top of the
/// ramp. This is the same quarter [`crate::report::WindowSample`] readers take
/// that rate over, and the two are the same number for that reason.
pub const PLATEAU_SHARE: f64 = 0.25;

/// Round trips from the first byte to a converged bandwidth estimate.
pub fn rounds_to_converge() -> f64 {
    STARTUP_ROUNDS + GAIN_CYCLE_ROUNDS * CONVERGENCE_CLIMB.ln() / GAIN_PER_CYCLE.ln()
}

/// Round trips a transfer must run for its last quarter to be a plateau.
///
/// Whole rounds: a fraction of a round trip is not a unit anything here moves
/// in, and rounding up is the conservative direction.
pub fn rounds_to_measure() -> f64 {
    (rounds_to_converge() / (1.0 - PLATEAU_SHARE)).ceil()
}

/// What a converged transfer costs in wall clock on a path with this round trip.
pub fn cost_at(rtt: Duration) -> Duration {
    Duration::from_secs_f64(rounds_to_measure() * rtt.as_secs_f64())
}

/// Where an upload's measurement window came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowBasis {
    /// The profile's window, or the operator's `--upload-secs`. A number of
    /// seconds, which is not a unit convergence happens in.
    Fixed,
    /// Derived from the round trip this run measured.
    Derived,
    /// A derived window was asked for and the run has no measured round trip,
    /// so the fixed one ran instead. Recorded as its own case because a window
    /// that silently fell back is a window nobody chose.
    DerivationUnavailable,
}

/// The window one bulk upload runs for, and what a reader has to know about it.
#[derive(Debug, Clone)]
pub struct UploadWindow {
    pub duration: Duration,
    pub basis: WindowBasis,
    /// The run's measured minimum round trip, when it has one. Every round-trip
    /// count below is against this, so a note without it states no counts.
    pub rtt: Option<Duration>,
}

impl UploadWindow {
    /// Resolve the window for this run.
    ///
    /// `fixed` is what the profile (or `--upload-secs`) asked for and is the
    /// fallback in every case where the derivation cannot be made, because a run
    /// that refuses to upload at all answers strictly less than one whose upload
    /// says what it is.
    pub fn resolve(want_derived: bool, fixed: Duration, rtt: Option<Duration>) -> Self {
        match (want_derived, rtt) {
            (true, Some(rtt)) => Self {
                duration: cost_at(rtt),
                basis: WindowBasis::Derived,
                rtt: Some(rtt),
            },
            (true, None) => Self {
                duration: fixed,
                basis: WindowBasis::DerivationUnavailable,
                rtt: None,
            },
            (false, rtt) => Self {
                duration: fixed,
                basis: WindowBasis::Fixed,
                rtt,
            },
        }
    }

    /// Round trips this window is, at the run's measured round trip.
    pub fn rounds(&self) -> Option<f64> {
        let rtt = self.rtt?;
        (rtt > Duration::ZERO).then(|| self.duration.as_secs_f64() / rtt.as_secs_f64())
    }

    /// Whether this window can hold a convergence, as far as the arithmetic
    /// above can say before the transfer runs.
    ///
    /// `None` without a measured round trip: the question is a comparison
    /// between two counts of round trips, and a run with no round trip has one
    /// of them. That is a different answer from "no", and conflating them is how
    /// a window nobody could size comes to read as a window that was sized.
    pub fn can_converge(&self) -> Option<bool> {
        Some(self.rounds()? >= rounds_to_converge())
    }

    /// The one line about this window that has to travel with the numbers.
    pub fn note(&self) -> String {
        let secs = self.duration.as_secs_f64();
        match self.basis {
            WindowBasis::Derived => {
                // Unwrapping is not needed: `Derived` is only constructed with a
                // round trip in hand, and the arithmetic below restates the
                // derivation rather than assuming it.
                let rtt_ms = self.rtt.map(|r| r.as_secs_f64() * 1000.0).unwrap_or(0.0);
                format!(
                    "upload window {secs:.1} s = {rounds:.0} round trips at the {rtt_ms:.0} ms this run measured: \
                     {startup:.0} for Startup, {climb:.0} for the gain cycle to climb {factor:.0}x at \
                     {per_cycle}x per {cycle:.0} rounds, and a further quarter of the transfer past that so \
                     the rate over its last quarter is a plateau rather than the top of the ramp",
                    rounds = rounds_to_measure(),
                    startup = STARTUP_ROUNDS,
                    climb = rounds_to_converge() - STARTUP_ROUNDS,
                    factor = CONVERGENCE_CLIMB,
                    per_cycle = GAIN_PER_CYCLE,
                    cycle = GAIN_CYCLE_ROUNDS,
                )
            }
            WindowBasis::DerivationUnavailable => format!(
                "a window derived from the path was asked for, but this run has no measured round trip \
                 (clock_sync did not complete), so the upload ran its fixed {secs:.1} s. On a long path \
                 that is a convergence time rather than a capacity, and nothing in this run can say which"
            ),
            WindowBasis::Fixed => match (self.rounds(), self.can_converge()) {
                (Some(rounds), Some(false)) => format!(
                    "upload window {secs:.1} s = {rounds:.0} round trips at the {rtt_ms:.0} ms this run \
                     measured, against the {needed:.0} a controller climbing {factor:.0}x at {per_cycle}x per \
                     {cycle:.0} rounds needs on this path: this window cannot converge, so its mean rate is a \
                     convergence time and not a capacity. --upload-converge derives the window from the path \
                     ({cost:.1} s here)",
                    rtt_ms = self.rtt.map(|r| r.as_secs_f64() * 1000.0).unwrap_or(0.0),
                    needed = rounds_to_converge(),
                    factor = CONVERGENCE_CLIMB,
                    per_cycle = GAIN_PER_CYCLE,
                    cycle = GAIN_CYCLE_ROUNDS,
                    cost = self
                        .rtt
                        .map(|r| cost_at(r).as_secs_f64())
                        .unwrap_or_default(),
                ),
                (Some(rounds), Some(true)) => format!(
                    "upload window {secs:.1} s = {rounds:.0} round trips at the {rtt_ms:.0} ms this run \
                     measured, past the {needed:.0} a controller climbing {factor:.0}x needs on this path — \
                     long enough to converge, which the transfer's own shape then either confirms or refutes",
                    rtt_ms = self.rtt.map(|r| r.as_secs_f64() * 1000.0).unwrap_or(0.0),
                    needed = rounds_to_converge(),
                    factor = CONVERGENCE_CLIMB,
                ),
                _ => format!(
                    "upload window {secs:.1} s; this run has no measured round trip, so whether that is long \
                     enough for the bandwidth estimate to converge cannot be stated, and neither can whether \
                     the rate it reports is a capacity"
                ),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The published cost of the derived window, on the path this harness is
    /// aimed at. It is in the flag's help text and in the README, and an
    /// operator budgets a run against it.
    #[test]
    fn a_converged_upload_costs_twenty_two_seconds_on_a_two_hundred_millisecond_path() {
        assert_eq!(rounds_to_measure(), 110.0);
        let cost = cost_at(Duration::from_millis(200));
        assert!(
            (cost.as_secs_f64() - 22.0).abs() < 1e-9,
            "110 rounds at 200 ms is 22.0 s, got {cost:?}"
        );
        // And it scales with the path, which is the whole reason it is not a
        // number of seconds: a 230 ms path needs longer, not the same.
        assert!(cost_at(Duration::from_millis(230)) > cost);
    }

    /// The derivation must be the arithmetic it claims to be, not a constant
    /// with a story attached.
    #[test]
    fn the_round_count_is_the_arithmetic_and_not_a_remembered_number() {
        let climb_rounds = GAIN_CYCLE_ROUNDS * CONVERGENCE_CLIMB.ln() / GAIN_PER_CYCLE.ln();
        assert!(
            (rounds_to_converge() - (STARTUP_ROUNDS + climb_rounds)).abs() < 1e-9,
            "convergence is Startup plus the climb"
        );
        // The climb it allows must actually reach the factor it names.
        let cycles = climb_rounds / GAIN_CYCLE_ROUNDS;
        assert!(
            GAIN_PER_CYCLE.powf(cycles) >= CONVERGENCE_CLIMB - 1e-9,
            "the rounds allowed do not deliver the climb they were sized for"
        );
        assert!(
            rounds_to_measure() >= rounds_to_converge() / (1.0 - PLATEAU_SHARE),
            "the last quarter has to lie past convergence"
        );
    }

    #[test]
    fn a_derived_window_scales_with_the_measured_round_trip() {
        let short = UploadWindow::resolve(
            true,
            Duration::from_secs(10),
            Some(Duration::from_millis(100)),
        );
        let long = UploadWindow::resolve(
            true,
            Duration::from_secs(10),
            Some(Duration::from_millis(400)),
        );
        assert_eq!(short.basis, WindowBasis::Derived);
        assert_eq!(
            long.duration.as_secs_f64() / short.duration.as_secs_f64(),
            4.0,
            "four times the round trip is four times the window"
        );
        assert!(
            short.duration > Duration::from_secs(10),
            "and not the fixed one"
        );
        assert_eq!(short.can_converge(), Some(true));
        assert!(short.note().contains("Startup"), "{}", short.note());
    }

    /// The case the whole flag exists for: a fixed ten-second window on a long
    /// path is a convergence time, and the run has to say so where its numbers
    /// are read rather than leaving it to be worked out afterwards.
    #[test]
    fn a_fixed_window_too_short_to_converge_says_so_in_its_own_note() {
        let w = UploadWindow::resolve(
            false,
            Duration::from_secs(10),
            Some(Duration::from_millis(191)),
        );
        assert_eq!(w.basis, WindowBasis::Fixed);
        assert_eq!(w.can_converge(), Some(false));
        let note = w.note();
        assert!(note.contains("cannot converge"), "{note}");
        assert!(note.contains("not a capacity"), "{note}");
        assert!(note.contains("--upload-converge"), "{note}");
        // 52 rounds at 191 ms, and the cost of the alternative, both stated.
        assert!(note.contains("52 round trips"), "{note}");
        assert!(note.contains("21.0 s"), "{note}");
    }

    #[test]
    fn a_long_enough_fixed_window_is_not_accused_of_being_a_ramp() {
        let w = UploadWindow::resolve(
            false,
            Duration::from_secs(60),
            Some(Duration::from_millis(191)),
        );
        assert_eq!(w.can_converge(), Some(true));
        let note = w.note();
        assert!(note.contains("long enough to converge"), "{note}");
        assert!(
            !note.contains("cannot converge"),
            "a window that can converge must not carry the opposite claim: {note}"
        );
        // Long enough to converge is not the same as having converged, and the
        // note must not be read as the second.
        assert!(note.contains("either confirms or refutes"), "{note}");
    }

    /// Without a round trip there are no round-trip counts, and the note must
    /// say that rather than printing counts against a guessed path.
    #[test]
    fn no_measured_round_trip_means_no_claim_in_either_direction() {
        let w = UploadWindow::resolve(false, Duration::from_secs(10), None);
        assert_eq!(w.rounds(), None);
        assert_eq!(w.can_converge(), None);
        let note = w.note();
        assert!(note.contains("no measured round trip"), "{note}");
        assert!(!note.contains("round trips at"), "{note}");

        // And asking for a derived window without one falls back, loudly.
        let d = UploadWindow::resolve(true, Duration::from_secs(10), None);
        assert_eq!(d.basis, WindowBasis::DerivationUnavailable);
        assert_eq!(d.duration, Duration::from_secs(10));
        assert!(
            d.note().contains("clock_sync did not complete"),
            "{}",
            d.note()
        );
    }

    /// A zero round trip is a loopback artefact rather than a path, and dividing
    /// by it would report an infinity as a round-trip count.
    #[test]
    fn a_zero_round_trip_produces_no_counts_rather_than_an_infinity() {
        let w = UploadWindow::resolve(false, Duration::from_secs(10), Some(Duration::ZERO));
        assert_eq!(w.rounds(), None);
        assert_eq!(w.can_converge(), None);
        assert!(w.note().contains("no measured round trip"), "{}", w.note());
    }
}
