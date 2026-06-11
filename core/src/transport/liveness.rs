//! Path-liveness decision logic (Phase 4 / P4.3).
//!
//! A purely-functional, async-free, [`Duration`]-only decision so the threshold
//! logic is exhaustively unit-testable without standing up the data pump. The
//! pump gathers the live signals each heartbeat and applies the returned verdict.
//!
//! Liveness signal (design §D4): *N×PTO of inbound silence while we have
//! outstanding unacked reliable data → the path is down.* The `inflight > 0` gate
//! is what keeps a slow-but-alive or genuinely-idle path from false-tripping — we
//! only declare a path down when we are *expecting* a response. A purely-passive
//! receiver (download-only, sending only ACKs) needs keep-alive PINGs to notice a
//! dead path; those are deferred (design §10), and the symmetric peer that is
//! *sending* the download detects the vanished receiver the same way.

use core::time::Duration;

/// Tunables for path-down / session-death detection (Phase 4 / P4.3).
#[derive(Debug, Clone, Copy)]
pub struct LivenessConfig {
    /// Floor for the probe-timeout period. The effective PTO is
    /// `max(min_pto, 3 × min_rtt)`, so an unmeasured RTT (`min_rtt == 0`) falls
    /// back to this floor.
    pub min_pto: Duration,
    /// Consecutive probe-timeout periods of inbound silence — while we have
    /// outstanding unacked data — before the path is declared down.
    pub path_down_ptos: u32,
    /// Once `Migrating`, how long to wait for the path to recover (a migrate +
    /// validate, or any inbound life) before declaring the session dead.
    pub idle_timeout: Duration,
}

impl Default for LivenessConfig {
    fn default() -> Self {
        Self {
            // ~1s of silence-with-outstanding-data on a fast path (5 × 200ms)
            // before "path down" — responsive but well clear of transient blips.
            min_pto: Duration::from_millis(200),
            path_down_ptos: 5,
            idle_timeout: Duration::from_secs(30),
        }
    }
}

impl LivenessConfig {
    /// Shrunk thresholds so tests/integration exercise the state machine in
    /// milliseconds instead of seconds (mirrors `Session::set_rekey_threshold`).
    pub fn for_test() -> Self {
        Self {
            min_pto: Duration::from_millis(10),
            path_down_ptos: 3,
            idle_timeout: Duration::from_millis(300),
        }
    }

    /// Effective probe-timeout period for an estimated `min_rtt`: `3 × RTT`,
    /// floored at `min_pto`. (Session-level approximation of RFC 9002 PTO; we do
    /// not track `rttvar` at the session level.)
    fn pto(&self, min_rtt: Duration) -> Duration {
        let scaled = min_rtt.saturating_mul(3);
        if scaled > self.min_pto {
            scaled
        } else {
            self.min_pto
        }
    }

    /// Inbound-silence (with outstanding data) beyond which the path is down.
    fn path_down_after(&self, min_rtt: Duration) -> Duration {
        self.pto(min_rtt).saturating_mul(self.path_down_ptos)
    }
}

/// The transition implied by one liveness evaluation. The caller maps it onto the
/// session state machine (`Connected` ⇄ `Migrating` → `Dead`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LivenessVerdict {
    /// No transition — keep the current state.
    Unchanged,
    /// Path is down: `Connected → Migrating` (surface "migrate me"; hold keys).
    PathDown,
    /// Inbound life resumed while `Migrating`: `Migrating → Connected`.
    Recovered,
    /// Idle-timeout elapsed while `Migrating` with no recovery: `Migrating → Dead`.
    Dead,
}

/// Decide the liveness transition from the current signals (pure).
///
/// - `silence`: time since the last authenticated inbound packet.
/// - `inflight`: outstanding unacked reliable bytes (BBR in-flight) — the gate
///   that keeps a slow-but-alive or idle path from false-tripping.
/// - `min_rtt`: path RTT estimate (`0`/unset → the `min_pto` floor governs).
/// - `in_migrating`: whether we are already in the `Migrating` keep-alive state.
/// - `migrating_for`: how long we have been `Migrating` (ignored when not).
pub fn liveness_verdict(
    silence: Duration,
    inflight: u64,
    min_rtt: Duration,
    in_migrating: bool,
    migrating_for: Duration,
    cfg: &LivenessConfig,
) -> LivenessVerdict {
    if in_migrating {
        // Recovery beats death: if inbound just resumed (silence within one PTO),
        // recover even at/after the idle-timeout edge — liveness over teardown.
        if silence <= cfg.pto(min_rtt) {
            return LivenessVerdict::Recovered;
        }
        if migrating_for > cfg.idle_timeout {
            return LivenessVerdict::Dead;
        }
        return LivenessVerdict::Unchanged;
    }
    // Connected: down only when we have outstanding data AND inbound has been
    // silent past `path_down_ptos × PTO`.
    if inflight > 0 && silence > cfg.path_down_after(min_rtt) {
        LivenessVerdict::PathDown
    } else {
        LivenessVerdict::Unchanged
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Explicit thresholds so the boundary asserts are obvious: with `min_rtt = 0`
    /// the PTO is `min_pto = 100ms` and the path-down threshold is `4 × 100ms = 400ms`.
    fn cfg() -> LivenessConfig {
        LivenessConfig {
            min_pto: Duration::from_millis(100),
            path_down_ptos: 4,
            idle_timeout: Duration::from_secs(1),
        }
    }

    #[test]
    fn no_outstanding_data_never_declares_path_down() {
        // Huge silence but nothing in flight → no transition: a quiet idle path is
        // not a dead path (keep-alive PINGs are deferred, §10).
        let v = liveness_verdict(
            Duration::from_secs(60),
            0,
            Duration::ZERO,
            false,
            Duration::ZERO,
            &cfg(),
        );
        assert_eq!(v, LivenessVerdict::Unchanged);
    }

    #[test]
    fn outstanding_data_just_below_threshold_is_unchanged() {
        let v = liveness_verdict(
            Duration::from_millis(399),
            1200,
            Duration::ZERO,
            false,
            Duration::ZERO,
            &cfg(),
        );
        assert_eq!(v, LivenessVerdict::Unchanged);
    }

    #[test]
    fn outstanding_data_past_threshold_is_path_down() {
        let v = liveness_verdict(
            Duration::from_millis(401),
            1200,
            Duration::ZERO,
            false,
            Duration::ZERO,
            &cfg(),
        );
        assert_eq!(v, LivenessVerdict::PathDown);
    }

    #[test]
    fn pto_scales_with_min_rtt() {
        // min_rtt=200ms → pto = max(100ms, 3×200ms) = 600ms; threshold = 4×600 = 2400ms.
        let below = liveness_verdict(
            Duration::from_millis(2000),
            800,
            Duration::from_millis(200),
            false,
            Duration::ZERO,
            &cfg(),
        );
        assert_eq!(
            below,
            LivenessVerdict::Unchanged,
            "2000ms < 2400ms threshold"
        );
        let above = liveness_verdict(
            Duration::from_millis(2500),
            800,
            Duration::from_millis(200),
            false,
            Duration::ZERO,
            &cfg(),
        );
        assert_eq!(
            above,
            LivenessVerdict::PathDown,
            "2500ms > 2400ms threshold"
        );
    }

    #[test]
    fn migrating_and_still_silent_is_unchanged_until_idle_timeout() {
        let v = liveness_verdict(
            Duration::from_secs(10),
            800,
            Duration::ZERO,
            true,
            Duration::from_millis(500),
            &cfg(),
        );
        assert_eq!(v, LivenessVerdict::Unchanged);
    }

    #[test]
    fn migrating_recovers_when_inbound_resumes() {
        // Silence collapsed to within one PTO (100ms) → we just heard from the peer.
        let v = liveness_verdict(
            Duration::from_millis(50),
            800,
            Duration::ZERO,
            true,
            Duration::from_millis(500),
            &cfg(),
        );
        assert_eq!(v, LivenessVerdict::Recovered);
    }

    #[test]
    fn migrating_dies_after_idle_timeout() {
        let v = liveness_verdict(
            Duration::from_secs(10),
            800,
            Duration::ZERO,
            true,
            Duration::from_millis(1100),
            &cfg(),
        );
        assert_eq!(v, LivenessVerdict::Dead);
    }

    #[test]
    fn recovery_beats_death_at_the_idle_timeout_edge() {
        // Even past the idle-timeout, if inbound JUST resumed we recover rather than
        // kill the session — liveness wins.
        let v = liveness_verdict(
            Duration::from_millis(20),
            800,
            Duration::ZERO,
            true,
            Duration::from_secs(5),
            &cfg(),
        );
        assert_eq!(v, LivenessVerdict::Recovered);
    }

    #[test]
    fn for_test_config_is_faster_than_default() {
        let t = LivenessConfig::for_test();
        let d = LivenessConfig::default();
        assert!(t.idle_timeout < d.idle_timeout);
        assert!(t.min_pto <= d.min_pto);
        assert!(t.path_down_ptos >= 1);
    }

    #[test]
    fn default_config_is_sane() {
        let d = LivenessConfig::default();
        assert!(d.min_pto > Duration::ZERO);
        assert!(d.path_down_ptos >= 1);
        assert!(d.idle_timeout > d.min_pto);
    }
}
