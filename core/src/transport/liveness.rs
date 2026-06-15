//! Path-liveness decision logic (Phase 4 / P4.3).
//!
//! A purely-functional, async-free, [`Duration`]-only decision so the threshold
//! logic is exhaustively unit-testable without standing up the data pump. The
//! pump gathers the live signals each heartbeat and applies the returned verdict.
//!
//! Liveness signal (design §D4): *N×PTO of inbound silence while we have
//! outstanding unacked reliable data → the path is down.* The `inflight > 0` gate
//! is what keeps a slow-but-alive or genuinely-idle path from false-tripping — we
//! only declare a path down when we are *expecting* a response.
//!
//! A purely-passive receiver (download-only, sending only ACKs) has nothing in
//! flight, so the inactivity sweep alone would never trip for it. Direction #3
//! closes that gap with an **idle keep-alive PING** ([`should_send_keepalive`]):
//! when a `Connected` session has been idle for `keepalive_interval`, the pump
//! emits a small `ENCRYPTED | KEEPALIVE` packet. That PING is in-flight until the
//! peer PONGs it, so the very same `inflight > 0` sweep now detects a dead
//! downstream on a download-only path — and the PONG refreshes the peer's
//! activity timer symmetrically.

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
    /// Idle keep-alive interval (Direction #3 — download-only liveness). When
    /// `Some(iv)`, an otherwise-idle `Connected` session (no inbound for `iv`
    /// **and** nothing in flight) emits a small encrypted keep-alive PING every
    /// `iv`. That PING is in-flight until the peer PONGs it, so a download-only
    /// path — which sends only ACKs and otherwise has nothing in flight — gains
    /// an outstanding probe and can detect a silently-dead downstream via the
    /// same `path_down_ptos × PTO` sweep. `None` disables keep-alives (the path
    /// only trips on inactivity while reliable data is already outstanding).
    pub keepalive_interval: Option<Duration>,
}

impl Default for LivenessConfig {
    fn default() -> Self {
        Self {
            // ~1s of silence-with-outstanding-data on a fast path (5 × 200ms)
            // before "path down" — responsive but well clear of transient blips.
            min_pto: Duration::from_millis(200),
            path_down_ptos: 5,
            idle_timeout: Duration::from_secs(30),
            // A 15s idle PING keeps a download-only path detectable: well under
            // the 30s idle-timeout, comfortably above any transient inbound gap,
            // and far rarer than data traffic so it adds negligible overhead.
            keepalive_interval: Some(Duration::from_secs(15)),
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
            // Fire a keep-alive quickly so the download-only path test exercises
            // it in milliseconds rather than waiting the 15s production cadence.
            keepalive_interval: Some(Duration::from_millis(40)),
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

/// Decide whether an idle `Connected` session should emit a keep-alive PING now
/// (Direction #3 — download-only liveness). Pure, so the cadence gate is unit-
/// testable without the data pump.
///
/// Fires only when **all** hold:
/// - keep-alives are enabled (`cfg.keepalive_interval.is_some()`),
/// - the session is `Connected` (not `Migrating`/handshaking/closed),
/// - nothing is in flight (`inflight == 0`) — an active reliable transfer
///   already anchors the liveness timer, so a keep-alive would be redundant
///   *and* could race the in-flight accounting,
/// - inbound has been silent for at least the interval (`inbound_silence ≥ iv`)
///   — the path is genuinely idle, not mid-download, and
/// - we have not sent a keep-alive within the last interval
///   (`since_last_keepalive ≥ iv`) — so at most one PING per interval, never a
///   spam burst on the 10 ms pump heartbeat.
///
/// The emitted PING is itself in-flight until PONGed, which is exactly what lets
/// the [`liveness_verdict`] `inflight > 0` gate then detect a dead downstream on a
/// path that would otherwise only ever send ACKs.
pub fn should_send_keepalive(
    connected: bool,
    inflight: u64,
    inbound_silence: Duration,
    since_last_keepalive: Duration,
    cfg: &LivenessConfig,
) -> bool {
    let Some(iv) = cfg.keepalive_interval else {
        return false;
    };
    connected && inflight == 0 && inbound_silence >= iv && since_last_keepalive >= iv
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
            // Keep-alives off in these verdict tests — they assert the inactivity
            // sweep alone; the keep-alive gate is covered by `should_send_keepalive`.
            keepalive_interval: None,
        }
    }

    #[test]
    fn no_outstanding_data_never_declares_path_down() {
        // Huge silence but nothing in flight → no transition: a quiet idle path is
        // not a dead path *by the inactivity sweep alone*. (A download-only path is
        // kept detectable by the idle keep-alive PING — `should_send_keepalive`.)
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
        // The test keep-alive must fire faster than the default cadence too.
        assert!(t.keepalive_interval.unwrap() < d.keepalive_interval.unwrap());
    }

    #[test]
    fn default_config_is_sane() {
        let d = LivenessConfig::default();
        assert!(d.min_pto > Duration::ZERO);
        assert!(d.path_down_ptos >= 1);
        assert!(d.idle_timeout > d.min_pto);
        // A sane default keep-alive fires well before the idle-timeout would
        // otherwise reap an idle session, and rarely enough to be cheap.
        let ka = d.keepalive_interval.expect("default keep-alive enabled");
        assert!(
            ka < d.idle_timeout,
            "keep-alive must precede the idle-timeout"
        );
        assert!(ka > d.min_pto, "keep-alive must be rarer than one PTO");
    }

    // ── Idle keep-alive gate (`should_send_keepalive`, Direction #3) ─────────

    /// A config with a 100 ms keep-alive interval (and the same sweep thresholds
    /// as `cfg()`), so the boundary asserts below are obvious.
    fn ka_cfg() -> LivenessConfig {
        LivenessConfig {
            keepalive_interval: Some(Duration::from_millis(100)),
            ..cfg()
        }
    }

    #[test]
    fn keepalive_fires_on_an_idle_connected_path() {
        // Connected, nothing in flight, inbound silent past the interval, and no
        // recent keep-alive → emit one (the download-only liveness anchor).
        assert!(should_send_keepalive(
            true,
            0,
            Duration::from_millis(150),
            Duration::from_millis(150),
            &ka_cfg(),
        ));
    }

    #[test]
    fn keepalive_suppressed_when_disabled() {
        let cfg = LivenessConfig {
            keepalive_interval: None,
            ..cfg()
        };
        assert!(!should_send_keepalive(
            true,
            0,
            Duration::from_secs(60),
            Duration::from_secs(60),
            &cfg,
        ));
    }

    #[test]
    fn keepalive_suppressed_with_data_in_flight() {
        // An active transfer already anchors the liveness timer — no PING needed.
        assert!(!should_send_keepalive(
            true,
            1200,
            Duration::from_millis(150),
            Duration::from_millis(150),
            &ka_cfg(),
        ));
    }

    #[test]
    fn keepalive_suppressed_when_not_connected() {
        // Already Migrating (or handshaking / closed) → the keep-alive path is off.
        assert!(!should_send_keepalive(
            false,
            0,
            Duration::from_millis(150),
            Duration::from_millis(150),
            &ka_cfg(),
        ));
    }

    #[test]
    fn keepalive_suppressed_before_the_interval_and_throttled_after_a_recent_ping() {
        // Inbound only just went quiet → not yet idle enough.
        assert!(!should_send_keepalive(
            true,
            0,
            Duration::from_millis(50),
            Duration::from_millis(150),
            &ka_cfg(),
        ));
        // Idle long enough, but a keep-alive was sent <interval ago → throttled to
        // at most one PING per interval (no 10 ms-heartbeat spam).
        assert!(!should_send_keepalive(
            true,
            0,
            Duration::from_millis(150),
            Duration::from_millis(50),
            &ka_cfg(),
        ));
    }
}
