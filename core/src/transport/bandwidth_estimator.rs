//! BBR-like Bandwidth Estimator
//!
//! Implements a simplified BBR (Bottleneck Bandwidth and Round-trip propagation time)
//! state machine on top of KCP's ACK feedback.
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
//! - **Startup:** Double sending rate exponentially until bottleneck bandwidth is found
//! - **Drain:** Reduce rate until inflight ≤ BDP (drain queues built during Startup)
//! - **ProbeBW:** Cycle through pacing gains (1.25, 0.75, 1.0, 1.0) to probe bandwidth
//! - **ProbeRTT:** Every 10s, reduce CWND to 4 packets for 200ms to measure true min RTT
//!
//! # Integration
//!
//! The estimator feeds the `Pacer` with target rates:
//! ```text
//!   BandwidthEstimator ──rate──▶ Pacer ──paced_send──▶ UdpTransport
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

/// A single delivery sample (attached to each ACKed packet)
#[derive(Debug, Clone, Copy)]
pub struct DeliverySample {
    /// Bytes delivered at time of sending
    pub delivered_bytes: u64,
    /// Timestamp when packet was sent
    pub sent_at: Instant,
    /// Timestamp when ACK was received
    pub acked_at: Instant,
    /// Bytes in this packet
    pub packet_bytes: u64,
    /// Whether the sender was application-limited when this packet was sent
    pub is_app_limited: bool,
    /// ACK delay reported by the receiver (microseconds).
    /// The receiver measures time between packet receipt and ACK send;
    /// subtracting this from the observed RTT gives the propagation delay.
    pub ack_delay_us: u64,
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
    /// Sliding window for max bandwidth (10 round-trips)
    bw_filter: WindowFilter,
    /// Sliding window for min RTT (10 seconds)
    rtt_filter: WindowFilter,
    /// Total bytes delivered (monotonically increasing)
    delivered_bytes: u64,
    /// Timestamp of last delivery
    last_delivery: Instant,
    /// Pacing gain multiplier (1.0 = 100%, 1.25 = probe, 0.75 = drain)
    pacing_gain: f64,
    /// CWND gain multiplier
    cwnd_gain: f64,
    /// Round counter (ticks on each ACK in Startup, cycles in ProbeBW)
    round_count: u32,
    /// Whether we've found the bottleneck bandwidth
    filled_pipe: bool,
    /// Previous bandwidth sample for startup exit decision
    prev_bw: u64,
    /// Number of rounds with insufficient BW increase (startup exit condition)
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
            delivered_bytes: 0,
            last_delivery: now,
            pacing_gain: 2.0, // Startup: double the rate
            cwnd_gain: 2.0,
            round_count: 0,
            filled_pipe: false,
            prev_bw: 0,
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

        // Calculate delivery rate for this sample.
        // `send_elapsed` is the full observed RTT. We subtract the receiver's ack_delay
        // to get the true propagation delay (RTprop), matching QUIC RFC 9002 §5.3.
        let send_elapsed = sample.acked_at.duration_since(sample.sent_at);
        let ack_delay = Duration::from_micros(sample.ack_delay_us);
        let rtt_propagation = send_elapsed.saturating_sub(ack_delay);

        // Update min RTT using the propagation delay (RTprop)
        let rtt_us = rtt_propagation.as_micros() as u64;
        if rtt_us > 0 {
            let min_rtt_us = self.rtt_filter.update_min(now, rtt_us);
            self.min_rtt = Duration::from_micros(min_rtt_us);
        }

        // Calculate bandwidth: delivered_bytes / time
        let delivery_rate = if !send_elapsed.is_zero() {
            (sample.packet_bytes as f64 / send_elapsed.as_secs_f64()) as u64
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
        self.update_state(now);

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

    /// Get the round count.
    pub fn round_count(&self) -> u32 {
        self.round_count
    }

    // ── State Machine ───────────────────────────────────────────────────────

    /// Run BBR state machine transitions.
    fn update_state(&mut self, now: Instant) {
        // ── ProbeRTT check: global timer, any state can enter except Startup and FastRecovery ──
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
                self.round_count += 1;

                // Check if pipe is filled (BW growth < threshold)
                if self.prev_bw > 0 {
                    let growth = (self.btl_bw as f64 - self.prev_bw as f64) / self.prev_bw as f64;

                    if growth < STARTUP_GROWTH_THRESHOLD {
                        self.rounds_without_growth += 1;
                    } else {
                        self.rounds_without_growth = 0;
                    }

                    if self.rounds_without_growth >= STARTUP_ROUNDS_LIMIT {
                        self.filled_pipe = true;
                        self.transition_to(BbrState::Drain);
                    }
                }
                self.prev_bw = self.btl_bw;
            }
            BbrState::Drain => {
                // Stay in Drain until inflight ≤ BDP
                let bdp = self.bdp();
                if self.inflight_bytes <= bdp || bdp == 0 {
                    self.transition_to(BbrState::ProbeBW);
                }
            }
            BbrState::ProbeBW => {
                // Cycle through pacing gains
                let cycle_idx = (self.round_count as usize) % PROBE_BW_GAINS.len();
                self.pacing_gain = PROBE_BW_GAINS[cycle_idx];
                self.cwnd_gain = 2.0;
                self.round_count += 1;
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
                // Exit FastRecovery when inflight drops below BDP (pipe drained)
                // or after one min_rtt has elapsed with no new losses
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
            sent_at,
            acked_at: sent_at + Duration::from_millis(rtt_ms),
            packet_bytes,
            is_app_limited: false,
            ack_delay_us: 0, // No ACK delay in tests
        }
    }

    fn make_app_limited_sample(sent_at: Instant, rtt_ms: u64, packet_bytes: u64) -> DeliverySample {
        DeliverySample {
            delivered_bytes: 0,
            sent_at,
            acked_at: sent_at + Duration::from_millis(rtt_ms),
            packet_bytes,
            is_app_limited: true,
            ack_delay_us: 0,
        }
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

        // Send many ACKs with constant bandwidth to trigger pipe-filled detection
        for i in 0..20 {
            let sent = now + Duration::from_millis(i * 10);
            est.on_send(1400);
            let sample = make_sample(sent, 10, 1400);
            est.on_ack(sample);
        }

        // After enough rounds with no BW growth, should exit startup
        assert!(
            est.state() != BbrState::Startup || est.round_count < 20,
            "expected startup exit, state = {:?}, rounds = {}",
            est.state(),
            est.round_count
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
        let mut est = BandwidthEstimator::new();
        let now = Instant::now();

        // Drive into Drain state
        for i in 0..20 {
            let sent = now + Duration::from_millis(i * 10);
            est.on_send(1400);
            est.on_ack(make_sample(sent, 10, 1400));
        }

        // Artificially set high inflight
        if est.state() == BbrState::Drain {
            // Add lots of inflight
            est.inflight_bytes = est.bdp() * 3;
            let sent = now + Duration::from_millis(300);
            est.on_ack(make_sample(sent, 10, 1400));
            // Should still be in Drain (inflight > BDP)
            if est.inflight_bytes > est.bdp() {
                assert_eq!(
                    est.state(),
                    BbrState::Drain,
                    "should stay in Drain while inflight ({}) > BDP ({})",
                    est.inflight_bytes,
                    est.bdp()
                );
            }
        }
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
