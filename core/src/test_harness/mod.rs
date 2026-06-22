//! Test Harness — Network Condition Simulator
//!
//! Provides tools for testing Phantom Protocol transport under various network conditions:
//! - Enable/disable the UDP and TCP transports (`set_udp_enabled` / `set_tcp_enabled`)
//! - Add artificial latency, with optional jitter (`latency + uniform[0, jitter]`)
//! - Simulate packet loss
//! - Throttle to a bandwidth limit (`bandwidth_delay` / `apply_bandwidth`)
//! - Trigger IP address changes (a counter the migration tests observe)
//!
//! `NetworkSimulator` only models conditions and computes delays/drop decisions;
//! the simulated values are atomics behind a shared `Arc`, so a single simulator
//! can be cloned into both ends of a test. The companion [`fault_transport`]
//! module is the per-frame, fault-injecting `SessionTransport` wrapper that the
//! loss-recovery tests actually drive.

use rand::Rng;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Fault-injecting `SessionTransport` wrapper (drops/…) used by loss-recovery tests.
pub mod fault_transport;

/// Network condition simulator for testing
#[derive(Clone)]
pub struct NetworkSimulator {
    inner: Arc<NetworkSimulatorInner>,
}

struct NetworkSimulatorInner {
    /// UDP transport enabled
    udp_enabled: AtomicBool,
    /// TCP transport enabled
    tcp_enabled: AtomicBool,
    /// Additional latency in milliseconds
    latency_ms: AtomicU32,
    /// Latency jitter in milliseconds — each packet's effective latency is
    /// `latency + uniform[0, jitter]` (0 = no jitter).
    jitter_ms: AtomicU32,
    /// Packet loss percentage (0-100)
    packet_loss_percent: AtomicU32,
    /// Bandwidth limit in bytes/second (0 = unlimited)
    bandwidth_limit: AtomicU32,
    /// IP change counter (incremented on each simulated change)
    ip_change_counter: AtomicU32,
}

impl NetworkSimulator {
    /// Create a new network simulator with default settings
    pub fn new() -> Self {
        Self {
            inner: Arc::new(NetworkSimulatorInner {
                udp_enabled: AtomicBool::new(true),
                tcp_enabled: AtomicBool::new(true),
                latency_ms: AtomicU32::new(0),
                jitter_ms: AtomicU32::new(0),
                packet_loss_percent: AtomicU32::new(0),
                bandwidth_limit: AtomicU32::new(0),
                ip_change_counter: AtomicU32::new(0),
            }),
        }
    }

    // === UDP Control ===

    /// Check if UDP is enabled
    pub fn is_udp_enabled(&self) -> bool {
        self.inner.udp_enabled.load(Ordering::SeqCst)
    }

    /// Enable or disable UDP transport
    pub fn set_udp_enabled(&self, enabled: bool) {
        self.inner.udp_enabled.store(enabled, Ordering::SeqCst);
        log::info!(
            "NetworkSimulator: UDP {}",
            if enabled { "enabled" } else { "disabled" }
        );
    }

    /// Disable UDP to force TCP fallback
    pub fn disable_udp(&self) {
        self.set_udp_enabled(false);
    }

    /// Re-enable UDP
    pub fn enable_udp(&self) {
        self.set_udp_enabled(true);
    }

    // === TCP Control ===

    /// Check if TCP is enabled
    pub fn is_tcp_enabled(&self) -> bool {
        self.inner.tcp_enabled.load(Ordering::SeqCst)
    }

    /// Enable or disable TCP transport
    pub fn set_tcp_enabled(&self, enabled: bool) {
        self.inner.tcp_enabled.store(enabled, Ordering::SeqCst);
        log::info!(
            "NetworkSimulator: TCP {}",
            if enabled { "enabled" } else { "disabled" }
        );
    }

    // === Latency Simulation ===

    /// Get current simulated latency
    pub fn latency(&self) -> Duration {
        Duration::from_millis(self.inner.latency_ms.load(Ordering::SeqCst) as u64)
    }

    /// Set simulated latency
    pub fn set_latency(&self, latency: Duration) {
        let ms = latency.as_millis().min(u32::MAX as u128) as u32;
        self.inner.latency_ms.store(ms, Ordering::SeqCst);
        log::info!("NetworkSimulator: latency set to {}ms", ms);
    }

    /// Get the current latency jitter.
    pub fn jitter(&self) -> Duration {
        Duration::from_millis(self.inner.jitter_ms.load(Ordering::SeqCst) as u64)
    }

    /// Set the latency jitter: each packet's effective latency is `latency +
    /// uniform[0, jitter]` (`Duration::ZERO` disables jitter, making the latency
    /// deterministic).
    pub fn set_jitter(&self, jitter: Duration) {
        let ms = jitter.as_millis().min(u32::MAX as u128) as u32;
        self.inner.jitter_ms.store(ms, Ordering::SeqCst);
        log::info!("NetworkSimulator: jitter set to {}ms", ms);
    }

    /// The effective per-packet latency = `latency + uniform[0, jitter]`. Sampled
    /// fresh on every call; equals exactly `latency()` when jitter is zero.
    pub fn effective_latency(&self) -> Duration {
        let base = self.latency();
        let jitter_ms = self.inner.jitter_ms.load(Ordering::SeqCst);
        if jitter_ms == 0 {
            return base;
        }
        let extra = rand::rngs::OsRng.gen_range(0..=jitter_ms);
        base + Duration::from_millis(extra as u64)
    }

    /// Apply the simulated latency (async delay), including jitter.
    pub async fn apply_latency(&self) {
        let latency = self.effective_latency();
        if !latency.is_zero() {
            tokio::time::sleep(latency).await;
        }
    }

    // === Packet Loss Simulation ===

    /// Get packet loss percentage
    pub fn packet_loss_percent(&self) -> u32 {
        self.inner.packet_loss_percent.load(Ordering::SeqCst)
    }

    /// Set packet loss percentage (0-100)
    pub fn set_packet_loss(&self, percent: u32) {
        let percent = percent.min(100);
        self.inner
            .packet_loss_percent
            .store(percent, Ordering::SeqCst);
        log::info!("NetworkSimulator: packet loss set to {}%", percent);
    }

    /// Check if a packet should be dropped (based on loss percentage)
    pub fn should_drop_packet(&self) -> bool {
        let loss = self.packet_loss_percent();
        if loss == 0 {
            return false;
        }
        if loss >= 100 {
            return true;
        }
        rand::rngs::OsRng.gen::<u32>() % 100 < loss
    }

    // === Bandwidth Limit ===

    /// Get bandwidth limit in bytes/second (0 = unlimited)
    pub fn bandwidth_limit(&self) -> u32 {
        self.inner.bandwidth_limit.load(Ordering::SeqCst)
    }

    /// Set bandwidth limit in bytes/second (0 = unlimited)
    pub fn set_bandwidth_limit(&self, bytes_per_sec: u32) {
        self.inner
            .bandwidth_limit
            .store(bytes_per_sec, Ordering::SeqCst);
        log::info!(
            "NetworkSimulator: bandwidth limit set to {} B/s",
            bytes_per_sec
        );
    }

    /// The transmission delay a `bytes`-sized packet incurs under the current
    /// bandwidth limit: `bytes / limit` seconds. `Duration::ZERO` when the limit is
    /// 0 (unlimited). Computed in microseconds for precision.
    pub fn bandwidth_delay(&self, bytes: usize) -> Duration {
        let limit = self.bandwidth_limit();
        if limit == 0 || bytes == 0 {
            return Duration::ZERO;
        }
        let micros = (bytes as u64).saturating_mul(1_000_000) / limit as u64;
        Duration::from_micros(micros)
    }

    /// Throttle to the bandwidth limit by awaiting [`bandwidth_delay`](Self::bandwidth_delay)
    /// for a `bytes`-sized packet (no-op when unlimited).
    pub async fn apply_bandwidth(&self, bytes: usize) {
        let delay = self.bandwidth_delay(bytes);
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
    }

    // === IP Change Simulation ===

    /// Get the current IP change counter
    pub fn ip_change_counter(&self) -> u32 {
        self.inner.ip_change_counter.load(Ordering::SeqCst)
    }

    /// Trigger an IP address change
    pub fn trigger_ip_change(&self) {
        let old = self.inner.ip_change_counter.fetch_add(1, Ordering::SeqCst);
        log::info!(
            "NetworkSimulator: IP change triggered (counter: {} -> {})",
            old,
            old + 1
        );
    }

    // === Presets ===

    /// Apply "high latency" preset (200ms, 5% loss)
    pub fn preset_high_latency(&self) {
        self.set_latency(Duration::from_millis(200));
        self.set_packet_loss(5);
    }

    /// Apply "lossy network" preset (50ms, 20% loss)
    pub fn preset_lossy(&self) {
        self.set_latency(Duration::from_millis(50));
        self.set_packet_loss(20);
    }

    /// Apply "mobile roaming" preset: 100 ms latency with 30 ms jitter, 2% loss, a
    /// ~1 MB/s bandwidth cap (cellular-ish), and an IP change on each call.
    pub fn preset_mobile_roaming(&self) {
        self.set_latency(Duration::from_millis(100));
        self.set_jitter(Duration::from_millis(30));
        self.set_packet_loss(2);
        self.set_bandwidth_limit(1_000_000);
        self.trigger_ip_change();
    }

    /// Reset to default settings
    pub fn reset(&self) {
        self.set_udp_enabled(true);
        self.set_tcp_enabled(true);
        self.set_latency(Duration::ZERO);
        self.set_jitter(Duration::ZERO);
        self.set_packet_loss(0);
        self.set_bandwidth_limit(0);
    }
}

impl Default for NetworkSimulator {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for NetworkSimulator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NetworkSimulator")
            .field("udp_enabled", &self.is_udp_enabled())
            .field("tcp_enabled", &self.is_tcp_enabled())
            .field("latency_ms", &self.latency().as_millis())
            .field("jitter_ms", &self.jitter().as_millis())
            .field("packet_loss_percent", &self.packet_loss_percent())
            .field("bandwidth_limit", &self.bandwidth_limit())
            .field("ip_changes", &self.ip_change_counter())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_simulator_basics() {
        let sim = NetworkSimulator::new();

        // Default state
        assert!(sim.is_udp_enabled());
        assert!(sim.is_tcp_enabled());
        assert_eq!(sim.latency(), Duration::ZERO);
        assert_eq!(sim.packet_loss_percent(), 0);

        // Disable UDP
        sim.disable_udp();
        assert!(!sim.is_udp_enabled());

        // Set latency
        sim.set_latency(Duration::from_millis(100));
        assert_eq!(sim.latency(), Duration::from_millis(100));

        // Set packet loss
        sim.set_packet_loss(10);
        assert_eq!(sim.packet_loss_percent(), 10);

        // Trigger IP change
        let c1 = sim.ip_change_counter();
        sim.trigger_ip_change();
        assert_eq!(sim.ip_change_counter(), c1 + 1);

        // Reset
        sim.reset();
        assert!(sim.is_udp_enabled());
        assert_eq!(sim.latency(), Duration::ZERO);
    }

    #[test]
    fn test_presets() {
        let sim = NetworkSimulator::new();

        sim.preset_high_latency();
        assert_eq!(sim.latency(), Duration::from_millis(200));
        assert_eq!(sim.packet_loss_percent(), 5);

        sim.preset_lossy();
        assert_eq!(sim.latency(), Duration::from_millis(50));
        assert_eq!(sim.packet_loss_percent(), 20);
    }

    #[test]
    fn test_packet_drop_decision() {
        let sim = NetworkSimulator::new();

        // 0% loss = never drop
        sim.set_packet_loss(0);
        for _ in 0..100 {
            assert!(!sim.should_drop_packet());
        }

        // 100% loss = always drop
        sim.set_packet_loss(100);
        for _ in 0..100 {
            assert!(sim.should_drop_packet());
        }
    }

    /// B5 — jitter varies the effective latency within `[latency, latency + jitter]`,
    /// and `jitter == 0` makes it exactly the base latency (deterministic).
    #[test]
    fn jitter_bounds_effective_latency() {
        let sim = NetworkSimulator::new();
        sim.set_latency(Duration::from_millis(100));
        sim.set_jitter(Duration::from_millis(20));
        assert_eq!(sim.jitter(), Duration::from_millis(20));

        let base = Duration::from_millis(100);
        let cap = Duration::from_millis(120);
        let mut saw_above = false;
        for _ in 0..1000 {
            let eff = sim.effective_latency();
            assert!(eff >= base, "effective latency {eff:?} must be >= base");
            assert!(
                eff <= cap,
                "effective latency {eff:?} must be <= base + jitter"
            );
            if eff > base {
                saw_above = true;
            }
        }
        assert!(
            saw_above,
            "jitter must actually vary the latency above the base"
        );

        // No jitter → exactly the base latency.
        sim.set_jitter(Duration::ZERO);
        for _ in 0..50 {
            assert_eq!(sim.effective_latency(), base);
        }
    }

    /// B5 — `bandwidth_delay(bytes)` is the time to transmit `bytes` at the limit
    /// (0 = unlimited → no delay).
    #[test]
    fn bandwidth_delay_throttles_to_the_limit() {
        let sim = NetworkSimulator::new();
        // Unlimited.
        assert_eq!(sim.bandwidth_delay(10_000), Duration::ZERO);
        // 1000 B/s: 1000 B = 1 s, 500 B = 500 ms, 0 B = 0.
        sim.set_bandwidth_limit(1000);
        assert_eq!(sim.bandwidth_delay(1000), Duration::from_secs(1));
        assert_eq!(sim.bandwidth_delay(500), Duration::from_millis(500));
        assert_eq!(sim.bandwidth_delay(0), Duration::ZERO);
    }

    /// B5 — the mobile-roaming preset now also exercises jitter + a bandwidth cap
    /// (real cellular characteristics), and `reset` clears them.
    #[test]
    fn mobile_roaming_preset_sets_jitter_and_bandwidth_and_reset_clears() {
        let sim = NetworkSimulator::new();
        sim.preset_mobile_roaming();
        assert!(sim.jitter() > Duration::ZERO, "mobile roaming adds jitter");
        assert!(sim.bandwidth_limit() > 0, "mobile roaming caps bandwidth");

        sim.reset();
        assert_eq!(sim.jitter(), Duration::ZERO);
        assert_eq!(sim.bandwidth_limit(), 0);
    }
}
