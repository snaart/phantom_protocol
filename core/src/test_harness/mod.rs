//! Test Harness — Network Condition Simulator
//!
//! Provides tools for testing Phantom transport under various network conditions:
//! - Enable/disable UDP transport
//! - Add artificial latency
//! - Simulate packet loss
//! - Trigger IP address changes

use rand::Rng;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

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

    /// Apply simulated latency (async delay)
    pub async fn apply_latency(&self) {
        let latency = self.latency();
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

    /// Apply "mobile roaming" preset (triggers IP change every call)
    pub fn preset_mobile_roaming(&self) {
        self.set_latency(Duration::from_millis(100));
        self.set_packet_loss(2);
        self.trigger_ip_change();
    }

    /// Reset to default settings
    pub fn reset(&self) {
        self.set_udp_enabled(true);
        self.set_tcp_enabled(true);
        self.set_latency(Duration::ZERO);
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
}
