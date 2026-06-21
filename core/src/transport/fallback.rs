//! Phantom Protocol - Fallback State Machine
//!
//! A degrade/heal state machine over three abstract transport "modes"
//! (`Turbo → Reliable → Stealth`): on repeated connection failures it walks one
//! step toward the most-robust mode, and probes back up to the best mode when the
//! path heals. The mode names predate the PhantomUDP rewrite — the concrete
//! KCP / TCP / FakeTLS legs they referred to are gone (PhantomUDP is now the only
//! production transport, with TCP/WebSocket/WASI/Embedded/MimicTls byte-pipes).
//!
//! **Vestigial.** The machine is still constructed inside `Session` (held behind
//! `#[allow(dead_code)]`) but no longer steers a live transport — the project does
//! single-path connection migration, not transport-mode switching. The logic and
//! tests are kept intact in case mode-switching is rewired against the current
//! transports; treat the `Turbo`/`Reliable`/`Stealth` names as opaque tiers, not
//! as the retired legs.

use crate::transport::scheduler::Scheduler;
use parking_lot::RwLock;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

/// Abstract transport-robustness tiers, most→least performant. The names are
/// historical (they once mapped to the retired KCP / TCP / FakeTLS legs) and are
/// now opaque ordering labels for the degrade/heal walk, not concrete transports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportMode {
    /// Most performant, least robust tier (the top of the fallback ladder).
    Turbo,
    /// Middle tier — trades some performance for robustness.
    Reliable,
    /// Most robust, most obfuscated tier (the bottom of the ladder; the machine
    /// degrades no further once here).
    Stealth,
}

/// Conditions that trigger a fallback
#[derive(Debug, Clone)]
pub struct FallbackTrigger {
    pub max_rtt: u32,
    pub max_loss: u8,
    pub failure_threshold: u32,
}

impl Default for FallbackTrigger {
    fn default() -> Self {
        Self {
            max_rtt: 500,
            max_loss: 10,
            failure_threshold: 3,
        }
    }
}

#[derive(Debug, Default)]
pub struct FallbackMetrics {
    pub packets_sent: AtomicU64,
    pub packets_acked: AtomicU64,
    pub connection_failures: AtomicU32,
    pub last_success_ms: AtomicU64,
}

impl FallbackMetrics {
    pub fn record_sent(&self) {
        self.packets_sent.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_success(&self) {
        self.packets_acked.fetch_add(1, Ordering::Relaxed);
        self.connection_failures.store(0, Ordering::Relaxed);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or_default();
        self.last_success_ms.store(now, Ordering::Relaxed);
    }

    pub fn record_failure(&self) {
        self.connection_failures.fetch_add(1, Ordering::Relaxed);
    }
}

/// Fallback state machine
pub struct FallbackStateMachine {
    /// Current transport mode
    current_mode: RwLock<TransportMode>,
    /// Trigger conditions
    trigger: FallbackTrigger,
    /// Metrics for decisions
    metrics: FallbackMetrics,
    /// Last mode change time
    last_change: RwLock<Instant>,
    /// Last probe attempt time
    last_probe: RwLock<Instant>,
    /// Best available mode to aim for
    best_mode: TransportMode,
    /// Optional scheduler the machine would push mode changes into. Always `None`
    /// today (the vestigial scheduler is not wired to mode switching) — kept as the
    /// seam for re-wiring mode-switching against a live transport.
    #[allow(dead_code)]
    scheduler: Option<Arc<Scheduler>>,
}

impl FallbackStateMachine {
    pub fn with_defaults() -> Self {
        Self::new(FallbackTrigger::default())
    }

    pub fn new(trigger: FallbackTrigger) -> Self {
        Self {
            current_mode: RwLock::new(TransportMode::Turbo),
            best_mode: TransportMode::Turbo,
            trigger,
            metrics: FallbackMetrics::default(),
            last_change: RwLock::new(Instant::now()),
            last_probe: RwLock::new(Instant::now()),
            scheduler: None,
        }
    }

    pub fn metrics(&self) -> &FallbackMetrics {
        &self.metrics
    }

    pub fn current_mode(&self) -> TransportMode {
        *self.current_mode.read()
    }

    pub fn check_and_fallback(&self) -> bool {
        let failures = self.metrics.connection_failures.load(Ordering::Relaxed);
        if failures >= self.trigger.failure_threshold {
            self.degrade();
            return true;
        }
        false
    }

    pub fn record_failure(&self) {
        self.metrics.record_failure();
        let _ = self.check_and_fallback();
    }

    fn degrade(&self) {
        let mut mode = self.current_mode.write();
        let new_mode = match *mode {
            TransportMode::Turbo => TransportMode::Reliable,
            TransportMode::Reliable => TransportMode::Stealth,
            TransportMode::Stealth => TransportMode::Stealth,
        };

        if new_mode != *mode {
            log::warn!("Transport degradation: {:?} -> {:?}", *mode, new_mode);
            *mode = new_mode;
            *self.last_change.write() = Instant::now();
        }
    }

    pub fn upgrade(&self) {
        let mut mode = self.current_mode.write();
        if *mode != self.best_mode {
            log::info!("Transport healing: {:?} -> {:?}", *mode, self.best_mode);
            *mode = self.best_mode;
            *self.last_change.write() = Instant::now();
            // Reset failures on upgrade
            self.metrics.connection_failures.store(0, Ordering::Relaxed);
        }
    }

    pub fn should_probe(&self) -> bool {
        let mode = self.current_mode.read();
        if *mode == self.best_mode {
            return false;
        }

        let last_probe = self.last_probe.read();
        let last_change = self.last_change.read();

        // Probe if it's been > 30s since last probe AND since last mode change
        last_probe.elapsed() > std::time::Duration::from_secs(30)
            && last_change.elapsed() > std::time::Duration::from_secs(30)
    }

    pub fn record_probe(&self) {
        *self.last_probe.write() = Instant::now();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fallback_cycle() {
        let fsm = FallbackStateMachine::with_defaults();
        assert_eq!(fsm.current_mode(), TransportMode::Turbo);

        // Degrade to Reliable
        fsm.degrade();
        assert_eq!(fsm.current_mode(), TransportMode::Reliable);

        // Degrade to Stealth
        fsm.degrade();
        assert_eq!(fsm.current_mode(), TransportMode::Stealth);

        // Upgrade back to Turbo
        fsm.upgrade();
        assert_eq!(fsm.current_mode(), TransportMode::Turbo);
    }

    #[test]
    fn test_should_probe() {
        let fsm = FallbackStateMachine::with_defaults();

        // No probe needed if already in best mode
        assert!(!fsm.should_probe());

        fsm.degrade();
        assert_eq!(fsm.current_mode(), TransportMode::Reliable);

        // No probe immediately after change
        assert!(!fsm.should_probe());

        // We can't easily fast-forward time in these tests without mocking Instant
        // But we can verify that after reset it's still false
        fsm.record_probe();
        assert!(!fsm.should_probe());
    }
}
