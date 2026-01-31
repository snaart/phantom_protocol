//! Phantom Transport - Fallback State Machine
//!
//! Automatic transport mode degradation:
//! Turbo (KCP) → Reliable (TCP) → Stealth (FakeTLS)

use crate::transport::legs::LegType;
use crate::transport::scheduler::{Scheduler, SchedulerMode};

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Transport mode (fallback levels)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TransportMode {
    /// KCP over UDP - fastest, primary transport
    Turbo = 0,
    /// Pure TCP - reliable fallback
    Reliable = 1,
    /// FakeTLS over TCP - obfuscated for DPI bypass
    Stealth = 2,
}

impl TransportMode {
    /// Get corresponding scheduler mode
    pub fn scheduler_mode(&self) -> SchedulerMode {
        match self {
            TransportMode::Turbo => SchedulerMode::LowLatency,
            TransportMode::Reliable => SchedulerMode::Reliable,
            TransportMode::Stealth => SchedulerMode::Stealth,
        }
    }

    /// Get preferred leg type for this mode
    pub fn preferred_leg(&self) -> LegType {
        match self {
            TransportMode::Turbo => LegType::Kcp,
            TransportMode::Reliable => LegType::Tcp,
            TransportMode::Stealth => LegType::FakeTls,
        }
    }

    /// Next fallback level
    pub fn fallback(&self) -> Option<TransportMode> {
        match self {
            TransportMode::Turbo => Some(TransportMode::Reliable),
            TransportMode::Reliable => Some(TransportMode::Stealth),
            TransportMode::Stealth => None, // No further fallback in MVP
        }
    }

    /// Previous (upgrade) level
    pub fn upgrade(&self) -> Option<TransportMode> {
        match self {
            TransportMode::Turbo => None,
            TransportMode::Reliable => Some(TransportMode::Turbo),
            TransportMode::Stealth => Some(TransportMode::Reliable),
        }
    }
}

/// Trigger conditions for fallback
#[derive(Debug, Clone, Copy)]
pub struct FallbackTrigger {
    /// Packet loss threshold to trigger fallback (0-100)
    pub loss_threshold_percent: u8,
    /// Connection failures before fallback
    pub failure_count_threshold: u32,
    /// Timeout for connection attempts (milliseconds)
    pub connect_timeout_ms: u64,
    /// Time to wait before trying to upgrade (seconds)
    pub upgrade_delay_secs: u64,
}

impl Default for FallbackTrigger {
    fn default() -> Self {
        Self {
            loss_threshold_percent: 15,
            failure_count_threshold: 3,
            connect_timeout_ms: 5000,
            upgrade_delay_secs: 60,
        }
    }
}

/// Metrics for fallback decisions
#[derive(Debug, Default)]
pub struct FallbackMetrics {
    /// Consecutive connection failures
    pub connection_failures: AtomicU32,
    /// Packets sent
    pub packets_sent: AtomicU64,
    /// Packets acknowledged
    pub packets_acked: AtomicU64,
    /// Last successful send timestamp (unix millis)
    pub last_success_ms: AtomicU64,
    /// DPI detection suspected
    pub dpi_detected: std::sync::atomic::AtomicBool,
}

impl FallbackMetrics {
    /// Calculate current loss percentage
    pub fn loss_percent(&self) -> u8 {
        let sent = self.packets_sent.load(Ordering::Relaxed);
        let acked = self.packets_acked.load(Ordering::Relaxed);
        
        if sent == 0 {
            return 0;
        }
        
        let lost = sent.saturating_sub(acked);
        ((lost * 100) / sent).min(100) as u8
    }

    /// Reset metrics (after mode change)
    pub fn reset(&self) {
        self.connection_failures.store(0, Ordering::Relaxed);
        self.packets_sent.store(0, Ordering::Relaxed);
        self.packets_acked.store(0, Ordering::Relaxed);
    }

    /// Record a successful packet
    pub fn record_success(&self) {
        self.packets_acked.fetch_add(1, Ordering::Relaxed);
        self.connection_failures.store(0, Ordering::Relaxed);
        self.last_success_ms.store(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            Ordering::Relaxed,
        );
    }

    /// Record a sent packet
    pub fn record_sent(&self) {
        self.packets_sent.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a connection failure
    pub fn record_failure(&self) {
        self.connection_failures.fetch_add(1, Ordering::Relaxed);
    }

    /// Record DPI detection
    pub fn record_dpi_detection(&self) {
        self.dpi_detected.store(true, std::sync::atomic::Ordering::Relaxed);
    }
}

/// Fallback state machine
pub struct FallbackStateMachine {
    /// Current transport mode
    current_mode: std::sync::RwLock<TransportMode>,
    /// Trigger conditions
    trigger: FallbackTrigger,
    /// Metrics for decisions
    metrics: FallbackMetrics,
    /// Last mode change time
    last_change: std::sync::RwLock<Instant>,
    /// Reference to scheduler (to update mode)
    scheduler: Option<Arc<Scheduler>>,
}

impl FallbackStateMachine {
    /// Create a new fallback state machine
    pub fn new(trigger: FallbackTrigger) -> Self {
        Self {
            current_mode: std::sync::RwLock::new(TransportMode::Turbo),
            trigger,
            metrics: FallbackMetrics::default(),
            last_change: std::sync::RwLock::new(Instant::now()),
            scheduler: None,
        }
    }

    /// Create with default triggers
    pub fn with_defaults() -> Self {
        Self::new(FallbackTrigger::default())
    }

    /// Attach a scheduler to update its mode
    pub fn attach_scheduler(&mut self, scheduler: Arc<Scheduler>) {
        self.scheduler = Some(scheduler);
    }

    /// Get current mode
    pub fn current_mode(&self) -> TransportMode {
        *self.current_mode.read().unwrap()
    }

    /// Get metrics
    pub fn metrics(&self) -> &FallbackMetrics {
        &self.metrics
    }

    /// Check and potentially trigger fallback
    /// 
    /// Returns true if mode changed.
    pub fn check_and_fallback(&self) -> bool {
        let loss = self.metrics.loss_percent();
        let failures = self.metrics.connection_failures.load(Ordering::Relaxed);
        let dpi = self.metrics.dpi_detected.load(std::sync::atomic::Ordering::Relaxed);

        let should_fallback = 
            loss > self.trigger.loss_threshold_percent ||
            failures >= self.trigger.failure_count_threshold ||
            dpi;

        if should_fallback {
            return self.fallback();
        }

        false
    }

    /// Force fallback to next level
    pub fn fallback(&self) -> bool {
        let current = *self.current_mode.read().unwrap();
        
        if let Some(next) = current.fallback() {
            *self.current_mode.write().unwrap() = next;
            *self.last_change.write().unwrap() = Instant::now();
            self.metrics.reset();
            
            // Update scheduler if attached
            if let Some(ref scheduler) = self.scheduler {
                scheduler.set_mode(next.scheduler_mode());
            }
            
            log::info!("Fallback: {:?} → {:?}", current, next);
            return true;
        }
        
        false
    }

    /// Try to upgrade to faster mode
    /// 
    /// Returns true if mode changed.
    pub fn try_upgrade(&self) -> bool {
        let current = *self.current_mode.read().unwrap();
        let last_change = *self.last_change.read().unwrap();
        
        // Don't upgrade too quickly
        if last_change.elapsed() < Duration::from_secs(self.trigger.upgrade_delay_secs) {
            return false;
        }
        
        // Only upgrade if metrics are good
        if self.metrics.loss_percent() > 5 ||
           self.metrics.connection_failures.load(Ordering::Relaxed) > 0 {
            return false;
        }
        
        if let Some(prev) = current.upgrade() {
            *self.current_mode.write().unwrap() = prev;
            *self.last_change.write().unwrap() = Instant::now();
            self.metrics.reset();
            
            // Update scheduler if attached
            if let Some(ref scheduler) = self.scheduler {
                scheduler.set_mode(prev.scheduler_mode());
            }
            
            log::info!("Upgrade: {:?} → {:?}", current, prev);
            return true;
        }
        
        false
    }

    /// Force set mode (for testing or manual override)
    pub fn set_mode(&self, mode: TransportMode) {
        *self.current_mode.write().unwrap() = mode;
        *self.last_change.write().unwrap() = Instant::now();
        self.metrics.reset();
        
        if let Some(ref scheduler) = self.scheduler {
            scheduler.set_mode(mode.scheduler_mode());
        }
    }
}

impl std::fmt::Debug for FallbackStateMachine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FallbackStateMachine")
            .field("mode", &self.current_mode())
            .field("loss%", &self.metrics.loss_percent())
            .field("failures", &self.metrics.connection_failures.load(Ordering::Relaxed))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transport_mode_fallback() {
        assert_eq!(TransportMode::Turbo.fallback(), Some(TransportMode::Reliable));
        assert_eq!(TransportMode::Reliable.fallback(), Some(TransportMode::Stealth));
        assert_eq!(TransportMode::Stealth.fallback(), None);
    }

    #[test]
    fn test_transport_mode_upgrade() {
        assert_eq!(TransportMode::Stealth.upgrade(), Some(TransportMode::Reliable));
        assert_eq!(TransportMode::Reliable.upgrade(), Some(TransportMode::Turbo));
        assert_eq!(TransportMode::Turbo.upgrade(), None);
    }

    #[test]
    fn test_fallback_on_loss() {
        let fsm = FallbackStateMachine::with_defaults();
        
        // Simulate high loss
        for _ in 0..100 {
            fsm.metrics.record_sent();
        }
        for _ in 0..80 {
            fsm.metrics.record_success();
        }
        // 20% loss
        
        assert_eq!(fsm.current_mode(), TransportMode::Turbo);
        assert!(fsm.check_and_fallback());
        assert_eq!(fsm.current_mode(), TransportMode::Reliable);
    }

    #[test]
    fn test_fallback_on_failures() {
        let fsm = FallbackStateMachine::with_defaults();
        
        // Simulate connection failures
        fsm.metrics.record_failure();
        fsm.metrics.record_failure();
        fsm.metrics.record_failure();
        
        assert!(fsm.check_and_fallback());
        assert_eq!(fsm.current_mode(), TransportMode::Reliable);
    }

    #[test]
    fn test_dpi_fallback() {
        let fsm = FallbackStateMachine::with_defaults();
        
        fsm.metrics.record_dpi_detection();
        
        assert!(fsm.check_and_fallback());
        // Should skip to stealth on DPI
        fsm.check_and_fallback();
        assert_eq!(fsm.current_mode(), TransportMode::Stealth);
    }
}
