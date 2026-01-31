//! Phantom Transport - Multi-path Scheduler
//!
//! Intelligent path selection for multi-homing support.
//! Chooses optimal transport leg based on RTT, loss rate, and mode.

use crate::transport::legs::LegType;

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::RwLock;
use std::time::{Duration, Instant};

/// Scheduler mode determines path selection strategy
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchedulerMode {
    /// Minimize latency - send via fastest path, duplicate if needed
    LowLatency,
    /// Maximize throughput - distribute across all paths
    HighThroughput,
    /// Minimize detection - use only obfuscated transports
    Stealth,
    /// Maximum reliability - use only TCP-based transports
    Reliable,
}

/// Path information for scheduling decisions
#[derive(Debug, Clone)]
pub struct PathInfo {
    /// Transport leg type
    pub leg_type: LegType,
    /// Smoothed RTT in milliseconds
    pub rtt_ms: u32,
    /// RTT variance for timeout calculation
    pub rtt_var_ms: u32,
    /// Packet loss percentage (0-100)
    pub loss_percent: u8,
    /// Estimated bandwidth in bytes/second
    pub bandwidth_bps: u64,
    /// Whether path is currently available
    pub available: bool,
    /// Last time path was probed
    pub last_probe: Instant,
    /// Bytes sent through this path
    pub bytes_sent: u64,
    /// Bytes received through this path
    pub bytes_received: u64,
}

impl PathInfo {
    /// Create a new path with initial estimates
    pub fn new(leg_type: LegType) -> Self {
        Self {
            leg_type,
            rtt_ms: 100, // Initial guess
            rtt_var_ms: 50,
            loss_percent: 0,
            bandwidth_bps: 1_000_000, // 1 MB/s initial
            available: true,
            last_probe: Instant::now(),
            bytes_sent: 0,
            bytes_received: 0,
        }
    }

    /// Update RTT using exponential moving average
    pub fn update_rtt(&mut self, sample_ms: u32) {
        // RFC 6298 style RTT smoothing
        let diff = if sample_ms > self.rtt_ms {
            sample_ms - self.rtt_ms
        } else {
            self.rtt_ms - sample_ms
        };
        
        self.rtt_var_ms = (3 * self.rtt_var_ms + diff) / 4;
        self.rtt_ms = (7 * self.rtt_ms + sample_ms) / 8;
    }

    /// Calculate retransmission timeout
    pub fn rto_ms(&self) -> u32 {
        (self.rtt_ms + 4 * self.rtt_var_ms).max(200).min(10_000)
    }

    /// Score for path selection (lower is better)
    pub fn score(&self, mode: SchedulerMode) -> u32 {
        if !self.available {
            return u32::MAX;
        }

        match mode {
            SchedulerMode::LowLatency => {
                // Prioritize low RTT
                self.rtt_ms + (self.loss_percent as u32 * 10)
            }
            SchedulerMode::HighThroughput => {
                // Prioritize high bandwidth, tolerate some loss
                let bw_factor = (10_000_000 / self.bandwidth_bps.max(1)) as u32;
                bw_factor + (self.loss_percent as u32 * 5)
            }
            SchedulerMode::Stealth => {
                // Only consider obfuscated, then by RTT
                if self.leg_type.is_obfuscated() {
                    self.rtt_ms
                } else {
                    u32::MAX - 1 // Non-obfuscated is last resort
                }
            }
            SchedulerMode::Reliable => {
                // Prefer TCP-based for reliability
                match self.leg_type {
                    LegType::Tcp | LegType::FakeTls => self.rtt_ms,
                    LegType::Kcp => self.rtt_ms + 100, // Slight penalty
                }
            }
        }
    }
}

/// Multi-path scheduler
pub struct Scheduler {
    /// Current scheduling mode
    mode: RwLock<SchedulerMode>,
    /// Path information per leg type
    paths: RwLock<HashMap<LegType, PathInfo>>,
    /// Round-robin counter for high-throughput mode
    rr_counter: AtomicU32,
    /// Total bytes scheduled
    total_bytes: AtomicU64,
}

impl Scheduler {
    /// Create a new scheduler
    pub fn new(mode: SchedulerMode) -> Self {
        let mut paths = HashMap::new();
        paths.insert(LegType::Kcp, PathInfo::new(LegType::Kcp));
        paths.insert(LegType::Tcp, PathInfo::new(LegType::Tcp));
        
        Self {
            mode: RwLock::new(mode),
            paths: RwLock::new(paths),
            rr_counter: AtomicU32::new(0),
            total_bytes: AtomicU64::new(0),
        }
    }

    /// Get current mode
    pub fn mode(&self) -> SchedulerMode {
        *self.mode.read().unwrap()
    }

    /// Set scheduling mode
    pub fn set_mode(&self, mode: SchedulerMode) {
        *self.mode.write().unwrap() = mode;
    }

    /// Select optimal path(s) for sending
    /// 
    /// Returns ordered list of leg types to try.
    pub fn select_paths(&self, is_priority: bool) -> Vec<LegType> {
        let mode = *self.mode.read().unwrap();
        let paths = self.paths.read().unwrap();
        
        // Get available paths sorted by score
        let mut available: Vec<_> = paths.iter()
            .filter(|(_, info)| info.available)
            .collect();
        
        available.sort_by_key(|(_, info)| info.score(mode));
        
        match mode {
            SchedulerMode::LowLatency => {
                if is_priority && available.len() >= 2 {
                    // Duplicate priority packets across two best paths
                    available.iter().take(2).map(|(lt, _)| **lt).collect()
                } else {
                    // Single best path
                    available.iter().take(1).map(|(lt, _)| **lt).collect()
                }
            }
            SchedulerMode::HighThroughput => {
                // Round-robin across all available paths
                if available.is_empty() {
                    return Vec::new();
                }
                let idx = self.rr_counter.fetch_add(1, Ordering::Relaxed) as usize;
                vec![*available[idx % available.len()].0]
            }
            SchedulerMode::Stealth => {
                // Only obfuscated paths
                available.iter()
                    .filter(|(lt, _)| lt.is_obfuscated())
                    .map(|(lt, _)| **lt)
                    .take(1)
                    .collect()
            }
            SchedulerMode::Reliable => {
                // Prefer TCP-based
                available.iter()
                    .map(|(lt, _)| **lt)
                    .take(1)
                    .collect()
            }
        }
    }

    /// Register a new path
    pub fn register_path(&self, leg_type: LegType) {
        self.paths.write().unwrap()
            .entry(leg_type)
            .or_insert_with(|| PathInfo::new(leg_type));
    }

    /// Update path RTT
    pub fn update_rtt(&self, leg_type: LegType, sample_ms: u32) {
        if let Some(path) = self.paths.write().unwrap().get_mut(&leg_type) {
            path.update_rtt(sample_ms);
        }
    }

    /// Update path availability
    pub fn set_path_available(&self, leg_type: LegType, available: bool) {
        if let Some(path) = self.paths.write().unwrap().get_mut(&leg_type) {
            path.available = available;
        }
    }

    /// Update loss percentage
    pub fn update_loss(&self, leg_type: LegType, loss_percent: u8) {
        if let Some(path) = self.paths.write().unwrap().get_mut(&leg_type) {
            path.loss_percent = loss_percent;
        }
    }

    /// Record bytes sent
    pub fn record_sent(&self, leg_type: LegType, bytes: u64) {
        self.total_bytes.fetch_add(bytes, Ordering::Relaxed);
        if let Some(path) = self.paths.write().unwrap().get_mut(&leg_type) {
            path.bytes_sent += bytes;
        }
    }

    /// Get path info (for metrics/debugging)
    pub fn get_path_info(&self, leg_type: LegType) -> Option<PathInfo> {
        self.paths.read().unwrap().get(&leg_type).cloned()
    }

    /// Get all available paths
    pub fn available_paths(&self) -> Vec<LegType> {
        self.paths.read().unwrap()
            .iter()
            .filter(|(_, info)| info.available)
            .map(|(lt, _)| *lt)
            .collect()
    }

    /// Check if any path is available
    pub fn has_available_path(&self) -> bool {
        self.paths.read().unwrap()
            .values()
            .any(|info| info.available)
    }
}

impl std::fmt::Debug for Scheduler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Scheduler")
            .field("mode", &self.mode())
            .field("paths", &self.available_paths())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_path_rtt_update() {
        let mut path = PathInfo::new(LegType::Kcp);
        path.rtt_ms = 100;
        path.rtt_var_ms = 10;
        
        path.update_rtt(80);
        assert!(path.rtt_ms < 100); // Should decrease
        
        path.update_rtt(150);
        assert!(path.rtt_ms < 150 && path.rtt_ms > 80); // Moving average
    }

    #[test]
    fn test_scheduler_select_paths() {
        let scheduler = Scheduler::new(SchedulerMode::LowLatency);
        
        // Set up paths with different RTTs
        scheduler.update_rtt(LegType::Kcp, 50);
        scheduler.update_rtt(LegType::Tcp, 100);
        
        let paths = scheduler.select_paths(false);
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0], LegType::Kcp); // Lower RTT
    }

    #[test]
    fn test_scheduler_priority_duplicate() {
        let scheduler = Scheduler::new(SchedulerMode::LowLatency);
        
        let paths = scheduler.select_paths(true);
        // Should return 2 paths for priority packets
        assert_eq!(paths.len(), 2);
    }

    #[test]
    fn test_scheduler_stealth_mode() {
        let scheduler = Scheduler::new(SchedulerMode::Stealth);
        scheduler.register_path(LegType::FakeTls);
        
        let paths = scheduler.select_paths(false);
        // Should only return obfuscated paths
        assert!(paths.iter().all(|lt| lt.is_obfuscated()));
    }
}
