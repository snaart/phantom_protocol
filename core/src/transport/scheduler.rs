//! Phantom Transport - Multi-Path Scheduler
//!
//! Round-robin and low-latency scheduling across multiple transport legs.

use crate::transport::types::{LegType, SchedulerMode};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

pub struct PathInfo {
    pub leg_type: LegType,
    pub rtt_ms: u32,
    pub loss_percent: u8,
    pub active: bool,
    pub bytes_sent: u64,
}

impl PathInfo {
    pub fn new(leg_type: LegType) -> Self {
        Self {
            leg_type,
            rtt_ms: 150, // Default estimate
            loss_percent: 0,
            active: true,
            bytes_sent: 0,
        }
    }
}

pub struct Scheduler {
    mode: RwLock<SchedulerMode>,
    paths: RwLock<HashMap<LegType, PathInfo>>,
    #[allow(dead_code)]
    rr_counter: AtomicU32,
    total_bytes: AtomicU64,
}

impl Scheduler {
    pub fn new(mode: SchedulerMode) -> Self {
        Self {
            mode: RwLock::new(mode),
            paths: RwLock::new(HashMap::new()),
            rr_counter: AtomicU32::new(0),
            total_bytes: AtomicU64::new(0),
        }
    }

    pub fn register_path(&self, leg_type: LegType) {
        let mut paths = self.paths.write();
        paths
            .entry(leg_type)
            .or_insert_with(|| PathInfo::new(leg_type));
    }

    pub fn set_path_available(&self, leg_type: LegType, available: bool) {
        let mut paths = self.paths.write();
        if let Some(path) = paths.get_mut(&leg_type) {
            path.active = available;
        }
    }

    pub fn select_paths(&self, is_priority: bool) -> Vec<LegType> {
        let paths = self.paths.read();
        let mode = self.mode.read();

        let mut available: Vec<_> = paths.iter().filter(|(_, p)| p.active).collect();

        if available.is_empty() {
            return Vec::new();
        }

        if is_priority {
            // Pick the single best path (lowest RTT)
            available.sort_by_key(|(_, p)| p.rtt_ms);
            return vec![*available[0].0];
        }

        match *mode {
            SchedulerMode::LowLatency => {
                available.sort_by_key(|(_, p)| p.rtt_ms);
                vec![*available[0].0]
            }
            SchedulerMode::HighThroughput => {
                // Return all active paths for multi-path bonding
                available.iter().map(|(t, _)| **t).collect()
            }
            SchedulerMode::Reliability | SchedulerMode::Stealth => {
                // Duplicate across all paths? No, just pick two best
                available.sort_by_key(|(_, p)| p.rtt_ms);
                available.iter().take(2).map(|(t, _)| **t).collect()
            }
        }
    }

    pub fn update_rtt(&self, leg_type: LegType, rtt: u32) {
        let mut paths = self.paths.write();
        if let Some(path) = paths.get_mut(&leg_type) {
            path.rtt_ms = rtt;
        }
    }

    pub fn record_sent(&self, leg_type: LegType, bytes: u64) {
        let mut paths = self.paths.write();
        if let Some(path) = paths.get_mut(&leg_type) {
            path.bytes_sent += bytes;
        }
        self.total_bytes.fetch_add(bytes, Ordering::Relaxed);
    }
}
