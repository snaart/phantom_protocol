//! Multi-path selection table — **not connected to the data path.**
//!
//! A [`Scheduler`] is constructed inside every `Session` and reachable through
//! `Session::scheduler()`, but [`select_paths`] is called by nothing that steers
//! production traffic, so no packet has ever left this crate on a path this table
//! chose. The per-path RTT and loss figures it would rank are populated nowhere
//! either; the live equivalents live in `transport::path::PathState` and the BBR
//! `BandwidthEstimator`, and those are what the sender actually reads.
//!
//! Connecting it is not a cleanup and probably not wanted at all: the design it
//! serves — bonding several paths at once — was evaluated and rejected in favour of
//! single-path connection migration, which moves one active path and does not
//! aggregate. The `HighThroughput` branch below spells out that rejected
//! aggregation and has never run against a socket. The table is kept as the seam a
//! future multi-path selector would occupy, and `SchedulerMode` outlives it for an
//! unrelated reason: it is a required argument of `Session::from_derived` and so is
//! genuinely live.
//!
//! [`select_paths`]: Scheduler::select_paths

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
