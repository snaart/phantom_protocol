use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const WINDOW_SECS: u64 = 60;
const BASE_DIFFICULTY: u8 = 8;
const MAX_DIFFICULTY: u8 = 20;

struct ReputationEntry {
    violations: AtomicU32,
    last_seen_secs: AtomicU64,
}

impl ReputationEntry {
    fn new(now: u64) -> Self {
        Self {
            violations: AtomicU32::new(1),
            last_seen_secs: AtomicU64::new(now),
        }
    }
}

/// Tracks IP reputation and calculates dynamic PoW difficulty
pub struct ReputationTracker {
    entries: DashMap<IpAddr, ReputationEntry>,
}

impl ReputationTracker {
    pub fn new() -> Self {
        Self {
            entries: DashMap::new(),
        }
    }

    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    /// Record a violation (e.g., failed handshake)
    pub fn record_violation(&self, ip: IpAddr) {
        let now = Self::now_secs();

        if let Some(entry) = self.entries.get(&ip) {
            let last_seen = entry.last_seen_secs.load(Ordering::Relaxed);
            if now > last_seen + WINDOW_SECS {
                // Window expired, reset
                entry.violations.store(1, Ordering::Relaxed);
            } else {
                entry.violations.fetch_add(1, Ordering::Relaxed);
            }
            entry.last_seen_secs.store(now, Ordering::Relaxed);
        } else {
            self.entries.insert(ip, ReputationEntry::new(now));
        }
    }

    /// Reset violations (e.g., successful session established or valid TLS ticket)
    pub fn reset_violations(&self, ip: IpAddr) {
        self.entries.remove(&ip);
    }

    /// Calculate dynamic PoW difficulty based on reputation
    pub fn calculate_difficulty(&self, ip: IpAddr, has_ticket: bool) -> u8 {
        if has_ticket {
            return 0; // Skip PoW for known returning clients
        }

        let now = Self::now_secs();

        if let Some(entry) = self.entries.get(&ip) {
            let last_seen = entry.last_seen_secs.load(Ordering::Relaxed);
            if now > last_seen + WINDOW_SECS {
                // Inside grace period / expired, back to base
                return BASE_DIFFICULTY;
            }

            let violations = entry.violations.load(Ordering::Relaxed);
            if violations == 0 {
                return BASE_DIFFICULTY;
            }

            // Exponential growth: 8, 10, 14, 20...
            let mut diff = BASE_DIFFICULTY as u32 + (1 << (violations - 1));
            if diff > MAX_DIFFICULTY as u32 {
                diff = MAX_DIFFICULTY as u32;
            }

            diff as u8
        } else {
            // New IP
            BASE_DIFFICULTY
        }
    }

    /// Garbage collect expired entries
    pub fn gc(&self) {
        let now = Self::now_secs();
        let before = self.entries.len();
        self.entries.retain(|_, v| {
            let last_seen = v.last_seen_secs.load(Ordering::Relaxed);
            now <= last_seen + WINDOW_SECS
        });
        let after = self.entries.len();
        if before > after {
            log::info!(
                "Reputation GC: removed {} expired entries, {} remaining",
                before - after,
                after
            );
        }
    }
}

impl Default for ReputationTracker {
    fn default() -> Self {
        Self::new()
    }
}
