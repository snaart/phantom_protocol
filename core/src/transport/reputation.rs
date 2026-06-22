//! Per-IP reputation tracking for adaptive PoW-difficulty escalation (DOS-2).
//!
//! Pairs with the stateless cookie + proof-of-work gate in
//! `transport::handshake`: an IP that repeatedly fails handshakes within a
//! sliding window accrues violations and pays an exponentially escalating PoW
//! difficulty (capped at `MAX_DIFFICULTY`), while clean / new IPs and resumption-
//! ticket holders pay nothing extra. The tracking map is bounded
//! ([`ReputationTracker::with_capacity`]) so a spoofed / varied-source-IP flood
//! cannot turn this CPU-DoS defense into a memory-DoS.

use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const WINDOW_SECS: u64 = 60;
const BASE_DIFFICULTY: u8 = 8;
const MAX_DIFFICULTY: u8 = 20;
/// Default cap on the number of tracked IPs (DOS-2). Bounds memory under a
/// spoofed / varied-source-IP flood; ~100k entries is a few MB and far above any
/// honest working set. A wired tracker without this bound would convert a
/// CPU-DoS into a memory-DoS.
const DEFAULT_MAX_ENTRIES: usize = 100_000;

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

/// Tracks per-IP reputation and computes a PoW-difficulty **escalation** for
/// abusive sources (DOS-2). A clean / new IP contributes 0 (so well-behaved
/// clients are never penalized); an IP that accrues handshake violations within
/// the sliding window pays an escalating difficulty, capped at
/// `MAX_DIFFICULTY`. The map is bounded (see [`Self::with_capacity`]).
pub struct ReputationTracker {
    entries: DashMap<IpAddr, ReputationEntry>,
    max_entries: usize,
}

impl ReputationTracker {
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_MAX_ENTRIES)
    }

    /// Create a tracker bounded to at most `max_entries` tracked IPs (DOS-2).
    pub fn with_capacity(max_entries: usize) -> Self {
        Self {
            entries: DashMap::new(),
            max_entries: max_entries.max(1),
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
            // DOS-2: bound the map. Drop expired entries first; if still at the
            // cap, skip — the untracked IP still pays the global difficulty tier,
            // so a spoofed/varied-IP flood cannot grow this map without limit.
            if self.entries.len() >= self.max_entries {
                self.gc();
                if self.entries.len() >= self.max_entries {
                    return;
                }
            }
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
                // Window expired — the IP is treated as clean again.
                return 0;
            }

            let violations = entry.violations.load(Ordering::Relaxed);
            if violations == 0 {
                return 0;
            }

            // Exponential escalation from BASE for IPs WITH recent violations.
            // Clamp the shift exponent so a large violation count cannot overflow
            // the shift (the result is capped at MAX_DIFFICULTY anyway).
            let exp = (violations - 1).min(8);
            let diff = (BASE_DIFFICULTY as u32 + (1u32 << exp)).min(MAX_DIFFICULTY as u32);
            diff as u8
        } else {
            // Clean / new IP — no extra PoW beyond the global load tier (DOS-2:
            // do not penalize well-behaved clients).
            0
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

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(n: u8) -> IpAddr {
        IpAddr::from([10, 0, 0, n])
    }

    /// **DOS-2.** Per-IP escalation must not penalize well-behaved clients: a
    /// clean/new IP (and any resumption-ticket holder) contributes 0, so legit
    /// clients stay 1-RTT when the global load tier is idle.
    #[test]
    fn clean_ip_pays_no_extra_difficulty() {
        let rep = ReputationTracker::new();
        assert_eq!(rep.calculate_difficulty(ip(1), false), 0, "new IP");
        assert_eq!(rep.calculate_difficulty(ip(1), true), 0, "ticket holder");
    }

    /// Repeated violations from one IP escalate the PoW difficulty (capped at
    /// MAX_DIFFICULTY); a reset (successful handshake) clears it.
    #[test]
    fn repeated_violations_escalate_and_reset_clears() {
        let rep = ReputationTracker::new();
        let a = ip(2);
        assert_eq!(rep.calculate_difficulty(a, false), 0);
        rep.record_violation(a);
        let d1 = rep.calculate_difficulty(a, false);
        assert!(
            d1 >= BASE_DIFFICULTY,
            "first violation escalates to >= base, got {d1}"
        );
        rep.record_violation(a);
        rep.record_violation(a);
        let d3 = rep.calculate_difficulty(a, false);
        assert!(
            d3 >= d1 && d3 <= MAX_DIFFICULTY,
            "escalates further, capped at max; got {d3}"
        );
        rep.reset_violations(a);
        assert_eq!(
            rep.calculate_difficulty(a, false),
            0,
            "reset clears escalation"
        );
    }

    /// **DOS-2.** A spoofed/varied-IP flood must not grow the map without limit.
    #[test]
    fn map_is_bounded() {
        let rep = ReputationTracker::with_capacity(8);
        for n in 0..100u8 {
            rep.record_violation(IpAddr::from([10, 1, 0, n]));
        }
        assert!(
            rep.entries.len() <= 8,
            "map must stay bounded, got {}",
            rep.entries.len()
        );
    }
}
