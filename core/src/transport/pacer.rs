//! Token Bucket Pacer
//!
//! Smooths out traffic bursts by enforcing a uniform send rate.
//! Instead of `socket.send()` dumping N packets at once (causing router queue buildups),
//! the pacer spreads packets uniformly over the RTT interval.
//!
//! # Design
//!
//! Uses a Token Bucket algorithm:
//! - Tokens replenish at `rate` bytes per second
//! - Each send consumes `packet_size` tokens
//! - If no tokens are available, the send is delayed
//!
//! The pacer operates in conjunction with the `BandwidthEstimator` which feeds
//! the target rate. When BBR says "send at X MB/s", the pacer enforces that rate.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Minimum pacing rate (1 KB/s) — prevents stalling
const MIN_PACING_RATE: u64 = 1_024;

/// Maximum tokens that can accumulate (burst allowance, in bytes)
const MAX_BURST_BYTES: u64 = 64 * 1_024; // 64 KB

/// Token Bucket Pacer
///
/// Thread-safe pacer that can be shared across async tasks.
pub struct Pacer {
    /// Current available tokens (bytes)
    tokens: AtomicU64,
    /// Pacing rate in bytes/sec
    rate_bps: AtomicU64,
    /// Maximum burst size in bytes
    max_burst: u64,
    /// Last token refill timestamp (nanoseconds since some epoch)
    last_refill_ns: AtomicU64,
    /// Whether pacing is enabled
    enabled: AtomicBool,
    /// Creation time (for relative nanoseconds)
    epoch: Instant,
}

impl Pacer {
    /// Create a new pacer with the given initial rate (bytes/sec).
    pub fn new(initial_rate_bps: u64) -> Self {
        let rate = initial_rate_bps.max(MIN_PACING_RATE);
        let epoch = Instant::now();

        Self {
            tokens: AtomicU64::new(MAX_BURST_BYTES),
            rate_bps: AtomicU64::new(rate),
            max_burst: MAX_BURST_BYTES,
            last_refill_ns: AtomicU64::new(0),
            enabled: AtomicBool::new(true),
            epoch,
        }
    }

    /// Create an unlimited pacer (always allows sends).
    pub fn unlimited() -> Self {
        let pacer = Self::new(u64::MAX);
        pacer.enabled.store(false, Ordering::Relaxed);
        pacer
    }

    /// Try to consume `bytes` tokens. Returns `true` if allowed, `false` if should wait.
    pub fn try_consume(&self, bytes: u64) -> bool {
        if !self.enabled.load(Ordering::Relaxed) {
            return true;
        }

        self.refill_tokens();

        let current = self.tokens.load(Ordering::Relaxed);
        if current >= bytes {
            self.tokens.fetch_sub(bytes, Ordering::Relaxed);
            true
        } else {
            false
        }
    }

    /// How long to wait before `bytes` tokens are available.
    pub fn time_until_available(&self, bytes: u64) -> Duration {
        if !self.enabled.load(Ordering::Relaxed) {
            return Duration::ZERO;
        }

        self.refill_tokens();

        let current = self.tokens.load(Ordering::Relaxed);
        if current >= bytes {
            return Duration::ZERO;
        }

        let deficit = bytes - current;
        let rate = self.rate_bps.load(Ordering::Relaxed).max(1);
        Duration::from_nanos(deficit * 1_000_000_000 / rate)
    }

    /// Update the pacing rate (called by BandwidthEstimator).
    pub fn set_rate(&self, rate_bps: u64) {
        let rate = rate_bps.max(MIN_PACING_RATE);
        self.rate_bps.store(rate, Ordering::Relaxed);
    }

    /// Get the current pacing rate (bytes/sec).
    pub fn rate(&self) -> u64 {
        self.rate_bps.load(Ordering::Relaxed)
    }

    /// Enable or disable pacing.
    pub fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Relaxed);
    }

    /// Whether pacing is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    /// Current available tokens.
    pub fn available_tokens(&self) -> u64 {
        self.refill_tokens();
        self.tokens.load(Ordering::Relaxed)
    }

    /// Refill tokens based on elapsed time.
    fn refill_tokens(&self) {
        let now_ns = self.epoch.elapsed().as_nanos() as u64;
        let last_ns = self.last_refill_ns.load(Ordering::Relaxed);
        let elapsed_ns = now_ns.saturating_sub(last_ns);

        if elapsed_ns == 0 {
            return;
        }

        let rate = self.rate_bps.load(Ordering::Relaxed);
        // tokens_to_add = rate * elapsed_time
        let new_tokens = (rate as u128 * elapsed_ns as u128 / 1_000_000_000) as u64;

        if new_tokens > 0 {
            // CAS loop to update atomically
            loop {
                let current = self.tokens.load(Ordering::Relaxed);
                let updated = (current + new_tokens).min(self.max_burst);
                if self
                    .tokens
                    .compare_exchange_weak(current, updated, Ordering::Relaxed, Ordering::Relaxed)
                    .is_ok()
                {
                    break;
                }
            }
            self.last_refill_ns.store(now_ns, Ordering::Relaxed);
        }
    }
}

impl std::fmt::Debug for Pacer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pacer")
            .field("rate_bps", &self.rate_bps.load(Ordering::Relaxed))
            .field("tokens", &self.tokens.load(Ordering::Relaxed))
            .field("enabled", &self.enabled.load(Ordering::Relaxed))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_pacer_allows_burst() {
        let pacer = Pacer::new(1_000_000); // 1 MB/s
                                           // Initial burst should be allowed (MAX_BURST_BYTES = 64 KB)
        assert!(pacer.try_consume(1400)); // one packet
        assert!(pacer.try_consume(1400)); // another packet
    }

    #[test]
    fn test_pacer_blocks_when_empty() {
        let pacer = Pacer::new(1_024); // 1 KB/s — very slow
                                       // Exhaust the burst allowance
        assert!(pacer.try_consume(MAX_BURST_BYTES));
        // No tokens left
        assert!(!pacer.try_consume(1));
    }

    #[test]
    fn test_pacer_refills_over_time() {
        let pacer = Pacer::new(100_000); // 100 KB/s
                                         // Drain all tokens
        assert!(pacer.try_consume(MAX_BURST_BYTES));
        assert!(!pacer.try_consume(1));

        // Wait a bit for refill
        thread::sleep(Duration::from_millis(50));

        // Should have some tokens now (~5KB at 100KB/s over 50ms)
        let available = pacer.available_tokens();
        assert!(
            available > 0,
            "expected tokens after sleep, got {}",
            available
        );
    }

    #[test]
    fn test_pacer_rate_update() {
        let pacer = Pacer::new(1_000_000);
        assert_eq!(pacer.rate(), 1_000_000);

        pacer.set_rate(2_000_000);
        assert_eq!(pacer.rate(), 2_000_000);
    }

    #[test]
    fn test_pacer_min_rate() {
        let pacer = Pacer::new(0); // Should clamp to MIN
        assert_eq!(pacer.rate(), MIN_PACING_RATE);
    }

    #[test]
    fn test_pacer_unlimited() {
        let pacer = Pacer::unlimited();
        assert!(!pacer.is_enabled());
        // Should always allow
        assert!(pacer.try_consume(u64::MAX));
        assert_eq!(pacer.time_until_available(1), Duration::ZERO);
    }

    #[test]
    fn test_pacer_time_until_available() {
        let pacer = Pacer::new(1_000_000); // 1 MB/s
                                           // Drain tokens
        pacer.try_consume(MAX_BURST_BYTES);

        // Need 10_000 bytes at 1 MB/s = 10ms
        let wait = pacer.time_until_available(10_000);
        assert!(wait > Duration::ZERO);
        assert!(wait < Duration::from_millis(50), "wait was {:?}", wait);
    }
}
