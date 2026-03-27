use anyhow::{bail, Result};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Replay protection using nonce tracking
///
/// Tracks seen nonces within a time window to prevent replay attacks.
/// Old nonces are automatically cleaned up to prevent memory exhaustion.
pub struct ReplayProtection {
    seen_nonces: RwLock<HashMap<u32, Instant>>,
    window: Duration,
    max_entries: usize,
}

impl ReplayProtection {
    /// Create new replay protection with default settings
    ///
    /// Default window: 120 seconds (2x the timestamp validation window)
    /// Max entries: 100,000 nonces
    pub fn new() -> Self {
        Self {
            seen_nonces: RwLock::new(HashMap::new()),
            window: Duration::from_secs(120),
            max_entries: 100_000,
        }
    }

    /// Create with custom window and max entries
    pub fn with_config(window: Duration, max_entries: usize) -> Self {
        Self {
            seen_nonces: RwLock::new(HashMap::new()),
            window,
            max_entries,
        }
    }

    /// Check if nonce has been seen before and record it
    ///
    /// Returns:
    /// - Ok(()) if nonce is new
    /// - Err if nonce is duplicate (replay attack detected)
    pub fn check_and_record(&self, nonce: u32) -> Result<()> {
        let mut seen = self.seen_nonces.write();

        // Check if nonce exists
        if let Some(first_seen) = seen.get(&nonce) {
            // Check if still within window
            if first_seen.elapsed() < self.window {
                bail!(
                    "Replay attack detected: duplicate nonce {} (first seen {:?} ago)",
                    nonce,
                    first_seen.elapsed()
                );
            }
            // Nonce is old, can be reused (remove old entry)
            seen.remove(&nonce);
        }

        // Check if we need to cleanup
        if seen.len() >= self.max_entries {
            self.cleanup_old_nonces(&mut seen);

            // If still full after cleanup, reject
            if seen.len() >= self.max_entries {
                bail!("Replay protection cache full (possible DoS attack)");
            }
        }

        // Record nonce
        seen.insert(nonce, Instant::now());

        Ok(())
    }

    /// Cleanup nonces older than the window
    fn cleanup_old_nonces(&self, seen: &mut HashMap<u32, Instant>) {
        let now = Instant::now();
        seen.retain(|_, first_seen| now.duration_since(*first_seen) < self.window);
    }

    /// Get current cache statistics
    pub fn stats(&self) -> ReplayProtectionStats {
        let seen = self.seen_nonces.read();
        ReplayProtectionStats {
            total_nonces: seen.len(),
            window_seconds: self.window.as_secs(),
            max_entries: self.max_entries,
        }
    }

    /// Clear all tracked nonces (for testing)
    #[cfg(test)]
    pub fn clear(&self) {
        self.seen_nonces.write().clear();
    }
}

impl Default for ReplayProtection {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct ReplayProtectionStats {
    pub total_nonces: usize,
    pub window_seconds: u64,
    pub max_entries: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_duplicate_nonce_rejected() {
        let rp = ReplayProtection::new();

        // First nonce should succeed
        assert!(rp.check_and_record(12345).is_ok());

        // Duplicate nonce should fail
        assert!(rp.check_and_record(12345).is_err());
    }

    #[test]
    fn test_different_nonces_accepted() {
        let rp = ReplayProtection::new();

        assert!(rp.check_and_record(1).is_ok());
        assert!(rp.check_and_record(2).is_ok());
        assert!(rp.check_and_record(3).is_ok());
    }

    #[test]
    fn test_nonce_expires() {
        let rp = ReplayProtection::with_config(Duration::from_millis(100), 1000);

        assert!(rp.check_and_record(999).is_ok());

        // Wait for expiration
        std::thread::sleep(Duration::from_millis(150));

        // Same nonce should be accepted after expiration
        assert!(rp.check_and_record(999).is_ok());
    }

    #[test]
    fn test_cleanup() {
        let rp = ReplayProtection::with_config(Duration::from_millis(50), 10);

        // Fill cache
        for i in 0..10 {
            assert!(rp.check_and_record(i).is_ok());
        }

        // Wait for expiration
        std::thread::sleep(Duration::from_millis(100));

        // Adding new nonce should trigger cleanup
        assert!(rp.check_and_record(999).is_ok());

        // Old nonces should be cleared
        let stats = rp.stats();
        assert_eq!(stats.total_nonces, 1);
    }
}
