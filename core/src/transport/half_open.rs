//! Half-Open Connection Slots
//!
//! Thread-safe storage for pending handshake states using `DashMap`.
//! Replaces the previous `UnsafeCell`-based ring buffer with a safe,
//! concurrent hash map with TTL-based expiration.

use dashmap::DashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Default TTL for half-open handshake slots (2 seconds).
const DEFAULT_TTL: Duration = Duration::from_secs(2);

/// Maximum number of pending handshakes before we start rejecting.
const MAX_PENDING: usize = 65536;

/// A timestamped entry in the half-open table.
struct SlotEntry<T> {
    data: T,
    created_at_ms: u64,
}

/// Thread-safe half-open connection table.
///
/// Stores pending handshake data keyed by a `u32` slot ID.
/// Entries are automatically expired after `ttl` and the table
/// enforces a maximum capacity to prevent SYN flood attacks.
///
/// # Safety
///
/// Fully safe — no `UnsafeCell`, no manual `Sync`/`Send` impls.
/// All concurrency is handled by `DashMap`.
pub struct HalfOpenSlots<T> {
    slots: DashMap<u32, SlotEntry<T>>,
    next_id: AtomicU32,
    ttl: Duration,
    max_pending: usize,
}

impl<T> HalfOpenSlots<T> {
    /// Create a new half-open table with default TTL (2s) and capacity (65536).
    pub fn new() -> Self {
        Self {
            slots: DashMap::with_capacity(1024),
            next_id: AtomicU32::new(1),
            ttl: DEFAULT_TTL,
            max_pending: MAX_PENDING,
        }
    }

    /// Create with custom TTL and capacity.
    pub fn with_config(ttl: Duration, max_pending: usize) -> Self {
        Self {
            slots: DashMap::with_capacity(max_pending.min(4096)),
            next_id: AtomicU32::new(1),
            ttl,
            max_pending,
        }
    }

    fn now_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }

    /// Insert a pending handshake state.
    ///
    /// Returns `Some(slot_id)` on success, `None` if the table is full.
    /// Triggers lazy garbage collection of expired entries.
    pub fn insert(&self, item: T) -> Option<u32> {
        // Lazy GC: clean expired entries if we're near capacity
        if self.slots.len() >= self.max_pending / 2 {
            self.gc();
        }

        if self.slots.len() >= self.max_pending {
            log::warn!(
                "HalfOpenSlots: table full ({} entries), rejecting new handshake",
                self.slots.len()
            );
            return None;
        }

        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let entry = SlotEntry {
            data: item,
            created_at_ms: Self::now_ms(),
        };
        self.slots.insert(id, entry);
        Some(id)
    }

    /// Retrieve and remove a pending handshake by slot ID.
    ///
    /// Returns `None` if the slot doesn't exist or has expired.
    pub fn take(&self, slot_id: u32) -> Option<T> {
        let now = Self::now_ms();
        let ttl_ms = self.ttl.as_millis() as u64;

        match self.slots.remove(&slot_id) {
            Some((_, entry)) => {
                if now <= entry.created_at_ms + ttl_ms {
                    Some(entry.data)
                } else {
                    // Expired
                    None
                }
            }
            None => None,
        }
    }

    /// Peek at a slot without removing it.
    ///
    /// Returns `true` if the slot exists and is still valid.
    pub fn contains(&self, slot_id: u32) -> bool {
        let now = Self::now_ms();
        let ttl_ms = self.ttl.as_millis() as u64;

        self.slots
            .get(&slot_id)
            .map(|entry| now <= entry.created_at_ms + ttl_ms)
            .unwrap_or(false)
    }

    /// Number of entries (including potentially expired ones).
    pub fn len(&self) -> usize {
        self.slots.len()
    }

    /// Whether the table is empty.
    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }

    /// Garbage-collect expired entries.
    pub fn gc(&self) {
        let now = Self::now_ms();
        let ttl_ms = self.ttl.as_millis() as u64;
        self.slots
            .retain(|_, entry| now <= entry.created_at_ms + ttl_ms);
    }
}

impl<T> Default for HalfOpenSlots<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_insert_and_take() {
        let slots = HalfOpenSlots::new();

        let id = slots.insert("hello").unwrap();
        assert!(slots.contains(id));
        assert_eq!(slots.len(), 1);

        let data = slots.take(id).unwrap();
        assert_eq!(data, "hello");
        assert!(!slots.contains(id));
        assert_eq!(slots.len(), 0);
    }

    #[test]
    fn test_take_nonexistent() {
        let slots: HalfOpenSlots<String> = HalfOpenSlots::new();
        assert!(slots.take(999).is_none());
    }

    #[test]
    fn test_expired_entry() {
        let slots = HalfOpenSlots::with_config(Duration::from_millis(1), 100);

        let id = slots.insert("ephemeral").unwrap();

        // Wait for expiration
        std::thread::sleep(Duration::from_millis(10));

        assert!(slots.take(id).is_none());
    }

    #[test]
    fn test_capacity_limit() {
        let slots = HalfOpenSlots::with_config(Duration::from_secs(60), 3);

        assert!(slots.insert(1).is_some());
        assert!(slots.insert(2).is_some());
        assert!(slots.insert(3).is_some());
        // Should be full
        assert!(slots.insert(4).is_none());
    }

    #[test]
    fn test_gc() {
        let slots = HalfOpenSlots::with_config(Duration::from_millis(1), 100);

        slots.insert("a").unwrap();
        slots.insert("b").unwrap();
        assert_eq!(slots.len(), 2);

        std::thread::sleep(Duration::from_millis(10));

        slots.gc();
        assert_eq!(slots.len(), 0);
    }

    #[test]
    fn test_concurrent_access() {
        use std::sync::Arc;
        use std::thread;

        let slots = Arc::new(HalfOpenSlots::with_config(Duration::from_secs(10), 10000));
        let mut handles = vec![];

        for i in 0u32..100 {
            let s = slots.clone();
            handles.push(thread::spawn(move || {
                let id = s.insert(i).unwrap();
                assert!(s.contains(id));
                let val = s.take(id).unwrap();
                assert_eq!(val, i);
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        assert!(slots.is_empty());
    }
}
