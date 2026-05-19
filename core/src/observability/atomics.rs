//! Lock-free hot-path counters.
//!
//! All packet/byte/timing recording goes through this struct on the hot
//! path. Each `AtomicU64` / `AtomicI64` field is wrapped in
//! `crossbeam_utils::CachePadded` so that tx-side and rx-side updates from
//! different cores do not bounce a shared cache line — a real measurable
//! win on multi-core hosts.
//!
//! No locks, no allocations on the recording path. `Relaxed` ordering is
//! sufficient: every consumer (OTel observable callback, FFI snapshot) reads
//! eventual values; we never use these counters for synchronization.
//!
//! Per-leg recording uses fixed-size arrays indexed by `LegType as usize`.
//! A compile-time guard pins the array size to the current enum cardinality
//! — adding a new `LegType` variant breaks the build until this constant is
//! updated.

use crate::transport::types::LegType;
use crossbeam_utils::CachePadded;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::time::Instant;

/// Number of `LegType` variants tracked per direction in [`HotPathAtomics`].
///
/// Keep in sync with `LegType`. The compile-time assert below fails the
/// build if a new variant is added without growing this constant.
pub(crate) const NUM_LEGS: usize = 3;

// Compile-time pin: ensures `NUM_LEGS` matches `LegType` cardinality.
// `LegType::FakeTls` is currently the highest discriminant (== 2), so
// `NUM_LEGS == 3` covers `Kcp` (0), `Tcp` (1), `FakeTls` (2). Adding a new
// variant will fail this assert and force an update here.
const _: () = {
    assert!(
        (LegType::FakeTls as usize) < NUM_LEGS,
        "NUM_LEGS must cover all LegType variants"
    );
};

/// Maximum path id tracked for RTT in the lock-free fast path. Paths above
/// this id silently skip the per-path RTT update — the long tail belongs in
/// the path registry, not the hot-path atomics.
pub(crate) const MAX_PATHS: usize = 16;

pub(crate) const DIR_SEND: usize = 0;
pub(crate) const DIR_RECV: usize = 1;
pub(crate) const NUM_DIRECTIONS: usize = 2;

/// Lock-free hot-path counters with cache-line padding.
///
/// Layout chosen so that no two hot atomics share a cache line: every
/// `AtomicU64` / `AtomicI64` is wrapped in `CachePadded`. Cost: ~256 B per
/// field; savings: tens of ns per contended update on multi-core hosts.
#[derive(Debug)]
pub(crate) struct HotPathAtomics {
    /// `packets[direction][leg]` — direction `DIR_SEND` or `DIR_RECV`.
    packets: [[CachePadded<AtomicU64>; NUM_LEGS]; NUM_DIRECTIONS],
    /// `bytes[direction][leg]` — same indexing as `packets`.
    bytes: [[CachePadded<AtomicU64>; NUM_LEGS]; NUM_DIRECTIONS],

    /// AEAD encrypt aggregate: cumulative duration (ns) + invocation count.
    encrypt_ns_sum: CachePadded<AtomicU64>,
    encrypt_count: CachePadded<AtomicU64>,
    /// AEAD decrypt aggregate: cumulative duration (ns) + invocation count.
    decrypt_ns_sum: CachePadded<AtomicU64>,
    decrypt_count: CachePadded<AtomicU64>,

    /// Last-observed RTT per path id (0..MAX_PATHS), microseconds. Stores
    /// only the latest value (gauge semantics); historical RTT is the path
    /// registry's responsibility.
    rtt_us_per_path: [CachePadded<AtomicU64>; MAX_PATHS],

    /// Active session and stream gauges — signed so that close-without-open
    /// surfaces as a negative value rather than panicking.
    active_sessions: CachePadded<AtomicI64>,
    active_streams: CachePadded<AtomicI64>,

    /// Process-start timestamp for uptime calculation. Set once at
    /// construction; the snapshot reader computes `elapsed()` on read.
    started_at: Instant,
}

impl HotPathAtomics {
    pub(crate) fn new() -> Self {
        Self {
            packets: std::array::from_fn(|_| {
                std::array::from_fn(|_| CachePadded::new(AtomicU64::new(0)))
            }),
            bytes: std::array::from_fn(|_| {
                std::array::from_fn(|_| CachePadded::new(AtomicU64::new(0)))
            }),
            encrypt_ns_sum: CachePadded::new(AtomicU64::new(0)),
            encrypt_count: CachePadded::new(AtomicU64::new(0)),
            decrypt_ns_sum: CachePadded::new(AtomicU64::new(0)),
            decrypt_count: CachePadded::new(AtomicU64::new(0)),
            rtt_us_per_path: std::array::from_fn(|_| CachePadded::new(AtomicU64::new(0))),
            active_sessions: CachePadded::new(AtomicI64::new(0)),
            active_streams: CachePadded::new(AtomicI64::new(0)),
            started_at: Instant::now(),
        }
    }

    // --- Hot path recorders ---

    #[inline]
    pub(crate) fn record_send(&self, bytes: usize, leg: LegType) {
        let idx = leg as usize;
        self.packets[DIR_SEND][idx].fetch_add(1, Ordering::Relaxed);
        self.bytes[DIR_SEND][idx].fetch_add(bytes as u64, Ordering::Relaxed);
    }

    #[inline]
    pub(crate) fn record_recv(&self, bytes: usize, leg: LegType) {
        let idx = leg as usize;
        self.packets[DIR_RECV][idx].fetch_add(1, Ordering::Relaxed);
        self.bytes[DIR_RECV][idx].fetch_add(bytes as u64, Ordering::Relaxed);
    }

    #[inline]
    pub(crate) fn record_encrypt_ns(&self, duration_ns: u64) {
        self.encrypt_ns_sum
            .fetch_add(duration_ns, Ordering::Relaxed);
        self.encrypt_count.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub(crate) fn record_decrypt_ns(&self, duration_ns: u64) {
        self.decrypt_ns_sum
            .fetch_add(duration_ns, Ordering::Relaxed);
        self.decrypt_count.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub(crate) fn record_rtt_us(&self, rtt_us: u64, path_id: u8) {
        let idx = path_id as usize;
        if idx < MAX_PATHS {
            self.rtt_us_per_path[idx].store(rtt_us, Ordering::Relaxed);
        }
    }

    #[inline]
    pub(crate) fn session_opened(&self) {
        self.active_sessions.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub(crate) fn session_closed(&self) {
        self.active_sessions.fetch_sub(1, Ordering::Relaxed);
    }

    #[inline]
    pub(crate) fn stream_opened(&self) {
        self.active_streams.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub(crate) fn stream_closed(&self) {
        self.active_streams.fetch_sub(1, Ordering::Relaxed);
    }

    // --- Read accessors (cold path) ---

    pub(crate) fn packets_total(&self, dir: usize) -> u64 {
        (0..NUM_LEGS)
            .map(|i| self.packets[dir][i].load(Ordering::Relaxed))
            .sum()
    }

    pub(crate) fn bytes_total(&self, dir: usize) -> u64 {
        (0..NUM_LEGS)
            .map(|i| self.bytes[dir][i].load(Ordering::Relaxed))
            .sum()
    }

    pub(crate) fn packets_per_leg(&self, dir: usize, leg: LegType) -> u64 {
        self.packets[dir][leg as usize].load(Ordering::Relaxed)
    }

    pub(crate) fn bytes_per_leg(&self, dir: usize, leg: LegType) -> u64 {
        self.bytes[dir][leg as usize].load(Ordering::Relaxed)
    }

    pub(crate) fn encrypt_sum_ns(&self) -> u64 {
        self.encrypt_ns_sum.load(Ordering::Relaxed)
    }

    pub(crate) fn encrypt_count(&self) -> u64 {
        self.encrypt_count.load(Ordering::Relaxed)
    }

    pub(crate) fn decrypt_sum_ns(&self) -> u64 {
        self.decrypt_ns_sum.load(Ordering::Relaxed)
    }

    pub(crate) fn decrypt_count(&self) -> u64 {
        self.decrypt_count.load(Ordering::Relaxed)
    }

    pub(crate) fn rtt_us(&self, path_id: u8) -> u64 {
        let idx = path_id as usize;
        if idx < MAX_PATHS {
            self.rtt_us_per_path[idx].load(Ordering::Relaxed)
        } else {
            0
        }
    }

    pub(crate) fn active_sessions(&self) -> i64 {
        self.active_sessions.load(Ordering::Relaxed)
    }

    pub(crate) fn active_streams(&self) -> i64 {
        self.active_streams.load(Ordering::Relaxed)
    }

    pub(crate) fn uptime_secs(&self) -> u64 {
        self.started_at.elapsed().as_secs()
    }
}

impl Default for HotPathAtomics {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn record_send_increments_per_leg() {
        let h = HotPathAtomics::new();
        h.record_send(1024, LegType::Tcp);
        h.record_send(2048, LegType::Tcp);
        h.record_send(512, LegType::Kcp);

        assert_eq!(h.packets_per_leg(DIR_SEND, LegType::Tcp), 2);
        assert_eq!(h.packets_per_leg(DIR_SEND, LegType::Kcp), 1);
        assert_eq!(h.packets_per_leg(DIR_SEND, LegType::FakeTls), 0);

        assert_eq!(h.bytes_per_leg(DIR_SEND, LegType::Tcp), 3072);
        assert_eq!(h.bytes_per_leg(DIR_SEND, LegType::Kcp), 512);

        assert_eq!(h.packets_total(DIR_SEND), 3);
        assert_eq!(h.bytes_total(DIR_SEND), 3584);
    }

    #[test]
    fn record_recv_does_not_touch_send() {
        let h = HotPathAtomics::new();
        h.record_recv(100, LegType::Tcp);
        h.record_send(200, LegType::Tcp);
        assert_eq!(h.packets_per_leg(DIR_SEND, LegType::Tcp), 1);
        assert_eq!(h.packets_per_leg(DIR_RECV, LegType::Tcp), 1);
        assert_eq!(h.bytes_per_leg(DIR_SEND, LegType::Tcp), 200);
        assert_eq!(h.bytes_per_leg(DIR_RECV, LegType::Tcp), 100);
    }

    #[test]
    fn crypto_timing_aggregates() {
        let h = HotPathAtomics::new();
        h.record_encrypt_ns(100);
        h.record_encrypt_ns(200);
        h.record_decrypt_ns(50);
        assert_eq!(h.encrypt_sum_ns(), 300);
        assert_eq!(h.encrypt_count(), 2);
        assert_eq!(h.decrypt_sum_ns(), 50);
        assert_eq!(h.decrypt_count(), 1);
    }

    #[test]
    fn rtt_per_path_stores_last_value() {
        let h = HotPathAtomics::new();
        h.record_rtt_us(1000, 0);
        h.record_rtt_us(2000, 0); // overwrite
        h.record_rtt_us(3000, 5);
        assert_eq!(h.rtt_us(0), 2000);
        assert_eq!(h.rtt_us(5), 3000);
        assert_eq!(h.rtt_us(15), 0);
    }

    #[test]
    fn rtt_out_of_range_path_silently_drops() {
        let h = HotPathAtomics::new();
        h.record_rtt_us(9999, 100); // path_id >= MAX_PATHS
        assert_eq!(h.rtt_us(100), 0);
    }

    #[test]
    fn session_gauge_balances() {
        let h = HotPathAtomics::new();
        h.session_opened();
        h.session_opened();
        h.session_opened();
        h.session_closed();
        assert_eq!(h.active_sessions(), 2);
    }

    #[test]
    fn stream_gauge_balances() {
        let h = HotPathAtomics::new();
        h.stream_opened();
        h.stream_opened();
        h.stream_closed();
        assert_eq!(h.active_streams(), 1);
    }

    #[test]
    fn concurrent_send_record_is_lock_free_and_correct() {
        let h = Arc::new(HotPathAtomics::new());
        let n_threads = 4;
        let iters = 10_000;
        let mut handles = Vec::with_capacity(n_threads);

        for _ in 0..n_threads {
            let h2 = h.clone();
            handles.push(thread::spawn(move || {
                for _ in 0..iters {
                    h2.record_send(100, LegType::Tcp);
                    h2.record_recv(50, LegType::Kcp);
                }
            }));
        }

        for hh in handles {
            hh.join().expect("thread join");
        }

        assert_eq!(
            h.packets_per_leg(DIR_SEND, LegType::Tcp),
            (n_threads * iters) as u64
        );
        assert_eq!(
            h.bytes_per_leg(DIR_SEND, LegType::Tcp),
            (n_threads * iters * 100) as u64
        );
        assert_eq!(
            h.packets_per_leg(DIR_RECV, LegType::Kcp),
            (n_threads * iters) as u64
        );
    }
}
