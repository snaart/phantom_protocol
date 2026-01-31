//! Lock-Free Transport Metrics
//!
//! AtomicU64 counters для real-time observability без блокировок.
//! Нулевой overhead в hot path благодаря Relaxed ordering.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// Transport-level metrics (lock-free)
pub struct TransportMetrics {
    // --- Packet counters ---
    pub packets_sent: AtomicU64,
    pub packets_recv: AtomicU64,
    pub bytes_sent: AtomicU64,
    pub bytes_recv: AtomicU64,

    // --- Crypto timing (nanoseconds, cumulative) ---
    pub encrypt_ns_total: AtomicU64,
    pub decrypt_ns_total: AtomicU64,
    pub encrypt_count: AtomicU64,
    pub decrypt_count: AtomicU64,

    // --- Network quality ---
    pub rtt_us: AtomicU64,       // Latest RTT in microseconds
    pub loss_count: AtomicU64,   // Lost packets
    pub retransmit_count: AtomicU64,

    // --- Compression ---
    pub compress_input_bytes: AtomicU64,
    pub compress_output_bytes: AtomicU64,

    // --- Session ---
    pub handshakes_total: AtomicU64,
    pub resumptions_total: AtomicU64,
    pub fallbacks_total: AtomicU64,

    /// Start time for uptime calculation
    started_at: Instant,
}

impl TransportMetrics {
    /// Create fresh metrics
    pub fn new() -> Self {
        Self {
            packets_sent: AtomicU64::new(0),
            packets_recv: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            bytes_recv: AtomicU64::new(0),
            encrypt_ns_total: AtomicU64::new(0),
            decrypt_ns_total: AtomicU64::new(0),
            encrypt_count: AtomicU64::new(0),
            decrypt_count: AtomicU64::new(0),
            rtt_us: AtomicU64::new(0),
            loss_count: AtomicU64::new(0),
            retransmit_count: AtomicU64::new(0),
            compress_input_bytes: AtomicU64::new(0),
            compress_output_bytes: AtomicU64::new(0),
            handshakes_total: AtomicU64::new(0),
            resumptions_total: AtomicU64::new(0),
            fallbacks_total: AtomicU64::new(0),
            started_at: Instant::now(),
        }
    }

    // --- Recording helpers (hot path, Relaxed ordering) ---

    #[inline]
    pub fn record_send(&self, bytes: usize) {
        self.packets_sent.fetch_add(1, Ordering::Relaxed);
        self.bytes_sent.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    #[inline]
    pub fn record_recv(&self, bytes: usize) {
        self.packets_recv.fetch_add(1, Ordering::Relaxed);
        self.bytes_recv.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    #[inline]
    pub fn record_encrypt(&self, duration_ns: u64) {
        self.encrypt_ns_total.fetch_add(duration_ns, Ordering::Relaxed);
        self.encrypt_count.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn record_decrypt(&self, duration_ns: u64) {
        self.decrypt_ns_total.fetch_add(duration_ns, Ordering::Relaxed);
        self.decrypt_count.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn record_rtt(&self, rtt_us: u64) {
        self.rtt_us.store(rtt_us, Ordering::Relaxed);
    }

    #[inline]
    pub fn record_loss(&self) {
        self.loss_count.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn record_compression(&self, input: usize, output: usize) {
        self.compress_input_bytes.fetch_add(input as u64, Ordering::Relaxed);
        self.compress_output_bytes.fetch_add(output as u64, Ordering::Relaxed);
    }

    // --- Snapshot (read path) ---

    /// Create a snapshot for reporting
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            packets_sent: self.packets_sent.load(Ordering::Relaxed),
            packets_recv: self.packets_recv.load(Ordering::Relaxed),
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            bytes_recv: self.bytes_recv.load(Ordering::Relaxed),
            avg_encrypt_ns: self.avg_encrypt_ns(),
            avg_decrypt_ns: self.avg_decrypt_ns(),
            rtt_us: self.rtt_us.load(Ordering::Relaxed),
            loss_count: self.loss_count.load(Ordering::Relaxed),
            compression_ratio: self.compression_ratio(),
            handshakes: self.handshakes_total.load(Ordering::Relaxed),
            resumptions: self.resumptions_total.load(Ordering::Relaxed),
            uptime_secs: self.started_at.elapsed().as_secs(),
        }
    }

    /// Average encrypt time in nanoseconds
    pub fn avg_encrypt_ns(&self) -> u64 {
        let count = self.encrypt_count.load(Ordering::Relaxed);
        if count == 0 { 0 } else {
            self.encrypt_ns_total.load(Ordering::Relaxed) / count
        }
    }

    /// Average decrypt time in nanoseconds
    pub fn avg_decrypt_ns(&self) -> u64 {
        let count = self.decrypt_count.load(Ordering::Relaxed);
        if count == 0 { 0 } else {
            self.decrypt_ns_total.load(Ordering::Relaxed) / count
        }
    }

    /// Compression ratio (1.0 = no benefit)
    pub fn compression_ratio(&self) -> f64 {
        let output = self.compress_output_bytes.load(Ordering::Relaxed);
        if output == 0 { 1.0 } else {
            self.compress_input_bytes.load(Ordering::Relaxed) as f64 / output as f64
        }
    }

    /// Throughput in bytes/sec (send direction)
    pub fn send_throughput(&self) -> f64 {
        let elapsed = self.started_at.elapsed().as_secs_f64();
        if elapsed < 0.001 { 0.0 } else {
            self.bytes_sent.load(Ordering::Relaxed) as f64 / elapsed
        }
    }
}

/// Immutable snapshot for reporting/logging
#[derive(Debug, Clone)]
pub struct MetricsSnapshot {
    pub packets_sent: u64,
    pub packets_recv: u64,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    pub avg_encrypt_ns: u64,
    pub avg_decrypt_ns: u64,
    pub rtt_us: u64,
    pub loss_count: u64,
    pub compression_ratio: f64,
    pub handshakes: u64,
    pub resumptions: u64,
    pub uptime_secs: u64,
}

impl std::fmt::Display for MetricsSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "tx={} rx={} bytes_tx={} rtt={}µs loss={} encrypt={}ns decrypt={}ns compress={:.2}x up={}s",
            self.packets_sent, self.packets_recv, self.bytes_sent,
            self.rtt_us, self.loss_count,
            self.avg_encrypt_ns, self.avg_decrypt_ns,
            self.compression_ratio, self.uptime_secs
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_and_snapshot() {
        let m = TransportMetrics::new();

        m.record_send(1024);
        m.record_send(2048);
        m.record_recv(512);
        m.record_encrypt(100);
        m.record_encrypt(200);
        m.record_decrypt(50);
        m.record_rtt(5000);
        m.record_loss();
        m.record_compression(1000, 500);

        let snap = m.snapshot();
        assert_eq!(snap.packets_sent, 2);
        assert_eq!(snap.packets_recv, 1);
        assert_eq!(snap.bytes_sent, 3072);
        assert_eq!(snap.bytes_recv, 512);
        assert_eq!(snap.avg_encrypt_ns, 150); // (100+200)/2
        assert_eq!(snap.avg_decrypt_ns, 50);
        assert_eq!(snap.rtt_us, 5000);
        assert_eq!(snap.loss_count, 1);
        assert!((snap.compression_ratio - 2.0).abs() < 0.01);
        eprintln!("Snapshot: {}", snap);
    }

    #[test]
    fn zero_metrics() {
        let m = TransportMetrics::new();
        let snap = m.snapshot();
        assert_eq!(snap.packets_sent, 0);
        assert_eq!(snap.avg_encrypt_ns, 0);
        assert!((snap.compression_ratio - 1.0).abs() < 0.01);
    }

    #[test]
    fn concurrent_access() {
        use std::sync::Arc;
        let m = Arc::new(TransportMetrics::new());
        let mut handles = Vec::new();

        for _ in 0..4 {
            let m2 = m.clone();
            handles.push(std::thread::spawn(move || {
                for _ in 0..10_000 {
                    m2.record_send(100);
                    m2.record_recv(50);
                }
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        let snap = m.snapshot();
        assert_eq!(snap.packets_sent, 40_000);
        assert_eq!(snap.packets_recv, 40_000);
        assert_eq!(snap.bytes_sent, 4_000_000);
        eprintln!("Concurrent: {}", snap);
    }
}
