//! Lock-Free Transport Metrics
//!
//! `AtomicU64` counters for real-time observability without locks.
//! Hot-path overhead is one `fetch_add` with `Relaxed` ordering per recording.
//!
//! Phase 4.5 expansion: structured counters covering security signals
//! (`replay_rejected_total`, `unencrypted_dropped_total`,
//! `aead_decrypt_failed_total`), session/stream gauges, and a
//! Prometheus text-format exposition (`to_prometheus_text`) ready to be
//! served by an optional HTTP endpoint in a downstream crate.

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
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
    pub rtt_us: AtomicU64,     // Latest RTT in microseconds
    pub loss_count: AtomicU64, // Lost packets
    pub retransmit_count: AtomicU64,

    // --- Compression ---
    pub compress_input_bytes: AtomicU64,
    pub compress_output_bytes: AtomicU64,

    // --- Session ---
    pub handshakes_total: AtomicU64,
    pub resumptions_total: AtomicU64,
    pub fallbacks_total: AtomicU64,

    // --- Security signals (Phase 4.5) ---
    /// Packets rejected because their sequence number falls inside the
    /// replay window of an already-seen value. Mirrors the per-Session
    /// counter aggregated across all sessions in this transport.
    pub replay_rejected_total: AtomicU64,
    /// Packets dropped because the `PacketFlags::ENCRYPTED` bit was
    /// missing on a non-empty application-data packet post-handshake.
    /// A non-zero count is a downgrade-attack signal.
    pub unencrypted_dropped_total: AtomicU64,
    /// AEAD decryption failures (tag mismatch). May indicate corruption
    /// or active tampering. Surface in alerting at >0 rate-per-minute.
    pub aead_decrypt_failed_total: AtomicU64,
    /// Path-migration completions (multi-path PATH_VALIDATION success).
    /// Phase 4.2 follow-up.
    pub path_migrations_total: AtomicU64,
    /// Handshake failures (any cause): cookie mismatch, signature
    /// rejection, KEM decap failure, transcript-version reject.
    pub handshake_failures_total: AtomicU64,

    // --- Gauges (Phase 4.5) ---
    /// Currently active sessions (inc on accept/connect, dec on close).
    pub active_sessions: AtomicI64,
    /// Currently active streams across all sessions.
    pub active_streams: AtomicI64,

    // --- Handshake latency histogram (Phase 4.5) ---
    /// Cumulative handshake latency in nanoseconds. Divide by
    /// `handshake_latency_count` for mean. Buckets in
    /// `handshake_latency_bucket_*` for percentile-style queries.
    pub handshake_latency_ns_total: AtomicU64,
    pub handshake_latency_count: AtomicU64,
    /// Bucket counters: ≤1ms, ≤10ms, ≤100ms, ≤1s, >1s.
    /// Prometheus-compatible histogram: each bucket is a count of
    /// observations whose value is ≤ the upper bound.
    pub handshake_latency_bucket_1ms: AtomicU64,
    pub handshake_latency_bucket_10ms: AtomicU64,
    pub handshake_latency_bucket_100ms: AtomicU64,
    pub handshake_latency_bucket_1s: AtomicU64,
    pub handshake_latency_bucket_inf: AtomicU64,

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
            replay_rejected_total: AtomicU64::new(0),
            unencrypted_dropped_total: AtomicU64::new(0),
            aead_decrypt_failed_total: AtomicU64::new(0),
            path_migrations_total: AtomicU64::new(0),
            handshake_failures_total: AtomicU64::new(0),
            active_sessions: AtomicI64::new(0),
            active_streams: AtomicI64::new(0),
            handshake_latency_ns_total: AtomicU64::new(0),
            handshake_latency_count: AtomicU64::new(0),
            handshake_latency_bucket_1ms: AtomicU64::new(0),
            handshake_latency_bucket_10ms: AtomicU64::new(0),
            handshake_latency_bucket_100ms: AtomicU64::new(0),
            handshake_latency_bucket_1s: AtomicU64::new(0),
            handshake_latency_bucket_inf: AtomicU64::new(0),
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
        self.encrypt_ns_total
            .fetch_add(duration_ns, Ordering::Relaxed);
        self.encrypt_count.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn record_decrypt(&self, duration_ns: u64) {
        self.decrypt_ns_total
            .fetch_add(duration_ns, Ordering::Relaxed);
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
        self.compress_input_bytes
            .fetch_add(input as u64, Ordering::Relaxed);
        self.compress_output_bytes
            .fetch_add(output as u64, Ordering::Relaxed);
    }

    // --- Security signals (Phase 4.5) ---

    #[inline]
    pub fn record_replay_rejected(&self) {
        self.replay_rejected_total.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn record_unencrypted_dropped(&self) {
        self.unencrypted_dropped_total
            .fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn record_aead_decrypt_failed(&self) {
        self.aead_decrypt_failed_total
            .fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn record_path_migration(&self) {
        self.path_migrations_total.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn record_handshake_failure(&self) {
        self.handshake_failures_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Record a successful handshake completion with its duration.
    /// Increments `handshakes_total`, accumulates latency, and bumps
    /// the appropriate histogram buckets (cumulative-≤ semantics).
    pub fn record_handshake_success(&self, duration_ns: u64) {
        self.handshakes_total.fetch_add(1, Ordering::Relaxed);
        self.handshake_latency_ns_total
            .fetch_add(duration_ns, Ordering::Relaxed);
        self.handshake_latency_count.fetch_add(1, Ordering::Relaxed);
        // Cumulative histogram: each observation increments every bucket
        // whose upper bound is ≥ the duration, matching Prometheus
        // `le=` semantics.
        if duration_ns <= 1_000_000 {
            self.handshake_latency_bucket_1ms
                .fetch_add(1, Ordering::Relaxed);
        }
        if duration_ns <= 10_000_000 {
            self.handshake_latency_bucket_10ms
                .fetch_add(1, Ordering::Relaxed);
        }
        if duration_ns <= 100_000_000 {
            self.handshake_latency_bucket_100ms
                .fetch_add(1, Ordering::Relaxed);
        }
        if duration_ns <= 1_000_000_000 {
            self.handshake_latency_bucket_1s
                .fetch_add(1, Ordering::Relaxed);
        }
        self.handshake_latency_bucket_inf
            .fetch_add(1, Ordering::Relaxed);
    }

    // --- Gauges ---

    #[inline]
    pub fn session_opened(&self) {
        self.active_sessions.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn session_closed(&self) {
        self.active_sessions.fetch_sub(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn stream_opened(&self) {
        self.active_streams.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn stream_closed(&self) {
        self.active_streams.fetch_sub(1, Ordering::Relaxed);
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
            handshake_failures: self.handshake_failures_total.load(Ordering::Relaxed),
            resumptions: self.resumptions_total.load(Ordering::Relaxed),
            replay_rejected: self.replay_rejected_total.load(Ordering::Relaxed),
            unencrypted_dropped: self.unencrypted_dropped_total.load(Ordering::Relaxed),
            aead_decrypt_failed: self.aead_decrypt_failed_total.load(Ordering::Relaxed),
            path_migrations: self.path_migrations_total.load(Ordering::Relaxed),
            active_sessions: self.active_sessions.load(Ordering::Relaxed),
            active_streams: self.active_streams.load(Ordering::Relaxed),
            handshake_latency_buckets: HandshakeLatencyHistogram {
                le_1ms: self.handshake_latency_bucket_1ms.load(Ordering::Relaxed),
                le_10ms: self.handshake_latency_bucket_10ms.load(Ordering::Relaxed),
                le_100ms: self.handshake_latency_bucket_100ms.load(Ordering::Relaxed),
                le_1s: self.handshake_latency_bucket_1s.load(Ordering::Relaxed),
                le_inf: self.handshake_latency_bucket_inf.load(Ordering::Relaxed),
                sum_ns: self.handshake_latency_ns_total.load(Ordering::Relaxed),
                count: self.handshake_latency_count.load(Ordering::Relaxed),
            },
            uptime_secs: self.started_at.elapsed().as_secs(),
        }
    }

    /// Average encrypt time in nanoseconds
    pub fn avg_encrypt_ns(&self) -> u64 {
        let count = self.encrypt_count.load(Ordering::Relaxed);
        if count == 0 {
            0
        } else {
            self.encrypt_ns_total.load(Ordering::Relaxed) / count
        }
    }

    /// Average decrypt time in nanoseconds
    pub fn avg_decrypt_ns(&self) -> u64 {
        let count = self.decrypt_count.load(Ordering::Relaxed);
        if count == 0 {
            0
        } else {
            self.decrypt_ns_total.load(Ordering::Relaxed) / count
        }
    }

    /// Compression ratio (1.0 = no benefit)
    pub fn compression_ratio(&self) -> f64 {
        let output = self.compress_output_bytes.load(Ordering::Relaxed);
        if output == 0 {
            1.0
        } else {
            self.compress_input_bytes.load(Ordering::Relaxed) as f64 / output as f64
        }
    }

    /// Throughput in bytes/sec (send direction)
    pub fn send_throughput(&self) -> f64 {
        let elapsed = self.started_at.elapsed().as_secs_f64();
        if elapsed < 0.001 {
            0.0
        } else {
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
    pub handshake_failures: u64,
    pub resumptions: u64,
    pub replay_rejected: u64,
    pub unencrypted_dropped: u64,
    pub aead_decrypt_failed: u64,
    pub path_migrations: u64,
    pub active_sessions: i64,
    pub active_streams: i64,
    pub handshake_latency_buckets: HandshakeLatencyHistogram,
    pub uptime_secs: u64,
}

/// Histogram of handshake latencies in nanoseconds, with Prometheus
/// cumulative `≤` bucket semantics.
#[derive(Debug, Clone, Default)]
pub struct HandshakeLatencyHistogram {
    pub le_1ms: u64,
    pub le_10ms: u64,
    pub le_100ms: u64,
    pub le_1s: u64,
    pub le_inf: u64,
    pub sum_ns: u64,
    pub count: u64,
}

impl MetricsSnapshot {
    /// Render the snapshot in Prometheus text-exposition format
    /// (`# TYPE name kind\nname value\n…`). The output is ready to be
    /// served by an HTTP `/metrics` endpoint built on top of any HTTP
    /// crate. Phantom Core does not link an HTTP server itself —
    /// downstream applications wire it up.
    pub fn to_prometheus_text(&self) -> String {
        let mut s = String::with_capacity(2048);
        // Counters
        let counters: [(&str, &str, u64); 9] = [
            (
                "phantom_packets_sent_total",
                "Packets transmitted",
                self.packets_sent,
            ),
            (
                "phantom_packets_recv_total",
                "Packets received",
                self.packets_recv,
            ),
            (
                "phantom_bytes_sent_total",
                "Bytes transmitted",
                self.bytes_sent,
            ),
            (
                "phantom_bytes_recv_total",
                "Bytes received",
                self.bytes_recv,
            ),
            (
                "phantom_handshakes_total",
                "Successful handshakes",
                self.handshakes,
            ),
            (
                "phantom_handshake_failures_total",
                "Failed handshakes",
                self.handshake_failures,
            ),
            (
                "phantom_replay_rejected_total",
                "Packets rejected by replay window",
                self.replay_rejected,
            ),
            (
                "phantom_unencrypted_dropped_total",
                "Non-empty post-handshake packets without ENCRYPTED flag",
                self.unencrypted_dropped,
            ),
            (
                "phantom_aead_decrypt_failed_total",
                "AEAD decryption failures (tag mismatch)",
                self.aead_decrypt_failed,
            ),
        ];
        for (name, help, value) in counters {
            s.push_str(&format!(
                "# HELP {name} {help}\n# TYPE {name} counter\n{name} {value}\n"
            ));
        }
        s.push_str(&format!(
            "# HELP phantom_path_migrations_total Successful multi-path migrations\n\
             # TYPE phantom_path_migrations_total counter\n\
             phantom_path_migrations_total {}\n",
            self.path_migrations,
        ));
        s.push_str(&format!(
            "# HELP phantom_resumptions_total 0-RTT resumptions accepted\n\
             # TYPE phantom_resumptions_total counter\n\
             phantom_resumptions_total {}\n",
            self.resumptions,
        ));
        // Gauges
        s.push_str(&format!(
            "# HELP phantom_active_sessions Current active sessions\n\
             # TYPE phantom_active_sessions gauge\n\
             phantom_active_sessions {}\n",
            self.active_sessions,
        ));
        s.push_str(&format!(
            "# HELP phantom_active_streams Current active streams across all sessions\n\
             # TYPE phantom_active_streams gauge\n\
             phantom_active_streams {}\n",
            self.active_streams,
        ));
        s.push_str(&format!(
            "# HELP phantom_rtt_us Latest observed RTT in microseconds\n\
             # TYPE phantom_rtt_us gauge\n\
             phantom_rtt_us {}\n",
            self.rtt_us,
        ));
        // Histogram
        let h = &self.handshake_latency_buckets;
        s.push_str("# HELP phantom_handshake_latency_seconds Handshake latency distribution\n");
        s.push_str("# TYPE phantom_handshake_latency_seconds histogram\n");
        s.push_str(&format!(
            "phantom_handshake_latency_seconds_bucket{{le=\"0.001\"}} {}\n",
            h.le_1ms
        ));
        s.push_str(&format!(
            "phantom_handshake_latency_seconds_bucket{{le=\"0.01\"}} {}\n",
            h.le_10ms
        ));
        s.push_str(&format!(
            "phantom_handshake_latency_seconds_bucket{{le=\"0.1\"}} {}\n",
            h.le_100ms
        ));
        s.push_str(&format!(
            "phantom_handshake_latency_seconds_bucket{{le=\"1\"}} {}\n",
            h.le_1s
        ));
        s.push_str(&format!(
            "phantom_handshake_latency_seconds_bucket{{le=\"+Inf\"}} {}\n",
            h.le_inf
        ));
        s.push_str(&format!(
            "phantom_handshake_latency_seconds_sum {:.9}\n",
            h.sum_ns as f64 / 1_000_000_000.0,
        ));
        s.push_str(&format!(
            "phantom_handshake_latency_seconds_count {}\n",
            h.count
        ));
        s
    }
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

    #[test]
    fn security_signals_recorded() {
        let m = TransportMetrics::new();
        m.record_replay_rejected();
        m.record_replay_rejected();
        m.record_unencrypted_dropped();
        m.record_aead_decrypt_failed();
        m.record_path_migration();
        m.record_handshake_failure();

        let snap = m.snapshot();
        assert_eq!(snap.replay_rejected, 2);
        assert_eq!(snap.unencrypted_dropped, 1);
        assert_eq!(snap.aead_decrypt_failed, 1);
        assert_eq!(snap.path_migrations, 1);
        assert_eq!(snap.handshake_failures, 1);
    }

    #[test]
    fn gauge_open_close_balances() {
        let m = TransportMetrics::new();
        m.session_opened();
        m.session_opened();
        m.session_opened();
        m.session_closed();

        m.stream_opened();
        m.stream_opened();
        m.stream_closed();

        let snap = m.snapshot();
        assert_eq!(snap.active_sessions, 2);
        assert_eq!(snap.active_streams, 1);
    }

    #[test]
    fn handshake_histogram_cumulative_le_semantics() {
        let m = TransportMetrics::new();
        // 500µs — falls in le_1ms
        m.record_handshake_success(500_000);
        // 5ms — falls in le_10ms (and ≤ 100ms, ≤ 1s, ≤ ∞)
        m.record_handshake_success(5_000_000);
        // 2s — only falls in le_inf
        m.record_handshake_success(2_000_000_000);

        let snap = m.snapshot();
        let h = &snap.handshake_latency_buckets;
        assert_eq!(h.count, 3);
        assert_eq!(h.le_1ms, 1);
        assert_eq!(h.le_10ms, 2);
        assert_eq!(h.le_100ms, 2);
        assert_eq!(h.le_1s, 2);
        assert_eq!(h.le_inf, 3);
        assert_eq!(h.sum_ns, 500_000 + 5_000_000 + 2_000_000_000);
    }

    #[test]
    fn prometheus_text_contains_expected_lines() {
        let m = TransportMetrics::new();
        m.record_send(1024);
        m.record_replay_rejected();
        m.record_handshake_success(50_000_000); // 50 ms
        m.session_opened();
        m.stream_opened();

        let text = m.snapshot().to_prometheus_text();

        // Every counter has a TYPE comment and a value line.
        assert!(text.contains("# TYPE phantom_packets_sent_total counter"));
        assert!(text.contains("phantom_packets_sent_total 1"));
        assert!(text.contains("# TYPE phantom_replay_rejected_total counter"));
        assert!(text.contains("phantom_replay_rejected_total 1"));

        // Gauges render with their current value (no monotonic prefix).
        assert!(text.contains("# TYPE phantom_active_sessions gauge"));
        assert!(text.contains("phantom_active_sessions 1"));
        assert!(text.contains("phantom_active_streams 1"));

        // Histogram: bucket `le="0.1"` must show >= 1 sample (50ms < 100ms).
        assert!(text.contains("phantom_handshake_latency_seconds_bucket{le=\"0.1\"} 1"));
        assert!(text.contains("phantom_handshake_latency_seconds_count 1"));
        // Sum is in seconds with 9-decimal precision.
        assert!(text.contains("phantom_handshake_latency_seconds_sum 0.050000000"));
    }
}
