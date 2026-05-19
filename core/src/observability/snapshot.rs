//! Cold-path snapshot of the observability state.
//!
//! Reads every hot-path atomic with `Ordering::Relaxed` and exposes the
//! values in a `Clone`-able plain struct suitable for FFI, logging, and
//! debugging. Per-leg breakdown is preserved so consumers can compute their
//! own slices.
//!
//! In step 3 of the rollout this struct does NOT carry the security signal
//! counters or histogram (those are added with the OTel instruments in
//! later steps). It provides at least the same totals as the legacy
//! `transport::metrics::MetricsSnapshot` so call sites can migrate.

use crate::observability::atomics::{HotPathAtomics, DIR_RECV, DIR_SEND};
use crate::transport::types::LegType;

/// Immutable cold-path snapshot of the hot-path atomics.
#[derive(Debug, Clone)]
pub struct MetricsSnapshot {
    pub packets_sent: u64,
    pub packets_recv: u64,
    pub bytes_sent: u64,
    pub bytes_recv: u64,

    /// Per-leg packet counts: `(LegType, packets_sent, packets_recv)`.
    pub per_leg_packets: [(LegType, u64, u64); 3],
    /// Per-leg byte counts: `(LegType, bytes_sent, bytes_recv)`.
    pub per_leg_bytes: [(LegType, u64, u64); 3],

    pub avg_encrypt_ns: u64,
    pub avg_decrypt_ns: u64,
    pub encrypt_count: u64,
    pub decrypt_count: u64,

    pub rtt_us_path_0: u64,

    pub active_sessions: i64,
    pub active_streams: i64,

    pub uptime_secs: u64,
}

impl Default for MetricsSnapshot {
    fn default() -> Self {
        Self {
            packets_sent: 0,
            packets_recv: 0,
            bytes_sent: 0,
            bytes_recv: 0,
            per_leg_packets: [
                (LegType::Kcp, 0, 0),
                (LegType::Tcp, 0, 0),
                (LegType::FakeTls, 0, 0),
            ],
            per_leg_bytes: [
                (LegType::Kcp, 0, 0),
                (LegType::Tcp, 0, 0),
                (LegType::FakeTls, 0, 0),
            ],
            avg_encrypt_ns: 0,
            avg_decrypt_ns: 0,
            encrypt_count: 0,
            decrypt_count: 0,
            rtt_us_path_0: 0,
            active_sessions: 0,
            active_streams: 0,
            uptime_secs: 0,
        }
    }
}

impl MetricsSnapshot {
    pub(crate) fn capture(h: &HotPathAtomics) -> Self {
        let avg_encrypt_ns = avg(h.encrypt_sum_ns(), h.encrypt_count());
        let avg_decrypt_ns = avg(h.decrypt_sum_ns(), h.decrypt_count());

        let per_leg_packets = [
            (
                LegType::Kcp,
                h.packets_per_leg(DIR_SEND, LegType::Kcp),
                h.packets_per_leg(DIR_RECV, LegType::Kcp),
            ),
            (
                LegType::Tcp,
                h.packets_per_leg(DIR_SEND, LegType::Tcp),
                h.packets_per_leg(DIR_RECV, LegType::Tcp),
            ),
            (
                LegType::FakeTls,
                h.packets_per_leg(DIR_SEND, LegType::FakeTls),
                h.packets_per_leg(DIR_RECV, LegType::FakeTls),
            ),
        ];
        let per_leg_bytes = [
            (
                LegType::Kcp,
                h.bytes_per_leg(DIR_SEND, LegType::Kcp),
                h.bytes_per_leg(DIR_RECV, LegType::Kcp),
            ),
            (
                LegType::Tcp,
                h.bytes_per_leg(DIR_SEND, LegType::Tcp),
                h.bytes_per_leg(DIR_RECV, LegType::Tcp),
            ),
            (
                LegType::FakeTls,
                h.bytes_per_leg(DIR_SEND, LegType::FakeTls),
                h.bytes_per_leg(DIR_RECV, LegType::FakeTls),
            ),
        ];

        Self {
            packets_sent: h.packets_total(DIR_SEND),
            packets_recv: h.packets_total(DIR_RECV),
            bytes_sent: h.bytes_total(DIR_SEND),
            bytes_recv: h.bytes_total(DIR_RECV),
            per_leg_packets,
            per_leg_bytes,
            avg_encrypt_ns,
            avg_decrypt_ns,
            encrypt_count: h.encrypt_count(),
            decrypt_count: h.decrypt_count(),
            rtt_us_path_0: h.rtt_us(0),
            active_sessions: h.active_sessions(),
            active_streams: h.active_streams(),
            uptime_secs: h.uptime_secs(),
        }
    }
}

fn avg(sum: u64, count: u64) -> u64 {
    if count == 0 {
        0
    } else {
        sum / count
    }
}

impl std::fmt::Display for MetricsSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "tx={} rx={} bytes_tx={} bytes_rx={} encrypt={}ns decrypt={}ns sessions={} streams={} up={}s",
            self.packets_sent,
            self.packets_recv,
            self.bytes_sent,
            self.bytes_recv,
            self.avg_encrypt_ns,
            self.avg_decrypt_ns,
            self.active_sessions,
            self.active_streams,
            self.uptime_secs,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observability::atomics::HotPathAtomics;

    #[test]
    fn snapshot_zero_state() {
        let h = HotPathAtomics::new();
        let s = MetricsSnapshot::capture(&h);
        assert_eq!(s.packets_sent, 0);
        assert_eq!(s.avg_encrypt_ns, 0);
        assert_eq!(s.active_sessions, 0);
    }

    #[test]
    fn snapshot_after_recording() {
        let h = HotPathAtomics::new();
        h.record_send(1024, LegType::Tcp);
        h.record_send(2048, LegType::Kcp);
        h.record_recv(512, LegType::Tcp);
        h.record_encrypt_ns(100);
        h.record_encrypt_ns(200);
        h.session_opened();
        h.stream_opened();

        let s = MetricsSnapshot::capture(&h);
        assert_eq!(s.packets_sent, 2);
        assert_eq!(s.packets_recv, 1);
        assert_eq!(s.bytes_sent, 3072);
        assert_eq!(s.avg_encrypt_ns, 150);
        assert_eq!(s.encrypt_count, 2);
        assert_eq!(s.active_sessions, 1);
        assert_eq!(s.active_streams, 1);
    }

    #[test]
    fn display_is_one_line() {
        let h = HotPathAtomics::new();
        let s = MetricsSnapshot::capture(&h);
        let text = format!("{}", s);
        assert!(!text.contains('\n'));
        assert!(text.contains("tx=0"));
    }
}
