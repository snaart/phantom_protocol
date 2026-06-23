//! Cold-path snapshot of the observability state.
//!
//! Reads every hot-path atomic with `Ordering::Relaxed` and exposes the
//! values in a `Clone`-able plain struct suitable for FFI, logging, and
//! debugging. Per-leg breakdown is preserved so consumers can compute their
//! own slices.
//!
//! Scope: this struct mirrors the lock-free `HotPathAtomics` — packet /
//! byte / timing totals, the session/stream gauges, the handshake
//! sum+count fields, and the always-on security counters
//! (`replay_rejected_total`, `aead_failure_total`). The snapshot is always
//! available regardless of the `telemetry-otel` feature, since the atomics
//! always exist. The labeled OTel instruments in `instruments.rs` carry
//! the same events with attribution; both paths are populated together.

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
    pub per_leg_packets: [(LegType, u64, u64); 4],
    /// Per-leg byte counts: `(LegType, bytes_sent, bytes_recv)`.
    pub per_leg_bytes: [(LegType, u64, u64); 4],

    pub avg_encrypt_ns: u64,
    pub avg_decrypt_ns: u64,
    pub encrypt_count: u64,
    pub decrypt_count: u64,

    pub rtt_us_path_0: u64,

    pub active_sessions: i64,
    pub active_streams: i64,

    pub handshakes_success: u64,
    pub handshakes_failure: u64,
    pub handshake_latency_ns_sum: u64,
    pub handshake_latency_count: u64,

    /// Always-on security counters. Populated by the `Observability` facade's
    /// `record_replay_rejected` / `record_aead_failure` methods regardless of
    /// whether the `telemetry-otel` feature is enabled.
    pub replay_rejected_total: u64,
    pub aead_failure_total: u64,

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
                (LegType::Udp, 0, 0),
            ],
            per_leg_bytes: [
                (LegType::Kcp, 0, 0),
                (LegType::Tcp, 0, 0),
                (LegType::FakeTls, 0, 0),
                (LegType::Udp, 0, 0),
            ],
            avg_encrypt_ns: 0,
            avg_decrypt_ns: 0,
            encrypt_count: 0,
            decrypt_count: 0,
            rtt_us_path_0: 0,
            active_sessions: 0,
            active_streams: 0,
            handshakes_success: 0,
            handshakes_failure: 0,
            handshake_latency_ns_sum: 0,
            handshake_latency_count: 0,
            replay_rejected_total: 0,
            aead_failure_total: 0,
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
            (
                LegType::Udp,
                h.packets_per_leg(DIR_SEND, LegType::Udp),
                h.packets_per_leg(DIR_RECV, LegType::Udp),
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
            (
                LegType::Udp,
                h.bytes_per_leg(DIR_SEND, LegType::Udp),
                h.bytes_per_leg(DIR_RECV, LegType::Udp),
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
            handshakes_success: h.handshake_success_count(),
            handshakes_failure: h.handshake_failure_count(),
            handshake_latency_ns_sum: h.handshake_latency_ns_sum(),
            handshake_latency_count: h.handshake_latency_count(),
            replay_rejected_total: h.replay_rejected_total(),
            aead_failure_total: h.aead_failure_total(),
            uptime_secs: h.uptime_secs(),
        }
    }
}

fn avg(sum: u64, count: u64) -> u64 {
    sum.checked_div(count).unwrap_or(0)
}

/// Flat, UniFFI-representable subset of [`MetricsSnapshot`].
///
/// Per-leg arrays are dropped because UniFFI `Record` fields must be plain
/// scalars or UniFFI-representable types — fixed-size arrays of tuples
/// containing non-`Record` enums (`LegType`) are not supported. All aggregate
/// scalar fields are preserved.
///
/// Always available regardless of whether the `telemetry-otel` feature is
/// enabled, because the underlying atomics are always present. On a
/// server-accepted session the counters are the owning listener's aggregate
/// (shared `Arc<Observability>` handle), not per-connection.
#[cfg_attr(feature = "bindings", derive(uniffi::Record))]
#[derive(Debug, Clone, Default)]
pub struct MetricsSnapshotFfi {
    pub packets_sent: u64,
    pub packets_recv: u64,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    pub avg_encrypt_ns: u64,
    pub avg_decrypt_ns: u64,
    pub encrypt_count: u64,
    pub decrypt_count: u64,
    pub rtt_us_path_0: u64,
    pub active_sessions: i64,
    pub active_streams: i64,
    pub handshakes_success: u64,
    pub handshakes_failure: u64,
    pub handshake_latency_ns_sum: u64,
    pub handshake_latency_count: u64,
    pub replay_rejected_total: u64,
    pub aead_failure_total: u64,
    pub uptime_secs: u64,
}

impl From<MetricsSnapshot> for MetricsSnapshotFfi {
    fn from(s: MetricsSnapshot) -> Self {
        Self {
            packets_sent: s.packets_sent,
            packets_recv: s.packets_recv,
            bytes_sent: s.bytes_sent,
            bytes_recv: s.bytes_recv,
            avg_encrypt_ns: s.avg_encrypt_ns,
            avg_decrypt_ns: s.avg_decrypt_ns,
            encrypt_count: s.encrypt_count,
            decrypt_count: s.decrypt_count,
            rtt_us_path_0: s.rtt_us_path_0,
            active_sessions: s.active_sessions,
            active_streams: s.active_streams,
            handshakes_success: s.handshakes_success,
            handshakes_failure: s.handshakes_failure,
            handshake_latency_ns_sum: s.handshake_latency_ns_sum,
            handshake_latency_count: s.handshake_latency_count,
            replay_rejected_total: s.replay_rejected_total,
            aead_failure_total: s.aead_failure_total,
            uptime_secs: s.uptime_secs,
        }
    }
}

impl MetricsSnapshot {
    /// Convert to the flat UniFFI-representable form, dropping per-leg arrays.
    pub fn to_ffi(&self) -> MetricsSnapshotFfi {
        self.clone().into()
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
    fn ffi_record_default_is_all_zero() {
        let ffi = MetricsSnapshotFfi::default();
        assert_eq!(ffi.packets_sent, 0);
        assert_eq!(ffi.packets_recv, 0);
        assert_eq!(ffi.bytes_sent, 0);
        assert_eq!(ffi.bytes_recv, 0);
        assert_eq!(ffi.avg_encrypt_ns, 0);
        assert_eq!(ffi.avg_decrypt_ns, 0);
        assert_eq!(ffi.encrypt_count, 0);
        assert_eq!(ffi.decrypt_count, 0);
        assert_eq!(ffi.rtt_us_path_0, 0);
        assert_eq!(ffi.active_sessions, 0);
        assert_eq!(ffi.active_streams, 0);
        assert_eq!(ffi.handshakes_success, 0);
        assert_eq!(ffi.handshakes_failure, 0);
        assert_eq!(ffi.handshake_latency_ns_sum, 0);
        assert_eq!(ffi.handshake_latency_count, 0);
        assert_eq!(ffi.replay_rejected_total, 0);
        assert_eq!(ffi.aead_failure_total, 0);
        assert_eq!(ffi.uptime_secs, 0);
    }

    #[test]
    fn ffi_flatten_preserves_all_scalar_fields() {
        let h = HotPathAtomics::new();
        h.record_send(1024, LegType::Tcp);
        h.record_recv(512, LegType::Kcp);
        h.record_encrypt_ns(200);
        h.record_decrypt_ns(100);
        h.record_rtt_us(3_000, 0);
        h.session_opened();
        h.stream_opened();
        h.record_handshake_success(1_000_000);
        h.record_handshake_failure();
        h.record_replay_rejected();
        h.record_aead_failure();

        let snap = MetricsSnapshot::capture(&h);
        let ffi = snap.to_ffi();

        assert_eq!(ffi.packets_sent, 1);
        assert_eq!(ffi.packets_recv, 1);
        assert_eq!(ffi.bytes_sent, 1024);
        assert_eq!(ffi.bytes_recv, 512);
        assert_eq!(ffi.avg_encrypt_ns, 200);
        assert_eq!(ffi.avg_decrypt_ns, 100);
        assert_eq!(ffi.encrypt_count, 1);
        assert_eq!(ffi.decrypt_count, 1);
        assert_eq!(ffi.rtt_us_path_0, 3_000);
        assert_eq!(ffi.active_sessions, 1);
        assert_eq!(ffi.active_streams, 1);
        assert_eq!(ffi.handshakes_success, 1);
        assert_eq!(ffi.handshakes_failure, 1);
        assert_eq!(ffi.handshake_latency_ns_sum, 1_000_000);
        assert_eq!(ffi.handshake_latency_count, 1);
        assert_eq!(ffi.replay_rejected_total, 1);
        assert_eq!(ffi.aead_failure_total, 1);
    }

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
