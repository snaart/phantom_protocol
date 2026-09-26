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
//! (`replay_rejected_total`, `aead_failure_total`,
//! `unencrypted_dropped_total`, `initial_datagrams_on_committed_route_total`,
//! `initial_flights_on_committed_route_total`,
//! `handshake_flight_repeated_total`, `handshake_flight_evicted_total`,
//! `handshake_flight_refused_total`). The snapshot is always
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

    /// Handshakes **this side** completed. Not a count of peers that joined: the
    /// server's `ServerHello` is acknowledged by nothing, so a reply lost on the
    /// way down leaves a session counted here that the peer never saw — one live
    /// run held such a session for 135 s with no byte in either direction. A
    /// server total above a client's is the ordinary reading of a lossy path.
    pub handshakes_success: u64,
    pub handshakes_failure: u64,
    pub handshake_latency_ns_sum: u64,
    pub handshake_latency_count: u64,

    /// Always-on security counters. Populated by the `Observability` facade's
    /// `record_replay_rejected` / `record_aead_failure` /
    /// `record_unencrypted_dropped` methods regardless of whether the
    /// `telemetry-otel` feature is enabled.
    pub replay_rejected_total: u64,
    pub aead_failure_total: u64,
    /// Post-handshake packets dropped for arriving without `ENCRYPTED`
    /// (Invariant 2, the stripped-flag downgrade defence). A non-zero value on a
    /// healthy peer means someone on the path is rewriting header flags.
    pub unencrypted_dropped_total: u64,
    /// **Unit: datagrams.** Handshake-type datagrams that arrived on a PhantomUDP
    /// connection the listener had already committed a route to, counted before
    /// reassembly (PROTOCOL § 6.1) — the duplicate wire load a repeating client
    /// puts on the listener, several per repeated flight. Not comparable with
    /// `handshake_flight_repeated_total`.
    pub initial_datagrams_on_committed_route_total: u64,
    /// **Unit: flights.** Reassembled handshake messages that arrived on a
    /// PhantomUDP connection the listener had already committed a route to — one
    /// per question a client asked again because it never saw the reply
    /// (PROTOCOL § 6.1). Read against a client that timed out connecting, a
    /// non-zero value says one reply flight was lost on the way down and zero says
    /// the path went silent in both directions; nothing else distinguishes those.
    /// **Meant to be read together with `handshake_flight_repeated_total`, which
    /// is in the same unit.**
    pub initial_flights_on_committed_route_total: u64,
    /// **Unit: flights.** Retained reply flights this listener actually repeated
    /// (PROTOCOL § 6.1), one per repeat sent. **Meant to be read together with
    /// `initial_flights_on_committed_route_total`**: that one says a client asked
    /// again, this one says an answer went back. Asks arriving with none going
    /// back is a listener whose retention did not cover that session.
    pub handshake_flight_repeated_total: u64,
    /// Retained reply flights dropped to make room for a newer one. Non-zero means
    /// the repair is running out of the memory it is allowed and some sessions are
    /// back to losing a connect to a single lost reply datagram.
    pub handshake_flight_evicted_total: u64,
    /// Reply flights never retained at all, because repeating one would have exceeded
    /// the RFC 9000 § 8.2 amplification limit. Zero with today's messages; non-zero
    /// says a message size moved past the bound and the repair stopped arming.
    pub handshake_flight_refused_total: u64,

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
            unencrypted_dropped_total: 0,
            initial_datagrams_on_committed_route_total: 0,
            initial_flights_on_committed_route_total: 0,
            handshake_flight_repeated_total: 0,
            handshake_flight_evicted_total: 0,
            handshake_flight_refused_total: 0,
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
            unencrypted_dropped_total: h.unencrypted_dropped_total(),
            initial_datagrams_on_committed_route_total: h
                .initial_datagrams_on_committed_route_total(),
            initial_flights_on_committed_route_total: h.initial_flights_on_committed_route_total(),
            handshake_flight_repeated_total: h.handshake_flight_repeated_total(),
            handshake_flight_evicted_total: h.handshake_flight_evicted_total(),
            handshake_flight_refused_total: h.handshake_flight_refused_total(),
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
    /// Handshakes **this side** completed — not a count of peers that joined.
    ///
    /// A server records one the moment it has derived keys and sent its `ServerHello`,
    /// and nothing under the handshake acknowledges that reply, so a flight lost on the
    /// way down leaves a session counted here that the peer never saw. A live run held
    /// exactly such a session for 135 s with no byte in either direction, counted as a
    /// success while its client was reporting timeouts. Read a server's total against a
    /// client's failures as two measurements of one path, not as a contradiction; the
    /// two `*_on_committed_route_total` fields and `handshake_flight_repeated_total`
    /// are what say whether the reply was asked for again and re-sent.
    pub handshakes_success: u64,
    pub handshakes_failure: u64,
    pub handshake_latency_ns_sum: u64,
    pub handshake_latency_count: u64,
    pub replay_rejected_total: u64,
    pub aead_failure_total: u64,
    pub uptime_secs: u64,
    /// Deliberately near the end of the record, and new fields go after it.
    ///
    /// UniFFI lays a record out in declaration order and the generated bindings
    /// read it back the same way, so inserting a field anywhere but the end
    /// shifts every field after it. The four generated surfaces are regenerated
    /// together and stay consistent; the two hand-curated C headers are not
    /// generated and carry no length check, so a C consumer built against an
    /// older header would keep reading at the old offsets and silently return
    /// this counter where it asked for `uptime_secs`. Appending is the only
    /// placement where a stale reader is merely missing a field rather than
    /// misreading the ones it already knew.
    pub unencrypted_dropped_total: u64,
    /// **Unit: datagrams.** Handshake-type datagrams that arrived on a PhantomUDP
    /// connection the listener had already committed a route to, counted as each one
    /// lands and before reassembly (PROTOCOL § 6.1). Appended for the reason above.
    ///
    /// What it measures is the duplicate wire load a repeating client puts on the
    /// listener, which is a real question and the only one this offset has ever
    /// answered — a cookie-bearing hello is three fragments, so one repeated question
    /// moves it by three. It keeps its place in the record for exactly that reason:
    /// the name gained a unit, the number did not change, so a consumer built against
    /// an older header reads the same quantity it always did.
    ///
    /// **Not the field to read against `handshake_flight_repeated_total`** — that one
    /// counts flights, so the comparison is off by the fragment count and reads as
    /// answers gone missing. `initial_flights_on_committed_route_total` is the half
    /// that pairs with it.
    pub initial_datagrams_on_committed_route_total: u64,
    /// **Unit: flights.** Retained reply flights this listener actually repeated
    /// (PROTOCOL § 6.1), one per repeat sent rather than per datagram of it. Appended
    /// for the reason above.
    ///
    /// **Meant to be read together with `initial_flights_on_committed_route_total`,
    /// which is in the same unit**: that one says a client asked again, this one says
    /// an answer went back, and the pair is what makes a failed connect readable.
    /// Asks and answers together is the repair working. Asks and no answers is a
    /// listener that had nothing retained for that session — it was evicted, expired,
    /// or the budget for it was already spent. No asks at all is a path that went
    /// silent upstream, which is a different fault in a different direction.
    pub handshake_flight_repeated_total: u64,
    /// Retained reply flights dropped to make room for a newer one (PROTOCOL § 6.1).
    /// Appended for the reason above.
    ///
    /// This is the repair running out of the memory it is allowed. Non-zero says the
    /// listener is completing handshakes faster than its retention budget covers, and
    /// that the evicted sessions are back to losing a whole connect to one lost reply
    /// datagram — a rare, load-dependent failure that nothing else makes visible.
    pub handshake_flight_evicted_total: u64,
    /// Reply flights never retained at all, because repeating one would have exceeded
    /// the RFC 9000 § 8.2 amplification limit (PROTOCOL § 6.1 rule 3). Appended for the
    /// reason above.
    ///
    /// The third way the repair can fail to cover a session, and the only one that is not
    /// about load: the two fields above mean the mechanism ran and then let go, this one
    /// means it never armed. It reads zero for every build whose reply is inside the bound —
    /// today's is 1.99x against a limit of 3 — so a non-zero value is a message size having
    /// moved, which changes no byte a peer would notice and which nothing else reports.
    pub handshake_flight_refused_total: u64,
    /// **Unit: flights.** Reassembled handshake messages that arrived on a PhantomUDP
    /// connection the listener had already committed a route to — one per question a
    /// client asked again because it never saw the reply (PROTOCOL § 6.1). Appended
    /// last for the reason given above, which is also why it is not adjacent to the
    /// field it is read with.
    ///
    /// Repetition is normal on a lossy path and is what the server's repeat answers,
    /// so a small non-zero value is health rather than alarm. What it is for is
    /// reading against a client that timed out connecting: non-zero says its
    /// questions arrived and one reply flight was lost on the way down; zero says the
    /// path fell silent in both directions. Nothing else on either side tells those
    /// apart.
    ///
    /// **Meant to be read together with `handshake_flight_repeated_total`, which is in
    /// the same unit.** The datagram-unit field of the same event
    /// (`initial_datagrams_on_committed_route_total`) is a different measurement, and
    /// comparing that one with the repeat count invents missing answers that never
    /// existed.
    pub initial_flights_on_committed_route_total: u64,
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
            unencrypted_dropped_total: s.unencrypted_dropped_total,
            initial_datagrams_on_committed_route_total: s
                .initial_datagrams_on_committed_route_total,
            handshake_flight_repeated_total: s.handshake_flight_repeated_total,
            handshake_flight_evicted_total: s.handshake_flight_evicted_total,
            handshake_flight_refused_total: s.handshake_flight_refused_total,
            initial_flights_on_committed_route_total: s.initial_flights_on_committed_route_total,
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
        assert_eq!(ffi.unencrypted_dropped_total, 0);
        assert_eq!(ffi.initial_datagrams_on_committed_route_total, 0);
        assert_eq!(ffi.initial_flights_on_committed_route_total, 0);
        assert_eq!(ffi.handshake_flight_repeated_total, 0);
        assert_eq!(ffi.handshake_flight_evicted_total, 0);
        assert_eq!(ffi.handshake_flight_refused_total, 0);
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
        h.record_unencrypted_dropped();
        // Two datagrams, one flight: the flatten must keep them in separate fields, since
        // one of them is comparable with the repeat count and the other is not.
        h.record_initial_datagram_on_committed_route();
        h.record_initial_datagram_on_committed_route();
        h.record_initial_flight_on_committed_route();
        h.record_handshake_flight_repeated();
        h.record_handshake_flight_evicted();
        h.record_handshake_flight_refused();

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
        assert_eq!(ffi.unencrypted_dropped_total, 1);
        assert_eq!(ffi.initial_datagrams_on_committed_route_total, 2);
        assert_eq!(ffi.initial_flights_on_committed_route_total, 1);
        assert_eq!(ffi.handshake_flight_repeated_total, 1);
        assert_eq!(ffi.handshake_flight_evicted_total, 1);
        assert_eq!(ffi.handshake_flight_refused_total, 1);
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
