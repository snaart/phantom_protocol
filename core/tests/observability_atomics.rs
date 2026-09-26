//! Integration tests for `phantom_protocol::observability` lock-free atomics.
//!
//! Complements the unit tests inside `core/src/observability/atomics.rs` by
//! exercising the public `Observability` facade end-to-end (recording sites,
//! per-leg slicing, snapshot read consistency).

// Tests `.unwrap()` freely so failures surface as readable diagnostics; the
// disallowed-methods list in `.clippy.toml` is for production code, not the test
// harness. (Integration-test crates are their own crate and therefore do not
// inherit `core/src/lib.rs`'s `#![cfg_attr(test, allow(...))]`.)
#![allow(clippy::disallowed_methods)]

use phantom_protocol::observability::{
    AeadAlgorithm, CookieOutcome, Direction, EarlyDataOutcome, Observability, ObservabilityConfig,
    PathValidationOutcome, PowOutcome, ResumptionMode,
};
use phantom_protocol::transport::types::LegType;
use std::sync::Arc;
use std::time::Duration;

#[test]
fn per_leg_packet_counters_isolate_legs() {
    let obs = Observability::new(ObservabilityConfig::default());

    obs.record_send(1024, LegType::Tcp);
    obs.record_send(2048, LegType::Tcp);
    obs.record_send(512, LegType::Kcp);
    obs.record_send(256, LegType::FakeTls);
    obs.record_recv(800, LegType::Tcp);

    let s = obs.snapshot();
    assert_eq!(s.packets_sent, 4);
    assert_eq!(s.packets_recv, 1);
    assert_eq!(s.bytes_sent, 1024 + 2048 + 512 + 256);
    assert_eq!(s.bytes_recv, 800);

    // Per-leg breakdown survives the snapshot.
    let tcp_send = s
        .per_leg_packets
        .iter()
        .find(|(l, _, _)| *l == LegType::Tcp)
        .unwrap();
    assert_eq!(tcp_send.1, 2);
    assert_eq!(tcp_send.2, 1);
}

#[test]
fn handshake_counters_drive_snapshot() {
    let obs = Observability::new(ObservabilityConfig::default());
    obs.record_handshake_success(1_000_000); // 1 ms
    obs.record_handshake_success(5_000_000); // 5 ms
    obs.record_handshake_failure();

    let s = obs.snapshot();
    assert_eq!(s.handshakes_success, 2);
    assert_eq!(s.handshakes_failure, 1);
    assert_eq!(s.handshake_latency_count, 2);
    assert_eq!(s.handshake_latency_ns_sum, 6_000_000);
}

#[test]
fn concurrent_hot_path_recording_is_lock_free() {
    let obs = Observability::new(ObservabilityConfig::default());
    let obs_arc: Arc<Observability> = obs;

    let n_threads = 8;
    let iters = 25_000;
    let mut handles = Vec::with_capacity(n_threads);

    for _ in 0..n_threads {
        let obs2 = obs_arc.clone();
        handles.push(std::thread::spawn(move || {
            for _ in 0..iters {
                obs2.record_send(64, LegType::Tcp);
                obs2.record_recv(64, LegType::Kcp);
                obs2.record_encrypt_ns(120);
                obs2.record_decrypt_ns(110);
            }
        }));
    }

    for h in handles {
        h.join().expect("thread panicked");
    }

    let s = obs_arc.snapshot();
    let expected = (n_threads * iters) as u64;
    assert_eq!(s.packets_sent, expected);
    assert_eq!(s.packets_recv, expected);
    assert_eq!(s.bytes_sent, expected * 64);
    assert_eq!(s.bytes_recv, expected * 64);
    assert_eq!(s.encrypt_count, expected);
    assert_eq!(s.decrypt_count, expected);
}

#[test]
fn namespace_prefix_is_honored() {
    let cfg = ObservabilityConfig::builder().namespace("custom").build();
    let obs = Observability::new(cfg);
    assert_eq!(obs.config().namespace.as_ref(), "custom");
}

#[test]
fn snapshot_reflects_session_and_stream_gauges() {
    let obs = Observability::new(ObservabilityConfig::default());
    obs.session_opened(LegType::Tcp);
    obs.session_opened(LegType::Tcp);
    obs.session_opened(LegType::Kcp);
    obs.session_closed(LegType::Kcp);

    obs.stream_opened();
    obs.stream_opened();
    obs.stream_opened();
    obs.stream_closed();

    let s = obs.snapshot();
    assert_eq!(s.active_sessions, 2);
    assert_eq!(s.active_streams, 2);
}

// ───────────────────────────────────────────────────────────────────────────
// Regression pins for the recorders that were registered but never called.
//
// These are facade-level contracts the newly-added call sites in
// `api/session.rs` and `transport/handshake.rs` depend on. The real loopback
// exercises live in `observability_e2e.rs` (always-on, atomics-backed) and
// `observability_instrument_wiring.rs` (`--features telemetry-otel`, the
// OTel-only recorders).
// ───────────────────────────────────────────────────────────────────────────

/// The `active_streams` gauge must be exactly balanced over repeated
/// open/close cycles and must never end up non-zero — the same defect class
/// already pinned for `active_sessions` in `observability_e2e.rs`.
#[test]
fn stream_gauge_balances_over_repeated_open_close_cycles() {
    let obs = Observability::new(ObservabilityConfig::default());

    for cycle in 0..64 {
        let n = (cycle % 5) + 1;
        for _ in 0..n {
            obs.stream_opened();
        }
        assert_eq!(
            obs.snapshot().active_streams,
            n as i64,
            "cycle {cycle}: gauge must reflect exactly the streams opened this cycle"
        );
        for _ in 0..n {
            obs.stream_closed();
        }
        assert_eq!(
            obs.snapshot().active_streams,
            0,
            "cycle {cycle}: gauge must return to zero when every stream is closed"
        );
    }
}

/// Interleaved opens and closes across threads must still settle at exactly
/// zero — `StreamGauge` fans `stream_closed()` out from the pump task, the
/// receive task and `Drop`, so the underlying gauge has to be race-free.
#[test]
fn concurrent_stream_gauge_updates_settle_at_zero() {
    let obs = Observability::new(ObservabilityConfig::default());

    let threads = 8;
    let iters = 5_000;
    let mut handles = Vec::with_capacity(threads);
    for _ in 0..threads {
        let obs2 = obs.clone();
        handles.push(std::thread::spawn(move || {
            for _ in 0..iters {
                obs2.stream_opened();
                obs2.stream_closed();
            }
        }));
    }
    for h in handles {
        h.join().expect("thread panicked");
    }

    assert_eq!(
        obs.snapshot().active_streams,
        0,
        "a balanced concurrent open/close workload must leave the gauge at zero"
    );
}

/// `avg_encrypt_ns` / `avg_decrypt_ns` are plain sum-over-count, and the
/// counts are "operations actually recorded". The pump records only successful
/// seals/opens, so these fields are the contract that makes
/// `encrypt_count == packets sealed` meaningful.
#[test]
fn encrypt_decrypt_aggregates_are_sum_over_count() {
    let obs = Observability::new(ObservabilityConfig::default());
    assert_eq!(
        obs.snapshot().avg_encrypt_ns,
        0,
        "no divide-by-zero at rest"
    );

    obs.record_encrypt_ns(100);
    obs.record_encrypt_ns(200);
    obs.record_encrypt_ns(300);
    obs.record_decrypt_ns(1_000);
    obs.record_decrypt_ns(3_000);

    let s = obs.snapshot();
    assert_eq!(s.encrypt_count, 3);
    assert_eq!(s.avg_encrypt_ns, 200);
    assert_eq!(s.decrypt_count, 2);
    assert_eq!(s.avg_decrypt_ns, 2_000);

    // The flat FFI record carries the same values — this is what a
    // Swift/Kotlin/Python consumer actually reads.
    let ffi = s.to_ffi();
    assert_eq!(ffi.encrypt_count, 3);
    assert_eq!(ffi.avg_encrypt_ns, 200);
    assert_eq!(ffi.decrypt_count, 2);
    assert_eq!(ffi.avg_decrypt_ns, 2_000);
}

/// The pump labels every RTT sample with the **inbound** `header.path_id`, and
/// `MetricsSnapshotFfi` exposes only path 0. Two properties the wiring relies
/// on: a sample on another path must not clobber slot 0, and an out-of-range
/// path id (>= the fixed per-path array width) must be dropped silently rather
/// than panic or alias onto slot 0.
#[test]
fn rtt_samples_are_per_path_and_never_clobber_path_zero() {
    let obs = Observability::new(ObservabilityConfig::default());
    assert_eq!(obs.snapshot().rtt_us_path_0, 0);

    obs.record_rtt_us(4_200, 0);
    assert_eq!(obs.snapshot().rtt_us_path_0, 4_200);

    // Another (in-range) path must land in its own slot.
    obs.record_rtt_us(99_999, 3);
    assert_eq!(
        obs.snapshot().rtt_us_path_0,
        4_200,
        "a sample on path 3 must not overwrite path 0"
    );

    // Out-of-range path ids — including the reserved rebind-validation id 255
    // and the top of the u8 migration space — must be dropped, not aliased.
    obs.record_rtt_us(1, 16);
    obs.record_rtt_us(2, 254);
    obs.record_rtt_us(3, 255);
    assert_eq!(
        obs.snapshot().rtt_us_path_0,
        4_200,
        "an out-of-range path id must be dropped silently, never folded into path 0"
    );

    // Latest-wins on the same slot (it is a gauge, not a counter).
    obs.record_rtt_us(7_000, 0);
    assert_eq!(obs.snapshot().rtt_us_path_0, 7_000);
}

/// **Documents the observability split, and pins it.**
///
/// `record_cookie`, `record_pow`, `record_early_data`, `record_resumption`,
/// `record_rekey`, `record_path_migration` and `record_path_validation` are
/// OTel-only: they reach `PhantomInstruments` and nothing else. With
/// `telemetry-otel` off (the default build) that holder is a ZST whose methods
/// compile away, so **no snapshot field can ever move for them**.
///
/// This is not a defect to fix here — it is the reason those seven recorders
/// are pinned in `core/tests/observability_instrument_wiring.rs` under
/// `--features telemetry-otel` instead of in `observability_e2e.rs`. If a
/// future change promotes one of them into the always-on atomics (as
/// `record_replay_rejected` / `record_aead_failure` already are), this test
/// fails and is the prompt to add a snapshot assertion for it.
/// Every scalar the always-on snapshot exposes, except `uptime_secs` (which is
/// wall-clock driven and not a recorder output).
fn counter_fingerprint(s: &phantom_protocol::observability::MetricsSnapshot) -> [i128; 15] {
    [
        s.packets_sent as i128,
        s.packets_recv as i128,
        s.bytes_sent as i128,
        s.bytes_recv as i128,
        s.avg_encrypt_ns as i128,
        s.avg_decrypt_ns as i128,
        s.encrypt_count as i128,
        s.decrypt_count as i128,
        s.rtt_us_path_0 as i128,
        s.active_sessions as i128,
        s.active_streams as i128,
        s.handshakes_success as i128,
        s.handshakes_failure as i128,
        s.replay_rejected_total as i128,
        s.aead_failure_total as i128,
    ]
}

#[test]
fn otel_only_recorders_are_invisible_to_the_snapshot() {
    let obs = Observability::new(ObservabilityConfig::default());
    let before = obs.snapshot();

    obs.record_cookie(CookieOutcome::Issued);
    obs.record_cookie(CookieOutcome::ValidatedOk);
    obs.record_cookie(CookieOutcome::ValidatedMismatch);
    obs.record_pow(PowOutcome::Solved, 12);
    obs.record_pow(PowOutcome::Rejected, 12);
    obs.record_early_data(EarlyDataOutcome::Accepted);
    obs.record_early_data(EarlyDataOutcome::RejectedUnknownTicket);
    obs.record_early_data(EarlyDataOutcome::RejectedOversized);
    obs.record_early_data(EarlyDataOutcome::RejectedAead);
    obs.record_early_data(EarlyDataOutcome::RejectedReplay);
    obs.record_resumption(ResumptionMode::ZeroRtt, true);
    obs.record_resumption(ResumptionMode::OneRtt, false);
    obs.record_rekey(Direction::Send);
    obs.record_rekey(Direction::Recv);
    obs.record_path_migration(0, 1);
    obs.record_path_validation(Duration::from_millis(3), 1, PathValidationOutcome::Success);
    obs.record_path_validation(Duration::from_millis(3), 1, PathValidationOutcome::Failure);

    let after = obs.snapshot();
    assert_eq!(
        counter_fingerprint(&after),
        counter_fingerprint(&before),
        "the OTel-only recorders must not touch the always-on atomics; if one now \
         does, pin it with a snapshot assertion in observability_e2e.rs"
    );

    // The two security recorders that ARE promoted into the atomics stay
    // observable — this is the contrast that makes the assertion above a
    // deliberate contract rather than an accident.
    obs.record_replay_rejected(phantom_protocol::observability::ReplayReason::Duplicate);
    obs.record_aead_failure(LegType::Udp, AeadAlgorithm::Aes256Gcm);
    let s = obs.snapshot();
    assert_eq!(s.replay_rejected_total, before.replay_rejected_total + 1);
    assert_eq!(s.aead_failure_total, before.aead_failure_total + 1);
}
