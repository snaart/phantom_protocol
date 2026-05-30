//! Integration tests for `phantom_core::observability` under the
//! `telemetry-otel` feature. These tests verify that the labeled recording
//! API compiles, runs, and exercises the OTel instrument call graph
//! without crashing. They do NOT spin up a real exporter; that's covered
//! end-to-end in `examples/observability-demo`.
//!
//! Compile-time gated — skipped on default-feature builds.

#![cfg(feature = "telemetry-otel")]

use phantom_core::observability::{
    AeadAlgorithm, CookieOutcome, Direction, EarlyDataOutcome, FallbackReason, HandshakeOutcome,
    Observability, ObservabilityConfig, PathValidationOutcome, PowOutcome, ProtocolVersion,
    ReplayReason, ResumptionMode,
};
use phantom_core::transport::types::LegType;
use std::time::Duration;

#[test]
fn full_labeled_event_surface_does_not_panic() {
    let obs = Observability::new(ObservabilityConfig::default());

    obs.record_handshake(
        Duration::from_millis(15),
        HandshakeOutcome::Success,
        LegType::Tcp,
        AeadAlgorithm::Aes256Gcm,
        ProtocolVersion::Current,
    );
    obs.record_handshake(
        Duration::from_millis(35),
        HandshakeOutcome::Failure,
        LegType::Kcp,
        AeadAlgorithm::ChaCha20Poly1305,
        ProtocolVersion::Current,
    );

    obs.record_resumption(ResumptionMode::ZeroRtt, true);
    obs.record_resumption(ResumptionMode::OneRtt, false);

    obs.record_replay_rejected(ReplayReason::Duplicate);
    obs.record_replay_rejected(ReplayReason::Old);

    obs.record_aead_failure(LegType::Tcp, AeadAlgorithm::Aes256Gcm);
    obs.record_unencrypted_dropped(LegType::FakeTls);
    obs.record_path_migration(0, 1);
    obs.record_path_validation(Duration::from_millis(8), 1, PathValidationOutcome::Success);

    obs.record_cookie(CookieOutcome::Issued);
    obs.record_cookie(CookieOutcome::ValidatedOk);
    obs.record_cookie(CookieOutcome::ValidatedMismatch);

    obs.record_pow(PowOutcome::Solved, 20);
    obs.record_pow(PowOutcome::Rejected, 22);

    obs.record_early_data(EarlyDataOutcome::Accepted);
    obs.record_early_data(EarlyDataOutcome::RejectedReplay);
    obs.record_early_data(EarlyDataOutcome::RejectedOversized);

    obs.record_rekey(Direction::Send);
    obs.record_rekey(Direction::Recv);

    obs.record_fallback(LegType::Tcp, LegType::Kcp, FallbackReason::RttThreshold);

    obs.session_opened(LegType::Tcp);
    obs.session_closed(LegType::Tcp);
    obs.stream_opened();
    obs.stream_closed();

    // Snapshot still works and reflects atomics drives.
    let s = obs.snapshot();
    assert_eq!(s.handshakes_success, 1);
    assert_eq!(s.handshakes_failure, 1);
    assert_eq!(s.active_sessions, 0);
    assert_eq!(s.active_streams, 0);
}

#[test]
fn observability_handles_are_cheap_to_clone() {
    let obs = Observability::new(ObservabilityConfig::default());
    let a = obs.clone();
    let b = obs.clone();
    a.record_send(1024, LegType::Tcp);
    b.record_send(2048, LegType::Tcp);
    assert_eq!(obs.snapshot().bytes_sent, 3072);
}
