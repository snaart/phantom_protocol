//! Compile-time and runtime checks for the no-op path when the
//! `telemetry-otel` feature is **disabled**. Guarantees that:
//!
//! 1. The full recording API still compiles and produces correct atomic
//!    accounting (the no-op shim accepts but discards OTel arguments).
//! 2. The library exports zero overhead at the call site (verified via the
//!    `PhantomInstruments` ZST assertion in the in-module test).
//!
//! This file is the inverse of `observability_otel.rs`.

#![cfg(not(feature = "telemetry-otel"))]

use phantom_core::observability::{
    AeadAlgorithm, HandshakeOutcome, Observability, ObservabilityConfig, ProtocolVersion,
    ReplayReason,
};
use phantom_core::transport::types::LegType;
use std::time::Duration;

#[test]
fn labeled_api_is_no_op_but_atomics_still_update() {
    let obs = Observability::new(ObservabilityConfig::default());

    obs.record_handshake(
        Duration::from_millis(20),
        HandshakeOutcome::Success,
        LegType::Tcp,
        AeadAlgorithm::Aes256Gcm,
        ProtocolVersion::V12,
    );
    obs.record_replay_rejected(ReplayReason::Duplicate);
    obs.record_aead_failure(LegType::Tcp, AeadAlgorithm::Aes256Gcm);
    obs.record_send(1024, LegType::Tcp);
    obs.session_opened(LegType::Tcp);
    obs.stream_opened();

    let s = obs.snapshot();
    assert_eq!(s.handshakes_success, 1);
    assert_eq!(s.packets_sent, 1);
    assert_eq!(s.bytes_sent, 1024);
    assert_eq!(s.active_sessions, 1);
    assert_eq!(s.active_streams, 1);
}
