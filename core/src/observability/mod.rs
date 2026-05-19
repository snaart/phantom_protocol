//! Phantom Core observability subsystem.
//!
//! Replaces the Phase 4.5 hand-rolled metrics module (`transport::metrics`).
//! Lock-free hot-path atomics for per-packet recording plus opt-in
//! OpenTelemetry instruments (metrics + traces) gated behind the
//! `telemetry-otel` Cargo feature.
//!
//! See `docs/observability/refactor-plan.md` for the full design and
//! atomic-commit rollout. This file is the public module surface; concrete
//! types live in the submodules below.
//!
//! ## Status (Phase 8 rollout)
//!
//! Step 2 — scaffold only. The `Observability` facade is a placeholder; the
//! hot-path atomics, OTel instruments, observable bridge, and recording APIs
//! land in subsequent atomic commits.

pub(crate) mod atomics;
pub mod config;
pub mod snapshot;

pub use config::{HistogramConfig, ObservabilityConfig, ObservabilityConfigBuilder};
pub use snapshot::MetricsSnapshot;

use crate::transport::types::LegType;
use atomics::HotPathAtomics;
use std::sync::Arc;

/// Public observability facade.
///
/// Wraps the lock-free atomic counters (always present) and — in later
/// rollout steps — the feature-gated OpenTelemetry instrument holder.
/// Recording sites in `transport`, `api`, and `crypto` call methods on this
/// struct via an `Arc<Observability>` borrowed from `PhantomListener` /
/// `PhantomSession`.
#[derive(Debug, Default)]
pub struct Observability {
    config: ObservabilityConfig,
    atomics: HotPathAtomics,
}

impl Observability {
    /// Construct a new observability handle.
    ///
    /// Returns an `Arc` because the handle is shared between recording sites
    /// (in `Session`, `Listener`, handshake code paths) and the OTel
    /// observable callbacks registered in a later step.
    pub fn new(config: ObservabilityConfig) -> Arc<Self> {
        Arc::new(Self {
            config,
            atomics: HotPathAtomics::new(),
        })
    }

    /// Borrow the captured configuration.
    pub fn config(&self) -> &ObservabilityConfig {
        &self.config
    }

    /// Capture a cold-path snapshot of all counters and gauges.
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot::capture(&self.atomics)
    }

    // --- Hot path recording ---

    #[inline]
    pub fn record_send(&self, bytes: usize, leg: LegType) {
        self.atomics.record_send(bytes, leg);
    }

    #[inline]
    pub fn record_recv(&self, bytes: usize, leg: LegType) {
        self.atomics.record_recv(bytes, leg);
    }

    #[inline]
    pub fn record_encrypt_ns(&self, duration_ns: u64) {
        self.atomics.record_encrypt_ns(duration_ns);
    }

    #[inline]
    pub fn record_decrypt_ns(&self, duration_ns: u64) {
        self.atomics.record_decrypt_ns(duration_ns);
    }

    #[inline]
    pub fn record_rtt_us(&self, rtt_us: u64, path_id: u8) {
        self.atomics.record_rtt_us(rtt_us, path_id);
    }

    // --- Gauges ---

    #[inline]
    pub fn session_opened(&self) {
        self.atomics.session_opened();
    }

    #[inline]
    pub fn session_closed(&self) {
        self.atomics.session_closed();
    }

    #[inline]
    pub fn stream_opened(&self) {
        self.atomics.stream_opened();
    }

    #[inline]
    pub fn stream_closed(&self) {
        self.atomics.stream_closed();
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_observability_has_default_config() {
        let obs = Observability::default();
        assert_eq!(obs.config().namespace.as_ref(), "phantom");
    }

    #[test]
    fn new_returns_arc_with_provided_config() {
        let cfg = ObservabilityConfig::builder().namespace("myapp").build();
        let obs = Observability::new(cfg);
        assert_eq!(obs.config().namespace.as_ref(), "myapp");
        // Cloning the Arc preserves identity.
        let obs2 = obs.clone();
        assert_eq!(obs2.config().namespace.as_ref(), "myapp");
    }

    #[test]
    fn record_send_round_trips_through_snapshot() {
        let obs = Observability::default();
        obs.record_send(1024, LegType::Tcp);
        obs.record_send(2048, LegType::Tcp);
        obs.record_recv(512, LegType::Kcp);
        obs.record_encrypt_ns(100);
        obs.record_encrypt_ns(300);
        obs.session_opened();
        obs.stream_opened();
        obs.stream_opened();
        obs.record_rtt_us(5_000, 0);

        let s = obs.snapshot();
        assert_eq!(s.packets_sent, 2);
        assert_eq!(s.packets_recv, 1);
        assert_eq!(s.bytes_sent, 3072);
        assert_eq!(s.bytes_recv, 512);
        assert_eq!(s.avg_encrypt_ns, 200);
        assert_eq!(s.encrypt_count, 2);
        assert_eq!(s.active_sessions, 1);
        assert_eq!(s.active_streams, 2);
        assert_eq!(s.rtt_us_path_0, 5_000);
    }
}
