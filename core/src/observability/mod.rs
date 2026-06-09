//! Phantom Protocol observability subsystem.
//!
//! Replaces the Phase 4.5 hand-rolled metrics module (`transport::metrics`).
//! Lock-free hot-path atomics for per-packet recording plus opt-in
//! OpenTelemetry instruments (metrics + traces) gated behind the
//! `telemetry-otel` Cargo feature.
//!
//! See `docs/observability/refactor-plan.md` for the full design and
//! `docs/observability/metrics-catalog.md` for the instrument inventory.
//! This file is the public module surface; concrete types live in the
//! submodules below.
//!
//! ## Layout
//!
//! - `atomics` — lock-free hot-path counters (`HotPathAtomics`).
//! - [`config`] — [`ObservabilityConfig`] (namespace, histogram buckets).
//! - `instruments` — OTel instrument holder; ZST no-op when the feature
//!   is off.
//! - `bridge` — registers `ObservableCounter` callbacks over the atomics.
//! - [`attrs`] — typed attribute-value enums (the cardinality contract).
//! - [`snapshot`] — [`MetricsSnapshot`], a cold-path read for FFI / debug.

pub(crate) mod atomics;
pub mod attrs;
pub(crate) mod bridge;
pub mod config;
pub(crate) mod instruments;
pub mod snapshot;

pub use attrs::{
    leg_str, AeadAlgorithm, CookieOutcome, Direction, EarlyDataOutcome, FallbackReason,
    HandshakeOutcome, PathValidationOutcome, PowOutcome, ProtocolVersion, ReplayReason,
    ResumptionMode,
};
pub use config::{HistogramConfig, ObservabilityConfig, ObservabilityConfigBuilder};
pub use snapshot::MetricsSnapshot;

use crate::transport::types::LegType;
use atomics::HotPathAtomics;
use instruments::PhantomInstruments;
use std::sync::Arc;

/// Public observability facade.
///
/// Wraps the lock-free atomic counters (always present) and — in later
/// rollout steps — the feature-gated OpenTelemetry instrument holder.
/// Recording sites in `transport`, `api`, and `crypto` call methods on this
/// struct via an `Arc<Observability>` borrowed from `PhantomListener` /
/// `PhantomSession`.
#[derive(Debug)]
pub struct Observability {
    config: ObservabilityConfig,
    atomics: Arc<HotPathAtomics>,
    instruments: PhantomInstruments,
}

impl Observability {
    /// Construct a new observability handle.
    ///
    /// Returns an `Arc` because the handle is shared between recording sites
    /// (in `Session`, `Listener`, handshake code paths) and the OTel
    /// observable callbacks.
    ///
    /// **Call once per process.** When `telemetry-otel` is on, this
    /// registers observable-instrument callbacks against the *global* OTel
    /// meter; those callbacks are never unregistered (the meter owns them
    /// for process life). Constructing many `Observability` instances would
    /// therefore accumulate callbacks. `PhantomListener` / `PhantomSession`
    /// each hold one shared `Arc<Observability>` — that is the intended
    /// usage.
    pub fn new(config: ObservabilityConfig) -> Arc<Self> {
        let instruments = PhantomInstruments::new(&config);
        let atomics = Arc::new(HotPathAtomics::new());
        // Register OTel observable callbacks that read the atomic counters
        // on each export tick. The atomics live behind `Arc` so the
        // callbacks own a strong ref independent of `Observability`'s
        // lifetime.
        bridge::register_observables(&atomics, &config);
        Arc::new(Self {
            config,
            atomics,
            instruments,
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

    /// Mark a new session as opened. Updates both the lock-free gauge and
    /// the OTel `UpDownCounter` (when the `telemetry-otel` feature is on).
    #[inline]
    pub fn session_opened(&self, leg: LegType) {
        self.atomics.session_opened();
        self.instruments.session_opened(leg);
    }

    #[inline]
    pub fn session_closed(&self, leg: LegType) {
        self.atomics.session_closed();
        self.instruments.session_closed(leg);
    }

    #[inline]
    pub fn stream_opened(&self) {
        self.atomics.stream_opened();
        self.instruments.stream_opened();
    }

    #[inline]
    pub fn stream_closed(&self) {
        self.atomics.stream_closed();
        self.instruments.stream_closed();
    }

    /// Record a successful handshake completion with its duration (ns).
    ///
    /// Transitional API — step 7 introduces a labeled `record_handshake`
    /// that takes `(outcome, leg, cipher_suite, version)` and writes to an
    /// OTel `Histogram`. Until then, the duration accumulates in atomic
    /// sum+count fields surfaced via [`Self::snapshot`].
    pub fn record_handshake_success(&self, duration_ns: u64) {
        self.atomics.record_handshake_success(duration_ns);
    }

    /// Record a handshake failure. Cause attribution (cookie / signature /
    /// transcript / KEM) lands with the labeled API in step 7.
    #[inline]
    pub fn record_handshake_failure(&self) {
        self.atomics.record_handshake_failure();
    }

    // --- Labeled OTel event recorders (step 7) ---

    /// Record a handshake outcome and its latency with full OTel
    /// attribution. The lock-free atomic counters and the OTel
    /// `Histogram` (`{ns}.handshake.duration`) are updated together; the
    /// histogram's `_count` series — sliced by the `outcome` attribute —
    /// is the canonical handshake count, so there is no separate counter.
    pub fn record_handshake(
        &self,
        duration: std::time::Duration,
        outcome: HandshakeOutcome,
        leg: LegType,
        cipher: AeadAlgorithm,
        version: ProtocolVersion,
    ) {
        let duration_ns = u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX);
        match outcome {
            HandshakeOutcome::Success => self.atomics.record_handshake_success(duration_ns),
            HandshakeOutcome::Failure => self.atomics.record_handshake_failure(),
        }
        self.instruments.record_handshake_duration(
            duration.as_secs_f64(),
            outcome,
            leg,
            cipher,
            version,
        );
    }

    /// Record a `PATH_VALIDATION` exchange latency.
    pub fn record_path_validation(
        &self,
        duration: std::time::Duration,
        path_id: u8,
        outcome: PathValidationOutcome,
    ) {
        self.instruments
            .record_path_validation_duration(duration.as_secs_f64(), path_id, outcome);
    }

    pub fn record_resumption(&self, mode: ResumptionMode, accepted: bool) {
        self.instruments.record_resumption(mode, accepted);
    }

    #[inline]
    pub fn record_replay_rejected(&self, reason: ReplayReason) {
        self.instruments.record_replay_rejected(reason);
    }

    #[inline]
    pub fn record_aead_failure(&self, leg: LegType, algorithm: AeadAlgorithm) {
        self.instruments.record_aead_failure(leg, algorithm);
    }

    #[inline]
    pub fn record_unencrypted_dropped(&self, leg: LegType) {
        self.instruments.record_unencrypted_dropped(leg);
    }

    pub fn record_path_migration(&self, from: u8, to: u8) {
        self.instruments.record_path_migration(from, to);
    }

    pub fn record_cookie(&self, outcome: CookieOutcome) {
        self.instruments.record_cookie(outcome);
    }

    pub fn record_pow(&self, outcome: PowOutcome, difficulty: u8) {
        self.instruments.record_pow(outcome, difficulty);
    }

    pub fn record_early_data(&self, outcome: EarlyDataOutcome) {
        self.instruments.record_early_data(outcome);
    }

    pub fn record_rekey(&self, direction: Direction) {
        self.instruments.record_rekey(direction);
    }

    pub fn record_fallback(&self, from_leg: LegType, to_leg: LegType, reason: FallbackReason) {
        self.instruments.record_fallback(from_leg, to_leg, reason);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_observability_has_default_config() {
        let obs = Observability::new(ObservabilityConfig::default());
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
        let obs = Observability::new(ObservabilityConfig::default());
        obs.record_send(1024, LegType::Tcp);
        obs.record_send(2048, LegType::Tcp);
        obs.record_recv(512, LegType::Kcp);
        obs.record_encrypt_ns(100);
        obs.record_encrypt_ns(300);
        obs.session_opened(LegType::Tcp);
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
