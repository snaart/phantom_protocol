//! Phantom Protocol observability subsystem.
//!
//! Replaced the Phase 4.5 hand-rolled metrics module (`transport::metrics`),
//! which has since been deleted. Lock-free hot-path atomics for per-packet
//! recording plus opt-in OpenTelemetry instruments (metrics + traces) gated
//! behind the `telemetry-otel` Cargo feature.
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
pub use snapshot::{MetricsSnapshot, MetricsSnapshotFfi};

use crate::transport::types::LegType;
use atomics::HotPathAtomics;
use instruments::PhantomInstruments;
use std::sync::Arc;

/// Public observability facade.
///
/// Wraps the lock-free atomic counters (always present) and the opt-in
/// OpenTelemetry instrument holder — metrics + traces, active when the
/// `telemetry-otel` Cargo feature is enabled and a zero-cost ZST otherwise.
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

    /// Record a successful handshake completion with its duration (ns) into
    /// the lock-free atomics only — no OTel attribution.
    ///
    /// This is the snapshot-only path: the duration accumulates in atomic
    /// sum+count fields surfaced via [`Self::snapshot`]. Callers that also
    /// want the labeled OTel `Histogram` use [`Self::record_handshake`]
    /// (which calls this internally for the success case).
    pub fn record_handshake_success(&self, duration_ns: u64) {
        self.atomics.record_handshake_success(duration_ns);
    }

    /// Record a handshake failure into the lock-free atomics only.
    ///
    /// Cause attribution (cookie / signature / transcript / KEM) is carried
    /// by the labeled OTel path in [`Self::record_handshake`], not here.
    #[inline]
    pub fn record_handshake_failure(&self) {
        self.atomics.record_handshake_failure();
    }

    // --- Labeled OTel event recorders ---

    /// Record a handshake outcome and its latency with full OTel
    /// attribution. The lock-free atomic counters and the OTel
    /// `Histogram` (`{ns}.handshake.duration`) are updated together; the
    /// histogram's `_count` series — sliced by the `outcome` attribute —
    /// is the canonical handshake count, so there is no separate counter.
    ///
    /// **`outcome = Success` is this side's own completion and says nothing about
    /// whether the peer received the reply.** The server records it once it has
    /// derived keys and sent its `ServerHello`, which is not acknowledged by
    /// anything — so a reply lost on the way down leaves a session counted here as
    /// a success that the peer never joined, and one live run held such a session
    /// open for 135 s having neither sent nor received a byte. A server's success
    /// total exceeding a client's is therefore an ordinary reading of a lossy path
    /// rather than a contradiction, and it is the whole reason the two sides are
    /// counted separately.
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
        self.atomics.record_replay_rejected();
        self.instruments.record_replay_rejected(reason);
    }

    #[inline]
    pub fn record_aead_failure(&self, leg: LegType, algorithm: AeadAlgorithm) {
        self.atomics.record_aead_failure();
        self.instruments.record_aead_failure(leg, algorithm);
    }

    #[inline]
    pub fn record_unencrypted_dropped(&self, leg: LegType) {
        self.atomics.record_unencrypted_dropped();
        self.instruments.record_unencrypted_dropped(leg);
    }

    /// **Unit: one datagram.** Record a handshake-type *datagram* arriving on a connection
    /// the PhantomUDP listener has already committed a route to, as it lands and before
    /// reassembly (PROTOCOL § 6.1).
    ///
    /// What it measures is the duplicate wire load a repeating client puts on the listener —
    /// a cookie-bearing hello is three fragments, so one repeated question moves this by
    /// three. **It is not the half to read against
    /// [`record_handshake_flight_repeated`]**, which counts flights; that comparison is off
    /// by the fragment count and reads as answers gone missing.
    /// [`record_initial_flight_on_committed_route`] is the half that pairs with it.
    ///
    /// Deliberately unlabeled: the interesting attribute would be which peer is repeating,
    /// and peer identity is exactly what the cardinality contract in
    /// [`attrs`] module keeps out of instrument labels.
    ///
    /// [`record_handshake_flight_repeated`]: Self::record_handshake_flight_repeated
    /// [`record_initial_flight_on_committed_route`]: Self::record_initial_flight_on_committed_route
    /// [`attrs`]: crate::observability::attrs
    #[inline]
    pub fn record_initial_datagram_on_committed_route(&self) {
        self.atomics.record_initial_datagram_on_committed_route();
        self.instruments
            .record_initial_datagram_on_committed_route();
    }

    /// **Unit: one flight.** Record a *reassembled* handshake message arriving on a
    /// connection the PhantomUDP listener has already committed a route to — one per
    /// question the client asked again, however many datagrams carried it (PROTOCOL § 6.1).
    ///
    /// **Meant to be read together with [`record_handshake_flight_repeated`], and in the
    /// same unit as it**: this one says a client asked again, that one says an answer went
    /// back. Unlabeled for the same reason as the datagram counter above.
    ///
    /// [`record_handshake_flight_repeated`]: Self::record_handshake_flight_repeated
    #[inline]
    pub fn record_initial_flight_on_committed_route(&self) {
        self.atomics.record_initial_flight_on_committed_route();
        self.instruments.record_initial_flight_on_committed_route();
    }

    /// **Unit: one flight.** Record a retained reply flight actually being repeated
    /// (PROTOCOL § 6.1) — one per repeat sent, not per datagram of it.
    ///
    /// **Meant to be read together with [`record_initial_flight_on_committed_route`], which
    /// is in the same unit**: that one says a client asked again, this one says the listener
    /// had an answer and sent it. Kept apart because the two failures they separate need
    /// opposite remedies: questions arriving with no answers going back is a listener whose
    /// retention did not cover the session, while questions never arriving at all is a path
    /// that went silent upstream. A single counter reads identically in both.
    ///
    /// [`record_initial_flight_on_committed_route`]: Self::record_initial_flight_on_committed_route
    #[inline]
    pub fn record_handshake_flight_repeated(&self) {
        self.atomics.record_handshake_flight_repeated();
        self.instruments.record_handshake_flight_repeated();
    }

    /// Record a retained reply flight dropped to make room for a newer one (PROTOCOL § 6.1).
    ///
    /// The repair holds a bounded amount of memory; past it the oldest answer goes so the
    /// newest can be kept. An evicted session is back to the behaviour that made a single
    /// lost reply datagram cost a whole connect, and nothing else on either side of that
    /// connect would say so — which is why the eviction is counted rather than merely done.
    #[inline]
    pub fn record_handshake_flight_evicted(&self) {
        self.atomics.record_handshake_flight_evicted();
        self.instruments.record_handshake_flight_evicted();
    }

    /// Record a reply flight that was never retained, because repeating it would have
    /// exceeded the RFC 9000 § 8.2 amplification limit (PROTOCOL § 6.1 rule 3).
    ///
    /// The third of the three ways the repair can fail to cover a session, and the only one
    /// that is not about load: an eviction and an expiry both mean the mechanism ran, while
    /// a refusal means it never armed. It cannot fire with today's messages, so a non-zero
    /// value is a message size having moved past the bound — a change that alters no
    /// serialized byte a peer would notice and that nothing else reports.
    #[inline]
    pub fn record_handshake_flight_refused(&self) {
        self.atomics.record_handshake_flight_refused();
        self.instruments.record_handshake_flight_refused();
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
    fn security_counters_surface_through_snapshot() {
        let obs = Observability::new(ObservabilityConfig::default());
        let s = obs.snapshot();
        assert_eq!(s.replay_rejected_total, 0);
        assert_eq!(s.aead_failure_total, 0);
        assert_eq!(s.unencrypted_dropped_total, 0);
        assert_eq!(s.initial_datagrams_on_committed_route_total, 0);
        assert_eq!(s.initial_flights_on_committed_route_total, 0);
        assert_eq!(s.handshake_flight_repeated_total, 0);
        assert_eq!(s.handshake_flight_evicted_total, 0);
        assert_eq!(s.handshake_flight_refused_total, 0);

        obs.record_replay_rejected(ReplayReason::Duplicate);
        obs.record_replay_rejected(ReplayReason::Duplicate);
        obs.record_aead_failure(LegType::Tcp, AeadAlgorithm::Aes256Gcm);
        obs.record_unencrypted_dropped(LegType::Tcp);
        // Three datagrams carrying the one flight that was then answered — the shape a
        // fragmented repeat produces, and the reason the first two are not one counter.
        obs.record_initial_datagram_on_committed_route();
        obs.record_initial_datagram_on_committed_route();
        obs.record_initial_datagram_on_committed_route();
        obs.record_initial_flight_on_committed_route();
        obs.record_handshake_flight_repeated();
        obs.record_handshake_flight_evicted();
        obs.record_handshake_flight_evicted();
        obs.record_handshake_flight_refused();
        obs.record_handshake_flight_refused();
        obs.record_handshake_flight_refused();

        let s = obs.snapshot();
        assert_eq!(s.replay_rejected_total, 2);
        assert_eq!(s.aead_failure_total, 1);
        assert_eq!(s.unencrypted_dropped_total, 1);
        assert_eq!(s.initial_datagrams_on_committed_route_total, 3);
        assert_eq!(s.initial_flights_on_committed_route_total, 1);
        assert_eq!(s.handshake_flight_repeated_total, 1);
        assert_eq!(s.handshake_flight_evicted_total, 2);
        assert_eq!(s.handshake_flight_refused_total, 3);
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
