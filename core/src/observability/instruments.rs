//! OpenTelemetry instrument holder.
//!
//! Holds the *synchronous* OTel event instruments — `Counter`s for events,
//! `UpDownCounter`s for the session/stream gauges, and the two latency
//! `Histogram`s. The hot-path packet/byte counters do NOT live here: those
//! are `ObservableCounter`s that read the lock-free atomics on each export
//! tick, registered in `bridge.rs`.
//!
//! Two compilations:
//!
//! - **`telemetry-otel` ON**: the real holder (`otel_on::PhantomInstruments`)
//!   with the concrete `opentelemetry::metrics::*` instruments.
//!
//! - **`telemetry-otel` OFF**: zero-sized type with `#[inline(always)]`
//!   no-op methods. The compiler eliminates every recording call at the
//!   call site, leaving only the underlying atomic increment in
//!   `HotPathAtomics`.

use crate::observability::attrs::*;

#[cfg(feature = "telemetry-otel")]
pub(crate) use otel_on::PhantomInstruments;

#[cfg(not(feature = "telemetry-otel"))]
pub(crate) use otel_off::PhantomInstruments;

// ──────────────────────────────────────────────────────────────────────────
// Feature OFF — zero-sized no-op shim.
// ──────────────────────────────────────────────────────────────────────────

#[cfg(not(feature = "telemetry-otel"))]
mod otel_off {
    use super::*;
    use crate::observability::config::ObservabilityConfig;

    /// Zero-sized OpenTelemetry instrument holder.
    ///
    /// When the `telemetry-otel` Cargo feature is disabled this type takes
    /// up no memory and its methods are unconditionally inlined to
    /// nothing — recording call sites collapse to the underlying atomic
    /// increment with no OTel cost.
    #[derive(Debug, Default)]
    pub(crate) struct PhantomInstruments;

    impl PhantomInstruments {
        #[inline(always)]
        pub(crate) fn new(_config: &ObservabilityConfig) -> Self {
            Self
        }

        #[inline(always)]
        pub(crate) fn record_handshake_duration(
            &self,
            _duration_s: f64,
            _outcome: HandshakeOutcome,
            _leg: crate::transport::types::LegType,
            _cipher: AeadAlgorithm,
            _version: ProtocolVersion,
        ) {
        }
        #[inline(always)]
        pub(crate) fn record_path_validation_duration(
            &self,
            _duration_s: f64,
            _path_id: u8,
            _outcome: PathValidationOutcome,
        ) {
        }
        #[inline(always)]
        pub(crate) fn record_resumption(&self, _mode: ResumptionMode, _accepted: bool) {}
        #[inline(always)]
        pub(crate) fn record_replay_rejected(&self, _reason: ReplayReason) {}
        #[inline(always)]
        pub(crate) fn record_aead_failure(
            &self,
            _leg: crate::transport::types::LegType,
            _algorithm: AeadAlgorithm,
        ) {
        }
        #[inline(always)]
        pub(crate) fn record_unencrypted_dropped(&self, _leg: crate::transport::types::LegType) {}
        #[inline(always)]
        pub(crate) fn record_initial_datagram_on_committed_route(&self) {}
        #[inline(always)]
        pub(crate) fn record_initial_flight_on_committed_route(&self) {}
        #[inline(always)]
        pub(crate) fn record_handshake_flight_repeated(&self) {}
        #[inline(always)]
        pub(crate) fn record_handshake_flight_evicted(&self) {}
        #[inline(always)]
        pub(crate) fn record_handshake_flight_refused(&self) {}
        #[inline(always)]
        pub(crate) fn record_path_migration(&self, _from: u8, _to: u8) {}
        #[inline(always)]
        pub(crate) fn record_cookie(&self, _outcome: CookieOutcome) {}
        #[inline(always)]
        pub(crate) fn record_pow(&self, _outcome: PowOutcome, _difficulty: u8) {}
        #[inline(always)]
        pub(crate) fn record_early_data(&self, _outcome: EarlyDataOutcome) {}
        #[inline(always)]
        pub(crate) fn record_rekey(&self, _direction: Direction) {}
        #[inline(always)]
        pub(crate) fn record_fallback(
            &self,
            _from_leg: crate::transport::types::LegType,
            _to_leg: crate::transport::types::LegType,
            _reason: FallbackReason,
        ) {
        }
        #[inline(always)]
        pub(crate) fn session_opened(&self, _leg: crate::transport::types::LegType) {}
        #[inline(always)]
        pub(crate) fn session_closed(&self, _leg: crate::transport::types::LegType) {}
        #[inline(always)]
        pub(crate) fn stream_opened(&self) {}
        #[inline(always)]
        pub(crate) fn stream_closed(&self) {}
    }
}

// ──────────────────────────────────────────────────────────────────────────
// Feature ON — real OTel instrument holder.
// ──────────────────────────────────────────────────────────────────────────

#[cfg(feature = "telemetry-otel")]
mod otel_on {
    use super::*;
    use crate::observability::config::ObservabilityConfig;
    use opentelemetry::metrics::{Counter, Histogram, UpDownCounter};
    use opentelemetry::KeyValue;

    /// OpenTelemetry instrument holder (counters, gauges, histograms).
    ///
    /// Hot-path packet/byte counters are NOT here — those are
    /// `ObservableCounter`s registered against the atomics in
    /// `bridge.rs`. This holder carries the synchronous event instruments.
    ///
    /// Handshake *count* is intentionally not a standalone counter: the
    /// `handshake_duration` `Histogram` already emits a `_count` series
    /// (sliced by the same `outcome` attribute), so a separate
    /// `handshake.attempts` counter would double-represent the same event.
    #[derive(Debug)]
    pub(crate) struct PhantomInstruments {
        resumptions: Counter<u64>,

        // Security signals (cold path; all marked #[cold] at call sites).
        replay_rejected: Counter<u64>,
        aead_failed: Counter<u64>,
        unencrypted_dropped: Counter<u64>,
        /// The same event in two units, kept apart because one of them is comparable with
        /// `handshake_flight_repeated` below and the other is not: `_datagrams_` counts
        /// wire arrivals (three per fragmented hello), `_flights_` counts questions asked.
        /// No attributes at all on either: the only attribution worth having would be per
        /// peer, which the cardinality contract in `attrs.rs` forbids.
        initial_datagrams_on_committed_route: Counter<u64>,
        initial_flights_on_committed_route: Counter<u64>,
        /// Retained reply flights actually repeated, and retained reply flights dropped to
        /// make room for a newer one. Unlabeled for the same reason as the counters above.
        handshake_flight_repeated: Counter<u64>,
        handshake_flight_evicted: Counter<u64>,
        handshake_flight_refused: Counter<u64>,

        // Path lifecycle.
        path_migrations: Counter<u64>,

        // Session lifecycle.
        rekey: Counter<u64>,
        early_data: Counter<u64>,
        fallback: Counter<u64>,

        // DoS gate.
        cookie: Counter<u64>,
        pow: Counter<u64>,

        // Gauges.
        active_sessions: UpDownCounter<i64>,
        active_streams: UpDownCounter<i64>,

        // Latency histograms (seconds). Bucket boundaries come from
        // `ObservabilityConfig::histogram` and are applied directly on the
        // instrument via `.with_boundaries(...)`.
        handshake_duration: Histogram<f64>,
        path_validation_duration: Histogram<f64>,
    }

    impl PhantomInstruments {
        pub(crate) fn new(config: &ObservabilityConfig) -> Self {
            let meter = opentelemetry::global::meter("phantom_protocol");
            let ns = config.namespace.as_ref();

            // Counters
            let resumptions = meter
                .u64_counter(format!("{ns}.handshake.resumptions"))
                .with_description("Handshake resumption ticket usage")
                .build();
            let replay_rejected = meter
                .u64_counter(format!("{ns}.security.replay_rejected"))
                .with_description("Packets rejected by the replay window")
                .build();
            let aead_failed = meter
                .u64_counter(format!("{ns}.security.aead_failed"))
                .with_description("AEAD authentication failures (tag mismatch)")
                .build();
            let unencrypted_dropped = meter
                .u64_counter(format!("{ns}.security.unencrypted_dropped"))
                .with_description("Non-empty post-handshake packets dropped because the ENCRYPTED flag was absent")
                .build();
            let initial_datagrams_on_committed_route = meter
                .u64_counter(format!(
                    "{ns}.handshake.initial_datagrams_on_committed_route"
                ))
                .with_description(
                    "Handshake-type datagrams arriving on a connection already routed — the \
                     wire cost of clients repeating themselves, several per repeated flight. \
                     Not comparable with flight_repeated; use \
                     initial_flights_on_committed_route for that",
                )
                .build();
            let initial_flights_on_committed_route = meter
                .u64_counter(format!("{ns}.handshake.initial_flights_on_committed_route"))
                .with_description(
                    "Reassembled handshake messages arriving on a connection already routed — \
                     one per question a client asked again because it has not seen the reply. \
                     The half that pairs with flight_repeated",
                )
                .build();
            let handshake_flight_repeated = meter
                .u64_counter(format!("{ns}.handshake.flight_repeated"))
                .with_description(
                    "Retained server reply flights repeated in answer to a client's repeated \
                     hello",
                )
                .build();
            let handshake_flight_evicted = meter
                .u64_counter(format!("{ns}.handshake.flight_evicted"))
                .with_description(
                    "Retained server reply flights dropped to make room for a newer one — the \
                     reply repair running out of its memory budget",
                )
                .build();
            let handshake_flight_refused = meter
                .u64_counter(format!("{ns}.handshake.flight_refused"))
                .with_description(
                    "Server reply flights never retained, because repeating one would exceed \
                     the RFC 9000 §8.2 amplification limit — the reply repair not arming at all",
                )
                .build();
            let path_migrations = meter
                .u64_counter(format!("{ns}.path.migrations"))
                .with_description("Successful multi-path migrations")
                .build();
            let rekey = meter
                .u64_counter(format!("{ns}.session.rekey"))
                .with_description("Per-direction traffic-key rotations")
                .build();
            let early_data = meter
                .u64_counter(format!("{ns}.session.early_data"))
                .with_description("0-RTT early-data attempts by outcome")
                .build();
            let fallback = meter
                .u64_counter(format!("{ns}.transport.fallback"))
                .with_description("Multi-leg transport fallbacks")
                .build();
            let cookie = meter
                .u64_counter(format!("{ns}.security.cookie"))
                .with_description("Stateless cookie issuance and validation")
                .build();
            let pow = meter
                .u64_counter(format!("{ns}.security.pow"))
                .with_description("Proof-of-work challenge outcomes")
                .build();

            // Gauges (UpDownCounter: increments on open, decrements on close).
            let active_sessions = meter
                .i64_up_down_counter(format!("{ns}.session.active"))
                .with_description("Currently active sessions")
                .build();
            let active_streams = meter
                .i64_up_down_counter(format!("{ns}.session.streams.active"))
                .with_description("Currently active streams across all sessions")
                .build();

            // Latency histograms (unit: seconds). Explicit bucket
            // boundaries from the config — see `HistogramConfig`.
            let boundaries = config.histogram.boundaries.clone();
            let handshake_duration = meter
                .f64_histogram(format!("{ns}.handshake.duration"))
                .with_description("Handshake latency end-to-end")
                .with_unit("s")
                .with_boundaries(boundaries.clone())
                .build();
            let path_validation_duration = meter
                .f64_histogram(format!("{ns}.path.validation.duration"))
                .with_description("PATH_VALIDATION challenge / response latency")
                .with_unit("s")
                .with_boundaries(boundaries)
                .build();

            Self {
                resumptions,
                replay_rejected,
                aead_failed,
                unencrypted_dropped,
                initial_datagrams_on_committed_route,
                initial_flights_on_committed_route,
                handshake_flight_repeated,
                handshake_flight_evicted,
                handshake_flight_refused,
                path_migrations,
                rekey,
                early_data,
                fallback,
                cookie,
                pow,
                active_sessions,
                active_streams,
                handshake_duration,
                path_validation_duration,
            }
        }

        // --- Recording API ---

        pub(crate) fn record_resumption(&self, mode: ResumptionMode, accepted: bool) {
            self.resumptions.add(
                1,
                &[
                    KeyValue::new("mode", mode.as_str()),
                    KeyValue::new("accepted", accepted),
                ],
            );
        }

        #[cold]
        pub(crate) fn record_replay_rejected(&self, reason: ReplayReason) {
            self.replay_rejected
                .add(1, &[KeyValue::new("reason", reason.as_str())]);
        }

        #[cold]
        pub(crate) fn record_aead_failure(
            &self,
            leg: crate::transport::types::LegType,
            algorithm: AeadAlgorithm,
        ) {
            self.aead_failed.add(
                1,
                &[
                    KeyValue::new("leg", leg_str(leg)),
                    KeyValue::new("algorithm", algorithm.as_str()),
                ],
            );
        }

        #[cold]
        pub(crate) fn record_unencrypted_dropped(&self, leg: crate::transport::types::LegType) {
            self.unencrypted_dropped
                .add(1, &[KeyValue::new("leg", leg_str(leg))]);
        }

        #[cold]
        pub(crate) fn record_initial_datagram_on_committed_route(&self) {
            self.initial_datagrams_on_committed_route.add(1, &[]);
        }

        #[cold]
        pub(crate) fn record_initial_flight_on_committed_route(&self) {
            self.initial_flights_on_committed_route.add(1, &[]);
        }

        #[cold]
        pub(crate) fn record_handshake_flight_repeated(&self) {
            self.handshake_flight_repeated.add(1, &[]);
        }

        #[cold]
        pub(crate) fn record_handshake_flight_evicted(&self) {
            self.handshake_flight_evicted.add(1, &[]);
        }

        #[cold]
        pub(crate) fn record_handshake_flight_refused(&self) {
            self.handshake_flight_refused.add(1, &[]);
        }

        pub(crate) fn record_path_migration(&self, from: u8, to: u8) {
            self.path_migrations.add(
                1,
                &[
                    KeyValue::new("from_path", from as i64),
                    KeyValue::new("to_path", to as i64),
                ],
            );
        }

        pub(crate) fn record_cookie(&self, outcome: CookieOutcome) {
            self.cookie
                .add(1, &[KeyValue::new("outcome", outcome.as_str())]);
        }

        pub(crate) fn record_pow(&self, outcome: PowOutcome, difficulty: u8) {
            self.pow.add(
                1,
                &[
                    KeyValue::new("outcome", outcome.as_str()),
                    KeyValue::new("difficulty", difficulty as i64),
                ],
            );
        }

        pub(crate) fn record_early_data(&self, outcome: EarlyDataOutcome) {
            self.early_data
                .add(1, &[KeyValue::new("outcome", outcome.as_str())]);
        }

        pub(crate) fn record_rekey(&self, direction: Direction) {
            self.rekey
                .add(1, &[KeyValue::new("direction", direction.as_str())]);
        }

        pub(crate) fn record_fallback(
            &self,
            from_leg: crate::transport::types::LegType,
            to_leg: crate::transport::types::LegType,
            reason: FallbackReason,
        ) {
            self.fallback.add(
                1,
                &[
                    KeyValue::new("from_leg", leg_str(from_leg)),
                    KeyValue::new("to_leg", leg_str(to_leg)),
                    KeyValue::new("reason", reason.as_str()),
                ],
            );
        }

        pub(crate) fn session_opened(&self, leg: crate::transport::types::LegType) {
            self.active_sessions
                .add(1, &[KeyValue::new("leg", leg_str(leg))]);
        }

        pub(crate) fn session_closed(&self, leg: crate::transport::types::LegType) {
            self.active_sessions
                .add(-1, &[KeyValue::new("leg", leg_str(leg))]);
        }

        pub(crate) fn stream_opened(&self) {
            self.active_streams.add(1, &[]);
        }

        pub(crate) fn stream_closed(&self) {
            self.active_streams.add(-1, &[]);
        }

        /// Record handshake completion latency into the
        /// `{ns}.handshake.duration` histogram.
        ///
        /// Exemplar note: when the embedder configures an exemplar
        /// reservoir on the SDK (not on by default in `opentelemetry_sdk`
        /// 0.32) and this call happens inside an active `tracing` span,
        /// the observation carries that span's `trace_id` — enabling a
        /// Grafana → Tempo drill-down. Without reservoir configuration the
        /// histogram still records normally, just without exemplars.
        pub(crate) fn record_handshake_duration(
            &self,
            duration_s: f64,
            outcome: HandshakeOutcome,
            leg: crate::transport::types::LegType,
            cipher: AeadAlgorithm,
            version: ProtocolVersion,
        ) {
            self.handshake_duration.record(
                duration_s,
                &[
                    KeyValue::new("outcome", outcome.as_str()),
                    KeyValue::new("leg", leg_str(leg)),
                    KeyValue::new("cipher_suite", cipher.as_str()),
                    KeyValue::new("version", version.as_str()),
                ],
            );
        }

        pub(crate) fn record_path_validation_duration(
            &self,
            duration_s: f64,
            path_id: u8,
            outcome: PathValidationOutcome,
        ) {
            self.path_validation_duration.record(
                duration_s,
                &[
                    KeyValue::new("path_id", path_id as i64),
                    KeyValue::new("outcome", outcome.as_str()),
                ],
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observability::config::ObservabilityConfig;

    #[test]
    fn instruments_constructible_in_both_feature_modes() {
        let cfg = ObservabilityConfig::default();
        let _i = PhantomInstruments::new(&cfg);
    }

    #[cfg(not(feature = "telemetry-otel"))]
    #[test]
    fn no_op_holder_is_zero_sized() {
        use std::mem::size_of;
        assert_eq!(size_of::<PhantomInstruments>(), 0);
    }
}
