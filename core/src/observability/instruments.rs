//! OpenTelemetry instrument holder.
//!
//! Two compilations:
//!
//! - **`telemetry-otel` ON**: holds concrete `opentelemetry::metrics::*`
//!   instruments — `Counter`s for events, `UpDownCounter`s for gauges.
//!   Step 8 of the rollout adds `ObservableCounter` / `ObservableGauge`
//!   callbacks reading the hot-path atomics. Step 9 adds the
//!   `phantom.handshake.duration` `Histogram` with exponential bucketing.
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

        #[inline(always)] pub(crate) fn record_handshake(&self, _outcome: HandshakeOutcome, _leg: crate::transport::types::LegType, _cipher: AeadAlgorithm, _version: ProtocolVersion) {}
        #[inline(always)] pub(crate) fn record_resumption(&self, _mode: ResumptionMode, _accepted: bool) {}
        #[inline(always)] pub(crate) fn record_replay_rejected(&self, _reason: ReplayReason) {}
        #[inline(always)] pub(crate) fn record_aead_failure(&self, _leg: crate::transport::types::LegType, _algorithm: AeadAlgorithm) {}
        #[inline(always)] pub(crate) fn record_unencrypted_dropped(&self, _leg: crate::transport::types::LegType) {}
        #[inline(always)] pub(crate) fn record_path_migration(&self, _from: u8, _to: u8) {}
        #[inline(always)] pub(crate) fn record_cookie(&self, _outcome: CookieOutcome) {}
        #[inline(always)] pub(crate) fn record_pow(&self, _outcome: PowOutcome, _difficulty: u8) {}
        #[inline(always)] pub(crate) fn record_early_data(&self, _outcome: EarlyDataOutcome) {}
        #[inline(always)] pub(crate) fn record_rekey(&self, _direction: Direction) {}
        #[inline(always)] pub(crate) fn record_fallback(&self, _from_leg: crate::transport::types::LegType, _to_leg: crate::transport::types::LegType, _reason: FallbackReason) {}
        #[inline(always)] pub(crate) fn session_opened(&self, _leg: crate::transport::types::LegType) {}
        #[inline(always)] pub(crate) fn session_closed(&self, _leg: crate::transport::types::LegType) {}
        #[inline(always)] pub(crate) fn stream_opened(&self) {}
        #[inline(always)] pub(crate) fn stream_closed(&self) {}
    }
}

// ──────────────────────────────────────────────────────────────────────────
// Feature ON — real OTel instrument holder.
// ──────────────────────────────────────────────────────────────────────────

#[cfg(feature = "telemetry-otel")]
mod otel_on {
    use super::*;
    use crate::observability::config::ObservabilityConfig;
    use opentelemetry::metrics::{Counter, UpDownCounter};
    use opentelemetry::KeyValue;

    /// OpenTelemetry instrument holder (counters + gauges).
    ///
    /// Observable instruments (`ObservableCounter` / `ObservableGauge`) for
    /// the hot-path atomics are wired up in step 8 via `with_callback`.
    /// The `phantom.handshake.duration` `Histogram` lands in step 9.
    #[derive(Debug)]
    pub(crate) struct PhantomInstruments {
        // Handshake outcome counter (count by outcome; latency goes to
        // Histogram in step 9).
        handshake: Counter<u64>,
        resumptions: Counter<u64>,

        // Security signals (cold path; all marked #[cold] at call sites).
        replay_rejected: Counter<u64>,
        aead_failed: Counter<u64>,
        unencrypted_dropped: Counter<u64>,

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
    }

    impl PhantomInstruments {
        pub(crate) fn new(config: &ObservabilityConfig) -> Self {
            let meter = opentelemetry::global::meter("phantom_core");
            let ns = config.namespace.as_ref();

            // Counters
            let handshake = meter
                .u64_counter(format!("{ns}.handshake.attempts"))
                .with_description("Handshake attempts by outcome")
                .build();
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

            Self {
                handshake,
                resumptions,
                replay_rejected,
                aead_failed,
                unencrypted_dropped,
                path_migrations,
                rekey,
                early_data,
                fallback,
                cookie,
                pow,
                active_sessions,
                active_streams,
            }
        }

        // --- Recording API ---

        pub(crate) fn record_handshake(
            &self,
            outcome: HandshakeOutcome,
            leg: crate::transport::types::LegType,
            cipher: AeadAlgorithm,
            version: ProtocolVersion,
        ) {
            self.handshake.add(
                1,
                &[
                    KeyValue::new("outcome", outcome.as_str()),
                    KeyValue::new("leg", leg_str(leg)),
                    KeyValue::new("cipher_suite", cipher.as_str()),
                    KeyValue::new("version", version.as_str()),
                ],
            );
        }

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
