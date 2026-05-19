//! OpenTelemetry instrument holder.
//!
//! Two compilations:
//!
//! - **`telemetry-otel` ON**: holds concrete `opentelemetry::metrics::*`
//!   instruments. Construction calls `opentelemetry::global::meter(...)`.
//!   Step 7 of the rollout fills the fields with `Counter` / `Histogram` /
//!   `UpDownCounter` instances and binds them to recording-API methods.
//!
//! - **`telemetry-otel` OFF**: zero-sized type with `#[inline(always)]`
//!   no-op methods. The compiler eliminates every recording call at the
//!   call site, leaving only the atomic increment in `HotPathAtomics`.
//!
//! See `docs/observability/refactor-plan.md` §3 ("Recording API") for the
//! intended public surface.

#[cfg(feature = "telemetry-otel")]
pub(crate) use otel_on::PhantomInstruments;

#[cfg(not(feature = "telemetry-otel"))]
pub(crate) use otel_off::PhantomInstruments;

// ──────────────────────────────────────────────────────────────────────────
// Feature OFF — zero-sized no-op shim.
// ──────────────────────────────────────────────────────────────────────────

#[cfg(not(feature = "telemetry-otel"))]
mod otel_off {
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
    }
}

// ──────────────────────────────────────────────────────────────────────────
// Feature ON — real OTel instrument holder. Step 6 is the scaffold only;
// step 7 populates the fields and wires recording-API methods.
// ──────────────────────────────────────────────────────────────────────────

#[cfg(feature = "telemetry-otel")]
mod otel_on {
    use crate::observability::config::ObservabilityConfig;

    /// OpenTelemetry instrument holder.
    ///
    /// In step 6 of the rollout this struct is a scaffold — it accepts the
    /// configuration and obtains a `Meter` from the global provider but
    /// does not yet construct any instruments. Step 7 fills in the
    /// `Counter` / `Histogram` / `UpDownCounter` fields and wires the
    /// recording-API methods.
    #[derive(Debug)]
    pub(crate) struct PhantomInstruments {
        // Step 7 will populate concrete instrument fields here.
        // For now the holder just remembers the namespace so subsequent
        // construction can prefix instrument names correctly.
        _namespace: std::sync::Arc<str>,
    }

    impl PhantomInstruments {
        pub(crate) fn new(config: &ObservabilityConfig) -> Self {
            let _meter = opentelemetry::global::meter("phantom_core");
            Self {
                _namespace: std::sync::Arc::from(config.namespace.as_ref()),
            }
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
