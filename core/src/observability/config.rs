//! Observability configuration.
//!
//! Configuration is captured at `Observability::new` time and frozen for the
//! lifetime of the instance. The values it carries (namespace prefix,
//! histogram bucket boundaries) are formatted into instrument names and
//! applied to instruments on construction, so freezing avoids per-call cost.
//!
//! Env-var conventions follow the OpenTelemetry SDK spec where applicable,
//! with `PHANTOM_TELEMETRY_*` for project-specific knobs. See
//! `docs/observability/refactor-plan.md` §7 for the full ENV reference.

use std::borrow::Cow;

/// Observability configuration.
///
/// Cheap to construct, `Clone`-able, and `Send + Sync`. The captured
/// `namespace` is used as a prefix for every OTel instrument name
/// (`"{namespace}.session.packets"`, etc.). Default prefix is `"phantom"`.
#[derive(Debug, Clone)]
pub struct ObservabilityConfig {
    /// Instrument-name prefix. Default `"phantom"`.
    ///
    /// Populated from `PHANTOM_TELEMETRY_NAMESPACE` by [`Self::from_env`].
    ///
    /// Note: this prefixes **metric instrument names** only. `tracing`
    /// span names are compile-time string literals (`phantom.handshake.*`,
    /// `phantom.listener.*`) and are not affected by this knob.
    pub namespace: Cow<'static, str>,

    /// Bucket boundaries for latency instruments
    /// (`handshake.duration`, `path.validation.duration`).
    pub histogram: HistogramConfig,
}

/// Explicit bucket boundaries (in seconds) for latency histograms
/// (`{ns}.handshake.duration`, `{ns}.path.validation.duration`).
///
/// Applied directly to the OTel `Histogram` instrument via
/// `f64_histogram(...).with_boundaries(...)` — a version-stable API across
/// the `opentelemetry` 0.27–0.29 line. (Base-2 exponential aggregation
/// would need an SDK View; the View API is still in flux across these
/// versions, so explicit boundaries are the supported choice for now.)
#[derive(Debug, Clone)]
pub struct HistogramConfig {
    /// Bucket upper bounds, seconds, ascending.
    pub boundaries: Vec<f64>,
}

impl Default for HistogramConfig {
    fn default() -> Self {
        // Latency-tuned for a post-quantum handshake: ~2-50 ms typical,
        // up to multi-second under PoW back-pressure / CPU saturation.
        Self {
            boundaries: vec![
                0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0,
            ],
        }
    }
}

impl Default for ObservabilityConfig {
    fn default() -> Self {
        Self {
            namespace: Cow::Borrowed("phantom"),
            histogram: HistogramConfig::default(),
        }
    }
}

impl ObservabilityConfig {
    /// Construct a config from environment variables. Unset or empty
    /// variables fall back to defaults.
    ///
    /// To disable telemetry at runtime, build without the `telemetry-otel`
    /// Cargo feature, or simply do not point `OTEL_EXPORTER_OTLP_ENDPOINT`
    /// at a reachable collector — the SDK's bounded export queue then drops
    /// telemetry at near-zero cost.
    pub fn from_env() -> Self {
        let namespace = std::env::var("PHANTOM_TELEMETRY_NAMESPACE")
            .ok()
            .filter(|s| !s.is_empty())
            .map(Cow::Owned)
            .unwrap_or(Cow::Borrowed("phantom"));
        Self {
            namespace,
            histogram: HistogramConfig::default(),
        }
    }

    /// Begin a programmatic builder for [`ObservabilityConfig`].
    pub fn builder() -> ObservabilityConfigBuilder {
        ObservabilityConfigBuilder::default()
    }
}

/// Builder for [`ObservabilityConfig`].
#[derive(Debug, Default)]
pub struct ObservabilityConfigBuilder {
    namespace: Option<Cow<'static, str>>,
    histogram: Option<HistogramConfig>,
}

impl ObservabilityConfigBuilder {
    /// Override the instrument-name prefix.
    pub fn namespace<S: Into<Cow<'static, str>>>(mut self, ns: S) -> Self {
        self.namespace = Some(ns.into());
        self
    }

    /// Override the histogram bucket boundaries.
    pub fn histogram(mut self, h: HistogramConfig) -> Self {
        self.histogram = Some(h);
        self
    }

    /// Finalize the configuration.
    pub fn build(self) -> ObservabilityConfig {
        let mut cfg = ObservabilityConfig::default();
        if let Some(ns) = self.namespace {
            cfg.namespace = ns;
        }
        if let Some(h) = self.histogram {
            cfg.histogram = h;
        }
        cfg
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_namespace_is_phantom() {
        let cfg = ObservabilityConfig::default();
        assert_eq!(cfg.namespace.as_ref(), "phantom");
        // Default histogram boundaries are ascending and non-empty.
        let b = &cfg.histogram.boundaries;
        assert!(!b.is_empty());
        assert!(b.windows(2).all(|w| w[0] < w[1]), "boundaries must ascend");
    }

    #[test]
    fn builder_overrides_namespace() {
        let cfg = ObservabilityConfig::builder().namespace("myapp").build();
        assert_eq!(cfg.namespace.as_ref(), "myapp");
    }

    #[test]
    fn builder_overrides_histogram() {
        let cfg = ObservabilityConfig::builder()
            .histogram(HistogramConfig {
                boundaries: vec![0.001, 0.01, 0.1, 1.0],
            })
            .build();
        assert_eq!(cfg.histogram.boundaries.len(), 4);
    }
}
