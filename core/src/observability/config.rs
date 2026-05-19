//! Observability configuration.
//!
//! Configuration is captured at `Observability::new` time and frozen for the
//! lifetime of the instance. The values it carries (namespace prefix,
//! histogram bucketing strategy, runtime kill-switch) are formatted into
//! instrument names and aggregation views on first use, so freezing avoids
//! per-call cost.
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
    pub namespace: Cow<'static, str>,

    /// Histogram bucketing strategy for latency instruments
    /// (`handshake.duration`, `path.validation.duration`).
    pub histogram: HistogramConfig,

    /// Runtime kill-switch for the OTel pipeline. When `true`, every
    /// recording call short-circuits to a no-op regardless of Cargo
    /// features. Useful for emergency disablement without redeploy.
    ///
    /// Populated from `PHANTOM_TELEMETRY_DISABLED` by [`Self::from_env`]
    /// when the value parses as `"1" | "true" | "TRUE"`.
    pub disable_otel: bool,
}

/// Histogram bucketing strategy.
#[derive(Debug, Clone)]
pub enum HistogramConfig {
    /// Explicit fixed bucket boundaries (in seconds).
    Explicit(Vec<f64>),
    /// Base-2 exponential bucketing — OTel native (OTEP 149). Sparse,
    /// auto-scaling, ~2-3× the precision of fixed buckets at the same wire
    /// size. Requires `opentelemetry_sdk` 0.27+ when the `telemetry-otel`
    /// feature is enabled; falls back to the SDK default otherwise.
    ExponentialBase2 {
        /// Maximum number of buckets (positive + negative ranges combined).
        max_size: u32,
        /// Maximum scale factor; SDK auto-scales below this on heavy spread.
        max_scale: i8,
    },
}

impl Default for HistogramConfig {
    fn default() -> Self {
        // OTel SDK defaults for base-2 exponential histograms.
        Self::ExponentialBase2 {
            max_size: 160,
            max_scale: 20,
        }
    }
}

impl Default for ObservabilityConfig {
    fn default() -> Self {
        Self {
            namespace: Cow::Borrowed("phantom"),
            histogram: HistogramConfig::default(),
            disable_otel: false,
        }
    }
}

impl ObservabilityConfig {
    /// Construct a config from environment variables. Unset or empty
    /// variables fall back to defaults.
    pub fn from_env() -> Self {
        let namespace = std::env::var("PHANTOM_TELEMETRY_NAMESPACE")
            .ok()
            .filter(|s| !s.is_empty())
            .map(Cow::Owned)
            .unwrap_or(Cow::Borrowed("phantom"));
        let disable_otel = std::env::var("PHANTOM_TELEMETRY_DISABLED")
            .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE"))
            .unwrap_or(false);
        Self {
            namespace,
            histogram: HistogramConfig::default(),
            disable_otel,
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
    disable_otel: Option<bool>,
}

impl ObservabilityConfigBuilder {
    /// Override the instrument-name prefix.
    pub fn namespace<S: Into<Cow<'static, str>>>(mut self, ns: S) -> Self {
        self.namespace = Some(ns.into());
        self
    }

    /// Override the histogram strategy.
    pub fn histogram(mut self, h: HistogramConfig) -> Self {
        self.histogram = Some(h);
        self
    }

    /// Override the runtime kill-switch.
    pub fn disable_otel(mut self, disabled: bool) -> Self {
        self.disable_otel = Some(disabled);
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
        if let Some(d) = self.disable_otel {
            cfg.disable_otel = d;
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
        assert!(!cfg.disable_otel);
        match cfg.histogram {
            HistogramConfig::ExponentialBase2 { max_size, max_scale } => {
                assert_eq!(max_size, 160);
                assert_eq!(max_scale, 20);
            }
            HistogramConfig::Explicit(_) => panic!("default should be exponential"),
        }
    }

    #[test]
    fn builder_overrides_namespace() {
        let cfg = ObservabilityConfig::builder().namespace("myapp").build();
        assert_eq!(cfg.namespace.as_ref(), "myapp");
    }

    #[test]
    fn builder_overrides_disable_flag() {
        let cfg = ObservabilityConfig::builder().disable_otel(true).build();
        assert!(cfg.disable_otel);
    }

    #[test]
    fn builder_overrides_histogram() {
        let cfg = ObservabilityConfig::builder()
            .histogram(HistogramConfig::Explicit(vec![0.001, 0.01, 0.1, 1.0]))
            .build();
        match cfg.histogram {
            HistogramConfig::Explicit(b) => assert_eq!(b.len(), 4),
            _ => panic!("expected explicit"),
        }
    }
}
