//! OpenTelemetry pipeline initialization for `phantom-server`.
//!
//! Installs the global `MeterProvider` and `TracerProvider` with OTLP/gRPC
//! exporters before any handshake records anything. The OTel `tracing`
//! bridge layer is composed into the global subscriber in `main.rs` using
//! [`TelemetryHandle::tracer`].
//!
//! Sampling, headers, TLS, and compression follow the OTel SDK env-var
//! convention (`OTEL_EXPORTER_OTLP_HEADERS`, `OTEL_EXPORTER_OTLP_COMPRESSION`,
//! `OTEL_TRACES_SAMPLER`, etc.) — see `docs/observability/otlp-setup.md`.

use anyhow::Result;
use opentelemetry::trace::TracerProvider as _;
use opentelemetry::{global, KeyValue};
use opentelemetry_otlp::{MetricExporter, SpanExporter, WithExportConfig};
use opentelemetry_sdk::metrics::SdkMeterProvider;
use opentelemetry_sdk::trace::SdkTracerProvider;
use opentelemetry_sdk::Resource;
use std::time::Duration;

/// Handle to OpenTelemetry providers. `shutdown` flushes any buffered
/// telemetry; call it on the binary's clean shutdown path.
pub struct TelemetryHandle {
    meter_provider: SdkMeterProvider,
    tracer_provider: SdkTracerProvider,
}

/// Telemetry configuration.
pub struct TelemetryCfg {
    pub service_name: String,
    pub otlp_endpoint: String,
    pub export_interval: Duration,
    pub trace_sample_ratio: f64,
}

impl TelemetryHandle {
    /// Build the OTLP-backed `MeterProvider` and `TracerProvider`, install
    /// them as global, and return the handle for shutdown sequencing.
    ///
    /// Call this once at startup, before constructing the listener.
    pub fn init(cfg: &TelemetryCfg) -> Result<Self> {
        let resource = Resource::builder()
            .with_service_name(cfg.service_name.clone())
            .with_attribute(KeyValue::new("phantom.role", "server"))
            .with_attribute(KeyValue::new(
                "service.version",
                env!("CARGO_PKG_VERSION"),
            ))
            .build();

        // --- Metrics pipeline ---------------------------------------------
        let metric_exporter = MetricExporter::builder()
            .with_tonic()
            .with_endpoint(&cfg.otlp_endpoint)
            .with_timeout(cfg.export_interval.saturating_mul(2))
            .build()?;
        let meter_provider = SdkMeterProvider::builder()
            .with_resource(resource.clone())
            .with_periodic_exporter(metric_exporter)
            .build();
        global::set_meter_provider(meter_provider.clone());

        // --- Traces pipeline ----------------------------------------------
        let span_exporter = SpanExporter::builder()
            .with_tonic()
            .with_endpoint(&cfg.otlp_endpoint)
            .build()?;
        let tracer_provider = SdkTracerProvider::builder()
            .with_resource(resource)
            .with_batch_exporter(span_exporter)
            .build();
        global::set_tracer_provider(tracer_provider.clone());

        // Note on sampling: 0.27 SDK reads `OTEL_TRACES_SAMPLER` and
        // `OTEL_TRACES_SAMPLER_ARG` from the environment, so we surface
        // `trace_sample_ratio` to the operator via that env path rather
        // than coupling our config to the (still-evolving) Sampler builder
        // API. The CLI flag plumbs into `OTEL_TRACES_SAMPLER_ARG` directly.
        let _ = cfg.trace_sample_ratio;

        Ok(Self {
            meter_provider,
            tracer_provider,
        })
    }

    /// Borrow a `Tracer` for the OTel `tracing` bridge layer. Used in
    /// `main::init_tracing` to build the `OpenTelemetryLayer` that
    /// forwards `tracing` spans into OTel traces.
    pub fn tracer(&self) -> opentelemetry_sdk::trace::Tracer {
        self.tracer_provider.tracer("phantom-server")
    }

    /// Flush and shut down both providers. Call from the binary's
    /// clean-shutdown path; idempotent.
    pub fn shutdown(&self) {
        let _ = self.meter_provider.shutdown();
        let _ = self.tracer_provider.shutdown();
    }
}
