//! End-to-end observability demo.
//!
//! Boots a `phantom_core::Observability` handle wired to a local OTel
//! Collector (default `http://localhost:4317`), simulates a small traffic
//! mix (handshakes + per-packet recording), and exits. Run alongside the
//! `docker-compose.yml` in this directory to see metrics in Grafana and
//! traces in Tempo.

use anyhow::Result;
use opentelemetry::trace::TracerProvider as _;
use opentelemetry::{global, KeyValue};
use opentelemetry_otlp::{MetricExporter, SpanExporter, WithExportConfig};
use opentelemetry_sdk::metrics::SdkMeterProvider;
use opentelemetry_sdk::trace::SdkTracerProvider;
use opentelemetry_sdk::Resource;
use phantom_core::observability::{
    AeadAlgorithm, HandshakeOutcome, Observability, ObservabilityConfig, ProtocolVersion,
    ReplayReason,
};
use phantom_core::transport::types::LegType;
use std::time::Duration;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

#[tokio::main]
async fn main() -> Result<()> {
    let endpoint = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
        .unwrap_or_else(|_| "http://localhost:4317".to_string());

    let resource = Resource::builder()
        .with_service_name("phantom-observability-demo")
        .with_attribute(KeyValue::new(
            "service.version",
            env!("CARGO_PKG_VERSION"),
        ))
        .build();

    let metric_exporter = MetricExporter::builder()
        .with_tonic()
        .with_endpoint(&endpoint)
        .build()?;
    let meter_provider = SdkMeterProvider::builder()
        .with_resource(resource.clone())
        .with_periodic_exporter(metric_exporter)
        .build();
    global::set_meter_provider(meter_provider.clone());

    let span_exporter = SpanExporter::builder()
        .with_tonic()
        .with_endpoint(&endpoint)
        .build()?;
    let tracer_provider = SdkTracerProvider::builder()
        .with_resource(resource)
        .with_batch_exporter(span_exporter)
        .build();
    global::set_tracer_provider(tracer_provider.clone());

    let otel_layer =
        tracing_opentelemetry::layer().with_tracer(tracer_provider.tracer("observability-demo"));
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(otel_layer)
        .with(tracing_subscriber::fmt::layer())
        .init();

    let obs = Observability::new(ObservabilityConfig::default());
    tracing::info!(endpoint = %endpoint, "demo started, emitting telemetry for ~30s");

    // Traffic simulation.
    for tick in 0..30u32 {
        let span = tracing::info_span!("demo.tick", n = tick);
        let _e = span.enter();

        // Handshakes with varying outcomes.
        let outcome = if tick % 7 == 0 {
            HandshakeOutcome::Failure
        } else {
            HandshakeOutcome::Success
        };
        obs.record_handshake(
            Duration::from_micros(2000 + (tick as u64 * 100)),
            outcome,
            LegType::Tcp,
            AeadAlgorithm::Aes256Gcm,
            if tick % 2 == 0 {
                ProtocolVersion::V12
            } else {
                ProtocolVersion::V3
            },
        );

        // Packet bursts.
        for _ in 0..500 {
            obs.record_send(1500, LegType::Tcp);
            obs.record_recv(1500, LegType::Tcp);
            obs.record_encrypt_ns(150);
            obs.record_decrypt_ns(140);
        }

        // Occasional security signal.
        if tick % 5 == 0 {
            obs.record_replay_rejected(ReplayReason::Duplicate);
        }
        if tick == 13 {
            obs.record_aead_failure(LegType::Tcp, AeadAlgorithm::Aes256Gcm);
        }

        obs.session_opened(LegType::Tcp);
        if tick > 0 {
            obs.session_closed(LegType::Tcp);
        }

        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    let snap = obs.snapshot();
    tracing::info!(?snap, "demo finished, flushing exporters");

    meter_provider.shutdown()?;
    tracer_provider.shutdown()?;
    Ok(())
}
