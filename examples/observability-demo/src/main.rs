//! End-to-end observability demo.
//!
//! Boots a real `PhantomListener` ↔ `PhantomSession` exchange over TCP
//! loopback wired to a local OTel Collector (default `http://localhost:4317`),
//! drives genuine traffic for ~30 s, and exits. Every metric — the handshake
//! counter, the per-packet/byte data-plane counters, and the active-session
//! gauge (which rises *and* falls as clients connect and disconnect) — is
//! produced by the production data path, not by synthetic `record_*` calls.
//! Run alongside the `docker-compose.yml` in this directory to see metrics in
//! Grafana and traces in Tempo.

use std::time::Duration;

use anyhow::{anyhow, Result};
use opentelemetry::trace::TracerProvider as _;
use opentelemetry::{global, KeyValue};
use opentelemetry_otlp::{MetricExporter, SpanExporter, WithExportConfig};
use opentelemetry_sdk::metrics::SdkMeterProvider;
use opentelemetry_sdk::trace::SdkTracerProvider;
use opentelemetry_sdk::Resource;
use phantom_core::api::{PhantomListener, PhantomSession, TcpSessionTransport};
use phantom_core::crypto::hybrid_sign::HybridVerifyingKey;
use tokio::net::TcpStream;
use tokio::time::Instant;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

/// Total wall-clock the demo generates traffic for.
const RUN_FOR: Duration = Duration::from_secs(30);
/// Concurrent client workers (each reconnects periodically).
const WORKERS: u32 = 4;
/// How long a single client session lives before it disconnects and the worker
/// reconnects — short enough that the server's active-session gauge visibly
/// oscillates rather than sitting pinned at `WORKERS`.
const SESSION_LIFETIME: Duration = Duration::from_secs(5);

#[tokio::main]
async fn main() -> Result<()> {
    let endpoint = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
        .unwrap_or_else(|_| "http://localhost:4317".to_string());

    let resource = Resource::builder()
        .with_service_name("phantom-observability-demo")
        .with_attribute(KeyValue::new("service.version", env!("CARGO_PKG_VERSION")))
        .build();

    let metric_exporter = MetricExporter::builder()
        .with_tonic()
        .with_endpoint(&endpoint)
        .build()?;
    let meter_provider = SdkMeterProvider::builder()
        .with_resource(resource.clone())
        .with_periodic_exporter(metric_exporter)
        .build();
    // Install the global MeterProvider *before* binding the listener so the
    // listener's `Observability` instruments bind to this OTLP exporter.
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

    // Real server. Its `Observability` (shared with every accepted session's
    // data pump) is what the OTLP exporter scrapes.
    let listener = PhantomListener::bind("127.0.0.1:0".to_string()).await?;
    let addr = listener.local_addr();
    let key_bytes = listener.verifying_key_bytes();
    let obs = listener.observability();
    tracing::info!(%endpoint, %addr, "demo started; driving real sessions for ~30s");

    // Server: accept connections and echo every message until aborted.
    let server_listener = listener.clone();
    let server = tokio::spawn(async move {
        loop {
            match server_listener.accept().await {
                Ok(outcome) => {
                    let session = outcome.session();
                    tokio::spawn(async move {
                        // Echo until the client disconnects (recv errors).
                        while let Ok(msg) = session.recv().await {
                            if session.send(msg).await.is_err() {
                                break;
                            }
                        }
                    });
                }
                Err(e) => {
                    tracing::debug!(error = ?e, "accept loop ending");
                    break;
                }
            }
        }
    });

    // Progress logger: snapshot the server-side metrics every 5 s so the
    // console shows the gauge rising and falling alongside the OTLP export.
    let progress_obs = obs.clone();
    let progress = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(5));
        ticker.tick().await; // immediate first tick
        loop {
            ticker.tick().await;
            let s = progress_obs.snapshot();
            tracing::info!(
                active_sessions = s.active_sessions,
                handshakes_ok = s.handshakes_success,
                handshakes_failed = s.handshakes_failure,
                packets_sent = s.packets_sent,
                packets_recv = s.packets_recv,
                bytes_sent = s.bytes_sent,
                bytes_recv = s.bytes_recv,
                "server metrics tick"
            );
        }
    });

    // Clients: each worker repeatedly opens a session, exchanges a steady
    // stream of echo messages for `SESSION_LIFETIME`, disconnects, then
    // reconnects — exercising the handshake counter, the data-plane counters,
    // and the active-session gauge up *and* down.
    let deadline = Instant::now() + RUN_FOR;
    let mut workers = Vec::new();
    for worker_id in 0..WORKERS {
        let addr = addr.clone();
        let key_bytes = key_bytes.clone();
        workers.push(tokio::spawn(async move {
            let mut conn = 0u32;
            while Instant::now() < deadline {
                let budget = deadline.saturating_duration_since(Instant::now());
                let lifetime = budget.min(SESSION_LIFETIME);
                if let Err(e) =
                    run_client_session(&addr, &key_bytes, worker_id, conn, lifetime).await
                {
                    tracing::warn!(worker = worker_id, conn, error = %e, "client session failed");
                    tokio::time::sleep(Duration::from_millis(250)).await;
                }
                conn += 1;
                // Brief gap so the server gauge dips below WORKERS between
                // reconnects.
                tokio::time::sleep(Duration::from_millis(150)).await;
            }
        }));
    }

    for w in workers {
        let _ = w.await;
    }
    progress.abort();
    server.abort();

    let snap = obs.snapshot();
    tracing::info!(?snap, "demo finished, flushing exporters");

    meter_provider.shutdown()?;
    tracer_provider.shutdown()?;
    Ok(())
}

/// One client session: pinned connect, a burst of echo round-trips for
/// `lifetime`, then a clean disconnect.
async fn run_client_session(
    addr: &str,
    key_bytes: &[u8],
    worker: u32,
    conn: u32,
    lifetime: Duration,
) -> Result<()> {
    let span = tracing::info_span!("demo.client.session", worker, conn);
    let _enter = span.enter();

    let key = HybridVerifyingKey::from_bytes(key_bytes)
        .map_err(|e| anyhow!("parse verifying key: {e:?}"))?;
    let tcp = TcpStream::connect(addr).await?;
    let client = PhantomSession::connect_with_transport(addr, TcpSessionTransport::new(tcp), key);

    let until = Instant::now() + lifetime;
    let mut seq = 0u32;
    while Instant::now() < until {
        let payload = format!("w{worker}-c{conn}-m{seq}").into_bytes();
        client
            .send(payload.clone())
            .await
            .map_err(|e| anyhow!("send: {e:?}"))?;
        let echo = tokio::time::timeout(Duration::from_secs(5), client.recv())
            .await
            .map_err(|_| anyhow!("recv timeout"))?
            .map_err(|e| anyhow!("recv: {e:?}"))?;
        if echo != payload {
            return Err(anyhow!("echo mismatch: {echo:?} != {payload:?}"));
        }
        seq += 1;
        // ~10 round-trips/sec per worker.
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    client
        .disconnect()
        .await
        .map_err(|e| anyhow!("disconnect: {e:?}"))?;
    Ok(())
}
