# OTLP Setup Recipes

Production-ready setups for shipping `phantom-server` telemetry to the
major backends. All examples assume the binary is started with at least:

```bash
export OTEL_EXPORTER_OTLP_ENDPOINT="..."
phantom-server
```

For the full env-var reference see [`README.md`](README.md).

## Recipe A: self-hosted (OTel Collector → Prometheus + Tempo + Loki)

The "Phantom-shaped" stack: one Collector, three pull/push sinks for the
three pillars.

```yaml
# otel-collector-config.yaml
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317

processors:
  batch:
    send_batch_size: 1000
    timeout: 5s
  memory_limiter:
    check_interval: 1s
    limit_mib: 512

exporters:
  prometheus:
    endpoint: 0.0.0.0:8889
  otlp/tempo:
    endpoint: tempo:4317
    tls:
      insecure: true

service:
  pipelines:
    metrics:
      receivers: [otlp]
      processors: [memory_limiter, batch]
      exporters: [prometheus]
    traces:
      receivers: [otlp]
      processors: [memory_limiter, batch]
      exporters: [otlp/tempo]
```

Point `phantom-server` at the Collector:

```bash
export OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector:4317
```

Prometheus scrapes `:8889/metrics` from the Collector. Grafana reads
Prometheus for metrics and Tempo for traces; the `traces_to_metrics`
datasource correlation wires exemplars into the latency panels.

## Recipe B: Datadog (direct)

Datadog accepts OTLP/gRPC natively as of agent 7.42+. Send directly from
`phantom-server`:

```bash
export OTEL_EXPORTER_OTLP_ENDPOINT="https://api.datadoghq.com:443"
export OTEL_EXPORTER_OTLP_HEADERS="DD-API-KEY=$DATADOG_API_KEY"
export OTEL_RESOURCE_ATTRIBUTES="service.namespace=phantom,deployment.environment=prod"
phantom-server
```

The metrics land in Datadog as `phantom.session.packets` etc., and traces
appear in APM under the configured `service.name`.

## Recipe C: Honeycomb (direct)

```bash
export OTEL_EXPORTER_OTLP_ENDPOINT="https://api.honeycomb.io:443"
export OTEL_EXPORTER_OTLP_HEADERS="x-honeycomb-team=$HONEYCOMB_API_KEY,x-honeycomb-dataset=phantom"
export OTEL_TRACES_SAMPLER_ARG=0.1   # 10% sampling on production traces
phantom-server
```

Honeycomb's `Metrics` product accepts the OTLP metrics stream. Traces and
metrics share the same dataset header.

## Recipe D: Grafana Cloud (direct)

```bash
export OTEL_EXPORTER_OTLP_ENDPOINT="https://otlp-gateway-prod-us-central-0.grafana.net/otlp"
export OTEL_EXPORTER_OTLP_HEADERS="Authorization=Basic $(echo -n "$GC_INSTANCE_ID:$GC_API_KEY" | base64)"
phantom-server
```

Grafana Cloud's OTLP gateway routes metrics to Mimir/Prometheus and traces
to Tempo automatically — no Collector required.

## Recipe E: mTLS (any backend)

Phantom Core uses `tonic` for OTLP/gRPC. To enable mTLS against a private
Collector, set the standard OTel TLS env vars:

```bash
export OTEL_EXPORTER_OTLP_ENDPOINT="https://otel-internal.prod.example.com:4317"
export OTEL_EXPORTER_OTLP_CERTIFICATE="/etc/ssl/ca.pem"
export OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE="/etc/ssl/phantom.pem"
export OTEL_EXPORTER_OTLP_CLIENT_KEY="/etc/ssl/phantom.key"
phantom-server
```

For tonic-specific knobs (compression, custom interceptors), build a
custom `server/src/telemetry.rs` that fully constructs the
`SpanExporter::builder().with_tonic()` chain.

## Recipe F: dual-export (OTLP push + Prometheus pull)

Some operators want both — push to a SaaS for traces, pull from an
internal Prometheus for metrics. The Collector pattern from Recipe A
already supports this: the Collector receives one OTLP stream from
`phantom-server` and fans out to `prometheusexporter` and
`otlp/datadog` simultaneously.

```yaml
# otel-collector-config.yaml — relevant section
exporters:
  prometheus:
    endpoint: 0.0.0.0:8889
  otlphttp/datadog:
    endpoint: https://api.datadoghq.com
    headers:
      DD-API-KEY: ${DATADOG_API_KEY}

service:
  pipelines:
    metrics:
      receivers: [otlp]
      processors: [batch]
      exporters: [prometheus, otlphttp/datadog]
```

## Operational tips

- **Lossy queues.** OTel batch processors drop telemetry rather than block.
  The library never installs the exporter, so export health is owned by the
  SDK/Collector, not Phantom Core: watch the OTel SDK's own
  `otel_sdk_exporter_metric_data_points` / `..._span` failure counters and the
  Collector's `otelcol_exporter_send_failed_*` — non-zero means the Collector
  / backend is congested or unreachable.
- **Sampling for cost.** Default trace ratio is 1%. For incident
  investigation flip `OTEL_TRACES_SAMPLER=always_on` per-instance; failure
  paths remain visible via the metrics counters regardless of trace
  sampling.
- **Resource attrs in containers.** Set `OTEL_RESOURCE_ATTRIBUTES` in
  the deployment manifest so every pod gets `deployment.environment`,
  `k8s.pod.name`, etc. automatically attached to all telemetry.
- **Cardinality budgets.** The SDK enforces a per-instrument cardinality
  limit (default 2000). If you see `overflow` data points, audit your
  custom attributes — the library itself never emits unbounded labels.
