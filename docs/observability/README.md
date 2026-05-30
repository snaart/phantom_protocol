# Phantom Core Observability

Phantom Core ships an OpenTelemetry-native observability subsystem (Phase 8).
The library exposes OTel instruments + `tracing` spans; embedders install
OTLP exporters; metrics and traces flow into any OTel-compatible backend
(Datadog, Honeycomb, Grafana Cloud, AWS CloudWatch, Tempo, Jaeger,
self-hosted Prometheus via the OTel Collector's `prometheusexporter`).

## What's exported

Two pillars, OTel-native:

- **Metrics** — `phantom.*` namespace (configurable via
  `PHANTOM_TELEMETRY_NAMESPACE`). Hot-path packet / byte counters via
  lock-free atomics with `ObservableCounter` callbacks; security signals,
  cookie/PoW gate, rekey, fallback, early-data outcomes as labeled
  `Counter`s; handshake / path-validation latency as exponential-base-2
  `Histogram`s with exemplar correlation to traces.

- **Traces** — `phantom.*` spans on listener bind/accept, handshake
  (client and server sides), session rekey, path
  validation. Span fields carry `client_ip`, `version` (single pinned
  `v1`), `outcome`,
  `cipher_suite`, etc. Bridged into the embedder's
  `tracing_subscriber::Registry` via `tracing-opentelemetry`.

Logs stay in `tracing` format (structured JSON or pretty); they are NOT in
scope for the OTel pipeline of this release.

## How to enable

`telemetry-otel` is an **opt-in Cargo feature** in `phantom_core`. The
default build is unchanged. The reference server (`phantom-server`) turns
it on:

```toml
# in server/Cargo.toml
phantom_core = { path = "../core", features = ["telemetry-otel"] }
```

For a custom embedder, enable the feature the same way and install
`MeterProvider` / `TracerProvider` per
[`docs/observability/otlp-setup.md`](otlp-setup.md).

## Layered design

```
your-app
  │
  ▼
phantom_core::observability::Observability        (recording API)
  │                              │
  │                              ▼
  │            opentelemetry::global::meter / tracer   (when feature ON)
  ▼
HotPathAtomics (lock-free, cache-padded)
  │
  └─► ObservableCounter callbacks (read once per SDK collection cycle)
```

Hot-path packet recording is **lock-free** (`AtomicU64` + cache-line
padding via `crossbeam-utils::CachePadded`). Microbench on Apple M1:
`record_send` ≈ **2.5 ns / call**, contended ≈ **84 ns / call** across 8
threads.

## What's NOT in the library

- HTTP server — `phantom_core` never bundles one. The Phase 4.5 hyper
  endpoint is gone (Phase 8). For Prometheus pull, run an OTel Collector
  with a `prometheusexporter`.
- Exporter configuration — the embedder owns it. See `server/src/telemetry.rs`
  for the reference implementation.

## Documents in this directory

- [`refactor-plan.md`](refactor-plan.md) — the working plan + atomic-commit
  rollout (Phase 8 — this refactor).
- [`metrics-catalog.md`](metrics-catalog.md) — every emitted instrument:
  name, type, unit, attributes, suggested alert thresholds.
- [`otlp-setup.md`](otlp-setup.md) — production setup recipes for the
  major backends (self-hosted, Datadog, Honeycomb, Grafana Cloud, mTLS).
- [`tracing-guide.md`](tracing-guide.md) — span inventory, sampling,
  exemplar correlation, cardinality contract.

## Environment variables

Phantom Core honors the OpenTelemetry SDK env-var spec where applicable:

| Variable | Default | Purpose |
|----------|---------|---------|
| `OTEL_EXPORTER_OTLP_ENDPOINT` | `http://localhost:4317` | OTLP gRPC endpoint |
| `OTEL_EXPORTER_OTLP_HEADERS` | — | Auth headers (Datadog/Honeycomb API keys) |
| `OTEL_EXPORTER_OTLP_COMPRESSION` | — | `gzip` / `zstd` |
| `OTEL_METRIC_EXPORT_INTERVAL` | `10000` (ms) | Push period |
| `OTEL_TRACES_SAMPLER` | `parentbased_traceidratio` | Sampler implementation |
| `OTEL_TRACES_SAMPLER_ARG` | `0.01` | Trace sampling ratio |
| `OTEL_RESOURCE_ATTRIBUTES` | — | `service.namespace=prod,deployment.environment=staging` |
| `PHANTOM_TELEMETRY_NAMESPACE` | `phantom` | Instrument-name prefix (Phantom-specific) |
| `PHANTOM_TELEMETRY_DISABLED` | `false` | Runtime kill-switch |
