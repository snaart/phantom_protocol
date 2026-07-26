# Phantom Protocol Observability

Phantom Protocol ships an OpenTelemetry-native observability subsystem (Phase 8).
The library exposes OTel instruments + `tracing` spans; embedders install
OTLP exporters; metrics and traces flow into any OTel-compatible backend
(Datadog, Honeycomb, Grafana Cloud, AWS CloudWatch, Tempo, Jaeger,
self-hosted Prometheus via the OTel Collector's `prometheusexporter`).

## What's exported

Two pillars, OTel-native:

- **Metrics** — `phantom.*` namespace (hard-wired; see metrics-catalog.md).
  Hot-path packet / byte counters, AEAD encrypt/decrypt timing and per-path
  RTT via lock-free atomics with `ObservableCounter` / `ObservableGauge`
  callbacks; the security signals (replay rejections, AEAD failures,
  unencrypted-drop downgrades, the cookie and PoW DoS gates) plus the
  active-session and active-stream gauges, rekey, 0-RTT early-data,
  resumption and path-migration as labeled instruments; handshake and
  path-validation latency as explicit-boundary `Histogram`s. **20 of the 21
  registered instruments have a live recording call site**; only
  `phantom.transport.fallback` is unfed, because the fallback state machine
  it would report on is never driven. The two former partial gaps are
  closed: a server with 0-RTT disabled by policy records
  `early_data{outcome="rejected_disabled"}` for a blob it refuses, and a
  path-validation challenge the peer never answers is expired by the pump's
  heartbeat as `path.validation.duration{outcome="timeout"}` (budget = the
  session's own path-down threshold; the sweep is metrics-only and leaves
  the path registry alone). Per-instrument detail is in the **Status** column of
  [`metrics-catalog.md`](metrics-catalog.md). Exemplar correlation requires
  an exemplar reservoir the embedder must configure; the reference server
  does not.

- **Traces** — `phantom.*` spans on listener bind/accept, handshake
  (client and server sides), session rekey, path validation. Span
  fields carry handshake/path detail: `difficulty`, `has_cookie`,
  `has_pow`, `resume`, `has_early_data` (server hello), `pinned` (client
  hello), `path_id` (path validation), `addr` (bind). The peer IP is
  deliberately **not** emitted on any span (it is correlatable PII; the
  DoS gate already has it in-band). `version` / `outcome` /
  `cipher_suite` are **metric labels**, not span fields. Bridged into the
  embedder's `tracing_subscriber::Registry` via `tracing-opentelemetry`.

Logs stay in `tracing` format (structured JSON or pretty); they are NOT in
scope for the OTel pipeline of this release.

## How to enable

`telemetry-otel` is an **opt-in Cargo feature** in `phantom_protocol`. The
default build is unchanged. The reference server (`phantom-server`) turns
it on:

```toml
# in server/Cargo.toml — the reference server opts out of the default
# `bindings` feature and names the rest explicitly
phantom-protocol = { path = "../core", default-features = false, features = [
    "std",
    "compression-zstd",
    "classical-crypto",
    "telemetry-otel",
] }
```

For a custom embedder, enable the feature the same way and install
`MeterProvider` / `TracerProvider` per
[`docs/observability/otlp-setup.md`](otlp-setup.md).

## Layered design

```
your-app
  │
  ▼
phantom_protocol::observability::Observability        (recording API)
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

- HTTP server — `phantom_protocol` never bundles one. The Phase 4.5 hyper
  endpoint is gone (Phase 8). For Prometheus pull, run an OTel Collector
  with a `prometheusexporter`.
- Exporter configuration — the embedder owns it. See `server/src/telemetry.rs`
  for the reference implementation.

## Documents in this directory

- [`refactor-plan.md`](refactor-plan.md) — the working plan + atomic-commit
  rollout (Phase 8 — this refactor).
- [`metrics-catalog.md`](metrics-catalog.md) — every registered instrument:
  name, type, unit, attributes, whether it is actually recorded today,
  suggested alert thresholds.
- [`otlp-setup.md`](otlp-setup.md) — production setup recipes for the
  major backends (self-hosted, Datadog, Honeycomb, Grafana Cloud, mTLS).
- [`tracing-guide.md`](tracing-guide.md) — span inventory, sampling,
  exemplar correlation, cardinality contract.

## Environment variables

Phantom Protocol honors the OpenTelemetry SDK env-var spec where applicable:

| Variable | Default | Purpose |
|----------|---------|---------|
| `OTEL_EXPORTER_OTLP_ENDPOINT` | `http://localhost:4317` | OTLP gRPC endpoint |
| `OTEL_EXPORTER_OTLP_HEADERS` | — | Auth headers (Datadog/Honeycomb API keys) |
| `OTEL_EXPORTER_OTLP_COMPRESSION` | — | `gzip` / `zstd` |
| `OTEL_METRIC_EXPORT_INTERVAL` | `10000` (ms) | Push period |
| `OTEL_TRACES_SAMPLER` | — (not consulted) | Sampler implementation. `phantom-server` installs its sampler explicitly, so this variable is ignored — use `OTEL_TRACES_SAMPLER_ARG` / `--otel-trace-sample-ratio` instead |
| `OTEL_TRACES_SAMPLER_ARG` | `1.0` (`phantom-server` default — export every trace) | Trace sampling ratio, the env fallback for `--otel-trace-sample-ratio`. `server/src/telemetry.rs` installs it as `ParentBased(TraceIdRatioBased(ratio))`, so it takes effect on its own without `OTEL_TRACES_SAMPLER`; the ratio gates root spans only and out-of-range values are clamped |
| `OTEL_RESOURCE_ATTRIBUTES` | — | `service.namespace=prod,deployment.environment=staging` |
| `PHANTOM_TELEMETRY_NAMESPACE` | `phantom` | Instrument-name prefix — read only by `ObservabilityConfig::from_env`, which currently has **no caller**; the variable is inert today |

`ObservabilityConfig::from_env` reads only `PHANTOM_TELEMETRY_NAMESPACE`, but
nothing calls it: the library always constructs
`Observability::new(ObservabilityConfig::default())` and exposes no seam to
inject a config, so the namespace is effectively fixed at `phantom`. There is
no runtime telemetry kill-switch. To disable telemetry, build
without the `telemetry-otel` Cargo feature, or simply do not point
`OTEL_EXPORTER_OTLP_ENDPOINT` at a reachable collector — the SDK's
bounded export queue then drops telemetry at near-zero cost.
