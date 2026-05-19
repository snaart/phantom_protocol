# Tracing Guide

This document inventories the OpenTelemetry / `tracing` spans that Phantom
Core emits, the attributes they carry, and how to wire the
`tracing-opentelemetry` bridge in an embedder.

## How tracing reaches OTel

Phantom Core uses the `tracing` crate as its structured-event fabric. When
the `telemetry-otel` Cargo feature is on, the embedder installs an
`OpenTelemetryLayer` (from `tracing-opentelemetry`) into its
`tracing_subscriber::Registry`. From then on, every `tracing` span the
library opens — `#[tracing::instrument]`-annotated functions, plus any
ad-hoc `tracing::info_span!` — is forwarded to the global OTel
`TracerProvider`. Spans are exported via OTLP gRPC by the embedder.

```rust
// Inside server/src/telemetry.rs (lands in step 11 of the refactor):
let otel_layer = OpenTelemetryLayer::new(
    tracer_provider.tracer("phantom-server"),
);
tracing_subscriber::registry()
    .with(env_filter)
    .with(json_fmt_layer)
    .with(otel_layer)
    .init();
```

## Span inventory

All spans live under the `phantom.*` namespace. The library emits them
unconditionally — the OTel bridge decides whether to export. Spans with
`Level::ERROR` events explicitly mark the parent span as sampled to defeat
ratio-based dropping for failure traces.

| Span name | Module | Fields | When |
|-----------|--------|--------|------|
| `phantom.listener.bind` | `api::listener` | `addr` | Listener construction |
| `phantom.listener.accept` | `api::listener` | — | Per accepted connection |
| `phantom.listener.shutdown` | `api::listener` | — | Graceful shutdown |
| `phantom.handshake.process_client_hello` | `transport::handshake` | `client_ip`, `difficulty`, `has_cookie`, `has_pow`, `resume` | V1/V2 server-side handshake |
| `phantom.handshake.process_client_hello_v3` | `transport::handshake` | `client_ip`, `difficulty`, `has_cookie`, `has_pow`, `resume`, `early_data_len` | V3 0-RTT server-side handshake |
| `phantom.handshake.process_server_hello` | `transport::handshake` | `pinned` | V1/V2 client-side handshake |
| `phantom.handshake.process_server_hello_v3` | `transport::handshake` | `pinned` | V3 client-side handshake |
| `phantom.session.rekey` | `transport::session` | — | Per-direction traffic-key rotation |
| `phantom.path.begin_validation` | `transport::session` | `path_id` | PATH_VALIDATION challenge issued |
| `phantom.path.complete_validation` | `transport::session` | `path_id` | PATH_VALIDATION response checked |

## Exemplar correlation

OTel histograms attach the current span's `trace_id` / `span_id` to each
observation. When `Observability::record_handshake(duration, …)` is called
inside the active `phantom.handshake.*` span, the histogram entry carries
that trace_id — Grafana / Tempo drill-down from a P99 latency point lands
on the specific failed handshake's full trace.

No code change required at recording sites; the SDK reads
`Context::current()` automatically.

## Sampling

Default at the embedder layer (`server/src/telemetry.rs`):

```rust
Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(0.01)))
```

- 1% baseline trace rate.
- Failure paths are visible to alerting via the counters / latency
  histograms regardless of trace sampling.
- Override at runtime via `OTEL_TRACES_SAMPLER_ARG=0.05` (5%) or
  `OTEL_TRACES_SAMPLER=always_on` (full trace export, useful during
  incident investigation).

## Cardinality contract

The library never emits unbounded attribute values as span fields:

- `client_ip` is the peer's IP address. **It is logged via `tracing`'s
  field machinery (intended for human-readable structured logs)** but
  must NOT be promoted to an OTel attribute that becomes a metric label.
  The `OpenTelemetryLayer` honors this — span fields are span attributes,
  not metric labels. If you write custom metrics in an embedder, do not
  read `client_ip` as a label.

- `session_id` is similarly span-scoped and never a metric attribute.

See `docs/observability/refactor-plan.md` §4 "Cardinality contract" for the
full policy.
