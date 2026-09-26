# Tracing Guide

This document inventories the OpenTelemetry / `tracing` spans that Phantom Protocol
Core emits, the attributes they carry, and how to wire the
`tracing-opentelemetry` bridge in an embedder.

## How tracing reaches OTel

Phantom Protocol uses the `tracing` crate as its structured-event fabric. When
the `telemetry-otel` Cargo feature is on, the embedder installs an
`OpenTelemetryLayer` (from `tracing-opentelemetry`) into its
`tracing_subscriber::Registry`. From then on, every `tracing` span the
library opens — `#[tracing::instrument]`-annotated functions, plus any
ad-hoc `tracing::info_span!` — is forwarded to the global OTel
`TracerProvider`. Spans are exported via OTLP gRPC by the embedder.

```rust
// server/src/main.rs::init_tracing — the OTel layer MUST come before the fmt
// layer: fmt::layer() does not forward `LookupSpan`, so an OTel layer
// composed after it never finds the registry.
let otel_layer = tracing_opentelemetry::layer().with_tracer(telemetry.tracer());
tracing_subscriber::registry()
    .with(env_filter)
    .with(otel_layer)
    .with(fmt::layer().json())
    .init();
```

## Span inventory

All spans live under the `phantom.*` namespace. The library emits them
unconditionally — the OTel bridge decides whether to export. Sampling is
decided once, at span creation, by the SDK's configured sampler — the
library does not force-sample error spans, so a low trace ratio drops
failure traces at the same rate as successful ones. Use the always-on metric
counters (not traces) for failure alerting.

| Span name | Module | Fields | When |
|-----------|--------|--------|------|
| `phantom.listener.bind` | `api::listener` | `addr` | Listener construction |
| `phantom.listener.bind_with_signing_key` | `api::listener` | `addr` | Listener construction from a persisted signing seed (`bind_with_signing_key_bytes`) |
| `phantom.listener.bind_with_config` | `api::listener` | `addr` | Listener construction from a persisted seed + `PhantomConfig` (`bind_with_config_bytes`) |
| `phantom.listener.accept` | `api::listener` | — | Per accepted connection |
| `phantom.listener.shutdown` | `api::listener` | — | Graceful shutdown |
| `phantom.handshake.process_client_hello` | `transport::handshake` | `difficulty`, `has_cookie`, `has_pow`, `resume`, `has_early_data` | Server-side handshake (incl. 0-RTT early-data) |
| `phantom.handshake.process_server_hello` | `transport::handshake` | `pinned` | Client-side handshake |
| `phantom.session.rekey` | `transport::session` | — | Per-direction traffic-key rotation |
| `phantom.path.begin_validation` | `transport::session` | `path_id` | PATH_VALIDATION challenge issued |
| `phantom.path.complete_validation` | `transport::session` | `path_id` | PATH_VALIDATION response checked |

The PhantomUDP server path (`api::udp_listener`) is **not** instrumented — it
emits no spans; the `phantom.listener.*` spans cover the TCP listener only.

## Exemplar correlation

OTel histograms can attach the active span's `trace_id` / `span_id` to an
observation as an *exemplar* — the hook for a Grafana → Tempo drill-down
from a P99 latency point to the specific handshake's trace.

`Observability::record_handshake(duration, …)` is called from the API layer
(`api/listener.rs`, `api/session.rs`, `api/udp_listener.rs`) *after* the
`phantom.handshake.*` span has closed, and the calling functions are not
themselves instrumented — so there is currently no active trace context at
the recording site and the histogram could not attach an exemplar even with a
reservoir configured. Wiring exemplar drill-down would require moving the
record call inside an instrumented scope.

**Reservoir configuration required.** Exemplar reservoirs are not enabled
by default in `opentelemetry_sdk` 0.32 (the version this crate pins, with
`tracing-opentelemetry` 0.33). Until the embedder configures one on the
`MeterProvider`, histograms record normally but emit no exemplars.
The reference `server/src/telemetry.rs` does not yet configure a reservoir;
treat exemplar drill-down as "available once the reservoir is wired", not
as on-by-default. The Grafana dashboard's `exemplar: true` query flags are
harmless no-ops until then.

## Sampling

The reference embedder (`server/src/telemetry.rs`) installs the sampler
explicitly on the `TracerProvider`:

```rust
Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(ratio)))
```

`ratio` comes from `--otel-trace-sample-ratio`, whose default is `1.0` —
**100 % of traces are exported** unless you lower it. Out-of-range values are
clamped to `0.0..=1.0`.

To sample, set the flag or its environment fallback — either one is enough:

```bash
export OTEL_TRACES_SAMPLER_ARG=0.01   # 1%
# equivalently: phantom-server --otel-trace-sample-ratio 0.01
```

- `OTEL_TRACES_SAMPLER` does **not** need to be set, and is not consulted —
  the explicitly installed sampler wins over the SDK's env-var path.
- `ParentBased` honors a sampling decision already made upstream, so a request
  sampled by a caller stays sampled end-to-end; the ratio gates root spans only.
- `--otel-trace-sample-ratio 1.0` (the default) gives full export for incident
  work; `0` disables trace export entirely.
- Failure paths remain visible via the always-on counters / latency histogram
  regardless of trace sampling.

## Cardinality contract

The library never emits unbounded attribute values as span fields:

- `client_ip` is the peer's IP address. The library deliberately **never
  emits it on a span** — it is correlatable PII, and the always-on
  handshake span omits it explicitly (the DoS gate already has the IP
  in-band, so it never needs to leak into a trace). Naturally, it is also
  never an OTel metric label. If you write custom metrics or spans in an
  embedder, do not read `client_ip` as a label.

- `session_id` is similarly never a span field or a metric attribute.

See `docs/observability/refactor-plan.md` §4 "Cardinality contract" for the
full policy.
