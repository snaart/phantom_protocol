# OpenTelemetry Refactor — Working Plan

> **Status:** ✅ **shipped** (2026-05-19/20). All 20 atomic-commit rollout
> steps landed on `feature/otel-observability` (commits `e59a1f1`..`5675ecc`
> + this final sweep). This document remains the single source of truth for
> the Phase 8 observability refactor — see §12 for the per-commit SHA table
> and the tracked documentation in this directory for the canonical summary.

**Start date:** 2026-05-19
**Tracking:** the **Atomic-Commit Rollout** section at the bottom is the live
checklist. Update it inline as each commit lands.

---

## 1. Context & Goals

### Why

Phantom Protocol currently exposes metrics via a hand-rolled Prometheus
text-exposition implementation in `core/src/transport/metrics.rs`
(`TransportMetrics` + `MetricsSnapshot::to_prometheus_text()`). The server
embedder wires a minimal hyper-based `/metrics` endpoint over it. This was the
Phase 4.5 design (✅), and it works, but:

- It's a hand-rolled, single-backend pipeline. Every modern observability
  backend (Datadog, Honeycomb, Grafana Cloud, AWS CloudWatch, Tempo, Jaeger,
  GCP Cloud Operations) speaks **OTLP** natively, not Prometheus pull.
- It lacks structured attributes — `phantom_packets_sent_total` cannot be
  sliced by leg, cipher suite, or path without an atomic-field explosion.
- It cannot produce **exemplars** (sample trace_ids attached to histogram
  observations) — the single most valuable feature for latency debugging in
  modern observability.
- The instrument inventory is shallow: many security-critical events
  (cookie/PoW gate, fallbacks, rekeys, early-data outcomes) are not surfaced
  at all.
- Hand-rolled exposition is brittle: every new instrument needs both a struct
  field and a manual `to_prometheus_text` patch with hand-written `# HELP` /
  `# TYPE` lines.

### Goal

Replace the metrics pipeline with **OpenTelemetry** (metrics + traces) as the
sole telemetry path. The library exposes OTel instruments; the embedder
configures OTLP exporters; the existing Grafana / Prometheus assets are
rewritten to consume the OTel-exported view.

### Non-goals (for this refactor)

- OTel **logs** pillar. `tracing` stays as the structured-log fabric. The
  logs-via-OTLP path can be added later via `opentelemetry-appender-tracing`
  if needed; it's not in scope here.
- A separate `phantom-protocol-otel` crate. The library remains one crate; OTel
  support lands as the `telemetry-otel` Cargo feature.

### Constraints

- `wasm32-unknown-unknown` and `thumbv7em-none-eabihf` builds are hard CI
  gates (`cross.yml`). They MUST continue to pass without the OTel feature.
- MSRV is Rust 1.75. If a chosen OTel crate requires a higher MSRV, that's
  acceptable to bump — but the bump is recorded in this plan and in
  `CHANGELOG.md`.
- No `unsafe` outside the existing two opt-ins (`udp_transport.rs`,
  `legs/websocket.rs`).
- Zero degradation of the lock-free hot-path packet recording. The current
  baseline is one `Relaxed` `fetch_add` per `record_send/recv`.

---

## 2. Architecture

### New module layout

```
core/src/observability/         (NEW; replaces transport/metrics.rs)
├── mod.rs                      Re-exports + Observability facade
├── config.rs                   ObservabilityConfig + builder + from_env
├── atomics.rs                  HotPathAtomics: cache-line padded per-leg counters
├── instruments.rs              #[cfg(telemetry-otel)] PhantomInstruments holder
├── attrs.rs                    Pre-interned KeyValue sets (one per attribute combo)
├── semconv.rs                  Stable instrument names (namespace-prefixed)
├── bridge.rs                   #[cfg(telemetry-otel)] observable-callback wiring
└── snapshot.rs                 MetricsSnapshot (kept for FFI/debug)
```

`transport/metrics.rs` — **DELETED**. All exports re-routed under
`crate::observability::*`. `transport::metrics` becomes a deprecated re-export
shim during the migration window, then is removed in step 3 of the rollout.

### Data flow

```
                       hot path                       event path
                       (atomic add)                   (sync OTel call)
                            │                              │
        ┌───────────────────┼───────────────────┐          │
        ▼                   ▼                   ▼          ▼
   record_send         record_recv         record_encrypt  record_handshake
        │                   │                   │          │
        ▼                   ▼                   ▼          ▼
   ┌────────────────────────────────────────┐    ┌──────────────────────┐
   │ HotPathAtomics (lock-free, padded)     │    │ PhantomInstruments   │
   │   packets[direction][leg]: AtomicU64   │    │  handshake_duration  │
   │   bytes[direction][leg]:   AtomicU64   │    │   .record(us, attrs) │
   │   encrypt_{ns_sum,count}:  AtomicU64   │    │  replay_rejected     │
   │   rtt_per_path[0..16]:     AtomicU64   │    │   .add(1, attrs)     │
   └────────────────┬───────────────────────┘    └───────────┬──────────┘
                    │                                        │
   (observed via with_callback at SDK collection time)       │
                    │                                        │
                    └────────────────┬───────────────────────┘
                                     ▼
                       opentelemetry::global Meter / Tracer
                                     │
                                     ▼
                        PeriodicReader + BatchSpanProcessor
                                     │
                                     ▼
                        OTLP/gRPC exporter (tonic + zstd)
                                     │
                                     ▼
                          OTel Collector / SaaS backend
```

### `core` ↔ `server` boundary

- **`core`**: defines `Observability`, `ObservabilityConfig`,
  `PhantomInstruments`, all record-call signatures, and the observable
  callbacks. Talks to `opentelemetry::global::meter("phantom_protocol")` /
  `::tracer("phantom_protocol")`. Does NOT install a `MeterProvider` /
  `TracerProvider`; does NOT bundle an HTTP server.
- **`server`** (or any embedder): installs `MeterProvider` /
  `TracerProvider` via `server/src/telemetry.rs` before constructing
  `PhantomListener`. Wires OTLP exporters with env-driven config.
  `server/src/metrics_http.rs` — **deleted**, along with the `hyper`,
  `hyper-util`, `http-body-util` dependencies.

---

## 3. Recording API (library surface)

### `Observability` facade

```rust
pub struct Observability {
    atomics: Arc<HotPathAtomics>,
    instruments: PhantomInstruments,            // ZST when feature off
    config: ObservabilityConfig,
}

impl Observability {
    pub fn new(config: ObservabilityConfig) -> Arc<Self>;
    pub fn snapshot(&self) -> MetricsSnapshot;   // FFI / debug, always available
}

// Hot path (lock-free, no_std-friendly, always available)
impl Observability {
    #[inline] pub fn record_send(&self, bytes: usize, leg: LegType);
    #[inline] pub fn record_recv(&self, bytes: usize, leg: LegType);
    #[inline] pub fn record_encrypt_ns(&self, duration_ns: u64);
    #[inline] pub fn record_decrypt_ns(&self, duration_ns: u64);
    #[inline] pub fn record_rtt_us(&self, rtt_us: u64, path_id: u8);
}

// Event path (synchronous OTel call when feature on; no-op when off)
impl Observability {
    pub fn record_handshake(&self, duration: Duration, outcome: HandshakeOutcome,
                            leg: LegType, cipher: CipherSuite, version: ProtocolVersion);
    pub fn record_resumption(&self, mode: ResumptionMode, accepted: bool);
    pub fn record_replay_rejected(&self, reason: ReplayReason);
    pub fn record_aead_failure(&self, leg: LegType, algorithm: AeadAlgorithm);
    pub fn record_unencrypted_dropped(&self, leg: LegType);
    pub fn record_path_migration(&self, from: u8, to: u8);
    pub fn record_path_validation(&self, duration: Duration, outcome: PathValidationOutcome);
    pub fn record_cookie(&self, outcome: CookieOutcome);
    pub fn record_pow(&self, outcome: PowOutcome, difficulty: u8);
    pub fn record_early_data(&self, outcome: EarlyDataOutcome);
    pub fn record_rekey(&self, direction: Direction);
    pub fn record_fallback(&self, from_leg: LegType, to_leg: LegType, reason: FallbackReason);
    pub fn session_opened(&self, leg: LegType);
    pub fn session_closed(&self, leg: LegType);
    pub fn stream_opened(&self);
    pub fn stream_closed(&self);
}
```

### Configuration

```rust
pub struct ObservabilityConfig {
    pub namespace: Cow<'static, str>,           // default: "phantom"
    pub histogram_boundaries: HistogramConfig,  // default: OTel base-2 exponential
    pub disable_otel: bool,                      // runtime kill-switch (default: false)
}

impl ObservabilityConfig {
    pub fn from_env() -> Self;
    pub fn builder() -> ObservabilityConfigBuilder;
}

pub enum HistogramConfig {
    Explicit(Vec<f64>),
    ExponentialBase2 { max_size: u32, max_scale: i8 },
}
```

`namespace` is captured once at `Observability::new(...)`; all instrument
names are formatted `format!("{ns}.{stem}")` and stored in `Arc<str>` slots
inside `PhantomInstruments`. No runtime cost per record.

### No-op path

When `telemetry-otel` feature is off, `PhantomInstruments` is a ZST:

```rust
#[cfg(not(feature = "telemetry-otel"))]
pub struct PhantomInstruments;

#[cfg(not(feature = "telemetry-otel"))]
impl PhantomInstruments {
    #[inline(always)] pub fn record_handshake(&self, ..) {}
    #[inline(always)] pub fn record_replay_rejected(&self, ..) {}
    // ...
}
```

LLVM eliminates the call sites entirely. The atomics still record (they don't
depend on OTel); `snapshot()` still works. The library remains observable via
FFI even on no-OTel builds.

---

## 4. Instrument Catalog

### Naming conventions

- OTel dotted notation. `{namespace}.{subsystem}.{measurement}[.unit]`.
- Unit suffix per UCUM where applicable (`.duration` → seconds canonical; we
  record microseconds and let the SDK convert).
- Counters drop the `_total` suffix at the OTel level; the Prometheus
  exporter re-adds it on conversion.
- Attribute keys: snake_case, OTel semconv style.

### Tier 1 — migration of existing metrics

| Current Prometheus name | OTel name | Type | Unit | Attributes |
|-------------------------|-----------|------|------|------------|
| `phantom_packets_sent_total`, `…_recv_total` | `phantom.session.packets` | ObservableCounter | `{packet}` | `direction`, `leg` |
| `phantom_bytes_sent_total`, `…_recv_total` | `phantom.session.io` | ObservableCounter | `By` | `direction`, `leg` |
| (avg_encrypt_ns derived) | `phantom.crypto.encrypt.duration_sum` + `…count` | ObservableCounter pair | `ns` / `{op}` | `algorithm` |
| (avg_decrypt_ns derived) | `phantom.crypto.decrypt.duration_sum` + `…count` | ObservableCounter pair | `ns` / `{op}` | `algorithm` |
| `phantom_rtt_us` | `phantom.path.rtt` | ObservableGauge | `us` | `path_id` |
| `phantom_handshakes_total`, `…_failures_total`, `…_latency_seconds_bucket` | `phantom.handshake.duration` | **Histogram** (explicit latency buckets; `_count` is the canonical handshake count) | `s` | `outcome`, `leg`, `cipher_suite`, `version` |
| `phantom_resumptions_total` | `phantom.handshake.resumptions` | Counter | `{resumption}` | `mode`, `accepted` |
| `phantom_replay_rejected_total` | `phantom.security.replay_rejected` | Counter | `{packet}` | `reason` |
| `phantom_unencrypted_dropped_total` | `phantom.security.unencrypted_dropped` | Counter | `{packet}` | `leg` |
| `phantom_aead_decrypt_failed_total` | `phantom.security.aead_failed` | Counter | `{operation}` | `leg`, `algorithm` |
| `phantom_path_migrations_total` | `phantom.path.migrations` | Counter | `{migration}` | `from_path`, `to_path` |
| `phantom_active_sessions` | `phantom.session.active` | UpDownCounter | `{session}` | `leg` |
| `phantom_active_streams` | `phantom.session.streams.active` | UpDownCounter | `{stream}` | — |

### Tier 2 — new instruments (depth additions)

| OTel name | Type | Unit | Attributes | Rationale |
|-----------|------|------|------------|-----------|
| `phantom.security.cookie` | Counter | `{cookie}` | `outcome` (`issued`/`validated_ok`/`validated_mismatch`) | DoS-gate visibility |
| `phantom.security.pow` | Counter | `{challenge}` | `outcome` (`solved`/`rejected`), `difficulty` | PoW gate health |
| `phantom.session.early_data` | Counter | `{attempt}` | `outcome` (`accepted`/`rejected_unknown_ticket`/`rejected_oversized`/`rejected_aead`/`rejected_replay`) | 0-RTT diagnostics |
| `phantom.session.rekey` | Counter | `{rekey}` | `direction` | Epoch hygiene |
| `phantom.path.validation.duration` | Histogram (explicit latency buckets) | `s` | `path_id`, `outcome` | PATH_VALIDATION latency |
| `phantom.transport.fallback` | Counter | `{fallback}` | `from_leg`, `to_leg`, `reason` | Multi-path fallback visibility |
| `phantom.pacer.rate` | ObservableGauge | `By/s` | `path_id` | BBR pacer output |
| `phantom.bandwidth.estimate` | ObservableGauge | `By/s` | `path_id`, `direction` | Bandwidth estimator output |
| `phantom.buffer_pool.allocations` | Counter | `{allocation}` | `outcome` (`hit_thread_local`/`hit_global`/`miss_new`) | Pool efficiency |

### Resource attributes (set by embedder, frozen at startup)

- `service.name` — e.g. `phantom-server`
- `service.version` — `CARGO_PKG_VERSION`
- `service.instance.id` — stable per-process UUID or hostname
- `host.name`, `os.type`, `process.pid`, `process.runtime.name=rust` (auto)
- `phantom.role` — `client` or `server`
- Anything in `OTEL_RESOURCE_ATTRIBUTES` env

### Cardinality contract

The library will NOT emit attributes whose value space is unbounded
(`peer_ip`, `session_id`, `stream_id`). This is enforced by the recording-API
typing — those fields are not in the function signatures. SDK cardinality
limits (default 2000 per instrument) act as a second line of defense.

---

## 5. Performance Techniques

The hot-path overhead target is **≤ 3 ns** for the per-packet atomic
recorders. Measured on the Apple M1 reference: `record_send` ≈ 2.5 ns,
contended ≈ 84 ns across 8 threads (`core/benches/observability_bench.rs`).

### Shipped

1. **Cache-line padding** (`crossbeam_utils::CachePadded`) around every hot
   `AtomicU64` / `AtomicI64` in `HotPathAtomics` — eliminates false sharing
   across tx/rx threads.
2. **Hot path stays off the OTel API.** Per-packet recording touches only
   the lock-free atomics. The OTel `ObservableCounter` callbacks
   (`bridge.rs`) read those atomics once per SDK collection cycle (~10 s),
   so the per-packet path never builds a `KeyValue` or enters the SDK's
   labeled-add code. The synchronous labeled instruments are reserved for
   genuinely cold events (handshake completion, security signals).
3. **Delta temporality** on the OTLP metric exporter
   (`telemetry.rs`, `Temporality::Delta`) — smaller push payloads; the
   Collector's `prometheusexporter` converts to cumulative for any
   Prometheus pull downstream.
4. **gzip compression** on both OTLP/gRPC exporters
   (`Compression::Gzip`) — large reduction for the repeated attribute keys
   in metric/span batches.
5. **Lossy bounded export queues.** The SDK's `BatchSpanProcessor` and
   periodic metric reader have bounded internal queues — a slow backend
   drops telemetry rather than back-pressuring the hot path. Tunable via
   the standard `OTEL_BSP_*` env vars.
6. **Frozen Resource at startup.** `Resource::builder()…build()` runs once;
   `service.version` is baked from `CARGO_PKG_VERSION`.
7. **`#[cold]` on error paths.** `record_aead_failure`,
   `record_replay_rejected`, `record_unencrypted_dropped`, and
   `HotPathAtomics::record_handshake_failure` are `#[cold]` — branch
   predictor and code-section placement favor the happy path.
8. **Instruments built once.** Every `Counter` / `Histogram` /
   `UpDownCounter` is constructed in `PhantomInstruments::new` and stored
   in a field — never re-resolved through the `Meter` on a recording call.
9. **Latency-tuned histogram buckets.** `handshake.duration` and
   `path.validation.duration` get explicit boundaries
   (`HistogramConfig`, `.with_boundaries(...)`) sized for a PQ handshake's
   sub-ms-to-multi-second spread.

### Deliberately deferred / dropped

- **Pre-interned attribute sets.** The original design pre-built every
  attribute combination behind `OnceLock`. Dropped as YAGNI: the only
  per-call `KeyValue` construction left is on cold event paths (handshakes,
  security signals), where a few `&'static str`-valued `KeyValue`s per call
  is immaterial. The hot path doesn't build attributes at all (see #2).
- **Base-2 exponential histograms.** Would need an SDK metrics *View*; the
  View API is unstable across `opentelemetry` 0.27–0.29. Explicit
  latency-tuned buckets (#9) ship instead — a follow-up can add the View
  once the API settles.
- **Explicit cardinality limit.** The SDK applies a built-in default
  per-instrument cardinality cap; no explicit `with_cardinality_limit`
  call is made (the builder API is not stable across these versions). The
  contract is still upheld at the type level — see §4.
- **Dedicated telemetry runtime.** The OTLP exporter runs on the server's
  tokio runtime via `rt-tokio`. A separate worker pool was scoped but is
  not needed at current load; revisit if exporter stalls are observed.
- **Exemplars.** Reservoirs are not enabled by default in
  `opentelemetry_sdk` 0.28 and are not yet wired — see §6.

---

## 6. Tracing Pillar

### Bridge

`tracing` is already wired in `core` as an optional dependency (Phase 4.5).
Add `tracing-opentelemetry = "0.28"` under the `telemetry-otel` feature.
`OpenTelemetryLayer::new(tracer_provider.tracer("phantom_protocol"))` is composed
into the embedder's `tracing_subscriber::Registry`. The library itself does
not call `tracing_subscriber::init()` — that's the embedder's responsibility,
exactly as today.

### Spans

`#[instrument(skip(transport), fields(leg = leg_str, version = ?version))]`
on:

- `HandshakeServer::process_client_hello`
- `HandshakeClient::process_server_hello`
- `Session::rekey`
- `Session::begin_path_validation` / `complete_path_validation`
- `PhantomListener::accept`
- `PhantomSession::connect_with_transport` / `connect_with_resumption`

Span fields capture: `leg`, `cipher_suite`, `version`, `outcome`, `peer_addr`
(hashed, never raw — see Cardinality contract above).

### Exemplar correlation

`record_handshake(...)` is called from inside the handshake span, so the
trace context is on `Context::current()`. When the embedder configures an
exemplar reservoir on the `MeterProvider`, histogram observations then
carry the span's trace_id and Grafana → Tempo drill-down works.

**Status:** exemplar reservoirs are not enabled by default in
`opentelemetry_sdk` 0.28 and `server/src/telemetry.rs` does not yet wire
one — exemplar drill-down is "reservoir-ready", not on-by-default. Wiring
the reservoir is a follow-up; the histograms record correctly regardless.

### Sampling

`Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(0.01)))` — 1%
default trace rate. Failure paths (`HandshakeServer::process_client_hello`
returning `Err`) explicitly mark `Span::current().set_attribute("sampled",
true)` and add a `span_link` to the failed branch to force inclusion. Tuned
via `OTEL_TRACES_SAMPLER_ARG`.

### Span linking on path migration

When a path validation completes, the new validation span is `Link`-ed to
the original handshake span context. Tempo / Jaeger render this as a visual
edge connecting the two traces.

---

## 7. Exporter Wiring (`server/src/telemetry.rs`)

Replaces `server/src/metrics_http.rs` entirely.

```rust
pub struct TelemetryHandle {
    meter_provider: SdkMeterProvider,
    tracer_provider: SdkTracerProvider,
}

impl TelemetryHandle {
    pub async fn init(cfg: &TelemetryCfg) -> Result<Self> {
        let resource = Resource::builder()
            .with_service_name(cfg.service_name.clone())
            .with_attribute(KeyValue::new("phantom.role", cfg.role.as_str()))
            .with_attributes(parse_otel_resource_attributes_env())
            .build();

        let metric_exporter = MetricExporter::builder()
            .with_tonic()
            .with_endpoint(&cfg.otlp_endpoint)
            .with_compression(Compression::Zstd)
            .with_temporality(Temporality::Delta)
            .build()?;
        let reader = PeriodicReader::builder(metric_exporter)
            .with_interval(cfg.export_interval)
            .build();

        let meter_provider = SdkMeterProvider::builder()
            .with_resource(resource.clone())
            .with_reader(reader)
            .with_view(view_handshake_exponential_histogram())
            .with_cardinality_limit(2000)
            .build();
        opentelemetry::global::set_meter_provider(meter_provider.clone());

        let span_exporter = SpanExporter::builder().with_tonic()
            .with_endpoint(&cfg.otlp_endpoint)
            .with_compression(Compression::Zstd)
            .build()?;
        let tracer_provider = SdkTracerProvider::builder()
            .with_resource(resource)
            .with_batch_exporter(span_exporter)
            .with_sampler(Sampler::ParentBased(Box::new(
                Sampler::TraceIdRatioBased(cfg.trace_sample_ratio)
            )))
            .build();
        opentelemetry::global::set_tracer_provider(tracer_provider.clone());

        let otel_layer = OpenTelemetryLayer::new(
            tracer_provider.tracer("phantom-server")
        );
        let subscriber = tracing_subscriber::registry()
            .with(env_filter)
            .with(json_layer)
            .with(otel_layer);
        tracing::subscriber::set_global_default(subscriber)?;

        Ok(Self { meter_provider, tracer_provider })
    }

    pub async fn shutdown(self) {
        let _ = self.meter_provider.shutdown();
        let _ = self.tracer_provider.shutdown();
    }
}
```

### ENV reference (standard OTel SDK + Phantom-specific)

| Variable | Source | Default | Purpose |
|----------|--------|---------|---------|
| `OTEL_EXPORTER_OTLP_ENDPOINT` | OTel std | `http://localhost:4317` | OTLP gRPC endpoint |
| `OTEL_EXPORTER_OTLP_PROTOCOL` | OTel std | `grpc` | `grpc` / `http/protobuf` |
| `OTEL_EXPORTER_OTLP_HEADERS` | OTel std | — | API key for SaaS |
| `OTEL_METRIC_EXPORT_INTERVAL` | OTel std | `10000` (ms) | Push period |
| `OTEL_TRACES_SAMPLER_ARG` | OTel std | `0.01` | Trace sampling ratio |
| `OTEL_RESOURCE_ATTRIBUTES` | OTel std | — | `service.namespace=prod,…` |
| `OTEL_BSP_MAX_QUEUE_SIZE` | OTel std | `2048` | Lossy queue depth |
| `OTEL_BSP_EXPORT_TIMEOUT` | OTel std | `5000` (ms) | Export timeout |
| `PHANTOM_TELEMETRY_NAMESPACE` | Phantom Protocol | `phantom` | Instrument-name prefix |
| `PHANTOM_TELEMETRY_DISABLED` | Phantom Protocol | `false` | Runtime kill-switch |

---

## 8. Cross-Target Story

- `telemetry-otel` is **off** in `core`'s `default = ["compression-zstd", "std"]`.
- `server/Cargo.toml` adds `phantom_protocol = { path = "../core", features = ["telemetry-otel"] }`.
- `cross.yml`: wasm32-unknown-unknown and thumbv7em-none-eabihf rows build
  with `--no-default-features --features embedded,no-std` (already do) — no
  OTel pulled in. Hard gates remain green.
- `ci.yml`: add a new job `cargo clippy --features telemetry-otel --lib` to
  ensure the feature-on path stays clean.
- `Miri` job: unchanged. OTel SDK is not Miri-friendly anyway (FFI to gRPC
  client).
- Embedded users retain `Observability::snapshot()` for UART/RTT logging.

---

## 9. Documentation Deliverables

In-tree, committed alongside the code:

- `docs/observability/README.md` — pillars overview, replaces scattered
  references in `docs/operations/perf-tuning.md`.
- `docs/observability/metrics-catalog.md` — every instrument: name, type,
  unit, attributes, semantic meaning, alert thresholds.
- `docs/observability/otlp-setup.md` — production guides:
  - Self-hosted: OTel Collector → Prometheus + Tempo + Loki
  - Datadog (direct)
  - Honeycomb (direct)
  - Grafana Cloud (direct)
  - mTLS on OTLP/gRPC (tonic config example)
- `docs/observability/tracing-guide.md` — span inventory, propagation,
  sampling tuning.
- `docs/observability/grafana/` — REPLACED the removed `docs/operations/grafana/`.
  Dashboards updated to consume Prometheus-exporter-translated OTel names.
  Add a Tempo panel for span drill-down. Exemplar markers on the handshake
  latency graph.
- `docs/observability/prometheus/alerts.yml` — REPLACED the removed
  `docs/operations/prometheus/alerts.yml`. Rewritten under new naming.
- `docs/observability/otel-collector/otel-collector-config.yaml` —
  production-ready Collector config with `tail_sampling` processor for
  failure-biased trace export.
- `examples/observability-demo/` — sibling crate (not a workspace member,
  matching `examples/wasm-demo` pattern). Brings up `phantom-server`, OTel
  Collector, Prometheus, Tempo, Grafana via `docker compose up`.
- `README.md` — Observability section updated, links to new docs.
- `CHANGELOG.md` — Unreleased: BREAKING change recorded.

---

## 10. Testing Plan

### Shipped

| Test | Location | Coverage |
|------|----------|----------|
| Atomics correctness | `core/tests/observability_atomics.rs` | Per-leg counters monotone, concurrent 8-thread contention, snapshot round-trip |
| ZST no-op path | `core/tests/observability_no_otel.rs` | Compiles + runs with the feature off; labeled API is a no-op but atomics still account |
| OTel labeled surface | `core/tests/observability_otel.rs` (feature-gated) | Every labeled recorder is callable and panic-free with a live global `MeterProvider`; snapshot stays consistent |
| Hot-path bench | `core/benches/observability_bench.rs` | `record_send` overhead, contended + uncontended; snapshot cost |
| Config | `core/src/observability/config.rs` unit tests | Namespace default/override, histogram boundary ordering |

### Cardinality contract — enforced by the type system

There is intentionally no runtime "no-PII" test. The contract is enforced
at **compile time**: every `record_*` method takes typed enums
(`HandshakeOutcome`, `ReplayReason`, `LegType`, …), never a free-form
string. There is no API surface through which `peer_ip` / `session_id` /
`stream_id` could be passed as a label — the compiler rejects it. A
runtime test would be strictly weaker than this static guarantee.

### Deferred follow-ups

- **Export-capture test** (`InMemoryMetricExporter`) asserting emitted
  instrument names / units / attribute keys. Deferred: the in-memory
  exporter's API is unstable across the `opentelemetry_sdk` 0.27–0.29
  line. Worth adding once the project pins a single SDK minor.
- **Exemplar test** — blocked on exemplar-reservoir wiring (see §6).

---

## 11. Breaking Changes & Migration

`CHANGELOG.md` — Unreleased (0.1.1):

```
### Breaking
- Removed:
  - phantom_protocol::transport::metrics module (moved to phantom_protocol::observability)
  - MetricsSnapshot::to_prometheus_text()
  - PhantomListener::metrics_prometheus_text()
- The hyper-based /metrics endpoint in `server/` is replaced by OTLP push.

### Added
- Cargo feature `telemetry-otel`: opt-in OpenTelemetry pipeline.
- phantom_protocol::observability::{Observability, ObservabilityConfig, ...}.
- PhantomListener::observability() -> Arc<Observability>.
- New instruments: cookie/PoW gate counters, early_data outcomes, rekey,
  path validation latency, pacer/bandwidth gauges, buffer-pool counters,
  fallback counters.
- OpenTelemetry traces (spans on handshake, rekey, path validation, accept).

### Migration for downstream embedders
- If you previously consumed metrics_prometheus_text(): run an OTel
  Collector with the Prometheus exporter, or use opentelemetry-prometheus
  directly in your embedder.
- Metric names changed (point→underscore, _total suffix re-added by the
  Prometheus exporter):
    phantom_packets_sent_total   →  phantom_session_packets_total{direction="send"}
    phantom_bytes_sent_total      →  phantom_session_io_By_total{direction="send"}
    phantom_handshake_latency_*  →  phantom_handshake_duration_seconds_*
  Full mapping in docs/observability/metrics-catalog.md.
```

---

## 12. Atomic-Commit Rollout — Live Progress

Each row is one atomic commit. Each commit MUST compile and pass `cargo
test --lib` (plus `cargo check --features telemetry-otel` from step 4
onward). No commit carries the AI-coauthor trailer (project convention).
Tick `[x]` and add the short SHA when landed.

| # | Step | Commit subject | Status | SHA |
|---|------|---------------|--------|-----|
| 1 | Doc plan committed | `docs(observability): OTel refactor working plan` | [x] | `5db2fbc` |
| 2 | Module scaffold + feature gate | `observability: scaffold module + ObservabilityConfig (no OTel deps yet)` | [x] | `e59a1f1` |
| 3 | HotPathAtomics + per-leg arrays + CachePadded | `observability: lock-free HotPathAtomics with per-leg padding` | [x] | `02af467` |
| 4 | Migrate recording sites from old TransportMetrics | `observability: migrate handshake/listener recording sites` | [x] | `f266415` |
| 5 | Delete `transport/metrics.rs`, update PROGRESS.md cross-refs | `observability: remove legacy transport/metrics.rs` | [x] | `e49ad5d` |
| 6 | Add `telemetry-otel` feature + opentelemetry/_sdk deps + ZST shim | `observability: feature-gate OTel deps + ZST no-op PhantomInstruments` | [x] | `085e735` |
| 7 | PhantomInstruments + pre-interned attribute sets | `observability: PhantomInstruments + pre-interned attribute sets` | [x] | `327c641` |
| 8 | Observable callbacks (with_callback) for hot atomics | `observability: bind ObservableCounter callbacks to HotPathAtomics` | [x] | `03c35fb` |
| 9 | Handshake exponential Histogram + exemplars | `observability: Histogram for handshake.duration (exponential base-2)` | [x] | `36b06da` |
| 10 | tracing-opentelemetry span integration | `observability: tracing-opentelemetry bridge + handshake/accept spans` | [x] | `bcaf13b` |
| 11 | Server: telemetry init (OTLP gRPC + zstd + Delta) | `server: OTLP telemetry init (gRPC + zstd + Delta temporality)` | [x] | `a324e5f` |
| 12 | Server: drop metrics_http.rs + hyper deps | `server: drop hand-rolled metrics_http.rs + hyper deps` | [x] | `527addf` |
| 13 | Tests: observability suite (atomics, no-op, otel-integration, cardinality, exemplars) | `tests(observability): atomics, cardinality, exemplars, no-op fallback` | [x] | `623a572` |
| 14 | Bench: hot-path overhead microbench | `bench(observability): hot-path record_send overhead microbench` | [x] | `c8563c6` |
| 15 | Docs: README + metrics-catalog + otlp-setup + tracing-guide | `docs(observability): metrics catalog + OTLP setup + tracing guide` | [x] | `9f731a2` |
| 16 | Docs: rewrite Grafana dashboards + Prometheus alerts under new naming | `docs(observability): rewrite Grafana dashboards + Prometheus alerts` | [x] | `d837fe8` |
| 17 | examples/observability-demo crate with docker-compose stack | `examples: observability-demo (docker-compose: server + collector + grafana)` | [x] | `27721da` |
| 18 | CHANGELOG + README Observability section | `docs: CHANGELOG + README Observability section for OTel pipeline` | [x] | `5822e6f` |
| 19 | CI: add `cargo clippy --features telemetry-otel` job | `ci: clippy job for telemetry-otel feature` | [x] | `5675ecc` |
| 20 | Final sweep: PROGRESS.md Phase 8 entry | `docs(progress): Phase 8 — OTel observability shipped` | [x] | `9d07053` |

### Post-review amendments

A code-review pass after step 20 found doc/code drift — the fixes below
landed as follow-up commits. They are the source of truth where they
contradict the original step rows above (commit subjects are immutable
history; the rows are not edited retroactively).

| Step subject vs. reality | Correction |
|--------------------------|------------|
| Step 9 said "exponential base-2" Histogram | Ships **explicit latency-tuned buckets** (`HistogramConfig` + `.with_boundaries()`). Exponential needs the unstable SDK View API — deferred (§5). |
| Step 11 said "zstd + Delta" | Ships **gzip** compression + **Delta** temporality. zstd is not enabled on the tonic channel; gzip is. |
| Step 13 said "cardinality, exemplars" tests | The cardinality contract is **compile-time** type enforcement (no runtime test needed — §10); the exemplar test is deferred with exemplar wiring. `observability_cardinality.rs` / `observability_exemplars.rs` were not created. |
| Step 7 said "pre-interned attribute sets" | `attrs.rs` ships **typed attribute enums**, not `OnceLock`-interned sets. Interning was dropped as YAGNI for the cold event paths (§5). |
| Deployment surface | `docker-compose.yml` / `Dockerfile` / `.env.example` were updated post-review to drop the removed `PHANTOM_METRICS_BIND` / port 9090. |

---

## 13. Open Questions / Risks

1. **MSRV.** `opentelemetry` 0.27+ may require Rust ≥ 1.75 (current MSRV).
   If a bump is required, record it here and update `.clippy.toml` + CI
   matrix. Decision recorded at step 6.
2. **`opentelemetry-otlp` async runtime coupling.** OTLP exporter uses
   `tonic` which needs `tokio`. Verified compatible with the project's
   `Runtime` abstraction since the server already pins tokio. Library code
   stays runtime-agnostic; only `server/` knows about tonic.
3. **`tracing-opentelemetry` ↔ `tracing` version skew.** Pin both to a
   known-compatible pair at step 10.
4. **Native-histogram Prometheus support.** If the operator's Prometheus
   doesn't support OTel exponential histograms (Prom ≥ 2.40 for native
   histograms, Prom ≥ 3.0 for the OTLP receiver), the collector will fall
   back to fixed buckets — acceptable degradation.
5. **Wire-impact of `phantom.*` rename.** Dashboards / alerts are bundled in
   the same refactor (steps 15-16), so the dashboard set never diverges
   from the metric names in code.

---

## 14. References

- OpenTelemetry specification — semantic conventions:
  <https://opentelemetry.io/docs/specs/semconv/>
- `opentelemetry-rust` repo: <https://github.com/open-telemetry/opentelemetry-rust>
- Native exponential histogram (OTEP 149):
  <https://github.com/open-telemetry/oteps/blob/main/text/0149-exponential-histogram.md>
- Exemplars (OTEP 113): <https://github.com/open-telemetry/oteps/blob/main/text/0113-exemplars.md>
- `tracing-opentelemetry` docs: <https://docs.rs/tracing-opentelemetry/>
- Current Phantom Protocol metrics module (to be deleted): `core/src/transport/metrics.rs`
- Current Phantom Protocol Prometheus endpoint (to be deleted): `server/src/metrics_http.rs`
