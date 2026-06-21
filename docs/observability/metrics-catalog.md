# Phantom Protocol Metrics Catalog

Single source of truth for every metric instrument the library emits.
Instrument names use OTel dotted notation under the `{namespace}.*`
prefix (`namespace=phantom` by default; override via
`PHANTOM_TELEMETRY_NAMESPACE`). The Prometheus exporter in an OTel Collector
translates dots to underscores and re-adds `_total` for monotonic counters.

All instruments are emitted unconditionally on the recording side; whether
they reach a backend depends on whether the embedder installs a
`MeterProvider` with an OTLP exporter.

## Hot-path observables (via `ObservableCounter` / `ObservableGauge`)

These are read from lock-free atomics on each SDK collection cycle.

| OTel name | Type | Unit | Attributes |
|-----------|------|------|------------|
| `phantom.session.packets` | ObservableCounter | `{packet}` | `direction` (send/recv), `leg` (tcp/faketls/…) |
| `phantom.session.io` | ObservableCounter | `By` | `direction`, `leg` |
| `phantom.crypto.encrypt.duration_sum` | ObservableCounter | `ns` | — |
| `phantom.crypto.encrypt.invocations` | ObservableCounter | `{op}` | — |
| `phantom.crypto.decrypt.duration_sum` | ObservableCounter | `ns` | — |
| `phantom.crypto.decrypt.invocations` | ObservableCounter | `{op}` | — |
| `phantom.path.rtt` | ObservableGauge | `us` | `path_id` (0..=15) |

## Synchronous labeled instruments

These fire at the point of the event.

### Handshake & session

| OTel name | Type | Unit | Attributes |
|-----------|------|------|------------|
| `phantom.handshake.duration` | Histogram (explicit latency buckets) | `s` | `outcome` (success/failure), `leg`, `cipher_suite` (aes-256-gcm/chacha20-poly1305), `version` (v1) |
| `phantom.handshake.resumptions` | Counter | `{resumption}` | `mode` (1rtt/0rtt), `accepted` (bool) |
| `phantom.session.early_data` | Counter | `{attempt}` | `outcome` (accepted / rejected_unknown_ticket / rejected_oversized / rejected_aead / rejected_replay) |
| `phantom.session.rekey` | Counter | `{rekey}` | `direction` (send/recv) |
| `phantom.session.active` | UpDownCounter | `{session}` | `leg` |
| `phantom.session.streams.active` | UpDownCounter | `{stream}` | — |

### Security

| OTel name | Type | Unit | Attributes |
|-----------|------|------|------------|
| `phantom.security.replay_rejected` | Counter | `{packet}` | `reason` (old/duplicate) |
| `phantom.security.aead_failed` | Counter | `{operation}` | `leg`, `algorithm` |
| `phantom.security.unencrypted_dropped` | Counter | `{packet}` | `leg` |
| `phantom.security.cookie` | Counter | `{cookie}` | `outcome` (issued/validated_ok/validated_mismatch) |
| `phantom.security.pow` | Counter | `{challenge}` | `outcome` (solved/rejected), `difficulty` (int) |

### Multi-path

| OTel name | Type | Unit | Attributes |
|-----------|------|------|------------|
| `phantom.path.migrations` | Counter | `{migration}` | `from_path`, `to_path` |
| `phantom.path.validation.duration` | Histogram (explicit latency buckets) | `s` | `path_id`, `outcome` (success/failure) |
| `phantom.transport.fallback` | Counter | `{fallback}` | `from_leg`, `to_leg`, `reason` (loss_threshold/rtt_threshold/path_failure/explicit) |

## Resource attributes (set by the embedder)

| Attribute | Source | Example |
|-----------|--------|---------|
| `service.name` | embedder builder | `phantom-server` |
| `service.version` | `CARGO_PKG_VERSION` | `0.2.1` |
| `service.instance.id` | hostname or UUID | `phantom-server-abc123` |
| `phantom.role` | embedder | `server` / `client` |
| `host.name`, `os.type`, `process.pid`, `process.runtime.name` | auto-detected | — |

## Cardinality contract

The library will NEVER emit these as OTel attribute values:

- `peer_ip` — high cardinality (IPv4/IPv6 universe)
- `session_id` — uniquely identifies a session; would explode time series
- `stream_id` — per-session multi-cardinality

If you ship a custom recording call site in your embedder, follow the same
rule. SDK cardinality limits (default 2000 per instrument) act as a second
line of defense.

## Suggested alert thresholds

Indicative starting points — tune to your traffic profile and SLO.

| Alert | Expression (PromQL-style) | Severity |
|-------|---------------------------|----------|
| AEAD failures spike | `rate(phantom_security_aead_failed_total[5m]) > 0.5/s` | high — active tampering or corruption |
| Unencrypted-flag downgrade | `increase(phantom_security_unencrypted_dropped_total[15m]) > 0` | critical — active downgrade attempt |
| Handshake failure rate | `rate(phantom_handshake_duration_seconds_count{outcome="failure"}[5m]) / rate(phantom_handshake_duration_seconds_count[5m]) > 0.1` | medium |
| P99 handshake latency | `histogram_quantile(0.99, sum by (le) (rate(phantom_handshake_duration_seconds_bucket[5m]))) > 0.5` | medium |
| Active sessions saturation | `phantom_session_active >= 0.9 * <provisioned-max>` | warn — scale up |
| Replay rejections rising | `rate(phantom_security_replay_rejected_total[10m]) > 1/s` | medium — possible attack or clock skew |

## Attributes that are **traces-only** (not metric labels)

These appear as span attributes (`tracing` field machinery) but are
explicitly NOT in the metric label set. Use traces for drill-down.

- handshake details: `difficulty`, `has_cookie`, `has_pow`, `resume`,
  `has_early_data` (server-side), `pinned` (client-side)
- `path_id` (path-validation spans), `addr` (listener-bind span)

The peer IP / `client_ip` is **never** emitted — neither as a span field
nor as a metric label (it is correlatable PII; the DoS gate has it
in-band). `session_id` is likewise never a span field or a metric label.
