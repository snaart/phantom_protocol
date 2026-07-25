# Phantom Protocol Metrics Catalog

Single source of truth for every OTel metric instrument the library
registers (the always-on snapshot surface is covered in its own section
below). Instrument names use OTel dotted notation under the `{namespace}.*`
prefix. The namespace is **hard-wired to `phantom`**: every production
construction site calls `Observability::new(ObservabilityConfig::default())`
(`api/listener.rs:219`, `api/session.rs:599`, `api/udp_listener.rs:149`) and
there is no seam to inject a custom `ObservabilityConfig`.
`ObservabilityConfig::from_env` — the only reader of
`PHANTOM_TELEMETRY_NAMESPACE` — currently has no caller, so setting that
variable has no effect. The Prometheus exporter in an OTel Collector
translates dots to underscores and re-adds `_total` for monotonic counters.

Instrument *construction* is unconditional. **20 of the 21 registered
instruments are fed by a live recording call site** in the library today;
the tables below carry a **Status** column naming that call site. The one
exception is `phantom.transport.fallback`, which has no possible source —
see its row under *Path & migration*.

Two honest partial gaps survive inside otherwise-live instruments, called
out in the rows themselves and worth knowing before you build an alert on
them:

- **`phantom.session.early_data`** emits nothing when the server has
  `set_early_data_enabled(false)` and a client still offers early data.
  `EarlyDataOutcome` models no "disabled by policy" variant, so that case
  produces no sample at all rather than a rejection sample.
- **`phantom.path.validation.duration`** has no timeout sweep behind it.
  Only an actual response to a challenge produces a sample; a challenge
  that is never answered records neither `success` nor `failure`.

Whether recorded values reach a backend depends on whether the embedder
installs a `MeterProvider` with an OTLP exporter. Note also that the
labeled synchronous instruments (cookie, PoW, rekey, early-data,
resumption, path-migration, path-validation) are **OTel-only** — they have
no atomic mirror, so they are visible only in a `telemetry-otel` build.
The observable instruments below are atomic-backed and additionally
surface through `metrics_snapshot()` in every build.

## Hot-path observables (via `ObservableCounter` / `ObservableGauge`)

These are read from lock-free atomics on each SDK collection cycle.

| OTel name | Type | Unit | Attributes | Status |
|-----------|------|------|------------|--------|
| `phantom.session.packets` | ObservableCounter | — (no unit set) | `direction` (send/recv), `leg` — all four label values are observed every cycle: `tcp`, `udp` (PhantomUDP), `faketls` (mimicry builds only), `kcp` (retained-but-dead, always 0) | live |
| `phantom.session.io` | ObservableCounter | `By` | `direction`, `leg` (same four values) | live |
| `phantom.crypto.encrypt.duration_sum` | ObservableCounter | `ns` | — | live — `timed_encrypt` (`api/session.rs`) wraps every pump-side `Session::encrypt_packet`; times the AEAD call only |
| `phantom.crypto.encrypt.invocations` | ObservableCounter | — (no unit set) | — | live — same call site; **successful seals only**, so the count is "packets actually sealed" |
| `phantom.crypto.decrypt.duration_sum` | ObservableCounter | `ns` | — | live — `handle_packet` (`api/session.rs`) times `decrypt_packet_accepting_rekey`; the timer stops before any routing |
| `phantom.crypto.decrypt.invocations` | ObservableCounter | — (no unit set) | — | live — same call site; **successful opens only**, so a rejected forgery cannot skew the average |
| `phantom.path.rtt` | ObservableGauge | `us` | `path_id` — the **inbound** `header.path_id` of the ACK. Stored slots are `0..=15` (`MAX_PATHS = 16`); a sample on a higher id is silently dropped by the atomics, and the gauge observes only paths whose last sample is non-zero | live — `feed_bbr_on_ack` (`api/session.rs`) on the authenticated-SACK path. Karn-gated: an ACK for a retransmit is not sampled, and a zero-µs sample is skipped |

## Synchronous labeled instruments

These fire at the point of the event.

### Handshake & session

| OTel name | Type | Unit | Attributes | Status |
|-----------|------|------|------------|--------|
| `phantom.handshake.duration` | Histogram (explicit latency buckets) | `s` | `outcome` (success/failure), `leg` (`tcp`/`udp`, plus `faketls` on mimicry builds), `cipher_suite` (always `aes-256-gcm` today — every call site passes `AeadAlgorithm::Aes256Gcm`), `version` (v1) | live |
| `phantom.handshake.resumptions` | Counter | — (no unit set) | `mode` (1rtt/0rtt), `accepted` (bool) | live — `process_client_hello` (`transport/handshake.rs`), one sample per hello carrying a `resume_session_id`. `mode` is what the client *asked* for (a sealed early-data blob ⇒ `0rtt`); `accepted` is whether the server honored exactly that |
| `phantom.session.early_data` | Counter | — (no unit set) | `outcome` (accepted / rejected_unknown_ticket / rejected_oversized / rejected_aead / rejected_replay) — all five variants are reachable | live — `process_client_hello`, one sample per hello carrying a sealed blob. **Partial gap:** the sample is emitted only while the server has early data enabled. Under `set_early_data_enabled(false)` (the A2b 0-RTT kill switch) an offered blob produces **no** sample — that is an operator policy decision, and `EarlyDataOutcome` models no "disabled by policy" variant |
| `phantom.session.rekey` | Counter | — (no unit set) | `direction` (send/recv) | live — `send` from `rekey_before_stamp` on a **committed** local rotation; `recv` once per **committed** catch-up step in `handle_packet` (bounded by `MAX_REKEY_CATCHUP`). Nothing is counted for a rotation that failed or a forward epoch that failed AEAD |
| `phantom.session.active` | UpDownCounter | — (no unit set) | `leg` | live (opened/closed by `run_data_pump`) |
| `phantom.session.streams.active` | UpDownCounter | — (no unit set) | — | live — via the balanced per-session `StreamGauge` (`api/session.rs`). Reserved ids **0** (control) and **1** (raw-app default) are excluded, so this counts user-visible streams only; the gauge drains at session teardown, so it returns to zero |

### Security

| OTel name | Type | Unit | Attributes | Status |
|-----------|------|------|------------|--------|
| `phantom.security.replay_rejected` | Counter | — (no unit set) | `reason` — always `duplicate` today (`decrypt_packet` does not surface old-vs-duplicate) | live |
| `phantom.security.aead_failed` | Counter | — (no unit set) | `leg`, `algorithm` (always `aes-256-gcm` today) | live |
| `phantom.security.unencrypted_dropped` | Counter | — (no unit set) | `leg` | live |
| `phantom.security.cookie` | Counter | — (no unit set) | `outcome` (issued/validated_ok/validated_mismatch) | live — `udp_admit` (the UDP demux pre-gate) and `cookie_pow_gate` (`transport/handshake.rs`). A *presented* cookie records `validated_ok` / `validated_mismatch`; the retry path records `issued`. A hello with no cookie is not a validation event, and a `validate_cookie` infra error (clock) records nothing |
| `phantom.security.pow` | Counter | — (no unit set) | `outcome` (solved/rejected), `difficulty` (int, the per-IP adaptive tier) | live — `cookie_pow_gate`. Recorded only when `difficulty > 0` **and** the hello presented a solution; a hello with no solution is first contact (a challenge is issued) and records nothing, so normal traffic does not drown the rejection signal |

### Path & migration

The library does single-path connection migration only (multipath
aggregation was removed in the PhantomUDP rewrite). Migration and path
validation are both wired; the *fallback* instrument — a multipath-era
leftover — is the one instrument in the whole catalog with no source.

| OTel name | Type | Unit | Attributes | Status |
|-----------|------|------|------------|--------|
| `phantom.path.migrations` | Counter | — (no unit set) | `from_path`, `to_path` (int path ids). `to_path` is `1..=254` for an active migration (`next_migration_path_id` wraps 254 → 1, skipping 0 and 255) and **255** for an M-3 passive NAT rebind — which is exactly what distinguishes the two on a dashboard | live — four call sites in `api/session.rs`: the `Migrate` command arm (local client migration), the `MigrateServer` arm, peer-migration detection on an authenticated forward `path_id`, and the M-3 passive-rebind promotion |
| `phantom.path.validation.duration` | Histogram (explicit latency buckets) | `s` | `path_id`, `outcome` (success/failure) | live — recorded in `handle_packet`'s `PATH_VALIDATION` arm when an outstanding challenge this side issued resolves. **Partial gap:** there is no timeout sweep in the pump, so a challenge that is never answered records **neither** outcome — only a real response (matching or not) produces a sample |
| `phantom.transport.fallback` | Counter | — (no unit set) | `from_leg`, `to_leg`, `reason` (loss_threshold/rtt_threshold/path_failure/explicit) | **not emitted — no possible source.** `transport/fallback.rs`'s `FallbackStateMachine` is constructed into every `Session` but none of its mutators is ever called, so there is no fallback *event* to record. The instrument and `attrs.rs::FallbackReason` are kept as a stable, pre-declared telemetry surface |

## Always-on snapshot (no `telemetry-otel` required)

`PhantomSession::metrics_snapshot()` / `PhantomListener::metrics_snapshot()`
return `MetricsSnapshotFfi`, a flat UniFFI record read straight from the
lock-free atomics — available regardless of the `telemetry-otel` feature.
Fields: `packets_sent`, `packets_recv`, `bytes_sent`, `bytes_recv`,
`avg_encrypt_ns`, `avg_decrypt_ns`, `encrypt_count`, `decrypt_count`,
`rtt_us_path_0`, `active_sessions`, `active_streams`, `handshakes_success`,
`handshakes_failure`, `handshake_latency_ns_sum`, `handshake_latency_count`,
`replay_rejected_total`, `aead_failure_total`, `uptime_secs`.
The Rust-only `MetricsSnapshot` adds `per_leg_packets` / `per_leg_bytes`
(`[(LegType, sent, recv); 4]`).

All of these fields are populated on a live session, including the ones
that used to read zero:

- `avg_encrypt_ns` / `encrypt_count` / `avg_decrypt_ns` / `decrypt_count` —
  fed by the same `timed_encrypt` / `handle_packet` timers as the OTel
  crypto-duration counters, so they count successful seals / opens only.
- `rtt_us_path_0` — the only per-path RTT slot the FFI snapshot exposes.
  It is keyed on the **inbound** `path_id`, which stays 0 until the *peer*
  migrates, so it keeps reporting across a local `migrate()`.
- `active_streams` — the balanced `StreamGauge`, user-visible streams only
  (reserved ids 0 and 1 excluded).

Caveat: on a server-accepted session the counters are the owning
listener's aggregate, not per-connection. The labeled OTel-only counters
(cookie / PoW / rekey / early-data / resumption / path-migration /
path-validation) have no snapshot mirror — they are visible only through
an OTLP pipeline in a `telemetry-otel` build.

## Resource attributes (set by the embedder)

| Attribute | Source | Example |
|-----------|--------|---------|
| `service.name` | embedder builder | `phantom-server` |
| `service.version` | `CARGO_PKG_VERSION` | `0.2.2` |
| `service.instance.id` | not set by the reference embedder — add it yourself via `OTEL_RESOURCE_ATTRIBUTES` or a custom `Resource` | `phantom-server-abc123` |
| `phantom.role` | embedder | `server` / `client` |
| `telemetry.sdk.name`, `telemetry.sdk.language`, `telemetry.sdk.version` | added by the OTel SDK's default detectors | — |
| `host.name`, `os.type`, `process.pid`, `process.runtime.name` | **not** collected — the reference server wires no resource detectors (`opentelemetry-resource-detectors` is not a dependency); set them via `OTEL_RESOURCE_ATTRIBUTES` | — |

## Cardinality contract

The library will NEVER emit these as OTel attribute values:

- `peer_ip` — high cardinality (IPv4/IPv6 universe)
- `session_id` — uniquely identifies a session; would explode time series
- `stream_id` — per-session multi-cardinality

None of these appear at any of the recording call sites now that the
instruments are wired: the path metrics label on `path_id` / `from_path` /
`to_path` (each a `u8`, so at most 256 values), the PoW counter labels on
the integer `difficulty` tier, and `phantom.session.streams.active` carries
**no** attributes at all — it is an unlabeled aggregate precisely so that
per-stream identity never becomes a dimension.

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
- `addr` (listener-bind span). Note `path_id` is **both** a span field and a
  bounded metric attribute (`phantom.path.rtt`,
  `phantom.path.validation.duration`, and as `from_path` / `to_path` on
  `phantom.path.migrations`). It is a `u8`, so the label space is at most
  256 values — and on `phantom.path.rtt` the atomics narrow it further to
  `0..=15` — which is not a cardinality risk.

The peer IP / `client_ip` is **never** emitted — neither as a span field
nor as a metric label (it is correlatable PII; the DoS gate has it
in-band). `session_id` is likewise never a span field or a metric label.
