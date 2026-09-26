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

Instrument *construction* is unconditional. **21 of the 22 registered
instruments are fed by a live recording call site** in the library today;
the tables below carry a **Status** column naming that call site. The one
exception is `phantom.transport.fallback`, which has no possible source —
see its row under *Path & migration*.

The two partial gaps that used to sit inside otherwise-live instruments are
now closed, each with its own attribution:

- **`phantom.session.early_data`** records `outcome="rejected_disabled"`
  when the server has `set_early_data_enabled(false)` and a client still
  offers early data, so a flat line no longer conflates "nobody is
  offering 0-RTT" with "the kill switch is on". A hello that offers *no*
  blob is still not an early-data event and emits nothing.
- **`phantom.path.validation.duration`** records `outcome="timeout"` for a
  challenge the peer never answers. The pump's heartbeat expires it after
  the session's own path-down budget (see the row below).

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
| `phantom.path.rtt` | ObservableGauge | `us` | `path_id` — the **inbound** `header.path_id` of the ACK. Stored slots are `0..=15` (`MAX_PATHS = 16`); a sample on a higher id is silently dropped by the atomics, and the gauge observes only paths whose last sample is non-zero | live — `feed_bbr_on_ack` (`api/session.rs`) on the authenticated-SACK path. Karn-gated: an ACK for a retransmit is not sampled, and a zero-µs sample is skipped. The sample is the locally timed round trip less the peer's claimed `Sack::ack_delay_us`, and it is the figure the estimator itself accepted (returned from `Session::on_packet_acked`), so it carries the `ack_delay_adjusted_rtt` bound the min-RTT filter applies (RFC 9002 §5.3). **Read that bound as exactly what it is: a floor.** Once this endpoint has timed a round trip, no reported delay pulls the reading below it — but between that floor and the round trip just observed the peer's claim still decides, so a peer claiming the whole difference on every ACK holds this gauge at the path's best-ever reading and hides a degradation. Alert on it rising; do not read a flat line as proof the path is healthy |

## Synchronous labeled instruments

These fire at the point of the event.

### Handshake & session

| OTel name | Type | Unit | Attributes | Status |
|-----------|------|------|------------|--------|
| `phantom.handshake.duration` | Histogram (explicit latency buckets) | `s` | `outcome` (success/failure), `leg` (`tcp`/`udp`, plus `faketls` on mimicry builds), `cipher_suite` (always `aes-256-gcm` today — every call site passes `AeadAlgorithm::Aes256Gcm`), `version` (v1) | live. **`outcome="success"` means the recording side finished, not that the peer joined.** A server records it once it has derived keys and sent its `ServerHello`, and nothing under the handshake acknowledges that reply, so a flight lost on the way down leaves a session counted successful here whose peer never spoke — one live run held such a session for 135 s with `rx=0, tx=0`. A server's success count exceeding a client's is the ordinary reading of a lossy path, not a contradiction, and it is why the two sides are counted separately; the two `initial_*_on_committed_route` rows and `flight_repeated` are what say whether the reply was asked for again and re-sent |
| `phantom.handshake.resumptions` | Counter | — (no unit set) | `mode` (1rtt/0rtt), `accepted` (bool) | live — `process_client_hello` (`transport/handshake.rs`), one sample per hello carrying a `resume_session_id`. `mode` is what the client *asked* for (a sealed early-data blob ⇒ `0rtt`); `accepted` is whether the server honored exactly that |
| `phantom.handshake.initial_flights_on_committed_route` | Counter | **one flight** (no OTel unit set) | **none** — deliberately unlabeled; the only attribution worth having would be per peer, and peer identity is what the cardinality contract keeps out of labels | live — the PhantomUDP demux (`api/udp_listener.rs`), one sample per **reassembled** handshake message arriving on a connection the listener has already committed a route to, i.e. one per question a client asked again however many datagrams carried it. That is a client repeating its flight because it has not seen the reply, which the server answers by repeating the reply (PROTOCOL § 6.1) — so a small non-zero rate on a lossy path is health, not alarm. What it is for is reading against a client that timed out connecting: non-zero says its questions arrived and one reply flight was lost on the way down; zero says the path fell silent in both directions. Nothing else on either side tells those apart. **Meant to be read together with `phantom.handshake.flight_repeated` below, and it is in the same unit as it.** Mirrored as the always-on `initial_flights_on_committed_route_total` in `MetricsSnapshotFfi`, so it is readable with `telemetry-otel` off |
| `phantom.handshake.flight_repeated` | Counter | **one flight** (no OTel unit set) | **none**, for the same reason | live — the PhantomUDP demux (`api/udp_listener.rs`), one sample per retained reply flight actually repeated, counted where the decision is made rather than where the request arrived. **Meant to be read together with the row above, which is the other half of the same question and in the same unit**: asks **and** repeats is the repair working; asks with no repeats is a listener that had nothing retained for that session (evicted, expired, or its three repeats already spent); no asks at all is a path that never carried the question. The row above cannot distinguish the first two on its own, which is why this exists separately. Mirrored as `handshake_flight_repeated_total` in `MetricsSnapshotFfi` |
| `phantom.handshake.initial_datagrams_on_committed_route` | Counter | **one datagram** (no OTel unit set) | **none**, for the same reason | live — the same demux branch as the flight counter above, but sampled per **datagram** as each one lands and before reassembly. It measures a different quantity: the duplicate wire load a repeating client puts on the listener, which nothing else here measures (the demux keeps no per-packet counters of its own). A cookie-bearing `ClientHello` is three fragments at `MAX_INNER_FRAG_CHUNK`, so it runs at roughly 3× the flight counter on today's messages. **Do not read it against `phantom.handshake.flight_repeated`** — the ratio is the fragment count and reads as answers gone missing, which is a conclusion that has been drawn from a live run. Mirrored as `initial_datagrams_on_committed_route_total` in `MetricsSnapshotFfi` |
| `phantom.handshake.flight_evicted` | Counter | — (no unit set) | **none**, for the same reason | live — the PhantomUDP demux (`api/udp_listener.rs`), one sample per retained reply flight dropped to make room for a newer one. This is the repair running out of the memory it is allowed (PROTOCOL § 6.1 rule 5): the listener is completing handshakes faster than its retention budget covers, and the evicted sessions are back to losing a whole connect to one lost reply datagram. Zero is the expected value below about 139 completed handshakes a second, which is where the 8 MiB budget binds against the 8-second retention; between there and about 1112/s a session still has its answer when its *first* repeat arrives, which is the repeat that pays, and above that it may not. A sustained non-zero rate is the signal to spread the load. Mirrored as `handshake_flight_evicted_total` in `MetricsSnapshotFfi` |
| `phantom.handshake.flight_refused` | Counter | — (no unit set) | **none**, for the same reason | live — `FlightTable::retain` (`api/udp_listener.rs`), one sample per reply flight never retained at all, because repeating it would exceed the RFC 9000 §8.2 amplification limit (PROTOCOL § 6.1 rule 3). The third way the repair can fail to cover a session and the only one that is not about load: the two rows above mean the mechanism ran and then let go, this one means it never armed. It reads zero for every build whose reply is inside the bound — the default build's is 1.99x against a limit of 3 — so a non-zero value says a message size has moved past it, which changes no byte a peer would notice and which nothing else reports. Mirrored as `handshake_flight_refused_total` in `MetricsSnapshotFfi` |
| `phantom.session.early_data` | Counter | — (no unit set) | `outcome` (accepted / rejected_unknown_ticket / rejected_oversized / rejected_aead / rejected_replay / rejected_disabled) — all six variants are reachable | live — `process_client_hello` (`transport/handshake.rs`), one sample per hello **carrying a sealed blob**; a hello that offers no early data is not a 0-RTT decision and emits nothing. `rejected_disabled` is the A2b kill switch (`set_early_data_enabled(false)`): it is checked first, before any ticket lookup or AEAD work, so an operator-disabled server never mis-attributes a blob to a client-side cause. Use it to tell "0-RTT is off here" from "no client is offering 0-RTT" |
| `phantom.session.rekey` | Counter | — (no unit set) | `direction` (send/recv) | live — `send` from `rekey_before_stamp` on a **committed** local rotation; `recv` once per **committed** catch-up step in `handle_packet` (bounded by `MAX_REKEY_CATCHUP`). Nothing is counted for a rotation that failed or a forward epoch that failed AEAD |
| `phantom.session.active` | UpDownCounter | — (no unit set) | `leg` | live (opened/closed by `run_data_pump`) |
| `phantom.session.streams.active` | UpDownCounter | — (no unit set) | — | live — via the balanced per-session `StreamGauge` (`api/session.rs`). Reserved ids **0** (control) and **1** (raw-app default) are excluded, so this counts user-visible streams only. A stream counts from its open until both of its halves have closed — one side's `disconnect()` alone leaves it counted until the peer closes too, for as long as that side's application still holds the stream — or until this side's own close is acknowledged after its application has dropped its handle, whatever the peer does; a stream opened and dropped without a reliable byte written stops counting at once. The gauge drains at session teardown, so it returns to zero |

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
| `phantom.path.validation.duration` | Histogram (explicit latency buckets) | `s` | `path_id`, `outcome` (success/failure/timeout) | live — `success` / `failure` in `handle_packet`'s `PATH_VALIDATION` arm when a response resolves an outstanding challenge; `timeout` from `sweep_path_validation_timeouts` on the pump's 10 ms heartbeat when the peer never answers. Every issued challenge yields **exactly one** sample: whichever of the two paths reaches its start stamp first removes it. The timeout budget is not a new tunable — it is the session's own path-down threshold, `path_down_ptos × max(min_pto, 3 × min_rtt)` from `LivenessConfig` (1.5 s at defaults before the first RTT sample, since the estimator seeds `min_rtt` at 100 ms), i.e. RTT-adaptive and more generous than QUIC's `3 × PTO` (RFC 9000 §8.2.4). `timeout` and `failure` mean different things: a failure is a wrong echo from something holding the session key, a timeout is a path carrying nothing at all. The sweep is metrics-only — it does **not** drive the `PathRegistry` entry to `Failed` (that would permanently burn the `path_id` for a challenge that was merely lost) |
| `phantom.transport.fallback` | Counter | — (no unit set) | `from_leg`, `to_leg`, `reason` (loss_threshold/rtt_threshold/path_failure/explicit) | **not emitted — no possible source.** `transport/fallback.rs`'s `FallbackStateMachine` is constructed into every `Session` but none of its mutators is ever called, so there is no fallback *event* to record. The instrument and `attrs.rs::FallbackReason` are kept as a stable, pre-declared telemetry surface |

## Always-on snapshot (no `telemetry-otel` required)

`PhantomSession::metrics_snapshot()` / `PhantomListener::metrics_snapshot()`
return `MetricsSnapshotFfi`, a flat UniFFI record read straight from the
lock-free atomics — available regardless of the `telemetry-otel` feature.
Fields: `packets_sent`, `packets_recv`, `bytes_sent`, `bytes_recv`,
`avg_encrypt_ns`, `avg_decrypt_ns`, `encrypt_count`, `decrypt_count`,
`rtt_us_path_0`, `active_sessions`, `active_streams`, `handshakes_success`,
`handshakes_failure`, `handshake_latency_ns_sum`, `handshake_latency_count`,
`replay_rejected_total`, `aead_failure_total`, `unencrypted_dropped_total`,
`initial_datagrams_on_committed_route_total`,
`handshake_flight_repeated_total`, `handshake_flight_evicted_total`,
`handshake_flight_refused_total`,
`initial_flights_on_committed_route_total`, `uptime_secs`.
(That order is the record's declaration order, which is the order the
generated bindings read it back in — new fields are appended, never
inserted, so a consumer built against an older header is missing a field
rather than misreading the ones it already knew.)
The Rust-only `MetricsSnapshot` adds `per_leg_packets` / `per_leg_bytes`
(`[(LegType, sent, recv); 4]`).

All of these fields are populated on a live session, including the ones
that used to read zero:

- `avg_encrypt_ns` / `encrypt_count` / `avg_decrypt_ns` / `decrypt_count` —
  fed by the same `timed_encrypt` / `handle_packet` timers as the OTel
  crypto-duration counters, so they count successful seals / opens only.
- `rtt_us_path_0` — the only per-path RTT slot the FFI snapshot exposes.
  It is keyed on the **inbound** `path_id`, which stays 0 until the *peer*
  migrates, so it keeps reporting across a local `migrate()`. It carries the
  same sample as `phantom.path.rtt` above, and the same caveat: the peer's
  claimed ack delay is bounded below by a round trip this endpoint timed, not
  bounded above, so a flat reading is not evidence of a healthy path.
- `active_streams` — the balanced `StreamGauge`, user-visible streams only
  (reserved ids 0 and 1 excluded).
- `unencrypted_dropped_total` — the Invariant-2 receive gate firing. It sits
  in the snapshot rather than in the OTel instruments alone because it is the
  only externally visible evidence that the gate ran: a dropped frame leaves
  no other trace, and an operator on a default build has no OTLP pipeline to
  read. On a healthy connection it stays at zero for the session's whole life.
- `handshakes_success` — handshakes **this side completed**, which is not the
  same as peers that joined. A server records one as soon as it has derived keys
  and sent its `ServerHello`, and nothing under the handshake acknowledges that
  reply, so a reply lost on the way down leaves a session counted here whose peer
  never spoke: a live run recorded one at `dur=135.0 s, rx=0, tx=0`. Read a
  server's total against a client's timeouts as two measurements of one path — the
  asymmetry is the finding, and the three fields below are what say whether the
  reply was asked for again and re-sent.
- `initial_flights_on_committed_route_total` — **one per flight**: clients
  repeating their handshake question at a PhantomUDP listener, counted after
  reassembly. The one field here that is expected to be non-zero on a healthy but
  lossy path: the server answers each repetition by repeating its reply
  (PROTOCOL § 6.1), so the count is repairs happening rather than failures. Read
  it against a client that timed out connecting, where it is the only thing that
  separates "one reply flight was lost on the way down" from "the path went silent
  in both directions". Only a listener has a meaningful value; a client-side
  session's copy is always zero.
- `handshake_flight_repeated_total` — **one per flight**: the answers this
  listener actually sent back, one per repeated flight rather than per datagram of
  it. **Meant to be read together with the field above, which is in the same
  unit**: asks with no repeats is a listener that had nothing retained for that
  session, which needs more retention budget, while no asks at all is a path that
  lost the question, which needs something else entirely. One field cannot
  separate those.
- `initial_datagrams_on_committed_route_total` — **one per datagram**: the same
  arrivals counted as they land and before reassembly, which is the duplicate wire
  load a repeating client costs the listener rather than the number of times it
  asked. Kept because nothing else measures that, and named for its unit because
  it is **not** the field to divide by the one above it: today's cookie-bearing
  hello is three fragments, so the ratio is the fragment count and reads as
  answers gone missing.
- `handshake_flight_evicted_total` — retained answers dropped to make room for
  newer ones. Expected to be zero. Non-zero says the repair is out of the memory
  it is allowed and that some sessions are silently back to the behaviour that
  made a single lost reply datagram cost a whole connect. It is a load figure:
  the budget holds about 1112 of today's flights, an unanswered one lives its
  whole 8-second retention, so the table binds at roughly 139 completed
  handshakes a second and covers every session's *first* repeat up to about
  1112/s.
- `handshake_flight_refused_total` — answers that were never retained, because
  repeating one would have exceeded the amplification limit. Unlike the field
  above this is not about load and not about any particular session: it reads
  zero for every build whose reply is inside the bound, so a non-zero value
  means the messages themselves have grown past it and the repair has stopped
  arming for everyone.

Caveat: on a server-accepted session the counters are the owning
listener's aggregate, not per-connection. The labeled OTel-only counters
(cookie / PoW / rekey / early-data / resumption / path-migration /
path-validation) have no snapshot mirror — they are visible only through
an OTLP pipeline in a `telemetry-otel` build.

## Resource attributes (set by the embedder)

| Attribute | Source | Example |
|-----------|--------|---------|
| `service.name` | embedder builder | `phantom-server` |
| `service.version` | `CARGO_PKG_VERSION` | `0.3.0` |
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
