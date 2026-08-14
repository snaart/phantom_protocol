# Deployment overview

Index of Phantom Protocol deployment surfaces, with pointers to the
detailed guide for each.

## Server-side

Phantom Protocol ships as a Rust library; you deploy a thin wrapper binary
that calls `PhantomListener::bind` / `accept`. The wrapper is what gets
containerized, packaged, or daemonized.

| Surface | Guide | Notes |
| --- | --- | --- |
| Docker | `docs/operations/docker.md` | Distroless / alpine variants; multi-arch builds. |
| systemd | `docs/operations/systemd.md` | Hardening profile, sysctl tuning, multi-instance template. |
| Kubernetes | [`kubernetes.md`](kubernetes.md) | Deployment + Service + probes + Secrets + PDB + HPA + NetworkPolicy. Operator remains a follow-up. |
| Helm | [`helm/phantom-protocol/`](helm/phantom-protocol/README.md) | Production chart (appVersion 0.2.2) implementing every pattern in `kubernetes.md`. |
| AWS EC2 / bare metal | use `systemd` guide | Same unit file applies. |

## Client-side

Clients link `phantom_protocol` directly (Rust) or through the UniFFI-
generated bindings (Python, Swift, Kotlin, and hand-curated C headers —
all four regenerated and CI-gated by `.github/workflows/bindings.yml`).

| Platform | Status |
| --- | --- |
| Linux server / desktop client | ✅ supported |
| macOS desktop client | ✅ supported |
| Windows desktop client | ✅ supported (CI cross-build) |
| iOS / iPadOS | ✅ supported — Swift binding + `examples/mobile/ios/` sample app |
| Android | ✅ supported — Kotlin binding + `examples/mobile/android/` sample app |
| Browser WASM | ✅ supported — `wasm32-unknown-unknown` is a hard CI gate (`WebSocketLeg` + `WasmRuntime`); see `wasm.md` |
| WASI Preview 2 | ✅ supported — `wasm32-wasip2` hard CI gate (`wasi-leg`); see `wasi.md` |
| Embedded (Cortex-M) | ✅ supported — `thumbv7em-none-eabihf` hard CI gate (`embedded,no-std`) |

## Configuration

Phantom Protocol has no config file or environment-variable surface
itself. Configuration crosses the API boundary via constructor
parameters. Wrapper binaries typically front the SDK with their own
config — see the examples under `core/examples/`.

The relevant runtime-visible knobs are:

| Knob | Where | Notes |
| --- | --- | --- |
| Listen address | `PhantomListener::bind(addr)` | "host:port" |
| Adaptive PoW difficulty | automatic | Tiered by handshake rate; see Phase 1.14. |
| Cipher suite | not negotiated | AES-256-GCM is pinned for every session (the `ClientHello` carries no suite field). `ChaCha20Poly1305` survives as an enum variant for wire stability and is rejected outright under `--features fips`. |
| Wire format version | pinned constant (not negotiated) | `WIRE_VERSION = 6` — a single pinned value; the receive path drops any frame whose version differs. (`PROTOCOL_VERSION = 3` is the borsh handshake version.) |
| Rekey trigger | automatic (`REKEY_SOFT_LIMIT` = 2^32 AEAD invocations) | The data pump rotates the traffic secret itself; `PhantomSession::set_rekey_threshold(u64)` (Rust-only) lowers the watermark for tests. |
| Tracing level | `RUST_LOG` | Standard `tracing_subscriber` filter syntax. |

## Pre-deployment checklist

- [ ] Server long-term `HybridVerifyingKey` distributed to all clients
      out-of-band (so they can pin).
- [ ] Server time synchronized via NTP — cookie / PoW bucketing
      depends on monotonic wall clock.
- [ ] File descriptor limit raised (≥65535) on the server host.
- [ ] `PHANTOM_MAX_SESSIONS` set **below** `LimitNOFILE` and within the memory
      budget; `PHANTOM_MAX_SESSIONS_PER_IP` set for the expected client mix
      (see *Session caps & resource limits* below).
- [ ] sysctl tuning applied (see `systemd.md`).
- [ ] CI build of the wrapper binary completes for all target
      platforms.
- [ ] OTLP collector endpoint configured (`--otlp-endpoint` /
      `OTEL_EXPORTER_OTLP_ENDPOINT`) and reachable from the server pods/hosts.
- [ ] Graceful-shutdown signal handler wired in the wrapper (`SIGTERM`
      → `PhantomListener::shutdown()`).
- [ ] Logs ship to a durable backend (journald → vector → Loki, or
      docker JSON → fluent-bit → Elastic, etc.).

## Session caps & resource limits

The reference server bounds load with two admission-control knobs (CLI flags or
env vars):

| Setting | Env | Default | Purpose |
| --- | --- | --- | --- |
| `--max-sessions` | `PHANTOM_MAX_SESSIONS` | `1024` | Global concurrent-session ceiling. At the cap the accept loop stops accepting — new connections queue in the OS backlog (`somaxconn` / `tcp_max_syn_backlog`) until a session closes. Backpressure, not a hard drop. `0` = unbounded. |
| `--max-sessions-per-ip` | `PHANTOM_MAX_SESSIONS_PER_IP` | `64` | Per-source-IP concurrent-session ceiling. A peer already at the cap has further connections rejected (closed right after the handshake), so one source cannot monopolise the global pool. `0` disables. |
| `--max-recv-memory-mib` | `PHANTOM_MAX_RECV_MEMORY_MIB` | `0` (off) | Receive-side memory the process may commit to peers, in MiB. Lowers `--max-sessions` to the largest number of sessions that fits; refuses to start if the budget cannot hold one. See "Memory" below. |

**Size `PHANTOM_MAX_SESSIONS` against two limits:**

- **File descriptors.** Each session holds ~1 fd. Keep
  `PHANTOM_MAX_SESSIONS` comfortably below `LimitNOFILE` (`systemd.md` sets
  `65535`) so the listen socket, OTLP exporter connection, and transient
  accept churn have headroom — e.g. `max_sessions ≈ LimitNOFILE − 1000`.
- **Memory.** Two different numbers, and using the first one as if it were the
  second is the mistake this section exists to prevent.

  A session carrying ordinary traffic sits around **512 KiB** (send/recv
  buffers plus crypto state), and that is what the Kubernetes guide's
  `~1000 sessions → 512 MiB limit` line is sized from. It is a typical figure,
  not a bound.

  The bound is **108 MiB per session** — `SESSION_RECV_MEMORY_COMMITMENT` in
  `core/src/api/session.rs`, which computes it from the transport's own
  constants so the two cannot drift:

  ```text
    reorder payload    Σ (window_i + 64 KiB), windows ≤ 256 × 64 KiB + 8 MiB   =  40 MiB
    reorder structure  256 streams × 2048 held entries × 128 B                 =  64 MiB
    delivery backlog   the per-session hard cap that tears a flooding peer down =  4 MiB
                                                                                ────────
                                                                                 108 MiB
  ```

  Every term is something the peer picks — how many streams it opens, how much
  it sends, how long it leaves a reassembly hole open — so this is what one
  **authenticated but hostile** peer can make a session hold. It is bounded per
  session; the transport does **not** divide it between concurrent sessions, so
  a process admitting `N` sessions commits `N × 108 MiB` in the worst case
  (`1024 × 108 MiB ≈ 108 GiB` at the default cap). Admission control is the only
  thing that bounds it at process scale, which is why the session cap is a
  memory setting whether or not it was set as one.

  Pick a posture:

  - **Trusted or authenticated-and-accountable clients** (the common case):
    size from the typical figure, leave `--max-recv-memory-mib` off, and watch
    RSS. The worst case needs a peer deliberately holding reassembly holes
    open on hundreds of streams.
  - **Open to the internet**: state the budget. `--max-recv-memory-mib 8192`
    on an 8 GiB host lowers the cap to 75 sessions and logs that it did. That
    is a small number because the guarantee is strong; if it is too small for
    the deployment, the honest fix is more hosts or the first posture, not a
    larger cap.

The per-IP cap is a *session-count* cap, not a handshake-rate limit — an
abusive IP can still trigger (cheap, PoW/cookie-gated) handshakes that are then
rejected. Pre-handshake per-IP rate limiting belongs at the edge (LB / nftables
`ct count` / a reverse proxy).

## Startup, health & telemetry resilience

- **Power-on self-test gates the bind.** Before opening the listen socket the
  server runs `crypto::self_tests::run_post()` — AES-256-GCM round-trip,
  hybrid-KEM and hybrid-sign pairwise consistency, and a HKDF KAT. If any
  primitive is wedged the server logs the failure and exits **without binding**.
  Consequently a `tcpSocket` probe on the app port is a genuine *readiness*
  signal for the crypto path (the port only opens after POST passes), not merely
  "the process is up". Use `tcpSocket` as the **liveness** probe too — there is
  no separate HTTP health port (the SDK ships no HTTP server).
- **An unreachable OTLP collector does NOT block startup.** The OTLP/gRPC
  exporters lazily connect, so the server binds and serves traffic even with the
  collector down; telemetry is buffered/dropped per the SDK's batch policy and
  resumes when the collector returns. (Watch the OTel SDK / Collector's own
  export-failure counters — see `docs/observability/otlp-setup.md`.) The gRPC
  channel is gzip-compressed; the `gzip-tonic` exporter feature is required for
  the server to start (a CI startup smoke test guards this).

## Logging & privacy

Default (INFO/WARN/ERROR) logs carry **no raw per-connection PII**. The peer
address and the 32-byte `SessionId` are personally-correlatable, so the
reference server logs them only at DEBUG (`RUST_LOG=phantom_server=debug`); the
library's always-on handshake span no longer carries `client_ip` either.
Aggregate health (sessions active, handshake outcomes) comes from the OTel
metrics, whose cardinality contract also excludes `peer_ip` / `session_id`.

The one default-level line that includes a source IP is the **per-IP admission
reject** (`per-IP session cap reached`, at WARN) — an abuse signal where the
source is operationally necessary for response (legitimate-interest basis). If
even that must be redacted, run with `PHANTOM_MAX_SESSIONS_PER_IP=0` (disables
the cap and its log) and rate-limit at the edge instead.

## Monitoring

Phantom Protocol emits OpenTelemetry metrics + traces; the library opens **no**
inbound port and serves no `/metrics` endpoint. The reference server
(`phantom-server`, built with the `telemetry-otel` feature) installs an
OTLP/gRPC exporter and **pushes** to an OpenTelemetry Collector. Point it at the
collector with `--otlp-endpoint` / `OTEL_EXPORTER_OTLP_ENDPOINT` (e.g.
`http://otel-collector:4317`); `--otel-service-name` / `OTEL_SERVICE_NAME` and
`--otel-trace-sample-ratio` / `OTEL_TRACES_SAMPLER_ARG` (head-sampling ratio for
root spans, default `1.0` = export everything) tune the export, and
`OTEL_EXPORTER_OTLP_HEADERS` carries auth headers for SaaS backends.

Data flow:

```
phantom-server  --OTLP/gRPC push-->  OTel Collector  -->  backend
```

The collector fans out to the backend of your choice — Prometheus (via the
collector's `prometheusexporter` or `remote_write`), Tempo / Jaeger for traces,
or Datadog / Honeycomb / Grafana Cloud directly. To land metrics in Prometheus,
run a collector with an `otlp` receiver plus a `prometheus` exporter and have
Prometheus scrape the **collector** — never the phantom pods. The starter
dashboard lives at `docs/observability/grafana/phantom-otel-dashboard.json`,
the alert rules at `docs/observability/prometheus/alerts.yml`, and the full
instrument catalog at `docs/observability/metrics-catalog.md`. OTLP backend
recipes are in `docs/observability/otlp-setup.md`.

Prometheus names follow the OTel dot→underscore translation. Key alerting
signals:

| Signal | Reaction |
| --- | --- |
| `phantom_handshake_duration_seconds` failure/spike | Investigate — could be misconfigured clients or active scan. |
| `phantom_security_aead_failed_total` rate spike | Tampering or corruption — page on-call. |
| `phantom_session_active` (label: `leg`) near process limit | Scale horizontally. |
| `phantom_session_packets_total` / `phantom_session_io_bytes_total` flatlining | Traffic stall — investigate the leg. |
| `phantom_handshake_duration_seconds` p95 > 1s | Investigate CPU / RNG / adaptive-PoW saturation. |

## Capacity planning

Per-session memory cost: ~64 KiB working estimate (BytesMut accumulator,
per-stream queues, replay window, crypto state). A 1 GiB-RAM host can
hold ~15k concurrent sessions in steady state.

Per-session CPU cost: AES-256-GCM saturates at ~4 GiB/s per core on
modern CPUs (Apple M1 / x86_64 with AES-NI). For 1 GiB/s of aggregate
encrypted traffic budget ~1 core for crypto plus 1-2 cores for the
async runtime and TCP stack.

Handshake CPU cost: full hybrid PQC handshake is on the order of
1-3 ms per accept on a typical server. Adaptive PoW (Phase 1.14)
raises the per-handshake cost under load to protect against SYN floods
— budget headroom for 2-4× handshake cost during a defended attack.

## See also

- `docs/operations/docker.md`
- `docs/operations/systemd.md`
- `docs/operations/perf-tuning.md`
- `docs/security/incident-response.md` — runbook when a metric trips.
