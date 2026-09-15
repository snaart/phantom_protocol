# Deployment overview

Index of Phantom Protocol deployment surfaces, with pointers to the
detailed guide for each.

## Server-side

Phantom Protocol ships as a Rust library; you deploy a thin wrapper binary
that binds a listener and runs its `accept` loop. The wrapper is what gets
containerized, packaged, or daemonized.

**The reference wrapper, `phantom-server`, binds the TCP leg only.** It listens
with `PhantomListener::bind_with_signing_key` on `--bind` and opens no UDP
socket, so it does not serve PhantomUDP — the transport recommended under
*Choosing a transport* below — and the root `Dockerfile`, `docker-compose.yml`
and the Helm chart expose and probe TCP 4242 to match. A PhantomUDP deployment
embeds `PhantomUdpListener` in its own wrapper:
`PhantomUdpListener::bind_udp_with_signing_key_bytes` accepts the same 64-byte
seed that `phantom-cli keygen` and `phantom-server` write, so one pinned
identity can serve both transports. The guides in the table below are written
for the TCP wrapper; for a UDP one, publish and allow the port as UDP, and
replace the `tcpSocket` probes, which have nothing to connect to on a UDP port.

| Surface | Guide | Notes |
| --- | --- | --- |
| Docker | `docs/operations/docker.md` | Distroless / alpine variants; multi-arch builds. |
| systemd | `docs/operations/systemd.md` | Hardening profile, sysctl tuning, multi-instance template. |
| Kubernetes | [`kubernetes.md`](kubernetes.md) | Deployment + Service + probes + Secrets + PDB + HPA + NetworkPolicy. Operator remains a follow-up. |
| Helm | [`helm/phantom-protocol/`](helm/phantom-protocol/README.md) | Production chart (appVersion 0.3.0) implementing every pattern in `kubernetes.md`. |
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

## Choosing a transport

Bind PhantomUDP (`PhantomUdpListener::bind_udp`) unless something stops you. It
is the production transport: it is the one that can migrate a live session across
a network change, and it is the one whose reliability and congestion control have
somewhere to work. Every other row below it is a fallback for reach.

| Leg | Deploy it when | What you give up |
| --- | --- | --- |
| PhantomUDP | always, by default | nothing — this is the reference path |
| TCP | UDP is blocked, throttled, or unavailable to the client — carrier NAT, corporate egress filtering, a proxy that only forwards streams | latency under load (below), and `migrate()` — it returns `Err(Unsupported)` |
| Mimicry (`mimicry` feature) | the deployment additionally needs the flow to look like HTTPS to a passive classifier | everything TCP gives up, plus the honest caveats in `docs/security/threat-model.md` § 6.1 — it is obfuscation, not a security boundary |
| WebSocket | the client is a browser | as TCP |

### Phantom over TCP is for compatibility, not for speed

Worth stating plainly, because the leg is easy to reach for and its cost is
invisible until a real path is under load.

Phantom's reliability layer — ARQ, SACK-driven loss detection, BBR-style
congestion control — is transport-independent and runs unchanged on every leg.
Over a datagram socket it is the only such layer, which is the arrangement it was
designed for. Over TCP it is the second one: the kernel below it already
retransmits, already sequences, and already has a congestion window of its own.
Neither loop can see the other, so they interact only through the queue between
them — and that queue is inside the round-trip figure our side measures, so a
filling kernel send buffer reads to us as a lengthening path.

Measured, by the WAN harness in `testbed/`:

| Observation on the TCP leg | Figure | Read it as |
| --- | --- | --- |
| min-RTT, worst seen | up to **4112 ms** | queueing under our own sender; no route the harness runs over is four seconds long |
| application throughput | moved with the route from run to run | quote only a figure with a same-run control beside it, like the row below |
| run `20260822-062705`, both ends from `8f710f69` | 4.83 Mbit/s received by the server | raw UDP echo measured 13.26 Mbit/s round-trip and the one-way downlink ceiling 20.90 Mbit/s on that path in that run |

How the harness measures, and which control each figure is read against, is in
`testbed/README.md`; the campaigns themselves, with their controls and caveats,
are summarised under *Performance* in the root `README.md`. Do not quote a
throughput number from the table above without the raw control from the same
run beside it: the one-way downlink ceiling on that route read 60–63 Mbit/s on
2026-08-17, 21 Mbit/s five days later and 76.5 Mbit/s on 2026-09-05.

None of this touches correctness or security. The leg carries the identical inner
wire (`docs/protocol/PROTOCOL.md`), and pinning, the AEAD and the replay window
sit above the transport and behave the same on all of them. Two things follow for
an operator. If your clients can reach a UDP port, give them one, and offer TCP as
the fallback rather than the default. And if you must run TCP for everyone,
size expectations against the numbers above rather than against `BENCHMARKS.md`,
whose figures are loopback and in-process and say nothing about a queue on a real
path.

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
| Cipher suite | not negotiated, and not selectable | The `ClientHello` carries no suite field and no API accepts one: each peer resolves it from its own target. AES-256-GCM where the CPU reports the AES extension on `x86`/`x86_64`/`aarch64`, **ChaCha20-Poly1305 unconditionally everywhere else** — every `wasm32` build included. Both ends must land on the same answer or the session establishes and then carries nothing; see `docs/protocol/PROTOCOL.md` § 2. Under `--features fips` it is pinned to AES-256-GCM and `ChaCha20Poly1305` is rejected outright. |
| Wire format version | pinned constant (not negotiated) | `WIRE_VERSION` = <!--pinned:WIRE_VERSION-->8 — a single pinned value; the receive path drops any frame whose version differs. (`PROTOCOL_VERSION` = <!--pinned:PROTOCOL_VERSION-->5 is the borsh handshake version.) |
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
      (see *Session caps & resource limits* below). The cap times 8 MiB is the
      process's receive-window-growth commitment on its own — 8 GiB at the
      default, which the server prints at startup. Read it as a floor on what
      the host must have, not a ceiling on what the process will use.
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

  The second number is what an **authenticated but hostile** peer can make one
  session hold, and *there is no single published figure for it*. Every
  receive-side buffer has a bound and each bound has something enforcing it, but
  a sum over them is not a bound on the session: it covers the buffers the
  session layer owns and not the ones underneath — the byte pipe's own receive
  accumulator, PhantomUDP's fragment reassembly, the per-stream structures
  themselves. Three successive attempts to state such a total were each
  corrected upward by a term the previous one had omitted, so the total was
  withdrawn rather than corrected a fourth time. What is published instead is
  the per-buffer table in the API documentation of
  `phantom_protocol::api::session`, which names each bound, what it limits, and
  what enforces it — and marks the two things that are observed rather than
  enforced.

  The rows worth knowing when sizing:

  | buffer | worst case a peer can drive it to | enforced by |
  | --- | --- | --- |
  | receive windows | one session-wide growth budget of 8 MiB over the 16 MiB of initial windows 256 streams start with | the growth budget; the advertised window itself is **not** a gate |
  | reorder buffers | 256 streams × 2048 held entries × ~128 B of structure ≈ 64 MiB, plus payload within each stream's byte budget | per-stream entry cap and byte budget, on out-of-order segments only |
  | delivery backlog | 4 MiB, plus the ~49 KiB of the frame that crossed the line | the session is torn down past the cap |
  | per-stream delivery queues | 256 streams × 1024 slots × 1160 B ≈ 290 MiB | bounded channels; the slot *contents* are bounded by the inbound frame gate |

  So the honest statement is: a hostile peer can move a session's receive
  footprint into the hundreds of megabytes, the dominant term is unread data
  sitting in per-stream delivery queues, and that term is a function of the
  application not reading rather than of anything the transport needs. None of
  it is divided between concurrent sessions, so a process admitting `N` sessions
  is exposed to `N ×` whatever one session reaches — which is why the session
  cap is a memory setting whether or not it was set as one.

  **Every commitment above is per session, and the multiplier is the session
  cap.** For the one row that is an enforced constant rather than a measured
  worst case, that arithmetic is exact:

  ```text
    PHANTOM_MAX_SESSIONS × SESSION_RECV_WINDOW_GROWTH_BUDGET
              1024       ×          8 MiB                    =  8 GiB
  ```

  8 GiB of receive-window growth alone, at the shipped default, before a single
  reorder entry, delivery item or queue slot is counted. **It is a floor on what
  the host must have, not a ceiling on what the process will use.** The other
  rows have no such constant — their per-session figures are worst cases derived
  from several constants apiece — so the same multiplication applied to them
  produces an estimate, not a bound; but the numbers it yields (64 GiB of
  reorder structure, 290 GiB of delivery queues) say plainly which term
  dominates, and it is not this one.

  Nor does the growth allowance need the application's cooperation to be spent.
  The transport credits window growth as the delivery task hands a frame to the
  bounded queue behind `recv()`, which is one queue ahead of the application
  actually reading it, and a peer opens as many streams as it likes — so a peer
  facing an application that never reads still reaches the allowance. The
  allowance is what bounds it; the reader is not.

  Pick a posture:

  - **Trusted or authenticated-and-accountable clients** (the common case):
    size from the typical figure and watch RSS. The worst case needs a peer
    deliberately holding reassembly holes open on hundreds of streams while the
    application reads none of them.
  - **Open to the internet**: measure. Run the deployment's own traffic against
    a session cap you can afford to be wrong about, watch peak RSS per session
    under load, and set `PHANTOM_MAX_SESSIONS` from that with headroom for the
    rows above.

  **Why there is no flag that turns a memory budget into a session cap.** Two
  have been tried and both were removed, and the second removal is the one worth
  recording, because its arithmetic was correct. `--max-recv-memory-mib` divided
  an operator's MiB by a published per-session *total*; that total was an
  estimate corrected upward three times, and a cap derived from an estimate
  under-provisions a host by exactly the factor the estimate is out.
  `--max-recv-window-growth-mib` replaced it and divided by the enforced growth
  constant instead, so its answer was exact — and it was still wrong to offer.
  Its unit is MiB, and nobody reaches for a MiB-denominated server flag except
  with a memory limit in hand — so the number an operator hands it is their
  memory limit, and what comes back is a session cap that same memory cannot
  support, by the ratio between this term and the ones the table above ranks an
  order of magnitude higher. Hand it 8 GiB and it admits 1024 sessions, whose
  reorder structure and delivery queues alone are measured in tens and hundreds
  of gigabytes. A knob whose documentation has to say "do not read this as its unit
  reads" is better as a log line, which is what it now is: `phantom-server`
  prints the product at startup and offers no control that appears to bound it.

  Growth is also an *advertisement* rather than a residency. What the allowance
  buys the peer is the right to have that much outstanding; the bytes it admits
  come to rest in the reorder buffers and the delivery queues, which are the
  rows this term is small next to. That is the second reason its MiB do not
  translate into a memory figure, and the first reason the 8 GiB above is a
  floor rather than a total.

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
