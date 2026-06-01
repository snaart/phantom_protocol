# Deployment overview

Index of Phantom Core deployment surfaces, with pointers to the
detailed guide for each.

## Server-side

Phantom Core ships as a Rust library; you deploy a thin wrapper binary
that calls `PhantomListener::bind` / `accept`. The wrapper is what gets
containerized, packaged, or daemonized.

| Surface | Guide | Notes |
| --- | --- | --- |
| Docker | `docs/operations/docker.md` | Distroless / alpine variants; multi-arch builds. |
| systemd | `docs/operations/systemd.md` | Hardening profile, sysctl tuning, multi-instance template. |
| Kubernetes | [`kubernetes.md`](kubernetes.md) | Deployment + Service + probes + Secrets + PDB + HPA + NetworkPolicy. Helm chart + operator remain a follow-up. |
| AWS EC2 / bare metal | use `systemd` guide | Same unit file applies. |

## Client-side

Clients link `phantom_core` directly (Rust) or through the UniFFI-
generated bindings (Python today; Swift / Kotlin / C are
Phase 3.9 work).

| Platform | Status |
| --- | --- |
| Linux server / desktop client | ✅ supported |
| macOS desktop client | ✅ supported |
| Windows desktop client | ✅ supported (CI cross-build) |
| iOS / iPadOS | ⏳ Phase 3.9 — Swift binding pending |
| Android | ⏳ Phase 3.9 — Kotlin binding pending |
| Browser WASM | 🔄 Phase 3.3 — `WebSocketLeg` lands, full crate-level wasm build pending |
| Embedded (Cortex-M) | ⏳ Phase 3.4 |

## Configuration

Phantom Core has no config file or environment-variable surface
itself. Configuration crosses the API boundary via constructor
parameters. Wrapper binaries typically front the SDK with their own
config — see the examples under `core/examples/`.

The relevant runtime-visible knobs are:

| Knob | Where | Notes |
| --- | --- | --- |
| Listen address | `PhantomListener::bind(addr)` | "host:port" |
| Adaptive PoW difficulty | automatic | Tiered by handshake rate; see Phase 1.14. |
| Cipher suite | negotiated at handshake | AES-256-GCM or ChaCha20-Poly1305 — see `device_profile.rs` |
| Wire format version | negotiated at handshake | V1 / V2 (V2 enabled by both sides) — see Phase 1.8 |
| Rekey trigger | `PhantomSession::rekey()` | Caller-driven (Phase 1.5). |
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
- [ ] If exposing `/metrics`, scrape rule added to Prometheus.
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
- **Memory.** Budget ~512 KiB per session (send/recv buffers + crypto state).
  The Kubernetes guide's `~1000 sessions → 512 MiB limit` line is exactly this:
  `PHANTOM_MAX_SESSIONS × 512 KiB` should fit the pod/host memory limit with
  headroom.

The per-IP cap is a *session-count* cap, not a handshake-rate limit — an
abusive IP can still trigger (cheap, PoW/cookie-gated) handshakes that are then
rejected. Pre-handshake per-IP rate limiting belongs at the edge (LB / nftables
`ct count` / a reverse proxy).

## Monitoring

Phase 4.5 exposes `phantom_*` Prometheus metrics. The starter
dashboard lives at `docs/operations/grafana/phantom-dashboard.json`
and the alert rules at `docs/operations/prometheus/alerts.yml`.

Key alerting signals:

| Signal | Reaction |
| --- | --- |
| `phantom_handshake_failures_total` rate spike | Investigate — could be misconfigured clients or active scan. |
| `phantom_replay_rejected_total` rate spike | Investigate — replay window saturated either by network reorder or by adversary. |
| `phantom_unencrypted_dropped_total` > 0 | Active downgrade attempt — page on-call. |
| `phantom_aead_decrypt_failed_total` rate spike | Tampering or corruption — page on-call. |
| `phantom_active_sessions` near process limit | Scale horizontally. |
| `phantom_handshake_latency_seconds_bucket{le="1"}` p95 > 1s | Investigate CPU / RNG / adaptive-PoW saturation. |

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
