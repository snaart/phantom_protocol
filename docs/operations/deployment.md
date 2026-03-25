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
| Kubernetes | _planned_ | Will land alongside the operator + helm chart in a follow-up. |
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
- [ ] sysctl tuning applied (see `systemd.md`).
- [ ] CI build of the wrapper binary completes for all target
      platforms.
- [ ] If exposing `/metrics`, scrape rule added to Prometheus.
- [ ] Graceful-shutdown signal handler wired in the wrapper (`SIGTERM`
      → `PhantomListener::shutdown()`).
- [ ] Logs ship to a durable backend (journald → vector → Loki, or
      docker JSON → fluent-bit → Elastic, etc.).

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
