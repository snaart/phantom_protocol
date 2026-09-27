# Phantom Protocol

[![crates.io](https://img.shields.io/crates/v/phantom-protocol.svg)](https://crates.io/crates/phantom-protocol)
[![docs.rs](https://img.shields.io/docsrs/phantom-protocol)](https://docs.rs/phantom-protocol)
[![CI](https://github.com/snaart/phantom_protocol/actions/workflows/ci.yml/badge.svg)](https://github.com/snaart/phantom_protocol/actions/workflows/ci.yml)
[![license](https://img.shields.io/crates/l/phantom-protocol.svg)](https://github.com/snaart/phantom_protocol/blob/main/LICENSE)
![MSRV](https://img.shields.io/badge/MSRV-1.93-blue)

Post-quantum-secure L4/L6 universal transport framework in Rust.

Phantom Protocol is an **SDK** — a foundation for building secure networked
products (VPN, messaging, …), not an end-user application. It gives applications
an authenticated, confidential, post-quantum-secure byte pipe, pairing a hybrid
classical-plus-PQ handshake (X25519 + ML-KEM-768 KEM, Ed25519 + ML-DSA-65
signatures — FIPS 203 / FIPS 204, pure Rust) with a transport layer: TCP /
WebSocket sessions and a native reliable-UDP transport (PhantomUDP), plus
WASI / embedded byte-stream framing. Cross-language bindings via UniFFI
(Python, Swift, Kotlin, C); native WASM target; bare-metal `EmbeddedLeg` for
no_std. (An optional TLS-over-TCP DPI-mimicry transport — `mimicry` feature —
makes a flow look like HTTPS to passive DPI; anti-DPI obfuscation only, detectable
by active probing — see [Status & limitations](#status--limitations).)

> **Pre-1.0 (`0.3.0`).** Wire format may break between minors; SemVer kicks in at
> 1.0. 0 workspace warnings, 0 `unsafe` outside two audited opt-ins, MSRV Rust
> 1.93, CI green across the full cross-target matrix. See
> [Status & limitations](#status--limitations).

## Install

Published on crates.io as [`phantom-protocol`](https://crates.io/crates/phantom-protocol)
(the import path is `phantom_protocol`):

```toml
[dependencies]
phantom-protocol = "0.3"
```

or `cargo add phantom-protocol`. API docs: <https://docs.rs/phantom-protocol>.

## Getting started

**Loopback demo (30 seconds):**

```bash
cargo run --manifest-path core/Cargo.toml --example loopback_demo
```

**Server + CLI ping (2 minutes):**

```bash
# Generate a persistent server identity
cargo run --manifest-path cli/Cargo.toml -- keygen --out ./server.key
# Start the reference server
cargo run --manifest-path server/Cargo.toml -- --bind 0.0.0.0:4242 --signing-key-file ./server.key
# In another terminal: get the public key and ping
cargo run --manifest-path cli/Cargo.toml -- pubkey --in ./server.key
cargo run --manifest-path cli/Cargo.toml -- ping --host 127.0.0.1 --port 4242 \
    --pinned-key-hex <hex-from-pubkey> --msg hello
```

**Language bindings (15 minutes):** see
[`tests/bindings/PACKAGING.md`](https://github.com/snaart/phantom_protocol/blob/main/tests/bindings/PACKAGING.md) for Swift, Kotlin,
Python, and C packaging workflows.

### Choosing a transport

| Transport | Entry points | `migrate()`? | Firewall-friendly? | Use it for |
|---|---|---|---|---|
| PhantomUDP | `connect_pinned_udp` / `PhantomUdpListener::bind_udp` | Yes | Mostly | **the default** — the production transport |
| TCP | `connect_pinned` / `PhantomListener::bind` | No — returns `Err(Unsupported)`; reconnect with 0-RTT | Yes | reach, where UDP is blocked — **not** speed |
| WebSocket | `WebSocketLeg` (wasm32 only) | No | Yes (port 443) | browsers |
| Embedded | `EmbeddedLeg` | No | N/A | UART / USB links |

**If you can use PhantomUDP, use it.** The byte-pipe legs exist for reach — a
network that blocks or throttles UDP, a proxy, a browser sandbox — and Phantom
over TCP in particular pays for that reach with latency. Its reliability layer
(ARQ, SACK loss detection, congestion control) is the same one PhantomUDP uses
and runs unchanged, which over a socket that already retransmits and already has
a congestion window means two control loops stacked on each other, communicating
only through the queue between them. Measured consequence, from the WAN harness
in [`testbed/`](https://github.com/snaart/phantom_protocol/tree/main/testbed):
min-RTT on the TCP leg has been observed as high as **4112 ms** — that is queueing
under our own sender, not a property of the route — and its throughput has moved
with the route from run to run, so the figure to quote is one with a control
from its own run: in run `20260822-062705` the server received 4.83 Mbit/s over
this leg while raw UDP echo on the same path in the same run measured
13.26 Mbit/s round-trip. How the harness counts, and which control each figure
is read against, is in
[`testbed/README.md`](https://github.com/snaart/phantom_protocol/blob/main/testbed/README.md).

This is what the leg is, not a defect being worked on: the inner wire, the
pinning, the AEAD and the replay window are identical on every transport, and TCP
is fully conformant. It simply has no way to be quick under load, and no way to
migrate.

### Two ways to send data

**`session.send()` / `session.recv()`** operate on a single implicit stream
(simplest). **`session.open_stream()` / `session.accept_stream()`** give you
independent multiplexed streams with per-stream flow control.

## Highlights

- **Hybrid post-quantum handshake** — X25519 + ML-KEM-768 KEM, Ed25519 + ML-DSA-65
  signatures. Both halves must verify. Pure-Rust RustCrypto primitives — no C
  bindings in the crypto path, so the full handshake compiles on native, mobile,
  and `wasm32`. (Bare-metal `thumbv7em` is `std`-gated to the framing transport
  only — see [Status & limitations](#status--limitations).)
- **0-RTT resumption** — AEAD-sealed early-data (≤ 16 KiB) folded into the
  single `ClientHello`, one-shot anti-replay via a consumed `SessionCache`
  ticket, best-effort fallback to a 1-RTT handshake when the ticket is
  unknown / expired or the blob fails to open.
- **Mid-session rekey** — HKDF ratchet, `REKEY` flag + per-packet `epoch`.
- **Transports** — `PhantomSession` runs an authenticated session over **TCP**,
  **WebSocket**, and a native **reliable-UDP transport (PhantomUDP)**:
  connection-ID demux, SACK loss recovery + RFC-9002 fast-retransmit, a BBR-style
  congestion controller, and **seamless connection migration** (one live path at
  a time — Wi-Fi↔cellular without a re-handshake), all with no extra crypto layer.
  WASI and Embedded ride as framing legs. An optional **`mimicry`** feature
  (a TLS-over-TCP `MimicTlsLeg` — `connect_pinned_mimic` / `bind_mimic`) makes a
  flow look like HTTPS to passive DPI + JA3/JA4 fingerprinting; it is
  **anti-DPI obfuscation only and is detectable by active probing**
  (see [Status & limitations](#status--limitations)). Bandwidth *aggregation*
  across transports is deliberately not pursued. The UDP data plane has been
  measured on a real WAN route against a QUIC reference and raw no-protocol
  controls (see [Performance](#performance)) — over one route, and with no
  external audit.
- **Multi-stream** — strict-priority scheduler, `WINDOW_UPDATE` per-stream
  flow control, BBRv2-inspired pacing (Startup / Drain / ProbeBW / ProbeRTT).
  Loss is not a state: it is answered by an `inflight_hi` volume bound, from
  which Startup is exempt.
- **DoS-resistant handshake** — stateless HMAC-SHA-256 cookie (per-process
  master → hourly-rotated derived secret, 5-minute validity buckets) + adaptive
  blake3 proof-of-work (load-tiered difficulty 0–16).
- **Per-direction replay protection** — RFC 4303 §3.4.3 sliding-window bitmap,
  default 1024 bits, checked _after_ AEAD verify.
- **Observability** — OpenTelemetry metrics + traces (opt-in
  `telemetry-otel` feature). Lock-free hot-path atomics (≤ 2.5 ns / call),
  OTLP/gRPC push to any backend (Datadog, Honeycomb, Grafana Cloud,
  self-hosted via OTel Collector). Pre-built Grafana dashboard + Prometheus
  alert rules in `docs/observability/`.
- **Signed build provenance** — every release artifact carries a sigstore-backed
  in-toto attestation naming the workflow, commit and runner that produced it
  (SLSA v1.0 Build **L2**; verify with `gh attestation verify`).
- **Cross-platform** — every CI target is a hard gate (Linux x4, macOS x2,
  iOS x2, Windows x2, wasm32-unknown-unknown, wasm32-wasip2,
  thumbv7em-none-eabihf); **no `allow_failure` rows**.

## Quick start

### Build / test / lint

```bash
cargo build   --manifest-path core/Cargo.toml
cargo test    --manifest-path core/Cargo.toml --lib
cargo clippy  --manifest-path core/Cargo.toml --lib -- -D warnings
cargo fmt     --manifest-path core/Cargo.toml --check
```

Loopback integration tests are `#[ignore]`-gated:

```bash
cargo test --manifest-path core/Cargo.toml --test tcp_integration -- --ignored
```

More commands (benches, fuzz, miri, cross-targets, embedded) live in the CI
workflow files under [`.github/workflows/`](https://github.com/snaart/phantom_protocol/tree/main/.github/workflows/); the PR
checklist is in [CONTRIBUTING.md](https://github.com/snaart/phantom_protocol/blob/main/CONTRIBUTING.md).

### Minimal client / server (UDP — production path)

Server identity must be pinned — `connect_with_transport` requires a
`HybridVerifyingKey`; there is no skip path (Security Invariant 1).
PhantomUDP is the recommended transport: it supports seamless `migrate()`.

```rust,no_run
use std::sync::Arc;
use phantom_protocol::api::{PhantomUdpListener, PhantomSession};

#[tokio::main]
async fn main() -> Result<(), phantom_protocol::CoreError> {
    // ── Server ────────────────────────────────────────────────────────────────
    let listener = PhantomUdpListener::builder("127.0.0.1:0").bind().await?;
    let server_addr = listener.local_addr();                // e.g. "127.0.0.1:54321"
    let pinned_key  = listener.verifying_key_bytes();       // share out-of-band

    let listener = Arc::clone(&listener);
    tokio::spawn(async move {
        let outcome = listener.accept().await?;
        let session = outcome.session();
        let _req = session.recv().await?;
        session.send(b"hello, post-quantum world".to_vec()).await?;
        Ok::<_, phantom_protocol::CoreError>(())
    });

    // ── Client ────────────────────────────────────────────────────────────────
    let port: u16 = server_addr.parse::<std::net::SocketAddr>().unwrap().port();
    let session = phantom_protocol::connect_pinned_udp(
        "127.0.0.1".into(), port, pinned_key,
    ).await?;
    session.await_ready().await?;
    session.send(b"ping".to_vec()).await?;
    let _reply = session.recv().await?;
    Ok(())
}
```

### Minimal client / server (TCP — simpler, no `migrate()`)

```rust,no_run
use std::sync::Arc;
use phantom_protocol::api::{PhantomListener, PhantomSession, TcpSessionTransport};
use phantom_protocol::crypto::hybrid_sign::HybridVerifyingKey;

#[tokio::main]
async fn main() -> Result<(), phantom_protocol::CoreError> {
    let listener = PhantomListener::builder("127.0.0.1:0").bind().await?;
    let server_addr = listener.local_addr();
    let pinned_key  = listener.verifying_key_bytes();

    let listener = Arc::clone(&listener);
    tokio::spawn(async move {
        let outcome = listener.accept().await?;
        let session = outcome.session();
        let _req = session.recv().await?;
        session.send(b"hello, post-quantum world".to_vec()).await?;
        Ok::<_, phantom_protocol::CoreError>(())
    });

    let session = phantom_protocol::connect_pinned(
        "127.0.0.1".into(),
        server_addr.parse::<std::net::SocketAddr>().unwrap().port(),
        pinned_key,
    ).await?;
    // Same rule as the UDP form above: `connect_pinned` returns before the
    // handshake has run, so this is where the pinned-key check surfaces. Without
    // it a wrong key looks like a successful connect.
    session.await_ready().await?;
    session.send(b"ping".to_vec()).await?;
    let _reply = session.recv().await?;
    Ok(())
}
```

Runnable forms: [`core/examples/loopback_demo.rs`](https://github.com/snaart/phantom_protocol/blob/main/core/examples/loopback_demo.rs),
[`core/examples/embedded_demo.rs`](https://github.com/snaart/phantom_protocol/blob/main/core/examples/embedded_demo.rs),
[`core/examples/crypto_bench.rs`](https://github.com/snaart/phantom_protocol/blob/main/core/examples/crypto_bench.rs).

## Cryptography

| Role | Primitive | Standard / source |
| --- | --- | --- |
| KEM | X25519 + ML-KEM-768 | RFC 7748 + FIPS 203 (RustCrypto `ml-kem`) |
| Signatures | Ed25519 + ML-DSA-65 | FIPS 186-5 + FIPS 204 (RustCrypto `ml-dsa`) |
| AEAD (primary) | AES-256-GCM | `ring`, HW-accelerated (AES-NI / ARMv8 PMULL) |
| AEAD (fallback) | ChaCha20-Poly1305 | RFC 8439, auto-selected without AES intrinsics |
| KDF | HKDF-SHA-256 + keyed BLAKE3 | RFC 5869 for the KEM combine / rekey / 0-RTT keying; `crypto::kdf::derive_key_32` label derivations use `blake3::derive_key`, swapping to HKDF-SHA-256 under `--features fips` |
| Hash / MAC | SHA-256, HMAC-SHA-256, blake3 (keyed) | FIPS 180-4 / FIPS 198-1 + non-FIPS |

The PQ primitives moved off the C-bound `pqcrypto-*` crates to the
RustCrypto FIPS-203 / FIPS-204 implementations. The crate compiles on
`wasm32-unknown-unknown` and `thumbv7em-none-eabihf` without C bindings.

## Architecture

```text
┌─────────────────────────────────────────────────────────────────┐
│  Public API   (core/src/api/)                                   │
│  PhantomSession · PhantomListener · TcpSessionTransport         │
├─────────────────────────────────────────────────────────────────┤
│  Transport    (core/src/transport/)                             │
│  Handshake{Client,Server} · Session · scheduler · pacer · paths │
│  api/{tcp,udp}_transport · legs/{websocket, wasi, embedded}     │
├─────────────────────────────────────────────────────────────────┤
│  Crypto       (core/src/crypto/)                                │
│  hybrid_kem · hybrid_sign · adaptive_crypto · kdf · pow · rng   │
├─────────────────────────────────────────────────────────────────┤
│  Security     (core/src/security/)                              │
│  ReplayWindow                                                   │
├─────────────────────────────────────────────────────────────────┤
│  Runtime      (core/src/runtime/)                               │
│  TokioRuntime (native) · WasmRuntime · EmbeddedRuntime (scaffold) · WasiRuntime │
└─────────────────────────────────────────────────────────────────┘
```

The formal architecture spec is
[`docs/architecture/ARCHITECTURE.md`](https://github.com/snaart/phantom_protocol/blob/main/docs/architecture/ARCHITECTURE.md);
the unified wire protocol (incl. 0-RTT) is
[`docs/protocol/PROTOCOL.md`](https://github.com/snaart/phantom_protocol/blob/main/docs/protocol/PROTOCOL.md). The eleven
numbered security invariants cited throughout the code are listed in
[`docs/security/invariants.md`](https://github.com/snaart/phantom_protocol/blob/main/docs/security/invariants.md),
and the threat model is
[`docs/security/threat-model.md`](https://github.com/snaart/phantom_protocol/blob/main/docs/security/threat-model.md).

## Transport features

- **Single unified wire protocol.** One `PacketHeader` (15 bytes on the wire,
  fully header-protected — the variable header fields and the leading `version`
  byte are HP-masked; the AEAD AAD image is 47 bytes) wrapped in a bare
  `PhantomPacket` (`header` + `payload` + TLV-headroom `extensions`) — no
  `VersionedPacket` enum, no per-session wire-version negotiation. `epoch`,
  `REKEY`, `PATH_VALIDATION`, `COALESCED`, `WINDOW_UPDATE` flags live in the one
  header; the recv path deserializes `PhantomPacket` directly and drops any frame
  whose `header.version` differs. Handshake messages are borsh structs: one
  `ClientHello` (with the optional 0-RTT `early_data` blob folded in) and three
  server replies — `ServerHello`, `HelloRetryRequest`, `ServerReject` — carried
  under a one-byte-discriminant `ServerReply` wrapper; one signed
  `HandshakeTranscript` leads with `protocol_variant`. The pinned bytes are
  `WIRE_VERSION` = <!--pinned:WIRE_VERSION-->8 and
  `PROTOCOL_VERSION` = <!--pinned:PROTOCOL_VERSION-->5; both are tamper-check
  anchors and a hook for a future deliberate bump.
- **Path validation (wired into the live UDP data plane).** `PathRegistry` +
  constant-time challenge/response; path 0 pre-validated, secondary paths
  transition `Unvalidated → Validating → Validated`. It backs the PhantomUDP
  data plane end-to-end — the PATH-001 send-gate + recv-relax, seamless
  connection migration (one live path at a time), and passive-NAT-rebind
  recovery. Only bandwidth *aggregation* / simultaneous multipath is unbuilt
  (rejected for this workload — see [Status & limitations](#status--limitations)).

## Performance

Two kinds of number live here and neither substitutes for the other. The first
set is **loopback and in-process**: it measures the cryptography and the packet
codec on one machine, and says nothing about how the transport behaves on a
path. The second set is from a **real route**, and every figure there is printed
beside the raw no-protocol control measured in the same run: on that route the
one-way downward ceiling moved by a factor of three between two campaigns five
days apart, and the upward one by about a third within a single day, so a
throughput number without its own control is not a result.

### Cryptography and codec — loopback, single host

Reference numbers on **Apple M1 Pro (8P + 2E, 16 GiB), macOS 26.0, rustc 1.93.0,
`ring` with ARMv8 AES-PMULL** (snapshot 2026-05-17, criterion `--quick`, default
`target-cpu`). The snapshot predates the current wire — it was captured under
`WIRE_VERSION = 2`, whereas the shipped format is
`WIRE_VERSION` = <!--pinned:WIRE_VERSION-->8 — so the crypto / throughput shape
is representative but re-capture before quoting these as live figures (see
[`BENCHMARKS.md`](https://github.com/snaart/phantom_protocol/blob/main/BENCHMARKS.md)):

| Path | Number | Notes |
| --- | --- | --- |
| Hybrid PQ handshake (pinned) | **1.06 ms** / ~945 conn/s/core | full production path; ~7,500 cold handshakes/s aggregate on 8P cores |
| AEAD encrypt, 64 KiB | **4.67 GiB/s/core** (13.1 µs) | `encrypt_packet` with header-AAD + replay window |
| AEAD decrypt, 16 KiB | **4.68 GiB/s/core** | same path |
| 1 MiB round-trip | **391.5 µs** → **5.0 GiB/s** | encrypt + decrypt |
| Raw AES-256-GCM (`ring`) | **5,514 MiB/s** at 64 KiB | bare cipher, no framing |
| ChaCha20-Poly1305 (software) | 1,555 MiB/s at 1 MiB | ~3.5× slower than AES on this part |
| ClientHello parse + cookie + reputation | **4.60 µs** / ~217K/s/core | DoS gate hot path |
| `kem_encapsulate` | 80.7 µs | hybrid X25519 + ML-KEM-768 |
| `hybrid_sign` / `hybrid_verify` | 310.0 µs / 131.6 µs | Ed25519 + ML-DSA-65 |

`RUSTFLAGS="-C target-cpu=native"` typically adds +5–10%; PGO via `cargo-pgo`
adds another +5–10% on stable workloads. The release profile (`opt-level=3`,
`lto="fat"`, `codegen-units=1`, `panic="abort"`) is set at the workspace root.
Linux x86_64 with AES-NI lands in similar ballparks. Full methodology and
production tuning (`bbr`, `fq`, `LimitNOFILE`, allocator swap, CPU pinning) in
[`BENCHMARKS.md`](https://github.com/snaart/phantom_protocol/blob/main/BENCHMARKS.md) and [`docs/operations/perf-tuning.md`](https://github.com/snaart/phantom_protocol/blob/main/docs/operations/perf-tuning.md).

### On a real route — WAN campaigns

Measured by [`testbed/`](https://github.com/snaart/phantom_protocol/tree/main/testbed/): a probe on a
workstation drives a scenario matrix against a daemon on a remote host. The
daemon binds the three Phantom legs, a **quinn QUIC reference** leg — a mature
implementation of the same class of protocol, on the same path, in the same run
— and **raw UDP controls that carry no protocol at all**: an echo, and a one-way
capacity ladder in each direction. The raw control is the denominator; the
reference is a second opinion, not a ranking. (A raw TCP echo runs as well, but a
TCP socket brings its own congestion control, so it is a second reference rather
than a control.)

Every rate is counted by the end that received it: the server on an upload, the
client on a download. A sending side's own count would be measuring how fast
`send()` filled a buffer. Every run in the tables below had both ends built from
one commit, verified from the run manifest.

**2026-09-05 — two campaigns on the same day, six hours apart, three runs each:
the last full campaigns before this release.** Uploads ran for 60 s and
downloads for 180 s, and every PhantomUDP transfer converged rather than ending
mid-ramp.

| Upload | Phantom UDP | quinn (reference) | One-way upward control, same run |
| --- | --- | --- | --- |
| `20260905-032309` | **28.11 Mbit/s** | not run | 84.97 |
| `20260905-033508` | **27.02** | not run | 84.26 |
| `20260905-034708` | **28.33** | not run | 84.49 |
| `20260905-103139` | **26.03** | 28.03 | 58.64 |
| `20260905-105207` | **27.10** | 65.85 | 59.29 |
| `20260905-111225` | **23.71** | 31.54 | 55.56 |

| Download | Phantom UDP | quinn (reference) | One-way downward control, same run |
| --- | --- | --- | --- |
| `20260905-032309` | **16.30 Mbit/s** | not run | 76.51 |
| `20260905-033508` | **16.38** | not run | 76.64 |
| `20260905-034708` | **16.45** | not run | 76.77 |
| `20260905-103139` | **11.46** | 0.33 | 76.53 |
| `20260905-105207` | **12.07** | 0.49 | 76.47 |
| `20260905-111225` | **11.13** | 0.36 | 76.51 |

Read these before reusing any of them:

- **The two campaigns ran the same library.** Between their two builds `core/src`
  differs by one compile-time assertion and one test, so what differs between the
  morning rows and the afternoon rows is the route.
- **The upward control fell by about a third within the day** — 84.26–84.97
  Mbit/s in the morning, 55.56–59.29 in the afternoon — and in `105207` quinn
  delivered 111% of that run's control, which says the ladder under-read the
  path rather than that quinn beat it. A share of the upward link is therefore
  not yet a reliable figure. The morning's 32–34% is quotable against its own
  control; the afternoon's is not.
- **Upload against quinn: 1.1–2.4× in quinn's favour, and the reference is the
  noisier of the two.** Across three consecutive runs it moved 2.3×, while this
  leg moved 1.14×.
- **Download against quinn goes the other way, and the route explains it.** The
  downward control held its 76.5 Mbit/s ceiling in both campaigns, but in the
  afternoon it lost 1.0–7.3% of datagrams at 1 Mbit/s and 2.0–9.9% at 5 Mbit/s,
  far below that ceiling, where in the morning it lost at most 0.4% on the same
  rungs. quinn ships a loss-based controller (Cubic), which reads each of those
  losses as congestion, and its 0.33–0.49 Mbit/s is within what the Mathis et
  al. formula predicts for such a controller at that loss and a round trip of
  about 200 ms. This transport paces to a measured delivery rate instead, and
  held 11.13–12.07 Mbit/s. That is a statement about the route, not a ranking.
- **Duplex** — the download half of a transfer running both ways at once,
  against the one-way download of the same run: 81–89% in the morning, 49–63% in
  the afternoon.
- **The released 0.3.0 is not the build measured here.** One congestion-control
  change landed after these campaigns — the loss-driven volume bound no longer
  applies during Startup — and it has so far been measured only in the in-tree
  bottleneck model (see [`CHANGELOG.md`](https://github.com/snaart/phantom_protocol/blob/main/CHANGELOG.md)),
  not on this route.

**2026-08-17 and 2026-08-22.** Upload only, and against a round-trip echo,
because no one-way upward control was taken in these runs:

| Run | Phantom UDP | quinn (reference) | Raw UDP echo, same run |
| --- | --- | --- | --- |
| 2026-08-17 `124710` | **16.51 Mbit/s** | 5.81 | 33.52 round-trip |
| 2026-08-17 `130955` | **18.96** | 40.52 | 31.61 round-trip |
| 2026-08-22 `061422` | **1.96** | 9.13 | 12.17 round-trip |
| 2026-08-22 `062705` | did not establish — `Timeout` on `connect` | 9.38 | 13.26 round-trip |

- **Rows from different campaigns are not comparable.** The route on 2026-08-22
  was materially worse than on 2026-08-17: the same raw UDP echo control read
  12.17 / 13.26 Mbit/s against 33.52 / 31.61, and the one-way downward ceiling
  read 21.09 / 20.90 against 60.45 / 62.97. Within one campaign the control holds
  steady and the rows can be read against each other.
- **The reference moved sevenfold between two adjacent runs** on the same route
  (5.81, then 40.52). A single comparison against quinn is not a ranking, in
  either direction.
- **August downloads are not quoted.** In the two 2026-08-17 runs above,
  PhantomUDP's download was still accelerating when its window closed, so its
  3.57 / 4.84 Mbit/s measured a ramp rather than a capacity, against a one-way
  downward control of 60.45 / 62.97; the byte-pipe legs and the reference read
  0.55–0.95.
- **The `Timeout` in run `062705` was a lost `ServerHello`, and 0.3.0 fixes it.**
  The server received the hello, completed the handshake and sent its reply — a
  six-datagram flight with no retransmission of its own — and the reply was lost
  on the way down. The client repeated its hello three times, and each repeat was
  routed into the session the server had already committed, which does not parse
  handshake messages, so one lost datagram out of six cost the whole connect at
  the end of the client's 8-second budget. A PhantomUDP listener now retains the
  reply flight and repeats it byte for byte when the same hello arrives again
  ([`docs/protocol/PROTOCOL.md`](https://github.com/snaart/phantom_protocol/blob/main/docs/protocol/PROTOCOL.md)
  § 6.1). Isolated PhantomUDP connect timeouts appear in earlier runs too — one
  handshake in ten in each 2026-08-17 run — but those runs did not record what
  would confirm their cause.
- **Handshake: a median of 416.0–589.1 ms per run against 254.5–304.4 ms for
  quinn**, in the four runs above. The difference is about one round trip, and
  it is a design choice rather than a defect: a PhantomUDP listener always
  answers a first hello with a stateless cookie before it commits any state, so
  the handshake takes two round trips where QUIC's takes one. The hybrid
  post-quantum cryptography itself costs about a millisecond (see the loopback
  table above).

An earlier campaign (2026-08-03, five runs) put upload at 2.40–3.59 Mbit/s,
counted by the server, in the four runs whose upload connected, against a
round-trip echo of 27.75–42.85 Mbit/s from the same runs. Cumulative
`WINDOW_UPDATE` (the `WIRE_VERSION` 6 → 7 bump), a segment-idempotent
flow-control charge, and symmetric reliable-byte accounting on both ends of the
ledger landed between that campaign and 2026-08-17. The campaigns are not
comparable, so no ratio between them is claimed.

Two results from the 2026-08-22 campaign are not about speed at all, and are the
firmer part of it:

- **A departed UDP client no longer holds a server session open.** Median
  server-side UDP session lifetime fell from **135.55 s to 2.19 s**, and the
  share of sessions living past 100 s from **32.5% to 2.3%** (986 sessions
  before the change, 256 after, across all legs).
- **The bandwidth estimator's overshoot is mostly filter memory, not bad
  samples.** On a download session of that campaign the filtered ten-second
  maximum ran at a median **1.52×** of what was actually delivered over the same
  interval, while the **raw single sample ran at 1.02×** — one session per run,
  because both quantities are only recorded where the server was the sender.

The harness, its scenarios, and how each figure above is computed — which end
counts, which control is the denominator, when a transfer counts as converged —
are documented in
[`testbed/README.md`](https://github.com/snaart/phantom_protocol/blob/main/testbed/README.md).
The rule this section follows is that a throughput figure never appears without
the raw control from its own run.

## Deploying

### `phantom-server` (reference binary)

Production embedder. Auto-loads-or-creates a persistent `HybridSigningKey`,
pushes OTLP telemetry to an OTel Collector / SaaS backend, handles SIGTERM
/ SIGINT with a 10s drain.

**It binds the TCP leg only.** `phantom-server` listens with
`PhantomListener::bind_with_signing_key` on `--bind` and opens no UDP socket, so
it does not serve PhantomUDP — the transport recommended above — and the
Dockerfile, compose file and Helm chart below expose and probe TCP 4242
accordingly. A PhantomUDP deployment embeds `PhantomUdpListener` in its own
server binary; `PhantomUdpListener::bind_udp_with_signing_key_bytes` accepts the
same 64-byte seed that `phantom-cli keygen` and `phantom-server` write, so one
pinned identity can serve both transports.

| Flag | Env | Default |
| --- | --- | --- |
| `--bind` | `PHANTOM_BIND` | `0.0.0.0:4242` |
| `--otlp-endpoint` | `OTEL_EXPORTER_OTLP_ENDPOINT` | `http://localhost:4317` |
| `--otel-service-name` | `OTEL_SERVICE_NAME` | `phantom-server` |
| `--otel-trace-sample-ratio` | `OTEL_TRACES_SAMPLER_ARG` | `1.0` (root-span head sampling; `0` = no traces) |
| `--signing-key-file` | `PHANTOM_SIGNING_KEY_FILE` | `/etc/phantom-server/signing.key` (0600, auto-created) |
| `--log-json` | `PHANTOM_LOG_JSON` | `false` |
| `--log-filter` | `RUST_LOG` | `info,phantom_protocol=debug` |
| `--max-sessions` | `PHANTOM_MAX_SESSIONS` | `1024` (`0` = unbounded) |
| `--max-sessions-per-ip` | `PHANTOM_MAX_SESSIONS_PER_IP` | `64` (`0` = off) |

```bash
cargo run --manifest-path server/Cargo.toml -- \
    --bind 0.0.0.0:4242 \
    --otlp-endpoint http://otel-collector:4317
```

### Docker / docker-compose

Multi-stage `Dockerfile` (`rust:1-slim-bookworm` → `debian:bookworm-slim`),
non-root `phantom` UID 65532, EXPOSE 4242 (no inbound metrics port — telemetry
is OTLP push), signing-key volume at
`/etc/phantom-server`. `docker-compose.yml` is ready to run with a named volume
and TCP healthcheck.

```bash
docker build -t phantom-server:0.3.0 .
docker compose up -d
```

### Kubernetes / Helm

Production-shape chart at
[`docs/operations/helm/phantom-protocol/`](https://github.com/snaart/phantom_protocol/tree/main/docs/operations/helm/phantom-protocol/).
`appVersion: 0.3.0`, ClusterIP service on `4242`, 3 replicas,
`tcpSocket` liveness / readiness. Raw manifests + walkthrough in
[`docs/operations/kubernetes.md`](https://github.com/snaart/phantom_protocol/blob/main/docs/operations/kubernetes.md).

### systemd

Hardened unit text in [`docs/operations/systemd.md`](https://github.com/snaart/phantom_protocol/blob/main/docs/operations/systemd.md)
(`NoNewPrivileges`, `ProtectSystem=strict`, `MemoryDenyWriteExecute`,
`SystemCallFilter`, 30s `TimeoutStopSec`) plus a multi-instance template using
`SO_REUSEPORT`.

### Observability

OpenTelemetry metrics + traces over OTLP/gRPC (replacing an earlier
hand-rolled Prometheus endpoint). The reference server pushes to
`OTEL_EXPORTER_OTLP_ENDPOINT`; backends supported include OTel Collector
(→ Prometheus / Tempo / Loki), Datadog, Honeycomb, Grafana Cloud, AWS
CloudWatch — anything OTLP-compatible. Pre-built Grafana dashboard at
[`docs/observability/grafana/phantom-otel-dashboard.json`](https://github.com/snaart/phantom_protocol/blob/main/docs/observability/grafana/phantom-otel-dashboard.json)
and Prometheus alert rules at
[`docs/observability/prometheus/alerts.yml`](https://github.com/snaart/phantom_protocol/blob/main/docs/observability/prometheus/alerts.yml).
End-to-end docker-compose demo in
[`examples/observability-demo/`](https://github.com/snaart/phantom_protocol/tree/main/examples/observability-demo/). Full setup
recipes in [`docs/observability/otlp-setup.md`](https://github.com/snaart/phantom_protocol/blob/main/docs/observability/otlp-setup.md).

### CLI

`phantom-cli` (sibling crate, edition 2024):

```bash
cargo run --manifest-path cli/Cargo.toml -- keygen --out ./server.key
cargo run --manifest-path cli/Cargo.toml -- pubkey --in  ./server.key
cargo run --manifest-path cli/Cargo.toml -- ping --host 127.0.0.1 --port 4242 \
    --pinned-key-hex <hex-from-keygen> --msg hello
cargo run --manifest-path cli/Cargo.toml -- version
```

## Platforms & language bindings

### Cross-compile matrix (`.github/workflows/cross.yml`)

| Target | Status |
| --- | --- |
| `x86_64-unknown-linux-gnu` / `aarch64-unknown-linux-gnu` / `aarch64-unknown-linux-musl` | hard gate |
| `x86_64-apple-darwin` / `aarch64-apple-darwin` | hard gate |
| `aarch64-apple-ios` (device) / `aarch64-apple-ios-sim` | hard gate |
| `x86_64-pc-windows-msvc` / `aarch64-pc-windows-msvc` | hard gate |
| `wasm32-unknown-unknown` | hard gate |
| `thumbv7em-none-eabihf` | hard gate (`--no-default-features --features embedded,no-std`) |
| `wasm32-wasip2` | hard gate (compile + host round-trip; WASI is client-side framing-only — see [`docs/operations/wasi.md`](https://github.com/snaart/phantom_protocol/blob/main/docs/operations/wasi.md)) |

### Language bindings (`tests/bindings/`)

| Binding | Maturity | Notes |
| --- | --- | --- |
| **Swift** | Production-shape | Auto-gen via UniFFI 0.32; iOS XCFramework recipe in [`docs/operations/mobile.md`](https://github.com/snaart/phantom_protocol/blob/main/docs/operations/mobile.md) |
| **Kotlin** | Production-shape | Auto-gen; Android NDK + Gradle `jniLibs` recipe in `mobile.md` |
| **Python** | UniFFI surface auto-gen | Demo harness `tests/run_test.py` |
| **C** | Experimental | **Hand-curated** header — UniFFI 0.32 has no C generator. Covers `connect_pinned` / `connect_pinned_udp` (incl. `_with_config` / `_with_resumption`), the `bind*_with_signing_key_bytes` / `bind*_with_config_bytes` constructors, `generate_signing_key`, and `PhantomConfig`; the typed `HybridSigningKey` / `HybridVerifyingKey` objects and runtime injection stay Rust-only. README recommends Swift / Kotlin / Python instead |
| **WASM (browser)** | Demo shipped | [`examples/wasm-demo/`](https://github.com/snaart/phantom_protocol/tree/main/examples/wasm-demo/) pairs with [`docs/operations/wasm.md`](https://github.com/snaart/phantom_protocol/blob/main/docs/operations/wasm.md); uses `WebSocketLeg` + `WasmRuntime` |

Regen: `tests/bindings/{generate_python,generate_swift,generate_kotlin,generate_c}.sh`.

### Embedded (`embedded` feature, default off)

On bare-metal `thumbv7em-none-eabihf` Phantom Protocol ships the **framing transport
only** — `EmbeddedLeg` and its length-prefix codec. The PQ handshake,
`PhantomSession`, the crypto primitives, and `TokioRuntime` are `std`-gated and
**not** built there; a bare-metal embedder brings its own crypto/handshake driver
and runs it over the leg. PQ-on-bare-metal is descoped for 1.0 (see
[Status & limitations](#status--limitations)).

`EmbeddedLeg<R, W, const N: usize>` wraps any `embedded-io-async = 0.7` byte
stream (UART, USB-CDC, …) with 4-byte BE length-prefix framing — the same wire
shape as `TcpSessionTransport`. Pure-Rust, no_std + alloc, target-arch-agnostic
(builds on host x86_64 for unit tests _and_ on bare-metal `thumbv7em-none-eabihf`).
Per-`(R, W)` `SessionTransport` impl via the `impl_embedded_session_transport!`
macro. `RngProvider` trait injects a hardware RNG when `getrandom` isn't
available. [`core/examples/embedded_demo.rs`](https://github.com/snaart/phantom_protocol/blob/main/core/examples/embedded_demo.rs) runs
the full session over a mock byte stream **on a host** (std), demonstrating the
leg — not a bare-metal handshake.

## Security

Full threat model, mitigations, and disclosure policy are in
[`SECURITY.md`](https://github.com/snaart/phantom_protocol/blob/main/SECURITY.md) and
[`docs/security/threat-model.md`](https://github.com/snaart/phantom_protocol/blob/main/docs/security/threat-model.md). Headline points:

- **Mandatory server identity pinning** — `connect_with_transport` requires a
  `HybridVerifyingKey`; no skip path.
- **Forward secrecy** — ephemeral hybrid KEM per handshake + HKDF-based
  mid-session rekey (epoch saturates at `u8::MAX`, never wraps).
- **Replay rejection happens _after_ AEAD verify** — RFC 4303 §3.4.3
  sliding-window bitmap, per-direction.
- **Downgrade resistance** — the pinned protocol version and `protocol_variant`
  are signed under the handshake transcript; stripped-`ENCRYPTED` post-handshake
  packets are dropped.
- **0-RTT anti-replay** — the server `peek()`s the ticket, verifies the
  `ClientHello.resumption_binder` in constant time (proof-of-possession), then
  eagerly `remove()`s it, so a ticket is strictly one-shot (and is re-inserted
  unchanged if the handshake later fails); oversized / expired / AEAD-failing
  early-data is best-effort and never fatal to the handshake.
- **AEAD nonce-exhaustion guard** — `CryptoError::NonceExhausted` at
  `AEAD_MAX_INVOCATIONS = 2^48`.
- **`ZeroizeOnDrop` on all key-bearing structs**; `#![deny(unsafe_code)]`
  crate-wide with two audited opt-ins (`transport/legs/websocket.rs`
  wasm-bindgen glue, `transport/legs/wasi.rs` WIT-bindgen `Send`/`Sync`) — both
  cross-language-boundary glue, so a native build compiles no `unsafe` at all.
- Cancel-safety audit: zero bugs found across all `tokio::select!` sites.
- Documented production panic sites with `PANIC-SAFETY:` invariants — see
  [`docs/security/panic-sites.md`](https://github.com/snaart/phantom_protocol/blob/main/docs/security/panic-sites.md).

### FIPS 140-3 / Common Criteria — exploratory only, NOT validated

> **No FIPS validation and no Common Criteria evaluation exist, and none is in
> progress.** The files under [`docs/compliance/`](https://github.com/snaart/phantom_protocol/tree/main/docs/compliance/) are
> self-authored *readiness/gap analyses*, not certifications — do not rely on
> them for any compliance claim.

- **FIPS 140-3:** the crypto uses several FIPS-approved primitives (ML-KEM-768,
  ML-DSA-65, Ed25519, SHA-256, HMAC/HKDF-SHA-256), and an optional `fips` Cargo
  feature swaps the remaining non-approved primitives toward an `aws-lc-rs`
  substrate. This is *not* a validated cryptographic module (no CMVP). Gap
  analysis: [`docs/compliance/fips-readiness.md`](https://github.com/snaart/phantom_protocol/blob/main/docs/compliance/fips-readiness.md);
  CAVP-style known-answer vectors in [`core/tests/cavp.rs`](https://github.com/snaart/phantom_protocol/blob/main/core/tests/cavp.rs).
- **Common Criteria:** an internal SFR gap-mapping exercise against NIAP
  PP-Module VPN Client exists for design reference only
  ([`docs/compliance/cc-pp-mapping.md`](https://github.com/snaart/phantom_protocol/blob/main/docs/compliance/cc-pp-mapping.md)). No
  lab evaluation is planned.

### Disclosure

Report privately, **not** via public issues. Embargo SLA 90 days; ack within
5 business days, triage within 14. Contact in [`SECURITY.md`](https://github.com/snaart/phantom_protocol/blob/main/SECURITY.md).

### Supply chain

`cargo deny` (permissive-license allowlist, `yanked = "deny"`,
`unknown-registry = "deny"`) and `cargo audit` run in CI. Release artifacts
carry **sigstore-backed in-toto build-provenance attestations** via
`actions/attest-build-provenance@v4` (SHA-pinned). Every artifact is covered, and
the attestation names the workflow, the commit and the runner that produced it, so
a tarball claiming to be a release of this crate can be checked against a
signature only a run of this repository's workflow can produce. Verify with
`gh attestation verify --owner <org> <artifact>` or
`cosign verify-blob-attestation`.

That is **SLSA v1.0 Build Level 2**, not Level 3. L3 asks that the build run
somewhere the provenance signing identity is not reachable from the build steps
themselves; here the attest step sits inline in the same `build-artifacts` job
that compiles, and that job restores a `Swatinem/rust-cache` shared with the rest
of CI. Reaching L3 is a workflow change, not a code change — see
[`docs/DEFERRED_WORK.md` §1](https://github.com/snaart/phantom_protocol/blob/main/docs/DEFERRED_WORK.md).

## Status & limitations

> **Maturity: early. Not production-ready.** This is a single implementation
> with **no external security audit**. The cryptographic handshake + identity
> layer and the UDP data plane (SACK loss recovery, congestion control,
> connection migration) are implemented and tested — against a deterministic
> fault-injection transport (loss / reorder), the `udp_integration` loopback
> suite, and, since August 2026, a real WAN route measured against a QUIC
> reference and raw no-protocol controls (see [Performance](#performance)).
> What that measurement does **not** cover is route diversity: one server, one
> client, one provider pair, no mobile carrier, no satellite, no lossy radio.
> The gating limitations are the **absence of an independent security audit**,
> the pre-1.0 wire churn, and that single route — **not** an unfinished data
> plane. Do not protect anything high-risk with this until it has been
> independently audited.

- **Pre-1.0 (`0.3.0`).** Wire format may break between minors; SemVer applies
  once 1.0 ships. The current wire protocol is a single pinned version — the
  former V1/V2/V3 axes were collapsed pre-1.0, with no negotiation and no
  fallback, so there are no cross-version migration guides. **0.3.x and 0.2.x
  peers do not interoperate:** this release speaks `WIRE_VERSION` <!--pinned:WIRE_VERSION-->8
  and `PROTOCOL_VERSION` <!--pinned:PROTOCOL_VERSION-->5, where 0.2.x spoke 6 and
  3, and the handshake refuses the mismatch with a typed `ServerReject` rather
  than negotiating down. Upgrade both ends together, and regenerate the language
  bindings rather than relinking them — every UniFFI checksum moved in 0.3.0 (see
  [`CHANGELOG.md`](https://github.com/snaart/phantom_protocol/blob/main/CHANGELOG.md)).
- **Native UDP transport (PhantomUDP): handshake + demux + reliability shipped.**
  `PhantomSession` runs an authenticated session over TCP, WebSocket, and raw UDP
  (connection-ID demux, server accept, fragmented handshake). The UDP data plane
  has SACK-based loss recovery (RFC-9002-style fast-retransmit) + an RFC-6298 RTO
  + a BBR-style congestion controller + mid-session rekey, exercised over a
  deterministic fault-injection transport (loss / reorder —
  `test_harness/fault_transport.rs`) and the `udp_integration` suite. **Seamless
  connection migration** (one live path at a time, Wi-Fi↔cellular without
  re-handshake) shipped too. The earlier experimental KCP / FakeTLS legs and the
  unused `TransportLeg` multipath trait were removed (never wired into the data
  plane). Bandwidth *aggregation* across transports is **not** planned — analysis
  showed it regresses for this workload and harms unobservability. What remains:
  an external audit, and route diversity — every WAN figure in this README comes
  from one route between one pair of hosts.
- **TLS-mimicry transport (`mimicry` feature, off by default).** A `MimicTlsLeg`
  makes a Phantom flow look like ordinary HTTPS (a synthetic TLS 1.3 handshake,
  then the session inside ApplicationData records) to defeat DPI that blocks
  unknown/high-entropy traffic. **The outer TLS is anti-DPI obfuscation only** —
  the handshake is theater (no real ECDHE/cert) and holds no keys; the inner
  Phantom PQ session is the sole auth/conf. **It defeats parsers, not provers:** a
  determined active-probing censor that completes a real TLS handshake detects it
  in one round trip, and against such an adversary it is net-negative. Use only
  where the threat is passive/commercial DPI, not active probing. Honest residuals
  + SAFE/UNSAFE guidance in [`docs/security/threat-model.md`](https://github.com/snaart/phantom_protocol/blob/main/docs/security/threat-model.md) §6.1.
- **Mobile connection migration (Wi-Fi ↔ LTE): use the UDP transport for real
  migration, or reconnect with 0-RTT on TCP.** `PhantomSession.migrate()` performs
  real single-path seamless migration when the session is backed by
  `UdpClientTransport` (via `connect_pinned_udp`). On TCP-backed sessions it returns
  `Err(CoreError::Unsupported)`. On a network change with TCP, reconnect — folding
  the first request in via `connect_pinned_with_resumption` to minimise cost. The
  [`examples/mobile/`](https://github.com/snaart/phantom_protocol/tree/main/examples/mobile/) sample apps demonstrate the reconnect-with-0-RTT
  model; see [`docs/operations/mobile.md`](https://github.com/snaart/phantom_protocol/blob/main/docs/operations/mobile.md) for the UDP
  migration path.
- **Work deferred past 0.2.0** — hermetic/reproducible builds, the `no-std` PQ
  handshake, WASI server-side sessions, and ECN congestion feedback — is
  consolidated with rationale in [`docs/DEFERRED_WORK.md`](https://github.com/snaart/phantom_protocol/blob/main/docs/DEFERRED_WORK.md).
- **Loss recovery and congestion control: measured on a real route — on one
  route.** The UDP data plane has RFC-9002-style SACK + dup-ACK fast-retransmit,
  an RFC-6298 RTO, a BBR-style congestion window, and mid-session rekey. It is
  exercised by `udp_integration` over `test_harness/fault_transport.rs`
  (injected loss + reorder) *and* by the WAN campaigns above, where it runs
  beside a QUIC reference and raw controls on the same path in the same run.
  That instrument is what found the congestion-control defects fixed in 0.3.0
  (recorded in
  [`CHANGELOG.md`](https://github.com/snaart/phantom_protocol/blob/main/CHANGELOG.md)),
  none of which the test suite could see: at a loopback round trip of 0.4 ms a
  5600-byte congestion window still yields 112 Mbit/s, and the same window on a
  210 ms path yields 0.213. What is still missing is a second route and an
  external review — treat the data plane as measured-on-one-path, not
  battle-tested.
- **What the transport does not reach, stated as measurements rather than as
  work items.** These are properties of the builds measured on the one route
  there is — those of the 2026-09-05 campaigns, which differ from this release
  by the one Startup change noted under [Performance](#performance) — and none
  of them is a defect with a fix pending. Every throughput figure taken on the
  route is against a raw no-protocol control from the same run.
  - **Upload reaches about a third of the measured ceiling.** The morning
    campaign of 2026-09-05 put it at 27.02–28.33 Mbit/s against an
    84.26–84.97 Mbit/s one-way upward control from the same runs — 32–34% of the
    link, up from 22–24% against the same 84 Mbit/s control on 2026-08-26, before
    the loss-response change. The transfer reached its final rate about six
    seconds into its sixty, where the 2026-08-26 runs took 13–18 s. A third of
    the link is a real gap, and the reason it is quotable at all is that both the
    numerator and the denominator come from the same run. It is quotable only
    against that run: six hours later the same control read 55.56–59.29 Mbit/s
    on the same route with the same library, so a share of the upward link is
    not yet a stable figure.
  - **Duplex runs short of the slower one-way direction, by an amount that
    moves with the route.** The download half of a duplex transfer, against a
    one-way download from the same run, ran at 81–89% in the morning campaign of
    2026-09-05 and at 49–63% six hours later, when the downward control had
    started losing 1–10% of datagrams at low rates. The criterion the project
    set for itself was "reproducibly no worse than the slower one-way", and
    neither campaign meets it. Within each campaign the three runs agree to
    within 14 percentage points, where the three 60-second runs of 2026-08-26
    spread across 35 (52–86%).
  - **The ARQ send buffer is bounded in segments, not bytes.** At 1024 segments
    it is 1024 × the segment size, so on a small application frame it binds
    about four times sooner than the peer's window does: a `send_ceiling` sweep
    reads 266,240 B of inflight on a 256-byte frame against 1,048,492 B on a
    2308-byte one, in three runs each. An application that writes small messages
    pays for that; one that writes large ones does not notice.
  - **The TCP leg carries two congestion controllers stacked.** Phantom's own
    BBR-style controller runs inside a TCP connection that has one of its own.
    The leg exists to cross networks that pass TCP and nothing else, not to go
    fast; the UDP leg is the production path and the only one where `migrate()`
    works.
  - **Against a mature implementation of the same class, on the same path, in
    the same run.** On upload, in the three afternoon runs of 2026-09-05, quinn
    delivered 1.1–2.4× what this transport did (28.03 / 65.85 / 31.54 against
    26.03 / 27.10 / 23.71 Mbit/s, counted by the server) against a one-way
    upward control of 58.64 / 59.29 / 55.56 from the same runs. The reference
    itself moved 2.3× across those three runs while this leg moved 1.14×, and in
    one of them quinn delivered 111% of the control, so the control under-read
    the path. That control moved between 55 and 85 Mbit/s within one day, so
    shares of the upward link are not yet reliable. On download, in the same
    runs, the route lost 1–10% of datagrams far below its 76.5 Mbit/s ceiling,
    and this transport held 11.13–12.07 Mbit/s where quinn's loss-based
    controller held 0.33–0.49 — more than an order of magnitude. In a loopback
    run of the download scenario, with no route and no raw control beside it,
    quinn moved roughly three times what this transport did. The size of the gap
    in either direction is a property of the path rather than a ranking.
- **Negative-security suite: 73 always-on tests** in
  `core/tests/security_invariants.rs`, covering most — not all — of the eleven
  numbered security invariants (listed in `docs/security/invariants.md`): identity pinning, the unencrypted-packet receive
  gate, replay rejection, rekey and epoch handling, path validation, transcript
  binding of the 0-RTT verdict, and 0-RTT ticket handling. Three are pinned
  elsewhere and deliberately not here: the two FIPS invariants (build-mode
  transcript binding, power-on self-tests) belong to a build this suite does not
  compile and are gated by the `fips-feature` CI job, and the TLS-mimicry parser
  bounds ride the off-by-default `mimicry` feature and its own job. Two more are
  pinned in part — the AEAD nonce ceiling (2^48) is not reachable from a test, so
  what is pinned is the counter feeding it, and the path-validation tests cover
  the state machine rather than its constant-timeness, which is an audit
  (`docs/compliance/constant-time-audit.md`) and not a measurement. Where only
  part of an invariant is pinned, the tests say so.
  Plus the proptest, fuzz, wire-vector, runtime-integration, and CAVP suites,
  683 library unit tests, and `#[ignore]`-gated loopback integration suites
  (TCP, UDP — including injected loss/reorder via the fault transport — WASI,
  TLS-mimicry). 0 workspace warnings, 0 clippy warnings. **Note:** broad test
  coverage, a fault-injection rig, and a WAN measurement campaign are *not* a
  substitute for an external security audit.
- **Broad feature coverage across the planned phases, but not production-ready.**
  The handshake / identity / data-plane / observability / cross-target work is in
  place and tested; what remains open is an **external security audit**, CMVP/CC
  validation, formal verification (ProVerif / Tamarin), and a soak across more
  than one route — none done.
- **`PhantomListener::bind()` generates a fresh signing key per process** —
  identities don't survive restart. Pin-stable production deployments must use
  `bind_with_signing_key()` with a key loaded from disk (`phantom-cli keygen`
  writes 0600 seed files).
- **The library ships no HTTP server.** The library exposes OTel
  instruments; embedders configure the exporter. `server/src/telemetry.rs`
  is the reference OTLP/gRPC wiring.
- **MSRV: Rust 1.93** (raised from 1.75 — the PQ crates pull `pkcs8 0.11` →
  edition2024 → Rust ≥1.85; the CI gate is 1.93). `cli/` uses edition 2024.
- **7 fuzz harnesses**, run in CI (`.github/workflows/fuzz.yml`: 60 s per target
  per PR, 600 s nightly). Fuzzing needs nightly; only `fuzz_embedded_framing`'s
  body also compiles on stable.
- **Embedded is framing-only on bare-metal.** The `thumbv7em-none-eabihf` build
  (`--no-default-features --features embedded,no-std`) ships `EmbeddedLeg` + its
  length-prefix framing; the PQ crypto, handshake, and `PhantomSession` are
  `std`-gated out. **PQ-on-bare-metal is descoped for 1.0** — the RustCrypto
  primitives need `alloc` plus entropy/heap the embedder supplies, and a real
  bare-metal handshake (no-std crypto, an Embassy/RTIC runtime, a QEMU-hosted
  handshake test) is a separate sub-project. Bare-metal embedders run their own
  crypto over the leg. The hard `thumbv7em` CI gate is `cargo check --lib` — it
  proves the framing compiles, not that a session runs.

## Documentation

- **Architecture:** [`docs/architecture/ARCHITECTURE.md`](https://github.com/snaart/phantom_protocol/blob/main/docs/architecture/ARCHITECTURE.md);
  contributor workflow in [CONTRIBUTING.md](https://github.com/snaart/phantom_protocol/blob/main/CONTRIBUTING.md)
- **Wire protocol:** [`docs/protocol/PROTOCOL.md`](https://github.com/snaart/phantom_protocol/blob/main/docs/protocol/PROTOCOL.md)
  (the single unified protocol, incl. 0-RTT)
- **Security:** [`SECURITY.md`](https://github.com/snaart/phantom_protocol/blob/main/SECURITY.md),
  [`docs/security/threat-model.md`](https://github.com/snaart/phantom_protocol/blob/main/docs/security/threat-model.md),
  [`docs/security/incident-response.md`](https://github.com/snaart/phantom_protocol/blob/main/docs/security/incident-response.md),
  [`docs/security/cancel-safety-audit.md`](https://github.com/snaart/phantom_protocol/blob/main/docs/security/cancel-safety-audit.md),
  [`docs/security/panic-sites.md`](https://github.com/snaart/phantom_protocol/blob/main/docs/security/panic-sites.md)
- **Compliance:** [`docs/compliance/`](https://github.com/snaart/phantom_protocol/tree/main/docs/compliance/) —
  `fips-readiness.md`, `cc-pp-mapping.md`, `constant-time-audit.md`,
  `rng-audit.md`, `key-management.md`, `self-tests.md`,
  `fips-security-policy.md`
- **Operations:** [`docs/operations/`](https://github.com/snaart/phantom_protocol/tree/main/docs/operations/) —
  `perf-tuning.md`, `deployment.md`, `docker.md`, `systemd.md`,
  `kubernetes.md` (+ `helm/`), `mobile.md`, `wasm.md`, `wasi.md`,
  `zero-rtt.md`
- **Policy:** [`docs/policy/versioning.md`](https://github.com/snaart/phantom_protocol/blob/main/docs/policy/versioning.md)
- **Performance:** [`BENCHMARKS.md`](https://github.com/snaart/phantom_protocol/blob/main/BENCHMARKS.md)
  (loopback benches), [`testbed/README.md`](https://github.com/snaart/phantom_protocol/blob/main/testbed/README.md)
  (the WAN measurement harness, and how each real-route figure is computed)
- **Change log:** [`CHANGELOG.md`](https://github.com/snaart/phantom_protocol/blob/main/CHANGELOG.md)

## Contributing

See [CONTRIBUTING.md](https://github.com/snaart/phantom_protocol/blob/main/CONTRIBUTING.md). PRs must pass `cargo fmt --check`,
`cargo clippy --lib -- -D warnings`, `cargo test --lib`, and `cargo deny check`.
The `cli-check` CI job requires that `core` API edits keep
`cli/` building.

## Acknowledgements

Developed with AI assistance from Anthropic's **Fable 5** via
[Claude Code](https://claude.com/claude-code). All architectural decisions,
security invariants, threat model, and FIPS / CC compliance artifacts are
authored, reviewed, tested, and maintained by the human author.

## License

Apache License 2.0. See [LICENSE](https://github.com/snaart/phantom_protocol/blob/main/LICENSE).
