# Phantom Protocol

[![crates.io](https://img.shields.io/crates/v/phantom-protocol.svg)](https://crates.io/crates/phantom-protocol)
[![docs.rs](https://img.shields.io/docsrs/phantom-protocol)](https://docs.rs/phantom-protocol)
[![CI](https://github.com/snaart/phantom_protocol/actions/workflows/ci.yml/badge.svg)](https://github.com/snaart/phantom_protocol/actions/workflows/ci.yml)
[![license](https://img.shields.io/crates/l/phantom-protocol.svg)](LICENSE)
![MSRV](https://img.shields.io/badge/MSRV-1.75-blue)

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

> **Pre-1.0 (`0.1.1`).** Wire format may break between minors; SemVer kicks in at
> 1.0. 0 workspace warnings, 0 `unsafe` outside three audited opt-ins, MSRV Rust
> 1.75, CI green across the full cross-target matrix. See
> [Status & limitations](#status--limitations).

## Install

Published on crates.io as [`phantom-protocol`](https://crates.io/crates/phantom-protocol)
(the import path is `phantom_protocol`):

```toml
[dependencies]
phantom-protocol = "0.1"
```

or `cargo add phantom-protocol`. API docs: <https://docs.rs/phantom-protocol>.

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
- **Transports** — `PhantomSession` runs an authenticated session over **TCP**
  and **WebSocket** today (plus WASI and Embedded as framing legs). A native
  reliable-UDP transport (**PhantomUDP**) is in development to add multi-path,
  congestion control, and connection migration with no extra crypto layer (see
  [Status & limitations](#status--limitations)). The earlier experimental
  KCP / FakeTLS legs and the unused `TransportLeg` multipath trait were removed
  pending that work. TLS traffic mimicry returned as the optional **`mimicry`
  feature** — a TLS-over-TCP `MimicTlsLeg` (`connect_pinned_mimic` / `bind_mimic`)
  that makes a flow look like HTTPS to passive DPI + JA3/JA4 fingerprinting. It is
  anti-DPI obfuscation only and is **detectable by active probing** — see
  [Status & limitations](#status--limitations).
- **Multi-stream** — strict-priority scheduler, `WINDOW_UPDATE` per-stream
  flow control, BBRv2-inspired pacing (Startup / Drain / ProbeBW / ProbeRTT /
  FastRecovery).
- **DoS-resistant handshake** — stateless HMAC-SHA-256 cookie (hourly-rotated
  master) + adaptive blake3 proof-of-work (load-tiered difficulty 0–16).
- **Per-stream replay protection** — RFC 4303 §3.4.3 sliding-window bitmap,
  default 1024 bits, checked _after_ AEAD verify.
- **Observability** — OpenTelemetry metrics + traces (opt-in
  `telemetry-otel` feature). Lock-free hot-path atomics (≤ 2.5 ns / call),
  OTLP/gRPC push to any backend (Datadog, Honeycomb, Grafana Cloud,
  self-hosted via OTel Collector). Pre-built Grafana dashboard + Prometheus
  alert rules in `docs/observability/`.
- **SLSA-3 build provenance** — OIDC attestation on every release artifact.
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

More commands (benches, fuzz, miri, cross-targets, embedded) are in
[CONTRIBUTING.md](CONTRIBUTING.md).

### Minimal client / server

Server identity must be pinned — `connect_with_transport` requires a
`HybridVerifyingKey`; there is no skip path (Security Invariant 1).

```rust
use phantom_protocol::api::{PhantomListener, PhantomSession, TcpSessionTransport};
use phantom_protocol::crypto::hybrid_sign::HybridVerifyingKey;
use tokio::net::TcpStream;

// ── Server ────────────────────────────────────────────────────────────────
let listener = PhantomListener::bind("127.0.0.1:0".to_string()).await?;
let server_addr = listener.local_addr();
let pinned_key  = listener.verifying_key_bytes();   // share out-of-band

tokio::spawn(async move {
    let outcome = listener.accept().await?;
    let session = outcome.session();
    let req = session.recv().await?;
    session.send(b"hello, post-quantum world".to_vec()).await?;
    Ok::<_, phantom_protocol::CoreError>(())
});

// ── Client (one-shot helper used by mobile / FFI consumers) ───────────────
let session = phantom_protocol::api::session::connect_pinned(
    "127.0.0.1".into(), 4242, pinned_key,
).await?;
session.send(b"ping".to_vec()).await?;
let reply = session.recv().await?;

// ── Or, explicit transport (TCP / WebSocket today; WASI / Embedded framing) ─
let stream    = TcpStream::connect(&server_addr).await?;
let transport = TcpSessionTransport::new(stream);
let key       = HybridVerifyingKey::from_bytes(&pinned_key)?;
let session   = PhantomSession::connect_with_transport(&server_addr, transport, key);
```

Runnable forms: [`core/examples/loopback_demo.rs`](core/examples/loopback_demo.rs),
[`core/examples/embedded_demo.rs`](core/examples/embedded_demo.rs),
[`core/examples/crypto_bench.rs`](core/examples/crypto_bench.rs).

## Cryptography

| Role | Primitive | Standard / source |
| --- | --- | --- |
| KEM | X25519 + ML-KEM-768 | RFC 7748 + FIPS 203 (RustCrypto `ml-kem`) |
| Signatures | Ed25519 + ML-DSA-65 | FIPS 186-5 + FIPS 204 (RustCrypto `ml-dsa`) |
| AEAD (primary) | AES-256-GCM | `ring`, HW-accelerated (AES-NI / ARMv8 PMULL) |
| AEAD (fallback) | ChaCha20-Poly1305 | RFC 8439, auto-selected without AES intrinsics |
| KDF | HKDF-SHA-256 | RFC 5869 |
| Hash / MAC | SHA-256, HMAC-SHA-256, blake3 (keyed) | FIPS 180-4 / FIPS 198-1 + non-FIPS |

Phase 5.1 moved the PQ primitives off the C-bound `pqcrypto-*` crates to the
RustCrypto FIPS-203 / FIPS-204 implementations. The crate compiles on
`wasm32-unknown-unknown` and `thumbv7em-none-eabihf` without C bindings.

## Architecture

```
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
│  ReplayWindow · ReplayProtection                                │
├─────────────────────────────────────────────────────────────────┤
│  Runtime      (core/src/runtime/)                               │
│  TokioRuntime (native) · WasmRuntime · (EmbeddedRuntime TODO)   │
└─────────────────────────────────────────────────────────────────┘
```

The formal architecture spec is
[`docs/architecture/ARCHITECTURE.md`](docs/architecture/ARCHITECTURE.md);
the unified wire protocol (incl. 0-RTT) is
[`docs/protocol/PROTOCOL.md`](docs/protocol/PROTOCOL.md). Per-subsystem
security invariants are catalogued in
[`docs/security/threat-model.md`](docs/security/threat-model.md).

## Transport features

- **Single unified wire protocol.** One `PacketHeader` (45 bytes, with a
  pinned `version` byte = `WIRE_VERSION`) wrapped in a bare `PhantomPacket`
  (`header` + `payload` + TLV-headroom `extensions`) — no `VersionedPacket`
  enum, no per-session wire-version negotiation. `epoch`, `REKEY`,
  `PATH_VALIDATION`, `COALESCED`, `WINDOW_UPDATE` flags live in the one header;
  the recv path deserializes `PhantomPacket` directly and drops any frame whose
  `header.version` differs. Handshake messages are bare borsh structs (no
  envelopes): one `ClientHello` (with the optional 0-RTT `early_data` blob folded
  in), one `ServerHello`, one `HelloRetryRequest`, one signed
  `HandshakeTranscript` leading with `protocol_variant`. The pinned
  `PROTOCOL_VERSION` / `WIRE_VERSION` bytes are tamper-check anchors and a hook
  for a future deliberate bump.
- **Path-validation primitive (internal).** `PathRegistry` + constant-time
  challenge/response; path 0 pre-validated, secondary paths transition
  `Unvalidated → Validating → Validated`. This is the building block for future
  connection migration; it is not yet wired into a live multi-path data plane.

## Performance

Reference numbers on **Apple M1 Pro (8P + 2E, 16 GiB), macOS 26.0, rustc 1.93.0,
`ring` with ARMv8 AES-PMULL** (snapshot 2026-05-17, criterion `--quick`, default
`target-cpu`):

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
[`BENCHMARKS.md`](BENCHMARKS.md) and [`docs/operations/perf-tuning.md`](docs/operations/perf-tuning.md).

## Deploying

### `phantom-server` (reference binary)

Production embedder. Auto-loads-or-creates a persistent `HybridSigningKey`,
pushes OTLP telemetry to an OTel Collector / SaaS backend, handles SIGTERM
/ SIGINT with a 10s drain.

| Flag | Env | Default |
| --- | --- | --- |
| `--bind` | `PHANTOM_BIND` | `0.0.0.0:4242` |
| `--otlp-endpoint` | `OTEL_EXPORTER_OTLP_ENDPOINT` | `http://localhost:4317` |
| `--otel-service-name` | `OTEL_SERVICE_NAME` | `phantom-server` |
| `--otel-trace-sample-ratio` | `OTEL_TRACES_SAMPLER_ARG` | `0.01` |
| `--signing-key-file` | `PHANTOM_SIGNING_KEY_FILE` | `/etc/phantom-server/signing.key` (0600, auto-created) |
| `--log-json` | `PHANTOM_LOG_JSON` | `false` |
| `--log-filter` | `RUST_LOG` | `info,phantom_protocol=debug` |

```bash
cargo run --manifest-path server/Cargo.toml -- \
    --bind 0.0.0.0:4242 \
    --otlp-endpoint http://otel-collector:4317
```

### Docker / docker-compose

Multi-stage `Dockerfile` (`rust:1-slim-bookworm` → `debian:bookworm-slim`),
non-root `phantom` UID 65532, EXPOSE 4242 + 9090, signing-key volume at
`/etc/phantom-server`. `docker-compose.yml` is ready to run with a named volume
and TCP healthcheck.

```bash
docker build -t phantom-server:0.1.1 .
docker compose up -d
```

### Kubernetes / Helm

Production-shape chart at
[`docs/operations/helm/phantom-protocol/`](docs/operations/helm/phantom-protocol/).
`appVersion: 0.1.1`, ClusterIP service on `4242`, 3 replicas,
`tcpSocket` liveness / readiness. Raw manifests + walkthrough in
[`docs/operations/kubernetes.md`](docs/operations/kubernetes.md).

### systemd

Hardened unit text in [`docs/operations/systemd.md`](docs/operations/systemd.md)
(`NoNewPrivileges`, `ProtectSystem=strict`, `MemoryDenyWriteExecute`,
`SystemCallFilter`, 30s `TimeoutStopSec`) plus a multi-instance template using
`SO_REUSEPORT`.

### Observability

OpenTelemetry metrics + traces over OTLP/gRPC (Phase 8 — replaces the
Phase 4.5 hand-rolled Prometheus endpoint). The reference server pushes to
`OTEL_EXPORTER_OTLP_ENDPOINT`; backends supported include OTel Collector
(→ Prometheus / Tempo / Loki), Datadog, Honeycomb, Grafana Cloud, AWS
CloudWatch — anything OTLP-compatible. Pre-built Grafana dashboard at
[`docs/observability/grafana/phantom-otel-dashboard.json`](docs/observability/grafana/phantom-otel-dashboard.json)
and Prometheus alert rules at
[`docs/observability/prometheus/alerts.yml`](docs/observability/prometheus/alerts.yml).
End-to-end docker-compose demo in
[`examples/observability-demo/`](examples/observability-demo/). Full setup
recipes in [`docs/observability/otlp-setup.md`](docs/observability/otlp-setup.md).

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
| `wasm32-unknown-unknown` | hard gate (Phase 3.3 / 3.5) |
| `thumbv7em-none-eabihf` | hard gate (Phase 3.6; `--no-default-features --features embedded,no-std`) |
| `wasm32-wasip2` | hard gate (compile + host round-trip; WASI is client-side framing-only — see [`docs/operations/wasi.md`](docs/operations/wasi.md)) |

### Language bindings (`tests/bindings/`)

| Binding | Maturity | Notes |
| --- | --- | --- |
| **Swift** | Production-shape | Auto-gen via UniFFI 0.29; iOS XCFramework recipe in [`docs/operations/mobile.md`](docs/operations/mobile.md) |
| **Kotlin** | Production-shape | Auto-gen; Android NDK + Gradle `jniLibs` recipe in `mobile.md` |
| **Python** | UniFFI surface auto-gen | Demo harness `tests/run_test.py` is stale and references a previous API |
| **C** | Experimental | **Hand-curated** header — UniFFI 0.29 has no C generator. Covers `connect_pinned` but not `HybridSigningKey` or `PhantomConfig`. README recommends Swift / Kotlin / Python instead |
| **WASM (browser)** | Demo shipped | [`examples/wasm-demo/`](examples/wasm-demo/) pairs with [`docs/operations/wasm.md`](docs/operations/wasm.md); uses `WebSocketLeg` + `WasmRuntime` |

Regen: `tests/bindings/{generate_swift,generate_kotlin,generate_c}.sh`.

### Embedded (`embedded` feature, default off)

On bare-metal `thumbv7em-none-eabihf` Phantom Protocol ships the **framing transport
only** — `EmbeddedLeg` and its length-prefix codec. The PQ handshake,
`PhantomSession`, the crypto primitives, and `TokioRuntime` are `std`-gated and
**not** built there; a bare-metal embedder brings its own crypto/handshake driver
and runs it over the leg. PQ-on-bare-metal is descoped for 1.0 (see
[Status & limitations](#status--limitations)).

`EmbeddedLeg<R, W, const N: usize>` wraps any `embedded-io-async = 0.6` byte
stream (UART, USB-CDC, …) with 4-byte BE length-prefix framing — the same wire
shape as `TcpSessionTransport`. Pure-Rust, no_std + alloc, target-arch-agnostic
(builds on host x86_64 for unit tests _and_ on bare-metal `thumbv7em-none-eabihf`).
Per-`(R, W)` `SessionTransport` impl via the `impl_embedded_session_transport!`
macro. `RngProvider` trait injects a hardware RNG when `getrandom` isn't
available. [`core/examples/embedded_demo.rs`](core/examples/embedded_demo.rs) runs
the full session over a mock byte stream **on a host** (std), demonstrating the
leg — not a bare-metal handshake.

## Security

Full threat model, mitigations, and disclosure policy are in
[`SECURITY.md`](SECURITY.md) and
[`docs/security/threat-model.md`](docs/security/threat-model.md). Headline points:

- **Mandatory server identity pinning** — `connect_with_transport` requires a
  `HybridVerifyingKey`; no skip path.
- **Forward secrecy** — ephemeral hybrid KEM per handshake + HKDF-based
  mid-session rekey (epoch saturates at `u8::MAX`, never wraps).
- **Replay rejection happens _after_ AEAD verify** — RFC 4303 §3.4.3
  sliding-window bitmap, per-stream.
- **Downgrade resistance** — the pinned protocol version and `protocol_variant`
  are signed under the handshake transcript; stripped-`ENCRYPTED` post-handshake
  packets are dropped.
- **0-RTT anti-replay** — `SessionCache::try_resume` consumes the resumption
  ticket on first lookup; oversized / expired / AEAD-failing early-data is
  best-effort and never fatal to the handshake.
- **AEAD nonce-exhaustion guard** — `CryptoError::NonceExhausted` at
  `AEAD_MAX_INVOCATIONS = 2^48`.
- **`ZeroizeOnDrop` on all key-bearing structs**; `#![deny(unsafe_code)]`
  crate-wide with one audited opt-in (`transport/udp_transport.rs` for libc
  GSO / `recvmmsg`).
- Cancel-safety audit: zero bugs found across all `tokio::select!` sites.
- 6 documented production panic sites with `PANIC-SAFETY:` invariants — see
  [`docs/security/panic-sites.md`](docs/security/panic-sites.md).

### FIPS 140-3 / Common Criteria — exploratory only, NOT validated

> **No FIPS validation and no Common Criteria evaluation exist, and none is in
> progress.** The files under [`docs/compliance/`](docs/compliance/) are
> self-authored *readiness/gap analyses*, not certifications — do not rely on
> them for any compliance claim.

- **FIPS 140-3:** the crypto uses several FIPS-approved primitives (ML-KEM-768,
  ML-DSA-65, Ed25519, SHA-256, HMAC/HKDF-SHA-256), and an optional `fips` Cargo
  feature swaps the remaining non-approved primitives toward an `aws-lc-rs`
  substrate. This is *not* a validated cryptographic module (no CMVP). Gap
  analysis: [`docs/compliance/fips-readiness.md`](docs/compliance/fips-readiness.md);
  CAVP-style known-answer vectors in [`core/tests/cavp.rs`](core/tests/cavp.rs).
- **Common Criteria:** an internal SFR gap-mapping exercise against NIAP
  PP-Module VPN Client exists for design reference only
  ([`docs/compliance/cc-pp-mapping.md`](docs/compliance/cc-pp-mapping.md)). No
  lab evaluation is planned.

### Disclosure

Report privately, **not** via public issues. Embargo SLA 90 days; ack within
5 business days, triage within 14. Contact in [`SECURITY.md`](SECURITY.md)
(the email there is a placeholder pending crate publication).

### Supply chain

`cargo deny` (permissive-license allowlist, `yanked = "deny"`,
`unknown-registry = "deny"`) and `cargo audit` run in CI. Release artifacts
carry **SLSA-3 OIDC build-provenance attestations** via
`actions/attest-build-provenance@v2`. Verify with
`gh attestation verify --owner <org> <artifact>` or
`cosign verify-blob-attestation`.

## Status & limitations

> **Maturity: early. Not production-ready.** This is a single implementation
> with **no external security audit**. The cryptographic handshake and identity
> layer are implemented and well-tested; the **data plane is the unfinished
> part** — the UDP transport's reliability (loss recovery) has **not yet been
> exercised against real packet loss** (see below). Do not protect anything
> high-risk with this until it has been independently audited and the loss-
> recovery path is validated.

- **Pre-1.0 (`0.1.1`).** Wire format may break between minors; SemVer applies
  once 1.0 ships. The current wire protocol is a single pinned version — the
  former V1/V2/V3 axes were collapsed pre-1.0 (no users, no negotiation, no
  fallback), so there are no cross-version migration guides.
- **Native UDP transport (PhantomUDP): handshake + demux work; loss recovery is
  the open piece.** `PhantomSession` runs an authenticated session over TCP,
  WebSocket, and now raw UDP (connection-ID demux, server accept, fragmented
  handshake) — proven end-to-end on a lossless loopback. What is **not** done:
  the UDP data plane's loss recovery has only ever run over reliable pipes and
  has not been validated over real loss; a deterministic lossy/reordering test
  transport (needed to validate it) is being built first. The earlier
  experimental KCP / FakeTLS legs and the unused `TransportLeg` multipath trait
  were removed (never wired into the data plane). Roadmap: prove single-path UDP
  loss recovery → seamless connection migration (one live path at a time, for
  Wi-Fi↔cellular handoff without re-handshake). Bandwidth *aggregation* across
  transports is **not** planned — analysis showed it regresses for this workload
  and harms unobservability.
- **TLS-mimicry transport (`mimicry` feature, off by default).** A `MimicTlsLeg`
  makes a Phantom flow look like ordinary HTTPS (a synthetic TLS 1.3 handshake,
  then the session inside ApplicationData records) to defeat DPI that blocks
  unknown/high-entropy traffic. **The outer TLS is anti-DPI obfuscation only** —
  the handshake is theater (no real ECDHE/cert) and holds no keys; the inner
  Phantom PQ session is the sole auth/conf. **It defeats parsers, not provers:** a
  determined active-probing censor that completes a real TLS handshake detects it
  in one round trip, and against such an adversary it is net-negative. Use only
  where the threat is passive/commercial DPI, not active probing. Honest residuals
  + SAFE/UNSAFE guidance in [`docs/security/threat-model.md`](docs/security/threat-model.md) §6.1.
- **Mobile connection migration (Wi-Fi ↔ LTE): reconnect with 0-RTT, not
  `migrate()`.** `PhantomSession.migrate()` is on the FFI surface, but it is a
  no-op over the TCP transport the bindings use (real single-socket migration is
  UDP-only and not yet FFI-exposed). On a network change, reconnect — folding the
  first request in via `connect_pinned_with_resumption` to minimise cost. The
  [`examples/mobile/`](examples/mobile/) sample apps implement exactly this; see
  [`docs/operations/mobile.md`](docs/operations/mobile.md).
- **Work deferred past 0.2.0** — hermetic/reproducible builds, the `no-std` PQ
  handshake, WASI server-side sessions, and ECN congestion feedback — is
  consolidated with rationale in [`docs/DEFERRED_WORK.md`](docs/DEFERRED_WORK.md).
- **Loss recovery is timeout-based (no SACK) and unproven over loss.** The code
  has an RFC-6298 RTO + retransmission + a BBR-style congestion window + mid-
  session rekey, but this machinery was built for reliable byte pipes and has
  **never been exercised against real packet loss/reorder** — validating it
  (and the lossy test rig that makes that possible) is the current priority.
  SACK / dup-ACK fast-retransmit / PTO are the next work item and need
  security-sensitive packet-number / ACK-range fields, i.e. a deliberate
  `WIRE_VERSION` bump.
- **Negative-security suite: 33 always-on tests** in
  `core/tests/security_invariants.rs`, pinning every documented invariant.
  Plus the proptest, fuzz, wire-vector, runtime-integration, and CAVP suites,
  282 library unit tests, and `#[ignore]`-gated loopback integration suites
  (TCP, UDP, WASI). 0 workspace warnings, 0 clippy warnings. **Note:** broad
  test coverage is *not* the same as a validated transport — none of these
  exercise the data plane under real loss yet (see the loss-recovery item above).
- **Broad feature coverage across the planned phases, but not production-ready.**
  The handshake/identity/observability/cross-target work is largely in place;
  the data plane (UDP loss recovery) is the unfinished, unvalidated piece, and
  there has been no external security audit or CMVP/CC validation. Formal
  verification (ProVerif / Tamarin) and an external audit are open, not done.
- **`PhantomListener::bind()` generates a fresh signing key per process** —
  identities don't survive restart. Pin-stable production deployments must use
  `bind_with_signing_key()` with a key loaded from disk (`phantom-cli keygen`
  writes 0600 seed files).
- **The library ships no HTTP server.** The library exposes OTel
  instruments; embedders configure the exporter. `server/src/telemetry.rs`
  is the reference OTLP/gRPC wiring.
- **MSRV: Rust 1.75.** `cli/` uses edition 2024 and builds on stable but not
  on the 1.75 gate.
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

- **Architecture:** [`docs/architecture/ARCHITECTURE.md`](docs/architecture/ARCHITECTURE.md);
  contributor workflow in [CONTRIBUTING.md](CONTRIBUTING.md)
- **Wire protocol:** [`docs/protocol/PROTOCOL.md`](docs/protocol/PROTOCOL.md)
  (the single unified protocol, incl. 0-RTT)
- **Security:** [`SECURITY.md`](SECURITY.md),
  [`docs/security/threat-model.md`](docs/security/threat-model.md),
  [`docs/security/incident-response.md`](docs/security/incident-response.md),
  [`docs/security/cancel-safety-audit.md`](docs/security/cancel-safety-audit.md),
  [`docs/security/panic-sites.md`](docs/security/panic-sites.md)
- **Compliance:** [`docs/compliance/`](docs/compliance/) —
  `fips-readiness.md`, `cc-pp-mapping.md`, `constant-time-audit.md`,
  `rng-audit.md`, `key-management.md`, `self-tests.md`,
  `fips-security-policy.md`
- **Operations:** [`docs/operations/`](docs/operations/) —
  `perf-tuning.md`, `deployment.md`, `docker.md`, `systemd.md`,
  `kubernetes.md` (+ `helm/`), `mobile.md`, `wasm.md`, `wasi.md`
- **Policy:** [`docs/policy/versioning.md`](docs/policy/versioning.md)
- **Performance:** [`BENCHMARKS.md`](BENCHMARKS.md)
- **Change log:** [`CHANGELOG.md`](CHANGELOG.md)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). PRs must pass `cargo fmt --check`,
`cargo clippy --lib -- -D warnings`, `cargo test --lib`, and `cargo deny check`.
The `cli-compat` CI job requires that `core` API edits keep
`cli/` building.

## Acknowledgements

Developed with AI assistance from Anthropic's **Fable 5** via
[Claude Code](https://claude.com/claude-code). All architectural decisions,
security invariants, threat model, and FIPS / CC compliance artifacts are
authored, reviewed, tested, and maintained by the human author.

## License

Apache License 2.0. See [`LICENSE`](LICENSE).
