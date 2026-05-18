# Phantom Core

Post-quantum-secure L4/L6 universal transport framework in Rust.

Phantom Core gives applications an authenticated, confidential, post-quantum-secure
byte pipe. It pairs a hybrid classical-plus-PQ handshake (X25519 + ML-KEM-768 KEM,
Ed25519 + ML-DSA-65 signatures — FIPS 203 / FIPS 204, pure Rust) with a multi-path
transport (TCP / KCP-over-UDP / FakeTLS-over-TCP / WebSocket / embedded byte
streams) and adaptive fallback. Cross-language bindings via UniFFI (Python, Swift,
Kotlin, C); native WASM target; bare-metal `EmbeddedLeg` for no_std.

> **Pre-1.0 (`0.2.0`).** Wire format may break between minors; SemVer kicks in at
> 1.0. **261 / 261** tests passing, 0 workspace warnings, 0 `unsafe` outside one
> audited opt-in, MSRV Rust 1.75. See [Status & limitations](#status--limitations).

## Highlights

- **Hybrid post-quantum handshake** — X25519 + ML-KEM-768 KEM, Ed25519 + ML-DSA-65
  signatures. Both halves must verify. Pure-Rust RustCrypto primitives — no C
  bindings in the crypto path, compiles on every target including wasm32 and
  `thumbv7em-none-eabihf`.
- **0-RTT resumption** — opt-in V3 handshake envelope carries AEAD-sealed
  early-data (≤ 16 KiB), one-shot anti-replay via a consumed `SessionCache`
  ticket, automatic 1-RTT fallback when the server doesn't speak V3.
- **Mid-session rekey** — HKDF ratchet, V2 `REKEY` flag + per-packet `epoch`.
- **Multi-path** — TCP / KCP-over-UDP / FakeTLS-over-TCP / WebSocket / EmbeddedLeg.
  Constant-time path validation, per-path RTT/loss tracking, round-robin or
  low-latency scheduling.
- **Multi-stream** — strict-priority scheduler, V2 `WINDOW_UPDATE` per-stream
  flow control, BBRv2-inspired pacing (Startup / Drain / ProbeBW / ProbeRTT /
  FastRecovery).
- **DoS-resistant handshake** — stateless HMAC-SHA-256 cookie (hourly-rotated
  master) + adaptive blake3 proof-of-work (load-tiered difficulty 0–16).
- **Per-stream replay protection** — RFC 4303 §3.4.3 sliding-window bitmap,
  default 1024 bits, checked _after_ AEAD verify.
- **Observability** — Prometheus text exposition via
  `PhantomListener::metrics_prometheus_text()`; Grafana dashboard +
  Prometheus alert templates ship in `docs/operations/`.
- **SLSA-3 build provenance** — OIDC attestation on every release artifact.
- **Cross-platform** — 11 hard CI gates (Linux x4, macOS x2, iOS x2, Windows x2,
  wasm32-unknown-unknown, thumbv7em-none-eabihf). Only `wasm32-wasi` is
  `allow_failure`.

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
cargo test --manifest-path core/Cargo.toml --test kcp_integration -- --ignored
```

More commands (benches, fuzz, miri, cross-targets, embedded) are in
[CONTRIBUTING.md](CONTRIBUTING.md).

### Minimal client / server

Server identity must be pinned — `connect_with_transport` requires a
`HybridVerifyingKey`; there is no skip path (Security Invariant 1).

```rust
use phantom_core::api::{PhantomListener, PhantomSession, TcpSessionTransport};
use phantom_core::crypto::hybrid_sign::HybridVerifyingKey;
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
    Ok::<_, phantom_core::errors::CoreError>(())
});

// ── Client (one-shot helper used by mobile / FFI consumers) ───────────────
let session = phantom_core::api::session::connect_pinned(
    "127.0.0.1".into(), 4242, pinned_key,
).await?;
session.send(b"ping".to_vec()).await?;
let reply = session.recv().await?;

// ── Or, explicit transport (lets you swap KCP / FakeTLS / WebSocket) ──────
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
│  legs/{tcp, kcp, faketls, websocket, embedded}                  │
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
the wire protocol (incl. V3 0-RTT in §12) is
[`docs/protocol/PROTOCOL.md`](docs/protocol/PROTOCOL.md). Per-subsystem
security invariants are catalogued in
[`docs/security/threat-model.md`](docs/security/threat-model.md).

## Transport features

- **Wire formats V1, V2, V3.** V2 is the default for application-data packets
  (`epoch`, `REKEY`, `PATH_VALIDATION`, `COALESCED`, `WINDOW_UPDATE` flags); V3
  is a handshake-envelope-only bump that carries AEAD-sealed 0-RTT early-data and
  finalizes a V2-wire session. Borsh-framed handshake envelope with a 1-byte
  version discriminant; a V3-unaware server returns `Unsupported` and the client
  transparently falls back to V2.
- **Multi-path validation.** `PathRegistry` + constant-time challenge/response.
  Path 0 pre-validated; secondary paths transition `Unvalidated → Validating →
  Validated`. V2 recv pump auto-echoes responses.
- **FakeTLS leg.** Anti-DPI obfuscation only — per-direction blake3-derived keys,
  per-record counter nonces. The inner Phantom session provides real authenticated
  confidentiality.

## Performance

Reference numbers on **Apple M1 Pro (8P + 2E, 16 GiB), macOS 26.0, rustc 1.93.0,
`ring` with ARMv8 AES-PMULL** (snapshot 2026-05-17, criterion `--quick`, default
`target-cpu`):

| Path | Number | Notes |
| --- | --- | --- |
| Hybrid PQ handshake (pinned) | **1.06 ms** / ~945 conn/s/core | full production path; ~7,500 cold handshakes/s aggregate on 8P cores |
| AEAD encrypt, 64 KiB | **4.67 GiB/s/core** (13.1 µs) | `encrypt_packet_v2` with header-AAD + replay window |
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
exposes `/metrics`, handles SIGTERM / SIGINT with a 10s drain.

| Flag | Env | Default |
| --- | --- | --- |
| `--bind` | `PHANTOM_BIND` | `0.0.0.0:4242` |
| `--metrics-bind` | `PHANTOM_METRICS_BIND` | unset (disabled) |
| `--signing-key-file` | `PHANTOM_SIGNING_KEY_FILE` | `/etc/phantom-server/signing.key` (0600, auto-created) |
| `--log-json` | `PHANTOM_LOG_JSON` | `false` |
| `--log-filter` | `RUST_LOG` | `info,phantom_core=debug` |

```bash
cargo run --manifest-path server/Cargo.toml -- \
    --bind 0.0.0.0:4242 --metrics-bind 127.0.0.1:9090
```

### Docker / docker-compose

Multi-stage `Dockerfile` (`rust:1-slim-bookworm` → `debian:bookworm-slim`),
non-root `phantom` UID 65532, EXPOSE 4242 + 9090, signing-key volume at
`/etc/phantom-server`. `docker-compose.yml` is ready to run with a named volume
and TCP healthcheck.

```bash
docker build -t phantom-server:0.2.0 .
docker compose up -d
```

### Kubernetes / Helm

Production-shape chart at
[`docs/operations/helm/phantom-core/`](docs/operations/helm/phantom-core/).
`appVersion: 0.2.0`, ClusterIP service on `4242` (metrics on `9090`), 3 replicas,
`tcpSocket` liveness / readiness. Raw manifests + walkthrough in
[`docs/operations/kubernetes.md`](docs/operations/kubernetes.md).

### systemd

Hardened unit text in [`docs/operations/systemd.md`](docs/operations/systemd.md)
(`NoNewPrivileges`, `ProtectSystem=strict`, `MemoryDenyWriteExecute`,
`SystemCallFilter`, 30s `TimeoutStopSec`) plus a multi-instance template using
`SO_REUSEPORT`.

### Metrics

Prometheus text via `/metrics` (HTTP listener in `server/src/metrics_http.rs`
scraping `PhantomListener::metrics_prometheus_text()`). Ready-to-import
[`docs/operations/prometheus/alerts.yml`](docs/operations/prometheus/alerts.yml)
and [`docs/operations/grafana/phantom-dashboard.json`](docs/operations/grafana/phantom-dashboard.json).

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
| `wasm32-wasi` | `allow_failure: true` — deferred, see [`docs/operations/wasi.md`](docs/operations/wasi.md) |

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

`EmbeddedLeg<R, W, const N: usize>` wraps any `embedded-io-async = 0.6` byte
stream (UART, USB-CDC, …) with 4-byte BE length-prefix framing — the same wire
shape as `TcpSessionTransport`. Pure-Rust, no_std + alloc, target-arch-agnostic
(builds on host x86_64 for unit tests _and_ on bare-metal `thumbv7em-none-eabihf`).
Per-`(R, W)` `SessionTransport` impl via the `impl_embedded_session_transport!`
macro. `RngProvider` trait injects a hardware RNG when `getrandom` isn't
available. Runnable reference:
[`core/examples/embedded_demo.rs`](core/examples/embedded_demo.rs).

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
- **Downgrade resistance** — wire-format version is signed under the handshake
  transcript; stripped-`ENCRYPTED` post-handshake packets are dropped.
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

### FIPS 140-3 / Common Criteria

- **FIPS 140-3: partial.** Approved primitives already in use: ML-KEM-768,
  ML-DSA-65, Ed25519, SHA-256, HMAC-SHA-256, HKDF-SHA-256. Gaps blocking lab
  validation: X25519 (needs an approved-only ECDH-P-256 path), AES-256-GCM via
  `ring` (needs an `aws-lc-rs`-backed module), ChaCha20-Poly1305 + blake3 (must
  be gated out in FIPS mode), DRBG (needs SP 800-90A), §7.7 power-on self-tests
  (not yet implemented). A `fips` Cargo feature is planned. Full gap analysis:
  [`docs/compliance/fips-readiness.md`](docs/compliance/fips-readiness.md).
  CAVP-style known-answer tests always-on in
  [`core/tests/cavp.rs`](core/tests/cavp.rs).
- **Common Criteria: SFR mapping documented**, against NIAP **PP-Module VPN
  Client v2.5** layered on **PP App SW v1.4**, with per-SFR file:line evidence
  and gap table G-1…G-13. Not yet lab-evaluated. See
  [`docs/compliance/cc-pp-mapping.md`](docs/compliance/cc-pp-mapping.md).

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

- **Pre-1.0 (`0.2.0`).** Wire format may break between minors; SemVer applies
  once 1.0 ships. The three migration guides for prior wire bumps are in
  [`docs/migration/`](docs/migration/).
- **261 / 261 tests passing** (220 unit + 24 negative-security + 5 proptest +
  3 fuzz + 1 alkahest + 1 runtime-integration + 5 CAVP). Plus 5
  `#[ignore]`-gated loopback integration tests. 0 workspace warnings,
  0 clippy warnings.
- **All 8 production-readiness phases (0–7) closed code-side.** Deferred with
  rationale: external CMVP / CC lab validation (Phase 5.7 — procurement, not
  code), ProVerif / Tamarin formal verification (Phase 6.10 — separate research
  engagement), `wasm32-wasi` (pending a `WasiLeg` + `WasiRuntime`).
- **`PhantomListener::bind()` generates a fresh signing key per process** —
  identities don't survive restart. Pin-stable production deployments must use
  `bind_with_signing_key()` with a key loaded from disk (`phantom-cli keygen`
  writes 0600 seed files).
- **The library ships no HTTP server.** `/metrics` HTTP scraping is the
  embedder's responsibility; `server/src/metrics_http.rs` is the reference
  implementation.
- **OpenTelemetry export** is a follow-up; only Prometheus text exposition
  ships in-library today.
- **MSRV: Rust 1.75.** `cli/` uses edition 2024 and builds on stable but not
  on the 1.75 gate.
- **4 of 5 fuzz harnesses** still need nightly; `fuzz_embedded_framing` builds
  on stable.

## Documentation

- **Architecture:** [`docs/architecture/ARCHITECTURE.md`](docs/architecture/ARCHITECTURE.md);
  contributor workflow in [CONTRIBUTING.md](CONTRIBUTING.md)
- **Wire protocol:** [`docs/protocol/PROTOCOL.md`](docs/protocol/PROTOCOL.md)
  (V3 0-RTT in §12)
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
- **Policy:** [`docs/policy/versioning.md`](docs/policy/versioning.md),
  [`docs/migration/`](docs/migration/) (`v1-to-v2.md`, `v2-to-v3.md`)
- **Roadmap:** [`docs/PROGRESS.md`](docs/PROGRESS.md),
  [`docs/PRODUCTION_READINESS.md`](docs/PRODUCTION_READINESS.md)
- **Performance:** [`BENCHMARKS.md`](BENCHMARKS.md)
- **Change log:** [`CHANGELOG.md`](CHANGELOG.md)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). PRs must pass `cargo fmt --check`,
`cargo clippy --lib -- -D warnings`, `cargo test --lib`, and `cargo deny check`.
The `cli-compat` CI job requires that `core` API edits keep
`cli/` building.

## Acknowledgements

Developed with AI assistance from Anthropic's **Claude Opus 4.6** via
[Claude Code](https://claude.com/claude-code). All architectural decisions,
security invariants, threat model, and FIPS / CC compliance artifacts are
authored, reviewed, tested, and maintained by the human author.


## License

Apache License 2.0. See [`LICENSE`](LICENSE).
