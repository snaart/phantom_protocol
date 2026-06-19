# phantom-protocol

[![crates.io](https://img.shields.io/crates/v/phantom-protocol.svg)](https://crates.io/crates/phantom-protocol)
[![docs.rs](https://img.shields.io/docsrs/phantom-protocol)](https://docs.rs/phantom-protocol)
[![license](https://img.shields.io/crates/l/phantom-protocol.svg)](https://github.com/snaart/phantom_protocol/blob/main/LICENSE)
![MSRV](https://img.shields.io/badge/MSRV-1.93-blue)

Post-quantum-secure **L4/L6 universal transport framework** in Rust.

`phantom-protocol` gives applications an authenticated, confidential,
post-quantum-secure byte pipe. It pairs a hybrid classical-plus-PQ handshake
(X25519 + ML-KEM-768 KEM, Ed25519 + ML-DSA-65 signatures — FIPS 203 / FIPS 204,
pure Rust) with a transport layer: TCP / WebSocket sessions and a native
reliable-UDP transport (PhantomUDP), plus WASI and embedded byte-stream framing
legs, and an optional TLS-mimicry transport (`mimicry` feature — `MimicTlsLeg`).
The earlier experimental KCP / FakeTLS legs and the unused `TransportLeg`
multipath trait were removed. Cross-language bindings via UniFFI (Python, Swift,
Kotlin, C); native `wasm32` target; bare-metal `EmbeddedLeg` for `no_std`.

> **Pre-1.0 (`0.1.x`).** Wire format may break between minor versions; SemVer
> stabilizes at 1.0. The Rust crate is `phantom-protocol`; the import path is
> `phantom_protocol`.

## Install

```toml
[dependencies]
phantom-protocol = "0.1"
```

or `cargo add phantom-protocol`.

## Highlights

- **Hybrid post-quantum handshake** — X25519 + ML-KEM-768 KEM, Ed25519 +
  ML-DSA-65 signatures; both halves must verify. Pure-Rust RustCrypto
  primitives (no C in the crypto path) — compiles on native, mobile, and
  `wasm32`.
- **0-RTT resumption** — AEAD-sealed early-data (≤ 16 KiB) folded into the
  single `ClientHello`, one-shot anti-replay, best-effort 1-RTT fallback.
- **Mid-session rekey** — HKDF ratchet with a per-stream sequence watermark that
  forces a rekey before any AEAD nonce can repeat.
- **Per-stream replay protection** — RFC 4303 §3.4.3 sliding-window bitmap,
  checked *after* AEAD verify.
- **DoS-resistant handshake** — stateless HMAC-SHA-256 cookie + adaptive
  blake3 proof-of-work.
- **Observability** — opt-in OpenTelemetry metrics + traces (`telemetry-otel`),
  lock-free hot-path atomics.
- **FIPS posture** — opt-in `fips` feature swaps in an AWS-LC-FIPS substrate
  (ECDH-P-256, AES-256-GCM, HKDF-SHA256, CTR_DRBG) with power-on self-tests.

## Minimal client / server

Server identity must be pinned — `connect_with_transport` requires a
`HybridVerifyingKey`; there is no skip path (a core security invariant).

```rust
use phantom_protocol::api::{PhantomListener, PhantomSession, TcpSessionTransport};
use phantom_protocol::crypto::hybrid_sign::HybridVerifyingKey;
use tokio::net::TcpStream;

// (inside an async context — every call below is `.await?`)

// ── Server ──────────────────────────────────────────────────────────────
let listener    = PhantomListener::bind("127.0.0.1:0".to_string()).await?;
let server_addr = listener.local_addr();
let pinned_key  = listener.verifying_key_bytes();   // share out-of-band

tokio::spawn(async move {
    let outcome = listener.accept().await?;
    let session = outcome.session();
    let _req = session.recv().await?;
    session.send(b"hello, post-quantum world".to_vec()).await?;
    Ok::<_, phantom_protocol::CoreError>(())
});

// ── Client ──────────────────────────────────────────────────────────────
let stream    = TcpStream::connect(&server_addr).await?;
let transport = TcpSessionTransport::new(stream);
let key       = HybridVerifyingKey::from_bytes(&pinned_key)?;
let session   = PhantomSession::connect_with_transport(&server_addr, transport, key);
session.send(b"ping".to_vec()).await?;
let _reply = session.recv().await?;
```

## Feature flags

| Feature | Default | Purpose |
| --- | --- | --- |
| `std` | ✅ | Standard "everything on" build (tokio, native transports). |
| `bindings` | ✅ | UniFFI scaffolding (Python / Swift / Kotlin / C). |
| `compression-zstd` | ✅ | zstd compression (lz4 is the always-on pure-Rust fallback). |
| `telemetry-otel` | — | OpenTelemetry metrics + traces pipeline. |
| `fips` | — | FIPS-140-3 substrate via AWS-LC-FIPS (native-only). |
| `embedded` | — | `EmbeddedLeg` over `embedded-io-async` (no_std + alloc). |
| `wasi-leg` | — | `WasiLeg` + `WasiRuntime` for `wasm32-wasip2`. |
| `no-std` | — | Bare-metal subset marker (pair with `--no-default-features`). |

Bare-metal: `--no-default-features --features embedded,no-std`.
WASI: `--no-default-features --features std,wasi-leg`.

## Links

- **Repository & full docs:** <https://github.com/snaart/phantom_protocol>
- **API docs:** <https://docs.rs/phantom-protocol>
- **Changelog:** [CHANGELOG.md](https://github.com/snaart/phantom_protocol/blob/main/CHANGELOG.md)
- **Protocol spec:** [`docs/protocol/PROTOCOL.md`](https://github.com/snaart/phantom_protocol/blob/main/docs/protocol/PROTOCOL.md)

## License

Licensed under the [Apache License, Version 2.0](https://github.com/snaart/phantom_protocol/blob/main/LICENSE).
