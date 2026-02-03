# Phantom Core

Post-quantum-secure L4/L6 universal transport framework in Rust.

Phantom Core provides a networking SDK with hybrid cryptography (Kyber768 + X25519
KEM, Dilithium3 + Ed25519 signatures), multi-path transport (TCP / KCP-over-UDP /
FakeTLS-over-TCP), and adaptive fallback. Cross-language bindings via UniFFI.

## Status

Pre-1.0. Wire format `VersionedPacket::V1`. Production readiness in progress; see
[`docs/PRODUCTION_READINESS.md`](docs/PRODUCTION_READINESS.md) for the roadmap.

## Workspace layout

- `core/` — the `phantom_core` library (workspace member).
- `cli/` — sibling consumer crate (NOT a workspace member); depends on `phantom_core`
  via path dep. Edits to the `core` API must keep `cli` compiling.
- `tests/` — FFI/integration glue (`run_test.py`, generated `bindings/`).
- Rust integration tests live in `core/tests/`.

## Quick build

```bash
cargo build   --manifest-path core/Cargo.toml
cargo test    --manifest-path core/Cargo.toml --lib
cargo clippy  --manifest-path core/Cargo.toml --lib -- -D warnings
cargo fmt     --manifest-path core/Cargo.toml
```

Loopback integration tests are `#[ignore]`-gated; run with `-- --ignored`.

```bash
cargo test --manifest-path core/Cargo.toml --test tcp_integration -- --ignored
```

## Features

The default feature `pqc-standard` enables `pqcrypto-kyber` / `pqcrypto-dilithium`.
Disabling removes the PQC half of the hybrid primitives — most call sites assume
it is on.

## Cryptography

- **Hybrid KEM**: X25519 + Kyber768 (`HybridSecretKey` / `HybridKeyPackage`).
- **Hybrid Signatures**: Ed25519 + Dilithium3 (`HybridSigningKey` / `HybridVerifyingKey`).
- **AEAD**: AES-256-GCM (HW-accelerated via ring) or ChaCha20-Poly1305 (auto-selected).
- **KDF**: HKDF-SHA-256 for transport keys; blake3 KDF for nonce prefixes and
  FakeTLS obfuscation seeds.

## Transport legs

- **TCP** with length-prefix framing.
- **KCP-over-UDP** for reliability over lossy links.
- **FakeTLS** for anti-DPI obfuscation (the inner Phantom session provides the
  real authenticated confidentiality).

## Security

See [`SECURITY.md`](SECURITY.md) for the threat model, supported primitives, and
the disclosure policy.

The May 2026 review fixed three HIGH-severity vulnerabilities. Future edits MUST
preserve the documented invariants in [`CLAUDE.md`](CLAUDE.md).

## Bindings

Cross-language bindings via UniFFI:

- Python (generated, in `tests/bindings/phantom_core.py`).
- Swift / Kotlin / C — planned (see roadmap).

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md).

## License

Apache License 2.0. See [`LICENSE`](LICENSE).
