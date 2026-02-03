# Changelog

All notable changes to this project will be documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
once it reaches 1.0.0. Pre-1.0 releases may have breaking changes between minors.

## [Unreleased]

### Added
- Workspace governance files: `LICENSE` (Apache-2.0), `README.md`, `CHANGELOG.md`,
  `SECURITY.md`, `CONTRIBUTING.md`.
- Toolchain pinning: `rust-toolchain.toml`, `.rustfmt.toml`, `.clippy.toml`.
- Supply-chain hygiene: `deny.toml` for `cargo-deny`.
- Minimal CI workflow (`.github/workflows/ci.yml`).
- `subtle` dependency for constant-time comparisons.

### Changed
- Moved `[profile.release]` from `core/Cargo.toml` (was being silently ignored —
  workspace warning) to the workspace root and switched `opt-level = "s"` (size)
  to `opt-level = 3` (speed). Release builds now actually apply LTO + single
  codegen unit + speed-optimized codegen.
- Pinned `zstd` from `git master` to a release version, removing unstable
  supply-chain dependency.

### Security
- Cookie comparison in `process_client_hello` now uses
  `subtle::ConstantTimeEq` instead of `==`, eliminating a timing-leak
  brute-force vector (`core/src/transport/handshake.rs`).
- `CryptoState`, `HandshakeServer::pow_secret`, `HandshakeClient::nonce`, and
  `Session::resumption_secret` now zero on drop via `zeroize::Zeroize` / `ZeroizeOnDrop`.
- Removed `.unwrap()` on `getrandom`, `borsh::to_vec`, and `SystemTime`
  conversions in the handshake hot path; they now return proper `HandshakeError`
  / `CoreError` results.
- Session IDs in the public API are now derived from `getrandom` (16 bytes /
  128 bits of entropy) instead of `rand::random::<u32>()` (32 bits, non-CSPRNG).

## [0.2.0]

### Added
- Initial public-facing transport API: `PhantomSession`, `PhantomListener`,
  `PhantomStream`, `PhantomConfig`.
- Hybrid handshake (X25519+Kyber768 KEM, Ed25519+Dilithium3 signatures).
- Multi-leg transport: TCP, KCP-over-UDP, FakeTLS-over-TCP.
- UniFFI scaffolding for cross-language bindings.

### Security
- Three HIGH-severity vulnerabilities from the May 2026 review fixed:
  server identity must be pinned at the API boundary, the negotiated session
  must be used for all post-handshake data, and FakeTLS now uses per-record
  counter nonces with direction-keyed AEAD (preventing the Forbidden Attack on
  AES-GCM and making cross-peer encryption actually work).
