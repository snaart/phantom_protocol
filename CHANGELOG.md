# Changelog

All notable changes to this project will be documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
once it reaches 1.0.0. Pre-1.0 releases may have breaking changes between minors.

## [Unreleased]

This release pulls phantom_core from its 0.2.0 pre-1.0 baseline through
the foundation and security-hardening phases of the production-readiness
roadmap (`docs/PRODUCTION_READINESS.md`). Test count grew from 122 to
132; the new ten cover the documented security invariants directly.

### Added
- FFI 0-RTT resumption: new `ResumptionHint` UniFFI record and the
  native `connect_pinned_with_resumption` free function expose 0-RTT
  session resumption to FFI / mobile consumers.
  `PhantomSession::resumption_hint()` now returns `Option<ResumptionHint>`
  and is on the UniFFI surface — it was previously a Rust-only
  `Option<([u8; 32], [u8; 32])>` tuple defined outside the export block.
- Governance: `LICENSE` (Apache-2.0), `README.md`, `CHANGELOG.md`,
  `SECURITY.md`, `CONTRIBUTING.md`.
- Toolchain: `rust-toolchain.toml` (stable), `.rustfmt.toml`, `.clippy.toml`.
- Supply-chain: `deny.toml` for `cargo-deny`.
- CI: `.github/workflows/ci.yml` (fmt, clippy, test, doc, deny, audit,
  cli-compat).
- `subtle = "2.5"` dependency for constant-time secret comparisons.
- Phase 6.8: `core/tests/security_invariants.rs` — ten non-`#[ignore]`
  tests pinning the documented invariants (AEAD authenticity, AAD
  binding, wire-format robustness, constant-time cookie, server-identity
  pinning, AEAD-counter exposure, cookie-tamper retry, signing-keypair
  non-determinism, encrypted round-trip, V1 wire-format roundtrip).
- Phase 6.4: `fuzz/` scaffolding with four cargo-fuzz / libfuzzer-sys
  targets (`fuzz_client_hello`, `fuzz_server_hello`, `fuzz_packet_parse`,
  `fuzz_aead_decrypt`) plus a `fuzz/README.md` documenting local and
  OSS-Fuzz workflows.
- Phase 1.7: `CryptoSession::send_invocations()` / `recv_invocations()`
  observability accessors. `AEAD_MAX_INVOCATIONS = 1 << 48` ceiling
  with `CryptoError::NonceExhausted` failure mode.
- Phase 0 / 7: `docs/PRODUCTION_READINESS.md` — full eight-phase
  roadmap with file:line traceability.

### Changed
- Moved `[profile.release]` from `core/Cargo.toml` (silently ignored —
  workspace warning) to the workspace root. `opt-level = "s"` (size) →
  `opt-level = 3` (speed); kept `lto = "fat"`, `codegen-units = 1`,
  `panic = "abort"`. Added `[profile.release-size]` and `[profile.bench]`
  variants.
- Pinned `zstd` from `git master` to `"0.13"`, removing the unstable
  supply-chain dependency.
- `workspace.exclude` now lists `cli`, `tests`, `fuzz` (sibling crates,
  intentionally outside the workspace).
- Phase 2.2: `PhantomSession`'s recv channel carries `Bytes` instead of
  `Vec<u8>`, eliminating the per-packet plaintext clone in the recv
  hot path. The public `recv()` still returns `Vec<u8>` (single
  `Bytes::to_vec` at the FFI boundary).

### Security
- Phase 1.1: cookie comparison in `process_client_hello` now uses
  `subtle::ConstantTimeEq` instead of `==`, closing a timing-leak
  brute-force vector (`core/src/transport/handshake.rs`).
- Phase 1.2: `CryptoState.session_key`, `Session.resumption_secret`,
  `HandshakeServer.pow_secret`, and `HandshakeClient.nonce` now zero on
  drop via `zeroize::ZeroizeOnDrop` / manual `Drop`. `Session::set_resumption_secret`
  zeroes the previous value before overwriting.
- Phase 1.3: removed every `.unwrap()` / `unreachable!()` from
  production hot paths. `compute_transcript_hash`,
  `HandshakeClient::new`, `generate_cookie`, `FakeTlsLeg::new` /
  `with_config`, and `derive_outer_keys` all return typed `Result`s
  now. New `HandshakeError` variants: `SerializationError`,
  `ClockBackwards`, `InternalError`.
- Phase 1.6: API-layer session IDs widened from 32-bit
  `rand::random::<u32>()` to 128-bit `rand::random::<[u8; 16]>()`
  (hex-encoded), removing birthday-collision and entropy concerns.
- Phase 1.7: AEAD nonce-exhaustion guard — both encrypt and decrypt
  paths fail with `CryptoError::NonceExhausted` if the per-direction
  counter reaches `1 << 48`.
- Phase 1.12: documented the phantom-limb `_ephemeral_kem_secret` and
  the reserved `HandshakeClient::take_early_data` hook (both pending
  Phase 4.1 0-RTT work).
- Phase 1.13: `#![deny(unsafe_code)]` at the crate root; only
  `core/src/crypto/keys.rs` and `core/src/transport/udp_transport.rs`
  opt back in, each `unsafe` block now carrying a `// SAFETY:` comment.
- Audit-friendly lints: `#![warn(clippy::unwrap_used, expect_used,
  panic, unreachable, todo, unimplemented, missing_safety_doc)]` in
  lib root. Surfaces remaining sites as TODOs without breaking CI.

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
