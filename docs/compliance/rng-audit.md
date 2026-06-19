# RNG / DRBG Audit

This document inventories every random-bytes source in `core/src/` and maps
each to its concrete OS / platform backend. The audit's purpose is twofold:

1. Confirm that every cryptographic byte (key material, nonce, challenge,
   cookie salt, session ID) originates from a CSPRNG.
2. Document the FIPS 140-3 build's SP 800-90A-validated DRBG. The
   `--features fips` build's DRBG swap (`aws_lc_rs::rand::SystemRandom`)
   and the `thread_rng()` fallback gating are **shipped** — see the
   "FIPS-mode requirements" section below.

## Backends per target

| Target | Primary syscall | Failure mode | Notes |
| --- | --- | --- | --- |
| `x86_64-unknown-linux-gnu` | `getrandom(2)` syscall (Linux ≥ 3.17). On older kernels falls back to `/dev/urandom`. | Returns `EAGAIN` if entropy pool not initialized very early in boot. | `getrandom`'s `linux_disable_fallback` is unset — fallback path remains for legacy environments. |
| `aarch64-unknown-linux-gnu` / `-musl` | Same as above. | Same. | |
| `x86_64-apple-darwin` / `aarch64-apple-darwin` | `getentropy(2)` (BSD-style). | Returns `EIO` only on syscall misuse, never for entropy starvation. | macOS guarantees a seeded CSPRNG before user space starts. |
| `aarch64-apple-ios` / `-ios-sim` | `SecRandomCopyBytes` via `getentropy(2)` shim. | Same. | |
| `x86_64-pc-windows-msvc` / `aarch64-pc-windows-msvc` | `BCryptGenRandom(BCRYPT_USE_SYSTEM_PREFERRED_RNG)` via getrandom. | Cannot fail under normal operation. | CNG's system DRBG is SP 800-90A AES-CTR. |
| `wasm32-unknown-unknown` (browser) | `window.crypto.getRandomValues` via `js-sys`. Enabled by the `getrandom = { features = ["js"] }` declaration in the wasm-only Cargo block. | Throws `QuotaExceededError` only for unreasonable lengths (`> 65536` per call). Phantom Protocol calls request `≤ 32` bytes per primitive — never hit. | Browser-provided CSPRNG (typically based on the platform PRNG). |
| `wasm32-wasi` | WASI `random_get`. | Cannot fail in WASI snapshot 1. | Host-provided entropy. |
| `thumbv7em-none-eabihf` (Cortex-M, embedded) | **OE-supplied** — the shipped `RngProvider` trait (`crypto/rng.rs`, Phase 3.8) is the seam; a downstream HAL plugs in a hardware TRNG driver or an externally-seeded software DRBG. | OE responsibility. | See "Embedded path" below. |

## RNG call sites

Sites that pull cryptographic entropy:

| Site (file:line) | Bytes | Purpose | Backend used |
| --- | --- | --- | --- |
| `crypto/hybrid_kem.rs:47` | 32 (ephemeral X25519 sk) + ML-KEM-768 internal entropy | KEM keygen | `OsRng` (rand::rngs::OsRng) → wraps `getrandom` |
| `crypto/hybrid_kem.rs:123` | encapsulation randomness | KEM encapsulate | `OsRng` |
| `crypto/hybrid_sign.rs:52` | Ed25519 keypair | Long-lived signing key | `OsRng` |
| `crypto/hybrid_sign.rs:58` (delegated) | ML-DSA-65 keypair | Long-lived signing key | `OsRng` (RustCrypto pulls via `rand_core::CryptoRng`) |
| `transport/types.rs:27` | 32 bytes | Session ID | `getrandom::getrandom`, falls back to `rand::thread_rng()` |
| `transport/handshake.rs:144` | 32 bytes | Server master secret (HMAC base for cookie + PoW bucket secrets) | `getrandom::getrandom`, propagates error |
| `transport/handshake.rs:437` | 32 bytes | Client handshake nonce | `getrandom::getrandom`, propagates error |
| `transport/path.rs:225` | 32 bytes | Multi-path validation challenge | `rand::random` (thread CSPRNG) — `getrandom`-failure fallback documented inline |

Sites that pull **non-cryptographic** entropy (test/jitter only):

| Site | Purpose | Note |
| --- | --- | --- |
| `test_harness/mod.rs:131` | Simulated loss decision | Test-only |

## Fallback chain semantics

Several sites use this pattern:

```rust
if getrandom::getrandom(&mut bytes).is_err() {
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut bytes);
}
```

`thread_rng()` returns a `ThreadRng` seeded from `OsRng` at thread startup
and reseeded periodically. The fallback exists because `getrandom` can fail
with `EAGAIN` in early boot before the kernel's CSPRNG is seeded. On any
practical deployment (user-space processes after `init`), the primary call
succeeds and the fallback is dead code.

For a FIPS build this fallback **must be removed** — FIPS forbids
fallback chains that drop entropy quality. Mitigation: gate it behind
`#[cfg(not(feature = "fips"))]` when the `fips` feature is introduced.

## Failure-mode policy

Sites that **propagate** RNG errors as `Result`:
- `handshake.rs:144` — server-side master-secret derivation, fatal at
  listener bind.
- `handshake.rs:437` — client-side nonce, fatal at handshake start.

Sites that **fall back to `thread_rng`** (all gated behind
`#[cfg(not(feature = "fips"))]` — the fips build cannot use them):
- `transport/types.rs` (session ID).
- `transport/legs/mimic_tls/` (TLS-Hello random — the fallback moved here
  when the old FakeTLS leg was replaced by the shipped `MimicTlsLeg`).
- `transport/path.rs` (path challenge — see comment in source).

The fallback choice is intentional for non-key material where retrying the
operation is more expensive than accepting a thread-RNG byte; the call sites
are documented in source. Under `--features fips` the fallbacks are compiled
out entirely.

## FIPS-mode RNG (shipped under `--features fips`)

The `--features fips` build's RNG posture is **shipped**:

1. **DRBG.** The OS-direct backend is replaced by an SP 800-90A DRBG:
   `crypto::rng::OsRng`'s `RngProvider` impl is cfg-split — `getrandom` on
   the default build, `aws_lc_rs::rand::SystemRandom` under `--features
   fips` (CTR_DRBG inside the AWS-LC-FIPS module, SP 800-90A § 10.2.1).
   This is the recommended path in `docs/compliance/fips-readiness.md`.

2. **Single seam for the swap.** The `RngProvider` trait
   (`crypto/rng.rs`, Phase 3.8) is the abstraction seam — production call
   sites route through `OsRng`, so the fips substitution is picked up
   automatically without touching each construction site.

3. **`thread_rng()` fallbacks removed under fips.** All `thread_rng()`
   fallbacks are gated behind `#[cfg(not(feature = "fips"))]`; the fips
   build cannot use them.

4. **Power-on self-test.** The DRBG is exercised transitively by the
   shipped POST (`crypto::self_tests::run_post` — hybrid KEM / sign keygen
   pull from the RNG); see `docs/compliance/self-tests.md`.

5. **Continuous health check.** SP 800-90B requires a continuous test on
   the entropy source. `aws-lc-rs` provides this in its FIPS mode; a test
   failure surfaces as a fatal error.

## Embedded path

`thumbv7em-none-eabihf` and other Cortex-M targets do not have `getrandom`
out of the box. Phase 3.4 (EmbeddedLeg) must select one of:

- **Hardware TRNG.** Most STM32 / nRF / ESP chips ship one; a thin driver
  feeds a chip-specific peripheral into a software DRBG (HMAC-SHA-256 in
  the simplest case).
- **External seed.** For deeply embedded devices without TRNG, seed a
  software DRBG from a per-device factory-programmed secret + a monotonic
  counter. **Not suitable for crypto** without an attached secure element;
  document this as a deliberate limitation.

The trait surface for this should be folded into the existing `Runtime`
trait (Phase 3.1) or a sibling `RngBackend` trait.

## Status of near-term actions

1. ✅ Every RNG call site routes through the `crate::crypto::rng` module
   (`RngProvider` / `OsRng`), so the FIPS swap is a single cfg-split in
   that one file.
2. ✅ `thread_rng` fallbacks are gated behind `#[cfg(not(feature =
   "fips"))]` — non-FIPS builds keep the fallback for deployability; FIPS
   builds compile it out.
3. ⏳ A CI smoke test that grep-checks for `rand::thread_rng` /
   `rand::random` outside of `test_harness/` and the documented fallback
   sites is not yet wired.

## References

- NIST SP 800-90A Rev. 1 — Recommendation for Random Number Generation
  Using Deterministic Random Bit Generators.
- NIST SP 800-90B — Recommendation for the Entropy Sources Used for
  Random Bit Generation.
- `getrandom` crate documentation — https://docs.rs/getrandom
- `aws-lc-rs` FIPS mode — https://github.com/aws/aws-lc-rs
