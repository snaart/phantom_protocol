# RNG / DRBG Audit

This document inventories every random-bytes source in `core/src/` and maps
each to its concrete OS / platform backend. The audit's purpose is twofold:

1. Confirm that every cryptographic byte (key material, nonce, challenge,
   cookie salt, session ID) originates from a CSPRNG.
2. Identify the changes required for an eventual FIPS 140-3 build, which
   demands an SP 800-90A-validated DRBG.

## Backends per target

| Target | Primary syscall | Failure mode | Notes |
| --- | --- | --- | --- |
| `x86_64-unknown-linux-gnu` | `getrandom(2)` syscall (Linux ≥ 3.17). On older kernels falls back to `/dev/urandom`. | Returns `EAGAIN` if entropy pool not initialized very early in boot. | `getrandom`'s `linux_disable_fallback` is unset — fallback path remains for legacy environments. |
| `aarch64-unknown-linux-gnu` / `-musl` | Same as above. | Same. | |
| `x86_64-apple-darwin` / `aarch64-apple-darwin` | `getentropy(2)` (BSD-style). | Returns `EIO` only on syscall misuse, never for entropy starvation. | macOS guarantees a seeded CSPRNG before user space starts. |
| `aarch64-apple-ios` / `-ios-sim` | `SecRandomCopyBytes` via `getentropy(2)` shim. | Same. | |
| `x86_64-pc-windows-msvc` / `aarch64-pc-windows-msvc` | `BCryptGenRandom(BCRYPT_USE_SYSTEM_PREFERRED_RNG)` via getrandom. | Cannot fail under normal operation. | CNG's system DRBG is SP 800-90A AES-CTR. |
| `wasm32-unknown-unknown` (browser) | `window.crypto.getRandomValues` via `js-sys`. Enabled by the `getrandom = { features = ["js"] }` declaration in the wasm-only Cargo block. | Throws `QuotaExceededError` only for unreasonable lengths (`> 65536` per call). Phantom calls request `≤ 32` bytes per primitive — never hit. | Browser-provided CSPRNG (typically based on the platform PRNG). |
| `wasm32-wasi` | WASI `random_get`. | Cannot fail in WASI snapshot 1. | Host-provided entropy. |
| `thumbv7em-none-eabihf` (Cortex-M, embedded) | **Not currently supported** — Phase 3.4 must select between a hardware TRNG driver or a software DRBG seeded externally. | N/A today. | See "Embedded path" below. |

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
| `transport/legs/faketls.rs:320` | 32 bytes | FakeTLS ClientHello random | `getrandom::getrandom`, falls back to `thread_rng` |
| `transport/legs/faketls.rs:356` | ECDHE keypair | TLS 1.3 ECDHE key share | `OsRng` |
| `transport/legs/faketls.rs:377-386` | 32 + 32 bytes | TLS ServerHello random + session ID | `getrandom::getrandom`, falls back to `thread_rng` |

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

Sites that **fall back to `thread_rng`**:
- `types.rs:27` (session ID).
- `faketls.rs:320,377-386` (TLS Hello random).
- `path.rs:225` (path challenge — see comment in source).

The fallback choice is intentional for non-key material where retrying the
operation is more expensive than accepting a thread-RNG byte; the call sites
are documented in source.

## FIPS-mode requirements (Phase 5)

For `cargo build --features fips` to be defensible:

1. **DRBG.** Replace the OS-direct backend with an SP 800-90A DRBG:
   - **`aws-lc-rs`** offers `aws_lc_rs::rand::SystemRandom`, which on a
     FIPS-validated build is a CTR_DRBG / HMAC_DRBG instantiated from
     `/dev/urandom`. This is the recommended path in this codebase per
     `docs/compliance/fips-readiness.md`.
   - Alternative: `ring`'s system random when built against the FIPS-mode
     BoringSSL fork.

2. **Replace `OsRng` and `getrandom::getrandom` call sites.** Three
   choices, in decreasing intrusiveness:
   - Plumb a `RngCore` parameter through each construction site (most
     invasive, cleanest for testing).
   - Introduce a `crate::crypto::rng::system_rng()` function that returns
     a static `&'static dyn RngCore` selected by feature flag (medium).
   - Hard-cfg-swap `OsRng` for `aws_lc_rs::rand::SystemRandom` behind
     `#[cfg(feature = "fips")]` (least invasive, fragile if APIs diverge).

3. **Remove all `thread_rng()` fallbacks** behind `#[cfg(not(feature
   = "fips"))]`.

4. **Power-on self-test.** Document and implement a startup self-test for
   the DRBG (see `docs/compliance/self-tests.md`).

5. **Continuous health check.** SP 800-90B requires a continuous test on
   the entropy source. `aws-lc-rs` provides this in its FIPS mode; ensure
   the test failure is surfaced as a fatal error.

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

## Recommended near-term actions

1. ⏳ Wrap every RNG call site behind a `crate::crypto::rng` module so the
   FIPS swap (Phase 5.3) is a one-file change.
2. ⏳ Remove `thread_rng` fallbacks behind a feature gate so non-FIPS
   builds still benefit from the fallback (deployability) but FIPS builds
   cannot use it.
3. ⏳ Add a CI smoke test that grep-checks for `rand::thread_rng` or
   `rand::random` outside of `test_harness/` and the documented fallback
   sites.

## References

- NIST SP 800-90A Rev. 1 — Recommendation for Random Number Generation
  Using Deterministic Random Bit Generators.
- NIST SP 800-90B — Recommendation for the Entropy Sources Used for
  Random Bit Generation.
- `getrandom` crate documentation — https://docs.rs/getrandom
- `aws-lc-rs` FIPS mode — https://github.com/aws/aws-lc-rs
