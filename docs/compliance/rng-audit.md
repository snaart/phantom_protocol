# RNG / DRBG Audit

This document inventories every random-bytes source in `core/src/` and maps
each to its concrete OS / platform backend. The audit's purpose is twofold:

1. Confirm that every cryptographic byte (key material, nonce, challenge,
   cookie salt, session ID) originates from a CSPRNG.
2. Document the FIPS 140-3 build's SP 800-90A-validated DRBG. The
   `--features fips` build's DRBG swap (`aws_lc_rs::rand::SystemRandom`)
   is **shipped**, and the old `thread_rng()` entropy fallbacks were
   removed outright on every build — see the "FIPS-mode RNG" section
   below.

## Backends per target

| Target | Primary syscall | Failure mode | Notes |
| --- | --- | --- | --- |
| `x86_64-unknown-linux-gnu` | `getrandom(2)` syscall (Linux ≥ 3.17). On older kernels falls back to `/dev/urandom`. | Returns `EAGAIN` if entropy pool not initialized very early in boot. | `getrandom`'s `linux_disable_fallback` is unset — fallback path remains for legacy environments. |
| `aarch64-unknown-linux-gnu` / `-musl` | Same as above. | Same. | |
| `x86_64-apple-darwin` / `aarch64-apple-darwin` | `getentropy(2)` (BSD-style). | Returns `EIO` only on syscall misuse, never for entropy starvation. | macOS guarantees a seeded CSPRNG before user space starts. |
| `aarch64-apple-ios` / `-ios-sim` | `SecRandomCopyBytes` via `getentropy(2)` shim. | Same. | |
| `x86_64-pc-windows-msvc` / `aarch64-pc-windows-msvc` | `BCryptGenRandom(BCRYPT_USE_SYSTEM_PREFERRED_RNG)` via getrandom. | Cannot fail under normal operation. | CNG's system DRBG is SP 800-90A AES-CTR. |
| `wasm32-unknown-unknown` (browser) | `crypto.getRandomValues` via `getrandom` **0.4**'s `wasm_js` backend (declared in the wasm-only Cargo block). The separate `js`-featured `getrandom02` alias (0.2) serves `ring` / the rand_core-0.6 ecosystem, not `crypto::rng::OsRng`. | Throws `QuotaExceededError` only for unreasonable lengths (`> 65536` per call). Phantom Protocol calls request `≤ 32` bytes per primitive — never hit. | Browser-provided CSPRNG (typically based on the platform PRNG). |
| `wasm32-wasip2` | WASI Preview 2 `wasi:random/random.get-random-bytes` (via the `wasi = 0.14` bindings). | Host-guaranteed; no in-guest failure path. | Host-provided entropy; the guest builds `std,wasi-leg` without `bindings`. |
| `thumbv7em-none-eabihf` (Cortex-M, embedded) | **OE-supplied** — the shipped `RngProvider` trait (`crypto/rng.rs`, Phase 3.8) is the seam; a downstream HAL plugs in a hardware TRNG driver or an externally-seeded software DRBG. | OE responsibility. | See "Embedded path" below. |

## RNG call sites

Sites that pull cryptographic entropy:

| Site (file:line) | Bytes | Purpose | Backend used |
| --- | --- | --- | --- |
| `crypto/hybrid_kem.rs:108` | 32 (classical secret seed) | KEM keygen; ML-KEM-768 draws internally via ml-kem's `getrandom` feature | `crate::crypto::rng::OsRng` |
| `crypto/hybrid_kem.rs:271` | 32 (ephemeral encap seed) | KEM encapsulate (classical half) | `crate::crypto::rng::OsRng` |
| `crypto/hybrid_sign.rs:76` | 32 (Ed25519 seed) | Long-lived signing key | injected `RngProvider` (default `OsRng`) |
| `crypto/hybrid_sign.rs:86` | 32 (ML-DSA-65 seed) | Long-lived signing key | injected `RngProvider` (default `OsRng`) |
| `transport/types.rs:29` | 32 bytes | Session ID | `crate::crypto::rng::OsRng` (panics on CSPRNG failure) |
| `transport/handshake.rs:651` | 32 bytes | Server master secret (HMAC base for cookie + PoW bucket secrets) | `getrandom::fill`, propagates error |
| `transport/handshake.rs:981` | 32 bytes | Server handshake nonce | `getrandom::fill`, propagates error |
| `transport/handshake.rs:1236` | 32 bytes | Client handshake nonce | `getrandom::fill`, propagates error |
| `transport/path.rs:256` | 32 bytes | Path-validation challenge | `crate::crypto::rng::OsRng` |
| `api/udp_transport.rs:148` | 8 bytes | Initial PhantomUDP `ConnId` | `getrandom::fill`, propagates error |

`rand` is **not** a production dependency — it is dev-only
(`core/Cargo.toml :: [dev-dependencies]`).

Sites that pull **non-cryptographic** entropy (handle/jitter/test only):

| Site | Purpose | Note |
| --- | --- | --- |
| `api/session.rs:56` | 16-byte display handle for a session | Non-secret identifier; still drawn from the `OsRng` seam |
| `transport/shaping.rs:137` | Traffic-shaping timing jitter | Non-cryptographic; drawn from the `OsRng` seam |
| `test_harness/mod.rs:142` | Latency jitter sample | Test-only |
| `test_harness/mod.rs:179` | Simulated loss decision | Test-only |

## Fallback chain semantics

**There are no fallback chains.** Earlier revisions of this crate used a
`getrandom` → `rand::thread_rng()` entropy-downgrade fallback; it was
removed when the `RngProvider` seam landed. `rand` is no longer a
production dependency at all (dev-only). Production sites either propagate
the `getrandom` error as a `Result` or route through
`crate::crypto::rng::OsRng`, whose documented failure model is **panic on a
broken CSPRNG** — a loud fail is preferred over silently biased keys.
This already satisfies the FIPS prohibition on entropy-quality fallbacks;
no `#[cfg(not(feature = "fips"))]` gating is involved.

## Failure-mode policy

Sites that **propagate** RNG errors as `Result`:
- `handshake.rs:651` — server-side master-secret derivation, fatal at
  `HandshakeServer` construction.
- `handshake.rs:981` — server handshake nonce, fatal for that handshake.
- `handshake.rs:1236` — client-side nonce, fatal at handshake start.
- `api/udp_transport.rs:148` — initial PhantomUDP `ConnId`, fatal at
  client transport construction.

Sites that route through the `RngProvider` seam
(`crate::crypto::rng::OsRng`, panic-on-CSPRNG-failure — no entropy
fallback on any build):
- `transport/types.rs` (session ID).
- `transport/legs/mimic_tls/` (TLS-Hello random — takes an injected
  `&impl RngProvider`).
- `transport/path.rs` (path challenge).
- `crypto/hybrid_kem.rs` / `crypto/hybrid_sign.rs` (key seeds).

Because the seam has no fallback branch at all, the FIPS prohibition on
entropy-downgrade chains is satisfied structurally rather than by `#[cfg]`
gating.

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

3. **No entropy fallbacks at all.** The `thread_rng()` fallbacks were
   removed outright (not cfg-gated) when the `RngProvider` seam landed, and
   `rand` is no longer a production dependency — so there is nothing for
   the fips build to compile out.

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
2. ✅ `thread_rng` fallbacks are gone from production code on **every**
   build — they were deleted with the `RngProvider` seam, and `rand` is now
   a dev-dependency only.
3. ⏳ A CI smoke test that grep-checks for `rand::thread_rng` /
   `rand::random` outside of `test_harness/` is not yet wired.

## References

- NIST SP 800-90A Rev. 1 — Recommendation for Random Number Generation
  Using Deterministic Random Bit Generators.
- NIST SP 800-90B — Recommendation for the Entropy Sources Used for
  Random Bit Generation.
- `getrandom` crate documentation — https://docs.rs/getrandom
- `aws-lc-rs` FIPS mode — https://github.com/aws/aws-lc-rs
