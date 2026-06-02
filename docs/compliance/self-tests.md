# Self-Tests

FIPS 140-3 requires a cryptographic module to run **known-answer tests
(KATs)** at startup ("power-on self-tests" / POST) and **pairwise
consistency tests (PCTs)** whenever a new key pair is generated.

This document describes the self-test implementation for Phantom Core. **Power-on self-tests (POST) are implemented** in `core/src/crypto/self_tests.rs` (Phase 5.5) and are wired into PhantomListener::bind and PhantomSession::connect under the `fips` feature. Pairwise consistency tests (PCTs) are in-progress.

## Test types

| Type | When | What it proves |
| --- | --- | --- |
| **POST** | At module initialization (first `PhantomListener::bind` / `PhantomSession::connect`). | Each primitive implementation matches its standardized test vectors — i.e. the code path is bug-free for at least the published KAT inputs. |
| **PCT** | After every key-pair generation (`HybridSigningKey::generate`, `HybridKemSecret::generate`). | The newly generated key pair satisfies the algorithm's correctness property (e.g., `verify(sign(m, sk), pk, m) == OK`). Detects RAM corruption or fault injection during keygen. |
| **CST** (continuous self-test) | On every cryptographic operation, on hot paths where allowed. | Entropy source has not regressed; cipher implementation continues to produce expected output for sentinel inputs. **Most CSTs are platform-provided** by `aws-lc-rs` / `ring`. |
| **On-demand** | API: `phantom_core::fips::run_self_tests()`. | Operator can re-run POSTs without restarting. |

## POST plan (Phase 5.5)

### Primitives requiring KATs

| Primitive | Vector source | Implementation today |
| --- | --- | --- |
| **AES-256-GCM** | NIST GCMVS (SP 800-38D). | `ring` (audited upstream). FIPS POST runs implicitly when `ring` initializes in FIPS mode. |
| **ChaCha20-Poly1305** | RFC 8439 test vectors. | `ring`. Not FIPS-approved — disabled in `--features fips`. |
| **SHA-256 / HKDF-SHA-256** | NIST SHAVS + RFC 5869 vectors. | `ring` / `hkdf` crate. |
| **BLAKE3** | BLAKE3 official KAT. | `blake3` crate. Not FIPS-approved — disabled in `--features fips`. |
| **Ed25519** | RFC 8032 test vectors §7.1. | `ed25519-dalek`. FIPS 186-5 approves Ed25519. |
| **X25519** | RFC 7748 §6.1 test vectors. | `x25519-dalek`. Not directly FIPS-approved as a KEM — must be replaced or supplemented in `--features fips`. |
| **ML-KEM-768** | FIPS 203 published KATs (NIST PQC round 4). | `ml-kem` crate (RustCrypto). |
| **ML-DSA-65** | FIPS 204 published KATs. | `ml-dsa` crate (RustCrypto). |
| **HMAC-SHA-256** | RFC 4231 + SP 800-198. | `hmac` crate. |

### Proposed implementation

A `core/src/crypto/self_tests.rs` module exposing:

```rust
pub fn run_post() -> Result<(), SelfTestError>;
pub enum SelfTestError {
    AesGcmKat,
    Sha256Kat,
    HkdfKat,
    Ed25519Kat,
    MlKemKat,
    MlDsaKat,
    HmacKat,
}
```

Wired into:

- `PhantomListener::bind` (first call) — runs POST and returns
  `CoreError::SelfTest` on failure.
- `PhantomSession::connect_with_transport` (first call per process).
- `phantom_core::fips::run_self_tests()` — public API for on-demand.

A `std::sync::Once` ensures POST runs exactly once per process.

### Vector storage

KATs land under `tests/cavp/` (Phase 5.4) and are pulled into the build via
`include_bytes!`. Format: NIST-style `.rsp` files for KAT-friendly
primitives; for ML-KEM / ML-DSA, the JSON-format vectors published with
FIPS 203 / 204.

## PCT plan

| Key | Test |
| --- | --- |
| Ed25519 keypair | Sign a fixed 32-byte message with `sk`; verify with `pk`. Both must succeed before `HybridSigningKey::generate` returns. |
| ML-DSA-65 keypair | Same: sign + verify a fixed buffer. |
| X25519 keypair | Compute `dh = X25519(sk, base_point)`. Compare against `pk` for consistency. |
| ML-KEM-768 keypair | `encap(pk)` to produce `(ss, ct)`; `decap(sk, ct)` must yield `ss`. |

Failure → return `CryptoError::PairwiseConsistencyFailed` and zero all key
material immediately. Caller is responsible for re-attempting keygen
(typically once — sustained failures indicate RAM corruption).

## Continuous self-tests

- **AEAD authenticator.** ring's AEAD already rejects on tag mismatch; the
  `decrypt_packet` error propagates. No additional CST needed.
- **RNG continuous health.** `aws-lc-rs::rand::SystemRandom` in FIPS mode
  implements SP 800-90B continuous tests automatically. For the non-FIPS
  build, we rely on the OS CSPRNG's own health policy.

## Test schedule

| Phase | Status | Deliverable |
| --- | --- | --- |
| Phase 5.4 | ✅ | CAVP vectors under `core/tests/cavp/`. (Implemented with ML-KEM-768, ML-DSA-65, AES-256-GCM, SHA-256, HMAC-SHA-256, HKDF-SHA-256, Ed25519 test vectors.) |
| Phase 5.5 | ✅ | `core/src/crypto/self_tests.rs` + `ensure_post_passed()` API. (Implemented and wired into PhantomListener::bind and PhantomSession::connect under `fips` feature.) |
| Phase 5.5 | ⏳ | PCTs wired into all four keygen functions. |
| Phase 5.5 | ⏳ | CI job that runs `cargo test --features fips self_tests` on every PR. |

## Failure-handling policy

FIPS 140-3 requires that on POST or CST failure:

1. The module enters an **error state** and inhibits all crypto API
   calls.
2. The error is logged with sufficient detail to identify the failed
   primitive.
3. Recovery requires either a process restart or an explicit on-demand
   re-run that succeeds.

Mapping to Phantom Core:

- POST failure → `PhantomListener::bind` / `PhantomSession::connect`
  return `CoreError::SelfTest(SelfTestError)`.
- CST failure → propagate as `CoreError::Crypto(CryptoError::...)`,
  caller can recreate the listener/session for retry.
- The current binary does not implement a global "error state" latch —
  this is a Phase 5.5 deliverable. The simplest model is a process-wide
  `AtomicBool` that all crypto entry points check.

## See also

- `docs/compliance/fips-readiness.md` — overall FIPS 140-3 gap analysis.
- `docs/compliance/key-management.md` — key lifecycle that PCTs
  validate.
- `docs/compliance/rng-audit.md` — entropy source whose health CSTs
  monitor.
