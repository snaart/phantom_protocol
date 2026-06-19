# Self-Tests

FIPS 140-3 requires a cryptographic module to run **known-answer tests
(KATs)** at startup ("power-on self-tests" / POST) and **pairwise
consistency tests (PCTs)** whenever a new key pair is generated.

This document describes the self-test implementation for Phantom Protocol. **Power-on self-tests (POST) are shipped** in `core/src/crypto/self_tests.rs` and are auto-invoked from `PhantomListener::bind*` / `PhantomSession::connect*` / `connect_pinned*` under the `fips` feature via the cached `ensure_post_passed()` wrapper. The POST battery is pairwise-consistency-based for the asymmetric primitives (hybrid KEM encap/decap, hybrid sign/verify) plus AEAD round-trips and a fixed HKDF-SHA-256 KAT. Per-keygen pairwise consistency tests (PCTs) wired into every keygen function are not yet shipped.

## Test types

| Type | When | What it proves |
| --- | --- | --- |
| **POST** | At module initialization (first `PhantomListener::bind` / `PhantomSession::connect`). | Each primitive implementation matches its standardized test vectors — i.e. the code path is bug-free for at least the published KAT inputs. |
| **PCT** | After every key-pair generation (`HybridSigningKey::generate`, `HybridKemSecret::generate`). | The newly generated key pair satisfies the algorithm's correctness property (e.g., `verify(sign(m, sk), pk, m) == OK`). Detects RAM corruption or fault injection during keygen. |
| **CST** (continuous self-test) | On every cryptographic operation, on hot paths where allowed. | Entropy source has not regressed; cipher implementation continues to produce expected output for sentinel inputs. **Most CSTs are platform-provided** by `aws-lc-rs` / `ring`. |
| **On-demand** | API: `crypto::self_tests::run_post()` (re-runs the full battery) or `ensure_post_passed()` (cached single-shot). | Operator can run the POST explicitly; the `fips` bootstrap calls `ensure_post_passed()` automatically. |

## POST (shipped)

### Primitives requiring KATs

| Primitive | Vector source | Implementation today |
| --- | --- | --- |
| **AES-256-GCM** | NIST GCMVS (SP 800-38D). | `ring` (default build) / `aws-lc-rs` (under `--features fips`, ring-free). POST is **explicit**: `run_post` exercises an AES-256-GCM round-trip via `CryptoSession`, gated into bind/connect by `ensure_post_passed()`. |
| **ChaCha20-Poly1305** | RFC 8439 test vectors. | `ring`. Not FIPS-approved — rejected with `CoreError::CipherSuiteUnavailable` in `--features fips`; only exercised by POST on non-fips builds. |
| **SHA-256 / HKDF-SHA-256** | NIST SHAVS + RFC 5869 vectors. | `ring` / `hkdf` crate. |
| **BLAKE3** | BLAKE3 official KAT. | `blake3` crate. Not FIPS-approved — disabled in `--features fips`. |
| **Ed25519** | RFC 8032 test vectors §7.1. | `ed25519-dalek`. FIPS 186-5 approves Ed25519. |
| **X25519** | RFC 7748 §6.1 test vectors. | `x25519-dalek`. Not directly FIPS-approved as a KEM — must be replaced or supplemented in `--features fips`. |
| **ML-KEM-768** | FIPS 203 published KATs (NIST PQC round 4). | `ml-kem` crate (RustCrypto). |
| **ML-DSA-65** | FIPS 204 published KATs. | `ml-dsa` crate (RustCrypto). |
| **HMAC-SHA-256** | RFC 4231 + SP 800-198. | `hmac` crate. |

### Shipped implementation

The `core/src/crypto/self_tests.rs` module exposes:

```rust
pub fn run_post() -> Result<(), SelfTestError>;
pub fn ensure_post_passed() -> Result<(), SelfTestError>;

pub enum SelfTestError {
    /// AEAD round-trip failed. `algorithm` is "AES-256-GCM" / "ChaCha20-Poly1305".
    Aead { algorithm: &'static str, stage: AeadStage },
    /// HKDF-SHA-256 produced output that did not match the bundled KAT.
    Hkdf,
    /// Hybrid KEM (X25519/P-256 + ML-KEM-768) round-trip failed.
    HybridKem { stage: KemStage },
    /// Hybrid signature (Ed25519 + ML-DSA-65) round-trip failed.
    HybridSign { stage: SignStage },
    /// Verification accepted a deliberately-tampered signature.
    NegativeVerify,
}
```

`AeadStage` (`Init` / `Encrypt` / `Decrypt` / `Mismatch`), `KemStage`
(`Generate` / `Encapsulate` / `Decapsulate` / `Mismatch`), and `SignStage`
(`Generate` / `Verify`) carry the per-primitive failure context.

Wired into:

- `PhantomListener::bind*` (under `--features fips`) — runs POST via
  `ensure_post_passed()` and returns `CoreError::FipsSelfTestFailure(String)`
  on failure before any cryptographic work.
- `PhantomSession::connect*` / `connect_pinned*` (under `--features fips`).
- `crypto::self_tests::run_post()` — runs the full battery on demand;
  `ensure_post_passed()` is the cached single-shot wrapper.

A `std::sync::OnceLock` (`POST_RESULT`) caches the verdict so POST runs
exactly once per process.

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
| Phase 5.5 | ✅ | `core/src/crypto/self_tests.rs` + `run_post()` / `ensure_post_passed()` API. Shipped and wired into `PhantomListener::bind*` / `PhantomSession::connect*` / `connect_pinned*` under the `fips` feature; failure → `CoreError::FipsSelfTestFailure`. |
| Phase 5.5 | ✅ | CI `fips-feature` job runs `cargo test --no-default-features --features fips,bindings,compression-zstd --lib` (which includes the `self_tests` module tests and the `set_force_post_fail` fault-injection seam) on every PR. |
| Phase 5.5 | ⏳ | Per-keygen PCTs wired into all four keygen functions (the POST already covers KEM/sign pairwise consistency once at startup). |

## Failure-handling policy

FIPS 140-3 requires that on POST or CST failure:

1. The module enters an **error state** and inhibits all crypto API
   calls.
2. The error is logged with sufficient detail to identify the failed
   primitive.
3. Recovery requires either a process restart or an explicit on-demand
   re-run that succeeds.

Mapping to Phantom Protocol:

- POST failure → `PhantomListener::bind*` / `PhantomSession::connect*` /
  `connect_pinned*` (under `--features fips`) return
  `CoreError::FipsSelfTestFailure(String)`. The `String` carries the
  `Debug` rendering of the underlying `SelfTestError` so the variant stays
  UniFFI-exportable.
- CST failure → propagate as `CoreError::Crypto(CryptoError::...)`,
  caller can recreate the listener/session for retry.
- The `OnceLock`-cached verdict means a failed POST short-circuits every
  subsequent bind/connect in the process. A dedicated global "error state"
  latch that inhibits *all* crypto API calls (not just bootstrap) remains a
  future hardening item.

## See also

- `docs/compliance/fips-readiness.md` — overall FIPS 140-3 gap analysis.
- `docs/compliance/key-management.md` — key lifecycle that PCTs
  validate.
- `docs/compliance/rng-audit.md` — entropy source whose health CSTs
  monitor.
