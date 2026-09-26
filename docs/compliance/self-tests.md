# Self-Tests

FIPS 140-3 requires a cryptographic module to run **known-answer tests
(KATs)** at startup ("power-on self-tests" / POST) and **pairwise
consistency tests (PCTs)** whenever a new key pair is generated.

This document describes the self-test implementation for Phantom Protocol. **Power-on self-tests (POST) are shipped** in `core/src/crypto/self_tests.rs` and are auto-invoked from `PhantomListener::bind*` / `PhantomUdpListener::bind_udp*` / `SessionBuilder::connect` / `connect_pinned*` under the `fips` feature via the cached `ensure_post_passed()` wrapper. The POST battery is pairwise-consistency-based for the asymmetric primitives (hybrid KEM encap/decap, hybrid sign/verify) plus AEAD round-trips and a fixed HKDF-SHA-256 KAT. The signing-key pairwise-consistency test **is shipped**: `HybridSigningKey::pairwise_consistency_check()` runs at every long-term-identity generation site (`HandshakeServer` construction, `api/identity.rs`, `phantom-cli keygen`, `phantom-server`'s load-or-create). It is deliberately not run in `HybridSigningKey::generate()`, which mints the client's ephemeral per-handshake key. The remaining gap is a PCT on the KEM keypair (`HybridSecretKey::generate`), which today is only covered once at startup by the POST.

## Test types

| Type | When | What it proves |
| --- | --- | --- |
| **POST** | At module initialization (first `PhantomListener::bind` / `PhantomSession::connect`). | Each primitive implementation matches its standardized test vectors — i.e. the code path is bug-free for at least the published KAT inputs. |
| **PCT** | After every key-pair generation (`HybridSigningKey::generate`, `HybridSecretKey::generate`). | The newly generated key pair satisfies the algorithm's correctness property (e.g., `verify(sign(m, sk), pk, m) == OK`). Detects RAM corruption or fault injection during keygen. |
| **CST** (continuous self-test) | On every cryptographic operation, on hot paths where allowed. | Entropy source has not regressed; cipher implementation continues to produce expected output for sentinel inputs. **Most CSTs are platform-provided** by `aws-lc-rs` / `ring`. |
| **On-demand** | API: `crypto::self_tests::run_post()` (re-runs the full battery) or `ensure_post_passed()` (cached single-shot). | Operator can run the POST explicitly; the `fips` bootstrap calls `ensure_post_passed()` automatically. |

## POST (shipped)

### Primitives requiring KATs

| Primitive | Vector source | Implementation today |
| --- | --- | --- |
| **AES-256-GCM** | NIST GCMVS (SP 800-38D). | `ring` (default build) / `aws-lc-rs` (under `--features fips`, ring-free). POST is **explicit**: `run_post` exercises an AES-256-GCM round-trip via `CryptoSession`, gated into bind/connect by `ensure_post_passed()`. |
| **ChaCha20-Poly1305** | RFC 8439 test vectors. | `ring`. Not FIPS-approved — rejected with `CoreError::CipherSuiteUnavailable` in `--features fips`; only exercised by POST on non-fips builds. |
| **SHA-256 / HKDF-SHA-256** | NIST SHAVS + RFC 5869 vectors. | `ring` / `hkdf` crate. |
| **BLAKE3** | BLAKE3 official KAT. | `blake3` crate. Not FIPS-approved. Every **KDF** call site routes through `crypto::kdf::derive_key_32`, which swaps to HKDF-SHA-256 under `--features fips`; BLAKE3 remains linked and is still used non-KDF in `crypto/pow.rs` (keyed-BLAKE3 challenge MAC + the unkeyed PoW work function), which is a DoS gate rather than an approved security function. |
| **Ed25519** | RFC 8032 test vectors §7.1. | `ed25519-dalek`. FIPS 186-5 approves Ed25519. |
| **X25519** | RFC 7748 §6.1 test vectors. | `x25519-dalek` (default build only). Not directly FIPS-approved as a KEM — **already replaced** under `--features fips` by ECDH-P-256 via `aws-lc-rs::agreement` (`CLASSICAL_PK_BYTES` 32 → 65); the ring-free fips build does not link `x25519-dalek`. |
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

- `PhantomListener::bind*` and `PhantomUdpListener::bind_udp*` (under
  `--features fips`) — run POST via `ensure_post_passed()` and return
  `CoreError::FipsSelfTestFailure(String)` on failure before any
  cryptographic work.
- `SessionBuilder::connect` / the seven `connect_pinned*` free functions
  (under `--features fips`), plus the shared client background task,
  which stores the failure in the session's `terminal_error` slot
  because it is infallible by signature.
- `crypto::self_tests::run_post()` — runs the full battery on demand;
  `ensure_post_passed()` is the cached single-shot wrapper.

A `std::sync::OnceLock` (`POST_RESULT`) caches the verdict so POST runs
exactly once per process.

### Vector storage

`core/tests/cavp.rs` carries its vectors inline as `const` byte arrays (no
fixture files). The byte-exact external NIST ACVP vectors for the raw
ML-KEM-768 / ML-DSA-65 primitives live in `core/tests/nist_kat/` as four
trimmed `.json` files (`ml_kem_768_keygen.json`,
`ml_kem_768_encap_decap.json`, `ml_dsa_65_keygen.json`,
`ml_dsa_65_siggen.json`) and are read at **runtime** by
`core/tests/nist_kat.rs` via `std::fs::read` + `serde_json` — they are not
`include_bytes!`-ed into the binary.

## PCT plan

| Key | Test |
| --- | --- |
| Ed25519 keypair | Sign a fixed message with `sk`; verify with `pk`. **Shipped** as `HybridSigningKey::pairwise_consistency_check()`, called at every long-term-identity generation site — deliberately *not* inside `HybridSigningKey::generate`, which mints the client's ephemeral per-handshake key. |
| ML-DSA-65 keypair | Same: sign + verify a fixed buffer, in the same shipped hybrid check. |
| X25519 keypair | Compute `dh = X25519(sk, base_point)`. Compare against `pk` for consistency. |
| ML-KEM-768 keypair | `encap(pk)` to produce `(ss, ct)`; `decap(sk, ct)` must yield `ss`. |

Failure → the shipped signing-key check returns `Err(HybridSignError)`
(`HybridSigningKey::pairwise_consistency_check`, `core/src/crypto/hybrid_sign.rs`)
and the generation site refuses the key, which is zeroized when it drops —
for example `HandshakeServer::new` / `HandshakeServer::new_with_cache` fail
construction with `HandshakeError::RngError`. Caller is responsible for
re-attempting keygen (typically once — sustained failures indicate RAM
corruption).

## Continuous self-tests

- **AEAD authenticator.** ring's AEAD already rejects on tag mismatch; the
  `decrypt_packet` error propagates. No additional CST needed.
- **RNG continuous health.** `aws-lc-rs::rand::SystemRandom` in FIPS mode
  implements SP 800-90B continuous tests automatically. For the non-FIPS
  build, we rely on the OS CSPRNG's own health policy.

## Test schedule

| Phase | Status | Deliverable |
| --- | --- | --- |
| Phase 5.4 | ✅ | CAVP-style KATs in `core/tests/cavp.rs` (ML-KEM-768, ML-DSA-65, AES-256-GCM, HKDF-SHA-256 (RFC 5869 A.1), SHA-256) plus byte-exact NIST ACVP vectors in `core/tests/nist_kat.rs` + `core/tests/nist_kat/*.json`. |
| Phase 5.5 | ✅ | `core/src/crypto/self_tests.rs` + `run_post()` / `ensure_post_passed()` API. Shipped and wired into `PhantomListener::bind*` / `PhantomSession::connect*` / `connect_pinned*` under the `fips` feature; failure → `CoreError::FipsSelfTestFailure`. |
| Phase 5.5 | ✅ | CI `fips-feature` job runs `cargo test --no-default-features --features fips,bindings,compression-zstd --lib` (which includes the `self_tests` module tests and the `set_force_post_fail` fault-injection seam) on every PR. |
| Phase 5.5 | ⏳ | PCT on the KEM keypair (`HybridSecretKey::generate`). The signing-key PCT is shipped; the POST already covers KEM pairwise consistency once at startup. |

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
