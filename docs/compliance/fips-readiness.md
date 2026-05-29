# FIPS 140-3 / Common Criteria Readiness

Living document tracking the gap between the current `phantom_core` build
and a FIPS 140-3 (or equivalent CC) validated configuration. Authoritative
for what Phase 5 in `PRODUCTION_READINESS.md` has to deliver.

This is **not** a Security Policy document yet — that lives under
`docs/compliance/fips-security-policy.md` and is the output of Phase 5.5.

## Status (2026-05-24)

The **`--features fips` primitive swap is shipped** — see the
`fips`-tagged commits in the history for the per-commit rollout.
Every primitive gap below now has an "implemented (commit `<sha>`)"
entry. The remaining FIPS work (`fips-security-policy.md`,
`key-management.md`, etc.) is documentation + the eventual CMVP
submission, not code.

---

## 1. Current primitive inventory vs. FIPS-approved set

| Operation | Default build | `--features fips` build | Status |
| --- | --- | --- | --- |
| Classical KEM | X25519 (`x25519-dalek`) | ECDH P-256 via `aws-lc-rs::agreement` | ✅ A4 (commit `67ef976`). Wire-incompatible across modes; gated by `PROTOCOL_VARIANT`. |
| Post-quantum KEM | ML-KEM-768 (`ml-kem = 0.2`, FIPS 203 RustCrypto pure-Rust) | identical | ✅ Phase 5.1, commit `7c7bde7`. CAVP vectors in `core/tests/cavp.rs`. |
| Classical signature | Ed25519 (`ed25519-dalek`) | identical | ✅ FIPS 186-5 approves EdDSA(Ed25519) out of the box. |
| Post-quantum signature | ML-DSA-65 (`ml-dsa = =0.1.0-rc.11`, FIPS 204 RustCrypto pure-Rust) | identical | ✅ Phase 5.1, commit `7c7bde7`. CAVP vectors in `core/tests/cavp.rs`. |
| Symmetric AEAD | AES-256-GCM via `ring` | AES-256-GCM via `aws-lc-rs::aead` (AWS-LC-FIPS) | ✅ A2 (commit `d691573`). Identical API surface; backend swap only. |
| Symmetric AEAD (alt) | ChaCha20-Poly1305 | rejected at handshake with `CoreError::CipherSuiteUnavailable` | ✅ A3 (commit `cd79cbd`). Enum variant stays for wire-format stability. |
| Hash | SHA-256 (`sha2`) | identical | ✅ FIPS 180-4. |
| Hash (KDF context) | `blake3::derive_key` | `HKDF-SHA-256.expand(label.as_bytes())` | ✅ A5 (commit `c2fa013`). All 9 KDF call sites swapped via `crypto::kdf::derive_key_32`. PoW `blake3::hash` stays (not KDF). |
| KDF (HKDF) | HKDF-SHA-256 (`hkdf`) | identical | ✅ NIST SP 800-56C. |
| HMAC | HMAC-SHA-256 (`hmac`) | identical | ✅ FIPS 198-1. |
| RNG | `getrandom` → OS DRBG | `aws-lc-rs::rand::SystemRandom` (CTR_DRBG inside AWS-LC-FIPS module, SP 800-90A § 10.2.1) | ✅ A6 (commit `2ec02b7`). Routed through the `RngProvider for OsRng` impl so production call sites pick up the swap automatically. |
| Power-on self-test | not invoked | `crypto::self_tests::run_post` wired into `PhantomListener::bind*` / `connect_pinned*` via `ensure_post_passed` (cached `OnceLock`) | ✅ A7 (commit `782ea3d`). Failure returns `CoreError::FipsSelfTestFailure`. |

Bottom line: under `--features fips`, **all primitive-level gaps from
the original gap analysis are closed**. The build is FIPS-substrate
clean: AWS-LC-FIPS for AES + ECDH + RNG, RustCrypto FIPS 203/204 for
the PQ halves, HKDF-SHA-256 for every derivation, POST gating the
bootstrap.

---

## 2. `fips` Cargo feature — shipped

The `fips` Cargo feature pulls in `aws-lc-rs` (AWS-LC-FIPS via the
`fips` aws-lc-rs sub-feature) and cfg-gates every non-FIPS-approved
primitive call site. The flag implies `std` and is mutually exclusive
with `no-std` (enforced by a `compile_error!` in `core/src/lib.rs`,
A8 commit `3fae01d`).

| Decision | Choice | Source |
| --- | --- | --- |
| Hybrid vs PQ-only | **Hybrid** — keep both halves, swap X25519 → ECDH-P-256 | Plan A4 |
| Wire-format compat | **Separate binary** — fips ↔ non-fips interop is out of scope | Plan A4 |
| Cross-mode safety | `PROTOCOL_VARIANT` constant baked into the signed transcript; a mixed-mode handshake fails on `HandshakeError::ProtocolVariantMismatch` (cleartext) or signature verify (transcript-bound) | Plan A4 |
| Conflict guard | `compile_error!` if both `fips` and `no-std` features are active | Plan A8 |

Mechanics, by item:

- `crypto::adaptive_crypto` — `aead` import block is cfg-gated to
  `ring::aead` (default) or `aws_lc_rs::aead` (fips). Same Rust API
  surface, so `CryptoSession` is untouched. (A2.)
- `crypto::adaptive_crypto::negotiate_cipher` returns
  `Result<CipherSuite, CoreError>`; under fips, a ChaCha-only client
  offer is rejected. `CryptoSession::with_suite{_peer}` rejects
  ChaCha-explicit construction with `CipherSuiteUnavailable`. (A3.)
- `crypto::hybrid_kem` — classical secret-key type becomes
  `aws_lc_rs::agreement::PrivateKey`; encap uses
  `EphemeralPrivateKey`. Wire-level: `classical_pk` grows from 32 to
  65 bytes (uncompressed SEC1 P-256). HKDF combine label switches
  from `HybridKEM_X25519_Kyber768` to `HybridKEM_P256_Kyber768`. (A4.)
- `crypto::kdf::derive_key_32(label, ikm)` — cfg-dispatched helper:
  `blake3::derive_key` by default, `HKDF-SHA256.expand(label_bytes)`
  under fips. Adopted by `crypto::adaptive_crypto`,
  `crypto::aes_session`, and `transport::legs::faketls`. (A5.)
- `crypto::rng::OsRng`'s `RngProvider` impl is cfg-split:
  `getrandom` default, `aws_lc_rs::rand::SystemRandom` under fips
  (CTR_DRBG SP 800-90A § 10.2.1 inside the FIPS module). (A6.)
- `crypto::self_tests::ensure_post_passed` — process-global single-
  shot wrapper around `run_post`. Wired into `bind_inner` and
  `connect_pinned*` under fips; failure surfaces as
  `CoreError::FipsSelfTestFailure(String)`. (A7.)

---

## 3. Self-tests (FIPS 140-3 §7.7 — Self-Tests)

A FIPS-validated module must run **power-on self-tests (POST)** at
initialization and **conditional self-tests** at key-generation
boundaries. **Implemented** in `core/src/crypto/self_tests.rs`
(Phase 5.5 commit `2dbe1cd` for the test battery; A7 commit `782ea3d`
for the bind/connect wiring).

POST coverage (`run_post`):
- AEAD round-trip per active cipher suite — AES-256-GCM
  unconditionally; ChaCha20-Poly1305 only on non-fips builds.
- HKDF-SHA-256 KAT against a fixed 32-byte output.
- Hybrid KEM round-trip (encap + decap, X25519/P-256 + ML-KEM-768).
- Hybrid signature round-trip (Ed25519 + ML-DSA-65).
- Negative-verify (tamper one signature byte, assert reject).

API:

```rust
pub fn run_post() -> Result<(), SelfTestError>;
pub fn ensure_post_passed() -> Result<(), SelfTestError>;
```

`ensure_post_passed` caches the verdict in a `OnceLock` so subsequent
bind/connect calls in the same process pay only an atomic read.
`PhantomListener::bind_inner` and the UniFFI `connect_pinned*`
entrypoints invoke it under `cfg(feature = "fips")` before any
cryptographic work; a failure short-circuits to
`CoreError::FipsSelfTestFailure(String)` instead of standing up a
session over broken primitives.

Fault injection is exercised in CI via the `set_force_post_fail` test
seam (`crypto::self_tests::tests::force_post_fail_returns_error_via_ensure_post_passed`
and `api::listener::tests::fips_post_failure_aborts_bind`).

---

## 4. CAVP test vectors

The Cryptographic Algorithm Validation Program (CAVP) is the
prerequisite for CMVP. It validates each approved algorithm against
NIST-provided test vectors.

Status (Phase 5.4 ✅): CAVP-style known-answer tests are **implemented**
in `core/tests/cavp.rs`. Coverage:

```
core/tests/cavp.rs
    ML-KEM-768  (FIPS 203 §7.2/§7.3 — Encaps / Decaps round-trip + hybrid wiring)
    ML-DSA-65   (FIPS 204 — Sign / Verify round-trip + hybrid wiring)
    AES-256-GCM (encrypt + decrypt via ring)
    SHA-256     (deterministic digest)
    HMAC-SHA-256
    HKDF-SHA-256 (RFC 5869 + NIST SP 800-56C)
    Ed25519     (sign / verify via ed25519-dalek)
```

These run on every `cargo test --manifest-path core/Cargo.toml`
invocation with no feature flag required. Failure of any vector = hard
red. No separate `cavp.yml` CI job exists; coverage is provided by the
main `ci.yml` test step.

---

## 5. Documentation deliverables (Phase 5.5)

Each of these is a separate file under `docs/compliance/`:

| Doc | What it contains | Status |
| --- | --- | --- |
| `fips-security-policy.md` | Module boundary, approved security functions, modes of operation, lifecycle | scaffold pending |
| `key-management.md` | Generation, distribution, storage, destruction, lifecycle per key type (signing, master, session, KEM ephemeral) | scaffold pending |
| `self-tests.md` | POST inventory, conditional self-test inventory, error-state handling | scaffold pending |
| `cc-st.md` | Common Criteria Security Target (PP, SFRs, SARs) | scaffold pending |

These documents are what the CMVP / CC laboratory reads; their
accuracy is enforced by the implementation. Drift between doc and code
is itself a finding.

---

## 6. Validation pathway

Two parallel certification tracks (out of scope for code, but
documented here so the team can budget):

| Track | Cost (rough) | Duration |
| --- | --- | --- |
| FIPS 140-3 CMVP submission via accredited laboratory | $80-150K | 6-12 months |
| Common Criteria EAL2-EAL4 evaluation via accredited laboratory | $150-300K | 12-24 months |

Code changes (Phases 5.1-5.5) are a precondition; the validation
itself is a separate business decision.

---

## 7. Compatibility implications

Switching primitives is a **wire-incompatible** change. A `--features fips`
build cannot interoperate with a default build:

- ML-KEM-768 (FIPS 203) ciphertexts have different bytes than the prior
  Kyber768 (NIST PQC Round-3) format — this break already occurred in
  Phase 5.1; current builds are ML-KEM-768 only.
- ML-DSA-65 (FIPS 204) signatures have different bytes than the prior
  Dilithium3 format — same break, already shipped.
- Removing ChaCha20-Poly1305 means a non-FIPS-AES-only peer cannot
  negotiate.
- Removing X25519 (PQ-only variant) cuts off classical compatibility.

Any future `fips` feature changes (e.g. dropping ChaCha20-Poly1305 or
X25519) remain wire-incompatible between `fips` and non-`fips` builds
and should be reflected in `VersionedPacket` or a negotiation extension.

---

## 8. Current readiness percentage

Rough scoring against FIPS 140-3 Level 1 requirements after the
`fips` primitive swap rollout (commits `613473a`..`5dd39c7`):

| Category | Status | Notes |
| --- | --- | --- |
| Approved primitive set | **100% under `--features fips`** | All KEM, signature, AEAD, KDF, RNG primitives match the FIPS approved set; AES + ECDH + RNG via AWS-LC-FIPS, HKDF-SHA-256 for every derivation, RustCrypto FIPS 203/204 for the PQ halves. Default build retains X25519/blake3/ChaCha20-Poly1305 for the non-FIPS deployment footprint. |
| Implementation roles | n/a for L1 | Operator + Cryptographic-Officer split is L2+ |
| Self-tests | **100% under `--features fips`** | `run_post` + `ensure_post_passed` wired into bind/connect (A7). Fault injection covered by `set_force_post_fail` test seam. |
| Key management | partial | Generation + destruction are right; storage + lifecycle docs missing (`key-management.md` still scaffold). |
| RNG | **CTR_DRBG under `--features fips`** | `aws-lc-rs::rand::SystemRandom` (SP 800-90A § 10.2.1) routed through `RngProvider for OsRng`. |
| Constant-time properties | 80% | cookie path done (Phase 1.1); rest relies on ring / dalek / ml-kem / ml-dsa / aws-lc-rs upstream. |
| Documentation | partial | This file + `self-tests.md` + `constant-time-audit.md` cover the primitive swap. `fips-security-policy.md` and `key-management.md` still need flesh for the CMVP submission. |

**Overall: ~80%.** The code-level FIPS posture is functionally
complete under `--features fips`. The remaining gap is the
documentation track for a real CMVP submission
(`fips-security-policy.md`, `key-management.md` flesh-out, etc.) —
those are out of scope for this rollout and pinned in Section 5
below.

---

## 9. Tracking

See `docs/PROGRESS.md` rows 5.1 through 5.7 for the live status of each
sub-task. This file is updated alongside whenever a Phase 5 item flips
status.
