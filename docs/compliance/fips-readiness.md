# FIPS 140-3 / Common Criteria Readiness

Living document tracking the gap between the current `phantom_core` build
and a FIPS 140-3 (or equivalent CC) validated configuration. Authoritative
for what Phase 5 in `PRODUCTION_READINESS.md` has to deliver.

This is **not** a Security Policy document yet — that lives under
`docs/compliance/fips-security-policy.md` and is the output of Phase 5.5.

---

## 1. Current primitive inventory vs. FIPS-approved set

| Operation | What we use today | FIPS-approved? | Mitigation under `fips` feature |
| --- | --- | --- | --- |
| Classical KEM | X25519 (`x25519-dalek`) | ❌ No FIPS-approved KEM uses X25519 | Replace with ECDH P-256 / P-384, OR drop the classical leg and rely on PQ alone |
| Post-quantum KEM | Kyber768 (`pqcrypto-kyber`) | ❌ Kyber768 is the NIST PQC Round-3 spec; ML-KEM-768 (FIPS 203) is the standardised variant | Switch to `ml-kem` crate or aws-lc-rs's ML-KEM impl |
| Classical signature | Ed25519 (`ed25519-dalek`) | ✅ FIPS 186-5 approves EdDSA(Ed25519) | Keep as-is |
| Post-quantum signature | Dilithium3 (`pqcrypto-dilithium`) | ❌ ML-DSA-65 (FIPS 204) is the standardised variant | Switch to `ml-dsa` crate or aws-lc-rs's ML-DSA impl |
| Symmetric AEAD | AES-256-GCM (`ring`) | ⚠️ Approved only if built against a FIPS-validated cryptographic module | Use `aws-lc-rs` (Amazon's FIPS module) instead of `ring`'s default build |
| Symmetric AEAD (alt) | ChaCha20-Poly1305 (`ring`) | ❌ Not FIPS-approved | Drop in `fips` mode |
| Hash | SHA-256 (`sha2`) | ✅ FIPS 180-4 | Keep |
| Hash (KDF context) | blake3 keyed-derivation | ❌ Not FIPS | Replace with HKDF-SHA-256 / SHA-512 |
| KDF (HKDF) | HKDF-SHA-256 (`hkdf`) | ✅ NIST SP 800-56C | Keep |
| HMAC | HMAC-SHA-256 (`hmac`) | ✅ FIPS 198-1 | Keep |
| RNG | `getrandom` → OS DRBG | ⚠️ FIPS approves only specific DRBGs (SP 800-90A: CTR_DRBG, HMAC_DRBG, Hash_DRBG) | Use `aws-lc-rs::rand` (CTR_DRBG inside the FIPS module) |

Bottom line: **two out of seven** crypto-relevant primitive choices are
FIPS-approved out of the box (Ed25519, SHA-256, HKDF, HMAC). The rest
need the `fips` feature swap.

---

## 2. Proposed `fips` feature

When implemented (Phase 5.1), `--features fips`:

- Replaces `ring` → `aws-lc-rs` everywhere AES-256-GCM is invoked. Both
  crates expose a sibling `ring`-shaped API; the swap is mostly a
  workspace dependency-rewrite plus a few `use` lines.
- Replaces `pqcrypto-kyber` → `ml-kem`.
- Replaces `pqcrypto-dilithium` → `ml-dsa`.
- Replaces every `blake3::derive_key("phantom-...-v1", seed)` call with
  `hkdf::Hkdf::<Sha256>::new(None, seed).expand("phantom-...-v1", &mut out)`.
- Removes `ChaCha20Poly1305` from the `CipherSuite` enum (and removes
  the dependency).
- Removes X25519 from the hybrid construction. Two policy options:
  - **PQ-only**: drop the classical leg entirely. Simpler; loses the
    defense-in-depth against an undiscovered Kyber/ML-KEM flaw.
  - **PQ + ECDH P-256**: keep a classical leg but FIPS-approved. More
    work; matches NIAP's hybrid recommendations for VPN PPs.

Default: PQ + ECDH P-256, behind a sub-feature `fips-hybrid`.

---

## 3. Self-tests (FIPS 140-3 §7.7 — Self-Tests)

A FIPS-validated module must run **power-on self-tests (POST)** at
initialization and **conditional self-tests** at key-generation
boundaries. Out of scope today; will live at
`core/src/crypto/self_tests.rs` (Phase 5.5).

POST coverage required:
- One known-answer test (KAT) per approved algorithm: AES-256-GCM,
  ML-KEM-768, ML-DSA-65, Ed25519, SHA-256, HMAC-SHA-256, HKDF-SHA-256.
- Pairwise consistency tests on key-pair generation (sign then verify
  with the freshly-generated keypair; abort on mismatch).

API contract:

```rust
pub fn run_self_tests() -> Result<(), FipsError>;
```

Called automatically on the first `HandshakeServer::new()` / first
`HybridSigningKey::generate()` under `fips` feature. Failure mode:
abort the process (FIPS 140-3 explicitly requires this — a failed
self-test puts the module into an error state from which no
cryptographic service may proceed).

---

## 4. CAVP test vectors

The Cryptographic Algorithm Validation Program (CAVP) is the
prerequisite for CMVP. It validates each approved algorithm against
NIST-provided test vectors.

Plan (Phase 5.4):

```
tests/cavp/
    aes_256_gcm.json        # encrypt + decrypt vectors
    ml_kem_768.json         # KAT vectors per FIPS 203 §6.4
    ml_dsa_65.json           # KAT vectors per FIPS 204 §A.4
    ed25519.json             # RFC 8032 vectors
    sha_256.json             # NIST hash vectors
    hmac_sha256.json
    hkdf_sha256.json         # RFC 5869 + NIST SP 800-56C
```

CI job `cavp.yml` runs every vector on every push under the `fips`
feature build. Failure of any vector = hard CI failure.

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

- ML-KEM-768 ciphertexts have different bytes than Kyber768 ciphertexts
  even though the math is structurally identical.
- ML-DSA-65 signatures have different bytes than Dilithium3 signatures.
- Removing ChaCha20-Poly1305 means a non-FIPS-AES-only peer cannot
  negotiate.
- Removing X25519 (PQ-only variant) cuts off classical compatibility.

This means the `fips` feature is the natural place to bump
`VersionedPacket` to `V2` (or to introduce a separate `V1_FIPS`
variant). Either way Phase 5 work intersects Phase 4.2's V2 bump.

---

## 8. Current readiness percentage

Rough scoring against FIPS 140-3 Level 1 requirements:

| Category | Status | Notes |
| --- | --- | --- |
| Approved primitive set | 25% | 2 of 7 default primitives are FIPS-approved |
| Implementation roles | n/a for L1 | Operator + Cryptographic-Officer split is L2+ |
| Self-tests | 0% | none implemented |
| Key management | partial | Generation + destruction are right; storage + lifecycle docs missing |
| RNG | conditional | depends on OS; `aws-lc-rs::rand` swap fixes |
| Constant-time properties | 80% | cookie path done (Phase 1.1); rest relies on ring / dalek / pqcrypto upstream |
| Documentation | 5% | this file is the only Phase 5 artifact today |

**Overall: ~15%.** The remaining 85% is Phase 5.1-5.5 work and is the
single largest gap between today's codebase and a CMVP submission.

---

## 9. Tracking

See `docs/PROGRESS.md` rows 5.1 through 5.7 for the live status of each
sub-task. This file is updated alongside whenever a Phase 5 item flips
status.
