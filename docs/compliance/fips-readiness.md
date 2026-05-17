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
| Post-quantum KEM | ML-KEM-768 (`ml-kem = 0.2`, FIPS 203 RustCrypto pure-Rust) | ✅ FIPS-approved primitive shipped; CAVP vectors in `core/tests/cavp.rs` (Phase 5.4 ✅) | — already done (Phase 5.1, commit `7c7bde7`) |
| Classical signature | Ed25519 (`ed25519-dalek`) | ✅ FIPS 186-5 approves EdDSA(Ed25519) | Keep as-is |
| Post-quantum signature | ML-DSA-65 (`ml-dsa = =0.1.0-rc.11`, FIPS 204 RustCrypto pure-Rust) | ✅ FIPS-approved primitive shipped; CAVP vectors in `core/tests/cavp.rs` (Phase 5.4 ✅) | — already done (Phase 5.1, commit `7c7bde7`) |
| Symmetric AEAD | AES-256-GCM (`ring`) | ⚠️ Approved only if built against a FIPS-validated cryptographic module | Use `aws-lc-rs` (Amazon's FIPS module) instead of `ring`'s default build |
| Symmetric AEAD (alt) | ChaCha20-Poly1305 (`chacha20poly1305`) | ❌ Not FIPS-approved | Drop in `fips` mode |
| Hash | SHA-256 (`sha2`) | ✅ FIPS 180-4 | Keep |
| Hash (KDF context) | blake3 keyed-derivation | ❌ Not FIPS | Replace with HKDF-SHA-256 / SHA-512 |
| KDF (HKDF) | HKDF-SHA-256 (`hkdf`) | ✅ NIST SP 800-56C | Keep |
| HMAC | HMAC-SHA-256 (`hmac`) | ✅ FIPS 198-1 | Keep |
| RNG | `getrandom` → OS DRBG | ⚠️ FIPS approves only specific DRBGs (SP 800-90A: CTR_DRBG, HMAC_DRBG, Hash_DRBG) | Use `aws-lc-rs::rand` (CTR_DRBG inside the FIPS module) |

Bottom line: **six out of nine** crypto-relevant primitive choices are
FIPS-approved out of the box (ML-KEM-768, ML-DSA-65, Ed25519, SHA-256,
HKDF-SHA-256, HMAC-SHA-256). The remaining gaps are X25519 (classical
KEM leg), AES-256-GCM via `ring` (module validation), ChaCha20-Poly1305,
blake3, and the RNG — these need the `fips` feature swap.

---

## 2. Proposed `fips` feature

There is **no `fips` cargo feature gate today**. The PQ primitive swap
(Phase 5.1, commit `7c7bde7`) was applied **unconditionally**: every
build now uses `ml-kem = 0.2` (FIPS 203) and `ml-dsa = =0.1.0-rc.11`
(FIPS 204) — the `pqcrypto-kyber` / `pqcrypto-dilithium` dependencies
are gone. CAVP known-answer tests for both primitives (plus AES-256-GCM,
Ed25519, SHA-256, HMAC-SHA-256, and HKDF-SHA-256) landed in Phase 5.4
and run on every `cargo test` invocation via `core/tests/cavp.rs`.

The remaining items below still require a future `fips` feature to gate:

- Replaces `ring` → `aws-lc-rs` everywhere AES-256-GCM is invoked. Both
  crates expose a sibling `ring`-shaped API; the swap is mostly a
  workspace dependency-rewrite plus a few `use` lines.
- Replaces every `blake3::derive_key("phantom-...-v1", seed)` call with
  `hkdf::Hkdf::<Sha256>::new(None, seed).expand("phantom-...-v1", &mut out)`.
- Removes `ChaCha20Poly1305` from the `CipherSuite` enum (and removes
  the dependency).
- Removes X25519 from the hybrid construction. Two policy options:
  - **PQ-only**: drop the classical leg entirely. Simpler; loses the
    defense-in-depth against an undiscovered ML-KEM flaw.
  - **PQ + ECDH P-256**: keep a classical leg but FIPS-approved. More
    work; matches NIAP's hybrid recommendations for VPN PPs.

Default plan: PQ + ECDH P-256, behind a sub-feature `fips-hybrid`.

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

Rough scoring against FIPS 140-3 Level 1 requirements:

| Category | Status | Notes |
| --- | --- | --- |
| Approved primitive set | 55% | 6 of 9 default primitives are FIPS-approved (ML-KEM-768, ML-DSA-65, Ed25519, SHA-256, HKDF-SHA-256, HMAC-SHA-256); X25519, ChaCha20-Poly1305, blake3 remain non-FIPS |
| Implementation roles | n/a for L1 | Operator + Cryptographic-Officer split is L2+ |
| Self-tests | 0% | none implemented |
| Key management | partial | Generation + destruction are right; storage + lifecycle docs missing |
| RNG | conditional | depends on OS; `aws-lc-rs::rand` swap fixes |
| Constant-time properties | 80% | cookie path done (Phase 1.1); rest relies on ring / dalek / ml-kem / ml-dsa upstream |
| Documentation | 5% | this file is the only Phase 5 artifact today |

**Overall: ~30%.** Phase 5.1 (PQ primitive swap) and 5.4 (CAVP vectors)
are complete. The remaining gap is Phase 5.2 (`fips` feature: ring →
aws-lc-rs, drop ChaCha20-Poly1305 and blake3 in FIPS mode, X25519 →
P-256) and Phase 5.5 (self-tests, security policy docs, key-management
docs).

---

## 9. Tracking

See `docs/PROGRESS.md` rows 5.1 through 5.7 for the live status of each
sub-task. This file is updated alongside whenever a Phase 5 item flips
status.
