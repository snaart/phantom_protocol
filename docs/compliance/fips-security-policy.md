# FIPS Security Policy (Draft)

> **Status.** Draft skeleton for the eventual CMVP submission. Phase 5.5 of
> the production-readiness roadmap. Not yet a validation document — used
> here to fix the boundary and approved-services model so subsequent code
> work has a target.

This document is the cryptographic-module security policy required by
FIPS 140-3 IG D.2 and SP 800-140C. It defines the boundary, the approved
security functions, the modes of operation, and the assumptions under
which the module operates.

## 1. Module identification

| Field | Value |
| --- | --- |
| Module name | Phantom Protocol |
| Module type | Software, multi-target |
| Versions | Tied to `phantom_protocol` crate version (`Cargo.toml`). FIPS-validated build identifier: `${cargo_version}-fips-${git_sha}`. |
| Vendor | (to be filled by deploying organization) |
| Target environments | Listed in §3. |
| Embodiment | Hybrid (software running on general-purpose hardware). |

## 2. Cryptographic boundary

The boundary is the compiled `phantom_protocol` Rust library plus its
statically-linked cryptographic dependencies:

- `aws-lc-rs` (FIPS-validated mode) — symmetric primitives, hashing, RNG.
- `ml-kem` (RustCrypto) — FIPS 203.
- `ml-dsa` (RustCrypto) — FIPS 204.
- `ed25519-dalek` — FIPS 186-5 Ed25519.

Outside the boundary:

- The host OS and TCP/UDP networking stack.
- The transport-leg implementations that handle non-crypto framing
  (`api/tcp_transport.rs`).
- The runtime abstraction (`runtime/`) — Tokio, WASM, embedded.
- Application code linking the SDK.

Data and key flows that cross the boundary:

- Application plaintext / ciphertext (in/out via `PhantomStream::send` /
  `recv`).
- Server's verifying key (`HybridVerifyingKey`) — out only.
- RNG entropy from the OS (`/dev/urandom` / `BCryptGenRandom` /
  `getrandom`) — in only.

## 3. Approved tested environments

Phase 5.5 needs concrete platform commitments for the CMVP submission.
Draft list:

| Platform | OS | CPU | Status |
| --- | --- | --- | --- |
| Linux server | Ubuntu 22.04 LTS | x86_64 with AES-NI | Primary target |
| Linux server | Ubuntu 22.04 LTS | aarch64 with ARMv8 crypto extensions | Primary target |
| Linux server | Amazon Linux 2023 | x86_64 with AES-NI | Secondary |

Mobile / WASM / embedded targets are **not** in the initial CMVP scope.

## 4. Roles, services, and authentication

### 4.1 Roles

| Role | Authentication | Capabilities |
| --- | --- | --- |
| **Crypto Officer (CO)** | None (role assumed by process startup). | Initialize the module (`PhantomListener::bind`), generate long-term signing key, run on-demand POST. |
| **User** | None (role assumed by any thread holding an active session/listener). | Open sessions, encrypt/decrypt application data, query module state. |

FIPS 140-3 Level 1 allows implicit role assumption — no operator
authentication is required at the module boundary.

### 4.2 Services

| Service | Role | Approved? | Inputs | Outputs |
| --- | --- | --- | --- | --- |
| Module initialization | CO | Yes | None | POST result |
| Signing key generation | CO | Yes | None | `HybridSigningKey` (Ed25519 + ML-DSA-65 keypair) |
| Listener bind | CO | Yes | Local address, signing key | `PhantomListener` |
| Session establish | User | Yes | Server pin, transport | `PhantomSession` |
| Stream open / close | User | Yes | Session, stream parameters | `PhantomStream` |
| Send / receive | User | Yes (AES-256-GCM or non-approved ChaCha20-Poly1305 depending on suite) | Application bytes | Encrypted/decrypted bytes |
| Rekey | User | Yes | None | Updated `CryptoState` |
| Path validation challenge/response | User | Yes | Path id | Validation result |
| Run self-tests | CO | Yes | None | POST result |
| Shutdown | CO | N/A | None | None |

**Non-approved services in FIPS mode (rejected at runtime):**

- ChaCha20-Poly1305 cipher suite — feature-gated to off in `--features
  fips`.
- BLAKE3 hashing — replaced by SHA-256 in `--features fips`.
- Pre-FIPS 203 Kyber768 / Pre-FIPS 204 Dilithium3 — already migrated to
  ML-KEM-768 / ML-DSA-65 in Phase 5.1.

## 5. Approved security functions

| Function | Standard | Use in module |
| --- | --- | --- |
| AES-256-GCM | SP 800-38D | AEAD (record encryption) |
| SHA-256 | FIPS 180-4 | Hashing |
| HKDF-SHA-256 | RFC 5869 / SP 800-56C Rev. 2 | Key derivation |
| HMAC-SHA-256 | FIPS 198-1 / SP 800-198 | Cookie + PoW MAC |
| Ed25519 | FIPS 186-5 | Classical signature half |
| ML-KEM-768 | FIPS 203 | Post-quantum KEM |
| ML-DSA-65 | FIPS 204 | Post-quantum signature |
| CTR_DRBG (via `aws-lc-rs`) | SP 800-90A Rev. 1 | RNG |

## 6. Modes of operation

| Mode | How selected | Approved? |
| --- | --- | --- |
| **Approved mode** | `cargo build --features fips --no-default-features` | Yes |
| **Non-approved mode** | Default build (or `--features compression-zstd` etc.) | No — ChaCha and BLAKE3 enabled |

A future runtime indicator (Phase 5.5):

```rust
phantom_protocol::fips::is_in_approved_mode() -> bool
```

returns `true` iff the build is FIPS-feature'd AND POST has succeeded.

## 7. Key zeroization

See `docs/compliance/key-management.md` §"Zeroize-on-Drop coverage". All
key material is zeroized when its containing struct is dropped. The
`Drop` impls come from the `zeroize` crate's `ZeroizeOnDrop` derive.

For ring keys (`LessSafeKey`) the seed bytes are zeroed; the opaque
interior is the responsibility of ring (FIPS-validated build).

## 8. Self-tests

See `docs/compliance/self-tests.md`. Summary:

- POST runs (via the cached `ensure_post_passed()`) on first call to
  `PhantomListener::bind*` / `PhantomSession::connect*` / `connect_pinned*`
  per process under `--features fips`.
- On failure: the bootstrap short-circuits and the call returns
  `CoreError::FipsSelfTestFailure(String)` instead of standing up a
  listener / session over broken primitives.
- Per-keygen PCTs wired into every keygen function are not yet shipped
  (POST already covers KEM / signature pairwise consistency once at
  startup).

## 9. Physical security

N/A — software module. Hosting platform's physical-security policy applies.

## 10. Operational environment

FIPS 140-3 Level 1, modifiable operational environment. The host OS is
out of scope; the operator is responsible for using a FIPS-validated
underlying CSPRNG (Linux kernel ≥ 5.18 in FIPS mode, or platform DRBG).

## 11. Mitigation of other attacks

| Attack | Mitigation |
| --- | --- |
| Timing on cookie / PoW / path-challenge verification | `subtle::ConstantTimeEq` (see `constant-time-audit.md`). |
| Timing on AEAD tag verification | Delegated to `aws-lc-rs` (audited upstream). |
| Replay | Per-stream sliding-window replay protection (`security/replay_protection.rs`) after AEAD verify. |
| Cross-protocol confusion | Domain-separated HKDF labels per direction and per epoch (`phantom-traffic-v1`, `phantom-rekey-v1`, `phantom-faketls-c2s-v1`, etc.). |
| Downgrade | Wire version is transcript-bound (Phase 1.8); FakeTLS outer AEAD is anti-DPI only and not the security boundary. |
| Nonce exhaustion | `AEAD_MAX_INVOCATIONS = 2^48` per epoch; rekey before exhaustion (Phase 1.7). |
| Replay of resumption / 0-RTT | 0-RTT resumption is shipped; `SessionCache::try_resume` is **one-shot** (the ticket is consumed on first lookup), so a replayed `ClientHello` finds no ticket and falls back to the normal 1-RTT cookie/PoW gate (Security Invariant 9). |

## 12. References

- FIPS 140-3 — Security Requirements for Cryptographic Modules.
- SP 800-140C — CMVP Module Validation Lists.
- SP 800-90A Rev. 1 — DRBG.
- SP 800-38D — AES-GCM.
- FIPS 203 — ML-KEM.
- FIPS 204 — ML-DSA.
- FIPS 186-5 — Digital Signatures (Ed25519).
- `docs/compliance/fips-readiness.md` — gap analysis vs this policy.
