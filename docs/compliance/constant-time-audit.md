# Constant-Time Audit

This document inventories every comparison in `core/src/` that involves a
**secret** (key material, nonce, MAC tag, cookie, PoW solution, validation
challenge) and classifies it against the constant-time discipline. The goal
is to prove there is no comparison whose timing leaks information an
adversary doesn't already have.

> **Scope.** Constant-time discipline is necessary for *secret-vs-secret*
> and *secret-vs-attacker-controlled* comparisons. Comparisons between two
> public values (e.g., pinned public key vs. peer's public key sent in
> cleartext) do not need CT — leaking match/mismatch reveals only the value
> the attacker already supplied.

## Classification

| Class | Risk | Required discipline |
| --- | --- | --- |
| **A.** Secret vs. attacker-controlled value | High — attacker can submit guesses and observe timing | **MUST** use `subtle::ConstantTimeEq` / `Choice` |
| **B.** Secret vs. another local secret | Medium — only attacker with side-channel access | **SHOULD** use `subtle::ConstantTimeEq` |
| **C.** Public vs. public (e.g., pinned key vs. received key) | None — both values known to attacker | Plain `==` is fine |
| **D.** Variable-time arithmetic on secrets (e.g., AES-NI, curve scalar mult) | Depends on underlying primitive | Hardware-provided CT (AES-NI, AVX2 curve impls) or audited crate |

## Inventory

### Cookie validation (Class A)

`core/src/transport/handshake.rs:631-665` — `verify_cookie`. The cookie is
an HMAC-SHA-256 tag bound to client IP + port + a rotating time-bucket secret.
Validation accepts either the current bucket or the previous bucket
(sliding-window freshness).

Discipline:
- Each `cookie == expected_for_bucket` performed via
  `cookie.ct_eq(&expected)` returning a `subtle::Choice`.
- Accept signal is **accumulated** as `accept |= cookie.ct_eq(...)` over both
  buckets. The function never branches on a per-bucket result, never
  short-circuits, and always evaluates HMACs for **both** buckets.
- Final conversion: `accept.into()` (`Choice` → `bool`) happens once at the
  return.

Compliance: ✅ class A satisfied.

### Path-validation challenge response (Class A)

`core/src/transport/path.rs:236-265` — `Session::complete_path_validation`.
The 32-byte challenge is server-issued and unique per `(path_id, session)`.
The response from the peer is attacker-controllable.

Discipline:
- `expected.ct_eq(response).into()` returns `bool` via `subtle::Choice`.
- No branching on intermediate state; failure transitions the path to
  `Failed` regardless of which byte mismatched.

Compliance: ✅ class A satisfied.

### PoW solution verification (Class A)

`core/src/crypto/pow.rs:44` — `Challenge::verify`. Solution is attacker-
controllable (the client submits it).

Discipline:
- The PoW invariant is "leading zero bits of HMAC-SHA-256(secret || client_id
  || solution) ≥ difficulty". The hash is computed in full regardless of the
  result; the zero-bit count is evaluated by reading bytes left-to-right and
  comparing each byte to `0u8`. The early termination happens on a non-zero
  byte, but the loop bound is `difficulty / 8 + 1` — which is determined by
  the **server's** policy, not the attacker. No secret bytes (key material)
  flow into the loop counter.

Compliance: ✅ class A satisfied. (The early-exit is on `difficulty`, a
public server policy parameter; not on a secret.)

### PoW challenge-integrity MAC (Class A) — CRYPTO-2/HS-04

`core/src/crypto/pow.rs:60` — `PoWChallenge::verify` compares the embedded
24-byte challenge MAC (keyed by the server's per-hour secret) against the
recomputed value. The submitted challenge bytes are attacker-controllable, so
this is Class A.

Discipline:
- `self.nonce[8..32].ct_eq(&mac.as_bytes()[0..24])` via `subtle::ConstantTimeEq`
  (was a short-circuiting `!=` before the CRYPTO-2/HS-04 fix, which leaked how
  many leading MAC bytes a guess matched).

Compliance: ✅ class A satisfied (since CRYPTO-2/HS-04).

### Server-identity pinning (Class C)

`core/src/transport/handshake.rs:476-479` — `process_server_hello` compares
the caller's pinned `HybridVerifyingKey` against the value advertised in
`ServerHello`.

Both values are **public**:
- The pin came from `PhantomListener::verifying_key_bytes()` — published
  out-of-band.
- The `server_hello.server_verify_key` is sent in cleartext during the
  handshake.

A timing leak here reveals only whether the attacker-supplied key matches
the attacker-known pin — no secret information is exposed.

Compliance: ✅ class C — plain `derive(PartialEq)` is correct.

### AEAD tag verification

`core/src/crypto/adaptive_crypto.rs` — `CryptoSession::decrypt*` delegates
to `ring::aead::LessSafeKey::open_in_place`. ring guarantees constant-time
tag comparison for AES-256-GCM and ChaCha20-Poly1305 on supported platforms
(AES-NI / ARMv8 crypto extensions / portable bitsliced ChaCha).

`core/src/crypto/aes_session.rs` — same ring backing.

Compliance: ✅ delegated to ring (audited upstream).

### Hybrid signature verification

`core/src/crypto/hybrid_sign.rs:140-167` — `HybridVerifyingKey::verify`.
Both Ed25519 (`ed25519-dalek`) and ML-DSA-65 (RustCrypto `ml-dsa`)
implementations are CT for the verify path; they reject on any inconsistency
without leaking which byte differed.

Compliance: ✅ delegated to ed25519-dalek + ml-dsa (audited upstream).

### Replay-window bitmap lookups

`core/src/security/replay_window.rs` — bitmap operations on per-stream
sequence numbers. Sequence numbers are **not secret** (they're sent in the
header AAD). No CT requirement.

Compliance: N/A — sequence numbers are public.

### Session ID compares

`core/src/api/session.rs` / `core/src/transport/handshake.rs` — `SessionId`
is `[u8; 32]` (32 bytes). After establishment, the session ID is exchanged
in cleartext per packet (in the `PacketHeader`). It is **not** a
confidentiality secret — it's a routing identifier.

Compliance: ✅ class C — plain `==` is correct.

### Wire-format flag tests

`core/src/transport/types.rs::PacketFlags::contains(...)` — bitmask
operations on flags. Flags are public.

Compliance: N/A — flags are public.

## Outstanding items

None at the time of writing — all known secret comparisons go through
`subtle`. This audit must be re-run when:

1. A new wire field is introduced that involves a secret (e.g., 0-RTT
   replay-window keys in Phase 4.1, ML-DSA-NN per-context signing keys).
2. A new primitive backend is added (e.g., `aws-lc-rs` for FIPS) — verify
   the new backend's CT guarantees.
3. Any `==` is added in `core/src/crypto/` or `core/src/security/` — the
   reviewer must classify it per the table above.

## Tooling

- `subtle = "2"` is in `core/Cargo.toml` and used for every class-A
  comparison.
- Clippy lint `clippy::disallowed_methods` could be configured in a future
  PR to flag `==` on tagged secret-newtypes; not yet wired (current types
  use raw `[u8; N]`).
- No statistical timing test is committed yet. The `dudect` methodology
  could be applied if a regression is suspected, but the inventory above
  shows no operation that takes a code path branching on secret bytes.

## References

- D. J. Bernstein, "Cache-timing attacks on AES" (2005) — motivation for CT
  AES on platforms without AES-NI.
- NIST SP 800-38D — AES-GCM nonce / invocation limits.
- RFC 9180 — HPKE constant-time discipline patterns.
- `subtle` crate documentation — https://docs.rs/subtle
