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

`core/src/transport/handshake.rs` — `validate_cookie` (reached from
`cookie_pow_gate`). The cookie is an HMAC-SHA-256 tag over the client IP
string and the 5-minute bucket index, keyed by an hour-rotating secret
derived from the listener's master secret. Validation accepts any of the
2×2 combinations of (current/previous hour) × (current/previous bucket).

Discipline:
- Each `cookie == expected_for_(hour, bucket)` performed via
  `cookie.ct_eq(&expected)` returning a `subtle::Choice`.
- Accept signal is **accumulated** as `accept |= cookie.ct_eq(...)` over all
  four candidates. The function never branches on a per-candidate result,
  never short-circuits, and always evaluates all four HMACs.
- Final conversion: `bool::from(accept)` (`Choice` → `bool`) happens once at
  the return.

Compliance: ✅ class A satisfied.

### Path-validation challenge response (Class A)

`core/src/transport/path.rs` — `Session::complete_path_validation`.
The 32-byte challenge is server-issued and unique per `(path_id, session)`.
The response from the peer is attacker-controllable.

Discipline:
- `expected.ct_eq(response).into()` returns `bool` via `subtle::Choice`.
- No branching on intermediate state; failure transitions the path to
  `Failed` regardless of which byte mismatched.

Compliance: ✅ class A satisfied.

### PoW solution verification (Class A)

`core/src/crypto/pow.rs` — `PoWChallenge::verify`. Solution is attacker-
controllable (the client submits it).

Discipline:
- The PoW invariant is "leading zero bits of `BLAKE3(nonce ‖ solution_le)`
  ≥ difficulty" — an **unkeyed** hash over public inputs. The hash is
  computed in full regardless of the result; the zero-bit count is
  evaluated by reading bytes left-to-right and comparing each byte to
  `0u8`. The early termination happens on a non-zero byte, but the loop
  bound is `difficulty / 8 + 1` — which is determined by the **server's**
  policy, not the attacker. No secret bytes flow into the loop counter.

Compliance: ✅ class A satisfied. (The early-exit is on `difficulty`, a
public server policy parameter; not on a secret.)

### PoW challenge-integrity MAC (Class A) — CRYPTO-2/HS-04

`core/src/crypto/pow.rs` — `PoWChallenge::verify` compares the embedded
24-byte challenge MAC (keyed by the server's per-hour secret) against the
recomputed value. The submitted challenge bytes are attacker-controllable, so
this is Class A.

Discipline:
- `self.nonce[8..32].ct_eq(&mac.as_bytes()[0..24])` via `subtle::ConstantTimeEq`
  (was a short-circuiting `!=` before the CRYPTO-2/HS-04 fix, which leaked how
  many leading MAC bytes a guess matched).

Compliance: ✅ class A satisfied (since CRYPTO-2/HS-04).

### 0-RTT resumption binder (Class A)

`core/src/transport/handshake.rs` — `HandshakeServer::has_valid_resume`
(handshake.rs:809) and the resume fast path in `process_client_hello`
(handshake.rs:902) compare the client-supplied
`ClientHello.resumption_binder` against `derive_resumption_binder(secret,
rid, nonce)` (handshake.rs:495), which is keyed by the cached 32-byte
resumption secret. The presented binder is fully attacker-controllable.

Discipline:
- `bool::from(presented.ct_eq(&expected))` via `subtle::ConstantTimeEq`.
- No short-circuit before the compare; a mismatch simply yields "no
  resume" and the ticket is left untouched (Security Invariant 9).

Compliance: ✅ class A satisfied.

### Server-identity pinning (Class C)

`core/src/transport/handshake.rs` — `process_server_hello` compares
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
to `ring::aead::LessSafeKey::open_in_place` on the default build and to
`aws_lc_rs::aead` under `--features fips` (the fips build is ring-free).
Both guarantee constant-time tag comparison for AES-256-GCM — and, on the
default build, ChaCha20-Poly1305 — on supported platforms (AES-NI / ARMv8
crypto extensions / portable bitsliced ChaCha).

`core/src/crypto/aes_session.rs` — same backing.

Compliance: ✅ delegated to ring / aws-lc-rs (both audited upstream).

### Hybrid signature verification

`core/src/crypto/hybrid_sign.rs` — `HybridVerifyingKey::verify`.
Both Ed25519 (`ed25519-dalek`) and ML-DSA-65 (RustCrypto `ml-dsa`)
implementations are CT for the verify path; they reject on any inconsistency
without leaking which byte differed.

Compliance: ✅ delegated to ed25519-dalek + ml-dsa (audited upstream).

### Replay-window bitmap lookups

`core/src/security/replay_window.rs` — bitmap operations on the single
per-direction u64 **packet number** (`WINDOW_BITS = 1024`, RFC 4303
§3.4.3). Packet numbers are **not secret** — they are covered by the AEAD
AAD and recoverable from the header once header protection is stripped.
No CT requirement.

Compliance: N/A — packet numbers are public.

### Session ID compares

`core/src/api/session.rs` / `core/src/transport/handshake.rs` — `SessionId`
is `[u8; 32]`. Since WIRE v5 it is **never transmitted**: it is bound into
the 47-byte AEAD AAD image only, and the receiver fills it from session
context before the AEAD open. It is a routing/context identifier, not a
confidentiality secret, and both peers already hold it.

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
2. A new primitive backend is added. The `aws-lc-rs` FIPS backend has
   already landed and is covered above; any further backend must be
   re-classified here.
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
