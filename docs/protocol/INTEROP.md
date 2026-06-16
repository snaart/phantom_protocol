# Phantom Protocol — Interoperability & Conformance Guide

This document is the **clean-room implementer's entry point**: it tells you how to
build a second, wire-compatible Phantom Protocol peer and how to *prove* it
conforms, using artifacts already committed to this repository.

It deliberately does **not** restate the byte grammar — that lives in the single
canonical spec, [`PROTOCOL.md`](./PROTOCOL.md), and duplicating it here would only
invite drift. Instead this guide is a **map + checklist**: it points at the exact
canonical section for each wire element, names the committed reference vector that
freezes it, and gives the order in which to bring an implementation up.

- **Canonical grammar:** [`docs/protocol/PROTOCOL.md`](./PROTOCOL.md) (offsets, widths, endianness, KDF labels, state machine).
- **Frozen reference bytes:** [`core/tests/wire_vectors/*.bin`](../../core/tests/wire_vectors/) (+ its [`README.md`](../../core/tests/wire_vectors/README.md)).
- **Independent (non-Rust) decoder/encoder:** [`tests/wire_vectors_decode.py`](../../tests/wire_vectors_decode.py).
- **Primitive known-answer tests:** [`core/tests/cavp.rs`](../../core/tests/cavp.rs).

> **Scope: the default (non-FIPS) build only.** The `--features fips` build is a
> *distinct, non-interoperable* wire (different `PROTOCOL_VARIANT`, ECDH-P-256
> 65-byte classical KEM key, HKDF-SHA-256 KDF, ChaCha20 rejected). A FIPS peer and
> a default peer **cannot** interoperate by design (§ 9 below). Everything here
> describes the default build.

---

## 1. Version handshake-of-constants

Phantom Protocol does **not** negotiate versions on the wire — both peers must be
built for the same triple, and any mismatch is a hard failure (never a silent
downgrade). Pin these first:

| Constant | Value (default build) | Source of truth | Wire role |
| --- | --- | --- | --- |
| `WIRE_VERSION` | `6` | `core/src/transport/types.rs:79` | `PacketHeader.version` (byte 0, HP-masked) |
| `PROTOCOL_VERSION` | `3` | `core/src/transport/handshake.rs:56` | `ClientHello.version`, transcript-bound |
| `PROTOCOL_VARIANT` | `b"phantom-default-1"` | `core/src/transport/handshake.rs:48` | leading field of the signed transcript |

A receiver **drops** any data frame whose `header.version != WIRE_VERSION`
(`api/session.rs`), and the server rejects a `ClientHello` whose
`version != PROTOCOL_VERSION` with a `ServerReject` (PROTOCOL.md § 6.10) — *before*
any KEM/signature work. The `PROTOCOL_VARIANT` is the leading field of the signed
handshake transcript (PROTOCOL.md § 6.5/§ 6.7), so a cross-variant peer fails the
signature check even if it forged the cleartext tag. See PROTOCOL.md § 1.

---

## 2. Bring-up order (conformance ladder)

Build and verify in this order — each rung is independently checkable against a
committed vector before you attempt the next, so you never debug the handshake and
the packet codec at the same time.

### Rung 0 — Primitives (no wire yet)

Confirm your crypto library reproduces the known-answer tests in
[`core/tests/cavp.rs`](../../core/tests/cavp.rs) before touching the wire:

| Primitive | KAT origin | Vector location |
| --- | --- | --- |
| AES-256-GCM | McGrew & Viega Test Case 13 | inline const, `cavp.rs::aes_256_gcm_kat` |
| HKDF-SHA-256 | RFC 5869 § A.1 | inline const, `cavp.rs::hkdf_sha256_rfc5869_a1` |
| SHA-256 | FIPS 180-4 § 5.3.3 (`"abc"`, empty) | inline const, `cavp.rs::sha_256_kat` |
| ML-KEM-768 | encap/decap round-trip (FIPS 203) | `cavp.rs::ml_kem_768_encap_decap_kat` |
| ML-DSA-65 | sign/verify + tamper (FIPS 204) | `cavp.rs::ml_dsa_65_sign_verify_kat` |

These are always-on (`cargo test --manifest-path core/Cargo.toml --test cavp`).
The ML-KEM / ML-DSA entries are round-trip (not byte-exact external ACVP) because
the RustCrypto crates do not expose a deterministic sign/encaps seam; treat the
canonical field lengths (1184 / 1088 / 1952 / 3309 bytes) as the conformance hook.

### Rung 1 — Packet codec (hand-rolled big-endian, no crypto)

Implement `PacketHeader` (15 wire bytes) and `PhantomPacket`
(`header(15) ‖ payload`, **no length prefixes** in v6) per PROTOCOL.md § 4.1–4.3.

| Vector | Freezes |
| --- | --- |
| `packet_header.bin` (15 B) | the 15-byte big-endian header layout |
| `phantom_packet_data.bin` (79 B) | header + 64-byte payload, no length prefix |
| `phantom_packet_ack.bin` (15 B) | an `ACK`-only header, empty payload |
| `phantom_packet_extensions.bin` (31 B) | `extensions` is **off-wire** in v6 (header + payload only) |

Cross-check your encoder/decoder against
[`tests/wire_vectors_decode.py`](../../tests/wire_vectors_decode.py), which decodes
**and** re-encodes each fixture with Python stdlib only — if your bytes and the
Python encoder's bytes both equal the `.bin`, the grammar is genuinely shared, not
self-referential.

### Rung 2 — Handshake messages (borsh, little-endian)

Implement the borsh structs in PROTOCOL.md § 6.2–6.4 / § 6.10. Borsh rules
(reproduced by the Python decoder): fixed arrays raw, `Vec<u8>` length-prefixed
with a little-endian `u32`, `Option` a 1-byte tag (0/1), `bool` a 1-byte value;
fields concatenate in **declaration order** (load-bearing).

| Vector | Message |
| --- | --- |
| `client_hello_minimal.bin` (3267 B) | `ClientHello`, all optional fields `None` |
| `client_hello_full.bin` (3455 B) | `ClientHello` with cookie + PoW + resume + binder + 48-byte early-data |
| `server_hello.bin` (6554 B) | `ServerHello`, `early_data_accepted = true` |
| `server_hello_rejected.bin` (6554 B) | `ServerHello`, `early_data_accepted = false` |
| `hello_retry_request_cookie.bin` (34 B) | `HelloRetryRequest`, cookie only |
| `hello_retry_request_pow.bin` (35 B) | `HelloRetryRequest`, PoW challenge present |
| `hybrid_key_package.bin` / `hybrid_ciphertext.bin` / `hybrid_verifying_key.bin` / `hybrid_signature.bin` | the hybrid KEM/sig sub-structs |
| `pow_challenge.bin` / `pow_solution.bin` | the proof-of-work fields |

> The handshake vectors use **deterministic filler** of the real field lengths,
> not valid KEM/signature material — they freeze the serialization *container*.
> Validating the PQ encodings themselves is Rung 0's job.

### Rung 3 — Transcript signing

Compute the signed transcript hash per PROTOCOL.md § 6.5. The signing input is
`SHA256(borsh(HandshakeTranscript))` over a **7-field** struct whose leading field
is `protocol_variant` and whose coverage includes the *whole* `ClientHello`
(early-data ciphertext included) and `early_data_accepted` — this is what makes the
version (Invariant 7) and build-variant (Invariant 10) downgrade-resistant.

| Vector | Freezes |
| --- | --- |
| `transcript_hash.bin` (32 B) | the real `compute_transcript_hash` output over the deterministic transcript (asserted by the lib unit test `transport::handshake::tests::transcript_hash_wire_vector`) |

If your transcript hash matches this fixture byte-for-byte, your signing input is
wire-compatible and your signatures will verify against a reference peer.

### Rung 4 — AEAD record protection + header protection

Wire up the data plane per PROTOCOL.md § 5 (AEAD: 12-byte nonce =
`prefix(4) ‖ packet_number_be(8)`; AAD = the reconstructed 47-byte header image)
and § 4.6 (header protection: per-direction session-stable HP keys; a mask derived
from a sample of the record's AEAD ciphertext is applied to the whole 15-byte wire
header — the exact sample offset, cipher, and apply step are in § 4.6). The HP mask
is keyed crypto and is **not** frozen as a `.bin` (it would require committing key
material); it is verified in Rust separately. To interoperate you must reproduce
the HP key-derivation labels exactly — see the KDF label inventory in
PROTOCOL.md § 3.

### Rung 5 — Migration & liveness (optional for a minimal peer)

The rotating outer connection ID, path validation, and liveness machinery are
PROTOCOL.md § 4.7 and § 12. A minimal single-path client can defer these; a peer
that wants seamless Wi-Fi↔cellular migration must implement the CID chain
(§ 4.7) and the path-validation grammar (§ 12).

---

## 3. The independent decoder as a conformance oracle

[`tests/wire_vectors_decode.py`](../../tests/wire_vectors_decode.py) is a complete
second implementation of the wire grammar in dependency-free Python: it decodes
every committed fixture to a structured value **and** re-encodes that value back to
bytes, asserting `encode(decode(fixture)) == fixture`. It exists precisely so the
grammar is not self-referential (Rust-encodes ↔ Rust-decodes would move together on
a regression). Run it as the reference cross-check while building your peer:

```sh
python3 tests/wire_vectors_decode.py     # exits non-zero on any mismatch
```

Use it two ways: (1) read it as a compact, executable restatement of the grammar;
(2) feed *your* serializer's output through its decoder (and vice-versa) to localize
a divergence to a single field.

---

## 4. Regenerating the vectors (intentional wire change only)

A failing vector means an on-wire byte moved. If that change is **intentional**,
it is by definition a new wire revision: bump `WIRE_VERSION` / `PROTOCOL_VERSION`
in `core/src/transport/{types,handshake}.rs`, update PROTOCOL.md in the **same**
change, regenerate, and review the diff:

```sh
PHANTOM_REGEN_WIRE_VECTORS=1 cargo test --manifest-path core/Cargo.toml --lib
PHANTOM_REGEN_WIRE_VECTORS=1 cargo test --manifest-path core/Cargo.toml --test wire_vectors
python3 tests/wire_vectors_decode.py     # confirm the independent decoder still agrees
```

Never hand-edit a `.bin`. See `core/tests/wire_vectors/README.md`.

---

## 5. Conformance checklist

A peer is wire-conformant with the default build of this repository when:

- [ ] It is built for `WIRE_VERSION = 6`, `PROTOCOL_VERSION = 3`, `PROTOCOL_VARIANT = phantom-default-1`, and treats a mismatch as a hard error (no downgrade).
- [ ] Its AEAD / KDF / hash / ML-KEM / ML-DSA primitives reproduce every KAT in `cavp.rs` (Rung 0).
- [ ] `encode(value)` equals each packet `.bin`, and `decode(.bin)` equals the value, for the four packet fixtures (Rung 1).
- [ ] The same holds for all borsh handshake / sub-struct fixtures (Rung 2).
- [ ] Its transcript hash equals `transcript_hash.bin` (Rung 3).
- [ ] Its AEAD nonce/AAD construction and HP masking reproduce PROTOCOL.md § 4.6 / § 5; a tampered AAD byte (version included) fails decryption with no oracle (Rung 4).
- [ ] `tests/wire_vectors_decode.py` agrees with the peer's serializer in both directions (§ 3).
- [ ] (If migrating) the CID chain and path-validation grammar match PROTOCOL.md § 4.7 / § 12 (Rung 5).

---

## 6. FIPS interop (explicitly out of scope)

The `--features fips` build is a separate, intentionally non-interoperable wire:
`PROTOCOL_VARIANT = phantom-fips-1`, a 65-byte ECDH-P-256 classical KEM key,
HKDF-SHA-256 in place of every blake3 KDF call, AES-256-GCM only (ChaCha20-Poly1305
is rejected at the handshake). Because `protocol_variant` leads the signed
transcript, a FIPS peer and a default peer fail each other's signature check on the
first message — they do not, and are not meant to, interoperate. A FIPS↔FIPS
conformance set would need its own committed vectors (the wire-vector test compiles
to nothing under `--features fips`). See `docs/compliance/fips-readiness.md`.
