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
| `WIRE_VERSION` | `6` | `core/src/transport/types.rs` | `PacketHeader.version` (byte 0, HP-masked) |
| `PROTOCOL_VERSION` | `3` | `core/src/transport/handshake.rs` | `ClientHello.version`, transcript-bound |
| `PROTOCOL_VARIANT` | `b"phantom-default-1"` | `core/src/transport/handshake.rs` | leading field of the signed transcript |

A receiver **drops** any data frame whose `header.version != WIRE_VERSION`
(`api/session.rs`), and the server rejects a `ClientHello` whose
`version != PROTOCOL_VERSION` with a `ServerReject` (PROTOCOL.md § 6.10) — *before*
any KEM/signature work. The `PROTOCOL_VARIANT` is the leading field of the signed
handshake transcript (PROTOCOL.md § 6.5/§ 6.7), so a cross-variant peer fails the
signature check even if it forged the cleartext tag. See PROTOCOL.md § 1.

**A fourth constant is agreed off the wire: the AEAD suite.** There is no cipher
field in any message; each peer independently resolves AES-256-GCM vs
ChaCha20-Poly1305 from local CPU capability and derives its keys — and its
header-protection mask primitive — accordingly (PROTOCOL.md § 2). Two peers that
resolve it differently finish the handshake and then fail every packet. Pin one
suite per deployment and pin it on both ends; do not build a probe for it.

**And one asymmetry is not a constant at all: which side swaps.** Every
per-direction key pair is derived once and assigned by role — the initiator
takes the `…-send-…` label as its send key, the responder takes `…-recv-…`
(PROTOCOL.md § 3). Getting this backwards is the single most common way a second
implementation passes every vector in this guide and still cannot exchange a
packet, because no fixture covers it: the vectors freeze the *cleartext* wire
image, and the key-role assignment only shows up under a live AEAD.

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

### Rung 1b — Transport framing (no fixture; still mandatory)

A `PhantomPacket` is not self-delimiting, so something has to carry it. This rung
has no `.bin` because the framing sits *outside* the frozen wire — but a peer
that skips it cannot exchange a byte, and the framing differs per transport:

| Transport | Framing | Spec |
| --- | --- | --- |
| PhantomUDP (the production transport) | 9-byte cleartext envelope `[flags: u8][ConnId: 8]` per datagram, plus an 8-byte fragment subheader when the `FRAG_BIT` is set | PROTOCOL.md § 4.9 |
| TCP (and the mimicry leg's inner stream) | 4-byte big-endian `u32` message length, phase-capped at 64 KiB before the session establishes and 4 MiB after | PROTOCOL.md § 9 |
| WebSocket / WASI / embedded | already message-framed by the substrate; no additional prefix | — |

Two properties of the envelope are easy to get wrong and fail closed only later:
the reserved low five flag bits **must be zero** (a datagram with any of them set
is rejected outright), and the `Initial` packet type carries a *bare* borsh
`ClientHello` from the client but a **discriminant-framed** `ServerReply`
(`[kind: u8] ‖ borsh(body)`) from the server — the asymmetry is deliberate
(PROTOCOL.md § 6).

Because `recv_bytes` is message-framed on every transport, `payload` is simply
the remainder after the 15-byte header (Rung 1) — which is exactly why v6 could
drop the length prefixes. A stream transport that loses message boundaries turns
that simplification into silent corruption.

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
PROTOCOL.md § 3, and note that the negotiated-off-the-wire suite (§ 1 above)
selects the mask primitive as well as the AEAD.

### Rung 4b — The AEAD plaintext codecs

Opening the AEAD gets you a plaintext, not a message. What is inside depends on
the (authenticated) flags, and each shape has its own grammar in PROTOCOL.md
§ 4.5 / § 4.8:

| Flag | Plaintext |
| --- | --- |
| `RELIABLE` | `stream_offset: u32 be` then the application bytes — a frame shorter than the 4-byte prefix is malformed |
| `ACK` | a `Sack`, scoped to the packet's `stream_id` |
| `WINDOW_UPDATE` | exactly 4 bytes: a big-endian `u32` of *relative* credit |
| `PATH_VALIDATION` | exactly 32 bytes: a challenge or its echo |
| `KEEPALIVE` | empty (PING); `KEEPALIVE \| ACK` is the PONG |
| `COALESCED` | `[count: u16][len: u16][payload]…` |
| `PADDED` | strip the `‹zeros› ‖ pad_n: u16 be` trailer **first**, then interpret the rest by the other flags |

A minimal peer needs `RELIABLE` and `ACK` to move data at all; `COALESCED` is
receive-only in this implementation (nothing emits a bundle), and `PADDED` /
`COVER` are opt-in shaping a peer may simply never enable. Every one of these is
inside the AEAD, so none of them is frozen by a `.bin` and none of them is a
`WIRE_VERSION` concern — but a mismatch here reads as data corruption, not as a
parse error.

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
- [ ] It agrees with its peer on the AEAD suite (not negotiated — § 1) and assigns the per-direction keys by role, initiator un-swapped and responder swapped (§ 1).
- [ ] Its AEAD / KDF / hash / ML-KEM / ML-DSA primitives reproduce every KAT in `cavp.rs` (Rung 0).
- [ ] `encode(value)` equals each packet `.bin`, and `decode(.bin)` equals the value, for the four packet fixtures (Rung 1).
- [ ] It frames packets for its transport — the 9-byte PhantomUDP envelope with zeroed reserved bits, or the 4-byte big-endian TCP prefix (Rung 1b).
- [ ] The same holds for all borsh handshake / sub-struct fixtures (Rung 2).
- [ ] Its transcript hash equals `transcript_hash.bin` (Rung 3).
- [ ] Its AEAD nonce/AAD construction and HP masking reproduce PROTOCOL.md § 4.6 / § 5; a tampered AAD byte (version included) fails decryption with no oracle (Rung 4).
- [ ] It reads the AEAD plaintext by flag — reliable offset prefix, SACK, window credit, path challenge, padding trailer (Rung 4b).
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

---

## 7. Last verified against the code

Checked against the source on **2026-08-15**, commit `41183f49` — the same
sync as PROTOCOL.md § 13, which carries the itemised list of what was
re-derived. Every fixture byte count quoted above was read off
the committed `.bin` files at that commit.
