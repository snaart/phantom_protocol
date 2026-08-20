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
| `WIRE_VERSION` | `8` | `core/src/transport/types.rs` | `PacketHeader.version` (byte 0, HP-masked) |
| `PROTOCOL_VERSION` | `5` | `core/src/transport/handshake.rs` | `ClientHello.version`, transcript-bound |
| `PROTOCOL_VARIANT` | `b"phantom-default-1"` | `core/src/transport/handshake.rs` | leading field of the signed transcript |

A receiver **drops** any data frame whose `header.version != WIRE_VERSION`
(`api/session.rs`), and the server rejects a `ClientHello` whose
`version != PROTOCOL_VERSION` with a `ServerReject` (PROTOCOL.md § 6.10) — *before*
any KEM/signature work. The `PROTOCOL_VARIANT` is the leading field of the signed
handshake transcript (PROTOCOL.md § 6.5/§ 6.7), so a cross-variant peer fails the
signature check even if it forged the cleartext tag. See PROTOCOL.md § 1.

Note the asymmetry between those two refusals, because it decides which one you will
actually observe while building: the data-frame drop is **silent** — no reply, nothing the
sender can distinguish from a black hole — while the `ServerReject` names both versions.
That is why the two constants move together even when only the data plane changed, as at
`WIRE_VERSION 6 → 7` / `PROTOCOL_VERSION 3 → 4` and again at `7 → 8` / `4 → 5`. If your
peer establishes a session and then moves no data, check the version pair before anything
else.

The `7 → 8` bump is worth reading as a worked example, because it is the case where nothing
on the header moved at all and the pairing rule is doing all the work. v8 gave the `CONTROL`
flag a one-byte subtype inside its AEAD plaintext (PROTOCOL.md § 4.11); the header is byte
for byte what it was at v7 apart from the version constant itself. Note carefully which half
of the pair does what, because it is easy to get backwards. The `WIRE_VERSION` half is what
stops a v7 receiver from ever reaching its flag dispatch with a v8 frame: the version check
is step 1 of § 4.3 and it **drops** the frame there, before any flag is examined, so nothing
is misread and nothing is corrupted. What that leaves is a peer that completes a handshake
and then silently discards every packet it is sent — the most expensive failure a protocol
can hand an implementer, because it looks like a working connection. The `PROTOCOL_VERSION`
half is what converts that into a diagnosis: a typed `ServerReject` naming both versions,
before a session exists. If you take one habit from this section, take this one: a change to
what is *inside* the AEAD is a wire revision exactly as much as a change to the header —
the header version will enforce it either way, and your only choice is whether the
enforcement is legible.

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

| Transport | Framing | Source |
| --- | --- | --- |
| PhantomUDP (the production transport) | 9-byte cleartext envelope `[flags: u8][ConnId: 8]` per datagram, plus an 8-byte fragment subheader when the `FRAG_BIT` is set — PROTOCOL.md § 4.9 | `transport/phantom_udp/envelope.rs` |
| TCP | `[len: u32 big-endian] ‖ message`, the declared length capped at 64 KiB before the session establishes and 4 MiB after — PROTOCOL.md § 9 | `api/tcp_transport.rs` |
| WASI (`wasi:sockets/tcp`) | the same `[len: u32 big-endian] ‖ message`; the cap is a flat 4 MiB rather than phase-gated | `transport/legs/wasi.rs` |
| Embedded (UART/USB) | the same `[len: u32 big-endian] ‖ message`; the cap is the leg's fixed buffer size `N` | `transport/legs/embedded/framing.rs` |
| Mimicry (TLS-over-TCP, `mimicry` feature) | the same `[len: u32 big-endian] ‖ message` byte-stream, then chunked `[chunk_len: u16 big-endian] ‖ chunk` into TLS ApplicationData records — PROTOCOL.md § 9.1 | `transport/legs/mimic_tls/record.rs` |
| WebSocket (browser) | none — the substrate delivers whole binary messages | `transport/legs/websocket.rs` |

**Four of the five stream transports share one framing**, byte-for-byte: a
4-byte big-endian message length. Only the caps differ, and a cap is a receive-side
refusal, not an encoding — so an embedded client and a TCP server frame each
other's messages identically. WebSocket is the sole leg whose substrate already
carries message boundaries, and it is the only one that adds no prefix; assuming
that of the others desynchronizes the stream on the first message, which is the
failure this rung exists to prevent.

Two properties of the PhantomUDP envelope are easy to get wrong and fail closed
only later: the reserved low five flag bits **must be zero** (a datagram with any
of them set is rejected outright), and the `Initial` packet type carries a *bare*
borsh `ClientHello` from the client but a **discriminant-framed** `ServerReply`
(`[kind: u8] ‖ borsh(body)`) from the server — the asymmetry is deliberate
(PROTOCOL.md § 4.9 / § 6).

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
| `WINDOW_UPDATE` | exactly 8 bytes: a big-endian `u64` **cumulative limit** — the total the receiver will let you send on that stream. Apply it as a maximum, never a sum |
| `PATH_VALIDATION` | exactly 32 bytes: a challenge or its echo |
| `KEEPALIVE` | empty (PING); `KEEPALIVE \| ACK` is the PONG |
| `CONTROL` | `[subtype: u8]` then whatever that subtype defines — nothing, for the only assignment so far (PROTOCOL.md § 4.11) |
| `COALESCED` | `[count: u16][len: u16][payload]…` |
| `PADDED` | strip the `‹zeros› ‖ pad_n: u16 be` trailer **first**, then interpret the rest by the other flags |

A minimal peer needs `RELIABLE` and `ACK` to move data at all; `COALESCED` is
receive-only in this implementation (nothing emits a bundle), and `PADDED` /
`COVER` are opt-in shaping a peer may simply never enable. Every one of these is
inside the AEAD, so none of them is frozen by a `.bin` — but do not read that as
meaning they are not a `WIRE_VERSION` concern. Two of the last two revisions changed
nothing but a plaintext in this table (`WINDOW_UPDATE` at v7, `CONTROL` at v8) and
both bumped the version pair, for the reason § 1 gives: a mismatch here reads as data
corruption rather than as a parse error, so the version check is the only place it
can be caught.

**`CONTROL` is the one row a peer may not skip.** The others degrade gracefully —
never emit a `COALESCED` bundle and you simply never receive one; ignore `PADDED` and
you were never sent a padded frame. `CONTROL` is different because the dispatch is
not optional even when the *frame* is. A peer that omits the branch does not fail to
act on a control frame; it falls through to its application-data path and hands the
subtype byte to its caller. So implement the branch first and its contents second:

- Read the leading byte after the padding trailer is off. `0x01` is `CLOSE` — the
  peer is ending the session; tear down as you would on any other teardown. It is
  unacknowledged: do not `ACK` it, do not answer it with a close of your own.
- **Do not tear down on the copy you first see — drain first.** The `CLOSE` is not
  `RELIABLE` and nothing retransmits the application data it may have overtaken, and
  on a datagram path one position of reordering is enough for it to. Record the close,
  keep processing inbound for a bounded window (PROTOCOL.md § 4.11 gives the sizing
  and both of its bounds), deliver what arrives, send nothing new, and tear down at
  the end of it. This is the receiver rule most likely to be missed, because a peer
  that omits it interoperates perfectly on a loopback test and silently truncates its
  peers' last writes in production.
- Drop the frame on **every** other byte, `0x00` included, and drop it if the
  plaintext is empty. Never read a missing or zero byte as a default.
- **Return on all of those paths.** That, not the `CLOSE` handling, is the
  conformance requirement: sending the frame is optional and receiving it correctly
  is not.

A peer that never sends a `CLOSE` is fully conformant — its peer falls back to the
liveness timer of PROTOCOL.md § 12.4 and reaches the same verdict more slowly, which
is what every peer did before v8. Sending one is a courtesy to the other end's
resources; dispatching one is a correctness obligation to your own caller's byte
stream.

Three of those shapes — `RELIABLE`, `ACK`, `WINDOW_UPDATE` — are scoped by the
header's `stream_id`, and that id is allocated by parity: initiator odd from 3,
responder even from 2, with 0 and 1 reserved (PROTOCOL.md § 4.4). It is the rule
here with the least behind it: every
committed vector carries a single hard-coded id, so a peer that allocates in the
wrong parity passes every check in this guide and then quietly merges its stream
with its peer's.

The flags combine, so the table above is only half the rule: which branch claims
a packet carrying several of them is fixed, and PROTOCOL.md § 4.3 gives the
receiver's dispatch order end to end — including the three orderings that are not
guessable (`PADDED` strips before anything parses; `KEEPALIVE` is tested before
`ACK`, because a PONG is `KEEPALIVE | ACK` and is not a `Sack`; and `CONTROL` is
dispatched *after* the AEAD open and the replay window but *before* everything that
could deliver data). That last one is a security property, not a layout choice:
above the AEAD gate a one-byte `CLOSE` would end any session whose connection id
could be guessed, and above the replay window a recorded one would be the same
primitive with a capture step in front of it. Below both, a repeat is refused before
your branch runs, so the branch needs no state of its own. The same section states
what to do with a flag you do not recognise: ignore it, never reject the packet.

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

- [ ] It is built for `WIRE_VERSION = 8`, `PROTOCOL_VERSION = 5`, `PROTOCOL_VARIANT = phantom-default-1`, and treats a mismatch as a hard error (no downgrade).
- [ ] It agrees with its peer on the AEAD suite (not negotiated — § 1) and assigns the per-direction keys by role, initiator un-swapped and responder swapped (§ 1).
- [ ] Its AEAD / KDF / hash / ML-KEM / ML-DSA primitives reproduce every KAT in `cavp.rs` (Rung 0).
- [ ] `encode(value)` equals each packet `.bin`, and `decode(.bin)` equals the value, for the four packet fixtures (Rung 1).
- [ ] It frames packets for its transport — the 9-byte PhantomUDP envelope with zeroed reserved bits, or the 4-byte big-endian message prefix every stream leg except WebSocket carries (Rung 1b).
- [ ] It allocates stream ids in its own parity — odd from 3 as the initiator, even from 2 as the responder, with 0 and 1 reserved (PROTOCOL.md § 4.4).
- [ ] The same holds for all borsh handshake / sub-struct fixtures (Rung 2).
- [ ] Its transcript hash equals `transcript_hash.bin` (Rung 3).
- [ ] Its AEAD nonce/AAD construction and HP masking reproduce PROTOCOL.md § 4.6 / § 5; a tampered AAD byte (version included) fails decryption with no oracle (Rung 4).
- [ ] It reads the AEAD plaintext by flag — reliable offset prefix, SACK, cumulative window limit, path challenge, padding trailer (Rung 4b).
- [ ] It dispatches a `CONTROL` frame on its leading subtype byte and **returns on every arm**, the unknown subtype and the empty plaintext included, so no control byte can reach its application (Rung 4b, PROTOCOL.md § 4.11). Emitting a `CLOSE` is optional; dispatching one is not.
- [ ] It applies an inbound `WINDOW_UPDATE` as a maximum, counts its own sent bytes once per byte, and never sends past the highest limit received (§ 4.5 of PROTOCOL.md).
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
the committed `.bin` files at that commit, and every row of the Rung 1b framing
table was read out of the leg named in its Source column rather than inferred
from the transport's name.

Two data-plane revisions have landed since and are reflected above:
`WIRE_VERSION 6 → 7` / `PROTOCOL_VERSION 3 → 4` (the cumulative `WINDOW_UPDATE`
limit) and `7 → 8` / `4 → 5` (the `CONTROL` subtype byte and the `CLOSE`
announcement, Rung 4b). Both changed an AEAD plaintext and no header byte, so no
fixture grammar moved — only the version byte inside the four packet fixtures and
the two `ClientHello` fixtures, and `transcript_hash.bin` with them.
