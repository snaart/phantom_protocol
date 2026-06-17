# Phantom Protocol Wire Protocol

Specification of the wire format, handshake state machine, and key-derivation
constructions used by `phantom_protocol` 0.x. There is exactly **one** wire
protocol: a single packet shape, a single handshake, and a single pinned
version byte. The protocol is **not negotiated** — pre-1.0 there are no
deployed peers, so there is no version handshake, no fallback, and no
protocol-*version* migration path. The one surviving version byte is a
tamper-check anchor and a hook for a future, deliberate bump. (*Connection*
migration — one session surviving a network-path change without re-handshaking
— is a separate axis on the **same** wire; see § 12.)

Audit-friendly format: every field has its Rust source-of-truth pinned with
`file:line`. The canonical wire bytes are the byte-frozen vectors in
`core/tests/wire_vectors/` (§ 11) — the Rust types produce them and this doc
narrates the grammar; all three are checked against each other in CI.

**Building a second, wire-compatible peer?** Read this spec for the grammar, then
follow the step-by-step conformance ladder in
[`INTEROP.md`](./INTEROP.md) — it sequences these sections against the committed
reference vectors, the independent Python decoder, and the CAVP primitive KATs.

---

## 1. Versioning policy

Two pinned constants identify the protocol. Neither is negotiated; a decoder
that sees any other value drops the frame (packets) or rejects the handshake
(`ClientHello`).

| Constant | Value | Source | Where it lives on the wire |
| --- | --- | --- | --- |
| `WIRE_VERSION` | `6` | `core/src/transport/types.rs` | `PacketHeader.version` byte (now HP-masked, inside the 15-byte header — § 4.2) |
| `PROTOCOL_VERSION` | `3` | `core/src/transport/handshake.rs:56` | `ClientHello.version`, transcript-bound |

`WIRE_VERSION` is `4`: it went `1 → 2` when the packet codec moved from
`alkahest` to the explicit big-endian layout in § 4.2, then `2 → 3` (Phase 4 /
P4.0) when the AEAD packet identity became a single **per-direction monotonic
`u64` packet number** — the header dropped the dead `ack_delay` field and widened
`sequence: u32` to `packet_number: u64` (45 → 47 bytes; § 4.2 / § 5) — then
`3 → 4` (T4.6) when **header protection** (QUIC RFC 9001 § 5.4) landed: the 47-byte
header was **reordered** so the 14 variable bytes (`packet_number ‖ flags ‖
stream_id ‖ epoch ‖ path_id`) form a contiguous span at offset `[33..47]` that is
**XOR-masked on the wire**, leaving only `version ‖ session_id` cleartext (§ 4.2 /
§ 4.6). Then `4 → 5` (ε / CID-collapse) **dropped the 32-byte inner `session_id`
from the data-plane wire entirely** — it stays in the AEAD AAD, reconstructed from
session context (§ 5) — shrinking the header `47 → 15` bytes. Then `5 → 6`
(**anti-fingerprint diet**, direction #4) removed the last two structural
fingerprints: **(a)** the masked region grew to cover the WHOLE 15-byte header so
the **`version` byte is itself HP-masked** (no constant cleartext byte left on the
data-plane wire), and **(b)** the two cleartext `u32` length prefixes
(`payload_len` / `ext_len`) were **dropped** — `payload` is now the message
remainder (`recv_bytes` is message-framed on every transport, so they were pure
redundancy) and `extensions` left the data-plane wire — saving 8 bytes/packet
(§ 4.1 / § 4.2 / § 4.6). v6 also adds opt-in **encrypted size padding** (PADÉ
bucketing, the `PADDED` flag) so the datagram size no longer tracks the payload
size (§ 4.8). The sole routing identifier is the outer 8-byte UDP `ConnId`,
which **rotates** on each migration (§ 4.7) — symmetrically for **both** a client- and
a server-initiated migration (both directions, EPS-02 closed by A2a; § 12.5). The handshake (`PROTOCOL_VERSION`) is unchanged by T4.6, ε, or v6.
`PROTOCOL_VERSION` is `3` (bumped
`1 → 2` when the signed transcript began covering the 0-RTT verdict
`early_data_accepted` (H2) and `ClientHello` gained the `resumption_binder`
proof-of-possession field (HS-03); `2 → 3` (T4.3) when `ServerHello`'s
`server_key_package` was replaced by a 32-byte `server_nonce`, changing the
signed-transcript content; handshakes across these versions cannot interoperate
because the signed transcript content differs). They exist so that:

- a tampered frame / hello that flips the byte is rejected up front
  (`PacketHeader.version != WIRE_VERSION` → drop; `ClientHello.version !=
  PROTOCOL_VERSION` → the server returns a typed `ServerReject`, see below), and
- a future protocol revision can deliberately increment one or both, gated by
  a code change rather than runtime negotiation.

**Unsupported-version signal (`ServerReject`).** When a `ClientHello.version`
is not `PROTOCOL_VERSION`, the server does not drop silently — it replies with a
small typed `ServerReject` frame *before* any KEM / signature work:

| Offset | Field | Size | Notes |
|---|---|---|---|
| 0 | `marker` | 4 | `= b"PRJ1"` (`SERVER_REJECT_MARKER`); an extra sanity check on top of the T4.4 discriminant byte (`kind = 2`) that frames the reply |
| 4 | `code` | 1 | reject reason; `1 = REJECT_UNSUPPORTED_VERSION` |
| 5 | `supported_version` | 1 | the `PROTOCOL_VERSION` this server speaks |

The client surfaces this as a hard error reporting both versions and **does not
auto-downgrade** to `supported_version` — an attacker-injected reject must not
be able to force a protocol downgrade, and the version is transcript-bound
(Invariant 7). A newer client thus learns *what* the old server speaks (an
actionable diagnostic) without weakening downgrade resistance. The contract is
symmetric: a future server meeting an older client whose `version` it no longer
accepts uses the same frame. `ServerReject` is an additive handshake message —
it does not alter the `ServerHello` / `HelloRetryRequest` / `PhantomPacket`
layouts, so the frozen wire vectors are unaffected.

`PROTOCOL_VARIANT` is an **orthogonal build-variant tag**, not a version. It
distinguishes the default build from the FIPS build and is unchanged by the
single-protocol collapse — see § 6.7.

There is no `VersionedPacket` enum and no handshake envelope. The wire is a
bare `PhantomPacket`; the handshake messages are bare borsh structs.

---

## 2. Cryptographic primitives

| Role | Primitive (default build) | Primitive (`--features fips`) | Crate |
| --- | --- | --- | --- |
| Classical KEM | X25519 | ECDH-P-256 | `x25519-dalek` / `aws-lc-rs` |
| Post-quantum KEM | ML-KEM-768 (FIPS 203) | ML-KEM-768 (FIPS 203) | `ml-kem = 0.2` (RustCrypto pure-Rust) |
| Classical signature | Ed25519 | Ed25519 | `ed25519-dalek` |
| Post-quantum signature | ML-DSA-65 (FIPS 204) | ML-DSA-65 (FIPS 204) | `ml-dsa = 0.1.0` (RustCrypto pure-Rust) |
| AEAD | AES-256-GCM or ChaCha20-Poly1305 | AES-256-GCM only | `ring` / `aws-lc-rs` |
| Hash | SHA-256 | SHA-256 | `sha2` / `aws-lc-rs` |
| KDF context | blake3 keyed-derivation | HKDF-SHA-256 | `blake3` / `hkdf` |
| KDF (HKDF) | HKDF-SHA-256 | HKDF-SHA-256 | `hkdf` |
| HMAC | HMAC-SHA-256 | HMAC-SHA-256 | `hmac` |

The PQ halves do not change under fips; only the classical KEM, the AEAD
backend, the KDF substrate, and the RNG do (see `core/src/crypto/` and
`docs/compliance/fips-readiness.md`). The
KDF label `"HybridKEM_X25519_Kyber768"` (§ 3) is preserved verbatim as a
wire-stable label string — it identifies the KDF domain, not the crate or FIPS
encoding (`core/src/crypto/hybrid_kem.rs:63`). Under fips the combine label
swaps to `"HybridKEM_P256_Kyber768"` (`hybrid_kem.rs:65`) because the classical
input differs (65-byte uncompressed SEC1 P-256 point vs 32-byte X25519).

The AEAD choice is auto-selected by `HwCaps::detect()` (AES-NI present → AES;
otherwise ChaCha). Cipher is `CipherSuite::Aes256Gcm = 1` or
`CipherSuite::ChaCha20Poly1305 = 2` (`core/src/crypto/adaptive_crypto.rs:56-68`).
Under fips only `Aes256Gcm` is selectable; the `ChaCha20Poly1305` enum variant
is retained for wire-format stability but its selection returns
`CoreError::CipherSuiteUnavailable`.

---

## 3. KDF label inventory

Every place that derives keying material from a master uses a string label to
domain-separate. Adding or changing any of these is a wire-incompatible
change.

| Label | Construction | Purpose |
| --- | --- | --- |
| `"HybridKEM_X25519_Kyber768"` / `"HybridKEM_P256_Kyber768"` (fips) | `HKDF-SHA-256(classical_secret \|\| kyber_secret)` | hybrid KEM shared secret (`hybrid_kem.rs:63-65`) |
| `b"phantom-transport-key"` | `HKDF-Expand(shared_secret)` | session AEAD master before per-direction derivation (`transport/session.rs:75`) |
| `"phantom-aes-send-v1"` / `"phantom-aes-recv-v1"` | `derive_key_32` over `shared_secret` | AES-256-GCM per-direction subkeys (`adaptive_crypto.rs:266-276`) |
| `"phantom-cc20-send-v1"` / `"phantom-cc20-recv-v1"` | `derive_key_32` | ChaCha20-Poly1305 per-direction subkeys (`adaptive_crypto.rs:267-276`) |
| `"phantom-nonce-pfx-v1"` | `derive_key_32(shared_secret)` | 4-byte nonce prefix (`adaptive_crypto.rs:287`) |
| `b"phantom-rekey-v1"` | `HKDF-Expand(current_traffic_secret)` | forward-derive the next per-epoch traffic secret (`transport/session.rs:397`) |
| `b"phantom-resumption-secret-v1"` | `HKDF-Expand(shared_secret)` | 0-RTT resumption secret (`transport/handshake.rs:584`, `:787`) |
| `b"phantom-session-id-v1"` | `SHA256(label \|\| shared_secret \|\| nonce)` | session id derivation (`transport/handshake.rs:830-836`) |
| `b"phantom-early-data-key-v3"` | `HKDF-Expand(HKDF-Extract(client_nonce, resumption_secret))` | 0-RTT early-data AEAD key (`crypto/kdf.rs:45`, `:83`) |
| `b"phantom-early-data-nonce-v3"` | `HKDF-Expand(HKDF-Extract(client_nonce, resumption_secret))` | 0-RTT early-data AEAD nonce (`crypto/kdf.rs:47`, `:86`) |
| `"phantom-faketls-c2s-v1"` / `"phantom-faketls-s2c-v1"` | `derive_key_32` over `(SNI \|\| version)` public seed | FakeTLS outer obfuscation keys (`legs/faketls.rs:124-125`) |
| `"phantom-faketls-pfx-v1"` | `derive_key_32` over the same public seed | FakeTLS outer nonce prefix (`legs/faketls.rs:126`) |
| `b"phantom-pow-cookie-v1" \|\| hour_be` | `HKDF-Expand(master_secret)` | hour-rotated cookie / PoW HMAC key (`transport/handshake.rs:936-938`) |

`derive_key_32` is the side-agnostic helper that dispatches per build:
`blake3::derive_key(label, ikm)` on the default build, `HKDF-SHA256(salt=∅,
info=label)` under fips (`core/src/crypto/kdf.rs:26-42`). The `-v3` suffix on
the early-data labels is historical naming; the labels are unchanged
wire-format constants.

---

## 4. Packet format

### 4.1 `PhantomPacket` (the sole on-wire data packet)

```rust
pub struct PhantomPacket {
    pub header: PacketHeader,   // 15 bytes on the wire (§ 4.2); session_id is off-wire
    pub payload: Vec<u8>,       // AEAD ciphertext (+16-byte tag) when ENCRYPTED;
                                // raw bytes for control/ACK; coalesced bundle when COALESCED
    pub extensions: Vec<u8>,    // TLV headroom; empty today, ignored if non-empty
}
```

Source: `core/src/transport/types.rs`. There is no enum wrapper — the recv path
deserializes a bare `PhantomPacket` directly (`PhantomPacket::from_wire`) and
**drops** any frame whose `header.version != WIRE_VERSION`
(`api/session.rs:679-687`). An unparseable frame is dropped, never panicked on.

The packet is serialised by `PhantomPacket::to_wire` as an explicit image — no
serialization library. **WIRE v6 (anti-fingerprint diet): no length prefixes.**

```text
header        15 bytes (§ 4.2)
payload       the message remainder (all bytes after the 15-byte header)
```

`recv_bytes` is message-framed on every `SessionTransport` (UDP datagram / TCP
4-byte frame / embedded frame), so the v5 cleartext `payload_len` / `ext_len`
`u32` prefixes were pure redundancy *and* a verifiable structural fingerprint
(`ext_len == 0x00000000`, `payload_len == datagram − const`); v6 drops both.
`from_wire` is bounds-checked (a buffer shorter than the 15-byte header is a drop,
never an out-of-bounds read). `extensions` is no longer carried on the data-plane
wire (it was always empty; the AEAD AAD still binds an empty extensions slice).

`payload` is the AEAD ciphertext when `PacketFlags::ENCRYPTED` is set,
otherwise raw bytes (control / ACK / path-validation). The AAD is the
reconstructed 47-byte header image (§ 5).

> **Security note.** The AEAD AAD is the reconstructed 47-byte header image
> followed by `extensions` (§ 5). With `extensions` empty (always, on the v6
> wire) the AAD is just the 47-byte image — which still binds `version` /
> `session_id` / all header fields. The on-wire header is 15 bytes (`session_id`
> off-wire), but the AAD reconstructs the full 47-byte v4 image, so the AEAD
> security argument is unchanged. Forward-compatibility headroom can return later
> via a reserved flag + an encrypted TLV inside the (padded) plaintext.

### 4.2 `PacketHeader` (15 wire bytes; 47-byte AAD image)

Serialised by `PacketHeader::to_wire` as an explicit, fixed **big-endian**
(network byte order) image — no serialization library, `version` first, byte
arrays as-is. WIRE_VERSION 5 (ε) dropped the inner `session_id` from the wire;
**WIRE_VERSION 6 (anti-fingerprint) masks the WHOLE 15-byte header `[0..15]`,
version byte INCLUDED** (no constant cleartext byte — see § 4.6); the Rust struct
keeps the `session_id` field (used for the AAD, off-wire):

```rust
#[repr(C)]
pub struct PacketHeader {
    pub version: u8,                 // pinned WIRE_VERSION   — wire [0],     HP-masked (v6)
    pub session_id: SessionId,       // [u8; 32]              — OFF-WIRE (AAD only; § 5)
    pub stream_id: StreamId,         // u16  (0 = control)    — wire [11..13], HP-masked
    pub packet_number: PacketNumber, // u64  per-dir monotonic — wire [1..9],   HP-masked
    pub flags: PacketFlags,          // u16  (§ 4.3)          — wire [9..11],  HP-masked
    pub epoch: u8,                   // rekey generation       — wire [13],    HP-masked
    pub path_id: u8,                 // migration path label   — wire [14],    HP-masked
}
```

Source: `core/src/transport/types.rs`. `PacketHeader::SIZE = 15` (the on-wire
header), pinned by `core/tests/check_wire.rs`,
`types.rs::packet_header_serializes_to_15_bytes`, and the byte-frozen vector
`core/tests/wire_vectors/packet_header.bin` (§ 11). The **AEAD AAD** is a separate
`PacketHeader::AAD_SIZE = 47`-byte image (`to_aad_image`) — the byte-identical v4
logical header `version ‖ session_id ‖ packet_number ‖ flags ‖ stream_id ‖ epoch
‖ path_id`, with the off-wire `session_id` reconstructed from session context
(§ 5). (`WIRE_VERSION 2 → 3` dropped the dead `ack_delay` and widened `sequence`
to a per-direction `packet_number: u64`; `3 → 4` reordered the span for header
protection — § 4.6; `4 → 5` (ε) dropped `session_id` from the wire; `5 → 6`
(anti-fingerprint) masks the version byte too + drops the length prefixes.)

**Wire byte layout** (15 bytes — WIRE v6: the WHOLE header is HP-masked, § 4.6):

| Offset | Field | Width | Encoding | On the wire |
| --- | --- | --- | --- | --- |
| 0 | `version` | 1 | u8, `= WIRE_VERSION` | **HP-masked (v6)** |
| 1 | `packet_number` | 8 | u64 big-endian | HP-masked |
| 9 | `flags` | 2 | u16 big-endian (§ 4.3) | HP-masked |
| 11 | `stream_id` | 2 | u16 big-endian | HP-masked |
| 13 | `epoch` | 1 | u8 | HP-masked |
| 14 | `path_id` | 1 | u8 | HP-masked |
| **total** | | **15** | | |

**AEAD AAD image** (47 bytes — the load-bearing crypto contract, byte-identical
to the v4 header; reconstructed off-wire, never serialised onto the wire):

| Offset | Field | Width |
| --- | --- | --- |
| 0 | `version` | 1 |
| 1 | `session_id` | 32 |
| 33 | `packet_number` | 8 |
| 41 | `flags` | 2 |
| 43 | `stream_id` | 2 |
| 45 | `epoch` | 1 |
| 46 | `path_id` | 1 |
| **total** | | **47** |

The `session_id` is **never on the wire** post-handshake (it was the v4 routing
CID; routing is now by the outer rotating `ConnId` — § 4.7). On receive,
`Session::parse_protected` reconstructs `header.session_id = self.id()` from the
routed session before the AEAD open, so the 47-byte AAD a sender authenticated is
reproduced byte-for-byte — a packet mis-delivered to the wrong session
reconstructs *that* session's id → wrong AAD → AEAD fail (the off-wire analogue of
the v4 cleartext-session_id bind). Flipping *any* AAD byte — `version` included —
fails decryption (§ 5); the recv path additionally drops a frame whose
`version != WIRE_VERSION`. An independent (non-Rust) decoder + encoder that
reproduces the 15-byte wire layout exactly is `tests/wire_vectors_decode.py` (the
HP mask is keyed crypto, verified separately in Rust — § 4.6).

### 4.3 `PacketFlags` (u16 bitfield)

Source: `core/src/transport/types.rs:74-107`.

| Bit | Constant | Meaning |
| --- | --- | --- |
| `0x0001` | `RELIABLE` | Requires ACK; retransmitted on timeout |
| `0x0002` | `ACK` | This packet is an authenticated ACK (`ENCRYPTED`; AEAD payload = a `Sack` — § 4.3) |
| `0x0004` | `FIN` | Stream finished |
| `0x0008` | `UNRELIABLE` | Fire-and-forget |
| `0x0010` | `PRIORITY` | Voice/video frame priority hint |
| `0x0020` | `ENCRYPTED` | Payload is AEAD ciphertext |
| `0x0040` | `COMPRESSED` | Payload is compressed (`AdaptiveCompressor`) |
| `0x0080` | `CONTROL` | Handshake / migration control message |
| `0x0100` | `REKEY` | Sender rekeyed; receiver trial-decrypts at `header.epoch` and commits the ratchet on AEAD success (§ 5) |
| `0x0200` | `PATH_VALIDATION` | Payload is a 32-byte challenge / response (multi-path) |
| `0x0400` | `COALESCED` | Payload bundles inner packets as `[count: u16][len1: u16][p1]…` (full byte layout — § 4.5) |
| `0x0800` | `WINDOW_UPDATE` | Payload is a big-endian `u32` relative flow-control credit (per-stream; the receiver grants the sender an additional `u32` bytes that is added to the sender's send window, saturating at `MAX_SEND_WINDOW`) |
| `0x1000` | `KEEPALIVE` | Idle keep-alive PING (empty payload); `KEEPALIVE \| ACK` is the PONG echo (download-only liveness — § 12.4) |
| `0x2000` | `PADDED` | Anti-fingerprint size padding present: the AEAD plaintext ends with a `‹zeros› ‖ pad_n:u16be` trailer the receiver strips post-decrypt (§ 4.8) |
| `0x4000` | `COVER` | Anti-fingerprint cover (dummy) traffic: empty inner plaintext (usually `PADDED`); authenticated then dropped by the peer, never reaches `recv()` (§ 4.8) |
| `0x8000` | _reserved_ | Future amendments |

`ENCRYPTED` is the post-handshake invariant flag — the API layer sets it on
every application-data packet, and the receive loop drops any non-empty
unencrypted application-data packet as a stripped-flag downgrade attempt
(Invariant 2; `api/session.rs`). ACK packets are **authenticated control frames**
(H1): they carry `ENCRYPTED | ACK`, and their AEAD plaintext is a **`Sack`**
(`core/src/transport/sack.rs`; full byte layout — § 4.5) — `largest_acked: u32 be`,
`ack_delay_us: u32 be` (the live ACK-delay signal, since A.5 moved it out of the
header), and a list of inclusive received ranges (selective ACK). The receiver
acts on them **only after
AEAD verify** — so a forged or plaintext ACK can neither retire a pending segment,
restore a flow-control permit, poison the BBR estimator, nor close a stream. Every
inbound frame is additionally bound to the negotiated `session_id` before any
processing. An ACK's own `header.packet_number` is drawn from the acker's single
per-direction packet-number space (shared with its data / `WINDOW_UPDATE` sends),
so the AEAD nonce never collides, and it obeys the §5 rekey discipline.

### 4.4 `SessionId`

`SessionId` (`[u8; 32]`, 32 bytes; `types.rs:21`) is the negotiated session
identifier, used as encryption salt and for migration across IP changes.
Server-side it is derived as `SHA256(b"phantom-session-id-v1" || shared_secret
|| client_nonce)` (`transport/handshake.rs:830-836`); the client adopts the
`session_id` echoed in the `ServerHello`.

### 4.5 AEAD-plaintext payload codecs (SACK / reliable frame / COALESCED)

These three are the **AEAD plaintext** that lives *inside* `PhantomPacket.payload`
once the AEAD opens — they are NOT the frozen outer `PhantomPacket` container
(§ 4.1) and changing them does **not** require a `WIRE_VERSION` bump or invalidate
`core/tests/wire_vectors`. They are authenticated (inside the AEAD) and invisible
on the wire. All integers are big-endian, matching the rest of the codec.

**SACK — the ACK control-frame plaintext** (`core/src/transport/sack.rs`).
Carried as the plaintext of an `ENCRYPTED | ACK` packet (§ 4.3). The ranges are
inclusive `(low, high)` runs of acknowledged reliable `stream_offset`s (the
reliable stream-frame index defined below in this section), sorted **descending**
(highest first), non-overlapping and non-adjacent;
there is always ≥ 1 range. Lengths use a **"length − 1"** convention, so a
single-acked offset encodes as `len = 0`.

| Offset | Field | Width | Encoding |
| --- | --- | --- | --- |
| 0 | `largest_acked` | 4 | u32 big-endian — highest acked offset; `= ranges[0].high` |
| 4 | `ack_delay_us` | 4 | u32 big-endian — sender-measured ACK delay (µs) |
| 8 | `range_count` | 2 | u16 big-endian — `1 ≤ N ≤ MAX_SACK_RANGES (32)` |
| 10 | `first_len` | 4 | u32 big-endian — width − 1 of the first (highest) range; `first_low = largest_acked − first_len` |
| 14 | `gap, len` × (N − 1) | 8 each | two u32 big-endian per continuation: `gap` = unacked sequences below the previous range (≥ 1), `len` = width − 1; `high_i = prev_low − 1 − gap`, `low_i = high_i − len` |

Minimum wire size = `10 + 4 + 8 × (N − 1)`: 14 bytes for one range, 22 for two.
`from_wire` rejects `range_count == 0` / `> 32` (`Malformed` / `TooManyRanges`),
a `gap == 0` (adjacent ranges — sender must coalesce), and any gap/len that
underflows the sequence space (`Malformed`); a buffer shorter than the declared
ranges is `Truncated`. The peer acts on a SACK **only after AEAD verify** (H1).

**Reliable stream-frame plaintext** (`api/session.rs` send path; recv at
`api/session.rs` reliable branch). A packet whose `flags` carry `RELIABLE`
(§ 4.3) prepends a gap-free per-stream offset to the application bytes so the
receiver reassembles in send order regardless of the `sequence` holes left by
interleaved control frames (A.5). Unreliable / control frames carry **no** prefix.

| Offset | Field | Width | Encoding |
| --- | --- | --- | --- |
| 0 | `stream_offset` | 4 | u32 big-endian — gap-free per-stream reassembly index |
| 4 | `data` | variable | the application payload bytes |

A reliable frame shorter than the 4-byte prefix is dropped as malformed (never a
panic). The `u32` offset space fails closed on exhaustion (`StreamError`; T4.5) —
it never wraps.

**`COALESCED` bundle plaintext** (`core/src/transport/packet_coalescer.rs`,
wrapped via `packet_coalescer_codec.rs`). A packet with `COALESCED` set (§ 4.3)
carries several inner sub-payloads under **one** AEAD tag (one encrypt, one replay
check, one sequence slot — the inner sub-packets are NOT re-numbered). The bundle
layout is a 2-byte count followed by length-prefixed sub-payloads:

| Offset | Field | Width | Encoding |
| --- | --- | --- | --- |
| 0 | `count` | 2 | u16 big-endian — number of sub-payloads |
| 2 | `len₁` | 2 | u16 big-endian — length of sub-payload 1 |
| 4 | `payload₁` | `len₁` | sub-payload 1 bytes |
| … | `lenᵢ, payloadᵢ` | 2 + `lenᵢ` | repeated `count` times |

`unwrap_coalesced_packet` rejects a payload shorter than the 2-byte header
(`EmptyOrTruncatedHeader`) and a `count` larger than the number of well-formed
sub-payloads actually present (`TruncatedSubPacket`). The default coalescer caps a
flushed bundle at `DEFAULT_MAX_DATAGRAM = 1200` bytes (path-MTU-safe). The decode
side is wired into the recv pump; the send-side wrap helper is a tested primitive
not yet driven from the live send path.

### 4.6 Header protection (T4.6, QUIC RFC 9001 § 5.4)

**WIRE v6:** the **whole 15-byte `[0..15]` header** (`version ‖ packet_number ‖
flags ‖ stream_id ‖ epoch ‖ path_id`) is **XOR-masked on the wire** so a passive
on-path observer cannot read the packet number, the `PRIORITY` ("voice") flag, the
stream id, the rekey epoch, the migration path label, *or* the version byte — the
data-plane wire has **no constant cleartext byte** to fingerprint. (v5 masked only
`[1..15]`, leaving the version byte cleartext.) The recv path locates the
ciphertext sample at the **fixed offset 15** (no length prefix needed — § 4.1), so
masking the version byte introduces no bootstrapping problem; the `session_id` is
off-wire (§ 4.2) and routing is by the outer **rotating** `ConnId` (§ 4.7).

**Keys.** Per-direction `hp_send` / `hp_recv` (32 bytes each) are derived ONCE at
session establishment via `kdf::derive_key_32("phantom-hp-{send,recv}-v1",
initial_secret)` (§ 3), swapped by side exactly like the AEAD keys. They are
**session-stable**: unlike the AEAD keys they do NOT rotate on rekey (QUIC § 6.1)
— `epoch` lives *inside* the masked span, so the receiver must remove header
protection before it knows the epoch; a per-epoch hp key would deadlock the
rekey-catchup path. Forward secrecy of confidentiality is unaffected — the hp key
masks only header metadata, never payload.

**Mask.** `sample` = the first 16 bytes of the AEAD ciphertext (the tag is always
present, so a sample exists even for an empty payload; the sample comes from the
payload ciphertext, which is never masked — so there is **no circular
dependency**). Per the negotiated suite:

```
AES-256-GCM suite:  mask = AES-256-ECB(hp_key, sample)                    (one block)
ChaCha20 suite:     mask = ChaCha20(key=hp_key, counter=u32_le(sample[0..4]),
                                    nonce=sample[4..16])[0..16]
apply / remove:     wire[0..15] ^= mask[0..15]      (v6: whole header, version incl.)
```

Under `--features fips` the AES mask routes through `aws_lc_rs::cipher` ECB (the
FIPS substrate); the ChaCha20 mask is unreachable (the suite is pinned to AES).

**No new oracle.** The AEAD AAD is the reconstructed 47-byte header image (§ 4.2),
which binds the unmasked `[0..15]` fields (v6: version byte included). A wire mutation of the masked span
unmasks to a wrong header → wrong AAD → the AEAD open fails, exactly like any
other AAD tamper. HP is an orthogonal
outer wrapping; it adds no decryption oracle. Source:
`core/src/crypto/header_protection.rs`, `Session::protect_packet` /
`parse_protected` (`transport/session.rs`). KATs: AES-256-ECB vs NIST SP 800-38A
F.1.5, ChaCha20 HP vs RFC 9001 § A.5; live end-to-end via `udp_integration` /
`tcp_integration`.

**Residual (closed by ε; EPS-02 now closed for *both* migration directions).** T4.6
hid the *variable* per-packet metadata but left two stable cleartext identifiers —
the 32-byte inner `session_id` and the outer 8-byte routing `ConnId`. ε removes the
`session_id` from the wire (§ 4.2) and makes the routing `ConnId` **rotate** on each
migration (§ 4.7), **symmetrically for both a client- and a server-initiated
migration**: whichever peer moves rotates its own outbound chain, and the other peer
rotates its return-direction chain in response, so **both directions are unlinkable
across a move by either peer**. For a server migration the client *reflects* — it
bumps its `path_id` and rotates its c2s chain — and that `path_id` bump is what makes
the server slide its c2s demux window to the rotated CID (no stranding); the server's
own s2c re-rotation is `path_id`-silent, so there is no ping-pong (audit 2026-06-15
**EPS-02**, closed by A2a). The honest caveat that **remains**: like the HP keys, the
CID chain is session-stable and **not** forward-secret — a session-key compromise lets
an attacker recompute the chain and link a *recorded* flow retroactively; the payload
stays forward-secret.

### 4.7 Rotating connection ID (ε / WIRE v5)

After ε the **only** per-connection cleartext identifier is the outer 8-byte UDP
`ConnId` (`transport/phantom_udp/envelope.rs`), and it **rotates** so an on-path
observer sees independent-random values across a migration. Rotation is **symmetric
for both migration directions** (EPS-02, closed by A2a):

- **Client migration** — the client advances its c2s chain on `migrate()`, and the
  server, on authenticating the new `path_id` (post-AEAD), rotates its s2c chain too;
  the socket-routed client absorbs the new inbound CID without a window slide, and the
  server does not bump its own `path_id`, so there is no ping-pong.
- **Server migration** — the server advances its s2c chain on `migrate_server()`, and
  the client, on authenticating the new server `path_id` (post-AEAD), *reflects*: it
  bumps its own `path_id` and advances its c2s chain. The `path_id` bump makes the
  server slide its c2s demux window to the rotated c2s CID (so it stays routable — no
  stranding, the hazard the per-direction asymmetry previously avoided); the server's
  matching s2c re-rotation is `path_id`-silent, so the client sees no new forward
  server `path_id` and does not re-reflect — it terminates in one round.

So a migration by **either** peer is unlinkable in **both** directions. See § 12.5.

**Chain.** At session establishment each peer derives two per-direction secrets
from the initial session secret (mirroring the HP / AEAD key swap):

```
cid_secret_c2s = derive_key_32("phantom-cid-c2s-v1", initial_secret)   // client→server
cid_secret_s2c = derive_key_32("phantom-cid-s2c-v1", initial_secret)   // server→client
CID_i          = derive_key_32("phantom-cid-v1", cid_secret ‖ i_be)[0..8]
```

The client stamps its outbound `ConnId` from the c2s chain (the chain the server
routes on); the server stamps from the s2c chain (`is_server` swaps, like the HP
keys). The chain secrets are **session-stable** (not rotated on rekey) and
zeroized on drop (`crypto/cid_chain.rs`).

**Index + window.** The outbound index `i` starts at 0 (`CID_0` is the first
post-handshake CID, replacing the random bootstrap `ConnId` the handshake ran on)
and **advances by one on each `migrate()`**, so post-migration datagrams stamp an
independent-random `CID_{i+1}`. The receiver (the UDP demux) routes on a sliding
window of accepted CIDs `[highest_seen − T, highest_seen + K]` (`T = 2` trailing
for in-flight reorder across a migration boundary, `K = 16` leading for migration
lookahead). The window advances **only post-AEAD**: an authenticated packet
carrying a new (forward) `path_id` — which the peer bumps in lock-step with its
CID index on each `migrate()` — slides the window by the **full forward delta `d`**
(the `d` migrations the `path_id` jumped): register the `d` new leading CIDs, drop
the `d` trailing ones, recentring the window on the sender's actual migration index
(EPS-01 fix — a single +1 step let lost intermediate migrations cumulatively erode
the leading margin). An off-path attacker cannot push the window (future CIDs are
unguessable without `cid_secret`, and a replayed observed CID never AEAD-verifies).
A CID outside every window is dropped → liveness → reconnect.

Because the slide is post-AEAD, the **triggering** packet's CID must itself be in
the current window — so `K` is the **hard cap on consecutive migrations whose
packets are ALL lost** before the sender's CID falls outside the window and the
session strands (recoverable by reconnect via the liveness sweep). A delivered
migration recentres the window, so only an unbroken run of `> K = 16` fully-lost
migrations strands — far beyond any realistic rapid-migration regime (audit
2026-06-15, **EPS-01**; K was widened 4 → 16 and the slide made multi-step, with
`MAX_ROUTES` raised to preserve session capacity).

**Bootstrap.** The handshake runs over a random bootstrap `ConnId` (the chain
secret is unavailable until the handshake completes). On completion both sides
derive the chain and the server registers `[CID_0 .. CID_K]`; the bootstrap id is
retired when the session's routes are reaped. It is visible only during the
inherently-observable handshake — unlinkability is about the post-migration flow.

**Cross-transport.** TCP / embedded are socket-routed and carry no on-wire CID;
the rotation applies only to the PhantomUDP envelope. The 15-byte inner header
(§ 4.2) is uniform across all transports.

Source: `crypto/cid_chain.rs`, `Session::{current_outbound_cid, advance_outbound_cid,
inbound_window_cids, note_migration_path}` (`transport/session.rs`), the UDP demux
`RouteTable` (`api/udp_listener.rs`). Live tests: `udp_integration`
(`client_stamps_cid0_*`, `cid_rotates_on_the_wire_across_migration`,
`window_slides_across_many_migrations`).

### 4.8 Size padding (WIRE v6, anti-fingerprint deliverable (c))

Even with the v6 length-prefix diet, the **datagram length** still tracks the
payload size. Opt-in size padding hides it by padding each packet up to a size
**bucket** before sealing. **Off by default** (it costs bandwidth); enabled per
session via `PhantomSession::set_traffic_shaping(TrafficShapingConfig { padding:
Padme })` (FFI-exported).

The padding lives **inside the AEAD plaintext**, so a network observer can neither
see, strip, nor forge it — only the bucketed datagram size is observable. A padded
packet sets `PacketFlags::PADDED` (§ 4.3, masked on the wire); its AEAD plaintext
gains the trailer:

```
‹inner plaintext› ‖ ‹pad_n zero bytes› ‖ pad_n : u16 big-endian
```

The receiver, after a successful AEAD open of a `PADDED` packet, reads the trailing
`u16` `pad_n` and strips the last `2 + pad_n` bytes to recover the inner plaintext
(a malformed trailer is dropped, never panicked on). The `PADDED` flag is in the
47-byte AAD, so an attacker cannot flip it to make the receiver mis-strip — that
fails the AEAD open like any other header tamper.

**Bucket policy — PADÉ** (Nikitin et al., "PURBs", 2019): round a length `L` up so
its low `E−S` bits are zero, where `E = ⌊log2 L⌋` and `S = ⌊log2 E⌋ + 1`. Overhead
is bounded by ≈ `1/E` (≤ ~12% for small packets, → 0 for large) while the size
distribution collapses to O(log) values per magnitude — far cheaper than
pad-to-MTU, far better than fixed buckets near their edges. The padded on-wire
packet is capped at `MAX_SHAPED_WIRE = 1184` bytes so the datagram stays under the
1200-byte path MTU after the UDP envelope; a packet already larger is not padded.
Padding bytes are paced (they consume the send rate) but do **not** inflate the
congestion window (cwnd / inflight track real payload bytes only), and a lost
padded packet retransmits only the real data, re-padded fresh.

Source: `transport/shaping.rs` (`padme`, `padding_trailer_len`, `append_padding`,
`strip_padding`), wired in `api/session.rs` `send_app_data` (apply) + the recv pump
(strip). Tests: `transport::shaping` units (bounded overhead, idempotence,
strip-is-inverse), `security_invariants` (padding inside the AEAD, bucketed, AAD-bound
flag), live `udp_integration::udp_integration_size_padding_delivers_byte_exact`.
**Timing jitter (d).** Independently opt-in (`TrafficShapingConfig::jitter_ms`,
`0` = off): the send path waits a uniform random `[0, jitter_ms]` ms before each
packet (`pace_send`, ahead of the wire-rate pacer), so inter-packet timing no
longer tracks the application's writes — at up to `jitter_ms` of added latency.
Jitter only delays; it never reorders or drops.

**Cover (dummy) traffic (e).** Independently opt-in
(`TrafficShapingConfig::cover_interval_ms`, `0` = off): the session maintains a
minimum outbound packet rate of `1000 / cover_interval_ms` packets/sec by emitting
an `ENCRYPTED | COVER` dummy packet (empty inner plaintext, PADÉ-padded to a
bucket) whenever no packet has gone out for `cover_interval_ms` — hiding the
idle/active pattern and volume, at a steady bandwidth cost. A cover packet
AEAD-authenticates like any packet (so it refreshes the peer's liveness and cannot
be off-path injected), and the receiver **drops** it before the data path (it
never reaches `recv()`). Source: `send_cover` / `maybe_send_cover` in
`api/session.rs` (the cover timer reuses the send-PN counter as the "did we send
anything?" signal). Tests: `security_invariants::cover_packet_is_authenticated_padded_and_carries_no_data`,
live `udp_integration::udp_integration_cover_traffic_fills_idle_and_is_dropped`.

---

## 5. AEAD construction

Per-direction keys (`send_key` / `recv_key`) and a 4-byte `nonce_prefix` are
derived once at session establishment from the hybrid shared secret (§ 3
labels). The per-packet AEAD nonce is **derived from the authenticated header's
packet number**, not from an internal counter — so a failed or tampered decrypt
never desyncs the receiver.

Nonce layout (12 bytes total; `Session::build_packet_nonce`,
`transport/session.rs`):

```
nonce[0..4]  = nonce_prefix          (from CryptoState; fresh per rekey epoch)
nonce[4..12] = header.packet_number  (u64, big-endian)
```

`epoch`, `stream_id`, and `path_id` are **not** in the nonce (① — Phase 4); they
remain authenticated as part of the 47-byte AAD. The version byte is likewise in
the AAD but not the nonce. `epoch` is still read from the header to *select* the
key (`CryptoState`) during the rekey-catchup window.

```
Sender:    plaintext, header  →  AEAD-encrypt(key  = send_key,
                                              nonce= prefix||packet_number_be,
                                              aad  = serialize(header)||extensions, // 47 B + TLV
                                              plaintext)
                              →  ciphertext (with 16-byte tag)
Receiver:  ciphertext, header →  AEAD-decrypt(key  = recv_key,
                                              nonce= prefix||packet_number_be,
                                              aad  = serialize(header)||extensions,
                                              ciphertext)
                              →  plaintext  OR  a single opaque "decrypt failed"
```

The AAD is the reconstructed 47-byte header image (`header.to_aad_image()`, § 4.2)
followed by the packet's `extensions` TLV (T4.1 — the forward-compat headroom is
now authenticated, closing the prior gap where it sat outside the AAD; it is empty
on every current packet, so the AAD is just the 47-byte image in practice). The
on-wire header is only 15 bytes (`session_id` is off-wire — § 4.2); the receiver
reconstructs `header.session_id = self.id()` from the routed session and unmasks
the `[0..15]` HP span (§ 4.6) before this AEAD-decrypt, rebuilding the byte-identical
47-byte AAD the sender authenticated, so a masked-region tamper or a wrong-session
delivery surfaces here as a `decrypt failed` — no separate oracle.

Source: `Session::encrypt_packet` / `decrypt_packet` / `protect_packet` /
`parse_protected` (`core/src/transport/session.rs`).

**Uniqueness (Invariant 8).** The `packet_number` is a **single per-direction
`u64`**, assigned at *send* time and **strictly monotonic** — it never resets, not
even across a rekey, and every transmission (including a retransmission) draws a
fresh value. Within an epoch the `nonce_prefix` is fixed and the packet number is
unique, so the nonce is never reused; across epochs the key + prefix are fresh
**and** the packet number keeps climbing — double safety. Because a `u64` cannot
wrap within any realistic session, the audit anchor is simply: *the packet number
is strictly monotonic and used exactly once per direction → the AEAD nonce is never
reused, full stop.* `epoch` and `path_id` are authenticated (AAD) but do not
participate in nonce uniqueness — so a rekey mid-migration, or a reused `path_id`
after a path is retired, can never collide a nonce. This **retires** the old
per-stream `u32`-sequence hazard and its `SEQ_REKEY_WATERMARK = 2^31` forced-rekey
crutch (Phase 4 / P4.0); the C1 nonce-reuse finding from the security audit is
closed.

**Replay window runs after AEAD verify (Invariant 4).** After a successful AEAD
open, the receiver consults **one per-direction** sliding-window bitmap
(`core/src/security/replay_window.rs`, RFC 4303 §3.4.3, default 1024 bits) keyed on
the `u64` packet number — not per-stream, since the packet number is already unique
across all streams and paths. Duplicates and below-window packet numbers yield
`CoreError::ReplayDetected`. The window check is **never** moved before the AEAD
verify, so the receiver never keys off an unauthenticated counter. A legitimately
reordered packet that arrives on the overlapping *old* path during a migration is
still within the window and accepted; the resulting data duplicate (old + new path
carrying the same `stream_offset`) is deduped at the stream layer.

**Nonce-exhaustion guard (Invariant 8).** `AEAD_MAX_INVOCATIONS = 1 << 48`
(`adaptive_crypto.rs`). The per-direction invocation count reaching this ceiling
yields `CryptoError::NonceExhausted` — a defensive ceiling far below any practical
AEAD safety boundary, and far below where a `u64` packet number could itself be a
concern (the `2^47` rekey soft-limit fires long first).

**Mid-session rekey (Invariant 5).** `Session::rekey()`:

1. `next_secret = HKDF-Expand(current_traffic_secret, "phantom-rekey-v1", 32)`.
2. Build a fresh `CryptoState` from `next_secret` with the same `is_server`
   orientation as the original handshake.
3. ArcSwap-install the new state — concurrent encrypt/decrypt see either the
   old or new state atomically.
4. Zero the previous traffic secret in place before overwriting.
5. Increment `epoch` (u8, **saturates** at `u8::MAX` — long-lived sessions
   reconnect rather than wrap to 0).

Every epoch transition is serialised by a per-session rekey mutex, so the
concurrent send-loop and receive-task of the data pump can never let the
installed key depth diverge from the `epoch` counter.

**Automatic rekey.** The data pump triggers a rekey on the send path, *before
stamping a packet's header*, once a direction's AEAD invocation count crosses
`REKEY_SOFT_LIMIT` (default `2^48 / 2 = 2^47`), well below the hard
`AEAD_MAX_INVOCATIONS = 2^48` ceiling. The old per-stream `SEQ_REKEY_WATERMARK`
forced-rekey threshold (the C1 crutch) is **gone**: with a per-direction `u64`
packet number there is no sequence to wrap, so the invocation soft-limit is the
only rekey driver.

If a rekey is required but the `epoch` has saturated (`u8::MAX`), the send **fails
closed** — the packet is not stamped, the send is reported as failed, and the
session is expected to reconnect rather than continue. Both data (`send_app_data`)
and `WINDOW_UPDATE` (`send_window_update`) sends obey this discipline.

Wire signalling: the sender emits a packet whose header carries the new `epoch`
and the `PacketFlags::REKEY` flag. The receiver follows via
`Session::decrypt_packet_accepting_rekey`: if `header.epoch` is ahead of its
local epoch (by up to `MAX_REKEY_CATCHUP = 16` steps, which absorbs the small
divergence when both directions rekey at slightly different cadences), it
derives the candidate key that many HKDF steps forward and **trial-decrypts**;
it commits the ratchet **only on AEAD success**. Because `header.epoch` is not
authenticated until the AEAD tag verifies, a forged epoch bump fails the trial,
commits nothing, and cannot desync the session — and the step bound caps the
HKDF work an attacker can force per spoofed packet. A packet more than
`MAX_REKEY_CATCHUP` ahead, or behind the current epoch, is dropped; over a
reliable transport the sender retransmits at the then-current epoch, so no data
is lost. The `"phantom-rekey-v1"` label is a wire-format constant.

The single opaque "decrypt failed" surface is deliberate: AEAD-tag mismatch,
wrong key, wrong AAD, and wrong packet number all manifest identically so a network
attacker learns nothing from the shape of the failure (§ 8).

---

## 6. Handshake

The `ClientHello` is a bare borsh struct (no envelope). **Server replies are framed
with a leading discriminant byte (T4.4):** the wire form is `[kind: u8] ‖ borsh(body)`,
where `kind` is `0 = ServerHello`, `1 = HelloRetryRequest`, `2 = ServerReject`. The
client dispatches on `kind` **explicitly** (`ServerReply::from_wire`) — an unknown kind
or a malformed body is a handshake error, never a misparse. This replaced the former
trial-deserialization (which distinguished the three by message size + the `b"PRJ1"`
reject marker — robust in practice, but a same-size confusion was structurally possible).
The discriminant byte is an API-layer framing element that sits *outside* the borsh
message structs, so it does not affect the frozen `wire_vectors` (which fix the bare
message encodings). The `ServerReject` marker is retained as an extra sanity check.

### 6.1 State machine

```
   client                                 server
   ──────                                 ──────
   Initial
     │ send ClientHello  ───────────────►  process_client_hello
     │                                        │ protocol_variant gate (§6.7)
     │                                        │ version pin (== PROTOCOL_VERSION)
     │                                        │ resume fast-path? (consume ticket)
     │                                        │ cookie / PoW gate (§6.5)
     │   ◄── HelloRetryRequest ──────────────┤ (cookie/PoW missing → loop)
     │ retry with cookie/PoW ──────────────►  │
     │                                        │ hybrid KEM encapsulate (fresh secret)
     │                                        │ best-effort early-data decrypt (§6.6)
     │                                        │ derive session_id, sign transcript
     │   ◄── ServerHello (transcript-signed)──┤ session established (server side)
     │ verify pinned server_verify_key
     │ verify transcript signature
     │ decapsulate KEM → shared_secret
     │ derive session
   Established
```

`HandshakeStage` (`Initial → ClassicalReady → Established | Failed`,
`handshake.rs:57-67`) supports optimistic start. `process_client_hello`
returns `HandshakeResponse::{Success(ServerHello, Session, Option<Vec<u8>>),
Retry(HelloRetryRequest), Reject(ServerReject), Fail(HandshakeError)}` — the
`Option<Vec<u8>>` is the decrypted 0-RTT early-data plaintext, or `None`; the
`Reject` arm carries the typed unsupported-version signal of §6.10 (the listener
serialises it back before closing). `process_server_hello` returns `(Session,
Option<bool>)` — the second element is the 0-RTT verdict (`None` when the client
sent no early-data).

### 6.2 `ClientHello` (borsh)

```rust
pub struct ClientHello {
    pub client_key_package: HybridKeyPackage,   // X25519(/P-256) + ML-KEM-768 pubkeys
    pub client_verify_key:  HybridVerifyingKey,  // Ed25519 + ML-DSA-65 pubkeys
    pub nonce:              [u8; 32],            // freshness; salts early-data keying
    pub version:            u8,                  // == PROTOCOL_VERSION (pinned, transcript-bound)
    pub cookie:             Option<[u8; 32]>,    // echoed from HelloRetryRequest
    pub pow_solution:       Option<PoWSolution>, // proof-of-work
    pub resume_session_id:  Option<[u8; 32]>,    // 0-RTT resumption ticket id
    pub resumption_binder:  Option<[u8; 32]>,    // HS-03 proof-of-possession over the ticket secret
    pub protocol_variant:   Vec<u8>,             // build-variant tag (§6.7), transcript-bound
    pub early_data:         Option<Vec<u8>>,     // AEAD-sealed 0-RTT blob, or None (§6.6)
}
```

`resumption_binder` (HS-03) is present iff `resume_session_id` is: it is a keyed
PRF `derive_key_32("phantom-resume-binder-v1", resumption_secret ‖
resume_session_id ‖ nonce)`. The server verifies it **constant-time against the
cached ticket's secret before consuming the one-shot ticket**, so a passive
observer that copied the cleartext `resume_session_id` cannot burn a victim's
ticket. The ticket is consumed eagerly (race-free) and re-inserted with its
original expiry if the handshake later fails (ZERORTT-2). Field order
(`resume_session_id` → `resumption_binder` → `protocol_variant`) is borsh
wire-load-bearing.

Source: `core/src/transport/handshake.rs:75-106`.

### 6.3 `ServerHello` (borsh)

```rust
pub struct ServerHello {
    pub server_nonce:         [u8; 32],          // server-contributed, transcript-bound (T4.3)
    pub ciphertext:           HybridCiphertext,  // KEM encapsulation
    pub server_verify_key:    HybridVerifyingKey,// pinned by client (Invariant 1)
    pub signature:            HybridSignature,   // over transcript hash
    pub session_id:           [u8; 32],
    pub early_data_accepted:  bool,              // 0-RTT verdict (§6.6)
}
```

Source: `core/src/transport/handshake.rs`. `server_nonce` is a 32-byte
server-contributed value bound into the transcript hash, giving the server a
session-specific, tamper-evident contribution beyond `session_id` + the client
nonce. **T4.3:** it replaced the former `server_key_package` — a full ~1184 B
ephemeral hybrid KEM public key whose secret was discarded (the protocol runs no
second KEM round trip), saving ~1.1 KB on every `ServerHello`. A future
second-KEM ring could repurpose this slot.

### 6.4 `HelloRetryRequest` (borsh)

```rust
pub struct HelloRetryRequest {
    pub challenge: Option<PoWChallenge>,  // PoW required iff difficulty > 0
    pub cookie:    Option<[u8; 32]>,      // fresh cookie to echo on retry
}
```

Source: `core/src/transport/handshake.rs:130-134`.

### 6.5 Transcript signing

The `ServerHello.signature` is the hybrid signature over `SHA256(borsh(
transcript))`, where the transcript embeds the **whole** `ClientHello` (every
field, including the `early_data` ciphertext) and **leads** with the build-side
`PROTOCOL_VARIANT`:

```rust
struct HandshakeTranscript<'a> {
    protocol_variant:    &'a [u8],            // leading field — binds the build variant
    client_hello:        &'a ClientHello,     // whole hello, early_data included
    server_nonce:        &'a [u8; 32],        // server-contributed (T4.3)
    ciphertext:          &'a HybridCiphertext,
    server_verify_key:   &'a HybridVerifyingKey,
    session_id:          &'a [u8; 32],
    early_data_accepted: bool,                // 0-RTT verdict, signed (Invariant 9); LAST so
                                              // protocol_variant stays the leading field
}
```

Source: `core/src/transport/handshake.rs:166-174`. The hybrid signature is
`Ed25519.sign(hash) || ML-DSA-65.sign(hash)` — **both** halves must verify
(`HandshakeError::KemFailed("Signature check failed: …")` otherwise). Because
`client_hello.version`, `protocol_variant`, and the `early_data` ciphertext are
all under the signature, a network rewrite of any of them forces a client-side
signature mismatch (Invariants 7, 10). This is the sole downgrade-resistance
mechanism — there is no version negotiation to attack.

Server identity pinning is mandatory in production (Invariant 1):
`process_server_hello` takes `expected_server_key: Option<&HybridVerifyingKey>`
and the API layer always passes `Some(...)`; a mismatch is
`HandshakeError::ServerIdentityMismatch` before the signature check
(`handshake.rs:735-740`). Clients obtain the key via
`PhantomListener::verifying_key_bytes()` + `HybridVerifyingKey::from_bytes`.

### 6.6 0-RTT early-data (best-effort, one-shot)

0-RTT early-data is folded directly into `ClientHello.early_data` — no separate
handshake version. A resuming client seals application bytes so the first
payload reaches the server without a full handshake round trip.

**Keying.** Both peers derive identical AEAD material from the prior session's
`resumption_secret` and *this* connect's `client_nonce`
(`core/src/crypto/kdf.rs:70-89`):

```
PRK              = HKDF-Extract(salt = client_nonce, ikm = resumption_secret)
early_data_key   = HKDF-Expand(PRK, "phantom-early-data-key-v3",   32)   // AES-256-GCM key
early_data_nonce = HKDF-Expand(PRK, "phantom-early-data-nonce-v3", 12)
```

HKDF-SHA256 (not BLAKE3) keeps the path FIPS-eligible. The blob is sealed with
**AES-256-GCM** (fixed — the cipher suite is not yet negotiated at ClientHello
time). AAD = `resume_session_id || client_nonce` (64 bytes;
`handshake.rs:866-868`, `:891-893`). The `(key, nonce)` pair is single-use: the
key is bound to one `client_nonce`, which is one-shot because the server
consumes the resumption ticket on first sight.

**Size cap.** Early-data plaintext is capped at `EARLY_DATA_MAX_LEN = 16 KiB`
(`handshake.rs:32`). The client constructor refuses a larger payload; the
server checks `sealed.len() > EARLY_DATA_MAX_LEN + 16` **before** any crypto
work (`handshake.rs:858`) and drops the blob, continuing 1-RTT — this caps the
work an unauthenticated peer can force.

**One-shot anti-replay (Invariant 9).** The defence is the resumption ticket
itself: `SessionCache::try_resume` **removes** the ticket on first lookup. A
replayed ClientHello carrying the same `resume_session_id` finds no ticket → no
cookie/PoW bypass → the server falls back to a normal 1-RTT handshake and
ignores the early-data. Each ticket authorises exactly one 0-RTT attempt.
Within that single delivery the application must still treat early-data with
the standard TLS-1.3 0-RTT discipline — only idempotent operations belong in
early-data.

> **⚠️ Distributed-deployment caveat (single-cache assumption).** The one-shot
> guarantee holds **only under a single coherent `SessionCache`** — i.e. one
> process, or a cluster sharing one authoritative ticket store. `SessionCache` is
> an in-process bounded-LRU `HashMap` (`core/src/transport/session_cache.rs`); it
> is **not** replicated or coordinated across nodes. In a horizontally-scaled
> deployment where each node keeps its **own** cache, an attacker who captures a
> 0-RTT `ClientHello` can replay it against a *different* node that still holds an
> unconsumed copy of the same ticket, and that node will accept the early-data a
> second time — the classic TLS-1.3 0-RTT-across-a-server-farm replay. Mitigations
> (all deployment-side, none enforced by this library): (a) consistently route a
> given `resume_session_id` to the same node (sticky / hashed load-balancing); (b)
> back the cache with a single shared store that performs an atomic
> compare-and-remove on resume; or (c) accept the residual and keep early-data
> strictly idempotent. The forward secrecy and authentication of the resulting
> *post-handshake* session are unaffected — only the at-most-once property of the
> 0-RTT early-data payload degrades. See the threat-model (STRIDE-S / LINDDUN).

**Best-effort semantics (Invariant 9).** The handshake **always** completes (as
1-RTT) even when early-data is rejected — unknown/expired ticket, oversized
blob, or AEAD failure all leave `early_data_accepted = false`.
`PhantomSession::early_data_accepted().await -> Option<bool>` reports the
verdict:

| Verdict | Meaning |
| --- | --- |
| `Some(true)` | server decrypted and surfaced the early-data |
| `Some(false)` | early-data sent but rejected — caller must re-send normally |
| `None` | client sent no early-data on this connect |

**Forward-secrecy caveat.** Early-data is encrypted under a key derived from a
**past** session's `resumption_secret`; compromise of that secret exposes this
connect's early-data — the standard TLS-1.3-style 0-RTT gap. The
*post-handshake* session retains full PFS: the handshake always runs a fresh
hybrid KEM (X25519 + ML-KEM-768, or ECDH-P-256 + ML-KEM-768 under fips)
regardless of the 0-RTT path.

**API surface.** Client: `PhantomSession::connect_with_resumption(addr,
transport, expected_server_key, resumption_hint, early_data)` (Rust) /
`connect_pinned_with_resumption` (native FFI); the `resumption_hint` tuple comes
from a prior session's `resumption_hint().await -> Option<(session_id,
resumption_secret)>` (each field 32 bytes). Server: `PhantomListener::accept()`
returns `Arc<AcceptOutcome>` (`api/listener.rs:292-316`):

```rust
let outcome = listener.accept().await?;
let session = outcome.session();                  // Arc<PhantomSession>
if let Some(bytes) = outcome.take_early_data() {   // take-once 0-RTT payload
    // handle the client's 0-RTT data (None = none sent / rejected)
}
```

`AcceptOutcome` is a `uniffi::Object` exposing `.session()`,
`.take_early_data()`, `.has_early_data()`. `take_early_data()` moves the ≤16 KiB
blob out once.

### 6.7 Build-variant tag (`PROTOCOL_VARIANT`) and FIPS interop

`ClientHello.protocol_variant: Vec<u8>` carries the compile-time build-variant
tag (`core/src/transport/handshake.rs:46-49`):

| Build | `PROTOCOL_VARIANT` |
| --- | --- |
| Default (`cargo build`) | `b"phantom-default-1"` |
| FIPS (`cargo build --features fips`) | `b"phantom-fips-1"` |

It is (a) carried cleartext on every `ClientHello` and (b) the **leading
field** of the signed transcript (§ 6.5). The server rejects a mismatch with
`HandshakeError::ProtocolVariantMismatch` **before** any KEM / signature work
(`handshake.rs:346-351`); an MITM that rewrites the cleartext field to match
the server's is still caught by the client's signature check, because the
transcript binds each side's *own* real variant (Invariant 10).

Operationally, fips and non-fips peers cannot interoperate: their primitive
sets differ (ECDH-P-256 vs X25519, HKDF-SHA-256 vs blake3-derive-key, AES-only
vs AES+ChaCha), so the derived secrets would not match even if the cleartext
gate were bypassed. Both ends of a deployment must be built with the same
feature flag; treat `--features fips` as a separate distribution channel with
its own wire-format pinning. The field is `Vec<u8>` (not a fixed enum) so a
future build can carry an additional tag value without a positional
wire-format break.

Under fips the power-on self-test (`crypto::self_tests::ensure_post_passed()`)
runs before any handshake on both `connect_*` and `bind_*`; a failure returns
`CoreError::FipsSelfTestFailure` instead of establishing a session
(Invariant 11).

### 6.8 Cookie format

```
cookie = HMAC-SHA-256(
    key = derive_session_secret_for_hour(master_secret, current_hour),
    msg = ip_string_bytes || bucket_be(8)
)
```

Source: `core/src/transport/handshake.rs:943-998`.

- `current_hour = unix_secs / 3600`; validation accepts the current OR previous
  hour.
- `bucket = unix_secs / 300` (5-minute bucket); validation accepts the current
  OR previous bucket.
- The IP is the client's source IP as observed by the server. Stateless — the
  server holds no per-cookie state. All comparisons are constant-time via
  `subtle::ConstantTimeEq`, accumulated into a single `subtle::Choice` so the
  validator never branches on an individual comparison.

A valid one-shot resumption ticket (§ 6.6) bypasses the cookie/PoW gate.

### 6.9 PoW format

`PoWChallenge { nonce: [u8; 32], difficulty: u8 }`. The client must find a
solution such that the blake3-based hash of `(challenge.nonce || client_ip ||
solution)` has at least `difficulty` leading zero bits. The challenge is
regenerated deterministically from the rotating per-hour secret — stateless
server-side, accepting the current or previous hour's derivation. The
challenge-integrity MAC is compared in constant time (`subtle::ConstantTimeEq`,
CRYPTO-2/HS-04).

**Client difficulty cap (H3).** `HelloRetryRequest` is unauthenticated, so the
client rejects any `difficulty > MAX_CLIENT_POW_DIFFICULTY = 24` (strictly above
the server's max legitimate tier) **before** solving, and `solve` is bounded to
`MAX_SOLVE_ITERATIONS = 2^32` — an injected `difficulty = 255` yields a handshake
error instead of pinning a CPU core forever.

Adaptive difficulty (`HandshakeServer::adaptive_difficulty`,
`handshake.rs:301-310`):

| Handshakes/min | Difficulty | Expected hash evals |
| --- | --- | --- |
| 0–99 | 0 | (no PoW required) |
| 100–499 | 4 | ~16 |
| 500–1999 | 8 | ~256 |
| 2000–9999 | 12 | ~4096 |
| 10000+ | 16 | ~65536 |

### 6.10 `ServerReject` (borsh) — unsupported-version signal

```rust
pub struct ServerReject {
    pub marker:            [u8; 4],   // = b"PRJ1" (SERVER_REJECT_MARKER)
    pub code:              u8,        // 1 = REJECT_UNSUPPORTED_VERSION
    pub supported_version: u8,        // the PROTOCOL_VERSION the server speaks
}
```

Source: `core/src/transport/handshake.rs`. A fixed 6 bytes. Returned by
`process_client_hello` as `HandshakeResponse::Reject(..)` when
`ClientHello.version != PROTOCOL_VERSION`, and serialised back to the client by
the listener (and the UDP demo path) *before* the connection closes — the one
case where the server speaks after an unacceptable hello instead of dropping
silently.

The client identifies it by the T4.4 discriminant byte (`kind = 2`, with the
`b"PRJ1"` marker as an extra check) and surfaces a hard error naming both
versions. It deliberately does **not**
auto-downgrade to `supported_version`: the version is bound into the signed
transcript (§6.5, Invariant 7), so honouring an attacker-injected reject would
be a downgrade oracle. The frame is purely diagnostic. Because it is an
*additive* message — never sent on the success path and shaped unlike the other
three messages — it leaves the frozen wire vectors (§11) untouched.

---

## 7. Reserved / forward-compatibility surface

- `PacketHeader.path_id`: the client-owned connection-migration path label
  (Phase 4, § 12); `epoch`: the rekey generation (Phase 1.5). Both default to 0.
  Since ① (§ 5) `path_id` no longer feeds the AEAD nonce — it is AAD-only — so a
  `path_id` becomes safely reusable once its path is retired.
- `PhantomPacket.extensions`: TLV headroom, empty today. A decoder ignores it;
  future amendments add fields here without a layout change.
- `ServerHello.server_nonce`: a 32-byte server-contributed, transcript-bound
  value (T4.3, replacing the old discarded ~1184 B ephemeral `server_key_package`).
  A future second-KEM ring could repurpose this slot for real key material.
- `PacketFlags 0x2000 … 0x8000`: reserved bits (`0x1000` = `KEEPALIVE`, § 4.3 / § 12.4).

A future protocol revision that needs more than this headroom increments
`WIRE_VERSION` / `PROTOCOL_VERSION` (§ 1) as a deliberate, code-gated bump.

---

## 8. Error model

Wire-visible errors fall into:

- **Authentication failure**: AEAD tag mismatch, transcript signature mismatch,
  server identity mismatch, protocol-variant mismatch. Surface as
  `CoreError::CryptoError(_)`, `HandshakeError::ServerIdentityMismatch`, or
  `HandshakeError::ProtocolVariantMismatch`.
- **Version / parse failure**: `header.version != WIRE_VERSION` (dropped),
  `ClientHello.version != PROTOCOL_VERSION` (`HandshakeError::UnsupportedVersion`),
  or a borsh / `PhantomPacket::from_wire` parse error
  (`CoreError::SerializationError(_)` / `HandshakeError::SerializationError` /
  `WireError::Truncated`).
- **Liveness failure**: connection closed / I/O error
  (`CoreError::NetworkError(_)` / `CoreError::ConnectionClosed`).
- **Replay**: post-AEAD sliding-window rejection (`CoreError::ReplayDetected(_)`).
- **Resource exhaustion**: AEAD counter ceiling (`CryptoError::NonceExhausted`),
  replay-cache full.
- **FIPS posture** (`--features fips`): a failed power-on self-test
  (`CoreError::FipsSelfTestFailure`).

The library never surfaces an error that distinguishes "wrong key" from "wrong
packet number" from "wrong AAD" — all manifest as a single "decrypt failed" so a
network attacker cannot learn anything from the shape of the failure.

---

## 9. Side notes

- The on-wire `PacketHeader` is exactly 15 bytes (ε; `session_id` off-wire); the
  AEAD AAD is the separate reconstructed 47-byte image (§ 4.2). Any layout drift
  in either is a wire-incompatible regression.
- The nonce's `packet_number` field is big-endian (§ 5); this is pinned
  independently of the header serialisation.
- Every length-prefix on the wire (e.g. `TcpSessionTransport` framing) is a
  4-byte big-endian `u32` length capped at `MAX_FRAME_BYTES = 16 MiB`.
- `SessionId`, `HybridKeyPackage`, `HybridVerifyingKey`, `HybridCiphertext`,
  `HybridSignature` derive `BorshSerialize + BorshDeserialize`; their on-wire
  bytes are the concatenation of their internal fields in declaration order.
> **Note (Phase 0):** the FakeTLS leg was removed; this section is retained for the planned HTTP-mimicry transport mode.

- FakeTLS outer obfuscation (Invariant 3) uses per-record counter nonces and
  direction-keyed AEAD derived from a public `(SNI || version)` seed via the
  `"phantom-faketls-*-v1"` labels (§ 3). It is anti-DPI obfuscation only — the
  inner Phantom Protocol session provides real auth/conf; the seed is intentionally
  public.

---

## 10. Compliance with documented invariants

The invariants from `SECURITY.md` and `docs/security/threat-model.md` map onto
this spec as follows:

| Invariant | Spec section |
| --- | --- |
| 1 — Server identity pinning | § 6.1 / § 6.3 / § 6.5 |
| 2 — Post-handshake ENCRYPTED flag | § 4.3 / § 5 |
| 3 — FakeTLS per-record counter nonces (anti-Forbidden-Attack) | § 3 / § 9 |
| 4 — Replay rejection after AEAD verify | § 5 |
| 5 — Rekey via HKDF `"phantom-rekey-v1"`, saturating epoch | § 5 |
| 6 — Constant-time path-validation responses | § 4.3 (`PATH_VALIDATION`) / § 12.1 |
| 7 — Transcript-bound version | § 1 / § 6.5 |
| 8 — AEAD nonce-exhaustion guard at 2^48 | § 5 |
| 9 — 0-RTT early-data one-shot + best-effort | § 6.6 |
| 10 — Build-mode (`PROTOCOL_VARIANT`) transcript-bound | § 6.5 / § 6.7 |
| 11 — FIPS POST runs before any handshake | § 6.7 |

Removing or weakening any of these requires a deliberate `WIRE_VERSION` /
`PROTOCOL_VERSION` bump (§ 1) and a corresponding update to `SECURITY.md`.

---

## 11. Wire test vectors

The on-wire bytes are frozen byte-for-byte in `core/tests/wire_vectors/*.bin`
and asserted in both directions (`serialize(value) == fixture` and
`deserialize(fixture) == value`) by `core/tests/wire_vectors.rs` (the packet and
handshake messages) and `transport::handshake::tests::transcript_hash_wire_vector`
(the signed transcript hash). This is the only test that pins the *bytes* rather
than driving Rust types ↔ Rust types, so a layout / endianness / discriminant
regression in the packet codec or in `borsh` fails CI instead of silently
breaking interop. `tests/wire_vectors_decode.py` is an independent (non-Rust)
decoder + encoder over the same fixtures — cross-implementation evidence that the
grammar is real.

| Fixture | Codec | Type |
| --- | --- | --- |
| `packet_header.bin` | hand-rolled big-endian | `PacketHeader` (§ 4.2) |
| `phantom_packet_data.bin` / `_ack.bin` / `_extensions.bin` | hand-rolled big-endian | `PhantomPacket` (§ 4.1) |
| `client_hello_minimal.bin` / `client_hello_full.bin` | borsh | `ClientHello` (§ 6.2) |
| `server_hello.bin` / `server_hello_rejected.bin` | borsh | `ServerHello` (§ 6.3) |
| `hello_retry_request_cookie.bin` / `_pow.bin` | borsh | `HelloRetryRequest` (§ 6.4) |
| `hybrid_key_package.bin` / `hybrid_ciphertext.bin` | borsh | KEM material (§ 6.2/6.3) |
| `hybrid_verifying_key.bin` / `hybrid_signature.bin` | borsh | signature material (§ 6.3) |
| `pow_challenge.bin` / `pow_solution.bin` | borsh | DoS-gate fields (§ 6.5) |
| `transcript_hash.bin` | SHA-256 | `HandshakeTranscript` hash (§ 6.5) |

The handshake fixtures use deterministic *filler* of the real field lengths, not
valid KEM/signature material — this freezes the serialization container.
Validating the ML-KEM / ML-DSA encodings themselves against published NIST KATs
is tracked separately. The vectors are scoped to the default (non-fips) build;
the fips build is a distinct wire (different `PROTOCOL_VARIANT`, 65-byte
classical key) and would need its own set.

The packet fixtures freeze the **cleartext** 15-byte wire image (ε; `session_id`
is off-wire — the AEAD AAD is the separate reconstructed 47-byte image, § 4.2).
The on-wire `[0..15]` header-protection mask (§ 4.6) is keyed crypto, so it is pinned
separately — by the `crypto::header_protection` KATs (NIST SP 800-38A F.1.5 for
AES-256-ECB, RFC 9001 § A.5 for ChaCha20), the `to_wire_masked` /
`RawPacket::unmask_header` round-trip, and the `security_invariants` HP
regressions — which keeps this fixture set and `wire_vectors_decode.py`
crypto-free while still pinning the masked wire by composition.

The packets use a hand-rolled big-endian codec (no serialization dependency);
the handshake uses `borsh`, pinned to an exact `=` version in `core/Cargo.toml`
so a minor bump cannot silently shift those bytes. An **intentional** wire change
is landed by bumping `WIRE_VERSION` / `PROTOCOL_VERSION` and regenerating:

```sh
PHANTOM_REGEN_WIRE_VECTORS=1 cargo test --manifest-path core/Cargo.toml --lib
PHANTOM_REGEN_WIRE_VECTORS=1 cargo test --manifest-path core/Cargo.toml --test wire_vectors
```

---

## 12. Connection migration & liveness (Phase 4)

One PQ-pinned identity survives a substrate change — Wi-Fi↔cellular, NAT-rebind, or a
**server** failover / multi-homing / egress-NAT rebind — **without** re-running the
kilobyte hybrid handshake. The session keeps the same internal `session_id` and the
same AEAD keys; only the underlying network path changes. The connection loses
**throughput** briefly, never **liveness**. This rides entirely on the **existing**
wire — there is no migration-specific packet type and no wire bump beyond ① (§ 5);
migration reuses the `PATH_VALIDATION` flag (§ 4.3), the `path_id` header byte
(§ 4.2 / § 7), and the rotating routing `ConnId` (the demux key — § 4.7; the
`session_id` is off-wire since ε). One live path at a time — aggregation / simultaneous
multipath is out of scope.

**SDK-boundary principle.** The product on top owns *when* to migrate (it has the best
signal — `NWPathMonitor` / `ConnectivityManager`, or a server-side failover decision);
the SDK owns *how* to survive it. Migration is **embedder-triggered** and **symmetric**:
the client triggers its own move with `migrate(new_local_addr)`, the server triggers its
own with `migrate_server(new_local_addr)` (Rust-only — server migration is a
native-deployment operation), and **each peer is the detector / validator / follower for
the other's move** (§ 12.1 is written from the client-moves perspective; a server move is
its exact mirror).

### 12.1 The switch (detect → challenge → validate → swap)

1. **Client rebind.** `migrate(new_local_addr)` binds a fresh local UDP socket,
   keeps the old one for the overlap (broken-rebind safety), bumps the client-owned
   send `path_id` to a fresh non-zero value, and routes app data + ARQ retransmits
   out the new socket. (Path 0 is permanently *validated*; a fresh non-zero label is
   what lets the server tell the new path apart and challenge it.)
2. **Server detect.** The Phase-1 connection-ID demux already routes a known
   `session_id`/CID arriving from a new source 5-tuple into the same session, and the
   new source is registered as the migration **candidate** only from an
   AEAD-authenticated frame (M-1, 2026-06-11 audit — a spoofed datagram never
   decrypts, so it cannot clobber the candidate). Detection is therefore
   **address-driven**, not purely path-id-driven, and covers two cases:
   - A deliberate `migrate()` bumps the client send `path_id` to a fresh non-zero
     value, which the server sees as a not-yet-`Validated` path and challenges on
     that path id (step 3).
   - A **passive NAT-rebind** keeps `path_id` 0 — permanently *validated* — so the
     client never bumps the label. The server still detects the new authenticated
     source (the migration candidate) and challenges it on a **reserved validation
     path-id** (`REBIND_VALIDATION_PATH_ID`, M-3), carved out of the active-migration
     id space, which the registry can take `Validating → Validated` independently of
     the always-`Validated` path 0. The reserved id is retired after a successful
     promotion so a *later* rebind re-challenges from scratch.

   In both cases the challenge goes **only to the candidate** (its claimed address)
   under the same 3× anti-amplification cap (§ 12.3), and the peer swaps only on a
   valid echo from that address (step 4) — anti-spoof is identical for the two paths.
   *(M-3, autonomous passive-rebind recovery — shipped 2026-06-15. The rebind's
   upload is also delivered immediately via PATH-001b recv-relax, § 12.2, so the
   session never stalls in either direction.)*
3. **Server challenge.** The server mints a `path_id`-bound entry for the new source
   (the migrated path id, or the reserved rebind id for a passive rebind) and sends a
   `PATH_VALIDATION` packet carrying a fresh **32-byte** random challenge to it
   (`PathRegistry::issue_challenge`). The legitimate peer — the only party holding the
   session AEAD key — echoes the bytes back in a `PATH_VALIDATION` response.
   Verification is **constant-time** (`subtle::ConstantTimeEq`, Invariant 6): a match
   transitions the path `Unvalidated → Validating → Validated`, a mismatch → `Failed`.
4. **Server swap.** On validation the server atomically switches its peer
   (`ArcSwap<SocketAddr>`) to the new source, drops the queue aimed at the dead
   address (the L1 ARQ re-carries every un-ACKed reliable byte on the new path with
   fresh packet numbers — § 5), retires the old `path_id`, and **resets the RTT
   estimator + congestion controller** (QUIC §9.4) — Wi-Fi→cellular is a different
   network, so the old bottleneck/RTT must not carry over and trigger a spurious
   retransmit storm.

**Server-initiated migration (the mirror — A2a).** A server move is the same machinery
with the roles swapped. `migrate_server(new_local_addr)` rebinds the server's *send*
socket (keeping the old receive path — the listener demux — alive through the overlap,
so c2s never drops) and bumps the server's send `path_id`, so the client sees a new s2c
source. The **client** is then the detector/validator/follower: its socket is unconnected
(so it can hear the new server source — it would otherwise be dropped at the kernel), it
commits the new source as a candidate **only post-AEAD** (M-1), path-validates it under
the 3× anti-amp cap (step 3), and on a valid echo switches its c2s send target to the new
server address (step 4, mirrored). The client also **reflects** the CID rotation (§ 4.7):
on authenticating the server's new `path_id` it bumps its own `path_id` + rotates its c2s
chain, which makes the server slide its c2s demux window so the rotated CID stays routable
(no stranding). So a server failover is followed seamlessly *and* unlinkably in both
directions (§ 12.5).

### 12.2 PATH-001 — strict send-gate, relaxed recv-delivery (Invariant 6 / RFC 9000 §9.3)

- **PATH-001a — send-gate (strict).** Application data is *sent* only to the
  established peer / a `Validated` path. To an *unvalidated* source the server sends
  **only** the `PATH_VALIDATION` challenge. This is the anti-redirection /
  anti-amplification core; it is non-negotiable.
- **PATH-001b — recv-delivery (relaxed).** AEAD-authenticated, non-replayed app data
  is *delivered* regardless of which source/path it arrived on. Dropping authenticated
  data by source buys no security — AEAD already gates authenticity and the
  per-direction replay window (§ 5) gates duplicates — and would needlessly stall a
  NAT-rebind's *upload* for ~1 RTT. The new source still triggers register → challenge.

The asymmetry is load-bearing: the client sends to the **pinned, unchanged** server
address (always "validated" for it), so on a break-before-make rebind the client's
**upload is seamless** (server delivers it recv-relaxed) while the server's
**download** resumes once it validates the new path (~1 RTT).

### 12.3 Anti-amplification (D9 / RFC 9000 §8.2)

To an unvalidated (possibly spoofed) address the server is **challenge-only** and
caps total bytes sent to **≤ 3× the bytes received** from that address. A spoofed
`(victim_addr, hijacked CID)` never echoes the unguessable 32-byte challenge → never
`Validated` → never switched-to; the only traffic a victim sees is the capped
challenge (≈1×). Without this cap, *known CID + spoofed source* would be a reflector.

### 12.4 Liveness (P4.3)

A silently-**dead** path (cellular degraded; the embedder missed the OS event) is
detected autonomously: **N×PTO of inbound silence while reliable data is
outstanding** (`PTO = max(min_pto, 3 × min_rtt)`) → the path is down. The session is
**held alive** — keys retained, outbound buffered + retransmitted — and the
`ConnectionState` surfaces **`Migrating`** so the embedder reacts (calls `migrate()`).
Inbound life resuming (a successful migrate, or the path's return) recovers
`Migrating → Connected`; no recovery before a **migration-idle timeout** transitions
to the terminal **`Dead`** (so `recv()` errors instead of hanging). The detector runs
on both peers via the shared data pump, so a server detects a vanished client
symmetrically. Detection is read-only over existing signals (BBR in-flight + an
inbound-activity timer).

**Idle keep-alive PINGs (Direction #3 — download-only liveness).** The in-flight
gate above means a purely-passive **download-only** path — which sends only ACKs
and so has zero reliable bytes in flight — would never trip the inactivity sweep,
leaving a silently-dead downstream unnoticed. To close that gap, an otherwise-idle
`Connected` session emits a small **`ENCRYPTED | KEEPALIVE`** packet (empty payload,
§ 4.3) once per `keepalive_interval` (default 15 s; off if `None`). The peer answers
with a **`KEEPALIVE | ACK`** PONG; both are AEAD-sealed control frames carrying no
application bytes, so neither reaches `recv()`. The unanswered PING is an
**outstanding probe** the sweep folds into its in-flight gate — so a dead downstream
on a download-only path now surfaces `Migrating → Dead` exactly like an active path
— while the PONG refreshes the peer's inbound-activity timer symmetrically. A PING
fires only when the path is genuinely idle (Connected, nothing in flight, inbound
silent ≥ interval, ≤ one PING per interval), so steady traffic pays nothing.
`KEEPALIVE` is a spare flag bit — **no header layout or `WIRE_VERSION` change**.

### 12.5 Threat model & residual risk (honest)

- **Worst achievable, even by a privileged attacker** who sees the plaintext CID
  *and* controls an address: a **redirection-DoS** — the server sends *encrypted*
  data "to the wrong place" and the real client stops receiving — **never a hijack
  or a decrypt.** This is exactly the QUIC §9 boundary; migration does not worsen it.
  Defences: path validation (an unguessable challenge that must be echoed *from* the
  claimed address), pinned-key AEAD (an attacker without the session keys can neither
  read nor inject app data), and the per-direction replay window (§ 5).
- **Linkability — closed by ε + A2a for migration by *either* peer (EPS-02 closed).**
  Header protection (T4.6, § 4.6) masks the variable per-packet metadata, and ε
  (§ 4.2 / § 4.7) removed the inner 32-byte `session_id` from the wire (off-wire in the
  AEAD AAD) and makes the routing `ConnId` **rotate** to an independent-random value
  per migration. Rotation is **symmetric for both migration directions**:
  - **client migration** — the client advances its c2s chain on `migrate()`, and the
    server, on authenticating the new `path_id` (post-AEAD), rotates its s2c chain too
    (the socket-routed client accepts any inbound CID — no window slide, no ping-pong);
  - **server migration** — the server advances its s2c chain on `migrate_server()`, and
    the client *reflects* on authenticating the new server `path_id`: it bumps its own
    `path_id` and advances its c2s chain. The `path_id` bump makes the server slide its
    c2s demux window to the rotated CID (so it stays routable — the no-stranding fix
    that the earlier asymmetry avoided by *not* rotating c2s); the server's matching s2c
    re-rotation is `path_id`-silent, so the client does not re-reflect (terminates in
    one round). Anti-spoof is preserved exactly as on the server: the client commits the
    new server source only post-AEAD (M-1), path-validates it under a 3× anti-amp cap,
    and switches its c2s target only on a valid `PATH_RESPONSE` (§ 12.3).

  So a migration by **either** peer (client moving Wi-Fi→cellular, or a server
  failover / egress change) is **unlinkable in both directions** by an on-path /
  colluding observer (audit 2026-06-15 **EPS-02**, closed by A2a). The `version` byte
  is HP-masked as of WIRE v6 (no constant cleartext byte). **Honest caveat (not
  forward-secret):** like the HP keys, the CID chain is session-stable; a session-key
  compromise lets an attacker recompute the chain (and unmask headers) to link a
  *recorded* flow retroactively — but the payload stays forward-secret (the AEAD
  ratchets). Same posture as the HP core.
