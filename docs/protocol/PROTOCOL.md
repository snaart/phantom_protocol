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

Audit-friendly format: every field names the Rust file that is its source of
truth. The canonical wire bytes are the byte-frozen vectors in
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
| `WIRE_VERSION` | `8` | `core/src/transport/types.rs` | `PacketHeader.version` byte (HP-masked, inside the 15-byte header — § 4.2) |
| `PROTOCOL_VERSION` | `5` | `core/src/transport/handshake.rs` | `ClientHello.version`, transcript-bound |

**The two move together.** `WIRE_VERSION 8` gave the `CONTROL` flag a one-byte subtype in
its AEAD plaintext (§ 4.11) and `WIRE_VERSION 7` changed the `WINDOW_UPDATE` plaintext
(§ 4.5); in both cases `PROTOCOL_VERSION` was incremented in the same change even though no
handshake message moved a byte. That is deliberate and is the rule for any future
data-plane change: the packet-level check on `PacketHeader.version` **drops** a mismatched
frame silently — no reply, nothing the sender can observe — so a wire bump on its own would
let an older peer complete a handshake and then stall with no diagnosis. Worse, at v8 it
would not even stall: a v7 receiver has no branch that claims a `CONTROL` frame, so the
subtype byte would fall through its dispatch and be delivered to its application as one
byte of the caller's stream. Incrementing `PROTOCOL_VERSION` alongside moves the refusal to
the handshake, where it is a typed `ServerReject` naming both versions, delivered before
any session exists. An implementation that bumps only one of the two is not interoperating;
it is failing quietly.

A version increment moves a *value*. It is never licence to move a field: in particular
`protocol_variant` remains the leading field of the signed transcript and
`early_data_accepted` remains the last (§ 7).

`WIRE_VERSION` is `8`: it went `1 → 2` when the packet codec moved from
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
(**anti-fingerprint diet**) removed the last two structural
fingerprints: **(a)** the masked region grew to cover the WHOLE 15-byte header so
the **`version` byte is itself HP-masked** (no constant cleartext byte left on the
data-plane wire), and **(b)** the two cleartext `u32` length prefixes
(`payload_len` / `ext_len`) were **dropped** — `payload` is now the message
remainder (`recv_bytes` is message-framed on every transport, so they were pure
redundancy) and `extensions` left the data-plane wire — saving 8 bytes/packet
(§ 4.1 / § 4.2 / § 4.6). v6 also adds opt-in **encrypted size padding** (PADÉ
bucketing, the `PADDED` flag) so the datagram size no longer tracks the payload
size (§ 4.8). Then `6 → 7` (**cumulative flow control**) changed the `WINDOW_UPDATE`
plaintext from a 4-byte *relative credit* to an 8-byte *cumulative limit* (§ 4.5) — the only
byte that moved, and the reason it had to move is in that section. Then `7 → 8`
(**in-session control frames**) gave the long-declared `CONTROL` flag a meaning: its AEAD
plaintext now leads with a one-byte **subtype**, and the first assignment is the
session-close announcement (§ 4.11). No header byte moved. The sole routing
identifier is the outer 8-byte UDP `ConnId`, which **rotates** on each migration (§ 4.7) —
symmetrically for **both** a client- and a server-initiated migration (both directions,
EPS-02 closed by A2a; § 12.5). The handshake byte grammar is unchanged by T4.6, ε, v6, v7
or v8.
`PROTOCOL_VERSION` is `5` (bumped
`1 → 2` when the signed transcript began covering the 0-RTT verdict
`early_data_accepted` (H2) and `ClientHello` gained the `resumption_binder`
proof-of-possession field (HS-03); `2 → 3` (T4.3) when `ServerHello`'s
`server_key_package` was replaced by a 32-byte `server_nonce`, changing the
signed-transcript content; `3 → 4` alongside `WIRE_VERSION 6 → 7` — no handshake field
changed, but a peer that speaks the older flow control must be refused here rather than
left to stall, per the rule above; `4 → 5` alongside `WIRE_VERSION 7 → 8`, likewise with no
handshake field changed, so that a peer with no `CONTROL` dispatch is refused here rather
than left to deliver a subtype byte to its application; handshakes across these versions
cannot interoperate).
They exist so that:

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
| Post-quantum KEM | ML-KEM-768 (FIPS 203) | ML-KEM-768 (FIPS 203) | `ml-kem = 0.3` (RustCrypto pure-Rust) |
| Classical signature | Ed25519 | Ed25519 | `ed25519-dalek` |
| Post-quantum signature | ML-DSA-65 (FIPS 204) | ML-DSA-65 (FIPS 204) | `ml-dsa = 0.1.1` (RustCrypto pure-Rust) |
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
encoding (`core/src/crypto/hybrid_kem.rs`). Under fips the combine label
swaps to `"HybridKEM_P256_Kyber768"` (`hybrid_kem.rs`) because the classical
input differs (65-byte uncompressed SEC1 P-256 point vs 32-byte X25519).

The AEAD choice is `CipherSuite::Aes256Gcm = 1` or
`CipherSuite::ChaCha20Poly1305 = 2` (`core/src/crypto/adaptive_crypto.rs`).
Under fips only `Aes256Gcm` is selectable; the `ChaCha20Poly1305` enum variant
is retained for wire-format stability but its selection returns
`CoreError::CipherSuiteUnavailable`.

**The suite is not negotiated — each peer picks it locally, and the two picks
must agree.** There is no cipher field anywhere on the wire: both sides call
`HwCaps::detect().recommended_cipher()` (AES-NI / ARMv8-crypto present → AES,
otherwise ChaCha) and derive their keys under the corresponding label pair
(§ 3). The suite therefore also selects the header-protection mask primitive
(§ 4.6). Two peers that resolve `detect()` differently — say an x86-64 client
with AES-NI against a server on a core without an AES extension — complete the
handshake (the signature does not depend on the suite) and then fail every
subsequent packet, because they are using different keys and a different mask.
A second implementation should treat this as a **deployment constraint**, not a
capability to probe: pick one suite for a deployment and pin it on both ends.
`adaptive_crypto::negotiate_cipher` exists but has no caller — it is not a
protocol mechanism today. Under fips this cannot bite: the recommendation is
pinned to `Aes256Gcm` regardless of hardware.

---

## 3. KDF label inventory

Every place that derives keying material from a master uses a string label to
domain-separate. Adding or changing any of these is a wire-incompatible
change.

| Label | Construction | Purpose |
| --- | --- | --- |
| `"HybridKEM_X25519_Kyber768"` / `"HybridKEM_P256_Kyber768"` (fips) | `HKDF-SHA-256(classical_secret \|\| kyber_secret)` | hybrid KEM shared secret (`hybrid_kem.rs`) |
| `b"phantom-transport-key"` | `HKDF-Expand(PRK = shared_secret, info = label, 32)` | auxiliary `CryptoState.session_key` — **not** on the AEAD key path (the per-direction AEAD subkeys derive straight from `shared_secret` via the `phantom-aes-*` / `phantom-cc20-*` labels below); derived but read by nothing today (`transport/session.rs`) |
| `"phantom-aes-send-v1"` / `"phantom-aes-recv-v1"` | `derive_key_32` over `shared_secret` | AES-256-GCM per-direction subkeys (`adaptive_crypto.rs`) |
| `"phantom-cc20-send-v1"` / `"phantom-cc20-recv-v1"` | `derive_key_32` | ChaCha20-Poly1305 per-direction subkeys (`adaptive_crypto.rs`) |
| `"phantom-nonce-pfx-v1"` | `derive_key_32(shared_secret)[0..4]` | 4-byte nonce prefix — the first 4 bytes of the 32-byte output (`adaptive_crypto.rs`) |
| `b"phantom-rekey-v1"` | `HKDF-Expand(PRK = current_traffic_secret, info = label, 32)` | forward-derive the next per-epoch traffic secret (`transport/session.rs`) |
| `b"phantom-resumption-secret-v1"` | `HKDF-Expand(HKDF-Extract(salt = ∅, ikm = shared_secret), info = label, 32)` | 0-RTT resumption secret (`transport/handshake.rs`) |
| `b"phantom-session-id-v1"` | `SHA256(label \|\| shared_secret \|\| nonce)` | session id derivation (`transport/handshake.rs`) |
| `b"phantom-early-data-key-v3"` | `HKDF-Expand(HKDF-Extract(salt = client_nonce, ikm = resumption_secret), info = label, 32)` | 0-RTT early-data AEAD key (`crypto/kdf.rs`) |
| `b"phantom-early-data-nonce-v3"` | `HKDF-Expand(HKDF-Extract(salt = client_nonce, ikm = resumption_secret), info = label, 12)` | 0-RTT early-data AEAD nonce (`crypto/kdf.rs`) |
| `b"phantom-pow-cookie-v1" \|\| hour_be` | `HKDF-Expand(HKDF-Extract(salt = ∅, ikm = master_secret), info = label \|\| hour_be, 32)` | hour-rotated cookie / PoW HMAC key (`transport/handshake.rs`) |
| `"phantom-hp-send-v1"` / `"phantom-hp-recv-v1"` | `derive_key_32(label, initial_secret)` | per-direction, session-stable header-protection keys (§ 4.6; `crypto/header_protection.rs`) |
| `"phantom-cid-c2s-v1"` / `"phantom-cid-s2c-v1"` | `derive_key_32(label, initial_secret)` | per-direction rotating-CID chain secrets (§ 4.7; `crypto/cid_chain.rs`) |
| `"phantom-cid-v1"` | `derive_key_32(label, cid_secret \|\| i.to_be_bytes())[0..8]` | the 8-byte routing CID at migration index `i` (§ 4.7; `crypto/cid_chain.rs`) |
| `"phantom-resume-binder-v1"` | `derive_key_32(label, resumption_secret \|\| resume_session_id \|\| client_nonce)` | 0-RTT resumption proof-of-possession binder (§ 6.2; `transport/handshake.rs`) |

> **Removed — `"phantom-faketls-*-v1"` (vestigial).** The legacy FakeTLS leg that
> derived these three outer-obfuscation labels (`c2s` / `s2c` / `pfx`) was deleted.
> Its replacement, the optional `mimicry` feature (`MimicTlsLeg`, § 9.1), is
> **framing-only with no outer AEAD**, so it derives **no** outer keys — there are
> no `phantom-faketls-*` labels on any current build. Do not reintroduce them.

`derive_key_32` is the side-agnostic helper that dispatches per build:
`blake3::derive_key(label, ikm)` on the default build, `HKDF-SHA256(salt=∅,
info=label)` under fips (`core/src/crypto/kdf.rs`). The `-v3` suffix on
the early-data labels is historical naming; the labels are unchanged
wire-format constants.

**Extract-vs-Expand is per call site, and it is load-bearing.** The table above
distinguishes the two deliberately: `phantom-transport-key` and
`phantom-rekey-v1` run **Expand only**, treating their input as an existing PRK
(`Hkdf::from_prk`), while `phantom-resumption-secret-v1`, the two early-data
labels and the cookie secret run a full **Extract-then-Expand**
(`Hkdf::new(salt, ikm)`). An implementation that uniformly extracts, or
uniformly does not, derives different bytes at half the call sites and fails at
the first packet rather than at the handshake.

**Per-direction keys are one derivation plus a side swap.** Each per-direction
label pair (`phantom-aes-{send,recv}-v1`, `phantom-cc20-{send,recv}-v1`,
`phantom-hp-{send,recv}-v1`, `phantom-cid-{c2s,s2c}-v1`) is derived once from
the same secret and then assigned by role, so one peer's *send* key is the
other's *recv* key. The **initiator (client)** takes the `send` label as its
send key; the **responder (server)** swaps, taking the `recv` label as its send
key (`CryptoSession::build`'s `swap` argument, `HeaderProtector::derive`,
`CidChain::derive` — all fed the session's `is_server` flag). The `c2s` / `s2c`
CID labels name their direction outright and so need no mental swap: the client
always stamps from `c2s`, the server from `s2c`.

---

## 4. Packet format

### 4.1 `PhantomPacket` (the sole on-wire data packet)

```rust
pub struct PhantomPacket {
    pub header: PacketHeader,   // 15 bytes on the wire (§ 4.2); session_id is off-wire
    pub payload: Vec<u8>,       // AEAD ciphertext (+16-byte tag) — ENCRYPTED is set on every
                                // post-handshake frame; coalesced bundle when COALESCED
    pub extensions: Vec<u8>,    // TLV headroom; NOT serialised on the v6 wire, so a
                                // decoder always yields it empty (see below)
}
```

Source: `core/src/transport/types.rs`. There is no enum wrapper — the recv path
deserializes a bare `PhantomPacket` directly (`PhantomPacket::from_wire`) and
**drops** any frame whose `header.version != WIRE_VERSION`
(`api/session.rs`). An unparseable frame is dropped, never panicked on.

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
wire (it was always empty; the AEAD AAD still binds an empty extensions slice), so
`from_wire` unconditionally yields an empty `extensions` — there is no encoding a
sender could use to deliver a non-empty one, and a decoder needs no rule for
ignoring what it cannot receive.

`payload` is the AEAD ciphertext (plus its 16-byte tag) — and on the live wire it
always is: every post-handshake packet, including the `ACK`, `PATH_VALIDATION`,
`WINDOW_UPDATE`, `KEEPALIVE` and `COVER` control frames, sets
`PacketFlags::ENCRYPTED`, and the recv loop **drops** any post-handshake frame
without it (Invariant 2). The unencrypted `PhantomPacket` constructors are
non-production. The AAD is the reconstructed 47-byte header image (§ 5).

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

Source: `core/src/transport/types.rs`.

| Bit | Constant | Meaning |
| --- | --- | --- |
| `0x0001` | `RELIABLE` | Requires ACK; retransmitted on timeout |
| `0x0002` | `ACK` | This packet is an authenticated ACK (`ENCRYPTED`; AEAD payload = a `Sack` — § 4.5) |
| `0x0004` | `FIN` | Stream finished |
| `0x0008` | `UNRELIABLE` | Fire-and-forget |
| `0x0010` | `PRIORITY` | Voice/video frame priority hint |
| `0x0020` | `ENCRYPTED` | Payload is AEAD ciphertext |
| `0x0040` | `COMPRESSED` | _Defined but unused_ — no send path sets it and the recv path never decompresses (`transport/compression.rs`'s `AdaptiveCompressor` is not wired to the packet path). Treat as reserved; do not emit |
| `0x0080` | `CONTROL` | In-session control frame: the AEAD plaintext leads with a one-byte subtype (§ 4.11). Always `PADDED`; carries no application bytes |
| `0x0100` | `REKEY` | Sender rekeyed; receiver trial-decrypts at `header.epoch` and commits the ratchet on AEAD success (§ 5) |
| `0x0200` | `PATH_VALIDATION` | AEAD plaintext is exactly a 32-byte challenge or its echo (connection migration — § 12; a plaintext of any other length is dropped) |
| `0x0400` | `COALESCED` | Payload bundles inner packets as `[count: u16][len1: u16][p1]…` (full byte layout — § 4.5) |
| `0x0800` | `WINDOW_UPDATE` | Payload is a big-endian `u64` **cumulative** flow-control limit (per-stream; the total the receiver is willing to have sent on that stream, counted from its first byte — see § 4.5) |
| `0x1000` | `KEEPALIVE` | Idle keep-alive PING (empty payload); `KEEPALIVE \| ACK` is the PONG echo (download-only liveness — § 12.4) |
| `0x2000` | `PADDED` | Anti-fingerprint size padding present: the AEAD plaintext ends with a `‹zeros› ‖ pad_n:u16be` trailer the receiver strips post-decrypt (§ 4.8) |
| `0x4000` | `COVER` | Anti-fingerprint cover (dummy) traffic: empty inner plaintext (usually `PADDED`); authenticated then dropped by the peer, never reaches `recv()` (§ 4.8) |
| `0x8000` | _reserved_ | Future amendments |

`ENCRYPTED` is the post-handshake invariant flag — the API layer sets it on
every application-data packet, and the receive loop drops **every** unencrypted
post-handshake packet as a stripped-flag downgrade attempt, an empty-payload one
included (Invariant 2 / M-2; `api/session.rs`). Dropping the empty case too is
what closes the forged standalone `FIN`, whose only effect would otherwise be to
tear down a stream without any AEAD verification. ACK packets are **authenticated control frames**
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

**Receiver dispatch order, and what an unknown bit means.** The flags are a
bitfield, not a tag: several are legitimately set at once (`ENCRYPTED | RELIABLE |
FIN`, `ENCRYPTED | KEEPALIVE | ACK`, `ENCRYPTED | COVER | PADDED`), so *which
branch claims the packet* is part of the format rather than an implementation
detail. A receiver dispatches in this order, each step consuming the packet:

1. `header.version != WIRE_VERSION` → drop (§ 4.1).
2. `ENCRYPTED` absent on a post-handshake frame → drop, unconditionally, empty
   payload included (Invariant 2 / M-2). Handshake messages never reach this
   dispatcher: they ride the transport's own framing (§ 4.9, § 9) and are
   consumed by § 6.
3. AEAD open (§ 5), then the replay window (Invariant 4). Only now is anything
   below trustworthy.
4. `PADDED` → strip the trailer (§ 4.8) *before* any further parse, so every
   branch below sees the true inner plaintext.
5. `KEEPALIVE` → a bare one is a PING, answer `KEEPALIVE | ACK`; one already
   carrying `ACK` is the PONG, nothing further. This **precedes** the `ACK`
   branch: a PONG is not a SACK and must not be parsed as one.
6. `CONTROL` → dispatch on the leading subtype byte (§ 4.11) and consume the
   packet on **every** arm, the unknown subtype included. It sits here — after the
   AEAD open and the replay window of step 3, before everything below — and both
   sides of that placement are the format, not an implementation choice: earlier and
   a forged or replayed one-byte datagram would end a session; later and an unknown
   subtype would fall through to step 12 and be delivered as application data. It
   follows `KEEPALIVE` for the same reason `KEEPALIVE` precedes `ACK`: the two
   branches are disjoint on today's frames, and ordering them fixes which one would
   claim a frame that ever set both.
7. `COVER` → drop after the liveness bookkeeping; it carries no application data.
8. `ACK` → the plaintext is a `Sack` (§ 4.5); a `FIN` riding the same packet
   closes the stream behind the data already queued for delivery.
9. `WINDOW_UPDATE` → exactly 8 bytes of cumulative limit (§ 4.5).
10. `PATH_VALIDATION` → exactly 32 bytes of challenge or echo (§ 12.1).
11. `COALESCED` → split the bundle and deliver each sub-payload in order (§ 4.5).
12. Otherwise it is application data. `RELIABLE` reassembles by the
    `stream_offset` prefix and is acknowledged (§ 4.5), and a `FIN` on it
    half-closes the stream only once the in-order cursor has passed the FIN's own
    offset — so a FIN that overtakes a gap cannot truncate the data behind it.
    Anything else is delivered as it arrives, with a `FIN` closing the stream
    immediately after this packet's bytes.

A bit this implementation does not recognise — today only `0x8000` (§ 7) — takes
no branch and causes no rejection: the packet is dispatched on the bits that *are*
known and the unknown one is ignored. That is safe rather than lax, because the
flags word is inside the AEAD AAD (§ 4.2): an unknown bit can only have been set
by the peer holding the session key, never by the network, and a network flip
fails the tag. A receiver must not reject a packet for an unrecognised flag, and a
sender must not set one — a reserved bit is spent by a version bump, not by
unilateral use.

### 4.4 Identifiers: `SessionId` and `stream_id`

`SessionId` (`[u8; 32]`, 32 bytes; `types.rs`) is the negotiated session
identifier. It is bound into the AEAD AAD (§ 4.2) but is **off-wire** since v5 —
migration and demux routing are by the outer rotating `ConnId` (§ 4.7), not by
`session_id`. Server-side it is derived as
`SHA256(b"phantom-session-id-v1" || shared_secret
|| client_nonce)` (`transport/handshake.rs`); the client adopts the
`session_id` echoed in the `ServerHello`.

**`stream_id` allocation.** The header's `stream_id` (u16 big-endian at wire
offset 11, § 4.2) names one logical stream inside the session. There is no
stream-open handshake: a stream exists the moment a packet carries its id, so the
two peers must be unable to *invent the same id independently*. That is arranged
by parity, QUIC-style, and it is the one rule a second implementation cannot
derive from the frozen vectors — every fixture carries a single hard-coded id.

| Id | Owner | Meaning |
| --- | --- | --- |
| `0` | — | Session control channel. Reserved; never allocated to an application stream |
| `1` | — | The raw-application stream behind `send()` / `recv()`, and the id stamped on keep-alives (§ 12.4). Reserved |
| odd, `3, 5, 7, …` | the **initiator** (the peer that sent the `ClientHello`) | Streams it opens |
| even, `2, 4, 6, …` | the **responder** | Streams it opens |

Each side allocates from its own parity in steps of two, so no id one peer
produces can ever be an id the other produces, and concurrent stream opens on
both ends never collide. Source: `transport/multiplexer.rs`
(`StreamDemultiplexer::new_with_role`), wired at both call sites in
`api/session.rs` (`is_client = true` for the connecting side, `false` for the
accepting side).

The parity is an **allocation** discipline, not a receive-side check: a receiver
creates a stream on first sight of any id greater than 1 and never asks whose
parity it is. That is deliberate — an id is not a capability, and rejecting the
wrong parity would buy nothing an authenticated peer could not sidestep — but it
does mean a peer that allocates in the wrong parity produces no error anywhere.
Its stream and its peer's stream of the same id merge into one, which surfaces as
interleaved application bytes, not as a parse failure. Get this wrong and every
byte-level vector in `INTEROP.md` still passes.

Concurrent *receive* streams are capped at `MAX_STREAMS = 256` per session
(`api/session.rs`); a reliable segment naming a new id past that cap is refused
rather than admitted, and — being unrecorded — is not acknowledged, so the peer
retransmits and that stream stalls instead of the table growing without bound.

### 4.5 AEAD-plaintext payload codecs (SACK / reliable frame / COALESCED / WINDOW_UPDATE)

These are the **AEAD plaintext** that lives *inside* `PhantomPacket.payload`
once the AEAD opens — they are NOT the frozen outer `PhantomPacket` container
(§ 4.1), so changing one does not invalidate `core/tests/wire_vectors`, which pins
only the container. They are authenticated (inside the AEAD) and invisible on the
wire. All integers are big-endian, matching the rest of the codec.

Not being frozen by a fixture is not the same as being free to change. Two peers
disagreeing about one of these codecs do not fail to parse — the frames decrypt, and
the peers then disagree about how much may be sent or what was acknowledged, which
surfaces as a stall rather than as an error. So a change to the *meaning or width* of
one of them is a version bump like any other: `WIRE_VERSION 6 → 7` was exactly that,
and nothing outside this section moved.

**SACK — the ACK control-frame plaintext** (`core/src/transport/sack.rs`).
Carried as the plaintext of an `ENCRYPTED | ACK` packet (§ 4.3). The ranges are
inclusive `(low, high)` runs of acknowledged reliable `stream_offset`s (the
reliable stream-frame index defined below in this section), sorted **descending**
(highest first), non-overlapping and non-adjacent;
there is always ≥ 1 range. Lengths use a **"length − 1"** convention, so a
single-acked offset encodes as `len = 0`.

A SACK is scoped to **one stream**: the offsets it covers belong to the stream
named by the enclosing packet's `header.stream_id`, and the acking packet also
echoes the `path_id` the acked data arrived on. Its own `packet_number` comes
from the acker's ordinary per-direction counter (§ 5), so an ACK is
indistinguishable from data as far as nonce and replay-window bookkeeping go.

| Offset | Field | Width | Encoding |
| --- | --- | --- | --- |
| 0 | `largest_acked` | 4 | u32 big-endian — highest acked offset; `= ranges[0].high` |
| 4 | `ack_delay_us` | 4 | u32 big-endian — sender-measured ACK delay (µs) |
| 8 | `range_count` | 2 | u16 big-endian — `1 ≤ N ≤ MAX_SACK_RANGES (32)` |
| 10 | `first_len` | 4 | u32 big-endian — width − 1 of the first (highest) range; `first_low = largest_acked − first_len` |
| 14 | `gap, len` × (N − 1) | 8 each | two u32 big-endian per continuation: `gap` = unacked sequences below the previous range (≥ 1), `len` = width − 1; `high_i = prev_low − 1 − gap`, `low_i = high_i − len` |

`ack_delay_us` is the one number in an acknowledgement that the receiving side
did not measure itself, so it is **advisory**: a conforming sender may subtract
it from a round-trip sample only where the result stays at or above a locally
observed minimum (RFC 9002 § 5.2/§ 5.3), and drops the claim whole rather than
trimming it to fit when it does not — which also disposes of a claim larger than
the round trip it rides on, since such a claim fails the same test. Subtracting
it unconditionally hands an authenticated-but-hostile peer the local congestion
window. Emitting `0` is always legal.

That rule is a **lower** bound and only a lower bound. Anywhere between the
locally observed minimum and the round trip just timed the peer's claim still
chooses the answer, so a sender must not treat an adjusted sample as a
measurement of the path: a peer claiming the whole difference on every
acknowledgement holds every derived reading at the best round trip the path ever
had. That is harmless for a minimum filter, which a peer could equally starve by
reporting nothing, and it is a real limitation for anything reporting the
*latest* round trip — see `phantom.path.rtt` in
[`docs/observability/metrics-catalog.md`](../observability/metrics-catalog.md).

Minimum wire size = `10 + 4 + 8 × (N − 1)`: 14 bytes for one range, 22 for two.
`from_wire` rejects `range_count == 0` / `> 32` (`Malformed` / `TooManyRanges`),
a `gap == 0` (adjacent ranges — sender must coalesce), and any gap/len that
underflows the sequence space (`Malformed`); a buffer shorter than the declared
ranges is `Truncated`. The peer acts on a SACK **only after AEAD verify** (H1).

**When an acknowledgement is required.** Exactly one class of packet is
acknowledged: a `RELIABLE` application-data frame. Every one that survives the
AEAD open and the replay window is acknowledged **immediately and individually** —
the receiver accepts the segment into its reorder buffer, derives a fresh `Sack`
from the live reorder state, and emits an `ENCRYPTED | ACK` inline on the same
stream, stamped with the `path_id` the data arrived on. There is no delayed-ACK
timer and no every-other-packet rule; a second implementation may add one, since
the SACK is cumulative and a sender's loss detection reads only what a SACK
covers, but nothing here waits for it.

Nothing else is acknowledged: unreliable data, `COALESCED` bundles (their
sub-payloads are not independently sequenced), `WINDOW_UPDATE`,
`PATH_VALIDATION` and `COVER` frames all take their own dispatch branch and
produce no ACK. An ACK is itself never `RELIABLE` and is never acknowledged —
a lost one costs nothing, because the next SACK re-covers the same offsets.
`PATH_VALIDATION` and `KEEPALIVE` have their own replies (the 32-byte echo,
§ 12.1, and the `KEEPALIVE | ACK` PONG, § 12.4); neither is an acknowledgement of
data and neither carries a `Sack`.

**Reduction policy when a receiver holds more than `MAX_SACK_RANGES` islands.**
The cap is a decode rule, so an over-full reorder buffer has to give something
up before it encodes. The sender **keeps the top `MAX_SACK_RANGES − 1` ranges
and the single lowest one, dropping from the middle**
(`Sack::from_ascending_coalesced`). The two it never drops are the two nothing
else can substitute for: the highest carries `largest_acked`, against which
every packet- and time-threshold loss decision is measured, and the lowest is
the receiver's contiguous delivered run, which is what retires the bulk of the
send buffer — omit it and the peer retransmits a whole window of data it has
already delivered *and* feeds a whole window of fabricated loss to congestion
control. The middle islands are the recoverable ones: this receiver rebuilds the
range set from live reorder state on every ACK, so an island dropped once is
merely deferred until the set falls back under the cap.

A second implementation is free to choose differently — the encoded form is what
must decode, not the selection — but it should not drop the lowest range, and it
should not respond to the cap by raising it, which only moves the point of
overflow. A conforming *receiver* of a SACK needs no knowledge of this at all.

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

**`WINDOW_UPDATE` plaintext** (`transport/stream.rs`). Exactly eight bytes: a u64
big-endian **cumulative limit**, scoped like a SACK to the stream named by the enclosing
header. It states the *total* number of application bytes the receiver is willing to have
sent on that stream, counted from the stream's first byte. A plaintext of any other length
is dropped.

Both ends count the same quantity in the same units, which is what lets the number be
compared without either end inferring the other's state: the sender counts every reliable
application byte it puts on the wire, counting each byte **once** — a retransmission is not
counted again, and a first transmission that the transport refused (so those bytes never
left) is subtracted back — and the receiver counts every **reliable** byte it has delivered
to its application. A sender MUST NOT transmit a byte whose position in that count would
exceed the highest limit it has received.

Unreliable data is outside this count on both ends, and has to be: a sender does not consult
the window before emitting it — nothing retransmits it, so no window could hold it back — and
a receiver that counted it would advertise a limit running ahead of the total its peer keeps
by exactly the unreliable volume. The consequence is not a lost byte but a lost promise: the
advertisement of a conforming peer would then be cut down by the local ceiling below, which
exists for a peer inventing numbers. Unreliable bytes are still delivered and still bounded,
by the receiver's own delivery backlog rather than by this window.

Three properties follow from the value being a monotone total rather than an increment, and
between them they are why this frame is never acknowledged and never retransmitted. A
conforming implementation MUST provide all three, which it does by applying an inbound limit
as `limit = max(limit, advertised)`:

  * **idempotent** — a duplicate frame grants nothing extra;
  * **reorder-safe** — a stale frame overtaken by a newer one states a smaller total and is
    discarded by the maximum;
  * **loss-tolerant** — a frame that never arrives costs nothing, because the next one to
    arrive states the whole truth rather than the difference since the last.

The relative-credit encoding this replaced had none of them. Its deficit from a lost frame
was permanent and monotone — at loss rate `p` it accrued as `p ×` the bytes transferred — so
on a lossy path it reached the initial window in finite time and stopped the sender for
good, with nothing outstanding and therefore no acknowledgement that could ever free it.

The two ends of the ledger are numbers, not encodings, and a second implementation has to
match them or the room it grants is silently discarded:

  * every stream starts at `INITIAL_STREAM_WINDOW = 64 KiB` — that is the limit both ends
    assume before any `WINDOW_UPDATE` is seen. An implementation that treats the opening
    limit as zero deadlocks, because the first frame is only emitted once the peer's
    application has consumed bytes it would never have been sent;
  * a receiver MUST NOT advertise more than `consumed + MAX_RECV_WINDOW`, with
    `MAX_RECV_WINDOW = 1 MiB` the ceiling its auto-tuning may not grant past;
  * a sender honours at most `MAX_SEND_WINDOW = 1 MiB` — the same figure — beyond the bytes
    it has already sent, whatever number arrives. A conforming peer is never clamped by
    this; it exists so that a peer advertising `u64::MAX` buys exactly one window of
    permission and must send another frame for more.

When to emit is a local choice (this implementation emits when unreported consumption
crosses half the initial window, when the advertised window grows, and in answer to a
persist probe); what the number means is not.

**Persist probe.** A `WINDOW_UPDATE` is emitted once, in a frame nothing acknowledges or
retransmits. A lost one is repaired by the next — *provided there is a next*, and the case
where there is not is this one: the receiver's application has consumed all it is going to
for now, so it has no reason to speak again, while the sender is stopped at a limit a lost
frame left below the truth, with data queued and *nothing outstanding*. No acknowledgement
is due either, so no event can free it. The signal has to come from the sender, because
"data queued and no room" is visible only there: a receiver cannot tell a blocked peer from
an idle one, since both are silent and both leave its counters unchanged.

In that state a sender MAY emit a **persist probe** — a `RELIABLE` frame carrying an empty
payload after its 4-byte stream offset, i.e. the FIN sentinel's shape without the `FIN`
flag.

The offset a probe carries MUST be one the receiver has already acknowledged, never
a fresh one; this implementation repeats the highest such offset. A probe on a fresh
offset would sit above the data the closed window is holding back, so the receiver
would hold it as an out-of-order island and SACK it there, raising `largest_acked`
past every offset the sender transmits next — which the sender's loss detector reads
as loss. An acknowledged offset cannot do that, because a receiver deriving its SACK
from live reorder state (as above) never acknowledges an offset it did not keep: it
has either delivered that offset or is still holding it out of order. A repeat of the
first is discarded as a duplicate before the reorder buffer is consulted; a repeat of
the second finds the offset already buffered and is dropped without adding an entry
or charging a byte. In both cases the SACK the receiver returns is the one it would
have sent anyway, and `largest_acked` does not move. It follows that a probe consumes
no offset, is not tracked as in flight and is not retransmitted: an unanswered probe
is simply asked again. This implementation sends no more than one per retransmit
timeout, and only while nothing is outstanding — and only on a stream the peer has
acknowledged something on, since otherwise there is no offset to repeat.

A receiver MUST deliver nothing to the application for an empty reliable segment. It SHOULD
answer one by emitting that stream's current limit. Because the limit is a total, one answer
repairs however many earlier frames the path ate — and it is still bounded by consumption: a
receiver whose application has consumed nothing re-states the number its peer is already
stopped at, and correctly leaves it stopped. A receiver that does not implement the answer is
interoperable — it acknowledges the probe and its peer stays blocked exactly as it would have
without it.

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
initial_secret)` (§ 3), swapped by side exactly like the AEAD keys —
`initial_secret` being the hybrid-KEM shared secret, i.e. the epoch-0 traffic
secret and the same input the AEAD subkeys and the CID chain take. They are
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

### 4.8 Size padding (WIRE v6, anti-fingerprint)

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

### 4.9 PhantomUDP outer datagram envelope (transport framing)

Every PhantomUDP datagram is prefixed with a 9-byte cleartext envelope
(`transport/phantom_udp/envelope.rs`) that the demux routes on. It is **transport
framing, not the frozen inner wire**: it lives outside `core/tests/wire_vectors`
and changing it does not bump `WIRE_VERSION` (same status as
`TcpSessionTransport`'s 4-byte length prefix; TCP / embedded carry no envelope at
all).

| Offset | Field | Width | Encoding |
| --- | --- | --- | --- |
| 0 | `flags` | 1 | bits 7..6 = packet type (`0b00` = `Initial`, inner is a handshake message — a bare borsh `ClientHello` from the client, a discriminant-framed `ServerReply` from the server (§ 6); `0b01` = `OneRtt`, inner is the HP-masked `PhantomPacket` of § 4.1; `0b10` = `Retry`, defined but never emitted; `0b11` rejected as `ReservedType`). Bit 5 = `FRAG_BIT` (`0x20`). Bits 4..0 are reserved and **must be zero** — a datagram with any of them set is rejected (`ReservedBitsSet`) |
| 1 | `cid` | 8 | the rotating routing `ConnId` (§ 4.7), raw bytes |
| 9 | body | remainder | the inner frame; when `FRAG_BIT` is set, an 8-byte fragment subheader followed by this datagram's chunk |

Fragment subheader (present iff `FRAG_BIT` is set):

| Offset | Field | Width | Encoding |
| --- | --- | --- | --- |
| 9 | `packet_id` | 4 | u32 big-endian — disambiguates concurrently-fragmented frames from the same `cid` |
| 13 | `chunk_index` | 2 | u16 big-endian — 0-based |
| 15 | `total_chunks` | 2 | u16 big-endian |

`PATH_MTU = 1200`: a frame of at most `1200 − 9 = 1191` bytes
(`MAX_INNER_UNFRAGMENTED`) ships unfragmented; a larger frame is split into
`1200 − 9 − 8 = 1183`-byte chunks (`MAX_INNER_FRAG_CHUNK`) sharing one
`packet_id`. A frame needing more than `MAX_TOTAL_CHUNKS` of them is refused at
the **sender** (`FrameTooLarge`) rather than emitted for the peer to drop
silently.

The reassembler (`transport/fragmentation.rs`) is keyed on `(cid, packet_id)` —
the 8-byte CID zero-extended to the assembler's 16-byte key — and bounds every
input, because the key is cleartext and therefore guessable:

- `MAX_REASSEMBLED_LEN = 256 KiB` caps one logical packet, and
  `MAX_TOTAL_CHUNKS` is derived from it (`MAX_REASSEMBLED_LEN / 1200 + 1`); a
  chunk declaring more, an index at or past `total_chunks`, or a payload over
  1200 bytes is dropped;
- `MAX_CONCURRENT_ASSEMBLIES = 256` caps the in-flight partials. A chunk that
  would open a **new** assembly while the table is full does not lose out: the
  **stalest** partial is evicted first, so a spray of abandoned assemblies
  cannot lock out live traffic, and the resident memory stays bounded by the
  product of the two caps;
- the first chunk to arrive for an index **wins** — a later chunk for the same
  index never overwrites it, so an attacker who guessed `(cid, packet_id)`
  cannot corrupt a victim's reassembly (it would then fail the victim's AEAD).

A datagram shorter than the 9-byte envelope — or than the fragment subheader it
claims — is `Truncated`, never an out-of-bounds read.

The envelope is **unauthenticated** — it is a routing label only. All
authenticity and confidentiality rest on the inner AEAD (Invariants 2 / 4), and
the CID is never transcript-bound.

### 4.10 Application chunk size (a sender-side choice, not a format rule)

Nothing in the grammar above constrains how much application data a sender puts
in one packet: `payload` is the message remainder (§ 4.1) and the reliable
plaintext prefix is fixed at 4 bytes (§ 4.5). A conforming peer may pick any
chunk size and interoperate. This implementation picks
`transport::mtu::MAX_APP_CHUNK = 1156`, derived so that a full reliable chunk
becomes exactly one unfragmented PhantomUDP datagram:

```text
  1200   PATH_MTU
−    9   DATAGRAM_HDR_LEN        outer [flags][ConnId]           (§ 4.9)
------
  1191   MAX_INNER_UNFRAGMENTED
−   15   PacketHeader::SIZE                                       (§ 4.2)
−    4   RELIABLE_OFFSET_LEN     in-plaintext gap-free offset     (§ 4.5)
−   16   AEAD tag                                                 (§ 5)
------
  1156   MAX_APP_CHUNK
```

Because the chunk is a sender-side split, **a stream is a byte stream and carries
no message boundaries**: a `send` larger than the chunk budget is written as
several packets, each delivered on its own, so the peer sees one `recv` per chunk
and nothing marks where one `send` ended. An application that needs messages
frames them itself, above this layer.

The derivation, not the number, is the thing to copy: raising `PATH_MTU` (once
path-MTU discovery exists) widens the chunk with nothing else to move.
Overshooting it by a single byte is what makes the choice worth stating — the
packet then fragments into a full datagram plus a small tail, which doubles the
datagram rate for the same goodput, spends a fresh IP/UDP header plus the 8-byte
fragment subheader on the tail, and makes the segment depend on *both* datagrams
arriving, so an independent per-datagram loss rate `p` becomes ≈ `2p` per
segment — and loss recovery, the SACK loss detector (§ 4.5) and the congestion
controller all count segments, not datagrams. Budgeting for the 4-byte reliable
prefix is the worst case, so an unreliable frame simply lands four bytes under
the budget rather than over it.

On the byte-pipe legs (TCP, mimicry, WebSocket, WASI, embedded) the size is not
a correctness constraint at all — those transports frame whatever they are
handed and never fragment — so sizing for the datagram budget only costs them a
slightly higher share of per-packet overhead. Source:
`core/src/transport/mtu.rs`.

### 4.11 In-session control frames (WIRE v8)

An `ENCRYPTED | CONTROL` packet is a signal from one end of a live session to the
other. Either end may send one, at any point after the handshake has established the
session and before its own teardown. Its AEAD **plaintext**, after the § 4.8 padding
trailer has been stripped, is:

```text
  [subtype: u8] ‖ ‹subtype-defined body›
```

and, for every subtype assigned so far, the body is empty — so the whole inner
plaintext of a `CLOSE` is the single byte `0x01`. The full plaintext handed to the
AEAD is therefore `[subtype][body][pad-zeros][pad_n: u16be]`, and the trailer comes
off at step 4 of § 4.3's dispatch, before anything reads the subtype byte.

A `CONTROL` frame is a **session**-level signal, not a stream-level one. Its
`stream_id` header field is not part of its meaning: a sender stamps whatever it
normally would (this implementation uses the reserved raw-app id `1`) and a receiver
must not route the frame by it, must not create a stream for it, and must not treat
an unfamiliar value as an error. `path_id` and `epoch` are stamped and read exactly
as on any other packet. The frame carries no application bytes, so one never reaches
`recv()`.

**Padding.** A sender **must** pad a `CONTROL` frame to a § 4.8 bucket, setting
`PADDED`, regardless of the session's data-padding policy — an unpadded `CLOSE` is
`15 + 1 + 16 = 32` bytes of header-plus-ciphertext, a size nothing else in the
protocol emits, occurring exactly once, immediately before a session goes quiet.
That is a shape an observer reads without breaking anything. A receiver, however,
**must not** require the flag: `PADDED` means only "a trailer is present", so a
control frame that arrives without it is well-formed and its plaintext is read
as-is.

**Subtype registry.** Assignments grow from the bottom. `0x00` is deliberately left
unassigned so that a zeroed buffer is not a valid control frame.

| Subtype | Name | Body | Meaning |
| --- | --- | --- | --- |
| `0x00` | _unassigned_ | — | Not a valid subtype; drop |
| `0x01` | `CLOSE` | empty | The sender is closing this session and will send nothing further on it |
| `0x02`–`0xFF` | _unassigned_ | — | Drop |

The subtype byte is why this frame rides the already-declared `CONTROL` bit rather
than `0x8000`, the one flag bit still free (§ 7). A flag is a 16-entry namespace and
three in-session control frames were added in the two revisions before v8; spending
the last bit on the first of four would have left the next one nowhere to go. One
flag plus a byte of namespace costs the same on the wire and does not run out.

**Receiver rules.** All four are load-bearing:

1. A plaintext shorter than one byte — that is, an inner plaintext that is empty
   once the padding trailer is off — names no subtype. Drop it, and in particular do
   not read a missing subtype as a default: `0x00` is unassigned precisely so that
   neither a zeroed buffer nor an absent byte can be mistaken for the lowest
   assignment, which is `CLOSE`.
2. Dispatch on the first byte against a **fixed** enumeration. There is no
   length-prefixed record to walk and no field sized by the peer, so a control frame
   gives an authenticated-but-hostile peer nothing to make a receiver allocate.
3. Every arm consumes the packet, **including the unknown one**. This is the rule a
   `WIRE_VERSION` mismatch exists to protect and the reason v8 could not ship without
   it: a receiver that falls out of its control dispatch lands in its
   application-data path, and the subtype byte is then delivered to the caller as one
   byte of the stream. Silence is the correct response to an unknown subtype;
   delivery is not.
4. Dispatch **after** the AEAD open and the replay window — step 6 of § 4.3's
   order. Both matter. Before the AEAD gate, a `CLOSE` is a one-byte plaintext
   datagram that ends any session whose connection id can be guessed. Before the
   replay window, a recorded `CLOSE` datagram is the same primitive with a capture
   step in front of it. After both, the frame is idempotent for free — the second
   copy of a byte-identical close is refused before the branch runs — which is why
   the branch itself holds no state.

**A `CONTROL` frame is never acknowledged.** It takes no part in the reliability
machinery of § 4.5: it is not `RELIABLE`, it carries no `stream_offset`, it is never
entered into a send buffer, it is never retransmitted, and it never appears in a
`Sack` — the SACK ranges are stream offsets, not packet numbers, and a frame with no
offset has nothing to be named by. A receiver must not answer one with an `ACK`, and
a sender must not wait for one.

**`CLOSE` semantics.** It is announced, not negotiated. A sender emits **one or
more** copies back to back (this implementation emits 3) because redundancy is the
only loss tolerance an unacknowledged frame has, and the count is fixed rather than
conditional because the only signal that could end a retry loop would have to come
from the peer we have just stopped being able to observe. Each copy draws its own
packet number from the ordinary per-direction space, so the peer's replay window
accepts whichever arrives first and refuses the rest; a receiver must therefore
tolerate any number of copies and must not treat the second as an error. A receiver
that gets one ends the session as it would on any other teardown — the same state
transition, the same gauges, the same resource release — and must not answer it with
a close of its own, or two departing sessions would each wait on the other's last
word.

**Draining: a receiver must not end the session on the copy it first sees.** This is
the receiver obligation the frame cannot work without, and it exists because of what
the frame is not. A `CLOSE` is not `RELIABLE`, carries no `stream_offset`, is never
acknowledged and is never retransmitted, so nothing re-sends application data it
overtakes. On a datagram transport it overtakes data routinely: one position of
displacement is enough, and ECMP/LAG rehash, a link-layer retry and the brief
two-live-paths window after a migration all produce that much as a matter of course.
A receiver that tore down on arrival would therefore destroy bytes whose sender's
`send()` had already returned success, with no error at either end — the sender's
close returns normally and the receiver's error is indistinguishable from an ordinary
teardown. Note that the sender cannot fix this from its side: emitting the close last
orders the *transmissions*, and transmission order is not arrival order. This is the
same hazard § 4.3's step-12 rule addresses at stream scope, where a `FIN` half-closes
only once the in-order cursor has passed its own offset; `CLOSE` has no offset to
compare, so the rule takes the form of a timer instead.

On receiving a `CLOSE`, a receiver **records** it and **keeps processing inbound
frames for a bounded draining window** before tearing down and releasing the
session's resources. Within the window it delivers what arrives, exactly as before.
It **must not** accept new application writes from its local side, and **must not**
treat the peer's close as licence to send data of its own — the peer has stated it is
leaving, so anything sent has nowhere to arrive.

The window is derived from the connection's own round-trip measurement — a small
multiple of it, this implementation using three, which is the shape of QUIC's
draining period — and it **must** be bounded absolutely. Both bounds are load-bearing
and for opposite reasons. A floor, because a sub-millisecond measurement on a
loopback or datacentre path would drain nothing, the displacement being produced by
the path's queues rather than by its length; this implementation floors at 200 ms. A
ceiling, because the round-trip figure is one the peer can inflate by delaying its
own acknowledgements, and without a ceiling the duration of a *local* commitment
would be a number a remote party writes; this implementation caps at 600 ms. The
deadline is taken once, when the first copy is seen, and is never extended by
anything that arrives afterwards — otherwise a peer could hold the session open by
continuing to talk. In the ordinary case that is 300 ms of held slot, against the
timer-driven alternative of § 12.4, which is over two minutes.

**If it is lost entirely**, nothing breaks and nothing is retried: the receiver falls
back to concluding the same thing from silence, on the liveness timer of § 12.4,
exactly as it did before v8. That is the whole compatibility story of the frame — it
improves the common case and changes no worst case — and it is why an implementation
that chooses never to send one is still conformant, while one that fails to dispatch
a received one is not.

A sender emits it **after** pushing out everything it owes the peer, and never
before. That is worth doing and is not sufficient: on a datagram transport the close
and the trailing data are separate datagrams with no ordering between them, so
sending them in turn orders the transmissions and nothing more — what covers the rest
is the receiver's draining window above, and a specification that asked only this of
the sender would be asking for a guarantee the sender cannot give. Note also that
"pushing out" is not "delivering": nothing acknowledges the flush either, so an
application that needs its last bytes delivered establishes that at its own level and
closes afterwards. Emitted only from an established session; one that never got past
the handshake has no keys to seal with and no peer state to release.

Why it exists is § 12.4's blind spot. On a byte pipe a departing peer's transport
drop makes the other side's read fail and its session ends within a second; a
datagram socket has no equivalent — an unconnected server socket surfaces no ICMP —
so a departure was indistinguishable from silence and the slot survived until the
liveness timer declared it dead, over two minutes later, with keep-alives fired at a
closed port throughout.

Source: `core/src/transport/types.rs` (`ControlSubtype`), `core/src/api/session.rs`.

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

`epoch`, `stream_id`, and `path_id` are **not** in the nonce (P4.0); they
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
concern (the `2^32` rekey soft-limit fires long first).

**Mid-session rekey (Invariant 5).** `Session::rekey()`:

1. `next_secret = HKDF-Expand(current_traffic_secret, "phantom-rekey-v1", 32)`.
2. Build a fresh `CryptoState` from `next_secret` with the same `is_server`
   orientation as the original handshake.
3. ArcSwap-install the new state — concurrent encrypt/decrypt see either the
   old or new state atomically.
4. Zero the previous traffic secret in place before overwriting.
5. Increment `epoch` (u8). It **never wraps to 0**, but the two directions
   reach that ceiling differently, and both behaviours are wire-visible:
   a locally-initiated `rekey()` at `epoch == u8::MAX` **returns an error and
   rotates nothing** (the caller is expected to reconnect — see the fail-closed
   rule below), while the receive-side catch-up advances with a *saturating*
   add, so following a peer can never roll the counter over either.

Every epoch transition is serialised by a per-session rekey mutex, so the
concurrent send-loop and receive-task of the data pump can never let the
installed key depth diverge from the `epoch` counter.

**Automatic rekey.** The data pump triggers a rekey on the send path, *before
stamping a packet's header*, once a direction's AEAD invocation count crosses
`REKEY_SOFT_LIMIT` (default `2^32`; T5.3 lowered it from `2^47` — the
AES-256-GCM IND-CPA advantage at `2^32` records is ~`2^-33`, inside the CFRG /
QUIC confidentiality margins), far below the hard
`AEAD_MAX_INVOCATIONS = 2^48` ceiling. The old per-stream `SEQ_REKEY_WATERMARK`
forced-rekey threshold (the C1 crutch) is **gone**: with a per-direction `u64`
packet number there is no sequence to wrap, so the invocation soft-limit is the
only rekey driver.

If a rekey is required but the `epoch` has saturated (`u8::MAX`), the send **fails
closed** — the packet is not stamped, the send is reported as failed, and the
session is expected to reconnect rather than continue. Both data (`send_app_data`)
and `WINDOW_UPDATE` (`send_window_update`) sends obey this discipline.

Wire signalling: the sender emits a packet whose header carries the new `epoch`
and the `PacketFlags::REKEY` flag — and **re-advertises `REKEY` on every packet
it sends at the new epoch** until an authenticated inbound packet arrives at that
epoch (T5.5(b)), so a lost rotation-trigger packet cannot strand the peer behind
the catch-up gate. Correspondingly the receiver **rejects a forward-epoch packet
that does not carry `REKEY`** cheaply, before taking the rekey lock or doing any
HKDF work — an honest sender always sets it, so an unflagged forward epoch is
forged or corrupt, and rejecting it early bounds the key-derivation work a
spoofed packet can force. The receiver follows via
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
`handshake.rs`) supports optimistic start. `process_client_hello`
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

**Bounded decode (M-7) — an admission rule, not just a hardening detail.** The
`ClientHello` is the one message an unauthenticated stranger can send, so both
listeners walk its borsh layout *before* decoding it, reading only the `Vec<u8>`
length prefixes and the `Option` tags and rejecting the frame without allocating
if any variable field is over its true maximum
(`client_hello_lengths_within_bounds`, called from `api/listener.rs` and
`api/udp_listener.rs`). A second implementation has to stay inside the same
bounds or its hello is dropped before anything reads a field:

| Field | Maximum |
| --- | --- |
| `client_key_package.ml_kem_pk` | 1184 B (FIPS 203, exact) |
| `client_verify_key.ml_dsa_pk` | 1952 B (FIPS 204, exact) |
| `protocol_variant` | 64 B |
| `early_data` | `EARLY_DATA_MAX_LEN` = 16 KiB (§ 6.6) |

Trailing bytes are rejected too: the walk must land exactly on the end of the
buffer, and `borsh::from_slice` would reject a surplus anyway. There is therefore
**no forward-compatible trailer** in any handshake message — borsh messages are
fixed-shape, and an unrecognised field cannot be appended for an older peer to
skip. Extending a handshake message means bumping `PROTOCOL_VERSION` (§ 1).

Source: `core/src/transport/handshake.rs`.

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

Source: `core/src/transport/handshake.rs`.

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

Source: `core/src/transport/handshake.rs`. The hybrid signature is
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
(`handshake.rs`). Clients obtain the key via
`PhantomListener::verifying_key_bytes()` + `HybridVerifyingKey::from_bytes`.

### 6.6 0-RTT early-data (best-effort, one-shot)

0-RTT early-data is folded directly into `ClientHello.early_data` — no separate
handshake version. A resuming client seals application bytes so the first
payload reaches the server without a full handshake round trip.

**Keying.** Both peers derive identical AEAD material from the prior session's
`resumption_secret` and *this* connect's `client_nonce`
(`core/src/crypto/kdf.rs`):

```
PRK              = HKDF-Extract(salt = client_nonce, ikm = resumption_secret)
early_data_key   = HKDF-Expand(PRK, "phantom-early-data-key-v3",   32)   // AES-256-GCM key
early_data_nonce = HKDF-Expand(PRK, "phantom-early-data-nonce-v3", 12)
```

HKDF-SHA256 (not BLAKE3) keeps the path FIPS-eligible. The blob is sealed with
**AES-256-GCM** (fixed — the cipher suite is not yet negotiated at ClientHello
time). AAD = `resume_session_id || client_nonce` (64 bytes;
`handshake.rs`). The `(key, nonce)` pair is single-use: the
key is bound to one `client_nonce`, which is one-shot because the server
consumes the resumption ticket on first sight.

**Size cap.** Early-data plaintext is capped at `EARLY_DATA_MAX_LEN = 16 KiB`
(`handshake.rs`). The client constructor refuses a larger payload; the
server checks `sealed.len() > EARLY_DATA_MAX_LEN + 16` **before** any crypto
work (`handshake.rs`) and drops the blob, continuing 1-RTT — this caps the
work an unauthenticated peer can force.

**One-shot anti-replay (Invariant 9).** The defence is the resumption ticket
itself: the server `peek()`s the ticket (no consume), verifies the
`ClientHello.resumption_binder` against it in constant time, then **eagerly
`remove()`s** it — `remove` returns `true` for exactly one of two racing
duplicates, so the consume is race-free — and re-inserts it unchanged
(`reinsert_with_expiry`) only if a later handshake step fails. A
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
> second time — the classic TLS-1.3 0-RTT-across-a-server-farm replay. Mitigations:
> (a) consistently route a given `resume_session_id` to the same node (sticky /
> hashed load-balancing); (b) install a distributed anti-replay store — the library
> ships the seam: implement `transport::handshake::ZeroRttAntiReplay` (a single
> `check_and_set(ticket_id) -> bool` first-use check against your shared store) and
> register it via `PhantomListener::set_zero_rtt_anti_replay` /
> `PhantomUdpListener::set_zero_rtt_anti_replay`, after which ticket consumption is
> one-shot **globally** (A2b); the backing store itself is yours to operate; or (c)
> accept the residual and keep early-data strictly idempotent. The forward
> secrecy and authentication of the resulting
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

**API surface.** Client (Rust):
```rust
PhantomSession::builder(addr)
    .pinned_key(expected_server_key)
    .resumption(resumption_hint, early_data)
    .transport(transport)
    .connect()
    .await?
```
Client (native FFI): `connect_pinned_with_resumption` / `connect_pinned_udp_with_resumption`.
The `resumption_hint` comes from a prior session's
`resumption_hint().await -> Option<ResumptionHint>` (each field 32 bytes).
Server: `PhantomListener::accept()` returns `Arc<AcceptOutcome>` (`api/listener.rs`):

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
tag (`core/src/transport/handshake.rs`):

| Build | `PROTOCOL_VARIANT` |
| --- | --- |
| Default (`cargo build`) | `b"phantom-default-1"` |
| FIPS (`cargo build --features fips`) | `b"phantom-fips-1"` |

It is (a) carried cleartext on every `ClientHello` and (b) the **leading
field** of the signed transcript (§ 6.5). The server rejects a mismatch with
`HandshakeError::ProtocolVariantMismatch` **before** any KEM / signature work
(`handshake.rs`); an MITM that rewrites the cleartext field to match
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

Source: `core/src/transport/handshake.rs`.

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
`solution: u64` such that the unkeyed BLAKE3 hash of `(challenge.nonce ||
solution.to_le_bytes())` has at least `difficulty` leading zero bits. The client
IP is **not** an input to the solution hash — it is bound into the 32-byte
`challenge.nonce`, which is itself a self-authenticating stateless cookie
`[timestamp: u64 LE (8 B) | keyed-BLAKE3(secret; timestamp ‖ client_ip)[0..24]]`;
the server re-MACs it on verify and rejects a challenge older than 120 s (or one
whose embedded timestamp is in the future). The verification is stateless: the
server takes the nonce back from the client's `PoWSolution`, re-derives the
keying from the rotating per-hour secret — accepting the current or previous
hour's derivation, so a challenge issued either side of an hour boundary still
validates — and recomputes the MAC. It keys the challenge on the same
`ip.to_string()` bytes as the cookie (§ 6.8). The challenge-integrity MAC is
compared in constant time (`subtle::ConstantTimeEq`, CRYPTO-2/HS-04). Note that
the difficulty checked at verify time is the server's **current** demand, not
whatever it advertised when the challenge was issued: under a rising load tier a
solution minted at the old difficulty is rejected and the client is simply
retried, which is why the retry loop has to be tolerated rather than assumed to
run once.

**Client difficulty cap (H3).** `HelloRetryRequest` is unauthenticated, so the
client rejects any `difficulty > MAX_CLIENT_POW_DIFFICULTY = 24` (strictly above
the server's max legitimate tier) **before** solving, and `solve` is bounded to
`MAX_SOLVE_ITERATIONS = 2^32` — an injected `difficulty = 255` yields a handshake
error instead of pinning a CPU core forever.

Adaptive difficulty (`HandshakeServer::adaptive_difficulty`,
`handshake.rs`):

| Handshakes/min | Difficulty | Expected hash evals |
| --- | --- | --- |
| 0–99 | 0 | (no PoW required) |
| 100–499 | 4 | ~16 |
| 500–1999 | 8 | ~256 |
| 2000–9999 | 12 | ~4096 |
| 10000+ | 16 | ~65536 |

That table is a floor, not the whole demand. The difficulty actually asked of a
client is `max(adaptive_difficulty(), reputation_difficulty(ip, has_ticket))`
(`api/listener.rs`, over `transport/reputation.rs`), so a source with recent
handshake violations is singled out — up to `MAX_DIFFICULTY = 20` — even while
the global load tier sits at 0. A verified resumption ticket zeroes the per-IP
term only, never the load tier (M-5: a junk resume id must not buy an abusive
source its reputation back). A client implementation should therefore solve
whatever it is handed, up to its own ceiling of 24, rather than assume the 16 in
this table is the most it can be asked for.

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

- `PacketHeader.path_id`: the sender-owned connection-migration path label —
  each peer bumps it on its own send direction (`migrate()` for the client,
  `migrate_server()` for the server; Phase 4, § 12); `epoch`: the rekey
  generation (Phase 1.5). Both default to 0.
  Since P4.0 (§ 5) `path_id` no longer feeds the AEAD nonce — it is AAD-only — so a
  `path_id` becomes safely reusable once its path is retired. Two of its 256
  values are reserved and are never handed out by an allocation:

  | `path_id` | Meaning |
  | --- | --- |
  | `0` | The handshake path. Permanently *validated* — never challenged, never allocated to a migration. A passive NAT rebind keeps it (§ 12.1) |
  | `1 … 254` | Migration labels, allocated in ascending order and wrapping `254 → 1` so `0` is skipped forever |
  | `255` | `REBIND_VALIDATION_PATH_ID` — the slot the passive-rebind challenge validates on (M-3, § 12.1), kept out of the migration cycle so an active-migration echo and a rebind echo can never resolve each other's registry entry |

  Reuse after a wrap is safe for the same reason retirement is: `path_id` is
  authenticated in the AAD but absent from the nonce (§ 5).
- `PhantomPacket.extensions`: TLV headroom that is **no longer on the wire**
  (v6 — § 4.1). It survives as a struct field bound into the AEAD AAD as an
  empty slice, so the headroom is authenticated but not transmitted; reaching it
  again means spending a reserved flag plus an encrypted TLV inside the (padded)
  plaintext, which is a deliberate revision, not a free extension point.
- `ServerHello.server_nonce`: a 32-byte server-contributed, transcript-bound
  value (T4.3, replacing the old discarded ~1184 B ephemeral `server_key_package`).
  A future second-KEM ring could repurpose this slot for real key material.
- **`ControlSubtype` `0x00` and `0x02 … 0xFF`** (§ 4.11): 255 unassigned values in
  the AEAD plaintext of an `ENCRYPTED | CONTROL` frame. This is now the *intended*
  place for a new in-session signal, and it is where a reader should look first.
- `PacketFlags 0x8000`: the sole remaining reserved bit (`0x1000` = `KEEPALIVE`
  § 4.3 / § 12.4, `0x2000` = `PADDED`, `0x4000` = `COVER` § 4.8 and `0x0080` =
  `CONTROL` § 4.11 are assigned). It is still free **because** v8 spent a subtype
  byte instead of it.

The last two entries are the same decision seen from both ends, and the ordering
between them is the forward-compatibility policy of this protocol, not a
preference. The flags word is a 16-entry namespace of which one entry remains; the
subtype registry is a 255-entry namespace that costs the same on the wire, because
a control frame's plaintext is padded to a bucket either way and one byte inside it
is free. Three in-session control frames — `KEEPALIVE`, `PADDED`/`COVER` shaping
and `WINDOW_UPDATE` — were added in the two revisions before v8; had the fourth
taken `0x8000`, the fifth would have had nowhere to go and would have forced a
header change. So: **a new in-session signal takes a subtype, not a flag.** A flag
is correct only for something the receiver must act on *before* it opens the AEAD,
or something that must combine freely with an existing branch — neither of which
describes a signal, and both of which are exactly what a header bit is scarce for.

None of this is a licence for unilateral use. A sender must not emit an unassigned
subtype or set an unassigned flag on a live session: an unknown subtype is dropped
(§ 4.11 rule 3) and an unknown flag is ignored (§ 4.3), so in both cases the peer
does nothing and the sender learns nothing. Both namespaces are spent by a
`WIRE_VERSION` / `PROTOCOL_VERSION` increment (§ 1) as a deliberate, code-gated
bump — which is what v8 was.

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
  4-byte big-endian `u32` length capped per phase: `HANDSHAKE_FRAME_CAP = 64 KiB`
  before the session establishes, `STEADY_STATE_FRAME_CAP = 4 MiB` after
  (`core/src/api/tcp_transport.rs`).
- `SessionId`, `HybridKeyPackage`, `HybridVerifyingKey`, `HybridCiphertext`,
  `HybridSignature` derive `BorshSerialize + BorshDeserialize`; their on-wire
  bytes are the concatenation of their internal fields in declaration order.
> **Note (Phase 0 → mimicry feature):** the original FakeTLS leg was removed in
> Phase 0. Active TLS mimicry returned as the optional **`mimicry` feature** — a
> `MimicTlsLeg` (`bind_mimic` / `connect_pinned_mimic`) that wraps the Phantom
> session in a *synthetic* TLS 1.3 flow (see below). It is **framing-only with no
> outer AEAD**, so it derives no outer keys — the old `"phantom-faketls-*-v1"`
> labels are gone from § 3 and from every build.

### 9.1 TLS-mimicry leg (`mimicry` feature)

Unlike the inner Phantom wire (a bare UDP `PhantomPacket`), the `MimicTlsLeg` is an
**outer, leg-local framing over TCP** — it does **not** change `WIRE_VERSION` or the
inner packet format. A connection looks like ordinary HTTPS:

1. **Synthetic TLS 1.3 handshake (theater).** Client sends a Chrome-shaped
   `ClientHello` (`0x16`, legacy_record_version `0x0301`; realistic JA3/JA4, GREASE,
   per-connection-random `random` / `session_id` / `key_share` / extension order).
   Server answers a `ServerHello` (`0x16` `0x0303`) **synthesized from the parsed
   ClientHello** (echoes an offered cipher + an offered `key_share` group of the
   correct point length, copies `legacy_session_id`, selects TLS 1.3 via
   `supported_versions`), then `ChangeCipherSpec` (`14 03 03 00 01 01`), an opaque
   "encrypted" server flight (`0x17`, random ~1.5–4 KB), and a NewSessionTicket-shaped
   `0x17` record. Client replies `ChangeCipherSpec` + an opaque Finished (`0x17`).
   **No real ECDHE, no certificate** — the bytes are theater.
2. **Data phase.** Each Phantom message is framed `msg_len(4 BE) ‖ message` into a
   byte-stream, chunked into TLS ApplicationData records (`0x17 0x0303 len fragment`,
   `len ≤ 2^14`), each fragment `chunk_len(2 BE) ‖ chunk ‖ pad`. Records decouple from
   message boundaries (a message may span records; a record may pad). The inner
   Phantom ciphertext is already AEAD-sealed and indistinguishable from random — what
   a TLS ApplicationData payload looks like — so there is **no second/outer AEAD**.

The outer TLS is **anti-DPI obfuscation only** and is **detectable by active
probing** (a probe that completes a real TLS handshake / validates a certificate
fails in one RTT). See `docs/security/threat-model.md` §6.1 for the honest residuals
(active-probing, template-drift, SNI-coherence, flow-shape) and SAFE/UNSAFE
deployment guidance.

---

## 10. Compliance with documented invariants

The invariants from `SECURITY.md` and `docs/security/threat-model.md` map onto
this spec as follows:

| Invariant | Spec section |
| --- | --- |
| 1 — Server identity pinning | § 6.1 / § 6.3 / § 6.5 |
| 2 — Post-handshake ENCRYPTED flag | § 4.3 / § 4.11 / § 5 |
| 3 — Anti-DPI obfuscation carries no confidentiality of its own (framing-only `mimicry` leg) | § 9.1 |
| 4 — Replay rejection after AEAD verify | § 5 / § 4.11 |
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
grammar is real. It also carries the two rules that have no fixture of their own,
because they govern AEAD plaintexts rather than outer containers: the
`WINDOW_UPDATE` plaintext codec with its monotone-maximum rule (§ 4.5), and the
`CONTROL` subtype registry with its dispatch (§ 4.11) — including the assertions
that an unassigned byte drops the frame and that a plaintext naming no subtype is
refused rather than read as a default.

| Fixture | Codec | Type |
| --- | --- | --- |
| `packet_header.bin` | hand-rolled big-endian | `PacketHeader` (§ 4.2) |
| `phantom_packet_data.bin` / `_ack.bin` / `_extensions.bin` | hand-rolled big-endian | `PhantomPacket` (§ 4.1) |
| `client_hello_minimal.bin` / `client_hello_full.bin` | borsh | `ClientHello` (§ 6.2) |
| `server_hello.bin` / `server_hello_rejected.bin` | borsh | `ServerHello` (§ 6.3) |
| `hello_retry_request_cookie.bin` / `_pow.bin` | borsh | `HelloRetryRequest` (§ 6.4) |
| `hybrid_key_package.bin` / `hybrid_ciphertext.bin` | borsh | KEM material (§ 6.2/6.3) |
| `hybrid_verifying_key.bin` / `hybrid_signature.bin` | borsh | signature material (§ 6.3) |
| `pow_challenge.bin` / `pow_solution.bin` | borsh | DoS-gate fields (§ 6.9) |
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
wire — there is no migration-specific packet type and no wire bump beyond P4.0 (§ 5);
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
2. **Server detect.** The connection-ID demux already routes a known
   `ConnId` (§ 4.7 — the inner `session_id` has been off-wire since ε) arriving
   from a new source 5-tuple into the same session, and the
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

**Idle keep-alive PINGs (download-only liveness).** The in-flight
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

**Departure is announced, not only inferred (WIRE v8).** Everything above infers the
peer's state from *silence*, which is the only evidence a datagram socket offers and
is necessarily slow: a keep-alive interval to reach `Migrating`, then a migration-idle
timeout to reach `Dead`. That is correct for a peer that vanished, and needlessly
expensive for a peer that simply left — and it could not tell the two apart, because
on PhantomUDP they look identical. There is no socket-level end-of-stream: on the
byte-pipe legs a departing peer's transport drop makes the other side's read fail
within the second, while an unconnected UDP server socket surfaces no ICMP at all, so
a departure and a quiet moment are the same observation. For as long as the timers
ran, the session slot stayed occupied and keep-alives were fired at a closed port,
holding a NAT binding open for a conversation that had ended.

So a session that is ending now says so first: a `CONTROL` frame carrying
`ControlSubtype::CLOSE` (§ 4.11), emitted after the final flush. It is
best-effort — unacknowledged, never retransmitted — and it **replaces nothing**.
Every timer above still runs and still reaches the same verdict on its own schedule;
the frame only lets the common case be decided in one draining window (§ 4.11,
typically 300 ms) instead of two minutes. A receiver that never gets one behaves
exactly as it did before v8, which is why an implementation is free to send none and
not free to ignore one — and, having got one, not free to act on it immediately
either.

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

---

## 13. Last verified against the code

Every constant, byte offset, field order and decode rule above was re-derived
from the source on **2026-08-15**, against commit `41183f49`. A reader picking
this up later should treat that pair as the document's expiry stamp: anything
that has moved in `core/src/transport/`,
`core/src/crypto/` or `core/src/api/session.rs` since then has not been
re-checked here.

Two changes have landed since that pass and are reflected above. `WIRE_VERSION 6 → 7`
and `PROTOCOL_VERSION 3 → 4` replaced the `WINDOW_UPDATE` relative credit with a
cumulative limit (§ 1, § 4.3, § 4.5). Then `WIRE_VERSION 7 → 8` and
`PROTOCOL_VERSION 4 → 5` gave the `CONTROL` flag a one-byte subtype in its AEAD
plaintext and assigned the first of them, the session-close announcement (§ 1, § 4.3,
§ 4.11, § 7, § 12.4). Neither moved a header byte or a handshake field, and both
moved the same seven frozen fixtures — the four packet vectors by their version byte,
the two `ClientHello` vectors by theirs, and `transcript_hash.bin` because the hello
it covers changed. That is the signature of a plaintext-format change, and it is
precisely why both versions had to move each time: nothing in the header would
otherwise have told a peer the rules for reading a payload had changed.

The same pass closed a set of silences, which are harder to notice than
contradictions because nothing in the document points at them: the `stream_id`
allocation rule (§ 4.4), the receiver's flag-dispatch order and what an
unrecognised flag means (§ 4.3), when an acknowledgement is required and what is
never acknowledged (§ 4.5), the `WINDOW_UPDATE` plaintext with the initial and
maximum window that make its limit meaningful (§ 4.5), the reserved `path_id`
values (§ 7), the bounded `ClientHello` decode a stranger's hello must satisfy
and the absence of any forward-compatible trailer (§ 6.2), and the per-source
term that puts the real PoW demand above the load-tier table (§ 6.9).

The sync covered, in order: `WIRE_VERSION` / `PROTOCOL_VERSION` / `PROTOCOL_VARIANT`;
the 15-byte `PacketHeader` grammar and `HP_PROTECTED_OFFSET`; the 47-byte AAD
image and the off-wire `session_id`; the nonce construction and which header
fields it excludes; the full `PacketFlags` set; the SACK / reliable-frame /
`COALESCED` plaintext codecs including the over-length SACK reduction; the
padding trailer and its bucket cap; the PhantomUDP envelope and its
fragmentation bounds; the derived application chunk size; the four handshake
messages, their borsh field order and the transcript's leading and trailing
fields; the cookie and PoW constructions; and the frozen vector inventory.

---

## 14. What this document does not specify

Recorded rather than left silent, because a specification's failure mode is the
thing it never mentions. Nothing below is a contradiction anyone could catch by
reading; each is something a second implementation would discover only by
building against a real peer.

- **Loss recovery, congestion control and pacing.** The `Sack` encoding (§ 4.5)
  is the entire contract. The retransmission timer, the packet- and
  time-threshold loss rules, the initial and maximum congestion window, the
  bandwidth estimator and the pacer are all sender-local: two peers with
  completely different ones interoperate byte-for-byte. This omission is
  deliberate — nothing about them is observable to the receiver except as
  timing — but an implementer should not go looking here for them.
- **Every timer except the keep-alive interval.** § 12.4 gives the keep-alive
  default (15 s) and states the liveness rules qualitatively (`N × PTO` of
  inbound silence while reliable data is outstanding; a migration-idle timeout
  to `Dead`). The numbers behind `N`, that idle timeout, and the client's
  handshake deadline are configuration, and a peer cannot work out from this
  document how long it may stay silent before the other side declares its path
  down. Anything built to sit idle should send keep-alives rather than infer a
  budget.
- **A ceiling on stream ids.** § 4.4 fixes the parity rule and the two reserved
  ids, but not a maximum, and this implementation does not enforce one: its
  allocator counts in 32 bits while the header field is 16 (§ 4.2), so a session
  that opens more than about 32 767 streams wraps its ids back onto low values —
  the reserved `0` and `1` included. Far outside any plausible use (the
  concurrent cap is 256), but it is a truncation, not a refusal, so nothing
  reports it.
- **How to interoperate with a `fips` build.** § 6.7 explains why a fips peer
  and a default peer cannot talk, and § 11 notes the frozen vectors compile to
  nothing under that feature. What a fips-to-fips conformance set would contain
  is therefore unspecified — its 65-byte classical key changes the byte lengths
  this document quotes throughout.
