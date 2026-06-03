# Phantom Core Wire Protocol

Specification of the wire format, handshake state machine, and key-derivation
constructions used by `phantom_core` 0.x. There is exactly **one** wire
protocol: a single packet shape, a single handshake, and a single pinned
version byte. The protocol is **not negotiated** — pre-1.0 there are no
deployed peers, so there is no version handshake, no fallback, and no
migration path. The one surviving version byte is a tamper-check anchor and a
hook for a future, deliberate bump.

Audit-friendly format: every field has its Rust source-of-truth pinned with
`file:line`. The canonical wire bytes are the byte-frozen vectors in
`core/tests/wire_vectors/` (§ 11) — the Rust types produce them and this doc
narrates the grammar; all three are checked against each other in CI.

---

## 1. Versioning policy

Two pinned constants identify the protocol. Neither is negotiated; a decoder
that sees any other value drops the frame (packets) or rejects the handshake
(`ClientHello`).

| Constant | Value | Source | Where it lives on the wire |
| --- | --- | --- | --- |
| `WIRE_VERSION` | `2` | `core/src/transport/types.rs` | `PacketHeader.version` byte (first byte of the 45-byte header — § 4.2) |
| `PROTOCOL_VERSION` | `2` | `core/src/transport/handshake.rs:55` | `ClientHello.version`, transcript-bound |

`WIRE_VERSION` is `2` (incremented when the packet codec moved from `alkahest`
to the explicit big-endian layout in § 4.2); `PROTOCOL_VERSION` is `2` (bumped
`1 → 2` when the signed transcript began covering the 0-RTT verdict
`early_data_accepted` (H2) and `ClientHello` gained the `resumption_binder`
proof-of-possession field (HS-03); a v1 ↔ v2 handshake cannot interoperate
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
| 0 | `marker` | 4 | `= b"PRJ1"` (`SERVER_REJECT_MARKER`); lets the client tell a reject from a `ServerHello` / `HelloRetryRequest` on its trial-deserialization path |
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
| Post-quantum signature | ML-DSA-65 (FIPS 204) | ML-DSA-65 (FIPS 204) | `ml-dsa = =0.1.0-rc.11` (RustCrypto pure-Rust) |
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
    pub header: PacketHeader,   // 45 bytes (§ 4.2)
    pub payload: Vec<u8>,       // AEAD ciphertext (+16-byte tag) when ENCRYPTED;
                                // raw bytes for control/ACK; coalesced bundle when COALESCED
    pub extensions: Vec<u8>,    // TLV headroom; empty today, ignored if non-empty
}
```

Source: `core/src/transport/types.rs`. There is no enum wrapper — the recv path
deserializes a bare `PhantomPacket` directly (`PhantomPacket::from_wire`) and
**drops** any frame whose `header.version != WIRE_VERSION`
(`api/session.rs:679-687`). An unparseable frame is dropped, never panicked on.

The packet is serialised by `PhantomPacket::to_wire` as an explicit,
length-prefixed image — no serialization library:

```text
header        45 bytes (§ 4.2)
payload_len   u32 big-endian
payload       payload_len bytes
ext_len       u32 big-endian
extensions    ext_len bytes
```

`from_wire` is bounds-checked (and overflow-safe on 32-bit targets), so a hostile
length prefix yields a drop, never an out-of-bounds read. Any bytes after
`extensions` are ignored (forward-compatibility headroom).

`payload` is the AEAD ciphertext when `PacketFlags::ENCRYPTED` is set,
otherwise raw bytes (control / ACK / path-validation). The AAD is the
serialised `PacketHeader` bytes (§ 5).

`extensions` is forward-compatibility headroom for future TLV amendments
(packet-number / SACK fields) without a layout change. It is empty in every
frame this build emits; a decoder ignores its contents.

> **Security note.** `extensions` is **not** covered by the AEAD AAD (the AAD is
> exactly the 45-byte `PacketHeader` image — § 5), so its bytes are
> attacker-malleable. A future TLV reader must therefore treat `extensions` as
> untrusted input and either authenticate it separately or restrict it to
> values that are safe when forged. For 1.0 it is reserved and never
> interpreted, which is why no reader exists yet.

### 4.2 `PacketHeader` (45 bytes)

Serialised by `PacketHeader::to_wire` as an explicit, fixed **big-endian**
(network byte order) image — no serialization library, declaration order == wire
order, `version` first, byte arrays as-is:

```rust
#[repr(C)]
pub struct PacketHeader {
    pub version: u8,             // pinned WIRE_VERSION
    pub session_id: SessionId,   // [u8; 32]
    pub stream_id: StreamId,     // u16  (0 = control stream)
    pub sequence: SequenceNumber,// u32  (per-stream)
    pub flags: PacketFlags,      // u16  (§ 4.3)
    pub ack_delay: u16,          // microseconds before ACK was sent (0 if N/A)
    pub epoch: u8,               // rekey generation (0 at establishment)
    pub path_id: u8,             // multi-path leg id (0 = default)
}
```

Source: `core/src/transport/types.rs`. `PacketHeader::SIZE = 45`, pinned by
`core/tests/check_wire.rs`, `types.rs::packet_header_serializes_to_45_bytes`, and
the byte-frozen vector `core/tests/wire_vectors/packet_header.bin` (§ 11).

Wire byte layout (the load-bearing contract — this image is the AEAD AAD, so any
layout drift silently breaks interop):

| Offset | Field | Width | Encoding |
| --- | --- | --- | --- |
| 0 | `version` | 1 | u8, `= WIRE_VERSION` |
| 1 | `session_id` | 32 | 32 bytes, as-is |
| 33 | `stream_id` | 2 | u16 big-endian |
| 35 | `sequence` | 4 | u32 big-endian |
| 39 | `flags` | 2 | u16 big-endian (§ 4.3) |
| 41 | `ack_delay` | 2 | u16 big-endian |
| 43 | `epoch` | 1 | u8 |
| 44 | `path_id` | 1 | u8 |
| **total** | | **45** | |

The pinned `version` byte leads the header. The full 45-byte image is the AEAD
AAD, so flipping *any* byte — `version` included — fails decryption (§ 5); the
recv path additionally drops a frame whose `version != WIRE_VERSION`. The same
big-endian convention is used for the `stream_id` / `sequence` bytes that feed
the AEAD nonce (§ 5). An independent (non-Rust) decoder + encoder that reproduces
this layout exactly is `tests/wire_vectors_decode.py`.

### 4.3 `PacketFlags` (u16 bitfield)

Source: `core/src/transport/types.rs:74-107`.

| Bit | Constant | Meaning |
| --- | --- | --- |
| `0x0001` | `RELIABLE` | Requires ACK; retransmitted on timeout |
| `0x0002` | `ACK` | This packet is an authenticated ACK (`ENCRYPTED`; AEAD payload = acked seq) |
| `0x0004` | `FIN` | Stream finished |
| `0x0008` | `UNRELIABLE` | Fire-and-forget |
| `0x0010` | `PRIORITY` | Voice/video frame priority hint |
| `0x0020` | `ENCRYPTED` | Payload is AEAD ciphertext |
| `0x0040` | `COMPRESSED` | Payload is compressed (`AdaptiveCompressor`) |
| `0x0080` | `CONTROL` | Handshake / migration control message |
| `0x0100` | `REKEY` | Sender rekeyed; receiver trial-decrypts at `header.epoch` and commits the ratchet on AEAD success (§ 5) |
| `0x0200` | `PATH_VALIDATION` | Payload is a 32-byte challenge / response (multi-path) |
| `0x0400` | `COALESCED` | Payload bundles inner packets as `[count: u16][len1: u16][p1]…` |
| `0x0800` | `WINDOW_UPDATE` | Payload is a big-endian `u32` relative flow-control credit (per-stream; the receiver grants the sender an additional `u32` bytes that is added to the sender's send window, saturating at `MAX_SEND_WINDOW`) |
| `0x1000` … `0x8000` | _reserved_ | Future amendments |

`ENCRYPTED` is the post-handshake invariant flag — the API layer sets it on
every application-data packet, and the receive loop drops any non-empty
unencrypted application-data packet as a stripped-flag downgrade attempt
(Invariant 2; `api/session.rs`). ACK packets are **authenticated control frames**
(H1): they carry `ENCRYPTED | ACK`, their AEAD payload is the 4-byte big-endian
acked data sequence, and the receiver acts on them **only after AEAD verify** —
so a forged or plaintext ACK can neither retire a pending segment, restore a
flow-control permit, poison the BBR estimator, nor close a stream. Every inbound
frame is additionally bound to the negotiated `session_id` before any processing.
An ACK's own `header.sequence` is drawn from the acker's per-stream send counter
(shared with its data/`WINDOW_UPDATE` sends) so the AEAD nonce never collides, and
it obeys the §5 rekey discipline.

### 4.4 `SessionId`

`SessionId` (`[u8; 32]`, 32 bytes; `types.rs:21`) is the negotiated session
identifier, used as encryption salt and for migration across IP changes.
Server-side it is derived as `SHA256(b"phantom-session-id-v1" || shared_secret
|| client_nonce)` (`transport/handshake.rs:830-836`); the client adopts the
`session_id` echoed in the `ServerHello`.

---

## 5. AEAD construction

Per-direction keys (`send_key` / `recv_key`) and a 4-byte `nonce_prefix` are
derived once at session establishment from the hybrid shared secret (§ 3
labels). The per-packet AEAD nonce is **derived from the authenticated header
fields**, not from an internal counter — so a failed or tampered decrypt never
desyncs the receiver.

Nonce layout (12 bytes total; `transport/session.rs:560-568`):

```
nonce[0..4]  = nonce_prefix          (from CryptoState; fresh per rekey epoch)
nonce[4]     = header.epoch
nonce[5..7]  = header.stream_id      (big-endian)
nonce[7..11] = header.sequence       (big-endian)
nonce[11]    = header.path_id
```

The version byte is in the AAD (the serialised 45-byte `PacketHeader`) but
**not** in the nonce.

```
Sender:    plaintext, header  →  AEAD-encrypt(key  = send_key,
                                              nonce= prefix||epoch||sid_be||seq_be||path,
                                              aad  = serialize(header),   // 45 bytes
                                              plaintext)
                              →  ciphertext (with 16-byte tag)
Receiver:  ciphertext, header →  AEAD-decrypt(key  = recv_key,
                                              nonce= prefix||epoch||sid_be||seq_be||path,
                                              aad  = serialize(header),
                                              ciphertext)
                              →  plaintext  OR  a single opaque "decrypt failed"
```

Source: `Session::encrypt_packet` / `decrypt_packet`
(`transport/session.rs:577-627`).

**Uniqueness (Invariant 8).** `sequence` is a **per-stream `u32`** that wraps at
`2^32`; `epoch` distinguishes rekey generations; `path_id` distinguishes the same
logical packet across multi-path legs. Uniqueness of `(epoch, stream_id, sequence,
path_id)` under a given key therefore requires that **no single stream's `sequence`
wraps within one epoch** — otherwise a stream that emits `2^32` packets without a
rekey would repeat the nonce (catastrophic AES-GCM nonce reuse / the Forbidden
Attack). The send path enforces this directly: it forces a rekey (epoch bump +
fresh nonce prefix) once any stream's `sequence` advances past
`SEQ_REKEY_WATERMARK = 2^31` within the current epoch (see *Automatic rekey*
below), so a stream's per-epoch sequence span is bounded to `2^31` — half the
wrap distance. The `epoch` is `u8` and **saturates** (never wraps), so once the
budget of 255 rekeys is exhausted the session fails closed and reconnects rather
than reuse a `(epoch, sequence)` pair. The `2^48` direction-wide invocation
ceiling below is a secondary backstop, not the primary nonce-uniqueness
guarantee.

**Replay window runs after AEAD verify (Invariant 4).** After a successful
AEAD open, the receiver consults a per-stream sliding-window bitmap
(`core/src/security/replay_window.rs`, RFC 4303 §3.4.3, default 1024 bits)
keyed on `(stream_id, sequence)` only — `epoch` and `path_id` do not
contribute to replay identity. Duplicates and below-window sequences yield
`CoreError::ReplayDetected`. The window check is **never** moved before the
AEAD verify, so the receiver never keys off an unauthenticated sequence number.

**Nonce-exhaustion guard (Invariant 8).** `AEAD_MAX_INVOCATIONS = 1 << 48`
(`adaptive_crypto.rs:42`). The per-direction counter (kept for telemetry, not
for nonce derivation) reaching this ceiling yields `CryptoError::NonceExhausted`.
This is a defensive ceiling well below any practical AEAD safety boundary.

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

**Automatic rekey (C1).** The data pump triggers a rekey on the send path, *before
stamping a packet's header*, when **either** of two thresholds is crossed:

1. **Per-stream sequence watermark (primary nonce-uniqueness guarantee).** Once
   any stream's `sequence` advances `SEQ_REKEY_WATERMARK = 2^31` past where that
   stream entered the current epoch (`Session::stream_seq_needs_rekey`), a rekey
   is forced so the per-stream `u32` can never wrap within one epoch. The
   per-stream `(epoch, base_sequence)` checkpoint is rebased lazily on the first
   send after an epoch change. This is what closes C1: a single high-throughput
   stream (which advances the *direction-wide* counter only ~`2^32`, far below
   threshold 2) would otherwise wrap its sequence and reuse a nonce.
2. **Direction-wide invocation watermark (secondary backstop).** Once a
   direction's AEAD invocation count crosses `REKEY_SOFT_LIMIT` (default
   `2^48 / 2`), well below the hard `AEAD_MAX_INVOCATIONS = 2^48` ceiling.

If a rekey is required but the `epoch` has saturated (`u8::MAX`), the send **fails
closed** — the packet is not stamped, the send is reported as failed, and the
session is expected to reconnect rather than reuse a nonce. Both data
(`send_app_data`) and `WINDOW_UPDATE` (`send_window_update`) packets, which share
the per-stream sequence space, obey this discipline.

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
wrong key, wrong AAD, and wrong sequence all manifest identically so a network
attacker learns nothing from the shape of the failure (§ 8).

---

## 6. Handshake

The handshake messages are bare borsh structs — no envelope, no per-message
version discriminant. The client distinguishes the server's reply purely by
trial-deserialisation: a `ServerHello` is thousands of bytes (it carries KEM
ciphertext + hybrid signature + verifying key); a `HelloRetryRequest` is tiny; a
`ServerReject` (§6.10) is a fixed 6 bytes led by the `b"PRJ1"` marker. The sizes
and the marker make the three unambiguous.

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
    pub server_key_package:   HybridKeyPackage,  // ephemeral; bound into transcript for freshness
    pub ciphertext:           HybridCiphertext,  // KEM encapsulation
    pub server_verify_key:    HybridVerifyingKey,// pinned by client (Invariant 1)
    pub signature:            HybridSignature,   // over transcript hash
    pub session_id:           [u8; 32],
    pub early_data_accepted:  bool,              // 0-RTT verdict (§6.6)
}
```

Source: `core/src/transport/handshake.rs:137-155`. `server_key_package` is an
ephemeral hybrid KEM public bound into the transcript hash for freshness; the
corresponding secret is discarded (no second KEM round trip today).

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
    protocol_variant:   &'a [u8],            // leading field — binds the build variant
    client_hello:       &'a ClientHello,     // whole hello, early_data included
    server_key_package: &'a HybridKeyPackage,
    ciphertext:         &'a HybridCiphertext,
    server_verify_key:  &'a HybridVerifyingKey,
    session_id:         &'a [u8; 32],
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

The client identifies it by the marker on its trial-deserialisation path and
surfaces a hard error naming both versions. It deliberately does **not**
auto-downgrade to `supported_version`: the version is bound into the signed
transcript (§6.5, Invariant 7), so honouring an attacker-injected reject would
be a downgrade oracle. The frame is purely diagnostic. Because it is an
*additive* message — never sent on the success path and shaped unlike the other
three messages — it leaves the frozen wire vectors (§11) untouched.

---

## 7. Reserved / forward-compatibility surface

- `PacketHeader.path_id` / `epoch`: active for multi-path (Phase 4.2) and rekey
  (Phase 1.5) respectively; both default to 0 for a single-leg, single-epoch
  session.
- `PhantomPacket.extensions`: TLV headroom, empty today. A decoder ignores it;
  future amendments add fields here without a layout change.
- `ServerHello.server_key_package`: ephemeral hybrid KEM public bound into the
  transcript for freshness; the secret half is discarded (no second KEM round
  trip yet).
- `PacketFlags 0x1000 … 0x8000`: reserved bits.

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
sequence" from "wrong AAD" — all manifest as a single "decrypt failed" so a
network attacker cannot learn anything from the shape of the failure.

---

## 9. Side notes

- The serialised `PacketHeader` is exactly 45 bytes and is used verbatim as the
  AEAD AAD. Any layout drift is a wire-incompatible regression.
- The nonce's `stream_id` / `sequence` fields are big-endian (§ 5); this is
  pinned independently of the header serialisation.
- Every length-prefix on the wire (e.g. `TcpSessionTransport` framing) is a
  4-byte big-endian `u32` length capped at `MAX_FRAME_BYTES = 16 MiB`.
- `SessionId`, `HybridKeyPackage`, `HybridVerifyingKey`, `HybridCiphertext`,
  `HybridSignature` derive `BorshSerialize + BorshDeserialize`; their on-wire
  bytes are the concatenation of their internal fields in declaration order.
- FakeTLS outer obfuscation (Invariant 3) uses per-record counter nonces and
  direction-keyed AEAD derived from a public `(SNI || version)` seed via the
  `"phantom-faketls-*-v1"` labels (§ 3). It is anti-DPI obfuscation only — the
  inner Phantom session provides real auth/conf; the seed is intentionally
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
| 6 — Constant-time path-validation responses | § 4.3 (`PATH_VALIDATION`) |
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

The packets use a hand-rolled big-endian codec (no serialization dependency);
the handshake uses `borsh`, pinned to an exact `=` version in `core/Cargo.toml`
so a minor bump cannot silently shift those bytes. An **intentional** wire change
is landed by bumping `WIRE_VERSION` / `PROTOCOL_VERSION` and regenerating:

```sh
PHANTOM_REGEN_WIRE_VECTORS=1 cargo test --manifest-path core/Cargo.toml --lib
PHANTOM_REGEN_WIRE_VECTORS=1 cargo test --manifest-path core/Cargo.toml --test wire_vectors
```
