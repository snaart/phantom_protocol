# Phantom Core Wire Protocol — V1

Specification of the wire format, handshake state machine, and key-derivation
constructions used by `phantom_core` 0.x. Authoritative for V1; V2 (when it
lands) will introduce a sibling document and a bump of `VersionedPacket`.

Audit-friendly format: every field has its Rust source-of-truth pinned with
`file:line`. The Rust types are the canonical wire definition; this doc
narrates them.

---

## 1. Versioning policy

The wire format is identified by a single byte in the
[`VersionedPacket`](../../core/src/transport/types.rs) discriminant
(alkahest enum tag). Current state:

- **V1**: stable. Sections 4-9 of this document describe V1.
- **V2**: landed. Section 11 describes the V2 packet format. V2 carries
  the rekey signal (Phase 1.5 ✅), is ready for the multi-path `path_id`
  field (Phase 4.2 — primitive wired, scheduler integration pending),
  and reserves a flag for the PacketCoalescer wrapper (Phase 2.5).
- V3+: reserved. Bumps are accompanied by a new section here and a
  migration guide.

---

## 2. Cryptographic primitives

| Role | Primitive | Crate |
| --- | --- | --- |
| Classical KEM | X25519 | `x25519-dalek` |
| Post-quantum KEM | Kyber768 | `pqcrypto-kyber` |
| Classical signature | Ed25519 | `ed25519-dalek` |
| Post-quantum signature | Dilithium3 | `pqcrypto-dilithium` |
| AEAD | AES-256-GCM or ChaCha20-Poly1305 | `ring` |
| Hash | SHA-256 | `sha2` |
| Hash (KDF context) | blake3 keyed-derivation | `blake3` |
| KDF (HKDF) | HKDF-SHA-256 | `hkdf` |
| HMAC | HMAC-SHA-256 | `hmac` |

The AEAD choice is auto-selected by `HwCaps::detect()` (AES-NI present → AES;
otherwise ChaCha). Cipher is `CipherSuite::Aes256Gcm = 1` or
`CipherSuite::ChaCha20Poly1305 = 2`
(`core/src/crypto/adaptive_crypto.rs:20-27`).

---

## 3. KDF label inventory

Every place that derives keying material from a master uses a string label
to domain-separate. Adding or changing any of these is a wire-incompatible
change.

| Label | Construction | Purpose |
| --- | --- | --- |
| `"HybridKEM_X25519_Kyber768"` | `HKDF-SHA-256(ecc_secret \|\| kyber_secret)` | hybrid KEM shared secret (`core/src/crypto/hybrid_kem.rs:106-111`) |
| `b"phantom-transport-key"` | `HKDF-Expand(shared_secret)` | session AEAD master before per-direction derivation (`core/src/transport/session.rs:54-59`) |
| `b"phantom-resumption-secret-v1"` | `HKDF-Expand(shared_secret)` | 0-RTT resumption secret (`core/src/transport/handshake.rs::process_client_hello`) |
| `b"phantom-session-id-v1"` | `SHA256(shared_secret \|\| nonce)` | session id derivation (`core/src/transport/handshake.rs:derive_session_id`) |
| `"phantom-aes-send-v1"` / `"phantom-aes-recv-v1"` | `blake3::derive_key` over `shared_secret` | AES-256-GCM per-direction subkeys |
| `"phantom-cc20-send-v1"` / `"phantom-cc20-recv-v1"` | `blake3::derive_key` | ChaCha20-Poly1305 per-direction subkeys |
| `"phantom-nonce-pfx-v1"` | `blake3::derive_key(shared_secret)` | 4-byte nonce prefix |
| `"phantom-faketls-c2s-v1"` / `"phantom-faketls-s2c-v1"` | `blake3::derive_key` over `(SNI \|\| version)` public seed | FakeTLS outer obfuscation keys |
| `"phantom-faketls-pfx-v1"` | `blake3::derive_key` over the same public seed | FakeTLS outer nonce prefix |
| `b"phantom-pow-cookie-v1" \|\| hour_be` | `HKDF-Expand(master_secret)` | hour-rotated cookie / PoW HMAC key (Phase 1.11) |

---

## 4. Packet structure

### 4.1 `VersionedPacket` (wire envelope)

Alkahest-tagged enum:

```rust
pub enum VersionedPacket {
    V1(PhantomPacketV1),
    // (future) V2(PhantomPacketV2),
}
```

On wire: 1-byte alkahest discriminant + inner variant bytes.

### 4.2 `PhantomPacketV1`

```rust
pub struct PhantomPacketV1 {
    pub header: PacketHeader,    // 41 bytes
    pub payload: Vec<u8>,        // variable, includes AEAD tag (16 bytes)
    pub extensions: Vec<u8>,     // reserved; empty in V1
}
```

`payload` is the AEAD ciphertext when `PacketFlags::ENCRYPTED` is set,
otherwise the raw bytes (control/ACK only). The AAD is the
alkahest-serialised `PacketHeader` bytes.

### 4.3 `PacketHeader` (41 bytes on wire)

```rust
pub struct PacketHeader {
    pub session_id: SessionId,        // 32 bytes
    pub stream_id: StreamId,          // u16
    pub sequence: SequenceNumber,     // u32
    pub flags: PacketFlags,           // u8
    pub ack_delay: u16,               // u16, milliseconds (0 if not ACK)
}
```

`SessionId` is 32 bytes derived from `SHA256("phantom-session-id-v1" ||
shared_secret || client_nonce)` (server side).

### 4.4 `PacketFlags` (u8 bitmask)

All eight bits are allocated in V1:

| Bit | Constant | Meaning |
| --- | --- | --- |
| `0b0000_0001` | `RELIABLE` | Requires ACK; retransmitted on timeout |
| `0b0000_0010` | `ACK` | This packet is an ACK (empty payload) |
| `0b0000_0100` | `FIN` | Stream finished |
| `0b0000_1000` | `UNRELIABLE` | Fire-and-forget |
| `0b0001_0000` | `PRIORITY` | Voice/video frame priority hint |
| `0b0010_0000` | `ENCRYPTED` | Payload is AEAD ciphertext |
| `0b0100_0000` | `COMPRESSED` | Payload is compressed (`AdaptiveCompressor`) |
| `0b1000_0000` | `CONTROL` | Handshake / migration control message |

Adding any new flag requires a V2 bump — V1's byte is full.

---

## 5. AEAD construction

Per-direction keys and nonce prefix are derived once at session
establishment from the hybrid shared secret. The AEAD nonce on each
packet is:

```
nonce[12] = nonce_prefix[4] || counter_be[8]
```

`counter` is a per-direction `AtomicU64` (`send_counter` / `recv_counter`)
that increments by one on every encrypt / decrypt call. Receivers do
**not** parse the counter from the wire — they maintain their own and
require the sender's to align exactly (strict-counter replay protection).

```
Sender:    plaintext, header  →  AEAD-encrypt(key=send_key,
                                              nonce=prefix||send_counter,
                                              aad=serialize(header),
                                              plaintext)
                              →  ciphertext (with tag)
Receiver:  ciphertext, header →  AEAD-decrypt(key=recv_key,
                                              nonce=prefix||recv_counter,
                                              aad=serialize(header),
                                              ciphertext)
                              →  plaintext  OR  AEAD failure
```

**Hard limit:** `AEAD_MAX_INVOCATIONS = 1 << 48`. Reaching it yields
`CryptoError::NonceExhausted` (`core/src/crypto/adaptive_crypto.rs`).
Per NIST SP 800-38D this is far below any practical AEAD safety boundary;
it is a defensive ceiling.

**Defense-in-depth replay window.** After successful AEAD decrypt, the
receiver consults a per-stream sliding-window bitmap
(`core/src/security/replay_window.rs`) keyed on `header.sequence`. The
window is 1024 sequences wide (RFC 4303 § 3.4.3). Duplicates and
below-window-old sequences yield `CoreError::ReplayDetected`. The window
is redundant with the AEAD strict-counter under in-order delivery (TCP,
KCP) but becomes the only defense if a future leg derives the nonce from
`header.sequence` to support out-of-order delivery.

---

## 6. Handshake (V1)

### 6.1 State machine

```
                    ┌─────────────────┐
                    │ Initial         │
                    │ (no msgs sent)  │
                    └────────┬────────┘
                             │
                  client     │ send ClientHello
                             ▼
                    ┌─────────────────┐
                    │ HelloSent       │
                    └────────┬────────┘
                             │
                   server    │ (validate cookie + PoW)
                             ├─── cookie/PoW invalid ─►  HelloRetry → loop
                             │
                             ▼
                    ┌─────────────────┐
                    │ KEM exchanged   │
                    │ derive session  │
                    └────────┬────────┘
                             │
                             │ send ServerHello (transcript-signed)
                             ▼
                    ┌─────────────────┐
                    │ HandshakeServer │  ← session can encrypt now
                    │ Established     │
                    └─────────────────┘

                    ┌─────────────────┐
                    │ Initial         │  client side
                    └────────┬────────┘
                             │ receive ServerHello
                             ▼
                    ┌─────────────────────────────────────┐
                    │ Verify server_verify_key            │
                    │ vs expected_server_key (pinning)    │
                    │       ▼                             │
                    │ Verify transcript signature         │
                    │       ▼                             │
                    │ Decapsulate KEM                     │
                    │       ▼                             │
                    │ Derive session                      │
                    └────────┬────────────────────────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │ Established     │
                    └─────────────────┘
```

### 6.2 Message: `ClientHello` (borsh-serialised)

```rust
pub struct ClientHello {
    pub client_key_package: HybridKeyPackage,   // X25519 + Kyber768 pubkeys
    pub client_verify_key: HybridVerifyingKey,  // Ed25519 + Dilithium3 pubkeys
    pub nonce: [u8; 32],                        // freshness
    pub version: u8,                            // == 1 in V1
    pub cookie: Option<[u8; 32]>,               // echoed from HelloRetryRequest
    pub pow_solution: Option<PoWSolution>,      // proof-of-work
    pub resume_session_id: Option<[u8; 32]>,    // reserved (Phase 4.1)
}
```

### 6.3 Message: `HelloRetryRequest` (borsh-serialised)

```rust
pub struct HelloRetryRequest {
    pub challenge: Option<PoWChallenge>,  // PoW required iff difficulty > 0
    pub cookie: Option<[u8; 32]>,         // fresh cookie to use on retry
}
```

### 6.4 Message: `ServerHello` (borsh-serialised)

```rust
pub struct ServerHello {
    pub server_key_package: HybridKeyPackage, // ephemeral, reserved (see § 7)
    pub ciphertext: HybridCiphertext,         // KEM encapsulation
    pub server_verify_key: HybridVerifyingKey,// pinned by client
    pub signature: HybridSignature,           // over transcript hash
    pub session_id: [u8; 32],
}
```

### 6.5 Transcript signing

The signature in `ServerHello` covers:

```rust
struct HandshakeTranscript<'a> {
    client_hello:        &'a ClientHello,
    server_key_package:  &'a HybridKeyPackage,
    ciphertext:          &'a HybridCiphertext,
    server_verify_key:   &'a HybridVerifyingKey,
    session_id:          &'a [u8; 32],
}
```

Hash = `SHA256(borsh(transcript))`. The hybrid signature is
`Ed25519.sign(hash) || Dilithium3.sign(hash)` — **both** must verify.

### 6.6 Cookie format

```
cookie = HMAC-SHA-256(
    key   = derive_session_secret_for_hour(master_secret, current_hour),
    msg   = ip_string_bytes || bucket_be(8)
)
```

- `current_hour = unix_secs / 3600`. Validation accepts current OR previous
  hour (Phase 1.11).
- `bucket = unix_secs / 300` (5-minute bucket). Validation accepts current
  OR previous bucket (Phase 1.10).
- The IP is the client's source IP as observed by the server (`accept`
  return). Stateless: server holds no per-cookie state.

### 6.7 PoW format

`PoWChallenge { nonce: [u8; 32], difficulty: u8 }`. Client must find a
preimage such that `SHA256(challenge.nonce || client_ip || solution) `
has at least `difficulty` leading zero bits. Verification: server recomputes
the hash with the candidate solution. Server-side stateless: the challenge
is regenerated deterministically from the rotating per-hour secret.

Difficulty tiers (`HandshakeServer::adaptive_difficulty`):

| Handshakes/min | Difficulty | Expected hash evals |
| --- | --- | --- |
| 0-99 | 0 | (no PoW required) |
| 100-499 | 4 | ~16 |
| 500-1999 | 8 | ~256 |
| 2000-9999 | 12 | ~4096 |
| 10000+ | 16 | ~65536 |

---

## 7. Reserved fields

V1 reserves these for future-but-not-yet-active use:

- `ServerHello.server_key_package`: ephemeral hybrid KEM public, currently
  bound into the transcript hash for freshness but the corresponding
  secret is discarded. Phase 4.1 (0-RTT) or V2 may remove or repurpose it.
- `ClientHello.resume_session_id`: 0-RTT resumption ticket id. Validation
  is a no-op in V1.
- `PhantomPacketV1.extensions: Vec<u8>`: empty in V1; reserved for V2
  extension TLVs.

Future versions MAY ignore these on the wire if and only if they bump
the `VersionedPacket` discriminant.

---

## 8. Error model

Wire-visible errors fall into:

- **Authentication failure**: AEAD tag mismatch, transcript signature
  mismatch, server identity mismatch. Surface as
  `CoreError::CryptoError(_)` or `HandshakeError::ServerIdentityMismatch`.
- **Parse failure**: alkahest / borsh deserialization error. Surface as
  `CoreError::SerializationError(_)` or `HandshakeError::SerializationError`.
- **Liveness failure**: connection closed by peer / I/O error. Surface as
  `CoreError::NetworkError(_)` / `CoreError::ConnectionClosed`.
- **Replay**: post-AEAD sliding-window rejection. Surface as
  `CoreError::ReplayDetected(_)`.
- **Resource exhaustion**: AEAD counter ceiling, replay-cache full.
  Surface as `CryptoError::NonceExhausted` or
  `CoreError::ReplayDetected`.

The library never surfaces an error that distinguishes "wrong key" from
"wrong sequence" from "wrong AAD" — all of these manifest as a single
"decrypt failed" so a network attacker cannot learn anything from the
shape of the failure.

---

## 9. Side notes

- Header fields are big-endian-on-wire (alkahest default for primitive
  ints). Endianness drift is a wire-incompatible regression.
- Every length-prefix on the wire (e.g. TCP framing in
  `TcpSessionTransport`) uses a 4-byte big-endian `u32` length capped at
  `MAX_FRAME_BYTES = 16 MiB`.
- `SessionId`, `HybridKeyPackage`, `HybridVerifyingKey`,
  `HybridCiphertext`, `HybridSignature` all derive
  `BorshSerialize + BorshDeserialize` — the on-wire byte sequence is the
  concatenation of their internal fields in declaration order.

---

## 10. Compliance with documented invariants

The invariants from `SECURITY.md` and `CLAUDE.md` are enforced by this
spec as follows:

| Invariant | Spec section |
| --- | --- |
| Server identity pinning | § 6.1 / § 6.4 / § 6.5 |
| Post-handshake ENCRYPTED flag | § 4.4 / § 5 |
| FakeTLS per-record counter nonces (anti-Forbidden-Attack) | § 3 (`"phantom-faketls-*-v1"` labels) |

Removing or weakening any of these requires a major version bump (V3+)
and a corresponding update to `SECURITY.md`.

---

## 11. V2 wire format

V2 is wire-incompatible with V1: it widens `PacketFlags` from u8 to u16
and adds two single-byte fields. Sessions are version-pinned end-to-end
— a V2 session never accepts V1 packets and vice versa. The
`VersionedPacket` alkahest enum naturally distinguishes the two with
its discriminant byte.

### 11.1 `PacketFlagsV2` (u16 bitfield)

Low byte mirrors V1's bit assignments verbatim (so `RELIABLE` is `0x0001`,
`ENCRYPTED` is `0x0020`, etc. — full table in § 4.4). High byte
introduces:

| Bit | Constant | Meaning |
| --- | --- | --- |
| `0x0100` | `REKEY` | Sender has rekeyed; receiver must `ratchet_to_epoch(header.epoch)` before decrypting (Phase 1.5). |
| `0x0200` | `PATH_VALIDATION` | Payload is a 32-byte challenge or response for multi-path validation (Phase 4.2). |
| `0x0400` | `COALESCED` | Payload is a bundle of inner packets in `[count: u16][len1: u16][p1]...` format (Phase 2.5). |
| `0x0800..0x8000` | _reserved_ | Future V2 amendments. |

### 11.2 `PacketHeaderV2` (44 wire bytes)

```rust
struct PacketHeaderV2 {
    session_id: SessionId,         // 32 bytes
    stream_id: StreamId,           // u16
    sequence: SequenceNumber,      // u32
    flags: PacketFlagsV2,          // u16
    ack_delay: u16,                // u16
    epoch: u8,                     // u8  — rekey generation
    path_id: u8,                   // u8  — multi-path leg identifier
}
```

V1's 41-byte header + 3 new bytes (`flags` widened by one byte plus
`epoch` and `path_id`).

### 11.3 V2 AEAD construction

V2 abandons V1's internal-counter-derived nonce in favour of a
nonce derived from the AAD-bound header fields. This fixes V1's
"failed-decrypt-desyncs-the-session" pathology (a tampered or replayed
packet permanently broke the session because `recv_counter` advanced
on every attempt).

Nonce layout (12 bytes total):

```
nonce[0..4]  = nonce_prefix    (from CryptoState; fresh per rekey epoch)
nonce[4]     = header.epoch
nonce[5..7]  = header.stream_id  (big-endian)
nonce[7..11] = header.sequence   (big-endian)
nonce[11]    = header.path_id
```

Uniqueness: senders never reuse `(stream_id, sequence)` within an epoch,
and `path_id` distinguishes the same logical packet across multi-path
legs. The full 12 bytes are therefore unique under a given key.

Failed decrypts do NOT advance any nonce-relevant state. The internal
`recv_counter` is kept only as a telemetry counter (capped at
`AEAD_MAX_INVOCATIONS = 1 << 48`).

### 11.4 Mid-session rekey (Phase 1.5)

`Session::rekey()`:

1. Derives `next_secret = HKDF-Expand(current_traffic_secret,
   "phantom-rekey-v1", 32)`.
2. Builds a fresh `CryptoState` from `next_secret` with the same
   `is_server` orientation as the original handshake.
3. ArcSwap-installs the new state — concurrent encrypt/decrypt see
   either the old or new state atomically.
4. Zeroes the previous traffic secret in place before overwriting.
5. Increments `Session.epoch` (saturating at `u8::MAX` — long-lived
   sessions must reconnect rather than wrap to epoch 0).

Wire signalling: the sender emits a V2 packet whose header carries the
new `epoch` value and the `PacketFlagsV2::REKEY` flag. Receivers respond
by calling `ratchet_to_epoch(header.epoch)` on themselves, which walks
the HKDF chain forward until the local epoch matches.

The KDF label `"phantom-rekey-v1"` is part of the V2 KDF inventory and
is treated as a wire-format constant.

### 11.5 V2 KDF additions

Adds to the inventory in § 3:

| Label | Construction | Purpose |
| --- | --- | --- |
| `b"phantom-rekey-v1"` | `HKDF-Expand(current_traffic_secret)` | Forward-derive the next per-epoch traffic secret |

### 11.6 Session pinning

A single `Session` is pinned to one wire version for its lifetime —
mixed V1+V2 use within a session is not supported. Version selection
happens at handshake time (Phase 1.8 work, currently in V1-only mode
because the handshake itself remains V1).

### 11.7 Cross-version isolation

A V1 ciphertext + header cannot be replayed against `decrypt_packet_v2`
on the same key: the AAD bytes differ (V1 header is 41 bytes,
V2 header is 44 bytes, different serialisation), so the AEAD tag check
fails by construction. Test
`v1_ciphertext_does_not_decrypt_as_v2` in
`core/tests/security_invariants.rs` pins this property.
