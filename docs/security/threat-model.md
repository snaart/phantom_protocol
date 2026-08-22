# Phantom Protocol Threat Model

Methodology: STRIDE for security, LINDDUN for privacy. Audit-friendly format —
each finding maps to a concrete mitigation, traceable to a file and the item
inside it. Pointers name the enclosing function, type or constant rather than a
line number: line numbers here had drifted far enough that five of them resolved
into unrelated code, which turns an adversarial read of this document into a
fiction. A name survives the edits a line number does not.

Document status: **draft**. Living document; updates with each substantive
change to the protocol or trust boundaries. Last reviewed against repo state
at the commit that introduces this file.

---

## 1. Scope and assumptions

### In scope

- The `phantom_protocol` library: hybrid post-quantum L4/L6 transport.
- Network adversary observing and manipulating traffic between two
  endpoints (active MITM, on-path attacker).
- Volume-based denial-of-service against the listener.
- Cryptographic agility (primitive choice, rotation, migration).

### Out of scope (informally; tracked but unowned by this codebase)

- Endpoint compromise (root on either peer's host).
- Compromise of the server's long-lived signing key after generation.
- Supply-chain attacks against the Rust toolchain or third-party crates
  (`cargo-deny` and `cargo-audit` jobs are the partial mitigation).
- Side-channel attacks beyond timing (power analysis, EM emanation,
  cache-microarchitectural attacks against AES-NI / ChaCha20).
- Application-layer logic flaws in callers (the SDK ships plaintext bytes
  in/out; semantic correctness is the caller's responsibility).
- Physical attacks on devices holding keys.

### Assumptions

1. The OS RNG (`getrandom` / `OsRng`) produces cryptographically secure
   randomness. A compromised OS RNG defeats every primitive here.
2. SHA-256, AES-256-GCM, X25519, Ed25519 retain their stated security
   margins. The post-quantum half is ML-KEM-768 (FIPS 203) and ML-DSA-65
   (FIPS 204) — the standardized successors to Kyber768 / Dilithium3, shipped
   via the pure-Rust RustCrypto `ml-kem` / `ml-dsa` crates.
3. Both peers know the server's `HybridVerifyingKey` out of band (TOFU,
   PKI, or app distribution). The library does NOT solve key distribution.
4. Time is approximately monotonic on each peer; the cookie freshness
   buckets (Phase 1.10) tolerate ±5 minutes of clock skew naturally.
5. Memory is not extractable from a running process by external means.
   `ZeroizeOnDrop` (Phase 1.2) protects against post-process forensic
   recovery, NOT against live introspection.

---

## 2. Trust boundaries

```
       ┌──────────────────────────────┐                ┌──────────────────────────────┐
       │  Client process              │                │  Server process              │
       │ ┌──────────────────────────┐ │                │ ┌──────────────────────────┐ │
       │ │ Application code (caller)│ │                │ │ Application code (caller)│ │
       │ └──────────┬───────────────┘ │                │ └──────────┬───────────────┘ │
       │            ▼                 │                │            ▼                 │
       │ ╔════════════════════════╗   │                │   ╔════════════════════════╗ │
       │ ║ phantom_protocol API       ║   │                │   ║ phantom_protocol API       ║ │
       │ ║ (PhantomSession,       ║   │                │   ║ (PhantomListener,      ║ │
       │ ║  PhantomStream, ...)   ║   │                │   ║  PhantomSession, ...)  ║ │
       │ ╚═════════╤══════════════╝   │                │   ╚═════════╤══════════════╝ │
       │           │ FFI boundary     │                │             │ FFI boundary   │
       │           ▼                  │                │             ▼                │
       │ ╔════════════════════════╗   │                │   ╔════════════════════════╗ │
       │ ║ transport / crypto     ║   │                │   ║ transport / crypto     ║ │
       │ ╚═════════╤══════════════╝   │                │   ╚═════════╤══════════════╝ │
       │           ▼                  │                │             ▼                │
       └───────────│──────────────────┘                └─────────────│────────────────┘
                   │                                                 │
                   │   ─────────►   active adversary   ◄─────         │
                   │     ───────►   passive observer   ◄───           │
                   └────────────────► hostile network ◄───────────────┘
```

The double-line boxes inside each process (`phantom_protocol API` and
`transport / crypto`) are this library's responsibility. Everything outside
is the caller's.

The **strongest** boundary in the diagram is the network — every byte that
crosses it is subject to active mutation. The FFI boundary inside each
process is a weaker boundary (we trust the caller and the OS).

---

## 3. Assets

| # | Asset | Where | Loss impact |
| --- | --- | --- | --- |
| A1 | Server long-lived `HybridSigningKey` | `HandshakeServer.signing_key` | Catastrophic — attackers can impersonate the server for all future handshakes; no forward secrecy mitigates retroactive reads. |
| A2 | Server master secret (cookie / PoW HMAC key root) | `HandshakeServer.master_secret` | Attacker can forge cookies, bypass PoW, mount IP-spoofing amplification. Hourly HKDF rotation (Phase 1.11) bounds compromise window. |
| A3 | Hybrid KEM private keys (ephemeral, per-handshake) | `HandshakeClient.kem_secret` | Compromise of one session's KEM key leaks that session's symmetric keys → all traffic from that session decryptable. Mitigated by ephemeral generation per handshake + `ZeroizeOnDrop`. |
| A4 | Session AEAD keys | `CryptoState.session_key`, ring `LessSafeKey` inside `CryptoSessionInner` | Compromise leaks the **current epoch's** packets in that direction. Mitigated by `ZeroizeOnDrop` (Phase 1.2) and the **shipped** mid-session HKDF rekey — **past-epoch forward secrecy only, no post-compromise security** (a live `traffic_secret` yields all future epochs; healing needs a re-handshake — see §8). |
| A5 | Application plaintext | passed in/out via `Vec<u8>` / `Bytes` | The whole point of the transport. |
| A6 | Session identity / linkability metadata | the inner 32-byte session_id is **off-wire** (ε §4.2, in the AEAD AAD only); stream id, packet numbers, flags, epoch, path id (**HP-masked** — T4.6 §4.6); the single routing 8-byte `ConnId` is the only per-connection cleartext and it **rotates per migration** (ε §4.7) | **Closed by ε + A2a for migration by *either* peer** (LINDDUN-L, PROTOCOL.md §12.5; EPS-02 closed): a migration rotates **both** directions' ConnId regardless of which peer moves. A *client* move rotates c2s (`migrate()`) and the server rotates s2c on the new `path_id`; a *server* move rotates s2c (`migrate_server()`) and the client *reflects* — it bumps its `path_id` + rotates c2s, which slides the server's c2s window so the rotated CID stays routable (no stranding) and there is no ping-pong (the server's matching s2c re-rotation is `path_id`-silent). So a client moving Wi-Fi→cellular **and** a server failover/egress-change are both unlinkable in both directions. Caveat: the CID chain is not forward-secret (a session-key compromise relinks a recorded flow). **WIRE v6 shipped the remaining wire-diet anti-fingerprinting:** the constant `version` byte is now HP-masked and the cleartext length prefixes are dropped (PROTOCOL.md §4.1/§4.6), and opt-in PADÉ size padding / timing jitter / cover traffic are available (§4.8, off by default — see the LINDDUN-D row). |
| A7 | Cookie / PoW state | client-side stored cookies | Loss enables replay of one round trip within freshness window only. |

---

## 4. Adversary model

| Capability | Modeled? | Mitigation locus |
| --- | --- | --- |
| Passive observation (any portion of the wire) | Yes | AEAD confidentiality |
| Active modification (any portion of the wire) | Yes | AEAD AAD over `PacketHeader`; transcript signing |
| Active injection (fabricated packets) | Yes | AEAD authenticity; replay window (Phase 1.4) |
| Replay of captured packets | Yes | AEAD strict-counter nonce + replay window (Phase 1.4) |
| MITM with own keypair (active impersonation) | Yes | Server identity pinning (`expected_server_key`, May 2026 review Vuln 1 fix) |
| Volumetric DoS (SYN flood, handshake flood) | Yes | Cookie + adaptive PoW (Phase 1.10, 1.11, 1.14) |
| Timing-channel observation | Yes (limited) | `subtle::ConstantTimeEq` on cookie path (Phase 1.1); constant-time crypto via ring/dalek libraries |
| Side channel (power / EM / cache) | **No** | Out of scope; documented assumption. |
| Quantum computer (CRQC) attacker | Yes | Hybrid PQ + classical KEM and signatures. Drop-classical degradation harmless until classical is broken; drop-PQ degradation harmless until CRQC arrives. |
| Endpoint compromise (root on peer) | **No** | Out of scope; defender problem. |
| OS RNG compromise | **No** | Out of scope; we treat `getrandom` as a trusted oracle. |
| Long-lived signing-key theft | **No** (post-compromise) | Phantom Protocol relies on the server signing key for authentication — once leaked, attacker can serve as the server. Key revocation is an out-of-band concern (PKI / OOB re-pinning). |

---

## 5. STRIDE analysis

### S — Spoofing identity

| Threat | Mitigation | Code |
| --- | --- | --- |
| Adversary presents a fake server key in `ServerHello` | Client pins `expected_server_key`; mismatch → `HandshakeError::ServerIdentityMismatch` | `core/src/transport/handshake.rs::process_server_hello` (the pinned-key compare) |
| Adversary forges a `ClientHello` to spoof an IP | Cookie + adaptive PoW; cookie is HMAC(rotating-secret, ip, bucket) so forgery requires the secret | `core/src/transport/handshake.rs::cookie_pow_gate` |
| Replay of an old, captured `ServerHello` to a fresh client | Transcript signature binds `client_hello.nonce` and `session_id_bytes`; replay fails signature check | `core/src/transport/handshake.rs::HandshakeTranscript` + `::process_server_hello` (client-side verify) |
| Connection-migration hijack: a known (plaintext) `session_id`/CID replayed from a spoofed source to steal the session | Path validation — a fresh unguessable 32-byte challenge must be echoed *from* the claimed address (only the session-key holder can), constant-time verified, before the server switches its peer; pinned-key AEAD blocks read/inject. Worst achievable is a **redirection-DoS**, **never** hijack/decrypt (the QUIC §9 boundary) | `core/src/transport/path.rs`, `core/src/api/session.rs`, `PROTOCOL.md` §12 |
| 0-RTT early-data replay against a **single** server | The server `peek()`s the ticket (non-consuming), verifies the `ClientHello.resumption_binder` proof-of-possession in constant time, then **eagerly `remove()`s** it (race-free one-shot, Invariant 9), so a replayed `ClientHello` finds no ticket and the server falls back to a 1-RTT handshake that ignores the early-data. On any *later* handshake failure the ticket is re-inserted unchanged (`reinsert_with_expiry`), so a corrupted resuming hello cannot burn a victim's ticket | `core/src/transport/handshake.rs::process_client_hello` (peek/binder/remove), `core/src/transport/session_cache.rs::{peek, remove, reinsert_with_expiry}`, `PROTOCOL.md` §6.6 |
| 0-RTT early-data replay against a **different node** (horizontal scale-out) | **Mitigable — the library provides the controls (A2b); the embedder picks a posture.** The built-in one-shot guarantee holds only under a *single coherent* `SessionCache` (an in-process LRU, not replicated), so a horizontally-scaled deployment with per-node caches would otherwise let an attacker replay a captured 0-RTT `ClientHello` against a node that still holds an unconsumed copy of the ticket (the classic TLS-1.3 0-RTT-across-a-server-farm replay). The library now offers two controls: **(1)** install a distributed `ZeroRttAntiReplay` store (`set_zero_rtt_anti_replay`) whose atomic `check_and_set` makes the consume first-use **globally** across the fleet — replay-safe 0-RTT at scale (the *store* is the embedder's infra, e.g. Redis `SET NX`; the transport ships only the seam, failing closed on store errors); or **(2)** disable 0-RTT early-data entirely (`set_early_data_enabled(false)`) so the payload is only ever delivered 1-RTT — the zero-infrastructure default. Sticky/hashed routing or idempotent early-data also suffice. The post-handshake session's PFS + auth are unaffected regardless. See `docs/operations/zero-rtt.md`. | `core/src/transport/handshake.rs` (`ZeroRttAntiReplay`, `set_early_data_enabled`), `core/src/transport/session_cache.rs`, `PROTOCOL.md` §6.6 |

### T — Tampering with data

| Threat | Mitigation | Code |
| --- | --- | --- |
| Bit-flip in ciphertext | AEAD tag check fails → packet dropped | `core/src/crypto/adaptive_crypto.rs::decrypt_with_nonce` |
| Mutation of header on the wire | The header is serialized by `PacketHeader::to_wire` (15 big-endian wire bytes, wholly HP-masked); the AEAD AAD is the separate 47-byte `PacketHeader::to_aad_image()` (which additionally binds the off-wire 32-byte `session_id`), so any mutation invalidates the tag | `core/src/transport/types.rs::{PacketHeader::to_wire, PacketHeader::to_aad_image}`, `core/src/transport/session.rs` |
| Tampering with handshake messages | Transcript signature covers every field of `ClientHello`/`ServerHello` | `core/src/transport/handshake.rs::HandshakeTranscript` + `::process_server_hello` (client-side verify) |
| Packet-number mutation (replay or skip) | After AEAD verify, `Session::decrypt_packet` consults a single per-direction `ReplayWindow` (keyed on the `u64` packet number) and rejects duplicates / out-of-window-old | `core/src/transport/session.rs`, `core/src/security/replay_window.rs` |

### R — Repudiation

Not in scope. The protocol does not provide non-repudiation: there is no
externally-verifiable proof of which peer sent which message. Adding
non-repudiation would require persistent per-message signing — out of scope
for a real-time secure transport.

### I — Information disclosure

| Threat | Mitigation | Code |
| --- | --- | --- |
| Plaintext leak on the wire | AEAD encryption (post-handshake invariant `PacketFlags::ENCRYPTED`); unencrypted post-handshake packets dropped, and every drop counted into `unencrypted_dropped_total` so the gate firing is visible without an OTLP pipeline | `core/src/api/session.rs::handle_packet` (the `ENCRYPTED` branch and the `else` arm that drops everything else); driven end-to-end by `core/tests/security_invariants.rs::forged_unencrypted_post_handshake_packet_is_dropped_by_the_recv_path` |
| Plaintext leak via error message | Error variants carry only the error class, not the payload; no `format!("{:?}", plaintext)` anywhere | grep `format!.*plaintext\|payload` in `core/src/` → 2 hits, both formatting a transport *error* under the literal label "write payload" (`transport/legs/wasi.rs:188`, `transport/legs/embedded/mod.rs:82`) — no call site interpolates application plaintext |
| Memory disclosure of keys after session close | Key-bearing structs zeroize on drop: `ZeroizeOnDrop` on `CryptoState` (`session.rs`), `HandshakeServer` / `HandshakeClient` (`handshake.rs`), and `ResumptionTicket` (`session_cache.rs`, T5.1); the rekey master `Session.traffic_secret` is zeroized in `Session::drop` (T5.1) along with `resumption_secret`; the transient handshake KEM secret is held in `Zeroizing` (T5.1). Mid-session rekey also zeroizes each superseded epoch secret. | `session.rs` (`CryptoState`, `Session::drop`), `handshake.rs` (`HandshakeServer`/`HandshakeClient` + `Zeroizing` KEM secret), `session_cache.rs` (`ResumptionTicket`) |
| Timing leak on cookie comparison | `subtle::ConstantTimeEq::ct_eq` — never branches on cookie content | `core/src/transport/handshake.rs::validate_cookie` |
| DPI fingerprinting | **Partial (WIRE v6) + opt-in TLS mimicry (`mimicry` feature):** the data-plane wire has **no constant cleartext byte** (the version byte is HP-masked) and **no cleartext length-prefix pattern** (dropped — §4.1/§4.6), removing the two structural tells a stateless DPI box keyed on; opt-in size padding / timing jitter / cover traffic (§4.8) blunt the statistical tells. The outer 8-byte `ConnId` + opaque-blob datagram *shape* is still recognizable on bare UDP — the **`mimicry` feature** (TLS-over-TCP `MimicTlsLeg`) makes a flow look like HTTPS instead. **Residual:** the mimicry defeats passive/light-stateful DPI but **not active probing** (§6.1). | PROTOCOL.md §4.1 / §4.6 / §4.8 ; threat-model §6.1 |

### D — Denial of service

| Threat | Mitigation | Code |
| --- | --- | --- |
| Handshake flood / IP spoof amplification | Stateless cookie (HMAC over rotating secret + IP + bucket) forces attacker to receive a packet at the spoofed IP before consuming server resources | `core/src/transport/handshake.rs::generate_cookie`, `validate_cookie` |
| CPU-exhaustion via cheap handshake attempts | Adaptive PoW difficulty tiers from 0 → 16 (~64k hash evals) based on per-minute load | `core/src/transport/handshake.rs::adaptive_difficulty` (Phase 1.14) |
| Panic-on-malformed input | `#![deny(clippy::unwrap_used, expect_used, panic, unreachable, todo, unimplemented, missing_safety_doc)]` (the crate-root `deny` block in `core/src/lib.rs`) plus `.clippy.toml`'s `disallowed-methods` ban on `Option::unwrap` / `Result::unwrap`; no `.unwrap()` on the recv/handshake hot path; fuzz harnesses in `fuzz/` | Phase 1.3, 6.4 |
| AEAD nonce exhaustion (theoretical) | Hard ceiling `AEAD_MAX_INVOCATIONS = 1 << 48` → `CryptoError::NonceExhausted` | `core/src/crypto/adaptive_crypto.rs::AEAD_MAX_INVOCATIONS` |
| Replay-window memory amplification | One per-direction `ReplayWindow` (~144 bytes) per session — no per-stream growth | `core/src/security/replay_window.rs` |
| **Receive-side memory amplification by an authenticated peer** | See the dedicated treatment below. Each receive buffer has a bound with something enforcing it; **no single per-session total is published**, two of the terms are observed rather than enforced, and every bound is **per session** — the process multiplier is the embedder's admission control | `core/src/transport/stream.rs`, `core/src/transport/bandwidth_estimator.rs`, `core/src/api/session.rs` (receive-memory section of the module documentation) |
| Connection-migration amplification: known CID + spoofed source used as a reflector toward a victim | To an unvalidated address the server is **challenge-only** and caps bytes sent to **≤ 3× bytes received** (RFC 9000 §8.2); a spoofed address never echoes the challenge so it is never switched-to | `core/src/api/udp_transport.rs` (anti-amp budget), `PROTOCOL.md` §12.3 |

#### D.1 — Receive-side memory amplification by an authenticated peer

Authentication is not trust (§4). Once a peer holds session keys it decides how
many streams to open, how much to send, and — the part that matters here — how
long to leave a reassembly hole open. Every receive-side buffer is therefore a
memory commitment this side makes on the peer's word, and the commitments
multiply:

```text
  advertised window   sizes one stream's unconsumed data AND the reorder budget
        ×             that tracks it (recv_reorder_byte_limit = window + 64 KiB)
  reorder buffer      out-of-order segments held above a hole, which flow control
        ×             never counts — only delivered data is
  streams             the peer opens them; the recv path auto-creates one per
        ×             stream_id it sees
  sessions            the peer opens those too
```

There is a fifth term that does not sit in that chain and is easy to miss for
exactly that reason: the congestion controller's own state is written by the
peer's **acknowledgements**, not by its data. It is included below because the
one instance of this class found in the estimator had no data-side symptom at
all.

**What is enforced, and by what.** Each row below states a bound and the code
that refuses to exceed it. The "enforced" column is the whole point of the
table: a limit nothing checks is a convention, and a convention constrains a
compliant peer and nobody else.

| link | bound | enforced by | enforced? |
| --- | --- | --- | --- |
| streams | `MAX_STREAMS` = 256 | `handle_packet` refuses the segment that would create the 257th; unrecorded, so it is not SACKed either | **yes** |
| inbound frame | `MAX_RECV_FRAME` = 1191 B, i.e. `MAX_RECV_PAYLOAD` = 1160 B of plaintext | the pump's reader drops a larger frame before decrypting it | **yes** |
| advertised window | `MAX_RECV_WINDOW` = 1 MiB per stream | *nothing* — the receive path admits in-order data without consulting it | **no — observed** |
| window growth | one session-wide `SESSION_RECV_WINDOW_GROWTH_BUDGET` = 8 MiB over the 64 KiB every stream starts with | `SharedRecvTuning` draws every doubling from the one allowance | **yes** |
| reorder buffer | `MAX_RECV_REORDER` = 2048 entries and `Stream::recv_reorder_byte_limit` bytes, per stream; ~128 B of structure per entry, which the byte budget does not count | `Stream::accept_in_order` refuses the segment (not SACKed → the sender retransmits) | **yes, on out-of-order segments only** |
| delivery backlog | `RECV_DELIVERY_HARD_CAP` = 4 MiB **plus `MAX_DELIVERY_CHARGE_PER_FRAME` ≈ 49 KiB**, charged per item as payload + `DELIVERY_ITEM_OVERHEAD_BYTES` = 128 B | the reader tears the session down past the cap | **yes** |
| per-stream delivery queues | `STREAM_RECV_CHANNEL_DEPTH` = 1024 slots per stream, `RAW_APP_RECV_CHANNEL_DEPTH` = 256 once per session | the channel is bounded and the delivery task blocks rather than growing it; the slot *contents* are bounded by the frame gate above | **yes, in slots; in bytes only because of the frame gate** |
| bandwidth / round-trip filters | 1024 entries per filter, two filters per session, an entry being a timestamp and a `u64` — tens of KiB | a minimum time separation between retained entries, so a horizon holds at most `horizon / separation` gaps and one entry more (`transport/bandwidth_estimator.rs`) | **yes** |

Five of those entries are qualified, and the qualifications are the point.

The **advertised window** is a promise about what this side will admit, not a
gate. Nothing on the receive path refuses in-order data for exceeding it, so it
shapes a compliant sender's behaviour and constrains a hostile one not at all.
It is listed because it is the number design discussions usually focus on
and because reading it as a bound is the specific mistake this row exists to
prevent.

The **reorder bounds cover the out-of-order arm only.** A segment that arrives
in order is released straight to the delivery path and never enters the reorder
buffer, so neither the entry cap nor the byte budget says anything about what a
peer sending a gap-free stream can make the session hold. What bounds that is
the frame gate on the way in and the delivery cap once it is through.

The **delivery backlog's cap is crossed before it is noticed**. The charge a
frame adds is only known once the frame has been decrypted and routed, so the
counter is read around the frame rather than inside it and one frame's worth
always lands past the line. Checking below the charge instead of above it does
not change that — the same frame is the one that crosses — so the overshoot is
published (`MAX_DELIVERY_CHARGE_PER_FRAME`) instead of being designed away. Its
size is set by the most sub-payloads a single `COALESCED` bundle can carry,
each of which becomes a separately-charged queue item.

The **per-stream delivery queues are bounded in slots intrinsically, and in
bytes only because of the frame gate.** That distinction is not academic: it is
exactly what the published figure for those queues got wrong. It charged a slot
`MAX_APP_CHUNK` — the size *this* side chunks to — while the receive path would
have accepted a frame three thousand times larger, so the figure was understated
by three orders of magnitude for as long as it stood.

The **estimator's filters are bounded by time, and were not bounded at all.**
Each of the two sliding filters — the bandwidth maximum and the round-trip
minimum — is a deque of unexpired candidate samples, one sample per
acknowledged flight. Nothing capped its length, and the number of samples inside
one horizon is the peer's acknowledgement cadence: a peer that acknowledges more
often puts more entries in, which is a local memory commitment sized by a remote
choice. Capping the length by count was tried and is wrong for a reason worth
recording, because it looks safe: evicting the least entry of a maximum filter
strands it as "the oldest entry plus the newest", and the moment the oldest
expires the reading falls to a value the path stopped offering a horizon ago,
which then sets the congestion window. Both filters are bounded instead by a
minimum time separation between retained entries, applied only to the entries
the reading does *not* come from — a sample that would move the reading is
always admitted. The length then follows as arithmetic (entries sit at least one
separation apart within one horizon) rather than as a cap someone checks, and
the peer's cadence buys it nothing. It is a small term in bytes; it is listed
because its input is acknowledgements rather than data, so none of the reasoning
about the four rows above would have found it.

**Why there is no per-session total.** Adding the rows up gives a number that
reads as a bound and is not one. The sum covers the buffers the session layer
owns and not the ones beneath it: the byte pipe's own receive accumulator, the
per-session PhantomUDP fragment reassembler
(`MAX_CONCURRENT_ASSEMBLIES × MAX_REASSEMBLED_LEN`), the `Stream` structures
themselves. Three successive attempts to publish such a total were each
corrected upward by a term the previous one had left out, so the total was
withdrawn rather than restated a fourth time. Sizing a host is a measurement
exercise against the deployment's own traffic; the table above is for reasoning
about what a hostile peer can move, not for arithmetic.

The dominant term, on any accounting, is unread data in the per-stream delivery
queues — `MAX_STREAMS` × `STREAM_RECV_CHANNEL_DEPTH` slots, which follows from
those two constants rather than from anything the transport needs. They fill
only when the local application is slower than the peer, which is why they are
deliberately outside the delivery hard cap: tearing a session down for a slow
consumer would punish an honest peer and mislabel the cause.

`security_invariants.rs` and the session unit tests pin these by measurement
rather than by restating the arithmetic: that N sessions of M streams hold no
more than N growth budgets between them; that the published process figure above
is the session cap times what a session is *observed* to draw, so the documents
and the reference server's flag cannot drift from the constant they were written
from; that a real reorder buffer at its entry
cap and a real delivery channel at its depth take no more heap than the figures
published for them; that a queued item costs more than its payload, so the
backlog charge is not fiction; that one frame cannot charge the backlog more
than the published overshoot; and — two-sided — that an oversized frame is
refused while the session survives it, and that nothing the pump itself emits
exceeds the gate the peer applies.

**Mitigation, and its honest limit.** The growth budget is the mechanism that
makes a *per-stream* window ceiling safe — it is what stops 256 streams each
reaching 1 MiB — and growth is earned only by bytes the local application has
actually consumed, never by arrival, so a peer that floods an application which
never reads moves nothing. The frame gate is what makes the queue depths mean
something in bytes.

**Every bound in the table is per session, and the multiplier is the session
cap.** For the growth budget — the one row that is a single enforced constant
rather than a worst case derived from several — the process arithmetic is exact:

```text
  PHANTOM_MAX_SESSIONS × SESSION_RECV_WINDOW_GROWTH_BUDGET
            1024       ×          8 MiB                    =  8 GiB
```

That is receive-window growth alone, at the reference server's shipped default,
before a reorder entry or a queue slot is counted. The other rows multiply the
same way but their per-session figures are worst cases, so the products are
estimates and are useful only for ranking the terms. Admission control is
therefore what bounds a process, and it belongs to the embedder;
`--max-recv-window-growth-mib` in the reference server states the left-hand side
of the arithmetic above and derives the session cap from it, refusing to start
on a ceiling that cannot hold one session. It bounds one term of five and not
the dominant one — a floor on the host's requirement rather than a ceiling on
its footprint — and `docs/operations/deployment.md` says so where an operator
will read it.

A process-wide second tier over the growth budget was considered and rejected.
It would bound that 8 GiB, and it would do so by putting one peer's growth
decisions in charge of another peer's window: growth is first-come, so a peer
that opens sessions and drains them just fast enough to earn doublings exhausts
the process allowance and pins every session admitted afterwards at the 64 KiB
initial window — 2.6 Mbit/s on a 200 ms path. That is a remote peer steering a
local control loop, which §4's adversary model forbids outright, and it is worse
than the exposure it removes: the present design's failure mode is a host sized
too small, which the operator can see and fix, while the shared tier's failure
mode is one peer degrading every other peer's throughput with no signal that
distinguishes it from a slow path.

**Consequences for review.** Any change that widens a term above — a larger
window ceiling, a larger reorder entry cap or byte budget, more streams, a
larger delivery cap, a deeper delivery channel, a larger frame gate, a longer
estimator filter — is a change to what a peer can make this side hold. Two such
changes were rejected during the receive-path work for exactly this reason. Nor
is a term small
because its unit is small: the delivery backlog was counted in payload bytes
with no per-item term until someone measured it, and the delivery *queues* were
sized against the sender's own chunk constant — a number this side picks — while
the peer was free to send frames three thousand times larger. Both errors have
the same shape, which is treating a figure this endpoint chose as though it
bounded the other one. The same applies to anything that would let a peer's
timing or acknowledgements decide how much this side holds: the growth trigger
is local consumption on purpose, and the RTT reference auto-tuning divides by is
a constant on purpose (`AUTOTUNE_RTT_FALLBACK`), because a peer that could
inflate it would be lowering the bar its own doublings have to clear.

### E — Elevation of privilege

Out of scope — `phantom_protocol` does not run with elevated privileges or
expose any privileged operation. The library is a passive data conduit.

---

## 6. LINDDUN privacy analysis

| Threat | Status | Note |
| --- | --- | --- |
| **L**inkability of two sessions to the same client | Partial | Same `HybridVerifyingKey` on the client side correlates handshakes (the client signing key is reused). Anonymous mode would require ephemeral client signing keys; tracked as future work. |
| **L**inkability of one session across a network change (migration) | **Mitigated (ε + A2a) — migration by *either* peer is unlinkable both ways (EPS-02 closed)** | Header protection (T4.6, §4.6) masks the variable per-packet metadata (packet numbers, flags incl. PRIORITY, stream id, epoch, path id), and ε removed the inner 32-byte `session_id` from the wire (off-wire in the AEAD AAD — §4.2) and makes the routing `ConnId` **rotate** per migration via per-direction KDF chains + a sliding demux window (§4.7). Rotation is symmetric for **both** migration directions: the moving peer advances its outbound chain and the other peer advances its return chain in response. A **client** migration: the client advances c2s on `migrate()`, the server advances s2c on the new `path_id` (the socket-routed client absorbs the new inbound CID, no slide, no ping-pong). A **server** migration: the server advances s2c on `migrate_server()`, and the client *reflects* on authenticating the server's new `path_id` — it bumps its own `path_id` + advances c2s, which slides the server's c2s demux window so the rotated CID stays routable (the no-stranding fix that the earlier asymmetry avoided by not rotating c2s); the server's matching s2c re-rotation is `path_id`-silent, so the client does not re-reflect (one round). So a client moving Wi-Fi→cellular **and** a server failover/egress-change are both unlinkable in both directions (EPS-02 closed by A2a — `docs/security/audit-report-2026-06-15-wire-v5-epsilon.md`). **Honest caveat:** the CID chain is session-stable and **not** forward-secret — a session-key compromise lets an attacker recompute the chain and relink a *recorded* flow; the payload stays forward-secret. The constant `version` byte (a protocol, not per-connection, fingerprint) is now **HP-masked** as of WIRE v6, along with the cleartext length prefixes; opt-in size/timing/volume shaping is available (§4.8 — off by default, see the LINDDUN-D row). See `PROTOCOL.md` §4.1 / §4.2 / §4.6 / §4.7 / §4.8 / §12.5. |
| **I**dentifiability of the client | No mitigation | Source IP is necessarily visible to the server. Client may use Tor / VPN externally. |
| **N**on-repudiation | Intentionally out of scope (see STRIDE-R) |
| **D**etectability that this is `phantom_protocol` | **Partially mitigated (WIRE v6) + opt-in active mimicry (`mimicry` feature)** | WIRE v6 removed the structural tells on the bare UDP wire (no constant cleartext version byte, no length-prefix pattern — §4.1/§4.6), and opt-in shaping (§4.8) blunts size/timing/volume tells — but the UDP datagram *shape* (8-byte `ConnId` + opaque blob) is still recognizable. The **`mimicry` feature** (a TLS-over-TCP `MimicTlsLeg`: `bind_mimic` / `connect_pinned_mimic`) makes a flow look like ordinary HTTPS to passive DPI + JA3/JA4 fingerprinting + light stateful inspection. **It defeats parsers, not provers:** it is detectable by an active-probing censor (the handshake is theater — no real ECDHE / certificate) and is net-negative against one. Honest residuals + SAFE/UNSAFE deployment guidance in **§6.1**. |
| **D**isclosure of metadata (sizes, timing) | **Opt-in mitigations (WIRE v6) — OFF by default** | The data-plane wire no longer carries a structural size fingerprint: WIRE v6 dropped the cleartext `payload_len` / `ext_len` prefixes (PROTOCOL.md §4.1). On top of that, three **opt-in** anti-fingerprint controls are available via `TrafficShapingConfig` (PROTOCOL.md §4.8): **(c) PADÉ size padding** — pads each packet to a bounded (≈ ≤12% worst-case) size bucket inside the AEAD, so the datagram size no longer tracks the payload size; **(d) timing jitter** — a uniform `[0, jitter_ms]` ms per-packet send delay, so inter-packet timing no longer tracks app writes; **(e) cover traffic** — an `ENCRYPTED \| COVER` dummy packet maintains a floor outbound rate, so silence/volume no longer leak (authenticated, then dropped by the peer). **Honest residual:** all three are **off by default** (an embedder must enable them, trading bandwidth/latency); PADÉ reduces but does not eliminate size classes; and a global passive adversary doing statistical traffic analysis is still out of scope (as for any non-mix-network transport). |
| **U**nawareness of data flows | Documented | This file. Operators must understand what does/doesn't leak. |
| **N**on-compliance | Tracked | Phase 5 (FIPS 140-3 / CC) work covers regulatory compliance. |

### 6.1 TLS-over-TCP active mimicry (the `mimicry` feature) — honest residuals

The optional `mimicry` feature ships a `MimicTlsLeg` (`bind_mimic` /
`connect_pinned_mimic`) that performs a **synthetic** TLS 1.3 handshake — a
Chrome-shaped ClientHello, a per-connection ServerHello synthesized to be
self-consistent with it, ChangeCipherSpec, opaque "encrypted" flight + lifecycle
records — then carries the Phantom session inside TLS ApplicationData records. The
handshake is **cryptographic theater**: there is no real ECDHE and no certificate;
the records are framing only (no outer AEAD). All real authentication /
confidentiality / integrity remains the inner Phantom post-quantum session. The
outer TLS is **anti-DPI obfuscation only**.

**The one-line model: it defeats parsers, not provers.** It is byte-for-byte a
plausible TLS 1.3 flow to anything that *parses* the wire, but fails deterministically
the moment something demands cryptographic *proof* of a real handshake.

**SAFE against** (with every implementation requirement met — a current ClientHello
template, the self-consistent ServerHello, per-connection-random fields, a
non-default rotated cover SNI): stateless commercial DPI; passive JA3/JA4 ClientHello
fingerprinting; light stateful protocol-conformance inspection (no active probing).

**UNSAFE / do-not-rely-on against:**

- **R1/R2 — active probing & cert-validation oracles.** A censor that runs a stock
  TLS client to completion, or relays a real ClientHello and demands a CA-chainable
  certificate for the cover SNI, fails in one round trip — the server has no real
  ECDHE and no cert. This *positively* fingerprints the endpoint as a masquerade
  (stronger than no obfuscation). The leg's black-hole posture (silent
  hold-then-drop on a bad prelude, constant timing) is the best achievable here, but
  the probe still learns TLS never completes. Closing R1/R2 needs a real-TLS tunnel
  (shadow-tls / REALITY style), which is **explicitly out of scope** for this leg.
  **Never serve a self-signed cert** (a stable, attributable blocklist artifact —
  worse than opaque theater).
- **R3 — template drift.** The Chrome ClientHello profile is a point-in-time capture
  (`PROFILE_CAPTURED`); a frozen template ages out of the live-browser population
  within ~1–2 Chrome releases and its JA3/JA4 then matches no real browser. The leg
  logs a staleness warning past ~6 months; the durable fix (auto-refresh from real
  captures, a rotating multi-browser pool) is deferred.
- **R5 — SNI ↔ destination coherence.** The cover SNI is cleartext; a popular SNI on
  a server IP outside that domain's CDN/AS, or many clients presenting one SNI to a
  server that can't complete TLS for it, is a passively-visible cluster signal. The
  operator must choose a plausible, rotated SNI consistent with the server's IP/AS —
  this is unfixable at the transport layer.
- **R7 — flow shape at scale.** The first post-prelude exchange is the large inner PQ
  handshake (a few KB up, a few KB down) where real HTTPS shows a small immediate
  request; passive flow-classification at scale can still distinguish it. The basic
  record-shaper reduces but cannot eliminate this.

**Bottom line:** the `mimicry` feature raises the bar against the *commercial /
passive / light-stateful* DPI that blocks "unknown high-entropy traffic," but it is
**not** a defense against a determined active-probing nation-state censor, and must
not be presented as one. (Invariant parity: the outer layer holds no keys and
changes no Phantom security invariant; the inner session is unchanged.)

---

## 7. Mitigation traceability

Each mitigation listed above is implemented or documented in the codebase
and the specialist docs in this directory. Cross-reference quick map:

- STRIDE-S (server identity) → Phase 1.1, 1.2, May 2026 Vuln-1 fix.
- STRIDE-T (tampering) → AEAD AAD construction in `transport::session`,
  Phase 1.4 replay window.
- STRIDE-I (info disclosure) → Phase 1.2 zeroize, Phase 1.1 constant-time.
- STRIDE-D (DoS) → Phase 1.10, 1.11, 1.14 cookie/PoW rotation + adaptive.
- LINDDUN — partially mitigated; full anonymity is out of scope.
- Connection migration (Phase 4) -> path validation (path.rs, Invariant 6), 3x
  anti-amplification (`core/src/api/udp_transport.rs`), PATH-001 strict send-gate + relaxed
  recv-delivery, and PTO-based liveness. See PROTOCOL.md §12.
---

## 8. Known limitations / future work

- **Mid-session key rotation SHIPS** (the HKDF traffic-secret ratchet; advertised on
  the wire by `PacketFlags::REKEY` + the `epoch` byte, applied via
  `decrypt_packet_accepting_rekey`; auto at `REKEY_SOFT_LIMIT = 2^32` send
  invocations or embedder-triggered; `epoch: u8` saturates at 255). Its
  forward-secrecy is **past-epoch only**: each `rekey()` zeroizes the previous
  `traffic_secret`, so a later key compromise cannot read *already-rotated* epochs.
  It provides **NO post-compromise security** — the ratchet is a deterministic
  forward HKDF (`next = HKDF-Expand(current, "phantom-rekey-v1", 32)`), so
  compromising a *live* `traffic_secret` yields every *future* epoch; healing
  (recovering confidentiality after a key leak) requires a fresh hybrid
  re-handshake, not a rekey. Cross-*session* forward secrecy is unaffected (each
  session's hybrid KEM is ephemeral, `ZeroizeOnDrop`).
- Connection migration with path validation (Phase 4) is SHIPPED (P4.0-P4.4):
  the server validates a new path (a 32-byte challenge echoed from the claimed
  address, constant-time) before switching its peer, so a MITM cannot redirect or
  hijack the session - worst case is a redirection-DoS, never decrypt
  (PROTOCOL.md §12). Header protection (T4.6, §4.6) masks the variable per-packet
  metadata, and ε (§4.2 / §4.7) made the inner session_id off-wire and the routing
  CID rotate per migration. Rotation is symmetric for migration by **either** peer
  (EPS-02 closed by A2a): a **client** migration rotates c2s (`migrate()`) and the
  server rotates s2c on the new path_id; a **server** migration rotates s2c
  (`migrate_server()`) and the client *reflects* — it bumps its path_id + rotates c2s,
  which slides the server's c2s window so the rotated CID stays routable (no stranding,
  no ping-pong). So a client move **and** a server failover are both unlinkable in both
  directions (audit 2026-06-15, EPS-02 — closed). Caveat: the CID chain is not
  forward-secret (a session-key compromise relinks a recorded flow); the payload
  stays forward-secret.
- **0-RTT early-data is one-shot under a single coherent cache; scale-out needs a
  posture (A2b).** The server `peek()`s the ticket, verifies the `resumption_binder`
  proof-of-possession, then eagerly `remove()`s it (Invariant 9), which defeats replay
  against a single server. The cache is an
  in-process bounded-LRU `HashMap` (`core/src/transport/session_cache.rs`), **not**
  replicated across nodes — so a horizontally-scaled deployment with per-node caches
  would otherwise let an attacker replay a captured 0-RTT `ClientHello` against a
  *different* node that still holds an unconsumed copy of the ticket (the classic
  TLS-1.3 0-RTT-across-a-server-farm replay). The library now provides the controls to
  close this (A2b): install a distributed `ZeroRttAntiReplay` store
  (`set_zero_rtt_anti_replay`) whose atomic `check_and_set` makes the consume first-use
  **globally** across the fleet (the store — e.g. Redis `SET NX` — is the embedder's
  infra; the transport ships the seam and fails closed on store errors), or **disable
  0-RTT early-data** (`set_early_data_enabled(false)`) so the payload is only delivered
  1-RTT (the zero-infrastructure default). Sticky/hashed routing or idempotent
  early-data also suffice — see `docs/operations/zero-rtt.md`. The post-handshake
  session's forward secrecy and authentication are unaffected regardless — only the
  at-most-once property of the early-data payload is at stake (PROTOCOL.md §6.6).
- No protection against side-channel cryptanalysis of the AEAD itself.
  Rely on ring / dalek / RustCrypto (`ml-kem`, `ml-dsa`) upstream
  constant-time properties.
- Endpoint compromise sweeps away the entire model.

---

## 9. Revision history

| Date | Reviewer | Notes |
| --- | --- | --- |
| _Initial draft_ | n/a | Captures state at the commit that introduced this file (Phase 6.1). |
| 2026-06-11 | Phase 4 | Connection migration + liveness (P4.0-P4.4): per-direction u64 packet number (WIRE 3); path validation; PATH-001a/b; 3x anti-amplification; Migrating/Dead liveness; honest "functional but linkable via stable CID" note (LINDDUN-L, PROTOCOL.md section 12). |
| 2026-06-12 | T4.6 | Header protection (QUIC RFC 9001 section 5.4; WIRE 4): the variable header fields (packet number, flags incl. PRIORITY, stream id, epoch, path id) are XOR-masked on the wire, leaving only version + session_id cleartext (PROTOCOL.md section 4.6). LINDDUN-L narrowed from "all metadata plaintext" to "linkable via the stable cleartext CID only"; CID rotation (the remaining piece) deferred. Also T4.1: packet extensions folded into the AEAD AAD; T4.2 X-Wing KEM combiner; T4.3/T4.4 ServerHello shrink + discriminant byte; T4.5 reliable-offset fail-closed. |
| 2026-06-13 | ε (WIRE 5) | CID-collapse: the inner 32-byte session_id left the data-plane wire (off-wire in the AEAD AAD; header 47→15 B — PROTOCOL.md section 4.2), and the single routing ConnId now rotates per migration via a per-direction KDF chain + sliding demux window (section 4.7). Honest caveat: the CID chain is session-stable and not forward-secret (a session-key compromise relinks a recorded flow); the payload stays forward-secret. |
| 2026-06-15 | ε audit | Security review of the ε surface (`docs/security/audit-report-2026-06-15-wire-v5-epsilon.md`): no confidentiality/integrity/auth regression; CID-chain, off-wire AAD bind, and post-AEAD window-slide verified sound. **Corrected the LINDDUN-L over-claim:** ε rotation is asymmetric — only the migrating peer rotates its outbound CID, so the **server→client** ConnId stays stable across a **client** migration (EPS-02, linkable to a both-networks observer); and migration tolerates at most K=4 un-acked in-flight generations before stranding (EPS-01, availability). |
| 2026-06-15 | EPS-02 fix | Symmetric CID rotation for a **client** migration: the server now rotates its s2c chain on authenticating the client's new path_id (post-AEAD), so a client move is unlinkable in **both** directions (the socket-routed client absorbs the new inbound CID; no ping-pong — the server does not bump its own path_id). LINDDUN-L is now **closed for client migration**; the residual is a *server*-initiated migration (c2s stays stable — the client does not rotate-on-detect, which would strand it in the server's un-sliding c2s window). EPS-01 (the >K-generation strand) remains tracked. |
| 2026-06-15 | EPS-01 fix | Robust migration window: the inbound CID demux slide is now **multi-step** (advances by the authenticated path_id forward delta, recentring on the sender's actual migration index — no cumulative lag) and the leading window **K is widened 4 → 16**, so only an unbroken run of > 16 consecutive fully-lost migrations strands the c2s data plane (recoverable by reconnect). `MAX_ROUTES` raised 1<<16 → 1<<18 to preserve concurrent-session capacity. Availability only; no security-invariant change. |
| 2026-06-15 | T5.2 doc-honesty | Rewrote §8 + the A4 asset row to reflect shipped reality: mid-session HKDF rekey **ships** (was "blocked on V2 wire format"). Stated its forward-secrecy honestly — **past-epoch FS only, NO post-compromise security** (the deterministic forward ratchet means a live `traffic_secret` yields all future epochs; healing needs a re-handshake). No code change. |
| 2026-06-15 | T5.7 doc-honesty | Documented the **0-RTT distributed-cache replay caveat**: the one-shot anti-replay (Invariant 9) holds only under a single coherent `SessionCache` (an in-process LRU, not replicated), so a horizontally-scaled deployment with per-node caches lets an attacker replay a captured 0-RTT `ClientHello` against a different node — added STRIDE-S rows + a §8 limitation; deployment-side mitigations only. Also PROTOCOL.md §6.6. No code change. |
| 2026-06-17 | A2b 0-RTT anti-replay controls | Turned the documented 0-RTT scale-out replay residual into a mitigable item. Added a pluggable `ZeroRttAntiReplay` trait (`HandshakeServer::set_zero_rtt_anti_replay`, exposed on both listeners) so a horizontally-scaled deployment can make the one-shot ticket consume atomic across nodes via a shared store (Redis `SET NX`, a conditional put — the embedder's infra; the transport ships the seam, default single-node), and a `set_early_data_enabled(false)` switch to disable 0-RTT early-data entirely (the zero-infrastructure default — early-data is rejected and resent 1-RTT). Loud deploy guide at `docs/operations/zero-rtt.md`. The single-node guarantee (Invariant 9) is unchanged. No wire change. |
| 2026-06-17 | A2a server migration (EPS-02 closed) | Made server-initiated migration a real, symmetric, unlinkable feature. The UDP client socket became unconnected (so it can hear a server that moves to a new address); the server gained `migrate_server(local_addr)` (Rust-only) that rebinds its send socket + rotates s2c in lock-step; the client now follows a migrated server (commits the new source post-AEAD/M-1, path-validates under the 3× anti-amp cap, switches its c2s target on a valid echo) and **reflects** the CID rotation (bumps its path_id + rotates c2s), which slides the server's c2s window so it stays routable (no stranding) with no ping-pong (the server's s2c re-rotation is path_id-silent). **LINDDUN-L / EPS-02 is now closed for migration by *either* peer** — a client move and a server failover are both unlinkable in both directions. No wire change (behavioural extension on v6). The not-forward-secret CID-chain caveat is unchanged. |
| 2026-06-16 | v6 anti-fingerprint (WIRE 6) | Removed the two structural data-plane fingerprints and added opt-in traffic shaping. **(a)** the `version` byte is now HP-masked (the whole 15-byte header is masked — no constant cleartext byte); **(b)** the cleartext `payload_len` / `ext_len` prefixes are dropped (`payload` is the message remainder; `extensions` off the wire) — PROTOCOL.md §4.1/§4.6. **Opt-in (off by default):** **(c)** PADÉ size padding (bounded ≈ ≤12% overhead, inside the AEAD), **(d)** uniform `[0, jitter_ms]` send-timing jitter, **(e)** `COVER` cover traffic (authenticated dummy packets, dropped by the peer) — PROTOCOL.md §4.8, via `TrafficShapingConfig`. Narrows LINDDUN-D ("No mitigation" → opt-in size/timing/volume controls) and the DPI-fingerprinting row (structural tells gone). **Honest residuals:** shaping is off by default; PADÉ reduces but doesn't eliminate size classes; the datagram *shape* + global statistical traffic analysis remain out of scope; full active protocol-mimicry is a separate future transport mode. |
| 2026-08-15 | Receive-side memory amplification | Added STRIDE-D §D.1: the class was absent, which is how two changes widening receive-side buffers reached review before being rejected on grounds this document did not state. Records the mechanism (advertised window × reorder buffer × streams × sessions) and the bound at each link. Also re-keyed §5's code pointers from line numbers to enclosing items: five had drifted into unrelated code, including the Invariant-2 `ENCRYPTED` gate, which pointed into `flush_deferred_sends`. |
| 2026-08-16 | §D.1 rewritten around what is enforced | The section published a single per-session resident total. It was wrong three times, each time because a figure this endpoint chooses was read as a bound on what the peer can do — most recently by charging a delivery-queue slot the *sender's* chunk size while the receive path would accept a frame three thousand times larger. Two changes: the receive path now **enforces** an inbound frame ceiling (`MAX_RECV_FRAME`, dropped pre-AEAD, so an oversized frame cannot reach a queue slot at all), which is what makes the queue depths mean anything in bytes; and the total is **withdrawn**. §D.1 now lists each bound with the code that enforces it and marks the two that are not enforced — the advertised window, which nothing on the receive path consults, and the delivery cap, which is crossed by one frame's charge before it is noticed (`MAX_DELIVERY_CHARGE_PER_FRAME`, published rather than designed away). A total is not restated because it would have to enumerate the buffers under this layer too — the byte pipe's accumulator, PhantomUDP's fragment reassembler, the per-stream structures — and each previous attempt was corrected upward by a term it had omitted. The reference server's `--max-recv-memory-mib` is removed for the same reason: it divided an operator's budget by that figure. |
| 2026-08-22 | §D.1: the process multiplier, and the ack-driven term | The section bounded a session and stopped there, so the arithmetic a reader needs — session cap × per-session bound — was never written down, and the one row that is a single enforced constant (`SESSION_RECV_WINDOW_GROWTH_BUDGET`) now carries it: 1024 × 8 MiB = 8 GiB at the reference server's default. Two additions beyond that. A **fifth term** joins the table: the bandwidth and round-trip sliding filters, whose deques had no cap and whose length was the peer's acknowledgement cadence — bounded now by a minimum time separation between retained entries, with the count-based cap that was tried recorded as wrong (evicting the least entry of a maximum filter drops the head's successors, so the reading collapses to a stale value the moment the head expires, and it sets the congestion window). It is a small term in bytes, listed because its input is acknowledgements rather than data and none of the reasoning about the other four rows would have reached it. And the process-wide second tier is rejected **on the record**: it trades a host sized too small — visible, fixable — for one peer's growth decisions pinning another peer's window at 64 KiB, with no signal separating that from a slow path. `phantom-server` gains `--max-recv-window-growth-mib`, which divides a stated ceiling by the enforced allowance rather than by a withdrawn total, and is documented as a floor on the host's requirement rather than a ceiling on its footprint. §5's code pointers were re-checked against the tree; all resolve, the Invariant-2 `ENCRYPTED` gate included (`api/session.rs::handle_packet`, the `ENCRYPTED` branch and the `else` arm). |
