# Phantom Protocol Threat Model

Methodology: STRIDE for security, LINDDUN for privacy. Audit-friendly format â
each finding maps to a concrete mitigation with file:line traceability.

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
   margins. Kyber768 and Dilithium3 are taken at NIST PQC Round-3 strength
   pending the migration to ML-KEM / ML-DSA (Phase 5).
3. Both peers know the server's `HybridVerifyingKey` out of band (TOFU,
   PKI, or app distribution). The library does NOT solve key distribution.
4. Time is approximately monotonic on each peer; the cookie freshness
   buckets (Phase 1.10) tolerate Â±5 minutes of clock skew naturally.
5. Memory is not extractable from a running process by external means.
   `ZeroizeOnDrop` (Phase 1.2) protects against post-process forensic
   recovery, NOT against live introspection.

---

## 2. Trust boundaries

```
       ââââââââââââââââââââââââââââââââ                ââââââââââââââââââââââââââââââââ
       â  Client process              â                â  Server process              â
       â ââââââââââââââââââââââââââââ â                â ââââââââââââââââââââââââââââ â
       â â Application code (caller)â â                â â Application code (caller)â â
       â ââââââââââââ¬ââââââââââââââââ â                â ââââââââââââ¬ââââââââââââââââ â
       â            â¼                 â                â            â¼                 â
       â ââââââââââââââââââââââââââ   â                â   ââââââââââââââââââââââââââ â
       â â phantom_protocol API       â   â                â   â phantom_protocol API       â â
       â â (PhantomSession,       â   â                â   â (PhantomListener,      â â
       â â  PhantomStream, ...)   â   â                â   â  PhantomSession, ...)  â â
       â âââââââââââ¤âââââââââââââââ   â                â   âââââââââââ¤âââââââââââââââ â
       â           â FFI boundary     â                â             â FFI boundary   â
       â           â¼                  â                â             â¼                â
       â ââââââââââââââââââââââââââ   â                â   ââââââââââââââââââââââââââ â
       â â transport / crypto     â   â                â   â transport / crypto     â â
       â âââââââââââ¤âââââââââââââââ   â                â   âââââââââââ¤âââââââââââââââ â
       â           â¼                  â                â             â¼                â
       ââââââââââââââââââââââââââââââââ                ââââââââââââââââââââââââââââââââ
                   â                                                 â
                   â   ââââââââââº   active adversary   ââââââ         â
                   â     ââââââââº   passive observer   ââââ           â
                   ââââââââââââââââââº hostile network âââââââââââââââââ
```

The double-line boxes inside each process (`phantom_protocol API` and
`transport / crypto`) are this library's responsibility. Everything outside
is the caller's.

The **strongest** boundary in the diagram is the network â every byte that
crosses it is subject to active mutation. The FFI boundary inside each
process is a weaker boundary (we trust the caller and the OS).

---

## 3. Assets

| # | Asset | Where | Loss impact |
| --- | --- | --- | --- |
| A1 | Server long-lived `HybridSigningKey` | `HandshakeServer.signing_key` | Catastrophic â attackers can impersonate the server for all future handshakes; no forward secrecy mitigates retroactive reads. |
| A2 | Server master secret (cookie / PoW HMAC key root) | `HandshakeServer.master_secret` | Attacker can forge cookies, bypass PoW, mount IP-spoofing amplification. Hourly HKDF rotation (Phase 1.11) bounds compromise window. |
| A3 | Hybrid KEM private keys (ephemeral, per-handshake) | `HandshakeClient.kem_secret` | Compromise of one session's KEM key leaks that session's symmetric keys â all traffic from that session decryptable. Mitigated by ephemeral generation per handshake + `ZeroizeOnDrop`. |
| A4 | Session AEAD keys | `CryptoState.session_key`, ring `LessSafeKey` inside `CryptoSessionInner` | Compromise leaks the **current epoch's** packets in that direction. Mitigated by `ZeroizeOnDrop` (Phase 1.2) and the **shipped** mid-session HKDF rekey — **past-epoch forward secrecy only, no post-compromise security** (a live `traffic_secret` yields all future epochs; healing needs a re-handshake — see §8). |
| A5 | Application plaintext | passed in/out via `Vec<u8>` / `Bytes` | The whole point of the transport. |
| A6 | Session identity / linkability metadata | the inner 32-byte session_id is **off-wire** (ε §4.2, in the AEAD AAD only); stream id, packet numbers, flags, epoch, path id (**HP-masked** — T4.6 §4.6); the single routing 8-byte `ConnId` is the only per-connection cleartext and it **rotates per migration** (ε §4.7) | **Closed by ε + A2a for migration by *either* peer** (LINDDUN-L, PROTOCOL.md §12.5; EPS-02 closed): a migration rotates **both** directions' ConnId regardless of which peer moves. A *client* move rotates c2s (`migrate()`) and the server rotates s2c on the new `path_id`; a *server* move rotates s2c (`migrate_server()`) and the client *reflects* — it bumps its `path_id` + rotates c2s, which slides the server's c2s window so the rotated CID stays routable (no stranding) and there is no ping-pong (the server's matching s2c re-rotation is `path_id`-silent). So a client moving Wi-Fi→cellular **and** a server failover/egress-change are both unlinkable in both directions. Caveat: the CID chain is not forward-secret (a session-key compromise relinks a recorded flow). **WIRE v6 (direction #4) shipped the remaining wire-diet anti-fingerprinting:** the constant `version` byte is now HP-masked and the cleartext length prefixes are dropped (PROTOCOL.md §4.1/§4.6), and opt-in PADÉ size padding / timing jitter / cover traffic are available (§4.8, off by default — see the LINDDUN-D row). |
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
| Long-lived signing-key theft | **No** (post-compromise) | Phantom Protocol relies on the server signing key for authentication â once leaked, attacker can serve as the server. Key revocation is an out-of-band concern (PKI / OOB re-pinning). |

---

## 5. STRIDE analysis

### S â Spoofing identity

| Threat | Mitigation | Code |
| --- | --- | --- |
| Adversary presents a fake server key in `ServerHello` | Client pins `expected_server_key`; mismatch â `HandshakeError::ServerIdentityMismatch` | `core/src/transport/handshake.rs:283-286` |
| Adversary forges a `ClientHello` to spoof an IP | Cookie + adaptive PoW; cookie is HMAC(rotating-secret, ip, bucket) so forgery requires the secret | `core/src/transport/handshake.rs:402-475` |
| Replay of an old, captured `ServerHello` to a fresh client | Transcript signature binds `client_hello.nonce` and `session_id_bytes`; replay fails signature check | `core/src/transport/handshake.rs:201-204, 320-326` |
| Connection-migration hijack: a known (plaintext) `session_id`/CID replayed from a spoofed source to steal the session | Path validation — a fresh unguessable 32-byte challenge must be echoed *from* the claimed address (only the session-key holder can), constant-time verified, before the server switches its peer; pinned-key AEAD blocks read/inject. Worst achievable is a **redirection-DoS**, **never** hijack/decrypt (the QUIC §9 boundary) | `core/src/transport/path.rs`, `core/src/api/session.rs`, `PROTOCOL.md` §12 |
| 0-RTT early-data replay against a **single** server | `SessionCache::try_resume` removes the resumption ticket on first lookup (Invariant 9), so a replayed `ClientHello` finds no ticket and the server falls back to a 1-RTT handshake that ignores the early-data | `core/src/transport/session_cache.rs::try_resume`, `PROTOCOL.md` §6.6 |
| 0-RTT early-data replay against a **different node** (horizontal scale-out) | **Residual — not fully mitigated by the library.** The one-shot guarantee holds only under a *single coherent* `SessionCache`; it is an in-process LRU, not replicated. A horizontally-scaled deployment with per-node caches lets an attacker replay a captured 0-RTT `ClientHello` against a node that still holds an unconsumed copy of the same ticket, accepting the early-data a second time (the classic TLS-1.3 0-RTT-across-a-server-farm replay). Deployment-side mitigations: sticky/hashed routing of a `resume_session_id` to one node, a shared store with atomic compare-and-remove on resume, or keeping early-data idempotent. The post-handshake session's PFS + auth are unaffected — only the at-most-once property of the early-data payload degrades. | `core/src/transport/session_cache.rs` (in-process LRU), `PROTOCOL.md` §6.6 |

### T â Tampering with data

| Threat | Mitigation | Code |
| --- | --- | --- |
| Bit-flip in ciphertext | AEAD tag check fails â packet dropped | `core/src/crypto/adaptive_crypto.rs:255-260` |
| Mutation of header on the wire | Header is serialized via `PacketHeader::to_wire` (47-byte big-endian image) and used as AEAD AAD; any mutation invalidates the tag | `core/src/transport/session.rs` |
| Tampering with handshake messages | Transcript signature covers every field of `ClientHello`/`ServerHello` | `core/src/transport/handshake.rs:201-204, 320-326` |
| Packet-number mutation (replay or skip) | After AEAD verify, `Session::decrypt_packet` consults a single per-direction `ReplayWindow` (keyed on the `u64` packet number) and rejects duplicates / out-of-window-old | `core/src/transport/session.rs`, `core/src/security/replay_window.rs` |

### R â Repudiation

Not in scope. The protocol does not provide non-repudiation: there is no
externally-verifiable proof of which peer sent which message. Adding
non-repudiation would require persistent per-message signing â out of scope
for a real-time secure transport.

### I â Information disclosure

| Threat | Mitigation | Code |
| --- | --- | --- |
| Plaintext leak on the wire | AEAD encryption (post-handshake invariant `PacketFlags::ENCRYPTED`); unencrypted post-handshake packets dropped | `core/src/api/session.rs:1415-1422` |
| Plaintext leak via error message | Error variants carry only the error class, not the payload; no `format!("{:?}", plaintext)` anywhere | grep `format!.*plaintext\|payload` in `core/src/` â 0 results |
| Memory disclosure of keys after session close | Key-bearing structs zeroize on drop: `ZeroizeOnDrop` on `CryptoState` (`session.rs`), `HandshakeServer` / `HandshakeClient` (`handshake.rs`), and `ResumptionTicket` (`session_cache.rs`, T5.1); the rekey master `Session.traffic_secret` is zeroized in `Session::drop` (T5.1) along with `resumption_secret`; the transient handshake KEM secret is held in `Zeroizing` (T5.1). Mid-session rekey also zeroizes each superseded epoch secret. | `session.rs` (`CryptoState`, `Session::drop`), `handshake.rs` (`HandshakeServer`/`HandshakeClient` + `Zeroizing` KEM secret), `session_cache.rs` (`ResumptionTicket`) |
| Timing leak on cookie comparison | `subtle::ConstantTimeEq::ct_eq` â never branches on cookie content | `core/src/transport/handshake.rs:1065` |
| DPI fingerprinting | **Partial (WIRE v6, direction #4):** the data-plane wire has **no constant cleartext byte** (the version byte is HP-masked) and **no cleartext length-prefix pattern** (dropped — §4.1/§4.6), removing the two structural tells a stateless DPI box keyed on; opt-in size padding / timing jitter / cover traffic (§4.8) blunt the statistical tells. **Residual:** the outer 8-byte `ConnId` + opaque-blob datagram *shape* is still recognizable; full active protocol-mimicry (looking like HTTP/TLS) is a separate future transport mode (FakeTLS leg removed in Phase 0). | PROTOCOL.md §4.1 / §4.6 / §4.8 |

### D â Denial of service

| Threat | Mitigation | Code |
| --- | --- | --- |
| Handshake flood / IP spoof amplification | Stateless cookie (HMAC over rotating secret + IP + bucket) forces attacker to receive a packet at the spoofed IP before consuming server resources | `core/src/transport/handshake.rs::generate_cookie`, `validate_cookie` |
| CPU-exhaustion via cheap handshake attempts | Adaptive PoW difficulty tiers from 0 â 16 (~64k hash evals) based on per-minute load | `core/src/transport/handshake.rs::adaptive_difficulty` (Phase 1.14) |
| Panic-on-malformed input | `#![warn(clippy::unwrap_used, expect_used, panic, unreachable, todo, unimplemented)]`; no `.unwrap()` on the recv/handshake hot path; fuzz harnesses in `fuzz/` | Phase 1.3, 6.4 |
| AEAD nonce exhaustion (theoretical) | Hard ceiling `AEAD_MAX_INVOCATIONS = 1 << 48` â `CryptoError::NonceExhausted` | `core/src/crypto/adaptive_crypto.rs:24-44` |
| Replay-window memory amplification | One per-direction `ReplayWindow` (~144 bytes) per session — no per-stream growth | `core/src/security/replay_window.rs` |
| Connection-migration amplification: known CID + spoofed source used as a reflector toward a victim | To an unvalidated address the server is **challenge-only** and caps bytes sent to **≤ 3× bytes received** (RFC 9000 §8.2); a spoofed address never echoes the challenge so it is never switched-to | `core/src/api/udp_transport.rs` (anti-amp budget), `PROTOCOL.md` §12.3 |

### E â Elevation of privilege

Out of scope â `phantom_protocol` does not run with elevated privileges or
expose any privileged operation. The library is a passive data conduit.

---

## 6. LINDDUN privacy analysis

| Threat | Status | Note |
| --- | --- | --- |
| **L**inkability of two sessions to the same client | Partial | Same `HybridVerifyingKey` on the client side correlates handshakes (the client signing key is reused). Anonymous mode would require ephemeral client signing keys; tracked as future work. |
| **L**inkability of one session across a network change (migration) | **Mitigated (ε + A2a) — migration by *either* peer is unlinkable both ways (EPS-02 closed)** | Header protection (T4.6, §4.6) masks the variable per-packet metadata (packet numbers, flags incl. PRIORITY, stream id, epoch, path id), and ε removed the inner 32-byte `session_id` from the wire (off-wire in the AEAD AAD — §4.2) and makes the routing `ConnId` **rotate** per migration via per-direction KDF chains + a sliding demux window (§4.7). Rotation is symmetric for **both** migration directions: the moving peer advances its outbound chain and the other peer advances its return chain in response. A **client** migration: the client advances c2s on `migrate()`, the server advances s2c on the new `path_id` (the socket-routed client absorbs the new inbound CID, no slide, no ping-pong). A **server** migration: the server advances s2c on `migrate_server()`, and the client *reflects* on authenticating the server's new `path_id` — it bumps its own `path_id` + advances c2s, which slides the server's c2s demux window so the rotated CID stays routable (the no-stranding fix that the earlier asymmetry avoided by not rotating c2s); the server's matching s2c re-rotation is `path_id`-silent, so the client does not re-reflect (one round). So a client moving Wi-Fi→cellular **and** a server failover/egress-change are both unlinkable in both directions (EPS-02 closed by A2a — `docs/security/audit-report-2026-06-15-wire-v5-epsilon.md`). **Honest caveat:** the CID chain is session-stable and **not** forward-secret — a session-key compromise lets an attacker recompute the chain and relink a *recorded* flow; the payload stays forward-secret. The constant `version` byte (a protocol, not per-connection, fingerprint) is now **HP-masked** as of WIRE v6 (direction #4), along with the cleartext length prefixes; opt-in size/timing/volume shaping is available (§4.8 — off by default, see the LINDDUN-D row). See `PROTOCOL.md` §4.1 / §4.2 / §4.6 / §4.7 / §4.8 / §12.5. |
| **I**dentifiability of the client | No mitigation | Source IP is necessarily visible to the server. Client may use Tor / VPN externally. |
| **N**on-repudiation | Intentionally out of scope (see STRIDE-R) |
| **D**etectability that this is `phantom_protocol` | **Partially mitigated (WIRE v6) — active mimicry still planned** | WIRE v6 removed the structural tells (no constant cleartext version byte, no length-prefix pattern — §4.1/§4.6), and opt-in shaping (§4.8) blunts size/timing/volume tells. The datagram *shape* (8-byte `ConnId` + opaque blob) is still recognizable; full active protocol-mimicry (looking like HTTP/TLS) will return as a dedicated transport mode (FakeTLS leg removed in Phase 0). |
| **D**isclosure of metadata (sizes, timing) | **Opt-in mitigations (WIRE v6, direction #4) — OFF by default** | The data-plane wire no longer carries a structural size fingerprint: WIRE v6 dropped the cleartext `payload_len` / `ext_len` prefixes (PROTOCOL.md §4.1). On top of that, three **opt-in** anti-fingerprint controls are available via `TrafficShapingConfig` (PROTOCOL.md §4.8): **(c) PADÉ size padding** — pads each packet to a bounded (≈ ≤12% worst-case) size bucket inside the AEAD, so the datagram size no longer tracks the payload size; **(d) timing jitter** — a uniform `[0, jitter_ms]` ms per-packet send delay, so inter-packet timing no longer tracks app writes; **(e) cover traffic** — an `ENCRYPTED \| COVER` dummy packet maintains a floor outbound rate, so silence/volume no longer leak (authenticated, then dropped by the peer). **Honest residual:** all three are **off by default** (an embedder must enable them, trading bandwidth/latency); PADÉ reduces but does not eliminate size classes; and a global passive adversary doing statistical traffic analysis is still out of scope (as for any non-mix-network transport). |
| **U**nawareness of data flows | Documented | This file. Operators must understand what does/doesn't leak. |
| **N**on-compliance | Tracked | Phase 5 (FIPS 140-3 / CC) work covers regulatory compliance. |

---

## 7. Mitigation traceability

Each mitigation listed above is implemented or documented in the codebase
and the specialist docs in this directory. Cross-reference quick map:

- STRIDE-S (server identity) â Phase 1.1, 1.2, May 2026 Vuln-1 fix.
- STRIDE-T (tampering) â AEAD AAD construction in `transport::session`,
  Phase 1.4 replay window.
- STRIDE-I (info disclosure) â Phase 1.2 zeroize, Phase 1.1 constant-time.
- STRIDE-D (DoS) â Phase 1.10, 1.11, 1.14 cookie/PoW rotation + adaptive.
- LINDDUN â partially mitigated; full anonymity is out of scope.
- Connection migration (Phase 4) -> path validation (path.rs, Invariant 6), 3x
  anti-amplification (udp_transport.rs), PATH-001 strict send-gate + relaxed
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
- **0-RTT early-data is one-shot only under a single coherent cache.**
  `SessionCache::try_resume` removes the resumption ticket on first lookup
  (Invariant 9), which defeats replay against a single server. The cache is an
  in-process bounded-LRU `HashMap` (`core/src/transport/session_cache.rs`), **not**
  replicated across nodes — so a horizontally-scaled deployment with per-node
  caches has a residual: an attacker who captures a 0-RTT `ClientHello` can replay
  it against a *different* node that still holds an unconsumed copy of the same
  ticket, re-running the early-data once more (the classic TLS-1.3
  0-RTT-across-a-server-farm replay). Mitigation is deployment-side and not
  enforced by the library: route a `resume_session_id` consistently to one node
  (sticky/hashed LB), back the cache with a single shared store doing an atomic
  compare-and-remove on resume, or keep early-data strictly idempotent. The
  post-handshake session's forward secrecy and authentication are unaffected — only
  the at-most-once property of the early-data payload degrades (PROTOCOL.md §6.6).
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
| 2026-06-15 | ε audit | Adversarial review of the ε surface (`docs/security/audit-report-2026-06-15-wire-v5-epsilon.md`): no confidentiality/integrity/auth regression; CID-chain, off-wire AAD bind, and post-AEAD window-slide verified sound. **Corrected the LINDDUN-L over-claim:** ε rotation is asymmetric — only the migrating peer rotates its outbound CID, so the **server→client** ConnId stays stable across a **client** migration (EPS-02, linkable to a both-networks observer); and migration tolerates at most K=4 un-acked in-flight generations before stranding (EPS-01, availability). |
| 2026-06-15 | EPS-02 fix | Symmetric CID rotation for a **client** migration: the server now rotates its s2c chain on authenticating the client's new path_id (post-AEAD), so a client move is unlinkable in **both** directions (the socket-routed client absorbs the new inbound CID; no ping-pong — the server does not bump its own path_id). LINDDUN-L is now **closed for client migration**; the residual is a *server*-initiated migration (c2s stays stable — the client does not rotate-on-detect, which would strand it in the server's un-sliding c2s window). EPS-01 (the >K-generation strand) remains tracked. |
| 2026-06-15 | EPS-01 fix | Robust migration window: the inbound CID demux slide is now **multi-step** (advances by the authenticated path_id forward delta, recentring on the sender's actual migration index — no cumulative lag) and the leading window **K is widened 4 → 16**, so only an unbroken run of > 16 consecutive fully-lost migrations strands the c2s data plane (recoverable by reconnect). `MAX_ROUTES` raised 1<<16 → 1<<18 to preserve concurrent-session capacity. Availability only; no security-invariant change. |
| 2026-06-15 | T5.2 doc-honesty | Rewrote §8 + the A4 asset row to reflect shipped reality: mid-session HKDF rekey **ships** (was "blocked on V2 wire format"). Stated its forward-secrecy honestly — **past-epoch FS only, NO post-compromise security** (the deterministic forward ratchet means a live `traffic_secret` yields all future epochs; healing needs a re-handshake). No code change. |
| 2026-06-15 | T5.7 doc-honesty | Documented the **0-RTT distributed-cache replay caveat**: the one-shot anti-replay (Invariant 9) holds only under a single coherent `SessionCache` (an in-process LRU, not replicated), so a horizontally-scaled deployment with per-node caches lets an attacker replay a captured 0-RTT `ClientHello` against a different node — added STRIDE-S rows + a §8 limitation; deployment-side mitigations only. Also PROTOCOL.md §6.6. No code change. |
| 2026-06-17 | A2a server migration (EPS-02 closed) | Made server-initiated migration a real, symmetric, unlinkable feature. The UDP client socket became unconnected (so it can hear a server that moves to a new address); the server gained `migrate_server(local_addr)` (Rust-only) that rebinds its send socket + rotates s2c in lock-step; the client now follows a migrated server (commits the new source post-AEAD/M-1, path-validates under the 3× anti-amp cap, switches its c2s target on a valid echo) and **reflects** the CID rotation (bumps its path_id + rotates c2s), which slides the server's c2s window so it stays routable (no stranding) with no ping-pong (the server's s2c re-rotation is path_id-silent). **LINDDUN-L / EPS-02 is now closed for migration by *either* peer** — a client move and a server failover are both unlinkable in both directions. No wire change (behavioural extension on v6). The not-forward-secret CID-chain caveat is unchanged. |
| 2026-06-16 | v6 anti-fingerprint (WIRE 6, direction #4) | Removed the two structural data-plane fingerprints and added opt-in traffic shaping. **(a)** the `version` byte is now HP-masked (the whole 15-byte header is masked — no constant cleartext byte); **(b)** the cleartext `payload_len` / `ext_len` prefixes are dropped (`payload` is the message remainder; `extensions` off the wire) — PROTOCOL.md §4.1/§4.6. **Opt-in (off by default):** **(c)** PADÉ size padding (bounded ≈ ≤12% overhead, inside the AEAD), **(d)** uniform `[0, jitter_ms]` send-timing jitter, **(e)** `COVER` cover traffic (authenticated dummy packets, dropped by the peer) — PROTOCOL.md §4.8, via `TrafficShapingConfig`. Narrows LINDDUN-D ("No mitigation" → opt-in size/timing/volume controls) and the DPI-fingerprinting row (structural tells gone). **Honest residuals:** shaping is off by default; PADÉ reduces but doesn't eliminate size classes; the datagram *shape* + global statistical traffic analysis remain out of scope; full active protocol-mimicry is a separate future transport mode. |
