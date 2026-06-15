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
| A4 | Session AEAD keys | `CryptoState.session_key`, ring `LessSafeKey` inside `CryptoSessionInner` | Compromise leaks all packets in that session direction. Mitigated by `ZeroizeOnDrop` (Phase 1.2) and (future) mid-session rekey (Phase 1.5, V2). |
| A5 | Application plaintext | passed in/out via `Vec<u8>` / `Bytes` | The whole point of the transport. |
| A6 | Session identity / linkability metadata | the inner 32-byte session_id is **off-wire** (ε §4.2, in the AEAD AAD only); stream id, packet numbers, flags, epoch, path id (**HP-masked** — T4.6 §4.6); the single routing 8-byte `ConnId` is the only per-connection cleartext and it **rotates per migration** (ε §4.7) | **Partially closed by ε** (LINDDUN-L, PROTOCOL.md §12.5): the **client→server (c2s)** ConnId rotates per migration, so that direction is unlinkable. **Residual (audit 2026-06-15, EPS-02):** the **server→client (s2c)** ConnId does **not** yet rotate on a client-initiated migration (only the migrating peer rotates its own outbound chain), so an observer seeing both networks can still link the s2c flow across the move — symmetric-rotation remediation in progress (`docs/security/audit-report-2026-06-15-wire-v5-epsilon.md`). Caveat: the CID chain is not forward-secret (a session-key compromise relinks a recorded flow). Full anti-fingerprinting (constant version byte / length padding) is a separate future pass. |
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
| Memory disclosure of keys after session close | `ZeroizeOnDrop` on every key-bearing struct | `core/src/transport/session.rs:75` (`CryptoState`), `core/src/transport/handshake.rs:253` (`HandshakeServer`), `core/src/transport/handshake.rs:686` (`HandshakeClient`) |
| Timing leak on cookie comparison | `subtle::ConstantTimeEq::ct_eq` â never branches on cookie content | `core/src/transport/handshake.rs:1065` |
| DPI fingerprinting | None today — planned: FakeTLS-style HTTP traffic mimicry (removed in Phase 0, returns as a dedicated transport mode) | — |

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
| **L**inkability of one session across a network change (migration) | **Partially mitigated (ε) — c2s unlinkable, s2c residual** | Header protection (T4.6, §4.6) masks the variable per-packet metadata (packet numbers, flags incl. PRIORITY, stream id, epoch, path id), and ε removed the inner 32-byte `session_id` from the wire (off-wire in the AEAD AAD — §4.2) and makes the routing `ConnId` **rotate** per migration via per-direction KDF chains + a sliding demux window (§4.7). The migrating peer rotates **its own outbound** chain, so a **client** migration makes the **client→server (c2s)** flow unlinkable. **Residual (audit 2026-06-15, EPS-02):** the **server→client (s2c)** ConnId does **not** yet rotate when the client migrates (the server only *detects* the migration and slides its inbound window; it never advances its own outbound index), so an on-path / colluding observer seeing both networks can still link the s2c flow by the stable `CID_s2c(0)`. Symmetric-rotation remediation (drive both directions' CID + the inbound window from one authenticated migration epoch) is in progress — see `docs/security/audit-report-2026-06-15-wire-v5-epsilon.md`. **Honest caveat:** the CID chain is session-stable and **not** forward-secret — a session-key compromise lets an attacker recompute the chain and relink a *recorded* flow; the payload stays forward-secret. The constant `version` byte is a protocol (not per-connection) fingerprint — full anti-fingerprinting is a separate future pass. See `PROTOCOL.md` §4.2 / §4.7 / §12.5. |
| **I**dentifiability of the client | No mitigation | Source IP is necessarily visible to the server. Client may use Tor / VPN externally. |
| **N**on-repudiation | Intentionally out of scope (see STRIDE-R) |
| **D**etectability that this is `phantom_protocol` | Planned (HTTP-mimicry mode) | FakeTLS leg removed in Phase 0; HTTP traffic mimicry will return as a dedicated transport mode. |
| **D**isclosure of metadata (sizes, timing) | No mitigation | Traffic analysis defeats Phantom Protocol as it would defeat any non-padded protocol. Future work could add cover traffic. |
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

- Mid-session key rotation (Phase 1.5) is blocked on V2 wire format.
  Sessions today rely solely on the initial handshake's KEM secret for
  the entire session lifetime. Acceptable because AEAD safety limits are
  far above any practical session volume, but adds forward-secrecy
  surface area that a future leak would expose.
- Connection migration with path validation (Phase 4) is SHIPPED (P4.0-P4.4):
  the server validates a new path (a 32-byte challenge echoed from the claimed
  address, constant-time) before switching its peer, so a MITM cannot redirect or
  hijack the session - worst case is a redirection-DoS, never decrypt
  (PROTOCOL.md §12). Header protection (T4.6, §4.6) masks the variable per-packet
  metadata, and ε (§4.2 / §4.7) made the inner session_id off-wire and the routing
  CID rotate per migration. The migrating peer rotates its own outbound CID, so a
  client migration unlinks the **client→server** flow; the **server→client** CID
  does **not** yet rotate on a client migration, so that direction stays linkable
  to a both-networks observer (audit 2026-06-15, EPS-02 — symmetric-rotation
  remediation in progress; LINDDUN-L partially, not fully, closed). Caveat: the CID
  chain is not forward-secret (a session-key compromise relinks a recorded flow);
  the payload stays forward-secret.
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
| 2026-06-15 | ε audit | Adversarial review of the ε surface (`docs/security/audit-report-2026-06-15-wire-v5-epsilon.md`): no confidentiality/integrity/auth regression; CID-chain, off-wire AAD bind, and post-AEAD window-slide verified sound. **Corrected the LINDDUN-L over-claim:** ε rotation is asymmetric — only the migrating peer rotates its outbound CID, so the **server→client** ConnId stays stable across a **client** migration (EPS-02, linkable to a both-networks observer); and migration tolerates at most K=4 un-acked in-flight generations before stranding (EPS-01, availability). Both are scheduled for a symmetric-migration-epoch fix that will re-close LINDDUN-L. |
