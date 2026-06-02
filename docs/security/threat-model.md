# Phantom Core Threat Model

Methodology: STRIDE for security, LINDDUN for privacy. Audit-friendly format —
each finding maps to a concrete mitigation with file:line traceability.

Document status: **draft**. Living document; updates with each substantive
change to the protocol or trust boundaries. Last reviewed against repo state
at the commit that introduces this file.

---

## 1. Scope and assumptions

### In scope

- The `phantom_core` library: hybrid post-quantum L4/L6 transport.
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
       │ ║ phantom_core API       ║   │                │   ║ phantom_core API       ║ │
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

The double-line boxes inside each process (`phantom_core API` and
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
| A4 | Session AEAD keys | `CryptoState.session_key`, ring `LessSafeKey` inside `CryptoSessionInner` | Compromise leaks all packets in that session direction. Mitigated by `ZeroizeOnDrop` (Phase 1.2) and (future) mid-session rekey (Phase 1.5, V2). |
| A5 | Application plaintext | passed in/out via `Vec<u8>` / `Bytes` | The whole point of the transport. |
| A6 | Session identity / linkability metadata | session id (32 B), stream id, sequence numbers | Traffic-analysis input. Out of scope for full anonymity. |
| A7 | Cookie / PoW state | client-side stored cookies | Loss enables replay of one round trip within freshness window only. |

---

## 4. Adversary model

| Capability | Modeled? | Mitigation locus |
| --- | --- | --- |
| Passive observation (any portion of the wire) | Yes | AEAD confidentiality; FakeTLS obfuscation |
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
| Long-lived signing-key theft | **No** (post-compromise) | Phantom relies on the server signing key for authentication — once leaked, attacker can serve as the server. Key revocation is an out-of-band concern (PKI / OOB re-pinning). |

---

## 5. STRIDE analysis

### S — Spoofing identity

| Threat | Mitigation | Code |
| --- | --- | --- |
| Adversary presents a fake server key in `ServerHello` | Client pins `expected_server_key`; mismatch → `HandshakeError::ServerIdentityMismatch` | `core/src/transport/handshake.rs:283-286` |
| Adversary forges a `ClientHello` to spoof an IP | Cookie + adaptive PoW; cookie is HMAC(rotating-secret, ip, bucket) so forgery requires the secret | `core/src/transport/handshake.rs:402-475` |
| Replay of an old, captured `ServerHello` to a fresh client | Transcript signature binds `client_hello.nonce` and `session_id_bytes`; replay fails signature check | `core/src/transport/handshake.rs:201-204, 320-326` |

### T — Tampering with data

| Threat | Mitigation | Code |
| --- | --- | --- |
| Bit-flip in ciphertext | AEAD tag check fails → packet dropped | `core/src/crypto/adaptive_crypto.rs:255-260` |
| Mutation of header on the wire | Header is serialized via `PacketHeader::to_wire` (45-byte big-endian image) and used as AEAD AAD; any mutation invalidates the tag | `core/src/transport/session.rs` |
| Tampering with handshake messages | Transcript signature covers every field of `ClientHello`/`ServerHello` | `core/src/transport/handshake.rs:201-204, 320-326` |
| Sequence-number mutation (replay or skip) | After AEAD verify, `Session::decrypt_packet` consults a per-stream `ReplayWindow` and rejects duplicates / out-of-window-old | `core/src/transport/session.rs:251-270`, `core/src/security/replay_window.rs` |

### R — Repudiation

Not in scope. The protocol does not provide non-repudiation: there is no
externally-verifiable proof of which peer sent which message. Adding
non-repudiation would require persistent per-message signing — out of scope
for a real-time secure transport.

### I — Information disclosure

| Threat | Mitigation | Code |
| --- | --- | --- |
| Plaintext leak on the wire | AEAD encryption (post-handshake invariant `PacketFlags::ENCRYPTED`); unencrypted post-handshake packets dropped | `core/src/api/session.rs:1415-1422` |
| Plaintext leak via error message | Error variants carry only the error class, not the payload; no `format!("{:?}", plaintext)` anywhere | grep `format!.*plaintext\|payload` in `core/src/` → 0 results |
| Memory disclosure of keys after session close | `ZeroizeOnDrop` on every key-bearing struct | `core/src/transport/session.rs:75` (`CryptoState`), `core/src/transport/handshake.rs:253` (`HandshakeServer`), `core/src/transport/handshake.rs:686` (`HandshakeClient`) |
| Timing leak on cookie comparison | `subtle::ConstantTimeEq::ct_eq` — never branches on cookie content | `core/src/transport/handshake.rs:1065` |
| DPI fingerprinting | FakeTLS outer obfuscation (anti-DPI only; not for real confidentiality) | `core/src/transport/legs/faketls.rs` |

### D — Denial of service

| Threat | Mitigation | Code |
| --- | --- | --- |
| Handshake flood / IP spoof amplification | Stateless cookie (HMAC over rotating secret + IP + bucket) forces attacker to receive a packet at the spoofed IP before consuming server resources | `core/src/transport/handshake.rs::generate_cookie`, `validate_cookie` |
| CPU-exhaustion via cheap handshake attempts | Adaptive PoW difficulty tiers from 0 → 16 (~64k hash evals) based on per-minute load | `core/src/transport/handshake.rs::adaptive_difficulty` (Phase 1.14) |
| Panic-on-malformed input | `#![warn(clippy::unwrap_used, expect_used, panic, unreachable, todo, unimplemented)]`; no `.unwrap()` on the recv/handshake hot path; fuzz harnesses in `fuzz/` | Phase 1.3, 6.4 |
| AEAD nonce exhaustion (theoretical) | Hard ceiling `AEAD_MAX_INVOCATIONS = 1 << 48` → `CryptoError::NonceExhausted` | `core/src/crypto/adaptive_crypto.rs:24-44` |
| Replay-window memory amplification | Per-stream `ReplayWindow` is 144 bytes; created lazily, bounded by stream count | `core/src/security/replay_window.rs` |

### E — Elevation of privilege

Out of scope — `phantom_core` does not run with elevated privileges or
expose any privileged operation. The library is a passive data conduit.

---

## 6. LINDDUN privacy analysis

| Threat | Status | Note |
| --- | --- | --- |
| **L**inkability of two sessions to the same client | Partial | Same `HybridVerifyingKey` on the client side correlates handshakes (the client signing key is reused). Anonymous mode would require ephemeral client signing keys; tracked as future work. |
| **I**dentifiability of the client | No mitigation | Source IP is necessarily visible to the server. Client may use Tor / VPN externally. |
| **N**on-repudiation | Intentionally out of scope (see STRIDE-R) |
| **D**etectability that this is `phantom_core` | Mitigated by FakeTLS | The outer leg simulates TLS 1.2/1.3 record framing; DPI fingerprinting probability greatly reduced but not zero (timing, sizing). |
| **D**isclosure of metadata (sizes, timing) | No mitigation | Traffic analysis defeats Phantom as it would defeat any non-padded protocol. Future work could add cover traffic. |
| **U**nawareness of data flows | Documented | This file. Operators must understand what does/doesn't leak. |
| **N**on-compliance | Tracked | Phase 5 (FIPS 140-3 / CC) work covers regulatory compliance. |

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

---

## 8. Known limitations / future work

- Mid-session key rotation (Phase 1.5) is blocked on V2 wire format.
  Sessions today rely solely on the initial handshake's KEM secret for
  the entire session lifetime. Acceptable because AEAD safety limits are
  far above any practical session volume, but adds forward-secrecy
  surface area that a future leak would expose.
- Multi-path migration validation (Phase 4.2) — without it, an attacker
  who can MITM both legs simultaneously could potentially confuse the
  sender about which path is active. Documented; the existing
  `expected_server_key` pinning still prevents impersonation.
- No protection against side-channel cryptanalysis of the AEAD itself.
  Rely on ring / dalek / RustCrypto (`ml-kem`, `ml-dsa`) upstream
  constant-time properties.
- Endpoint compromise sweeps away the entire model.

---

## 9. Revision history

| Date | Reviewer | Notes |
| --- | --- | --- |
| _Initial draft_ | n/a | Captures state at the commit that introduced this file (Phase 6.1). |
