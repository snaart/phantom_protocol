# Phantom Core — Security Audit Report

- **Date:** 2026-06-03
- **Target:** `phantom_core` library (`core/`), at `main` @ `5827909`
- **Scope:** ~25,000 LoC across crypto, handshake, session/AEAD, transport legs, wire codec, API/FFI, `unsafe`, DoS/concurrency, supply chain, observability. Sibling crates (`server/`, `cli/`) referenced where they embed the library.
- **Method:** 13-dimension fan-out source review; every raw finding adversarially verified by a 3-lens panel (faithful-read / exploitability / mitigation-search). A finding is **Confirmed** only with ≥2/3 "real" votes, **Disputed** at 1/3, **Dropped** at 0/3. Supply-chain baseline from `cargo audit` against `Cargo.lock` (343 deps).
- **Verification cost:** 141 agents, ~7.7M tokens.

> Severity reflects the **inner Phantom session** as the real security boundary; the outer FakeTLS layer is anti-DPI obfuscation only (by design). Network attacker = full wire control (inject/replay/reorder/drop/truncate/downgrade/flood).

---

## Executive Summary

**Overall risk rating: `needs-work`** (ship-blocking issue present).

Phantom Core is well-architected, and its **cryptographic primitive choices and the handshake/identity layer are sound** — server-key pinning is correctly mandatory, the transcript binds version + FIPS build-mode + the whole ClientHello (incl. early-data), replay rejection runs after AEAD verify, long-term keys are `ZeroizeOnDrop` with redacted `Debug`, and `unsafe` is governed by `#![deny(unsafe_code)]` with three narrowly-scoped, audited opt-ins (no memory-safety defect found anywhere).

The weakness is concentrated in the **data-plane and DoS-resistance layers**, where the discipline of the handshake layer is not consistently applied:

1. **One critical, network-reachable crypto defect:** AES-GCM **nonce reuse** caused by the per-stream 32-bit sequence wrapping long before the only rekey/exhaustion trigger (a session-wide 2⁴⁷ counter) ever fires. Reachable on any long-lived single-stream tunnel. This is the textbook Forbidden-Attack condition and breaks both confidentiality and integrity of the affected session/epoch.
2. **An unauthenticated control plane:** ACK/FIN frames and the 0-RTT `early_data_accepted` verdict are processed/trusted without authentication, letting an on-path attacker corrupt reliable delivery, tear down streams, and duplicate or black-hole 0-RTT payloads — despite application data being AEAD-protected.
3. **A pre-auth DoS surface:** serial accept loop with no in-library handshake/read timeout (slowloris), 4-byte→16 MiB memory amplification, uncapped client-side PoW difficulty, and unbounded retry loops.
4. **A false-assurance gap:** several documented defenses (per-IP PoW escalation, SYN-flood half-open slots, path-validation gating) are **dead code** — present and advertised but never wired into the live path.

The completeness critic additionally flagged a **compiled-but-unwired `networks/` layer** that is `pub`-exported and contains a certificate-pinning bypass gated on `debug_assertions` and a plaintext-forwarding engine — latent today (no production callers) but reachable public API.

### Findings by severity (confirmed)

| Severity | Count | IDs (deduplicated) |
|---|---|---|
| **Critical** | 1 | C1 (AEAD-1 / CRYPTO-1) |
| **High** | 4 | H1 (AEAD-2 / APIFFI-01), H2 (ZERORTT-1), H3 (HS-01), H4 (DOS-1 / LEGS-001) |
| **Medium** | 6 | WIRE-001, LEGS-002, LEGS-003, HS-02, PATH-001, DOS-2 |
| **Low** | 12 | CRYPTO-2 (=HS-04), CRYPTO-3, HS-03, ZERORTT-2, WIRE-002, faketls-2, LEGS-004, UNSAFE-1, DOS-4, SUPPLY-01, SUPPLY-02, SUPPLY-03, INFOLEAK-1 |
| **Info** | 5 | LEGS-005, APIFFI-03, UNSAFE-2, SUPPLY-04, SUPPLY-05 |

*(33 confirmed raw findings → presented deduplicated; AEAD-1≡CRYPTO-1, AEAD-2≡APIFFI-01, DOS-1≡LEGS-001, CRYPTO-2≡HS-04 are the same issues reported by two dimensions.)*

---

## CRITICAL

### C1 — AES-GCM nonce reuse via per-stream `u32` sequence wrap (AEAD-1 / CRYPTO-1) · Invariant 8
**Location:** `core/src/transport/session.rs:771-779` (`build_packet_nonce`); `core/src/transport/stream.rs:447,472-474` (`next_send_sequence`); rekey trigger `session.rs:56,526-529`; caps `core/src/crypto/adaptive_crypto.rs:42,424-427` · **Verifier votes: 3/3**

The 12-byte AEAD nonce is `prefix(4) ‖ epoch(1) ‖ stream_id(2) ‖ sequence(4) ‖ path_id(1)`; its uniqueness rests entirely on `(epoch, stream_id, sequence)` never repeating within a session. `sequence` is a per-stream `AtomicU32::fetch_add(1)` with **no overflow guard** — it wraps silently at 2³². The only mid-session rekey trigger (`send_needs_rekey()` at `REKEY_SOFT_LIMIT = 2⁴⁷`) and the hard `NonceExhausted` cap (`AEAD_MAX_INVOCATIONS = 2⁴⁸`) are both keyed on the **direction-wide** AEAD invocation counter (sum over all streams), **not** the per-stream sequence. `path_id` is always `0` on the data send path, so it adds no entropy.

**Consequence:** a session dominated by one stream sends 2³²+1 packets while the direction counter is still only ~2³² (≈32,768× below the rekey threshold) — so no rekey, no fresh prefix, no epoch bump occurs. The per-stream sequence wraps `2³²−1 → 0` and the full nonce repeats under the unchanged AES-256-GCM key.

**Impact:** Catastrophic. Two ciphertexts under the same (key, nonce): keystream XOR leaks plaintext (confidentiality), and a single nonce-reuse pair recovers the GHASH subkey `H` via the **Forbidden Attack (Joux)** → existential forgery of arbitrary authenticated ciphertexts for that direction/epoch (integrity). 2³² packets ≈ 4.3×10⁹; at 10⁶ pkt/s on one stream this is reached in **~71 minutes** of a benign bulk transfer — no special privilege required, just an on-path observer.

**Fix (ship-blocking):** make per-stream sequence exhaustion a hard nonce-uniqueness boundary independent of the session-wide counter. Either (a) force a rekey (epoch bump + fresh prefix) before any stream's sequence can wrap; (b) widen `sequence` to `u64` in both the wire header and the nonce (wire bump); or (c) at minimum, `checked_add` and return `NonceExhausted` at the wrap boundary instead of `fetch_add` wrapping silently. Add a `security_invariants.rs`/property test driving one stream past 2³² sends, asserting no `(epoch, stream_id, sequence, path_id)` nonce ever repeats.

---

## HIGH

### H1 — Forged unauthenticated ACK/FIN frames corrupt reliable delivery & tear down streams (AEAD-2 / APIFFI-01) · Invariant 2
**Location:** `core/src/api/session.rs:1374-1388` (ACK short-circuit in `handle_packet`); `core/src/transport/stream.rs:566-592` (`Stream::ack`) · **Votes: 3/3**

The ACK branch in `handle_packet` runs **before** the `ENCRYPTED` decrypt gate. ACK frames are unencrypted, carry no AEAD tag, and are never bound to the session — the recv reader also never checks `header.session_id` (only `version`). The handler feeds the attacker-controlled `header.sequence` straight into `stream.ack()` (removes the matching pending reliable segment from the retransmit buffer, restores a semaphore permit, records an RTT sample), `feed_bbr_on_ack`, and — on `ACK|FIN` — `route_close`.

**Impact:** On any non-FakeTLS leg, a network attacker injects forged ACKs for guessable `(stream_id, sequence)` pairs (the reserved raw-app stream has a small monotonic space): (a) silent data loss/truncation by acking never-received segments; (b) BBR/pacer poisoning via bogus RTT/delivery samples; (c) flow-control corruption via restored permits; (d) spurious stream teardown via forged `FIN`. Reliable-delivery integrity of the inner session is defeated.

**Fix:** authenticate ACKs end-to-end — either carry the ack number inside an `ENCRYPTED` control frame, or encrypt an empty payload so the header (incl. `session_id/stream_id/sequence/epoch`) is AEAD-AAD-bound and route ACKs through `decrypt_packet`. Until then, never let an unauthenticated ACK mutate send state or close a stream, and verify `header.session_id` on every inbound frame.

### H2 — `ServerHello.early_data_accepted` verdict is not transcript-signed → 0-RTT duplication or silent loss (ZERORTT-1) · Invariant 9
**Location:** `core/src/transport/handshake.rs:208` (field), `:221-228` (transcript excludes it), `:512-519` (set), `:869-872` (client reads forged value); `core/src/api/session.rs:560-577` (retransmit driven by the unauthenticated verdict) · **Votes: 3/3**

The signed `HandshakeTranscript` covers `protocol_variant`, the whole `ClientHello`, key package, ciphertext, verify key and session id — but **not** `early_data_accepted`. Handshake messages travel as bare plaintext borsh blobs. An active on-path attacker re-serializes the `ServerHello` with the verdict bit flipped while leaving the signature/ciphertext/session_id intact; the client recomputes the transcript hash (which omits the bit) and the signature **still verifies**.

**Impact (no ClientHello replay, no key knowledge required):** (1) flip `true→false` after the server accepted & delivered the early-data → client re-sends the identical payload over the 1-RTT session → server application receives the 0-RTT request **twice** (replay/duplication of possibly non-idempotent requests, defeating Invariant 9's one-shot promise). (2) flip `false→true` after the server rejected → client suppresses the retransmit and silently drops already-consumed bytes while `early_data_accepted()` reports success → attacker selectively black-holes 0-RTT data undetectably.

**Fix:** add `early_data_accepted` to the signed transcript (client recomputes with the received bit and rejects on mismatch), or bind the verdict to authenticated material. At minimum the retransmit decision must not depend on an unauthenticated wire bit. Add a negative test that flips the bit.

### H3 — Client brute-forces attacker-chosen PoW difficulty with no cap → CPU-exhaustion DoS (HS-01)
**Location:** `core/src/api/session.rs:680-683`; `core/src/crypto/pow.rs:82-97` (`solve`) · **Votes: 3/3**

On a `HelloRetryRequest` the client unconditionally calls `challenge.solve()`. `PoWChallenge.difficulty` is a `u8` read verbatim off the wire and is **never validated/capped client-side**; the client cannot verify the challenge's server-keyed MAC, so it trusts whatever difficulty arrives. `solve()` loops until it finds a hash with `difficulty` leading zero bits — expected 2^difficulty evaluations — with no iteration/time bound.

**Impact:** a MITM (or malicious/compromised server) injects a `HelloRetryRequest` with `difficulty = 255`; the client spins a CPU core on an infeasible 2²⁵⁵ proof-of-work and never completes the handshake. One injected packet pins a client core indefinitely, pre-auth, per connection. (The challenge need not even be MAC-valid — the client solves before the server's MAC check is ever reached.)

**Fix:** reject `difficulty > MAX_CLIENT_POW_DIFFICULTY` (e.g. 24) before solving, and bound `solve()` by wall-clock/iteration count returning an error rather than spinning.

### H4 — Serial accept loop + no in-library handshake/read timeout → slowloris listener DoS (DOS-1 / LEGS-001)
**Location:** `core/src/api/listener.rs:234-235,369`; `core/src/api/tcp_transport.rs:70-99` (`recv_bytes`, no timeout); ref. server serial arm `server/src/main.rs:228` · **Votes: 3/3**

`PhantomListener::accept()` drives the **entire** PQC handshake inline, reading the ClientHello via `recv_bytes().await` → `read_exact` with **no deadline**. The reference server's accept loop is **serial** (one handshake awaited at a time) with only a generous 30 s liveness timeout; the global session-slot semaphore and per-IP limiter gate only *established* sessions, not in-flight handshakes. Library/FFI embedders without their own timeout get zero protection — the handshake can hang forever.

**Impact:** a single attacker opening one TCP connection and withholding (or trickling) handshake bytes parks the accept loop, denying service to all clients for up to the embedder's timeout — and forever for FFI embedders. Reconnecting yields sustained, near-zero-cost DoS that defeats both global and per-IP caps.

**Fix:** add an in-library handshake deadline (5–10 s, shorter per-read), spawn the handshake off the accept loop so a stall can't block `accept()`, and bound concurrent in-flight handshakes with a dedicated semaphore. Don't rely on the embedder for the timeout.

---

## MEDIUM

- **WIRE-001 — 4-byte → 16 MiB memory-amplification pre-allocation** (`core/src/api/tcp_transport.rs:91-99`, mirrored `transport/legs/wasi.rs:186-189`; votes 3/3). `recv_bytes` does `buf.resize(len, 0)` for the full declared length *before* the body read, reached on the first unauthenticated ClientHello frame with no connection cap. Attacker sends 4 bytes (`0x01000000` = 16 MiB) and stalls → ~4,000,000× amplification → OOM. **Fix:** allocate lazily/incrementally; use a small frame cap for the unauthenticated handshake, raise only post-establishment; add a connection limit + read timeout.
- **LEGS-002 — KCP leg pre-allocates attacker-controlled length** (`core/src/transport/legs/kcp.rs:252-266`; votes 2/3). `vec![0u8; len]` (≤10 MiB) before reading any payload, no timeout. 4 bytes in → 10 MiB pinned per connection. **Fix:** bounded incremental accumulator + read timeout.
- **LEGS-003 — `TcpSessionTransport` accumulator never shrinks** (`core/src/api/tcp_transport.rs:21,88-96`; votes 3/3). Production recv path; one legitimate 16 MiB frame pins 16 MiB resident for the connection's life though steady-state frames are ~1.4 KiB. N connections → 16·N MiB sticky RSS. **Fix:** `shrink_to` after `split_to().freeze()` when capacity ≫ steady-state, or lower `MAX_FRAME_BYTES` to the 4 MiB app cap.
- **HS-02 — Unbounded `HelloRetryRequest` loop** (`core/src/api/session.rs:645-690`; votes 3/3). Client retry loop has no round cap and no timeout; a MITM answers every ClientHello with a cheap retry → client loops forever, never surfacing an error. **Fix:** cap to ~2–3 rounds + handshake timeout. (Compounds H3.)
- **PATH-001 — Path-validation gating documented but never enforced** (`core/src/api/session.rs:1449-1569`, `transport/session.rs:661-663`, `transport/path.rs:60-67`; votes 2/3). `begin_path_validation` has no production callers; `handle_packet` never consults `path_state` before delivering app data. No break today (all data is AEAD-authenticated, single transport), but the Invariant-6 "MUST NOT accept on an unvalidated path" gate **does not exist in code** — a landmine if real multi-path is later wired in assuming it does. **Fix:** wire the gate, or demote the docs to a clearly-marked TODO.
- **DOS-2 — Per-IP PoW escalation (`ReputationTracker`) is dead code** (`core/src/transport/reputation.rs:25`, `api/listener.rs:376`, `transport/handshake.rs:366`; votes 2/3). Only referenced by a bench. Production uses only the *global* load tier (`adaptive_difficulty`), which returns **0 PoW below 100 handshakes/min** and treats all IPs identically — so a low-and-slow attacker pays zero PoW while forcing full ML-KEM/ML-DSA work per handshake, and abusive sources can't be singled out. **Fix:** wire `ReputationTracker` into `drive_server_handshake`, or delete it and the docs.

> Also **DOS-3** (no library-level cap on concurrent in-flight handshakes; `HalfOpenSlots` SYN-flood guard is dead code) scored 1/3 → listed under Disputed, but it is the same theme as H4/DOS-2 and is worth addressing together.

---

## LOW

- **CRYPTO-2 / HS-04 — Non-constant-time keyed-MAC compare in the PoW/cookie verify path** (`core/src/crypto/pow.rs:60`; votes 3/3). `self.nonce[8..32] != mac.as_bytes()[0..24]` short-circuits → timing leak on a server-keyed MAC authenticating attacker data. Defense-in-depth regression vs. the `subtle::ConstantTimeEq` used for path validation. **Fix:** `ct_eq`.
- **CRYPTO-3 — Transient KEM secret & derived AEAD keys not zeroized** (`core/src/crypto/hybrid_kem.rs:187`, `adaptive_crypto.rs:275-288`, `aes_session.rs:52-64`; votes 2/3). The combined HKDF IKM (`[ecc, pq].concat()`) and per-direction key locals drop without wiping. Long-term structs *are* `ZeroizeOnDrop` — only transients leak. **Fix:** wrap in `zeroize::Zeroizing` (the rekey path already models this).
- **HS-03 — Resumption ticket burned by a passive observer** (`core/src/transport/handshake.rs:448-455`; votes 3/3). `try_resume` consumes the one-shot ticket *before* the cookie/PoW gate and without proof-of-possession of `resumption_secret`; `resume_session_id` was sent in cleartext earlier. An observer replays it (no early-data) to burn the victim's ticket → forced 1-RTT fallback (availability/latency, not confidentiality). **Fix:** require a binder/MAC over the transcript keyed by `resumption_secret` before consuming.
- **ZERORTT-2 — Ticket consumed before the handshake can still fail** (`core/src/transport/handshake.rs:448-454,480-509`; votes 3/3). KEM encapsulate / transcript-hash steps after `try_resume` can fail with the ticket already gone; an attacker corrupting the unauthenticated KEM ciphertext burns it. **Fix:** consume only on the success path, or re-insert on failure.
- **WIRE-002 — `FragmentAssembler` unbounded map + first-frame `total_chunks` trust** (`core/src/transport/fragmentation.rs:43-121`; votes 2/3). `pub` but unwired; unbounded `assemblies` map, eviction only via an uncalled method, accepts mismatched chunk indices → reassembly poisoning / memory growth if an embedder wires it to a datagram path. **Fix:** bound concurrent assemblies & bytes, validate indices, timer-driven eviction, or feature-gate/remove.
- **faketls-2 — Unconditional `.unwrap()` on AEAD seal in the outbound hot path** (`core/src/transport/legs/faketls.rs:605-608,615`; votes 2/3). `TransportLeg::send` takes arbitrary-length `Bytes`; no length check before `seal`, and `in_out.len() as u16` truncates >~65519 B. Latent panic-as-DoS / framing corruption if a future caller sends large buffers directly. **Fix:** `map_err` + reject oversized payloads before sealing.
- **LEGS-004 — `VirtualSocket::start_recv_loop` reads a stale `closed` snapshot** (`core/src/transport/virtual_socket.rs:220-228,304-306`; votes 2/3). The recv task checks a fresh `Arc<AtomicBool>` initialized by value at spawn, not the field `close()` flips → recv tasks outlive `close()` (orphaned-task leak). Legacy path. **Fix:** share one `Arc<AtomicBool>`.
- **UNSAFE-1 — `WasiLeg` `unsafe impl Send/Sync` rests on a partially-misstated SAFETY comment** (`core/src/transport/legs/wasi.rs:82-107`; votes 2/3). Sound for current code, but the comment claims "the Mutex is the only access path for the handles" while `_socket` is a bare un-mutexed field (used only on `Drop`). Latent UB if a future `&self` accessor touches `_socket` or `wasi-threads` stabilizes. **Fix:** carve out `_socket` in the comment / structurally enforce the mutex contract.
- **DOS-4 — Handshake retry loop has no round cap** (`core/src/api/listener.rs:368-412`; votes 3/3). Server-side mirror of HS-02; a peer cycling Retry rounds occupies the serial accept loop arbitrarily long (amplifies H4). **Fix:** cap rounds + per-read timeout.
- **SUPPLY-01 — `uniffi` `cli` feature pulls the bindgen toolchain into the production graph** (`core/Cargo.toml:217`; votes 2/3). Default-on `bindings` activates `cli` on the *library*, dragging `clap`/`cargo_metadata`/`tempfile`/`uniffi_bindgen` into every consumer incl. the network-facing reference server. **Fix:** scope `cli` to the bin only; set `default-features = false` on `phantom_core` in `server/`.
- **SUPPLY-02 — `chacha20poly1305` is a declared, default-on, unused dependency** (`core/Cargo.toml:183`; votes 2/3). The real ChaCha20-Poly1305 comes from `ring`/`aws-lc-rs`; the RustCrypto crate is dead weight in every build. **Fix:** remove it.
- **SUPPLY-03 — FIPS build still links non-FIPS crypto (`ring`, `x25519-dalek`)** (`core/Cargo.toml:112`; votes 2/3). The runtime backend swap is correct, but the dep *declarations* aren't cfg-gated, so a FIPS artifact ships non-approved crypto as dead code — muddies the CMVP module boundary. **Fix:** cfg-gate non-FIPS crypto out of `fips` builds.
- **INFOLEAK-1 — `ResumptionHint` derives `Debug` and prints the 32-byte `resumption_secret`** (`core/src/api/session.rs:109-117`; votes 3/3). The lone secret-bearing type crossing the FFI boundary uses a derived `Debug` (every other secret type is `REDACTED`). A mobile/FFI consumer logging it leaks the 0-RTT key material; an attacker who recovers it can forge/decrypt a later resumed handshake's early-data (undercuts Invariant 9). **Fix:** hand-written redacting `Debug`, mirroring `HybridSigningKey`.

---

## INFO

- **LEGS-005** — `VirtualSocket` recv-loop parses header flags at `data[38]` and `ack_delay` as little-endian, mismatching the canonical big-endian 45-byte `PacketHeader` → silent BBR corruption on the legacy path (`virtual_socket.rs:244-258`; 2/3). **Fix:** use `PacketHeader::from_wire`.
- **APIFFI-03** — `connect_pinned_with_resumption` opens the TCP socket before the `EARLY_DATA_MAX_LEN` check, so oversized early-data wastes a connection (`api/session.rs:1922-1937`; 2/3). Local misuse only. **Fix:** hoist the length check.
- **UNSAFE-2** — `sendmmsg(2)` GSO path ships hand-written libc `unsafe` but is **unreachable dead code** (`transport/udp_transport.rs:317-374`; 2/3). The `unsafe` was independently verified **sound**; concern is audit-burden only. Stale `recvmmsg` references in `lib.rs:56` / `udp_transport.rs:19` / CLAUDE.md. **Fix:** wire it with tests or feature-gate/remove; fix stale comments.
- **SUPPLY-04** — `deny.toml:16` rationale for ignoring RUSTSEC-2026-0097 is **factually wrong** ("`rand` is dev-only") — `rand 0.8` is a runtime dep used for the path-validation challenge & session-id fallback. The advisory doesn't actually affect the pinned `0.8.6`, so the outcome is harmless, but the wrong rationale could mislead future triage. **Fix:** correct the comment; consider `OsRng` for the path challenge.
- **SUPPLY-05** — `rustls-pemfile` unmaintained (RUSTSEC-2025-0134) **confirmed not network-reachable** — only `configure_client_tls` (no in-crate callers) parses operator-supplied PEM (`networks/tls.rs:19`; 2/3). `deny.toml` ignore is appropriately scoped. **Fix:** track migration to `rustls_pki_types::pem`.

---

## Additional surface — Completeness critic (beyond the 13 dimensions)

These are in compiled-and-`pub`-exported but **unwired** code (no production callers today), so they are **latent, not actively exploitable** — but reachable public API that would become live vulnerabilities if an embedder composes them or a future change wires them in:

1. **`networks/tls.rs` — certificate-pinning bypass gated on `debug_assertions`** (`networks/tls.rs:26`). When no CA is pinned, `configure_client_tls` enforces pinning only behind `if !cfg!(debug_assertions)` — i.e. a plain `cargo build`/`cargo test`/dev-profile embedder **silently falls back to system WebPKI roots with no pinning**, contradicting the project's core pinning invariant for this path. Tying a security control to the optimization level is the bug. **Recommend: audit or delete the `networks/` layer; if kept, gate pinning on an explicit feature, never `debug_assertions`.**
2. **Decompression bombs** — `transport/compression.rs` (`AdaptiveCompressor::decompress`) and the orphan `networks/compression.rs` impose **no output-size cap**; `lz4_flex::decompress_size_prepended` trusts an attacker-prepended size and `zstd::decode_all` is unbounded → small input → multi-GB OOM if ever folded into the recv path (post-decrypt is still peer-influenced). **Recommend: add a hard decompression-output cap before any compression code is wired in.**
3. **`networks/engine.rs` forwards undecrypted payloads** — `NetworkEngine::process_inbound` pushes decoded payloads to a broadcast channel with a `// A future crypto layer would decrypt here` TODO. A second, parallel transport stack with **no encryption/auth**, `pub`-exported and described only as "skeletal" — an embedder who mistakes it for the secure stack ships plaintext. **Recommend: clearly mark non-secure / remove.**
4. **Orphan/dead scaffolding encoding dangerous assumptions** — `networks/serialization.rs` imports `rkyv`/`bytecheck` (a zero-copy deser stack **not in any Cargo.toml**, contradicting the borsh design and a known UB vector on untrusted bytes); `transport/reputation.rs` & `validation.rs` are dead with unbounded per-IP maps. **Recommend: delete or feature-gate so they cannot be wired without re-review.**

> Cleared by the critic: `test_harness` is correctly `#[cfg(all(test, feature="std"))]`-gated (no prod leak); runtime executors' panics are inventoried in `docs/security/panic-sites.md`; `pacer`/`bandwidth_estimator` use guarded/saturating arithmetic; the live multiplexer/coalescer decode paths are bounds-checked and run post-AEAD.

---

## Attack chains

- **Nonce-reuse key compromise on a long-lived bulk stream** [C1]. One busy stream → sequence wraps before the 2⁴⁷ session-wide rekey → identical AES-GCM (key, nonce) → Forbidden Attack → existential forgery for the epoch. Collapses Invariants 2 & 8.
- **Pre-auth listener wipeout** [H4 + WIRE-001 + DOS-4 + HS-02 + DOS-2 + LEGS-002/003 + DOS-3]. Stall the serial accept loop (slowloris) and/or commit 16 MiB per 4-byte prefix, with no concurrent-handshake cap, no per-IP escalation (dead code), and uncapped retries → one cheap source denies the whole listener pre-authentication.
- **Reflected client CPU exhaustion** [H3 + HS-02]. One forged `HelloRetryRequest` with `difficulty=255` pins a client core forever; or an endless stream of cheap retries loops the client indefinitely.
- **On-path corruption without breaking AEAD** [H1 + H2]. Forged ACK/FIN corrupt reliable delivery & tear down streams; the unsigned `early_data_accepted` bit duplicates or black-holes 0-RTT payloads.
- **0-RTT resumption denial** [HS-03 + ZERORTT-2]. A passive observer (or a corrupted KEM field) burns the victim's one-shot ticket → forced 1-RTT for every subsequent connection.
- **Latent multi-path/FFI footguns** [PATH-001 + WIRE-002 + INFOLEAK-1 + networks/ critic gaps]. Documented-but-dead or trap-shaped controls become exploitable the moment they're wired in.

---

## Strengths (verified, no confirmed regression)

- **Server identity pinning** is correctly mandatory (`Some(&expected_server_key)` on every connect path) — no bypass found (Inv 1).
- **Transcript binding** is robust: version + FIPS `protocol_variant` are signed leading fields, and the transcript covers the whole ClientHello incl. early-data (Inv 7, 10). H2 is an *omission* of one field, not a flaw in the mechanism.
- **Replay protection runs after AEAD verify** with per-stream sliding-window bitmaps; property + negative tests pin it (Inv 4).
- **Key hygiene on long-term/structural material:** `HybridSecretKey`/`HybridSigningKey`/`CryptoState` are `ZeroizeOnDrop` with redacted `Debug`. Findings are confined to transients + the one `ResumptionHint` outlier.
- **Constant-time** path-validation responses and cookie compare (Inv 6); the two timing findings are one inconsistent MAC compare, not absence of awareness.
- **`unsafe` governance:** `#![deny(unsafe_code)]` + 3 audited opt-ins. The one hand-written syscall `unsafe` (`sendmmsg`) was verified **sound**. **No memory-safety defect found anywhere.**
- **Primitive selection & the data-packet encryption boundary** are sound (hybrid X25519+ML-KEM-768 / Ed25519+ML-DSA-65, header-as-AAD with `session_id`, per-direction keys, HKDF rekey).
- **FakeTLS** correctly uses per-record counter nonces + direction-keyed AEAD (Inv 3) — the prior zero-nonce design is remediated, no regression.
- **Wire-format stability** actively defended (byte-exact vectors, transcript-hash freeze, borsh `=`-pinned, independent non-Rust decoder).
- **Supply chain** mostly disciplined: the two flagged advisories are confirmed **not network-reachable**; FIPS backend-swap cfg-gating is correct.

---

## Prioritized remediation roadmap

1. **Ship-blocker — C1 nonce reuse.** Force rekey before any stream sequence can wrap (or widen to `u64`, or fail-closed at the boundary). Add the no-nonce-repeat test. **Block any 1.0/production claim until fixed.**
2. **Authenticate the data-plane control path** — H1 (ACKs/FIN through/under AEAD; check `session_id` on every frame) and H2 (sign `early_data_accepted`). Add forged-ACK and flipped-verdict negative tests.
3. **Close the pre-auth DoS surface** — H4/DOS-4 (in-library handshake + per-read timeout; spawn off the accept loop; bound concurrent handshakes), WIRE-001/LEGS-002/LEGS-003 (lazy alloc, small unauthenticated-frame cap, shrink the accumulator).
4. **Cap client-side PoW** — H3 (reject high difficulty before solving; bound `solve()`), HS-02 (cap retry rounds + handshake timeout).
5. **Resolve documented-but-dead defenses (false assurance)** — wire or delete `ReputationTracker` (DOS-2), `HalfOpenSlots` (DOS-3), path-validation gating (PATH-001); gate/remove the unwired `networks/` layer, `FragmentAssembler`, `VirtualSocket`, and dead UDP/GSO `unsafe`.
6. **Bind resumption-ticket consumption to proof-of-possession** and consume only after validation — HS-03, ZERORTT-2.
7. **Crypto-hygiene & info-leak cleanups** — CRYPTO-2/HS-04 (`ct_eq`), CRYPTO-3 (`Zeroizing`), INFOLEAK-1 (redact `ResumptionHint::Debug`).
8. **Supply-chain tightening** — SUPPLY-01/02/03 (trim bindgen toolchain, drop unused `chacha20poly1305`, cfg-gate non-FIPS crypto out of FIPS), SUPPLY-04 (fix the `deny.toml` rationale).

---

## Disputed (1/3 — flagged for human judgment, not confirmed)

`CRYPTO-4` (Ed25519 `verify` vs `verify_strict` — malleability), `WIRE-003` (decompression-bomb helpers — overlaps critic gap #2), `faketls-1` (recv no overall read timeout), `PATH-002` (`VirtualSocket::send` raw plaintext + attacker-influenced path RTT), `PATH-003` (`issue_challenge` overwrites an in-flight challenge), `APIFFI-02` (exported `connect()` returns a transport-less session whose `recv()` deadlocks), `DOS-3` (no concurrent-handshake cap; `HalfOpenSlots` dead — *recommend addressing with H4 regardless*), `SUPPLY-06` (stale CLAUDE.md `ml-dsa` pin note).

## Dropped (0/3 — refuted)

`ZERORTT-3` ("no test pins 0-RTT no-double-accept") — **refuted**: `core/tests/tcp_integration.rs:278-377` (`tcp_zero_rtt_rejection_retransmits_early_data_over_1rtt`) drives a full resume + byte-identical replay and asserts rejection end-to-end, and `.github/workflows/ci.yml:274` runs it `--ignored` in CI. The anti-replay guarantee is pinned and gated.
