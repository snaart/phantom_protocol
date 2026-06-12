# Phantom Protocol — Security Audit Report

- **Date:** 2026-06-11
- **Target:** `phantom_protocol` library (`core/`), at `main` @ `6a7586f` (post Phase-4 connection migration + liveness).
- **Scope:** ~29,000 LoC across crypto, handshake, session/AEAD, the per-direction packet-number rework, the **new** PhantomUDP transport / demux, connection migration + path validation, liveness, SACK/reliability, wire codec, API/FFI, `unsafe`, DoS/concurrency, ICMP/middlebox handling, traffic-analysis/metadata, forward secrecy, timing, supply chain.
- **Method:** **22-dimension** adversarial source-review fan-out (14 core + 8 added: ICMP, middlebox, state-confusion, fingerprinting, metadata, key-rotation, forward-secrecy, timing), followed by a **2-lens adversarial verification** (faithful-read + exploitability, refute-biased, each re-reading the actual code) of the deduplicated HIGH/MEDIUM set. Prior findings re-verified against current source.
- **Cost:** 22 finder agents + 30 verification agents (52 total), ~5.6M subagent tokens.
- **Predecessor:** builds on `docs/security/audit-report-2026-06-03.md` (1 Critical + 4 High). This audit verifies those fixes and audits the large post-2026-06-03 surface (PhantomUDP / migration / liveness / SACK / per-direction PN) that did not exist then.

> Severity reflects the **inner Phantom session** as the real security boundary. Network attacker = full wire control (inject/replay/reorder/drop/truncate/downgrade/flood) + source-address spoofing + ICMP spoofing + middlebox; an off-path attacker can observe/guess the plaintext 8-byte connection-ID (CID) and 4-tuples; an "authenticated peer" is admitted for reliability/data-plane attacks.

---

## Executive summary

**Overall risk rating: `needs-work` — but the previous ship-blocker is gone.**

The headline result is positive: **the prior CRITICAL (C1, AES-GCM nonce reuse via per-stream `u32` sequence wrap) is genuinely fixed.** The Phase-4 / P4.0 rework to a single **per-direction monotonic `u64` packet number** (`nonce = nonce_prefix(4) ‖ packet_number(8)`, drawn at send time for every packet including retransmits, with `epoch`/`stream_id`/`path_id` moved out of the nonce into the AAD) was verified sound across rekey and migration — there is no remaining path to a nonce collision. The prior Highs H2 (unsigned 0-RTT verdict), H3 (uncapped client PoW), H4 (slowloris) are fixed, as are WIRE-001/002, PATH-001, INFOLEAK-1, DOS-2/3 and the CRYPTO-2/3/4 hygiene items. The cryptographic/identity core remains strong: server-key pinning is mandatory, the transcript binds version + build-variant + the whole ClientHello incl. early-data, replay runs after AEAD, `unsafe` is governed by `#![deny(unsafe_code)]` with three audited, **sound** opt-ins, and **no memory-safety defect and no confidentiality/integrity/auth break was found** — connection migration's worst case is a redirection-DoS, never a hijack or decrypt (the QUIC §9 boundary), exactly as the project documents.

The weakness is, as in the prior audit, concentrated in the **data plane and DoS-resistance layers** — and specifically in the **new PhantomUDP transport** added since the last audit, which does not yet carry the resource-bounding and authentication-ordering discipline the handshake layer has:

1. **Pre-auth resource exhaustion on the PhantomUDP demux/data plane.** The per-CID `routes` map is unbounded (H-1), the 256 handshake slots are committed to a spoofed source before any address validation (H-2), and the receive-side reorder buffer is bounded by entry count but **not bytes** and escapes flow control entirely (H-3). Each is reachable cheaply by a spoofing/off-path or authenticated attacker and degrades or kills a server with modest effort.
2. **A few authentication-ordering gaps.** A forged **unencrypted empty-payload FIN** still tears down `open_stream()` streams (a residual of the prior H1 — the ACK path was authenticated but the standalone-FIN path was missed, M-2); the migration **candidate** is mutated from unauthenticated source addresses (M-1), and per-IP PoW reputation is both **bypassable** (attach any `resume_session_id`, M-5) and **poisonable** against a victim IP (pre-cookie `record_violation` on a spoofable source, M-4).
3. **Network-layer interactions the new UDP transport doesn't handle.** A single spoofed **ICMP** error tears down the connected client socket (M-6, the UDP analogue of a forged RST), and a **passive NAT rebind is not autonomously recovered** despite the documentation claiming it is (M-3) — both on the new migration/UDP surface.
4. **Documentation-honesty drift on the newest features.** The threat model's forward-secrecy section is stale (it says mid-session rekey "does not exist" while it ships) and the rekey ratchet's **no-post-compromise-security** property is undocumented (L-cluster); several plaintext header fields and the rekey/session master secrets' zeroization gaps are real-but-bounded and under-documented.

None of the new findings is a confidentiality/integrity/auth break, and there is no critical. **Recommendation: harden the PhantomUDP pre-auth DoS surface and close the FIN/candidate/reputation authentication-ordering gaps before any production/1.0 claim; the crypto core is in good shape.**

### Findings by severity (confirmed)

| Severity | Count | IDs |
|---|---|---|
| **Critical** | 0 | — |
| **High** | 3 | H-1 (routes-leak), H-2 (handshake-slot-exhaust), H-3 (reorder-OOM) |
| **Medium** | 8 | M-1 (migration-candidate), M-2 (FIN-teardown), M-3 (NAT-rebind), M-4 (reputation-poison), M-5 (reputation-bypass), M-6 (ICMP-teardown), M-7 (borsh-1MiB / fragment-assembler DoS), M-8 (async-lock MSRV) |
| **Low** | ~14 | SACK-storm, metadata/header cleartext cluster, no-padding length-leak, zeroize-master-secret cluster, rekey epoch/key TOCTOU, recv-counter-on-fail, rekey-catchup amplifier, FS doc-stale, cleartext magic-string, FFI inert-connect, PoW window 120s, liveness self-trip, keep-alive-PING gap, anti-amp budget reset |
| **Info / verified strengths** | many | C1-fixed, prior-H fixes, cardinality contract, unsafe soundness, data-plane panic-free, opaque-decrypt-failed, AEAD-gated liveness, redirection-not-hijack boundary |

---

## HIGH

### H-1 — Unbounded PhantomUDP demux `routes` map → pre-auth memory-exhaustion DoS
**Location:** `core/src/api/udp_listener.rs:154,183-187,199,206` · **Verdict: confirmed real (both lenses); severity high (slow-burn).**

`run_udp_demux` keeps `routes: HashMap<ConnId, mpsc::Sender>` keyed on the **unauthenticated, attacker-chosen** 8-byte CID. A fresh-CID `Initial` datagram inserts a route (`:199`) + spawns a handshake task; the **only** removal (`:184-185`) fires only when a *later* datagram for that exact CID arrives *and* `tx.is_closed()`. There is no sweep, no cap, no LRU, no TTL (the `% 256` GC at `:206` sweeps the *reputation* map, not `routes`). The 256-permit `inflight` semaphore bounds concurrent *tasks*, not total routes.

**Exploit:** an off-path attacker sprays single ~10-byte `Initial` datagrams, each a fresh random CID + garbage payload. Each leaks a permanent `routes` entry: the task fails `borsh::from_slice::<ClientHello>` (`listener.rs:408`) in microseconds, releasing its permit but never reaping the route (the attacker never reuses the CID). At commodity rates the map grows GB/hour with no recovery short of restart. Pre-auth, spoofable, no PoW.

**Fix:** reap on task completion (RAII `RouteGuard` that removes the CID on drop), and/or bound the map with stalest-eviction (as `FragmentAssembler` already does), and/or `routes.retain(|_, tx| !tx.is_closed())` on the existing `% 256` cadence.

### H-2 — PhantomUDP handshake-slot exhaustion via spoofed-source `Initial` datagrams
**Location:** `core/src/api/udp_listener.rs:193-201,222-233`; `core/src/api/listener.rs:407` · **Verdict: confirmed real (both lenses); high.**

On the first `Initial` for a new CID the demux acquires one of 256 `inflight` permits and spawns `drive_server_handshake` **before any address-validation round**. The task emits one cookie `Retry` and then blocks on `recv_bytes().await` for the cookie echo; for a spoofed source that echo never comes, pinning the permit for `HANDSHAKE_DEADLINE = 10s`. There is no per-source cap in the core listener (the server's `PerIpLimiter` runs only *after* a session is established).

**Exploit:** spoof 256 distinct-CID `Initial`s per burst → all permits held 10s → every legitimate `Initial` is dropped (`try_acquire_owned() == Err`). ~26 pkt/s (negligible bandwidth, no PoW, no connection state) keeps the listener permanently unable to accept new connections. The cookie gate stops forgery/amplification but not the slot hold.

**Fix:** run the stateless cookie/Retry round on the demux thread *before* allocating any per-connection slot (QUIC Retry shape): only acquire a permit + insert a route once a datagram carries a valid address-validation cookie. Add a per-source-IP cap on pending handshakes.

### H-3 — Receive reorder buffer is byte-unbounded and escapes flow control → receiver OOM
**Location:** `core/src/transport/stream.rs:23,929-939`; `core/src/api/session.rs:872-885,927-933,1936-1945` · **Verdict: confirmed real (both lenses); high.**

`Stream::recv_buffer` (out-of-order reliable segments keyed on the peer-chosen `stream_offset`) is bounded only by `MAX_RECV_REORDER = 2048` **entries**, with **no byte cap**. Flow-control credit and the `RECV_DELIVERY_HARD_CAP` / `undelivered_bytes` guard count only **in-order delivered** data; a "future hole" segment is buffered but never counted, never credited, never delivered until the gap fills — so the advertised window never closes and the session is never torn down. Entries are up to ~253 KiB (UDP) / 4 MiB (TCP) each, and the recv path auto-creates a `Stream` for any of 2³² `stream_id`s with **no `MAX_STREAMS` cap**.

**Exploit:** an authenticated/semi-compliant peer (admitted for reliability attacks) sends offsets `1..2048` (never `0`) on stream 0, repeats across `stream_id`s. Per stream this pins `2048 × frame_size` of unaccounted memory (≈128 MiB/stream at 64 KiB frames; multiples of GB at max frame size) while "honoring" flow control → receiver OOM/swap-thrash at modest bandwidth.

**Fix:** account reorder-buffered bytes in a per-stream + per-session budget tied to the advertised window; refuse to buffer a future hole past the window (drop → retransmit, which the "refused segment is not SACKed" contract already handles safely); fold reorder bytes into `RECV_DELIVERY_HARD_CAP`; cap concurrent receive streams (`MAX_STREAMS`).

---

## MEDIUM

### M-1 — Migration candidate is set from unauthenticated source addresses → migration-denial DoS (not a hijack)
**Location:** `core/src/api/udp_transport.rs:320-343,375-390`; `core/src/api/session.rs:1805-1812,1853-1865` · **Verdict: confirmed real; medium (the "hijack" claim was over-stated and refuted).**

`UdpServerTransport::recv_bytes` stamps the **single global** `candidate` (and resets the 3× anti-amp budget) from the unauthenticated source of any CID-matched datagram, *before* AEAD. `promote_candidate()` then switches `peer` to whatever `candidate` currently holds. **This is not a current hijack:** the data-pump reader is single-threaded and sequential (`recv_bytes` then `handle_packet` per datagram), so the legitimate `PATH_VALIDATION` echo's *own* `recv_bytes` sets `candidate = echo_src` immediately before `handle_packet` calls `promote_candidate` — the attacker cannot interpose. What an off-path attacker who knows the CID *can* do: spray spoofed CID datagrams to clobber the single candidate slot and reset the anti-amp budget, **misdirecting the server's `PATH_CHALLENGE`** away from the real migrating client and **stalling/denying the legitimate migration** (forcing it into `Migrating` → `Dead` → a full PQ re-handshake). It also leaves the `path_id` pinned in `Validating` with no timeout.

**Fortified note (latent HIGH):** correctness today is *emergent* from single-threaded recv, not enforced. Any future change that makes the reader concurrent or batched turns this into a real wrong-address peer switch (downstream blackhole/redirection).

**Fix:** register/refresh the candidate only from an **AEAD-authenticated** packet (inside `handle_packet` after `decrypt` succeeds), bind `promote_candidate(expected_src)` to the source that actually echoed the challenge (RFC 9000 §9.3), track candidates per-`path_id` (not one global slot), and add a per-path validation timeout.

### M-2 — Forged unencrypted empty-payload FIN tears down any `open_stream()` stream (residual of prior H1)
**Location:** `core/src/api/session.rs:1686-1696,1998-2000`; `multiplexer.rs:149`; `api/stream.rs:67-69` · **Verdict: confirmed real (both lenses); medium.**

The stripped-flag downgrade defense (`:1686`) drops unencrypted packets only when the payload is **non-empty**. An unencrypted packet with an **empty** payload takes the `else` branch (`plaintext = Vec::new()`), is not dropped, skips every flag branch, and reaches the standalone FIN check (`:1998`) `if flags.contains(FIN) { route_close(stream_id) }` with **no AEAD verification**. The only gate is the cleartext `session_id` guard, and `session_id` is plaintext-on-wire. Legitimate FINs are always `ENCRYPTED` (`send_app_data` ORs it in), so the fix is clean. The connectionless raw-app `recv()` (reserved stream 1, delivered via `deliver_tx`) is unaffected — only streams opened via `open_stream()` (ids 2+) are vulnerable; impact is spurious stream teardown, not confidentiality.

**Fix:** require `ENCRYPTED` for any FIN action — move the standalone-FIN `route_close` inside an `ENCRYPTED` guard, or drop **all** non-`ENCRYPTED` post-handshake packets regardless of payload length. Add a negative test (a forged unencrypted FIN with a valid `session_id` must not close a stream).

### M-3 — Passive NAT rebind is not autonomously recovered, contradicting PROTOCOL.md §12.1
**Location:** `core/src/api/session.rs:1853`; `core/src/transport/session.rs:807-836`; `docs/protocol/PROTOCOL.md:868-872` · **Verdict: confirmed real (both lenses); medium (correctness + doc).**

The server's challenge/swap is gated on the inbound packet's `path_id` being **not** `Validated`. A passive NAT rebind (no embedder `migrate()`) does **not** bump `path_id` (`next_migration_path_id` is only called from the `Migrate` command), so the client keeps stamping `path_id = 0`, which is permanently `Validated`. The server therefore skips the entire challenge block, never challenges the new source, never promotes — and keeps sending downstream to the dead old peer **forever**. PROTOCOL.md §12.1 explicitly claims a known-CID-from-new-source is handled "identically" for `migrate()` **and** passive NAT-rebind; that autonomous recovery does not exist.

**Fix:** make server detection **address-driven** for path 0 — when `recv_bytes` records a new source whose authenticated app data arrives on a `Validated` `path_id`, still challenge that source and promote on a validated echo (allocate an internal `path_id` for the new source, or gate the challenge on `has_migration_candidate()` rather than `path_state != Validated`). Then correct PROTOCOL.md §12.1.

### M-4 — Source-spoofed reputation poisoning of a victim IP (pre-cookie `record_violation`)
**Location:** `core/src/api/listener.rs:457,464`; `core/src/transport/handshake.rs:496-514`; `core/src/api/udp_listener.rs:190-201` · **Verdict: confirmed real (both lenses); medium.**

`process_client_hello` returns `Fail(ProtocolVariantMismatch)` / `Reject(unsupported_version)` **before** the cookie/PoW gate. `drive_server_handshake` charges `record_violation(peer.ip())` on both arms, and the UDP demux admits any first `Initial` with the datagram's spoofable source. So an attacker spoofing source = victim V, sending a ClientHello with a bad `protocol_variant`/`version`, charges violations to V; a few within the decay window escalate V's PoW difficulty up to `MAX_DIFFICULTY = 20`, forcing the legitimate client at V to solve ≈2²⁰-hash PoW per connect.

**Fix:** charge reputation violations only **after** IP-ownership is proven (after a valid cookie round); drop the pre-cookie variant/version-mismatch arms silently, or key escalation on cookie-validated identity.

### M-5 — Per-IP PoW reputation escalation nullified by attaching any `resume_session_id`
**Location:** `core/src/api/listener.rs:415-418`; `core/src/transport/reputation.rs:92-95` · **Verdict: confirmed real; medium (impact bounded — cookie gate intact).**

`has_ticket = client_hello.resume_session_id.is_some()` — **presence only**, with no check that the id names a cached ticket or that the binder verifies. `calculate_difficulty` short-circuits to `0` when `has_ticket` is true, *before* consulting the violation count. So a flagged abuser sets `resume_session_id` to 32 random bytes and pays **zero** PoW on an idle server, nullifying the per-IP escalation DOS-2 exists to impose. (The unknown id does **not** bypass the stateless cookie gate, so amplification/spoofing protection is intact — hence medium, not high.)

**Fix:** compute `has_ticket` from an actually-valid resume (post-binder/peek in `process_client_hello`), not from field presence.

### M-6 — Off-path connection teardown via one spoofed ICMP error on the connected client socket
**Location:** `core/src/api/udp_transport.rs:54-66,189-222`; `core/src/api/session.rs:941-943,1161-1164` · **Verdict: confirmed real (both lenses); medium.**

`UdpClientTransport` uses a **connected** UDP socket. On Linux a connected UDP socket surfaces a matching ICMP error (port/host/net-unreachable) as a fatal error on the next `recv()`. `recv_bytes` maps **every** recv error to `CoreError::NetworkError` with **no `ErrorKind` discrimination** (verified: zero `ErrorKind`/`raw_os_error` filtering anywhere in `core/src`); the data-pump reader does `Err(_) => break`, which tears the session down to `ConnectionState::Closed`, **bypassing the liveness state machine** (which would have gated death + offered migration). An off-path attacker who knows/guesses the client↔server 4-tuple spoofs one ICMP "port unreachable" → the session dies — the UDP analogue of a forged RST, the exact attack QUIC's advisory-only ICMP rule (RFC 8085 §5.5 / RFC 9000 §14.2) prevents. (Medium not high because it needs the client's ephemeral source port; the server side, using `recv_from` on an unconnected socket with `continue`-on-error, is not exposed.)

**Fix:** treat ICMP-induced recv errors as **advisory** — in `recv_bytes`, for `ConnectionRefused`/`HostUnreachable`/`NetworkUnreachable`/`ConnectionReset`, log + `continue` rather than returning `Err`; or route transport recv errors into the gated liveness/`Migrating` path instead of an instant `Closed`. Add a regression test (a client whose server port is dead must not transition to `Closed` on the resulting ICMP error).

### M-7 — Pre-auth memory/handshake DoS in the handshake decode + shared fragment reassembler
**Location:** `core/src/api/listener.rs:408`; `core/src/api/udp_listener.rs:160,177`; `core/src/transport/fragmentation.rs:83-96,135-143` · **Verdict: confirmed real; medium (two related vectors).**

(a) **Borsh 1 MiB eager allocate+memset:** the server decodes the first unauthenticated ClientHello with `borsh::from_slice` *before* any cookie gate; borsh's `Vec<u8>` deserializer does `vec![0u8; len.min(1 MiB)]` from a 4-byte on-wire length prefix *before* reading the body. A ~45-byte datagram (`ml_kem_pk` length prefix `0xFFFFFFFF`) forces a 1 MiB allocate+memset (~23,000× amplification). The **UDP handshake recv has no frame cap** (unlike the TCP `HANDSHAKE_FRAME_CAP` from the WIRE-001 fix). (b) **Single shared `FragmentAssembler` across all CIDs** (a known, code-commented Phase-2 weakness): an attacker spraying distinct-`(CID,packet_id)` first-fragments keeps all 256 slots fresh, **evicting legitimate clients' partial multi-fragment ClientHello reassemblies** before completion (handshake denial); `process_chunk` also overwrites an existing chunk with no check on a cleartext, guessable key, enabling targeted fragment poisoning (the reassembled frame fails the victim's AEAD → dropped). Both are bounded (no OOM) and AEAD prevents forgery, hence medium.

**Fix:** add a `MAX_HANDSHAKE_FRAME` cap (8–16 KiB) on the UDP demux/recv before borsh **and** bound each ClientHello `Vec<u8>` field to its real maximum; give each route/CID its own `FragmentAssembler` (the promised Phase-2 fix); make chunk insertion insert-if-absent; require a cookie/address-validation round before admitting fragmented `Initial` reassembly.

### M-8 — `async-lock` resolves to 3.4.2 (MSRV 1.85), breaking the promised MSRV 1.75; MSRV CI job absent
**Location:** `core/Cargo.toml:241-245`; `Cargo.lock`; `.github/workflows/*` · **Verdict: confirmed real; medium (build-integrity).**

The dependency requirement is `async-lock = ">=3, <3.5"` while the adjacent comment says it must be capped `<3.4` to hold MSRV 1.75 (`async-lock ≥3.4` needs rustc 1.85). The lock resolved `async-lock 3.4.2` (`rust-version = 1.85`); `3.3.0` (MSRV 1.60) is available under a correct cap. Compounding it: **no MSRV CI job exists** (no `1.75`/`@1.75` in any workflow) despite CLAUDE.md/`rust-toolchain.toml` claiming CI enforces 1.75. So an embedded integrator on Rust 1.75 building `--features embedded` against the lock gets a hard compile failure, uncaught.

**Fix:** tighten to `async-lock = ">=3, <3.4"`, `cargo update -p async-lock --precise 3.3.0`, commit the lock; add the missing `dtolnay/rust-toolchain@1.75` CI job so the MSRV promise is actually enforced.

---

## LOW (clustered; verified or self-assessed)

- **SACK `largest_acked` trusted → forced fast-retransmit storm bypassing cwnd** (`stream.rs` `on_sack`; `sack.rs` `from_wire`). An authenticated peer sets `largest_acked = high + 1e6` each SACK → sender declares the whole buffer lost and Pass-0 retransmits ignoring the congestion window + drives BBR `FastRecovery`. Bounded to the peer's own connection, nonce-safe (fresh PN per retransmit). **Fix:** clamp `largest_acked` to the highest offset actually sent.
- **Cleartext-header / metadata cluster** (documented header-protection gap): the 47-byte inner `PacketHeader` is AAD, not encrypted — `flags`, `stream_id`, `epoch`, `path_id`, and the per-direction `packet_number` are plaintext on every datagram, classifying each packet's purpose (REKEY/PATH_VALIDATION/WINDOW_UPDATE/FIN), leaking exact directional volume, and marking migration/rekey events. PROTOCOL.md §12.5 documents the PN/CID; the `flags`/`epoch`/`path_id` event channels are **not** enumerated. **Fix:** enumerate them; fold under the deferred QUIC-style header-protection phase.
- **No AEAD length-hiding padding** → ciphertext length ≈ plaintext length (request/response correlation, keystroke/voice fingerprinting); the implemented `framing.rs::apply_adaptive_padding` is dead/unwired on the PhantomUDP path. Fixed-size control frames (4 B WINDOW_UPDATE, 32 B PATH_VALIDATION) are individually size-classifiable. **Documented as out of scope** (threat-model LINDDUN-D) — flag the dead padding code + note the handshake-shape fingerprint.
- **Zeroization gaps on master secrets** (memory-disclosure FS): the handshake `shared_secret` and `Session.traffic_secret` (the rekey master from which all epochs derive) are **not** zeroized on drop (only `resumption_secret` is); previous-epoch `ring` AEAD round-keys are not zeroized; the `resumption_secret` is stored unzeroized ≤1h and not wiped on evict. This contradicts the threat-model claim "`ZeroizeOnDrop` on every key-bearing struct" and weakens past-epoch FS under a post-session memory disclosure (short of full endpoint root). **Fix:** zeroize `traffic_secret` in `Session::Drop`, wrap the handshake `shared_secret`/combined-KEM secret in `Zeroizing`, add `ZeroizeOnDrop` to `ResumptionTicket`; scope the doc claim to reality.
- **Rekey epoch/key TOCTOU** (`api/session.rs:1467` read-epoch vs `:1489` encrypt): a recv-side rekey-catchup can interleave so the header stamps epoch N but the body is sealed under N+1 → the peer drops it ("behind current epoch"); reliable data self-heals via ARQ, unreliable is lost. **Not** a nonce reuse. The in-code "single rekey owner / single writer owns the rekey lock" comments are inaccurate (the recv task is a second writer). **Fix:** stamp the header from the same `crypto.load()` guard used to encrypt; correct the comments.
- **`recv_counter` increments on FAILED decrypts** (`adaptive_crypto.rs:457-460`, before `open`): forged same-epoch packets advance the recv invocation counter toward the 2⁴⁸ `NonceExhausted` ceiling; impractical (2⁴⁸ ≈ 9 months at 10 M pps, and a peer rekey resets it) but undocumented. **Fix:** increment only after a successful open (or use a separate telemetry counter).
- **Rekey-catchup HKDF amplifier** (`session.rs:601-622`): a spoofed packet with `header.epoch = current+16` forces ~16–20 HKDF/blake3 ops before the AEAD trial fails (commit-only-on-success is sound). Bounded ~20× CPU amplifier, no per-source gate. **Fix:** gate the catchup branch on the `REKEY` flag; cache the next-epoch candidate; add a coarse per-source token bucket.
- **Forward-secrecy documentation stale + no-PCS undocumented** (`threat-model.md §8`): §8 says mid-session rekey is "blocked / does not exist" while it ships and is wired; and the rekey ratchet provides past-epoch FS but **no post-compromise security** (a symmetric HKDF ratchet injects no fresh entropy) — undocumented. **Fix:** rewrite §8 (rekey is shipped; the ratchet gives past-epoch FS only, no break-in recovery; FS recovery needs a re-handshake).
- **Cleartext `phantom-default-1` magic string** in every ClientHello — a zero-false-positive DPI signature. *Already documented as cleartext in PROTOCOL.md §6.7*, and the whole PQ ClientHello is already trivially fingerprintable, and DPI-resistance is an explicit non-goal — so this is a doc-completeness + trivial-hardening item, not a security bug. **Fix:** note it in the threat-model DPI row; optionally replace the ASCII tag with a 1-byte enum.
- **FFI `connect()` returns a permanently-inert, transport-less session** that silently black-holes `send()` (APIFFI-02, still-open). **Fix:** mark deprecated / return an error, or wire a transport.
- **PoW stateless-challenge window is 120 s, not the documented 60 s** (widens cheap solution-replay). **Resume-path timing** distinguishes "ticket cached" vs "absent" (presence oracle on a plaintext `resume_session_id`). **Liveness** is one-directional (a passive/idle receiver can't detect a dead path) and an on-path drop can cheaply force a healthy session into `Migrating`/`Dead` (within the model, no hysteresis). **No keep-alive PING** → idle sessions die on a middlebox NAT-timeout. **Anti-amp budget resets per candidate source** (re-armable 3× headroom). **`WasiLeg`** uses `std::sync::Mutex` whose poisoning turns one in-flight panic into a permanent leg-wide panic.

---

## INFO / verified strengths (positive results)

- **C1 (prior CRITICAL nonce reuse) — genuinely retired.** Per-direction `u64` PN drawn at send time for every packet (incl. retransmit), never reset on rekey/migration, with a per-epoch fresh `nonce_prefix` → `(key, nonce)` globally unique. No nonce-collision path found.
- **Prior Highs H2/H3/H4 and WIRE-001/002, PATH-001, INFOLEAK-1, DOS-2/3, CRYPTO-2/3/4 — fixed and verified.** (H1 is *partially* fixed — see M-2.)
- **No memory-safety defect; all three `unsafe` opt-ins sound; the new PhantomUDP/migration/SACK data plane is panic-free under attacker input.**
- **Migration confidentiality/integrity/auth boundary is sound** — every state-mutating control frame (ACK/WINDOW_UPDATE/PATH_VALIDATION/REKEY) is processed only after a successful AEAD open; the `session_id` guard drops cross-session frames; the worst migration outcome is redirection-DoS, **never** hijack or decrypt (the QUIC §9 boundary, matching the project's honest doc claim).
- **Liveness `update_activity` is strictly AEAD-gated** — forged/replayed/plaintext packets cannot refresh or reset the liveness timer (verified safe).
- **Observability cardinality contract upheld** (no `peer_ip`/`session_id`/`stream_id` labels); **INFOLEAK-1 redaction correct**; logs/tracing are PII-disciplined; the "single opaque decrypt failed" claim holds at the AEAD layer (the replay-vs-AEAD distinction is by design and reveals nothing key-relevant).
- **ICMP PMTU manipulation not exploitable** (fixed 1200-byte MTU, no PMTU discovery).

---

## Delta vs. the 2026-06-03 audit

| Prior | Now |
|---|---|
| **C1 (Critical)** nonce reuse | ✅ **Fixed** (per-direction u64 PN) — the ship-blocker is gone |
| H1 (forged ACK/FIN) | ⚠️ **Partial** — ACK authenticated; **FIN path still unauthenticated** (M-2) |
| H2 (unsigned 0-RTT verdict), H3 (PoW cap), H4 (slowloris) | ✅ Fixed |
| WIRE-001/002, PATH-001, DOS-2/3, LEGS-*, `networks/` layer, INFOLEAK-1, CRYPTO-2/3/4 | ✅ Fixed / deleted |
| SUPPLY-01 | ◐ Partial · **SUPPLY-02** ✅ · **SUPPLY-03** ✗ still-open · **SUPPLY-04** ✗ regressed (dead `deny.toml` ignore, wrong rationale) |
| — | **New** (post-2026-06-03 PhantomUDP/migration/liveness surface): H-1, H-2, H-3, M-1…M-8 and the LOW cluster |

The pattern is the same one the prior audit named: **the data plane lags the handshake layer's discipline** — only now the data plane is the new native UDP transport, and the gaps are pre-auth resource-bounding + a few authentication-ordering misses rather than the prior nonce/control-auth breaks.

---

## Attack chains

- **Pre-auth listener wipeout** [H-2 + H-1 + M-7]: spoof 256 `Initial`s/burst to pin all handshake slots (H-2) while leaking unbounded `routes` entries (H-1) and 1 MiB borsh allocations / evicting legit fragment reassemblies (M-7) — a single cheap spoofing source denies the whole PhantomUDP listener pre-authentication and grows its RSS until OOM.
- **Off-path session kill** [M-6]: one spoofed ICMP "port unreachable" tears down a healthy client session, bypassing the liveness/migration machinery (forged-RST analogue).
- **Migration denial → forced re-handshake** [M-1 + M-3]: clobber the single global migration candidate from a spoofed source to stall a legitimate `migrate()` into `Dead`; and a routine passive NAT rebind is never recovered at all (M-3) — both break the advertised seamless-migration property on the most common mobile events.
- **Per-IP DoS-throttle defeat** [M-4 + M-5]: poison a victim IP's PoW difficulty with spoofed pre-cookie violations (M-4) while nullifying your own escalation by attaching a junk `resume_session_id` (M-5).
- **Authenticated-peer receiver OOM / retransmit storm** [H-3 + SACK-storm]: a compliant-looking peer pins gigabytes of reorder buffer (H-3) and/or forces a cwnd-bypassing retransmit storm via a bogus `largest_acked`.

---

## Prioritized remediation roadmap

1. **Bound the PhantomUDP pre-auth surface (the new ship-gate for production/1.0):** reap/cap `routes` (H-1); cookie-before-slot + per-source cap (H-2); per-CID `FragmentAssembler` + a UDP handshake frame cap + per-field borsh caps (M-7).
2. **Close the receive-side memory escape:** account reorder-buffer bytes against the advertised window + `MAX_STREAMS` (H-3); clamp SACK `largest_acked` (LOW).
3. **Authentication-ordering fixes:** require `ENCRYPTED` for FIN (M-2); register/promote the migration candidate only from AEAD-authenticated sources, bound to the challenged address (M-1); fix `has_ticket` validity (M-5) and move `record_violation` past cookie validation (M-4).
4. **Network-layer robustness:** treat ICMP as advisory (M-6); make passive NAT-rebind autonomously recoverable on path 0 (M-3).
5. **Build integrity:** cap `async-lock < 3.4`, repin the lock, add the missing MSRV-1.75 CI job (M-8); cfg-gate non-FIPS crypto out of `fips` (SUPPLY-03); fix the `deny.toml` ignore (SUPPLY-04).
6. **Hardening + honesty:** zeroize the rekey/handshake master secrets and the resumption ticket (LOW); rewrite threat-model §8 (rekey is shipped; ratchet = past-epoch FS only, no PCS); enumerate the cleartext header event channels; gate the rekey-catchup on the REKEY flag; stop counting failed decrypts toward `NonceExhausted`.

---

## Methodology note

22 parallel finder agents (each reading the real source under a defined adversary model and re-verifying every relevant prior finding) produced 83 raw findings; cross-dimension duplicates were consolidated; the resulting HIGH/MEDIUM set was put through a 2-lens adversarial verification (faithful-read + exploitability, each re-reading the cited code and biased to refute). No finding survived as a confidentiality/integrity/auth break; one HIGH "connection hijack" claim was correctly refuted to a MEDIUM migration-denial DoS by reading the single-threaded reader's ordering. Severities in this report reflect the post-verification consensus.
