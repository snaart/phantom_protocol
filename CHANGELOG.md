# Changelog

All notable changes to this project will be documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
once it reaches 1.0.0. Pre-1.0 releases may have breaking changes between minors.

## [Unreleased]

### Added

- **Liveness — autonomous dead-path detection (Phase 4 / P4.3):** the SDK now notices a **silently-dead
  path** on its own — no inbound for N×PTO while reliable data is outstanding — and surfaces
  `ConnectionState::Migrating` so the embedder can `migrate()`; the session is held alive (keys retained,
  outbound buffered + retransmitted) rather than torn down. With no recovery (a `migrate()`, or the path's
  return) before a migration-idle timeout it transitions to the terminal `ConnectionState::Dead` and
  `recv()` errors instead of hanging. Detection is read-only over existing signals (BBR in-flight + an
  inbound-activity timer) and runs on both peers via the shared data pump, so a server detects a vanished
  client symmetrically. Two new `ConnectionState` variants (`Migrating`, `Dead`) → bindings regenerated.
  Thresholds (default ~1s-to-down / 30s-to-dead) are overridable; **no wire change**. Keep-alive PINGs for a
  purely-passive (download-only) path are deferred.
- **Seamless connection migration (Phase 4 / P4.1–P4.2):** a live PhantomUDP session now survives a
  client network change (Wi-Fi↔cellular, NAT rebind) **without re-running the post-quantum handshake** —
  the connection loses throughput briefly, never liveness. The embedder triggers it via the new
  `PhantomSession::migrate(local_addr)` (FFI-exported, best-effort, non-blocking): the client rebinds its
  UDP socket (keeping the old one for the overlap — broken-rebind safety) and stamps a fresh client-owned
  `path_id`; the server detects the new source, validates it with a `PATH_CHALLENGE` (anti-amplification-
  capped, RFC 9000 §8.2), then atomically switches its peer and resets the RTT / congestion estimators for
  the new network (QUIC §9.4). Keys and the session id persist; the reliable byte stream resumes
  byte-exact. No wire-format change — `path_id` already rode the 47-byte header and left the AEAD nonce
  under model ①. PATH-001 is split into a strict send-gate (app data only to validated paths) and a
  relaxed recv-delivery (authenticated, non-replayed data is delivered regardless of source), so a
  NAT-rebind upload is seamless. Header protection (below, T4.6) now masks the variable per-packet
  metadata, but migration stays **linkable via the stable connection-ID**; CID rotation — the remaining
  piece of unlinkable migration — is a later hardening phase.
- **PhantomUDP (Phase 1):** native datagram `SessionTransport` over raw UDP with connection-ID
  demultiplexing — `PhantomUdpListener` (server accept) plus `UdpClientTransport` / `UdpServerTransport`.
  The multi-KB post-quantum handshake is fragmented to the path MTU and reassembled. No wire-format or
  crypto change — `WIRE_VERSION` / `PROTOCOL_VERSION` unchanged; the outer UDP envelope is transport framing.

### Security

- **Header protection (T4.6 — QUIC RFC 9001 §5.4):** the 14 variable header bytes — packet number, flags
  (incl. the `PRIORITY`/voice bit), stream id, rekey epoch, and migration path id — are now **XOR-masked on
  the wire**, leaving only `version` + `session_id` (the routing CID) cleartext. A passive on-path observer
  can no longer read per-packet metadata. Per-direction header-protection keys are derived once from the
  initial session secret and held **session-stable** (they do NOT rotate on rekey — QUIC §6.1, because the
  epoch lives inside the masked span); the mask is `AES-256-ECB(hp_key, sample)` (AES suite) or a ChaCha20
  keystream (ChaCha suite), keyed by the AEAD ciphertext sample. The AEAD AAD remains the cleartext header,
  so a masked-region tamper fails decryption — **no new oracle**. Under `--features fips` the AES mask
  routes through `aws-lc-rs` ECB. This is the first half of the §12.5 traffic-analysis hardening; CID
  rotation (the stable-CID residual) follows in a later phase.
- **Packet `extensions` are now authenticated (T4.1):** the forward-compat TLV headroom was previously
  outside the AEAD AAD — an on-path attacker could rewrite it without breaking the tag. The AAD is now
  `header ‖ extensions`. Empty on every current packet, so no wire/vector drift.
- **X-Wing-style hybrid-KEM combiner (T4.2):** the KEM combiner now binds the classical ciphertext and the
  recipient classical public key into the shared-secret derivation (per draft-ietf-tls-hybrid-design /
  X-Wing), so its security no longer leans on the transcript signature alone.
- **Fail-closed on `reliable_offset` exhaustion (T4.5):** `Stream::send_reliable` returns `Result` and fails
  closed (rather than wrapping the `u32` gap-free reliable offset) at exhaustion, mirroring epoch saturation.

### Changed

- **`WIRE_VERSION` 3 → 4 (T4.6):** the 47-byte packet header is reordered so the 14 HP-protected bytes form
  a contiguous `[33..47]` span, and that span is masked on the wire (above). Interop-breaking, but no
  deployed peers (pre-1.0 0.2.0 window). Frozen wire vectors + the independent Python decoder regenerated.
- **`ServerHello` shrunk ~1.1 KB + `PROTOCOL_VERSION` 2 → 3 (T4.3):** the unused `server_key_package` (a full
  ML-KEM key package whose secret was discarded) is replaced by a 32-byte `server_nonce` (still
  transcript-bound). Handshakes across the version boundary cannot interoperate.
- **Explicit server-reply discriminant (T4.4):** `ServerReply{Hello,Retry,Reject}` is framed as
  `[kind:u8] ‖ borsh(body)`, so the client dispatches on an explicit tag instead of trial-deserialization +
  size heuristics. Framing sits outside the borsh structs, so the frozen handshake vectors are unaffected.

### Fixed

- Graceful session shutdown (outer handle drop or `disconnect()`) now flushes buffered `send()` data to the
  peer before closing, instead of potentially dropping a payload handed to `send()` immediately before
  shutdown. Affects all transports.

### Removed

- Retired the C1 per-stream sequence rekey watermark (`SEQ_REKEY_WATERMARK` /
  `set_seq_rekey_watermark` / `stream_seq_needs_rekey`): a `u64` packet number cannot wrap within a
  session, so the forced-rekey crutch is gone. Also removed the now-unwired `ReplayProtection` helper and
  the dead unencrypted `Session::create_control_packet` stub.
- **Removed the unwired `TransportLeg` multipath cluster** — `transport/legs/{kcp,tcp,faketls}.rs`,
  the `TransportLeg` trait, and `transport/virtual_socket.rs` — plus the `kcp-tokio` dependency and
  the `kcp_integration` test. These were never wired into the `PhantomSession` data plane (which
  consumes `SessionTransport`, not `TransportLeg`) and are superseded by an in-development native
  reliable-UDP transport (PhantomUDP). The `fragmentation` / `compression` / `device_profile`
  building blocks are retained for integration into that work. FakeTLS-style HTTP traffic mimicry
  will return as a dedicated transport mode. No change to the live data plane, wire format, or crypto.

### Changed

- **PhantomUDP (Phase 4 / P4.0):** the AEAD packet identity moved to a single per-direction monotonic
  `u64` **packet number** (model ①), replacing the per-stream `u32` `sequence`. `WIRE_VERSION` bumped
  **2 → 3**: the 47-byte `PacketHeader` drops the dead `ack_delay` field and widens `sequence` (u32) to
  `packet_number` (u64); the AEAD nonce is now `nonce_prefix ‖ packet_number` (`epoch` / `stream_id` /
  `path_id` remain in the authenticated 47-byte AAD but leave the nonce). Anti-replay is now a single
  per-direction sliding window on the packet number. **Interop-breaking** vs. 0.1.x (batched into the
  upcoming 0.2.0). Reliable in-order delivery is unaffected — it keys on the A.5 `stream_offset`, not the
  wire packet number.
- Documentation & branding cleanup: replaced lingering old-brand prose
  ("Phantom Transport Core", "Phantom Universal Transport") and standalone
  "Phantom" product references with the "Phantom Protocol" brand across the docs
  and source-level doc-comments. Comments/prose only — no code, API, wire-format,
  or crypto change.

### Security

- **PhantomUDP pre-auth DoS hardening (post-audit Tier 1).** Closes the pre-authentication
  resource-exhaustion surface on the native UDP transport found in the 2026-06-11 security
  audit. No wire-format or crypto change.
  - *Demux route table (H-1):* the per-CID `routes` map is now bounded and self-reaping
    (a hard cap + reclaiming a route as soon as its handshake task finishes), so a fresh-CID
    garbage spray can no longer leak one permanent entry per datagram.
  - *Address validation before state (H-2):* the stateless cookie/Retry round now runs on the
    demux thread **before** any per-connection slot (inflight permit + route + task) is
    committed, so a spoofed source can never pin a handshake slot; plus a per-source-IP
    pending-handshake cap. (0-RTT-over-UDP completes a cookie round first; TCP is unchanged.)
  - *Receive memory (H-3):* the out-of-order reorder buffer is now bounded by **bytes**
    (tied to the flow-control window) rather than entry count, and concurrent receive streams
    are capped (`MAX_STREAMS`), so a peer leaving the stream head missing cannot pin unbounded
    receiver RAM. New `PhantomUdpListener::active_route_count()` and `Stream::recv_reorder_bytes()`.
  - *Handshake decode (M-7):* a `ClientHello` whose borsh length prefixes are forged is now
    rejected by a non-allocating structural pre-check before `borsh::from_slice`, removing the
    ~45-byte → 1 MiB allocate+memset amplifier; fragment reassembly is insert-if-absent.
  - The always-on `security_invariants` negative-test suite is now part of the CI `test` gate.
- **Data-plane authentication-ordering (post-audit Tier 2).** Closes the authentication-ordering
  and migration-integrity gaps found in the 2026-06-11 audit. No wire-format or crypto change.
  - *Forged FIN (M-2):* **all** unencrypted post-handshake packets are now dropped — including an
    empty-payload one — so a forged unencrypted `FIN` can no longer tear down an `open_stream()`
    stream without AEAD verification (Invariant 2 strengthened).
  - *Migration candidate (M-1):* the migration candidate (the server's `PATH_CHALLENGE` target)
    is registered only from an **AEAD-authenticated** source, so a spoofed CID-matched datagram
    can no longer clobber the slot and stall a legitimate migration.
  - *Per-IP DoS reputation (M-4, M-5):* a pre-cookie protocol-variant / version mismatch no
    longer escalates a (possibly spoofed) IP's PoW difficulty, and the per-IP difficulty
    reduction for "ticket holders" now requires a **valid** resume (cached ticket + verified
    binder), not mere presence of a `resume_session_id`.
  - *Injected `ServerReject`:* an injected reject during a healthy handshake no longer aborts it —
    the client remembers it and keeps waiting for a valid `ServerHello`.
- **Network-layer robustness (post-audit Tier 3).** No wire-format or crypto change.
  - *ICMP advisory (M-6):* a single ICMP-induced recv error on the connected client UDP socket
    (`ConnectionRefused` / `ConnectionReset`, plus host/net-unreachable by errno on Linux) — the
    UDP analogue of a forged RST — is now treated as **advisory** (logged + retried), not a fatal
    error that tears the session down bypassing liveness (RFC 8085 §5.5 / RFC 9000 §14.2).
  - *Passive NAT-rebind (M-3, doc):* `docs/protocol/PROTOCOL.md` §12.1 no longer claims a passive
    NAT-rebind and a deliberate `migrate()` are recovered identically — the rebind's upload is
    delivered and the session survives, but autonomous downstream re-pointing on path 0 is a
    documented planned fix (the candidate is already registered only from an authenticated source).
- **Crypto / transport hygiene (post-audit Tier 5).** No wire-format change.
  - *Rekey margin (T5.3):* the automatic-rekey soft watermark drops from `2^47` to `2^32` for
    clean CFRG / QUIC standards alignment (defense-in-depth; far above any realistic session).
  - *SACK clamp (T5.4):* a SACK's `largest_acked` is clamped to the highest stream-offset
    actually sent, so an authenticated peer can't inflate it to force a cwnd-bypassing
    retransmit storm against fresh in-flight segments.
  - *AEAD recv counter (T5.5):* a failed (forged) AEAD open no longer advances the per-direction
    recv invocation counter toward the `NonceExhausted` ceiling — only an authenticated open counts.

### Changed

- **MSRV raised to Rust 1.93** (from 1.75). The post-quantum dependency chain (`pkcs8 0.11` via the
  ML-KEM / ML-DSA / signature crates) requires Cargo's `edition2024` feature (stable from Rust 1.85),
  so the prior 1.75 claim was already unenforceable. 1.93 is now declared in `rust-version` /
  `.clippy.toml` and enforced by a new `cargo check (MSRV 1.93)` CI gate; the temporary
  `async-lock < 3.4` MSRV cap is removed (now tracks 3.4.x).
- **Target threat model recorded (`SECURITY.md`):** TLS-like guarantees **plus** resistance to
  traffic-analysis linkability (unobservability). Header protection (encrypting the packet number
  + variable header fields) and connection-ID rotation are a core pre-1.0 requirement for the next
  wire revision; the current cleartext header (linkable) is documented as a known gap being closed.

## [0.1.1] - 2026-06-09

### Changed

- Crate `description` reworded to drop the legacy "Core" branding and lead with
  the post-quantum primitive set.
- Added a crate-level `core/README.md` (rendered on crates.io / docs.rs) wired in
  via the `readme` manifest field, plus badges and a crates.io install section in
  the repository README.
- Refreshed documentation version references — server / CLI / Helm `appVersion` /
  packaging / WASI examples — from the pre-rename `0.3.0` (and a stray `0.2`) to
  the current `0.1.x` series. Docs-only; no code, wire-format, or crypto change.

## [0.1.0] - 2026-06-09

### Changed

- **Renamed the crate `phantom_core` → `phantom-protocol`** for the first public
  release on crates.io (the `phantom_core` / `phantom-core` name was already taken
  by an unrelated crate). The Rust import path is now `phantom_protocol`, the
  crates.io package is `phantom-protocol`, and the UniFFI namespace plus the
  generated Swift / Kotlin / Python / C bindings move from `phantom_core` to
  `phantom_protocol`. No wire-format or crypto change (`WIRE_VERSION` 2 /
  `PROTOCOL_VERSION` 2 unchanged; the frozen wire vectors and CAVP KATs pass
  unmodified). First versioned release; supersedes internal pre-1.0 development
  under the old name.

### Security

- **C1 (critical): AES-GCM nonce reuse from per-stream sequence wrap — fixed.**
  The AEAD nonce is `(epoch, stream_id, sequence, path_id)` where `sequence` is a
  per-stream `u32`. The only mid-session rekey trigger keyed off the
  *direction-wide* invocation counter (`REKEY_SOFT_LIMIT = 2^47`), so a single
  high-throughput stream could wrap its `u32` sequence (≈`2^32` packets) and
  repeat a `(key, nonce)` pair — the catastrophic GCM nonce-reuse / Forbidden
  Attack condition — long before any rekey fired. The send path now also forces a
  rekey once any stream's sequence advances past a per-stream watermark
  (`SEQ_REKEY_WATERMARK = 2^31`) within the current epoch, bounding each stream's
  per-epoch sequence span to half the wrap distance; if the `u8` epoch saturates,
  the send fails closed (reconnect) rather than wrap. No wire-format change
  (`WIRE_VERSION` stays 2; frozen wire vectors unchanged). Pinned by
  `security_invariants.rs` (`single_stream_seq_watermark_forces_rekey_before_wrap`,
  `seq_watermark_fails_closed_at_epoch_saturation`) and a `property.rs` invariant
  (`no_nonce_repeats_across_forced_rekeys`). See PROTOCOL.md §5.

- **H1 (high): forged unauthenticated ACK/FIN injection — fixed.** ACK/FIN frames
  were processed *before* the AEAD gate and trusted the plaintext `header.sequence`,
  and the receive path never checked `header.session_id`, so an on-path attacker
  could inject forged ACKs to silently drop never-acknowledged reliable segments
  (data loss/truncation), restore flow-control permits, poison the BBR estimator,
  or tear down streams with `ACK|FIN` — all without breaking the AEAD on
  application data (Invariant 2). ACKs are now **authenticated `ENCRYPTED | ACK`
  control frames**: the acked data sequence travels in the AEAD payload (4 bytes,
  big-endian), the handler acts on it only after AEAD verify, and every inbound
  frame is dropped unless its `header.session_id` matches the negotiated session.
  The ACK's own `header.sequence` is drawn from the acker's per-stream send counter
  (shared with its data/`WINDOW_UPDATE` sends) so the AEAD nonce never collides, and
  it obeys the C1 rekey discipline. No `PhantomPacket`/header layout change (only
  ACK flags + payload), so frozen wire vectors are unchanged. Pinned by
  `api::session::tests::{forged_plaintext_ack_does_not_retire_pending_segment,
  authenticated_ack_retires_pending_segment, ack_with_wrong_session_id_is_dropped}`.

- **H2 (high): 0-RTT verdict `early_data_accepted` now transcript-signed — fixed.**
  `ServerHello.early_data_accepted` was not covered by the signed handshake
  transcript, so an on-path attacker could flip it (signature still verified):
  `true→false` made the client re-send already-delivered early-data over the
  1-RTT session (duplication/replay of non-idempotent requests), `false→true`
  silently black-holed rejected early-data while reporting success (Invariant 9).
  The verdict is now the final field of the signed `HandshakeTranscript`, so a
  flipped bit fails the client's signature check.

- **HS-03 (low) + ZERORTT-2 (low): resumption ticket-burning DoS — fixed.**
  A resume now carries a `resumption_binder` proof-of-possession (a keyed PRF
  over `resumption_secret ‖ resume_session_id ‖ nonce`, label
  `phantom-resume-binder-v1`) that the server verifies **constant-time before**
  consuming the one-shot ticket — a passive observer that copied only the
  cleartext `resume_session_id` can no longer burn a victim's ticket (HS-03). The
  ticket is consumed eagerly (race-free, so a duplicate resume can't double-accept
  early-data) and **re-inserted with its original expiry on any post-consume
  handshake failure** (e.g. a corrupted KEM ciphertext), so a malformed resuming
  `ClientHello` can no longer burn the ticket either (ZERORTT-2).

- **Wire: `PROTOCOL_VERSION` 1 → 2 (breaking handshake interop).** H2 and HS-03
  both change the signed transcript / `ClientHello` layout, so v1 and v2 peers
  cannot interoperate. `WIRE_VERSION` is unchanged (the `PhantomPacket` codec is
  untouched). Frozen `client_hello_*.bin` + `transcript_hash.bin` regenerated and
  re-verified byte-exact by the independent Python decoder; `server_hello*.bin`
  unchanged. Pinned by `security_invariants.rs::{flipped_early_data_accepted_bit_fails_signature,
  binderless_resume_does_not_burn_ticket, failed_resume_handshake_leaves_ticket_usable}`.

- **H3 (high): client PoW difficulty cap + bounded solver — fixed.** The client
  solved whatever PoW difficulty an *unauthenticated* `HelloRetryRequest`
  demanded, in an unbounded loop — so a MITM (or malicious server) could inject
  `difficulty = 255` and pin a client CPU core indefinitely (~2^255 hashes),
  pre-authentication. The client now rejects any difficulty above
  `MAX_CLIENT_POW_DIFFICULTY = 24` (strictly above the server's max legitimate
  tier) **before** solving, and `PoWChallenge::solve` is iteration-bounded
  (`MAX_SOLVE_ITERATIONS = 2^32`), returning a typed error rather than looping.
  `PoWChallenge::solve` now returns `Result<PoWSolution, PowError>` (a pre-1.0
  Rust-API change). No wire change.

- **CRYPTO-2 / HS-04 (low): constant-time PoW/cookie MAC compare — fixed.**
  `PoWChallenge::verify` compared the server-keyed challenge MAC with a
  short-circuiting `!=`, leaking via timing how many leading MAC bytes an
  attacker guessed. It now uses `subtle::ConstantTimeEq`, matching the cookie /
  path-validation compares. (Folded into the H3 `crypto/pow.rs` change.)

- **H4 / DOS-1 (high): slowloris — in-library handshake timeout + decoupled
  accept loop — fixed.** `PhantomListener` drove each handshake inline in
  `accept()` with no timeout, so a peer that opened a connection and stalled (or
  dribbled bytes) hung the handshake — forever for FFI embedders, up to the
  reference server's 30s `accept()` timeout — and the serial accept loop meant
  one stalled connection blocked all other clients. Now a background acceptor
  task owns the socket and drives each handshake in its **own task bounded by a
  10s in-library deadline** (via the `Runtime` clock, so `bind_with_runtime` and
  wasm/embedded runtimes are honored); `accept()` returns the next *completed*
  session from a bounded queue. A stalled/slow/failed handshake therefore never
  blocks accepting or returning other clients. Concurrent in-flight handshakes
  are bounded by a dedicated semaphore (`MAX_INFLIGHT_HANDSHAKES = 256`, distinct
  from any established-session cap). `accept()`'s signature and the
  `ConnectionClosed`-on-shutdown contract are unchanged (no FFI break); a
  handshake failure is now dropped server-side (logged + recorded) rather than
  surfaced as an `accept()` error.

- **DOS-4 (low): cap server-side cookie/PoW Retry rounds.** A peer that keeps
  triggering `Retry` without satisfying the gate is dropped after
  `MAX_SERVER_RETRY_ROUNDS = 2` rather than occupying the handshake indefinitely.

- **HS-02 (medium): cap client HelloRetryRequest rounds + bound the client
  handshake.** A MITM answering every `ClientHello` with a fresh cheap
  `HelloRetryRequest` could loop the client forever. The client now caps retries
  at `MAX_CLIENT_RETRY_ROUNDS = 3` and wraps the whole handshake in a 10s
  deadline (via the `Runtime` clock), so a silent or stalling server can no
  longer hang `connect`. Pinned by `client_handshake_caps_retry_rounds` and the
  `tcp_integration_stalled_peer_does_not_block_accept` integration test.

- **WIRE-001 (medium): length-prefix memory amplification — fixed.** The
  length-prefixed receive path pre-allocated and zeroed the full *declared* frame
  length before reading the body, so a peer could send the 4 bytes `0x01000000`
  (declaring 16 MiB) and stall, forcing a ~16 MiB commit per connection — a
  ~4,000,000× amplification reachable pre-authentication on the very first frame.
  The receive path now reads **incrementally in ≤64 KiB chunks** (a stalled peer
  commits at most one chunk, not the declared length) and applies a **phase-gated
  cap**: a tight 64 KiB during the unauthenticated handshake (a `ClientHello`,
  even with a 16 KiB 0-RTT blob, is well under it), raised to 4 MiB once the
  session is established (down from 16 MiB) via a new defaulted
  `SessionTransport::set_frame_phase` called at the handshake → data-pump
  boundary. Applies to `TcpSessionTransport` and the WASI leg.

- **LEGS-003 (medium): sticky recv accumulator — fixed.** The persistent recv
  accumulator never shrank, so a single large frame pinned its buffer for the
  connection's life. It is now reset to baseline (`RECV_BUF_INITIAL_CAPACITY`)
  after any frame larger than 256 KiB. Pinned by
  `tcp_transport::tests::{handshake_phase_rejects_oversized_frame,
  established_phase_accepts_large_frame_and_resets_accumulator}`.

- **LEGS-002 (medium): KCP leg pre-allocation — fixed.** The KCP leg allocated
  the full declared length (up to 10 MiB) before reading the body and had no read
  timeout. It now reads incrementally, caps frames at 4 MiB, and bounds the read
  with a 30s timeout (terminal for the leg on expiry).

- **DOS-2 (medium): per-IP PoW escalation wired (was dead code) — fixed.** The
  `ReputationTracker` was never wired into the live handshake, so the only
  establishment-cost gate was the *global* load tier (0 PoW below 100
  handshakes/min, identical for every IP) — an abusive source could not be
  singled out and a low-and-slow attacker paid nothing while forcing full
  ML-KEM/ML-DSA work per handshake. It is now wired into the server handshake as
  `difficulty = max(global_tier, per_ip_escalation)`: a clean IP (or
  resumption-ticket holder) adds **0** (well-behaved clients stay 1-RTT when the
  server is idle), while an IP with recent handshake violations pays an
  escalating PoW (capped at difficulty 20). Violations are recorded on genuine
  protocol failures (retry-round-cap exceeded, version/variant reject, fail) and
  cleared on a successful handshake. The per-IP map is **bounded**
  (`max_entries = 100_000`, evict-on-overflow + periodic GC) so wiring it cannot
  turn a CPU-DoS into a memory-DoS. Also fixed a latent shift-overflow in the
  escalation formula (`1 << (violations - 1)` for a large violation count). No
  wire change. Pinned by `reputation::tests::*` and
  `handshake::tests::reputation_wiring_escalates_and_resets_per_ip`.

- **INFOLEAK-1 (low): `ResumptionHint` Debug leaked the secret — fixed.**
  `ResumptionHint` (a UniFFI-exported type that crosses the FFI boundary) derived
  `Debug`, printing its 32-byte `resumption_secret` — so a mobile/FFI consumer
  logging it with `{:?}` would emit the live 0-RTT key material. It now has a
  hand-written redacting `Debug` (`resumption_secret: "REDACTED"`), mirroring
  `HybridSigningKey`/`HybridSecretKey`. ABI-safe (UniFFI needs no `Debug`). Pinned
  by `resumption_hint_debug_redacts_secret`.

- **CRYPTO-3 (low): zeroize transient key material.** The combined hybrid-KEM
  HKDF input (`[ecc, pq].concat()`) and the per-direction AEAD key locals
  (`combine_secrets`, `CryptoSession::build`, `AesSession::build`) were dropped
  without zeroizing — only the long-term key structs were `ZeroizeOnDrop`. They
  are now wrapped in `zeroize::Zeroizing` so each transient is wiped on every exit
  path (the public `nonce_prefix` is left plain).

- **CRYPTO-4 (low): strict Ed25519 verification.** The Ed25519 half of the hybrid
  signature used the lenient `verify`; it now uses `verify_strict`, which rejects
  non-canonical / malleable signatures and low-order public keys (we only ever
  produce canonical signatures, so no legitimate signature is rejected). Removes
  signature malleability as a class.

- **PATH-001 (low): application data is delivered only on a Validated path —
  enforced.** The receive path decrypted and delivered every authenticated
  application frame regardless of its header `path_id`, so a peer could send data
  on a path that had never completed a `PATH_VALIDATION` challenge/response
  (Invariant 6 was a documented-but-unwired defense for the data plane). The
  data-pump now gates delivery on `path_state(path_id) == Validated` **after** the
  AEAD verify (so it never acts on an attacker-chosen plaintext `path_id` that
  fails decryption); path 0 is pre-validated at session establishment, so normal
  single-path traffic is unaffected. A frame on a non-validated path is dropped
  (not counted toward the backlog) and the path id is registered `Unvalidated` so
  a subsequent challenge can promote it. Pinned by
  `api::session::tests::app_data_on_non_validated_path_is_dropped`. No wire change.

- **PATH-003 (low): path-challenge issuance is now idempotent.** `issue_challenge`
  minted and installed a fresh challenge on every call, so a re-issue while one
  was already in flight (e.g. a retransmitted trigger) clobbered the pending
  challenge — a legitimate response to the *original* would then no longer match
  and would push the path to `Failed`. It now holds the pending-challenge lock
  across the decision and returns the existing challenge unchanged when one is
  already outstanding. Pinned by
  `transport::path::tests::reissue_on_validating_path_returns_same_challenge`.

- **APIFFI-03 (info): reject oversized 0-RTT early-data before opening a socket.**
  The FFI `connect_pinned_with_resumption` entry point forwarded `early_data` of
  any size and only hit the `EARLY_DATA_MAX_LEN` (16 KiB) cap deep inside the
  handshake, after a TCP connection had already been established. The cap is now
  checked up front (before `TcpStream::connect`), so a caller bug or oversized
  blob fails fast with a `ValidationError` instead of wasting a connection; the
  inner `connect_with_resumption` keeps the same cap as defense-in-depth.

- **COMP-01 (low): decompression-bomb cap on `AdaptiveCompressor`.** The
  public `decompress` helper trusted the input to bound its own output — LZ4's
  size-prefix and Zstd's frame were decoded to whatever length they declared, so
  a few crafted bytes could expand to gigabytes and exhaust memory. Decompression
  is now capped at `MAX_DECOMPRESSED_LEN` (16 MiB): the LZ4 path rejects an
  oversized declared length from the little-endian size prefix *before*
  allocating, and the Zstd path stream-decodes through a reader bounded at the
  cap and fails closed if the frame exceeds it. A new `OutputTooLarge` error
  variant and a `decompress_with_limit(algo, data, max_output)` entry point let
  callers pick a tighter bound. Pinned by
  `transport::compression::tests::{lz4_decompress_rejects_oversized_declared_size,
  lz4_decompress_with_limit_rejects_overlimit_output,
  zstd_decompress_with_limit_rejects_overlimit_output}`.

- **COMP-02 (low): bounded `FragmentAssembler`.** The UDP fragment reassembler
  accepted any fragment unconditionally: a `total_chunks` up to 65 535, an
  out-of-range `chunk_index`, a `payload` larger than the datagram MTU (the
  field is borsh-decoded, so not implicitly capped), and an unbounded number of
  distinct `(session_id, packet_id)` keys — each a way to pin memory without
  ever completing a packet. `process_chunk` now drops malformed/abusive
  fragments (`total_chunks` zero or `> MAX_TOTAL_CHUNKS`, `chunk_index` out of
  range, `payload > MAX_UDP_PAYLOAD`) and caps concurrent in-flight assemblies
  at `MAX_CONCURRENT_ASSEMBLIES` (256, evicting the stalest on overflow). The
  worst-case resident memory is now bounded (≈ 64 MiB) instead of unbounded.
  Pinned by `transport::fragmentation::tests::*`. Both `AdaptiveCompressor` and
  `FragmentAssembler` are public-but-unwired helpers; these are defense-in-depth
  hardenings of the public surface.

- **SUPPLY-04b (info): path-validation challenge now drawn from the CSPRNG seam.**
  `PathRegistry::issue_challenge` minted its 32-byte challenge with
  `rand::random()` (a non-cryptographic thread RNG by configuration). A path
  challenge is security-sensitive — it gates application data onto a new path
  (Invariant 6) — so it now draws from the `crypto::rng::OsRng` seam, which is
  `getrandom` on default builds and the aws-lc-rs CTR_DRBG under `--features
  fips`. The seam owns the inventoried getrandom-failure panic contract, so no
  fresh `unwrap`/`expect` is introduced at the call site.

- **faketls-2 (low): FakeTLS record length-overflow guard + no-panic seal.**
  `FakeTlsLeg::wrap_as_tls_record` cast the sealed body length to `u16` for the
  outer TLS record-length field without checking it fits, so a payload larger
  than ~64 KiB would silently truncate the length into a corrupt record; and the
  AEAD seal used `.unwrap()`. It now rejects any payload whose sealed length
  (`data + 1 inner-type byte + AEAD tag`) would exceed `u16::MAX` with
  `io::ErrorKind::InvalidData` **before** sealing, and propagates a seal failure
  with `?` instead of panicking (the function now returns `io::Result<Vec<u8>>`).
  Invariant 3 is preserved unchanged — the per-record `send_counter` nonce and
  direction-keyed `send_key` are untouched. Pinned by
  `oversized_record_payload_is_rejected_not_truncated`.

- **Supply-chain / CI hardening.** Every GitHub Actions `uses:` is now pinned to
  a full commit SHA (with the human-readable tag in a trailing comment) so a
  retagged or compromised action can no longer change what CI runs; all seven
  workflows default `GITHUB_TOKEN` to least privilege (`permissions: contents:
  read`, with jobs opting into narrower scopes where needed) and add a
  `concurrency` group (PR runs cancel superseded runs; `main` and release runs
  never cancel mid-flight). Dependabot now keeps the SHA pins and Cargo
  dependencies fresh across the workspace and every sibling crate, and a
  `CODEOWNERS` file auto-requests review on the security-sensitive crypto /
  transport paths. Added the standard community-health files (Code of Conduct,
  issue/PR templates, `.editorconfig`).

### Removed

- **Dead GSO `sendmmsg` batch-send path + `GsoBatchResult` (UNSAFE-2).** The
  `UdpTransport::send_batch_gso` / `platform_send_batch` / `sendmmsg_batch`
  chain and the `GsoBatchResult` type were `pub` but had no callers anywhere in
  the crate, benches, or examples — dead code that was also the *only* user of
  `unsafe { libc::sendmmsg }` and `MaybeUninit::<libc::mmsghdr>::zeroed()`, the
  most intricate hand-written `unsafe` in the tree. All of it is deleted, so the
  one remaining `unsafe` block in `transport::udp_transport` is the trivially
  sound `libc::setsockopt(SO_MAX_PACING_RATE)` in `set_pacing_rate`. (The
  module-level comment and the crate-root audit-lens are updated; the stale
  `recvmmsg` references — there was never a `recvmmsg` call — are removed.)
  Removing the `pub GsoBatchResult` is a pre-1.0 public-surface removal.

- **`chacha20poly1305` crate dependency (SUPPLY-02).** The standalone
  `chacha20poly1305` crate was a declared dependency but never imported — the
  ChaCha20-Poly1305 AEAD is provided by `ring` (and `aws-lc-rs` under fips) via
  their `CHACHA20_POLY1305` constants. Dropped from `core/Cargo.toml`. The
  `CipherSuite::ChaCha20Poly1305` wire enum value (2) is **kept** for wire-format
  stability; only the redundant crate is removed.

- **`PhantomListener::ensure_acceptor` from the FFI surface.** The internal
  lazy-init helper added with the H4 accept-decoupling sat inside the
  `#[uniffi::export]` impl block, so UniFFI 0.29 exported it into every language
  binding even though it is a private `fn` with no business in the public API.
  It is moved to a non-exported `impl` block; behaviour is unchanged (`accept()`
  still calls it). This also re-aligns the committed Swift/Kotlin/Python/C
  bindings with the generated output (an earlier commit had left them drifted).

- **`networks/` layer.** The entire `core/src/networks/` module —
  `engine.rs` (a `NetworkEngine` that forwarded **plaintext** between a transport
  and a pipeline), `pipeline.rs`, `transport.rs`, `tls.rs`, and the orphaned
  `serialization.rs` / `compression.rs` files — is deleted. It was compiled and
  `pub` but **entirely unwired** (no code outside the module referenced it), a
  half-built parallel stack to the real `transport::` layer. Most importantly it
  carried a **certificate-pinning weakening**: `networks/tls.rs` fell back to
  system WebPKI roots (no pinning) whenever `cfg!(debug_assertions)` was set — a
  posture that silently disables pinning in every non-`--release` build (dev,
  `cargo test`, many integration setups). Deleting the layer removes that
  footgun entirely. With it gone, the `rustls`, `tokio-rustls`, `rustls-pemfile`,
  and `webpki-roots` dependencies are dropped from `core/Cargo.toml` (they had no
  other users — the FakeTLS leg uses its own AEAD, not rustls), shrinking the
  native dependency and attack surface. This also makes the planned
  `rustls-pemfile → rustls-pki-types` migration (SUPPLY-05) moot. Removing
  `pub mod networks` is a pre-1.0 public-surface removal.

- **`HalfOpenSlots` (DOS-3).** The unused `transport::half_open::HalfOpenSlots`
  SYN-flood scaffolding is deleted — it was dead code (a TTL slot store, the
  wrong primitive for the TCP path), and the concurrent-handshake cap is now
  provided by the listener's in-flight-handshake semaphore (H4/DOS-1). Removing
  `pub mod half_open` is a pre-1.0 public-surface removal.

### Changed

- **Split the UniFFI codegen CLI off the runtime library (SUPPLY-01).** The
  `uniffi` dependency previously carried the `cli` feature unconditionally, so
  every default library / server / mobile build pulled `clap` (and its tree)
  purely to support the `uniffi-bindgen` codegen binary that only the
  `tests/bindings/generate_*.sh` scripts ever run. The `cli` feature now lives
  behind a new opt-in `uniffi-cli` Cargo feature, and the `uniffi-bindgen`
  binary declares `required-features = ["uniffi-cli"]` so a default `cargo build`
  skips it entirely. `clap` no longer appears in the default dependency tree.
  The reference server's `phantom_protocol` dependency switches to
  `default-features = false` (it embeds the Rust API and never generates FFI),
  dropping the UniFFI scaffolding from the server build too. The generated
  bindings are byte-identical (verified by regenerating all four languages).

### Added

- **Graceful unsupported-version signal.** When a `ClientHello.version` is one
  the server does not speak, the server now replies with a small typed
  `ServerReject` frame (a `b"PRJ1"`-marked 6-byte message carrying the version
  it *does* speak) before closing, instead of dropping the connection silently.
  The client surfaces this as a clear version-mismatch error and does **not**
  auto-downgrade — the version stays transcript-bound, so an injected reject
  cannot force a downgrade. This makes an old-server ↔ newer-client encounter
  degrade with an actionable diagnostic. `ServerReject` is an additive handshake
  message; existing `ServerHello` / `HelloRetryRequest` / `PhantomPacket`
  layouts and the frozen wire vectors are unchanged. See
  `docs/protocol/PROTOCOL.md` §6.10.

- **0-RTT rejection is now lossless.** When the server rejects a client's 0-RTT
  early-data (unknown/expired/replayed ticket, oversized blob, or AEAD failure),
  the client re-sends that data over the established 1-RTT session instead of
  dropping it — prepended ahead of anything queued while connecting, preserving
  order. `early_data_accepted()` still reports the verdict. Forward secrecy is
  preserved (the re-send rides the fresh session keys). Closes the 0-RTT
  rejection-retransmission contract.

- **Automatic mid-session rekey.** A long-lived session now rotates its AEAD
  keys automatically once a direction's invocation count crosses a soft
  high-watermark (well below the `2^48` `NonceExhausted` ceiling), instead of
  eventually erroring. The sender flags the rekey and the receiver follows by
  trial-decrypting the new epoch and committing the ratchet only on AEAD
  success — a forged epoch bump cannot desync the session, and every epoch
  transition is serialised so the concurrent send/receive pump tasks keep the
  installed key and the epoch counter in lockstep. See PROTOCOL.md §5.

- **Receive backpressure decoupled from control traffic; enforced flow
  control.** The post-handshake receive path now splits the wire reader from
  application delivery: the reader decrypts, replay-checks, ACKs inline, and
  hands payloads to a dedicated delivery task over an unbounded queue, so a slow
  or stalled `recv()` consumer can no longer head-of-line-stall inbound ACK /
  `WINDOW_UPDATE` / control processing for the other direction. Flow control is
  now actually enforced on the send side — new data is admitted only within
  `min(congestion_window, peer_flow_control_window)` while retransmissions
  bypass both (Karn) — and the window is replenished by **relative credit**
  granted on real consumption (robust for sessions of any length, unlike an
  absolute `u32` window). A delivery-backlog hard cap tears down a peer that
  ignores flow control instead of buffering without bound.

### Fixed

- **LEGS-004: `VirtualSocket::close()` now actually stops the per-leg recv
  tasks.** The recv loop captured a *fresh* `Arc<AtomicBool>` initialised from a
  snapshot of `self.closed`, not a clone of the shared flag — so `close()`
  setting `self.closed` could never signal a running recv task, which leaked
  until its leg errored. The flag is now a single shared `Arc<AtomicBool>` the
  loop clones, so `close()` stops it. Pinned by `close_signals_the_shared_flag`.

- **LEGS-005: `VirtualSocket` BBR ACK detection read the wrong header bytes.**
  The recv loop decoded the packet header with magic offsets — `data[38]` as the
  "flags byte" and `data[39..41]` as a *little-endian* `ack_delay` — but the
  canonical 45-byte header is **big-endian** with `flags` at `[39..41]` and
  `ack_delay` at `[41..43]`; offset 38 is the LSB of the `sequence` field. So
  every ACK feedback sample was mis-parsed. It now decodes via the canonical
  `PacketHeader::from_wire`. Pinned by `ack_header_decodes_via_canonical_codec`.

- **UNSAFE-1: tightened the `WasiLeg` `unsafe impl Send/Sync` SAFETY rationale**
  to explicitly carve out the non-`Mutex` `_socket` field (accessed only by its
  destructor under unique ownership, never through a shared `&self`), so the
  single-accessor argument is complete. Documentation only.

- **Flow-control control frames could collide with data on the AEAD nonce.**
  `WINDOW_UPDATE` (and a bare `FIN`) drew their packet sequence from a separate
  counter than application data on the same stream/direction. Because the AEAD
  nonce is `(epoch, stream_id, sequence, path_id)`, a control frame sharing a
  `(stream_id, sequence)` with a data packet in the same epoch reused a nonce
  **and** was dropped by the receiver's replay window — which, once flow control
  became enforced, deadlocked a sustained bidirectional bulk transfer. All
  packets emitted on a stream now draw from one monotonic per-stream sequence
  space (`Stream::next_send_sequence`), so `(stream_id, sequence)` is never
  reused within an epoch. Relatedly, staged flow-control credit now accumulates
  additively (so back-to-back grants between send-loop flushes are summed, not
  overwritten) and the receive-backlog byte counter is accounted exactly as
  items enter and leave the delivery queue.

- **Congestion-window inflight leak.** The send path credited the full on-wire
  packet size to the in-flight byte counter while the ACK/loss paths only
  debited the payload length, leaking ~69 bytes (header + length prefixes +
  AEAD tag) of phantom in-flight per packet. On a long-lived session this
  silently exhausted the BBR congestion window after a few dozen packets and
  stalled all further sends. Send accounting now uses the payload length, so
  inflight balances exactly against the ACK and loss paths.

## [0.3.0] - 2026-06-01

This release takes phantom_protocol from its 0.2.0 pre-1.0 baseline through the
foundation, security-hardening, and production-readiness phases of the roadmap:
the unified single wire protocol (WIRE-BREAKING
— hence the `0.3.0` minor bump), byte-exact wire-format + NIST ACVP KAT vectors,
the observability data-path wiring, FIPS 140-3 substrate, and a now-green
cross-target CI. The wire format changed since 0.2.0, so peers must upgrade
together (no negotiation pre-1.0).

### Changed — unified wire protocol (WIRE-BREAKING)

**The three independent version axes are collapsed into one wire
protocol.** Pre-1.0 there are no deployed peers, so there is nothing to
negotiate, fall back to, or migrate; the redundant dual-format machinery
is gone and a single 1-byte version survives as a pinned tamper-check
anchor (and a hook for a future deliberate bump).

Collapsed:
- **Data packets** — the dual V1/V2 format (`VersionedPacket::{V1, V2}`
  + `PacketHeader` / `PacketHeaderV2`) folds into one 45-byte
  `PacketHeader` whose `version: u8` field is pinned to `WIRE_VERSION = 2`.
  The header is serialised by `PacketHeader::to_wire` as an explicit
  big-endian image, `version` first: `version, session_id, stream_id,
  sequence, flags, ack_delay, epoch, path_id` — see
  `docs/protocol/PROTOCOL.md` § 4.2 for the exact offsets. The single
  `PacketFlags` (`u16`) carries every flag that was
  previously split across `PacketFlags` / `PacketFlagsV2` (`RELIABLE`,
  `ACK`, `FIN`, `UNRELIABLE`, `PRIORITY`, `ENCRYPTED`, `COMPRESSED`,
  `CONTROL`, `REKEY`, `PATH_VALIDATION`, `COALESCED`, `WINDOW_UPDATE`;
  `0x1000`..`0x8000` reserved).
- **Handshake envelopes** — the V1/V2/V3 borsh envelope dispatch
  (`ClientHelloEnvelope`, `ServerHelloEnvelope`,
  `HelloRetryRequestEnvelope`, with the 1-byte discriminant and the
  `Unsupported` V3→V2 fallback arm) folds into bare borsh structs: one
  `ClientHello`, one `ServerHello`, one `HelloRetryRequest`. The client
  distinguishes a `ServerHello` from a `HelloRetryRequest` by
  deserialization (size), not a discriminant.
- **Per-session wire-version negotiation** — removed. The format is
  pinned, not negotiated; the recv path deserializes `PhantomPacket`
  directly and drops any frame whose `header.version != WIRE_VERSION`.

**0-RTT early-data is now a field of the single `ClientHello`**
(`early_data: Option<Vec<u8>>`) rather than a separate V3 envelope arm.
One `HandshakeTranscript` signs the whole `ClientHello` — the AEAD-sealed
early-data ciphertext included — and leads with `protocol_variant`. There
is one `process_client_hello` and one `process_server_hello`
(`-> (Session, Option<bool>)`, the `Option<bool>` being the 0-RTT verdict,
`None` when no early-data was sent). Semantics are unchanged: best-effort
(unknown / expired ticket, oversized `> 16 KiB`, or AEAD failure leaves
`early_data_accepted = false` and completes a 1-RTT handshake), one-shot
(the resumption ticket is consumed once), and the fresh hybrid KEM
preserves forward secrecy on the 0-RTT path.

`PROTOCOL_VERSION` (the `ClientHello.version` byte, `transport/handshake.rs`)
and `WIRE_VERSION` (the packet-header byte, `transport/types.rs`) are both
pinned to `1`. `PROTOCOL_VARIANT` (`phantom-default-1` / `phantom-fips-1`)
is an orthogonal build-variant tag and is unaffected by this collapse.

**Observability** — the `ProtocolVersion` metric-label enum collapses to a
single pinned variant (`ProtocolVersion::Current`, label value `"v1"`); the
`version` dimension is retained for a future deliberate bump but no longer
takes more than one value.

**Impact.** This is a hard, pre-1.0 wire break in every direction: any peer
on a prior build (dual-format data packets, enveloped handshake, V3 0-RTT)
cannot interoperate with a post-collapse peer. Rebuild both ends together.

### Removed — dual-format wire machinery

- `VersionedPacket` enum (`{V1, V2}`) — the wire is now a bare
  `PhantomPacket { header: PacketHeader, payload: Vec<u8>, extensions:
  Vec<u8> }`. The `extensions` field is TLV headroom.
- `PacketHeaderV2` / `PacketFlagsV2` — folded into the single
  `PacketHeader` / `PacketFlags`.
- `ClientHelloEnvelope`, `ServerHelloEnvelope` (incl. the `Unsupported`
  fallback arm), `HelloRetryRequestEnvelope`, and the 1-byte version
  discriminant on every handshake message.
- `ClientHelloV3` / `ServerHelloV3` / `HandshakeTranscriptV3` and the
  separate `process_client_hello_v3` / `process_server_hello_v3` paths —
  0-RTT is now the single `ClientHello.early_data` field on the one
  handshake path.
- Per-session wire-version negotiation / fallback logic.
- Negative-security suite trims from 24 to 20 always-on tests in
  `core/tests/security_invariants.rs`: the V1/V2 twin tests and the
  V1-vs-V2 cross-version distinctness test fold into single canonical
  tests now that the dual format is gone.

### Changed — packet codec moved off `alkahest` (WIRE-BREAKING)

- The packet header + `PhantomPacket` are now serialised by a **hand-rolled
  big-endian codec** (`PacketHeader::to_wire` / `from_wire`,
  `PhantomPacket::to_wire` / `from_wire`) instead of `alkahest`. The layout is
  explicit, network-byte-order, `version`-first, with byte arrays stored as-is —
  trivially reimplementable in any language. `WIRE_VERSION` bumps `1` → `2`;
  `PROTOCOL_VERSION` (the borsh handshake) is unchanged.
- The **`alkahest` dependency is removed** entirely. `borsh` stays for the
  handshake messages (it has a canonical published spec and a derive for the
  complex nested structs) and remains pinned to an exact `=` version.
- `from_wire` is bounds-checked and overflow-safe on 32-bit targets — a hostile
  length prefix is dropped, never an out-of-bounds read.

### Added — byte-exact wire-format vectors

- `core/tests/wire_vectors/*.bin` freeze the on-wire bytes byte-for-byte: the
  `PacketHeader` / `PhantomPacket` (hand-rolled big-endian codec), the
  `ClientHello` / `ServerHello` / `HelloRetryRequest` and their crypto
  sub-structs (borsh), and the signed `HandshakeTranscript` hash. The
  always-on `core/tests/wire_vectors.rs` and the lib unit test
  `transport::handshake::tests::transcript_hash_wire_vector` assert
  `encode == fixture` and `decode(fixture) == value`; both now gate CI. This
  is the first test in the repo that pins the *bytes* rather than driving Rust
  types ↔ Rust types, so a packet-codec or `borsh` layout regression fails CI
  instead of silently breaking interop.
- `tests/wire_vectors_decode.py` — an independent, non-Rust decoder + encoder
  over the same fixtures (cross-implementation interop evidence).
- `docs/protocol/PROTOCOL.md` § 4.2 documents the explicit big-endian header
  layout (offsets, widths, network byte order — `version` first) and gains a
  § 11 test-vector catalog.

### Changed — observability wired into the production data path

- The OpenTelemetry metrics are now driven by real traffic instead of staying
  flat until an embedder hand-called the `record_*` API. The data pump records
  every data-plane `send` / `recv` (via a transparent `SessionTransport`
  decorator), the recv path records the security drops
  (`replay_rejected` / `aead_failed` / `unencrypted_dropped`), and the
  server handshake is recorded with its full attribute set
  (`outcome` / `leg` / `cipher_suite` / `version`).
- **The active-session gauge now goes up *and* down.** It is opened when a
  session's data pump starts and closed at teardown, so it tracks live sessions
  instead of growing monotonically — fixing a Helm HPA / autoscaler signal that
  previously latched after warm-up. The listener no longer double-counts the
  open.
- New Rust-only accessor `PhantomSession::observability() -> Arc<Observability>`
  (and the existing `PhantomListener::observability()`) expose the live
  `snapshot()` counters. Server-accepted sessions share the listener's instance;
  client sessions own their own.
- `examples/observability-demo` now drives a real `PhantomListener` ↔
  `PhantomSession` exchange (it previously emitted synthetic `record_*` calls).
- Removed the documented-but-never-emitted `phantom.telemetry.export_failures`
  metric from the metrics catalog, OTLP guide, and Prometheus alerts: the
  library never installs the exporter, so export health belongs to the OTel
  SDK / Collector, not Phantom Protocol.
- New always-on integration test `core/tests/observability_e2e.rs` gates the
  wiring (a real session must populate the counters and return the gauge to 0).

### Added — `wasi-leg` Cargo feature (commits `f6c0c0a`..`255be95`)

**`cargo build --target wasm32-wasip2 --features wasi-leg` is now a
shipped configuration.** Phantom Protocol embedders can run inside any
WASI Preview 2 host (Wasmtime, WasmEdge, Spin, wasmCloud, Cloudflare
Workers WASI sandbox).

New surface:
- **`phantom_protocol::transport::legs::wasi::WasiLeg`** — length-prefix-
  framed `SessionTransport` over `wasi:sockets/tcp`. Client-only
  for now; `connect(SocketAddr)` wraps the Preview 2 socket-create +
  start_connect + poll + finish_connect dance. Same 4-byte
  big-endian framing as `TcpSessionTransport`.
- **`phantom_protocol::runtime::wasi_runtime::WasiRuntime`** — single-
  task `Runtime` impl. `drive()` polls every spawned future once;
  `poll_until_progress(max_wait)` blocks on `wasi:io/poll::poll`
  with a `subscribe_duration` watchdog so the drive loop always
  makes eventual progress. `SpawnHandle::abort` toggles an
  `AtomicBool` the wrapping future checks.

Both modules are gated on `cfg(all(feature = "wasi-leg", target_os
= "wasi"))`. A `compile_error!` in `core/src/lib.rs` rejects the
`wasi-leg + wasm32-unknown-unknown` combination (browser target —
use `WebSocketLeg` + `WasmRuntime` instead).

**Cargo feature split** — UniFFI scaffolding moved from the `std`
feature into a new `bindings` Cargo feature (default-on, so native
embedders see the historical surface unchanged). WASI guests opt out
via `--no-default-features --features std,wasi-leg` because
UniFFI's exported-symbol metadata is incompatible with
`wasm-component-ld`, the wasm32-wasip2 linker. Every
`#[uniffi::*]` attribute in `core/src/{api/*,errors,config,lib,
bin/uniffi-bindgen}` was wrapped in `#[cfg_attr(feature =
"bindings", …)]`.

**Breaking for `--no-default-features --features std` consumers.**
Default builds are unaffected (`default = ["compression-zstd", "std",
"bindings"]`), and so is anything that opts into `default-features`.
But a consumer pinning
`phantom_protocol = { default-features = false, features = ["std"] }`
used to get the UniFFI scaffolding for free via `std`; after this
PR they must explicitly add `bindings`:
`features = ["std", "bindings"]`. Pre-1.0 SemVer permits this, but
the call-out is here so embedders pinning `std`-only do not see a
silent removal of the `uniffi::Object` / `uniffi::Record` derives.

**Cargo target-cfg refinement** — `core/Cargo.toml`'s
`[target.'cfg(target_arch = "wasm32")']` block (the
browser-WASM-only deps: `wasm-bindgen`, `web-sys`, `js-sys`,
`getrandom = { features = ["js"] }`) narrows to
`cfg(all(target_arch = "wasm32", target_os = "unknown"))` so WASI
builds skip them entirely.

**CI** — `wasm32-wasi` (legacy alias) `allow_failure: true` row in
`.github/workflows/cross.yml` is replaced with a hard-gated
`wasm32-wasip2` matrix entry. New `wasi-integration` job installs
`wasmtime` and runs the `#[ignore]`-gated
`core/tests/wasi_integration.rs` host driver, which spawns the
`phantom-wasi-guest` fixture under `wasmtime` and verifies a
round-trip through `WasiLeg`. The 12-target cross-compile matrix
now has zero `allow_failure: true` rows.

Out of scope (follow-up):
- Server-side `accept` for `WasiLeg` (running `phantom-server` as a
  WASI guest is explicitly deferred per the plan's Decision Point 3).
- Full `PhantomSession` over `WasiLeg` (the B5 host test exercises
  the byte pipe, not the handshake).

Detailed quickstart in `docs/operations/wasi.md`.

### Security — FIPS 140-3 primitive swap (commits `613473a`..`5dd39c7`)

**`cargo build --features fips` is now a shipped configuration.** The
scaffold `compile_error!` from commit `d4d121b` is removed; enabling
the feature pulls in `aws-lc-rs` (AWS-LC-FIPS) and swaps every
non-FIPS-approved primitive call site:

- **AEAD** — AES-256-GCM via `aws_lc_rs::aead`. ChaCha20-Poly1305 is
  rejected at handshake (`negotiate_cipher`) and at
  `CryptoSession::with_suite` with `CoreError::CipherSuiteUnavailable`.
  The wire-format `CipherSuite` enum variant is preserved.
- **Classical KEM** — X25519 → ECDH-P-256 via `aws_lc_rs::agreement`.
  The classical public key on the wire grows from 32 bytes to 65 bytes
  (uncompressed SEC1).
- **KDF** — every `blake3::derive_key` call routes through the new
  `crypto::kdf::derive_key_32` shim, which uses `HKDF-SHA256` under
  fips (label-compatible API).
- **RNG** — `RngProvider for OsRng` swaps to
  `aws_lc_rs::rand::SystemRandom` (CTR_DRBG, SP 800-90A § 10.2.1).
- **POST** — `crypto::self_tests::ensure_post_passed` is invoked from
  every Phantom Protocol entry point that performs cryptographic work
  before serving traffic: `PhantomListener::bind*`,
  `PhantomSession::connect_with_transport*`,
  `PhantomSession::connect_with_resumption`, and the UniFFI
  `connect_pinned*` paths. Failure surfaces as
  `CoreError::FipsSelfTestFailure(String)` on the fallible paths
  (listener bind, `connect_with_resumption`, `connect_pinned*`) and as
  a `ConnectionState::Failed` transition with the error in the log on
  the infallible paths (`connect_with_transport*`, which return `Self`
  by API contract).

**Wire-format break (V1/V2 ClientHello)** — adding the
`protocol_variant: Vec<u8>` field to `ClientHello` is a positional
wire-format change. Because borsh is strict about trailing bytes,
the impact is **bidirectional and generation-wide**, not just
fips ↔ non-fips:

- A pre-PR client cannot connect to a post-PR server (server
  expects the new field, fails to deserialize the envelope).
- A post-PR client cannot connect to a pre-PR server (server has
  no slot for the trailer, deserialize errors on extra bytes).
- A fips peer cannot connect to a non-fips peer of the same build
  generation (the cleartext field mismatches up front, and the
  signed transcript binds the build-side `PROTOCOL_VARIANT`).

In short: **both peers must be on a post-PR build, and both must
share the same `PROTOCOL_VARIANT`** (`phantom-default-1` for the
default build, `phantom-fips-1` under `--features fips`). The
`PROTOCOL_VARIANT` constant is the leading field of the signed
handshake transcript, so an MITM rewriting the cleartext field is
still caught by the signature-verify check. Pre-1.0 callers should
treat this as a hard generation bump and rebuild both ends together;
see `docs/protocol/PROTOCOL.md` §6.7 for the cross-mode
(`PROTOCOL_VARIANT`) interop policy.

**Build constraints** — `fips` implies `std` and is mutually exclusive
with `no-std` (compile_error in `core/src/lib.rs`). `aws-lc-rs`
requires libc + dlopen / OpenSSL ABI and does not target wasm32 or
bare-metal. macOS hosts may need `brew install pkg-config openssl@3`
for the first build.

**CI** — new `fips-feature` job in `.github/workflows/ci.yml`
(cargo test/clippy + cavp + the no-std-conflict assertion) and a
new `x86_64-unknown-linux-gnu (--features fips)` row in
`.github/workflows/cross.yml`.

Test count under `--features fips`: 244 lib tests + 3 ignored TCP
integration tests (all green). Detailed primitive table and the
remaining documentation work for a real CMVP submission are in
`docs/compliance/fips-readiness.md`.


### Phase 8 — OpenTelemetry refactor (Observability)

**Breaking changes for embedders:**
- Removed `phantom_protocol::transport::metrics` module entirely.
- Removed `PhantomListener::metrics_prometheus_text()` and the deprecated
  `PhantomListener::metrics()` alias. Use `PhantomListener::observability()`
  → `Arc<Observability>` and capture snapshots via `observability.snapshot()`.
- The reference server (`phantom-server`) no longer ships an HTTP
  `/metrics` endpoint. `--metrics-bind` and `PHANTOM_METRICS_BIND` are
  removed. For Prometheus pull, run an OTel Collector with a
  `prometheusexporter` consuming the server's OTLP stream.
- Metric names changed (post-Collector translation):
  - `phantom_packets_sent_total` →
    `phantom_session_packets_total{direction="send"}`
  - `phantom_bytes_sent_total` →
    `phantom_session_io_By_total{direction="send"}`
  - `phantom_handshakes_total` + `phantom_handshake_failures_total` →
    `phantom_handshake_attempts_total{outcome=…}`
  - `phantom_handshake_latency_seconds_*` →
    `phantom_handshake_duration_seconds_*`
  - Full mapping in `docs/observability/metrics-catalog.md`.

**Added:**
- New Cargo feature `telemetry-otel` (off by default) — opt-in OTel
  pipeline. When on, the library exposes `Counter` / `Histogram` /
  `UpDownCounter` / `ObservableCounter` instruments under the configurable
  `phantom.*` namespace (env: `PHANTOM_TELEMETRY_NAMESPACE`).
- `phantom_protocol::observability::*` module: `Observability` facade,
  `ObservabilityConfig` builder, `MetricsSnapshot` (always available for
  FFI / debug), typed attribute enums (`Direction`, `HandshakeOutcome`,
  `AeadAlgorithm`, `ProtocolVersion`, `ReplayReason`, `CookieOutcome`,
  `PowOutcome`, `EarlyDataOutcome`, `ResumptionMode`,
  `PathValidationOutcome`, `FallbackReason`).
- Lock-free hot-path atomics with `crossbeam_utils::CachePadded` —
  microbench on Apple M1 records `record_send` at **2.5 ns / call**,
  contended at **84 ns / call** across 8 threads.
- OTel observable callbacks for hot-path atomics; sync labeled
  instruments for security signals, cookie/PoW gate, rekey, fallback,
  early-data outcomes; latency `Histogram`s for handshake and
  path-validation with explicit, latency-tuned bucket boundaries.
- `tracing-opentelemetry` bridge under `telemetry-otel`. Existing
  `#[tracing::instrument]` spans (`phantom.handshake.*`,
  `phantom.listener.*`) now flow into OTLP traces. Added spans on
  `Session::rekey`, `begin_path_validation`, `complete_path_validation`.
- `server/src/telemetry.rs` — installs OTLP/gRPC `MeterProvider` /
  `TracerProvider` (Delta temporality, gzip compression) and wires
  `tracing-opentelemetry` into the global subscriber. New CLI flags:
  `--otlp-endpoint`, `--otel-service-name`, `--otel-trace-sample-ratio`.
- `examples/observability-demo` — sibling crate with a `docker-compose.yml`
  bringing up OTel Collector + Prometheus + Tempo + Grafana.
- Documentation under `docs/observability/`: `README.md`,
  `metrics-catalog.md`, `otlp-setup.md`, `tracing-guide.md`,
  rewritten Grafana dashboard and Prometheus alert rules under the new
  OTel-translated names.

### Added
- FFI 0-RTT resumption: new `ResumptionHint` UniFFI record and the
  native `connect_pinned_with_resumption` free function expose 0-RTT
  session resumption to FFI / mobile consumers.
  `PhantomSession::resumption_hint()` now returns `Option<ResumptionHint>`
  and is on the UniFFI surface — it was previously a Rust-only
  `Option<([u8; 32], [u8; 32])>` tuple defined outside the export block.
- CI: `.github/workflows/bindings.yml` `drift` job now runs
  `tests/bindings/check_versions.sh`, asserting that every binding
  manifest (`pyproject.toml`, `phantom_protocol.pc.in`) reports the same
  version as the source-of-truth `core/Cargo.toml`. Catches release-time
  version skew before it ships to PyPI / pkg-config consumers. `server`
  and `cli` Cargo manifests are checked too.
- Tests: real-TCP 0-RTT coverage —
  `core/tests/tcp_integration.rs::tcp_integration_zero_rtt_resumption_round_trip`
  exercises the full FFI sequence (`connect_pinned` →
  `resumption_hint()` → `connect_pinned_with_resumption(..., hint,
  early_data)`) over loopback, asserting both 32-byte hint fields and
  echo round-trips on both connections.
- Tests: Python loopback (`tests/run_test.py`) now runs a phase-2 0-RTT
  scenario — polls for the resumption hint, opens a second connection
  through `connect_pinned_with_resumption` carrying a 22-byte
  early-data payload, and verifies `early_data_accepted()` returns a
  concrete `Some(...)` (`None` would mean the FFI silently fell back to
  1-RTT, the regression worth catching).
- Governance: `LICENSE` (Apache-2.0), `README.md`, `CHANGELOG.md`,
  `SECURITY.md`, `CONTRIBUTING.md`.
- Toolchain: `rust-toolchain.toml` (stable), `.rustfmt.toml`, `.clippy.toml`.
- Supply-chain: `deny.toml` for `cargo-deny`.
- CI: `.github/workflows/ci.yml` (fmt, clippy, test, doc, deny, audit,
  cli-compat).
- `subtle = "2.5"` dependency for constant-time secret comparisons.
- Phase 6.8: `core/tests/security_invariants.rs` — ten non-`#[ignore]`
  tests pinning the documented invariants (AEAD authenticity, AAD
  binding, wire-format robustness, constant-time cookie, server-identity
  pinning, AEAD-counter exposure, cookie-tamper retry, signing-keypair
  non-determinism, encrypted round-trip, V1 wire-format roundtrip).
- Phase 6.4: `fuzz/` scaffolding with four cargo-fuzz / libfuzzer-sys
  targets (`fuzz_client_hello`, `fuzz_server_hello`, `fuzz_packet_parse`,
  `fuzz_aead_decrypt`) plus a `fuzz/README.md` documenting local and
  OSS-Fuzz workflows.
- Phase 1.7: `CryptoSession::send_invocations()` / `recv_invocations()`
  observability accessors. `AEAD_MAX_INVOCATIONS = 1 << 48` ceiling
  with `CryptoError::NonceExhausted` failure mode.
- Phase 0 / 7: Full eight-phase roadmap for production readiness tracking.

### Changed
- FFI: renamed `PhantomSession::close()` and `PhantomStream::close()` to
  `disconnect()`. UniFFI 0.29's Kotlin generator unconditionally adds an
  `AutoCloseable.close()` to every object; a Rust-side method named
  `close` collides with it and prevents the Kotlin binding from
  compiling at all. The Rust API, all four FFI surfaces, internal
  callers (`server/`, embedded tests, `runtime_integration.rs`) and the
  mobile guide were updated together.
- FFI: every `#[uniffi::export]` block with async methods now carries
  `async_runtime = "tokio"`. Without it UniFFI polled the exported
  futures on a non-tokio executor and every async FFI call panicked at
  the first tokio I/O point (latent across all four bindings).
- Moved `[profile.release]` from `core/Cargo.toml` (silently ignored —
  workspace warning) to the workspace root. `opt-level = "s"` (size) →
  `opt-level = 3` (speed); kept `lto = "fat"`, `codegen-units = 1`,
  `panic = "abort"`. Added `[profile.release-size]` and `[profile.bench]`
  variants.
- Pinned `zstd` from `git master` to `"0.13"`, removing the unstable
  supply-chain dependency.
- `workspace.exclude` now lists `cli`, `tests`, `fuzz` (sibling crates,
  intentionally outside the workspace).
- Phase 2.2: `PhantomSession`'s recv channel carries `Bytes` instead of
  `Vec<u8>`, eliminating the per-packet plaintext clone in the recv
  hot path. The public `recv()` still returns `Vec<u8>` (single
  `Bytes::to_vec` at the FFI boundary).
- Bindings regen (post-Phase-8 sweep): Python, Swift, and Kotlin
  auto-generated bindings plus the hand-curated
  `tests/bindings/c/phantom_protocol.h` were re-synced to the post-OTel
  cdylib. The now-deleted `metrics_prometheus_text` was the last
  residual symbol — Python `import phantom_protocol` would `dlsym`-fail
  at import time against the new lib until the regen.
- Tests: integration tests in `core/tests/tcp_integration.rs` no longer
  hard-code ports. They bind to `127.0.0.1:0` and read `local_addr()`,
  eliminating CI port collisions and TIME_WAIT lockout on rerun.
- Tests: `tcp_integration_zero_rtt_resumption_round_trip` replaces the
  fixed `sleep(300 ms)` between handshake and `resumption_hint()` with
  a bounded poll (5 s deadline) — kills both the slow-runner flake and
  the wasted latency on fast runners.

### Security
- Phase 1.1: cookie comparison in `process_client_hello` now uses
  `subtle::ConstantTimeEq` instead of `==`, closing a timing-leak
  brute-force vector (`core/src/transport/handshake.rs`).
- Phase 1.2: `CryptoState.session_key`, `Session.resumption_secret`,
  `HandshakeServer.pow_secret`, and `HandshakeClient.nonce` now zero on
  drop via `zeroize::ZeroizeOnDrop` / manual `Drop`. `Session::set_resumption_secret`
  zeroes the previous value before overwriting.
- Phase 1.3: removed every `.unwrap()` / `unreachable!()` from
  production hot paths. `compute_transcript_hash`,
  `HandshakeClient::new`, `generate_cookie`, `FakeTlsLeg::new` /
  `with_config`, and `derive_outer_keys` all return typed `Result`s
  now. New `HandshakeError` variants: `SerializationError`,
  `ClockBackwards`, `InternalError`.
- Phase 1.6: API-layer session IDs widened from 32-bit
  `rand::random::<u32>()` to 128-bit `rand::random::<[u8; 16]>()`
  (hex-encoded), removing birthday-collision and entropy concerns.
- Phase 1.7: AEAD nonce-exhaustion guard — both encrypt and decrypt
  paths fail with `CryptoError::NonceExhausted` if the per-direction
  counter reaches `1 << 48`.
- Phase 1.12: documented the phantom-limb `_ephemeral_kem_secret` and
  the reserved `HandshakeClient::take_early_data` hook (both pending
  Phase 4.1 0-RTT work).
- Phase 1.13: `#![deny(unsafe_code)]` at the crate root; only
  `core/src/crypto/keys.rs` and `core/src/transport/udp_transport.rs`
  opt back in, each `unsafe` block now carrying a `// SAFETY:` comment.
- Audit-friendly lints: `#![warn(clippy::unwrap_used, expect_used,
  panic, unreachable, todo, unimplemented, missing_safety_doc)]` in
  lib root. Surfaces remaining sites as TODOs without breaking CI.
- Supply chain: `tests/bindings/kotlin/run_kotlin_test.sh` now
  SHA-256-verifies the kotlinc + JNA + coroutines downloads against
  pinned hashes before unpacking / putting them on the classpath. A
  transient MITM on GitHub Releases or Maven Central can no longer
  swap in a tampered compiler / jar between download and execution.

## [0.2.0]

### Added
- Initial public-facing transport API: `PhantomSession`, `PhantomListener`,
  `PhantomStream`, `PhantomConfig`.
- Hybrid handshake (X25519+Kyber768 KEM, Ed25519+Dilithium3 signatures).
- Multi-leg transport: TCP, KCP-over-UDP, FakeTLS-over-TCP.
- UniFFI scaffolding for cross-language bindings.

### Security
- Three HIGH-severity vulnerabilities from the May 2026 review fixed:
  server identity must be pinned at the API boundary, the negotiated session
  must be used for all post-handshake data, and FakeTLS now uses per-record
  counter nonces with direction-keyed AEAD (preventing the Forbidden Attack on
  AES-GCM and making cross-peer encryption actually work).
