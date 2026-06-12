# Phantom Core — Security Remediation Plan

- **Date:** 2026-06-03
- **Input:** [`docs/security/audit-report-2026-06-03.md`](audit-report-2026-06-03.md) — 33 confirmed + 8 disputed findings + completeness-critic gaps.
- **Target:** `core/` @ `main` `5827909`. Crate is **v0.3.0 (pre-1.0)** — per project policy, deliberate breaking changes are acceptable when flagged in `CHANGELOG.md` and bundled into one coherent minor bump.
- **Scope:** every finding from **critical → info**, plus disputed items and the latent `networks/` gaps. Organized into **12 work-packages (WP1–WP12)** across **5 execution phases**, with a single coordinated wire bump.

This plan is code-grounded: every change cites `file:line`. Read **§0 (cross-cutting rules)** first — it governs every fix.

---

## §0 — Cross-cutting rules (apply to EVERY fix)

### 0.1 Wire & version policy (the single deliberate bump)
- **`WIRE_VERSION` stays `2`.** No recommended fix changes the 45-byte `PacketHeader` layout or the bare `PhantomPacket` container. (The only thing that would bump it is the **rejected** C1 option-(b) "widen sequence to `u64`".)
- **`PROTOCOL_VERSION` `1 → 2`: ONE shared bump** (handshake.rs:55), owned jointly by **WP2-H2** (adds `early_data_accepted` to the signed transcript) and **WP6-HS-03/ZERORTT-2** (adds `ClientHello.resumption_binder`). If WP2 and WP6 land in separate PRs, the **first to merge owns the `1→2` bump; the second inherits `2` (do NOT bump to 3)**. Update all ~6 assertions: `handshake.rs:55`, `docs/protocol/PROTOCOL.md` (PROTOCOL rows only — rows 27/47/207-219), `docs/policy/versioning.md`; the negative pin test `handshake.rs:1228` reads `PROTOCOL_VERSION` symbolically and auto-tracks (re-run it).
- **H1's optional `WIRE_VERSION 2→3`**: only if you choose to mark the ACK-frame semantics change with a version. Recommended: **fold H1 into the same release** as the PROTOCOL bump so the version line tells one story; do not bump WIRE separately.

### 0.2 Frozen-fixture regeneration runbook
Frozen artifacts live in `core/tests/wire_vectors/*.bin`, checked byte-exact by `core/tests/wire_vectors.rs` + the independent `tests/wire_vectors_decode.py`; the signed transcript hash is frozen by the lib unit test `transport::handshake::tests::transcript_hash_wire_vector` (`handshake.rs:1123-1187`). **All of this is default-build-only** (`wire_vectors.rs` is `#![cfg(not(feature="fips"))]`; the freeze test is `#[cfg(not(feature="fips"))]`). **Never run `PHANTOM_REGEN_WIRE_VECTORS=1` under `--features fips`.**

| Fixture | Touched by | Action |
|---|---|---|
| `transcript_hash.bin` | WP2-H2 (+1 byte `early_data_accepted`) **and** WP6-HS-03 (ClientHello embeds `resumption_binder`) | Regenerate **once**, after BOTH struct edits land. Update the in-test sample at `handshake.rs:1141-1168`. |
| `client_hello_minimal.bin`, `client_hello_full.bin` | **WP6-HS-03 only** | Regen (`sample_client_hello_*` at `wire_vectors.rs:120/134`). `None` binder = +1 byte; `Some` = +33 bytes. |
| `tests/wire_vectors_decode.py` | **WP6-HS-03 only** | Add `resumption_binder` in `dec_client_hello`/`enc_client_hello` (after `resume_session_id`, before `protocol_variant`). |
| `server_hello*.bin` | **NEITHER** (verify-before-regen) | `ServerHello.early_data_accepted` already exists at `handshake.rs:208` and is already serialized. Run a byte-diff dry-run; expected **zero diff**. If it changes, STOP — an unintended ServerHello edit slipped in. |
| `packet_header.bin`, `phantom_packet_*.bin`, `pow_*.bin`, `check_wire.rs` | **NONE** | No action (WIRE_VERSION unchanged; PoW layout unchanged). |

Regen command (default build): `PHANTOM_REGEN_WIRE_VECTORS=1 cargo test --manifest-path core/Cargo.toml --test wire_vectors` and `... --lib transcript_hash_wire_vector`.

### 0.3 FFI / UniFFI ABI rule
A fix trips the `bindings.yml` `drift` job **only** if it (a) changes a signature of an exported item (`PhantomSession`/`PhantomListener`/`PhantomStream`/`AcceptOutcome`/`PhantomConfig`/`ConnectionState`/`ResumptionHint`/`CoreError`, free fns `connect_pinned`/`connect_pinned_with_resumption`), (b) adds/removes/renames a `#[uniffi::export]` item, or (c) **adds a `CoreError` variant**. **No WP in this plan does (a)/(b)/(c)** — every fix reuses existing error variants (`CoreError::Timeout`, `::HandshakeError(String)`). Adding *private* fields to a `uniffi::Object` is ABI-safe. Swapping `derive(Debug)` for a manual `Debug` is ABI-safe.

### 0.4 FIPS rule
`fips = ["std", "dep:aws-lc-rs"]`, native-only, mutually exclusive with `no-std` (`lib.rs:79`). Validated by the `fips-feature` CI job + the `cross.yml` fips row. Every handshake **struct field is added unconditionally (not cfg-gated)** so both builds sign it. Binder/transcript **bytes differ** between builds (blake3 vs HKDF-SHA256; `phantom-fips-1` variant; 65-byte P-256 key) — that is fine (variants are already non-interop) and the fips transcript is **un-frozen**. The FIPS-central item is **WP10-SUPPLY-03** (see it for the `ring` removal hazard).

### 0.5 no-std / wasm / embedded + Runtime rule
`cross.yml` is 13 hard gates (no `allow_failure`): `wasm32-unknown-unknown`, `wasm32-wasip2` (`--features std,wasi-leg`), `thumbv7em-none-eabihf` (`--features embedded,no-std`). **Any timeout/sleep MUST go through `Runtime::sleep` (`Arc<dyn Runtime>`), never raw `tokio::time::sleep`** — load-bearing for WP3/HS-02 because the client `background_task` runs under `WasmRuntime`/`EmbeddedRuntime`. `select!` is fine; only the *timer source* must be the Runtime. Acceptor/handshake tasks spawn on `self.runtime`, not `tokio::spawn`. Exception: `KcpLeg` (WP4-LEGS-002) is native-only, so `tokio::time::timeout` is acceptable there.

### 0.6 MSRV / lint rule
MSRV **1.75**, edition 2021. Crate root denies `clippy::{unwrap_used, expect_used, panic, unreachable, todo, unimplemented}` + `unsafe_code`. **Every production fix uses `?`/`map_err`/`match`/`checked_add` — never `.unwrap()`/`.expect()`/`panic!`.** Tests may `unwrap`/`expect`. Do not bump `async-lock` (≥3.4 → MSRV 1.81) or `embedded-io-async` (0.7 → 1.81). `bytes` ≥1.4 needed for `BytesMut::shrink_to` (verify resolved `Cargo.lock`; it clamps, never panics).

### 0.7 Touch-with-care / branch strategy
Codeowner paths: `core/src/crypto/`, `transport/handshake.rs`, `transport/legs/faketls.rs`, `transport/session.rs`, `security/`. **One invariant per touch-with-care PR**, naming the Invariant(s) in the description. Non-codeowner work (`api/listener.rs`, `api/tcp_transport.rs`, `transport/legs/{tcp,kcp}.rs`, `networks/`, `validation.rs`) batches more freely. Every PR updates `CHANGELOG.md [Unreleased]`; stamp `docs/PROGRESS.md` + `docs/PRODUCTION_READINESS.md` with the remediation SHA as each finding closes.

---

## §1 — Roadmap at a glance

| Phase | Theme | Packages | Parallelism |
|---|---|---|---|
| **0 — Quick wins** | low-risk hygiene, no cross-deps | WP8 (crypto-hygiene), WP10 (most supply), WP12, WP7 | fully parallel; touch-with-care items as separate single-concern PRs |
| **1 — Ship-blocker** | C1 nonce reuse | WP1 | serial, single PR |
| **2 — Auth + the ONE wire bump** | authenticate control plane + transcript | WP2 (H1, H2), WP6 (HS-03, ZERORTT-2) | H1 parallel; H2+HS-03+ZERORTT-2 serialized into one transcript re-freeze |
| **3 — DoS cluster** | timeouts, concurrency cap, PoW cap, memory amplification, FIPS dep prune | WP5 (H3, DOS-2, DOS-3), WP3, WP4, WP10-SUPPLY-03 | WP5-H3 leaf first → WP3 spine → WP5 DOS-2/3 + WP4 in parallel |
| **4 — Dead-code purge + unsafe hygiene** | delete `networks/`, harden live helpers, unsafe/legacy | WP11, WP9 | parallel (disjoint files) |

**Critical path (5 hops):** WP1 (C1) → WP2-H1 → WP3 core (Semaphore/decouple) → WP5 DOS-2/DOS-3 → WP11. WP4 hangs off WP3 (depth 4); WP6 rides Phase 2's bump (depth 2).

**Why this order:** C1 must land first so every later encrypt/decrypt change builds on a correct nonce boundary (WP2-H1's authenticated-ACK frames draw `header.sequence` from the C1-corrected allocator). The transcript-mutating fixes (WP2-H2 + WP6) share one PROTOCOL bump and one fixture regen. The DoS cluster shares the `accept()`/`drive_server_handshake` flow, so WP3's timeout+Semaphore skeleton lands before WP5's reputation wiring and WP4's frame-phase seam. Dead-code deletion is last so `cargo-semver-checks` reports one coherent set of pre-1.0 pub-surface removals.

---

## §2 — The phased plan

### PHASE 0 — Quick wins (land immediately, fully parallel)

#### WP8 — Crypto hygiene & info-leak (touch-with-care: `crypto/`)
- **CRYPTO-2 / HS-04 — constant-time PoW/cookie MAC compare.** `crypto/pow.rs:60`: replace `self.nonce[8..32] != mac.as_bytes()[0..24]` with `subtle::ConstantTimeEq` — `bool::from(a.ct_eq(b))` (use `bool::from`, NOT `Choice::into()` — clippy-ambiguous under deny). Both windows are fixed 24 bytes. Leave the public-nonce compare at `:46` and the lint-clean `try_into().unwrap_or_default()` at `:51`. *Folded into WP5-H3's same-file edit if WP5 lands first.* Effort S / risk low. Test: `pow_mac_compare_rejects_flipped_byte`.
- **CRYPTO-3 — zeroize transient key material.** Wrap in `zeroize::Zeroizing`: the combined KEM IKM `[ecc, pq].concat()` at `crypto/hybrid_kem.rs:187`; `key_a`/`key_b`/`send_bytes`/`recv_bytes` at `crypto/adaptive_crypto.rs:275-288`; the locals at `crypto/aes_session.rs:52-64`. **Do not** double-wrap `ml_kem_shared` (already `ZeroizeOnDrop`) or wrap `nonce_prefix` (public). One fix covers default + fips (`combine_secrets` is upstream of the fips cfg branch). Effort S / risk low. Verify `cargo clippy --features fips --lib`.
- **INFOLEAK-1 — redact `ResumptionHint` Debug.** `api/session.rs:109-117`: replace `derive(Debug)` with a hand-written impl printing `resumption_secret: "REDACTED"` (mirror `HybridSigningKey` at `hybrid_sign.rs:178-185`). Keep `Clone`, `uniffi::Record`, `#[non_exhaustive]` (UniFFI needs no Debug → ABI-safe). NOT a codeowner path. Test: `{:?}` contains no secret bytes. Effort S / risk low.
- **CRYPTO-4 (disputed) — `verify_strict` for the Ed25519 half.** `crypto/hybrid_sign.rs`: switch `verify`→`verify_strict` (ed25519-dalek 2.2 exposes it; no dep bump). Rejects non-canonical/malleable signatures; safe because we only generate canonical ones. Applies to both builds (Ed25519 half never swaps under fips). Propagate with existing `?`/`map_err`. Effort S / risk low.

#### WP10 — Supply chain (most items; SUPPLY-03 deferred to Phase 3)
- **SUPPLY-01 — split the uniffi `cli` feature off the runtime lib.** `core/Cargo.toml:217`: change the `uniffi` dep to carry only `["tokio"]`; add a `uniffi-cli` feature enabling `cli`; add explicit `[[bin]]` for `uniffi-bindgen` with `required-features = ["uniffi-cli"]` (the `uniffi_bindgen_main` symbol needs `cli`). Set `default-features = false` on `phantom_core` in `server/Cargo.toml:15`. Drops `clap`/`cargo_metadata`/`tempfile` from default builds. Verify `bindings.yml` drift green (generate scripts pass `--features uniffi-cli`), `cli-check`/server build. Effort M / risk low.
- **SUPPLY-02 — drop unused `chacha20poly1305`.** `core/Cargo.toml:183` + its `dep:` in the `std` feature; **keep** the `CipherSuite::ChaCha20Poly1305` wire enum value (value 2). Update stale comments (`lib.rs:126`, `transport/mod.rs:20`). Commit regenerated `Cargo.lock`. Effort S / risk low.
- **SUPPLY-04a — fix `deny.toml:16` rationale.** The RUSTSEC-2026-0097 ignore falsely claims `rand` is dev-only; it is a runtime dep (`types.rs:25`, `path.rs:225`). Correct the comment (the pinned `0.8.6` is patched per the advisory's own range). Config-only.
- **SUPPLY-04b — path-challenge RNG via the OsRng seam.** `transport/path.rs:225`: migrate `rand::random()`→`crypto::rng` `OsRng` (fips substrate = aws-lc-rs CTR_DRBG). **Call the seam** (it owns the inventoried `getrandom().expect` PANIC-SAFETY contract) — do not add a fresh `.expect`/`.unwrap` at the call site. Coordinates with Invariant 6.
- **SUPPLY-05 — migrate off `rustls-pemfile`.** `networks/tls.rs:19`: `PrivateKeyDer::from_pem_reader` (`rustls_pki_types::pem`, already in the rustls 0.23 tree); drop the `RUSTSEC-2025-0134` ignore (`deny.toml:14`) **in the same commit**. ⚠️ **Moot if WP11 deletes `networks/` first** — coordinate which package frees the dep; run `cargo tree -i rustls-pemfile` before removing the ignore (else `cargo deny` warns advisory-not-found).
- **SUPPLY-06 — doc fix.** `CLAUDE.md:124` (and grep `docs/` for `rc.11`/`0.1.0-rc`): `ml-dsa =0.1.0-rc.11` → `0.1.0` (matches `Cargo.toml:195`).

#### WP12 — API footguns
- **APIFFI-03 — hoist the early-data size check.** `api/session.rs:1922-1937`: move `early_data.len() > EARLY_DATA_MAX_LEN` above `TcpStream::connect` in `connect_pinned_with_resumption` (keep the inner check at `:312`). Use `return Err(...)`, copy the existing block. Test using TEST-NET-1 `192.0.2.1` for a deterministic short-circuit. Effort S / risk low.
- **APIFFI-02 (disputed) — loud-fail the transport-less session.** The exported `connect()` returns a session whose `recv()` deadlocks. Make `send`/`recv` return a clear `CoreError` (reuse existing variant) instead of blocking; `AtomicBool` with `Ordering::Relaxed` (match `:1585`). ⚠️ **`test_phantom_session_send_queue` (`:2032`) constructs via `connect()` and asserts queueing — it MUST be updated in the same change** (add a `#[cfg(test)] pump_started` setter or reframe to assert the error) or CI's `test` job goes red. No signature change → ABI-safe.

#### WP7 — Path validation (medium, but standalone — no urgency, no deps)
- **PATH-001 — make Invariant 6 code-true (wire the receive-side gate).** `api/session.rs handle_packet`: after decrypt and after the control-flag branches (PATH_VALIDATION early-returns at `:1495`, COALESCED at `:1534`), but **before** delivery (before the RELIABLE-ACK block at `:1542` and `deliver_tx.send` at `:1565`), add: if `crypto_recv.path_state(path_id)` is not `Some(Validated)`, `register_unvalidated_path(path_id)` if absent, `record_unvalidated_path_dropped(leg)`, `warn!`, and `return`. New `register_unvalidated_path` (`pub(crate)`) near `begin_path_validation` (`transport/session.rs:661`) + an observability counter. No break today (single transport, all data AEAD-authed) but closes the false-assurance landmine. Effort M / risk low. Tests: `app_data_on_unvalidated_path_is_dropped`, `path_becomes_deliverable_after_validation` (so the gate isn't permanently fail-closed). No wire/ABI/FIPS/cross impact.
- **PATH-003 (disputed) — idempotent challenge re-issue.** `transport/path.rs:215-229`: if a path is already `Validating` and `pending_challenge.lock().is_some()`, return the existing challenge instead of clobbering it (take the lock **once**, decide under it — avoid TOCTOU with `verify_response` which `take()`s the slot). Only allocate a fresh challenge on `Unvalidated→Validating`. Test: `reissue_on_validating_path_keeps_original_challenge`. Effort S / risk low.

**Phase 0 exit:** `cargo test --lib`, `--test security_invariants`, `--test property` green; `cargo deny check` passes **without** the RUSTSEC-2025-0134 ignore and with corrected 2026-0097 rationale; `clippy --lib` and `--lib --features fips` clean; `bindings.yml` drift green; `cargo tree` shows `clap`/`cargo_metadata`/`tempfile`/`chacha20poly1305` gone from default; `cli-check` + server build.

---

### PHASE 1 — Ship-blocker: C1 nonce reuse (serial, gates all downstream wire/crypto)

#### WP1 — C1 (CRITICAL, Invariants 8 & 5; touch-with-care: `session.rs`, reasons about `crypto/`)
**Root cause:** the AEAD nonce embeds the per-stream `u32` `header.sequence` (`build_packet_nonce`, `session.rs:771-779`), but the only rekey trigger `send_needs_rekey()` (`session.rs:526`) keys off the **direction-wide** `send_counter` vs `REKEY_SOFT_LIMIT=2⁴⁷` (`session.rs:56`). A single hot stream wraps its `AtomicU32` sequence at 2³² while the direction counter is still ~2³² (2¹⁵ below the trigger) → no epoch/prefix change → nonce repeats. The receiver is **already correct** (`decrypt_packet_accepting_rekey`, `session.rs:1398`, trial-decrypts up to `MAX_REKEY_CATCHUP=16` epochs ahead) — only the send-side trigger is wrong.

**Recommended design — (a) per-stream watermark forced rekey + (c) fail-closed backstop (NO wire change):**
1. Add `pub const SEQ_REKEY_WATERMARK: u32 = 1 << 31;` (2³¹ leaves a full 2³¹ of reorder/in-flight headroom before the 2³² wrap) and optionally `SEQ_HARD_LIMIT: u32 = (1<<31)|(1<<30)` near `session.rs:56`.
2. Track the max per-stream sequence reached in the current epoch: add `max_stream_seq_this_epoch: AtomicU32` to `Session` (reset to 0 in `commit_forward_crypto` at `:490` alongside the epoch bump). Add `CryptoSession::stream_seq_needs_rekey(seq) -> bool` returning true once a stamped seq crosses `SEQ_REKEY_WATERMARK`.
3. In `send_app_data` (`api/session.rs:1231`) change the rekey decision to `if send_needs_rekey() || stream_seq_needs_rekey(seg.seq)` — **the check MUST run before stamping the header** so the crossing packet goes out under the *new* epoch.
4. Fail-closed backstop: add `Stream::reserve_send_sequence() -> Option<SequenceNumber>` using `checked_add` (returns `None` at `u32::MAX`). Because (a) caps each epoch at 2³¹, the u32 never actually reaches `u32::MAX` within an epoch; (c) converts any logic error in (a) into a hard fail instead of silent reuse. Since `epoch:u8` saturates at 255 (`rekey()` errors at `:434-436`) and each epoch gets a 2³¹ budget, a single stream caps at ~255·2³¹ ≈ 2³⁹ packets; at that boundary `send_app_data` must **fail-closed → session reconnect**, not wrap.

**Rejected:** (b) widen `sequence` to `u64` — an unnecessary `WIRE_VERSION 2→3` bump (header 45→49B, all packet fixtures + `check_wire.rs` regenerated). (c)-only — wastes the existing rekey machinery and forces reconnects too often.

**Devil-details:**
- **The fail-closed path must distinguish "crypto fail-closed → terminate session" from "transient transport failure → re-offer via `mark_unsent`"** — a naive `return false` busy-loops the pump (`api/session.rs:1147`). Use a distinct fatal tear-down signal, not infinite re-offer.
- `rekey` does **not** reset per-stream sequence; it changes epoch+prefix+keys — so the forced rekey restores nonce uniqueness via the epoch change. But epoch saturation (255) is the hard ceiling → reconnect.
- Test seam `set_seq_rekey_watermark(u32)` and `max_stream_seq_this_epoch` are **Rust-only — never `#[uniffi::export]`**. No `CoreError` variant added (reuse an existing error path) → ABI-safe.
- Cipher-agnostic (`fetch_max`/`wrapping_sub`/`checked_add`/integer compares) → identical under fips, builds on every cross target, no Runtime involvement.
- **`phantom-rekey-v1` HKDF label (`session.rs:473`) and nonce layout (`:771`) MUST NOT change (Invariant 5).**

**Tests:** `security_invariants.rs::single_stream_seq_watermark_forces_rekey_before_wrap` (epoch advances via the watermark; zero duplicate nonce tuples), `seq_boundary_fails_closed_at_epoch_saturation` (fatal signal at `u8::MAX` epoch, NOT a busy-loop), `property.rs::no_nonce_repeats_across_forced_rekeys` (bijective nonce check), `tcp_integration.rs` (#[ignore]) single-stream bulk transfer shows `current_epoch()` advancing. **All frozen fixtures + `transcript_hash.bin` + `check_wire.rs` UNCHANGED** (proof of no wire impact). Effort M / risk medium.

**Docs:** rewrite `PROTOCOL.md §5 "Automatic rekey (C1)"` (lines 330-335) + "Uniqueness" (line 297); extend CLAUDE.md Invariant 8 (per-stream watermark is now the *primary* nonce-uniqueness boundary; 2⁴⁸ direction ceiling is secondary) + note Invariant 5; `threat-model.md:164`; `CHANGELOG` Security.

**Phase 1 exit:** the four new tests green; frozen fixtures byte-identical; fips lib build + clippy green; codeowner review citing Invariants 8 & 5.

---

### PHASE 2 — High-severity auth + the coordinated PROTOCOL_VERSION 1→2 bump

#### WP2 — Control-plane authentication (depends_on WP1)
- **H1 — authenticate ACK/FIN (Invariant 2; touch-with-care: `session.rs`).** Make ACKs a **new encrypted control frame `ENCRYPTED | ACK`**, structurally like the existing WINDOW_UPDATE frame (`session.rs:1276-1302`). The acked sequence travels in the **4-byte big-endian ENCRYPTED payload** (not `header.sequence`); `header.sequence` is drawn from the acker's own `Stream::next_send_sequence()` (the **C1-corrected** allocator — hence the WP1 dependency) so the nonce never collides with the acker's outbound data. Concretely:
  1. At `handle_packet` top (`session.rs:~1366`) add a **session-id guard**: `if packet.header.session_id != session_id { return; }` — binds every inbound frame to the negotiated session.
  2. **Delete** the pre-decrypt ACK short-circuit (`session.rs:1374-1388`).
  3. Add a post-decrypt branch (after `plaintext` at `:1425`, before WINDOW_UPDATE at `:1430`): on `flags.contains(ACK)`, parse the 4-byte BE acked-seq from `plaintext` (use `match`/`map_err`, mirror the WINDOW_UPDATE length check at `:1431-1437` — drop on malformed), then run `stream.ack`/`feed_bbr_on_ack`/`route_ack`/`route_close` keyed on the **authenticated** seq. Peer-initiated close uses the existing post-decrypt FIN check at `:1572-1574` (now only fires on a decrypted frame).
  4. Replace the inline plaintext ACK builder (`:1542-1557`) with a `send_ack` helper modeled on `send_window_update`: `flags = ENCRYPTED | ACK` (OR `FIN` to ack-close), `header.sequence = stream.next_send_sequence()`, payload = acked seq as 4 BE bytes, then `encrypt_packet` + `send_bytes`. The stripped-flag downgrade branch (`:1415-1422`) now also protects ACKs.

  Keeps the lock-free `ArcSwap` encrypt (no rekey-lock, prompt-when-consumer-slow). **Perf:** ACKs now pay one AES-GCM seal+open — if >5% on the ack-heavy bench, record in `BENCHMARKS.md`. Wire: container/header byte-identical (only ACK flags+payload change) → `packet_header.bin`/`phantom_packet_*.bin` unaffected. No ABI change. Effort M / risk medium. Tests: `forged_plaintext_ack_does_not_mutate_send_state`, `forged_ack_wrong_session_id_dropped`, `authenticated_ack_roundtrip` (positive control), + wire-observation negative assert (no plaintext ACK appears).

- **H2 — transcript-sign `early_data_accepted` (Invariants 9/7/10; touch-with-care: `handshake.rs`).** Add `early_data_accepted: bool` to the signed `HandshakeTranscript` (`handshake.rs:221-228`) as the **LAST field** (keep `protocol_variant` leading per Invariant 10). Server: it's already computed at `:476` before the transcript is built, so add it to the literal at `:498-505`. Client: add `early_data_accepted: server_hello.early_data_accepted` to the verify-site literal at `:818-825` — the existing `verify()` at `:827-830` **is** the enforcement (a flipped bit → recomputed hash differs → `KemFailed("Signature check failed")`, no new branch). This makes the C3 retransmit (`session.rs:570-577`) depend only on authenticated material. Bump `PROTOCOL_VERSION 1→2`. Regenerate `transcript_hash.bin` (update the test sample at `handshake.rs:1141-1168`); verify `server_hello*.bin` does NOT change. Effort M / risk medium. Tests: `flipped_early_data_accepted_bit_fails_signature`, `honest_early_data_verdict_verifies`.

#### WP6 — 0-RTT resumption hardening (shares the PROTOCOL bump; touch-with-care: `handshake.rs`, `crypto/kdf.rs`, security-adjacent `session_cache.rs`)
- **HS-03 — resumption proof-of-possession binder (Invariant 9).** Add `resumption_binder: Option<[u8;32]>` to `ClientHello` (`handshake.rs:124-155`, **immediately after `resume_session_id` at `:141`, before `protocol_variant`** — order is load-bearing for borsh + the Python decoder). Client computes it on resume via a new helper: `derive_key_32("phantom-resume-binder-v1", resumption_secret(32) ‖ resume_session_id(32) ‖ client_nonce(32))`. Server (rewrite `:448-455`): **peek** the ticket (new `SessionCache::peek` — no remove), recompute the expected binder, compare with `subtle::ConstantTimeEq`; only on match proceed to the resume fast-path. A missing/wrong binder → no cookie/PoW bypass, ticket untouched → normal 1-RTT fallback. Effort M / risk medium.
  - **Devil:** use `ct_eq` (timing oracle otherwise); **guard the `None` case explicitly** (don't `ct_eq` a default that could collide with a real zero binder). `derive_key_32` dispatches blake3/HKDF → binder bytes differ per build (fine). Regenerate `client_hello_*.bin`, `transcript_hash.bin`, and the Python decoder. Tests: `replayed_resume_without_binder_does_not_burn_ticket`, `binder_mismatch_constant_time_rejected`, `security_invariants.rs::resumption_ticket_survives_unauthenticated_replay`.
- **ZERORTT-2 — consume the ticket only on success (Invariant 9).** Recommended: **consume eagerly after the binder check** (so a concurrent double-resume with the same valid binder can't both win), then **re-insert with the ORIGINAL expiry** on every post-consume failure path (KEM fail `:481-483`, transcript-hash fail `:507-509`, `finalize_session` Err `:523-526`). Add `SessionCache::reinsert_with_expiry(id, secret, suite, created_at, expires_at)` preserving timestamps (a naive `store` would **extend** the ticket lifetime — anti-replay window widening) and refusing to resurrect an expired ticket; fix up `lru_order` consistently with `store`/`remove`. Effort M / risk medium. Tests: `forced_kem_failure_leaves_ticket_usable`, `security_invariants.rs::resumption_ticket_not_consumed_on_handshake_failure`.

**Phase 2 exit:** **one** `transcript_hash.bin` (+ `client_hello_*.bin`, verified `server_hello*.bin`) regen on a default build; Python decoder updated + cross-decoder byte-exact; all WP2/WP6 negative tests green; `PROTOCOL_VERSION` = 2 everywhere; `fips-feature` CI green (struct edits are unconditional; fips transcript round-trips); per-PR codeowner review citing Invariants 2, 7, 9, 10.

---

### PHASE 3 — High-severity DoS cluster

#### WP5-H3 — client PoW difficulty cap + bounded solver (HIGH; leaf — land first; touch-with-care: `crypto/pow.rs`)
- Add `MAX_CLIENT_POW_DIFFICULTY: u8 = 24` and `MAX_SOLVE_ITERATIONS: u64 = 1 << (24+8) = 2³²` to `crypto/pow.rs`. **In `run_client_handshake` (`api/session.rs:680-683`), BEFORE solving and inside the retry arm (so EVERY round is checked)**, reject `challenge.difficulty > MAX_CLIENT_POW_DIFFICULTY` → `CoreError::HandshakeError(...)`. Change `solve()` → `Result<PoWSolution, PowError>` iterating `0..MAX_SOLVE_ITERATIONS` (no clock — keeps it portable/sync), returning `Err(PowError::Exhausted)` past the bound. Propagate with `map_err`+`?`.
- **Devil:** **`MAX_CLIENT_POW_DIFFICULTY` MUST be ≥ 20** — the frozen `pow_challenge.bin` has `difficulty:20` and `ReputationTracker::MAX_DIFFICULTY=20`; a lower cap self-rejects a legitimate server. `2³²` headroom over the worst legit `2²⁴` so real solves never spuriously fail; never set iterations `== 2^difficulty`. `solve()→Result` is a pre-1.0 public-API change on `PoWChallenge` (only caller `session.rs:682`) — note in `CHANGELOG`; do NOT add a `CoreError` variant. No wire/fixture/ABI/FIPS impact. Effort S / risk low. Tests: `client_rejects_oversized_pow_difficulty_without_solving` (<1s), `solve_is_bounded_and_fails_closed` (via a `#[cfg(test)] solve_bounded(max_iters)` helper), `solve_round_trips_at_realistic_difficulty`.

#### WP3 — handshake timeouts + accept-loop decouple (HIGH; the serial spine of this phase)
- **H4 timeout (`api/listener.rs`).** Add `HANDSHAKE_DEADLINE = 10s`, `HANDSHAKE_READ_TIMEOUT = 5s`. Pass `&self.runtime` into `drive_server_handshake` (`:363`); compute `deadline = runtime.now_monotonic() + HANDSHAKE_DEADLINE` before the loop; wrap each `recv_bytes().await` (`:369`) in `select!` against `runtime.sleep(min(READ_TIMEOUT, deadline - now))` → `CoreError::Timeout` on expiry. **Timer = `Runtime::sleep`, not `tokio::time`** (§0.5). The deadline is computed **once** (an attacker must not reset the budget via retries). Effort M / risk medium.
- **H4 decouple (`api/listener.rs`).** A single internal `acceptor` task owns the `TcpListener`; per connection it acquires a permit from `inflight_handshakes: Arc<Semaphore>` (~256, distinct from the embedder's established-session cap), `self.runtime.spawn`s the handshake (with the timeout), and pushes the result into an internal `mpsc`. `accept()` selects `mpsc::Receiver.recv()` against `shutdown_notify` (preserving the `ConnectionClosed` contract at `:213-225`) and builds the `PhantomSession` as today (`:261-268`). **`accept()` signature is byte-identical** → no ABI change. Permit released via `OwnedSemaphorePermit` RAII in the spawned task. **PhantomListener gains private fields only — do NOT add public methods** (keeps `cargo-semver-checks` green). Effort L / risk high. Tests: `accept_times_out_on_stalled_peer_and_others_still_connect`, `inflight_handshake_semaphore_bounds_concurrency` (#[ignore] TCP).
- **DOS-4 (`api/listener.rs:368`).** `MAX_SERVER_RETRY_ROUNDS = 2`; bound the Retry loop → `CoreError::Timeout` past the cap. Effort S / risk low. Test: `server_caps_retry_rounds`.
- **HS-02 (touch-with-care: `session.rs`).** `MAX_CLIENT_RETRY_ROUNDS = 3` in `run_client_handshake` (`:677` arm); wrap the whole client handshake in `background_task` (`:536-541`, `runtime` already in scope at `:497`) in a `CLIENT_HANDSHAKE_DEADLINE = 10s` `select!` against `runtime.sleep` → `ConnectionState::Failed` (no panic). Effort M / risk medium. Tests: `client_caps_hello_retry_rounds`, `client_handshake_times_out_against_silent_server` (#[ignore]). Update `docs/security/cancel-safety-audit.md` with the new client-handshake `select!`.

#### WP5-DOS-2 — wire `ReputationTracker` with a BOUNDED map (MEDIUM; after WP3 Semaphore; touch-with-care: `handshake.rs`)
- Add `reputation: Arc<ReputationTracker>` to `HandshakeServer` (`:254-278`, `#[zeroize(skip)]`); init `with_capacity(100_000)` at `:322`. Add `pub(crate)` wrappers (`reputation_difficulty`/`record_violation`/`reset_violations`/`gc_reputation`) near `adaptive_difficulty` (`:366`). In `drive_server_handshake` (`:376`): `difficulty = adaptive_difficulty().max(reputation_difficulty(ip, has_ticket))`; `reset_violations(ip)` on success, `record_violation(ip)` on **genuine** failure (NOT the normal first-contact cookie Retry — coordinate with DOS-4). Drive periodic `gc()` via `Runtime::sleep`.
- **Devil — the bounded map is NON-OPTIONAL:** `reputation.rs:26`'s `DashMap<IpAddr,_>` has no count cap; wiring it naively converts a CPU-DoS into a memory-DoS under a spoofed-source flood. Add `max_entries` + gc-then-evict-or-skip on overflow (`reputation.rs:25,44-59`). Keep `ReputationTracker` `pub` (sole consumer `syn_flood_bench.rs`). Effort M / risk medium. Tests: `repeated_handshake_violations_escalate_per_ip_difficulty` (8→10→14→20), `reputation_map_is_bounded`, integration test proving `.max()` wiring. Fix the stale `PRODUCTION_READINESS.md:224,677` half_open references.

#### WP5-DOS-3 — delete `HalfOpenSlots` (LOW; after WP3 Semaphore exists)
- Delete `transport/half_open.rs` + `pub mod half_open` (`transport/mod.rs:36`). It's a TTL slot-store (wrong primitive — the TCP path holds handshake state on the spawned task's stack); WP3's `Semaphore` is the correct concurrent-handshake cap. **Order: WP3's Semaphore in FIRST, then delete** (else the SYN-flood guard vanishes with no replacement). `pub` removal = `cargo-semver-checks` flag → `CHANGELOG` Removed (pre-1.0 OK). Effort S / risk low.

#### WP4 — memory amplification & framing (parallel off non-codeowner files; depends_on WP3 for the frame-phase seam)
- **WIRE-001 (`api/tcp_transport.rs`, mirror `legs/wasi.rs`).** Stop pre-allocating the full declared length: read incrementally into a bounded `BytesMut` by `RECV_CHUNK = 64 KiB` (replicate `UnexpectedEof` on `n==0` mid-frame via returned `Err`, never spin/panic — `#![deny(unsafe_code)]` forbids the reserve+unsafe-write alt). Two-phase cap: `HANDSHAKE_FRAME_CAP = 64 KiB` for the unauthenticated handshake frame, raised to `STEADY_STATE_FRAME_CAP = 4 MiB` (down from 16 MiB) after establishment — via a `set_frame_phase(FramePhase)` default-bodied `SessionTransport` trait method (source-compatible → semver-clean; keep `FramePhase` internal), called at the handshake→pump boundary (`api/listener.rs:~388`, `api/session.rs:~586`). Cap is `AtomicUsize` (Release/Acquire). Effort M / risk medium.
- **LEGS-003 (`api/tcp_transport.rs:105`, mirror `wasi.rs:191`).** After `split_to(len).freeze()`, `if buf.capacity() > RECV_BUF_INITIAL_CAPACITY * SHRINK_SLACK_MULT { buf.shrink_to(RECV_BUF_INITIAL_CAPACITY); }` with `SHRINK_SLACK_MULT = 4` (256 KiB threshold — larger than the 64 KiB chunk/handshake cap so steady traffic never thrashes the allocator). Verify `bytes ≥ 1.4` for `shrink_to`. Effort S / risk low. Test: `accumulator_returns_to_baseline_after_large_frame`.
- **LEGS-002 (`legs/kcp.rs:252-266`).** Bounded incremental read (`RECV_CHUNK`), lower cap 10 MiB → 4 MiB (`:257`), wrap reads in `tokio::time::timeout(KCP_READ_TIMEOUT=30s)` (acceptable — KCP is native-only) → `io::ErrorKind::TimedOut`; flatten `Result<io::Result,Elapsed>` with `map_err`+`?`. **A read timeout is terminal for the leg** (the pump tears down on `Err`) — don't resume a partial frame. Effort M / risk low. Tests: `kcp_oversized_frame_rejected`, `kcp_stalled_body_times_out`.
- **tcp.rs consistency (LOW, optional):** `legs/tcp.rs:114,136` `TcpLeg::read_framed` shares the family (dead path, not session-wired) — lower its cap to 4 MiB + add the shrink for parity, or record as a follow-up. Don't confuse `TcpLeg` (dead) with `TcpSessionTransport` (live).

#### WP10-SUPPLY-03 — FIPS artifact excludes non-approved crypto (the FIPS-central item; touch-with-care: `faketls.rs`)
- Introduce a `default-crypto` sub-feature that `std` enables but `fips` does **not**; gate `ring`/`x25519-dalek`/`chacha20poly1305` behind it. `x25519-dalek` removal is clean (`hybrid_kem.rs` already `cfg(not(fips))`-gates it). **`ring` is the hazard:** three native modules (`aes_session.rs`, `faketls.rs`, `udp_transport.rs`) import `ring` unconditionally — **the source-side fips gating MUST ship in the same change** or the `fips-feature`/`cross.yml` fips rows go red at compile. **Recommended: port the FakeTLS AEAD to `aws-lc-rs` under fips** (rather than dropping the leg). Add a `fips-feature` CI assertion: `cargo tree --features fips --no-default-features | grep -E '^ring|x25519-dalek'` is empty. ⚠️ **Caution:** dev-deps `rustls(features=["ring"])` + `tokio-rustls` (`Cargo.toml:334-335`) pull `ring` into the *test* graph — assert absence only in the non-test `cargo tree`. Default (non-fips) build must stay byte-identical (frozen fixtures valid). Effort M / risk medium.

**Phase 3 exit:** WP5-H3 (`client_rejects_oversized_pow_difficulty_without_solving` <1s, `solve` returns Result, no panic); WP3 (stalled-peer timeout + others connect, semaphore bounds concurrency, retry caps, client timeout; `accept()` ABI byte-identical; `ConnectionClosed`-on-shutdown preserved; acceptor on `self.runtime`); WP5-DOS-2 (`reputation_map_is_bounded`, escalation curve, `.max()` wiring; gc via `Runtime::sleep`); WP5-DOS-3 (`HalfOpenSlots` deleted, `CHANGELOG` Removed); WP4 (oversized handshake frame rejected at 64 KiB, no commit-on-stall, accumulator returns to baseline, KCP cap+timeout; no `n==0` busy-loop; outbound stays 4 MiB); WP10-SUPPLY-03 (`fips-feature` green, `cargo tree --features fips` shows no `ring`/`x25519-dalek`, Invariant-3 faketls counter-nonce test passes under both backends, default build byte-identical). Codeowner review for `session.rs`/`faketls.rs` citing Invariants 1, 2, 3 (none weakened).

---

### PHASE 4 — Dead-code purge + unsafe/legacy hygiene (parallel; WP11 depends_on WP5's reputation decision)

#### WP11 — delete the `networks/` layer + harden live helpers + delete orphans
- **Delete the entire `networks/` layer (HIGH — kills critic gaps #1 & #3 at the root).** Remove `networks/{engine,pipeline,tls,transport,mod}.rs` and `pub mod networks` (`lib.rs:136-137`). This eliminates the **`debug_assertions` cert-pinning bypass** (`tls.rs:26`) and the **plaintext-forwarding engine** (`engine.rs` "crypto would go here"), and frees the 4 native TLS deps (`rustls`/`tokio-rustls`/`rustls-pemfile`/`webpki-roots` — `Cargo.toml:73,75,76,255-258`). Drop the `RUSTSEC-2025-0134` ignore (`deny.toml:9-14`) here if WP10-SUPPLY-05 didn't already (run `cargo tree -i rustls-pemfile` first). `pub mod` removal = `cargo-semver-checks` flag (pre-1.0 OK). Effort S / risk low. Validate via `cargo check --lib` + `cli-check` + `cargo deny check` + `cargo doc` (no dangling intra-doc links).
- **AdaptiveCompressor decompression cap (MEDIUM — WIRE-003, since it's `pub`).** `transport/compression.rs`: LZ4 — read the 4-byte prepended size, reject `> MAX_DECOMPRESSED_LEN` (~1 MiB const) **before** allocating, then bounded-decompress (don't trust `decompress_size_prepended`). Zstd — size-limited streaming `Decoder` aborting past the cap (not `decode_all`). Add `CompressionError::OutputTooLarge` (enum has zero external callers, not `#[non_exhaustive]` → pre-1.0 OK). Use `?`/`map_err`. Effort S / risk low. Tests: `decompress_bomb_lz4_rejected`, `decompress_bomb_zstd_rejected`.
- **FragmentAssembler hardening (MEDIUM — WIRE-002).** `transport/fragmentation.rs:17-121`: add `max_assemblies` + `max_total_bytes` caps (reject/evict-oldest), validate `chunk_index < total_chunks`, reject `total_chunks == 0` and first-frame-total mismatches, run the 5000ms dead-timer eviction **inline at the top of `process_chunk`** (so it can't grow unbounded without the externally-called method). Replace the two `#[allow(unwrap_used)]` blocks with graceful `None` returns; if you change them, update `docs/security/panic-sites.md` counts. Effort M / risk medium. Tests (in `security_invariants.rs`): `fragment_assembler_rejects_out_of_range_index`/`_rejects_zero_total_chunks`/`_caps_concurrent_assemblies`/`_evicts_dead_inline`.
- **Delete orphans + dead `validation.rs`.** `networks/serialization.rs` (rkyv/bytecheck — deps not even in Cargo.toml; UB-on-untrusted-bytes vector) and `networks/compression.rs` (orphan zstd dup) vanish with the dir. Delete `validation.rs` + `pub mod validation` (`lib.rs:122-123`) — `InputValidator` is dead and encodes stale assumptions (16-byte group IDs, u64 epochs vs the live u8 epoch). `pub mod validation` removal = semver flag (pre-1.0 OK). Effort S / risk low.
- **DO NOT touch `reputation.rs`** — WP5-DOS-2 wires it (and `syn_flood_bench.rs` consumes it). WP11 only flags the unbounded-map concern, which DOS-2 resolves.
- **Refresh stale crate-root comments** (`lib.rs:55-61` "two/three modules", `:136-137` networks phrasing) + CLAUDE.md "Networks layer" section + Conditional Compilation Matrix native-crate list. Coordinate with WP9-UNSAFE-2 so the audit-lens is consistent in one pass.

#### WP9 — unsafe soundness & legacy correctness (parallel; faketls-2 is the only codeowner item)
- **UNSAFE-1 (`legs/wasi.rs:82-107`).** Tighten the SAFETY comment to **explicitly carve out `_socket`** (access-only-on-Drop, never deref'd through a shared `&self`) — and/or wrap `_socket` to structurally enforce the mutex contract. Keep the `unsafe impl Send/Sync` (Resource<T> is `!Send`; the Mutex enforces single-accessor). Don't add a third `.expect` for `_socket`; don't lock in `Drop`. Validate via the `wasm32-wasip2` cross row / `wasi-integration` job. Effort S / risk low.
- **UNSAFE-2 (`udp_transport.rs:317-374`).** The `sendmmsg`/GSO unsafe is dead + sound — **gate it behind an explicit `gso` feature, or delete it** (so the only shipped hand-written `unsafe` is live+tested). If deleting: `GsoBatchResult` (a `pub` type) removal = semver flag (pre-1.0 OK); remove `all_sent` + `test_gso_batch_result` in the same commit. Fix the stale `recvmmsg` refs (`lib.rs:56`, `udp_transport.rs:19`) + the CLAUDE.md "two modules" audit-lens. Effort S / risk low.
- **LEGS-004 (`virtual_socket.rs:220-228,304-306`).** Share one `Arc<AtomicBool>` for `closed` (clone the Arc, not the bool) so `close()` signals the recv loop. `Ordering::Relaxed`. Effort S / risk low. Test: `VirtualSocket` recv-loop terminates on `close()`.
- **LEGS-005 (`virtual_socket.rs:244-258`).** Parse the header via `PacketHeader::from_wire` (big-endian, `?`) instead of magic offsets/little-endian. Reader-only (no wire emit). Effort S / risk low. Test: `decode_ack_sample` agrees byte-for-byte with the canonical codec.
- **faketls-2 (touch-with-care: `faketls.rs:605-608,615`; Invariant 3).** Replace the seal `.unwrap()` with `?` (not `.expect`); reject payloads whose framed length would exceed `u16::MAX` → `Err(InvalidData)` **before** the `in_out.len() as u16` cast (`:615`). PR must state Invariant 3 (per-record counter nonce + direction-keyed AEAD) is preserved. Effort S / risk low. Test: 16384B payload round-trips across peers; oversized → `Err` not panic.
- **faketls-1 (disputed) — DEFER.** Surfaced only to prevent a contributor adding a non-portable `tokio::time::timeout`; the portable answer is a byte-ceiling, and WP3's Runtime-deadline already covers the live path. No action unless forced.

**Phase 4 exit:** `cargo check --lib` + `cli-check` + server build clean after deletions; `cargo deny check` passes; `cargo doc` green; `cargo-semver-checks` reports the deliberate pre-1.0 removals (one `CHANGELOG` Removed entry: `networks::*`, `validation::InputValidator`, `HalfOpenSlots`, `GsoBatchResult` if deleted); decompression/fragment tests green; `security_invariants.rs` count bumped in CLAUDE.md; WP9 tests green; `panic-sites.md` + crate-root audit-lens refreshed; full `cross.yml` matrix (wasm32/thumbv7em/wasi) green.

---

## §3 — Finding traceability matrix

| Finding | Sev (corrected) | WP | Phase | Wire/ABI | Status |
|---|---|---|---|---|---|
| AEAD-1 / CRYPTO-1 (**C1**) | critical | WP1 | 1 | none (rejected u64 bump) | confirmed |
| AEAD-2 / APIFFI-01 (**H1**) | high | WP2 | 2 | ACK flags+payload (no WIRE bump) | confirmed |
| ZERORTT-1 (**H2**) | high | WP2 | 2 | PROTOCOL 1→2, transcript_hash.bin | confirmed |
| HS-01 (**H3**) | high | WP5 | 3 | none | confirmed |
| DOS-1 / LEGS-001 (**H4**) | high | WP3 | 3 | none | confirmed |
| WIRE-001 | medium | WP4 | 3 | none | confirmed |
| LEGS-002 | medium | WP4 | 3 | none | confirmed |
| LEGS-003 | medium | WP4 | 3 | none | confirmed |
| HS-02 | medium | WP3 | 3 | none | confirmed |
| PATH-001 | medium | WP7 | 0 | none | confirmed |
| DOS-2 | medium | WP5 | 3 | none | confirmed |
| CRYPTO-2 / HS-04 | low | WP8 (via WP5) | 0/3 | none | confirmed |
| CRYPTO-3 | low | WP8 | 0 | none | confirmed |
| HS-03 | low | WP6 | 2 | PROTOCOL 1→2, client_hello+transcript fixtures | confirmed |
| ZERORTT-2 | low | WP6 | 2 | (shares HS-03 bump) | confirmed |
| WIRE-002 | low | WP11 | 4 | none | confirmed |
| faketls-2 | low | WP9 | 4 | none | confirmed |
| LEGS-004 | low | WP9 | 4 | none | confirmed |
| UNSAFE-1 | low | WP9 | 4 | none | confirmed |
| DOS-4 | low | WP3 | 3 | none | confirmed |
| SUPPLY-01 | low | WP10 | 0 | adds `uniffi-cli` feature | confirmed |
| SUPPLY-02 | low | WP10 | 0 | none (keep enum value) | confirmed |
| SUPPLY-03 | low | WP10 | 3 | adds `default-crypto` feature | confirmed |
| INFOLEAK-1 | low | WP8 | 0 | none (ABI-safe) | confirmed |
| LEGS-005 | info | WP9 | 4 | none | confirmed |
| APIFFI-03 | info | WP12 | 0 | none | confirmed |
| UNSAFE-2 | info | WP9 | 4 | `GsoBatchResult` removal (if deleted) | confirmed |
| SUPPLY-04 | info | WP10 | 0 | none | confirmed |
| SUPPLY-05 | info | WP10/WP11 | 0/4 | none | confirmed |
| CRYPTO-4 | disputed | WP8 | 0 | none | disputed→fix |
| WIRE-003 | disputed | WP11 | 4 | none | disputed→fix (compression cap) |
| PATH-002 | disputed | WP11 (covered by deletion / VirtualSocket) | 4 | none | disputed→addressed |
| PATH-003 | disputed | WP7 | 0 | none | disputed→fix |
| DOS-3 | disputed | WP5 | 3 | `HalfOpenSlots` removal | disputed→fix |
| APIFFI-02 | disputed | WP12 | 0 | none | disputed→fix |
| SUPPLY-06 | disputed | WP10 | 0 | none (doc) | disputed→fix |
| faketls-1 | disputed | WP9 | 4 | none | disputed→DEFER |
| ZERORTT-3 | dropped | — | — | — | refuted (test exists + CI-gated) |
| **Critic #1** networks/tls pinning bypass | high (latent) | WP11 | 4 | `pub mod networks` removal | gap→fix (delete) |
| **Critic #2** decompression bomb | medium (latent) | WP11 | 4 | none | gap→fix (cap) |
| **Critic #3** networks/engine plaintext | high (latent) | WP11 | 4 | `pub mod networks` removal | gap→fix (delete) |
| **Critic #4** orphan rkyv serialization.rs | low (latent) | WP11 | 4 | none | gap→fix (delete) |

---

## §4 — Governance & docs checklist (per CLAUDE.md / CONTRIBUTING)

**CLAUDE.md Security Invariants — edits/additions:**
- **Inv 8 (WP1):** per-stream sequence watermark is the *primary* nonce-uniqueness boundary (forced epoch bump + fresh prefix before any `u32` seq reaches `SEQ_REKEY_WATERMARK=2³¹`, fail-closed backstop); 2⁴⁸ direction ceiling is secondary.
- **Inv 5 (WP1):** rekey is now also driven by the per-stream watermark — `phantom-rekey-v1` label + nonce layout unchanged.
- **Inv 2 (WP2-H1):** ACK/FIN are AUTHENTICATED (`ENCRYPTED` control frames, acked-seq in AEAD payload); `handle_packet` binds `header.session_id` on every inbound frame. Rewrite the "Wire-Format and AAD Notes" ACK bullet.
- **Inv 9 + 7/10 (WP2-H2):** the 0-RTT `early_data_accepted` verdict is transcript-SIGNED (flipped bit → signature mismatch).
- **Inv 9 (WP6):** resumption consumption requires a `resumption_binder` PoP verified constant-time before consume; ticket consumed only after binder+KEM+transcript success, re-inserted (original expiry) on failure.
- **Inv 6 (WP7):** wording changes from doc-only to CODE-TRUE — `handle_packet` drops app data on any non-Validated `path_id` (path 0 implicitly validated). (WP10-SUPPLY-04b: challenge now from the OsRng/getrandom CSPRNG seam.)
- **NEW (WP4-WIRE-001):** unauthenticated handshake frames capped at 64 KiB; 4 MiB steady-state cap raised only after establishment.
- Non-invariant edits: listener.rs (WP3 decouple+timeout), tcp_transport/wasi (WP4), add `reputation.rs` to the layer map (WP5-DOS-2), fix the stale audit-lens (WP9-UNSAFE-2), FFI/Common-Commands (WP10-SUPPLY-01), Conditional-Compilation Matrix (`default-crypto`, networks deletion), `ml-dsa` doc (SUPPLY-06), bump the `security_invariants.rs` test count (WP11).

**Other docs:** `PROTOCOL.md` (§5 rekey, §6 flags/ACK, §6.2/§6.6 ClientHello+resumption_binder+KDF label, §6.9 PoW cap + reputation, PROTOCOL_VERSION rows, framing caps); `threat-model.md` (nonce-exhaustion, unauthenticated-control Tampering, handshake-deadline STRIDE-D, amplification, reflected-CPU PoW, HS-03/ZERORTT-2, path-validation, cookie-compare timing→`pow.rs:60`, ResumptionHint redaction); `docs/compliance/{constant-time-audit.md (correct the false class-A claim + add pow.rs:60),key-management.md,fips-readiness.md}`; `cancel-safety-audit.md` (HS-02 select!); `panic-sites.md` (WasiLeg, FragmentAssembler, count); `observability/metrics-catalog.md` (unvalidated-path drop counter); `versioning.md` (PROTOCOL 1→2 + pre-1.0 pub retractions); `ARCHITECTURE.md` (remove Networks layer, add acceptor task topology); `PRODUCTION_READINESS.md:224,677` (fix stale half_open references).

**`deny.toml`:** remove RUSTSEC-2025-0134 ignore in the commit that frees `rustls-pemfile` (`cargo tree -i` first); correct the RUSTSEC-2026-0097 (`rand`) rationale.

**`CHANGELOG.md [Unreleased]`** (Keep-a-Changelog): Security (C1; auth ACK/FIN; transcript-signed verdict + PROTOCOL 1→2 breaking; handshake deadline+decouple+caps; WIRE-001/LEGS-002/003; PoW cap+ct_eq; reputation wiring; path-gating; CRYPTO-2/3/4+INFOLEAK-1; faketls fix); Build (uniffi-cli split, drop chacha, FIPS excludes ring/x25519, rustls-pemfile→pki-types); **Removed** (HalfOpenSlots, networks/ layer, validation module, orphans, GsoBatchResult-if-deleted); Fixed (APIFFI-02/03).

**SemVer (pre-1.0, `cargo-semver-checks`):** bundle all pub-surface removals into **one coherent minor bump** with rationale in `versioning.md`: `networks::*`, `validation::InputValidator`, `half_open::HalfOpenSlots`, `GsoBatchResult` (if deleted), `PoWChallenge::solve`→`Result`. All other fixes are semver-clean.

---

## §5 — Disputed / dropped disposition
- **Fix (folded into WPs above):** CRYPTO-4 (WP8), WIRE-003 (WP11 compression cap), PATH-003 (WP7), DOS-3 (WP5/WP3 Semaphore), APIFFI-02 (WP12), SUPPLY-06 (WP10), PATH-002 (resolved by `networks/` deletion + the WP9 VirtualSocket fixes; do not wire `VirtualSocket::send` for app data).
- **Defer:** faketls-1 (no raw `tokio::time`; portable byte-ceiling only if forced — WP3's deadline covers the live path).
- **Dropped (no action):** ZERORTT-3 — refuted; `tcp_integration.rs:278-377` already pins 0-RTT no-double-accept and runs `--ignored` in CI (`ci.yml:274`).

---

## §6 — Suggested PR train (respecting codeowner queues)
1. **Phase 0** (parallel, day 1): `sec/ct-eq-pow` (WP8 CRYPTO-2), `sec/zeroize-transients` (WP8 CRYPTO-3), `sec/verify-strict` (WP8 CRYPTO-4) — three small `crypto/` PRs; `fix/resumption-hint-redact` (WP8 INFOLEAK-1, non-codeowner); `build/uniffi-cli-split` + `build/drop-chacha` + `chore/deny-rationale` + `chore/mldsa-doc` (WP10); `fix/early-data-size-hoist` + `fix/connectless-loud-fail` (WP12); `sec/path-gate` + `fix/path-challenge-idempotent` (WP7).
2. **Phase 1:** `sec/c1-nonce-watermark` (WP1, `session.rs`, Inv 8+5) — alone.
3. **Phase 2 (one release, one PROTOCOL bump):** `sec/h1-authenticated-ack` (`session.rs`, Inv 2) → `sec/h2-transcript-early-data` (`handshake.rs`, Inv 7/9/10) + `sec/hs03-resumption-binder` (`handshake.rs`+`kdf.rs`, Inv 9) + `sec/zerortt2-consume-on-success` (`handshake.rs`+`session_cache.rs`, Inv 9) — agree field order, regen fixtures once.
4. **Phase 3:** `sec/h3-pow-cap` → `feat/handshake-timeout` + `feat/accept-decouple-semaphore` + `feat/client-handshake-caps` (WP3) → `sec/reputation-wiring` + `chore/remove-halfopen` (WP5) ∥ `feat/frame-caps-shrink` + `feat/kcp-bounded-read` (WP4) ∥ `build/fips-exclude-ring` (WP10-SUPPLY-03, `faketls.rs`, Inv 3).
5. **Phase 4:** `chore/remove-networks-layer` (+ validation/orphans, one semver-removal PR) + `sec/decompression-cap` + `sec/fragment-assembler-bounds` (WP11) ∥ `fix/wasi-safety-comment` + `chore/retire-gso-unsafe` + `fix/virtualsocket-close-and-parse` + `fix/faketls-seal-truncation` (WP9).
