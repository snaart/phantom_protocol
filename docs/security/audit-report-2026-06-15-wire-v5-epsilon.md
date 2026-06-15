# Phantom Protocol — Security Audit: WIRE v5 / ε CID-Collapse Surface (PR #118)

- **Date:** 2026-06-15
- **Target:** `phantom_protocol` library (`core/`), at `main` @ `bb0452f` (post WIRE v5 CID-collapse, ε).
- **Diff range:** `f246123..bb0452f` (PR #118, 9 commits).
- **Scope:** the ε change only — collapse the two connection-ID layers into a single rotating CID, drop the 32-byte inner `session_id` from the data-plane wire (reconstruct it into the AEAD AAD), shrink the packet header 47 B → 15 B, and make `ObservedTransport` fully transparent over `SessionTransport`. Files:
  - `core/src/crypto/cid_chain.rs` (**new**) — rotating-CID KDF chain + inbound-window primitive.
  - `core/src/transport/types.rs` — 15-byte header `to_wire`/`from_wire` + the 47-byte `to_aad_image` reconstruction; `RawPacket`/`HP_PROTECTED_OFFSET`.
  - `core/src/transport/session.rs` — `cid_chain` field, `advance_outbound_cid`, `note_migration_path`, `parse_protected`, AAD reconstruction, `CidSlide`.
  - `core/src/api/session.rs` — recv path / `handle_packet` slide signal, migrate wiring, `ObservedTransport` transparency fix, CID_0 stamping.
  - `core/src/api/udp_listener.rs` — demux, `RouteTable` window register / slide.
  - `core/src/api/udp_transport.rs` — CID stamping (`established_cid`), `set_outbound_cid`.
  - `core/src/transport/session_transport.rs` — the 7 control-method trait defaults.
  - `core/src/crypto/header_protection.rs` — offset `33 → 1`.
  - tests / vectors / docs: `core/tests/{check_wire,security_invariants,udp_integration,wire_vectors}.rs`, `core/tests/wire_vectors/*.bin`, `tests/wire_vectors_decode.py`, `fuzz/fuzz_targets/fuzz_aead_decrypt.rs`, `docs/protocol/PROTOCOL.md`, `docs/security/threat-model.md`, `CHANGELOG.md`.
- **Method:** a 5-dimension adversarial source-review fan-out — **(1)** CID-chain crypto primitive, **(2)** 15-byte header & AAD reconstruction, **(3)** CID rotation / migration / window-slide, **(4)** ObservedTransport transparency & wrapper completeness, **(5)** wire-format freeze & cross-cutting interactions — followed by an **independent refutation lens** (re-read the cited code, biased to refute) on every raw finding and a **completeness-critic** pass. Findings were then reconciled with a manual maintainer review of the full ε diff, which **added one finding the fan-out missed (EPS-02)**.
- **Predecessor:** `docs/security/audit-report-2026-06-11.md` (0 Critical · 3 High · 8 Medium). This audit covers only the ε surface added after that report.

> Severity reflects the **inner Phantom session** as the real security boundary. Network attacker = full wire control (inject / replay / reorder / drop / truncate / flood) + source-address spoofing; an off-path attacker can observe the rotating 8-byte CID and 4-tuples; an "authenticated peer" is admitted for data-plane / availability attacks. The ε goal is threat-model § 12.5 / LINDDUN-L: migration **unlinkable** to an on-path observer, with the honest caveat that the CID chain is session-stable (KDF-derived, **not** forward-secret).

---

## Executive summary

**Overall risk rating: `acceptable, with availability + one linkability gap` — no confidentiality / integrity / authentication regression.**

The ε crypto and AAD core is **sound**. The 32-byte `session_id` is off the wire but still binds every packet through the reconstructed 47-byte AAD image (`PacketHeader::to_aad_image`), so a cross-session mis-delivery is a hard AEAD drop, never a cross-decrypt (verified — V-4). The rotating-CID KDF chain is domain-separated, zeroized, saturating, and KAT-frozen; the window slide is **strictly post-AEAD** (Inv 4 preserved — V-1); and the per-direction `u64` packet number + replay window survive a CID rotation with **no replay hole and no nonce reuse** (Inv 4 / Inv 8 preserved — V-2). The headline transparency fix is **complete and correct**: `ObservedTransport` now forwards all 9 `SessionTransport` methods (V-3), which is what turns the previously-vacuous FFI `migrate()` into a real on-wire CID rotation. **No memory-safety, confidentiality, integrity, or authentication defect was found, and there is no Critical or High.**

The surviving issues are concentrated in **availability / robustness, one linkability residual, and regression-coverage integrity** — not in the crypto boundary:

1. **The inbound CID-window slide cannot catch up to a multi-step / lossy migration jump (EPS-01, Medium).** The server advances its demux window by exactly +1 per *delivered, AEAD-verified* forward `path_id` step, but the client always stamps its *latest* CID, and an out-of-window CID is dropped **pre-AEAD** — so a burst of rapid/lossy migrations drives the client's CID past the K=4 leading edge and permanently strands the client→server data plane (the session then dies via the liveness machinery). Three independent finders converged on this.
2. **CID rotation is asymmetric — the server→client direction does not rotate on a *client* migration (EPS-02, Medium).** `advance_outbound_cid` fires only in the embedder's own `migrate()` handler, so when a client migrates only the c2s ConnId rotates; the server keeps stamping its unchanged outbound CID (s2c). An observer who sees both networks links the session by the stable s2c ConnId — so the § 12.5 "no stable cleartext identifier remains / unlinkable / LINDDUN-L **closed**" claim is **over-stated** for the common (client-moves-network) case. This is a linkability gap, not a confidentiality break.
3. **The on-wire CID-rotation regression test is `#[ignore]`-gated with no CI runner (EPS-03, Medium).** `udp_integration_cid_rotates_on_the_wire_across_migration` is the direct negative test for EPS-02's *opposite* — that `migrate()` actually rotates the on-wire CID — but no CI job runs `udp_integration -- --ignored`, so a regression of the transparency fix (i.e. a relapse to vacuous `migrate()` / linkable migration) would pass a fully green pipeline. This is the same blind spot that let the original vacuous `migrate()` ship.
4. **Structural / latent foot-guns (EPS-04 Low, EPS-05/06/07 Info).** The `SessionTransport` trait's 7 silently-succeeding control-method defaults are the generative root cause of the wrapper bug class; the test-only `LossyTransport` still has the same partial-forwarding shape ε just fixed in `ObservedTransport`; the AEAD fuzz target never exercises the non-empty-extensions AAD branch; and a now-tautological `session_id` backstop in `handle_packet` is dead code (documented honestly in-line).

**Recommendation:** land the audit + the regression/CI hardening (this PR), then make migration **symmetric and robust** — drive both directions' CID rotation and the inbound window from a single authenticated migration epoch (closes EPS-01 + EPS-02 together) before relying on seamless, unlinkable migration under loss.

### Findings by severity

| Severity | Count | IDs |
|---|---|---|
| **Critical** | 0 | — |
| **High** | 0 | — |
| **Medium** | 3 | EPS-01 (window-slide strand), EPS-02 (asymmetric s2c rotation — linkability), EPS-03 (CI-coverage gap) |
| **Low** | 1 | EPS-04 (trait default-method foot-gun) |
| **Info** | 3 | EPS-05 (LossyTransport latent shape), EPS-06 (fuzz extensions-branch gap), EPS-07 (dead `session_id` backstop) |
| **Verified clean** | 4 | V-1 (slide is post-AEAD), V-2 (replay survives rotation), V-3 (ObservedTransport complete), V-4 (cross-session AAD bind holds off-wire) |

---

## MEDIUM

### EPS-01 — Inbound CID window slides at most +1 per delivered migration and never catches up → lost/rapid migrations strand the client→server data plane

**Severity:** Medium · **Invariant:** none regressed (availability only) · **Location:** `core/src/transport/session.rs:492-528` (`note_migration_path`, `fetch_add(1)` at `:508-511`); `core/src/api/udp_listener.rs:253-264` (`apply_slide`); window radii `core/src/crypto/cid_chain.rs:59-61` (T=2, K=4); client stamps the latest CID at `core/src/api/udp_transport.rs:189`.

On every `migrate()` the client advances **both** `path_id` (`next_migration_path_id`, +1 mod-256) **and** the outbound CID index (`advance_outbound_cid`, +1) in lock-step (`api/session.rs:1209` / `:1216`), then stamps **only the newest CID** on every datagram and L1 retransmit. The server advances its inbound demux window by exactly **+1** per *distinct, AEAD-verified, forward* `path_id` it actually receives: `note_migration_path` does `inbound_cid_highest_seen.fetch_add(1)` regardless of how far `path_id` jumped (the forward-distance gate `(0,128]` decides *whether* to slide, never *how far*), and the registered window covers only `[highest_seen − 2 .. highest_seen + 4]`.

Crucially, CID routing is **pre-AEAD**: the demux drops any datagram whose CID misses the route table, so a datagram stamped with an out-of-window CID never reaches the post-AEAD `note_migration_path` that would have slid the window. The lag `L = (client outbound index − server highest_seen)` is therefore **monotonic** — a multi-step jump collapses to a single +1 and then the gate closes (`fwd = 0`).

**Impact / exploit.** A client on a flapping link migrates ≥ K+1 = 5 times in quick succession while its datagrams are lost during the flap — exactly the regime migration exists to survive. When the link stabilises the client stamps `CID_5`; the server window is still `{CID_0..CID_4}` → every datagram is dropped pre-AEAD → the window never slides → the **client→server data plane is permanently stranded**. Server→client still works (the client is socket-routed), masking the failure until the liveness sweep declares the session `Dead` (bounded by `idle_timeout`, default 30 s — so a session-loss DoS, not an unbounded hang). An on-path attacker who can induce client→server loss *during* migrations (cheap on a radio handoff) turns ε's migration feature into a deterministic session-DoS trigger that survives the attacker leaving the path. **No security invariant regresses — mis-routing only ever yields a drop.** The only multi-migration test (`udp_integration_window_slides_across_many_migrations`) sleeps 120 ms between hops so each index is delivered in-window first, exercising only the happy path.

**Recommended fix.** Decouple the server's window centre from the count of *received* slides: drive `inbound_cid_highest_seen` from the peer's **authenticated migration index** (recoverable from the `path_id` forward distance, since `path_id` and the CID index advance in lock-step) and apply a **multi-step** slide (re-register every CID between the old and new leading edge); and/or widen `CID_WINDOW_LEADING`; and add a stalled-session fallback. See the EPS-01 + EPS-02 joint remediation below.

**Regression test:** `eps01_multistep_path_jump_slides_window_by_the_full_delta` in `core/tests/security_invariants.rs` — a 5-step forward `path_id` jump must produce a `CidSlide` whose `add` registers **5** new leading CIDs (multi-step), not 1 (RED → GREEN).

**Status (fixed — multi-step slide + widen-K):** the inbound window slide now advances by the **full** authenticated `path_id` forward delta (registering `d` leading CIDs, dropping `d` trailing), recentring on the sender's actual migration index so lost intermediate migrations no longer cumulatively erode the margin; and `CID_WINDOW_LEADING` is widened **4 → 16**, so `K` is the hard cap on *consecutive fully-lost* migrations before a strand (recoverable by reconnect) — > 16 is far beyond any realistic regime. `MAX_ROUTES` is raised `1<<16 → 1<<18` to preserve concurrent-session capacity with the 19-CID per-session window. No wire change.

### EPS-02 — Asymmetric CID rotation: the server→client (s2c) ConnId stays stable across a *client* migration → on-path linkability; § 12.5 "unlinkable" is over-claimed

**Severity:** Medium · **Invariant:** threat-model § 12.5 / LINDDUN-L (the ε goal) · **Location:** `core/src/transport/session.rs:479-482` (`advance_outbound_cid`); its only call site `core/src/api/session.rs:1216` (the embedder `migrate()` handler); the server-side migration-detect path `core/src/api/session.rs:1865-1872` (`confirm_authenticated_source` / `note_migration_path` / `signal_cid_slide`) **never** advances the server's own outbound index; server stamps its outbound CID at `core/src/api/udp_transport.rs:403-407` from `established_cid`, set once at `core/src/api/session.rs:545`.

> This finding was **not** surfaced by the 5-dimension fan-out (which converged on the *client→server* availability strand, EPS-01); it was added on maintainer reconciliation. It concerns the *opposite* direction and a *different* property (linkability, not availability).

The two CID chains are per-direction (`c2s`, `s2c`) with **independent** indices (`outbound_cid_index`, `inbound_cid_highest_seen`). `advance_outbound_cid` — the only thing that rotates a peer's outbound CID — is called from exactly one site: the embedder-triggered `migrate()` command handler (`api/session.rs:1216`). When a **client** migrates:

- the client's `migrate()` runs `advance_outbound_cid()` → the **c2s** CID rotates to an independent-random value (good — client→server is unlinkable); but
- the server only *detects* the migration (`note_migration_path` slides its **inbound** c2s window and `confirm_authenticated_source` commits the new peer address). It does **not** call `advance_outbound_cid`, so the server keeps stamping `CID_s2c(0)` — its index never moved — on every server→client datagram.

**Impact / exploit.** The s2c ConnId is the only per-connection cleartext on server→client datagrams, and it is **stable across the client's migration**. An on-path / colluding observer who sees both networks (exactly the adversary the § 12.5 claim is written against) reads the same `CID_s2c(0)` on the pre-migration (e.g. Wi-Fi) and post-migration (e.g. cellular) server→client flows and **links them** — "same session moved networks" — defeating ε's headline property in the server→client direction. The threat-model entry "**No stable cleartext identifier remains — migration is unlinkable by an on-path observer (LINDDUN-L … closed by ε)**" and PROTOCOL.md § 12.5 / § 4.7 are therefore **over-claimed** for the common client-migration case. Confidentiality / integrity / authentication are unaffected (the s2c CID is a routing tag, not a secret); this is purely a linkability / metadata gap — but it is a gap in the *one property ε exists to deliver*.

The fix is contained: the UDP **client is socket-routed** — its recv path ignores the inbound envelope ConnId (`api/udp_transport.rs` `recv_bytes` discards `_hdr` from `push_datagram`), so the server can rotate its s2c outbound CID with **no** client-side window machinery and **no** ping-pong (rotate-on-detect must not bump the server's own `path_id`, or the client's `note_migration_path` would re-trigger). The clean, symmetric form is the shared-epoch redesign below, which also closes EPS-01.

**Recommended fix (joint with EPS-01).** Make migration symmetric and index-driven via a **single authenticated migration epoch `E`** per session (replacing the two independent indices): `migrate()` does `E += 1`; on recv (post-AEAD) a peer catches `E` up to the authenticated `path_id` (`E := max(E, path_id)`), which simultaneously (a) rotates **its own** outbound CID to `chain_out(E)` — closing EPS-02 in both directions and for either migrating peer — and (b) re-centres / multi-step-slides its inbound window to `E` — closing EPS-01. Idempotent (once both peers reach `E`, `path_id == E` ⇒ `fwd = 0` ⇒ no re-trigger), so no ping-pong. No wire change (the `path_id` byte already carries it; CID is already 8 bytes) — interop-breaking *semantics* only, acceptable in the 0.2.0 window.

**Regression test:** `eps02_server_rotates_s2c_cid_on_client_migration` in `core/src/api/session.rs` (in-crate, drives `handle_packet` via `run_recv`) — after a client migration is observed by the server, assert `server.current_outbound_cid()` rotated. Companion `eps02_client_does_not_rotate_on_detecting_server_migration` pins the socket-routed-client guard. Plus the extended on-wire `udp_integration_cid_rotates_on_the_wire_across_migration` asserting **both** directions' ConnIds rotate across a client migration.

**Status (fixed for the client-migration case):** the server now rotates its s2c CID on authenticating the client's new `path_id` (post-AEAD); the socket-routed client absorbs it (no window slide, no ping-pong). LINDDUN-L is **closed for a client migration** (both directions unlinkable). The remaining residual — a *server*-initiated migration leaves c2s stable (the client does not rotate-on-detect, which would strand it in the server's un-sliding c2s window) — is rare and tracked for the full shared-migration-epoch fix (which also closes EPS-01).

### EPS-03 — The on-wire CID-rotation regression test that pins ε's transparency fix is `#[ignore]`-gated with no CI runner

**Severity:** Medium · **Invariant:** coverage integrity (no runtime attack) · **Location:** `core/tests/udp_integration.rs:269-362` (test `udp_integration_cid_rotates_on_the_wire_across_migration`); `.github/workflows/ci.yml` (the integration job runs only `tcp_integration -- --ignored`).

ε's whole point is that `ObservedTransport::set_outbound_cid` reaches the inner UDP transport so `migrate()` actually rotates the on-wire CID. The direct regression test for that records every OneRtt CID on a real UDP relay, calls `client.migrate()`, and asserts the cleartext CID rotated. **Problem:** every test in `udp_integration.rs` is `#[ignore]`-gated, and CI runs only `tcp_integration -- --ignored` and `wasi_integration -- --ignored` — **no job runs `udp_integration -- --ignored`**. The always-on `cargo test --lib` migration coverage uses the in-memory `ChannelTransport`, which has no on-wire CID and inherits the no-op `set_outbound_cid` default, so a regression is invisible there too.

**Impact.** A later refactor drops or shadows the `set_outbound_cid` forward (e.g. a new wrapper layer in the pump). `cargo test --lib`, fmt, clippy, test, deny all stay green; `migrate()` is once again a vacuous no-op; an on-path observer trivially links pre-/post-migration flows by the stable cleartext CID, and **§ 12.5 / LINDDUN-L unlinkability silently regresses** — undetected until a manual `-- --ignored` run or an external audit. This is exactly the blind spot that let the original vacuous `migrate()` ship.

**Recommended fix.** (a) Add a CI job mirroring `tcp_integration --ignored`: `cargo test --manifest-path core/Cargo.toml --test udp_integration -- --ignored`. (b) Add an **always-on** in-crate `#[cfg(test)]` test asserting `ObservedTransport::set_outbound_cid` (and the other 6 control methods) forwards to a recording mock — pinning the transparency invariant without UDP loopback. **Both land in this PR.**

**Regression test:** `observed_transport_forwards_all_control_methods` in `core/src/api/session.rs` (always-on) + the new `udp_integration --ignored` CI step.

---

## LOW

### EPS-04 — Every `SessionTransport` control method has a silently-succeeding default body — the structural foot-gun that hid the original bug

**Severity:** Low · **Invariant:** design / ergonomics (no exploit) · **Location:** `core/src/transport/session_transport.rs:78-146`.

The trait gives silently-succeeding defaults to all 7 non-I/O methods (`set_frame_phase → {}`, `set_outbound_cid → {}`, `has_migration_candidate → false`, `send_to_candidate → Ok(false)`, `confirm_authenticated_source → {}`, `promote_candidate → false`, `migrate → Ok(())`). Correct for genuinely-non-migrating transports, but the same silent-success is precisely what lets a **partial** wrapper impl compile with zero warnings while swallowing every control call — the compiler gives no signal a wrapper forgot to forward. This is the documented root cause of the pre-ε vacuous `migrate()` (ε's own comment at `api/session.rs:199-203` concedes it); `migrate()`'s default `Ok(())` is the worst — a wrapper that forgets it reports migration **success** while doing nothing.

**Recommended fix.** A loud trait-doc note on `SessionTransport` that wrappers MUST forward every method (not just send/recv), backed by an **always-on per-method tripwire test** that fails if any wrapper leaves a control method on its default. **Lands in this PR.** (A forwarding macro was considered and rejected as over-engineering for two wrappers — explicit forwarding is more obviously correct and the tripwire test is the real guard.)

**Regression test:** `observed_transport_forwards_all_control_methods` (a per-method tripwire) doubles as the EPS-04 guard.

---

## INFO

### EPS-05 — `LossyTransport<T>` has the same latent partial-forwarding shape ε just fixed in `ObservedTransport`

**Severity:** Info (test-only, no current defect) · **Location:** `core/src/test_harness/fault_transport.rs:439-476`.

`LossyTransport<T>` implements only `send_bytes`/`recv_bytes` — the identical pre-ε shape of `ObservedTransport`; all 7 control methods fall through to the silent defaults. Latent today (it only ever wraps `ChannelTransport`), but the moment someone writes a "migration-under-loss" test wrapping a `UdpClientTransport`, the control methods silently no-op and the test passes vacuously — the precise failure mode ε exists to eliminate.

**Recommended fix.** Make `LossyTransport` fully transparent (forward all 7 control methods explicitly; fault injection only concerns the send path). **Lands in this PR.**

### EPS-06 — `fuzz_aead_decrypt` never exercises the non-empty-extensions AAD branch

**Severity:** Info (coverage gap, no exploit) · **Location:** `fuzz/fuzz_targets/fuzz_aead_decrypt.rs:53`; `core/src/transport/session.rs:1062-1077` (`with_packet_aad`).

The fuzzer was correctly updated to the 3-arg `decrypt_packet(header, ct, extensions)` but hard-codes `extensions = &[]`, only ever driving `with_packet_aad`'s empty branch — even though the recv path feeds attacker-controlled, wire-length-prefixed `packet.extensions` into the non-empty branch (`api/session.rs:1820-1824`). The missed branch is a bounds-safe `with_capacity` + two `extend_from_slice` and the extensions are already AAD-bound (a mutation yields a typed AEAD `Err`, never a panic), so it is a pure assurance gap.

**Recommended fix.** Carve a few input bytes as the extensions slice to exercise both branches. **Lands in this PR**, paired with an always-on round-trip + tamper unit test (`extensions_are_aead_bound_and_total`).

### EPS-07 — Post-ε `session_id` backstop in `handle_packet` is a tautology (dead defensive check, honestly documented)

**Severity:** Info (no exploit) · **Location:** `core/src/api/session.rs:1800`.

`if packet.header.session_id != session_id { return; }` can never reject in production: `parse_protected` unconditionally overwrites `header.session_id` with `*self.id()`, and the `session_id` argument is the same `*session.id()`, so the comparison is `x != x` — always false. **Not** a vulnerability: the real cross-session bind is the AEAD AAD (`to_aad_image` copies `session_id` into AAD `[1..33]`, the sole chokepoint before decrypt), and `session_id`s are session-distinct, so a frame mis-delivered across a CID-window collision reconstructs the wrong id into the AAD → AEAD fail → drop (verified, V-4). The inline comment already concedes the check is always-true. Left as a defensive backstop; a cosmetic `debug_assert_eq!` cleanup is deferred to the migration-redesign PR to avoid touching the `handle_packet` hot path in this test-focused PR.

---

## Verified clean (focus items cleared — pinned as regression guards)

### V-1 — Off-path forced window-slide is correctly prevented: the slide is strictly post-AEAD (Inv 4 preserved)

`note_migration_path` / `signal_cid_slide` are reachable from exactly one site (`api/session.rs:1870-1871`), inside the `if … ENCRYPTED` block (`:1858`) entered only after `decrypt_packet_accepting_rekey` succeeds (`:1820`; a failed decrypt returns at `:1838`). The only pre-AEAD action on `path_id` is `mark_path_seen` (a liveness timestamp; cannot move the CID window). A spoofed-source datagram that matches a window CID fails AEAD and is dropped before any slide. **An off-path attacker cannot force a slide or desync the demux.** **Pinned** by `eps_slide_requires_aead_success` (this PR).

### V-2 — Replay window and packet number survive CID rotation: rotation opens no replay hole (Inv 4 / Inv 8 preserved)

The per-direction monotonic `u64` packet number and the sliding `ReplayWindow` are session-global and are **not** reset/re-seeded by a rotation (`advance_outbound_cid` touches only `outbound_cid_index`; `note_migration_path` only `inbound_cid_highest_seen` / `last_seen_path_id`). The nonce derives from `prefix ‖ packet_number` and `accept(packet_number)` runs **after** AEAD open. A packet replayed across a migration boundary still carries its original `packet_number` and is rejected by the unchanged `ReplayWindow`. **Pinned** by `eps_replay_rejected_across_cid_rotation` (this PR).

### V-3 — `ObservedTransport` forwards the full `SessionTransport` surface: the transparency fix is complete

The trait has exactly 9 methods; `ObservedTransport<T>` forwards all 9 (send/recv with one metric each on the Ok path; the 7 control methods as pure pass-throughs) — no method left to a default, no double-count. **Pinned** by `observed_transport_forwards_all_control_methods` (this PR).

### V-4 — Cross-session AAD bind holds off-wire

Two sessions with matching AEAD keys but distinct `session_id`s cannot open each other's packets: the receiver reconstructs **its** id into the 47-byte AAD image, which differs from the sender's → AEAD fail. Already pinned by the ε test `v5_session_id_bound_via_aad_off_wire` (encrypt/decrypt level) and `tampered_extensions_is_rejected_via_aad` (extensions branch). A `parse_protected`-level cross-delivery negative (exercising the HP unmask + off-wire reconstruction end-to-end) is folded into the follow-up migration-redesign PR alongside the EPS-07 cleanup.

---

## Appendix — Reviewed and dismissed

| ID | Title | Why dismissed |
|---|---|---|
| D-CID-a | `cid_from_secret` leaves an un-zeroized plaintext copy of the chain secret on the stack | **Refuted (info).** Real un-wipe, but strictly dominated by the pre-existing un-zeroized parent `traffic_secret` (`RwLock<[u8;32]>`, longer-lived, also un-wiped) which re-derives the entire CID chain *and* the HP/AEAD keys. Zero incremental capability; mirrors the `HeaderProtector::derive` analog. Hygiene nit dominated by a larger pre-existing gap. |
| D-FLOOD | Authenticated peer floods the unbounded CID-slide channel (one slide/packet) to starve the demux | **Refuted (info).** Strict 1:1 causal bound — each slide costs the attacker one full datagram the demux already read + AEAD-opened, and `apply_slide` is O(1). No super-linear amplification; table hard-capped at `MAX_ROUTES`; ≤ 2× constant-factor work per datagram, no new availability primitive. |
| D-EVICT | `apply_slide` removes trailing CIDs unconditionally but adds leading CIDs only on success → eviction under `MAX_ROUTES` pressure strands a session | **Refuted (info).** The guaranteed remove only drops the *oldest trailing* CID (3 behind the anchor) the client has stopped using; the anchor the client actively stamps is never in `slide.remove`. A failed add only loses the furthest lookahead. Trigger (65 536 *live* post-PQ-handshake routes) is not cheaply attacker-inducible. Minor robustness nit. |

---

## Prioritised remediation checklist

1. **[this PR] Lock in the verified-clean invariants + close the coverage/CI blind spot (EPS-03, EPS-04, EPS-05, EPS-06, V-1..V-4).** GREEN pins for the post-AEAD slide (V-1) and replay-across-rotation (V-2); an always-on `ObservedTransport` per-method-forwarding tripwire test (V-3 / EPS-03 / EPS-04) + a loud trait-doc note; a `udp_integration --ignored` CI job (EPS-03); explicit control-method forwarding in `LossyTransport` (EPS-05); the fuzz extensions-branch widening (EPS-06). The AAD-bind invariants (V-4) are already pinned by existing ε tests. **No production data-plane behaviour change.**
2. **[✅ DONE, follow-up PRs] Symmetric & robust migration.** Closed **separately** (simpler than the originally-sketched shared epoch): **EPS-02** via server-side rotate-on-detect (the server rotates its s2c CID on authenticating the client's new `path_id`; the socket-routed client absorbs it) — § 12.5 closed for client migration; **EPS-01** via a **multi-step** window slide (advance by the authenticated `path_id` delta) + widening `K` 4 → 16 + raising `MAX_ROUTES` 1<<16 → 1<<18. Residual: a *server*-initiated migration leaves c2s stable (rare). See the per-finding Status notes above.
3. **[follow-up] Cosmetic: replace the dead `session_id` backstop (EPS-07) with a `debug_assert_eq!` + a cross-delivery negative test.**
