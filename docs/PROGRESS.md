# Phantom Core — Production-Readiness Progress

Live tracker for the eight-phase roadmap in
[`PRODUCTION_READINESS.md`](PRODUCTION_READINESS.md). Updated alongside every
feature commit; the latest commit SHA appears in the right-most column of each
phase table.

## Snapshot

| Metric | Value |
| --- | --- |
| Tests passing | **143 / 143** (132 unit + 11 negative-security) |
| Integration tests | 5 (`tcp_integration` x2 `#[ignore]`, `kcp_integration` x3 `#[ignore]`) |
| Fuzz harnesses | 4 scaffolded (cargo-fuzz, nightly) |
| Workspace warnings | **0** |
| `cargo clippy --lib` warnings | 47 (audit-todo lints; non-blocking) |
| `unsafe` blocks outside `crypto/keys` & `transport/udp_transport` | **0** (denied at crate root) |
| `.unwrap()` / `unreachable!()` in production hot path | **0** |
| Wire format | `VersionedPacket::V1` (stable, no V2 yet) |
| MSRV | Rust 1.75+ (CI enforced via `dtolnay/rust-toolchain@1.75`) |
| Last commit | _filled by each update_ |

## Legend

| Symbol | Meaning |
| --- | --- |
| ✅ | Done — implemented and covered by tests / verifiable artifact |
| 🔄 | In progress this development cycle |
| ⏳ | Planned — not started, blocks nothing critical |
| ⏭️ | Skipped/deferred with documented rationale (see notes) |

---

## Phase 0 — Governance, CI, Tooling

| # | Item | Status | Commit | Notes |
| --- | --- | --- | --- | --- |
| 0.1 | Governance docs (LICENSE / README / SECURITY / CONTRIBUTING / CHANGELOG) | ✅ | `f7c73e8` | Apache-2.0 |
| 0.2 | Toolchain pinning (rust-toolchain / rustfmt / clippy) | ✅ | `988a846` | stable channel; MSRV 1.75 enforced separately |
| 0.3 | Supply-chain hygiene (`deny.toml`) | ✅ | `60bddf9` | allowlist of permissive licences; ring exception |
| 0.4 | CI workflow (fmt, clippy, test, doc, deny, audit, cli-compat) | ✅ | `8413f5c` | `.github/workflows/ci.yml` |
| 0.5 | Pre-commit hooks | ⏳ | — | Deferred — CI gate is sufficient short-term |
| 0.6 | Performance baseline (`BENCHMARKS.md`) | ⏳ | — | Will be filled when criterion baseline JSON is committed |
| 0.7 | Release profile fix (workspace root, `opt-level = 3`) | ✅ | `4e79b8a` | was silently ignored under `core/`; speed > size |
| 0.8 | Dep pinning (zstd 0.13 release, subtle 2.5 added) | ✅ | `36e9f07` | drops git-master supply-chain risk |
| 0.9 | Production-readiness roadmap (`PRODUCTION_READINESS.md`) | ✅ | `0f13b1c` | the canonical source of truth |
| 0.10 | Audit-friendly lint set in lib root | ✅ | `7cf87dd` | `warn` for now, deny later |

**Phase 0 verdict:** ✅ effectively complete. Pre-commit hooks (0.5) and bench
baseline (0.6) are nice-to-haves; they don't block any later phase.

---

## Phase 1 — Security Hardening

| # | Item | Status | Commit | Notes |
| --- | --- | --- | --- | --- |
| 1.1 | Constant-time cookie comparison (`subtle::ConstantTimeEq`) | ✅ | `068e354` | `core/src/transport/handshake.rs:147-152` |
| 1.2 | ZeroizeOnDrop on session secrets | ✅ | `068e354` + `3ef15c6` | `CryptoState`, `Session.resumption_secret`, `HandshakeServer.master_secret` (was `pow_secret`), `HandshakeClient.nonce` |
| 1.3 | Remove `.unwrap()` / `unreachable!()` from production hot paths | ✅ | `068e354` + `e25f7a7` + `005e22f` | handshake, api/session, faketls, compression |
| 1.4 | Wire `ReplayProtection` into recv path | ✅ | _this commit_ | bitmap-based per-stream `ReplayWindow` (RFC 4303 § 3.4.3); 1024-bit window; `Session::decrypt_packet` checks after AEAD verify; `replay_rejected_total` counter exposed |
| 1.5 | Mid-session key rotation (PFS within a session) | ⏭️ | — | **Blocked on V2 bump.** All 8 `PacketFlags` bits are used in V1; no room for `REKEY`. Resumes when Phase 4.2 introduces V2. |
| 1.6 | Strong session ID (32 → 128 bits) | ✅ | `e25f7a7` | `new_session_id` via thread_rng / ChaCha CSPRNG |
| 1.7 | AEAD nonce-exhaustion guard (`AEAD_MAX_INVOCATIONS`) | ✅ | `53f2c5e` | `CryptoError::NonceExhausted` at 2^48; observability accessors |
| 1.8 | Wire format & version-list negotiation | ⏭️ | — | **Blocked on V2 bump.** `ClientHello.version` is a `u8`; needs `Vec<u8>` of offered versions, transcript-bound. Resumes alongside V2. |
| 1.9 | Strict `PacketFlags::ENCRYPTED` invariant | ✅ | (pre-existing) | `api/session.rs:430-437` drops stripped-flag packets; covered by negative tests |
| 1.10 | Cookie freshness (rotating salt) | ✅ | _this commit_ | 5-min buckets; current + previous bucket accepted (sliding-window) via constant-time `subtle::Choice` accumulator |
| 1.11 | PoW secret rotation | ✅ | _this commit_ | hour-bucketed HKDF derivation from a long-lived master; cookie/PoW validation accepts current + previous hour |
| 1.12 | Phantom-limb cleanup (docs on `_ephemeral_kem_secret` / `take_early_data`) | ✅ | `49180ee` | non-breaking — full removal blocked on V2 bump |
| 1.13 | `#![deny(unsafe_code)]` everywhere except 2 documented modules | ✅ | `8b4ee23` | SAFETY comments on every remaining `unsafe { }` block |
| 1.14 | Adaptive PoW difficulty under load | ✅ | _this commit_ | per-minute handshake counter on `HandshakeServer`; `adaptive_difficulty()` tiers (0/4/8/12/16); `PhantomListener::accept` now passes it instead of hard-coded 0 |

**Phase 1 verdict:** ~⅔ done by item count; the deferred ones (1.4, 1.5, 1.8,
1.10, 1.11, 1.14) are bundled into the next development cycle.

---

## Phase 2 — Performance Critical Path

| # | Item | Status | Commit | Notes |
| --- | --- | --- | --- | --- |
| 2.1 | Wire `BufferPool` into `TcpSessionTransport::recv_bytes` | ⏳ | — | requires `SessionTransport` trait signature change |
| 2.2 | Drop `plaintext.clone()` in recv path | ✅ | `9d92262` | recv channel now carries `Bytes`; single `to_vec` at FFI boundary |
| 2.3 | Stack-buffered serialization for small packets | ⏳ | — | `SmallVec` / fixed-array for ACK packets |
| 2.4 | Event-driven send loop (replace 10 ms `interval`) | ⏳ | — | `Notify` per stream → no polling |
| 2.5 | Wire `PacketCoalescer` into send path | ⏳ | — | aggregate per-tick packets into single transport write |
| 2.6 | Wire `Pacer` + `BandwidthEstimator` | ⏳ | — | foundation for Phase 4.4 congestion control |
| 2.7 | `ArcSwap` on crypto state (lock-free read) | ⏳ | — | interacts with rekey (Phase 1.5) |
| 2.8 | `Bytes` throughout API boundary | 🔄 | (partial via 2.2) | recv channel is `Bytes`; `SessionTransport` still `Vec<u8>` |
| 2.9 | SO_REUSEPORT multi-accept | ⏳ | — | Linux-only; gated behind feature flag |
| 2.10 | GSO / `sendmmsg` UDP | ✅ | (pre-existing) | already in `transport/udp_transport.rs` |
| 2.11 | Per-CPU work-stealing | ⏳ | — | likely overkill; revisit after Phase 4 |
| 2.12 | PGO + native CPU optional build | ⏳ | — | release profile foundation in place (Phase 0.7) |
| 2.13 | Async/`select!` cancel-safety audit | ⏳ | — | audit pass; no known issues yet |

**Phase 2 verdict:** kicked off (2.2 done; 2.8 partial; 2.10 pre-existing). Big-ticket
items (2.1, 2.4, 2.5, 2.6) remain.

---

## Phase 3 — Portability (WASM, embedded, mobile)

| # | Item | Status | Commit | Notes |
| --- | --- | --- | --- | --- |
| 3.1 | `Runtime` trait (decouple from tokio) | ⏳ | — | XL — touches every `tokio::spawn` / `tokio::time` site |
| 3.2 | `Clock` trait (WASM-compatible time) | ⏳ | — | feeds 3.1 |
| 3.3 | `WebSocketLeg` for browser WASM | ⏳ | — | new `transport/legs/websocket.rs` |
| 3.4 | `EmbeddedLeg` (UART / serial / CAN) | ⏳ | — | generic over `embedded-io-async` traits |
| 3.5 | Conditional compilation matrix (`std` / `wasm` / `embedded` / ...) | ⏳ | — | features in `core/Cargo.toml` |
| 3.6 | no_std + `alloc` for embedded | ⏳ | — | swap `pqcrypto-*` → `ml-kem` / `ml-dsa` |
| 3.7 | Drop `zstd` C bindings (already on `0.13` release) | 🔄 | — | needs `ruzstd` for full pure-Rust |
| 3.8 | RNG abstraction (`getrandom` features) | ⏳ | — | feature-gate per target |
| 3.9 | FFI bindings generation (Swift, Kotlin, C) | ⏳ | — | only Python ships today |
| 3.10 | WASM-specific tweaks | ⏳ | — | drop `tokio = "full"`, etc. |
| 3.11 | Cross-platform CI matrix (8+ triples) | ⏳ | — | extends `.github/workflows/ci.yml` |

**Phase 3 verdict:** untouched. XL effort — independent of Phase 1/2.

---

## Phase 4 — New Subsystems

| # | Item | Status | Commit | Notes |
| --- | --- | --- | --- | --- |
| 4.1 | 0-RTT resumption (server `SessionCache` wire-in, early-data encrypt) | ⏳ | — | `session_cache.rs` exists but disconnected |
| 4.2 | Multi-path failover + connection migration | ⏳ | — | requires V2 wire format with `path_id` |
| 4.3 | Multi-stream finalization (priority, flow control) | ⏳ | — | priority field exists; never read by scheduler |
| 4.4 | Congestion control (BBRv2-inspired) | ⏳ | — | depends on 2.6 (Pacer + Estimator wired) |
| 4.5 | Telemetry: `tracing` instrumentation + metrics exporter | ⏳ | — | new `core/src/observability/` module |
| 4.6 | Graceful shutdown + signal handling | ⏳ | — | small once API is settled |

**Phase 4 verdict:** untouched. Depends on 2.x and 3.x foundations.

---

## Phase 5 — FIPS 140-3 / Common Criteria

| # | Item | Status | Commit | Notes |
| --- | --- | --- | --- | --- |
| 5.1 | `fips` feature flag (primitive swap) | ⏳ | — | ML-KEM / ML-DSA / SHA-256 / AES-256-GCM via aws-lc-rs |
| 5.2 | Constant-time audit pass | 🔄 | — | cookie path done (1.1); rest pending |
| 5.3 | RNG / DRBG audit | ⏳ | — | document Linux / macOS / WASM RNG sources |
| 5.4 | CAVP test vectors | ⏳ | — | `tests/cavp/` directory |
| 5.5 | Compliance docs (`docs/compliance/`) | ⏳ | — | FIPS security policy, key management, self-tests |
| 5.6 | Common Criteria Protection Profile mapping | ⏳ | — | NIAP PP-Mobile Device VPN Client likely |
| 5.7 | Validation pathway (CMVP / CC submission) | ⏳ | — | external lab; out of code scope |

**Phase 5 verdict:** untouched. Parallel to Phases 1–3.

---

## Phase 6 — Audit Readiness

| # | Item | Status | Commit | Notes |
| --- | --- | --- | --- | --- |
| 6.1 | Threat model (`docs/security/threat-model.md`) | ⏳ | — | STRIDE + LINDDUN |
| 6.2 | Protocol specification (`docs/protocol/PROTOCOL.md`) | ⏳ | — | wire format, state machine, KDF labels |
| 6.3 | Architecture document (`docs/architecture/ARCHITECTURE.md`) | ⏳ | — | module diagram + data flow |
| 6.4 | cargo-fuzz harnesses + OSS-Fuzz integration | ✅ | `24015d2` | 4 targets in `fuzz/`; OSS-Fuzz job tracked separately |
| 6.5 | Property tests (`proptest`) | ⏳ | — | round-trip / handshake / replay |
| 6.6 | Loom tests (concurrency invariants) | ⏳ | — | DashMap, atomic counters, send_queue |
| 6.7 | `cargo miri` CI job | ⏳ | — | catches UB, leaks |
| 6.8 | Formal negative-security tests | ✅ | `8d69521` | `core/tests/security_invariants.rs` — 10 tests |
| 6.9 | Coverage measurement (`cargo-llvm-cov`) | ⏳ | — | aim ≥85 % line / ≥75 % branch |
| 6.10 | Formal verification (ProVerif / Tamarin) | ⏳ | — | optional; only if audit demands |
| 6.11 | Inline `SAFETY` / `PANIC-SAFETY` comments | 🔄 | `8b4ee23` | unsafe blocks done; remaining `expect_used` sites are test-only |

**Phase 6 verdict:** 6.4 + 6.8 done; rest pending. Threat-model / protocol-spec
docs are the next high-leverage items here.

---

## Phase 7 — Operations & Release

| # | Item | Status | Commit | Notes |
| --- | --- | --- | --- | --- |
| 7.1 | End-to-end examples (server / client / mobile / WASM / embedded) | ⏳ | — | only `core/examples/crypto_bench.rs` today |
| 7.2 | Deployment guides (Docker / k8s / systemd / mobile / WASM) | ⏳ | — | `docs/operations/` |
| 7.3 | Versioning policy + `cargo-semver-checks` | ⏳ | — | `docs/policy/versioning.md` |
| 7.4 | Release pipeline (cargo-release + GPG + SLSA) | ⏳ | — | GitHub Actions release job |
| 7.5 | Incident-response playbook | ⏳ | — | extension of `SECURITY.md` |
| 7.6 | Grafana dashboards + Prometheus alert rules | ⏳ | — | depends on Phase 4.5 telemetry |
| 7.7 | Performance tuning guide | ⏳ | — | sysctl, build flags, profiling |
| 7.8 | Migration guides per breaking change | ⏳ | — | starts at first V2 bump |

**Phase 7 verdict:** untouched. Depends on most prior phases.

---

## How this file is updated

Each substantive feature commit either:

1. Sets a row to ✅ and records its commit SHA, **or**
2. Flips a row from ⏳ to 🔄 when started, **or**
3. Marks ⏭️ with a rationale in `Notes` when the team decides to skip.

Snapshot metrics at the top are refreshed when:

- The test count changes.
- A new fuzz target is added.
- A new clippy lint set is wired or relaxed.
- A wire-format version is bumped.

If the live state of the repo diverges from this file, prefer the repo
(commits + `cargo test` output) — this file is a reading guide, not the
source of truth.
