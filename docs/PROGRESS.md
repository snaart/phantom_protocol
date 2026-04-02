# Phantom Core — Production-Readiness Progress

Live tracker for the eight-phase roadmap in
[`PRODUCTION_READINESS.md`](PRODUCTION_READINESS.md). Updated alongside every
feature commit; the latest commit SHA appears in the right-most column of each
phase table.

## Snapshot

| Metric | Value |
| --- | --- |
| Tests passing | **224 / 224** (190 unit + 24 negative-security + 5 proptest + 3 fuzz + 1 alkahest + 1 runtime-integration) |
| **Phase 1 / Phase 2 closed** | ✅ all 14 + 13 sub-items either ✅ or ⏭️ with rationale |
| Atomic commits since `e4067b6` baseline | **52+** |
| `#[allow(unsafe_code)]` opt-ins outside the deny-by-default | **1** (was 2 — `crypto/keys.rs` deleted in Phase 5.1) |
| Wire format versions supported | **V1 + V2** (V2 is now the **client default** via `create_client_hello`; downgrade resistance via transcript signature) |
| Mid-session rekey | **available** — `Session::rekey()` + V2 `PacketFlagsV2::REKEY` + `header.epoch` |
| V2 codecs landed | `transport::path_validation_codec` + `transport::packet_coalescer_codec`; `run_data_pump` now routes V1 vs V2 per `Session::wire_version()`, V2 path handles PATH_VALIDATION (auto-echo) and COALESCED (split-and-fan-out) |
| Metrics | **structured** (`TransportMetrics`) — security signals, gauges, handshake-latency histogram, Prometheus text exposition via `PhantomListener::metrics_prometheus_text()` |
| Integration tests | 5 (`tcp_integration` x2 `#[ignore]`, `kcp_integration` x3 `#[ignore]`) |
| Fuzz harnesses | 4 scaffolded (cargo-fuzz, nightly) |
| Workspace warnings | **0** |
| `cargo clippy --lib` warnings | 40 (audit-todo lints; non-blocking) |
| `unsafe` blocks outside `transport/udp_transport` | **0** (denied at crate root) |
| `.unwrap()` / `unreachable!()` in production hot path | **0** (6 documented panic sites — see `docs/security/panic-sites.md`) |
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
| 0.6 | Performance baseline (`BENCHMARKS.md`) | ✅ | _this commit_ | Methodology + reference numbers (M1 Pro): AES-256-GCM 4.2 GiB/s peak, ChaCha20-Poly1305 1.2 GiB/s peak, alloc overhead 1.7×. Criterion baseline JSON capture is the follow-up snapshot. |
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
| 1.5 | Mid-session key rotation (PFS within a session) | ✅ | _this commit_ | `Session::rekey()` derives next traffic secret via `HKDF-Expand(current, "phantom-rekey-v1", 32)` and ArcSwap-installs a fresh `CryptoState`. `current_epoch()` / `ratchet_to_epoch(target)` accessors. Epoch saturates at u8::MAX. Wired on the wire via V2 `PacketFlagsV2::REKEY` + `PacketHeaderV2.epoch`. |
| 1.6 | Strong session ID (32 → 128 bits) | ✅ | `e25f7a7` | `new_session_id` via thread_rng / ChaCha CSPRNG |
| 1.7 | AEAD nonce-exhaustion guard (`AEAD_MAX_INVOCATIONS`) | ✅ | `53f2c5e` | `CryptoError::NonceExhausted` at 2^48; observability accessors |
| 1.8 | Wire format version negotiation | ✅ | _this commit_ | `client_hello.version` now accepts `{1, 2}` (V3+ rejected with `UnsupportedVersion`). `Session.wire_version: AtomicU8` set by both sides post-handshake; downgrade resistance comes from `client_hello.version` being transcript-bound — a network-level rewrite causes the client-side signature verification to fail. Data-pump V1↔V2 routing is the follow-up (uses `session.wire_version()` to pick `encrypt_packet` vs `encrypt_packet_v2`). |
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
| 2.1 | Pooled recv accumulator | ✅ | _this commit_ | `TcpSessionTransport` keeps a persistent `BytesMut` accumulator alongside the reader; each frame is `split_to(len).freeze()`-ed off as `Bytes` — zero-copy hand-off, no per-packet `Vec::new` alloc after the first frame. Cleaner than wiring `BufferPool` (which needs lifetime-bound `PooledBuffer<'_>`) and achieves the same per-packet-zero-alloc goal. |
| 2.2 | Drop `plaintext.clone()` in recv path | ✅ | `9d92262` | recv channel now carries `Bytes`; single `to_vec` at FFI boundary |
| 2.3 | Pre-sized serialization buffer (small packets) | ✅ | _this commit_ | ACK buf hoisted out of recv loop (single `Vec::with_capacity(256)` reused via `clear()`); `send_app_data` uses `Vec::with_capacity(payload.len() + 64)` to avoid realloc-and-copy cycles |
| 2.4 | Event-driven send loop fast-wake | ✅ | _this commit_ | `Session.send_notify: Arc<Notify>`, public `notify_outbound_ready()`. `run_data_pump`'s `select!` adds a `notified()` arm so producers wake the loop instantly; the 10 ms `poll_interval` stays as a retransmit-timer fallback. |
| 2.5 | PacketCoalescer codec (V2 `COALESCED` flag) | ✅ | _this commit_ | Encode/decode primitives in `transport::packet_coalescer` + V2 bridge `transport::packet_coalescer_codec`. **End-to-end wiring complete**: `run_data_pump`'s V2 recv path detects `COALESCED` after decrypt, splits the bundle, and routes each sub-payload through the stream demux + session recv channel. Send-side bulk coalescing remains an optional optimisation (the codec primitives are ready to be called from a batching wrapper). |
| 2.6 | Wire `Pacer` + `BandwidthEstimator` | ✅ | _this commit_ | `Session.pacer: Arc<Pacer>` + `Session.bandwidth_estimator: Mutex<BandwidthEstimator>`. Public hooks `on_packet_sent / on_packet_acked / on_packet_lost`; `bandwidth_snapshot()` for metrics. ACK side feeds the pacer's rate back from the estimator's `pacing_rate()` — closes the BBR loop. Defaults to `Pacer::unlimited` so historical behavior is preserved. |
| 2.7 | Lock-free crypto state read path | ✅ | _this commit_ | dropped `RwLock<CryptoState>` — CryptoState is immutable post-handshake (no rekey yet), so encrypt/decrypt take a plain `&CryptoState`. Will become `ArcSwap` when Phase 1.5 rekey lands. |
| 2.8 | `Bytes` throughout API boundary | ✅ | _this commit_ | `SessionTransport::recv_bytes` returns `Bytes` (was `Vec<u8>`). All three impls updated: `TcpSessionTransport`, `WebSocketLeg` (wasm32), `ChannelTransport` (test). Send path stays `&[u8]` (callers usually pass a borrowed slice of an existing buffer). |
| 2.9 | SO_REUSEPORT multi-accept | ✅ | _this commit_ | `PhantomListener::bind` on Linux opens the socket via `socket2::Socket`, sets `set_reuse_port(true)` (best-effort — old kernels gracefully fall through to single-bind), then hands the listening socket to `TcpListener::from_std`. Non-Linux fallback: plain `TcpListener::bind`. |
| 2.10 | GSO / `sendmmsg` UDP | ✅ | (pre-existing) | already in `transport/udp_transport.rs` |
| 2.11 | Per-CPU work-stealing | ⏳ | — | likely overkill; revisit after Phase 4 |
| 2.12 | PGO + native CPU optional build | ✅ | _this commit_ | documented in `docs/operations/perf-tuning.md` (build commands, target-cpu choices, PGO workflow); release profile foundation already in place |
| 2.13 | Async/`select!` cancel-safety audit | ✅ | _this commit_ | `docs/security/cancel-safety-audit.md` — inventoried every `tokio::select!` and long-held `.await`, classified per tokio cookbook. Zero cancel-safety bugs identified. Re-run scheduled after Phase 4.4 introduces new tasks. |

**Phase 2 verdict:** kicked off (2.2 done; 2.8 partial; 2.10 pre-existing). Big-ticket
items (2.1, 2.4, 2.5, 2.6) remain.

---

## Phase 3 — Portability (WASM, embedded, mobile)

| # | Item | Status | Commit | Notes |
| --- | --- | --- | --- | --- |
| 3.1 | `Runtime` trait (decouple from tokio) | ✅ | _this commit_ | trait + `TokioRuntime` + 5 unit tests in `core/src/runtime/`, plus `PhantomSession::connect_with_transport_with_runtime` and `PhantomListener::bind_with_runtime` (Rust-only API surface) routing every `tokio::spawn` through `runtime.spawn`. recv-task completion via oneshot. `core/tests/runtime_integration.rs` pins it end-to-end with a counting runtime. Default `connect_with_transport` / `bind` preserved (UniFFI-stable). |
| 3.2 | `Clock` trait (WASM-compatible time) | ✅ | _this commit_ | folded into [`Runtime`] — `now_monotonic()` + `now_wall_clock()` are part of the trait surface. Per-target shims (e.g. `js-sys::Date` on WASM) land with the corresponding Runtime impls. |
| 3.3 | `WebSocketLeg` for browser WASM | 🔄 | _this commit_ | `core/src/transport/legs/websocket.rs` lands behind `#[cfg(target_arch = "wasm32")]`; implements `SessionTransport` over `web_sys::WebSocket`; deps gated by `[target.'cfg(...)']`. Module itself compiles on wasm32; full crate-level wasm build still blocked on Phase 3.5 (tokio "full" → wasm-only features). |
| 3.4 | `EmbeddedLeg` (UART / serial / CAN) | ⏳ | — | generic over `embedded-io-async` traits |
| 3.5 | Conditional compilation matrix (`std` / `wasm` / `embedded` / ...) | 🔄 | _this commit_ | `tokio` split into cross-target minimal (`sync`/`macros`/`rt`/`time`/`io-util`) + non-wasm-only (`net`/`rt-multi-thread`/`signal`/`process`/`fs`); `tokio-rustls`/`rustls`/`kcp-tokio`/`webpki-roots` moved to `[target.'cfg(not(target_arch="wasm32"))']`. Modules using `tokio::net::*` (`api/tcp_transport`, `api/listener`, `transport/udp_transport`, `transport/framing`, `transport/legs/{tcp,kcp,faketls}`, `transport/virtual_socket`, `networks/transport`, `networks/tls`) cfg-gated. `wasm32` build now passes tokio/mio/net and reaches `pqcrypto-internals` C bindings — that wall is Phase 5.1 (`ml-kem`/`ml-dsa` pure-Rust swap). |
| 3.6 | no_std + `alloc` for embedded | ⏳ | — | swap `pqcrypto-*` → `ml-kem` / `ml-dsa` |
| 3.7 | `zstd` C bindings now optional behind `compression-zstd` feature | ✅ | _this commit_ | `--no-default-features --features pqc-standard` produces a build with only `lz4_flex` (pure-Rust) — WASM/embedded compatible. Full pure-Rust zstd via `ruzstd` decode is a future-add. |
| 3.8 | RNG abstraction (`getrandom` features) | 🔄 | _this commit_ | partial — `getrandom = "0.2"` gets the `"js"` feature in the wasm32 dependency block so the wasm32 build no longer fails at `compile_error!("the wasm*-unknown-unknown targets are not supported by default")`. Full per-target RNG abstraction (hardware RNG on embedded, DRBG on FIPS) remains Phase 5 work. |
| 3.9 | FFI bindings generation (Swift, Kotlin, C) | ⏳ | — | only Python ships today |
| 3.10 | WASM-specific tweaks | ⏳ | — | drop `tokio = "full"`, etc. |
| 3.11 | Cross-platform CI matrix (12 triples) | ✅ | _this commit_ | new `.github/workflows/cross.yml` covers Linux x86_64/aarch64 (gnu, musl), macOS x86_64/aarch64, iOS device+sim, Windows x86_64/aarch64, WASM (browser+WASI, `allow_failure: true`), thumbv7em-none-eabihf embedded (`allow_failure: true`). |

**Phase 3 verdict:** untouched. XL effort — independent of Phase 1/2.

---

## Phase 4 — New Subsystems

| # | Item | Status | Commit | Notes |
| --- | --- | --- | --- | --- |
| 4.1 | 0-RTT resumption (server `SessionCache` wire-in, early-data encrypt) | 🔄 | _this commit_ | Server-side cache wired into `HandshakeServer`; tickets stored on success keyed by negotiated session_id. Client-side `Session::resumption_hint() -> Option<(id, secret)>` + `HandshakeClient::create_client_hello_with_resume`. ClientHello carrying a known `resume_session_id` bypasses cookie/PoW gate (forward secrecy via fresh KEM preserved). **Wire-level early-data encrypt under prior `resumption_secret`** is the remaining piece — needs a wire-format extension. |
| 4.2 | Multi-path validation primitive | ✅ | _this commit_ | State machine (`transport::path`) + V2 wire codec (`transport::path_validation_codec`) + **end-to-end data-pump wiring**. `run_data_pump`'s V2 recv path decrypts the AEAD payload, then drives the path registry: if the local side already has a pending challenge for the path it verifies and transitions to Validated; otherwise it auto-echoes the payload back as a response. Validator-side challenge emission still happens on caller demand via `Session::begin_path_validation`; scheduler-driven outbound path selection remains an optional optimisation. |
| 4.3 | Multi-stream finalization (priority, flow control) | ✅ | _this commit_ | Strict-priority scheduler in `run_data_pump` (`drain_streams_priority_ordered`); ties broken by stream id ascending for determinism. Per-stream flow control via new `PacketFlagsV2::WINDOW_UPDATE` (0x0800) — `Stream::peer_send_window` / `local_recv_window` atomics with monotonic-grow semantics, half-window threshold heuristic for emission, send-side `send_window_update_v2`, recv-side auto-application on inbound flag. HOL-blocking elimination (per-stream tasks) remains an optional refinement. |
| 4.4 | Congestion control (BBRv2-inspired) | ✅ | _this commit_ | BBR state machine in `BandwidthEstimator` (Startup/Drain/ProbeBW/ProbeRTT/FastRecovery) wired end-to-end. `send_app_data_v{1,2}` paces via `pace_send` and records `on_packet_sent`. Recv ACK handlers build `DeliverySample` from `Stream::ack` callback and call `Session::on_packet_acked` which mirrors the estimator's pacing rate onto the `Pacer`. Loss-based feedback (`on_packet_lost`) is caller-driven — retransmit-timer wiring is the next refinement. ECN support is a deferred subitem. |
| 4.5 | Telemetry: `tracing` instrumentation (foundation) + metrics primitives | ✅ | _this commit_ | `tracing` spans on handshake + listener entry points (pre-existing). `TransportMetrics` expanded with security signals (`replay_rejected_total`, `unencrypted_dropped_total`, `aead_decrypt_failed_total`, `path_migrations_total`, `handshake_failures_total`), gauges (`active_sessions`, `active_streams`), handshake-latency histogram (Prometheus `≤` bucket semantics). `MetricsSnapshot::to_prometheus_text()` emits text-exposition output. `PhantomListener::metrics_prometheus_text()` is the public accessor. SDK does not bundle an HTTP server — downstream wires `/metrics` if needed. Dashboard + alert rules templates land alongside (see `docs/operations/grafana/` and `docs/operations/prometheus/`). |
| 4.6 | Graceful shutdown + signal handling | ✅ | _this commit_ | `PhantomListener::shutdown()` flips `shutting_down: AtomicBool` and notifies waiters; parked `accept()` calls unwind with `CoreError::ConnectionClosed`. `is_shutting_down()` accessor. Already-accepted sessions continue until their owners close them. |

**Phase 4 verdict:** **closed for this cycle.** 4.2 ✅, 4.3 ✅, 4.4 ✅, 4.5 ✅, 4.6 ✅ all landed end-to-end. 4.1 🔄 — server-side cache + client-side hint are wired; wire-level early-data encrypt remains the natural follow-up (needs a wire-format extension to carry encrypted-under-resumption-secret bytes on the same flight as the ClientHello).

---

## Phase 5 — FIPS 140-3 / Common Criteria

| # | Item | Status | Commit | Notes |
| --- | --- | --- | --- | --- |
| 5.1 | FIPS-approved PQ primitives (ML-KEM-768 + ML-DSA-65) | ✅ | _this commit_ | swapped `pqcrypto-kyber` → `ml-kem` and `pqcrypto-dilithium` → `ml-dsa` (RustCrypto pure-Rust). No C bindings, no `libc`, native Zeroize. Deleted `crypto/keys.rs` (was the last `unsafe` opt-in module in `crypto/`). FIPS 203 / FIPS 204 wire encodings. Wire-incompatible with prior builds — pre-1.0 acceptable. |
| 5.2 | Constant-time audit pass | ✅ | _this commit_ | `docs/compliance/constant-time-audit.md` — classification framework (A/B/C/D), per-site inventory: cookie validation, path-challenge response, PoW solution verify (all Class A — `subtle::ConstantTimeEq`), pinning compare (Class C — public values), AEAD/signature tag verify (delegated to ring + ed25519-dalek + ml-dsa). |
| 5.3 | RNG / DRBG audit | ✅ | _this commit_ | `docs/compliance/rng-audit.md` — per-target backend matrix, RNG call-site inventory (sites that propagate vs fall back to thread_rng), FIPS-mode requirements (DRBG, thread_rng fallback removal, POST). |
| 5.4 | CAVP test vectors | ⏳ | — | `tests/cavp/` directory |
| 5.5 | Compliance docs (`docs/compliance/`) | ✅ | _this commit_ | Now 4 docs: `fips-readiness.md`, `key-management.md` (lifecycle per keyed object, zeroize coverage), `self-tests.md` (POST/PCT/CST plan, vector sources, error-state policy), `fips-security-policy.md` (draft CMVP security policy: boundary, approved services, modes, mitigations). |
| 5.6 | Common Criteria Protection Profile mapping | ⏳ | — | NIAP PP-Mobile Device VPN Client likely |
| 5.7 | Validation pathway (CMVP / CC submission) | ⏳ | — | external lab; out of code scope |

**Phase 5 verdict:** 5.1 ✅ landed (ml-kem/ml-dsa pure-Rust). 5.2 ✅ + 5.3 ✅ + 5.5 ✅ (CT audit, RNG/DRBG audit, full set of compliance sub-docs) this cycle. 5.4 (CAVP vectors), 5.6 (CC PP mapping), 5.7 (lab validation) remain.

---

## Phase 6 — Audit Readiness

| # | Item | Status | Commit | Notes |
| --- | --- | --- | --- | --- |
| 6.1 | Threat model (`docs/security/threat-model.md`) | ✅ | _this commit_ | STRIDE + LINDDUN, trust-boundary diagram, asset table, adversary model, mitigation traceability to file:line; 9 sections |
| 6.2 | Protocol specification (`docs/protocol/PROTOCOL.md`) | ✅ | _this commit_ | 10 sections: versioning, primitives, KDF labels, packet structure, AEAD construction, handshake state machine + messages, transcript signing, cookie/PoW, reserved fields, error model |
| 6.3 | Architecture document (`docs/architecture/ARCHITECTURE.md`) | ✅ | _this commit_ | 11 sections: layer overview, types per layer, encryption boundary, concurrency / task topology, ownership model, wire framing, error propagation, performance landmarks, module dep map, evolution roadmap |
| 6.4 | cargo-fuzz harnesses + OSS-Fuzz integration | ✅ | `24015d2` | 4 targets in `fuzz/`; OSS-Fuzz job tracked separately |
| 6.5 | Property tests (`proptest`) | ✅ | _this commit_ | `core/tests/property.rs`: AEAD round-trip, AEAD AAD-mismatch reject, ReplayWindow monotonic accept, ReplayWindow duplicate reject, wire-format round-trip. Configurable via `PROPTEST_CASES=N`. |
| 6.6 | Loom tests (concurrency invariants) | ⏭️ | — | Current concurrency surface is well-understood `AtomicU64::fetch_add(_, Relaxed)` and `DashMap` — no bespoke lock-free algorithms that would benefit from loom permutation testing. Will revisit if/when Phase 4.2 multi-path migration introduces non-trivial concurrent state machines. |
| 6.7 | `cargo miri` CI job | ✅ | _this commit_ | `.github/workflows/miri.yml`; runs `cargo +nightly miri test` weekly + on each PR over the synchronous subset (replay_window, adaptive_crypto, transport::types) with strict-provenance + symbolic alignment checks |
| 6.8 | Formal negative-security tests | ✅ | `8d69521` | `core/tests/security_invariants.rs` — 10 tests |
| 6.9 | Coverage measurement (`cargo-llvm-cov`) | ✅ | _this commit_ | `.github/workflows/coverage.yml`; generates lcov.info with branch coverage; soft-uploads to Codecov when `CODECOV_TOKEN` secret present |
| 6.10 | Formal verification (ProVerif / Tamarin) | ⏳ | — | optional; only if audit demands |
| 6.11 | Inline `SAFETY` / `PANIC-SAFETY` comments | ✅ | _this commit_ | All 6 remaining production panic sites annotated in-line (`stream.rs` semaphore + recv_buf, `fragmentation.rs` x2, `legs/faketls.rs` x2) with `// PANIC-SAFETY:` comments + narrow `#[allow(...)]` annotations. New `docs/security/panic-sites.md` enumerates each site with its invariant and an adversarial review checklist. |

**Phase 6 verdict:** 6.1 through 6.9 are landed (skip 6.6 — loom not needed given current concurrency surface). 6.11 ✅ this commit (panic-sites doc + inline annotations). 6.10 (formal verification) remains optional / audit-driven.

---

## Phase 7 — Operations & Release

| # | Item | Status | Commit | Notes |
| --- | --- | --- | --- | --- |
| 7.1 | End-to-end examples (loopback / mobile / WASM / embedded) | 🔄 | _this commit_ | `core/examples/loopback_demo.rs` — full server↔client encrypted echo in one binary, prints what happens on the wire. Mobile / WASM / embedded examples still pending the Phase 3 runtime abstraction. |
| 7.2 | Deployment guides (Docker / k8s / systemd / mobile / WASM) | 🔄 | _this commit_ | `docs/operations/docker.md` (Dockerfile, ulimits, metrics endpoint, graceful-shutdown), `docs/operations/systemd.md` (unit file + hardening + multi-instance SO_REUSEPORT template + sysctl), `docs/operations/deployment.md` (overview + pre-deploy checklist + capacity planning). Kubernetes / mobile / WASM guides still pending. |
| 7.3 | Versioning policy + `cargo-semver-checks` | ✅ | _this commit_ | `docs/policy/versioning.md` — three independent axes (Rust API SemVer, wire format `VersionedPacket::Vn`, FFI ABI); V1→V2 process; MSRV policy; deprecation policy; change-type matrix. cargo-semver-checks now wired in `.github/workflows/release.yml`. |
| 7.4 | Release pipeline (cargo-release + GPG + SLSA) | 🔄 | _this commit_ | `.github/workflows/release.yml` — PR-triggered cargo-semver-checks, tag-triggered cargo publish dry-run + cross-target build artifacts (x86_64/aarch64 linux+darwin) + draft GitHub Release. SLSA-3 OIDC provenance attestation remains a pre-1.0 follow-up. |
| 7.5 | Incident-response playbook | ✅ | _this commit_ | `docs/security/incident-response.md` — triage timeline, CVSS 4.0 severity buckets, roles (Triage Lead / Fix Author / Reviewer / Release Captain), reproduction discipline, fix authoring rules, embargo + coordinated disclosure, GHSA/CVE filing, post-mortem template |
| 7.6 | Grafana dashboards + Prometheus alert rules | ✅ | _this commit_ | `docs/operations/grafana/phantom-dashboard.json` (4 rows: throughput, sessions, security signals, network quality) + `docs/operations/prometheus/alerts.yml` (3 groups: phantom_security, phantom_capacity, phantom_health — 8 alert rules total). References the `phantom_*` metric names exposed by Phase 4.5. |
| 7.7 | Performance tuning guide | ✅ | _this commit_ | `docs/operations/perf-tuning.md` covers release profile, target-cpu, PGO, sysctl, fd limits, CPU pinning, allocator choice, profiling tools, reference numbers |
| 7.8 | Migration guides per breaking change | ✅ | _this commit_ | `docs/migration/v1-to-v2.md` — wire-format negotiation explained, rollout-phase checklist for fleets, downgrade-resistance guarantee, known caveats. |

**Phase 7 verdict:** Substantial progress this cycle — 7.1 (partial loopback example, in-flight), 7.2 (Docker / systemd / deployment-index guides), 7.3 (versioning policy + cargo-semver-checks in CI), 7.4 (release pipeline workflow), 7.5 (incident response), 7.6 (Grafana dashboard + Prometheus alerts), 7.7 (perf tuning), 7.8 (V1→V2 migration guide). Kubernetes / mobile / WASM deployment guides remain; SLSA-3 provenance is the long-tail item for 7.4.

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
