# Changelog

All notable changes to this project will be documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
once it reaches 1.0.0. Pre-1.0 releases may have breaking changes between minors.

## [Unreleased]

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

This release takes phantom_core from its 0.2.0 pre-1.0 baseline through the
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
  SDK / Collector, not Phantom Core.
- New always-on integration test `core/tests/observability_e2e.rs` gates the
  wiring (a real session must populate the counters and return the gauge to 0).

### Added — `wasi-leg` Cargo feature (commits `f6c0c0a`..`255be95`)

**`cargo build --target wasm32-wasip2 --features wasi-leg` is now a
shipped configuration.** Phantom Core embedders can run inside any
WASI Preview 2 host (Wasmtime, WasmEdge, Spin, wasmCloud, Cloudflare
Workers WASI sandbox).

New surface:
- **`phantom_core::transport::legs::wasi::WasiLeg`** — length-prefix-
  framed `SessionTransport` over `wasi:sockets/tcp`. Client-only
  for now; `connect(SocketAddr)` wraps the Preview 2 socket-create +
  start_connect + poll + finish_connect dance. Same 4-byte
  big-endian framing as `TcpSessionTransport`.
- **`phantom_core::runtime::wasi_runtime::WasiRuntime`** — single-
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
`phantom_core = { default-features = false, features = ["std"] }`
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
  every Phantom Core entry point that performs cryptographic work
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
- Removed `phantom_core::transport::metrics` module entirely.
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
- `phantom_core::observability::*` module: `Observability` facade,
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
  manifest (`pyproject.toml`, `phantom_core.pc.in`) reports the same
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
  `tests/bindings/c/phantom_core.h` were re-synced to the post-OTel
  cdylib. The now-deleted `metrics_prometheus_text` was the last
  residual symbol — Python `import phantom_core` would `dlsym`-fail
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
