# Changelog

All notable changes to this project will be documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
once it reaches 1.0.0. Pre-1.0 releases may have breaking changes between minors.

## [Unreleased]

### Removed

- **`api::session::SESSION_RECV_MEMORY_COMMITMENT`, and `phantom-server`'s
  `--max-recv-memory-mib` / `PHANTOM_MAX_RECV_MEMORY_MIB` with it.** The constant published a
  single per-session resident total for the receive path, and the flag divided an operator's
  memory budget by it to derive a session cap. It was wrong three times. Each correction
  raised it, and each time the error had the same shape: a figure this endpoint chooses was
  treated as though it bounded the peer. The last of them charged a delivery-queue slot the
  sender's own chunk size while the receive path would have accepted a frame three thousand
  times larger.

  The frame ceiling above fixes the mechanism, but the total is withdrawn rather than
  restated. A per-session total has to enumerate every allocation the receive path makes,
  including the ones beneath this layer — the byte pipe's receive accumulator, the
  per-session PhantomUDP fragment reassembler, the `Stream` structures themselves — and a sum
  that misses one reads as a bound while being an estimate. What is published in its place is
  the per-buffer table in the module documentation of `api::session`: each bound, what it
  limits, and the code that enforces it, with the two that are *not* enforced marked as such
  — the advertised receive window, which nothing on the receive path consults, and the
  delivery hard cap, which one frame's charge crosses before the reader notices (that
  overshoot is now published as `MAX_DELIVERY_CHARGE_PER_FRAME` rather than rounded away).
  `docs/security/threat-model.md` §5 §D.1 and `docs/operations/deployment.md` carry the same
  split. A cap derived from an estimate under-provisions a host by exactly the factor the
  estimate is out, which is worse than no flag, so sizing goes back to measurement against
  `PHANTOM_MAX_SESSIONS`.

- **`transport::udp_transport` — a public module nothing could reach, carrying the crate's
  only native `unsafe`.** `UdpTransport`, `UdpHandshakeListener`, `PacedSender` and
  `FastSender` were exported from `phantom_protocol::transport::udp_transport` and had no
  caller anywhere: not in the library, not in the benches, examples, integration tests or
  fuzz targets, and not in the `server` / `cli` / `testbed` siblings. Restricting the module
  to `pub(crate)` made the compiler report every item in it as never constructed; the same
  restriction applied to a live module reports nothing, which is what makes that a proof and
  not an absence of evidence. What hid it for so long is a name collision:
  `core/src/api/udp_transport.rs` is the live PhantomUDP transport and is the file everyone
  meant when they read the path. This is a public API removal, but no code could have been
  depending on it — the types were unreachable in the sense that constructing one gave a
  socket helper wired to nothing.

  It mattered beyond the dead bytes. The module held one of three `#![allow(unsafe_code)]`
  opt-ins and the crate's only `libc::setsockopt(SO_MAX_PACING_RATE)` call, and the `unsafe`
  inventory at the crate root — the comment an auditor reads first to learn where `unsafe` lives —
  described it as a live low-level socket and pacing helper. An inventory of `unsafe` that
  points at code no build can execute overstates the surface under review and, worse,
  understates the reviewer's ability to trust the rest of the list. Two opt-ins remain
  (`transport/legs/websocket.rs`, `transport/legs/wasi.rs`), both cross-language-boundary
  glue confined to a non-native target, so a native build now compiles no `unsafe` at all.
  The Linux-only `libc` dependency went with it, since nothing in `core/src` names `libc::`
  any more.

- **`transport::device_profile` — a public tier table that contradicted the crypto layer.**
  `DeviceProfile`, `DeviceTier`, `PqKemLevel` and `PqSignLevel` were exported and referenced
  by nothing: not by the handshake, not by the crypto layer whose parameters they described,
  and not by any bench, example, integration test, fuzz target or sibling crate. Being merely
  unused would have been an argument for leaving them alone. What decided the removal is that
  they were unused *and wrong in a direction that costs the reader something*: the table
  offered `PqKemLevel::Kyber512` and `PqSignLevel::Dilithium2` for a constrained tier, and the
  handshake negotiates one fixed hybrid suite — X25519 + ML-KEM-768 with Ed25519 + ML-DSA-65 —
  with no mechanism to select a lighter post-quantum level for anything. Someone sizing an
  embedded target against that table would have planned for key material the protocol will
  never send, and would have had no way to find that out short of reading the handshake. The
  non-crypto knobs beside them (`buffer_size`, `max_streams`, `coalescing`, MTU) steered
  nothing either. This is a public API removal in the pre-1.0 breaking window; nothing could
  have depended on it for behaviour, since constructing a `DeviceProfile` changed no bytes and
  no timing.

### Changed (wire-breaking)

- **`WINDOW_UPDATE` carries a cumulative limit instead of a relative credit —
  `WIRE_VERSION` 6 → 7, `PROTOCOL_VERSION` 3 → 4.** The frame's AEAD plaintext is now eight
  big-endian bytes stating the *total* the receiver will let its peer send on that stream,
  counted from the stream's first byte, in place of four bytes saying "add this much". Both
  ends count the same quantity — the sender counts every reliable application byte it puts
  on the wire once, the receiver counts every byte it hands to its application — so the two
  can be compared without either inferring the other's state, and a receiver applies an
  inbound limit as `max(held, advertised)`.

  The defect this removes is a permanent stall, not a slow path. A `WINDOW_UPDATE` rides in
  one unacknowledged datagram that nothing retransmits, and the receiver destroyed the credit
  as it composed the frame, so a lost one subtracted from the sender's window **for the rest
  of the connection**. The deficit is monotone — at loss rate `p` it accrues as `p ×` the
  bytes transferred — so on any lossy path it reaches the initial 64 KiB window in finite
  time, and the sender is then blocked with *nothing in flight*, which means no
  acknowledgement can arrive to free it. On the reference WAN path it reproduced in four of
  seven uploads that established a session: 69.7 s, 69.9 s, 55.9 s and 48.7 s frozen, each
  ending only at the harness cap, with `inflight/cwnd` at a median of 0.000 against 0.63–0.93
  for a transfer that completes and the congestion window open the whole time. The TCP and
  mimic legs, whose datagrams cannot be lost, never froze for more than 2.8 s in the same
  runs. The persist probe that had already shipped could not close it, because it can only
  return credit still sitting in the receiver's accumulator and the terminal case is the one
  where the lost frame is what emptied that accumulator — neither end retains it, so no local
  mechanism can reconstruct it.

  A total has the three properties an increment lacks, and they are what make the frame safe
  to lose: it is **idempotent** (a duplicate grants nothing extra), **reorder-safe** (a stale
  frame states a smaller total and the maximum discards it) and **loss-tolerant** (the next
  frame states the whole truth rather than the difference since the last). The persist probe
  is kept — it is the only place the fact "data queued and no room" exists, since a receiver
  cannot tell a blocked peer from an idle one — but its answer is now simply the current
  limit, which repairs however many earlier frames were lost. `Stream::take_owed_window_credit`
  and the two-task race on the emission accumulator it required are deleted with it.

  `PROTOCOL_VERSION` moves with `WIRE_VERSION` even though no handshake byte changed, and
  that pairing is the point: the data-plane version check **drops** a mismatched frame
  silently, so a wire bump on its own would let an older peer complete a handshake and then
  stall with no error — the exact failure this change exists to remove. With the handshake
  version moved too, an older peer gets a typed `ServerReject` naming both versions before
  any session exists. `docs/policy/versioning.md` records the rule.

  Seven frozen fixtures moved: the four packet vectors by their `version` byte alone, the two
  `ClientHello` vectors by theirs, and `transcript_hash.bin` because the hello it covers
  changed. `tests/wire_vectors_decode.py` gained an independent statement of the new
  plaintext codec and of the monotone-maximum rule. What a hostile peer gains is unchanged:
  `MAX_SEND_WINDOW` (1 MiB) now clamps the honoured limit to `bytes_sent + 1 MiB`, so a peer
  advertising `u64::MAX` buys one window of permission and must send another frame for more,
  exactly as a peer flooding inflated credits did before.

### Changed

- **`BandwidthEstimator::on_ack` and `Session::on_packet_acked` now hand back the RTT sample
  the acknowledgement produced.** `on_ack` returns `(u64, Duration)` where it returned the
  pacing rate alone, and `on_packet_acked` returns that `Duration` where it returned a
  bandwidth figure no caller in the tree read. The sample is the locally timed round trip less
  as much of the peer's claimed `Sack::ack_delay_us` as RFC 9002 §5.2/§5.3 permits, and the
  per-path RTT gauge now publishes exactly it.

  Two reasons, one of each kind. The correctness one: the gauge previously re-derived the
  figure at its own call site, and two subtractions written separately is how the gauge came
  to accept one the congestion window already refused. The cost one: the floor that bounds the
  subtraction lives behind the estimator's mutex, so fetching it from the gauge's side meant a
  second acquisition for every segment retired — and a cumulative SACK retires a whole flight
  in a loop, so the price was 2N acquisitions where N is right. Handing the conclusion back
  from the acquisition that already holds the lock settles both at once. The helper the two
  call sites share, `ack_delay_adjusted_rtt`, and the floor accessor `rtt_floor` are
  deliberately `pub(crate)`: both call sites are in-crate, and a bound of this shape has no
  meaning outside the estimator that supplies the floor.

- **`transport::{compression, fallback, scheduler, packet_coalescer}` stay public and now say
  on their first documented line that nothing calls them.** These four are exported, compiled
  and tested, and no send or receive path reaches any of them; `PacketFlags::COMPRESSED` is set
  by no code in the crate, so the adaptive compressor in the public API compresses nothing that
  has ever been sent. Each was checked individually rather than inherited from an inventory:
  `compression` has no caller at all; `fallback` is constructed into every `Session` behind
  `#[allow(dead_code)]` and none of `record_sent` / `record_success` / `record_failure` /
  `check_and_fallback` / `upgrade` is called outside its own tests; `scheduler` is likewise
  constructed into every `Session` and reachable through `Session::scheduler()`, but
  `select_paths` steers nothing; and `packet_coalescer` is split — `Decoalescer` is live in the
  receive path via `packet_coalescer_codec`, while `PacketCoalescer` is constructed only under
  `#[cfg(test)]`. `transport`'s own module documentation lost its claim that adaptive fallback
  tiers are a property of this transport and gained the list instead.

  The rejected alternatives are worth recording, because each looks better than it is.
  `pub(crate)` is unavailable to three of the four: with no in-crate caller the compiler
  reports every item as dead, and silencing that with `#[allow(dead_code)]` states the opposite
  of what is true. Deleting `compression` was the tempting one — it is the only consumer of
  either `lz4_flex` or `zstd` in the crate, so it alone is what puts the C-bound `zstd-sys` in
  a default build's graph. But the module is the visible tip of that cost and not the cost
  itself: `compression-zstd` is a default feature named in `server/Cargo.toml`,
  `testbed/Cargo.toml`, `examples/wasm-demo/Cargo.toml`, the FIPS and cross-target CI command
  lines, the version string `phantom-cli` prints, and eight compliance and operations
  documents. Deleting the module alone would leave a feature flag that toggles nothing —
  trading a false promise a reader can see for one they cannot — and deleting the flag as well
  is a coordinated manifest and CI change across three sibling crates, which is a maintainer's
  decision rather than a module edit. Deleting `fallback` or `scheduler` means editing
  `Session`, and `SchedulerMode` has to survive either way: it is a required argument of
  `Session::from_derived` and genuinely live.

- **`Stream::poll_send` (public, `phantom_protocol::transport::stream`) returns
  `Result<OutboundSegment, SendBlocked>` instead of `Option<OutboundSegment>`, and takes a
  fourth argument.** A pass that comes up empty because the application ran dry, because
  the local congestion window is full, and because the *peer's* advertised receive window
  is full are three different statements about the connection, and only the first is BBR's
  application-limited signal — which the send loop is the only place that can observe. The
  new `SendBlocked` enum carries that distinction; the new `app_limited_now: bool` argument
  is stamped onto each segment's first transmission and reported back on
  `RetiredSegment::app_limited_at_send`, so the phase a `DeliverySample` carries is the one
  the segment was *sent* in rather than whichever phase happened to be in force when its
  acknowledgement arrived. A peer's advertised window is deliberately not routed into the
  flag: it gates the loss response, the Startup judgement and the bandwidth filter, and no
  remote party may hold that switch.

- **`phantom_protocol::transport::stream` gained the session-wide receive-window ledger.**
  `SharedRecvTuning` (new public struct) is the handle every stream of one connection draws
  its window growth from; `Stream::with_recv_tuning` constructs a stream against one and
  `Stream::recv_tuning` hands the handle on, so a stream created by the pump or by a peer
  joins the same ledger as one opened through the API. `SESSION_RECV_WINDOW_GROWTH_BUDGET`
  (8 MiB) is what the ledger holds and `SharedRecvTuning::remaining_growth_budget` reports
  what is left of it. `MAX_SEND_WINDOW` and `MAX_RECV_WINDOW` doubled from 512 KiB to 1 MiB
  with the ceiling above. `MAX_RECV_REORDER` and the new `REORDER_ENTRY_OVERHEAD_BYTES` are
  public alongside them, and `api::session` exports `MAX_STREAMS`,
  `RECV_DELIVERY_HARD_CAP`, `DELIVERY_ITEM_OVERHEAD_BYTES`,
  `MAX_DELIVERY_CHARGE_PER_FRAME`, `STREAM_RECV_CHANNEL_DEPTH` and
  `RAW_APP_RECV_CHANNEL_DEPTH`, with `transport::mtu` exporting `MAX_RECV_FRAME` and
  `MAX_RECV_PAYLOAD` and `transport::sack` exporting `MAX_SACK_WIRE`. Each names one
  receive-side bound the transport enforces; the module documentation of `api::session`
  lists them together with what enforces each and marks the two that are observed rather
  than enforced. They are deliberately not summed into a per-session total — see the
  Removed entry below.
- **`migrate()` on a non-migration transport now returns `Err(CoreError::Unsupported)`**
  instead of a silent `Ok(())` no-op. Real migration requires a UDP-backed session
  (`connect_pinned_udp*`); on TCP / WebSocket / WASI / Embedded it now errors honestly.
- **Combinatorial Rust constructors were removed** in favour of the builder:
  `PhantomSession::connect_with_resumption`,
  `PhantomListener::bind_with_signing_key_with_runtime`, and
  `PhantomListener::bind_with_signing_key_mimic`. The runtime-injection shims
  `PhantomSession::connect_with_transport_with_runtime` and
  `PhantomListener::bind_with_runtime` survive, as do `connect_with_transport` and the
  UniFFI-exported free functions and constructors. `PhantomStream::recv()` returns
  `Option<Vec<u8>>` (`None` = clean EOF). All breaking, within the pre-1.0 0.2.x window.
- **`PhantomUdpListener::accept()` now takes an owned receiver** (`self: Arc<Self>`
  instead of `self: &Arc<Self>`) — required by its new UniFFI export. Rust callers
  write `listener.clone().accept().await`. Breaking, within the pre-1.0 0.2.x window.
- **`MetricsSnapshotFfi` gained a field, which breaks every FFI consumer built against
  0.2.2 — and breaks the C one silently.** `unencrypted_dropped_total` (see Added) sits
  between `aead_failure_total` and `uptime_secs`, and a UniFFI record is lowered as its
  fields in declaration order with nothing on the wire naming them. Nothing catches this at
  load time: UniFFI's per-function checksums are computed from the function's name and the
  *names* of its argument and return types, so adding a field to a record leaves every
  checksum and the contract version unchanged. Python, Swift and Kotlin fail at the call
  instead — their generated lift asserts the buffer was fully consumed and raises "junk
  data left in buffer" / `incompleteData` — which is loud but says nothing about the cause.
  A C consumer walking the buffer per the layout documented in
  `tests/bindings/c/phantom_protocol.h` gets no error at all: it reads the new counter as
  `uptime_secs` and stops one field short.

  What a consumer must do: regenerate. `tests/bindings/generate_{python,swift,kotlin}.sh`
  produce the updated glue and the in-tree bindings are already regenerated with it; C
  consumers must re-copy `phantom_protocol.h` and re-check any hand-written decoder against
  the `PhantomMetricsSnapshotFfi` layout in it. Bindings and native library must be shipped
  as a matched pair — a new `libphantom_protocol` under an old binding is the failure above.
  Breaking, within the pre-1.0 0.2.x window.

### Added

- **`unencrypted_dropped_total` in the metrics snapshot, and an always-on test that drives the
  gate it counts.** The receive path drops every unencrypted post-handshake packet — the
  stripped-flag downgrade defence, and the one thing standing between a forged standalone
  `FIN` and a torn-down stream. Two things were wrong with how that was carried. The drop was
  recorded only into an OpenTelemetry instrument, which is a no-op ZST unless the
  `telemetry-otel` feature is on, so on a default build neither an operator nor a test could
  see the gate fire; a dropped frame leaves no other trace, and "nothing arrived" and "we
  refused what arrived" looked identical. It now increments a lock-free counter alongside
  `replay_rejected_total` and `aead_failure_total` and surfaces through `MetricsSnapshot` /
  `MetricsSnapshotFfi`, so it is readable from every language binding with no exporter
  configured. The FFI record gains one `u64` field, and the Python, Swift, Kotlin and
  hand-curated C surfaces are regenerated with it. The testbed's own `ClientMetrics` carries
  it too, so a wire-capture record now shows whether the gate fired — the one thing a capture
  cannot establish, since header protection hides the flag the gate reads.

  And `core/tests/security_invariants.rs` — the file this project points auditors at as the
  place its numbered invariants are pinned — did not drive that receive path at all. What it
  held was the neighbouring AEAD property, that the flag cannot be stripped from a *genuine*
  packet without breaking the tag, which is a different statement from a freshly forged
  unencrypted packet being refused. The gate was covered by two in-crate tests under
  `cargo test --lib`, so it was gated; it just was not where a reviewer following the
  documentation would look, and an inventory that does not contain what it claims turns a
  security review into theatre. The suite now runs a live session against a hand-driven
  server and puts four frames on the wire, all on an `open_stream()` stream — the only place
  a `FIN` means anything, since the delivery router discards a close for the reserved
  raw-app ids and the `recv()` behind them has no EOF to deliver. An empty-payload forged
  `FIN`, which on the v6 wire cannot reach the flag gate at all because header protection
  samples sixteen ciphertext bytes it does not have; the same forgery at the smallest size
  the wire admits, laid out so that a receiver skipping the gate would hand its bytes to the
  application; an authentic frame, whose delivery is what keeps the test from passing on a
  receive path that drops everything; and a second authentic frame on the same stream.

  The last two fail for different regressions, which is the reason both are there. Deleting
  the gate delivers the forgery's bytes and the third assertion reads `downgraded!!` where
  it wanted `authentic`. A gate that refuses the bytes but still records the `FIN` leaves
  that assertion passing — the `FIN`'s EOF is released only once the in-order cursor passes
  its offset, and it is the authentic frame that advances the cursor — and surfaces one
  frame later as a `None` in place of the fourth. Both were run: the gate was removed, then
  narrowed to note the `FIN` only, and each failure was observed where predicted.

  The always-on suite is now 64 tests; `CONTRIBUTING.md`, `README.md` and the Common Criteria
  mapping carried 60.

- **The testbed's raw UDP controls now report a reorder *distance* distribution, in both
  directions.** They counted a datagram as reordered when it arrived below the highest
  sequence seen, which says a path reorders and sizes nothing: a transport's reordering
  tolerance is a distance and a duration. On the production test path the downstream
  control has measured 60 Mbit/s carried at 1.1% loss while 13–14% of datagrams reordered,
  and at 20 Mbit/s 13.4% reordering against 0.12% loss — separable quantities that a single
  counter cannot separate. Each rung now records the distance behind the highest seen
  (`p50`/`p90`/`p95`/`p99`/`max`), the receiver-side time displacement between the arrival
  that revealed a gap and the arrival that filled it — the quantity a RACK-style threshold
  is sized in — and, correcting for the head start the late datagram had on its overtaker
  using the send stamps both directions now carry, the extra transit time the path added.
  Loss and reordering are classified per gap rather than inferred: a gap a later arrival
  filled is reordering, one the receiver's window slid past is loss, and one still open when
  the rung ended is neither and is reported as its own number instead of being folded into
  either. The receiver's bookkeeping is a fixed 4096-slot array allocated once, so a rung of
  100 000 datagrams — or a sender naming arbitrary 64-bit sequence numbers — cannot grow it;
  what falls outside that window is counted and named rather than silently booked as loss.
  The client → server echo control gained the same instrumentation by numbering and stamping
  its own datagrams in bytes that were already filler, so the daemon, the datagram size, the
  rate ladder and the pacing are all unchanged and the numbers stay comparable with runs
  already taken. `analyze.py` prints both directions side by side and flags a tail that
  reached the instrument's window rather than the path's.

- **`testbed/` — a real-network (WAN) test harness.** A new sibling crate with two
  binaries: `phantom-testd`, a daemon that binds every network-testable leg
  (PhantomUDP, Phantom-over-TCP, mimic-TLS) from a single persisted identity plus raw
  TCP/UDP echo controls, and `phantom-probe`, which drives a scenario matrix and writes
  raw per-operation samples. Scenarios: clock offset estimation, handshake latency,
  RTT sweeps across payload sizes, message-boundary integrity, upload / download /
  full-duplex goodput, concurrent streams, 0-RTT resumption, forced rekey, connection
  migration, concurrency, and negative cases (wrong pin, closed port, junk flood).
  Profiles `smoke` / `standard` / `deep`. Results are flushed after every scenario and
  the client uploads its bundle to the daemon over the Phantom session itself.
  Every automated test in this repository previously ran over loopback or an in-memory
  transport, where RTT is microseconds, nothing reorders, no NAT exists, and the path
  MTU is 65535 — a regime that cannot exercise the RTO timer, the bandwidth estimator,
  real migration, or path-MTU behaviour. See `testbed/README.md`.
- **PhantomUDP is now reachable through the FFI surface.** New UniFFI exports make the
  production, migration-capable transport usable from every binding (Python / Swift /
  Kotlin / C), where previously only the TCP transport was reachable:
  - free functions `connect_pinned_udp(host, port, pinned_key)` and
    `connect_pinned_udp_with_resumption(host, port, pinned_key, hint, early_data)` (the
    0-RTT analogue);
  - the `PhantomUdpListener` object — constructor `bind_udp` plus `accept`,
    `verifying_key_bytes`, `local_addr`, `shutdown`, and `is_shutting_down`.
  Over a `connect_pinned_udp` session the exported `migrate()` now performs a real
  single-path connection migration (e.g. Wi-Fi ↔ LTE handover); over a TCP session
  (`connect_pinned`) it now returns `Err(Unsupported)` rather than silently succeeding.
  Liveness / `Migrating` / `Dead` transitions, path validation, and passive NAT-rebind
  recovery are all live for FFI consumers on the UDP path.
- **FFI server identity.** `generate_signing_key()` and `verifying_key_from_signing_key(seed)`
  (free functions) plus the `PhantomListener::bind_with_signing_key_bytes` and
  `PhantomUdpListener::bind_udp_with_signing_key_bytes` constructors let a pure-FFI
  (mobile / C) embedder generate, persist, load, and pin a server's hybrid signing
  identity, so a server keeps a stable pinned identity across restarts — previously key
  generation and `bind_with_signing_key` were Rust/CLI-only. The 64-byte seed
  (`ed25519_seed[32] || ml_dsa_seed[32]`, the same form `phantom-cli keygen` writes) is
  secret key material and is **not** zeroized across the FFI boundary — persist it `0600`
  and wipe the buffer after use.
- **In-app metrics over FFI.** `metrics_snapshot()` on `PhantomSession` and
  `PhantomListener` returns a flat `MetricsSnapshotFfi` record (packets/bytes,
  encrypt/decrypt timing, RTT, handshakes, active sessions/streams, uptime, and — newly
  promoted into the lock-free atomics so they're available without an OpenTelemetry
  collector — `replay_rejected_total` / `aead_failure_total`). A server-accepted session
  reports the owning listener's aggregate (shared handle).
- **Working tunables via `PhantomConfig`.** `PhantomConfig` was an FFI-exported struct
  whose fields nothing read; it is now an honest 4-field record
  (`keepalive_interval`, `session_timeout`, `session_cache_capacity`,
  `session_ticket_lifetime`) consumed through new `connect_pinned_with_config` /
  `connect_pinned_udp_with_config` and `bind_with_config_bytes` /
  `bind_udp_with_config_bytes`. Keepalive/timeout map to the live `LivenessConfig`;
  cache fields size the server resumption cache. (`session_timeout` is the
  Migrating→Dead reap window, not a general idle-disconnect.) The 8 inert legacy fields
  (fallback/buffer/MTU/connect_timeout) were removed.
- **Multi-stream is usable.** `PhantomSession::accept_stream()` surfaces peer-initiated
  streams; `PhantomStream::set_priority()` sets scheduler priority; `PhantomStream::recv()`
  now returns `Option<Vec<u8>>` (`None` = clean peer EOF) instead of a stringly-typed
  error. Stream ids are allocated client-odd / server-even so concurrent opens never
  collide.
- **FFI ergonomics.** `AcceptOutcome::peer_addr_string()` (per-peer admission control),
  and `set_early_data_enabled(bool)` is now exported on both listeners.
- **Builder API (Rust).** `PhantomSession::builder(addr)` / `PhantomListener::builder(addr)` /
  `PhantomUdpListener::builder(addr)` with orthogonal chained setters
  (`.transport()` / `.pinned_key()` / `.resumption()` / `.config()` / `.runtime()` →
  `.connect()`; `.signing_key()` / `.config()` / `.runtime()` → `.bind()`, plus
  `.mimic_sni()` on `ListenerBuilder`) replace the combinatorial
  `connect_with_resumption` / `bind_with_signing_key_with_runtime` /
  `bind_with_signing_key_mimic` variant explosion (the
  `connect_with_transport_with_runtime` and `bind_with_runtime` runtime-injection
  shims survive). A builder cannot produce an unpinned session (Security Invariant 1).
- **Typed client failure.** `PhantomSession::last_error()` and `await_ready()` (both
  FFI-exported) let an embedder learn *why* a connect failed (the background handshake
  task now captures the terminal `CoreError`) and wait for readiness; `send()`/`recv()`
  surface the captured cause instead of a generic "session closed". New structured
  `CoreError` variants — `ServerIdentityMismatch` (fatal pinning failure),
  `ProtocolRejected`, `Unsupported` — with a retryable-vs-fatal classification in the
  rustdoc, so callers can build correct retry/backoff logic without string-matching.
  Handshake failures also stop collapsing into `CoreError::InternalError`: the
  `From<HandshakeError>` conversion now yields `ServerIdentityMismatch` /
  `ProtocolRejected` for those two cases and `CoreError::HandshakeError(..)` for the
  rest, so `match`es on `InternalError` for handshake errors must be updated.
- **Migration discoverability.** `PhantomSession::supports_migration()` reports whether a
  session can migrate (true only for UDP-backed sessions); client-side handshake outcome
  metrics are now recorded (a client `metrics_snapshot()` no longer always shows 0
  handshakes).
- **Secure seed default for Rust.** `generate_signing_key_secure()` returns the 64-byte
  seed wrapped in `Zeroizing` (wiped on drop); the FFI `generate_signing_key()` (which
  cannot carry `Zeroizing` across UniFFI) now documents the secure variant.
- **Documentation.** README is now the docs.rs landing page with a UDP-first runnable
  quickstart, a "Getting started" / "Choosing a transport" / "Two ways to send" guide,
  and runnable rustdoc examples on the session/listener types; a PyPI-wheel packaging
  path (maturin) + a manual CI smoke job were added.
- **Observability instruments that were registered but never recorded are now live.**
  Twelve instruments existed in the registry with no call site anywhere in the library, so
  the corresponding Grafana panels and the `PhantomPoWRejectionStorm` alert were silently
  empty and `MetricsSnapshotFfi`'s encrypt/decrypt-timing and RTT fields were always zero.
  Now recorded: AEAD encrypt/decrypt durations, RTT samples (per `path_id`, Karn-gated),
  rekey events per direction, path migrations (active, server-initiated, peer-detected and
  passive NAT-rebind), path-validation outcomes, a balanced active-stream gauge, and the
  handshake-side cookie / proof-of-work / early-data / resumption outcomes. The handshake
  recorders required plumbing an optional `Arc<Observability>` into `HandshakeServer` via a
  purely additive `with_observability(...)` builder — every existing constructor keeps its
  signature and gets a no-op sink. `record_fallback` remains unrecorded: the
  `FallbackStateMachine` it would observe is itself inert.
  Two attribute values are new: `EarlyDataOutcome::RejectedDisabled` (`rejected_disabled`)
  so a server running the 0-RTT kill switch is distinguishable from one simply seeing no
  0-RTT traffic, and `PathValidationOutcome::Timeout` (`timeout`) so an abandoned path
  challenge is distinguishable from one answered wrongly. The latter is backed by an
  expiry sweep on the pump's existing 10 ms heartbeat, budgeted from the session's own
  `LivenessConfig` and BBR `min_rtt` — the same threshold at which that heartbeat already
  declares a path down — so a challenge yields exactly one `success`, `failure` or
  `timeout` sample and never leaks its bookkeeping. The sweep is metrics-only; it does not
  change `PathRegistry` state.
- **Two API properties that were recorded only here are now stated where they are read.**
  Every `connect_pinned*` function's rustdoc now opens with the fact that it returns
  **before** the handshake — so `Ok` means a socket was opened, not that the server holds
  the pinned key — and carries an example that calls `await_ready()` immediately. Likewise
  `PhantomSession::send`, `PhantomStream::send_reliable` and `PhantomStream::send_unreliable`
  now state that they do not preserve message boundaries, name
  `transport::mtu::MAX_APP_CHUNK` as the split size, and point at the length-prefix pattern
  in `testbed/src/framing.rs`. No behaviour change.


- **`PhantomUdpListener::metrics_snapshot()`**, exported over UniFFI and identical in shape to
  the TCP `PhantomListener`'s, so the two listeners are interchangeable in an embedder's
  monitoring code. The UDP listener owns the `Arc<Observability>` that its handshake path and
  every accepted session write through, but published no accessor for it: the aggregate was
  reachable only through an *accepted session's* `metrics_snapshot()`. An operator running the
  production, migration-capable transport from a foreign language therefore had no listener-level
  metrics at all, and — precisely when it matters — a server that is being probed but has no live
  session could report neither its handshake counters nor `replay_rejected_total` nor
  `aead_failure_total`. Nothing about what is counted changes; the counters were always there,
  only unreadable.

### Fixed

- **The crate could not be packaged, and nothing in CI noticed for two months.**
  `core/src/lib.rs` inlined the repository-root README into the crate documentation with
  `#![doc = include_str!("../../README.md")]`. That path is correct in this repository, where
  `src/lib.rs` sits two levels below the root, and wrong inside a `cargo package` archive,
  where it sits one level below the archive root and the two dots address the parent of the
  extracted directory. `cargo package` verifies by unpacking its own tarball and building it,
  so every run since the line landed ended in `couldn't read src/../../README.md`. No path can
  be right in both layouts: an archive carries only what sits under the manifest directory, so
  the file has to be inside `core/`.

  It is, as `core/README.md`, now a byte-identical copy of the landing page rather than the
  five-kilobyte stub that had been sitting there since before the `include_str!` — a stub
  whose status line still read "Pre-1.0 (`0.1.x`)" and which is what crates.io has been
  rendering for 0.2.2. A symlink was considered and rejected: on a checkout without symlink
  support it becomes a twelve-byte file whose entire contents are the text `../README.md`,
  which packages, compiles, and ships that string as both the crates.io page and the docs.rs
  front page, with every exit code zero. A duplicate can only drift, and drift is checkable —
  `scripts/sync_readme.sh` repairs it from a pre-commit hook and asserts it in CI, and
  `cargo test --lib` fails on it in a required branch-protection context.

  The reason this survived is that no job ever built the crate the way a consumer receives it.
  A new `cargo package` CI job now does, and before that build it asserts something the
  verification build structurally cannot: that the README inside the tarball is the landing
  page. Verification compiles the archive, and a crate compiles just as happily around the
  wrong README — which is exactly the failure that shipped.

- **A stream stopped on its flow-control limit with nothing outstanding had no way to ask, and
  no answer was on its way.** Blocked with nothing in flight is the one state a sender cannot
  leave on its own: what would free it is an acknowledgement, and an acknowledgement only comes
  back for something sent. Until then it waits on the receiver volunteering a `WINDOW_UPDATE`
  — which that side emits only when its application consumes enough to cross the half-window
  threshold governing emission. A peer that has stopped reading never crosses it, and neither
  does one whose earlier frame the path ate.

  Measured on a route losing 9.5–15.9 % of its UDP round trips at ~300 ms: an upload's
  congestion window froze at 45 881 bytes with `inflight` at 0 and delivered bytes frozen at
  163 469 for the remaining 70 seconds of the run, never leaving Startup. Peak inflight had
  been 3.2 % of the ARQ send buffer, so no volume limit was involved. The TCP and mimicry
  legs in the same run ran to completion.

  A stream that is flow-control blocked *and has nothing outstanding* — the state that proves
  no acknowledgement is on its way — now asks. The **persist probe** is a zero-length reliable
  segment, the FIN sentinel's shape without the `FIN` flag, and it carries **no application
  byte**. That is the whole of why it is safe. A sender cannot tell a receiver whose grant was
  lost from one whose application has simply stopped reading — the two are the same
  observation from here — and with an empty probe it does not have to: the second receiver is
  charged nothing at all and keeps this side stopped for as long as it is not reading, which
  is flow control working. The trigger and the `MIN_RTO` floor under the interval are both
  local values; withholding credit is what causes a probe, and withholding it faster does not
  make one come sooner.

  The offset it carries is the highest the peer has already acknowledged, and that is
  load-bearing rather than economical. A probe on a fresh offset necessarily sits above the
  data the window is holding back, so the peer parks it in its reorder buffer and SACKs it as
  an island — and an island above the gap raises `largest_acked` past every offset the stream
  sends next, which RFC 9002's packet threshold reads as loss. That design was built and
  measured before this one: with a probe SACKed at offset 8, the next two segments were
  declared lost the instant they were acknowledged, and
  `a_probe_does_not_make_the_next_segments_look_lost` fails on it with `[1, 2]`. Repeating an
  acknowledged offset moves nothing, and the reason has to cover both of the things being
  acknowledged means: a receiver acknowledges what it has delivered and what its reorder
  buffer still holds, so the repeat is either discarded as a duplicate before the reorder
  buffer is consulted, or found already buffered and dropped without adding an entry. So a
  probe consumes no offset, occupies no reorder entry, is not tracked in flight and is never
  retransmitted; an unanswered one is simply asked again next interval.

  The answer comes from the receiver, which is the side that knows. An empty reliable segment
  is recognised there and re-states the cumulative limit that side is currently advertising —
  bytes its application has really consumed, plus the window it is offering on top. Because a
  limit is a total, one answer repairs however many earlier `WINDOW_UPDATE` frames the path
  ate; because both of its terms move only on real consumption, a receiver that is not reading
  re-states the very number its peer is already stopped at and leaves it stopped. A peer that
  probes repeatedly extracts nothing it has not earned.

  A peer that does not answer stays interoperable: it acknowledges the probe and its sender
  remains blocked exactly as it would have been without one. No frame kind is added, and no
  value the peer writes enters the sender's side of the mechanism.

- **A write the transport refused cost the peer's flow-control window a segment, permanently.**
  `Stream::poll_send` debits the peer's window as it hands a first transmission out, so a
  write that then failed — a datagram socket out of buffer space, a byte pipe that went away —
  had taken credit off a counter no acknowledgement would ever put back: `mark_unsent` cleared
  the send timestamp so the segment would be re-offered, and the re-offer debited the window a
  second time for the same bytes. Every refusal therefore shrank the window by one segment for
  the rest of the connection, arriving at the same dead end as a lost `WINDOW_UPDATE` by a
  route entirely inside this endpoint, with no peer and no path involved.

  The debit is now marked on the segment that carries it, so the pass that levies one skips a
  segment already holding it, and a refused write returns it only when the send buffer says no
  copy of those bytes has ever left — `retries == 0`, which the two retransmit passes and
  nothing else move. Reading that from the buffer rather than from the caller is what makes
  the accounting idempotent at both ends. A refused *retransmission* keeps its charge, because
  the original did reach the wire; returning it and re-levying it on the re-offer would be
  correct only if the two happened together, and they do not — an acknowledgement of the
  original is processed on the receive task and can land in between, retiring the segment by
  offset whether or not it is currently stamped, so there would be no re-offer left to take
  the credit back. The sent total would then sit below the bytes the receiver has counted,
  which is this side granting itself room to overrun a window nobody opened, ending at the
  delivery hard cap where a conforming peer closes the session.

- **A number the peer writes could end the task that drains every stream on the session.**
  `Stream::try_consume_send_window` decided whether a charge fit by adding it to the sent
  total and comparing afterwards, and the addition was an ordinary one. The clamp that holds
  an advertisement to one `MAX_SEND_WINDOW` past what has gone out is a saturating add, so it
  degenerates at the top of the `u64` range: a peer advertising exactly `u64::MAX` against a
  sent total near it is honoured verbatim, is left holding a few bytes of window, and the
  charge for those bytes is a sum that leaves the range — a wrap in release, a panic in the
  drain task in debug. The comparison is now made on `checked_add`, and a sum that cannot be
  represented reads as the ordinary refusal rather than as a special case: `peer_send_limit`
  is a `u64` too, so such a sum is above every limit the peer is able to state.

- **The PhantomUDP handshake abandoned paths a mature implementation completes, because its
  retransmission timer asserted a number about the path instead of adapting to it.** The
  client-side stop-and-wait shim used a fixed 400 ms retransmit timeout and a cap of six
  retransmits — 2.8 s of waiting in total, ending in `CoreError::Timeout`. On a route
  measuring 267 ms minimum / 298 ms average / 367 ms maximum round trip with 11.7 % ICMP
  loss, quinn completed ten handshakes out of ten while PhantomUDP completed eight, five and
  eight across three runs of ten, every failure taking exactly 3.40 s. The reference
  implementation finishing on the same path in the same run is what identifies this as ours
  rather than the network's, and the server side confirms it: for one run of ten attempts the
  daemon logged eleven session opens — it completed handshakes for attempts the client had
  abandoned roughly half a second earlier. The replies were not being dropped. They were
  merely later than the timer allowed.

  Two things were wrong. The interval was shorter than the path's round trip plus the
  server's hybrid-KEM and dual-signature work, so honest replies arrived after the timer had
  already fired and each one spent a retransmit on a reply nothing had lost. And the total,
  2.8 s, was far tighter than the 10 s session-level handshake deadline it runs underneath —
  the transport refused while 72 % of the budget it was given remained unspent.

  The schedule is now the one both RFC 6298 §2.1 and RFC 9002 §6.2.2 arrive at for a first
  transmission with no round-trip sample: a 1 s initial timeout, doubling on every expiry
  (RFC 6298 §5.5, RFC 9002 §6.2.1), bounded by a total of 8 s. That spends as 1 s → 3 s → 7 s
  — three retransmits, four flights in all, against seven flights before — and gives up at
  8 s, leaving the last retransmit a full second to be answered. Nothing meaningful precedes
  the first flight: the two hybrid keypairs the client generates measure 48.7 µs and 225.7 µs
  at the criterion medians of `transport_bench`'s `pqc_keygen` group on an Apple Silicon
  release build, under 0.3 ms together, so the 8 s refuses with most of two seconds of the
  10 s deadline still in hand. (The half-second a handshake takes end to end on the measured
  route is round trips; it is not key generation, and reading it as key generation is what
  made this margin look tight.) Client patience against a slow path goes from 2.8 s to 8 s
  while the duplicate flights a slow path provokes are more than halved.

  What it costs is the speed of a refusal. A `ServerReject` is read past up to three times
  before the client believes it, and over PhantomUDP each of those reads is answered only
  once the schedule retransmits the flight — a version check is stateless, so a retransmitted
  hello is rejected again — which makes a server that does not speak our version take 3.0 s
  to be believed where the old timer took 1.2 s. That is accepted: the only way to shorten it
  is the short first interval that abandoned honest connects, and if the path also falls
  silent after the reject the cost is the 8 s any silent path costs, because the loop gives up
  on the first read that fails.

  Nothing in the schedule is derived from anything the peer supplies. A round-trip sample is
  the interval between our transmission and *its* reply, so learning from one would let a
  peer that answers slowly dictate our timer; the handshake is a few flights long and has no
  sample for the first one regardless, so the fixed conservative start costs nothing. Nor can
  a peer stretch the schedule by arriving: the client socket is unconnected, the loop resumes
  after every datagram that fails to complete a frame, and a timer built from a *length*
  restarts its interval on each resumption — so it is now an absolute deadline computed once
  and carried across those resumptions, and a source that sprays undecodable datagrams faster
  than the interval no longer postpones the refusal at all. The wire is unchanged: this is a
  local timer, not a negotiated parameter.

  No server-side change accompanies it. A retransmitted `ClientHello` carries the same
  bootstrap connection id, so the demux routes it to the existing session rather than opening
  a second one; the in-flight state an abandoned attempt occupies is already bounded by the
  server's own 10 s handshake deadline, one of 256 concurrency permits, and a route reaped as
  soon as the task ends. Telling the server to stop would mean either a new wire message or a
  teardown an unauthenticated source could trigger, and the state it would reclaim is
  measured in seconds.

- **A peer could put a 4 MiB frame in a delivery-queue slot sized for 1156 B.** The
  per-stream queues between the delivery task and `PhantomStream::recv` are bounded in slots,
  not in bytes, so what a session holds is the slot count times whatever a peer can put in a
  slot — and nothing bounded the second factor. `MAX_APP_CHUNK` is a *sender-side* budget
  describing how this side chunks; the receive path never applied it, the reorder buffer's
  byte budget governs out-of-order segments only (in-order data goes straight to the queue),
  and the byte pipe underneath hands over whatever its own frame cap allows — 4 MiB on the
  TCP and mimicry legs once the frame phase is `Established`. Across `MAX_STREAMS` × the
  channel depth that is a quarter of a terabyte reachable by an authenticated peer against an
  application that is not reading.

  The receive path now refuses an inbound frame larger than `MAX_RECV_FRAME`
  (`transport::mtu`). That ceiling is **not** this side's own chunk budget read backwards:
  the published 0.2.2 chunks at a flat 1300 bytes, 144 more than this build's derived
  figure, so a gate set to our own budget would have refused every full-size data frame a
  released peer sends — before the AEAD, so never acknowledged, with its retransmits meeting
  the same gate. That session would not fail, it would stop, silently and with nothing in a
  counter. `MAX_RECV_FRAME` is therefore derived from `LEGACY_APP_CHUNK`, the largest chunk
  any released version emits, and a compile-time assertion holds it there independently of
  this side's own budget so that lowering ours cannot narrow what a peer may send. It is checked in the pump's reader before header protection and before
  the AEAD, so an oversized frame costs a length comparison. It is a **drop**, not a
  teardown: nothing has been authenticated at that point, so tearing the session down would
  hand anyone who guesses a connection id a one-datagram kill. A peer that really sends
  oversized frames stalls instead — the segment is never delivered, never SACKed, and its
  retransmits meet the same gate.

  Nothing on the wire changes and no field carries a length; this is a receive-side
  rejection, invisible to a peer that respects the chunking rule. That nothing legitimate
  exceeds it is checked on both sides: `transport::mtu` asserts each of the three
  post-handshake frame shapes against the budget at compile time (a full reliable chunk,
  which fills it exactly; anti-fingerprint padding, which has its own lower ceiling; and the
  largest SACK, now `sack::MAX_SACK_WIRE`), and a unit test watches the wire while a live
  pump produces all of them with padding and cover traffic armed. Handshake messages are far
  larger and are unaffected — they are exchanged before the pump exists.

- **The receive-window growth budget was handed out per stream on the raw session API, and
  described as bounding more than it does.** `Session::open_stream` — the Rust-only
  transport-level API, distinct from `PhantomSession::open_stream` — built each of its
  streams with a `SharedRecvTuning` of its own. The allowance whose entire purpose is to stop
  256 streams each reaching the per-stream ceiling was therefore multiplied by the stream
  count, which is a number the peer picks: 32 streams of one session took 30 MiB of growth
  against an 8 MiB budget, scaling linearly to 256. One handle per `Session` now, as the
  streams the data pump builds already had. `security_invariants.rs` pins it two-sided —
  N sessions × M streams hold no more than N budgets between them, with a positive control
  showing the same streams blow past that when each gets its own handle.

  The accompanying claim needed correcting too. `SESSION_RECV_WINDOW_GROWTH_BUDGET` bounds
  *growth*, so it is worth 8 MiB of what one session can be made to hold; it does not touch
  the 16 MiB of initial windows 256 streams start with, the 64 MiB of reorder structure a
  peer can pin with tiny segments above a hole it never fills (the byte budget counts payload,
  the entry cap counts entries), the delivery backlog, or the per-stream delivery channels
  that fill when the application reads slower than the peer sends. `REORDER_ENTRY_OVERHEAD_BYTES`
  is the per-entry structure charge that makes the reorder figure a memory rather than a
  count, and `DELIVERY_ITEM_OVERHEAD_BYTES` does the same for the delivery backlog: an item
  is not a byte, and measured against the real queue one costs about 65 B, so a 4 MiB
  payload-only cap really admitted around 300 MiB when a peer chose one-byte segments. Every
  queued item is charged it, FIN signals included, since an uncharged item is an uncapped
  one. `docs/security/threat-model.md` §5 §D.1 is where this whole class of threat now has a
  row; `docs/operations/deployment.md` carries the operator-facing version.

- **A SACK carrying more than 32 islands threw away the one range that retires data.**
  `Stream::received_sack` builds its range list with the contiguous delivered run first —
  lowest — and `Sack::from_ascending_coalesced` reversed the list to descending and then
  truncated it to `MAX_SACK_RANGES`. The reverse put the highest ranges at the front, so
  the truncation dropped the lowest, which is exactly the cumulative run. The justification
  on the books was that a dropped range is "recovered by cumulative re-ACK"; that does not
  hold when the range dropped *is* the cumulative one. Downstream, `on_sack` retires only
  what `Sack::acks` covers, so every segment of a delivered window stayed in the send
  buffer, fell at least `PACKET_THRESHOLD` behind `largest_acked`, was declared lost and
  was retransmitted — a whole window of already-delivered data resent and a whole window of
  fabricated loss fed to congestion control. It needed no malice: the reorder buffer holds
  thousands of islands, so more than 32 holes in one flight is a function of loss rate and
  window size. An overflowing range set is now reduced **from the middle**, keeping the
  largest range (which drives loss detection) and the cumulative run (which drives
  retirement); the middle islands are the recoverable ones, because `received_sack` rebuilds
  the whole set from live reorder state on every ACK and reports them again as the buffer
  drains. `MAX_SACK_RANGES` is unchanged: the cap exists so the encoded form always decodes
  at the peer, and raising it moves the cliff rather than removing it. Below the cap the
  emitted bytes are exactly what they were.

- **The receive window's ceiling sat below the path.** `MAX_RECV_WINDOW` was 512 KiB, and a
  window of `W` bytes admits `W / RTT` bytes per second whatever congestion control decides.
  On the 235 ms path this transport was last measured on that is 17.85 Mbit/s, against
  41.8 and 42.9 Mbit/s of raw one-way UDP over the same path in two runs; server-side
  samples showed inflight pinned flat against the cap at 492–520 KB run after run. The
  ceiling is now 1 MiB, which doubles that to 35.7 Mbit/s. It is not raised further because
  nothing above it is reachable: a stream's ARQ send buffer holds at most 1024 unacked
  segments of at most 1156 bytes, so 1 183 744 B is all one stream can ever have
  outstanding whatever credit it is granted, and window granted past that is memory
  committed for data that cannot arrive. Moving both together is a separate change with its
  own memory case to make.

  The receive-side memory a session can be made to commit is now bounded by a session-wide
  growth budget (`SESSION_RECV_WINDOW_GROWTH_BUDGET`, 8 MiB) that every doubling draws on
  and every dropped stream returns to. A per-stream ceiling never bounded a session, which
  may hold 256 streams: with the budget the session-wide worst case works out *lower* than
  before (40 MiB of reorder budget against 144 MiB) even though the per-stream ceiling
  doubled. Every stream of a connection — API-opened, pump-created or peer-initiated —
  draws on one handle, so the bound holds rather than merely being intended. Growth remains
  driven by what the application consumed, never by what arrived. What the budget bounds and
  what it does not is set out in the entry below and in `docs/security/threat-model.md`
  §5 §D.1; the short form is that it is 8 MiB of a 429 MiB per-session commitment, and that
  the commitment is per session rather than per process. The round-trip reference
  the interval is derived from is a constant on a receive-only stream, which is the flow
  auto-tuning exists for, because such a stream never measures a round trip of its own. On a
  stream that also sends, it is that stream's own `min_rtt`, and a peer that delays every
  acknowledgement can stretch it — the interval is `2 × rtt`, so a longer one lowers the
  consumption rate a doubling has to beat. What that buys the peer is bounded and is not the
  dangerous direction: it can reach the ceiling sooner, never pass it, and every doubling is
  still paid for in bytes the local application actually consumed. `MAX_SEND_WINDOW` moves
  with the ceiling — the two ends of one credit ledger must agree.

- **Every full-size PhantomUDP segment was sent as two datagrams.** The data pump chunked
  application data at 1300 bytes, a number chosen independently of the datagram budget it
  had to fit. One reliable chunk becomes `header(15) ‖ AEAD(stream_offset(4) ‖ chunk)`,
  and the AEAD adds a 16-byte tag, so a 1300-byte chunk is a 1335-byte inner frame — 144
  bytes past the 1191 that fit one 1200-byte datagram after the 9-byte outer envelope.
  The transport dutifully fragmented it into a full datagram plus a 169-byte tail.
  That doubled the datagram rate for the same goodput, spent an 8-byte fragment
  subheader plus a fresh 28-byte IP/UDP header on the tail, and — because a segment is
  delivered only when every one of its fragments arrives — turned an independent
  per-datagram loss rate `p` into `1 − (1 − p)² ≈ 2p` per segment. Loss recovery, the
  SACK loss detector and BBR's 2% loss threshold all count segments, so the protocol was
  reacting to roughly twice the loss the path was applying. The chunk size is now derived
  from `PATH_MTU` in `transport::mtu` (1200 − 9 − 15 − 4 − 16 = 1156 B), so a full segment
  is exactly one full datagram, and a future `PATH_MTU` rise widens it automatically.
  The byte-pipe legs (TCP, mimicry, WebSocket, WASI, embedded) never fragmented and are
  unaffected beyond a 0.4-point rise in per-packet framing overhead.
  `PhantomSession::send()` still does not preserve message boundaries above the chunk;
  only the threshold moved, from 1300 to 1156 bytes.

- **The congestion window was released as a burst, because nothing on the send path read
  the pacing rate.** BBR computed one for every session ever opened, and every `Session`
  was constructed with `Pacer::unlimited()`, which sets `enabled = false`. `set_rate`
  stored a number; `set_enabled` was never called from outside the pacer's own tests; the
  drain's only gate was `budget = min(cwnd, window) − inflight`. A congestion window is a
  volume, and a volume released without a rate is a burst: everything the window allows
  goes out back to back and the sender then waits a round trip. That is not what BBR's
  gains describe — Startup's 2.0 and ProbeBW's 1.25/0.75 are instructions to a rate
  limiter, and with no limiter to instruct, the ProbeBW cycle that is supposed to probe
  for more bandwidth was performing arithmetic nobody read.
  It went unnoticed while the window was small. Three congestion-control fixes since have
  moved it from a pinned 5600 bytes to peaks of 690–938 KB with estimates of
  11.8–16.4 Mbit/s, and a path whose raw-socket profile is 0.6% loss at 9.6 Mbit/s but
  41% at 57.6 Mbit/s does not absorb most of a megabyte arriving at line rate. The
  measured symptom was the reverse direction: downstream during a bidirectional run held
  0.93–1.15 Mbit/s while the upload moved 2.5–4.2 MB over the same interval, because the
  upload's acknowledgements and flow-control credit queued behind the download sender's
  standing burst.
  The drain now consults the pacer before every segment and settles the true on-wire size
  after it, so the two budgets it enforces are the window's volume and the estimate's
  rate. The wait is not taken on the send path: a pass with no pacing credit *returns*,
  and the pump arms a `sleep_until` branch of its own `select!`. Sleeping inside the
  drain would park the whole pump — no flow-control credit, no commands, no liveness
  sweep — which is the shape that starved the download in the first place, so
  implementing pacing that way would have traded one direction's collapse for the other's.
  Acknowledgements, `WINDOW_UPDATE`, keep-alives and path validation stay unpaced for the
  same reason.
  The bucket's burst allowance is a fixed duration of the current rate (4 ms, clamped to
  16 KiB–512 KiB) rather than a constant. A pacer is consulted by a task that wakes on a
  timer, and a timer's granularity is about a millisecond, so a constant allowance is a
  constant ceiling: one packet's worth — a pacer that slept between every packet — caps
  at about 9.6 Mbit/s at this MTU, and the previous fixed 64 KB at about 512 Mbit/s. The
  clamps state where the reasoning holds; the ceiling this pacer can sustain is 512 KiB
  per 4 ms, about 1.07 Gbit/s. The bucket is signed, so a send authorised before its size
  was known carries the overshoot as debt instead of having it forgiven.
  Pacing stays off until the estimator has measured a bottleneck bandwidth, which is the
  answer to the bootstrap: before the first acknowledgement `btl_bw` is zero and any rate
  derived from it is invented — the old `btl_bw.max(1)` made that two bytes per second,
  which on the first segment is a deadlock, since the first segment is what produces the
  acknowledgement that would fix it. A congestion reset on migration switches it back off
  with the estimate it belonged to. `pacing_rate()` is additionally floored at the
  smallest window this controller will ever use divided by the minimum round trip:
  pacing may smooth what congestion control permits, it may not overrule it downward.
  Measured on the in-crate 512 KiB/s, 200 ms full-duplex harness: upload under a
  saturating download rose from 76 KB to 188–285 KB per window, restoring an assertion
  that had been lowered from 96 KiB to 24 KiB pending exactly this change, while the
  download was unchanged. On the 2 MiB/s, 200 ms harness a unidirectional download costs
  about 2% of link utilisation (2.03 → 1.99 MB/s median), which is the ProbeBW cycle's
  0.75 phase being real for the first time.

- **BBR's loss response removed the mechanism by which the sender could recover from
  loss, so a lossy path pinned the bandwidth estimate at whatever it happened to hold.**
  Every retransmitted segment reported a loss, which put the estimator into a
  `FastRecovery` state whose only substantive effect was to set `cwnd_gain = 1.0`; every
  other state uses 2.0. That single line is an absorbing state rather than a back-off.
  A sender's measurable delivery rate is bounded by what it has in flight —
  `rate ≤ inflight / rtt` — so holding inflight at exactly one bandwidth-delay product,
  which is what a gain of 1.0 means, makes the best sample it can possibly take equal to
  `btl_bw`, the value it already holds. `btl_bw` is a *maximum* filter, so a sample that
  merely equals it is no news and the estimate does not move. Growth needs headroom above
  the BDP, and the back-off consumed exactly that headroom: after entering, the connection
  could no longer discover that the path was faster than it believed, and no amount of
  time on the path gave that back. On a link losing a few percent, retransmissions are
  continuous and the state was re-entered on every one of them. A path measured with raw
  sockets at 9.34 Mbit/s and 2.7% loss carried 1.2 Mbit/s of protocol traffic, with a
  congestion window peaking at 300–350 KB — room for roughly 13 Mbit/s at the path's
  200 ms round trip. The window was never the limit. The estimate was, and it was pinned
  by its own output.
  The granularity was wrong in the other direction at the same time. Loss on a real path
  is a rate, not an event: a sender with a few hundred segments in flight at 2.7%
  retransmits several times per round trip, so a response scaled per lost segment fires
  permanently and conveys nothing. One lost segment out of 194 halved the window in the
  regression test that now pins it — and by the end of that same round trip the response
  had evaporated entirely, because `FastRecovery` exited as soon as inflight fell back
  inside the BDP, which a window capped at the BDP satisfies almost immediately. The
  sender was simultaneously over-reacting to a single packet and running with no
  steady-state reduction at all.
  Loss is now answered the way BBRv2 and BBRv3 answer it: with a bound on the volume
  rather than a change to a gain, judged once per round trip against the round's loss
  rate. `BBRHandleLostPacket` books the bytes and does nothing else — it does not move
  the state machine's phase, and `BbrState::FastRecovery` is gone because loss is not a
  phase. Once per round, a loss rate past the draft's `BBRLossThresh` (2%) reduces an
  `inflight_hi` bound by `BBRBeta` (0.7); the congestion window becomes
  `min(cwnd_gain × BDP, inflight_hi)`. The separation is the whole point: the gain governs
  *growth*, the bound governs the *level*, and only one of them can be taken away without
  blinding the sender. The bound is floored at 1.25 × BDP — strictly above one BDP, so the
  fixed point cannot be reached through it either, and 1.25 specifically because that is
  the ProbeBW probe gain, whose job is to ask the path for a quarter more than the current
  estimate. Rounds that stay under the threshold lift the bound back by the same factor
  until it no longer binds and is dropped, so it is a response and not a ratchet.
  Rounds that say nothing about the path are skipped: an application-limited round has a
  denominator it did not earn, and ProbeRTT pins the window to four packets by fiat, so
  both halves of its ratio are the controller's own doing.
  In a closed-loop regression over the measured path — 9.34 Mbit/s, 2.7% loss, 200 ms —
  the estimate now climbs from 1.34 Mbit/s to 9.10 Mbit/s across eighteen round trips;
  before, it moved from 1.34 to 2.59 Mbit/s and stopped. Sustained loss still costs the
  sender a 37.5% window reduction, and a clean path returns it in full.
  What is deliberately not implemented: `bw_lo` / `bw_hi`, the draft's short-term
  *bandwidth* bounds. They exist to bound the pacing rate, and this crate's pacer is inert
  on the live path (`Pacer::unlimited()` at every `Session` construction, `set_enabled`
  never called), so a second bound there would be a knob wired to nothing — the congestion
  window is the only limiter the drain loop consults. `BBRCheckStartupHighLoss` is also
  omitted: the inflight bound already caps Startup's overshoot, and a second Startup exit
  keyed on loss would end the connection's only exponential-growth phase on exactly the
  class of path this change is about.
  `Session::bbr_bytes_lost()` replaces the BBR phase as the observable for "the send path
  reported a retransmission to congestion control".
  **Sender-local congestion control only: no wire-format, handshake or key-schedule change,
  and old and new peers interoperate unchanged.**
- **A fixed 64 KiB per-stream receive window was a hard rate ceiling that congestion
  control could never lift.** Flow control returns credit to the sender one round trip
  after the receiving application consumed the data, so a window of `W` bytes admits at
  most `W` bytes per round trip: 2.62 Mbit/s per stream on a 200 ms path, and in practice
  about half of that, because the credit for the second half of a window arrives only after
  the first half has already been acknowledged. The measured sustained rate on such a path
  was 1.2 Mbit/s — 46% of the nominal ceiling — on a link a raw socket carries 9.34 Mbit/s
  over. None of that was congestion control's doing: its window reached 300–350 KB, which
  at that round trip would have permitted around 13 Mbit/s. The window simply refused to
  let it.
  The receiver now auto-tunes the window it advertises, the same mechanism TCP receive-window
  auto-tuning and QUIC flow-control auto-tuning implement. Over a measurement interval of
  two round trips, if the application consumed more than four fifths of a window, the window
  is close enough to being the binding constraint to double it, up to the existing 512 KiB
  `MAX_SEND_WINDOW` — so the advertised window converges on two and a half bandwidth-delay
  products and stops. The threshold sits deliberately below the round half, because a flow
  that really is window-limited achieves about half its nominal ceiling and a test placed on
  that figure would never fire on the flow it exists for.
  What the growth is tied to is the whole of its safety argument: **demonstrated application
  consumption, never arrival**. The counter is fed only by the delivery task, as it hands
  bytes onward to the application, so a peer that floods a reader that never reads moves the
  window by exactly nothing, however long it keeps it up. Measuring over a time interval
  rather than a byte count matters for the same reason — the bounded delivery queue in front
  of the application absorbs one queue's worth of bytes even when the reader has stopped, and
  a byte-triggered rule would read that transient as a sustained rate and climb the whole
  ladder on it. The round trip the interval is measured against is the *minimum* RTT sampled
  on the stream rather than the smoothed one: a saturated path inflates the smoothed estimate,
  a longer estimate makes growth easier, and a larger window queues more, which is a loop that
  ends at the cap no matter what the application does.
  The per-stream reorder budget now tracks the tuned window (`Stream::recv_reorder_byte_limit`,
  128 KiB at the initial window as before, 576 KiB at the cap) rather than staying pinned to
  twice the initial one. A window larger than the reorder budget would have had legitimate
  out-of-order segments refused and retransmitted on exactly the lossy long paths a large
  window is for. Session-wide, the number that bounds buffered-but-undelivered bytes is
  unchanged: the pump still tears a session down at 4 MiB of delivery backlog.
  **Receiver-local: a wider window is expressed as a larger number in the `WINDOW_UPDATE`
  frame the receiver already sends, so no field, frame kind or layout changes here and this
  change on its own leaves the byte-exact wire vectors untouched.**
- **BBR had no concept of a round trip, so the sender left its only growth phase within
  the first one and then stopped probing for bandwidth entirely.** Both of the estimator's
  round-scaled rules — the Startup exit test and the ProbeBW gain cycle — were driven off
  a counter incremented once per *acknowledged packet*, because `update_state` runs at the
  end of `on_ack`. Nothing in the file tracked round trips at all.
  The Startup exit rule itself is canonical: three consecutive rounds whose bandwidth grew
  by less than 25% mean the pipe is full. Evaluated per acknowledgement it is meaningless.
  Dozens of acknowledgements arrive inside one round trip, and between two of them
  microseconds apart a max-filtered estimate essentially never grows a quarter — it cannot,
  there is no new information between them. The three-strike counter therefore ran out
  inside the very first flight, and the connection left the one phase that grows its window
  exponentially before that window had doubled even once, carrying out whatever estimate
  the opening flight happened to produce. The same counter indexed the ProbeBW gain cycle
  `[1.25, 0.75, 1.0, 1.0]`, whose whole purpose is that the 1.25 phase asks the path for a
  quarter more than the current estimate and lasts long enough — one `min_rtt` — for the
  answer to come back and be measured. Advanced per acknowledgement it turned over ten
  times inside a single round trip in the regression test that now pins it, so the probe
  covered roughly one packet in four and never probed anything. Between the two, the
  estimate could not climb during Startup and could not climb after it.
  Round trips are now counted the way the BBR draft defines them
  (`BBRUpdateRound`), against the delivered-bytes counter rather than a timer: the sender
  records the current `delivered` when a round opens, and an acknowledgement for a packet
  whose delivered-at-send mark is at or beyond that value means every packet in flight when
  the round opened has been answered — one round trip. The mark was already threaded end to
  end for the delivery-rate fix (`Stream::poll_send` stamps it from the estimator's own
  snapshot, `RetiredSegment` carries it back), so this reads a field that was already
  correct. Counting in delivered bytes rather than wall clock is deliberate: it needs no
  RTT estimate to be right first, and it stays right across an idle application or a moving
  RTT.
  Two further deviations from the draft's `BBRCheckStartupFullBandwidth` are corrected
  while the rule is being rewritten, both of which also end Startup early. The growth
  comparison is now against BBR's `full_bw` plateau — a high-water mark raised only when a
  round beats it by the threshold — instead of against the immediately preceding round;
  measured round-to-round, a path growing a steady 20% per round reads as a plateau and the
  sender quits while the path is still opening up. And an application-limited round no
  longer counts as evidence that the pipe is full: its sample never reached the bandwidth
  filter in the first place, so its "growth" is flat by construction, and an idle moment
  could end Startup on its own.
  ProbeRTT was audited for the same confusion and does **not** have it: `PROBE_RTT_INTERVAL`
  and `PROBE_RTT_DURATION` are compared as wall-clock `Instant` differences, which is what
  the draft specifies for both, and they are left alone.
  **Sender-local congestion control only: no wire-format, handshake or key-schedule change,
  and old and new peers interoperate unchanged.**
- **A peer could set the local congestion window by reporting a false acknowledgement
  delay.** `Sack::ack_delay_us` is the receiver's own claim about how long it held an
  acknowledgement before sending it, and the sender subtracted it from the round trip it
  had measured before feeding the result to its minimum-RTT filter. Nothing bounded the
  claim. Because the consumer is a *minimum* filter — one that back-pops every entry at
  or above a new value — a single report did not merely sit at the head of the window,
  it discarded the accumulated honest history and restarted the expiry clock. A peer
  reporting 199.9 ms of delay on a 200 ms path drove the sample to 100 µs, and since
  `cwnd = 2 × btl_bw × min_rtt` the window then sat on its 5600-byte floor for as long
  as the peer kept reporting. The same collapse signature was measured in the field: a
  WAN transfer that peaked near a 128 KB window fell to exactly 5600 bytes and sustained
  4.7-7.6% of a link whose raw-socket control measured 6.63 Mbit/s at 0.0% loss.
  The `Sack` rides inside the AEAD plaintext, so this was never reachable by an on-path
  attacker — it required the authenticated peer. That is a smaller mitigation than it
  sounds: **a malicious or merely defective server could pin every client's congestion
  window to its floor for the life of the connection, and a client could do the same to
  a server.** A peer does not get to choose the other side's congestion window.
  The order is now the one RFC 9002 specifies. §5.2: an endpoint "uses only locally
  observed times in computing the min_rtt and does not adjust for acknowledgment delays
  reported by the peer", and "min_rtt MUST be set to the latest_rtt on the first RTT
  sample" — so the first round trip seeds the filter raw, rather than being measured
  against the 100 ms opening guess the estimator starts with. §5.3: "MUST NOT subtract
  the acknowledgment delay from the RTT sample if the resulting value is smaller than
  the min_rtt", i.e. subtract only when `latest_rtt >= min_rtt + ack_delay`. Every value
  entering the filter is therefore either a raw locally observed round trip or a value at
  or above the filter's current minimum, so a reported delay can no longer lower
  `min_rtt` below what the local clock saw; the worst a hostile report now achieves is
  declining to lower it further, which is what reporting nothing would achieve. The
  legitimate correction is retained — receivers really do batch acknowledgements, and a
  reported hold that fits inside the round trip is still subtracted. The reported value
  is additionally clamped to the observed round trip, since a peer cannot have held an
  acknowledgement longer than the whole trip took; that also stops a nonsense report from
  suppressing an honest measurement, which the previous saturating subtraction did by
  collapsing the sample to zero.
  **Sender-local accounting only: no wire-format, handshake or key-schedule change, the
  `Sack` encoding is untouched, and old and new peers interoperate unchanged.**
- **A saturating send in one direction starved the other, collapsing the download to
  roughly a tenth of what the same path carried when nothing was being uploaded.** The
  data pump admitted application writes from inside its `select!` loop by pushing them
  straight into the target stream's send buffer — a call that parks on the stream's
  backpressure semaphore until an acknowledgement frees a slot. Parking there parks the
  whole pump: the 10 ms heartbeat stops, the drain stops, the command channel stops
  being read, and, decisively, the receive side's `WINDOW_UPDATE` credit stops being
  emitted. The peer then exhausts its initial 64 KiB flow-control window and has nothing
  to refill it with. Measured over a ~200 ms WAN path, downstream during a bidirectional
  transfer: 0.07 Mbit/s on PhantomUDP and mimic-TLS and 0.32 Mbit/s over TCP, against
  0.84-1.07 Mbit/s for the same download with the upload idle — and identical byte
  counts on three different transports, because the cause was above all of them. Every
  leg also failed to hand its closing control frame to the session inside 60 seconds.
  An in-crate reproduction over a 200 ms simulated path pins it at 65,536 bytes in each
  direction — exactly one window, credit never issued once.
  Writes the send buffer refuses are now queued in the pump and re-offered as slots
  free, in FIFO order so byte ordering and the reliable FIN's position are unchanged.
  While that queue is non-empty the pump stops taking commands, which puts the
  backpressure where it belongs — on the application's own `send()` — instead of on the
  session's scheduler. The same admission path replaces the pre-handshake queue flush,
  which ran *before* the loop that transmits and before the receive task existed, so an
  application that wrote more than the buffer holds while still connecting stalled the
  session permanently with no acknowledgement able to reach it. One drain pass is also
  now bounded at 32 segments and re-arms the outbound notify, so a stream with a full
  congestion window can no longer hold the pump for most of a round trip while inbound
  credit waits; and a SACK that retires segments wakes the loop, since it has both
  freed congestion window and returned a buffer slot.
  **Scheduling only: no wire-format, handshake or key-schedule change, and congestion
  and flow control are untouched — new data is still bounded by `min(cwnd, window)` and
  retransmits still bypass both.**

- **An acknowledgement for a retransmitted segment poisoned the minimum-RTT filter,
  pinning the congestion window on its floor for the life of the connection.** A sender
  restamps a segment's send time when it resends it, so an acknowledgement for the
  *original* transmission — already on the wire when the copy went out — was measured
  from the copy and read as microseconds on a path whose real round trip is a fifth of a
  second. Nothing in an acknowledgement says which of the two transmissions it answers,
  which is why Karn's algorithm excludes these samples; the reliable stream's own SRTT
  estimator already did, but the bandwidth estimator fed every sample into its minimum
  filter unconditionally. A minimum is not averaged away like a mean: one bad sample
  evicted every honest measurement in the 10-second window and governed the
  bandwidth-delay product until it aged out — and on a lossy path the next retransmit
  renewed it, so it never did. Since `cwnd = 2 × btl_bw × min_rtt`, the window then sat
  on its 5600-byte floor. Measured over a ~200 ms WAN path: the window grew to a ~128 KB
  peak and collapsed back to exactly 5600 bytes, averaging 7.7 KB in flight where
  filling the pipe needs ~165 KB, and sustaining 4.7-7.6% of a link whose raw-socket
  control measured 6.63 Mbit/s at 0.0% loss.
  Karn's condition was already computed and already threaded to the call site, but only
  the observability RTT gauge consulted it; it is now carried on the delivery sample and
  gates the filter as well. The delivery-rate half of the sample is deliberately left
  ungated — send time, delivered counter and delivery timestamp are restamped together,
  so that rate still measures bytes delivered since the resend over the time since the
  resend, a short interval but an honest one.
  **Sender-local accounting only: no wire-format, handshake or key-schedule change, and
  old and new peers interoperate unchanged.**

- **BBR read a burst of acknowledgements as a whole window delivered inside one packet's
  round trip, overestimating the path by an order of magnitude.** The delivery-rate
  sample counted the bytes the connection delivered while a packet was in flight, but
  divided them only by that packet's own send-to-ack time. Acknowledgements do not
  arrive spread out the way data was sent — receivers batch them and one cumulative SACK
  retires everything it covers at once — so the last packet of a burst contributed the
  entire window's bytes against its own short flight time. Measured over a 200 ms WAN
  path: a peak estimate of 63.51 Mbit/s against a link demonstrating 6.63 Mbit/s of UDP
  echo at 0.0% loss, 9.6x the real ceiling; over TCP, 25.71 Mbit/s against 4.22. The
  window grew to ~128 KB on that estimate, overshot, took loss and collapsed, ending one
  upload in `fast_recovery` and sustaining 4.7-7.6% of the path.
  The sample interval is now bounded by the acknowledgement interval as well as the send
  interval (`max(send_elapsed, ack_elapsed)`, canonical BBR). Each outgoing segment is
  stamped with *when* the connection's delivered counter last advanced alongside the
  counter value it was already carrying, so both ends of the interval the sample
  measures are known and the numerator is no longer divided by a shorter span than it
  was accumulated over.
  **Sender-local accounting only: no wire-format, handshake or key-schedule change, and
  old and new peers interoperate unchanged.**

- **Congestion control could not open its window past the floor, capping a session at
  roughly `cwnd_floor / rtt` on any real path.** BBR's delivery-rate sample divided a
  single packet's size by that same packet's round-trip time, making every sample "one
  packet per round trip" by construction however much was actually in flight. The BDP
  then collapsed to one packet (`bytes/rtt × rtt ≡ bytes`), so the window sat on its
  5600-byte floor permanently. Measured over a 210 ms path: 0.19 Mbit/s sustained
  against a link demonstrating 6.7 Mbit/s of UDP echo at 0.3% loss — about 3% of
  capacity, identical across the UDP, TCP and mimic legs. The same window also made an
  8 KiB round trip cost ~3 RTT where the raw path needed one.
  The rate is now the bytes the connection delivered over the interval the packet
  spanned, per BBR: each outgoing segment is stamped with the connection's delivered
  counter and reports it back when acknowledged (`DeliverySample::delivered_bytes`,
  previously present but hardcoded to `0`).
  Loopback could not surface this — with an RTT near zero the same floor still yields
  >100 Mbit/s, which is why every existing test passed.
  **Sender-local accounting only: no wire-format, handshake or key-schedule change, and
  old and new peers interoperate unchanged.**

- **ProbeRTT timed a path it had not emptied, so the min-RTT filter could only ever
  ratchet upward.** Entering ProbeRTT cuts the congestion window to four packets; it does
  not retire the bytes already sitting in the bottleneck's queue, and until those have
  been served every round trip the sender times still includes them. The window was
  clocked from entry for a flat 200 ms, which on a converged flow is not enough time for
  the queue to drain — at 600 KB/s a 240 KB backlog needs 400 ms of bottleneck service
  before a single packet crosses an empty path. Because the filter is a ten-second
  *minimum*, an unrefreshed one takes the smallest inflated sample available, so `min_rtt`
  climbs to `prop + 2 × min_rtt_old`, `bdp = btl_bw × min_rtt` climbs with it, `cwnd`
  with that, and the queue grows again. ProbeRTT now waits for `inflight` to fall to the
  ProbeRTT window and holds `max(200 ms, one round trip)` from *that* instant, bounded by
  a ceiling of two round trips of drain allowance plus the hold — retransmissions bypass
  the congestion window, so a path losing enough to keep the sender resending must not be
  able to pin it at the 5600-byte floor. Both the hold and the ceiling are derived from
  the round trip as it stood at entry, so a successful probe lowering `min_rtt` cannot
  shrink the ceiling out from under the hold it bounds.

- **Unreliable datagrams were counted as congestion-controlled inflight.** `send_unreliable`
  data went out through the same accounting as reliable data, but nothing acknowledges an
  unreliable datagram, so no arrival ever subtracted it. The debt was permanent: it shrank
  `cwnd − inflight` for the reliable data behind it for the rest of the session, and past
  5600 bytes it also put ProbeRTT's drain condition permanently out of reach. Only
  segments the ARQ tracks are booked now.

- **The bandwidth filter never learned anything from a sender whose writes are smaller
  than a congestion window.** Request/response is the shape of most traffic and of the
  reference server's own handler, and every such write empties the send buffer, so every
  round is application-limited. Such a round's delivery rate may not *set* the filter's
  maximum — it measures the application, not the path — but a sample at or above the
  current maximum is still a valid lower bound on capacity, and admitting it is the only
  way such a flow measures anything at all. Without that escape (canonical BBR's
  `!rs->is_app_limited || bw >= bbr_max_bw(sk)`) `btl_bw` stayed at zero, `bdp` with it,
  and the window sat on its `4 × MIN_PACKET_SIZE` floor — about 25 KB/s on a 226 ms path,
  for a flow whose problem was never congestion.
- **Connection migration could hang the client receive loop.** `UdpClientTransport::recv_bytes`
  did not wake when `migrate_to()` rebound the local socket: a receive parked on the old
  socket (which goes silent once the server follows the client) would block forever. Both
  the single-socket and the dual-socket migration-overlap receive paths now wake on a
  migration and re-snapshot the active/previous sockets, also closing a loop-top torn-read
  race (a migration interleaved between the two socket loads) and a hang on a second
  migration during an overlap. Regression-tested (each guard verified to fail without the
  fix).
- **C ABI declaration for `PhantomListener::shutdown` was wrong.** The hand-curated C
  header declared the synchronous `shutdown()` as an async future handle
  (`uint64_t ...(void *ptr)`); it is now correctly `void ...(void *ptr, RustCallStatus *)`,
  matching the actual ABI and the other bindings.
- **Per-stream receive was lossy and could deliver EOF before data.** Inbound data on
  an opened stream (id ≥ 2) was double-delivered — once losslessly to `session.recv()`
  and once via a best-effort `try_send` that **dropped** on a full/unknown channel — so
  `PhantomStream::recv()` lost bytes under load. Opened-stream delivery is now lossless
  and backpressured via a dedicated delivery task that never blocks the raw-app path, and
  a reliable in-order FIN (carried over the ARQ path, retransmitted until SACKed) now
  surfaces clean EOF strictly **after** all data — so a FIN arriving over a gap on a
  lossy/reordering path no longer truncates the stream. (Two bugs in this area were caught
  in review: a DashMap shard guard held across an `await` that could stall
  `open_stream()` / the pump, and the premature-EOF ordering — both fixed and
  regression-tested.)
- **Inert legacy `connect()` now reports `Failed`** instead of an eternal `Connecting`
  shell, so misuse is observable via `connection_state()` (use `connect_pinned` /
  `connect_pinned_udp`).
- **Dropping the last `PhantomSession` handle now closes the session** (sends an in-order
  `Close` so the peer sees EOF), fixing a regression where extra internal command
  senders kept the pump alive after the handle was dropped.
- **Release tarballs contained no library.** The packaging step copied from
  `core/target/<triple>/release/` — a path that does not exist, since `core` is the only
  workspace member and cargo's target directory is the repository root — and the copy was
  guarded by `2>/dev/null || true`, so every published `0.1.0`–`0.2.2` artifact silently
  shipped `LICENSE` + `README.md` only. The path is corrected, the `cdylib` (the actual
  FFI delivery vehicle) is shipped alongside the `rlib`, and a missing library now fails
  the job loudly instead of producing an empty tarball.
- **The Helm chart ignored the mounted signing-key Secret**, so every pod minted a fresh
  identity on restart and broke client key pinning. The chart published `PHANTOM_BIND_PORT`
  and `PHANTOM_SIGNING_KEY_PATH`, neither of which `phantom-server` reads, and the
  Deployment never set `PHANTOM_SIGNING_KEY_FILE` at all. It now emits `PHANTOM_BIND`
  (a full `SocketAddr`) and `PHANTOM_SIGNING_KEY_FILE` pointing at the mounted key. The
  sample manifest in `docs/operations/kubernetes.md` had the same defect.
- **`--otel-trace-sample-ratio` was parsed and then discarded** (`let _ = cfg.trace_sample_ratio;`),
  so no sampler was ever installed and the effective trace rate was 100% regardless of the
  flag. The ratio is now applied as `Sampler::ParentBased(TraceIdRatioBased(ratio))`, which
  also makes it effective from the `OTEL_TRACES_SAMPLER_ARG` env form without additionally
  setting `OTEL_TRACES_SAMPLER`. The default changed `0.01` → `1.0` so shipped behaviour is
  unchanged — lower it deliberately.
- **`core/examples/embedded_demo.rs` did not compile** under `--features embedded`: the
  `embedded-io-async` 0.6 → 0.7 bump made `Write::flush` a required method and the example's
  `MockWriter` never gained one (`E0046`). It went unnoticed because the `embedded-feature`
  CI job runs `cargo test --lib`, and `--lib` never builds examples; the job now checks them.
- **The iOS static-library flow could not work.** `build-xcframework.sh` and the by-hand
  `lipo` recipes feed `libphantom_protocol.a` to `xcodebuild -create-xcframework`, but
  `[lib] crate-type = ["lib", "cdylib"]` never emits a static archive. The slices are now
  built with `cargo rustc --crate-type staticlib`. (Adding `staticlib` to the manifest is
  *not* a valid fix: a staticlib is a final artifact, so it makes cargo demand a
  `#[panic_handler]` and a `#[global_allocator]` from the library and breaks the
  `thumbv7em-none-eabihf` bare-metal build.)
- **Several hand-curated C ABI declarations were wrong**, so a C consumer following the
  header got undefined behaviour rather than a compile error: `open_stream` was declared
  async although it is synchronous, `flush_queue` was declared to complete to `void`
  although it yields `u32`, a `_pointer` future poll/complete family was documented that
  does not exist in the cdylib (objects complete through `_u64`), and the `ConnectionState`
  discriminant comment named five states that do not exist. The maximum-datagram macro
  advertised 65507 bytes where PhantomUDP's path MTU is 1200, and a comment still described
  the replay window as per-stream.
- **`phantom_helpers.h`'s blocking wrappers could not work.** `Vec<u8>` arguments were
  passed as raw bytes although UniFFI lowers them as a RustBuffer of
  `[i32 big-endian length][payload]` (only a top-level `String` is raw UTF-8), so
  `phantom_blocking_connect_pinned` failed unconditionally with `RustCallStatus.code == 2`;
  and the helpers passed the caller's handle straight to the scaffolding, but a UniFFI
  method **consumes** its receiver — every generated binding clones per call — so the second
  call on a session was a use-after-free. Both are fixed with explicit lowering and
  clone-per-call helpers.
- **`phantom_protocol.h` was unusable from C++** even though it guards its declarations
  with `extern "C"`: `PhantomRustBuffer` was defined *inside* `PhantomRustCallStatus`, which
  C gives file scope but C++ scopes to the enclosing class, leaving the type incomplete for
  every C++ translation unit. Hoisted; layout and ABI unchanged.
- **`check_versions.sh` did not cover `python/pyproject.toml`**, the maturin manifest that
  `PACKAGING.md` designates as the recommended PyPI path and which carries its own hardcoded
  version — so it could drift from `core/Cargo.toml` undetected. Six manifests are now
  drift-checked, not five.
- **`.github/CODEOWNERS` had drifted from `CONTRIBUTING.md`'s touch-with-care set**: it still
  routed the deleted `transport/legs/faketls.rs` (matching nothing, so the rule was inert)
  and omitted `transport/udp_transport.rs` and `transport/legs/mimic_tls/`, which therefore
  never requested codeowner review.
- **The panic-site inventory had drifted from the code it inventories.**
  `docs/security/panic-sites.md` claimed nineteen rows against twenty marked sites, and not
  one of its `stream.rs` line numbers still pointed at the code it described — a document
  whose addresses do not resolve turns the security review it exists to support into a
  formality. Four production panics carried no `// PANIC-SAFETY:` comment at all
  (`WasiLeg::recv_bytes`, `WasiRuntime::{spawn, tasks_pending}` and the three `setTimeout`
  calls in `WasmRuntime::sleep`, the last in a module the native clippy job never compiles,
  so nothing had ever required one). The table is rebuilt from the source, rows are keyed on
  file and enclosing function instead of a line number, and `scripts/check_panic_sites.py`
  now re-derives the inventory and fails when the two disagree — as a `pre-commit` hook and
  as the `panic-sites` CI job. No behaviour changed; the four new comments are comments.


- **Connection migration could hang the client receive loop.** `UdpClientTransport::recv_bytes`
  did not wake when `migrate_to()` rebound the local socket: a receive parked on the old
  socket (which goes silent once the server follows the client) would block forever. Both
  the single-socket and the dual-socket migration-overlap receive paths now wake on a
  migration and re-snapshot the active/previous sockets, also closing a loop-top torn-read
  race (a migration interleaved between the two socket loads) and a hang on a second
  migration during an overlap. Regression-tested (each guard verified to fail without the
  fix).
- **C ABI declaration for `PhantomListener::shutdown` was wrong.** The hand-curated C
  header declared the synchronous `shutdown()` as an async future handle
  (`uint64_t ...(void *ptr)`); it is now correctly `void ...(void *ptr, RustCallStatus *)`,
  matching the actual ABI and the other bindings.
- **Per-stream receive was lossy and could deliver EOF before data.** Inbound data on
  an opened stream (id ≥ 2) was double-delivered — once losslessly to `session.recv()`
  and once via a best-effort `try_send` that **dropped** on a full/unknown channel — so
  `PhantomStream::recv()` lost bytes under load. Opened-stream delivery is now lossless
  and backpressured via a dedicated delivery task that never blocks the raw-app path, and
  a reliable in-order FIN (carried over the ARQ path, retransmitted until SACKed) now
  surfaces clean EOF strictly **after** all data — so a FIN arriving over a gap on a
  lossy/reordering path no longer truncates the stream. (Two bugs in this area were caught
  in review: a DashMap shard guard held across an `await` that could stall
  `open_stream()` / the pump, and the premature-EOF ordering — both fixed and
  regression-tested.)
- **Inert legacy `connect()` now reports `Failed`** instead of an eternal `Connecting`
  shell, so misuse is observable via `connection_state()` (use `connect_pinned` /
  `connect_pinned_udp`).
- **Dropping the last `PhantomSession` handle now closes the session** (sends an in-order
  `Close` so the peer sees EOF), fixing a regression where extra internal command
  senders kept the pump alive after the handle was dropped.
- **Release tarballs contained no library.** The packaging step copied from
  `core/target/<triple>/release/` — a path that does not exist, since `core` is the only
  workspace member and cargo's target directory is the repository root — and the copy was
  guarded by `2>/dev/null || true`, so every published `0.1.0`–`0.2.2` artifact silently
  shipped `LICENSE` + `README.md` only. The path is corrected, the `cdylib` (the actual
  FFI delivery vehicle) is shipped alongside the `rlib`, and a missing library now fails
  the job loudly instead of producing an empty tarball.
- **The Helm chart ignored the mounted signing-key Secret**, so every pod minted a fresh
  identity on restart and broke client key pinning. The chart published `PHANTOM_BIND_PORT`
  and `PHANTOM_SIGNING_KEY_PATH`, neither of which `phantom-server` reads, and the
  Deployment never set `PHANTOM_SIGNING_KEY_FILE` at all. It now emits `PHANTOM_BIND`
  (a full `SocketAddr`) and `PHANTOM_SIGNING_KEY_FILE` pointing at the mounted key. The
  sample manifest in `docs/operations/kubernetes.md` had the same defect.
- **`--otel-trace-sample-ratio` was parsed and then discarded** (`let _ = cfg.trace_sample_ratio;`),
  so no sampler was ever installed and the effective trace rate was 100% regardless of the
  flag. The ratio is now applied as `Sampler::ParentBased(TraceIdRatioBased(ratio))`, which
  also makes it effective from the `OTEL_TRACES_SAMPLER_ARG` env form without additionally
  setting `OTEL_TRACES_SAMPLER`. The default changed `0.01` → `1.0` so shipped behaviour is
  unchanged — lower it deliberately.
- **`core/examples/embedded_demo.rs` did not compile** under `--features embedded`: the
  `embedded-io-async` 0.6 → 0.7 bump made `Write::flush` a required method and the example's
  `MockWriter` never gained one (`E0046`). It went unnoticed because the `embedded-feature`
  CI job runs `cargo test --lib`, and `--lib` never builds examples; the job now checks them.
- **The iOS static-library flow could not work.** `build-xcframework.sh` and the by-hand
  `lipo` recipes feed `libphantom_protocol.a` to `xcodebuild -create-xcframework`, but
  `[lib] crate-type = ["lib", "cdylib"]` never emits a static archive. The slices are now
  built with `cargo rustc --crate-type staticlib`. (Adding `staticlib` to the manifest is
  *not* a valid fix: a staticlib is a final artifact, so it makes cargo demand a
  `#[panic_handler]` and a `#[global_allocator]` from the library and breaks the
  `thumbv7em-none-eabihf` bare-metal build.)
- **Several hand-curated C ABI declarations were wrong**, so a C consumer following the
  header got undefined behaviour rather than a compile error: `open_stream` was declared
  async although it is synchronous, `flush_queue` was declared to complete to `void`
  although it yields `u32`, a `_pointer` future poll/complete family was documented that
  does not exist in the cdylib (objects complete through `_u64`), and the `ConnectionState`
  discriminant comment named five states that do not exist. The maximum-datagram macro
  advertised 65507 bytes where PhantomUDP's path MTU is 1200, and a comment still described
  the replay window as per-stream.
- **`phantom_helpers.h`'s blocking wrappers could not work.** `Vec<u8>` arguments were
  passed as raw bytes although UniFFI lowers them as a RustBuffer of
  `[i32 big-endian length][payload]` (only a top-level `String` is raw UTF-8), so
  `phantom_blocking_connect_pinned` failed unconditionally with `RustCallStatus.code == 2`;
  and the helpers passed the caller's handle straight to the scaffolding, but a UniFFI
  method **consumes** its receiver — every generated binding clones per call — so the second
  call on a session was a use-after-free. Both are fixed with explicit lowering and
  clone-per-call helpers.
- **`phantom_protocol.h` was unusable from C++** even though it guards its declarations
  with `extern "C"`: `PhantomRustBuffer` was defined *inside* `PhantomRustCallStatus`, which
  C gives file scope but C++ scopes to the enclosing class, leaving the type incomplete for
  every C++ translation unit. Hoisted; layout and ABI unchanged.
- **`check_versions.sh` did not cover `python/pyproject.toml`**, the maturin manifest that
  `PACKAGING.md` designates as the recommended PyPI path and which carries its own hardcoded
  version — so it could drift from `core/Cargo.toml` undetected. Six manifests are now
  drift-checked, not five.
- **`.github/CODEOWNERS` had drifted from `CONTRIBUTING.md`'s touch-with-care set**: it still
  routed the deleted `transport/legs/faketls.rs` (matching nothing, so the rule was inert)
  and omitted `transport/udp_transport.rs` and `transport/legs/mimic_tls/`, which therefore
  never requested codeowner review.

### Documented

- **`connect_pinned*` returns before the handshake completes.** The returned session is
  in `Connecting` state with the handshake running on a background task, so callers must
  `await_ready()` before treating the connection as established. Until they do, a
  deliberately wrong pin looks like a successful connect (`ServerIdentityMismatch` has
  not been raised yet), `resumption_hint()` returns `None`, and any timing around the
  call measures socket setup rather than the post-quantum key exchange. This was
  implied by the invariants but stated nowhere on the entry points themselves.
- **`PhantomSession::send()` does not preserve application message boundaries.** The
  data pump splits payloads above its internal chunk size (1156 B) into chunks,
  writes each as a separate reliable-stream write, and the peer's `recv()` yields them
  one at a time — on every leg, since the split happens above the transport. The
  failure mode is silent for structured payloads: the first chunk still parses, with
  the tail gone. Embedders that need message semantics must frame and reassemble
  themselves; `testbed/src/framing.rs` is a worked example.
- **`migrate()` on a non-migration transport now returns `Err(CoreError::Unsupported)`**
  instead of a silent `Ok(())` no-op. Real migration requires a UDP-backed session
  (`connect_pinned_udp*`); on TCP / WebSocket / WASI / Embedded it now errors honestly.
- **Combinatorial Rust constructors were removed** in favour of the builder:
  `PhantomSession::connect_with_resumption`,
  `PhantomListener::bind_with_signing_key_with_runtime`, and
  `PhantomListener::bind_with_signing_key_mimic`. The runtime-injection shims
  `PhantomSession::connect_with_transport_with_runtime` and
  `PhantomListener::bind_with_runtime` survive, as do `connect_with_transport` and the
  UniFFI-exported free functions and constructors. `PhantomStream::recv()` returns
  `Option<Vec<u8>>` (`None` = clean EOF). All breaking, within the pre-1.0 0.2.x window.
- **`PhantomUdpListener::accept()` now takes an owned receiver** (`self: Arc<Self>`
  instead of `self: &Arc<Self>`) — required by its new UniFFI export. Rust callers
  write `listener.clone().accept().await`. Breaking, within the pre-1.0 0.2.x window.
- **`ConnectionState::{ClassicalReady, PqcUpgrading, PqcReady}` and
  `PhantomSession::is_pqc_ready()` were removed.** They belonged to a staged
  classical-then-post-quantum upgrade the protocol never shipped: the hybrid handshake is a
  single flight, so no production path ever wrote those three states and `is_pqc_ready()`
  was permanently false. An embedder following the rustdoc would have waited for a state
  that cannot arrive, or gated its send path on a readiness flag that never turns true.
  The session rustdoc now describes the machine that exists —
  `Connecting → Connected → Migrating → Dead`, plus `Failed` and `Closed`. Use
  `is_data_ready()`: because the handshake is one flight, a data-ready session is
  post-quantum protected by construction. Discriminants `1..=3` are left retired rather
  than reused. Breaking for the FFI enum and for `is_pqc_ready()` callers, within the
  pre-1.0 breaking window.
- **`PhantomSession::current_epoch()` and `set_rekey_threshold()` are no longer exported
  over FFI.** Both documented themselves as Rust-only while sitting inside the UniFFI
  export block. `set_rekey_threshold` lowers the watermark that triggers key rotation on a
  live session — a knob on the same axis as the `AEAD_MAX_INVOCATIONS` ceiling, which is
  documented as not to be moved without an audit — so it should not have reached foreign
  callers by accident. Both remain public Rust API for soak and integration harnesses.
  Breaking for any binding consumer that called them.


## [0.2.2] - 2026-06-22

Documentation release. **No code, wire-format, public-API, or dependency changes** —
binary- and wire-compatible with 0.2.x (`WIRE_VERSION = 6`, `PROTOCOL_VERSION = 3`).

### Added

- **docs.rs now documents the opt-in feature surfaces.** A `[package.metadata.docs.rs]`
  table builds the `telemetry-otel` (OpenTelemetry), `mimicry`, and `embedded` features
  and enables `doc_cfg`, so every feature-gated item carries an "Available on crate
  feature `X`" badge. Previously docs.rs built default-features-only, which hid the
  OpenTelemetry / mimicry / embedded APIs from the rendered documentation entirely.
  (`all-features` is intentionally not used — `fips` + `no-std` are mutually exclusive.)

### Fixed

- **Crate-wide comment accuracy + clarity pass (~60 source files).** Corrected
  doc-comments and inline comments that no longer matched the code, including: stale
  wire-format descriptions (the 47-byte → 15-byte `PacketHeader`, the v4 `[33..47]`
  header-protection span → v6 whole-header masking, the off-wire `session_id`); the
  REKEY-flag key derivation (wrongly described as the resumption-secret chain → the
  traffic-secret `HKDF-Expand(current, "phantom-rekey-v1", 32)` chain, Invariant 5);
  transports removed long ago but still described as live (the KCP / FakeTLS legs, the
  multipath `TransportLeg` trait); the `ServerReply` kind dispatch (trial-deserialization
  → explicit discriminant byte); the AEAD nonce construction (stale per-stream
  `(epoch, stream_id, sequence)` → `nonce_prefix(4) ‖ packet_number(8)`); the auto-rekey
  watermark (`2^47` → `2^32`); the proof-of-work cookie (HMAC → keyed BLAKE3, 60 s →
  120 s validity); and a nonexistent "sits below MLS" architectural claim. Also
  translated stray non-English comments to English and removed duplicated doc blocks.
- **Warning-clean docs.rs build.** Fixed 7 broken intra-doc links exposed by documenting
  the previously-undocumented `mimicry` / `embedded` modules.

## [0.2.1] - 2026-06-21

Documentation/metadata patch release. **No code, wire-format, public-API, or
dependency changes** — binary- and wire-compatible with 0.2.0
(`WIRE_VERSION = 6`, `PROTOCOL_VERSION = 3`).

### Fixed

- **Stale version references in the published README and deployment docs.** 0.2.0 was
  published immediately before the version-reference refresh merged, so the README
  rendered on crates.io / docs.rs still read `Pre-1.0 (0.1.1)` and advised
  `phantom-protocol = "0.1"`. 0.2.1 re-publishes the corrected README and bumps the
  remaining current-version references — the README pre-1.0 banner, Docker image tags,
  Helm `appVersion` + chart version, the observability `service.version` example, the
  C/Python binding packaging manifests, and the CLI version banner — to `0.2.1`.

## [0.2.0] - 2026-06-20

### Added

- **TLS-over-TCP active mimicry transport (`mimicry` cargo feature, off by default).** A new
  `MimicTlsLeg` makes a Phantom flow look like ordinary HTTPS to an on-path observer: the client
  (`connect_pinned_mimic`) and server (`PhantomListener::bind_mimic`) perform a *synthetic* TLS 1.3
  handshake (a Chrome-shaped ClientHello with realistic JA3/JA4 + a per-connection ServerHello
  synthesized to be self-consistent with it, ChangeCipherSpec, opaque flight + lifecycle records),
  then carry the existing Phantom session inside TLS ApplicationData records. **No `WIRE_VERSION`
  change** — it is outer, leg-local framing; the inner packet wire is untouched.
  - **The outer TLS is anti-DPI obfuscation ONLY and is detectable by active probing.** The handshake
    is cryptographic theater (no real ECDHE, no certificate) and holds no keys — all auth / conf /
    integrity remain the inner Phantom post-quantum session; the records are framing-only (no second
    AEAD, since the inner ciphertext is already indistinguishable from random). It **defeats parsers,
    not provers**: SAFE against stateless DPI + passive JA3/JA4 fingerprinting + light stateful
    inspection, but net-negative against a censor that completes a real TLS handshake / validates a
    cert. The server uses a constant-timing black-hole for garbage/probe preludes. Native-only,
    Rust-only entry points. Honest residuals + SAFE/UNSAFE deployment guidance in
    `docs/security/threat-model.md` §6.1; wire shape in `docs/protocol/PROTOCOL.md` §9.1.

- **Mobile sample apps (`examples/mobile/`).** Two runnable client samples embedding the SDK via
  its UniFFI bindings: an iOS SwiftUI app (`examples/mobile/ios/`, SwiftPM) and an Android Jetpack
  Compose app (`examples/mobile/android/`, Gradle). Both demonstrate pinned connect, 0-RTT
  resumption with platform secure-storage of the `ResumptionHint` (iOS Keychain / Android
  `EncryptedSharedPreferences`), encrypted send/recv, lock-free `connectionState()` surfacing
  (incl. `Migrating`/`Dead`), and reconnect-with-0-RTT on a network change. They are **complete,
  reviewed source but not built in CI** (no Xcode / Android SDK / NDK / server in CI) — each app's
  `README.md` documents the local build+run steps. Honest about migration: `migrate()` is a no-op
  over the TCP transport the FFI exposes (real path migration lives on the not-yet-FFI-exposed UDP
  transport), so the working recovery pattern is reconnect-with-0-RTT. The canonical
  `docs/operations/mobile.md` migration note was corrected to match.

- **0-RTT anti-replay controls for scaled deployments (A2b).** 0-RTT early-data is
  replay-safe out of the box on a single node (one-shot ticket consumption, Invariant 9),
  but a horizontally-scaled fleet with per-node caches could otherwise let a captured 0-RTT
  `ClientHello` be replayed to a different node. Two new controls close this:
  - **`ZeroRttAntiReplay` trait** + `PhantomListener::set_zero_rtt_anti_replay` /
    `PhantomUdpListener::set_zero_rtt_anti_replay` (Rust-only): install a store shared by all
    nodes whose atomic `check_and_set` makes the one-shot consume first-use **globally** (e.g.
    Redis `SET NX`, a conditional DB write — the *store* is the embedder's infrastructure; the
    transport ships only the seam, failing closed). Replay-safe 0-RTT at scale.
  - **`set_early_data_enabled(false)`** on either listener: disable 0-RTT early-data entirely
    (resumption still bypasses the cookie/PoW gate, but early-data is rejected and resent
    1-RTT) — a one-line, zero-infrastructure defence, the recommended default for any multi-node
    deployment that has not installed a distributed store.

  Loud deploy guide at `docs/operations/zero-rtt.md`; threat-model updated (the scale-out
  replay row is now *mitigable* rather than a residual). No wire-format change.

- **Server-side connection migration (A2a) — real, bidirectional, unlinkable.** An
  accepted server session can now move its network path mid-session without a
  re-handshake via the new **Rust-only** `PhantomSession::migrate_server(local_addr)`
  (deliberately not on the UniFFI/FFI surface — server migration is a native-deployment
  operation: failover, multi-homing, egress-NAT rebind). It rebinds the server's send
  socket and rotates the server→client `path_id` + connection-ID in lock-step; the peer
  follows the new s2c source automatically and, when the old server address is
  unreachable, switches its own send target to the new one (path-validated failover).
  To make this work:
  - the UDP **client socket is now unconnected** (`send_to` a tracked server address,
    `recv_from` any source) instead of kernel-`connect`ed, so it can hear — and follow —
    a server that moves to a new address; the inner AEAD + replay window remain the
    authenticity guards;
  - the client mirrors the server's migration machinery (commit the new server source
    only post-AEAD per M-1, path-validate it under a 3× anti-amplification cap, switch
    its c2s target only on a valid `PATH_RESPONSE`), so the worst case for a spoofed /
    replayed frame is a bounded reflection, never a c2s redirection;
  - CID rotation is now **symmetric for migration by either peer (EPS-02 closed)**: on a
    server migration the client reflects — it bumps its `path_id` and rotates its c2s
    chain, which slides the server's c2s demux window so the rotated CID stays routable
    (no stranding) with no ping-pong (the server's s2c re-rotation is `path_id`-silent).
    So a client move **and** a server failover are both unlinkable in both directions to
    a both-networks observer (the not-forward-secret CID-chain caveat is unchanged).

  No wire-format change (a behavioural extension on WIRE v6 — `path_id`, the rotating
  CID, and `PATH_VALIDATION` are all already on the wire).

- **Blocking C helpers for the FFI (`tests/bindings/c/phantom_helpers.h`).**
  A header-only, pure-C convenience layer that wraps the async future-poll
  boilerplate (`connect_pinned` / `send` / `recv` / `disconnect`) into plain
  blocking calls — `phantom_blocking_connect_pinned` / `_send` / `_recv` /
  `_disconnect` — so a synchronous C consumer no longer hand-rolls a poll loop.
  No new Rust code or `unsafe` (it sits on the existing `extern "C"` ABI); the
  wait is a 1 ms `nanosleep` on a C11 `_Atomic` flag (no `-lpthread`). Also
  corrected the C header's stale `_pointer` future declarations to the real `_u64`
  object-future ABI (UniFFI 0.31 represents objects as `u64` handles). The C
  consumer smoke test now exercises the blocking path end-to-end.

- **Traffic-shaping can be configured before the session establishes.**
  `PhantomSession::set_traffic_shaping` may now be called **before** the (async)
  client handshake completes: the config is stored as pending and applied to the
  negotiated session the moment the background task installs it, so the **first
  data packets are already shaped** (no "warm up, then configure" gap). It always
  returns `true` (accepted) — previously it returned `false` while still
  connecting and did nothing. New `PhantomSession::traffic_shaping() ->
  Option<TrafficShapingConfig>` getter reads back the applied config (`None` while
  connecting). Both FFI-exported; bindings regenerated.

- **Anti-fingerprint cover (dummy) traffic (WIRE v6, shaping control (e)).**
  Opt-in, additive (no wire change). When enabled, an otherwise-idle session
  maintains a minimum outbound packet rate (`1000 / cover_interval_ms` packets/sec)
  by emitting an `ENCRYPTED | COVER` dummy packet — empty inner plaintext, PADÉ-padded
  to a bucket — whenever no packet has gone out for `cover_interval_ms`, so silence
  and volume no longer leak. A cover packet AEAD-authenticates like any packet (so
  it refreshes the peer's liveness and cannot be off-path injected) and the receiver
  **drops** it before the data path — it never reaches `recv()`. New
  `PacketFlags::COVER` (0x4000, masked) + `cover_interval_ms` field on
  `TrafficShapingConfig` (FFI-exported; `0` = off, the default). The cover timer
  reuses the send packet-number counter as a lock-free "did we send anything?"
  signal, so cover only fills genuine idle gaps. Bindings regenerated. (This
  completes the WIRE v6 shaping suite: (a) masked version + (b) length-prefix
  diet + (c) PADÉ padding + (d) timing jitter + (e) cover traffic.)

- **Anti-fingerprint send-timing jitter (WIRE v6, shaping control (d)).**
  Opt-in, additive (no wire change). When enabled, the send path waits a uniform
  random `[0, jitter_ms]` ms before each packet, so the inter-packet timing no
  longer tracks the application's write pattern — at a cost of up to `jitter_ms` of
  added latency per packet. Configured via the new `jitter_ms` field on
  `TrafficShapingConfig` (FFI-exported; `0` = off, the default). Applied in
  `pace_send` ahead of (and independently of) the wire-rate pacer; jitter only
  delays, never reorders or drops. Bindings regenerated. (Cover traffic (e) is the
  next phase.)

- **Anti-fingerprint wire diet + opt-in size padding (WIRE v6).**
  **BREAKING wire change (`WIRE_VERSION` 5 → 6).** Removes the last two structural
  data-plane fingerprints and adds opt-in size hiding:
  - **(a) Masked version byte.** Header protection now covers the WHOLE 15-byte
    header (`HP_PROTECTED_OFFSET` 1 → 0), so the `version` byte is HP-masked too —
    the data-plane wire has **no constant cleartext byte** to fingerprint. The recv
    path recovers + checks the version after unmask; the AAD image is unchanged.
  - **(b) Dropped length prefixes.** The two cleartext `u32` prefixes
    (`payload_len` / `ext_len`) are gone — `payload` is the message remainder
    (`SessionTransport::recv_bytes` is message-framed on every transport, so they
    were pure redundancy and a verifiable invariant), and `extensions` leave the
    data-plane wire (always empty; the AEAD AAD still binds an empty slice). −8
    bytes/packet.
  - **(c) Opt-in PADÉ size padding.** A new `PacketFlags::PADDED` (0x2000, masked)
    + an encrypted plaintext trailer (`‹zeros› ‖ pad_n:u16be`, stripped after
    decrypt) pad each packet up to a **PADÉ** bucket (bounded ≈ ≤12% worst-case
    overhead) so the datagram size no longer tracks the payload size. **Off by
    default**; enabled per session via the FFI-exported
    `PhantomSession::set_traffic_shaping(TrafficShapingConfig { padding: Padme })`
    (new `TrafficShapingConfig` record + `PaddingPolicy` enum on the UniFFI
    surface). Padding lives inside the AEAD (authenticated, invisible); only the
    bucketed datagram size is observable. Paced but does not inflate the congestion
    window.

    Regenerated the four packet wire-vector fixtures + the independent python
    decoder + all UniFFI bindings; updated `docs/protocol/PROTOCOL.md` (§4.1/§4.2/
    §4.3/§4.6 + new §4.8). Removed a dead, never-wired "adaptive padding" scaffold
    from `transport/framing.rs`. Timing jitter (d) and cover traffic (e) are
    separate later phases. No crypto/auth change; invariants preserved.

- **Idle keep-alive PINGs — download-only liveness (Phase 4):** a purely-passive,
  **download-only** path (the receiver sends only ACKs, so nothing is in flight) can now detect a
  silently-dead downstream. An otherwise-idle `Connected` session emits a small `ENCRYPTED | KEEPALIVE`
  packet (empty payload) once per `keepalive_interval` (default 15 s; `None` disables it); the peer answers
  with a `KEEPALIVE | ACK` PONG. The unanswered PING is an outstanding probe the liveness sweep folds into
  its in-flight gate, so a dead download-only path surfaces `Migrating → Dead` exactly like an active one,
  and the PONG refreshes the peer's activity timer symmetrically. A PING fires only when the path is
  genuinely idle (Connected, nothing in flight, inbound silent ≥ interval, ≤ one per interval), so steady
  traffic pays nothing; both PING and PONG are AEAD-sealed and carry no application bytes (never reach
  `recv()`). `KEEPALIVE` is a spare `PacketFlags` bit (`0x1000`) — **no header layout or wire-version
  change**. The keep-alive interval is configurable via `LivenessConfig::keepalive_interval`.
- **Liveness — autonomous dead-path detection (Phase 4 / P4.3):** the SDK now notices a **silently-dead
  path** on its own — no inbound for N×PTO while reliable data is outstanding — and surfaces
  `ConnectionState::Migrating` so the embedder can `migrate()`; the session is held alive (keys retained,
  outbound buffered + retransmitted) rather than torn down. With no recovery (a `migrate()`, or the path's
  return) before a migration-idle timeout it transitions to the terminal `ConnectionState::Dead` and
  `recv()` errors instead of hanging. Detection is read-only over existing signals (BBR in-flight + an
  inbound-activity timer) and runs on both peers via the shared data pump, so a server detects a vanished
  client symmetrically. Two new `ConnectionState` variants (`Migrating`, `Dead`) → bindings regenerated.
  Thresholds (default ~1s-to-down / 30s-to-dead) are overridable; **no wire change**. A purely-passive
  (download-only) path is kept detectable by the idle keep-alive PINGs above.
- **Seamless connection migration (Phase 4 / P4.1–P4.2):** a live PhantomUDP session now survives a
  client network change (Wi-Fi↔cellular, NAT rebind) **without re-running the post-quantum handshake** —
  the connection loses throughput briefly, never liveness. The embedder triggers it via the new
  `PhantomSession::migrate(local_addr)` (FFI-exported, best-effort, non-blocking): the client rebinds its
  UDP socket (keeping the old one for the overlap — broken-rebind safety) and stamps a fresh client-owned
  `path_id`; the server detects the new source, validates it with a `PATH_CHALLENGE` (anti-amplification-
  capped, RFC 9000 §8.2), then atomically switches its peer and resets the RTT / congestion estimators for
  the new network (QUIC §9.4). Keys and the session id persist; the reliable byte stream resumes
  byte-exact. No wire-format change — `path_id` already rode the 47-byte header and left the AEAD nonce
  under P4.0. PATH-001 is split into a strict send-gate (app data only to validated paths) and a
  relaxed recv-delivery (authenticated, non-replayed data is delivered regardless of source), so a
  NAT-rebind upload is seamless. Combined with header protection (T4.6, below) and CID collapse +
  rotation (ε, below), a **client** migration is unlinkable by an on-path observer in **both**
  directions (the server rotates its s2c CID on detecting the client's migration — EPS-02 fix, see
  Security below); a rarer *server*-initiated migration leaves the client→server CID stable (residual).
- **PhantomUDP (Phase 1):** native datagram `SessionTransport` over raw UDP with connection-ID
  demultiplexing — `PhantomUdpListener` (server accept) plus `UdpClientTransport` / `UdpServerTransport`.
  The multi-KB post-quantum handshake is fragmented to the path MTU and reassembled. No wire-format or
  crypto change — `WIRE_VERSION` / `PROTOCOL_VERSION` unchanged; the outer UDP envelope is transport framing.

### Security

- **Rekey hygiene — T5.5(b): re-advertised REKEY + a catch-up gate.** A mid-session rekey now
  re-advertises `PacketFlags::REKEY` on **every** packet sent at the new epoch (not just the single
  rotation-trigger packet) until the peer is observed at that epoch — so losing the trigger packet no
  longer leaves later new-epoch packets (incl. reliable retransmits) unflagged. On the strength of that
  guarantee the receive-side forward-rekey catch-up (`decrypt_packet_accepting_rekey`) now **gates** on
  the flag: a forward-epoch packet **without** `REKEY` is cheap-rejected *before* the HKDF catch-up walk
  runs, tightening the DoS bound (a spoofed forward epoch with the flag cleared forces zero key
  derivation; the existing `MAX_REKEY_CATCHUP` = 16 HKDF-step cap still bounds the flagged case). An
  honest not-yet-confirmed sender is unaffected (it always re-advertises). New `Session::rekey_unconfirmed`
  state (`AtomicBool`, set in `rekey()`, cleared on an authenticated inbound packet at the current epoch).
  Invariants 4 / 5 / 8 (replay-after-AEAD, epoch saturation, nonce-exhaustion) are preserved; no
  wire-format change (`REKEY` is an existing flag bit). Also corrects the stale "single rekey owner /
  single writer" comments — the receive task is a second epoch-writer, serialised through `rekey_lock`.
- **Build-integrity / supply chain — T5.6 (SUPPLY-03/04).** The FIPS build no longer links the
  non-FIPS classical crypto crates. `ring` (AEAD) and `x25519-dalek` (classical KEM half) are moved
  behind a new `classical-crypto` Cargo feature (folded into `default`, intentionally *not* implied by
  `std`), and the `AesSession` AEAD backend now cfg-dispatches `ring` → `aws-lc-rs` under `--features
  fips` (matching `adaptive_crypto`). Under `--features fips` the AEAD already routes through `aws-lc-rs`
  and the classical KEM half through ECDH-P-256, so both crates are genuinely unused there — they are now
  *absent* from the FIPS dependency graph (`cargo tree --no-default-features --features fips -i ring` →
  "did not match any packages"), shrinking the FIPS attack surface. A CI guard (`cargo tree -i`) fails the
  `fips-feature` job if either crate ever leaks back in. The FIPS CI invocations and the `cross.yml` FIPS
  row switch to `--no-default-features --features fips,...`; the `--no-default-features` non-FIPS
  cross-target rows (wasm / WASI) and the `server` / `wasm-demo` / `wasi-guest` embedders name
  `classical-crypto` explicitly. Separately, the dead `cargo-deny` advisory ignore (`RUSTSEC-2026-0097`,
  no longer matching any crate in the tree → an `advisory-not-detected` warning) was removed so `cargo
  deny check` is clean again. No wire, API, or crypto-behaviour change. (2026-06-16 docs follow-up:
  corrected the now-stale `cargo tree --features fips` "ring-free dependency tree" assertion in
  `docs/security/remediation-plan-2026-06-03.md` to the canonical `--no-default-features --features
  fips` form — plain `--features fips` keeps `ring`/`x25519-dalek` linked-but-unused via the default
  `classical-crypto` feature.)
- **Documented the 0-RTT distributed-cache replay caveat (T5.7).** The one-shot anti-replay for 0-RTT
  early-data (Invariant 9 — `SessionCache::try_resume` removes the ticket on first lookup) holds **only**
  under a single coherent `SessionCache`. The cache is an in-process bounded-LRU, not replicated, so a
  horizontally-scaled deployment with per-node caches lets an attacker replay a captured 0-RTT `ClientHello`
  against a *different* node that still holds the unconsumed ticket — the classic TLS-1.3
  0-RTT-across-a-server-farm replay. Mitigation is deployment-side (sticky/hashed routing of a
  `resume_session_id`, a shared store with atomic compare-and-remove, or idempotent early-data); the
  post-handshake session's PFS + auth are unaffected. Documented in PROTOCOL.md §6.6 and the threat-model
  (STRIDE-S + §8). No code change.
- **Zeroize the master secrets — T5.1 (key hygiene).** The rekey master `Session.traffic_secret` is now
  zeroized in `Session::drop` (rekey already wiped each *superseded* epoch secret; this covers the final
  live one); `ResumptionTicket` derives `ZeroizeOnDrop` (the verbatim resumption secret no longer lingers in
  the bounded session cache or in freed memory), guarded by a compile-time `ZeroizeOnDrop` assertion that
  fails the build if the derive is ever removed; and the transient handshake KEM shared secret is held in
  `Zeroizing` on both the encapsulate (server) and decapsulate (client) paths. Scoped the threat-model
  "keys zeroize on drop" mitigation row to this reality. No behavior or wire change.
- **Autonomous passive-NAT-rebind recovery (M-3):** a live PhantomUDP session now recovers from a
  **passive NAT rebind** — the peer's source address changes *without* the client calling `migrate()`,
  so its `path_id` stays `0` (the always-`Validated` handshake path) — with no embedder action and no
  re-handshake. Previously the server's path-validation challenge was path-id-gated, so it skipped the
  Validated path 0, never challenged the new authenticated source, never promoted it, and kept sending the
  downstream (server→client) direction to the old, now-dead address → the reliable stream stalled
  (upstream already survived via PATH-001b recv-relax). Detection is now **address-driven**: an
  AEAD-authenticated frame from a new source on a Validated path is challenged on a reserved validation
  `path_id` (`REBIND_VALIDATION_PATH_ID`, carved out of the active-migration id space), validated from the
  claimed address, promoted, and the server's downstream follows. Anti-spoof is preserved exactly as for an
  active migration: the candidate is committed only from an AEAD-authenticated source (M-1), the challenge
  goes only to that address under the 3× anti-amplification cap (RFC 9000 §8.2), and the peer swaps only on
  a valid echo. The reserved id is retired after promotion so a later rebind re-challenges from scratch.
  **No wire change.**
- **Unlinkable migration — CID collapse + rotation (ε; `WIRE_VERSION` 4→5, breaking):** the data-plane
  packet header drops the inner 32-byte `session_id` from the wire entirely (47→15 bytes — it stays in the
  AEAD AAD, reconstructed from session context, so the AEAD binding is byte-identical to v4), and the single
  remaining cleartext connection identifier — the outer 8-byte UDP `ConnId` — now **rotates** to an
  independent-random value on each `migrate()` via a per-direction KDF chain (`CID_i =
  derive_key_32("phantom-cid-v1", cid_secret‖i)[0..8]`), with the server demux routing on a sliding window
  that advances post-AEAD on the peer's authenticated `path_id`. With header protection (T4.6) already
  masking the variable per-packet metadata, the migrating peer's outbound CID rotates — so a **client**
  migration is unlinkable in the **client→server** direction (LINDDUN-L; threat-model §12.5 / PROTOCOL.md
  §4.7). *Residual (2026-06-15 audit, EPS-02):* rotation is asymmetric — the **server→client** CID does not
  rotate on a client migration, so that direction stays linkable to a both-networks observer; a
  symmetric-rotation fix is tracked. *Honest caveat:* like the HP keys, the CID chain is session-stable and **not**
  forward-secret — a session-key compromise recomputes the chain and relinks a *recorded* flow; the payload
  stays forward-secret. Breaking wire change (no deployed peers): `WIRE_VERSION` 4→5, packet wire-vectors
  regenerated; `PROTOCOL_VERSION` (handshake) unchanged; TCP / embedded (socket-routed) carry no on-wire CID
  and are unaffected. Also fixes a latent bug where `ObservedTransport` (the pump's observability wrapper)
  only forwarded send/recv, silently no-op'ing the FFI `migrate()` and the server-side migration detection
  once wrapped — the wrapper is now fully transparent, so FFI-triggered migration actually rebinds and the
  server follows + slides its CID window.
- **ε security audit + regression/CI hardening (2026-06-15):** a security review of the
  WIRE-v5 ε surface (`docs/security/audit-report-2026-06-15-wire-v5-epsilon.md`) found **no confidentiality /
  integrity / authentication regression** — the CID-chain primitive, the off-wire AAD reconstruction, the
  strictly-post-AEAD window slide, and replay-survives-rotation are all verified sound. It surfaced one
  **linkability residual** (EPS-02: asymmetric CID rotation — the server→client CID stays stable across a
  client migration; docs corrected above, fix tracked), one **availability** bound (EPS-01: the single-step
  window slide strands a sender that gets > K=4 migrations ahead under loss; fix tracked), and a **coverage
  gap** (EPS-03: no CI job ran the `udp_integration` suite, so a regression to a vacuous/linkable `migrate()`
  would have passed green CI). This release adds the **always-on `observed_transport_forwards_all_control_methods`
  tripwire** (pins that every `SessionTransport` control method is forwarded through the pump's wrapper),
  invariant pins for the post-AEAD slide (`eps_slide_requires_aead_success`) and replay-across-rotation
  (`eps_replay_rejected_across_cid_rotation`), a **`udp_integration --ignored` CI gate**, full control-surface
  forwarding in the test-only `LossyTransport` (the same latent partial-forwarding shape), a loud
  wrapper-contract note on the `SessionTransport` trait, and a widened `fuzz_aead_decrypt` that now exercises
  the non-empty-`extensions` AAD branch.
- **Symmetric CID rotation on client migration — EPS-02 fix (2026-06-15):** the audit's linkability residual
  is closed for the common case. When the server authenticates a client's new `path_id` (post-AEAD), it now
  rotates its **own** outbound (server→client) CID too, so a client moving Wi-Fi↔cellular is **unlinkable in
  both directions** — not just client→server. The socket-routed client accepts any inbound CID, so no
  client-side window slide is needed; the server does not bump its own send `path_id`, so there is no
  ping-pong. Verified by `eps02_server_rotates_s2c_cid_on_client_migration` (in-crate) and the extended
  on-wire `udp_integration_cid_rotates_on_the_wire_across_migration` (asserts **both** directions' ConnIds
  rotate). **Residual:** a *server*-initiated migration rotates s2c but not c2s (the socket-routed client does
  not rotate-on-detect — that would strand it in the server's un-sliding c2s window); rare, and tracked.
  No wire change.
- **Robust migration window — EPS-01 fix (2026-06-15):** the rotating-CID demux window no longer strands a
  client that migrates faster than delivery under loss. The window slide is now **multi-step** — it advances
  by the authenticated `path_id` forward delta `d` (registering `d` leading CIDs, dropping `d` trailing),
  recentring on the sender's actual migration index instead of lagging +1 per slide (the old single-step let
  lost intermediate migrations cumulatively erode the leading margin) — and the leading window **K is widened
  4 → 16**, so only an unbroken run of **> 16 consecutive fully-lost migrations** can push the sender's CID out
  of the window (recoverable by reconnect via liveness), far beyond any realistic rapid-migration regime.
  `MAX_ROUTES` is raised `1<<16 → 1<<18` to preserve concurrent-session capacity with the wider (19-CID)
  per-session window. Pinned by `eps01_multistep_path_jump_slides_window_by_the_full_delta`. No wire change.
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

- **`PhantomSession::connect(addr)` documented as deprecated/inert (T5.7).** This constructor never opens a
  transport, runs no handshake, and sends no bytes — it returns a placeholder stuck in `Connecting`. Its
  doc-comment now says so loudly and steers callers to the real entry points (`connect_with_transport` in
  Rust, `connect_pinned` over FFI). A `#[deprecated]` *attribute* is deliberately **not** applied: UniFFI
  0.31 emits FFI scaffolding that calls `Self::connect()` from generated code, which would trip the
  `deprecated` lint that CI promotes to a hard error under `clippy --lib -D warnings`. The regenerated
  Python / Swift / Kotlin docstrings carry the new wording (bindings committed; the `bindings` drift job
  stays green). New regression test `deprecated_connect_is_inert_and_sends_no_bytes` pins the inert contract.
- **PROTOCOL.md — byte-layout tables for the three AEAD-plaintext payload codecs (T5.7).** New §4.5
  documents, against the actual codec, the `Sack` ACK plaintext (`largest_acked`, `ack_delay_us`, the
  descending inclusive ranges), the reliable stream-frame plaintext (`[stream_offset: u32 BE][data]`), and
  the `COALESCED` bundle (`[count: u16][len_i: u16][payload_i]…` sub-payloads under one AEAD tag). These are
  AEAD plaintext, not the frozen outer container — documentation only, no wire change.
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

- **Congestion control: BBR loss signal was double-counted on SACK-gap losses.** A segment the
  SACK gap detector declared lost was fed to BBR's loss path twice — once at detection (the L1-B
  feed in the ACK handler) and again at retransmission (the `seg.retransmit` feed in the send loop).
  Because `inflight_bytes` is purely incremental, this permanently under-counted in-flight bytes
  (`+b −b −b +b −b = −b` over a segment's send/loss/resend/ack lifecycle), inflating the cwnd budget
  (`cwnd − inflight`) and accumulating with every SACK-gap loss → over-send exactly when the
  controller should back off. Loss is now fed **exactly once per loss event, at the retransmission
  point**, which covers both SACK-gap fast-retransmits and RTO-timeout retransmits (retransmits
  bypass the cwnd gate, so the single feed reliably fires; a spurious gap that is ACKed before
  retransmit now correctly feeds no loss). Regression test
  `loss_declaring_sack_does_not_feed_bbr_loss_at_detection`.

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
  `u64` **packet number**, replacing the per-stream `u32` `sequence`. `WIRE_VERSION` bumped
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
  module-level comment and the crate-root `unsafe` inventory are updated; the
  stale `recvmmsg` references — there was never a `recvmmsg` call — are removed.)
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
