# Phantom Core Architecture

Companion to `PROTOCOL.md` (wire format) and `SECURITY.md` (invariants).
This document covers the **internal** structure: modules, data flow,
concurrency, and ownership.

---

## 1. Three-layer overview

```
                  ┌───────────────────────────────────────────────┐
                  │                  api/                         │  ←── public surface,
                  │  PhantomSession   PhantomListener             │     UniFFI-exported,
                  │  PhantomStream    PhantomConfig               │     FFI-stable
                  │  ConnectionState  SessionTransport            │
                  └────────────────────┬──────────────────────────┘
                                       │
                                       ▼
                  ┌───────────────────────────────────────────────┐
                  │             transport/                        │  ←── protocol internals,
                  │  Session  CryptoState  PacketHeader           │     Rust-only API
                  │  HandshakeServer HandshakeClient              │
                  │  Stream  Scheduler  ReplayWindow              │
                  │  legs/{tcp, kcp, faketls}                     │
                  └────────────────────┬──────────────────────────┘
                                       │
                                       ▼
                  ┌───────────────────────────────────────────────┐
                  │               crypto/                         │  ←── primitives,
                  │  hybrid_kem  hybrid_sign                      │     called only by
                  │  adaptive_crypto (AEAD)  aes_session          │     transport layer
                  │  pow                                          │
                  └───────────────────────────────────────────────┘
```

**Direction of dependency** flows strictly downward: `api` may use anything
in `transport` or `crypto`; `transport` may use anything in `crypto`;
`crypto` does not depend on anything else inside the crate.

The `security/` module is sibling to `transport/` and depends only on
`std` + crypto helpers; it provides `ReplayWindow` and the older
`ReplayProtection` map-based deduper.

---

## 2. The public API layer (`core/src/api/`)

### Types

| Type | Role | UniFFI exported |
| --- | --- | --- |
| `PhantomSession` | Client session — non-blocking connect, queued sends | Yes (`uniffi::Object`) |
| `PhantomListener` | Server: bind, accept, expose verifying key bytes | Yes (`uniffi::Object`) |
| `PhantomStream` | Per-stream API on top of a session | Yes (`uniffi::Object`) |
| `ConnectionState` | Lifecycle enum (`Connecting` → ... → `Closed`) | Yes (`uniffi::Enum`) |
| `PhantomConfig` | User-tunable knobs | Yes (`uniffi::Record`) |
| `SessionTransport` (trait) | Byte-pipe abstraction below the encryption layer | No (Rust trait) |
| `TcpSessionTransport` | Length-prefix-framed TCP impl of `SessionTransport` | No |

### Lifecycle

```
client                                            server
──────                                            ──────

PhantomSession::connect_with_transport(           PhantomListener::bind(addr)
    addr, transport, expected_server_key)            ↓
    ↓                                             listener.accept()  ──┐
spawns background_task                                                  │
    ↓                                                                   │
    └─── ClientHello (borsh) ───────────────────────────────────────────►
                                                  drive_server_handshake
                                                     ↓
    ◄─── HelloRetryRequest (if cookie/PoW bad) ─────────┤
    └─── ClientHello (with cookie+pow) ─────────────────►
                                                  process_client_hello
                                                  → derives Session
                                                  ↓
    ◄─── ServerHello (transcript-signed) ───────────────┘
    ↓
process_server_hello(Some(expected_server_key))
    ↓
PhantomSession.state = Connected
                                                  ↓
spawn run_data_pump(crypto_session, ...)         spawn run_data_pump(server_session, ...)
                                                  via PhantomSession::from_accepted_server_session
    ↓                                                 ↓

    ──── encrypted PhantomPacket frames ──────────────►
    ◄─── encrypted PhantomPacket frames ───────────────
```

### The shared data pump (`api/session.rs::run_data_pump`)

Both client and server, after their respective handshakes, spawn the same `run_data_pump` function, which owns three tasks:

- A **delivery task** that drains an unbounded `deliver_rx` channel, handles the app-paced `recv_tx.send()`, and credits the flow-control window. This decoupling lets the reader emit inline ACKs without blocking on slow consumers.
- A **receive (reader) task** looping `transport.recv_bytes() → PhantomPacket::from_wire → decrypt → handle_packet()`, which emits inline ACKs for reliable packets and hands application data to the unbounded `deliver_tx` channel without ever blocking on the consumer.
- A **main select! loop** in the calling task that picks among:
  - `poll_interval.tick()` every 10 ms — sweeps all streams for queued sends and flushes pending WINDOW_UPDATEs.
  - `send_notify.notified()` — wakes immediately on outbound-ready notification (event-driven fast path, Phase 2.4+).
  - `cmd_rx.recv()` — application-level `SessionCommand`s (Send, SendStreamReliable, etc.).
  - `recv_done_rx` — exit when the receive task ends (transport closed).

The asymmetry between client and server stops here: the same pump
handles both directions of data after the handshake derives the
`Session`.

---

## 3. Transport / protocol layer (`core/src/transport/`)

### Types

| Type | Role |
| --- | --- |
| `Session` | Per-association state: id, AEAD `CryptoState`, streams, scheduler, replay windows. Immutable post-handshake fields use plain `&CryptoState` (Phase 2.7); mutable state is in `RwLock` / `DashMap`. |
| `CryptoState` | The per-direction AEAD keying material (`CryptoSession`) plus a 32-byte `session_key` for further HKDF. `ZeroizeOnDrop`. |
| `HandshakeServer` | Long-lived signing key + master secret for cookie/PoW. Per-process. `ZeroizeOnDrop`. |
| `HandshakeClient` | Per-connection ephemeral state — KEM key pair, signing key pair, nonce. `ZeroizeOnDrop`. |
| `Stream` | Per-stream send/recv buffers, sequence counters, reliability machinery |
| `Scheduler` | Multi-leg path selection (currently placeholder for future Phase 4.2 migration) |
| `PacketHeader` / `PhantomPacket` | Wire types |
| `legs/{tcp,kcp,faketls}` | `TransportLeg` trait impls |
| `BufferPool`, `Pacer`, `PacketCoalescer`, `BandwidthEstimator` | Performance infrastructure — most not yet wired in (Phase 2.1, 2.4, 2.5, 2.6) |

### Encryption boundary

Every byte that crosses `Session::encrypt_packet` / `Session::decrypt_packet`
is authenticated with the `PacketHeader` as AAD. This is THE place to look
when reasoning about confidentiality + integrity:

```rust
pub fn encrypt_packet(&self, header: &PacketHeader, plaintext: &[u8]) -> Result<Vec<u8>, CoreError> {
    let header_bytes = header.to_wire(); // 45-byte big-endian image = AAD
    self.crypto.encrypt(&header_bytes, plaintext)
}
```

There is no second path. Every send goes through here. Every receive
goes through `decrypt_packet` which adds a ReplayWindow check after AEAD
verification.

---

## 4. Cryptography layer (`core/src/crypto/`)

| Module | Type | Role |
| --- | --- | --- |
| `hybrid_kem` | `HybridSecretKey`, `HybridKeyPackage`, `HybridCiphertext` | X25519 + Kyber768; ZeroizeOnDrop on secret |
| `hybrid_sign` | `HybridSigningKey`, `HybridVerifyingKey`, `HybridSignature` | Ed25519 + Dilithium3; ZeroizeOnDrop |
| `adaptive_crypto` | `CryptoSession`, `CipherSuite`, `HwCaps` | Per-direction AEAD with counter-derived nonce; HW auto-selection |
| `aes_session` | `AesSession` | Earlier AEAD reference design; still used in places |
| `pow` | `PoWChallenge`, `PoWSolution` | Proof-of-work for handshake DoS resistance |

The crate has `#[allow(unsafe_code)]` in three modules: `transport/udp_transport.rs` for libc GSO syscalls, `transport/legs/wasi.rs` for WASI syscalls, and `transport/legs/websocket.rs` for wasm-bindgen JS-boundary glue. The previous `crypto/keys.rs` (pqcrypto byte zeroing via `ptr::write_volatile`) was deleted in Phase 5.1; ml-dsa and ml-kem now provide native `ZeroizeOnDrop` (hybrid_sign and hybrid_kem modules).

---

## 5. Concurrency model

```
              ┌────────────────────────────────────┐
              │  PhantomSession (Arc<Self>)         │  ← cloned freely;
              │   id, peer, state (AtomicU8),       │     all method bodies
              │   send_queue (tokio::Mutex),        │     take &self
              │   cmd_tx (mpsc::Sender),            │
              │   recv_rx (tokio::Mutex<Receiver>), │
              │   demux (Arc<Demultiplexer>),       │
              │   streams (Arc<DashMap>)            │
              └─────┬──────────────────────┬───────┘
                    │                      │
                    │ cmd_tx               │ recv_rx
                    ▼                      ▲
              ┌─────────────────────────────────────────────────────────────────────┐
              │ run_data_pump  (the calling / select! task)                         │
              │                                                                     │
              │ spawns DELIVERY task:                                               │
              │   deliver_rx.recv()                                                 │
              │     → undelivered_bytes -= n                                        │
              │     → record_app_consumed → stage WINDOW_UPDATE credit              │
              │   → recv_tx.send().await        (app-paced; the backpressure point) │
              │                                                                     │
              │ spawns READER task  (never blocks on the app consumer):             │
              │   transport.recv_bytes() → PhantomPacket::from_wire                 │
              │     → AEAD decrypt + per-stream replay check                        │
              │     → inline ACK for RELIABLE (unencrypted; no rekey dep)           │
              │     → deliver_tx.send()   [unbounded queue, never blocks]           │
              │     → route_close on FIN                                            │
              │                                                                     │
              │ loop select! { poll_interval.tick() | send_notify.notified()        │
              │                | cmd_rx.recv() | recv_done_rx => break }            │
              └─────────────────────────────────────────────────────────────────────┘
```

**Task topology per session: 3 spawned tasks.**

- The main task (`run_data_pump`) drives the send path and application command channel via the `select!` loop.
- The delivery task handles the app-paced `recv_tx.send()` and flow-control window crediting from the unbounded `deliver_rx` queue.
- The reader task drives the receive path: decrypt, emit inline ACKs, and hand off data to `deliver_tx` without blocking.

They communicate through `mpsc` channels (one for commands client→pump,
one for decrypted payloads pump→app) and through `Arc<...>` shared
state.

**Concurrency primitives used:**

- `tokio::sync::Mutex` — for state held across `.await`.
- `parking_lot::RwLock` — for fast sync state.
- `AtomicU8` / `AtomicU32` / `AtomicU64` — for lock-free flags and
  counters.
- `dashmap::DashMap` — for the per-stream map (lock-free concurrent map).
- `tokio::sync::mpsc` (bounded) — async channels for commands (cmd_rx/cmd_tx) and bounded app recv (recv_tx/recv_rx).
- `tokio::sync::mpsc::unbounded_channel` — for receive-delivery decoupling (`deliver_tx`/`deliver_rx`), allowing the reader to hand off data without blocking on app consumption.

**Lock-free fast path.** Phase 2.7 dropped the `RwLock` around
`CryptoState`, so encrypt/decrypt now reads through a plain `&CryptoState`
reference — no lock acquisition per packet. Interior counters in
`CryptoSessionInner` are `AtomicU64`.

---

## 6. Ownership model

`PhantomSession` is `Arc<Self>` from construction. Cloning is cheap (refcount
bump). The spawned tasks all hold `Arc<...>` clones of the things they
need; nothing crosses task boundaries by reference.

`Session` (the lower-level transport association) is owned by the
spawned data pump task as `Arc<Session>` — the same value flows from
the handshake into the data plane.

`CryptoState`, `HandshakeServer`, `HandshakeClient`, and
`Session.resumption_secret` all carry `ZeroizeOnDrop` so dropping the
Arc — once refcount hits zero — zeroes the key material before the
allocator reuses the memory.

---

## 7. Wire framing

For TCP-based legs (`TcpSessionTransport`, `legs/tcp.rs`), every
`PhantomPacket` is wrapped in a 4-byte big-endian length prefix on the
TCP byte stream:

```
[len: u32 BE][PhantomPacket::to_wire image]
[len: u32 BE][PhantomPacket::to_wire image]
...
```

Maximum frame size: `MAX_FRAME_BYTES = 16 MiB`
(`core/src/api/tcp_transport.rs:21`). Frames larger than the cap are
rejected at the framing layer before the packet is parsed.

KCP-based legs reuse KCP's own segmentation; FakeTLS wraps frames in
fake TLS 1.3 records.

---

## 8. Error propagation

Errors flow upward as typed `CoreError` (UniFFI-exported) at the API
boundary, internally as the more specific module-level error enums
(`HandshakeError`, `CryptoError`, etc.). The conversion is mechanical:
each module's `From<ModuleError> for CoreError` impl maps the variant.

The public surface has **no** `.unwrap()` / `.expect()` / `panic!` /
`unreachable!` calls in production code paths
(`#![warn(clippy::unwrap_used, ...)]` in `lib.rs` enforces this for the
lib target; test/bench scaffolding is exempt).

---

## 9. Performance landmarks

| Module | Why it's hot | What we did |
| --- | --- | --- |
| `api/session.rs::run_data_pump` (recv) | Every inbound packet | Unbounded delivery queue decoupling (Phase 2.2, prevent reader blocking on slow consumers); inline ACK emission in reader (Phase 2.3); ACK buffer hoisted (Phase 2.3); per-stream WINDOW_UPDATE sequence (Phase 4.3); inline FIN sequence (Phase 4.3) |
| `api/session.rs::send_app_data` | Every outbound packet | `Vec::with_capacity(payload + 64)` to avoid realloc (Phase 2.3) |
| `transport/session.rs::encrypt/decrypt_packet` | Per packet | Lock-free `&CryptoState` (Phase 2.7) |
| `transport/udp_transport.rs` | UDP fast paths | GSO / `sendmmsg` on Linux (pre-existing) |
| `crypto/adaptive_crypto.rs` | Per AEAD op | HW-AES detection; ring's optimized AES-NI / NEON paths |

Hot paths still on the deferred list:
- `api/tcp_transport.rs::recv_bytes` allocates a fresh `Vec` per packet
  (Phase 2.1, blocked on `SessionTransport` trait refactor).
- The 10 ms `poll_interval.tick()` in `run_data_pump` (Phase 2.4
  event-driven replacement).

---

## 10. Module dependency map

```
                    api/
                  ┌──┴──┐
                 session  listener  stream  config  tcp_transport
                    │       │        │       │       │
                    │       └────┐   │       │       │
                    │            ▼   │       │       │
                    │       transport│       │       │
                    │       ┌───────┴┐      │       │
                    └──────►│session │◄─────┤       │
                            │handshake      │       │
                            │stream         │       │
                            │types          │       │
                            │legs/*         │       │
                            └──┬───────────┴───────┘
                               │
                               ▼
                             crypto/
                         ┌─────┴─────┐
                       hybrid_kem  hybrid_sign  adaptive_crypto  pow  keys
                            │            │             │           │    │
                            └────────────┴─────────────┴───────────┴────┘
                                          standard / OS crates only
```

`security/` is parallel to `transport/` and similarly depends only on
`crypto/` + std.

---

## 11. Roadmap for evolution

The architecture sketched here is the single-protocol baseline. The major
moves in the eight-phase production-readiness plan:

- **Phase 3**: introduce a `Runtime` trait between the API layer and
  the tokio types, so WASM / embedded backends can drop into the same
  shape. The trait itself has landed in [`crate::runtime`] with
  `TokioRuntime` as the default impl; call-site migration is in
  progress.
- **Phase 4**: turn `Scheduler` from a placeholder into a real
  multi-path / migration policy (`PacketHeader.path_id` is in place;
  scheduler integration is the next step).
- **Phase 5**: gate the crypto layer behind `fips` feature so it can be
  built with ML-KEM / ML-DSA / aws-lc-rs primitives.
- **Phase 4.5**: insert `tracing` instrumentation and `metrics`
  counters at the boundary between the API layer and the data pump
  without altering the data flow. Tracing foundation is in place on
  the four entry points (Phase 4.5 partial).

The split into the four layers (api / transport / crypto / runtime) is
designed to keep each of those moves self-contained.

## 12. The `runtime/` module (Phase 3.1)

```
                ┌────────────────────────────────┐
                │  runtime::Runtime  (trait)      │
                │  ┌──────────────────────────┐  │
                │  │ spawn(BoxFuture<()>)     │  │
                │  │ sleep(Duration)          │  │
                │  │ now_monotonic()          │  │
                │  │ now_wall_clock()         │  │
                │  └──────────────────────────┘  │
                └────────────────┬───────────────┘
                                 │ implemented by
                  ┌──────────────┼──────────────┬─────────────┐
                  ▼              ▼              ▼             ▼
           TokioRuntime   (WasmRuntime)   (EmbeddedRuntime)  test mocks
              ✅              scaffold         scaffold
```

`TokioRuntime` is a zero-sized struct that wraps the existing
`tokio::spawn` / `tokio::time::sleep` / `std::time::Instant` /
`std::time::SystemTime` calls. Callers that take `Arc<dyn Runtime>`
have zero behavioural difference today.

`SpawnHandle` is the runtime-agnostic equivalent of
`tokio::task::JoinHandle<()>` — exposes `abort()` and `is_finished()`.
Dropping it detaches the task (matches tokio semantics).

When WASM and embedded backends land, they implement the same trait;
no other code in the crate needs to change shape.
