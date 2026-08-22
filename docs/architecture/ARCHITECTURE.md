# Phantom Protocol Architecture

Companion to `PROTOCOL.md` (wire format) and `SECURITY.md` (invariants).
This document covers the **internal** structure: modules, data flow,
concurrency, and ownership. It is current as of Phase 8 (OpenTelemetry) +
Phase 4 (connection migration & liveness, P4.0–P4.4) — the native **PhantomUDP**
transport, the per-direction `u64` packet number, path validation, and the
liveness state machine are all live and described below.

---

## 1. Layer overview

```
                  ┌───────────────────────────────────────────────┐
                  │                  api/                          │  ←── public surface,
                  │  PhantomSession   PhantomListener              │     UniFFI-exported,
                  │  PhantomUdpListener   PhantomStream            │     FFI-stable
                  │  UdpClientTransport   UdpServerTransport       │
                  │  ConnectionState  ResumptionHint  AcceptOutcome│
                  │  TcpSessionTransport  SessionTransport (trait) │
                  └────────────────────┬──────────────────────────┘
                                       │
                                       ▼
                  ┌───────────────────────────────────────────────┐
                  │             transport/                         │  ←── protocol internals,
                  │  Session  CryptoState  PacketHeader            │     Rust-only API
                  │  HandshakeServer/Client  Stream  Sack          │
                  │  PathRegistry  liveness  ReplayWindow          │
                  │  phantom_udp/{envelope,datagram}  legs/*       │
                  └────────────────────┬──────────────────────────┘
                                       │
                                       ▼
                  ┌───────────────────────────────────────────────┐
                  │               crypto/                          │  ←── primitives,
                  │  hybrid_kem  hybrid_sign  adaptive_crypto      │     called only by
                  │  kdf  rng  self_tests  aes_session  pow        │     transport layer
                  └───────────────────────────────────────────────┘

   sibling, std-light:   security/ (ReplayWindow) · runtime/ (Runtime trait) · observability/ (OTel)
```

**Direction of dependency** flows strictly downward: `api` may use anything in
`transport`/`crypto`; `transport` may use `crypto`; `crypto` depends on nothing
else in the crate. `security/` and `runtime/` are siblings to `transport/` and
depend only on `crypto/` helpers + `std`/OS crates; `observability/` is a sibling
too, but it imports one transport type — `transport::types::LegType`, its per-leg
metric-attribute enum. (The `session_transport` trait and `legs/embedded` are
`no_std + alloc`-clean.)

---

## 2. The public API layer (`core/src/api/`)

### Types

| Type | Role | UniFFI exported |
| --- | --- | --- |
| `PhantomSession` | Client/served session — non-blocking connect, queued sends, `migrate()` | Yes (`uniffi::Object`) |
| `PhantomListener` | TCP server: bind, accept, expose verifying-key bytes | Yes (`uniffi::Object`) |
| `PhantomUdpListener` | **PhantomUDP server**: `bind_udp`, CID-demuxed accept | Yes (`uniffi::Object`) |
| `UdpClientTransport` / `UdpServerTransport` | Native UDP `SessionTransport` impls (client = connected socket + dual-socket migrate; server = per-session demux shim with `ArcSwap` peer) | No (Rust) |
| `TcpSessionTransport` | Length-prefix-framed TCP impl of `SessionTransport` | No |
| `PhantomStream` | Per-stream API on top of a session | Yes (`uniffi::Object`) |
| `AcceptOutcome` | `accept()` result — `.session()` + take-once 0-RTT early-data | Yes (`uniffi::Object`) |
| `ConnectionState` | Lifecycle enum: `Connecting`/`Connected`/`Failed`/`Closed`/`Migrating`/`Dead`/**`Draining`**. Discriminants are `0,4,5,6,7,8,9` — `1..=3` are holes left by a staged classical-then-PQC upgrade the protocol never shipped, so an old log's number cannot come back meaning something else | Yes (`uniffi::Enum`) |
| `ResumptionHint` | 0-RTT `(session_id, resumption_secret)` record (redacting `Debug`) | Yes (`uniffi::Record`) |
| `PhantomConfig` | User-tunable knobs | Yes (`uniffi::Record`) |
| `SessionTransport` (trait) | Byte-pipe abstraction below the encryption layer; SocketAddr-free migration hooks (`has_migration_candidate` / `send_to_candidate` / `promote_candidate` / `migrate`) | No (Rust trait) |
| `SessionBuilder` / `ListenerBuilder` / `UdpListenerBuilder` | The canonical Rust entry points — `PhantomSession::builder(addr)` / `PhantomListener::builder(addr)` / `PhantomUdpListener::builder(addr)`. Type-state: only `SessionBuilder<T: SessionTransport>` exposes `.connect()`, and `.connect()` errors `ConfigError` unless `.pinned_key(...)` was set (Invariant 1). | No (Rust) |
| `TrafficShapingConfig` / `PaddingPolicy` | Opt-in anti-fingerprint shaping (v6): PADME size padding, send jitter, cover-traffic interval. | Yes (`uniffi::Record` / `uniffi::Enum`) |
| `MetricsSnapshotFfi` | Flat metrics carrier returned by `PhantomSession::metrics_snapshot()`; available regardless of `telemetry-otel`. | Yes (`uniffi::Record`) |

Free functions exported for mobile/FFI: `connect_pinned` / `connect_pinned_with_config` /
`connect_pinned_with_resumption` (TCP) and `connect_pinned_udp` /
`connect_pinned_udp_with_config` / `connect_pinned_udp_with_resumption` (PhantomUDP), plus
the sync identity helpers `generate_signing_key` / `verifying_key_from_signing_key`.
Rust-only (not exported): `connect_pinned_mimic` (feature `mimicry`) and
`generate_signing_key_secure`.

### Lifecycle

```
client                                            server
──────                                            ──────
connect_with_transport(addr, transport,           PhantomListener::bind(addr)  /  PhantomUdpListener::bind_udp(addr)
    expected_server_key)                              ↓
    ↓ spawns background_task                       accept()  (UDP: run_udp_demux routes by CID → spawn_handshake_task)
    └── ClientHello (borsh; UDP: fragmented to PATH_MTU=1200, reassembled) ─────►
    ◄── HelloRetryRequest (if cookie/PoW missing) ────────┤  drive_server_handshake
    └── ClientHello (+ cookie + PoW) ─────────────────────►  process_client_hello → derives Session
    ◄── ServerHello (transcript-signed) ──────────────────┘
    ↓ process_server_hello(Some(expected_server_key)); pin + verify; derive Session
ConnectionState = Connected
    ↓ spawn run_data_pump(crypto_session, ...)        spawn run_data_pump(server_session, ...)
    ──── encrypted PhantomPacket frames (WIRE 6) ─────────►
    ◄──── encrypted PhantomPacket frames ──────────────────
    │
    └─ [optional] migrate(new_local_addr) → rebind + new path_id → server detects new source → PATH_CHALLENGE → validate → peer switch
```

**Only the server is authenticated** by the handshake (server-key pinning +
transcript signature). The client sends `client_verify_key` but does **not**
prove possession of its private half at this stage — mutual / peer-identity
authentication, if needed by a product on top, lives above the transport.

### The shared data pump (`api/session.rs::run_data_pump`)

Both client and server, after their handshakes, spawn the **same** `run_data_pump`
(one function, **five** concurrent units — its own `select!` loop plus four spawned tasks):

- **Delivery tasks A + B** — Task A drains the raw-app queue (stream ids ≤ 1) and paces
  `recv_tx.send()`; Task B drains the opened-stream queue (ids ≥ 2) into the demux. Both
  decrement `undelivered_bytes` and stage flow-control (`WINDOW_UPDATE`) credit.
  Decoupling lets the reader never block on a slow consumer.
- **Router task** — moves each `DeliverItem` off the reader's unbounded `deliver_tx` onto
  Task A's or Task B's (also unbounded) queue, so no hand-off ever blocks the reader.
- **Reader task** — loops `transport.recv_bytes() → Session::parse_protected` (unmask the
  header-protected frame, reconstruct the off-wire `session_id`) → drop anything whose
  `header.version != WIRE_VERSION` → `handle_packet()`.
  `handle_packet` binds every frame to the negotiated `session_id`, decrypts (the
  `ENCRYPTED` gate, with an authenticated forward-rekey catch-up of up to
  `MAX_REKEY_CATCHUP` = 16 epochs — a forward epoch without the `REKEY` flag is rejected
  before any HKDF work), then
  dispatches: authenticated **SACK ACK** (`ENCRYPTED|ACK`, post-AEAD — the H1 fix),
  `WINDOW_UPDATE`, `PATH_VALIDATION` (migration), `COALESCED`, and reliable data
  (gap-free `stream_offset` reassembly). Inbound that passes AEAD calls
  `update_activity()` (the liveness signal).
- **Main `select!` loop** picks among:
  - `poll_interval.tick()` (10 ms) — drains streams, flushes `WINDOW_UPDATE`s, and runs
    the **liveness sweep** (`apply_liveness`).
  - `send_notify.notified()` — event-driven outbound-ready fast path.
  - `cmd_rx.recv()` — `SessionCommand`s: `Send`, `SendStreamReliable/Unreliable`,
    `CloseStream`, `SetStreamPriority`, **`Migrate(local_addr)`**,
    **`MigrateServer(local_addr)`**, `Close`.
  - `recv_done_rx` — exit when the reader ends (transport closed).

---

## 3. Transport / protocol layer (`core/src/transport/`)

### Types

| Type | Role |
| --- | --- |
| `Session` | Per-association state: `id`, AEAD `CryptoState` (`ArcSwap`, rekey-swappable), `traffic_secret`, `epoch` (`AtomicU8`, saturates), the **`send_packet_number: AtomicU64`** (the per-direction nonce + replay identity — P4.0), `send_path_id: AtomicU8` (client-owned migration label), one per-direction `recv_replay: Mutex<ReplayWindow>`, `path_registry: Arc<PathRegistry>`, `liveness_config`, `pacer`, `bandwidth_estimator`, `scheduler`, streams. |
| `CryptoState` | Per-direction AEAD keying (`CryptoSession`) + 32-byte `session_key` for further HKDF. `ZeroizeOnDrop`. Swapped wholesale on rekey via `ArcSwap`. |
| `HandshakeServer` | Long-lived signing key + master secret (cookie/PoW), per-IP `ReputationTracker`. Per-process. `ZeroizeOnDrop`. |
| `HandshakeClient` | Per-connection **ephemeral** state — hybrid KEM key pair, signing key pair, nonce. `ZeroizeOnDrop`. |
| `Stream` | Per-stream send/recv buffers, the gap-free **`stream_offset: u32`** (A.5 reliability layer), `RtoEstimator` (RFC 6298), reorder buffer, SACK-driven retransmit. |
| `Sack` | Authenticated ACK payload: `largest_acked: u32`, `ack_delay_us: u32`, inclusive received ranges — over `stream_offset`, **not** the wire packet number (the layer split). |
| `PathRegistry` | Per-session path lifecycle (`Unvalidated → Validating → Validated/Failed`), constant-time challenge/response (Invariant 6), `retire` for `path_id` reuse. |
| `liveness` | Two pure gates — `liveness_verdict()` (Unchanged / PathDown / Recovered / Dead) and `should_send_keepalive()` (the idle `KEEPALIVE` PING cadence) — + `LivenessConfig` thresholds. |
| `Scheduler` | **Vestigial** — constructed inside `Session` and reachable via `Session::scheduler()`, but `select_paths` is never called on the live data path (single-path migration, not multipath aggregation). Live per-path RTT/loss lives in `path.rs::PathState` + the BBR `BandwidthEstimator`. |
| `PacketHeader` / `PhantomPacket` | Wire types (15-byte on-wire header / 47-byte AEAD AAD image; § PROTOCOL.md). |
| `phantom_udp/{envelope,datagram}` | The PhantomUDP `[flags][cid]` envelope + fragmentation/reassembly to `PATH_MTU`. |
| `legs/{websocket,wasi,embedded,mimic_tls}` | `SessionTransport` impls — browser WebSocket (`wasm32-unknown`), WASI P2 TCP (feature `wasi-leg`), bare-metal `embedded-io-async` (feature `embedded`), and the TLS-mimicry leg (feature `mimicry`, native-only; obfuscation-only — see § 8). |
| `BufferPool`, `Pacer`, `PacketCoalescer`, `BandwidthEstimator` (BBR) | Performance infrastructure. |

### Encryption boundary

Every byte that crosses `Session::encrypt_packet` / `decrypt_packet` is
authenticated with the reconstructed **47-byte** `PacketHeader` AAD image
(`to_aad_image()` — distinct from the 15-byte on-wire `to_wire()`; the 32-byte
`session_id` is in the AAD but off the wire, § 8). The AEAD nonce is
`nonce_prefix(4) ‖ packet_number(8)` — the per-direction monotonic `u64` packet
number drawn at send time (P4.0). `epoch`/`stream_id`/`path_id` are in the
AAD but **not** the nonce.

```rust
fn build_packet_nonce(prefix: [u8;4], header: &PacketHeader) -> [u8;12] // prefix ‖ packet_number_be
pub fn encrypt_packet(&self, header: &PacketHeader, pt: &[u8]) -> Result<Vec<u8>, CoreError> {
    let nonce = Self::build_packet_nonce(self.crypto.load().nonce_prefix(), header);
    // AAD = header.to_aad_image()  (47 bytes; the on-wire header is 15 bytes)
}
```

There is no second path. Every receive goes through `decrypt_packet`
(`decrypt_packet_accepting_rekey` on the recv side), which consults **one
per-direction** `ReplayWindow` keyed on the `u64` packet number **after** AEAD
verify (Invariant 4). A failed/tampered decrypt never desyncs the receiver
(the nonce is derived from the authenticated header, not an internal counter).

---

## 4. PhantomUDP native transport & connection migration (Phase 4)

The primary native transport. A single PQ-pinned identity survives a network-path
change (Wi-Fi↔cellular, NAT-rebind) **without** re-running the handshake — one live
path at a time (aggregation/multipath are out of scope).

### Framing & demux

- **Envelope** (`phantom_udp/envelope.rs`): each datagram = `[flags: u8][cid: 8]` +
  inner frame; `flags` carries the packet type (`Initial`/`OneRtt`) + a fragment bit.
  The 8-byte `cid` is the **plaintext** demux key.
- **Fragmentation** (`phantom_udp/datagram.rs`): frames above `MAX_INNER_UNFRAGMENTED`
  (the multi-KB PQ handshake) are split to `PATH_MTU = 1200` and reassembled by a
  `FragmentAssembler` (bounded slot table with stalest-eviction).
- **Server demux** (`api/udp_listener.rs::run_udp_demux`): a single task routes inbound
  datagrams to per-session channels by CID, gates new handshakes behind a 256-permit
  `inflight` semaphore, and spawns `drive_server_handshake` per fresh CID.

### The migration switch (detect → challenge → validate → swap)

1. **Client** (`UdpClientTransport::migrate_to`): binds a fresh local socket, keeps the
   old one for the overlap (dual-socket; `socket`/`prev_socket` are `ArcSwap`), bumps the
   send `path_id` (`Session::next_migration_path_id`, never 0), and routes app data + ARQ
   retransmits out the new socket.
2. **Server** detects *known CID + new source 5-tuple* and records a migration candidate
   (`UdpServerTransport`, `ArcSwap` peer + candidate + a 3× anti-amplification budget, D9).
3. **Server** challenges the candidate path with a 32-byte `PATH_VALIDATION` (constant-time
   verify, Invariant 6), then atomically `ArcSwap`s its peer to the new source, resets the
   RTT estimator + congestion controller (QUIC §9.4), and retires the old path.

**PATH-001 split (D10):** *send-gate strict* — app data is sent only to the established
peer / a `Validated` path; *recv-delivery relaxed* — AEAD-authenticated, non-replayed data
is delivered regardless of source (so a NAT-rebind upload is seamless; only the real
key-holder can produce it, and the per-direction replay window gates duplicates).

### Liveness (P4.3)

`transport/liveness.rs` holds two pure decisions.
`liveness_verdict(silence, inflight, min_rtt, in_migrating, migrating_for, cfg)` is fed by
the pump's 10 ms tick and returns `Unchanged` / `PathDown` / `Recovered` / `Dead`:

- **PathDown** — *N×PTO of inbound silence while reliable data is outstanding* →
  `ConnectionState::Migrating` (keys held, outbound buffered; the embedder reacts by
  calling `migrate()`).
- **Recovered** — inbound resumes → back to `Connected`.
- **Dead** — no recovery before the migration-idle timeout → terminal `Dead`, the pump
  ends, `recv()` errors (not a hang).

`should_send_keepalive(connected, inflight, inbound_silence, since_last_keepalive, cfg)` is
the second gate: on an idle `Connected` session it fires one empty `ENCRYPTED | KEEPALIVE`
PING per `keepalive_interval`, which the peer echoes back as `KEEPALIVE | ACK`. The
outstanding PING counts as in-flight for the sweep above, so a download-only path with a
silently-dead downstream is detected exactly like an active one.

`update_activity()` is called only on **AEAD-authenticated** inbound, so a forged/replayed
packet cannot mask a dead path or reset the timer. The same pump runs on both peers, so a
server detects a vanished client symmetrically.

### The layer split (P4.0 + A.5)

- **Packet layer:** the per-direction monotonic `u64` `packet_number` — the AEAD nonce +
  anti-replay identity. Assigned at send time; a retransmit draws a fresh PN.
- **Stream layer:** the gap-free per-stream `u32` `stream_offset` in the reliable AEAD
  plaintext — feeds reassembly, SACK, loss detection, retransmit dedup.

> Migration is now **unlinkable in both directions** for a move by *either* peer: header
> protection masks the whole 15-byte header (the `version` byte included), the inner
> 32-byte `session_id` left the wire, and the routing `ConnId` **rotates** per migration
> (the ε / A2a work — EPS-02 closed). The honest residual: the HP keys and CID chain are
> session-stable (not forward-secret), so a session-key compromise can link a *recorded*
> flow retroactively — the payload stays forward-secret. See PROTOCOL.md § 4.2 / § 4.6 /
> § 4.7 / § 12.5.

---

## 5. Cryptography layer (`core/src/crypto/`)

| Module | Type | Role |
| --- | --- | --- |
| `hybrid_kem` | `HybridSecretKey`, `HybridKeyPackage`, `HybridCiphertext` | X25519 + ML-KEM-768 (FIPS 203); ECDH-P-256 + ML-KEM-768 under `fips`. `ZeroizeOnDrop` on secrets. Combiner = `HKDF-SHA256(ecc_secret ‖ pq_secret ‖ classical_ct ‖ classical_pk)` under the domain label `HybridKEM_X25519_Kyber768` (`HybridKEM_P256_Kyber768` under `fips`) — X-Wing-style, binding the classical ciphertext + recipient pubkey, not just the two raw secrets. |
| `hybrid_sign` | `HybridSigningKey`, `HybridVerifyingKey`, `HybridSignature` | Ed25519 (`verify_strict`) + ML-DSA-65 (FIPS 204); both halves must verify. `ZeroizeOnDrop`. |
| `adaptive_crypto` | `CryptoSession`, `CipherSuite`, `HwCaps` | AES-256-GCM / ChaCha20-Poly1305 with the `prefix ‖ packet_number` nonce; HW auto-select (AES-NI → AES). `aws-lc-rs` backend + ChaCha rejected under `fips`. |
| `header_protection` | `HeaderProtector` | QUIC-style (RFC 9001 §5.4) masking of the whole 15-byte header (`HP_MASK_LEN = 15`). **Session-stable** keys (`phantom-hp-send-v1` / `phantom-hp-recv-v1`), NOT epoch-rotated; AES-256-ECB mask under `fips`. Keys zeroized on `Drop`. |
| `cid_chain` | `CidChain` | The rotating 8-byte connection ID (`CID_LEN = 8`) behind unlinkable migration: per-direction secrets (`phantom-cid-c2s-v1` / `phantom-cid-s2c-v1`), `CID_i = derive_key_32("phantom-cid-v1", secret ‖ i)[..8]`. Secrets zeroize on `Drop`. |
| `kdf` | side-agnostic `derive_key_32` + early-data keying | `blake3::derive_key` (default) / `HKDF-SHA256` (`fips`). |
| `rng` | `RngProvider` + `OsRng` | `getrandom` default; `aws-lc-rs` CTR_DRBG under `fips`. |
| `self_tests` | `run_post` / `ensure_post_passed` | FIPS 140-3 §7.7 power-on self-tests; auto-invoked under `fips` before any handshake (Invariant 11). |
| `aes_session` | `AesSession` | Reference per-direction AEAD pattern. |
| `pow` | `PoWChallenge`, `PoWSolution` | blake3 PoW + stateless cookie DoS gate (constant-time MAC compare). |

`#![deny(unsafe_code)]` at the crate root; two audited, sound opt-ins:
`transport/legs/wasi.rs` (`unsafe impl Send/Sync` over WIT-bindgen handles) and
`transport/legs/websocket.rs` (wasm-bindgen JS glue). Both are confined to a
non-native target, so a native build compiles no `unsafe` at all. No `unsafe`
in `crypto/`.

---

## 6. Concurrency model

**Task topology per session: five concurrent units** (the `run_data_pump` `select!` loop +
two delivery tasks (raw-app / opened-stream) + a router task + the reader task),
communicating via `mpsc` channels + `Arc<…>` shared state.

```
PhantomSession (Arc) ── cmd_tx ──► run_data_pump select! loop ── drain/flush/apply_liveness (10ms) ──► transport.send_bytes
       ▲ recv_rx ◄── delivery task A (ids ≤ 1) ◄─┐
                                                 ├── router task ◄── deliver_rx (unbounded) ◄── reader task: recv_bytes → parse_protected → handle_packet → AEAD → replay → dispatch
         demux ◄── delivery task B (ids ≥ 2) ◄───┘
```

**Shared mutable state & its primitives:**
- `ArcSwap` — `Session.crypto` (rekey), and on the UDP transport: `UdpServerTransport.peer`
  + `candidate`, `UdpClientTransport.socket` + `prev_socket` (migration swaps, lock-free w.r.t.
  the send/recv loops).
- `parking_lot::RwLock` / `Mutex` — `state`, `traffic_secret`, `liveness_config`,
  `bandwidth_estimator`; `recv_replay` (`Mutex<ReplayWindow>`).
- `AtomicU8/U32/U64` — `epoch`, `send_packet_number` (the nonce/replay counter), `send_path_id`,
  the anti-amp budget (`cand_recv`/`cand_sent`), `ConnectionState`.
- `dashmap::DashMap` — the per-stream map.
- `mpsc` (bounded cmd + bounded app-recv; unbounded delivery decoupling).

**Rekey serialization (honest note):** `rekey_lock` serializes each epoch transition, but
there are **two writers** to `(epoch, crypto)`: the send loop (`rekey_before_stamp`) and the
**recv task** (the forward-rekey catch-up commits on an authenticated peer rekey). The
nonce is safe regardless (fresh per-epoch prefix + unique `u64` PN), but a recv-side commit
can race a concurrent send's read-epoch→encrypt window and produce a self-inconsistent
epoch-stamp that the peer drops (reliable data self-heals via ARQ). The in-code "single
rekey owner" comments overstate this — the recv task is a second writer.

**Single-threaded reader.** The per-session reader processes `recv_bytes` then
`handle_packet` **sequentially** per datagram; this ordering is load-bearing for migration
correctness (the legitimate `PATH_VALIDATION` echo's own `recv_bytes` sets the candidate
before `handle_packet` promotes it). Making the reader concurrent would require binding the
promoted peer to the authenticated challenge source.

---

## 7. Ownership model

`PhantomSession` is `Arc<Self>` from construction (cheap clones; all methods take `&self`).
The lower-level `Session` flows from the handshake into the data-pump task as `Arc<Session>`.
Migration state (`peer`/`socket`/`candidate`) lives behind `ArcSwap` inside the concrete UDP
transport, swapped atomically without touching the generic pump. `CryptoState`,
`HandshakeServer/Client`, and `Session.resumption_secret` are `ZeroizeOnDrop`. The
`Session.traffic_secret` rekey-master is zeroized in `impl Drop for Session` (and in place
on each rekey), and the handshake `shared_secret` copy lives in a `Zeroizing` wrapper — both
are now wiped (T5.1), closing the former audit gap.

---

## 8. Wire framing

- **PhantomUDP** (primary): `[flags: u8][cid: 8]` envelope + fragmentation to
  `PATH_MTU = 1200`; reassembled before parsing the inner `PhantomPacket`.
- **TCP** (`TcpSessionTransport`): a 4-byte big-endian length prefix per `PhantomPacket`,
  capped per phase — `HANDSHAKE_FRAME_CAP = 64 KiB` bounds the unauthenticated handshake
  frame, `STEADY_STATE_FRAME_CAP = 4 MiB` once established. *(The legacy KCP and FakeTLS
  legs were removed; TLS HTTP-mimicry shipped as the optional `mimicry` feature —
  `MimicTlsLeg` / `bind_mimic` / `connect_pinned_mimic` — a framing-only, anti-DPI-only
  outer wrapper detectable by active probing; see PROTOCOL.md § 9.1.)*

The inner `PhantomPacket` wire image is one bare packet, `header(15) ‖ payload`
— there are **no** cleartext length prefixes (the v5 `payload_len` / `ext_len` `u32`
prefixes were dropped as a structural fingerprint, and `extensions` is off the data-plane
wire). The 47-byte figure is the reconstructed **AEAD AAD image** only, not the on-wire
header (PROTOCOL.md § 4.1 / § 4.2). `from_wire` is bounds-checked and overflow-safe.

---

## 9. Error propagation

Errors flow upward as typed `CoreError` (UniFFI-exported) at the API boundary; internally
as module-level enums (`HandshakeError`, `CryptoError`, `WireError`). Conversions are
mechanical `From` impls. The recv/handshake/data-plane hot paths carry **no**
`unwrap`/`expect`/`panic`/`unreachable` (`#![deny(clippy::unwrap_used, …)]`; the 23
inventoried production panic sites are documented in `docs/security/panic-sites.md`,
and `scripts/check_panic_sites.py` fails CI when the inventory and the code disagree).
A wrong-key / wrong-AAD / wrong-PN failure all surface as a single opaque "decrypt failed".

---

## 10. Performance landmarks

| Module | Why hot | What we did |
| --- | --- | --- |
| `run_data_pump` (recv) | Every inbound packet | Unbounded delivery-queue decoupling; authenticated SACK ACK; the 10 ms tick also runs the (cheap) liveness sweep |
| `send_app_data` | Every outbound packet | Pre-sized buffers; PN drawn once at send (nonce never reused) |
| `session.rs::encrypt/decrypt_packet` | Per packet | Lock-free `ArcSwap` `CryptoState` load; nonce from the authenticated header |
| `pacer.rs` + `bandwidth_estimator.rs` | Every outbound packet | Userspace token-bucket pacing at the BBR-estimated rate; no kernel pacing offload (the `SO_MAX_PACING_RATE` module was deleted unreachable) |
| `adaptive_crypto.rs` | Per AEAD op | HW-AES detection; ring/aws-lc optimized paths |
| `observability/atomics.rs` | Per packet record | Lock-free `CachePadded` atomics (~2.5 ns/call) |

Per-packet wire overhead is **31 bytes** (the 15-byte on-wire header + the 16-byte AEAD
tag) — the 32-byte `session_id` is **off the wire** (AAD only, reconstructed from session
context) and there are **no** cleartext length prefixes (dropped in WIRE v6, § 8). The
header-protection phase that delivered this — QUIC-style header masking, the rotating CID
chain, and the wire diet — is **shipped**, not future (PROTOCOL.md § 4.2 / § 4.6 / § 4.7).

---

## 11. Module dependency map

```
                api/  session · stream · identity · listener · tcp_transport · udp_listener · udp_transport
                  │
                  ▼
            transport/  session · handshake · stream · sack · path · liveness · types
                        phantom_udp/{envelope,datagram} · scheduler · pacer · bandwidth_estimator · legs/*
                  │
                  ▼
              crypto/  hybrid_kem · hybrid_sign · adaptive_crypto · kdf · rng · self_tests · pow
                  │
                  ▼
            standard / OS crates only

   security/ (replay_window)   runtime/ (Runtime trait)   observability/ (OTel)   ── siblings of transport/
```

---

## 12. The `runtime/` module

A `Runtime` trait (`spawn` / `sleep` / `now_monotonic` / `now_wall_clock`) between the
data plane and the concrete async runtime. Default `TokioRuntime` (native, zero-cost).
`WasmRuntime` (browser, `spawn_local` + `Performance.now()`), `WasiRuntime` (WASI P2,
single-task `drive()` executor), and an `EmbeddedRuntime` scaffold all implement the same
trait, injected via the builders' `.runtime(Arc<dyn Runtime>)` setter (`SessionBuilder` /
`ListenerBuilder` / `UdpListenerBuilder`); two Rust-only shims survive —
`PhantomSession::connect_with_transport_with_runtime` and `PhantomListener::bind_with_runtime`.
Runtime injection is Rust-only; UniFFI entry points stay on `TokioRuntime`.
`SpawnHandle` is the runtime-agnostic `JoinHandle` equivalent (`abort` / `is_finished`).

---

## 13. Evolution & known hardening backlog

- **Phase 3** (portability): the `Runtime` trait + WASM/WASI/embedded backends — **landed**;
  `wasm32-unknown-unknown` / `wasm32-wasip2` / `thumbv7em-none-eabihf` are hard CI gates.
- **Phase 4** (connection migration & liveness, P4.0–P4.4): the per-direction `u64` PN
  (retiring the C1 nonce-reuse hazard), server-side path detection + challenge, the peer
  switch + client `migrate()` + dual-socket overlap, and the liveness state machine — **all
  shipped** (see § 4 and PROTOCOL.md §12).
- **Phase 5** (`fips`): the aws-lc-rs FIPS-140-3 substrate swap — **shipped**.
- **Phase 8** (observability): the OpenTelemetry refactor (`observability/`) replaced the
  Phase-4.5 hand-rolled metrics — **shipped**.
- **Unlinkable migration (ε / WIRE v4→v5→v6):** header protection (whole-header XOR mask,
  PN included), the inner `session_id` removed from the wire, and a rotating CID chain —
  **shipped**, making a migration by either peer unlinkable in both directions (EPS-02
  closed). See PROTOCOL.md § 4.2 / § 4.6 / § 4.7 / § 12.5.
- **Pre-1.0 remediation backlog** (from the 2026-06-11 security audit and a spec review):
  PhantomUDP pre-auth DoS bounding (demux `routes` cap, cookie-before-slot, reorder-byte
  budget + `MAX_STREAMS`), authentication-ordering fixes (encrypted FIN, AEAD-bound migration
  candidate, reputation validity/poisoning), ICMP-as-advisory, passive-NAT-rebind recovery,
  master-secret zeroization, KEM-combiner ct/pk binding, `extensions`-in-AAD, MSRV/CI, and the
  ML-KEM/ML-DSA NIST-KAT gate. See `docs/security/audit-report-2026-06-11.md` and
  `CHANGELOG.md`.

The four-layer split (api / transport / crypto / runtime, with security & observability
siblings) keeps each of these self-contained.
