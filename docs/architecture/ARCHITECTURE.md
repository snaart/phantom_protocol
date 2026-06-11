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
else in the crate. `security/`, `runtime/`, and `observability/` are siblings to
`transport/` and depend only on `crypto/` helpers + `std`/OS crates (the
`session_transport` trait and `legs/embedded` are `no_std + alloc`-clean).

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
| `ConnectionState` | Lifecycle enum: `Connecting`/`ClassicalReady`/`PqcUpgrading`/`PqcReady`/`Connected`/`Failed`/`Closed`/**`Migrating`**/**`Dead`** | Yes (`uniffi::Enum`) |
| `ResumptionHint` | 0-RTT `(session_id, resumption_secret)` record (redacting `Debug`) | Yes (`uniffi::Record`) |
| `PhantomConfig` | User-tunable knobs | Yes (`uniffi::Record`) |
| `SessionTransport` (trait) | Byte-pipe abstraction below the encryption layer; SocketAddr-free migration hooks (`has_migration_candidate` / `send_to_candidate` / `promote_candidate` / `migrate`) | No (Rust trait) |

Free functions exported for mobile/FFI: `connect_pinned`, `connect_pinned_with_resumption`.

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
    ──── encrypted PhantomPacket frames (WIRE 3) ─────────►
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
(one function, three concurrent units):

- **Delivery task** — drains the unbounded `deliver_rx` queue, paces `recv_tx.send()`,
  decrements `undelivered_bytes`, and stages flow-control (`WINDOW_UPDATE`) credit.
  Decoupling lets the reader never block on a slow consumer.
- **Reader task** — loops `transport.recv_bytes() → PhantomPacket::from_wire → handle_packet()`.
  `handle_packet` binds every frame to the negotiated `session_id`, decrypts (the
  `ENCRYPTED` gate, with a single authenticated forward-rekey catch-up step), then
  dispatches: authenticated **SACK ACK** (`ENCRYPTED|ACK`, post-AEAD — the H1 fix),
  `WINDOW_UPDATE`, `PATH_VALIDATION` (migration), `COALESCED`, and reliable data
  (gap-free `stream_offset` reassembly). Inbound that passes AEAD calls
  `update_activity()` (the liveness signal).
- **Main `select!` loop** picks among:
  - `poll_interval.tick()` (10 ms) — drains streams, flushes `WINDOW_UPDATE`s, and runs
    the **liveness sweep** (`apply_liveness`).
  - `send_notify.notified()` — event-driven outbound-ready fast path.
  - `cmd_rx.recv()` — `SessionCommand`s: `Send`, `SendStreamReliable/Unreliable`,
    `CloseStream`, **`Migrate(local_addr)`**, `Close`.
  - `recv_done_rx` — exit when the reader ends (transport closed).

---

## 3. Transport / protocol layer (`core/src/transport/`)

### Types

| Type | Role |
| --- | --- |
| `Session` | Per-association state: `id`, AEAD `CryptoState` (`ArcSwap`, rekey-swappable), `traffic_secret`, `epoch` (`AtomicU8`, saturates), the **`send_packet_number: AtomicU64`** (the per-direction nonce + replay identity — ① / P4.0), `send_path_id: AtomicU8` (client-owned migration label), one per-direction `recv_replay: Mutex<ReplayWindow>`, `path_registry: Arc<PathRegistry>`, `liveness_config`, `pacer`, `bandwidth_estimator`, `scheduler`, streams. |
| `CryptoState` | Per-direction AEAD keying (`CryptoSession`) + 32-byte `session_key` for further HKDF. `ZeroizeOnDrop`. Swapped wholesale on rekey via `ArcSwap`. |
| `HandshakeServer` | Long-lived signing key + master secret (cookie/PoW), per-IP `ReputationTracker`. Per-process. `ZeroizeOnDrop`. |
| `HandshakeClient` | Per-connection **ephemeral** state — hybrid KEM key pair, signing key pair, nonce. `ZeroizeOnDrop`. |
| `Stream` | Per-stream send/recv buffers, the gap-free **`stream_offset: u32`** (A.5 reliability layer), `RtoEstimator` (RFC 6298), reorder buffer, SACK-driven retransmit. |
| `Sack` | Authenticated ACK payload: `largest_acked: u32`, `ack_delay_us: u32`, inclusive received ranges — over `stream_offset`, **not** the wire packet number (the layer split). |
| `PathRegistry` | Per-session path lifecycle (`Unvalidated → Validating → Validated/Failed`), constant-time challenge/response (Invariant 6), `retire` for `path_id` reuse. |
| `liveness` | Pure `liveness_verdict()` (PathDown / Recovered / Dead) + `LivenessConfig` thresholds. |
| `PathRegistry`/`Scheduler` | Path selection / migration state (migration is **shipped** — see § 4; the `Scheduler` does per-leg RTT/loss tracking). |
| `PacketHeader` / `PhantomPacket` | Wire types (47-byte header; § PROTOCOL.md). |
| `phantom_udp/{envelope,datagram}` | The PhantomUDP `[flags][cid]` envelope + fragmentation/reassembly to `PATH_MTU`. |
| `legs/{websocket,wasi,embedded}` | `SessionTransport` impls (browser / WASI / bare-metal). |
| `BufferPool`, `Pacer`, `PacketCoalescer`, `BandwidthEstimator` (BBR) | Performance infrastructure. |

### Encryption boundary

Every byte that crosses `Session::encrypt_packet` / `decrypt_packet` is
authenticated with the **47-byte** `PacketHeader` as AAD. The AEAD nonce is
`nonce_prefix(4) ‖ packet_number(8)` — the per-direction monotonic `u64` packet
number drawn at send time (① / P4.0). `epoch`/`stream_id`/`path_id` are in the
AAD but **not** the nonce.

```rust
fn build_packet_nonce(prefix: [u8;4], header: &PacketHeader) -> [u8;12] // prefix ‖ packet_number_be
pub fn encrypt_packet(&self, header: &PacketHeader, pt: &[u8]) -> Result<Vec<u8>, CoreError> {
    let nonce = Self::build_packet_nonce(self.crypto.load().nonce_prefix(), header);
    // AAD = header.to_wire()  (47 bytes)
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

`transport/liveness.rs` is a pure decision (`liveness_verdict`); the pump's 10 ms tick
feeds it `(silence, inflight, min_rtt, migrating_since)`:

- **PathDown** — *N×PTO of inbound silence while reliable data is outstanding* →
  `ConnectionState::Migrating` (keys held, outbound buffered; the embedder reacts by
  calling `migrate()`).
- **Recovered** — inbound resumes → back to `Connected`.
- **Dead** — no recovery before the migration-idle timeout → terminal `Dead`, the pump
  ends, `recv()` errors (not a hang).

`update_activity()` is called only on **AEAD-authenticated** inbound, so a forged/replayed
packet cannot mask a dead path or reset the timer. The same pump runs on both peers, so a
server detects a vanished client symmetrically.

### The layer split (① + A.5)

- **Packet layer:** the per-direction monotonic `u64` `packet_number` — the AEAD nonce +
  anti-replay identity. Assigned at send time; a retransmit draws a fresh PN.
- **Stream layer:** the gap-free per-stream `u32` `stream_offset` in the reliable AEAD
  plaintext — feeds reassembly, SACK, loss detection, retransmit dedup.

> Migration is **functional but linkable** via the stable plaintext CID (documented
> honestly in PROTOCOL.md §12.5); unlinkable migration (header protection + CID rotation)
> is a deferred hardening phase.

---

## 5. Cryptography layer (`core/src/crypto/`)

| Module | Type | Role |
| --- | --- | --- |
| `hybrid_kem` | `HybridSecretKey`, `HybridKeyPackage`, `HybridCiphertext` | X25519 + ML-KEM-768 (FIPS 203); ECDH-P-256 + ML-KEM-768 under `fips`. `ZeroizeOnDrop` on secrets. Combiner = `HKDF-SHA256(ss_classical ‖ ss_pq)` under a domain label. |
| `hybrid_sign` | `HybridSigningKey`, `HybridVerifyingKey`, `HybridSignature` | Ed25519 (`verify_strict`) + ML-DSA-65 (FIPS 204); both halves must verify. `ZeroizeOnDrop`. |
| `adaptive_crypto` | `CryptoSession`, `CipherSuite`, `HwCaps` | AES-256-GCM / ChaCha20-Poly1305 with the `prefix ‖ packet_number` nonce; HW auto-select (AES-NI → AES). `aws-lc-rs` backend + ChaCha rejected under `fips`. |
| `kdf` | side-agnostic `derive_key_32` + early-data keying | `blake3::derive_key` (default) / `HKDF-SHA256` (`fips`). |
| `rng` | `RngProvider` + `OsRng` | `getrandom` default; `aws-lc-rs` CTR_DRBG under `fips`. |
| `self_tests` | `run_post` / `ensure_post_passed` | FIPS 140-3 §7.7 power-on self-tests; auto-invoked under `fips` before any handshake (Invariant 11). |
| `aes_session` | `AesSession` | Reference per-direction AEAD pattern. |
| `pow` | `PoWChallenge`, `PoWSolution` | blake3 PoW + stateless cookie DoS gate (constant-time MAC compare). |

`#![deny(unsafe_code)]` at the crate root; three audited, sound opt-ins:
`transport/udp_transport.rs` (libc GSO/`recvmmsg`), `transport/legs/wasi.rs`
(`unsafe impl Send/Sync` over WIT-bindgen handles), `transport/legs/websocket.rs`
(wasm-bindgen JS glue). No `unsafe` in `crypto/`.

---

## 6. Concurrency model

**Task topology per session: three spawned units** (main `select!` loop + delivery
task + reader task), communicating via `mpsc` channels + `Arc<…>` shared state.

```
PhantomSession (Arc) ── cmd_tx ──► run_data_pump select! loop ── drain/flush/apply_liveness (10ms) ──► transport.send_bytes
       ▲ recv_rx ◄── delivery task ◄── deliver_rx (unbounded) ◄── reader task: recv_bytes → handle_packet → AEAD → replay → dispatch
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
`HandshakeServer/Client`, and `Session.resumption_secret` are `ZeroizeOnDrop`. *(Audit gap:
the `Session.traffic_secret` rekey-master and the handshake `shared_secret` copy are **not**
yet zeroized — tracked in the pre-1.0 remediation plan.)*

---

## 8. Wire framing

- **PhantomUDP** (primary): `[flags: u8][cid: 8]` envelope + fragmentation to
  `PATH_MTU = 1200`; reassembled before parsing the inner `PhantomPacket`.
- **TCP** (`TcpSessionTransport`): a 4-byte big-endian length prefix per `PhantomPacket`,
  capped at `MAX_FRAME_BYTES = 16 MiB`; a tight `HANDSHAKE_FRAME_CAP` bounds the
  unauthenticated handshake frame. *(The legacy KCP and FakeTLS legs were removed; FakeTLS
  HTTP-mimicry will return as a dedicated transport mode.)*

The inner `PhantomPacket` wire image is one bare packet (`header(47) ‖ payload_len:u32be ‖
payload ‖ ext_len:u32be ‖ extensions`); `from_wire` is bounds-checked and overflow-safe.

---

## 9. Error propagation

Errors flow upward as typed `CoreError` (UniFFI-exported) at the API boundary; internally
as module-level enums (`HandshakeError`, `CryptoError`, `WireError`). Conversions are
mechanical `From` impls. The recv/handshake/data-plane hot paths carry **no**
`unwrap`/`expect`/`panic`/`unreachable` (`#![deny(clippy::unwrap_used, …)]`; the 16
inventoried production panic sites are documented in `docs/security/panic-sites.md`).
A wrong-key / wrong-AAD / wrong-PN failure all surface as a single opaque "decrypt failed".

---

## 10. Performance landmarks

| Module | Why hot | What we did |
| --- | --- | --- |
| `run_data_pump` (recv) | Every inbound packet | Unbounded delivery-queue decoupling; authenticated SACK ACK; the 10 ms tick also runs the (cheap) liveness sweep |
| `send_app_data` | Every outbound packet | Pre-sized buffers; PN drawn once at send (nonce never reused) |
| `session.rs::encrypt/decrypt_packet` | Per packet | Lock-free `ArcSwap` `CryptoState` load; nonce from the authenticated header |
| `udp_transport.rs` | UDP fast path | GSO / `sendmmsg` on Linux |
| `adaptive_crypto.rs` | Per AEAD op | HW-AES detection; ring/aws-lc optimized paths |
| `observability/atomics.rs` | Per packet record | Lock-free `CachePadded` atomics (~2.5 ns/call) |

Per-packet overhead is 71 bytes (47-byte header incl. a 32-byte plaintext `session_id`, +8
length, +16 AEAD tag) — heavy for small/voice payloads; the future header-protection phase
(QUIC-style PN encryption + shorter/rotated CID) is the lever.

---

## 11. Module dependency map

```
                api/  session · listener · udp_listener · udp_transport · stream · config · tcp_transport
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
trait, injected via the `_with_runtime` constructor variants (UniFFI stays on `TokioRuntime`).
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
- **Deferred hardening:** unlinkable migration (header protection / PN encryption + CID
  rotation) — the `u64` PN and single PN space are HP-ready by design.
- **Pre-1.0 remediation backlog** (from the 2026-06-11 security audit + external spec review):
  PhantomUDP pre-auth DoS bounding (demux `routes` cap, cookie-before-slot, reorder-byte
  budget + `MAX_STREAMS`), authentication-ordering fixes (encrypted FIN, AEAD-bound migration
  candidate, reputation validity/poisoning), ICMP-as-advisory, passive-NAT-rebind recovery,
  master-secret zeroization, KEM-combiner ct/pk binding, `extensions`-in-AAD, MSRV/CI, and the
  ML-KEM/ML-DSA NIST-KAT gate. See `docs/security/audit-report-2026-06-11.md` and the
  consolidated remediation plan.

The four-layer split (api / transport / crypto / runtime, with security & observability
siblings) keeps each of these self-contained.
