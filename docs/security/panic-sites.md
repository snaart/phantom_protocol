# Panic-Site Inventory

Tracked, audited list of every production code path in `core/src` that can
abort the process: `unwrap()` / `expect()` / `panic!()` / `unreachable!()`,
plus the handful of implicit panics (slice indexing, unchecked subtraction)
whose reasoning was worth writing down. Each one carries an inline
`// PANIC-SAFETY:` comment naming the invariant that makes it unreachable,
and each such comment gets exactly one row below.

Test code is out of scope — `expect_used` is relaxed inside `#[cfg(test)]` on
purpose, so failures surface as readable diagnostics.

The crate's `#![deny(clippy::unwrap_used, clippy::expect_used, …)]` (see
`core/src/lib.rs`) means a new panic site needs an explicit `#[allow(...)]`
next to the comment, which keeps the list small and reviewed. One module is
outside that net: `runtime/wasm_runtime.rs` is `#[cfg(target_arch =
"wasm32")]`, which the native `clippy` job never compiles and the `wasm32`
cross job only `cargo check`s. Its row carries the rationale but no
statement-level `#[allow]`.

**Rows are keyed on file and enclosing function, never on a line number.**
A line number in a checked-in document goes wrong the moment anyone inserts a
statement above it, and goes wrong *silently* — it still resolves, just to
unrelated code. That is exactly how this file drifted: it claimed nineteen
rows against twenty marked sites, and not one of its `stream.rs` line numbers
pointed at the code it described.

`scripts/check_panic_sites.py` now re-derives the inventory from the source
and fails when the two disagree — see "Maintaining this file" below.

This file enumerates **23** production panic sites (rows): 13 always-on, 3
fips-only (gated on `feature = "fips"`), 5 wasi-only (`feature = "wasi-leg"` +
`cfg(target_os = "wasi")`), 1 embedded-runtime-only (`feature = "embedded"` +
`std`), and 1 browser-wasm-only (`cfg(target_arch = "wasm32")`). Counting
individual calls rather than rows, three rows cover several calls each (rows
1, 2 and 10, two calls each except row 10's three).

## Sites

| # | File | Function | Build | Call | Invariant |
| --- | --- | --- | --- | --- | --- |
| 1 | `core/src/crypto/hybrid_kem.rs` | `generate` | fips | `PrivateKey::generate(&ECDH_P256).expect(...)` + `sk.compute_public_key().expect(...)` (×2) | `aws_lc_rs::agreement::PrivateKey::generate` only fails when the AWS-LC CTR_DRBG itself returns an error — the same unrecoverable condition that makes `getrandom` failure (row 4) a panic. `compute_public_key` on a freshly-generated valid P-256 private cannot fail. `HybridSecretKey::generate` returns `(Self, HybridKeyPackage)` infallibly (no `Result`), so error propagation here would be an API break; loud panic matches the row 4 convention. (Added in the FIPS primitive swap.) |
| 2 | `core/src/crypto/kdf.rs` | `derive_early_data_keying` | always | `hk.expand(EARLY_DATA_{KEY,NONCE}_INFO, ...).expect(...)` (×2) | `Hkdf::expand` only fails when the requested output length exceeds 255 × HashLen (= 8160 bytes for SHA-256). The two outputs here are 32 bytes (AEAD key) and 12 bytes (AEAD nonce), both compile-time constants far below the ceiling. (Added Phase 4.1 alongside the V3 0-RTT early-data keying.) |
| 3 | `core/src/crypto/kdf.rs` | `derive_key_32` | fips | `hk.expand(label.as_bytes(), &mut out).expect(...)` | HKDF-SHA256 `expand` only errors when output length exceeds 255 × HashLen = 8160 bytes for SHA-256. `derive_key_32` requests exactly 32 bytes — far below the ceiling. (Added in the FIPS primitive swap.) |
| 4 | `core/src/crypto/rng.rs` | `fill_bytes` | always | `fill(dest).expect("OS RNG (getrandom) failed")` (the non-fips `impl RngProvider for OsRng`) | `getrandom` only fails when the OS CSPRNG itself is broken or unavailable — an unrecoverable condition at this layer. Panicking loudly is preferable to silently producing zeros or propagating a partially-filled buffer that the caller would treat as good entropy. (Added Phase 3.8 with the `RngProvider` trait extraction.) |
| 5 | `core/src/crypto/rng.rs` | `fill_bytes` | fips | `rng.fill(dest).expect("AWS-LC CTR_DRBG fill failed")` (the `#[cfg(feature = "fips")]` impl of the same trait) | `aws_lc_rs::rand::SystemRandom::fill` only fails when the AWS-LC CTR_DRBG itself is broken or in a self-test-failed state — unrecoverable at this layer. Direct fips-build analogue of row 4; same panic-loud-rather-than-silent-zeros policy. (Added in the FIPS primitive swap.) |
| 6 | `core/src/runtime/embedded_runtime.rs` | `poll` | embedded + std | `self.inner.lock().expect("SleepFuture mutex poisoned")` (in `impl Future for SleepFuture`) | The `std::sync::Mutex` is private to this `SleepFuture` and its parker thread, neither of which panics while holding it. A `PoisonError` would indicate an unrecoverable runtime bug, not adversary input. (`EmbeddedRuntime` is the std-backed scaffold; bare-metal embedders ship their own runtime.) |
| 7 | `core/src/runtime/wasi_runtime.rs` | `drive` | wasi | `self.inner.tasks.lock().expect("WasiRuntime task queue mutex poisoned")` | The mutex is a `std::sync::Mutex` over the private `tasks: Vec<TaskSlot>` field of `WasiInner`. Only ever held briefly inside `drive`, `spawn` and `tasks_pending`. A poison would mean a panic occurred inside one of those calls — by which point the runtime state is unrecoverable. (Added alongside the `wasi-leg` feature; mirrors the `EmbeddedRuntime` mutex pattern.) |
| 8 | `core/src/runtime/wasi_runtime.rs` | `spawn` | wasi | same `.expect(...)` on the `tasks` mutex | Same mutex and argument as row 7; the write path that pushes a `TaskSlot`. |
| 9 | `core/src/runtime/wasi_runtime.rs` | `tasks_pending` | wasi | same `.expect(...)` on the `tasks` mutex | Same mutex and argument as row 7; query-only path. |
| 10 | `core/src/runtime/wasm_runtime.rs` | `sleep` | browser wasm | `Reflect::get(global, "setTimeout")`, the `dyn_into::<Function>()` cast, and the `call2` invocation (×3) | Resolving `setTimeout` off the JS global drives `sleep` without the `web-sys` `Window` feature. All three only fail if the host is not a browser/Web-Worker context (no `setTimeout` on the global, or it is not callable) — a structural mis-deployment of the wasm artifact, not adversary input, and unrecoverable at the runtime layer. The native build never compiles this module. (No statement-level `#[allow]` — see the note above; the module is not clippy-linted.) |
| 11 | `core/src/transport/fragmentation.rs` | `process_chunk` | always | `self.assemblies.remove(&key).unwrap()` | The `is_complete` branch above just inserted the entry under `key` via `entry(key).or_insert(...)`; the function holds `&mut self`, so nothing else can remove it before this line. |
| 12 | `core/src/transport/fragmentation.rs` | `process_chunk` | always | `state.chunks.get(&i).unwrap()` | The preceding loop returned early if any chunk `i` in `0..total_chunks` was missing. Reaching this loop proves every index is present. |
| 13 | `core/src/transport/legs/wasi.rs` | `send_bytes` | wasi | `self.output.lock().expect("WasiLeg output mutex poisoned")` | The mutex is a `std::sync::Mutex<OutputStream>` over a private field of `WasiLeg`, constructed once in `connect()` and never replaced. Only held by `send_bytes`. A poison would only arise from a panic inside an earlier `send_bytes` call — the underlying WASI `OutputStream` is then in an indeterminate state and not recoverable. |
| 14 | `core/src/transport/legs/wasi.rs` | `recv_bytes` | wasi | `self.read.lock().expect("WasiLeg read mutex poisoned")` | Same shape as row 13; the mutex covers `(InputStream, BytesMut)` so the per-direction accumulator's lifetime tracks the reader's. Only held by `recv_bytes`. |
| 15 | `core/src/transport/sack.rs` | `to_wire` | always | `range_count.min(u16::MAX as usize) as u16` (no explicit panic call) | The only row here that cannot panic at all: the `min` makes the cast saturate instead of truncating, so an oversized `Vec` yields a saturated count rather than silently dropping ranges. Kept as a row because the reasoning belongs to the same audit surface as its two neighbours. |
| 16 | `core/src/transport/sack.rs` | `to_wire` | always | `self.ranges[0]` (no explicit panic call) | `ranges` is a private field and every constructor leaves it non-empty: `from_received` and `from_inclusive_ranges` both return `None` on an empty result, and `from_wire` rejects `range_count == 0`. The index cannot be out of bounds. |
| 17 | `core/src/transport/sack.rs` | `to_wire` | always | `first_high - first_low` (no explicit panic call) | Every stored range satisfies `low ≤ high` — the two building constructors derive them from sorted, coalesced sequences and `from_wire` validates the ordering before storing — so the `u32` subtraction cannot underflow. |
| 18 | `core/src/transport/sack.rs` | `from_ascending_coalesced` | always | `*asc_ranges.last().unwrap()` | Reached only inside `if asc_ranges.len() > MAX_SACK_RANGES`, so the vector holds more than 32 elements and `last()` cannot be `None`. (Added with the reduce-from-the-middle policy, which keeps the cumulative run and the lowest range when an over-long set has to be cut down.) |
| 19 | `core/src/transport/stream.rs` | `send_reliable` | always | `send_semaphore.acquire().await.expect("Semaphore closed")` | `Semaphore::acquire` only errors after `close()`. `send_semaphore` is a private field of `Stream`, constructed once in `new()` and never closed anywhere in the crate. Structurally unreachable. |
| 20 | `core/src/transport/stream.rs` | `queue_fin` | always | `send_semaphore.acquire().await.expect("Semaphore closed")` | Identical invariant to row 19 — `queue_fin` takes a backpressure permit from the same private, never-closed semaphore. |
| 21 | `core/src/transport/stream.rs` | `on_sack` | always | `sack.acks(buffer.get(i).unwrap().stream_offset)` | `i < buffer.len()` is the enclosing `while` loop guard, so the index is in range and `get` cannot return `None`. |
| 22 | `core/src/transport/stream.rs` | `on_sack` | always | `buffer.remove(i).unwrap()` | Same loop guard as row 21 — `i` is an in-range index, so `VecDeque::remove` returns `Some`. The buffer is locked across the SACK scan, so no concurrent drain. |
| 23 | `core/src/transport/stream.rs` | `accept_in_order` | always | `buf.remove(pos).unwrap()` | `pos` is the value just returned by `buf.iter().position(...)`, so the element exists. `recv_buf` is locked across the read and the remove, so no other task can drain it in between. |

Several functions hold more than one site — `process_chunk`, `to_wire`,
`on_sack` — and each gets its own row. The guard compares counts per
function, so deleting one site of a group still fails the check.

## Unsafe Blocks

The crate is `#![deny(unsafe_code)]` at the root (`core/src/lib.rs`). Three
modules opt in with module-level `#![allow(unsafe_code)]` plus per-block
`// SAFETY:` comments:

| Module | Why `unsafe` |
| --- | --- |
| `core/src/transport/udp_transport.rs` | A single `libc::setsockopt` call in `set_pacing_rate` (Linux `SO_MAX_PACING_RATE`, with the `fq` qdisc). The block has a SAFETY line explaining the fd, option-value pointer, and length-argument invariants. The earlier dead `sendmmsg(2)` GSO-batch path (the only user of `libc::sendmmsg` / `libc::mmsghdr` / `MaybeUninit::zeroed`) was removed in the unsafe-surface reduction. Native (`cfg(not(target_arch = "wasm32"))`) only. |
| `core/src/transport/legs/websocket.rs` | wasm-bindgen-generated JS-boundary glue (`#[wasm_bindgen]` extern blocks). `wasm32-*` browser target only (`cfg(all(target_arch = "wasm32", target_os = "unknown"))`). |
| `core/src/transport/legs/wasi.rs` | `unsafe impl Send` + `unsafe impl Sync` for `WasiLeg`. The WIT-bindgen `Resource<TcpSocket>` / `Resource<InputStream>` / `Resource<OutputStream>` types hide an opaque numeric host handle and are `!Send + !Sync` by default. The internal `std::sync::Mutex` wrappers enforce single-accessor discipline; the unsafe impl is the contract that any cross-thread access goes through that mutex. WASI Preview 2 today provides no thread primitive, so the contract is vacuously satisfied — the explicit `unsafe impl` (plus the SAFETY block in the file) keeps the argument auditable if a future WASI threading proposal stabilizes. `cfg(all(feature = "wasi-leg", target_os = "wasi"))` only. |

The pre-Phase-5.1 opt-in `core/src/crypto/keys.rs` was deleted when the crate
moved off `pqcrypto-internals` (see commit `7c7bde7`). The pure-Rust RustCrypto
swap (`ml-kem` / `ml-dsa`) eliminated the only other place `unsafe` was needed
inside `crypto/`.

## Maintaining this file

When adding a new production panic site:

1. Annotate the call with an inline `// PANIC-SAFETY:` comment that names the
   invariant making the call infallible (not "this can't happen" — say *why*).
2. Add a `#[allow(clippy::unwrap_used)]` or `#[allow(clippy::expect_used)]`
   on the immediate statement (not the function — keep the allow surface
   narrow).
3. Add a row to the table above, and bump the count in the header paragraph.
   Name the file and the enclosing function; do not add a line number.
4. If the invariant relies on a private field, name the field so future code
   review can verify nothing has weakened it.

When removing a panic site (preferred path), delete the corresponding row.

`scripts/check_panic_sites.py` enforces steps 1–3. It re-derives the inventory
from `core/src` and fails when a marked site has no row, a row names a
function that no longer exists, a function that can panic carries no marker at
all, or the header's count disagrees with the table. It runs as a
`pre-commit` hook and as the `panic-sites` CI job, and takes no arguments:

```
scripts/check_panic_sites.py
```

Deliberate limits, so nobody mistakes it for a proof: it reads text, not the
AST, so it sees only the panics that are visible as `unwrap`/`expect`/`panic!`
/`unreachable!`/`todo!`/`unimplemented!` calls or as a lint suppression. An
implicit panic — an index, a subtraction — is invisible to it unless someone
marks it, which is why rows 15 and 16 exist. It also checks per function
rather than per call, so a second unmarked panic added to a function that
already has a marker will not be caught. Both gaps are for review to close,
not the script.

## Adversarial review checklist

When auditing this list during a security review:

- For each site, can an attacker influence any value involved in the
  invariant? If yes, the site **must** be converted to error propagation.
- For sites that depend on a private field's lifecycle, has anyone added a
  way to drop/close/replace that field since the comment was written?
- For ring/library panic-on-overflow sites: has the upper bound on input
  size been verified at every call site (framing layer, MTU clamping)?
