# Panic-Site Inventory

Tracked, audited list of every `unwrap()` / `expect()` / `panic!()` /
`unreachable!()` left in **production** code paths (everything under
`core/src/` outside of `#[cfg(test)] mod tests` and `#[cfg(test)] fn …`
helpers). Each site carries an inline `PANIC-SAFETY:` comment explaining the
invariant that makes the call infallible.

Test-module panics are intentionally not enumerated here — `expect_used` is
permitted in tests so failures surface as readable diagnostics.

The crate's `#![deny(clippy::unwrap_used, clippy::expect_used, …)]` (see
`core/src/lib.rs`) ensures any new panic site needs an explicit
`#[allow(...)]` annotation alongside the safety comment, keeping the list
small and reviewed. (Exception: the `wasm_runtime.rs` sites below are inside
a `#[cfg(target_arch = "wasm32")]` module that the native `clippy` CI job
never compiles and the `wasm32` cross job only `cargo check`s, so they carry
the `PANIC-SAFETY` rationale here but no statement-level `#[allow]`.)

This file enumerates **18** production panic sites (rows): 8 always-on, 3
fips-only (gated on `feature = "fips"`), 5 wasi-only (`feature = "wasi-leg"` +
`cfg(target_os = "wasi")`), 1 embedded-runtime-only (`feature = "embedded"` +
`std`), and 1 browser-wasm-only row (`cfg(target_arch = "wasm32")`, three
`.expect` calls). Counting individual calls rather than rows, two rows cover
multiple sites (row 10 = 2 calls, row 11 = 2 calls, row 12 = 3 calls).

## Sites

| # | File | Line | Call | Invariant |
| --- | --- | --- | --- | --- |
| 1 | `core/src/transport/stream.rs` | 619 | `send_semaphore.acquire().await.expect("Semaphore closed")` | `Semaphore::acquire` only errors after `close()`. `send_semaphore` is private to `Stream`, constructed once in `new()`, and never closed anywhere in the crate. Structurally unreachable. |
| 2 | `core/src/transport/stream.rs` | 875 | `sack.acks(buffer.get(i).unwrap().stream_offset)` | `i < buffer.len()` is the enclosing `while` loop guard, so the index is in range and `get` cannot return `None`. |
| 3 | `core/src/transport/stream.rs` | 880 | `buffer.remove(i).unwrap()` | Same loop guard as site #2 — `i` is an in-range index, so `VecDeque::remove` returns `Some`. The buffer is locked across the SACK scan, so no concurrent drain. |
| 4 | `core/src/transport/stream.rs` | 1020 | `buf.remove(pos).unwrap()` | `pos` is the value just returned by `buf.iter().position(...)`, so the element exists. `recv_buf` is locked across the read+remove, so no other task can drain it in between. |
| 5 | `core/src/transport/fragmentation.rs` | 113 | `self.assemblies.remove(&key).unwrap()` | The `is_complete` branch above just inserted the entry under `key` via `entry(key).or_insert(...)`; the function holds `&mut self`, so nothing else can remove it before this line. |
| 6 | `core/src/transport/fragmentation.rs` | 129 | `state.chunks.get(&i).unwrap()` | The preceding loop returned `None` early if any chunk `i` in `0..total_chunks` was missing. Reaching this loop proves every index is present. |
| 7 | `core/src/crypto/rng.rs` | 179 | `getrandom(dest).expect("OS RNG (getrandom) failed")` (default, non-fips) | `getrandom` only fails when the OS CSPRNG itself is broken or unavailable — an unrecoverable condition at this layer. Panicking loudly is preferable to silently producing zeros or propagating a partially-filled buffer that the caller would treat as good entropy. (Added Phase 3.8 with the `RngProvider` trait extraction.) |
| 8 | `core/src/crypto/rng.rs` | 200 | `rng.fill(dest).expect("AWS-LC CTR_DRBG fill failed")` (fips path only, gated on `feature = "fips"`) | `aws_lc_rs::rand::SystemRandom::fill` only fails when the AWS-LC CTR_DRBG itself is broken or in a self-test-failed state — unrecoverable at this layer. Direct fips-build analogue of site #7 (`getrandom` failure); same panic-loud-rather-than-silent-zeros policy. (Added in FIPS primitive swap.) |
| 9 | `core/src/crypto/kdf.rs` | 38 | `hk.expand(label.as_bytes(), &mut out).expect(...)` in `derive_key_32` (fips path only, gated on `feature = "fips"`) | HKDF-SHA256 `expand` only errors when output length exceeds 255 × HashLen = 8160 bytes for SHA-256. `derive_key_32` requests exactly 32 bytes — far below the ceiling. (Added in FIPS primitive swap.) |
| 10 | `core/src/crypto/kdf.rs` | 83, 86 | `hk.expand(EARLY_DATA_{KEY,NONCE}_INFO, ...).expect(...)` (×2, in `derive_early_data_keying`) | `Hkdf::expand` only fails when the requested output length exceeds 255 × HashLen (= 8160 bytes for SHA-256). The two outputs here are 32 bytes (AEAD key) and 12 bytes (AEAD nonce), both compile-time constants far below the ceiling. (Added Phase 4.1 alongside the V3 0-RTT early-data keying.) |
| 11 | `core/src/crypto/hybrid_kem.rs` | 117, 120 | `PrivateKey::generate(&ECDH_P256).expect(...)` + `sk.compute_public_key().expect(...)` (fips path only, gated on `feature = "fips"`) | `aws_lc_rs::agreement::PrivateKey::generate` only fails when the AWS-LC CTR_DRBG itself returns an error — the same unrecoverable condition that makes `getrandom` failure (site #7) a panic. `compute_public_key` on a freshly-generated valid P-256 private cannot fail. `HybridSecretKey::generate` returns `(Self, HybridKeyPackage)` infallibly (no `Result`), so error propagation here would be an API break; loud panic matches the site #7 convention. (Added in FIPS primitive swap.) |
| 12 | `core/src/runtime/wasm_runtime.rs` | 91, 94, 101 | three `.expect(...)` in `WasmRuntime::sleep`: `Reflect::get(global, "setTimeout")`, the `dyn_into::<Function>()` cast, and the `call2` invocation (browser-wasm only, `cfg(target_arch = "wasm32")`) | Resolving `setTimeout` off the JS global drives `sleep` without the `web-sys` `Window` feature. All three only fail if the host is not a browser/Web-Worker context (no `setTimeout` on the global, or it is not callable) — a structural mis-deployment of the wasm artifact, not adversary input, and unrecoverable at the runtime layer. The native build never compiles this module. (No statement-level `#[allow]` — see the note above; the module is not clippy-linted.) |
| 13 | `core/src/runtime/embedded_runtime.rs` | 191 | `self.inner.lock().expect("SleepFuture mutex poisoned")` (in `SleepFuture::poll`, `feature = "embedded"` + `std`) | The `std::sync::Mutex` is private to this `SleepFuture` and its parker thread, neither of which panics while holding it. A `PoisonError` would indicate an unrecoverable runtime bug, not adversary input. (`EmbeddedRuntime` is the std-backed scaffold; bare-metal embedders ship their own runtime.) |
| 14 | `core/src/runtime/wasi_runtime.rs` | 93 | `self.inner.tasks.lock().expect("WasiRuntime task queue mutex poisoned")` (in `drive`) | The mutex is `std::sync::Mutex` over the private `tasks: Vec<TaskSlot>` field of `WasiInner`. Only ever held briefly inside `drive`, `spawn`, and `tasks_pending`. A poison would mean a panic occurred inside one of those calls — by which point the runtime state is unrecoverable. (Added Section B alongside the `wasi-leg` feature; mirrors the `EmbeddedRuntime` mutex pattern.) |
| 15 | `core/src/runtime/wasi_runtime.rs` | 138 | same `.expect(...)` in `tasks_pending` | Same `tasks` mutex as site #14; query-only path. |
| 16 | `core/src/runtime/wasi_runtime.rs` | 152 | same `.expect(...)` in `spawn` | Same `tasks` mutex as site #14; write path that pushes a `TaskSlot`. |
| 17 | `core/src/transport/legs/wasi.rs` | 183 | `self.output.lock().expect("WasiLeg output mutex poisoned")` (in `send_bytes`) | The mutex is `std::sync::Mutex<OutputStream>` over a private field of `WasiLeg`, constructed once in `connect()` and never replaced. Only held by `send_bytes`. A poison would only arise from a panic inside an earlier `send_bytes` call — the underlying WASI `OutputStream` is then in an indeterminate state and not recoverable. (Section B.) |
| 18 | `core/src/transport/legs/wasi.rs` | 194 | `self.read.lock().expect("WasiLeg read mutex poisoned")` (in `recv_bytes`) | Same shape as site #17; mutex covers `(InputStream, BytesMut)` so the per-direction accumulator's lifetime tracks the reader's. Only held by `recv_bytes`. |

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
3. Add a row to the table above.
4. If the invariant relies on a private field, name the field so future code
   review can verify nothing has weakened it.

When removing a panic site (preferred path), delete the corresponding row.

## Adversarial review checklist

When auditing this list during a security review:

- For each site, can an attacker influence any value involved in the
  invariant? If yes, the site **must** be converted to error propagation.
- For sites that depend on a private field's lifecycle, has anyone added a
  way to drop/close/replace that field since the comment was written?
- For ring/library panic-on-overflow sites: has the upper bound on input
  size been verified at every call site (framing layer, MTU clamping)?
