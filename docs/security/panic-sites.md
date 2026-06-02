# Panic-Site Inventory

Tracked, audited list of every `unwrap()` / `expect()` / `panic!()` /
`unreachable!()` left in **production** code paths (everything under
`core/src/` outside of `#[cfg(test)] mod tests` and `#[cfg(test)] fn …`
helpers). Each site carries an inline `PANIC-SAFETY:` comment explaining the
invariant that makes the call infallible.

Test-module panics are intentionally not enumerated here — `expect_used` is
permitted in tests so failures surface as readable diagnostics.

The crate's `#![warn(clippy::unwrap_used, clippy::expect_used, …)]` (see
`core/src/lib.rs:23-31`) ensures any new panic site needs an explicit
`#[allow(...)]` annotation alongside the safety comment, keeping the list
small and reviewed.

## Sites

| # | File | Line range | Call | Invariant |
| --- | --- | --- | --- | --- |
| 1 | `core/src/transport/stream.rs` | 440-444 | `send_semaphore.acquire().await.expect("Semaphore closed")` | `Semaphore::acquire` only errors after `close()`. `send_semaphore` is private to `Stream`, constructed once in `new()`, and never closed anywhere in the crate. Structurally unreachable. |
| 2 | `core/src/transport/stream.rs` | 640-646 | `recv_buf.remove(pos).unwrap()` | `pos` is the value just returned by `recv_buf.iter().position(...)`, so the element exists. `recv_buf` is locked across the read+remove, so no other task can drain it in between. |
| 3 | `core/src/transport/fragmentation.rs` | 59-64 | `self.assemblies.remove(&key).unwrap()` | The `is_complete` branch above just inserted the entry under `key` via `entry(key).or_insert_with(...)`; the function holds `&mut self`, so nothing else can remove it before this line. |
| 4 | `core/src/transport/fragmentation.rs` | 75-80 | `state.chunks.get(&i).unwrap()` | The preceding loop returned `None` early if any chunk `i` in `0..total_chunks` was missing. Reaching this loop proves every index is present. |
| 5 | `core/src/transport/legs/faketls.rs` | 594-602 | `self.send_key.seal_in_place_append_tag(nonce, aad, &mut in_out).unwrap()` | ring's `seal_in_place_append_tag` only fails when input length + tag exceeds AES-GCM's NIST SP 800-38D invocation limit (~2^36 bytes). Phantom records are MTU-bounded (≤ 1300 + framing). Cannot occur in practice. |
| 6 | `core/src/transport/legs/faketls.rs` | 650-660 | `FakeTlsLeg::default() -> Self::new().expect(...)` | `FakeTlsLeg::new` only fails if the underlying AES key init returns an error. The seed → key derivation is deterministic over fixed inputs and never returns errors with the current `ring` API. The `Default` impl exists for ergonomic test/setup use; callers in production paths use `FakeTlsLeg::new()` directly and propagate the error. Documented with `///` doc rather than `// PANIC-SAFETY:` because the panicking call is the entire body of the `Default::default` impl, not a buried sub-expression. |
| 7 | `core/src/crypto/rng.rs` | 162-175 | `getrandom(dest).expect("OS RNG (getrandom) failed")` | `getrandom` only fails when the OS CSPRNG itself is broken or unavailable — an unrecoverable condition at this layer. Panicking loudly is preferable to silently producing zeros or propagating a partially-filled buffer that the caller would treat as good entropy. (Added Phase 3.8 with the `RngProvider` trait extraction.) |
| 8 | `core/src/crypto/kdf.rs` | 42-56 | `hk.expand(EARLY_DATA_{KEY,NONCE}_INFO, ...).expect(...)` (×2) | `Hkdf::expand` only fails when the requested output length exceeds 255 × HashLen (= 8160 bytes for SHA-256). The two outputs here are 32 bytes (AEAD key) and 12 bytes (AEAD nonce), both compile-time constants far below the ceiling. (Added Phase 4.1 alongside the V3 0-RTT early-data keying.) |
| 9 | `core/src/crypto/kdf.rs` | 31-41 | `hk.expand(label.as_bytes(), &mut out).expect(...)` in `derive_key_32` (fips path only, gated on `feature = "fips"`) | HKDF-SHA256 `expand` only errors when output length exceeds 255 × HashLen = 8160 bytes for SHA-256. `derive_key_32` requests exactly 32 bytes — far below the ceiling. (Added in FIPS primitive swap, commit `a592722`.) |
| 10 | `core/src/crypto/hybrid_kem.rs` | 110-128 | `PrivateKey::generate(&ECDH_P256).expect(...)` + `sk.compute_public_key().expect(...)` (fips path only, gated on `feature = "fips"`) | `aws_lc_rs::agreement::PrivateKey::generate` only fails when the AWS-LC CTR_DRBG itself returns an error — the same unrecoverable condition that makes `getrandom` failure (site #7) a panic. `compute_public_key` on a freshly-generated valid P-256 private cannot fail. `HybridSecretKey::generate` returns `(Self, HybridKeyPackage)` infallibly (no `Result`), so error propagation here would be an API break; loud panic matches the existing site #7 convention. (Added in FIPS primitive swap, commit `bff7262`.) |
| 11 | `core/src/crypto/rng.rs` | 196-201 | `rng.fill(dest).expect("AWS-LC CTR_DRBG fill failed")` (fips path only, gated on `feature = "fips"`) | `aws_lc_rs::rand::SystemRandom::fill` only fails when the AWS-LC CTR_DRBG itself is broken or in a self-test-failed state — unrecoverable at this layer. Direct fips-build analogue of site #7 (`getrandom` failure); same panic-loud-rather-than-silent-zeros policy. (Added in FIPS primitive swap, commit `0dcc55f`.) |
| 12 | `core/src/runtime/wasi_runtime.rs` | 83-110 | `self.inner.tasks.lock().expect("WasiRuntime task queue mutex poisoned")` (in `drive`) | The mutex is `std::sync::Mutex` over the private `tasks: Vec<TaskSlot>` field of `WasiInner`. Only ever held briefly inside `drive`, `spawn`, and `tasks_pending`. A poison would mean a panic occurred inside one of those calls — by which point the runtime state is unrecoverable. (Added Section B / B2 alongside the `wasi-leg` feature; mirrors the `EmbeddedRuntime` mutex pattern.) |
| 13 | `core/src/runtime/wasi_runtime.rs` | 133-141 | same `.expect(...)` in `tasks_pending` | Same `tasks` mutex as Site 12; query-only path. |
| 14 | `core/src/runtime/wasi_runtime.rs` | 144-160 | same `.expect(...)` in `spawn` | Same `tasks` mutex as Site 12; write path that pushes a `TaskSlot`. |
| 15 | `core/src/transport/legs/wasi.rs` | 149-168 | `self.output.lock().expect("WasiLeg output mutex poisoned")` (in `send_bytes`) | The mutex is `std::sync::Mutex<OutputStream>` over a private field of `WasiLeg`, constructed once in `connect()` and never replaced. Only held by `send_bytes`. A poison would only arise from a panic inside an earlier `send_bytes` call — the underlying WASI `OutputStream` is then in an indeterminate state and not recoverable. (Section B / B3.) |
| 16 | `core/src/transport/legs/wasi.rs` | 170-196 | `self.read.lock().expect("WasiLeg read mutex poisoned")` (in `recv_bytes`) | Same shape as Site 15; mutex covers `(InputStream, BytesMut)` so the per-direction accumulator's lifetime tracks the reader's. Only held by `recv_bytes`. |

## Unsafe Blocks

The crate is `#![deny(unsafe_code)]` at the root (`core/src/lib.rs:39`). Three
modules opt in with module-level `#![allow(unsafe_code)]` plus per-block
`// SAFETY:` comments:

| Module | Why `unsafe` |
| --- | --- |
| `core/src/transport/udp_transport.rs` | libc GSO / `recvmmsg` / `sendmmsg` syscalls — must construct `mmsghdr` via `MaybeUninit::zeroed()` and call FFI with raw fd. Each block has a SAFETY line explaining lifetime, ownership, and validity invariants. Native (`cfg(not(target_arch = "wasm32"))`) only. |
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
