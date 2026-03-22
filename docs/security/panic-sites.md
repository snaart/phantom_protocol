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
| 1 | `core/src/transport/stream.rs` | 113-122 | `send_semaphore.acquire().await.expect("Semaphore closed")` | `Semaphore::acquire` only errors after `close()`. `send_semaphore` is private to `Stream`, constructed once in `new()`, and never closed anywhere in the crate. Structurally unreachable. |
| 2 | `core/src/transport/stream.rs` | 226-238 | `recv_buf.remove(pos).unwrap()` | `pos` is the value just returned by `recv_buf.iter().position(...)`, so the element exists. `recv_buf` is locked across the read+remove, so no other task can drain it in between. |
| 3 | `core/src/transport/fragmentation.rs` | 53-60 | `self.assemblies.remove(&key).unwrap()` | The `is_complete` branch above just inserted the entry under `key` via `entry(key).or_insert_with(...)`; the function holds `&mut self`, so nothing else can remove it before this line. |
| 4 | `core/src/transport/fragmentation.rs` | 67-74 | `state.chunks.get(&i).unwrap()` | The preceding loop returned `None` early if any chunk `i` in `0..total_chunks` was missing. Reaching this loop proves every index is present. |
| 5 | `core/src/transport/legs/faketls.rs` | 590-600 | `self.send_key.seal_in_place_append_tag(nonce, aad, &mut in_out).unwrap()` | ring's `seal_in_place_append_tag` only fails when input length + tag exceeds AES-GCM's NIST SP 800-38D invocation limit (~2^36 bytes). Phantom records are MTU-bounded (≤ 1300 + framing). Cannot occur in practice. |
| 6 | `core/src/transport/legs/faketls.rs` | 639-649 | `FakeTlsLeg::default() -> Self::new().expect(...)` | `FakeTlsLeg::new` only fails if the underlying AES key init returns an error. The seed → key derivation is deterministic over fixed inputs and never returns errors with the current `ring` API. The `Default` impl exists for ergonomic test/setup use; callers in production paths use `FakeTlsLeg::new()` directly and propagate the error. |

## Unsafe Blocks

The crate is `#![deny(unsafe_code)]` at the root (`core/src/lib.rs:38`). Two
modules opt in with module-level `#![allow(unsafe_code)]` plus per-block
`// SAFETY:` comments:

| Module | Why `unsafe` |
| --- | --- |
| `core/src/transport/udp_transport.rs` | libc GSO / `recvmmsg` / `sendmmsg` syscalls — must construct `mmsghdr` via `MaybeUninit::zeroed()` and call FFI with raw fd. Each block has a SAFETY line explaining lifetime, ownership, and validity invariants. |

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
