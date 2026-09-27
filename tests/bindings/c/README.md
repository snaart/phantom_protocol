# Phantom Protocol — C-language FFI bindings

This directory contains a hand-curated C header (`phantom_protocol.h`) and a
regeneration script (`../generate_c.sh`) for the Phantom Protocol Rust
library.

> If you have the option, use the Python / Swift / Kotlin bindings —
> they wrap this same `extern "C"` surface with proper memory
> management, async glue, and typed errors. This C surface is intended
> for low-level / embedded callers, or as a starting point if you are
> building your own generator.

## Why hand-curated?

Phantom Protocol's FFI is produced by Mozilla UniFFI 0.32 via
`uniffi::setup_scaffolding!()` in `core/src/lib.rs`. UniFFI ships
first-class generators for Kotlin, Swift, Python, and Ruby; pure-C is
*not* one of them. Two third-party-ish alternatives we evaluated:

| Approach | Outcome |
|---|---|
| `cbindgen` (Rust→C header generator that walks the AST) | Produces ~70 lines of constants — `WINDOW_BITS`, `AEAD_OVERHEAD`, `EARLY_DATA_MAX_LEN`, etc. It cannot see through `setup_scaffolding!()`'s proc-macro expansion, so it emits **zero function declarations**. We extracted the constants and re-include them in `phantom_protocol.h`. |
| `uniffi-bindgen-cs` / `uniffi-bindgen-c` | The C# generator targets a different ABI (P/Invoke marshalling); no actively-maintained pure-C UniFFI generator exists for 0.32. |
| Hand-curate from the dylib's exported symbol table | The chosen approach. `nm -gU` on `libphantom_protocol.dylib` lists all 189 `extern "C"` symbols UniFFI emits (74 `uniffi_phantom_protocol_fn_*`, 62 `uniffi_phantom_protocol_checksum_*`, 53 `ffi_phantom_protocol_*` runtime symbols). We catalogue each one with its calling-convention contract. |

The header is therefore generated from the dylib + the published UniFFI
0.32 calling convention; see `../generate_c.sh` for the procedure.

## Linking against `libphantom_protocol`

The Rust crate declares `crate-type = ["lib", "cdylib"]`. Build with:

```sh
cargo build --release --manifest-path core/Cargo.toml
```

That produces:

- Linux: `target/release/libphantom_protocol.so`
- macOS: `target/release/libphantom_protocol.dylib`
- Windows: `target/release/phantom_protocol.dll` (+ `.lib` import library)

A minimal `gcc`/`clang` command line:

```sh
# The source/object MUST precede -lphantom_protocol (GNU ld resolves
# left-to-right and drops an unreferenced library's symbols).
clang -I tests/bindings/c \
      my_program.c \
      -L target/release \
      -lphantom_protocol \
      -lpthread -lm -ldl \
      -o my_program
```

On macOS you may also need `-framework Security -framework CoreFoundation`
(for `ring`'s system-RNG / keychain shims). On Linux some distros also
require `-Wl,--as-needed -lutil`.

## Calling-convention quick reference

Every entry point follows one of these shapes:

1. **Sync call (most metrics / accessors)**

   ```c
   PhantomRustCallStatus status = {0};
   PhantomRustBuffer addr =
       uniffi_phantom_protocol_fn_method_phantomlistener_local_addr(handle, &status);
   if (status.code != 0) { /* handle status.error_buf; free it */ }
   /* use addr.data[0..addr.len], then... */
   ffi_phantom_protocol_rustbuffer_free(addr, &status);
   ```

2. **Async call (anything `accept`, `recv`, `send`, `connect`, `bind`,
   `close`)** returns a `uint64_t` future handle. Drive it with the
   `ffi_phantom_protocol_rust_future_poll_*` family — picking the variant
   matching the eventual return type:

   ```c
   uint64_t fut = uniffi_phantom_protocol_fn_method_phantomsession_recv(session);
   for (;;) {
       int8_t poll_code = -1;
       ffi_phantom_protocol_rust_future_poll_rust_buffer(
           fut, my_callback, (uint64_t)&my_callback_state);
       /* wait on my_callback to set poll_code... */
       if (poll_code == 0) break; /* ready */
   }
   PhantomRustCallStatus s = {0};
   PhantomRustBuffer payload =
       ffi_phantom_protocol_rust_future_complete_rust_buffer(fut, &s);
   ffi_phantom_protocol_rust_future_free_rust_buffer(fut);
   /* payload is yours; free with ffi_phantom_protocol_rustbuffer_free. */
   ```

3. **Constructor** — same as an async call, but the future completes to a
   `uint64_t` object handle (`_complete_u64`).

4. **Buffer / string lowering** — the two differ. A top-level `String`
   argument lowers to a `PhantomRustBuffer` of RAW UTF-8 bytes with **no**
   length prefix. A `Vec<u8>` argument lowers to a `PhantomRustBuffer` whose
   first 4 bytes are an **i32 big-endian length** followed by the payload.
   For a string, `ffi_phantom_protocol_rustbuffer_from_bytes` over the raw
   bytes is enough; for `Vec<u8>`, allocate via
   `ffi_phantom_protocol_rustbuffer_alloc(n+4, &status)`, write the BE
   length, then copy your payload (`phantom_helpers.h`'s
   `phantom__lower_bytes` does exactly this). Return values of both kinds
   ARE length-prefixed. The higher-level bindings (e.g. Python
   `phantom_protocol.py`'s `_UniffiFfiConverterString.lower` vs
   `_UniffiFfiConverterBytes.write`) are the reference for the binary layout.

## Memory management rules

- Object handles (`PhantomListener`, `PhantomSession`, `PhantomStream`,
  `AcceptOutcome`) are `Arc<T>` on the Rust side. Constructor +
  `_clone_*` add a reference; `_free_*` drops one. Forgetting a `_free_*`
  leaks the entire object graph.
- **A method call consumes the receiver handle.** The scaffolding lifts the
  `void *` you pass back into the owning `Arc<T>` and drops it, so pass a
  fresh `uniffi_phantom_protocol_fn_clone_<object>` handle to every call and
  keep your own for the final `_free_*`. Skipping the clone drops your last
  reference on the first call — for a `PhantomSession` that closes the
  session, and every subsequent call sees a dead one. The generated
  Python / Swift / Kotlin bindings clone before every call; so does
  `phantom_helpers.h`.
- `PhantomRustBuffer` is owned heap memory; **always** free with
  `ffi_phantom_protocol_rustbuffer_free`. Inspecting `data` / `len` is
  read-only — do not call `free(buf.data)` from `<stdlib.h>`.
- A non-zero `PhantomRustCallStatus.code` means `error_buf` is populated
  and **also** needs to be freed.

## Caveats

The hand-curated header is best-effort; the following limits and gotchas
apply — please read before committing to a C-side integration:

1. **Pinned client connect IS available.** Six pinned entry points are
   FFI-exported as free functions: `connect_pinned`,
   `connect_pinned_with_config`, `connect_pinned_with_resumption` (TCP) and
   `connect_pinned_udp`, `connect_pinned_udp_with_config`,
   `connect_pinned_udp_with_resumption` (PhantomUDP — the migration-capable
   path). Pass the server's `HybridVerifyingKey` bytes from
   `PhantomListener::verifying_key_bytes()`. The
   `PhantomSession::connect(addr)` constructor is an inert legacy shell —
   never use it. Only the typed-argument Rust entry points
   (`connect_with_transport`, the `SessionBuilder`, and the `_with_runtime`
   shims) remain Rust-only, because they take non-UniFFI types
   (`SessionTransport` trait objects, `Arc<dyn Runtime>`,
   `HybridVerifyingKey` references).
2. **Missing pieces.** `EmbeddedLeg`, the network simulator, runtime
   injection (`Arc<dyn Runtime>`), and the typed `HybridSigningKey` /
   `HybridVerifyingKey` structs are not on the FFI surface. `PhantomConfig`
   IS (a UniFFI Record accepted by `bind_with_config_bytes`,
   `bind_udp_with_config_bytes`, `connect_pinned_with_config` and
   `connect_pinned_udp_with_config`), and key material crosses as bytes via
   `generate_signing_key` / `verifying_key_from_signing_key` /
   `verifying_key_bytes`. `CoreError` variants are lowered with a 1-based
   discriminant (15 = ServerIdentityMismatch, 16 = ProtocolRejected,
   17 = Unsupported).
3. **Stale on UniFFI bump.** Contract version 30 (UniFFI 0.32) is current
   as of phantom_protocol 0.3.0. If you upgrade UniFFI, re-run
   `tests/bindings/generate_c.sh` and reconcile changes.
4. **Integer-typed futures.** Only the `_u64`, `_rust_buffer`,
   `_void`, and `_u8` variants of the future-poll family are declared
   in the header. The rest (`i8`/`u16`/`i16`/`u32`/`i32`/`i64`/`f32`/`f64`)
   are present in the dylib and follow the identical pattern — re-declare
   on demand. There is no `_pointer` variant: UniFFI 0.32 returns exported
   objects as `u64` handles.
5. **Checksums.** All 62 `uniffi_phantom_protocol_checksum_*` symbols are
   exported but not declared. Higher-level bindings call them at load
   time; for C callers they are optional. Signature is
   `uint16_t uniffi_phantom_protocol_checksum_<name>(void);`.

## Regenerating

```sh
./tests/bindings/generate_c.sh
```

Verifies the dylib exists, lists exported `uniffi_*` / `ffi_phantom_*`
symbols, and diffs them against the header. If new symbols appear
(e.g. you added a `#[uniffi::export]` method), the script prints them
so you can extend `phantom_protocol.h` accordingly.

## Blocking helpers (`phantom_helpers.h`)

The raw surface above is async: `connect_pinned` / `send` / `recv` / `disconnect`
return a `uint64_t` future you must drive with the `_poll_*` / `_complete_*` /
`_free_*` family (see the async quick-reference). `phantom_helpers.h` is a
**header-only** (pure-C, no new Rust) convenience layer that factors that loop into
plain blocking calls:

```c
#include "phantom_protocol.h"
#include "phantom_helpers.h"   /* requires C11 <stdatomic.h> */

/* pinned_key = server's HybridVerifyingKey bytes (PhantomListener::verifying_key_bytes) */
int32_t err = PHANTOM_ERR_OK;
void *s = phantom_blocking_connect_pinned_checked("127.0.0.1", 4242,
                                                 pinned_key, key_len, &err);
if (!s) {
    /* err says which failure it was — the distinction a C caller needs:
     *   PHANTOM_ERR_SERVER_IDENTITY_MISMATCH  the server is not the pinned one
     *   PHANTOM_ERR_NETWORK                   refused / unreachable
     *   PHANTOM_ERR_CRYPTO                    the pinned_key blob is malformed
     *   PHANTOM_ERR_TIMEOUT                   the handshake did not finish  */
    return 1;
}
phantom_blocking_send(s, (const uint8_t *)"hello", 5);
uint8_t buf[2048];
ptrdiff_t n = phantom_blocking_recv(s, buf, sizeof buf);   /* n bytes, or -1 */
phantom_blocking_disconnect(s);
uniffi_phantom_protocol_fn_free_phantomsession(s, &(PhantomRustCallStatus){0});
```

**The connect waits for the handshake, and that is load-bearing.** The exported
`connect_pinned` future resolves as soon as the SOCKET is connected; the hybrid
PQC handshake, and with it the pinned-identity check, runs on a background task
afterwards. A helper that returned at that point handed back a live-looking
session for a WRONG pinned key — `send` returned 0 and only a later `recv`
returned -1, indistinguishable from a network fault. So
`phantom_blocking_connect_pinned_checked` drives `await_ready` before returning,
and reports `PHANTOM_ERR_SERVER_IDENTITY_MISMATCH` for a mispinned server.
`phantom_blocking_connect_pinned(host, port, key, len)` is the same call with the
reason discarded; it returns NULL in every case the checked form does.

Two more helpers expose the same machinery on an existing session:
`phantom_blocking_await_ready(session, &err)` (0 = established, -1 = failed with
`err` set) and `phantom_blocking_last_error(session, &err)` (1 = an error is
present, 0 = none, -1 = the call itself failed). `PhantomErrorCode` in
`phantom_helpers.h` enumerates the lowered `CoreError` discriminants.

The wait is a 1 ms `nanosleep` poll on a C11 `_Atomic` flag the UniFFI continuation
sets — no `-lpthread` needed for the helpers themselves.
`tests/bindings/c/consumer_smoke.c` exercises the poll/complete/free path (a
malformed pin returns NULL with `PHANTOM_ERR_CRYPTO`), and
`tests/bindings/c/pinning_smoke.c` — built and run by `run_c_pinning_test.sh` —
drives a real in-process listener with the right key, a wrong key, a malformed key
and a dead port, asserting the reason in each case. That one links `-lpthread`,
because it runs the server side on a second thread. The blocking helpers are
intended for synchronous C callers; bindings that already have an event loop
(Python/Swift/Kotlin) should keep using the async surface.
