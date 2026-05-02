# Phantom Core — C-language FFI bindings

This directory contains a hand-curated C header (`phantom_core.h`) and a
regeneration script (`../generate_c.sh`) for the Phantom Core Rust
library.

> If you have the option, use the Python / Swift / Kotlin bindings —
> they wrap this same `extern "C"` surface with proper memory
> management, async glue, and typed errors. This C surface is intended
> for low-level / embedded callers, or as a starting point if you are
> building your own generator.

## Why hand-curated?

Phantom Core's FFI is produced by Mozilla UniFFI 0.29 via
`uniffi::setup_scaffolding!()` in `core/src/lib.rs`. UniFFI ships
first-class generators for Kotlin, Swift, Python, and Ruby; pure-C is
*not* one of them. Two third-party-ish alternatives we evaluated:

| Approach | Outcome |
|---|---|
| `cbindgen` (Rust→C header generator that walks the AST) | Produces ~70 lines of constants — `WINDOW_BITS`, `AEAD_OVERHEAD`, `EARLY_DATA_MAX_LEN`, etc. It cannot see through `setup_scaffolding!()`'s proc-macro expansion, so it emits **zero function declarations**. We extracted the constants and re-include them in `phantom_core.h`. |
| `uniffi-bindgen-cs` / `uniffi-bindgen-c` | The C# generator targets a different ABI (P/Invoke marshalling); no actively-maintained pure-C UniFFI generator exists for 0.29. |
| Hand-curate from the dylib's exported symbol table | The chosen approach. `nm -gU` on `libphantom_core.dylib` lists all 123 `extern "C"` symbols UniFFI emits. We catalogue each one with its calling-convention contract. |

The header is therefore generated from the dylib + the published UniFFI
0.29 calling convention; see `../generate_c.sh` for the procedure.

## Linking against `libphantom_core`

The Rust crate declares `crate-type = ["lib", "cdylib"]`. Build with:

```sh
cargo build --release --manifest-path core/Cargo.toml
```

That produces:

- Linux: `target/release/libphantom_core.so`
- macOS: `target/release/libphantom_core.dylib`
- Windows: `target/release/phantom_core.dll` (+ `.lib` import library)

A minimal `gcc`/`clang` command line:

```sh
clang -I tests/bindings/c \
      -L target/release \
      -lphantom_core \
      -lpthread -lm -ldl \
      my_program.c -o my_program
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
       uniffi_phantom_core_fn_method_phantomlistener_local_addr(handle, &status);
   if (status.code != 0) { /* handle status.error_buf; free it */ }
   /* use addr.data[0..addr.len], then... */
   ffi_phantom_core_rustbuffer_free(addr, &status);
   ```

2. **Async call (anything `accept`, `recv`, `send`, `connect`, `bind`,
   `close`)** returns a `uint64_t` future handle. Drive it with the
   `ffi_phantom_core_rust_future_poll_*` family — picking the variant
   matching the eventual return type:

   ```c
   uint64_t fut = uniffi_phantom_core_fn_method_phantomsession_recv(session);
   for (;;) {
       int8_t poll_code = -1;
       ffi_phantom_core_rust_future_poll_rust_buffer(
           fut, my_callback, (uint64_t)&my_callback_state);
       /* wait on my_callback to set poll_code... */
       if (poll_code == 0) break; /* ready */
   }
   PhantomRustCallStatus s = {0};
   PhantomRustBuffer payload =
       ffi_phantom_core_rust_future_complete_rust_buffer(fut, &s);
   ffi_phantom_core_rust_future_free_rust_buffer(fut);
   /* payload is yours; free with ffi_phantom_core_rustbuffer_free. */
   ```

3. **Constructor** — same as async call but returns a `void *` future
   result that is the object handle.

4. **Buffer / string lowering** — UTF-8 strings and `Vec<u8>` payloads
   are lowered the same way: a `PhantomRustBuffer` whose first 4 bytes
   are a big-endian length and whose remainder is the payload (UniFFI's
   default `_lower` representation). Allocate via
   `ffi_phantom_core_rustbuffer_alloc(n+4, &status)`, write the BE
   length, copy your payload, then hand the buffer in. The higher-level
   bindings (e.g. Python `phantom_core.py:_UniffiRustBufferBuilder`)
   are a faithful reference for the binary layout.

## Memory management rules

- Object handles (`PhantomListener`, `PhantomSession`, `PhantomStream`,
  `AcceptOutcome`) are `Arc<T>` on the Rust side. Constructor +
  `_clone_*` add a reference; `_free_*` drops one. Forgetting a `_free_*`
  leaks the entire object graph.
- `PhantomRustBuffer` is owned heap memory; **always** free with
  `ffi_phantom_core_rustbuffer_free`. Inspecting `data` / `len` is
  read-only — do not call `free(buf.data)` from `<stdlib.h>`.
- A non-zero `PhantomRustCallStatus.code` means `error_buf` is populated
  and **also** needs to be freed.

## Caveats

The hand-curated header is best-effort and has the following hard
limits — please read before committing to a C-side integration:

1. **No pinned client connect.** The UniFFI-exported
   `PhantomSession::connect(addr)` is the placeholder shell. The
   security-critical paths `connect_with_transport`,
   `connect_with_resumption`, and the `_with_runtime` overloads are
   `Rust`-only — they take non-UniFFI types (`SessionTransport` trait
   objects, `Arc<dyn Runtime>`, `HybridVerifyingKey` references). A
   C consumer that needs production-quality pinning must either:
   - write a small Rust shim that re-exposes a UniFFI-friendly entry
     point (e.g. a typed `connect_tcp_pinned(addr, server_pk)` that
     internally builds the `TcpSessionTransport`), or
   - drive the SDK from a higher-level language with UniFFI support.
2. **Missing pieces.** `HybridSigningKey` / `HybridVerifyingKey`,
   `PhantomConfig`, `EmbeddedLeg`, the network simulator, runtime
   injection, and `CoreError` variant introspection are not on the
   FFI surface.
3. **Stale on UniFFI bump.** Contract version 26 is current as of
   phantom_core 0.2.0. If you upgrade UniFFI, re-run
   `tests/bindings/generate_c.sh` and reconcile changes.
4. **Integer-typed futures.** Only the `_pointer`, `_rust_buffer`,
   `_void`, and `_u8` variants of the future-poll family are declared
   in the header. The rest (`u16`/`i16`/`u32`/`i32`/`u64`/`i64`/`f32`/`f64`)
   are present in the dylib and follow the identical pattern — re-declare
   on demand.
5. **Checksums.** All 30 `uniffi_phantom_core_checksum_*` symbols are
   exported but not declared. Higher-level bindings call them at load
   time; for C callers they are optional. Signature is
   `uint16_t uniffi_phantom_core_checksum_<name>(void);`.

## Regenerating

```sh
./tests/bindings/generate_c.sh
```

Verifies the dylib exists, lists exported `uniffi_*` / `ffi_phantom_*`
symbols, and diffs them against the header. If new symbols appear
(e.g. you added a `#[uniffi::export]` method), the script prints them
so you can extend `phantom_core.h` accordingly.
