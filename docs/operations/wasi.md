# wasm32-wasi (Preview 2) — shipped

`wasm32-wasip2` is a hard CI gate — the `wasm32-wasip2` row of
`.github/workflows/cross.yml` plus the `wasi-integration` job that runs
`core/tests/wasi_integration.rs` under `wasmtime` (it landed across `af1662a`..
`5187d28`, and `95e266a` is where `allow_failure` came off). This page
is the quickstart for embedders running Phantom Protocol inside a WASI
Preview 2 host (Wasmtime, WasmEdge, Spin, wasmCloud, Cloudflare
Workers WASI sandbox).

## TL;DR

```toml
# Cargo.toml of a WASI guest using phantom_protocol
[package]
name = "my-wasi-guest"
version = "0.1.0"
edition = "2021"

[dependencies]
phantom-protocol = { version = "0.3", default-features = false, features = ["std", "wasi-leg", "classical-crypto"] }
futures = { version = "0.3", default-features = false, features = ["executor"] }

[[bin]]
name = "my-wasi-guest"
path = "src/main.rs"
```

The `[[bin]]` form is what `wasmtime run …wasm` expects. A `[lib]
crate-type = ["cdylib"]` setup produces a shared library with no
entry point — useful for `jco`-style component-model imports, but
not for the simple `fn main()` quickstart below.

```rust
use std::net::SocketAddr;
use phantom_protocol::api::session::SessionTransport;
use phantom_protocol::transport::legs::wasi::WasiLeg;

fn main() {
    let addr: SocketAddr = "127.0.0.1:4242".parse().unwrap();
    let leg = WasiLeg::connect(addr).expect("WasiLeg::connect");

    // WasiLeg's SessionTransport futures block the instance inside the
    // call — a read through `wasi:io/streams::blocking-read`, a write
    // through `wasi:io/poll` on the stream's readiness and a stall timer —
    // so they resolve as soon as they are polled.
    futures::executor::block_on(leg.send_bytes(b"hello")).unwrap();
    let echo = futures::executor::block_on(leg.recv_bytes()).unwrap();
    assert_eq!(&echo[..], b"hello");
}
```

Build + run:

```sh
cargo build --target wasm32-wasip2 --release
wasmtime run -S inherit-network ./target/wasm32-wasip2/release/your-guest.wasm
```

## What ships in the `wasi-leg` feature

| Symbol | Path | Role |
| --- | --- | --- |
| `WasiLeg` | `phantom_protocol::transport::legs::wasi::WasiLeg` | Length-prefix-framed `SessionTransport` over `wasi:sockets/tcp`. Client-only (no `accept` yet). |
| `WasiRuntime` | `phantom_protocol::runtime::wasi_runtime::WasiRuntime` | Single-task `Runtime` impl. Spawns futures into an in-process queue; `drive()` polls all tasks, `poll_until_progress(max_wait)` blocks the host on `wasi:io/poll::poll` with a `subscribe_duration` watchdog. |

Both are gated on `cfg(all(feature = "wasi-leg", target_os = "wasi"))`.
The Cargo feature itself implies `std`; it is mutually exclusive with
`wasm32-unknown-unknown` (the browser target) — a `compile_error!` in
`core/src/lib.rs` rejects the combination explicitly with a pointer at
the `WebSocketLeg` + `WasmRuntime` surface that the browser path
already provides.

## Why `--no-default-features --features std,wasi-leg,classical-crypto`?

The `bindings` Cargo feature (default-on) pulls in UniFFI's
`setup_scaffolding!` and the `#[uniffi::export]` derives that the
native Swift / Kotlin / Python / C bindings consume. UniFFI's
exported-symbol metadata is incompatible with `wasm-component-ld`
(the wasm32-wasip2 linker — it expects a Wasm component, not a
bag of named exports). WASI guests therefore drop `bindings` and
re-add only the features they need. `classical-crypto` must be named
explicitly — it is deliberately not implied by `std` so a FIPS build can
drop `ring` / `x25519-dalek`:

```toml
phantom-protocol = { ..., default-features = false, features = ["std", "wasi-leg", "classical-crypto"] }
```

The `bindings` feature is irrelevant inside a WASI guest anyway —
no host-side FFI binding generator targets WASI.

## Browser vs WASI vs native dependency split

The `core/Cargo.toml` target gates carve the dep graph three ways:

```
cfg(not(target_arch = "wasm32"))                       — native targets
cfg(all(target_arch = "wasm32", target_os = "unknown")) — browser
cfg(target_os = "wasi")                                — wasi-leg
```

- The browser-only block (`wasm-bindgen`, `web-sys`, `js-sys`, the
  `getrandom = { features = ["js"] }` shim) is invisible to WASI
  builds. WASI builds get the default `getrandom` path, which routes
  through the WASI `random_get` syscall.
- `tokio` cross-target features (`sync`, `macros`, `rt`, `time`,
  `io-util`) are available in WASI builds; the native-only features
  (`net`, `rt-multi-thread`, `signal`, `process`, `fs`, `io-std`)
  are not. This matches Tokio's own WASI support story.

## Running the host integration test

`core/tests/wasi_integration.rs` boots the `phantom-wasi-guest`
fixture under `wasmtime` and round-trips a payload through `WasiLeg`
against a native length-prefix-aware echo server. The test is
`#[ignore]`-gated; run it explicitly:

```sh
rustup target add wasm32-wasip2
# macOS: brew install wasmtime
# Linux: curl -sSf https://wasmtime.dev/install.sh | bash
cargo test --manifest-path core/Cargo.toml --test wasi_integration -- --ignored
```

CI runs this in a dedicated `wasi-integration` job in
`.github/workflows/cross.yml` (separate from the `wasm32-wasip2`
compile-check matrix entry).

## Out of scope (today)

These are deliberate omissions, not bugs:

- **Server-side accept.** `WasiLeg` is client-only. `wasi:sockets/tcp`'s
  `start_listen` / `finish_listen` / `accept` exist; wiring them to
  `PhantomListener` requires a `WasiListener` mirror that doesn't
  exist yet; running `phantom-server` as a WASI guest is deliberately
  deferred (see `docs/DEFERRED_WORK.md` §3).
- **Full `PhantomSession` over `WasiLeg`.** The host integration
  test exercises `WasiLeg::connect / send / recv`, not a complete
  handshake. The session machinery needs
  `connect_with_transport_with_runtime` wiring against
  `WasiRuntime::drive` + `poll_until_progress`, plus the host echo
  server has to become a real `PhantomListener`. Follow-up work.
- **WASI Preview 1.** `wasm32-wasip1` builds the library (the
  Preview 1 target is in the rustup tree), but `wasi:sockets` is
  Preview 2 only — `wasi 0.14`'s socket imports are not satisfied
  by Preview 1 hosts. Use `wasm32-wasip2` for the wasi-leg surface.

## See also

- `core/tests/fixtures/wasi-guest/` — the WASI Preview 2 reference
  embedder.
- `core/tests/wasi_integration.rs` — the host driver for the
  `wasmtime`-backed round-trip test.
- `core/src/runtime/wasi_runtime.rs` — `WasiRuntime` source.
- `core/src/transport/legs/wasi.rs` — `WasiLeg` source.
- `.github/workflows/cross.yml` — `wasm32-wasip2` matrix row and
  the dedicated `wasi-integration` job.
- `docs/operations/wasm.md` — companion guide for the
  `wasm32-unknown-unknown` browser surface.
