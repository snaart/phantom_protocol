# wasm32-wasi support — deferral and path forward

`wasm32-wasi` remains `allow_failure: true` in `.github/workflows/cross.yml`.
This page records why, what would need to change, and when it matters.

## What wasm32-wasi is and how it differs from wasm32-unknown-unknown

`wasm32-unknown-unknown` is the browser target: no OS, no POSIX, execution
driven by the JavaScript event loop, I/O through `web_sys` / `wasm-bindgen`
shims. `wasm32-wasi` (and its successors `wasm32-wasip1` / `wasm32-wasip2` in
the Rust target naming) is the server-side / CLI target — a WebAssembly module
running in a WASI-capable runtime (Wasmtime, WasmEdge, Spin, wasmCloud, the
Cloudflare Workers WASI sandbox) that provides POSIX-adjacent syscall stubs for
file I/O, environment variables, clocks, and (via the `wasi-sockets` proposal)
networking. The two targets share the `wasm32` architecture but otherwise have
nothing in common at the platform API level.

## Why Phantom Core does not currently support wasm32-wasi

### Tokio runtime gap

Tokio's async I/O layer uses `mio`, which drives `epoll` / `kqueue` /
`IOCP` depending on the host OS. `mio` does not compile for WASI — the
necessary poll primitives are absent from the WASI syscall surface.
`tokio-wasi` (third-party fork) re-implements the mio layer using WASI
poll APIs, but it is not a drop-in: it lags Tokio upstream in version and
surface area, and Phantom Core's `Runtime` trait would need a
`WasiRuntime` implementation paralleling the existing `WasmRuntime` for
browsers. That implementation does not exist.

### Network leg gap

No `WasiLeg` transport leg exists. All current legs use native network
primitives that are either unavailable on WASI or gated out:

| Leg | Status on wasm32-wasi |
| --- | --- |
| `tcp.rs` | uses `tokio::net::TcpStream` — fails to compile (`mio` absent) |
| `kcp.rs` | depends on `kcp-tokio` which depends on `tokio::net::UdpSocket` |
| `faketls.rs` | wraps `tcp.rs` — same blocker |
| `websocket.rs` | `web_sys::WebSocket` — wasm32-unknown-unknown only, cfg-gated out |
| `embedded/` | `embedded-io-async` traits — closest to WASI-compatible, but no WASI shim |

A `WasiLeg` would need to use either `tokio-wasi`'s `TcpStream` or the
raw `wasi::sockets::TcpSocket` type directly.

### WASI networking maturity

The `wasi-sockets` proposal (TCP + UDP) was not part of the original
`wasi-preview1` syscall set. Support was added in `wasi-preview2`
(component model). As of mid-2026 the Rust toolchain's `wasm32-wasi`
target still targets preview1, and the `wasm32-wasip2` target is in
stabilization. Relying on either demands careful target selection and
toolchain pinning not yet done.

## Realistic path forward

A wasm32-wasi closeout is four discrete steps in dependency order:

**Step 1 — `WasiLeg`.** Implement a `WasiLeg` over either:

- `tokio-wasi 0.x`: lower friction, inherits existing TCP session transport
  framing unchanged; depends on the fork remaining maintained and compatible.
- Raw `wasi::sockets::TcpSocket` (preview2): more stable long-term; requires
  writing the async poll layer without tokio internals.

```toml
# core/Cargo.toml — wasi-only section (does not exist yet)
[target.'cfg(target_os = "wasi")'.dependencies]
tokio-wasi = { version = "0.1", features = ["net", "rt", "macros"] }
```

Cfg-gate the module exactly as `websocket.rs` is gated on wasm32:
```toml
#[cfg(target_os = "wasi")]
pub mod wasi;
```

**Step 2 — `WasiRuntime`.** Implement `core/src/runtime/wasi_runtime.rs`
satisfying the `Runtime` trait. Time source: `wasi::clocks::wall_clock` /
`monotonic_clock`. Task spawning: single-threaded `LocalSet` or
`tokio-wasi::task::spawn_local`. This parallels `WasmRuntime` in
`runtime/wasm_runtime.rs` almost line-for-line.

**Step 3 — `core/Cargo.toml` cfg splits.** Add a
`[target.'cfg(target_os = "wasi")']` dependency block mirroring the
existing `[target.'cfg(not(target_arch = "wasm32"))']` block. Remove any
`tokio/net` and `tokio/rt-multi-thread` from the WASI view — WASI is
single-threaded.

**Step 4 — flip the gate.** Once `cargo check --lib --target wasm32-wasi`
(or `wasm32-wasip2`) is green on CI, update `.github/workflows/cross.yml`:

```yaml
- target: wasm32-wasi        # or wasm32-wasip2
  runner: ubuntu-latest
  install_target: true
  allow_failure: false       # remove this line; omit = false
```

**Estimated effort.** A `tokio-wasi`-backed preview1 attempt: 1–2 weeks.
A `wasm32-wasip2` component-model attempt: 2–4 weeks (more upstream churn,
component-model ABI differences). Neither timeline includes test coverage
in a real WASI runtime (Wasmtime), which is a separate CI task.

## Why the deferral is safe

The platforms Phantom Core ships for today are all CI-green:

| Deployment target | Status |
| --- | --- |
| Linux server (x86_64 / aarch64 gnu + musl) | hard gate |
| macOS (x86_64 / aarch64) | hard gate |
| Windows (x86_64 / aarch64 msvc) | hard gate |
| iOS device + simulator | hard gate |
| Browser (`wasm32-unknown-unknown`) | hard gate (Phase 3.3 + 3.5) |
| Embedded Cortex-M (`thumbv7em-none-eabihf`) | hard gate (Phase 3.6) |
| **wasm32-wasi** | **allow_failure — this deferral** |

The deployment models where wasm32-wasi would matter are:

- Server-side CDN edge workers (Cloudflare Workers WASI mode, Fastly
  Compute@Edge) running a Phantom proxy or forwarder.
- WASI container orchestrators (wasmCloud, Spin) deploying Phantom Core
  as a portable wasm module.
- CLI tools distributed as a single `.wasm` binary runnable via
  `wasmtime phantom-cli.wasm`.

None of these has a current Phantom Core consumer or a filed user request.
They are emerging deployment models and the toolchain story is still
settling. Deferral does not affect any existing user.

## See also

- `.github/workflows/cross.yml` — wasm32-wasi matrix entry (keep
  `allow_failure: true` until this doc's Step 4 is complete).
- `docs/operations/wasm.md` — `wasm32-unknown-unknown` browser deployment
  (already green, unrelated to WASI).
- `core/src/runtime/wasm_runtime.rs` — `WasmRuntime` to mirror for
  `WasiRuntime`.
- `core/src/transport/legs/websocket.rs` — `WebSocketLeg` to mirror for
  `WasiLeg` cfg-gating pattern.
