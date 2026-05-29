# Browser / WASM client deployment

Reference patterns for embedding a Phantom Core client in a browser via the
`wasm32-unknown-unknown` target.

## Build setup

**Target.** Build with `wasm-pack`:

```sh
# <script type="module"> usage
wasm-pack build --target web --release -- --manifest-path phantom-wasm-client/Cargo.toml
# webpack / Rollup / Vite (preferred for production)
wasm-pack build --target bundler --release -- --manifest-path phantom-wasm-client/Cargo.toml
```

**Feature flags.** Do NOT enable native-only features (`rt-multi-thread`, `net`,
`kcp`). Minimal `Cargo.toml` for the wasm-pack crate:

```toml
[dependencies]
phantom_core    = { path = "../core", default-features = false }
wasm-bindgen    = "0.2"
wasm-bindgen-futures = "0.4"
```

**CSPRNG backend.** `getrandom` requires an explicit JS backend on `wasm32`.
Add to `.cargo/config.toml` in the workspace root:

```toml
[target.wasm32-unknown-unknown]
rustflags = ["--cfg=getrandom_backend=\"wasm_js\""]
```

Omitting this flag causes a runtime panic.

**Post-processing.** Shrink with `wasm-opt` (`brew install binaryen`):

```sh
wasm-opt -Oz pkg/phantom_wasm_client_bg.wasm -o pkg/phantom_wasm_client_bg.wasm
```

## Wiring `WebSocketLeg` + `WasmRuntime`

`WebSocketLeg` is the browser `SessionTransport`. It wraps `web_sys::WebSocket`
and resolves once `onopen` fires. Pair it with `WasmRuntime`:

```rust
use std::sync::Arc;
use phantom_core::{
    api::session::PhantomSession,
    crypto::hybrid_sign::HybridVerifyingKey,
    runtime::WasmRuntime,
    transport::legs::websocket::WebSocketLeg,
};

#[wasm_bindgen]
pub async fn start_phantom_session() -> Result<(), JsError> {
    // Resolves once WebSocket readyState == OPEN.
    let leg = WebSocketLeg::connect("wss://phantom.example.com/ws").await
        .map_err(|e| JsError::new(&e.to_string()))?;

    // Server key baked in at compile time (see Pinning section).
    let pinned = HybridVerifyingKey::from_bytes(SERVER_VERIFYING_KEY)
        .map_err(|e| JsError::new(&e.to_string()))?;

    let session = PhantomSession::connect_with_transport_with_runtime(
        "wss://phantom.example.com",
        leg,
        pinned,
        Arc::new(WasmRuntime),   // setTimeout-based sleep, spawn_local task spawning
    ).await.map_err(|e| JsError::new(&e.to_string()))?;

    session.send(b"hello from browser").await
        .map_err(|e| JsError::new(&e.to_string()))?;
    Ok(())
}
```

## Pinning the server key

Phantom requires clients to pin the server's `HybridVerifyingKey` — the parameter
is non-optional. Export it via `PhantomListener::verifying_key_bytes()` during
server provisioning and bake it into the wasm module at compile time:

```rust
// Binary blob from verifying_key_bytes() on the server.
const SERVER_VERIFYING_KEY: &[u8] =
    include_bytes!("../keys/phantom_server_verifying_key.bin");
```

Commit the file alongside source; do NOT generate it at runtime. Rotating the
server signing key requires a wasm rebuild and redeploy.

**Never** embed a `HybridSigningKey` (private) in a client bundle.

## Session resumption via IndexedDB

After a session establishes, `PhantomSession::resumption_hint()` returns
`Option<ResumptionHint>` — a record with 32-byte `session_id` and
`resumption_secret` fields. Persist it in IndexedDB for 0-RTT resumption
on subsequent page loads.

**Recommended JSON shape** (keyed by server hostname):

```ts
{ sid: hex32, secret: hex32, savedAt: number /* ms since epoch */ }
```

**Resumption TTL.** Discard hints older than 3 600 000 ms (server
`SessionCache` default: 1 hour).

**Resuming.** The native `connect_pinned_with_resumption` shim is
`cfg(not(wasm32))`; browser builds resume through the Rust-level
`connect_with_resumption`, which takes the raw `(session_id,
resumption_secret)` tuple and an early-data `Vec<u8>` (≤ 16 KiB):

```rust
let session = PhantomSession::connect_with_resumption(
    "wss://phantom.example.com",
    leg,
    pinned,
    (sid, secret),        // [u8; 32] each, hex-decoded from IndexedDB
    Vec::new(),           // early_data: Vec<u8>, max 16 KiB
)?;

// None = no V3 attempt; Some(true) = server accepted early data.
if session.early_data_accepted().await == Some(true) { /* ... */ }
```

**Anti-replay.** `SessionCache::try_resume` is one-shot — a replayed or expired
hint falls back to 1-RTT. Clear stored hints on logout. The SDK ships no
IndexedDB helper; use `web_sys::IdbDatabase` / `IdbObjectStore` directly.

## Bundle size

Phantom's wasm32 build pulls in ml-kem (FIPS 203), ml-dsa (FIPS 204), ring
AES-256-GCM, and ChaCha20-Poly1305 unconditionally.

**Concrete numbers** for the cdylib output (raw and after `wasm-opt -Oz`)
live in [`binary-sizes.md` §Table 7](binary-sizes.md) — refreshed by
[`scripts/measure-binary-sizes.sh`](../../scripts/measure-binary-sizes.sh).

**Manual one-shot measurement**:

```sh
cargo build --release --target wasm32-unknown-unknown --manifest-path core/Cargo.toml
wc -c target/wasm32-unknown-unknown/release/phantom_core.wasm
# Optional: shrink with binaryen
wasm-opt -Oz target/wasm32-unknown-unknown/release/phantom_core.wasm \
    -o /tmp/phantom_core.opt.wasm && wc -c /tmp/phantom_core.opt.wasm
```

**Shrinking options:**

- `wasm-opt -Oz` (see Build setup) — no runtime tradeoff.
- `wee_alloc` global allocator — saves ~10 KiB at the cost of slower per-
  allocation throughput (acceptable for handshake-rate workloads); add
  `wee_alloc = "0.4"` to `[dependencies]` and set `#[global_allocator]`.
- LTO is already on in `[profile.release]`; ensure `wasm-pack` uses `--release`.

## Threading / Web Workers

`WebSocketLeg` keeps `web_sys::WebSocket` inside a `spawn_local` task. The
`WebSocketLeg` the session holds is `Send + Sync` (channel handles only).

- **Main-thread** works out of the box via `wasm-bindgen-futures::spawn_local`.
- **Dedicated Worker** is supported but requires a `WasmRuntime` variant that
  uses `WorkerGlobalScope` for `setTimeout`. Default `WasmRuntime` targets the
  main browser thread.
- `SharedArrayBuffer` / Atomics are not required — concurrency is channel-based.

## Browser console observability

Phantom uses `tracing` spans. On `wasm32`, pick one backend (SDK bundles
neither):

```toml
# Option A — tracing ecosystem
tracing-wasm = "0.2"
# Option B — log ecosystem (lighter)
console_log = { version = "1", features = ["color"] }
log = "0.4"
```

Initialize in the wasm entry point:

```rust
#[wasm_bindgen(start)]
pub fn init() {
    tracing_wasm::set_as_global_default();
    // or: console_log::init_with_level(log::Level::Debug).ok();
}
```

Span names are not part of the stable API surface.

## Security caveats

- **Signing key is server-side only.** `SERVER_VERIFYING_KEY` is the public
  half. Never bundle a `HybridSigningKey` (secret) in wasm.
- **IndexedDB is same-origin readable.** Enforce a strict
  `Content-Security-Policy`, no XSS surface, and `Subresource-Integrity` on
  third-party scripts. Clear resumption hints on logout.
- **`wss://` is required in production.** Browsers block `ws://` from HTTPS
  origins (mixed-content rules). Place Phantom behind a TLS-terminating proxy.
- **Phantom key vs TLS cert.** `HybridVerifyingKey` is Phantom-layer identity,
  independent of the WebSocket TLS cert. TLS cert rotation does not require a
  wasm rebuild; Phantom signing key rotation does.

## Performance notes

Server-side numbers are in `docs/operations/perf-tuning.md`. Browser-side:

- **`Performance.now()` granularity** is capped at ~1 ms without cross-origin
  isolation headers. RTT estimates in `WasmRuntime` are coarser than native.
- **JS↔Rust marshaling.** Each `send_bytes` / `recv_bytes` crosses the WASM
  boundary once; low-microsecond overhead — negligible for handshake-rate
  workloads, worth profiling for high-frequency small-message protocols.
- **PQC keygen in WASM.** Expect ~30–100 ms per full handshake on a mid-range
  device (TBD — measure with DevTools Timeline). 0-RTT resumption skips keygen.
- Prefer `--target bundler` + LTO for production; bundlers tree-shake dead
  paths that `--target web` retains.

## See also

- `docs/operations/kubernetes.md` — cluster deployment of the server side.
- `docs/operations/docker.md` — container image and graceful shutdown wiring.
- `docs/operations/perf-tuning.md` — server-side build flags and throughput numbers.
- `docs/operations/deployment.md` — index of all deployment surfaces.
- `wasm-pack` book: <https://rustwasm.github.io/docs/wasm-pack/> — `wasm-bindgen` guide: <https://rustwasm.github.io/docs/wasm-bindgen/>
