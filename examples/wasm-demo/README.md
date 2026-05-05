# Phantom Core — Browser WASM Demo

A minimal browser demo that runs a full post-quantum Phantom Core handshake
over WebSocket, entirely inside a browser tab. It connects to a Phantom server,
sends a `"ping from wasm"` message, and logs the echoed response to the console.

## What this demo does

1. Hex-decodes the server's `HybridVerifyingKey` (pinned key for identity
   verification — defeats MITM even against a quantum adversary).
2. Opens a `WebSocketLeg` to the server URL.
3. Calls `PhantomSession::connect_with_transport_with_runtime` with a
   `WasmRuntime` — the hybrid X25519+ML-KEM-768 + Ed25519+ML-DSA-65
   handshake runs in the background via `wasm_bindgen_futures::spawn_local`.
4. Sends `"ping from wasm"` (queued until handshake completes).
5. Awaits the echo from the server.
6. Returns the round-trip result as a JS string.

All status messages are written to the browser console via `console.log`.

## Prerequisites

- [Rust](https://rustup.rs/) with `wasm32-unknown-unknown` target:
  ```
  rustup target add wasm32-unknown-unknown
  ```
- [wasm-pack](https://rustwasm.github.io/wasm-pack/installer/):
  ```
  cargo install wasm-pack
  ```
- A running Phantom Core server with WebSocket support. See the operator
  guide at `docs/operations/wasm.md` in the main repo.

## Build

```sh
cd examples/wasm-demo
wasm-pack build --target web --out-dir pkg
```

This compiles the Rust crate to `pkg/phantom_wasm_demo_bg.wasm` and generates
the JS glue in `pkg/phantom_wasm_demo.js`. The `--target web` flag produces
ES-module output suitable for `<script type="module">`.

## Serve and run

```sh
# Any static file server works. Python's built-in is the simplest:
python3 -m http.server 8000
```

Open `http://localhost:8000` in your browser and watch the console.

## Pointing at a real Phantom server

Edit the two constants at the top of the `<script>` block in `index.html`:

```js
const SERVER_URL    = 'wss://your-server.example.com/ws';
const SERVER_PK_HEX = '<hex output of PhantomListener::verifying_key_bytes()>';
```

To obtain `SERVER_PK_HEX` on the server side:

```rust
let listener = PhantomListener::bind("0.0.0.0:8443").await?;
let hex_key: String = listener
    .verifying_key_bytes()
    .iter()
    .map(|b| format!("{b:02x}"))
    .collect();
println!("{hex_key}");
```

The server must handle WebSocket upgrade at the path you specify and run a
Phantom handshake — this is out of scope for the demo itself.

## Caveats

**Bundle size.** The `.wasm` blob includes the full hybrid-crypto stack
(ML-KEM-768 + ML-DSA-65 in pure Rust) and will be several hundred KB. Use
`wasm-opt` (bundled with wasm-pack) or `wasm-pack build --release` (the
default) for production; debug builds are significantly larger.

**Mixed content.** Browsers block `ws://` connections from `https://` origins.
If your server is accessed over HTTPS, the WebSocket endpoint must be `wss://`.
For local development, `http://localhost` is exempted and `ws://localhost` works.

**Web Workers.** `WebSocketLeg` and `WasmRuntime` both target the browser
main thread (they ride `spawn_local` on the JS event loop). Running the demo
inside a `Worker` requires adapting the `spawn_local` invocations to the
worker context; `WasmRuntime::sleep` uses `js_sys::Reflect` to call
`setTimeout` so it already works in workers, but `WebSocket` construction in
a worker context must be verified per your target environment.

**No tokio runtime.** The wasm32 build does not use `tokio::runtime`. All
async work is driven by `wasm_bindgen_futures::spawn_local` via `WasmRuntime`.
Do not mix in `#[tokio::main]` or `tokio::spawn` — they will panic.

## Further reading

- `docs/operations/wasm.md` — operator guide for the WASM transport.
- `core/src/transport/legs/websocket.rs` — `WebSocketLeg` implementation.
- `core/src/runtime/wasm_runtime.rs` — `WasmRuntime` implementation.
- `docs/protocol/PROTOCOL.md` — full wire-format specification.
