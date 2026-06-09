//! Phantom Protocol — browser WASM demo.
//!
//! Entry point: `run_demo(url, pinned_key_hex)` — opens a `WebSocketLeg`,
//! performs a full post-quantum handshake via `PhantomSession`, sends
//! a ping, waits for the echo, and returns the round-trip result.
//!
//! Build with:  wasm-pack build --target web --out-dir pkg
//! Host with:   python3 -m http.server 8000  (then open index.html)

#![cfg(target_arch = "wasm32")]

use std::sync::Arc;

use js_sys::JsString;
use phantom_protocol::api::session::PhantomSession;
use phantom_protocol::crypto::hybrid_sign::HybridVerifyingKey;
use phantom_protocol::runtime::wasm_runtime::WasmRuntime;
use phantom_protocol::transport::legs::websocket::WebSocketLeg;
use wasm_bindgen::prelude::*;
use web_sys::console;

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn log(msg: &str) {
    console::log_1(&JsString::from(msg));
}

fn err(msg: String) -> JsValue {
    JsValue::from_str(&msg)
}

/// Decode a hex string to bytes.
fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err("hex string has odd length".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|e| format!("bad hex at offset {i}: {e}"))
        })
        .collect()
}

// ─── Entry point ─────────────────────────────────────────────────────────────

/// Connect to a Phantom Protocol server over WebSocket, send a ping, and return the
/// echoed response as a JS string.
///
/// # Arguments
/// * `url` — WebSocket URL, e.g. `wss://localhost:8443/ws`
/// * `pinned_key_hex` — hex-encoded `HybridVerifyingKey` bytes from the
///   server (obtain via `PhantomListener::verifying_key_bytes()` on the
///   server side).
///
/// # Errors
/// Returns a `JsValue` string describing the error if any step fails.
#[wasm_bindgen]
pub async fn run_demo(url: &str, pinned_key_hex: &str) -> Result<JsValue, JsValue> {
    // Install panic hook so Rust panics surface in the browser console.
    console_error_panic_hook::set_once();

    log("[phantom] starting demo");
    log(&format!("[phantom] connecting to {url}"));

    // 1. Decode the pinned server public key.
    let pk_bytes = hex_decode(pinned_key_hex)
        .map_err(|e| err(format!("pinned_key_hex decode error: {e}")))?;
    let pinned_key = HybridVerifyingKey::from_bytes(&pk_bytes)
        .map_err(|e| err(format!("HybridVerifyingKey::from_bytes: {e:?}")))?;
    log("[phantom] server key decoded");

    // 2. Open the WebSocket transport leg.
    let leg = WebSocketLeg::connect(url)
        .await
        .map_err(|e| err(format!("WebSocketLeg::connect: {e:?}")))?;
    log("[phantom] WebSocket open");

    // 3. Wrap the WasmRuntime and start the Phantom Protocol session (background
    //    handshake + data pump spawned via wasm_bindgen_futures::spawn_local).
    let runtime: Arc<dyn phantom_protocol::runtime::Runtime> = Arc::new(WasmRuntime);
    let session =
        PhantomSession::connect_with_transport_with_runtime(url, leg, pinned_key, runtime);
    log("[phantom] session created, handshake running");

    // 4. Send a test message.  The session queues it until the handshake
    //    completes, so this returns quickly even before PQC finishes.
    let ping = b"ping from wasm".to_vec();
    session
        .send(ping)
        .await
        .map_err(|e| err(format!("session.send: {e:?}")))?;
    log("[phantom] ping sent");

    // 5. Receive the echo.
    let echo = session
        .recv()
        .await
        .map_err(|e| err(format!("session.recv: {e:?}")))?;
    log(&format!("[phantom] echo received ({} bytes)", echo.len()));

    // 6. Return the echo as a UTF-8 JS string (or a hex fallback).
    let result = String::from_utf8(echo.clone())
        .unwrap_or_else(|_| format!("0x{}", hex_encode(&echo)));

    log(&format!("[phantom] result: {result}"));
    Ok(JsValue::from_str(&result))
}

/// Minimal hex encoder — avoids pulling in an extra crate dependency.
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
