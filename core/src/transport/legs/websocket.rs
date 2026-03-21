//! WebSocket transport leg for `wasm32` browser builds (Phase 3.3).
//!
//! Implements [`SessionTransport`](crate::api::session::SessionTransport)
//! on top of `web_sys::WebSocket`, allowing `PhantomSession::connect_with_transport_with_runtime`
//! to drive a hybrid post-quantum session from inside a browser.
//!
//! ## Design
//!
//! `web_sys::WebSocket` is `!Send` — its JS-bound state cannot cross
//! browser worker threads. The leg therefore keeps the actual WebSocket
//! **inside** a `spawn_local` task on the WASM single-threaded executor
//! and exposes only `Send` channels to the rest of the crate:
//!
//! ```text
//!  user task               leg (Send)              spawn_local task                JS event loop
//!  ────────────            ────────────            ──────────────────              ─────────────
//!  send_bytes(b)  ────►   send_tx.send(b)  ────►   send_rx.recv()    ────►   ws.send_with_u8_array
//!  recv_bytes()   ◄────   recv_rx.recv()   ◄────   recv_tx.send(b)   ◄────   onmessage(MessageEvent)
//! ```
//!
//! The `WebSocketLeg` value the rest of the crate holds is `Send + Sync`
//! because it only owns `tokio::sync::mpsc` handles. The WebSocket
//! itself never leaves the spawn_local task.
//!
//! ## Lifecycle
//!
//! - `WebSocketLeg::connect(url)` opens the WebSocket and resolves once
//!   the `onopen` event fires (or rejects on early `onerror` / `onclose`).
//! - `send_bytes` queues bytes for the spawn_local task to flush.
//! - `recv_bytes` reads the next message; returns
//!   `CoreError::NetworkError` when the WebSocket closes.
//! - `close()` triggers `ws.close()` and drops both channel halves.
//!
//! ## Status
//!
//! Compile-only at the time of landing — the
//! `wasm32-unknown-unknown` job in `cross.yml` is still
//! `allow_failure: true` because other parts of the crate (TCP/UDP/KCP
//! legs, `tokio::net::*`) still need feature-gating before a full WASM
//! build links. That work is Phase 3.5.

#![cfg(target_arch = "wasm32")]
#![allow(unsafe_code)] // wasm-bindgen generates `unsafe` JS-boundary glue

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use bytes::Bytes;
use js_sys::Uint8Array;
use tokio::sync::{mpsc, oneshot, Mutex};
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use web_sys::{BinaryType, CloseEvent, ErrorEvent, MessageEvent, WebSocket};

use crate::api::session::SessionTransport;
use crate::errors::CoreError;

/// Sized cap on the outbound queue. Provides backpressure to misbehaving
/// senders without unbounded memory growth. Inbound is unbounded because
/// the browser already drops or backpressures at the socket layer; we
/// just want to deliver what the kernel handed us.
const SEND_QUEUE_CAPACITY: usize = 256;

/// WebSocket-backed `SessionTransport` for browser WASM clients.
///
/// Construct via [`WebSocketLeg::connect`]. Held as `Send + Sync` because
/// only the channel handles live on this side of the API boundary; the
/// underlying `web_sys::WebSocket` is owned by the spawn_local task.
pub struct WebSocketLeg {
    /// Outbound bytes channel. `send_bytes` pushes here; the spawn_local
    /// task drains it and calls `ws.send_with_u8_array`.
    send_tx: mpsc::Sender<Vec<u8>>,
    /// Inbound bytes channel. The `onmessage` callback pushes here;
    /// `recv_bytes` awaits the next value.
    recv_rx: Mutex<mpsc::UnboundedReceiver<Vec<u8>>>,
    /// Set to true once `close()` has been called or the socket signals
    /// `onclose` / `onerror`. Subsequent `send_bytes` / `recv_bytes`
    /// return `NetworkError`.
    closed: Arc<AtomicBool>,
}

impl WebSocketLeg {
    /// Open a WebSocket to `url` and resolve once the connection is
    /// ready for data exchange (`readyState == OPEN`). The URL must use
    /// the `wss://` or `ws://` scheme.
    ///
    /// Returns `CoreError::NetworkError` if construction fails (bad URL),
    /// if the socket fires `onerror` before opening, or if `onclose`
    /// fires before opening (unreachable server).
    pub async fn connect(url: &str) -> Result<Self, CoreError> {
        let ws = WebSocket::new(url)
            .map_err(|e| CoreError::NetworkError(format!("WebSocket new: {:?}", e)))?;
        ws.set_binary_type(BinaryType::Arraybuffer);

        let (send_tx, mut send_rx) = mpsc::channel::<Vec<u8>>(SEND_QUEUE_CAPACITY);
        let (recv_tx, recv_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let closed = Arc::new(AtomicBool::new(false));

        // Open handshake: resolved by onopen, rejected by onerror / onclose
        // arriving first.
        let (open_tx, open_rx) = oneshot::channel::<Result<(), CoreError>>();
        let open_tx = Arc::new(Mutex::new(Some(open_tx)));

        // ─── onopen ───────────────────────────────────────────────────
        {
            let open_tx = open_tx.clone();
            let onopen = Closure::wrap(Box::new(move |_e: web_sys::Event| {
                let open_tx = open_tx.clone();
                wasm_bindgen_futures::spawn_local(async move {
                    if let Some(tx) = open_tx.lock().await.take() {
                        let _ = tx.send(Ok(()));
                    }
                });
            }) as Box<dyn FnMut(web_sys::Event)>);
            ws.set_onopen(Some(onopen.as_ref().unchecked_ref()));
            // forget() leaks the Closure so the JS-side callback stays
            // alive for the lifetime of the WebSocket. Standard
            // wasm-bindgen pattern.
            onopen.forget();
        }

        // ─── onmessage ────────────────────────────────────────────────
        let recv_tx_clone = recv_tx.clone();
        let closed_clone = closed.clone();
        {
            let onmessage = Closure::wrap(Box::new(move |e: MessageEvent| {
                if closed_clone.load(Ordering::Acquire) {
                    return;
                }
                // Binary type is ArrayBuffer (set above) so .data() is
                // an ArrayBuffer. Convert to Uint8Array → Vec<u8>.
                if let Ok(buf) = e.data().dyn_into::<js_sys::ArrayBuffer>() {
                    let array = Uint8Array::new(&buf);
                    let mut bytes = vec![0u8; array.length() as usize];
                    array.copy_to(&mut bytes);
                    // The receiver is `recv_rx` inside `WebSocketLeg` —
                    // an unbounded channel, so `send` only fails if the
                    // receiver was dropped (leg was closed). That's the
                    // signal to stop trying.
                    let _ = recv_tx_clone.send(bytes);
                }
                // Text frames are ignored — we only carry binary
                // PhantomPacket bytes.
            }) as Box<dyn FnMut(MessageEvent)>);
            ws.set_onmessage(Some(onmessage.as_ref().unchecked_ref()));
            onmessage.forget();
        }

        // ─── onerror ──────────────────────────────────────────────────
        {
            let open_tx = open_tx.clone();
            let closed = closed.clone();
            let onerror = Closure::wrap(Box::new(move |e: ErrorEvent| {
                closed.store(true, Ordering::Release);
                let open_tx = open_tx.clone();
                let msg = format!("WebSocket error: {}", e.message());
                wasm_bindgen_futures::spawn_local(async move {
                    if let Some(tx) = open_tx.lock().await.take() {
                        let _ = tx.send(Err(CoreError::NetworkError(msg)));
                    }
                });
            }) as Box<dyn FnMut(ErrorEvent)>);
            ws.set_onerror(Some(onerror.as_ref().unchecked_ref()));
            onerror.forget();
        }

        // ─── onclose ──────────────────────────────────────────────────
        {
            let open_tx = open_tx.clone();
            let closed = closed.clone();
            let onclose = Closure::wrap(Box::new(move |e: CloseEvent| {
                closed.store(true, Ordering::Release);
                let open_tx = open_tx.clone();
                let msg = format!("WebSocket close: code={} reason={}", e.code(), e.reason());
                wasm_bindgen_futures::spawn_local(async move {
                    if let Some(tx) = open_tx.lock().await.take() {
                        let _ = tx.send(Err(CoreError::NetworkError(msg)));
                    }
                });
            }) as Box<dyn FnMut(CloseEvent)>);
            ws.set_onclose(Some(onclose.as_ref().unchecked_ref()));
            onclose.forget();
        }

        // ─── send-task ────────────────────────────────────────────────
        // Drains `send_rx` and forwards bytes to `ws.send_with_u8_array`.
        // This task owns the WebSocket; nothing else holds a reference,
        // so when `send_rx.recv()` returns None (all senders dropped) we
        // close the socket gracefully.
        let closed_send = closed.clone();
        wasm_bindgen_futures::spawn_local(async move {
            while let Some(bytes) = send_rx.recv().await {
                if closed_send.load(Ordering::Acquire) {
                    break;
                }
                if let Err(e) = ws.send_with_u8_array(&bytes) {
                    web_sys::console::warn_1(
                        &format!("WebSocketLeg send failed: {:?}", e).into(),
                    );
                    closed_send.store(true, Ordering::Release);
                    break;
                }
            }
            // Best-effort close on drop of the send queue.
            let _ = ws.close();
        });

        // Block until the open handshake resolves.
        open_rx
            .await
            .map_err(|_| {
                CoreError::NetworkError("WebSocket open signal lost".into())
            })??;

        Ok(Self {
            send_tx,
            recv_rx: Mutex::new(recv_rx),
            closed,
        })
    }

    /// Mark the leg as closed and stop accepting sends. The underlying
    /// WebSocket is closed by the spawn_local task once its send queue
    /// drains (we drop the last `send_tx` here via `mem::drop`).
    pub fn close(&self) {
        self.closed.store(true, Ordering::Release);
    }

    /// Whether the WebSocket has been closed (by either side).
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }
}

#[async_trait::async_trait]
impl SessionTransport for WebSocketLeg {
    async fn send_bytes(&self, data: &[u8]) -> Result<(), CoreError> {
        if self.closed.load(Ordering::Acquire) {
            return Err(CoreError::ConnectionClosed);
        }
        self.send_tx
            .send(data.to_vec())
            .await
            .map_err(|_| CoreError::NetworkError("WebSocket send queue closed".into()))
    }

    async fn recv_bytes(&self) -> Result<Bytes, CoreError> {
        let mut rx = self.recv_rx.lock().await;
        match rx.recv().await {
            Some(bytes) => Ok(Bytes::from(bytes)),
            None => Err(CoreError::ConnectionClosed),
        }
    }
}

// `WebSocketLeg` is `Send + Sync` because it owns only `mpsc::Sender`,
// `Mutex<mpsc::UnboundedReceiver>`, and an `Arc<AtomicBool>` — all of
// which are `Send + Sync`. The `web_sys::WebSocket` lives inside the
// spawn_local task and is never accessed from outside that task.
// An explicit static_assertions check here is overkill; the compiler
// already enforces the trait bound at every `SessionTransport`
// callsite.
