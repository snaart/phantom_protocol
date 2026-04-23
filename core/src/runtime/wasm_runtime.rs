//! `WasmRuntime` — `Runtime` impl for browser wasm32 builds.
//!
//! Uses `wasm_bindgen_futures::spawn_local` for task spawning (the wasm32
//! browser environment is single-threaded; tasks ride the JS event loop),
//! a `setTimeout`-driven `futures::channel::oneshot` for `sleep`, and
//! `std::time::Instant::now()` / `js_sys::Date::now()` for monotonic and
//! wall-clock time respectively.
//!
//! ## Cancellation
//!
//! `spawn_local` returns no handle, so abortability is added with
//! `futures::future::Abortable` — the wrapper races the user future against
//! an `AbortHandle` we hand to the returned [`SpawnHandle`]. A shared
//! `Arc<AtomicBool>` flips to `true` when the outer wrapper completes
//! (either the inner future finished, or it was aborted), driving
//! `SpawnHandle::is_finished()`.
//!
//! ## `setTimeout` indirection
//!
//! `web_sys::Window` is not in the crate's `web-sys` feature allow-list,
//! so this impl drives `setTimeout` via `js_sys::Reflect` on the global
//! object instead. That works in both browser main-thread and Web Worker
//! contexts (both expose `setTimeout` on their global). The closure is
//! intentionally leaked via [`Closure::forget`] — the JS runtime owns it
//! until the timer fires; if the future is dropped before then, the
//! closure simply fires into a closed channel and is reaped on the next
//! GC cycle.
//!
//! ## Gating
//!
//! Gated behind `#[cfg(target_arch = "wasm32")]`; the native build never
//! sees this module.

#![cfg(target_arch = "wasm32")]

use core::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use futures::channel::oneshot;
use futures::future::{AbortHandle, Abortable};
use futures::FutureExt;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::spawn_local;

use super::{BoxFuture, Runtime, SpawnHandle, SpawnHandleInner};

/// Browser-wasm32 [`Runtime`]. Zero-sized — construct with `WasmRuntime`
/// and wrap in `Arc` to share across tasks (the wasm32 build is
/// single-threaded; `Send + Sync` is satisfied trivially).
#[derive(Clone, Copy, Default)]
pub struct WasmRuntime;

impl Runtime for WasmRuntime {
    fn spawn(&self, fut: BoxFuture<()>) -> SpawnHandle {
        let (abort_handle, abort_reg) = AbortHandle::new_pair();
        let finished = Arc::new(AtomicBool::new(false));
        let finished_for_task = finished.clone();
        let wrapped = Abortable::new(fut, abort_reg);
        spawn_local(async move {
            // `Abortable` returns `Result<T, Aborted>`; we don't care which
            // arm we took — both are terminal for the task.
            let _ = wrapped.await;
            finished_for_task.store(true, Ordering::SeqCst);
        });
        SpawnHandle::from_inner(WasmSpawnHandle {
            abort_handle,
            finished,
        })
    }

    fn sleep(&self, duration: Duration) -> BoxFuture<()> {
        let (tx, rx) = oneshot::channel::<()>();
        // `Closure::once` consumes `tx` on the single JS-side invocation.
        let closure = Closure::once(Box::new(move || {
            let _ = tx.send(());
        }) as Box<dyn FnOnce()>);

        // Clamp at i32::MAX milliseconds — the HTML5 spec limits `setTimeout`
        // delays to a 32-bit signed range anyway. Anything larger is almost
        // certainly a logic bug, but saturating is safer than wrapping into
        // a near-zero negative.
        let ms: i32 = duration.as_millis().try_into().unwrap_or(i32::MAX).max(0);

        // Resolve `setTimeout` via the JS global object so we don't depend
        // on the `Window` web-sys feature (which isn't enabled in this
        // crate's `web-sys` feature set).
        let global = js_sys::global();
        let set_timeout = js_sys::Reflect::get(&global, &JsValue::from_str("setTimeout"))
            .expect("global.setTimeout missing — not a browser/worker context");
        let set_timeout: js_sys::Function = set_timeout
            .dyn_into()
            .expect("global.setTimeout is not a function");
        let _ = set_timeout
            .call2(
                &global,
                closure.as_ref().unchecked_ref(),
                &JsValue::from_f64(ms as f64),
            )
            .expect("setTimeout invocation failed");

        // The JS runtime now owns the closure until the timer fires.
        // Leaking it is intentional: the alternative is dropping it here,
        // which would invalidate the function pointer setTimeout is
        // holding and cause a use-after-free on the JS side.
        closure.forget();

        // Map the channel's `Result<(), Canceled>` to `()` — if the
        // sender is dropped (shouldn't happen here, but be defensive) we
        // resolve the sleep anyway rather than hang forever.
        rx.map(|_| ()).boxed()
    }

    fn now_monotonic(&self) -> Instant {
        // `std::time::Instant::now()` on `wasm32-unknown-unknown` is
        // backed by `performance.now()` in modern rustc and produces a
        // monotonic value suitable for RTT / expiry arithmetic.
        Instant::now()
    }

    fn now_wall_clock(&self) -> SystemTime {
        // `SystemTime::now()` panics on `wasm32-unknown-unknown`; route
        // through `Date.now()` (ms since UNIX epoch, as f64) instead.
        SystemTime::UNIX_EPOCH + Duration::from_millis(js_sys::Date::now() as u64)
    }
}

/// Inner type behind a [`SpawnHandle`] produced by [`WasmRuntime`].
///
/// Holds the `AbortHandle` (for `abort()`) and a shared boolean the spawned
/// task flips on completion (for `is_finished()`).
pub(super) struct WasmSpawnHandle {
    abort_handle: AbortHandle,
    finished: Arc<AtomicBool>,
}

impl SpawnHandleInner for WasmSpawnHandle {
    fn abort(&self) {
        self.abort_handle.abort();
    }

    fn is_finished(&self) -> bool {
        self.finished.load(Ordering::SeqCst)
    }
}
