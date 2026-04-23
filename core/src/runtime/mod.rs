//! Async runtime abstraction (Phase 3.1).
//!
//! `phantom_core` historically hard-coded `tokio` everywhere: every
//! `tokio::spawn`, every `tokio::time::sleep`, every `tokio::sync::Mutex`,
//! every `tokio::net::TcpStream`. That couples the library to a
//! multi-threaded executor that does not exist on `wasm32-unknown-unknown`
//! (single-threaded, JS event loop) or on bare-metal embedded targets
//! (no executor at all without `embassy`/RTIC).
//!
//! This module introduces a small trait surface — `Runtime` — that the
//! rest of the crate can use *in place of* direct tokio calls. The default
//! implementation, [`TokioRuntime`], preserves today's behavior verbatim.
//! Follow-up commits will gradually migrate call sites; this commit lands
//! only the trait + the default impl + tests.
//!
//! ## What the trait covers
//!
//! - **Task spawning** — `spawn(boxed_future) -> SpawnHandle`. The handle
//!   exposes a non-blocking `abort()` so callers can cancel the task.
//! - **Sleep** — `sleep(duration) -> BoxFuture<()>` for delay loops.
//! - **Monotonic clock** — `now_monotonic() -> Instant` for RTT and
//!   expiry math.
//! - **Wall-clock** — `now_wall_clock() -> SystemTime` for cookie buckets
//!   and timestamp-bound material.
//!
//! ## What the trait deliberately does NOT cover (yet)
//!
//! - **Channels** — `tokio::sync::mpsc` is portable enough across `tokio`
//!   and `tokio` derivatives that we keep using it directly.
//! - **Mutexes** — see above.
//! - **Network I/O** — this is the [`crate::transport::legs`] trait's job.
//!   `TcpStream` / `UdpSocket` are leg-impl details, not runtime-level.
//!
//! ## Implementations
//!
//! | Impl | Status | Target |
//! | --- | --- | --- |
//! | [`TokioRuntime`] | ✅ | Linux / macOS / Windows / iOS / Android servers and clients |
//! | `WasmRuntime`    | ✅ (`cfg(target_arch = "wasm32")`) | `wasm32-unknown-unknown` browsers via `wasm-bindgen-futures` |
//! | `EmbeddedRuntime` | scaffold | `embassy` / bare metal |
//!
//! The non-tokio implementations are scaffolded under future feature
//! flags; this commit only ships the trait and the tokio default so the
//! call-site migration can begin against a stable abstraction.

use std::future::Future;
use std::pin::Pin;
use std::time::{Duration, Instant, SystemTime};

mod tokio_runtime;

pub use tokio_runtime::TokioRuntime;

#[cfg(target_arch = "wasm32")]
pub mod wasm_runtime;

#[cfg(target_arch = "wasm32")]
pub use wasm_runtime::WasmRuntime;

/// Boxed, owned, `Send` future of unit output — the shape `Runtime::spawn`
/// and `Runtime::sleep` work in.
///
/// `'static` lifetime because spawned futures outlive any borrow at the
/// call site; `Send` because the default tokio impl is multi-threaded and
/// the futures cross thread boundaries. On future WASM impls the Send
/// bound is harmless — single-threaded executors accept Send futures.
pub type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;

/// Async runtime abstraction.
///
/// Every method takes `&self` so a single runtime handle (typically wrapped
/// in `Arc<dyn Runtime>`) can be shared across spawned tasks.
pub trait Runtime: Send + Sync + 'static {
    /// Spawn a future to run on the runtime. The returned [`SpawnHandle`]
    /// can be `abort()`-ed to request cancellation; dropping the handle
    /// detaches the task without cancelling it.
    fn spawn(&self, fut: BoxFuture<()>) -> SpawnHandle;

    /// Yield control for at least `duration`.
    fn sleep(&self, duration: Duration) -> BoxFuture<()>;

    /// Monotonic instant — strictly non-decreasing across calls on the
    /// same runtime. Used for RTT measurement, retry timers, and any
    /// duration arithmetic that must not be affected by wall-clock skew.
    fn now_monotonic(&self) -> Instant;

    /// Wall-clock time. May jump forward or backward as the system clock
    /// is adjusted. Used for timestamp-bound material (cookie buckets,
    /// PoW challenge expiry).
    fn now_wall_clock(&self) -> SystemTime;
}

/// Opaque handle to a spawned task. Created by [`Runtime::spawn`].
///
/// Calling [`abort`](Self::abort) requests the runtime cancel the task at
/// the next `.await` point. The cancellation is cooperative — a task that
/// never yields will run to completion regardless.
///
/// Dropping a `SpawnHandle` without calling `abort` detaches the task: it
/// continues running independently. This matches `tokio::task::JoinHandle`
/// semantics.
pub struct SpawnHandle {
    inner: Box<dyn SpawnHandleInner>,
}

impl SpawnHandle {
    /// Build a handle from any inner abort-capable implementation.
    /// Used by runtime adapters (e.g. [`TokioRuntime`]) to wrap their
    /// concrete `JoinHandle`-equivalent into the trait object.
    pub fn from_inner<T: SpawnHandleInner>(inner: T) -> Self {
        Self {
            inner: Box::new(inner),
        }
    }

    /// Request cancellation of the spawned task. Idempotent.
    pub fn abort(&self) {
        self.inner.abort();
    }

    /// Whether the task has finished (success or cancellation).
    pub fn is_finished(&self) -> bool {
        self.inner.is_finished()
    }
}

impl std::fmt::Debug for SpawnHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpawnHandle")
            .field("is_finished", &self.is_finished())
            .finish()
    }
}

/// Implementation detail of [`SpawnHandle`]. Runtime adapters implement
/// this on their concrete handle type.
pub trait SpawnHandleInner: Send + 'static {
    fn abort(&self);
    fn is_finished(&self) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// Spawn → sleep → see the side effect.
    #[tokio::test]
    async fn tokio_runtime_spawn_and_sleep() {
        let rt: Arc<dyn Runtime> = Arc::new(TokioRuntime);
        let counter = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let c = counter.clone();
        let rt_for_task = rt.clone();
        let handle = rt.spawn(Box::pin(async move {
            rt_for_task.sleep(Duration::from_millis(10)).await;
            c.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }));

        // Wait long enough for the task to run.
        rt.sleep(Duration::from_millis(100)).await;
        assert_eq!(counter.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert!(handle.is_finished());
    }

    /// Aborting a long-running task must prevent its side effect.
    #[tokio::test]
    async fn tokio_runtime_abort_cancels_task() {
        let rt: Arc<dyn Runtime> = Arc::new(TokioRuntime);
        let counter = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let c = counter.clone();
        let rt_for_task = rt.clone();

        let handle = rt.spawn(Box::pin(async move {
            rt_for_task.sleep(Duration::from_secs(60)).await;
            c.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }));

        // Give the task a moment to actually start awaiting the sleep,
        // then abort. The 60-second sleep will never elapse.
        rt.sleep(Duration::from_millis(20)).await;
        handle.abort();
        rt.sleep(Duration::from_millis(20)).await;

        assert_eq!(counter.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    /// `now_monotonic` must be non-decreasing within a single thread.
    #[test]
    fn monotonic_clock_does_not_go_backwards() {
        let rt = TokioRuntime;
        let a = rt.now_monotonic();
        // Spin for a few microseconds.
        for _ in 0..1000 {
            std::hint::black_box(a);
        }
        let b = rt.now_monotonic();
        assert!(b >= a, "monotonic clock went backwards: {:?} → {:?}", a, b);
    }

    /// `now_wall_clock` returns a `SystemTime` that's at or after the
    /// UNIX epoch (this is essentially "the host clock is sane").
    #[test]
    fn wall_clock_is_after_unix_epoch() {
        let rt = TokioRuntime;
        let now = rt.now_wall_clock();
        assert!(now > SystemTime::UNIX_EPOCH);
    }

    /// Object-safety check — the trait must be usable as `dyn Runtime`.
    #[test]
    fn runtime_is_object_safe() {
        fn assert_runtime_obj_safe(_: &dyn Runtime) {}
        let rt = TokioRuntime;
        assert_runtime_obj_safe(&rt);
    }
}
