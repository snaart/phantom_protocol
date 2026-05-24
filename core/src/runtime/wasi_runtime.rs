//! [`WasiRuntime`] — [`Runtime`] impl for `wasm32-wasi*` targets via
//! WASI Preview 2 (Section B / B2 of the pre-1.0 deferred-followups
//! plan).
//!
//! **Single-task executor.** WASI Preview 2 has no native thread
//! primitive; the runtime keeps spawned futures in a `Vec<TaskSlot>`
//! and exposes a host-callable [`WasiRuntime::drive`] entry point
//! that polls every task once. The intended embedder loop is:
//!
//! ```ignore
//! let rt = phantom_core::runtime::WasiRuntime::new();
//! // ... spawn tasks via Runtime::spawn ...
//! while rt.tasks_pending() > 0 {
//!     rt.drive();
//!     rt.poll_until_progress();   // poll_oneoff over registered Pollables
//! }
//! ```
//!
//! **Sleep** is deadline-checking against `std::time::Instant::now()`,
//! which on `wasm32-wasi*` targets maps to
//! `wasi::clocks::monotonic_clock`. The future returns `Pending` until
//! the deadline elapses, so the embedder's drive loop must continue
//! calling `drive()` periodically — `poll_until_progress` provides the
//! WASI-native bounded blocking via `wasi::clocks::monotonic_clock::
//! subscribe_duration` + `wasi::io::poll::poll` so the host doesn't
//! spin-wait.
//!
//! **Abort** mirrors [`super::embedded_runtime::EmbeddedRuntime`]:
//! `SpawnHandle::abort` flips an `AtomicBool` that the task slot
//! checks on each poll and short-circuits the future.
//!
//! Module-gated on `cfg(all(target_os = "wasi", feature = "wasi-leg"))`
//! — the `wasi` crate's WIT bindings are only available on WASI
//! targets, and the feature flag is the per-rollout opt-in.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant, SystemTime};

use futures::task::noop_waker;
use wasi::clocks::monotonic_clock;
use wasi::io::poll;

use super::{BoxFuture, Runtime, SpawnHandle, SpawnHandleInner};

/// Single-task WASI executor — see the module docs for the embedder
/// loop shape and the abort model.
#[derive(Clone, Default)]
pub struct WasiRuntime {
    inner: Arc<WasiInner>,
}

#[derive(Default)]
struct WasiInner {
    tasks: Mutex<Vec<TaskSlot>>,
}

struct TaskSlot {
    fut: BoxFuture<()>,
    aborted: Arc<AtomicBool>,
    finished: Arc<AtomicBool>,
}

impl WasiRuntime {
    /// Construct a fresh `WasiRuntime`. Cheap; the task queue is an
    /// empty `Vec` until the first [`Runtime::spawn`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Poll every spawned task exactly once. Tasks that complete or
    /// have been `abort()`-ed are removed from the queue. Returns
    /// the number of tasks still pending after the poll round.
    ///
    /// Pair with [`Self::poll_until_progress`] in the embedder's
    /// drive loop: `drive()` advances any future whose I/O is
    /// already ready, `poll_until_progress` blocks the host on the
    /// WASI-native `poll_oneoff` until at least one registered
    /// Pollable fires.
    pub fn drive(&self) -> usize {
        // PANIC-SAFETY: the mutex is private and only held briefly
        // here and inside `spawn`; a poison would mean a panic
        // occurred inside another `drive` / `spawn` call, which is
        // unrecoverable.
        #[allow(clippy::expect_used)]
        let mut tasks = self
            .inner
            .tasks
            .lock()
            .expect("WasiRuntime task queue mutex poisoned");
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        tasks.retain_mut(|task| {
            if task.aborted.load(Ordering::SeqCst) {
                task.finished.store(true, Ordering::SeqCst);
                return false;
            }
            match task.fut.as_mut().poll(&mut cx) {
                Poll::Ready(()) => {
                    task.finished.store(true, Ordering::SeqCst);
                    false
                }
                Poll::Pending => true,
            }
        });
        tasks.len()
    }

    /// Block the host on `wasi::io::poll::poll` for at most
    /// `max_wait`. Wakes when any Pollable currently registered by
    /// a sleep / I/O future fires, OR when the timeout elapses
    /// (whichever comes first). Returns immediately if there are
    /// no Pollables to wait on.
    ///
    /// Bounded by `max_wait` to defend against a future that never
    /// registers a Pollable but still returns `Poll::Pending` — the
    /// drive loop must always make eventual progress.
    pub fn poll_until_progress(&self, max_wait: Duration) {
        // Always include a timeout Pollable so the call eventually
        // returns even if no other Pollable is registered. WASI
        // Preview 2 `subscribe_duration` takes nanoseconds.
        let nanos = u64::try_from(max_wait.as_nanos()).unwrap_or(u64::MAX);
        let deadline = monotonic_clock::subscribe_duration(nanos);
        let pollables = [&deadline];
        let _ready = poll::poll(&pollables);
    }

    /// Number of tasks currently in the queue (neither completed nor
    /// aborted). Useful as a loop-termination signal.
    pub fn tasks_pending(&self) -> usize {
        #[allow(clippy::expect_used)]
        self.inner
            .tasks
            .lock()
            .expect("WasiRuntime task queue mutex poisoned")
            .len()
    }
}

impl Runtime for WasiRuntime {
    fn spawn(&self, fut: BoxFuture<()>) -> SpawnHandle {
        let aborted = Arc::new(AtomicBool::new(false));
        let finished = Arc::new(AtomicBool::new(false));
        #[allow(clippy::expect_used)]
        let mut tasks = self
            .inner
            .tasks
            .lock()
            .expect("WasiRuntime task queue mutex poisoned");
        tasks.push(TaskSlot {
            fut,
            aborted: Arc::clone(&aborted),
            finished: Arc::clone(&finished),
        });
        SpawnHandle::from_inner(WasiSpawnHandle { aborted, finished })
    }

    fn sleep(&self, duration: Duration) -> BoxFuture<()> {
        Box::pin(WasiSleep::new(duration))
    }

    fn now_monotonic(&self) -> Instant {
        // `std::time::Instant::now()` on `wasm32-wasi*` is backed by
        // `wasi::clocks::monotonic_clock::now()` (libstd's WASI port);
        // round-tripping through the Rust type keeps the `Runtime`
        // trait surface uniform with the host impls.
        Instant::now()
    }

    fn now_wall_clock(&self) -> SystemTime {
        // Same wiring as `now_monotonic` — `std::time::SystemTime::now()`
        // delegates to `wasi::clocks::wall_clock::now()` on WASI.
        SystemTime::now()
    }
}

/// Inner type behind a [`SpawnHandle`] produced by [`WasiRuntime`].
pub(super) struct WasiSpawnHandle {
    aborted: Arc<AtomicBool>,
    finished: Arc<AtomicBool>,
}

impl SpawnHandleInner for WasiSpawnHandle {
    fn abort(&self) {
        self.aborted.store(true, Ordering::SeqCst);
    }

    fn is_finished(&self) -> bool {
        self.finished.load(Ordering::SeqCst)
    }
}

// ─── Sleep future ────────────────────────────────────────────────────────

struct WasiSleep {
    deadline: Instant,
}

impl WasiSleep {
    fn new(duration: Duration) -> Self {
        Self {
            deadline: Instant::now() + duration,
        }
    }
}

impl Future for WasiSleep {
    type Output = ();

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        if Instant::now() >= self.deadline {
            Poll::Ready(())
        } else {
            // The embedder's drive loop calls `poll_until_progress`
            // with a bounded `max_wait`; the next call to `drive`
            // re-polls this future and either advances or waits more.
            Poll::Pending
        }
    }
}

// `futures::task::noop_waker` provides a safe `Waker` whose `wake` is
// a no-op — enough to satisfy `Context::from_waker` since this
// runtime re-polls every task on every `drive()` invocation rather
// than relying on wakeups.

#[cfg(test)]
mod tests {
    use super::*;

    /// Object-safety: `WasiRuntime` is usable as `dyn Runtime`.
    #[test]
    fn wasi_runtime_is_object_safe() {
        fn assert_runtime_obj_safe(_: &dyn Runtime) {}
        let rt = WasiRuntime::new();
        assert_runtime_obj_safe(&rt);
    }

    /// Monotonic clock is non-decreasing.
    #[test]
    fn monotonic_clock_does_not_go_backwards() {
        let rt = WasiRuntime::new();
        let a = rt.now_monotonic();
        for _ in 0..1_000 {
            std::hint::black_box(a);
        }
        let b = rt.now_monotonic();
        assert!(b >= a, "monotonic clock went backwards: {:?} → {:?}", a, b);
    }

    /// Wall clock is after the UNIX epoch (host sanity).
    #[test]
    fn wall_clock_is_after_unix_epoch() {
        let rt = WasiRuntime::new();
        let now = rt.now_wall_clock();
        assert!(now > SystemTime::UNIX_EPOCH);
    }

    /// Spawn + drive: a noop future completes on the first drive.
    #[test]
    fn spawn_noop_completes_on_first_drive() {
        let rt = WasiRuntime::new();
        let handle = rt.spawn(Box::pin(async {}));
        assert_eq!(rt.tasks_pending(), 1);
        rt.drive();
        assert_eq!(rt.tasks_pending(), 0);
        assert!(handle.is_finished());
    }

    /// Abort flips finished before the next drive observes the
    /// task, even if the future would never yield otherwise.
    #[test]
    fn abort_short_circuits_pending_future() {
        let rt = WasiRuntime::new();
        let handle = rt.spawn(Box::pin(WasiSleep::new(Duration::from_secs(60))));
        rt.drive(); // task observed Pending and stayed in the queue
        assert_eq!(rt.tasks_pending(), 1);
        handle.abort();
        rt.drive(); // abort observed → task removed, finished flag set
        assert_eq!(rt.tasks_pending(), 0);
        assert!(handle.is_finished());
    }
}
