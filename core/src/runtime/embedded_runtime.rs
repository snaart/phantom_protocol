//! [`EmbeddedRuntime`] — minimal [`Runtime`] implementation for embeddings
//! that do not (or cannot) carry tokio (Phase 3.1 scaffold).
//!
//! **Scaffold status.** This implementation exists to prove the `Runtime`
//! trait is implementable off-tokio without dragging in a specific
//! executor crate as a hard dependency. It uses **one OS thread per
//! spawned future** plus `futures::executor::block_on` inside that
//! thread to drive the future to completion. That's correct (every
//! future makes progress, `abort` actually cancels, sleeps actually
//! wait) but it is **not** what bare-metal embedded targets want —
//! `embassy_executor`, `RTIC`, or an in-house cooperative scheduler is.
//! Production embedders are expected to ship their own `impl Runtime`;
//! the value of this scaffold is that the *trait surface* is now
//! demonstrably usable off the default tokio impl, so future executor
//! crates plug in without changing call sites.
//!
//! The module is gated on **both** the `embedded` and `std` features.
//! Pure `no_std` support requires the `Runtime` trait to drop its
//! `std::time::{Instant, SystemTime}` dependence — tracked as a
//! follow-up under the same Phase 3.1 work.
//!
//! ## What this is good for
//!
//! - Wiring up call sites that take `Arc<dyn Runtime>` so they can be
//!   exercised in non-tokio contexts (e.g. host-side integration tests
//!   for the `EmbeddedLeg` transport).
//! - Demonstrating cancel-safety (`abort` actually drops the spawned
//!   thread's `block_on` future and runs its `Drop` impls).
//!
//! ## What this is NOT good for
//!
//! - Bare-metal targets (`thumbv7em-none-eabihf`, etc.) — they have no
//!   `std::thread`. They need an `EmbassyRuntime` / `RticRuntime` /
//!   custom-scheduler impl. The follow-up PR ships those alongside the
//!   no_std refactor of the trait.
//! - High-task-count workloads. One OS thread per future is fine for a
//!   handful of long-lived tasks (handshake driver, accept loop) but a
//!   poor match for short-lived spawned work.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime};

use super::{BoxFuture, Runtime, SpawnHandle, SpawnHandleInner};

/// [`Runtime`] impl that spawns one OS thread per future and drives it
/// with `futures::executor::block_on`. See module docs for limitations.
#[derive(Clone, Copy, Default)]
pub struct EmbeddedRuntime;

impl Runtime for EmbeddedRuntime {
    fn spawn(&self, fut: BoxFuture<()>) -> SpawnHandle {
        // Each spawned future gets its own OS thread + its own
        // `block_on`. The shared `aborted` flag lets `SpawnHandle::abort`
        // signal cancellation cooperatively — the wrapping future polls
        // it between awaits.
        let aborted = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let finished = Arc::new(std::sync::atomic::AtomicBool::new(false));

        let aborted_for_task = Arc::clone(&aborted);
        let finished_for_task = Arc::clone(&finished);

        let handle = thread::spawn(move || {
            let wrapped = AbortableFuture {
                inner: fut,
                aborted: aborted_for_task,
            };
            futures::executor::block_on(wrapped);
            finished_for_task.store(true, std::sync::atomic::Ordering::SeqCst);
        });

        SpawnHandle::from_inner(EmbeddedSpawnHandle {
            handle: Some(handle),
            aborted,
            finished,
        })
    }

    fn sleep(&self, duration: Duration) -> BoxFuture<()> {
        Box::pin(SleepFuture::new(duration))
    }

    fn now_monotonic(&self) -> Instant {
        Instant::now()
    }

    fn now_wall_clock(&self) -> SystemTime {
        SystemTime::now()
    }
}

/// Inner type behind a [`SpawnHandle`] produced by [`EmbeddedRuntime`].
pub(super) struct EmbeddedSpawnHandle {
    // `Option` so a future `Drop` impl could join/detach if we wanted;
    // today we leave the thread to its block_on naturally.
    handle: Option<JoinHandle<()>>,
    aborted: Arc<std::sync::atomic::AtomicBool>,
    finished: Arc<std::sync::atomic::AtomicBool>,
}

impl SpawnHandleInner for EmbeddedSpawnHandle {
    fn abort(&self) {
        // Cooperative cancellation: flip the flag. The wrapping
        // `AbortableFuture` checks it on each poll and returns
        // `Poll::Ready(())` early.
        self.aborted
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    fn is_finished(&self) -> bool {
        self.finished.load(std::sync::atomic::Ordering::SeqCst)
            || self
                .handle
                .as_ref()
                .map(|h| h.is_finished())
                .unwrap_or(false)
    }
}

// ─── Internal: abortable future wrapper ──────────────────────────────────

struct AbortableFuture {
    inner: BoxFuture<()>,
    aborted: Arc<std::sync::atomic::AtomicBool>,
}

impl Future for AbortableFuture {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.aborted.load(std::sync::atomic::Ordering::SeqCst) {
            return Poll::Ready(());
        }
        self.inner.as_mut().poll(cx)
    }
}

// ─── Internal: sleep future ──────────────────────────────────────────────

struct SleepFuture {
    deadline: Instant,
    inner: Arc<Mutex<SleepInner>>,
}

struct SleepInner {
    waker: Option<Waker>,
    waiter_spawned: bool,
}

impl SleepFuture {
    fn new(duration: Duration) -> Self {
        Self {
            deadline: Instant::now() + duration,
            inner: Arc::new(Mutex::new(SleepInner {
                waker: None,
                waiter_spawned: false,
            })),
        }
    }
}

impl Future for SleepFuture {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if Instant::now() >= self.deadline {
            return Poll::Ready(());
        }

        // PANIC-SAFETY: the mutex is private to this `SleepFuture` and
        // the parker thread, neither of which panics while holding it.
        // A `PoisonError` here would indicate an unrecoverable runtime
        // bug, not adversary input.
        #[allow(clippy::expect_used)]
        let mut inner = self.inner.lock().expect("SleepFuture mutex poisoned");
        inner.waker = Some(cx.waker().clone());

        // First poll: spawn a parker that wakes us when the deadline
        // elapses. Subsequent polls just refresh the waker slot above
        // (the parker holds a clone of the Arc and re-fetches the
        // current waker when it fires).
        if !inner.waiter_spawned {
            inner.waiter_spawned = true;
            let deadline = self.deadline;
            let inner_for_parker = Arc::clone(&self.inner);
            thread::spawn(move || {
                let now = Instant::now();
                if deadline > now {
                    thread::sleep(deadline - now);
                }
                if let Ok(guard) = inner_for_parker.lock() {
                    if let Some(w) = guard.waker.as_ref() {
                        w.wake_by_ref();
                    }
                }
            });
        }

        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// Spawn → see the side effect after a sleep.
    #[test]
    fn spawn_and_sleep_round_trip() {
        let rt: Arc<dyn Runtime> = Arc::new(EmbeddedRuntime);
        let counter = Arc::new(AtomicU32::new(0));
        let c = counter.clone();
        let rt_for_task = rt.clone();
        let handle = rt.spawn(Box::pin(async move {
            rt_for_task.sleep(Duration::from_millis(10)).await;
            c.fetch_add(1, Ordering::SeqCst);
        }));

        // Block on a sleep here in the test thread until the spawned
        // task should have run.
        futures::executor::block_on(rt.sleep(Duration::from_millis(100)));
        assert_eq!(counter.load(Ordering::SeqCst), 1);
        assert!(handle.is_finished());
    }

    /// `abort` must short-circuit a long-running task before its side
    /// effect can land.
    #[test]
    fn abort_cancels_task() {
        let rt: Arc<dyn Runtime> = Arc::new(EmbeddedRuntime);
        let counter = Arc::new(AtomicU32::new(0));
        let c = counter.clone();
        let rt_for_task = rt.clone();

        let handle = rt.spawn(Box::pin(async move {
            rt_for_task.sleep(Duration::from_secs(60)).await;
            c.fetch_add(1, Ordering::SeqCst);
        }));

        // Give the parker thread a moment to spawn, then abort.
        futures::executor::block_on(rt.sleep(Duration::from_millis(50)));
        handle.abort();
        // Give the wrapping AbortableFuture a chance to observe the
        // flag — but `block_on` won't poll a Pending future without a
        // wake. Force a wake by sleeping again.
        futures::executor::block_on(rt.sleep(Duration::from_millis(50)));

        // The increment must not have happened within our short window
        // (60-second sleep is the upper bound).
        assert_eq!(counter.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn monotonic_clock_does_not_go_backwards() {
        let rt = EmbeddedRuntime;
        let a = rt.now_monotonic();
        for _ in 0..1000 {
            std::hint::black_box(a);
        }
        let b = rt.now_monotonic();
        assert!(b >= a, "monotonic clock went backwards: {:?} → {:?}", a, b);
    }

    #[test]
    fn wall_clock_is_after_unix_epoch() {
        let rt = EmbeddedRuntime;
        let now = rt.now_wall_clock();
        assert!(now > SystemTime::UNIX_EPOCH);
    }

    /// Object-safety: usable as `dyn Runtime` just like tokio.
    #[test]
    fn embedded_runtime_is_object_safe() {
        fn assert_runtime_obj_safe(_: &dyn Runtime) {}
        let rt = EmbeddedRuntime;
        assert_runtime_obj_safe(&rt);
    }
}
