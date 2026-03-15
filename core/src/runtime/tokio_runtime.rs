//! [`TokioRuntime`] — default [`Runtime`] implementation backed by tokio.
//!
//! Preserves today's behavior verbatim (`tokio::spawn`,
//! `tokio::time::sleep`, `std::time::Instant`, `std::time::SystemTime`).
//! Call sites that take an `Arc<dyn Runtime>` can substitute this without
//! observable behavioral change.

use std::time::{Duration, Instant, SystemTime};

use tokio::task::JoinHandle;

use super::{BoxFuture, Runtime, SpawnHandle, SpawnHandleInner};

/// Tokio-backed [`Runtime`]. Zero-sized — construct with `TokioRuntime`
/// and wrap in `Arc` to share across tasks.
#[derive(Clone, Copy, Default)]
pub struct TokioRuntime;

impl Runtime for TokioRuntime {
    fn spawn(&self, fut: BoxFuture<()>) -> SpawnHandle {
        let handle: JoinHandle<()> = tokio::spawn(fut);
        SpawnHandle::from_inner(TokioSpawnHandle { handle })
    }

    fn sleep(&self, duration: Duration) -> BoxFuture<()> {
        Box::pin(tokio::time::sleep(duration))
    }

    fn now_monotonic(&self) -> Instant {
        Instant::now()
    }

    fn now_wall_clock(&self) -> SystemTime {
        SystemTime::now()
    }
}

/// Inner type behind a [`SpawnHandle`] produced by [`TokioRuntime`]. Wraps
/// a `tokio::task::JoinHandle` so the public-facing handle stays opaque.
pub(super) struct TokioSpawnHandle {
    handle: JoinHandle<()>,
}

impl SpawnHandleInner for TokioSpawnHandle {
    fn abort(&self) {
        self.handle.abort();
    }

    fn is_finished(&self) -> bool {
        self.handle.is_finished()
    }
}
