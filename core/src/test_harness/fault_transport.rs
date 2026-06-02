//! Fault-injecting [`SessionTransport`] wrapper for loss-recovery testing.
//!
//! Wraps any inner [`SessionTransport`] and injects faults on the send path. It
//! supports four deterministic, index-addressed faults:
//!
//! - **Drop** — by fixed 0-based send index, or "drop the next N sends from now"
//!   (armed at runtime). A dropped send still returns `Ok(())` to the caller
//!   (the sender believes the bytes left the host); the frame is simply never
//!   handed to the inner transport, exactly as a packet lost in the network.
//! - **Duplicate** — forward a frame to the inner transport twice, so the
//!   receiver's replay window / dedup path is exercised.
//! - **Reorder** — hold the frame at a given index and release it *after* the
//!   next forwarded frame (an adjacent swap), so out-of-order delivery is
//!   exercised. A held frame is flushed by the following send, or explicitly via
//!   [`LossyTransport::flush`]; reorder a non-final frame, or call `flush`.
//! - **Delay** — sleep a fixed duration before forwarding every send, to inject
//!   latency (RTT / RTO timing).
//!
//! Faults compose (a frame can be delayed *and* duplicated, etc.). This is the
//! substrate the reliable-delivery / loss-recovery tests need — without a
//! transport that can drop, dup, reorder, or delay a frame, retransmission and
//! out-of-order handling cannot be exercised at all.
//!
//! Fault state lives behind a cloneable [`FaultControl`] handle so a test can
//! arm faults *after* the transport has been moved into a session's data pump
//! (e.g. drop the first data frame once the handshake has completed).

use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;

use crate::errors::CoreError;
use crate::transport::session_transport::SessionTransport;

struct FaultState {
    /// Monotonic count of sends seen so far (0-based index of the next send).
    send_index: AtomicU64,
    /// Number of upcoming sends to drop unconditionally (armed at runtime).
    arm_drop: AtomicU64,
    /// Fixed 0-based send indices to drop (set at construction).
    drop_indices: HashSet<u64>,
    /// Fixed 0-based send indices to forward twice (duplicate).
    dup_indices: HashSet<u64>,
    /// Fixed 0-based send indices to hold and release after the next send
    /// (adjacent reorder).
    reorder_indices: HashSet<u64>,
    /// A frame held back by a reorder, awaiting the next forwarded send.
    pending_reorder: Mutex<Option<Vec<u8>>>,
    /// Per-send forwarding delay in milliseconds (0 = none).
    delay_ms: AtomicU64,
}

/// What to do with the current send. Returned by [`FaultControl::classify`],
/// which also advances the send index.
enum SendFault {
    /// Forward to the inner transport unchanged.
    Forward,
    /// Drop (never forward) — simulates network loss.
    Drop,
    /// Forward twice.
    Duplicate,
    /// Hold this frame and release it after the next forwarded send.
    Reorder,
}

/// Cloneable handle to a [`LossyTransport`]'s fault state.
///
/// Retain a clone in the test to arm faults after the transport itself has been
/// moved into a session pump.
#[derive(Clone)]
pub struct FaultControl {
    state: Arc<FaultState>,
}

impl FaultControl {
    fn build(
        drop_indices: HashSet<u64>,
        dup_indices: HashSet<u64>,
        reorder_indices: HashSet<u64>,
        delay_ms: u64,
    ) -> Self {
        Self {
            state: Arc::new(FaultState {
                send_index: AtomicU64::new(0),
                arm_drop: AtomicU64::new(0),
                drop_indices,
                dup_indices,
                reorder_indices,
                pending_reorder: Mutex::new(None),
                delay_ms: AtomicU64::new(delay_ms),
            }),
        }
    }

    /// An empty control — injects nothing until armed.
    pub fn new() -> Self {
        Self::build(HashSet::new(), HashSet::new(), HashSet::new(), 0)
    }

    /// A control that drops the sends at these fixed 0-based indices.
    pub fn with_drop_indices(indices: &[u64]) -> Self {
        Self::build(
            indices.iter().copied().collect(),
            HashSet::new(),
            HashSet::new(),
            0,
        )
    }

    /// A control that forwards the sends at these fixed 0-based indices twice.
    pub fn with_dup_indices(indices: &[u64]) -> Self {
        Self::build(
            HashSet::new(),
            indices.iter().copied().collect(),
            HashSet::new(),
            0,
        )
    }

    /// A control that reorders (holds-then-releases-after-next) the sends at
    /// these fixed 0-based indices.
    pub fn with_reorder_indices(indices: &[u64]) -> Self {
        Self::build(
            HashSet::new(),
            HashSet::new(),
            indices.iter().copied().collect(),
            0,
        )
    }

    /// A control that sleeps `delay` before forwarding every send.
    pub fn with_delay(delay: Duration) -> Self {
        Self::build(
            HashSet::new(),
            HashSet::new(),
            HashSet::new(),
            delay.as_millis() as u64,
        )
    }

    /// Drop the next `n` sends from now, regardless of index. Use right after a
    /// handshake completes to target the first data frame(s).
    pub fn arm_drop_next(&self, n: u64) {
        self.state.arm_drop.store(n, Ordering::Relaxed);
    }

    /// Set the per-send forwarding delay (latency injection). `Duration::ZERO`
    /// disables it.
    pub fn set_delay(&self, delay: Duration) {
        self.state
            .delay_ms
            .store(delay.as_millis() as u64, Ordering::Relaxed);
    }

    /// Classify the current send, advancing the send index. Drop takes
    /// precedence, then duplicate, then reorder; otherwise forward.
    fn classify(&self) -> SendFault {
        let index = self.state.send_index.fetch_add(1, Ordering::Relaxed);
        if self.state.drop_indices.contains(&index) || self.consume_armed_drop() {
            return SendFault::Drop;
        }
        if self.state.dup_indices.contains(&index) {
            return SendFault::Duplicate;
        }
        if self.state.reorder_indices.contains(&index) {
            return SendFault::Reorder;
        }
        SendFault::Forward
    }

    /// The configured per-send delay, if any.
    fn delay(&self) -> Option<Duration> {
        match self.state.delay_ms.load(Ordering::Relaxed) {
            0 => None,
            ms => Some(Duration::from_millis(ms)),
        }
    }

    /// Take any frame held back by a reorder (to release after the current send).
    fn take_pending_reorder(&self) -> Option<Vec<u8>> {
        self.state.pending_reorder.lock().expect("poisoned").take()
    }

    /// Hold a frame for reorder; returns any previously-held frame so the caller
    /// can flush it (a second reorder before the first is released).
    fn hold_for_reorder(&self, data: Vec<u8>) -> Option<Vec<u8>> {
        self.state
            .pending_reorder
            .lock()
            .expect("poisoned")
            .replace(data)
    }

    fn consume_armed_drop(&self) -> bool {
        loop {
            let pending = self.state.arm_drop.load(Ordering::Relaxed);
            if pending == 0 {
                return false;
            }
            if self
                .state
                .arm_drop
                .compare_exchange_weak(pending, pending - 1, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                return true;
            }
        }
    }
}

impl Default for FaultControl {
    fn default() -> Self {
        Self::new()
    }
}

/// A [`SessionTransport`] that injects faults around an inner transport.
pub struct LossyTransport<T> {
    inner: T,
    control: FaultControl,
}

impl<T> LossyTransport<T> {
    /// Wrap `inner`, sharing the given [`FaultControl`] handle.
    pub fn new(inner: T, control: FaultControl) -> Self {
        Self { inner, control }
    }

    /// Convenience: wrap `inner`, dropping the sends at the given 0-based indices.
    pub fn drop_sends(inner: T, indices: &[u64]) -> Self {
        Self::new(inner, FaultControl::with_drop_indices(indices))
    }

    /// Convenience: wrap `inner`, forwarding the sends at the given 0-based
    /// indices twice (duplication).
    pub fn dup_sends(inner: T, indices: &[u64]) -> Self {
        Self::new(inner, FaultControl::with_dup_indices(indices))
    }

    /// Convenience: wrap `inner`, reordering the sends at the given 0-based
    /// indices (each held and released after the following send).
    pub fn reorder_sends(inner: T, indices: &[u64]) -> Self {
        Self::new(inner, FaultControl::with_reorder_indices(indices))
    }
}

impl<T: SessionTransport> LossyTransport<T> {
    /// Flush any frame currently held back by a reorder (e.g. when the reordered
    /// frame was the last send and has no following frame to release it).
    pub async fn flush(&self) -> Result<(), CoreError> {
        if let Some(held) = self.control.take_pending_reorder() {
            self.inner.send_bytes(&held).await?;
        }
        Ok(())
    }
}

impl<T: SessionTransport> SessionTransport for LossyTransport<T> {
    async fn send_bytes(&self, data: &[u8]) -> Result<(), CoreError> {
        // Latency injection happens before any forwarding decision.
        if let Some(delay) = self.control.delay() {
            tokio::time::sleep(delay).await;
        }
        match self.control.classify() {
            SendFault::Drop => {
                // Simulate loss: tell the sender it succeeded, never forward the
                // bytes. A frame held for reorder is NOT released by a dropped
                // send (the dropped frame isn't "delivered"); it waits for the
                // next forwarded send or an explicit `flush`.
                Ok(())
            }
            SendFault::Reorder => {
                // Hold this frame; release any previously-held frame first so a
                // second reorder before the first is delivered doesn't lose it.
                if let Some(prev) = self.control.hold_for_reorder(data.to_vec()) {
                    self.inner.send_bytes(&prev).await?;
                }
                Ok(())
            }
            SendFault::Duplicate => {
                self.inner.send_bytes(data).await?;
                self.inner.send_bytes(data).await?;
                self.release_pending_reorder().await
            }
            SendFault::Forward => {
                self.inner.send_bytes(data).await?;
                self.release_pending_reorder().await
            }
        }
    }

    async fn recv_bytes(&self) -> Result<Bytes, CoreError> {
        self.inner.recv_bytes().await
    }
}

impl<T: SessionTransport> LossyTransport<T> {
    /// Release a frame held by a reorder *after* the current frame was
    /// forwarded, so the held frame lands later in the stream (the swap).
    async fn release_pending_reorder(&self) -> Result<(), CoreError> {
        if let Some(held) = self.control.take_pending_reorder() {
            self.inner.send_bytes(&held).await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Inner transport that records every frame actually forwarded to it.
    struct RecordingTransport {
        forwarded: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    impl SessionTransport for RecordingTransport {
        async fn send_bytes(&self, data: &[u8]) -> Result<(), CoreError> {
            self.forwarded.lock().expect("poisoned").push(data.to_vec());
            Ok(())
        }

        async fn recv_bytes(&self) -> Result<Bytes, CoreError> {
            Err(CoreError::NetworkError("recv unused in this test".into()))
        }
    }

    #[tokio::test]
    async fn lossy_transport_drops_configured_send_indices() {
        let forwarded = Arc::new(Mutex::new(Vec::new()));
        let inner = RecordingTransport {
            forwarded: forwarded.clone(),
        };
        // Drop the 2nd send (0-based index 1).
        let lossy = LossyTransport::drop_sends(inner, &[1]);

        lossy.send_bytes(b"f0").await.expect("send f0");
        lossy.send_bytes(b"f1").await.expect("send f1"); // dropped: never forwarded
        lossy.send_bytes(b"f2").await.expect("send f2");

        let got = forwarded.lock().expect("poisoned");
        assert_eq!(
            &*got,
            &[b"f0".to_vec(), b"f2".to_vec()],
            "frame at index 1 must be dropped, not forwarded to the inner transport"
        );
    }

    #[tokio::test]
    async fn arm_drop_next_drops_exactly_the_next_send() {
        let forwarded = Arc::new(Mutex::new(Vec::new()));
        let inner = RecordingTransport {
            forwarded: forwarded.clone(),
        };
        let control = FaultControl::new();
        let lossy = LossyTransport::new(inner, control.clone());

        control.arm_drop_next(1); // drop the very next send only
        lossy.send_bytes(b"d0").await.expect("send d0"); // dropped
        lossy.send_bytes(b"d1").await.expect("send d1");
        lossy.send_bytes(b"d2").await.expect("send d2");

        let got = forwarded.lock().expect("poisoned");
        assert_eq!(
            &*got,
            &[b"d1".to_vec(), b"d2".to_vec()],
            "an armed drop of 1 must skip exactly the next send, then forward the rest"
        );
    }

    #[tokio::test]
    async fn dup_sends_forwards_configured_indices_twice() {
        let forwarded = Arc::new(Mutex::new(Vec::new()));
        let inner = RecordingTransport {
            forwarded: forwarded.clone(),
        };
        // Duplicate the 2nd send (index 1).
        let lossy = LossyTransport::dup_sends(inner, &[1]);

        lossy.send_bytes(b"u0").await.expect("send u0");
        lossy.send_bytes(b"u1").await.expect("send u1"); // forwarded twice
        lossy.send_bytes(b"u2").await.expect("send u2");

        let got = forwarded.lock().expect("poisoned");
        assert_eq!(
            &*got,
            &[
                b"u0".to_vec(),
                b"u1".to_vec(),
                b"u1".to_vec(),
                b"u2".to_vec()
            ],
            "the duplicated frame must reach the inner transport twice, in place"
        );
    }

    #[tokio::test]
    async fn reorder_sends_swaps_with_the_following_frame() {
        let forwarded = Arc::new(Mutex::new(Vec::new()));
        let inner = RecordingTransport {
            forwarded: forwarded.clone(),
        };
        // Reorder the 2nd send (index 1): it is held and released after index 2.
        let lossy = LossyTransport::reorder_sends(inner, &[1]);

        lossy.send_bytes(b"r0").await.expect("send r0");
        lossy.send_bytes(b"r1").await.expect("send r1"); // held
        lossy.send_bytes(b"r2").await.expect("send r2"); // forwards r2, then r1

        let got = forwarded.lock().expect("poisoned");
        assert_eq!(
            &*got,
            &[b"r0".to_vec(), b"r2".to_vec(), b"r1".to_vec()],
            "the reordered frame must land after the following frame"
        );
    }

    #[tokio::test]
    async fn reorder_of_final_frame_is_released_by_flush() {
        let forwarded = Arc::new(Mutex::new(Vec::new()));
        let inner = RecordingTransport {
            forwarded: forwarded.clone(),
        };
        let lossy = LossyTransport::reorder_sends(inner, &[1]);

        lossy.send_bytes(b"r0").await.expect("send r0");
        lossy.send_bytes(b"r1").await.expect("send r1"); // held, last send

        // Without a following send the held frame is still pending.
        assert_eq!(&*forwarded.lock().expect("poisoned"), &[b"r0".to_vec()]);

        lossy.flush().await.expect("flush the held frame");
        assert_eq!(
            &*forwarded.lock().expect("poisoned"),
            &[b"r0".to_vec(), b"r1".to_vec()],
            "flush must release a reorder held past the final send"
        );
    }

    #[tokio::test]
    async fn delay_holds_each_send_for_at_least_the_configured_duration() {
        let forwarded = Arc::new(Mutex::new(Vec::new()));
        let inner = RecordingTransport {
            forwarded: forwarded.clone(),
        };
        let control = FaultControl::with_delay(Duration::from_millis(25));
        let lossy = LossyTransport::new(inner, control);

        let start = tokio::time::Instant::now();
        lossy.send_bytes(b"slow").await.expect("send slow");
        // `tokio::time::sleep` guarantees at least the requested duration.
        assert!(
            start.elapsed() >= Duration::from_millis(25),
            "delay must hold the send for at least the configured duration"
        );
        assert_eq!(&*forwarded.lock().expect("poisoned"), &[b"slow".to_vec()]);
    }
}
