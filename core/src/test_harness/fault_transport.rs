//! Fault-injecting [`SessionTransport`] wrapper for loss-recovery testing.
//!
//! Wraps any inner [`SessionTransport`] and injects faults on the send path.
//! Today it supports deterministic packet drops — either by fixed 0-based send
//! index, or "drop the next N sends from now" (armed at runtime). Delay,
//! reorder, and duplication are follow-on increments. This is the substrate the
//! reliable-delivery / loss-recovery tests need — without a transport that can
//! drop a frame, retransmission cannot be exercised at all.
//!
//! A dropped send still returns `Ok(())` to the caller (the sender believes the
//! bytes left the host); the frame is simply never handed to the inner
//! transport, exactly as a packet lost in the network would behave.
//!
//! Fault state lives behind a cloneable [`FaultControl`] handle so a test can
//! arm faults *after* the transport has been moved into a session's data pump
//! (e.g. drop the first data frame once the handshake has completed).

use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

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
    /// An empty control — drops nothing until armed.
    pub fn new() -> Self {
        Self {
            state: Arc::new(FaultState {
                send_index: AtomicU64::new(0),
                arm_drop: AtomicU64::new(0),
                drop_indices: HashSet::new(),
            }),
        }
    }

    /// A control that drops the sends at these fixed 0-based indices.
    pub fn with_drop_indices(indices: &[u64]) -> Self {
        Self {
            state: Arc::new(FaultState {
                send_index: AtomicU64::new(0),
                arm_drop: AtomicU64::new(0),
                drop_indices: indices.iter().copied().collect(),
            }),
        }
    }

    /// Drop the next `n` sends from now, regardless of index. Use right after a
    /// handshake completes to target the first data frame(s).
    pub fn arm_drop_next(&self, n: u64) {
        self.state.arm_drop.store(n, Ordering::Relaxed);
    }

    /// Decide whether the current send should be dropped, advancing the index.
    fn take_should_drop(&self) -> bool {
        let index = self.state.send_index.fetch_add(1, Ordering::Relaxed);
        if self.state.drop_indices.contains(&index) {
            return true;
        }
        // Consume one armed drop, if any are pending.
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
}

impl<T: SessionTransport> SessionTransport for LossyTransport<T> {
    async fn send_bytes(&self, data: &[u8]) -> Result<(), CoreError> {
        if self.control.take_should_drop() {
            // Simulate loss: tell the sender it succeeded, never forward the bytes.
            return Ok(());
        }
        self.inner.send_bytes(data).await
    }

    async fn recv_bytes(&self) -> Result<Bytes, CoreError> {
        self.inner.recv_bytes().await
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
}
