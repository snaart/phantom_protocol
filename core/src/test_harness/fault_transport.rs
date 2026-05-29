//! Fault-injecting [`SessionTransport`] wrapper for loss-recovery testing.
//!
//! Wraps any inner [`SessionTransport`] and injects faults on the send path.
//! Today it supports deterministic packet drops by 0-based send index; delay,
//! reorder, and duplication are follow-on increments. This is the substrate the
//! reliable-delivery / loss-recovery tests need — without a transport that can
//! drop a frame, retransmission cannot be exercised at all.
//!
//! A dropped send still returns `Ok(())` to the caller (the sender believes the
//! bytes left the host); the frame is simply never handed to the inner
//! transport, exactly as a packet lost in the network would behave.

use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};

use bytes::Bytes;

use crate::errors::CoreError;
use crate::transport::session_transport::SessionTransport;

/// Declares which frames a [`LossyTransport`] drops, by 0-based send index.
#[derive(Debug, Default, Clone)]
pub struct FaultPolicy {
    drop_indices: HashSet<u64>,
}

impl FaultPolicy {
    /// An empty policy — drops nothing.
    pub fn new() -> Self {
        Self::default()
    }

    /// Drop the sends at these 0-based indices (simulating packet loss).
    pub fn drop_sends(mut self, indices: &[u64]) -> Self {
        self.drop_indices.extend(indices.iter().copied());
        self
    }

    /// Whether the send at `index` should be dropped.
    fn should_drop(&self, index: u64) -> bool {
        self.drop_indices.contains(&index)
    }
}

/// A [`SessionTransport`] that injects faults around an inner transport.
pub struct LossyTransport<T> {
    inner: T,
    policy: FaultPolicy,
    send_index: AtomicU64,
}

impl<T> LossyTransport<T> {
    /// Wrap `inner` with an explicit [`FaultPolicy`].
    pub fn new(inner: T, policy: FaultPolicy) -> Self {
        Self {
            inner,
            policy,
            send_index: AtomicU64::new(0),
        }
    }

    /// Convenience: wrap `inner`, dropping the sends at the given 0-based indices.
    pub fn drop_sends(inner: T, indices: &[u64]) -> Self {
        Self::new(inner, FaultPolicy::new().drop_sends(indices))
    }
}

impl<T: SessionTransport> SessionTransport for LossyTransport<T> {
    async fn send_bytes(&self, data: &[u8]) -> Result<(), CoreError> {
        let index = self.send_index.fetch_add(1, Ordering::Relaxed);
        if self.policy.should_drop(index) {
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
    use std::sync::{Arc, Mutex};

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
}
