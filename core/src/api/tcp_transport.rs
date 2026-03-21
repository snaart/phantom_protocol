//! Length-prefixed `SessionTransport` over `tokio::net::TcpStream`.
//!
//! `SessionTransport` is message-oriented (returns one frame per `recv_bytes`),
//! while TCP is a stream. This adapter inserts a 4-byte big-endian length prefix
//! before each frame so the trait contract is preserved.
//!
//! Phase 2.1: the receive path keeps a single persistent `BytesMut`
//! accumulator across `recv_bytes` calls. Each frame is `split_to`-ed off
//! into an owned `Bytes` which the caller takes — zero-copy from the
//! accumulator to the returned frame, no per-packet `Vec::new` alloc.

use crate::api::session::SessionTransport;
use crate::errors::CoreError;
use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

/// Hard upper bound on a single frame. Frames larger than this are rejected to
/// keep an attacker from making us allocate unbounded memory off a single u32.
const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024; // 16 MiB

/// Initial capacity for the persistent recv accumulator. Sized to a
/// generous MTU so the typical workload never reallocates after the
/// first frame.
const RECV_BUF_INITIAL_CAPACITY: usize = 64 * 1024;

pub struct TcpSessionTransport {
    write_half: Mutex<tokio::net::tcp::OwnedWriteHalf>,
    /// Read half + the per-direction accumulator. Held together under
    /// one mutex so the buffer lifetime tracks the reader's exactly
    /// (Phase 2.1).
    read_half: Mutex<(tokio::net::tcp::OwnedReadHalf, BytesMut)>,
}

impl TcpSessionTransport {
    pub fn new(stream: TcpStream) -> Self {
        let _ = stream.set_nodelay(true);
        let (r, w) = stream.into_split();
        Self {
            write_half: Mutex::new(w),
            read_half: Mutex::new((r, BytesMut::with_capacity(RECV_BUF_INITIAL_CAPACITY))),
        }
    }
}

#[async_trait::async_trait]
impl SessionTransport for TcpSessionTransport {
    async fn send_bytes(&self, data: &[u8]) -> Result<(), CoreError> {
        if data.len() > MAX_FRAME_BYTES {
            return Err(CoreError::NetworkError(format!(
                "frame too large: {} > {}",
                data.len(),
                MAX_FRAME_BYTES
            )));
        }
        let mut w = self.write_half.lock().await;
        let len = (data.len() as u32).to_be_bytes();
        w.write_all(&len)
            .await
            .map_err(|e| CoreError::NetworkError(e.to_string()))?;
        w.write_all(data)
            .await
            .map_err(|e| CoreError::NetworkError(e.to_string()))?;
        w.flush()
            .await
            .map_err(|e| CoreError::NetworkError(e.to_string()))?;
        Ok(())
    }

    async fn recv_bytes(&self) -> Result<Bytes, CoreError> {
        let mut guard = self.read_half.lock().await;
        let (r, buf) = &mut *guard;

        // Read the 4-byte big-endian length prefix.
        let mut len_buf = [0u8; 4];
        r.read_exact(&mut len_buf)
            .await
            .map_err(|e| CoreError::NetworkError(e.to_string()))?;
        let len = u32::from_be_bytes(len_buf) as usize;
        if len > MAX_FRAME_BYTES {
            return Err(CoreError::NetworkError(format!(
                "oversized frame from peer: {} > {}",
                len, MAX_FRAME_BYTES
            )));
        }

        // Grow the accumulator just enough to hold this frame; the
        // `reserve` is a no-op if capacity already suffices, which is
        // the steady-state case (we never shrink). `resize` extends
        // logical length so `read_exact` has a valid destination slice.
        buf.clear();
        buf.reserve(len);
        // SAFETY-equivalent: `resize` writes zeros into the new bytes
        // before `read_exact` overwrites them. Functionally same as
        // `vec![0u8; len]` but without the allocator round-trip.
        buf.resize(len, 0);
        r.read_exact(&mut buf[..])
            .await
            .map_err(|e| CoreError::NetworkError(e.to_string()))?;

        // `split_to(len)` is O(1) for BytesMut: it hands the caller an
        // owned `BytesMut` view over the first `len` bytes, retaining
        // the rest in the accumulator. `freeze` turns it into a `Bytes`
        // (immutable, refcounted). Caller's clone() is cheap thereafter.
        let frame = buf.split_to(len).freeze();
        Ok(frame)
    }
}
