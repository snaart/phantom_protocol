//! Length-prefixed `SessionTransport` over `tokio::net::TcpStream`.
//!
//! `SessionTransport` is message-oriented (returns one frame per `recv_bytes`),
//! while TCP is a stream. This adapter inserts a 4-byte big-endian length prefix
//! before each frame so the trait contract is preserved.

use crate::api::session::SessionTransport;
use crate::errors::CoreError;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

/// Hard upper bound on a single frame. Frames larger than this are rejected to
/// keep an attacker from making us allocate unbounded memory off a single u32.
const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024; // 16 MiB

pub struct TcpSessionTransport {
    write_half: Mutex<tokio::net::tcp::OwnedWriteHalf>,
    read_half: Mutex<tokio::net::tcp::OwnedReadHalf>,
}

impl TcpSessionTransport {
    pub fn new(stream: TcpStream) -> Self {
        let _ = stream.set_nodelay(true);
        let (r, w) = stream.into_split();
        Self {
            write_half: Mutex::new(w),
            read_half: Mutex::new(r),
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

    async fn recv_bytes(&self) -> Result<Vec<u8>, CoreError> {
        let mut r = self.read_half.lock().await;
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
        let mut buf = vec![0u8; len];
        r.read_exact(&mut buf)
            .await
            .map_err(|e| CoreError::NetworkError(e.to_string()))?;
        Ok(buf)
    }
}
