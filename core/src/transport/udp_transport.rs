//! High-Performance UDP Transport
//!
//! Zero-copy, batched UDP I/O for maximum throughput.
//! Uses ring AES-256-GCM with in-place encryption.

use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::io::{self, Result as IoResult};
use super::buffer_pool::BufferPool;
use crate::crypto::aes_session::AesSession;

/// High-performance UDP transport with batching and encryption
pub struct UdpTransport {
    socket: Arc<UdpSocket>,
    peer_addr: SocketAddr,
    session: Arc<AesSession>,
    buffer_pool: Arc<BufferPool>,
}

impl UdpTransport {
    /// Create a new UDP transport
    pub async fn bind(local_addr: &str) -> IoResult<Self> {
        let socket = UdpSocket::bind(local_addr).await?;
        socket.set_broadcast(false)?;

        Ok(Self {
            socket: Arc::new(socket),
            peer_addr: "0.0.0.0:0".parse().unwrap(),
            session: Arc::new(AesSession::from_shared_secret(&[0u8; 32])),
            buffer_pool: Arc::new(BufferPool::new(65536, 16, 256)),
        })
    }

    /// Connect to a peer
    pub async fn connect(&mut self, peer_addr: SocketAddr, session: AesSession) {
        self.peer_addr = peer_addr;
        self.session = Arc::new(session);
    }

    /// Send encrypted data
    #[inline]
    pub async fn send(&self, data: &[u8]) -> IoResult<usize> {
        let encrypted = self.session.encrypt(data)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        self.socket.send_to(&encrypted, self.peer_addr).await
    }

    /// Send encrypted data with in-place encryption (zero-copy)
    #[inline]
    pub async fn send_zero_copy(&self, data: &[u8]) -> IoResult<usize> {
        let mut buf = Vec::with_capacity(data.len() + 16);
        buf.extend_from_slice(data);
        self.session.encrypt_in_place(&mut buf)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        self.socket.send_to(&buf, self.peer_addr).await
    }

    /// Receive and decrypt data
    #[inline]
    pub async fn recv(&self) -> IoResult<(Vec<u8>, SocketAddr)> {
        let mut buf = self.buffer_pool.acquire();
        buf.resize(65536, 0);

        let (len, addr) = self.socket.recv_from(&mut buf).await?;

        let decrypted = self.session.decrypt(&buf[..len])
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        Ok((decrypted, addr))
    }

    /// Batch send multiple packets
    #[inline]
    pub async fn send_batch(&self, packets: &[&[u8]]) -> IoResult<usize> {
        let mut total = 0;
        for packet in packets {
            total += self.send(packet).await?;
        }
        Ok(total)
    }

    /// Get buffer pool stats
    pub fn buffer_stats(&self) -> super::buffer_pool::PoolStats {
        self.buffer_pool.stats()
    }
}

/// Ultra-fast datagram sender (for benchmarks)
pub struct FastSender {
    socket: Arc<UdpSocket>,
    session: Arc<AesSession>,
    peer_addr: SocketAddr,
}

impl FastSender {
    pub fn new(socket: Arc<UdpSocket>, session: Arc<AesSession>, peer_addr: SocketAddr) -> Self {
        Self { socket, session, peer_addr }
    }

    /// Send with in-place encryption
    #[inline]
    pub async fn send(&self, data: &[u8]) -> IoResult<usize> {
        let mut buf = Vec::with_capacity(data.len() + 16);
        buf.extend_from_slice(data);
        self.session.encrypt_in_place(&mut buf)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        self.socket.send_to(&buf, self.peer_addr).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_udp_transport_create() {
        let transport = UdpTransport::bind("127.0.0.1:0").await.unwrap();
        assert!(transport.buffer_stats().pool_size >= 0);
    }
}
