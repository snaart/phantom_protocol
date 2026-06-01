//! TCP Transport Leg
//!
//! Reliable fallback transport using raw TCP.

use crate::transport::legs::TransportLeg;

use async_trait::async_trait;
use bytes::{Buf, Bytes, BytesMut};
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU8, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

/// TCP transport leg
pub struct TcpLeg {
    /// TCP stream (wrapped in Mutex for shared access)
    stream: Mutex<Option<TcpStream>>,
    /// Remote address
    remote_addr: Option<SocketAddr>,
    /// Current RTT estimate (ms)
    rtt_ms: AtomicU32,
    /// Packet loss percentage (always 0 for TCP)
    #[allow(dead_code)]
    loss_percent: AtomicU8,
    /// Whether leg is available
    available: AtomicBool,
    /// Read buffer
    read_buf: Mutex<BytesMut>,
}

impl TcpLeg {
    /// Create a new unconnected TCP leg
    pub fn new() -> Self {
        Self {
            stream: Mutex::new(None),
            remote_addr: None,
            rtt_ms: AtomicU32::new(100), // Initial estimate
            loss_percent: AtomicU8::new(0),
            available: AtomicBool::new(false),
            read_buf: Mutex::new(BytesMut::with_capacity(16384)),
        }
    }

    /// Connect to remote address
    pub async fn connect(addr: SocketAddr) -> io::Result<Self> {
        let start = std::time::Instant::now();
        let stream = TcpStream::connect(addr).await?;
        let rtt = start.elapsed().as_millis() as u32;

        // Disable Nagle's algorithm for lower latency
        stream.set_nodelay(true)?;

        log::debug!("TCP connected to {} (RTT {}ms)", addr, rtt);

        Ok(Self {
            stream: Mutex::new(Some(stream)),
            remote_addr: Some(addr),
            rtt_ms: AtomicU32::new(rtt),
            loss_percent: AtomicU8::new(0),
            available: AtomicBool::new(true),
            read_buf: Mutex::new(BytesMut::with_capacity(16384)),
        })
    }

    /// Wrap an existing TCP stream
    pub fn from_stream(stream: TcpStream, addr: SocketAddr) -> Self {
        let _ = stream.set_nodelay(true);

        Self {
            stream: Mutex::new(Some(stream)),
            remote_addr: Some(addr),
            rtt_ms: AtomicU32::new(100),
            loss_percent: AtomicU8::new(0),
            available: AtomicBool::new(true),
            read_buf: Mutex::new(BytesMut::with_capacity(16384)),
        }
    }

    /// Update RTT sample
    pub fn update_rtt(&self, sample_ms: u32) {
        let current = self.rtt_ms.load(Ordering::Relaxed);
        let new_rtt = (7 * current + sample_ms) / 8;
        self.rtt_ms.store(new_rtt, Ordering::Relaxed);
    }

    /// Read a length-prefixed message
    async fn read_framed(&self) -> io::Result<Bytes> {
        let mut stream_guard = self.stream.lock().await;
        let stream = stream_guard
            .as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "Not connected"))?;

        let mut read_buf = self.read_buf.lock().await;

        // Read length prefix (4 bytes)
        while read_buf.len() < 4 {
            let mut temp = [0u8; 4096];
            let n = stream.read(&mut temp).await?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "Connection closed",
                ));
            }
            read_buf.extend_from_slice(&temp[..n]);
        }

        let length =
            u32::from_be_bytes([read_buf[0], read_buf[1], read_buf[2], read_buf[3]]) as usize;

        // Sanity check
        if length > 10 * 1024 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Message too large",
            ));
        }

        // Read full message
        while read_buf.len() < 4 + length {
            let mut temp = [0u8; 4096];
            let n = stream.read(&mut temp).await?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "Connection closed",
                ));
            }
            read_buf.extend_from_slice(&temp[..n]);
        }

        // Extract message
        read_buf.advance(4);
        let data = read_buf.split_to(length).freeze();

        Ok(data)
    }

    /// Write a length-prefixed message
    async fn write_framed(&self, data: &[u8]) -> io::Result<()> {
        let mut stream_guard = self.stream.lock().await;
        let stream = stream_guard
            .as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "Not connected"))?;

        let length = data.len() as u32;
        stream.write_all(&length.to_be_bytes()).await?;
        stream.write_all(data).await?;
        stream.flush().await?;

        Ok(())
    }
}

impl Default for TcpLeg {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl TransportLeg for TcpLeg {
    async fn send(&self, data: Bytes) -> io::Result<()> {
        if !self.is_available() {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "TCP not connected",
            ));
        }

        self.write_framed(&data).await
    }

    async fn recv(&self) -> io::Result<Bytes> {
        if !self.is_available() {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "TCP not connected",
            ));
        }

        self.read_framed().await
    }

    fn is_available(&self) -> bool {
        self.available.load(Ordering::Relaxed)
    }

    fn rtt_ms(&self) -> u32 {
        self.rtt_ms.load(Ordering::Relaxed)
    }

    fn loss_percent(&self) -> u8 {
        0 // TCP is reliable
    }

    fn remote_addr(&self) -> Option<SocketAddr> {
        self.remote_addr
    }

    async fn close(&self) -> io::Result<()> {
        self.available.store(false, Ordering::Relaxed);

        if let Some(stream) = self.stream.lock().await.take() {
            drop(stream); // Gracefully close
        }

        log::info!("TCP closed");
        Ok(())
    }
}

impl std::fmt::Debug for TcpLeg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TcpLeg")
            .field("remote", &self.remote_addr)
            .field("rtt_ms", &self.rtt_ms.load(Ordering::Relaxed))
            .field("available", &self.is_available())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_leg_creation() {
        let leg = TcpLeg::new();
        assert!(!leg.is_available());
        assert_eq!(leg.loss_percent(), 0);
    }
}
