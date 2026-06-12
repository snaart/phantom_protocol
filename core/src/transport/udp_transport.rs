//! High-Performance UDP Transport
//!
//! Zero-copy, batched UDP I/O for maximum throughput.
//! Uses ring AES-256-GCM with in-place encryption.
//!
//! ## Paced Sending
//!
//! `PacedSender` wraps `UdpTransport` + `Pacer` to enforce a rate limit
//! set by the `BandwidthEstimator`. Prevents burst-induced congestion.
//! On Linux, `set_pacing_rate` can additionally offload pacing to the kernel
//! via `SO_MAX_PACING_RATE` (with the `fq` qdisc).

// This module opts back in to `unsafe` (denied at the crate root in lib.rs).
// The single remaining `unsafe` block is the `libc::setsockopt` call in
// `set_pacing_rate` (Linux `SO_MAX_PACING_RATE`). The previous dead
// `sendmmsg(2)` GSO-batch path — the only user of `libc::sendmmsg` /
// `libc::mmsghdr` / `MaybeUninit::zeroed` — was removed in the unsafe
// hygiene pass (it had no callers; UNSAFE-2). Every block must carry a
// `// SAFETY:` comment.
#![allow(unsafe_code)]

use super::buffer_pool::BufferPool;
use super::pacer::Pacer;
use crate::crypto::aes_session::AesSession;
use crate::transport::bandwidth_estimator;
use crate::transport::handshake::{ClientHello, HandshakeResponse, HandshakeServer, ServerReply};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{self, Result as IoResult};
use tokio::net::UdpSocket;

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

        let peer_addr = "0.0.0.0:0"
            .parse()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

        let session = AesSession::from_shared_secret(&[0u8; 32]).map_err(io::Error::other)?;

        Ok(Self {
            socket: Arc::new(socket),
            peer_addr,
            session: Arc::new(session),
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
        let encrypted = self.session.encrypt(&[], data).map_err(io::Error::other)?;
        self.socket.send_to(&encrypted, self.peer_addr).await
    }

    /// Send encrypted data with in-place encryption (zero-copy)
    #[inline]
    pub async fn send_zero_copy(&self, data: &[u8]) -> IoResult<usize> {
        let mut buf = Vec::with_capacity(data.len() + 16);
        buf.extend_from_slice(data);
        self.session
            .encrypt_in_place(&[], &mut buf)
            .map_err(io::Error::other)?;
        self.socket.send_to(&buf, self.peer_addr).await
    }

    /// Receive and decrypt data
    #[inline]
    pub async fn recv(&self) -> IoResult<(Vec<u8>, SocketAddr)> {
        let mut buf = self.buffer_pool.acquire();
        buf.resize(65536, 0);

        let (len, addr) = self.socket.recv_from(&mut buf).await?;

        let decrypted = self
            .session
            .decrypt(&[], &buf[..len])
            .map_err(io::Error::other)?;

        Ok((decrypted, addr))
    }

    /// Batch send multiple packets (simple loop fallback).
    #[inline]
    pub async fn send_batch(&self, packets: &[&[u8]]) -> IoResult<usize> {
        let mut total = 0;
        for packet in packets {
            total += self.send(packet).await?;
        }
        Ok(total)
    }

    /// Get a reference to the underlying socket (for raw operations).
    pub fn socket(&self) -> &Arc<UdpSocket> {
        &self.socket
    }

    /// Set the kernel-level pacing rate for this UDP socket (Linux only).
    ///
    /// Uses `SO_MAX_PACING_RATE` via `setsockopt(2)`. When the kernel's
    /// `net.core.default_qdisc` is `fq` (Fair Queuing), the kernel will
    /// enforce the pacing rate without any per-packet user-space timer,
    /// eliminating microbursts caused by tokio sleep granularity (~1 ms).
    ///
    /// On non-Linux platforms this is a no-op and always returns `Ok`.
    ///
    /// # Arguments
    /// * `rate_bps` — desired pacing rate in **bytes per second**
    pub fn set_pacing_rate(&self, rate_bps: u64) -> IoResult<()> {
        // Pacing offload (`SO_MAX_PACING_RATE`) is Linux-only; the rate is
        // unused on other platforms.
        #[cfg(not(target_os = "linux"))]
        let _ = rate_bps;
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::io::AsRawFd;
            // SO_MAX_PACING_RATE takes a u32 on older kernels (Linux 3.13+)
            // and a u64 on 4.20+. We use u32 for maximum compatibility.
            let rate_u32 = rate_bps.min(u32::MAX as u64) as u32;
            let fd = self.socket.as_ref().as_raw_fd();
            // SAFETY: fd is valid, &rate_u32 is a valid u32 pointer,
            // size_of::<u32>() is correct. SO_MAX_PACING_RATE = 47.
            let ret = unsafe {
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    47, // SO_MAX_PACING_RATE
                    &rate_u32 as *const u32 as *const libc::c_void,
                    std::mem::size_of::<u32>() as libc::socklen_t,
                )
            };
            if ret != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }

    /// Get buffer pool stats
    pub fn buffer_stats(&self) -> super::buffer_pool::PoolStats {
        self.buffer_pool.stats()
    }
}

/// Raw UDP listener for handling new handshakes (Phase 3: Paranoia Funnel)
pub struct UdpHandshakeListener {
    socket: Arc<UdpSocket>,
    buffer_pool: Arc<BufferPool>,
}

impl UdpHandshakeListener {
    pub async fn bind(local_addr: &str) -> IoResult<Self> {
        let socket = UdpSocket::bind(local_addr).await?;
        socket.set_broadcast(false)?;

        Ok(Self {
            socket: Arc::new(socket),
            buffer_pool: Arc::new(BufferPool::new(65536, 16, 256)),
        })
    }

    /// Read raw packets from socket, dropping small ones instantly (anti-amplification)
    pub async fn accept_handshake(&self, server: &HandshakeServer, difficulty: u8) -> IoResult<()> {
        let mut buf = self.buffer_pool.acquire();
        buf.resize(65536, 0);

        loop {
            let (len, addr) = self.socket.recv_from(&mut buf).await?;

            // 1. Padding Check / Anti-amplification
            // Any ClientHello packet smaller than 1200 bytes is dropped instantly without generating errors.
            if len < 1200 {
                continue;
            }

            // Decode the ClientHello. An unknown / future layout surfaces as
            // a borsh parse error and is dropped silently. The unified server
            // path handles cookie/PoW, resume, and best-effort 0-RTT
            // early-data; this is a demonstration listener that simply replies.
            let client_hello = match borsh::from_slice::<ClientHello>(&buf[..len]) {
                Ok(ch) => ch,
                Err(_) => {
                    // Not a valid ClientHello, drop silently
                    continue;
                }
            };

            // Process ClientHello
            match server.process_client_hello(&client_hello, difficulty, addr.ip()) {
                HandshakeResponse::Retry(retry_req) => {
                    // Server demands PoW or Cookie, send Retry (stateless) and forget.
                    // T4.4: frame with the ServerReply discriminant the client dispatches on.
                    if let Ok(encoded) = ServerReply::Retry(retry_req).to_wire() {
                        let _ = self.socket.send_to(&encoded, addr).await;
                    }
                }
                HandshakeResponse::Success(server_hello, _session, _early_data) => {
                    // Handshake Success, send the discriminant-framed ServerHello.
                    if let Ok(encoded) = ServerReply::Hello(server_hello).to_wire() {
                        let _ = self.socket.send_to(&encoded, addr).await;
                    }
                    // Transition connection to established state...
                }
                HandshakeResponse::Reject(reject) => {
                    // Unsupported version (H9): send the typed reject so the
                    // client gets an actionable signal, then forget.
                    if let Ok(encoded) = ServerReply::Reject(reject).to_wire() {
                        let _ = self.socket.send_to(&encoded, addr).await;
                    }
                }
                HandshakeResponse::Fail(_) => {
                    // Handshake error, drop silently
                }
            }

            // For now, this is a demonstration of the listener loop
            break;
        }

        Ok(())
    }
}

// ─── Paced Sender ───────────────────────────────────────────────────────────

/// Rate-limited UDP sender — integrates `Pacer` + `UdpTransport`.
///
/// Call `try_send()` instead of `UdpTransport::send()`. If the pacer
/// has no tokens, the send is delayed via `tokio::time::sleep`.
pub struct PacedSender {
    transport: Arc<UdpTransport>,
    pacer: Arc<Pacer>,
    estimator: Arc<parking_lot::Mutex<bandwidth_estimator::BandwidthEstimator>>,
}

impl PacedSender {
    /// Create a new paced sender.
    pub fn new(
        transport: Arc<UdpTransport>,
        pacer: Arc<Pacer>,
        estimator: Arc<parking_lot::Mutex<bandwidth_estimator::BandwidthEstimator>>,
    ) -> Self {
        Self {
            transport,
            pacer,
            estimator,
        }
    }

    /// Send data respecting the pacing rate.
    /// If tokens aren't available, yields to tokio until they are.
    pub async fn send(&self, data: &[u8]) -> IoResult<usize> {
        let bytes = data.len() as u64;

        // Wait for pacing tokens
        loop {
            if self.pacer.try_consume(bytes) {
                break;
            }
            let wait = self.pacer.time_until_available(bytes);
            if wait.is_zero() {
                break;
            }
            tokio::time::sleep(wait).await;
        }

        // Notify estimator of outgoing data
        self.estimator.lock().on_send(bytes);

        self.transport.send(data).await
    }

    /// Send without pacing (bypass for control packets).
    pub async fn send_unpaced(&self, data: &[u8]) -> IoResult<usize> {
        self.transport.send(data).await
    }

    /// Process an ACK and update everything.
    pub fn on_ack(&self, sample: bandwidth_estimator::DeliverySample) {
        let mut est = self.estimator.lock();
        est.on_ack(sample);
        let new_rate = est.pacing_rate();
        self.pacer.set_rate(new_rate);
    }

    /// Update the pacing rate (explicit override).
    pub fn set_rate(&self, rate_bps: u64) {
        self.pacer.set_rate(rate_bps);
    }

    /// Get current pacing rate.
    pub fn rate(&self) -> u64 {
        self.pacer.rate()
    }
}

impl std::fmt::Debug for PacedSender {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PacedSender")
            .field("rate_bps", &self.pacer.rate())
            .field("pacer_enabled", &self.pacer.is_enabled())
            .finish()
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
        Self {
            socket,
            session,
            peer_addr,
        }
    }

    /// Send with in-place encryption
    #[inline]
    pub async fn send(&self, data: &[u8]) -> IoResult<usize> {
        let mut buf = Vec::with_capacity(data.len() + 16);
        buf.extend_from_slice(data);
        self.session
            .encrypt_in_place(&[], &mut buf)
            .map_err(io::Error::other)?;
        self.socket.send_to(&buf, self.peer_addr).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_udp_transport_create() {
        let transport = UdpTransport::bind("127.0.0.1:0").await.unwrap();
        assert_eq!(transport.buffer_stats().pool_size, 16);
    }

    #[tokio::test]
    async fn test_paced_sender_creation() {
        let transport = Arc::new(UdpTransport::bind("127.0.0.1:0").await.unwrap());
        let pacer = Arc::new(Pacer::new(1_000_000)); // 1 MB/s
        let estimator = Arc::new(parking_lot::Mutex::new(
            bandwidth_estimator::BandwidthEstimator::new(),
        ));
        let sender = PacedSender::new(transport, pacer, estimator);

        assert_eq!(sender.rate(), 1_000_000);
        sender.set_rate(2_000_000);
        assert_eq!(sender.rate(), 2_000_000);
    }
}
