//! High-Performance UDP Transport
//!
//! Zero-copy, batched UDP I/O for maximum throughput.
//! Uses ring AES-256-GCM with in-place encryption.
//!
//! ## GSO (Generic Segmentation Offload)
//!
//! On Linux, `send_batch_gso` uses `sendmmsg(2)` to hand the kernel multiple
//! datagrams in a single syscall, dramatically reducing per-packet overhead.
//! On other platforms, a userspace fallback iterates.
//!
//! ## Paced Sending
//!
//! `PacedSender` wraps `UdpTransport` + `Pacer` to enforce a rate limit
//! set by the `BandwidthEstimator`. Prevents burst-induced congestion.

// This module opts back in to `unsafe` (denied at the crate root in lib.rs).
// The `unsafe` blocks here are required to call `libc::sendmmsg` /
// `libc::recvmmsg` and to allocate `libc::mmsghdr` via `MaybeUninit::zeroed`.
// Every block must carry a `// SAFETY:` comment.
#![allow(unsafe_code)]

use super::buffer_pool::BufferPool;
use super::pacer::Pacer;
use crate::crypto::aes_session::AesSession;
use crate::transport::bandwidth_estimator;
use crate::transport::handshake::{
    ClientHelloEnvelope, HandshakeResponse, HandshakeServer, HelloRetryRequestEnvelope,
    ServerHelloEnvelope,
};
use borsh::BorshDeserialize;
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

        let session = AesSession::from_shared_secret(&[0u8; 32])
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

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
        let encrypted = self
            .session
            .encrypt(&[], data)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        self.socket.send_to(&encrypted, self.peer_addr).await
    }

    /// Send encrypted data with in-place encryption (zero-copy)
    #[inline]
    pub async fn send_zero_copy(&self, data: &[u8]) -> IoResult<usize> {
        let mut buf = Vec::with_capacity(data.len() + 16);
        buf.extend_from_slice(data);
        self.session
            .encrypt_in_place(&[], &mut buf)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
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
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

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

    /// GSO-accelerated batch send.
    ///
    /// On **Linux**: encrypts all packets, then uses `sendmmsg(2)` to deliver
    /// them to the kernel in a single syscall (up to 64 datagrams at once).
    ///
    /// On **other platforms**: falls back to sequential sends.
    pub async fn send_batch_gso(&self, packets: &[&[u8]]) -> IoResult<GsoBatchResult> {
        // Encrypt all packets first
        let mut encrypted: Vec<Vec<u8>> = Vec::with_capacity(packets.len());
        for pkt in packets {
            let ct = self
                .session
                .encrypt(&[], pkt)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
            encrypted.push(ct);
        }

        let sent = platform_send_batch(&self.socket, &self.peer_addr, &encrypted).await?;

        Ok(GsoBatchResult {
            packets_sent: sent,
            packets_total: packets.len(),
            used_gso: cfg!(target_os = "linux"),
        })
    }

    /// Get a reference to the underlying socket (for GSO/raw operations).
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
    pub fn set_pacing_rate(&self, _rate_bps: u64) -> IoResult<()> {
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

            // Attempt to decode the ClientHello envelope (wire V3:
            // version-prefixed). This UDP listener is a V1/V2-only demo
            // path — a `V3` ClientHello is not decodable here and is
            // dropped just like any other malformed input. The TCP
            // `PhantomListener` is the V3-capable handshake path.
            let client_hello = match ClientHelloEnvelope::try_from_slice(&buf[..len]) {
                Ok(ClientHelloEnvelope::V12(ch)) => ch,
                Err(_) => {
                    // Not a valid V12 ClientHello envelope, drop silently
                    continue;
                }
            };

            // Process ClientHello
            match server.process_client_hello(&client_hello, difficulty, addr.ip()) {
                HandshakeResponse::Retry(retry_req) => {
                    // Server demands PoW or Cookie, send Retry (stateless) and forget
                    if let Ok(encoded) = borsh::to_vec(&HelloRetryRequestEnvelope::V12(retry_req)) {
                        let _ = self.socket.send_to(&encoded, addr).await;
                    }
                }
                HandshakeResponse::Success(server_hello, _session) => {
                    // Handshake Success, send ServerHello
                    if let Ok(encoded) = borsh::to_vec(&ServerHelloEnvelope::V12(server_hello)) {
                        let _ = self.socket.send_to(&encoded, addr).await;
                    }
                    // Transition connection to established state...
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

/// Result of a GSO batch send
#[derive(Debug, Clone, Copy)]
pub struct GsoBatchResult {
    /// Number of packets successfully sent
    pub packets_sent: usize,
    /// Total number of packets attempted
    pub packets_total: usize,
    /// Whether the kernel GSO path was used
    pub used_gso: bool,
}

impl GsoBatchResult {
    /// Whether all packets were sent
    pub fn all_sent(&self) -> bool {
        self.packets_sent == self.packets_total
    }
}

// ─── Platform-specific batch send ───────────────────────────────────────────

/// Linux: use sendmmsg for true kernel-level batching
#[cfg(target_os = "linux")]
async fn platform_send_batch(
    socket: &Arc<UdpSocket>,
    peer_addr: &SocketAddr,
    datagrams: &[Vec<u8>],
) -> IoResult<usize> {
    use std::os::unix::io::AsRawFd;

    // sendmmsg is a blocking syscall — run in spawn_blocking to avoid
    // blocking the tokio runtime
    let fd = socket.as_ref().as_raw_fd();
    let addr: std::net::SocketAddrV4 = match peer_addr {
        SocketAddr::V4(v4) => *v4,
        SocketAddr::V6(_) => {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "GSO sendmmsg only supports IPv4 in this implementation",
            ));
        }
    };

    // Clone datagrams for the blocking closure
    let owned: Vec<Vec<u8>> = datagrams.to_vec();

    let sent = tokio::task::spawn_blocking(move || sendmmsg_batch(fd, &addr, &owned))
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))??;

    Ok(sent)
}

/// Linux sendmmsg implementation
#[cfg(target_os = "linux")]
fn sendmmsg_batch(
    fd: i32,
    addr: &std::net::SocketAddrV4,
    datagrams: &[Vec<u8>],
) -> IoResult<usize> {
    use std::mem::MaybeUninit;

    let max_batch = datagrams.len().min(64); // sendmmsg limit per call

    // Build sockaddr_in
    let sin = libc::sockaddr_in {
        sin_family: libc::AF_INET as u16,
        sin_port: addr.port().to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(addr.ip().octets()),
        },
        sin_zero: [0; 8],
    };

    // Build iov + mmsghdr arrays
    let mut iovs: Vec<libc::iovec> = datagrams[..max_batch]
        .iter()
        .map(|d| libc::iovec {
            iov_base: d.as_ptr() as *mut _,
            iov_len: d.len(),
        })
        .collect();

    let mut msgs: Vec<libc::mmsghdr> = iovs
        .iter_mut()
        .map(|iov| {
            // SAFETY: `libc::mmsghdr` is `#[repr(C)]` with primitive integer
            // and raw-pointer fields. The all-zero bit pattern is a valid
            // (though uninitialized-by-protocol) instance: every field is
            // populated below before the struct is read by the kernel.
            let mut hdr: libc::mmsghdr = unsafe { MaybeUninit::zeroed().assume_init() };
            hdr.msg_hdr.msg_name = &sin as *const _ as *mut _;
            hdr.msg_hdr.msg_namelen = std::mem::size_of::<libc::sockaddr_in>() as u32;
            hdr.msg_hdr.msg_iov = iov as *mut _;
            hdr.msg_hdr.msg_iovlen = 1;
            hdr
        })
        .collect();

    // SAFETY: `fd` is owned by `self.socket` and remains valid for the duration
    // of this call. `msgs` is a `Vec<libc::mmsghdr>` of `msgs.len()` initialized
    // entries (populated above) — `as_mut_ptr()` is valid for that range. The
    // kernel reads through each `msg_hdr.msg_iov` which points to the `iov_base`
    // of a `datagrams[i]` byte slice, also alive for the duration of this call.
    let ret = unsafe { libc::sendmmsg(fd, msgs.as_mut_ptr(), msgs.len() as u32, 0) };

    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret as usize)
    }
}

/// Non-Linux: sequential fallback
#[cfg(not(target_os = "linux"))]
async fn platform_send_batch(
    socket: &Arc<UdpSocket>,
    peer_addr: &SocketAddr,
    datagrams: &[Vec<u8>],
) -> IoResult<usize> {
    let mut sent = 0;
    for dgram in datagrams {
        socket.send_to(dgram, peer_addr).await?;
        sent += 1;
    }
    Ok(sent)
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
        assert_eq!(transport.buffer_stats().pool_size, 16);
    }

    #[tokio::test]
    async fn test_gso_batch_result() {
        let result = GsoBatchResult {
            packets_sent: 10,
            packets_total: 10,
            used_gso: false,
        };
        assert!(result.all_sent());

        let partial = GsoBatchResult {
            packets_sent: 5,
            packets_total: 10,
            used_gso: false,
        };
        assert!(!partial.all_sent());
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
