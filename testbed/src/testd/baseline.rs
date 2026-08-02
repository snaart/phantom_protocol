//! Raw TCP / UDP echo servers — the control group.
//!
//! No Phantom, no handshake, no crypto: just the path itself. Without this,
//! "PhantomUDP sustained X Mbit/s at Y ms" is uninterpretable, because the
//! link's own ceiling and jitter floor are unknown. Every protocol number in
//! the report is meant to be read as a ratio against these.
//!
//! The TCP baseline uses the same 4-byte big-endian length prefix as
//! `TcpSessionTransport`, so the framing cost is matched and the difference
//! measured is the protocol's, not the framing's.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

/// Matches the established-phase frame cap of `TcpSessionTransport`.
const MAX_FRAME: u32 = 4 * 1024 * 1024;

/// Request larger socket buffers; the kernel may clamp, and that is fine — the
/// point is not to be the bottleneck, not to hit an exact number.
fn size_socket_buffers(sock: &tokio::net::TcpStream, want: usize) {
    use std::os::fd::{AsRawFd, BorrowedFd};
    // SAFETY: the fd is owned by `sock` and outlives this borrow; socket2 only
    // sets options on it and never takes ownership.
    let borrowed = unsafe { BorrowedFd::borrow_raw(sock.as_raw_fd()) };
    let s2 = socket2::SockRef::from(&borrowed);
    let _ = s2.set_send_buffer_size(want);
    let _ = s2.set_recv_buffer_size(want);
}

#[derive(Default)]
pub struct BaselineStats {
    pub tcp_conns: AtomicU64,
    pub tcp_frames: AtomicU64,
    pub tcp_bytes: AtomicU64,
    pub udp_datagrams: AtomicU64,
    pub udp_bytes: AtomicU64,
}

/// Length-prefixed TCP echo.
pub async fn run_tcp(addr: String, stats: Arc<BaselineStats>) -> std::io::Result<()> {
    let listener = TcpListener::bind(&addr).await?;
    tracing::info!(addr = %addr, "raw TCP echo baseline listening");
    serve_tcp(listener, stats).await
}

/// Serve on an already-bound listener.
///
/// Split out from [`run_tcp`] so a caller that needs to know the port before
/// the server starts (a test on port 0) can bind once and hand the socket over,
/// rather than binding, closing, and racing to rebind the same port.
pub async fn serve_tcp(listener: TcpListener, stats: Arc<BaselineStats>) -> std::io::Result<()> {
    loop {
        let (mut sock, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "raw tcp accept failed");
                continue;
            }
        };
        // Nagle off: the baseline measures the path, and coalescing small
        // frames would flatter it relative to a protocol that paces explicitly.
        let _ = sock.set_nodelay(true);
        // Size the buffers for the bandwidth-delay product. A control that
        // leaves them at the OS default measures `default / rtt` and reports it
        // as the link — which is how this probe once produced a "path ceiling"
        // that was really the kernel's.
        size_socket_buffers(&sock, 1024 * 1024);
        stats.tcp_conns.fetch_add(1, Ordering::Relaxed);
        let stats = stats.clone();

        tokio::spawn(async move {
            let mut len_buf = [0u8; 4];
            loop {
                if sock.read_exact(&mut len_buf).await.is_err() {
                    break;
                }
                let len = u32::from_be_bytes(len_buf);
                if len > MAX_FRAME {
                    tracing::warn!(%peer, len, "raw tcp frame over cap; closing");
                    break;
                }
                let mut body = vec![0u8; len as usize];
                if sock.read_exact(&mut body).await.is_err() {
                    break;
                }
                if sock.write_all(&len_buf).await.is_err() || sock.write_all(&body).await.is_err() {
                    break;
                }
                stats.tcp_frames.fetch_add(1, Ordering::Relaxed);
                stats.tcp_bytes.fetch_add(len as u64, Ordering::Relaxed);
            }
        });
    }
}

/// Datagram echo. One socket, no per-peer state — the path is the only thing
/// under measurement.
pub async fn run_udp(addr: String, stats: Arc<BaselineStats>) -> std::io::Result<()> {
    let sock = UdpSocket::bind(&addr).await?;
    tracing::info!(addr = %addr, "raw UDP echo baseline listening");
    serve_udp(sock, stats).await
}

/// Serve on an already-bound socket. See [`serve_tcp`] for why this split exists.
pub async fn serve_udp(sock: UdpSocket, stats: Arc<BaselineStats>) -> std::io::Result<()> {
    // 64 KiB covers the largest datagram IPv4 permits; the path itself tops out
    // far lower (measured ~1392 B payload), which is one of the things the
    // client's size sweep is there to discover rather than assume.
    let mut buf = vec![0u8; 65_536];
    loop {
        let (n, peer) = match sock.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "raw udp recv failed");
                continue;
            }
        };
        if sock.send_to(&buf[..n], peer).await.is_ok() {
            stats.udp_datagrams.fetch_add(1, Ordering::Relaxed);
            stats.udp_bytes.fetch_add(n as u64, Ordering::Relaxed);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn tcp_baseline_echoes_framed_payloads_byte_for_byte() {
        let stats = Arc::new(BaselineStats::default());
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let s = stats.clone();
        tokio::spawn(async move {
            let _ = serve_tcp(listener, s).await;
        });

        let mut c = tokio::net::TcpStream::connect(addr).await.expect("connect");
        for len in [1usize, 64, 1500, 60_000] {
            let payload: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            c.write_all(&(len as u32).to_be_bytes()).await.expect("len");
            c.write_all(&payload).await.expect("body");

            let mut lb = [0u8; 4];
            c.read_exact(&mut lb).await.expect("read len");
            assert_eq!(u32::from_be_bytes(lb) as usize, len);
            let mut back = vec![0u8; len];
            c.read_exact(&mut back).await.expect("read body");
            assert_eq!(back, payload, "echo must be byte-exact at {len} bytes");
        }
        assert_eq!(stats.tcp_frames.load(Ordering::Relaxed), 4);
    }

    /// An oversized declared length must close the connection, not allocate.
    #[tokio::test]
    async fn tcp_baseline_rejects_an_oversized_frame() {
        let stats = Arc::new(BaselineStats::default());
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let _ = serve_tcp(listener, stats).await;
        });

        let mut c = tokio::net::TcpStream::connect(addr).await.expect("connect");
        c.write_all(&u32::MAX.to_be_bytes()).await.expect("len");
        let mut b = [0u8; 1];
        // The server closes rather than waiting for 4 GiB.
        let r = tokio::time::timeout(std::time::Duration::from_secs(3), c.read(&mut b)).await;
        assert!(
            matches!(r, Ok(Ok(0)) | Ok(Err(_))),
            "connection should be closed, got {r:?}"
        );
    }

    #[tokio::test]
    async fn udp_baseline_echoes_datagrams() {
        let stats = Arc::new(BaselineStats::default());
        let probe = UdpSocket::bind("127.0.0.1:0").await.expect("bind probe");
        let server = UdpSocket::bind("127.0.0.1:0").await.expect("bind server");
        let addr = server.local_addr().expect("addr");
        let s = stats.clone();
        tokio::spawn(async move {
            let _ = serve_udp(server, s).await;
        });

        for len in [1usize, 512, 1200] {
            let payload: Vec<u8> = (0..len).map(|i| (i % 253) as u8).collect();
            probe.send_to(&payload, addr).await.expect("send");
            let mut buf = vec![0u8; 65_536];
            let (n, _) =
                tokio::time::timeout(std::time::Duration::from_secs(3), probe.recv_from(&mut buf))
                    .await
                    .expect("no timeout")
                    .expect("recv");
            assert_eq!(&buf[..n], &payload[..], "datagram echo must be exact");
        }
        assert_eq!(stats.udp_datagrams.load(Ordering::Relaxed), 3);
    }
}
