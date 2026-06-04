//! KCP Transport Leg
//!
//! Primary transport using KCP over UDP via kcp-tokio.
//! Provides reliable delivery with 30-40% lower latency than TCP.

use crate::transport::legs::TransportLeg;

use async_trait::async_trait;
use bytes::Bytes;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU8, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;

use crate::transport::bandwidth_estimator;
use kcp_tokio::{async_kcp::KcpStream, KcpConfig};

/// KCP leg configuration
#[derive(Debug, Clone)]
pub struct KcpLegConfig {
    /// Maximum Transmission Unit
    pub mtu: u32,
    /// Send window size
    pub snd_wnd: u32,
    /// Receive window size  
    pub rcv_wnd: u32,
    /// Performance mode
    pub mode: KcpMode,
}

/// KCP performance mode
#[derive(Debug, Clone, Copy, Default)]
pub enum KcpMode {
    /// Normal mode - balanced
    #[default]
    Normal,
    /// Fast mode - lower latency
    Fast,
    /// Turbo mode - aggressive retransmission
    Turbo,
}

impl KcpMode {
    /// Apply mode to KcpConfig
    pub fn apply(&self, config: KcpConfig) -> KcpConfig {
        match self {
            KcpMode::Normal => config,
            KcpMode::Fast => config.fast_mode(),
            KcpMode::Turbo => config.turbo_mode(),
        }
    }
}

impl Default for KcpLegConfig {
    fn default() -> Self {
        Self {
            mtu: 1400,
            snd_wnd: 256,
            rcv_wnd: 256,
            mode: KcpMode::Fast,
        }
    }
}

/// KCP transport leg with kcp-tokio integration
pub struct KcpLeg {
    /// Configuration
    config: KcpLegConfig,
    /// KCP stream (wrapped in Mutex for shared access)
    stream: Mutex<Option<KcpStream>>,
    /// Remote address
    remote_addr: Option<SocketAddr>,
    /// Current RTT estimate (ms)
    rtt_ms: AtomicU32,
    /// Packet loss percentage
    loss_percent: AtomicU8,
    /// Whether leg is available
    available: AtomicBool,
    /// Bytes sent counter
    bytes_sent: AtomicU32,
    /// Bytes received counter
    bytes_received: AtomicU32,
    /// Bandwidth estimator
    estimator: Option<Arc<parking_lot::Mutex<bandwidth_estimator::BandwidthEstimator>>>,
}

impl KcpLeg {
    /// Create a new KCP leg with default config
    pub fn new() -> Self {
        Self::with_config(KcpLegConfig::default())
    }

    /// Create a new KCP leg with custom config
    pub fn with_config(config: KcpLegConfig) -> Self {
        Self {
            config,
            stream: Mutex::new(None),
            remote_addr: None,
            rtt_ms: AtomicU32::new(50), // Initial estimate
            loss_percent: AtomicU8::new(0),
            available: AtomicBool::new(false),
            bytes_sent: AtomicU32::new(0),
            bytes_received: AtomicU32::new(0),
            estimator: None,
        }
    }

    /// Connect to remote address
    pub async fn connect(addr: SocketAddr, config: KcpLegConfig) -> io::Result<Self> {
        let start = std::time::Instant::now();

        // Create KCP config
        let mut kcp_config = KcpConfig::new();
        kcp_config = config.mode.apply(kcp_config);

        // Connect via KCP
        let stream = KcpStream::connect(addr, kcp_config)
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::ConnectionRefused, e.to_string()))?;

        let rtt = start.elapsed().as_millis() as u32;

        log::debug!(
            "KCP connected to {} (RTT {}ms, mode {:?})",
            addr,
            rtt,
            config.mode
        );

        Ok(Self {
            config,
            stream: Mutex::new(Some(stream)),
            remote_addr: Some(addr),
            rtt_ms: AtomicU32::new(rtt),
            loss_percent: AtomicU8::new(0),
            available: AtomicBool::new(true),
            bytes_sent: AtomicU32::new(0),
            bytes_received: AtomicU32::new(0),
            estimator: None, // Will be set after creation if multi-path is active
        })
    }

    /// Wrap an existing KCP stream
    pub fn from_stream(stream: KcpStream, addr: SocketAddr, config: KcpLegConfig) -> Self {
        Self {
            config,
            stream: Mutex::new(Some(stream)),
            remote_addr: Some(addr),
            rtt_ms: AtomicU32::new(50),
            loss_percent: AtomicU8::new(0),
            available: AtomicBool::new(true),
            bytes_sent: AtomicU32::new(0),
            bytes_received: AtomicU32::new(0),
            estimator: None,
        }
    }

    /// Update RTT sample
    pub fn update_rtt(&self, sample_ms: u32) {
        // Simple EMA (exponential moving average)
        let current = self.rtt_ms.load(Ordering::Relaxed);
        let new_rtt = (7 * current + sample_ms) / 8;
        self.rtt_ms.store(new_rtt, Ordering::Relaxed);
    }

    /// Update loss percentage
    pub fn update_loss(&self, percent: u8) {
        self.loss_percent.store(percent.min(100), Ordering::Relaxed);
    }

    /// Get bytes sent
    pub fn bytes_sent(&self) -> u32 {
        self.bytes_sent.load(Ordering::Relaxed)
    }

    /// Get bytes received
    pub fn bytes_received(&self) -> u32 {
        self.bytes_received.load(Ordering::Relaxed)
    }

    /// Set the bandwidth estimator for this leg
    pub fn set_estimator(
        &mut self,
        estimator: Arc<parking_lot::Mutex<bandwidth_estimator::BandwidthEstimator>>,
    ) {
        self.estimator = Some(estimator);
    }
}

impl Default for KcpLeg {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl TransportLeg for KcpLeg {
    async fn send(&self, data: Bytes) -> io::Result<()> {
        if !self.is_available() {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "KCP not connected",
            ));
        }

        let mut stream_guard = self.stream.lock().await;
        let stream = stream_guard
            .as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "No stream"))?;

        let start = std::time::Instant::now();

        // Write length prefix (4 bytes) + data
        let len = data.len() as u32;
        stream.write_all(&len.to_be_bytes()).await?;
        stream.write_all(&data).await?;
        stream.flush().await?;

        // Notify estimator
        if let Some(ref est) = self.estimator {
            est.lock().on_send(data.len() as u64 + 4);
        }

        // Update RTT estimate
        let elapsed = start.elapsed().as_millis() as u32;
        self.update_rtt(elapsed);

        // Update bytes counter
        self.bytes_sent
            .fetch_add(data.len() as u32 + 4, Ordering::Relaxed);

        log::trace!("KCP send {} bytes", data.len());
        Ok(())
    }

    async fn recv(&self) -> io::Result<Bytes> {
        if !self.is_available() {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "KCP not connected",
            ));
        }

        let mut stream_guard = self.stream.lock().await;
        let stream = stream_guard
            .as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "No stream"))?;

        // LEGS-002: frame cap (4 MiB, down from 10), incremental read (no
        // pre-commit of the declared length), and an overall read timeout so a
        // peer that declares a frame then stalls cannot pin the leg. The timeout
        // is terminal for the leg (a partial read leaves the reliable stream
        // desynced) — the data pump tears down on the error.
        const KCP_MAX_FRAME_BYTES: usize = 4 * 1024 * 1024;
        const KCP_RECV_CHUNK: usize = 64 * 1024;
        let read_timeout = std::time::Duration::from_secs(30);

        let read_fut = async {
            let mut len_buf = [0u8; 4];
            stream.read_exact(&mut len_buf).await?;
            let len = u32::from_be_bytes(len_buf) as usize;
            if len > KCP_MAX_FRAME_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Message too large",
                ));
            }
            // Grow by at most KCP_RECV_CHUNK per read — a 4-byte prefix never
            // commits the full declared length before the body arrives.
            let mut data: Vec<u8> = Vec::with_capacity(len.min(KCP_RECV_CHUNK));
            let mut filled = 0usize;
            while filled < len {
                let chunk = (len - filled).min(KCP_RECV_CHUNK);
                data.resize(filled + chunk, 0);
                stream.read_exact(&mut data[filled..filled + chunk]).await?;
                filled += chunk;
            }
            Ok::<Vec<u8>, io::Error>(data)
        };
        let data = tokio::time::timeout(read_timeout, read_fut)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "KCP read timed out"))??;

        // Update bytes counter
        self.bytes_received
            .fetch_add(data.len() as u32 + 4, Ordering::Relaxed);

        log::trace!("KCP recv {} bytes", data.len());
        Ok(Bytes::from(data))
    }

    fn is_available(&self) -> bool {
        self.available.load(Ordering::Relaxed)
    }

    fn rtt_ms(&self) -> u32 {
        self.rtt_ms.load(Ordering::Relaxed)
    }

    fn loss_percent(&self) -> u8 {
        self.loss_percent.load(Ordering::Relaxed)
    }

    fn remote_addr(&self) -> Option<SocketAddr> {
        self.remote_addr
    }

    async fn close(&self) -> io::Result<()> {
        self.available.store(false, Ordering::Relaxed);

        // Drop the stream to close connection
        if let Some(stream) = self.stream.lock().await.take() {
            drop(stream);
        }

        log::info!(
            "KCP closed (sent: {} bytes, recv: {} bytes)",
            self.bytes_sent(),
            self.bytes_received()
        );
        Ok(())
    }
}

impl std::fmt::Debug for KcpLeg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KcpLeg")
            .field("remote", &self.remote_addr)
            .field("mode", &self.config.mode)
            .field("rtt_ms", &self.rtt_ms.load(Ordering::Relaxed))
            .field("loss%", &self.loss_percent.load(Ordering::Relaxed))
            .field("available", &self.is_available())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kcp_leg_creation() {
        let leg = KcpLeg::new();
        assert!(!leg.is_available());
        assert_eq!(leg.rtt_ms(), 50);
    }

    #[test]
    fn test_kcp_rtt_update() {
        let leg = KcpLeg::new();
        leg.update_rtt(100);
        assert!(leg.rtt_ms() > 50); // Should increase
    }

    #[test]
    fn test_kcp_mode_config() {
        let config = KcpLegConfig {
            mode: KcpMode::Turbo,
            ..Default::default()
        };
        let leg = KcpLeg::with_config(config);
        assert!(!leg.is_available());
    }
}
