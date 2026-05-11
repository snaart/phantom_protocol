//! Phantom Transport - Virtual Socket
//!
//! Unified socket abstraction over multiple transport legs.
//! Routes packets through the scheduler, handles fallback.

use crate::transport::bandwidth_estimator;
use crate::transport::{
    fallback::{FallbackStateMachine, TransportMode},
    legs::TransportLeg,
    scheduler::Scheduler,
    types::{LegType, SchedulerMode},
};

use bytes::Bytes;
use std::collections::HashMap;
use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, Mutex, RwLock};

/// Virtual socket configuration
#[derive(Debug, Clone)]
pub struct VirtualSocketConfig {
    /// Maximum packet size (MTU)
    pub max_packet_size: u32,
    /// Send buffer size
    pub send_buffer_size: u32,
    /// Receive buffer size  
    pub recv_buffer_size: u32,
    /// Enable automatic fallback
    pub auto_fallback: bool,
}

impl Default for VirtualSocketConfig {
    fn default() -> Self {
        Self {
            max_packet_size: 1400,
            send_buffer_size: 1024,
            recv_buffer_size: 1024,
            auto_fallback: true,
        }
    }
}

/// Virtual socket - unified interface over multiple transport legs
pub struct VirtualSocket {
    /// Configuration
    config: VirtualSocketConfig,
    /// Transport legs
    legs: RwLock<HashMap<LegType, Arc<dyn TransportLeg>>>,
    /// Multi-path scheduler
    scheduler: Arc<Scheduler>,
    /// Fallback state machine
    fallback: Arc<FallbackStateMachine>,
    /// Receive channel
    recv_tx: mpsc::Sender<Bytes>,
    recv_rx: Mutex<mpsc::Receiver<Bytes>>,
    /// Per-leg bandwidth estimators — each network path has independent BBR state.
    /// Sharing a single estimator across LTE and Wi-Fi is mathematically incorrect
    /// since RTT, BDP, and loss patterns differ significantly per path.
    estimators: Arc<Mutex<HashMap<LegType, bandwidth_estimator::BandwidthEstimator>>>,
    /// Whether socket is closed
    closed: std::sync::atomic::AtomicBool,
}

impl VirtualSocket {
    /// Create a new virtual socket
    pub fn new(
        config: VirtualSocketConfig,
        scheduler: Arc<Scheduler>,
        fallback: Arc<FallbackStateMachine>,
    ) -> Self {
        let (recv_tx, recv_rx) = mpsc::channel(config.recv_buffer_size as usize);

        Self {
            config,
            legs: RwLock::new(HashMap::new()),
            scheduler,
            fallback,
            recv_tx,
            recv_rx: Mutex::new(recv_rx),
            estimators: Arc::new(Mutex::new(HashMap::new())),
            closed: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Create with default configuration
    pub fn with_defaults() -> Self {
        let scheduler = Arc::new(Scheduler::new(SchedulerMode::LowLatency));
        let fallback = Arc::new(FallbackStateMachine::with_defaults());
        Self::new(VirtualSocketConfig::default(), scheduler, fallback)
    }

    /// Register a transport leg
    pub async fn register_leg(&self, leg_type: LegType, leg: Arc<dyn TransportLeg>) {
        self.legs.write().await.insert(leg_type, leg);
        self.scheduler.register_path(leg_type);
    }

    /// Unregister a transport leg
    pub async fn unregister_leg(&self, leg_type: LegType) -> Option<Arc<dyn TransportLeg>> {
        let leg = self.legs.write().await.remove(&leg_type);
        self.scheduler.set_path_available(leg_type, false);
        leg
    }

    /// Get a transport leg
    pub async fn get_leg(&self, leg_type: LegType) -> Option<Arc<dyn TransportLeg>> {
        self.legs.read().await.get(&leg_type).cloned()
    }

    /// Send data through the virtual socket
    ///
    /// The scheduler selects the optimal path(s).
    pub async fn send(&self, data: Bytes, is_priority: bool) -> io::Result<()> {
        // Allow one fallback retry
        const MAX_FALLBACK_ATTEMPTS: u8 = 2;

        for attempt in 0..MAX_FALLBACK_ATTEMPTS {
            if self.is_closed() {
                return Err(io::Error::new(io::ErrorKind::NotConnected, "Socket closed"));
            }

            // Select paths via scheduler
            let paths = self.scheduler.select_paths(is_priority);

            if paths.is_empty() {
                // Check for fallback on first attempt
                if attempt == 0 && self.config.auto_fallback {
                    self.fallback.check_and_fallback();
                    continue; // Retry with new mode
                }
                return Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "No available paths",
                ));
            }

            let legs = self.legs.read().await;
            let mut last_error = None;
            let mut send_succeeded = false;

            for leg_type in paths {
                if let Some(leg) = legs.get(&leg_type) {
                    self.fallback.metrics().record_sent();

                    match leg.send(data.clone()).await {
                        Ok(()) => {
                            self.fallback.metrics().record_success();
                            self.scheduler.record_sent(leg_type, data.len() as u64);

                            // Update RTT from leg
                            self.scheduler.update_rtt(leg_type, leg.rtt_ms());

                            send_succeeded = true;
                            break;
                        }
                        Err(e) => {
                            self.fallback.metrics().record_failure();
                            last_error = Some(e);

                            // Mark path as potentially unavailable
                            if leg.loss_percent() > 50 {
                                self.scheduler.set_path_available(leg_type, false);
                            }
                        }
                    }
                }
            }

            if send_succeeded {
                return Ok(());
            }

            // All paths failed on this attempt, try fallback (only on first attempt)
            if attempt == 0 && self.config.auto_fallback && self.fallback.check_and_fallback() {
                // Will retry in next loop iteration with new mode
                continue;
            }

            return Err(last_error.unwrap_or_else(|| io::Error::other("All paths failed")));
        }

        Err(io::Error::other("Max fallback attempts reached"))
    }

    /// Receive data from the virtual socket
    pub async fn recv(&self) -> io::Result<Bytes> {
        if self.is_closed() {
            return Err(io::Error::new(io::ErrorKind::NotConnected, "Socket closed"));
        }

        let mut rx = self.recv_rx.lock().await;

        rx.recv()
            .await
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "Channel closed"))
    }

    /// Try to receive without blocking
    pub async fn try_recv(&self) -> Option<Bytes> {
        let mut rx = self.recv_rx.lock().await;
        rx.try_recv().ok()
    }

    /// Start background receive loop for a leg
    pub async fn start_recv_loop(&self, leg_type: LegType) -> io::Result<()> {
        let leg = self
            .legs
            .read()
            .await
            .get(&leg_type)
            .cloned()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Leg not found"))?;

        let tx = self.recv_tx.clone();
        let scheduler = self.scheduler.clone();
        let estimators = self.estimators.clone();
        let fallback = self.fallback.clone();
        // Clone the AtomicBool into an Arc so we can move it into the spawned task
        let closed = Arc::new(std::sync::atomic::AtomicBool::new(
            self.closed.load(std::sync::atomic::Ordering::Relaxed),
        ));

        tokio::spawn(async move {
            loop {
                if closed.load(std::sync::atomic::Ordering::Relaxed) {
                    break;
                }

                match leg.recv().await {
                    Ok(data) => {
                        // If we receive ANY data on KCP leg, try to upgrade from degraded modes
                        if leg_type == LegType::Kcp {
                            fallback.upgrade();
                        }

                        // Update RTT
                        scheduler.update_rtt(leg_type, leg.rtt_ms());

                        // Detect ACKs for BBR feedback; update the leg-specific estimator.
                        // Each leg maintains independent BBR state so that different network
                        // paths (LTE, Wi-Fi, TCP) don't corrupt each other's bandwidth estimate.
                        if data.len() >= crate::transport::types::PacketHeader::SIZE {
                            let flags = data[38]; // flags byte is always at offset 38
                            if (flags & 0b0000_0010) != 0 {
                                // PacketFlags::ACK
                                let mut ests: tokio::sync::MutexGuard<
                                    '_,
                                    HashMap<LegType, bandwidth_estimator::BandwidthEstimator>,
                                > = estimators.lock().await;
                                let est = ests.entry(leg_type).or_default();
                                // Read ack_delay from packet header (bytes 39..41, little-endian u16)
                                let ack_delay_us = if data.len() >= 41 {
                                    u16::from_le_bytes([data[39], data[40]]) as u64
                                } else {
                                    0
                                };
                                let sample = bandwidth_estimator::DeliverySample {
                                    delivered_bytes: 0,
                                    sent_at: Instant::now()
                                        - Duration::from_millis(leg.rtt_ms() as u64),
                                    acked_at: Instant::now(),
                                    packet_bytes: data.len() as u64,
                                    is_app_limited: false,
                                    ack_delay_us,
                                };
                                est.on_ack(sample);
                            }
                        }

                        if tx.send(data).await.is_err() {
                            break; // Receiver dropped
                        }
                    }
                    Err(e) => {
                        log::error!("Recv error on {:?}: {}", leg_type, e);
                        scheduler.set_path_available(leg_type, false);
                        break;
                    }
                }
            }
        });

        Ok(())
    }

    /// Get current transport mode
    pub fn current_mode(&self) -> TransportMode {
        self.fallback.current_mode()
    }

    /// Get available leg types
    pub async fn available_legs(&self) -> Vec<LegType> {
        self.legs.read().await.keys().cloned().collect()
    }

    /// Check if socket is closed
    pub fn is_closed(&self) -> bool {
        self.closed.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Close the virtual socket
    pub async fn close(&self) -> io::Result<()> {
        self.closed
            .store(true, std::sync::atomic::Ordering::Relaxed);

        // Close all legs
        let legs = self.legs.write().await;
        for (_, leg) in legs.iter() {
            let _ = leg.close().await;
        }

        Ok(())
    }

    /// Get scheduler reference
    pub fn scheduler(&self) -> &Arc<Scheduler> {
        &self.scheduler
    }

    /// Get fallback state machine reference
    pub fn fallback(&self) -> &Arc<FallbackStateMachine> {
        &self.fallback
    }

    /// Start the background probe loop to allow transport healing
    pub fn start_probe_loop(self: Arc<Self>) {
        let socket = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            loop {
                interval.tick().await;

                if socket.is_closed() {
                    break;
                }

                if socket.fallback.should_probe() {
                    let legs = socket.legs.read().await;
                    if let Some(leg) = legs.get(&LegType::Kcp) {
                        socket.fallback.record_probe();

                        // Send a dummy probe packet (40 bytes of zeros)
                        // Peer will receive it, and its recv_loop will trigger their upgrade
                        let probe = Bytes::from(vec![0u8; 40]);
                        let _ = leg.send(probe).await;
                        log::debug!("Sent transport upgrade probe via KCP");
                    }
                }
            }
        });
    }
}

impl std::fmt::Debug for VirtualSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VirtualSocket")
            .field("mode", &self.current_mode())
            .field("closed", &self.is_closed())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_virtual_socket_creation() {
        let socket = VirtualSocket::with_defaults();

        assert!(!socket.is_closed());
        assert_eq!(socket.current_mode(), TransportMode::Turbo);
        assert!(socket.available_legs().await.is_empty());
    }
}
