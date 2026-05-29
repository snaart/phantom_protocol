//! Phantom Transport - Stream Management
//!
//! Multiplexed streams within a session.
//! Each stream has independent sequence numbers (no Head-of-Line blocking).

use crate::transport::types::{SequenceNumber, StreamId};

use bytes::Bytes;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, Notify, Semaphore};

const MAX_PENDING_PACKETS: usize = 1024;

/// Initial per-stream send window — caps how many bytes the local
/// side will put on the wire before receiving a `WINDOW_UPDATE` from
/// the peer. 64 KiB matches QUIC's stream initial-window default.
pub const INITIAL_STREAM_WINDOW: u32 = 64 * 1024;

/// Stream state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamState {
    /// Stream is open for both directions
    Open,
    /// Local side has finished sending
    HalfClosedLocal,
    /// Remote side has finished sending
    HalfClosedRemote,
    /// Stream is fully closed
    Closed,
}

/// Pending data waiting to be sent
#[derive(Debug)]
struct PendingData {
    sequence: SequenceNumber,
    data: Bytes,
    sent_at: Option<tokio::time::Instant>,
    #[allow(dead_code)]
    retries: u32,
}

/// RFC 6298 retransmission-timeout estimator (per stream). Replaces a fixed
/// retransmit timer with one that tracks measured RTT (SRTT / RTTVAR) and backs
/// off exponentially on consecutive timeouts.
#[derive(Debug)]
struct RtoEstimator {
    /// Smoothed RTT; `None` until the first measurement.
    srtt: Option<Duration>,
    /// RTT variation estimate.
    rttvar: Duration,
    /// Number of consecutive timeouts (RTO is doubled `backoff_shift` times).
    backoff_shift: u32,
}

impl RtoEstimator {
    /// RFC 6298 (2.1): RTO before the first measurement.
    const INITIAL_RTO: Duration = Duration::from_secs(1);
    /// Floor — RFC's 1s minimum is too conservative for a low-latency transport.
    const MIN_RTO: Duration = Duration::from_millis(200);
    /// Ceiling, so a stalled path can't push the timer arbitrarily high.
    const MAX_RTO: Duration = Duration::from_secs(60);
    /// Clock-granularity term `G` in RFC 6298 (2.3).
    const GRANULARITY: Duration = Duration::from_millis(1);
    /// Cap on the backoff doubling (2^6 = 64×).
    const MAX_BACKOFF_SHIFT: u32 = 6;

    fn new() -> Self {
        Self {
            srtt: None,
            rttvar: Duration::ZERO,
            backoff_shift: 0,
        }
    }

    /// Feed a fresh (non-retransmitted, per Karn) RTT measurement.
    fn on_rtt_sample(&mut self, r: Duration) {
        match self.srtt {
            None => {
                // RFC 6298 (2.2): first measurement.
                self.srtt = Some(r);
                self.rttvar = r / 2;
            }
            Some(srtt) => {
                // RFC 6298 (2.3): RTTVAR = (1-1/4)·RTTVAR + 1/4·|SRTT-R|;
                //                 SRTT  = (1-1/8)·SRTT  + 1/8·R.
                let diff = if srtt > r { srtt - r } else { r - srtt };
                self.rttvar = (self.rttvar * 3 + diff) / 4;
                self.srtt = Some((srtt * 7 + r) / 8);
            }
        }
        // A fresh measurement clears any accumulated backoff.
        self.backoff_shift = 0;
    }

    /// Current RTO, honoring backoff and the floor / ceiling.
    fn rto(&self) -> Duration {
        // RFC 6298 (2.2)/(2.3): RTO = SRTT + max(G, K·RTTVAR), K = 4.
        let base = match self.srtt {
            None => Self::INITIAL_RTO,
            Some(srtt) => srtt + std::cmp::max(Self::GRANULARITY, self.rttvar * 4),
        };
        // Exponential backoff (RFC 6298 (5.5)); saturate to MAX_RTO on overflow.
        let scaled = base
            .checked_mul(1u32 << self.backoff_shift)
            .unwrap_or(Self::MAX_RTO);
        scaled.clamp(Self::MIN_RTO, Self::MAX_RTO)
    }

    /// On a retransmission timeout: double the RTO (RFC 6298 (5.5)).
    fn on_timeout(&mut self) {
        self.backoff_shift = (self.backoff_shift + 1).min(Self::MAX_BACKOFF_SHIFT);
    }
}

#[cfg(test)]
mod rto_tests {
    use super::RtoEstimator;
    use std::time::Duration;

    #[test]
    fn follows_rfc6298_srtt_rttvar() {
        let mut est = RtoEstimator::new();
        // No samples yet → initial 1s.
        assert_eq!(est.rto(), Duration::from_secs(1));
        // First sample R=100ms: SRTT=100, RTTVAR=50, RTO = 100 + 4*50 = 300ms.
        est.on_rtt_sample(Duration::from_millis(100));
        assert_eq!(est.rto(), Duration::from_millis(300));
        // A steady stream of identical samples drives RTTVAR→0, so RTO→SRTT,
        // floored at MIN_RTO (200ms).
        for _ in 0..50 {
            est.on_rtt_sample(Duration::from_millis(100));
        }
        assert_eq!(est.rto(), Duration::from_millis(200));
    }

    #[test]
    fn backoff_doubles_and_fresh_sample_resets() {
        let mut est = RtoEstimator::new();
        est.on_rtt_sample(Duration::from_millis(100)); // RTO = 300ms
        assert_eq!(est.rto(), Duration::from_millis(300));
        est.on_timeout();
        assert_eq!(est.rto(), Duration::from_millis(600));
        est.on_timeout();
        assert_eq!(est.rto(), Duration::from_millis(1200));
        // A fresh measurement clears the backoff. This is a *second* sample, so
        // RTTVAR shrinks 50ms → 37.5ms and RTO = 100 + 4*37.5 = 250ms. The key
        // check is that backoff is gone: with shift still at 2 it would be 1000ms.
        est.on_rtt_sample(Duration::from_millis(100));
        assert_eq!(est.rto(), Duration::from_millis(250));
    }
}

/// Stream - multiplexed data channel within a session
pub struct Stream {
    /// Stream identifier
    id: StreamId,
    /// Current state
    state: Mutex<StreamState>,
    /// Send sequence number
    send_sequence: AtomicU32,
    /// Next expected receive sequence
    recv_sequence: AtomicU32,
    /// Send buffer (data waiting to be sent)
    send_buffer: Mutex<VecDeque<PendingData>>,
    /// Unreliable send buffer (fire and forget)
    unreliable_buffer: Mutex<VecDeque<(SequenceNumber, Bytes)>>,
    /// Receive buffer (out-of-order data)
    recv_buffer: Mutex<VecDeque<(SequenceNumber, Bytes)>>,
    /// Ordered receive queue (ready for application)
    recv_ready: Mutex<VecDeque<Bytes>>,
    /// Notify when data is ready to read
    recv_notify: Notify,
    /// Whether stream is finished locally
    local_finished: AtomicBool,
    /// Whether stream is finished remotely
    remote_finished: AtomicBool,
    /// Priority (higher = more important)
    priority: AtomicU32,
    /// Backpressure semaphore
    send_semaphore: Arc<Semaphore>,
    /// Bytes the **peer** has granted us to send — decremented as we
    /// emit payload bytes, replenished by inbound `WINDOW_UPDATE`
    /// frames (Phase 4.3). When it hits zero, `poll_send` stalls
    /// until the next `WINDOW_UPDATE`.
    peer_send_window: AtomicU32,
    /// Bytes the local side has granted the peer — replenished as
    /// the application drains `recv_ready`. We periodically emit a
    /// `WINDOW_UPDATE` carrying the new absolute window.
    local_recv_window: AtomicU32,
    /// Total bytes the local side has consumed since the last
    /// emitted `WINDOW_UPDATE`. Used to decide when to send the
    /// next update (avoid flooding the wire with tiny updates).
    bytes_since_last_update: AtomicU32,
    /// RFC 6298 retransmission-timeout estimator. A plain (sync) mutex: it is
    /// updated only from the serial ACK path and read by `poll_send`, and the
    /// guard is never held across an `.await`.
    rto: std::sync::Mutex<RtoEstimator>,
}

impl Stream {
    /// Create a new stream
    pub fn new(id: StreamId) -> Self {
        Self {
            id,
            state: Mutex::new(StreamState::Open),
            send_sequence: AtomicU32::new(0),
            recv_sequence: AtomicU32::new(0),
            send_buffer: Mutex::new(VecDeque::new()),
            unreliable_buffer: Mutex::new(VecDeque::new()),
            recv_buffer: Mutex::new(VecDeque::new()),
            recv_ready: Mutex::new(VecDeque::new()),
            recv_notify: Notify::new(),
            local_finished: AtomicBool::new(false),
            remote_finished: AtomicBool::new(false),
            priority: AtomicU32::new(0),
            send_semaphore: Arc::new(Semaphore::new(MAX_PENDING_PACKETS)),
            peer_send_window: AtomicU32::new(INITIAL_STREAM_WINDOW),
            local_recv_window: AtomicU32::new(INITIAL_STREAM_WINDOW),
            bytes_since_last_update: AtomicU32::new(0),
            rto: std::sync::Mutex::new(RtoEstimator::new()),
        }
    }

    // ── RFC 6298 retransmission timeout ──

    /// Current retransmission timeout. A poisoned lock is recovered by taking
    /// the inner value — the RTO is a heuristic, not a correctness invariant.
    fn current_rto(&self) -> Duration {
        match self.rto.lock() {
            Ok(g) => g.rto(),
            Err(poisoned) => poisoned.into_inner().rto(),
        }
    }

    /// Feed a fresh RTT measurement into the RTO estimator.
    fn record_rtt_sample(&self, rtt: Duration) {
        let mut g = match self.rto.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        g.on_rtt_sample(rtt);
    }

    /// Tell the RTO estimator a segment timed out (exponential backoff).
    fn note_rto_timeout(&self) {
        let mut g = match self.rto.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        g.on_timeout();
    }

    /// Get stream ID
    pub fn id(&self) -> StreamId {
        self.id
    }

    /// Get current state
    pub async fn state(&self) -> StreamState {
        *self.state.lock().await
    }

    /// Get priority
    pub fn priority(&self) -> u32 {
        self.priority.load(Ordering::Relaxed)
    }

    /// Set priority
    pub fn set_priority(&self, priority: u32) {
        self.priority.store(priority, Ordering::Relaxed);
    }

    // ── Flow control (Phase 4.3) ──

    /// Bytes the peer currently allows us to send.
    pub fn peer_send_window(&self) -> u32 {
        self.peer_send_window.load(Ordering::Acquire)
    }

    /// Atomically reserve `n` bytes from the peer's send window.
    /// Returns `true` if the reservation succeeded (and the window
    /// was decremented); `false` if the window doesn't have enough
    /// capacity — caller must wait for a `WINDOW_UPDATE`.
    pub fn try_consume_send_window(&self, n: u32) -> bool {
        let mut cur = self.peer_send_window.load(Ordering::Acquire);
        loop {
            if cur < n {
                return false;
            }
            match self.peer_send_window.compare_exchange_weak(
                cur,
                cur - n,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(actual) => cur = actual,
            }
        }
    }

    /// Process an inbound `WINDOW_UPDATE` from the peer. The payload
    /// is the new ABSOLUTE window size (not a delta). We accept
    /// monotonic increases only — a smaller value than the current
    /// window is ignored (it would be a regression).
    pub fn apply_peer_window_update(&self, new_window: u32) {
        let mut cur = self.peer_send_window.load(Ordering::Acquire);
        while new_window > cur {
            match self.peer_send_window.compare_exchange_weak(
                cur,
                new_window,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(actual) => cur = actual,
            }
        }
    }

    /// Bytes the local side has granted the peer.
    pub fn local_recv_window(&self) -> u32 {
        self.local_recv_window.load(Ordering::Acquire)
    }

    /// Record that the application has consumed `n` bytes from this
    /// stream's recv buffer. Returns `Some(new_window)` if a
    /// `WINDOW_UPDATE` should be emitted (the unreported delta has
    /// crossed half the initial window — a common heuristic that
    /// trades update frequency vs. peer stalls).
    pub fn record_app_consumed(&self, n: u32) -> Option<u32> {
        // Replenish the local recv window.
        self.local_recv_window.fetch_add(n, Ordering::AcqRel);
        let pending = self.bytes_since_last_update.fetch_add(n, Ordering::AcqRel) + n;
        let threshold = INITIAL_STREAM_WINDOW / 2;
        if pending >= threshold {
            self.bytes_since_last_update.store(0, Ordering::Release);
            Some(self.local_recv_window.load(Ordering::Acquire))
        } else {
            None
        }
    }

    /// Queue data for sending with reliability
    ///
    /// Returns the sequence number assigned to this chunk.
    pub async fn send_reliable(&self, data: Bytes) -> SequenceNumber {
        // Backpressure: wait until there is space in the buffer.
        // PANIC-SAFETY: `Semaphore::acquire` only errors after `close()`. The
        // `send_semaphore` is a private field of this struct, constructed in
        // `Stream::new` and never closed anywhere in the crate — the variant
        // is structurally unreachable.
        #[allow(clippy::expect_used)]
        let permit = self
            .send_semaphore
            .acquire()
            .await
            .expect("Semaphore closed");
        permit.forget();

        let seq = self.send_sequence.fetch_add(1, Ordering::SeqCst);

        let pending = PendingData {
            sequence: seq,
            data,
            sent_at: None,
            retries: 0,
        };

        self.send_buffer.lock().await.push_back(pending);

        seq
    }

    /// Queue data for unreliable sending
    ///
    /// Returns the sequence number assigned to this chunk.
    pub async fn send_unreliable(&self, data: Bytes) -> SequenceNumber {
        // Unreliable data does not consume buffer permits
        let seq = self.send_sequence.fetch_add(1, Ordering::SeqCst);

        self.unreliable_buffer.lock().await.push_back((seq, data));

        seq
    }

    /// Get next data chunk to send
    /// Returns: (SequenceNumber, Bytes, is_reliable)
    pub async fn poll_send(&self) -> Option<(SequenceNumber, Bytes, bool)> {
        // First check unreliable buffer (fire and forget)
        if let Some((seq, data)) = self.unreliable_buffer.lock().await.pop_front() {
            return Some((seq, data, false));
        }

        let mut buffer = self.send_buffer.lock().await;
        let now = tokio::time::Instant::now();
        // Adaptive RFC 6298 timeout (was a fixed 500ms).
        let timeout = self.current_rto();

        // Find reliable data not yet sent or needing retransmission
        for pending in buffer.iter_mut() {
            if pending.sent_at.is_none() {
                pending.sent_at = Some(now);
                return Some((pending.sequence, pending.data.clone(), true));
            } else if let Some(sent_at) = pending.sent_at {
                if now.duration_since(sent_at) >= timeout {
                    pending.sent_at = Some(now);
                    pending.retries += 1;
                    // Back the RTO off exponentially for the next attempt.
                    self.note_rto_timeout();
                    return Some((pending.sequence, pending.data.clone(), true));
                }
            }
        }

        None
    }

    /// Mark a sequence number as acknowledged.
    /// Returns the timestamp when the packet was originally sent and its size, if found.
    pub async fn ack(&self, sequence: SequenceNumber) -> Option<(tokio::time::Instant, u64)> {
        let mut buffer = self.send_buffer.lock().await;
        let mut result = None;

        // Find the packet and get its sent_at time
        if let Some(pos) = buffer.iter().position(|p| p.sequence == sequence) {
            let sent_at = buffer[pos].sent_at;
            let retries = buffer[pos].retries;
            let size = buffer[pos].data.len() as u64;
            buffer.remove(pos);

            // Released space, add permit back
            self.send_semaphore.add_permits(1);

            if let Some(sent_at) = sent_at {
                result = Some((sent_at, size));
                // Karn's algorithm: only sample RTT from segments that were not
                // retransmitted — an ACK for a resent sequence is ambiguous.
                if retries == 0 {
                    let rtt = tokio::time::Instant::now().duration_since(sent_at);
                    self.record_rtt_sample(rtt);
                }
            }
        }

        result
    }

    /// Handle received data
    ///
    /// Data is buffered until it can be delivered in order.
    pub async fn on_receive(&self, sequence: SequenceNumber, data: Bytes) {
        let expected = self.recv_sequence.load(Ordering::SeqCst);

        if sequence == expected {
            // In-order delivery
            self.recv_ready.lock().await.push_back(data);
            self.recv_sequence.fetch_add(1, Ordering::SeqCst);

            // Try to deliver buffered out-of-order data
            self.deliver_buffered().await;

            // Notify waiters
            self.recv_notify.notify_waiters();
        } else if sequence > expected {
            // Out-of-order, buffer it
            self.recv_buffer.lock().await.push_back((sequence, data));
        }
        // sequence < expected means duplicate, ignore it
    }

    /// Try to deliver buffered out-of-order data
    async fn deliver_buffered(&self) {
        let mut recv_buf = self.recv_buffer.lock().await;
        let mut ready = self.recv_ready.lock().await;

        loop {
            let expected = self.recv_sequence.load(Ordering::SeqCst);

            // Find and remove the expected sequence.
            // PANIC-SAFETY: `pos` was just returned by `iter().position(...)`,
            // so `recv_buf` has an element at that index — `remove` cannot
            // return `None`. `recv_buf` is locked for the duration of this
            // loop, so no other task can drain it.
            if let Some(pos) = recv_buf.iter().position(|(seq, _)| *seq == expected) {
                #[allow(clippy::unwrap_used, clippy::disallowed_methods)]
                let (_, data) = recv_buf.remove(pos).unwrap();
                ready.push_back(data);
                self.recv_sequence.fetch_add(1, Ordering::SeqCst);
            } else {
                break;
            }
        }
    }

    /// Read data from the stream (async, waits if no data available)
    pub async fn recv(&self) -> Option<Bytes> {
        loop {
            {
                let mut ready = self.recv_ready.lock().await;
                if let Some(data) = ready.pop_front() {
                    return Some(data);
                }

                // Check if stream is closed
                if self.remote_finished.load(Ordering::SeqCst) {
                    return None;
                }
            }

            // Wait for new data
            self.recv_notify.notified().await;
        }
    }

    /// Try to read data without waiting
    pub async fn try_recv(&self) -> Option<Bytes> {
        self.recv_ready.lock().await.pop_front()
    }

    /// Mark local side as finished (no more data to send)
    pub async fn finish(&self) {
        self.local_finished.store(true, Ordering::SeqCst);
        self.update_state().await;
    }

    /// Mark remote side as finished
    pub async fn on_remote_finish(&self) {
        self.remote_finished.store(true, Ordering::SeqCst);
        self.recv_notify.notify_waiters();
        self.update_state().await;
    }

    /// Update stream state based on finish flags
    async fn update_state(&self) {
        let local = self.local_finished.load(Ordering::SeqCst);
        let remote = self.remote_finished.load(Ordering::SeqCst);

        let new_state = match (local, remote) {
            (true, true) => StreamState::Closed,
            (true, false) => StreamState::HalfClosedLocal,
            (false, true) => StreamState::HalfClosedRemote,
            (false, false) => StreamState::Open,
        };

        *self.state.lock().await = new_state;
    }

    /// Get number of pending send chunks
    pub async fn pending_send_count(&self) -> usize {
        self.send_buffer.lock().await.len()
    }

    /// Get number of pending receive chunks
    pub async fn pending_recv_count(&self) -> usize {
        self.recv_ready.lock().await.len()
    }

    /// Check if stream is closed
    pub fn is_closed(&self) -> bool {
        self.local_finished.load(Ordering::SeqCst) && self.remote_finished.load(Ordering::SeqCst)
    }
}

impl std::fmt::Debug for Stream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Stream")
            .field("id", &self.id)
            .field("send_seq", &self.send_sequence.load(Ordering::Relaxed))
            .field("recv_seq", &self.recv_sequence.load(Ordering::Relaxed))
            .field("priority", &self.priority.load(Ordering::Relaxed))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_stream_send_recv() {
        let stream = Stream::new(1);

        // Send data
        stream.send_reliable(Bytes::from("hello")).await;
        stream.send_reliable(Bytes::from("world")).await;

        // Check pending
        assert_eq!(stream.pending_send_count().await, 2);

        // Poll send twice, the second should be None because it's already sent and hasn't timed out
        let (seq, data, is_reliable) = stream.poll_send().await.unwrap();
        assert_eq!(seq, 0);
        assert_eq!(data, Bytes::from("hello"));
        assert!(is_reliable);

        let (seq2, data2, is_reliable2) = stream.poll_send().await.unwrap();
        assert_eq!(seq2, 1);
        assert_eq!(data2, Bytes::from("world"));
        assert!(is_reliable2);

        assert!(stream.poll_send().await.is_none());
    }

    #[tokio::test]
    async fn test_stream_retransmission() {
        // We use tokio::time::pause to mock time and test timeout
        tokio::time::pause();
        let stream = Stream::new(1);

        stream.send_reliable(Bytes::from("hello")).await;

        // First send
        let (seq, _, is_reliable) = stream.poll_send().await.unwrap();
        assert_eq!(seq, 0);
        assert!(is_reliable);

        // Immediate poll should be None
        assert!(stream.poll_send().await.is_none());

        // Advance 400ms — still under the initial 1s RTO (RFC 6298 (2.1):
        // no RTT samples yet, so the timer sits at the 1-second default).
        tokio::time::advance(std::time::Duration::from_millis(400)).await;
        assert!(stream.poll_send().await.is_none());

        // Advance past the 1s initial RTO (total ~1.1s).
        tokio::time::advance(std::time::Duration::from_millis(700)).await;

        // Now it should retransmit
        let (seq2, data2, is_reliable2) = stream.poll_send().await.unwrap();
        assert_eq!(seq2, 0);
        assert_eq!(data2, Bytes::from("hello"));
        assert!(is_reliable2);

        // Ack it
        let acked = stream.ack(0).await;
        assert!(acked.is_some());

        // Poll again - queue is empty
        assert!(stream.poll_send().await.is_none());
    }

    #[tokio::test]
    async fn test_stream_in_order_receive() {
        let stream = Stream::new(1);

        // Receive in order
        stream.on_receive(0, Bytes::from("first")).await;
        stream.on_receive(1, Bytes::from("second")).await;

        assert_eq!(stream.try_recv().await, Some(Bytes::from("first")));
        assert_eq!(stream.try_recv().await, Some(Bytes::from("second")));
        assert_eq!(stream.try_recv().await, None);
    }

    #[tokio::test]
    async fn test_stream_out_of_order_receive() {
        let stream = Stream::new(1);

        // Receive out of order
        stream.on_receive(1, Bytes::from("second")).await;
        stream.on_receive(0, Bytes::from("first")).await;

        // Should be reordered
        assert_eq!(stream.try_recv().await, Some(Bytes::from("first")));
        assert_eq!(stream.try_recv().await, Some(Bytes::from("second")));
    }

    #[tokio::test]
    async fn test_stream_state() {
        let stream = Stream::new(1);

        assert_eq!(stream.state().await, StreamState::Open);

        stream.finish().await;
        assert_eq!(stream.state().await, StreamState::HalfClosedLocal);

        stream.on_remote_finish().await;
        assert_eq!(stream.state().await, StreamState::Closed);
        assert!(stream.is_closed());
    }

    #[tokio::test]
    async fn test_stream_backpressure() {
        let stream = Stream::new(1);

        // Fill the buffer
        for _ in 0..MAX_PENDING_PACKETS {
            stream.send_reliable(Bytes::from("data")).await;
        }

        assert_eq!(stream.pending_send_count().await, MAX_PENDING_PACKETS);

        // Try to send one more with timeout
        let send_future = stream.send_reliable(Bytes::from("blocked"));
        let result = tokio::time::timeout(std::time::Duration::from_millis(100), send_future).await;
        assert!(result.is_err(), "Send should have blocked");

        // Ack one
        stream.ack(0).await;

        // Now it should succeed
        let send_future = stream.send_reliable(Bytes::from("resumed"));
        let result = tokio::time::timeout(std::time::Duration::from_millis(100), send_future).await;
        assert!(result.is_ok(), "Send should have succeeded after ack");
        assert_eq!(stream.pending_send_count().await, MAX_PENDING_PACKETS);
    }

    // ── Flow control (Phase 4.3) ──

    #[test]
    fn peer_send_window_starts_at_initial() {
        let s = Stream::new(1);
        assert_eq!(s.peer_send_window(), INITIAL_STREAM_WINDOW);
    }

    #[test]
    fn try_consume_send_window_decrements_atomically() {
        let s = Stream::new(1);
        assert!(s.try_consume_send_window(1000));
        assert_eq!(s.peer_send_window(), INITIAL_STREAM_WINDOW - 1000);
        assert!(s.try_consume_send_window(INITIAL_STREAM_WINDOW - 1000));
        assert_eq!(s.peer_send_window(), 0);
        // Further consumption fails until refilled.
        assert!(!s.try_consume_send_window(1));
    }

    #[test]
    fn apply_peer_window_update_only_grows() {
        let s = Stream::new(1);
        // Drain to 100 bytes.
        assert!(s.try_consume_send_window(INITIAL_STREAM_WINDOW - 100));
        assert_eq!(s.peer_send_window(), 100);

        // Replenish to a larger value than the current.
        s.apply_peer_window_update(INITIAL_STREAM_WINDOW);
        assert_eq!(s.peer_send_window(), INITIAL_STREAM_WINDOW);

        // A smaller value is ignored (window is monotonic).
        s.apply_peer_window_update(50);
        assert_eq!(s.peer_send_window(), INITIAL_STREAM_WINDOW);
    }

    #[test]
    fn record_app_consumed_emits_only_after_threshold() {
        let s = Stream::new(1);
        let threshold = INITIAL_STREAM_WINDOW / 2;

        // Small drains return None.
        assert!(s.record_app_consumed(100).is_none());
        assert!(s.record_app_consumed(200).is_none());

        // Drain across the half-window threshold → expect an update.
        let pending = s.record_app_consumed(threshold);
        assert!(pending.is_some(), "should emit WINDOW_UPDATE");
        // The announced window equals the new local_recv_window
        // (post-replenish).
        assert_eq!(pending.unwrap(), INITIAL_STREAM_WINDOW + 300 + threshold,);

        // Counter resets after emitting — small further drains do not
        // re-emit immediately.
        assert!(s.record_app_consumed(10).is_none());
    }
}
