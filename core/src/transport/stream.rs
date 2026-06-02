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

/// Hard ceiling on the credit-based send window. `WINDOW_UPDATE` frames add
/// *relative* credit; this caps the accumulated window so a peer that floods
/// inflated credits cannot overflow the counter. A compliant peer never grants
/// more than ~one [`INITIAL_STREAM_WINDOW`] of outstanding credit, so the cap is
/// only a misbehaving-peer guard (the receiver's own delivery HARD_CAP is the
/// real bound on buffering).
pub const MAX_SEND_WINDOW: u32 = 8 * INITIAL_STREAM_WINDOW;

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

/// One segment handed back by [`Stream::poll_send`] for transmission.
#[derive(Debug, Clone)]
pub struct OutboundSegment {
    /// Sequence number of the segment.
    pub seq: SequenceNumber,
    /// Payload bytes.
    pub data: Bytes,
    /// Whether the segment is on the reliable (ACK-tracked) path.
    pub reliable: bool,
    /// True when this is a retransmission (the RTO expired) rather than a first
    /// transmission — the caller reports it to congestion control as a loss.
    pub retransmit: bool,
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
    /// Pending **relative** flow-control credit to advertise in a
    /// `WINDOW_UPDATE`, staged by the receive **delivery** task (which credits
    /// the window on *real* app consumption) and flushed by the **send loop** —
    /// the single writer that also owns rekey, so the encrypted control frame is
    /// sealed under a consistent epoch. Credits accumulate additively, so
    /// several grants between two flushes are never lost. `0` = nothing pending.
    pending_window_update: AtomicU32,
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
            pending_window_update: AtomicU32::new(0),
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

    /// Process an inbound `WINDOW_UPDATE` from the peer. The payload is a
    /// **relative credit** — the number of bytes the peer's application just
    /// consumed and is therefore newly willing to receive. We *add* it to the
    /// send window (saturating at [`MAX_SEND_WINDOW`] so a misbehaving peer's
    /// inflated credit cannot overflow the counter).
    ///
    /// Relative credit (vs. an absolute window) is what makes flow control
    /// correct for a session of any length: the sender's window is
    /// `initial + Σ credit_granted − Σ bytes_sent` = `initial + consumed −
    /// sent`, so the receiver's outstanding (unconsumed) bytes `sent − consumed`
    /// are bounded by `initial`. An absolute u32 window could not express this
    /// for sessions exceeding 4 GiB and over-committed the receiver's buffer.
    pub fn apply_peer_window_update(&self, credit: u32) {
        let mut cur = self.peer_send_window.load(Ordering::Acquire);
        loop {
            let next = cur.saturating_add(credit).min(MAX_SEND_WINDOW);
            if next == cur {
                return; // already at the cap; nothing to add
            }
            match self.peer_send_window.compare_exchange_weak(
                cur,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return,
                Err(actual) => cur = actual,
            }
        }
    }

    /// Bytes the local side has granted the peer.
    pub fn local_recv_window(&self) -> u32 {
        self.local_recv_window.load(Ordering::Acquire)
    }

    /// Record that the application has actually consumed `n` bytes from this
    /// stream (called by the receive *delivery* task on real drainage, not
    /// on routing). Accumulates the consumed bytes and, once the unreported
    /// total crosses half the initial window, returns `Some(credit)` — the
    /// **relative credit** to advertise in a `WINDOW_UPDATE` (the peer *adds*
    /// it to its send window). The half-window threshold trades update frequency
    /// against peer stalls.
    pub fn record_app_consumed(&self, n: u32) -> Option<u32> {
        let pending = self.bytes_since_last_update.fetch_add(n, Ordering::AcqRel) + n;
        let threshold = INITIAL_STREAM_WINDOW / 2;
        if pending >= threshold {
            // Grant exactly the bytes we accumulated since the last update and
            // reset the accumulator. Use a CAS-free `fetch_sub` of the granted
            // amount rather than `store(0)` so a concurrent consume isn't lost.
            self.bytes_since_last_update
                .fetch_sub(pending, Ordering::AcqRel);
            // Keep the (now informational) local_recv_window in step for stats.
            self.local_recv_window.fetch_add(pending, Ordering::AcqRel);
            Some(pending)
        } else {
            None
        }
    }

    /// Stage relative flow-control credit to be flushed by the send loop.
    /// Called by the receive delivery task after it credits real app
    /// consumption. Credits **accumulate additively** (saturating at
    /// `u32::MAX`) rather than overwriting, so several grants landing between
    /// two send-loop flushes are summed instead of lost — the send loop is the
    /// single emitter (epoch-safe), and it may run arbitrarily after a grant.
    pub fn stage_window_update_credit(&self, credit: u32) {
        let mut cur = self.pending_window_update.load(Ordering::Acquire);
        loop {
            let next = cur.saturating_add(credit);
            if next == cur {
                return; // nothing to add (zero credit, or already saturated)
            }
            match self.pending_window_update.compare_exchange_weak(
                cur,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return,
                Err(actual) => cur = actual,
            }
        }
    }

    /// Take all staged credit (swaps the slot back to `0`). The send loop calls
    /// this each drain pass and emits one `WINDOW_UPDATE` carrying the summed
    /// credit if `Some`.
    pub fn take_pending_window_update(&self) -> Option<u32> {
        match self.pending_window_update.swap(0, Ordering::AcqRel) {
            0 => None,
            w => Some(w),
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

    /// Reserve the next outbound sequence number from this stream's send space.
    ///
    /// Control frames that are emitted directly on a data stream (e.g.
    /// `WINDOW_UPDATE`, a bare `FIN`) MUST draw their sequence from here rather
    /// than a private counter: the AEAD nonce is `(epoch, stream_id, sequence,
    /// path_id)` and the receiver's replay window is keyed on `(stream_id,
    /// sequence)`, so a control frame sharing a `(stream_id, sequence)` with a
    /// data packet in the same epoch would reuse a nonce **and** be dropped as a
    /// replay. Sharing one monotonic space keeps every packet on the stream
    /// unique. Control frames are unreliable, so the resulting gap in the data
    /// sequence is harmless (no ACK is expected, nothing waits to reassemble it).
    pub fn next_send_sequence(&self) -> SequenceNumber {
        self.send_sequence.fetch_add(1, Ordering::SeqCst)
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

    /// Get the next segment to (re)transmit, or `None` if nothing is due.
    ///
    /// `cwnd_budget` is how many bytes of *new* data the congestion window
    /// currently permits. Retransmissions ignore it — loss recovery must always
    /// proceed — but a first transmission is withheld (`None`) when it would
    /// exceed the budget, so the next drain resumes once ACKs free the window.
    /// Pass `u64::MAX` to disable the limit.
    pub async fn poll_send(&self, cwnd_budget: u64) -> Option<OutboundSegment> {
        // Unreliable data is fire-and-forget and not congestion-controlled.
        if let Some((seq, data)) = self.unreliable_buffer.lock().await.pop_front() {
            return Some(OutboundSegment {
                seq,
                data,
                reliable: false,
                retransmit: false,
            });
        }

        let mut buffer = self.send_buffer.lock().await;
        let now = tokio::time::Instant::now();
        // Adaptive RFC 6298 timeout (was a fixed 500ms).
        let timeout = self.current_rto();

        // Pass 1: a timed-out segment (retransmission) — always allowed.
        for pending in buffer.iter_mut() {
            if let Some(sent_at) = pending.sent_at {
                if now.duration_since(sent_at) >= timeout {
                    pending.sent_at = Some(now);
                    pending.retries += 1;
                    // Back the RTO off exponentially for the next attempt.
                    self.note_rto_timeout();
                    return Some(OutboundSegment {
                        seq: pending.sequence,
                        data: pending.data.clone(),
                        reliable: true,
                        retransmit: true,
                    });
                }
            }
        }

        // Pass 2: the next unsent segment, if it fits BOTH the congestion window
        // AND the peer's advertised flow-control window. In-order: if the head
        // unsent segment doesn't fit, stop (don't skip). Retransmissions (Pass 1)
        // bypass both budgets — those bytes were already accounted on first send
        // (Karn), and loss recovery must always proceed.
        for pending in buffer.iter_mut() {
            if pending.sent_at.is_none() {
                let len = pending.data.len() as u64;
                if len > cwnd_budget {
                    return None; // congestion window full — wait for ACKs to free it
                }
                // Flow-control enforcement: consume the peer's advertised
                // receive window. If it is exhausted, withhold the segment and
                // wait for a `WINDOW_UPDATE` — this is what propagates a slow
                // peer-side consumer back to us as real backpressure (the
                // receive delivery task only credits the window on actual app
                // consumption). `try_consume_send_window` is an atomic CAS; on
                // success the window is debited and we WILL send (no later check
                // can fail), so the debit never leaks.
                if !self.try_consume_send_window(len as u32) {
                    return None; // peer flow-control window closed — wait for WINDOW_UPDATE
                }
                pending.sent_at = Some(now);
                return Some(OutboundSegment {
                    seq: pending.sequence,
                    data: pending.data.clone(),
                    reliable: true,
                    retransmit: false,
                });
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

    /// Reset a still-buffered reliable segment's send timestamp so the next
    /// [`poll_send`](Self::poll_send) re-offers it immediately (as an unsent
    /// segment) rather than waiting a full RTO for the retransmit pass. Used
    /// when a send attempt failed *after* `poll_send` had already stamped
    /// `sent_at` — the bytes never reached the wire, so the segment must not be
    /// treated as in-flight. No-op if the segment was already acknowledged and
    /// removed.
    pub async fn mark_unsent(&self, sequence: SequenceNumber) {
        let mut buffer = self.send_buffer.lock().await;
        if let Some(pending) = buffer.iter_mut().find(|p| p.sequence == sequence) {
            pending.sent_at = None;
        }
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
        let seg = stream.poll_send(u64::MAX).await.unwrap();
        assert_eq!(seg.seq, 0);
        assert_eq!(seg.data, Bytes::from("hello"));
        assert!(seg.reliable);
        assert!(!seg.retransmit);

        let seg2 = stream.poll_send(u64::MAX).await.unwrap();
        assert_eq!(seg2.seq, 1);
        assert_eq!(seg2.data, Bytes::from("world"));
        assert!(seg2.reliable);
        assert!(!seg2.retransmit);

        assert!(stream.poll_send(u64::MAX).await.is_none());
    }

    #[tokio::test]
    async fn test_stream_retransmission() {
        // We use tokio::time::pause to mock time and test timeout
        tokio::time::pause();
        let stream = Stream::new(1);

        stream.send_reliable(Bytes::from("hello")).await;

        // First send — not a retransmission.
        let seg = stream.poll_send(u64::MAX).await.unwrap();
        assert_eq!(seg.seq, 0);
        assert!(seg.reliable);
        assert!(!seg.retransmit);

        // Immediate poll should be None
        assert!(stream.poll_send(u64::MAX).await.is_none());

        // Advance 400ms — still under the initial 1s RTO (RFC 6298 (2.1):
        // no RTT samples yet, so the timer sits at the 1-second default).
        tokio::time::advance(std::time::Duration::from_millis(400)).await;
        assert!(stream.poll_send(u64::MAX).await.is_none());

        // Advance past the 1s initial RTO (total ~1.1s).
        tokio::time::advance(std::time::Duration::from_millis(700)).await;

        // Now it should retransmit — flagged as a retransmission.
        let seg2 = stream.poll_send(u64::MAX).await.unwrap();
        assert_eq!(seg2.seq, 0);
        assert_eq!(seg2.data, Bytes::from("hello"));
        assert!(seg2.reliable);
        assert!(seg2.retransmit);

        // Ack it
        let acked = stream.ack(0).await;
        assert!(acked.is_some());

        // Poll again - queue is empty
        assert!(stream.poll_send(u64::MAX).await.is_none());
    }

    #[tokio::test]
    async fn mark_unsent_re_offers_without_waiting_rto() {
        // Time is paused, so nothing ever crosses the RTO — any re-offer here is
        // due to `mark_unsent`, not the retransmit timer.
        tokio::time::pause();
        let stream = Stream::new(1);
        stream.send_reliable(Bytes::from("hello")).await;

        // First poll stamps `sent_at`; an immediate re-poll yields nothing
        // (treated as in-flight, not yet timed out).
        let seg = stream.poll_send(u64::MAX).await.unwrap();
        assert_eq!(seg.seq, 0);
        assert!(!seg.retransmit);
        assert!(stream.poll_send(u64::MAX).await.is_none());

        // Simulate a send that failed *after* `poll_send` stamped the segment:
        // clear `sent_at` so it is no longer considered in-flight.
        stream.mark_unsent(0).await;

        // It is re-offered immediately — without advancing past the RTO — and as
        // a fresh send (Pass 2), not a retransmission.
        let seg2 = stream.poll_send(u64::MAX).await.unwrap();
        assert_eq!(seg2.seq, 0);
        assert_eq!(seg2.data, Bytes::from("hello"));
        assert!(seg2.reliable);
        assert!(!seg2.retransmit);

        // `mark_unsent` on an already-acked (removed) segment is a no-op.
        assert!(stream.ack(0).await.is_some());
        stream.mark_unsent(0).await; // no panic, no effect
        assert!(stream.poll_send(u64::MAX).await.is_none());
    }

    #[tokio::test]
    async fn poll_send_respects_the_cwnd_budget() {
        let stream = Stream::new(1);
        stream.send_reliable(Bytes::from("0123456789")).await; // 10 bytes
        stream.send_reliable(Bytes::from("abcde")).await; // 5 bytes

        // Budget of 10 admits the 10-byte head segment.
        let seg = stream.poll_send(10).await.unwrap();
        assert_eq!(seg.data.len(), 10);
        assert!(!seg.retransmit);

        // Budget of 4 is too small for the next (5-byte) segment → withheld.
        assert!(stream.poll_send(4).await.is_none());

        // A budget of 5 now admits it.
        let seg2 = stream.poll_send(5).await.unwrap();
        assert_eq!(seg2.data, Bytes::from("abcde"));
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
    fn apply_peer_window_update_adds_relative_credit() {
        let s = Stream::new(1);
        // Drain to 100 bytes.
        assert!(s.try_consume_send_window(INITIAL_STREAM_WINDOW - 100));
        assert_eq!(s.peer_send_window(), 100);

        // A WINDOW_UPDATE is a relative credit: it ADDS to the window.
        s.apply_peer_window_update(1000);
        assert_eq!(s.peer_send_window(), 1100);
        s.apply_peer_window_update(50);
        assert_eq!(s.peer_send_window(), 1150);

        // Saturates at the hard cap (misbehaving-peer guard).
        s.apply_peer_window_update(u32::MAX);
        assert_eq!(s.peer_send_window(), MAX_SEND_WINDOW);
    }

    #[test]
    fn record_app_consumed_grants_relative_credit_after_threshold() {
        let s = Stream::new(1);
        let threshold = INITIAL_STREAM_WINDOW / 2;

        // Small drains return None.
        assert!(s.record_app_consumed(100).is_none());
        assert!(s.record_app_consumed(200).is_none());

        // Drain across the half-window threshold → emit a credit equal to the
        // accumulated consumption (300 + threshold), NOT an absolute window.
        let credit = s.record_app_consumed(threshold);
        assert_eq!(
            credit,
            Some(300 + threshold),
            "WINDOW_UPDATE carries the relative credit (bytes consumed since last update)"
        );

        // Counter resets after emitting — small further drains do not re-emit.
        assert!(s.record_app_consumed(10).is_none());
    }

    #[test]
    fn relative_credit_round_trip_bounds_outstanding_to_one_window() {
        // Model: receiver grants credit == consumed; sender's window =
        // initial + Σcredit − Σsent, so outstanding (sent − consumed) ≤ initial.
        let sender = Stream::new(1);
        let receiver = Stream::new(1);
        let threshold = INITIAL_STREAM_WINDOW / 2;

        // Sender fills the initial window exactly.
        assert!(sender.try_consume_send_window(INITIAL_STREAM_WINDOW));
        assert_eq!(sender.peer_send_window(), 0, "initial window exhausted");

        // Receiver consumes one threshold's worth → grants that much credit.
        let credit = receiver
            .record_app_consumed(threshold)
            .expect("threshold crossed");
        sender.apply_peer_window_update(credit);
        assert_eq!(
            sender.peer_send_window(),
            threshold,
            "sender may now send exactly the bytes the receiver consumed"
        );
    }

    #[test]
    fn staged_window_update_credit_accumulates_until_taken() {
        let s = Stream::new(1);
        assert_eq!(s.take_pending_window_update(), None);

        // Two grants staged before a single flush must SUM, not overwrite: the
        // send loop (sole emitter) may run arbitrarily late after a credit is
        // staged, so back-to-back grants would otherwise lose all but the last
        // — a permanent credit leak that shrinks the peer's window over time.
        s.stage_window_update_credit(1000);
        s.stage_window_update_credit(2500);
        assert_eq!(s.take_pending_window_update(), Some(3500));

        // The slot resets to empty once taken.
        assert_eq!(s.take_pending_window_update(), None);

        // Accumulation saturates instead of wrapping past u32::MAX.
        s.stage_window_update_credit(u32::MAX);
        s.stage_window_update_credit(10);
        assert_eq!(s.take_pending_window_update(), Some(u32::MAX));

        // Zero credit is a no-op (no spurious WINDOW_UPDATE).
        s.stage_window_update_credit(0);
        assert_eq!(s.take_pending_window_update(), None);
    }
}
