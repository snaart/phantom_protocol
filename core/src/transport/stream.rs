//! Phantom Protocol - Stream Management
//!
//! Multiplexed streams within a session.
//! Each stream has independent sequence numbers (no Head-of-Line blocking).

use crate::transport::sack::Sack;
use crate::transport::types::{SequenceNumber, StreamId};

use bytes::Bytes;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, Notify, Semaphore};

const MAX_PENDING_PACKETS: usize = 1024;

/// Upper bound on out-of-order segments held for reassembly per stream. In
/// practice the flow-control window bounds in-flight (hence reorderable) data far
/// below this; a peer that floods past its window with huge gaps is refused here
/// (the refused segment is NOT recorded as received, so it is not SACKed and the
/// sender retransmits it — no SACK-without-data hazard, bounded memory).
const MAX_RECV_REORDER: usize = 2048;

/// RFC 9002 §6.1.1 packet-threshold: a still-unacked segment is declared lost
/// once a segment at least this many offsets *newer* has been SACK-acked.
const PACKET_THRESHOLD: u32 = 3;

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
    /// Wire `header.sequence` — the AEAD-nonce / replay id (shared with control
    /// frames, so NOT gap-free). Reused verbatim on retransmit.
    sequence: SequenceNumber,
    /// Gap-free per-stream reliable-data offset — the reassembly / SACK / loss-
    /// detection key (A.5). Carried in the AEAD plaintext so the receiver can
    /// deliver reliable data strictly in send order even when `sequence` has
    /// control-frame holes. Stable across retransmits.
    stream_offset: SequenceNumber,
    data: Bytes,
    sent_at: Option<tokio::time::Instant>,
    #[allow(dead_code)]
    retries: u32,
    /// Flagged lost by the SACK-driven loss detector (RFC 9002 packet- or
    /// time-threshold, L1-B). `poll_send`'s Pass-0 fast-retransmits it ahead of
    /// cwnd/window, then clears the flag. Distinct from the RTO pass (Pass-1).
    lost: bool,
}

/// One reliable segment retired by [`Stream::on_sack`] — a segment whose
/// sequence a received SACK covered and which has now been removed from the
/// send buffer.
#[derive(Debug, Clone, Copy)]
pub struct RetiredSegment {
    /// When the segment was last (re)transmitted, if it had been sent at all.
    /// `None` means the segment was acknowledged before `poll_send` ever stamped
    /// it (e.g. a duplicate cumulative SACK) — no RTT sample is taken.
    pub sent_at: Option<tokio::time::Instant>,
    /// On-wire payload size of the segment.
    pub size: u64,
    /// True if the segment had been retransmitted at least once (`retries > 0`).
    /// Per Karn's algorithm, the caller must NOT sample RTT from such a segment.
    pub was_retransmit: bool,
}

/// One segment newly declared lost by [`Stream::on_sack`]'s RFC-9002 loss
/// detector (L1-B) — still buffered, now flagged for fast-retransmit.
#[derive(Debug, Clone, Copy)]
pub struct LostSegment {
    /// Gap-free reliable offset of the lost segment.
    pub stream_offset: SequenceNumber,
    /// On-wire payload size — the caller reports it to congestion control via
    /// `Session::on_packet_lost`.
    pub size: u64,
}

/// Outcome of processing a received SACK against the send buffer.
#[derive(Debug, Default)]
pub struct SackResult {
    /// The segments newly retired by this SACK (were in the send buffer, now
    /// removed). The caller feeds each into congestion control / the RTT
    /// estimator. Empty if the SACK acknowledged nothing still buffered (e.g. a
    /// duplicate or stale ACK).
    pub retired: Vec<RetiredSegment>,
    /// Segments newly declared lost (packet- or time-threshold, RFC 9002) by this
    /// SACK — still buffered, now flagged for Pass-0 fast-retransmit. The caller
    /// feeds each into `Session::on_packet_lost` (the real BBR loss signal).
    pub lost: Vec<LostSegment>,
}

impl SackResult {
    /// The gap-free offsets of the segments newly declared lost, ascending.
    pub fn lost_offsets(&self) -> Vec<SequenceNumber> {
        self.lost.iter().map(|l| l.stream_offset).collect()
    }
}

/// One segment handed back by [`Stream::poll_send`] for transmission.
#[derive(Debug, Clone)]
pub struct OutboundSegment {
    /// Wire `header.sequence` of the segment (AEAD nonce / replay id).
    pub seq: SequenceNumber,
    /// Gap-free per-stream reliable-data offset (A.5). The send path prepends it
    /// (big-endian u32) to the AEAD plaintext of a reliable segment so the
    /// receiver reassembles in send order regardless of `seq` holes. Meaningless
    /// for unreliable segments (the send path does not prefix those).
    pub stream_offset: SequenceNumber,
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
    /// Send sequence number — the wire `header.sequence` counter, shared with
    /// control frames (`next_send_sequence`), so it is NOT gap-free.
    send_sequence: AtomicU32,
    /// Gap-free per-stream reliable-data offset counter (A.5). Only reliable data
    /// consumes it, so it has no control-frame holes; it is the reassembly / SACK
    /// key carried in the reliable-data AEAD plaintext.
    reliable_offset: AtomicU32,
    /// Next expected receive **stream offset** (gap-free reassembly cursor, A.5).
    recv_sequence: AtomicU32,
    /// Send buffer (data waiting to be sent)
    send_buffer: Mutex<VecDeque<PendingData>>,
    /// Unreliable send buffer (fire and forget)
    unreliable_buffer: Mutex<VecDeque<(SequenceNumber, Bytes)>>,
    /// Receive buffer (out-of-order data). Each entry is one cursor position
    /// `(sequence, payloads)`; `payloads` is normally a single reliable frame but
    /// carries a COALESCED bundle's sub-payloads when several share one sequence.
    recv_buffer: Mutex<VecDeque<(SequenceNumber, Vec<Bytes>)>>,
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
    /// Receive instant of the most recent reliable data packet, used to populate
    /// the SACK's `ack_delay_us` (`now − recv_at`). A plain sync mutex; the guard
    /// is never held across an `.await`.
    last_data_recv_at: std::sync::Mutex<Option<tokio::time::Instant>>,
}

impl Stream {
    /// Create a new stream
    pub fn new(id: StreamId) -> Self {
        Self {
            id,
            state: Mutex::new(StreamState::Open),
            send_sequence: AtomicU32::new(0),
            reliable_offset: AtomicU32::new(0),
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
            last_data_recv_at: std::sync::Mutex::new(None),
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

    /// Smoothed RTT estimate, or `None` before the first measurement. Feeds the
    /// RFC-9002 time-threshold loss detector (L1-B).
    fn smoothed_rtt(&self) -> Option<Duration> {
        match self.rto.lock() {
            Ok(g) => g.srtt,
            Err(poisoned) => poisoned.into_inner().srtt,
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
        // Gap-free reliable-data offset (distinct from the shared wire sequence).
        let stream_offset = self.reliable_offset.fetch_add(1, Ordering::SeqCst);

        let pending = PendingData {
            sequence: seq,
            stream_offset,
            data,
            sent_at: None,
            retries: 0,
            lost: false,
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
                // Unreliable segments are not reassembled; offset is unused (the
                // send path does not prefix it). Mirror `seq` for a sane value.
                stream_offset: seq,
                data,
                reliable: false,
                retransmit: false,
            });
        }

        let mut buffer = self.send_buffer.lock().await;
        let now = tokio::time::Instant::now();
        // Adaptive RFC 6298 timeout (was a fixed 500ms).
        let timeout = self.current_rto();

        // Pass 0: fast-retransmit a segment the SACK loss detector flagged (RFC
        // 9002, L1-B). Recovers a loss in ~1 RTT instead of waiting out an RTO.
        // Like Pass 1 it BYPASSES cwnd/window (loss recovery must always proceed —
        // the flow-control invariant), but it does NOT back the RTO off (this was a
        // SACK-detected loss, not a timeout). Clears the flag and marks the segment
        // retransmitted (ambiguous for RTT — Karn).
        for pending in buffer.iter_mut() {
            if pending.lost && pending.sent_at.is_some() {
                pending.lost = false;
                pending.sent_at = Some(now);
                pending.retries += 1;
                return Some(OutboundSegment {
                    seq: pending.sequence,
                    stream_offset: pending.stream_offset,
                    data: pending.data.clone(),
                    reliable: true,
                    retransmit: true,
                });
            }
        }

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
                        stream_offset: pending.stream_offset,
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
                    stream_offset: pending.stream_offset,
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

    // ── SACK (selective acknowledgement) — L1-A / A.5 ──

    /// Build a [`Sack`] describing exactly the reliable-data sequences this stream
    /// currently holds, derived from the **reorder state** (single source of truth):
    /// the contiguous delivered run `[0, recv_sequence-1]` as one range, plus one
    /// range per out-of-order island still buffered in `recv_buffer`. Returns
    /// `None` if nothing has been received yet.
    ///
    /// Because the SACK is derived from what the reorder buffer actually holds, the
    /// receiver never SACKs a sequence it has dropped (the SACK-without-data hazard
    /// of a separate received-set). `ack_delay_us`: the caller's measured value, or
    /// — when `0` — a coarse `now − last_data_recv_at` so the on-wire field is
    /// populated. The range set is capped to [`crate::transport::sack::MAX_SACK_RANGES`]
    /// by [`Sack::from_inclusive_ranges`] so it always decodes at the peer.
    pub async fn received_sack(&self, ack_delay_us: u32) -> Option<Sack> {
        let next = self.recv_sequence.load(Ordering::SeqCst);
        let buf = self.recv_buffer.lock().await;
        if next == 0 && buf.is_empty() {
            return None;
        }
        // Contiguous delivered run first (lowest), then the buffered islands
        // (all strictly above `next`, since `next` itself is the missing hole).
        let mut ranges: Vec<(u32, u32)> = Vec::new();
        if next > 0 {
            ranges.push((0, next - 1));
        }
        let mut islands: Vec<SequenceNumber> = buf.iter().map(|(s, _)| *s).collect();
        drop(buf);
        islands.sort_unstable();
        for s in islands {
            match ranges.last_mut() {
                // Coalesce adjacent / duplicate into the previous ascending range.
                Some(last) if s <= last.1.saturating_add(1) => {
                    if s > last.1 {
                        last.1 = s;
                    }
                }
                _ => ranges.push((s, s)),
            }
        }

        let delay = if ack_delay_us != 0 {
            ack_delay_us
        } else {
            // Coarse fallback: time since the most recent data arrival.
            let recv_at = match self.last_data_recv_at.lock() {
                Ok(g) => *g,
                Err(poisoned) => *poisoned.into_inner(),
            };
            recv_at
                .map(|t| {
                    let micros = tokio::time::Instant::now().duration_since(t).as_micros();
                    u32::try_from(micros).unwrap_or(u32::MAX)
                })
                .unwrap_or(0)
        };
        Sack::from_inclusive_ranges(ranges, delay)
    }

    /// Process a received SACK, retiring **every** buffered reliable segment whose
    /// gap-free `stream_offset` the SACK covers (A.5; the SACK ranges are over
    /// `stream_offset`, not the control-frame-holed wire `sequence`). Returns a
    /// [`SackResult`] listing the newly-retired segments so the caller can feed
    /// congestion control / the RTT estimator per segment.
    ///
    /// RTT is sampled here (Karn's algorithm) only for segments that were never
    /// retransmitted (`retries == 0`); `RetiredSegment::was_retransmit` marks the
    /// rest so the caller does not double-count or use an ambiguous sample.
    ///
    /// This is a cumulative retire: a SACK re-acks every still-buffered offset it
    /// covers, so a lost ACK no longer strands a segment — the next SACK retires
    /// it. **No loss detection / fast-retransmit here** — that is L1-B.
    pub async fn on_sack(&self, sack: &Sack) -> SackResult {
        let mut buffer = self.send_buffer.lock().await;
        let mut retired = Vec::new();
        let mut freed = 0u32;
        let now = tokio::time::Instant::now();

        // Retain only the segments the SACK does NOT cover; collect the rest.
        let mut i = 0;
        while i < buffer.len() {
            // SACK ranges are over the gap-free reliable `stream_offset` (A.5),
            // NOT the wire `sequence` (which has control-frame holes).
            // PANIC-SAFETY: `i < buffer.len()` is the loop guard, so the index is
            // in range; `get` cannot return `None`.
            #[allow(clippy::unwrap_used, clippy::disallowed_methods)]
            let covered = sack.acks(buffer.get(i).unwrap().stream_offset);
            if covered {
                // PANIC-SAFETY: `i` is a valid index (loop guard); `remove`
                // returns `Some` for an in-range index in a VecDeque.
                #[allow(clippy::unwrap_used, clippy::disallowed_methods)]
                let pending = buffer.remove(i).unwrap();
                freed += 1;
                let was_retransmit = pending.retries > 0;
                let size = pending.data.len() as u64;
                if let Some(sent_at) = pending.sent_at {
                    // Karn: only sample RTT from segments never retransmitted.
                    if !was_retransmit {
                        let rtt = now.duration_since(sent_at);
                        self.record_rtt_sample(rtt);
                    }
                }
                retired.push(RetiredSegment {
                    sent_at: pending.sent_at,
                    size,
                    was_retransmit,
                });
                // Do NOT advance `i`: `remove` shifted the next element into `i`.
            } else {
                i += 1;
            }
        }

        // Loss detection (RFC 9002 §6.1.1) over the still-buffered, in-flight
        // segments, keyed on the gap-free `stream_offset`: declare lost any offset
        // at least `PACKET_THRESHOLD` behind `largest_acked` (packet-threshold), or
        // — if an srtt is known — any offset below `largest_acked` aged past
        // srtt·9/8 (RACK time-threshold). Flagged segments are fast-retransmitted
        // by `poll_send`'s Pass-0; already-flagged ones are skipped (no double-count
        // into congestion control).
        let largest_acked = sack.largest_acked;
        // RFC 9002: loss_delay = max(kGranularity, kTimeThreshold · smoothed_rtt).
        // The kGranularity (1 ms) floor is load-bearing: without it a near-zero
        // srtt makes the threshold ~0 and flags freshly-sent segments as "aged",
        // which would over-report loss.
        let time_threshold = self
            .smoothed_rtt()
            .map(|r| std::cmp::max(Duration::from_millis(1), r * 9 / 8));
        let mut lost = Vec::new();
        for pending in buffer.iter_mut() {
            if pending.lost {
                continue;
            }
            let Some(sent_at) = pending.sent_at else {
                continue; // not yet on the wire — nothing to lose
            };
            if pending.stream_offset >= largest_acked {
                continue; // not behind the largest ack — still legitimately in flight
            }
            let packet_lost =
                largest_acked >= pending.stream_offset.saturating_add(PACKET_THRESHOLD);
            let time_lost = time_threshold.is_some_and(|t| now.duration_since(sent_at) >= t);
            if packet_lost || time_lost {
                pending.lost = true;
                lost.push(LostSegment {
                    stream_offset: pending.stream_offset,
                    size: pending.data.len() as u64,
                });
            }
        }
        drop(buffer);

        // Return the buffer permits for every retired segment in one shot.
        if freed > 0 {
            self.send_semaphore.add_permits(freed as usize);
        }

        SackResult { retired, lost }
    }

    // ── Receive-side in-order reassembly (A.5) ──

    /// Accept reliable data payloads carried at `sequence` and return the
    /// contiguous in-order run now deliverable to the application, in ascending
    /// order. The returned `Vec` is empty when this is a future hole (buffered for
    /// later), a duplicate, or refused for capacity.
    ///
    /// `payloads` is normally one element (a single RELIABLE frame); a COALESCED
    /// bundle passes its sub-payloads so the whole bundle occupies one cursor
    /// position. This is the **single source of truth** for receive ordering: the
    /// live data pump routes every reliable app payload through here so the app
    /// sees the reliable stream strictly in `sequence` order even over a
    /// reordering (UDP) path. Out-of-order segments are held in `recv_buffer`
    /// (bounded by `MAX_RECV_REORDER`); the data-arrival instant is stamped for
    /// the SACK `ack_delay_us`.
    pub async fn accept_in_order(
        &self,
        sequence: SequenceNumber,
        payloads: Vec<Bytes>,
    ) -> Vec<Bytes> {
        {
            let mut at = match self.last_data_recv_at.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            *at = Some(tokio::time::Instant::now());
        }

        let expected = self.recv_sequence.load(Ordering::SeqCst);
        if sequence < expected {
            return Vec::new(); // duplicate of already-delivered data
        }

        let mut buf = self.recv_buffer.lock().await;
        if sequence != expected {
            // Future segment: buffer if not already held and within capacity.
            // A refused segment is NOT recorded, so it is not SACKed → the sender
            // retransmits it (no SACK-without-data hazard).
            let already = buf.iter().any(|(s, _)| *s == sequence);
            if !already && buf.len() < MAX_RECV_REORDER {
                buf.push_back((sequence, payloads));
            }
            return Vec::new();
        }

        // In-order: deliver this segment's payloads, then drain any now-contiguous
        // buffered segments.
        let mut out = payloads;
        self.recv_sequence.fetch_add(1, Ordering::SeqCst);
        loop {
            let next = self.recv_sequence.load(Ordering::SeqCst);
            if let Some(pos) = buf.iter().position(|(s, _)| *s == next) {
                // PANIC-SAFETY: `pos` was just returned by `position`, so the
                // index is valid; `recv_buf` is locked, so no concurrent drain.
                #[allow(clippy::unwrap_used, clippy::disallowed_methods)]
                let (_, payloads) = buf.remove(pos).unwrap();
                out.extend(payloads);
                self.recv_sequence.fetch_add(1, Ordering::SeqCst);
            } else {
                break;
            }
        }
        out
    }

    /// Pull-API adapter over [`accept_in_order`](Self::accept_in_order): buffer a
    /// single reliable payload for in-order reassembly and push the released run
    /// into `recv_ready` for [`recv`](Self::recv) / [`try_recv`](Self::try_recv).
    /// (Not used by the live session pump, which consumes the returned run
    /// directly; retained for the pull-style read API.)
    pub async fn on_receive(&self, sequence: SequenceNumber, data: Bytes) {
        let delivered = self.accept_in_order(sequence, vec![data]).await;
        if !delivered.is_empty() {
            let mut ready = self.recv_ready.lock().await;
            for d in delivered {
                ready.push_back(d);
            }
            drop(ready);
            self.recv_notify.notify_waiters();
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

    // ── SACK (selective acknowledgement) — L1-A ──

    /// Stage segments 0..=5 on the send buffer, feed a SACK that covers
    /// {0,1,2,4,5} (gap at 3), and assert it retires exactly those five segments,
    /// leaving only segment 3 buffered. This is the headline L1-A behaviour: a
    /// single SACK retires multiple segments at once, skipping the gap.
    #[tokio::test]
    async fn on_sack_retires_all_covered_segments_skipping_the_gap() {
        let stream = Stream::new(1);
        for i in 0..6u32 {
            let seq = stream.send_reliable(Bytes::from(format!("seg-{i}"))).await;
            assert_eq!(seq, i);
            // Stamp it as in-flight so RTT sampling has a `sent_at`.
            let seg = stream.poll_send(u64::MAX).await.expect("poll");
            assert_eq!(seg.seq, i);
        }
        assert_eq!(stream.pending_send_count().await, 6);

        // SACK covers {0,1,2,4,5} — segment 3 is the gap.
        let sack = Sack::from_received(&[0, 1, 2, 4, 5], 1234).expect("sack");
        assert_eq!(sack.ranges(), &[(4, 5), (0, 2)]);
        let result = stream.on_sack(&sack).await;

        // Five segments retired, none of them retransmissions.
        assert_eq!(result.retired.len(), 5);
        assert!(result.retired.iter().all(|r| !r.was_retransmit));
        assert!(result.retired.iter().all(|r| r.sent_at.is_some()));

        // Only segment 3 remains buffered.
        assert_eq!(stream.pending_send_count().await, 1);
        // Re-acking the retired sequences finds nothing (already removed); seq 3
        // is still ackable.
        for retired_seq in [0u32, 1, 2, 4, 5] {
            assert!(
                stream.ack(retired_seq).await.is_none(),
                "seq {retired_seq} should already be retired by the SACK"
            );
        }
        assert!(
            stream.ack(3).await.is_some(),
            "the gap segment 3 must remain buffered"
        );
    }

    /// A SACK that covers nothing still buffered (stale / duplicate) retires
    /// nothing and leaves the send buffer intact.
    #[tokio::test]
    async fn on_sack_for_unbuffered_sequences_retires_nothing() {
        let stream = Stream::new(1);
        stream.send_reliable(Bytes::from("zero")).await; // seq 0
        let _ = stream.poll_send(u64::MAX).await.expect("poll");

        // SACK only covers high sequences we never sent.
        let sack = Sack::from_received(&[100, 101, 102], 0).expect("sack");
        let result = stream.on_sack(&sack).await;
        assert!(result.retired.is_empty());
        assert_eq!(stream.pending_send_count().await, 1);
    }

    /// A retransmitted segment retired by a SACK is flagged `was_retransmit`, so
    /// the caller does not sample RTT from it (Karn's algorithm).
    #[tokio::test]
    async fn on_sack_flags_retransmits_for_karn() {
        tokio::time::pause();
        let stream = Stream::new(1);
        stream.send_reliable(Bytes::from("payload")).await; // seq 0
        let _ = stream.poll_send(u64::MAX).await.expect("first send");

        // Force a retransmit by crossing the RTO, so retries > 0.
        tokio::time::advance(Duration::from_millis(1100)).await;
        let retx = stream.poll_send(u64::MAX).await.expect("retransmit");
        assert!(retx.retransmit);

        let sack = Sack::from_received(&[0], 0).expect("sack");
        let result = stream.on_sack(&sack).await;
        assert_eq!(result.retired.len(), 1);
        assert!(
            result.retired[0].was_retransmit,
            "a retransmitted segment must be flagged so the caller skips RTT sampling"
        );
    }

    // ── L1-B: loss detection (RFC 9002) + fast-retransmit ──

    /// **L1-B packet-threshold loss + Pass-0 fast-retransmit.** Stage offsets
    /// 0..=5 in flight; a SACK acking only {4,5} declares every still-buffered
    /// offset ≤ largest_acked − PACKET_THRESHOLD(3) = 2 lost (0,1,2), leaving 3
    /// unflagged. `poll_send`'s Pass-0 then fast-retransmits a flagged-lost segment
    /// even with a CLOSED congestion window (cwnd_budget = 0), ahead of new data.
    #[tokio::test]
    async fn on_sack_packet_threshold_marks_lost_and_pass0_fast_retransmits() {
        // Pause time so no segment ages past the 1 ms time-threshold floor — this
        // isolates the PACKET-threshold (the time-threshold has its own test).
        tokio::time::pause();
        let stream = Stream::new(1);
        for _ in 0..6u32 {
            stream.send_reliable(Bytes::from_static(b"x")).await;
            let _ = stream.poll_send(u64::MAX).await.expect("in-flight");
        }
        // SACK acks offsets {4,5}: 0,1,2 are ≤ 5−3 → lost; 3 is within threshold.
        let sack = Sack::from_received(&[4, 5], 0).expect("sack");
        let result = stream.on_sack(&sack).await;
        assert_eq!(
            result.lost_offsets(),
            vec![0, 1, 2],
            "packet-threshold must flag every offset ≤ largest_acked − 3"
        );
        // Pass-0 re-sends a flagged segment even with a closed congestion window.
        let seg = stream
            .poll_send(0)
            .await
            .expect("Pass-0 fast-retransmit must ignore the congestion window");
        assert!(seg.retransmit, "Pass-0 segment is a retransmit");
        assert!(
            [0u32, 1, 2].contains(&seg.stream_offset),
            "a flagged-lost offset is fast-retransmitted (got {})",
            seg.stream_offset
        );
    }

    /// **L1-B time-threshold (RACK) loss.** With an established srtt, a
    /// still-buffered segment older than srtt·9/8 is declared lost once a LATER
    /// segment is acked, even when the packet threshold cannot fire (fewer than 3
    /// newer offsets acked). Offsets 0 and 1 are in flight; a SACK acks only {1}
    /// (largest_acked = 1, so 0 is within the packet threshold) but 0 has aged past
    /// srtt·9/8 → lost by time-threshold.
    #[tokio::test]
    async fn on_sack_time_threshold_marks_aged_segment_lost() {
        tokio::time::pause();
        let stream = Stream::new(1);
        // Establish a small srtt: send offset 0, ack it after ~10 ms.
        stream.send_reliable(Bytes::from_static(b"a")).await; // offset 0
        let _ = stream.poll_send(u64::MAX).await.expect("send 0");
        tokio::time::advance(Duration::from_millis(10)).await;
        let _ = stream
            .on_sack(&Sack::from_received(&[0], 0).expect("sack"))
            .await; // srtt ≈ 10 ms

        // Send offsets 1 and 2; age them well past srtt·9/8 (≈ 11 ms).
        stream.send_reliable(Bytes::from_static(b"b")).await; // offset 1
        stream.send_reliable(Bytes::from_static(b"c")).await; // offset 2
        let _ = stream.poll_send(u64::MAX).await.expect("send 1");
        let _ = stream.poll_send(u64::MAX).await.expect("send 2");
        tokio::time::advance(Duration::from_millis(50)).await;

        // SACK acks only {2} (largest_acked = 2). Offset 1 is within the packet
        // threshold (2 − 1 < 3) but aged past srtt·9/8 → lost by time-threshold.
        let result = stream
            .on_sack(&Sack::from_received(&[2], 0).expect("sack"))
            .await;
        assert_eq!(
            result.lost_offsets(),
            vec![1],
            "an aged unacked segment must be flagged by the time-threshold"
        );
    }

    /// `received_sack` derives ranges from the reorder state with a gap, and
    /// `ack_delay_us` is populated (non-zero) when the receiver holds before
    /// emitting (here, the coarse `now − recv_at` fallback under paused time).
    #[tokio::test]
    async fn received_sack_builds_ranges_with_gap_and_populates_ack_delay() {
        tokio::time::pause();
        let stream = Stream::new(1);
        // Receiver got 0,1,2,4,5 (gap at 3): 0,1,2 deliver in order (recv_sequence
        // → 3), 4 and 5 stay buffered as an island.
        for seq in [0u32, 1, 2, 4, 5] {
            let _ = stream
                .accept_in_order(seq, vec![Bytes::from_static(b"x")])
                .await;
        }
        // Hold briefly so `now − recv_at` is non-zero.
        tokio::time::advance(Duration::from_micros(500)).await;

        let sack = stream
            .received_sack(0)
            .await
            .expect("non-empty received set");
        assert_eq!(sack.largest_acked, 5);
        // Contiguous run (0,2) plus the buffered island (4,5), descending.
        assert_eq!(sack.ranges(), &[(4, 5), (0, 2)]);
        assert!(
            sack.ack_delay_us >= 500,
            "ack_delay_us must be populated from the recv-to-emit hold (got {})",
            sack.ack_delay_us
        );

        // An explicit (non-zero) ack_delay passes through verbatim.
        let sack2 = stream.received_sack(42).await.expect("non-empty");
        assert_eq!(sack2.ack_delay_us, 42);
    }

    /// Nothing received yet yields no SACK.
    #[tokio::test]
    async fn received_sack_empty_returns_none() {
        let stream = Stream::new(1);
        assert!(stream.received_sack(0).await.is_none());
    }

    /// `accept_in_order` delivers the contiguous run and buffers holes: feeding
    /// 0, then 2, then 1 yields `[0]`, `[]` (2 buffered), `[1, 2]` (1 fills the
    /// gap and drains the buffered 2) — strict in-order delivery.
    #[tokio::test]
    async fn accept_in_order_delivers_contiguous_run_and_buffers_holes() {
        let stream = Stream::new(1);
        let d0 = stream
            .accept_in_order(0, vec![Bytes::from_static(b"0")])
            .await;
        assert_eq!(d0, vec![Bytes::from_static(b"0")]);
        let d2 = stream
            .accept_in_order(2, vec![Bytes::from_static(b"2")])
            .await;
        assert!(
            d2.is_empty(),
            "seq 2 is a future hole — buffered, not delivered"
        );
        let d1 = stream
            .accept_in_order(1, vec![Bytes::from_static(b"1")])
            .await;
        assert_eq!(
            d1,
            vec![Bytes::from_static(b"1"), Bytes::from_static(b"2")],
            "filling the gap at 1 must release 1 then the buffered 2, in order"
        );
    }

    /// `accept_in_order` drops duplicates of already-delivered sequences.
    #[tokio::test]
    async fn accept_in_order_drops_duplicates() {
        let stream = Stream::new(1);
        let _ = stream
            .accept_in_order(0, vec![Bytes::from_static(b"0")])
            .await;
        let _ = stream
            .accept_in_order(1, vec![Bytes::from_static(b"1")])
            .await;
        let dup = stream
            .accept_in_order(0, vec![Bytes::from_static(b"0")])
            .await;
        assert!(
            dup.is_empty(),
            "a duplicate of delivered data must release nothing"
        );
    }

    /// A COALESCED bundle's multiple sub-payloads occupy ONE cursor position and
    /// are delivered together, in order, ahead of the next sequence.
    #[tokio::test]
    async fn accept_in_order_delivers_coalesced_bundle_as_one_cursor_position() {
        let stream = Stream::new(1);
        let bundle = vec![
            Bytes::from_static(b"A"),
            Bytes::from_static(b"B"),
            Bytes::from_static(b"C"),
        ];
        let d0 = stream.accept_in_order(0, bundle).await;
        assert_eq!(
            d0,
            vec![
                Bytes::from_static(b"A"),
                Bytes::from_static(b"B"),
                Bytes::from_static(b"C")
            ]
        );
        // The bundle consumed exactly one sequence; the next reliable frame is 1.
        let d1 = stream
            .accept_in_order(1, vec![Bytes::from_static(b"D")])
            .await;
        assert_eq!(d1, vec![Bytes::from_static(b"D")]);
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
