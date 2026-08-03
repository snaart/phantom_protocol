//! Phantom Protocol - Stream Management
//!
//! Independently-flow-controlled, reliability-segmented data channels multiplexed
//! within one session. Each [`Stream`] owns its own send/receive buffers, gap-free
//! reliable offset space (A.5), SACK-driven loss detection (RFC 9002), RFC-6298 RTO
//! estimator, and credit-based flow-control windows. Per-stream sequencing means a
//! stall or loss on one stream does not head-of-line-block any other stream (HoL
//! blocking still applies *within* a stream — reliable data is delivered strictly
//! in send order via `accept_in_order`).

use crate::errors::CoreError;
use crate::transport::sack::Sack;
use crate::transport::types::{SequenceNumber, StreamId};

use bytes::Bytes;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
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

/// Per-stream byte budget for the out-of-order reorder buffer (H-3) **at the initial
/// window**, tied to the flow-control window. A compliant peer keeps in-flight (hence
/// reorderable) data within one advertised window; the [`INITIAL_STREAM_WINDOW`] of headroom
/// absorbs a boundary segment. A future hole that would push the buffered total past the
/// budget is refused (dropped → retransmitted via the "refused segment is not SACKed"
/// contract), so per-stream reorder memory is bounded regardless of the per-entry frame size
/// (~253 KiB UDP / 4 MiB TCP) — the entry cap alone is not, since one entry can dwarf the
/// window.
///
/// Since the advertised window auto-tunes (see [`Stream::advertised_recv_window`]) the live
/// budget is [`Stream::recv_reorder_byte_limit`], which tracks it; this constant is that
/// function's value before any tuning, and [`MAX_RECV_REORDER_BYTES_CEILING`] is its maximum.
pub const MAX_RECV_REORDER_BYTES: usize = 2 * INITIAL_STREAM_WINDOW as usize;

/// Absolute per-stream ceiling on reorder-buffer bytes, reached only by a stream whose
/// advertised window has auto-tuned all the way to [`MAX_RECV_WINDOW`].
pub const MAX_RECV_REORDER_BYTES_CEILING: usize =
    MAX_RECV_WINDOW as usize + INITIAL_STREAM_WINDOW as usize;

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
/// more outstanding credit than its own advertised window, itself capped at
/// [`MAX_RECV_WINDOW`] — the same value — so the cap is only a misbehaving-peer
/// guard (the receiver's own delivery HARD_CAP is the real bound on buffering).
pub const MAX_SEND_WINDOW: u32 = 8 * INITIAL_STREAM_WINDOW;

/// Ceiling on the **receiver's** auto-tuned advertised window (see
/// [`Stream::advertised_recv_window`]). Deliberately equal to [`MAX_SEND_WINDOW`]: the two
/// ends of the same credit ledger must agree, or a receiver would grant credit its peer
/// silently discards. 512 KiB carries ~21 Mbit/s on a 200 ms path, which is above the
/// measured capacity of the paths this transport targets.
pub const MAX_RECV_WINDOW: u32 = MAX_SEND_WINDOW;

/// RTT reference used by receive-window auto-tuning when the stream has no RTT sample of
/// its own. A stream that only *receives* never puts a reliable segment on the wire, so its
/// RFC-6298 estimator is never fed — and a pure download is precisely the case auto-tuning
/// exists for. [`RtoEstimator::MIN_RTO`] is the transport's own "no measurement yet" floor,
/// so reusing it keeps one answer to "how long is a round trip when we have not measured
/// one". Erring high here would make growth *easier*, so the floor is the safe direction.
const AUTOTUNE_RTT_FALLBACK: Duration = RtoEstimator::MIN_RTO;

/// Shortest measurement interval auto-tuning will draw a conclusion from. Below this the
/// interval is dominated by scheduler jitter rather than by the application, and a rate
/// computed over it is not evidence of anything.
const AUTOTUNE_MIN_INTERVAL: Duration = Duration::from_millis(10);

/// One measurement interval of the receive-window auto-tuner: how many bytes the
/// application consumed since `started_at`.
#[derive(Debug, Default)]
struct RecvWindowProbe {
    /// Start of the open interval. `None` until the application consumes its first byte —
    /// a stream nobody reads from never opens an interval and so never grows.
    started_at: Option<tokio::time::Instant>,
    /// Bytes the application has consumed since `started_at`.
    bytes: u64,
}

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
    /// Gap-free per-stream reliable-data offset — the reassembly / SACK / loss-
    /// detection key (A.5). Carried in the AEAD plaintext so the receiver can
    /// deliver reliable data strictly in send order even when `sequence` has
    /// control-frame holes. Stable across retransmits.
    stream_offset: SequenceNumber,
    data: Bytes,
    sent_at: Option<tokio::time::Instant>,
    /// The connection's `delivered_bytes` counter at the moment this segment
    /// was **first** put on the wire. BBR's delivery-rate sample is the bytes
    /// delivered *between* that instant and the acknowledgement, so without
    /// this the rate degenerates to one packet per round trip.
    ///
    /// Deliberately not moved by a retransmission, unlike `sent_at`. Nothing in
    /// an acknowledgement says which copy of a resent segment it answers, and
    /// the common case is that it answers the original: the ack was already on
    /// the path when the copy went out. Restamping then divides everything the
    /// connection delivered during that round trip by the time since the resend
    /// — microseconds — and hands a maximum filter a rate no interval of the
    /// connection ever sustained. Anchoring on the original send can only
    /// under-state the instantaneous rate, and a maximum filter ignores a low
    /// sample.
    delivered_at_send: u64,
    /// When the counter above was last at that value — the near end of the
    /// interval the acknowledgement will measure. `None` until `poll_send`
    /// stamps the segment on its first transmission; from then on it is pinned
    /// alongside `delivered_at_send`.
    delivered_time_at_send: Option<std::time::Instant>,
    #[allow(dead_code)]
    retries: u32,
    /// Flagged lost by the SACK-driven loss detector (RFC 9002 packet- or
    /// time-threshold, L1-B). `poll_send`'s Pass-0 fast-retransmits it ahead of
    /// cwnd/window, then clears the flag. Distinct from the RTO pass (Pass-1).
    lost: bool,
    /// True when this is the reliable FIN sentinel (zero-length data, marks
    /// end-of-stream). The drain path ORs `PacketFlags::FIN` into the wire frame
    /// flags when it sees this segment. Stays in the send buffer until SACKed so
    /// the FIN is retransmitted like any reliable segment.
    fin: bool,
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
    /// The connection's delivered-bytes counter when this segment was **first**
    /// sent — retransmission does not move it. Feeds
    /// `DeliverySample::delivered_bytes`.
    pub delivered_at_send: u64,
    /// When that counter last advanced, as of this segment's first send. Feeds
    /// `DeliverySample::delivered_at`. `Some` whenever `sent_at` is — the pair
    /// is stamped by the same `poll_send` pass that first put the segment on
    /// the wire.
    pub delivered_time_at_send: Option<std::time::Instant>,
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
    /// Gap-free per-stream reliable-data offset (A.5). The send path prepends it
    /// (big-endian u32) to the AEAD plaintext of a reliable segment so the
    /// receiver reassembles in send order regardless of control-frame holes.
    /// Meaningless for unreliable segments (the send path does not prefix those).
    pub stream_offset: SequenceNumber,
    /// Payload bytes.
    pub data: Bytes,
    /// Whether the segment is on the reliable (ACK-tracked) path.
    pub reliable: bool,
    /// True when this is a retransmission (the RTO expired) rather than a first
    /// transmission — the caller reports it to congestion control as a loss.
    pub retransmit: bool,
    /// True when this segment is the reliable FIN sentinel (zero-length data).
    /// The drain path must OR `PacketFlags::FIN` into the wire frame flags.
    pub fin: bool,
}

/// Why [`Stream::poll_send`] handed nothing back.
///
/// The three answers are not interchangeable, and collapsing them into a bare
/// `None` cost the congestion controller the one signal it cannot derive for
/// itself. `Idle` and `FlowControl` both mean the sender was *not* held back by
/// its own congestion window — in the first case because the application had
/// nothing more to give, in the second because the peer's receive window is
/// closed — so a round that ends either way says nothing about where the path's
/// knee is. `CongestionWindow` is the opposite: it is the controller enforcing
/// its own decision about how much may be outstanding, and a round that ends
/// there is exactly the kind a loss response exists to judge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendBlocked {
    /// Nothing buffered: every segment has been sent and none is due for
    /// retransmission.
    Idle,
    /// The head unsent segment is larger than the congestion budget offered.
    CongestionWindow,
    /// The peer's advertised flow-control window has no room for the head
    /// unsent segment. Clears on a `WINDOW_UPDATE`, not on an acknowledgement.
    FlowControl,
}

/// RFC 6298 retransmission-timeout estimator (per stream). Replaces a fixed
/// retransmit timer with one that tracks measured RTT (SRTT / RTTVAR) and backs
/// off exponentially on consecutive timeouts.
#[derive(Debug)]
struct RtoEstimator {
    /// Smoothed RTT; `None` until the first measurement.
    srtt: Option<Duration>,
    /// Smallest RTT ever sampled on this stream — the path's propagation delay, with
    /// whatever queue happened to be standing at the time excluded. `None` until the first
    /// measurement. The RTO does not use it (RFC 6298 is a smoothed estimator by design);
    /// receive-window auto-tuning does, because sizing a buffer from an RTT that the buffer
    /// itself inflated is a feedback loop that ends at the cap.
    min_rtt: Option<Duration>,
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
            min_rtt: None,
            rttvar: Duration::ZERO,
            backoff_shift: 0,
        }
    }

    /// Feed a fresh (non-retransmitted, per Karn) RTT measurement.
    fn on_rtt_sample(&mut self, r: Duration) {
        self.min_rtt = Some(match self.min_rtt {
            Some(m) => m.min(r),
            None => r,
        });
        match self.srtt {
            None => {
                // RFC 6298 (2.2): first measurement.
                self.srtt = Some(r);
                self.rttvar = r / 2;
            }
            Some(srtt) => {
                // RFC 6298 (2.3): RTTVAR = (1-1/4)·RTTVAR + 1/4·|SRTT-R|;
                //                 SRTT  = (1-1/8)·SRTT  + 1/8·R.
                let diff = srtt.abs_diff(r);
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

    /// Reset to the initial state (Phase 4 / QUIC §9.4): a migration path switch
    /// lands on a different network, so the old RTT estimate must not carry over.
    /// Wired by the P4.2 migration switch (`Stream::reset_rto`).
    fn reset(&mut self) {
        self.srtt = None;
        self.min_rtt = None;
        self.rttvar = Duration::ZERO;
        self.backoff_shift = 0;
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

    #[test]
    fn reset_clears_estimate_and_backoff() {
        let mut est = RtoEstimator::new();
        // Build up an SRTT and a backed-off RTO.
        est.on_rtt_sample(Duration::from_millis(100)); // RTO = 300ms
        est.on_timeout(); // RTO = 600ms (backed off)
        assert_eq!(est.rto(), Duration::from_millis(600));
        // Phase 4 / QUIC §9.4: a migration path switch must reset the estimate so
        // the new network's RTT is measured fresh (no stale tiny RTO => no
        // spurious-retransmit storm on the first packets of the new path).
        est.reset();
        assert_eq!(est.rto(), Duration::from_secs(1)); // INITIAL_RTO, no backoff
    }
}

/// Stream - multiplexed data channel within a session
pub struct Stream {
    /// Stream identifier
    id: StreamId,
    /// Current state
    state: Mutex<StreamState>,
    /// Gap-free per-stream reliable-data offset counter (A.5). Only reliable data
    /// consumes it, so it has no control-frame holes; it is the reassembly / SACK
    /// key carried in the reliable-data AEAD plaintext.
    reliable_offset: AtomicU32,
    /// Next expected receive **stream offset** (gap-free reassembly cursor, A.5).
    recv_sequence: AtomicU32,
    /// Send buffer (data waiting to be sent)
    send_buffer: Mutex<VecDeque<PendingData>>,
    /// Unreliable send buffer (fire and forget)
    unreliable_buffer: Mutex<VecDeque<Bytes>>,
    /// Receive buffer (out-of-order data). Each entry is one cursor position
    /// `(sequence, payloads)`; `payloads` is normally a single reliable frame but
    /// carries a COALESCED bundle's sub-payloads when several share one sequence.
    recv_buffer: Mutex<VecDeque<(SequenceNumber, Vec<Bytes>)>>,
    /// Total payload bytes currently held in `recv_buffer` (H-3). Mutated only under the
    /// `recv_buffer` lock (in `accept_in_order`), so it stays exactly in step with the
    /// buffer; an `AtomicUsize` only so it can be read lock-free for stats/tests. Bounds the
    /// out-of-order reorder buffer by *bytes*, not entries, since one entry can be ~253 KiB
    /// (UDP) / 4 MiB (TCP).
    recv_buffer_bytes: AtomicUsize,
    /// Ordered receive queue (ready for application)
    recv_ready: Mutex<VecDeque<Bytes>>,
    /// Notify when data is ready to read
    recv_notify: Notify,
    /// Whether stream is finished locally
    local_finished: AtomicBool,
    /// Whether stream is finished remotely
    remote_finished: AtomicBool,
    /// The peer's FIN reliable offset once seen (`u32::MAX` = none). The per-stream
    /// Close (EOF) is emitted only once the reorder buffer releases this offset
    /// in order (see [`Stream::take_in_order_fin`]), so a FIN that arrives over a
    /// gap never delivers EOF ahead of the gap-filling data.
    remote_fin_offset: AtomicU32,
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
    /// The window this side is currently *advertising*: how many bytes the peer may hold
    /// unacknowledged-by-the-application at once. Auto-tuned upward by
    /// [`Stream::tune_recv_window`] and never above [`MAX_RECV_WINDOW`].
    advertised_recv_window: AtomicU32,
    /// Measurement interval backing the auto-tuner. A plain sync mutex — taken only by the
    /// single delivery task that credits this stream, and never held across an `.await`.
    recv_window_probe: std::sync::Mutex<RecvWindowProbe>,
    /// Total bytes the local side has consumed since the last
    /// emitted `WINDOW_UPDATE`. Used to decide when to send the
    /// next update (avoid flooding the wire with tiny updates).
    bytes_since_last_update: AtomicU32,
    /// Pending **relative** flow-control credit to advertise in a
    /// `WINDOW_UPDATE`, staged by the receive **delivery** task (which credits
    /// the window on *real* app consumption) and flushed by the **send loop** —
    /// the sole *outbound* writer, so the encrypted control frame is sealed by the
    /// same task that stamps every data packet, under the epoch live at flush
    /// time. (The epoch itself has TWO writers — the send loop's own `rekey()` and
    /// the receive task's authenticated forward catch-up in
    /// `decrypt_packet_accepting_rekey` — but both serialise through the session's
    /// `rekey_lock`, so the send loop always seals under a consistent key.)
    /// Credits accumulate additively, so several grants between two flushes are
    /// never lost. `0` = nothing pending.
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
            reliable_offset: AtomicU32::new(0),
            recv_sequence: AtomicU32::new(0),
            send_buffer: Mutex::new(VecDeque::new()),
            unreliable_buffer: Mutex::new(VecDeque::new()),
            recv_buffer: Mutex::new(VecDeque::new()),
            recv_buffer_bytes: AtomicUsize::new(0),
            recv_ready: Mutex::new(VecDeque::new()),
            recv_notify: Notify::new(),
            local_finished: AtomicBool::new(false),
            remote_finished: AtomicBool::new(false),
            remote_fin_offset: AtomicU32::new(u32::MAX),
            priority: AtomicU32::new(0),
            send_semaphore: Arc::new(Semaphore::new(MAX_PENDING_PACKETS)),
            peer_send_window: AtomicU32::new(INITIAL_STREAM_WINDOW),
            local_recv_window: AtomicU32::new(INITIAL_STREAM_WINDOW),
            advertised_recv_window: AtomicU32::new(INITIAL_STREAM_WINDOW),
            recv_window_probe: std::sync::Mutex::new(RecvWindowProbe::default()),
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

    /// Reset the RTT estimator (Phase 4 / QUIC §9.4): a migration path switch lands
    /// on a different network, so the old RTT must not carry over. A poisoned lock
    /// is recovered by taking the inner value — the RTO is a heuristic.
    pub fn reset_rto(&self) {
        match self.rto.lock() {
            Ok(mut g) => g.reset(),
            Err(poisoned) => poisoned.into_inner().reset(),
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

    /// Smallest RTT sampled on this stream, or `None` before the first measurement — the
    /// path's propagation delay rather than the queue-inflated smoothed estimate. Feeds
    /// receive-window auto-tuning; see [`Self::tune_recv_window`].
    fn min_rtt(&self) -> Option<Duration> {
        match self.rto.lock() {
            Ok(g) => g.min_rtt,
            Err(poisoned) => poisoned.into_inner().min_rtt,
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

    /// The window this side currently advertises: the most bytes the peer may hold in our
    /// buffers before it must stop and wait for the application to consume. Starts at
    /// [`INITIAL_STREAM_WINDOW`] and is auto-tuned upward by [`Self::tune_recv_window`],
    /// never past [`MAX_RECV_WINDOW`].
    pub fn advertised_recv_window(&self) -> u32 {
        self.advertised_recv_window.load(Ordering::Acquire)
    }

    /// Live per-stream reorder-buffer byte budget (H-3). Tracks the advertised window,
    /// because that window is what bounds in-flight — hence reorderable — data: a fixed
    /// budget smaller than the window would refuse legitimate out-of-order segments on a
    /// lossy path and force them to be retransmitted, collapsing throughput exactly where
    /// a large window is most needed. Equals [`MAX_RECV_REORDER_BYTES`] before any tuning
    /// and [`MAX_RECV_REORDER_BYTES_CEILING`] at [`MAX_RECV_WINDOW`].
    pub fn recv_reorder_byte_limit(&self) -> usize {
        self.advertised_recv_window() as usize + INITIAL_STREAM_WINDOW as usize
    }

    /// Receive-window auto-tuning. Returns the **extra** relative credit to hand the peer
    /// because the advertised window just grew (`0` when it did not).
    ///
    /// ## Why the window has to move at all
    ///
    /// A credit window of `W` bytes returned one round trip after the data was consumed is
    /// a hard rate ceiling of `W / RTT`, whatever congestion control decides. A fixed 64 KiB
    /// window on a 200 ms path is 2.6 Mbit/s per stream — below the capacity of any path
    /// worth measuring — so on a long path flow control, not the network, is the limiter.
    /// TCP window auto-tuning and QUIC flow-control auto-tuning both exist for this reason,
    /// and this is the same mechanism: notice that the window is the binding constraint and
    /// double it.
    ///
    /// ## What the growth is tied to
    ///
    /// **Application consumption, never arrival.** `n` reaches this function only from the
    /// delivery task, which counts bytes it has handed onward to the application, and the
    /// interval is opened by the first such byte. A peer that sends fast to an application
    /// that never reads calls this function zero times and moves nothing. That is the whole
    /// memory-safety argument, and it is why the trigger may not be moved to the receive
    /// path, where "bytes arrived" is entirely the peer's choice.
    ///
    /// The rule: over a closed interval of `2 × RTT`, if the application consumed more than
    /// **four fifths of a window** — a rate above `0.4 × window / RTT` — the window is close
    /// enough to binding to double it. Equivalently the window converges on
    /// `2.5 × (application consumption rate) × RTT`, two and a half bandwidth-delay products,
    /// and stops there: the advertised window is a measurement of the application, clamped to
    /// [`MAX_RECV_WINDOW`]. The neighbourhood of two BDPs is the target Linux receive-window
    /// auto-tuning aims at too, and it is deliberately not far above it — the point is to
    /// stop being the binding constraint, not to hand out buffer nobody needs.
    ///
    /// Why `0.4` and not the round `0.5`: credit is returned a round trip *after* the
    /// application consumed, so a flow that really is window-limited does not achieve
    /// `window / RTT` — it achieves about half of that, which is exactly what the measurement
    /// that prompted this work showed (1.2 Mbit/s against a 2.62 Mbit/s window ceiling, 46%).
    /// A threshold sitting on that same figure would never fire on the flow it exists for.
    ///
    /// Measuring over a *time* interval rather than a byte count is deliberate. The delivery
    /// pipeline in front of the application is a bounded queue, so a stalled reader still
    /// absorbs one queue's worth of bytes in a burst; a byte-triggered test would read that
    /// one-off burst as a sustained rate and climb the whole ladder on it. An interval no
    /// shorter than a round trip cannot be satisfied by a transient.
    ///
    /// ## What a hostile but authenticated peer gets
    ///
    /// Nothing it does not have to buy. Moving this stream's window from 64 KiB to the
    /// 512 KiB cap costs it three doublings, and each one requires the local application to
    /// consume four fifths of the *current* window inside one round-trip-length interval —
    /// ~360 KiB of genuinely consumed data in total, at a rate the peer cannot supply on its
    /// own because the application has to keep up with it. If the application stops, the
    /// window stops where it is.
    ///
    /// Having paid, the peer may hold 512 KiB of unconsumed data on this stream and up to
    /// 576 KiB of reorder buffer ([`Self::recv_reorder_byte_limit`]), against 64 KiB and
    /// 128 KiB before. Session-wide, the number that bounds buffered-but-undelivered bytes
    /// is unchanged: the pump's `RECV_DELIVERY_HARD_CAP` still tears the session down at
    /// 4 MiB of backlog. What auto-tuning changes is how few streams it takes to reach that
    /// cap when an application stalls after running fast — eight rather than sixty-four —
    /// and the per-stream reorder ceiling, whose `MAX_STREAMS`-wide worst case rises from
    /// 32 MiB to 144 MiB, reachable only by an attacker who has already induced 256 separate
    /// applications' worth of sustained consumption.
    fn tune_recv_window(&self, n: u32) -> u32 {
        let window = self.advertised_recv_window.load(Ordering::Acquire);
        if window >= MAX_RECV_WINDOW {
            return 0;
        }
        // The path's propagation delay, NOT the smoothed estimate: a saturated forward
        // path inflates smoothed RTT, a longer RTT lowers the rate a window has to beat to
        // grow, and a bigger window queues more — a loop that ends at the cap regardless of
        // what the application is doing. `min_rtt` is what the queue cannot move. A stream
        // that only receives never feeds its own estimator at all, so the fallback is the
        // common case on exactly the flows auto-tuning exists for.
        let rtt = self.min_rtt().unwrap_or(AUTOTUNE_RTT_FALLBACK);
        let interval = rtt.saturating_mul(2).max(AUTOTUNE_MIN_INTERVAL);

        let now = tokio::time::Instant::now();
        let mut probe = match self.recv_window_probe.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        probe.bytes = probe.bytes.saturating_add(u64::from(n));
        let Some(started_at) = probe.started_at else {
            // First consumption on this stream opens the interval; there is no elapsed
            // time yet to draw a rate from.
            probe.started_at = Some(now);
            return 0;
        };
        let elapsed = now.duration_since(started_at);
        if elapsed < interval {
            return 0; // interval still open — keep accumulating
        }
        let bytes = probe.bytes;
        probe.bytes = 0;
        probe.started_at = Some(now);
        drop(probe);

        // `bytes / elapsed > (4/5) * window / interval` (recall `interval == 2 × RTT`),
        // cross-multiplied so there is no division and no float. u128 because
        // `window * elapsed_ns` overflows u64 for a 512 KiB window past ~35 s, and a long
        // idle interval is ordinary.
        let lhs = u128::from(bytes)
            .saturating_mul(5)
            .saturating_mul(interval.as_nanos());
        let rhs = u128::from(window)
            .saturating_mul(4)
            .saturating_mul(elapsed.as_nanos());
        if lhs <= rhs {
            return 0; // the application is not keeping up with the window we already gave it
        }

        let next = window.saturating_mul(2).min(MAX_RECV_WINDOW);
        match self.advertised_recv_window.compare_exchange(
            window,
            next,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => next - window,
            // Lost a race with a concurrent grower: its increase stands, ours is dropped
            // rather than compounded.
            Err(_) => 0,
        }
    }

    /// Record that the application has actually consumed `n` bytes from this
    /// stream (called by the receive *delivery* task on real drainage, not
    /// on routing). Accumulates the consumed bytes and, once the unreported
    /// total crosses half the initial window, returns `Some(credit)` — the
    /// **relative credit** to advertise in a `WINDOW_UPDATE` (the peer *adds*
    /// it to its send window). The half-window threshold trades update frequency
    /// against peer stalls.
    ///
    /// The credit also carries any growth [`Self::tune_recv_window`] just decided. Because
    /// `WINDOW_UPDATE` is relative, opening the window wider is simply extra credit — the
    /// wire format expresses it as it stands, and a window increase needs no new frame.
    /// Growth is emitted immediately even when the consumption credit is still below the
    /// update threshold: it is precisely the case where the peer is stalled waiting.
    pub fn record_app_consumed(&self, n: u32) -> Option<u32> {
        let growth = self.tune_recv_window(n);
        let pending = self.bytes_since_last_update.fetch_add(n, Ordering::AcqRel) + n;
        let threshold = INITIAL_STREAM_WINDOW / 2;
        let consumed_credit = if pending >= threshold {
            // Grant exactly the bytes we accumulated since the last update and
            // reset the accumulator. Use a CAS-free `fetch_sub` of the granted
            // amount rather than `store(0)` so a concurrent consume isn't lost.
            self.bytes_since_last_update
                .fetch_sub(pending, Ordering::AcqRel);
            pending
        } else {
            0
        };
        let credit = consumed_credit.saturating_add(growth);
        if credit == 0 {
            return None;
        }
        // Keep the (now informational) local_recv_window in step for stats.
        self.local_recv_window.fetch_add(credit, Ordering::AcqRel);
        Some(credit)
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

    /// Assign the next gap-free reliable `stream_offset`, failing closed at `u32`
    /// exhaustion (T4.5). The cursor (`reliable_offset`) holds the
    /// next-to-assign value; the last assignable offset is `u32::MAX - 1` (assigning
    /// it advances the cursor to the `u32::MAX` exhaustion sentinel). A plain
    /// `fetch_add(1)` would wrap `u32::MAX` back to `0`, re-issuing offset `0` and
    /// corrupting reassembly / SACK dedup (a duplicate offset — NOT an AEAD nonce
    /// reuse, since the nonce is the `u64` packet number). Instead we fail closed,
    /// mirroring the epoch-saturation guard in [`Session::rekey`]. The CAS loop keeps
    /// the "never wrap" invariant correct even under a (rare) concurrent caller.
    fn next_reliable_offset(&self) -> Result<SequenceNumber, CoreError> {
        loop {
            let cur = self.reliable_offset.load(Ordering::SeqCst);
            let next = cur.checked_add(1).ok_or_else(|| {
                CoreError::StreamError(
                    "reliable stream offset space exhausted (u32); reconnect required".into(),
                )
            })?;
            if self
                .reliable_offset
                .compare_exchange(cur, next, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                return Ok(cur);
            }
        }
    }

    /// Queue data for sending with reliability.
    ///
    /// Returns the gap-free `stream_offset` assigned to this chunk (the reassembly
    /// / SACK key). The wire packet number is assigned later, at send time, by the
    /// data pump (WIRE v3). Fails closed with [`CoreError::StreamError`] once the
    /// `u32` offset space is exhausted (T4.5) — the acquired backpressure permit is
    /// released on that path so the semaphore accounting stays correct.
    pub async fn send_reliable(&self, data: Bytes) -> Result<SequenceNumber, CoreError> {
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

        // Gap-free reliable-data offset (A.5) — the reassembly / SACK key. Assigned
        // BEFORE forgetting the permit so a fail-closed exhaustion (`?`) drops the
        // permit and releases the slot instead of leaking backpressure capacity.
        let stream_offset = self.next_reliable_offset()?;
        permit.forget();

        let pending = PendingData {
            stream_offset,
            data,
            sent_at: None,
            delivered_at_send: 0,
            delivered_time_at_send: None,
            retries: 0,
            lost: false,
            fin: false,
        };

        self.send_buffer.lock().await.push_back(pending);

        Ok(stream_offset)
    }

    /// Non-blocking twin of [`send_reliable`](Self::send_reliable).
    ///
    /// Returns `Ok(true)` when `data` was admitted into the send buffer and
    /// `Ok(false)` when the buffer is full — the caller keeps ownership and
    /// re-offers the same chunk later, so ordering is preserved. `Err` is the
    /// same fail-closed offset exhaustion `send_reliable` reports.
    ///
    /// This exists because the data pump admits application writes from inside
    /// its `select!` loop. `send_reliable` parks on the backpressure semaphore
    /// until an acknowledgement frees a slot, and a parked pump is a pump that
    /// has stopped emitting the *receive* side's flow-control credit and
    /// stopped draining its command channel — so a saturating send in one
    /// direction silently strangles the other. Refusing the write and letting
    /// the pump loop keep turning replaces that with real, visible
    /// backpressure: the pump stops reading commands, so the application's own
    /// `send()` blocks instead of the session's scheduler.
    pub async fn try_send_reliable(&self, data: &Bytes) -> Result<bool, CoreError> {
        let Ok(permit) = self.send_semaphore.try_acquire() else {
            return Ok(false);
        };
        // Offset assigned before the permit is forgotten so a fail-closed
        // exhaustion releases the slot instead of leaking backpressure capacity
        // (same discipline as `send_reliable`).
        let stream_offset = self.next_reliable_offset()?;
        permit.forget();

        self.send_buffer.lock().await.push_back(PendingData {
            stream_offset,
            data: data.clone(),
            sent_at: None,
            delivered_at_send: 0,
            delivered_time_at_send: None,
            retries: 0,
            lost: false,
            fin: false,
        });
        Ok(true)
    }

    /// Non-blocking twin of [`queue_fin`](Self::queue_fin) — see
    /// [`try_send_reliable`](Self::try_send_reliable) for why the pump needs one.
    /// Returns `Ok(false)` when the send buffer is full; the caller re-offers the
    /// FIN later, so it still lands after every byte queued before it.
    pub async fn try_queue_fin(&self) -> Result<bool, CoreError> {
        let Ok(permit) = self.send_semaphore.try_acquire() else {
            return Ok(false);
        };
        let stream_offset = self.next_reliable_offset()?;
        permit.forget();

        self.local_finished.store(true, Ordering::SeqCst);
        self.send_buffer.lock().await.push_back(PendingData {
            stream_offset,
            data: Bytes::new(),
            sent_at: None,
            delivered_at_send: 0,
            delivered_time_at_send: None,
            retries: 0,
            lost: false,
            fin: true,
        });
        Ok(true)
    }

    /// Queue the reliable FIN sentinel for this stream.
    ///
    /// Enqueues a zero-length reliable segment flagged as the FIN. The segment
    /// goes through the same ARQ machinery as any reliable data — it is
    /// retransmitted until SACKed, guaranteeing the peer receives the FIN even
    /// under packet loss. The drain path (`drain_streams_priority_ordered`) ORs
    /// `PacketFlags::FIN` into the wire frame when it sees `seg.fin == true`.
    ///
    /// Simultaneously marks `local_finished = true` so `is_fin_acked()` can detect
    /// when the send buffer is empty (FIN was SACKed) and clean up.
    ///
    /// Calling this more than once on the same stream is a no-op in practice:
    /// the second call also allocates an offset and enqueues another zero-length
    /// segment, which is harmless (the peer SACKs them all). The caller
    /// (`CloseStream` handler in the pump) removes the stream from the table after
    /// calling this once, so no second call is possible via the normal path.
    pub async fn queue_fin(&self) -> Result<(), CoreError> {
        // Acquire backpressure permit — reuses `send_reliable`'s logic.
        // PANIC-SAFETY: identical to the site in `send_reliable` above —
        // `Semaphore::acquire` only errors after `close()`, and `send_semaphore`
        // is a private field constructed in `Stream::new` and never closed
        // anywhere in the crate, so the variant is structurally unreachable.
        #[allow(clippy::expect_used)]
        let permit = self
            .send_semaphore
            .acquire()
            .await
            .expect("Semaphore closed");
        let stream_offset = self.next_reliable_offset()?;
        permit.forget();

        let pending = PendingData {
            stream_offset,
            data: Bytes::new(),
            sent_at: None,
            delivered_at_send: 0,
            delivered_time_at_send: None,
            retries: 0,
            lost: false,
            fin: true,
        };

        // Mark local side finished now so `is_fin_acked()` knows the FIN
        // was queued (not just that the buffer happened to be empty).
        self.local_finished.store(true, Ordering::SeqCst);
        self.send_buffer.lock().await.push_back(pending);
        Ok(())
    }

    /// Returns `true` if the local FIN was queued (via `queue_fin`) AND the
    /// send buffer is empty (the FIN has been SACKed by the peer).
    ///
    /// Used by the data pump's `CloseStream` handler to know when it is safe to
    /// remove the stream from the routing tables — we cannot remove it until the
    /// FIN is gone from the send buffer, or retransmits would fail.
    pub async fn is_fin_acked(&self) -> bool {
        self.local_finished.load(Ordering::SeqCst) && self.send_buffer.lock().await.is_empty()
    }

    /// Record the peer's FIN reliable offset (set-once; idempotent under FIN
    /// retransmits). The Close/EOF is NOT emitted here — see
    /// [`take_in_order_fin`](Self::take_in_order_fin).
    pub fn note_remote_fin(&self, stream_offset: u32) {
        let _ = self.remote_fin_offset.compare_exchange(
            u32::MAX,
            stream_offset,
            Ordering::SeqCst,
            Ordering::SeqCst,
        );
    }

    /// Returns `true` exactly once — when a previously-noted remote FIN has been
    /// released by the reorder buffer **in order** (the in-order receive cursor has
    /// advanced past the FIN's offset, so every preceding data byte was delivered
    /// first). The recv path then emits the per-stream Close (EOF). Call it on every
    /// reliable packet so a late gap-filling segment is what finally surfaces the
    /// EOF — never ahead of the data it was waiting on.
    pub fn take_in_order_fin(&self) -> bool {
        let fin = self.remote_fin_offset.load(Ordering::SeqCst);
        fin != u32::MAX
            && self.recv_sequence.load(Ordering::SeqCst) > fin
            && !self.remote_finished.swap(true, Ordering::SeqCst)
    }

    /// Queue data for unreliable sending. Fire-and-forget; the wire packet number
    /// is assigned at send time by the data pump (WIRE v3).
    pub async fn send_unreliable(&self, data: Bytes) {
        // Unreliable data does not consume buffer permits.
        self.unreliable_buffer.lock().await.push_back(data);
    }

    /// Get the next segment to (re)transmit, or the reason nothing is due.
    ///
    /// The failure side is a [`SendBlocked`] rather than a bare `None` because
    /// the three ways a pass can come up empty are three different statements
    /// about the connection, and only one of them is about congestion. See the
    /// enum.
    ///
    /// `delivered_now` is the connection's current delivered-bytes counter and
    /// `delivered_time_now` is when it last advanced; the pair is stamped onto a
    /// segment's **first** transmission so the acknowledgement can be turned
    /// into a delivery-rate sample over the right interval. The counter alone
    /// fixes only how many bytes the sample covers — the timestamp is what fixes
    /// how long they took, and a burst of acknowledgements is exactly the case
    /// where those two answers diverge. A retransmission leaves both alone (see
    /// Pass 0); only `sent_at` moves, because only the timers care which copy
    /// went out last.
    ///
    /// `cwnd_budget` is how many bytes of *new* data the congestion window
    /// currently permits. Retransmissions ignore it — loss recovery must always
    /// proceed — but a first transmission is withheld when it would exceed the
    /// budget, so the next drain resumes once ACKs free the window. Pass
    /// `u64::MAX` to disable the limit.
    pub async fn poll_send(
        &self,
        cwnd_budget: u64,
        delivered_now: u64,
        delivered_time_now: std::time::Instant,
    ) -> Result<OutboundSegment, SendBlocked> {
        // Unreliable data is fire-and-forget and not congestion-controlled.
        if let Some(data) = self.unreliable_buffer.lock().await.pop_front() {
            return Ok(OutboundSegment {
                // Unreliable segments are not reassembled; offset is unused (the
                // send path does not prefix it).
                stream_offset: 0,
                data,
                reliable: false,
                retransmit: false,
                fin: false,
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
        //
        // `sent_at` moves, the delivery marks do not — see the field docs on
        // `PendingData::delivered_at_send`. The RTO and the RACK time threshold
        // both ask "how long since this segment was last on the wire", so they
        // need the new instant; the delivery-rate sample asks "how much has the
        // connection delivered since these bytes were first entrusted to the
        // path", and moving its origin forward is what let one acknowledgement
        // report a whole window as having arrived in a millisecond.
        for pending in buffer.iter_mut() {
            if pending.lost && pending.sent_at.is_some() {
                pending.lost = false;
                pending.sent_at = Some(now);
                pending.retries += 1;
                return Ok(OutboundSegment {
                    stream_offset: pending.stream_offset,
                    data: pending.data.clone(),
                    reliable: true,
                    retransmit: true,
                    fin: pending.fin,
                });
            }
        }

        // Pass 1: a timed-out segment (retransmission) — always allowed. Same
        // restamping rule as Pass 0: the timer moves, the delivery marks stay
        // with the original transmission.
        for pending in buffer.iter_mut() {
            if let Some(sent_at) = pending.sent_at {
                if now.duration_since(sent_at) >= timeout {
                    pending.sent_at = Some(now);
                    pending.retries += 1;
                    // Back the RTO off exponentially for the next attempt.
                    self.note_rto_timeout();
                    return Ok(OutboundSegment {
                        stream_offset: pending.stream_offset,
                        data: pending.data.clone(),
                        reliable: true,
                        retransmit: true,
                        fin: pending.fin,
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
                    // The controller's own window is the binding constraint —
                    // wait for ACKs to free it.
                    return Err(SendBlocked::CongestionWindow);
                }
                // The reliable FIN sentinel (len == 0) bypasses the
                // flow-control window check — it consumes no peer window.
                // For non-FIN segments, enforce the peer's flow-control window.
                if !pending.fin && !self.try_consume_send_window(len as u32) {
                    // The peer's receive window is the binding constraint —
                    // wait for a WINDOW_UPDATE, not for an acknowledgement.
                    return Err(SendBlocked::FlowControl);
                }
                let is_fin = pending.fin;
                pending.sent_at = Some(now);
                pending.delivered_at_send = delivered_now;
                pending.delivered_time_at_send = Some(delivered_time_now);
                return Ok(OutboundSegment {
                    stream_offset: pending.stream_offset,
                    data: pending.data.clone(),
                    reliable: true,
                    retransmit: false,
                    fin: is_fin,
                });
            }
        }

        Err(SendBlocked::Idle)
    }

    /// Mark a sequence number as acknowledged.
    /// Returns the timestamp when the packet was originally sent and its size, if found.
    pub async fn ack(&self, stream_offset: SequenceNumber) -> Option<(tokio::time::Instant, u64)> {
        let mut buffer = self.send_buffer.lock().await;
        let mut result = None;

        // Find the segment (by gap-free `stream_offset`, A.5) and get its sent_at.
        if let Some(pos) = buffer.iter().position(|p| p.stream_offset == stream_offset) {
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
    pub async fn mark_unsent(&self, stream_offset: SequenceNumber) {
        let mut buffer = self.send_buffer.lock().await;
        if let Some(pending) = buffer.iter_mut().find(|p| p.stream_offset == stream_offset) {
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
                    delivered_at_send: pending.delivered_at_send,
                    delivered_time_at_send: pending.delivered_time_at_send,
                });
                // Do NOT advance `i`: `remove` shifted the next element into `i`.
            } else {
                i += 1;
            }
        }

        // Loss detection (RFC 9002 §6.1.1) over the still-buffered, in-flight
        // segments, keyed on the gap-free `stream_offset`: declare lost any offset
        // at least `PACKET_THRESHOLD` behind `largest_acked` (packet-threshold, and
        // only while nothing has been resent for it — see the predicate), or — if
        // an srtt is known — any offset below `largest_acked` aged past srtt·9/8
        // since its latest transmission (RACK time-threshold). Flagged segments are
        // fast-retransmitted by `poll_send`'s Pass-0; already-flagged ones are
        // skipped (no double-count into congestion control).
        // T5.4: clamp `largest_acked` to the highest `stream_offset` we have actually assigned
        // (`reliable_offset` is the next-to-assign, so it bounds every offset on the wire). A
        // peer cannot legitimately ack an offset we never sent; without this an authenticated
        // peer inflating `largest_acked` (e.g. `high + 1e6`) would declare freshly-sent,
        // in-flight segments "lost" and force a cwnd-bypassing Pass-0 retransmit storm.
        let largest_acked = sack
            .largest_acked
            .min(self.reliable_offset.load(Ordering::SeqCst));
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
            // The packet threshold is a one-shot test, and the predicate has to
            // say so, because nothing else does. `largest_acked` only grows, so
            // once it is three offsets past a segment it stays there for the
            // rest of the connection; and the `lost` flag is not a record of the
            // detection — `poll_send`'s Pass-0 clears it the instant it puts the
            // copy on the wire. With the flag cleared and the comparison
            // permanently true, every subsequent acknowledgement re-declared the
            // same segment lost and Pass-0 emitted another copy of it. On a path
            // that acknowledges each packet with a window of a few hundred
            // segments, that is hundreds of bogus loss reports and hundreds of
            // duplicates per round trip, all for one drop: the round's computed
            // loss rate saturates, the inflight bound sits on its floor, and
            // Pass-0 (which runs ahead of the new-data pass) starves the
            // application for as long as it lasts.
            //
            // `retries` is the record that a copy is already out there. Once one
            // is, the question is no longer "did this segment arrive" — it is
            // "did the copy arrive", and the only evidence that bears on that is
            // time since the copy left. That is the RACK time threshold below,
            // measured from the restamped `sent_at`, and it re-declares the
            // segment once per `srtt·9/8` rather than once per acknowledgement.
            // The RTO pass remains the backstop underneath both.
            let packet_lost = pending.retries == 0
                && largest_acked >= pending.stream_offset.saturating_add(PACKET_THRESHOLD);
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
            // Future segment: buffer if not already held, within the entry cap, AND within
            // the per-stream byte budget (H-3). A refused segment is NOT recorded, so it is
            // not SACKed → the sender retransmits it (no SACK-without-data hazard, bounded
            // memory regardless of per-entry frame size).
            let already = buf.iter().any(|(s, _)| *s == sequence);
            let seg_bytes: usize = payloads.iter().map(Bytes::len).sum();
            let within_byte_budget = self
                .recv_buffer_bytes
                .load(Ordering::Relaxed)
                .saturating_add(seg_bytes)
                <= self.recv_reorder_byte_limit();
            if !already && buf.len() < MAX_RECV_REORDER && within_byte_budget {
                buf.push_back((sequence, payloads));
                self.recv_buffer_bytes
                    .fetch_add(seg_bytes, Ordering::Relaxed);
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
                let seg_bytes: usize = payloads.iter().map(Bytes::len).sum();
                self.recv_buffer_bytes
                    .fetch_sub(seg_bytes, Ordering::Relaxed);
                out.extend(payloads);
                self.recv_sequence.fetch_add(1, Ordering::SeqCst);
            } else {
                break;
            }
        }
        out
    }

    /// Total payload bytes currently held in the out-of-order reorder buffer (H-3). Bounded
    /// by [`Self::recv_reorder_byte_limit`]; exposed so the byte bound is observable/testable.
    pub fn recv_reorder_bytes(&self) -> usize {
        self.recv_buffer_bytes.load(Ordering::Relaxed)
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
            .field("recv_offset", &self.recv_sequence.load(Ordering::Relaxed))
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
        stream.send_reliable(Bytes::from("hello")).await.unwrap();
        stream.send_reliable(Bytes::from("world")).await.unwrap();

        // Check pending
        assert_eq!(stream.pending_send_count().await, 2);

        // Poll send twice, the second should be None because it's already sent and hasn't timed out
        let seg = stream
            .poll_send(u64::MAX, 0, std::time::Instant::now())
            .await
            .unwrap();
        assert_eq!(seg.stream_offset, 0);
        assert_eq!(seg.data, Bytes::from("hello"));
        assert!(seg.reliable);
        assert!(!seg.retransmit);

        let seg2 = stream
            .poll_send(u64::MAX, 0, std::time::Instant::now())
            .await
            .unwrap();
        assert_eq!(seg2.stream_offset, 1);
        assert_eq!(seg2.data, Bytes::from("world"));
        assert!(seg2.reliable);
        assert!(!seg2.retransmit);

        assert!(stream
            .poll_send(u64::MAX, 0, std::time::Instant::now())
            .await
            .is_err());
    }

    /// T4.5 (`stream_offset`): the gap-free reliable offset is a `u32`
    /// assigned per reliable segment. A naive `fetch_add(1)` silently wraps `u32::MAX`
    /// back to `0`, colliding with the first segment's offset and corrupting
    /// reassembly / SACK dedup (a duplicate offset, NOT a nonce reuse — the AEAD nonce
    /// is the `u64` packet number). It must fail-closed instead — mirroring the epoch
    /// saturation guard in `Session::rekey` — so an exhausted stream refuses new
    /// reliable data rather than corrupting the stream.
    #[tokio::test]
    async fn reliable_offset_fails_closed_at_u32_exhaustion() {
        let stream = Stream::new(1);

        // The last assignable offset is `u32::MAX - 1`; assigning it leaves the cursor
        // at `u32::MAX`, the exhaustion sentinel.
        stream.reliable_offset.store(u32::MAX - 1, Ordering::SeqCst);
        let last = stream
            .send_reliable(Bytes::from_static(b"a"))
            .await
            .expect("offset u32::MAX-1 must still be assignable");
        assert_eq!(last, u32::MAX - 1, "last assignable reliable offset");

        // The next send must fail-closed — never wrap to 0.
        let exhausted = stream.send_reliable(Bytes::from_static(b"b")).await;
        assert!(
            matches!(exhausted, Err(crate::errors::CoreError::StreamError(_))),
            "send_reliable must fail-closed (StreamError) at u32 offset exhaustion, got {exhausted:?}"
        );

        // And directly at the sentinel.
        stream.reliable_offset.store(u32::MAX, Ordering::SeqCst);
        let at_sentinel = stream.send_reliable(Bytes::from_static(b"c")).await;
        assert!(
            at_sentinel.is_err(),
            "send_reliable at the u32::MAX sentinel must fail-closed, got {at_sentinel:?}"
        );
    }

    #[tokio::test]
    async fn test_stream_retransmission() {
        // We use tokio::time::pause to mock time and test timeout
        tokio::time::pause();
        let stream = Stream::new(1);

        stream.send_reliable(Bytes::from("hello")).await.unwrap();

        // First send — not a retransmission.
        let seg = stream
            .poll_send(u64::MAX, 0, std::time::Instant::now())
            .await
            .unwrap();
        assert_eq!(seg.stream_offset, 0);
        assert!(seg.reliable);
        assert!(!seg.retransmit);

        // Immediate poll should be None
        assert!(stream
            .poll_send(u64::MAX, 0, std::time::Instant::now())
            .await
            .is_err());

        // Advance 400ms — still under the initial 1s RTO (RFC 6298 (2.1):
        // no RTT samples yet, so the timer sits at the 1-second default).
        tokio::time::advance(std::time::Duration::from_millis(400)).await;
        assert!(stream
            .poll_send(u64::MAX, 0, std::time::Instant::now())
            .await
            .is_err());

        // Advance past the 1s initial RTO (total ~1.1s).
        tokio::time::advance(std::time::Duration::from_millis(700)).await;

        // Now it should retransmit — flagged as a retransmission.
        let seg2 = stream
            .poll_send(u64::MAX, 0, std::time::Instant::now())
            .await
            .unwrap();
        assert_eq!(seg2.stream_offset, 0);
        assert_eq!(seg2.data, Bytes::from("hello"));
        assert!(seg2.reliable);
        assert!(seg2.retransmit);

        // Ack it
        let acked = stream.ack(0).await;
        assert!(acked.is_some());

        // Poll again - queue is empty
        assert!(stream
            .poll_send(u64::MAX, 0, std::time::Instant::now())
            .await
            .is_err());
    }

    #[tokio::test]
    async fn mark_unsent_re_offers_without_waiting_rto() {
        // Time is paused, so nothing ever crosses the RTO — any re-offer here is
        // due to `mark_unsent`, not the retransmit timer.
        tokio::time::pause();
        let stream = Stream::new(1);
        stream.send_reliable(Bytes::from("hello")).await.unwrap();

        // First poll stamps `sent_at`; an immediate re-poll yields nothing
        // (treated as in-flight, not yet timed out).
        let seg = stream
            .poll_send(u64::MAX, 0, std::time::Instant::now())
            .await
            .unwrap();
        assert_eq!(seg.stream_offset, 0);
        assert!(!seg.retransmit);
        assert!(stream
            .poll_send(u64::MAX, 0, std::time::Instant::now())
            .await
            .is_err());

        // Simulate a send that failed *after* `poll_send` stamped the segment:
        // clear `sent_at` so it is no longer considered in-flight.
        stream.mark_unsent(0).await;

        // It is re-offered immediately — without advancing past the RTO — and as
        // a fresh send (Pass 2), not a retransmission.
        let seg2 = stream
            .poll_send(u64::MAX, 0, std::time::Instant::now())
            .await
            .unwrap();
        assert_eq!(seg2.stream_offset, 0);
        assert_eq!(seg2.data, Bytes::from("hello"));
        assert!(seg2.reliable);
        assert!(!seg2.retransmit);

        // `mark_unsent` on an already-acked (removed) segment is a no-op.
        assert!(stream.ack(0).await.is_some());
        stream.mark_unsent(0).await; // no panic, no effect
        assert!(stream
            .poll_send(u64::MAX, 0, std::time::Instant::now())
            .await
            .is_err());
    }

    /// A segment must carry back the delivered counter it was stamped with when
    /// it went out, per transmission.
    ///
    /// This is the plumbing behind BBR's delivery-rate sample. If it silently
    /// degrades to a constant (a hardcoded 0, say) the estimator's own tests
    /// still pass while every sample collapses to one packet per round trip —
    /// which is how a session came to be capped near `cwnd_floor / rtt` on a
    /// real path.
    #[tokio::test]
    async fn a_retired_segment_reports_the_delivered_counter_from_its_send() {
        let stream = Stream::new(1);
        stream.send_reliable(Bytes::from("aaaa")).await.unwrap();
        stream.send_reliable(Bytes::from("bbbb")).await.unwrap();

        let first = stream
            .poll_send(u64::MAX, 10_000, std::time::Instant::now())
            .await
            .unwrap();
        let second = stream
            .poll_send(u64::MAX, 25_000, std::time::Instant::now())
            .await
            .unwrap();
        assert_ne!(first.stream_offset, second.stream_offset);

        let sack = Sack::from_received(&[first.stream_offset, second.stream_offset], 0)
            .expect("sack covering both");
        let retired = stream.on_sack(&sack).await.retired;
        assert_eq!(retired.len(), 2, "both segments are covered");

        let mut stamps: Vec<u64> = retired.iter().map(|r| r.delivered_at_send).collect();
        stamps.sort_unstable();
        assert_eq!(
            stamps,
            vec![10_000, 25_000],
            "each segment reports the counter as of its own transmission"
        );
    }

    /// A retransmission is a fresh transmission for the *timers* only. The
    /// delivery marks stay with the original send, because an acknowledgement
    /// does not say which copy it answers and the usual answer is the original —
    /// measuring from the retry would then divide a round trip's worth of
    /// delivery by the moments since the resend.
    #[tokio::test]
    async fn a_retransmit_keeps_the_delivery_marks_of_the_original_send() {
        let stream = Stream::new(1);
        stream.send_reliable(Bytes::from("payload")).await.unwrap();

        // Push enough segments that the packet-threshold detector can flag the
        // head as lost, then let Pass-0 fast-retransmit it.
        for _ in 0..5u32 {
            stream
                .send_reliable(Bytes::from_static(b"x"))
                .await
                .unwrap();
        }
        let head = stream
            .poll_send(u64::MAX, 1_000, std::time::Instant::now())
            .await
            .unwrap();
        assert!(!head.retransmit);
        let mut acked = Vec::new();
        for _ in 0..5u32 {
            let seg = stream
                .poll_send(u64::MAX, 1_000, std::time::Instant::now())
                .await
                .expect("in flight");
            acked.push(seg.stream_offset);
        }
        let flagging = Sack::from_received(&acked, 0).expect("sack");
        assert!(
            stream
                .on_sack(&flagging)
                .await
                .lost_offsets()
                .contains(&head.stream_offset),
            "the head segment should be flagged lost by the packet threshold"
        );

        let again = stream
            .poll_send(u64::MAX, 7_000, std::time::Instant::now())
            .await
            .unwrap();
        assert!(again.retransmit, "expected the fast-retransmit pass");
        assert_eq!(again.stream_offset, head.stream_offset);

        let sack = Sack::from_received(&[head.stream_offset], 0).expect("sack");
        let retired = stream.on_sack(&sack).await.retired;
        assert_eq!(retired.len(), 1);
        assert_eq!(
            retired[0].delivered_at_send, 1_000,
            "the interval the acknowledgement measures starts at the original \
             transmission, not at the retry"
        );
        assert!(
            retired[0].was_retransmit,
            "the segment is still flagged retransmitted, so Karn's gate still \
             keeps its round trip out of the RTT filter"
        );
    }

    #[tokio::test]
    async fn poll_send_respects_the_cwnd_budget() {
        let stream = Stream::new(1);
        stream
            .send_reliable(Bytes::from("0123456789"))
            .await
            .unwrap(); // 10 bytes
        stream.send_reliable(Bytes::from("abcde")).await.unwrap(); // 5 bytes

        // Budget of 10 admits the 10-byte head segment.
        let seg = stream
            .poll_send(10, 0, std::time::Instant::now())
            .await
            .unwrap();
        assert_eq!(seg.data.len(), 10);
        assert!(!seg.retransmit);

        // Budget of 4 is too small for the next (5-byte) segment → withheld.
        assert!(stream
            .poll_send(4, 0, std::time::Instant::now())
            .await
            .is_err());

        // A budget of 5 now admits it.
        let seg2 = stream
            .poll_send(5, 0, std::time::Instant::now())
            .await
            .unwrap();
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
            stream.send_reliable(Bytes::from("data")).await.unwrap();
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
            let seq = stream
                .send_reliable(Bytes::from(format!("seg-{i}")))
                .await
                .unwrap();
            assert_eq!(seq, i);
            // Stamp it as in-flight so RTT sampling has a `sent_at`.
            let seg = stream
                .poll_send(u64::MAX, 0, std::time::Instant::now())
                .await
                .expect("poll");
            assert_eq!(seg.stream_offset, i);
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

    /// T5.4 (audit SACK-storm LOW): a SACK's `largest_acked` is clamped to the highest
    /// stream_offset actually sent, so an authenticated peer can't inflate it (e.g.
    /// `high + 1e6`) to declare freshly-sent, legitimately-in-flight segments "lost" and force
    /// a cwnd-bypassing Pass-0 retransmit storm.
    #[tokio::test]
    async fn on_sack_clamps_inflated_largest_acked() {
        let stream = Stream::new(1);
        for i in 0..5u32 {
            let seq = stream
                .send_reliable(Bytes::from(format!("seg-{i}")))
                .await
                .unwrap();
            assert_eq!(seq, i);
            let seg = stream
                .poll_send(u64::MAX, 0, std::time::Instant::now())
                .await
                .expect("poll"); // stamps sent_at
            assert_eq!(seg.stream_offset, i);
        }
        // A SACK that acks NONE of our segments (0..5) but claims a `largest_acked` far beyond
        // anything we ever sent.
        let sack = Sack::from_received(&[1_000_000], 0).expect("sack");
        assert_eq!(sack.largest_acked, 1_000_000);
        let result = stream.on_sack(&sack).await;
        // The freshest in-flight segment (within PACKET_THRESHOLD of the highest sent) must NOT
        // be flagged lost — the clamp limits loss detection to the real sent range.
        assert!(
            !result.lost.iter().any(|l| l.stream_offset == 4),
            "an inflated largest_acked must not flag the freshest in-flight segment as lost"
        );
    }

    /// A SACK that covers nothing still buffered (stale / duplicate) retires
    /// nothing and leaves the send buffer intact.
    #[tokio::test]
    async fn on_sack_for_unbuffered_sequences_retires_nothing() {
        let stream = Stream::new(1);
        stream.send_reliable(Bytes::from("zero")).await.unwrap(); // seq 0
        let _ = stream
            .poll_send(u64::MAX, 0, std::time::Instant::now())
            .await
            .expect("poll");

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
        stream.send_reliable(Bytes::from("payload")).await.unwrap(); // seq 0
        let _ = stream
            .poll_send(u64::MAX, 0, std::time::Instant::now())
            .await
            .expect("first send");

        // Force a retransmit by crossing the RTO, so retries > 0.
        tokio::time::advance(Duration::from_millis(1100)).await;
        let retx = stream
            .poll_send(u64::MAX, 0, std::time::Instant::now())
            .await
            .expect("retransmit");
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
            stream
                .send_reliable(Bytes::from_static(b"x"))
                .await
                .unwrap();
            let _ = stream
                .poll_send(u64::MAX, 0, std::time::Instant::now())
                .await
                .expect("in-flight");
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
            .poll_send(0, 0, std::time::Instant::now())
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
        stream
            .send_reliable(Bytes::from_static(b"a"))
            .await
            .unwrap(); // offset 0
        let _ = stream
            .poll_send(u64::MAX, 0, std::time::Instant::now())
            .await
            .expect("send 0");
        tokio::time::advance(Duration::from_millis(10)).await;
        let _ = stream
            .on_sack(&Sack::from_received(&[0], 0).expect("sack"))
            .await; // srtt ≈ 10 ms

        // Send offsets 1 and 2; age them well past srtt·9/8 (≈ 11 ms).
        stream
            .send_reliable(Bytes::from_static(b"b"))
            .await
            .unwrap(); // offset 1
        stream
            .send_reliable(Bytes::from_static(b"c"))
            .await
            .unwrap(); // offset 2
        let _ = stream
            .poll_send(u64::MAX, 0, std::time::Instant::now())
            .await
            .expect("send 1");
        let _ = stream
            .poll_send(u64::MAX, 0, std::time::Instant::now())
            .await
            .expect("send 2");
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

    /// Build the five-segment "one open hole" shape every loss-storm test below
    /// starts from: offsets 0..=4 are all on the wire, and a SACK covering
    /// {1,2,3,4} leaves offset 0 as the only hole. `largest_acked` is then 4,
    /// which is at or past `0 + PACKET_THRESHOLD`, so the packet threshold
    /// qualifies offset 0 on the very first acknowledgement.
    ///
    /// Time must be paused by the caller: these tests separate the packet
    /// threshold from the RACK time threshold, and the latter fires on any
    /// segment aged past `max(1 ms, srtt·9/8)`.
    async fn stream_with_one_open_hole() -> (Stream, Sack) {
        let stream = Stream::new(1);
        for _ in 0..5u32 {
            stream
                .send_reliable(Bytes::from_static(b"x"))
                .await
                .unwrap();
            let _ = stream
                .poll_send(u64::MAX, 0, std::time::Instant::now())
                .await
                .expect("in flight");
        }
        let sack = Sack::from_received(&[1, 2, 3, 4], 0).expect("sack over the hole");
        (stream, sack)
    }

    /// **A loss is reported once per loss, not once per acknowledgement.**
    ///
    /// `largest_acked` only grows, so once an offset has qualified under the
    /// packet threshold it qualifies under it forever. The `lost` flag is not a
    /// memory of that — `poll_send`'s Pass-0 clears it the moment it puts the
    /// copy on the wire — so with the flag cleared and the threshold still
    /// satisfied, every subsequent acknowledgement re-declared the same segment
    /// lost. On a path that acknowledges every packet, that is one bogus loss
    /// report per received packet for a whole round trip: a round with a single
    /// genuine loss reads as a round that lost most of its window, and the
    /// congestion controller's inflight bound sits on its floor.
    #[tokio::test]
    async fn a_retransmitted_segment_is_not_re_declared_lost_by_every_ack() {
        tokio::time::pause();
        let (stream, sack) = stream_with_one_open_hole().await;

        let mut reports = 0usize;
        for _ in 0..20 {
            reports += stream.on_sack(&sack).await.lost.len();
            // Stand in for the pump: Pass-0 answers the flag and clears it,
            // which is what re-armed the packet threshold on the next ack.
            if let Ok(seg) = stream
                .poll_send(u64::MAX, 0, std::time::Instant::now())
                .await
            {
                assert!(seg.retransmit, "Pass-0 hands back a retransmission");
                assert_eq!(seg.stream_offset, 0, "the hole is offset 0");
            }
        }

        assert_eq!(
            reports, 1,
            "one hole must be reported lost exactly once while its retransmission \
             is outstanding; got {reports} reports over 20 acknowledgements"
        );
    }

    /// Two-sided companion to the test above: the suppression is scoped to a
    /// segment that has *already* been resent. A hole that meets the packet
    /// threshold for the first time — `retries == 0`, nothing on the wire to
    /// wait for — is still declared lost immediately.
    ///
    /// This rejects the naive "fix" of deleting the packet-threshold test, which
    /// would silence the storm by removing fast retransmit altogether and leave
    /// every loss to the RTO.
    #[tokio::test]
    async fn a_never_retransmitted_hole_is_still_declared_lost_at_once() {
        tokio::time::pause();
        let (stream, sack) = stream_with_one_open_hole().await;

        let result = stream.on_sack(&sack).await;
        assert_eq!(
            result.lost_offsets(),
            vec![0],
            "the first acknowledgement that puts largest_acked three offsets past \
             the hole must declare it lost"
        );
    }

    /// Two-sided companion: a retransmission that is *itself* lost must be
    /// re-declared. The rule that replaces the packet threshold is RACK's time
    /// threshold measured from the latest transmission — so the re-detection is
    /// paced by `srtt·9/8`, once per round trip, instead of once per
    /// acknowledgement.
    ///
    /// This rejects the naive "fix" of declaring a segment lost at most once
    /// ever, which would leave a lost retransmission to the RTO backstop and
    /// turn a second drop into a whole RTO of stall.
    #[tokio::test]
    async fn a_lost_retransmission_is_re_declared_by_the_time_threshold() {
        tokio::time::pause();
        let stream = Stream::new(1);

        // Establish an srtt of ~10 ms so the time threshold is ~11.25 ms — well
        // clear of the 1 ms kGranularity floor, and well under the RTO.
        stream
            .send_reliable(Bytes::from_static(b"a"))
            .await
            .unwrap();
        let _ = stream
            .poll_send(u64::MAX, 0, std::time::Instant::now())
            .await
            .expect("send offset 0");
        tokio::time::advance(Duration::from_millis(10)).await;
        let _ = stream
            .on_sack(&Sack::from_received(&[0], 0).expect("sack"))
            .await;

        // Offsets 1..=5 go out; a SACK covering {2,3,4,5} leaves 1 as the hole.
        for _ in 0..5u32 {
            stream
                .send_reliable(Bytes::from_static(b"x"))
                .await
                .unwrap();
            let _ = stream
                .poll_send(u64::MAX, 0, std::time::Instant::now())
                .await
                .expect("in flight");
        }
        let sack = Sack::from_received(&[2, 3, 4, 5], 0).expect("sack over the hole");

        assert_eq!(
            stream.on_sack(&sack).await.lost_offsets(),
            vec![1],
            "first detection"
        );
        let resend = stream
            .poll_send(u64::MAX, 0, std::time::Instant::now())
            .await
            .expect("Pass-0 fast-retransmit");
        assert_eq!(resend.stream_offset, 1);

        // Immediately after the resend nothing has been learned, so nothing is
        // reported: the copy has not had time to be acknowledged.
        assert!(
            stream.on_sack(&sack).await.lost.is_empty(),
            "an ack landing in the same instant as the resend carries no news"
        );

        // A round trip later the copy is still unacknowledged. That IS news.
        tokio::time::advance(Duration::from_millis(50)).await;
        assert_eq!(
            stream.on_sack(&sack).await.lost_offsets(),
            vec![1],
            "a retransmission aged past srtt·9/8 must be re-declared lost"
        );
    }

    /// The wire-facing half of the same defect: a re-declaration is also a
    /// re-*transmission*, because Pass-0 bypasses the congestion window and runs
    /// ahead of the pass that sends new data. Under a storm the sender spends a
    /// whole round trip emitting copies of one segment while new data waits.
    #[tokio::test]
    async fn pass0_emits_one_copy_of_a_hole_per_detection_not_per_ack() {
        tokio::time::pause();
        let (stream, sack) = stream_with_one_open_hole().await;

        let mut copies = 0usize;
        for _ in 0..20 {
            let _ = stream.on_sack(&sack).await;
            // Drain whatever the pump would have drained this pass. Bounded so a
            // regression fails the assertion below instead of hanging.
            for _ in 0..4 {
                match stream
                    .poll_send(u64::MAX, 0, std::time::Instant::now())
                    .await
                {
                    Ok(seg) => {
                        assert!(seg.retransmit, "nothing new is queued");
                        copies += 1;
                    }
                    Err(_) => break,
                }
            }
        }

        assert_eq!(
            copies, 1,
            "the hole must go on the wire once per detection; got {copies} copies \
             over 20 acknowledgements"
        );
    }

    /// **A retransmission must not fabricate a delivery-rate sample.**
    ///
    /// The estimator's rate is `bytes the connection delivered since the sample's
    /// mark` over `time since that mark`. Moving the mark forward on a resend
    /// keeps the two consistent only if the acknowledgement being measured
    /// answers the *resend*. It frequently does not: an acknowledgement already
    /// in flight for the original lands moments after the copy goes out, and
    /// then a whole window of delivery is divided by the milliseconds since the
    /// restamp.
    ///
    /// The arithmetic this test sets up, with 20 segments of 1200 B on a 250 ms
    /// path whose acknowledgements arrive 100 µs apart:
    ///
    /// - the connection delivers 20 × 1200 = 24 000 B, all of it acknowledged by
    ///   t ≈ 251.9 ms, so nothing above 24 000 B / 0.2519 s ≈ 95 KB/s (0.76
    ///   Mbit/s) is supported by anything that happened;
    /// - restamping put the hole's mark at 3 × 1200 = 3600 B delivered, at
    ///   t ≈ 250.2 ms. Its acknowledgement lands at t ≈ 251.9 ms, so the sample
    ///   reads (24 000 − 3600) B / 1.7 ms ≈ 12 MB/s — 126× the truth, from one
    ///   sample, into a maximum filter that holds it for ten seconds;
    /// - keeping the mark at the original send gives 24 000 B / 251.9 ms, i.e.
    ///   exactly the supported figure. It can only ever under-report, and a
    ///   maximum filter is indifferent to a low sample.
    #[tokio::test]
    async fn a_retransmits_ack_cannot_fabricate_a_delivery_rate() {
        use crate::transport::bandwidth_estimator::BandwidthEstimator;

        const SEGMENTS: u32 = 20;
        const PAYLOAD: usize = 1200;
        const RTT_MS: u64 = 250;
        /// Spacing between the acknowledgements of the burst.
        const ACK_GAP_US: u64 = 100;

        tokio::time::pause();
        // The tokio clock is frozen, so this origin and every `advance` below
        // agree with the `std::time::Instant`s the estimator works in.
        let t0 = tokio::time::Instant::now().into_std();
        let stream = Stream::new(1);
        let mut est = BandwidthEstimator::new();
        let payload = Bytes::from(vec![0u8; PAYLOAD]);

        // A window's worth leaves back-to-back at t = 0.
        for _ in 0..SEGMENTS {
            stream.send_reliable(payload.clone()).await.unwrap();
            let sent = stream
                .poll_send(u64::MAX, est.delivered_bytes(), est.delivered_time())
                .await
                .expect("in flight");
            est.on_send(sent.data.len() as u64);
        }

        // One round trip later the acknowledgements arrive, one per received
        // packet, with offset 0 missing.
        tokio::time::advance(Duration::from_millis(RTT_MS)).await;
        let mut acked: Vec<u32> = Vec::new();
        for offset in 1..SEGMENTS {
            acked.push(offset);
            let sack = Sack::from_received(&acked, 0).expect("sack");
            feed_retirements(&stream, &sack, &mut est).await;
            // The packet threshold qualifies the hole once largest_acked reaches
            // 3; the pump answers by resending it, which is where the mark used
            // to move.
            if let Ok(seg) = stream
                .poll_send(u64::MAX, est.delivered_bytes(), est.delivered_time())
                .await
            {
                assert!(seg.retransmit);
                est.on_send(seg.data.len() as u64);
            }
            tokio::time::advance(Duration::from_micros(ACK_GAP_US)).await;
        }

        // Finally the hole's own acknowledgement lands — answering the original
        // transmission, which had been in flight for the whole round trip.
        acked.push(0);
        let sack = Sack::from_received(&acked, 0).expect("sack");
        feed_retirements(&stream, &sack, &mut est).await;

        let total = u64::from(SEGMENTS) * PAYLOAD as u64;
        let elapsed = tokio::time::Instant::now().into_std().duration_since(t0);
        let supported = (total as f64 / elapsed.as_secs_f64()) as u64;
        assert!(
            est.bottleneck_bandwidth() <= supported + supported / 10,
            "estimate {} B/s exceeds the {} B/s that {} B over {:?} supports",
            est.bottleneck_bandwidth(),
            supported,
            total,
            elapsed
        );
        // ...and it must still find the rate, or an estimator that refused to
        // sample a retransmitted segment at all would satisfy the bound above.
        assert!(
            est.bottleneck_bandwidth() >= supported / 2,
            "estimate {} B/s undershoots the {} B/s actually delivered",
            est.bottleneck_bandwidth(),
            supported
        );
    }

    /// Mirror what the data pump does with a `SackResult`: turn every retired
    /// segment into the `DeliverySample` the estimator is fed, using the marks
    /// the segment carried and `now` as the acknowledgement instant.
    async fn feed_retirements(
        stream: &Stream,
        sack: &Sack,
        est: &mut crate::transport::bandwidth_estimator::BandwidthEstimator,
    ) {
        use crate::transport::bandwidth_estimator::DeliverySample;
        let acked_at = tokio::time::Instant::now().into_std();
        for retired in stream.on_sack(sack).await.retired {
            let Some(sent_at) = retired.sent_at else {
                continue;
            };
            let sent_at = sent_at.into_std();
            est.on_ack(DeliverySample {
                delivered_bytes: retired.delivered_at_send,
                delivered_at: retired.delivered_time_at_send.unwrap_or(sent_at),
                sent_at,
                acked_at,
                packet_bytes: retired.size,
                is_app_limited: false,
                ack_delay_us: 0,
                rtt_sampled: !retired.was_retransmit,
            });
        }
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

    // ── Receive-window auto-tuning ──
    //
    // The measurement interval is `2 × AUTOTUNE_RTT_FALLBACK` = 400 ms (these streams never
    // send, so they have no RTT sample of their own), and a window doubles when the
    // application consumed more than four fifths of a window across a closed interval — that
    // is, more than 51.2 KiB per 400 ms at the 64 KiB initial window, 128 KiB/s. The clock is
    // paused, so every number below is exact rather than a race with the scheduler.

    /// The safety direction, and the reason the feature is defensible: bytes *arriving* move
    /// nothing. Only the delivery task, handing bytes onward to the application, calls
    /// `record_app_consumed` — so a peer that floods a reader that never reads cannot make
    /// the receiver widen its own buffer by one byte, no matter how long it keeps it up.
    #[tokio::test]
    async fn arrival_without_consumption_never_grows_the_window() {
        tokio::time::pause();
        let s = Stream::new(1);
        assert_eq!(s.advertised_recv_window(), INITIAL_STREAM_WINDOW);

        // A peer pushes a full window of in-order data as fast as it can; nothing reads it.
        for seq in 0..64 {
            let _ = s
                .accept_in_order(seq, vec![Bytes::from(vec![0u8; 1024])])
                .await;
            tokio::time::advance(Duration::from_millis(10)).await;
        }
        tokio::time::advance(Duration::from_secs(30)).await;

        assert_eq!(
            s.advertised_recv_window(),
            INITIAL_STREAM_WINDOW,
            "the advertised window must be a function of what the application consumed, \
             never of what the peer chose to send"
        );
        assert_eq!(s.recv_reorder_byte_limit(), MAX_RECV_REORDER_BYTES);
    }

    /// An application consuming below `window / (4 × RTT)` is not window-limited — the window
    /// it already has is more than it can use — so it must not be given a larger one.
    #[tokio::test]
    async fn slow_consumption_never_grows_the_window() {
        tokio::time::pause();
        let s = Stream::new(1);
        s.record_app_consumed(1); // opens the first interval

        // 16 KiB per 400 ms interval = 40 KiB/s, under a third of the 128 KiB/s threshold.
        for _ in 0..10 {
            tokio::time::advance(Duration::from_millis(400)).await;
            s.record_app_consumed(16 * 1024);
        }

        assert_eq!(
            s.advertised_recv_window(),
            INITIAL_STREAM_WINDOW,
            "a reader slower than the window permits gains nothing from a wider window"
        );
    }

    /// The positive direction: an application outrunning the window gets a wider one, by
    /// doubling, and the ladder stops dead at the cap.
    #[tokio::test]
    async fn fast_consumption_doubles_the_window_up_to_the_cap() {
        tokio::time::pause();
        let s = Stream::new(1);
        s.record_app_consumed(1);

        // 128 KiB per 400 ms = 320 KiB/s, two and a half times the 128 KiB/s threshold at
        // the initial window — one doubling per closed interval.
        tokio::time::advance(Duration::from_millis(400)).await;
        s.record_app_consumed(128 * 1024);
        assert_eq!(s.advertised_recv_window(), 2 * INITIAL_STREAM_WINDOW);
        assert_eq!(
            s.recv_reorder_byte_limit(),
            3 * INITIAL_STREAM_WINDOW as usize,
            "the reorder budget tracks the window it has to hold out-of-order data for"
        );

        // Keep outrunning it: the window climbs to the cap and then stops for good.
        for _ in 0..12 {
            tokio::time::advance(Duration::from_millis(400)).await;
            s.record_app_consumed(MAX_RECV_WINDOW);
        }
        assert_eq!(s.advertised_recv_window(), MAX_RECV_WINDOW);
        assert_eq!(
            s.recv_reorder_byte_limit(),
            MAX_RECV_REORDER_BYTES_CEILING,
            "and the reorder budget stops with it"
        );
    }

    /// The reason the trigger is a time interval and not a byte count. The delivery queue in
    /// front of the application is bounded but not empty, so even a stalled reader absorbs
    /// one queue's worth of bytes in a burst. A byte-triggered tuner would read that burst as
    /// a sustained rate and climb the entire ladder on it; an interval no shorter than a
    /// round trip lets it buy at most the one doubling the burst genuinely paid for.
    #[tokio::test]
    async fn a_burst_shorter_than_the_interval_does_not_climb_the_ladder() {
        tokio::time::pause();
        let s = Stream::new(1);
        s.record_app_consumed(1);

        // 256 KiB drains through in 50 ms — four windows' worth, at 5 MiB/s.
        for _ in 0..256 {
            s.record_app_consumed(1024);
            tokio::time::advance(Duration::from_micros(195)).await;
        }
        assert_eq!(
            s.advertised_recv_window(),
            INITIAL_STREAM_WINDOW,
            "no interval has closed yet, so there is nothing to conclude"
        );

        // The interval closes and the burst buys exactly one doubling …
        tokio::time::advance(Duration::from_millis(400)).await;
        s.record_app_consumed(1024);
        assert_eq!(s.advertised_recv_window(), 2 * INITIAL_STREAM_WINDOW);

        // … after which the real reader rate governs, and it is far below the threshold.
        for _ in 0..10 {
            tokio::time::advance(Duration::from_millis(400)).await;
            s.record_app_consumed(1024);
        }
        assert_eq!(
            s.advertised_recv_window(),
            2 * INITIAL_STREAM_WINDOW,
            "a one-off burst must not be mistaken for a sustained rate"
        );
    }

    /// A window increase reaches the peer as ordinary relative credit, and is emitted at once
    /// rather than waiting for the consumption credit to reach its own threshold — the peer
    /// is stalled on exactly this grant.
    #[tokio::test]
    async fn window_growth_is_emitted_as_relative_credit_immediately() {
        tokio::time::pause();
        let s = Stream::new(1);
        s.record_app_consumed(1);

        // Mid-interval, consumption crosses its own update threshold and is flushed …
        tokio::time::advance(Duration::from_millis(200)).await;
        assert_eq!(s.record_app_consumed(60 * 1024), Some(60 * 1024 + 1));

        // … so when the interval closes, the growth is all that is left to advertise.
        tokio::time::advance(Duration::from_millis(200)).await;
        let credit = s.record_app_consumed(8 * 1024).expect("growth is credited");
        assert_eq!(
            credit, INITIAL_STREAM_WINDOW,
            "the credit is the 64 KiB the window grew by; the 8 KiB of consumption is still \
             accumulating toward its own threshold"
        );

        // A peer applying it ends up with initial + growth, i.e. the new window.
        let peer = Stream::new(1);
        peer.apply_peer_window_update(credit);
        assert_eq!(peer.peer_send_window(), 2 * INITIAL_STREAM_WINDOW);
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

    // ── Reliable FIN over ARQ ──

    /// `queue_fin` enqueues a zero-length PendingData with `fin = true`, marks
    /// `local_finished`, and consumes exactly one backpressure permit.
    #[tokio::test]
    async fn queue_fin_enqueues_zero_length_fin_segment() {
        let stream = Stream::new(3);
        // Nothing in the buffer initially.
        assert_eq!(stream.pending_send_count().await, 0);
        assert!(!stream.local_finished.load(Ordering::SeqCst));

        stream.queue_fin().await.expect("queue_fin must succeed");

        // Exactly one segment queued.
        assert_eq!(stream.pending_send_count().await, 1);
        // local_finished flag is raised.
        assert!(stream.local_finished.load(Ordering::SeqCst));
    }

    /// `queue_fin` must fail-closed (StreamError) when the reliable offset
    /// is at u32::MAX — the same exhaustion guard as `send_reliable`.
    #[tokio::test]
    async fn queue_fin_fails_closed_at_offset_exhaustion() {
        let stream = Stream::new(3);
        stream.reliable_offset.store(u32::MAX, Ordering::SeqCst);
        let result = stream.queue_fin().await;
        assert!(
            matches!(result, Err(crate::errors::CoreError::StreamError(_))),
            "queue_fin at u32::MAX offset must fail-closed, got {result:?}"
        );
    }

    /// `poll_send` returns the FIN segment with `seg.fin == true` and
    /// `seg.data.is_empty()`.  The segment carries the assigned stream_offset so
    /// it can be SACKed.
    #[tokio::test]
    async fn poll_send_emits_fin_segment_with_empty_payload() {
        let stream = Stream::new(3);
        stream.queue_fin().await.expect("queue_fin");

        let seg = stream
            .poll_send(u64::MAX, 0, std::time::Instant::now())
            .await
            .expect("must yield FIN segment");
        assert!(
            seg.fin,
            "OutboundSegment.fin must be true for the FIN sentinel"
        );
        assert!(seg.data.is_empty(), "FIN segment must carry no payload");
        assert!(seg.reliable, "FIN must be sent reliably");
        assert!(!seg.retransmit, "first send is not a retransmit");
    }

    /// `is_fin_acked` is false while the FIN segment is still in the send buffer
    /// (not yet SACKed), and becomes true once the FIN's sequence is ACKed.
    #[tokio::test]
    async fn is_fin_acked_becomes_true_after_fin_sacked() {
        let stream = Stream::new(3);
        // Before any FIN: local_finished is false → is_fin_acked must be false.
        assert!(!stream.is_fin_acked().await, "no FIN queued yet");

        stream.queue_fin().await.expect("queue_fin");
        // FIN queued but not yet ACKed.
        assert!(!stream.is_fin_acked().await, "FIN not yet SACKed");

        // Poll the FIN out (stamps sent_at, keeps it in buffer until ACKed).
        let seg = stream
            .poll_send(u64::MAX, 0, std::time::Instant::now())
            .await
            .expect("FIN segment");
        assert_eq!(stream.pending_send_count().await, 1, "still buffered");
        assert!(!stream.is_fin_acked().await, "still in-flight");

        // SACK the FIN offset → buffer drains → is_fin_acked becomes true.
        let sack = Sack::from_received(&[seg.stream_offset], 0).expect("sack");
        let _ = stream.on_sack(&sack).await;
        assert_eq!(
            stream.pending_send_count().await,
            0,
            "buffer must be empty after SACK"
        );
        assert!(
            stream.is_fin_acked().await,
            "FIN was SACKed → is_fin_acked must be true"
        );
    }

    /// The FIN segment bypasses the send-window check: even with a fully-drained
    /// congestion window (budget = 0), `poll_send` must still emit the FIN.
    #[tokio::test]
    async fn fin_segment_bypasses_congestion_window() {
        let stream = Stream::new(3);
        stream.queue_fin().await.expect("queue_fin");

        // Pass budget = 0 — a normal data segment would be withheld.
        let seg = stream.poll_send(0, 0, std::time::Instant::now()).await;
        assert!(seg.is_ok(), "FIN must be emitted even when cwnd_budget = 0");
        let seg = seg.unwrap();
        assert!(seg.fin, "segment must be the FIN sentinel");
    }

    /// FIN retransmits after RTO expiry (same retransmit machinery as data).
    /// After the initial send, an immediate poll yields nothing; once the RTO
    /// elapses the FIN is re-offered as a retransmit.
    #[tokio::test]
    async fn fin_retransmits_after_rto() {
        tokio::time::pause();
        let stream = Stream::new(3);
        stream.queue_fin().await.expect("queue_fin");

        // First send.
        let seg = stream
            .poll_send(u64::MAX, 0, std::time::Instant::now())
            .await
            .expect("first FIN");
        assert!(seg.fin);
        assert!(!seg.retransmit);

        // Immediate re-poll: nothing (in-flight, RTO not elapsed).
        assert!(stream
            .poll_send(u64::MAX, 0, std::time::Instant::now())
            .await
            .is_err());

        // Advance past the initial 1-second RTO.
        tokio::time::advance(std::time::Duration::from_millis(1100)).await;

        let retx = stream
            .poll_send(u64::MAX, 0, std::time::Instant::now())
            .await
            .expect("FIN retransmit");
        assert!(retx.fin, "retransmit must still carry fin = true");
        assert!(retx.retransmit, "must be flagged as a retransmit");
        assert!(
            retx.data.is_empty(),
            "retransmitted FIN payload is still empty"
        );
    }

    /// Regression: a remote FIN that arrives OVER A GAP (an earlier reliable
    /// offset still missing, as happens on a reordering/lossy UDP path) must NOT
    /// surface EOF until the gap closes — otherwise a reader trusting
    /// `recv() -> Ok(None)` stops and silently loses the trailing data.
    #[tokio::test]
    async fn remote_fin_eof_surfaces_only_after_in_order_release() {
        let s = Stream::new(2);

        // data@0 arrives in order and is released.
        let run0 = s
            .accept_in_order(0, vec![Bytes::from_static(b"zero")])
            .await;
        assert!(run0.iter().any(|b| b.as_ref() == b"zero"));
        assert!(!s.take_in_order_fin(), "no FIN seen yet");

        // FIN sentinel @2 (zero-length) arrives BEFORE data@1 — a gap at offset 1.
        s.note_remote_fin(2);
        let run_fin = s.accept_in_order(2, vec![Bytes::new()]).await;
        assert!(
            run_fin.is_empty(),
            "a FIN over a gap must be buffered, not released"
        );
        assert!(
            !s.take_in_order_fin(),
            "EOF must NOT surface while offset 1 is still missing"
        );

        // The gap-filling data@1 arrives, releasing [data@1, FIN@2] in order.
        let run1 = s.accept_in_order(1, vec![Bytes::from_static(b"one")]).await;
        assert!(
            run1.iter().any(|b| b.as_ref() == b"one"),
            "the gap-filling data must be released"
        );
        assert!(
            s.take_in_order_fin(),
            "EOF surfaces now — strictly AFTER the gap-filling data"
        );
        assert!(!s.take_in_order_fin(), "EOF is one-shot");
    }
}
