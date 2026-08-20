//! Phantom Protocol - Stream Management
//!
//! Independently-flow-controlled, reliability-segmented data channels multiplexed
//! within one session. Each [`Stream`] owns its own send/receive buffers, gap-free
//! reliable offset space (A.5), SACK-driven loss detection (RFC 9002), RFC-6298 RTO
//! estimator, and cumulative-limit flow control. Per-stream sequencing means a
//! stall or loss on one stream does not head-of-line-block any other stream (HoL
//! blocking still applies *within* a stream — reliable data is delivered strictly
//! in send order via `accept_in_order`).

use crate::errors::CoreError;
use crate::transport::sack::Sack;
use crate::transport::types::{SequenceNumber, StreamId};

use bytes::Bytes;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, Notify, Semaphore};

/// Segments one stream's ARQ send buffer may hold outstanding at once, and so
/// the most acknowledgements a single round trip of that stream can return.
///
/// Visible to the crate rather than to this file alone because that second
/// reading of it is load-bearing elsewhere: it is the length of the longest
/// monotone run one round trip can put into either of the estimator's sliding
/// filters, which is what
/// [`WINDOW_FILTER_MAX_ENTRIES`](crate::transport::bandwidth_estimator) is sized
/// from. A comment claiming that tie is not the same thing as the compiler
/// holding it, and this constant is a live tuning dial — the receive window is
/// already const-asserted against it below.
pub(crate) const MAX_PENDING_PACKETS: usize = 1024;

/// Upper bound on out-of-order segments held for reassembly per stream. A peer that floods
/// past its window with huge gaps is refused here (the refused segment is NOT recorded as
/// received, so it is not SACKed and the sender retransmits it — no SACK-without-data
/// hazard, bounded memory).
///
/// It stays above the number of *segments* one maximum window holds — at
/// [`MAX_RECV_WINDOW`] and the 1156-byte UDP application chunk
/// ([`crate::transport::mtu::MAX_APP_CHUNK`]) that is ~908, so 2048 clears it with better
/// than 2× margin (pinned by
/// `the_reorder_entry_cap_clears_the_segments_one_window_holds`).
/// Below that it would become the binding constraint before the byte budget does and start
/// refusing legitimate out-of-order data on exactly the long, lossy paths a large window
/// exists for. It is not raised further, because the byte budget accounts only for payload
/// while an entry also costs a deque slot, a `Vec<Bytes>` and the retained plaintext
/// allocation — so the entry cap, not the byte budget, is what bounds a peer sending
/// one-byte segments above a hole it never fills. It is also the bound on the linear scan
/// `accept_in_order` does per out-of-order arrival.
pub const MAX_RECV_REORDER: usize = 2048;

/// Bytes of *structure* one held reorder entry costs beyond the payload the byte budget
/// counts: a deque slot for `(SequenceNumber, Vec<Bytes>)`, the heap `Vec<Bytes>` behind it,
/// and the decrypted-packet allocation the `Bytes` keeps alive. Measured against the code
/// that allocates them these come to well under a hundred bytes; 128 is a deliberate
/// over-estimate, because this figure is what a memory bound is published from and erring
/// high there is the safe direction.
///
/// It exists as a named constant because it is the multiplier on the one part of the receive
/// path that [`SESSION_RECV_WINDOW_GROWTH_BUDGET`] does **not** bound — a peer sending tiny
/// segments above a hole it never fills reaches the entry cap without ever moving the window
/// — so any statement about what a stream holds has to carry it.
pub const REORDER_ENTRY_OVERHEAD_BYTES: usize = 128;

// The entry cap is squeezed from both sides, and moving the window ceiling moves one of
// them — so both bounds are checked at compile time rather than left to a reader.
//
// Below one window of MTU-sized segments the cap becomes the binding constraint before the
// byte budget does, and starts refusing legitimate out-of-order data on the long, lossy
// paths a large window exists for.
const _: () =
    assert!(MAX_RECV_REORDER > MAX_RECV_WINDOW as usize / crate::transport::mtu::MAX_APP_CHUNK);
// Above that it is pure cost. The byte budget counts only payload, so a peer sending
// one-byte segments above a hole it never fills is bounded by the entry cap alone, and each
// held entry carries a deque slot, the `Vec<Bytes>` allocation behind it and a retained
// plaintext allocation that the budget never sees. 128 B per entry is a deliberate
// over-estimate of that structure; 2048 entries is then 256 KiB per stream, and `MAX_STREAMS`
// is 256, so 64 MiB per session held for 2 KiB of budgeted payload. That is what raising this
// cap costs, and it is why the cap did not move when the window ceiling did.
const _: () = assert!(MAX_RECV_REORDER * REORDER_ENTRY_OVERHEAD_BYTES <= 256 * 1024);

/// Per-stream byte budget for the out-of-order reorder buffer (H-3) **at the initial
/// window**, tied to the flow-control window. A compliant peer keeps in-flight (hence
/// reorderable) data within one advertised window; the [`INITIAL_STREAM_WINDOW`] of headroom
/// absorbs a boundary segment. A future hole that would push the buffered total past the
/// budget is refused (dropped → retransmitted via the "refused segment is not SACKed"
/// contract), so per-stream reorder memory is bounded in bytes and not only in entries — the
/// entry cap alone would not be, since nothing about it says how heavy an entry is.
///
/// It governs the out-of-order arm only. A segment that arrives *in* order is released
/// straight to the delivery path and never sits here, so this budget says nothing about what
/// a peer sending a gap-free stream can make the session hold; what bounds that is
/// [`MAX_RECV_FRAME`](crate::transport::mtu::MAX_RECV_FRAME) on the way in and the delivery
/// queue's own cap once it is through.
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
///
/// It is also the cumulative limit both ends assume for a stream before any
/// `WINDOW_UPDATE` has been exchanged: the first `INITIAL_STREAM_WINDOW` bytes sent on a
/// stream need no permission, and every later limit is an absolute total measured from the
/// same origin.
pub const INITIAL_STREAM_WINDOW: u32 = 64 * 1024;

/// Hard ceiling on how far the local side will run ahead of the peer's last advertisement.
///
/// A `WINDOW_UPDATE` states a cumulative total, so a peer is free to write any number it
/// likes into one; [`Stream::apply_peer_window_limit`] therefore clamps what it will honour
/// to `bytes already sent + MAX_SEND_WINDOW`. A compliant peer never advertises more than
/// `consumed + its own advertised window`, and its window is capped at [`MAX_RECV_WINDOW`]
/// — the same value — so the clamp never touches one; it exists so that a peer writing
/// `u64::MAX` buys the same allowance as a peer writing the truth. (The real bound on what
/// this side can hold outstanding is elsewhere: the ARQ send buffer's `MAX_PENDING_PACKETS`
/// segments, and the congestion window.)
pub const MAX_SEND_WINDOW: u32 = 16 * INITIAL_STREAM_WINDOW;

/// Ceiling on the **receiver's** auto-tuned advertised window (see
/// [`Stream::advertised_recv_window`]). Deliberately equal to [`MAX_SEND_WINDOW`]: the two
/// ends of the same ledger must agree, or a receiver would advertise room its peer's clamp
/// silently discards.
///
/// A window of `W` bytes admits `W / RTT` bytes per second, so this constant is a hard rate
/// ceiling on every stream. The path this transport was last measured on has a 235 ms RTT
/// and carried 41.8 Mbit/s of raw one-way UDP; its bandwidth-delay product is 1228 KB. At
/// the previous 512 KiB the window could not hold even one BDP of that path — it admitted
/// 17.85 Mbit/s, and server-side samples showed inflight pinned flat against the cap at
/// 492–520 KB run after run. 1 MiB doubles that to 35.7 Mbit/s and removes the wall those
/// samples were sitting against.
///
/// It is not raised further because nothing above it is reachable: a stream's ARQ send
/// buffer holds at most `MAX_PENDING_PACKETS` unacked segments of at most
/// [`crate::transport::mtu::MAX_APP_CHUNK`] bytes, so 1 183 744 B is all one stream can ever
/// have outstanding however large a window it is granted. Above roughly that figure the send
/// buffer, not the window, is the binding constraint, and window granted past it is memory
/// the receiver commits to hold for data that cannot arrive. Moving both together is a
/// separate change with a memory case of its own to make; this constant sits just under the
/// structural cap, pinned by
/// `the_recv_window_ceiling_stays_within_what_the_send_buffer_can_put_in_flight`.
///
/// The ceiling is not a memory commitment on its own, and it is not even a gate: it is what
/// this side *advertises*, and the receive path admits in-order data without consulting it.
/// What a session may grant across all its streams is
/// [`SESSION_RECV_WINDOW_GROWTH_BUDGET`], which is enforced; the rest of the receive path's
/// bounds are catalogued in `crate::api::session`'s module documentation.
pub const MAX_RECV_WINDOW: u32 = MAX_SEND_WINDOW;

// The ceiling must stay above the 512 KiB the measured path was pinned flat against, and at
// or below what one stream's ARQ send buffer can ever have outstanding — window granted past
// that point is memory held for data that cannot arrive. The upper bound is also measured
// behaviourally by
// `the_recv_window_ceiling_stays_within_what_the_send_buffer_can_put_in_flight`; this is the
// same statement made where the constant is, so that moving it fails the build rather than a
// test somebody might not run.
const _: () = assert!(MAX_RECV_WINDOW > 512 * 1024);
const _: () =
    assert!(MAX_RECV_WINDOW as usize <= MAX_PENDING_PACKETS * crate::transport::mtu::MAX_APP_CHUNK);

/// Total receive-window *growth* one session may hand out across all of its streams, over
/// and above the [`INITIAL_STREAM_WINDOW`] every stream starts with.
///
/// It exists because the per-stream ceiling bounds nothing on its own: a session may hold
/// up to `MAX_STREAMS` (256) streams, so a per-stream ceiling alone multiplies by 256. With
/// the budget, the window-derived part of one session's worst case is
///
/// ```text
///   advertised windows   256 × 64 KiB + 8 MiB          = 24 MiB
///   reorder budgets      Σ (window_i + 64 KiB)         = 40 MiB
/// ```
///
/// — bounded regardless of how the streams divide it up, and *below* what the same
/// arithmetic gave before this budget existed (256 × 512 KiB advertised = 128 MiB, 256 ×
/// 576 KiB of reorder = 144 MiB), even though the per-stream ceiling is now twice as large.
/// A single stream can still take the whole 1 MiB ceiling; what it cannot do is let 256 of
/// them do so at once.
///
/// Budget is drawn on growth and returned when the stream is dropped, so a long-lived
/// session that opens and closes many streams is not starved by streams that have gone.
///
/// ## What it does not bound
///
/// It bounds *growth*, so it is worth 8 MiB and no more. It does not touch the 16 MiB of
/// initial windows 256 streams start with, the reorder structure a peer can pin without
/// moving any window at all ([`REORDER_ENTRY_OVERHEAD_BYTES`]), the delivery backlog, or the
/// per-stream delivery channels. Those have bounds of their own, each with something
/// different enforcing it; `crate::api::session`'s module documentation lists them together
/// and says which are enforced and which are only observed.
///
/// It is also per **session**: nothing here divides it between concurrent sessions, so a
/// process draws it once per session it admits. Admission control is what bounds the
/// process, and it is the embedder's (`PHANTOM_MAX_SESSIONS` in the reference server).
pub const SESSION_RECV_WINDOW_GROWTH_BUDGET: u32 = 8 * 1024 * 1024;

/// RTT reference used by receive-window auto-tuning when the stream has no RTT sample of
/// its own. A stream that only *receives* never puts a reliable segment on the wire, so its
/// RFC-6298 estimator is never fed — and a pure download is precisely the case auto-tuning
/// exists for. [`RtoEstimator::MIN_RTO`] is the transport's own "no measurement yet" floor,
/// so reusing it keeps one answer to "how long is a round trip when we have not measured
/// one".
///
/// The reference has to be a constant rather than something observed during the connection,
/// because it is the denominator of the consumption rate a window must beat to grow: raising
/// it lowers that bar in proportion. Every round trip this side could observe before
/// application data moves — the handshake exchange, the gap to the peer's first packet — is
/// a quantity the peer chooses by delaying, so an observed reference would hand the peer a
/// dial on how much memory this side is willing to commit to it. Erring low costs growth on
/// paths longer than about 250 ms, which is the safe direction to err.
const AUTOTUNE_RTT_FALLBACK: Duration = RtoEstimator::MIN_RTO;

/// Receive-tuning state shared by every [`Stream`] of one session: the session-wide growth
/// budget. It belongs here rather than on the stream because a per-stream ceiling cannot
/// bound a session — see [`SESSION_RECV_WINDOW_GROWTH_BUDGET`].
#[derive(Debug)]
pub struct SharedRecvTuning {
    /// Remaining session-wide receive-window growth, in bytes. Drawn on by
    /// [`Stream::tune_recv_window`] and returned by [`Stream`]'s `Drop`.
    growth_budget: AtomicU32,
}

impl Default for SharedRecvTuning {
    fn default() -> Self {
        Self {
            growth_budget: AtomicU32::new(SESSION_RECV_WINDOW_GROWTH_BUDGET),
        }
    }
}

impl SharedRecvTuning {
    /// Remaining session-wide growth budget in bytes. Observability / test hook.
    pub fn remaining_growth_budget(&self) -> u32 {
        self.growth_budget.load(Ordering::Acquire)
    }

    /// Draw `bytes` from the budget, all or nothing. `false` means the session has already
    /// committed its growth allowance to other streams and this one keeps the window it has.
    fn try_take_growth(&self, bytes: u32) -> bool {
        let mut cur = self.growth_budget.load(Ordering::Acquire);
        loop {
            if cur < bytes {
                return false;
            }
            match self.growth_budget.compare_exchange_weak(
                cur,
                cur - bytes,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(actual) => cur = actual,
            }
        }
    }

    /// Return `bytes` to the budget (a lost growth race, or a stream going away).
    fn return_growth(&self, bytes: u32) {
        if bytes == 0 {
            return;
        }
        let mut cur = self.growth_budget.load(Ordering::Acquire);
        loop {
            // Saturate rather than wrap: the accounting is symmetric by construction, and a
            // budget that overflowed would be a far worse failure than one that is briefly
            // short.
            let next = cur
                .saturating_add(bytes)
                .min(SESSION_RECV_WINDOW_GROWTH_BUDGET);
            match self.growth_budget.compare_exchange_weak(
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
}

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
    /// Whether the connection was inside an application-limited phase when this
    /// segment was **first** put on the wire. Pinned across retransmission for
    /// the same reason the delivery marks are: the sample this segment will
    /// produce describes the flight it left with.
    app_limited_at_send: bool,
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
    /// Whether these bytes have been charged against the peer's flow-control limit and
    /// have not been given back. The charge belongs to the segment for as long as it is
    /// buffered, not to the attempt that carried it: `poll_send`'s unsent pass is the only
    /// place that levies one, and a segment reaches that pass again whenever a refused
    /// write clears its send stamp. Without a mark saying the room is already reserved, the
    /// same bytes would be paid for once per refusal — and the peer, which computes its
    /// limit from what it received, would never give any of it back. The FIN sentinel is
    /// exempt from the charge and so stays `false` here for its whole life; the persist
    /// probe never occupies a `PendingData` at all, being synthesised from an offset the
    /// peer has already acknowledged.
    charged: bool,
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
    /// Whether the connection was application-limited when this segment was
    /// first sent. Feeds `DeliverySample::is_app_limited`, which decides whether
    /// the sample may set the bandwidth maximum and whether its round's loss
    /// rate is judged at all — so it has to describe the flight the segment left
    /// with, not the phase in force when its acknowledgement happened to arrive.
    pub app_limited_at_send: bool,
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
/// itself: `Idle` says the application ran out of data, which is the whole
/// content of BBR's application-limited flag. The other two are statements that
/// a stream *had* data and something refused to carry it — the local
/// controller's own window in one case, the peer's advertised window in the
/// other — and neither is a statement about the sender's supply. Keeping the
/// peer's answer distinct matters beyond bookkeeping: it is the one of the three
/// a remote party chooses, and it must not be able to reach a local
/// congestion-control decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendBlocked {
    /// Nothing buffered: every segment has been sent and none is due for
    /// retransmission.
    Idle,
    /// The head unsent segment is larger than the congestion budget offered.
    CongestionWindow,
    /// The peer's advertised flow-control window has no room for the head
    /// unsent segment. Clears on a `WINDOW_UPDATE`, not on an acknowledgement.
    ///
    /// Reported only once there is nothing left to ask: a stream with nothing outstanding
    /// gets an empty persist probe from `Stream::poll_send` instead, so this answer also
    /// says that one of the probe's three preconditions failed — an acknowledgement is still
    /// owed, the probe interval has not elapsed, or the peer has acknowledged no offset yet
    /// and there is none to repeat.
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
    /// Total reliable application bytes this side has put on the wire for this stream,
    /// counting each byte once however many times the path makes it repeat them. A segment
    /// is charged the first time the unsent pass hands it out and carries the mark
    /// ([`PendingData::charged`]) that keeps a later pass from charging it again; the only
    /// thing that gives a charge back is a write the transport refused before any copy had
    /// ever left ([`Stream::mark_unsent`]). An acknowledgement leaves the charge standing,
    /// which is the point: the bytes arrived, and a total that shed them would be counting
    /// what is outstanding rather than what has been sent. The one thing a hostile peer can
    /// do to this total is acknowledge an offset whose write was refused a moment ago and
    /// so keep a charge for bytes it never saw — an overcount, which costs this side room
    /// and buys the peer none. It is one half of the flow-control ledger and the peer counts
    /// the other half in the same units, which is what lets an absolute limit be compared
    /// against it without either end inferring the other's state.
    bytes_sent: AtomicU64,
    /// The largest cumulative total the peer has said may be sent on this stream, as this
    /// side honours it. Starts at [`INITIAL_STREAM_WINDOW`] — the allowance both ends assume
    /// before any `WINDOW_UPDATE` — and only ever rises
    /// ([`Stream::apply_peer_window_limit`]). When it stops exceeding `bytes_sent`,
    /// `poll_send` stalls until a later `WINDOW_UPDATE` raises it — sending, meanwhile, the
    /// empty persist probe [`Stream::try_persist_probe`] issues when no such frame can be
    /// counted on.
    peer_send_limit: AtomicU64,
    /// Total bytes the local application has consumed on this stream. The limit this side
    /// advertises is this counter plus [`Stream::advertised_recv_window`], so the number on
    /// the wire moves only when the application really took bytes.
    bytes_consumed: AtomicU64,
    /// The window this side is currently *advertising*: how many bytes the peer may hold
    /// unacknowledged-by-the-application at once. Auto-tuned upward by
    /// [`Stream::tune_recv_window`] and never above [`MAX_RECV_WINDOW`].
    advertised_recv_window: AtomicU32,
    /// Measurement interval backing the auto-tuner. A plain sync mutex — taken only by the
    /// single delivery task that credits this stream, and never held across an `.await`.
    recv_window_probe: std::sync::Mutex<RecvWindowProbe>,
    /// Bytes the local application has consumed since the last emitted `WINDOW_UPDATE`.
    /// Used to decide when to send the next one, so the wire is not flooded with tiny
    /// updates. Accumulated and reset in one compare-exchange transition, which is what
    /// keeps a reset from discarding bytes credited while it was being computed.
    bytes_since_last_update: AtomicU32,
    /// Pending cumulative flow-control limit to advertise in a `WINDOW_UPDATE`, staged by
    /// the receive **delivery** task (which moves the limit only on *real* app consumption)
    /// and flushed by the **send loop** — the sole *outbound* writer, so the encrypted
    /// control frame is sealed by the same task that stamps every data packet, under the
    /// epoch live at flush time. (The epoch itself has TWO writers — the send loop's own
    /// `rekey()` and the receive task's authenticated forward catch-up in
    /// `decrypt_packet_accepting_rekey` — but both serialise through the session's
    /// `rekey_lock`, so the send loop always seals under a consistent key.)
    ///
    /// Stagings resolve by **maximum**, not by sum: the value is a total, so two stagings
    /// between one pair of flushes are two statements about the same quantity and the later,
    /// larger one subsumes the earlier. `0` = nothing pending, which is unambiguous because
    /// a real limit is never below [`INITIAL_STREAM_WINDOW`].
    pending_window_update: AtomicU64,
    /// RFC 6298 retransmission-timeout estimator. A plain (sync) mutex: it is
    /// updated only from the serial ACK path and read by `poll_send`, and the
    /// guard is never held across an `.await`.
    rto: std::sync::Mutex<RtoEstimator>,
    /// Receive instant of the most recent reliable data packet, used to populate
    /// the SACK's `ack_delay_us` (`now − recv_at`). A plain sync mutex; the guard
    /// is never held across an `.await`.
    last_data_recv_at: std::sync::Mutex<Option<tokio::time::Instant>>,
    /// When the last flow-control persist probe left, or `None` if this stream has never
    /// needed one. See [`Stream::try_persist_probe`]. A plain sync mutex, taken only from
    /// `poll_send` and never held across an `.await`.
    persist_probe_at: std::sync::Mutex<Option<tokio::time::Instant>>,
    /// One past the highest reliable offset the peer has acknowledged, or `0` when it has
    /// acknowledged none — offsets start at zero, so the count is what distinguishes "never"
    /// from "offset 0". It is the offset [`Stream::try_persist_probe`] repeats, and it is
    /// deliberately the *acknowledged* high-water mark rather than the sent one: an offset
    /// the peer has already delivered is one it will discard as a duplicate, which is what
    /// keeps a probe from disturbing its reassembly or its SACK.
    highest_acked_plus_one: AtomicU32,
    /// Receive-window growth budget shared with every other stream of the same session.
    recv_tuning: Arc<SharedRecvTuning>,
}

impl Stream {
    /// Create a new stream with a growth budget of its own.
    ///
    /// Every stream of a live session shares one [`SharedRecvTuning`] — see
    /// [`Self::with_recv_tuning`], which is what the session pump uses. This constructor
    /// exists for standalone streams (tests, and the pull-style read API) where there is no
    /// session to share with; such a stream gets the full budget to itself, which is the
    /// same thing as being the session's only stream.
    pub fn new(id: StreamId) -> Self {
        Self::with_recv_tuning(id, Arc::new(SharedRecvTuning::default()))
    }

    /// Create a stream that draws its receive-window growth from `recv_tuning`, the state
    /// its session shares across all of its streams.
    pub fn with_recv_tuning(id: StreamId, recv_tuning: Arc<SharedRecvTuning>) -> Self {
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
            bytes_sent: AtomicU64::new(0),
            peer_send_limit: AtomicU64::new(u64::from(INITIAL_STREAM_WINDOW)),
            bytes_consumed: AtomicU64::new(0),
            advertised_recv_window: AtomicU32::new(INITIAL_STREAM_WINDOW),
            recv_window_probe: std::sync::Mutex::new(RecvWindowProbe::default()),
            bytes_since_last_update: AtomicU32::new(0),
            pending_window_update: AtomicU64::new(0),
            rto: std::sync::Mutex::new(RtoEstimator::new()),
            last_data_recv_at: std::sync::Mutex::new(None),
            persist_probe_at: std::sync::Mutex::new(None),
            highest_acked_plus_one: AtomicU32::new(0),
            recv_tuning,
        }
    }

    /// The receive-tuning state this stream draws on. The session pump hands the same handle
    /// to every stream it creates.
    pub fn recv_tuning(&self) -> &Arc<SharedRecvTuning> {
        &self.recv_tuning
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
    /// receive-window auto-tuning; see `tune_recv_window`.
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

    /// Record that the peer has acknowledged `offset`, keeping the high-water mark the
    /// persist probe repeats. `fetch_max` because acknowledgements arrive out of order and
    /// a SACK re-acks offsets already retired.
    fn note_acked_offset(&self, offset: SequenceNumber) {
        self.highest_acked_plus_one
            .fetch_max(offset.saturating_add(1), Ordering::AcqRel);
    }

    /// The highest reliable offset the peer has acknowledged, or `None` if it has
    /// acknowledged none.
    fn last_acked_offset(&self) -> Option<SequenceNumber> {
        match self.highest_acked_plus_one.load(Ordering::Acquire) {
            0 => None,
            n => Some(n - 1),
        }
    }

    /// Bytes the peer currently allows us to send: its cumulative limit less what has
    /// already gone out. Zero means the stream is stopped until a later `WINDOW_UPDATE`
    /// raises the limit. Reported as a `u32` because it is a difference between two totals
    /// that [`Self::apply_peer_window_limit`] brings within [`MAX_SEND_WINDOW`] of each
    /// other every time it applies an advertisement, and clamped rather than truncated so
    /// it can never read as small when it is large.
    pub fn peer_send_window(&self) -> u32 {
        let limit = self.peer_send_limit.load(Ordering::Acquire);
        let sent = self.bytes_sent.load(Ordering::Acquire);
        limit.saturating_sub(sent).min(u64::from(u32::MAX)) as u32
    }

    /// Total bytes this side has put on the wire for this stream — the sender's half of the
    /// flow-control ledger. Observability / test hook.
    pub fn bytes_sent(&self) -> u64 {
        self.bytes_sent.load(Ordering::Acquire)
    }

    /// Atomically charge `n` bytes against the peer's cumulative limit.
    /// Returns `true` if the bytes fit under the limit (and the sent-byte total was
    /// advanced); `false` if they do not — the caller must wait for a `WINDOW_UPDATE`.
    ///
    /// A total plus a charge that will not fit in a `u64` is refused rather than reduced to
    /// something that will. The limit is a `u64` as well, so a sum past the top of the range
    /// is above every number the peer is able to state, and refusing it is the same answer
    /// this method already gives any other overrun rather than a special case. Computing the
    /// sum first and comparing it afterwards is what makes the state reachable at all: the
    /// clamp on an advertisement saturates, so a sent total near the top of the range leaves
    /// a peer that writes `u64::MAX` holding a limit of exactly `u64::MAX`, a few bytes of
    /// window under it, and an addition that wraps — or, in a debug build, ends the task
    /// draining every stream on the session.
    pub fn try_consume_send_window(&self, n: u32) -> bool {
        let n = u64::from(n);
        let mut sent = self.bytes_sent.load(Ordering::Acquire);
        loop {
            // Re-read the limit on every attempt: a `WINDOW_UPDATE` applied on the receive
            // task between two attempts of this loop is a raise this pass may as well use.
            let limit = self.peer_send_limit.load(Ordering::Acquire);
            let Some(next) = sent.checked_add(n) else {
                return false;
            };
            if next > limit {
                return false;
            }
            match self.bytes_sent.compare_exchange_weak(
                sent,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(actual) => sent = actual,
            }
        }
    }

    /// Process an inbound `WINDOW_UPDATE` from the peer. The payload is a **cumulative
    /// limit** — the total number of bytes the peer is willing to have sent on this stream,
    /// counted from the stream's first byte in the same units this side counts
    /// `bytes_sent`.
    ///
    /// Three properties follow from the quantity being a monotone total rather than an
    /// increment, and between them they are why the frame does not have to be reliable:
    ///
    /// * **idempotent** — applying the same limit twice is a no-op, so a duplicate carries
    ///   no error;
    /// * **reorder-safe** — a stale frame overtaken by a newer one states a smaller total
    ///   and the maximum below discards it;
    /// * **loss-tolerant** — a frame that never arrives costs nothing, because the next one
    ///   states the whole truth rather than the difference since the last.
    ///
    /// The limit is a number the peer writes, so what this side honours is clamped to
    /// `bytes_sent + MAX_SEND_WINDOW`. A compliant peer is never clamped: it advertises
    /// `consumed + its advertised window`, its window is capped at [`MAX_RECV_WINDOW`] —
    /// the same figure — and it cannot have consumed more than this side has sent. What the
    /// clamp denies is the peer that writes an enormous number to buy itself unlimited
    /// permission: it buys one [`MAX_SEND_WINDOW`] beyond what has already gone out, the
    /// same as any other advertisement, and must send another frame for more.
    ///
    /// The middle step of that argument — that the peer cannot have consumed more than this
    /// side has sent — is a property of what each end counts, not a law of nature: it holds
    /// because both ends count reliable bytes and only those. Unreliable data is charged by
    /// neither ([`Stream::record_app_consumed`] declines it, and `poll_send` emits it without
    /// consulting the window), so it cannot walk one end's total past the other's. Count it
    /// on the receiving end alone and the sentence above becomes false by exactly its volume,
    /// with the clamp — written for a peer inventing numbers — spent on one telling the truth.
    pub fn apply_peer_window_limit(&self, limit: u64) {
        let ceiling = self
            .bytes_sent
            .load(Ordering::Acquire)
            .saturating_add(u64::from(MAX_SEND_WINDOW));
        self.peer_send_limit
            .fetch_max(limit.min(ceiling), Ordering::AcqRel);
    }

    /// The window this side currently advertises: the most bytes the peer may hold in our
    /// buffers before it must stop and wait for the application to consume. Starts at
    /// [`INITIAL_STREAM_WINDOW`] and is auto-tuned upward by `tune_recv_window`,
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

    /// Receive-window auto-tuning. Returns `true` when the advertised window just grew, so
    /// the caller can advertise the new, larger limit at once instead of waiting for
    /// consumption to reach its own emission threshold — a peer stalled on the old limit is
    /// waiting for exactly this.
    ///
    /// ## Why the window has to move at all
    ///
    /// A window of `W` bytes whose room reopens one round trip after the data was consumed
    /// is a hard rate ceiling of `W / RTT`, whatever congestion control decides. A fixed
    /// 64 KiB
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
    /// Why `0.4` and not the round `0.5`: room reopens a round trip *after* the
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
    /// 1 MiB cap costs it four doublings, and each one requires the local application to
    /// consume four fifths of the *current* window inside one round-trip-length interval —
    /// ~790 KiB of genuinely consumed data in total, at a rate the peer cannot supply on its
    /// own because the application has to keep up with it. If the application stops, the
    /// window stops where it is.
    ///
    /// The interval itself is not entirely outside the peer's reach, and claiming otherwise
    /// would be the more comfortable statement rather than the true one. On a stream that
    /// also *sends*, `min_rtt` is a real measurement and a peer that delays every one of its
    /// acknowledgements can raise it, which lengthens the interval and so lowers the
    /// consumption rate a doubling has to beat. What that buys is bounded and is not the
    /// dangerous direction: it can only bring the window to the [`MAX_RECV_WINDOW`] ceiling
    /// **sooner**, never past it, and the peer pays for it in its own throughput because
    /// every doubling still has to be earned in bytes the local application actually took.
    /// A receive-only stream — the flow auto-tuning exists for — never feeds its estimator
    /// at all and uses the constant.
    ///
    /// Having paid, the peer may hold one window of unconsumed data on this stream and one
    /// window plus 64 KiB of reorder buffer ([`Self::recv_reorder_byte_limit`]). What bounds
    /// the *session* is not that per-stream number but
    /// [`SESSION_RECV_WINDOW_GROWTH_BUDGET`], which every doubling draws on: 256 streams
    /// cannot each reach the ceiling, because between them they have 8 MiB of growth to
    /// spend. The session-wide worst case works out lower than it was before the ceiling
    /// moved — see that constant for the arithmetic.
    fn tune_recv_window(&self, n: u32) -> bool {
        let window = self.advertised_recv_window.load(Ordering::Acquire);
        if window >= MAX_RECV_WINDOW {
            return false;
        }
        // The path's propagation delay, NOT the smoothed estimate: a saturated forward
        // path inflates smoothed RTT, a longer RTT lowers the rate a window has to beat to
        // grow, and a bigger window queues more — a loop that ends at the cap regardless of
        // what the application is doing. `min_rtt` is what the queue cannot move. A stream
        // that only receives never feeds its own estimator at all, so the fallback is the
        // common case on exactly the flows auto-tuning exists for — see
        // `AUTOTUNE_RTT_FALLBACK` for why that reference stays a constant.
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
            return false;
        };
        let elapsed = now.duration_since(started_at);
        if elapsed < interval {
            return false; // interval still open — keep accumulating
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
            return false; // the application is not keeping up with the window we already gave it
        }

        let next = window.saturating_mul(2).min(MAX_RECV_WINDOW);
        let growth = next - window;
        // The session, not the stream, is what has to fit in memory. Take the growth from
        // the shared budget first: if the session has already committed its allowance to
        // other streams, this one keeps the window it has rather than adding to a total
        // nobody bounded.
        if !self.recv_tuning.try_take_growth(growth) {
            return false;
        }
        match self.advertised_recv_window.compare_exchange(
            window,
            next,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => true,
            // Lost a race with a concurrent grower: its increase stands, ours is dropped
            // rather than compounded — and the budget it drew must go back, or a contended
            // stream would leak the session's allowance one lost race at a time.
            Err(_) => {
                self.recv_tuning.return_growth(growth);
                false
            }
        }
    }

    /// The cumulative flow-control limit this side currently grants the peer on this
    /// stream: every byte the application has consumed, plus one advertised window of room
    /// beyond it. Both terms move only on real application consumption — the second because
    /// `tune_recv_window` is fed from the same place — so the number on the wire is a
    /// statement about what this side has actually digested, never about what has arrived.
    pub fn recv_limit(&self) -> u64 {
        self.bytes_consumed
            .load(Ordering::Acquire)
            .saturating_add(u64::from(self.advertised_recv_window()))
    }

    /// Record that the application has actually consumed `n` bytes from this
    /// stream (called by the receive *delivery* task on real drainage, not
    /// on routing). Advances the consumed total and returns `Some(limit)` — the cumulative
    /// limit to advertise in a `WINDOW_UPDATE` — when it is worth spending a frame on:
    /// either the unreported consumption has crossed half the initial window, or the
    /// advertised window just grew. The half-window threshold trades update frequency
    /// against peer stalls; growth is emitted regardless of it, because a window that just
    /// doubled is precisely the case where the peer is stopped waiting for the room.
    ///
    /// A limit needs no arithmetic on the wire and no separate frame for growth: whatever
    /// moved, the answer is the same sentence, and the peer takes the larger of it and what
    /// it already had.
    ///
    /// `reliable` says whether the bytes arrived on the reliable path, and it decides
    /// whether they count at all. The two ends of this ledger have to measure the same
    /// quantity, and the sending end charges only reliable bytes — unreliable ones leave
    /// `poll_send` before the window is consulted, because nothing retransmits them and no
    /// window can stop them. Counting them here would walk the advertised limit ahead of the
    /// total the peer keeps, by exactly the unreliable volume, and the peer would then have
    /// its own honest advertisement cut down by this side's `bytes_sent + MAX_SEND_WINDOW`
    /// clamp — a bound written for a peer inventing numbers, applied instead to one telling
    /// the truth. They are still delivered, still counted against the delivery backlog, and
    /// still bounded by it; what they are not is a claim about a window neither end applies
    /// to them.
    pub fn record_app_consumed(&self, n: u32, reliable: bool) -> Option<u64> {
        if !reliable {
            return None;
        }
        self.bytes_consumed
            .fetch_add(u64::from(n), Ordering::AcqRel);
        let grew = self.tune_recv_window(n);
        let threshold = INITIAL_STREAM_WINDOW / 2;
        // Accumulate and — on crossing the threshold — clear the accumulator, in one
        // transition rather than a read followed by a write, so bytes credited in between
        // are carried into the next interval instead of being dropped by the reset.
        let mut cur = self.bytes_since_last_update.load(Ordering::Acquire);
        let crossed = loop {
            // Saturating rather than wrapping: what keeps this sum small is the reset in the
            // same transition, not the width of the type, and `n` is the length of something
            // a peer sent.
            let pending = cur.saturating_add(n);
            let (next, crossed) = if pending >= threshold {
                (0, true)
            } else {
                (pending, false)
            };
            match self.bytes_since_last_update.compare_exchange_weak(
                cur,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break crossed,
                Err(actual) => cur = actual,
            }
        };
        (crossed || grew).then(|| self.recv_limit())
    }

    /// Stage a cumulative flow-control limit to be flushed by the send loop. Called by the
    /// receive delivery task after real app consumption moved the limit, and by the receive
    /// task when the peer's persist probe asks for it.
    ///
    /// Stagings resolve by **maximum**: the value is a total, so a second staging before the
    /// send loop has flushed the first is a later statement about the same quantity, and
    /// keeping the larger loses nothing. This is also what makes a failed send safe to
    /// re-stage — see `flush_pending_window_updates`.
    pub fn stage_window_update_limit(&self, limit: u64) {
        self.pending_window_update
            .fetch_max(limit, Ordering::AcqRel);
    }

    /// Take the staged limit (swapping the slot back to `0`). The send loop calls this each
    /// drain pass and emits one `WINDOW_UPDATE` carrying it if `Some`. `0` is the empty
    /// sentinel and cannot collide with a real limit, which is never below
    /// [`INITIAL_STREAM_WINDOW`].
    pub fn take_pending_window_update(&self) -> Option<u64> {
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
            app_limited_at_send: false,
            retries: 0,
            lost: false,
            fin: false,
            charged: false,
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
    /// has stopped emitting the *receive* side's flow-control limits and
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
            app_limited_at_send: false,
            retries: 0,
            lost: false,
            fin: false,
            charged: false,
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
            app_limited_at_send: false,
            retries: 0,
            lost: false,
            fin: true,
            charged: false,
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
            app_limited_at_send: false,
            retries: 0,
            lost: false,
            fin: true,
            charged: false,
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

    /// Hand back the flow-control persist probe, if a stream the peer's window has stopped
    /// is due one.
    ///
    /// A `WINDOW_UPDATE` is sent once, unacknowledged, and nothing retransmits it. Because
    /// it carries a cumulative limit, a lost one costs nothing *provided another follows* —
    /// and the case this exists for is the one where none will: the peer's application has
    /// consumed everything it is going to for now, so it has no reason to speak again, while
    /// this side is stopped at a limit that a lost frame has left below the truth. Nothing
    /// outstanding means no acknowledgement is due either, so the stream has no event left
    /// that could free it.
    ///
    /// The signal has to come from here rather than from the receiver, because the fact that
    /// matters — data queued and no room for it — is only visible on this side. A receiver
    /// cannot tell a peer that is blocked from one that simply has nothing to send: both are
    /// silent, and both leave its own counters unchanged. So it would have to re-advertise
    /// on a timer forever, on every open stream, since no frame in that direction is ever
    /// acknowledged and it could never learn that it may stop.
    ///
    /// The probe is a **zero-length** reliable segment — the [`Self::queue_fin`] sentinel's
    /// shape without the `FIN` flag — so it carries no application byte past a window that
    /// has no room for one. That is the whole of why it is safe: the sender cannot tell a
    /// receiver whose grant was lost from one whose application has simply stopped reading,
    /// and with an empty probe it does not have to. A receiver holding a full window of
    /// unconsumed data is charged nothing at all and stays entitled to keep this side
    /// stopped for as long as its application is not reading — which is flow control
    /// working, not failing.
    ///
    /// It repeats the **highest offset the peer has already acknowledged**, and that choice
    /// is load-bearing rather than economical. A probe on a fresh offset would necessarily
    /// sit above the data the window is holding back, so the peer would park it in its
    /// reorder buffer as an out-of-order island and SACK it there — and an island above the
    /// gap raises `Sack::largest_acked` past every offset this stream sends next, which is
    /// precisely the input RFC 9002's packet threshold reads as loss. Measured on that
    /// design: with a probe SACKed at offset 8, the next two segments were declared lost the
    /// instant they were acknowledged. An acknowledged offset moves nothing, and it is worth
    /// being exact about why, because acknowledged is the weaker of the two properties: a
    /// peer building its SACK the way [`Self::received_sack`] does acknowledges what it has
    /// delivered and what its reorder buffer still holds, and nothing else. If the offset was
    /// delivered, [`Self::accept_in_order`] discards the repeat as a duplicate before it
    /// touches the reorder buffer; if it is still an island, the repeat finds it already
    /// held and is dropped without adding an entry or charging a byte against the reorder
    /// budget. Either way the peer's SACK is unchanged, no offset is consumed and no state
    /// accrues on either side.
    ///
    /// It is therefore not tracked as in flight and nothing retransmits it — an unanswered
    /// probe is simply asked again at the next interval, which is what TCP's persist timer
    /// does too. What bounds it is [`RtoEstimator::MIN_RTO`] under that interval, and the
    /// bound is meaningful because a probe is one small frame carrying nothing: there is no
    /// volume for a second bound to limit. Neither the trigger nor the interval is a value
    /// the peer writes — withholding room is what causes a probe, and withholding it
    /// faster does not make one come sooner.
    ///
    /// The answer comes from the receiver: an empty reliable segment is recognised there as
    /// a probe and re-states that stream's current limit ([`Self::recv_limit`]). That is a
    /// total, not the crumbs held back below an emission threshold, so one answer repairs
    /// however many earlier frames the path ate. It is still bounded by what the local
    /// application took: a receiver whose application has consumed nothing re-states the
    /// limit the peer is already stopped at, and a probing peer extracts nothing it has not
    /// earned however often it asks.
    fn try_persist_probe(
        &self,
        now: tokio::time::Instant,
        anything_in_flight: bool,
    ) -> Option<OutboundSegment> {
        if anything_in_flight {
            return None;
        }
        // A stream the peer has acknowledged nothing on has no offset to repeat, so it does
        // not probe. It should not arrive here — the window only closes by sending, and the
        // precondition above says everything sent has been retired — but declining is the
        // answer to that state rather than inventing an offset, which would land above the
        // gap and cost precisely what repeating one avoids.
        let stream_offset = self.last_acked_offset()?;
        let interval = self.current_rto();
        let mut last = match self.persist_probe_at.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        if last.is_some_and(|at| now.duration_since(at) < interval) {
            return None;
        }
        *last = Some(now);
        Some(OutboundSegment {
            stream_offset,
            data: Bytes::new(),
            reliable: true,
            retransmit: false,
            fin: false,
        })
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
    /// `app_limited_now` is the connection's application-limited phase as it
    /// stands right now, and it is stamped alongside the pair above for the same
    /// reason they are: it is a property of the flight this segment is joining,
    /// not of the moment its acknowledgement happens to arrive. Read at
    /// acknowledgement time instead, it retroactively labels bytes that went out
    /// at full rate with a phase that opened after they left.
    ///
    /// `cwnd_budget` is how many bytes of *new* data the congestion window
    /// currently permits. Retransmissions ignore it — loss recovery must always
    /// proceed — but a first transmission is withheld when it would exceed the
    /// budget, so the next drain resumes once ACKs free the window. Pass
    /// `u64::MAX` to disable the limit.
    ///
    /// The peer's flow-control window bounds a first transmission as well, and it is the
    /// one budget whose replenishment depends on a frame arriving. A stream it has stopped
    /// with nothing outstanding — the state in which no other event can ever come — is
    /// handed the empty persist probe instead of `SendBlocked::FlowControl`. It carries no
    /// application byte, so it is not an exception to the rule that new data stays within
    /// `min(cwnd, window)`; see `try_persist_probe` below.
    pub async fn poll_send(
        &self,
        cwnd_budget: u64,
        delivered_now: u64,
        delivered_time_now: std::time::Instant,
        app_limited_now: bool,
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
        //
        // Whether anything is outstanding is settled here, once, before the pass hands
        // any segment out — inside the loop the answer would change under it. It is the
        // precondition of the persist probe below: nothing outstanding is what proves no
        // acknowledgement is on its way, and so distinguishes a sender the window has
        // merely slowed from one it has stopped for good.
        let anything_in_flight = buffer.iter().any(|p| p.sent_at.is_some());
        let mut flow_control_blocked = false;
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
                //
                // Once, though, and not once per attempt. This pass is reached again by
                // any segment whose send stamp a refused write cleared, and a segment that
                // still holds its charge holds room the peer has already granted for
                // exactly these bytes: asking for that room a second time would both count
                // bytes the wire carries once and — on a window that closed on this very
                // segment — refuse it forever, since the frame that would raise the limit
                // is the one the peer sends after receiving it.
                if !pending.fin && !pending.charged {
                    if !self.try_consume_send_window(len as u32) {
                        // The peer's receive window is the binding constraint — wait for a
                        // WINDOW_UPDATE, not for an acknowledgement. Answered below, once
                        // the borrow on the buffer is gone.
                        flow_control_blocked = true;
                        break;
                    }
                    pending.charged = true;
                }
                let is_fin = pending.fin;
                pending.sent_at = Some(now);
                pending.delivered_at_send = delivered_now;
                pending.delivered_time_at_send = Some(delivered_time_now);
                pending.app_limited_at_send = app_limited_now;
                return Ok(OutboundSegment {
                    stream_offset: pending.stream_offset,
                    data: pending.data.clone(),
                    reliable: true,
                    retransmit: false,
                    fin: is_fin,
                });
            }
        }

        if flow_control_blocked {
            // Waiting is right while an acknowledgement is still owed — it may carry the
            // window open behind it. With nothing outstanding there is no acknowledgement
            // to wait for, and the only frame that could free this stream is the one class
            // of frame nothing retransmits, so this side asks instead of waiting. The probe
            // carries no application byte; see `try_persist_probe`.
            if let Some(probe) = self.try_persist_probe(now, anything_in_flight) {
                return Ok(probe);
            }
            return Err(SendBlocked::FlowControl);
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
            self.note_acked_offset(stream_offset);

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
    ///
    /// The charge these bytes hold against the peer's limit comes back only when no copy of
    /// them has ever been on the wire, and the segment itself is what says so.
    /// `PendingData::retries` is bumped by the two retransmit passes and by nothing else,
    /// so `retries == 0` on a segment whose write was just refused means this attempt was
    /// the only one there has ever been. It is read here rather than taken from the caller
    /// because the caller cannot see it: the charging pass hands out more than first
    /// transmissions — a segment whose retransmission was refused comes back through it —
    /// so "the unsent pass emitted this" and "these bytes have never left" are two different
    /// statements, and only the second one licenses the correction. A retransmission's
    /// charge stays where it is: it was levied when the original left, the peer has those
    /// bytes, and giving it back would put the sent total below what the receiver has
    /// counted — this side granting itself room to overrun a window nobody opened.
    ///
    /// The `PendingData::charged` mark is cleared along with the bytes, so a second call
    /// on one offset takes nothing more, and the subtraction saturates because the two
    /// halves of the ledger are advanced by different paths and an underflow here is not a
    /// small error. Wrapped, the sent total lands just under `u64::MAX`, and the two ends of
    /// that are opposite. Against a peer advertising an honest limit — a finite number far
    /// below the total — [`Self::peer_send_window`] is zero from then on and the stream
    /// never sends again. Against a peer advertising `u64::MAX` the clamp in
    /// [`Self::apply_peer_window_limit`] degenerates, because the ceiling it clamps to is
    /// the sent total plus [`MAX_SEND_WINDOW`] and that addition saturates as well: the
    /// peer's own number is then honoured in full, it holds a few bytes of window under it,
    /// and the charge for them is an addition at the very top of the range —
    /// [`Self::try_consume_send_window`] refuses that one rather than wrapping on it.
    pub async fn mark_unsent(&self, stream_offset: SequenceNumber) {
        // Held across the correction so the bytes and the mark that records them move
        // together: the pass that levies a charge runs under this same lock, and the
        // acknowledgement that retires a segment outright runs under it on another task.
        let mut buffer = self.send_buffer.lock().await;
        if let Some(pending) = buffer.iter_mut().find(|p| p.stream_offset == stream_offset) {
            pending.sent_at = None;
            if pending.charged && pending.retries == 0 {
                let uncharge = pending.data.len() as u64;
                pending.charged = false;
                let _ = self
                    .bytes_sent
                    .fetch_update(Ordering::AcqRel, Ordering::Acquire, |sent| {
                        Some(sent.saturating_sub(uncharge))
                    });
            }
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
                self.note_acked_offset(pending.stream_offset);
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
                    app_limited_at_send: pending.app_limited_at_send,
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

impl Drop for Stream {
    /// Hand this stream's share of the session's receive-window growth back.
    ///
    /// Without this a session that opens and closes streams over its lifetime would spend
    /// its allowance once and leave every later stream pinned at the initial window, which
    /// is the same failure the budget exists to prevent, only slower. The buffers the growth
    /// paid for are being released with the stream, so returning the credit is exactly
    /// accurate rather than optimistic.
    fn drop(&mut self) {
        let grown = self
            .advertised_recv_window
            .load(Ordering::Acquire)
            .saturating_sub(INITIAL_STREAM_WINDOW);
        self.recv_tuning.return_growth(grown);
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

    /// The reorder-buffer entry cap has to sit in a window, and both walls are real.
    ///
    /// **Above** the number of segments one maximum flow-control window can hold: below
    /// that the entry cap, not the byte budget, becomes the binding constraint, and the
    /// receiver starts refusing legitimate out-of-order data on exactly the long lossy
    /// paths a large window exists for. The segment count is `MAX_RECV_WINDOW` divided by
    /// the application chunk size, so it moves whenever either does — which is why this is
    /// computed here rather than restated as a number.
    ///
    /// **Below** the point where the entries' own unaccounted cost dominates. The byte
    /// budget counts payload only; an entry also costs a deque slot, a `Vec<Bytes>` and the
    /// retained allocation, and none of that is budgeted. A peer sending one-byte segments
    /// above a hole it never fills pays the entry cap, not the byte budget. That wall is a
    /// compile-time assertion next to the constant and is deliberately not restated here:
    /// both of its sides are constants, so a runtime copy would assert at test time what
    /// the build has already proved, and report it later.
    ///
    /// What the compiler cannot prove is the lower wall, because the segment count depends
    /// on the chunk size the datagram budget derives — so that is what this states.
    #[test]
    fn the_reorder_entry_cap_clears_the_segments_one_window_holds() {
        let segments_in_one_window =
            MAX_RECV_WINDOW as usize / crate::transport::mtu::MAX_APP_CHUNK;
        assert!(
            MAX_RECV_REORDER >= 2 * segments_in_one_window,
            "the entry cap ({MAX_RECV_REORDER}) must clear the {segments_in_one_window} \
             segments a full {MAX_RECV_WINDOW}-byte window holds with margin, or it — not \
             the byte budget — is what refuses out-of-order data"
        );
    }

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
            .poll_send(u64::MAX, 0, std::time::Instant::now(), false)
            .await
            .unwrap();
        assert_eq!(seg.stream_offset, 0);
        assert_eq!(seg.data, Bytes::from("hello"));
        assert!(seg.reliable);
        assert!(!seg.retransmit);

        let seg2 = stream
            .poll_send(u64::MAX, 0, std::time::Instant::now(), false)
            .await
            .unwrap();
        assert_eq!(seg2.stream_offset, 1);
        assert_eq!(seg2.data, Bytes::from("world"));
        assert!(seg2.reliable);
        assert!(!seg2.retransmit);

        assert!(stream
            .poll_send(u64::MAX, 0, std::time::Instant::now(), false)
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
            .poll_send(u64::MAX, 0, std::time::Instant::now(), false)
            .await
            .unwrap();
        assert_eq!(seg.stream_offset, 0);
        assert!(seg.reliable);
        assert!(!seg.retransmit);

        // Immediate poll should be None
        assert!(stream
            .poll_send(u64::MAX, 0, std::time::Instant::now(), false)
            .await
            .is_err());

        // Advance 400ms — still under the initial 1s RTO (RFC 6298 (2.1):
        // no RTT samples yet, so the timer sits at the 1-second default).
        tokio::time::advance(std::time::Duration::from_millis(400)).await;
        assert!(stream
            .poll_send(u64::MAX, 0, std::time::Instant::now(), false)
            .await
            .is_err());

        // Advance past the 1s initial RTO (total ~1.1s).
        tokio::time::advance(std::time::Duration::from_millis(700)).await;

        // Now it should retransmit — flagged as a retransmission.
        let seg2 = stream
            .poll_send(u64::MAX, 0, std::time::Instant::now(), false)
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
            .poll_send(u64::MAX, 0, std::time::Instant::now(), false)
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
            .poll_send(u64::MAX, 0, std::time::Instant::now(), false)
            .await
            .unwrap();
        assert_eq!(seg.stream_offset, 0);
        assert!(!seg.retransmit);
        assert!(stream
            .poll_send(u64::MAX, 0, std::time::Instant::now(), false)
            .await
            .is_err());

        // Simulate a send that failed *after* `poll_send` stamped the segment:
        // clear `sent_at` so it is no longer considered in-flight.
        stream.mark_unsent(0).await;

        // It is re-offered immediately — without advancing past the RTO — and as
        // a fresh send (Pass 2), not a retransmission.
        let seg2 = stream
            .poll_send(u64::MAX, 0, std::time::Instant::now(), false)
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
            .poll_send(u64::MAX, 0, std::time::Instant::now(), false)
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
            .poll_send(u64::MAX, 10_000, std::time::Instant::now(), false)
            .await
            .unwrap();
        let second = stream
            .poll_send(u64::MAX, 25_000, std::time::Instant::now(), false)
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

    /// The application-limited phase belongs to the segment, stamped when it
    /// went out — not to the moment its acknowledgement arrives.
    ///
    /// This is the difference between "these bytes left while the sender had
    /// nothing more to give" and "these bytes are being acknowledged now, and
    /// the sender happens to have nothing more to give *now*". The second is
    /// true of the tail of every flight ever sent, so reading the flag at
    /// acknowledgement time labels the whole flight — including the part that
    /// went out at full rate — with a phase that opened after it left. Those are
    /// exactly the samples the bandwidth filter needs.
    #[tokio::test]
    async fn a_retired_segment_reports_the_app_limited_phase_of_its_own_send() {
        let stream = Stream::new(1);
        stream
            .send_reliable(Bytes::from("full-rate"))
            .await
            .unwrap();
        stream
            .send_reliable(Bytes::from("ran-dry!!"))
            .await
            .unwrap();

        // The first segment leaves while the connection is sending at full
        // rate; the second leaves after the sender has been marked.
        let saturated = stream
            .poll_send(u64::MAX, 0, std::time::Instant::now(), false)
            .await
            .unwrap();
        let starved = stream
            .poll_send(u64::MAX, 0, std::time::Instant::now(), true)
            .await
            .unwrap();

        // Both are acknowledged by one SACK, arriving at a single instant with a
        // single connection-level phase in force. Only a per-segment stamp can
        // tell them apart.
        let sack = Sack::from_received(&[saturated.stream_offset, starved.stream_offset], 0)
            .expect("sack covering both");
        let retired = stream.on_sack(&sack).await.retired;
        assert_eq!(retired.len(), 2, "both segments are covered");

        let mut flags: Vec<bool> = retired.iter().map(|r| r.app_limited_at_send).collect();
        flags.sort_unstable();
        assert_eq!(
            flags,
            vec![false, true],
            "the two segments came back with the same phase; the flag was read from \
             the connection when the acknowledgement landed rather than stamped on \
             each segment when it went out"
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
            .poll_send(u64::MAX, 1_000, std::time::Instant::now(), false)
            .await
            .unwrap();
        assert!(!head.retransmit);
        let mut acked = Vec::new();
        for _ in 0..5u32 {
            let seg = stream
                .poll_send(u64::MAX, 1_000, std::time::Instant::now(), false)
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
            .poll_send(u64::MAX, 7_000, std::time::Instant::now(), false)
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
            .poll_send(10, 0, std::time::Instant::now(), false)
            .await
            .unwrap();
        assert_eq!(seg.data.len(), 10);
        assert!(!seg.retransmit);

        // Budget of 4 is too small for the next (5-byte) segment → withheld.
        assert!(stream
            .poll_send(4, 0, std::time::Instant::now(), false)
            .await
            .is_err());

        // A budget of 5 now admits it.
        let seg2 = stream
            .poll_send(5, 0, std::time::Instant::now(), false)
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
                .poll_send(u64::MAX, 0, std::time::Instant::now(), false)
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
                .poll_send(u64::MAX, 0, std::time::Instant::now(), false)
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
            .poll_send(u64::MAX, 0, std::time::Instant::now(), false)
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
            .poll_send(u64::MAX, 0, std::time::Instant::now(), false)
            .await
            .expect("first send");

        // Force a retransmit by crossing the RTO, so retries > 0.
        tokio::time::advance(Duration::from_millis(1100)).await;
        let retx = stream
            .poll_send(u64::MAX, 0, std::time::Instant::now(), false)
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
                .poll_send(u64::MAX, 0, std::time::Instant::now(), false)
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
            .poll_send(0, 0, std::time::Instant::now(), false)
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
            .poll_send(u64::MAX, 0, std::time::Instant::now(), false)
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
            .poll_send(u64::MAX, 0, std::time::Instant::now(), false)
            .await
            .expect("send 1");
        let _ = stream
            .poll_send(u64::MAX, 0, std::time::Instant::now(), false)
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
                .poll_send(u64::MAX, 0, std::time::Instant::now(), false)
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
                .poll_send(u64::MAX, 0, std::time::Instant::now(), false)
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
            .poll_send(u64::MAX, 0, std::time::Instant::now(), false)
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
                .poll_send(u64::MAX, 0, std::time::Instant::now(), false)
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
            .poll_send(u64::MAX, 0, std::time::Instant::now(), false)
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
                    .poll_send(u64::MAX, 0, std::time::Instant::now(), false)
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
                .poll_send(u64::MAX, est.delivered_bytes(), est.delivered_time(), false)
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
                .poll_send(u64::MAX, est.delivered_bytes(), est.delivered_time(), false)
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

    /// Deliver `delivered` offsets in order, then plant `islands` single-offset holes above
    /// the resulting hole so the SACK range set is `1 + islands` entries wide.
    async fn stream_with_islands(delivered: u32, islands: u32) -> Stream {
        let stream = Stream::new(1);
        for seq in 0..delivered {
            let _ = stream
                .accept_in_order(seq, vec![Bytes::from_static(b"x")])
                .await;
        }
        // The offset `delivered` itself stays missing, so every island below is a
        // separate range; the extra `2 * i` keeps them non-adjacent.
        for i in 0..islands {
            let _ = stream
                .accept_in_order(delivered + 1 + 2 * i, vec![Bytes::from_static(b"x")])
                .await;
        }
        stream
    }

    /// **The truncation defect.** A receiver holding more islands than the wire form can
    /// carry must still acknowledge the contiguous run it has already delivered. That run
    /// is the one range the sender cannot reconstruct from anything else: without it every
    /// segment in it stays in the send buffer, falls `PACKET_THRESHOLD` behind
    /// `largest_acked`, and is retransmitted as a whole window of bogus loss.
    #[tokio::test]
    async fn received_sack_over_the_range_cap_still_acks_the_cumulative_run() {
        const DELIVERED: u32 = 100;
        let stream = stream_with_islands(DELIVERED, 40).await;

        let sack = stream.received_sack(0).await.expect("non-empty");
        assert!(
            sack.ranges().len() <= crate::transport::sack::MAX_SACK_RANGES,
            "the emitted SACK must fit the wire form: {} ranges",
            sack.ranges().len()
        );
        assert!(
            sack.acks(0),
            "the cumulative run was dropped: SACK {:?} does not ack offset 0",
            sack.ranges()
        );
        assert!(
            sack.acks(DELIVERED - 1),
            "the cumulative run was dropped: SACK {:?} does not ack offset {}",
            sack.ranges(),
            DELIVERED - 1
        );
    }

    /// The common case must not move. With the island count inside the cap the emitted
    /// range set is exactly the ascending set reversed — no reordering, no reshuffling —
    /// so the bytes on the wire are what they always were. This is what rejects a fix that
    /// changes the range order for every SACK rather than only for the ones that overflow.
    #[tokio::test]
    async fn received_sack_under_the_range_cap_is_unchanged() {
        const DELIVERED: u32 = 50;
        const ISLANDS: u32 = 31; // 1 cumulative + 31 islands == the 32-range cap exactly
        let stream = stream_with_islands(DELIVERED, ISLANDS).await;

        let sack = stream.received_sack(0).await.expect("non-empty");

        // What the ascending build produces, reversed: cumulative run last, islands
        // descending above it.
        let mut expected: Vec<(u32, u32)> = vec![(0, DELIVERED - 1)];
        for i in 0..ISLANDS {
            let s = DELIVERED + 1 + 2 * i;
            expected.push((s, s));
        }
        expected.reverse();
        assert_eq!(sack.ranges(), expected.as_slice());

        // And the wire bytes follow from the range set, so pinning the set pins the bytes.
        let round_tripped = Sack::from_wire(&sack.to_wire()).expect("decodes");
        assert_eq!(round_tripped.ranges(), expected.as_slice());
    }

    /// The sender side of the same defect. Given the SACK a receiver with 40 islands
    /// emits, `on_sack` must retire the whole cumulative run and declare none of it lost.
    /// Before the fix the run was not in the SACK at all, so every one of its segments
    /// stayed buffered and was flagged lost by the packet threshold.
    #[tokio::test]
    async fn on_sack_over_the_range_cap_retires_the_cumulative_run() {
        const DELIVERED: u32 = 60;
        const ISLANDS: u32 = 40;

        // A sender that has put offsets 0..DELIVERED+2*ISLANDS on the wire.
        let sender = Stream::new(1);
        let total = DELIVERED + 1 + 2 * ISLANDS;
        for i in 0..total {
            let off = sender
                .send_reliable(Bytes::from(format!("seg-{i}")))
                .await
                .unwrap();
            assert_eq!(off, i);
            let seg = sender
                .poll_send(u64::MAX, 0, std::time::Instant::now(), false)
                .await
                .expect("poll");
            assert_eq!(seg.stream_offset, i);
        }

        // The SACK its peer would build having delivered 0..DELIVERED-1 and buffered the
        // islands above the hole at DELIVERED.
        let receiver = stream_with_islands(DELIVERED, ISLANDS).await;
        let sack = receiver.received_sack(0).await.expect("non-empty");

        let result = sender.on_sack(&sack).await;

        assert!(
            result.retired.len() as u32 >= DELIVERED,
            "one SACK must retire at least the whole cumulative run 0..{}; retired {}",
            DELIVERED - 1,
            result.retired.len()
        );
        for off in 0..DELIVERED {
            assert!(
                !result.lost.iter().any(|l| l.stream_offset == off),
                "offset {off} is delivered data the SACK covers — it must not be declared lost"
            );
            assert!(
                sender.ack(off).await.is_none(),
                "offset {off} is still in the send buffer — the SACK did not retire it"
            );
        }
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
    fn try_consume_send_window_charges_the_sent_total_atomically() {
        let s = Stream::new(1);
        assert!(s.try_consume_send_window(1000));
        assert_eq!(s.bytes_sent(), 1000);
        assert_eq!(s.peer_send_window(), INITIAL_STREAM_WINDOW - 1000);
        assert!(s.try_consume_send_window(INITIAL_STREAM_WINDOW - 1000));
        assert_eq!(s.bytes_sent(), u64::from(INITIAL_STREAM_WINDOW));
        assert_eq!(s.peer_send_window(), 0);
        // Nothing more fits under the limit until a later WINDOW_UPDATE raises it.
        assert!(!s.try_consume_send_window(1));
    }

    /// **The three properties of a cumulative limit**, each asserted by name, because they
    /// are the whole reason the frame carrying it does not have to be reliable.
    #[test]
    fn a_cumulative_limit_is_idempotent_reorder_safe_and_loss_tolerant() {
        let s = Stream::new(1);
        assert!(s.try_consume_send_window(INITIAL_STREAM_WINDOW - 100));
        assert_eq!(s.peer_send_window(), 100);
        let sent = s.bytes_sent();

        // Loss-tolerant: whatever was in the frames that never arrived, this one states the
        // total outright, so the window it leaves behind does not depend on them.
        s.apply_peer_window_limit(sent + 1100);
        assert_eq!(s.peer_send_window(), 1100);

        // Idempotent: the same total restated is the same room, not more of it.
        s.apply_peer_window_limit(sent + 1100);
        assert_eq!(s.peer_send_window(), 1100);

        // Reorder-safe: a stale, smaller total arriving late does not shrink the window.
        s.apply_peer_window_limit(sent + 200);
        assert_eq!(s.peer_send_window(), 1100);

        // And a genuinely larger one does raise it — the same test in the other direction,
        // so "ignores the small one" cannot pass by ignoring everything.
        s.apply_peer_window_limit(sent + 1150);
        assert_eq!(s.peer_send_window(), 1150);
    }

    /// **What an absurd advertisement buys.** The limit is a number the peer writes, so the
    /// bound on it has to be local: this side honours at most one [`MAX_SEND_WINDOW`] beyond
    /// what it has already put on the wire, and the peer has to send another frame for more.
    #[test]
    fn an_absurd_limit_buys_one_max_send_window_and_no_more() {
        let s = Stream::new(1);
        assert!(s.try_consume_send_window(INITIAL_STREAM_WINDOW));
        let sent = s.bytes_sent();

        s.apply_peer_window_limit(u64::MAX);
        assert_eq!(
            s.peer_send_window(),
            MAX_SEND_WINDOW,
            "a peer advertising u64::MAX bought more than the local cap allows"
        );

        // Having spent it, the same absurd advertisement is worth nothing further until the
        // sent total moves again — and it only moves by bytes that actually went out.
        assert!(s.try_consume_send_window(MAX_SEND_WINDOW));
        assert_eq!(s.bytes_sent(), sent + u64::from(MAX_SEND_WINDOW));
        s.apply_peer_window_limit(u64::MAX);
        assert_eq!(
            s.peer_send_window(),
            MAX_SEND_WINDOW,
            "the clamp is re-evaluated against the bytes sent since, so it is a rate of \
             permission per frame rather than a one-off ceiling"
        );
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
        s.record_app_consumed(1, true); // opens the first interval

        // 16 KiB per 400 ms interval = 40 KiB/s, under a third of the 128 KiB/s threshold.
        for _ in 0..10 {
            tokio::time::advance(Duration::from_millis(400)).await;
            s.record_app_consumed(16 * 1024, true);
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
        s.record_app_consumed(1, true);

        // 128 KiB per 400 ms = 320 KiB/s, two and a half times the 128 KiB/s threshold at
        // the initial window — one doubling per closed interval.
        tokio::time::advance(Duration::from_millis(400)).await;
        s.record_app_consumed(128 * 1024, true);
        assert_eq!(s.advertised_recv_window(), 2 * INITIAL_STREAM_WINDOW);
        assert_eq!(
            s.recv_reorder_byte_limit(),
            3 * INITIAL_STREAM_WINDOW as usize,
            "the reorder budget tracks the window it has to hold out-of-order data for"
        );

        // Keep outrunning it: the window climbs to the cap and then stops for good.
        for _ in 0..12 {
            tokio::time::advance(Duration::from_millis(400)).await;
            s.record_app_consumed(MAX_RECV_WINDOW, true);
        }
        assert_eq!(s.advertised_recv_window(), MAX_RECV_WINDOW);
        assert_eq!(
            s.recv_reorder_byte_limit(),
            MAX_RECV_REORDER_BYTES_CEILING,
            "and the reorder budget stops with it"
        );
    }

    /// **The ceiling defect, and the constraint that bounds the fix.** A window of
    /// `W` bytes admits `W / RTT` bytes per second whatever else is true, so the ceiling on
    /// `W` is a hard rate ceiling on every stream. On the path this was measured on — 235 ms
    /// RTT — the old 512 KiB ceiling admitted 2 230 828 B/s, i.e. 17.85 Mbit/s, while raw
    /// one-way UDP over that same path carried 41.8 and 42.9 Mbit/s in two runs, and
    /// server-side samples showed inflight pinned flat against the cap at 492–520 KB run
    /// after run.
    ///
    /// What stops the answer being "make it enormous" is measured here rather than asserted
    /// in prose: a stream's ARQ send buffer holds a fixed number of segments, so there is a
    /// hard limit on what one stream can have outstanding however large a window it is
    /// granted, and receive window above that limit is memory committed for data that cannot
    /// arrive. The ceiling must sit under it — shrink the send buffer and the assertion
    /// below is what says so, since the constant that would otherwise catch it is checked
    /// against `MAX_PENDING_PACKETS` rather than against the permits actually issued.
    #[tokio::test]
    async fn the_recv_window_ceiling_stays_within_what_the_send_buffer_can_put_in_flight() {
        tokio::time::pause();

        // Fill one stream's ARQ send buffer with full-size segments until it refuses more.
        // That total is the most this stream can ever have unacknowledged.
        let s = Stream::new(1);
        let chunk = Bytes::from(vec![0u8; crate::transport::mtu::MAX_APP_CHUNK]);
        let mut buffered = 0usize;
        while tokio::time::timeout(Duration::from_secs(1), s.send_reliable(chunk.clone()))
            .await
            .is_ok()
        {
            buffered += chunk.len();
            assert!(
                buffered < 8 * 1024 * 1024,
                "the send buffer accepted {buffered} B without ever blocking — this test no \
                 longer measures what it thinks it does"
            );
        }

        assert!(
            MAX_RECV_WINDOW as usize <= buffered,
            "the window ceiling ({MAX_RECV_WINDOW} B) advertises room for more than one \
             stream can ever have in flight ({buffered} B): the send buffer, not the \
             window, is what decides the rate above that point, and the excess is memory \
             held for data that cannot arrive"
        );
        // What that admits on the measured path, in the units the defect was reported in:
        // 1 MiB / 0.235 s = 4 461 655 B/s = 35.7 Mbit/s, against 17.85 Mbit/s before.
        const PATH_RTT_MS: u64 = 235;
        let ceiling_bits_per_sec = u64::from(MAX_RECV_WINDOW) * 8 * 1000 / PATH_RTT_MS;
        assert!(
            ceiling_bits_per_sec > 30_000_000,
            "the window ceiling admits only {ceiling_bits_per_sec} bit/s at a {PATH_RTT_MS} \
             ms RTT"
        );

        // And the tuner reaches it. Four doublings from the 64 KiB initial window, one per
        // closed measurement interval, so the ceiling is 1.6 s of sustained consumption away
        // — not a ladder that outlives the transfer it is meant to accelerate.
        let t = Stream::new(2);
        t.record_app_consumed(1, true);
        let mut intervals = 0u32;
        while t.advertised_recv_window() < MAX_RECV_WINDOW {
            tokio::time::advance(Duration::from_millis(400)).await;
            t.record_app_consumed(MAX_RECV_WINDOW, true);
            intervals += 1;
            assert!(
                intervals <= 6,
                "the tuner did not reach the ceiling within 6 measurement intervals; it \
                 stalled at {} B",
                t.advertised_recv_window()
            );
        }
        assert_eq!(t.advertised_recv_window(), MAX_RECV_WINDOW);
    }

    /// The per-stream ceiling is not what bounds a session. Sixteen streams that each earn
    /// the ceiling would commit 15 MiB of growth between them; the session-wide budget is
    /// what says they may not, and it says so without denying any single stream the ceiling
    /// (the test above shows a lone stream still reaching it).
    #[tokio::test]
    async fn the_session_growth_budget_bounds_every_stream_together() {
        tokio::time::pause();
        let tuning = Arc::new(SharedRecvTuning::default());
        let streams: Vec<Stream> = (1..=16u16)
            .map(|id| Stream::with_recv_tuning(id, tuning.clone()))
            .collect();

        for s in &streams {
            s.record_app_consumed(1, true); // open each interval
        }
        // Far more sustained consumption than the whole budget is worth, on every stream at
        // once — the growth has to stop because the session ran out, not because the
        // applications did.
        for _ in 0..40 {
            tokio::time::advance(Duration::from_millis(400)).await;
            for s in &streams {
                s.record_app_consumed(MAX_RECV_WINDOW, true);
            }
        }

        let total_growth: u64 = streams
            .iter()
            .map(|s| u64::from(s.advertised_recv_window() - INITIAL_STREAM_WINDOW))
            .sum();
        assert!(
            total_growth <= u64::from(SESSION_RECV_WINDOW_GROWTH_BUDGET),
            "sixteen streams grew by {total_growth} B against a \
             {SESSION_RECV_WINDOW_GROWTH_BUDGET} B session budget"
        );
        // And the budget is what stopped them, not the per-stream ceiling: unconstrained,
        // sixteen streams at this ceiling would have taken half again as much.
        let unconstrained =
            u64::from(MAX_RECV_WINDOW - INITIAL_STREAM_WINDOW) * streams.len() as u64;
        assert!(
            unconstrained > u64::from(SESSION_RECV_WINDOW_GROWTH_BUDGET),
            "this test no longer exercises the budget: sixteen streams at the ceiling want \
             {unconstrained} B, which the {SESSION_RECV_WINDOW_GROWTH_BUDGET} B budget already \
             covers"
        );
        assert_eq!(
            u64::from(tuning.remaining_growth_budget()),
            u64::from(SESSION_RECV_WINDOW_GROWTH_BUDGET) - total_growth,
            "the budget accounting must match the windows actually handed out"
        );
        // And the reorder memory the session can be made to hold follows from it: one budget
        // plus one initial window per stream, whatever the per-stream ceiling is.
        let reorder: usize = streams.iter().map(|s| s.recv_reorder_byte_limit()).sum();
        assert!(
            reorder
                <= SESSION_RECV_WINDOW_GROWTH_BUDGET as usize
                    + 2 * streams.len() * INITIAL_STREAM_WINDOW as usize
        );
    }

    /// A long-lived session opens and closes streams. If growth were spent for good, the
    /// budget would drain away and every later stream would be pinned at the initial window —
    /// the same failure the budget exists to prevent, only slower.
    #[tokio::test]
    async fn a_closed_stream_returns_its_growth_to_the_session() {
        tokio::time::pause();
        let tuning = Arc::new(SharedRecvTuning::default());
        {
            let s = Stream::with_recv_tuning(1, tuning.clone());
            s.record_app_consumed(1, true);
            for _ in 0..8 {
                tokio::time::advance(Duration::from_millis(400)).await;
                s.record_app_consumed(MAX_RECV_WINDOW, true);
            }
            assert_eq!(s.advertised_recv_window(), MAX_RECV_WINDOW);
            assert!(tuning.remaining_growth_budget() < SESSION_RECV_WINDOW_GROWTH_BUDGET);
        }
        assert_eq!(
            tuning.remaining_growth_budget(),
            SESSION_RECV_WINDOW_GROWTH_BUDGET,
            "the closed stream's buffers are gone; its share of the budget must be too"
        );
    }

    /// **The RTT reference is a constant on purpose.** A stream that only receives never puts
    /// a reliable segment on the wire, so `record_rtt_sample` — reached only from `ack` and
    /// `on_sack`, both send-side — is never called and `min_rtt()` stays `None` for the life
    /// of the transfer. That is the case auto-tuning exists for, and the obvious repair is to
    /// feed it a round trip observed elsewhere in the connection.
    ///
    /// It must not be. The interval is `2 × rtt_used` and growth requires the application to
    /// consume `0.8 × window` inside it, so the consumption rate a peer has to be outrun by
    /// is inversely proportional to `rtt_used` — and every round trip this side could observe
    /// before application data moves is one the far end sets by choosing when to answer. What
    /// this pins is the direction: whatever the peer does, the bar this side holds it to is
    /// the same one, and it comes from a constant.
    #[tokio::test]
    async fn the_growth_bar_does_not_move_with_anything_the_peer_controls() {
        tokio::time::pause();

        // A trickle: 30 KB/s, against the 131 KB/s that the 64 KiB window at the 200 ms
        // reference demands (0.8 × 64 KiB / 0.4 s). Sustained for eight minutes of simulated
        // time — far longer than any handshake gap a peer could introduce and then exploit.
        let s = Stream::new(1);
        s.record_app_consumed(1, true);
        for _ in 0..480 {
            tokio::time::advance(Duration::from_secs(1)).await;
            s.record_app_consumed(30_000, true);
        }
        assert_eq!(
            s.advertised_recv_window(),
            INITIAL_STREAM_WINDOW,
            "a trickle earned window growth — the consumption bar is being computed against \
             something other than the fixed reference"
        );

        // And the bar is still met by an application that genuinely keeps up, so the test
        // above is not passing merely because growth is broken.
        let fast = Stream::new(2);
        fast.record_app_consumed(1, true);
        for _ in 0..8 {
            tokio::time::advance(Duration::from_millis(400)).await;
            fast.record_app_consumed(MAX_RECV_WINDOW, true);
        }
        assert_eq!(fast.advertised_recv_window(), MAX_RECV_WINDOW);
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
        s.record_app_consumed(1, true);

        // 256 KiB drains through in 50 ms — four windows' worth, at 5 MiB/s.
        for _ in 0..256 {
            s.record_app_consumed(1024, true);
            tokio::time::advance(Duration::from_micros(195)).await;
        }
        assert_eq!(
            s.advertised_recv_window(),
            INITIAL_STREAM_WINDOW,
            "no interval has closed yet, so there is nothing to conclude"
        );

        // The interval closes and the burst buys exactly one doubling …
        tokio::time::advance(Duration::from_millis(400)).await;
        s.record_app_consumed(1024, true);
        assert_eq!(s.advertised_recv_window(), 2 * INITIAL_STREAM_WINDOW);

        // … after which the real reader rate governs, and it is far below the threshold.
        for _ in 0..10 {
            tokio::time::advance(Duration::from_millis(400)).await;
            s.record_app_consumed(1024, true);
        }
        assert_eq!(
            s.advertised_recv_window(),
            2 * INITIAL_STREAM_WINDOW,
            "a one-off burst must not be mistaken for a sustained rate"
        );
    }

    /// A window increase reaches the peer as an ordinary raised limit — no separate frame,
    /// no arithmetic — and is emitted at once rather than waiting for consumption to reach
    /// its own threshold, because the peer is stopped on exactly this room.
    #[tokio::test]
    async fn window_growth_is_advertised_immediately_as_a_raised_limit() {
        tokio::time::pause();
        let s = Stream::new(1);
        s.record_app_consumed(1, true);

        // Mid-interval, consumption crosses its own update threshold and is flushed …
        tokio::time::advance(Duration::from_millis(200)).await;
        let consumed = 60u64 * 1024 + 1;
        assert_eq!(
            s.record_app_consumed(60 * 1024, true),
            Some(consumed + u64::from(INITIAL_STREAM_WINDOW))
        );

        // … so when the interval closes, the growth is what makes the next one worth
        // emitting: the 8 KiB of consumption is nowhere near the threshold on its own.
        tokio::time::advance(Duration::from_millis(200)).await;
        let limit = s
            .record_app_consumed(8 * 1024, true)
            .expect("growth is advertised");
        assert_eq!(
            limit,
            consumed + 8 * 1024 + u64::from(2 * INITIAL_STREAM_WINDOW),
            "the limit is everything consumed plus the window that just doubled"
        );

        // A peer applying it may send up to that total, having sent nothing yet.
        let peer = Stream::new(1);
        peer.apply_peer_window_limit(limit);
        assert_eq!(peer.peer_send_window(), MAX_SEND_WINDOW.min(limit as u32));
    }

    #[test]
    fn record_app_consumed_advertises_the_limit_after_the_threshold() {
        let s = Stream::new(1);
        let threshold = INITIAL_STREAM_WINDOW / 2;

        // Small drains move the limit but are not worth a frame.
        assert!(s.record_app_consumed(100, true).is_none());
        assert!(s.record_app_consumed(200, true).is_none());

        // Drain across the half-window threshold → advertise the cumulative limit:
        // everything consumed so far plus one advertised window of room beyond it.
        assert_eq!(
            s.record_app_consumed(threshold, true),
            Some(u64::from(300 + threshold + INITIAL_STREAM_WINDOW)),
            "WINDOW_UPDATE carries the total the peer may send, not the increment"
        );

        // The emission accumulator resets — small further drains do not re-emit — but the
        // limit itself keeps rising underneath, so the next frame states the truth including
        // everything withheld in between.
        assert!(s.record_app_consumed(10, true).is_none());
        assert_eq!(
            s.recv_limit(),
            u64::from(310 + threshold + INITIAL_STREAM_WINDOW)
        );
    }

    /// **Both ends of the ledger must count the same bytes.**
    ///
    /// The sending end charges reliable bytes only — unreliable ones leave `poll_send`
    /// before the window is consulted, and nothing about them is retransmitted or
    /// windowed. If the receiving end counted them, the limit it advertises would run
    /// ahead of the total its peer keeps by exactly the unreliable volume, and the peer's
    /// honest advertisement would then be cut down by this side's `bytes_sent +
    /// MAX_SEND_WINDOW` clamp — a bound written for a peer inventing numbers, spent on one
    /// telling the truth. The two documents that describe the clamp say a conforming peer
    /// is never clamped by it; this is the arithmetic that has to hold for that to be true.
    #[test]
    fn unreliable_bytes_do_not_move_the_limit_the_sender_is_measured_against() {
        let s = Stream::new(1);
        let opening = s.recv_limit();

        // A whole window of unreliable data, delivered and consumed. It is real traffic and
        // the application really read it — what it is not is bytes the peer charged itself
        // for, so the number this side puts on the wire must not move.
        for _ in 0..8 {
            assert!(
                s.record_app_consumed(INITIAL_STREAM_WINDOW / 8, false)
                    .is_none(),
                "unreliable consumption asked for a WINDOW_UPDATE"
            );
        }
        assert_eq!(
            s.recv_limit(),
            opening,
            "unreliable bytes advanced the limit the sender is measured against"
        );

        // Reliable consumption on the same stream still moves it, so the guard above is a
        // distinction between two paths rather than an accounting that stopped working.
        let threshold = INITIAL_STREAM_WINDOW / 2;
        assert_eq!(
            s.record_app_consumed(threshold, true),
            Some(opening + u64::from(threshold)),
            "reliable consumption must still advertise the cumulative total"
        );
    }

    /// The clamp's promise, stated as arithmetic on the two halves of the ledger.
    ///
    /// A conforming peer advertises `its consumed total + its advertised window`; this side
    /// honours at most `bytes_sent + MAX_SEND_WINDOW`. The promise that the first never
    /// exceeds the second holds only while both ends count the same bytes: the peer cannot
    /// have consumed more than this side has sent, and the two windows are the same figure.
    /// Count unreliable bytes on one end only and the promise fails by exactly their volume,
    /// which is what this pins.
    #[test]
    fn a_conforming_peers_advertisement_stays_under_the_local_ceiling() {
        let sender = Stream::new(1);
        let receiver = Stream::new(1);

        // The sender puts one full window of reliable data on the wire, and the receiving
        // application drains exactly that much of it.
        assert!(sender.try_consume_send_window(INITIAL_STREAM_WINDOW));
        receiver.record_app_consumed(INITIAL_STREAM_WINDOW, true);

        // Alongside it flows unreliable traffic, and the application drains that too.
        // Neither end charged it: `poll_send` never consulted the window for those bytes.
        // The volume is one `MAX_SEND_WINDOW`, which is what it takes for the difference to
        // reach the ceiling rather than merely dent the slack under it — a smaller figure
        // would leave the assertion true whichever way the bytes were counted, and prove
        // nothing about the counting.
        let chunk = INITIAL_STREAM_WINDOW;
        for _ in 0..(MAX_SEND_WINDOW / chunk) {
            receiver.record_app_consumed(chunk, false);
        }

        let ceiling = sender.bytes_sent() + u64::from(MAX_SEND_WINDOW);
        assert!(
            receiver.recv_limit() <= ceiling,
            "a conforming peer advertised {} against a local ceiling of {ceiling} — the \
             clamp exists for a peer inventing numbers, not for this one",
            receiver.recv_limit()
        );
    }

    #[test]
    fn the_limit_round_trip_bounds_outstanding_to_one_window() {
        // Model: the receiver advertises `consumed + window`, the sender may send up to it,
        // so outstanding (sent − consumed) never exceeds the advertised window.
        let sender = Stream::new(1);
        let receiver = Stream::new(1);
        let threshold = INITIAL_STREAM_WINDOW / 2;

        // Sender fills the initial window exactly.
        assert!(sender.try_consume_send_window(INITIAL_STREAM_WINDOW));
        assert_eq!(sender.peer_send_window(), 0, "initial window exhausted");

        // Receiver consumes one threshold's worth → advertises that much past the initial
        // window it had already granted.
        let limit = receiver
            .record_app_consumed(threshold, true)
            .expect("threshold crossed");
        sender.apply_peer_window_limit(limit);
        assert_eq!(
            sender.peer_send_window(),
            threshold,
            "sender may now send exactly the bytes the receiver consumed"
        );
        // What the receiver is still holding unconsumed, plus the room it has left open, is
        // exactly one advertised window — the property the whole scheme exists to maintain,
        // stated on the two counters that maintain it.
        let outstanding = sender.bytes_sent() - u64::from(threshold);
        assert_eq!(
            outstanding + u64::from(sender.peer_send_window()),
            u64::from(INITIAL_STREAM_WINDOW),
        );
    }

    #[test]
    fn a_staged_limit_keeps_the_larger_of_two() {
        let s = Stream::new(1);
        assert_eq!(s.take_pending_window_update(), None);

        // Two stagings before a single flush are two statements about the same total, so the
        // later, larger one subsumes the earlier: summing them would advertise a limit
        // nobody's application paid for.
        s.stage_window_update_limit(70_000);
        s.stage_window_update_limit(72_500);
        assert_eq!(s.take_pending_window_update(), Some(72_500));

        // Order does not matter — a lower one staged second must not pull the limit down.
        s.stage_window_update_limit(80_000);
        s.stage_window_update_limit(70_000);
        assert_eq!(s.take_pending_window_update(), Some(80_000));

        // The slot resets to empty once taken.
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
            .poll_send(u64::MAX, 0, std::time::Instant::now(), false)
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
            .poll_send(u64::MAX, 0, std::time::Instant::now(), false)
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
        let seg = stream
            .poll_send(0, 0, std::time::Instant::now(), false)
            .await;
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
            .poll_send(u64::MAX, 0, std::time::Instant::now(), false)
            .await
            .expect("first FIN");
        assert!(seg.fin);
        assert!(!seg.retransmit);

        // Immediate re-poll: nothing (in-flight, RTO not elapsed).
        assert!(stream
            .poll_send(u64::MAX, 0, std::time::Instant::now(), false)
            .await
            .is_err());

        // Advance past the initial 1-second RTO.
        tokio::time::advance(std::time::Duration::from_millis(1100)).await;

        let retx = stream
            .poll_send(u64::MAX, 0, std::time::Instant::now(), false)
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

    // ── Flow-control frames that never arrive ──

    /// What the data pump hands a stream: one application chunk, one segment, one datagram.
    const HARNESS_SEG: usize = crate::transport::mtu::MAX_APP_CHUNK;

    /// Simulated round trip. Above [`RtoEstimator::MIN_RTO`] so a round is also long enough
    /// for anything the retransmit clock owes to come due — the harness must not hide a
    /// stall behind a timer that has not fired yet.
    const HARNESS_ROUND: Duration = Duration::from_millis(250);

    /// Whether a segment `poll_send` handed back is the flow-control persist probe: an empty
    /// reliable segment that is not the FIN sentinel. This is the same test the receive path
    /// applies, and it is stated once here so the harness recognises a probe by what is on
    /// the wire rather than by anything only the sender knows.
    fn is_persist_probe(seg: &OutboundSegment) -> bool {
        seg.reliable && !seg.fin && seg.data.is_empty()
    }

    /// Move `total` bytes from `sender` to `receiver` a round trip at a time, delivering
    /// every segment and every acknowledgement, and dropping the flow-control frames `lose`
    /// selects — by ordinal, so a test names which `WINDOW_UPDATE` datagrams the path ate.
    ///
    /// Dropping one is exactly what losing that datagram does to both ends: the receiver
    /// emitted it and moved on, and the sender never hears it. Nothing else is impaired — no
    /// data is dropped, no acknowledgement is delayed — so anything the sender fails to move
    /// is attributable to the flow-control frames alone.
    ///
    /// The receiver's answer to a probe is modelled the way the pump implements it: an empty
    /// reliable segment is answered with the stream's current limit, and that frame takes an
    /// ordinal like any other and can be lost like any other.
    ///
    /// Returns the number of rounds it took, or `Err(bytes_delivered)` when `max_rounds` ran
    /// out. A stall must report as a bounded assertion, never as a test that hangs.
    async fn move_bytes_losing_grants(
        sender: &Stream,
        receiver: &Stream,
        total: usize,
        max_rounds: usize,
        lose: impl Fn(u64) -> bool,
    ) -> Result<usize, usize> {
        let mut queued = 0usize;
        while queued < total {
            let len = HARNESS_SEG.min(total - queued);
            sender
                .send_reliable(Bytes::from(vec![0u8; len]))
                .await
                .unwrap();
            queued += len;
        }

        let mut delivered = 0usize;
        let mut grant_ordinal = 0u64;
        let mut grant = |sender: &Stream, limit: Option<u64>| {
            if let Some(limit) = limit {
                grant_ordinal += 1;
                if !lose(grant_ordinal) {
                    sender.apply_peer_window_limit(limit);
                }
            }
        };
        for round in 1..=max_rounds {
            // Everything this round allows goes out at once. The congestion window is
            // deliberately unlimited, so flow control is the only thing that can stop it.
            let mut flight = Vec::new();
            while let Ok(seg) = sender
                .poll_send(u64::MAX, 0, std::time::Instant::now(), false)
                .await
            {
                flight.push(seg);
            }
            for seg in &flight {
                for released in receiver
                    .accept_in_order(seg.stream_offset, vec![seg.data.clone()])
                    .await
                {
                    if released.is_empty() {
                        continue; // a probe reaching its turn in the reassembly order
                    }
                    delivered += released.len();
                    grant(
                        sender,
                        receiver.record_app_consumed(released.len() as u32, true),
                    );
                }
                if is_persist_probe(seg) {
                    grant(sender, Some(receiver.recv_limit()));
                }
            }
            for seg in &flight {
                sender.ack(seg.stream_offset).await;
            }
            if delivered >= total {
                return Ok(round);
            }
            tokio::time::advance(HARNESS_ROUND).await;
        }
        Err(delivered)
    }

    /// **The upload that stops and never resumes.**
    ///
    /// A `WINDOW_UPDATE` is emitted once, in a single unacknowledged frame that nothing
    /// retransmits. A sender left with no room, data queued and *nothing outstanding* is in
    /// a state no event can leave on its own: no acknowledgement is due, because nothing is
    /// in flight, and the frame that would open the window is the class of frame that just
    /// went missing.
    ///
    /// One lost frame is enough here. The transfer is eight times the initial window, so it
    /// cannot finish on the opening allowance; the first advertisement closes the gap and is
    /// lost. What frees the sender is asking for it.
    #[tokio::test(start_paused = true)]
    async fn a_transfer_completes_when_the_grant_that_would_continue_it_is_lost() {
        let sender = Stream::new(1);
        let receiver = Stream::new(1);
        const TOTAL: usize = 8 * INITIAL_STREAM_WINDOW as usize;

        match move_bytes_losing_grants(&sender, &receiver, TOTAL, 200, |n| n == 1).await {
            Ok(rounds) => eprintln!("delivered {TOTAL} B in {rounds} rounds, first grant lost"),
            Err(delivered) => panic!(
                "the sender stopped after {delivered} of {TOTAL} bytes and never resumed: \
                 its peer window is {} bytes — under one {HARNESS_SEG}-byte segment — with \
                 nothing in flight, so no acknowledgement can free it and the only frame \
                 that could is the one that was lost",
                sender.peer_send_window()
            ),
        }
    }

    /// **A share of the frames, not one of them.**
    ///
    /// A lossy path does not eat one flow-control frame, it eats a share of them. While the
    /// frame stated the room earned since the last one, that share was a debt neither end
    /// could settle — the receiver had cleared those bytes out of its emission accumulator
    /// as it composed the frame the path then ate, and the sender never heard of them — so
    /// at loss rate `p` the allowance fell behind by `p ×` the bytes transferred and, on a
    /// long enough transfer, stopped for good. Here two frames in every three are lost and
    /// the transfer is eight times the initial window, so a third of the frames carries it
    /// only if each one carries the whole truth.
    ///
    /// Each one does, and the transfer needs both halves of that to be true. The limit is a
    /// total measured from the stream's first byte: put the retired pair back — a receiver
    /// stating the bytes earned since its last frame, a sender adding them to its allowance
    /// — and this stalls at the first grant the path eats. Take the persist probe away
    /// instead, leaving the total in place, and it stalls in the same place, because a round
    /// that loses every grant ends with nothing outstanding and no acknowledgement owed. The
    /// two are not redundant with each other: the probe is what makes a frame happen at all,
    /// and the total is what makes the one frame that survives worth as much as the two that
    /// did not.
    #[tokio::test(start_paused = true)]
    async fn a_transfer_survives_losing_two_flow_control_frames_in_every_three() {
        let sender = Stream::new(1);
        let receiver = Stream::new(1);
        const TOTAL: usize = 8 * INITIAL_STREAM_WINDOW as usize;

        match move_bytes_losing_grants(&sender, &receiver, TOTAL, 200, |n| n % 3 != 0).await {
            Ok(rounds) => {
                eprintln!("delivered {TOTAL} B in {rounds} rounds with 2 grants in 3 lost")
            }
            Err(delivered) => panic!(
                "the sender stopped after {delivered} of {TOTAL} bytes: its peer window is \
                 {} bytes with nothing in flight, so no acknowledgement can free it — and \
                 the frames that did arrive, or the answer to a probe, should each have \
                 carried the whole allowance forward, which is the only thing that lets one \
                 frame in three finish this transfer",
                sender.peer_send_window()
            ),
        }
    }

    /// **The limit only travels in the frames that carry it.**
    ///
    /// A cumulative limit repairs the frames that were lost *before* it, but it cannot
    /// repair itself: with every flow-control frame lost, including every answer to a probe,
    /// the sender never learns of any allowance beyond the opening one and the transfer does
    /// **not** complete. That is the correct outcome and the one worth pinning — a sender
    /// that finished this transfer would be one that had stopped obeying the limit
    /// altogether. This test and the two above it differ in exactly which frames get
    /// through, which is what makes them evidence about the mechanism instead of about the
    /// harness.
    #[tokio::test(start_paused = true)]
    async fn a_sender_invents_no_allowance_when_every_flow_control_frame_is_lost() {
        let sender = Stream::new(1);
        let receiver = Stream::new(1);
        const TOTAL: usize = 8 * INITIAL_STREAM_WINDOW as usize;

        let outcome = move_bytes_losing_grants(&sender, &receiver, TOTAL, 40, |_| true).await;
        let delivered = outcome.expect_err(
            "the limit travels only in the frames that carry it, so a transfer that \
             completes with every one of them lost is one whose sender stopped obeying the \
             limit",
        );
        assert!(
            delivered < TOTAL,
            "delivered {delivered} of {TOTAL} bytes with no limit ever arriving"
        );
    }

    /// A stream whose peer window is closed, with `n` full segments queued behind it and one
    /// earlier segment already delivered — which is how a window closes in the first place,
    /// and which leaves the peer holding an acknowledged offset for a probe to repeat.
    async fn blocked_stream_with_queued_segments(n: usize) -> Stream {
        let s = Stream::new(1);
        s.send_reliable(Bytes::from(vec![0u8; HARNESS_SEG]))
            .await
            .unwrap();
        let first = poll_once(&s)
            .await
            .expect("the initial window admits the first segment");
        s.ack(first.stream_offset).await;
        assert!(s.try_consume_send_window(s.peer_send_window()));
        assert_eq!(s.peer_send_window(), 0, "the window is closed");
        for _ in 0..n {
            s.send_reliable(Bytes::from(vec![0u8; HARNESS_SEG]))
                .await
                .unwrap();
        }
        s
    }

    async fn poll_once(s: &Stream) -> Result<OutboundSegment, SendBlocked> {
        s.poll_send(u64::MAX, 0, std::time::Instant::now(), false)
            .await
    }

    /// **The bound that makes probing safe: no application byte ever crosses a closed
    /// window.**
    ///
    /// The sender cannot distinguish a receiver whose grant was lost from one whose
    /// application has simply stopped reading — the two look identical from here — so
    /// whatever it does when blocked, it does to both. An empty probe is what makes that
    /// acceptable: the second receiver is charged one stream offset per probe and not one
    /// byte of buffer, and it stays entitled to keep this side stopped for as long as it is
    /// not reading.
    ///
    /// Twenty timeouts of a receiver that acknowledges everything and grants nothing — the
    /// non-reading receiver exactly — and the bound asserted is zero: not "little", not
    /// "bounded per interval". Give the probe a payload and it fails on the first one.
    #[tokio::test(start_paused = true)]
    async fn a_receiver_that_grants_nothing_is_sent_no_application_bytes() {
        let s = blocked_stream_with_queued_segments(64).await;

        let mut probes = 0usize;
        let mut payload_past_the_window = 0usize;
        for _ in 0..20 {
            while let Ok(seg) = poll_once(&s).await {
                assert!(
                    is_persist_probe(&seg),
                    "a stream with a closed window handed back a {}-byte segment",
                    seg.data.len()
                );
                payload_past_the_window += seg.data.len();
                probes += 1;
            }
            tokio::time::advance(RtoEstimator::MAX_RTO).await;
        }

        assert!(probes > 0, "the stream never probed at all");
        assert_eq!(
            payload_past_the_window, 0,
            "{probes} probes put {payload_past_the_window} application bytes past a window \
             that had no room for any of them; a receiver whose application has stopped \
             reading must be able to keep this side stopped"
        );
        assert_eq!(
            s.peer_send_window(),
            0,
            "the probe must not debit a window that has nothing in it"
        );
    }

    /// **The probe's rate bound.** One per retransmit timeout, and the floor under that
    /// timeout is what keeps the rate finite on a short path — poll a blocked stream in a
    /// tight loop and it would otherwise emit a frame as fast as the loop turns. Remove the
    /// interval check and the middle assertion fails; remove the probe itself and the first
    /// does.
    #[tokio::test(start_paused = true)]
    async fn a_blocked_stream_probes_no_more_than_once_per_retransmit_timeout() {
        let s = blocked_stream_with_queued_segments(2).await;

        // Closed window, nothing outstanding, data queued: the state no acknowledgement can
        // leave. One probe goes out.
        let probe = poll_once(&s).await.expect(
            "a stream with a closed window, nothing outstanding and data queued must probe \
             — nothing else can ever free it",
        );
        assert!(is_persist_probe(&probe));
        assert!(!probe.retransmit, "the probe is a first transmission");

        // Acknowledged, so nothing is outstanding again — but the interval has not passed.
        s.ack(probe.stream_offset).await;
        assert_eq!(
            poll_once(&s).await.unwrap_err(),
            SendBlocked::FlowControl,
            "a probe left before the retransmit timeout had elapsed: on a short path that \
             is an unbounded rate of frames the peer did not ask for"
        );

        tokio::time::advance(RtoEstimator::MAX_RTO).await;
        let second = poll_once(&s)
            .await
            .expect("the next interval is due, so the next probe is too");
        assert!(is_persist_probe(&second));
        assert_eq!(
            second.stream_offset, probe.stream_offset,
            "each probe must repeat the same delivered offset — a fresh one would land in \
             the peer's reorder buffer above the gap"
        );
    }

    /// **The trigger.** Nothing outstanding is what proves no acknowledgement is on its way,
    /// and so what separates a sender the window has merely slowed from one it has stopped
    /// for good. A stream with a segment still in flight must wait for it: the acknowledgement
    /// may carry the window open behind it, and asking early is asking about a silence that
    /// has not happened. Remove the precondition and the second assertion fails.
    #[tokio::test(start_paused = true)]
    async fn a_stream_with_something_outstanding_waits_instead_of_probing() {
        let s = Stream::new(1);
        for _ in 0..3 {
            s.send_reliable(Bytes::from(vec![0u8; HARNESS_SEG]))
                .await
                .unwrap();
        }
        // One segment delivered — so an offset to probe on exists and this test cannot pass
        // for want of one — and a second still unacknowledged when the window closes.
        let delivered = poll_once(&s).await.expect("the initial window admits it");
        s.ack(delivered.stream_offset).await;
        let inflight = poll_once(&s).await.expect("and the next");
        assert!(!is_persist_probe(&inflight));
        assert!(s.try_consume_send_window(s.peer_send_window()));

        assert_eq!(
            poll_once(&s).await.unwrap_err(),
            SendBlocked::FlowControl,
            "a stream still owed an acknowledgement probed instead of waiting for it"
        );

        // Acknowledged: now nothing is outstanding and the same poll probes.
        s.ack(inflight.stream_offset).await;
        assert!(is_persist_probe(
            &poll_once(&s)
                .await
                .expect("nothing outstanding — the probe is due")
        ));
    }

    /// **A probe must not move the peer's `largest_acked`.**
    ///
    /// This is what decides the offset a probe carries. A probe on a fresh offset sits above
    /// the data the window is holding back, so the peer parks it in its reorder buffer and
    /// SACKs it as an island — and `Sack::largest_acked` then stands `PACKET_THRESHOLD` or
    /// more above every offset this stream sends next, which RFC 9002's packet threshold
    /// reads as loss. On that design this test reported `declared lost: [1, 2]` for two
    /// segments that had just left. Repeating a delivered offset is what makes the probe
    /// invisible to the peer's acknowledgement: it is discarded as a duplicate before the
    /// reorder buffer is touched, so the SACK it produces is the one it would have produced
    /// anyway.
    #[tokio::test(start_paused = true)]
    async fn a_probe_does_not_make_the_next_segments_look_lost() {
        let sender = blocked_stream_with_queued_segments(8).await;
        // A real receiver, holding exactly what the sender's first segment delivered. The
        // acknowledgement below is derived from it rather than written by hand, because what
        // is under test is precisely what the peer's SACK says after it has seen a probe.
        let receiver = Stream::new(1);
        receiver
            .accept_in_order(0, vec![Bytes::from(vec![0u8; HARNESS_SEG])])
            .await;

        let probe = poll_once(&sender)
            .await
            .expect("blocked with nothing outstanding");
        assert!(is_persist_probe(&probe));
        receiver
            .accept_in_order(probe.stream_offset, vec![probe.data.clone()])
            .await;

        // The window reopens and two segments genuinely go into flight — not yet delivered,
        // so the peer's next acknowledgement says nothing about them either way.
        sender.apply_peer_window_limit(sender.bytes_sent() + 10_000);
        let a = poll_once(&sender).await.expect("the window admits it");
        let b = poll_once(&sender).await.expect("and the next");
        assert!(!is_persist_probe(&a) && !is_persist_probe(&b));
        assert_eq!(a.stream_offset + 1, b.stream_offset);

        let sack = receiver
            .received_sack(0)
            .await
            .expect("the receiver has delivered data, so it has a SACK to send");
        let result = sender.on_sack(&sack).await;
        assert!(
            result.lost_offsets().is_empty(),
            "offsets {:?} — in flight, and acknowledged by nothing — were declared lost; \
             the probe raised the peer's largest_acked past them",
            result.lost_offsets()
        );
    }

    /// **A receiver that is not reading grants nothing, however often it is asked.**
    ///
    /// The answer to a probe is `consumed + advertised window`, and both terms move only on
    /// application consumption. An application that has consumed nothing leaves the answer at
    /// the number the peer is already stopped at, however much has arrived and however many
    /// times it asks — so the peer stays stopped. This is the discrimination the sender
    /// cannot make and does not have to: it is made here, on the side that knows.
    #[tokio::test]
    async fn a_receiver_whose_application_has_not_read_grants_no_room() {
        let r = Stream::new(1);
        let opening = r.recv_limit();
        assert_eq!(opening, u64::from(INITIAL_STREAM_WINDOW));

        for offset in 0..16 {
            r.accept_in_order(offset, vec![Bytes::from(vec![0u8; HARNESS_SEG])])
                .await;
        }
        for _ in 0..64 {
            assert_eq!(
                r.recv_limit(),
                opening,
                "the limit moved for bytes that arrived rather than for bytes the \
                 application took"
            );
        }

        // One chunk consumed — below the emission threshold, so `record_app_consumed`
        // withholds the frame; the limit itself has still moved by exactly that chunk, and a
        // probe would state it.
        assert_eq!(r.record_app_consumed(HARNESS_SEG as u32, true), None);
        assert_eq!(
            r.recv_limit(),
            opening + HARNESS_SEG as u64,
            "the answer to a probe is the bytes the application consumed, and only those"
        );
    }

    /// **A probing peer cannot open a window for itself.**
    ///
    /// The peer chooses when a probe arrives, so the answer is computed on the receive task
    /// while the delivery task is crediting consumption — and the peer can ask as fast as it
    /// likes. What bounds it is that the answer is derived, not consumed: it is a read of two
    /// counters that only real consumption advances, so asking cannot move it and asking
    /// twice cannot move it twice. Asserted against an independent count of the bytes the
    /// application actually took, under concurrency, so an answer that ever ran ahead of that
    /// figure fails here.
    #[test]
    fn a_probe_answer_never_exceeds_what_the_application_consumed() {
        const ROUNDS: u32 = 200_000;
        let chunk = INITIAL_STREAM_WINDOW / 2;

        let s = Arc::new(Stream::new(1));
        // Pin the advertised window at its ceiling so `tune_recv_window` returns on its first
        // load, before it reads a clock or takes a lock. This measures the consumed term
        // alone; a window doubling underneath would be a second moving part in the bound.
        s.advertised_recv_window
            .store(MAX_RECV_WINDOW, Ordering::SeqCst);
        let room = u64::from(MAX_RECV_WINDOW);

        let delivery = {
            let s = s.clone();
            std::thread::spawn(move || {
                for _ in 0..ROUNDS {
                    s.record_app_consumed(chunk, true);
                }
            })
        };
        let probing = {
            let s = s.clone();
            std::thread::spawn(move || {
                let mut highest = 0u64;
                for _ in 0..ROUNDS {
                    // Exactly what the receive path does when a probe lands, and the
                    // strongest form of the claim: the answer is bounded by what had been
                    // consumed when it was read, so it is compared against a fresh read of
                    // that counter taken afterwards.
                    let answer = s.recv_limit();
                    let consumed = s.bytes_consumed.load(Ordering::Acquire);
                    assert!(
                        answer <= consumed + room,
                        "a probe was answered with {answer} against {consumed} B consumed \
                         and {room} B of window — the peer opened a window for itself by \
                         asking"
                    );
                    highest = highest.max(answer);
                }
                highest
            })
        };

        delivery.join().expect("the delivery side panicked");
        let highest = probing.join().expect("the probing side panicked");
        assert_eq!(
            s.recv_limit(),
            u64::from(ROUNDS) * u64::from(chunk) + room,
            "the final limit is every consumed byte plus one window, exactly"
        );
        assert!(
            highest <= s.recv_limit(),
            "a probe was answered with {highest}, above the final limit {} — the answer is \
             not a read of the consumed total",
            s.recv_limit()
        );
    }

    /// **A write the transport refused must not cost the window.**
    ///
    /// `poll_send` charges the sent total as it hands a first transmission out, so a write
    /// that then fails has counted bytes that never reached the wire — and the segment is
    /// re-offered and charged a second time for the same bytes. Left uncorrected the total
    /// drifts above what the peer can ever receive, and since the peer computes its limit
    /// from what it received, every refusal shrank this side's room by a segment for the rest
    /// of the connection — arriving at the same dead end as a lost frame by a route entirely
    /// inside this side. Drop the correction from `mark_unsent` and the second assertion
    /// fails.
    #[tokio::test(start_paused = true)]
    async fn a_refused_write_uncharges_the_bytes_that_never_left() {
        let s = Stream::new(1);
        s.send_reliable(Bytes::from(vec![0u8; HARNESS_SEG]))
            .await
            .unwrap();

        let seg = poll_once(&s).await.expect("first transmission");
        assert!(!seg.retransmit);
        assert_eq!(s.bytes_sent(), HARNESS_SEG as u64);
        assert_eq!(
            s.peer_send_window(),
            INITIAL_STREAM_WINDOW - HARNESS_SEG as u32,
            "a first transmission charges the sent total"
        );

        // The write failed after `poll_send` had stamped the segment: the bytes never
        // reached the wire, so the charge was for nothing.
        s.mark_unsent(seg.stream_offset).await;
        assert_eq!(s.bytes_sent(), 0);
        assert_eq!(
            s.peer_send_window(),
            INITIAL_STREAM_WINDOW,
            "the sent total counted bytes that never left"
        );

        // The re-offer is a first transmission again and charges once, not twice.
        let again = poll_once(&s).await.expect("re-offered immediately");
        assert!(!again.retransmit);
        assert_eq!(again.stream_offset, seg.stream_offset);
        assert_eq!(s.bytes_sent(), HARNESS_SEG as u64);

        // A retransmission was accounted on its original send (Karn), so its failure must
        // uncharge nothing — that would put the sent total below the bytes the peer saw.
        tokio::time::advance(RtoEstimator::MAX_RTO).await;
        let rtx = poll_once(&s).await.expect("retransmission");
        assert!(rtx.retransmit);
        s.mark_unsent(rtx.stream_offset).await;
        assert_eq!(
            s.bytes_sent(),
            HARNESS_SEG as u64,
            "a failed retransmission uncharged bytes it never charged"
        );
    }

    /// **One segment's bytes are one segment's worth of the peer's window, however many
    /// times the path makes this side repeat them.**
    ///
    /// The charge is levied in one place — the pass that hands out a segment carrying no
    /// send stamp — and clearing that stamp is what returns a segment to it. A refused
    /// retransmission clears the stamp and rightly keeps the charge, so the re-offer walks
    /// back through the charging pass and pays for the same bytes again. Nothing gives that
    /// back: the peer's limit is computed from what it received, so each refusal leaves this
    /// side a segment short of its room for the rest of the connection, and enough of them
    /// stop the stream with no peer and no path involved.
    #[tokio::test(start_paused = true)]
    async fn a_refused_retransmit_is_not_charged_a_second_time() {
        let s = Stream::new(1);
        s.send_reliable(Bytes::from(vec![0u8; HARNESS_SEG]))
            .await
            .unwrap();

        let first = poll_once(&s).await.expect("first transmission");
        assert!(!first.retransmit);
        assert_eq!(s.bytes_sent(), HARNESS_SEG as u64);

        for round in 1..=3u32 {
            tokio::time::advance(RtoEstimator::MAX_RTO).await;
            let rtx = poll_once(&s).await.expect("retransmission");
            assert!(rtx.retransmit);

            // The write of the retransmission failed: that copy never reached the wire,
            // but the original did, so the charge must stand.
            s.mark_unsent(rtx.stream_offset).await;

            // Cleared of its stamp, the segment comes back through the charging pass.
            let again = poll_once(&s).await.expect("re-offered as unsent");
            assert_eq!(again.stream_offset, first.stream_offset);
            assert_eq!(
                s.bytes_sent(),
                HARNESS_SEG as u64,
                "after {round} refused retransmit(s) the sent total counts {} bytes for \
                 the {HARNESS_SEG} the peer will ever see",
                s.bytes_sent()
            );
            assert_eq!(
                s.peer_send_window(),
                INITIAL_STREAM_WINDOW - HARNESS_SEG as u32,
                "a refused retransmit took room the peer never spent"
            );
        }
    }

    /// **An acknowledgement that overtakes the re-offer must not carry the charge away.**
    ///
    /// This is why the correction cannot simply follow the send stamp. After a refused
    /// write the pump leaves the drain and reads its inbound packets first, so a SACK for
    /// the *original* copy can land before the segment is offered again — and `on_sack`
    /// retires a segment by offset whether or not it currently carries a stamp. Return the
    /// charge on a refused retransmission and there is no re-offer left to take it back: the
    /// sent total ends below the bytes the peer actually received, which is this side
    /// granting itself room to overrun the receiver's window.
    #[tokio::test(start_paused = true)]
    async fn an_original_acknowledged_after_a_refused_retransmit_keeps_its_charge() {
        let s = Stream::new(1);
        s.send_reliable(Bytes::from(vec![0u8; HARNESS_SEG]))
            .await
            .unwrap();

        let first = poll_once(&s).await.expect("first transmission");
        assert_eq!(s.bytes_sent(), HARNESS_SEG as u64);

        tokio::time::advance(RtoEstimator::MAX_RTO).await;
        let rtx = poll_once(&s).await.expect("retransmission");
        assert!(rtx.retransmit);
        s.mark_unsent(rtx.stream_offset).await;

        // The peer had the original all along; its SACK arrives before the drain runs again.
        let sack = Sack::from_inclusive_ranges(vec![(first.stream_offset, first.stream_offset)], 0)
            .expect("sack");
        assert_eq!(s.on_sack(&sack).await.retired.len(), 1);

        assert_eq!(
            s.bytes_sent(),
            HARNESS_SEG as u64,
            "the peer received {HARNESS_SEG} bytes and the sent total says {} — this side \
             may now overrun the window by the difference",
            s.bytes_sent()
        );
    }

    /// **A segment already holding its charge goes out though the window has no room left.**
    ///
    /// The charge is room reserved for those bytes, not a toll collected per attempt, so a
    /// segment that still holds one is entitled to the wire whatever the window says. Charge
    /// it afresh on the re-offer and a stream whose window closed exactly on it can never
    /// send it again: the retransmit passes want a send stamp it no longer has, the charging
    /// pass wants room the peer has already granted and this side has already spent, and the
    /// only frame that would raise the limit is one the peer sends after receiving the very
    /// segment that is stuck.
    #[tokio::test(start_paused = true)]
    async fn a_segment_still_holding_its_charge_is_re_offered_through_a_closed_window() {
        let s = Stream::new(1);
        s.send_reliable(Bytes::from(vec![0u8; HARNESS_SEG]))
            .await
            .unwrap();

        let first = poll_once(&s).await.expect("first transmission");
        // Spend the rest of the peer's grant elsewhere: the window now has room for nothing.
        assert!(s.try_consume_send_window(s.peer_send_window()));
        assert_eq!(s.peer_send_window(), 0);

        tokio::time::advance(RtoEstimator::MAX_RTO).await;
        let rtx = poll_once(&s).await.expect("retransmission");
        s.mark_unsent(rtx.stream_offset).await;

        let again = poll_once(&s)
            .await
            .expect("a segment that already paid for its room is offered again");
        assert_eq!(again.stream_offset, first.stream_offset);
    }

    /// **Returning more than was charged must not turn the window inside out.**
    ///
    /// The correction is a subtraction on a `u64` between two totals that different paths
    /// maintain, so "more returned than charged" is a state to survive rather than one to
    /// assume away. Wrapped, the sent total lands just under `u64::MAX` and neither outcome
    /// is a small error. Against an honest peer the stream stops for good: its advertised
    /// limit is a finite number, `peer_send_window` is that limit less the total, and the
    /// subtraction is zero from then on. Against a peer that advertises `u64::MAX` the
    /// opposite happens — `apply_peer_window_limit`'s ceiling is the total plus
    /// `MAX_SEND_WINDOW`, which saturates, so the limit it honours is the peer's own number
    /// and the check that bounds a sender by its receiver stops binding at all; the few
    /// bytes of window that leaves are the ones the test below charges for. Saturation costs
    /// one compare and leaves an ordinary open window.
    #[tokio::test(start_paused = true)]
    async fn returning_more_than_was_charged_saturates_at_zero() {
        let s = Stream::new(1);
        s.send_reliable(Bytes::from(vec![0u8; HARNESS_SEG]))
            .await
            .unwrap();
        let seg = poll_once(&s).await.expect("first transmission");
        assert_eq!(s.bytes_sent(), HARNESS_SEG as u64);

        // Stand the two totals apart by one byte — the smallest divergence that makes the
        // correction larger than what it is correcting.
        s.bytes_sent
            .store(HARNESS_SEG as u64 - 1, Ordering::Release);
        s.mark_unsent(seg.stream_offset).await;

        assert_eq!(
            s.bytes_sent(),
            0,
            "the sent total wrapped instead of stopping at zero"
        );
        assert_eq!(
            s.peer_send_window(),
            INITIAL_STREAM_WINDOW,
            "an underflowed total leaves the peer unable to open the window at all"
        );
    }

    /// **A charge that will not fit in a `u64` is refused, not wrapped.**
    ///
    /// The clamp that normally holds an advertisement to one `MAX_SEND_WINDOW` past what has
    /// gone out is a saturating addition, so it degenerates at the top of the range: a peer
    /// that writes `u64::MAX` there is honoured verbatim and is left holding a handful of
    /// bytes of window. Charging for them is then an addition that leaves the range, and
    /// deciding whether it fits by computing it first answers with a wrapped number — in a
    /// debug build, by ending the task that drains every stream on the session, which a
    /// peer's advertisement must never be able to do. Refusing is not a conservative
    /// approximation either: `peer_send_limit` is a `u64`, so a sum above the range is above
    /// any limit that can be advertised.
    #[test]
    fn a_charge_that_leaves_the_u64_range_is_refused_rather_than_wrapped() {
        let s = Stream::new(1);
        s.bytes_sent.store(u64::MAX - 4, Ordering::Release);
        s.apply_peer_window_limit(u64::MAX);
        assert_eq!(
            s.peer_send_limit.load(Ordering::Acquire),
            u64::MAX,
            "the ceiling did not saturate, so this is not the state under test"
        );
        assert_eq!(s.peer_send_window(), 4);

        assert!(
            !s.try_consume_send_window(5),
            "five bytes were charged against four bytes of window"
        );
        assert_eq!(
            s.bytes_sent(),
            u64::MAX - 4,
            "a refused charge advanced the sent total"
        );

        // The exact fit still goes through: the refusal above is about the sum leaving the
        // range, not about backing away from the boundary.
        assert!(s.try_consume_send_window(4));
        assert_eq!(s.bytes_sent(), u64::MAX);
        assert_eq!(s.peer_send_window(), 0);
    }
}
