//! Token-bucket pacer
//!
//! A congestion window is a *volume*: it says how many unacknowledged bytes may
//! be outstanding, and nothing more. Released all at once it is a burst — the
//! whole window leaves back to back at whatever rate the link card manages, and
//! the sender then waits a round trip. Every intermediate queue on the path
//! absorbs that burst, or drops it.
//!
//! The pacer turns the volume into a rate. Tokens accrue at `rate` bytes per
//! second, a send debits what it put on the wire, and a sender with no credit
//! waits. Spread over a round trip at the bottleneck rate, a window's worth of
//! data arrives at the bottleneck exactly as fast as the bottleneck drains it,
//! and the standing queue is the residue of one round trip's mis-estimate
//! rather than a window.
//!
//! This is also the assumption BBR is built on. Its pacing gains — 1.25 to ask
//! the path for a quarter more than the current estimate, 0.75 to give back
//! whatever queue that built — are instructions to a rate limiter. Without one
//! they are arithmetic performed on a number nobody reads, and the ProbeBW
//! cycle that is supposed to discover more bandwidth does nothing at all.
//!
//! # The burst allowance, and the ceiling it implies
//!
//! A pacer is consulted by a task that wakes on a timer, and a timer's
//! granularity is about a millisecond. A bucket that holds `B` bytes therefore
//! sustains at most `B` per wake-up, so a *fixed* allowance is a fixed ceiling:
//! 64 KB against a millisecond wake is roughly 512 Mbit/s, and one packet's
//! worth — which is what a pacer that slept between every packet would
//! effectively have — is about 9.6 Mbit/s at this transport's MTU. That second
//! figure is not hypothetical; it is what a per-packet `sleep` measured.
//!
//! So the allowance here is a fixed *duration* of the current rate,
//! [`BURST_INTERVAL`], clamped into [`MIN_BURST_BYTES`]..=[`MAX_BURST_BYTES`].
//! Four milliseconds is comfortably longer than the timer granularity, so an
//! ordinary wake never finds the bucket clipped, and it bounds what a sender
//! that has been idle may dump to four milliseconds of the path — not a window.
//! The clamps state the range where that reasoning holds: below about 4 MB/s
//! the floor is a slightly longer burst than four milliseconds, and the ceiling
//! this pacer can sustain is [`MAX_BURST_BYTES`] per [`BURST_INTERVAL`], which
//! is 128 MiB/s — about 1.07 Gbit/s.
//!
//! # Debt
//!
//! The bucket is signed. A caller that must decide whether to send *before* it
//! knows how large the segment will be — which is every caller, since the
//! segment is chosen by the stream — can only ask "is there credit?" and settle
//! the true size afterwards. Carrying the overshoot as debt keeps the long-run
//! rate exact; clamping it at zero would forgive up to a packet every time the
//! bucket ran dry, which on a busy sender is continuous.

use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Minimum pacing rate (1 KB/s) — prevents stalling
const MIN_PACING_RATE: u64 = 1_024;

/// How much of the current rate the bucket may hold as burst credit.
///
/// Longer than the ~1 ms granularity of the timer the pump wakes on, so a
/// wake-up that lands late does not find the bucket clipped and lose rate it
/// was owed; short enough that an idle sender's first move is four
/// milliseconds of the path rather than a congestion window.
const BURST_INTERVAL: Duration = Duration::from_millis(4);

/// Floor on the burst allowance. Ten to thirteen MTU-sized segments — the same
/// order as QUIC's initial window, and the point below which a bucket cannot
/// hold even a first flight and would meter out the start of every connection
/// one packet per timer tick.
const MIN_BURST_BYTES: i64 = 16 * 1_024;

/// Ceiling on the burst allowance, and with [`BURST_INTERVAL`] the ceiling on
/// the rate this pacer can sustain: 512 KiB per 4 ms is 128 MiB/s ≈ 1.07 Gbit/s.
/// Above that the bucket, not the rate, is the limiter.
const MAX_BURST_BYTES: i64 = 512 * 1_024;

/// Token-bucket pacer.
///
/// Thread-safe and cheap to consult — the fast path is one relaxed load. Shared
/// across async tasks behind an `Arc`; in this crate the data pump is the only
/// consumer, so the refill's read-modify-write races with nothing in practice,
/// and where it could the burst allowance bounds the error.
pub struct Pacer {
    /// Available credit in bytes, signed: negative is debt owed from a send
    /// that overshot the credit it was authorised against.
    tokens: AtomicI64,
    /// Pacing rate in bytes/sec
    rate_bps: AtomicU64,
    /// Last token refill timestamp (nanoseconds since [`Self::epoch`])
    last_refill_ns: AtomicU64,
    /// Whether pacing is enabled
    enabled: AtomicBool,
    /// Creation time (for relative nanoseconds)
    epoch: Instant,
}

impl Pacer {
    /// Create a new pacer with the given initial rate (bytes/sec).
    pub fn new(initial_rate_bps: u64) -> Self {
        let rate = initial_rate_bps.max(MIN_PACING_RATE);
        Self {
            tokens: AtomicI64::new(Self::burst_for(rate)),
            rate_bps: AtomicU64::new(rate),
            last_refill_ns: AtomicU64::new(0),
            enabled: AtomicBool::new(true),
            epoch: Instant::now(),
        }
    }

    /// Create an unlimited pacer (always allows sends).
    ///
    /// This is the state every session starts in and the answer to the
    /// bootstrap: before an acknowledgement has been processed there is no
    /// bandwidth estimate, `btl_bw` is zero, and any rate derived from it would
    /// be a fabrication. A pacer that metered against a fabricated rate would
    /// throttle — or with a rate of zero, deadlock — a connection at its first
    /// byte. Congestion control turns pacing on when it has measured something.
    pub fn unlimited() -> Self {
        let pacer = Self::new(u64::MAX);
        pacer.enabled.store(false, Ordering::Relaxed);
        pacer
    }

    /// The burst allowance for `rate`: [`BURST_INTERVAL`] of it, clamped.
    fn burst_for(rate: u64) -> i64 {
        let per_interval =
            (rate as u128).saturating_mul(BURST_INTERVAL.as_nanos()) / 1_000_000_000u128;
        let per_interval = i64::try_from(per_interval).unwrap_or(i64::MAX);
        per_interval.clamp(MIN_BURST_BYTES, MAX_BURST_BYTES)
    }

    /// The burst allowance currently in force (bytes).
    pub fn burst_bytes(&self) -> u64 {
        Self::burst_for(self.rate_bps.load(Ordering::Relaxed)) as u64
    }

    /// Whether the bucket holds credit for another send *right now*.
    ///
    /// This, not [`Self::try_consume`], is what a send loop asks: it has to
    /// decide whether to pull a segment out of a stream before it knows how big
    /// that segment is. Settle the real size with [`Self::consume`] afterwards.
    /// Always `true` when pacing is disabled.
    pub fn can_send(&self) -> bool {
        if !self.enabled.load(Ordering::Relaxed) {
            return true;
        }
        self.refill_tokens();
        self.tokens.load(Ordering::Relaxed) > 0
    }

    /// Debit `bytes` from the bucket, whether or not the credit was there.
    ///
    /// The overshoot a [`Self::can_send`]-then-send caller can produce is one
    /// segment, and it is carried as debt rather than forgiven, so the rate
    /// stays exact over any interval longer than a packet. No-op when pacing is
    /// disabled.
    pub fn consume(&self, bytes: u64) {
        if !self.enabled.load(Ordering::Relaxed) {
            return;
        }
        let debit = i64::try_from(bytes).unwrap_or(i64::MAX);
        let mut current = self.tokens.load(Ordering::Relaxed);
        loop {
            let updated = current.saturating_sub(debit);
            match self.tokens.compare_exchange_weak(
                current,
                updated,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return,
                Err(actual) => current = actual,
            }
        }
    }

    /// How long until the bucket holds credit again — the delay a paused sender
    /// should wait before asking [`Self::can_send`] a second time.
    ///
    /// Zero when credit is already available or pacing is disabled. Deliberately
    /// not capped here: the caller knows what latency it can tolerate for its
    /// other work, and capping it here would make an early wake look like
    /// available credit.
    pub fn time_until_credit(&self) -> Duration {
        if !self.enabled.load(Ordering::Relaxed) {
            return Duration::ZERO;
        }
        self.refill_tokens();
        let tokens = self.tokens.load(Ordering::Relaxed);
        if tokens > 0 {
            return Duration::ZERO;
        }
        // Credit is owed up to and including the first positive byte.
        let deficit = (1i64.saturating_sub(tokens)) as u128;
        self.wait_for(deficit)
    }

    /// Try to consume `bytes` tokens. Returns `true` if allowed, `false` if should wait.
    ///
    /// All-or-nothing, for a caller that knows the size up front.
    pub fn try_consume(&self, bytes: u64) -> bool {
        if !self.enabled.load(Ordering::Relaxed) {
            return true;
        }
        self.refill_tokens();
        let want = i64::try_from(bytes).unwrap_or(i64::MAX);
        let mut current = self.tokens.load(Ordering::Relaxed);
        loop {
            if current < want {
                return false;
            }
            match self.tokens.compare_exchange_weak(
                current,
                current - want,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(actual) => current = actual,
            }
        }
    }

    /// How long to wait before `bytes` tokens are available.
    pub fn time_until_available(&self, bytes: u64) -> Duration {
        if !self.enabled.load(Ordering::Relaxed) {
            return Duration::ZERO;
        }
        self.refill_tokens();
        let want = i64::try_from(bytes).unwrap_or(i64::MAX);
        let current = self.tokens.load(Ordering::Relaxed);
        if current >= want {
            return Duration::ZERO;
        }
        self.wait_for((want.saturating_sub(current)) as u128)
    }

    /// Time for `deficit` bytes of credit to accrue at the current rate.
    fn wait_for(&self, deficit: u128) -> Duration {
        let rate = self.rate_bps.load(Ordering::Relaxed).max(1) as u128;
        let nanos = deficit.saturating_mul(1_000_000_000) / rate;
        Duration::from_nanos(u64::try_from(nanos).unwrap_or(u64::MAX))
    }

    /// Update the pacing rate (called by BandwidthEstimator).
    ///
    /// The burst allowance tracks the rate, so credit already banked is trimmed
    /// to the new allowance — a rate that just fell must not leave the sender
    /// holding the old rate's burst.
    pub fn set_rate(&self, rate_bps: u64) {
        let rate = rate_bps.max(MIN_PACING_RATE);
        self.rate_bps.store(rate, Ordering::Relaxed);
        let cap = Self::burst_for(rate);
        let mut current = self.tokens.load(Ordering::Relaxed);
        while current > cap {
            match self.tokens.compare_exchange_weak(
                current,
                cap,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return,
                Err(actual) => current = actual,
            }
        }
    }

    /// Get the current pacing rate (bytes/sec).
    pub fn rate(&self) -> u64 {
        self.rate_bps.load(Ordering::Relaxed)
    }

    /// Enable or disable pacing.
    ///
    /// Enabling restarts the refill clock and trims banked credit to the current
    /// allowance: a pacer that spent the connection's first seconds disabled has
    /// an arbitrarily stale refill mark, and crediting it for that whole period
    /// would hand the sender a free burst at the exact moment pacing was
    /// supposed to start governing.
    pub fn set_enabled(&self, enabled: bool) {
        if enabled {
            let now_ns = u64::try_from(self.epoch.elapsed().as_nanos()).unwrap_or(u64::MAX);
            self.last_refill_ns.store(now_ns, Ordering::Relaxed);
            let cap = Self::burst_for(self.rate_bps.load(Ordering::Relaxed));
            let mut current = self.tokens.load(Ordering::Relaxed);
            loop {
                let clamped = current.clamp(0, cap);
                if clamped == current {
                    break;
                }
                match self.tokens.compare_exchange_weak(
                    current,
                    clamped,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => break,
                    Err(actual) => current = actual,
                }
            }
        }
        self.enabled.store(enabled, Ordering::Relaxed);
    }

    /// Whether pacing is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    /// Current available credit, with debt reported as zero.
    pub fn available_tokens(&self) -> u64 {
        self.refill_tokens();
        self.tokens.load(Ordering::Relaxed).max(0) as u64
    }

    /// Refill tokens based on elapsed time.
    fn refill_tokens(&self) {
        let now_ns = u64::try_from(self.epoch.elapsed().as_nanos()).unwrap_or(u64::MAX);
        let last_ns = self.last_refill_ns.load(Ordering::Relaxed);
        let elapsed_ns = now_ns.saturating_sub(last_ns);
        if elapsed_ns == 0 {
            return;
        }

        let rate = self.rate_bps.load(Ordering::Relaxed);
        let credit = (rate as u128).saturating_mul(elapsed_ns as u128) / 1_000_000_000u128;
        if credit == 0 {
            // Leave the mark where it is so sub-nanosecond-per-byte fractions
            // accumulate instead of being rounded away on every call.
            return;
        }
        let credit = i64::try_from(credit).unwrap_or(i64::MAX);

        let cap = Self::burst_for(rate);
        let mut current = self.tokens.load(Ordering::Relaxed);
        loop {
            let updated = current.saturating_add(credit).min(cap);
            if updated == current {
                break;
            }
            match self.tokens.compare_exchange_weak(
                current,
                updated,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(actual) => current = actual,
            }
        }
        self.last_refill_ns.store(now_ns, Ordering::Relaxed);
    }
}

impl std::fmt::Debug for Pacer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pacer")
            .field("rate_bps", &self.rate_bps.load(Ordering::Relaxed))
            .field("tokens", &self.tokens.load(Ordering::Relaxed))
            .field("enabled", &self.enabled.load(Ordering::Relaxed))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_pacer_allows_burst() {
        let pacer = Pacer::new(1_000_000); // 1 MB/s
                                           // A fresh bucket opens holding its burst allowance.
        assert!(pacer.try_consume(1400)); // one packet
        assert!(pacer.try_consume(1400)); // another packet
    }

    #[test]
    fn test_pacer_blocks_when_empty() {
        let pacer = Pacer::new(1_024); // 1 KB/s — very slow
                                       // Exhaust the burst allowance
        assert!(pacer.try_consume(pacer.burst_bytes()));
        // No tokens left
        assert!(!pacer.try_consume(1));
    }

    #[test]
    fn test_pacer_refills_over_time() {
        let pacer = Pacer::new(100_000); // 100 KB/s
                                         // Drain all tokens
        assert!(pacer.try_consume(pacer.burst_bytes()));
        assert!(!pacer.try_consume(1));

        // Wait a bit for refill
        thread::sleep(Duration::from_millis(50));

        // Should have some tokens now (~5KB at 100KB/s over 50ms)
        let available = pacer.available_tokens();
        assert!(
            available > 0,
            "expected tokens after sleep, got {}",
            available
        );
    }

    #[test]
    fn test_pacer_rate_update() {
        let pacer = Pacer::new(1_000_000);
        assert_eq!(pacer.rate(), 1_000_000);

        pacer.set_rate(2_000_000);
        assert_eq!(pacer.rate(), 2_000_000);
    }

    #[test]
    fn test_pacer_min_rate() {
        let pacer = Pacer::new(0); // Should clamp to MIN
        assert_eq!(pacer.rate(), MIN_PACING_RATE);
    }

    #[test]
    fn test_pacer_unlimited() {
        let pacer = Pacer::unlimited();
        assert!(!pacer.is_enabled());
        // Should always allow
        assert!(pacer.try_consume(u64::MAX));
        assert_eq!(pacer.time_until_available(1), Duration::ZERO);
    }

    /// The pump wakes on a timer, and a timer's granularity is about a
    /// millisecond. Whatever the bucket refuses therefore waits at least that
    /// long, which makes the *burst allowance*, not the rate, the thing that
    /// decides the achievable ceiling: a consumer that can only collect credit
    /// once per millisecond is capped at one burst per millisecond however fast
    /// the rate says it may go.
    ///
    /// This models that floor explicitly rather than hoping the host's own
    /// sleep happens to be coarse enough to expose it.
    const TIMER_GRANULARITY: Duration = Duration::from_millis(1);

    /// Drive `pacer` the way the drain does — take everything it will give,
    /// then wait for more — and report the bytes it admitted and over how long.
    fn admitted_over(pacer: &Pacer, packet: u64, run: Duration) -> (u64, Duration) {
        let start = Instant::now();
        let mut admitted = 0u64;
        while start.elapsed() < run {
            if pacer.try_consume(packet) {
                admitted += packet;
                continue;
            }
            let wait = pacer.time_until_available(packet).max(TIMER_GRANULARITY);
            thread::sleep(wait);
        }
        (admitted, start.elapsed())
    }

    /// **Pacing must limit.** Offered far more than the rate allows, the bucket
    /// admits about `rate × interval` and no more — that is the whole claim.
    #[test]
    fn a_paced_bucket_admits_about_the_rate_over_an_interval() {
        // 2 MB/s is 16 Mbit/s — the order of the paths this transport was
        // measured on.
        const RATE: u64 = 2 * 1_000_000;
        const PACKET: u64 = 1_400;
        const RUN: Duration = Duration::from_millis(300);

        let pacer = Pacer::new(RATE);
        let (admitted, elapsed) = admitted_over(&pacer, PACKET, RUN);
        let want = (RATE as u128 * elapsed.as_nanos() / 1_000_000_000) as u64;

        assert!(
            admitted <= want + want / 2,
            "the bucket admitted {admitted} B over {} ms, more than half again the \
             {want} B its {RATE} B/s rate allows",
            elapsed.as_millis(),
        );
        // ...and it has to be a rate limiter, not an off switch: a bucket that
        // admitted almost nothing would satisfy the bound above.
        assert!(
            admitted >= want / 2,
            "the bucket admitted only {admitted} B of the {want} B its {RATE} B/s rate \
             allows over {} ms",
            elapsed.as_millis(),
        );
    }

    /// **A pacer must not become the path's ceiling.** The bucket's burst
    /// allowance has to scale with the rate it is set to. Fixed at 64 KB it
    /// silently caps a consumer that can only collect once per millisecond at
    /// 64 MB/s, whatever rate congestion control asked for — a pacer that turns
    /// a fast path into a slow one is worse than no pacer at all.
    #[test]
    fn a_high_rate_pacer_does_not_cap_the_offered_load() {
        // 128 MB/s ≈ 1 Gbit/s: above anything this transport has measured, and
        // deliberately so — the assertion is about the shape of the bound, not
        // about a rate anyone will meet.
        const RATE: u64 = 128 * 1_000_000;
        const PACKET: u64 = 1_400;
        const RUN: Duration = Duration::from_millis(200);

        let pacer = Pacer::new(RATE);
        let (admitted, elapsed) = admitted_over(&pacer, PACKET, RUN);
        let want = (RATE as u128 * elapsed.as_nanos() / 1_000_000_000) as u64;

        assert!(
            admitted >= want / 4 * 3,
            "the pacer held a {RATE} B/s rate to {admitted} B over {} ms, where the rate \
             itself allows {want} B — the burst allowance, not the rate, is the limiter",
            elapsed.as_millis(),
        );
    }

    /// **The bootstrap.** Before congestion control has measured anything there
    /// is no rate to pace at, and a bucket that answered "wait" to that would
    /// deadlock a connection at its first byte. A disabled pacer admits
    /// everything, immediately.
    #[test]
    fn a_pacer_with_no_rate_yet_admits_everything() {
        let pacer = Pacer::unlimited();
        assert!(!pacer.is_enabled());
        for _ in 0..1000 {
            assert!(
                pacer.try_consume(1_400),
                "a pacer with no bandwidth estimate refused a send"
            );
        }
        assert_eq!(pacer.time_until_available(1_400), Duration::ZERO);
    }

    #[test]
    fn test_pacer_time_until_available() {
        let pacer = Pacer::new(1_000_000); // 1 MB/s
                                           // Drain tokens
        pacer.try_consume(pacer.burst_bytes());

        // Need 10_000 bytes at 1 MB/s = 10ms
        let wait = pacer.time_until_available(10_000);
        assert!(wait > Duration::ZERO);
        assert!(wait < Duration::from_millis(50), "wait was {:?}", wait);
    }

    /// The burst allowance is a duration of the rate, not a constant. A pacer
    /// whose allowance did not scale would be a ceiling (see
    /// [`a_high_rate_pacer_does_not_cap_the_offered_load`]) at the top and a
    /// stutter at the bottom.
    #[test]
    fn the_burst_allowance_tracks_the_rate_between_its_clamps() {
        // 4 ms of 10 MB/s is 40 KB, comfortably inside the clamps.
        let mid = Pacer::new(10_000_000);
        assert_eq!(mid.burst_bytes(), 40_000);

        // A slow path clamps up to the floor: metering a first flight one
        // packet per timer tick is not pacing, it is a stall.
        let slow = Pacer::new(100_000);
        assert_eq!(slow.burst_bytes(), MIN_BURST_BYTES as u64);

        // A very fast one clamps down to the ceiling, which is where this
        // pacer stops being able to sustain the rate it was given.
        let fast = Pacer::new(1_000_000_000);
        assert_eq!(fast.burst_bytes(), MAX_BURST_BYTES as u64);
    }

    /// A caller that cannot know a segment's size before it pulls it out of a
    /// stream asks `can_send` and settles with `consume`. The overshoot that
    /// produces is carried as debt, so the rate stays exact instead of the
    /// bucket forgiving a packet every time it runs dry.
    #[test]
    fn an_oversized_send_is_carried_as_debt_not_forgiven() {
        let pacer = Pacer::new(1_000_000); // 1 MB/s → 16 KiB allowance (floor)
        let burst = pacer.burst_bytes();

        // Spend the allowance down to a sliver, then overshoot it.
        assert!(pacer.try_consume(burst - 100));
        assert!(pacer.can_send(), "100 B of credit is still credit");
        pacer.consume(10_000);

        assert!(
            !pacer.can_send(),
            "a send that overshot its credit must leave the bucket empty"
        );
        // The debt is ~9900 B, which at 1 MB/s is ~9.9 ms. A bucket that
        // clamped at zero would report ~0 and hand back the overshoot free.
        let wait = pacer.time_until_credit();
        assert!(
            wait > Duration::from_millis(5),
            "the overshoot was forgiven rather than owed: wait {wait:?}"
        );
        assert!(wait < Duration::from_millis(30), "wait was {wait:?}");
    }

    /// A disabled pacer answers every question with "go", including the ones a
    /// send loop asks on its hot path.
    #[test]
    fn a_disabled_pacer_gates_nothing() {
        let pacer = Pacer::unlimited();
        assert!(pacer.can_send());
        pacer.consume(1_000_000);
        assert!(pacer.can_send());
        assert_eq!(pacer.time_until_credit(), Duration::ZERO);
    }

    /// Turning pacing on must not hand the sender credit for the period it was
    /// off. The refill mark is otherwise arbitrarily stale, and the first thing
    /// pacing would do is authorise the burst it exists to prevent.
    #[test]
    fn enabling_pacing_does_not_bank_the_idle_period() {
        let pacer = Pacer::unlimited();
        pacer.consume(0); // no-op while disabled
        thread::sleep(Duration::from_millis(20));

        pacer.set_rate(1_000_000);
        pacer.set_enabled(true);
        assert!(
            pacer.available_tokens() <= pacer.burst_bytes(),
            "enabling credited {} B against a {} B allowance",
            pacer.available_tokens(),
            pacer.burst_bytes()
        );
    }
}
