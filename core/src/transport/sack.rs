//! Selective-acknowledgement (SACK) range codec.
//!
//! # Purpose
//!
//! Replaces the legacy 4-byte single-sequence ACK payload inside the
//! `ENCRYPTED | ACK` [`crate::transport::PhantomPacket`] control frame with a
//! compact multi-range encoding that lets the sender retire many segments in a
//! single ACK and detect gaps for fast-retransmit.
//!
//! This is the **AEAD plaintext** of that control frame — it is NOT the outer
//! frozen `PhantomPacket` container. Changing this format does NOT require a
//! `WIRE_VERSION` or `PROTOCOL_VERSION` bump and does NOT invalidate
//! `core/tests/wire_vectors`.
//!
//! # Wire format
//!
//! All integers are big-endian (network byte order), matching the rest of the
//! Phantom Protocol codec (`PacketHeader::to_wire`, etc.).
//!
//! ```text
//! off  0  largest_acked  : u32 be   — the highest sequence number ACKed
//! off  4  ack_delay_us   : u32 be   — sender-measured ACK delay in µs
//! off  8  range_count    : u16 be   — number of SACK ranges; ≥ 1, ≤ MAX_SACK_RANGES
//! off 10  first_len      : u32 be   — length-minus-one of the first (highest) range
//! off 14  [gap : u32 be, len : u32 be] × (range_count − 1)
//! ```
//!
//! ## Range encoding
//!
//! Ranges are stored **descending** (highest first).  The first range is:
//!
//! ```text
//! high = largest_acked
//! low  = largest_acked − first_len          (inclusive; first_len is length − 1)
//! ```
//!
//! Each subsequent `(gap, len)` pair descends below the previous range's low:
//!
//! ```text
//! high_i = low_{i-1} − 1 − gap             (skip `gap` unACKed sequences)
//! low_i  = high_i − len                    (len is length − 1)
//! ```
//!
//! The "length − 1" convention means `len == 0` encodes a single-sequence range
//! (one ACKed packet).  `gap` = number of unACKed sequences between a range's
//! low and the next (lower) range's high; `gap` is always ≥ 1 (adjacent ranges
//! are coalesced by the sender and rejected as `Malformed` on decode).
//!
//! ## Minimum wire size
//!
//! | ranges | bytes |
//! |--------|-------|
//! | 1      | 14    |
//! | 2      | 22    |
//! | N      | 10 + 4 + 8×(N−1) |
//!
//! ## Decode error conditions
//!
//! | Condition                        | Error            |
//! |----------------------------------|------------------|
//! | Buffer shorter than declared     | `Truncated`      |
//! | `range_count > MAX_SACK_RANGES`  | `TooManyRanges`  |
//! | `range_count == 0`               | `Malformed`      |
//! | `gap == 0` (adjacent ranges)     | `Malformed`      |
//! | gap/len underflows below 0       | `Malformed`      |
//! | resulting range overlaps / is adjacent to previous | `Malformed` |

use std::fmt;

/// Maximum number of SACK ranges accepted during decode — anti-DoS bound.
/// A 32-range SACK fits in 262 bytes, well within any AEAD budget.
pub const MAX_SACK_RANGES: usize = 32;

/// Minimum wire size for a 1-range SACK (10 fixed + 4 first_len).
const MIN_WIRE_LEN: usize = 14;

/// Fixed header before the variable-length range array.
const FIXED_HDR_LEN: usize = 10; // largest_acked(4) + ack_delay_us(4) + range_count(2)

/// Per-range continuation bytes after the first range.
const CONTINUATION_BYTES: usize = 8; // gap(4) + len(4)

/// A selective acknowledgement over a per-stream `u32` sequence space.
///
/// `ranges` are **inclusive `(low, high)`** runs of acknowledged sequences,
/// sorted **descending** (highest first), non-overlapping and non-adjacent.
/// `ranges[0].1 == largest_acked`.  An empty `ranges` slice is invalid — a
/// [`Sack`] always ACKs at least one sequence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sack {
    /// The highest sequence number covered by this ACK.
    pub largest_acked: u32,
    /// Sender-measured delay between receiving the data packet and generating
    /// this ACK, in microseconds.  Used by the BBR / RTT estimator.
    pub ack_delay_us: u32,
    /// Inclusive `(low, high)` ranges, sorted descending (highest first),
    /// non-overlapping and non-adjacent.  Always non-empty.
    ranges: Vec<(u32, u32)>,
}

/// Errors returned by [`Sack::from_wire`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SackError {
    /// The buffer is shorter than the structure it declares.
    Truncated,
    /// `range_count` exceeds [`MAX_SACK_RANGES`].  Checked before any
    /// allocation so an adversarial count cannot trigger OOM.
    TooManyRanges,
    /// The encoding is structurally invalid: `range_count == 0`, `gap == 0`
    /// (adjacent ranges), a gap/len pair would underflow the sequence space,
    /// or ranges are not strictly descending and non-adjacent.
    Malformed,
}

impl fmt::Display for SackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => write!(f, "SACK payload too short for the declared range count"),
            Self::TooManyRanges => write!(
                f,
                "SACK range_count exceeds the anti-DoS limit of {MAX_SACK_RANGES}"
            ),
            Self::Malformed => write!(
                f,
                "SACK encoding is malformed (zero ranges, adjacent ranges, underflow, or overlapping ranges)"
            ),
        }
    }
}

impl std::error::Error for SackError {}

impl Sack {
    /// Build a [`Sack`] from an unordered slice of received sequence numbers.
    ///
    /// Coalesces adjacent or overlapping sequences into the minimal set of
    /// inclusive `(low, high)` ranges sorted descending (highest first).
    ///
    /// Returns `None` if `received` is empty (there is nothing to ACK).
    pub fn from_received(received: &[u32], ack_delay_us: u32) -> Option<Sack> {
        if received.is_empty() {
            return None;
        }

        // Sort ascending so we can coalesce in a single pass.
        let mut seqs: Vec<u32> = received.to_vec();
        seqs.sort_unstable();

        // Coalesce into ascending (low, high) ranges.
        let mut asc_ranges: Vec<(u32, u32)> = Vec::new();
        for seq in seqs {
            match asc_ranges.last_mut() {
                Some(last) if seq <= last.1.saturating_add(1) => {
                    // Extend or merge: handles both adjacent (seq == last.1+1)
                    // and duplicate (seq <= last.1) entries.
                    if seq > last.1 {
                        last.1 = seq;
                    }
                }
                _ => asc_ranges.push((seq, seq)),
            }
        }

        Self::from_ascending_coalesced(asc_ranges, ack_delay_us)
    }

    /// Build a [`Sack`] from explicit inclusive `(low, high)` ranges in any order
    /// (each must have `low <= high`). Ranges are sorted ascending, coalesced
    /// (adjacent/overlapping merged), reversed to descending, and **capped to the
    /// highest [`MAX_SACK_RANGES`]** so the encoded SACK always decodes at the peer
    /// (`from_wire` rejects `range_count > MAX_SACK_RANGES`). Dropping the lowest
    /// ranges is safe: those sequences are recovered by cumulative re-ACK as holes
    /// fill, or by RTO. Returns `None` if `ranges` is empty.
    pub fn from_inclusive_ranges(mut ranges: Vec<(u32, u32)>, ack_delay_us: u32) -> Option<Sack> {
        if ranges.is_empty() {
            return None;
        }
        ranges.sort_unstable_by_key(|&(lo, _)| lo);
        let mut asc: Vec<(u32, u32)> = Vec::with_capacity(ranges.len());
        for (lo, hi) in ranges {
            match asc.last_mut() {
                // Adjacent or overlapping with the previous (ascending) range → merge.
                Some(last) if lo <= last.1.saturating_add(1) => {
                    if hi > last.1 {
                        last.1 = hi;
                    }
                }
                _ => asc.push((lo, hi)),
            }
        }
        Self::from_ascending_coalesced(asc, ack_delay_us)
    }

    /// Shared tail for [`from_received`] / [`from_inclusive_ranges`]: take ascending,
    /// already-coalesced ranges, reverse to descending, **cap to the highest
    /// [`MAX_SACK_RANGES`]** (drop the lowest, oldest ranges so the wire form always
    /// decodes at the peer), set `largest_acked`, and construct. `None` if empty.
    fn from_ascending_coalesced(mut asc_ranges: Vec<(u32, u32)>, ack_delay_us: u32) -> Option<Sack> {
        if asc_ranges.is_empty() {
            return None;
        }
        // Reverse to descending order (highest first), then keep the highest ranges.
        asc_ranges.reverse();
        asc_ranges.truncate(MAX_SACK_RANGES);
        let largest_acked = asc_ranges[0].1;

        Some(Sack {
            largest_acked,
            ack_delay_us,
            ranges: asc_ranges,
        })
    }

    /// Returns the inclusive `(low, high)` ranges, sorted descending (highest
    /// first), non-overlapping and non-adjacent.  Always non-empty.
    pub fn ranges(&self) -> &[(u32, u32)] {
        &self.ranges
    }

    /// Serialise to wire bytes.
    ///
    /// Panics are structurally impossible: `ranges` is always non-empty (the
    /// invariant is enforced by the private field — only `from_received` and
    /// `from_wire` can construct a `Sack`, both of which guarantee at least one
    /// range), and the arithmetic cannot overflow because all fields fit in
    /// `u32`.
    pub fn to_wire(&self) -> Vec<u8> {
        let range_count = self.ranges.len();
        // 10 bytes fixed header + 4 bytes first_len + 8 bytes per continuation.
        let capacity = FIXED_HDR_LEN + 4 + CONTINUATION_BYTES * range_count.saturating_sub(1);
        let mut buf = Vec::with_capacity(capacity);

        buf.extend_from_slice(&self.largest_acked.to_be_bytes());
        buf.extend_from_slice(&self.ack_delay_us.to_be_bytes());
        // PANIC-SAFETY: range_count is bounded by the caller; values from
        // `from_received` are bounded by `received.len()` which is a `usize`
        // but in practice never close to u16::MAX.  Values from a decoded and
        // re-encoded Sack are already ≤ MAX_SACK_RANGES (32). We cast
        // defensively with `min` so an edge-case huge Vec produces a saturated
        // count rather than truncation silently dropping ranges.
        #[allow(clippy::cast_possible_truncation)]
        let range_count_wire = (range_count.min(u16::MAX as usize)) as u16;
        buf.extend_from_slice(&range_count_wire.to_be_bytes());

        // First range: [largest_acked - first_len, largest_acked].
        // `first_len` = high - low = range_width - 1.
        // PANIC-SAFETY: `ranges` is always non-empty — the field is private and
        // only populated by `from_received` (which requires a non-empty input)
        // and `from_wire` (which rejects range_count == 0).  This index cannot
        // panic.
        let (first_low, first_high) = self.ranges[0];
        // PANIC-SAFETY: `from_received` guarantees low ≤ high because ranges
        // are built from sorted sequences; `from_wire` validates the same
        // invariant before storing.  The subtraction cannot underflow.
        let first_len: u32 = first_high - first_low;
        buf.extend_from_slice(&first_len.to_be_bytes());

        // Continuation ranges: (gap, len) pairs.
        let mut prev_low = first_low;
        for &(low, high) in &self.ranges[1..] {
            // gap = number of unACKed sequences between prev range and this one.
            // prev_low - 1 is the sequence just below the previous range.
            // high      is the top of the current range.
            // gap = (prev_low - 1) - high   (both sides of the unACKed gap)
            // Since ranges are strictly descending with at least one gap seq,
            // prev_low >= high + 2 must hold (invariant checked on decode;
            // maintained by from_received which merges adjacent ranges).
            let gap: u32 = prev_low.saturating_sub(1).saturating_sub(high);
            buf.extend_from_slice(&gap.to_be_bytes());

            let len: u32 = high - low;
            buf.extend_from_slice(&len.to_be_bytes());

            prev_low = low;
        }

        buf
    }

    /// Decode a [`Sack`] from wire bytes produced by [`Sack::to_wire`].
    ///
    /// # Errors
    ///
    /// See [`SackError`] for the full error table.
    pub fn from_wire(buf: &[u8]) -> Result<Sack, SackError> {
        // Need at least the fixed header + first_len field.
        if buf.len() < MIN_WIRE_LEN {
            return Err(SackError::Truncated);
        }

        let largest_acked = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let ack_delay_us = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let range_count = u16::from_be_bytes([buf[8], buf[9]]) as usize;

        // Anti-DoS check BEFORE any allocation.
        if range_count == 0 {
            return Err(SackError::Malformed);
        }
        if range_count > MAX_SACK_RANGES {
            return Err(SackError::TooManyRanges);
        }

        // Check that the buffer is long enough for all declared ranges.
        // Wire size = 10 (fixed) + 4 (first_len) + 8*(range_count-1) (continuations)
        let needed = FIXED_HDR_LEN
            .checked_add(4)
            .and_then(|n| n.checked_add(CONTINUATION_BYTES * (range_count - 1)))
            .ok_or(SackError::Truncated)?;
        if buf.len() < needed {
            return Err(SackError::Truncated);
        }

        // Decode the first range.
        let first_len = u32::from_be_bytes([buf[10], buf[11], buf[12], buf[13]]);
        let first_high = largest_acked;
        let first_low = largest_acked
            .checked_sub(first_len)
            .ok_or(SackError::Malformed)?;

        let mut ranges: Vec<(u32, u32)> = Vec::with_capacity(range_count);
        ranges.push((first_low, first_high));

        // Decode continuation ranges.
        let mut prev_low = first_low;
        let mut pos = 14usize; // bytes consumed so far
        for _ in 1..range_count {
            let gap = u32::from_be_bytes([buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]]);
            let len = u32::from_be_bytes([buf[pos + 4], buf[pos + 5], buf[pos + 6], buf[pos + 7]]);
            pos += 8;

            // Fix 2: adjacent ranges (gap == 0) are invalid — the sender must
            // coalesce them.  Reject rather than silently accepting malformed
            // input.
            if gap == 0 {
                return Err(SackError::Malformed);
            }

            // high_i = prev_low - 1 - gap
            // prev_low must be ≥ gap + 1 so we don't wrap below 0.
            let below_prev = prev_low.checked_sub(1).ok_or(SackError::Malformed)?;
            let high = below_prev.checked_sub(gap).ok_or(SackError::Malformed)?;
            let low = high.checked_sub(len).ok_or(SackError::Malformed)?;

            // Ranges must be strictly descending and non-adjacent; `high` must
            // be strictly less than `prev_low - 1` (gap ≥ 1 enforced above).
            // The arithmetic already ensures high < prev_low.  We additionally
            // verify that low ≤ high (no inverted range).
            if low > high {
                return Err(SackError::Malformed);
            }

            ranges.push((low, high));
            prev_low = low;
        }

        Ok(Sack {
            largest_acked,
            ack_delay_us,
            ranges,
        })
    }

    /// Returns `true` if `seq` is covered by any range in this SACK.
    pub fn acks(&self, seq: u32) -> bool {
        for &(low, high) in &self.ranges {
            if seq >= low && seq <= high {
                return true;
            }
        }
        false
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    // ── from_received coalescing ──────────────────────────────────────────

    #[test]
    fn coalesces_to_descending_ranges() {
        // Input: [5,6,7,10,11,3] → ranges [(10,11),(5,7),(3,3)], largest 11
        let sack = Sack::from_received(&[5, 6, 7, 10, 11, 3], 0).unwrap();
        assert_eq!(sack.largest_acked, 11);
        assert_eq!(sack.ranges(), &[(10, 11), (5, 7), (3, 3)]);
    }

    #[test]
    fn from_received_empty_returns_none() {
        assert!(Sack::from_received(&[], 42).is_none());
    }

    #[test]
    fn from_received_single_seq() {
        let sack = Sack::from_received(&[7], 100).unwrap();
        assert_eq!(sack.largest_acked, 7);
        assert_eq!(sack.ranges(), &[(7, 7)]);
    }

    #[test]
    fn from_received_contiguous() {
        // 0..=9 should produce a single range (0, 9)
        let input: Vec<u32> = (0..=9).collect();
        let sack = Sack::from_received(&input, 0).unwrap();
        assert_eq!(sack.largest_acked, 9);
        assert_eq!(sack.ranges(), &[(0, 9)]);
    }

    #[test]
    fn from_received_duplicate_seqs_coalesced() {
        let sack = Sack::from_received(&[3, 3, 3, 5, 5], 0).unwrap();
        assert_eq!(sack.ranges(), &[(5, 5), (3, 3)]);
    }

    // ── F1: generation must cap to MAX_SACK_RANGES so the peer can decode ──

    #[test]
    fn from_received_caps_ranges_to_max_and_stays_decodable() {
        // 40 disjoint singleton islands (even sequences 0,2,..,78) → 40 ranges,
        // which a peer would reject as TooManyRanges. Generation must cap to 32,
        // keep the HIGHEST ranges (nearest largest_acked), and remain decodable.
        let seqs: Vec<u32> = (0u32..40).map(|i| i * 2).collect();
        let sack = Sack::from_received(&seqs, 0).expect("non-empty");
        assert!(
            sack.ranges().len() <= MAX_SACK_RANGES,
            "generated SACK must be capped to MAX_SACK_RANGES, got {}",
            sack.ranges().len()
        );
        // Kept the highest 32 ranges: (78,78) down to (16,16); largest unchanged.
        assert_eq!(sack.largest_acked, 78);
        assert_eq!(sack.ranges().len(), MAX_SACK_RANGES);
        assert_eq!(sack.ranges()[0], (78, 78));
        assert_eq!(sack.ranges()[MAX_SACK_RANGES - 1], (16, 16));
        let wire = sack.to_wire();
        let decoded = Sack::from_wire(&wire).expect("a capped SACK must decode at the peer");
        assert_eq!(decoded, sack);
    }

    #[test]
    fn from_inclusive_ranges_caps_and_keeps_highest() {
        // Ascending (low,high) input with 40 islands; keep the highest 32.
        let asc: Vec<(u32, u32)> = (0u32..40).map(|i| (i * 2, i * 2)).collect();
        let sack = Sack::from_inclusive_ranges(asc, 7).expect("non-empty");
        assert_eq!(sack.ack_delay_us, 7);
        assert_eq!(sack.ranges().len(), MAX_SACK_RANGES);
        assert_eq!(sack.largest_acked, 78);
        assert_eq!(sack.ranges()[0], (78, 78));
        // Decodes at the peer.
        assert_eq!(Sack::from_wire(&sack.to_wire()).expect("decode"), sack);
    }

    #[test]
    fn from_inclusive_ranges_coalesces_and_orders() {
        // Unsorted, with an adjacent pair (4,5)+(6,7) that must coalesce to (4,7).
        let sack = Sack::from_inclusive_ranges(vec![(6, 7), (0, 1), (4, 5)], 0).expect("non-empty");
        assert_eq!(sack.ranges(), &[(4, 7), (0, 1)]);
        assert_eq!(sack.largest_acked, 7);
        assert_eq!(Sack::from_wire(&sack.to_wire()).expect("decode"), sack);
    }

    #[test]
    fn from_inclusive_ranges_empty_is_none() {
        assert!(Sack::from_inclusive_ranges(Vec::new(), 0).is_none());
    }

    // ── round-trip tests ─────────────────────────────────────────────────

    #[test]
    fn roundtrip_multi_gap() {
        // Three disjoint ranges: (20,25), (10,13), (1,3)
        let sack =
            Sack::from_received(&[20, 21, 22, 23, 24, 25, 10, 11, 12, 13, 1, 2, 3], 1234).unwrap();
        assert_eq!(sack.ranges(), &[(20, 25), (10, 13), (1, 3)]);
        let wire = sack.to_wire();
        let decoded = Sack::from_wire(&wire).expect("should decode");
        assert_eq!(decoded, sack);
    }

    #[test]
    fn roundtrip_single_contiguous() {
        let sack = Sack::from_received(&(0u32..=9).collect::<Vec<_>>(), 0).unwrap();
        assert_eq!(sack.ranges(), &[(0, 9)]);
        let wire = sack.to_wire();
        let decoded = Sack::from_wire(&wire).expect("roundtrip single");
        assert_eq!(decoded, sack);
    }

    #[test]
    fn roundtrip_degenerate_single_seq() {
        let sack = Sack::from_received(&[42], 999).unwrap();
        assert_eq!(sack.largest_acked, 42);
        let wire = sack.to_wire();
        let decoded = Sack::from_wire(&wire).expect("roundtrip single seq");
        assert_eq!(decoded, sack);
    }

    #[test]
    fn roundtrip_from_received_coalesced() {
        let input = [5u32, 6, 7, 10, 11, 3];
        let sack = Sack::from_received(&input, 500).unwrap();
        let wire = sack.to_wire();
        let decoded = Sack::from_wire(&wire).expect("from_received roundtrip");
        assert_eq!(decoded, sack);
    }

    #[test]
    fn roundtrip_preserves_ack_delay() {
        let sack = Sack::from_received(&[1, 2, 3], 0xDEAD_BEEF).unwrap();
        let wire = sack.to_wire();
        let decoded = Sack::from_wire(&wire).expect("roundtrip ack_delay");
        assert_eq!(decoded.ack_delay_us, 0xDEAD_BEEF);
    }

    // ── Fix 1: large span round-trip (was silently truncated with u16) ────

    #[test]
    fn roundtrip_large_span_exceeds_u16() {
        // first_len = 100_000 − 0 = 100_000, which overflows u16::MAX (65535).
        // This is the exact case that was silently corrupted before the fix.
        let seqs: Vec<u32> = (0u32..=100_000).collect();
        let sack = Sack::from_received(&seqs, 0).unwrap();
        assert_eq!(sack.largest_acked, 100_000);
        assert_eq!(sack.ranges(), &[(0, 100_000)]);
        let wire = sack.to_wire();
        let decoded = Sack::from_wire(&wire).expect("large span must round-trip");
        assert_eq!(decoded, sack);
        // Verify first_len on wire (bytes 10..14) is 100_000 in big-endian u32.
        let first_len_wire = u32::from_be_bytes([wire[10], wire[11], wire[12], wire[13]]);
        assert_eq!(first_len_wire, 100_000u32);
    }

    #[test]
    fn roundtrip_large_gap_exceeds_u16() {
        // Two ranges: (200_000, 200_000) and (0, 0).
        // gap = 200_000 - 1 - 0 = 199_999, which overflows u16::MAX.
        let sack = Sack::from_received(&[200_000u32, 0], 0).unwrap();
        assert_eq!(sack.ranges(), &[(200_000, 200_000), (0, 0)]);
        let wire = sack.to_wire();
        let decoded = Sack::from_wire(&wire).expect("large gap must round-trip");
        assert_eq!(decoded, sack);
        // Verify gap on wire (bytes 14..18) is 199_999 in big-endian u32.
        // Layout: largest_acked(4) + ack_delay_us(4) + range_count(2) + first_len(4) = 14
        // then gap(4) starting at byte 14.
        let gap_wire = u32::from_be_bytes([wire[14], wire[15], wire[16], wire[17]]);
        assert_eq!(gap_wire, 199_999u32);
    }

    // ── Fix 2: gap == 0 must be rejected as Malformed ────────────────────

    #[test]
    fn decode_gap_zero_is_malformed() {
        // Craft a 2-range SACK where gap == 0 (adjacent ranges).
        // Wire layout (u32 fields):
        //   largest_acked=10, ack_delay=0, range_count=2,
        //   first_len=0  (range (10,10)),
        //   gap=0, len=0 (adjacent range (9,9) — invalid)
        let mut buf = vec![0u8; 22]; // 10 + 4 + 8 = 22 bytes for 2 ranges
        buf[0..4].copy_from_slice(&10u32.to_be_bytes()); // largest_acked
        buf[4..8].copy_from_slice(&0u32.to_be_bytes()); // ack_delay_us
        buf[8..10].copy_from_slice(&2u16.to_be_bytes()); // range_count = 2
        buf[10..14].copy_from_slice(&0u32.to_be_bytes()); // first_len = 0
        buf[14..18].copy_from_slice(&0u32.to_be_bytes()); // gap = 0  ← invalid
        buf[18..22].copy_from_slice(&0u32.to_be_bytes()); // len = 0
        assert!(
            matches!(Sack::from_wire(&buf), Err(SackError::Malformed)),
            "gap == 0 must be rejected as Malformed"
        );
    }

    // ── acks() helper ────────────────────────────────────────────────────

    #[test]
    fn acks_correctness_across_gaps() {
        // Ranges: (10,11), (5,7), (3,3)
        let sack = Sack::from_received(&[5, 6, 7, 10, 11, 3], 0).unwrap();

        // Covered sequences
        for seq in [3u32, 5, 6, 7, 10, 11] {
            assert!(sack.acks(seq), "expected seq {seq} to be ACKed");
        }
        // Gaps
        for seq in [0u32, 1, 2, 4, 8, 9, 12, 100] {
            assert!(!sack.acks(seq), "expected seq {seq} to NOT be ACKed");
        }
    }

    #[test]
    fn acks_single_seq() {
        let sack = Sack::from_received(&[99], 0).unwrap();
        assert!(sack.acks(99));
        assert!(!sack.acks(98));
        assert!(!sack.acks(100));
    }

    // ── decode error cases ───────────────────────────────────────────────

    #[test]
    fn decode_truncated_too_short() {
        // Need at least 14 bytes; supply 13
        let buf = [0u8; 13];
        assert!(
            matches!(Sack::from_wire(&buf), Err(SackError::Truncated)),
            "expected Truncated for 13-byte buffer"
        );
    }

    #[test]
    fn decode_truncated_claimed_ranges_exceed_buffer() {
        // Header claims 2 ranges but buffer only has the 1-range minimum (14 bytes).
        // 2 ranges need 14 + 8 = 22 bytes.
        let mut buf = vec![0u8; 14];
        // largest_acked = 10
        buf[0..4].copy_from_slice(&10u32.to_be_bytes());
        // ack_delay_us = 0
        buf[4..8].copy_from_slice(&0u32.to_be_bytes());
        // range_count = 2
        buf[8..10].copy_from_slice(&2u16.to_be_bytes());
        // first_len = 0
        buf[10..14].copy_from_slice(&0u32.to_be_bytes());
        // Buffer is only 14 bytes but 2 ranges need 22 bytes → Truncated
        assert!(
            matches!(Sack::from_wire(&buf), Err(SackError::Truncated)),
            "expected Truncated when buffer too small for claimed ranges"
        );
    }

    #[test]
    fn decode_too_many_ranges() {
        // Craft a header with range_count = MAX_SACK_RANGES + 1
        let bad_count = (MAX_SACK_RANGES + 1) as u16;
        let needed = FIXED_HDR_LEN + 4 + CONTINUATION_BYTES * MAX_SACK_RANGES; // one more than max
        let mut buf = vec![0u8; needed + CONTINUATION_BYTES]; // enough bytes to not be Truncated
                                                              // largest_acked = 0xFFFF_FFFF so ranges have room to descend
        buf[0..4].copy_from_slice(&u32::MAX.to_be_bytes());
        buf[4..8].copy_from_slice(&0u32.to_be_bytes());
        buf[8..10].copy_from_slice(&bad_count.to_be_bytes());
        // first_len and continuations don't matter — check happens before decode
        assert!(
            matches!(Sack::from_wire(&buf), Err(SackError::TooManyRanges)),
            "expected TooManyRanges for range_count = MAX+1"
        );
    }

    #[test]
    fn decode_zero_range_count_is_malformed() {
        let mut buf = vec![0u8; 14];
        buf[8..10].copy_from_slice(&0u16.to_be_bytes()); // range_count = 0
        assert!(
            matches!(Sack::from_wire(&buf), Err(SackError::Malformed)),
            "expected Malformed for range_count == 0"
        );
    }

    #[test]
    fn decode_first_len_underflow_is_malformed() {
        // largest_acked = 3, first_len = 5 → low would be 3 - 5 (underflow)
        let mut buf = vec![0u8; 14];
        buf[0..4].copy_from_slice(&3u32.to_be_bytes()); // largest_acked = 3
        buf[4..8].copy_from_slice(&0u32.to_be_bytes());
        buf[8..10].copy_from_slice(&1u16.to_be_bytes()); // range_count = 1
        buf[10..14].copy_from_slice(&5u32.to_be_bytes()); // first_len = 5 (> 3)
        assert!(
            matches!(Sack::from_wire(&buf), Err(SackError::Malformed)),
            "expected Malformed when first_len underflows"
        );
    }

    #[test]
    fn decode_continuation_gap_underflow_is_malformed() {
        // First range: largest_acked=5, first_len=0 → range (5,5)
        // Continuation gap=10, len=0 → high = 5 - 1 - 10 = underflow
        let mut buf = vec![0u8; 22]; // 14 + 8 for one continuation
        buf[0..4].copy_from_slice(&5u32.to_be_bytes()); // largest_acked = 5
        buf[4..8].copy_from_slice(&0u32.to_be_bytes());
        buf[8..10].copy_from_slice(&2u16.to_be_bytes()); // range_count = 2
        buf[10..14].copy_from_slice(&0u32.to_be_bytes()); // first_len = 0
        buf[14..18].copy_from_slice(&10u32.to_be_bytes()); // gap = 10 (underflows)
        buf[18..22].copy_from_slice(&0u32.to_be_bytes()); // len = 0
        assert!(
            matches!(Sack::from_wire(&buf), Err(SackError::Malformed)),
            "expected Malformed when continuation gap underflows"
        );
    }

    // ── wire size sanity ─────────────────────────────────────────────────

    #[test]
    fn wire_size_1_range() {
        let sack = Sack::from_received(&[5], 0).unwrap();
        assert_eq!(sack.to_wire().len(), 14);
    }

    #[test]
    fn wire_size_2_ranges() {
        let sack = Sack::from_received(&[8, 9, 10, 3, 4, 5], 0).unwrap();
        assert_eq!(sack.ranges(), &[(8, 10), (3, 5)]);
        assert_eq!(sack.to_wire().len(), 22);
    }

    #[test]
    fn wire_size_n_ranges() {
        // Build a 5-range SACK with gaps >0 between each range.
        // Ranges (descending): (80,89), (60,69), (40,49), (20,29), (0,9)
        let mut seqs: Vec<u32> = Vec::new();
        for i in 0u32..5 {
            for s in (i * 20)..(i * 20 + 10) {
                seqs.push(s);
            }
        }
        let sack = Sack::from_received(&seqs, 0).unwrap();
        let n = sack.ranges().len();
        assert_eq!(n, 5);
        assert_eq!(sack.to_wire().len(), 10 + 4 + 8 * (n - 1));
    }

    // ── Display / Error trait ────────────────────────────────────────────

    #[test]
    fn sack_error_display_is_non_empty() {
        for e in [
            SackError::Truncated,
            SackError::TooManyRanges,
            SackError::Malformed,
        ] {
            let s = e.to_string();
            assert!(!s.is_empty(), "Display must not be empty for {e:?}");
        }
    }

    #[test]
    fn sack_error_is_std_error() {
        // Verify the trait bound compiles and the source chain is None.
        let e: &dyn std::error::Error = &SackError::Truncated;
        assert!(e.source().is_none());
    }
}
