//! Bitmap-based sliding-window replay detection (RFC 4303 § 3.4.3 / IPsec ESP).
//!
//! Per-direction replay protection for the data plane (① — Phase 4). Tracks the
//! highest accepted packet number plus a 1024-bit bitmap covering
//! `[high - 1024 + 1, high]`, rejecting duplicates and out-of-window-old packets.
//!
//! ## Why this exists if the AEAD already prevents replay
//!
//! The AEAD nonce is `nonce_prefix || header.packet_number` — derived from the
//! authenticated `u64` packet number in the wire header, not an internal
//! counter. A replayed packet therefore reuses a nonce + AAD that the receiver
//! has already opened, but the AEAD open *itself* does not reject a duplicate
//! (a faithfully-replayed ciphertext still verifies). This window is what makes
//! replay an explicit, **observable** rejection:
//!
//! - Yields the `CoreError::ReplayDetected` error variant and bumps the
//!   `replay_rejected_total` counter (metrics / detection signal).
//! - Enforces freshness on top of confidentiality + integrity: even an exact
//!   re-injection of an authentic packet is dropped once.
//! - Tolerates legitimate reordering within the window (out-of-order delivery
//!   on the reliable transport) while still rejecting true duplicates.
//!
//! **Ordering (Invariant 4):** in `Session::decrypt_packet` the window is
//! consulted *after* a successful AEAD open, never before — so the window never
//! keys off an attacker-controlled (un-authenticated) packet number, and a
//! spoofed counter cannot drive a timing channel.
//!
//! ## Window semantics
//!
//! - `WINDOW_BITS = 1024`. Bit 0 represents `high_watermark`; bit `i` represents
//!   `high_watermark - i`.
//! - Sequence numbers strictly greater than `high_watermark` advance the window
//!   (left-shift the bitmap, mark bit 0).
//! - Sequence numbers within the window: check the bit; reject if set, accept
//!   and set the bit otherwise.
//! - Sequence numbers below `high_watermark - WINDOW_BITS + 1`: too old, reject.
//!
//! The struct is small (128-byte bitmap + a couple of small words) and intended
//! to be held once per direction under a `parking_lot::Mutex`.

/// Width of the sliding window in bits. 1024 matches RFC 4303's recommended
/// upper bound and gives us comfortable headroom for severely reordered
/// transports.
pub const WINDOW_BITS: usize = 1024;
const WINDOW_WORDS: usize = WINDOW_BITS / 64;

/// Sliding-window replay tracker for one direction's packet-number space.
#[derive(Debug)]
pub struct ReplayWindow {
    /// Bitmap. Bit `i` (counting from LSB of word 0) corresponds to
    /// `high_watermark - i`. Bit 0 is the high-watermark itself.
    bitmap: [u64; WINDOW_WORDS],
    /// Highest accepted packet number seen so far.
    high_watermark: u64,
    /// Whether any packet has been accepted yet. Until the first packet, every
    /// sequence number is novel.
    initialized: bool,
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplayWindow {
    /// Create an empty window. The first `accept` call is always accepted.
    pub const fn new() -> Self {
        Self {
            bitmap: [0u64; WINDOW_WORDS],
            high_watermark: 0,
            initialized: false,
        }
    }

    /// Attempt to accept a new sequence number.
    ///
    /// Returns `true` if the sequence is novel (never seen before AND within
    /// the window). Updates internal state to record the acceptance.
    ///
    /// Returns `false` for:
    /// - Exact duplicate of a previously-accepted sequence within the window.
    /// - Sequence below the window (too old).
    pub fn accept(&mut self, seq: u64) -> bool {
        if !self.initialized {
            self.high_watermark = seq;
            self.bitmap[0] = 1; // bit 0 set: high_watermark itself
            self.initialized = true;
            return true;
        }

        if seq > self.high_watermark {
            let shift = (seq - self.high_watermark) as usize;
            if shift >= WINDOW_BITS {
                // Big forward jump — entire window beyond the old high. Reset.
                self.bitmap = [0u64; WINDOW_WORDS];
            } else {
                Self::shift_left(&mut self.bitmap, shift);
            }
            self.bitmap[0] |= 1; // mark new high
            self.high_watermark = seq;
            true
        } else {
            let offset = (self.high_watermark - seq) as usize;
            if offset >= WINDOW_BITS {
                return false; // too old, beyond the window
            }
            let word = offset / 64;
            let bit = offset % 64;
            let mask = 1u64 << bit;
            if self.bitmap[word] & mask != 0 {
                false // duplicate
            } else {
                self.bitmap[word] |= mask;
                true
            }
        }
    }

    /// Highest accepted sequence number. Returns 0 if no packets have been
    /// accepted yet (caller should check `is_initialized` to disambiguate).
    pub fn high_watermark(&self) -> u64 {
        self.high_watermark
    }

    /// Whether any packet has been accepted yet.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Left-shift the bitmap by `shift` bits (`shift < WINDOW_BITS`).
    ///
    /// "Left" in the conceptual layout: bit at position `i` moves to position
    /// `i + shift`. In multi-word storage with bit 0 at LSB of word 0, this
    /// is a high-word shift in big-endian-bit ordering.
    fn shift_left(bitmap: &mut [u64; WINDOW_WORDS], shift: usize) {
        debug_assert!(shift < WINDOW_BITS);
        let word_shift = shift / 64;
        let bit_shift = shift % 64;

        if word_shift > 0 {
            // Move each word `word_shift` positions toward higher indices.
            // The lowest `word_shift` words become 0.
            for i in (word_shift..WINDOW_WORDS).rev() {
                bitmap[i] = bitmap[i - word_shift];
            }
            for word in bitmap[..word_shift].iter_mut() {
                *word = 0;
            }
        }

        if bit_shift > 0 {
            let inv = 64 - bit_shift;
            // From high-index to low: shift within each word and OR in the
            // carry from the next-lower word.
            for i in (1..WINDOW_WORDS).rev() {
                bitmap[i] = (bitmap[i] << bit_shift) | (bitmap[i - 1] >> inv);
            }
            bitmap[0] <<= bit_shift;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_packet_always_accepted() {
        let mut w = ReplayWindow::new();
        assert!(w.accept(42));
        assert!(w.is_initialized());
        assert_eq!(w.high_watermark(), 42);
    }

    #[test]
    fn duplicate_is_rejected() {
        let mut w = ReplayWindow::new();
        assert!(w.accept(10));
        assert!(!w.accept(10));
    }

    #[test]
    fn monotonic_sequence_accepted() {
        let mut w = ReplayWindow::new();
        for seq in 1..=2000u64 {
            assert!(w.accept(seq), "seq {} must be accepted", seq);
        }
        assert_eq!(w.high_watermark(), 2000);
    }

    #[test]
    fn out_of_order_within_window_accepted_once() {
        let mut w = ReplayWindow::new();
        assert!(w.accept(100));
        assert!(w.accept(90)); // within window
        assert!(!w.accept(90)); // duplicate
        assert!(w.accept(80));
        assert!(!w.accept(80));
        assert!(w.accept(99));
        assert!(!w.accept(99));
        // High watermark unchanged after older packets.
        assert_eq!(w.high_watermark(), 100);
    }

    #[test]
    fn ancient_packet_rejected() {
        let mut w = ReplayWindow::new();
        assert!(w.accept(2000));
        // Window covers [high - WINDOW_BITS + 1, high] inclusive
        //              = [2000 - 1024 + 1, 2000]
        //              = [977, 2000].
        // 977 is the lowest sequence still in-window.
        assert!(w.accept(977));
        // 976 is below the window edge.
        assert!(!w.accept(976));
        assert!(!w.accept(100));
        assert!(!w.accept(0));
    }

    #[test]
    fn large_forward_jump_resets_window() {
        let mut w = ReplayWindow::new();
        assert!(w.accept(1));
        assert!(w.accept(10_000)); // huge jump > WINDOW_BITS
        assert_eq!(w.high_watermark(), 10_000);
        // Old in-window-of-1 packet is now far outside the new window.
        assert!(!w.accept(1));
        // But 9_000 (within new window) is fine.
        assert!(w.accept(9_000));
        assert!(!w.accept(9_000));
    }

    #[test]
    fn shift_within_word() {
        let mut w = ReplayWindow::new();
        assert!(w.accept(5));
        assert!(w.accept(10)); // shifts by 5
                               // 5 should still be marked (bit 5 of word 0).
        assert!(!w.accept(5));
        assert!(!w.accept(10));
    }

    #[test]
    fn shift_across_word_boundary() {
        let mut w = ReplayWindow::new();
        assert!(w.accept(0));
        assert!(w.accept(64)); // crosses word boundary on shift
        assert!(!w.accept(64));
        assert!(!w.accept(0));
        assert!(w.accept(32));
        assert!(!w.accept(32));
    }

    #[test]
    fn shift_multiple_words() {
        let mut w = ReplayWindow::new();
        assert!(w.accept(0));
        assert!(w.accept(100)); // shifts by 100 = 1 word + 36 bits
        assert!(!w.accept(0));
        assert!(!w.accept(100));
        assert!(w.accept(50));
        assert!(!w.accept(50));
    }

    #[test]
    fn boundary_exactly_at_window_edge() {
        let mut w = ReplayWindow::new();
        assert!(w.accept(WINDOW_BITS as u64));
        // The edge: high_watermark - WINDOW_BITS + 1 = 1 → accepted.
        assert!(w.accept(1));
        // One below the edge: 0 → too old.
        assert!(!w.accept(0));
    }
}
