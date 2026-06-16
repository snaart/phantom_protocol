//! Traffic shaping — anti-fingerprint size padding (WIRE v6, deliverable (c)).
//!
//! The data-plane datagram size otherwise tracks the application payload size
//! (even with the v6 length-prefix diet, the datagram *length* is observable).
//! This module hides it by padding each packet up to a size **bucket** before it
//! is sealed, so an on-path observer sees only a small set of sizes.
//!
//! Padding lives **inside** the AEAD plaintext (encrypted + authenticated), so a
//! network attacker can neither see it, strip it, nor forge it — only the bucketed
//! datagram size is observable. A padded packet sets
//! [`PacketFlags::PADDED`](crate::transport::types::PacketFlags::PADDED); its
//! plaintext gains a trailer `‹pad_n zero bytes› ‖ pad_n:u16be`, which the receiver
//! strips after a successful decrypt.
//!
//! The policy that picks the bucket is **PADÉ** (Nikitin et al., "PURBs", 2019):
//! a length is rounded up so its low `E−S` bits are zero (`E = ⌊log2 L⌋`,
//! `S = ⌊log2 E⌋+1`), which caps the overhead at ≈ `1/E` (≤ ~12% for small
//! packets, →0 for large) while collapsing the size distribution to O(log) values
//! per magnitude. Far cheaper than pad-to-MTU, far better than fixed buckets near
//! their edges.
//!
//! Pure + `no_std`-friendly (no allocation in the size math; `append`/`strip`
//! operate on caller buffers). Default policy is [`PaddingPolicy::None`] — shaping
//! is fully opt-in (it costs bandwidth).

use crate::crypto::adaptive_crypto::AEAD_OVERHEAD;
use crate::transport::types::{PacketHeader, WireError};
use std::time::Duration;

/// Upper bound on the padded on-wire packet size (the `PhantomPacket` wire image:
/// 15-byte header + ciphertext). Capped below the 1200-byte path MTU with margin
/// for the largest transport envelope (the 8-byte UDP `ConnId`, plus slack), so a
/// padded datagram never fragments. A packet already larger than this is not
/// padded (it is near-MTU already — low size entropy).
pub const MAX_SHAPED_WIRE: usize = 1184;

/// Size of the in-plaintext padding length field (`pad_n: u16be`). The minimum
/// trailer a padded packet carries (with `pad_n == 0` zero bytes).
pub const PAD_LEN_FIELD: usize = 2;

/// How a packet's on-wire size is chosen before sealing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "bindings", derive(uniffi::Enum))]
pub enum PaddingPolicy {
    /// No padding — the wire size is the natural payload size (default).
    #[default]
    None,
    /// PADÉ bucketing (bounded ≈12% worst-case overhead).
    Padme,
}

/// PADÉ: round `l` up so its low `E−S` bits are zero, where `E = ⌊log2 l⌋` and
/// `S = ⌊log2 E⌋ + 1`. Returns `l` unchanged for `l ≤ 2` (nothing to round).
/// Monotone non-decreasing and idempotent; overhead `(padme(l) − l)/l < 2^−S`.
pub fn padme(l: usize) -> usize {
    if l <= 2 {
        return l;
    }
    // E = ⌊log2 l⌋ (≥ 1 here); S = ⌊log2 E⌋ + 1 = bits needed to represent E.
    let e = l.ilog2() as usize;
    let s = if e == 0 { 1 } else { e.ilog2() as usize + 1 };
    let mask_bits = e.saturating_sub(s);
    // Round `l` up, clearing its low `mask_bits` bits.
    let mask = (1usize << mask_bits) - 1;
    (l + mask) & !mask
}

/// The number of trailer bytes to append to the AEAD **plaintext** to bring the
/// resulting on-wire packet to a PADÉ bucket. `0` when no padding applies (policy
/// `None`, or the packet is already too large to pad under [`MAX_SHAPED_WIRE`]).
/// When non-zero it is `≥ PAD_LEN_FIELD` (the 2-byte length field plus zero fill).
///
/// `plaintext_len` is the length of the inner AEAD plaintext *before* padding; the
/// on-wire size is `header(15) + plaintext_len + AEAD_OVERHEAD`.
pub fn padding_trailer_len(plaintext_len: usize, policy: PaddingPolicy) -> usize {
    match policy {
        PaddingPolicy::None => 0,
        PaddingPolicy::Padme => {
            let wire = PacketHeader::SIZE + plaintext_len + AEAD_OVERHEAD;
            // Target a bucket at least `PAD_LEN_FIELD` above the current wire size
            // (we must have room for the mandatory pad-length field), capped so the
            // datagram cannot exceed the MTU.
            let target = padme(wire + PAD_LEN_FIELD).min(MAX_SHAPED_WIRE);
            if target >= wire + PAD_LEN_FIELD {
                target - wire
            } else {
                0
            }
        }
    }
}

/// Append a padding trailer of `trailer` total bytes to `plaintext`:
/// `(trailer − PAD_LEN_FIELD)` zero bytes, then the big-endian `u16` count of
/// those zero bytes. `trailer` must be `≥ PAD_LEN_FIELD` and `≤ u16::MAX +
/// PAD_LEN_FIELD` (callers get `trailer` from [`padding_trailer_len`], which
/// respects both). A `trailer < PAD_LEN_FIELD` is a no-op (defensive).
pub fn append_padding(plaintext: &mut Vec<u8>, trailer: usize) {
    if trailer < PAD_LEN_FIELD {
        return;
    }
    let pad_n = (trailer - PAD_LEN_FIELD) as u16;
    plaintext.resize(plaintext.len() + pad_n as usize, 0);
    plaintext.extend_from_slice(&pad_n.to_be_bytes());
}

/// Strip a padding trailer from a decrypted, `PADDED`-flagged plaintext: read the
/// trailing `u16be` pad length, then drop that many zero bytes plus the 2-byte
/// field. Returns the inner plaintext slice. A trailer that claims more bytes than
/// are present is [`WireError::Truncated`] (an authenticated peer cannot reach this
/// with a malformed trailer — the AEAD already verified — but a buggy peer must not
/// panic the receiver).
pub fn strip_padding(plaintext: &[u8]) -> Result<&[u8], WireError> {
    if plaintext.len() < PAD_LEN_FIELD {
        return Err(WireError::Truncated);
    }
    let split = plaintext.len() - PAD_LEN_FIELD;
    let pad_n = u16::from_be_bytes([plaintext[split], plaintext[split + 1]]) as usize;
    let inner_len = split.checked_sub(pad_n).ok_or(WireError::Truncated)?;
    Ok(&plaintext[..inner_len])
}

/// Anti-fingerprint timing jitter (WIRE v6, deliverable (d)): a **uniform random**
/// delay in `[0, max_ms]` milliseconds to add before a send, so the inter-packet
/// timing no longer tracks the application's write pattern. Returns
/// `Duration::ZERO` when `max_ms == 0` (jitter off). Opt-in; it trades up to
/// `max_ms` of added latency per packet for timing-correlation resistance.
pub fn random_jitter(max_ms: u32) -> Duration {
    if max_ms == 0 {
        return Duration::ZERO;
    }
    use rand::Rng;
    // Inclusive `[0, max_ms]` so both endpoints are reachable.
    let ms = rand::thread_rng().gen_range(0..=max_ms);
    Duration::from_millis(ms as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// PADÉ rounds to the expected buckets (hand-computed): the low `E−S` bits are
    /// zeroed, so powers of two and just-below-power values collapse together.
    #[test]
    fn padme_rounds_to_expected_buckets() {
        assert_eq!(padme(0), 0);
        assert_eq!(padme(1), 1);
        assert_eq!(padme(2), 2);
        assert_eq!(padme(3), 3); // E=1,S=1 → 0 low bits → unchanged
        assert_eq!(padme(63), 64); // E=5,S=3 → clear 2 bits → 64
        assert_eq!(padme(64), 64); // power of two → unchanged
        assert_eq!(padme(100), 104); // E=6,S=3 → clear 3 bits → 104
        assert_eq!(padme(1000), 1024); // E=9,S=4 → clear 5 bits → 1024
    }

    /// PADÉ is monotone non-decreasing, never shrinks a length, is idempotent, and
    /// the overhead is bounded (≤ ~12% above 8 bytes).
    #[test]
    fn padme_is_monotone_idempotent_and_bounded() {
        let mut prev = 0;
        for l in 0..4096usize {
            let p = padme(l);
            assert!(p >= l, "padme never shrinks: padme({l})={p}");
            assert!(p >= prev, "padme is monotone: padme({l})={p} < prev {prev}");
            assert_eq!(padme(p), p, "padme is idempotent at the bucket {p}");
            if l >= 8 {
                assert!(
                    (p - l) * 100 <= l * 12,
                    "overhead bound: padme({l})={p} exceeds ~12%"
                );
            }
            prev = p;
        }
    }

    /// A padding trailer round-trips: stripping `plaintext ‖ append(trailer)`
    /// recovers exactly `plaintext`, for every inner length and every trailer the
    /// policy can pick.
    #[test]
    fn append_then_strip_is_identity() {
        for inner_len in [0usize, 1, 15, 16, 17, 100, 500, 1100] {
            let inner: Vec<u8> = (0..inner_len).map(|i| (i % 251) as u8).collect();
            let trailer = padding_trailer_len(inner_len, PaddingPolicy::Padme);
            let mut padded = inner.clone();
            append_padding(&mut padded, trailer);
            // The padded wire size lands on a PADÉ bucket (or is capped).
            let wire = PacketHeader::SIZE + padded.len() + AEAD_OVERHEAD;
            if trailer > 0 {
                assert!(wire <= MAX_SHAPED_WIRE);
                assert_eq!(
                    wire,
                    padme(PacketHeader::SIZE + inner_len + AEAD_OVERHEAD + PAD_LEN_FIELD)
                        .min(MAX_SHAPED_WIRE)
                );
            }
            let recovered = strip_padding(&padded).expect("strip");
            assert_eq!(recovered, &inner[..], "strip(append(x)) == x");
        }
    }

    /// `None` policy never pads; near-MTU packets are not padded (would fragment).
    #[test]
    fn policy_none_and_mtu_cap() {
        assert_eq!(padding_trailer_len(500, PaddingPolicy::None), 0);
        // A plaintext whose wire size is already at/above the cap → no padding.
        let big = MAX_SHAPED_WIRE; // wire would exceed the cap once header+tag added
        assert_eq!(padding_trailer_len(big, PaddingPolicy::Padme), 0);
    }

    /// Timing jitter is bounded to `[0, max_ms]` and actually varies (so it isn't
    /// the trivial zero implementation); `max_ms == 0` disables it.
    #[test]
    fn random_jitter_is_bounded_and_varies() {
        assert_eq!(random_jitter(0), Duration::ZERO, "0 disables jitter");
        let max = 15u32;
        let cap = Duration::from_millis(max as u64);
        let mut saw_nonzero = false;
        for _ in 0..1000 {
            let d = random_jitter(max);
            assert!(d <= cap, "jitter {d:?} exceeds the {max}ms ceiling");
            if d > Duration::ZERO {
                saw_nonzero = true;
            }
        }
        assert!(
            saw_nonzero,
            "jitter must actually add delay (not always zero)"
        );
    }

    /// A malformed trailer (claims more pad than present) is a typed error, never a
    /// panic — a buggy authenticated peer must not crash the receiver.
    #[test]
    fn strip_rejects_malformed_trailer() {
        // pad_n = 0xFFFF but only a few bytes present.
        let bad = vec![0u8, 0u8, 0xFF, 0xFF];
        assert_eq!(strip_padding(&bad), Err(WireError::Truncated));
        // Shorter than the length field.
        assert_eq!(strip_padding(&[0u8]), Err(WireError::Truncated));
    }
}
