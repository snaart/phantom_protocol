//! The path-MTU budget, and the application-chunk size derived from it.
//!
//! A datagram is this protocol's unit of loss. The sender therefore has to size an
//! application chunk so that the packet it becomes still fits **one** PhantomUDP
//! datagram: a chunk that overflows the budget by a single byte is fragmented into
//! a full datagram plus a small tail, which
//!
//! - doubles the datagram rate for the same goodput;
//! - makes the segment depend on *both* datagrams arriving, so an independent
//!   per-datagram loss rate `p` becomes `1 − (1 − p)² ≈ 2p` per segment — and loss
//!   recovery, the SACK loss detector and the BBR loss threshold all count
//!   segments, not datagrams;
//! - spends an 8-byte fragment subheader plus a fresh 28-byte IP/UDP header on a
//!   tail that carries a hundred-odd bytes.
//!
//! The constants live here rather than beside the UDP envelope because the code
//! that does the chunking (`api::session`'s data pump) also compiles for targets
//! that never build the UDP transport at all — browser wasm, WASI, embedded UART.
//! `phantom_udp::envelope` re-exports them, so there is still exactly one
//! definition of the budget.
//!
//! On the byte-pipe legs (TCP, mimicry, WebSocket, WASI, embedded) the chunk size
//! is not a correctness constraint at all — those transports frame whatever they
//! are handed and never fragment — so sizing for the datagram budget only costs
//! them a slightly higher share of per-packet overhead.

use crate::crypto::adaptive_crypto::AEAD_OVERHEAD;
use crate::transport::types::PacketHeader;

/// Conservative fixed path-MTU budget: 1200 bytes is the QUIC-style floor that
/// survives almost every Internet path without IP fragmentation. Static today —
/// dynamic DPLPMTUD to raise it is future work.
pub const PATH_MTU: usize = 1200;

/// The PhantomUDP outer datagram header: one flags byte plus the 8-byte rotating
/// `ConnId`. Unauthenticated transport framing, outside the frozen inner wire.
/// `phantom_udp::envelope::HDR_LEN` is this constant, and asserts it agrees with
/// `1 + CID_LEN` there.
pub const DATAGRAM_HDR_LEN: usize = 1 + 8;

/// Largest inner frame that fits one unfragmented datagram. Anything longer is
/// split by `phantom_udp::datagram::encode_datagrams`.
pub const MAX_INNER_UNFRAGMENTED: usize = PATH_MTU - DATAGRAM_HDR_LEN;

/// Bytes the reliable path prefixes to the AEAD **plaintext**: the gap-free
/// per-stream `stream_offset`, big-endian `u32` (A.5). Unreliable and control
/// frames carry no prefix, so budgeting for this is the worst case — it leaves an
/// unreliable datagram four bytes under the budget rather than over it.
pub const RELIABLE_OFFSET_LEN: usize = 4;

/// Everything one reliable application chunk costs on the wire beyond its own
/// bytes, measured on the inner frame that the UDP transport is handed:
/// `header ‖ AEAD(stream_offset ‖ chunk)`. Header protection masks the header in
/// place and does not resize it; the AEAD tag is appended to the ciphertext.
pub const PER_PACKET_OVERHEAD: usize = PacketHeader::SIZE + RELIABLE_OFFSET_LEN + AEAD_OVERHEAD;

/// Largest application chunk the data pump hands to a stream, so that the packet
/// it becomes is exactly one unfragmented PhantomUDP datagram:
///
/// ```text
///   1200   PATH_MTU
/// −    9   DATAGRAM_HDR_LEN        (outer [flags][ConnId])
/// ------
///   1191   MAX_INNER_UNFRAGMENTED
/// −   15   PacketHeader::SIZE
/// −    4   RELIABLE_OFFSET_LEN     (in-plaintext gap-free stream offset)
/// −   16   AEAD_OVERHEAD           (Poly1305 / GCM tag)
/// ------
///   1156   MAX_APP_CHUNK
/// ```
///
/// Derived, not chosen: raising `PATH_MTU` (say, once DPLPMTUD lands) widens the
/// chunk automatically, and nothing else has to move.
pub const MAX_APP_CHUNK: usize = MAX_INNER_UNFRAGMENTED - PER_PACKET_OVERHEAD;

/// Largest inner frame the data pump will accept from a peer, in bytes.
///
/// Everything above is a sender-side budget: it says how this side chunks, and a
/// peer is under no obligation to have read it. What the receive path was left
/// with instead was whatever its byte pipe would hand over — 4 MiB on the TCP and
/// mimicry legs once the frame phase goes to `Established`, a quarter-megabyte
/// reassembly on PhantomUDP — and every one of those bytes came to rest in a
/// per-stream delivery slot whose only limit is a slot *count*. A queue bounded
/// in items holds whatever the items weigh, so the weight has to be bounded here.
///
/// This is the same budget read from the other side: a frame this side would
/// never emit is one it will not accept. Nothing on the wire changes — the format
/// is untouched and no field carries a length — it is a receive-side rejection,
/// so a peer that respects the chunking rule cannot tell it exists.
///
/// The three post-handshake frame shapes are all under it by construction, and
/// the asserts below are what keep them there: a full reliable data chunk fills
/// it exactly, anti-fingerprint padding has its own lower ceiling
/// (`shaping::MAX_SHAPED_WIRE`), and the largest control frame is a full SACK,
/// which is an order of magnitude smaller. Handshake messages are far larger —
/// a `ServerHello` carries an ML-DSA-65 signature — but they are exchanged before
/// the pump exists and never reach this gate.
pub const MAX_RECV_FRAME: usize = MAX_INNER_UNFRAGMENTED;

/// Largest AEAD plaintext a peer can deliver in one frame: [`MAX_RECV_FRAME`]
/// less the header it carries and the tag it is sealed with.
///
/// This is the figure that bounds one queued delivery item, and it is the reason
/// the per-stream channels can be described in bytes at all rather than only in
/// slots. The reliable path spends four more bytes of it on the in-plaintext
/// stream offset, so a reliable segment is [`MAX_APP_CHUNK`]; an unreliable one
/// keeps the whole plaintext, which is why the bound is stated here and not as
/// the chunk size.
pub const MAX_RECV_PAYLOAD: usize = MAX_RECV_FRAME - PacketHeader::SIZE - AEAD_OVERHEAD;

// A full-size chunk must still fit the unfragmented budget. Tautological as long
// as `MAX_APP_CHUNK` stays derived — which is the point: the day someone replaces
// the derivation with a literal, this is what stops the build.
const _: () = assert!(MAX_APP_CHUNK + PER_PACKET_OVERHEAD <= MAX_INNER_UNFRAGMENTED);

// The receive gate has to admit everything this side sends, or the two ends of a
// legitimate session disagree about what is deliverable. Each post-handshake
// frame shape is checked against it separately, because "they all fit" is exactly
// the kind of claim that stops being true one shape at a time.
const _: () = assert!(MAX_APP_CHUNK + PER_PACKET_OVERHEAD <= MAX_RECV_FRAME);
const _: () = assert!(crate::transport::shaping::MAX_SHAPED_WIRE <= MAX_RECV_FRAME);
const _: () = assert!(
    PacketHeader::SIZE + crate::transport::sack::MAX_SACK_WIRE + AEAD_OVERHEAD <= MAX_RECV_FRAME
);

// Anti-fingerprint size padding rounds a packet *up* to a PADÉ bucket inside the
// AEAD plaintext, so it has its own ceiling on the inner wire image. That ceiling
// plus the outer header must also fit the path MTU, or enabling padding would
// silently reintroduce the fragmentation this module exists to avoid.
const _: () = assert!(crate::transport::shaping::MAX_SHAPED_WIRE + DATAGRAM_HDR_LEN <= PATH_MTU);

#[cfg(test)]
mod tests {
    use super::*;

    /// The arithmetic in the doc comment, asserted rather than trusted.
    #[test]
    fn the_chunk_plus_its_overhead_exactly_fills_the_unfragmented_budget() {
        assert_eq!(
            MAX_APP_CHUNK + PER_PACKET_OVERHEAD,
            MAX_INNER_UNFRAGMENTED,
            "a full-size chunk must fill the datagram, not merely fit it: leaving \
             slack wastes the path on every packet"
        );
        assert_eq!(
            DATAGRAM_HDR_LEN + MAX_INNER_UNFRAGMENTED,
            PATH_MTU,
            "the outer envelope plus the largest unfragmented inner frame is the MTU"
        );
    }

    /// The envelope module and this one must agree; they are the same constants,
    /// and this fails if the re-export is ever replaced by a second definition.
    #[test]
    #[cfg(not(target_arch = "wasm32"))]
    fn the_udp_envelope_uses_this_budget() {
        use crate::transport::phantom_udp::envelope;
        assert_eq!(envelope::PATH_MTU, PATH_MTU);
        assert_eq!(envelope::HDR_LEN, DATAGRAM_HDR_LEN);
        assert_eq!(envelope::MAX_INNER_UNFRAGMENTED, MAX_INNER_UNFRAGMENTED);
    }
}
