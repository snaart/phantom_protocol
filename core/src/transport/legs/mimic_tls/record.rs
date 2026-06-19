//! TLS 1.3 record-layer framing for the mimicry leg.
//!
//! The leg carries Phantom traffic inside TLS ApplicationData records. This
//! module is the codec for that outer framing — **no cryptography** (the inner
//! Phantom ciphertext is already AEAD-sealed; the records are framing only).
//!
//! # Two layers, decoupled
//!
//! 1. **Record layer (the wire):** each TLS record is
//!    `content_type(1) ‖ legacy_record_version(2 BE) ‖ length(2 BE) ‖ fragment`.
//!    Post-prelude data records are `0x17 0x0303 <len> | fragment`.
//! 2. **Inner framing (inside the opaque ApplicationData fragment, invisible to an
//!    observer):** each fragment is `chunk_len(2 BE) ‖ stream_chunk[chunk_len] ‖
//!    pad[..]`. The `stream_chunk`s concatenate into a continuous byte-stream of
//!    `msg_len(4 BE) ‖ message` entries (the same 4-byte message framing
//!    `TcpSessionTransport` uses). This decouples Phantom message boundaries from
//!    TLS record boundaries: a message may span several records, a record may pad,
//!    and a `chunk_len == 0` record is a pure padding/decoy record.
//!
//! # Receive-side denial-of-service discipline (mirrors `TcpSessionTransport`)
//!
//! Two attacker-declared lengths exist: the per-record `length` (≤ 2^14 + 256,
//! rejected above that) and the inner `msg_len` (phase-gated cap — 64 KiB during
//! the handshake, 4 MiB once established — checked **before** buffering the body).
//! All parse failures map to a typed [`CoreError`]; the parser never panics, never
//! indexes out of bounds, and never pre-allocates a buffer sized to an
//! attacker-declared length. The reassembly buffer is additionally bounded to
//! `cap + slack` — a peer cannot stream unbounded valid chunks to balloon memory,
//! matching the accumulator-bounded-by-cap guarantee `TcpSessionTransport` gets by
//! reading exactly `len` bytes. A flood of empty (`chunk_len == 0`) records that
//! make no forward progress is bounded and rejected (livelock defense).

use bytes::{Buf, Bytes, BytesMut};

use crate::errors::CoreError;
use crate::transport::session_transport::FramePhase;

// ── TLS content types (RFC 8446 §5.1) ───────────────────────────────────────
/// `ChangeCipherSpec` (`0x14`) — the middlebox-compatibility record.
pub(crate) const CT_CHANGE_CIPHER_SPEC: u8 = 0x14;
/// `Handshake` (`0x16`) — the cleartext ClientHello / ServerHello records.
pub(crate) const CT_HANDSHAKE: u8 = 0x16;
/// `ApplicationData` (`0x17`) — carries the opaque server flight AND all Phantom
/// data (in TLS 1.3 the post-ServerHello handshake is also ApplicationData-typed).
pub(crate) const CT_APPLICATION_DATA: u8 = 0x17;

// ── legacy_record_version values ────────────────────────────────────────────
/// `0x0301` — the legacy_record_version on the initial ClientHello record.
pub(crate) const VER_TLS10: u16 = 0x0301;
/// `0x0303` — the legacy_record_version on every other record (ServerHello, CCS,
/// ApplicationData), and the handshake-body legacy_version everywhere.
pub(crate) const VER_TLS12: u16 = 0x0303;

/// TLS record header length: `content_type(1) + version(2) + length(2)`.
pub(crate) const TLS_RECORD_HEADER_LEN: usize = 5;

/// RFC 8446 §5.1: `TLSPlaintext.length` MUST NOT exceed 2^14. Every fragment the
/// framer emits stays at/under this — the bound that guarantees the 2-byte length
/// field can never overflow (the removed FakeTLS leg overflowed exactly here).
pub(crate) const MAX_RECORD_FRAGMENT: usize = 16384;

/// RFC 8446 §5.2: `TLSCiphertext.length` MUST NOT exceed 2^14 + 256 (the AEAD
/// expansion band). The de-framer rejects any declared fragment length above this.
pub(crate) const MAX_RECORD_FRAGMENT_WIRE: usize = MAX_RECORD_FRAGMENT + 256;

/// Inner per-record framing header: the 2-byte big-endian `chunk_len`.
const INNER_CHUNK_HEADER_LEN: usize = 2;

/// Phase-gated inner-message cap during the unauthenticated handshake (WIRE-001),
/// matching `TcpSessionTransport`.
const HANDSHAKE_FRAME_CAP: usize = 64 * 1024;

/// Phase-gated inner-message cap once established, matching `TcpSessionTransport`.
const STEADY_STATE_FRAME_CAP: usize = 4 * 1024 * 1024;

/// Slack above the phase cap that the reassembly buffer (`stream`) may hold: one
/// in-flight message (≤ cap) plus one socket read's worth of records not yet
/// popped. Bounds the de-framer's memory to O(cap) no matter how the caller
/// batches `push`es; comfortably above the leg's 64 KiB read granularity so a
/// well-behaved peer is never falsely rejected.
const STREAM_SLACK: usize = 256 * 1024;

/// Max consecutive empty (zero forward-progress) records before the de-framer
/// rejects the peer — a livelock / busy-spin defense. Legitimate cover/padding
/// records are occasional, never 64-plus in a row.
const MAX_CONSECUTIVE_EMPTY: u32 = 64;

/// Largest inner stream chunk a single framer record carries (`MAX_RECORD_FRAGMENT`
/// minus the 2-byte inner `chunk_len` header).
const MAX_STREAM_CHUNK: usize = MAX_RECORD_FRAGMENT - INNER_CHUNK_HEADER_LEN;

/// Write one TLS record `content_type ‖ version ‖ length ‖ fragment` into `out`.
///
/// Rejects a fragment larger than [`MAX_RECORD_FRAGMENT_WIRE`] with a typed error
/// **before** casting the length to `u16` — this is the bounds-check the removed
/// FakeTLS leg lacked (it truncated a `> u16::MAX` payload into a corrupt record).
pub(crate) fn encode_record(
    content_type: u8,
    version: u16,
    fragment: &[u8],
    out: &mut Vec<u8>,
) -> Result<(), CoreError> {
    if fragment.len() > MAX_RECORD_FRAGMENT_WIRE {
        return Err(CoreError::NetworkError(format!(
            "TLS record fragment too large: {} > {}",
            fragment.len(),
            MAX_RECORD_FRAGMENT_WIRE
        )));
    }
    out.push(content_type);
    out.extend_from_slice(&version.to_be_bytes());
    // Safe cast: bounded ≤ MAX_RECORD_FRAGMENT_WIRE (< u16::MAX) by the check above.
    out.extend_from_slice(&(fragment.len() as u16).to_be_bytes());
    out.extend_from_slice(fragment);
    Ok(())
}

/// Frame one Phantom message into a sequence of TLS ApplicationData records.
///
/// Builds the inner stream `msg_len(4 BE) ‖ message`, splits it into chunks of at
/// most [`MAX_STREAM_CHUNK`], and wraps each chunk as `chunk_len(2 BE) ‖ chunk`
/// inside an ApplicationData (`0x17`) record. PR-1 emits no padding (the format
/// supports it — the de-framer ignores trailing fragment bytes — and the
/// size-shaping policy lands with the leg). Stateless: cross-message coalescing is
/// a later shaper refinement and needs no de-framer change.
pub(crate) fn frame_message(message: &[u8]) -> Result<Vec<u8>, CoreError> {
    let msg_len = u32::try_from(message.len()).map_err(|_| {
        CoreError::NetworkError(format!("message too large to frame: {}", message.len()))
    })?;

    let mut stream = Vec::with_capacity(4 + message.len());
    stream.extend_from_slice(&msg_len.to_be_bytes());
    stream.extend_from_slice(message);

    let mut out = Vec::new();
    // An empty stream is impossible (always ≥ the 4-byte length prefix), so this
    // always emits ≥ 1 record.
    for chunk in stream.chunks(MAX_STREAM_CHUNK) {
        let mut fragment = Vec::with_capacity(INNER_CHUNK_HEADER_LEN + chunk.len());
        // chunk.len() ≤ MAX_STREAM_CHUNK < u16::MAX — safe cast.
        fragment.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
        fragment.extend_from_slice(chunk);
        encode_record(CT_APPLICATION_DATA, VER_TLS12, &fragment, &mut out)?;
    }
    Ok(out)
}

/// Stateful receive-side de-framer: raw TLS-record bytes in, whole Phantom
/// messages out. Holds a record-parse accumulator (`wire`) and a
/// message-reassembly accumulator (`stream`); both grow only from bytes actually
/// delivered, never from an attacker-declared length.
pub(crate) struct RecordDeframer {
    /// Raw wire bytes pushed but not yet parsed into a complete record.
    wire: BytesMut,
    /// Reassembled inner byte-stream (`msg_len ‖ message ‖ …`) awaiting de-framing.
    stream: BytesMut,
    /// Phase-gated inner-message cap (WIRE-001).
    cap: usize,
    /// Consecutive zero-forward-progress records (livelock defense).
    consecutive_empty: u32,
}

impl Default for RecordDeframer {
    fn default() -> Self {
        Self::new()
    }
}

impl RecordDeframer {
    pub(crate) fn new() -> Self {
        Self {
            wire: BytesMut::new(),
            stream: BytesMut::new(),
            cap: HANDSHAKE_FRAME_CAP,
            consecutive_empty: 0,
        }
    }

    /// Raise/lower the inner-message cap on the handshake → established transition.
    pub(crate) fn set_phase(&mut self, phase: FramePhase) {
        self.cap = match phase {
            FramePhase::Handshake => HANDSHAKE_FRAME_CAP,
            FramePhase::Established => STEADY_STATE_FRAME_CAP,
        };
    }

    /// Feed raw bytes read from the socket. Cheap append; parsing happens in
    /// [`next_message`](Self::next_message).
    pub(crate) fn push(&mut self, data: &[u8]) {
        self.wire.extend_from_slice(data);
    }

    /// Drain every complete TLS record from `wire` into the inner `stream`,
    /// validating record-layer invariants. Stops at the first incomplete record
    /// (leaving its partial bytes in `wire` for the next `push`).
    fn drain_records(&mut self) -> Result<(), CoreError> {
        loop {
            if self.wire.len() < TLS_RECORD_HEADER_LEN {
                return Ok(()); // need a full header before we can size the record
            }
            let content_type = self.wire[0];
            // self.wire[1..3] is legacy_record_version — not load-bearing for
            // de-framing; a stateful observer checks it, we just don't gate on it.
            let frag_len = u16::from_be_bytes([self.wire[3], self.wire[4]]) as usize;

            // Reject an oversized DECLARED fragment up front (before buffering the
            // body), exactly like TcpSessionTransport's prefix check.
            if frag_len > MAX_RECORD_FRAGMENT_WIRE {
                return Err(CoreError::NetworkError(format!(
                    "oversized TLS record from peer: {} > {}",
                    frag_len, MAX_RECORD_FRAGMENT_WIRE
                )));
            }
            // Post-prelude, only ApplicationData is expected. (The prelude's
            // Handshake/CCS records are consumed by the handshake-theater layer
            // before this de-framer is used for data.)
            if content_type != CT_APPLICATION_DATA {
                return Err(CoreError::NetworkError(format!(
                    "unexpected TLS content_type in data phase: 0x{content_type:02x}"
                )));
            }
            if self.wire.len() < TLS_RECORD_HEADER_LEN + frag_len {
                return Ok(()); // record body not fully arrived yet
            }

            // Consume the header, then split off the fragment.
            self.wire.advance(TLS_RECORD_HEADER_LEN);
            let fragment = self.wire.split_to(frag_len);

            if frag_len == 0 {
                self.note_empty()?;
                continue;
            }
            if frag_len < INNER_CHUNK_HEADER_LEN {
                // A 1-byte fragment cannot hold the 2-byte inner chunk_len. We
                // never emit this; a peer that does is malformed.
                return Err(CoreError::NetworkError(
                    "TLS record fragment too small for inner framing".into(),
                ));
            }
            let chunk_len = u16::from_be_bytes([fragment[0], fragment[1]]) as usize;
            if chunk_len > frag_len - INNER_CHUNK_HEADER_LEN {
                return Err(CoreError::NetworkError(format!(
                    "inner chunk_len {} exceeds fragment body {}",
                    chunk_len,
                    frag_len - INNER_CHUNK_HEADER_LEN
                )));
            }
            if chunk_len == 0 {
                self.note_empty()?;
                continue;
            }
            self.consecutive_empty = 0;
            self.stream.extend_from_slice(
                &fragment[INNER_CHUNK_HEADER_LEN..INNER_CHUNK_HEADER_LEN + chunk_len],
            );
            // fragment[INNER_CHUNK_HEADER_LEN + chunk_len ..] is padding — ignored.

            // Bound the reassembly buffer to O(cap) regardless of how the caller
            // batches `push`es. `next_message` caps the *declared* `msg_len`, but
            // without this an attacker could stream unbounded valid chunks (e.g.
            // declare a cap-sized message, then feed far more than cap bytes of
            // records) and balloon `stream` before any message completes. This is
            // the accumulator-bounded-by-cap guarantee `TcpSessionTransport` gets
            // for free by reading exactly `len` bytes; here we enforce it
            // explicitly. The slack admits one in-flight message (≤ cap) plus one
            // socket read's worth of not-yet-popped records.
            if self.stream.len() > self.cap.saturating_add(STREAM_SLACK) {
                return Err(CoreError::NetworkError(format!(
                    "inner reassembly buffer exceeded cap: {} > {} + {}",
                    self.stream.len(),
                    self.cap,
                    STREAM_SLACK
                )));
            }
        }
    }

    /// Count a zero-forward-progress record; reject the peer past the bound.
    fn note_empty(&mut self) -> Result<(), CoreError> {
        self.consecutive_empty += 1;
        if self.consecutive_empty > MAX_CONSECUTIVE_EMPTY {
            return Err(CoreError::NetworkError(
                "too many consecutive empty TLS records (livelock defense)".into(),
            ));
        }
        Ok(())
    }

    /// Parse any newly-complete records, then pop one whole Phantom message if the
    /// inner stream holds a full `msg_len ‖ message`. Returns `Ok(None)` when more
    /// bytes are needed (the caller reads the socket and `push`es again).
    pub(crate) fn next_message(&mut self) -> Result<Option<Bytes>, CoreError> {
        self.drain_records()?;

        if self.stream.len() < 4 {
            return Ok(None);
        }
        let msg_len = u32::from_be_bytes([
            self.stream[0],
            self.stream[1],
            self.stream[2],
            self.stream[3],
        ]) as usize;
        // WIRE-001: reject an oversized declared message length up front, before
        // waiting for (and buffering) the body.
        if msg_len > self.cap {
            return Err(CoreError::NetworkError(format!(
                "oversized inner message from peer: {} > {}",
                msg_len, self.cap
            )));
        }
        if self.stream.len() < 4 + msg_len {
            return Ok(None);
        }
        self.stream.advance(4);
        Ok(Some(self.stream.split_to(msg_len).freeze()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `Handshake` content type — only the data-phase rejection test needs it
    /// here; the real handshake-theater layer (PR-2) defines its own vocabulary.
    const CT_HANDSHAKE: u8 = 0x16;

    /// Build a single ApplicationData record with an explicit `chunk_len` and an
    /// arbitrary amount of trailing padding — used to prove the de-framer strips
    /// pad and the format genuinely decouples chunk size from record size.
    fn padded_record(chunk: &[u8], pad: usize) -> Vec<u8> {
        let mut fragment = Vec::new();
        fragment.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
        fragment.extend_from_slice(chunk);
        fragment.extend(std::iter::repeat(0u8).take(pad));
        let mut out = Vec::new();
        encode_record(CT_APPLICATION_DATA, VER_TLS12, &fragment, &mut out).expect("encode");
        out
    }

    #[test]
    fn round_trip_single_message() {
        let msg = b"hello phantom over tls";
        let wire = frame_message(msg).expect("frame");
        let mut d = RecordDeframer::new();
        d.push(&wire);
        let got = d.next_message().expect("parse").expect("one message");
        assert_eq!(&got[..], msg);
        assert!(
            d.next_message().expect("parse").is_none(),
            "no second message"
        );
    }

    #[test]
    fn round_trip_multiple_messages_concatenated() {
        let mut wire = Vec::new();
        wire.extend_from_slice(&frame_message(b"first").expect("f1"));
        wire.extend_from_slice(&frame_message(b"second").expect("f2"));
        wire.extend_from_slice(&frame_message(b"third").expect("f3"));
        let mut d = RecordDeframer::new();
        d.push(&wire);
        assert_eq!(&d.next_message().expect("p").expect("m1")[..], b"first");
        assert_eq!(&d.next_message().expect("p").expect("m2")[..], b"second");
        assert_eq!(&d.next_message().expect("p").expect("m3")[..], b"third");
        assert!(d.next_message().expect("p").is_none());
    }

    #[test]
    fn round_trip_empty_message() {
        let wire = frame_message(b"").expect("frame empty");
        let mut d = RecordDeframer::new();
        d.push(&wire);
        let got = d.next_message().expect("parse").expect("empty message");
        assert_eq!(got.len(), 0);
    }

    /// A message larger than one TLS record (2^14) MUST split across records and
    /// reassemble byte-exact — the path a 0-RTT ClientHello + 16 KiB early-data
    /// (~19.6 KB) exercises on the very first message.
    #[test]
    fn round_trip_large_message_spans_multiple_records() {
        let msg: Vec<u8> = (0..40_000u32).map(|i| (i % 251) as u8).collect();
        let wire = frame_message(&msg).expect("frame");
        // It must be more than one record (40 KB / ~16 KB chunks → ≥ 3 records).
        let record_count = count_records(&wire);
        assert!(record_count >= 3, "expected ≥3 records, got {record_count}");
        let mut d = RecordDeframer::new();
        d.set_phase(FramePhase::Established); // 40 KB > the 64 KiB handshake cap is fine; be explicit
        d.push(&wire);
        let got = d.next_message().expect("parse").expect("message");
        assert_eq!(got.len(), msg.len());
        assert_eq!(&got[..], &msg[..]);
    }

    /// Reassembly must work even when the wire arrives one byte per `push` — a
    /// peer (or middlebox) dribbling bytes must not desync the parser.
    #[test]
    fn dribble_one_byte_at_a_time_reassembles() {
        let msg = b"dribbled across many tiny reads";
        let wire = frame_message(msg).expect("frame");
        let mut d = RecordDeframer::new();
        for b in &wire {
            // Before the final byte arrives the message is incomplete: the parser
            // must neither error nor surface a premature message.
            assert!(
                d.next_message()
                    .expect("parse must not error mid-dribble")
                    .is_none(),
                "no message should complete before the last byte is pushed"
            );
            d.push(std::slice::from_ref(b));
        }
        let got = d
            .next_message()
            .expect("parse")
            .expect("message after full dribble");
        assert_eq!(&got[..], msg);
    }

    /// A record declaring a fragment length above the TLS ciphertext bound
    /// (2^14 + 256) is rejected with a typed error — never an over-allocation.
    #[test]
    fn oversized_declared_record_rejected() {
        // content_type 0x17, version 0x0303, length 0xFFFF, then a little body.
        let wire = [0x17u8, 0x03, 0x03, 0xFF, 0xFF, 0x00, 0x00, 0x00];
        let mut d = RecordDeframer::new();
        d.push(&wire);
        let err = d
            .next_message()
            .expect_err("must reject oversized declared record");
        assert!(matches!(err, CoreError::NetworkError(_)));
    }

    /// During the handshake phase the inner-message cap is 64 KiB: a declared
    /// message length above it is rejected as soon as the 4-byte length is read.
    #[test]
    fn oversized_inner_message_rejected_in_handshake_phase() {
        let big = vec![0u8; 100 * 1024]; // 100 KiB > 64 KiB handshake cap
        let wire = frame_message(&big).expect("frame");
        let mut d = RecordDeframer::new(); // defaults to handshake phase
        d.push(&wire);
        let err = d
            .next_message()
            .expect_err("must reject an oversized inner message in handshake phase");
        assert!(matches!(err, CoreError::NetworkError(_)));
    }

    /// The same oversized message is accepted once the phase is raised to
    /// established (cap 4 MiB) — proves the cap is the gate, not a hard limit.
    #[test]
    fn established_phase_accepts_larger_message() {
        let big = vec![0x5au8; 100 * 1024]; // 100 KiB: > 64 KiB, < 4 MiB
        let wire = frame_message(&big).expect("frame");
        let mut d = RecordDeframer::new();
        d.set_phase(FramePhase::Established);
        d.push(&wire);
        let got = d.next_message().expect("parse").expect("message");
        assert_eq!(got.len(), big.len());
    }

    /// A flood of empty (`chunk_len == 0`) records that make no forward progress is
    /// bounded and rejected (livelock defense).
    #[test]
    fn empty_record_flood_is_bounded() {
        let mut d = RecordDeframer::new();
        // An empty fragment (frag_len == 0) is a zero-progress record.
        let empty_record = [CT_APPLICATION_DATA, 0x03, 0x03, 0x00, 0x00];
        for _ in 0..(MAX_CONSECUTIVE_EMPTY + 2) {
            d.push(&empty_record);
        }
        let err = d
            .next_message()
            .expect_err("must reject an empty-record flood");
        assert!(matches!(err, CoreError::NetworkError(_)));
    }

    /// `encode_record` refuses a fragment larger than the wire bound rather than
    /// truncating it into a corrupt record (the removed-FakeTLS u16-overflow bug).
    #[test]
    fn encode_rejects_oversized_fragment() {
        let huge = vec![0u8; 70_000]; // > u16::MAX and > MAX_RECORD_FRAGMENT_WIRE
        let mut out = Vec::new();
        let err = encode_record(CT_APPLICATION_DATA, VER_TLS12, &huge, &mut out)
            .expect_err("must reject an oversized fragment");
        assert!(matches!(err, CoreError::NetworkError(_)));
        assert!(out.is_empty(), "nothing written on the error path");
    }

    /// A non-ApplicationData content type in the data phase is rejected (the
    /// prelude consumes Handshake/CCS records before the data de-framer runs).
    #[test]
    fn non_application_data_content_type_rejected() {
        let mut wire = Vec::new();
        // A well-formed Handshake (0x16) record in the data phase is unexpected.
        encode_record(CT_HANDSHAKE, VER_TLS12, b"\x00\x05hello", &mut wire).expect("encode");
        let mut d = RecordDeframer::new();
        d.push(&wire);
        let err = d
            .next_message()
            .expect_err("must reject 0x16 in the data phase");
        assert!(matches!(err, CoreError::NetworkError(_)));
    }

    /// A record carrying `chunk_len` plaintext bytes followed by arbitrary padding
    /// recovers exactly the chunk; the pad is stripped. Proves the format
    /// decouples record (wire) size from carried bytes — the basis for the shaper.
    #[test]
    fn padded_record_strips_padding() {
        // The inner stream for message "PAD" is len32(=3) ‖ "PAD" = 7 bytes. Put
        // all 7 in one chunk, then 500 pad bytes.
        let mut stream = Vec::new();
        stream.extend_from_slice(&3u32.to_be_bytes());
        stream.extend_from_slice(b"PAD");
        let wire = padded_record(&stream, 500);
        // The record's wire fragment is 2 + 7 + 500 = 509 bytes, far larger than
        // the 7 carried bytes.
        assert!(wire.len() > 500);
        let mut d = RecordDeframer::new();
        d.push(&wire);
        let got = d.next_message().expect("parse").expect("message");
        assert_eq!(&got[..], b"PAD");
    }

    /// A record whose inner `chunk_len` claims more than the fragment body is
    /// rejected (no over-read).
    #[test]
    fn inner_chunk_len_overrun_rejected() {
        // fragment = chunk_len(0x0010 = 16) but only 3 body bytes present.
        let mut wire = Vec::new();
        let fragment = [0x00u8, 0x10, b'a', b'b', b'c'];
        encode_record(CT_APPLICATION_DATA, VER_TLS12, &fragment, &mut wire).expect("encode");
        let mut d = RecordDeframer::new();
        d.push(&wire);
        let err = d
            .next_message()
            .expect_err("must reject inner chunk_len overrun");
        assert!(matches!(err, CoreError::NetworkError(_)));
    }

    /// The reassembly buffer is bounded by the phase cap + slack: a peer that
    /// streams more valid chunk bytes than that (without a message completing) is
    /// rejected with a typed error rather than ballooning memory. Mirrors
    /// `TcpSessionTransport`'s accumulator-bounded-by-cap guarantee.
    #[test]
    fn reassembly_buffer_is_bounded_by_cap() {
        // Handshake phase: cap 64 KiB + 256 KiB slack ≈ a 320 KiB stream ceiling.
        let mut d = RecordDeframer::new();
        let chunk = vec![0u8; 16_000];
        let mut wire = Vec::new();
        // 25 records × 16 000 = 400 KB of stream bytes, well over the ceiling.
        for _ in 0..25 {
            let mut frag = Vec::new();
            frag.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
            frag.extend_from_slice(&chunk);
            encode_record(CT_APPLICATION_DATA, VER_TLS12, &frag, &mut wire).expect("encode");
        }
        d.push(&wire);
        let err = d
            .next_message()
            .expect_err("the reassembly buffer must be bounded by cap, not grow to the fed size");
        assert!(matches!(err, CoreError::NetworkError(_)));
    }

    /// The 4-byte inner `msg_len` prefix may straddle a record/chunk boundary;
    /// reassembly is record-boundary-independent and must still recover the message.
    #[test]
    fn msg_len_prefix_split_across_records() {
        // Message "hi" → inner stream = [00 00 00 02 'h' 'i'] (6 bytes). Split so
        // record A carries the first 3 bytes (part of the length prefix) and
        // record B the remaining 3 (rest of the prefix + body).
        let mut stream = Vec::new();
        stream.extend_from_slice(&2u32.to_be_bytes());
        stream.extend_from_slice(b"hi");
        let mut wire = Vec::new();
        for part in [&stream[0..3], &stream[3..6]] {
            let mut frag = Vec::new();
            frag.extend_from_slice(&(part.len() as u16).to_be_bytes());
            frag.extend_from_slice(part);
            encode_record(CT_APPLICATION_DATA, VER_TLS12, &frag, &mut wire).expect("encode");
        }
        let mut d = RecordDeframer::new();
        d.push(&wire);
        let got = d
            .next_message()
            .expect("parse")
            .expect("message across split prefix");
        assert_eq!(&got[..], b"hi");
    }

    // Count how many TLS records a buffer holds (header-walk; test helper).
    fn count_records(mut buf: &[u8]) -> usize {
        let mut n = 0;
        while buf.len() >= TLS_RECORD_HEADER_LEN {
            let frag_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
            let total = TLS_RECORD_HEADER_LEN + frag_len;
            if buf.len() < total {
                break;
            }
            n += 1;
            buf = &buf[total..];
        }
        n
    }
}
