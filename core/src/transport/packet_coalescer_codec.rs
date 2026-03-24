//! V2 wire-format bridge for the packet coalescer (Phase 2.5).
//!
//! [`crate::transport::packet_coalescer`] owns the byte layout for a
//! batched bundle (`[count: u16][len1: u16][payload1]...`). The V2 wire
//! format reserves [`PacketFlagsV2::COALESCED`] to mark a packet whose
//! payload **is** such a bundle. This module is the thin layer that:
//!
//! 1. Wraps a coalesced bundle into a `PhantomPacketV2` with
//!    `COALESCED` set on the header.
//! 2. Inversely, parses an incoming V2 packet — if `COALESCED` is set
//!    it hands back the decoded sub-payloads as a `Vec<Vec<u8>>` ready
//!    to feed back into the normal per-stream demux.
//!
//! ## Sequence numbering
//!
//! A coalesced packet still occupies a slot in the sequence space.
//! The outer header's `sequence` is the bundle's own sequence; the
//! inner sub-packets are NOT re-numbered. Replay protection runs
//! exactly once per bundle.
//!
//! ## Why a separate codec module
//!
//! `transport::packet_coalescer` is target-agnostic (could be reused
//! by an unrelated protocol). `transport::types` owns wire types. This
//! module is the per-protocol glue so neither has to know about the
//! other. Same pattern as `transport::path_validation_codec`.
//!
//! ## End-to-end wiring status
//!
//! The codec is callable today. The corresponding `run_data_pump`
//! integration depends on the data pump being V2-routing-aware (so it
//! can produce/consume `PhantomPacketV2` instead of `PhantomPacketV1`).
//! Until that lands, this codec exists as a stable, tested primitive.

use crate::transport::packet_coalescer::{Decoalescer, PacketCoalescer};
use crate::transport::types::{
    PacketFlagsV2, PacketHeaderV2, PhantomPacketV2, SequenceNumber, SessionId, StreamId,
    VersionedPacket,
};

/// Build a single COALESCED V2 packet from a fresh datagram emitted by
/// [`PacketCoalescer::flush`].
///
/// The `flags_extra` parameter lets the caller OR in additional flag
/// bits (e.g. ENCRYPTED, RELIABLE). PATH_VALIDATION and COALESCED MUST
/// NOT both be set on the same packet — the data pump should choose
/// one or the other per send.
pub fn wrap_coalesced_into_v2_packet(
    session_id: SessionId,
    stream_id: StreamId,
    sequence: SequenceNumber,
    flags_extra: u16,
    bundle: Vec<u8>,
) -> VersionedPacket {
    let flag_bits = flags_extra | PacketFlagsV2::COALESCED;
    let header = PacketHeaderV2::new(
        session_id,
        stream_id,
        sequence,
        PacketFlagsV2::new(flag_bits),
    );
    PhantomPacketV2::new(header, bundle).into_versioned()
}

/// Attempt to decode a V2 packet as a COALESCED bundle.
///
/// Returns:
/// - `Ok(Some(vec_of_subpayloads))` when COALESCED is set and the
///   payload parses cleanly.
/// - `Ok(None)` when the packet is a valid V2 frame that is NOT
///   COALESCED — the caller routes it normally.
/// - `Err(...)` when COALESCED is set but the payload is malformed.
pub fn unwrap_coalesced_v2_packet(
    packet: &PhantomPacketV2,
) -> Result<Option<Vec<Vec<u8>>>, CoalescedParseError> {
    if !packet.header.flags.contains(PacketFlagsV2::COALESCED) {
        return Ok(None);
    }
    // Read the bundle's count prefix before consuming the iterator —
    // `Decoalescer` implements `Iterator`, whose `count(self)` would
    // move it.
    if packet.payload.len() < 2 {
        return Err(CoalescedParseError::EmptyOrTruncatedHeader);
    }
    let claimed_count = u16::from_be_bytes([packet.payload[0], packet.payload[1]]) as usize;
    let decoder =
        Decoalescer::new(&packet.payload).ok_or(CoalescedParseError::EmptyOrTruncatedHeader)?;
    let mut out = Vec::with_capacity(claimed_count);
    for sub in decoder {
        out.push(sub.to_vec());
    }
    if out.len() != claimed_count {
        return Err(CoalescedParseError::TruncatedSubPacket {
            expected: claimed_count,
            got: out.len(),
        });
    }
    Ok(Some(out))
}

/// Errors from [`unwrap_coalesced_v2_packet`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoalescedParseError {
    /// Payload was shorter than the 2-byte bundle header.
    EmptyOrTruncatedHeader,
    /// The declared count was larger than the number of well-formed
    /// sub-packets parseable from the bundle payload.
    TruncatedSubPacket { expected: usize, got: usize },
}

impl std::fmt::Display for CoalescedParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyOrTruncatedHeader => {
                write!(f, "COALESCED payload truncated before the bundle header")
            }
            Self::TruncatedSubPacket { expected, got } => write!(
                f,
                "COALESCED bundle declared {} sub-packets, got {} well-formed",
                expected, got
            ),
        }
    }
}

impl std::error::Error for CoalescedParseError {}

/// Convenience helper for the send side: drain a coalescer immediately
/// (no timeout wait) and wrap each emitted datagram into a V2
/// COALESCED packet. The coalescer's internal state is reset.
///
/// Returns the list of ready-to-send V2 packets. Empty if the
/// coalescer had nothing pending.
pub fn drain_coalescer_to_v2_packets(
    coalescer: &mut PacketCoalescer,
    session_id: SessionId,
    stream_id: StreamId,
    next_sequence: &mut SequenceNumber,
    flags_extra: u16,
) -> Vec<VersionedPacket> {
    let mut out = Vec::new();
    while let Some(bundle) = coalescer.flush() {
        let pkt = wrap_coalesced_into_v2_packet(
            session_id,
            stream_id,
            *next_sequence,
            flags_extra,
            bundle,
        );
        *next_sequence = next_sequence.wrapping_add(1);
        out.push(pkt);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::packet_coalescer::CoalescerConfig;

    fn fixed_session_id() -> SessionId {
        SessionId::from_bytes([0xAB; 32])
    }

    #[test]
    fn wrap_sets_coalesced_flag_and_preserves_payload() {
        let bundle = vec![0u8; 64];
        let v = wrap_coalesced_into_v2_packet(fixed_session_id(), 7, 1, 0, bundle.clone());
        let v2 = v.as_v2().expect("v2");
        assert!(v2.header.flags.contains(PacketFlagsV2::COALESCED));
        assert_eq!(v2.payload, bundle);
    }

    #[test]
    fn wrap_or_s_in_extra_flags() {
        let v = wrap_coalesced_into_v2_packet(
            fixed_session_id(),
            7,
            1,
            PacketFlagsV2::ENCRYPTED,
            vec![],
        );
        let v2 = v.as_v2().unwrap();
        assert!(v2.header.flags.contains(PacketFlagsV2::COALESCED));
        assert!(v2.header.flags.contains(PacketFlagsV2::ENCRYPTED));
    }

    #[test]
    fn round_trip_three_subpayloads() {
        let mut c = PacketCoalescer::new(CoalescerConfig::default());
        c.push(b"aaaa");
        c.push(b"bb");
        c.push(b"cccccc");
        let bundle = c.flush().expect("flush");

        let packet = wrap_coalesced_into_v2_packet(fixed_session_id(), 0, 0, 0, bundle);
        let v2 = packet.into_v2().unwrap();
        let parsed = unwrap_coalesced_v2_packet(&v2)
            .expect("ok")
            .expect("coalesced flag matched");

        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed[0], b"aaaa");
        assert_eq!(parsed[1], b"bb");
        assert_eq!(parsed[2], b"cccccc");
    }

    #[test]
    fn unwrap_returns_none_when_not_coalesced() {
        let header = PacketHeaderV2::new(
            fixed_session_id(),
            0,
            0,
            PacketFlagsV2::new(PacketFlagsV2::ENCRYPTED),
        );
        let p = PhantomPacketV2::new(header, vec![0u8; 16]);
        let parsed = unwrap_coalesced_v2_packet(&p).expect("no error");
        assert!(parsed.is_none());
    }

    #[test]
    fn unwrap_errors_on_truncated_header() {
        let header = PacketHeaderV2::new(
            fixed_session_id(),
            0,
            0,
            PacketFlagsV2::new(PacketFlagsV2::COALESCED),
        );
        // Single-byte payload — below the 2-byte bundle-header floor.
        let p = PhantomPacketV2::new(header, vec![0u8]);
        let err = unwrap_coalesced_v2_packet(&p).expect_err("err");
        assert_eq!(err, CoalescedParseError::EmptyOrTruncatedHeader);
    }

    #[test]
    fn unwrap_errors_when_bundle_count_exceeds_actual_subs() {
        // Hand-craft a bundle that claims 5 sub-packets but only
        // encodes 1, then truncates.
        let mut bundle = Vec::new();
        bundle.extend_from_slice(&5u16.to_be_bytes()); // count = 5
        bundle.extend_from_slice(&3u16.to_be_bytes()); // sub-len = 3
        bundle.extend_from_slice(b"abc");
        // No further bytes — declared 4 more subs but the buffer ends.

        let header = PacketHeaderV2::new(
            fixed_session_id(),
            0,
            0,
            PacketFlagsV2::new(PacketFlagsV2::COALESCED),
        );
        let p = PhantomPacketV2::new(header, bundle);
        let err = unwrap_coalesced_v2_packet(&p).expect_err("err");
        match err {
            CoalescedParseError::TruncatedSubPacket { expected, got } => {
                assert_eq!(expected, 5);
                assert_eq!(got, 1);
            }
            other => panic!("unexpected error variant: {:?}", other),
        }
    }

    #[test]
    fn drain_coalescer_helper_emits_one_packet_per_flush() {
        let mut c = PacketCoalescer::new(CoalescerConfig::default());
        c.push(b"x");
        c.push(b"yy");

        let mut next_seq: SequenceNumber = 100;
        let packets = drain_coalescer_to_v2_packets(
            &mut c,
            fixed_session_id(),
            3,
            &mut next_seq,
            PacketFlagsV2::ENCRYPTED,
        );
        // Single flush — single output packet.
        assert_eq!(packets.len(), 1);
        let v2 = packets.into_iter().next().unwrap().into_v2().unwrap();
        assert!(v2.header.flags.contains(PacketFlagsV2::COALESCED));
        assert!(v2.header.flags.contains(PacketFlagsV2::ENCRYPTED));
        assert_eq!(v2.header.stream_id, 3);
        assert_eq!(v2.header.sequence, 100);

        // Sequence advanced for the next round.
        assert_eq!(next_seq, 101);
    }
}
