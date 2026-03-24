//! Wire-format helpers for PATH_VALIDATION packets (Phase 4.2).
//!
//! The path-validation state machine lives in [`crate::transport::path`].
//! This module is the **wire encoder/decoder** that turns those state
//! transitions into V2 packets ready to push through a `SessionTransport`
//! and the inverse decode on the receive side.
//!
//! ## Frame layout
//!
//! A PATH_VALIDATION frame is a V2 `PhantomPacketV2` with:
//!
//! - `header.flags` ⊇ [`PacketFlagsV2::PATH_VALIDATION`]
//! - `header.path_id` = the path the validation is for
//! - `header.stream_id` = 0 (control stream)
//! - `header.sequence` = caller-chosen (typically a small monotonic
//!   counter; not security-critical here because the payload itself is
//!   the unique-per-attempt random challenge)
//! - `payload` = exactly 32 bytes (`PATH_CHALLENGE_LEN`) — either the
//!   challenge (request) or the echoed challenge (response). Sender
//!   role determines the interpretation.
//!
//! ## Authentication
//!
//! The cryptographic protection on PATH_VALIDATION packets comes from
//! the **outer AEAD wrap** when the packet is emitted alongside normal
//! application data — the same AEAD context that secures app-data
//! protects the validation payload from forgery. Encoders here do not
//! perform AEAD themselves; the caller threads them through
//! `Session::encrypt_packet` / `decrypt_packet` exactly as it does for
//! application-data packets, then sets the PATH_VALIDATION flag in the
//! header.
//!
//! ## Why a separate module
//!
//! `transport::path` owns the state machine. `transport::types` owns
//! the wire types. This module is the thin bridge so neither has to
//! know about the other.

use crate::transport::path::PATH_CHALLENGE_LEN;
use crate::transport::types::{
    PacketFlagsV2, PacketHeaderV2, PhantomPacketV2, SequenceNumber, SessionId, StreamId,
    VersionedPacket,
};

/// Whether a frame carries an outgoing challenge or an echoed
/// response. The two are wire-identical; the distinction lives in the
/// **sender** state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathValidationKind {
    Challenge,
    Response,
}

/// Build a V2 PATH_VALIDATION packet carrying the given 32-byte
/// challenge/response payload on the supplied `path_id`.
///
/// The control stream is hard-coded to id 0. The caller supplies a
/// `sequence` value — pick a fresh per-(session, path_id) counter so
/// the replay window can dedupe duplicates if the same challenge is
/// retransmitted.
pub fn build_path_validation_packet(
    session_id: SessionId,
    path_id: u8,
    sequence: SequenceNumber,
    payload: [u8; PATH_CHALLENGE_LEN],
) -> VersionedPacket {
    let stream_id: StreamId = 0;
    let header = PacketHeaderV2::new(
        session_id,
        stream_id,
        sequence,
        PacketFlagsV2::new(PacketFlagsV2::PATH_VALIDATION),
    )
    .with_path_id(path_id);
    PhantomPacketV2::new(header, payload.to_vec()).into_versioned()
}

/// A parsed incoming PATH_VALIDATION frame, with all fields the
/// receiver needs to feed into the state machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedPathValidation {
    pub path_id: u8,
    pub payload: [u8; PATH_CHALLENGE_LEN],
}

/// Attempt to parse a V2 packet as a PATH_VALIDATION frame.
///
/// Returns:
/// - `Ok(Some(...))` when the packet is a well-formed PATH_VALIDATION
///   (correct flag + correct payload length).
/// - `Ok(None)` when the packet is a valid V2 frame but NOT a
///   PATH_VALIDATION frame — the caller routes it normally.
/// - `Err(...)` when the PATH_VALIDATION flag is set but the payload
///   length is wrong.
pub fn parse_path_validation(
    packet: &PhantomPacketV2,
) -> Result<Option<ParsedPathValidation>, PathValidationParseError> {
    if !packet.header.flags.contains(PacketFlagsV2::PATH_VALIDATION) {
        return Ok(None);
    }
    if packet.payload.len() != PATH_CHALLENGE_LEN {
        return Err(PathValidationParseError::WrongPayloadLength {
            got: packet.payload.len(),
        });
    }
    let mut buf = [0u8; PATH_CHALLENGE_LEN];
    buf.copy_from_slice(&packet.payload);
    Ok(Some(ParsedPathValidation {
        path_id: packet.header.path_id,
        payload: buf,
    }))
}

/// Errors from [`parse_path_validation`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathValidationParseError {
    /// Flag set but payload was not exactly `PATH_CHALLENGE_LEN` bytes.
    WrongPayloadLength { got: usize },
}

impl std::fmt::Display for PathValidationParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WrongPayloadLength { got } => write!(
                f,
                "PATH_VALIDATION payload length is {}, expected {}",
                got, PATH_CHALLENGE_LEN
            ),
        }
    }
}

impl std::error::Error for PathValidationParseError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_session_id() -> SessionId {
        SessionId::from_bytes([0x42; 32])
    }

    #[test]
    fn build_round_trip_preserves_path_id_and_payload() {
        let payload = [0xAA; PATH_CHALLENGE_LEN];
        let v = build_path_validation_packet(fixed_session_id(), 7, 42, payload);
        let v2 = v.as_v2().expect("built as V2");
        assert_eq!(v2.header.path_id, 7);
        assert!(v2.header.flags.contains(PacketFlagsV2::PATH_VALIDATION));
        assert_eq!(v2.header.stream_id, 0u16);
        assert_eq!(v2.header.sequence, 42u32);
        assert_eq!(v2.payload, payload.to_vec());
    }

    #[test]
    fn parse_path_validation_returns_payload_on_match() {
        let payload = [0xCC; PATH_CHALLENGE_LEN];
        let v = build_path_validation_packet(fixed_session_id(), 3, 1, payload);
        let v2 = v.into_v2().unwrap();
        let parsed = parse_path_validation(&v2).expect("ok").expect("some");
        assert_eq!(parsed.path_id, 3);
        assert_eq!(parsed.payload, payload);
    }

    #[test]
    fn parse_returns_none_when_flag_missing() {
        let header = PacketHeaderV2::new(
            fixed_session_id(),
            0u16,
            0u32,
            PacketFlagsV2::new(PacketFlagsV2::ENCRYPTED), // not PATH_VALIDATION
        );
        let p = PhantomPacketV2::new(header, vec![0u8; PATH_CHALLENGE_LEN]);
        let parsed = parse_path_validation(&p).expect("no error");
        assert!(parsed.is_none());
    }

    #[test]
    fn parse_errors_on_wrong_payload_length() {
        let header = PacketHeaderV2::new(
            fixed_session_id(),
            0u16,
            0u32,
            PacketFlagsV2::new(PacketFlagsV2::PATH_VALIDATION),
        );
        let p = PhantomPacketV2::new(header, vec![0u8; 16]); // wrong length
        let err = parse_path_validation(&p).expect_err("err");
        assert_eq!(
            err,
            PathValidationParseError::WrongPayloadLength { got: 16 }
        );
    }

    #[test]
    fn challenge_and_response_are_wire_identical() {
        // Two builds with the same inputs must be byte-identical on the
        // wire — the kind enum is a sender-side hint only. We compare
        // by re-serializing and comparing.
        let payload = [0x55; PATH_CHALLENGE_LEN];
        let a = build_path_validation_packet(fixed_session_id(), 1, 5, payload);
        let b = build_path_validation_packet(fixed_session_id(), 1, 5, payload);

        let mut buf_a = Vec::new();
        let mut buf_b = Vec::new();
        let _ = alkahest::serialize_to_vec::<VersionedPacket, _>(&a, &mut buf_a);
        let _ = alkahest::serialize_to_vec::<VersionedPacket, _>(&b, &mut buf_b);
        assert_eq!(buf_a, buf_b);
    }

    #[test]
    fn kind_enum_round_trips_for_documentation() {
        // The kind enum exists purely so the sender can label its
        // intent; it is not part of the wire layout. This test pins
        // that it has the expected two variants.
        assert_ne!(PathValidationKind::Challenge, PathValidationKind::Response);
    }

    /// End-to-end PATH_VALIDATION flow exercised through the wire
    /// codec and the session-level `PathRegistry`. Demonstrates that a
    /// receiver-issued challenge round-trips through this codec and
    /// completes the state machine on the responder side.
    #[test]
    fn full_challenge_response_round_trip_via_codec() {
        use crate::transport::path::{PathRegistry, PathStateKind, RegistrationResult};

        // Side A is the validator (issues the challenge), Side B is
        // the responder (echoes it back). Each side keeps its own
        // PathRegistry; the path id is the shared identifier.
        let side_a = PathRegistry::new();
        let side_b = PathRegistry::new();
        let path_id: u8 = 5;

        // A sees a new path and issues a challenge.
        assert_eq!(side_a.register(path_id), RegistrationResult::Created);
        let challenge = side_a.issue_challenge(path_id).expect("challenge issued");
        let session_id = fixed_session_id();

        // A serializes the PATH_VALIDATION frame and hands it over to
        // the network. We then immediately "receive" it as raw bytes
        // and parse on side B.
        let outgoing = build_path_validation_packet(session_id, path_id, 0, challenge);
        let mut buf = Vec::new();
        let (n, _) = alkahest::serialize_to_vec::<VersionedPacket, _>(&outgoing, &mut buf);
        let parsed_packet: VersionedPacket =
            alkahest::deserialize::<VersionedPacket, VersionedPacket>(&buf[..n])
                .expect("deserialize");
        let v2 = parsed_packet.into_v2().expect("v2");
        let parsed = parse_path_validation(&v2)
            .expect("ok")
            .expect("flag matched");
        assert_eq!(parsed.path_id, path_id);
        assert_eq!(parsed.payload, challenge);

        // Side B echoes the payload back. (It doesn't need a registry
        // entry to do that — it just mirrors whatever it saw.)
        let response = build_path_validation_packet(session_id, path_id, 0, parsed.payload);
        let mut buf2 = Vec::new();
        let (m, _) = alkahest::serialize_to_vec::<VersionedPacket, _>(&response, &mut buf2);
        let echoed: VersionedPacket =
            alkahest::deserialize::<VersionedPacket, VersionedPacket>(&buf2[..m])
                .expect("deserialize");
        let v2_echoed = echoed.into_v2().expect("v2");
        let echoed_parsed = parse_path_validation(&v2_echoed)
            .expect("ok")
            .expect("flag matched");

        // A verifies the response against its in-flight challenge.
        let accepted = side_a.verify_response(echoed_parsed.path_id, &echoed_parsed.payload);
        assert!(accepted, "responder's echo must validate");
        assert_eq!(side_a.state(path_id), Some(PathStateKind::Validated));

        // The unrelated side_b registry has not learned anything —
        // it's a stateless responder in this minimal test.
        let _ = side_b;
    }

    #[test]
    fn tampered_response_fails_validation() {
        use crate::transport::path::{PathRegistry, PathStateKind};

        let validator = PathRegistry::new();
        validator.register(2);
        let challenge = validator.issue_challenge(2).expect("challenge");

        // Build a corrupt response: same path/header, flipped bytes.
        let mut tampered = challenge;
        tampered[7] ^= 0xFF;
        let pkt = build_path_validation_packet(fixed_session_id(), 2, 0, tampered);
        let v2 = pkt.into_v2().unwrap();
        let parsed = parse_path_validation(&v2).unwrap().unwrap();

        assert!(!validator.verify_response(parsed.path_id, &parsed.payload));
        assert_eq!(validator.state(2), Some(PathStateKind::Failed));
    }
}
