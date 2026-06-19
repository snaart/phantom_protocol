//! The synthetic TLS 1.3 handshake "theater" — the one-time prelude exchanged
//! before Phantom data flows over the leg.
//!
//! Wire order a stateful parser sees (content_type / legacy_record_version):
//!
//! ```text
//! client → ClientHello        0x16 0x0301
//! server → ServerHello        0x16 0x0303
//! server → ChangeCipherSpec   0x14 0x0303 00 01 01
//! server → opaque flight      0x17 0x0303   (random ~1.5–4 KB; the TLS-1.3-
//!                                            encrypted EncryptedExtensions/Cert/
//!                                            CertVerify/Finished are 0x17-typed)
//! server → NewSessionTicket   0x17 0x0303   (random ~150–300 B; lifecycle theater)
//! client → ChangeCipherSpec   0x14 0x0303 00 01 01
//! client → Finished           0x17 0x0303   (random ~36–64 B)
//!   ── prelude complete; bidirectional 0x17 ApplicationData (Phantom) follows ──
//! ```
//!
//! The record COUNT and TYPES per direction are fixed so each side consumes an
//! exact prelude; the sizes within are randomized per connection. No real ECDHE,
//! no certificate — the bytes are theater; the inner Phantom session is the real
//! crypto. close_notify on graceful teardown is an opaque `0x17` record (a TLS 1.3
//! Alert is encrypted, hence ApplicationData-typed on the wire).

// PR-2 lands the prelude builders + the record consumer; the live driver (the
// leg's connect/accept) is PR-3. Until then they are exercised only by tests.
#![allow(dead_code)]

use bytes::{Buf, Bytes, BytesMut};

use super::client_hello;
use super::record::{
    encode_record, CT_APPLICATION_DATA, CT_CHANGE_CIPHER_SPEC, CT_HANDSHAKE,
    MAX_RECORD_FRAGMENT_WIRE, TLS_RECORD_HEADER_LEN, VER_TLS10, VER_TLS12,
};
use super::server_hello::{self, ParsedClientHello};
use crate::crypto::rng::RngProvider;
use crate::errors::CoreError;

/// The fixed 6-byte middlebox-compatibility ChangeCipherSpec record.
const CHANGE_CIPHER_SPEC: [u8; 6] = [0x14, 0x03, 0x03, 0x00, 0x01, 0x01];

// Plausible opaque-record size ranges (from the red-team's real-TLS profile).
const OPAQUE_FLIGHT_MIN: usize = 1500;
const OPAQUE_FLIGHT_MAX: usize = 4000;
const TICKET_MIN: usize = 150;
const TICKET_MAX: usize = 300;
const FINISHED_MIN: usize = 36;
const FINISHED_MAX: usize = 64;
const CLOSE_NOTIFY_MIN: usize = 19;
const CLOSE_NOTIFY_MAX: usize = 31;

/// The fixed prelude record types per direction (used to validate the counterpart
/// while consuming). The leading ClientHello is read separately (its bytes are
/// parsed), so the server-flight types start at ServerHello.
pub(crate) const SERVER_FLIGHT_TYPES: [u8; 4] = [
    CT_HANDSHAKE, // ServerHello
    CT_CHANGE_CIPHER_SPEC,
    CT_APPLICATION_DATA, // opaque encrypted flight
    CT_APPLICATION_DATA, // NewSessionTicket-shaped lifecycle record
];
/// The client's post-flight types: ChangeCipherSpec then the opaque Finished.
pub(crate) const CLIENT_FINISHED_TYPES: [u8; 2] = [CT_CHANGE_CIPHER_SPEC, CT_APPLICATION_DATA];

/// Uniform random length in `[min, max]`.
fn rand_len(rng: &dyn RngProvider, min: usize, max: usize) -> usize {
    debug_assert!(max >= min);
    min + (rng.next_u64() % (max - min + 1) as u64) as usize
}

/// One opaque record of `len` fresh-random bytes with the given content type.
fn opaque_record(
    content_type: u8,
    len: usize,
    rng: &dyn RngProvider,
) -> Result<Vec<u8>, CoreError> {
    let mut frag = vec![0u8; len];
    rng.fill_bytes(&mut frag);
    let mut out = Vec::with_capacity(TLS_RECORD_HEADER_LEN + len);
    encode_record(content_type, VER_TLS12, &frag, &mut out)?;
    Ok(out)
}

/// Build the cleartext ClientHello record (`0x16`, legacy_record_version `0x0301`).
pub(crate) fn client_hello_record(sni: &str, rng: &dyn RngProvider) -> Result<Vec<u8>, CoreError> {
    let ch = client_hello::build_client_hello(sni, rng);
    let mut out = Vec::with_capacity(TLS_RECORD_HEADER_LEN + ch.len());
    encode_record(CT_HANDSHAKE, VER_TLS10, &ch, &mut out)?;
    Ok(out)
}

/// Build the full server prelude flight, answering a parsed ClientHello:
/// ServerHello ‖ ChangeCipherSpec ‖ opaque flight ‖ NewSessionTicket-shaped record.
pub(crate) fn server_flight(
    client: &ParsedClientHello,
    rng: &dyn RngProvider,
) -> Result<Vec<u8>, CoreError> {
    let sh = server_hello::build_server_hello(client, rng)?;
    let mut out = Vec::new();
    encode_record(CT_HANDSHAKE, VER_TLS12, &sh, &mut out)?;
    out.extend_from_slice(&CHANGE_CIPHER_SPEC);
    out.extend_from_slice(&opaque_record(
        CT_APPLICATION_DATA,
        rand_len(rng, OPAQUE_FLIGHT_MIN, OPAQUE_FLIGHT_MAX),
        rng,
    )?);
    out.extend_from_slice(&opaque_record(
        CT_APPLICATION_DATA,
        rand_len(rng, TICKET_MIN, TICKET_MAX),
        rng,
    )?);
    Ok(out)
}

/// Build the client's post-flight: ChangeCipherSpec ‖ opaque Finished record.
pub(crate) fn client_finished_flight(rng: &dyn RngProvider) -> Result<Vec<u8>, CoreError> {
    let mut out = Vec::new();
    out.extend_from_slice(&CHANGE_CIPHER_SPEC);
    out.extend_from_slice(&opaque_record(
        CT_APPLICATION_DATA,
        rand_len(rng, FINISHED_MIN, FINISHED_MAX),
        rng,
    )?);
    Ok(out)
}

/// Build an opaque close_notify-shaped record for graceful teardown.
pub(crate) fn close_notify_record(rng: &dyn RngProvider) -> Result<Vec<u8>, CoreError> {
    opaque_record(
        CT_APPLICATION_DATA,
        rand_len(rng, CLOSE_NOTIFY_MIN, CLOSE_NOTIFY_MAX),
        rng,
    )
}

/// Consume exactly one TLS record of `expected_type` from the front of `buf`,
/// returning its fragment bytes. `Ok(None)` when the record has not fully arrived
/// yet (the caller reads more and retries); `Err` on a wrong content type or a
/// malformed/oversized record (the leg drops the connection — its black-hole
/// posture). Bounds-checked: never panics or over-reads.
pub(crate) fn take_record(
    buf: &mut BytesMut,
    expected_type: u8,
) -> Result<Option<Bytes>, CoreError> {
    if buf.len() < TLS_RECORD_HEADER_LEN {
        return Ok(None);
    }
    let content_type = buf[0];
    let frag_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    if frag_len > MAX_RECORD_FRAGMENT_WIRE {
        return Err(CoreError::NetworkError(format!(
            "prelude record too large: {frag_len} > {MAX_RECORD_FRAGMENT_WIRE}"
        )));
    }
    if content_type != expected_type {
        return Err(CoreError::NetworkError(format!(
            "unexpected prelude record type: 0x{content_type:02x}, expected 0x{expected_type:02x}"
        )));
    }
    if buf.len() < TLS_RECORD_HEADER_LEN + frag_len {
        return Ok(None);
    }
    buf.advance(TLS_RECORD_HEADER_LEN);
    Ok(Some(buf.split_to(frag_len).freeze()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::rng::OsRng;

    fn record_type(buf: &[u8]) -> u8 {
        buf[0]
    }
    fn record_total_len(buf: &[u8]) -> usize {
        TLS_RECORD_HEADER_LEN + u16::from_be_bytes([buf[3], buf[4]]) as usize
    }

    /// Full prelude round-trip: client CH → server parses + answers → client
    /// consumes the server flight → server consumes the client finished flight.
    #[test]
    fn full_prelude_round_trip() {
        // Client sends ClientHello.
        let ch_rec = client_hello_record("round.trip.test", &OsRng).expect("ch record");
        assert_eq!(record_type(&ch_rec), CT_HANDSHAKE);
        assert_eq!(&ch_rec[1..3], &[0x03, 0x01], "CH record version is 0x0301");

        // Server reads the ClientHello record and parses it.
        let mut server_in = BytesMut::from(&ch_rec[..]);
        let ch_frag = take_record(&mut server_in, CT_HANDSHAKE)
            .expect("take")
            .expect("complete CH");
        assert!(server_in.is_empty());
        let parsed = server_hello::parse_client_hello(&ch_frag).expect("parse CH");

        // Server builds + sends its flight.
        let flight = server_flight(&parsed, &OsRng).expect("server flight");

        // Client consumes the four server-flight records in order.
        let mut client_in = BytesMut::from(&flight[..]);
        let sh_frag = take_record(&mut client_in, CT_HANDSHAKE)
            .expect("take SH")
            .expect("SH complete");
        for t in &SERVER_FLIGHT_TYPES[1..] {
            take_record(&mut client_in, *t)
                .expect("take flight record")
                .expect("flight record complete");
        }
        assert!(
            client_in.is_empty(),
            "exactly the four flight records consumed"
        );

        // The ServerHello is consistent with the ClientHello (cross-check).
        // (Reuse server_hello's invariant by re-parsing the SH fragment minimally.)
        assert_eq!(record_type(&flight), CT_HANDSHAKE);
        assert_eq!(sh_frag[0], 0x02, "ServerHello handshake type");

        // Client sends its finished flight; server consumes it.
        let fin = client_finished_flight(&OsRng).expect("client finished");
        let mut server_in2 = BytesMut::from(&fin[..]);
        for t in &CLIENT_FINISHED_TYPES {
            take_record(&mut server_in2, *t)
                .expect("take finished record")
                .expect("finished record complete");
        }
        assert!(server_in2.is_empty());
    }

    #[test]
    fn change_cipher_spec_is_the_canonical_six_bytes() {
        let fin = client_finished_flight(&OsRng).expect("finished");
        assert_eq!(&fin[..6], &[0x14, 0x03, 0x03, 0x00, 0x01, 0x01]);
    }

    #[test]
    fn server_flight_record_types_and_versions() {
        let parsed = ParsedClientHello {
            legacy_session_id: vec![0u8; 32],
            cipher_suites: vec![0x1301],
            supported_groups: vec![0x001d],
            key_share_groups: vec![0x001d],
        };
        let flight = server_flight(&parsed, &OsRng).expect("flight");
        // Walk the records and assert types in order + all 0x0303.
        let mut buf = &flight[..];
        let mut seen = Vec::new();
        while buf.len() >= TLS_RECORD_HEADER_LEN {
            seen.push(record_type(buf));
            assert_eq!(&buf[1..3], &[0x03, 0x03], "flight record version 0x0303");
            let total = record_total_len(buf);
            buf = &buf[total..];
        }
        assert_eq!(seen, SERVER_FLIGHT_TYPES);
    }

    #[test]
    fn take_record_waits_for_a_full_record() {
        let rec = close_notify_record(&OsRng).expect("rec");
        let mut buf = BytesMut::new();
        // Dribble all but the last byte: still incomplete.
        buf.extend_from_slice(&rec[..rec.len() - 1]);
        assert!(take_record(&mut buf, CT_APPLICATION_DATA)
            .expect("no error mid-dribble")
            .is_none());
        buf.extend_from_slice(&rec[rec.len() - 1..]);
        assert!(take_record(&mut buf, CT_APPLICATION_DATA)
            .expect("parse")
            .is_some());
    }

    #[test]
    fn take_record_rejects_wrong_type() {
        let ch_rec = client_hello_record("x.test", &OsRng).expect("ch");
        let mut buf = BytesMut::from(&ch_rec[..]);
        // The CH is 0x16; asking for 0x17 must error (the black-hole trigger).
        assert!(take_record(&mut buf, CT_APPLICATION_DATA).is_err());
    }

    #[test]
    fn take_record_rejects_oversized_declared() {
        let mut buf = BytesMut::from(&[CT_HANDSHAKE, 0x03, 0x01, 0xFF, 0xFF, 0x00][..]);
        assert!(take_record(&mut buf, CT_HANDSHAKE).is_err());
    }

    #[test]
    fn opaque_record_sizes_are_in_range() {
        let parsed = ParsedClientHello {
            legacy_session_id: vec![0u8; 32],
            cipher_suites: vec![0x1301],
            supported_groups: vec![0x001d],
            key_share_groups: vec![0x001d],
        };
        for _ in 0..32 {
            let flight = server_flight(&parsed, &OsRng).expect("flight");
            // records: SH, CCS(6), opaque, ticket
            let mut buf = &flight[..];
            // skip SH
            buf = &buf[record_total_len(buf)..];
            // skip CCS
            assert_eq!(record_type(buf), CT_CHANGE_CIPHER_SPEC);
            buf = &buf[record_total_len(buf)..];
            // opaque flight
            let opaque_len = record_total_len(buf) - TLS_RECORD_HEADER_LEN;
            assert!((OPAQUE_FLIGHT_MIN..=OPAQUE_FLIGHT_MAX).contains(&opaque_len));
            buf = &buf[record_total_len(buf)..];
            // ticket
            let ticket_len = record_total_len(buf) - TLS_RECORD_HEADER_LEN;
            assert!((TICKET_MIN..=TICKET_MAX).contains(&ticket_len));
        }
    }

    /// The degenerate `min == max` case returns `min` (modulus is `% 1 == 0`), and
    /// the `+ 1` keeps the divisor ≥ 1 — locking the precondition no live caller
    /// exercises (all call sites pass `MIN < MAX`).
    #[test]
    fn rand_len_handles_min_equals_max() {
        assert_eq!(rand_len(&OsRng, 42, 42), 42);
    }
}
