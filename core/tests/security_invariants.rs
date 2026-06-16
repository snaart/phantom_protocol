//! Formal negative-security tests for the documented invariants.
//!
//! Each test pins a specific property from `SECURITY.md` / `docs/security/threat-model.md` so that
//! a future regression which silently weakens one of them surfaces as a hard
//! red here. These run on every `cargo test --test security_invariants` path —
//! they are NOT `#[ignore]`-gated. Most are pure (no sockets); the PhantomUDP
//! pre-auth DoS-bound tests bind a loopback `UdpSocket` (fast + deterministic).
//!
//! Coverage map (Phase 6.8 of `docs/PRODUCTION_READINESS.md`):
//!   - AEAD authenticated decryption rejects bit-flipped ciphertext.
//!   - AEAD AAD-binding: a tampered `PacketHeader` (used as AAD) is rejected
//!     even if the ciphertext bytes are intact.
//!   - Malformed wire bytes are rejected as a typed parse error, not a panic.
//!   - The handshake cookie path uses constant-time equality (smoke check).
//!   - Server identity mismatch fails the handshake at the client side.
//!   - The AEAD `AEAD_MAX_INVOCATIONS` ceiling is reachable through a
//!     synthetic counter-bump and yields `NonceExhausted`.
//!   - Cookie tampering yields a `Retry` (not `Success`) on the server side.

use bytes::Bytes;
use phantom_protocol::crypto::adaptive_crypto::{CipherSuite, CryptoSession};
use phantom_protocol::crypto::hybrid_sign::{HybridSigningKey, HybridVerifyingKey};
use phantom_protocol::transport::handshake::{
    ClientHello, HandshakeClient, HandshakeError, HandshakeResponse, HandshakeServer, ServerHello,
};
use phantom_protocol::transport::path::PathStateKind;
use phantom_protocol::transport::session::{
    CryptoState, Session, MAX_REKEY_CATCHUP, REBIND_VALIDATION_PATH_ID,
};
use phantom_protocol::transport::stream::{Stream, INITIAL_STREAM_WINDOW};
use phantom_protocol::transport::types::{
    PacketFlags, PacketHeader, PhantomPacket, SchedulerMode, SessionId, WIRE_VERSION,
};
use std::time::Duration;

// ── Helpers ────────────────────────────────────────────────────────────────

fn make_session_pair(shared: [u8; 32]) -> (Session, Session) {
    let id = SessionId::from_bytes([1u8; 32]);
    let crypto_a = CryptoState::new(&shared, false).expect("client crypto");
    let crypto_b = CryptoState::new(&shared, true).expect("server crypto");
    (
        Session::from_derived(id, crypto_a, SchedulerMode::LowLatency, shared, false),
        Session::from_derived(id, crypto_b, SchedulerMode::LowLatency, shared, true),
    )
}

// ── Tests ──────────────────────────────────────────────────────────────────

/// AAD binding: even with intact ciphertext, mutating the header (which is
/// fed into the AEAD as AAD) must cause decryption to fail. This is the
/// invariant that prevents an attacker from rewriting `stream_id`, `flags`,
/// or `sequence` on the wire while keeping the encrypted payload intact.
/// (Companion to `tampered_epoch_or_path_id_is_rejected`, which covers the
/// `epoch` / `path_id` header fields.)
#[test]
fn tampered_header_is_rejected_via_aad() {
    let (client, server) = make_session_pair([0xB2u8; 32]);
    let real_header = PacketHeader::new(
        *server.id(),
        7,
        1,
        PacketFlags::new(PacketFlags::ENCRYPTED | PacketFlags::RELIABLE),
    );

    let ct = client
        .encrypt_packet(&real_header, b"AAD-bound payload", &[])
        .expect("encrypt");

    // Server tries to decrypt with a different header (stream_id changed).
    let tampered_header = PacketHeader {
        stream_id: 8, // changed: 7 -> 8
        ..real_header
    };

    let result = server.decrypt_packet(&tampered_header, &ct, &[]);
    assert!(
        result.is_err(),
        "AEAD must reject a packet whose header (AAD) was mutated"
    );
}

/// T4.1 — `PhantomPacket.extensions` is bound into the AEAD AAD. The trailing
/// TLV headroom used to sit *outside* the AAD (the AAD was only the 47-byte
/// header image), so an on-path attacker could rewrite `extensions` without
/// invalidating the tag. Binding it closes that malleability: decrypting under
/// a different `extensions` than the sender sealed must fail, and the untampered
/// value must still decrypt. (Companion to `tampered_header_is_rejected_via_aad`,
/// which covers the header fields.)
#[test]
fn tampered_extensions_is_rejected_via_aad() {
    let (client, server) = make_session_pair([0x4Au8; 32]);
    let header = PacketHeader::new(*server.id(), 3, 1, PacketFlags::new(PacketFlags::ENCRYPTED));
    let ext = vec![0xFFu8, 0x01, 0x00, 0x04, b't', b'e', b's', b't'];

    let ct = client
        .encrypt_packet(&header, b"ext-bound payload", &ext)
        .expect("encrypt");

    // Same header + ciphertext, but a single flipped extensions byte → the
    // AEAD open must reject it (extensions are part of the AAD).
    let mut tampered = ext.clone();
    tampered[0] ^= 0x80;
    assert!(
        server.decrypt_packet(&header, &ct, &tampered).is_err(),
        "AEAD must reject a packet whose extensions (AAD) were mutated"
    );

    // The intact extensions still decrypt to the original payload.
    let pt = server
        .decrypt_packet(&header, &ct, &ext)
        .expect("decrypt with intact extensions");
    assert_eq!(pt, b"ext-bound payload");
}

/// T4.6 — header protection (QUIC RFC 9001 §5.4) masks the 14 variable header
/// bytes (`packet_number ‖ flags ‖ stream_id ‖ epoch ‖ path_id`, wire `[1..15]`
/// in ε / WIRE v5) so a passive on-path observer reads neither the packet number
/// nor the `PRIORITY` ("voice") flag; only the `version` byte stays cleartext
/// (session_id is off-wire; routing is by the outer ConnId). The peer recovers
/// the exact packet via `parse_protected`.
#[test]
fn hp_masks_header_fields_on_the_wire() {
    let (client, server) = make_session_pair([0x71u8; 32]);
    let header = PacketHeader::new(
        *server.id(),
        9,
        0xA1B2C3D4E5F60718,
        PacketFlags::new(PacketFlags::ENCRYPTED | PacketFlags::PRIORITY),
    )
    .with_epoch(2)
    .with_path_id(3);
    let ct = client
        .encrypt_packet(&header, b"voice frame", &[])
        .expect("encrypt");
    let packet = PhantomPacket::new(header, ct);
    let wire = client.protect_packet(&packet).expect("protect");
    let cleartext = packet.to_wire();

    // The 14-byte protected region [1..15] is masked → not the cleartext bytes.
    assert_ne!(
        &wire[1..15],
        &cleartext[1..15],
        "pn/flags/stream_id/epoch/path_id must be masked on the wire"
    );
    // Only the `version` byte stays cleartext (session_id is off-wire).
    assert_eq!(&wire[..1], &cleartext[..1]);
    // The flags bytes (incl. the PRIORITY/voice bit) sit in the masked span, so
    // an observer cannot read the priority class off the wire.
    assert_ne!(
        &wire[9..11],
        &cleartext[9..11],
        "the PRIORITY/voice flag must not be readable on the wire without the hp key"
    );
    // The peer recovers the exact packet (header + payload) by unmasking; the
    // off-wire session_id is reconstructed to this session's id (= the original,
    // since both sides share the negotiated id here).
    let parsed = server.parse_protected(&wire).expect("parse");
    assert_eq!(parsed.header, header);
    assert_eq!(parsed.payload, packet.payload);
}

/// T4.6 — header protection adds NO new decryption oracle: a wire mutation of the
/// masked `[1..15]` region (ε / WIRE v5) unmasks to a WRONG header, so the
/// subsequent AEAD open (the reconstructed header image is the AAD) fails —
/// caught exactly like any other AAD / ciphertext tamper, with no separate signal.
#[test]
fn hp_masked_region_tamper_fails_aead() {
    let (client, server) = make_session_pair([0x72u8; 32]);
    let header = PacketHeader::new(*server.id(), 1, 5, PacketFlags::new(PacketFlags::ENCRYPTED));
    let ct = client
        .encrypt_packet(&header, b"payload", &[])
        .expect("encrypt");
    let packet = PhantomPacket::new(header, ct);
    let mut wire = client.protect_packet(&packet).expect("protect");

    // Flip a byte inside the masked header region [1..15] (here in the masked
    // packet_number span).
    wire[5] ^= 0x40;
    // Unmasking still "succeeds" structurally but recovers a different header...
    let tampered = server.parse_protected(&wire).expect("parse");
    assert_ne!(
        tampered.header, header,
        "a flipped masked byte must change the recovered header"
    );
    // ...and the AEAD open under that wrong header (its wire image is the AAD)
    // fails — the masked-region tamper is caught by the AEAD, not a new oracle.
    assert!(
        server
            .decrypt_packet(&tampered.header, &tampered.payload, &tampered.extensions)
            .is_err(),
        "a tampered masked-header byte must fail the AEAD via the AAD"
    );
}

/// ε / WIRE v5 — the 32-byte inner `session_id` is dropped from the data-plane
/// wire (the header shrinks to 15 bytes); it stays only in the AEAD AAD,
/// reconstructed from session context by `parse_protected`. This pins both
/// halves: (1) a distinctive session_id never appears on the protected wire, and
/// (2) the peer still recovers it and the HP + AEAD round-trip succeeds.
#[test]
fn v5_session_id_is_off_wire_but_reconstructed() {
    let shared = [0x33u8; 32];
    let id = SessionId::from_bytes([0xC7u8; 32]);
    let crypto_a = CryptoState::new(&shared, false).expect("client crypto");
    let crypto_b = CryptoState::new(&shared, true).expect("server crypto");
    let client = Session::from_derived(id, crypto_a, SchedulerMode::LowLatency, shared, false);
    let server = Session::from_derived(id, crypto_b, SchedulerMode::LowLatency, shared, true);

    let header = PacketHeader::new(*client.id(), 2, 9, PacketFlags::new(PacketFlags::ENCRYPTED));
    let ct = client
        .encrypt_packet(&header, b"hidden id", &[])
        .expect("encrypt");
    let packet = PhantomPacket::new(header, ct);
    let wire = client.protect_packet(&packet).expect("protect");

    // The distinctive session id (0xC7..) never appears anywhere on the wire.
    assert!(
        !wire.windows(8).any(|w| w == [0xC7u8; 8]),
        "session_id must not be serialised onto the v5 wire"
    );
    // ...yet the server reconstructs it from session context and decrypts.
    let parsed = server.parse_protected(&wire).expect("parse");
    assert_eq!(
        parsed.header.session_id,
        *server.id(),
        "parse_protected reconstructs session_id from the routed session"
    );
    let pt = server
        .decrypt_packet(&parsed.header, &parsed.payload, &parsed.extensions)
        .expect("decrypt");
    assert_eq!(pt, b"hidden id");
}

/// ε / WIRE v5 — `session_id` is bound through the AEAD AAD even though it is
/// off-wire. Two sessions sharing the AEAD keys (same `shared` secret, swap-paired
/// directions → matching keys + nonce) but holding DIFFERENT session ids must not
/// open each other's packets: the receiver reconstructs ITS id into the 47-byte
/// AAD image, which differs from the sender's → AEAD fail. A session with the
/// matching id does open it. This is the off-wire analogue of the v4
/// cleartext-session_id binding (design §2.2).
#[test]
fn v5_session_id_bound_via_aad_off_wire() {
    let shared = [0x5Eu8; 32];
    let id_a = SessionId::from_bytes([0xAAu8; 32]);
    let id_b = SessionId::from_bytes([0xBBu8; 32]);

    let sender = Session::from_derived(
        id_a,
        CryptoState::new(&shared, false).expect("sender crypto"),
        SchedulerMode::LowLatency,
        shared,
        false,
    );
    // Same AEAD keys (shared secret + server direction), DIFFERENT session id.
    let wrong = Session::from_derived(
        id_b,
        CryptoState::new(&shared, true).expect("wrong crypto"),
        SchedulerMode::LowLatency,
        shared,
        true,
    );
    // Same AEAD keys AND the matching session id.
    let right = Session::from_derived(
        id_a,
        CryptoState::new(&shared, true).expect("right crypto"),
        SchedulerMode::LowLatency,
        shared,
        true,
    );
    assert_ne!(sender.id(), wrong.id(), "distinct session ids");

    let header = PacketHeader::new(*sender.id(), 1, 1, PacketFlags::new(PacketFlags::ENCRYPTED));
    let ct = sender
        .encrypt_packet(&header, b"bound to A", &[])
        .expect("encrypt");

    // The wrong session reconstructs id_b into the AAD → AEAD fails, even though
    // its AEAD key and nonce match the sender's.
    let wrong_header =
        PacketHeader::new(*wrong.id(), 1, 1, PacketFlags::new(PacketFlags::ENCRYPTED));
    assert!(
        wrong.decrypt_packet(&wrong_header, &ct, &[]).is_err(),
        "a different session_id (off-wire, in the AAD) must not open the packet"
    );
    // The session with the matching id reconstructs id_a → AAD matches → opens.
    let right_header =
        PacketHeader::new(*right.id(), 1, 1, PacketFlags::new(PacketFlags::ENCRYPTED));
    let pt = right
        .decrypt_packet(&right_header, &ct, &[])
        .expect("matching session_id must open");
    assert_eq!(pt, b"bound to A");
}

/// ε / WIRE v5 (P3) — the rotating-CID chain is wired into `Session`: the
/// client's current outbound CID (`CID_0`) is EXACTLY what the server routes on —
/// it is the first entry of the server's inbound demux window. This is the
/// routing contract the UDP demux relies on (client stamps `current_outbound_cid`;
/// the server registers `inbound_window_cids` and a hit routes to the session).
/// The chains are per-direction (c2s / s2c), so the property holds both ways.
#[test]
fn v5_session_cid_chain_outbound_matches_peer_inbound_window() {
    let (client, server) = make_session_pair([0x5Eu8; 32]);

    // Client → server: the client stamps CID_0; the server's inbound window (the
    // c2s chain it routes on) must contain it as its leading entry.
    let client_cid0 = client.current_outbound_cid();
    let server_window = server.inbound_window_cids();
    assert_eq!(
        server_window[0], client_cid0,
        "server inbound window[0] must equal the client's CID_0"
    );
    assert!(server_window.contains(&client_cid0));

    // Server → client: symmetric (the s2c chain).
    let server_cid0 = server.current_outbound_cid();
    let client_window = client.inbound_window_cids();
    assert_eq!(client_window[0], server_cid0);

    // At index 0 the window is the leading lookahead (trailing saturates at 0):
    // K + 1 = 17 CIDs (indices 0..=16, with K = CID_WINDOW_LEADING = 16 — EPS-01).
    assert_eq!(
        server_window.len(),
        17,
        "leading window is K+1 = 17 CIDs at start (K = 16)"
    );
}

/// ε / WIRE v5 (P4) — `migrate()` rotates the outbound CID: `advance_outbound_cid`
/// bumps the index and returns the next CID (`CID_1` after `CID_0`). The rotated
/// CID is independent-random vs `CID_0` (the unlinkability property) yet still
/// inside the peer's pre-registered inbound window `[CID_0..CID_K]`, so the server
/// routes it without a re-handshake (for up to K migrations before a slide).
#[test]
fn v5_advance_outbound_cid_rotates_within_peer_window() {
    let (client, server) = make_session_pair([0x6Au8; 32]);
    let cid0 = client.current_outbound_cid();
    let cid1 = client.advance_outbound_cid();
    assert_ne!(cid0, cid1, "the CID must rotate on migrate");
    assert_eq!(
        cid1,
        client.current_outbound_cid(),
        "the outbound index advanced to 1"
    );

    // The rotated CID is still in the server's pre-registered leading window, so a
    // single migration routes without any window slide.
    let window = server.inbound_window_cids();
    assert!(
        window.contains(&cid1),
        "CID_1 must be routable via the pre-registered window"
    );

    // Each further migration yields another distinct CID (still within K).
    let cid2 = client.advance_outbound_cid();
    assert_ne!(cid1, cid2);
    assert!(window.contains(&cid2));
}

/// ε / WIRE v5 (P4b) — the server slides its inbound CID window as the client
/// migrates. `note_migration_path` advances the window one step per NEW (forward,
/// mod-256) path_id and yields the CIDs to add (new leading edge) / remove (past
/// the trailing edge); a reordered-old, duplicate, or unchanged path_id slides
/// nothing (robust to reordering + passive rebind, which never advances the index).
#[test]
fn v5_note_migration_path_slides_inbound_window() {
    use std::collections::HashSet;
    let (_client, server) = make_session_pair([0x7Bu8; 32]);
    let original: HashSet<[u8; 8]> = server.inbound_window_cids().into_iter().collect();

    // path_id 0 is the initial path — no slide.
    assert!(
        server.note_migration_path(0).is_none(),
        "the initial path does not slide"
    );

    // First migration: path_id 1 (forward) slides one step.
    let s1 = server
        .note_migration_path(1)
        .expect("a forward path_id must slide the window");
    assert_eq!(s1.add.len(), 1, "one CID added at the new leading edge");
    assert!(
        s1.remove.is_empty(),
        "nothing removed yet (highest=1 <= trailing T)"
    );
    assert!(
        !original.contains(&s1.add[0]),
        "the added CID is a fresh leading-edge CID, not one already registered"
    );
    // The post-slide window now centers at index 1 and includes the new CID.
    assert!(server.inbound_window_cids().contains(&s1.add[0]));

    // A duplicate of the same path_id does NOT slide again (idempotent).
    assert!(
        server.note_migration_path(1).is_none(),
        "a duplicate path_id slides nothing"
    );
    // A reordered OLD path_id (far behind, mod-256) does NOT slide.
    assert!(
        server.note_migration_path(0).is_none(),
        "a reordered-old path_id slides nothing"
    );

    // The next migration (path_id 2) slides again, to a distinct leading CID.
    let s2 = server
        .note_migration_path(2)
        .expect("the next forward path_id slides");
    assert_ne!(
        s1.add[0], s2.add[0],
        "each slide adds a distinct leading-edge CID"
    );
}

/// M-3 (passive NAT rebind): a passive rebind keeps `path_id = 0` — the
/// permanently-`Validated` handshake path — so the server CANNOT validate the new
/// source by re-challenging path 0 (`begin_path_validation` refuses a Validated
/// path). The fix reserves a dedicated validation id ([`REBIND_VALIDATION_PATH_ID`])
/// that ① is never produced by the active-migration counter (no slot collision
/// between an active migration and a concurrent passive rebind), ② can be taken
/// `Validating → Validated` independently of path 0, and ③ is re-challengeable
/// after a successful validation+retire (so a SECOND rebind also recovers). A
/// regression that reused path 0, or let the migration counter hand back the
/// reserved id, would silently break passive-rebind recovery or let two distinct
/// validations resolve each other's registry slot.
#[test]
fn m3_reserved_rebind_validation_path_is_disjoint_and_challengeable() {
    let (_client, server) = make_session_pair([0x3Cu8; 32]);

    // ① The active-migration counter never hands back 0 (handshake path) nor the
    //    reserved rebind id — across > 2 full u8 wraps.
    for _ in 0..600 {
        let id = server.next_migration_path_id();
        assert_ne!(
            id, 0,
            "the migration counter must never reuse the handshake path"
        );
        assert_ne!(
            id, REBIND_VALIDATION_PATH_ID,
            "the migration counter must never reuse the reserved rebind validation path"
        );
    }

    // ② Path 0 is permanently Validated, so it refuses a fresh challenge — which is
    //    exactly why a passive rebind (path_id still 0) cannot validate via path 0.
    assert_eq!(server.path_state(0), Some(PathStateKind::Validated));
    assert!(
        server.begin_path_validation(0).is_none(),
        "the always-Validated path 0 must refuse a new challenge"
    );

    // ...but the reserved id has no prior state and DOES yield a challenge, taking
    // it to Validating. This is the slot the server uses to validate the rebind.
    assert_eq!(server.path_state(REBIND_VALIDATION_PATH_ID), None);
    let challenge = server
        .begin_path_validation(REBIND_VALIDATION_PATH_ID)
        .expect("the reserved rebind id must be challengeable from scratch");
    assert_eq!(
        server.path_state(REBIND_VALIDATION_PATH_ID),
        Some(PathStateKind::Validating)
    );

    // ③ A correct echo validates it; a wrong echo would fail it (anti-spoof: only a
    //    response matching the server-issued random challenge promotes). The
    //    promotion itself is address-gated at the transport (`promote_candidate`),
    //    tested in the live udp_integration path.
    let mut wrong = challenge;
    wrong[0] ^= 0xFF;
    assert!(
        !server.complete_path_validation(REBIND_VALIDATION_PATH_ID, &wrong),
        "a wrong echo must NOT validate the rebind path"
    );
    assert_eq!(
        server.path_state(REBIND_VALIDATION_PATH_ID),
        Some(PathStateKind::Failed),
        "a wrong echo fails the path closed"
    );
}

/// Malformed wire bytes must fail parsing as a typed error, never a panic.
/// This protects the receive loop from a malicious peer crashing the process
/// by sending random bytes.
#[test]
fn malformed_versioned_packet_fails_to_parse_not_panic() {
    // A short byte stream (< the 15-byte v5 header): must be rejected, not parsed.
    let garbage: Vec<u8> = (0u8..10).collect();
    let result = PhantomPacket::from_wire(&garbage);
    assert!(
        result.is_err(),
        "Parser must reject random bytes with Err, not panic or accept"
    );

    // Empty input.
    let empty: Vec<u8> = Vec::new();
    let result = PhantomPacket::from_wire(&empty);
    assert!(result.is_err(), "Parser must reject empty input");
}

/// Sanity check that the constant-time cookie comparison wired in Phase 1.1
/// remains in place — if a future refactor accidentally replaces
/// `ConstantTimeEq` with `==`, a smoke test verifying that the function
/// `subtle::ConstantTimeEq::ct_eq` is callable on `[u8; 32]` will still pass,
/// but at least confirm here that two equal/unequal cookies behave correctly
/// at the boundary the handshake actually uses.
#[test]
fn cookie_equality_smoke_via_subtle() {
    use subtle::ConstantTimeEq;
    let a = [0x42u8; 32];
    let b = [0x42u8; 32];
    let mut c = [0x42u8; 32];
    c[31] ^= 1;
    assert!(bool::from(a.ct_eq(&b)), "equal cookies must compare equal");
    assert!(
        !bool::from(a.ct_eq(&c)),
        "different cookies must compare unequal"
    );
}

/// Server identity mismatch (the Vuln-1 fix from the May 2026 review) must
/// surface as a typed handshake error on the client side.
#[test]
fn server_identity_mismatch_aborts_handshake() {
    let real_server = HandshakeServer::new().expect("server new");
    let attacker_server = HandshakeServer::new().expect("attacker new");
    let attacker_pk = attacker_server.verifying_key().clone();

    let client = HandshakeClient::new().expect("client new");
    let client_hello = client.create_client_hello();
    let client_ip = "127.0.0.1".parse().expect("ip");

    // Drive the real server (the "honest" peer the client is actually talking
    // to). Skip the cookie retry by passing through twice.
    let server_hello = match real_server.process_client_hello(&client_hello, 0, client_ip) {
        HandshakeResponse::Retry(retry) => {
            let mut hello_retry = client_hello.clone();
            hello_retry.cookie = retry.cookie;
            match real_server.process_client_hello(&hello_retry, 0, client_ip) {
                HandshakeResponse::Success(sh, _, _) => sh,
                other => panic!("unexpected after retry: {:?}", other),
            }
        }
        HandshakeResponse::Success(sh, _, _) => sh,
        other => panic!("unexpected first response: {:?}", other),
    };

    // Client pins the *attacker*'s key — must reject.
    let result = client.process_server_hello(&client_hello, &server_hello, Some(&attacker_pk));
    match result {
        Err(HandshakeError::ServerIdentityMismatch) => { /* expected */ }
        other => panic!(
            "expected ServerIdentityMismatch, got {:?}",
            other.as_ref().map(|_| "Ok").unwrap_or("Err(<other>)")
        ),
    }
}

/// The `AEAD_MAX_INVOCATIONS` ceiling must be reachable: when the per-direction
/// counter reaches the limit, encrypt/decrypt return `CryptoError::NonceExhausted`
/// rather than wrapping past safe usage.
///
/// We can't actually push the counter to 2^48 in a test (~9 years of packets);
/// instead we encrypt one record and observe that the API exposes the counter,
/// confirming the safety-check plumbing exists.
#[test]
fn aead_invocations_counter_increments_per_op() {
    let secret = [0xC3u8; 32];
    let session = CryptoSession::with_suite(&secret, CipherSuite::Aes256Gcm).expect("session");
    assert_eq!(
        session.send_invocations(),
        0,
        "fresh session has zero count"
    );
    let _ = session.encrypt(&[], b"first").expect("encrypt 1");
    assert_eq!(session.send_invocations(), 1);
    let _ = session.encrypt(&[], b"second").expect("encrypt 2");
    assert_eq!(session.send_invocations(), 2);
}

/// Cookie tampering must cause the server to demand a retry (with a fresh
/// cookie), never `Success` with the tampered cookie accepted. This pins the
/// CT-equality fix in Phase 1.1 against a future regression.
#[test]
fn cookie_tampering_yields_retry_not_success() {
    let server = HandshakeServer::new().expect("server new");
    let client_ip = "10.20.30.40".parse().expect("ip");
    let client = HandshakeClient::new().expect("client new");
    let mut hello = client.create_client_hello();
    // A 32-byte cookie that the server certainly didn't issue.
    hello.cookie = Some([0xDEu8; 32]);

    match server.process_client_hello(&hello, 0, client_ip) {
        HandshakeResponse::Retry(retry) => {
            assert!(retry.cookie.is_some(), "server must provide a fresh cookie");
        }
        other => panic!(
            "expected Retry on bogus cookie, got {:?}",
            std::mem::discriminant(&other)
        ),
    }
}

/// Smoke check that `HybridSigningKey::generate()` produces distinct keypairs
/// across invocations (RNG is live). A regression that returned a constant
/// keypair would be a catastrophic security failure.
#[test]
fn signing_keypair_generation_is_non_deterministic() {
    let (_sk1, vk1) = HybridSigningKey::generate();
    let (_sk2, vk2) = HybridSigningKey::generate();
    assert_ne!(
        vk1.to_bytes(),
        vk2.to_bytes(),
        "two consecutive HybridSigningKey::generate() returned identical public keys"
    );
}

/// Encrypt → decrypt round-trip property: payload survives intact and the
/// ciphertext does not leak the plaintext.
#[test]
fn encrypted_packet_round_trip_preserves_payload() {
    let (client, server) = make_session_pair([0xD4u8; 32]);
    let payload = b"production-ready transport payload";
    let header = PacketHeader::new(
        *server.id(),
        2,
        42,
        PacketFlags::new(PacketFlags::ENCRYPTED | PacketFlags::RELIABLE),
    );
    let ct = client
        .encrypt_packet(&header, payload, &[])
        .expect("encrypt");
    assert_ne!(
        &ct[..payload.len()],
        payload,
        "ciphertext must not contain plaintext"
    );
    let pt = server.decrypt_packet(&header, &ct, &[]).expect("decrypt");
    assert_eq!(&pt, payload);
}

/// AEAD authenticity: flipping a single ciphertext byte must cause decrypt to
/// fail. This is what protects post-handshake traffic from tampering.
#[test]
fn tampered_ciphertext_is_rejected() {
    let (client, server) = make_session_pair([0xF1u8; 32]);
    let header = PacketHeader::new(
        *server.id(),
        7,
        1,
        PacketFlags::new(PacketFlags::ENCRYPTED | PacketFlags::RELIABLE),
    )
    .with_epoch(2)
    .with_path_id(3);

    let mut ct = client
        .encrypt_packet(&header, b"v2 payload", &[])
        .expect("encrypt v2");
    ct[0] ^= 0x01;

    let result = server.decrypt_packet(&header, &ct, &[]);
    assert!(
        result.is_err(),
        "V2 AEAD must reject bit-flipped ciphertext; got {:?}",
        result.as_ref().ok().map(|v| v.len())
    );
}

/// The header's `epoch` and `path_id` are AAD-bound. Flipping either after
/// encryption must invalidate the tag.
#[test]
fn tampered_epoch_or_path_id_is_rejected() {
    let (client, server) = make_session_pair([0xF2u8; 32]);
    let real_header = PacketHeader::new(
        *server.id(),
        7,
        1,
        PacketFlags::new(PacketFlags::ENCRYPTED | PacketFlags::RELIABLE),
    )
    .with_epoch(5)
    .with_path_id(0);
    let ct = client
        .encrypt_packet(&real_header, b"epoch-bound payload", &[])
        .expect("encrypt");

    // Mutate epoch.
    let tampered_epoch = PacketHeader {
        epoch: 6,
        ..real_header
    };
    assert!(server.decrypt_packet(&tampered_epoch, &ct, &[]).is_err());

    // Re-encrypt fresh so the AEAD recv counter aligns, then mutate path_id.
    let ct2 = client
        .encrypt_packet(&real_header, b"path-bound payload", &[])
        .expect("re-encrypt");
    let tampered_path = PacketHeader {
        path_id: 7,
        ..real_header
    };
    assert!(server.decrypt_packet(&tampered_path, &ct2, &[]).is_err());
}

/// Replay window: re-feeding a fresh ciphertext that reuses an
/// already-accepted `(stream_id, sequence)` must fail with
/// `CoreError::ReplayDetected`, and the per-session counter must increment.
/// The window keys on `(stream_id, sequence)` only — independent of epoch /
/// path_id.
#[test]
fn replay_window_rejects_duplicate_sequence() {
    use phantom_protocol::CoreError;

    let (client, server) = make_session_pair([0xF4u8; 32]);
    let header = PacketHeader::new(
        *server.id(),
        3,
        17,
        PacketFlags::new(PacketFlags::ENCRYPTED | PacketFlags::RELIABLE),
    );
    let ct1 = client.encrypt_packet(&header, b"payload", &[]).expect("e1");
    server
        .decrypt_packet(&header, &ct1, &[])
        .expect("first decrypt");
    assert_eq!(server.replay_rejected_total(), 0);

    let ct2 = client.encrypt_packet(&header, b"payload", &[]).expect("e2");
    match server.decrypt_packet(&header, &ct2, &[]) {
        Err(CoreError::ReplayDetected(_)) => { /* expected */ }
        other => panic!(
            "expected ReplayDetected on V2 duplicate, got {:?}",
            other.as_ref().map(|_| "Ok").unwrap_or("Err(<other>)")
        ),
    }
    assert_eq!(server.replay_rejected_total(), 1);
}

/// ε / WIRE v5 (audit EPS / V-2) — a CID rotation must open **no** replay hole.
/// The rotating-CID chain and the replay window are orthogonal: rotating the
/// outbound CID (`advance_outbound_cid`) or sliding the inbound window
/// (`note_migration_path`, a peer-migration signal) touches only the CID
/// counters, never the per-direction `u64` packet number or the sliding
/// `ReplayWindow`. So a packet replayed *across* a migration boundary still
/// carries its original `(stream_id, sequence)` and is rejected after AEAD
/// verify, exactly as before rotation (Invariant 4 — replay after AEAD).
#[test]
fn eps_replay_rejected_across_cid_rotation() {
    use phantom_protocol::CoreError;

    let (client, server) = make_session_pair([0x77u8; 32]);
    let header = PacketHeader::new(
        *server.id(),
        5,
        9,
        PacketFlags::new(PacketFlags::ENCRYPTED | PacketFlags::RELIABLE),
    );
    let ct1 = client
        .encrypt_packet(&header, b"v2-payload", &[])
        .expect("e1");
    server
        .decrypt_packet(&header, &ct1, &[])
        .expect("first decrypt accepts the sequence");
    assert_eq!(server.replay_rejected_total(), 0);

    // Rotate the CID on BOTH directions between the accept and the replay: the
    // client advances its outbound CID, and the server observes the client's
    // migration and slides its inbound window. Neither resets the replay state.
    let cid_before = client.current_outbound_cid();
    let _rotated = client.advance_outbound_cid();
    let window_before = server.inbound_window_cids();
    let _slide = server.note_migration_path(1);
    assert_ne!(
        client.current_outbound_cid(),
        cid_before,
        "outbound CID must actually rotate"
    );
    assert_ne!(
        server.inbound_window_cids(),
        window_before,
        "inbound window must actually slide"
    );

    // The same (stream_id, sequence) is still a replay — rotation opened no hole.
    let ct2 = client
        .encrypt_packet(&header, b"v2-payload", &[])
        .expect("e2");
    match server.decrypt_packet(&header, &ct2, &[]) {
        Err(CoreError::ReplayDetected(_)) => { /* expected */ }
        other => panic!(
            "expected ReplayDetected after a CID rotation, got {:?}",
            other.as_ref().map(|_| "Ok").unwrap_or("Err(<other>)")
        ),
    }
    assert_eq!(server.replay_rejected_total(), 1);
}

/// EPS-01 (multi-step window slide) — a forward `path_id` jump of `d > 1` (the
/// peer migrated d times but only the d-th packet was delivered + AEAD-verified)
/// must advance the inbound CID demux window by the **full delta `d`** — registering
/// `d` new leading CIDs — so the window recenters on the peer's actual migration
/// index instead of lagging by one. The pre-fix single-step slide advanced only +1,
/// so repeated lossy migrations cumulatively eroded the leading window until the
/// peer's CID fell out of it and the session stranded (audit 2026-06-15, EPS-01).
#[test]
fn eps01_multistep_path_jump_slides_window_by_the_full_delta() {
    let (_client, server) = make_session_pair([0x3Cu8; 32]);
    let slide = server
        .note_migration_path(5)
        .expect("a forward path_id jump must slide");
    assert_eq!(
        slide.add.len(),
        5,
        "a 5-step path_id jump must add 5 leading CIDs (multi-step slide), not 1 (single-step lag)"
    );
    // The window now centers on index 5 (highest_seen advanced to 5), so a
    // subsequent single migration to index 6 is a clean +1 step.
    let next = server
        .note_migration_path(6)
        .expect("the next migration slides");
    assert_eq!(
        next.add.len(),
        1,
        "a subsequent +1 migration adds exactly 1 leading CID"
    );
}

/// Nonce-from-header property — a tampered packet that fails AEAD
/// verification must NOT desync the receiver from the sender. The next
/// legitimate packet must still decrypt cleanly.
///
/// The AEAD nonce is derived from the authenticated `header.sequence` rather
/// than an internal monotonic counter, so a failed decrypt is stateless from
/// the AEAD's perspective — a single dropped / mutated packet does not break
/// the session.
#[test]
fn failed_decrypt_does_not_desync_session() {
    let (client, server) = make_session_pair([0x20u8; 32]);

    // Sender encrypts packet #1.
    let h1 = PacketHeader::new(
        *server.id(),
        1,
        1,
        PacketFlags::new(PacketFlags::ENCRYPTED | PacketFlags::RELIABLE),
    );
    let ct1 = client
        .encrypt_packet(&h1, b"first", &[])
        .expect("encrypt 1");

    // Bad packet arrives in between — flipped tag byte.
    let mut tampered = ct1.clone();
    let n = tampered.len();
    tampered[n - 1] ^= 0x80;
    assert!(server.decrypt_packet(&h1, &tampered, &[]).is_err());

    // The original ct1 (same header, same payload) must still decrypt —
    // in V1 this would fail because the recv_counter desynchronised; in
    // V2 the nonce is reconstructible from h1 alone.
    let pt1 = server.decrypt_packet(&h1, &ct1, &[]).expect("decrypt 1");
    assert_eq!(pt1, b"first");

    // And a subsequent packet at sequence 2 also goes through.
    let h2 = PacketHeader {
        packet_number: 2,
        ..h1
    };
    let ct2 = client
        .encrypt_packet(&h2, b"second", &[])
        .expect("encrypt 2");
    let pt2 = server.decrypt_packet(&h2, &ct2, &[]).expect("decrypt 2");
    assert_eq!(pt2, b"second");
}

/// Mid-session rekey (Phase 1.5) — `Session::rekey()` increments the epoch
/// and derives a new AEAD state. Ciphertext produced before rekey must NOT
/// decrypt with the post-rekey state.
#[test]
fn rekey_changes_keys_and_breaks_old_ciphertexts() {
    let (client, server) = make_session_pair([0x10u8; 32]);
    assert_eq!(client.current_epoch(), 0);
    assert_eq!(server.current_epoch(), 0);

    let header = PacketHeader::new(
        *server.id(),
        1,
        100,
        PacketFlags::new(PacketFlags::ENCRYPTED | PacketFlags::RELIABLE),
    );
    let ct_epoch0 = client
        .encrypt_packet(&header, b"pre-rekey payload", &[])
        .expect("encrypt e0");

    // Lock-step rekey on both ends.
    let client_new = client.rekey().expect("client rekey");
    let server_new = server.rekey().expect("server rekey");
    assert_eq!(client_new, 1);
    assert_eq!(server_new, 1);
    assert_eq!(client.current_epoch(), 1);
    assert_eq!(server.current_epoch(), 1);

    // The OLD ciphertext must NOT authenticate under the new keys.
    let header_epoch1 = PacketHeader { epoch: 1, ..header };
    assert!(
        server
            .decrypt_packet(&header_epoch1, &ct_epoch0, &[])
            .is_err(),
        "post-rekey CryptoState must reject pre-rekey ciphertext"
    );

    // A fresh encrypt under the new epoch round-trips successfully.
    let header_v1_e1 = PacketHeader::new(
        *server.id(),
        1,
        101,
        PacketFlags::new(PacketFlags::ENCRYPTED | PacketFlags::RELIABLE),
    )
    .with_epoch(1);
    let ct_epoch1 = client
        .encrypt_packet(&header_v1_e1, b"post-rekey payload", &[])
        .expect("encrypt e1");
    let pt = server
        .decrypt_packet(&header_v1_e1, &ct_epoch1, &[])
        .expect("decrypt e1");
    assert_eq!(pt, b"post-rekey payload");
}

/// `Session::ratchet_to_epoch(target)` advances the local epoch by repeated
/// HKDF chain steps. Useful for a receiver that fell behind and needs to
/// catch up to a higher-epoch packet.
#[test]
fn ratchet_to_epoch_walks_forward_n_steps() {
    let (_client, server) = make_session_pair([0x11u8; 32]);
    assert_eq!(server.current_epoch(), 0);
    server.ratchet_to_epoch(5).expect("ratchet to 5");
    assert_eq!(server.current_epoch(), 5);
    // Going to a lower target is a no-op.
    server.ratchet_to_epoch(3).expect("ratchet to 3 (no-op)");
    assert_eq!(server.current_epoch(), 5);
}

/// `Session::rekey` saturates at `u8::MAX` rather than wrapping — long
/// sessions must reconnect rather than reuse epoch 0 keys with a higher
/// counter.
#[test]
fn rekey_saturates_at_u8_max() {
    let (_, server) = make_session_pair([0x12u8; 32]);
    server
        .ratchet_to_epoch(u8::MAX)
        .expect("walk up to u8::MAX");
    assert_eq!(server.current_epoch(), u8::MAX);
    // The 256th rekey must fail rather than wrap to 0.
    assert!(server.rekey().is_err());
    assert_eq!(server.current_epoch(), u8::MAX, "epoch must not wrap");
}

/// C1: `decrypt_packet_accepting_rekey` follows a single *authenticated* forward
/// rekey step. The sender rekeys to epoch 1 and encrypts there; the receiver,
/// still at epoch 0, trial-decrypts under the next key, succeeds, and commits
/// the ratchet — ending at epoch 1 with the plaintext intact.
#[test]
fn accepting_decrypt_follows_one_authentic_rekey_step() {
    let (client, server) = make_session_pair([0x20u8; 32]);
    assert_eq!(server.current_epoch(), 0);

    // Sender rekeys ahead of the receiver.
    assert_eq!(client.rekey().expect("client rekey"), 1);
    let header = PacketHeader::new(
        *server.id(),
        1,
        7,
        PacketFlags::new(PacketFlags::ENCRYPTED | PacketFlags::REKEY),
    )
    .with_epoch(1);
    let ct = client
        .encrypt_packet(&header, b"first post-rekey", &[])
        .expect("encrypt e1");

    // Receiver is still at epoch 0; the accepting decrypt ratchets it forward.
    let pt = server
        .decrypt_packet_accepting_rekey(&header, &ct, &[])
        .expect("accepting decrypt follows the bump");
    assert_eq!(pt, b"first post-rekey");
    assert_eq!(server.current_epoch(), 1, "receiver committed the ratchet");
}

/// C1 security: a *forged* epoch bump (correct +1 epoch in the header, but
/// ciphertext that does not authenticate under the next key) is rejected and
/// MUST NOT commit the ratchet — otherwise an attacker could desync the session
/// by spoofing an epoch. After the rejection a legitimate same-epoch packet
/// still decrypts.
#[test]
fn accepting_decrypt_rejects_forged_bump_without_desync() {
    let (client, server) = make_session_pair([0x21u8; 32]);

    // Attacker forges a +1-epoch header but supplies garbage ciphertext.
    let forged = PacketHeader::new(
        *server.id(),
        1,
        1,
        PacketFlags::new(PacketFlags::ENCRYPTED | PacketFlags::REKEY),
    )
    .with_epoch(1);
    let garbage = vec![0xABu8; 64];
    assert!(
        server
            .decrypt_packet_accepting_rekey(&forged, &garbage, &[])
            .is_err(),
        "a forged epoch bump must fail the AEAD trial"
    );
    assert_eq!(
        server.current_epoch(),
        0,
        "a failed trial decrypt must NOT advance the epoch (no desync)"
    );

    // The session is intact: a genuine epoch-0 packet still round-trips.
    let header = PacketHeader::new(*server.id(), 1, 2, PacketFlags::new(PacketFlags::ENCRYPTED));
    let ct = client
        .encrypt_packet(&header, b"still in sync", &[])
        .expect("encrypt e0");
    let pt = server
        .decrypt_packet_accepting_rekey(&header, &ct, &[])
        .expect("same-epoch decrypt still works");
    assert_eq!(pt, b"still in sync");
}

/// C1: a *bounded* multi-epoch catch-up (within [`MAX_REKEY_CATCHUP`]) with a
/// genuinely valid ciphertext is followed — the receiver derives the chain
/// forward and commits all the steps at once. This absorbs the small epoch
/// divergence that arises when both directions rekey at slightly different
/// cadences.
#[test]
fn accepting_decrypt_follows_bounded_multi_step_catchup() {
    let (client, server) = make_session_pair([0x22u8; 32]);
    client.ratchet_to_epoch(3).expect("client to 3");
    let header = PacketHeader::new(
        *server.id(),
        1,
        1,
        PacketFlags::new(PacketFlags::ENCRYPTED | PacketFlags::REKEY),
    )
    .with_epoch(3);
    let ct = client
        .encrypt_packet(&header, b"three ahead", &[])
        .expect("encrypt e3");

    // Receiver at epoch 0 catches up 3 steps because the ciphertext authenticates.
    let pt = server
        .decrypt_packet_accepting_rekey(&header, &ct, &[])
        .expect("bounded multi-step catch-up follows a valid jump");
    assert_eq!(pt, b"three ahead");
    assert_eq!(server.current_epoch(), 3, "receiver caught up to epoch 3");
}

/// C1 security: a jump *beyond* [`MAX_REKEY_CATCHUP`] is rejected outright even
/// with a valid ciphertext — this caps the HKDF work an attacker can force per
/// spoofed packet. A legitimate gap is never this large; over a reliable
/// transport the sender retransmits at the current epoch.
#[test]
fn accepting_decrypt_rejects_jump_beyond_catchup_bound() {
    let (client, server) = make_session_pair([0x24u8; 32]);
    let target = MAX_REKEY_CATCHUP + 1;
    client.ratchet_to_epoch(target).expect("client far ahead");
    let header = PacketHeader::new(
        *server.id(),
        1,
        1,
        PacketFlags::new(PacketFlags::ENCRYPTED | PacketFlags::REKEY),
    )
    .with_epoch(target);
    let ct = client
        .encrypt_packet(&header, b"too far", &[])
        .expect("encrypt far");

    assert!(
        server
            .decrypt_packet_accepting_rekey(&header, &ct, &[])
            .is_err(),
        "a jump beyond MAX_REKEY_CATCHUP must be rejected"
    );
    assert_eq!(
        server.current_epoch(),
        0,
        "no ratchet on an over-bound jump"
    );
}

/// C1: the automatic-rekey trigger predicate flips once the send direction
/// crosses the configurable high-watermark, and an actual `rekey()` clears it
/// (the counter resets under the fresh key).
#[test]
fn send_needs_rekey_fires_at_threshold_and_clears_on_rekey() {
    let (client, _server) = make_session_pair([0x23u8; 32]);
    client.set_rekey_threshold(4);
    assert!(
        !client.send_needs_rekey(),
        "fresh session is below threshold"
    );

    let header = PacketHeader::new(*client.id(), 1, 0, PacketFlags::new(PacketFlags::ENCRYPTED));
    for i in 0..4u32 {
        let h = PacketHeader {
            packet_number: i as u64,
            ..header
        };
        client.encrypt_packet(&h, b"x", &[]).expect("encrypt");
    }
    assert!(
        client.send_needs_rekey(),
        "after {} sends the trigger must fire",
        client.send_invocations()
    );

    assert_eq!(client.rekey().expect("rekey"), 1);
    assert!(
        !client.send_needs_rekey(),
        "rekey resets the send counter under the new key, clearing the trigger"
    );
}

/// T5.5(b) — the forward-rekey catch-up GATE. A legitimate sender that has
/// rekeyed but whose peer hasn't acknowledged it re-advertises
/// `PacketFlags::REKEY` on EVERY new-epoch packet (see `rekey_unconfirmed`), so a
/// forward-epoch packet WITHOUT the flag never comes from an honest
/// not-yet-confirmed sender — it is forged/corrupt and is cheap-rejected BEFORE
/// the HKDF catch-up walk runs. This pins the DoS bound: no key derivation for an
/// unflagged spoofed epoch. The ciphertext here is genuinely valid under the next
/// key (its AAD matches the flag-less header), so WITHOUT the gate the old code
/// would follow the bump and silently advance the epoch — the gate is exactly
/// what rejects it pre-catch-up.
#[test]
fn forward_epoch_without_rekey_flag_is_rejected_before_catchup() {
    let (client, server) = make_session_pair([0x40u8; 32]);
    // Sender rekeys to epoch 1 and encrypts a VALID epoch-1 packet whose header
    // carries NO REKEY flag (so the AAD matches and the ciphertext would open if
    // the catch-up actually ran).
    assert_eq!(client.rekey().expect("client rekey"), 1);
    let no_rekey = PacketHeader::new(
        *server.id(),
        1,
        9,
        PacketFlags::new(PacketFlags::ENCRYPTED), // deliberately NO REKEY
    )
    .with_epoch(1);
    let ct = client
        .encrypt_packet(&no_rekey, b"forward but unflagged", &[])
        .expect("encrypt e1");

    // The receiver (still at epoch 0) must reject it WITHOUT running the HKDF
    // catch-up.
    assert!(
        server
            .decrypt_packet_accepting_rekey(&no_rekey, &ct, &[])
            .is_err(),
        "a forward-epoch packet without REKEY must be rejected"
    );
    assert_eq!(
        server.current_epoch(),
        0,
        "the gate rejects before catch-up: no HKDF step, no epoch advance"
    );

    // The SAME forward step but WITH the REKEY flag (the legitimate re-advertised
    // form) IS followed — proving the rejection above was specifically the missing
    // flag, not the epoch. (Re-encrypt because the flag is AAD-bound.)
    let with_rekey = PacketHeader::new(
        *server.id(),
        1,
        9,
        PacketFlags::new(PacketFlags::ENCRYPTED | PacketFlags::REKEY),
    )
    .with_epoch(1);
    let ct2 = client
        .encrypt_packet(&with_rekey, b"forward and flagged", &[])
        .expect("encrypt e1 flagged");
    let pt = server
        .decrypt_packet_accepting_rekey(&with_rekey, &ct2, &[])
        .expect("a REKEY-flagged forward packet is followed");
    assert_eq!(pt, b"forward and flagged");
    assert_eq!(server.current_epoch(), 1);
}

/// T5.5(b) — `rekey_unconfirmed` tracks whether our locally-initiated rekey has
/// been acknowledged by the peer. It is SET when we `rekey()` and stays set —
/// driving the REKEY re-advertise on every outbound packet — until we receive an
/// AUTHENTICATED inbound packet at our current epoch (proof the peer caught up).
/// A peer packet still BEHIND our epoch must NOT clear it.
#[test]
fn rekey_unconfirmed_set_on_rekey_cleared_only_by_peer_at_current_epoch() {
    let (client, server) = make_session_pair([0x41u8; 32]);
    assert!(
        !client.rekey_unconfirmed(),
        "fresh session: nothing to confirm"
    );

    // We rekey → unconfirmed until the peer is seen at our new epoch.
    assert_eq!(client.rekey().expect("client rekey"), 1);
    assert!(
        client.rekey_unconfirmed(),
        "a locally-initiated rekey is unconfirmed until the peer catches up"
    );

    // A peer packet still at the OLD epoch (peer hasn't processed our rekey) is
    // BEHIND our epoch → rejected → must NOT clear the flag.
    let behind = PacketHeader::new(*client.id(), 1, 1, PacketFlags::new(PacketFlags::ENCRYPTED));
    let ct_behind = server
        .encrypt_packet(&behind, b"still at e0", &[])
        .expect("server encrypt e0");
    assert!(
        client
            .decrypt_packet_accepting_rekey(&behind, &ct_behind, &[])
            .is_err(),
        "a peer packet behind our epoch is rejected"
    );
    assert!(
        client.rekey_unconfirmed(),
        "a behind-epoch peer packet does not confirm catch-up"
    );

    // The peer catches up to our epoch and sends there → an authenticated inbound
    // packet at our current epoch CLEARS the flag (stop re-advertising REKEY).
    assert_eq!(server.rekey().expect("server rekey"), 1);
    let at_current =
        PacketHeader::new(*client.id(), 1, 2, PacketFlags::new(PacketFlags::ENCRYPTED))
            .with_epoch(1);
    let ct_current = server
        .encrypt_packet(&at_current, b"caught up to e1", &[])
        .expect("server encrypt e1");
    let pt = client
        .decrypt_packet_accepting_rekey(&at_current, &ct_current, &[])
        .expect("peer-at-current decrypts");
    assert_eq!(pt, b"caught up to e1");
    assert!(
        !client.rekey_unconfirmed(),
        "an authenticated peer packet at our epoch confirms the rekey"
    );
}

/// T5.5(b) — re-advertising REKEY makes the rekey robust to losing the FIRST
/// new-epoch packet. In the old design only the single trigger packet carried
/// REKEY; if it was lost, later new-epoch packets (incl. reliable retransmits)
/// went unflagged. With the gate in place that would strand the receiver. Because
/// `rekey_unconfirmed` is still set after the loss, the NEXT packet at the new
/// epoch is ALSO flagged REKEY, so the receiver still catches up through the gate.
#[test]
fn rekey_survives_loss_of_the_first_rekey_packet() {
    let (client, server) = make_session_pair([0x42u8; 32]);
    assert_eq!(client.rekey().expect("client rekey"), 1);
    assert!(client.rekey_unconfirmed());

    // Packet #1 at the new epoch (REKEY flagged) — LOST: encrypted but never
    // delivered to the server.
    let p1 = PacketHeader::new(
        *server.id(),
        1,
        10,
        PacketFlags::new(PacketFlags::ENCRYPTED | PacketFlags::REKEY),
    )
    .with_epoch(1);
    let _dropped = client
        .encrypt_packet(&p1, b"lost trigger", &[])
        .expect("encrypt p1");

    // The client has heard nothing back, so it is still unconfirmed and the send
    // path re-advertises REKEY on packet #2.
    assert!(
        client.rekey_unconfirmed(),
        "no peer confirmation yet → keep re-advertising REKEY"
    );
    let p2 = PacketHeader::new(
        *server.id(),
        1,
        11,
        PacketFlags::new(PacketFlags::ENCRYPTED | PacketFlags::REKEY),
    )
    .with_epoch(1);
    let ct2 = client
        .encrypt_packet(&p2, b"retransmit catches up", &[])
        .expect("encrypt p2");

    // The receiver never saw p1 but still catches up from p2 because REKEY was
    // re-advertised.
    let pt = server
        .decrypt_packet_accepting_rekey(&p2, &ct2, &[])
        .expect("re-advertised REKEY lets the receiver catch up after losing p1");
    assert_eq!(pt, b"retransmit catches up");
    assert_eq!(
        server.current_epoch(),
        1,
        "receiver caught up despite the lost trigger packet"
    );
}

/// C1 concurrency: the data pump drives the send loop and the receive task
/// concurrently over one `Arc<Session>`, so a send-side `rekey()` can race a
/// receive-side ratchet. Every transition must be atomic — the installed key
/// depth and the epoch counter must never diverge. We hammer `rekey()` from
/// many threads and then prove the final key is exactly `epoch` HKDF steps deep
/// by round-tripping a packet against a peer ratcheted to the same epoch. With
/// a non-atomic (read-epoch / derive / bump-relative) transition this wedges:
/// the epoch overshoots the key depth and the round-trip fails.
#[test]
fn concurrent_rekeys_keep_epoch_and_key_in_lockstep() {
    use std::sync::Arc;

    const THREADS: usize = 8;
    const PER_THREAD: usize = 20; // 160 total < u8::MAX, so none saturate

    let (client, server) = make_session_pair([0x30u8; 32]);
    let client = Arc::new(client);

    let mut handles = Vec::new();
    for _ in 0..THREADS {
        let c = Arc::clone(&client);
        handles.push(std::thread::spawn(move || {
            for _ in 0..PER_THREAD {
                c.rekey().expect("concurrent rekey");
            }
        }));
    }
    for h in handles {
        h.join().expect("rekey thread");
    }

    let epoch = client.current_epoch();
    assert_eq!(
        epoch as usize,
        THREADS * PER_THREAD,
        "every concurrent rekey must advance the epoch exactly once (no lost/double bumps)"
    );

    // Prove key-depth == epoch: a peer ratcheted to the same epoch must decrypt.
    server.ratchet_to_epoch(epoch).expect("server catch up");
    let header = PacketHeader::new(*client.id(), 1, 1, PacketFlags::new(PacketFlags::ENCRYPTED))
        .with_epoch(epoch);
    let ct = client
        .encrypt_packet(&header, b"post-race payload", &[])
        .expect("encrypt at final epoch");
    let pt = server
        .decrypt_packet(&header, &ct, &[])
        .expect("installed key depth must equal the epoch counter");
    assert_eq!(pt, b"post-race payload");
}

// ── Multi-path / migration (Phase 4.2) ────────────────────────────────────

/// New paths must NOT be implicitly trusted. After session creation,
/// path 0 is the validated default; an unfamiliar path id starts at
/// `Unvalidated` and only transitions to `Validated` through the
/// challenge-response API.
#[test]
fn new_paths_default_to_unvalidated() {
    let (_client, server) = make_session_pair([0x40u8; 32]);
    // Path 0 was registered at construction and pre-validated — it's
    // the path the handshake traversed.
    assert_eq!(server.path_state(0), Some(PathStateKind::Validated));
    // Path 7 has never been seen.
    assert_eq!(server.path_state(7), None);

    // begin_path_validation registers + issues challenge.
    let challenge = server.begin_path_validation(7).expect("challenge");
    assert_eq!(challenge.len(), 32);
    assert_eq!(server.path_state(7), Some(PathStateKind::Validating));
}

/// A correct challenge response transitions the path to `Validated`
/// and surfaces it in `validated_paths`.
#[test]
fn correct_response_validates_path() {
    let (_client, server) = make_session_pair([0x41u8; 32]);
    let challenge = server.begin_path_validation(3).expect("challenge");
    assert!(server.complete_path_validation(3, &challenge));
    assert_eq!(server.path_state(3), Some(PathStateKind::Validated));

    let mut validated = server.validated_paths();
    validated.sort();
    // Path 0 was pre-validated at construction; path 3 just was.
    assert_eq!(validated, vec![0, 3]);
}

/// A wrong response transitions the path to `Failed` — application data
/// must NOT cross over it.
#[test]
fn wrong_response_marks_path_failed() {
    let (_client, server) = make_session_pair([0x42u8; 32]);
    let mut challenge = server.begin_path_validation(5).expect("challenge");
    challenge[0] ^= 0xFF;
    assert!(!server.complete_path_validation(5, &challenge));
    assert_eq!(server.path_state(5), Some(PathStateKind::Failed));
    assert!(!server.validated_paths().contains(&5));
}

/// `complete_path_validation` returns `false` for paths that were never
/// challenged — protects against an attacker bypassing the challenge step.
#[test]
fn unchallenged_path_cannot_be_completed() {
    let (_client, server) = make_session_pair([0x43u8; 32]);
    assert!(!server.complete_path_validation(9, &[0u8; 32]));
    // No state was created (registry wasn't touched).
    assert_eq!(server.path_state(9), None);
}

/// A `PhantomPacket` survives serialize + deserialize with the pinned wire
/// version and all header fields preserved.
#[test]
fn packet_roundtrip_preserves_fields() {
    let header = PacketHeader::new(
        SessionId::from_bytes([9u8; 32]),
        99,
        2025,
        PacketFlags::new(PacketFlags::RELIABLE | PacketFlags::ENCRYPTED | PacketFlags::REKEY),
    )
    .with_epoch(11)
    .with_path_id(2);
    let packet = PhantomPacket::new(header, vec![0xDE, 0xAD]);
    let buf = packet.to_wire();
    let decoded = PhantomPacket::from_wire(&buf).expect("roundtrip");
    assert_eq!(decoded.header.version, WIRE_VERSION);
    assert_eq!(decoded.header.epoch, 11);
    assert_eq!(decoded.header.path_id, 2);
    assert!(decoded.header.flags.contains(PacketFlags::REKEY));
    assert_eq!(decoded.payload, vec![0xDE, 0xAD]);
}

// ── Flow-control enforcement invariants (receive-backpressure decoupling) ────
//
// With backpressure decoupled from the recv reader, the SEND side is where flow
// control is actually enforced: `Stream::poll_send` admits new data only within
// `min(congestion_window, peer_flow_control_window)`, while retransmissions must
// bypass both so loss recovery can never be starved by a closed window. These
// two tests pin those properties so a future change can't silently let a stream
// outrun a slow peer (unbounded receiver memory) or wedge loss recovery.

/// New (first-transmission) data is admitted only within the advertised
/// flow-control window AND the congestion window — `min` of the two. A segment
/// that does not fit is withheld and, crucially, does NOT debit the window (so
/// the credit is not leaked while the segment waits).
#[tokio::test]
async fn flow_control_bounds_new_data_to_the_advertised_window() {
    // ── Flow-control window bound ──
    let s = Stream::new(1);
    // Drain the peer's advertised window down to a known small amount.
    assert!(s.try_consume_send_window(INITIAL_STREAM_WINDOW - 100));
    assert_eq!(s.peer_send_window(), 100);

    // Two new-data segments queued: the first fits the 100-byte window, the
    // second does not. The congestion budget is unbounded so ONLY the
    // flow-control window can gate us here.
    s.send_reliable(Bytes::from(vec![0u8; 60])).await.unwrap(); // seq 0
    s.send_reliable(Bytes::from(vec![0u8; 60])).await.unwrap(); // seq 1

    let first = s
        .poll_send(u64::MAX)
        .await
        .expect("first segment fits the window");
    assert!(!first.retransmit);
    assert_eq!(first.data.len(), 60);
    assert_eq!(s.peer_send_window(), 40, "window debited by the sent bytes");

    // The second 60-byte segment exceeds the remaining 40-byte window → withheld.
    assert!(
        s.poll_send(u64::MAX).await.is_none(),
        "new data exceeding the flow-control window must be withheld"
    );
    assert_eq!(
        s.peer_send_window(),
        40,
        "a withheld segment must NOT debit the window (no credit leak)"
    );

    // ── Congestion window bound ──
    let s2 = Stream::new(2);
    s2.send_reliable(Bytes::from(vec![0u8; 100])).await.unwrap();
    // cwnd budget smaller than the segment → withheld by congestion control,
    // BEFORE the flow-control window is even consulted.
    assert!(
        s2.poll_send(50).await.is_none(),
        "new data exceeding the congestion window must be withheld"
    );
    assert_eq!(
        s2.peer_send_window(),
        INITIAL_STREAM_WINDOW,
        "a cwnd-blocked segment must not debit the flow-control window"
    );
}

/// Retransmissions bypass BOTH the congestion window and the flow-control
/// window: a timed-out segment is re-offered even when `cwnd_budget == 0` and
/// the peer's window is fully closed — loss recovery must always proceed, and
/// the retransmit must not debit the (already-accounted) window again.
#[tokio::test]
async fn retransmissions_bypass_congestion_and_flow_control_windows() {
    tokio::time::pause();
    let s = Stream::new(1);
    s.send_reliable(Bytes::from(vec![0u8; 200])).await.unwrap(); // seq 0

    // First transmission debits the window (200 bytes) under an unbounded cwnd.
    let first = s.poll_send(u64::MAX).await.expect("first transmission");
    assert!(!first.retransmit);
    assert_eq!(first.data.len(), 200);
    assert_eq!(s.peer_send_window(), INITIAL_STREAM_WINDOW - 200);

    // Slam BOTH budgets shut: drain the flow-control window to zero …
    assert!(s.try_consume_send_window(s.peer_send_window()));
    assert_eq!(s.peer_send_window(), 0);
    // … and an immediate re-poll (cwnd 0, window 0) yields nothing — the
    // segment is in-flight, not yet timed out.
    assert!(s.poll_send(0).await.is_none());

    // Advance past the initial 1s RTO so the unacked segment is due to retransmit.
    tokio::time::advance(Duration::from_millis(1100)).await;

    // The retransmit is produced despite cwnd == 0 AND window == 0 (Karn: the
    // bytes were accounted on first send; loss recovery must always proceed).
    let rtx = s
        .poll_send(0)
        .await
        .expect("retransmission must bypass both the congestion and flow-control windows");
    assert!(rtx.retransmit, "must be flagged as a retransmission");
    assert_eq!(rtx.stream_offset, first.stream_offset);
    assert_eq!(rtx.data.len(), 200);
    assert_eq!(
        s.peer_send_window(),
        0,
        "a retransmission must not debit the flow-control window again"
    );
}

// ── Auth cluster: H2 (transcript-signed 0-RTT verdict) ──────────────────────

/// Drive a fresh `ClientHello` through the server to a `ServerHello`,
/// transparently answering the single cookie `Retry` the DoS gate issues.
/// Returns the **effective** `ClientHello` the server actually signed over
/// (the retried one, carrying the cookie) alongside the `ServerHello`, so the
/// caller verifies the signature against the matching transcript input.
fn drive_handshake_to_success(
    server: &HandshakeServer,
    client_hello: &ClientHello,
    client_ip: std::net::IpAddr,
) -> (ClientHello, ServerHello) {
    match server.process_client_hello(client_hello, 0, client_ip) {
        HandshakeResponse::Success(sh, _, _) => (client_hello.clone(), sh),
        HandshakeResponse::Retry(retry) => {
            let mut retried = client_hello.clone();
            retried.cookie = retry.cookie;
            match server.process_client_hello(&retried, 0, client_ip) {
                HandshakeResponse::Success(sh, _, _) => (retried, sh),
                other => panic!("unexpected response after cookie retry: {:?}", other),
            }
        }
        other => panic!("unexpected first handshake response: {:?}", other),
    }
}

/// **H2 (Invariant 9).** `ServerHello.early_data_accepted` is the server's 0-RTT
/// verdict. It MUST be covered by the signed handshake transcript: an on-path
/// attacker who flips the bit (leaving signature/ciphertext/session_id intact)
/// must break the client's signature check, not slip a forged verdict through —
/// a forged verdict would let the attacker duplicate or silently black-hole
/// 0-RTT early-data.
#[test]
fn flipped_early_data_accepted_bit_fails_signature() {
    let server = HandshakeServer::new().expect("server");
    let server_pk = server.verifying_key().clone();
    let client = HandshakeClient::new().expect("client");
    let hello = client.create_client_hello();
    let ip = "127.0.0.1".parse().expect("ip");
    let (effective_hello, sh) = drive_handshake_to_success(&server, &hello, ip);

    // Honest verdict verifies (positive control).
    assert!(
        client
            .process_server_hello(&effective_hello, &sh, Some(&server_pk))
            .is_ok(),
        "an untampered ServerHello must verify"
    );

    // Flip the verdict; signature/ciphertext/session_id are left intact.
    let mut tampered = sh.clone();
    tampered.early_data_accepted = !tampered.early_data_accepted;
    assert!(
        matches!(
            client.process_server_hello(&effective_hello, &tampered, Some(&server_pk)),
            Err(HandshakeError::KemFailed(_))
        ),
        "flipping early_data_accepted must fail the transcript signature check"
    );
}

// ── Auth cluster: HS-03 (resumption PoP binder) + ZERORTT-2 (consume-on-success)

/// Drive a first full handshake so the server mints a resumption ticket; return
/// the `(resume_session_id, resumption_secret)` the client would later resume
/// with (the two halves of `Session::resumption_hint()`).
fn first_handshake_mint_ticket(
    server: &HandshakeServer,
    client: &HandshakeClient,
    server_pk: &HybridVerifyingKey,
    ip: std::net::IpAddr,
) -> ([u8; 32], [u8; 32]) {
    let hello = client.create_client_hello();
    let (effective, sh) = drive_handshake_to_success(server, &hello, ip);
    let (session, _) = client
        .process_server_hello(&effective, &sh, Some(server_pk))
        .expect("client establishes session");
    let secret = session
        .resumption_secret()
        .expect("resumption secret installed");
    (sh.session_id, secret)
}

/// **HS-03 (Invariant 9).** A resume must carry a `resumption_binder` proving
/// possession of the prior session's `resumption_secret`. A passive observer
/// that copied only the cleartext `resume_session_id` cannot forge it, so a
/// binderless (or wrong-binder) resume must NOT consume the victim's one-shot
/// ticket — it falls back to the normal cookie/PoW gate, ticket intact.
#[test]
fn binderless_resume_does_not_burn_ticket() {
    let server = HandshakeServer::new().expect("server");
    let server_pk = server.verifying_key().clone();
    let ip = "127.0.0.1".parse().expect("ip");
    let client1 = HandshakeClient::new().expect("client1");
    let (rid, secret) = first_handshake_mint_ticket(&server, &client1, &server_pk, ip);
    assert_eq!(
        server.session_cache_len(),
        1,
        "first handshake mints a ticket"
    );

    // Observer: right rid, NO binder (cannot compute it without `secret`).
    let client2 = HandshakeClient::new().expect("client2");
    let mut forged = client2.create_client_hello_with_resume(rid, &secret, None);
    forged.resumption_binder = None;
    match server.process_client_hello(&forged, 0, ip) {
        HandshakeResponse::Retry(_) => {} // fell back to the DoS gate — correct
        other => panic!("a binderless resume must not bypass the gate: {:?}", other),
    }
    assert_eq!(
        server.session_cache_len(),
        1,
        "a binderless resume must NOT consume the ticket"
    );

    // Also: a WRONG binder (attacker guesses) must not burn it either.
    let mut wrong = client2.create_client_hello_with_resume(rid, &secret, None);
    wrong.resumption_binder = Some([0xAB; 32]);
    let _ = server.process_client_hello(&wrong, 0, ip);
    assert_eq!(
        server.session_cache_len(),
        1,
        "a wrong-binder resume must NOT consume the ticket"
    );

    // A legitimate resume (correct binder, proving possession of `secret`)
    // bypasses the gate and consumes the ticket.
    let client3 = HandshakeClient::new().expect("client3");
    let valid = client3.create_client_hello_with_resume(rid, &secret, None);
    match server.process_client_hello(&valid, 0, ip) {
        HandshakeResponse::Success(..) => {} // bypass ⇒ binder verified + consumed
        other => panic!("a valid resume should succeed: {:?}", other),
    }
    // One-shot (Invariant 9): replaying the SAME resume no longer bypasses the
    // gate — the ticket for `rid` was consumed (a successful resume mints a
    // fresh ticket under a NEW id, so this `rid` is gone for good).
    match server.process_client_hello(&valid, 0, ip) {
        HandshakeResponse::Retry(_) => {}
        other => panic!(
            "a replayed resume must not resume again (one-shot): {:?}",
            other
        ),
    }
}

/// **ZERORTT-2 (Invariant 9).** The ticket is consumed eagerly after the binder
/// check, but a handshake step that fails AFTER consumption (here: a corrupted
/// KEM key package fails `encapsulate()`) must re-insert the ticket — a
/// corrupted resuming `ClientHello` must not burn a victim's one-shot ticket.
#[test]
fn failed_resume_handshake_leaves_ticket_usable() {
    let server = HandshakeServer::new().expect("server");
    let server_pk = server.verifying_key().clone();
    let ip = "127.0.0.1".parse().expect("ip");
    let client1 = HandshakeClient::new().expect("client1");
    let (rid, secret) = first_handshake_mint_ticket(&server, &client1, &server_pk, ip);
    assert_eq!(server.session_cache_len(), 1);

    // Valid binder (over secret/rid/nonce), but corrupt the ML-KEM public so
    // encapsulate() fails after the ticket is consumed.
    let client2 = HandshakeClient::new().expect("client2");
    let mut hello = client2.create_client_hello_with_resume(rid, &secret, None);
    hello.client_key_package.ml_kem_pk.truncate(1); // wrong length → KEM decode fails
    match server.process_client_hello(&hello, 0, ip) {
        HandshakeResponse::Fail(HandshakeError::KemFailed(_)) => {}
        other => panic!("a corrupted-KEM resume should fail: {:?}", other),
    }
    assert_eq!(
        server.session_cache_len(),
        1,
        "a resume that fails after consume must re-insert the ticket (not burn it)"
    );

    // And the re-inserted ticket is still usable by a clean resume afterwards
    // (Success with difficulty=0 and no cookie can only happen via the resume
    // bypass — so this proves the ticket survived the failed attempt).
    let client3 = HandshakeClient::new().expect("client3");
    let valid = client3.create_client_hello_with_resume(rid, &secret, None);
    assert!(
        matches!(
            server.process_client_hello(&valid, 0, ip),
            HandshakeResponse::Success(..)
        ),
        "the re-inserted ticket must be usable by a clean resume"
    );
}

// ── 1 (Phase 4): per-direction u64 packet-number invariants ─────────────────
// These replace the deleted C1 per-stream-watermark tests: under model 1 the
// AEAD nonce is `prefix || packet_number`, with `packet_number` a per-direction
// monotonic u64 that cannot wrap within a session.

/// `next_send_pn` yields a strictly increasing, never-repeating per-direction
/// sequence — the basis of "the AEAD nonce is never reused, full stop".
#[test]
fn packet_number_is_strictly_monotonic_and_unique() {
    let (client, _server) = make_session_pair([0x91u8; 32]);
    let mut seen = std::collections::HashSet::new();
    let mut last: Option<u64> = None;
    for _ in 0..10_000 {
        let pn = client.next_send_pn();
        assert!(seen.insert(pn), "packet number {pn} reused");
        if let Some(prev) = last {
            assert!(
                pn > prev,
                "packet number not strictly increasing: {prev} -> {pn}"
            );
        }
        last = Some(pn);
    }
}

/// D5 audit anchor: `path_id` is authenticated in the 47-byte AAD but is NOT in
/// the AEAD nonce (`prefix || packet_number`). Encrypting the SAME plaintext
/// under the SAME `(packet_number, stream_id, epoch)` but a DIFFERENT `path_id`
/// must yield an identical ciphertext **body** (same nonce => same keystream) and
/// a DIFFERENT auth tag (path_id is in the AAD). The body-equality is what makes
/// retiring/reusing a `path_id` nonce-safe; the tag-difference confirms path_id
/// stays authenticated.
#[test]
fn path_id_is_in_aad_not_nonce() {
    let (client, _server) = make_session_pair([0x92u8; 32]);
    let sid = *client.id();
    let pt = b"phantom-path-id-nonce-probe";
    let h0 =
        PacketHeader::new(sid, 1, 42, PacketFlags::new(PacketFlags::ENCRYPTED)).with_path_id(0);
    let h5 =
        PacketHeader::new(sid, 1, 42, PacketFlags::new(PacketFlags::ENCRYPTED)).with_path_id(5);
    let c0 = client.encrypt_packet(&h0, pt, &[]).expect("encrypt h0");
    let c5 = client.encrypt_packet(&h5, pt, &[]).expect("encrypt h5");
    // AEAD output = ciphertext-body || 16-byte auth tag.
    const TAG: usize = 16;
    assert_eq!(c0.len(), c5.len());
    assert!(c0.len() > TAG);
    let (body0, tag0) = c0.split_at(c0.len() - TAG);
    let (body5, tag5) = c5.split_at(c5.len() - TAG);
    // Nonce ignores path_id => identical keystream => identical ciphertext body.
    assert_eq!(
        body0, body5,
        "ciphertext body differs => path_id leaked into the nonce"
    );
    // path_id IS authenticated (it is in the AAD) => the tag must differ.
    assert_ne!(
        tag0, tag5,
        "tag identical => path_id not bound into the AAD"
    );
}

/// The collapse from per-`StreamId` replay windows to ONE per-direction window
/// must still accept packets interleaved across streams (the packet number is
/// unique per direction regardless of stream) and reject only a true PN dup.
#[test]
fn per_direction_window_accepts_interleaved_streams() {
    let (client, server) = make_session_pair([0x93u8; 32]);
    let sid = *client.id();
    let mut pn = 0u64;
    for _round in 0..500 {
        for stream_id in [1u16, 7u16] {
            let h = PacketHeader::new(sid, stream_id, pn, PacketFlags::new(PacketFlags::ENCRYPTED));
            let ct = client.encrypt_packet(&h, b"x", &[]).expect("encrypt");
            assert!(
                server.decrypt_packet(&h, &ct, &[]).is_ok(),
                "stream {stream_id} pn {pn} must be accepted by the single window"
            );
            pn += 1;
        }
    }
    // Replaying an earlier packet number is now a duplicate.
    let h_dup = PacketHeader::new(sid, 1, 0, PacketFlags::new(PacketFlags::ENCRYPTED));
    let ct_dup = client.encrypt_packet(&h_dup, b"x", &[]).expect("encrypt");
    assert!(
        matches!(
            server.decrypt_packet(&h_dup, &ct_dup, &[]),
            Err(phantom_protocol::CoreError::ReplayDetected(_))
        ),
        "a replayed packet_number must be rejected after AEAD verify (Inv-4)"
    );
}

// ── D8 (Phase 4): migration-switch congestion-controller reset ──────────────

/// `Session::reset_congestion` re-initialises the BBR controller so a migration
/// path switch (QUIC §9.4) measures the new network's bandwidth/cwnd fresh rather
/// than inheriting the dead path's estimate. (`RtoEstimator::reset` — the RTT
/// half — is unit-tested in `transport::stream::rto_tests`.)
#[test]
fn reset_congestion_returns_controller_to_initial() {
    let (s, _server) = make_session_pair([0x94u8; 32]);
    let (fresh, _f) = make_session_pair([0x95u8; 32]);
    let initial_cwnd = fresh.bandwidth_snapshot().cwnd_bytes;

    // Perturb the controller: register inflight + a loss.
    s.on_packet_sent(200_000);
    s.on_packet_lost(100_000);
    assert!(
        s.bandwidth_snapshot().inflight_bytes > 0,
        "precondition: on_packet_sent should register inflight bytes"
    );

    s.reset_congestion();

    let snap = s.bandwidth_snapshot();
    assert_eq!(snap.inflight_bytes, 0, "reset must clear inflight");
    assert_eq!(
        snap.cwnd_bytes, initial_cwnd,
        "reset must restore the initial cwnd"
    );
}

/// H-1 (audit 2026-06-11): the PhantomUDP demux `routes` map must not grow without
/// bound under a fresh-CID garbage spray. Each garbage `Initial` carries a new random
/// connection-ID and a payload that fails `ClientHello` parsing, so its handshake task
/// dies immediately and its route becomes dead. The demux must reap dead routes (with a
/// hard cap as a backstop), keeping `active_route_count()` bounded near the in-flight
/// ceiling rather than leaking one permanent entry per spoofed datagram.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn udp_demux_routes_map_is_bounded_under_fresh_cid_spray() {
    use phantom_protocol::api::udp_listener::PhantomUdpListener;
    use tokio::net::UdpSocket;

    const SPRAY: usize = 3000;
    // Far below SPRAY: a leak-per-datagram demux sits near SPRAY; a reaping one returns
    // to roughly the in-flight handshake ceiling (<= the 256 concurrency permits).
    const BOUND: usize = 512;

    let listener = PhantomUdpListener::bind_udp("127.0.0.1:0".to_string())
        .await
        .expect("bind_udp");
    let server_addr: std::net::SocketAddr = listener.local_addr().parse().unwrap();

    // accept() lazily starts the demux task. No garbage datagram completes a handshake,
    // so this never resolves — keep it pending in the background to drive the demux.
    let l = listener.clone();
    let _demux_pump = tokio::spawn(async move { l.accept().await });

    // Spray fresh-CID garbage Initials. Outer envelope = [flags=0x00 (Initial, unfragmented)]
    // ++ [cid: 8 bytes] ++ [inner frame]; the inner frame is garbage that fails ClientHello.
    let attacker = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    attacker.connect(server_addr).await.unwrap();
    for i in 0..SPRAY {
        let mut dg = Vec::with_capacity(20);
        dg.push(0x00u8); // Initial, not fragmented, reserved bits clear
        dg.extend_from_slice(&(i as u64).to_be_bytes()); // distinct 8-byte CID per datagram
        dg.extend_from_slice(b"not-a-clienthello"); // non-empty garbage -> borsh fails
        let _ = attacker.send(&dg).await;
        // Periodically yield so the single demux task keeps pace with the spray (otherwise
        // the loopback socket buffer just drops datagrams, which only weakens the attack).
        if i % 64 == 0 {
            tokio::task::yield_now().await;
        }
    }

    // The map must settle to a bounded size as the failed handshakes are reaped. Poll up to
    // ~5s; a leaking demux never drops to BOUND and the assertion fires.
    let mut observed = listener.active_route_count();
    for _ in 0..250 {
        observed = listener.active_route_count();
        if observed <= BOUND {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        observed <= BOUND,
        "demux routes leaked under fresh-CID spray: active_route_count()={observed} after \
         spraying {SPRAY} garbage Initials (expected <= {BOUND} once dead routes are reaped)"
    );
}

/// H-2 (audit 2026-06-11): on the connectionless UDP path a per-connection slot (an
/// `inflight` permit + a demux route + a handshake task that can hold the permit for up to
/// HANDSHAKE_DEADLINE) must NOT be committed to a source that has not proven it can receive
/// at its claimed address. The demux must run the stateless cookie/Retry round itself and
/// allocate a slot only once a valid address-validation cookie echoes back. A spray of
/// cookie-less (but otherwise borsh-valid) ClientHellos — exactly what a spoofed source can
/// cheaply send — must therefore allocate ZERO slots, so legitimate connects are never
/// locked out by pinned permits.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn udp_cookieless_initials_get_no_slot_until_address_validated() {
    use phantom_protocol::api::udp_listener::PhantomUdpListener;
    use phantom_protocol::transport::handshake::HandshakeClient;
    use phantom_protocol::transport::phantom_udp::datagram::encode_datagrams;
    use phantom_protocol::transport::phantom_udp::envelope::PacketType;
    use tokio::net::UdpSocket;

    const SPRAY: usize = 400; // > the 256 inflight permits

    let listener = PhantomUdpListener::bind_udp("127.0.0.1:0".to_string())
        .await
        .expect("bind_udp");
    let server_addr: std::net::SocketAddr = listener.local_addr().parse().unwrap();
    let l = listener.clone();
    let _demux_pump = tokio::spawn(async move { l.accept().await });

    // One real first-flight ClientHello (cookie = None), serialized once and sprayed under
    // many fresh CIDs — a borsh-valid hello with no cookie, exactly what a spoofer sends. A
    // real PQ ClientHello (~6 KB) exceeds the path MTU, so it must be sent as the same
    // multi-datagram fragmentation the demux reassembles for a genuine client.
    let hello = HandshakeClient::new()
        .expect("client")
        .create_client_hello();
    assert!(
        hello.cookie.is_none(),
        "a first-flight hello must carry no cookie"
    );
    let hello_bytes = borsh::to_vec(&hello).expect("serialize hello");

    let attacker = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    attacker.connect(server_addr).await.unwrap();
    for i in 0..SPRAY {
        let cid: [u8; 8] = (i as u64).to_be_bytes(); // distinct CID per connection attempt
        let dgrams = encode_datagrams(PacketType::Initial, &cid, 0, &hello_bytes).expect("encode");
        for d in &dgrams {
            let _ = attacker.send(d).await;
        }
        if i % 16 == 0 {
            tokio::task::yield_now().await;
        }
    }

    // A slot-allocating demux climbs to the 256-permit ceiling and pins those permits for
    // HANDSHAKE_DEADLINE; an address-validating demux commits nothing for a cookie-less hello.
    let mut peak = 0usize;
    for _ in 0..100 {
        peak = peak.max(listener.active_route_count());
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(
        peak, 0,
        "cookie-less Initials must allocate no demux slots (saw {peak} routes); the demux must \
         answer the cookie round statelessly before committing any per-connection slot"
    );
}

/// H-3 (audit 2026-06-11): the per-stream out-of-order reorder buffer must be bounded by
/// BYTES, not just entries. A peer that leaves the head (offset 0) missing and streams future
/// segments must not pin unbounded receiver RAM — each entry can be ~253 KiB (UDP) / 4 MiB
/// (TCP), and a future hole is never counted against flow control (only delivered data is).
/// Once the per-stream byte budget is reached, further future holes are refused (dropped →
/// retransmitted, which the "refused segment is not SACKed" contract already handles), so the
/// reorder buffer is byte-bounded.
#[tokio::test]
async fn reorder_buffer_is_byte_bounded_when_the_head_is_missing() {
    let stream = Stream::new(0);
    let chunk = Bytes::from(vec![0u8; 4096]); // 4 KiB per future segment
                                              // A peer that never sends offset 0 floods future offsets 1.. (each held for reassembly).
    for off in 1u32..2000 {
        let _ = stream.accept_in_order(off, vec![chunk.clone()]).await;
    }
    let buffered = stream.recv_reorder_bytes();
    assert!(
        buffered <= 256 * 1024,
        "reorder buffer must be byte-bounded under a missing head: held {buffered} B (≈{} KiB) \
         — a per-stream byte budget must refuse future holes past the window",
        buffered / 1024
    );
}

/// Idle keep-alive (Direction #3) is invariant-safe: a keep-alive packet is
/// `ENCRYPTED | KEEPALIVE` with an **empty** payload, so it
///  (1) carries the post-handshake `ENCRYPTED` invariant flag (Inv-2 — the recv
///      path drops every unencrypted post-handshake packet, including empty ones),
///  (2) is AEAD-authenticated (the empty plaintext seals to a bare tag and opens
///      back to empty — an off-path peer cannot forge one),
///  (3) draws a per-direction packet number like any other packet, so a replayed
///      keep-alive is rejected by the sliding replay window **after** AEAD verify
///      (Inv-4) — it can neither reset a liveness timer nor be reused as a nonce.
/// The `KEEPALIVE` flag is a distinct spare bit (`0x1000`) that overlaps no
/// existing flag, so adding it changed no existing wire encoding.
#[test]
fn idle_keepalive_is_encrypted_authenticated_and_replay_protected() {
    use phantom_protocol::CoreError;

    // (1) The KEEPALIVE bit is a fresh spare bit — it collides with no other flag.
    for other in [
        PacketFlags::RELIABLE,
        PacketFlags::ACK,
        PacketFlags::FIN,
        PacketFlags::UNRELIABLE,
        PacketFlags::PRIORITY,
        PacketFlags::ENCRYPTED,
        PacketFlags::COMPRESSED,
        PacketFlags::CONTROL,
        PacketFlags::REKEY,
        PacketFlags::PATH_VALIDATION,
        PacketFlags::COALESCED,
        PacketFlags::WINDOW_UPDATE,
    ] {
        assert_eq!(
            PacketFlags::KEEPALIVE & other,
            0,
            "KEEPALIVE (0x{:04x}) must not overlap an existing flag (0x{other:04x})",
            PacketFlags::KEEPALIVE
        );
    }

    let (client, server) = make_session_pair([0x5Au8; 32]);
    // A keep-alive: ENCRYPTED | KEEPALIVE, empty payload, drawn at a real PN.
    let pn = client.next_send_pn();
    let header = PacketHeader::new(
        *server.id(),
        1,
        pn,
        PacketFlags::new(PacketFlags::ENCRYPTED | PacketFlags::KEEPALIVE),
    )
    .with_epoch(client.current_epoch());
    // (1) it carries ENCRYPTED.
    assert!(
        header.flags.contains(PacketFlags::ENCRYPTED),
        "a keep-alive must be ENCRYPTED (Inv-2 downgrade defense)"
    );

    // (2) it AEAD-seals an empty payload and opens back to empty — authenticated.
    let ct = client
        .encrypt_packet(&header, &[], &[])
        .expect("seal keep-alive");
    let pt = server
        .decrypt_packet(&header, &ct, &[])
        .expect("authenticated keep-alive opens");
    assert!(pt.is_empty(), "a keep-alive carries no application bytes");

    // (3) a replayed keep-alive (same PN) is rejected AFTER AEAD verify (Inv-4).
    let replay = server.decrypt_packet(&header, &ct, &[]);
    assert!(
        matches!(replay, Err(CoreError::ReplayDetected(_))),
        "a replayed keep-alive must be rejected by the replay window (Inv-4); got {replay:?}"
    );
}

/// T5.5 (audit recv-counter-on-fail LOW): a FAILED AEAD open must NOT advance the per-direction
/// recv invocation counter. Otherwise a stream of forged same-epoch packets drives the counter
/// toward the `AEAD_MAX_INVOCATIONS` (2^48) `NonceExhausted` ceiling — only a successful,
/// authenticated decryption should count. (Matches `decrypt_with_nonce`'s own doc contract.)
#[test]
fn failed_decrypt_does_not_advance_recv_invocation_counter() {
    let secret = [0x77u8; 32];
    let session = CryptoSession::with_suite(&secret, CipherSuite::Aes256Gcm).expect("session");
    let before = session.recv_invocations();

    // A forged ciphertext (garbage) with a well-formed nonce fails the tag check.
    let forged = vec![0u8; 48];
    assert!(
        session
            .decrypt_with_nonce([0u8; 12], b"aad", &forged)
            .is_err(),
        "a forged ciphertext must fail to decrypt"
    );
    assert_eq!(
        session.recv_invocations(),
        before,
        "a failed AEAD open must not advance the recv invocation counter (T5.5)"
    );
}
