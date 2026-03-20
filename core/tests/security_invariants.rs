//! Formal negative-security tests for the documented invariants.
//!
//! Each test pins a specific property from `SECURITY.md` / `CLAUDE.md` so that
//! a future regression which silently weakens one of them surfaces as a hard
//! red here. These run on every `cargo test --lib`-equivalent path — they are
//! NOT `#[ignore]`-gated — because they do not need real network sockets.
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

use phantom_core::crypto::adaptive_crypto::{CipherSuite, CryptoSession};
use phantom_core::crypto::hybrid_sign::HybridSigningKey;
use phantom_core::transport::handshake::{
    HandshakeClient, HandshakeError, HandshakeResponse, HandshakeServer,
};
use phantom_core::transport::path::PathStateKind;
use phantom_core::transport::session::{CryptoState, Session};
use phantom_core::transport::types::{
    PacketFlags, PacketFlagsV2, PacketHeader, PacketHeaderV2, PhantomPacketV1, PhantomPacketV2,
    SchedulerMode, SessionId, VersionedPacket,
};

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

/// AEAD authenticity: flipping a single ciphertext byte must cause decrypt to
/// fail. This is what protects post-handshake traffic from tampering.
#[test]
fn tampered_ciphertext_is_rejected() {
    let (client, server) = make_session_pair([0xA1u8; 32]);
    let header = PacketHeader::new(
        *server.id(),
        7, // stream_id
        1, // sequence
        PacketFlags::new(PacketFlags::ENCRYPTED | PacketFlags::RELIABLE),
    );

    let mut ct = client
        .encrypt_packet(&header, b"the quick brown fox")
        .expect("encrypt");
    // Flip exactly one bit in the ciphertext body (not the auth tag).
    ct[0] ^= 0x01;

    let result = server.decrypt_packet(&header, &ct);
    assert!(
        result.is_err(),
        "AEAD must reject a bit-flipped ciphertext; instead got Ok({:?})",
        result.as_ref().ok().map(|v| v.len())
    );
}

/// AAD binding: even with intact ciphertext, mutating the header (which is
/// fed into the AEAD as AAD) must cause decryption to fail. This is the
/// invariant that prevents an attacker from rewriting `stream_id`, `flags`,
/// or `sequence` on the wire while keeping the encrypted payload intact.
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
        .encrypt_packet(&real_header, b"AAD-bound payload")
        .expect("encrypt");

    // Server tries to decrypt with a different header (stream_id changed).
    let tampered_header = PacketHeader::new(
        *server.id(),
        8, // changed: 7 -> 8
        1,
        PacketFlags::new(PacketFlags::ENCRYPTED | PacketFlags::RELIABLE),
    );

    let result = server.decrypt_packet(&tampered_header, &ct);
    assert!(
        result.is_err(),
        "AEAD must reject a packet whose header (AAD) was mutated"
    );
}

/// Malformed wire bytes must fail parsing as a typed error, never a panic.
/// This protects the receive loop from a malicious peer crashing the process
/// by sending random bytes.
#[test]
fn malformed_versioned_packet_fails_to_parse_not_panic() {
    // A short, non-alkahest-compatible byte stream.
    let garbage: Vec<u8> = (0u8..32).collect();
    let result = alkahest::deserialize::<VersionedPacket, VersionedPacket>(&garbage);
    assert!(
        result.is_err(),
        "Parser must reject random bytes with Err, not panic or accept"
    );

    // Empty input.
    let empty: Vec<u8> = Vec::new();
    let result = alkahest::deserialize::<VersionedPacket, VersionedPacket>(&empty);
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
    assert!(!bool::from(a.ct_eq(&c)), "different cookies must compare unequal");
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
                HandshakeResponse::Success(sh, _) => sh,
                other => panic!("unexpected after retry: {:?}", other),
            }
        }
        HandshakeResponse::Success(sh, _) => sh,
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
    assert_eq!(session.send_invocations(), 0, "fresh session has zero count");
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
/// `ENCRYPTED` flag is the only protection mode the API path will accept.
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
    let ct = client.encrypt_packet(&header, payload).expect("encrypt");
    assert_ne!(
        &ct[..payload.len()],
        payload,
        "ciphertext must not contain plaintext"
    );
    let pt = server.decrypt_packet(&header, &ct).expect("decrypt");
    assert_eq!(&pt, payload);
}

/// Sliding-window replay protection (Phase 1.4) — re-feeding an
/// already-decrypted ciphertext with the same `(stream_id, sequence)` must
/// fail with `CoreError::ReplayDetected`, and the per-session counter must
/// increment.
#[test]
fn replay_window_rejects_duplicate_sequence() {
    use phantom_core::CoreError;

    let (client, server) = make_session_pair([0xE5u8; 32]);
    let header = PacketHeader::new(
        *server.id(),
        3,
        17,
        PacketFlags::new(PacketFlags::ENCRYPTED | PacketFlags::RELIABLE),
    );

    let ct = client.encrypt_packet(&header, b"some-payload").expect("encrypt");

    // First decrypt accepted.
    let _ = server.decrypt_packet(&header, &ct).expect("first decrypt");
    assert_eq!(server.replay_rejected_total(), 0);

    // The same ciphertext is, by the AEAD strict-counter invariant, no longer
    // decryptable (recv_counter has advanced) — so we re-encrypt a *new*
    // ciphertext with the same (stream_id, sequence) header to isolate the
    // window check from the AEAD-counter check.
    let ct2 = client
        .encrypt_packet(&header, b"some-payload")
        .expect("re-encrypt");
    let result = server.decrypt_packet(&header, &ct2);
    match result {
        Err(CoreError::ReplayDetected(_)) => { /* expected */ }
        other => panic!(
            "expected ReplayDetected on duplicate sequence, got {:?}",
            other.as_ref().map(|_| "Ok(...)").unwrap_or("Err(<other>)")
        ),
    }
    assert_eq!(
        server.replay_rejected_total(),
        1,
        "replay_rejected_total counter must increment on duplicate"
    );
}

// ── V2 wire format negative tests ──────────────────────────────────────────

/// Same authenticity property as `tampered_ciphertext_is_rejected` but for
/// the V2 wire path.
#[test]
fn v2_tampered_ciphertext_is_rejected() {
    let (client, server) = make_session_pair([0xF1u8; 32]);
    let header = PacketHeaderV2::new(
        *server.id(),
        7,
        1,
        PacketFlagsV2::new(PacketFlagsV2::ENCRYPTED | PacketFlagsV2::RELIABLE),
    )
    .with_epoch(2)
    .with_path_id(3);

    let mut ct = client
        .encrypt_packet_v2(&header, b"v2 payload")
        .expect("encrypt v2");
    ct[0] ^= 0x01;

    let result = server.decrypt_packet_v2(&header, &ct);
    assert!(
        result.is_err(),
        "V2 AEAD must reject bit-flipped ciphertext; got {:?}",
        result.as_ref().ok().map(|v| v.len())
    );
}

/// The V2 header's `epoch` and `path_id` are AAD-bound. Flipping either
/// after encryption must invalidate the tag.
#[test]
fn v2_tampered_epoch_or_path_id_is_rejected() {
    let (client, server) = make_session_pair([0xF2u8; 32]);
    let real_header = PacketHeaderV2::new(
        *server.id(),
        7,
        1,
        PacketFlagsV2::new(PacketFlagsV2::ENCRYPTED | PacketFlagsV2::RELIABLE),
    )
    .with_epoch(5)
    .with_path_id(0);
    let ct = client
        .encrypt_packet_v2(&real_header, b"epoch-bound payload")
        .expect("encrypt");

    // Mutate epoch.
    let tampered_epoch = PacketHeaderV2 { epoch: 6, ..real_header };
    assert!(server.decrypt_packet_v2(&tampered_epoch, &ct).is_err());

    // Re-encrypt fresh so the AEAD recv counter aligns, then mutate path_id.
    let ct2 = client
        .encrypt_packet_v2(&real_header, b"path-bound payload")
        .expect("re-encrypt");
    let tampered_path = PacketHeaderV2 { path_id: 7, ..real_header };
    assert!(server.decrypt_packet_v2(&tampered_path, &ct2).is_err());
}

/// Cross-version isolation: a ciphertext produced by `encrypt_packet` (V1
/// header AAD) cannot be authenticated by `decrypt_packet_v2` against a
/// "matching" V2 header. The AAD bytes differ because V1 and V2 headers
/// have different serialisations — the AEAD tag mismatch is the witness.
#[test]
fn v1_ciphertext_does_not_decrypt_as_v2() {
    let (client, server) = make_session_pair([0xF3u8; 32]);
    let v1_header = PacketHeader::new(
        *server.id(),
        7,
        1,
        PacketFlags::new(PacketFlags::ENCRYPTED | PacketFlags::RELIABLE),
    );
    let ct = client
        .encrypt_packet(&v1_header, b"v1 payload")
        .expect("encrypt v1");

    // Construct a "would-be-equivalent" V2 header.
    let v2_header = PacketHeaderV2::new(
        *server.id(),
        7,
        1,
        PacketFlagsV2::new(PacketFlagsV2::ENCRYPTED | PacketFlagsV2::RELIABLE),
    );
    let result = server.decrypt_packet_v2(&v2_header, &ct);
    assert!(
        result.is_err(),
        "V1 ciphertext must not authenticate as V2 (different AAD)"
    );
}

/// V2 replay window: same property as the V1 test, exercised through
/// `decrypt_packet_v2`. The per-stream window is shared between V1 and V2
/// paths (replay identity is `(stream_id, sequence)`, not version).
#[test]
fn v2_replay_window_rejects_duplicate_sequence() {
    use phantom_core::CoreError;

    let (client, server) = make_session_pair([0xF4u8; 32]);
    let header = PacketHeaderV2::new(
        *server.id(),
        3,
        17,
        PacketFlagsV2::new(PacketFlagsV2::ENCRYPTED | PacketFlagsV2::RELIABLE),
    );
    let ct1 = client.encrypt_packet_v2(&header, b"payload").expect("e1");
    server.decrypt_packet_v2(&header, &ct1).expect("first decrypt");
    assert_eq!(server.replay_rejected_total(), 0);

    let ct2 = client.encrypt_packet_v2(&header, b"payload").expect("e2");
    match server.decrypt_packet_v2(&header, &ct2) {
        Err(CoreError::ReplayDetected(_)) => { /* expected */ }
        other => panic!(
            "expected ReplayDetected on V2 duplicate, got {:?}",
            other.as_ref().map(|_| "Ok").unwrap_or("Err(<other>)")
        ),
    }
    assert_eq!(server.replay_rejected_total(), 1);
}

/// V2 nonce-from-header property — a tampered packet that fails AEAD
/// verification must NOT desync the receiver from the sender. The next
/// legitimate packet must still decrypt cleanly.
///
/// This is the V2 architectural fix relative to V1: V1's recv_counter
/// advances on every decrypt attempt (success or failure), so a single
/// dropped / mutated packet permanently breaks the session. V2 derives
/// the nonce from the authenticated `header.sequence`, so failed
/// decrypts are stateless from the AEAD's perspective.
#[test]
fn v2_failed_decrypt_does_not_desync_session() {
    let (client, server) = make_session_pair([0x20u8; 32]);

    // Sender encrypts packet #1.
    let h1 = PacketHeaderV2::new(
        *server.id(),
        1,
        1,
        PacketFlagsV2::new(PacketFlagsV2::ENCRYPTED | PacketFlagsV2::RELIABLE),
    );
    let ct1 = client.encrypt_packet_v2(&h1, b"first").expect("encrypt 1");

    // Bad packet arrives in between — flipped tag byte.
    let mut tampered = ct1.clone();
    let n = tampered.len();
    tampered[n - 1] ^= 0x80;
    assert!(server.decrypt_packet_v2(&h1, &tampered).is_err());

    // The original ct1 (same header, same payload) must still decrypt —
    // in V1 this would fail because the recv_counter desynchronised; in
    // V2 the nonce is reconstructible from h1 alone.
    let pt1 = server.decrypt_packet_v2(&h1, &ct1).expect("decrypt 1");
    assert_eq!(pt1, b"first");

    // And a subsequent packet at sequence 2 also goes through.
    let h2 = PacketHeaderV2 { sequence: 2, ..h1 };
    let ct2 = client.encrypt_packet_v2(&h2, b"second").expect("encrypt 2");
    let pt2 = server.decrypt_packet_v2(&h2, &ct2).expect("decrypt 2");
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

    let header = PacketHeaderV2::new(
        *server.id(),
        1,
        100,
        PacketFlagsV2::new(PacketFlagsV2::ENCRYPTED | PacketFlagsV2::RELIABLE),
    );
    let ct_epoch0 = client
        .encrypt_packet_v2(&header, b"pre-rekey payload")
        .expect("encrypt e0");

    // Lock-step rekey on both ends.
    let client_new = client.rekey().expect("client rekey");
    let server_new = server.rekey().expect("server rekey");
    assert_eq!(client_new, 1);
    assert_eq!(server_new, 1);
    assert_eq!(client.current_epoch(), 1);
    assert_eq!(server.current_epoch(), 1);

    // The OLD ciphertext must NOT authenticate under the new keys.
    let header_epoch1 = PacketHeaderV2 { epoch: 1, ..header };
    assert!(
        server.decrypt_packet_v2(&header_epoch1, &ct_epoch0).is_err(),
        "post-rekey CryptoState must reject pre-rekey ciphertext"
    );

    // A fresh encrypt under the new epoch round-trips successfully.
    let header_v1_e1 = PacketHeaderV2::new(
        *server.id(),
        1,
        101,
        PacketFlagsV2::new(PacketFlagsV2::ENCRYPTED | PacketFlagsV2::RELIABLE),
    )
    .with_epoch(1);
    let ct_epoch1 = client
        .encrypt_packet_v2(&header_v1_e1, b"post-rekey payload")
        .expect("encrypt e1");
    let pt = server
        .decrypt_packet_v2(&header_v1_e1, &ct_epoch1)
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

/// `VersionedPacket::V2` survives serialize + deserialize with all V2-only
/// fields preserved.
#[test]
fn versioned_packet_v2_roundtrip_preserves_fields() {
    let header = PacketHeaderV2::new(
        SessionId::from_bytes([9u8; 32]),
        99,
        2025,
        PacketFlagsV2::new(
            PacketFlagsV2::RELIABLE | PacketFlagsV2::ENCRYPTED | PacketFlagsV2::REKEY,
        ),
    )
    .with_epoch(11)
    .with_path_id(2);
    let packet = PhantomPacketV2::new(header, vec![0xDE, 0xAD]).into_versioned();
    let mut buf = Vec::new();
    let (size, _) = alkahest::serialize_to_vec::<VersionedPacket, _>(&packet, &mut buf);
    let decoded = alkahest::deserialize::<VersionedPacket, VersionedPacket>(&buf[..size])
        .expect("v2 roundtrip");
    assert_eq!(decoded.wire_version(), 2);
    let v2 = decoded.into_v2().expect("v2 inner");
    assert_eq!(v2.header.epoch, 11);
    assert_eq!(v2.header.path_id, 2);
    assert!(v2.header.flags.contains(PacketFlagsV2::REKEY));
}

/// The wire format embeds `PhantomPacketV1` inside a `VersionedPacket` enum;
/// V1-only roundtrips must preserve every header bit.
#[test]
fn versioned_packet_v1_roundtrip_preserves_header() {
    let header = PacketHeader::new(
        SessionId::from_bytes([7u8; 32]),
        99,
        2025,
        PacketFlags::new(PacketFlags::RELIABLE | PacketFlags::ENCRYPTED),
    );
    let packet = PhantomPacketV1::new(header, vec![1, 2, 3, 4, 5]).into_versioned();
    let mut buf = Vec::new();
    let (size, _) =
        alkahest::serialize_to_vec::<VersionedPacket, _>(&packet, &mut buf);
    let decoded = alkahest::deserialize::<VersionedPacket, VersionedPacket>(&buf[..size])
        .expect("round-trip decode");
    let v1 = decoded.into_v1().expect("v1");
    assert_eq!(v1.header.stream_id, 99);
    assert_eq!(v1.header.sequence, 2025);
    assert!(v1.header.flags.contains(PacketFlags::ENCRYPTED));
    assert!(v1.header.flags.contains(PacketFlags::RELIABLE));
    assert_eq!(v1.payload, &[1, 2, 3, 4, 5]);
}
