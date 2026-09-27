//! Formal negative-security tests for the documented invariants.
//!
//! "Invariant N" below refers to the numbered list in `docs/security/invariants.md`, which
//! states each invariant, where it is enforced, and which tests here pin it. Each test pins a
//! specific property from that list or from `docs/security/threat-model.md` so that a future
//! regression which silently weakens one of them surfaces as a hard red here. These run on
//! every `cargo test --test security_invariants` path — they are NOT `#[ignore]`-gated. Most
//! are pure (no sockets); the PhantomUDP pre-auth DoS-bound tests bind a loopback `UdpSocket`
//! (fast + deterministic).
//!
//! Coverage map:
//!   - AEAD authenticated decryption rejects bit-flipped ciphertext.
//!   - AEAD AAD-binding: a tampered `PacketHeader` (used as AAD) is rejected
//!     even if the ciphertext bytes are intact.
//!   - The receive path drops a forged unencrypted post-handshake packet
//!     (Invariant 2), driven through a live session's pump.
//!   - Malformed wire bytes are rejected as a typed parse error, not a panic.
//!   - The handshake cookie path uses constant-time equality (smoke check).
//!   - Server identity mismatch fails the handshake at the client side.
//!   - The per-direction AEAD invocation counter — the input to the
//!     `AEAD_MAX_INVOCATIONS` ceiling — advances once per successful operation
//!     and not at all on a failed open. The ceiling itself (2^48) is not
//!     reachable from a test; what is pinned here is the counter feeding it.
//!   - Cookie tampering yields a `Retry` (not `Success`) on the server side.

// Tests `.unwrap()` freely so failures surface as readable diagnostics; the
// disallowed-methods list in `.clippy.toml` is for production code, not the test
// harness. (Integration-test crates are their own crate and therefore do not
// inherit `core/src/lib.rs`'s `#![cfg_attr(test, allow(...))]`.)
#![allow(clippy::disallowed_methods)]

use bytes::Bytes;
use phantom_protocol::api::session::{
    DELIVERY_ITEM_OVERHEAD_BYTES, RECV_DELIVERY_HARD_CAP, STREAM_RECV_CHANNEL_DEPTH,
};
use phantom_protocol::crypto::adaptive_crypto::{CipherSuite, CryptoSession, AEAD_OVERHEAD};
use phantom_protocol::crypto::hybrid_sign::{HybridSigningKey, HybridVerifyingKey};
use phantom_protocol::transport::handshake::{
    ClientHello, HandshakeClient, HandshakeError, HandshakeResponse, HandshakeServer, ServerHello,
    PROTOCOL_VERSION, REJECT_UNSUPPORTED_VERSION,
};
use phantom_protocol::transport::mtu::MAX_RECV_PAYLOAD;
use phantom_protocol::transport::multiplexer::{StreamDemultiplexer, StreamMessage};
use phantom_protocol::transport::path::PathStateKind;
use phantom_protocol::transport::session::{
    CryptoState, Session, MAX_REKEY_CATCHUP, REBIND_VALIDATION_PATH_ID,
};
use phantom_protocol::transport::shaping::{self, PaddingPolicy, MAX_SHAPED_WIRE};
use phantom_protocol::transport::stream::{
    SendBlocked, SharedRecvTuning, Stream, INITIAL_STREAM_WINDOW, MAX_RECV_REORDER,
    MAX_RECV_WINDOW, REORDER_ENTRY_OVERHEAD_BYTES, SESSION_RECV_WINDOW_GROWTH_BUDGET,
};
use phantom_protocol::transport::types::{
    ControlSubtype, PacketFlags, PacketHeader, PhantomPacket, SchedulerMode, SessionId,
    WIRE_VERSION,
};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::Arc;
use std::time::Duration;

// ── Heap accounting ────────────────────────────────────────────────────────
//
// The receive-memory tests below are the only place in this suite that asserts a
// *quantity* rather than a behaviour, and a quantity asserted against the expression it
// came from proves nothing. So they measure: this allocator reports live heap bytes, and
// each published per-buffer figure is checked against what that buffer is observed to take
// when it is driven to its own cap.
//
// The counter is per thread, not global, so a measurement is unaffected by whatever the
// other tests in this binary are allocating in parallel. Measured regions therefore keep
// all of their work on the calling thread (`flavor = "current_thread"`).

thread_local! {
    /// Live heap bytes attributed to this thread. `const`-initialised and destructor-free
    /// so that touching it from inside the allocator cannot itself allocate or recurse.
    static LIVE_HEAP: Cell<isize> = const { Cell::new(0) };
}

struct AccountingAllocator;

// SAFETY: every method forwards to `System` unchanged; the added work is a `Cell` update on
// a `const`-initialised, destructor-free thread-local, which allocates nothing and so cannot
// re-enter the allocator. `try_with` tolerates the window during thread teardown when the
// thread-local is no longer accessible.
unsafe impl GlobalAlloc for AccountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let _ = LIVE_HEAP.try_with(|c| c.set(c.get() + layout.size() as isize));
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let _ = LIVE_HEAP.try_with(|c| c.set(c.get() + layout.size() as isize));
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let _ = LIVE_HEAP.try_with(|c| c.set(c.get() - layout.size() as isize));
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let _ = LIVE_HEAP.try_with(|c| c.set(c.get() - layout.size() as isize + new_size as isize));
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static HEAP: AccountingAllocator = AccountingAllocator;

/// Live heap bytes this thread currently holds.
fn live_heap() -> isize {
    LIVE_HEAP.with(|c| c.get())
}

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

/// Header protection (QUIC RFC 9001 §5.4) masks the header bytes so a passive
/// on-path observer reads neither the packet number nor the `PRIORITY` ("voice")
/// flag. **WIRE v6 (anti-fingerprint):** the masked region is the WHOLE 15-byte
/// header `[0..15]` — the `version` byte is masked too, so there is no constant
/// cleartext byte to fingerprint (session_id is off-wire; routing is by the outer
/// ConnId). The peer recovers the exact packet via `parse_protected`.
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

    // The whole 15-byte header region [0..15] is masked → not the cleartext bytes.
    assert_ne!(
        &wire[0..15],
        &cleartext[0..15],
        "version/pn/flags/stream_id/epoch/path_id must all be masked on the wire"
    );
    // v6: the version byte is masked too — no constant cleartext fingerprint.
    assert_ne!(
        wire[0], cleartext[0],
        "the version byte must be masked on the v6 wire"
    );
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
/// cleartext-session_id binding (`docs/protocol/PROTOCOL.md` § 4.2).
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

/// ε / WIRE v5 — the rotating-CID chain is wired into `Session`: the
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

/// ε / WIRE v5 — `migrate()` rotates the outbound CID: `advance_outbound_cid`
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

/// ε / WIRE v5 — the server slides its inbound CID window as the client
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

/// **Invariant 8, the reachable half.** The `AEAD_MAX_INVOCATIONS` ceiling is
/// checked against a per-direction counter, and this pins that the counter is
/// real: it starts at zero, advances once per encrypt, and is readable through
/// the API the check itself reads.
///
/// It does not reach the ceiling and does not claim to. Driving a counter to
/// 2^48 is roughly nine years of packets, and no test in this repository takes
/// the `NonceExhausted` branch — it is held by inspection of the five sites in
/// `crypto/adaptive_crypto.rs` that compare against the limit, and nothing more.
/// The complement that *is* driven is
/// `failed_decrypt_does_not_advance_recv_invocation_counter`, the property an
/// attacker could otherwise abuse: a forged packet must not push anyone toward
/// the ceiling.
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

/// Replay window: re-feeding a fresh ciphertext that reuses an already-accepted
/// packet number must fail with `CoreError::ReplayDetected`, and the per-session
/// counter must increment. There is one window per direction, keyed on the u64
/// `packet_number` alone — not per stream, and independent of epoch and path_id;
/// `per_direction_window_accepts_interleaved_streams` is the test for that half.
///
/// What this does not establish is the *ordering* against the AEAD open (the other
/// half of Invariant 4). The replayed ciphertext here is freshly sealed and opens
/// cleanly, so a window consulted before the open would reject it identically. The
/// ordering is a property of `Session::decrypt_packet`'s structure.
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

/// WIRE v6 (c) — anti-fingerprint size padding lives INSIDE the AEAD: a padded
/// packet's plaintext gains a `‹zeros› ‖ pad_n:u16be` trailer before sealing, so
/// (1) the padding is encrypted — a network observer sees only ciphertext, never
/// the inner payload length, and (2) the on-wire packet lands on a PADÉ bucket.
/// The receiver decrypts then strips the trailer to recover the EXACT inner bytes.
#[test]
fn size_padding_is_inside_the_aead_and_strips_to_inner() {
    let (client, server) = make_session_pair([0x90u8; 32]);
    let inner = b"application data of some particular, fingerprintable length".to_vec();

    // Pad as the send path does: compute the trailer, append it, flag PADDED.
    let trailer = shaping::padding_trailer_len(inner.len(), PaddingPolicy::Padme);
    assert!(trailer >= 2, "a small packet must be padded to a bucket");
    let mut pt = inner.clone();
    shaping::append_padding(&mut pt, trailer);

    let header = PacketHeader::new(
        *server.id(),
        1,
        1,
        PacketFlags::new(PacketFlags::ENCRYPTED | PacketFlags::PADDED),
    );
    let ct = client
        .encrypt_packet(&header, &pt, &[])
        .expect("encrypt padded");

    // (1) The ciphertext covers the padded plaintext — the padding is inside the
    // AEAD, not appended in the clear. The on-wire packet size is a PADÉ bucket.
    let wire = PhantomPacket::new(header, ct.clone()).to_wire();
    let expected =
        shaping::padme(PacketHeader::SIZE + inner.len() + AEAD_OVERHEAD + 2).min(MAX_SHAPED_WIRE);
    assert_eq!(
        wire.len(),
        expected,
        "padded wire size lands on a PADÉ bucket"
    );
    // The cleartext inner bytes never appear on the wire (only ciphertext does).
    assert!(
        !wire.windows(inner.len()).any(|w| w == inner.as_slice()),
        "inner plaintext must not appear on the wire"
    );

    // (2) The receiver decrypts then strips → exactly the inner bytes back.
    let dec = server
        .decrypt_packet(&header, &ct, &[])
        .expect("decrypt padded");
    let stripped = shaping::strip_padding(&dec).expect("strip padding");
    assert_eq!(
        stripped,
        &inner[..],
        "strip recovers the exact inner plaintext"
    );
}

/// WIRE v6 (c) — the `PADDED` flag is AEAD-AAD-bound: it rides in the header image
/// that is the AEAD AAD, so an attacker cannot flip it to make the receiver
/// mis-strip (or skip stripping) a packet. Flipping PADDED after sealing fails the
/// AEAD open, exactly like any other header tamper — no padding-specific oracle.
#[test]
fn padded_flag_is_aead_bound() {
    let (client, server) = make_session_pair([0x91u8; 32]);
    let inner = b"padded payload".to_vec();
    let trailer = shaping::padding_trailer_len(inner.len(), PaddingPolicy::Padme);
    let mut pt = inner.clone();
    shaping::append_padding(&mut pt, trailer);

    let padded_header = PacketHeader::new(
        *server.id(),
        1,
        1,
        PacketFlags::new(PacketFlags::ENCRYPTED | PacketFlags::PADDED),
    );
    let ct = client
        .encrypt_packet(&padded_header, &pt, &[])
        .expect("encrypt");

    // Attacker clears the PADDED bit in the header used as AAD → wrong AAD → fail.
    let stripped_flag = PacketHeader {
        flags: PacketFlags::new(PacketFlags::ENCRYPTED),
        ..padded_header
    };
    assert!(
        server.decrypt_packet(&stripped_flag, &ct, &[]).is_err(),
        "clearing the AEAD-bound PADDED flag must fail the open"
    );
    // The genuine PADDED header still opens (no desync from the failed attempt).
    assert!(server.decrypt_packet(&padded_header, &ct, &[]).is_ok());
}

/// WIRE v6 (e) — a COVER (cover-traffic) packet is built like a real packet
/// (ENCRYPTED, PADÉ-padded to a bucket) but carries an EMPTY inner plaintext, and
/// the `COVER` flag is AEAD-AAD-bound. So (1) it authenticates exactly like a data
/// packet (an off-path attacker cannot inject one), (2) after decrypt + strip its
/// inner plaintext is empty — there is no data to leak even if the recv-side drop
/// were missed — and (3) flipping the COVER flag fails the AEAD open (no oracle to
/// turn a data packet into a "dropped" one or vice-versa).
#[test]
fn cover_packet_is_authenticated_padded_and_carries_no_data() {
    let (client, server) = make_session_pair([0x92u8; 32]);

    // Build a cover packet the way `send_cover` does: empty plaintext, PADÉ-padded,
    // flagged ENCRYPTED | COVER | PADDED.
    let trailer = shaping::padding_trailer_len(0, PaddingPolicy::Padme);
    let mut pt = Vec::new();
    shaping::append_padding(&mut pt, trailer);
    let cover_header = PacketHeader::new(
        *server.id(),
        1,
        1,
        PacketFlags::new(PacketFlags::ENCRYPTED | PacketFlags::COVER | PacketFlags::PADDED),
    );
    let ct = client
        .encrypt_packet(&cover_header, &pt, &[])
        .expect("encrypt cover");

    // The on-wire cover packet is a bucketed size (not a tiny tell), and decrypt +
    // strip yields an EMPTY inner plaintext.
    let wire = PhantomPacket::new(cover_header, ct.clone()).to_wire();
    assert!(
        wire.len() > PacketHeader::SIZE,
        "cover packet is padded, not a tiny tell"
    );
    let dec = server
        .decrypt_packet(&cover_header, &ct, &[])
        .expect("decrypt cover");
    let inner = shaping::strip_padding(&dec).expect("strip cover");
    assert!(
        inner.is_empty(),
        "a cover packet carries no application data"
    );

    // The COVER flag is AEAD-AAD-bound: clearing it fails the open.
    let no_cover = PacketHeader {
        flags: PacketFlags::new(PacketFlags::ENCRYPTED | PacketFlags::PADDED),
        ..cover_header
    };
    assert!(
        server.decrypt_packet(&no_cover, &ct, &[]).is_err(),
        "clearing the AEAD-bound COVER flag must fail the open"
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
//
// The four path-validation tests below pin the state-machine half of Invariant 6:
// a path is not trusted until it answers its own challenge, a wrong answer fails it
// for good, and an unchallenged path cannot be completed at all. They say nothing
// about the other half — that the comparison is constant-time. A functional test
// cannot: `subtle::ConstantTimeEq` and `==` agree on every input, so a rewrite to
// `==` would leave all four green. That half is held by code review, recorded in
// `docs/compliance/constant-time-audit.md`.

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

/// **A peer speaking an older protocol is refused, not left to stall.**
///
/// The data-plane version check drops a mismatched frame *silently*: nothing is logged to
/// the peer, no error is raised, the packet simply vanishes. That is the right behaviour for
/// a frame — an attacker must not learn anything from spraying them — and it is exactly why
/// a wire-format change cannot rely on `WIRE_VERSION` alone. An older peer would complete a
/// handshake, believe itself connected, and then sit with its packets disappearing: a stall
/// with no diagnosis, which is the failure mode a format change is normally made to remove.
///
/// So the handshake version moves with the wire version, and this pins both halves of that
/// argument: the hello is refused with a typed reject naming the version this build speaks,
/// **before** any KEM or signature work; and the packet-level check really is the silent
/// drop that makes the refusal necessary.
#[test]
fn an_older_peer_is_refused_at_the_handshake_rather_than_dropped_on_the_wire() {
    let server = HandshakeServer::new().unwrap();
    let client = HandshakeClient::new().unwrap();
    let client_ip = "127.0.0.1".parse().unwrap();

    let mut hello = client.create_client_hello();
    hello.version = PROTOCOL_VERSION - 1;

    match server.process_client_hello(&hello, 0, client_ip) {
        HandshakeResponse::Reject(reject) => {
            assert!(reject.has_marker(), "reject must carry the marker");
            assert_eq!(reject.code, REJECT_UNSUPPORTED_VERSION);
            assert_eq!(
                reject.supported_version, PROTOCOL_VERSION,
                "the reject must name the version this build speaks, or an operator \
                 reading it learns nothing actionable"
            );
        }
        other => panic!(
            "an older peer's hello was not refused with a typed reject: {other:?} — it \
             would have established a session and then stalled"
        ),
    }

    // The contrast that makes the bump load-bearing. The packet codec carries the version
    // byte but does not judge it: a frame at the previous wire version parses cleanly here,
    // and what refuses it is the receive loop's gate, whose only action is to skip the frame
    // — no reply, no error, nothing the peer can observe. So the version byte can tell a
    // receiver that a frame is foreign, and can tell the *sender* nothing at all; that is
    // the whole argument for refusing an older peer one layer earlier, at the handshake.
    let header = PacketHeader::new(
        SessionId::from_bytes([7u8; 32]),
        1,
        1,
        PacketFlags::new(PacketFlags::ENCRYPTED),
    );
    let mut wire = PhantomPacket::new(header, vec![0u8; 32]).to_wire();
    wire[0] = WIRE_VERSION - 1;
    let decoded = PhantomPacket::from_wire(&wire)
        .expect("the codec parses the header before anything judges its version");
    assert_eq!(
        decoded.header.version,
        WIRE_VERSION - 1,
        "the version byte a receiver gates on must survive decoding"
    );
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
/// that does not fit is withheld and, crucially, does not advance the sent
/// total. The window is the peer's cumulative limit less what has gone out, so
/// charging bytes the wire never carried would retire room against nothing, and
/// only a later and larger limit could ever return it.
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
        .poll_send(u64::MAX, 0, std::time::Instant::now(), false)
        .await
        .expect("first segment fits the window");
    assert!(!first.retransmit);
    assert_eq!(first.data.len(), 60);
    assert_eq!(s.peer_send_window(), 40, "window debited by the sent bytes");

    // The second 60-byte segment exceeds the remaining 40-byte window → withheld,
    // and withheld for that reason: the congestion budget is unbounded here, so a
    // stream reporting anything else has consulted the wrong budget.
    assert_eq!(
        s.poll_send(u64::MAX, 0, std::time::Instant::now(), false)
            .await
            .err(),
        Some(SendBlocked::FlowControl),
        "new data exceeding the flow-control window must be withheld"
    );
    assert_eq!(
        s.peer_send_window(),
        40,
        "a withheld segment advanced the sent total — the room it costs was spent on bytes \
         the wire never carried"
    );

    // ── Congestion window bound ──
    let s2 = Stream::new(2);
    s2.send_reliable(Bytes::from(vec![0u8; 100])).await.unwrap();
    // cwnd budget smaller than the segment → withheld by congestion control,
    // BEFORE the flow-control window is even consulted.
    assert_eq!(
        s2.poll_send(50, 0, std::time::Instant::now(), false)
            .await
            .err(),
        Some(SendBlocked::CongestionWindow),
        "new data exceeding the congestion window must be withheld"
    );
    assert_eq!(
        s2.peer_send_window(),
        INITIAL_STREAM_WINDOW,
        "a cwnd-blocked segment must not debit the flow-control window"
    );
}

/// The one frame a closed window does not stop is the flow-control persist probe, and the
/// reason it is not an exception to the invariant above is that it carries **no application
/// payload**. A stream the peer's window has stopped with nothing outstanding has no event
/// left that could free it — no acknowledgement is coming, and the raised limit that would
/// free it rides in a frame nothing retransmits — so it asks, with an empty reliable
/// segment. What the peer is charged for the asking is one stream offset; what it is
/// charged in buffer is nothing, which is what keeps a receiver whose application has
/// stopped reading able to hold this side still.
///
/// Pinned here, next to the bound it must not breach: a probe that ever carried queued data
/// would be new data admitted past the advertised window, and this fails on the first one.
#[tokio::test]
async fn the_persist_probe_carries_no_application_payload() {
    tokio::time::pause();
    let s = Stream::new(1);
    // A window closes by sending, so one segment has already gone out and been acknowledged.
    s.send_reliable(Bytes::from(vec![0u8; 1200])).await.unwrap();
    let sent = s
        .poll_send(u64::MAX, 0, std::time::Instant::now(), false)
        .await
        .expect("the initial window admits the first segment");
    s.ack(sent.stream_offset).await;
    // Close what is left of it, with a full segment still queued behind.
    assert!(s.try_consume_send_window(s.peer_send_window()));
    s.send_reliable(Bytes::from(vec![0u8; 1200])).await.unwrap();

    let probe = s
        .poll_send(u64::MAX, 0, std::time::Instant::now(), false)
        .await
        .expect("a blocked stream with nothing outstanding probes rather than waiting");
    assert!(
        probe.data.is_empty(),
        "the probe carried {} application bytes past a closed flow-control window",
        probe.data.len()
    );
    assert!(probe.reliable && !probe.fin);
    assert_eq!(
        s.peer_send_window(),
        0,
        "the probe must not debit a window that has nothing in it"
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
    let first = s
        .poll_send(u64::MAX, 0, std::time::Instant::now(), false)
        .await
        .expect("first transmission");
    assert!(!first.retransmit);
    assert_eq!(first.data.len(), 200);
    assert_eq!(s.peer_send_window(), INITIAL_STREAM_WINDOW - 200);

    // Slam BOTH budgets shut: drain the flow-control window to zero …
    assert!(s.try_consume_send_window(s.peer_send_window()));
    assert_eq!(s.peer_send_window(), 0);
    // … and an immediate re-poll (cwnd 0, window 0) yields nothing — the
    // segment is in-flight, not yet timed out.
    assert_eq!(
        s.poll_send(0, 0, std::time::Instant::now(), false)
            .await
            .err(),
        Some(SendBlocked::Idle),
        "an in-flight segment that has not timed out is nothing to send, not a \
         budget the sender is up against"
    );

    // Advance past the initial 1s RTO so the unacked segment is due to retransmit.
    tokio::time::advance(Duration::from_millis(1100)).await;

    // The retransmit is produced despite cwnd == 0 AND window == 0 (Karn: the
    // bytes were accounted on first send; loss recovery must always proceed).
    let rtx = s
        .poll_send(0, 0, std::time::Instant::now(), false)
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

/// **A2b (Invariant 9 / T5.7 caveat).** A deployment that cannot guarantee a single coherent /
/// atomically-consumed resumption cache can disable 0-RTT early-data entirely: a valid resume
/// then still bypasses the cookie/PoW gate, but its early-data is rejected
/// (`ServerHello.early_data_accepted = false`) so the payload is only ever delivered 1-RTT —
/// the simplest, zero-infrastructure defence against 0-RTT replay.
#[test]
fn zero_rtt_early_data_can_be_disabled_by_config() {
    let server = HandshakeServer::new().expect("server");
    let server_pk = server.verifying_key().clone();
    let ip: std::net::IpAddr = "127.0.0.1".parse().expect("ip");

    // Two tickets so we can show the SAME resume shape is accepted while enabled and rejected
    // while disabled (the config is the only difference — non-vacuous).
    let c1 = HandshakeClient::new().expect("c1");
    let (rid1, sec1) = first_handshake_mint_ticket(&server, &c1, &server_pk, ip);
    let c2 = HandshakeClient::new().expect("c2");
    let (rid2, sec2) = first_handshake_mint_ticket(&server, &c2, &server_pk, ip);

    // Enabled (default): a valid resume with early-data is accepted.
    let r1 = c1.create_client_hello_with_resume(rid1, &sec1, Some(b"0rtt-payload"));
    let (_e1, sh1) = drive_handshake_to_success(&server, &r1, ip);
    assert!(
        sh1.early_data_accepted,
        "0-RTT early-data is accepted by default"
    );

    // Disable 0-RTT early-data, then the same-shaped resume is rejected (1-RTT) — the resume
    // bypass still works (Success at difficulty 0 with no cookie proves it), only the
    // early-data is dropped.
    server.set_early_data_enabled(false);
    assert!(!server.early_data_enabled());
    let r2 = c2.create_client_hello_with_resume(rid2, &sec2, Some(b"0rtt-payload"));
    let (_e2, sh2) = drive_handshake_to_success(&server, &r2, ip);
    assert!(
        !sh2.early_data_accepted,
        "disabling 0-RTT must reject early-data even on a valid resume"
    );
}

/// **A2b (Invariant 9 / T5.7 caveat).** A horizontally-scaled deployment installs a distributed
/// [`ZeroRttAntiReplay`] store so the one-shot consume is atomic across nodes. A replayed 0-RTT
/// `ClientHello` reaching a *different* node — whose local cache still holds the ticket replica,
/// and whose binder check passes — is blocked by the shared store (`check_and_set` returns
/// `false`) and falls back to 1-RTT, instead of accepting the early-data a second time.
#[test]
fn distributed_anti_replay_store_blocks_a_cross_node_0rtt_replay() {
    use phantom_protocol::transport::handshake::ZeroRttAntiReplay;
    use std::collections::HashSet;
    use std::sync::{Arc, Mutex};

    // A store standing in for a single shared (e.g. Redis) authority across all nodes.
    struct SharedStore {
        consumed: Mutex<HashSet<[u8; 32]>>,
    }
    impl SharedStore {
        /// Simulate a legitimate first use that happened on a SIBLING node.
        fn mark_consumed_elsewhere(&self, id: [u8; 32]) {
            self.consumed.lock().unwrap().insert(id);
        }
    }
    impl ZeroRttAntiReplay for SharedStore {
        fn check_and_set(&self, ticket_id: &[u8; 32]) -> bool {
            // HashSet::insert returns true on first insertion (first use), false if already
            // present (a replay) — exactly the check_and_set contract.
            self.consumed.lock().unwrap().insert(*ticket_id)
        }
    }

    let server = HandshakeServer::new().expect("server");
    let server_pk = server.verifying_key().clone();
    let ip: std::net::IpAddr = "127.0.0.1".parse().expect("ip");
    let store = Arc::new(SharedStore {
        consumed: Mutex::new(HashSet::new()),
    });
    server.set_zero_rtt_anti_replay(store.clone());

    // Positive control: a genuine first-use resume is accepted (the store records it).
    let c1 = HandshakeClient::new().expect("c1");
    let (rid1, sec1) = first_handshake_mint_ticket(&server, &c1, &server_pk, ip);
    let r1 = c1.create_client_hello_with_resume(rid1, &sec1, Some(b"first-use"));
    let (_e1, sh1) = drive_handshake_to_success(&server, &r1, ip);
    assert!(
        sh1.early_data_accepted,
        "the store must allow a genuine first-use 0-RTT"
    );

    // Negative: a ticket the shared store has ALREADY seen (consumed on a sibling node) but
    // whose replica is still in THIS node's local cache must be blocked — the local cache's
    // own one-shot would have accepted it, so only the distributed store catches the replay.
    let c2 = HandshakeClient::new().expect("c2");
    let (rid2, sec2) = first_handshake_mint_ticket(&server, &c2, &server_pk, ip);
    store.mark_consumed_elsewhere(rid2);
    let r2 = c2.create_client_hello_with_resume(rid2, &sec2, Some(b"replayed-0rtt"));
    let (_e2, sh2) = drive_handshake_to_success(&server, &r2, ip);
    assert!(
        !sh2.early_data_accepted,
        "the distributed store must block a 0-RTT replay across nodes"
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

    // Perturb the controller: register inflight + a retransmission.
    s.on_packet_sent(200_000);
    s.on_packet_retransmitted(100_000);
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

/// PROTOCOL § 6.1: repeating a lost `ServerHello` must not turn the listener into an
/// amplifier, and must never send anything to whoever asked for the repeat.
///
/// The repair being pinned here is the server answering a client that repeats its handshake
/// flight, which before it existed was dropped: a single lost reply datagram cost the whole
/// connect. The hazard it introduces is the obvious one — a ~3.5 KB question drawing a
/// ~6.7 KB answer, now on demand rather than once — so both halves of the bound are measured
/// against real traffic rather than argued.
///
/// The first half is RFC 9000 § 8.2 read as a ratio at the path: everything the server sent
/// towards this client, including the flight the relay swallowed, against everything the
/// client sent it. The relay swallows the first fragmented downstream flight, which is the
/// `ServerHello` — the only message in this handshake large enough to fragment — so a repeat
/// is genuinely required to complete the connect and the measurement covers the repair path
/// rather than the quiet one.
///
/// The second half is stronger than a ratio: an off-path source that replays the captured
/// hello verbatim — the best position anyone can occupy against a gate whose key is
/// possession of the exact bytes — receives nothing at all. A repeat's destination comes
/// from the server's record of a completed handshake, and the address in that record echoed
/// an IP-bound cookie, which is what proves it is a real source. The listener's
/// `initial_flights_on_committed_route_total` is what keeps that half from being vacuous: it
/// says the replay reassembled and reached the branch that decides whether to repeat, and
/// that the branch chose to send nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn udp_handshake_reply_repeat_stays_inside_the_anti_amplification_bound() {
    use phantom_protocol::api::session::connect_pinned_udp;
    use phantom_protocol::api::udp_listener::PhantomUdpListener;
    use phantom_protocol::transport::phantom_udp::envelope::{
        decode_header, PacketType, FRAG_SUBHDR_LEN, PATH_MTU,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::net::UdpSocket;

    /// RFC 9000 § 8.2. The listener enforces this when it decides to retain a reply at all;
    /// what is checked here is the traffic that results.
    const AMPLIFICATION_LIMIT: usize = 3;

    let listener = PhantomUdpListener::bind_udp("127.0.0.1:0".to_string())
        .await
        .expect("bind_udp");
    let server_addr: std::net::SocketAddr = listener.local_addr().parse().unwrap();
    let pinned = listener.verifying_key_bytes();
    let acceptor = listener.clone();
    let accepted = tokio::spawn(async move { acceptor.accept().await });

    // Relay: counts both directions, swallows the first fragmented downstream flight, and
    // keeps the client's handshake datagrams so they can be replayed from elsewhere.
    let downstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let relay_addr = downstream.local_addr().unwrap();
    let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    upstream.connect(server_addr).await.unwrap();
    let to_server = Arc::new(AtomicUsize::new(0));
    let from_server = Arc::new(AtomicUsize::new(0));
    let swallowed = Arc::new(AtomicUsize::new(0));
    let captured: Arc<std::sync::Mutex<std::collections::HashMap<u32, Vec<Vec<u8>>>>> =
        Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
    {
        let (up, down) = (to_server.clone(), from_server.clone());
        let lost = swallowed.clone();
        let sink = captured.clone();
        tokio::spawn(async move {
            let mut c2s = vec![0u8; PATH_MTU + 64];
            let mut s2c = vec![0u8; PATH_MTU + 64];
            let mut client: Option<std::net::SocketAddr> = None;
            let mut owed: Option<usize> = None;
            loop {
                tokio::select! {
                    r = downstream.recv_from(&mut c2s) => {
                        let Ok((n, from)) = r else { continue };
                        client = Some(from);
                        up.fetch_add(n, Ordering::Relaxed);
                        let datagram = &c2s[..n];
                        if let Ok((hdr, rest)) = decode_header(datagram) {
                            if hdr.ty == PacketType::Initial
                                && hdr.fragmented
                                && rest.len() >= FRAG_SUBHDR_LEN
                            {
                                let pid = u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]);
                                sink.lock()
                                    .unwrap()
                                    .entry(pid)
                                    .or_default()
                                    .push(datagram.to_vec());
                            }
                        }
                        let _ = upstream.send(datagram).await;
                    }
                    r = upstream.recv(&mut s2c) => {
                        let Ok(n) = r else { continue };
                        down.fetch_add(n, Ordering::Relaxed);
                        let datagram = &s2c[..n];
                        if let Ok((hdr, rest)) = decode_header(datagram) {
                            if hdr.fragmented && rest.len() >= FRAG_SUBHDR_LEN {
                                let total = u16::from_be_bytes([rest[6], rest[7]]) as usize;
                                let left = owed.get_or_insert(total);
                                if *left > 0 {
                                    *left -= 1;
                                    lost.fetch_add(1, Ordering::Relaxed);
                                    continue;
                                }
                            }
                        }
                        if let Some(c) = client {
                            let _ = downstream.send_to(datagram, c).await;
                        }
                    }
                }
            }
        });
    }

    let client = connect_pinned_udp("127.0.0.1".to_string(), relay_addr.port(), pinned)
        .await
        .expect("client socket");
    client
        .await_ready()
        .await
        .expect("the handshake completes through the repair");
    // Snapshot before any application byte moves, so the ratio is the handshake's own.
    let sent_by_server = from_server.load(Ordering::Relaxed);
    let sent_by_client = to_server.load(Ordering::Relaxed);
    let _outcome = accepted.await.expect("accept task").expect("session");

    assert!(
        swallowed.load(Ordering::Relaxed) > 0,
        "the relay must have swallowed a reply flight, or this measures the path that never \
         needed a repeat"
    );
    assert!(
        sent_by_server <= sent_by_client * AMPLIFICATION_LIMIT,
        "the server sent {sent_by_server} bytes for the client's {sent_by_client} — past the \
         {AMPLIFICATION_LIMIT}× RFC 9000 §8.2 bound. A reply repeated on demand is only safe \
         while each repeat costs the asker a whole flight"
    );

    // And an off-path source with a perfect capture gets nothing back.
    let flight = {
        let seen = captured.lock().unwrap();
        let newest = seen
            .keys()
            .copied()
            .max()
            .expect("a captured client flight");
        seen.get(&newest).cloned().expect("its datagrams")
    };
    let before = listener
        .metrics_snapshot()
        .initial_flights_on_committed_route_total;
    let attacker = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    attacker.connect(server_addr).await.unwrap();
    let mut asked = 0usize;
    for _ in 0..8 {
        for d in &flight {
            attacker.send(d).await.expect("replay");
            asked += d.len();
        }
    }
    let mut buf = vec![0u8; PATH_MTU + 64];
    let heard = tokio::time::timeout(Duration::from_secs(2), attacker.recv(&mut buf)).await;
    assert!(
        heard.is_err(),
        "an off-path source that replayed {asked} bytes of captured hello received bytes \
         back; the amplification factor towards whoever asks must be exactly zero"
    );

    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while listener
        .metrics_snapshot()
        .initial_flights_on_committed_route_total
        == before
        && std::time::Instant::now() < deadline
    {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        listener
            .metrics_snapshot()
            .initial_flights_on_committed_route_total
            > before,
        "the replay must have reached the branch that decides whether to repeat; if it never \
         got there, the zero above is about routing rather than about the bound"
    );

    listener.shutdown();
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

/// Idle keep-alive (`KEEPALIVE` PING/PONG) is invariant-safe: a keep-alive packet is
/// `ENCRYPTED | KEEPALIVE` with an **empty** payload, so it
///  (1) carries the post-handshake `ENCRYPTED` invariant flag, which is what the
///      recv gate requires of it — the gate itself is driven by
///      `forged_unencrypted_post_handshake_packet_is_dropped_by_the_recv_path`;
///      the header here is one this test built, so this is a statement about the
///      keep-alive's shape, not about the receiver,
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

/// The session-close frame (WIRE v8) is invariant-safe by exactly the mechanisms that
/// make every other in-session control frame safe, and by nothing of its own:
///  (1) it rides the already-declared `CONTROL` bit, which overlaps no other flag, and
///      it does **not** spend `0x8000` — the one bit still unassigned. That is the
///      point of putting a subtype byte inside the plaintext: a flag is a scarce
///      16-entry namespace and three in-session control frames were added in the two
///      revisions before this one, so the next one still has somewhere to go;
///  (2) it carries `ENCRYPTED`, which is what the receive gate requires of it. That
///      the gate holds is pinned by
///      `forged_unencrypted_close_frame_cannot_end_a_session`, driven through a live
///      pump; the header here is one this test built, so this is a statement about
///      the frame's shape;
///  (3) it AEAD-seals a one-byte plaintext and opens back to that byte — an off-path
///      peer cannot forge one;
///  (4) it draws a per-direction packet number, so a replay of a captured close is
///      refused by the sliding window **after** AEAD verify (Inv-4). That is what
///      makes the receive branch idempotent without the branch doing anything: a
///      recorded close datagram is not a session-kill primitive.
#[test]
fn session_close_frame_is_encrypted_authenticated_and_replay_protected() {
    use phantom_protocol::CoreError;

    // (1a) CONTROL overlaps nothing else on the wire.
    for other in [
        PacketFlags::RELIABLE,
        PacketFlags::ACK,
        PacketFlags::FIN,
        PacketFlags::UNRELIABLE,
        PacketFlags::PRIORITY,
        PacketFlags::ENCRYPTED,
        PacketFlags::COMPRESSED,
        PacketFlags::REKEY,
        PacketFlags::PATH_VALIDATION,
        PacketFlags::COALESCED,
        PacketFlags::WINDOW_UPDATE,
        PacketFlags::KEEPALIVE,
        PacketFlags::PADDED,
        PacketFlags::COVER,
    ] {
        assert_eq!(
            PacketFlags::CONTROL & other,
            0,
            "CONTROL (0x{:04x}) must not overlap an existing flag (0x{other:04x})",
            PacketFlags::CONTROL
        );
    }

    // (1b) The last free bit is still free. A close frame that had taken it would
    // have left the next in-session control frame with no bit at all.
    let assigned = PacketFlags::RELIABLE
        | PacketFlags::ACK
        | PacketFlags::FIN
        | PacketFlags::UNRELIABLE
        | PacketFlags::PRIORITY
        | PacketFlags::ENCRYPTED
        | PacketFlags::COMPRESSED
        | PacketFlags::CONTROL
        | PacketFlags::REKEY
        | PacketFlags::PATH_VALIDATION
        | PacketFlags::COALESCED
        | PacketFlags::WINDOW_UPDATE
        | PacketFlags::KEEPALIVE
        | PacketFlags::PADDED
        | PacketFlags::COVER;
    assert_eq!(
        assigned & 0x8000,
        0,
        "0x8000 is the only unassigned flag bit; the close frame must not have spent it"
    );

    let (client, server) = make_session_pair([0x3Cu8; 32]);
    let pn = client.next_send_pn();
    let header = PacketHeader::new(
        *server.id(),
        1,
        pn,
        PacketFlags::new(PacketFlags::ENCRYPTED | PacketFlags::CONTROL),
    )
    .with_epoch(client.current_epoch());
    // (2) it carries ENCRYPTED.
    assert!(
        header.flags.contains(PacketFlags::ENCRYPTED),
        "a close frame must be ENCRYPTED (Inv-2 downgrade defense)"
    );

    // (3) it AEAD-seals the subtype byte and opens back to it — authenticated.
    let body = [ControlSubtype::CLOSE];
    let ct = client
        .encrypt_packet(&header, &body, &[])
        .expect("seal close frame");
    let pt = server
        .decrypt_packet(&header, &ct, &[])
        .expect("authenticated close frame opens");
    assert_eq!(
        pt, body,
        "the control body is the close subtype and nothing else"
    );

    // (4) a replayed close (same PN) is rejected AFTER AEAD verify (Inv-4).
    let replay = server.decrypt_packet(&header, &ct, &[]);
    assert!(
        matches!(replay, Err(CoreError::ReplayDetected(_))),
        "a replayed close must be rejected by the replay window (Inv-4); got {replay:?}"
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

/// Anti-amplification + no-redirection (D9 / A2a server-migration follow). When the client
/// follows a migrated server it mirrors the server's M-1 + 3× anti-amplification guarantees:
///   (1) it must NOT send more than 3× the bytes it received from an unvalidated candidate
///       (so an on-path attacker that replays a fresh server frame with a spoofed source —
///       a victim's address — can induce at most a bounded reflection to that victim), AND
///   (2) an unvalidated candidate is NEVER the c2s send target — application data keeps
///       flowing to the ESTABLISHED server until a valid PATH_RESPONSE promotes the candidate.
/// Worst case is therefore a bounded reflection, never a c2s redirection/hijack.
#[tokio::test]
async fn client_server_migration_candidate_is_anti_amp_capped_and_never_the_send_target() {
    use phantom_protocol::api::session::{FramePhase, SessionTransport};
    use phantom_protocol::api::udp_transport::UdpClientTransport;
    use phantom_protocol::transport::phantom_udp::datagram::encode_datagrams;
    use phantom_protocol::transport::phantom_udp::envelope::PacketType;
    use std::time::Duration;
    use tokio::net::UdpSocket;

    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server.local_addr().unwrap();
    let client = UdpClientTransport::connect(server_addr).await.unwrap();
    client.set_frame_phase(FramePhase::Established);

    // Learn the client's local address so the candidate can target it.
    client.send_bytes(b"hi").await.unwrap();
    let mut buf = vec![0u8; 2048];
    let (_n, client_addr) = server.recv_from(&mut buf).await.unwrap();

    // A candidate (a NEW source — in the attack, a fresh frame an on-path attacker rewrote to
    // a victim's address) sends ONE small (10-byte) framed datagram, seeding a small 3× budget.
    // The cid is irrelevant to delivery (recv_bytes delivers from any source; AEAD is the guard).
    let candidate = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    for d in encode_datagrams(PacketType::OneRtt, &[0u8; 8], 1, b"0123456789").unwrap() {
        candidate.send_to(&d, client_addr).await.unwrap();
    }
    let _ = tokio::time::timeout(Duration::from_secs(2), client.recv_bytes())
        .await
        .expect("recv")
        .expect("frame");

    // M-1: a raw recv must NOT commit the candidate (only the post-AEAD confirm does).
    assert!(
        !client.has_migration_candidate(),
        "a raw recv must not commit a server-migration candidate (M-1)"
    );
    client.confirm_authenticated_source();
    assert!(client.has_migration_candidate());

    // (1) Anti-amp: keep challenging until the 3× cap blocks, then drain everything the
    // candidate received and assert it is bounded by 3× the 10 bytes it sent us.
    let mut blocked = false;
    for _ in 0..100 {
        if !client.send_to_candidate(b"challenge-frame").await.unwrap() {
            blocked = true;
            break;
        }
    }
    assert!(
        blocked,
        "the 3× anti-amplification cap must block excessive challenges to a candidate"
    );
    let mut total_to_candidate = 0u64;
    while let Ok(Ok((n, _))) =
        tokio::time::timeout(Duration::from_millis(100), candidate.recv_from(&mut buf)).await
    {
        total_to_candidate += n as u64;
    }
    assert!(
        total_to_candidate <= 30,
        "the client must not send > 3× (30 bytes) to an unvalidated candidate; sent {total_to_candidate}"
    );

    // (2) An unvalidated candidate is NEVER the c2s send target: app data flows to the
    // ESTABLISHED server, and the candidate receives nothing further.
    client.send_bytes(b"app-data-to-server").await.unwrap();
    let (sn, _) = tokio::time::timeout(Duration::from_secs(1), server.recv_from(&mut buf))
        .await
        .expect("app data must reach the established server")
        .unwrap();
    assert!(sn > 0);
    assert!(
        tokio::time::timeout(Duration::from_millis(200), candidate.recv_from(&mut buf))
            .await
            .is_err(),
        "an unvalidated candidate must never receive app data — it is not the c2s send target"
    );
}

/// Receive-side memory amplification by an authenticated peer (threat-model §5 §D).
///
/// A peer chooses how many streams to open, how much it sends and how long it leaves a
/// reassembly hole open, so every receive-side buffer is a commitment this side makes on
/// the peer's word. The advertised receive window is the head of that chain — it sizes
/// both what one stream may hold unconsumed and the reorder budget that tracks it — which
/// is why window growth is drawn from **one allowance per session** rather than granted
/// per stream: a per-stream ceiling multiplies by `MAX_STREAMS`, a session-wide one does
/// not.
///
/// The bound is per **session**, deliberately (a process-wide pool would let one peer's
/// growth decide another peer's window). What this pins is that the per-session bound
/// really is per-session: N sessions of M streams hold no more than N budgets between them.
#[tokio::test]
async fn recv_window_growth_is_bounded_per_session_not_per_stream() {
    tokio::time::pause();
    const SESSIONS: usize = 3;
    const STREAMS_PER_SESSION: usize = 32;

    // Every stream of every session consumes far more than the whole budget is worth, so
    // growth stops because the session ran out of allowance, not because an application
    // stopped reading.
    let mut per_session_growth = Vec::new();
    for i in 0..SESSIONS {
        let (session, _peer) = make_session_pair([0x40 + i as u8; 32]);
        let streams: Vec<_> = (0..STREAMS_PER_SESSION)
            .map(|_| session.open_stream().expect("open a stream"))
            .collect();
        for s in &streams {
            s.record_app_consumed(1, true); // open each measurement interval
        }
        for _ in 0..40 {
            tokio::time::advance(Duration::from_millis(400)).await;
            for s in &streams {
                s.record_app_consumed(MAX_RECV_WINDOW, true);
            }
        }
        per_session_growth.push(
            streams
                .iter()
                .map(|s| u64::from(s.advertised_recv_window() - INITIAL_STREAM_WINDOW))
                .sum::<u64>(),
        );
    }

    for (i, growth) in per_session_growth.iter().enumerate() {
        assert!(
            *growth <= u64::from(SESSION_RECV_WINDOW_GROWTH_BUDGET),
            "session {i}'s {STREAMS_PER_SESSION} streams grew by {growth} B against a \
             {SESSION_RECV_WINDOW_GROWTH_BUDGET} B session budget — the budget is being \
             handed out per stream, so the commitment scales with stream count"
        );
    }
    let total: u64 = per_session_growth.iter().sum();
    assert!(
        total <= SESSIONS as u64 * u64::from(SESSION_RECV_WINDOW_GROWTH_BUDGET),
        "{SESSIONS} sessions × {STREAMS_PER_SESSION} streams grew by {total} B; the \
         documented bound is one budget per session"
    );

    // Positive control: the assertions above are not vacuous. The naive removal of the
    // mechanism is one budget per stream — exactly what a stream built without a shared
    // handle gets — and under it the same streams blow past the bound.
    let mut unshared_total = 0u64;
    for _ in 0..SESSIONS {
        let streams: Vec<Stream> = (0..STREAMS_PER_SESSION)
            .map(|id| Stream::with_recv_tuning(id as u16, Arc::new(SharedRecvTuning::default())))
            .collect();
        for s in &streams {
            s.record_app_consumed(1, true);
        }
        for _ in 0..40 {
            tokio::time::advance(Duration::from_millis(400)).await;
            for s in &streams {
                s.record_app_consumed(MAX_RECV_WINDOW, true);
            }
        }
        unshared_total += streams
            .iter()
            .map(|s| u64::from(s.advertised_recv_window() - INITIAL_STREAM_WINDOW))
            .sum::<u64>();
    }
    assert!(
        unshared_total > SESSIONS as u64 * u64::from(SESSION_RECV_WINDOW_GROWTH_BUDGET),
        "this test no longer exercises the budget: without it these streams took only \
         {unshared_total} B, which one budget per session already covers"
    );
}

/// The growth allowance is per session, so what a *process* commits is its session cap
/// times one allowance — and that arithmetic is published, which makes it a thing that can
/// go stale.
///
/// `CHANGELOG.md`, `docs/security/threat-model.md` §5 §D.1,
/// `docs/operations/deployment.md` and the Helm chart's `values.yaml` all state the figure
/// for the reference server's default `PHANTOM_MAX_SESSIONS` of 1024. This test pins it
/// against what sessions are *observed* to draw rather than against the constant it was
/// typed from: if the allowance ever stopped being enforced, the observed per-session
/// maximum would exceed it and the published product would silently understate the process
/// by whatever factor the enforcement was out.
///
/// The two constants below are literals in a crate that cannot see `server/`, so this test
/// on its own could only ever agree with the tree it was written against.
/// `scripts/check_memory_arithmetic.py` is what couples them: it reads
/// `PHANTOM_MAX_SESSIONS`'s clap default out of `server/src/config.rs`, reads
/// `SESSION_RECV_WINDOW_GROWTH_BUDGET` out of `core/src/transport/stream.rs`, recomputes
/// the product, and fails when this file or any published statement of it disagrees. Change
/// the server's default and that script is what says so — this test would stay green.
///
/// Companion to `recv_window_growth_is_bounded_per_session_not_per_stream`, which pins the
/// *per-session* half. This one pins the multiplier.
#[tokio::test]
async fn the_published_process_growth_figure_is_the_session_cap_times_what_a_session_draws() {
    tokio::time::pause();
    const SESSIONS: usize = 4;
    const STREAMS_PER_SESSION: usize = 16;
    // Both figures below are checked against `server/src/config.rs` and
    // `core/src/transport/stream.rs` by `scripts/check_memory_arithmetic.py`, which parses
    // these two lines by name. Keep the names and the literal forms.
    /// `PHANTOM_MAX_SESSIONS`'s default in the reference server.
    const REFERENCE_DEFAULT_SESSION_CAP: u64 = 1024;
    /// The receive-window growth those sessions commit, as published alongside that cap.
    const PUBLISHED_PROCESS_GROWTH: u64 = 8 * 1024 * 1024 * 1024;

    // Drive every stream of every session far past what any window could absorb, so growth
    // stops where the session runs out of allowance rather than where an application
    // stopped reading. Sessions are built and driven one at a time: what is being measured
    // is the maximum one of them reaches, and that is the multiplicand of the arithmetic.
    let mut per_session_growth = Vec::new();
    for i in 0..SESSIONS {
        let (session, _peer) = make_session_pair([0x70 + i as u8; 32]);
        let streams: Vec<_> = (0..STREAMS_PER_SESSION)
            .map(|_| session.open_stream().expect("open a stream"))
            .collect();
        for s in &streams {
            s.record_app_consumed(1, true); // open each stream's measurement interval
        }
        for _ in 0..40 {
            tokio::time::advance(Duration::from_millis(400)).await;
            for s in &streams {
                s.record_app_consumed(MAX_RECV_WINDOW, true);
            }
        }
        per_session_growth.push(
            streams
                .iter()
                .map(|s| u64::from(s.advertised_recv_window() - INITIAL_STREAM_WINDOW))
                .sum::<u64>(),
        );
    }

    let worst = *per_session_growth
        .iter()
        .max()
        .expect("SESSIONS is non-zero, so there is a maximum");

    // The multiplicand has to be the real per-session maximum from both sides. Too high and
    // the published product is not a bound at all; too low — a session that never managed
    // to spend its allowance — and the product would look safe for a reason that has
    // nothing to do with enforcement. The smallest step a window can grow by is one
    // `INITIAL_STREAM_WINDOW` (the first doubling of a fresh stream), so a session within
    // one of those of the allowance has spent everything a doubling could claim.
    assert!(
        worst <= u64::from(SESSION_RECV_WINDOW_GROWTH_BUDGET),
        "a session drew {worst} B of window growth against a \
         {SESSION_RECV_WINDOW_GROWTH_BUDGET} B allowance — the per-session bound is not \
         holding, so every published process figure derived from it understates by the \
         same factor"
    );
    assert!(
        worst + u64::from(INITIAL_STREAM_WINDOW) > u64::from(SESSION_RECV_WINDOW_GROWTH_BUDGET),
        "a session only managed {worst} B of the {SESSION_RECV_WINDOW_GROWTH_BUDGET} B \
         allowance, so this test is not measuring the maximum and the arithmetic below \
         would pass for the wrong reason"
    );

    let total: u64 = per_session_growth.iter().sum();
    assert!(
        total <= SESSIONS as u64 * u64::from(SESSION_RECV_WINDOW_GROWTH_BUDGET),
        "{SESSIONS} sessions drew {total} B between them; nothing divides the allowance \
         across sessions, so the process figure is the session count times one allowance"
    );

    // The published product, checked against the observed multiplicand rather than against
    // the constant it was written from.
    assert!(
        REFERENCE_DEFAULT_SESSION_CAP * worst <= PUBLISHED_PROCESS_GROWTH,
        "{REFERENCE_DEFAULT_SESSION_CAP} sessions each drawing the observed {worst} B come \
         to more than the published {PUBLISHED_PROCESS_GROWTH} B, so every document that \
         states the product is out"
    );
    assert!(
        REFERENCE_DEFAULT_SESSION_CAP * (worst + u64::from(INITIAL_STREAM_WINDOW))
            > PUBLISHED_PROCESS_GROWTH,
        "the published {PUBLISHED_PROCESS_GROWTH} B is loose against what \
         {REFERENCE_DEFAULT_SESSION_CAP} sessions of {worst} B actually reach; a figure \
         with slack in it invites being read as headroom that is not there"
    );
}

/// Bytes the real delivery queue takes to park `n` one-byte items, over and above the
/// payload — measured, not modelled. The payloads are allocated before the measurement
/// starts and sliced inside it, exactly as the reliable receive path does
/// (`plaintext.slice(4..)`), so what the delta captures is the queue slot plus the
/// reference block that slice allocates.
fn measured_backlog_structure_per_item(n: usize) -> f64 {
    let payloads: Vec<Bytes> = (0..n).map(|_| Bytes::from(vec![0u8; 1])).collect();
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<StreamMessage>();
    let before = live_heap();
    for p in &payloads {
        tx.send(StreamMessage::Data(p.slice(0..1)))
            .expect("receiver alive");
    }
    let used = live_heap() - before;
    drop(rx);
    drop(payloads);
    used as f64 / n as f64
}

/// A queued delivery item costs more than the bytes it carries, so a cap that counts only
/// payload does not cap memory.
///
/// The item count, not the byte count, is what a peer choosing minimum-size segments
/// controls: at one byte per item a payload-only cap of `RECV_DELIVERY_HARD_CAP` admits
/// four million items, and an item is not one byte. This measures what one really costs
/// and requires `DELIVERY_ITEM_OVERHEAD_BYTES` — the figure the accounting charges on top
/// of the payload — to cover it, which is what turns the cap into a bound on resident
/// bytes.
#[test]
fn a_queued_delivery_item_costs_more_than_the_payload_it_carries() {
    let per_item = measured_backlog_structure_per_item(1 << 15);

    // Positive control: a measurement that cannot see anything would satisfy the bound
    // below for free.
    assert!(
        per_item > 8.0,
        "the heap measurement saw only {per_item:.1} B per queued item — it is not \
         observing the queue, so the bound below would hold vacuously"
    );
    assert!(
        per_item <= DELIVERY_ITEM_OVERHEAD_BYTES as f64,
        "one queued delivery item really costs {per_item:.1} B of structure, but the \
         backlog charges {DELIVERY_ITEM_OVERHEAD_BYTES} B for it — with that charge \
         {RECV_DELIVERY_HARD_CAP} B of counted backlog is {:.0} MiB resident, so the cap \
         bounds a number rather than a memory",
        RECV_DELIVERY_HARD_CAP as f64 / (1.0 + DELIVERY_ITEM_OVERHEAD_BYTES as f64) * per_item
            / (1024.0 * 1024.0)
    );
}

/// Each of the two per-stream receive buffers must stay inside the figure published for it.
///
/// These are stated separately and never added up. A per-session total has to enumerate
/// every allocation the receive path makes, including the ones under this crate's own
/// abstractions — the byte pipe's accumulator, PhantomUDP's fragment reassembly, the
/// `Stream` structures — and a total that misses one reads as a bound while being an
/// estimate. What is checked here is what each row of the published table claims, measured
/// against the real structure driven to its own cap.
///
/// The reorder buffer is held at its entry cap by a hole that never fills, using one-byte
/// segments: that is the shape the byte budget does not bound, and the entry-structure
/// figure is what covers it. The delivery channel is filled to its depth with the largest
/// payload the frame gate admits, which is now a figure this side enforces rather than the
/// chunk size the *sender* happens to use.
#[tokio::test(flavor = "current_thread")]
async fn the_per_stream_receive_buffers_stay_inside_the_figures_published_for_them() {
    // ── One stream's reorder buffer, held at its entry cap ──
    let stream = Stream::new(11);
    let before = live_heap();
    for i in 0..MAX_RECV_REORDER {
        let offset = 1 + i as u32 * 2;
        stream
            .accept_in_order(offset, vec![Bytes::from(vec![0u8; 1])])
            .await;
    }
    let reorder_resident = (live_heap() - before).max(0) as u64;

    // ── One stream's delivery channel, filled to its depth at the largest admitted item ──
    let (demux, _control_rx) = StreamDemultiplexer::new_with_role(16, false);
    let handle = demux.register_stream(21, STREAM_RECV_CHANNEL_DEPTH);
    let before = live_heap();
    for _ in 0..STREAM_RECV_CHANNEL_DEPTH {
        assert!(
            demux
                .route_data_async(21, Bytes::from(vec![0u8; MAX_RECV_PAYLOAD]))
                .await,
            "the registered stream must accept up to its channel depth"
        );
    }
    let channel_resident = (live_heap() - before).max(0) as u64;
    drop(handle);

    // Positive control: both measurements have to be seeing the structures they name, or
    // the comparisons below are satisfied by measuring nothing.
    assert!(
        reorder_resident > MAX_RECV_REORDER as u64
            && channel_resident > (STREAM_RECV_CHANNEL_DEPTH * MAX_RECV_PAYLOAD) as u64,
        "the heap measurement is not observing the buffers: reorder {reorder_resident} B, \
         channel {channel_resident} B"
    );

    let reorder_published = MAX_RECV_REORDER as u64 * (REORDER_ENTRY_OVERHEAD_BYTES as u64 + 1);
    assert!(
        reorder_resident <= reorder_published,
        "a reorder buffer held at its entry cap takes {reorder_resident} B against a \
         published {reorder_published} B ({REORDER_ENTRY_OVERHEAD_BYTES} B of structure \
         per entry)"
    );

    let channel_published =
        STREAM_RECV_CHANNEL_DEPTH as u64 * (MAX_RECV_PAYLOAD as u64 + DELIVERY_ITEM_OVERHEAD_BYTES);
    assert!(
        channel_resident <= channel_published,
        "one stream's delivery channel at its depth takes {channel_resident} B against a \
         published {channel_published} B ({STREAM_RECV_CHANNEL_DEPTH} slots of \
         {MAX_RECV_PAYLOAD} B plus {DELIVERY_ITEM_OVERHEAD_BYTES} B of structure each)"
    );
}

// ── Invariant 2: the receive path rejects unencrypted post-handshake packets ──
//
// The neighbouring AAD tests above say a genuine packet cannot have its `ENCRYPTED`
// flag stripped without breaking the tag. That is a different statement from the one
// Invariant 2 makes, which is about a packet that was never sealed at all: the recv
// loop drops it before it can be routed, empty payload included (the M-2 forged
// standalone FIN). Reaching that gate means going through the real pump — header
// protection, the version gate, the session-id bind — so this drives a live
// `PhantomSession` against a hand-run server and puts the forgeries on the wire.

/// The wire between the client under test and the server this test plays. Message
/// oriented like every other `SessionTransport`, so a frame handed to `to_peer` is
/// exactly one frame out of the client's `recv_bytes` — which is what lets the test
/// forge a single packet rather than a byte stream.
///
/// A leaf transport, not a wrapper: it has no address and no migration, so the
/// defaulted control surface of the trait is the right answer for every method it
/// does not implement. The EPS-04 forwarding obligation is on types that wrap
/// another `SessionTransport` and would otherwise silence its control calls.
struct PipeTransport {
    to_peer: tokio::sync::mpsc::Sender<Bytes>,
    from_peer: tokio::sync::Mutex<tokio::sync::mpsc::Receiver<Bytes>>,
}

impl phantom_protocol::api::session::SessionTransport for PipeTransport {
    async fn send_bytes(&self, data: &[u8]) -> Result<(), phantom_protocol::CoreError> {
        self.to_peer
            .send(Bytes::copy_from_slice(data))
            .await
            .map_err(|_| phantom_protocol::CoreError::NetworkError("pipe closed".into()))
    }

    async fn recv_bytes(&self) -> Result<Bytes, phantom_protocol::CoreError> {
        self.from_peer
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| phantom_protocol::CoreError::NetworkError("pipe closed".into()))
    }
}

/// **Invariant 2.** A post-handshake packet that arrives without `ENCRYPTED` is
/// dropped by the receive path — it is never decrypted, never routed to a stream,
/// and its `FIN` never closes one. This is the stripped-flag downgrade defence, and
/// the case it exists for is the smallest possible forgery: a standalone FIN
/// carrying no application data, which under the pre-M-2 rule (drop only *non-empty*
/// unencrypted payloads) would have torn a stream down without any AEAD verification.
///
/// The frames ride an `open_stream()` stream rather than the reserved raw-app id,
/// because that is the only place a FIN means anything: the delivery router discards
/// `DeliverItem::Close` for ids 0 and 1 outright ("not used in the current
/// protocol"), and the raw-app `recv()` reads a plain channel that has no EOF at
/// all. A forged FIN aimed there could not close a thing even with the gate deleted,
/// so an assertion about it would be unfalsifiable.
///
/// Four frames go down the wire, in order, and the stream's own `recv()` is the
/// barrier that proves each was processed before the next was read:
///
///  1. a forged FIN with a literally empty payload. On the v6 wire this cannot even
///     reach the flag gate: header protection samples the first 16 ciphertext bytes,
///     so a frame with no payload fails to unmask and is dropped one layer earlier.
///     Pinned here because it is the shape the audit named — the gate is required to
///     hold it, whichever layer happens to reach it first;
///  2. a forged FIN at the smallest size header protection admits — 16 payload
///     bytes, masked with the server's real send key so it unmasks into a valid
///     header on the client. Its bytes are laid out as a reliable frame at stream
///     offset 0, so a receiver that skipped the gate would hand `downgraded!!` to
///     the application;
///  3. a genuine `ENCRYPTED | RELIABLE` frame on the same stream and path;
///  4. a second genuine frame, the next segment on the same stream.
///
/// (3) and (4) fail for different regressions, which is why both are here.
///
/// (3) is what a *deleted* gate breaks: the forgery's bytes are delivered and the
/// stream yields `downgraded!!` where `authentic` was expected.
///
/// (4) is what a *partial* gate breaks — one that refuses the forgery's payload but
/// still records its FIN. That the two come apart at all is a consequence of the FIN
/// release being order-gated: `note_remote_fin` only files the offset, and
/// `take_in_order_fin` releases the EOF later, once the in-order cursor has passed
/// it. So a gate that drops the bytes and notes the FIN leaves (3) intact — the
/// authentic frame is delivered, and is itself what advances the cursor past the
/// forged offset — and surfaces one frame later as `Ok(None)` in place of (4). Only
/// (4) catches that; hoisting the FIN bookkeeping above the gate, on the reasoning
/// that a FIN arriving over a reorder gap must not be lost, produces exactly it.
///
/// Both are also the two-sidedness: a receive path that dropped *everything* would
/// satisfy any assertion about the forgeries and fail (3) and (4) both. The drop
/// counter is the third leg — it separates "refused" from "never arrived".
#[tokio::test]
async fn forged_unencrypted_post_handshake_packet_is_dropped_by_the_recv_path() {
    use phantom_protocol::api::PhantomSession;
    use phantom_protocol::transport::handshake::ServerReply;

    let (to_client_tx, to_client_rx) = tokio::sync::mpsc::channel::<Bytes>(64);
    let (to_server_tx, mut to_server_rx) = tokio::sync::mpsc::channel::<Bytes>(64);
    let client_transport = PipeTransport {
        to_peer: to_server_tx,
        from_peer: tokio::sync::Mutex::new(to_client_rx),
    };

    let server_hs = HandshakeServer::new().expect("server handshake state");
    let pinned = server_hs.verifying_key().clone();
    let session = PhantomSession::connect_with_transport("pipe-peer:0", client_transport, pinned);

    // Run the server side by hand: the DoS gate answers the first hello with a
    // cookie `Retry`, and the re-sent hello succeeds. Looping rather than
    // straight-lining keeps the test correct if the gate ever adds a round.
    let client_ip = "127.0.0.1".parse().expect("client ip");
    let server_session = loop {
        let hello_bytes = to_server_rx.recv().await.expect("client hello");
        let hello = borsh::from_slice::<ClientHello>(&hello_bytes).expect("decode client hello");
        match server_hs.process_client_hello(&hello, 0, client_ip) {
            HandshakeResponse::Retry(retry) => {
                let wire = ServerReply::Retry(retry).to_wire().expect("encode retry");
                to_client_tx
                    .send(Bytes::from(wire))
                    .await
                    .expect("send retry");
            }
            HandshakeResponse::Success(server_hello, negotiated, _) => {
                let wire = ServerReply::Hello(server_hello)
                    .to_wire()
                    .expect("encode server hello");
                to_client_tx
                    .send(Bytes::from(wire))
                    .await
                    .expect("send server hello");
                break negotiated;
            }
            HandshakeResponse::Reject(r) => panic!("server rejected its own client: {r:?}"),
            HandshakeResponse::Fail(e) => panic!("handshake failed: {e:?}"),
        }
    };

    session
        .await_ready()
        .await
        .expect("the pinned handshake completes");

    assert_eq!(
        session.metrics_snapshot().unencrypted_dropped_total,
        0,
        "nothing has been dropped yet — the handshake itself must not trip the gate"
    );

    let session_id = *server_session.id();

    // The target stream. `open_stream()` registers it in the demux and in the stream
    // table the pump reads, both of which the session created before the pump was
    // spawned, so no wire traffic and no cooperation from the server side is needed
    // to make the client route frames stamped with this id to it.
    let app_stream = session.open_stream().expect("open a stream");
    let target: u16 = app_stream
        .stream_id()
        .try_into()
        .expect("a locally-opened stream id fits the wire field");

    // (1) The empty-payload forged FIN. Unmasked on purpose: there is nothing to
    // mask it against, since header protection derives its mask from a ciphertext
    // sample this frame does not have.
    let empty_fin = PhantomPacket::new(
        PacketHeader::new(
            session_id,
            target,
            1,
            PacketFlags::new(PacketFlags::RELIABLE | PacketFlags::FIN),
        ),
        Vec::new(),
    );
    to_client_tx
        .send(Bytes::from(empty_fin.to_wire()))
        .await
        .expect("send empty forged FIN");

    // (2) The same forgery at the smallest size the wire admits. The payload of an
    // unencrypted packet IS its plaintext, so these bytes are laid out exactly as the
    // reliable receive path expects — `[stream_offset: u32 BE][data]` at offset 0 —
    // to make a missing gate deliver something recognisable rather than something
    // that happens to be discarded further down.
    let mut forged_payload = 0u32.to_be_bytes().to_vec();
    forged_payload.extend_from_slice(b"downgraded!!");
    assert_eq!(
        forged_payload.len(),
        16,
        "the minimum header-protected size"
    );
    let forged_fin = PhantomPacket::new(
        PacketHeader::new(
            session_id,
            target,
            2,
            PacketFlags::new(PacketFlags::RELIABLE | PacketFlags::FIN),
        ),
        forged_payload,
    );
    let forged_wire = server_session
        .protect_packet(&forged_fin)
        .expect("mask the forgery with the real send key");
    to_client_tx
        .send(Bytes::from(forged_wire))
        .await
        .expect("send forged FIN");

    // (3) The authentic frame — first reliable frame server→client on this stream, so
    // its gap-free stream offset is 0.
    let genuine_header = PacketHeader::new(
        session_id,
        target,
        3,
        PacketFlags::new(PacketFlags::ENCRYPTED | PacketFlags::RELIABLE),
    )
    .with_epoch(server_session.current_epoch());
    let mut genuine_plaintext = 0u32.to_be_bytes().to_vec();
    genuine_plaintext.extend_from_slice(b"authentic");
    let ciphertext = server_session
        .encrypt_packet(&genuine_header, &genuine_plaintext, &[])
        .expect("seal the authentic frame");
    let genuine_wire = server_session
        .protect_packet(&PhantomPacket::new(genuine_header, ciphertext))
        .expect("protect the authentic frame");
    to_client_tx
        .send(Bytes::from(genuine_wire))
        .await
        .expect("send authentic frame");

    // The pipe is FIFO and the reader task drains it in order, so a delivered
    // authentic payload proves both forgeries were seen and disposed of first. The
    // timeout is only there so that a build which swallowed the frame fails instead
    // of hanging.
    let delivered = tokio::time::timeout(Duration::from_secs(10), app_stream.recv())
        .await
        .expect("the authentic frame is delivered")
        .expect("recv")
        .expect("the stream is open, so this is data and not a peer FIN");
    assert_eq!(
        delivered, b"authentic",
        "the forged unencrypted frame must not reach the application"
    );

    // (4) The other half of what a forged FIN would have done. Not delivering its
    // bytes is only one of the two effects the gate prevents; the other is the FIN
    // itself, which half-closes the stream and makes everything after it unreachable.
    // A second authentic frame is what separates "the forged bytes were discarded"
    // from "the forged FIN was not acted on" — a receiver that did the first but not
    // the second returns `Ok(None)` here. Its prefix is 1, not the byte length of the
    // frame before it: the `[stream_offset: u32 BE]` field the reliable path reorders
    // on counts segments, one per frame, whatever each one carries.
    let second_header = PacketHeader::new(
        session_id,
        target,
        4,
        PacketFlags::new(PacketFlags::ENCRYPTED | PacketFlags::RELIABLE),
    )
    .with_epoch(server_session.current_epoch());
    let mut second_plaintext = 1u32.to_be_bytes().to_vec();
    second_plaintext.extend_from_slice(b"still-open");
    let second_ciphertext = server_session
        .encrypt_packet(&second_header, &second_plaintext, &[])
        .expect("seal the follow-up frame");
    let second_wire = server_session
        .protect_packet(&PhantomPacket::new(second_header, second_ciphertext))
        .expect("protect the follow-up frame");
    to_client_tx
        .send(Bytes::from(second_wire))
        .await
        .expect("send follow-up frame");

    let after_fin = tokio::time::timeout(Duration::from_secs(10), app_stream.recv())
        .await
        .expect("a follow-up frame arrives")
        .expect("recv");
    assert_eq!(
        after_fin.as_deref(),
        Some(&b"still-open"[..]),
        "the forged FIN must not have half-closed the stream — `None` here is the \
         peer's EOF, released from a FIN that was never authenticated"
    );

    // The counter is what separates "the gate refused something" from "nothing ever
    // arrived" — the two are otherwise indistinguishable from outside. It is asserted
    // as a floor rather than as an exact figure on purpose: today it reads exactly 1,
    // because forgery (1) is refused one layer earlier by header protection, whose
    // mask needs a 16-byte ciphertext sample an empty payload cannot supply
    // (`Session::hp_sample`). Which layer catches the empty case is that layer's
    // business and is pinned with it; pinning it here would turn a change in the
    // header-protection minimum into a failure of an invariant-2 test.
    let dropped = session.metrics_snapshot().unencrypted_dropped_total;
    assert!(
        dropped >= 1,
        "the ENCRYPTED gate never fired, so nothing above shows the forgery was \
         refused rather than lost (unencrypted_dropped_total = {dropped})"
    );
}

/// **Invariant 2, for the close frame.** A `CONTROL` frame that arrives without
/// `ENCRYPTED` must not end a session.
///
/// This is the one new attack surface the close frame opens, and it is the reason the
/// receive branch sits below the AEAD gate rather than above it. Above the gate, a
/// single short datagram — a header, a `CONTROL` flag and one plaintext byte — sent by
/// anyone who can guess a connection id would tear down a live session. Below it, the
/// forgery is refused before anything reads its subtype, because a frame that no key
/// sealed is not a frame the peer sent.
///
/// The liveness probe afterwards is the two-sidedness: a receive path that dropped
/// *everything* would satisfy any assertion about the forgery alone. The authentic
/// frame delivered after it proves the session survived rather than that the pipe went
/// quiet, and the drop counter separates "refused" from "never arrived".
#[tokio::test]
async fn forged_unencrypted_close_frame_cannot_end_a_session() {
    use phantom_protocol::api::PhantomSession;
    use phantom_protocol::transport::handshake::ServerReply;

    let (to_client_tx, to_client_rx) = tokio::sync::mpsc::channel::<Bytes>(64);
    let (to_server_tx, mut to_server_rx) = tokio::sync::mpsc::channel::<Bytes>(64);
    let client_transport = PipeTransport {
        to_peer: to_server_tx,
        from_peer: tokio::sync::Mutex::new(to_client_rx),
    };

    let server_hs = HandshakeServer::new().expect("server handshake state");
    let pinned = server_hs.verifying_key().clone();
    let session = PhantomSession::connect_with_transport("pipe-peer:0", client_transport, pinned);

    let client_ip = "127.0.0.1".parse().expect("client ip");
    let server_session = loop {
        let hello_bytes = to_server_rx.recv().await.expect("client hello");
        let hello = borsh::from_slice::<ClientHello>(&hello_bytes).expect("decode client hello");
        match server_hs.process_client_hello(&hello, 0, client_ip) {
            HandshakeResponse::Retry(retry) => {
                let wire = ServerReply::Retry(retry).to_wire().expect("encode retry");
                to_client_tx
                    .send(Bytes::from(wire))
                    .await
                    .expect("send retry");
            }
            HandshakeResponse::Success(server_hello, negotiated, _) => {
                let wire = ServerReply::Hello(server_hello)
                    .to_wire()
                    .expect("encode server hello");
                to_client_tx
                    .send(Bytes::from(wire))
                    .await
                    .expect("send server hello");
                break negotiated;
            }
            HandshakeResponse::Reject(r) => panic!("server rejected its own client: {r:?}"),
            HandshakeResponse::Fail(e) => panic!("handshake failed: {e:?}"),
        }
    };

    session
        .await_ready()
        .await
        .expect("the pinned handshake completes");
    let session_id = *server_session.id();
    let app_stream = session.open_stream().expect("open a stream");
    let target: u16 = app_stream
        .stream_id()
        .try_into()
        .expect("a locally-opened stream id fits the wire field");

    // The forgery. Its payload IS its plaintext (nothing sealed it), laid out exactly
    // as the control path reads one — the close subtype first — so that a branch which
    // ran above the AEAD gate would find a well-formed close and act on it. Sixteen
    // bytes because that is the smallest ciphertext sample header protection can mask
    // against; anything shorter is refused a layer earlier and would prove nothing
    // about this gate.
    let mut forged_body = vec![ControlSubtype::CLOSE];
    forged_body.resize(16, 0);
    let forged = PhantomPacket::new(
        PacketHeader::new(
            session_id,
            target,
            1,
            PacketFlags::new(PacketFlags::CONTROL),
        ),
        forged_body,
    );
    let forged_wire = server_session
        .protect_packet(&forged)
        .expect("mask the forgery with the real send key");
    to_client_tx
        .send(Bytes::from(forged_wire))
        .await
        .expect("send forged close");

    // The liveness probe: first reliable frame server→client on this stream, so its
    // gap-free stream offset is 0.
    let genuine_header = PacketHeader::new(
        session_id,
        target,
        2,
        PacketFlags::new(PacketFlags::ENCRYPTED | PacketFlags::RELIABLE),
    )
    .with_epoch(server_session.current_epoch());
    let mut genuine_plaintext = 0u32.to_be_bytes().to_vec();
    genuine_plaintext.extend_from_slice(b"still-here");
    let ciphertext = server_session
        .encrypt_packet(&genuine_header, &genuine_plaintext, &[])
        .expect("seal the authentic frame");
    let genuine_wire = server_session
        .protect_packet(&PhantomPacket::new(genuine_header, ciphertext))
        .expect("protect the authentic frame");
    to_client_tx
        .send(Bytes::from(genuine_wire))
        .await
        .expect("send authentic frame");

    // The pipe is FIFO and the reader drains it in order, so a delivered authentic
    // payload proves the forgery was seen and disposed of first. The timeout is only
    // there so that a build which tore the session down fails instead of hanging.
    let delivered = tokio::time::timeout(Duration::from_secs(10), app_stream.recv())
        .await
        .expect("the session is still alive after the forged close")
        .expect("recv")
        .expect("the stream is open, so this is data and not a peer FIN");
    assert_eq!(
        delivered, b"still-here",
        "a forged unencrypted close must not end the session"
    );

    let dropped = session.metrics_snapshot().unencrypted_dropped_total;
    assert!(
        dropped >= 1,
        "the ENCRYPTED gate never fired, so nothing above shows the forged close was \
         refused rather than lost (unencrypted_dropped_total = {dropped})"
    );
}

/// An authenticated close does not discard what is behind it, and the window in which
/// it does not is **bounded**.
///
/// Both halves are one property and neither is safe alone. The close is not
/// `RELIABLE`, carries no stream offset and is never acknowledged, so nothing re-sends
/// data it overtakes; a receiver that tore down on the first copy would destroy bytes
/// the peer's `send()` had already returned `Ok` for, silently at both ends. But a
/// receiver that simply kept reading would have turned an unacknowledged one-byte
/// frame into a way for a peer to decide how long this side holds a session's
/// resources. So it drains: it keeps reading for a window it computes itself, and
/// then it goes.
///
/// The two frames go down a FIFO pipe in the order a reordering path would deliver
/// them — close first, data behind it — and the stream's own `recv()` is the barrier
/// proving the close was processed before the data was read. The teardown assertion
/// afterwards is what stops this from passing on a build that never closes at all.
#[tokio::test]
async fn an_authenticated_close_drains_trailing_data_and_then_ends_the_session() {
    use phantom_protocol::api::session::ConnectionState;
    use phantom_protocol::api::PhantomSession;
    use phantom_protocol::transport::handshake::ServerReply;

    let (to_client_tx, to_client_rx) = tokio::sync::mpsc::channel::<Bytes>(64);
    let (to_server_tx, mut to_server_rx) = tokio::sync::mpsc::channel::<Bytes>(64);
    let client_transport = PipeTransport {
        to_peer: to_server_tx,
        from_peer: tokio::sync::Mutex::new(to_client_rx),
    };

    let server_hs = HandshakeServer::new().expect("server handshake state");
    let pinned = server_hs.verifying_key().clone();
    let session = PhantomSession::connect_with_transport("pipe-peer:0", client_transport, pinned);

    let client_ip = "127.0.0.1".parse().expect("client ip");
    let server_session = loop {
        let hello_bytes = to_server_rx.recv().await.expect("client hello");
        let hello = borsh::from_slice::<ClientHello>(&hello_bytes).expect("decode client hello");
        match server_hs.process_client_hello(&hello, 0, client_ip) {
            HandshakeResponse::Retry(retry) => {
                let wire = ServerReply::Retry(retry).to_wire().expect("encode retry");
                to_client_tx
                    .send(Bytes::from(wire))
                    .await
                    .expect("send retry");
            }
            HandshakeResponse::Success(server_hello, negotiated, _) => {
                let wire = ServerReply::Hello(server_hello)
                    .to_wire()
                    .expect("encode server hello");
                to_client_tx
                    .send(Bytes::from(wire))
                    .await
                    .expect("send server hello");
                break negotiated;
            }
            HandshakeResponse::Reject(r) => panic!("server rejected its own client: {r:?}"),
            HandshakeResponse::Fail(e) => panic!("handshake failed: {e:?}"),
        }
    };

    session
        .await_ready()
        .await
        .expect("the pinned handshake completes");
    let session_id = *server_session.id();
    let app_stream = session.open_stream().expect("open a stream");
    let target: u16 = app_stream
        .stream_id()
        .try_into()
        .expect("a locally-opened stream id fits the wire field");

    // The close, sealed by the real key. Deliberately unpadded: a receiver must not
    // require `PADDED` — the flag means only "a trailer is present" — so this is also
    // the conformance case for a peer whose shaping policy differs from ours.
    let close_header = PacketHeader::new(
        session_id,
        1,
        1,
        PacketFlags::new(PacketFlags::ENCRYPTED | PacketFlags::CONTROL),
    )
    .with_epoch(server_session.current_epoch());
    let close_ct = server_session
        .encrypt_packet(&close_header, &[ControlSubtype::CLOSE], &[])
        .expect("seal the close frame");
    let close_wire = server_session
        .protect_packet(&PhantomPacket::new(close_header, close_ct))
        .expect("protect the close frame");
    to_client_tx
        .send(Bytes::from(close_wire))
        .await
        .expect("send close");

    // The data the close overtook: first reliable frame server→client on this stream,
    // so its gap-free stream offset is 0.
    let data_header = PacketHeader::new(
        session_id,
        target,
        2,
        PacketFlags::new(PacketFlags::ENCRYPTED | PacketFlags::RELIABLE),
    )
    .with_epoch(server_session.current_epoch());
    let mut data_plaintext = 0u32.to_be_bytes().to_vec();
    data_plaintext.extend_from_slice(b"behind-the-close");
    let data_ct = server_session
        .encrypt_packet(&data_header, &data_plaintext, &[])
        .expect("seal the trailing frame");
    let data_wire = server_session
        .protect_packet(&PhantomPacket::new(data_header, data_ct))
        .expect("protect the trailing frame");
    to_client_tx
        .send(Bytes::from(data_wire))
        .await
        .expect("send trailing data");

    let delivered = tokio::time::timeout(Duration::from_secs(10), app_stream.recv())
        .await
        .expect("data behind an authenticated close is still delivered")
        .expect("recv")
        .expect("the stream is open, so this is data and not a peer FIN");
    assert_eq!(
        delivered, b"behind-the-close",
        "a close that overtook a data frame must not discard it"
    );

    // …and the draining window ends. Polled rather than slept on so the assertion is
    // "this happens", not "this happens at time T": the window is derived from the
    // session's own round-trip measurement, so its length is not a constant this test
    // is entitled to know. The cap is far above any value the window can take.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while session.connection_state() != ConnectionState::Closed
        && std::time::Instant::now() < deadline
    {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(
        session.connection_state(),
        ConnectionState::Closed,
        "the draining window must be bounded — a session that keeps reading after its \
         peer left is a resource a peer decided to hold"
    );
}

/// While a session is draining its peer's close, **no API returns `Ok` for a payload
/// it will not send**, and every accessor that describes the session agrees about it.
///
/// The draining window removed a silent data loss on the receive side and, left at
/// that, would have installed the same defect on the send side. For the 200–600 ms
/// the window lasts the pump refuses application writes — it has to, the peer's
/// session is over — and the API in front of it kept reporting `Connected`,
/// data-ready, nothing queued, no error, and returned `Ok(())` for every byte the
/// pump then dropped. A caller in any of the four bound languages had no way to learn
/// its write was discarded, which is the thing the window was built to stop.
///
/// So the session publishes `ConnectionState::Draining` at the packet that carried
/// the close, and this pins the whole surface against it at once: the state, the
/// readiness answer derived from it, the session write, the stream writes, the queue
/// depth, the readiness wait and the error slot. They are asserted together on
/// purpose — the failure this reproduces was not any one of them being wrong, it was
/// four of them agreeing with each other and disagreeing with the pump.
///
/// The final assertion that the window still ends is what stops this passing on a
/// build that simply never leaves `Draining`: refusing every write forever would
/// satisfy everything above it and would be a worse session than the one it replaced.
#[tokio::test]
async fn a_draining_session_refuses_writes_instead_of_discarding_them_behind_an_ok() {
    use phantom_protocol::api::session::ConnectionState;
    use phantom_protocol::api::PhantomSession;
    use phantom_protocol::transport::handshake::ServerReply;
    use phantom_protocol::CoreError;

    let (to_client_tx, to_client_rx) = tokio::sync::mpsc::channel::<Bytes>(64);
    let (to_server_tx, mut to_server_rx) = tokio::sync::mpsc::channel::<Bytes>(64);
    let client_transport = PipeTransport {
        to_peer: to_server_tx,
        from_peer: tokio::sync::Mutex::new(to_client_rx),
    };

    let server_hs = HandshakeServer::new().expect("server handshake state");
    let pinned = server_hs.verifying_key().clone();
    let session = PhantomSession::connect_with_transport("pipe-peer:0", client_transport, pinned);

    let client_ip = "127.0.0.1".parse().expect("client ip");
    let server_session = loop {
        let hello_bytes = to_server_rx.recv().await.expect("client hello");
        let hello = borsh::from_slice::<ClientHello>(&hello_bytes).expect("decode client hello");
        match server_hs.process_client_hello(&hello, 0, client_ip) {
            HandshakeResponse::Retry(retry) => {
                let wire = ServerReply::Retry(retry).to_wire().expect("encode retry");
                to_client_tx
                    .send(Bytes::from(wire))
                    .await
                    .expect("send retry");
            }
            HandshakeResponse::Success(server_hello, negotiated, _) => {
                let wire = ServerReply::Hello(server_hello)
                    .to_wire()
                    .expect("encode server hello");
                to_client_tx
                    .send(Bytes::from(wire))
                    .await
                    .expect("send server hello");
                break negotiated;
            }
            HandshakeResponse::Reject(r) => panic!("server rejected its own client: {r:?}"),
            HandshakeResponse::Fail(e) => panic!("handshake failed: {e:?}"),
        }
    };

    session
        .await_ready()
        .await
        .expect("the pinned handshake completes");

    // Everything below the close has to be true of a healthy session first, or the
    // assertions after it would be satisfied by a session that was never usable.
    assert_eq!(session.connection_state(), ConnectionState::Connected);
    assert!(session.is_data_ready());
    let app_stream = session.open_stream().expect("open a stream");
    session
        .send(b"before-the-close".to_vec())
        .await
        .expect("a connected session accepts a write");

    let session_id = *server_session.id();
    let close_header = PacketHeader::new(
        session_id,
        1,
        1,
        PacketFlags::new(PacketFlags::ENCRYPTED | PacketFlags::CONTROL),
    )
    .with_epoch(server_session.current_epoch());
    let close_ct = server_session
        .encrypt_packet(&close_header, &[ControlSubtype::CLOSE], &[])
        .expect("seal the close frame");
    let close_wire = server_session
        .protect_packet(&PhantomPacket::new(close_header, close_ct))
        .expect("protect the close frame");
    to_client_tx
        .send(Bytes::from(close_wire))
        .await
        .expect("send close");

    // Poll rather than sleep: the state has to be published at the packet, not at the
    // send loop's next tick, and a sleep long enough to hide that difference is
    // exactly the interval the defect lived in. The cap is far above the window.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while session.connection_state() != ConnectionState::Draining
        && std::time::Instant::now() < deadline
    {
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    assert_eq!(
        session.connection_state(),
        ConnectionState::Draining,
        "a session whose peer has announced its close must say so; reporting Connected \
         while the pump discards every write is the silent loss this window exists to \
         remove, moved to the other direction"
    );
    assert!(
        !session.is_data_ready(),
        "data-ready must not claim a session can carry data the pump will discard"
    );

    match session.send(b"after-the-close".to_vec()).await {
        Err(CoreError::ConnectionClosed) => {}
        Err(other) => panic!("send() while draining must be ConnectionClosed, got {other:?}"),
        Ok(()) => panic!(
            "send() returned Ok for a payload the pump discards — the caller has no \
             way to learn its write was dropped"
        ),
    }
    match app_stream.send_reliable(b"after-the-close".to_vec()).await {
        Err(CoreError::ConnectionClosed) => {}
        Err(other) => {
            panic!("stream send_reliable while draining must be ConnectionClosed, got {other:?}")
        }
        Ok(()) => {
            panic!("a stream write reaches the same pump and must be refused the same way")
        }
    }
    match app_stream
        .send_unreliable(b"after-the-close".to_vec())
        .await
    {
        Err(CoreError::ConnectionClosed) => {}
        Err(other) => {
            panic!("stream send_unreliable while draining must be ConnectionClosed, got {other:?}")
        }
        Ok(()) => panic!("an unreliable stream write is discarded by the same arm"),
    }
    match app_stream.disconnect().await {
        Err(CoreError::ConnectionClosed) => {}
        Err(other) => {
            panic!("stream disconnect while draining must be ConnectionClosed, got {other:?}")
        }
        Ok(()) => panic!("the FIN is a reliable write and the peer will never see it"),
    }

    assert_eq!(
        session.queued_count().await,
        0,
        "a refused write must not be queued either — a non-zero depth here would mean \
         bytes are waiting for a pump that will never send them"
    );
    match session.await_ready().await {
        Err(CoreError::ConnectionClosed) => {}
        other => {
            panic!("await_ready() must not report a draining session ready to send; got {other:?}")
        }
    }
    assert!(
        session.last_error().await.is_none(),
        "a peer leaving in an orderly way is not a failure, and reporting one would be \
         as misleading in the other direction"
    );

    // The window is still bounded. Without this, refusing every write forever would
    // satisfy every assertion above.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while session.connection_state() != ConnectionState::Closed
        && std::time::Instant::now() < deadline
    {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(
        session.connection_state(),
        ConnectionState::Closed,
        "draining must end; a session that never leaves it is a resource the peer holds"
    );
}

/// A frame stamped at the **previous** wire version is dropped before the flag
/// dispatch, so it can neither end a session nor reach an application.
///
/// This is the mechanism the version-pairing rule actually rests on, and it is worth
/// a test because the natural way to describe that rule is the wrong way round. The
/// tempting story is that an older peer *misreads* a newer frame — that a `CONTROL`
/// frame it has no branch for falls through to its data path and its subtype byte
/// arrives at the caller as a byte of the stream. It does not: the version check is
/// step 1 of the receive dispatch and nothing downstream of it runs. What the older
/// peer does instead is drop the whole flow — every data-plane packet carries the
/// version byte — so it completes a handshake and then moves nothing, with no error
/// at either end. That, and not corruption, is why `PROTOCOL_VERSION` moves with
/// `WIRE_VERSION`: it converts a silent total stall into a typed refusal before a
/// session exists.
///
/// The close subtype is the sharpest probe available for it, because acting on that
/// one byte is the most consequential thing a receiver could do with a frame it was
/// never meant to see.
#[tokio::test]
async fn a_previous_wire_version_frame_is_dropped_before_the_flag_dispatch() {
    use phantom_protocol::api::session::ConnectionState;
    use phantom_protocol::api::PhantomSession;
    use phantom_protocol::transport::handshake::ServerReply;

    let (to_client_tx, to_client_rx) = tokio::sync::mpsc::channel::<Bytes>(64);
    let (to_server_tx, mut to_server_rx) = tokio::sync::mpsc::channel::<Bytes>(64);
    let client_transport = PipeTransport {
        to_peer: to_server_tx,
        from_peer: tokio::sync::Mutex::new(to_client_rx),
    };

    let server_hs = HandshakeServer::new().expect("server handshake state");
    let pinned = server_hs.verifying_key().clone();
    let session = PhantomSession::connect_with_transport("pipe-peer:0", client_transport, pinned);

    let client_ip = "127.0.0.1".parse().expect("client ip");
    let server_session = loop {
        let hello_bytes = to_server_rx.recv().await.expect("client hello");
        let hello = borsh::from_slice::<ClientHello>(&hello_bytes).expect("decode client hello");
        match server_hs.process_client_hello(&hello, 0, client_ip) {
            HandshakeResponse::Retry(retry) => {
                let wire = ServerReply::Retry(retry).to_wire().expect("encode retry");
                to_client_tx
                    .send(Bytes::from(wire))
                    .await
                    .expect("send retry");
            }
            HandshakeResponse::Success(server_hello, negotiated, _) => {
                let wire = ServerReply::Hello(server_hello)
                    .to_wire()
                    .expect("encode server hello");
                to_client_tx
                    .send(Bytes::from(wire))
                    .await
                    .expect("send server hello");
                break negotiated;
            }
            HandshakeResponse::Reject(r) => panic!("server rejected its own client: {r:?}"),
            HandshakeResponse::Fail(e) => panic!("handshake failed: {e:?}"),
        }
    };

    session
        .await_ready()
        .await
        .expect("the pinned handshake completes");
    let session_id = *server_session.id();
    let app_stream = session.open_stream().expect("open a stream");
    let target: u16 = app_stream
        .stream_id()
        .try_into()
        .expect("a locally-opened stream id fits the wire field");

    // A close sealed by the real key, and correct in every respect except its version
    // byte — stamped before the seal, so the AEAD it carries is self-consistent at the
    // older version and the frame is refused by the version check rather than by a tag
    // mismatch. That is the whole point: it is the version alone that refuses it.
    let mut close_header = PacketHeader::new(
        session_id,
        1,
        1,
        PacketFlags::new(PacketFlags::ENCRYPTED | PacketFlags::CONTROL),
    )
    .with_epoch(server_session.current_epoch());
    close_header.version = WIRE_VERSION - 1;
    let close_ct = server_session
        .encrypt_packet(&close_header, &[ControlSubtype::CLOSE], &[])
        .expect("seal the previous-version close");
    let close_wire = server_session
        .protect_packet(&PhantomPacket::new(close_header, close_ct))
        .expect("protect the previous-version close");
    to_client_tx
        .send(Bytes::from(close_wire))
        .await
        .expect("send previous-version close");

    // The probe behind it, at the current version. The pipe is FIFO and the reader
    // drains it in order, so a delivered payload proves the older frame was seen and
    // disposed of first rather than still sitting unread.
    let data_header = PacketHeader::new(
        session_id,
        target,
        2,
        PacketFlags::new(PacketFlags::ENCRYPTED | PacketFlags::RELIABLE),
    )
    .with_epoch(server_session.current_epoch());
    let mut data_plaintext = 0u32.to_be_bytes().to_vec();
    data_plaintext.extend_from_slice(b"still-here");
    let data_ct = server_session
        .encrypt_packet(&data_header, &data_plaintext, &[])
        .expect("seal the probe");
    let data_wire = server_session
        .protect_packet(&PhantomPacket::new(data_header, data_ct))
        .expect("protect the probe");
    to_client_tx
        .send(Bytes::from(data_wire))
        .await
        .expect("send probe");

    let delivered = tokio::time::timeout(Duration::from_secs(10), app_stream.recv())
        .await
        .expect("the session survives a previous-version frame")
        .expect("recv")
        .expect("the stream is open, so this is data and not a peer FIN");
    assert_eq!(
        delivered, b"still-here",
        "a previous-version frame must be dropped, not delivered and not acted on"
    );

    // Long enough that a close which *had* been acted on would have finished draining
    // and published `Closed`, which is the state this asserts the absence of. The
    // ceiling on the draining window is well under a second.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(
        session.connection_state(),
        ConnectionState::Connected,
        "a close stamped at the previous wire version must not end the session — the \
         version check runs before anything reads a flag"
    );
}

/// **A cross-variant peer is answered, not left to time out (Invariant 10).**
///
/// `ClientHello.protocol_variant` carries the build's `PROTOCOL_VARIANT` tag, so a fips
/// peer meeting a non-fips one is caught before any KEM or signature work. What happened
/// to the peer afterwards was the problem: the refusal was a `HandshakeResponse::Fail`,
/// which the listener answers by closing without a reply, so over TCP the client saw a
/// bare connection error and over PhantomUDP — where there is no close to observe — it
/// retransmitted until its handshake deadline and reported `Timeout`. A timeout is the
/// shape of failure a typed refusal exists to replace: it names no cause, and the cause
/// here is a compile-time property of the two builds that no retry can change.
///
/// This drives the refusal all the way onto the wire through the real listener, because
/// that is the half that was missing: the server's decision was already typed, and it was
/// the reply that never left.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cross_variant_peer_is_answered_rather_than_left_to_time_out() {
    use phantom_protocol::api::PhantomListener;
    use phantom_protocol::transport::handshake::{
        ServerReply, PROTOCOL_VARIANT, REJECT_PROTOCOL_VARIANT,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = PhantomListener::bind("127.0.0.1:0".to_string())
        .await
        .unwrap();
    let addr = listener.local_addr();
    // The acceptor is lazily spawned by the first `accept()`; nothing here ever completes
    // a handshake, so this task exists only to start it.
    let accepting = tokio::spawn(async move { listener.accept().await });

    let client = HandshakeClient::new().unwrap();
    let mut hello = client.create_client_hello();
    assert_eq!(
        hello.protocol_variant, PROTOCOL_VARIANT,
        "a hello from this build advertises this build's variant"
    );
    hello.protocol_variant = b"phantom-some-other-mode-1".to_vec();
    let body = borsh::to_vec(&hello).unwrap();

    let mut sock = tokio::net::TcpStream::connect(addr).await.unwrap();
    // The stream transport's framing: a 4-byte big-endian length, then the message.
    sock.write_all(&(body.len() as u32).to_be_bytes())
        .await
        .unwrap();
    sock.write_all(&body).await.unwrap();
    sock.flush().await.unwrap();

    let mut len_buf = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(10), sock.read_exact(&mut len_buf))
        .await
        .expect("the server must answer a cross-variant hello, not close in silence")
        .expect("read the reply length");
    let len = u32::from_be_bytes(len_buf) as usize;
    assert!(
        len > 0 && len < 4096,
        "a reject is a handful of bytes: {len}"
    );
    let mut reply = vec![0u8; len];
    tokio::time::timeout(Duration::from_secs(10), sock.read_exact(&mut reply))
        .await
        .expect("the reply body follows its length")
        .expect("read the reply body");

    match ServerReply::from_wire(&reply).expect("the reply is a well-formed server reply") {
        ServerReply::Reject(reject) => {
            assert!(
                reject.has_marker(),
                "the reject must carry its integrity tag, or the client discards it"
            );
            assert_eq!(
                reject.code, REJECT_PROTOCOL_VARIANT,
                "the code must say the variant was the problem, not the version — they \
                 call for different actions and only one of them is retryable"
            );
            assert_eq!(
                reject.supported_version, PROTOCOL_VERSION,
                "the field is defined as the version this server speaks, which is still true"
            );
        }
        other => panic!("a cross-variant hello must be answered with a reject, got {other:?}"),
    }

    accepting.abort();
}

/// **The cross-variant refusal reaches the client as a typed error, not a timeout.**
///
/// The companion to the test above, from the other end: given a server that answers with
/// the variant reject, the client must surface [`CoreError::ProtocolRejected`] — the
/// documented typed form of this failure — and must surface it promptly, rather than
/// waiting out the handshake deadline. Asserting the variant rather than the message is
/// deliberate: the error string a client builds for a reject still speaks of versions, and
/// what an embedder branches on is the variant.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cross_variant_refusal_reaches_the_client_as_a_typed_error() {
    use phantom_protocol::api::session::SessionTransport;
    use phantom_protocol::api::PhantomSession;
    use phantom_protocol::transport::handshake::{ServerReject, ServerReply};
    use phantom_protocol::CoreError;

    /// Answers every hello with the variant reject, exactly as a server of the other
    /// build now does, and counts the hellos so the client's refusal cannot be mistaken
    /// for it never having sent one.
    struct AlwaysRejectsTheVariant {
        hellos: Arc<std::sync::atomic::AtomicU32>,
        reply: Vec<u8>,
    }
    impl SessionTransport for AlwaysRejectsTheVariant {
        async fn send_bytes(&self, _data: &[u8]) -> Result<(), CoreError> {
            self.hellos
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }
        async fn recv_bytes(&self) -> Result<Bytes, CoreError> {
            Ok(Bytes::from(self.reply.clone()))
        }
    }

    let hellos = Arc::new(std::sync::atomic::AtomicU32::new(0));
    let transport = AlwaysRejectsTheVariant {
        hellos: hellos.clone(),
        reply: ServerReply::Reject(ServerReject::protocol_variant_mismatch())
            .to_wire()
            .unwrap(),
    };
    let (_sk, server_key) = HybridSigningKey::generate();

    // The pin is required (Invariant 1) and never reached: the refusal comes before a
    // `ServerHello` this key could be checked against.
    let session = PhantomSession::connect_with_transport("127.0.0.1:4242", transport, server_key);

    // The client's own handshake deadline is ten seconds. A bound below it is what makes
    // this a test of the refusal rather than of the deadline: a reject that never reached
    // the client would leave this waiting, and waiting is the defect.
    let outcome = tokio::time::timeout(Duration::from_secs(5), session.await_ready())
        .await
        .expect("a refused handshake must resolve well inside the handshake deadline");
    match outcome {
        Err(CoreError::ProtocolRejected(_)) => {}
        other => panic!(
            "a cross-variant refusal must surface as ProtocolRejected — the variant an \
             embedder branches on — got {other:?}"
        ),
    }
    assert!(
        hellos.load(std::sync::atomic::Ordering::SeqCst) >= 1,
        "the client must have sent a hello for the reject to be a refusal of anything"
    );
    assert!(
        matches!(
            session.last_error().await,
            Some(CoreError::ProtocolRejected(_))
        ),
        "the terminal error is captured, so a caller that missed await_ready still sees it"
    );
}

/// **Over PhantomUDP too: the cross-variant refusal is a reply, not a silence.**
///
/// This is the direction the defect showed worst. A datagram transport has no close for a
/// client to observe, so a refusal that is not sent is indistinguishable from a lost
/// packet: the client retransmitted its hello on the handshake schedule and then reported
/// `Timeout`, which says a peer did not answer — while the peer had in fact decided, at the
/// first field it read, that it never would.
///
/// The hello is driven raw so the variant can be foreign in a single-build test. It takes
/// the cookie round first, because over UDP the source is unproven and the address
/// validation runs ahead of everything, which also means the refusal below is sent to an
/// address that has already echoed an IP-bound cookie — not to a spoofable one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cross_variant_peer_over_udp_is_answered_rather_than_left_to_time_out() {
    use phantom_protocol::api::udp_listener::PhantomUdpListener;
    use phantom_protocol::transport::handshake::{ServerReply, REJECT_PROTOCOL_VARIANT};
    use phantom_protocol::transport::phantom_udp::datagram::encode_datagrams;
    use phantom_protocol::transport::phantom_udp::envelope::{decode_header, PacketType, PATH_MTU};
    use tokio::net::UdpSocket;

    let listener = PhantomUdpListener::bind_udp("127.0.0.1:0".to_string())
        .await
        .expect("bind_udp");
    let server_addr: std::net::SocketAddr = listener.local_addr().parse().unwrap();
    let acceptor = listener.clone();
    // The demux is started by the first `accept()`; nothing here completes a handshake.
    let accepting = tokio::spawn(async move { acceptor.accept().await });

    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sock.connect(server_addr).await.unwrap();
    let cid: [u8; 8] = [0xA5; 8];

    /// Reads datagrams until one carries a whole single-datagram server reply. Every reply
    /// this exchange can produce — a retry and a reject — is far inside one datagram, so a
    /// fragmented one is a reply to something else and is skipped.
    async fn next_reply(sock: &UdpSocket) -> ServerReply {
        let mut buf = vec![0u8; PATH_MTU + 64];
        for _ in 0..16 {
            let n = tokio::time::timeout(Duration::from_secs(10), sock.recv(&mut buf))
                .await
                .expect("the server must answer; a silence here is the defect itself")
                .expect("recv");
            let Ok((hdr, frame)) = decode_header(&buf[..n]) else {
                continue;
            };
            if hdr.fragmented {
                continue;
            }
            if let Ok(reply) = ServerReply::from_wire(frame) {
                return reply;
            }
        }
        panic!("no single-datagram server reply arrived");
    }

    let client = HandshakeClient::new().unwrap();
    let mut hello = client.create_client_hello();
    hello.protocol_variant = b"phantom-some-other-mode-1".to_vec();
    for d in encode_datagrams(
        PacketType::Initial,
        &cid,
        0,
        &borsh::to_vec(&hello).unwrap(),
    )
    .expect("encode the first flight")
    {
        sock.send(&d).await.unwrap();
    }

    // Address validation comes first: an unproven source gets a cookie demand, and the
    // variant is not looked at until the source has answered it.
    let cookie = match next_reply(&sock).await {
        ServerReply::Retry(retry) => retry
            .cookie
            .expect("the address-validation round demands a cookie"),
        other => panic!("an unvalidated UDP source must get the cookie round first: {other:?}"),
    };

    hello.cookie = Some(cookie);
    for d in encode_datagrams(
        PacketType::Initial,
        &cid,
        1,
        &borsh::to_vec(&hello).unwrap(),
    )
    .expect("encode the cookie-bearing flight")
    {
        sock.send(&d).await.unwrap();
    }

    match next_reply(&sock).await {
        ServerReply::Reject(reject) => {
            assert!(
                reject.has_marker(),
                "the reject must carry its integrity tag"
            );
            assert_eq!(
                reject.code, REJECT_PROTOCOL_VARIANT,
                "the code must say the variant was the problem"
            );
        }
        other => panic!(
            "a cross-variant hello from a validated UDP source must be refused on the wire, \
             not dropped — dropping it is what produced a client-side Timeout. Got {other:?}"
        ),
    }

    accepting.abort();
}
