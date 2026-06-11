//! Property-based tests (Phase 6.5).
//!
//! Where `core/tests/security_invariants.rs` pins specific named cases
//! ("a bit-flipped ciphertext must be rejected"), this file exercises the
//! same boundaries against **random inputs** to catch the cases we did not
//! think to enumerate.
//!
//! Tested properties (proptest):
//! - AEAD round-trip: for any plaintext + secret + AAD, `decrypt(encrypt(x)) == x`.
//! - AEAD AAD binding: with the same key but different AAD, decrypt fails.
//! - `ReplayWindow.accept`: a strictly increasing sequence is always accepted,
//!   and a duplicate is always rejected.
//! - Wire format round-trip: any `PhantomPacket` survives `to_wire` /
//!   `from_wire` with all fields preserved.
//!
//! Defaults to 1024 cases per property; turn the dial via
//! `PROPTEST_CASES=10000 cargo test --test property`.

use phantom_protocol::crypto::adaptive_crypto::{CipherSuite, CryptoSession};
use phantom_protocol::security::ReplayWindow;
use phantom_protocol::transport::session::{CryptoState, Session, MAX_REKEY_CATCHUP};
use phantom_protocol::transport::types::{
    PacketFlags, PacketHeader, PhantomPacket, SchedulerMode, SessionId, WIRE_VERSION,
};
use proptest::prelude::*;

/// Build a paired (client, server) `Session` from a shared secret — the same
/// deterministic HKDF orientation both ends derive at handshake.
fn session_pair(secret: [u8; 32]) -> (Session, Session) {
    let id = SessionId::from_bytes([0x5Au8; 32]);
    (
        Session::from_derived(
            id,
            CryptoState::new(&secret, false).expect("client crypto"),
            SchedulerMode::LowLatency,
            secret,
            false,
        ),
        Session::from_derived(
            id,
            CryptoState::new(&secret, true).expect("server crypto"),
            SchedulerMode::LowLatency,
            secret,
            true,
        ),
    )
}

// ── AEAD round-trip ────────────────────────────────────────────────────────

proptest! {
    /// For any (secret, plaintext, AAD), encrypting and then decrypting on a
    /// peer session must recover the plaintext bit-for-bit.
    #[test]
    fn aead_round_trip(
        secret in proptest::array::uniform32(any::<u8>()),
        plaintext in proptest::collection::vec(any::<u8>(), 0..2048),
        aad in proptest::collection::vec(any::<u8>(), 0..256),
    ) {
        let a = CryptoSession::with_suite(&secret, CipherSuite::Aes256Gcm)
            .expect("init send");
        let b = CryptoSession::with_suite_peer(&secret, CipherSuite::Aes256Gcm)
            .expect("init recv");
        let ct = a.encrypt(&aad, &plaintext).expect("encrypt");
        let pt = b.decrypt(&aad, &ct).expect("decrypt");
        prop_assert_eq!(pt, plaintext);
    }

    /// Decrypting with a different AAD must always fail (authenticated
    /// associated data is bound into the AEAD tag).
    #[test]
    fn aead_aad_mismatch_rejects(
        secret in proptest::array::uniform32(any::<u8>()),
        plaintext in proptest::collection::vec(any::<u8>(), 0..2048),
        aad in proptest::collection::vec(any::<u8>(), 1..256),
    ) {
        let a = CryptoSession::with_suite(&secret, CipherSuite::Aes256Gcm)
            .expect("init send");
        let b = CryptoSession::with_suite_peer(&secret, CipherSuite::Aes256Gcm)
            .expect("init recv");
        let ct = a.encrypt(&aad, &plaintext).expect("encrypt");
        // Flip one byte of AAD before decrypt.
        let mut bad_aad = aad.clone();
        bad_aad[0] ^= 0x01;
        prop_assert!(b.decrypt(&bad_aad, &ct).is_err());
    }
}

// ── ReplayWindow ───────────────────────────────────────────────────────────

proptest! {
    /// A strictly-increasing sequence is always fully accepted, regardless of
    /// the absolute values picked.
    #[test]
    fn replay_window_accepts_monotonic(
        starts in proptest::collection::vec(0u64..1_000_000_u64, 1..32),
    ) {
        let mut sorted = starts.clone();
        sorted.sort_unstable();
        sorted.dedup();
        let mut w = ReplayWindow::new();
        for seq in sorted {
            prop_assert!(w.accept(seq), "monotonic seq {} must be accepted", seq);
        }
    }

    /// The first time a sequence is presented it is accepted; the second time
    /// it is rejected (within the 1024-bit window).
    #[test]
    fn replay_window_rejects_duplicates(
        base in 1024u64..(u64::MAX / 2),
        // offset must be strictly positive — `offset == 0` would mean
        // `seq == base`, and `base` was already accepted on the first
        // call, so the "first time it shows up" precondition fails.
        offset in 1u64..1023,
    ) {
        let mut w = ReplayWindow::new();
        prop_assert!(w.accept(base));
        let seq = base - offset; // strictly within the window, strictly below base
        // First time within-window-out-of-order: accept.
        prop_assert!(w.accept(seq));
        // Same seq again: replay, reject.
        prop_assert!(!w.accept(seq));
    }
}

// ── Wire format round-trip ─────────────────────────────────────────────────

proptest! {
    /// Any PhantomPacket with arbitrary header field values must round-trip
    /// through `to_wire` / `from_wire` with every bit preserved.
    #[test]
    fn wire_round_trip_preserves_fields(
        sid_bytes in proptest::array::uniform32(any::<u8>()),
        stream_id in any::<u16>(),
        sequence in any::<u64>(),
        flags_bits in any::<u16>(),
        epoch in any::<u8>(),
        path_id in any::<u8>(),
        payload in proptest::collection::vec(any::<u8>(), 0..4096),
    ) {
        let header = PacketHeader::new(
            SessionId::from_bytes(sid_bytes),
            stream_id,
            sequence,
            PacketFlags::new(flags_bits),
        )
        .with_epoch(epoch)
        .with_path_id(path_id);
        let packet = PhantomPacket::new(header, payload.clone());

        let buf = packet.to_wire();
        let decoded =
            PhantomPacket::from_wire(&buf).expect("round-trip decode must succeed");

        prop_assert_eq!(decoded.header.version, WIRE_VERSION);
        prop_assert_eq!(decoded.header.stream_id, stream_id);
        prop_assert_eq!(decoded.header.packet_number, sequence);
        prop_assert_eq!(decoded.header.flags.0, flags_bits);
        prop_assert_eq!(decoded.header.epoch, epoch);
        prop_assert_eq!(decoded.header.path_id, path_id);
        prop_assert_eq!(decoded.payload, payload);
    }

    /// The `extensions` TLV headroom also round-trips byte-for-byte alongside
    /// the payload (both length-prefixed sections must be recovered).
    #[test]
    fn wire_round_trip_preserves_payload_and_extensions(
        sequence in any::<u64>(),
        payload in proptest::collection::vec(any::<u8>(), 0..1024),
        extensions in proptest::collection::vec(any::<u8>(), 0..512),
    ) {
        let header = PacketHeader::new(
            SessionId::from_bytes([0x11u8; 32]),
            3,
            sequence,
            PacketFlags::new(PacketFlags::ENCRYPTED),
        );
        let mut packet = PhantomPacket::new(header, payload.clone());
        packet.extensions = extensions.clone();

        let buf = packet.to_wire();
        let decoded = PhantomPacket::from_wire(&buf).expect("round-trip decode");
        prop_assert_eq!(decoded.payload, payload);
        prop_assert_eq!(decoded.extensions, extensions);
    }

    /// Robustness: `from_wire` on ARBITRARY bytes must return `Ok`/`Err`, never
    /// panic or read out of bounds. This is the always-on companion to the
    /// `fuzz_packet_parse` cargo-fuzz target — a malicious peer sending garbage
    /// must not crash the receive loop.
    #[test]
    fn from_wire_never_panics_on_arbitrary_bytes(
        buf in proptest::collection::vec(any::<u8>(), 0..8192),
    ) {
        // Whatever the verdict, the only property under test is "no panic".
        let _ = PhantomPacket::from_wire(&buf);
    }
}

// ── Mid-session rekey (C1) ─────────────────────────────────────────────────

proptest! {
    /// For ANY number of lock-step rekeys, both ends derive the same epoch key:
    /// the HKDF rekey chain is deterministic, so a packet encrypted after `n`
    /// rekeys decrypts on a peer that rekeyed `n` times. Catches any divergence
    /// in the `derive_forward_crypto` chain across the epoch range.
    #[test]
    fn rekey_chains_stay_in_lockstep(
        secret in proptest::array::uniform32(any::<u8>()),
        n in 0u8..40,
    ) {
        let (client, server) = session_pair(secret);
        for _ in 0..n {
            client.rekey().expect("client rekey");
            server.rekey().expect("server rekey");
        }
        prop_assert_eq!(client.current_epoch(), n);
        prop_assert_eq!(server.current_epoch(), n);

        let header = PacketHeader::new(
            *server.id(),
            1,
            1,
            PacketFlags::new(PacketFlags::ENCRYPTED),
        )
        .with_epoch(n);
        let ct = client.encrypt_packet(&header, b"chain").expect("encrypt");
        let pt = server.decrypt_packet(&header, &ct).expect("decrypt at matched epoch");
        prop_assert_eq!(pt, b"chain".to_vec());
    }

    /// For any forward gap within `MAX_REKEY_CATCHUP`, the receiver follows an
    /// authentic rekey via `decrypt_packet_accepting_rekey`: it trial-decrypts
    /// the candidate key `steps` epochs ahead, succeeds, and commits the ratchet.
    #[test]
    fn accepting_decrypt_follows_any_bounded_forward_step(
        secret in proptest::array::uniform32(any::<u8>()),
        steps in 1u8..=MAX_REKEY_CATCHUP,
    ) {
        let (client, server) = session_pair(secret);
        for _ in 0..steps {
            client.rekey().expect("client rekey");
        }
        let header = PacketHeader::new(
            *server.id(),
            1,
            1,
            PacketFlags::new(PacketFlags::ENCRYPTED | PacketFlags::REKEY),
        )
        .with_epoch(steps);
        let ct = client.encrypt_packet(&header, b"forward").expect("encrypt");
        let pt = server
            .decrypt_packet_accepting_rekey(&header, &ct)
            .expect("accepting decrypt follows a bounded forward step");
        prop_assert_eq!(pt, b"forward".to_vec());
        prop_assert_eq!(server.current_epoch(), steps);
    }
}
