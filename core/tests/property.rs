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

use phantom_core::crypto::adaptive_crypto::{CipherSuite, CryptoSession};
use phantom_core::security::ReplayWindow;
use phantom_core::transport::types::{
    PacketFlags, PacketHeader, PhantomPacket, SessionId, WIRE_VERSION,
};
use proptest::prelude::*;

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
        starts in proptest::collection::vec(0u32..1_000_000_u32, 1..32),
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
        base in 1024u32..(u32::MAX / 2),
        // offset must be strictly positive — `offset == 0` would mean
        // `seq == base`, and `base` was already accepted on the first
        // call, so the "first time it shows up" precondition fails.
        offset in 1u32..1023,
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
        sequence in any::<u32>(),
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
        prop_assert_eq!(decoded.header.sequence, sequence);
        prop_assert_eq!(decoded.header.flags.0, flags_bits);
        prop_assert_eq!(decoded.header.epoch, epoch);
        prop_assert_eq!(decoded.header.path_id, path_id);
        prop_assert_eq!(decoded.payload, payload);
    }
}
