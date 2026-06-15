//! CAVP-style known-answer-tests for Phantom Protocol's FIPS-approved primitives.
//!
//! Each test pins one primitive against a published reference vector (or, for
//! the PQ primitives exercised through Phantom Protocol's *hybrid* wrappers, a
//! deterministic end-to-end round-trip). The intent is the same as a NIST CAVP
//! submission: prove a regression in any of these primitives shows up as a hard
//! red here.
//!
//! The byte-exact **external** NIST ACVP KATs for the raw ML-KEM-768 / ML-DSA-65
//! primitives (which catch a crate-encoding regression a self-referential
//! round-trip cannot) live in `core/tests/nist_kat.rs`.
//!
//! Phase 5.4 MVP closure — `docs/PROGRESS.md`.

use hkdf::Hkdf;
use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, KeyInit, Keypair, MlDsa65, Signature as MlDsaSignature,
    SigningKey as MlDsaSigningKey, VerifyingKey as MlDsaVerifyingKey,
};
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{KemCore, MlKem768};
use phantom_protocol::crypto::hybrid_kem::HybridSecretKey;
use phantom_protocol::crypto::hybrid_sign::HybridSigningKey;
use rand::rngs::StdRng;
use rand::SeedableRng;
// AEAD backend mirrors the library's cfg dispatch (SUPPLY-03): `ring` on the
// default build, `aws-lc-rs` under `--features fips` — `ring` is not linked on
// the fips path, so importing it unconditionally here would break the fips
// build of this test.
#[cfg(feature = "fips")]
use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
#[cfg(not(feature = "fips"))]
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use sha2::{Digest, Sha256};

// ─── ML-KEM-768 (FIPS 203) ────────────────────────────────────────────────

/// Source: FIPS 203 §7.2 / §7.3 (ML-KEM.Encaps / ML-KEM.Decaps). The byte-exact
/// NIST ACVP KAT for the raw primitive lives in `core/tests/nist_kat.rs` (which
/// enables `ml-kem`'s `deterministic` feature). This test instead drives a
/// seeded `StdRng` (ChaCha-based CSPRNG, `CryptoRngCore`) through the standard
/// `KemCore::generate` + `Encapsulate` + `Decapsulate` path and asserts the
/// encap and decap sides recover the same shared secret — the FIPS 203
/// correctness invariant — and exercises Phantom Protocol's hybrid combiner end-to-end.
///
/// The same primitive sits inside `HybridSecretKey` (the X25519 + ML-KEM-768
/// hybrid that `crypto::hybrid_kem` builds the handshake on), and we also
/// exercise that wrapper end-to-end via `HybridSecretKey::generate` /
/// `HybridKeyPackage::encapsulate` / `HybridSecretKey::decapsulate` so a
/// regression in either the raw ML-KEM call or Phantom Protocol's hybrid combiner
/// surfaces here.
#[test]
fn ml_kem_768_encap_decap_kat() {
    // ── Raw ML-KEM-768 KAT-shaped round trip ───────────────────────────
    let mut rng = StdRng::from_seed([0xA5u8; 32]);
    let (dk, ek) = MlKem768::generate(&mut rng);
    let (ct, k_send) = ek.encapsulate(&mut rng).expect("ML-KEM-768 encapsulate");
    let k_recv = dk.decapsulate(&ct).expect("ML-KEM-768 decapsulate");
    assert_eq!(
        k_send.as_slice(),
        k_recv.as_slice(),
        "ML-KEM-768: encap and decap shared secrets must agree (FIPS 203 §7.3)"
    );
    // FIPS 203 ML-KEM-768 fixed sizes — ciphertext is 1088 bytes,
    // shared secret is 32 bytes.
    assert_eq!(
        ct.as_slice().len(),
        1088,
        "FIPS 203 ML-KEM-768 ciphertext length is 1088 bytes"
    );
    assert_eq!(
        k_send.as_slice().len(),
        32,
        "FIPS 203 ML-KEM-768 shared secret length is 32 bytes"
    );

    // ── Phantom Protocol hybrid wiring ──────────────────────────────────────────
    // The classical X25519 half is mixed in via HKDF-SHA256 with the
    // `HybridKEM_X25519_Kyber768` label (kept from V1 per `hybrid_kem.rs`).
    // Encap-side and decap-side must agree on the 32-byte hybrid secret.
    let (sk, pk) = HybridSecretKey::generate();
    let (ss_send, ciphertext) = pk.encapsulate().expect("Phantom hybrid encap");
    let ss_recv = sk.decapsulate(&ciphertext).expect("Phantom hybrid decap");
    assert_eq!(
        ss_send, ss_recv,
        "Phantom hybrid KEM: encap and decap must derive the same secret"
    );
}

// ─── ML-DSA-65 (FIPS 204) ─────────────────────────────────────────────────

/// Source: FIPS 204 §5 (ML-DSA.Sign / ML-DSA.Verify). The `ml-dsa 0.1-rc.11`
/// crate supports seeded keygen via `KeyInit::new(&seed)` (FIPS 204 algorithm 1,
/// `ML-DSA.KeyGen_internal`) but does NOT expose `sign_deterministic` on its
/// default surface, so the signature bytes themselves are not byte-matchable
/// against an external KAT (the signing path consumes fresh randomness for the
/// mask vector `y`). We pin the verification invariant instead: a signature
/// produced under a seed-derived key over a known message must verify, and
/// flipping a single byte of the message must fail verification. We exercise
/// both the raw `ml-dsa` API and Phantom Protocol's `HybridSigningKey` wrapper so a
/// regression in either lights up here.
#[test]
fn ml_dsa_65_sign_verify_kat() {
    // ── Raw ML-DSA-65 with a fixed seed ────────────────────────────────
    let seed = ml_dsa::B32::try_from(&[0x42u8; 32][..]).expect("32-byte ML-DSA seed");
    let sk: MlDsaSigningKey<MlDsa65> = MlDsaSigningKey::<MlDsa65>::new(&seed);
    let vk: MlDsaVerifyingKey<MlDsa65> = sk.verifying_key();

    let msg: &[u8] = b"FIPS-204 ML-DSA-65 KAT vector / phantom_protocol";
    let sig: MlDsaSignature<MlDsa65> = ml_dsa::Signer::sign(&sk, msg);

    // FIPS 204 ML-DSA-65 fixed sizes.
    assert_eq!(
        vk.encode().as_slice().len(),
        1952,
        "FIPS 204 ML-DSA-65 verifying-key encoding is 1952 bytes"
    );
    assert_eq!(
        sig.encode().as_slice().len(),
        3309,
        "FIPS 204 ML-DSA-65 signature encoding is 3309 bytes"
    );

    // Encode -> decode round-trip the signature & key, then verify.
    let sig_bytes = sig.encode();
    let vk_bytes = vk.encode();
    let vk_decoded =
        MlDsaVerifyingKey::<MlDsa65>::decode(&EncodedVerifyingKey::<MlDsa65>::from(vk_bytes));
    let sig_decoded =
        MlDsaSignature::<MlDsa65>::decode(&EncodedSignature::<MlDsa65>::from(sig_bytes))
            .expect("ML-DSA-65 signature decode");
    ml_dsa::Verifier::verify(&vk_decoded, msg, &sig_decoded)
        .expect("FIPS 204 ML-DSA-65: signature over the original message must verify");

    // Tamper: flipping a single message byte must break verification.
    let mut tampered = msg.to_vec();
    tampered[0] ^= 0x01;
    assert!(
        ml_dsa::Verifier::verify(&vk_decoded, &tampered, &sig_decoded).is_err(),
        "FIPS 204 ML-DSA-65: tampered message must NOT verify"
    );

    // ── Phantom Protocol hybrid wiring (Ed25519 + ML-DSA-65) ────────────────────
    // `HybridSigningKey::from_bytes` reconstructs both halves from a 64-byte
    // seed (32 bytes ed25519 + 32 bytes ML-DSA), per `hybrid_sign.rs`.
    let hybrid_seed = [0x33u8; 64];
    let hybrid_sk = HybridSigningKey::from_bytes(&hybrid_seed).expect("Phantom hybrid seed load");
    let hybrid_vk = hybrid_sk.verifying_key();
    let hybrid_sig = hybrid_sk.sign(msg);
    hybrid_vk
        .verify(msg, &hybrid_sig)
        .expect("Phantom hybrid signature over original message must verify");
    assert!(
        hybrid_vk.verify(&tampered, &hybrid_sig).is_err(),
        "Phantom hybrid signature over tampered message must NOT verify"
    );
}

// ─── AES-256-GCM (FIPS 197 + SP 800-38D) ─────────────────────────────────

/// Source: McGrew & Viega, "The Galois/Counter Mode of Operation (GCM)",
/// Test Case 13 — also referenced by NIST SP 800-38D. The vector is the
/// all-zero AES-256 key with the all-zero 96-bit IV, empty plaintext and
/// empty AAD; the spec mandates a ciphertext of `""` and a 16-byte
/// authentication tag of `530f8afbc74536b9a963b4f1c4cb738b`.
///
/// We exercise `ring::aead::AES_256_GCM` directly here (rather than
/// `phantom_protocol::crypto::adaptive_crypto::CryptoSession`) because the
/// Phantom Protocol wrapper derives its 32-byte AEAD key from a `shared_secret`
/// via `blake3::derive_key("phantom-aes-send-v1", ...)` and builds its
/// 12-byte nonce from a blake3-derived 4-byte prefix plus a u64 counter
/// — there is no public API surface that accepts a caller-supplied raw
/// AES key and raw 12-byte nonce. The primitive under test
/// (`AES_256_GCM`) is the same `ring` object Phantom Protocol passes to
/// `UnboundKey::new` (`adaptive_crypto.rs:188-191`), so a regression in
/// Phantom Protocol's AEAD backend would surface here too.
#[test]
fn aes_256_gcm_kat() {
    // Test Case 13 (McGrew & Viega, "GCM", §3.3).
    const KEY: [u8; 32] = [0u8; 32];
    const IV: [u8; 12] = [0u8; 12];
    const PT: &[u8] = b"";
    const AAD: &[u8] = b"";
    const EXPECTED_TAG: [u8; 16] = [
        0x53, 0x0f, 0x8a, 0xfb, 0xc7, 0x45, 0x36, 0xb9, 0xa9, 0x63, 0xb4, 0xf1, 0xc4, 0xcb, 0x73,
        0x8b,
    ];

    let unbound = UnboundKey::new(&AES_256_GCM, &KEY).expect("AES-256-GCM key install");
    let key = LessSafeKey::new(unbound);

    // Encrypt path: seal in place. With an empty plaintext, the resulting
    // buffer must equal exactly the 16-byte tag.
    let mut buf = PT.to_vec();
    let nonce = Nonce::assume_unique_for_key(IV);
    key.seal_in_place_append_tag(nonce, Aad::from(AAD), &mut buf)
        .expect("AES-256-GCM encrypt");
    assert_eq!(
        buf, EXPECTED_TAG,
        "GCM Test Case 13: ciphertext||tag must match the published value"
    );

    // Decrypt path: a correct tag opens cleanly to the (empty) plaintext.
    let nonce = Nonce::assume_unique_for_key(IV);
    let mut buf_ok = EXPECTED_TAG.to_vec();
    let pt = key
        .open_in_place(nonce, Aad::from(AAD), &mut buf_ok)
        .expect("AES-256-GCM decrypt with correct tag");
    assert!(
        pt.is_empty(),
        "GCM Test Case 13: plaintext must be empty after opening"
    );

    // Tampered tag must fail. Flip one bit of the last byte of the tag.
    let mut tampered = EXPECTED_TAG;
    tampered[15] ^= 0x01;
    let nonce = Nonce::assume_unique_for_key(IV);
    let mut buf_bad = tampered.to_vec();
    assert!(
        key.open_in_place(nonce, Aad::from(AAD), &mut buf_bad)
            .is_err(),
        "AES-256-GCM authenticity: tampered tag must NOT verify"
    );
}

// ─── HKDF-SHA256 (RFC 5869) ──────────────────────────────────────────────

/// Source: RFC 5869 §A.1 (Test Case 1) — HKDF-SHA256 with a 22-byte IKM, a
/// 13-byte salt, a 10-byte info, and L=42 output bytes. The published
/// OKM is included as a `const` byte array below; the test asserts byte
/// equality.
///
/// The Phantom-public `derive_early_data_keying` helper
/// (`crypto::kdf::derive_early_data_keying`) builds on top of this exact
/// primitive — `Hkdf::<Sha256>::new(salt, ikm).expand(info, &mut out)`,
/// see `kdf.rs:42-56`. We exercise the underlying `hkdf` crate directly
/// here because the helper is constrained to fixed labels and output
/// sizes; the dependency is the same one Phantom Protocol links against.
#[test]
fn hkdf_sha256_rfc5869_a1() {
    const IKM: [u8; 22] = [0x0b; 22];
    const SALT: [u8; 13] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
    ];
    const INFO: [u8; 10] = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
    const EXPECTED_OKM: [u8; 42] = [
        0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f,
        0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4,
        0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
    ];

    let hk = Hkdf::<Sha256>::new(Some(&SALT), &IKM);
    let mut okm = [0u8; 42];
    hk.expand(&INFO, &mut okm)
        .expect("HKDF-SHA256 expand to L=42 (well within 255*HashLen)");
    assert_eq!(
        okm, EXPECTED_OKM,
        "RFC 5869 §A.1: HKDF-SHA256 OKM must match the published value"
    );
}

// ─── SHA-256 (FIPS 180-4) ────────────────────────────────────────────────

/// Sources:
///   - FIPS 180-4 (§5.3.3, §A.2 / NIST SHAVS) — SHA-256 of the 3-byte
///     message "abc" is `ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad`.
///   - SHA-256 of the empty string is
///     `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` (the
///     canonical zero-length-input digest, also referenced in NIST CAVS
///     `SHA256ShortMsg.rsp` at Len=0).
///
/// SHA-256 is the hash inside Phantom Protocol's KDF (`hybrid_kem::combine_secrets`
/// and `kdf::derive_early_data_keying` both bind to `Hkdf::<Sha256>`), so a
/// regression in the `sha2` crate would silently break every key derivation
/// the handshake performs. Pinning both vectors here is cheap insurance.
#[test]
fn sha_256_kat() {
    const ABC_DIGEST: [u8; 32] = [
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22,
        0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00,
        0x15, 0xad,
    ];
    const EMPTY_DIGEST: [u8; 32] = [
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9,
        0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52,
        0xb8, 0x55,
    ];

    let abc = Sha256::digest(b"abc");
    assert_eq!(
        abc.as_slice(),
        ABC_DIGEST,
        "FIPS 180-4: SHA-256(\"abc\") must match the published digest"
    );

    let empty = Sha256::digest(b"");
    assert_eq!(
        empty.as_slice(),
        EMPTY_DIGEST,
        "NIST CAVS: SHA-256(\"\") must match the canonical digest"
    );
}
