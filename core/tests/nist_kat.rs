//! Real NIST ACVP known-answer tests for the post-quantum primitives.
//!
//! Unlike `cavp.rs` (which round-trips ML-KEM/ML-DSA against *themselves*), this
//! pins the `ml-kem` / `ml-dsa` crates against **published byte-exact NIST
//! vectors** (FIPS 203 / FIPS 204, from the NIST ACVP-Server project). It is the
//! gate that catches an encoding/arithmetic regression from a crate-version swap
//! — e.g. the `ml-dsa` `rc.11 → 0.1.0` move — which a self-referential
//! round-trip cannot see.
//!
//! Vectors live under `core/tests/nist_kat/*.json` (trimmed ACVP
//! `internalProjection.json` files; each carries its `_source` URL). They are
//! U.S. Government work (public domain). Regenerate/extend by re-trimming the
//! upstream files.
//!
//! Coverage:
//!   * **ML-KEM-768** — keyGen `(d,z) → (ek,dk)`, encaps `(ek,m) → (c,k)`, decaps
//!     `(dk,c) → k` (incl. the implicit-reject VAL cases), all byte-exact, via the
//!     `deterministic` feature. Plus a tamper guard.
//!   * **ML-DSA-65** — keyGen `seed → pk` byte-exact, and `verify` of real NIST
//!     `(pk, msg, ctx, signature)` (accept) with a 1-byte-tampered signature
//!     (reject). NB: `ml-dsa 0.1.0`'s `SigningKey` is seed-based and exposes no
//!     FIPS-204 encoded-`sk` decode, so the ACVP `sigGen` `sk` cannot be loaded to
//!     byte-match a *generated* signature; the verify-side KAT consumes the real
//!     NIST signature instead.

use std::path::PathBuf;

use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, Keypair, MlDsa65, Signature as MlDsaSignature,
    SigningKey as MlDsaSigningKey, VerifyingKey as MlDsaVerifyingKey, B32 as DsaB32,
};
use ml_kem::kem::Decapsulate;
use ml_kem::{
    Ciphertext, EncapsulateDeterministic, Encoded, EncodedSizeUser, KemCore, MlKem768, B32,
};
use serde_json::Value;

type EncapKey = <MlKem768 as KemCore>::EncapsulationKey;
type DecapKey = <MlKem768 as KemCore>::DecapsulationKey;

// ─── fixture / hex helpers ──────────────────────────────────────────────────

fn load(name: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/nist_kat")
        .join(name);
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("read {name}: {e}"));
    serde_json::from_slice(&bytes).unwrap_or_else(|e| panic!("parse {name}: {e}"))
}

/// `(group, test)` pairs flattened across all test groups in a vector file.
fn cases(doc: &Value) -> Vec<(&Value, &Value)> {
    let mut out = Vec::new();
    for g in doc["testGroups"].as_array().expect("testGroups") {
        for t in g["tests"].as_array().expect("tests") {
            out.push((g, t));
        }
    }
    out
}

fn hx(v: &Value, key: &str) -> Vec<u8> {
    hex::decode(
        v[key]
            .as_str()
            .unwrap_or_else(|| panic!("missing hex field {key}")),
    )
    .unwrap_or_else(|e| panic!("bad hex in {key}: {e}"))
}

fn b32(bytes: &[u8]) -> B32 {
    B32::try_from(bytes).expect("expected 32 bytes")
}

/// ML-DSA carries its own `hybrid-array` `B32`, distinct from ml-kem's.
fn dsa_b32(bytes: &[u8]) -> DsaB32 {
    DsaB32::try_from(bytes).expect("expected 32 bytes")
}

// ─── ML-KEM-768 (FIPS 203) ──────────────────────────────────────────────────

#[test]
fn ml_kem_768_keygen_kat() {
    let doc = load("ml_kem_768_keygen.json");
    let mut n = 0;
    for (_g, t) in cases(&doc) {
        let (d, z) = (hx(t, "d"), hx(t, "z"));
        let (dk, ek) = MlKem768::generate_deterministic(&b32(&d), &b32(&z));
        assert_eq!(
            ek.as_bytes().as_slice(),
            hx(t, "ek").as_slice(),
            "ML-KEM-768 keyGen ek mismatch (tcId {})",
            t["tcId"]
        );
        assert_eq!(
            dk.as_bytes().as_slice(),
            hx(t, "dk").as_slice(),
            "ML-KEM-768 keyGen dk mismatch (tcId {})",
            t["tcId"]
        );
        n += 1;
    }
    assert!(n >= 3, "expected several keyGen cases, got {n}");
}

#[test]
fn ml_kem_768_encaps_kat() {
    let doc = load("ml_kem_768_encap_decap.json");
    let mut n = 0;
    for (g, t) in cases(&doc) {
        if g["function"] != "encapsulation" {
            continue;
        }
        let ek_enc = Encoded::<EncapKey>::try_from(hx(t, "ek").as_slice()).expect("ek size");
        let ek = EncapKey::from_bytes(&ek_enc);
        let (c, k) = ek
            .encapsulate_deterministic(&b32(&hx(t, "m")))
            .expect("ML-KEM-768 deterministic encaps");
        assert_eq!(
            c.as_slice(),
            hx(t, "c").as_slice(),
            "encaps c (tcId {})",
            t["tcId"]
        );
        assert_eq!(
            k.as_slice(),
            hx(t, "k").as_slice(),
            "encaps k (tcId {})",
            t["tcId"]
        );
        n += 1;
    }
    assert!(n >= 1, "expected encaps cases");
}

#[test]
fn ml_kem_768_decaps_kat() {
    // The VAL "decapsulation" group includes modified-ciphertext cases whose
    // expected `k` is the FIPS-203 implicit-reject value — so this also pins the
    // implicit-rejection path, not just the happy path.
    let doc = load("ml_kem_768_encap_decap.json");
    let mut n = 0;
    for (g, t) in cases(&doc) {
        if g["function"] != "decapsulation" {
            continue;
        }
        let dk_enc = Encoded::<DecapKey>::try_from(hx(t, "dk").as_slice()).expect("dk size");
        let dk = DecapKey::from_bytes(&dk_enc);
        let ct = Ciphertext::<MlKem768>::try_from(hx(t, "c").as_slice()).expect("ct size");
        let k = dk.decapsulate(&ct).expect("ML-KEM-768 decaps");
        assert_eq!(
            k.as_slice(),
            hx(t, "k").as_slice(),
            "decaps k (tcId {})",
            t["tcId"]
        );
        n += 1;
    }
    assert!(n >= 1, "expected decaps VAL cases");
}

#[test]
fn ml_kem_768_kat_tamper_is_caught() {
    // A 1-byte change to an expected key-gen output must make the vector fail —
    // proves the assertions are real, not vacuous.
    let doc = load("ml_kem_768_keygen.json");
    let (_g, t) = cases(&doc)[0];
    let (dk, _ek) = MlKem768::generate_deterministic(&b32(&hx(t, "d")), &b32(&hx(t, "z")));
    let mut tampered = hx(t, "dk");
    tampered[0] ^= 0x01;
    assert_ne!(
        dk.as_bytes().as_slice(),
        tampered.as_slice(),
        "a tampered expected dk must not match"
    );
}

// ─── ML-DSA-65 (FIPS 204) ───────────────────────────────────────────────────

#[test]
fn ml_dsa_65_keygen_pk_kat() {
    let doc = load("ml_dsa_65_keygen.json");
    let mut n = 0;
    for (_g, t) in cases(&doc) {
        let sk = MlDsaSigningKey::<MlDsa65>::from_seed(&dsa_b32(&hx(t, "seed")));
        assert_eq!(
            sk.verifying_key().encode().as_slice(),
            hx(t, "pk").as_slice(),
            "ML-DSA-65 keyGen pk mismatch (tcId {})",
            t["tcId"]
        );
        n += 1;
    }
    assert!(n >= 3, "expected several keyGen cases, got {n}");
}

#[test]
fn ml_dsa_65_verify_kat() {
    // External / deterministic / pure ACVP sigGen vectors: verify the *real* NIST
    // signature under the real NIST public key + context (accept), and a 1-byte
    // tampered signature (reject). This byte-consumes the NIST pk + signature, so
    // a regression in the verify path or the pk/signature encoding fails here.
    let doc = load("ml_dsa_65_siggen.json");
    let mut n = 0;
    for (_g, t) in cases(&doc) {
        let pk_enc =
            EncodedVerifyingKey::<MlDsa65>::try_from(hx(t, "pk").as_slice()).expect("pk size");
        let vk = MlDsaVerifyingKey::<MlDsa65>::decode(&pk_enc);
        let msg = hx(t, "message");
        let ctx = hx(t, "context");

        let sig_bytes = hx(t, "signature");
        let sig_enc =
            EncodedSignature::<MlDsa65>::try_from(sig_bytes.as_slice()).expect("sig size");
        let sig = MlDsaSignature::<MlDsa65>::decode(&sig_enc).expect("decode NIST signature");
        assert!(
            vk.verify_with_context(&msg, &ctx, &sig),
            "ML-DSA-65 must accept the real NIST signature (tcId {})",
            t["tcId"]
        );

        // Tamper: flip one byte; the result must NOT verify (either it fails to
        // decode, or it decodes and verification returns false).
        let mut bad = sig_bytes.clone();
        bad[0] ^= 0x01;
        let accepted = EncodedSignature::<MlDsa65>::try_from(bad.as_slice())
            .ok()
            .and_then(|e| MlDsaSignature::<MlDsa65>::decode(&e))
            .is_some_and(|s| vk.verify_with_context(&msg, &ctx, &s));
        assert!(
            !accepted,
            "a tampered NIST signature must be rejected (tcId {})",
            t["tcId"]
        );
        n += 1;
    }
    assert!(n >= 1, "expected sigGen verify cases");
}
