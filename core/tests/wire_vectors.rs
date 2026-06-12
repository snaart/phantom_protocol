//! Byte-exact wire-format vectors — the wire-stability freeze (Phase 6).
//!
//! Every other protocol test drives Rust types ↔ Rust types (in-proc or
//! loopback), so both ends move together: a layout, endianness, or
//! discriminant regression in the hand-rolled packet codec
//! ([`PacketHeader::to_wire`]) or in `borsh` (handshake messages) passes
//! silently. These vectors are the only test in the repo that pins the
//! *bytes*. Each case asserts two directions:
//!
//!   * **encode** — `serialize(value) == fixture`, and
//!   * **decode** — `deserialize(fixture)` reconstructs the same value
//!     (direct `PartialEq` where the type derives it; canonical re-encode plus
//!     field spot-checks for the borsh handshake structs, which do not).
//!
//! The fixtures live in `core/tests/wire_vectors/*.bin` and are committed. A
//! change to any on-wire byte fails CI; an *intentional* wire change is landed
//! by bumping `WIRE_VERSION` / `PROTOCOL_VERSION` and regenerating:
//!
//! ```sh
//! PHANTOM_REGEN_WIRE_VECTORS=1 cargo test --manifest-path core/Cargo.toml \
//!     --test wire_vectors
//! ```
//!
//! The crypto material in the handshake vectors is deterministic *filler* of
//! the real field lengths (1184-byte ML-KEM-768 encap key, 1088-byte
//! ciphertext, 1952-byte ML-DSA-65 verifying key, 3309-byte signature, …), not
//! a valid KEM/signature. This freezes the serialization *container*; the PQ
//! encodings themselves are validated against published NIST KATs separately.
//! The transcript-hash freeze (real `compute_transcript_hash` over real borsh) is a
//! `#[cfg(test)]` unit test inside `transport::handshake`, which can reach the
//! private transcript type.
//!
//! Scoped to the default (non-fips) build: the fips build is a distinct wire
//! (different `PROTOCOL_VARIANT`, 65-byte classical KEM key) and would need its
//! own vector set. Under `--features fips` this test compiles to nothing.
#![cfg(not(feature = "fips"))]

use std::fs;
use std::path::PathBuf;

use phantom_protocol::crypto::hybrid_kem::{HybridCiphertext, HybridKeyPackage};
use phantom_protocol::crypto::hybrid_sign::{HybridSignature, HybridVerifyingKey};
use phantom_protocol::crypto::pow::{PoWChallenge, PoWSolution};
use phantom_protocol::transport::handshake::{
    ClientHello, HelloRetryRequest, ServerHello, PROTOCOL_VARIANT, PROTOCOL_VERSION,
};
use phantom_protocol::transport::types::{
    PacketFlags, PacketHeader, PhantomPacket, SessionId, WIRE_VERSION,
};

// ─── Deterministic filler ──────────────────────────────────────────────────
//
// A distinct `seed` per field makes a cross-field copy bug visible in a
// hexdump and gives the independent decoder (`tests/wire_vectors_decode.py`)
// recognisable, recomputable bytes.

/// `n` bytes ramping from `seed` (wrapping) — `seed, seed+1, seed+2, …`.
fn pat(seed: u8, n: usize) -> Vec<u8> {
    (0..n).map(|i| seed.wrapping_add(i as u8)).collect()
}

/// 32-byte ramp from `seed`.
fn arr32(seed: u8) -> [u8; 32] {
    pat(seed, 32)
        .try_into()
        .expect("pat(seed, 32) is exactly 32 bytes")
}

// Canonical field lengths for the default (non-fips) build.
const ML_KEM_PK_LEN: usize = 1184; // FIPS-203 ML-KEM-768 encapsulation key
const ML_KEM_CT_LEN: usize = 1088; // FIPS-203 ML-KEM-768 ciphertext
const ML_DSA_PK_LEN: usize = 1952; // FIPS-204 ML-DSA-65 verifying key
const ML_DSA_SIG_LEN: usize = 3309; // FIPS-204 ML-DSA-65 signature
const CLASSICAL_PK_LEN: usize = 32; // X25519 public key

fn sample_key_package() -> HybridKeyPackage {
    HybridKeyPackage {
        classical_pk: arr32(0x10),
        ml_kem_pk: pat(0x20, ML_KEM_PK_LEN),
    }
}

fn sample_ciphertext() -> HybridCiphertext {
    HybridCiphertext {
        classical_pk: arr32(0x30),
        ml_kem_ct: pat(0x40, ML_KEM_CT_LEN),
    }
}

fn sample_verify_key() -> HybridVerifyingKey {
    HybridVerifyingKey {
        ed25519_pk: arr32(0x50),
        ml_dsa_pk: pat(0x60, ML_DSA_PK_LEN),
    }
}

fn sample_signature() -> HybridSignature {
    HybridSignature {
        ed25519_sig: pat(0x70, 64)
            .try_into()
            .expect("pat(_, 64) is exactly 64 bytes"),
        ml_dsa_sig: pat(0x80, ML_DSA_SIG_LEN),
    }
}

fn sample_pow_challenge() -> PoWChallenge {
    PoWChallenge {
        nonce: arr32(0x90),
        difficulty: 20,
    }
}

fn sample_pow_solution() -> PoWSolution {
    PoWSolution {
        nonce: arr32(0x90),
        solution: 0x0123_4567_89AB_CDEF,
    }
}

fn sample_client_hello_minimal() -> ClientHello {
    ClientHello {
        client_key_package: sample_key_package(),
        client_verify_key: sample_verify_key(),
        nonce: arr32(0xA0),
        version: PROTOCOL_VERSION,
        cookie: None,
        pow_solution: None,
        resume_session_id: None,
        resumption_binder: None,
        protocol_variant: PROTOCOL_VARIANT.to_vec(),
        early_data: None,
    }
}

fn sample_client_hello_full() -> ClientHello {
    ClientHello {
        client_key_package: sample_key_package(),
        client_verify_key: sample_verify_key(),
        nonce: arr32(0xA0),
        version: PROTOCOL_VERSION,
        cookie: Some(arr32(0xB0)),
        pow_solution: Some(sample_pow_solution()),
        resume_session_id: Some(arr32(0xC0)),
        resumption_binder: Some(arr32(0xC8)),
        protocol_variant: PROTOCOL_VARIANT.to_vec(),
        early_data: Some(pat(0xD0, 48)),
    }
}

fn sample_server_hello(accepted: bool) -> ServerHello {
    ServerHello {
        server_nonce: arr32(0x70),
        ciphertext: sample_ciphertext(),
        server_verify_key: sample_verify_key(),
        signature: sample_signature(),
        session_id: arr32(0xE0),
        early_data_accepted: accepted,
    }
}

fn sample_hrr_cookie() -> HelloRetryRequest {
    HelloRetryRequest {
        challenge: None,
        cookie: Some(arr32(0xF0)),
    }
}

fn sample_hrr_pow() -> HelloRetryRequest {
    HelloRetryRequest {
        challenge: Some(sample_pow_challenge()),
        cookie: None,
    }
}

fn sample_header() -> PacketHeader {
    PacketHeader::new(
        SessionId::from_bytes(arr32(0x01)),
        7,
        42,
        PacketFlags::new(PacketFlags::ENCRYPTED | PacketFlags::RELIABLE),
    )
    .with_epoch(3)
    .with_path_id(1)
}

fn sample_packet_data() -> PhantomPacket {
    PhantomPacket::new(sample_header(), pat(0x11, 64))
}

fn sample_packet_ack() -> PhantomPacket {
    PhantomPacket::ack(SessionId::from_bytes(arr32(0x01)), 7, 42)
}

fn sample_packet_ext() -> PhantomPacket {
    let mut p = PhantomPacket::new(sample_header(), pat(0x11, 16));
    p.extensions = vec![0xFF, 0x01, 0x00, 0x04, b't', b'e', b's', b't'];
    p
}

// ─── wire / borsh encoders ───────────────────────────────────────────────────

fn ser_header(h: &PacketHeader) -> Vec<u8> {
    h.to_wire().to_vec()
}

fn ser_packet(p: &PhantomPacket) -> Vec<u8> {
    p.to_wire()
}

fn ser_borsh<T: borsh::BorshSerialize>(v: &T) -> Vec<u8> {
    borsh::to_vec(v).expect("borsh serialize")
}

// ─── fixture I/O + freeze assertion ─────────────────────────────────────────

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/wire_vectors")
}

fn regen() -> bool {
    std::env::var_os("PHANTOM_REGEN_WIRE_VECTORS").is_some()
}

/// Pretty index of the first differing byte, for actionable failures.
fn first_diff(a: &[u8], b: &[u8]) -> String {
    let n = a.len().min(b.len());
    for i in 0..n {
        if a[i] != b[i] {
            return format!(
                "first diff at byte {i}: got 0x{:02x}, fixture 0x{:02x}",
                a[i], b[i]
            );
        }
    }
    format!(
        "identical for first {n} bytes; lengths differ ({} vs {})",
        a.len(),
        b.len()
    )
}

/// Assert `actual` equals the committed fixture `name`, or (re)write it when
/// `PHANTOM_REGEN_WIRE_VECTORS` is set. Returns the canonical fixture bytes so
/// the caller can run its decode check against exactly what is on disk.
fn freeze(name: &str, actual: &[u8]) -> Vec<u8> {
    let path = fixtures_dir().join(name);
    if regen() {
        fs::create_dir_all(fixtures_dir()).expect("create wire_vectors dir");
        fs::write(&path, actual).expect("write fixture");
        eprintln!("regenerated {name} ({} bytes)", actual.len());
        return actual.to_vec();
    }
    let expected = fs::read(&path).unwrap_or_else(|e| {
        panic!("missing wire-vector fixture {name}: {e}\nregenerate with PHANTOM_REGEN_WIRE_VECTORS=1 cargo test --test wire_vectors")
    });
    assert_eq!(
        actual,
        expected.as_slice(),
        "wire bytes changed for {name} ({}). This is a WIRE-BREAKING change: \
         if intentional, bump WIRE_VERSION/PROTOCOL_VERSION and regenerate with \
         PHANTOM_REGEN_WIRE_VECTORS=1.",
        first_diff(actual, &expected),
    );
    expected
}

// ─── packet vectors (hand-rolled big-endian codec) ──────────────────────────

#[test]
fn vector_packet_header() {
    let h = sample_header();
    let bytes = ser_header(&h);
    assert_eq!(
        bytes.len(),
        PacketHeader::SIZE,
        "header is the AEAD AAD; must be exactly {} bytes",
        PacketHeader::SIZE
    );
    let frozen = freeze("packet_header.bin", &bytes);
    let decoded = PacketHeader::from_wire(&frozen).expect("decode packet header");
    assert_eq!(decoded, h);
    assert_eq!(decoded.version, WIRE_VERSION);
    assert_eq!(decoded.stream_id, 7);
    assert_eq!(decoded.packet_number, 42);
    assert_eq!(decoded.epoch, 3);
    assert_eq!(decoded.path_id, 1);
}

#[test]
fn vector_phantom_packet_data() {
    let p = sample_packet_data();
    let frozen = freeze("phantom_packet_data.bin", &ser_packet(&p));
    let decoded = PhantomPacket::from_wire(&frozen).expect("decode data packet");
    assert_eq!(decoded, p);
    assert_eq!(decoded.payload, pat(0x11, 64));
    assert!(decoded.extensions.is_empty());
}

#[test]
fn vector_phantom_packet_ack() {
    let p = sample_packet_ack();
    let frozen = freeze("phantom_packet_ack.bin", &ser_packet(&p));
    let decoded = PhantomPacket::from_wire(&frozen).expect("decode ack packet");
    assert_eq!(decoded, p);
    assert!(decoded.header.flags.is_ack());
    assert!(decoded.payload.is_empty());
}

#[test]
fn vector_phantom_packet_extensions() {
    let p = sample_packet_ext();
    let frozen = freeze("phantom_packet_extensions.bin", &ser_packet(&p));
    let decoded = PhantomPacket::from_wire(&frozen).expect("decode ext packet");
    assert_eq!(decoded, p);
    assert_eq!(
        decoded.extensions,
        vec![0xFF, 0x01, 0x00, 0x04, b't', b'e', b's', b't']
    );
}

// ─── handshake vectors (borsh) ──────────────────────────────────────────────
//
// The handshake structs do not derive PartialEq, so the decode check is
// canonical-re-encode (borsh has exactly one encoding per value) plus field
// spot-checks.

fn roundtrip_borsh<T: borsh::BorshSerialize + borsh::BorshDeserialize>(name: &str, value: &T) -> T {
    let frozen = freeze(name, &ser_borsh(value));
    let decoded: T = borsh::from_slice(&frozen).expect("borsh decode");
    assert_eq!(
        ser_borsh(&decoded),
        frozen,
        "borsh re-encode of the decoded {name} must reproduce the fixture"
    );
    decoded
}

#[test]
fn vector_hybrid_key_package() {
    let v = sample_key_package();
    let d = roundtrip_borsh("hybrid_key_package.bin", &v);
    assert_eq!(d.classical_pk.len(), CLASSICAL_PK_LEN);
    assert_eq!(d.ml_kem_pk.len(), ML_KEM_PK_LEN);
}

#[test]
fn vector_hybrid_ciphertext() {
    let v = sample_ciphertext();
    let d = roundtrip_borsh("hybrid_ciphertext.bin", &v);
    assert_eq!(d.classical_pk.len(), CLASSICAL_PK_LEN);
    assert_eq!(d.ml_kem_ct.len(), ML_KEM_CT_LEN);
}

#[test]
fn vector_hybrid_verifying_key() {
    let v = sample_verify_key();
    // HybridVerifyingKey derives PartialEq/Eq — use direct equality.
    let frozen = freeze("hybrid_verifying_key.bin", &ser_borsh(&v));
    let decoded: HybridVerifyingKey = borsh::from_slice(&frozen).expect("decode vk");
    assert_eq!(decoded, v);
    assert_eq!(decoded.ml_dsa_pk.len(), ML_DSA_PK_LEN);
}

#[test]
fn vector_hybrid_signature() {
    let v = sample_signature();
    let d = roundtrip_borsh("hybrid_signature.bin", &v);
    assert_eq!(d.ed25519_sig.len(), 64);
    assert_eq!(d.ml_dsa_sig.len(), ML_DSA_SIG_LEN);
}

#[test]
fn vector_pow_challenge() {
    let v = sample_pow_challenge();
    let d = roundtrip_borsh("pow_challenge.bin", &v);
    assert_eq!(d.difficulty, 20);
    assert_eq!(d.nonce, arr32(0x90));
}

#[test]
fn vector_pow_solution() {
    let v = sample_pow_solution();
    let d = roundtrip_borsh("pow_solution.bin", &v);
    assert_eq!(d.solution, 0x0123_4567_89AB_CDEF);
}

#[test]
fn vector_client_hello_minimal() {
    let v = sample_client_hello_minimal();
    let d = roundtrip_borsh("client_hello_minimal.bin", &v);
    assert_eq!(d.version, PROTOCOL_VERSION);
    assert_eq!(d.protocol_variant, PROTOCOL_VARIANT.to_vec());
    assert!(d.cookie.is_none());
    assert!(d.pow_solution.is_none());
    assert!(d.resume_session_id.is_none());
    assert!(d.early_data.is_none());
    assert_eq!(d.client_key_package.ml_kem_pk.len(), ML_KEM_PK_LEN);
}

#[test]
fn vector_client_hello_full() {
    let v = sample_client_hello_full();
    let d = roundtrip_borsh("client_hello_full.bin", &v);
    assert_eq!(d.version, PROTOCOL_VERSION);
    assert_eq!(d.protocol_variant, PROTOCOL_VARIANT.to_vec());
    assert!(d.cookie.is_some());
    assert!(d.pow_solution.is_some());
    assert!(d.resume_session_id.is_some());
    assert_eq!(d.early_data.as_deref(), Some(pat(0xD0, 48).as_slice()));
}

#[test]
fn vector_server_hello() {
    let v = sample_server_hello(true);
    let d = roundtrip_borsh("server_hello.bin", &v);
    assert!(d.early_data_accepted);
    assert_eq!(d.ciphertext.ml_kem_ct.len(), ML_KEM_CT_LEN);
    assert_eq!(d.signature.ml_dsa_sig.len(), ML_DSA_SIG_LEN);
}

#[test]
fn vector_server_hello_rejected() {
    let v = sample_server_hello(false);
    let d = roundtrip_borsh("server_hello_rejected.bin", &v);
    assert!(!d.early_data_accepted);
}

#[test]
fn vector_hello_retry_request_cookie() {
    let v = sample_hrr_cookie();
    let d = roundtrip_borsh("hello_retry_request_cookie.bin", &v);
    assert!(d.challenge.is_none());
    assert_eq!(d.cookie, Some(arr32(0xF0)));
}

#[test]
fn vector_hello_retry_request_pow() {
    let v = sample_hrr_pow();
    let d = roundtrip_borsh("hello_retry_request_pow.bin", &v);
    assert!(d.cookie.is_none());
    assert_eq!(d.challenge.as_ref().map(|c| c.difficulty), Some(20));
}
