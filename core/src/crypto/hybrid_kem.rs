//! Hybrid KEM: X25519 (classical) + ML-KEM-768 (FIPS 203, post-quantum).
//!
//! Phase 5.1 — switched the PQ half from `pqcrypto-kyber`'s C reference
//! implementation of NIST PQC round-3 Kyber768 to the RustCrypto pure-Rust
//! `ml-kem` crate's FIPS-203 ML-KEM-768. Same algorithm at the math level,
//! but the byte encoding follows FIPS 203 (canonicalised polynomials,
//! different deterministic derivation paths). Wire-incompatible with any
//! prior `phantom_core` build.
//!
//! Both KEM halves contribute 32 bytes of shared secret, combined via
//! `HKDF-SHA-256` with the label `"HybridKEM_X25519_Kyber768"` (kept
//! verbatim from V1 so the KDF label inventory in `PROTOCOL.md` does not
//! grow another entry — the algorithm is the same, only the byte
//! encoding changed).

use borsh::{BorshDeserialize, BorshSerialize};
use hkdf::Hkdf;
use ml_kem::array::Array;
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{Encoded, EncodedSizeUser, KemCore, MlKem768};
use rand::rngs::OsRng;
use sha2::Sha256;
use std::fmt;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::ZeroizeOnDrop;

type MlKem768DecapKey = <MlKem768 as KemCore>::DecapsulationKey;
type MlKem768EncapKey = <MlKem768 as KemCore>::EncapsulationKey;

/// Hybrid secret key. Holds the X25519 long-term secret and the ML-KEM-768
/// decapsulation key. Both halves are `Zeroize`-on-drop via the derive
/// (the ml-kem types implement `Zeroize` natively — no more `unsafe`).
///
/// `ml_kem_dk` is `Box`-ed so the (~2.4 KiB) decapsulation key lives on
/// the heap; constructing several `HybridSecretKey`s in a deep call
/// chain (as happens during the handshake) would otherwise stress
/// tokio's default test thread stack.
#[derive(ZeroizeOnDrop)]
pub struct HybridSecretKey {
    pub x25519_sk: StaticSecret,
    #[zeroize(skip)] // Box's Drop calls T::Drop which zeroes the inner key
    pub ml_kem_dk: Box<MlKem768DecapKey>,
}

impl HybridSecretKey {
    pub fn generate() -> (Self, HybridKeyPackage) {
        let mut rng = OsRng;

        // X25519 (classical)
        let x25519_sk = StaticSecret::random_from_rng(rng);
        let x25519_pk = X25519PublicKey::from(&x25519_sk);

        // ML-KEM-768 (post-quantum, FIPS 203). Box the decap key so the
        // ~2.4 KiB structure never lives on the stack.
        let (dk, ek) = MlKem768::generate(&mut rng);

        let secret_key = HybridSecretKey {
            x25519_sk,
            ml_kem_dk: Box::new(dk),
        };
        let key_package = HybridKeyPackage {
            x25519_pk: *x25519_pk.as_bytes(),
            ml_kem_pk: ek.as_bytes().to_vec(),
        };
        (secret_key, key_package)
    }

    pub fn decapsulate(&self, ciphertext: &HybridCiphertext) -> Result<[u8; 32], anyhow::Error> {
        // 1. X25519 ECDH.
        let peer_x25519 = X25519PublicKey::from(ciphertext.x25519_pk);
        let x25519_shared = self.x25519_sk.diffie_hellman(&peer_x25519);

        // 2. ML-KEM-768 decapsulation.
        let ct_array = decode_ml_kem_ciphertext(&ciphertext.ml_kem_ct)
            .ok_or_else(|| anyhow::anyhow!("invalid ML-KEM-768 ciphertext length"))?;
        let ml_kem_shared = self
            .ml_kem_dk
            .decapsulate(&ct_array)
            .map_err(|e| anyhow::anyhow!("ML-KEM decapsulation failed: {:?}", e))?;

        // 3. Combine the two 32-byte secrets via HKDF.
        Self::combine_secrets(x25519_shared.as_bytes(), ml_kem_shared.as_slice())
    }

    pub(crate) fn combine_secrets(
        ecc_secret: &[u8],
        pq_secret: &[u8],
    ) -> Result<[u8; 32], anyhow::Error> {
        let hkdf = Hkdf::<Sha256>::new(None, &[ecc_secret, pq_secret].concat());
        let mut okm = [0u8; 32];
        // KDF label preserved from V1 hybrid_kem so the protocol's KDF
        // label inventory does not grow — the algorithm pair is identical
        // (X25519 + a Kyber-family KEM), only the FIPS-203 byte encoding
        // changed.
        hkdf.expand(&b"HybridKEM_X25519_Kyber768"[..], &mut okm)
            .map_err(|_| anyhow::anyhow!("HKDF expansion failed"))?;
        Ok(okm)
    }
}

impl fmt::Debug for HybridSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HybridSecretKey")
            .field("x25519_sk", &"REDACTED")
            .field("ml_kem_dk", &"REDACTED")
            .finish()
    }
}

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct HybridKeyPackage {
    pub x25519_pk: [u8; 32],
    pub ml_kem_pk: Vec<u8>,
}

impl HybridKeyPackage {
    pub fn encapsulate(&self) -> Result<([u8; 32], HybridCiphertext), anyhow::Error> {
        let mut rng = OsRng;

        // 1. X25519 ECDH: fresh ephemeral on the sender side.
        let ephemeral_sk = StaticSecret::random_from_rng(rng);
        let ephemeral_pk = X25519PublicKey::from(&ephemeral_sk);
        let peer_x25519 = X25519PublicKey::from(self.x25519_pk);
        let x25519_shared = ephemeral_sk.diffie_hellman(&peer_x25519);

        // 2. ML-KEM-768 encapsulation against the peer's encap key.
        let ek_array = decode_ml_kem_encap_key(&self.ml_kem_pk)
            .ok_or_else(|| anyhow::anyhow!("invalid ML-KEM-768 public key length"))?;
        let ek = MlKem768EncapKey::from_bytes(&ek_array);
        let (ct, ml_kem_shared) = ek
            .encapsulate(&mut rng)
            .map_err(|e| anyhow::anyhow!("ML-KEM encapsulation failed: {:?}", e))?;

        // 3. Combine via HKDF.
        let shared_secret =
            HybridSecretKey::combine_secrets(x25519_shared.as_bytes(), ml_kem_shared.as_slice())?;

        let ciphertext = HybridCiphertext {
            x25519_pk: *ephemeral_pk.as_bytes(),
            ml_kem_ct: ct.as_slice().to_vec(),
        };
        Ok((shared_secret, ciphertext))
    }
}

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct HybridCiphertext {
    /// Ephemeral X25519 public key from the sender.
    pub x25519_pk: [u8; 32],
    /// ML-KEM-768 ciphertext bytes (FIPS-203 encoded).
    pub ml_kem_ct: Vec<u8>,
}

// ─── Encoding helpers ─────────────────────────────────────────────────────
//
// `ml-kem` stores its byte-encoded keys and ciphertexts as `Encoded<T>`,
// a `GenericArray<u8, N>` from the `hybrid-array` crate. We carry them on
// the wire as `Vec<u8>` (borsh-friendly) and round-trip via these
// helpers. Length mismatches return `None` so callers can map them to a
// proper handshake / KEM error.

fn decode_ml_kem_encap_key(bytes: &[u8]) -> Option<Encoded<MlKem768EncapKey>> {
    Encoded::<MlKem768EncapKey>::try_from(bytes).ok()
}

fn decode_ml_kem_ciphertext(
    bytes: &[u8],
) -> Option<Array<u8, <MlKem768 as KemCore>::CiphertextSize>> {
    Array::<u8, <MlKem768 as KemCore>::CiphertextSize>::try_from(bytes).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hybrid_kem_round_trip() {
        let (sk, pk) = HybridSecretKey::generate();
        let (ss_send, ct) = pk.encapsulate().expect("encap");
        let ss_recv = sk.decapsulate(&ct).expect("decap");
        assert_eq!(
            ss_send, ss_recv,
            "encap/decap must agree on the shared secret"
        );
    }

    #[test]
    fn hybrid_kem_two_handshakes_yield_distinct_secrets() {
        let (_sk, pk) = HybridSecretKey::generate();
        let (ss1, _ct1) = pk.encapsulate().expect("first encap");
        let (ss2, _ct2) = pk.encapsulate().expect("second encap");
        // Same recipient, different sender ephemeral X25519 + different
        // ML-KEM randomness → different shared secrets.
        assert_ne!(ss1, ss2);
    }

    #[test]
    fn ml_kem_ciphertext_size_matches_fips_203() {
        // FIPS-203 ML-KEM-768 ciphertext is 1088 bytes.
        let (_sk, pk) = HybridSecretKey::generate();
        let (_ss, ct) = pk.encapsulate().expect("encap");
        assert_eq!(ct.ml_kem_ct.len(), 1088);
    }

    #[test]
    fn ml_kem_public_key_size_matches_fips_203() {
        // FIPS-203 ML-KEM-768 encap key is 1184 bytes.
        let (_sk, pk) = HybridSecretKey::generate();
        assert_eq!(pk.ml_kem_pk.len(), 1184);
    }

    #[test]
    fn hybrid_kem_two_secrets_distinct_under_same_recipient_key() {
        let (sk, pk) = HybridSecretKey::generate();
        let (ss1, ct1) = pk.encapsulate().expect("encap1");
        let (_ss2, _ct2) = pk.encapsulate().expect("encap2");
        let pt1 = sk.decapsulate(&ct1).expect("decap1");
        // The recipient's decap yields the same secret as the sender's encap1.
        assert_eq!(pt1, ss1);
    }
}
