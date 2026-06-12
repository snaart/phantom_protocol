//! Hybrid KEM: classical ECDH + ML-KEM-768 (FIPS 203, post-quantum).
//!
//! Phase 5.1 — switched the PQ half from `pqcrypto-kyber`'s C reference
//! implementation of NIST PQC round-3 Kyber768 to the RustCrypto pure-Rust
//! `ml-kem` crate's FIPS-203 ML-KEM-768. Same algorithm at the math level,
//! but the byte encoding follows FIPS 203.
//!
//! Under `--features fips`, the classical half swaps from X25519
//! to ECDH-P-256 via `aws-lc-rs`. The classical public-key length on
//! the wire grows from 32 bytes (X25519) to 65 bytes (uncompressed
//! SEC1 P-256). Cross-mode interop (fips ↔ non-fips) is **not
//! supported** — both peers MUST be compiled with matching feature
//! flags, and the `PROTOCOL_VARIANT` handshake constant
//! (`transport::handshake::PROTOCOL_VARIANT`) is baked into the
//! signed transcript so a mixed-mode attempt fails on the client's
//! signature check rather than producing a silently-wrong shared
//! secret.
//!
//! Both KEM halves contribute 32 bytes of shared secret, combined via
//! `HKDF-SHA-256` with the label `"HybridKEM_X25519_Kyber768"` on the
//! default build and `"HybridKEM_P256_Kyber768"` under fips. The label
//! divergence is intentional defense-in-depth: even if `PROTOCOL_VARIANT`
//! were stripped, the derived traffic secret would differ.

use borsh::{BorshDeserialize, BorshSerialize};
use hkdf::Hkdf;
use ml_kem::array::Array;
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{Encoded, EncodedSizeUser, KemCore, MlKem768};
use rand::rngs::OsRng;
use sha2::Sha256;
use std::fmt;
use zeroize::ZeroizeOnDrop;

#[cfg(not(feature = "fips"))]
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

#[cfg(feature = "fips")]
use aws_lc_rs::{
    agreement::{self, agree, EphemeralPrivateKey, PrivateKey, UnparsedPublicKey, ECDH_P256},
    rand::SystemRandom,
};

type MlKem768DecapKey = <MlKem768 as KemCore>::DecapsulationKey;
type MlKem768EncapKey = <MlKem768 as KemCore>::EncapsulationKey;

/// Classical KEM public-key byte length on the wire.
///
/// - Default build: X25519 → 32 bytes (RFC 7748).
/// - `--features fips`: ECDH-P-256 uncompressed SEC1 → 65 bytes.
#[cfg(not(feature = "fips"))]
pub const CLASSICAL_PK_BYTES: usize = 32;
#[cfg(feature = "fips")]
pub const CLASSICAL_PK_BYTES: usize = 65;

/// Combined-secret HKDF label. The default build keeps the V1/V2 label
/// verbatim so the protocol's KDF-label inventory stays stable; the fips
/// build uses a distinct label because the classical primitive is
/// different.
#[cfg(not(feature = "fips"))]
const COMBINE_LABEL: &[u8] = b"HybridKEM_X25519_Kyber768";
#[cfg(feature = "fips")]
const COMBINE_LABEL: &[u8] = b"HybridKEM_P256_Kyber768";

/// Hybrid secret key. Holds the classical long-term secret (X25519 by
/// default, ECDH-P-256 under fips) and the ML-KEM-768 decapsulation
/// key. Both halves are zeroized on drop — `ml_kem`'s `DecapsulationKey`
/// implements `Zeroize` natively, and the classical side either uses
/// `x25519_dalek`'s `Zeroize` impl (default) or aws-lc-rs's internal
/// Drop, which frees the underlying key material.
///
/// `ml_kem_dk` is `Box`-ed so the (~2.4 KiB) decapsulation key lives on
/// the heap; constructing several `HybridSecretKey`s in a deep call
/// chain (as happens during the handshake) would otherwise stress
/// tokio's default test thread stack.
#[derive(ZeroizeOnDrop)]
pub struct HybridSecretKey {
    /// Classical long-lived secret. Type depends on the active backend:
    /// `x25519_dalek::StaticSecret` (default) or
    /// `aws_lc_rs::agreement::PrivateKey` (`--features fips`, ECDH-P-256).
    #[cfg(not(feature = "fips"))]
    pub classical_sk: StaticSecret,
    #[cfg(feature = "fips")]
    #[zeroize(skip)] // aws-lc-rs frees the inner key on Drop
    pub classical_sk: PrivateKey,

    /// ML-KEM-768 decapsulation key (FIPS 203). Boxed to keep stack
    /// pressure down — the structure is ~2.4 KiB.
    #[zeroize(skip)] // Box's Drop calls T::Drop which zeroes the inner key
    pub ml_kem_dk: Box<MlKem768DecapKey>,
}

impl HybridSecretKey {
    pub fn generate() -> (Self, HybridKeyPackage) {
        let mut rng = OsRng;

        // Classical (X25519 or ECDH-P-256) key generation + public key
        // derivation. Branch is fully cfg-gated; the build pulls in
        // exactly one path.
        #[cfg(not(feature = "fips"))]
        let (classical_sk, classical_pk_bytes) = {
            let sk = StaticSecret::random_from_rng(rng);
            let pk = X25519PublicKey::from(&sk);
            (sk, *pk.as_bytes())
        };
        #[cfg(feature = "fips")]
        let (classical_sk, classical_pk_bytes) = {
            // PANIC-SAFETY: `PrivateKey::generate` only fails when the
            // underlying AWS-LC random source is broken — same failure
            // mode as `getrandom` on the default build, where we also
            // panic via `OsRng`. `compute_public_key` derives a
            // P-256 public from a fresh, just-generated valid private,
            // which cannot fail. A failure here means the FIPS module
            // is in a non-recoverable state; loud panic is the correct
            // surface for the embedder.
            #[allow(clippy::expect_used)]
            let sk = PrivateKey::generate(&ECDH_P256)
                .expect("aws-lc-rs ECDH-P-256 generate must succeed");
            #[allow(clippy::expect_used)]
            let pk = sk
                .compute_public_key()
                .expect("aws-lc-rs ECDH-P-256 compute_public_key must succeed");
            let mut bytes = [0u8; CLASSICAL_PK_BYTES];
            bytes.copy_from_slice(pk.as_ref());
            (sk, bytes)
        };

        // ML-KEM-768 (post-quantum, FIPS 203). Box the decap key so the
        // ~2.4 KiB structure never lives on the stack.
        let (dk, ek) = MlKem768::generate(&mut rng);

        let secret_key = HybridSecretKey {
            classical_sk,
            ml_kem_dk: Box::new(dk),
        };
        let key_package = HybridKeyPackage {
            classical_pk: classical_pk_bytes,
            ml_kem_pk: ek.as_bytes().to_vec(),
        };
        (secret_key, key_package)
    }

    pub fn decapsulate(&self, ciphertext: &HybridCiphertext) -> Result<[u8; 32], anyhow::Error> {
        // 1. Classical ECDH.
        #[cfg(not(feature = "fips"))]
        let classical_shared: [u8; 32] = {
            let peer = X25519PublicKey::from(ciphertext.classical_pk);
            let s = self.classical_sk.diffie_hellman(&peer);
            *s.as_bytes()
        };
        #[cfg(feature = "fips")]
        let classical_shared: [u8; 32] = {
            let peer = UnparsedPublicKey::new(&ECDH_P256, &ciphertext.classical_pk[..]);
            // aws-lc-rs's `agree` returns `Result<R, E>` where the
            // closure is `FnOnce(&[u8]) -> Result<R, E>`. The
            // `error_value` arg is the E returned when peer-key parse
            // fails before the closure runs.
            agree(
                &self.classical_sk,
                peer,
                anyhow::anyhow!("aws-lc-rs ECDH-P-256 agree failed (peer key parse)"),
                |km| -> Result<[u8; 32], anyhow::Error> {
                    // ECDH-P-256 shared secret is the 32-byte X coordinate.
                    let mut out = [0u8; 32];
                    out.copy_from_slice(km);
                    Ok(out)
                },
            )?
        };

        // 2. ML-KEM-768 decapsulation.
        let ct_array = decode_ml_kem_ciphertext(&ciphertext.ml_kem_ct)
            .ok_or_else(|| anyhow::anyhow!("invalid ML-KEM-768 ciphertext length"))?;
        let ml_kem_shared = self
            .ml_kem_dk
            .decapsulate(&ct_array)
            .map_err(|e| anyhow::anyhow!("ML-KEM decapsulation failed: {:?}", e))?;

        // 3. Our own classical public key — bound into the combiner (T4.2). Derived
        // from the long-lived classical secret on each build path.
        #[cfg(not(feature = "fips"))]
        let our_classical_pk: [u8; CLASSICAL_PK_BYTES] =
            *X25519PublicKey::from(&self.classical_sk).as_bytes();
        #[cfg(feature = "fips")]
        let our_classical_pk: [u8; CLASSICAL_PK_BYTES] = {
            let pk = self
                .classical_sk
                .compute_public_key()
                .map_err(|e| anyhow::anyhow!("aws-lc-rs P-256 compute_public_key: {:?}", e))?;
            let mut b = [0u8; CLASSICAL_PK_BYTES];
            b.copy_from_slice(pk.as_ref());
            b
        };

        // 4. Combine the two 32-byte secrets via HKDF, binding the classical ciphertext
        // (the sender's ephemeral pk) + the recipient classical pk (T4.2).
        Self::combine_secrets(
            &classical_shared,
            ml_kem_shared.as_slice(),
            &ciphertext.classical_pk,
            &our_classical_pk,
        )
    }

    /// Combine the classical + ML-KEM shared secrets into the 32-byte session secret.
    ///
    /// T4.2 (X-Wing / draft-ietf-tls-hybrid-design): the IKM binds, in addition to the
    /// two raw shared secrets, the **classical ciphertext** (`classical_ct` — the
    /// sender's ephemeral classical pubkey, carried in [`HybridCiphertext::classical_pk`])
    /// and the **recipient classical pubkey** (`classical_pk`). This makes the combined
    /// secret commit to the full classical transcript so the combiner's security does not
    /// rest on the handshake signature alone. The ML-KEM half is implicitly committed via
    /// its shared secret (ML-KEM is IND-CCA / binds its ciphertext); only the classical
    /// half needs the explicit ct/pk binding here.
    pub(crate) fn combine_secrets(
        ecc_secret: &[u8],
        pq_secret: &[u8],
        classical_ct: &[u8],
        classical_pk: &[u8],
    ) -> Result<[u8; 32], anyhow::Error> {
        // CRYPTO-3: the combined IKM holds both raw classical and ML-KEM shared
        // secrets — wipe it on every exit path rather than leaving it in freed
        // memory.
        let ikm =
            zeroize::Zeroizing::new([ecc_secret, pq_secret, classical_ct, classical_pk].concat());
        let hkdf = Hkdf::<Sha256>::new(None, &ikm);
        let mut okm = [0u8; 32];
        hkdf.expand(COMBINE_LABEL, &mut okm)
            .map_err(|_| anyhow::anyhow!("HKDF expansion failed"))?;
        Ok(okm)
    }
}

impl fmt::Debug for HybridSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HybridSecretKey")
            .field("classical_sk", &"REDACTED")
            .field("ml_kem_dk", &"REDACTED")
            .finish()
    }
}

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct HybridKeyPackage {
    /// Classical public key. Encoded as raw bytes; semantics depend on
    /// the build (X25519 32-byte key by default, P-256 uncompressed
    /// SEC1 65-byte key under fips).
    pub classical_pk: [u8; CLASSICAL_PK_BYTES],
    pub ml_kem_pk: Vec<u8>,
}

impl HybridKeyPackage {
    pub fn encapsulate(&self) -> Result<([u8; 32], HybridCiphertext), anyhow::Error> {
        let mut rng = OsRng;

        // 1. Classical ECDH: fresh ephemeral on the sender side.
        #[cfg(not(feature = "fips"))]
        let (eph_pk_bytes, classical_shared) = {
            let eph_sk = StaticSecret::random_from_rng(rng);
            let eph_pk = X25519PublicKey::from(&eph_sk);
            let peer = X25519PublicKey::from(self.classical_pk);
            let shared = eph_sk.diffie_hellman(&peer);
            (*eph_pk.as_bytes(), *shared.as_bytes())
        };
        #[cfg(feature = "fips")]
        let (eph_pk_bytes, classical_shared): ([u8; CLASSICAL_PK_BYTES], [u8; 32]) = {
            let aws_rng = SystemRandom::new();
            let eph_sk = EphemeralPrivateKey::generate(&ECDH_P256, &aws_rng)
                .map_err(|e| anyhow::anyhow!("aws-lc-rs ECDH-P-256 ephemeral generate: {:?}", e))?;
            let eph_pk = eph_sk
                .compute_public_key()
                .map_err(|e| anyhow::anyhow!("compute_public_key: {:?}", e))?;
            let mut pk_bytes = [0u8; CLASSICAL_PK_BYTES];
            pk_bytes.copy_from_slice(eph_pk.as_ref());
            let peer = UnparsedPublicKey::new(&ECDH_P256, &self.classical_pk[..]);
            let shared = agreement::agree_ephemeral(
                eph_sk,
                peer,
                anyhow::anyhow!("aws-lc-rs ECDH-P-256 agree_ephemeral failed (peer parse)"),
                |km| -> Result<[u8; 32], anyhow::Error> {
                    let mut o = [0u8; 32];
                    o.copy_from_slice(km);
                    Ok(o)
                },
            )?;
            (pk_bytes, shared)
        };

        // 2. ML-KEM-768 encapsulation against the peer's encap key.
        let ek_array = decode_ml_kem_encap_key(&self.ml_kem_pk)
            .ok_or_else(|| anyhow::anyhow!("invalid ML-KEM-768 public key length"))?;
        let ek = MlKem768EncapKey::from_bytes(&ek_array);
        let (ct, ml_kem_shared) = ek
            .encapsulate(&mut rng)
            .map_err(|e| anyhow::anyhow!("ML-KEM encapsulation failed: {:?}", e))?;

        // 3. Combine via HKDF, binding the classical ciphertext (this ephemeral pk)
        // + the recipient classical pk (T4.2).
        let shared_secret = HybridSecretKey::combine_secrets(
            &classical_shared,
            ml_kem_shared.as_slice(),
            &eph_pk_bytes,
            &self.classical_pk,
        )?;

        let ciphertext = HybridCiphertext {
            classical_pk: eph_pk_bytes,
            ml_kem_ct: ct.as_slice().to_vec(),
        };
        Ok((shared_secret, ciphertext))
    }
}

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct HybridCiphertext {
    /// Sender's ephemeral classical public key. Encoding matches
    /// [`HybridKeyPackage::classical_pk`].
    pub classical_pk: [u8; CLASSICAL_PK_BYTES],
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

    /// T4.2 (X-Wing / draft-ietf-tls-hybrid-design): the hybrid combiner must bind the
    /// classical ciphertext (the sender's ephemeral pubkey) and the recipient classical
    /// pubkey into the IKM, not just the two raw shared secrets — so the combined secret
    /// commits to the full classical transcript and the construction's security does not
    /// rest on the handshake signature alone. Changing either the ct or the pk while
    /// holding both shared secrets fixed must change the combined secret.
    #[test]
    fn combiner_binds_classical_ct_and_pk() {
        let ecc = [7u8; 32];
        let pq = [9u8; 32];
        let ct1 = [1u8; CLASSICAL_PK_BYTES];
        let ct2 = [2u8; CLASSICAL_PK_BYTES];
        let pk1 = [3u8; CLASSICAL_PK_BYTES];
        let pk2 = [4u8; CLASSICAL_PK_BYTES];

        let base = HybridSecretKey::combine_secrets(&ecc, &pq, &ct1, &pk1).expect("combine");
        let diff_ct = HybridSecretKey::combine_secrets(&ecc, &pq, &ct2, &pk1).expect("combine");
        let diff_pk = HybridSecretKey::combine_secrets(&ecc, &pq, &ct1, &pk2).expect("combine");

        assert_ne!(
            base, diff_ct,
            "combined secret must depend on the classical ciphertext (sender ephemeral pk)"
        );
        assert_ne!(
            base, diff_pk,
            "combined secret must depend on the recipient classical pubkey"
        );
    }

    #[test]
    fn hybrid_kem_two_handshakes_yield_distinct_secrets() {
        let (_sk, pk) = HybridSecretKey::generate();
        let (ss1, _ct1) = pk.encapsulate().expect("first encap");
        let (ss2, _ct2) = pk.encapsulate().expect("second encap");
        // Same recipient, different sender ephemeral classical + different
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

    /// Classical public key length matches the active backend.
    #[test]
    fn classical_public_key_size_matches_backend() {
        let (_sk, pk) = HybridSecretKey::generate();
        assert_eq!(pk.classical_pk.len(), CLASSICAL_PK_BYTES);
        #[cfg(not(feature = "fips"))]
        assert_eq!(CLASSICAL_PK_BYTES, 32, "X25519 public key is 32 bytes");
        #[cfg(feature = "fips")]
        assert_eq!(
            CLASSICAL_PK_BYTES, 65,
            "ECDH-P-256 uncompressed SEC1 public key is 65 bytes"
        );
    }

    /// fips-only: P-256 SEC1 uncompressed encoding starts with 0x04.
    #[cfg(feature = "fips")]
    #[test]
    fn fips_classical_public_key_is_uncompressed_sec1() {
        let (_sk, pk) = HybridSecretKey::generate();
        assert_eq!(
            pk.classical_pk[0], 0x04,
            "uncompressed SEC1 P-256 key must lead with 0x04"
        );
    }
}
