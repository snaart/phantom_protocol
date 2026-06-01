//! Hybrid Digital Signatures: Ed25519 + ML-DSA-65 (FIPS 204).
//!
//! Phase 5.1 — switched the PQ half from `pqcrypto-dilithium`'s C reference
//! implementation of NIST PQC round-3 Dilithium3 to the RustCrypto pure-Rust
//! `ml-dsa` crate's FIPS-204 ML-DSA-65. Same algorithm at the math level,
//! different byte encoding per FIPS 204. Wire-incompatible with the prior
//! `phantom_core` build.
//!
//! Both signatures must verify for the hybrid to be considered valid.

use borsh::{BorshDeserialize, BorshSerialize};
use ed25519_dalek::{
    Signature as Ed25519Signature, Signer as Ed25519Signer, SigningKey,
    Verifier as Ed25519Verifier, VerifyingKey,
};
use ml_dsa::Signature as MlDsaSignature;
use ml_dsa::SigningKey as MlDsaSigningKey;
use ml_dsa::VerifyingKey as MlDsaVerifyingKey;
use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, KeyExport, KeyInit, Keypair, MlDsa65, Signer, Verifier,
};
use std::fmt;
use zeroize::ZeroizeOnDrop;

/// Hybrid signing key — Ed25519 + ML-DSA-65 secret material.
///
/// On drop, both halves are zeroed: `ed25519_dalek::SigningKey` carries
/// its own `Drop` impl (via the `zeroize` feature enabled in Cargo.toml),
/// and `ml_dsa::SigningKey<P>` implements `ZeroizeOnDrop` natively. The
/// pre-Phase-5.1 `unsafe` `ptr::write_volatile` wrapper in `crypto::keys`
/// is no longer needed and was deleted.
///
/// `ml_dsa_sk` is `Box`-ed because `SigningKey<MlDsa65>` internally
/// embeds the ~4 KiB ExpandedSigningKey by value; placing the whole
/// thing on the stack at every construction would overflow default
/// tokio test threads (the `from_seed` call alone constructs a large
/// temporary). On the heap it's a single pointer-sized field at our
/// level; `Box<T: ZeroizeOnDrop>` correctly forwards `Drop` to T.
#[derive(ZeroizeOnDrop)]
pub struct HybridSigningKey {
    #[zeroize(skip)] // ed25519's SigningKey zeroes via its own Drop
    pub ed25519_sk: SigningKey,
    #[zeroize(skip)] // Box's Drop calls T::Drop which zeroes the inner SigningKey
    pub ml_dsa_sk: Box<MlDsaSigningKey<MlDsa65>>,
}

impl HybridSigningKey {
    /// Generate a fresh hybrid keypair using the OS RNG.
    ///
    /// Equivalent to `Self::generate_with_provider(&crate::crypto::rng::OsRng)`.
    /// Preserved as the call-compatible default so the rest of the crate
    /// (and downstream callers) does not change shape.
    pub fn generate() -> (Self, HybridVerifyingKey) {
        Self::generate_with_provider(&crate::crypto::rng::OsRng)
    }

    /// Generate a fresh hybrid keypair using an arbitrary
    /// [`RngProvider`](crate::crypto::rng::RngProvider).
    ///
    /// Phase 3.8 demonstration of the `RngProvider` indirection: this is
    /// the canonical "small, well-bounded crypto entry point that needs
    /// randomness" call site. Embedders that need to drive key generation
    /// from a hardware TRNG (on no_std) or a FIPS-approved DRBG plug in
    /// here without disturbing the default surface.
    ///
    /// Internally, 32 bytes are drawn from the provider for each algorithm:
    ///
    /// - Ed25519: the 32 bytes are the seed for `SigningKey::from_bytes`.
    /// - ML-DSA-65: the 32 bytes are the FIPS 204 § Algorithm 1 seed `xi`
    ///   passed to `SigningKey::<MlDsa65>::new(&seed)` (== KeyInit /
    ///   `from_seed`).
    pub fn generate_with_provider<R: crate::crypto::rng::RngProvider + ?Sized>(
        provider: &R,
    ) -> (Self, HybridVerifyingKey) {
        // Ed25519 — 32-byte seed.
        let mut ed_seed = [0u8; 32];
        provider.fill_bytes(&mut ed_seed);
        let ed25519_sk = SigningKey::from_bytes(&ed_seed);
        let ed25519_pk = ed25519_sk.verifying_key();

        // ML-DSA-65 (FIPS 204 § Algorithm 1 ML-DSA.KeyGen). The seed is
        // the 32-byte `xi`. `KeyInit::new` runs the algorithm
        // deterministically over it. Box immediately so the ~4 KiB
        // expanded signing key never lives on the stack (matches the
        // rationale in `from_bytes`).
        let mut ml_seed_bytes = [0u8; 32];
        provider.fill_bytes(&mut ml_seed_bytes);
        let ml_dsa_seed = ml_dsa::B32::from(ml_seed_bytes);
        let ml_dsa_sk = Box::new(MlDsaSigningKey::<MlDsa65>::new(&ml_dsa_seed));
        let ml_dsa_vk = ml_dsa_sk.verifying_key();

        let signing_key = Self {
            ed25519_sk,
            ml_dsa_sk,
        };
        let verifying_key = HybridVerifyingKey {
            ed25519_pk: ed25519_pk.to_bytes(),
            ml_dsa_pk: ml_dsa_vk.encode().to_vec(),
        };
        (signing_key, verifying_key)
    }

    /// FIPS 140-3 §7.10 pairwise-consistency test for a freshly-generated
    /// **long-term** hybrid signing identity: sign a fixed message with this
    /// secret key and verify it against `verifying_key`. Returns `Err` iff the
    /// keypair cannot validate its own signature — i.e. the RNG or a signing
    /// primitive was faulted and the key must not be used.
    ///
    /// Call this **only** at persisted / long-lived-identity generation sites
    /// (CLI keygen, server identity load-or-create, `PhantomListener::bind`).
    /// It is deliberately **not** run inside [`generate`](Self::generate) /
    /// [`generate_with_provider`](Self::generate_with_provider): those mint the
    /// client's *ephemeral* per-handshake signing key, and a sign+verify there
    /// would add ~40% to every client handshake. The requirement targets
    /// long-term keypairs, not per-connection ephemerals.
    pub fn pairwise_consistency_check(
        &self,
        verifying_key: &HybridVerifyingKey,
    ) -> Result<(), HybridSignError> {
        let msg: &[u8] = b"phantom-core keygen pairwise-consistency test";
        verifying_key.verify(msg, &self.sign(msg))
    }

    /// Sign with both algorithms. Both signatures are returned in the
    /// `HybridSignature`; verification on the peer side requires both to
    /// be valid.
    pub fn sign(&self, message: &[u8]) -> HybridSignature {
        let ed25519_sig = self.ed25519_sk.sign(message);
        let ml_dsa_sig: MlDsaSignature<MlDsa65> = self.ml_dsa_sk.sign(message);
        HybridSignature {
            ed25519_sig: ed25519_sig.to_bytes(),
            ml_dsa_sig: ml_dsa_sig.encode().to_vec(),
        }
    }

    pub fn verifying_key(&self) -> HybridVerifyingKey {
        let ed25519_pk = self.ed25519_sk.verifying_key();
        HybridVerifyingKey {
            ed25519_pk: ed25519_pk.to_bytes(),
            ml_dsa_pk: self.ml_dsa_sk.verifying_key().encode().to_vec(),
        }
    }

    /// Serialize the signing key as `(ed25519_seed[32] || ml_dsa_seed[32])`.
    /// ML-DSA-65 is fully derivable from its 32-byte seed (per FIPS 204
    /// `KeyGen` algorithm) so we store the compact form rather than the
    /// 4032-byte expanded representation.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64);
        out.extend_from_slice(&self.ed25519_sk.to_bytes());
        // KeyExport::to_bytes returns the 32-byte seed.
        out.extend_from_slice(self.ml_dsa_sk.to_bytes().as_slice());
        out
    }

    /// Restore from `to_bytes` output.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, HybridSignError> {
        if bytes.len() != 64 {
            return Err(HybridSignError::InvalidKeyLength);
        }
        let ed25519_bytes: [u8; 32] = bytes[..32]
            .try_into()
            .map_err(|_| HybridSignError::InvalidKeyFormat)?;
        let ed25519_sk = SigningKey::from_bytes(&ed25519_bytes);
        let ml_dsa_seed =
            ml_dsa::B32::try_from(&bytes[32..]).map_err(|_| HybridSignError::InvalidKeyFormat)?;
        // `KeyInit::new(&seed)` reconstructs the SigningKey from its seed
        // (algorithm 1 in FIPS 204: ML-DSA.KeyGen). Boxed for the same
        // stack-overflow reason as `generate`.
        let ml_dsa_sk = Box::new(MlDsaSigningKey::<MlDsa65>::new(&ml_dsa_seed));
        Ok(Self {
            ed25519_sk,
            ml_dsa_sk,
        })
    }
}

impl fmt::Debug for HybridSigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HybridSigningKey")
            .field("ed25519_sk", &"REDACTED")
            .field("ml_dsa_sk", &"REDACTED")
            .finish()
    }
}

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct HybridVerifyingKey {
    pub ed25519_pk: [u8; 32],
    pub ml_dsa_pk: Vec<u8>,
}

impl HybridVerifyingKey {
    /// Both signatures must verify for the hybrid to be considered valid.
    pub fn verify(
        &self,
        message: &[u8],
        signature: &HybridSignature,
    ) -> Result<(), HybridSignError> {
        // Ed25519
        let ed25519_pk = VerifyingKey::from_bytes(&self.ed25519_pk)
            .map_err(|_| HybridSignError::InvalidPublicKey)?;
        let ed25519_sig = Ed25519Signature::from_bytes(&signature.ed25519_sig);
        ed25519_pk
            .verify(message, &ed25519_sig)
            .map_err(|_| HybridSignError::Ed25519VerificationFailed)?;

        // ML-DSA-65 (FIPS 204)
        let vk_encoded = EncodedVerifyingKey::<MlDsa65>::try_from(self.ml_dsa_pk.as_slice())
            .map_err(|_| HybridSignError::InvalidPublicKey)?;
        let vk = MlDsaVerifyingKey::<MlDsa65>::decode(&vk_encoded);

        let sig_encoded = EncodedSignature::<MlDsa65>::try_from(signature.ml_dsa_sig.as_slice())
            .map_err(|_| HybridSignError::InvalidSignature)?;
        let sig = MlDsaSignature::<MlDsa65>::decode(&sig_encoded)
            .ok_or(HybridSignError::InvalidSignature)?;

        vk.verify(message, &sig)
            .map_err(|_| HybridSignError::DilithiumVerificationFailed)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + self.ml_dsa_pk.len());
        out.extend_from_slice(&self.ed25519_pk);
        out.extend_from_slice(&self.ml_dsa_pk);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, HybridSignError> {
        const ED_SIZE: usize = 32;
        // FIPS-204 ML-DSA-65 verifying-key encoded size = 1952 bytes.
        const VK_SIZE: usize = 1952;
        if bytes.len() != ED_SIZE + VK_SIZE {
            return Err(HybridSignError::InvalidKeyLength);
        }
        let ed25519_pk: [u8; ED_SIZE] = bytes[..ED_SIZE]
            .try_into()
            .map_err(|_| HybridSignError::InvalidKeyFormat)?;
        let ml_dsa_pk = bytes[ED_SIZE..].to_vec();
        Ok(Self {
            ed25519_pk,
            ml_dsa_pk,
        })
    }
}

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct HybridSignature {
    pub ed25519_sig: [u8; 64],
    pub ml_dsa_sig: Vec<u8>,
}

impl HybridSignature {
    pub fn size(&self) -> usize {
        64 + self.ml_dsa_sig.len()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64 + self.ml_dsa_sig.len());
        out.extend_from_slice(&self.ed25519_sig);
        out.extend_from_slice(&self.ml_dsa_sig);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, HybridSignError> {
        if bytes.len() < 64 {
            return Err(HybridSignError::InvalidSignatureLength);
        }
        let ed25519_sig: [u8; 64] = bytes[..64]
            .try_into()
            .map_err(|_| HybridSignError::InvalidKeyFormat)?;
        let ml_dsa_sig = bytes[64..].to_vec();
        Ok(Self {
            ed25519_sig,
            ml_dsa_sig,
        })
    }
}

#[derive(Debug, Clone, Copy, thiserror::Error)]
pub enum HybridSignError {
    #[error("Invalid key length")]
    InvalidKeyLength,
    #[error("Invalid key format")]
    InvalidKeyFormat,
    #[error("Invalid public key")]
    InvalidPublicKey,
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Invalid signature length")]
    InvalidSignatureLength,
    #[error("Ed25519 verification failed")]
    Ed25519VerificationFailed,
    #[error("Dilithium verification failed")]
    DilithiumVerificationFailed,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hybrid_sign_verify() {
        let (signing_key, verifying_key) = HybridSigningKey::generate();
        let message = b"Hello, post-quantum world!";
        let signature = signing_key.sign(message);

        assert!(verifying_key.verify(message, &signature).is_ok());

        let wrong = b"Wrong message";
        assert!(verifying_key.verify(wrong, &signature).is_err());
    }

    #[test]
    fn pairwise_consistency_check_passes_for_a_matched_keypair_and_fails_for_a_mismatch() {
        let (sk, vk) = HybridSigningKey::generate();
        // A correctly-generated keypair passes its own PCT.
        assert!(sk.pairwise_consistency_check(&vk).is_ok());

        // A signing key checked against a DIFFERENT public key fails — exactly
        // the fault-injected-keygen signal the long-term-identity sites rely on.
        let (_other_sk, other_vk) = HybridSigningKey::generate();
        assert!(sk.pairwise_consistency_check(&other_vk).is_err());
    }

    #[test]
    fn test_key_serialization() {
        let (signing_key, verifying_key) = HybridSigningKey::generate();
        let bytes = signing_key.to_bytes();
        let restored = HybridSigningKey::from_bytes(&bytes).expect("restore");

        let message = b"Test message";
        let sig = restored.sign(message);
        assert!(verifying_key.verify(message, &sig).is_ok());

        let pk_bytes = verifying_key.to_bytes();
        let restored_pk = HybridVerifyingKey::from_bytes(&pk_bytes).expect("restore vk");
        assert!(restored_pk.verify(message, &sig).is_ok());
    }

    #[test]
    fn test_signature_sizes() {
        let (signing_key, _) = HybridSigningKey::generate();
        let message = b"Size test";
        let signature = signing_key.sign(message);
        // FIPS-204 ML-DSA-65 signature is 3309 bytes.
        assert_eq!(signature.ed25519_sig.len(), 64);
        assert_eq!(signature.ml_dsa_sig.len(), 3309);
    }
}
