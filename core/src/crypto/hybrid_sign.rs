//! Hybrid Digital Signatures (Ed25519 + Dilithium3)
//!
//! Post-quantum secure signatures using:
//! - Ed25519 for classical security (fast, small signatures)
//! - Dilithium3 for post-quantum security (NIST Level 3)
//!
//! Both signatures must verify for maximum security.

use ed25519_dalek::{
    SigningKey, VerifyingKey, Signature as Ed25519Signature,
    Signer, Verifier
};
use pqcrypto_dilithium::dilithium3;
use pqcrypto_traits::sign::{
    PublicKey as DilithiumPublicKey,
    SecretKey as DilithiumSecretKey,
    SignedMessage,
    DetachedSignature,
};
use rand::rngs::OsRng;
use rkyv::{Archive, Deserialize, Serialize};
use bytecheck::CheckBytes;
use std::fmt;

/// Hybrid signing key (Ed25519 + Dilithium3)
pub struct HybridSigningKey {
    /// Ed25519 signing key (32 bytes)
    ed25519_sk: SigningKey,
    /// Dilithium3 secret key (~4KB)
    dilithium_sk: dilithium3::SecretKey,
    /// Dilithium3 public key (~1.5KB) - needed for verifying_key()
    dilithium_pk: dilithium3::PublicKey,
}

impl HybridSigningKey {
    /// Generate a new hybrid signing key pair
    pub fn generate() -> (Self, HybridVerifyingKey) {
        let mut rng = OsRng;
        
        // Ed25519
        let ed25519_sk = SigningKey::generate(&mut rng);
        let ed25519_pk = ed25519_sk.verifying_key();
        
        // Dilithium3
        let (dilithium_pk, dilithium_sk) = dilithium3::keypair();
        
        let signing_key = Self {
            ed25519_sk,
            dilithium_sk,
            dilithium_pk,
        };
        
        let verifying_key = HybridVerifyingKey {
            ed25519_pk: ed25519_pk.to_bytes(),
            dilithium_pk: dilithium_pk.as_bytes().to_vec(),
        };
        
        (signing_key, verifying_key)
    }
    
    /// Sign a message with both algorithms
    pub fn sign(&self, message: &[u8]) -> HybridSignature {
        // Ed25519 signature
        let ed25519_sig = self.ed25519_sk.sign(message);
        
        // Dilithium3 detached signature
        let dilithium_sig = dilithium3::detached_sign(message, &self.dilithium_sk);
        
        HybridSignature {
            ed25519_sig: ed25519_sig.to_bytes(),
            dilithium_sig: dilithium_sig.as_bytes().to_vec(),
        }
    }
    
    /// Export to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.ed25519_sk.to_bytes());
        out.extend_from_slice(self.dilithium_sk.as_bytes());
        out.extend_from_slice(self.dilithium_pk.as_bytes());
        out
    }
    
    /// Import from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, HybridSignError> {
        let ed25519_size = 32;
        let dilithium_sk_size = dilithium3::secret_key_bytes();
        let dilithium_pk_size = dilithium3::public_key_bytes();
        
        if bytes.len() != ed25519_size + dilithium_sk_size + dilithium_pk_size {
            return Err(HybridSignError::InvalidKeyLength);
        }
        
        let ed25519_bytes: [u8; 32] = bytes[0..32].try_into()
            .map_err(|_| HybridSignError::InvalidKeyFormat)?;
        let ed25519_sk = SigningKey::from_bytes(&ed25519_bytes);
        
        let sk_start = 32;
        let sk_end = sk_start + dilithium_sk_size;
        let dilithium_sk = dilithium3::SecretKey::from_bytes(&bytes[sk_start..sk_end])
            .map_err(|_| HybridSignError::InvalidKeyFormat)?;
        
        let dilithium_pk = dilithium3::PublicKey::from_bytes(&bytes[sk_end..])
            .map_err(|_| HybridSignError::InvalidKeyFormat)?;
        
        Ok(Self { ed25519_sk, dilithium_sk, dilithium_pk })
    }
    
    /// Get the corresponding verifying key
    pub fn verifying_key(&self) -> HybridVerifyingKey {
        let ed25519_pk = self.ed25519_sk.verifying_key();
        
        HybridVerifyingKey {
            ed25519_pk: ed25519_pk.to_bytes(),
            dilithium_pk: self.dilithium_pk.as_bytes().to_vec(),
        }
    }
}

impl fmt::Debug for HybridSigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HybridSigningKey")
            .field("ed25519_sk", &"REDACTED")
            .field("dilithium_sk", &"REDACTED")
            .finish()
    }
}

/// Hybrid verifying key (Ed25519 + Dilithium3 public keys)
#[derive(Archive, Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
#[archive(check_bytes)]
pub struct HybridVerifyingKey {
    /// Ed25519 public key (32 bytes)
    pub ed25519_pk: [u8; 32],
    /// Dilithium3 public key (~1.5KB)
    pub dilithium_pk: Vec<u8>,
}

impl HybridVerifyingKey {
    /// Verify a hybrid signature
    /// 
    /// BOTH signatures must verify for the message to be considered valid.
    pub fn verify(&self, message: &[u8], signature: &HybridSignature) -> Result<(), HybridSignError> {
        // Verify Ed25519
        let ed25519_pk = VerifyingKey::from_bytes(&self.ed25519_pk)
            .map_err(|_| HybridSignError::InvalidPublicKey)?;
        let ed25519_sig = Ed25519Signature::from_bytes(&signature.ed25519_sig);
        ed25519_pk.verify(message, &ed25519_sig)
            .map_err(|_| HybridSignError::Ed25519VerificationFailed)?;
        
        // Verify Dilithium3
        let dilithium_pk = dilithium3::PublicKey::from_bytes(&self.dilithium_pk)
            .map_err(|_| HybridSignError::InvalidPublicKey)?;
        let dilithium_sig = dilithium3::DetachedSignature::from_bytes(&signature.dilithium_sig)
            .map_err(|_| HybridSignError::InvalidSignature)?;
        dilithium3::verify_detached_signature(&dilithium_sig, message, &dilithium_pk)
            .map_err(|_| HybridSignError::DilithiumVerificationFailed)?;
        
        Ok(())
    }
    
    /// Export to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.ed25519_pk);
        out.extend_from_slice(&self.dilithium_pk);
        out
    }
    
    /// Import from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, HybridSignError> {
        let ed25519_size = 32;
        let dilithium_size = dilithium3::public_key_bytes();
        
        if bytes.len() != ed25519_size + dilithium_size {
            return Err(HybridSignError::InvalidKeyLength);
        }
        
        let ed25519_pk: [u8; 32] = bytes[0..32].try_into()
            .map_err(|_| HybridSignError::InvalidKeyFormat)?;
        let dilithium_pk = bytes[32..].to_vec();
        
        Ok(Self { ed25519_pk, dilithium_pk })
    }
}

/// Hybrid signature (Ed25519 + Dilithium3)
#[derive(Archive, Deserialize, Serialize, Debug, Clone)]
#[archive(check_bytes)]
pub struct HybridSignature {
    /// Ed25519 signature (64 bytes)
    pub ed25519_sig: [u8; 64],
    /// Dilithium3 signature (~3KB)
    pub dilithium_sig: Vec<u8>,
}

impl HybridSignature {
    /// Total size of the signature
    pub fn size(&self) -> usize {
        64 + self.dilithium_sig.len()
    }
    
    /// Export to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.ed25519_sig);
        out.extend_from_slice(&self.dilithium_sig);
        out
    }
    
    /// Import from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, HybridSignError> {
        if bytes.len() < 64 {
            return Err(HybridSignError::InvalidSignatureLength);
        }
        
        let ed25519_sig: [u8; 64] = bytes[0..64].try_into()
            .map_err(|_| HybridSignError::InvalidKeyFormat)?;
        let dilithium_sig = bytes[64..].to_vec();
        
        Ok(Self { ed25519_sig, dilithium_sig })
    }
}

/// Errors from hybrid signature operations
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
        
        // Valid signature
        assert!(verifying_key.verify(message, &signature).is_ok());
        
        // Wrong message
        let wrong_message = b"Wrong message";
        assert!(verifying_key.verify(wrong_message, &signature).is_err());
    }
    
    #[test]
    fn test_key_serialization() {
        let (signing_key, verifying_key) = HybridSigningKey::generate();
        
        // Round-trip signing key
        let bytes = signing_key.to_bytes();
        let restored = HybridSigningKey::from_bytes(&bytes).unwrap();
        
        // Verify signature with restored key
        let message = b"Test message";
        let sig = restored.sign(message);
        assert!(verifying_key.verify(message, &sig).is_ok());
        
        // Round-trip verifying key
        let pk_bytes = verifying_key.to_bytes();
        let restored_pk = HybridVerifyingKey::from_bytes(&pk_bytes).unwrap();
        assert!(restored_pk.verify(message, &sig).is_ok());
    }
    
    #[test]
    fn test_signature_sizes() {
        let (signing_key, _) = HybridSigningKey::generate();
        let message = b"Size test";
        let signature = signing_key.sign(message);
        
        // Ed25519: 64 bytes, Dilithium3: ~3293 bytes
        assert_eq!(signature.ed25519_sig.len(), 64);
        assert!(signature.dilithium_sig.len() > 3000);
        assert!(signature.dilithium_sig.len() < 4000);
    }
}
