// Crypto Provider for OpenMLS 0.6
// Simplified: Uses OpenMlsRustCrypto directly instead of custom wrapper

use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_basic_credential::SignatureKeyPair;
use openmls::prelude::*;
use openmls_traits::signatures::Signer;

/// Re-export the standard provider for use throughout the crate
pub type MlsProvider = OpenMlsRustCrypto;

/// Create a new MLS provider instance
pub fn new_provider() -> MlsProvider {
    OpenMlsRustCrypto::default()
}

// Keep hybrid KEM imports for PSK fallback mode
use crate::crypto::hybrid_kem::{HybridSecretKey, HybridKeyPackage, HybridCiphertext};
use crate::network::serialization::{serialize, deserialize};

/// Helper to generate signature keypair and store it
pub fn generate_signature_keypair(
    provider: &MlsProvider,
    ciphersuite: Ciphersuite,
) -> Result<SignatureKeyPair, String> {
    let signature_keys = SignatureKeyPair::new(ciphersuite.signature_algorithm())
        .map_err(|e| format!("SignatureKeyPair generation failed: {:?}", e))?;
    
    signature_keys
        .store(provider.storage())
        .map_err(|e| format!("Failed to store signature keys: {:?}", e))?;
    
    Ok(signature_keys)
}

/// QuantumSigner wrapper for MLS operations
/// Wraps SignatureKeyPair for use with MLS operations
#[derive(Debug, Clone)]
pub struct QuantumSigner {
    inner: SignatureKeyPair,
}

impl QuantumSigner {
    pub fn new(keypair: SignatureKeyPair) -> Self {
        Self { inner: keypair }
    }
    
    pub fn public_key(&self) -> Vec<u8> {
        self.inner.public().to_vec()
    }
    
    pub fn store(&self, provider: &MlsProvider) -> Result<(), String> {
        self.inner
            .store(provider.storage())
            .map_err(|e| format!("Store failed: {:?}", e))
    }
}

impl Signer for QuantumSigner {
    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, openmls_traits::signatures::SignerError> {
        self.inner.sign(payload)
    }

    fn signature_scheme(&self) -> SignatureScheme {
        self.inner.signature_scheme()
    }
}

// ==== Hybrid KEM Helpers (for PSK mode, not MLS-integrated) ====

/// Derive PSK app key using HKDF
pub fn derive_psk_key(group_id: &[u8], shared_secret: &[u8]) -> Result<Vec<u8>, String> {
    use hkdf::Hkdf;
    use sha2::Sha256;
    
    let hk = Hkdf::<Sha256>::new(Some(group_id), shared_secret);
    let mut okm = [0u8; 32];
    hk.expand(b"phantom_app_key", &mut okm)
        .map_err(|e| format!("HKDF expand failed: {:?}", e))?;
    
    Ok(okm.to_vec())
}

/// Generate hybrid keypair for quantum-resistant key exchange
pub fn generate_hybrid_keypair() -> (HybridSecretKey, HybridKeyPackage) {
    HybridSecretKey::generate()
}

/// Serialize hybrid public key
pub fn serialize_hybrid_pk(pk: &HybridKeyPackage) -> Result<Vec<u8>, String> {
    serialize(pk).map_err(|e| format!("Serialize failed: {:?}", e))
}

/// Deserialize hybrid public key  
pub fn deserialize_hybrid_pk(bytes: &[u8]) -> Result<HybridKeyPackage, String> {
    deserialize(bytes).map_err(|e| format!("Deserialize failed: {:?}", e))
}
