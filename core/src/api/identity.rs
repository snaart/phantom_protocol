//! Server-identity helpers exposed for FFI: generate a hybrid signing key and
//! extract its verifying half. The 64-byte seed is the same
//! `ed25519_seed(32) || ml_dsa_seed(32)` form the `phantom-cli keygen` tool writes
//! and that [`HybridSigningKey::to_bytes`] documents — persist it (0600) to keep a
//! server's pinned identity stable across restarts.

use crate::crypto::hybrid_sign::HybridSigningKey;
use crate::errors::CoreError;

/// Generate a fresh hybrid (Ed25519 + ML-DSA-65) signing key and return its 64-byte
/// seed (`ed25519_seed[32] || ml_dsa_seed[32]`). A pairwise-consistency check runs
/// before the seed is returned, so a key that cannot verify its own signature is
/// never handed out (matching `phantom-cli keygen`).
///
/// **The returned `Vec<u8>` is secret key material.** It is not zeroized when it
/// crosses the FFI boundary — persist it with restrictive permissions (0600) and wipe
/// the buffer when done. Load it back into a listener with
/// `bind_with_signing_key_bytes` / `bind_udp_with_signing_key_bytes`.
#[cfg_attr(feature = "bindings", uniffi::export)]
pub fn generate_signing_key() -> Result<Vec<u8>, CoreError> {
    let (signing_key, verifying_key) = HybridSigningKey::generate();
    signing_key
        .pairwise_consistency_check(&verifying_key)
        .map_err(|e| {
            CoreError::CryptoError(format!("generated key failed pairwise consistency: {e:?}"))
        })?;
    Ok(signing_key.to_bytes())
}

/// Derive the public verifying-key bytes (for client pinning) from a 64-byte signing
/// seed produced by [`generate_signing_key`]. Returns the same bytes a server's
/// `verifying_key_bytes()` would return after loading the seed.
#[cfg_attr(feature = "bindings", uniffi::export)]
pub fn verifying_key_from_signing_key(seed: Vec<u8>) -> Result<Vec<u8>, CoreError> {
    let signing_key = HybridSigningKey::from_bytes(&seed)
        .map_err(|e| CoreError::CryptoError(format!("invalid signing key seed: {e}")))?;
    Ok(signing_key.verifying_key().to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_then_derive_pubkey_round_trips() {
        let seed = generate_signing_key().expect("generate");
        assert_eq!(seed.len(), 64, "seed is ed25519[32] || ml_dsa[32]");
        let vk_from_seed = verifying_key_from_signing_key(seed.clone()).expect("derive vk");
        let sk = HybridSigningKey::from_bytes(&seed).expect("load");
        assert_eq!(vk_from_seed, sk.verifying_key().to_bytes());
        assert_eq!(vk_from_seed, verifying_key_from_signing_key(seed).expect("derive again"));
    }

    #[test]
    fn verifying_key_from_a_malformed_seed_is_a_clean_error() {
        let err = verifying_key_from_signing_key(vec![0u8; 5]).expect_err("5 bytes is not a seed");
        assert!(matches!(err, CoreError::CryptoError(_)));
    }
}
