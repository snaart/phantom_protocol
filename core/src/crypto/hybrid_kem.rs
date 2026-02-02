use x25519_dalek::{StaticSecret, PublicKey as X25519PublicKey};
use pqcrypto_kyber::kyber768;
use pqcrypto_traits::kem::{Ciphertext as KyberCiphertext, PublicKey as KyberPublicKey, SharedSecret as KyberSharedSecret, SecretKey as KyberSecretKeyTrait};
use hkdf::Hkdf;
use sha2::Sha256;
use rand::rngs::OsRng;
use borsh::{BorshSerialize, BorshDeserialize};
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};
use crate::crypto::keys::KyberSecretKey;


// Secret keys should not be blindly cloned or debug-printed.
// But we need to store them in OpenMLS KeyStore (encrypted at rest usually).
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct HybridSecretKey {
    pub x25519_sk: StaticSecret,
    pub kyber_sk: KyberSecretKey,
}

impl HybridSecretKey {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.x25519_sk.to_bytes());
        out.extend_from_slice(self.kyber_sk.0.as_bytes());
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, anyhow::Error> {
        if bytes.len() != 32 + kyber768::secret_key_bytes() {
             return Err(anyhow::anyhow!("Invalid HybridSecretKey length"));
        }
        
        let x25519_bytes: [u8; 32] = bytes[0..32].try_into()?;
        let x25519_sk = StaticSecret::from(x25519_bytes);
        
        let kyber_bytes = &bytes[32..];
        let kyber_sk = kyber768::SecretKey::from_bytes(kyber_bytes)
            .map_err(|_| anyhow::anyhow!("Invalid Kyber SK bytes"))?;
            
        Ok(Self { x25519_sk, kyber_sk: KyberSecretKey(kyber_sk) })
    }
}


impl fmt::Debug for HybridSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HybridSecretKey")
         .field("x25519_sk", &"REDACTED")
         .field("kyber_sk", &"REDACTED")
         .finish()
    }
}


#[derive(BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct HybridKeyPackage {
    pub x25519_pk: [u8; 32],
    pub kyber_pk: Vec<u8>,
}

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct HybridCiphertext {
    pub x25519_pk: [u8; 32], // Ephemeral public key from sender
    pub kyber_ct: Vec<u8>,
}

impl HybridSecretKey {
    pub fn generate() -> (Self, HybridKeyPackage) {
        let mut rng = OsRng;
        
        // X25519
        let x25519_sk = StaticSecret::random_from_rng(&mut rng);
        let x25519_pk = X25519PublicKey::from(&x25519_sk);

        // Kyber
        let (kyber_pk, kyber_sk) = kyber768::keypair();

        let secret_key = HybridSecretKey {
            x25519_sk,
            kyber_sk: KyberSecretKey(kyber_sk),
        };

        let key_package = HybridKeyPackage {
            x25519_pk: *x25519_pk.as_bytes(),
            kyber_pk: kyber_pk.as_bytes().to_vec(),
        };

        (secret_key, key_package)
    }

    pub fn decapsulate(&self, ciphertext: &HybridCiphertext) -> Result<[u8; 32], anyhow::Error> {
        // 1. X25519
        let peer_x25519 = X25519PublicKey::from(ciphertext.x25519_pk);
        let x25519_shared = self.x25519_sk.diffie_hellman(&peer_x25519);

        // 2. Kyber
        let kyber_ct = kyber768::Ciphertext::from_bytes(&ciphertext.kyber_ct)
            .map_err(|_| anyhow::anyhow!("Invalid Kyber ciphertext"))?;
        let kyber_shared = kyber768::decapsulate(&kyber_ct, &self.kyber_sk.0);

        // 3. Combine (KDF)
        Self::combine_secrets(x25519_shared.as_bytes(), kyber_shared.as_bytes())
    }

    fn combine_secrets(ecc_secret: &[u8], kyber_secret: &[u8]) -> Result<[u8; 32], anyhow::Error> {
        let hkdf = Hkdf::<Sha256>::new(None, &[ecc_secret, kyber_secret].concat());
        let mut okm = [0u8; 32];
        hkdf.expand(&b"HybridKEM_X25519_Kyber768"[..], &mut okm)
            .map_err(|_| anyhow::anyhow!("HKDF expansion failed"))?;
        Ok(okm)
    }
}

impl HybridKeyPackage {
    pub fn encapsulate(&self) -> Result<([u8; 32], HybridCiphertext), anyhow::Error> {
        let mut rng = OsRng;

        // 1. X25519
        let ephemeral_sk = StaticSecret::random_from_rng(&mut rng);
        let ephemeral_pk = X25519PublicKey::from(&ephemeral_sk);
        
        let peer_x25519 = X25519PublicKey::from(self.x25519_pk);
        let x25519_shared = ephemeral_sk.diffie_hellman(&peer_x25519);

        // 2. Kyber
        let kyber_pk = kyber768::PublicKey::from_bytes(&self.kyber_pk)
             .map_err(|_| anyhow::anyhow!("Invalid Kyber public key"))?;
        let (kyber_shared, kyber_ct) = kyber768::encapsulate(&kyber_pk);

        // 3. Combine
        let shared_secret = HybridSecretKey::combine_secrets(x25519_shared.as_bytes(), kyber_shared.as_bytes())?;

        let ciphertext = HybridCiphertext {
            x25519_pk: *ephemeral_pk.as_bytes(),
            kyber_ct: kyber_ct.as_bytes().to_vec(),
        };

        Ok((shared_secret, ciphertext))
    }
}
