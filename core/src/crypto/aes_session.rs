//! High-Performance AES-GCM Session Encryption
//!
//! Uses `ring` crate for AES-256-GCM with hardware acceleration.
//! On Apple Silicon M1: ARM FEAT_AES intrinsics (~4-8 GB/s)
//! On x86_64: AES-NI instructions (~4-8 GB/s)
//!
//! `ring` uses hand-optimized assembly for both ARM64 and x86_64,
//! ensuring maximum throughput compared to pure-Rust crates.

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use std::sync::atomic::{AtomicU64, Ordering};

/// Overhead bytes added by AES-256-GCM (16-byte auth tag)
pub const AES_GCM_OVERHEAD: usize = 16;

/// High-performance session encryption using ring's AES-256-GCM
/// (hardware accelerated on ARM64/x86_64)
pub struct AesSession {
    /// Send cipher key
    send_key: LessSafeKey,
    /// Receive cipher key
    recv_key: LessSafeKey,
    /// Send nonce counter
    send_counter: AtomicU64,
    /// Receive nonce counter
    recv_counter: AtomicU64,
    /// Nonce prefix (4 bytes, set per session)
    nonce_prefix: [u8; 4],
}

impl AesSession {
    /// Create from a 32-byte shared secret (derived from PQC handshake).
    /// This is the "initiator" side.
    /// Create from a 32-byte shared secret (derived from PQC handshake).
    /// This is the "initiator" side.
    pub fn from_shared_secret(shared_secret: &[u8; 32]) -> Result<Self, crate::CoreError> {
        Self::build(shared_secret, false)
    }

    /// Create the "peer" (responder) side — send/recv keys are swapped so that
    /// initiator's encrypt can be decrypted by peer's decrypt, and vice versa.
    /// Create the "peer" (responder) side — send/recv keys are swapped so that
    /// initiator's encrypt can be decrypted by peer's decrypt, and vice versa.
    pub fn from_shared_secret_peer(shared_secret: &[u8; 32]) -> Result<Self, crate::CoreError> {
        Self::build(shared_secret, true)
    }

    fn build(shared_secret: &[u8; 32], swap: bool) -> Result<Self, crate::CoreError> {
        // `crypto::kdf::derive_key_32` cfg-dispatches between
        // `blake3::derive_key` (default) and HKDF-SHA256 (`--features
        // fips`). API shape and 32-byte output are identical.
        let key_a = crate::crypto::kdf::derive_key_32("phantom-aes-send-v1", shared_secret);
        let key_b = crate::crypto::kdf::derive_key_32("phantom-aes-recv-v1", shared_secret);

        let (send_bytes, recv_bytes) = if swap { (key_b, key_a) } else { (key_a, key_b) };

        let send_unbound = UnboundKey::new(&AES_256_GCM, &send_bytes)
            .map_err(|_| crate::CoreError::CryptoError("Invalid key".into()))?;
        let recv_unbound = UnboundKey::new(&AES_256_GCM, &recv_bytes)
            .map_err(|_| crate::CoreError::CryptoError("Invalid key".into()))?;

        let prefix_bytes =
            crate::crypto::kdf::derive_key_32("phantom-nonce-pfx-v1", shared_secret);
        let mut nonce_prefix = [0u8; 4];
        nonce_prefix.copy_from_slice(&prefix_bytes[..4]);

        Ok(Self {
            send_key: LessSafeKey::new(send_unbound),
            recv_key: LessSafeKey::new(recv_unbound),
            send_counter: AtomicU64::new(0),
            recv_counter: AtomicU64::new(0),
            nonce_prefix,
        })
    }

    /// Encrypt in place: appends 16-byte tag. Returns total ciphertext length.
    #[inline]
    pub fn encrypt_in_place(&self, aad: &[u8], buf: &mut Vec<u8>) -> Result<(), EncryptError> {
        let counter = self.send_counter.fetch_add(1, Ordering::Relaxed);
        let nonce = self.make_nonce(counter);
        self.send_key
            .seal_in_place_append_tag(nonce, Aad::from(aad), buf)
            .map_err(|_| EncryptError::EncryptionFailed)?;
        Ok(())
    }

    /// Encrypt: allocates a new Vec with ciphertext.
    #[inline]
    pub fn encrypt(&self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, EncryptError> {
        let mut buf = Vec::with_capacity(plaintext.len() + AES_GCM_OVERHEAD);
        buf.extend_from_slice(plaintext);
        self.encrypt_in_place(aad, &mut buf)?;
        Ok(buf)
    }

    /// Decrypt in place: verifies tag and truncates. Returns plaintext slice.
    #[inline]
    pub fn decrypt_in_place<'a>(
        &self,
        aad: &[u8],
        buf: &'a mut [u8],
    ) -> Result<&'a mut [u8], EncryptError> {
        let counter = self.recv_counter.fetch_add(1, Ordering::Relaxed);
        let nonce = self.make_nonce(counter);
        self.recv_key
            .open_in_place(nonce, Aad::from(aad), buf)
            .map_err(|_| EncryptError::DecryptionFailed)
    }

    /// Decrypt: allocates a new Vec with plaintext.
    #[inline]
    pub fn decrypt(&self, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, EncryptError> {
        let mut buf = ciphertext.to_vec();
        let plaintext = self.decrypt_in_place(aad, &mut buf)?;
        let len = plaintext.len();
        buf.truncate(len);
        Ok(buf)
    }

    #[inline(always)]
    fn make_nonce(&self, counter: u64) -> Nonce {
        let mut n = [0u8; 12];
        n[..4].copy_from_slice(&self.nonce_prefix);
        n[4..12].copy_from_slice(&counter.to_be_bytes());
        Nonce::assume_unique_for_key(n)
    }
}

/// Encryption errors
#[derive(Debug, Clone, Copy)]
pub enum EncryptError {
    EncryptionFailed,
    DecryptionFailed,
}

impl std::fmt::Display for EncryptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EncryptionFailed => write!(f, "Encryption failed"),
            Self::DecryptionFailed => write!(f, "Decryption / authentication failed"),
        }
    }
}

impl std::error::Error for EncryptError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let secret = [0xABu8; 32];
        // Two "peers" derived from the same secret, but with swapped keys
        // Two "peers" derived from the same secret, but with swapped keys
        let session_a = AesSession::from_shared_secret(&secret).unwrap();
        let session_b = AesSession::from_shared_secret_peer(&secret).unwrap();

        let msg = b"Hello, PQC world!";
        let ct = session_a.encrypt(&[], msg).expect("Encryption failed");

        // session_b decrypt uses recv_key which matches session_a's send_key
        let pt = session_b.decrypt(&[], &ct).expect("Decryption failed");
        assert_eq!(&pt, msg);
    }

    #[test]
    fn throughput_smoke() {
        use std::time::Instant;

        let session = AesSession::from_shared_secret(&[0xAB; 32]).unwrap();
        let data = vec![0u8; 64 * 1024];
        let iters = 50_000;

        let start = Instant::now();
        for _ in 0..iters {
            let enc = session.encrypt(&[], &data).expect("Encryption failed");
            std::hint::black_box(enc);
        }
        let elapsed = start.elapsed();

        let total_mb = (data.len() * iters) as f64 / 1024.0 / 1024.0;
        let throughput = total_mb / elapsed.as_secs_f64();
        eprintln!("ring AES-256-GCM: {:.0} MiB/s", throughput);
        // With HW AES should be well above 1 GiB/s
    }
}
