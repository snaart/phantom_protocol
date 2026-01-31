//! Adaptive Crypto Engine
//!
//! Автоматический выбор шифра в зависимости от HW capabilities:
//! - AES-256-GCM (ring asm) → Apple Silicon (FEAT_AES), x86_64 (AES-NI)
//! - ChaCha20-Poly1305 (ring asm) → ARM без AES, MIPS, RISC-V, IoT
//!
//! На устройствах без HW AES ChaCha20 в 3-4x быстрее.
//! На устройствах с HW AES AES-GCM в ~1.3x быстрее ChaCha20.

use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, CHACHA20_POLY1305};
use std::sync::atomic::{AtomicU64, Ordering};

/// Overhead bytes: both AES-GCM and ChaCha20-Poly1305 produce a 16-byte tag
pub const AEAD_OVERHEAD: usize = 16;

/// Supported cipher suites
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CipherSuite {
    /// AES-256-GCM — optimal on HW-accelerated platforms
    Aes256Gcm = 1,
    /// ChaCha20-Poly1305 — optimal on SW-only platforms (IoT, old ARM)
    ChaCha20Poly1305 = 2,
}

impl CipherSuite {
    /// Byte representation for handshake negotiation
    pub fn to_byte(self) -> u8 {
        self as u8
    }

    /// Parse from byte
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            1 => Some(Self::Aes256Gcm),
            2 => Some(Self::ChaCha20Poly1305),
            _ => None,
        }
    }

    /// AEAD algorithm reference for ring
    fn algorithm(&self) -> &'static aead::Algorithm {
        match self {
            Self::Aes256Gcm => &AES_256_GCM,
            Self::ChaCha20Poly1305 => &CHACHA20_POLY1305,
        }
    }
}

/// Hardware capabilities report
#[derive(Debug, Clone, Copy)]
pub struct HwCaps {
    pub has_hw_aes: bool,
}

impl HwCaps {
    /// Detect hardware capabilities on the current platform
    pub fn detect() -> Self {
        Self {
            has_hw_aes: Self::detect_hw_aes(),
        }
    }

    #[cfg(target_arch = "aarch64")]
    fn detect_hw_aes() -> bool {
        std::arch::is_aarch64_feature_detected!("aes")
    }

    #[cfg(target_arch = "x86_64")]
    fn detect_hw_aes() -> bool {
        std::is_x86_feature_detected!("aes")
    }

    #[cfg(target_arch = "x86")]
    fn detect_hw_aes() -> bool {
        std::is_x86_feature_detected!("aes")
    }

    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64", target_arch = "x86")))]
    fn detect_hw_aes() -> bool {
        false // MIPS, RISC-V, ARM32 without crypto extension → no HW AES
    }

    /// Recommend best cipher for this hardware
    pub fn recommended_cipher(&self) -> CipherSuite {
        if self.has_hw_aes {
            CipherSuite::Aes256Gcm
        } else {
            CipherSuite::ChaCha20Poly1305
        }
    }
}

/// Negotiate best cipher suite between client and server
pub fn negotiate_cipher(
    client_preferred: &[CipherSuite],
    server_caps: &HwCaps,
) -> CipherSuite {
    let server_pref = server_caps.recommended_cipher();
    // If server's preference is in client's list, use it
    if client_preferred.contains(&server_pref) {
        return server_pref;
    }
    // Otherwise use client's first choice
    client_preferred.first().copied().unwrap_or(CipherSuite::ChaCha20Poly1305)
}

/// Unified crypto session — works with any supported cipher suite.
///
/// Drop-in replacement for `AesSession` with auto cipher selection.
pub struct CryptoSession {
    suite: CipherSuite,
    send_key: LessSafeKey,
    recv_key: LessSafeKey,
    send_counter: AtomicU64,
    recv_counter: AtomicU64,
    nonce_prefix: [u8; 4],
}

impl CryptoSession {
    /// Auto-detect best cipher and create session from shared secret.
    /// Initiator side.
    pub fn from_shared_secret(shared_secret: &[u8; 32]) -> Self {
        let suite = HwCaps::detect().recommended_cipher();
        Self::build(shared_secret, suite, false)
    }

    /// Auto-detect, peer (responder) side — keys swapped.
    pub fn from_shared_secret_peer(shared_secret: &[u8; 32]) -> Self {
        let suite = HwCaps::detect().recommended_cipher();
        Self::build(shared_secret, suite, true)
    }

    /// Create with explicit cipher suite (for negotiation scenarios).
    /// Initiator side.
    pub fn with_suite(shared_secret: &[u8; 32], suite: CipherSuite) -> Self {
        Self::build(shared_secret, suite, false)
    }

    /// Create with explicit cipher suite. Peer side.
    pub fn with_suite_peer(shared_secret: &[u8; 32], suite: CipherSuite) -> Self {
        Self::build(shared_secret, suite, true)
    }

    fn build(shared_secret: &[u8; 32], suite: CipherSuite, swap: bool) -> Self {
        let ctx = match suite {
            CipherSuite::Aes256Gcm => "phantom-aes-",
            CipherSuite::ChaCha20Poly1305 => "phantom-cc20-",
        };
        let send_label = format!("{}send-v1", ctx);
        let recv_label = format!("{}recv-v1", ctx);

        let key_a = blake3::derive_key(&send_label, shared_secret);
        let key_b = blake3::derive_key(&recv_label, shared_secret);

        let (send_bytes, recv_bytes) = if swap { (key_b, key_a) } else { (key_a, key_b) };

        let algo = suite.algorithm();
        let send_unbound = UnboundKey::new(algo, &send_bytes).unwrap();
        let recv_unbound = UnboundKey::new(algo, &recv_bytes).unwrap();

        let prefix_bytes = blake3::derive_key("phantom-nonce-pfx-v1", shared_secret);
        let mut nonce_prefix = [0u8; 4];
        nonce_prefix.copy_from_slice(&prefix_bytes[..4]);

        Self {
            suite,
            send_key: LessSafeKey::new(send_unbound),
            recv_key: LessSafeKey::new(recv_unbound),
            send_counter: AtomicU64::new(0),
            recv_counter: AtomicU64::new(0),
            nonce_prefix,
        }
    }

    /// Which cipher suite is active
    #[inline]
    pub fn cipher_suite(&self) -> CipherSuite {
        self.suite
    }

    /// Encrypt in place: appends 16-byte tag.
    #[inline]
    pub fn encrypt_in_place(&self, buf: &mut Vec<u8>) -> Result<(), CryptoError> {
        let counter = self.send_counter.fetch_add(1, Ordering::Relaxed);
        let nonce = self.make_nonce(counter);
        self.send_key
            .seal_in_place_append_tag(nonce, Aad::empty(), buf)
            .map_err(|_| CryptoError::EncryptionFailed)?;
        Ok(())
    }

    /// Encrypt in place with offset: leaves `offset` bytes untouched at the start
    /// (for prepending frame headers). Encrypts buf[offset..] in place, appends tag.
    /// Returns ciphertext length (data + tag).
    #[inline]
    pub fn encrypt_in_place_offset(
        &self,
        buf: &mut Vec<u8>,
        offset: usize,
    ) -> Result<usize, CryptoError> {
        let counter = self.send_counter.fetch_add(1, Ordering::Relaxed);
        let nonce = self.make_nonce(counter);
        // seal_in_place_separate_tag works on &mut [u8] (no Extend needed)
        let tag = self.send_key
            .seal_in_place_separate_tag(nonce, Aad::empty(), &mut buf[offset..])
            .map_err(|_| CryptoError::EncryptionFailed)?;
        // Manually append the 16-byte auth tag
        buf.extend_from_slice(tag.as_ref());
        Ok(buf.len() - offset)
    }

    /// Encrypt: allocates a new Vec.
    #[inline]
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut buf = Vec::with_capacity(plaintext.len() + AEAD_OVERHEAD);
        buf.extend_from_slice(plaintext);
        self.encrypt_in_place(&mut buf)?;
        Ok(buf)
    }

    /// Decrypt in place: verifies tag and returns plaintext slice.
    #[inline]
    pub fn decrypt_in_place<'a>(&self, buf: &'a mut [u8]) -> Result<&'a mut [u8], CryptoError> {
        let counter = self.recv_counter.fetch_add(1, Ordering::Relaxed);
        let nonce = self.make_nonce(counter);
        self.recv_key
            .open_in_place(nonce, Aad::empty(), buf)
            .map_err(|_| CryptoError::DecryptionFailed)
    }

    /// Decrypt: allocates a new Vec.
    #[inline]
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut buf = ciphertext.to_vec();
        let plaintext = self.decrypt_in_place(&mut buf)?;
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

/// Crypto errors
#[derive(Debug, Clone, Copy)]
pub enum CryptoError {
    EncryptionFailed,
    DecryptionFailed,
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EncryptionFailed => write!(f, "Encryption failed"),
            Self::DecryptionFailed => write!(f, "Decryption / authentication failed"),
        }
    }
}

impl std::error::Error for CryptoError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hw_detection() {
        let caps = HwCaps::detect();
        let suite = caps.recommended_cipher();
        eprintln!("HW AES: {}, Recommended: {:?}", caps.has_hw_aes, suite);
        // On Apple Silicon / modern x86, should pick AES
        // On old ARM / MIPS, should pick ChaCha20
    }

    #[test]
    fn round_trip_aes() {
        let secret = [0xABu8; 32];
        let a = CryptoSession::with_suite(&secret, CipherSuite::Aes256Gcm);
        let b = CryptoSession::with_suite_peer(&secret, CipherSuite::Aes256Gcm);

        let msg = b"Hello, PQ AES world!";
        let ct = a.encrypt(msg).unwrap();
        let pt = b.decrypt(&ct).unwrap();
        assert_eq!(&pt, msg);
    }

    #[test]
    fn round_trip_chacha() {
        let secret = [0xCDu8; 32];
        let a = CryptoSession::with_suite(&secret, CipherSuite::ChaCha20Poly1305);
        let b = CryptoSession::with_suite_peer(&secret, CipherSuite::ChaCha20Poly1305);

        let msg = b"Hello, PQ ChaCha world!";
        let ct = a.encrypt(msg).unwrap();
        let pt = b.decrypt(&ct).unwrap();
        assert_eq!(&pt, msg);
    }

    #[test]
    fn round_trip_auto() {
        let secret = [0xEFu8; 32];
        let a = CryptoSession::from_shared_secret(&secret);
        let b = CryptoSession::from_shared_secret_peer(&secret);

        assert_eq!(a.cipher_suite(), b.cipher_suite());
        let msg = b"Auto-detected cipher!";
        let ct = a.encrypt(msg).unwrap();
        let pt = b.decrypt(&ct).unwrap();
        assert_eq!(&pt, msg);
    }

    #[test]
    fn in_place_with_offset() {
        let secret = [0xAB; 32];
        let session = CryptoSession::with_suite(&secret, CipherSuite::Aes256Gcm);
        let peer = CryptoSession::with_suite_peer(&secret, CipherSuite::Aes256Gcm);

        let data = b"Payload after header";
        let header_len = 4usize;
        let mut buf = Vec::with_capacity(header_len + data.len() + AEAD_OVERHEAD);
        buf.extend_from_slice(&[0u8; 4]); // placeholder for header
        buf.extend_from_slice(data);

        let ct_len = session.encrypt_in_place_offset(&mut buf, header_len).unwrap();

        // Write header
        buf[..4].copy_from_slice(&(ct_len as u32).to_be_bytes());

        // Decrypt on peer side
        let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        let pt = peer.decrypt_in_place(&mut buf[4..4 + len]).unwrap();
        assert_eq!(pt, data);
    }

    #[test]
    fn negotiation() {
        let server_aes = HwCaps { has_hw_aes: true };
        let server_no_aes = HwCaps { has_hw_aes: false };

        // Client prefers both, server has AES → AES
        let result = negotiate_cipher(
            &[CipherSuite::Aes256Gcm, CipherSuite::ChaCha20Poly1305],
            &server_aes,
        );
        assert_eq!(result, CipherSuite::Aes256Gcm);

        // Client prefers both, server no AES → ChaCha20
        let result = negotiate_cipher(
            &[CipherSuite::Aes256Gcm, CipherSuite::ChaCha20Poly1305],
            &server_no_aes,
        );
        assert_eq!(result, CipherSuite::ChaCha20Poly1305);

        // Client only ChaCha, server has AES → ChaCha (client's preference)
        let result = negotiate_cipher(
            &[CipherSuite::ChaCha20Poly1305],
            &server_aes,
        );
        assert_eq!(result, CipherSuite::ChaCha20Poly1305);
    }

    #[test]
    fn throughput_comparison() {
        use std::time::Instant;

        let secret = [0xAB; 32];
        let data = vec![0u8; 16 * 1024]; // 16KB
        let iters = 50_000;

        for suite in [CipherSuite::Aes256Gcm, CipherSuite::ChaCha20Poly1305] {
            let session = CryptoSession::with_suite(&secret, suite);
            let start = Instant::now();
            for _ in 0..iters {
                let e = session.encrypt(&data).unwrap();
                std::hint::black_box(e);
            }
            let elapsed = start.elapsed();
            let tput = (data.len() * iters) as f64 / 1_048_576.0 / elapsed.as_secs_f64();
            eprintln!("{:?}: {:.0} MiB/s", suite, tput);
        }
    }
}
