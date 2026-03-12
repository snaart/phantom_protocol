//! Adaptive Crypto Engine
//!
//! Автоматический выбор шифра в зависимости от HW capabilities:
//! - AES-256-GCM (ring asm) → Apple Silicon (FEAT_AES), x86_64 (AES-NI)
//! - ChaCha20-Poly1305 (ring asm) → ARM без AES, MIPS, RISC-V, IoT
//!
//! На устройствах без HW AES ChaCha20 в 3-4x быстрее.
//! На устройствах с HW AES AES-GCM в ~1.3x быстрее ChaCha20.

use crate::errors::CoreError;
use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, CHACHA20_POLY1305};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;


/// Overhead bytes: both AES-GCM and ChaCha20-Poly1305 produce a 16-byte tag
pub const AEAD_OVERHEAD: usize = 16;

/// Hard upper bound on per-direction AEAD invocations before forcing a key
/// rotation (or, in the absence of rekey, failing the operation).
///
/// AES-GCM's safety margins under deterministic-counter nonces are governed
/// by NIST SP 800-38D: with this construction the key may be used for up to
/// 2^48 invocations before the security level meaningfully degrades. We pick
/// 2^48 as a defensive ceiling.  At 10^6 packets/sec it is ~9 years away —
/// effectively unreachable for any real session — but the explicit check
/// prevents catastrophic key abuse if a counter ever rolls back or a callsite
/// loops pathologically.
///
/// When mid-session key rotation lands (Phase 1.5 in
/// `docs/PRODUCTION_READINESS.md`) the rekey trigger will fire well before
/// this limit so the error path here becomes a backstop, not a normal failure
/// mode.
pub const AEAD_MAX_INVOCATIONS: u64 = 1u64 << 48;

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
/// Unified crypto session — works with any supported cipher suite.
///
/// Drop-in replacement for `AesSession` with auto cipher selection.
#[derive(Clone)]
pub struct CryptoSession {
    inner: Arc<CryptoSessionInner>,
}

struct CryptoSessionInner {
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
    pub fn from_shared_secret(shared_secret: &[u8; 32]) -> Result<Self, CoreError> {
        let suite = HwCaps::detect().recommended_cipher();
        Self::build(shared_secret, suite, false)
    }

    /// Auto-detect, peer (responder) side — keys swapped.
    pub fn from_shared_secret_peer(shared_secret: &[u8; 32]) -> Result<Self, CoreError> {
        let suite = HwCaps::detect().recommended_cipher();
        Self::build(shared_secret, suite, true)
    }

    /// Create with explicit cipher suite (for negotiation scenarios).
    /// Initiator side.
    pub fn with_suite(shared_secret: &[u8; 32], suite: CipherSuite) -> Result<Self, CoreError> {
        Self::build(shared_secret, suite, false)
    }

    /// Create with explicit cipher suite. Peer side.
    pub fn with_suite_peer(shared_secret: &[u8; 32], suite: CipherSuite) -> Result<Self, CoreError> {
        Self::build(shared_secret, suite, true)
    }

    fn build(shared_secret: &[u8; 32], suite: CipherSuite, swap: bool) -> Result<Self, CoreError> {
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
        let send_unbound = UnboundKey::new(algo, &send_bytes)
            .map_err(|_| CoreError::CryptoError("Failed to create send key".into()))?;
        let recv_unbound = UnboundKey::new(algo, &recv_bytes)
            .map_err(|_| CoreError::CryptoError("Failed to create recv key".into()))?;

        let prefix_bytes = blake3::derive_key("phantom-nonce-pfx-v1", shared_secret);
        let mut nonce_prefix = [0u8; 4];
        nonce_prefix.copy_from_slice(&prefix_bytes[..4]);

        Ok(Self {
            inner: Arc::new(CryptoSessionInner {
                suite,
                send_key: LessSafeKey::new(send_unbound),
                recv_key: LessSafeKey::new(recv_unbound),
                send_counter: AtomicU64::new(0),
                recv_counter: AtomicU64::new(0),
                nonce_prefix,
            }),
        })
    }

    /// Which cipher suite is active
    #[inline]
    pub fn cipher_suite(&self) -> CipherSuite {
        self.inner.suite
    }

    /// Encrypt in place: appends 16-byte tag.
    #[inline]
    pub fn encrypt_in_place(&self, aad: &[u8], buf: &mut Vec<u8>) -> Result<(), CryptoError> {
        let counter = self.inner.send_counter.fetch_add(1, Ordering::Relaxed);
        if counter >= AEAD_MAX_INVOCATIONS {
            return Err(CryptoError::NonceExhausted);
        }
        let nonce = self.make_nonce(counter);
        self.inner
            .send_key
            .seal_in_place_append_tag(nonce, Aad::from(aad), buf)
            .map_err(|_| CryptoError::EncryptionFailed)?;
        Ok(())
    }

    /// Encrypt in place with offset: leaves `offset` bytes untouched at the start
    /// (for prepending frame headers). Encrypts buf[offset..] in place, appends tag.
    /// Returns ciphertext length (data + tag).
    #[inline]
    pub fn encrypt_in_place_offset(
        &self,
        aad: &[u8],
        buf: &mut Vec<u8>,
        offset: usize,
    ) -> Result<usize, CryptoError> {
        let counter = self.inner.send_counter.fetch_add(1, Ordering::Relaxed);
        if counter >= AEAD_MAX_INVOCATIONS {
            return Err(CryptoError::NonceExhausted);
        }
        let nonce = self.make_nonce(counter);
        // seal_in_place_separate_tag works on &mut [u8] (no Extend needed)
        let tag = self.inner
            .send_key
            .seal_in_place_separate_tag(nonce, Aad::from(aad), &mut buf[offset..])
            .map_err(|_| CryptoError::EncryptionFailed)?;
        // Manually append the 16-byte auth tag
        buf.extend_from_slice(tag.as_ref());
        Ok(buf.len() - offset)
    }


    /// Encrypt: allocates a new Vec.
    #[inline]
    pub fn encrypt(&self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut buf = Vec::with_capacity(plaintext.len() + AEAD_OVERHEAD);
        buf.extend_from_slice(plaintext);
        self.encrypt_in_place(aad, &mut buf)?;
        Ok(buf)
    }

    /// Decrypt in place: verifies tag and returns plaintext slice.
    #[inline]
    pub fn decrypt_in_place<'a>(&self, aad: &[u8], buf: &'a mut [u8]) -> Result<&'a mut [u8], CryptoError> {
        let counter = self.inner.recv_counter.fetch_add(1, Ordering::Relaxed);
        if counter >= AEAD_MAX_INVOCATIONS {
            return Err(CryptoError::NonceExhausted);
        }
        let nonce = self.make_nonce(counter);
        self.inner
            .recv_key
            .open_in_place(nonce, Aad::from(aad), buf)
            .map_err(|_| CryptoError::DecryptionFailed)
    }

    /// Number of encryptions performed on this session (per-direction send counter).
    /// Useful for emitting `aead_invocations_total` metrics and for rekey-trigger
    /// logic when mid-session key rotation lands.
    #[inline]
    pub fn send_invocations(&self) -> u64 {
        self.inner.send_counter.load(Ordering::Relaxed)
    }

    /// Number of decryptions performed on this session (per-direction recv counter).
    #[inline]
    pub fn recv_invocations(&self) -> u64 {
        self.inner.recv_counter.load(Ordering::Relaxed)
    }

    /// Decrypt: allocates a new Vec.
    #[inline]
    pub fn decrypt(&self, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut buf = ciphertext.to_vec();
        let plaintext = self.decrypt_in_place(aad, &mut buf)?;
        let len = plaintext.len();
        buf.truncate(len);
        Ok(buf)
    }

    // ── V2 / explicit-nonce path ───────────────────────────────────────
    //
    // The V1 paths above derive the AEAD nonce from an internal monotonic
    // counter — fast and minimal-on-wire, but fragile under attack: a
    // failed decrypt still advances the counter, so a follow-up legitimate
    // packet decrypts under a different nonce than the sender used.
    //
    // V2 fixes this by deriving the nonce from the authenticated header
    // fields the caller supplies. Failed decrypts no longer desync the
    // receiver. The counter API is kept in place so the caller can still
    // track / cap invocation counts for telemetry.

    /// Encrypt with an explicit caller-supplied nonce. The caller MUST
    /// ensure uniqueness of `(key, nonce)` — the V2 path derives the nonce
    /// from `(nonce_prefix, epoch, stream_id, sequence)` so uniqueness
    /// follows from the wire-format invariant that sender never reuses
    /// `(stream_id, sequence)` within an epoch.
    #[inline]
    pub fn encrypt_with_nonce(
        &self,
        nonce_bytes: [u8; 12],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let counter = self.inner.send_counter.fetch_add(1, Ordering::Relaxed);
        if counter >= AEAD_MAX_INVOCATIONS {
            return Err(CryptoError::NonceExhausted);
        }
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        let mut buf = Vec::with_capacity(plaintext.len() + AEAD_OVERHEAD);
        buf.extend_from_slice(plaintext);
        self.inner
            .send_key
            .seal_in_place_append_tag(nonce, Aad::from(aad), &mut buf)
            .map_err(|_| CryptoError::EncryptionFailed)?;
        Ok(buf)
    }

    /// Decrypt with an explicit caller-supplied nonce. Unlike [`decrypt`],
    /// a tag-check failure does NOT advance the internal counter — only
    /// the bounded telemetry counter increments.
    #[inline]
    pub fn decrypt_with_nonce(
        &self,
        nonce_bytes: [u8; 12],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let counter = self.inner.recv_counter.fetch_add(1, Ordering::Relaxed);
        if counter >= AEAD_MAX_INVOCATIONS {
            return Err(CryptoError::NonceExhausted);
        }
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        let mut buf = ciphertext.to_vec();
        let plaintext_slice = self
            .inner
            .recv_key
            .open_in_place(nonce, Aad::from(aad), &mut buf)
            .map_err(|_| CryptoError::DecryptionFailed)?;
        let len = plaintext_slice.len();
        buf.truncate(len);
        Ok(buf)
    }

    /// Expose the 4-byte nonce prefix for the V2 nonce construction
    /// (`prefix || epoch || stream_id_be || sequence_be`).
    #[inline]
    pub fn nonce_prefix(&self) -> [u8; 4] {
        self.inner.nonce_prefix
    }

    #[inline(always)]
    fn make_nonce(&self, counter: u64) -> Nonce {
        let mut n = [0u8; 12];
        n[..4].copy_from_slice(&self.inner.nonce_prefix);
        n[4..12].copy_from_slice(&counter.to_be_bytes());
        Nonce::assume_unique_for_key(n)
    }
}


/// Crypto errors
#[derive(Debug, Clone, Copy)]
pub enum CryptoError {
    EncryptionFailed,
    DecryptionFailed,
    /// Per-direction AEAD counter would exceed [`AEAD_MAX_INVOCATIONS`].
    /// Callers must rotate keys (Phase 1.5) or close the session.
    NonceExhausted,
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EncryptionFailed => write!(f, "Encryption failed"),
            Self::DecryptionFailed => write!(f, "Decryption / authentication failed"),
            Self::NonceExhausted => write!(
                f,
                "AEAD nonce exhausted: per-direction counter exceeded {} invocations \
                 (rotate keys before reusing this session)",
                AEAD_MAX_INVOCATIONS
            ),
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
        let a = CryptoSession::with_suite(&secret, CipherSuite::Aes256Gcm).unwrap();
        let b = CryptoSession::with_suite_peer(&secret, CipherSuite::Aes256Gcm).unwrap();

        let msg = b"Hello, PQ AES world!";
        let ct = a.encrypt(&[], msg).unwrap();
        let pt = b.decrypt(&[], &ct).unwrap();
        assert_eq!(&pt, msg);
    }

    #[test]
    fn round_trip_chacha() {
        let secret = [0xCDu8; 32];
        let a = CryptoSession::with_suite(&secret, CipherSuite::ChaCha20Poly1305).unwrap();
        let b = CryptoSession::with_suite_peer(&secret, CipherSuite::ChaCha20Poly1305).unwrap();

        let msg = b"Hello, PQ ChaCha world!";
        let ct = a.encrypt(&[], msg).unwrap();
        let pt = b.decrypt(&[], &ct).unwrap();
        assert_eq!(&pt, msg);
    }

    #[test]
    fn round_trip_auto() {
        let secret = [0xEFu8; 32];
        let a = CryptoSession::from_shared_secret(&secret).unwrap();
        let b = CryptoSession::from_shared_secret_peer(&secret).unwrap();

        assert_eq!(a.cipher_suite(), b.cipher_suite());
        let msg = b"Auto-detected cipher!";
        let ct = a.encrypt(&[], msg).unwrap();
        let pt = b.decrypt(&[], &ct).unwrap();
        assert_eq!(&pt, msg);
    }

    #[test]
    fn in_place_with_offset() {
        let secret = [0xAB; 32];
        let session = CryptoSession::with_suite(&secret, CipherSuite::Aes256Gcm).unwrap();
        let peer = CryptoSession::with_suite_peer(&secret, CipherSuite::Aes256Gcm).unwrap();

        let data = b"Payload after header";
        let header_len = 4usize;
        let mut buf = Vec::with_capacity(header_len + data.len() + AEAD_OVERHEAD);
        buf.extend_from_slice(&[0u8; 4]); // placeholder for header
        buf.extend_from_slice(data);

        let ct_len = session.encrypt_in_place_offset(&[0u8; 4], &mut buf, header_len).unwrap();

        // Write header
        buf[..4].copy_from_slice(&(ct_len as u32).to_be_bytes());

        // Decrypt on peer side
        let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        let (_header, payload) = buf.split_at_mut(4);
        let pt = peer.decrypt_in_place(&[0u8; 4], &mut payload[..len]).unwrap();
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
            let session = CryptoSession::with_suite(&secret, suite).unwrap();
            let start = Instant::now();
            for _ in 0..iters {
                let e = session.encrypt(&[], &data).unwrap();
                std::hint::black_box(e);
            }
            let elapsed = start.elapsed();
            let tput = (data.len() * iters) as f64 / 1_048_576.0 / elapsed.as_secs_f64();
            eprintln!("{:?}: {:.0} MiB/s", suite, tput);
        }
    }
}
