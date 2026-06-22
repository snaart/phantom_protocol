//! Adaptive Crypto Engine
//!
//! Picks the AEAD cipher automatically from the host's hardware capabilities:
//! - AES-256-GCM (ring asm) → Apple Silicon (FEAT_AES), x86_64 (AES-NI)
//! - ChaCha20-Poly1305 (ring asm) → ARM without AES, MIPS, RISC-V, IoT
//!
//! Without HW AES, ChaCha20 is ~3-4x faster; with HW AES, AES-GCM is ~1.3x
//! faster than ChaCha20.
//!
//! Under `--features fips` the AEAD backend swaps to `aws-lc-rs`
//! (FIPS-validated AWS-LC). The Rust API surface is identical to
//! `ring::aead`, so the rest of this module is untouched. The cipher
//! suite enum keeps `ChaCha20Poly1305` (wire-format stability) but the
//! negotiation/build paths reject it under `fips`.

use crate::errors::CoreError;
#[cfg(feature = "fips")]
use aws_lc_rs::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, CHACHA20_POLY1305};
#[cfg(not(feature = "fips"))]
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
/// Mid-session key rotation (`Session::rekey`, label `"phantom-rekey-v1"`) is
/// implemented and fires its rekey trigger well below this limit, so in normal
/// operation this error path is a backstop, not a reachable failure mode. It is
/// pinned by Security Invariant #8.
pub const AEAD_MAX_INVOCATIONS: u64 = 1u64 << 48;

/// Supported cipher suites.
///
/// The wire byte for each variant is stable across feature configurations —
/// `Aes256Gcm = 1`, `ChaCha20Poly1305 = 2` — so a peer's `CipherSuite`
/// offer round-trips through `to_byte` / `from_byte` regardless of which
/// build the peer is running. Under `--features fips` only `Aes256Gcm`
/// is actually selectable; `ChaCha20Poly1305` is reserved for
/// wire-format stability and is rejected at `negotiate_cipher` /
/// `CryptoSession::with_suite{_peer}` with
/// `CoreError::CipherSuiteUnavailable`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CipherSuite {
    /// AES-256-GCM — optimal on HW-accelerated platforms.
    /// FIPS-approved; the only suite selectable under `--features fips`.
    Aes256Gcm = 1,
    /// ChaCha20-Poly1305 — optimal on SW-only platforms (IoT, old ARM).
    ///
    /// **Reserved for wire-format stability under `--features fips`.**
    /// The variant remains in the enum so a peer's offer can still be
    /// parsed and a clear `CipherSuiteUnavailable` error returned;
    /// construction via `CryptoSession::with_suite{_peer}` and selection
    /// in `negotiate_cipher` are explicitly rejected under fips. Not
    /// FIPS-approved (RFC 7539 / 8439 — outside FIPS 140-3 Annex A).
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

    /// Recommend best cipher for this hardware.
    ///
    /// Under `--features fips` the only FIPS-approved AEAD on the wire
    /// is `Aes256Gcm`, so we pin the recommendation regardless of
    /// hardware capability — software AES is still allowed; only the
    /// cipher choice is restricted.
    pub fn recommended_cipher(&self) -> CipherSuite {
        #[cfg(feature = "fips")]
        {
            let _ = self.has_hw_aes;
            CipherSuite::Aes256Gcm
        }
        #[cfg(not(feature = "fips"))]
        {
            if self.has_hw_aes {
                CipherSuite::Aes256Gcm
            } else {
                CipherSuite::ChaCha20Poly1305
            }
        }
    }
}

/// Negotiate best cipher suite between client and server.
///
/// Returns `Err(CoreError::CipherSuiteUnavailable)` under `--features
/// fips` when the client does not offer a FIPS-approved suite
/// (today: `Aes256Gcm`). On non-fips builds this never fails; the
/// return type is `Result` so the API shape is feature-stable.
pub fn negotiate_cipher(
    client_preferred: &[CipherSuite],
    server_caps: &HwCaps,
) -> Result<CipherSuite, CoreError> {
    #[cfg(feature = "fips")]
    {
        let _ = server_caps;
        if client_preferred.contains(&CipherSuite::Aes256Gcm) {
            Ok(CipherSuite::Aes256Gcm)
        } else {
            Err(CoreError::CipherSuiteUnavailable(
                "no FIPS-approved cipher suite in client offer (only AES-256-GCM is approved under fips)"
                    .into(),
            ))
        }
    }
    #[cfg(not(feature = "fips"))]
    {
        let server_pref = server_caps.recommended_cipher();
        // If server's preference is in client's list, use it
        if client_preferred.contains(&server_pref) {
            return Ok(server_pref);
        }
        // Otherwise use client's first choice
        Ok(client_preferred
            .first()
            .copied()
            .unwrap_or(CipherSuite::ChaCha20Poly1305))
    }
}

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
    ///
    /// Under `--features fips`, requesting [`CipherSuite::ChaCha20Poly1305`]
    /// returns [`CoreError::CipherSuiteUnavailable`] — the wire-format
    /// variant is preserved (enum stable across feature configurations)
    /// but the primitive is not FIPS-approved.
    pub fn with_suite(shared_secret: &[u8; 32], suite: CipherSuite) -> Result<Self, CoreError> {
        Self::guard_suite_under_fips(suite)?;
        Self::build(shared_secret, suite, false)
    }

    /// Create with explicit cipher suite. Peer side.
    ///
    /// Mirrors the `fips` guard of [`Self::with_suite`].
    pub fn with_suite_peer(
        shared_secret: &[u8; 32],
        suite: CipherSuite,
    ) -> Result<Self, CoreError> {
        Self::guard_suite_under_fips(suite)?;
        Self::build(shared_secret, suite, true)
    }

    #[inline]
    fn guard_suite_under_fips(suite: CipherSuite) -> Result<(), CoreError> {
        #[cfg(feature = "fips")]
        {
            if suite == CipherSuite::ChaCha20Poly1305 {
                return Err(CoreError::CipherSuiteUnavailable(
                    "ChaCha20-Poly1305 is not FIPS-approved; only AES-256-GCM is permitted under --features fips"
                        .into(),
                ));
            }
        }
        #[cfg(not(feature = "fips"))]
        {
            let _ = suite;
        }
        Ok(())
    }

    fn build(shared_secret: &[u8; 32], suite: CipherSuite, swap: bool) -> Result<Self, CoreError> {
        let ctx = match suite {
            CipherSuite::Aes256Gcm => "phantom-aes-",
            CipherSuite::ChaCha20Poly1305 => "phantom-cc20-",
        };
        let send_label = format!("{}send-v1", ctx);
        let recv_label = format!("{}recv-v1", ctx);

        // `crypto::kdf::derive_key_32` cfg-dispatches between
        // `blake3::derive_key` (default) and HKDF-SHA256 (fips). The
        // 32-byte output and label-string API are identical.
        // CRYPTO-3: the per-direction AEAD key bytes are wiped on every exit
        // path once copied into ring's opaque `UnboundKey` (the public
        // `nonce_prefix` below is not secret and stays plain).
        let key_a = zeroize::Zeroizing::new(crate::crypto::kdf::derive_key_32(
            &send_label,
            shared_secret,
        ));
        let key_b = zeroize::Zeroizing::new(crate::crypto::kdf::derive_key_32(
            &recv_label,
            shared_secret,
        ));

        let (send_bytes, recv_bytes) = if swap { (key_b, key_a) } else { (key_a, key_b) };

        let algo = suite.algorithm();
        let send_unbound = UnboundKey::new(algo, &*send_bytes)
            .map_err(|_| CoreError::CryptoError("Failed to create send key".into()))?;
        let recv_unbound = UnboundKey::new(algo, &*recv_bytes)
            .map_err(|_| CoreError::CryptoError("Failed to create recv key".into()))?;

        let prefix_bytes = crate::crypto::kdf::derive_key_32("phantom-nonce-pfx-v1", shared_secret);
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
        let tag = self
            .inner
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
    pub fn decrypt_in_place<'a>(
        &self,
        aad: &[u8],
        buf: &'a mut [u8],
    ) -> Result<&'a mut [u8], CryptoError> {
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
    /// Useful for emitting AEAD-invocation metrics and for the mid-session
    /// rekey-trigger logic in `Session::rekey`.
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
    /// ensure uniqueness of `(key, nonce)`. The production caller
    /// (`Session::build_packet_nonce`) derives the 12-byte nonce as
    /// `nonce_prefix(4) ‖ packet_number(8, big-endian)`, so uniqueness
    /// follows from the wire-format invariant that the per-direction `u64`
    /// packet number is strictly monotonic and never reused within an epoch.
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

    /// Decrypt with an explicit caller-supplied nonce. Unlike [`Self::decrypt`],
    /// a tag-check failure does NOT advance the internal counter — only
    /// the bounded telemetry counter increments.
    #[inline]
    pub fn decrypt_with_nonce(
        &self,
        nonce_bytes: [u8; 12],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        // T5.5: check the ceiling against the CURRENT count without consuming it — a forged
        // packet (which fails the open below) must NOT advance the recv invocation counter
        // toward `NonceExhausted`. Only a successful, authenticated open counts.
        if self.inner.recv_counter.load(Ordering::Relaxed) >= AEAD_MAX_INVOCATIONS {
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
        // Authenticated open succeeded — now it counts toward the per-direction ceiling (T5.5).
        self.inner.recv_counter.fetch_add(1, Ordering::Relaxed);
        buf.truncate(len);
        Ok(buf)
    }

    /// Expose the 4-byte nonce prefix for the V2 nonce construction
    /// (`prefix(4) || packet_number(8, big-endian)`; see
    /// `Session::build_packet_nonce`).
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
    /// Callers must rotate keys (`Session::rekey`) or close the session.
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

    /// Round-trip AES-256-GCM through the FIPS backend (`aws-lc-rs`).
    /// Identical to [`round_trip_aes`] but explicit about which backend
    /// is exercised — runs only when the `fips` feature is active.
    #[cfg(feature = "fips")]
    #[test]
    fn round_trip_aes_aws_lc_rs() {
        let secret = [0xCEu8; 32];
        let a = CryptoSession::with_suite(&secret, CipherSuite::Aes256Gcm).unwrap();
        let b = CryptoSession::with_suite_peer(&secret, CipherSuite::Aes256Gcm).unwrap();

        let msg = b"Hello, FIPS-mode AES world!";
        let ct = a.encrypt(&[], msg).unwrap();
        let pt = b.decrypt(&[], &ct).unwrap();
        assert_eq!(&pt, msg);
    }

    // ChaCha20-Poly1305 is rejected under `--features fips`; only run
    // the positive round-trip on non-fips builds.
    #[cfg(not(feature = "fips"))]
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

    /// Under fips, requesting ChaCha20-Poly1305 fails fast with
    /// `CoreError::CipherSuiteUnavailable`.
    #[cfg(feature = "fips")]
    #[test]
    fn chacha_rejected_under_fips() {
        let secret = [0xCDu8; 32];

        match CryptoSession::with_suite(&secret, CipherSuite::ChaCha20Poly1305) {
            Err(CoreError::CipherSuiteUnavailable(_)) => {}
            Err(e) => panic!("expected CipherSuiteUnavailable, got {e:?}"),
            Ok(_) => panic!("expected error, got ok"),
        }

        match CryptoSession::with_suite_peer(&secret, CipherSuite::ChaCha20Poly1305) {
            Err(CoreError::CipherSuiteUnavailable(_)) => {}
            Err(e) => panic!("expected CipherSuiteUnavailable, got {e:?}"),
            Ok(_) => panic!("expected error, got ok"),
        }
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

        let ct_len = session
            .encrypt_in_place_offset(&[0u8; 4], &mut buf, header_len)
            .unwrap();

        // Write header
        buf[..4].copy_from_slice(&(ct_len as u32).to_be_bytes());

        // Decrypt on peer side
        let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        let (_header, payload) = buf.split_at_mut(4);
        let pt = peer
            .decrypt_in_place(&[0u8; 4], &mut payload[..len])
            .unwrap();
        assert_eq!(pt, data);
    }

    #[cfg(not(feature = "fips"))]
    #[test]
    fn negotiation() {
        let server_aes = HwCaps { has_hw_aes: true };
        let server_no_aes = HwCaps { has_hw_aes: false };

        // Client prefers both, server has AES → AES
        let result = negotiate_cipher(
            &[CipherSuite::Aes256Gcm, CipherSuite::ChaCha20Poly1305],
            &server_aes,
        )
        .unwrap();
        assert_eq!(result, CipherSuite::Aes256Gcm);

        // Client prefers both, server no AES → ChaCha20
        let result = negotiate_cipher(
            &[CipherSuite::Aes256Gcm, CipherSuite::ChaCha20Poly1305],
            &server_no_aes,
        )
        .unwrap();
        assert_eq!(result, CipherSuite::ChaCha20Poly1305);

        // Client only ChaCha, server has AES → ChaCha (client's preference)
        let result = negotiate_cipher(&[CipherSuite::ChaCha20Poly1305], &server_aes).unwrap();
        assert_eq!(result, CipherSuite::ChaCha20Poly1305);
    }

    /// Under fips, a ChaCha-only client offer is rejected.
    #[cfg(feature = "fips")]
    #[test]
    fn negotiation_rejects_chacha_only_under_fips() {
        let server_aes = HwCaps { has_hw_aes: true };

        // Mixed: AES present → succeeds with AES regardless of order.
        let suite = negotiate_cipher(
            &[CipherSuite::ChaCha20Poly1305, CipherSuite::Aes256Gcm],
            &server_aes,
        )
        .unwrap();
        assert_eq!(suite, CipherSuite::Aes256Gcm);

        // ChaCha-only offer: rejected.
        let err = negotiate_cipher(&[CipherSuite::ChaCha20Poly1305], &server_aes).unwrap_err();
        assert!(
            matches!(err, CoreError::CipherSuiteUnavailable(_)),
            "expected CipherSuiteUnavailable, got {err:?}"
        );
    }

    // Skip the dual-suite throughput sweep under `fips` — only one
    // suite (`Aes256Gcm`) is permitted in that configuration.
    #[cfg(not(feature = "fips"))]
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
