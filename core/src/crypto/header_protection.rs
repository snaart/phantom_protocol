//! Header protection (QUIC RFC 9001 §5.4) — the per-packet mask that hides the
//! variable header fields (`packet_number ‖ flags ‖ stream_id ‖ epoch ‖
//! path_id`, the 14 bytes at wire offset `[1..15]` since ε / WIRE v5; `[33..47]`
//! in v4) from a passive on-path observer.
//!
//! The mask is `cipher(hp_key, sample)` where `sample` is the first 16 bytes of
//! the packet's AEAD ciphertext (the tag is always present, so a sample exists
//! even for an empty payload). The sample is drawn from the *payload* ciphertext,
//! which is never masked — so there is **no circular dependency** (cleaner than
//! QUIC, whose packet number sits inside the sampled span). The AEAD AAD remains
//! the *cleartext* header image, so HP is an orthogonal outer wrapping: a wire
//! mutation of the masked region unmasks to a wrong header → wrong AAD → AEAD
//! fails. It adds **no new decryption oracle**.
//!
//! ## Why the HP key is session-stable (NOT epoch-rotated)
//!
//! QUIC RFC 9001 §6.1 keeps the header-protection key **constant across key
//! updates**, and so do we. `epoch` lives *inside* the masked region, so the
//! receiver must remove header protection **before** it knows the packet's
//! epoch. If the hp key rotated per epoch, a receiver one epoch behind the
//! sender (the exact case `Session::decrypt_packet_accepting_rekey` exists to
//! handle) could not pick the right hp key → garbage epoch → the catch-up path
//! can't read `header.epoch` → rekey-catchup deadlock. Deriving the hp keys once
//! from the initial session secret and holding them stable avoids that. Forward
//! secrecy of *confidentiality* is unaffected: the hp key masks only header
//! metadata, never payload — the AEAD keys still ratchet with full FS.
//!
//! ## FIPS
//!
//! Header protection is anti-DPI obfuscation, **not** confidentiality (the same
//! posture as the FakeTLS outer layer — see Security Invariant #3). Under
//! `--features fips` the AES mask still routes through the FIPS substrate
//! (`aws_lc_rs::cipher` AES-256-ECB) so the masking primitive stays inside the
//! validated module; the ChaCha20 mask is unreachable there because the cipher
//! suite is pinned to AES-256-GCM at session construction.

use crate::crypto::adaptive_crypto::CipherSuite;
use crate::crypto::kdf::derive_key_32;
use crate::errors::CoreError;
use zeroize::Zeroize;

/// Bytes of the packet header protected by HP — the contiguous region at wire
/// offset `[1..15]` (ε / WIRE v5; was `[33..47]` in v4): `packet_number(8) ‖
/// flags(2) ‖ stream_id(2) ‖ epoch(1) ‖ path_id(1)`. Only the cleartext
/// `version(1)` byte (offset `[0..1]`) is left in the clear; the inner
/// `session_id` is off-wire and routing is by the outer (rotating) ConnId.
pub const HP_MASK_LEN: usize = 14;

/// Bytes of AEAD ciphertext sampled to seed the mask cipher — one AES block
/// (RFC 9001 §5.4.2). Always available: every data-plane packet carries at least
/// the 16-byte AEAD tag.
pub const HP_SAMPLE_LEN: usize = 16;

/// KDF labels for the per-direction header-protection keys. Domain-separated
/// from the AEAD `phantom-{aes,cc20}-{send,recv}-v1` keys and the
/// `phantom-nonce-pfx-v1` prefix, so the hp key reveals nothing about the AEAD
/// key and vice-versa.
const HP_SEND_LABEL: &str = "phantom-hp-send-v1";
const HP_RECV_LABEL: &str = "phantom-hp-recv-v1";

/// Per-direction, **session-stable** header-protection keys plus the negotiated
/// cipher suite (which selects AES-256-ECB vs ChaCha20 for the mask). Derived
/// once from the initial session secret and held for the session's lifetime; see
/// the module docs for why this does not rotate with the AEAD epoch.
pub struct HeaderProtector {
    suite: CipherSuite,
    hp_send: [u8; 32],
    hp_recv: [u8; 32],
}

impl HeaderProtector {
    /// Derive the per-direction HP keys from the initial session secret. `swap`
    /// (= the session's `is_server` flag) swaps send/recv so one peer's `send`
    /// key equals the other peer's `recv` key — mirroring the AEAD key layout in
    /// `CryptoSession::build`.
    pub fn derive(suite: CipherSuite, initial_secret: &[u8; 32], swap: bool) -> Self {
        let hp_a = derive_key_32(HP_SEND_LABEL, initial_secret);
        let hp_b = derive_key_32(HP_RECV_LABEL, initial_secret);
        let (hp_send, hp_recv) = if swap { (hp_b, hp_a) } else { (hp_a, hp_b) };
        Self {
            suite,
            hp_send,
            hp_recv,
        }
    }

    /// The negotiated cipher suite (drives the mask primitive). Exposed for
    /// diagnostics / tests.
    #[inline]
    pub fn cipher_suite(&self) -> CipherSuite {
        self.suite
    }

    /// Compute the mask for an **outbound** packet from its ciphertext `sample`.
    #[inline]
    pub fn mask_send(
        &self,
        sample: &[u8; HP_SAMPLE_LEN],
    ) -> Result<[u8; HP_SAMPLE_LEN], CoreError> {
        compute_mask(self.suite, &self.hp_send, sample)
    }

    /// Compute the mask for an **inbound** packet from its ciphertext `sample`.
    #[inline]
    pub fn mask_recv(
        &self,
        sample: &[u8; HP_SAMPLE_LEN],
    ) -> Result<[u8; HP_SAMPLE_LEN], CoreError> {
        compute_mask(self.suite, &self.hp_recv, sample)
    }
}

impl Drop for HeaderProtector {
    fn drop(&mut self) {
        self.hp_send.zeroize();
        self.hp_recv.zeroize();
    }
}

/// RFC 9001 §5.4.3 (AES) / §5.4.4 (ChaCha20) mask derivation.
#[inline]
fn compute_mask(
    suite: CipherSuite,
    key: &[u8; 32],
    sample: &[u8; HP_SAMPLE_LEN],
) -> Result<[u8; HP_SAMPLE_LEN], CoreError> {
    match suite {
        CipherSuite::Aes256Gcm => aes256_ecb_block(key, sample),
        CipherSuite::ChaCha20Poly1305 => chacha20_mask(key, sample),
    }
}

/// AES-256-ECB of a single 16-byte block (RFC 9001 §5.4.3) — the raw block
/// cipher applied to the sample. Default build: the pure-Rust RustCrypto `aes`
/// crate.
#[cfg(not(feature = "fips"))]
fn aes256_ecb_block(key: &[u8; 32], sample: &[u8; 16]) -> Result<[u8; 16], CoreError> {
    use aes::cipher::generic_array::GenericArray;
    use aes::cipher::{BlockEncrypt, KeyInit};

    let cipher = aes::Aes256::new(GenericArray::from_slice(key));
    let mut block = *GenericArray::<u8, aes::cipher::consts::U16>::from_slice(sample);
    cipher.encrypt_block(&mut block);
    let mut out = [0u8; 16];
    out.copy_from_slice(block.as_slice());
    Ok(out)
}

/// AES-256-ECB of a single 16-byte block (RFC 9001 §5.4.3). FIPS build: routed
/// through the FIPS-validated `aws_lc_rs::cipher` ECB primitive so the masking
/// stays inside the validated module. The `map_err`s are unreachable for the
/// fixed 32-byte key / 16-byte block, but surfacing a typed error keeps the path
/// panic-free (no `expect`).
#[cfg(feature = "fips")]
fn aes256_ecb_block(key: &[u8; 32], sample: &[u8; 16]) -> Result<[u8; 16], CoreError> {
    use aws_lc_rs::cipher::{EncryptingKey, UnboundCipherKey, AES_256};

    let unbound = UnboundCipherKey::new(&AES_256, key)
        .map_err(|_| CoreError::CryptoError("HP: AES-256 key init failed".into()))?;
    let enc = EncryptingKey::ecb(unbound)
        .map_err(|_| CoreError::CryptoError("HP: AES-256-ECB init failed".into()))?;
    let mut block = *sample;
    enc.encrypt(&mut block)
        .map_err(|_| CoreError::CryptoError("HP: AES-256-ECB encrypt failed".into()))?;
    Ok(block)
}

/// ChaCha20 header-protection mask (RFC 9001 §5.4.4): `counter = sample[0..4]`
/// as a little-endian `u32`, `nonce = sample[4..16]`; the mask is the first 16
/// bytes of the ChaCha20 keystream at that `(counter, nonce)`. Used only on the
/// default build's ChaCha20-Poly1305 suite — unreachable under `--features fips`
/// (the suite is pinned to AES there), but the code is suite-, not feature-,
/// gated, so it always compiles.
fn chacha20_mask(key: &[u8; 32], sample: &[u8; 16]) -> Result<[u8; 16], CoreError> {
    use chacha20::cipher::generic_array::GenericArray;
    use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};

    let counter = u32::from_le_bytes([sample[0], sample[1], sample[2], sample[3]]);
    let key_ga = GenericArray::from_slice(key);
    let nonce_ga = GenericArray::from_slice(&sample[4..16]);
    let mut cipher = chacha20::ChaCha20::new(key_ga, nonce_ga);
    // The QUIC "counter" is the 32-bit block counter; ChaCha20 blocks are 64
    // bytes, so seek to that block before pulling the keystream.
    cipher.seek(u64::from(counter) * 64);
    let mut out = [0u8; 16];
    cipher.apply_keystream(&mut out);
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn hex16(s: &str) -> [u8; 16] {
        let v = hex::decode(s).unwrap();
        let mut a = [0u8; 16];
        a.copy_from_slice(&v);
        a
    }

    fn hex32(s: &str) -> [u8; 32] {
        let v = hex::decode(s).unwrap();
        let mut a = [0u8; 32];
        a.copy_from_slice(&v);
        a
    }

    /// AES-256-ECB single-block known-answer test from NIST SP 800-38A F.1.5
    /// (ECB-AES256.Encrypt, block #1). Pins the AES mask primitive against an
    /// independent standard vector on **both** the default (`aes` crate) and the
    /// FIPS (`aws-lc-rs`) backend — same algorithm, identical output.
    #[test]
    fn aes256_ecb_matches_nist_sp800_38a() {
        let key = hex32("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
        let pt = hex16("6bc1bee22e409f96e93d7e117393172a");
        let ct = hex16("f3eed1bdb5d2a03c064b5a7e3db181f8");
        assert_eq!(aes256_ecb_block(&key, &pt).unwrap(), ct);
    }

    /// ChaCha20 header-protection KAT from QUIC RFC 9001 §A.5. The mask's first
    /// five bytes (the span QUIC protects) must equal the RFC's published value.
    /// ChaCha20 HP is the default build's software-AES fallback suite and is
    /// never selected under `--features fips`, so this runs non-fips only.
    #[cfg(not(feature = "fips"))]
    #[test]
    fn chacha20_mask_matches_rfc9001_a5() {
        let key = hex32("25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4");
        let sample = hex16("5e5cd55c41f69080575d7999c25a5bfb");
        let mask = chacha20_mask(&key, &sample).unwrap();
        assert_eq!(&mask[..5], &[0xae, 0xfe, 0xfe, 0x7d, 0x03]);
    }

    /// The send/recv swap: one peer's `mask_send` must equal the other peer's
    /// `mask_recv` for the same sample, so a header masked by the sender unmasks
    /// at the receiver. Mirrors the AEAD send/recv key swap.
    #[test]
    fn derive_swaps_send_recv_between_peers() {
        let secret = [0x33u8; 32];
        let client = HeaderProtector::derive(CipherSuite::Aes256Gcm, &secret, false);
        let server = HeaderProtector::derive(CipherSuite::Aes256Gcm, &secret, true);
        let sample = hex16("000102030405060708090a0b0c0d0e0f");

        assert_eq!(
            client.mask_send(&sample).unwrap(),
            server.mask_recv(&sample).unwrap(),
            "client send-mask must equal server recv-mask"
        );
        assert_eq!(
            server.mask_send(&sample).unwrap(),
            client.mask_recv(&sample).unwrap(),
            "server send-mask must equal client recv-mask"
        );
    }

    /// The two directions use independent keys, so the send and recv masks for a
    /// given sample differ (a sanity check that send ≠ recv within one peer).
    #[test]
    fn send_and_recv_masks_differ() {
        let secret = [0x77u8; 32];
        let hp = HeaderProtector::derive(CipherSuite::Aes256Gcm, &secret, false);
        let sample = hex16("0f0e0d0c0b0a09080706050403020100");
        assert_ne!(
            hp.mask_send(&sample).unwrap(),
            hp.mask_recv(&sample).unwrap()
        );
    }

    /// The ChaCha20 suite produces a different (but still swap-consistent) mask
    /// than AES — exercises the non-AES branch of `compute_mask` end-to-end.
    #[cfg(not(feature = "fips"))]
    #[test]
    fn chacha_suite_swap_is_consistent() {
        let secret = [0x9au8; 32];
        let client = HeaderProtector::derive(CipherSuite::ChaCha20Poly1305, &secret, false);
        let server = HeaderProtector::derive(CipherSuite::ChaCha20Poly1305, &secret, true);
        let sample = hex16("aabbccddeeff00112233445566778899");
        assert_eq!(
            client.mask_send(&sample).unwrap(),
            server.mask_recv(&sample).unwrap()
        );
    }
}
