//! Shared key-derivation helpers (Phase 4.1).
//!
//! Functions here are deterministic and side-agnostic: the client and the
//! server feed identical inputs and obtain identical outputs. They live in
//! `crypto/` rather than `transport/` so both the server handshake path
//! (`transport::handshake`) and the client API path (`api::session`) can
//! call them without a circular module dependency.

use hkdf::Hkdf;
use sha2::Sha256;

/// HKDF `info` label for the 0-RTT early-data AEAD key.
const EARLY_DATA_KEY_INFO: &[u8] = b"phantom-early-data-key-v3";
/// HKDF `info` label for the 0-RTT early-data AEAD nonce.
const EARLY_DATA_NONCE_INFO: &[u8] = b"phantom-early-data-nonce-v3";

/// Derive the AEAD `(key, nonce)` pair that protects 0-RTT early-data
/// carried inside a V3 `ClientHello`.
///
/// Both peers hold the two inputs:
/// - `resumption_secret` — the 32-byte secret a prior handshake produced;
///   the server keeps it in its `SessionCache`, the client gets it from
///   `Session::resumption_hint()`.
/// - `client_nonce` — the fresh 32-byte nonce in *this* connect's
///   `ClientHello`, visible to both sides.
///
/// Construction: HKDF-SHA256 with `client_nonce` as the salt and
/// `resumption_secret` as the IKM, then two `expand` calls with
/// distinct `info` labels — one for the 32-byte key, one for the
/// 12-byte AEAD nonce. HKDF-SHA256 (not BLAKE3) keeps this path
/// FIPS-eligible.
///
/// The output is single-use: the key is bound to one `client_nonce`,
/// which is itself one-shot (the server consumes the resumption ticket
/// on first sight — see `SessionCache::try_resume`). So a fixed,
/// deterministically-derived nonce is safe — the `(key, nonce)` pair is
/// never reused for a second encryption.
pub fn derive_early_data_keying(
    resumption_secret: &[u8; 32],
    client_nonce: &[u8; 32],
) -> ([u8; 32], [u8; 12]) {
    let hk = Hkdf::<Sha256>::new(Some(client_nonce), resumption_secret);
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 12];
    // HKDF-Expand only fails when the requested length exceeds
    // 255 * HashLen (255 * 32 = 8160 bytes for SHA-256). 32 and 12 are
    // both far below that ceiling, so these expansions are infallible.
    // PANIC-SAFETY: see above — the length precondition is a compile-time
    // constant well within the HKDF bound.
    #[allow(clippy::expect_used)]
    hk.expand(EARLY_DATA_KEY_INFO, &mut key)
        .expect("HKDF expand: 32 bytes is within the SHA-256 output bound");
    #[allow(clippy::expect_used)]
    hk.expand(EARLY_DATA_NONCE_INFO, &mut nonce)
        .expect("HKDF expand: 12 bytes is within the SHA-256 output bound");
    (key, nonce)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_same_inputs_same_outputs() {
        // The whole point: client and server, given identical inputs,
        // derive byte-identical keying material.
        let secret = [0x11u8; 32];
        let nonce = [0x22u8; 32];
        let a = derive_early_data_keying(&secret, &nonce);
        let b = derive_early_data_keying(&secret, &nonce);
        assert_eq!(a.0, b.0, "key must be deterministic");
        assert_eq!(a.1, b.1, "nonce must be deterministic");
    }

    #[test]
    fn distinct_client_nonce_yields_distinct_keying() {
        let secret = [0x11u8; 32];
        let (k1, n1) = derive_early_data_keying(&secret, &[0x01u8; 32]);
        let (k2, n2) = derive_early_data_keying(&secret, &[0x02u8; 32]);
        assert_ne!(k1, k2, "different client_nonce must change the key");
        assert_ne!(n1, n2, "different client_nonce must change the nonce");
    }

    #[test]
    fn distinct_resumption_secret_yields_distinct_keying() {
        let nonce = [0x22u8; 32];
        let (k1, _) = derive_early_data_keying(&[0xAAu8; 32], &nonce);
        let (k2, _) = derive_early_data_keying(&[0xBBu8; 32], &nonce);
        assert_ne!(k1, k2, "different resumption_secret must change the key");
    }

    #[test]
    fn key_and_nonce_are_independent() {
        // The two HKDF expansions use distinct info labels, so the key
        // bytes and nonce bytes are not a prefix/suffix of one another.
        let (key, nonce) = derive_early_data_keying(&[0x33u8; 32], &[0x44u8; 32]);
        assert_ne!(
            &key[..12],
            &nonce[..],
            "key prefix must not equal the nonce"
        );
    }
}
