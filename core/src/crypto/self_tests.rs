//! Power-on + conditional self-tests for Phantom Core's cryptographic
//! primitives (FIPS 140-3 §7.7).
//!
//! FIPS 140-3 requires that **every approved algorithm pass a known-answer
//! or pairwise-consistency test before it can be used for the first time
//! after module power-up**. This module exposes [`run_post`] — call it
//! once at process start (typically from the embedder's bootstrap before
//! the first [`crate::api::PhantomSession::connect_with_transport`] or
//! [`crate::api::PhantomListener::bind`]) to satisfy that requirement.
//! Failure means a primitive returned a wrong answer or refused to
//! initialize at all; in that case **abort** rather than serve traffic
//! with a broken cryptographic module.
//!
//! The library does *not* auto-invoke `run_post` — embedders pulling in
//! `phantom_core` for non-FIPS deployments shouldn't pay the (~ms) startup
//! cost. The CAVP-style canonical vectors live in `core/tests/cavp.rs`
//! (Phase 5.4); this module re-tests the same primitives via pairwise
//! consistency + a fixed HKDF KAT, sufficient for a §7.7 POST without
//! pulling the full CAVP corpus into the production binary.
//!
//! Phase 5.5 (per `docs/PROGRESS.md` / `docs/compliance/fips-readiness.md`).

use crate::crypto::adaptive_crypto::{CipherSuite, CryptoSession};
use crate::crypto::hybrid_kem::HybridSecretKey;
use crate::crypto::hybrid_sign::HybridSigningKey;
use hkdf::Hkdf;
use sha2::Sha256;
use std::sync::OnceLock;

/// Process-global cache for [`run_post`]'s result. The fips
/// bootstrap (`PhantomListener::bind*` / `PhantomSession::connect*`)
/// calls [`ensure_post_passed`] which lazily runs the POST exactly
/// once per process and caches the verdict. Subsequent calls return
/// the cached `Result` without re-running the test battery.
///
/// Production only — `cfg(test)` builds re-run on every call so the
/// `FORCE_POST_FAIL` fault-injection switch is observable. The
/// `dead_code` suppression covers the test build.
#[cfg_attr(test, allow(dead_code))]
static POST_RESULT: OnceLock<Result<(), SelfTestError>> = OnceLock::new();

/// Test-only fault-injection switch. When `true`, [`ensure_post_passed`]
/// pretends the AEAD self-test failed (regardless of what the actual
/// POST would have returned) — used by integration tests covering the
/// `bind`/`connect` reject path. Production builds compile without
/// this field at all.
#[cfg(test)]
static FORCE_POST_FAIL: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Process-global single-shot wrapper around [`run_post`]. The first
/// call runs the POST and caches the verdict; subsequent calls return
/// the cached verdict. Designed for the fips bootstrap path
/// (`PhantomListener::bind*`, `PhantomSession::connect*`) which calls
/// this before doing any cryptographic work — a failure short-circuits
/// to [`crate::CoreError::FipsSelfTestFailure`] instead of standing up
/// a listener / session over broken primitives.
///
/// Production cost: amortised to zero after the first call.
///
/// Under `cfg(test)` the POST is **re-run on every call** so a test
/// can flip [`FORCE_POST_FAIL`] and observe the new verdict without
/// having to reset a process-global cache (`OnceLock::take` is
/// MSRV 1.81 — too new for this crate). The cache is exercised by
/// production builds, not by tests.
pub fn ensure_post_passed() -> Result<(), SelfTestError> {
    #[cfg(test)]
    {
        if FORCE_POST_FAIL.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(SelfTestError::Aead {
                algorithm: "AES-256-GCM",
                stage: AeadStage::Decrypt,
            });
        }
        return run_post();
    }
    #[cfg(not(test))]
    {
        *POST_RESULT.get_or_init(run_post)
    }
}

/// Test-only — flip the [`FORCE_POST_FAIL`] switch. Tests that flip
/// it MUST `set_force_post_fail(false)` again in their teardown to
/// avoid poisoning sibling tests in the same binary.
#[cfg(test)]
pub fn set_force_post_fail(enable: bool) {
    FORCE_POST_FAIL.store(enable, std::sync::atomic::Ordering::SeqCst);
}

/// Test-only — shared serial guard for every test that touches
/// [`FORCE_POST_FAIL`]. Tests in sibling modules (e.g. the bind
/// reject-path test in `api::listener::tests`) acquire this mutex
/// for the duration of their fault injection so parallel runners
/// do not interleave flips.
#[cfg(test)]
pub fn tests_serial_guard() -> &'static std::sync::Mutex<()> {
    static G: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    G.get_or_init(|| std::sync::Mutex::new(()))
}

/// Stage at which a per-algorithm self-test failed. Lets the caller log
/// "AES-GCM encrypt failed" vs "AES-GCM decrypt mismatch" instead of an
/// opaque "self-test failed".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeadStage {
    /// `CryptoSession::with_suite` / `from_shared_secret` rejected the
    /// fixed shared-secret input. Indicates a broken key schedule.
    Init,
    /// `encrypt` returned an error on a well-formed plaintext.
    Encrypt,
    /// `decrypt` returned an error on a freshly-encrypted ciphertext.
    Decrypt,
    /// Decrypt succeeded but produced the wrong plaintext.
    Mismatch,
}

/// Stage at which the hybrid KEM round-trip failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KemStage {
    /// `HybridSecretKey::generate` produced an unusable keypair (or panicked
    /// — caught at the call site).
    Generate,
    /// `HybridKeyPackage::encapsulate` returned an error.
    Encapsulate,
    /// `HybridSecretKey::decapsulate` returned an error.
    Decapsulate,
    /// Decapsulated shared-secret did not match the encapsulator's.
    Mismatch,
}

/// Stage at which the hybrid signature round-trip failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignStage {
    /// `HybridSigningKey::generate` produced an unusable keypair.
    Generate,
    /// `verify` rejected a signature this build just produced.
    Verify,
}

/// Top-level error surface. Each variant carries enough context for an
/// operator to know which primitive misbehaved without pulling in
/// long-form error types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelfTestError {
    /// AEAD round-trip failed. The algorithm name is `&'static str`
    /// (`"AES-256-GCM"` or `"ChaCha20-Poly1305"`).
    Aead {
        algorithm: &'static str,
        stage: AeadStage,
    },
    /// HKDF-SHA256 produced output that did not match the bundled KAT.
    Hkdf,
    /// Hybrid KEM (X25519 + ML-KEM-768) round-trip failed.
    HybridKem { stage: KemStage },
    /// Hybrid signature (Ed25519 + ML-DSA-65) round-trip failed.
    HybridSign { stage: SignStage },
    /// Verification accepted a deliberately-tampered signature. Either
    /// AEAD authenticity is broken or the verifier's reject path is dead.
    NegativeVerify,
}

/// Run every per-algorithm self-test once and return `Ok(())` only if all
/// pass. Aborts at the first failure (do not continue with a broken
/// cryptographic module). Designed to be called once at process start.
///
/// Cost: a single hybrid KEM keygen + encap/decap + a single hybrid
/// signature gen + sign + verify, plus one or two AEAD round-trips
/// and one HKDF expansion. Around 1-5 ms on a modern host;
/// FIPS-mandated regardless.
///
/// Under `--features fips` only the FIPS-approved AEAD (AES-256-GCM)
/// is exercised; `CryptoSession::with_suite` rejects ChaCha20-Poly1305
/// in that configuration, and the POST refuses to run a primitive the
/// production build cannot use.
pub fn run_post() -> Result<(), SelfTestError> {
    test_aead(CipherSuite::Aes256Gcm, "AES-256-GCM")?;
    #[cfg(not(feature = "fips"))]
    test_aead(CipherSuite::ChaCha20Poly1305, "ChaCha20-Poly1305")?;
    test_hkdf_sha256()?;
    test_hybrid_kem()?;
    test_hybrid_sign()?;
    test_negative_verify()?;
    Ok(())
}

/// Round-trip a fixed plaintext through the given suite and assert
/// authenticated equality. `CryptoSession` is direction-asymmetric in
/// production — the local side's `send_key` is the peer side's
/// `recv_key`, mirrored — so the test wires up a local + peer pair from
/// the same shared secret and round-trips local→peer, matching the
/// production handshake.
fn test_aead(suite: CipherSuite, name: &'static str) -> Result<(), SelfTestError> {
    let shared_secret = [0x42u8; 32];
    let aad = b"phantom-self-test-aad";
    let plaintext = b"phantom-core self-test payload";

    let local =
        CryptoSession::with_suite(&shared_secret, suite).map_err(|_| SelfTestError::Aead {
            algorithm: name,
            stage: AeadStage::Init,
        })?;
    let peer =
        CryptoSession::with_suite_peer(&shared_secret, suite).map_err(|_| SelfTestError::Aead {
            algorithm: name,
            stage: AeadStage::Init,
        })?;

    let ciphertext = local
        .encrypt(aad, plaintext)
        .map_err(|_| SelfTestError::Aead {
            algorithm: name,
            stage: AeadStage::Encrypt,
        })?;

    let recovered = peer
        .decrypt(aad, &ciphertext)
        .map_err(|_| SelfTestError::Aead {
            algorithm: name,
            stage: AeadStage::Decrypt,
        })?;

    if recovered != plaintext {
        return Err(SelfTestError::Aead {
            algorithm: name,
            stage: AeadStage::Mismatch,
        });
    }
    Ok(())
}

/// HKDF-SHA256 KAT. The IKM / salt / info triple below was derived from
/// the Phantom rekey path's exact construction (label
/// `phantom-rekey-v1`) over a fixed 32-byte traffic secret of `0x11..`.
/// Output is a 32-byte expansion. A mismatch here is a regression in
/// the underlying `hkdf` / `sha2` crates or in their wiring at the
/// crate boundary.
fn test_hkdf_sha256() -> Result<(), SelfTestError> {
    let ikm = [0x11u8; 32];
    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut output = [0u8; 32];
    hk.expand(b"phantom-rekey-v1", &mut output)
        .map_err(|_| SelfTestError::Hkdf)?;

    // KAT computed from `Hkdf::<Sha256>::new(None, &[0x11; 32])` then
    // `expand(b"phantom-rekey-v1", &mut [0u8; 32])` against `hkdf = "0.12"` +
    // `sha2 = "0.10"`. Regenerate if either dependency bumps to a major
    // version with a behavior change — a mismatch on a clean build
    // means the upstream crate's output shape moved under us.
    const KAT: [u8; 32] = [
        0x41, 0x90, 0x72, 0xe4, 0xca, 0x1b, 0xa9, 0xca, 0xdc, 0x1b, 0x02, 0xd3, 0x75, 0xb0, 0xf8,
        0x84, 0x70, 0xa7, 0x0f, 0xe9, 0x57, 0x13, 0x1d, 0x7b, 0x5b, 0x35, 0xe5, 0x74, 0x14, 0x34,
        0xe4, 0x10,
    ];
    if output != KAT {
        return Err(SelfTestError::Hkdf);
    }
    Ok(())
}

/// Hybrid KEM (X25519 + ML-KEM-768) pairwise-consistency test. Generates
/// a fresh keypair, encapsulates against the published half, decapsulates
/// with the secret half, and asserts both sides derived the same
/// 32-byte shared secret. This is the FIPS pairwise-consistency check
/// for ML-KEM-768 plus the classical X25519 half of the hybrid.
fn test_hybrid_kem() -> Result<(), SelfTestError> {
    let (sk, pk) = HybridSecretKey::generate();
    let (ss_encap, ct) = pk.encapsulate().map_err(|_| SelfTestError::HybridKem {
        stage: KemStage::Encapsulate,
    })?;
    let ss_decap = sk.decapsulate(&ct).map_err(|_| SelfTestError::HybridKem {
        stage: KemStage::Decapsulate,
    })?;
    if ss_encap != ss_decap {
        return Err(SelfTestError::HybridKem {
            stage: KemStage::Mismatch,
        });
    }
    Ok(())
}

/// Hybrid signature (Ed25519 + ML-DSA-65) pairwise-consistency test.
/// Generates a fresh keypair, signs a fixed message, verifies — both
/// halves must verify for the hybrid to succeed.
fn test_hybrid_sign() -> Result<(), SelfTestError> {
    let (sk, pk) = HybridSigningKey::generate();
    let message = b"phantom-core self-test signature input";
    let sig = sk.sign(message);
    pk.verify(message, &sig)
        .map_err(|_| SelfTestError::HybridSign {
            stage: SignStage::Verify,
        })?;
    Ok(())
}

/// Confirms the verifier actually rejects tampered signatures. Without
/// this, a fault-injected verify-always-accepts implementation would
/// silently pass [`test_hybrid_sign`] (verification of a valid sig also
/// passes there). Flip one byte in the signature payload and assert
/// `verify` returns `Err`.
fn test_negative_verify() -> Result<(), SelfTestError> {
    let (sk, pk) = HybridSigningKey::generate();
    let message = b"phantom-core self-test negative input";
    let sig = sk.sign(message);
    let mut sig_bytes = sig.to_bytes();
    // Pick a byte deep in the signature payload (not a length prefix at
    // the start) and flip its low bit. Any non-trivial tamper that
    // changes signature bytes should fail verification.
    let idx = sig_bytes.len() / 2;
    sig_bytes[idx] ^= 0x01;

    let tampered = match crate::crypto::hybrid_sign::HybridSignature::from_bytes(&sig_bytes) {
        Ok(s) => s,
        // A decode error is also acceptable rejection — the tampered
        // bytes don't round-trip as a valid signature wire format.
        Err(_) => return Ok(()),
    };
    if pk.verify(message, &tampered).is_ok() {
        return Err(SelfTestError::NegativeVerify);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn post_succeeds_on_clean_build() {
        run_post().expect("self-tests must pass on a clean build");
    }

    #[test]
    fn aead_test_passes_for_both_suites() {
        test_aead(CipherSuite::Aes256Gcm, "AES-256-GCM").unwrap();
        // ChaCha20-Poly1305 is rejected under `--features fips`;
        // only exercise it on non-fips builds.
        #[cfg(not(feature = "fips"))]
        test_aead(CipherSuite::ChaCha20Poly1305, "ChaCha20-Poly1305").unwrap();
    }

    #[test]
    fn hkdf_kat_locks_the_construction() {
        test_hkdf_sha256().unwrap();
    }

    #[test]
    fn hybrid_kem_round_trip_consistent() {
        test_hybrid_kem().unwrap();
    }

    #[test]
    fn hybrid_sign_round_trip_consistent() {
        test_hybrid_sign().unwrap();
    }

    #[test]
    fn negative_verify_rejects_tampered_signature() {
        test_negative_verify().unwrap();
    }

    #[test]
    fn full_post_under_a_loop_is_stable() {
        // Self-tests must be repeatable — no internal mutable state that
        // poisons a second invocation. Useful as a smoke check that
        // future refactors don't introduce a one-shot init.
        for _ in 0..3 {
            run_post().unwrap();
        }
    }

    /// `ensure_post_passed()` runs the POST and returns its
    /// result. On a clean build, `Ok(())`.
    #[test]
    fn ensure_post_passed_succeeds_on_clean_build() {
        let _guard = tests_serial_guard().lock().unwrap();
        set_force_post_fail(false);
        assert!(ensure_post_passed().is_ok());
    }

    /// `FORCE_POST_FAIL` flips `ensure_post_passed` to return
    /// the fault-injected error variant. Used by the
    /// `listener::bind*` / `session::connect*` reject-path tests.
    #[test]
    fn force_post_fail_returns_error_via_ensure_post_passed() {
        let _guard = tests_serial_guard().lock().unwrap();
        set_force_post_fail(true);
        let result = ensure_post_passed();
        set_force_post_fail(false);
        match result {
            Err(SelfTestError::Aead {
                algorithm: "AES-256-GCM",
                stage: AeadStage::Decrypt,
            }) => {}
            other => panic!("expected fault-injected AEAD Decrypt failure, got {other:?}"),
        }
        // Cleared; next call should succeed again.
        assert!(ensure_post_passed().is_ok());
    }
}
