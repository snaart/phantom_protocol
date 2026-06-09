//! `RngProvider` — the indirection through which Phantom Protocol obtains
//! cryptographic randomness. Default is [`OsRng`], which delegates to
//! [`getrandom::getrandom`] and therefore picks up the platform's CSPRNG on
//! every supported target (Linux `getrandom(2)`, macOS / iOS
//! `CCRandomGenerateBytes`, Windows `BCryptGenRandom`, wasm32 via the `js`
//! feature → `crypto.getRandomValues`, etc.).
//!
//! Embedders can swap in their own provider by implementing this trait and
//! threading it into the relevant `_with_provider` entry points (the
//! [`HybridSigningKey::generate_with_provider`] demonstration is wired up
//! in this commit; the rest of the crate continues to call the
//! `OsRng`-using default until a follow-up sweep lifts the abstraction
//! through every call site).
//!
//! [`HybridSigningKey::generate_with_provider`]: crate::crypto::hybrid_sign::HybridSigningKey::generate_with_provider
//!
//! ## Phase 3.8 scope (this commit)
//!
//! Trait + default [`OsRng`] impl + tests. **No** new crate dependencies
//! (this module uses only what already ships in `Cargo.toml`).
//!
//! What is intentionally NOT in scope here:
//!
//! - Refactoring every existing `thread_rng()` / `OsRng` call site to
//!   thread an `Arc<dyn RngProvider>` through the codebase. That sweep is
//!   a follow-up.
//! - A real NIST SP 800-90A DRBG (e.g., HMAC-DRBG). The trait is shaped to
//!   accept one, but the impl itself is Phase 5 (FIPS) work.
//! - A hardware-RNG impl. Those are inherently target-specific and belong
//!   in a downstream HAL adapter crate, not in `phantom_protocol` itself.
//!
//! ## Slotting in alternative providers
//!
//! ### Hardware TRNG on embedded
//!
//! On microcontrollers exposing a true-RNG peripheral (e.g., the STM32
//! `RNG`, the nRF52 `RNG`, RP2040 ROSC, …), the HAL crate typically
//! exposes a blocking reader (`embedded_hal::blocking::rng::Read` or the
//! `rand_core::RngCore` impl that newer HALs wrap it in). A downstream
//! adapter looks roughly like:
//!
//! ```ignore
//! use phantom_protocol::crypto::rng::RngProvider;
//! use core::sync::atomic::AtomicBool;
//! use spin::Mutex;          // or critical_section::Mutex on no_std-no-alloc
//!
//! pub struct HwRng<R> {
//!     inner: Mutex<R>,
//! }
//!
//! impl<R> HwRng<R> {
//!     pub fn new(peripheral: R) -> Self {
//!         Self { inner: Mutex::new(peripheral) }
//!     }
//! }
//!
//! impl<R> RngProvider for HwRng<R>
//! where
//!     R: rand_core::RngCore + Send + 'static,
//! {
//!     fn fill_bytes(&self, dest: &mut [u8]) {
//!         self.inner.lock().fill_bytes(dest);
//!     }
//! }
//! ```
//!
//! The `Mutex` is needed because `fill_bytes` takes `&self`. A real HAL
//! adapter should also surface health-test failures from the peripheral
//! (most TRNGs have a stuck-bit / continuous-test register) rather than
//! returning silently-biased bytes.
//!
//! ### NIST-approved DRBG in FIPS mode
//!
//! Phase 5 will add an internal `HmacDrbg` (SP 800-90A § 10.1.2) keyed
//! from `getrandom` at boot and re-seeded on a request / time interval
//! per SP 800-90A § 9. The skeleton:
//!
//! ```ignore
//! use phantom_protocol::crypto::rng::RngProvider;
//! use std::sync::Mutex;
//!
//! pub struct HmacDrbg { /* V, Key, reseed_counter, ... */ }
//! impl HmacDrbg {
//!     pub fn from_entropy() -> Self { /* seed from getrandom */ todo!() }
//!     fn generate(&mut self, out: &mut [u8]) { /* SP 800-90A 10.1.2.5 */ todo!() }
//! }
//!
//! pub struct FipsDrbg(Mutex<HmacDrbg>);
//! impl RngProvider for FipsDrbg {
//!     fn fill_bytes(&self, dest: &mut [u8]) {
//!         self.0.lock().expect("DRBG poisoned").generate(dest);
//!     }
//! }
//! ```
//!
//! See `docs/compliance/fips-readiness.md` for the larger picture.
//!
//! ### Deterministic test fixture
//!
//! See `tests::CounterRng` below for a tiny in-tree example.

#[cfg(not(feature = "fips"))]
use getrandom::getrandom;

#[cfg(feature = "fips")]
use aws_lc_rs::rand::{SecureRandom, SystemRandom};

/// Source of cryptographically secure random bytes.
///
/// The trait takes `&self` (not `&mut self`) on every method so a single
/// `Arc<dyn RngProvider>` can be shared across tasks / threads without
/// callers having to wrap it in a `Mutex`. Implementations that internally
/// need mutation (a software DRBG, a `ChaChaRng`-backed test fixture, …)
/// must supply their own interior mutability — see the `CounterRng`
/// example in the test module.
///
/// `Send + Sync + 'static` lets the provider be held in `Arc<dyn …>` for
/// the lifetime of a long-running listener.
///
/// # Failure model
///
/// Implementations are expected to be **infallible** at the call boundary
/// — randomness is required for crypto correctness, and there is no
/// useful fallback at the Phantom Protocol layer. If the underlying source
/// can fail (a hardware-RNG health-test trip, an OS RNG that returns
/// `EIO`, …) the impl must surface that as a panic so the higher layer
/// fails loudly rather than silently producing biased keys. The default
/// [`OsRng`] follows this convention via `getrandom`'s
/// `Result::expect`.
pub trait RngProvider: Send + Sync + 'static {
    /// Fill `dest` with cryptographically secure random bytes.
    fn fill_bytes(&self, dest: &mut [u8]);

    /// Convenience: return a single fresh `u64` of randomness.
    ///
    /// Default impl reads 8 bytes from [`fill_bytes`] and decodes them
    /// little-endian. Implementations with a faster word-aligned path
    /// (e.g., an HMAC-DRBG outputting 64-bit blocks) may override.
    ///
    /// [`fill_bytes`]: RngProvider::fill_bytes
    fn next_u64(&self) -> u64 {
        let mut buf = [0u8; 8];
        self.fill_bytes(&mut buf);
        u64::from_le_bytes(buf)
    }
}

/// Default [`RngProvider`] — delegates to `getrandom` and therefore to the
/// OS's CSPRNG on every supported target.
///
/// Zero-sized; cheap to construct. Hold a single instance per session (or
/// wrap in `Arc<dyn RngProvider>` if you need to swap providers).
#[derive(Debug, Default, Clone, Copy)]
pub struct OsRng;

impl OsRng {
    /// Construct a fresh [`OsRng`]. Equivalent to `OsRng::default()` /
    /// `OsRng`; the explicit constructor exists for symmetry with future
    /// providers that need configuration.
    pub const fn new() -> Self {
        Self
    }
}

#[cfg(not(feature = "fips"))]
impl RngProvider for OsRng {
    fn fill_bytes(&self, dest: &mut [u8]) {
        // `getrandom` is configured to call the platform CSPRNG on every
        // target the crate compiles on (the wasm32 `js` feature is enabled
        // in `Cargo.toml`'s wasm-only block). A failure here means the OS
        // RNG itself returned an error, which is unrecoverable at this
        // layer — surface it loudly rather than silently producing zeros.
        // PANIC-SAFETY: A failure from `getrandom` means the OS CSPRNG itself
        // is broken or unavailable — a condition from which this crate cannot
        // recover. Panicking loudly is preferable to silently producing zeros
        // or propagating a partially-filled buffer that the caller would treat
        // as good entropy.
        #[allow(clippy::expect_used)]
        getrandom(dest).expect("OS RNG (getrandom) failed");
    }
}

/// `--features fips` impl: delegates to `aws_lc_rs::rand::SystemRandom`,
/// which under AWS-LC-FIPS is a CTR_DRBG (NIST SP 800-90A § 10.2.1)
/// seeded from the OS CSPRNG. This is the FIPS 140-3 approved RNG
/// substrate that pairs with the rest of the primitive swap (AES-256-
/// GCM, ECDH-P-256, HKDF-SHA256). The construction is wrapped in a
/// fresh `SystemRandom` per call — the type is zero-sized and the
/// underlying DRBG state lives inside AWS-LC's process-global module.
#[cfg(feature = "fips")]
impl RngProvider for OsRng {
    fn fill_bytes(&self, dest: &mut [u8]) {
        let rng = SystemRandom::new();
        // PANIC-SAFETY: a fips `OsRng` failure means AWS-LC's CTR_DRBG
        // itself returned an error (entropy source unavailable or the
        // FIPS module is in a self-test-failed state) — a condition
        // unrecoverable at this layer. Same loud-fail policy as the
        // default `getrandom` impl above.
        #[allow(clippy::expect_used)]
        rng.fill(dest).expect("AWS-LC CTR_DRBG fill failed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Deterministic test-only RNG. Emits a counter encoded little-endian,
    /// reseeded by an arbitrary `[u8; 32]` "seed" that XORs each output
    /// word. Not cryptographically secure — exists solely to demonstrate
    /// that an interior-mutability-based provider plugs into
    /// [`RngProvider`].
    struct CounterRng {
        state: Mutex<(u64, [u8; 32])>,
    }

    impl CounterRng {
        fn from_seed(seed: [u8; 32]) -> Self {
            Self {
                state: Mutex::new((0, seed)),
            }
        }
    }

    impl RngProvider for CounterRng {
        fn fill_bytes(&self, dest: &mut [u8]) {
            let mut guard = self.state.lock().expect("CounterRng mutex poisoned");
            let (counter, seed) = &mut *guard;
            for chunk in dest.chunks_mut(8) {
                let word = *counter;
                *counter = counter.wrapping_add(1);
                let bytes = word.to_le_bytes();
                let seed_off = ((word as usize) & 0x3) * 8;
                for (i, b) in chunk.iter_mut().enumerate() {
                    *b = bytes[i] ^ seed[(seed_off + i) % 32];
                }
            }
        }
    }

    #[test]
    fn os_rng_fills_with_non_zero_bytes() {
        let rng = OsRng::new();
        let mut buf = [0u8; 32];
        rng.fill_bytes(&mut buf);
        // 32 zero bytes from a CSPRNG is astronomically unlikely (2^-256).
        assert!(buf.iter().any(|&b| b != 0), "OsRng returned all-zero block");
    }

    #[test]
    fn os_rng_two_calls_differ() {
        let rng = OsRng;
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        rng.fill_bytes(&mut a);
        rng.fill_bytes(&mut b);
        assert_ne!(a, b, "Two CSPRNG draws collided");
    }

    #[test]
    fn os_rng_next_u64_varies() {
        let rng = OsRng;
        let x = rng.next_u64();
        let y = rng.next_u64();
        // 2^-64 collision probability — acceptable for a smoke test.
        assert_ne!(x, y, "next_u64 returned the same value twice");
    }

    #[test]
    fn deterministic_test_provider() {
        let seed = [0x5Au8; 32];
        let rng_a = CounterRng::from_seed(seed);
        let rng_b = CounterRng::from_seed(seed);

        let mut a = [0u8; 64];
        let mut b = [0u8; 64];
        rng_a.fill_bytes(&mut a);
        rng_b.fill_bytes(&mut b);

        assert_eq!(a, b, "Same seed must produce identical streams");

        // And a different seed produces a different stream.
        let rng_c = CounterRng::from_seed([0xA5u8; 32]);
        let mut c = [0u8; 64];
        rng_c.fill_bytes(&mut c);
        assert_ne!(a, c, "Different seeds must produce different streams");
    }

    #[test]
    fn object_safety() {
        // Compile-time proof that `RngProvider` is dyn-compatible — i.e.,
        // a downstream embedder can erase the concrete type behind
        // `Arc<dyn RngProvider>`.
        fn assert_obj_safe(_: &dyn RngProvider) {}
        let rng = OsRng;
        assert_obj_safe(&rng);

        // And the `Arc<dyn …>` shape compiles too.
        use std::sync::Arc;
        let _shared: Arc<dyn RngProvider> = Arc::new(OsRng::new());
    }

    /// fips-only: pull a 64-byte block and confirm it is neither
    /// all-zero nor a constant byte pattern. Smokes the AWS-LC
    /// CTR_DRBG → `OsRng` wiring.
    #[cfg(feature = "fips")]
    #[test]
    fn fips_os_rng_64_byte_block_has_entropy() {
        let rng = OsRng::new();
        let mut buf = [0u8; 64];
        rng.fill_bytes(&mut buf);
        // All-zero from a CSPRNG is astronomically unlikely (2^-512).
        assert!(buf.iter().any(|&b| b != 0), "fips OsRng returned all-zero");
        // Reject any single-byte fill pattern (all bytes identical).
        let first = buf[0];
        assert!(
            buf.iter().any(|&b| b != first),
            "fips OsRng returned a constant byte pattern ({:#x} repeated)",
            first
        );
        // Two consecutive draws must differ.
        let mut buf2 = [0u8; 64];
        rng.fill_bytes(&mut buf2);
        assert_ne!(buf, buf2, "fips OsRng repeated a 64-byte block");
    }
}
