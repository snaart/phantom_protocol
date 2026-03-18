pub mod hybrid_kem;
pub mod hybrid_sign;
pub mod aes_session;
pub mod adaptive_crypto;
pub mod pow;
// `keys.rs` previously wrapped pqcrypto-* opaque secret keys with manual
// `unsafe` `ptr::write_volatile` zeroing. After Phase 5.1 we use ml-kem /
// ml-dsa types that implement `Zeroize` natively, so this module is gone
// — one fewer `#[allow(unsafe_code)]` opt-in in the crate.
