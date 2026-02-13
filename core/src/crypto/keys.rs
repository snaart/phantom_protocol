// This module opts back in to `unsafe` (denied at the crate root in lib.rs).
// The `unsafe` blocks here are required to obtain `&mut [u8]` slices over the
// opaque pqcrypto secret-key types so they can be zeroed via `volatile_write`
// on drop. Each block carries a `// SAFETY:` comment explaining the invariant.
#![allow(unsafe_code)]

use pqcrypto_kyber::kyber768;
use pqcrypto_dilithium::dilithium3;
use pqcrypto_traits::kem::SecretKey as KemSecretKey;
use pqcrypto_traits::sign::SecretKey as SignSecretKey;
use std::sync::atomic::{compiler_fence, Ordering};
use std::ptr;
use zeroize::Zeroize;

/// Secure wrapper around Kyber768 secret key that ensures memory is zeroed on drop
pub struct KyberSecretKey(pub kyber768::SecretKey);

impl Drop for KyberSecretKey {
    fn drop(&mut self) {
        compiler_fence(Ordering::SeqCst);
        let ptr = self.0.as_bytes().as_ptr() as *mut u8;
        let len = self.0.as_bytes().len();
        for i in 0..len {
            // SAFETY: `ptr` was obtained from `self.0.as_bytes()` which returns
            // a slice valid for `len` bytes of the secret-key buffer. `ptr.add(i)`
            // stays within bounds because `i < len`. `write_volatile` is the only
            // way to defeat the optimizer's dead-store elimination on this
            // soon-to-be-deallocated memory.
            unsafe {
                ptr::write_volatile(ptr.add(i), 0);
            }
        }
        compiler_fence(Ordering::SeqCst);
    }
}

impl Zeroize for KyberSecretKey {
    fn zeroize(&mut self) {
        // Our custom Drop takes care of zeroing out the memory.
    }
}

/// Secure wrapper around Dilithium3 secret key
pub struct DilithiumSecretKey(pub dilithium3::SecretKey);

impl Drop for DilithiumSecretKey {
    fn drop(&mut self) {
        compiler_fence(Ordering::SeqCst);
        let ptr = self.0.as_bytes().as_ptr() as *mut u8;
        let len = self.0.as_bytes().len();
        for i in 0..len {
            // SAFETY: same invariants as `KyberSecretKey::drop` — `ptr` is
            // valid for `len` bytes, `i < len`, and `write_volatile` survives
            // optimizer dead-store removal.
            unsafe {
                ptr::write_volatile(ptr.add(i), 0);
            }
        }
        compiler_fence(Ordering::SeqCst);
    }
}

impl Zeroize for DilithiumSecretKey {
    fn zeroize(&mut self) {
        // Our custom Drop takes care of zeroing out the memory.
    }
}
