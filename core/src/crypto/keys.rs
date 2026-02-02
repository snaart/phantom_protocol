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
