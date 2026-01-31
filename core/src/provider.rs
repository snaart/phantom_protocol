use openmls_traits::OpenMlsProvider;
use openmls_rust_crypto::RustCrypto;
use openmls_memory_storage::MemoryStorage;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct UniversalProvider {
    // Оборачиваем в Arc для поддержки Clone
    crypto: Arc<RustCrypto>,
    storage: Arc<MemoryStorage>,
}

impl UniversalProvider {
    pub fn new() -> Self {
        Self {
            crypto: Arc::new(RustCrypto::default()),
            storage: Arc::new(MemoryStorage::default()),
        }
    }
}

impl Default for UniversalProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl OpenMlsProvider for UniversalProvider {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = MemoryStorage;

    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }
}