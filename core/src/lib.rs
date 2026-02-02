pub mod crypto;
pub mod network;
pub mod storage;
pub mod client;

uniffi::setup_scaffolding!();

// For FFI usage
pub extern "C" fn init_function() {
    // logger init
    // mimalloc is auto-registered if linked
}
