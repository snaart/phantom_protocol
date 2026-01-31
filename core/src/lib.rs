mod errors;
mod provider;
mod core_actor;
mod api;
mod network;

// Crypto module (hybrid KEM, hybrid sign)
pub mod crypto;

// Transport module (Universal Transport Core)
pub mod transport;

// Networks module (transport, pipeline, engine, tls)
pub mod networks;

// Client module for external use
pub mod client;

// Test harness for network simulation
#[cfg(test)]
pub mod test_harness;

// Public exports
pub use api::UniversalMlsCore;
pub use errors::CoreError;

uniffi::setup_scaffolding!();