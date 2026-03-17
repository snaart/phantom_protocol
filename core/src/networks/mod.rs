// `transport` and `tls` are native-only (raw sockets / rustls). Phase 3.5.
#[cfg(not(target_arch = "wasm32"))]
pub mod transport;
pub mod pipeline;
pub mod engine;
#[cfg(not(target_arch = "wasm32"))]
pub mod tls;