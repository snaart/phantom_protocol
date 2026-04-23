// `transport`, `tls`, and `engine` are native-only (raw sockets / rustls /
// BoxedTransport). Phase 3.5. `engine` depends on `transport::BoxedTransport`
// which is non-wasm32, so it must be gated together.
#[cfg(not(target_arch = "wasm32"))]
pub mod engine;
pub mod pipeline;
#[cfg(not(target_arch = "wasm32"))]
pub mod tls;
#[cfg(not(target_arch = "wasm32"))]
pub mod transport;
