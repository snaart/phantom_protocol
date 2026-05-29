//! Transport Legs Module
//!
//! Pluggable physical transports. Native targets carry KCP / TCP /
//! FakeTLS; the `wasm32` target exposes a WebSocket leg (Phase 3.3)
//! since browsers cannot open raw TCP/UDP sockets.

#[cfg(all(feature = "std", not(target_arch = "wasm32")))]
pub mod faketls;
#[cfg(all(feature = "std", not(target_arch = "wasm32")))]
pub mod kcp;
#[cfg(all(feature = "std", not(target_arch = "wasm32")))]
pub mod tcp;

#[cfg(all(feature = "std", target_arch = "wasm32", target_os = "unknown"))]
pub mod websocket;

#[cfg(all(feature = "std", target_arch = "wasm32", target_os = "unknown"))]
pub use websocket::WebSocketLeg;

// Section B / B3 — WASI Preview 2 TCP leg. Same `cfg` gate as
// `runtime::wasi_runtime`: only built when the `wasi-leg` feature is
// active AND the build target is a WASI triple
// (`cfg(target_os = "wasi")`). Mutual exclusion with `wasm32-unknown-
// unknown` is enforced in `core/src/lib.rs`.
#[cfg(all(feature = "wasi-leg", target_os = "wasi"))]
pub mod wasi;

#[cfg(all(feature = "wasi-leg", target_os = "wasi"))]
pub use wasi::WasiLeg;

// `EmbeddedLeg` — `SessionTransport` over `embedded-io-async` byte streams,
// behind the `embedded` feature. Compiles on any target (host included) so the
// tests run there. Phase 3.4. no_std-clean, so it is NOT gated behind `std`.
#[cfg(feature = "embedded")]
pub mod embedded;

// The `TransportLeg` trait below uses `async_trait`, `std::io`, and
// `std::net::SocketAddr` — std-only. The `embedded` leg implements
// `SessionTransport` directly and does not need `TransportLeg`.
#[cfg(feature = "std")]
mod trait_def {
    use async_trait::async_trait;
    use bytes::Bytes;
    use std::io;
    use std::net::SocketAddr;

    /// Transport leg trait - abstraction over different physical transports
    #[async_trait]
    pub trait TransportLeg: Send + Sync {
        /// Send data to the remote peer
        async fn send(&self, data: Bytes) -> io::Result<()>;

        /// Receive data from the remote peer
        async fn recv(&self) -> io::Result<Bytes>;

        /// Check if this leg is currently available
        fn is_available(&self) -> bool;

        /// Get the current RTT estimate in milliseconds
        fn rtt_ms(&self) -> u32;

        /// Get packet loss percentage (0-100)
        fn loss_percent(&self) -> u8;

        /// Get the remote address
        fn remote_addr(&self) -> Option<SocketAddr>;

        /// Gracefully close the transport
        async fn close(&self) -> io::Result<()>;
    }
}

#[cfg(feature = "std")]
pub use trait_def::TransportLeg;
