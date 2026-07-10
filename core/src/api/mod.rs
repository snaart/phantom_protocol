//! Phantom Protocol Public API
//!
//! Transport session facade for the SDK.
//! - [`session::PhantomSession`] — Client-first transport session (all targets)
//! - [`stream::PhantomStream`] — Multiplexed reliable stream (all targets)
//! - [`listener::PhantomListener`] — Server socket listener (native only)
//! - [`tcp_transport::TcpSessionTransport`] — Length-prefixed framing over TCP (native only)
//!
//! On `wasm32-unknown-unknown` (browser) targets the TCP-based building
//! blocks are absent; use `WebSocketLeg` as
//! the `SessionTransport` implementation. On `wasm32-wasi*` targets
//! with `--features wasi-leg`, use
//! `WasiLeg` (paired with
//! `WasiRuntime`) for a TCP-shaped
//! transport over WASI Preview 2 sockets.

pub mod identity;
pub mod session;
pub mod stream;

#[cfg(not(target_arch = "wasm32"))]
pub mod listener;
#[cfg(not(target_arch = "wasm32"))]
pub mod tcp_transport;
#[cfg(not(target_arch = "wasm32"))]
pub mod udp_listener;
#[cfg(not(target_arch = "wasm32"))]
pub mod udp_transport;

#[cfg(test)]
mod loss_recovery_tests;

// Cross-target re-exports
pub use session::{ConnectionState, NoTransport, PhantomSession, SessionBuilder, SessionTransport};
pub use stream::PhantomStream;

// Native-only re-exports
#[cfg(not(target_arch = "wasm32"))]
pub use listener::{ListenerBuilder, PhantomListener};
#[cfg(not(target_arch = "wasm32"))]
pub use tcp_transport::TcpSessionTransport;
#[cfg(not(target_arch = "wasm32"))]
pub use udp_listener::{PhantomUdpListener, UdpListenerBuilder};
#[cfg(not(target_arch = "wasm32"))]
pub use udp_transport::UdpClientTransport;

// One-shot connect helpers — re-exported here so `phantom_protocol::api::connect_pinned*`
// works as an alternative to the `phantom_protocol::connect_pinned*` crate-root path.
#[cfg(not(target_arch = "wasm32"))]
pub use session::{
    connect_pinned, connect_pinned_udp, connect_pinned_udp_with_config,
    connect_pinned_udp_with_resumption, connect_pinned_with_config, connect_pinned_with_resumption,
};
