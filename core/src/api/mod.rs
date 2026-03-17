//! Phantom Core Public API
//!
//! Transport session facade for the SDK.
//! - [`session::PhantomSession`] — Client-first transport session (all targets)
//! - [`stream::PhantomStream`] — Multiplexed reliable stream (all targets)
//! - [`listener::PhantomListener`] — Server socket listener (native only)
//! - [`tcp_transport::TcpSessionTransport`] — Length-prefixed framing over TCP (native only)
//!
//! On `wasm32-*` targets the TCP-based building blocks are absent; use
//! [`crate::transport::legs::WebSocketLeg`] as the `SessionTransport`
//! implementation instead.

pub mod session;
pub mod stream;

#[cfg(not(target_arch = "wasm32"))]
pub mod listener;
#[cfg(not(target_arch = "wasm32"))]
pub mod tcp_transport;

// Cross-target re-exports
pub use session::{PhantomSession, ConnectionState, SessionTransport};
pub use stream::PhantomStream;

// Native-only re-exports
#[cfg(not(target_arch = "wasm32"))]
pub use listener::PhantomListener;
#[cfg(not(target_arch = "wasm32"))]
pub use tcp_transport::TcpSessionTransport;
