//! Phantom Core Public API
//!
//! Transport session facade for the SDK.
//! - [`session::PhantomSession`] — Client-first transport session
//! - [`stream::PhantomStream`] — Multiplexed reliable stream
//! - [`listener::PhantomListener`] — Server socket listener
//! - [`tcp_transport::TcpSessionTransport`] — Length-prefixed framing over TCP

pub mod session;
pub mod stream;
pub mod listener;
pub mod tcp_transport;

// Re-exports
pub use session::{PhantomSession, ConnectionState, SessionTransport};
pub use stream::PhantomStream;
pub use listener::PhantomListener;
pub use tcp_transport::TcpSessionTransport;
