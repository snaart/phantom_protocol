//! Phantom Universal Transport Core
//! 
//! A meta-transport layer combining SCTP, QUIC, and KCP advantages:
//! - Multi-homing (seamless Wi-Fi ↔ LTE)
//! - Multi-streaming (independent streams, no HoL blocking)
//! - 0-RTT connection establishment
//! - Connection migration (session persists across IP changes)
//! - Adaptive fallback (Turbo → Reliable → Stealth)

pub mod types;
pub mod session;
pub mod stream;
pub mod scheduler;
pub mod fallback;
pub mod legs;
pub mod virtual_socket;
pub mod handshake;
pub mod buffer_pool;
pub mod udp_transport;
pub mod packet_coalescer;
pub mod pacer;
pub mod bandwidth_estimator;
pub mod device_profile;
pub mod framing;
pub mod session_cache;
pub mod compression;
pub mod metrics;
pub mod api;
pub mod multiplexer;
pub mod reputation;
pub mod half_open;
pub mod fragmentation;

// Re-exports for convenience
pub use types::*;
pub use session::Session;
pub use stream::Stream;
pub use scheduler::Scheduler;
pub use fallback::{FallbackStateMachine, TransportMode};
pub use virtual_socket::VirtualSocket;
