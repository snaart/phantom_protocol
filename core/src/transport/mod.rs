//! Phantom Universal Transport Core
//!
//! A meta-transport layer combining SCTP, QUIC, and KCP advantages:
//! - Multi-homing (seamless Wi-Fi ↔ LTE)
//! - Multi-streaming (independent streams, no HoL blocking)
//! - 0-RTT connection establishment
//! - Connection migration (session persists across IP changes)
//! - Adaptive fallback (Turbo → Reliable → Stealth)

pub mod api;
pub mod bandwidth_estimator;
pub mod buffer_pool;
pub mod compression;
pub mod device_profile;
pub mod fallback;
pub mod fragmentation;
pub mod half_open;
pub mod handshake;
pub mod legs;
pub mod metrics;
pub mod multiplexer;
pub mod pacer;
pub mod packet_coalescer;
pub mod packet_coalescer_codec;
pub mod path;
pub mod path_validation_codec;
pub mod reputation;
pub mod scheduler;
pub mod session;
pub mod session_cache;
pub mod stream;
pub mod types;

// ── Native-only sub-modules (Phase 3.5) ────────────────────────────────
// These pull in `tokio::net::*` / raw sockets / libc and have no wasm
// equivalent. On wasm32 the corresponding functionality is provided
// either by `legs::WebSocketLeg` (transport) or by simply not being
// available (listening for incoming TCP — browsers cannot listen).
#[cfg(not(target_arch = "wasm32"))]
pub mod framing;
#[cfg(not(target_arch = "wasm32"))]
pub mod udp_transport;
#[cfg(not(target_arch = "wasm32"))]
pub mod virtual_socket;

// Re-exports for convenience
pub use fallback::{FallbackStateMachine, TransportMode};
pub use scheduler::Scheduler;
pub use session::Session;
pub use stream::Stream;
pub use types::*;

#[cfg(not(target_arch = "wasm32"))]
pub use virtual_socket::VirtualSocket;
