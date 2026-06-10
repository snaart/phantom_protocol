//! Phantom Protocol
//!
//! A meta-transport layer combining SCTP, QUIC, and KCP advantages:
//! - Multi-homing (seamless Wi-Fi ↔ LTE)
//! - Multi-streaming (independent streams, no HoL blocking)
//! - 0-RTT connection establishment
//! - Connection migration (session persists across IP changes)
//! - Adaptive fallback (Turbo → Reliable → Stealth)

// ── no_std-clean subset (Phase 3.6) ────────────────────────────────────
// `session_transport` and `legs::embedded` compile on bare-metal and are the
// only modules required for the embedded build.
pub mod legs;
pub mod session_transport;

// ── std-bound modules ──────────────────────────────────────────────────
// Everything below pulls `tokio`, `parking_lot`, `dashmap`, `arc-swap`,
// `std::sync::*`, `std::time::Instant`, raw sockets, or a std-bound crypto dep
// (`ring`, `ml-kem`, `ml-dsa`, `x25519-dalek`, `ed25519-dalek`).
// Gated behind `std`.
#[cfg(feature = "std")]
pub mod api;
#[cfg(feature = "std")]
pub mod bandwidth_estimator;
#[cfg(feature = "std")]
pub mod buffer_pool;
#[cfg(feature = "std")]
pub mod compression;
#[cfg(feature = "std")]
pub mod device_profile;
#[cfg(feature = "std")]
pub mod fallback;
#[cfg(feature = "std")]
pub mod fragmentation;
#[cfg(feature = "std")]
pub mod handshake;
#[cfg(feature = "std")]
pub mod multiplexer;
#[cfg(feature = "std")]
pub mod pacer;
#[cfg(feature = "std")]
pub mod packet_coalescer;
#[cfg(feature = "std")]
pub mod packet_coalescer_codec;
#[cfg(feature = "std")]
pub mod path;
#[cfg(feature = "std")]
pub mod path_validation_codec;
#[cfg(feature = "std")]
pub mod reputation;
#[cfg(feature = "std")]
pub mod sack;
#[cfg(feature = "std")]
pub mod scheduler;
#[cfg(feature = "std")]
pub mod session;
#[cfg(feature = "std")]
pub mod session_cache;
#[cfg(feature = "std")]
pub mod stream;
#[cfg(feature = "std")]
pub mod types;

// ── Native-only sub-modules (Phase 3.5) ────────────────────────────────
// These pull in `tokio::net::*` / raw sockets / libc and have no wasm
// equivalent. On wasm32 the corresponding functionality is provided
// either by `legs::WebSocketLeg` (transport) or by simply not being
// available (listening for incoming TCP — browsers cannot listen).
// All require `std`.
#[cfg(all(feature = "std", not(target_arch = "wasm32")))]
pub mod framing;
#[cfg(all(feature = "std", not(target_arch = "wasm32")))]
pub mod phantom_udp;
#[cfg(all(feature = "std", not(target_arch = "wasm32")))]
pub mod udp_transport;

// Re-exports for convenience
#[cfg(feature = "std")]
pub use fallback::{FallbackStateMachine, TransportMode};
#[cfg(feature = "std")]
pub use scheduler::Scheduler;
#[cfg(feature = "std")]
pub use session::Session;
#[cfg(feature = "std")]
pub use stream::Stream;
#[cfg(feature = "std")]
pub use types::*;
