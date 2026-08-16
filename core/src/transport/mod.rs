//! Phantom Protocol transport internals.
//!
//! The protocol layer beneath the public `crate::api` surface. PhantomUDP — a
//! QUIC-class reliable transport over raw UDP — is the production transport;
//! TCP / WebSocket / WASI / Embedded / TLS-mimicry byte-pipes also plug in via
//! `SessionTransport`. Key properties:
//! - Multi-streaming (independent streams, no head-of-line blocking)
//! - 0-RTT connection establishment (resumption + early-data)
//! - Seamless single-path connection migration (session survives IP changes)
//!
//! NOTE: multipath bandwidth aggregation / multi-homing was deliberately rejected
//! — migration moves one active path at a time, it does not bond paths.
//!
//! # Modules that are published but not on the data path
//!
//! [`compression`], [`fallback`], [`scheduler`] and the encoding half of
//! [`packet_coalescer`] are compiled, tested and exported, and no send or receive
//! path calls any of them. They are named here rather than left to be discovered
//! because the cost of mistaking one for a working mechanism falls on the reader
//! and never on the compiler: someone who finds `AdaptiveCompressor` in the public
//! API concludes that packets are compressed, and not one is. Each of those
//! modules now opens its own documentation with the same statement, so the
//! disclaimer survives arriving at a module directly rather than through this
//! index. Connecting any of them to the pump is a feature with a wire-level design
//! behind it, not a cleanup.

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
pub mod fallback;
#[cfg(feature = "std")]
pub mod fragmentation;
#[cfg(feature = "std")]
pub mod handshake;
#[cfg(feature = "std")]
pub mod liveness;
#[cfg(feature = "std")]
pub mod mtu;
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
pub mod shaping;
#[cfg(feature = "std")]
pub mod stream;
#[cfg(feature = "std")]
pub mod types;

// ── Native-only sub-modules (Phase 3.5) ────────────────────────────────
// These pull in `tokio::net::*` / raw sockets and have no wasm
// equivalent. On wasm32 the corresponding functionality is provided
// either by `legs::WebSocketLeg` (transport) or by simply not being
// available (listening for incoming TCP — browsers cannot listen).
// All require `std`.
#[cfg(all(feature = "std", not(target_arch = "wasm32")))]
pub mod framing;
#[cfg(all(feature = "std", not(target_arch = "wasm32")))]
pub mod phantom_udp;

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
