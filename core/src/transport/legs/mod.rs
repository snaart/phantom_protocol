//! Transport Legs Module
//!
//! Pluggable physical transports. The browser `wasm32` target exposes a
//! WebSocket leg (Phase 3.3) since browsers cannot open raw TCP/UDP sockets;
//! WASI Preview 2 uses a TCP leg; bare-metal uses the `embedded` leg.
//!
//! The native KCP / TCP / FakeTLS legs and the `TransportLeg` multipath trait
//! were removed in Phase 0 of the PhantomUDP rewrite — they were never wired
//! into the session data plane (`PhantomSession` consumes `SessionTransport`,
//! not `TransportLeg`) and are superseded by the forthcoming native
//! reliable-UDP transport. FakeTLS-style traffic mimicry will return as a
//! dedicated transport mode.

#[cfg(all(feature = "std", target_arch = "wasm32", target_os = "unknown"))]
pub mod websocket;

#[cfg(all(feature = "std", target_arch = "wasm32", target_os = "unknown"))]
pub use websocket::WebSocketLeg;

// Section B / B3 — WASI Preview 2 TCP leg. Same `cfg` gate as
// `runtime::wasi_runtime`: only built when the `wasi-leg` feature is
// active AND the build target is a WASI triple (`cfg(target_os = "wasi")`).
// Mutual exclusion with `wasm32-unknown-unknown` is enforced in
// `core/src/lib.rs`.
#[cfg(all(feature = "wasi-leg", target_os = "wasi"))]
pub mod wasi;

#[cfg(all(feature = "wasi-leg", target_os = "wasi"))]
pub use wasi::WasiLeg;

// `EmbeddedLeg` — `SessionTransport` over `embedded-io-async` byte streams,
// behind the `embedded` feature. Compiles on any target (host included) so the
// tests run there. Phase 3.4. no_std-clean, so it is NOT gated behind `std`.
#[cfg(feature = "embedded")]
pub mod embedded;
