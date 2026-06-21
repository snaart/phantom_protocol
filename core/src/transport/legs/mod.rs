//! Transport Legs Module
//!
//! Pluggable physical transports, each a `SessionTransport` impl. The browser
//! `wasm32` target exposes a WebSocket leg (Phase 3.3) since browsers cannot open
//! raw TCP/UDP sockets; WASI Preview 2 uses a TCP leg; bare-metal uses the
//! `embedded` leg; the off-by-default `mimicry` feature adds a TLS-mimicry leg.
//!
//! The native KCP / TCP / FakeTLS legs and the `TransportLeg` multipath trait
//! were removed in Phase 0 of the PhantomUDP rewrite — they were never wired
//! into the session data plane (`PhantomSession` consumes `SessionTransport`,
//! not `TransportLeg`). The production reliable transport is now PhantomUDP
//! (`UdpClientTransport` / `UdpServerTransport`, which live outside this module
//! under `transport/phantom_udp/` + `api/udp_transport.rs`), and FakeTLS-style
//! traffic mimicry has returned as the `MimicTlsLeg` (`mimic_tls`, below). The
//! plain TCP byte-pipe is `TcpSessionTransport` (in `api/tcp_transport.rs`).

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

// `MimicTlsLeg` — TLS-over-TCP active-mimicry `SessionTransport`. Native-only
// (rides `tokio::net`), behind the off-by-default `mimicry` feature. Comprises the
// record layer (`mimic_tls::record`), a TLS-1.3 handshake "theater", and the leg
// itself (`mimic_tls::leg`). The outer TLS is anti-DPI obfuscation ONLY (never a
// confidentiality boundary) and is detectable by active probing — the inner Phantom
// session provides the real auth/conf. See the module head and Security Invariant 3.
#[cfg(all(feature = "mimicry", not(target_arch = "wasm32")))]
pub mod mimic_tls;
