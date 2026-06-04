//! The `SessionTransport` byte-pipe abstraction — the boundary between
//! `PhantomSession`'s background data pump and a concrete physical transport
//! (`TcpSessionTransport`, `WebSocketLeg`, `EmbeddedLeg`, ...).
//!
//! Defined with **native async fn in trait** (AFIT, stable since Rust 1.75)
//! rather than the `#[async_trait]` macro: method calls do not allocate a
//! boxed future, and `Send`-ness of the returned futures is checked at the
//! *use* site (the concrete impl type), not at the trait-impl site. The
//! latter is what allows `EmbeddedLeg<R, W, ...>` to compose with
//! `embedded-io-async`, whose async-fn-in-trait futures are not `Send`-
//! bounded — `#[async_trait]` here would have failed to prove `Send`-ness
//! at the generic impl site.
//!
//! Dependency-light (only `bytes` + `CoreError`) so it can compile in a
//! future `no_std + alloc` build ahead of the rest of the crate.
//! Re-exported from [`crate::api::session`] so the historical import path
//! stays stable.
//!
//! Phase 3.6 (no-std foundation): module compiles without `std` because the
//! implementation uses only `core::future::Future` and pulls nothing from
//! `std::*`. The crate-level `#![cfg_attr(not(feature = "std"), no_std)]` in
//! `lib.rs` drives the no_std switch; this module needs no extra attribute.

use crate::errors::CoreError;
use bytes::Bytes;

/// Lifecycle phase of a [`SessionTransport`], used to bound the receive frame
/// size differently before vs. after the handshake (WIRE-001). During the
/// unauthenticated handshake a peer can open a connection and declare a large
/// frame; capping the receive size tightly there bounds the memory a single
/// unauthenticated peer can make the server buffer. After establishment the cap
/// rises to the steady-state application limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FramePhase {
    /// Pre-establishment: only small handshake messages are expected.
    Handshake,
    /// Post-establishment: full-size application frames are allowed.
    Established,
}

/// Async transport trait for PhantomSession.
///
/// Abstractions over UDP, TCP, FakeTLS, etc.
/// Used by the background handshake task for I/O.
///
/// `recv_bytes` returns `Bytes` (Phase 2.8) so the recv pipeline can
/// fan out the same buffer to multiple consumers via cheap refcount
/// clones — no `Vec → Bytes` conversion at the trait boundary.
/// `send_bytes` keeps `&[u8]` because the caller routinely sends a
/// borrowed slice of an already-allocated send buffer.
pub trait SessionTransport: Send + Sync + 'static {
    /// Send raw bytes to the peer.
    ///
    /// Desugared form (`fn -> impl Future + Send`) rather than `async fn`
    /// so the `+ Send` bound on the returned future is explicit. This is
    /// what lets the data pump spawn its task generically over any
    /// `T: SessionTransport` without an AFIT `return_type_notation` hack.
    fn send_bytes(
        &self,
        data: &[u8],
    ) -> impl core::future::Future<Output = Result<(), CoreError>> + Send;
    /// Receive the next message from the peer. The returned `Bytes` is
    /// a refcounted view over an opaque buffer; subsequent `clone()`s
    /// are cheap.
    fn recv_bytes(&self) -> impl core::future::Future<Output = Result<Bytes, CoreError>> + Send;

    /// Move the transport to a new [`FramePhase`], adjusting the receive
    /// frame-size cap (WIRE-001). Default no-op — transports that do not
    /// length-prefix / buffer, or are inherently bounded, need not implement it.
    /// Called once by the session machinery at the handshake → data-pump
    /// boundary. Adding this defaulted method is source-compatible for every
    /// existing impl.
    fn set_frame_phase(&self, _phase: FramePhase) {}
}
