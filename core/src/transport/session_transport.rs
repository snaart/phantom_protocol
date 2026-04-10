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

use crate::errors::CoreError;
use bytes::Bytes;

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
    fn recv_bytes(&self)
        -> impl core::future::Future<Output = Result<Bytes, CoreError>> + Send;
}
