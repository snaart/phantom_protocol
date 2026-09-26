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
//! Dependency-light (only `bytes` + `CoreError`) so it compiles in the
//! shipped `no_std + alloc` subset (Phase 3.6) alongside `legs::embedded`.
//! Re-exported from [`crate::api::session`] so the historical import path
//! stays stable.
//!
//! Phase 3.6 (no-std foundation): module compiles without `std` because the
//! implementation uses only `core::future::Future` and pulls nothing from
//! `std::*`. The crate-level `#![cfg_attr(not(feature = "std"), no_std)]` in
//! `lib.rs` drives the no_std switch; this module needs no extra attribute.

use crate::errors::CoreError;
use bytes::Bytes;
// `String` is in the std prelude on std builds; under `no_std` it comes from `alloc`
// (the migration address crosses this boundary as a `String` to keep the trait
// `SocketAddr`-free — `std::net::SocketAddr` does not exist in `core`/`alloc`).
#[cfg(not(feature = "std"))]
use alloc::string::String;

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

/// Async transport trait for `PhantomSession`.
///
/// The byte-pipe abstraction over every concrete physical transport — PhantomUDP
/// (`UdpClientTransport` / `UdpServerTransport`), TCP (`TcpSessionTransport`),
/// WebSocket, WASI, Embedded, and the off-by-default TLS-mimicry leg. Used by the
/// background handshake + data-pump task for all message-oriented I/O.
///
/// `recv_bytes` returns `Bytes` (Phase 2.8) so the recv pipeline can
/// fan out the same buffer to multiple consumers via cheap refcount
/// clones — no `Vec → Bytes` conversion at the trait boundary.
/// `send_bytes` keeps `&[u8]` because the caller routinely sends a
/// borrowed slice of an already-allocated send buffer.
///
/// **Wrapper contract (audit EPS-04):** every method below the two I/O methods
/// has a *silently-succeeding* default (`{}` / `false` / `Ok(())`). Those are
/// correct for transports without migration, but they make a **partial wrapper**
/// (a newtype that forwards only `send_bytes` / `recv_bytes`) compile with no
/// warning while every control call no-ops on the default — the exact bug that
/// made the pre-ε FFI `migrate()` vacuous through `ObservedTransport`. Any wrapper
/// over a `SessionTransport` **MUST forward the full surface** (all the control
/// methods, not just I/O); the `observed_transport_forwards_all_control_methods`
/// tripwire test guards this for the in-crate wrappers.
pub trait SessionTransport: Send + Sync + 'static {
    /// Send raw bytes to the peer.
    ///
    /// Desugared form (`fn -> impl Future + Send`) rather than `async fn`
    /// so the `+ Send` bound on the returned future is explicit. This is
    /// what lets the data pump spawn its task generically over any
    /// `T: SessionTransport` without an AFIT `return_type_notation` hack.
    ///
    /// # A write must not wait on the peer forever
    ///
    /// On a byte-stream transport a write can wait on the peer: once the peer
    /// stops reading, the buffers between the two ends fill and stay full. The
    /// session's data pump is the writer, and while one of its writes waits, the
    /// rest of the pump waits with it — no liveness sweep, and no local close,
    /// since `disconnect()` and dropping the handle are requests the pump reads
    /// between writes. A peer could hold the session for as long as it liked.
    ///
    /// So an implementation whose write can wait on the peer bounds it: once a
    /// write has made **no progress** for a bounded time, fail it with
    /// [`CoreError::Timeout`]. Progress is the point — a peer still taking bytes,
    /// however slowly, is a slow link and must not be cut off; only one that has
    /// stopped. After such a failure, refuse every later write with the same error
    /// without touching the connection, because the write that gave up may have
    /// left a frame cut part-way through, and any byte written after it would be
    /// read by the peer as the rest of that frame.
    ///
    /// The session treats `Timeout` from either I/O method as the transport
    /// having given up on the peer, and nothing short of that: it writes nothing
    /// more, stops reading, and ends in `ConnectionState::Dead`, reporting the
    /// `Timeout` from `last_error()` and `recv()`. Any other error from a write is
    /// the transport's own business and the session carries on.
    ///
    /// How each shipped transport stands:
    ///
    /// - `TcpSessionTransport` bounds every write by a progress deadline, thirty
    ///   seconds unless set otherwise — with `with_write_stall_timeout` on a
    ///   transport the caller builds, or through `PhantomConfig::write_stall_timeout`
    ///   on the ones the listeners and the config-taking connects build.
    /// - The TLS-mimicry leg does the same once its prelude is done; the prelude's
    ///   writes already sit under the prelude's own deadline.
    /// - The WASI leg does the same through `wasi:io/poll`.
    /// - `EmbeddedLeg` has no clock of its own on a bare-metal target, so the bound
    ///   is its writer's to impose: a writer that can block indefinitely (a USB
    ///   CDC link whose host stopped reading, a UART under hardware flow control)
    ///   should wrap its writes in the executor's timeout and report
    ///   `ErrorKind::TimedOut`, which the leg turns into `Timeout` and treats as
    ///   final. A UART without flow control never waits on its peer at all.
    /// - The PhantomUDP transports and the browser WebSocket leg never wait on the
    ///   peer: a datagram send completes or fails locally, and a browser WebSocket
    ///   buffers whatever it is given.
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

    /// Stamp this transport's outbound routing CID (ε / WIRE v5). Called once by
    /// the session machinery at the handshake → data-pump boundary with the
    /// session's `current_outbound_cid()` (the rotating `CID_0`), switching the
    /// transport off the bootstrap ConnId onto the chain. Default no-op —
    /// socket-routed transports (TCP / WebSocket / WASI / Embedded) carry no
    /// on-wire CID and ignore it. Source-compatible for every existing impl.
    fn set_outbound_cid(&self, _cid: [u8; 8]) {}

    /// Whether the transport has observed an unvalidated **candidate** source for
    /// this session — a connection-migration signal (Phase 4). Only an
    /// address-aware transport (the UDP server) ever returns `true`; stream
    /// transports (TCP / WebSocket / WASI / Embedded) have no migration and use
    /// the default `false`. Deliberately **SocketAddr-free** so the generic data
    /// pump that calls it stays no_std-clean (`std::net::SocketAddr` does not
    /// exist in `core`/`alloc`); the candidate address is held inside the
    /// concrete transport.
    fn has_migration_candidate(&self) -> bool {
        false
    }

    /// Send `data` — an already-encrypted `PATH_VALIDATION` challenge built by the
    /// session — to the transport's internally-tracked candidate source, distinct
    /// from the established peer, under the transport's own anti-amplification cap
    /// (RFC 9000 §8.2). Returns `Ok(true)` if a candidate existed and the send was
    /// within budget, `Ok(false)` otherwise (no candidate, or the 3× cap was hit).
    /// Default (non-address transports): a no-op `Ok(false)`. The candidate
    /// address never crosses this boundary, keeping the trait no_std-safe.
    fn send_to_candidate(
        &self,
        _data: &[u8],
    ) -> impl core::future::Future<Output = Result<bool, CoreError>> + Send {
        async { Ok(false) }
    }

    /// Commit the most-recently-received frame's source as the migration candidate — call ONLY
    /// from the post-decrypt path, i.e. once that frame has been AEAD-verified (M-1). On the
    /// address-aware UDP server this is the migration-integrity fix: the candidate (and hence
    /// the server's `PATH_CHALLENGE` target) is only ever an AEAD-authenticated source, so a
    /// spoofed CID-matched datagram (which never decrypts) cannot clobber the candidate slot
    /// and misdirect / stall a legitimate migration. SocketAddr-free — the address stays inside
    /// the concrete transport. Default no-op for transports without migration.
    fn confirm_authenticated_source(&self) {}

    /// Promote the migration candidate to the established peer (Phase 4, the
    /// switch): after the candidate's path validates, subsequent app data and
    /// retransmits go to it instead of the old peer. Returns `true` if a candidate
    /// was promoted. Default no-op (`false`) for transports without migration.
    /// SocketAddr-free — the address is internal to the concrete transport.
    fn promote_candidate(&self) -> bool {
        false
    }

    /// Whether this transport supports seamless connection migration without a
    /// re-handshake. Returns `true` only for address-aware UDP transports
    /// ([`UdpClientTransport`] / [`UdpServerTransport`]); all stream transports
    /// (TCP, WebSocket, WASI, Embedded) return `false`.
    ///
    /// Use this to guard calls to [`migrate`](Self::migrate) at runtime.
    ///
    /// [`UdpClientTransport`]: crate::api::udp_transport::UdpClientTransport
    /// [`UdpServerTransport`]: crate::api::udp_transport::UdpServerTransport
    fn supports_migration(&self) -> bool {
        false
    }

    /// Migrate this transport to a new local address (Phase 4 / P4.2c — embedder-
    /// triggered connection migration). The address crosses as a `String` (parsed
    /// inside the concrete native transport) so the
    /// trait stays `SocketAddr`-free and no_std-clean — `std::net::SocketAddr` does
    /// not exist in `core`/`alloc`. Best-effort: a parse / bind / connect failure
    /// returns `Err` and the session is expected to keep running on its existing
    /// socket — migration never tears it down.
    ///
    /// Default: returns [`CoreError::Unsupported`] for transports without migration
    /// (TCP / WebSocket / WASI / Embedded / the in-memory test pipe); only the native
    /// UDP client (`UdpClientTransport`) overrides this with the real implementation.
    /// Call [`supports_migration`](Self::supports_migration) before calling this method
    /// to avoid receiving `Unsupported` on non-UDP sessions.
    fn migrate(
        &self,
        _local_addr: String,
    ) -> impl core::future::Future<Output = Result<(), CoreError>> + Send {
        async {
            Err(CoreError::Unsupported(
                "this transport does not support connection migration; use a UDP-backed session"
                    .into(),
            ))
        }
    }

    /// Migrate the **server side** of this transport to a new local send address — the
    /// mirror of [`migrate`](Self::migrate) for the accepting peer. The server binds a
    /// fresh local socket, sends subsequent server→client datagrams from it (so the client
    /// sees a new s2c source and follows it), and receives on it too (so once the client
    /// switches its send target the c2s frames are delivered transparently). The address
    /// crosses as a `String` to keep the trait `SocketAddr`-free / no_std-clean. Best-effort:
    /// a parse / bind failure returns `Err` and the session keeps running on the old socket.
    ///
    /// Default: returns [`CoreError::Unsupported`] — only the native UDP server
    /// (`UdpServerTransport`) implements it. Kept distinct from [`migrate`](Self::migrate)
    /// so the FFI-exported client `migrate()` cannot trigger a server migration.
    fn migrate_server(
        &self,
        _local_addr: String,
    ) -> impl core::future::Future<Output = Result<(), CoreError>> + Send {
        async {
            Err(CoreError::Unsupported(
                "this transport does not support server-side migration; use a UDP-backed session"
                    .into(),
            ))
        }
    }
}
