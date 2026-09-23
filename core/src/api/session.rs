//! Client-First Transport Session
//!
//! `PhantomSession` is the user-facing client session: `connect_with_transport`
//! returns instantly and spawns a background task that drives the hybrid
//! post-quantum handshake and then the data pump, with `send()` calls queued
//! in-memory until the handshake completes. It is the transport-level API that
//! sits directly above a `SessionTransport` byte-pipe (PhantomUDP / TCP /
//! WebSocket / WASI / Embedded / MimicTls) and below any application protocol an
//! embedder layers on top of `send()` / `recv()`.
//!
//! This file also carries the shared client/server data pump (`run_data_pump`)
//! and every per-packet build/parse helper (`send_app_data`, `handle_packet`,
//! the keep-alive / cover / window-update / path-validation senders), so any
//! change to encrypt/decrypt, framing, or stream routing happens here, in one
//! place, for both sides.
//!
//! # Receive-side memory
//!
//! An authenticated peer decides how many streams a session opens, how much it
//! sends, and how long it leaves a reassembly hole open, so what a session holds
//! on the receive side is a quantity the *other end* picks. Each of the buffers
//! it picks between has a bound, and each bound has something that enforces it:
//!
//! | bound | what it limits | enforced by |
//! | --- | --- | --- |
//! | [`MAX_STREAMS`] | concurrent receive streams | `handle_packet` refuses the stream-creating segment past the cap; unrecorded, so it is not SACKed either |
//! | [`MAX_RECV_FRAME`] | one inbound frame, hence one queued item | the pump's reader drops the frame before decrypting it |
//! | [`MAX_RECV_REORDER`](crate::transport::stream::MAX_RECV_REORDER) entries and `Stream::recv_reorder_byte_limit` | one stream's out-of-order backlog | `Stream::accept_in_order` refuses the segment; the sender retransmits |
//! | [`SESSION_RECV_WINDOW_GROWTH_BUDGET`](crate::transport::stream::SESSION_RECV_WINDOW_GROWTH_BUDGET) | window growth across all streams of a session | `SharedRecvTuning` hands growth out of one allowance |
//! | [`RECV_DELIVERY_HARD_CAP`] + [`MAX_DELIVERY_CHARGE_PER_FRAME`] | the session's delivery backlog | the reader tears the session down; the second term is the frame that crossed the line |
//! | [`STREAM_RECV_CHANNEL_DEPTH`], [`RAW_APP_RECV_CHANNEL_DEPTH`] | one delivered-stream queue | the channel is bounded; the delivery task blocks rather than growing it |
//! | a minimum time separation between retained entries | each of the session's two sliding estimator filters | `crate::transport::bandwidth_estimator`, which admits any sample that moves the reading and thins only its successors |
//!
//! The last row is in a different chain from the others: its input is the peer's
//! *acknowledgements*, not its data, so the reasoning that bounds a receive
//! buffer never reaches it. It is here because that is exactly how it came to be
//! unbounded.
//!
//! One number that looks like it belongs in that table is **observed rather than
//! enforced**, and reading it as a bound is the mistake this section exists to
//! prevent: the advertised receive window. It is a promise about what this side
//! will admit, not an allocation and not a gate — nothing on the receive path
//! refuses in-order data for exceeding it — so it constrains a compliant sender
//! and no one else.
//!
//! Three of the rows above are also qualified, and the qualifications matter.
//! The reorder bounds cover the *out-of-order* arm only; a segment arriving in
//! order is released straight to the delivery path and never enters the reorder
//! buffer. The delivery cap is crossed before it is noticed, which is why its
//! row carries a second term. And the per-stream channels are bounded in slots
//! intrinsically but in *bytes* only because [`MAX_RECV_FRAME`] bounds what a
//! slot can hold — remove that gate and the same channel holds whatever the byte
//! pipe carries, which is how the figure published for them came to be understated
//! by three orders of magnitude.
//!
//! **There is deliberately no published per-session total.** Adding the rows up
//! produces a number that reads as a bound and is not one: the sum covers the
//! buffers this module owns and not the ones underneath it — the transport's own
//! receive accumulator, PhantomUDP's fragment reassembly
//! (`MAX_CONCURRENT_ASSEMBLIES × MAX_REASSEMBLED_LEN` per session), the `Stream`
//! structures themselves — and each attempt to state such a total has been
//! corrected upward by a term it had left out. Size a host from measurement
//! under the traffic it will actually carry, use the rows above to reason about
//! what a hostile peer can move, and treat any single figure claiming to cover
//! the receive path as an estimate.
//!
//! **Every row is a bound on one session**, and that is the last thing to carry
//! away from here. Nothing divides any of them between concurrent sessions, so
//! what a process commits is its admission cap times each row. For the growth
//! allowance — the one row whose per-session figure is a single constant, which
//! makes the product a bound rather than an estimate — that is
//! `1024 × 8 MiB` = 8 GiB at the reference server's default
//! `PHANTOM_MAX_SESSIONS`, before any other row is counted. Admission control is
//! therefore what bounds a process and it belongs to the embedder;
//! `phantom-server` prints that product at startup.
//!
//! It is **a floor on what the host must have, not a ceiling on what the process
//! will use**: window growth is one term of the table above and among the
//! smallest, and it is an advertisement rather than a residency — the bytes it
//! admits come to rest in the reorder buffers and the delivery queues, which are
//! separately bounded and individually larger. `phantom-server` deliberately
//! offers no flag that divides a memory budget by it;
//! `docs/operations/deployment.md` records why, twice over.
//!
//! One thing the allowance does **not** rest on is the application's
//! cooperation. Growth is credited by the delivery task as it hands a frame to
//! the bounded queue behind `recv()` — one queue ahead of the application
//! reading it — and a peer opens as many streams, hence as many queues, as it
//! likes. A peer facing an application that never reads therefore still reaches
//! the allowance; the allowance is what stops it.

use crate::crypto::hybrid_sign::HybridVerifyingKey;
use crate::errors::CoreError;
use crate::observability::attrs::{
    AeadAlgorithm, Direction, HandshakeOutcome, PathValidationOutcome, ProtocolVersion,
    ReplayReason,
};
use crate::observability::{Observability, ObservabilityConfig};
use crate::runtime::{Runtime, TokioRuntime};
use crate::transport::bandwidth_estimator::DrainOutcome;
use crate::transport::handshake::{HandshakeClient, ServerReject, ServerReply, EARLY_DATA_MAX_LEN};
use crate::transport::mtu::{MAX_RECV_FRAME, MAX_RECV_PAYLOAD};
use crate::transport::multiplexer::StreamDemultiplexer;
use crate::transport::packet_coalescer_codec::unwrap_coalesced_packet;
use crate::transport::path_validation_codec::build_path_validation_packet;
use crate::transport::session::{Session, SessionState};
use crate::transport::shaping::{self, PaddingPolicy};
use crate::transport::stream::{SendBlocked, SharedRecvTuning, Stream};
use crate::transport::types::{
    ControlSubtype, LegType, PacketFlags, PacketHeader, PhantomPacket, SessionId,
    StreamId as TransportStreamId, CONTROL_SUBTYPE_LEN, WINDOW_UPDATE_PAYLOAD_LEN, WIRE_VERSION,
};
use bytes::Bytes;
use dashmap::DashMap;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicI64, AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot, watch, Mutex};

/// Marker type for a [`SessionBuilder`] that has not yet been given a transport.
///
/// The builder's `.transport(t)` method consumes a `SessionBuilder<NoTransport>`
/// and produces a `SessionBuilder<T>` where `T: SessionTransport`. Only
/// `SessionBuilder<T: SessionTransport>` exposes `.connect()`, so the type
/// system prevents calling connect without a transport.
pub struct NoTransport;

/// Generate a fresh 128-bit session identifier from the OS CSPRNG.
///
/// This is a non-secret display/handle identifier, not key material; 128 bits
/// is enough to avoid birthday collisions at scale. Sourced from the crate's
/// `RngProvider` seam (`crate::crypto::rng::OsRng`, backed by `getrandom`) so
/// the codebase carries no direct production `rand` dependency.
fn new_session_id() -> String {
    use crate::crypto::rng::RngProvider;
    let mut bytes = [0u8; 16];
    crate::crypto::rng::OsRng.fill_bytes(&mut bytes);
    format!("phantom-{}", hex::encode(bytes))
}

// ─── Connection State ───────────────────────────────────────────────────────

/// Connection state for `PhantomSession`.
///
/// The session is usable from the moment it's created — sends are queued
/// until the handshake completes.
///
/// The discriminants are not contiguous: `1..=3` are retired numbers that once
/// stood for a staged classical-then-PQC upgrade the protocol never shipped —
/// the hybrid handshake is a single flight, so there is no intermediate
/// classical-only state to be in. They are left as holes rather than reused so a
/// number captured in an old log cannot come back meaning something else.
#[cfg_attr(feature = "bindings", derive(uniffi::Enum))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[non_exhaustive]
pub enum ConnectionState {
    /// Connection initiated, handshake pending
    Connecting = 0,
    /// Fully connected and operational
    Connected = 4,
    /// Connection failed
    Failed = 5,
    /// Gracefully closed
    Closed = 6,
    /// The active path went silent (liveness lost); the session is held alive
    /// (keys retained, outbound buffered) awaiting a `migrate()` or the path's
    /// return. The embedder reacts by calling `migrate()` (Phase 4 / P4.3).
    Migrating = 7,
    /// The session is dead: its peer stopped answering and the session gave up on
    /// it. Terminal — `recv()` errors instead of hanging.
    ///
    /// Two things reach it. The path stayed down past the migration idle-timeout with
    /// no recovery; or a stream transport gave up on a peer that stopped reading its
    /// socket: a write went the transport's write deadline without the socket taking a
    /// byte — on TCP and the TLS-mimicry leg thirty seconds, unless
    /// [`PhantomConfig::write_stall_timeout`](crate::config::PhantomConfig::write_stall_timeout)
    /// says otherwise — after which the transport writes nothing more. Either way
    /// `last_error()`, `recv()` and `send()` report [`CoreError::Timeout`]. A session
    /// closed with `disconnect()` while such a write was stuck ends here too, rather
    /// than in [`Closed`](Self::Closed), because the close never reached the peer.
    Dead = 8,
    /// The peer announced its own close (WIRE v8) and this side is reading out
    /// whatever was still in flight behind it before letting go.
    ///
    /// Reading continues; **writing does not**. The peer's session is over, so a
    /// payload accepted here would be one the pump discards, and the whole point of
    /// publishing this state is that no caller is told otherwise:
    /// [`PhantomSession::send`], [`PhantomStream::send_reliable`],
    /// [`PhantomStream::send_unreliable`] and [`PhantomStream::disconnect`] all
    /// refuse with [`CoreError::ConnectionClosed`] rather than returning `Ok` for
    /// bytes that will never reach the wire, `is_data_ready()` is `false`, and
    /// `queued_count()` stays `0` because a refused write is refused rather than
    /// queued. It is not a failure: nothing went wrong, so `last_error()` stays
    /// `None` unless something else already failed.
    ///
    /// The window is bounded and short — see `peer_close_drain_window` — after which
    /// the session settles into [`Closed`](Self::Closed).
    ///
    /// [`PhantomStream`]: crate::api::stream::PhantomStream
    /// [`PhantomStream::send_reliable`]: crate::api::stream::PhantomStream::send_reliable
    /// [`PhantomStream::send_unreliable`]: crate::api::stream::PhantomStream::send_unreliable
    /// [`PhantomStream::disconnect`]: crate::api::stream::PhantomStream::disconnect
    Draining = 9,
}

/// Anti-fingerprint traffic-shaping configuration (WIRE v6). Set on
/// an established session via [`PhantomSession::set_traffic_shaping`]. **All
/// shaping is opt-in** — the default (and the field defaults here) is no shaping,
/// so a session pays nothing unless an embedder enables it.
///
/// Carries all three knobs: the size-padding policy, the send-timing jitter
/// ceiling and the cover-traffic interval, each documented on its own field
/// below and each wired to the send path.
///
/// Padding hides the datagram *size* at a bounded cost (≈ ≤12% worst case);
/// jitter hides the *timing* at a cost of up to its own ceiling in latency;
/// cover traffic hides the *presence* of application data at the cost of the
/// bandwidth it spends.
#[cfg_attr(feature = "bindings", derive(uniffi::Record))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TrafficShapingConfig {
    /// Size-padding policy. [`PaddingPolicy::None`] (default) = no padding;
    /// [`PaddingPolicy::Padme`] = pad each packet up to a PADÉ bucket.
    pub padding: PaddingPolicy,
    /// Send-timing jitter ceiling in milliseconds. `0` (default)
    /// = no jitter; otherwise each packet waits a uniform random `[0, jitter_ms]`
    /// ms before it is sent, so the inter-packet timing no longer tracks the
    /// application's writes — at a cost of up to `jitter_ms` of added latency.
    pub jitter_ms: u32,
    /// Cover-traffic floor interval in milliseconds. `0`
    /// (default) = no cover traffic; otherwise the session maintains a minimum
    /// outbound packet rate of `1000 / cover_interval_ms` packets/sec, emitting an
    /// encrypted dummy (`COVER`) packet whenever no packet has gone out for
    /// `cover_interval_ms` — hiding idle/active patterns and volume, at a steady
    /// bandwidth cost. A typical value is 100–500 ms (10–2 packets/sec).
    pub cover_interval_ms: u32,
}

/// Apply a [`TrafficShapingConfig`] to an established [`Session`]. Shared by
/// the immediate (`set_traffic_shaping` on a live session) and the deferred
/// (background-task, at session install) paths.
fn apply_shaping(session: &Session, cfg: TrafficShapingConfig) {
    session.set_padding_policy(cfg.padding);
    session.set_jitter_ms(cfg.jitter_ms);
    session.set_cover_interval_ms(cfg.cover_interval_ms);
}

impl ConnectionState {
    /// Read a state back out of the atomic the pump publishes it into. `pub(crate)`
    /// because the stream handles read the same atomic to answer the same question
    /// their session does.
    pub(crate) fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::Connecting,
            4 => Self::Connected,
            5 => Self::Failed,
            6 => Self::Closed,
            7 => Self::Migrating,
            8 => Self::Dead,
            9 => Self::Draining,
            // Includes the retired 1..=3: a value nothing writes any more is not
            // a state, and `Failed` is the safe reading of a number we cannot
            // interpret — it makes the session unusable rather than pretending
            // data can flow.
            _ => Self::Failed,
        }
    }

    /// Whether data can flow. `Migrating` counts as ready: the keep-alive window
    /// still accepts `send()` (buffered + retransmitted until the path recovers),
    /// so the embedder's send path doesn't error mid-migration.
    ///
    /// [`Draining`](Self::Draining) does **not**, and the distinction between it and
    /// `Migrating` is the whole reason it is a separate state. Both keep reading;
    /// only one of them still has somewhere to put a write. A migrating session's
    /// peer is still there and its buffered bytes go out when the path returns; a
    /// draining session's peer has said it is gone, so a byte accepted here is a
    /// byte discarded at teardown.
    pub fn is_data_ready(&self) -> bool {
        matches!(self, Self::Connected | Self::Migrating)
    }
}

// ─── Resumption Hint ────────────────────────────────────────────────────────

/// 0-RTT resumption material extracted from a completed session.
///
/// Produced by [`PhantomSession::resumption_hint`] after a handshake completes,
/// and fed back into [`connect_pinned_with_resumption`] (or
/// [`PhantomSession::builder`] + `.resumption()`) to attempt a 0-RTT reconnect
/// to the same server.
///
/// # Why this is an object and not a record
///
/// UniFFI lowers a record into a plain struct in each target language and
/// generates that language's own stringifier for it. The Python one formats
/// every field, so `print(hint)`, an f-string or `logging.info("%s", hint)`
/// wrote the 32-byte resumption secret out in full — and the redacting Rust
/// [`Debug`] below never prevented that, because UniFFI does not call it. An
/// object crosses the FFI as an opaque handle instead: the generated classes
/// carry no field-dumping `__str__` / `toString()` / `description`, and the
/// bytes leave only through [`session_id`](Self::session_id) and
/// [`resumption_secret`](Self::resumption_secret), where the caller asked for
/// them by name. That removes the leak rather than documenting it.
///
/// Both byte strings are exactly 32 bytes. The length is checked where the hint
/// is *used* — the `connect_pinned_*_with_resumption` free functions and the
/// builder's `.resumption()`, each before any I/O — and deliberately not in the
/// constructor, so a stored blob of the wrong size surfaces as a clean
/// `CoreError::ValidationError` on the connect path rather than as a failure a
/// persistence layer has to handle on load.
///
/// Store the hint alongside the pinned `HybridVerifyingKey` of the server it
/// was negotiated against: the resumption secret is server-pinned, and reusing
/// a hint across servers is a configuration bug.
#[cfg_attr(feature = "bindings", derive(uniffi::Object))]
pub struct ResumptionHint {
    session_id: Vec<u8>,
    resumption_secret: Vec<u8>,
}

// The exported surface. `uniffi::export` exports **every** method of the block,
// so nothing may be added here that should stay Rust-only — the borrowing
// accessors live in the second, unannotated `impl` below, the same discipline
// `PhantomSession` uses. **Do not add `Debug` or `Display` to this block:**
// UniFFI generates `__str__` / `__repr__` from exactly those traits, so
// exporting either puts back the leak this type became an object to remove.
#[cfg_attr(feature = "bindings", uniffi::export)]
impl ResumptionHint {
    /// Construct a hint from stored bytes.
    ///
    /// The name `new` is load-bearing. UniFFI treats a constructor called `new`
    /// as the *primary* one, and only a primary constructor becomes a plain
    /// Python `__init__`, a Swift `init(sessionId:resumptionSecret:)` and a
    /// Kotlin primary constructor rather than a static factory. Renaming it
    /// would silently change the call shape in all three languages.
    ///
    /// Returns `Arc<Self>` so a Rust caller keeps the previous one-liner: the
    /// entry points take `Arc<ResumptionHint>`, so `ResumptionHint::new(sid,
    /// secret)` still drops straight into the call with no wrapper.
    #[cfg_attr(feature = "bindings", uniffi::constructor)]
    pub fn new(session_id: Vec<u8>, resumption_secret: Vec<u8>) -> Arc<Self> {
        Arc::new(Self {
            session_id,
            resumption_secret,
        })
    }

    /// The negotiated session id (32 bytes).
    ///
    /// Not secret on its own — a resuming `ClientHello` carries it in the clear
    /// as `resume_session_id` — and useless without the secret below, which is
    /// what a resuming handshake actually proves possession of.
    pub fn session_id(&self) -> Vec<u8> {
        self.session_id.clone()
    }

    /// The resumption secret (32 bytes) — sensitive; treat it like a key.
    ///
    /// **Never log this value.** It is the proof-of-possession input a resuming
    /// handshake proves it holds (Security Invariant 9), so a copy in a log is
    /// a credential in a log. The warning sits on the accessor because that is
    /// what reaches every language: UniFFI copies a method's documentation into
    /// all four bindings, where it carries no record field's.
    ///
    /// Persist it the way a private key is persisted — the iOS sample uses the
    /// Keychain, the Android one `EncryptedSharedPreferences`.
    pub fn resumption_secret(&self) -> Vec<u8> {
        self.resumption_secret.clone()
    }
}

// Rust-only borrowing accessors, deliberately in a second, unannotated `impl`
// so they stay off the bindings. The exported pair above returns owned copies
// because that is what crosses an FFI boundary; the in-crate validation paths
// read the bytes once and would otherwise clone 32 bytes twice per connect for
// nothing.
impl ResumptionHint {
    pub(crate) fn session_id_ref(&self) -> &[u8] {
        &self.session_id
    }

    pub(crate) fn resumption_secret_ref(&self) -> &[u8] {
        &self.resumption_secret
    }
}

// INFOLEAK-1: hand-written redacting `Debug` (not derived), so a **Rust**
// caller that logs the hint with `{:?}` cannot leak the 0-RTT resumption
// secret. Mirrors the REDACTED `Debug` on `HybridSigningKey` /
// `HybridSecretKey`.
//
// It protects Rust callers and nothing else — UniFFI does not call it — and it
// is deliberately not in the exported block above, because exporting `Debug` is
// precisely how UniFFI is asked to generate a field-printing `__str__`. The
// foreign-language half of this problem is solved by the type being an object.
impl std::fmt::Debug for ResumptionHint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResumptionHint")
            .field(
                "session_id",
                &format_args!("<{} bytes>", self.session_id.len()),
            )
            .field("resumption_secret", &"REDACTED")
            .finish()
    }
}

// ─── Transport Abstraction ──────────────────────────────────────────────────

// `SessionTransport` now lives in `crate::transport::session_transport` — a
// dependency-light module that can compile in a `no_std + alloc` build. It is
// re-exported here so `crate::api::session::SessionTransport` and the public
// `phantom_protocol::api::SessionTransport` path stay stable.
pub use crate::transport::session_transport::{FramePhase, SessionTransport};

/// Transport decorator that records `record_send` / `record_recv` on the
/// session's [`Observability`] for every frame that crosses the wire — so the
/// data-plane packet/byte counters reflect a real run without threading the
/// handle through every send site. Wraps the concrete `SessionTransport` just
/// before the data pump takes over, so handshake bytes are not counted as
/// data-plane packets (they have their own handshake metric).
///
/// It is also where the pump learns that the transport has given up on the peer.
/// A [`CoreError::Timeout`] from either I/O method means exactly that (see
/// [`SessionTransport::send_bytes`]), and it is noticed here because this is the
/// one place every write and every read passes through: the write that gives up
/// is usually one of the pump's own, deep inside a helper that reports failure as
/// a `bool`, while the task that has to hear about it is the receive loop, parked
/// in a read the peer may never answer. From then on nothing more is written —
/// the transport may have left a frame cut part-way through — and
/// [`given_up`](Self::given_up) resolves, which is what ends that loop.
struct ObservedTransport<T> {
    inner: T,
    observability: Arc<Observability>,
    leg: LegType,
    /// Set once the transport has reported [`CoreError::Timeout`]; never cleared.
    gave_up: std::sync::atomic::AtomicBool,
    /// Wakes whoever is waiting in [`given_up`](Self::given_up).
    gave_up_notify: tokio::sync::Notify,
}

impl<T> ObservedTransport<T> {
    fn new(inner: T, observability: Arc<Observability>, leg: LegType) -> Self {
        Self {
            inner,
            observability,
            leg,
            gave_up: std::sync::atomic::AtomicBool::new(false),
            gave_up_notify: tokio::sync::Notify::new(),
        }
    }

    /// Record that the transport has given up on the peer, and wake the waiter.
    fn give_up(&self) {
        if !self.gave_up.swap(true, Ordering::AcqRel) {
            self.gave_up_notify.notify_waiters();
        }
    }

    /// Whether the transport has given up on the peer.
    fn has_given_up(&self) -> bool {
        self.gave_up.load(Ordering::Acquire)
    }

    /// Resolves once the transport has given up on the peer.
    ///
    /// Meant to be created once and polled across a whole loop rather than once per
    /// iteration, so the waiter is registered a single time. It registers before it
    /// looks at the flag, so a give-up landing between the two is still seen.
    async fn given_up(&self) {
        let notified = self.gave_up_notify.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        if self.has_given_up() {
            return;
        }
        notified.await;
    }
}

impl<T: SessionTransport> SessionTransport for ObservedTransport<T> {
    async fn send_bytes(&self, data: &[u8]) -> Result<(), CoreError> {
        if self.has_given_up() {
            return Err(CoreError::Timeout);
        }
        let result = self.inner.send_bytes(data).await;
        match result {
            Ok(()) => self.observability.record_send(data.len(), self.leg),
            Err(CoreError::Timeout) => self.give_up(),
            Err(_) => {}
        }
        result
    }

    async fn recv_bytes(&self) -> Result<Bytes, CoreError> {
        let result = self.inner.recv_bytes().await;
        match result {
            Ok(ref bytes) => self.observability.record_recv(bytes.len(), self.leg),
            Err(CoreError::Timeout) => self.give_up(),
            Err(_) => {}
        }
        result
    }

    // ── Transparent forwarding of the non-I/O trait surface ───────────────────
    //
    // ObservedTransport wraps the concrete transport for the whole data pump, so
    // every control method the pump calls on it (phase, CID stamping, migration)
    // MUST reach the inner transport — otherwise they silently hit the trait's
    // defaults (no-op / `false`) and the feature is dead through the pump. (The
    // pre-ε code only forwarded send/recv, so the FFI `migrate()` and the
    // server-side migration detection were no-ops once wrapped; ε needs them live
    // to rotate the CID on migration, so the wrapper is made fully transparent.)
    fn supports_migration(&self) -> bool {
        self.inner.supports_migration()
    }

    fn set_frame_phase(&self, phase: FramePhase) {
        self.inner.set_frame_phase(phase);
    }

    fn set_outbound_cid(&self, cid: [u8; 8]) {
        self.inner.set_outbound_cid(cid);
    }

    fn has_migration_candidate(&self) -> bool {
        self.inner.has_migration_candidate()
    }

    fn send_to_candidate(
        &self,
        data: &[u8],
    ) -> impl core::future::Future<Output = Result<bool, CoreError>> + Send {
        self.inner.send_to_candidate(data)
    }

    fn confirm_authenticated_source(&self) {
        self.inner.confirm_authenticated_source();
    }

    fn promote_candidate(&self) -> bool {
        self.inner.promote_candidate()
    }

    fn migrate(
        &self,
        local_addr: String,
    ) -> impl core::future::Future<Output = Result<(), CoreError>> + Send {
        self.inner.migrate(local_addr)
    }

    fn migrate_server(
        &self,
        local_addr: String,
    ) -> impl core::future::Future<Output = Result<(), CoreError>> + Send {
        self.inner.migrate_server(local_addr)
    }
}

// ─── Session ────────────────────────────────────────────────────────────────

/// Client-first session — instant construction, non-blocking `send()`.
///
/// # Design
///
/// The real entry point is `connect_with_transport` (NOT the inert legacy
/// `connect()` constructor — see its doc): it returns instantly and runs the
/// handshake + data pump in the background, so sends issued before the handshake
/// finishes are buffered and auto-flushed once the channel is up.
///
/// ```text
///   // instant — spawns the background handshake + pump:
///   let session = PhantomSession::connect_with_transport(addr, transport, pinned_key);
///   session.send(data).await;   // queued until handshake completes
///   session.send(data2).await;  // also queued
///   // ... handshake completes in background ...
///   // queued data auto-flushed, new sends go directly
/// ```
///
/// The session progresses through states:
/// `Connecting → Connected → Migrating → Dead`, with `Failed` reachable from
/// `Connecting` (handshake rejection, a wrong pin) and `Closed` from
/// `disconnect()`. `Migrating` is entered when the path goes silent and left
/// again for `Connected` if it recovers; sends keep buffering throughout.
/// [`Draining`](ConnectionState::Draining) is the one state that buffers
/// nothing: it means the *peer* announced its close, so reads continue while
/// writes are refused rather than queued for a wire they will never reach.
/// There is no intermediate classical-only state — the hybrid handshake is one
/// flight, so the session is either unkeyed or fully post-quantum keyed.
///
/// # Example
///
/// ```rust,no_run
/// # #[tokio::main]
/// # async fn main() -> Result<(), phantom_protocol::CoreError> {
/// use std::sync::Arc;
/// use phantom_protocol::api::{PhantomUdpListener, PhantomSession};
///
/// // Start a UDP server (production path — supports migrate())
/// let listener = PhantomUdpListener::builder("127.0.0.1:0").bind().await?;
/// let server_addr = listener.local_addr();
/// let pinned_key = listener.verifying_key_bytes();
///
/// // Accept in the background
/// let listener = Arc::clone(&listener);
/// tokio::spawn(async move {
///     let outcome = listener.accept().await?;
///     let session = outcome.session();
///     let _req = session.recv().await?;
///     session.send(b"hello, post-quantum world".to_vec()).await?;
///     Ok::<_, phantom_protocol::CoreError>(())
/// });
///
/// // Connect a UDP client
/// let port: u16 = server_addr.parse::<std::net::SocketAddr>().unwrap().port();
/// let session = phantom_protocol::connect_pinned_udp(
///     "127.0.0.1".into(), port, pinned_key,
/// ).await?;
/// session.await_ready().await?;
/// session.send(b"ping".to_vec()).await?;
/// let _reply = session.recv().await?;
/// # Ok(())
/// # }
/// ```
#[cfg_attr(feature = "bindings", derive(uniffi::Object))]
pub struct PhantomSession {
    /// Session identifier
    id: String,
    /// Target server address
    peer_addr: String,
    /// Connection state (atomic for lock-free reads)
    state: Arc<AtomicU8>,
    /// Queued messages before connection is ready
    send_queue: Arc<Mutex<Vec<Vec<u8>>>>,
    /// Channel to send commands to the background handshake task
    cmd_tx: mpsc::Sender<SessionCommand>,
    /// Raised by [`disconnect`](Self::disconnect) and by dropping the handle, to ask the
    /// pump to close the session.
    ///
    /// A signal of its own rather than a command queued behind the application's writes.
    /// The pump stops reading its command channel while it holds a write the send buffer
    /// refused, and it holds one until the peer acknowledges data that the peer's own
    /// window may forbid sending — so a close queued in that channel was a close a peer
    /// that stopped reading could postpone for as long as it liked, and a caller waiting
    /// for room in the channel waited with it. Raising this never waits, and the pump
    /// reads it whatever else it is holding.
    close_request: watch::Sender<bool>,
    /// Control that writes nothing — [`migrate`](Self::migrate), `migrate_server()` and
    /// every stream's `set_priority()` — on a channel the pump never stops reading, for the
    /// same reason the close has a signal of its own. See `ControlCommand`.
    control_tx: mpsc::Sender<ControlCommand>,
    /// Where a dropped [`PhantomStream`](crate::api::stream::PhantomStream) tells the pump
    /// that it is gone. See `StreamLink::released`.
    released_tx: mpsc::UnboundedSender<u32>,
    /// Command receiver — taken by the background task when spawned
    #[allow(dead_code)]
    cmd_rx: Mutex<Option<mpsc::Receiver<SessionCommand>>>,
    /// Received messages channel. Carries `Bytes` (not `Vec<u8>`) so the recv
    /// path can fan out via cheap refcount clones to both the stream demux
    /// and the synchronous `recv()` consumer without deep-copying the payload.
    recv_rx: Mutex<mpsc::Receiver<Bytes>>,
    /// Multiplexes incoming packets to independent streams
    demux: Arc<StreamDemultiplexer>,
    /// Active outgoing streams (ARQ management)
    streams: Arc<DashMap<u32, Arc<Stream>>>,
    /// Negotiated session handle, populated by the background task
    /// once the handshake completes. Exposed via `resumption_hint`
    /// for Phase 4.1 0-RTT clients. `None` while still handshaking
    /// or after a failure.
    inner_session: Arc<Mutex<Option<Arc<Session>>>>,
    /// 0-RTT verdict. `None` while handshaking, after a failure, or when the
    /// client sent no early-data on this connect. `Some(true)` — the server
    /// consumed the early-data; `Some(false)` — the client sent early-data and
    /// the server rejected it. Exposed via `early_data_accepted()`.
    early_data_accepted: Arc<Mutex<Option<bool>>>,
    /// Anti-fingerprint traffic-shaping config. Set via `set_traffic_shaping`
    /// at any time — **including before the (async) client handshake completes** —
    /// and applied to the negotiated `Session` the moment it is installed by the
    /// background task, so the very first data packets are already shaped. A
    /// `parking_lot::Mutex` (no poison, never held across an `.await`). Default:
    /// no shaping.
    shaping: Arc<parking_lot::Mutex<TrafficShapingConfig>>,
    /// Session observability handle. Server-accepted sessions share the
    /// `PhantomListener`'s instance (so its `snapshot()` aggregates every
    /// session it accepted); client sessions get their own. The data pump
    /// records send/recv, the security drops, and the session lifecycle
    /// (open/close) against it. A ZST no-op when `telemetry-otel` is off.
    observability: Arc<Observability>,
    /// Receive channel for peer-initiated streams (`accept_stream()`).
    ///
    /// When the remote peer opens a new stream (stream id ≥ 2 that the pump
    /// has not seen before), the recv task registers it in the demux, wraps it
    /// in an `Arc<PhantomStream>`, and sends it here. The embedder calls
    /// `accept_stream()` to pick it up. Bounded at 128 so a peer that opens
    /// many unaccepted streams does not grow this buffer unboundedly. A stream
    /// that finds it full is not held for an application that will never see
    /// it: its handle is dropped on the spot, which closes this side's half of
    /// it like any dropped handle, and the stream leaves the table once that
    /// close is acknowledged.
    incoming_stream_rx: Arc<Mutex<mpsc::Receiver<Arc<crate::api::stream::PhantomStream>>>>,
    /// Captured terminal error from a failed handshake. Written once by the
    /// background task on `Err(e)`, then readable via `last_error()`. Never
    /// written on the success path. `None` on a live or clean-closed session.
    ///
    /// `parking_lot::Mutex` is used so the lock is never held across an `.await`
    /// (the background task writes it once, synchronously, before changing
    /// `state` to `Failed`; readers only call `.lock().clone()`).
    terminal_error: Arc<parking_lot::Mutex<Option<CoreError>>>,
    /// Watch channel for handshake readiness. The background task publishes
    /// the terminal `ConnectionState` (as a `u8`) once the session reaches
    /// `Connected`, `Failed`, or `Dead`. `await_ready()` subscribes and
    /// blocks until the value changes from its initial `Connecting` sentinel.
    ///
    /// Using `watch` avoids the lost-notification race that `Notify` has when
    /// the signal fires before the subscriber registers — `watch` always
    /// delivers the *current* value on subscribe, so a late `await_ready()`
    /// caller immediately sees the already-resolved state.
    ///
    /// `ready_tx` is retained on the struct to keep the channel open (while
    /// senders exist `wait_for` will not prematurely error). The background
    /// task holds an `Arc<watch::Sender<u8>>` clone and publishes to it.
    #[allow(dead_code)]
    ready_tx: Arc<watch::Sender<u8>>,
    ready_rx: watch::Receiver<u8>,
    /// Whether the underlying transport supports seamless connection migration.
    /// Set at construction from [`SessionTransport::supports_migration`].
    /// `true` only when the session is backed by `UdpClientTransport` /
    /// `UdpServerTransport`; `false` for TCP, WebSocket, WASI, Embedded, and
    /// the in-memory test pipe.
    migration_capable: bool,
    /// Balanced `active_streams` gauge for this session (see [`StreamGauge`]).
    /// Shared with the data pump: `open_stream()` counts here, the pump's
    /// receive path counts peer-initiated streams, and both the pump exit and
    /// `Drop for PhantomSession` drain whatever is still open.
    stream_gauge: Arc<StreamGauge>,
    /// The connection's single receive-window growth budget (see
    /// [`crate::transport::stream::SharedRecvTuning`]), shared with the data pump.
    ///
    /// Every stream of the connection — API-opened, pump-created, or peer-initiated — is
    /// built from this one handle, which is what makes
    /// [`crate::transport::stream::SESSION_RECV_WINDOW_GROWTH_BUDGET`] an actual bound
    /// rather than an intention. It lives here rather than on the negotiated [`Session`]
    /// because `open_stream()` is reachable before the handshake completes.
    recv_tuning: Arc<SharedRecvTuning>,
}

/// Commands for the background session task that write, or that have to stay in order
/// with the writes: the application's data, and a stream's close.
///
/// This channel is read on an arm the pump disables while it holds a write a send buffer
/// refused, which is what carries backpressure back to the caller. Anything that must be
/// acted on while the session is in that state travels elsewhere: control that writes
/// nothing — a migration, a stream's priority — on a channel of its own, the drop of a
/// stream handle on another, and the session's own close on a signal of its own.
pub enum SessionCommand {
    /// Queue data for sending
    Send(Vec<u8>),
    /// Send data on a specific stream reliably
    SendStreamReliable { stream_id: u32, data: bytes::Bytes },
    /// Send data on a specific stream unreliably
    SendStreamUnreliable { stream_id: u32, data: bytes::Bytes },
    /// Close a specific stream
    CloseStream { stream_id: u32 },
    /// Close the session. Honoured when it arrives, but `disconnect()` and a dropped
    /// handle do not send it: their close travels on a signal of its own, which the
    /// pump reads even while it has stopped reading this channel.
    Close,
}

/// Commands for the background session task that write nothing, carried apart from the
/// application's writes.
///
/// The command channel is disabled while the pump holds a write a send buffer refused, and
/// nothing bounds how long it holds one: on a path that died in the middle of an upload no
/// acknowledgement arrives to free a slot. A migration requested then is what would bring
/// the acknowledgements back, so queued behind the stalled writes it waited for them while
/// they waited for it — `migrate()` blocked once the channel filled, and the session sat in
/// `Migrating` until the liveness timer declared it dead. These commands therefore have a
/// channel of their own, read on an arm nothing disables.
///
/// **What ordering holds.** Control commands are carried out in the order they were sent,
/// one at a time, and each migration is carried out whole: the rebind, then the `path_id`
/// and connection-id rotation, with no send in between. They are *not* ordered against the
/// writes on the command channel — a migration can take effect before a write issued ahead
/// of it has been admitted to its stream's send buffer. That costs nothing the migration
/// design depends on: a segment goes out on whichever path is current when it is sent, and
/// whatever was sent on the old path is retransmitted on the new one. A priority is a
/// property of the stream, applied to whatever it holds at the next drain. A local close
/// takes in the control commands queued ahead of it before it flushes, so a migration
/// requested before `disconnect()` decides which path the final flush goes out on.
pub(crate) enum ControlCommand {
    /// Migrate to a new local address (Phase 4 / P4.2 — embedder-triggered). Carries
    /// the new local bind address as a `String`; the pump rebinds the transport and
    /// bumps the send `path_id` (best-effort, never fatal to the session).
    Migrate(String),
    /// Migrate the SERVER's send path to a new local address (Rust-only, the server-side
    /// mirror of [`Migrate`](Self::Migrate)). Carries the new local bind address as a
    /// `String`; the pump rebinds the server's send socket (its receive keeps flowing on
    /// the old address via the listener demux during the overlap) and rotates the s2c send
    /// `path_id` + outbound CID in lock-step, so the client sees — and follows — a fresh
    /// server source with a fresh, unlinkable ConnId. Best-effort, never fatal.
    MigrateServer(String),
    /// Set the scheduler priority of a specific stream (higher = drained first).
    /// Takes effect on the next drain pass; no notify needed since priority only
    /// reorders an already-scheduled drain.
    SetStreamPriority { stream_id: u32, priority: u32 },
}

/// How many [`ControlCommand`]s may wait for the pump at once. The arm that reads them is
/// never disabled, so this bounds a burst from the application rather than a backlog the
/// peer can build: a caller waits for room only while the pump is inside another arm.
const CONTROL_CHANNEL_DEPTH: usize = 32;

/// What a [`PhantomStream`](crate::api::stream::PhantomStream) holds to reach the pump that
/// owns its stream.
#[derive(Clone)]
pub(crate) struct StreamLink {
    /// Writes and the stream's close, in order with the rest of the session's writes.
    pub(crate) commands: mpsc::Sender<SessionCommand>,
    /// Control that writes nothing — the stream's priority. See [`ControlCommand`].
    pub(crate) control: mpsc::Sender<ControlCommand>,
    /// Where a handle reports, as it is dropped, that it is gone.
    ///
    /// Unbounded because `Drop` can neither wait for room nor fail usefully, and a
    /// notice that did not arrive would leave the stream in the table for the life of the
    /// session. It holds at most one notice per handle, and the pump reads it on an arm
    /// nothing disables, so what waits in it is a burst of drops the pump has not reached
    /// yet rather than anything that accumulates.
    pub(crate) released: mpsc::UnboundedSender<u32>,
}

impl PhantomSession {
    /// Create a new session and start the background handshake task.
    ///
    /// Requires `expected_server_key` for MITM resistance — the client will
    /// abort the handshake unless the server presents this exact verifying key.
    /// Callers obtain this key out-of-band (e.g. from `PhantomListener::verifying_key_bytes`).
    ///
    /// The handshake runs in the background:
    /// 1. Exchange hybrid PQC `ClientHello`/`ServerHello`.
    /// 2. Verify server identity against `expected_server_key`.
    /// 3. Derive AEAD keys; flush queued sends as encrypted packets.
    ///
    /// All network I/O goes through the provided `SessionTransport`. The
    /// task that drives the handshake + data pump runs on the default
    /// [`TokioRuntime`]; use
    /// [`connect_with_transport_with_runtime`](Self::connect_with_transport_with_runtime)
    /// to substitute a different `Runtime`.
    pub fn connect_with_transport<T: SessionTransport>(
        peer_addr: &str,
        transport: T,
        expected_server_key: HybridVerifyingKey,
    ) -> Self {
        Self::connect_with_transport_with_runtime(
            peer_addr,
            transport,
            expected_server_key,
            Arc::new(TokioRuntime),
        )
    }

    /// Like [`connect_with_transport`](Self::connect_with_transport) but
    /// runs the background task on the supplied `Runtime`. Intended for
    /// WASM / embedded / test backends that don't drive `tokio::spawn`.
    pub fn connect_with_transport_with_runtime<T: SessionTransport>(
        peer_addr: &str,
        transport: T,
        expected_server_key: HybridVerifyingKey,
        runtime: Arc<dyn Runtime>,
    ) -> Self {
        Self::spawn_client(
            peer_addr,
            transport,
            expected_server_key,
            runtime,
            None,
            None,
        )
    }

    /// Create a [`SessionBuilder`] for constructing a client session.
    ///
    /// The builder collects configuration (pinned key, optional resumption hint,
    /// optional config / runtime) and then `.transport(t).connect().await` drives the
    /// handshake and returns the session. This is the ergonomic alternative to the
    /// `connect_with_transport*` family — every option (runtime, config, resumption,
    /// mimicry) is an orthogonal `SessionBuilder` setter instead of a positional
    /// argument or a `_with_*` name suffix.
    pub fn builder(addr: impl Into<String>) -> SessionBuilder {
        SessionBuilder {
            peer_addr: addr.into(),
            transport: None,
            pinned_key: None,
            resumption: None,
            config: None,
            runtime: None,
        }
    }

    /// Shared constructor body for [`connect_with_transport_with_runtime`]
    /// and the [`SessionBuilder`] `connect()` method. `resumption_request` is
    /// `None` for a plain handshake, `Some((id, secret, early_data))` to
    /// attempt a 0-RTT resumption.
    fn spawn_client<T: SessionTransport>(
        peer_addr: &str,
        transport: T,
        expected_server_key: HybridVerifyingKey,
        runtime: Arc<dyn Runtime>,
        resumption_request: Option<([u8; 32], [u8; 32], Vec<u8>)>,
        liveness: Option<crate::transport::liveness::LivenessConfig>,
    ) -> Self {
        let (cmd_tx, cmd_rx) = mpsc::channel(256);
        let (close_request, close_requested) = watch::channel(false);
        let (control_tx, control_rx) = mpsc::channel(CONTROL_CHANNEL_DEPTH);
        let (released_tx, released_rx) = mpsc::unbounded_channel();
        let (recv_tx, recv_rx) = mpsc::channel(RAW_APP_RECV_CHANNEL_DEPTH);
        // Channel for peer-initiated streams exposed via accept_stream().
        let (incoming_stream_tx, incoming_stream_rx) = mpsc::channel(128);

        let state = Arc::new(AtomicU8::new(ConnectionState::Connecting as u8));
        let send_queue = Arc::new(Mutex::new(Vec::new()));
        let peer = peer_addr.to_string();
        // Client allocates odd stream ids (3, 5, 7, …) — QUIC-style role split so
        // concurrent open_stream() on both ends never collides.
        let (demux, _ctrl_rx) = StreamDemultiplexer::new_with_role(256, true);
        let demux = Arc::new(demux);

        let streams = Arc::new(DashMap::new());
        let inner_session: Arc<Mutex<Option<Arc<Session>>>> = Arc::new(Mutex::new(None));
        let early_data_accepted: Arc<Mutex<Option<bool>>> = Arc::new(Mutex::new(None));
        // Shared pending traffic-shaping config, applied at session install.
        let shaping = Arc::new(parking_lot::Mutex::new(TrafficShapingConfig::default()));
        // Client sessions have no listener, so they own their observability
        // instance (its `snapshot()` reflects just this connection).
        let observability = Observability::new(ObservabilityConfig::default());
        // Balanced active-streams gauge, shared with the pump (see StreamGauge).
        let stream_gauge = StreamGauge::new(observability.clone());
        // One receive-window growth budget for the whole connection. It is created here
        // rather than on the negotiated `Session`, which does not exist yet: `open_stream()`
        // is reachable before the handshake completes, and a stream built with a budget of
        // its own would sit outside the session-wide bound for as long as it lived.
        let recv_tuning = Arc::new(SharedRecvTuning::default());

        // Terminal-error capture + readiness signal.
        let terminal_error: Arc<parking_lot::Mutex<Option<CoreError>>> =
            Arc::new(parking_lot::Mutex::new(None));
        // watch channel starts at `Connecting` (== 0); background_task publishes
        // the resolved state once the handshake succeeds (Connected) or fails
        // (Failed / Dead). `await_ready()` subscribes on the Receiver.
        let (ready_tx, ready_rx) = watch::channel(ConnectionState::Connecting as u8);
        let ready_tx = Arc::new(ready_tx);

        // Query before moving `transport` into the background task.
        let migration_capable = transport.supports_migration();

        let recv_tuning_for_pump = recv_tuning.clone();
        let session = Self {
            id: new_session_id(),
            peer_addr: peer.clone(),
            state: state.clone(),
            send_queue: send_queue.clone(),
            cmd_tx: cmd_tx.clone(),
            close_request,
            control_tx: control_tx.clone(),
            released_tx: released_tx.clone(),
            cmd_rx: Mutex::new(None), // taken by background task
            recv_rx: Mutex::new(recv_rx),
            demux: demux.clone(),
            streams: streams.clone(),
            inner_session: inner_session.clone(),
            early_data_accepted: early_data_accepted.clone(),
            shaping: shaping.clone(),
            observability: observability.clone(),
            incoming_stream_rx: Arc::new(Mutex::new(incoming_stream_rx)),
            terminal_error: terminal_error.clone(),
            ready_tx: ready_tx.clone(),
            ready_rx,
            migration_capable,
            stream_gauge: stream_gauge.clone(),
            recv_tuning: recv_tuning.clone(),
        };

        // Spawn the background handshake + data pump task on the supplied
        // runtime. `SpawnHandle` is detached: dropping it leaves the task
        // running. The session is owned by the caller for its lifetime
        // and natural shutdown comes via the close request that
        // `disconnect()` and dropping the handle raise.
        let runtime_for_pump = runtime.clone();
        let _detached = runtime.spawn(Box::pin(Self::background_task(
            state,
            send_queue,
            cmd_tx.clone(),
            cmd_rx,
            close_requested,
            control_rx,
            released_rx,
            recv_tx,
            transport,
            peer,
            demux,
            streams,
            expected_server_key,
            runtime_for_pump,
            inner_session,
            early_data_accepted,
            shaping,
            resumption_request,
            observability,
            liveness,
            StreamLink {
                commands: cmd_tx,
                control: control_tx,
                released: released_tx,
            },
            incoming_stream_tx,
            terminal_error,
            ready_tx,
            migration_capable,
            stream_gauge,
            recv_tuning_for_pump,
        )));

        session
    }

    /// Install a server-side `Session` (already derived by `HandshakeServer::process_client_hello`)
    /// and spawn the data pump on the default [`TokioRuntime`]. Used by
    /// `PhantomListener::accept` after driving the server handshake.
    ///
    /// `PhantomListener::accept` itself now uses
    /// `from_accepted_server_session_with_runtime` so the listener's
    /// runtime is honored. This wrapper is preserved for callers that
    /// do not have a runtime handle and want the default `TokioRuntime`.
    #[allow(dead_code)]
    pub(crate) fn from_accepted_server_session<T: SessionTransport>(
        peer_addr: String,
        transport: T,
        server_session: Arc<Session>,
    ) -> Arc<Self> {
        Self::from_accepted_server_session_with_runtime(
            peer_addr,
            transport,
            server_session,
            Arc::new(TokioRuntime),
            Observability::new(ObservabilityConfig::default()),
            LegType::Tcp,
        )
    }

    /// Runtime-aware variant of [`from_accepted_server_session`].
    pub(crate) fn from_accepted_server_session_with_runtime<T: SessionTransport>(
        peer_addr: String,
        transport: T,
        server_session: Arc<Session>,
        runtime: Arc<dyn Runtime>,
        observability: Arc<Observability>,
        leg: LegType,
    ) -> Arc<Self> {
        let (cmd_tx, cmd_rx) = mpsc::channel(256);
        let (close_request, close_requested) = watch::channel(false);
        let (control_tx, control_rx) = mpsc::channel(CONTROL_CHANNEL_DEPTH);
        let (released_tx, released_rx) = mpsc::unbounded_channel();
        let (recv_tx, recv_rx) = mpsc::channel(RAW_APP_RECV_CHANNEL_DEPTH);
        // Channel for peer-initiated streams exposed via accept_stream().
        let (incoming_stream_tx, incoming_stream_rx) = mpsc::channel(128);

        let state = Arc::new(AtomicU8::new(ConnectionState::Connected as u8));
        // Shared with the pump below rather than created inside the session
        // literal: an accepted session never runs a client handshake, but it can
        // still be reaped by the liveness timer, and that is a cause the handle
        // has to be able to report.
        let terminal_error: Arc<parking_lot::Mutex<Option<CoreError>>> =
            Arc::new(parking_lot::Mutex::new(None));
        let send_queue = Arc::new(Mutex::new(Vec::new()));
        // Server allocates even stream ids (2, 4, 6, …) — QUIC-style role split so
        // concurrent open_stream() on both ends never collides.
        let (demux, _ctrl_rx) = StreamDemultiplexer::new_with_role(256, false);
        let demux = Arc::new(demux);
        let streams = Arc::new(DashMap::new());
        // Balanced active-streams gauge, shared with the pump (see StreamGauge).
        // Note the observability handle here is the *listener's* aggregate, so
        // the gauge it feeds is "streams open across every accepted session" —
        // which is why the per-session drain below has to be exact.
        let stream_gauge = StreamGauge::new(observability.clone());
        // One receive-window growth budget for the whole connection: this handle, and only
        // this handle, is what every stream of the session is built from.
        let recv_tuning = Arc::new(SharedRecvTuning::default());
        let recv_tuning_for_pump = recv_tuning.clone();

        let inner_session: Arc<Mutex<Option<Arc<Session>>>> =
            Arc::new(Mutex::new(Some(server_session.clone())));

        // Server-side sessions are already Connected — publish that in the
        // watch channel immediately so `await_ready()` resolves at once.
        let (ready_tx, ready_rx) = watch::channel(ConnectionState::Connected as u8);

        // Query before moving `transport` into the data pump below.
        let migration_capable = transport.supports_migration();

        let session = Arc::new(Self {
            id: new_session_id(),
            peer_addr: peer_addr.clone(),
            state: state.clone(),
            send_queue: send_queue.clone(),
            cmd_tx: cmd_tx.clone(),
            close_request,
            control_tx: control_tx.clone(),
            released_tx: released_tx.clone(),
            cmd_rx: Mutex::new(None),
            recv_rx: Mutex::new(recv_rx),
            demux: demux.clone(),
            streams: streams.clone(),
            inner_session,
            // Server side: 0-RTT early-data is delivered via
            // `AcceptOutcome`, not this client-facing field.
            early_data_accepted: Arc::new(Mutex::new(None)),
            // Server side: the session is already established here, so
            // `set_traffic_shaping` applies immediately; default = no shaping.
            shaping: Arc::new(parking_lot::Mutex::new(TrafficShapingConfig::default())),
            // Shares the listener's instance so its `snapshot()` aggregates
            // every accepted session.
            observability: observability.clone(),
            incoming_stream_rx: Arc::new(Mutex::new(incoming_stream_rx)),
            // The same slot the pump is handed below. A server-side session runs no
            // handshake to fail, but its pump can still end it with a cause — the
            // liveness timer, a transport that gave up on its peer — and a fresh slot
            // here would leave `last_error()` and `recv()` reading one nobody writes.
            terminal_error: terminal_error.clone(),
            ready_tx: Arc::new(ready_tx),
            ready_rx,
            migration_capable,
            stream_gauge: stream_gauge.clone(),
            recv_tuning,
        });

        let session_id = *server_session.id();
        let runtime_for_pump = runtime.clone();
        // WIRE-001: the server handshake is complete — raise the receive frame
        // cap from the tight unauthenticated handshake limit to the steady-state
        // application limit before the data pump takes over.
        transport.set_frame_phase(FramePhase::Established);
        // ε / WIRE v5: switch the transport off the bootstrap ConnId onto this
        // session's rotating CID_0 (the c2s chain the client routes on; the
        // demux registers the matching inbound window). The server→client
        // direction rotates too, so neither flow keeps a stable cleartext id.
        transport.set_outbound_cid(server_session.current_outbound_cid());
        let observed = Arc::new(ObservedTransport::new(
            transport,
            observability.clone(),
            leg,
        ));
        let _detached = runtime.spawn(Box::pin(run_data_pump(
            server_session,
            session_id,
            observed,
            state,
            send_queue,
            cmd_rx,
            close_requested,
            control_rx,
            released_rx,
            recv_tx,
            demux,
            streams,
            runtime_for_pump,
            observability,
            leg,
            StreamLink {
                commands: cmd_tx,
                control: control_tx,
                released: released_tx,
            },
            incoming_stream_tx,
            stream_gauge,
            recv_tuning_for_pump,
            terminal_error,
        )));

        session
    }

    /// Background task: performs handshake, then pumps data.
    #[allow(clippy::too_many_arguments)]
    async fn background_task<T: SessionTransport>(
        state: Arc<AtomicU8>,
        send_queue: Arc<Mutex<Vec<Vec<u8>>>>,
        _cmd_tx: mpsc::Sender<SessionCommand>,
        cmd_rx: mpsc::Receiver<SessionCommand>,
        close_requested: watch::Receiver<bool>,
        control_rx: mpsc::Receiver<ControlCommand>,
        released_rx: mpsc::UnboundedReceiver<u32>,
        recv_tx: mpsc::Sender<Bytes>,
        transport: T,
        peer: String,
        demux: Arc<StreamDemultiplexer>,
        streams: Arc<DashMap<u32, Arc<Stream>>>,
        expected_server_key: HybridVerifyingKey,
        runtime: Arc<dyn Runtime>,
        inner_session: Arc<Mutex<Option<Arc<Session>>>>,
        early_data_accepted: Arc<Mutex<Option<bool>>>,
        shaping: Arc<parking_lot::Mutex<TrafficShapingConfig>>,
        resumption_request: Option<([u8; 32], [u8; 32], Vec<u8>)>,
        observability: Arc<Observability>,
        liveness: Option<crate::transport::liveness::LivenessConfig>,
        stream_link: StreamLink,
        incoming_stream_tx: mpsc::Sender<Arc<crate::api::stream::PhantomStream>>,
        // Terminal-error capture + readiness signal
        terminal_error: Arc<parking_lot::Mutex<Option<CoreError>>>,
        ready_tx: Arc<watch::Sender<u8>>,
        // True when the transport supports connection migration (UDP); used to
        // label the handshake metric and ObservedTransport with the correct leg.
        migration_capable: bool,
        // Balanced active-streams gauge shared with the outer `PhantomSession`.
        stream_gauge: Arc<StreamGauge>,
        // The connection's single receive-window growth budget, created by the
        // `PhantomSession` (which outlives the handshake) and handed to the pump below.
        recv_tuning: Arc<SharedRecvTuning>,
    ) {
        // Derive the leg label once from migration_capable so every metric
        // and ObservedTransport inside this task uses the right leg type.
        let leg = if migration_capable {
            LegType::Udp
        } else {
            LegType::Tcp
        };
        // DEBUG: the peer address is correlatable; keep it off default logs.
        log::debug!("PhantomSession: starting handshake with {}", peer);

        // fips bootstrap POST gate, mirroring the listener and
        // `connect_pinned*` paths: the synchronous Rust-only entry
        // points (`connect_with_transport*` / `SessionBuilder::connect`)
        // also need to honor FIPS 140-3 §7.7 before any cryptographic
        // work. Cached `OnceLock` makes the second+ call an atomic
        // read; the first call runs the full POST battery.
        //
        // On failure we cannot return a `CoreError` (the entry points
        // are infallible by API contract) — instead we transition the
        // state machine to `Failed` and bail, matching the existing
        // handshake-failure shape. The error string lands in the log.
        #[cfg(feature = "fips")]
        if let Err(e) = crate::crypto::self_tests::ensure_post_passed() {
            log::error!(
                "PhantomSession: FIPS POST self-test failed; refusing to handshake: {:?}",
                e
            );
            let core_err = CoreError::FipsSelfTestFailure(format!("{e:?}"));
            *terminal_error.lock() = Some(core_err);
            state.store(ConnectionState::Failed as u8, Ordering::Relaxed);
            // Signal awaiting callers (await_ready) that we have reached a terminal state.
            let _ = ready_tx.send(ConnectionState::Failed as u8);
            return;
        }

        // Retain a copy of any 0-RTT early-data so it can be losslessly
        // re-sent over the established session if the server rejects it (C3 —
        // the rejection-retransmission contract). `run_client_handshake`
        // consumes `resumption_request`, so clone the blob first.
        let pending_early_data: Option<Vec<u8>> = resumption_request
            .as_ref()
            .and_then(|(_, _, ed)| (!ed.is_empty()).then(|| ed.clone()));

        // ── Stage 1 & 2: Hybrid Handshake (optionally 0-RTT resumption) ──
        // HS-02: bound the whole client handshake by a wall-clock deadline so a
        // silent or stalling server can't hang the connect indefinitely. The
        // TIMER is `runtime.sleep` (NOT raw tokio::time) so it stays correct
        // under WasmRuntime/EmbeddedRuntime; `select!` is just the combinator.
        let handshake_started = std::time::Instant::now();
        // Scoped so the handshake future's borrow of `transport` ends before
        // `transport` is moved into the data pump below.
        let handshake_result = {
            let handshake_fut =
                run_client_handshake(&transport, &expected_server_key, resumption_request);
            let handshake_timeout = runtime.sleep(CLIENT_HANDSHAKE_DEADLINE);
            tokio::pin!(handshake_fut);
            tokio::select! {
                r = &mut handshake_fut => r,
                _ = handshake_timeout => Err(CoreError::Timeout),
            }
        };
        let (crypto_session, ed_accepted) = match handshake_result {
            Ok((session, accepted)) => (Arc::new(session), accepted),
            Err(e) => {
                log::error!("PhantomSession: handshake failed: {}", e);
                observability.record_handshake(
                    handshake_started.elapsed(),
                    HandshakeOutcome::Failure,
                    leg,
                    AeadAlgorithm::Aes256Gcm,
                    ProtocolVersion::Current,
                );
                // Capture the terminal error BEFORE setting state so
                // await_ready() readers that wake on the state transition always
                // see the error already in place.
                *terminal_error.lock() = Some(e);
                state.store(ConnectionState::Failed as u8, Ordering::Relaxed);
                // Signal awaiting callers (await_ready) that we have reached a
                // terminal Failed state.
                let _ = ready_tx.send(ConnectionState::Failed as u8);
                return;
            }
        };
        log::info!("PhantomSession: Handshake complete — hybrid channel ready");
        observability.record_handshake(
            handshake_started.elapsed(),
            HandshakeOutcome::Success,
            leg,
            AeadAlgorithm::Aes256Gcm,
            ProtocolVersion::Current,
        );

        // Phase 4.1 — publish the negotiated Session + the 0-RTT
        // verdict via the outer PhantomSession so `resumption_hint()`
        // and `early_data_accepted()` can reach them after the
        // background task moves the Arc into the pump.
        {
            let mut guard = inner_session.lock().await;
            *guard = Some(crypto_session.clone());
        }
        // Apply any traffic-shaping config the embedder set BEFORE the
        // handshake completed (connect is async), so the very first data packets
        // are already shaped rather than only after a manual post-establishment
        // `set_traffic_shaping`. A later `set_traffic_shaping` re-applies live.
        apply_shaping(&crypto_session, *shaping.lock());
        *early_data_accepted.lock().await = ed_accepted;
        if let Some(live) = liveness {
            crypto_session.set_liveness_config(live);
        }

        // C3 — 0-RTT rejection retransmission contract. If we sent early-data
        // and the server rejected it (`Some(false)`), it never reached the
        // application layer, so re-send it losslessly over the now-established
        // 1-RTT session. Prepend it to the pre-handshake send queue (drained
        // first by the pump onto the reliable raw-app stream) so it lands
        // *ahead* of anything the app queued while connecting — preserving the
        // order in which the bytes were originally offered. `Some(true)` (the
        // server consumed it) and `None` (none sent) need no action.
        if ed_accepted == Some(false) {
            if let Some(ed) = pending_early_data {
                send_queue.lock().await.insert(0, ed);
                log::debug!(
                    "PhantomSession: 0-RTT early-data rejected; re-queued for 1-RTT delivery"
                );
            }
        }

        let session_id = *crypto_session.id();
        state.store(ConnectionState::Connected as u8, Ordering::Relaxed);
        // Signal readiness — handshake succeeded. The watch fires once;
        // late `await_ready()` callers see the already-resolved Connected value.
        let _ = ready_tx.send(ConnectionState::Connected as u8);
        log::debug!("PhantomSession: fully connected to {}", peer);

        // Wrap the (post-handshake) transport so every data-plane send/recv is
        // recorded. `leg` (derived from `migration_capable` at task entry) correctly
        // labels UDP sessions as Udp and TCP sessions as Tcp.
        // WIRE-001: the handshake is done — raise the frame cap from the tight
        // unauthenticated handshake limit to the steady-state application limit.
        transport.set_frame_phase(FramePhase::Established);
        // ε / WIRE v5: stamp this session's rotating CID_0 on every post-handshake
        // datagram (the chain the server's demux routes on) instead of the
        // bootstrap ConnId.
        transport.set_outbound_cid(crypto_session.current_outbound_cid());
        let observed = Arc::new(ObservedTransport::new(
            transport,
            observability.clone(),
            leg,
        ));
        run_data_pump(
            crypto_session,
            session_id,
            observed,
            state,
            send_queue,
            cmd_rx,
            close_requested,
            control_rx,
            released_rx,
            recv_tx,
            demux,
            streams,
            runtime,
            observability,
            leg,
            stream_link,
            incoming_stream_tx,
            stream_gauge,
            recv_tuning,
            terminal_error,
        )
        .await;
    }
}

/// Drive the client side of the Phantom Protocol handshake to completion.
///
/// When `resumption` is `Some((resume_id, resume_secret, early_data))` the
/// first-flight `ClientHello` carries the resume id and, when `early_data` is
/// non-empty, a sealed 0-RTT blob folded into `ClientHello.early_data` — so it
/// reaches the server on the first flight. A cookie/PoW `HelloRetryRequest` is
/// answered in-loop, reusing the same hello (the early-data blob rides along).
///
/// Returns the established `Session` and the 0-RTT verdict:
/// - `Some(true)`  — the client sent early-data and the server consumed it
/// - `Some(false)` — the client sent early-data and the server rejected it
///   (stale ticket / oversized / AEAD failure)
/// - `None`        — the client sent no early-data on this connect
async fn run_client_handshake<T: SessionTransport>(
    transport: &T,
    expected_server_key: &HybridVerifyingKey,
    resumption: Option<([u8; 32], [u8; 32], Vec<u8>)>,
) -> Result<(Session, Option<bool>), CoreError> {
    let handshake = HandshakeClient::new()?;

    // Build the first-flight ClientHello. A resumption request folds the
    // resume id and (optionally) a sealed 0-RTT early-data blob into the
    // single hello; otherwise it is a plain hello.
    let mut hello = match &resumption {
        Some((resume_id, resume_secret, early_data)) => {
            let ed: Option<&[u8]> = if early_data.is_empty() {
                None
            } else {
                Some(early_data.as_slice())
            };
            handshake.create_client_hello_with_resume(*resume_id, resume_secret, ed)
        }
        None => handshake.create_client_hello(),
    };

    // HS-02: cap the number of HelloRetryRequest rounds. The legitimate flow
    // needs at most one cookie round + one PoW round; a bound of 3 leaves slack
    // for a benign reorder. Without it, a MITM answering every ClientHello with
    // a fresh cheap HelloRetryRequest could loop the client forever.
    const MAX_CLIENT_RETRY_ROUNDS: u32 = 3;
    // Bound how many injected/genuine ServerRejects we read past while still
    // waiting for a ServerHello, so a reject flood can't loop the inner read forever.
    const MAX_CLIENT_REJECT_ROUNDS: u32 = 3;
    let mut retry_rounds: u32 = 0;
    let mut reject_rounds: u32 = 0;
    // An *injected* ServerReject (a tiny pre-crypto blob a network attacker can
    // spray) must not abort a healthy handshake. Remember it and keep reading for a valid
    // ServerHello; surface it only if one never arrives (do NOT auto-downgrade — Invariant 7).
    let mut remembered_reject: Option<ServerReject> = None;

    loop {
        // (Re)send the current hello (fresh, or cookie/PoW-updated after a HelloRetryRequest).
        let bytes = borsh::to_vec(&hello).map_err(|e| {
            CoreError::SerializationError(format!("ClientHello encode failed: {}", e))
        })?;
        transport.send_bytes(&bytes).await?;

        // Read responses for THIS hello, reading past an injected ServerReject (WITHOUT
        // re-sending) until a ServerHello (success), a HelloRetryRequest (re-send with the
        // cookie/PoW), or the channel ends.
        loop {
            let resp = match transport.recv_bytes().await {
                Ok(r) => r,
                Err(e) => {
                    // No further responses: surface a remembered reject (a genuine version
                    // mismatch) over the raw transport error using the typed variant.
                    return match &remembered_reject {
                        Some(r) => Err(CoreError::ProtocolRejected(format!(
                            "server rejected the handshake: unsupported protocol version \
                             (client speaks v{}, server speaks v{})",
                            hello.version, r.supported_version
                        ))),
                        None => Err(e),
                    };
                }
            };

            // T4.4: the reply leads with an explicit discriminant byte
            // (`[kind] ‖ borsh(body)`); dispatch on it instead of trial-deserializing by
            // size. An unknown kind / malformed body is a handshake error, not a misparse.
            match ServerReply::from_wire(&resp) {
                Ok(ServerReply::Hello(sh)) => {
                    let (session, accepted) =
                        handshake.process_server_hello(&hello, &sh, Some(expected_server_key))?;
                    return Ok((session, accepted));
                }
                Ok(ServerReply::Reject(reject)) => {
                    // The marker is an extra sanity check on top of the discriminant. We do
                    // NOT auto-downgrade to `reject.supported_version` (Invariant 7).
                    if reject.has_marker() {
                        reject_rounds += 1;
                        if reject_rounds > MAX_CLIENT_REJECT_ROUNDS {
                            // Use the typed ProtocolRejected variant so callers can branch
                            // without string-matching ("update your client").
                            return Err(CoreError::ProtocolRejected(format!(
                                "server rejected the handshake: unsupported protocol version \
                                 (client speaks v{}, server speaks v{})",
                                hello.version, reject.supported_version
                            )));
                        }
                        // Keep waiting for a valid ServerHello — read the next
                        // frame WITHOUT re-sending, so a single forged reject can't kill the
                        // handshake.
                        remembered_reject = Some(reject);
                        continue;
                    }
                    return Err(CoreError::HandshakeError(
                        "server reject missing marker".into(),
                    ));
                }
                Ok(ServerReply::Retry(retry)) => {
                    retry_rounds += 1;
                    if retry_rounds > MAX_CLIENT_RETRY_ROUNDS {
                        return Err(CoreError::HandshakeError(format!(
                            "server demanded more than {MAX_CLIENT_RETRY_ROUNDS} HelloRetryRequest rounds"
                        )));
                    }
                    log::info!("PhantomSession: Received HelloRetryRequest, retrying...");
                    hello.cookie = retry.cookie;
                    if let Some(challenge) = retry.challenge {
                        // H3: cap the accepted difficulty and bound the solver, so an
                        // injected/malicious HelloRetryRequest (e.g. difficulty 255)
                        // surfaces a handshake error instead of pinning a CPU core.
                        log::info!("PhantomSession: Solving PoW challenge...");
                        hello.pow_solution = Some(
                            challenge
                                .solve_capped(crate::crypto::pow::MAX_CLIENT_POW_DIFFICULTY)
                                .map_err(|e| CoreError::HandshakeError(e.to_string()))?,
                        );
                    }
                    break; // re-send the cookie/PoW-updated hello (outer loop)
                }
                Err(e) => {
                    return Err(CoreError::HandshakeError(format!(
                        "invalid server reply: {e}"
                    )));
                }
            }
        }
    }
}

/// Wall-clock ceiling on the whole client handshake (HS-02), from the first
/// keypair generated to the established `Session`, so a silent or stalling server
/// cannot hang a connect indefinitely.
///
/// This is the outer authority over every retransmission strategy underneath it: a
/// transport that retransmits its handshake flight — `UdpClientTransport` is the one
/// that does — must exhaust its own budget *inside* this window, or its last
/// retransmit is sent after the session has already abandoned the connect and the
/// work is wasted. That transport's `HANDSHAKE_RETRANSMIT_BUDGET` is sized against
/// this constant.
pub(crate) const CLIENT_HANDSHAKE_DEADLINE: std::time::Duration =
    std::time::Duration::from_secs(10);

/// Reserved stream id for the connectionless `send()`/`recv()` surface. The
/// demultiplexer hands out ids of two and above, so this never collides with a
/// user-opened stream. Idle keep-alives ([`send_keepalive`]) also stamp it for a
/// well-formed, consistent header.
const RAW_APP_STREAM_ID: u32 = 1;

/// Per-session bookkeeping for the `active_streams` gauge.
///
/// The gauge is an `UpDownCounter` (and a signed atomic in the hot-path
/// snapshot), so every `stream_opened()` MUST be matched by exactly one
/// `stream_closed()` — an unbalanced gauge is the exact defect
/// `core/tests/observability_e2e.rs` pins for *sessions*, and this type is what
/// keeps it from reappearing for *streams*.
///
/// Discipline:
/// - Only **user-visible** streams are counted. Ids `0` (control) and
///   [`RAW_APP_STREAM_ID`] (the reserved raw-app `send()`/`recv()` stream the
///   pump creates for every session) are internal plumbing, not streams the
///   embedder opened, so they are filtered out here rather than at each call
///   site.
/// - [`Self::opened`] is called where a user stream enters the session's stream
///   table: `PhantomSession::open_stream` (local) and the receive path's
///   new-peer-stream branch (remote, surfaced via `accept_stream`).
/// - [`Self::closed`] is called where one leaves it: `retire_stream`, once both
///   halves are closed; `retire_released_stream`, once the application has let go
///   of the stream and this side's own half is closed; or the offset-exhaustion
///   fallback in `flush_deferred_sends`, which drops the stream after a bare FIN.
///   Each of them acts only when it is the one that takes the stream out of the
///   table, so a stream is counted out exactly once.
/// - [`Self::drain`] retires whatever is still open when the session ends. It
///   runs both at data-pump exit **and** in `Drop for PhantomSession` — the
///   `swap(0)` is atomic, so whichever runs first retires the streams and the
///   other one sees zero. That covers every abnormal exit (transport death,
///   liveness `Dead`, handle drop, a session whose pump never started, and an
///   `open_stream()` issued after the pump already ended). The pump drain is the
///   prompt one; the `Drop` drain is the backstop that also mops up the narrow
///   race where the (aborted, possibly still-running) receive task registers a
///   peer-initiated stream concurrently with the pump's drain.
/// - [`Self::closed`] never decrements below zero, so a removal racing a drain
///   cannot push the gauge negative.
#[derive(Debug)]
pub(crate) struct StreamGauge {
    /// User-visible streams currently reported open by this session.
    open: AtomicI64,
    observability: Arc<Observability>,
}

impl StreamGauge {
    fn new(observability: Arc<Observability>) -> Arc<Self> {
        Arc::new(Self {
            open: AtomicI64::new(0),
            observability,
        })
    }

    /// Count a newly-opened user-visible stream. No-op for the internal ids.
    fn opened(&self, stream_id: u32) {
        if stream_id <= RAW_APP_STREAM_ID {
            return;
        }
        self.open.fetch_add(1, Ordering::AcqRel);
        self.observability.stream_opened();
    }

    /// Retire a stream previously counted by [`Self::opened`]. No-op for the
    /// internal ids and for a stream this session never counted (or already
    /// retired via [`Self::drain`]).
    fn closed(&self, stream_id: u32) {
        if stream_id <= RAW_APP_STREAM_ID {
            return;
        }
        if self
            .open
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |v| {
                (v > 0).then_some(v - 1)
            })
            .is_ok()
        {
            self.observability.stream_closed();
        }
    }

    /// Retire every stream still counted (session teardown). Idempotent.
    fn drain(&self) {
        let still_open = self.open.swap(0, Ordering::AcqRel);
        for _ in 0..still_open {
            self.observability.stream_closed();
        }
    }
}

/// Issue instant of every PATH_CHALLENGE this side currently has outstanding,
/// keyed by path id — the start stamp for
/// [`Observability::record_path_validation`].
///
/// The path registry itself keeps no timestamp, so this map is the authoritative
/// start time. Bounded by the 256-value `path_id` space; an entry leaves the map
/// exactly once, either when the peer's response resolves it (reader task) or
/// when the pump's expiry sweep abandons it (send loop) — so a challenge
/// produces exactly one `success` / `failure` / `timeout` sample, never two.
///
/// Shared between the reader task (which issues and resolves challenges) and the
/// pump's heartbeat (which expires them), hence the mutex. Every method locks,
/// finishes its map work, and releases before returning; the lock is never held
/// across an `.await`, and no recording happens under it.
#[derive(Default)]
struct PathChallenges {
    started: parking_lot::Mutex<std::collections::HashMap<u8, std::time::Instant>>,
}

impl PathChallenges {
    /// Stamp (or re-stamp, on a re-issued challenge) the start of a validation
    /// attempt on `path_id`.
    fn start(&self, path_id: u8) {
        self.started
            .lock()
            .insert(path_id, std::time::Instant::now());
    }

    /// Take the start stamp for `path_id` if this side has an outstanding
    /// challenge there. `None` means we never issued one (or the sweep already
    /// timed it out), in which case there is nothing to time.
    fn resolve(&self, path_id: u8) -> Option<std::time::Instant> {
        self.started.lock().remove(&path_id)
    }

    /// Whether nothing is outstanding. The overwhelmingly common case on a
    /// steady session, so the pump's heartbeat checks this before doing any
    /// budget arithmetic.
    fn is_empty(&self) -> bool {
        self.started.lock().is_empty()
    }

    /// Remove and return every challenge that has been outstanding longer than
    /// `timeout`, as `(path_id, waited)` pairs. The caller records the samples
    /// *after* this returns, so the lock is released first.
    fn expire(&self, timeout: std::time::Duration) -> Vec<(u8, std::time::Duration)> {
        let now = std::time::Instant::now();
        let mut expired = Vec::new();
        let mut guard = self.started.lock();
        guard.retain(|path_id, started| {
            let waited = now.saturating_duration_since(*started);
            if waited > timeout {
                expired.push((*path_id, waited));
                false
            } else {
                true
            }
        });
        drop(guard);
        expired
    }

    #[cfg(test)]
    fn outstanding(&self) -> usize {
        self.started.lock().len()
    }

    /// Backdate a challenge's start stamp so the expiry sweep can be tested
    /// without sleeping (an injected clock, not a wall-clock race).
    #[cfg(test)]
    fn start_at(&self, path_id: u8, at: std::time::Instant) {
        self.started.lock().insert(path_id, at);
    }
}

/// Receive-task-local scratch space and observability bookkeeping.
///
/// Owned exclusively by the single reader task (passed as `&mut`), so nothing in
/// here needs synchronisation — with the single, explicitly-shared exception of
/// [`PathChallenges`], whose entries the pump's heartbeat also expires. No lock
/// is ever held across an `.await`.
struct RecvScratch {
    /// Reusable ACK-frame serialization buffer. Hoisted out of the read loop so
    /// a busy reliable stream doesn't pay a fresh allocation per emitted ACK.
    ack_buf: Vec<u8>,
    /// Outstanding PATH_CHALLENGE start stamps. Shared with the pump loop, which
    /// sweeps unanswered challenges — see [`PathChallenges`].
    challenges: Arc<PathChallenges>,
    /// Most recent peer `path_id` observed to move forward. Seeded at 0 (the
    /// implicit handshake path) and updated on each detected peer migration, so
    /// `record_path_migration` can report a real `from` → `to` pair.
    last_peer_path: u8,
    /// Shared user-visible-stream gauge (see [`StreamGauge`]).
    stream_gauge: Arc<StreamGauge>,
    /// The connection's single receive-window growth budget. The receive path needs it for
    /// the same reason it needs the gauge above: it is where peer-initiated streams are
    /// materialised, and a stream built with a budget of its own would sit outside the
    /// session-wide bound.
    recv_tuning: Arc<SharedRecvTuning>,
    /// The peer-opened stream ids this side has ever held, so that a frame for one it has
    /// since dropped is not mistaken for the peer opening a new stream.
    peer_streams: PeerStreamIds,
}

impl RecvScratch {
    fn new(
        ack_buf_capacity: usize,
        stream_gauge: Arc<StreamGauge>,
        challenges: Arc<PathChallenges>,
        recv_tuning: Arc<SharedRecvTuning>,
    ) -> Self {
        Self {
            ack_buf: Vec::with_capacity(ack_buf_capacity),
            challenges,
            last_peer_path: 0,
            stream_gauge,
            recv_tuning,
            peer_streams: PeerStreamIds::default(),
        }
    }
}

/// Every stream id the peer has opened on this session, one bit each.
///
/// A stream is dropped once both of its halves are closed, and frames for it can still
/// arrive after that: the peer retransmits its FIN whenever the acknowledgement of it is
/// lost, and the path can deliver a delayed copy of anything. A stream is opened by the
/// peer's first frame on a new id, so without a record of which ids it has already used,
/// such a frame opens the stream a second time — handed to `accept_stream`, with its offsets
/// starting over, and with nothing that will ever close it.
///
/// This side's own streams need no record: their ids come from the demultiplexer, which
/// can say which of them it has handed out. The peer's are learnt only by seeing them, and
/// stream ids are 16 bits on the wire with each side confined to one parity, so a bit per
/// id of the peer's parity is the whole of the space: 32 768 bits. The table is allocated on
/// the first stream the peer opens, so a session in which it opens none pays nothing.
#[derive(Default)]
struct PeerStreamIds {
    seen: Option<Box<[u64; PEER_STREAM_ID_WORDS]>>,
}

/// Words in [`PeerStreamIds`]: one bit for every id of one parity in the 16-bit id space.
const PEER_STREAM_ID_WORDS: usize = (1 << 16) / 2 / 64;

impl PeerStreamIds {
    /// Word index and bit mask for `stream_id`. Ids of one parity map one-to-one onto the
    /// bits; `None` only for an id wider than the wire's 16 bits, which no frame carries.
    fn slot(stream_id: u32) -> Option<(usize, u64)> {
        let index = (stream_id >> 1) as usize;
        (index / 64 < PEER_STREAM_ID_WORDS).then(|| (index / 64, 1u64 << (index % 64)))
    }

    fn has_seen(&self, stream_id: u32) -> bool {
        match (&self.seen, Self::slot(stream_id)) {
            (Some(seen), Some((word, bit))) => seen.get(word).is_some_and(|w| w & bit != 0),
            _ => false,
        }
    }

    fn mark_seen(&mut self, stream_id: u32) {
        if let Some((word, bit)) = Self::slot(stream_id) {
            let seen = self
                .seen
                .get_or_insert_with(|| Box::new([0; PEER_STREAM_ID_WORDS]));
            if let Some(w) = seen.get_mut(word) {
                *w |= bit;
            }
        }
    }
}

/// Seal one packet through the session AEAD, timing **only** the AEAD call and
/// folding the duration into the always-on encrypt aggregate
/// (`MetricsSnapshotFfi::avg_encrypt_ns` / `encrypt_count`).
///
/// Recording is a pair of relaxed atomic adds and cannot fail, block, or change
/// the result: the `Result` is returned untouched. Only successful seals are
/// recorded, so `encrypt_count` stays "packets actually sealed" — every caller
/// aborts the send on `Err`, so a failed seal never becomes a packet.
#[inline]
fn timed_encrypt(
    crypto_session: &Session,
    observability: &Observability,
    header: &PacketHeader,
    plaintext: &[u8],
    extensions: &[u8],
) -> Result<Vec<u8>, CoreError> {
    let started = std::time::Instant::now();
    let sealed = crypto_session.encrypt_packet(header, plaintext, extensions);
    if sealed.is_ok() {
        observability.record_encrypt_ns(duration_ns(started));
    }
    sealed
}

/// Elapsed nanoseconds since `started`, saturating instead of wrapping on the
/// (unreachable) >584-year overflow. Shared by the encrypt/decrypt timers.
#[inline]
fn duration_ns(started: std::time::Instant) -> u64 {
    u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX)
}

/// Items routed from the reader task to the delivery task via the internal
/// UNBOUNDED channel.
///
/// Using an explicit enum (rather than `(u32, Bytes)`) lets FIN signals be
/// ordered after any data frames for the same stream, and lets the delivery task
/// dispatch without a separate close channel.
enum DeliverItem {
    /// Inbound data payload `(stream_id, bytes, reliable)`. The reader adds
    /// [`delivery_charge`] to `undelivered_bytes` on enqueue; the delivery task
    /// subtracts the same figure once the frame is forwarded to a bounded
    /// downstream channel.
    ///
    /// The third field says which path the bytes arrived on, and it is carried this
    /// far because only the reader knows it and only the delivery task can act on it:
    /// flow control counts reliable bytes and nothing else, since those are the only
    /// ones the sending end charged against the window. Delivery, ordering and the
    /// backlog charge treat both alike.
    Data(u32, Bytes, bool),
    /// Peer sent FIN on `stream_id`. Ordered after any `Data` items already
    /// queued for that stream so the consumer sees EOF last.
    Close(u32),
    /// The reader has dropped `stream_id` from the stream table — both halves are closed,
    /// or this side's is and the application has let go of the stream: release its
    /// demultiplexer route.
    ///
    /// The route is the sender behind the application's channel, and the reader cannot
    /// release it itself — the stream's last data and its EOF may still be queued ahead of
    /// this item, and closing the channel first would lose them. Queued behind them
    /// instead, it is acted on only once they have been handed over. Carries no payload
    /// and is not charged to the backlog: the reader emits one per stream, not per frame.
    Retire(u32),
}

/// Bytes charged to the delivery backlog for one queued item.
///
/// The payload is what the application will eventually read; the rest is what parking the
/// item costs regardless of how little it carries. Charging both is what makes
/// [`RECV_DELIVERY_HARD_CAP`] a bound on resident bytes — a peer choosing minimum-size
/// segments pays the item cost, which is where the memory actually goes. A FIN carries no
/// payload and is charged the structure alone.
#[inline]
fn delivery_charge(payload_len: usize) -> u64 {
    payload_len as u64 + DELIVERY_ITEM_OVERHEAD_BYTES
}

/// Outbound work the pump has taken off the command channel but that the target
/// stream's send buffer has not yet accepted.
///
/// The pump used to hand application writes straight to `Stream::send_reliable`,
/// which parks on the stream's backpressure semaphore until an acknowledgement
/// frees a slot. Doing that from inside the pump's `select!` parks the *whole
/// pump*: no heartbeat, no `WINDOW_UPDATE` flush, no drain, no command
/// processing — so a saturating send in one direction stops the session issuing
/// the other direction's flow-control limits and the download collapses to the
/// single initial window. Deferring the refused chunk here instead keeps the loop
/// turning; the pump simply stops reading commands until the backlog clears,
/// which pushes the backpressure out to the application's own `send()` where it
/// belongs.
///
/// FIFO order across the queue is what preserves stream ordering: the pump stops
/// at the first chunk a buffer refuses rather than skipping ahead.
#[derive(Clone)]
enum Deferred {
    /// Reliable application payload awaiting a send-buffer slot on `stream`.
    Data { stream: Arc<Stream>, data: Bytes },
    /// The reliable FIN sentinel for `stream_id` awaiting a slot.
    Fin { stream_id: u32, stream: Arc<Stream> },
    /// The application dropped its handle to `stream_id`: close the writing half if
    /// nothing has closed it yet, behind every write the handle queued. Queued rather than
    /// acted on at once for the same reason a FIN is — it has to land after those writes —
    /// and resolved when it reaches the head of the queue, where all of them are in the
    /// send buffer (see [`flush_deferred_sends`]).
    Release { stream_id: u32, stream: Arc<Stream> },
}

/// Maximum segments one [`drain_streams_priority_ordered`] pass puts on the wire
/// before handing control back to the pump's `select!`.
///
/// Without a bound, one stream with a full congestion window monopolises the
/// pump for as long as it takes to encrypt and write that whole window, during
/// which no inbound flow-control limit is flushed and no command is serviced.
/// The drain re-arms the outbound notify when it stops on this budget, so the
/// only cost of the bound is one extra trip through `select!` per 32 packets;
/// the gain is that every other arm gets a turn at that same cadence.
const DRAIN_MAX_SEGMENTS_PER_PASS: usize = 32;

/// Safety valve on the flush-everything loops used at graceful close: bounds the
/// number of `DRAIN_MAX_SEGMENTS_PER_PASS`-sized passes so a stream that keeps
/// re-offering work can never wedge the teardown.
const DRAIN_MAX_PASSES_ON_CLOSE: usize = 256;

/// Floor on how long the pump waits after the pacer refuses a segment.
///
/// The wait is a timer, and a timer's resolution is about a millisecond, so
/// asking for less than this buys nothing and a zero-length one would spin the
/// pump against a bucket that still has no credit.
const PACING_WAKE_MIN: std::time::Duration = std::time::Duration::from_millis(1);

/// Ceiling on the same wait. The 10 ms heartbeat drains unconditionally, so a
/// pacing deadline further out than that is already covered; capping here keeps
/// a low rate estimate from being able to defer queued data by more than the
/// pump's own worst-case latency.
const PACING_WAKE_MAX: std::time::Duration = std::time::Duration::from_millis(10);

/// Ceiling on a single pacing wait during the close-time flush. The flush obeys
/// the rate — dumping a connection's tail at line rate is the same burst pacing
/// exists to prevent — but a teardown must not be held hostage by a low
/// estimate, and [`DRAIN_MAX_PASSES_ON_CLOSE`] bounds how many of these it can
/// take.
const CLOSE_FLUSH_PACING_WAIT_MAX: std::time::Duration = std::time::Duration::from_millis(2);

/// Why a [`drain_streams_priority_ordered`] pass stopped.
///
/// The distinction matters because the two bounded cases want opposite things
/// from the pump: a pass that spent its segment budget has work ready *now* and
/// wants to be re-entered as soon as the other `select!` arms have had a turn,
/// while a pass the pacer stopped must not be re-entered until credit exists,
/// or the pump spins.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DrainStop {
    /// Every stream ran dry: the application had nothing more to give. Nothing
    /// to schedule — the next application write will wake the pump.
    Drained,
    /// At least one stream still had data, and the congestion window had no
    /// room for it. Nothing to schedule — an acknowledgement frees the window
    /// and wakes the pump.
    CongestionLimited,
    /// At least one stream still had data, and the *peer's* advertised
    /// flow-control window had no room for it. Nothing to schedule — a
    /// `WINDOW_UPDATE` wakes the pump.
    ///
    /// Nothing to schedule, but not nothing to fall back on: the credit that would
    /// clear this rides in a single unacknowledged frame, so it may simply never
    /// arrive. The 10 ms heartbeat re-enters the drain regardless, and it is there
    /// that `Stream::try_persist_probe` lets a stream with nothing outstanding ask
    /// the peer for what it is owed rather than wait for a frame that is not coming.
    FlowControlled,
    /// The transport refused a write — a datagram socket out of buffer space,
    /// a stream transport that has gone away. The segment was re-marked unsent
    /// and the next pass re-offers it.
    TransportRefused,
    /// Stopped on [`DRAIN_MAX_SEGMENTS_PER_PASS`] with data still offered.
    SegmentBudget,
    /// Stopped because the pacer has no credit. The delay is how long until it
    /// does.
    ///
    /// Reported without first establishing that a stream had anything to
    /// offer, because establishing that means polling a segment out and the
    /// pacer's answer is a precondition of doing so. The cost is one wake-up
    /// per pass that ends with an empty bucket and an empty stream, bounded by
    /// [`PACING_WAKE_MAX`] — no more often than the pump's own heartbeat, and
    /// it clears as soon as the bucket has credit again.
    Paced(std::time::Duration),
}

/// Whether a pass that stopped for `stop` is one in which the sender's own
/// supply of data, rather than anything else, is what bounded it.
///
/// Exactly one variant qualifies, and the narrowness is the point. The
/// application-limited flag switches off the loss response, the Startup
/// judgement and the bandwidth filter's ability to take a new maximum, so
/// anything that raises it is something that can quiet those three — and the
/// only statement that honestly warrants it is "there was nothing left to send".
///
/// The rest, variant by variant:
///
/// - [`DrainStop::CongestionLimited`] — the controller's own window is what held
///   the data back. A saturated round by construction, and exactly the kind a
///   loss response exists to judge.
/// - [`DrainStop::FlowControlled`] — the *peer's* advertised receive window is
///   what held the data back. The sender still has a full send queue, so it is
///   not short of anything; and the input is the peer's, which must not be
///   allowed to reach a local congestion-control decision at all. (Linux agrees
///   on both counts: `tcp_rate_check_app_limited`'s first condition is "we have
///   less than one packet to send", which a receive-window-blocked sender fails.)
/// - [`DrainStop::Paced`] — the pacer is the controller metering itself, on
///   purpose, and in steady state it is what stops nearly every pass.
/// - [`DrainStop::SegmentBudget`] — there is data ready right now and the pump
///   is coming straight back for it.
/// - [`DrainStop::TransportRefused`] — the local send path would not take the
///   bytes. That is the moment it is most congested, and reporting it as an idle
///   application is precisely backwards.
///
/// The other half of the rule — that the congestion window must still have had
/// room — lives in `BandwidthEstimator::note_app_limited_drain`, where both
/// figures are already under the lock.
fn drain_stop_is_app_limited(stop: DrainStop) -> bool {
    match stop {
        DrainStop::Drained => true,
        DrainStop::CongestionLimited
        | DrainStop::FlowControlled
        | DrainStop::TransportRefused
        | DrainStop::Paced(_)
        | DrainStop::SegmentBudget => false,
    }
}

/// Translate a drain pass's stopping reason into the pump's next move, and
/// return the pacing deadline the pump's pacing branch should wait on (`None`
/// when the pass did not stop on pacing).
///
/// The deadline is returned rather than awaited on purpose. The drain runs
/// inside a `select!` arm body, and an arm body runs to completion — so a sleep
/// taken here parks the entire pump: no flow-control limit for the reverse
/// direction, no commands accepted, no liveness sweep. That is the shape that
/// starved the download in the first place, and re-introducing it to implement
/// pacing would trade one direction's collapse for the other's.
///
/// This is also where the app-limited signal is raised, because this is the only
/// place that knows *why* the pass ended. Congestion control cannot derive it:
/// from the acknowledgement stream alone, a round in which the sender had
/// nothing to send is indistinguishable from one in which the path refused to
/// carry more.
/// `pump_had_work` says whether the pump itself was holding application bytes at
/// the moment the pass came up empty — a refused chunk in `deferred`, or a command
/// still unread in its channel. Only meaningful for a pass that ran dry, and
/// recorded there rather than acted on.
///
/// It exists because the drain and the pump's ingestion of application data are
/// competing branches of one `select!`. A turn spent draining is a turn not spent
/// reading the channel, so a pass can find every stream empty while the
/// application's next chunk is already in the process — and the phase that opens
/// then says the application was the limit, when the limit was this endpoint's own
/// scheduling. Measurement rather than assertion: the ARQ-buffer explanation for
/// the same observation was closed by a counter that came back zero, and this is
/// the remaining named candidate.
fn apply_drain_outcome(
    crypto_session: &Arc<Session>,
    stop: DrainStop,
    pump_had_work: bool,
) -> Option<tokio::time::Instant> {
    if drain_stop_is_app_limited(stop) {
        crypto_session.note_app_limited_drain();
        if pump_had_work {
            crypto_session.note_dry_pass_with_pump_work();
        }
    }
    match stop {
        DrainStop::Drained
        | DrainStop::CongestionLimited
        | DrainStop::FlowControlled
        | DrainStop::TransportRefused => None,
        DrainStop::SegmentBudget => {
            crypto_session.notify_outbound_ready();
            None
        }
        DrainStop::Paced(delay) => {
            Some(tokio::time::Instant::now() + delay.clamp(PACING_WAKE_MIN, PACING_WAKE_MAX))
        }
    }
}

/// Write `cause` into a session's terminal-error slot, unless a cause is already
/// there: an earlier, more specific failure is the better answer.
fn record_terminal_cause(slot: &parking_lot::Mutex<Option<CoreError>>, cause: CoreError) {
    let mut slot = slot.lock();
    if slot.is_none() {
        *slot = Some(cause);
    }
}

/// Shared client/server data pump.
///
/// After the handshake completes (client side) or after the server `Session` is
/// derived (server side), this loop:
///   - drains the queued early-data buffer,
///   - listens for incoming packets and decrypts them,
///   - encrypts outgoing application/stream packets,
///   - sends ACKs for reliable packets.
// The parameters represent the complete session-identity and I/O surface.
// Grouping them into a struct would require a generic struct (due to `T:
// SessionTransport`), add indirection with no safety or clarity gain, and
// constitute a public-API change. The function is private (`async fn`, no
// `pub`), so the extra arguments are contained here.
#[allow(clippy::too_many_arguments)]
async fn run_data_pump<T: SessionTransport>(
    crypto_session: Arc<Session>,
    session_id: SessionId,
    // Always the observing wrapper: it is how the pump learns that the transport has
    // given up on the peer (see `ObservedTransport`).
    transport: Arc<ObservedTransport<T>>,
    state: Arc<AtomicU8>,
    send_queue: Arc<Mutex<Vec<Vec<u8>>>>,
    mut cmd_rx: mpsc::Receiver<SessionCommand>,
    // The local close request (`PhantomSession::close_request`), read beside the command
    // channel rather than through it.
    mut close_requested: watch::Receiver<bool>,
    // Control that writes nothing (`ControlCommand`), read beside the command channel for
    // the same reason.
    mut control_rx: mpsc::Receiver<ControlCommand>,
    // Stream handles the application has dropped (`StreamLink::released`).
    mut released_rx: mpsc::UnboundedReceiver<u32>,
    recv_tx: mpsc::Sender<Bytes>,
    demux: Arc<StreamDemultiplexer>,
    streams: Arc<DashMap<u32, Arc<Stream>>>,
    runtime: Arc<dyn Runtime>,
    observability: Arc<Observability>,
    leg: LegType,
    // The channels a `PhantomStream` handle needs, cloned for the handles built on
    // peer-initiated streams (passed through to `handle_packet` → new-stream branch).
    // Holding it also keeps the control and release channels open for as long as the pump
    // runs, so their arms below never see them close.
    stream_link: StreamLink,
    // Sink for newly-registered peer-initiated streams (`accept_stream()`).
    incoming_stream_tx: mpsc::Sender<Arc<crate::api::stream::PhantomStream>>,
    // Balanced active-streams gauge shared with the outer `PhantomSession`
    // (see `StreamGauge`): the receive path counts peer-initiated streams, the
    // close paths retire them, and the teardown below drains the remainder.
    stream_gauge: Arc<StreamGauge>,
    // The connection's single receive-window growth budget, created by the
    // `PhantomSession` that outlives this pump. Every stream the pump builds — its own
    // raw stream and each peer-initiated one — draws on this handle, which is what makes
    // the session-wide bound hold rather than merely be intended.
    recv_tuning: Arc<SharedRecvTuning>,
    // Where a terminal cause is recorded, shared with the `PhantomSession` handle so
    // `last_error()`, `await_ready()` and `recv()` can report it. The pump writes into
    // it at the two places it ends a session of its own accord: the liveness timer,
    // and a transport that has given up on a peer which stopped taking bytes.
    terminal_error: Arc<parking_lot::Mutex<Option<CoreError>>>,
) {
    // Session is now established and active — bump the active-session gauge.
    // The matching `session_closed` at teardown (below) lets the gauge fall,
    // so it tracks live sessions instead of growing monotonically.
    observability.session_opened(leg);

    // Liveness (P4.3): stamp "alive now" at establishment so the inbound-silence
    // sweep measures from the data-plane start, not from session construction (which
    // predates the multi-KB handshake and would otherwise look stale immediately).
    crypto_session.update_activity();

    // ── Raw-app session stream (reserved id 1) ──
    // The connectionless `send()` / `recv()` surface is multiplexed onto one
    // reserved stream so it gets the same reliable-delivery machinery as
    // explicitly-opened streams: `drain_streams_priority_ordered` (re)transmits
    // its buffered segments on the poll tick / outbound-ready notify, and
    // inbound ACKs for id 1 clear them via `Stream::ack`. The demultiplexer
    // hands out ids 2+, so this never collides with a user-opened stream.
    let raw_stream = Arc::new(Stream::with_recv_tuning(
        RAW_APP_STREAM_ID as TransportStreamId,
        recv_tuning.clone(),
    ));
    streams.insert(RAW_APP_STREAM_ID, raw_stream.clone());

    // Application writes the pump has accepted but that a stream's send buffer
    // has not yet admitted (see `Deferred`). While this queue is non-empty the
    // command arm below is disabled, so the pump keeps servicing the heartbeat,
    // the receive-driven wake-ups and the flow-control flush, and the
    // backpressure surfaces at the application's own `send()` instead of parking
    // the pump. It also keeps servicing the local close request, which is read
    // on an arm of its own for exactly this reason: nothing bounds how long this
    // queue stays non-empty except the peer.
    let mut deferred: VecDeque<Deferred> = VecDeque::new();

    // Stream handles the application has dropped, each waiting until the pump has taken in
    // every write that handle queued. A drop is reported on a channel of its own — `Drop`
    // can neither wait for room in the command channel nor ride it — so the report can
    // arrive while the handle's last writes are still in that channel, and closing the
    // stream then would put its FIN ahead of them. Every such write was queued before the
    // drop, and so before the report, so all of them are among the commands in the channel
    // when the report is read: the release is due once that many more have been taken.
    // `commands_taken` counts every command the command arm takes; the queue is in
    // non-decreasing order of `due`, because a later report can only find the earlier
    // one's commands still ahead of it in the channel.
    let mut releases: VecDeque<(u32, u64)> = VecDeque::new();
    let mut commands_taken: u64 = 0;

    // ── Flush queued early-data onto the raw-app stream ──
    // Routed through the stream (not a one-shot direct send) so queued
    // pre-handshake data is buffered for retransmit just like post-handshake
    // sends — a dropped early-data frame is recovered, not lost.
    //
    // Queued rather than pushed directly: the pre-handshake queue has no size
    // limit, so an application that writes more than the stream's 1024-segment
    // buffer holds before the handshake completes would park here — before the
    // loop that transmits, hence before any acknowledgement could ever free a
    // slot. That is a permanent stall, not backpressure. The main loop admits
    // this backlog as slots free.
    {
        let mut queue = send_queue.lock().await;
        let count = queue.len();
        for msg in queue.drain(..) {
            for chunk in msg.chunks(APP_CHUNK) {
                deferred.push_back(Deferred::Data {
                    stream: raw_stream.clone(),
                    data: Bytes::copy_from_slice(chunk),
                });
            }
        }
        if count > 0 {
            log::info!(
                "PhantomSession: queued {} early-data message(s) onto the raw-app stream",
                count
            );
            crypto_session.notify_outbound_ready();
        }
    }

    // ── Receive-delivery decoupling (lossless backpressured per-stream recv) ──
    //
    // Three-task delivery pipeline with provably isolated paths:
    //
    //   Reader → deliver_tx (UNBOUNDED, DeliverItem) → Router task
    //               │                         ├─ id 0/1 → raw_deliver_tx (UNBOUNDED)
    //               │                         └─ id ≥ 2 → streams_deliver_tx (UNBOUNDED)
    //               │
    //               Task A: raw_deliver_rx   → recv_tx.send().await
    //               Task B: streams_deliver_rx → demux.route_data_async().await
    //
    // The Router forwards items to TWO separate UNBOUNDED downstream channels;
    // since both targets are UNBOUNDED, the Router NEVER blocks — no HOL stall.
    // Task A and Task B drain their channels independently: a slow opened-stream
    // consumer stalling Task B has ZERO effect on Task A (raw-app isolation).
    //
    // `undelivered_bytes` is incremented by the reader and decremented by Task A
    // or Task B on dequeue — BEFORE the blocking downstream send — so the
    // hard-cap check in the reader is accurate and no byte is leaked on failure.
    // What it counts is `delivery_charge`: payload plus the structure a queued item
    // costs, because the item count is what a peer minimising segment size controls.
    //
    // It stops counting at the hand-off. What is resident downstream — the raw-app
    // channel and the per-stream demux channels — is bounded by those channels' own
    // depths, and in bytes by the frame gate that decides what a slot can hold.
    // Folding it into this counter would mean tearing a session down because the
    // local application stopped reading, which is neither the peer's fault nor what
    // the hard cap is for.
    //
    // The flow-control limit is advanced in Task A / Task B immediately on dequeue
    // (one item of look-ahead, cancel-safe: mpsc send drops the item on cancel
    // but cannot double-count because we already subtracted from undelivered_bytes
    // before the blocking send).
    //
    // HoL among opened streams (id ≥ 2): Task B is a single sequential task, so
    // a consumer that never calls PhantomStream::recv() will eventually fill the
    // per-stream bounded channel and backpressure Task B → streams_deliver_tx
    // (UNBOUNDED, can grow). This is accepted behaviour; per-stream independent
    // tasks are future work. The raw-app path is NOT affected. What fills that
    // channel is only ever what the peer sent on the stream — its data and its FIN,
    // never this side's own acknowledgements — so a stream the application only
    // writes to cannot fill it.

    // Downstream UNBOUNDED channels (the Router → Tasks A/B paths never block).
    let (raw_deliver_tx, mut raw_deliver_rx) = mpsc::unbounded_channel::<(Bytes, bool)>();
    let (streams_deliver_tx, mut streams_deliver_rx) = mpsc::unbounded_channel::<DeliverItem>();

    let undelivered_bytes = Arc::new(AtomicU64::new(0));

    // Task A — raw-app (id 0 / 1) delivery. Semantics unchanged by the decoupling.
    {
        let recv_tx_deliver = recv_tx; // move the session recv channel here
        let streams_a = streams.clone();
        let crypto_a = crypto_session.clone();
        let undelivered_a = undelivered_bytes.clone();
        runtime.spawn(Box::pin(async move {
            while let Some((bytes, reliable)) = raw_deliver_rx.recv().await {
                let len = bytes.len() as u64;
                // Decrement backlog counter before the blocking send — see comment
                // on `undelivered_bytes` above. The figure released is the one the
                // reader charged: payload plus item structure.
                undelivered_a.fetch_sub(delivery_charge(bytes.len()), Ordering::AcqRel);
                // Credit the flow-control window for the raw-app stream (id 1).
                if let Some(stream) = streams_a.get(&RAW_APP_STREAM_ID) {
                    if let Some(limit) = stream.record_app_consumed(len as u32, reliable) {
                        stream.stage_window_update_limit(limit);
                        crypto_a.notify_outbound_ready();
                    }
                }
                // App-paced delivery to the session recv channel. A closed channel
                // means the consumer is gone → session ending; stop.
                if recv_tx_deliver.send(bytes).await.is_err() {
                    break;
                }
            }
        }));
    }

    // Task B — opened-stream (id ≥ 2) delivery. Independent of Task A.
    {
        let demux_b = demux.clone();
        let streams_b = streams.clone();
        let crypto_b = crypto_session.clone();
        let undelivered_b = undelivered_bytes.clone();
        runtime.spawn(Box::pin(async move {
            while let Some(item) = streams_deliver_rx.recv().await {
                match item {
                    DeliverItem::Data(stream_id, bytes, reliable) => {
                        let len = bytes.len() as u64;
                        undelivered_b.fetch_sub(delivery_charge(bytes.len()), Ordering::AcqRel);
                        // Credit flow-control for this opened stream.
                        if let Some(stream) = streams_b.get(&stream_id) {
                            if let Some(limit) = stream.record_app_consumed(len as u32, reliable) {
                                stream.stage_window_update_limit(limit);
                                crypto_b.notify_outbound_ready();
                            }
                        }
                        // Blocking, lossless delivery to the per-stream demux channel.
                        if !demux_b.route_data_async(stream_id, bytes).await {
                            log::debug!(
                                "PhantomSession: opened-stream delivery: stream {} not \
                                 registered, frame discarded",
                                stream_id
                            );
                        }
                    }
                    DeliverItem::Close(stream_id) => {
                        undelivered_b.fetch_sub(delivery_charge(0), Ordering::AcqRel);
                        // Lossless FIN delivery (ordered after any data above).
                        if !demux_b.route_close_async(stream_id).await {
                            log::debug!(
                                "PhantomSession: opened-stream delivery: FIN for \
                                 unregistered stream {}",
                                stream_id
                            );
                        }
                    }
                    DeliverItem::Retire(stream_id) => {
                        // Everything the stream had to deliver is in its channel by now,
                        // so dropping the route only ends the channel after it.
                        demux_b.close_stream(stream_id);
                    }
                }
            }
        }));
    }

    // Router task — dispatches items from the UNBOUNDED deliver_tx to Task A or B.
    // Both targets are UNBOUNDED so every send succeeds immediately (no .await);
    // errors only occur when the receiver is dropped (session shutting down).
    // Router exits when the reader drops deliver_tx, allowing Tasks A/B to drain.
    let (deliver_tx, mut deliver_router_rx) = mpsc::unbounded_channel::<DeliverItem>();
    {
        let raw_tx_r = raw_deliver_tx;
        let streams_tx_r = streams_deliver_tx;
        let undelivered_r = undelivered_bytes.clone();
        runtime.spawn(Box::pin(async move {
            while let Some(item) = deliver_router_rx.recv().await {
                match item {
                    DeliverItem::Data(stream_id, bytes, reliable) => {
                        if stream_id <= RAW_APP_STREAM_ID {
                            // UNBOUNDED → never blocks; error only if Task A dropped.
                            let _ = raw_tx_r.send((bytes, reliable));
                        } else {
                            let _ =
                                streams_tx_r.send(DeliverItem::Data(stream_id, bytes, reliable));
                        }
                    }
                    DeliverItem::Close(stream_id) => {
                        if stream_id > RAW_APP_STREAM_ID {
                            let _ = streams_tx_r.send(DeliverItem::Close(stream_id));
                        } else {
                            // Close on id 0/1 is not used in the current protocol; discard.
                            // Discarding is where the charge has to be released — nothing
                            // downstream will see this item, and a charge nobody releases is
                            // a counter that only climbs, which a peer emitting FINs on the
                            // raw-app id would ride into a false teardown.
                            undelivered_r.fetch_sub(delivery_charge(0), Ordering::AcqRel);
                        }
                    }
                    DeliverItem::Retire(stream_id) => {
                        // Only opened streams are ever retired; ids 0 and 1 have no route.
                        if stream_id > RAW_APP_STREAM_ID {
                            let _ = streams_tx_r.send(DeliverItem::Retire(stream_id));
                        }
                    }
                }
            }
            // Router done: Tasks A/B will drain remaining items and exit naturally.
        }));
    }

    // ── Receive (reader) task: deserialize, decrypt, hand off to delivery ──
    let transport_recv = transport.clone();
    let transport_send_ack = transport.clone();
    let crypto_recv = crypto_session.clone();
    // The FFI-visible state, written from the receive side too: the peer's close
    // arrives here, and the accessors that must stop claiming the session can carry a
    // write read this atomic (see `ConnectionState::Draining`).
    let state_recv = state.clone();
    let demux_recv = demux.clone();
    let streams_recv = streams.clone();
    let undelivered_reader = undelivered_bytes.clone();
    let observability_recv = observability.clone();
    let stream_gauge_recv = stream_gauge.clone();
    // Clones moved into the recv task for new-stream registration.
    let stream_link_recv = stream_link.clone();
    let incoming_stream_tx_recv = incoming_stream_tx.clone();
    let terminal_error_recv = terminal_error.clone();
    // Completion signal for the receive task. `SpawnHandle` from the
    // runtime trait does not expose a `Future` for `.await` directly
    // (different runtimes provide different join futures), so we wire a
    // one-shot channel — the recv task sends `()` right before exiting
    // and the main loop selects on the receiver to detect transport
    // closure.
    let (recv_done_tx, mut recv_done_rx) = oneshot::channel::<()>();
    let transport_for_path = transport.clone();
    // Outstanding PATH_CHALLENGE start stamps. Created here (not inside the
    // reader task) because BOTH halves of the pump touch it: the reader issues
    // and resolves challenges, and the send loop's heartbeat expires the ones
    // that are never answered (`sweep_path_validation_timeouts`).
    let path_challenges = Arc::new(PathChallenges::default());
    let path_challenges_recv = path_challenges.clone();
    let recv_handle = runtime.spawn(Box::pin(async move {
        // Reader-local scratch: the reusable ACK frame serialization buffer
        // (hoisted out of the loop since Phase 2.3 so we don't pay a fresh
        // `Vec::new()` allocation for every ACK we emit on a busy reliable
        // stream — 256 bytes is comfortably larger than a serialized empty
        // `PhantomPacket`, the 15-byte header plus the AEAD tag, so the
        // underlying buffer is never reallocated after the first frame) plus
        // the observability bookkeeping the receive path needs.
        let mut scratch =
            RecvScratch::new(256, stream_gauge_recv, path_challenges_recv, recv_tuning);
        // Draining (WIRE v8): the instant this loop stops reading once the peer has
        // announced its close. `None` until the first close copy is handled, and
        // computed exactly once from a window the peer cannot extend.
        let mut drain_deadline: Option<std::time::Instant> = None;
        // Resolves once the transport gives up on the peer — almost always because one
        // of the send loop's writes waited out its deadline while this loop sat in a
        // read that same peer is not answering. Built once, outside the loop, so its
        // waiter is registered once rather than on every packet.
        let given_up = transport_recv.given_up();
        tokio::pin!(given_up);
        loop {
            // Flow-control / anti-flood gate: if the app-delivery backlog
            // has blown past the cap, the peer is not honouring the window —
            // close instead of growing the in-memory queue unboundedly. Cheap
            // pre-check, before any AEAD work.
            if undelivered_reader.load(Ordering::Acquire) > RECV_DELIVERY_HARD_CAP {
                log::warn!(
                    "PhantomSession: receive backlog {} B exceeds cap — peer ignoring flow \
                     control; closing session",
                    undelivered_reader.load(Ordering::Acquire)
                );
                break;
            }
            // A read abandoned here may be part-way through a frame, which is harmless:
            // the transport is not read again.
            let data = tokio::select! {
                received = transport_recv.recv_bytes() => match received {
                    Ok(b) => b,
                    Err(_) => break,
                },
                () = &mut given_up => break,
            };

            // Frame-size gate. Everything below this line ends up in a queue that is
            // bounded in slots rather than in bytes, so a slot holds whatever a peer
            // chooses to put in it unless something refuses the oversized frame first.
            // The chunk size the sender works to is not that something: it is this
            // side's budget, and the byte pipe underneath will hand over megabytes
            // (`STEADY_STATE_FRAME_CAP` on the TCP and mimicry legs, a reassembled
            // datagram on PhantomUDP). `MAX_RECV_FRAME` is the same budget read from
            // the receiving end.
            //
            // Dropped, not fatal. The frame is unauthenticated at this point — nothing
            // has been through the AEAD yet — so tearing the session down here would
            // hand an off-path attacker who guesses a connection id a way to kill a
            // session with one datagram. A peer that really is sending oversized frames
            // stalls instead: the segment is never delivered, never SACKed, and its
            // retransmits meet the same gate.
            if data.len() > MAX_RECV_FRAME {
                log::debug!(
                    "PhantomSession: dropping {} B frame; the receive budget is \
                     {MAX_RECV_FRAME} B",
                    data.len()
                );
                continue;
            }

            // Remove header protection (T4.6) and parse: a malformed / unparseable
            // / short-of-the-AEAD-tag frame (no legitimate peer produces one) is
            // dropped — never a panic. Since WIRE v6 the WHOLE 15-byte header is
            // HP-masked (`HP_PROTECTED_OFFSET == 0`, no cleartext header byte on
            // the wire); `parse_protected` unmasks it with this session's recv HP
            // key and reconstructs the off-wire 32-byte `session_id` from session
            // context before the header is interpreted.
            let packet = match crypto_recv.parse_protected(&data) {
                Ok(v) => v,
                Err(_) => continue,
            };
            // Pinned wire-version gate: the format is not negotiated, so a
            // frame carrying any other version byte is dropped.
            if packet.header.version != WIRE_VERSION {
                continue;
            }
            handle_packet(
                packet,
                session_id,
                &crypto_recv,
                &streams_recv,
                &demux_recv,
                &transport_send_ack,
                &transport_for_path,
                &deliver_tx,
                &undelivered_reader,
                &mut scratch,
                &observability_recv,
                leg,
                &stream_link_recv,
                &incoming_stream_tx_recv,
                &state_recv,
            )
            .await;
            // The peer announced its close on the packet just handled (WIRE v8).
            // Checked here rather than acted on inside `handle_packet` so the loop
            // ends the same way it ends for a dead transport — everything already
            // delivered stays queued for the delivery task, and the pump learns of
            // it through the one signal it already watches.
            //
            // It does not end *now*, though. The close is not `RELIABLE`, carries no
            // stream offset and is never acknowledged, so nothing re-sends whatever
            // it overtakes; on a datagram path a single one-position reorder is
            // enough for it to arrive ahead of data the peer's `send()` already
            // returned `Ok` for, and stopping here would discard those bytes with no
            // error at either end. So the session drains instead: it keeps reading
            // for a bounded window and only then lets go. The deadline is taken once,
            // on the first copy, and never moved — a peer that keeps sending cannot
            // hold this loop open by talking.
            if crypto_recv.peer_closed() {
                // Publish the draining state from here — the packet boundary at which
                // the close is recorded — rather than leaving it to the send loop's
                // next 10 ms tick. `send()` reads this atomic and nothing else, so for
                // however long it lags the recorded close, the API is handing callers
                // `Ok` for payloads the pump has already decided to discard. That is
                // the defect the state exists to remove, so the two must not be
                // separated by a scheduling interval.
                state_recv.store(ConnectionState::Draining as u8, Ordering::Relaxed);
                let deadline = *drain_deadline.get_or_insert_with(|| {
                    std::time::Instant::now() + peer_close_drain_window(&crypto_recv)
                });
                if std::time::Instant::now() >= deadline {
                    break;
                }
            }
        }
        // A transport that gave up on the peer ends the session with a cause, and the
        // cause is written here, before `deliver_tx` goes, rather than by the send loop
        // when it hears this task finish. Dropping `deliver_tx` is what eventually
        // closes the channel `recv()` waits on, and a `recv()` woken by that reads the
        // slot at once — a cause written any later would reach it as a bare "closed".
        // A peer that announced its own close is the exception: the session is ending
        // in the orderly way, and a write that failed during its drain is no failure
        // of the session's.
        //
        // `Dead` is published here too, after the cause, for the same reason: the send
        // loop's teardown publishes it as well, but only once it has noticed this task
        // finish, and until then `connection_state()` would go on reading `Connected`
        // while `recv()` already reports the session over — and `send()`, which reads
        // the state, would go on accepting writes the transport refuses. Nothing walks
        // it back: the teardown publishes the same `Dead` on the same condition (the
        // give-up is never cleared, and nothing but this task records a peer close);
        // the liveness verdict leaves an ended session alone (`publish_unless_ended`);
        // the tick arm's `Draining` follows a peer close, which rules this path out;
        // and `disconnect()`, called from the application's thread, leaves `Dead` and
        // `Failed` in place.
        if transport_recv.has_given_up() && !crypto_recv.peer_closed() {
            record_terminal_cause(&terminal_error_recv, CoreError::Timeout);
            state_recv.store(ConnectionState::Dead as u8, Ordering::Relaxed);
        }
        // Reader exiting → drop `deliver_tx` so the delivery task drains any
        // queued items and then sees the channel closed and exits.
        drop(deliver_tx);
        // Signal the main loop that the recv task has exited so it can
        // also unwind. `send` returns `Err(())` if the receiver was
        // already dropped — that case is harmless, the main loop has
        // already shut down.
        let _ = recv_done_tx.send(());
    }));

    // Phase 2.4: the 10 ms `poll_interval` stays as a retransmit-timer
    // fallback (streams without an explicit notifier reference still
    // get swept), but `send_notify.notified()` joins the select! so the
    // pump wakes immediately when a producer calls
    // `Session::notify_outbound_ready()`. This drops idle CPU usage to
    // zero on quiet sessions while keeping the worst-case post-queue
    // latency at <10 ms even for producers that haven't been wired into
    // the notifier yet.
    let mut poll_interval = tokio::time::interval(std::time::Duration::from_millis(10));
    let send_notify = crypto_session.send_notifier();
    // Liveness keep-alive bookkeeping (P4.3): `Some(t)` while in the `Migrating`
    // window (the pump-local truth + how long); `died` records a death — the idle
    // timeout here, or a transport that gave up on its peer, at the teardown — so the
    // teardown publishes `Dead` instead of overwriting it with `Closed`.
    let mut migrating_since: Option<std::time::Instant> = None;
    let mut died = false;
    // Idle keep-alive bookkeeping (download-only liveness): the
    // pump-local instant of the last keep-alive PING we emitted, so we send at most
    // one per `keepalive_interval` (no 10 ms-heartbeat spam). Seeded at "now" so the
    // first PING waits a full interval after the data plane starts.
    let mut last_keepalive = std::time::Instant::now();
    // Cover-traffic bookkeeping (WIRE v6): the send PN observed at
    // the last cover check, and the instant of the last observed outbound activity.
    // Any real packet advances the PN, resetting the idle window, so cover only
    // fills genuine gaps (idle-fill + a floor rate). Seeded at "now"/current PN.
    let mut last_outbound_pn = crypto_session.peek_send_pn();
    let mut last_outbound_at = std::time::Instant::now();
    // Pacing bookkeeping: when the last drain stopped for want of pacing credit,
    // the instant the pacer said credit would be back. `None` means the last
    // drain did not stop on pacing, and the branch below stays disabled.
    //
    // The wait lives here, as a `select!` *branch*, and not inside the drain. An
    // arm body runs to completion, so a sleep taken inside `drain_streams_*`
    // parks the whole pump — no flow-control limit for the reverse direction,
    // no commands accepted, no liveness sweep — which is the exact shape that
    // collapsed the download under a saturating upload. Pacing must slow the
    // sender, not stop the session.
    let mut paced_until: Option<tokio::time::Instant> = None;
    // Draining (WIRE v8): the instant this pump tears down once the peer has
    // announced its close, or `None` while it has not. The receive task runs the same
    // deadline at a packet boundary, which is the clean exit; this one covers the case
    // the receive task cannot see, namely that nothing further arrives at all — a
    // reader parked in `recv_bytes()` has no boundary at which to notice a deadline.
    let mut draining_until: Option<std::time::Instant> = None;
    // Outbound WINDOW_UPDATE control packets are emitted on the send loop — the
    // sole outbound writer — so the encrypted control frame is always sealed under
    // the epoch live when it stamps. The epoch has two writers (this loop's own
    // `rekey()` and the receive task's authenticated forward catch-up in
    // `decrypt_packet_accepting_rekey`), but both serialise through the session's
    // `rekey_lock`, so the seal is always epoch-consistent. The delivery task only
    // stages the cumulative limit (`Stream::stage_window_update_limit`) and
    // wakes us; the wire sequence is drawn from the stream's own send-sequence
    // space inside `flush_pending_window_updates` (no private counter, so it
    // can never collide with application data on the AEAD nonce).

    loop {
        // tokio evaluates a disabled branch's expression and simply never polls
        // the future, so this needs a real instant even when there is no pacing
        // deadline. An hour out is "never" at this loop's timescale.
        let paced_wake = paced_until
            .unwrap_or_else(|| tokio::time::Instant::now() + std::time::Duration::from_secs(3600));
        tokio::select! {
            _ = poll_interval.tick() => {
                // Draining (WIRE v8). The peer said it is leaving, so this side stops
                // producing and keeps consuming for a bounded window: the receive task
                // is still delivering whatever was in flight behind the close, and the
                // demux route retire at the foot of this function is deferred until
                // this loop exits, which is what keeps those datagrams routable while
                // it is. Armed once from a window computed once — see
                // `peer_close_drain_window` for why the peer cannot lengthen it.
                if draining_until.is_none() && crypto_session.peer_closed() {
                    let window = peer_close_drain_window(&crypto_session);
                    log::info!(
                        "PhantomSession: peer announced session close; draining for {window:?}"
                    );
                    draining_until = Some(std::time::Instant::now() + window);
                    // The receive task normally publishes this first, at the packet
                    // that carried the close. Repeated here because the flag is set
                    // inside `handle_packet`, so this loop can in principle observe it
                    // before the receive loop reaches its own check — and a state that
                    // still says `Connected` while this arm refuses writes is exactly
                    // the disagreement between accessors that has to not exist.
                    state.store(ConnectionState::Draining as u8, Ordering::Relaxed);
                }
                if let Some(until) = draining_until {
                    if std::time::Instant::now() >= until {
                        break;
                    }
                    // Nothing outbound while draining: the peer's session is ending, so
                    // new data has nowhere to arrive, a keep-alive has nobody to answer
                    // it, and a liveness verdict about a path the peer has abandoned
                    // would only publish a state this teardown is about to overwrite.
                    continue;
                }
                flush_deferred_sends(
                    &mut deferred, &transport, &crypto_session, session_id, &streams,
                    &demux, &stream_gauge, &observability,
                )
                .await;
                flush_pending_window_updates(
                    &transport, &crypto_session, session_id, &streams, &observability,
                )
                .await;
                // Stopped on the per-pass segment budget with work left? Come
                // straight back after the other arms get a turn. Stopped for
                // want of pacing credit? Come back when there is some.
                paced_until = apply_drain_outcome(
                    &crypto_session,
                    drain_streams_priority_ordered(
                        &transport,
                        &crypto_session,
                        session_id,
                        &streams,
                        &observability,
                    )
                    .await,
                    !deferred.is_empty() || !cmd_rx.is_empty(),
                );
                // Idle keep-alive (download-only liveness): on an
                // otherwise-idle Connected path, emit one small ENCRYPTED PING so a
                // download-only path (which sends only ACKs) has an outstanding probe
                // to anchor the liveness sweep below — and the peer's PONG refreshes
                // its activity timer. Runs before the sweep so a just-emitted PING is
                // already marked outstanding this tick.
                maybe_send_keepalive(
                    &transport, &crypto_session, session_id, &mut last_keepalive, &observability,
                )
                .await;
                // Cover traffic (WIRE v6): on this same heartbeat,
                // maintain the minimum outbound packet rate — emit a COVER dummy when
                // the outbound path has been idle past the floor interval. No-op when
                // cover is disabled (default) or real traffic is flowing.
                maybe_send_cover(
                    &transport,
                    &crypto_session,
                    session_id,
                    &mut last_outbound_pn,
                    &mut last_outbound_at,
                    &observability,
                )
                .await;
                // Path-validation expiry sweep: abandon (and report) any
                // PATH_CHALLENGE the peer never answered. Runs on the same
                // heartbeat as the liveness sweep because it is the same class of
                // question — "is this path carrying traffic?" — and shares its
                // threshold. Metrics + bookkeeping only; no session state moves.
                sweep_path_validation_timeouts(
                    &crypto_session, &path_challenges, &observability,
                );
                // Liveness sweep (P4.3): the 10 ms heartbeat is the reliable place to
                // evaluate inbound silence vs. outstanding data and surface
                // Migrating / recover / Dead. A `Dead` verdict ends the pump.
                // A death decided there has no failing call site to carry a cause, so
                // `apply_liveness` records one itself, before it publishes the state.
                if apply_liveness(&crypto_session, &state, &terminal_error, &mut migrating_since)
                {
                    died = true;
                    break;
                }
            }
            // Disabled while draining: this arm exists to put newly-queued bytes on
            // the wire promptly, and a session whose peer has announced its close has
            // nowhere to put them.
            _ = send_notify.notified(), if draining_until.is_none() => {
                // Same drain logic as the tick arm — fast-wake path. Also admit
                // whatever the send buffers have room for now (an acknowledgement
                // that freed a slot wakes us here) and flush any flow-control
                // limit the delivery task staged.
                flush_deferred_sends(
                    &mut deferred, &transport, &crypto_session, session_id, &streams,
                    &demux, &stream_gauge, &observability,
                )
                .await;
                flush_pending_window_updates(
                    &transport, &crypto_session, session_id, &streams, &observability,
                )
                .await;
                paced_until = apply_drain_outcome(
                    &crypto_session,
                    drain_streams_priority_ordered(
                        &transport,
                        &crypto_session,
                        session_id,
                        &streams,
                        &observability,
                    )
                    .await,
                    !deferred.is_empty() || !cmd_rx.is_empty(),
                );
            }
            // Pacing wake-up. Armed only while the previous drain stopped for
            // want of credit, so an unpaced session never registers this timer
            // at all. It exists because the 10 ms heartbeat above is too coarse
            // to be a pacing clock: at a 16 KiB burst allowance, waking only
            // every 10 ms caps the sender at 1.6 MB/s no matter what rate
            // congestion control asked for.
            _ = tokio::time::sleep_until(paced_wake),
                if paced_until.is_some() && draining_until.is_none() => {
                paced_until = apply_drain_outcome(
                    &crypto_session,
                    drain_streams_priority_ordered(
                        &transport,
                        &crypto_session,
                        session_id,
                        &streams,
                        &observability,
                    )
                    .await,
                    !deferred.is_empty() || !cmd_rx.is_empty(),
                );
            }
            // The local close: `disconnect()`, or the handle dropped. On an arm of its
            // own and not gated on `deferred`, which is the whole reason it is not a
            // command. The command arm is disabled while a refused write is held, and
            // a refused write is held until the peer acknowledges data its own window
            // may forbid sending — so a peer that stopped reading, while still
            // answering probes and keep-alives, could hold a close queued behind that
            // write for as long as it chose. `changed()` also resolves once the
            // handle's sender is gone, which is the same request.
            //
            // A graceful close with TCP-FIN shape: push what is queued, then announce.
            // What is queued includes commands the application handed over before it
            // asked to close, which the command arm has not necessarily read — the two
            // arms can be ready at once — so they are taken in here, in order, for as
            // long as the send buffers admit them. That is where the command arm stops
            // too, and it keeps `send(x); disconnect()` pushing `x` exactly as it did
            // when the close waited in line behind it. Nothing here waits on the peer:
            // a write still refused once the drain is done is a write this close
            // discards, which is what `disconnect()` documents.
            _ = close_requested.changed() => {
                log::info!("PhantomSession: closing");
                if !crypto_session.peer_closed() {
                    // Control queued ahead of the close is carried out first, so a
                    // migration requested before it decides which path the flush below
                    // goes out on. The two arms can be ready at once, and nothing else
                    // would read that channel again.
                    for _ in 0..control_rx.len() {
                        let Ok(control) = control_rx.try_recv() else {
                            break;
                        };
                        take_control(control, &transport, &crypto_session, &streams, &observability)
                            .await;
                    }
                    flush_deferred_sends(
                        &mut deferred, &transport, &crypto_session, session_id, &streams,
                        &demux, &stream_gauge, &observability,
                    )
                    .await;
                    // Only what was queued when the close was seen, so a writer still at
                    // work on another handle cannot keep a closing session busy.
                    for _ in 0..cmd_rx.len() {
                        if !deferred.is_empty() {
                            break;
                        }
                        let Ok(cmd) = cmd_rx.try_recv() else {
                            break;
                        };
                        // A `Close` among them asks for what is already under way.
                        take_command(
                            cmd, &raw_stream, &mut deferred, &transport, &crypto_session,
                            session_id, &streams, &demux, &stream_gauge, &observability,
                        )
                        .await;
                    }
                }
                finish_and_announce(
                    &transport, &crypto_session, session_id, &streams, &observability,
                )
                .await;
                if !deferred.is_empty() {
                    log::debug!(
                        "PhantomSession: the close discards {} chunk(s) the send buffers \
                         never admitted",
                        deferred.len()
                    );
                }
                break;
            }
            // Control that writes nothing — a migration, a stream's priority. On an arm of
            // its own and not gated on `deferred`, for the reason the local close is: the
            // command arm below stops while a refused write is held, and on a path that has
            // died a refused write is held until a migration brings the acknowledgements
            // back. `ControlCommand` says what ordering this keeps and what it gives up.
            // Not disabled while draining either: the command arm never refused these.
            Some(control) = control_rx.recv() => {
                take_control(control, &transport, &crypto_session, &streams, &observability)
                    .await;
            }
            // A stream handle the application dropped. Only recorded here, with the number
            // of commands the pump has to take before every write that handle queued is in
            // (see `releases`); acted on as soon as that many have been — at once, if the
            // channel holds nothing. Never gated: a report that waited on the command arm
            // could wait as long as that arm does, and the channel it arrives on grows.
            Some(stream_id) = released_rx.recv() => {
                releases.push_back((stream_id, commands_taken + cmd_rx.len() as u64));
                release_due_streams(
                    &mut releases, commands_taken, &mut deferred, &transport, &crypto_session,
                    session_id, &streams, &demux, &stream_gauge, &observability,
                )
                .await;
            }
            // Disabled while `deferred` holds work: the queue must clear in FIFO
            // order before another command is taken, which is what preserves
            // per-stream byte ordering and lets the bounded command channel carry
            // the backpressure back to the caller.
            cmd_opt = cmd_rx.recv(), if deferred.is_empty() => {
                if cmd_opt.is_some() {
                    commands_taken += 1;
                }
                // Draining (WIRE v8): the local side may still hand this pump writes
                // after the peer has announced its close. They are refused rather than
                // queued — the peer's session is over, so a byte accepted here would
                // be a byte silently dropped at teardown. This is the second half of
                // that refusal and not the first: `ConnectionState::Draining` is
                // published the moment the close is recorded, and the send API reads it
                // and returns an error, so what reaches here is only what was already
                // in the channel or what raced the publish by less than a scheduling
                // point. Dropping those silently is the residue of a genuine race and
                // not a window — which is what the state moved it from. The arm keeps
                // *reading* commands so the ones that are not writes still land; only
                // the writes are declined.
                if draining_until.is_some()
                    && matches!(
                        cmd_opt,
                        Some(SessionCommand::Send(_))
                            | Some(SessionCommand::SendStreamReliable { .. })
                            | Some(SessionCommand::SendStreamUnreliable { .. })
                            | Some(SessionCommand::CloseStream { .. })
                    )
                {
                    log::debug!(
                        "PhantomSession: refusing an application write while draining the \
                         peer's close"
                    );
                    release_due_streams(
                        &mut releases, commands_taken, &mut deferred, &transport,
                        &crypto_session, session_id, &streams, &demux, &stream_gauge,
                        &observability,
                    )
                    .await;
                    continue;
                }
                let Some(cmd) = cmd_opt else {
                    log::info!("PhantomSession: command channel dropped");
                    // The outer `PhantomSession` handle was dropped. Data already
                    // handed to `send()` was routed onto the raw-app stream but may
                    // not have hit the wire yet (transmission happens on the next
                    // tick / notify of THIS loop). Flush it before exiting so a
                    // fire-and-forget `send()` immediately followed by dropping the
                    // handle still reaches the peer — otherwise a freshly-accepted
                    // server session that does `recv(); send(echo)` then drops loses
                    // the echo, and the client's `recv()` hangs to its timeout.
                    finish_and_announce(
                        &transport, &crypto_session, session_id, &streams, &observability,
                    )
                    .await;
                    break;
                };
                if take_command(
                    cmd, &raw_stream, &mut deferred, &transport, &crypto_session, session_id,
                    &streams, &demux, &stream_gauge, &observability,
                )
                .await
                {
                    log::info!("PhantomSession: closing");
                    // A `Close` that came down the channel: the same graceful close as
                    // the local close request above — push what is queued, then
                    // announce — bearing in mind that "push" is what the drain does and
                    // not "deliver", which is what `disconnect()`'s own documentation
                    // says out loud.
                    finish_and_announce(
                        &transport, &crypto_session, session_id, &streams, &observability,
                    )
                    .await;
                    break;
                }
                // Behind the command just taken, which may have been the last write of a
                // handle whose drop is waiting on it.
                release_due_streams(
                    &mut releases, commands_taken, &mut deferred, &transport, &crypto_session,
                    session_id, &streams, &demux, &stream_gauge, &observability,
                )
                .await;
            }
            _ = &mut recv_done_rx => {
                if crypto_session.peer_closed() {
                    // The peer announced its close and the receive loop has finished
                    // draining behind it. Nothing is wrong and nothing is owed back:
                    // answering a close with a close would only make two sessions each
                    // wait for the other's last word.
                    log::info!("PhantomSession: peer closed the session");
                } else if transport.has_given_up() {
                    log::warn!(
                        "PhantomSession: the transport gave up on a peer that stopped taking \
                         bytes; ending the session"
                    );
                } else {
                    log::error!(
                        "PhantomSession: receive task ended unexpectedly (transport closed)"
                    );
                }
                break;
            }
        }
    }

    // A transport that gave up on its peer ends the session as a death, whichever arm
    // above happened to notice first: the receive task finishing, or a local close that
    // raced it — in which case the close was not announced, because the write carrying
    // it was refused. Recorded before the receive task is aborted, since aborting it is
    // what starts closing the channel `recv()` waits on. The receive task records the
    // same cause on its own way out; whichever comes second finds the slot taken.
    if transport.has_given_up() && !crypto_session.peer_closed() {
        record_terminal_cause(&terminal_error, CoreError::Timeout);
        state.store(ConnectionState::Dead as u8, Ordering::Relaxed);
        died = true;
    }

    // Abort the recv task if it's still running; idempotent on a finished
    // handle. Goes through the runtime-agnostic `SpawnHandle::abort`.
    recv_handle.abort();
    // Release this session's demux routes (WIRE v8). On the PhantomUDP server this is
    // what actually frees the slot: the route table is keyed on connection ids the
    // demux cannot recompute, and its other reclaim triggers all wait for a datagram
    // that a departed peer will never send. Placed on the common teardown path rather
    // than in the graceful-close arm, because a session ends five ways and the routes
    // should go on all of them. A no-op everywhere but the UDP server.
    //
    // Reaching it is what ends the draining window on the receiving side, and that
    // ordering is load-bearing rather than incidental: retiring the routes is the
    // second way a late datagram gets discarded — one that finds no route is not an
    // `Initial`, so the demux drops it before any session sees it — so the retire has
    // to wait for the same deadline the receive loop does, and it does that by being
    // here rather than at the moment the close was read.
    crypto_session.signal_route_retire();
    // A death — the liveness idle timeout, or the transport giving up above — has
    // already published `ConnectionState::Dead`; only a normal teardown (graceful close
    // / transport drop) publishes `Closed`.
    if !died {
        state.store(ConnectionState::Closed as u8, Ordering::Relaxed);
    }
    // Retire every stream still open on this session so the active-streams gauge
    // comes back down on EVERY pump exit — graceful close, handle drop, transport
    // death, and the liveness `Dead` verdict alike. `drain()` swaps the counter to
    // zero atomically, so the identical drain in `Drop for PhantomSession` (which
    // covers an `open_stream()` issued after the pump already ended) cannot
    // double-retire.
    stream_gauge.drain();
    // Session torn down — drop the active-session gauge back down.
    observability.session_closed(leg);
}

/// How much application data goes into one packet. Derived from the PhantomUDP
/// datagram budget (`transport::mtu`) so that a full chunk plus its header, its
/// in-plaintext stream offset and its AEAD tag is exactly one unfragmented
/// datagram: a chunk one byte over the budget would be split into a full
/// datagram plus a short tail, which doubles the datagram rate and makes the
/// segment need both halves to survive. On the byte-pipe legs the same constant
/// just sets the framing granularity.
const APP_CHUNK: usize = crate::transport::mtu::MAX_APP_CHUNK;

/// Take one application command into the pump.
///
/// Two callers: the command arm, one command per turn, and the local close, which
/// takes in what was queued ahead of it before it announces. Nothing here waits on
/// the peer — a write the send buffer cannot take yet stays at the tail of
/// `deferred`, and that is what tells the command arm to stop reading. Returns `true`
/// for [`SessionCommand::Close`] and leaves acting on it to the caller, because
/// ending the session is the loop's decision.
#[allow(clippy::too_many_arguments)]
async fn take_command<T: SessionTransport>(
    cmd: SessionCommand,
    raw_stream: &Arc<Stream>,
    deferred: &mut VecDeque<Deferred>,
    transport: &Arc<T>,
    crypto_session: &Arc<Session>,
    session_id: SessionId,
    streams: &Arc<DashMap<u32, Arc<Stream>>>,
    demux: &Arc<StreamDemultiplexer>,
    stream_gauge: &Arc<StreamGauge>,
    observability: &Observability,
) -> bool {
    match cmd {
        SessionCommand::Send(data) => {
            // Route through the raw-app stream so the payload is
            // buffered for retransmit until ACKed (drained by
            // `drain_streams_priority_ordered`), instead of being
            // fired once and forgotten on the wire. Admission goes
            // through `deferred` so a full send buffer refuses the
            // chunk instead of parking this whole loop.
            for chunk in data.chunks(APP_CHUNK) {
                deferred.push_back(Deferred::Data {
                    stream: raw_stream.clone(),
                    data: Bytes::copy_from_slice(chunk),
                });
            }
            flush_deferred_sends(
                deferred,
                transport,
                crypto_session,
                session_id,
                streams,
                demux,
                stream_gauge,
                observability,
            )
            .await;
            crypto_session.notify_outbound_ready();
        }
        SessionCommand::SendStreamReliable { stream_id, data } => {
            // Clone the Arc out and drop the DashMap guard before any
            // await — the shard lock must never be held across one.
            let stream = streams.get(&stream_id).map(|s| s.clone());
            if let Some(stream) = stream {
                for chunk in data.chunks(APP_CHUNK) {
                    deferred.push_back(Deferred::Data {
                        stream: stream.clone(),
                        data: Bytes::copy_from_slice(chunk),
                    });
                }
                flush_deferred_sends(
                    deferred,
                    transport,
                    crypto_session,
                    session_id,
                    streams,
                    demux,
                    stream_gauge,
                    observability,
                )
                .await;
            }
        }
        SessionCommand::SendStreamUnreliable { stream_id, data } => {
            let stream = streams.get(&stream_id).map(|s| s.clone());
            // Nothing follows a FIN, unreliable or not: the peer has already
            // been told the stream ended.
            if let Some(stream) = stream.filter(|s| !s.is_local_finished()) {
                for chunk in data.chunks(APP_CHUNK) {
                    stream.send_unreliable(Bytes::copy_from_slice(chunk)).await;
                }
            }
        }
        SessionCommand::CloseStream { stream_id } => {
            // Reliable FIN over ARQ: enqueue a zero-length reliable
            // FIN sentinel rather than firing a bare (unreliable) FIN.
            // The sentinel goes through the same send buffer + retransmit
            // machinery as all other reliable data, so it is guaranteed to
            // be delivered in order and acknowledged by the peer even under
            // packet loss. It closes this side's half only: the stream stays
            // in `streams` and `demux` — still receiving — until the FIN is
            // acknowledged AND either the peer's own FIN has been released in
            // order or the application has dropped its handle, and the receive
            // path or the pump drops it then.
            //
            // Invariant 2 is preserved: the FIN packet is sealed with
            // ENCRYPTED | RELIABLE | FIN — a forged unencrypted one is
            // dropped at the AEAD gate before FIN processing (the existing
            // "must have ENCRYPTED" gate in handle_packet). The security
            // invariant test `forged_unencrypted_fin_does_not_close_a_stream`
            // continues to pass because the drop happens before any FIN logic.
            //
            // Queued through `deferred` like any other reliable write,
            // so it lands strictly after the bytes queued before it and
            // a full send buffer refuses it rather than parking the
            // pump. `flush_deferred_sends` carries the offset-exhaustion
            // fallback (bare ENCRYPTED FIN + retire) that used to live
            // inline here.
            //
            // A stream no longer in the table has been dropped — closed from
            // both ends, or by the offset-exhaustion fallback on an earlier
            // close — and there is nothing to do: its route is released by the
            // delivery task behind whatever it still had to deliver, or was
            // released with the fallback's bare FIN, and releasing it here — on
            // a second `disconnect()`, say — could cut the first short.
            let stream = streams.get(&stream_id).map(|s| s.clone());
            if let Some(stream) = stream {
                deferred.push_back(Deferred::Fin { stream_id, stream });
                flush_deferred_sends(
                    deferred,
                    transport,
                    crypto_session,
                    session_id,
                    streams,
                    demux,
                    stream_gauge,
                    observability,
                )
                .await;
                // Wake the send loop so the FIN is put on the wire on
                // the very next drain pass rather than after a 10 ms tick.
                crypto_session.notify_outbound_ready();
            }
        }
        SessionCommand::Close => return true,
    }
    false
}

/// Carry out one [`ControlCommand`].
///
/// Two callers: the control arm, one command per turn, and the local close, which takes
/// in the ones queued ahead of it before it flushes. Neither is gated on the writes the
/// pump holds, which is the whole point — see [`ControlCommand`].
async fn take_control<T: SessionTransport>(
    control: ControlCommand,
    transport: &Arc<T>,
    crypto_session: &Arc<Session>,
    streams: &Arc<DashMap<u32, Arc<Stream>>>,
    observability: &Observability,
) {
    match control {
        ControlCommand::SetStreamPriority {
            stream_id,
            priority,
        } => {
            if let Some(stream) = streams.get(&stream_id) {
                stream.set_priority(priority);
            }
        }
        ControlCommand::Migrate(local_addr) => {
            // Embedder-triggered connection migration (Phase 4 / P4.2).
            // Rebind the transport to the new local socket FIRST (it keeps
            // the old socket for the overlap); only on a successful rebind
            // bump the send `path_id` so every subsequent packet from the
            // new socket carries a fresh, not-yet-Validated path label —
            // which is what makes the server detect + challenge the new
            // path (a still-`0` path_id would be skipped, path 0 being
            // permanently Validated). Both happen inside this one
            // command, so no send interleaves between them. Best-effort: a
            // failed rebind leaves the session untouched on the old socket
            // (broken-rebind safety) — migration never tears it down.
            match transport.migrate(local_addr).await {
                Ok(()) => {
                    let from_path = crypto_session.current_send_path_id();
                    let new_path = crypto_session.next_migration_path_id();
                    // Real migration event: the local send path moved
                    // from `from_path` to `new_path`.
                    observability.record_path_migration(from_path, new_path);
                    // ε / WIRE v5: rotate the outbound CID so every
                    // post-migration datagram stamps an
                    // independent-random ConnId an observer cannot link
                    // to the pre-migration flow. The new CID_{i+1} is
                    // already in the server's pre-registered inbound
                    // window (which slides post-AEAD beyond K migrations).
                    transport.set_outbound_cid(crypto_session.advance_outbound_cid());
                    log::info!(
                        "PhantomSession: migrated send path -> path_id {}, CID rotated",
                        new_path
                    );
                    // Wake the send loop so app data + L1 retransmits flow
                    // from the new socket immediately, triggering the
                    // server-side new-source detection.
                    crypto_session.notify_outbound_ready();
                }
                Err(e) => {
                    log::warn!(
                        "PhantomSession: migrate rebind failed (staying on the old path): {}",
                        e
                    );
                }
            }
        }
        ControlCommand::MigrateServer(local_addr) => {
            // Server-side migration (the mirror of `Migrate`). Rebind the
            // server's SEND socket to the new local address FIRST (its receive
            // keeps flowing on the old address through the listener demux during
            // the overlap, so c2s never drops); only on a successful rebind
            // rotate the s2c send `path_id` + outbound CID in lock-step, so the
            // client sees a fresh server source with a fresh, unlinkable ConnId
            // and follows it (its unconnected socket hears the new source). Both
            // happen inside this one command, so no send interleaves between
            // them. Best-effort: a failed rebind leaves the session on the old
            // send socket — server migration never tears it down.
            match transport.migrate_server(local_addr).await {
                Ok(()) => {
                    let from_path = crypto_session.current_send_path_id();
                    let new_path = crypto_session.next_migration_path_id();
                    // Real migration event: the server's send path moved.
                    observability.record_path_migration(from_path, new_path);
                    transport.set_outbound_cid(crypto_session.advance_outbound_cid());
                    log::info!(
                        "PhantomSession: migrated server send path -> path_id {}, s2c CID rotated",
                        new_path
                    );
                    // Wake the send loop so the next s2c packet carries the new
                    // source + path_id + CID immediately.
                    crypto_session.notify_outbound_ready();
                }
                Err(e) => {
                    log::warn!(
                        "PhantomSession: server migrate rebind failed (staying on the old send socket): {}",
                        e
                    );
                }
            }
        }
    }
}

/// Act on every dropped stream handle whose own writes the pump has now taken in (see
/// `releases` in [`run_data_pump`]).
///
/// The stream is marked released, so from here on nobody is left to read it and an
/// acknowledged FIN is enough to drop it. Then either that is already true and the stream
/// goes now, or a [`Deferred::Release`] is queued behind the writes still waiting for room
/// — the handle's own among them — to close the writing half once they are in.
#[allow(clippy::too_many_arguments)]
async fn release_due_streams<T: SessionTransport>(
    releases: &mut VecDeque<(u32, u64)>,
    commands_taken: u64,
    deferred: &mut VecDeque<Deferred>,
    transport: &Arc<T>,
    crypto_session: &Arc<Session>,
    session_id: SessionId,
    streams: &Arc<DashMap<u32, Arc<Stream>>>,
    demux: &Arc<StreamDemultiplexer>,
    stream_gauge: &Arc<StreamGauge>,
    observability: &Observability,
) {
    while let Some(&(stream_id, due)) = releases.front() {
        if due > commands_taken {
            break;
        }
        releases.pop_front();
        // Clone the Arc out so no table guard is held across the awaits below. A stream
        // already gone was dropped while its handle was on its way out — closed from both
        // ends, or by the offset-exhaustion fallback behind a `disconnect()`.
        let Some(stream) = streams.get(&stream_id).map(|s| s.clone()) else {
            continue;
        };
        stream.release_app_handle();
        if stream.is_retirable().await {
            retire_released_stream(stream_id, streams, demux, stream_gauge);
            continue;
        }
        deferred.push_back(Deferred::Release { stream_id, stream });
        flush_deferred_sends(
            deferred,
            transport,
            crypto_session,
            session_id,
            streams,
            demux,
            stream_gauge,
            observability,
        )
        .await;
        crypto_session.notify_outbound_ready();
    }
}

/// Evaluate path liveness once (Phase 4 / P4.3) and apply the resulting transition to
/// both the internal [`SessionState`] and the FFI-visible [`ConnectionState`]. Returns
/// `true` when the session has died (idle-timeout in `Migrating`), so the caller ends
/// the pump. `migrating_since` is the pump-local truth for the keep-alive window.
///
/// A death is recorded in `terminal_error` as [`CoreError::Timeout`] — the session went
/// unanswered for the whole configured window and was reaped, which is a deadline
/// elapsing rather than a transport error — and recorded *before* `Dead` is published,
/// so a caller that sees the state and then asks `last_error()` why finds the answer
/// already there.
fn apply_liveness(
    crypto_session: &Arc<Session>,
    state: &Arc<AtomicU8>,
    terminal_error: &parking_lot::Mutex<Option<CoreError>>,
    migrating_since: &mut Option<std::time::Instant>,
) -> bool {
    use crate::transport::liveness::{liveness_verdict, LivenessVerdict};
    let cfg = crypto_session.liveness_config();
    let snap = crypto_session.bandwidth_snapshot();
    let silence = crypto_session.last_activity_elapsed();
    let in_migrating = migrating_since.is_some();
    let migrating_for = migrating_since
        .map(|t| t.elapsed())
        .unwrap_or(std::time::Duration::ZERO);
    // Download-only liveness: an outstanding idle keep-alive PING is
    // an outstanding probe just like in-flight reliable data, so fold it into the
    // sweep's `inflight > 0` gate. This is what lets a download-only path — which
    // sends only ACKs and so has zero reliable bytes in flight — declare the path
    // down when the PING goes unanswered (the PONG would have refreshed activity).
    let effective_inflight = if crypto_session.keepalive_outstanding() {
        snap.inflight_bytes.max(1)
    } else {
        snap.inflight_bytes
    };
    match liveness_verdict(
        silence,
        effective_inflight,
        snap.min_rtt,
        in_migrating,
        migrating_for,
        &cfg,
    ) {
        LivenessVerdict::PathDown => {
            *migrating_since = Some(std::time::Instant::now());
            crypto_session.set_state(SessionState::Migrating);
            publish_unless_ended(state, ConnectionState::Migrating);
            log::info!(
                "PhantomSession: path down (no inbound for {silence:?} with data in flight) \
                 — entering Migrating; the embedder should migrate()"
            );
            false
        }
        LivenessVerdict::Recovered => {
            *migrating_since = None;
            crypto_session.set_state(SessionState::Connected);
            publish_unless_ended(state, ConnectionState::Connected);
            log::info!("PhantomSession: path recovered — back to Connected");
            false
        }
        LivenessVerdict::Dead => {
            record_terminal_cause(terminal_error, CoreError::Timeout);
            crypto_session.set_state(SessionState::Closed);
            state.store(ConnectionState::Dead as u8, Ordering::Relaxed);
            log::warn!("PhantomSession: migration idle-timeout elapsed — session dead");
            true
        }
        LivenessVerdict::Unchanged => false,
    }
}

/// Publish `next` — a state the session can still leave, `Connected` or `Migrating` —
/// unless the session has already reached one it cannot: an end (`Closed`, `Failed`,
/// `Dead`) or the peer's announced close (`Draining`).
///
/// The liveness verdict is not the only writer of the state. The receive task publishes
/// `Dead` when the transport gives up and `Draining` when the peer's close arrives, and
/// `disconnect()` publishes `Closed` from the caller's thread, each of them possibly
/// between the moment the send loop read the path's signals and the moment it publishes
/// what they said. A verdict landing after one of them must not walk it back: a caller
/// that read `Dead`, then `Connected`, then `Dead` again was told the session recovered.
/// The check and the write are one atomic step, so no end published in between is lost.
fn publish_unless_ended(state: &AtomicU8, next: ConnectionState) {
    let _ = state.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
        match ConnectionState::from_u8(current) {
            ConnectionState::Closed
            | ConnectionState::Failed
            | ConnectionState::Dead
            | ConnectionState::Draining => None,
            _ => Some(next as u8),
        }
    });
}

/// How long an unanswered PATH_CHALLENGE is allowed to stay outstanding before
/// the pump abandons it and records a `timeout` sample.
///
/// Deliberately **not** a fresh constant: it is exactly the threshold at which
/// this same heartbeat already declares the whole path down —
/// `path_down_ptos × PTO`, with `PTO = max(min_pto, 3 × min_rtt)` (see
/// `transport::liveness`). Rationale:
///
/// - It is RTT-adaptive. `min_rtt` comes from the live BBR estimator, so a
///   satellite path gets a proportionally longer budget than loopback. Before
///   the first RTT sample the estimator's own conservative 100 ms seed governs
///   (`3 × 100 ms = 300 ms`, above the 200 ms `min_pto` floor), which errs on
///   the generous side — exactly the right direction for a metric that must not
///   steal a sample from a validation that was merely slow.
/// - It is already the operator's tuning knob for "this path stopped
///   responding". A challenge that has been silent that long is silent by the
///   session's own definition, so a second, independent timeout would just be a
///   knob that can disagree with the first.
/// - It is more generous than the QUIC analogue (RFC 9000 §8.2.4 abandons a
///   path validation after `3 × PTO`); the default config is `5 × PTO`, so the
///   sweep never fires ahead of a validation QUIC would still consider live.
///
/// `path_down_ptos` is floored at 1 so a hand-built `LivenessConfig` with a zero
/// there cannot collapse the budget to "expire on the next tick".
fn path_validation_timeout(crypto_session: &Arc<Session>) -> std::time::Duration {
    let cfg = crypto_session.liveness_config();
    let min_rtt = crypto_session.bandwidth_snapshot().min_rtt;
    let pto = cfg.min_pto.max(min_rtt.saturating_mul(3));
    pto.saturating_mul(cfg.path_down_ptos.max(1))
}

/// Expire every PATH_CHALLENGE that has gone unanswered past
/// [`path_validation_timeout`], recording one
/// [`PathValidationOutcome::Timeout`] sample each.
///
/// Without this, `phantom.path.validation.duration` only ever saw an *answered*
/// challenge: a validation into a blackhole produced neither `success` nor
/// `failure`, and its start stamp was never reclaimed. `Timeout` is kept
/// distinct from `Failure` because they mean different things operationally — a
/// failure is a wrong echo from something that holds the session key, a timeout
/// is a path that carries nothing at all.
///
/// **Metrics + bookkeeping only.** The `PathRegistry` entry is deliberately left
/// in `Validating`: `issue_challenge` is idempotent while a challenge is in
/// flight (PATH-003) and refuses to re-issue from the terminal `Failed` state,
/// so driving the path to `Failed` here would permanently burn that `path_id`
/// for the session and break a migration whose challenge was merely lost. The
/// registry is bounded by the 256-value `path_id` space either way.
fn sweep_path_validation_timeouts(
    crypto_session: &Arc<Session>,
    challenges: &PathChallenges,
    observability: &Observability,
) {
    // Fast path for the steady state: no challenge outstanding means no budget
    // to compute (and no `liveness_config` / `bandwidth_snapshot` locks to take)
    // on a heartbeat that fires every 10 ms. A challenge registered between this
    // check and the next tick is simply swept one tick later.
    if challenges.is_empty() {
        return;
    }
    let timeout = path_validation_timeout(crypto_session);
    for (path_id, waited) in challenges.expire(timeout) {
        log::debug!(
            "PhantomSession: PATH_CHALLENGE on path {path_id} unanswered after {waited:?} \
             (budget {timeout:?}) — abandoning validation"
        );
        observability.record_path_validation(waited, path_id, PathValidationOutcome::Timeout);
    }
}

/// Emit an idle keep-alive PING when the path is idle (download-only
/// liveness). Decides via the pure [`should_send_keepalive`] gate
/// over the live signals (Connected? nothing in flight? inbound silent ≥ interval?
/// no recent PING?). On a fire it sends one empty `ENCRYPTED | KEEPALIVE` packet,
/// marks the probe outstanding (so the very next liveness sweep treats the path as
/// awaiting a response even with no reliable data queued), and records the send
/// instant for the per-interval throttle. Best-effort: a send failure just leaves
/// `last_keepalive` unchanged so the next tick retries.
async fn maybe_send_keepalive<T: SessionTransport>(
    transport: &Arc<T>,
    crypto_session: &Arc<Session>,
    session_id: SessionId,
    last_keepalive: &mut std::time::Instant,
    observability: &Observability,
) {
    use crate::transport::liveness::should_send_keepalive;
    let cfg = crypto_session.liveness_config();
    // Cheap fast-path: skip everything when keep-alives are disabled.
    if cfg.keepalive_interval.is_none() {
        return;
    }
    let connected = crypto_session.state() == SessionState::Connected;
    let snap = crypto_session.bandwidth_snapshot();
    // An already-outstanding PING is itself "in flight" — fold it into the gate so
    // we don't queue a second PING before the first is answered or times out.
    let inflight = if crypto_session.keepalive_outstanding() {
        snap.inflight_bytes.max(1)
    } else {
        snap.inflight_bytes
    };
    if !should_send_keepalive(
        connected,
        inflight,
        crypto_session.last_activity_elapsed(),
        last_keepalive.elapsed(),
        &cfg,
    ) {
        return;
    }
    // PING (not a PONG): a bare KEEPALIVE that the peer echoes back as KEEPALIVE|ACK.
    if send_keepalive(transport, crypto_session, session_id, false, observability).await {
        crypto_session.mark_keepalive_outstanding();
        *last_keepalive = std::time::Instant::now();
    }
}

/// Emit any flow-control limit the receive **delivery** task staged.
///
/// The delivery task moves the limit on real app consumption and stages it via
/// `Stream::stage_window_update_limit` + a send-loop wake; the send loop (this, the sole
/// outbound writer) actually encrypts and sends the `WINDOW_UPDATE`, so the control frame is
/// always sealed under the epoch live when it stamps. The epoch can be advanced by either
/// this loop's own `rekey()` or the receive task's authenticated forward catch-up, but both
/// serialise through `rekey_lock`, so the seal is always epoch-consistent. The staged limits
/// are snapshotted out of the `DashMap` first so no shard lock is held across the `.await`
/// (which would deadlock the delivery / reader tasks that also touch `streams`).
async fn flush_pending_window_updates<T: SessionTransport>(
    transport: &Arc<T>,
    crypto_session: &Arc<Session>,
    session_id: SessionId,
    streams: &Arc<DashMap<u32, Arc<Stream>>>,
    observability: &Observability,
) {
    let pending: Vec<(u32, u64, Arc<Stream>)> = streams
        .iter()
        .filter_map(|e| {
            e.value()
                .take_pending_window_update()
                .map(|c| (*e.key(), c, e.value().clone()))
        })
        .collect();
    for (stream_id, limit, stream) in pending {
        if !send_window_update(
            transport,
            crypto_session,
            session_id,
            stream_id as TransportStreamId,
            limit,
            observability,
        )
        .await
        {
            // The send failed (transient transport hiccup): re-stage the limit so the next
            // send-loop pass — the 10 ms tick at the latest — retries it. Staging resolves
            // by maximum, so a limit the delivery task raised while this send was failing
            // survives the retry rather than being pushed back down by it. A permanently
            // dead transport tears the session down via the reader, which ends this loop.
            stream.stage_window_update_limit(limit);
        }
    }
}

/// Admit as much deferred outbound work into the stream send buffers as their
/// backpressure currently allows, in strict FIFO order.
///
/// Stops at the first chunk a buffer refuses — the refused chunk stays at the
/// head of the queue and is re-offered on the next pass — so a stream's byte
/// order is preserved and a FIN can never overtake data queued before it. The
/// only unbounded wait `Stream::send_reliable` had (the backpressure semaphore)
/// is replaced by that refusal, which is what keeps the pump's `select!` loop
/// turning while one direction saturates.
///
/// Wakes the send loop when anything was admitted so the newly-buffered bytes go
/// out on the very next drain rather than after a heartbeat tick.
#[allow(clippy::too_many_arguments)]
async fn flush_deferred_sends<T: SessionTransport>(
    deferred: &mut VecDeque<Deferred>,
    transport: &Arc<T>,
    crypto_session: &Arc<Session>,
    session_id: SessionId,
    streams: &Arc<DashMap<u32, Arc<Stream>>>,
    demux: &Arc<StreamDemultiplexer>,
    stream_gauge: &Arc<StreamGauge>,
    observability: &Observability,
) {
    let mut admitted = false;
    while let Some(item) = deferred.front().cloned() {
        match item {
            // A write queued behind its stream's FIN. The queue is FIFO, so by the time
            // one reaches the front the FIN ahead of it has been admitted, and admitting
            // this would send it on the offset after the FIN — past the end of the stream
            // as the peer's application has already been told it.
            Deferred::Data { stream, .. } if stream.is_local_finished() => {
                log::debug!(
                    "PhantomSession: dropping a write queued after stream {}'s close",
                    stream.id()
                );
                deferred.pop_front();
            }
            Deferred::Data { stream, data } => match stream.try_send_reliable(&data).await {
                Ok(true) => {
                    admitted = true;
                    deferred.pop_front();
                }
                // Buffer full: leave it at the head and try again next pass.
                Ok(false) => break,
                Err(e) => {
                    // T4.5 fail-closed: the reliable offset space is exhausted
                    // (~2^32 segments). Astronomically unreachable; drop the
                    // chunk so the queue cannot wedge, and let the liveness
                    // sweep tear the stalled session down.
                    log::error!("PhantomSession: send aborted — {e}");
                    deferred.pop_front();
                }
            },
            // A dropped handle whose stream's writing half is already closed — by a
            // `disconnect()` whose FIN was ahead of this in the queue. There is no second
            // FIN to send. What drops the stream now that nobody holds it is that FIN's
            // acknowledgement (the receive path asks `is_retirable`), unless it has
            // already arrived, which is checked here.
            Deferred::Release { stream_id, stream } if stream.is_local_finished() => {
                deferred.pop_front();
                if stream.is_retirable().await {
                    retire_released_stream(stream_id, streams, demux, stream_gauge);
                }
            }
            // A dropped handle to a stream this side opened and never put a reliable
            // byte on: nothing has reached the peer that could have told it the stream
            // exists, since only a reliable segment opens one there. A FIN would open it
            // on the peer only to end it, so the stream just goes. Every write the handle
            // made was ahead of this in the queue, so none of them is still to come.
            Deferred::Release { stream_id, stream }
                if demux.is_local_stream_id(stream_id) && !stream.has_sent_reliable() =>
            {
                deferred.pop_front();
                retire_released_stream(stream_id, streams, demux, stream_gauge);
            }
            // Otherwise a dropped handle closes the writing half exactly as `disconnect()`
            // does: the FIN follows every write the handle queued, and once it is
            // acknowledged the stream goes whether or not the peer ever closes its half.
            Deferred::Fin { stream_id, stream } | Deferred::Release { stream_id, stream } => {
                match stream.try_queue_fin().await {
                    Ok(true) => {
                        admitted = true;
                        deferred.pop_front();
                    }
                    Ok(false) => break,
                    Err(e) => {
                        deferred.pop_front();
                        // Same offset exhaustion, on the FIN sentinel. Fall back to a bare
                        // (still ENCRYPTED — Invariant 2) FIN and drop the stream — once. The
                        // fallback records no FIN as queued, so a second close queued for
                        // the same stream — the handle's drop behind a `disconnect()` —
                        // arrives here too, and finds the stream already gone: it had its
                        // bare FIN, and has already left the table and the gauge.
                        if streams.remove(&stream_id).is_none() {
                            continue;
                        }
                        log::error!(
                            "PhantomSession: queue_fin failed for stream {stream_id}: {e}; \
                             sending bare FIN (best-effort)"
                        );
                        let _ = send_app_data(
                            transport,
                            crypto_session,
                            session_id,
                            stream_id as TransportStreamId,
                            &[],
                            PacketFlags::FIN,
                            None,
                            observability,
                        )
                        .await;
                        demux.close_stream(stream_id);
                        stream_gauge.closed(stream_id);
                    }
                }
            }
        }
    }
    if admitted {
        crypto_session.notify_outbound_ready();
    }
}

/// Drain every stream with pending data, scheduling them in strict
/// priority order (higher `Stream::priority()` wins). Streams of equal
/// priority are drained in stream-id order (deterministic so tests
/// don't get flaky under DashMap's hash-order shuffle).
///
/// This is **strict priority**: a stream with priority N never yields
/// to a stream with priority < N while it still has data. A future
/// weighted-fair scheduler can replace this without changing the
/// caller surface. Phase 4.3.
///
/// One pass emits at most [`DRAIN_MAX_SEGMENTS_PER_PASS`] segments, and stops
/// earlier if the pacer runs out of credit. The [`DrainStop`] it returns tells
/// the caller which of the three happened; [`apply_drain_outcome`] turns that
/// into the pump's next move.
///
/// **Two budgets, and they answer different questions.** The congestion window
/// bounds the *volume* outstanding — `min(cwnd, window) − inflight`, recomputed
/// every iteration. The pacer bounds the *rate* it leaves at. A window released
/// without the second bound is a burst: every byte the window allows goes out
/// back to back and the sender then waits a round trip, which is not what BBR's
/// gains describe and not what any queue on the path is sized for. Consulting
/// only cwnd is how a window that grew from 5.6 KB to nearly a megabyte turned
/// into a nearly-a-megabyte burst.
///
/// The pacer is asked *before* the segment is polled, because the stream picks
/// the segment and its size is not known until it has. The bucket is settled
/// with the true on-wire size inside `send_app_data`, carrying at most one
/// segment of overshoot as debt.
///
/// **Only this path is paced.** Acknowledgements, `WINDOW_UPDATE` limits,
/// keep-alives, path validation and cover frames are emitted elsewhere and are
/// never gated on pacing credit. That asymmetry is deliberate and is what makes
/// the reverse direction work: the flow-control limit the *other* direction
/// depends on must not queue behind this direction's rate limiter, or pacing
/// would re-create, one layer up, the standing queue it exists to remove. They
/// are also small and infrequent enough that leaving them out of the rate
/// accounting costs a fraction of a percent of it.
async fn drain_streams_priority_ordered<T: SessionTransport>(
    transport: &Arc<T>,
    crypto_session: &Arc<Session>,
    session_id: SessionId,
    streams: &Arc<DashMap<u32, Arc<Stream>>>,
    observability: &Observability,
) -> DrainStop {
    let stop = drain_streams_inner(
        transport,
        crypto_session,
        session_id,
        streams,
        observability,
    )
    .await;
    // Counted here and nowhere else. The pass has six exits and five callers, so
    // a tally at the call sites would be five places to forget and six to get
    // wrong; a wrapper has one of each. What it buys is a census of what actually
    // stopped the sender, rather than the one an analysis infers afterwards from
    // the window and the bytes outstanding — an inference that cannot see the
    // difference between a pass the pacer metered and a pass that ran dry with
    // the window open, because both leave the same window behind them.
    //
    // Nothing the peer sends enters this. It is a tally of a decision this
    // endpoint made about its own send path, taken at the moment it made it.
    crypto_session.note_drain_stop(match stop {
        DrainStop::Drained => DrainOutcome::Drained,
        DrainStop::CongestionLimited => DrainOutcome::CongestionLimited,
        DrainStop::FlowControlled => DrainOutcome::FlowControlled,
        DrainStop::TransportRefused => DrainOutcome::TransportRefused,
        DrainStop::SegmentBudget => DrainOutcome::SegmentBudget,
        DrainStop::Paced(_) => DrainOutcome::Paced,
    });
    stop
}

/// The pass itself. See [`drain_streams_priority_ordered`], which wraps it so the
/// outcome is counted at one point rather than at six.
async fn drain_streams_inner<T: SessionTransport>(
    transport: &Arc<T>,
    crypto_session: &Arc<Session>,
    session_id: SessionId,
    streams: &Arc<DashMap<u32, Arc<Stream>>>,
    observability: &Observability,
) -> DrainStop {
    // Snapshot the stream set so we can sort without holding DashMap
    // shard locks across awaits. Each entry is (priority, stream_id,
    // stream-Arc) — Arc clones are cheap (refcount bump).
    let mut snapshot: Vec<(u32, u32, Arc<Stream>)> = streams
        .iter()
        .map(|e| (e.value().priority(), *e.key(), e.value().clone()))
        .collect();
    // Descending priority; ties broken by stream id ascending so the
    // order is stable across iterations.
    snapshot.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));

    let mut sent = 0usize;
    // The most binding reason any stream was withheld this pass. The congestion
    // window is a session-wide budget, so a stream it blocked means the pass was
    // congestion-limited whatever the other streams did; a closed peer window is
    // per-stream and only speaks for the pass if nothing else bound it.
    let mut blocked: Option<SendBlocked> = None;
    // A write the transport refused. Tracked apart from `blocked`, which only
    // ever speaks for what a stream had to offer, because the two answer
    // different questions and only this one is about the local send path.
    let mut transport_refused = false;
    for (_priority, stream_id, stream) in snapshot.iter().map(|(p, id, s)| (p, *id, s)) {
        loop {
            if sent >= DRAIN_MAX_SEGMENTS_PER_PASS {
                // Budget spent. Congestion and flow control are unchanged — this
                // only splits the same window across several passes — so the
                // caller re-arms and we resume from the same priority order.
                return DrainStop::SegmentBudget;
            }
            // Rate budget. Asked before the segment is polled out of the stream
            // (see the function comment) and answered by *returning*: the wait
            // belongs to the pump's `select!`, not to this loop.
            if !crypto_session.pacing_allows_send() {
                return DrainStop::Paced(crypto_session.pacing_delay());
            }
            // Bytes of new data the congestion window currently permits.
            // Recomputed each iteration: every send grows inflight, so the
            // budget shrinks and the drain stops once the window is full.
            let snap = crypto_session.bandwidth_snapshot();
            let budget = snap.cwnd_bytes.saturating_sub(snap.inflight_bytes);
            let seg = match stream
                .poll_send(
                    budget,
                    snap.delivered_bytes,
                    snap.delivered_time,
                    snap.app_limited,
                )
                .await
            {
                Ok(seg) => seg,
                Err(why) => {
                    if blocked.is_none_or(|held| drain_block_rank(why) > drain_block_rank(held)) {
                        blocked = Some(why);
                    }
                    break;
                }
            };
            // Two different reports, on two different counts.
            //
            // Every copy replaces a transmission this sender is no longer
            // waiting for, so every copy settles the flight arithmetic here —
            // deferring it would leave `inflight` a segment high for a round
            // trip, and the budget this loop computes is `cwnd − inflight`.
            //
            // The congestion signal is raised for the *first* copy only. It is
            // raised here, and not on the acknowledgement that eventually
            // retires the segment, because this instant is the last one in the
            // segment's life that the peer has no hand in: the copy goes out on
            // this endpoint's own RTO even if the peer never says anything
            // again. And once per segment rather than once per copy, because the
            // round's loss rate is judged against what the round delivered, and
            // a segment being resent for the third time is delivering nothing
            // while it happens.
            if seg.retransmit {
                crypto_session.on_packet_retransmitted(seg.data.len() as u64);
                // Which rule ordered this copy is recorded for **every** copy,
                // and deliberately not only for the first.
                //
                // The two counts answer different questions and share no
                // denominator. A hole is booked once however many copies it
                // takes, so the hole count pairs with the bytes charged to
                // congestion control. But a rule's *rate of firing* is a
                // property of the copies it ordered, and RACK's characteristic
                // failure — re-declaring a segment whose repair is merely slow,
                // once per `srtt·9/8` — lives entirely in the copies after the
                // first. Attributing only first copies would have left the
                // instrument blind to precisely the behaviour it was built to
                // look for, and every run would have reported a packet-threshold
                // majority by construction, since that arm can only ever fire on
                // a segment with no copy on the wire.
                if let Some(cause) = seg.loss_cause {
                    crypto_session.note_repair_ordered_by(cause);
                }
                if seg.first_retransmit {
                    crypto_session.on_packet_lost(seg.data.len() as u64);
                }
            }
            let mut base = if seg.reliable {
                PacketFlags::RELIABLE
            } else {
                PacketFlags::UNRELIABLE
            };
            // The reliable FIN sentinel carries PacketFlags::FIN so the
            // receiver orders EOF after all preceding data (the SACK path
            // delivers it strictly in stream-offset order via accept_in_order).
            if seg.fin {
                base |= PacketFlags::FIN;
            }
            // Reliable segments carry their gap-free `stream_offset` in the AEAD
            // plaintext (A.5) for in-order reassembly; unreliable segments do not.
            let reliable_offset = if seg.reliable {
                Some(seg.stream_offset)
            } else {
                None
            };
            if !send_app_data(
                transport,
                crypto_session,
                session_id,
                stream_id as TransportStreamId,
                &seg.data,
                base,
                reliable_offset,
                observability,
            )
            .await
            {
                log::error!("PhantomSession: priority-ordered drain send failed");
                // `poll_send` already stamped `sent_at` on this reliable
                // segment, but the bytes never reached the wire. Clear it so the
                // next drain re-offers it immediately instead of stalling a full
                // RTO before the retransmit pass. Whether the bytes also owe the
                // peer's flow-control limit a refund is not this loop's to judge
                // and not asked here: the send buffer records how many copies of
                // the segment have gone out, and `mark_unsent` reads it.
                // Unreliable segments were removed by `poll_send`
                // (fire-and-forget) — nothing to reset.
                if seg.reliable {
                    stream.mark_unsent(seg.stream_offset).await;
                }
                transport_refused = true;
                break;
            }
            sent += 1;
        }
    }
    // The room the peer has left, as this pass saw it — the minimum over the
    // streams it looked at, and zero when it looked at none. Recorded on every
    // pass rather than only on the dry ones, because the question it answers is
    // about the passes that *did* send: the sender settles a fifth below the
    // nominal ceiling, and whether that fifth is the peer's cumulative grant
    // lagging under load or something on this side cannot be told from bytes
    // outstanding alone.
    crypto_session.note_peer_window_remaining(
        snapshot
            .iter()
            .map(|(_, _, s)| u64::from(s.peer_send_window()))
            .min()
            .unwrap_or(0),
    );
    // A refusal outranks everything a stream reported: whatever the streams had
    // to say about their own buffers, this pass ended because the wire would not
    // take the bytes.
    if transport_refused {
        return DrainStop::TransportRefused;
    }
    match blocked {
        None | Some(SendBlocked::Idle) => {
            // A pass that came up empty is not necessarily an application that
            // came up empty, and the two have been reported identically. Ask the
            // streams which it was, once, here — where the snapshot of them is
            // still in hand and the answer is a local fact about this endpoint's
            // own buffers.
            //
            // The distinction is not acted on: it is counted. `poll_send` still
            // returns `Idle`, this pass is still `Drained`, and the
            // application-limited phase still opens exactly where it did. What
            // changes is that a recorded run can say which of the two it saw,
            // where until now it could only say how often the pair happened.
            let dry_against_a_full_buffer = snapshot.iter().any(|(_, _, s)| s.send_buffer_full());
            // And whether any stream was out of peer window. `poll_send` reports
            // `FlowControl` only when it holds an unsent segment for the peer to
            // refuse; with nothing unsent it answers the same `Idle` an empty
            // stream gives, however closed the window is. So whether a pass calls
            // itself flow-controlled or application-limited turns on whether the
            // peer's SACK or its WINDOW_UPDATE arrived first — and only one of
            // those two opens a phase that disables the loss response.
            let dry_with_no_peer_window =
                snapshot.iter().any(|(_, _, s)| s.peer_send_window() == 0);
            crypto_session.note_dry_pass(dry_against_a_full_buffer, dry_with_no_peer_window);
            DrainStop::Drained
        }
        Some(SendBlocked::FlowControl) => DrainStop::FlowControlled,
        Some(SendBlocked::CongestionWindow) => DrainStop::CongestionLimited,
    }
}

/// How strongly a per-stream [`SendBlocked`] speaks for the whole pass.
///
/// A closed congestion window outranks everything because it is a session-wide
/// budget: if it withheld one stream it would have withheld any other with data
/// to offer. A closed *peer* window outranks an idle stream for the mirror-image
/// reason — it is a statement that a stream had data and could not send it,
/// where an idle stream is a statement that it had none.
fn drain_block_rank(why: SendBlocked) -> u8 {
    match why {
        SendBlocked::Idle => 0,
        SendBlocked::FlowControl => 1,
        SendBlocked::CongestionWindow => 2,
    }
}

/// Run [`drain_streams_priority_ordered`] until every stream is drained or the
/// pass budget runs out. Used on the teardown paths (graceful close and handle
/// drop), which must put everything the congestion and flow-control windows
/// currently allow on the wire before the pump exits — the per-pass segment
/// budget is a scheduling bound, not a send budget, so it must not silently
/// truncate a close.
async fn drain_streams_fully<T: SessionTransport>(
    transport: &Arc<T>,
    crypto_session: &Arc<Session>,
    session_id: SessionId,
    streams: &Arc<DashMap<u32, Arc<Stream>>>,
    observability: &Observability,
) {
    for _ in 0..DRAIN_MAX_PASSES_ON_CLOSE {
        match drain_streams_priority_ordered(
            transport,
            crypto_session,
            session_id,
            streams,
            observability,
        )
        .await
        {
            // Nothing further can leave until something outside this loop acts —
            // an acknowledgement frees the congestion window, a `WINDOW_UPDATE`
            // frees the peer's, a socket makes room. A teardown does not wait.
            DrainStop::Drained
            | DrainStop::CongestionLimited
            | DrainStop::FlowControlled
            | DrainStop::TransportRefused => return,
            DrainStop::SegmentBudget => {}
            // The tail of a connection is still data on a path, so the flush
            // obeys the rate; the cap keeps a low estimate from turning a close
            // into a hang. This is the one place a pacing wait is taken inline,
            // and it is safe here for the reason it is not safe in the pump:
            // the loop below is the teardown, not a `select!` arm — there is no
            // other arm left to starve.
            DrainStop::Paced(delay) => {
                tokio::time::sleep(delay.min(CLOSE_FLUSH_PACING_WAIT_MAX)).await;
            }
        }
    }
    log::warn!(
        "PhantomSession: close-time flush hit the {DRAIN_MAX_PASSES_ON_CLOSE}-pass bound with \
         data still buffered"
    );
}

/// Build a `DeliverySample` from a successful Stream ack callback and
/// feed it into the session's BBR estimator (Phase 4.4). The BBR loop
/// internally re-sets the pacer rate via `Session::on_packet_acked`,
/// so the next outbound packet is paced at the freshly-estimated
/// bottleneck bandwidth.
///
/// `ack_delay_us` is the `Sack::ack_delay_us` field carried in the ACK's AEAD
/// plaintext (microseconds the receiver held the ACK before sending) —
/// subtracted from the observed RTT to yield the propagation delay. Pass 0 when
/// no peer-side delay is known (the estimator treats it as "no delay reported").
///
/// This is also the RTT-sampling site: the propagation figure the estimator
/// folds into its `min_rtt` filter is published to `Observability::record_rtt_us`
/// for `path_id`. Literally the same figure — the estimator hands it back from
/// [`Session::on_packet_acked`](crate::transport::session::Session::on_packet_acked)
/// rather than the gauge re-deriving it, and it carries
/// [`ack_delay_adjusted_rtt`](crate::transport::bandwidth_estimator::ack_delay_adjusted_rtt)'s
/// bound on the peer's claimed delay. That bound is a floor and nothing more:
/// the published sample never falls below a round trip this endpoint timed
/// itself, but between that floor and the round trip just observed the peer's
/// claim still chooses, so a peer claiming the whole difference every time keeps
/// the gauge pinned at the path's best-ever reading. That caveat has to travel
/// with the number rather than sit here, because the slot has two readers and
/// neither passes through this file: `MetricsSnapshotFfi::rtt_us_path_0` in
/// `observability::snapshot`, and the `phantom.path.rtt` `ObservableGauge`
/// callback in `observability::bridge` under `telemetry-otel`. Both are
/// documented in `docs/observability/metrics-catalog.md`. `sampled_rtt` is Karn's
/// condition and gates **both** consumers — pass `false` for a retransmitted
/// segment so the per-path RTT gauge and the estimator's min-RTT filter obey
/// Karn's algorithm exactly like `Stream`'s own srtt (an ACK for a retransmit is
/// ambiguous about which copy it acknowledges, and the sender restamped
/// `sent_at` when it resent). Only the single `Instant::now()` the
/// `DeliverySample` already needed is read.
///
/// Nothing else is inferred from the flag, and nothing at all is inferred from
/// *when* the acknowledgement arrived: this path reports no loss. See
/// [`DeliverySample::rtt_sampled`](crate::transport::bandwidth_estimator::DeliverySample::rtt_sampled).
///
/// `path_id` is the **inbound** `header.path_id` (the id the ACK arrived under),
/// which is the same id space `mark_path_seen` / `begin_path_validation` /
/// `record_path_validation` key on. It stays 0 until the *peer* migrates, which
/// is what keeps `MetricsSnapshotFfi::rtt_us_path_0` — the only per-path RTT
/// slot the FFI snapshot exposes — populated across a local `migrate()`.
#[allow(clippy::too_many_arguments)]
fn feed_bbr_on_ack(
    crypto_session: &Arc<Session>,
    sent_at: tokio::time::Instant,
    packet_bytes: u64,
    delivered_at_send: u64,
    delivered_time_at_send: Option<std::time::Instant>,
    ack_delay_us: u64,
    observability: &Observability,
    path_id: u8,
    sampled_rtt: bool,
    app_limited: bool,
) {
    let acked_at = std::time::Instant::now();
    let sent_at_std = sent_at.into_std();
    let sample = crate::transport::bandwidth_estimator::DeliverySample {
        // The connection's delivered counter when this segment went out. The
        // estimator subtracts it from the current total to get the bytes
        // delivered over the interval — the quantity BBR's rate sample is
        // defined as. Passing 0 here made every sample "one packet per RTT".
        delivered_bytes: delivered_at_send,
        // ...and when the counter stood at that value, which is the other end
        // of the same interval. `poll_send` stamps it in lock-step with
        // `sent_at`, so the fallback below is unreachable for any segment that
        // reached the wire; it degrades to the segment's own round trip, which
        // is the interval the estimator would have assumed anyway.
        delivered_at: delivered_time_at_send.unwrap_or(sent_at_std),
        sent_at: sent_at_std,
        acked_at,
        packet_bytes,
        // The application-limited phase this segment was **sent** in, carried
        // back by the segment itself (`RetiredSegment::app_limited_at_send`).
        // Not the phase in force now: a flight that left at full rate and is
        // being acknowledged after the sender ran dry was not app-limited, and
        // labelling it so would exclude from the bandwidth filter exactly the
        // samples that measure the path.
        is_app_limited: app_limited,
        ack_delay_us,
        // Karn's condition, carried through to the estimator's min-RTT filter.
        // A retransmitted segment's `sent_at` was restamped when it was resent,
        // so the elapsed time to this acknowledgement is not a round trip.
        rtt_sampled: sampled_rtt,
    };
    // The gauge publishes what the estimator concluded, not a second opinion.
    // The peer's claimed ack delay is a number nobody here measured, and the
    // estimator subtracts it only as far as the round trip this endpoint has
    // already timed allows (RFC 9002 §5.3, in `ack_delay_adjusted_rtt`).
    // Subtracting it again here on its own terms, which is what this used to do,
    // made the gauge say whatever the peer wanted: an operator judging a path by
    // `MetricsSnapshotFfi::rtt_us_path_0` or the `phantom.path.rtt` OTel gauge
    // could not tell "the path got faster" from "the peer claimed a long ack
    // delay", and a claim past the whole round trip drove the reading to zero,
    // where the guard below then discarded it and left the last honest sample
    // standing. Nothing in the control loop reads the gauge, so this was never a
    // safety problem — but a metric a remote party can dictate is worse than no
    // metric.
    let rtt_sample = crypto_session.on_packet_acked(sample);
    if sampled_rtt {
        let rtt_us = rtt_sample.as_micros() as u64;
        // A zero sample carries no information for a "last observed RTT" gauge,
        // so it is skipped; under the bound above it means the two clock
        // readings landed in the same microsecond, not that a peer talked the
        // sample down.
        if rtt_us > 0 {
            observability.record_rtt_us(rtt_us, path_id);
        }
    }
}

/// Anti-fingerprint send-timing jitter (WIRE v6): when enabled,
/// wait a uniform random [0, max] ms before this send so the inter-packet timing
/// no longer tracks the application's writes. Opt-in (default 0 → no-op, no
/// latency cost).
///
/// Distinct from pacing, and deliberately still an inline wait. Jitter is a
/// per-packet timing perturbation whose whole purpose is to sit between the
/// decision to send and the send; a session that has switched it on has already
/// accepted the latency. Pacing is a rate, it is answered by the pump's own
/// scheduler ([`DrainStop::Paced`]), and it must never be waited on from here.
async fn apply_send_jitter(crypto_session: &Arc<Session>) {
    let jitter_max = crypto_session.send_jitter();
    if jitter_max.is_zero() {
        return;
    }
    let delay = shaping::random_jitter(jitter_max.as_millis() as u32);
    if !delay.is_zero() {
        tokio::time::sleep(delay).await;
    }
}

/// Decide whether a rekey is needed before stamping a packet and, if so, perform
/// it. A rekey fires when the direction-wide AEAD-invocation high-watermark
/// ([`Session::send_needs_rekey`]) is crossed (Invariant 8). The per-stream C1
/// watermark is gone — since P4.0 the packet number is a per-direction `u64` that
/// cannot wrap within a session, so the nonce can never repeat.
///
/// Returns the extra flag bits to OR into the header, or `None` if a rekey was
/// required but failed (epoch saturated at `u8::MAX`) — the caller MUST fail the
/// send so the session reconnects rather than reusing a nonce.
///
/// T5.5(b) — the returned `PacketFlags::REKEY` bit is set not only on the single
/// rotation-trigger packet but on EVERY packet sent at the new epoch until the
/// peer acknowledges the rekey ([`Session::rekey_unconfirmed`] clears once an
/// authenticated inbound packet is seen at the new epoch). Re-advertising the
/// flag is what makes the receive-side catch-up gate in
/// [`Session::decrypt_packet_accepting_rekey`] safe: a lost rotation-trigger
/// packet no longer strands the peer, because the next new-epoch packet (incl. a
/// reliable retransmit) still carries REKEY and drives the catch-up.
fn rekey_before_stamp(crypto_session: &Arc<Session>, observability: &Observability) -> Option<u16> {
    if crypto_session.send_needs_rekey() {
        // Crossed the high-watermark: rotate now. `rekey()` marks the session
        // `rekey_unconfirmed`, so the flag below re-arms automatically.
        if let Err(e) = crypto_session.rekey() {
            log::error!("PhantomSession: mid-session rekey failed: {}", e);
            return None;
        }
        // A local (send-direction) key rotation actually committed.
        observability.record_rekey(Direction::Send);
    }
    // Re-advertise REKEY while our last rekey is still unacknowledged — even when
    // no rotation happened on this packet (the trigger may have rotated several
    // packets ago and been lost).
    Some(if crypto_session.rekey_unconfirmed() {
        PacketFlags::REKEY
    } else {
        0
    })
}

/// V2 send. Builds `PhantomPacket` with `PacketFlags::ENCRYPTED` and
/// the negotiated rekey epoch; AEAD nonce derives from the header
/// (`Session::encrypt_packet`), so a failed peer decrypt no longer
/// desyncs the local counter.
async fn send_app_data<T: SessionTransport>(
    transport: &Arc<T>,
    crypto_session: &Arc<Session>,
    session_id: SessionId,
    stream_id: TransportStreamId,
    payload: &[u8],
    base_flags: u16,
    reliable_offset: Option<u32>,
    observability: &Observability,
) -> bool {
    // Always OR in ENCRYPTED for application data.
    let mut flag_bits = base_flags | PacketFlags::ENCRYPTED;
    // Mid-session rekey: rotate to a fresh key BEFORE stamping this header when the
    // direction-wide AEAD high-watermark is crossed, so the header carries the new
    // epoch (+ the REKEY flag). The peer follows on the authenticated epoch bump
    // (it trial-decrypts under the next key).
    match rekey_before_stamp(crypto_session, observability) {
        Some(extra) => flag_bits |= extra,
        // Epoch saturated (u8::MAX): can't rotate further. Surface as a failed
        // send so the caller re-offers; the session reconnects rather than wrap.
        None => return false,
    }
    // Phase 4 / P4.0: draw the per-direction packet number at send time (so a
    // retransmit gets a fresh PN and the nonce is never reused).
    let packet_number = crypto_session.next_send_pn();
    // Build the inner AEAD plaintext (owned so size-padding can extend it). For
    // reliable data, prepend the gap-free per-stream `stream_offset` (A.5, 4
    // big-endian bytes) so the receiver reassembles in send order regardless of
    // `sequence` holes left by interleaved control frames. Unreliable / control
    // frames carry no offset. This all lives inside the AEAD (authenticated,
    // invisible on the wire).
    let mut plaintext: Vec<u8> = match reliable_offset {
        Some(off) => {
            let mut v = Vec::with_capacity(4 + payload.len());
            v.extend_from_slice(&off.to_be_bytes());
            v.extend_from_slice(payload);
            v
        }
        None => payload.to_vec(),
    };
    // Anti-fingerprint size padding (WIRE v6): when the session's
    // padding policy is enabled, pad this packet up to a PADÉ bucket INSIDE the
    // AEAD plaintext and flag it `PADDED`, so the on-wire datagram size no longer
    // tracks the payload size. The receiver strips the trailer after a successful
    // decrypt. Opt-in (default `None` → no-op, zero overhead). The `PADDED` flag
    // rides in the AAD (and is HP-masked on the wire), so a tamper fails the AEAD.
    let trailer = shaping::padding_trailer_len(plaintext.len(), crypto_session.padding_policy());
    if trailer > 0 {
        shaping::append_padding(&mut plaintext, trailer);
        flag_bits |= PacketFlags::PADDED;
    }
    let header = PacketHeader::new(
        session_id,
        stream_id,
        packet_number,
        PacketFlags::new(flag_bits),
    )
    .with_epoch(crypto_session.current_epoch())
    // Stamp the current send-side path_id (D5 — Phase 4). Default 0 (the implicit
    // handshake path) is behaviour-preserving; after a `migrate()` bump this carries
    // the new path label so the peer detects the new path and issues a challenge.
    // Retransmits flow through here too, so ARQ re-carries on the new path (D7).
    .with_path_id(crypto_session.current_send_path_id());
    // The data-plane packet carries no `extensions` (TLV headroom stays empty),
    // so the AEAD AAD binds an empty extensions slice — matching the wire.
    let ciphertext = match timed_encrypt(crypto_session, observability, &header, &plaintext, &[]) {
        Ok(c) => c,
        Err(e) => {
            log::error!("PhantomSession: encrypt_packet failed: {}", e);
            return false;
        }
    };
    let packet = PhantomPacket::new(header, ciphertext);
    // Header protection (T4.6): XOR-mask the whole 15-byte header before it hits
    // the wire (WIRE v6: `HP_PROTECTED_OFFSET == 0`, no cleartext header byte).
    // Infallible in practice (the payload always carries the AEAD tag).
    let buf = match crypto_session.protect_packet(&packet) {
        Ok(b) => b,
        Err(e) => {
            log::error!("PhantomSession: header protection failed: {}", e);
            return false;
        }
    };
    let size = buf.len();
    apply_send_jitter(crypto_session).await;
    if let Err(e) = transport.send_bytes(&buf[..size]).await {
        log::error!("PhantomSession: transport send failed: {}", e);
        return false;
    }
    // Pacing is a wire-rate limiter, so it settles the full on-wire size —
    // header, ciphertext and tag, not just the payload. The drain authorised
    // this segment against the bucket before it knew how large it would be, so
    // this is where the true cost is booked; the difference is at most one
    // segment and the bucket carries it as debt rather than forgiving it.
    crypto_session.pacing_consume(size as u64);
    // Inflight/cwnd accounting MUST use the same unit the ACK and retransmission
    // paths settle in. `Stream::ack` returns and `on_packet_retransmitted`
    // subtracts the segment's *payload* length (`seg.data.len()`), so the send side has to add
    // the payload length too — adding the full wire size here leaked the
    // per-packet framing overhead (15-byte header + AEAD tag) as phantom
    // inflight, which silently exhausted the congestion window after a few dozen
    // packets and stalled long-lived sessions. (Bandwidth/BDP derive from acked
    // bytes, so they stay in the same payload unit.)
    //
    // ...and only congestion-controlled bytes may be booked at all. The presence
    // of a reliable offset is exactly what says this segment is one the ARQ will
    // track: acknowledgements name reliable offsets, so those are the only bytes
    // the retire path can ever subtract again. An unreliable datagram booked here
    // would be a debt nothing can pay — it would shrink `cwnd - inflight` for the
    // reliable data behind it for the rest of the session, and put ProbeRTT's
    // "wait until the pipe is empty" condition permanently out of reach.
    if reliable_offset.is_some() {
        crypto_session.on_packet_sent(payload.len() as u64);
    }
    true
}

/// Emit a WINDOW_UPDATE packet announcing `limit` — the cumulative total this side is
/// willing to have sent on `stream_id`, counted from the stream's first byte. Encrypted
/// under the current session epoch (Phase 4.3 flow control).
async fn send_window_update<T: SessionTransport>(
    transport: &Arc<T>,
    crypto_session: &Arc<Session>,
    session_id: SessionId,
    stream_id: TransportStreamId,
    limit: u64,
    observability: &Observability,
) -> bool {
    let mut flag_bits = PacketFlags::ENCRYPTED | PacketFlags::WINDOW_UPDATE;
    // WINDOW_UPDATE obeys the same direction-wide rekey discipline before stamping.
    match rekey_before_stamp(crypto_session, observability) {
        Some(extra) => flag_bits |= extra,
        None => return false,
    }
    let packet_number = crypto_session.next_send_pn();
    let header = PacketHeader::new(
        session_id,
        stream_id,
        packet_number,
        PacketFlags::new(flag_bits),
    )
    .with_epoch(crypto_session.current_epoch());
    let payload = limit.to_be_bytes();
    let ciphertext = match timed_encrypt(crypto_session, observability, &header, &payload, &[]) {
        Ok(c) => c,
        Err(e) => {
            log::error!("PhantomSession: WINDOW_UPDATE encrypt failed: {}", e);
            return false;
        }
    };
    let packet = PhantomPacket::new(header, ciphertext);
    let buf = match crypto_session.protect_packet(&packet) {
        Ok(b) => b,
        Err(e) => {
            log::error!(
                "PhantomSession: WINDOW_UPDATE header protection failed: {}",
                e
            );
            return false;
        }
    };
    if let Err(e) = transport.send_bytes(&buf).await {
        log::error!("PhantomSession: WINDOW_UPDATE send failed: {}", e);
        return false;
    }
    true
}

/// Emit an idle keep-alive packet (download-only liveness): a
/// small `ENCRYPTED | KEEPALIVE` packet with an **empty** payload, stamped on the
/// current send path.
///
/// `is_pong` selects the role: a bare `KEEPALIVE` is a PING (`is_pong = false`);
/// `KEEPALIVE | ACK` is the PONG echo a receiver sends back (`is_pong = true`).
/// Either way the payload is empty, so the peer's `recv()` never sees it. The
/// packet is sealed exactly like application data — ENCRYPTED (Inv-2), a fresh
/// per-direction packet number (no nonce reuse), header-protected — so an off-path
/// peer can neither forge nor replay it (the replay window rejects a duplicate PN
/// after AEAD verify, Inv-4). Returns `false` on a rekey-saturation or
/// seal/transport failure (the caller just skips the keep-alive — it is
/// best-effort).
async fn send_keepalive<T: SessionTransport>(
    transport: &Arc<T>,
    crypto_session: &Arc<Session>,
    session_id: SessionId,
    is_pong: bool,
    observability: &Observability,
) -> bool {
    let mut flag_bits = PacketFlags::ENCRYPTED | PacketFlags::KEEPALIVE;
    if is_pong {
        flag_bits |= PacketFlags::ACK;
    }
    // Obey the same direction-wide rekey discipline before stamping the header.
    match rekey_before_stamp(crypto_session, observability) {
        Some(extra) => flag_bits |= extra,
        None => return false,
    }
    let packet_number = crypto_session.next_send_pn();
    let header = PacketHeader::new(
        session_id,
        // Reserved raw-app stream id (1) — the keep-alive carries no stream data,
        // but a stable id keeps the header well-formed and consistent with the
        // session's own send()/recv() surface.
        RAW_APP_STREAM_ID as TransportStreamId,
        packet_number,
        PacketFlags::new(flag_bits),
    )
    .with_epoch(crypto_session.current_epoch())
    .with_path_id(crypto_session.current_send_path_id());
    let ciphertext = match timed_encrypt(crypto_session, observability, &header, &[], &[]) {
        Ok(c) => c,
        Err(e) => {
            log::error!("PhantomSession: keep-alive encrypt failed: {}", e);
            return false;
        }
    };
    let packet = PhantomPacket::new(header, ciphertext);
    let buf = match crypto_session.protect_packet(&packet) {
        Ok(b) => b,
        Err(e) => {
            log::error!("PhantomSession: keep-alive header protection failed: {}", e);
            return false;
        }
    };
    if let Err(e) = transport.send_bytes(&buf).await {
        log::error!("PhantomSession: keep-alive send failed: {}", e);
        return false;
    }
    true
}

/// Emit one anti-fingerprint COVER (dummy) packet (WIRE v6): an
/// `ENCRYPTED | COVER` packet with **empty** inner plaintext, PADÉ-padded to a
/// bucket so it is not a tiny distinctive size on the wire. It carries no stream
/// data; the peer AEAD-authenticates it (which refreshes its liveness timer and
/// makes off-path injection impossible) then drops it before the data path, so it
/// never reaches `recv()`. Cover is always padded, independent of the session's
/// data-padding policy.
async fn send_cover<T: SessionTransport>(
    transport: &Arc<T>,
    crypto_session: &Arc<Session>,
    session_id: SessionId,
    observability: &Observability,
) -> bool {
    let mut flag_bits = PacketFlags::ENCRYPTED | PacketFlags::COVER;
    // Same direction-wide rekey discipline as any other send.
    match rekey_before_stamp(crypto_session, observability) {
        Some(extra) => flag_bits |= extra,
        None => return false,
    }
    let mut plaintext = Vec::new();
    let trailer = shaping::padding_trailer_len(0, PaddingPolicy::Padme);
    if trailer > 0 {
        shaping::append_padding(&mut plaintext, trailer);
        flag_bits |= PacketFlags::PADDED;
    }
    let packet_number = crypto_session.next_send_pn();
    let header = PacketHeader::new(
        session_id,
        RAW_APP_STREAM_ID as TransportStreamId,
        packet_number,
        PacketFlags::new(flag_bits),
    )
    .with_epoch(crypto_session.current_epoch())
    .with_path_id(crypto_session.current_send_path_id());
    let ciphertext = match timed_encrypt(crypto_session, observability, &header, &plaintext, &[]) {
        Ok(c) => c,
        Err(e) => {
            log::error!("PhantomSession: cover encrypt failed: {}", e);
            return false;
        }
    };
    let packet = PhantomPacket::new(header, ciphertext);
    let buf = match crypto_session.protect_packet(&packet) {
        Ok(b) => b,
        Err(e) => {
            log::error!("PhantomSession: cover header protection failed: {}", e);
            return false;
        }
    };
    if let Err(e) = transport.send_bytes(&buf).await {
        log::error!("PhantomSession: cover send failed: {}", e);
        return false;
    }
    true
}

/// Round trips the draining window spans, once the peer has announced its close
/// (WIRE v8). QUIC's draining period is three PTOs and this is the same shape and
/// the same reason: three round trips is long enough that a datagram already on the
/// path when the close was sent has arrived, and short enough that nothing waits on
/// a session neither side is using.
const DRAIN_ROUND_TRIPS: u32 = 3;

/// Floor on the draining window.
///
/// The round-trip figure it multiplies is a *measurement*, and on a loopback or a
/// datacentre path that measurement is a few hundred microseconds — three of which
/// would drain nothing at all, because the displacement this window exists to absorb
/// is produced by the path's queues and not by its length. It is the same judgement
/// the retransmit timer already makes with its own 200 ms floor: below this, a
/// round-trip measurement is too small to size a timeout with.
const DRAIN_WINDOW_MIN: std::time::Duration = std::time::Duration::from_millis(200);

/// Absolute ceiling on the draining window, and the reason it exists is the peer.
///
/// The round-trip figure is one the peer can inflate — delaying its own
/// acknowledgements raises what this side measures — so without a ceiling the length
/// of a *local* commitment would be a number a remote party writes. The cost of the
/// ceiling is that a genuinely very long path drains for fewer than
/// [`DRAIN_ROUND_TRIPS`] round trips; the cost of not having one is a lever, and a
/// lever is worse.
const DRAIN_WINDOW_MAX: std::time::Duration = std::time::Duration::from_millis(600);

/// How long this side keeps reading after the peer announces its close (WIRE v8).
///
/// What this buys and what it costs both belong in the open, and the two things it
/// moves are different resources with different reclaim paths — conflating them is
/// how the improvement gets overstated. Measured on loopback against the revision
/// before this frame existed, one client connecting to one listener and then dropped:
///
/// * The **embedder-visible session slot** — how long the accepted session's `recv()`
///   goes on blocking, which is how long a handler loop is held — was **44.8 s** and
///   is **0.20 s**, a factor of about 220. The 44.8 s is the liveness path doing its
///   job slowly: an idle keep-alive fired into a closed port, a path-down verdict,
///   then the migration idle timeout.
/// * The **demux route table** — the 18 CID routes the listener holds for that
///   session — was **not reclaimed at all** within a 250 s observation, and is
///   reclaimed in **0.22 s**. That one is not a ratio and should not be written as
///   one: at the old revision nothing reclaimed it, because every trigger the table
///   had was waiting for a datagram the departed client was never going to send.
///
/// The window is held rather than released the instant the close lands, and unlike
/// either figure above it is a duration this side chose. The peer cannot lengthen it
/// past [`DRAIN_WINDOW_MAX`], and cannot re-arm it by sending more: the deadline is
/// taken once, from this value, at the first close copy. On a fast path it is
/// [`DRAIN_WINDOW_MIN`] — a measured loopback `min_rtt` is a few hundred
/// microseconds, so three of it is nowhere near the floor — and on the 235 ms
/// reference WAN path it is the ceiling.
fn peer_close_drain_window(crypto_session: &Session) -> std::time::Duration {
    // `min_rtt` is the only round-trip figure kept at session scope. RFC 9002's PTO
    // is larger — it adds the variance term and the peer's maximum acknowledgement
    // delay — so multiplying this one gives a deliberately modest window rather than
    // a generous one, which is the right direction for a value that holds a resource.
    drain_window_for_rtt(crypto_session.bandwidth_snapshot().min_rtt)
}

/// The draining window for one measured round trip. Split out from
/// [`peer_close_drain_window`] because the bounds are the part with a security
/// argument behind them, and they should be checkable without a session to hang a
/// round-trip measurement on.
fn drain_window_for_rtt(rtt: std::time::Duration) -> std::time::Duration {
    rtt.saturating_mul(DRAIN_ROUND_TRIPS)
        .clamp(DRAIN_WINDOW_MIN, DRAIN_WINDOW_MAX)
}

/// Put what this session still owes the peer on the wire, then tell the peer it is
/// over. The shared tail of `disconnect()` and of dropping the handle.
///
/// Both do nothing when the peer has already announced its own close: there is
/// nobody left to flush to, and answering a close with a close would only make two
/// sessions each wait for the other's last word.
async fn finish_and_announce<T: SessionTransport>(
    transport: &Arc<T>,
    crypto_session: &Arc<Session>,
    session_id: SessionId,
    streams: &Arc<DashMap<u32, Arc<Stream>>>,
    observability: &Observability,
) {
    if crypto_session.peer_closed() {
        return;
    }
    flush_pending_window_updates(
        transport,
        crypto_session,
        session_id,
        streams,
        observability,
    )
    .await;
    drain_streams_fully(
        transport,
        crypto_session,
        session_id,
        streams,
        observability,
    )
    .await;
    // Only now — the close frame ends the peer's session, so a peer that acted on it
    // before the drained data arrived would lose that data. Sending them in turn is
    // the only ordering this side can impose, and on a datagram transport it is not
    // arrival order; what covers the rest is the peer's own draining window, not
    // anything achievable from here.
    announce_close(transport, crypto_session, session_id, observability).await;
}

/// How many close frames a departing session emits back to back.
///
/// The frame is unacknowledged and never retransmitted, so redundancy is the only
/// loss tolerance available to it, and this is a fixed count rather than a loop with
/// a condition on purpose: the condition would have to be something about the peer,
/// and the peer is by then the thing we have stopped being able to observe. Three
/// datagrams survive an independent 10% loss rate with probability 0.999, and cost
/// three packet numbers out of a `u64` — nothing against the nonce budget Invariant 8
/// guards, which is why the number is small rather than merely finite.
const CLOSE_FRAME_COPIES: usize = 3;

/// Emit one session-close announcement (WIRE v8): an `ENCRYPTED | CONTROL` packet
/// whose AEAD plaintext is the single byte [`ControlSubtype::CLOSE`], Padme-padded to
/// a bucket.
///
/// What the padding does, stated narrowly because the broad version is not true.
/// Unpadded this frame is 41 bytes on the PhantomUDP wire — a 9-byte envelope, a
/// 15-byte header and a 16-byte tag over a one-byte plaintext — and the Padme trailer
/// takes it to 45. That collapses the *body length* into a bucket: a control frame
/// with a one-, two- or three-byte body is the same size on the wire, so the emitted
/// size says a control frame went out and does not say which one, which is what keeps
/// a later subtype from being told apart from a close by an observer counting bytes.
///
/// Two things it does **not** do, and the second is the one that was claimed here and
/// is false. It does not put the frame on a size nothing else emits: a default
/// session's one-byte reliable application write is the same 45 bytes, because the
/// padded control plaintext and a four-byte stream offset plus one application byte
/// are both five bytes. So a close is not distinguishable *by size alone* from every
/// other frame — only from most of them, and from every control frame the registry
/// might later add. And it does not hide that a session ended: [`CLOSE_FRAME_COPIES`]
/// identical datagrams back to back followed by silence is a *pattern*, and no amount
/// of per-frame padding removes a pattern. Hiding that would take the session padding
/// its data frames too, which is the opt-in policy and costs bandwidth on every
/// packet — a decision for the deployment, not for this frame.
///
/// Everything about it is best-effort: a rekey saturation, a seal failure or a dead
/// transport all just mean the peer will fall back to noticing the silence, which is
/// exactly what it did before this frame existed. Nothing here is allowed to be fatal
/// to a session that is ending anyway.
async fn send_control_close<T: SessionTransport>(
    transport: &Arc<T>,
    crypto_session: &Arc<Session>,
    session_id: SessionId,
    observability: &Observability,
) -> bool {
    let mut flag_bits = PacketFlags::ENCRYPTED | PacketFlags::CONTROL;
    // Same direction-wide rekey discipline as any other send (Invariant 5). On
    // `None` the direction has run out of epochs, and the only correct thing left to
    // do is stop sending: retrying a best-effort teardown frame against a saturated
    // key schedule spends nonce budget on a session nobody is listening to.
    match rekey_before_stamp(crypto_session, observability) {
        Some(extra) => flag_bits |= extra,
        None => return false,
    }
    let mut plaintext = vec![ControlSubtype::CLOSE];
    let trailer = shaping::padding_trailer_len(plaintext.len(), PaddingPolicy::Padme);
    if trailer > 0 {
        shaping::append_padding(&mut plaintext, trailer);
        flag_bits |= PacketFlags::PADDED;
    }
    let packet_number = crypto_session.next_send_pn();
    let header = PacketHeader::new(
        session_id,
        RAW_APP_STREAM_ID as TransportStreamId,
        packet_number,
        PacketFlags::new(flag_bits),
    )
    .with_epoch(crypto_session.current_epoch())
    .with_path_id(crypto_session.current_send_path_id());
    let ciphertext = match timed_encrypt(crypto_session, observability, &header, &plaintext, &[]) {
        Ok(c) => c,
        Err(e) => {
            log::error!("PhantomSession: close-frame encrypt failed: {}", e);
            return false;
        }
    };
    let packet = PhantomPacket::new(header, ciphertext);
    let buf = match crypto_session.protect_packet(&packet) {
        Ok(b) => b,
        Err(e) => {
            log::error!(
                "PhantomSession: close-frame header protection failed: {}",
                e
            );
            return false;
        }
    };
    if let Err(e) = transport.send_bytes(&buf).await {
        log::error!("PhantomSession: close-frame send failed: {}", e);
        return false;
    }
    true
}

/// Tell the peer this session is over, [`CLOSE_FRAME_COPIES`] times.
///
/// Each copy draws its own packet number, so the peer's replay window accepts the
/// first to arrive and refuses the rest without the receive branch needing to be
/// idempotent itself. Emitted only from a session that reached the wire: a handshake
/// that never established has no keys to seal with and no peer state to release.
async fn announce_close<T: SessionTransport>(
    transport: &Arc<T>,
    crypto_session: &Arc<Session>,
    session_id: SessionId,
    observability: &Observability,
) {
    if !matches!(
        crypto_session.state(),
        SessionState::Connected | SessionState::Migrating
    ) {
        return;
    }
    for _ in 0..CLOSE_FRAME_COPIES {
        if !send_control_close(transport, crypto_session, session_id, observability).await {
            // The first failure is the transport or the key schedule telling us the
            // remaining copies would fail the same way; stop rather than log thrice.
            break;
        }
    }
}

/// Maintain a minimum outbound packet rate with cover traffic (WIRE v6): when
/// no packet has gone out for `cover_interval`, emit a COVER dummy so
/// silence + volume no longer leak (idle-fill + a floor rate of `1000 / interval_ms`
/// packets/sec). `last_pn` / `last_at` track the last observed outbound activity —
/// any real packet advances the send PN, resetting the idle window, so cover only
/// fills genuine gaps and never piles on top of active traffic.
async fn maybe_send_cover<T: SessionTransport>(
    transport: &Arc<T>,
    crypto_session: &Arc<Session>,
    session_id: SessionId,
    last_pn: &mut u64,
    last_at: &mut std::time::Instant,
    observability: &Observability,
) {
    let interval = crypto_session.cover_interval();
    if interval.is_zero() {
        return;
    }
    if crypto_session.state() != SessionState::Connected {
        return;
    }
    let pn = crypto_session.peek_send_pn();
    if pn != *last_pn {
        // Real (or prior cover) traffic went out since the last check — reset.
        *last_pn = pn;
        *last_at = std::time::Instant::now();
        return;
    }
    if last_at.elapsed() >= interval
        && send_cover(transport, crypto_session, session_id, observability).await
    {
        *last_pn = crypto_session.peek_send_pn();
        *last_at = std::time::Instant::now();
    }
}

/// Emit a V2 PATH_VALIDATION packet on `path_id` carrying the given
/// 32-byte challenge or response payload. Encrypted under the current
/// session epoch.
/// Build + encrypt a `PATH_VALIDATION` packet, returning its on-wire bytes. The
/// caller routes them: to the established peer (a response echo) via `send_bytes`,
/// or to a migration candidate (a server-issued challenge) via `send_to_candidate`
/// (Phase 4). Returns `None` only if the AEAD seal fails.
fn encrypt_path_validation(
    crypto_session: &Arc<Session>,
    session_id: SessionId,
    path_id: u8,
    payload: [u8; crate::transport::path::PATH_CHALLENGE_LEN],
    observability: &Observability,
) -> Option<Vec<u8>> {
    let packet_number = crypto_session.next_send_pn();
    let mut packet = build_path_validation_packet(session_id, path_id, packet_number, payload);
    let flag_bits = packet.header.flags.0 | PacketFlags::ENCRYPTED;
    packet.header.flags = PacketFlags::new(flag_bits);
    packet.header.epoch = crypto_session.current_epoch();
    let plaintext = std::mem::take(&mut packet.payload);
    let ciphertext = match timed_encrypt(
        crypto_session,
        observability,
        &packet.header,
        &plaintext,
        &[],
    ) {
        Ok(c) => c,
        Err(e) => {
            log::error!("PhantomSession: PATH_VALIDATION encrypt failed: {}", e);
            return None;
        }
    };
    packet.payload = ciphertext;
    match crypto_session.protect_packet(&packet) {
        Ok(buf) => Some(buf),
        Err(e) => {
            log::error!(
                "PhantomSession: PATH_VALIDATION header protection failed: {}",
                e
            );
            None
        }
    }
}

/// Send a `PATH_VALIDATION` packet to the established peer (a response echo).
async fn send_path_validation<T: SessionTransport>(
    transport: &Arc<T>,
    crypto_session: &Arc<Session>,
    session_id: SessionId,
    path_id: u8,
    payload: [u8; crate::transport::path::PATH_CHALLENGE_LEN],
    observability: &Observability,
) -> bool {
    let buf = match encrypt_path_validation(
        crypto_session,
        session_id,
        path_id,
        payload,
        observability,
    ) {
        Some(b) => b,
        None => return false,
    };
    if let Err(e) = transport.send_bytes(&buf).await {
        log::error!("PhantomSession: PATH_VALIDATION send failed: {}", e);
        return false;
    }
    true
}

/// Hard cap on concurrent receive streams a peer can open on one session (H-3).
///
/// The recv path auto-creates a `Stream` for any of the 2^32 `stream_id`s; without a cap a
/// peer can spray distinct ids to explode the stream table. Enforced in `handle_packet`,
/// on the arm that would create the stream: past the cap the segment is refused, and being
/// unrecorded it is not SACKed either, so the sender retransmits rather than believing the
/// stream exists. Sized well above QUIC's ~100-stream default so real multiplexing is
/// unaffected.
///
/// It is a multiplier on several of the per-stream bounds below, so raising it raises what
/// one session can be made to hold — see the receive-memory section in this module's
/// documentation for which of them it multiplies.
pub const MAX_STREAMS: usize = 256;

/// Ceiling on the app-delivery backlog one session may hold, in bytes.
///
/// The delivery queue is unbounded so the reader never blocks, but a peer that ignores flow
/// control could flood it. Compliant senders are bounded by one advertised window per stream
/// (enforced in `poll_send`); crossing this cap means the peer is misbehaving, so the session
/// is torn down rather than buffered without limit. Every byte counted here is resident, so
/// the number is a memory commitment and stays a fixed literal: it is deliberately NOT
/// derived from the window ceiling, or raising that ceiling would silently raise how much a
/// peer can make this side hold. 4 MiB is four times what one auto-tuned stream can
/// legitimately have outstanding, so honest traffic does not approach it.
///
/// The cap bounds *resident* bytes only because every queued item is charged
/// [`DELIVERY_ITEM_OVERHEAD_BYTES`] on top of its payload — see there for what a cap
/// counting payload alone would really admit.
///
/// **The backlog can stand at this cap plus [`MAX_DELIVERY_CHARGE_PER_FRAME`], and that sum
/// is the figure to size from.** The charge for a frame is only known once the frame has
/// been decrypted and routed, so the reader checks the counter around the frame rather than
/// inside it and one frame's worth always lands past the line. Moving the check below the
/// charge instead of above it does not change that — the same frame is the one that crosses
/// — so the overshoot is stated here rather than designed away.
pub const RECV_DELIVERY_HARD_CAP: u64 = 4 * 1024 * 1024;

/// The most one inbound frame can add to the delivery backlog, in bytes — the overshoot
/// [`RECV_DELIVERY_HARD_CAP`] can be standing at when the reader notices it has been passed.
///
/// A frame usually enqueues one item, but a `COALESCED` bundle is split into one item per
/// non-empty sub-payload, and each of those is charged [`DELIVERY_ITEM_OVERHEAD_BYTES`]. So
/// the worst frame is not the fullest one: it is the one carrying the most sub-payloads, and
/// a sub-payload costs a peer only its two-byte length prefix and the single byte that keeps
/// it from being skipped as empty. Derived from the bundle framing rather than stated, so a
/// change to either takes this with it.
pub const MAX_DELIVERY_CHARGE_PER_FRAME: u64 = {
    let bundle = MAX_RECV_PAYLOAD - crate::transport::packet_coalescer::HEADER_SIZE;
    let per_sub = crate::transport::packet_coalescer::SUB_HEADER_SIZE + 1;
    (bundle / per_sub) as u64 * (1 + DELIVERY_ITEM_OVERHEAD_BYTES)
};

/// Bytes of *structure* one queued delivery item costs beyond its payload: a slot in the
/// channel block the item is parked in, and — for reliable data, which arrives as
/// `plaintext.slice(4..)` — the reference block that slice allocates plus the
/// decrypted-packet allocation it keeps alive.
///
/// It exists because the item count, not the byte count, is what a peer minimising segment
/// size controls. A cap counting payload alone admits `RECV_DELIVERY_HARD_CAP` **items** when
/// each carries one byte, and an item costs far more than a byte: measured against the real
/// channel it is a little over 64 B, so a 4 MiB payload cap really admitted about 300 MiB.
/// Charging this figure per item makes the cap bound what is resident rather than what is
/// nominal. 128 B is a deliberate over-estimate of the measured cost, because this is what a
/// published memory bound rests on and erring high there is the safe direction.
///
/// It is charged on FIN items too, which carry no payload at all: a peer can emit those
/// without limit, and an uncharged item is an uncapped one.
pub const DELIVERY_ITEM_OVERHEAD_BYTES: u64 = 128;

/// Depth, in items, of the bounded channel between the delivery task and one opened stream's
/// [`PhantomStream::recv`](crate::api::stream::PhantomStream::recv).
///
/// A bounded channel is its own enforcement — the delivery task blocks rather than growing it
/// — so the slot count needs no separate gate. The bytes did: a queue bounded in slots holds
/// whatever the slots weigh, and until the receive path refused oversized frames a slot held
/// as much as the byte pipe would carry. With
/// [`MAX_RECV_PAYLOAD`] enforced on the way in, this
/// depth times that payload is a real byte bound, and both halves of it are things this side
/// decides.
///
/// It is resident whenever the application is slower than the peer, and there are
/// [`MAX_STREAMS`] of it.
pub const STREAM_RECV_CHANNEL_DEPTH: usize = 1024;

/// Depth, in items, of the bounded channel behind
/// [`PhantomSession::recv`](PhantomSession::recv) — the raw-app stream (id 1), which is the
/// path `send`/`recv` use and the one every WAN measurement in the tree ran through.
///
/// One per session rather than one per stream, hence a small term next to
/// [`STREAM_RECV_CHANNEL_DEPTH`], but resident on the same terms.
pub const RAW_APP_RECV_CHANNEL_DEPTH: usize = 256;

/// EPS-02 symmetric-rotation step — extracted from [`handle_packet`] so the role
/// branch is unit-tested always-on (not only by the `#[ignore]` `udp_integration`
/// suite). After the post-AEAD path detects a peer migration (`note_migration_path`
/// returned a slide), rotate OUR OWN outbound CID so the return direction's
/// cleartext ConnId does not stay stable across the peer's move (§12.5). A server
/// (whose client migrated) rotates the s2c CID path-id-silent (the socket-routed
/// client needs no window slide, and not bumping the send `path_id` prevents a
/// ping-pong). A client (whose server migrated) bumps its send `path_id` and
/// rotates the c2s CID (the path_id bump slides the server's c2s demux window onto
/// the rotated CID — the no-stranding fix), ending the exchange in one round.
fn apply_eps02_peer_migration_rotation<T: SessionTransport>(crypto: &Session, transport: &T) {
    if crypto.is_server() {
        transport.set_outbound_cid(crypto.advance_outbound_cid());
    } else {
        crypto.next_migration_path_id();
        transport.set_outbound_cid(crypto.advance_outbound_cid());
    }
}

/// Recv-side handler for a packet:
/// - session-id guard → drop any frame not stamped with the negotiated
///   session id before touching any state (H1).
/// - decrypt (REQUIRED on application data — a non-empty unencrypted
///   post-handshake packet is a downgrade indicator and is dropped).
/// - ACK (now `ENCRYPTED | ACK`, post-decrypt) → parse the authenticated
///   `Sack` from the plaintext, retire every covered segment, feed BBR per
///   retired segment + route to the stream / demux. Forged/plaintext ACKs
///   cannot reach this path (H1); a malformed SACK is dropped, never a panic.
/// - PATH_VALIDATION flag → drive the path registry: verify against an
///   outstanding challenge if one exists, otherwise echo the payload
///   back as a response.
/// - WINDOW_UPDATE flag → apply the peer's announced cumulative flow-control
///   limit, taking the maximum of it and the one already held.
/// - COALESCED flag → split the decrypted bundle into sub-payloads and
///   route each through the demux as an independent application chunk.
#[allow(clippy::too_many_arguments)]
async fn handle_packet<T: SessionTransport>(
    packet: PhantomPacket,
    session_id: SessionId,
    crypto_recv: &Arc<Session>,
    streams_recv: &Arc<DashMap<u32, Arc<Stream>>>,
    demux_recv: &Arc<StreamDemultiplexer>,
    transport_send_ack: &Arc<T>,
    transport_for_path: &Arc<T>,
    // The reader hands decrypted application data and FIN signals to the
    // delivery task via this unbounded channel instead of blocking on
    // `recv_tx`/the demux — so a slow `recv()` consumer can never
    // head-of-line-stall inbound ACK/control.
    deliver_tx: &mpsc::UnboundedSender<DeliverItem>,
    undelivered_bytes: &AtomicU64,
    // Reader-task-local scratch: the reusable ACK buffer plus the observability
    // bookkeeping (path-challenge start instants, last peer path, stream gauge).
    scratch: &mut RecvScratch,
    observability: &Observability,
    leg: LegType,
    // The channels a `PhantomStream` needs, used to build one for each
    // newly-registered peer-initiated stream (the same ones a locally opened
    // stream's handle holds).
    stream_link: &StreamLink,
    // Sink where newly-registered peer-initiated streams are
    // pushed so `accept_stream()` can hand them to the embedder.
    incoming_stream_tx: &mpsc::Sender<Arc<crate::api::stream::PhantomStream>>,
    // The session's published `ConnectionState`. Handed to every `PhantomStream`
    // built here so a peer-initiated stream can refuse a write the pump would
    // discard, exactly as a locally-opened one does.
    session_state: &Arc<AtomicU8>,
) {
    let stream_id: u32 = packet.header.stream_id.into();
    let path_id = packet.header.path_id;

    // Bind every inbound frame to the negotiated session (H1). In ε / WIRE v5 the
    // inner `session_id` is off-wire: `parse_protected` reconstructed
    // `header.session_id` from this session's id, so this comparison is now a
    // structural backstop (always true on a correctly-routed frame). The real
    // cross-session bind is the AEAD AAD, which still authenticates `session_id`
    // — a frame mis-delivered to the wrong session reconstructs that session's id
    // into the AAD → wrong AAD → AEAD fail below, so forged ACK/FIN injection can
    // never reach the stream table, BBR, or the path registry. Retained as a
    // defensive backstop.
    if packet.header.session_id != session_id {
        return;
    }

    // Mark path activity even before decrypt (the path id is plaintext
    // header bytes; this is just a liveness signal for the sweep).
    crypto_recv.mark_path_seen(path_id);

    // NOTE: ACK/FIN are NO LONGER processed here, pre-decrypt. They are
    // authenticated `ENCRYPTED | ACK` control frames now (H1) and are handled
    // *after* the AEAD gate below — see the ACK branch following the decrypt.

    // Decrypt if marked. V2 sessions REQUIRE ENCRYPTED on application
    // data — a non-empty unencrypted V2 application-data packet is a
    // downgrade indicator and is dropped (same posture as V1).
    let plaintext: Vec<u8> = if packet.header.flags.contains(PacketFlags::ENCRYPTED) {
        // Read the epoch we are on BEFORE the open (one relaxed atomic load) so a
        // forward-epoch packet that the catch-up path actually accepts can be
        // reported as a receive-direction rekey below. Comparing the packet's own
        // epoch against this (rather than re-reading ours afterwards) keeps an
        // ordinary send-side rotation out of the `Recv` count. A send-side
        // rotation landing *inside* this window can still over-count by one — it
        // is a counter, never control flow, so the skew is accepted rather than
        // paid for with a lock on the receive hot path.
        let epoch_before = crypto_recv.current_epoch();
        // Accept a single authenticated forward rekey step (C1): if this
        // packet's epoch is one ahead, the peer rekeyed — trial-decrypt under
        // the next key and only commit the ratchet on AEAD success, so a forged
        // epoch can't desync us. Same-epoch packets take the ordinary path.
        let decrypt_started = std::time::Instant::now();
        let opened = crypto_recv.decrypt_packet_accepting_rekey(
            &packet.header,
            &packet.payload,
            &packet.extensions,
        );
        // Time only the AEAD call itself (the timer stops before any routing).
        // Successful opens only, so `decrypt_count` stays "packets actually
        // opened" and a rejected forgery cannot skew the average.
        if opened.is_ok() {
            observability.record_decrypt_ns(duration_ns(decrypt_started));
            // The open succeeded at a forward epoch → the catch-up path derived
            // and committed `header.epoch - epoch_before` rotations. Report one
            // rekey per committed step (bounded by `MAX_REKEY_CATCHUP`).
            let steps = packet.header.epoch.saturating_sub(epoch_before);
            for _ in 0..steps {
                observability.record_rekey(Direction::Recv);
            }
        }
        match opened {
            Ok(pt) => pt,
            Err(e) => {
                // Distinguish the two drop reasons for the security metrics: a
                // post-AEAD sliding-window replay reject vs an AEAD-verify
                // failure (Invariant 4 — replay is checked after AEAD opens).
                // decrypt_packet doesn't surface old-vs-duplicate, so record the
                // representative `Duplicate` reason.
                if matches!(e, CoreError::ReplayDetected(_)) {
                    observability.record_replay_rejected(ReplayReason::Duplicate);
                } else {
                    observability.record_aead_failure(leg, AeadAlgorithm::Aes256Gcm);
                }
                log::warn!("PhantomSession: V2 decrypt failed (dropping packet): {}", e);
                return;
            }
        }
    } else {
        // Stripped-flag downgrade defense (Invariant 2, M-2): ANY unencrypted post-handshake
        // packet is dropped — including an empty-payload one whose only remaining effect would
        // be a forged standalone FIN tearing down an `open_stream()` stream without AEAD
        // verification. Legitimate data and control frames (incl. FIN) always set ENCRYPTED.
        observability.record_unencrypted_dropped(leg);
        log::warn!(
            "PhantomSession: dropping unencrypted post-handshake packet (downgrade / forged FIN?)"
        );
        return;
    };

    // Strip anti-fingerprint size padding (WIRE v6): a PADDED
    // packet's AEAD plaintext ends with a `‹zeros› ‖ pad_n:u16be` trailer. The
    // PADDED flag is AEAD-authenticated (it is part of the header AAD verified
    // above), so this only runs on genuine padded packets; a malformed trailer
    // from a buggy peer is dropped without panic. Stripping here — before any
    // downstream parse — means the SACK / keepalive / data paths all see the real
    // inner plaintext, exactly as if no padding had been applied.
    let plaintext: Vec<u8> = if packet.header.flags.contains(PacketFlags::PADDED) {
        match shaping::strip_padding(&plaintext) {
            Ok(inner) => inner.to_vec(),
            Err(_) => {
                log::warn!("PhantomSession: dropping packet with malformed padding trailer");
                return;
            }
        }
    } else {
        plaintext
    };

    // Liveness (P4.3): an authenticated inbound packet (it passed AEAD above) proves
    // the peer is alive on some path — refresh the activity timer so the pump's
    // liveness sweep does not false-trip. Plaintext/forged packets never reach here
    // (a failed decrypt returned early), so an off-path attacker cannot keep a dead
    // session looking alive.
    if packet.header.flags.contains(PacketFlags::ENCRYPTED) {
        crypto_recv.update_activity();
        // M-1: this packet just AEAD-authenticated, so its source really is the peer — possibly
        // at a NEW address (migration / NAT rebind). Commit it as the migration candidate ONLY
        // now (post-decrypt), so a spoofed CID-matched datagram (which never decrypts) cannot
        // clobber the candidate slot and misdirect / stall a legitimate migration. No-op for
        // same-source packets and for non-address transports (default trait impl).
        transport_for_path.confirm_authenticated_source();
        // ε / WIRE v5: the path_id is now authenticated. If the peer migrated
        // (a new forward path_id), slide our inbound CID demux window so its rotated
        // CID stays routable for arbitrarily many migrations. No-op on the client and
        // for a path_id that is not newer (reorder / duplicate / passive rebind).
        if let Some(slide) = crypto_recv.note_migration_path(packet.header.path_id) {
            crypto_recv.signal_cid_slide(slide);
            // The PEER migrated: an authenticated packet arrived on a forward
            // path id. This is the counterpart of the local `Migrate` /
            // `MigrateServer` records — without it a server (which never issues
            // `Migrate` itself) would report no migrations at all. `note_migration_path`
            // CASes exactly once per migration, so this records once too.
            observability.record_path_migration(scratch.last_peer_path, packet.header.path_id);
            scratch.last_peer_path = packet.header.path_id;
            // EPS-02 (symmetric rotation) — the peer migrated, so rotate our OWN outbound
            // CID too; otherwise the return direction keeps a stable cleartext ConnId across
            // the move and a both-networks observer relinks the session by it (§12.5). BOTH
            // sides now act, but the mechanism differs by demux topology:
            //
            //  * SERVER detecting a CLIENT migration: rotate the s2c CID only, path_id-SILENT.
            //    The client is socket-routed (accepts any inbound CID), so it needs no window
            //    slide; and NOT bumping the server's send path_id is what prevents a ping-pong
            //    (the client would otherwise see a forward server path_id and re-reflect).
            //
            //  * CLIENT detecting a SERVER migration (D4, the EPS-02 closure for server-
            //    initiated migration): rotate the c2s CID AND bump our send path_id. The
            //    server DOES demux c2s by a CID window keyed on the client path_id, so the
            //    path_id bump is what makes it slide that window to the rotated c2s CID — the
            //    no-stranding fix (rotating the CID alone, without the path_id bump, was the
            //    hazard the old "client must not rotate" rule avoided). This terminates in one
            //    round: the server, seeing the client's forward path_id, slides its c2s window
            //    AND runs its own path_id-silent s2c re-rotation (the SERVER arm above), from
            //    which the client sees no new forward server path_id → note_migration_path
            //    returns None → no re-reflection. The reflected c2s comes from the SAME client
            //    source, so the server's confirm_authenticated_source is a no-op for it.
            //
            // The `path_id` bump (session layer) and the CID rotation (transport layer)
            // are not a single atomic step, so a send racing this rotation can stamp a
            // one-step-skewed `(path_id=N, CID_{N-1})` or `(path_id=N-1, CID_N)` pair. That
            // is harmless: the peer demux routes by CID against a window with `T = 2`
            // trailing + `K = 16` leading slack (cid_chain), which absorbs a ±1 skew, so the
            // skewed packet still routes and the L1 ARQ would re-carry it anyway — no strand.
            // Same two-step shape as the `Migrate` / `migrate_server` pump arms above.
            apply_eps02_peer_migration_rotation(crypto_recv, transport_for_path.as_ref());
        }
    }

    // Idle keep-alive (download-only liveness). A keep-alive carries
    // no application bytes; its sole effect is the `update_activity()` above (which
    // refreshed this side's liveness timer and cleared any outstanding probe). It
    // is handled here, BEFORE the ACK branch, because a PONG is `KEEPALIVE | ACK`
    // and must not be mis-parsed as a SACK. A bare `KEEPALIVE` is a PING → echo a
    // `KEEPALIVE | ACK` PONG so the peer's own liveness timer + outstanding-probe
    // flag clear; a `KEEPALIVE | ACK` is that PONG → nothing more to do. Either way
    // we return so the empty payload never reaches the SACK / data paths.
    if packet.header.flags.contains(PacketFlags::KEEPALIVE) {
        if !packet.header.flags.contains(PacketFlags::ACK) {
            // PING → reply with a PONG (KEEPALIVE | ACK). Best-effort; a drop just
            // means the peer re-PINGs next interval (its probe stays outstanding).
            let _ = send_keepalive(
                transport_send_ack,
                crypto_recv,
                session_id,
                true,
                observability,
            )
            .await;
        }
        return;
    }

    // In-session control frame (WIRE v8). The AEAD plaintext leads with a one-byte
    // `ControlSubtype`; the branch for that subtype owns whatever follows it.
    //
    // Where this sits is the whole of its security argument, and moving it earlier to
    // save work would give away the only thing that makes it safe:
    //
    //  * it is BELOW the ENCRYPTED gate above, whose `else` arm drops every
    //    unencrypted post-handshake frame including an empty one (Invariant 2), so a
    //    forged plaintext close cannot reach it — a control frame that arrived here
    //    was sealed by the peer's key;
    //  * it is BELOW the replay window inside `decrypt_packet_accepting_rekey`
    //    (Invariant 4), so a byte-identical replay of a captured close was already
    //    refused before this line runs. That is what makes the branch idempotent for
    //    free rather than something it has to implement — and it is why an off-path
    //    attacker holding a recorded datagram has no session-kill primitive.
    //
    // Every path returns, including the unknown-subtype one. The function ends in a
    // fall-through that hands non-empty plaintext to the application, so a control
    // body that fell out of here would be delivered as a byte of the caller's stream.
    if packet.header.flags.contains(PacketFlags::CONTROL) {
        if plaintext.len() < CONTROL_SUBTYPE_LEN {
            // Names no subtype. An authenticated peer does not produce this, so it is
            // a peer bug rather than an attack — dropped either way, and in
            // particular it is not read as a close: a zeroed or truncated body must
            // not be able to end a session.
            log::debug!("PhantomSession: dropping control frame with no subtype byte");
            return;
        }
        match plaintext[0] {
            ControlSubtype::CLOSE => {
                // The peer said it is leaving. Recorded here and acted on nowhere near
                // here: the receive loop reads this after each packet and starts its
                // draining window, at the end of which it ends and the pump runs its
                // ordinary teardown — the same teardown that publishes the state,
                // retires the stream gauge and releases the demux routes. Recording
                // rather than tearing down is what keeps a close that overtook a data
                // frame from discarding it; nothing re-sends what this frame passes.
                log::info!("PhantomSession: peer announced session close");
                crypto_recv.note_peer_closed();
            }
            other => {
                log::debug!("PhantomSession: dropping control frame with unknown subtype {other}");
            }
        }
        return;
    }

    // Cover traffic (WIRE v6): a COVER packet carries no application
    // data (its inner plaintext is empty after the padding strip above). Its only
    // effect is the `update_activity()` already done above (it AEAD-authenticated, so
    // it proves the peer is alive and cannot be off-path injected). Drop it here,
    // before the SACK / data paths, so the empty payload never surfaces in `recv()`.
    // (A cover packet is never an ACK — it is `ENCRYPTED | COVER | PADDED` — so this
    // must precede the ACK branch below.)
    if packet.header.flags.contains(PacketFlags::COVER) {
        return;
    }

    // Authenticated SACK ACK (H1, L1-A). ACKs are `ENCRYPTED | ACK` control
    // frames whose AEAD *plaintext* carries a `Sack` (largest_acked,
    // ack_delay_us, and the inclusive received ranges). We act on the ACK only
    // *after* AEAD verify, which authenticates the header (including `session_id`)
    // and the SACK plaintext — so a forged or stripped-flag ACK (dropped above by
    // the downgrade defense) can neither retire a pending segment, restore a
    // flow-control permit, poison BBR, nor close a stream. A malformed SACK from
    // a buggy (but authenticated) peer is dropped without panic and retires
    // nothing.
    if packet.header.flags.contains(PacketFlags::ACK) {
        let sack = match crate::transport::sack::Sack::from_wire(&plaintext) {
            Ok(s) => s,
            Err(e) => {
                log::debug!(
                    "PhantomSession: dropping malformed SACK ({} B): {}",
                    plaintext.len(),
                    e
                );
                return;
            }
        };
        // Clone the stream out so the table's shard is released before anything is awaited.
        // `on_sack` waits for the stream's send-buffer lock, which the drain path holds for
        // a whole pass, and a `DashMap` reference held across that wait holds the shard's
        // read lock with it: `open_stream` and every other write to the shard would block
        // the thread it runs on until the drain let go.
        let stream = streams_recv.get(&stream_id).map(|s| s.clone());
        if let Some(stream) = stream {
            // Retire EVERY segment the SACK covers (cumulative). RTT is sampled
            // inside `on_sack` per Karn (only for never-retransmitted segments);
            // feed BBR per retired segment using the real `ack_delay_us`.
            let result = stream.on_sack(&sack).await;
            for retired in &result.retired {
                if let Some(sent_at) = retired.sent_at {
                    // `!was_retransmit` is Karn's condition — the same gate
                    // `Stream::on_sack` uses for its own srtt sample — so the
                    // per-path RTT gauge never records an ambiguous sample.
                    feed_bbr_on_ack(
                        crypto_recv,
                        sent_at,
                        retired.size,
                        retired.delivered_at_send,
                        retired.delivered_time_at_send,
                        sack.ack_delay_us as u64,
                        observability,
                        path_id,
                        !retired.was_retransmit,
                        retired.app_limited_at_send,
                    );
                }
            }
            // L1-B: the SACK gap detector just declared
            // segments lost; wake the send loop so Pass-0 fast-retransmits them promptly.
            // Nothing about that declaration is reported to congestion control from here.
            // Both reports — the copy against the flight and the hole against the round —
            // are made at the *retransmission* point (`drain_streams_priority_ordered`'s
            // `if seg.retransmit { … }`), which covers BOTH a SACK-gap fast-retransmit and
            // an RTO-timeout retransmit and so fires even against a peer that has stopped
            // acknowledging altogether.
            //
            // Reporting here as well would take the same bytes off `inflight_bytes` twice:
            // a SACK-gap-lost segment charged at both detection AND retransmission nets
            // `+b −b −b +b −b = −b` over its send/loss/resend/ack lifecycle — a permanent
            // under-count that inflates the cwnd budget (`cwnd − inflight`) and accumulates
            // with every SACK-gap loss → over-send, exactly when the controller should be
            // backing off. And it would double the hole count too, since a declaration
            // here is answered by a copy there.
            //
            // Nor does the acknowledgement loop above report any: it is handed each retired
            // segment and the instant that segment's latest copy left, and it draws no
            // conclusion about loss from either. What it could conclude is bounded by what
            // an acknowledgement carries, which is the segment's gap-free stream offset —
            // shared by every copy — plus the moment it turned up, which the peer chooses.
            //
            // A retirement wakes the loop for two more reasons: it frees
            // congestion-window room for new data, and it returns a send-buffer
            // slot that a deferred application write may be waiting on. Without
            // this the pump would only notice on the next 10 ms heartbeat, which
            // on an ack-clocked path is a self-inflicted rate limit.
            if !result.lost.is_empty() || !result.retired.is_empty() {
                crypto_recv.notify_outbound_ready();
            }
            // The acknowledgement goes no further than the stream's send side. In
            // particular it is not queued to the stream's application channel: nothing reads
            // it there, and a stream only ever written to would fill that bounded channel
            // with its own acknowledgements, after which the delivery task — which serves
            // every stream in turn — would wait on that stream's next item for good. A FIN
            // riding the ACK ends the peer's half, and goes through the delivery channel so
            // it is ordered after any in-flight data frames.
            if packet.header.flags.contains(PacketFlags::FIN) {
                take_unordered_remote_fin(&stream, stream_id, deliver_tx, undelivered_bytes);
            }
            // Reliable FIN teardown. An acknowledged FIN finishes this side's half of
            // the stream and nothing more: the peer's half stays open until its own FIN has
            // ended it, and until then the stream keeps receiving — unless the application
            // has let go of the stream, in which case nobody is left to receive anything.
            // It is dropped when both are done, which this acknowledgement, the peer's FIN
            // (the reliable branch below) or the release in the pump can be the one to
            // complete.
            if stream.is_retirable().await {
                retire_stream(stream_id, streams_recv, deliver_tx, &scratch.stream_gauge);
            }
        }
        return;
    }

    // WINDOW_UPDATE dispatch (Phase 4.3 flow control). Payload is a big-endian u64 carrying
    // the peer's cumulative limit for this stream — the total it is willing to have sent on
    // it, counted from the stream's first byte.
    if packet.header.flags.contains(PacketFlags::WINDOW_UPDATE) {
        let Ok(be) = <[u8; WINDOW_UPDATE_PAYLOAD_LEN]>::try_from(&plaintext[..]) else {
            log::warn!(
                "PhantomSession: WINDOW_UPDATE payload length {} (expected {})",
                plaintext.len(),
                WINDOW_UPDATE_PAYLOAD_LEN
            );
            return;
        };
        let limit = u64::from_be_bytes(be);
        if let Some(stream) = streams_recv.get(&stream_id) {
            // The limit is monotone, so applying it takes the maximum — a duplicate or a
            // reordered frame changes nothing. Then wake the send loop so a stream stopped
            // at the old limit resumes immediately instead of waiting a full poll tick.
            stream.apply_peer_window_limit(limit);
            crypto_recv.notify_outbound_ready();
        }
        return;
    }

    // PATH_VALIDATION dispatch (Phase 4.2): the codec inspects the *plaintext*
    // because the wire packet was sealed by the AEAD layer.
    if packet.header.flags.contains(PacketFlags::PATH_VALIDATION) {
        if plaintext.len() != crate::transport::path::PATH_CHALLENGE_LEN {
            log::warn!(
                "PhantomSession: PATH_VALIDATION plaintext length {} (expected {})",
                plaintext.len(),
                crate::transport::path::PATH_CHALLENGE_LEN
            );
            return;
        }
        let mut payload_buf = [0u8; crate::transport::path::PATH_CHALLENGE_LEN];
        payload_buf.copy_from_slice(&plaintext);
        // If we have an in-flight challenge on this path, try to
        // verify against it. If verification succeeds, the path
        // transitions to Validated and we're done. If it fails, the
        // registry already transitioned to Failed — also done.
        match crypto_recv.path_state(path_id) {
            Some(crate::transport::path::PathStateKind::Validating) => {
                // The peer echoed our challenge on this path. If it validates AND a
                // migration candidate is pending, SWITCH the active peer to it (D7)
                // and reset RTT/cwnd for the new network (D8) — no re-handshake,
                // keys persist; subsequent app data + ARQ retransmits flow to the
                // new peer. (P4.1 only challenged; P4.2 performs the switch.)
                let validated = crypto_recv.complete_path_validation(path_id, &payload_buf);
                // Resolve the outstanding challenge's latency. The start stamp is
                // recorded where we issued the challenge (below); a missing entry
                // means either this side never issued one, or the pump's expiry
                // sweep (`sweep_path_validation_timeouts`) already abandoned it
                // and recorded a `timeout` sample — either way there is nothing
                // left to time, and the one-entry-one-sample rule is preserved.
                if let Some(started) = scratch.challenges.resolve(path_id) {
                    observability.record_path_validation(
                        started.elapsed(),
                        path_id,
                        if validated {
                            PathValidationOutcome::Success
                        } else {
                            PathValidationOutcome::Failure
                        },
                    );
                }
                if validated && transport_for_path.promote_candidate() {
                    crypto_recv.reset_congestion();
                    for s in streams_recv.iter() {
                        s.value().reset_rto();
                    }
                    // M-3: if this was a passive-rebind validation (the reserved id),
                    // retire the path so a LATER rebind re-registers it fresh and can
                    // be challenged again. The reserved id stays Validated otherwise,
                    // and `begin_path_validation` on a Validated path returns None, so
                    // the second rebind would never issue a challenge. Active-migration
                    // ids are left intact (they are retired by their own lifecycle).
                    if path_id == crate::transport::session::REBIND_VALIDATION_PATH_ID {
                        crypto_recv.retire_path(path_id);
                        // M-3 passive NAT rebind: the peer's ADDRESS moved without it
                        // bumping `path_id`, so the peer-migration record above never
                        // fired — but the active peer really did just switch. Report it
                        // with the reserved validation id as the destination, which is
                        // exactly what distinguishes a passive rebind from an active
                        // `migrate()` on a dashboard.
                        observability.record_path_migration(scratch.last_peer_path, path_id);
                    }
                }
                return;
            }
            Some(crate::transport::path::PathStateKind::Validated)
            | Some(crate::transport::path::PathStateKind::Failed) => {
                // Terminal state — ignore.
                return;
            }
            _ => {
                // Unknown or Unvalidated: treat this packet as an
                // incoming challenge and echo the payload back as our
                // response. The remote will then verify it against its
                // own pending challenge.
                let _ = send_path_validation(
                    transport_for_path,
                    crypto_recv,
                    session_id,
                    path_id,
                    payload_buf,
                    observability,
                )
                .await;
                return;
            }
        }
    }

    // PATH-001 split (D10, Phase 4). Runs AFTER AEAD verify + the per-direction
    // replay window, so it never acts on an attacker-chosen plaintext path_id.
    //
    // PATH-001b (recv, relaxed): AEAD-authenticated, non-replayed app data is
    // DELIVERED regardless of which path it arrived on. Dropping it by source buys
    // no security (only the real peer holds the keys; replays are already rejected)
    // and would break a seamless NAT-rebind / migration. PATH-001a (the strict
    // send-gate) lives in the send loop: app data is only ever sent to the
    // established peer — a candidate gets a PATH_CHALLENGE, never app data.
    //
    // Server-side migration (P4.1): if this app packet arrived on a not-yet-
    // Validated path AND the transport flagged a migration candidate (a new source
    // for this CID), proactively issue + send a challenge to the candidate so the
    // new path can validate. We do NOT switch the peer here (that is P4.2); the
    // challenge goes to the candidate under its anti-amplification budget.
    if !matches!(
        crypto_recv.path_state(path_id),
        Some(crate::transport::path::PathStateKind::Validated)
    ) {
        if transport_for_path.has_migration_candidate() {
            if let Some(challenge) = crypto_recv.begin_path_validation(path_id) {
                // Start (or restart, on a re-issued challenge) the validation
                // timer for this path. The completion branch above resolves it;
                // the pump's heartbeat expires it if the peer never answers.
                scratch.challenges.start(path_id);
                if let Some(buf) = encrypt_path_validation(
                    crypto_recv,
                    session_id,
                    path_id,
                    challenge,
                    observability,
                ) {
                    // To the candidate, NOT the peer; capped at 3× by the transport.
                    let _ = transport_for_path.send_to_candidate(&buf).await;
                }
            }
        } else {
            // No migration candidate (non-address transport, or a path id seen
            // without a source change): track it for a possible later challenge.
            crypto_recv.register_unvalidated_path(path_id);
        }
        // PATH-001b: fall through and deliver the authenticated data below.
    } else if transport_for_path.has_migration_candidate() {
        // M-3 (passive NAT rebind): the frame arrived on an already-Validated path —
        // the path-0 rebind case, where the peer's source address changed WITHOUT it
        // calling `migrate()`, so it never bumped `path_id`. The active-migration gate
        // above is skipped (path is Validated), so without this branch the new
        // authenticated source would never be challenged → never promoted → the
        // downstream (server→client) direction keeps targeting the OLD, now-dead
        // address → stall. Detection is therefore ADDRESS-driven, not path-id-driven:
        // a migration candidate exists only because `confirm_authenticated_source`
        // committed an AEAD-authenticated source that differs from the established
        // peer (M-1). We challenge that candidate on the RESERVED validation path-id
        // (carved out of the migration id space), which the registry can take through
        // `Validating → Validated` independently of the always-Validated path 0. The
        // challenge goes ONLY to the candidate (its claimed address), under the same
        // 3× anti-amplification cap — anti-spoof is preserved exactly as for an active
        // migration. The peer switch happens later, when the candidate echoes the
        // challenge (the PATH_VALIDATION completion branch above).
        let rebind_path = crate::transport::session::REBIND_VALIDATION_PATH_ID;
        if let Some(challenge) = crypto_recv.begin_path_validation(rebind_path) {
            // Same validation timer as the active-migration challenge above.
            scratch.challenges.start(rebind_path);
            if let Some(buf) = encrypt_path_validation(
                crypto_recv,
                session_id,
                rebind_path,
                challenge,
                observability,
            ) {
                let _ = transport_for_path.send_to_candidate(&buf).await;
            }
        }
    }

    // COALESCED dispatch (Phase 2.5): split the decrypted bundle into sub-payloads
    // and hand each, IN ORDER, to the single FIFO delivery task. Bundles are NOT
    // reassembled by stream offset — they are not emitted by the live sender (a
    // recv-side capability only), are not independently sequenced, and do not
    // auto-ACK (the outer sequence was consumed by the replay window). Delivered in
    // arrival order, preserving the bundle's internal order.
    if packet.header.flags.contains(PacketFlags::COALESCED) {
        let inner_for_codec = PhantomPacket {
            header: packet.header,
            payload: plaintext,
            extensions: Vec::new(),
        };
        match unwrap_coalesced_packet(&inner_for_codec) {
            Ok(Some(subs)) => {
                let payloads: Vec<Bytes> = subs
                    .into_iter()
                    .filter(|s| !s.is_empty())
                    .map(Bytes::from)
                    .collect();
                deliver_in_order_run(payloads, stream_id, deliver_tx, undelivered_bytes);
            }
            Ok(None) => {
                log::warn!("PhantomSession: COALESCED flag set but bundle didn't parse");
            }
            Err(e) => {
                log::warn!("PhantomSession: COALESCED parse error: {}", e);
            }
        }
        return;
    }

    // Reliable application data → reassemble by the gap-free `stream_offset` (A.5),
    // emit an authenticated **SACK** ACK inline (H1, L1-A), then deliver the
    // in-order run. The reliable AEAD plaintext is `[stream_offset: u32 BE][data]`;
    // reordering on `stream_offset` (not the control-frame-holed `header.sequence`)
    // is what makes reliable in-order delivery correct over a reordering path. The
    // ACK is an `ENCRYPTED | ACK` control frame whose AEAD *plaintext* carries a
    // `Sack` over `stream_offset` ranges; the peer parses it only after AEAD verify,
    // so it cannot be forged off-path and a malformed range from a buggy peer is
    // dropped post-decrypt without crashing (handled in the sender branch). The SACK
    // retires every covered segment at once, so a lost ACK no longer strands a
    // segment — the next SACK re-acks it cumulatively. The ACK's own
    // `header.sequence` is drawn from this side's per-stream send counter — shared
    // with our data/window-update sends — so `(epoch, stream_id, sequence, path_id)`
    // is unique and never collides with our outbound data (the nonce-reuse trap); it
    // obeys the C1 rekey discipline. "ACK" means "received, decrypted, replay-passed,
    // accepted into in-order reassembly."
    if packet.header.flags.contains(PacketFlags::RELIABLE) {
        // Reliable plaintext = [stream_offset: u32 BE][data] (A.5). A frame shorter
        // than the 4-byte offset prefix is malformed — no legitimate sender emits
        // one — so drop it (never a panic).
        if plaintext.len() < 4 {
            log::warn!(
                "PhantomSession: reliable frame missing stream-offset prefix ({} B)",
                plaintext.len()
            );
            return;
        }
        let pt = Bytes::from(plaintext);
        let stream_offset = u32::from_be_bytes([pt[0], pt[1], pt[2], pt[3]]);
        let data = pt.slice(4..);
        // Read before the payload is handed on: an empty one is the peer's persist probe,
        // and the answer to it is composed further down, after the reassembly step.
        let is_persist_probe = data.is_empty() && !packet.header.flags.contains(PacketFlags::FIN);

        // H-3: cap concurrent receive streams. A new stream_id is auto-created only while
        // under MAX_STREAMS; past the cap the segment is refused (and, being unrecorded, not
        // SACKed → the sender retransmits / the stream stalls), so a peer cannot explode the
        // stream table across the 2^32 id space.
        let existing = streams_recv.get(&stream_id).map(|s| s.clone());
        let local = match existing {
            Some(s) => s,
            None => {
                match classify_unheld_stream(stream_id, demux_recv, &scratch.peer_streams) {
                    UnheldStream::Opens => {}
                    UnheldStream::Retired => {
                        // Dropped, in one of two ways. Closed from both ends: what arrives
                        // now is a copy of a segment this side already took — usually the
                        // peer's FIN, resent because the acknowledgement of it was lost — and
                        // every offset up to it arrived before the stream was dropped, since
                        // that is what its read half having closed means. Or let go of by
                        // this side's application once its own FIN was acknowledged, with the
                        // peer's half still open: the peer may still be writing, and nobody
                        // is left here to read what it writes.
                        //
                        // Either way the answer acknowledges every offset up to this one. In
                        // the second case that deliberately includes offsets this side never
                        // received and bytes it throws away unread: there is no reader to owe
                        // them to, and an acknowledgement is what lets the peer's writes on
                        // the stream complete instead of being resent for the life of the
                        // session.
                        if let Some(sack) = crate::transport::sack::Sack::from_inclusive_ranges(
                            vec![(0, stream_offset)],
                            0,
                        ) {
                            send_stream_sack(
                                &sack,
                                stream_id,
                                path_id,
                                session_id,
                                crypto_recv,
                                transport_send_ack,
                                &mut scratch.ack_buf,
                                observability,
                            )
                            .await;
                        }
                        // Completing needs room as well as acknowledgements: the peer writes
                        // no further than the last limit it was granted, and a sender queues
                        // the writes it cannot place ahead of every other stream's. So a
                        // stream that granted nothing more would stop the peer's whole
                        // session. See `released_stream_grant` for what is granted and how
                        // often.
                        if let Some(limit) = released_stream_grant(
                            stream_offset,
                            is_persist_probe,
                            packet.header.flags.contains(PacketFlags::FIN),
                        ) {
                            send_window_update(
                                transport_send_ack,
                                crypto_recv,
                                session_id,
                                stream_id as TransportStreamId,
                                limit,
                                observability,
                            )
                            .await;
                        }
                        return;
                    }
                    UnheldStream::NotThePeers => {
                        // Refused like a segment past the cap: unrecorded, so not
                        // acknowledged. A peer allocating from this side's half of the id
                        // space then sees a stall, where acknowledging would have it retire
                        // data that no stream here will ever deliver.
                        log::warn!(
                            "PhantomSession: refusing a segment on stream {stream_id}, an id \
                             of this side's parity that it never opened"
                        );
                        return;
                    }
                }
                if streams_recv.len() >= MAX_STREAMS {
                    log::warn!(
                        "PhantomSession: refusing new receive stream {stream_id}: \
                         MAX_STREAMS ({MAX_STREAMS}) reached"
                    );
                    return;
                }
                let new_stream = Arc::new(Stream::with_recv_tuning(
                    stream_id as TransportStreamId,
                    scratch.recv_tuning.clone(),
                ));
                streams_recv.insert(stream_id, new_stream.clone());

                // For peer-initiated user streams (id ≥ 2), register in
                // the demux so Task B can route data to this stream, then push a
                // PhantomStream handle onto the incoming-stream channel so the
                // embedder can pick it up via `accept_stream()`. `try_send` is
                // non-blocking: if the 128-slot channel is full the handle is dropped
                // right here, and a dropped handle is a released stream like any
                // other — this side closes its half, and the stream leaves the table
                // once that close is acknowledged, instead of sitting in it with no
                // reader for the life of the session. Only streams with id ≥ 2 are
                // user-visible; id 1 is the raw-app reserved stream (never accepted
                // via this path). Registration happens exactly ONCE per stream_id
                // (the `None` arm here), guarded by the DashMap entry.
                if stream_id > RAW_APP_STREAM_ID {
                    // From here on a frame for this id finds either the stream or the
                    // record that it existed, never an id free to open again.
                    scratch.peer_streams.mark_seen(stream_id);
                    // Peer-initiated user stream — count it on the active-streams
                    // gauge exactly once (this `None` arm runs once per stream id,
                    // guarded by the DashMap entry and the record above). The matching
                    // retire is `retire_stream`, `retire_released_stream`, the
                    // offset-exhaustion fallback in `flush_deferred_sends`, or the
                    // session-teardown drain.
                    scratch.stream_gauge.opened(stream_id);
                    let handle = demux_recv.register_stream(stream_id, STREAM_RECV_CHANNEL_DEPTH);
                    let phantom_stream = Arc::new(crate::api::stream::PhantomStream::new(
                        handle,
                        stream_link.clone(),
                        session_state.clone(),
                    ));
                    // Non-blocking push: a full incoming channel is a backpressure
                    // signal from the embedder (not consuming); don't block the reader.
                    if incoming_stream_tx.try_send(phantom_stream).is_err() {
                        log::debug!(
                            "PhantomSession: incoming_stream_tx full or closed; stream \
                             {stream_id} was never handed to the application and is released"
                        );
                    }
                }
                new_stream
            }
        };
        // Accept into the reorder buffer FIRST so the SACK derived next reflects it.
        // `accept_in_order` returns the in-order run now deliverable and stamps the
        // data-arrival instant; `received_sack(0)` then populates `ack_delay_us`
        // from a coarse `now − recv_at`. A `None` SACK is structurally impossible
        // here (we just accepted an offset), but we skip the ACK rather than unwrap.
        let delivered = local.accept_in_order(stream_offset, vec![data]).await;
        let Some(sack) = local.received_sack(0).await else {
            return;
        };
        if !send_stream_sack(
            &sack,
            stream_id,
            path_id,
            session_id,
            crypto_recv,
            transport_send_ack,
            &mut scratch.ack_buf,
            observability,
        )
        .await
        {
            return;
        }

        // Deliver the in-order run released by the reorder buffer (empty if this
        // segment filled a future hole — it waits for the gap to close). A
        // zero-length payload contributes nothing to it and is dropped there.
        deliver_in_order_run(delivered, stream_id, deliver_tx, undelivered_bytes);

        // A zero-length reliable segment that is not the FIN sentinel is the peer's
        // flow-control persist probe: it is stopped on this side's limit and has nothing
        // outstanding to wait on, so it is asking what that limit is. Re-state it. Because
        // the limit is a total, one answer repairs however many earlier `WINDOW_UPDATE`
        // frames the path ate — and because both of its terms move only on real application
        // consumption, a receiver that is not reading re-states the number its peer is
        // already stopped at and leaves it stopped.
        if is_persist_probe {
            local.stage_window_update_limit(local.recv_limit());
            crypto_recv.notify_outbound_ready();
        }

        // Record a FIN's reliable offset; emit the per-stream Close (EOF) ONLY once
        // the reorder buffer has released that offset IN ORDER (after all preceding
        // data). Checked on every reliable packet so a FIN that arrived over a gap
        // surfaces its EOF only when the gap-filling segment finally closes it —
        // never ahead of the data it was waiting on (otherwise a reader trusting
        // `recv() -> Ok(None)` would stop and silently lose the trailing data).
        if packet.header.flags.contains(PacketFlags::FIN) {
            local.note_remote_fin(stream_offset);
        }
        if local.take_in_order_fin() {
            if deliver_tx.send(DeliverItem::Close(stream_id)).is_ok() {
                undelivered_bytes.fetch_add(delivery_charge(0), Ordering::AcqRel);
            }
            // The peer's half just ended. If this side's FIN was already acknowledged, both
            // halves are done and this frame is the one that completes the close.
            if local.is_retirable().await {
                retire_stream(stream_id, streams_recv, deliver_tx, &scratch.stream_gauge);
            }
        }
        return;
    }

    // Non-reliable application data → deliver in arrival order (unreliable data is
    // not sequenced/reordered by design). Unbounded + non-blocking, so the reader
    // never stalls on a slow `recv()` consumer; counted toward the backlog only on
    // a successful enqueue (a dead delivery task can't inflate `undelivered_bytes`).
    if !plaintext.is_empty() {
        let charge = delivery_charge(plaintext.len());
        if deliver_tx
            .send(DeliverItem::Data(stream_id, Bytes::from(plaintext), false))
            .is_ok()
        {
            undelivered_bytes.fetch_add(charge, Ordering::AcqRel);
        }
    }

    // A FIN outside the reliable stream: a bare `ENCRYPTED | FIN`, which a sender falls back
    // to once a stream's offset space is exhausted. It ends the peer's half as surely as the
    // in-order one does, so it is recorded the same way — otherwise a stream closed from
    // both ends this way would never be dropped. A stream the table no longer holds has
    // nothing left to end.
    if packet.header.flags.contains(PacketFlags::FIN) {
        let stream = streams_recv.get(&stream_id).map(|s| s.clone());
        if let Some(stream) = stream {
            take_unordered_remote_fin(&stream, stream_id, deliver_tx, undelivered_bytes);
            if stream.is_retirable().await {
                retire_stream(stream_id, streams_recv, deliver_tx, &scratch.stream_gauge);
            }
        }
    }
}

/// Record a FIN the peer sent outside the reliable stream — on an unreliable frame or on an
/// acknowledgement — and hand the application its EOF through the delivery channel, ordered
/// after any data already queued there.
///
/// The EOF goes out only if this FIN is what ended the peer's half. One that arrives after
/// the half has already ended, however it ended, delivers nothing: the application has had
/// its EOF. Ids 0 and 1 have no application channel a FIN could end.
fn take_unordered_remote_fin(
    stream: &Stream,
    stream_id: u32,
    deliver_tx: &mpsc::UnboundedSender<DeliverItem>,
    undelivered_bytes: &AtomicU64,
) {
    if stream_id > RAW_APP_STREAM_ID
        && stream.note_unordered_remote_fin()
        && deliver_tx.send(DeliverItem::Close(stream_id)).is_ok()
    {
        undelivered_bytes.fetch_add(delivery_charge(0), Ordering::AcqRel);
    }
}

/// Hand an in-order run of reliable payloads (as released by
/// [`Stream::accept_in_order`]) to the single FIFO delivery task, in order. Each
/// non-empty chunk is counted toward the `undelivered_bytes` backlog only on a
/// successful enqueue, so a dead delivery task (consumer gone, `deliver_tx`
/// dropped) cannot inflate the counter for data that was discarded.
fn deliver_in_order_run(
    run: Vec<Bytes>,
    stream_id: u32,
    deliver_tx: &mpsc::UnboundedSender<DeliverItem>,
    undelivered_bytes: &AtomicU64,
) {
    for chunk in run {
        if chunk.is_empty() {
            continue;
        }
        let charge = delivery_charge(chunk.len());
        if deliver_tx
            .send(DeliverItem::Data(stream_id, chunk, true))
            .is_ok()
        {
            undelivered_bytes.fetch_add(charge, Ordering::AcqRel);
        }
    }
}

/// Seal `sack` as an `ENCRYPTED | ACK` frame for `stream_id` and send it on the path the
/// acknowledged segment arrived on.
///
/// Returns `false` only when the send epoch is saturated, in which case nothing was sent:
/// the frame is dropped rather than a nonce reused, the sender retransmits, and the session
/// is expected to reconnect. A failed seal or send is logged and still returns `true`.
#[allow(clippy::too_many_arguments)]
async fn send_stream_sack<T: SessionTransport>(
    sack: &crate::transport::sack::Sack,
    stream_id: u32,
    path_id: u8,
    session_id: SessionId,
    crypto_recv: &Arc<Session>,
    transport_send_ack: &Arc<T>,
    ack_buf: &mut Vec<u8>,
    observability: &Observability,
) -> bool {
    let mut ack_flag_bits = PacketFlags::ENCRYPTED | PacketFlags::ACK;
    match rekey_before_stamp(crypto_recv, observability) {
        Some(extra) => ack_flag_bits |= extra,
        None => return false,
    }
    let ack_pn = crypto_recv.next_send_pn();
    let ack_header = PacketHeader::new(
        session_id,
        stream_id as TransportStreamId,
        ack_pn,
        PacketFlags::new(ack_flag_bits),
    )
    .with_epoch(crypto_recv.current_epoch())
    .with_path_id(path_id);
    let ack_payload = sack.to_wire();
    match timed_encrypt(crypto_recv, observability, &ack_header, &ack_payload, &[]) {
        Ok(ct) => {
            let ack_packet = PhantomPacket::new(ack_header, ct);
            match crypto_recv.protect_packet(&ack_packet) {
                Ok(buf) => {
                    ack_buf.clear();
                    ack_buf.extend_from_slice(&buf);
                    let _ = transport_send_ack.send_bytes(ack_buf.as_slice()).await;
                }
                Err(e) => log::error!("PhantomSession: ACK header protection failed: {}", e),
            }
        }
        Err(e) => log::error!("PhantomSession: ACK encrypt failed: {}", e),
    }
    true
}

/// Drop a stream from the receive path once [`Stream::is_retirable`] says it can go: this
/// side's FIN acknowledged, and either the peer's half ended or the application's handle
/// gone.
///
/// The stream leaves the table and the active-streams gauge here and now. Its
/// demultiplexer route is released by the delivery task instead, behind whatever it still
/// has to hand to the application for this stream (see [`DeliverItem::Retire`]). The ids
/// 0 and 1 are never dropped, and a stream already gone is left alone, so the gauge is
/// retired exactly once per stream — whichever of this and [`retire_released_stream`]
/// gets there first.
fn retire_stream(
    stream_id: u32,
    streams: &DashMap<u32, Arc<Stream>>,
    deliver_tx: &mpsc::UnboundedSender<DeliverItem>,
    stream_gauge: &StreamGauge,
) {
    if stream_id <= RAW_APP_STREAM_ID || streams.remove(&stream_id).is_none() {
        return;
    }
    stream_gauge.closed(stream_id);
    // A closed delivery task means the session is ending, and its teardown drops every
    // route with the demultiplexer.
    let _ = deliver_tx.send(DeliverItem::Retire(stream_id));
    log::debug!("PhantomSession: stream {stream_id} closed — dropped");
}

/// Drop, from the pump, a stream the application has let go of: its handle is gone, and
/// this side's half is closed and acknowledged, or never reached the peer at all.
///
/// The same bookkeeping as [`retire_stream`], guarded the same way so that of the two only
/// the first to get there acts. The route goes at once rather than behind the delivery
/// queue: that queue exists so the application reads a stream's last data and its EOF
/// before its channel closes, and an application that dropped its handle reads nothing.
fn retire_released_stream(
    stream_id: u32,
    streams: &DashMap<u32, Arc<Stream>>,
    demux: &StreamDemultiplexer,
    stream_gauge: &StreamGauge,
) {
    if stream_id <= RAW_APP_STREAM_ID || streams.remove(&stream_id).is_none() {
        return;
    }
    stream_gauge.closed(stream_id);
    demux.close_stream(stream_id);
    log::debug!("PhantomSession: stream {stream_id} let go of by the application — dropped");
}

/// What a reliable segment on an id with no stream in the table is.
enum UnheldStream {
    /// The peer opening a new stream.
    Opens,
    /// A stream that was held here and has been dropped: closed from both ends, or let go
    /// of by the application once this side's own half was closed and acknowledged — in
    /// which case the peer's half may still be open and the peer still writing on it — or,
    /// for one this side opened, let go of before a byte of it reached the peer.
    Retired,
    /// An id of this side's parity that this side never opened, which the peer has no
    /// business sending on.
    NotThePeers,
}

/// Tell a segment that opens a stream from one that arrives after its stream was dropped.
///
/// Only the peer opens a stream by sending on it, and only in its own parity. So an id of
/// this side's parity with no stream is one this side opened and has since dropped — or
/// never opened at all — and one of the peer's parity is new exactly when the peer has
/// never used it. Ids 0 and 1 belong to neither side and keep the behaviour they always
/// had.
fn classify_unheld_stream(
    stream_id: u32,
    demux: &StreamDemultiplexer,
    peer_streams: &PeerStreamIds,
) -> UnheldStream {
    if demux.is_local_stream_id(stream_id) {
        if demux.has_opened(stream_id) {
            UnheldStream::Retired
        } else {
            UnheldStream::NotThePeers
        }
    } else if peer_streams.has_seen(stream_id) {
        UnheldStream::Retired
    } else {
        UnheldStream::Opens
    }
}

/// The most reliable application bytes one segment can carry past the receive gate: the
/// largest plaintext a frame may hold, less the offset prefix every reliable one leads with.
///
/// This is a bound on any peer, not a figure about how this build chunks: a larger frame is
/// dropped before it is opened (see [`MAX_RECV_FRAME`]), so no segment that reaches the
/// receive path carries more.
const MAX_RECV_RELIABLE_CHUNK: u64 =
    (MAX_RECV_PAYLOAD - crate::transport::mtu::RELIABLE_OFFSET_LEN) as u64;

/// How many offsets of a dropped stream one flow-control grant covers: a grant goes out for
/// every segment whose offset is a multiple of this, and for no other data segment.
///
/// The peer can put at most this many segments on the wire between two grants, so the room a
/// grant leaves has to cover them with plenty to spare — held below — or the peer would stop
/// between two of them and wait out a persist probe.
const RELEASED_GRANT_STRIDE: u32 = 16;

const _: () = assert!(
    RELEASED_GRANT_STRIDE as u64 * MAX_RECV_RELIABLE_CHUNK
        + crate::transport::stream::INITIAL_STREAM_WINDOW as u64
        <= crate::transport::stream::MAX_RECV_WINDOW as u64
);

/// The flow-control limit to grant the peer for a reliable segment on a stream this side no
/// longer holds, or `None` when the segment calls for none.
///
/// Such a stream keeps no receive state, so the limit is worked out from the arriving offset
/// alone. Offsets are gap-free and every one carries at most [`MAX_RECV_RELIABLE_CHUNK`]
/// bytes, so `(offset + 1) × MAX_RECV_RELIABLE_CHUNK` is at least everything the peer can
/// have sent up to and including this segment, whatever size it chunks at. One
/// [`MAX_RECV_WINDOW`](crate::transport::stream::MAX_RECV_WINDOW) of room goes on top — the
/// most any stream is ever granted, and a sender of this build honours no more than that
/// beyond what it has already sent. Granting a stream nobody reads the largest window there
/// is costs nothing: what arrives on it is acknowledged and discarded, never held.
///
/// What bounds the work is how often a grant goes out, not how large it is:
///
/// * a data segment is answered with one only at every [`RELEASED_GRANT_STRIDE`]th offset, so
///   a peer writing on a stream nobody reads draws one grant for that many acknowledgements;
/// * the peer's persist probe — an empty segment that is not a FIN, sent when it is stopped
///   on its limit with nothing in flight — is always answered, because it is the one frame
///   that says the peer has nothing left to send until it hears one; the peer paces its
///   probes by its retransmission timer;
/// * a FIN is never answered with one: the peer's writing half has ended and needs no room.
///
/// Nothing a peer can send draws more than one grant, and nothing grows on this side for it
/// — no state is kept, however long the peer writes. The limit is a total like any other, so
/// a grant that is lost, reordered or superseded costs nothing, and a peer that stated
/// offsets it never sent is granted room on a stream whose every byte is thrown away.
fn released_stream_grant(stream_offset: u32, is_persist_probe: bool, fin: bool) -> Option<u64> {
    if fin || (!is_persist_probe && !stream_offset.is_multiple_of(RELEASED_GRANT_STRIDE)) {
        return None;
    }
    Some(
        (u64::from(stream_offset) + 1)
            .saturating_mul(MAX_RECV_RELIABLE_CHUNK)
            .saturating_add(u64::from(crate::transport::stream::MAX_RECV_WINDOW)),
    )
}

// Internal-only methods — deliberately NOT on the `#[uniffi::export]` surface.
// `set_state` mutates the connection state machine; a foreign caller forcing
// `Connected` mid-handshake would make `is_data_ready()` lie and let `send()`
// bypass the queue, or `Closed` without tearing down the pump.
impl PhantomSession {
    /// Force the connection state. Test-only: in production the handshake task, the
    /// pump and `disconnect()` publish the state through the shared atomic, each with
    /// its own rule about which states it may overwrite.
    #[cfg(test)]
    pub(crate) fn set_state(&self, new_state: ConnectionState) {
        self.state.store(new_state as u8, Ordering::Relaxed);
    }

    /// Session observability handle (Rust-only — `Observability` is not a
    /// UniFFI type). For a server-accepted session this is the
    /// `PhantomListener`'s shared instance; for a client it is the session's
    /// own. Read `.snapshot()` for the lock-free metric counters.
    pub fn observability(&self) -> Arc<Observability> {
        self.observability.clone()
    }

    /// Snapshot of the live congestion-control state: window, bytes in flight,
    /// estimated bottleneck bandwidth, minimum RTT, pacing rate, BBR phase.
    /// `None` while still connecting.
    ///
    /// Rust-only. Exists because a window that fails to open is otherwise
    /// invisible from outside the crate: throughput alone cannot distinguish a
    /// congestion window pinned at its floor from a slow link, and the two call
    /// for opposite responses. Sampling this over a transfer turns that question
    /// into a measurement.
    pub async fn bandwidth_snapshot(&self) -> Option<crate::transport::session::BandwidthSnapshot> {
        self.inner_session
            .lock()
            .await
            .as_ref()
            .map(|s| s.bandwidth_snapshot())
    }
}

#[cfg_attr(feature = "bindings", uniffi::export(async_runtime = "tokio"))]
impl PhantomSession {
    /// Create a placeholder session — returns instantly and performs **no**
    /// handshake.
    ///
    /// # ⚠️ This does not connect
    ///
    /// Despite the name, this constructor never opens a transport, never runs
    /// the PQC handshake, and never spawns the background data pump. The
    /// returned session immediately reports [`ConnectionState::Failed`] so
    /// misuse is observable: any `connection_state()` check will see `Failed`
    /// rather than an eternal `Connecting`. `send()` returns an error and
    /// `recv()` never yields application bytes. **No bytes ever reach the
    /// network.** It exists only as a pre-handshake placeholder from an earlier
    /// API shape.
    ///
    /// **Deprecated — use a real entry point instead:**
    /// - [`PhantomSession::connect_with_transport`] (Rust) — supply a
    ///   `SessionTransport` and the pinned `expected_server_key`; this spawns
    ///   the handshake + pump.
    /// - [`connect_pinned`] (native FFI / mobile) — one-shot TCP connect with a
    ///   pinned key.
    /// - [`connect_pinned_udp`] (native FFI / mobile) — one-shot PhantomUDP
    ///   connect with a pinned key.
    ///
    /// # Why no `#[deprecated]` attribute (T5.7)
    ///
    /// A `#[deprecated]` attribute would be the natural way to flag this, but it
    /// **cannot** be applied here: this constructor is `#[uniffi::constructor]`,
    /// and UniFFI 0.32 emits FFI scaffolding that calls `Self::connect()` from
    /// generated code in this same crate. That generated call would trip the
    /// `deprecated` lint, which CI promotes to a hard error under
    /// `clippy --lib -D warnings` — and no item-scoped `#[allow(deprecated)]`
    /// reaches the macro-generated call site (only a module-wide
    /// `#![allow(deprecated)]` would, which would silently mask every *future*
    /// genuine deprecation across this module). So the deprecation is documented
    /// loudly here instead, and UniFFI copies this doc-comment into the generated
    /// Python / Swift / Kotlin docstrings (the C header carries no docstrings), so
    /// foreign-language callers see it too. See
    /// `tests::deprecated_connect_is_inert_and_reports_failed` for the
    /// regression pinning the inert behaviour.
    #[cfg_attr(feature = "bindings", uniffi::constructor)]
    pub fn connect(peer_addr: String) -> Arc<Self> {
        let (cmd_tx, cmd_rx) = mpsc::channel(256);
        // No pump reads either; a command sent on one fails, and a dropped stream's
        // report goes nowhere.
        let (control_tx, _control_rx) = mpsc::channel(CONTROL_CHANNEL_DEPTH);
        let (released_tx, _released_rx) = mpsc::unbounded_channel();
        let (_recv_tx, recv_rx) = mpsc::channel(256);
        let (_incoming_tx, incoming_rx) = mpsc::channel(128);

        let (demux, _ctrl_rx) = StreamDemultiplexer::new(256);
        let streams = Arc::new(DashMap::new());
        // Placeholder observability (no transport / pump); a no-op holder.
        let observability = Observability::new(ObservabilityConfig::default());
        // Inert constructor — immediately Failed; publish Failed in the watch so
        // await_ready() resolves immediately with an error.
        let (ready_tx, ready_rx) = watch::channel(ConnectionState::Failed as u8);
        Arc::new(Self {
            id: new_session_id(),
            peer_addr,
            // Start in `Failed` so callers can detect misuse via `connection_state()`.
            // This constructor never establishes a transport or runs a handshake;
            // `Failed` makes that observable rather than leaving the session in an
            // eternal `Connecting` shell.
            state: Arc::new(AtomicU8::new(ConnectionState::Failed as u8)),
            send_queue: Arc::new(Mutex::new(Vec::new())),
            cmd_tx,
            // No pump to read it; raising it is a harmless no-op.
            close_request: watch::channel(false).0,
            control_tx,
            released_tx,
            cmd_rx: Mutex::new(Some(cmd_rx)),
            recv_rx: Mutex::new(recv_rx),
            demux: Arc::new(demux),
            streams,
            inner_session: Arc::new(Mutex::new(None)),
            early_data_accepted: Arc::new(Mutex::new(None)),
            shaping: Arc::new(parking_lot::Mutex::new(TrafficShapingConfig::default())),
            incoming_stream_rx: Arc::new(Mutex::new(incoming_rx)),
            // No handshake failure — just inert; no terminal error.
            terminal_error: Arc::new(parking_lot::Mutex::new(None)),
            ready_tx: Arc::new(ready_tx),
            ready_rx,
            // Inert constructor has no transport; migration is not possible.
            migration_capable: false,
            // Inert constructor: no pump, so only `Drop` ever drains this.
            stream_gauge: StreamGauge::new(observability.clone()),
            observability,
            recv_tuning: Arc::new(SharedRecvTuning::default()),
        })
    }

    /// Open a new multiplexed stream.
    ///
    /// Nothing reaches the peer until the first reliable write. Dropping the returned
    /// handle closes the stream's writing half behind everything written on it; see
    /// [`PhantomStream`](crate::api::stream::PhantomStream) for when the stream then
    /// leaves the session.
    ///
    /// # Errors
    ///
    /// [`CoreError::StreamError`] once this side has opened 32 767 streams in the
    /// session. A stream id travels in a 16-bit header field and each side allocates
    /// from its own half of that space, never reusing an id — even one whose stream
    /// has long since closed, because the peer may still be holding it or the record
    /// that it closed, and would fold a new stream's bytes into it. Nothing is opened
    /// and the session is otherwise unaffected: streams already open carry on, and
    /// `accept_stream()` still takes the peer's. The limit counts every stream opened,
    /// not the ones open at once, so a long-lived session that opens a stream per
    /// request reaches it; open a new session to continue.
    pub fn open_stream(&self) -> Result<Arc<crate::api::stream::PhantomStream>, CoreError> {
        let handle = self.demux.open_stream(STREAM_RECV_CHANNEL_DEPTH)?;
        let stream_id = handle.stream_id;

        let transport_stream = Arc::new(Stream::with_recv_tuning(
            stream_id as TransportStreamId,
            self.recv_tuning.clone(),
        ));
        self.streams.insert(stream_id, transport_stream);
        // Count the stream on the active-streams gauge. The matching retire is
        // `retire_stream`, once both halves are closed; `retire_released_stream`,
        // once the handle has been dropped and this side's half is closed (at once,
        // for a stream dropped before a reliable byte was written on it); the
        // offset-exhaustion fallback in `flush_deferred_sends`; or — for a stream
        // still open when the session ends (including one opened after the pump
        // already exited) — the drain in `Drop for PhantomSession` / at pump exit.
        self.stream_gauge.opened(stream_id);

        Ok(Arc::new(crate::api::stream::PhantomStream::new(
            handle,
            StreamLink {
                commands: self.cmd_tx.clone(),
                control: self.control_tx.clone(),
                released: self.released_tx.clone(),
            },
            self.state.clone(),
        )))
    }

    /// Accept the next peer-initiated stream.
    ///
    /// Blocks until the remote peer opens a new stream (one with an id ≥ 2 that
    /// we haven't seen yet). The returned [`PhantomStream`](crate::api::stream::PhantomStream)
    /// is already registered in the session's demux and ready for `recv()` / `send_reliable()`.
    ///
    /// Returns `Err(CoreError::ConnectionClosed)` when the session has ended and no
    /// further streams will arrive (the internal channel was dropped by the pump).
    ///
    /// # Stream-ID parity
    ///
    /// Peer-initiated streams have the *opposite* parity from locally-opened ones
    /// (QUIC-style): if the local side is the client (odd ids) the peer uses even
    /// ids, and vice versa.
    ///
    /// # Concurrency
    ///
    /// Only one caller should call `accept_stream()` at a time. The receiver is
    /// protected by an async `Mutex`; a concurrent call will wait for the lock.
    pub async fn accept_stream(&self) -> Result<Arc<crate::api::stream::PhantomStream>, CoreError> {
        let mut rx = self.incoming_stream_rx.lock().await;
        rx.recv().await.ok_or(CoreError::ConnectionClosed)
    }

    /// Send data through the session.
    ///
    /// - If the session is connected: sends immediately
    /// - If still handshaking: queues the data for auto-flush later
    /// - If the peer has announced its close ([`ConnectionState::Draining`]):
    ///   returns [`CoreError::ConnectionClosed`] without queueing anything. The
    ///   peer's session is over, so this call cannot put `data` on the wire, and
    ///   an `Ok` here would be the same silent loss the draining window exists to
    ///   prevent on the receive side.
    /// - If the session is `Failed` or `Dead`: returns the captured terminal
    ///   error (from the handshake or the data pump) so the caller gets the
    ///   *specific* cause (e.g. [`CoreError::ServerIdentityMismatch`]) rather
    ///   than the generic `"Cannot send in state Failed"` message.
    ///
    /// # ⚠ This is a byte stream, not a message channel
    ///
    /// **Message boundaries are not preserved.** The data pump splits `data`
    /// into chunks of [`MAX_APP_CHUNK`](crate::transport::mtu::MAX_APP_CHUNK)
    /// bytes — 1156 on this build, sized so that one chunk plus its packet
    /// overhead is exactly one PhantomUDP datagram — and writes each chunk
    /// separately, so the peer's [`recv`](Self::recv) yields one result *per
    /// chunk*, not one per `send`. An 8 KiB `send` arrives as eight `recv`s.
    /// Nothing reassembles them, and nothing marks where one `send` ended and
    /// the next began.
    ///
    /// This is silent when it bites: the first chunk of a structured message
    /// usually still parses, as a truncated one, so a caller that reads a single
    /// `recv` and calls it a message records a successful round trip for a
    /// payload that was quietly cut.
    ///
    /// A caller that needs messages must frame them itself — the usual shape is
    /// a length prefix written ahead of each payload and a reassembler that
    /// accumulates `recv` results until the declared length is complete.
    /// `testbed/src/framing.rs` in this repository is a worked example.
    pub async fn send(&self, data: Vec<u8>) -> Result<(), CoreError> {
        let state = self.connection_state();

        if state == ConnectionState::Draining {
            // Refused before the branch below can read it as a terminal failure: the
            // session has not failed, and reporting a failure for a peer's orderly
            // departure would be as wrong in the other direction. `ConnectionClosed`
            // says the one thing that is true of this call and of every one after it.
            return Err(CoreError::ConnectionClosed);
        }
        if state.is_data_ready() {
            // Channel is up — send directly
            self.cmd_tx
                .send(SessionCommand::Send(data))
                .await
                .map_err(|_| CoreError::NetworkError("Session closed".into()))?;
        } else if state == ConnectionState::Connecting {
            // Still handshaking — queue
            self.send_queue.lock().await.push(data);
        } else {
            // Surface the captured terminal error (e.g. ServerIdentityMismatch)
            // instead of the generic "Cannot send in state …" message.
            return Err(self.terminal_error.lock().clone().unwrap_or_else(|| {
                CoreError::NetworkError(format!("Cannot send in state {state:?}"))
            }));
        }

        Ok(())
    }

    /// Receive data from the session.
    ///
    /// Internally the recv pipeline keeps payloads as `Bytes` to avoid the
    /// per-packet Vec clone that used to fan out to the stream demux. The
    /// FFI surface still hands callers a `Vec<u8>`; if this is the last
    /// refcount the Vec is moved out of the underlying buffer, otherwise
    /// `Bytes::to_vec` copies.
    ///
    /// When the session is `Failed` or `Dead` and the recv channel has been
    /// dropped, returns the captured terminal error (if any) rather than the
    /// generic `"Session closed"` message.
    pub async fn recv(&self) -> Result<Vec<u8>, CoreError> {
        let mut rx = self.recv_rx.lock().await;
        let bytes = rx.recv().await.ok_or_else(|| {
            // Surface the captured terminal error on channel-closed.
            self.terminal_error
                .lock()
                .clone()
                .unwrap_or_else(|| CoreError::NetworkError("Session closed".into()))
        })?;
        Ok(bytes.to_vec())
    }

    /// Returns the terminal error from a failed handshake or a dead session,
    /// or `None` if the session has not failed (still connecting, connected,
    /// draining the peer's close, or cleanly closed).
    ///
    /// A [`Draining`](ConnectionState::Draining) session reads `None` here on
    /// purpose, and that is not in tension with `send()` returning
    /// [`CoreError::ConnectionClosed`] at the same moment: nothing failed, the peer
    /// left. The question "can I still write?" is answered by
    /// [`connection_state`](Self::connection_state) and
    /// [`is_data_ready`](Self::is_data_ready); the question this answers is "what
    /// went wrong?", and for an orderly departure the answer is nothing.
    ///
    /// The error is written once by the background task immediately before the
    /// state transitions to `Failed` or `Dead`, so callers that read this after
    /// receiving `ConnectionState::Failed` from `connection_state()` or
    /// `Err(…)` from `await_ready()` always see the populated value.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let _ = session.await_ready().await;  // wait for outcome
    /// if let Some(e) = session.last_error().await {
    ///     eprintln!("session failed: {e}");
    /// }
    /// ```
    pub async fn last_error(&self) -> Option<CoreError> {
        self.terminal_error.lock().clone()
    }

    /// Wait until the session reaches `Connected` (handshake succeeded) or
    /// `Failed`/`Dead` (handshake or pump failure).
    ///
    /// Returns `Ok(())` on successful connection, or `Err(cause)` with the
    /// captured terminal error on failure. This is the preferred alternative
    /// to polling `connection_state()` in a loop.
    ///
    /// Because the readiness signal is carried on a `watch` channel, a call
    /// made *after* the handshake has already resolved (either direction)
    /// returns immediately — there is no lost-notification race.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// session.await_ready().await?;   // returns Err(ServerIdentityMismatch) if key wrong
    /// session.send(b"hello".to_vec()).await?;
    /// ```
    pub async fn await_ready(&self) -> Result<(), CoreError> {
        // Clone the receiver so we can wait on it without holding a lock on self.
        let mut rx = self.ready_rx.clone();
        // Wait until the value is anything other than Connecting (== 0).
        rx.wait_for(|&v| v != ConnectionState::Connecting as u8)
            .await
            .map_err(|_| CoreError::NetworkError("readiness channel closed".into()))?;
        // Now check the resolved state. Anything that is NOT a terminal failure
        // (Connected, and also Migrating — the keys exist, the path is moving)
        // counts as ready; only a genuine failure surfaces the captured error.
        match self.connection_state() {
            // The peer announced its close while we were waiting. The handshake did
            // succeed, but answering `Ok(())` would tell the caller to go on and send,
            // and the very next `send()` refuses — so the readiness answer has to be
            // the same one, and it is not "failed" either.
            ConnectionState::Draining => Err(CoreError::ConnectionClosed),
            ConnectionState::Failed | ConnectionState::Dead | ConnectionState::Closed => {
                // Surface the captured terminal error, or a generic fallback.
                Err(self
                    .terminal_error
                    .lock()
                    .clone()
                    .unwrap_or(CoreError::NetworkError("session failed".into())))
            }
            _ => Ok(()),
        }
    }

    /// Flat snapshot of this session's connection metrics. For a client
    /// session these are its own per-session counters; for a server-accepted
    /// session they are the owning listener's aggregate (shared handle).
    /// Lock-free read; available with or without `telemetry-otel`.
    pub fn metrics_snapshot(&self) -> crate::observability::MetricsSnapshotFfi {
        self.observability.snapshot().into()
    }

    /// Get the current connection state (lock-free).
    pub fn connection_state(&self) -> ConnectionState {
        ConnectionState::from_u8(self.state.load(Ordering::Relaxed))
    }

    /// Whether the session is ready for data transmission.
    ///
    /// There is no separate "post-quantum ready" question to ask: the hybrid
    /// KEM and the hybrid signature both belong to the one handshake flight, so
    /// there is no window in which a session is up but only classically
    /// protected. Data-ready implies post-quantum protected.
    pub fn is_data_ready(&self) -> bool {
        self.connection_state().is_data_ready()
    }

    /// Flush all queued messages (called when handshake completes).
    ///
    /// Refuses with [`CoreError::ConnectionClosed`] once the peer has announced its
    /// close: the count this returns is a count of payloads handed to the pump, and
    /// while draining the pump discards them, so returning one would be the same
    /// dishonest `Ok` that [`send`](Self::send) refuses to give.
    pub async fn flush_queue(&self) -> Result<u32, CoreError> {
        if self.connection_state() == ConnectionState::Draining {
            return Err(CoreError::ConnectionClosed);
        }
        let mut queue = self.send_queue.lock().await;
        let count = queue.len() as u32;
        for msg in queue.drain(..) {
            self.cmd_tx
                .send(SessionCommand::Send(msg))
                .await
                .map_err(|_| CoreError::NetworkError("Session closed during flush".into()))?;
        }
        Ok(count)
    }

    /// Number of messages queued (waiting for handshake).
    ///
    /// This counter only ever holds pre-handshake writes, so it reads `0` on a
    /// [`Draining`](ConnectionState::Draining) session — and that reading is
    /// accurate rather than a gap: a write offered while draining is refused at
    /// [`send`](Self::send), not accepted into this queue, so there is nothing here
    /// for it to be missing from.
    pub async fn queued_count(&self) -> u32 {
        self.send_queue.lock().await.len() as u32
    }

    /// Session identifier.
    pub fn id(&self) -> String {
        self.id.clone()
    }

    /// Target peer address.
    pub fn peer_addr(&self) -> String {
        self.peer_addr.clone()
    }

    /// The 0-RTT verdict for this session.
    ///
    /// - `None` — still handshaking, the handshake failed, or the client sent
    ///   no early-data on this connect.
    /// - `Some(true)` — the server consumed the 0-RTT early-data.
    /// - `Some(false)` — the client sent early-data and the server rejected it
    ///   (stale/unknown ticket, oversized blob, or AEAD failure). The caller
    ///   must re-send that payload over the normal channel.
    pub async fn early_data_accepted(&self) -> Option<bool> {
        *self.early_data_accepted.lock().await
    }

    /// Extract a [`ResumptionHint`] for a future 0-RTT reconnect.
    ///
    /// Returns `Some` after a successful handshake; `None` while still
    /// handshaking, after a failure, or before the inner session has
    /// been published.
    ///
    /// Store the hint alongside the pinned `HybridVerifyingKey` of the
    /// server it was negotiated against and feed it back to
    /// [`connect_pinned_with_resumption`]. Reusing a hint across
    /// servers is a configuration bug — the `resumption_secret` is
    /// server-pinned.
    pub async fn resumption_hint(&self) -> Option<Arc<ResumptionHint>> {
        let guard = self.inner_session.lock().await;
        guard
            .as_ref()
            .and_then(|s| s.resumption_hint())
            .map(|(session_id, resumption_secret)| {
                ResumptionHint::new(session_id.to_vec(), resumption_secret.to_vec())
            })
    }

    /// Apply an anti-fingerprint traffic-shaping configuration (WIRE v6).
    ///
    /// **Accepted at any point in a session's life, including before the
    /// handshake has run.** The configuration is stored and applied when the
    /// session is installed, so an embedder that wants shaping on from the first
    /// byte sets it immediately after connecting rather than waiting for
    /// readiness. The return is always `true` and carries no information; it
    /// survives because removing it is an FFI-breaking change. Do not branch on
    /// it.
    ///
    /// All shaping is opt-in (default: none); enabling size padding
    /// ([`PaddingPolicy::Padme`]) makes outbound packets pad up to a PADÉ bucket so
    /// the datagram size no longer tracks the payload size, at a bounded (≈ ≤12%
    /// worst-case) bandwidth cost. FFI-exported so mobile / other embedders can
    /// tune it.
    pub async fn set_traffic_shaping(&self, config: TrafficShapingConfig) -> bool {
        // Store as the pending config (a clone applied at session install, so
        // it works BEFORE the async client handshake completes), then apply
        // immediately too if the session is already established. Always accepted.
        *self.shaping.lock() = config;
        if let Some(s) = self.inner_session.lock().await.as_ref() {
            apply_shaping(s, config);
        }
        true
    }

    /// Read back the traffic-shaping config currently applied to the established
    /// session. `None` while still connecting (the session is not installed
    /// yet — the pending config set via [`set_traffic_shaping`](Self::set_traffic_shaping)
    /// will apply on install). FFI-exported.
    pub async fn traffic_shaping(&self) -> Option<TrafficShapingConfig> {
        self.inner_session
            .lock()
            .await
            .as_ref()
            .map(|s| TrafficShapingConfig {
                padding: s.padding_policy(),
                jitter_ms: s.send_jitter().as_millis() as u32,
                cover_interval_ms: s.cover_interval().as_millis() as u32,
            })
    }

    /// Whether this session's transport supports seamless connection migration
    /// (i.e., [`migrate`](Self::migrate) will succeed for UDP sessions).
    ///
    /// Returns `true` only when the session is backed by `UdpClientTransport`.
    /// On TCP, WebSocket, WASI, or Embedded sessions, [`migrate`](Self::migrate)
    /// returns [`CoreError::Unsupported`] — use reconnection with 0-RTT resumption
    /// instead.
    pub fn supports_migration(&self) -> bool {
        self.migration_capable
    }

    /// Migrate the session to a new local network address (Phase 4 — embedder-
    /// triggered connection migration). The embedder calls this when the OS reports a
    /// network change (Wi-Fi↔cellular, NAT rebind); `local_addr` is the new local
    /// bind address (e.g. `"0.0.0.0:0"` to let the OS pick an ephemeral port on the
    /// new interface).
    ///
    /// **Best-effort and non-blocking on validation.** It hands the request to the
    /// background pump, which rebinds the transport (keeping the old socket for the
    /// overlap) and bumps the send `path_id`; the path validation + server-side peer
    /// switch then complete asynchronously. The keys and session persist — **no
    /// re-handshake**. A failed rebind never tears the session down: it keeps running
    /// on the existing socket (broken-rebind safety). `Err` here means only that the
    /// session was already closed (the pump is gone).
    ///
    /// **It does not wait behind queued writes.** A path that has died leaves the
    /// application's writes waiting for acknowledgements that cannot arrive until the
    /// session has moved, so the request travels apart from them and the pump acts on
    /// it at once, however much is queued. Writes already accepted go out on the new
    /// path, and what was sent on the old one is retransmitted there.
    ///
    /// **Transport requirement:** seamless migration (Wi-Fi ↔ LTE without
    /// re-handshake) requires the session to be backed by
    /// `UdpClientTransport`. Calling `migrate()` on a TCP, WebSocket, WASI,
    /// or Embedded session returns [`CoreError::Unsupported`]. Check
    /// [`supports_migration`](Self::supports_migration) first, or use
    /// `connect_pinned_udp` to ensure UDP backing.
    pub async fn migrate(&self, local_addr: String) -> Result<(), CoreError> {
        if !self.migration_capable {
            return Err(CoreError::Unsupported(
                "this session does not support connection migration; use a UDP-backed session"
                    .into(),
            ));
        }
        self.control_tx
            .send(ControlCommand::Migrate(local_addr))
            .await
            .map_err(|_| CoreError::NetworkError("Session closed".into()))
    }

    /// Ask the background pump to push out what it can, tell the peer this session is
    /// over, and shut it down.
    ///
    /// **What a caller can rely on.** That the session ends, and that this returns at
    /// once — it raises a close signal and returns without waiting for anything; the work
    /// happens on the pump afterwards. The signal does not queue behind the application's
    /// writes: the pump reads it even while those writes are stalled, so a peer that has
    /// stopped reading cannot hold the close back. The pump then takes in, in order, the
    /// writes queued ahead of the close for as long as the send buffers admit them, so
    /// `send(x)` followed by this call still pushes `x`.
    ///
    /// Nothing here is a delivery guarantee. The pump pushes queued bytes until the
    /// socket, the congestion window or the peer's flow-control limit refuses the next
    /// one, and then stops; it does not wait for an acknowledgement, so "pushed" means
    /// "handed to the transport", not "the peer has it". A write still refused at that
    /// point is discarded, so a payload larger than one congestion window is mostly
    /// discarded — half a mebibyte handed to `send()` immediately before this call
    /// arrives as a few kibibytes — and a process that exits right afterwards can leave
    /// before any of it, or the announcement, reaches the wire. Dropping the handle is
    /// the same path with no await to hold the process still.
    ///
    /// **If delivery matters, do not use this to obtain it.** There is no
    /// transport-level signal that could be waited on here: the close announcement is
    /// itself unacknowledged. Have the peer say it received the data, at the
    /// application level, and close after that answer arrives.
    ///
    /// **On a stream socket its peer has stopped reading** — TCP or the TLS-mimicry
    /// leg — the pump can be parked inside a single transport write that the peer is
    /// not taking, and nothing, this request included, is read until that write
    /// returns. If the peer starts reading again, the close is carried out and
    /// announced as usual. If it does not, the write gives up once it has
    /// gone the transport's write deadline without progress (thirty seconds unless
    /// [`PhantomConfig::write_stall_timeout`](crate::config::PhantomConfig::write_stall_timeout)
    /// says otherwise), and the session ends [`ConnectionState::Dead`], with
    /// [`CoreError::Timeout`] from `last_error()` and `recv()` — **not announced**: the
    /// transport refuses every write after the one that stalled, the close frame
    /// included, and resets the connection. This call has returned long before; the
    /// `Closed` it published gives way to `Dead` when that happens. Called on a session
    /// that has already ended `Dead` or `Failed`, it leaves that state — and the cause
    /// `last_error()` reports — as it is.
    ///
    /// The announcement is a best-effort `CONTROL` frame carrying
    /// [`ControlSubtype::CLOSE`]: it is not acknowledged and not retransmitted, so a
    /// peer that never receives it falls back to concluding the same thing from
    /// silence, on its liveness timer. It is what lets a PhantomUDP server release
    /// the session's slot in under a second instead of two minutes later, because a
    /// datagram socket gives it no other end-of-stream to observe. A peer that does
    /// receive it keeps reading for a short bounded window before tearing down, so
    /// data this side put on the wire just before the close is still delivered if it
    /// is merely reordered behind it.
    ///
    /// Named `disconnect` rather than `close` because UniFFI's Kotlin
    /// generator unconditionally adds `AutoCloseable.close()` to every
    /// object, and a Rust-side `close` here would conflict with it.
    pub async fn disconnect(&self) -> Result<(), CoreError> {
        // An end the session already reached says more than `Closed` would: `Dead`
        // carries the cause `last_error()` reports, and `Failed` the handshake's. Both
        // stay; anything else becomes `Closed`.
        let _ = self
            .state
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                match ConnectionState::from_u8(current) {
                    ConnectionState::Dead | ConnectionState::Failed => None,
                    _ => Some(ConnectionState::Closed as u8),
                }
            });
        // Raised rather than queued: a full command channel, or a pump that has stopped
        // reading it because the peer stopped reading, must not be able to hold this
        // call or the close it asks for.
        self.close_request
            .send_modify(|requested| *requested = true);
        Ok(())
    }
}

impl PhantomSession {
    /// Get the stream demultiplexer (internal use, not exposed to UniFFI)
    pub fn demux(&self) -> Arc<StreamDemultiplexer> {
        self.demux.clone()
    }

    /// The established inner [`Session`], or `None` while the handshake is still
    /// running.
    ///
    /// Crate-internal and deliberately not on the public surface: the inner session
    /// is where the machinery lives that the API in front of it exists to hide, and
    /// handing it out would make every internal invariant a compatibility promise.
    /// The callers are in-crate tests that need to reach a listener-installed
    /// [`DemuxLink`](crate::transport::session::DemuxLink) — a wire between two
    /// internals that no public accessor names — so it is compiled only for them
    /// rather than left in the production build as a door nobody walks through.
    #[cfg(test)]
    pub(crate) async fn inner_session_handle(&self) -> Option<Arc<Session>> {
        self.inner_session.lock().await.clone()
    }

    /// Current rekey epoch of the established session (`None` while still
    /// connecting). Rust-only — used by soak / integration tests to confirm
    /// that automatic mid-session rekey (C1) advanced the epoch.
    pub async fn current_epoch(&self) -> Option<u8> {
        self.inner_session
            .lock()
            .await
            .as_ref()
            .map(|s| s.current_epoch())
    }

    /// Override the automatic-rekey send-invocation high-watermark on the
    /// established session (default `REKEY_SOFT_LIMIT`, currently `2^32`).
    /// Returns `false` if the session is still connecting. Primarily for
    /// soak / load harnesses that need to exercise mid-session rekey without
    /// sending `2^32` packets.
    ///
    /// **Rust-only, and deliberately so.** This lowers the watermark that
    /// triggers key rotation on a live session — a knob on the same axis as the
    /// `AEAD_MAX_INVOCATIONS` ceiling, which is documented as not to be moved
    /// without an audit. A harness that links the crate directly is inside that
    /// audit boundary; an arbitrary foreign-language embedder reached through
    /// the bindings is not, and none has asked for it. Keeping it off the FFI
    /// surface is reversible in one line; recalling it from a shipped binding is
    /// not.
    pub async fn set_rekey_threshold(&self, n: u64) -> bool {
        match self.inner_session.lock().await.as_ref() {
            Some(s) => {
                s.set_rekey_threshold(n);
                true
            }
            None => false,
        }
    }

    /// Override the path-liveness thresholds on the established session (Phase 4 /
    /// P4.3). Returns `false` if the session is still connecting. Rust-only (the
    /// `LivenessConfig` type is not on the UniFFI surface) — for tests / advanced
    /// embedders that want a faster or slower path-down / migration-idle timeout than
    /// the default.
    pub async fn set_liveness_config(
        &self,
        cfg: crate::transport::liveness::LivenessConfig,
    ) -> bool {
        match self.inner_session.lock().await.as_ref() {
            Some(s) => {
                s.set_liveness_config(cfg);
                true
            }
            None => false,
        }
    }

    /// Migrate the **server side** of this session to a new local send address (the
    /// server-side mirror of [`migrate`](Self::migrate)). Intended for an accepted server
    /// session whose network path changes (failover, multi-homing, an egress NAT rebind):
    /// the server rebinds its send socket to `local_addr` and rotates its server→client
    /// `path_id` + connection-ID in lock-step, so the peer follows the fresh s2c source
    /// (its unconnected socket hears it) and an observer cannot relink the session by the
    /// s2c ConnId across the move. The keys and session persist — **no re-handshake**.
    ///
    /// The server keeps RECEIVING client→server traffic on the established (listen) address
    /// through the overlap, so the session stays bidirectional immediately. Best-effort: a
    /// failed rebind leaves the session on the old send socket and never tears it down.
    /// `Err` here means only that the session was already closed. Like `migrate`, the
    /// request does not wait behind the session's queued writes.
    ///
    /// **Rust-only** (deliberately not on the UniFFI/FFI surface): server migration is a
    /// native-deployment operation, not a mobile-client one. The peer follows
    /// symmetrically: it path-validates the new server source, re-points its send target
    /// there, and rotates its c2s CID to match.
    ///
    /// **Transport requirement:** requires the session to be backed by
    /// `UdpServerTransport`. Returns [`CoreError::Unsupported`] on TCP,
    /// WebSocket, WASI, or Embedded sessions.
    pub async fn migrate_server(&self, local_addr: String) -> Result<(), CoreError> {
        if !self.migration_capable {
            return Err(CoreError::Unsupported(
                "this session does not support server-side migration; use a UDP-backed session"
                    .into(),
            ));
        }
        self.control_tx
            .send(ControlCommand::MigrateServer(local_addr))
            .await
            .map_err(|_| CoreError::NetworkError("Session closed".into()))
    }
}

impl std::fmt::Debug for PhantomSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PhantomSession")
            .field("id", &self.id)
            .field("peer", &self.peer_addr)
            .field("state", &self.connection_state())
            .finish()
    }
}

/// Signal the data pump to flush-and-close when the public session
/// handle is dropped without an explicit `disconnect()` call.
///
/// Before peer-initiated streams existed, the pump detected handle-drop via
/// `cmd_rx.recv() → None` because the struct's `cmd_tx` clone was the ONLY
/// sender. Accepting peer-initiated streams added extra `cmd_tx` clones inside
/// the pump and recv task (needed to build `PhantomStream` handles for them),
/// so `cmd_rx` no longer goes to `None` on struct-drop alone and the pump
/// would linger with an open transport
/// indefinitely — blocking the remote peer's next `recv()`.
///
/// The Drop impl raises the same close request `disconnect()` does. It used to
/// `try_send` a `SessionCommand::Close` instead, which failed silently whenever
/// the channel was full and, when it did land, sat unread for as long as the
/// pump held a write the send buffer had refused — so a peer that stopped
/// reading kept a dropped session running indefinitely. The request is a
/// signal the pump reads whatever else it is holding, and the pump takes in
/// the commands queued ahead of it before announcing the close, so a
/// fire-and-forget `send(x); drop(session)` idiom still pushes `x` before the
/// pump exits — pushes, not delivers, exactly as for `disconnect()`.
impl Drop for PhantomSession {
    fn drop(&mut self) {
        // Cannot fail and cannot block. With no pump listening (a handshake that
        // never completed, the inert `connect()`) it is a no-op.
        self.close_request
            .send_modify(|requested| *requested = true);
        // Retire any stream still counted on the active-streams gauge. The pump
        // drains too (that is the normal path, and it fires promptly); this
        // covers the cases the pump cannot — a session whose pump never started
        // (failed handshake, the inert `connect()`), and an `open_stream()`
        // issued after the pump already exited. `drain()` swaps the counter to
        // zero atomically, so exactly one of the two drains does the work.
        self.stream_gauge.drain();
    }
}

// ─── Pinned-Connect Shim (Phase 7.2 mobile bridge) ──────────────────────────

/// Connect to a server over **TCP**, pinning its identity to `pinned_key`.
///
/// # ⚠ Returns before the handshake — `Ok` here does not mean the pin matched
///
/// This returns as soon as the TCP socket is open. The handshake, and with it
/// the check that the server actually holds `pinned_key`, runs on the background
/// task. Until it completes the session reports
/// [`ConnectionState::Connecting`], and [`send`](PhantomSession::send) accepts
/// bytes into the pending queue rather than refusing them. A connection to an
/// impostor therefore looks exactly like a connection to the right server, right
/// up to the moment the caller asks.
///
/// **Call [`await_ready`](PhantomSession::await_ready) before treating the
/// session as authenticated.** It resolves the handshake outcome and surfaces
/// [`CoreError::ServerIdentityMismatch`] on a wrong pin; the same error is also
/// available later from [`last_error`](PhantomSession::last_error) and is what
/// `send`/`recv` return once the state is terminal.
///
/// ```rust,no_run
/// # #[tokio::main]
/// # async fn main() {
/// # let pinned_key: Vec<u8> = vec![];
/// let session = phantom_protocol::connect_pinned("host".into(), 4242, pinned_key)
///     .await
///     .expect("socket opened — says nothing about the peer's identity");
///
/// // The pin is verified here, not above.
/// if let Err(e) = session.await_ready().await {
///     eprintln!("not the pinned server: {e}");
///     return;
/// }
/// # }
/// ```
///
/// Opens a `TcpSessionTransport`, parses the pinned [`HybridVerifyingKey`]
/// from raw bytes (Security Invariant 1 — mandatory), and starts the
/// background handshake + data pump.
///
/// The transport gives up on a server that stops reading once a write has gone
/// thirty seconds without progress, and the session then ends
/// [`ConnectionState::Dead`] with [`CoreError::Timeout`]. Use
/// [`connect_pinned_with_config`] to choose another deadline
/// ([`PhantomConfig::write_stall_timeout`](crate::config::PhantomConfig::write_stall_timeout)).
///
/// Use [`connect_pinned_udp`] instead when you need seamless
/// connection migration (Wi-Fi ↔ LTE via [`PhantomSession::migrate`]).
/// TCP sessions return [`CoreError::Unsupported`] from `migrate()`.
///
/// Native-only (not available on `wasm32-unknown-unknown`); FFI-exported.
///
/// # Example
///
/// ```rust,no_run
/// # #[tokio::main]
/// # async fn main() -> Result<(), phantom_protocol::CoreError> {
/// // `pinned_key` bytes come from `PhantomListener::verifying_key_bytes()`,
/// // baked into the app bundle — never fetched at runtime.
/// let pinned_key: Vec<u8> = vec![/* ... */];
/// let session = phantom_protocol::connect_pinned(
///     "phantom.example.com".into(), 4242, pinned_key,
/// ).await?;
/// session.await_ready().await?;
/// session.send(b"hello".to_vec()).await?;
/// let _reply = session.recv().await?;
/// # Ok(())
/// # }
/// ```
#[cfg(not(target_arch = "wasm32"))]
#[cfg_attr(feature = "bindings", uniffi::export(async_runtime = "tokio"))]
pub async fn connect_pinned(
    host: String,
    port: u16,
    pinned_key: Vec<u8>,
) -> Result<Arc<PhantomSession>, CoreError> {
    // fips bootstrap POST gate (same policy as
    // `PhantomListener::bind_inner`). A failure here aborts the
    // connect before any socket is opened or key material is
    // touched.
    #[cfg(feature = "fips")]
    crate::crypto::self_tests::ensure_post_passed()
        .map_err(|e| CoreError::FipsSelfTestFailure(format!("{e:?}")))?;

    // Decode the server's hybrid verifying key. A malformed blob is a
    // crypto-layer problem (wrong length, wrong encoding) rather than a
    // network failure — surface it as `CryptoError`.
    let expected_server_key = HybridVerifyingKey::from_bytes(&pinned_key)
        .map_err(|e| CoreError::CryptoError(format!("invalid pinned key: {}", e)))?;

    // Open the TCP stream. The `format!` is shared between the actual
    // connect target and the `peer_addr` recorded inside the session
    // (`connect_with_transport` takes it as a free-form string).
    let addr = format!("{}:{}", host, port);
    let stream = tokio::net::TcpStream::connect(&addr)
        .await
        .map_err(|e| CoreError::NetworkError(format!("connect {}: {}", addr, e)))?;
    let transport = crate::api::tcp_transport::TcpSessionTransport::new(stream);

    // The handshake is driven by the background task spawned inside
    // `connect_with_transport`; the returned `PhantomSession` is usable
    // immediately (state `Connecting`, sends auto-queued until ready).
    let session = PhantomSession::connect_with_transport(&addr, transport, expected_server_key);
    Ok(Arc::new(session))
}

/// Like [`connect_pinned`] but also applies [`PhantomConfig`](crate::config::PhantomConfig)
/// to the session: its liveness settings, and its
/// [`write_stall_timeout`](crate::config::PhantomConfig::write_stall_timeout) as the TCP
/// transport's write deadline. FFI-exported.
///
/// A zero `write_stall_timeout` is refused with [`CoreError::ConfigError`] before any
/// socket is opened.
///
/// # ⚠ Returns before the handshake — `Ok` here does not mean the pin matched
///
/// Same contract as [`connect_pinned`]: the pinned-key check runs on the
/// background task, so an impostor is indistinguishable from the real server
/// until [`await_ready`](PhantomSession::await_ready) resolves it.
///
/// ```rust,no_run
/// # #[tokio::main]
/// # async fn main() {
/// # let pinned_key: Vec<u8> = vec![];
/// let config = phantom_protocol::config::PhantomConfig::mobile();
/// let session =
///     phantom_protocol::connect_pinned_with_config("host".into(), 4242, pinned_key, config)
///         .await
///         .expect("socket opened — says nothing about the peer's identity");
///
/// // The pin is verified here, not above.
/// session.await_ready().await.expect("not the pinned server");
/// # }
/// ```
#[cfg(not(target_arch = "wasm32"))]
#[cfg_attr(feature = "bindings", uniffi::export(async_runtime = "tokio"))]
pub async fn connect_pinned_with_config(
    host: String,
    port: u16,
    pinned_key: Vec<u8>,
    config: crate::config::PhantomConfig,
) -> Result<Arc<PhantomSession>, CoreError> {
    #[cfg(feature = "fips")]
    crate::crypto::self_tests::ensure_post_passed()
        .map_err(|e| CoreError::FipsSelfTestFailure(format!("{e:?}")))?;
    let expected_server_key = HybridVerifyingKey::from_bytes(&pinned_key)
        .map_err(|e| CoreError::CryptoError(format!("invalid pinned key: {}", e)))?;
    let write_stall_timeout = config.stream_write_stall_timeout()?;
    let addr = format!("{}:{}", host, port);
    let stream = tokio::net::TcpStream::connect(&addr)
        .await
        .map_err(|e| CoreError::NetworkError(format!("connect {}: {}", addr, e)))?;
    let transport = crate::api::tcp_transport::TcpSessionTransport::new(stream)
        .with_write_stall_timeout(write_stall_timeout);
    let liveness = config.liveness();
    let session = PhantomSession::spawn_client(
        &addr,
        transport,
        expected_server_key,
        Arc::new(TokioRuntime),
        None,
        Some(liveness),
    );
    Ok(Arc::new(session))
}

/// Connect to a pinned server over the **TLS-over-TCP active-mimicry** transport
/// (`mimicry` feature) — the flow looks like an ordinary HTTPS handshake to an
/// on-path observer, while the real authentication / confidentiality remains the
/// inner Phantom post-quantum session.
///
/// # ⚠ Returns before the handshake — `Ok` here does not mean the pin matched
///
/// The synthetic TLS prelude completes before this returns, but the *Phantom*
/// handshake — the only thing that authenticates anyone — runs on the background
/// task. Exactly as in [`connect_pinned`], call
/// [`await_ready`](PhantomSession::await_ready) before treating the session as
/// authenticated.
///
/// ```rust,no_run
/// # #[tokio::main]
/// # async fn main() {
/// # let pinned_key: Vec<u8> = vec![];
/// let session = phantom_protocol::api::session::connect_pinned_mimic(
///     "host".into(),
///     443,
///     pinned_key,
///     "www.example.com".into(),
/// )
/// .await
/// .expect("cover handshake completed — says nothing about the peer's identity");
///
/// // The pin is verified here, not above.
/// session.await_ready().await.expect("not the pinned server");
/// # }
/// ```
///
/// `sni` is the cover domain presented in the synthetic ClientHello. It is
/// **required and should be rotated** per connection and kept plausible for the
/// server's IP/AS — a single network-wide default SNI is itself a blocklist key.
///
/// **The outer TLS is anti-DPI obfuscation only, and is detectable by active
/// probing.** It defeats stateless DPI + passive JA3/JA4 fingerprinting + light
/// stateful inspection, but a censor that completes a real TLS handshake or
/// validates a certificate detects it in one round trip — do **not** use this
/// where active probing is in the threat model. See `docs/security/threat-model.md`.
///
/// Once the prelude is done, a write that goes thirty seconds without the socket
/// taking a byte gives up on the server, and the session ends
/// [`ConnectionState::Dead`] with [`CoreError::Timeout`];
/// [`connect_pinned_mimic_with_config`] chooses another deadline.
///
/// Rust-only and native-only, gated on the `mimicry` feature.
#[cfg(all(not(target_arch = "wasm32"), feature = "mimicry"))]
pub async fn connect_pinned_mimic(
    host: String,
    port: u16,
    pinned_key: Vec<u8>,
    sni: String,
) -> Result<Arc<PhantomSession>, CoreError> {
    connect_mimic(host, port, pinned_key, sni, None).await
}

/// Like [`connect_pinned_mimic`] but also applies a
/// [`PhantomConfig`](crate::config::PhantomConfig): its liveness settings, and its
/// [`write_stall_timeout`](crate::config::PhantomConfig::write_stall_timeout) as the
/// leg's write deadline once the prelude is done. The mimicry analogue of
/// [`connect_pinned_with_config`], with the same contract — including that it returns
/// before the Phantom handshake has checked the pin, so call
/// [`await_ready`](PhantomSession::await_ready) before trusting the session.
///
/// A zero `write_stall_timeout` is refused with [`CoreError::ConfigError`] before any
/// socket is opened.
///
/// Rust-only and native-only, gated on the `mimicry` feature.
#[cfg(all(not(target_arch = "wasm32"), feature = "mimicry"))]
pub async fn connect_pinned_mimic_with_config(
    host: String,
    port: u16,
    pinned_key: Vec<u8>,
    sni: String,
    config: crate::config::PhantomConfig,
) -> Result<Arc<PhantomSession>, CoreError> {
    connect_mimic(host, port, pinned_key, sni, Some(config)).await
}

/// The body both mimicry connects share: `config` is `None` for the one that takes no
/// config, which keeps the default liveness settings and write deadline.
#[cfg(all(not(target_arch = "wasm32"), feature = "mimicry"))]
async fn connect_mimic(
    host: String,
    port: u16,
    pinned_key: Vec<u8>,
    sni: String,
    config: Option<crate::config::PhantomConfig>,
) -> Result<Arc<PhantomSession>, CoreError> {
    #[cfg(feature = "fips")]
    crate::crypto::self_tests::ensure_post_passed()
        .map_err(|e| CoreError::FipsSelfTestFailure(format!("{e:?}")))?;

    let expected_server_key = HybridVerifyingKey::from_bytes(&pinned_key)
        .map_err(|e| CoreError::CryptoError(format!("invalid pinned key: {}", e)))?;
    let write_stall_timeout = match &config {
        Some(config) => config.stream_write_stall_timeout()?,
        None => crate::transport::write_stall::DEFAULT_WRITE_STALL_TIMEOUT,
    };

    let addr = format!("{}:{}", host, port);
    let stream = tokio::net::TcpStream::connect(&addr)
        .await
        .map_err(|e| CoreError::NetworkError(format!("connect {}: {}", addr, e)))?;

    // Run the synthetic TLS prelude before handing the leg to the background
    // handshake pump (the leg is ready for `send_bytes`/`recv_bytes` once this
    // returns). A prelude failure (e.g. an unreachable / non-mimic server) aborts
    // the connect.
    let mimic = crate::transport::legs::mimic_tls::MimicConfig::new(sni);
    let transport = crate::transport::legs::mimic_tls::MimicTlsLeg::connect(stream, &mimic)
        .await?
        .with_write_stall_timeout(write_stall_timeout);

    let session = PhantomSession::spawn_client(
        &addr,
        transport,
        expected_server_key,
        Arc::new(TokioRuntime),
        None,
        config.map(|c| c.liveness()),
    );
    Ok(Arc::new(session))
}

/// Connect to a pinned server with a **0-RTT resumption attempt** — the
/// resumption-aware analogue of [`connect_pinned`].
///
/// # ⚠ Returns before the handshake — `Ok` here does not mean the pin matched
///
/// Same contract as [`connect_pinned`]. It matters more here: the early-data
/// blob is already on the wire when this returns, so `Ok` is not even evidence
/// that the ticket was usable. [`await_ready`](PhantomSession::await_ready)
/// resolves the pin, and only then does
/// [`early_data_accepted`](PhantomSession::early_data_accepted) mean anything.
///
/// ```rust,no_run
/// # #[tokio::main]
/// # async fn main() {
/// # let pinned_key: Vec<u8> = vec![];
/// # let hint: std::sync::Arc<phantom_protocol::api::session::ResumptionHint> = unimplemented!();
/// let session = phantom_protocol::connect_pinned_with_resumption(
///     "host".into(), 4242, pinned_key, hint, b"GET /".to_vec(),
/// )
/// .await
/// .expect("socket opened — says nothing about the peer's identity");
///
/// // The pin is verified here, not above.
/// session.await_ready().await.expect("not the pinned server");
/// if session.early_data_accepted().await != Some(true) {
///     // The server declined 0-RTT; the payload was requeued for 1-RTT.
/// }
/// # }
/// ```
///
/// `hint` is a [`ResumptionHint`] from a prior session's
/// [`PhantomSession::resumption_hint`]; both of its fields must be
/// exactly 32 bytes or the call fails with `ValidationError` before any
/// socket is opened. `early_data` (≤ 16 KiB) is sealed into the resuming
/// ClientHello so it reaches the server on the very first flight.
///
/// Acceptance is best-effort: when the server does not consume the early-data
/// (stale/unknown ticket or AEAD failure) the handshake completes 1-RTT — the
/// caller checks [`PhantomSession::early_data_accepted`] and re-sends over the
/// normal channel when it is not `Some(true)`.
///
/// It takes no [`PhantomConfig`](crate::config::PhantomConfig), so the session keeps
/// the default liveness settings and the thirty-second write deadline of
/// [`connect_pinned`].
///
/// Native-only, like [`connect_pinned`]: `TcpSessionTransport` lives
/// behind `cfg(not(target_arch = "wasm32"))`.
#[cfg(not(target_arch = "wasm32"))]
#[cfg_attr(feature = "bindings", uniffi::export(async_runtime = "tokio"))]
pub async fn connect_pinned_with_resumption(
    host: String,
    port: u16,
    pinned_key: Vec<u8>,
    hint: Arc<ResumptionHint>,
    early_data: Vec<u8>,
) -> Result<Arc<PhantomSession>, CoreError> {
    // fips bootstrap POST gate (same policy as
    // `connect_pinned`).
    #[cfg(feature = "fips")]
    crate::crypto::self_tests::ensure_post_passed()
        .map_err(|e| CoreError::FipsSelfTestFailure(format!("{e:?}")))?;

    // Server-key pinning stays mandatory (security invariant 1): a
    // malformed blob is a crypto-layer problem, surfaced as `CryptoError`.
    let expected_server_key = HybridVerifyingKey::from_bytes(&pinned_key)
        .map_err(|e| CoreError::CryptoError(format!("invalid pinned key: {}", e)))?;

    // `ResumptionHint` fields are `Vec<u8>` (UniFFI has no fixed-size
    // array type) — enforce the 32-byte invariant here, before any
    // socket is opened, so a caller bug never becomes a network call.
    let session_id: [u8; 32] = hint.session_id_ref().try_into().map_err(|_| {
        CoreError::ValidationError(format!(
            "resumption hint session_id must be 32 bytes, got {}",
            hint.session_id_ref().len()
        ))
    })?;
    let resumption_secret: [u8; 32] = hint.resumption_secret_ref().try_into().map_err(|_| {
        CoreError::ValidationError(format!(
            "resumption hint resumption_secret must be 32 bytes, got {}",
            hint.resumption_secret_ref().len()
        ))
    })?;

    // APIFFI-03: reject oversized early-data BEFORE opening a socket, so a caller
    // bug (or oversized blob) never wastes a TCP connection establishment.
    if early_data.len() > EARLY_DATA_MAX_LEN {
        return Err(CoreError::ValidationError(format!(
            "early_data is {} bytes, exceeds the {}-byte 0-RTT cap",
            early_data.len(),
            EARLY_DATA_MAX_LEN
        )));
    }

    let addr = format!("{}:{}", host, port);
    let stream = tokio::net::TcpStream::connect(&addr)
        .await
        .map_err(|e| CoreError::NetworkError(format!("connect {}: {}", addr, e)))?;
    let transport = crate::api::tcp_transport::TcpSessionTransport::new(stream);

    // All validation (key pin, hint size, early-data cap) is done above.
    // Delegates directly to `spawn_client` to keep 0-RTT one-shot /
    // best-effort (security invariant 9).
    let session = PhantomSession::spawn_client(
        &addr,
        transport,
        expected_server_key,
        Arc::new(TokioRuntime),
        Some((session_id, resumption_secret, early_data)),
        None,
    );
    Ok(Arc::new(session))
}

/// Connect to a pinned server over the production **PhantomUDP** transport — the
/// reliable-UDP, migration-capable analogue of [`connect_pinned`].
///
/// # ⚠ Returns before the handshake — `Ok` here does not mean the pin matched
///
/// This returns as soon as the UDP socket is bound — which, on an unconnected
/// datagram socket, involves no exchange with the peer at all. The handshake and
/// the check that the server holds `pinned_key` run on the background task,
/// while the session reports [`ConnectionState::Connecting`] and
/// [`send`](PhantomSession::send) queues bytes rather than refusing them.
///
/// **Call [`await_ready`](PhantomSession::await_ready) before treating the
/// session as authenticated**; it surfaces
/// [`CoreError::ServerIdentityMismatch`] on a wrong pin. The example below does
/// it immediately.
///
/// Unlike the TCP [`connect_pinned`], a session built here runs over
/// [`UdpClientTransport`](crate::api::udp_transport::UdpClientTransport), so
/// [`PhantomSession::migrate`] performs a real single-path connection migration
/// (e.g. Wi-Fi ↔ LTE handover) instead of returning
/// [`CoreError::Unsupported`], and liveness / `Migrating` / `Dead` transitions,
/// path validation, and passive NAT-rebind recovery are all live for FFI
/// consumers.
///
/// `host` is resolved via the system resolver; the **first** returned address is
/// used. Unlike the TCP [`connect_pinned`] (whose `TcpStream::connect` tries every
/// resolved address in turn), this does **not** fall back to subsequent addresses
/// if the first is unreachable — pass an IP literal or a single-family host when
/// that matters. Server-key pinning is mandatory (security invariant 1).
/// Native-only, like [`connect_pinned`].
///
/// # Example
///
/// ```rust,no_run
/// # #[tokio::main]
/// # async fn main() -> Result<(), phantom_protocol::CoreError> {
/// // `pinned_key` bytes come from `PhantomUdpListener::verifying_key_bytes()`,
/// // baked into the app bundle — never fetched at runtime.
/// let pinned_key: Vec<u8> = vec![/* ... */];
/// let session = phantom_protocol::connect_pinned_udp(
///     "phantom.example.com".into(), 4242, pinned_key,
/// ).await?;
/// session.await_ready().await?;
/// session.send(b"hello".to_vec()).await?;
/// let _reply = session.recv().await?;
///
/// // On a network change (iOS NWPathMonitor / Android NetworkCallback):
/// session.migrate("0.0.0.0:0".into()).await?;  // rebind to new interface
/// # Ok(())
/// # }
/// ```
#[cfg(not(target_arch = "wasm32"))]
#[cfg_attr(feature = "bindings", uniffi::export(async_runtime = "tokio"))]
pub async fn connect_pinned_udp(
    host: String,
    port: u16,
    pinned_key: Vec<u8>,
) -> Result<Arc<PhantomSession>, CoreError> {
    #[cfg(feature = "fips")]
    crate::crypto::self_tests::ensure_post_passed()
        .map_err(|e| CoreError::FipsSelfTestFailure(format!("{e:?}")))?;

    let expected_server_key = HybridVerifyingKey::from_bytes(&pinned_key)
        .map_err(|e| CoreError::CryptoError(format!("invalid pinned key: {}", e)))?;

    let addr = format!("{}:{}", host, port);
    let server: std::net::SocketAddr = tokio::net::lookup_host(&addr)
        .await
        .map_err(|e| CoreError::NetworkError(format!("resolve {}: {}", addr, e)))?
        .next()
        .ok_or_else(|| CoreError::NetworkError(format!("no address for {}", addr)))?;

    let transport = crate::api::udp_transport::UdpClientTransport::connect(server).await?;
    let session = PhantomSession::connect_with_transport(&addr, transport, expected_server_key);
    Ok(Arc::new(session))
}

/// Like [`connect_pinned_udp`] but also applies [`PhantomConfig`](crate::config::PhantomConfig)
/// liveness settings. FFI-exported.
///
/// # ⚠ Returns before the handshake — `Ok` here does not mean the pin matched
///
/// Same contract as [`connect_pinned_udp`]: binding a datagram socket says
/// nothing about who is on the other end, and the pinned-key check runs on the
/// background task.
///
/// ```rust,no_run
/// # #[tokio::main]
/// # async fn main() {
/// # let pinned_key: Vec<u8> = vec![];
/// let config = phantom_protocol::config::PhantomConfig::mobile();
/// let session =
///     phantom_protocol::connect_pinned_udp_with_config("host".into(), 4242, pinned_key, config)
///         .await
///         .expect("socket bound — says nothing about the peer's identity");
///
/// // The pin is verified here, not above.
/// session.await_ready().await.expect("not the pinned server");
/// # }
/// ```
#[cfg(not(target_arch = "wasm32"))]
#[cfg_attr(feature = "bindings", uniffi::export(async_runtime = "tokio"))]
pub async fn connect_pinned_udp_with_config(
    host: String,
    port: u16,
    pinned_key: Vec<u8>,
    config: crate::config::PhantomConfig,
) -> Result<Arc<PhantomSession>, CoreError> {
    #[cfg(feature = "fips")]
    crate::crypto::self_tests::ensure_post_passed()
        .map_err(|e| CoreError::FipsSelfTestFailure(format!("{e:?}")))?;
    let expected_server_key = HybridVerifyingKey::from_bytes(&pinned_key)
        .map_err(|e| CoreError::CryptoError(format!("invalid pinned key: {}", e)))?;
    let addr = format!("{}:{}", host, port);
    let server: std::net::SocketAddr = tokio::net::lookup_host(&addr)
        .await
        .map_err(|e| CoreError::NetworkError(format!("resolve {}: {}", addr, e)))?
        .next()
        .ok_or_else(|| CoreError::NetworkError(format!("no address for {}", addr)))?;
    let transport = crate::api::udp_transport::UdpClientTransport::connect(server).await?;
    let liveness = config.liveness();
    let session = PhantomSession::spawn_client(
        &addr,
        transport,
        expected_server_key,
        Arc::new(TokioRuntime),
        None,
        Some(liveness),
    );
    Ok(Arc::new(session))
}

/// 0-RTT resumption analogue of [`connect_pinned_udp`] — the UDP sibling of
/// [`connect_pinned_with_resumption`].
///
/// # ⚠ Returns before the handshake — `Ok` here does not mean the pin matched
///
/// Same contract as [`connect_pinned_udp`], and it matters more here: the
/// early-data blob is already on the wire when this returns, so `Ok` is not even
/// evidence that the ticket was usable.
/// [`await_ready`](PhantomSession::await_ready) resolves the pin, and only then
/// does [`early_data_accepted`](PhantomSession::early_data_accepted) mean
/// anything.
///
/// ```rust,no_run
/// # #[tokio::main]
/// # async fn main() {
/// # let pinned_key: Vec<u8> = vec![];
/// # let hint: std::sync::Arc<phantom_protocol::api::session::ResumptionHint> = unimplemented!();
/// let session = phantom_protocol::connect_pinned_udp_with_resumption(
///     "host".into(), 4242, pinned_key, hint, b"GET /".to_vec(),
/// )
/// .await
/// .expect("socket bound — says nothing about the peer's identity");
///
/// // The pin is verified here, not above.
/// session.await_ready().await.expect("not the pinned server");
/// if session.early_data_accepted().await != Some(true) {
///     // The server declined 0-RTT; the payload was requeued for 1-RTT.
/// }
/// # }
/// ```
///
/// `hint` is a [`ResumptionHint`] from a prior session's
/// [`PhantomSession::resumption_hint`]; both of its fields must be exactly 32 bytes
/// or the call fails with `ValidationError` before any socket is opened. `early_data`
/// (≤ 16 KiB) is sealed into the resuming ClientHello — an oversized blob is likewise
/// rejected before the UDP socket is bound. Acceptance is best-effort (security
/// invariant 9): an unknown/stale ticket completes 1-RTT and the caller checks
/// [`PhantomSession::early_data_accepted`] and re-sends when it is not `Some(true)`.
/// Like [`connect_pinned_udp`], the first resolved address is used with no fallback.
/// Native-only.
#[cfg(not(target_arch = "wasm32"))]
#[cfg_attr(feature = "bindings", uniffi::export(async_runtime = "tokio"))]
pub async fn connect_pinned_udp_with_resumption(
    host: String,
    port: u16,
    pinned_key: Vec<u8>,
    hint: Arc<ResumptionHint>,
    early_data: Vec<u8>,
) -> Result<Arc<PhantomSession>, CoreError> {
    #[cfg(feature = "fips")]
    crate::crypto::self_tests::ensure_post_passed()
        .map_err(|e| CoreError::FipsSelfTestFailure(format!("{e:?}")))?;

    let expected_server_key = HybridVerifyingKey::from_bytes(&pinned_key)
        .map_err(|e| CoreError::CryptoError(format!("invalid pinned key: {}", e)))?;

    let session_id: [u8; 32] = hint.session_id_ref().try_into().map_err(|_| {
        CoreError::ValidationError(format!(
            "resumption hint session_id must be 32 bytes, got {}",
            hint.session_id_ref().len()
        ))
    })?;
    let resumption_secret: [u8; 32] = hint.resumption_secret_ref().try_into().map_err(|_| {
        CoreError::ValidationError(format!(
            "resumption hint resumption_secret must be 32 bytes, got {}",
            hint.resumption_secret_ref().len()
        ))
    })?;

    if early_data.len() > EARLY_DATA_MAX_LEN {
        return Err(CoreError::ValidationError(format!(
            "early_data is {} bytes, exceeds the {}-byte 0-RTT cap",
            early_data.len(),
            EARLY_DATA_MAX_LEN
        )));
    }

    let addr = format!("{}:{}", host, port);
    let server: std::net::SocketAddr = tokio::net::lookup_host(&addr)
        .await
        .map_err(|e| CoreError::NetworkError(format!("resolve {}: {}", addr, e)))?
        .next()
        .ok_or_else(|| CoreError::NetworkError(format!("no address for {}", addr)))?;

    let transport = crate::api::udp_transport::UdpClientTransport::connect(server).await?;
    // All validation (key pin, hint size, early-data cap) is done above.
    // Delegates directly to `spawn_client` to keep 0-RTT one-shot /
    // best-effort (security invariant 9).
    let session = PhantomSession::spawn_client(
        &addr,
        transport,
        expected_server_key,
        Arc::new(TokioRuntime),
        Some((session_id, resumption_secret, early_data)),
        None,
    );
    Ok(Arc::new(session))
}

// ─── SessionBuilder ─────────────────────────────────────────────────────────

/// Builder for [`PhantomSession`] client connections.
///
/// Created via [`PhantomSession::builder`]. Call setters to configure, then
/// call `.transport(t)` to supply a [`SessionTransport`], then `.connect().await`
/// to perform the handshake and return a session.
///
/// ```rust,no_run
/// # use phantom_protocol::api::{PhantomSession, TcpSessionTransport};
/// # async fn example() -> Result<(), phantom_protocol::CoreError> {
/// # let my_key = phantom_protocol::crypto::hybrid_sign::HybridVerifyingKey::from_bytes(&[]).unwrap();
/// let stream = tokio::net::TcpStream::connect("127.0.0.1:4242").await.unwrap();
/// let transport = TcpSessionTransport::new(stream);
/// let session = PhantomSession::builder("127.0.0.1:4242")
///     .pinned_key(my_key)
///     .transport(transport)
///     .connect()
///     .await?;
/// # Ok(())
/// # }
/// ```
pub struct SessionBuilder<T = NoTransport> {
    peer_addr: String,
    transport: Option<T>,
    pinned_key: Option<HybridVerifyingKey>,
    resumption: Option<(Arc<ResumptionHint>, Vec<u8>)>,
    config: Option<crate::config::PhantomConfig>,
    runtime: Option<Arc<dyn Runtime>>,
}

impl<T> SessionBuilder<T> {
    /// Pin the expected server verifying key (required before calling `.connect()`).
    pub fn pinned_key(mut self, key: HybridVerifyingKey) -> Self {
        self.pinned_key = Some(key);
        self
    }

    /// Attach a [`ResumptionHint`] for 0-RTT resumption.
    ///
    /// Both values behind the hint — `hint.session_id()` and
    /// `hint.resumption_secret()` — must be exactly 32 bytes; oversized
    /// `early_data` (> [`EARLY_DATA_MAX_LEN`]) is rejected at `.connect()` time.
    pub fn resumption(mut self, hint: Arc<ResumptionHint>, early_data: Vec<u8>) -> Self {
        // Stored raw; the exact-32-byte length is validated at `.connect()` time
        // (matching the strict FFI `connect_pinned_*_with_resumption` path), so a
        // malformed hint is a clean `ValidationError` rather than a silent truncation.
        self.resumption = Some((hint, early_data));
        self
    }

    /// Apply a [`PhantomConfig`](crate::config::PhantomConfig)'s liveness settings.
    ///
    /// Only those. The session-cache fields are a server's, and
    /// [`write_stall_timeout`](crate::config::PhantomConfig::write_stall_timeout) belongs
    /// to a transport, which here the caller has built: its deadline is the one it was
    /// built with, so set it there — for example with
    /// [`TcpSessionTransport::with_write_stall_timeout`](crate::api::tcp_transport::TcpSessionTransport::with_write_stall_timeout).
    pub fn config(mut self, config: crate::config::PhantomConfig) -> Self {
        self.config = Some(config);
        self
    }

    /// Use a custom [`Runtime`] instead of the default [`TokioRuntime`].
    pub fn runtime(mut self, runtime: Arc<dyn Runtime>) -> Self {
        self.runtime = Some(runtime);
        self
    }

    /// Supply the `SessionTransport` implementation, transitioning the builder to a
    /// concrete type ready for `.connect()`.
    pub fn transport<U: SessionTransport>(self, transport: U) -> SessionBuilder<U> {
        SessionBuilder {
            peer_addr: self.peer_addr,
            transport: Some(transport),
            pinned_key: self.pinned_key,
            resumption: self.resumption,
            config: self.config,
            runtime: self.runtime,
        }
    }
}

impl<T: SessionTransport> SessionBuilder<T> {
    /// Start the session and return it **before the handshake has run**.
    ///
    /// This is the same contract as the `connect_pinned*` free functions and it
    /// is the one thing about this entry point worth reading twice: the returned
    /// session is in [`ConnectionState::Connecting`], the handshake proceeds on a
    /// background task, and the pinned-key check that Security Invariant 1 exists
    /// to guarantee has **not happened yet**. So `send()` returns `Ok` for bytes
    /// that are only queued, and a wrong pin surfaces later through
    /// [`PhantomSession::await_ready`] or [`PhantomSession::last_error`] rather
    /// than here. Call `await_ready()` immediately unless you have a reason not
    /// to.
    ///
    /// What *is* checked before any I/O: `Err(CoreError::ConfigError(...))` if no
    /// pinned key was supplied via `.pinned_key(...)`, and the shape of a
    /// resumption hint if one was. The transport must have been supplied via
    /// `.transport(...)`, which the type state enforces at compile time.
    pub async fn connect(self) -> Result<Arc<PhantomSession>, CoreError> {
        let pinned_key = self.pinned_key.ok_or_else(|| {
            CoreError::ConfigError("SessionBuilder: pinned_key is required".into())
        })?;
        // Transport is always Some when T != NoTransport (type-state), but we store
        // it as Option<T> so the type-converting `.transport()` setter compiles.
        let transport = self.transport.ok_or_else(|| {
            CoreError::ConfigError("SessionBuilder: transport is required".into())
        })?;
        // Validate the resumption hint to exactly 32-byte fields here (the strict
        // path the FFI `connect_pinned_*_with_resumption` shims use), before any I/O.
        let resumption = match self.resumption {
            Some((hint, early_data)) => {
                if early_data.len() > EARLY_DATA_MAX_LEN {
                    return Err(CoreError::ValidationError(format!(
                        "early_data is {} bytes, exceeds the {}-byte 0-RTT cap",
                        early_data.len(),
                        EARLY_DATA_MAX_LEN
                    )));
                }
                let session_id: [u8; 32] = hint.session_id_ref().try_into().map_err(|_| {
                    CoreError::ValidationError(format!(
                        "resumption hint session_id must be 32 bytes, got {}",
                        hint.session_id_ref().len()
                    ))
                })?;
                let resumption_secret: [u8; 32] =
                    hint.resumption_secret_ref().try_into().map_err(|_| {
                        CoreError::ValidationError(format!(
                            "resumption hint resumption_secret must be 32 bytes, got {}",
                            hint.resumption_secret_ref().len()
                        ))
                    })?;
                Some((session_id, resumption_secret, early_data))
            }
            None => None,
        };
        #[cfg(feature = "fips")]
        crate::crypto::self_tests::ensure_post_passed()
            .map_err(|e| CoreError::FipsSelfTestFailure(format!("{e:?}")))?;
        let runtime = self
            .runtime
            .unwrap_or_else(|| Arc::new(TokioRuntime) as Arc<dyn Runtime>);
        let liveness = self.config.map(|c| c.liveness());
        let session = PhantomSession::spawn_client(
            &self.peer_addr,
            transport,
            pinned_key,
            runtime,
            resumption,
            liveness,
        );
        Ok(Arc::new(session))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::handshake::{ClientHello, HandshakeResponse, HandshakeServer};

    /// Every state the enum offers is a state some production path writes.
    ///
    /// `ConnectionState` is `#[non_exhaustive]` only for downstream crates, so
    /// inside the crate the match below stays exhaustive and wildcard-free. That
    /// is the whole point of the test: a variant nobody writes is worse than a
    /// missing one, because an embedder reading the enum will wait for it. Adding
    /// a variant therefore has to break this compile, and the arm that unbreaks it
    /// has to name the code that reaches the state.
    #[test]
    fn every_connection_state_has_a_production_writer() {
        for state in [
            ConnectionState::Connecting,
            ConnectionState::Connected,
            ConnectionState::Failed,
            ConnectionState::Closed,
            ConnectionState::Migrating,
            ConnectionState::Dead,
            ConnectionState::Draining,
        ] {
            // The session keeps the state in an `AtomicU8`, so every reachable
            // variant has to survive the round trip through it.
            assert_eq!(
                ConnectionState::from_u8(state as u8),
                state,
                "{state:?} does not round-trip through the atomic it is stored in"
            );

            let (writer, data_ready) = match state {
                // `spawn_client` before the background handshake resolves.
                ConnectionState::Connecting => ("spawn_client", false),
                // The handshake completed, or `apply_liveness` saw the path recover.
                ConnectionState::Connected => ("handshake completion", true),
                // A terminal handshake or pump failure, plus the inert `connect()`.
                ConnectionState::Failed => ("terminal_error capture", false),
                // `disconnect()`.
                ConnectionState::Closed => ("disconnect", false),
                // `apply_liveness` on `PathDown`: sends still buffer for the move.
                ConnectionState::Migrating => ("apply_liveness/PathDown", true),
                // `apply_liveness` once the migration idle timeout expires.
                ConnectionState::Dead => ("apply_liveness/Dead", false),
                // The receive task, at the packet carrying the peer's close (WIRE
                // v8), and the send loop when it arms the draining window.
                ConnectionState::Draining => ("peer-close draining", false),
            };
            assert_eq!(
                state.is_data_ready(),
                data_ready,
                "{state:?} (written by {writer}) disagrees with is_data_ready()"
            );
        }
    }

    // ── No-op sinks for handle_packet calls in tests that don't exercise accept_stream ──

    /// Return a no-op stream link and incoming_stream_tx for test handle_packet calls.
    /// The receivers are immediately dropped so every send on them silently fails — which
    /// is fine; tests that do not exercise `accept_stream()` do not care about these
    /// channels.
    fn noop_accept_sinks() -> (
        StreamLink,
        mpsc::Sender<Arc<crate::api::stream::PhantomStream>>,
    ) {
        let (inc_tx, _inc_rx) = mpsc::channel(1);
        (detached_stream_link(), inc_tx)
    }

    /// A stream link whose far ends are all gone: a handle built from it can be created and
    /// dropped, and every command it sends fails.
    fn detached_stream_link() -> StreamLink {
        let (commands, _) = mpsc::channel(1);
        let (control, _) = mpsc::channel(1);
        let (released, _) = mpsc::unbounded_channel();
        StreamLink {
            commands,
            control,
            released,
        }
    }

    /// The published-state handle a direct `handle_packet` call needs. `Connected`,
    /// because a test driving one packet by hand is standing in for a live session;
    /// the tests that care about the draining state build their own and assert on it.
    fn connected_state() -> Arc<AtomicU8> {
        Arc::new(AtomicU8::new(ConnectionState::Connected as u8))
    }

    /// Reader-task scratch for a direct `handle_packet` call in a test, wired to
    /// `obs` so any stream the packet opens lands on that handle's gauge.
    fn test_recv_scratch(obs: &Arc<Observability>, ack_capacity: usize) -> RecvScratch {
        RecvScratch::new(
            ack_capacity,
            StreamGauge::new(obs.clone()),
            Arc::new(PathChallenges::default()),
            Arc::new(SharedRecvTuning::default()),
        )
    }

    // ── Mock transport for testing ──

    /// In-memory transport using channels (simulates a loopback pipe).
    struct ChannelTransport {
        tx: mpsc::Sender<Vec<u8>>,
        rx: Mutex<mpsc::Receiver<Vec<u8>>>,
    }

    impl ChannelTransport {
        /// Create a pair of connected transports (client ↔ server).
        fn pair() -> (Self, Self) {
            let (a_tx, b_rx) = mpsc::channel(64);
            let (b_tx, a_rx) = mpsc::channel(64);
            (
                Self {
                    tx: a_tx,
                    rx: Mutex::new(a_rx),
                },
                Self {
                    tx: b_tx,
                    rx: Mutex::new(b_rx),
                },
            )
        }
    }

    impl SessionTransport for ChannelTransport {
        async fn send_bytes(&self, data: &[u8]) -> Result<(), CoreError> {
            self.tx
                .send(data.to_vec())
                .await
                .map_err(|_| CoreError::NetworkError("channel closed".into()))
        }

        async fn recv_bytes(&self) -> Result<Bytes, CoreError> {
            let mut rx = self.rx.lock().await;
            let v = rx
                .recv()
                .await
                .ok_or_else(|| CoreError::NetworkError("channel closed".into()))?;
            Ok(Bytes::from(v))
        }
    }

    // ── Tests ──

    /// T5.5(b) send-side: `rekey_before_stamp` re-advertises `PacketFlags::REKEY`
    /// on EVERY packet at the new epoch — not just the rotation-trigger packet —
    /// until the peer acknowledges the rekey. This is what lets a lost trigger
    /// packet recover: the next stamp still flags REKEY so the receive-side gate
    /// follows the catch-up. Without re-advertise the second stamp would carry the
    /// new epoch unflagged and the gate would strand the receiver.
    #[test]
    fn rekey_before_stamp_re_advertises_rekey_until_peer_confirms() {
        use crate::transport::session::{CryptoState, Session};
        use crate::transport::types::{SchedulerMode, SessionId};

        let shared = [0x55u8; 32];
        let id = SessionId::from_bytes([7u8; 32]);
        let crypto = CryptoState::new(&shared, false).expect("crypto");
        let session = Arc::new(Session::from_derived(
            id,
            crypto,
            SchedulerMode::LowLatency,
            shared,
            false,
        ));
        session.set_rekey_threshold(2);
        let obs = Observability::new(ObservabilityConfig::default());

        // Below the watermark: no rekey, no flag.
        assert_eq!(
            rekey_before_stamp(&session, &obs),
            Some(0),
            "below threshold: no flag"
        );

        // Cross the high-watermark so the next stamp rotates.
        let h = PacketHeader::new(
            *session.id(),
            1,
            0,
            PacketFlags::new(PacketFlags::ENCRYPTED),
        );
        for i in 0..2u64 {
            session
                .encrypt_packet(
                    &PacketHeader {
                        packet_number: i,
                        ..h
                    },
                    b"x",
                    &[],
                )
                .expect("encrypt");
        }
        assert!(session.send_needs_rekey());

        // The rotation-trigger stamp flags REKEY and bumps the epoch.
        assert_eq!(rekey_before_stamp(&session, &obs), Some(PacketFlags::REKEY));
        assert_eq!(session.current_epoch(), 1);
        assert!(session.rekey_unconfirmed());

        // The NEXT stamp re-advertises REKEY even though no further rekey happens —
        // the peer has not confirmed yet.
        assert_eq!(rekey_before_stamp(&session, &obs), Some(PacketFlags::REKEY));
        assert_eq!(
            session.current_epoch(),
            1,
            "no second rekey — only a re-advertise"
        );
    }

    /// H9 forward-compat (client side): when the server answers a `ClientHello`
    /// with a typed `ServerReject` (the version isn't one it speaks), the client
    /// surfaces a clear version-mismatch error instead of hanging or returning a
    /// generic failure — and crucially does NOT auto-downgrade.
    #[tokio::test]
    async fn client_surfaces_server_reject_as_version_error() {
        use crate::transport::handshake::{ServerReject, ServerReply, PROTOCOL_VERSION};

        let (client_transport, server_transport) = ChannelTransport::pair();
        // The reject path errors before any key verification, so any key works.
        let (_sk, expected_vk) = crate::crypto::hybrid_sign::HybridSigningKey::generate();

        let server = tokio::spawn(async move {
            // Consume the ClientHello, then reply with the typed reject (T4.4 framed).
            let _hello = server_transport.recv_bytes().await.unwrap();
            let reject = ServerReply::Reject(ServerReject::unsupported_version())
                .to_wire()
                .unwrap();
            server_transport.send_bytes(&reject).await.unwrap();
        });

        let result = run_client_handshake(&client_transport, &expected_vk, None).await;
        server.await.unwrap();

        let err = result.expect_err("client must surface the reject as an error");
        // The typed variant, not a string: this is what an application branches on to tell
        // "update your client" apart from a generic handshake failure, and it is the whole
        // reason `PROTOCOL_VERSION` moves whenever the wire does — a version mismatch left
        // to the packet-level check would be a silent drop with no error at all.
        assert!(
            matches!(err, CoreError::ProtocolRejected(_)),
            "expected a typed rejection, got: {err:?}"
        );
        let msg = format!("{err:?}");
        assert!(
            msg.contains("unsupported protocol version")
                && msg.contains(&format!("v{PROTOCOL_VERSION}")),
            "the error must name the versions involved so an operator can act on it, got: \
             {msg}"
        );
    }

    /// A rejection is a definitive answer, so the client must not spend the whole connect
    /// arriving at it. The tolerance loop reads past up to `MAX_CLIENT_REJECT_ROUNDS`
    /// rejects before it believes one, and over PhantomUDP each of those reads is answered
    /// only after the transport retransmits the flight — so the cost of the reject path is
    /// set by the handshake retransmission schedule, and this pins that it stays well
    /// inside the deadline the session would otherwise report a timeout at.
    ///
    /// The peer here answers every flight, which is what a server that does not speak the
    /// client's version does: the version check is stateless, so a retransmitted hello is
    /// rejected again rather than ignored.
    #[tokio::test]
    async fn a_rejecting_server_is_believed_well_inside_the_session_deadline() {
        use crate::api::udp_transport::UdpClientTransport;
        use crate::transport::handshake::{ServerReject, ServerReply};
        use crate::transport::phantom_udp::datagram::{
            encode_datagrams, push_datagram, FragmentAssembler,
        };
        use crate::transport::phantom_udp::envelope::PacketType;

        let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = peer.local_addr().unwrap();
        let client = UdpClientTransport::connect(peer_addr).await.unwrap();
        // The reject path errors before any key verification, so any key works.
        let (_sk, expected_vk) = crate::crypto::hybrid_sign::HybridSigningKey::generate();

        let serve = tokio::spawn(async move {
            let reject = ServerReply::Reject(ServerReject::unsupported_version())
                .to_wire()
                .unwrap();
            let mut asm = FragmentAssembler::new();
            let mut buf = vec![0u8; 2048];
            let mut pkt_id = 0u32;
            loop {
                let Ok((n, from)) = peer.recv_from(&mut buf).await else {
                    return;
                };
                let Ok((hdr, Some(_frame))) = push_datagram(&mut asm, &buf[..n]) else {
                    continue; // a fragment, or garbage: wait for the rest
                };
                pkt_id += 1;
                for d in encode_datagrams(PacketType::Initial, &hdr.cid, pkt_id, &reject).unwrap() {
                    let _ = peer.send_to(&d, from).await;
                }
            }
        });

        let started = std::time::Instant::now();
        let result = run_client_handshake(&client, &expected_vk, None).await;
        let elapsed = started.elapsed();
        serve.abort();

        let err = result.expect_err("client must surface the reject as an error");
        assert!(
            matches!(err, CoreError::ProtocolRejected(_)),
            "expected a typed rejection, got: {err:?}"
        );
        assert!(
            elapsed < CLIENT_HANDSHAKE_DEADLINE,
            "the rejection took {elapsed:?} to surface, which is not inside the \
             {CLIENT_HANDSHAKE_DEADLINE:?} the session gives the whole connect — the user \
             would see a timeout instead of the reason"
        );
    }

    /// An **injected** `ServerReject` (a tiny, pre-crypto blob a network
    /// attacker can spray) during a HEALTHY handshake must NOT abort it. The client remembers
    /// the reject and keeps waiting for a valid `ServerHello`; it gives up (surfacing the
    /// reject) only if one never arrives. Here the attacker injects a reject ahead of the real
    /// cookie/ServerHello flow; the handshake must still succeed.
    #[tokio::test]
    async fn injected_server_reject_does_not_abort_a_healthy_handshake() {
        use crate::transport::handshake::{ServerReject, ServerReply};

        let (client_transport, server_transport) = ChannelTransport::pair();
        let server_hs = HandshakeServer::new().unwrap();
        let expected_vk = server_hs.verifying_key().clone();

        let server = tokio::spawn(async move {
            let Ok(hello_bytes) = server_transport.recv_bytes().await else {
                return;
            };
            let Ok(client_hello) = borsh::from_slice::<ClientHello>(&hello_bytes) else {
                return;
            };
            // Inject a forged reject AHEAD of the real handshake responses (T4.4 framed).
            let reject = ServerReply::Reject(ServerReject::unsupported_version())
                .to_wire()
                .unwrap();
            if server_transport.send_bytes(&reject).await.is_err() {
                return;
            }
            let ip = "127.0.0.1".parse().unwrap();
            let sh = match server_hs.process_client_hello(&client_hello, 0, ip) {
                HandshakeResponse::Retry(retry) => {
                    if server_transport
                        .send_bytes(&ServerReply::Retry(retry).to_wire().unwrap())
                        .await
                        .is_err()
                    {
                        return;
                    }
                    let Ok(h2) = server_transport.recv_bytes().await else {
                        return;
                    };
                    let Ok(next) = borsh::from_slice::<ClientHello>(&h2) else {
                        return;
                    };
                    match server_hs.process_client_hello(&next, 0, ip) {
                        HandshakeResponse::Success(sh, _, _) => sh,
                        _ => return,
                    }
                }
                HandshakeResponse::Success(sh, _, _) => sh,
                _ => return,
            };
            let _ = server_transport
                .send_bytes(&ServerReply::Hello(sh).to_wire().unwrap())
                .await;
        });

        let result = run_client_handshake(&client_transport, &expected_vk, None).await;
        // Close the channel so the server task ends even if the client aborted (the
        // regression case), instead of blocking forever on the retried-hello it will
        // never receive.
        drop(client_transport);
        let _ = server.await;
        assert!(
            result.is_ok(),
            "an injected ServerReject ahead of the real ServerHello must not abort a healthy \
             handshake; got {result:?}"
        );
    }

    /// **HS-02.** A MITM that answers every `ClientHello` with a fresh cheap
    /// `HelloRetryRequest` must NOT loop the client forever — `run_client_handshake`
    /// caps the retry rounds and returns an error. (Pre-fix this test would hang.)
    #[tokio::test]
    async fn client_handshake_caps_retry_rounds() {
        use crate::transport::handshake::HelloRetryRequest;

        let (client_transport, server_transport) = ChannelTransport::pair();
        let (_sk, expected_vk) = crate::crypto::hybrid_sign::HybridSigningKey::generate();

        // Malicious server: answer EVERY ClientHello with a fresh, cheap
        // HelloRetryRequest (no cookie, no PoW) — never converging.
        let server = tokio::spawn(async move {
            loop {
                if server_transport.recv_bytes().await.is_err() {
                    break;
                }
                let retry = borsh::to_vec(&HelloRetryRequest {
                    challenge: None,
                    cookie: None,
                })
                .expect("encode retry");
                if server_transport.send_bytes(&retry).await.is_err() {
                    break;
                }
            }
        });

        let result = run_client_handshake(&client_transport, &expected_vk, None).await;
        drop(client_transport); // close the channel so the server task ends
        let _ = server.await;

        assert!(
            matches!(result, Err(CoreError::HandshakeError(_))),
            "client must error after the retry-round cap, not loop forever; got {result:?}"
        );
    }

    /// **INFOLEAK-1.** `ResumptionHint`'s `Debug` must redact the 0-RTT
    /// resumption secret, so a **Rust** caller logging it with `{:?}` does not
    /// put key material in a log.
    ///
    /// This covers Rust callers only, and saying so is the point: UniFFI never
    /// calls this impl, so it protects no foreign-language consumer. The
    /// foreign-language half is covered by
    /// `resumption_hint_is_an_object_so_no_binding_can_stringify_its_fields`
    /// below, and by the type being a `uniffi::Object` at all.
    #[test]
    fn resumption_hint_debug_redacts_secret() {
        let hint = ResumptionHint::new(vec![0xAB; 32], vec![0xCD; 32]);
        let dbg = format!("{hint:?}");
        assert!(dbg.contains("REDACTED"), "secret must be redacted: {dbg}");
        // No representation of the secret bytes (0xCD) leaks — neither hex nor
        // the decimal the derived Debug would have printed for a Vec<u8>.
        assert!(
            !dbg.contains("205"),
            "no decimal secret bytes in Debug: {dbg}"
        );
        assert!(
            !dbg.to_lowercase().contains("cd, cd"),
            "no hex secret bytes: {dbg}"
        );
    }

    /// The accessors return exactly the bytes the constructor was given, and
    /// the borrowing pair used on the connect path agrees with the owned pair
    /// the bindings call.
    ///
    /// Trivial as an assertion, and it is here for what it pins rather than
    /// what it checks: turning `ResumptionHint` from a record into an object
    /// moved two public fields behind four methods, and a hint whose accessors
    /// disagreed with its storage would fail as a handshake that cannot
    /// succeed — a network-level symptom for a data-level bug.
    #[test]
    fn resumption_hint_accessors_round_trip_the_bytes_they_were_given() {
        let sid: Vec<u8> = (0u8..32).collect();
        let secret: Vec<u8> = (32u8..64).collect();
        let hint = ResumptionHint::new(sid.clone(), secret.clone());

        assert_eq!(hint.session_id(), sid);
        assert_eq!(hint.resumption_secret(), secret);
        assert_eq!(hint.session_id_ref(), sid.as_slice());
        assert_eq!(hint.resumption_secret_ref(), secret.as_slice());
    }

    /// The type must stay a `uniffi::Object` with no exported `Debug` or
    /// `Display`, because that pair is exactly what UniFFI turns into a
    /// field-printing `__str__`.
    ///
    /// **This reads its own source**, which is worth stating plainly: the leak
    /// it guards lives in generated files under `tests/bindings/`, which no
    /// Rust test can see. What can be checked from here is the declaration that
    /// produces them. The check strips block comments as well as line comments
    /// — a gate in this repository once accepted a call it was meant to reject
    /// because the text sat inside `/* */`.
    #[test]
    fn resumption_hint_is_an_object_so_no_binding_can_stringify_its_fields() {
        let src = include_str!("session.rs");
        let decl = src
            .split("pub struct ResumptionHint {")
            .next()
            .expect("the type declaration must be in this file");
        // Everything from the doc-comment header down to the struct keyword,
        // with comments removed so prose about records cannot satisfy or fail
        // this.
        let tail = &decl[decl.len().saturating_sub(4000)..];
        let stripped = strip_comments(tail);
        assert!(
            stripped.contains("derive(uniffi::Object)"),
            "ResumptionHint must stay a uniffi::Object: a Record gets a \
             generated stringifier that prints every field, and the Python one \
             writes the resumption secret out in full"
        );
        assert!(
            !stripped.contains("derive(uniffi::Record)"),
            "ResumptionHint must not be a uniffi::Record"
        );

        // And no stringifying trait is exported for it. The form that matters
        // is `#[uniffi::export(Debug)]` **on the struct** — UniFFI parses that
        // attribute's arguments as trait discriminants and generates Python's
        // `__repr__` from `Debug` and `__str__` from `Display`. Writing
        // `#[uniffi::export]` above `impl std::fmt::Debug` does not compile, so
        // it is not the shape to guard against; this one does compile, and an
        // earlier version of this test looked only for the shape that does not.
        for trait_name in ["Debug", "Display", "Eq", "Hash", "Ord"] {
            let bad = format!("uniffi::export({trait_name})");
            assert!(
                !stripped.contains(&bad),
                "`#[uniffi::export({trait_name})]` on ResumptionHint makes UniFFI \
                 generate a stringifier (or a comparator) from that trait, which \
                 is what printed the resumption secret when this type was a record"
            );
        }
    }

    /// Strip `//` line comments and `/* */` block comments, so a source-reading
    /// test cannot be satisfied — or defeated — by prose.
    fn strip_comments(src: &str) -> String {
        let mut out = String::with_capacity(src.len());
        let bytes = src.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i..].starts_with(b"//") {
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
            } else if bytes[i..].starts_with(b"/*") {
                i += 2;
                while i < bytes.len() && !bytes[i..].starts_with(b"*/") {
                    i += 1;
                }
                i = (i + 2).min(bytes.len());
            } else {
                out.push(bytes[i] as char);
                i += 1;
            }
        }
        out
    }

    #[tokio::test]
    async fn test_phantom_session_instant_connect() {
        let session = PhantomSession::connect("example.com:443".to_string());

        // The inert constructor reports Failed so misuse is observable.
        assert_eq!(session.connection_state(), ConnectionState::Failed);
        assert!(!session.is_data_ready());
        assert_eq!(session.peer_addr(), "example.com:443");
    }

    /// **T5.7 regression — the inert `connect()` performs no handshake
    /// and sends no bytes.** The constructor is documented as deprecated (no
    /// `#[deprecated]` attribute is possible — see the doc-comment for why), so
    /// this test pins the inert contract the doc promises: the session immediately
    /// reports [`ConnectionState::Failed`] so misuse is observable, `send()`
    /// returns an error (not a silent queue), and `recv()` never yields. If a
    /// future change ever wires a real pump into this constructor, this test must
    /// be updated alongside the doc — the two must not drift apart.
    /// `disconnect()` on a session that has already ended keeps the end it reached:
    /// `Dead` is what a transport that gave up publishes beside the cause
    /// `last_error()` reports, and `Failed` is a handshake's. Overwriting either with
    /// `Closed` told a caller the session was closed on request when it had died.
    #[tokio::test]
    async fn disconnect_leaves_an_ended_session_in_the_state_it_ended_in() {
        let failed = PhantomSession::connect("example.com:443".to_string());
        assert_eq!(failed.connection_state(), ConnectionState::Failed);
        failed.disconnect().await.unwrap();
        assert_eq!(failed.connection_state(), ConnectionState::Failed);

        let dead = PhantomSession::connect("example.com:443".to_string());
        dead.set_state(ConnectionState::Dead);
        dead.disconnect().await.unwrap();
        assert_eq!(dead.connection_state(), ConnectionState::Dead);

        for live in [
            ConnectionState::Connecting,
            ConnectionState::Connected,
            ConnectionState::Migrating,
            ConnectionState::Draining,
        ] {
            let session = PhantomSession::connect("example.com:443".to_string());
            session.set_state(live);
            session.disconnect().await.unwrap();
            assert_eq!(
                session.connection_state(),
                ConnectionState::Closed,
                "disconnect() from {live:?} must publish Closed"
            );
        }
    }

    #[tokio::test]
    async fn deprecated_connect_is_inert_and_reports_failed() {
        let session = PhantomSession::connect("example.com:443".to_string());

        // Inert constructor immediately reports Failed — not an eternal Connecting.
        assert_eq!(session.connection_state(), ConnectionState::Failed);
        assert!(!session.is_data_ready());

        // send() returns an error in Failed state — no silent buffering.
        let send_err = session.send(b"first".to_vec()).await;
        assert!(
            send_err.is_err(),
            "inert connect() must reject send() with an error in Failed state"
        );

        // recv() must never deliver application bytes — no pump feeds the recv
        // channel, and the inert constructor drops the channel's sender at once,
        // so recv() resolves to an error rather than any data. A short timeout
        // bounds the wait and proves recv() does not yield a payload.
        let recv = tokio::time::timeout(std::time::Duration::from_millis(50), session.recv()).await;
        match recv {
            Ok(Err(_)) => { /* expected: "session closed" — never any bytes */ }
            Ok(Ok(bytes)) => panic!(
                "inert connect() must never deliver received data, got {} bytes",
                bytes.len()
            ),
            Err(_elapsed) => { /* also acceptable: recv blocked the whole window */ }
        }
    }

    /// `connect()` immediately reports `Failed` so a caller checking
    /// `connection_state()` sees the no-op rather than blocking forever on
    /// `Connecting`.
    #[test]
    fn deprecated_connect_reports_failed_state() {
        let session = PhantomSession::connect("x:1".to_string());
        assert_eq!(
            session.connection_state(),
            ConnectionState::Failed,
            "inert connect() must report Failed, not Connecting"
        );
    }

    #[tokio::test]
    async fn test_phantom_session_send_queue() {
        let session = PhantomSession::connect("example.com:443".to_string());

        // Simulate the Connecting state that a real pump would set (the inert
        // constructor reports Failed, but the queue mechanism is exercised by
        // advancing the state to Connecting).
        session.set_state(ConnectionState::Connecting);

        // Send while connecting — should queue
        session.send(vec![1, 2, 3]).await.unwrap();
        session.send(vec![4, 5, 6]).await.unwrap();
        assert_eq!(session.queued_count().await, 2);

        // Simulate handshake completion
        session.set_state(ConnectionState::Connected);
        assert!(session.is_data_ready());

        // Flush queue
        let flushed = session.flush_queue().await.unwrap();
        assert_eq!(flushed, 2);
        assert_eq!(session.queued_count().await, 0);
    }

    /// Walk the state machine the rustdoc advertises, in order, and check the
    /// data-readiness answer at every step. `Migrating` is the interesting one:
    /// it must stay data-ready, because a session whose path went silent still
    /// accepts `send()` — the bytes buffer and go out after the move.
    #[tokio::test]
    async fn test_phantom_session_state_progression() {
        let session = PhantomSession::connect("example.com:443".to_string());

        // Advance to Connecting to exercise the state-progression sequence.
        session.set_state(ConnectionState::Connecting);
        assert_eq!(session.connection_state(), ConnectionState::Connecting);
        assert!(!session.is_data_ready());

        session.set_state(ConnectionState::Connected);
        assert!(session.is_data_ready());

        session.set_state(ConnectionState::Migrating);
        assert!(session.is_data_ready());

        session.set_state(ConnectionState::Connected);
        assert!(session.is_data_ready());

        session.set_state(ConnectionState::Dead);
        assert!(!session.is_data_ready());
    }

    #[tokio::test]
    async fn test_phantom_session_close() {
        // A live session: the inert constructor reports `Failed`, which a later
        // `disconnect()` deliberately leaves in place.
        let session = PhantomSession::connect("example.com:443".to_string());
        session.set_state(ConnectionState::Connected);
        session.disconnect().await.unwrap();
        assert_eq!(session.connection_state(), ConnectionState::Closed);
        assert!(!session.is_data_ready());
    }

    /// Helper: decrypt an incoming encrypted frame on the test server side.
    fn decrypt_incoming(
        server_session: &crate::transport::session::Session,
        bytes: &[u8],
    ) -> Vec<u8> {
        // The peer pump applies header protection (T4.6); unmask with this
        // side's recv HP key (== the sender's send HP key) before reading.
        let pkt = server_session
            .parse_protected(bytes)
            .expect("parse header-protected PhantomPacket");
        assert!(
            pkt.header.flags.contains(PacketFlags::ENCRYPTED),
            "expected ENCRYPTED flag on application data"
        );
        let plain = server_session
            .decrypt_packet(&pkt.header, &pkt.payload, &[])
            .expect("decrypt application data");
        // Reliable app frames carry a 4-byte gap-free stream_offset prefix (A.5);
        // strip it so callers compare against the raw application payload.
        if pkt.header.flags.contains(PacketFlags::RELIABLE) && plain.len() >= 4 {
            plain[4..].to_vec()
        } else {
            plain
        }
    }

    /// Helper: build an encrypted reply frame from the test server side. Mirrors
    /// the live sender's reliable framing: plaintext = `[stream_offset: u32 BE]
    /// [payload]` with `stream_offset == sequence` (no control gaps in this test).
    fn encrypt_outgoing(
        server_session: &crate::transport::session::Session,
        session_id: SessionId,
        stream_id: TransportStreamId,
        sequence: u32,
        payload: &[u8],
    ) -> Vec<u8> {
        encrypt_outgoing_at(
            server_session,
            session_id,
            stream_id,
            sequence as u64,
            sequence,
            payload,
        )
    }

    /// The same frame builder with the two counters separated. The packet number is
    /// per-direction and never repeats (a repeat is a replay and the window drops it),
    /// while the stream offset is per-stream and starts at zero — so a test that sends
    /// two frames competing for the same offset has to advance the packet number on its
    /// own. `encrypt_outgoing` ties them together for the common case where a test sends
    /// one frame per offset.
    fn encrypt_outgoing_at(
        server_session: &crate::transport::session::Session,
        session_id: SessionId,
        stream_id: TransportStreamId,
        packet_number: u64,
        stream_offset: u32,
        payload: &[u8],
    ) -> Vec<u8> {
        let flag_bits = PacketFlags::RELIABLE | PacketFlags::ENCRYPTED;
        let header = PacketHeader::new(
            session_id,
            stream_id,
            packet_number,
            PacketFlags::new(flag_bits),
        )
        .with_epoch(server_session.current_epoch());
        let mut pt = Vec::with_capacity(4 + payload.len());
        pt.extend_from_slice(&stream_offset.to_be_bytes());
        pt.extend_from_slice(payload);
        let ct = server_session
            .encrypt_packet(&header, &pt, &[])
            .expect("encrypt reply");
        let packet = PhantomPacket::new(header, ct);
        // Apply header protection so the peer pump's parse_protected unmasks it.
        server_session
            .protect_packet(&packet)
            .expect("header protection")
    }

    /// The congestion-control snapshot must be absent before a session exists
    /// and present once it does. Without this the accessor could silently
    /// return `None` forever and a recorded window series would just be empty —
    /// indistinguishable from a window that never moved.
    #[tokio::test]
    async fn bandwidth_snapshot_is_none_until_the_session_is_established() {
        let (client_transport, _server_transport) = ChannelTransport::pair();
        let (_sk, vk) = crate::crypto::hybrid_sign::HybridSigningKey::generate();
        let session =
            PhantomSession::connect_with_transport("test-server:9000", client_transport, vk);

        assert!(
            session.bandwidth_snapshot().await.is_none(),
            "no negotiated session yet, so there is no window to report"
        );
    }

    /// Integration test: Client handshake via ChannelTransport with a
    /// simulated server responder.
    #[tokio::test]
    async fn test_phantom_session_handshake_via_transport() {
        let (client_transport, server_transport) = ChannelTransport::pair();
        let server_hs = HandshakeServer::new().unwrap();
        let server_pinned_key = server_hs.verifying_key().clone();

        // Start client session — spawns background handshake (with pinning)
        let session = PhantomSession::connect_with_transport(
            "test-server:9000",
            client_transport,
            server_pinned_key,
        );

        // Queue a message before handshake completes
        session.send(b"early-data".to_vec()).await.unwrap();

        // Simulate server responder
        let server_handle = tokio::spawn(async move {
            let client_ip = "127.0.0.1".parse().unwrap();

            // 1. Receive the (bare borsh) ClientHello.
            let client_hello_bytes = server_transport.recv_bytes().await.unwrap();
            let client_hello = borsh::from_slice::<ClientHello>(&client_hello_bytes).unwrap();

            // 2. Process. The DoS gate answers at most ONE hello with a
            //    cookie/PoW `Retry` — the re-sent, cookie-bearing hello is
            //    admitted — so this is a straight-line match, not a loop.
            let response = server_hs.process_client_hello(&client_hello, 0, client_ip);
            let server_session = match response {
                HandshakeResponse::Retry(retry) => {
                    let retry_bytes = ServerReply::Retry(retry).to_wire().unwrap();
                    server_transport.send_bytes(&retry_bytes).await.unwrap();
                    // Receive retried client hello
                    let next_bytes = server_transport.recv_bytes().await.unwrap();
                    let next_hello = borsh::from_slice::<ClientHello>(&next_bytes).unwrap();
                    let resp2 = server_hs.process_client_hello(&next_hello, 0, client_ip);
                    match resp2 {
                        HandshakeResponse::Success(server_hello, session, _) => {
                            let server_hello_bytes =
                                ServerReply::Hello(server_hello).to_wire().unwrap();
                            server_transport
                                .send_bytes(&server_hello_bytes)
                                .await
                                .unwrap();
                            session
                        }
                        _ => panic!("Expected success after retry"),
                    }
                }
                HandshakeResponse::Success(server_hello, session, _) => {
                    let server_hello_bytes = ServerReply::Hello(server_hello).to_wire().unwrap();
                    server_transport
                        .send_bytes(&server_hello_bytes)
                        .await
                        .unwrap();
                    session
                }
                HandshakeResponse::Reject(r) => panic!("unexpected reject: {r:?}"),
                HandshakeResponse::Fail(e) => panic!("handshake failed: {e:?}"),
            };

            let session_id = *server_session.id();

            // 3. Receive the flushed early data — must be ENCRYPTED.
            let early_frame = server_transport.recv_bytes().await.unwrap();
            assert!(
                !early_frame
                    .windows(b"early-data".len())
                    .any(|w| w == b"early-data"),
                "encrypted frame must not contain plaintext early-data"
            );
            let early_plain = decrypt_incoming(&server_session, &early_frame);
            assert_eq!(early_plain, b"early-data");

            // 4. Receive a post-handshake message — must be ENCRYPTED.
            let post_frame = server_transport.recv_bytes().await.unwrap();
            let post_plain = decrypt_incoming(&server_session, &post_frame);
            assert_eq!(post_plain, b"after-handshake");

            // 5. Send encrypted reply back. stream_offset (== sequence here) must
            // be 0: this is the FIRST reliable frame server→client on this stream,
            // so the client reassembles it at offset 0 (A.5).
            let reply = encrypt_outgoing(&server_session, session_id, 1, 0, b"server-reply");
            server_transport.send_bytes(&reply).await.unwrap();
        });

        // Wait for handshake to progress
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        // Should be connected now
        assert_eq!(session.connection_state(), ConnectionState::Connected);

        // Send after handshake
        session.send(b"after-handshake".to_vec()).await.unwrap();

        // Receive server reply — now returns DECRYPTED plaintext payload.
        let reply = session.recv().await.unwrap();
        assert_eq!(reply, b"server-reply");

        server_handle.await.unwrap();
        session.disconnect().await.unwrap();
    }

    /// After a successful handshake via `ChannelTransport`, the client session's
    /// observability must record at least one handshake success.
    #[tokio::test]
    async fn client_session_records_handshake_success_metric() {
        let (client_transport, server_transport) = ChannelTransport::pair();
        let server_hs = HandshakeServer::new().unwrap();
        let server_pinned_key = server_hs.verifying_key().clone();

        let session = PhantomSession::connect_with_transport(
            "test-server:9001",
            client_transport,
            server_pinned_key,
        );

        // Drive the server handshake in a background task. Keep `server_transport`
        // alive until after we've checked the metric so the client pump doesn't
        // get a premature EOF that races with the handshake outcome.
        let server_handle = tokio::spawn(async move {
            let client_ip = "127.0.0.1".parse().unwrap();
            let client_hello_bytes = server_transport.recv_bytes().await.unwrap();
            let client_hello = borsh::from_slice::<ClientHello>(&client_hello_bytes).unwrap();
            let response = server_hs.process_client_hello(&client_hello, 0, client_ip);
            match response {
                HandshakeResponse::Success(server_hello, _server_session, _) => {
                    let reply_bytes = ServerReply::Hello(server_hello).to_wire().unwrap();
                    server_transport.send_bytes(&reply_bytes).await.unwrap();
                    // Keep the transport alive (holding the channel open) while the
                    // client reads and processes the ServerHello.
                    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                    drop(server_transport);
                }
                HandshakeResponse::Retry(retry) => {
                    let retry_bytes = ServerReply::Retry(retry).to_wire().unwrap();
                    server_transport.send_bytes(&retry_bytes).await.unwrap();
                    let next_bytes = server_transport.recv_bytes().await.unwrap();
                    let next_hello = borsh::from_slice::<ClientHello>(&next_bytes).unwrap();
                    let resp2 = server_hs.process_client_hello(&next_hello, 0, client_ip);
                    match resp2 {
                        HandshakeResponse::Success(server_hello, _server_session, _) => {
                            let reply_bytes = ServerReply::Hello(server_hello).to_wire().unwrap();
                            server_transport.send_bytes(&reply_bytes).await.unwrap();
                            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                            drop(server_transport);
                        }
                        _ => panic!("expected success after retry"),
                    }
                }
                other => panic!("unexpected: {other:?}"),
            }
        });

        // Wait long enough for the handshake to complete (mirrors existing tests).
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;

        let snap = session.observability().snapshot();
        assert!(
            snap.handshakes_success >= 1,
            "client session must record at least one handshake success; got {}",
            snap.handshakes_success
        );
        assert_eq!(snap.handshakes_failure, 0, "no handshake failures expected");

        server_handle.await.unwrap();
        session.disconnect().await.unwrap();
    }

    /// Reliable delivery: a RELIABLE application send must survive a dropped data frame.
    ///
    /// The client runs over a `LossyTransport`; once the handshake completes we
    /// arm a drop of the next frame (the data frame) and send a reliable
    /// payload. The first transmission is lost, so the server only sees the
    /// payload because the raw-app stream buffers it and the data pump
    /// retransmits the timed-out segment.
    #[tokio::test]
    async fn reliable_send_survives_a_dropped_data_frame() {
        use crate::test_harness::fault_transport::{FaultControl, LossyTransport};

        let (client_transport, server_transport) = ChannelTransport::pair();
        let faults = FaultControl::new();
        let lossy_client = LossyTransport::new(client_transport, faults.clone());

        let server_hs = HandshakeServer::new().unwrap();
        let server_pinned_key = server_hs.verifying_key().clone();

        let session = PhantomSession::connect_with_transport(
            "test-server:9000",
            lossy_client,
            server_pinned_key,
        );

        let server_handle = tokio::spawn(async move {
            let client_ip = "127.0.0.1".parse().unwrap();
            let client_hello_bytes = server_transport.recv_bytes().await.unwrap();
            let client_hello = borsh::from_slice::<ClientHello>(&client_hello_bytes).unwrap();

            // Drive the handshake to completion. The DoS gate takes at most one
            // cookie/PoW retry round, so this is a match rather than a loop.
            let server_session = match server_hs.process_client_hello(&client_hello, 0, client_ip) {
                HandshakeResponse::Retry(retry) => {
                    let retry_bytes = ServerReply::Retry(retry).to_wire().unwrap();
                    server_transport.send_bytes(&retry_bytes).await.unwrap();
                    let next_bytes = server_transport.recv_bytes().await.unwrap();
                    let next_hello = borsh::from_slice::<ClientHello>(&next_bytes).unwrap();
                    match server_hs.process_client_hello(&next_hello, 0, client_ip) {
                        HandshakeResponse::Success(server_hello, session, _) => {
                            let b = ServerReply::Hello(server_hello).to_wire().unwrap();
                            server_transport.send_bytes(&b).await.unwrap();
                            session
                        }
                        _ => panic!("expected success after retry"),
                    }
                }
                HandshakeResponse::Success(server_hello, session, _) => {
                    let b = ServerReply::Hello(server_hello).to_wire().unwrap();
                    server_transport.send_bytes(&b).await.unwrap();
                    session
                }
                HandshakeResponse::Reject(r) => panic!("unexpected reject: {r:?}"),
                HandshakeResponse::Fail(e) => panic!("handshake failed: {e:?}"),
            };

            // The reliable data frame was dropped on first transmission; it can
            // only arrive via retransmission. Time-bounded so a missing
            // retransmit fails loudly instead of hanging the test forever.
            let data_frame = tokio::time::timeout(
                std::time::Duration::from_secs(3),
                server_transport.recv_bytes(),
            )
            .await
            .expect(
                "reliable payload never arrived within 3s — the dropped data frame was not \
                 retransmitted (loss-recovery regression)",
            )
            .unwrap();
            let plain = decrypt_incoming(&server_session, &data_frame);
            assert_eq!(plain, b"reliable-payload");
        });

        // Wait for the handshake to complete.
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        assert_eq!(session.connection_state(), ConnectionState::Connected);

        // Arm a single drop, then send: the next frame on the wire (the data
        // frame) is silently lost.
        faults.arm_drop_next(1);
        session.send(b"reliable-payload".to_vec()).await.unwrap();

        server_handle.await.unwrap();
        session.disconnect().await.unwrap();
    }

    /// A retransmission driven by the RTO — with **no acknowledgement in the
    /// session's history at all** — must reach congestion control as both a copy
    /// and a loss.
    ///
    /// This is the drain → `on_packet_retransmitted` / `on_packet_lost` wiring,
    /// and it is deliberately exercised on the silent path. The RTO pass is a
    /// local timer, so this is the case that shows the loss report is not
    /// conditioned on anything the peer does: a peer that answers nothing cannot
    /// make the connection read as a path that lost nothing.
    ///
    /// The observable is the byte counters rather than the BBR phase. Loss no
    /// longer moves the state machine (it bounds inflight instead), and a test
    /// that asserted on a phase would in any case have been asserting that a
    /// particular response was chosen, not that the loss was reported at all.
    #[tokio::test]
    async fn drain_reports_a_retransmit_as_loss_to_bbr() {
        tokio::time::pause();
        let sid = fixed_session_id();
        let (client, _server) = paired_sessions(sid);

        let stream = Arc::new(TransportStream::new(1));
        stream.send_reliable(Bytes::from("payload")).await.unwrap();
        let streams: Arc<DashMap<u32, Arc<TransportStream>>> = Arc::new(DashMap::new());
        streams.insert(1u32, stream);

        let (client_t, _server_t) = ChannelTransport::pair();
        let transport = Arc::new(client_t);
        let obs = Observability::new(ObservabilityConfig::default());

        // First drain: the initial transmission — neither a retransmission nor a
        // loss.
        drain_streams_priority_ordered(&transport, &client, sid, &streams, &obs).await;
        assert_eq!(
            client.bbr_bytes_retransmitted(),
            0,
            "an initial transmission is not a retransmission"
        );
        assert_eq!(
            client.bbr_bytes_lost(),
            0,
            "an initial transmission is not a loss"
        );

        // The RTO expires; the next drain retransmits and must report both.
        tokio::time::advance(std::time::Duration::from_millis(1100)).await;
        drain_streams_priority_ordered(&transport, &client, sid, &streams, &obs).await;
        assert_eq!(
            client.bbr_bytes_retransmitted(),
            b"payload".len() as u64,
            "the copy must reach the flight arithmetic"
        );
        assert_eq!(
            client.bbr_bytes_lost(),
            b"payload".len() as u64,
            "and the hole must reach the loss response, on a connection that has \
             never received a single acknowledgement"
        );
    }

    /// New data must not be transmitted while inflight already exceeds the
    /// congestion window — the drain holds it back until ACKs free the window.
    #[tokio::test]
    async fn drain_withholds_new_data_when_inflight_exceeds_cwnd() {
        let sid = fixed_session_id();
        let (client, _server) = paired_sessions(sid);

        // Drive inflight far above any plausible initial cwnd, so the window
        // has no room for new data.
        client.on_packet_sent(100_000_000);
        let inflight_before = client.bandwidth_snapshot().inflight_bytes;

        let stream = Arc::new(TransportStream::new(1));
        stream.send_reliable(Bytes::from("new-data")).await.unwrap();
        let streams: Arc<DashMap<u32, Arc<TransportStream>>> = Arc::new(DashMap::new());
        streams.insert(1u32, stream);

        let (client_t, _server_t) = ChannelTransport::pair();
        let transport = Arc::new(client_t);
        let obs = Observability::new(ObservabilityConfig::default());

        drain_streams_priority_ordered(&transport, &client, sid, &streams, &obs).await;

        // No new segment was transmitted — inflight is unchanged (a send would
        // have grown it via on_packet_sent).
        assert_eq!(
            client.bandwidth_snapshot().inflight_bytes,
            inflight_before,
            "no new data should be sent when inflight >= cwnd"
        );
    }

    /// Feed the estimator a round trip's worth of delivery samples so it holds a
    /// real bottleneck bandwidth and a real minimum RTT: `packets × bytes`
    /// delivered over `rtt`. Returns with inflight back at zero.
    fn seed_bandwidth_estimate(
        session: &Arc<InnerSession>,
        packets: u64,
        bytes: u64,
        rtt: std::time::Duration,
    ) {
        use crate::transport::bandwidth_estimator::DeliverySample;
        let start = std::time::Instant::now();
        for _ in 0..packets {
            session.on_packet_sent(bytes);
        }
        for _ in 0..packets {
            session.on_packet_acked(DeliverySample {
                delivered_bytes: 0,
                delivered_at: start,
                sent_at: start,
                acked_at: start + rtt,
                packet_bytes: bytes,
                is_app_limited: false,
                ack_delay_us: 0,
                rtt_sampled: true,
            });
        }
    }

    /// **Pacing has to gate the wire, not just the window.** The congestion
    /// window is a volume, and releasing a volume all at once is a burst: the
    /// whole window leaves back to back and the sender then waits a round trip.
    /// BBR's design assumes that window is spread across the round trip at the
    /// pacing rate — without that, `cwnd` is a burst size and the estimator's
    /// pacing rate is a number nothing reads.
    ///
    /// The window here is opened to 240 KB, far past what one drain pass could
    /// want, so the only thing that can stop the pass short is the pacer.
    #[tokio::test]
    async fn the_drain_stops_on_the_pacer_instead_of_emptying_the_window() {
        const SEGMENT: usize = 1_200;

        let sid = fixed_session_id();
        let (client, _server) = paired_sessions(sid);

        // 100 × 1200 B delivered over a 200 ms round trip: 600 KB/s with a
        // 120 KB bandwidth-delay product, so the window opens to 240 KB.
        seed_bandwidth_estimate(&client, 100, 1_200, std::time::Duration::from_millis(200));
        let snap = client.bandwidth_snapshot();
        assert!(
            snap.cwnd_bytes > 200_000,
            "precondition: the window must be wide enough that only pacing can stop the \
             drain short (cwnd {} B)",
            snap.cwnd_bytes
        );
        assert_eq!(
            snap.inflight_bytes, 0,
            "precondition: every seeded packet was acknowledged"
        );

        // Offer twice the drain's own per-pass segment budget, so a pass that
        // stops short stopped for a reason of its own.
        let stream = Arc::new(TransportStream::new(1));
        for _ in 0..64 {
            stream
                .send_reliable(Bytes::from(vec![0xA5u8; SEGMENT]))
                .await
                .unwrap();
        }
        let streams: Arc<DashMap<u32, Arc<TransportStream>>> = Arc::new(DashMap::new());
        streams.insert(1u32, stream);

        let (client_t, _server_t) = ChannelTransport::pair();
        let transport = Arc::new(client_t);
        let obs = Observability::new(ObservabilityConfig::default());

        let began = std::time::Instant::now();
        let stop = drain_streams_priority_ordered(&transport, &client, sid, &streams, &obs).await;
        let took = began.elapsed();

        // Inflight counts payload bytes, so it is the segment count.
        let emitted = client.bandwidth_snapshot().inflight_bytes / SEGMENT as u64;
        assert!(
            emitted > 0,
            "the pass emitted nothing at all — pacing must meter the window out, not \
             withhold it"
        );
        assert!(
            emitted <= 20,
            "the pass put {emitted} segments on the wire in one go with a {} B/s pacing \
             rate — the window is being released as a burst",
            snap.pacing_rate_bps,
        );
        assert!(
            matches!(stop, DrainStop::Paced(_)),
            "the pass stopped for a reason other than pacing ({stop:?}) — with a 240 KB \
             window and 64 segments offered, nothing else should have been able to"
        );
        // And it must stop by *returning*, not by sleeping inside the pass: the
        // drain runs in a `select!` arm body, so a wait taken here parks the
        // whole pump — no flow-control limit, no commands, no heartbeat.
        assert!(
            took < std::time::Duration::from_millis(50),
            "the drain pass took {} ms — it waited for pacing credit inside the pass \
             instead of handing control back to the pump",
            took.as_millis(),
        );
    }

    /// **The bootstrap, at the drain.** A connection that has never had an
    /// acknowledgement has no bandwidth estimate, and a pacer metering against
    /// a rate derived from `btl_bw == 0` would admit two bytes a second — which
    /// on the first segment is indistinguishable from a deadlock, because the
    /// first segment is what produces the acknowledgement that would fix it.
    ///
    /// So a session with nothing measured must put its offered data on the
    /// wire, promptly, under the congestion window alone.
    #[tokio::test]
    async fn a_session_with_no_bandwidth_estimate_still_sends() {
        let sid = fixed_session_id();
        let (client, _server) = paired_sessions(sid);

        let snap = client.bandwidth_snapshot();
        assert_eq!(
            snap.bottleneck_bw_bps, 0,
            "precondition: a fresh session has measured no bandwidth"
        );
        assert!(
            !client.pacer().is_enabled(),
            "pacing must stay off until something has been measured"
        );

        let stream = Arc::new(TransportStream::new(1));
        for _ in 0..4 {
            stream
                .send_reliable(Bytes::from_static(b"first-flight"))
                .await
                .unwrap();
        }
        let streams: Arc<DashMap<u32, Arc<TransportStream>>> = Arc::new(DashMap::new());
        streams.insert(1u32, stream);

        let (client_t, _server_t) = ChannelTransport::pair();
        let transport = Arc::new(client_t);
        let obs = Observability::new(ObservabilityConfig::default());

        let began = std::time::Instant::now();
        let stop = drain_streams_priority_ordered(&transport, &client, sid, &streams, &obs).await;
        let took = began.elapsed();

        assert!(
            client.bandwidth_snapshot().inflight_bytes > 0,
            "the first flight never left: a session with no bandwidth estimate paced \
             itself to a stop"
        );
        assert_eq!(
            stop,
            DrainStop::Drained,
            "the pass stopped on {stop:?} with no estimate to pace against"
        );
        assert!(
            took < std::time::Duration::from_millis(50),
            "the first flight took {} ms to leave",
            took.as_millis()
        );
    }

    // ── The app-limited signal ──────────────────────────────────────────

    /// Segment size for the estimator rounds driven below.
    const APP_LIMITED_SEG: u64 = 1_200;

    /// One round trip of a bulk flight through a bandwidth estimator.
    ///
    /// The loss the previous round suffered is reported at the top, which is
    /// where the live drain resends it and therefore where it reports it; that
    /// one round of lag is what puts the judgement on the round the loss belongs
    /// to. `app_limited` is whatever the drain's stopping reason produced for
    /// this round.
    fn bbr_round(
        est: &mut crate::transport::bandwidth_estimator::BandwidthEstimator,
        t0: std::time::Instant,
        rtt: std::time::Duration,
        packets: u64,
        carry_lost: u64,
        app_limited: bool,
    ) {
        use crate::transport::bandwidth_estimator::DeliverySample;
        if carry_lost > 0 {
            est.on_retransmit(carry_lost * APP_LIMITED_SEG);
            est.on_loss(carry_lost * APP_LIMITED_SEG);
        }
        for _ in 0..packets {
            est.on_send(APP_LIMITED_SEG);
        }
        let mark = est.delivered_bytes();
        let mark_time = est.delivered_time();
        for _ in 0..packets {
            est.on_ack(DeliverySample {
                delivered_bytes: mark,
                delivered_at: mark_time,
                sent_at: t0,
                acked_at: t0 + rtt,
                packet_bytes: APP_LIMITED_SEG,
                is_app_limited: app_limited,
                ack_delay_us: 0,
                rtt_sampled: true,
            });
        }
    }

    /// **A round the application starved is not evidence about the path.**
    ///
    /// `adapt_inflight_bound` skips app-limited rounds precisely because such a
    /// round's loss *rate* has a denominator it did not earn: one retransmit
    /// against a nearly idle round reads as heavy congestion and clamps
    /// `inflight_hi` for a path that was never asked to carry anything. The
    /// guard is only worth having if something ever sets the flag, and nothing
    /// did — every `DeliverySample` the pump built said `is_app_limited: false`.
    ///
    /// The flag is taken here from the real drain rather than asserted into
    /// existence: a pass over a stream with nothing buffered, with the
    /// congestion window wide open, is the definition of application-limited,
    /// and the boolean that pass produces is the one fed to the estimator below.
    #[tokio::test]
    async fn a_drain_that_ran_dry_marks_the_round_app_limited_and_spares_the_bound() {
        const RTT: std::time::Duration = std::time::Duration::from_millis(100);

        let sid = fixed_session_id();
        let (client, _server) = paired_sessions(sid);

        // A wide window, and a registered stream with nothing in it.
        seed_bandwidth_estimate(&client, 100, 1_200, RTT);
        let stream = Arc::new(TransportStream::new(1));
        let streams: Arc<DashMap<u32, Arc<TransportStream>>> = Arc::new(DashMap::new());
        streams.insert(1u32, stream);

        let snap = client.bandwidth_snapshot();
        assert!(
            snap.inflight_bytes < snap.cwnd_bytes,
            "precondition: the congestion window must have room ({} B in flight against \
             a {} B window), or the round is congestion-limited and not app-limited",
            snap.inflight_bytes,
            snap.cwnd_bytes
        );

        let (client_t, _server_t) = ChannelTransport::pair();
        let transport = Arc::new(client_t);
        let obs = Observability::new(ObservabilityConfig::default());
        let stop = drain_streams_priority_ordered(&transport, &client, sid, &streams, &obs).await;
        apply_drain_outcome(&client, stop, false);

        assert!(
            client.bandwidth_snapshot().app_limited,
            "a drain pass that ran dry with the window open ({stop:?}) left the \
             connection un-marked — the controller cannot tell an idle sender from a \
             saturated one"
        );

        // ...and the flag has to reach the loss response. A round that lost 5%
        // of a small flight is over the 2% threshold on paper; app-limited, it
        // is not a measurement of the path and must not clamp the bound.
        let mut est = crate::transport::bandwidth_estimator::BandwidthEstimator::new();
        let mut t = std::time::Instant::now();
        for _ in 0..6 {
            bbr_round(&mut est, t, RTT, 200, 0, false);
            t += RTT;
        }
        assert_eq!(
            est.inflight_hi(),
            None,
            "precondition: a clean warm-up must leave no bound in place"
        );

        let app_limited = client.bandwidth_snapshot().app_limited;
        for _ in 0..4 {
            bbr_round(&mut est, t, RTT, 200, 10, app_limited);
            t += RTT;
        }
        assert_eq!(
            est.inflight_hi(),
            None,
            "a 5% loss rate over rounds the application starved clamped inflight_hi to \
             {:?} — the round's denominator is the sender's own idleness, not the path's \
             capacity",
            est.inflight_hi()
        );
    }

    /// **The other side, and the one that stops the fix above from being "mark
    /// everything app-limited".**
    ///
    /// A pass stopped by the congestion window or by the pacer is the controller
    /// throttling *itself* — on purpose, because it decided that is how much may
    /// be outstanding and how fast it may leave. Those are exactly the rounds a
    /// loss response is meant to judge, and marking them app-limited would
    /// disable it in the only regime where it matters.
    /// **A dry pass says which of two states it found, where `poll_send` says only
    /// one.**
    ///
    /// `Stream::poll_send` reaches its final `Idle` whenever no segment is unsent.
    /// A stream holding nothing satisfies that; so does a stream whose every
    /// segment is on the wire with the ARQ buffer at its bound, and in the second
    /// case the application is not idle at all — it is parked against a ceiling
    /// this endpoint chose. Both open an application-limited phase, which
    /// disables the loss response, the Startup exit judgement and the bandwidth
    /// filter's right to a new maximum.
    ///
    /// The 2026-08-25 frame sweep measured the consequence: at a 256-byte frame,
    /// where the ARQ buffer is the lower of the two byte ceilings, the flag stood
    /// in 68.6% and 100% of steady-state samples with `inflight` pinned exactly at
    /// `1024 × 260`. At 2308 bytes, where the peer's window binds first, it stood
    /// in 0.0%.
    ///
    /// Nothing here changes what the sender does — the phase opens for both, as
    /// before. What it changes is that a run can now say which it saw.
    #[tokio::test]
    async fn a_dry_pass_records_whether_the_send_buffer_was_full() {
        // One byte per segment. The ARQ buffer is bounded in *segments* and the
        // congestion window in *bytes*, so a thousand tiny writes fill the buffer
        // while leaving the opening window — 5600 B, four minimum packets — able
        // to carry every one of them onto the wire. At a realistic segment size
        // the pass would stop on the window long before the buffer filled, and
        // this test would be measuring the window instead.
        const SEGMENT: usize = 1;
        let sid = fixed_session_id();
        let obs = Observability::new(ObservabilityConfig::default());

        // Genuinely dry: a stream with nothing in it at all.
        let (idle, _s1) = paired_sessions(sid);
        let streams: Arc<DashMap<u32, Arc<TransportStream>>> = Arc::new(DashMap::new());
        streams.insert(1u32, Arc::new(TransportStream::new(1)));
        let (t1, _r1) = ChannelTransport::pair();
        let stop = drain_streams_priority_ordered(&Arc::new(t1), &idle, sid, &streams, &obs).await;
        assert_eq!(stop, DrainStop::Drained, "precondition: nothing buffered");
        let snap = idle.bandwidth_snapshot();
        assert_eq!(snap.drain_outcomes[0], 1, "the pass is counted as drained");
        assert_eq!(
            snap.dry_passes_against_a_full_buffer, 0,
            "an empty stream is the application's limit and must not be filed \
             under this endpoint's ceiling"
        );

        // Dry against a full buffer: fill the ARQ buffer to its bound, put every
        // segment on the wire, then drain again. `poll_send` answers `Idle` for
        // the same reason it did above, and the application is provably unable to
        // add more.
        let (full, _s2) = paired_sessions(sid);
        let stream = Arc::new(TransportStream::new(1));
        // A peer window large enough that the ARQ buffer is the binding ceiling —
        // at the default frame the peer's 1 MiB binds four segments sooner, and
        // then the pass answers FlowControl instead and this case does not arise.
        stream.apply_peer_window_limit(u64::MAX / 2);
        let mut queued = 0usize;
        while stream
            .try_send_reliable(&Bytes::from(vec![0x11u8; SEGMENT]))
            .await
            .unwrap_or(false)
        {
            queued += 1;
        }
        assert!(
            queued > 0
                && !stream
                    .try_send_reliable(&Bytes::new())
                    .await
                    .unwrap_or(false),
            "precondition: the buffer must be full and refusing the application"
        );
        let streams2: Arc<DashMap<u32, Arc<TransportStream>>> = Arc::new(DashMap::new());
        streams2.insert(1u32, stream);
        let (t2, r2) = ChannelTransport::pair();
        // Drain the far end. The pair's channels hold 64 frames, and this half of
        // the test puts a thousand on the wire — without a reader the send blocks
        // and the drain never reaches the state under test.
        tokio::spawn(async move { while r2.recv_bytes().await.is_ok() {} });
        let transport2 = Arc::new(t2);
        // Drain until everything queued is on the wire; the pass that follows has
        // nothing unsent and no room for more.
        for _ in 0..64 {
            if drain_streams_priority_ordered(&transport2, &full, sid, &streams2, &obs).await
                == DrainStop::Drained
            {
                break;
            }
        }
        let snap2 = full.bandwidth_snapshot();
        assert!(
            snap2.drain_outcomes[0] >= 1,
            "precondition: a pass must have come up dry, got census {:?}",
            snap2.drain_outcomes
        );
        assert!(
            snap2.dry_passes_against_a_full_buffer >= 1,
            "a pass that came up dry against a full send buffer must be recorded \
             as such — it is the state the application is waiting on us for, and \
             it is indistinguishable from an idle application everywhere else"
        );

        // Dry with the peer's window closed. `poll_send` answers `FlowControl`
        // only when it has an unsent segment for the peer to refuse; with nothing
        // unsent it answers the same `Idle` an empty stream gives, however closed
        // the window is. Which of the two a pass reports therefore turns on
        // whether the peer's SACK or its WINDOW_UPDATE arrived first — and only
        // one of the two opens a phase that disables the loss response.
        // The peer's limit is cumulative and only ever grows, so a shut window is
        // reached by spending it rather than by setting it: exactly
        // `INITIAL_STREAM_WINDOW` bytes go out and the grant is used up. The
        // congestion window has to be raised first or the pass stops on cwnd long
        // before the peer's window is spent, and the test would be measuring the
        // wrong ceiling.
        let (shut, _s3) = paired_sessions(sid);
        seed_bandwidth_estimate(&shut, 200, 8_192, std::time::Duration::from_millis(10));
        let closed = Arc::new(TransportStream::new(1));
        let grant = crate::transport::stream::INITIAL_STREAM_WINDOW as usize;
        let chunk = grant / 64;
        for _ in 0..64 {
            closed
                .send_reliable(Bytes::from(vec![0x22u8; chunk]))
                .await
                .expect("queued");
        }
        let streams3: Arc<DashMap<u32, Arc<TransportStream>>> = Arc::new(DashMap::new());
        streams3.insert(1u32, closed.clone());
        let (t3, r3) = ChannelTransport::pair();
        tokio::spawn(async move { while r3.recv_bytes().await.is_ok() {} });
        let transport3 = Arc::new(t3);
        let mut stop3 = DrainStop::SegmentBudget;
        for _ in 0..64 {
            stop3 = drain_streams_priority_ordered(&transport3, &shut, sid, &streams3, &obs).await;
            if closed.peer_send_window() == 0 && stop3 == DrainStop::Drained {
                break;
            }
        }
        assert_eq!(
            closed.peer_send_window(),
            0,
            "precondition: the peer's whole grant must be spent, or the window is \
             not the state under test"
        );
        assert_eq!(
            stop3,
            DrainStop::Drained,
            "the pass has nothing unsent, so it reports Idle and not FlowControl \
             even though the peer's window is shut — which is the conflation"
        );
        let snap3 = shut.bandwidth_snapshot();
        assert_eq!(
            snap3.dry_passes_with_no_peer_window, 1,
            "a dry pass that met a shut peer window must be recorded, or the \
             record cannot say how often an application-limited phase opened on a \
             state the peer chose"
        );
        assert_eq!(
            snap3.dry_passes_against_a_full_buffer, 0,
            "and it must not be filed under the send buffer, which was empty"
        );
    }

    /// **The census records what stopped each pass, where an inference could not.**
    ///
    /// Every reading of "what stopped the sender" in the harness was drawn
    /// afterwards from the window and the bytes outstanding, and that inference
    /// is blind in exactly one place: a pass the pacer metered and a pass that
    /// ran dry with the window open leave the same window behind them. Those two
    /// are the pair the application-limited flag turns on, so telling them apart
    /// decides whether a run's rate describes the path or the application.
    ///
    /// The two halves here are that pair, and the census separates them.
    #[tokio::test]
    async fn the_reason_a_pass_ended_is_counted_where_the_pass_ended() {
        const SEGMENT: usize = 1_200;
        let sid = fixed_session_id();

        // A stream with nothing to give: the pass runs dry.
        let (dry, _server) = paired_sessions(sid);
        let streams: Arc<DashMap<u32, Arc<TransportStream>>> = Arc::new(DashMap::new());
        streams.insert(1u32, Arc::new(TransportStream::new(1)));
        let (client_t, _server_t) = ChannelTransport::pair();
        let transport = Arc::new(client_t);
        let obs = Observability::new(ObservabilityConfig::default());
        let stop = drain_streams_priority_ordered(&transport, &dry, sid, &streams, &obs).await;
        assert_eq!(stop, DrainStop::Drained, "precondition: nothing to send");

        let census = dry.bandwidth_snapshot().drain_outcomes;
        assert_eq!(
            census[0], 1,
            "a pass that ran dry must be counted as drained, not inferred later \
             from a window it left untouched"
        );
        assert_eq!(
            census[5], 0,
            "and it must not be counted as paced — that confusion is what the \
             census exists to end"
        );

        // A stream with plenty to give, against a rate the pacer will not grant:
        // the pass stops on the rate, and from outside it leaves the same open
        // window the dry pass did.
        let (paced, _server2) = paired_sessions(sid);
        seed_bandwidth_estimate(&paced, 100, 1_200, std::time::Duration::from_millis(200));
        let stream = Arc::new(TransportStream::new(1));
        for _ in 0..32 {
            stream
                .send_reliable(Bytes::from(vec![0x5Au8; SEGMENT]))
                .await
                .unwrap();
        }
        let streams2: Arc<DashMap<u32, Arc<TransportStream>>> = Arc::new(DashMap::new());
        streams2.insert(1u32, stream);
        let (client_t2, _server_t2) = ChannelTransport::pair();
        let transport2 = Arc::new(client_t2);
        let stop2 = drain_streams_priority_ordered(&transport2, &paced, sid, &streams2, &obs).await;
        assert!(
            matches!(stop2, DrainStop::Paced(_)),
            "precondition: the pacer must be what stopped this pass, got {stop2:?}"
        );

        let census2 = paced.bandwidth_snapshot().drain_outcomes;
        assert_eq!(
            census2[5], 1,
            "a pass the pacer stopped is counted as paced"
        );
        assert_eq!(
            census2[0], 0,
            "and not as drained — the stream had thirty-two segments waiting"
        );
    }

    #[tokio::test]
    async fn a_drain_stopped_by_the_congestion_window_or_the_pacer_is_not_app_limited() {
        const SEGMENT: usize = 1_200;
        const RTT: std::time::Duration = std::time::Duration::from_millis(100);

        // ── Stopped by the congestion window ────────────────────────────
        let sid = fixed_session_id();
        let (client, _server) = paired_sessions(sid);
        // No estimate at all, so the window is its 5600 B floor and four
        // segments fill it. Pacing stays off until something is measured.
        let stream = Arc::new(TransportStream::new(1));
        for _ in 0..32 {
            stream
                .send_reliable(Bytes::from(vec![0x5Au8; SEGMENT]))
                .await
                .unwrap();
        }
        let streams: Arc<DashMap<u32, Arc<TransportStream>>> = Arc::new(DashMap::new());
        streams.insert(1u32, stream);

        let (client_t, _server_t) = ChannelTransport::pair();
        let transport = Arc::new(client_t);
        let obs = Observability::new(ObservabilityConfig::default());
        let stop = drain_streams_priority_ordered(&transport, &client, sid, &streams, &obs).await;
        apply_drain_outcome(&client, stop, false);

        let snap = client.bandwidth_snapshot();
        assert!(
            snap.inflight_bytes + SEGMENT as u64 > snap.cwnd_bytes,
            "precondition: the pass should have filled the {} B window ({} B in flight)",
            snap.cwnd_bytes,
            snap.inflight_bytes
        );
        assert!(
            !snap.app_limited,
            "a pass stopped by the congestion window ({stop:?}) was marked app-limited — \
             the sender had 32 segments queued and the controller's own window is what \
             held them back"
        );

        // ── Stopped by the pacer ────────────────────────────────────────
        let (paced, _server2) = paired_sessions(sid);
        seed_bandwidth_estimate(&paced, 100, 1_200, std::time::Duration::from_millis(200));
        let stream2 = Arc::new(TransportStream::new(1));
        for _ in 0..64 {
            stream2
                .send_reliable(Bytes::from(vec![0xA5u8; SEGMENT]))
                .await
                .unwrap();
        }
        let streams2: Arc<DashMap<u32, Arc<TransportStream>>> = Arc::new(DashMap::new());
        streams2.insert(1u32, stream2);
        let (client_t2, _server_t2) = ChannelTransport::pair();
        let transport2 = Arc::new(client_t2);
        let stop2 = drain_streams_priority_ordered(&transport2, &paced, sid, &streams2, &obs).await;
        apply_drain_outcome(&paced, stop2, false);
        assert!(
            matches!(stop2, DrainStop::Paced(_)),
            "precondition: a 240 KB window and 64 segments offered should leave pacing \
             as the only thing able to stop the pass ({stop2:?})"
        );
        assert!(
            !paced.bandwidth_snapshot().app_limited,
            "a pass stopped for want of pacing credit was marked app-limited — the rate \
             limiter is the controller metering itself, and in steady state it is what \
             stops nearly every pass"
        );

        // ...and a genuinely congested round must still cost the sender its
        // bound. A response that never fires is not a conservative response.
        let mut est = crate::transport::bandwidth_estimator::BandwidthEstimator::new();
        let mut t = std::time::Instant::now();
        for _ in 0..6 {
            bbr_round(&mut est, t, RTT, 200, 0, false);
            t += RTT;
        }
        let target = est.cwnd();
        assert_eq!(
            est.inflight_hi(),
            None,
            "precondition: a clean warm-up must leave no bound in place"
        );

        let congested = client.bandwidth_snapshot().app_limited;
        bbr_round(&mut est, t, RTT, 200, 10, congested);
        let bound = est
            .inflight_hi()
            .expect("a 5% loss rate over a saturated round must set a bound");
        assert!(
            bound < target,
            "the bound came out at {bound} B against a {target} B window — a 5% loss \
             rate did not cost the sender anything"
        );
    }

    /// **Only congestion-controlled bytes may be counted as outstanding.**
    ///
    /// An unreliable datagram is fire-and-forget: it carries no reliable offset,
    /// no acknowledgement ever names it, and nothing on the receive path will
    /// ever retire it. Booking it into `inflight_bytes` therefore adds a debt no
    /// arrival can ever pay, and every consumer of that figure is a consumer of a
    /// number that only rises.
    ///
    /// The consequences are not abstract. `budget = cwnd - inflight` is what the
    /// drain offers the next segment, so a session that has sent its window's
    /// worth of unreliable data can never send reliable data again. And
    /// ProbeRTT's whole premise is "wait until the pipe is empty, then time it":
    /// its drain condition is `inflight <= 4 × MIN_PACKET_SIZE`, which a session
    /// carrying a permanent unreliable debt above that figure can never satisfy,
    /// so every ProbeRTT would run to its ceiling and take no sample at all.
    #[tokio::test]
    async fn unreliable_sends_are_not_booked_as_congestion_controlled_inflight() {
        const SEGMENT: usize = 1_200;
        /// Comfortably past the ProbeRTT drain floor (4 × 1400 B), so a leak
        /// here is a leak that would defeat the drain condition outright.
        const DATAGRAMS: usize = 20;

        let sid = fixed_session_id();
        let (client, _server) = paired_sessions(sid);
        seed_bandwidth_estimate(&client, 100, 1_200, std::time::Duration::from_millis(100));

        let stream = Arc::new(TransportStream::new(1));
        for _ in 0..DATAGRAMS {
            stream
                .send_unreliable(Bytes::from(vec![0x3Cu8; SEGMENT]))
                .await;
        }
        let streams: Arc<DashMap<u32, Arc<TransportStream>>> = Arc::new(DashMap::new());
        streams.insert(1u32, stream);

        let before = client.bandwidth_snapshot().inflight_bytes;
        let (client_t, _server_t) = ChannelTransport::pair();
        let transport = Arc::new(client_t);
        let obs = Observability::new(ObservabilityConfig::default());
        drain_streams_priority_ordered(&transport, &client, sid, &streams, &obs).await;

        let after = client.bandwidth_snapshot().inflight_bytes;
        assert_eq!(
            after,
            before,
            "{DATAGRAMS} unreliable datagrams left {} B of extra outstanding bytes \
             behind them; nothing acknowledges an unreliable datagram, so that debt is \
             permanent — it shrinks the congestion budget for the reliable data that \
             follows and puts ProbeRTT's drain condition permanently out of reach",
            after - before
        );
    }

    /// **A peer must not be able to reach the local congestion controller.**
    ///
    /// The application-limited flag gates three of its decisions: whether a
    /// delivery-rate sample may set the bandwidth maximum, whether the round's
    /// loss rate is judged at all (`adapt_inflight_bound` returns early), and
    /// whether Startup may be concluded (`check_startup_full_bandwidth` returns
    /// early — and a sender held in Startup never runs ProbeRTT). A pass stopped
    /// by the peer's advertised receive window is decided entirely by a number
    /// the peer chose, so routing it into that flag would hand the peer a switch
    /// over all three, for the life of the connection, by the simple expedient of
    /// never opening its window.
    ///
    /// It is also wrong on its own terms. A sender blocked on the peer's window
    /// has a full send queue; it is short of nothing. Linux's
    /// `tcp_rate_check_app_limited` — the rule this classification otherwise
    /// follows — requires "less than one packet to send" before it will mark, and
    /// a receive-window-blocked sender fails that test.
    #[tokio::test]
    async fn a_peer_that_closes_its_window_cannot_mark_the_sender_app_limited() {
        const SEGMENT: usize = 60;

        let sid = fixed_session_id();
        let (client, _server) = paired_sessions(sid);
        // A wide congestion window, so nothing but the peer's window can bind.
        seed_bandwidth_estimate(&client, 100, 1_200, std::time::Duration::from_millis(100));

        let stream = Arc::new(TransportStream::new(1));
        // Leave the peer's advertised window too small for the segments queued
        // behind it, exactly as a peer that stops reading would.
        assert!(
            stream.try_consume_send_window(crate::transport::stream::INITIAL_STREAM_WINDOW - 50)
        );
        for _ in 0..4 {
            stream
                .send_reliable(Bytes::from(vec![0x11u8; SEGMENT]))
                .await
                .unwrap();
        }
        let streams: Arc<DashMap<u32, Arc<TransportStream>>> = Arc::new(DashMap::new());
        streams.insert(1u32, stream);

        let (client_t, _server_t) = ChannelTransport::pair();
        let transport = Arc::new(client_t);
        let obs = Observability::new(ObservabilityConfig::default());
        let stop = drain_streams_priority_ordered(&transport, &client, sid, &streams, &obs).await;
        apply_drain_outcome(&client, stop, false);

        assert_eq!(
            stop,
            DrainStop::FlowControlled,
            "precondition: the pass must have stopped on the peer's window"
        );
        let snap = client.bandwidth_snapshot();
        assert!(
            snap.inflight_bytes < snap.cwnd_bytes,
            "precondition: the congestion window must still have room ({} B in flight \
             against {} B), or the assertion below would pass for the wrong reason",
            snap.inflight_bytes,
            snap.cwnd_bytes
        );
        assert!(
            !snap.app_limited,
            "a pass stopped by the peer's advertised receive window marked the sender \
             application-limited — that is a local congestion-control decision taken \
             on a remote party's number"
        );
    }

    /// A transport that refuses every write, the way a datagram socket does
    /// under `ENOBUFS` or `EAGAIN`. Receives nothing, because nothing in the
    /// test below reads.
    struct RefusingTransport;

    impl SessionTransport for RefusingTransport {
        async fn send_bytes(&self, _data: &[u8]) -> Result<(), CoreError> {
            Err(CoreError::NetworkError("send buffer full".into()))
        }

        async fn recv_bytes(&self) -> Result<Bytes, CoreError> {
            std::future::pending().await
        }
    }

    /// **A write the transport refused is not the application running dry.**
    ///
    /// The two look identical from inside the drain loop — a pass ends early
    /// with the congestion window still open — and they ask for opposite
    /// responses. "Ran dry" is the app-limited signal, which switches the loss
    /// response and the Startup judgement off for the flight that follows. A
    /// local send buffer that just refused a write is the one moment when the
    /// local send path is most congested, and telling the controller the
    /// application had nothing to give is precisely backwards.
    #[tokio::test]
    async fn a_write_the_transport_refused_is_not_an_application_that_ran_dry() {
        const SEGMENT: usize = 1_200;

        let sid = fixed_session_id();
        let (client, _server) = paired_sessions(sid);
        seed_bandwidth_estimate(&client, 100, 1_200, std::time::Duration::from_millis(100));

        let stream = Arc::new(TransportStream::new(1));
        for _ in 0..8 {
            stream
                .send_reliable(Bytes::from(vec![0x77u8; SEGMENT]))
                .await
                .unwrap();
        }
        let streams: Arc<DashMap<u32, Arc<TransportStream>>> = Arc::new(DashMap::new());
        streams.insert(1u32, stream);

        let transport = Arc::new(RefusingTransport);
        let obs = Observability::new(ObservabilityConfig::default());
        let stop = drain_streams_priority_ordered(&transport, &client, sid, &streams, &obs).await;
        apply_drain_outcome(&client, stop, false);

        let snap = client.bandwidth_snapshot();
        assert!(
            snap.inflight_bytes < snap.cwnd_bytes,
            "precondition: nothing reached the wire, so the window must still have \
             room ({} B in flight against {} B) — otherwise the assertion below would \
             pass for the wrong reason",
            snap.inflight_bytes,
            snap.cwnd_bytes
        );
        assert!(
            !snap.app_limited,
            "a pass in which every write was refused by the transport ({stop:?}) marked \
             the connection application-limited — the sender had eight segments queued \
             and the local send path is what would not take them"
        );
    }

    // ────────────────────────────────────────────────────────────────────
    // V2 wire-routing tests (Phase 4.2 / 2.5 follow-up — data-pump V2)
    // ────────────────────────────────────────────────────────────────────

    use crate::transport::multiplexer::StreamDemultiplexer;
    use crate::transport::session::Session as InnerSession;
    use crate::transport::stream::Stream as TransportStream;

    /// Build two `InnerSession` instances that share a 32-byte secret —
    /// one as the "client" (peer_side=false), one as the "server"
    /// (peer_side=true). Mirrors the role split after a real handshake.
    fn paired_sessions(session_id: SessionId) -> (Arc<InnerSession>, Arc<InnerSession>) {
        let secret = [0x11u8; 32];
        let client = Arc::new(InnerSession::new(session_id, &secret, false).unwrap());
        let server = Arc::new(InnerSession::new(session_id, &secret, true).unwrap());
        (client, server)
    }

    fn fixed_session_id() -> SessionId {
        SessionId::from_bytes([0x88; 32])
    }

    /// Encrypt a V2 application-data packet from the client side at
    /// `stream_id` / `sequence`. The returned bytes are wire-serialised
    /// ([`PhantomPacket::to_wire`]) and ready to feed into `handle_packet`.
    /// Build a RELIABLE app frame whose `stream_offset` equals its `sequence` (the
    /// no-control-gap case, which holds for almost every test).
    fn build_app_frame(
        client_session: &InnerSession,
        session_id: SessionId,
        stream_id: TransportStreamId,
        sequence: u32,
        payload: &[u8],
    ) -> Vec<u8> {
        build_app_frame_with_offset(
            client_session,
            session_id,
            stream_id,
            sequence,
            sequence,
            payload,
        )
    }

    /// Build a RELIABLE app frame with an explicit gap-free `stream_offset`
    /// distinct from the wire `sequence` (A.5). The plaintext is
    /// `[stream_offset: u32 BE][payload]`, matching the live sender's reliable
    /// framing; the receiver reassembles by `stream_offset`.
    fn build_app_frame_with_offset(
        client_session: &InnerSession,
        session_id: SessionId,
        stream_id: TransportStreamId,
        sequence: u32,
        stream_offset: u32,
        payload: &[u8],
    ) -> Vec<u8> {
        let flag_bits = PacketFlags::RELIABLE | PacketFlags::ENCRYPTED;
        let header = PacketHeader::new(
            session_id,
            stream_id,
            sequence as u64,
            PacketFlags::new(flag_bits),
        )
        .with_epoch(client_session.current_epoch());
        let mut pt = Vec::with_capacity(4 + payload.len());
        pt.extend_from_slice(&stream_offset.to_be_bytes());
        pt.extend_from_slice(payload);
        let ciphertext = client_session
            .encrypt_packet(&header, &pt, &[])
            .expect("encrypt_packet");
        // Cleartext wire: this frame is decoded back to a struct and fed to
        // handle_packet directly (it never traverses the pump's transport, which
        // is the only path that applies/removes header protection).
        PhantomPacket::new(header, ciphertext).to_wire()
    }

    /// Decode a test-built frame the way the recv pump's `parse_protected` does:
    /// `from_wire` + reconstruct the off-wire `session_id` from session context
    /// (ε / WIRE v5). The `build_*` helpers emit cleartext `to_wire` (header
    /// protection is exercised separately), so the inner `session_id` is the
    /// placeholder zero until this sets it — mirroring production, where
    /// `parse_protected` reconstructs it before `handle_packet` ever sees the
    /// packet.
    fn decode_recv_frame(frame: &[u8], session_id: SessionId) -> PhantomPacket {
        let mut packet = PhantomPacket::from_wire(frame).expect("decode test recv frame");
        packet.header.session_id = session_id;
        packet
    }

    /// One connection, one receive-window growth budget.
    ///
    /// `SESSION_RECV_WINDOW_GROWTH_BUDGET` bounds a session's receive-side memory only if
    /// every stream of that session actually draws on the same handle; a stream built with
    /// a budget of its own is a second, unbounded allowance for as long as it lives, and
    /// nothing about the arithmetic would show it. Two paths create streams outside
    /// `open_stream()` — the pump's own raw stream and the peer-initiated branch of
    /// `handle_packet` — and this pins both of them to the handle the `PhantomSession`
    /// holds, including for a stream opened before the handshake had a chance to finish.
    #[tokio::test]
    async fn every_stream_of_one_connection_draws_on_one_growth_budget() {
        let (client_transport, server_transport) = ChannelTransport::pair();
        let server_hs = HandshakeServer::new().unwrap();
        let server_pinned_key = server_hs.verifying_key().clone();

        let session = PhantomSession::connect_with_transport(
            "test-server:9007",
            client_transport,
            server_pinned_key,
        );

        // Before the handshake has any chance to complete: the ordering that makes the
        // budget's owner the API layer rather than the negotiated session.
        let _early = session.open_stream().expect("open a stream");

        let server_handle = tokio::spawn(async move {
            let client_ip = "127.0.0.1".parse().unwrap();
            let hello_bytes = server_transport.recv_bytes().await.unwrap();
            let hello = borsh::from_slice::<ClientHello>(&hello_bytes).unwrap();
            let mut response = server_hs.process_client_hello(&hello, 0, client_ip);
            if let HandshakeResponse::Retry(retry) = response {
                let retry_bytes = ServerReply::Retry(retry).to_wire().unwrap();
                server_transport.send_bytes(&retry_bytes).await.unwrap();
                let next_bytes = server_transport.recv_bytes().await.unwrap();
                let next_hello = borsh::from_slice::<ClientHello>(&next_bytes).unwrap();
                response = server_hs.process_client_hello(&next_hello, 0, client_ip);
            }
            match response {
                HandshakeResponse::Success(server_hello, _s, _) => {
                    let bytes = ServerReply::Hello(server_hello).to_wire().unwrap();
                    server_transport.send_bytes(&bytes).await.unwrap();
                    // Hold the pipe open past the assertions below: an EOF here would
                    // close the session and the stream table with it.
                    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
                }
                other => panic!("handshake did not succeed: {other:?}"),
            }
        });

        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
        assert_eq!(session.connection_state(), ConnectionState::Connected);
        let _late = session.open_stream().expect("open a stream");

        // The pump inserted its own raw stream (id 1) alongside the two opened here, so
        // this covers all three creation sites the API layer owns.
        assert!(
            session.streams.len() >= 3,
            "expected the pump's raw stream plus both opened streams, found {}",
            session.streams.len()
        );
        for entry in session.streams.iter() {
            assert!(
                Arc::ptr_eq(entry.value().recv_tuning(), &session.recv_tuning),
                "stream {} draws on a growth budget of its own — the session-wide bound \
                 does not hold for it",
                entry.key()
            );
        }

        server_handle.await.unwrap();
        session.disconnect().await.unwrap();
    }

    /// The peer-initiated branch of the same invariant: a stream this side never asked for
    /// must land on the connection's budget too, or a peer could open `MAX_STREAMS` of them
    /// and each would arrive with a fresh allowance.
    #[tokio::test]
    async fn a_peer_initiated_stream_draws_on_the_connection_growth_budget() {
        let session_id = fixed_session_id();
        let (client_session, server_session) = paired_sessions(session_id);

        // Stream 3 is a client-allocated user stream this side has never seen, so
        // `handle_packet` takes the create-on-receive branch.
        let frame = build_app_frame(&client_session, session_id, 3, 0, b"peer-opened");
        let v2 = decode_recv_frame(&frame, session_id);

        let (demux, _ctrl_rx) = StreamDemultiplexer::new(16);
        let demux = Arc::new(demux);
        let streams: Arc<DashMap<u32, Arc<TransportStream>>> = Arc::new(DashMap::new());
        let (deliver_tx, _deliver_rx) = mpsc::unbounded_channel::<DeliverItem>();
        let undelivered = AtomicU64::new(0);
        let (ack_a, ack_b) = mpsc::channel::<Vec<u8>>(4);
        let transport_send: Arc<ChannelTransport> = Arc::new(ChannelTransport {
            tx: ack_a,
            rx: Mutex::new(ack_b),
        });
        let obs = Observability::new(ObservabilityConfig::default());

        let connection_budget = Arc::new(SharedRecvTuning::default());
        let mut scratch = RecvScratch::new(
            256,
            StreamGauge::new(obs.clone()),
            Arc::new(PathChallenges::default()),
            connection_budget.clone(),
        );
        let link = detached_stream_link();
        let (inc_tx, _inc_rx) = mpsc::channel(4);
        handle_packet(
            v2,
            session_id,
            &server_session,
            &streams,
            &demux,
            &transport_send,
            &transport_send,
            &deliver_tx,
            &undelivered,
            &mut scratch,
            &obs,
            LegType::Tcp,
            &link,
            &inc_tx,
            &connected_state(),
        )
        .await;

        let created = streams
            .get(&3)
            .expect("the packet must have opened stream 3");
        assert!(
            Arc::ptr_eq(created.value().recv_tuning(), &connection_budget),
            "a peer-initiated stream was built with a growth budget of its own"
        );
    }

    #[tokio::test]
    async fn v2_recv_routes_encrypted_app_data_through_recv_channel() {
        let session_id = fixed_session_id();
        let (client_session, server_session) = paired_sessions(session_id);

        // Encrypt a V2 application-data packet on the client side.
        let stream_id: TransportStreamId = 1;
        let frame = build_app_frame(&client_session, session_id, stream_id, 0, b"hello-v2");

        // Receive on the server side: decode (reconstructing the off-wire
        // session_id, as parse_protected does) then drive handle_packet.
        let v2 = decode_recv_frame(&frame, session_id);

        let (demux, _ctrl_rx) = StreamDemultiplexer::new(16);
        let demux = Arc::new(demux);
        let streams: Arc<DashMap<u32, Arc<TransportStream>>> = Arc::new(DashMap::new());
        let (deliver_tx, mut deliver_rx) = mpsc::unbounded_channel::<DeliverItem>();
        let undelivered = AtomicU64::new(0);
        let (ack_a, ack_b) = mpsc::channel::<Vec<u8>>(4);
        let transport_send: Arc<ChannelTransport> = Arc::new(ChannelTransport {
            tx: ack_a,
            rx: Mutex::new(ack_b),
        });

        let obs = Observability::new(ObservabilityConfig::default());
        let mut scratch = test_recv_scratch(&obs, 256);
        let (no_link, no_inc_tx) = noop_accept_sinks();
        handle_packet(
            v2,
            session_id,
            &server_session,
            &streams,
            &demux,
            &transport_send,
            &transport_send,
            &deliver_tx,
            &undelivered,
            &mut scratch,
            &obs,
            LegType::Tcp,
            &no_link,
            &no_inc_tx,
            &connected_state(),
        )
        .await;

        // The decrypted plaintext must have been handed to the delivery task,
        // tagged with its stream id, and counted toward the undelivered backlog.
        let item = deliver_rx.recv().await.expect("delivery hand-off");
        let (sid, received) = match item {
            DeliverItem::Data(sid, bytes, _) => (sid, bytes),
            DeliverItem::Close(sid) => panic!("unexpected Close({sid}) in deliver channel"),
            DeliverItem::Retire(sid) => panic!("unexpected Retire({sid}) in deliver channel"),
        };
        assert_eq!(sid, stream_id as u32);
        assert_eq!(&received[..], b"hello-v2");
        // The backlog is charged the payload plus what parking one item costs, so the
        // hard cap it feeds bounds resident bytes rather than a count.
        assert_eq!(
            undelivered.load(Ordering::Acquire),
            delivery_charge(b"hello-v2".len())
        );
    }

    /// H-3: the recv path must cap concurrent receive streams. A peer that sprays reliable
    /// frames across far more distinct `stream_id`s than the cap must not auto-create an
    /// unbounded number of `Stream`s — the table is bounded by `MAX_STREAMS`, which (with the
    /// per-stream reorder byte budget) bounds the session's total reorder memory.
    #[tokio::test]
    async fn recv_path_caps_concurrent_streams_at_max_streams() {
        let session_id = fixed_session_id();
        let (client_session, server_session) = paired_sessions(session_id);

        let (demux, _ctrl_rx) = StreamDemultiplexer::new(16);
        let demux = Arc::new(demux);
        let streams: Arc<DashMap<u32, Arc<TransportStream>>> = Arc::new(DashMap::new());
        let (deliver_tx, _deliver_rx) = mpsc::unbounded_channel::<DeliverItem>();
        let undelivered = AtomicU64::new(0);
        let attempts = MAX_STREAMS as u32 + 64;
        let (ack_a, ack_b) = mpsc::channel::<Vec<u8>>(attempts as usize + 16);
        let transport_send: Arc<ChannelTransport> = Arc::new(ChannelTransport {
            tx: ack_a,
            rx: Mutex::new(ack_b),
        });
        let obs = Observability::new(ObservabilityConfig::default());
        let mut scratch = test_recv_scratch(&obs, 256);

        // A peer opens far more receive streams than the cap. Each frame uses a distinct
        // `sequence` (the per-direction packet number, else they replay-reject) but
        // stream_offset 0 so it delivers in order and creates its stream.
        for sid in 0..attempts {
            let frame = build_app_frame_with_offset(
                &client_session,
                session_id,
                sid as TransportStreamId,
                sid, // sequence = distinct per-direction PN
                0,   // stream_offset 0 → in-order delivery
                b"x",
            );
            let v2 = decode_recv_frame(&frame, session_id);
            let (no_link, no_inc_tx) = noop_accept_sinks();
            handle_packet(
                v2,
                session_id,
                &server_session,
                &streams,
                &demux,
                &transport_send,
                &transport_send,
                &deliver_tx,
                &undelivered,
                &mut scratch,
                &obs,
                LegType::Tcp,
                &no_link,
                &no_inc_tx,
                &connected_state(),
            )
            .await;
        }

        assert!(
            streams.len() <= MAX_STREAMS,
            "recv path must cap concurrent receive streams at MAX_STREAMS ({MAX_STREAMS}); have {}",
            streams.len()
        );
    }

    /// M-2 (audit 2026-06-11, residual of prior H1): a forged **unencrypted, empty-payload**
    /// packet carrying only the `FIN` flag (valid `session_id`) must NOT tear down an
    /// `open_stream()` stream. The stripped-flag downgrade defense must drop ALL unencrypted
    /// post-handshake packets — not only non-empty ones — so the standalone-FIN path is never
    /// reached without AEAD verification. Legitimate FINs are always `ENCRYPTED`.
    #[tokio::test]
    async fn forged_unencrypted_fin_does_not_close_a_stream() {
        let session_id = fixed_session_id();
        let (_client_session, server_session) = paired_sessions(session_id);

        let (demux, _ctrl_rx) = StreamDemultiplexer::new(16);
        let demux = Arc::new(demux);
        // Register stream 2 — an open_stream()-style stream (ids 2+), the M-2 target.
        let mut handle = demux.register_stream(2, 8);
        let streams: Arc<DashMap<u32, Arc<TransportStream>>> = Arc::new(DashMap::new());
        let (deliver_tx, _deliver_rx) = mpsc::unbounded_channel::<DeliverItem>();
        let undelivered = AtomicU64::new(0);
        let (ack_a, ack_b) = mpsc::channel::<Vec<u8>>(4);
        let transport_send: Arc<ChannelTransport> = Arc::new(ChannelTransport {
            tx: ack_a,
            rx: Mutex::new(ack_b),
        });
        let obs = Observability::new(ObservabilityConfig::default());
        let mut scratch = test_recv_scratch(&obs, 64);

        // Forged: UNENCRYPTED, empty payload, FIN flag, valid session_id, stream 2.
        let header = PacketHeader::new(session_id, 2, 0, PacketFlags::new(PacketFlags::FIN));
        let forged = PhantomPacket::new(header, Vec::new());

        let (no_link, no_inc_tx) = noop_accept_sinks();
        handle_packet(
            forged,
            session_id,
            &server_session,
            &streams,
            &demux,
            &transport_send,
            &transport_send,
            &deliver_tx,
            &undelivered,
            &mut scratch,
            &obs,
            LegType::Tcp,
            &no_link,
            &no_inc_tx,
            &connected_state(),
        )
        .await;

        assert!(
            handle.rx.try_recv().is_err(),
            "a forged unencrypted FIN must not close an open_stream() stream"
        );
    }

    // ── A stream's two halves, and what is left of it once both are closed ──

    /// What the receive path handed to the delivery task, in a form a test can compare.
    #[derive(Debug, PartialEq, Eq)]
    enum Delivered {
        Data(u32, Vec<u8>),
        Close(u32),
        Retire(u32),
    }

    /// One receive path driven a packet at a time, keeping every channel it writes to so a
    /// test can read back what each packet did.
    ///
    /// The receiving side is the server half of [`paired_sessions`] behind a server-role
    /// demultiplexer, so it opens even stream ids and its peer odd ones — the allocation the
    /// two ends of a real session make.
    struct RecvRig {
        session_id: SessionId,
        client: Arc<InnerSession>,
        server: Arc<InnerSession>,
        streams: Arc<DashMap<u32, Arc<TransportStream>>>,
        demux: Arc<StreamDemultiplexer>,
        deliver_tx: mpsc::UnboundedSender<DeliverItem>,
        deliver_rx: mpsc::UnboundedReceiver<DeliverItem>,
        undelivered: AtomicU64,
        transport: Arc<ChannelTransport>,
        scratch: RecvScratch,
        obs: Arc<Observability>,
        link: StreamLink,
        /// Where the handles of the peer's streams report being dropped.
        released_rx: mpsc::UnboundedReceiver<u32>,
        inc_tx: mpsc::Sender<Arc<crate::api::stream::PhantomStream>>,
        inc_rx: mpsc::Receiver<Arc<crate::api::stream::PhantomStream>>,
        /// The peer's next packet number. Each frame it sends takes a fresh one, as a
        /// retransmission does on the wire, so none is refused as a replay.
        next_pn: u64,
    }

    impl RecvRig {
        fn new() -> Self {
            Self::with_accept_depth(8192)
        }

        /// A rig whose `accept_stream` channel holds `depth` streams the application has
        /// not taken yet.
        fn with_accept_depth(depth: usize) -> Self {
            let session_id = fixed_session_id();
            let (client, server) = paired_sessions(session_id);
            let (demux, _ctrl_rx) = StreamDemultiplexer::new_with_role(16, false);
            let (deliver_tx, deliver_rx) = mpsc::unbounded_channel();
            // Deep enough that no frame the receive path emits is refused for room.
            let (ack_tx, ack_rx) = mpsc::channel::<Vec<u8>>(8192);
            let obs = Observability::new(ObservabilityConfig::default());
            let scratch = test_recv_scratch(&obs, 256);
            let (released, released_rx) = mpsc::unbounded_channel();
            let link = StreamLink {
                released,
                ..detached_stream_link()
            };
            let (inc_tx, inc_rx) = mpsc::channel(depth);
            Self {
                session_id,
                client,
                server,
                streams: Arc::new(DashMap::new()),
                demux: Arc::new(demux),
                deliver_tx,
                deliver_rx,
                undelivered: AtomicU64::new(0),
                transport: Arc::new(ChannelTransport {
                    tx: ack_tx,
                    rx: Mutex::new(ack_rx),
                }),
                scratch,
                obs,
                link,
                released_rx,
                inc_tx,
                inc_rx,
                next_pn: 0,
            }
        }

        /// Open a stream from this side the way `PhantomSession::open_stream` does. The
        /// handle is returned so the stream's delivery channel stays open.
        fn open_local(&self) -> crate::transport::multiplexer::StreamHandle {
            let handle = self
                .demux
                .open_stream(STREAM_RECV_CHANNEL_DEPTH)
                .expect("an id is free");
            self.streams.insert(
                handle.stream_id,
                Arc::new(TransportStream::with_recv_tuning(
                    handle.stream_id as TransportStreamId,
                    self.scratch.recv_tuning.clone(),
                )),
            );
            handle
        }

        /// Close this side's half of `stream_id` the way the pump's `CloseStream` arm
        /// does: the FIN takes the stream's next offset.
        async fn close_local(&self, stream_id: u32) {
            let stream = self
                .streams
                .get(&stream_id)
                .map(|s| s.clone())
                .expect("the stream is in the table");
            assert!(
                stream.try_queue_fin().await.expect("offset space"),
                "the send buffer has room for the FIN"
            );
        }

        async fn feed(&mut self, packet: PhantomPacket) {
            handle_packet(
                packet,
                self.session_id,
                &self.server,
                &self.streams,
                &self.demux,
                &self.transport,
                &self.transport,
                &self.deliver_tx,
                &self.undelivered,
                &mut self.scratch,
                &self.obs,
                LegType::Tcp,
                &self.link,
                &self.inc_tx,
                &connected_state(),
            )
            .await;
        }

        fn take_pn(&mut self) -> u64 {
            let pn = self.next_pn;
            self.next_pn += 1;
            pn
        }

        /// The peer sends a reliable segment at `offset` on `stream_id` — its FIN when
        /// `fin` is set, which carries no payload.
        async fn peer_segment(&mut self, stream_id: u32, offset: u32, payload: &[u8], fin: bool) {
            let mut bits = PacketFlags::RELIABLE | PacketFlags::ENCRYPTED;
            if fin {
                bits |= PacketFlags::FIN;
            }
            let header = PacketHeader::new(
                self.session_id,
                stream_id as TransportStreamId,
                self.take_pn(),
                PacketFlags::new(bits),
            )
            .with_epoch(self.client.current_epoch());
            let mut plaintext = stream_offset_prefix(offset);
            plaintext.extend_from_slice(payload);
            let ciphertext = self
                .client
                .encrypt_packet(&header, &plaintext, &[])
                .expect("encrypt");
            let wire = PhantomPacket::new(header, ciphertext).to_wire();
            self.feed(decode_recv_frame(&wire, self.session_id)).await;
        }

        /// The peer acknowledges offsets `0..=upto` on `stream_id`.
        async fn peer_ack(&mut self, stream_id: u32, upto: u32) {
            let sack = crate::transport::sack::Sack::from_inclusive_ranges(vec![(0, upto)], 0)
                .expect("a non-empty range")
                .to_wire();
            let pn = self.take_pn() as u32;
            let wire = build_encrypted_ack_with_payload(
                &self.client,
                self.session_id,
                stream_id as TransportStreamId,
                pn,
                &sack,
            );
            self.feed(decode_recv_frame(&wire, self.session_id)).await;
        }

        /// The peer closes its half of `stream_id` with a FIN outside the reliable stream: a
        /// bare `ENCRYPTED | FIN` carrying no offset, which is what a sender falls back to
        /// once the stream's offset space is exhausted.
        async fn peer_bare_fin(&mut self, stream_id: u32) {
            let header = PacketHeader::new(
                self.session_id,
                stream_id as TransportStreamId,
                self.take_pn(),
                PacketFlags::new(PacketFlags::ENCRYPTED | PacketFlags::FIN),
            )
            .with_epoch(self.client.current_epoch());
            let ciphertext = self
                .client
                .encrypt_packet(&header, &[], &[])
                .expect("encrypt");
            let wire = PhantomPacket::new(header, ciphertext).to_wire();
            self.feed(decode_recv_frame(&wire, self.session_id)).await;
        }

        /// The peer acknowledges offsets `0..=upto` on `stream_id` with `FIN` set on the
        /// acknowledgement itself.
        async fn peer_ack_with_fin(&mut self, stream_id: u32, upto: u32) {
            let sack = crate::transport::sack::Sack::from_inclusive_ranges(vec![(0, upto)], 0)
                .expect("a non-empty range")
                .to_wire();
            let header = PacketHeader::new(
                self.session_id,
                stream_id as TransportStreamId,
                self.take_pn(),
                PacketFlags::new(PacketFlags::ENCRYPTED | PacketFlags::ACK | PacketFlags::FIN),
            )
            .with_epoch(self.client.current_epoch());
            let ciphertext = self
                .client
                .encrypt_packet(&header, &sack, &[])
                .expect("encrypt");
            let wire = PhantomPacket::new(header, ciphertext).to_wire();
            self.feed(decode_recv_frame(&wire, self.session_id)).await;
        }

        /// Every SACK this side has emitted since the last call, decoded as the peer
        /// would decode it, with the stream it was stamped on.
        async fn emitted_sacks(&self) -> Vec<(u32, crate::transport::sack::Sack)> {
            let mut out = Vec::new();
            let mut rx = self.transport.rx.lock().await;
            while let Ok(frame) = rx.try_recv() {
                let packet = self
                    .client
                    .parse_protected(&frame)
                    .expect("parse an emitted frame");
                if !packet.header.flags.contains(PacketFlags::ACK) {
                    continue;
                }
                let plaintext = self
                    .client
                    .decrypt_packet(&packet.header, &packet.payload, &[])
                    .expect("decrypt an emitted ACK");
                out.push((
                    u32::from(packet.header.stream_id),
                    crate::transport::sack::Sack::from_wire(&plaintext).expect("decode a SACK"),
                ));
            }
            out
        }

        /// Stream ids handed to `accept_stream` since the last call.
        fn accepted(&mut self) -> Vec<u32> {
            let mut out = Vec::new();
            while let Ok(stream) = self.inc_rx.try_recv() {
                out.push(stream.stream_id());
            }
            out
        }

        /// What was handed to the delivery task since the last call.
        fn delivered(&mut self) -> Vec<Delivered> {
            let mut out = Vec::new();
            while let Ok(item) = self.deliver_rx.try_recv() {
                out.push(match item {
                    DeliverItem::Data(id, bytes, _) => Delivered::Data(id, bytes.to_vec()),
                    DeliverItem::Close(id) => Delivered::Close(id),
                    DeliverItem::Retire(id) => Delivered::Retire(id),
                });
            }
            out
        }

        /// Every frame this side has emitted since the last call, opened as the peer would
        /// open it: the header it carried and its plaintext.
        async fn emitted_frames(&self) -> Vec<(PacketHeader, Vec<u8>)> {
            let mut out = Vec::new();
            let mut rx = self.transport.rx.lock().await;
            while let Ok(frame) = rx.try_recv() {
                let packet = self
                    .client
                    .parse_protected(&frame)
                    .expect("parse an emitted frame");
                let plaintext = self
                    .client
                    .decrypt_packet(&packet.header, &packet.payload, &[])
                    .expect("decrypt an emitted frame");
                out.push((packet.header, plaintext));
            }
            out
        }

        /// Every flow-control limit this side has granted since the last call, with the
        /// stream it was stamped on. Other frames are read and dropped.
        async fn emitted_window_updates(&self) -> Vec<(u32, u64)> {
            self.emitted_frames()
                .await
                .into_iter()
                .filter(|(header, _)| header.flags.contains(PacketFlags::WINDOW_UPDATE))
                .map(|(header, plaintext)| {
                    let limit = <[u8; WINDOW_UPDATE_PAYLOAD_LEN]>::try_from(&plaintext[..])
                        .expect("a WINDOW_UPDATE carries an 8-byte limit");
                    (u32::from(header.stream_id), u64::from_be_bytes(limit))
                })
                .collect()
        }
    }

    fn stream_offset_prefix(offset: u32) -> Vec<u8> {
        offset.to_be_bytes().to_vec()
    }

    /// The end that closes first keeps its read half: the peer's later data and FIN reach
    /// the stream this side opened, and only then does the stream leave the table.
    ///
    /// Dropping the stream when the peer acknowledged this side's FIN took the read half
    /// with it, and the peer's next segment — on an id the table no longer held — was taken
    /// for the peer opening a new stream: one of this side's own parity, handed to
    /// `accept_stream`, and never closed.
    #[tokio::test]
    async fn the_read_half_outlives_an_acknowledged_local_close() {
        let mut rig = RecvRig::new();
        let handle = rig.open_local();
        let id = handle.stream_id;

        rig.close_local(id).await;
        rig.peer_ack(id, 0).await;
        assert!(
            rig.streams.contains_key(&id),
            "the peer has not closed its half, so the stream must stay"
        );

        rig.peer_segment(id, 0, b"late", false).await;
        rig.peer_segment(id, 1, b"", true).await;

        assert_eq!(
            rig.accepted(),
            Vec::<u32>::new(),
            "the peer's data on a stream this side opened surfaced as a new peer stream"
        );
        // The route is released behind the data and the EOF, never ahead of them.
        assert_eq!(
            rig.delivered(),
            vec![
                Delivered::Data(id, b"late".to_vec()),
                Delivered::Close(id),
                Delivered::Retire(id)
            ]
        );
        assert!(
            !rig.streams.contains_key(&id),
            "closed from both ends and every segment of both halves settled, so dropped"
        );
    }

    /// A frame for a stream this side has dropped is acknowledged and nothing else: it
    /// neither opens a stream nor delivers anything.
    ///
    /// Such a frame is ordinary. The peer retransmits its FIN whenever the acknowledgement
    /// of it is lost, and by then this side may have dropped the stream. Taking it for a new
    /// stream is the defect above by another route; ignoring it would leave the peer
    /// retransmitting it for as long as the session lives. Both directions of opening are
    /// covered, since this side remembers the two differently.
    #[tokio::test]
    async fn a_late_frame_for_a_dropped_stream_is_only_acknowledged() {
        let mut rig = RecvRig::new();

        // A stream this side opened: the peer's FIN arrives first, then this side's is
        // acknowledged, which completes the close.
        let local = rig.open_local();
        let local_id = local.stream_id;
        rig.close_local(local_id).await;
        rig.peer_segment(local_id, 0, b"", true).await;
        rig.peer_ack(local_id, 0).await;
        assert!(!rig.streams.contains_key(&local_id));

        // A stream the peer opened: its data and FIN, then this side's close, acknowledged.
        let peer_id = 3;
        rig.peer_segment(peer_id, 0, b"hello", false).await;
        rig.peer_segment(peer_id, 1, b"", true).await;
        assert_eq!(rig.accepted(), vec![peer_id]);
        rig.close_local(peer_id).await;
        rig.peer_ack(peer_id, 0).await;
        assert!(!rig.streams.contains_key(&peer_id));

        let _ = rig.delivered();
        let _ = rig.emitted_sacks().await;

        // Each peer FIN again, as a retransmission whose acknowledgement was lost.
        rig.peer_segment(local_id, 0, b"", true).await;
        rig.peer_segment(peer_id, 1, b"", true).await;

        assert_eq!(
            rig.accepted(),
            Vec::<u32>::new(),
            "a dropped stream was reopened"
        );
        assert!(!rig.streams.contains_key(&local_id));
        assert!(!rig.streams.contains_key(&peer_id));
        assert_eq!(
            rig.delivered(),
            Vec::new(),
            "a dropped stream delivered again"
        );
        let sacks = rig.emitted_sacks().await;
        assert_eq!(
            sacks.len(),
            2,
            "each retransmission must be acknowledged so the peer can stop sending it"
        );
        assert_eq!(sacks[0].0, local_id);
        assert!(sacks[0].1.acks(0));
        assert_eq!(sacks[1].0, peer_id);
        assert!(sacks[1].1.acks(0) && sacks[1].1.acks(1));
    }

    /// A segment on an id of this side's own parity that this side never opened makes no
    /// stream, and — having made none — is not acknowledged either.
    ///
    /// Only the peer can open a stream by sending on it, and it opens its own parity. A
    /// segment like this is a peer allocating from the wrong half of the id space, and
    /// leaving it unacknowledged makes that a stall the peer can see rather than data this
    /// side claims to have taken and then discards.
    #[tokio::test]
    async fn a_segment_on_an_id_this_side_never_opened_makes_no_stream() {
        let mut rig = RecvRig::new();
        rig.peer_segment(2, 0, b"wrong half", false).await;

        assert_eq!(rig.accepted(), Vec::<u32>::new());
        assert!(!rig.streams.contains_key(&2));
        assert_eq!(rig.delivered(), Vec::new());
        assert!(rig.emitted_sacks().await.is_empty());
    }

    /// Streams closed from both ends leave the table as they found it, however many of
    /// them there are, so the cap on concurrent streams keeps meaning concurrent.
    ///
    /// Anything a close left behind would count against [`MAX_STREAMS`] for the rest of
    /// the session, and the cap is what refuses the peer's next stream. Both directions of
    /// opening, and both orders of the two FINs, are cycled past the cap here.
    #[tokio::test]
    async fn closing_streams_from_both_ends_does_not_use_up_the_stream_table() {
        let mut rig = RecvRig::new();
        // Twice the cap, so that even the order that loses half of its streams to a leak
        // runs past it.
        let cycles = 2 * MAX_STREAMS as u32 + 44;

        for n in 0..cycles {
            // Opened here; this side's FIN is acknowledged before the peer's arrives on
            // even cycles and after it on odd ones.
            let local = rig.open_local();
            let id = local.stream_id;
            rig.close_local(id).await;
            if n % 2 == 0 {
                rig.peer_ack(id, 0).await;
                rig.peer_segment(id, 0, b"", true).await;
            } else {
                rig.peer_segment(id, 0, b"", true).await;
                rig.peer_ack(id, 0).await;
            }

            // Opened by the peer, closed by it first.
            let peer_id = 3 + 2 * n;
            rig.peer_segment(peer_id, 0, b"", true).await;
            assert!(
                rig.streams.contains_key(&peer_id),
                "the peer's stream {peer_id} was refused after {n} cycles, with {} stream(s) \
                 in the table",
                rig.streams.len()
            );
            rig.close_local(peer_id).await;
            rig.peer_ack(peer_id, 0).await;
        }

        assert!(
            rig.streams.is_empty(),
            "{} stream(s) left in the table after {cycles} closes from both ends",
            rig.streams.len()
        );
        let accepted = rig.accepted();
        assert_eq!(
            accepted.len(),
            cycles as usize,
            "exactly the peer's own streams are accepted, once each"
        );
        assert!(accepted.iter().all(|id| id % 2 == 1));

        // The peer can still open a stream.
        let next = 3 + 2 * cycles;
        rig.peer_segment(next, 0, b"still open for business", false)
            .await;
        assert_eq!(rig.accepted(), vec![next]);
        assert!(rig.streams.contains_key(&next));
    }

    /// A SACK waiting for a stream's send buffer does not hold the stream table.
    ///
    /// `Stream::on_sack` waits on that buffer's lock, which the drain path takes on every
    /// pass. A caller still holding its `DashMap` reference while it waits holds the table
    /// shard's read lock with it, and every write to that shard — `open_stream` on the
    /// application's thread, a stream's removal in the pump — blocks the OS thread it runs
    /// on until the drain lets go. On a single-threaded runtime that thread is the one the
    /// drain needs.
    #[tokio::test(flavor = "current_thread")]
    async fn a_sack_waiting_for_the_send_buffer_does_not_hold_the_stream_table() {
        let session_id = fixed_session_id();
        let (client_session, server_session) = paired_sessions(session_id);
        let stream_id: TransportStreamId = 2;
        let stream = Arc::new(TransportStream::new(stream_id));
        let streams: Arc<DashMap<u32, Arc<TransportStream>>> = Arc::new(DashMap::new());
        streams.insert(stream_id as u32, stream.clone());
        let ack = decode_recv_frame(
            &build_encrypted_ack(&client_session, session_id, stream_id, 0, 0),
            session_id,
        );

        let held = stream.hold_send_buffer_for_test().await;
        let task = {
            let streams = streams.clone();
            let server_session = server_session.clone();
            tokio::spawn(async move {
                run_recv(ack, session_id, &server_session, &streams).await;
            })
        };
        for _ in 0..16 {
            tokio::task::yield_now().await;
        }
        assert!(
            !task.is_finished(),
            "the SACK must be waiting on the held send buffer for this test to mean anything"
        );
        let shard_free = matches!(
            streams.try_get_mut(&(stream_id as u32)),
            dashmap::try_result::TryResult::Present(_)
        );
        drop(held);
        task.await.expect("receive path");
        assert!(
            shard_free,
            "a SACK waiting on the stream's send buffer held the stream table's shard lock"
        );
    }

    /// A SACK never reaches the stream's application channel.
    ///
    /// Nothing reads acknowledgements there — `PhantomStream::recv` skips them — while the
    /// channel is bounded and shared with the stream's data and its EOF. A stream that is
    /// only written to therefore filled it with its own acknowledgements, after which the
    /// delivery task parked on the stream's next item for good.
    #[tokio::test]
    async fn a_sack_is_not_queued_to_the_streams_application_channel() {
        let mut rig = RecvRig::new();
        let mut handle = rig.open_local();
        let id = handle.stream_id;
        for _ in 0..8 {
            rig.peer_ack(id, 0).await;
        }
        assert!(
            handle.rx.try_recv().is_err(),
            "an acknowledgement was queued to the stream's application channel"
        );
    }

    /// A FIN that arrives outside the reliable stream closes the peer's half as surely as
    /// one inside it, so a stream this side has closed too is dropped there and then.
    ///
    /// Two shapes carry one: a bare `ENCRYPTED | FIN`, which a sender falls back to once a
    /// stream's offset space is exhausted, and `FIN` set on an acknowledgement. Both handed
    /// the application its EOF and recorded nothing else, so under the rule that a stream is
    /// dropped once both halves are closed, such a stream never was — it stayed in the table,
    /// counted against [`MAX_STREAMS`], until the session ended.
    #[tokio::test]
    async fn a_fin_outside_the_reliable_stream_completes_the_close() {
        let mut rig = RecvRig::new();

        let bare = rig.open_local();
        let bare_id = bare.stream_id;
        rig.close_local(bare_id).await;
        rig.peer_ack(bare_id, 0).await;
        let _ = rig.delivered();
        rig.peer_bare_fin(bare_id).await;
        assert_eq!(
            rig.delivered(),
            vec![Delivered::Close(bare_id), Delivered::Retire(bare_id)],
            "a bare FIN on a stream whose own FIN is acknowledged must end it"
        );
        assert!(!rig.streams.contains_key(&bare_id));

        let riding = rig.open_local();
        let riding_id = riding.stream_id;
        rig.close_local(riding_id).await;
        rig.peer_ack_with_fin(riding_id, 0).await;
        assert_eq!(
            rig.delivered(),
            vec![Delivered::Close(riding_id), Delivered::Retire(riding_id)],
            "a FIN on the acknowledgement that settles this side's FIN must end the stream"
        );
        assert!(!rig.streams.contains_key(&riding_id));
    }

    /// A FIN outside the reliable stream, after the peer's half has already ended in order,
    /// hands the application no second EOF.
    ///
    /// The in-order FIN delivers its EOF exactly once; the other shapes delivered theirs
    /// every time one arrived, so a stream could end twice on the reading side.
    #[tokio::test]
    async fn a_second_fin_delivers_no_second_eof() {
        let mut rig = RecvRig::new();
        let peer_id = 3;
        rig.peer_segment(peer_id, 0, b"hello", false).await;
        rig.peer_segment(peer_id, 1, b"", true).await;
        assert_eq!(
            rig.delivered(),
            vec![
                Delivered::Data(peer_id, b"hello".to_vec()),
                Delivered::Close(peer_id)
            ]
        );

        rig.peer_bare_fin(peer_id).await;
        assert_eq!(
            rig.delivered(),
            Vec::new(),
            "the peer's half had already ended, so there is no EOF left to deliver"
        );
    }

    /// A stream the application has let go of is dropped as soon as this side's FIN is
    /// acknowledged, with the peer's half still open; what the peer sends on it afterwards
    /// is acknowledged and goes nowhere.
    ///
    /// The peer's half is the peer's to close, and a peer that never closes it used to keep
    /// the stream in this side's table for the life of the session. With the handle gone
    /// there is nobody here to read that half, so there is nothing to keep it for — and the
    /// acknowledgement is what lets the peer's writes on it complete instead of stalling.
    #[tokio::test]
    async fn a_released_stream_goes_once_its_own_close_is_acknowledged() {
        let mut rig = RecvRig::new();
        let local = rig.open_local();
        let id = local.stream_id;
        rig.close_local(id).await;
        rig.streams
            .get(&id)
            .expect("the stream is in the table")
            .release_app_handle();
        let _ = rig.delivered();

        rig.peer_ack(id, 0).await;
        assert!(
            !rig.streams.contains_key(&id),
            "the stream's own close is acknowledged and nobody holds it, so it must go"
        );
        assert_eq!(rig.delivered(), vec![Delivered::Retire(id)]);

        let _ = rig.emitted_sacks().await;
        rig.peer_segment(id, 0, b"to nobody", false).await;
        rig.peer_segment(id, 1, b"", true).await;
        assert_eq!(
            rig.accepted(),
            Vec::<u32>::new(),
            "a dropped stream was reopened"
        );
        assert_eq!(rig.delivered(), Vec::new(), "a dropped stream delivered");
        let sacks = rig.emitted_sacks().await;
        assert_eq!(
            sacks.len(),
            2,
            "each of the peer's segments must be acknowledged, or its writes stall"
        );
        assert!(sacks.iter().all(|(sid, _)| *sid == id));
        assert!(sacks[1].1.acks(0) && sacks[1].1.acks(1));
    }

    /// Letting go of the handle alone drops nothing: a stream whose own close has not been
    /// acknowledged still has a FIN to deliver, and the peer's acknowledgement of it is
    /// what drops the stream.
    #[tokio::test]
    async fn a_released_stream_stays_until_its_own_close_is_acknowledged() {
        let mut rig = RecvRig::new();
        let local = rig.open_local();
        let id = local.stream_id;
        rig.streams
            .get(&id)
            .expect("the stream is in the table")
            .release_app_handle();
        rig.peer_segment(id, 0, b"", true).await;
        assert!(
            rig.streams.contains_key(&id),
            "the peer closed its half, but this side's FIN has not even been sent"
        );

        rig.close_local(id).await;
        rig.peer_ack(id, 0).await;
        assert!(!rig.streams.contains_key(&id));
    }

    /// A stream this side has let go of keeps granting the peer room for what it writes on
    /// it after the stream has left the table, a grant per stretch of offsets rather than
    /// one per segment, and none once the peer has closed its half.
    ///
    /// With the stream dropped there was no receive window left to advance, and all the peer
    /// heard back was the acknowledgement. Its writes stopped at the last limit this side had
    /// granted — and a sender keeps a single queue of refused writes for every stream of its
    /// session, so the whole of the peer's session stopped behind the one stream nobody would
    /// ever read.
    #[tokio::test]
    async fn a_released_stream_keeps_granting_room_for_what_the_peer_sends_on_it() {
        const STRIDE: u32 = RELEASED_GRANT_STRIDE;
        let mut rig = RecvRig::new();
        let local = rig.open_local();
        let id = local.stream_id;
        rig.close_local(id).await;
        rig.streams
            .get(&id)
            .expect("the stream is in the table")
            .release_app_handle();
        rig.peer_ack(id, 0).await;
        assert!(
            !rig.streams.contains_key(&id),
            "released and closed, so gone"
        );
        let _ = rig.delivered();
        let _ = rig.emitted_frames().await;

        // The peer writes on, in the largest chunks the receive gate lets through: the case in
        // which a grant worked out from the offset alone has the least to spare.
        let chunk = vec![0x33; MAX_RECV_PAYLOAD - crate::transport::mtu::RELIABLE_OFFSET_LEN];
        let segments = 4 * STRIDE;
        let mut granted = 0u64;
        let mut grants = 0u32;
        for offset in 0..segments {
            rig.peer_segment(id, offset, &chunk, false).await;
            for (sid, limit) in rig.emitted_window_updates().await {
                assert_eq!(sid, id, "a grant stamped on the wrong stream");
                grants += 1;
                granted = granted.max(limit);
            }
            let sent = u64::from(offset + 1) * chunk.len() as u64;
            assert!(
                granted >= sent + u64::from(crate::transport::stream::INITIAL_STREAM_WINDOW),
                "after offset {offset} the peer has sent {sent} B and holds a limit of \
                 {granted} B: less room than a stream is opened with"
            );
        }
        assert!(
            grants <= segments / STRIDE,
            "{grants} grants for {segments} segments — the answer to a stream nobody reads \
             must not be a frame for every frame"
        );

        // Far along the stream the grant still covers every byte the peer can have sent: the
        // per-segment bound is the receive gate's, not this build's own chunk size, or a
        // peer chunking larger would fall behind it by a little on every segment.
        let far = 1 << 20;
        rig.peer_segment(id, far, &chunk, false).await;
        let far_grant = rig.emitted_window_updates().await;
        assert_eq!(far_grant.len(), 1, "offset {far} is on a stride");
        assert!(
            far_grant[0].1
                >= u64::from(far + 1) * chunk.len() as u64
                    + u64::from(crate::transport::stream::INITIAL_STREAM_WINDOW),
            "at offset {far} the grant {} fell behind what the peer can have sent",
            far_grant[0].1
        );

        // The peer runs out of things in flight and asks with its persist probe, which repeats
        // the highest offset already acknowledged. A probe is answered whatever its offset.
        let sent = u64::from(segments) * chunk.len() as u64;
        rig.peer_segment(id, segments - 1, b"", false).await;
        let answer = rig.emitted_window_updates().await;
        assert_eq!(
            answer.len(),
            1,
            "the persist probe must be answered with a grant"
        );
        assert!(
            answer[0].1 > sent,
            "the answer to a probe must let the peer move"
        );

        // A FIN is the peer's writing half closing: it needs no more room.
        rig.peer_segment(id, segments, b"", true).await;
        assert!(rig.emitted_window_updates().await.is_empty());

        assert_eq!(
            rig.accepted(),
            Vec::<u32>::new(),
            "a dropped stream was reopened"
        );
        assert_eq!(rig.delivered(), Vec::new(), "a dropped stream delivered");
    }

    /// A stream whose offset space is exhausted falls back to a bare FIN once, and leaves the
    /// active-streams gauge once, however many closes are queued for it.
    ///
    /// The fallback drops the stream without ever recording a FIN as queued on it, so a
    /// `Release` waiting behind a `Fin` that had already fallen back found the FIN still
    /// refused and fell back again: a second bare FIN on the wire, and a second decrement of
    /// a gauge that counts streams rather than ids — one more open stream reported closed
    /// than had been.
    #[tokio::test]
    async fn an_exhausted_stream_falls_back_to_a_bare_fin_once() {
        let rig = RecvRig::new();
        let exhausted = rig.open_local();
        let other = rig.open_local();
        for id in [exhausted.stream_id, other.stream_id] {
            rig.scratch.stream_gauge.opened(id);
        }
        let id = exhausted.stream_id;
        let stream = rig
            .streams
            .get(&id)
            .map(|s| s.clone())
            .expect("the stream is in the table");
        stream.exhaust_reliable_offsets_for_test();

        // `disconnect()` and then the handle's drop, both refused room for their FIN.
        let mut deferred = VecDeque::from([
            Deferred::Fin {
                stream_id: id,
                stream: stream.clone(),
            },
            Deferred::Release {
                stream_id: id,
                stream: stream.clone(),
            },
        ]);
        flush_deferred_sends(
            &mut deferred,
            &rig.transport,
            &rig.server,
            rig.session_id,
            &rig.streams,
            &rig.demux,
            &rig.scratch.stream_gauge,
            &rig.obs,
        )
        .await;

        assert!(deferred.is_empty(), "both closes were taken off the queue");
        assert!(!rig.streams.contains_key(&id));
        assert!(!rig.demux.has_stream(id));
        let fins = rig
            .emitted_frames()
            .await
            .into_iter()
            .filter(|(header, _)| header.flags.contains(PacketFlags::FIN))
            .count();
        assert_eq!(fins, 1, "one stream, one bare FIN");
        assert_eq!(
            rig.obs.snapshot().active_streams,
            1,
            "stream {} is still open and has to be counted",
            other.stream_id
        );
    }

    /// Every handle to a peer's stream reports being dropped — the one the application took
    /// and let go of, and the one that never reached it because the accept queue was full.
    ///
    /// The second used to sit in the table for the life of the session with no reader:
    /// delivered data was thrown away at the channel, acknowledged all the same, and the
    /// stream counted against [`MAX_STREAMS`].
    #[tokio::test]
    async fn every_dropped_handle_to_a_peer_stream_reports_its_release() {
        let mut rig = RecvRig::with_accept_depth(1);
        rig.peer_segment(3, 0, b"taken", false).await;
        rig.peer_segment(5, 0, b"never seen", false).await;
        assert_eq!(
            rig.released_rx.try_recv().ok(),
            Some(5),
            "the handle the accept queue had no room for was dropped unreported"
        );
        assert!(
            rig.streams.contains_key(&5),
            "the pump decides when it goes"
        );

        assert_eq!(rig.accepted(), vec![3]);
        assert_eq!(
            rig.released_rx.try_recv().ok(),
            Some(3),
            "a handle the application let go of went unreported"
        );
    }

    /// Like [`build_app_frame`] but stamps a caller-chosen `path_id` so the
    /// receive-side path gate (PATH-001) can be exercised.
    fn build_app_frame_on_path(
        client_session: &InnerSession,
        session_id: SessionId,
        stream_id: TransportStreamId,
        sequence: u32,
        stream_offset: u32,
        path_id: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let flag_bits = PacketFlags::RELIABLE | PacketFlags::ENCRYPTED;
        let header = PacketHeader::new(
            session_id,
            stream_id,
            sequence as u64,
            PacketFlags::new(flag_bits),
        )
        .with_epoch(client_session.current_epoch())
        .with_path_id(path_id);
        // Reliable plaintext = [stream_offset: u32 BE][payload] (A.5).
        let mut pt = Vec::with_capacity(4 + payload.len());
        pt.extend_from_slice(&stream_offset.to_be_bytes());
        pt.extend_from_slice(payload);
        let ciphertext = client_session
            .encrypt_packet(&header, &pt, &[])
            .expect("encrypt_packet");
        // Cleartext wire: this frame is decoded back to a struct and fed to
        // handle_packet directly (it never traverses the pump's transport, which
        // is the only path that applies/removes header protection).
        PhantomPacket::new(header, ciphertext).to_wire()
    }

    #[test]
    fn send_path_id_starts_at_zero_then_bumps_per_migration() {
        // D5 (Phase 4): the client owns a monotonic send-side path_id, default 0 (the
        // implicit handshake path), bumped on each migration so the server can detect
        // and challenge the new path. Reuse is nonce-safe since P4.0 (path_id left the
        // AEAD nonce — `nonce = nonce_prefix ‖ packet_number`).
        let session_id = fixed_session_id();
        let (client_session, _server_session) = paired_sessions(session_id);
        assert_eq!(client_session.current_send_path_id(), 0);
        assert_eq!(client_session.next_migration_path_id(), 1);
        assert_eq!(client_session.current_send_path_id(), 1);
        assert_eq!(client_session.next_migration_path_id(), 2);
        assert_eq!(client_session.current_send_path_id(), 2);
    }

    // ── Path-validation expiry sweep ────────────────────────────────────────

    /// `expire` must take exactly the challenges past the budget, leave the rest
    /// outstanding, and hand back the real wait so the histogram sample is the
    /// true latency and not the budget. Deterministic — the start stamps are
    /// injected via `start_at`, no sleeping.
    #[test]
    fn expire_takes_only_challenges_past_the_budget() {
        let challenges = PathChallenges::default();
        let now = std::time::Instant::now();
        // Path 1: outstanding for 5 s → past a 1 s budget.
        challenges.start_at(1, now - std::time::Duration::from_secs(5));
        // Path 2: outstanding for 100 ms → well inside it.
        challenges.start_at(2, now - std::time::Duration::from_millis(100));

        let expired = challenges.expire(std::time::Duration::from_secs(1));
        assert_eq!(expired.len(), 1, "exactly one challenge is past the budget");
        assert_eq!(expired[0].0, 1);
        assert!(
            expired[0].1 >= std::time::Duration::from_secs(5),
            "the sample must carry the ACTUAL wait ({:?}), not the budget",
            expired[0].1
        );
        assert_eq!(challenges.outstanding(), 1, "path 2 must still be pending");
        assert!(
            challenges.resolve(2).is_some(),
            "the in-budget challenge is still resolvable by a late response"
        );
    }

    /// One entry ⇒ exactly one sample. After the sweep abandons a challenge, a
    /// response that finally arrives must NOT also record a `success` — the
    /// entry is gone, so `resolve` returns `None` and `handle_packet` skips the
    /// recording. This is the double-count regression the shared map prevents.
    #[test]
    fn a_swept_challenge_cannot_also_record_a_response() {
        let challenges = PathChallenges::default();
        challenges.start_at(
            3,
            std::time::Instant::now() - std::time::Duration::from_secs(30),
        );
        assert_eq!(
            challenges.expire(std::time::Duration::from_secs(1)).len(),
            1
        );
        assert!(
            challenges.resolve(3).is_none(),
            "a swept challenge must leave nothing for the response path to time"
        );
        assert_eq!(challenges.outstanding(), 0);
    }

    /// A re-issued challenge (PATH-003 returns the same bytes) restarts the
    /// clock rather than accumulating a second entry, so a path being
    /// re-challenged every heartbeat is never swept out from under itself.
    #[test]
    fn restarting_a_challenge_replaces_its_stamp() {
        let challenges = PathChallenges::default();
        challenges.start_at(
            4,
            std::time::Instant::now() - std::time::Duration::from_secs(60),
        );
        challenges.start(4);
        assert_eq!(challenges.outstanding(), 1, "no duplicate entry");
        assert!(
            challenges
                .expire(std::time::Duration::from_secs(1))
                .is_empty(),
            "the re-issue must have reset the clock"
        );
    }

    /// The budget is the session's own path-down threshold —
    /// `path_down_ptos × max(min_pto, 3 × min_rtt)` — read live from the
    /// `LivenessConfig`, not a private constant. On a session with no RTT sample
    /// yet the estimator's conservative 100 ms seed governs, so the PTO is
    /// `3 × 100 ms = 300 ms` in every case below.
    #[test]
    fn path_validation_timeout_tracks_the_liveness_config() {
        use crate::transport::liveness::LivenessConfig;
        let (session, _peer) = paired_sessions(fixed_session_id());
        let pto = std::time::Duration::from_millis(300);
        assert_eq!(
            session.bandwidth_snapshot().min_rtt,
            std::time::Duration::from_millis(100),
            "the estimator seeds min_rtt conservatively; the arithmetic below assumes it"
        );

        // Defaults: 5 × max(200 ms, 300 ms) = 1.5 s.
        session.set_liveness_config(LivenessConfig::default());
        assert_eq!(path_validation_timeout(&session), pto * 5);

        // A shrunk config shrinks the budget with it: 3 × max(10 ms, 300 ms).
        session.set_liveness_config(LivenessConfig::for_test());
        assert_eq!(path_validation_timeout(&session), pto * 3);

        // `path_down_ptos = 0` must not collapse the budget to zero (which would
        // expire every challenge on the very next 10 ms heartbeat).
        session.set_liveness_config(LivenessConfig {
            path_down_ptos: 0,
            ..LivenessConfig::for_test()
        });
        assert_eq!(
            path_validation_timeout(&session),
            pto,
            "path_down_ptos is floored at 1"
        );
    }

    /// End-to-end shape of the pump-side call: an over-budget challenge is
    /// reclaimed and reported, an in-budget one is untouched. The recording
    /// itself is OTel-only (a no-op ZST in this build), so what is asserted here
    /// is the bookkeeping; the metric emission is pinned by
    /// `core/tests/observability_instrument_wiring.rs`.
    #[test]
    fn sweep_reclaims_only_expired_challenges() {
        use crate::transport::liveness::LivenessConfig;
        let (session, _peer) = paired_sessions(fixed_session_id());
        session.set_liveness_config(LivenessConfig::default()); // 1 s budget
        let obs = Observability::new(ObservabilityConfig::default());
        let challenges = PathChallenges::default();

        let now = std::time::Instant::now();
        challenges.start_at(1, now - std::time::Duration::from_secs(10));
        challenges.start_at(2, now);

        sweep_path_validation_timeouts(&session, &challenges, &obs);

        assert_eq!(challenges.outstanding(), 1);
        assert!(
            challenges.resolve(1).is_none(),
            "the stale challenge must have been reclaimed"
        );
        assert!(
            challenges.resolve(2).is_some(),
            "the fresh challenge must survive the sweep"
        );
    }

    /// ε / WIRE v5 (audit V-1 / Invariant 4) — the inbound CID-window slide is
    /// signalled ONLY from the post-AEAD path. A forged packet that fails AEAD —
    /// even one carrying a NEW forward `path_id` (the migration signal) — must not
    /// advance the inbound CID window or emit a `CidSlide`. This pins that an
    /// off-path attacker (who cannot produce a valid tag) cannot push the demux
    /// window; a future refactor that hoists the slide above the AEAD gate fails here.
    #[tokio::test]
    async fn eps_slide_requires_aead_success() {
        let session_id = fixed_session_id();
        let (client_session, server_session) = paired_sessions(session_id);
        let streams: Arc<DashMap<u32, Arc<TransportStream>>> = Arc::new(DashMap::new());

        use crate::transport::session::{DemuxLink, DemuxRouteOwner};

        // Install the demux link and snapshot the inbound CID window.
        let (slide_tx, mut slide_rx) = mpsc::unbounded_channel();
        let (retire_tx, _retire_rx) = mpsc::channel(4);
        server_session.set_demux_link(DemuxLink {
            slide_tx,
            retire_tx,
            owner: DemuxRouteOwner(1),
        });
        let window_before = server_session.inbound_window_cids();

        // A valid frame on a NEW path_id (1, the migration signal), then corrupt
        // the ciphertext so AEAD verification fails. The header stays intact.
        let stream_id: TransportStreamId = 1;
        let frame =
            build_app_frame_on_path(&client_session, session_id, stream_id, 0, 0, 1, b"forged");
        let mut pkt = decode_recv_frame(&frame, session_id);
        assert!(!pkt.payload.is_empty(), "ciphertext present to corrupt");
        pkt.payload[0] ^= 0xFF; // tamper → AEAD open fails

        run_recv(pkt, session_id, &server_session, &streams).await;

        assert!(
            slide_rx.try_recv().is_err(),
            "a forged (AEAD-failing) packet must emit no CidSlide"
        );
        assert_eq!(
            server_session.inbound_window_cids(),
            window_before,
            "the inbound CID window must not advance on a forged packet (slide is post-AEAD)"
        );
    }

    use std::sync::atomic::AtomicBool;

    /// Records each `SessionTransport` control method the inner transport receives,
    /// for the [`observed_transport_forwards_all_control_methods`] tripwire.
    #[derive(Default)]
    struct ControlRecorder {
        supports_migration: AtomicBool,
        set_frame_phase: AtomicBool,
        set_outbound_cid: std::sync::Mutex<Option<[u8; 8]>>,
        has_migration_candidate: AtomicBool,
        send_to_candidate: AtomicBool,
        confirm_authenticated_source: AtomicBool,
        promote_candidate: AtomicBool,
        migrate: std::sync::Mutex<Option<String>>,
        migrate_server: std::sync::Mutex<Option<String>>,
    }

    struct RecordingTransport {
        rec: Arc<ControlRecorder>,
    }

    impl SessionTransport for RecordingTransport {
        async fn send_bytes(&self, _data: &[u8]) -> Result<(), CoreError> {
            Ok(())
        }
        async fn recv_bytes(&self) -> Result<Bytes, CoreError> {
            Ok(Bytes::new())
        }
        fn supports_migration(&self) -> bool {
            self.rec.supports_migration.store(true, Ordering::SeqCst);
            true
        }
        fn set_frame_phase(&self, _phase: FramePhase) {
            self.rec.set_frame_phase.store(true, Ordering::SeqCst);
        }
        fn set_outbound_cid(&self, cid: [u8; 8]) {
            *self.rec.set_outbound_cid.lock().unwrap() = Some(cid);
        }
        fn has_migration_candidate(&self) -> bool {
            self.rec
                .has_migration_candidate
                .store(true, Ordering::SeqCst);
            true
        }
        async fn send_to_candidate(&self, _data: &[u8]) -> Result<bool, CoreError> {
            self.rec.send_to_candidate.store(true, Ordering::SeqCst);
            Ok(true)
        }
        fn confirm_authenticated_source(&self) {
            self.rec
                .confirm_authenticated_source
                .store(true, Ordering::SeqCst);
        }
        fn promote_candidate(&self) -> bool {
            self.rec.promote_candidate.store(true, Ordering::SeqCst);
            true
        }
        async fn migrate(&self, local_addr: String) -> Result<(), CoreError> {
            *self.rec.migrate.lock().unwrap() = Some(local_addr);
            Ok(())
        }
        async fn migrate_server(&self, local_addr: String) -> Result<(), CoreError> {
            *self.rec.migrate_server.lock().unwrap() = Some(local_addr);
            Ok(())
        }
    }

    /// EPS-02 (audit L4) — the symmetric-rotation role branch, pinned ALWAYS-ON
    /// (the live wire-level proof is `#[ignore]` `udp_integration`). On detecting a
    /// peer migration, a **server** rotates its s2c CID but keeps its send `path_id`
    /// (path-id-silent — prevents a ping-pong), while a **client** rotates its c2s
    /// CID **and** bumps its send `path_id` (the window-slide / no-stranding fix).
    /// Non-vacuous: flipping the `is_server` branch flips which side bumps `path_id`,
    /// failing an assertion here.
    #[test]
    fn eps02_rotation_branch_is_role_correct() {
        let session_id = fixed_session_id();
        let (client, server) = paired_sessions(session_id);

        // SERVER (its client migrated): rotate s2c CID, path_id SILENT.
        let s_path_before = server.current_send_path_id();
        let s_cid_before = server.current_outbound_cid();
        let rec_s = Arc::new(ControlRecorder::default());
        apply_eps02_peer_migration_rotation(&server, &RecordingTransport { rec: rec_s.clone() });
        assert_ne!(
            server.current_outbound_cid(),
            s_cid_before,
            "server must rotate its s2c CID on a peer (client) migration"
        );
        assert_eq!(
            *rec_s.set_outbound_cid.lock().unwrap(),
            Some(server.current_outbound_cid()),
            "server stamps the rotated CID onto its transport"
        );
        assert_eq!(
            server.current_send_path_id(),
            s_path_before,
            "server rotation is path-id-SILENT (bumping it would ping-pong the client)"
        );

        // CLIENT (its server migrated): rotate c2s CID AND bump send path_id.
        let c_path_before = client.current_send_path_id();
        let c_cid_before = client.current_outbound_cid();
        let rec_c = Arc::new(ControlRecorder::default());
        apply_eps02_peer_migration_rotation(&client, &RecordingTransport { rec: rec_c.clone() });
        assert_ne!(
            client.current_outbound_cid(),
            c_cid_before,
            "client must rotate its c2s CID on a peer (server) migration"
        );
        assert_eq!(
            *rec_c.set_outbound_cid.lock().unwrap(),
            Some(client.current_outbound_cid()),
            "client stamps the rotated CID onto its transport"
        );
        assert_eq!(
            client.current_send_path_id(),
            c_path_before + 1,
            "client bumps its send path_id (slides the server's c2s demux window — no stranding)"
        );
    }

    /// ε / WIRE v5 (audit V-3 / EPS-03 / EPS-04) — `ObservedTransport` must forward
    /// EVERY `SessionTransport` control method to the inner transport, not just
    /// send/recv. A method left on the trait default silently no-ops — the bug that
    /// made the pre-ε FFI `migrate()` vacuous and linkable. This always-on tripwire
    /// pins the full control surface without UDP loopback: a dropped forward, or a
    /// future-added trait method the wrapper forgets, fails an assertion here.
    #[tokio::test]
    async fn observed_transport_forwards_all_control_methods() {
        let rec = Arc::new(ControlRecorder::default());
        let observed = ObservedTransport::new(
            RecordingTransport { rec: rec.clone() },
            Observability::new(ObservabilityConfig::default()),
            LegType::Udp,
        );

        assert!(
            observed.supports_migration(),
            "supports_migration not forwarded at the call site"
        );
        observed.set_frame_phase(FramePhase::Established);
        observed.set_outbound_cid([7u8; 8]);
        assert!(observed.has_migration_candidate());
        assert!(observed
            .send_to_candidate(b"challenge")
            .await
            .expect("send_to_candidate"));
        observed.confirm_authenticated_source();
        assert!(observed.promote_candidate());
        observed
            .migrate("127.0.0.1:0".to_string())
            .await
            .expect("migrate");
        observed
            .migrate_server("127.0.0.1:0".to_string())
            .await
            .expect("migrate_server");

        assert!(
            rec.supports_migration.load(Ordering::SeqCst),
            "supports_migration not forwarded"
        );
        assert!(
            rec.set_frame_phase.load(Ordering::SeqCst),
            "set_frame_phase not forwarded"
        );
        assert_eq!(
            *rec.set_outbound_cid.lock().unwrap(),
            Some([7u8; 8]),
            "set_outbound_cid not forwarded"
        );
        assert!(
            rec.has_migration_candidate.load(Ordering::SeqCst),
            "has_migration_candidate not forwarded"
        );
        assert!(
            rec.send_to_candidate.load(Ordering::SeqCst),
            "send_to_candidate not forwarded"
        );
        assert!(
            rec.confirm_authenticated_source.load(Ordering::SeqCst),
            "confirm_authenticated_source not forwarded"
        );
        assert!(
            rec.promote_candidate.load(Ordering::SeqCst),
            "promote_candidate not forwarded"
        );
        assert_eq!(
            rec.migrate.lock().unwrap().as_deref(),
            Some("127.0.0.1:0"),
            "migrate not forwarded"
        );
        assert_eq!(
            rec.migrate_server.lock().unwrap().as_deref(),
            Some("127.0.0.1:0"),
            "migrate_server not forwarded"
        );
    }

    /// A transport whose writes fail with a scripted error and whose reads never
    /// complete — the shape of a stream transport whose peer has stopped reading and
    /// has nothing to say.
    struct ScriptedWriteFailure {
        failure: CoreError,
        writes: AtomicU64,
    }

    impl SessionTransport for ScriptedWriteFailure {
        async fn send_bytes(&self, _data: &[u8]) -> Result<(), CoreError> {
            self.writes.fetch_add(1, Ordering::SeqCst);
            Err(self.failure.clone())
        }
        async fn recv_bytes(&self) -> Result<Bytes, CoreError> {
            std::future::pending().await
        }
    }

    fn observed(failure: CoreError) -> ObservedTransport<ScriptedWriteFailure> {
        ObservedTransport::new(
            ScriptedWriteFailure {
                failure,
                writes: AtomicU64::new(0),
            },
            Observability::new(ObservabilityConfig::default()),
            LegType::Tcp,
        )
    }

    /// A `Timeout` from the transport is final: the wrapper wakes a reader parked on
    /// the peer, and refuses every later write without passing it to the transport,
    /// which may have left a frame cut part-way through on the wire.
    #[tokio::test]
    async fn a_timeout_from_the_transport_ends_reading_and_writing_through_it() {
        let transport = Arc::new(observed(CoreError::Timeout));
        let reader = {
            let transport = transport.clone();
            tokio::spawn(async move {
                let given_up = transport.given_up();
                tokio::pin!(given_up);
                tokio::select! {
                    _ = transport.recv_bytes() => "the read completed",
                    () = &mut given_up => "woken by the give-up",
                }
            })
        };
        // Let the reader park before the write fails, so the wake-up is what ends it.
        tokio::task::yield_now().await;
        assert!(!transport.has_given_up());

        let first = transport.send_bytes(b"stalls").await;
        assert!(matches!(first, Err(CoreError::Timeout)), "{first:?}");
        assert!(transport.has_given_up());
        let woken = tokio::time::timeout(std::time::Duration::from_secs(5), reader)
            .await
            .expect("a reader parked on the peer was never woken")
            .expect("reader task");
        assert_eq!(woken, "woken by the give-up");

        let second = transport.send_bytes(b"after").await;
        assert!(matches!(second, Err(CoreError::Timeout)), "{second:?}");
        assert_eq!(
            transport.inner.writes.load(Ordering::SeqCst),
            1,
            "a write after the give-up reached the transport"
        );
        // Resolves at once for a waiter that arrives late.
        tokio::time::timeout(std::time::Duration::from_secs(5), transport.given_up())
            .await
            .expect("given_up() must resolve immediately once the transport has given up");
    }

    /// Any other write failure is the transport's own business — a datagram socket out
    /// of buffer, say — and the next write is still passed through.
    #[tokio::test]
    async fn other_transport_errors_do_not_count_as_giving_up() {
        let transport = observed(CoreError::NetworkError("no buffer space".into()));
        for _ in 0..2 {
            let r = transport.send_bytes(b"x").await;
            assert!(matches!(r, Err(CoreError::NetworkError(_))), "{r:?}");
        }
        assert!(!transport.has_given_up());
        assert_eq!(transport.inner.writes.load(Ordering::SeqCst), 2);
    }

    /// EPS-02 (symmetric CID rotation) — when the **server** (the demuxing side)
    /// detects a client migration (a new authenticated `path_id`, post-AEAD), it
    /// must rotate its OWN outbound (server→client) CID so that direction also
    /// gets a fresh `ConnId` across the move. Otherwise an on-path observer seeing
    /// both networks links the session by the stable s2c CID (the ε §12.5 residual
    /// this fix closes). The socket-routed client accepts any inbound CID, so no
    /// client-side window slide is needed and there is no ping-pong (we never bump
    /// the server's own send path_id here).
    #[tokio::test]
    async fn eps02_server_rotates_s2c_cid_on_client_migration() {
        let session_id = fixed_session_id();
        let (client_session, server_session) = paired_sessions(session_id);
        let streams: Arc<DashMap<u32, Arc<TransportStream>>> = Arc::new(DashMap::new());

        assert!(server_session.is_server(), "server side");
        let s2c_cid_before = server_session.current_outbound_cid();

        // The client migrates: it bumps its send path_id and sends app data on the
        // new path. Deliver that migration packet (path_id = 1) to the server.
        let stream_id: TransportStreamId = 1;
        let frame =
            build_app_frame_on_path(&client_session, session_id, stream_id, 0, 0, 1, b"migrated");
        let pkt = decode_recv_frame(&frame, session_id);
        run_recv(pkt, session_id, &server_session, &streams).await;

        assert_ne!(
            server_session.current_outbound_cid(),
            s2c_cid_before,
            "the server must rotate its server->client CID when the client migrates (EPS-02)"
        );
    }

    /// EPS-02 CLOSURE (D4, symmetric rotation) — when the CLIENT detects a server
    /// migration (a new authenticated server `path_id`, post-AEAD) it REFLECTS: it bumps
    /// its OWN send path_id AND rotates its outbound (c2s) CID. The path_id bump is what
    /// makes the server slide its c2s demux window so the rotated c2s CID stays routable
    /// (no stranding — the reason the old "client must not rotate" rule existed); the CID
    /// rotation closes the s2c/c2s linkability residual for SERVER-initiated migration.
    /// The server's own s2c re-rotation (the test above) is path_id-silent, so the client
    /// sees no new forward server path_id from it — no ping-pong, terminates in one round.
    #[tokio::test]
    async fn eps02_client_rotates_c2s_on_server_migration() {
        let session_id = fixed_session_id();
        let (client_session, server_session) = paired_sessions(session_id);
        let streams: Arc<DashMap<u32, Arc<TransportStream>>> = Arc::new(DashMap::new());

        assert!(!client_session.is_server(), "client side");
        let c2s_cid_before = client_session.current_outbound_cid();
        let send_path_before = client_session.current_send_path_id();

        // The server migrates: build a server→client app frame on a new path_id and
        // deliver it to the client's recv path.
        let stream_id: TransportStreamId = 1;
        let frame = build_app_frame_on_path(
            &server_session,
            session_id,
            stream_id,
            0,
            0,
            1,
            b"srv-moved",
        );
        let pkt = decode_recv_frame(&frame, session_id);
        run_recv(pkt, session_id, &client_session, &streams).await;

        assert_ne!(
            client_session.current_outbound_cid(),
            c2s_cid_before,
            "the client must rotate its c2s CID on detecting a server migration (EPS-02 closure)"
        );
        assert_ne!(
            client_session.current_send_path_id(),
            send_path_before,
            "the client must bump its send path_id so the server slides its c2s window (no stranding)"
        );
    }

    /// EPS-02 closure, multi-step case — the client's c2s rotation is driven by ITS OWN
    /// reflection count, NOT by the server's migration count `d`. When the client detects a
    /// *forward* server `path_id` of `d > 1` (it missed intermediate server migrations under
    /// loss), it reflects ONCE: `send_path_id` and `outbound_cid_index` each advance by 1 and
    /// stay **1:1**. That 1:1 is exactly the invariant the server's c2s window slide relies on
    /// — the server slides by the *client's* `path_id` delta (1) and routes the client's c2s
    /// CID at index 1. So a `d > 1` server migration does NOT desync the c2s direction (the
    /// `d` the client computes here is its *inbound* view of the server's s2c chain, which the
    /// socket-routed client does not even use). Guards against an over-eager "bump by d" fix.
    #[tokio::test]
    async fn eps02_client_reflects_once_for_a_multi_step_server_migration() {
        let session_id = fixed_session_id();
        let (client_session, server_session) = paired_sessions(session_id);
        let streams: Arc<DashMap<u32, Arc<TransportStream>>> = Arc::new(DashMap::new());

        assert!(!client_session.is_server(), "client side");

        // The server migrated TWICE but the client only sees the second (the first s2c on
        // path_id 1 was lost): deliver a server→client app frame on path_id = 2 (forward
        // distance d = 2 from the client's view).
        let stream_id: TransportStreamId = 1;
        let frame = build_app_frame_on_path(
            &server_session,
            session_id,
            stream_id,
            0,
            0,
            2,
            b"srv-moved-2x",
        );
        let pkt = decode_recv_frame(&frame, session_id);
        run_recv(pkt, session_id, &client_session, &streams).await;

        assert_eq!(
            client_session.current_send_path_id(),
            1,
            "client reflects ONCE (not d = 2) — its c2s rotation is decoupled from the server's migration count"
        );
        assert_eq!(
            client_session.outbound_cid_index(),
            1,
            "outbound CID index stays 1:1 with send_path_id, so the server (which slides its c2s window by the CLIENT's path_id delta) routes the rotated c2s CID — no desync on a d>1 server migration"
        );
    }

    #[test]
    fn migration_path_id_never_collides_with_the_handshake_path() {
        // The migration counter must never hand back path_id 0 — that id is
        // permanently the Validated handshake path on both peers, so reusing it would
        // make the server skip the challenge (path 0 is always Validated) and the
        // switch would never fire. Spanning > 2 u8 wraps proves the wrap (never 0;
        // it also skips the reserved 255 — see the dedicated collision test).
        let session_id = fixed_session_id();
        let (client_session, _server_session) = paired_sessions(session_id);
        for _ in 0..600 {
            assert_ne!(client_session.next_migration_path_id(), 0);
        }
    }

    #[tokio::test]
    async fn send_app_data_stamps_the_current_send_path_id() {
        // P4.2b: `send_app_data` must stamp `header.path_id` from the session's
        // current send path_id (default 0). After a migration bump, every outbound
        // app-data packet — including ARQ retransmits, which also flow through
        // `send_app_data` — carries the new path_id, which is exactly what makes the
        // server detect the new path and issue a PATH_CHALLENGE (D5 / D6).
        let session_id = fixed_session_id();
        let (client_session, _server_session) = paired_sessions(session_id);
        let (client_t, server_t) = ChannelTransport::pair();
        let client_t = Arc::new(client_t);
        let obs = Observability::new(ObservabilityConfig::default());

        // Default: app data is stamped on the implicit path 0.
        assert!(
            send_app_data(
                &client_t,
                &client_session,
                session_id,
                1,
                b"pre-migration",
                PacketFlags::RELIABLE,
                Some(0),
                &obs,
            )
            .await
        );
        let wire = server_t.recv_bytes().await.unwrap();
        let pkt = _server_session.parse_protected(&wire).unwrap();
        assert_eq!(
            pkt.header.path_id, 0,
            "default send path is the implicit path 0"
        );

        // After a migration bump, the new path_id is stamped on subsequent app data.
        assert_eq!(client_session.next_migration_path_id(), 1);
        assert!(
            send_app_data(
                &client_t,
                &client_session,
                session_id,
                1,
                b"post-migration",
                PacketFlags::RELIABLE,
                Some(13),
                &obs,
            )
            .await
        );
        let wire2 = server_t.recv_bytes().await.unwrap();
        let pkt2 = _server_session.parse_protected(&wire2).unwrap();
        assert_eq!(
            pkt2.header.path_id, 1,
            "after migrate(), app data must carry the bumped send path_id"
        );
    }

    #[tokio::test]
    async fn app_data_on_non_validated_path_is_delivered_recv_relax() {
        // PATH-001 split (D10, Phase 4). RECV is relaxed: AEAD-authenticated,
        // non-replayed app data is DELIVERED regardless of which path it arrived
        // on (the data already passed AEAD + the per-direction replay window, so
        // dropping it by source buys no security and would break a seamless
        // NAT-rebind). The path is still registered Unvalidated so it can be
        // challenged. The strict half (PATH-001a, the send-gate: app data only to
        // the peer / a Validated path) is exercised over a real UdpServerTransport
        // in udp_integration.
        use crate::transport::path::PathStateKind;
        let session_id = fixed_session_id();
        let (client_session, server_session) = paired_sessions(session_id);
        let stream_id: TransportStreamId = 1;

        let frame = build_app_frame_on_path(
            &client_session,
            session_id,
            stream_id,
            0,
            0, // stream_offset 0 — first reliable frame on this stream
            7, // a path the receiver has never validated
            b"on-new-path",
        );
        let frame = decode_recv_frame(&frame, session_id);

        let (demux, _ctrl_rx) = StreamDemultiplexer::new(16);
        let demux = Arc::new(demux);
        let streams: Arc<DashMap<u32, Arc<TransportStream>>> = Arc::new(DashMap::new());
        let (deliver_tx, mut deliver_rx) = mpsc::unbounded_channel::<DeliverItem>();
        let undelivered = AtomicU64::new(0);
        let (ack_a, ack_b) = mpsc::channel::<Vec<u8>>(4);
        let transport_send: Arc<ChannelTransport> = Arc::new(ChannelTransport {
            tx: ack_a,
            rx: Mutex::new(ack_b),
        });
        let obs = Observability::new(ObservabilityConfig::default());
        let mut scratch = test_recv_scratch(&obs, 256);

        let (no_link, no_inc_tx) = noop_accept_sinks();
        handle_packet(
            frame,
            session_id,
            &server_session,
            &streams,
            &demux,
            &transport_send,
            &transport_send,
            &deliver_tx,
            &undelivered,
            &mut scratch,
            &obs,
            LegType::Tcp,
            &no_link,
            &no_inc_tx,
            &connected_state(),
        )
        .await;

        // Recv-relax (D10b): the authenticated frame IS delivered, even though
        // path 7 is not validated.
        let item = tokio::time::timeout(std::time::Duration::from_secs(1), deliver_rx.recv())
            .await
            .expect("recv-relax must deliver promptly (no drop / hang)")
            .expect("delivery channel open");
        let (sid, received) = match item {
            DeliverItem::Data(sid, bytes, _) => (sid, bytes),
            DeliverItem::Close(sid) => panic!("unexpected Close({sid}) in deliver channel"),
            DeliverItem::Retire(sid) => panic!("unexpected Retire({sid}) in deliver channel"),
        };
        assert_eq!(sid, stream_id as u32);
        assert_eq!(&received[..], b"on-new-path");
        // The new path is registered Unvalidated for a later challenge. (The
        // ChannelTransport reports no migration candidate, so no challenge is
        // issued here — the server-challenge path is exercised in udp_integration.)
        assert_eq!(
            server_session.path_state(7),
            Some(PathStateKind::Unvalidated),
            "the new path id must be registered for a later challenge"
        );
    }

    #[tokio::test]
    async fn server_challenges_a_migration_candidate() {
        // P4.1 end-to-end over a real UdpServerTransport: app data on a NEW path_id
        // from a NEW source makes the server issue a PATH_VALIDATION challenge TO
        // THAT SOURCE (not the established peer), under the 3× anti-amp cap, and the
        // new path goes Validating. No peer switch (that is P4.2).
        use crate::api::udp_transport::UdpServerTransport;
        use crate::transport::path::PathStateKind;
        use crate::transport::phantom_udp::datagram::{push_datagram, FragmentAssembler};

        let session_id = fixed_session_id();
        let (client_session, server_session) = paired_sessions(session_id);
        let stream_id: TransportStreamId = 1;

        let server_sock = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let peer: std::net::SocketAddr = "127.0.0.1:9".parse().unwrap(); // established (old) peer
        let cand_sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let cand_addr = cand_sock.local_addr().unwrap();

        // Build the server transport and set the candidate by feeding a frame from
        // the candidate source through the demux channel (as the demux would), with
        // enough received bytes that the 3× budget admits a challenge.
        let (tx, rx) = mpsc::channel(8);
        let ust = Arc::new(UdpServerTransport::new(
            server_sock.clone(),
            peer,
            [5u8; 8],
            tx.clone(),
            rx,
        ));
        tx.send((Bytes::from(vec![0u8; 256]), cand_addr))
            .await
            .unwrap();
        let _ = ust.recv_bytes().await.unwrap();
        // M-1: the candidate is committed only on the post-decrypt (authenticated) path, which
        // handle_packet drives in production; mirror that here for the manual setup.
        ust.confirm_authenticated_source();
        assert!(
            ust.has_migration_candidate(),
            "new source must set a candidate"
        );

        // App data on a NEW (unvalidated) path id → the server must challenge it.
        let frame =
            build_app_frame_on_path(&client_session, session_id, stream_id, 0, 0, 1, b"migrated");
        let frame = decode_recv_frame(&frame, session_id);

        let (demux, _ctrl_rx) = StreamDemultiplexer::new(16);
        let demux = Arc::new(demux);
        let streams: Arc<DashMap<u32, Arc<TransportStream>>> = Arc::new(DashMap::new());
        let (deliver_tx, _deliver_rx) = mpsc::unbounded_channel::<DeliverItem>();
        let undelivered = AtomicU64::new(0);
        let obs = Observability::new(ObservabilityConfig::default());
        let mut scratch = test_recv_scratch(&obs, 256);

        let (no_link, no_inc_tx) = noop_accept_sinks();
        handle_packet(
            frame,
            session_id,
            &server_session,
            &streams,
            &demux,
            &ust,
            &ust,
            &deliver_tx,
            &undelivered,
            &mut scratch,
            &obs,
            LegType::Udp,
            &no_link,
            &no_inc_tx,
            &connected_state(),
        )
        .await;

        // The server issued a challenge → path 1 is now Validating.
        assert_eq!(
            server_session.path_state(1),
            Some(PathStateKind::Validating),
            "an unvalidated path on a candidate source must be challenged"
        );
        // ...and the challenge datagram reached the CANDIDATE socket (not the peer).
        let mut buf = vec![0u8; 2048];
        let (n, _from) = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            cand_sock.recv_from(&mut buf),
        )
        .await
        .expect("challenge must reach the candidate")
        .unwrap();
        let mut asm = FragmentAssembler::new();
        let (_hdr, inner) = push_datagram(&mut asm, &buf[..n]).expect("decode envelope");
        let inner = inner.expect("single-datagram challenge");
        // The server emitted this challenge (protect_packet under its send HP
        // key); unmask it from the client side (== the server's send key).
        let pkt = client_session
            .parse_protected(&inner)
            .expect("inner packet");
        assert!(
            pkt.header.flags.contains(PacketFlags::PATH_VALIDATION),
            "the candidate must receive a PATH_VALIDATION challenge"
        );
        assert_eq!(pkt.header.path_id, 1, "challenge must be on the new path");
    }

    #[tokio::test]
    async fn server_challenges_a_passive_rebind_on_path_zero() {
        // M-3: a *passive* NAT rebind keeps `path_id = 0` (the client never called
        // `migrate()`, so it never bumped its send path_id). Path 0 is permanently
        // `Validated`, so the path-id-gated challenge block is skipped — pre-fix the
        // server NEVER challenged the new source, never promoted it, and kept sending
        // downstream to the OLD (now-dead) address → stall. The fix makes detection
        // address-driven: when an authenticated frame arrives on a Validated path AND
        // the transport flags a migration candidate (a new authenticated source), the
        // server issues a PATH_CHALLENGE to that candidate on a RESERVED validation
        // path-id (`REBIND_VALIDATION_PATH_ID`), under the 3× anti-amp cap. Anti-spoof
        // still holds: the candidate is only ever the AEAD-authenticated source, and
        // the challenge only goes there.
        use crate::api::udp_transport::UdpServerTransport;
        use crate::transport::path::PathStateKind;
        use crate::transport::phantom_udp::datagram::{push_datagram, FragmentAssembler};
        use crate::transport::session::REBIND_VALIDATION_PATH_ID;

        let session_id = fixed_session_id();
        let (client_session, server_session) = paired_sessions(session_id);
        let stream_id: TransportStreamId = 1;

        let server_sock = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let peer: std::net::SocketAddr = "127.0.0.1:9".parse().unwrap(); // established (old) peer
        let cand_sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let cand_addr = cand_sock.local_addr().unwrap();

        let (tx, rx) = mpsc::channel(8);
        let ust = Arc::new(UdpServerTransport::new(
            server_sock.clone(),
            peer,
            [5u8; 8],
            tx.clone(),
            rx,
        ));
        // A frame from the rebind source seeds the candidate + its 3× budget.
        tx.send((Bytes::from(vec![0u8; 256]), cand_addr))
            .await
            .unwrap();
        let _ = ust.recv_bytes().await.unwrap();
        ust.confirm_authenticated_source();
        assert!(
            ust.has_migration_candidate(),
            "new source must set a candidate"
        );

        // The reserved validation path is untouched at the start.
        assert_eq!(
            server_session.path_state(REBIND_VALIDATION_PATH_ID),
            None,
            "the rebind validation path must not exist before the rebind is observed"
        );

        // App data on the ESTABLISHED, always-Validated path 0 (passive rebind:
        // path_id unchanged) from the candidate source → the server must STILL
        // challenge the candidate on the reserved validation path-id.
        let frame =
            build_app_frame_on_path(&client_session, session_id, stream_id, 0, 0, 0, b"rebound");
        let frame = decode_recv_frame(&frame, session_id);

        let (demux, _ctrl_rx) = StreamDemultiplexer::new(16);
        let demux = Arc::new(demux);
        let streams: Arc<DashMap<u32, Arc<TransportStream>>> = Arc::new(DashMap::new());
        let (deliver_tx, _deliver_rx) = mpsc::unbounded_channel::<DeliverItem>();
        let undelivered = AtomicU64::new(0);
        let obs = Observability::new(ObservabilityConfig::default());
        let mut scratch = test_recv_scratch(&obs, 256);

        let (no_link, no_inc_tx) = noop_accept_sinks();
        handle_packet(
            frame,
            session_id,
            &server_session,
            &streams,
            &demux,
            &ust,
            &ust,
            &deliver_tx,
            &undelivered,
            &mut scratch,
            &obs,
            LegType::Udp,
            &no_link,
            &no_inc_tx,
            &connected_state(),
        )
        .await;

        // The server issued a challenge on the RESERVED rebind path → it is Validating.
        assert_eq!(
            server_session.path_state(REBIND_VALIDATION_PATH_ID),
            Some(PathStateKind::Validating),
            "a path-0 rebind on a candidate source must be challenged on the reserved id"
        );
        // ...and the challenge datagram reached the CANDIDATE socket (not the peer).
        let mut buf = vec![0u8; 2048];
        let (n, _from) = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            cand_sock.recv_from(&mut buf),
        )
        .await
        .expect("rebind challenge must reach the candidate")
        .unwrap();
        let mut asm = FragmentAssembler::new();
        let (_hdr, inner) = push_datagram(&mut asm, &buf[..n]).expect("decode envelope");
        let inner = inner.expect("single-datagram challenge");
        let pkt = client_session
            .parse_protected(&inner)
            .expect("inner packet");
        assert!(
            pkt.header.flags.contains(PacketFlags::PATH_VALIDATION),
            "the candidate must receive a PATH_VALIDATION challenge"
        );
        assert_eq!(
            pkt.header.path_id, REBIND_VALIDATION_PATH_ID,
            "the passive-rebind challenge must be stamped on the reserved validation path-id"
        );
    }

    #[test]
    fn migration_path_id_never_collides_with_the_rebind_validation_path() {
        // M-3: the client's active-migration counter must never hand back the
        // reserved rebind validation id — otherwise an active migration and a
        // concurrent passive-rebind challenge would share a registry slot and a
        // late echo to one could resolve the other. The counter wraps 254 → 1,
        // skipping both 0 (the handshake path) and 255 (the reserved id).
        use crate::transport::session::REBIND_VALIDATION_PATH_ID;
        let session_id = fixed_session_id();
        let (client_session, _server_session) = paired_sessions(session_id);
        for _ in 0..600 {
            let id = client_session.next_migration_path_id();
            assert_ne!(id, 0, "must never reuse the handshake path");
            assert_ne!(
                id, REBIND_VALIDATION_PATH_ID,
                "must never reuse the reserved rebind validation path"
            );
        }
    }

    /// Build an `ENCRYPTED | ACK` frame (H1, L1-A) from `acker_session`
    /// acknowledging `acked_seq` on `stream_id`, with its own header sequence
    /// `ack_header_seq` (drawn from the acker's send space, distinct from the
    /// acked data sequence). The AEAD plaintext is a single-sequence `Sack`
    /// (the SACK superset of the legacy single-seq ACK). Wire-serialised, ready
    /// for `handle_packet`.
    fn build_encrypted_ack(
        acker_session: &InnerSession,
        session_id: SessionId,
        stream_id: TransportStreamId,
        ack_header_seq: u32,
        acked_seq: u32,
    ) -> Vec<u8> {
        let sack = crate::transport::sack::Sack::from_received(&[acked_seq], 0)
            .expect("single-seq sack")
            .to_wire();
        build_encrypted_ack_with_payload(
            acker_session,
            session_id,
            stream_id,
            ack_header_seq,
            &sack,
        )
    }

    /// Like [`build_encrypted_ack`] but with an arbitrary AEAD plaintext payload
    /// (used to exercise malformed-SACK handling on the sender path).
    fn build_encrypted_ack_with_payload(
        acker_session: &InnerSession,
        session_id: SessionId,
        stream_id: TransportStreamId,
        ack_header_seq: u32,
        payload: &[u8],
    ) -> Vec<u8> {
        let flag_bits = PacketFlags::ENCRYPTED | PacketFlags::ACK;
        let header = PacketHeader::new(
            session_id,
            stream_id,
            ack_header_seq as u64,
            PacketFlags::new(flag_bits),
        )
        .with_epoch(acker_session.current_epoch());
        let ct = acker_session
            .encrypt_packet(&header, payload, &[])
            .expect("encrypt ack");
        PhantomPacket::new(header, ct).to_wire()
    }

    /// Drive a single inbound packet through `handle_packet` against
    /// `server_session` with throwaway delivery/transport wiring. Returns the
    /// throwaway `Observability` handle so a caller can assert on what the
    /// receive path recorded.
    async fn run_recv(
        pkt: PhantomPacket,
        session_id: SessionId,
        server_session: &Arc<InnerSession>,
        streams: &Arc<DashMap<u32, Arc<TransportStream>>>,
    ) -> Arc<Observability> {
        let (demux, _ctrl_rx) = StreamDemultiplexer::new(16);
        let demux = Arc::new(demux);
        let (deliver_tx, _deliver_rx) = mpsc::unbounded_channel::<DeliverItem>();
        let undelivered = AtomicU64::new(0);
        let (ack_a, ack_b) = mpsc::channel::<Vec<u8>>(4);
        let transport: Arc<ChannelTransport> = Arc::new(ChannelTransport {
            tx: ack_a,
            rx: Mutex::new(ack_b),
        });
        let obs = Observability::new(ObservabilityConfig::default());
        let mut scratch = test_recv_scratch(&obs, 64);
        let (no_link, no_inc_tx) = noop_accept_sinks();
        handle_packet(
            pkt,
            session_id,
            server_session,
            streams,
            &demux,
            &transport,
            &transport,
            &deliver_tx,
            &undelivered,
            &mut scratch,
            &obs,
            LegType::Tcp,
            &no_link,
            &no_inc_tx,
            &connected_state(),
        )
        .await;
        obs
    }

    /// Stage a stream with one in-flight reliable segment; returns the stream,
    /// the shared streams map, and the segment's sequence number.
    async fn staged_pending_segment() -> (
        Arc<TransportStream>,
        Arc<DashMap<u32, Arc<TransportStream>>>,
        u32,
    ) {
        let stream_id: TransportStreamId = 1;
        let stream = Arc::new(TransportStream::new(stream_id));
        let seq = stream
            .send_reliable(Bytes::from_static(b"reliable-payload"))
            .await
            .unwrap();
        let _ = stream
            .poll_send(u64::MAX, 0, std::time::Instant::now(), false)
            .await
            .expect("segment in-flight");
        let streams: Arc<DashMap<u32, Arc<TransportStream>>> = Arc::new(DashMap::new());
        streams.insert(stream_id as u32, stream.clone());
        (stream, streams, seq)
    }

    /// **H1 (Invariant 2).** A forged *unauthenticated* ACK — whether bare
    /// (`ACK` flag, empty payload) or carrying a plaintext 4-byte acked-seq —
    /// must NOT retire a pending reliable segment. Pre-fix, the ACK branch ran
    /// before the AEAD gate and trusted `header.sequence`, so an off-path
    /// attacker could silently drop never-acknowledged segments.
    #[tokio::test]
    async fn forged_plaintext_ack_does_not_retire_pending_segment() {
        let session_id = fixed_session_id();
        let (_client, server_session) = paired_sessions(session_id);
        let (stream, streams, seq) = staged_pending_segment().await;
        let stream_id: TransportStreamId = 1;

        // Variant 1: bare ACK, no ENCRYPTED, empty payload, guessed sequence.
        run_recv(
            PhantomPacket::new(
                PacketHeader::new(
                    session_id,
                    stream_id,
                    seq as u64,
                    PacketFlags::new(PacketFlags::ACK),
                ),
                Vec::new(),
            ),
            session_id,
            &server_session,
            &streams,
        )
        .await;
        // Variant 2: ACK with a plaintext 4-byte acked-seq, no ENCRYPTED.
        run_recv(
            PhantomPacket::new(
                PacketHeader::new(
                    session_id,
                    stream_id,
                    999,
                    PacketFlags::new(PacketFlags::ACK),
                ),
                seq.to_be_bytes().to_vec(),
            ),
            session_id,
            &server_session,
            &streams,
        )
        .await;

        assert!(
            stream.ack(seq).await.is_some(),
            "a forged unauthenticated ACK must not retire the pending reliable segment"
        );
    }

    /// **H1 + L1-B.** A forged *unauthenticated* SACK (plaintext `ACK`, no
    /// `ENCRYPTED`) carrying a wide range must neither retire a pending segment NOR
    /// trigger a fast-retransmit: it is dropped by the downgrade defense before the
    /// AEAD gate, so it never reaches the SACK loss detector (which would otherwise
    /// flag segments lost and drive Pass-0). The SACK plaintext is acted on only
    /// after AEAD verify.
    #[tokio::test]
    async fn forged_sack_neither_retires_nor_fast_retransmits() {
        let session_id = fixed_session_id();
        let (_client, server_session) = paired_sessions(session_id);
        let stream_id: TransportStreamId = 1;

        // Stage offsets 0..=5, all in flight.
        let stream = Arc::new(TransportStream::new(stream_id));
        for _ in 0..6u32 {
            stream
                .send_reliable(Bytes::from_static(b"x"))
                .await
                .unwrap();
            let _ = stream
                .poll_send(u64::MAX, 0, std::time::Instant::now(), false)
                .await
                .expect("in-flight");
        }
        let streams: Arc<DashMap<u32, Arc<TransportStream>>> = Arc::new(DashMap::new());
        streams.insert(stream_id as u32, stream.clone());
        assert_eq!(stream.pending_send_count().await, 6);

        // Forged PLAINTEXT ACK (no ENCRYPTED) carrying a SACK over offset {5}.
        // If acted on, it would retire offset 5 AND flag offsets 0,1,2 lost.
        let forged_sack = crate::transport::sack::Sack::from_received(&[5], 0)
            .expect("sack")
            .to_wire();
        run_recv(
            PhantomPacket::new(
                PacketHeader::new(
                    session_id,
                    stream_id,
                    4242,
                    PacketFlags::new(PacketFlags::ACK),
                ),
                forged_sack, // plaintext — NOT encrypted
            ),
            session_id,
            &server_session,
            &streams,
        )
        .await;

        // Nothing retired: all six segments remain buffered.
        assert_eq!(
            stream.pending_send_count().await,
            6,
            "a forged unauthenticated SACK must not retire any segment (H1)"
        );
        // No fast-retransmit: nothing was flagged lost, so poll_send (all sent, no
        // new data) reports an idle stream rather than a Pass-0 retransmit.
        assert_eq!(
            stream
                .poll_send(u64::MAX, 0, std::time::Instant::now(), false)
                .await
                .err(),
            Some(SendBlocked::Idle),
            "a forged SACK must not trigger a fast-retransmit (no segment flagged lost)"
        );
    }

    /// **Loss is fed once.** A SACK that declares segments lost must NOT itself feed
    /// BBR's loss signal — loss is fed exactly once per loss event, at the *retransmission*
    /// point (`drain_streams`'s `if seg.retransmit`), which covers both SACK-gap and RTO
    /// retransmits. Feeding it again here, at SACK-gap detection, double-decrements the
    /// purely-incremental `inflight_bytes`: a lost segment fed at both detection and
    /// retransmission nets a permanent inflight under-count, inflating the cwnd budget
    /// (`cwnd − inflight`) → over-send, accumulating with every SACK-gap loss. Here a sender
    /// has six in-flight segments; an authenticated SACK acking offset {5} retires segment 5
    /// and flags 0,1,2 lost. Afterward `inflight_bytes` must drop by ONLY the retired
    /// segment — never by the three flagged-lost ones (which the bug would subtract here).
    #[tokio::test]
    async fn loss_declaring_sack_does_not_feed_bbr_loss_at_detection() {
        tokio::time::pause();
        let session_id = fixed_session_id();
        let (client_session, server_session) = paired_sessions(session_id);
        let stream_id: TransportStreamId = 1;

        // Stage six in-flight reliable segments on the sender, mirroring the pump's
        // inflight accounting (`on_packet_sent` per sent segment).
        let stream = Arc::new(TransportStream::new(stream_id));
        let mut seg_size = 0u64;
        for _ in 0..6u32 {
            stream
                .send_reliable(Bytes::from_static(b"x"))
                .await
                .unwrap();
            let seg = stream
                .poll_send(u64::MAX, 0, std::time::Instant::now(), false)
                .await
                .expect("in-flight");
            seg_size = seg.data.len() as u64;
            server_session.on_packet_sent(seg_size);
        }
        let streams: Arc<DashMap<u32, Arc<TransportStream>>> = Arc::new(DashMap::new());
        streams.insert(stream_id as u32, stream.clone());
        let inflight_before = server_session.bandwidth_snapshot().inflight_bytes;
        assert_eq!(inflight_before, 6 * seg_size, "six segments in flight");

        // Authenticated SACK acking offset {5}: retires segment 5, flags 0,1,2 lost.
        let ack = build_encrypted_ack(&client_session, session_id, stream_id, 4242, 5);
        let pkt = decode_recv_frame(&ack, session_id);
        run_recv(pkt, session_id, &server_session, &streams).await;

        let inflight_after = server_session.bandwidth_snapshot().inflight_bytes;
        assert_eq!(
            inflight_after,
            inflight_before - seg_size,
            "inflight must drop by ONLY the retired (acked) segment; double-feeding loss at \
             SACK-gap detection would over-decrement it by the three flagged-lost segments"
        );
    }

    /// **H1 positive control.** A genuine `ENCRYPTED | ACK` frame from the peer,
    /// whose AEAD payload carries the acked data sequence, retires the matching
    /// pending segment after AEAD verify. The ACK's own `header.sequence`
    /// (`ack_header_seq`) is deliberately different from the acked sequence to
    /// prove the handler reads the authenticated payload, not the header.
    #[tokio::test]
    async fn authenticated_ack_retires_pending_segment() {
        let session_id = fixed_session_id();
        let (client_session, server_session) = paired_sessions(session_id);
        let (stream, streams, seq) = staged_pending_segment().await;
        let stream_id: TransportStreamId = 1;

        let ack_header_seq = seq.wrapping_add(54_321);
        let frame =
            build_encrypted_ack(&client_session, session_id, stream_id, ack_header_seq, seq);
        let ack_pkt = decode_recv_frame(&frame, session_id);
        run_recv(ack_pkt, session_id, &server_session, &streams).await;

        assert!(
            stream.ack(seq).await.is_none(),
            "an authenticated ACK must retire the acked pending segment"
        );
    }

    /// The per-path RTT gauge behind `MetricsSnapshotFfi::rtt_us_path_0` must be
    /// fed from the SACK path — it was a registered-but-never-recorded
    /// instrument before this wiring. The sample is labelled with the inbound
    /// `header.path_id` (the same id space the path registry and
    /// `record_path_validation` use), which is why it lands on path 0 here.
    #[tokio::test]
    async fn authenticated_sack_publishes_an_rtt_sample() {
        let session_id = fixed_session_id();
        let (client_session, server_session) = paired_sessions(session_id);
        let (_stream, streams, seq) = staged_pending_segment().await;
        let stream_id: TransportStreamId = 1;

        // Give the segment a measurable age so the propagation sample is > 0.
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;

        let frame = build_encrypted_ack(&client_session, session_id, stream_id, 777, seq);
        let ack_pkt = decode_recv_frame(&frame, session_id);
        let obs = run_recv(ack_pkt, session_id, &server_session, &streams).await;

        assert!(
            obs.snapshot().rtt_us_path_0 > 0,
            "retiring a never-retransmitted segment must publish an RTT sample"
        );
    }

    /// `Sack::ack_delay_us` is a number the *peer* writes, and it is the only
    /// term in the RTT sample this endpoint did not measure. The gauge behind
    /// `MetricsSnapshotFfi::rtt_us_path_0` is what an operator reads to judge a
    /// path, so a peer that can drive it at will turns "the path got faster"
    /// and "the peer said so" into the same reading. The estimator's minimum
    /// filter already refuses a peer-supplied subtraction that would undercut
    /// what the local clock saw (RFC 9002 §5.2/§5.3); the gauge must be fed the
    /// same guarded figure rather than a second, unguarded subtraction.
    ///
    /// The segment is deliberately aged before the acknowledgement arrives, so
    /// the local clock has a floor under it that no scheduling delay can lower:
    /// the assertion is that the published sample is at least the age this
    /// endpoint itself observed, whatever the peer claims about its own delay.
    #[tokio::test]
    async fn a_peers_claimed_ack_delay_cannot_erase_the_rtt_gauge() {
        let session_id = fixed_session_id();
        let (client_session, server_session) = paired_sessions(session_id);
        let (_stream, streams, seq) = staged_pending_segment().await;
        let stream_id: TransportStreamId = 1;

        // The locally observed floor: the acknowledgement cannot arrive before
        // this much of the segment's life has elapsed.
        let observed_floor = std::time::Duration::from_millis(20);
        tokio::time::sleep(observed_floor).await;

        // The peer claims it sat on the acknowledgement for over an hour —
        // orders of magnitude more than the round trip it rides on.
        let sack = crate::transport::sack::Sack::from_received(&[seq], u32::MAX)
            .expect("single-seq sack")
            .to_wire();
        let frame =
            build_encrypted_ack_with_payload(&client_session, session_id, stream_id, 777, &sack);
        let ack_pkt = decode_recv_frame(&frame, session_id);
        let obs = run_recv(ack_pkt, session_id, &server_session, &streams).await;

        let published = obs.snapshot().rtt_us_path_0;
        assert!(
            published >= observed_floor.as_micros() as u64,
            "a peer's claimed ack delay must not push the published RTT below \
             the {} µs this endpoint measured itself; got {} µs",
            observed_floor.as_micros(),
            published
        );
    }

    /// The same guard, on the arm this endpoint spends its life in.
    ///
    /// The test above acknowledges the *first* segment of the session, so the
    /// estimator's minimum filter is still unseeded and the guard's "no local
    /// measurement to protect yet" arm ignores the peer's claim wholesale. That
    /// arm is indistinguishable from having no guard at all — both publish the
    /// raw locally timed round trip — so it cannot show that the guard is wired
    /// into the pump. Every acknowledgement after the first takes the other arm,
    /// where the claim *is* subtracted and only the floor bounds it, and that is
    /// the arm an operator's gauge actually rides on.
    ///
    /// So: seed the filter with a short round trip, then let a much longer one
    /// arrive carrying a claim the guard must subtract in full. What the gauge
    /// publishes is then the endpoint's own round trip less exactly that claim,
    /// which the wall time this test measures around the exchange bounds from
    /// above — arithmetic rather than a tuned constant, and never below the
    /// floor already timed.
    ///
    /// The claim is *derived* from the two clock readings rather than fixed,
    /// which is what keeps the arm under test from moving. Half the headroom
    /// between the floor and a round trip already known to have elapsed is a
    /// claim §5.3 must subtract whole, whatever a loaded machine did to either
    /// sleep. A constant chosen against the sleeps instead would quietly slide
    /// the test onto the *other* arm the moment the seeding round trip
    /// overshot — where it would fail while nothing was wrong.
    #[tokio::test]
    async fn a_seeded_paths_gauge_bounds_what_a_peers_ack_delay_subtracts() {
        let session_id = fixed_session_id();
        let (client_session, server_session) = paired_sessions(session_id);
        let stream_id: TransportStreamId = 1;

        // Round one: an honest acknowledgement, claiming no delay, whose only
        // job is to give the estimator a round trip it timed itself. What the
        // gauge publishes for it is that same figure, which is therefore the
        // floor every later sample is measured against.
        let (_seed_stream, seed_streams, seed_seq) = staged_pending_segment().await;
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let seed_frame = build_encrypted_ack(&client_session, session_id, stream_id, 501, seed_seq);
        let seed_pkt = decode_recv_frame(&seed_frame, session_id);
        let seeded = run_recv(seed_pkt, session_id, &server_session, &seed_streams).await;
        let floor_us = seeded.snapshot().rtt_us_path_0;
        assert!(
            floor_us > 0,
            "the seeding acknowledgement must leave the estimator with a timed round trip"
        );

        // Round two, on the same session and so against that floor.
        let round_started = std::time::Instant::now();
        let (_stream, streams, seq) = staged_pending_segment().await;
        // Taken once the segment is staged, so the send stamp the pump measures
        // from is at or before this reading.
        let staged_at = std::time::Instant::now();
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        // The acknowledgement has not been handled yet, so the round trip the
        // pump will time is at least this wide.
        let at_least_us = staged_at.elapsed().as_micros() as u64;
        let claimed_delay_us = at_least_us.saturating_sub(floor_us) / 2;
        assert!(
            claimed_delay_us > 0,
            "the second round trip ({at_least_us} µs) must leave headroom above the \
             {floor_us} µs floor for a claim the guard is obliged to subtract"
        );
        let claimed_delay_field =
            u32::try_from(claimed_delay_us).expect("claim fits the wire field");
        let sack = crate::transport::sack::Sack::from_received(&[seq], claimed_delay_field)
            .expect("single-seq sack")
            .to_wire();
        let frame =
            build_encrypted_ack_with_payload(&client_session, session_id, stream_id, 502, &sack);
        let ack_pkt = decode_recv_frame(&frame, session_id);
        let obs = run_recv(ack_pkt, session_id, &server_session, &streams).await;
        // Measured after the exchange and around all of it, so it strictly
        // contains the interval the pump timed internally.
        let round_span_us = round_started.elapsed().as_micros() as u64;

        let published = obs.snapshot().rtt_us_path_0;
        assert!(
            published.saturating_add(claimed_delay_us) <= round_span_us,
            "the gauge published {published} µs for a round trip of at most {round_span_us} µs \
             while the peer claimed {claimed_delay_us} µs of ack delay — the claim was not \
             subtracted, so the pump is not applying the estimator's bound at all"
        );
        assert!(
            published >= floor_us,
            "the gauge published {published} µs, below the {floor_us} µs round trip this \
             endpoint had already timed itself"
        );
    }

    /// The other half of the seeded arm: the subtraction stops at the floor.
    ///
    /// The test above shows an honest claim reaching the gauge; this one shows a
    /// dishonest one being refused, on the same arm. The distinction matters
    /// because the two failures look nothing alike from the pump's side — a
    /// guard that subtracts nothing and a guard that subtracts everything both
    /// publish a plausible number — and only one existing test covers the
    /// refusal, on the *unseeded* arm, where the claim is ignored wholesale for
    /// a different reason (RFC 9002 §5.2's first-sample rule) and no floor is
    /// consulted at all. An endpoint spends one acknowledgement there and the
    /// rest of its life here.
    ///
    /// So: seed the filter, then claim an ack delay of an hour on a round trip
    /// of tens of milliseconds. §5.3 permits a subtraction only where the
    /// remainder stays at or above the floor, and no part of an hour does, so
    /// the whole claim is dropped and the endpoint's own round trip stands.
    /// Subtracting it regardless — what this call site used to do on its own
    /// terms — saturates the reading at zero, where the pump's zero guard
    /// discards it and the gauge reports nothing at all for the path. A fresh
    /// `Observability` per acknowledgement is what makes that visible rather
    /// than leaving the previous honest sample standing in the slot.
    ///
    /// What the published figure is checked against is the endpoint's own round
    /// trip, bracketed from both sides by clock readings this test takes around
    /// the exchange: the interval from the segment being staged to just before
    /// the acknowledgement is handled sits strictly inside the interval the pump
    /// times, which in turn sits inside the span measured around the whole
    /// round. No constant is tuned, so neither a fast machine nor a stalled one
    /// can move the verdict. Note that the *seeding* sample is deliberately not
    /// the reference: the floor is a minimum, and a later round trip is free to
    /// come in under an earlier one and become the new minimum.
    #[tokio::test]
    async fn a_seeded_paths_gauge_refuses_a_claim_that_would_undercut_the_floor() {
        // An hour, in a field that is a u32 of microseconds — beyond any round
        // trip a loopback test can produce, so no scheduling delay can turn this
        // into a claim the floor would legitimately accommodate.
        const CLAIMED_DELAY_US: u64 = 3_600_000_000;
        let session_id = fixed_session_id();
        let (client_session, server_session) = paired_sessions(session_id);
        let stream_id: TransportStreamId = 1;

        // Round one seeds the estimator's minimum filter, exactly as above.
        let (_seed_stream, seed_streams, seed_seq) = staged_pending_segment().await;
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let seed_frame = build_encrypted_ack(&client_session, session_id, stream_id, 601, seed_seq);
        let seed_pkt = decode_recv_frame(&seed_frame, session_id);
        let seeded = run_recv(seed_pkt, session_id, &server_session, &seed_streams).await;
        assert!(
            seeded.snapshot().rtt_us_path_0 > 0,
            "the seeding acknowledgement must leave the estimator with a timed round trip"
        );

        // Round two carries the impossible claim.
        let round_started = std::time::Instant::now();
        let (_stream, streams, seq) = staged_pending_segment().await;
        // Taken once the segment is staged, so the send stamp the pump measures
        // from is at or before this reading.
        let staged_at = std::time::Instant::now();
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let sack = crate::transport::sack::Sack::from_received(&[seq], CLAIMED_DELAY_US as u32)
            .expect("single-seq sack")
            .to_wire();
        let frame =
            build_encrypted_ack_with_payload(&client_session, session_id, stream_id, 602, &sack);
        let ack_pkt = decode_recv_frame(&frame, session_id);
        // Taken before the acknowledgement is handled, so the pump's own
        // acknowledgement stamp is at or after this reading: the round trip it
        // times is at least this wide.
        let at_least_us = staged_at.elapsed().as_micros() as u64;
        let obs = run_recv(ack_pkt, session_id, &server_session, &streams).await;
        let at_most_us = round_started.elapsed().as_micros() as u64;

        let published = obs.snapshot().rtt_us_path_0;
        assert!(
            published >= at_least_us,
            "the gauge published {published} µs for an acknowledgement claiming \
             {CLAIMED_DELAY_US} µs of ack delay, below the {at_least_us} µs this endpoint's \
             own clock had already run — the claim was subtracted with nothing bounding it \
             (a published 0 means the subtraction reached zero and the sample was discarded, \
             leaving the path with no reading at all)"
        );
        assert!(
            published <= at_most_us,
            "the gauge published {published} µs for a round trip of at most {at_most_us} µs"
        );
    }

    /// **L1-A SACK end-to-end (gap retire).** Stage segments 0..=5 on the sender,
    /// deliver one authenticated `ENCRYPTED | ACK` carrying a SACK over the
    /// received set {0,1,2,4,5} (gap at 3), and assert the sender retires exactly
    /// those five segments from its send buffer — keeping only the gap segment 3.
    /// This proves the SACK retires MULTIPLE segments in one ACK (vs. the legacy
    /// single-seq ACK).
    #[tokio::test]
    async fn authenticated_sack_retires_all_covered_segments_skipping_gap() {
        let session_id = fixed_session_id();
        let (client_session, server_session) = paired_sessions(session_id);
        let stream_id: TransportStreamId = 1;

        // Sender stages segments 0..=5, all in-flight.
        let stream = Arc::new(TransportStream::new(stream_id));
        for i in 0..6u32 {
            let seq = stream
                .send_reliable(Bytes::from(format!("seg-{i}")))
                .await
                .unwrap();
            assert_eq!(seq, i);
            let _ = stream
                .poll_send(u64::MAX, 0, std::time::Instant::now(), false)
                .await
                .expect("in-flight");
        }
        let streams: Arc<DashMap<u32, Arc<TransportStream>>> = Arc::new(DashMap::new());
        streams.insert(stream_id as u32, stream.clone());
        assert_eq!(stream.pending_send_count().await, 6);

        // The receiver (client_session) emits a SACK over {0,1,2,4,5}.
        let sack = crate::transport::sack::Sack::from_received(&[0, 1, 2, 4, 5], 777)
            .expect("sack")
            .to_wire();
        let frame = build_encrypted_ack_with_payload(
            &client_session,
            session_id,
            stream_id,
            9_999, // ACK header seq distinct from the acked data seqs
            &sack,
        );
        let ack_pkt = decode_recv_frame(&frame, session_id);
        run_recv(ack_pkt, session_id, &server_session, &streams).await;

        // Exactly the gap segment (3) remains.
        assert_eq!(
            stream.pending_send_count().await,
            1,
            "SACK must retire all five covered segments at once"
        );
        for retired in [0u32, 1, 2, 4, 5] {
            assert!(
                stream.ack(retired).await.is_none(),
                "seq {retired} should have been retired by the SACK"
            );
        }
        assert!(
            stream.ack(3).await.is_some(),
            "the gap segment 3 must remain buffered"
        );
    }

    /// **L1-A malformed-SACK robustness.** An authenticated (post-AEAD) but
    /// structurally malformed SACK payload — here a truncated 5-byte blob — must
    /// be dropped on the sender path WITHOUT panic and retire NOTHING. Post-AEAD
    /// the frame is authenticated, but a buggy peer must not crash us.
    #[tokio::test]
    async fn malformed_sack_is_dropped_and_retires_nothing() {
        let session_id = fixed_session_id();
        let (client_session, server_session) = paired_sessions(session_id);
        let (stream, streams, seq) = staged_pending_segment().await;
        let stream_id: TransportStreamId = 1;

        // 5 bytes < MIN_WIRE_LEN (14) → Sack::from_wire returns Truncated.
        let bad_payload = vec![0u8; 5];
        let frame = build_encrypted_ack_with_payload(
            &client_session,
            session_id,
            stream_id,
            1234,
            &bad_payload,
        );
        let ack_pkt = decode_recv_frame(&frame, session_id);
        // Must not panic.
        run_recv(ack_pkt, session_id, &server_session, &streams).await;

        assert!(
            stream.ack(seq).await.is_some(),
            "a malformed SACK must retire nothing — the pending segment stays buffered"
        );
    }

    /// **L1-A ack_delay plumbing.** A reliable data packet driven through the
    /// receiver's `handle_packet` produces an `ENCRYPTED | ACK` frame on the wire
    /// whose decoded SACK has a populated (non-zero) `ack_delay_us` — proving the
    /// field, previously always 0, is now plumbed end-to-end.
    #[tokio::test]
    async fn receiver_emits_sack_with_populated_ack_delay() {
        let session_id = fixed_session_id();
        // Two paired sessions sharing keys so the receiver's ACK decrypts under
        // the sender's session.
        let (sender_session, receiver_session) = paired_sessions(session_id);
        let stream_id: TransportStreamId = 1;

        // Build a reliable data packet from the sender at sequence 7 (stream_offset
        // == sequence == 7 via build_app_frame, so the SACK's largest_acked is 7).
        let data_seq = 7u32;
        let data_pkt = decode_recv_frame(
            &build_app_frame(
                &sender_session,
                session_id,
                stream_id,
                data_seq,
                b"hello-reliable",
            ),
            session_id,
        );

        // Wiring with a capturable ACK transport.
        let (demux, _ctrl_rx) = StreamDemultiplexer::new(16);
        let demux = Arc::new(demux);
        let streams: Arc<DashMap<u32, Arc<TransportStream>>> = Arc::new(DashMap::new());
        let (deliver_tx, _deliver_rx) = mpsc::unbounded_channel::<DeliverItem>();
        let undelivered = AtomicU64::new(0);
        let (ack_a, ack_b) = mpsc::channel::<Vec<u8>>(4);
        let transport: Arc<ChannelTransport> = Arc::new(ChannelTransport {
            tx: ack_a,
            rx: Mutex::new(ack_b),
        });
        let obs = Observability::new(ObservabilityConfig::default());
        let mut scratch = test_recv_scratch(&obs, 64);
        let (no_link, no_inc_tx) = noop_accept_sinks();
        handle_packet(
            data_pkt,
            session_id,
            &receiver_session,
            &streams,
            &demux,
            &transport,
            &transport,
            &deliver_tx,
            &undelivered,
            &mut scratch,
            &obs,
            LegType::Tcp,
            &no_link,
            &no_inc_tx,
            &connected_state(),
        )
        .await;

        // Pull the emitted ACK frame off the transport and decode the SACK.
        let ack_frame = transport
            .rx
            .lock()
            .await
            .recv()
            .await
            .expect("an ACK frame must have been emitted");
        // The receiver pump emitted this ACK with header protection; unmask from
        // the sender side (== the receiver's send HP key).
        let ack_pkt = sender_session
            .parse_protected(&ack_frame)
            .expect("parse emitted ack");
        assert!(ack_pkt.header.flags.contains(PacketFlags::ACK));
        // Decrypt under the sender's session (shared keys) to read the SACK.
        let plain = sender_session
            .decrypt_packet(&ack_pkt.header, &ack_pkt.payload, &[])
            .expect("decrypt emitted ack");
        let sack = crate::transport::sack::Sack::from_wire(&plain).expect("decode emitted sack");
        assert_eq!(sack.largest_acked, data_seq, "SACK must ack the data seq");
        assert!(sack.acks(data_seq));
        // The field is plumbed: ack_delay_us is the coarse recv-to-emit hold.
        // It is derived from `now − recv_at` and is therefore populated (the
        // assertion is on the field being threaded through, not a tight bound).
        let _ = sack.ack_delay_us;
    }

    /// **H1 session binding.** A frame whose `header.session_id` does not match
    /// the negotiated session must be dropped by the per-frame guard before any
    /// state mutation — pre-fix the ACK was processed with no session check.
    #[tokio::test]
    async fn ack_with_wrong_session_id_is_dropped() {
        let session_id = fixed_session_id();
        let (_client, server_session) = paired_sessions(session_id);
        let (stream, streams, seq) = staged_pending_segment().await;
        let stream_id: TransportStreamId = 1;

        let wrong_id = SessionId::from_bytes([0x11; 32]);
        run_recv(
            PhantomPacket::new(
                PacketHeader::new(
                    wrong_id,
                    stream_id,
                    seq as u64,
                    PacketFlags::new(PacketFlags::ACK),
                ),
                Vec::new(),
            ),
            session_id,
            &server_session,
            &streams,
        )
        .await;

        assert!(
            stream.ack(seq).await.is_some(),
            "an ACK for a different session id must not retire the segment"
        );
    }

    #[tokio::test]
    async fn v2_recv_drops_unencrypted_non_empty_post_handshake_payload() {
        // Downgrade defense: a V2 application-data packet WITHOUT the
        // ENCRYPTED flag but with a non-empty plaintext-looking payload
        // must be dropped, mirroring the V1 invariant.
        let session_id = fixed_session_id();
        let (_, server_session) = paired_sessions(session_id);

        let stream_id: TransportStreamId = 2;
        let bad_header = PacketHeader::new(
            session_id,
            stream_id,
            0,
            PacketFlags::new(PacketFlags::RELIABLE), // no ENCRYPTED
        );
        let bad_packet = PhantomPacket::new(bad_header, b"leaked-cleartext".to_vec());

        let (demux, _ctrl_rx) = StreamDemultiplexer::new(16);
        let demux = Arc::new(demux);
        let streams: Arc<DashMap<u32, Arc<TransportStream>>> = Arc::new(DashMap::new());
        let (deliver_tx, mut deliver_rx) = mpsc::unbounded_channel::<DeliverItem>();
        let undelivered = AtomicU64::new(0);
        let (ack_a, ack_b) = mpsc::channel::<Vec<u8>>(4);
        let transport_send: Arc<ChannelTransport> = Arc::new(ChannelTransport {
            tx: ack_a,
            rx: Mutex::new(ack_b),
        });

        let obs = Observability::new(ObservabilityConfig::default());
        let mut scratch = test_recv_scratch(&obs, 256);
        let (no_link, no_inc_tx) = noop_accept_sinks();
        handle_packet(
            bad_packet,
            session_id,
            &server_session,
            &streams,
            &demux,
            &transport_send,
            &transport_send,
            &deliver_tx,
            &undelivered,
            &mut scratch,
            &obs,
            LegType::Tcp,
            &no_link,
            &no_inc_tx,
            &connected_state(),
        )
        .await;

        // Nothing should have been handed to the delivery task, and the backlog
        // counter must stay at zero (the packet was dropped before hand-off).
        assert!(
            deliver_rx.try_recv().is_err(),
            "unencrypted post-handshake payload must NOT be handed off for delivery"
        );
        assert_eq!(undelivered.load(Ordering::Acquire), 0);
    }

    /// Seal an `ENCRYPTED | CONTROL` frame from the client side carrying `plaintext`
    /// as the control body, Padme-padded exactly as the live emitter pads it. Used by
    /// the control-frame tests to feed hand-built bodies — including ones no emitter
    /// would ever produce — through the real receive path.
    fn build_control_frame(
        client_session: &InnerSession,
        session_id: SessionId,
        body: &[u8],
    ) -> PhantomPacket {
        let mut flag_bits = PacketFlags::ENCRYPTED | PacketFlags::CONTROL;
        let mut plaintext = body.to_vec();
        let trailer = shaping::padding_trailer_len(plaintext.len(), PaddingPolicy::Padme);
        if trailer > 0 {
            shaping::append_padding(&mut plaintext, trailer);
            flag_bits |= PacketFlags::PADDED;
        }
        let header = PacketHeader::new(
            session_id,
            RAW_APP_STREAM_ID as TransportStreamId,
            client_session.next_send_pn(),
            PacketFlags::new(flag_bits),
        )
        .with_epoch(client_session.current_epoch());
        let ciphertext = client_session
            .encrypt_packet(&header, &plaintext, &[])
            .expect("seal control frame");
        PhantomPacket::new(header, ciphertext)
    }

    /// An in-session control frame is dispatched on a **fixed** enumeration of subtype
    /// bytes, and a subtype outside it is dropped.
    ///
    /// The failure this pins is not "we ignored something we did not understand" — it is
    /// the opposite. `handle_packet` ends in a fall-through that hands any non-empty
    /// plaintext to the application, so a control body that no branch claims does not
    /// vanish: it arrives at `recv()` as a byte of the caller's stream. A peer speaking a
    /// later revision of the subtype registry would silently corrupt the byte stream of
    /// one speaking an earlier one. The subtype registry is only an extension point if
    /// the unknown arm returns.
    #[tokio::test]
    async fn control_frame_with_unknown_subtype_is_not_delivered_as_application_data() {
        let session_id = fixed_session_id();
        let (client_session, server_session) = paired_sessions(session_id);

        // 0xFE is assigned to nothing and never will be by accident — the registry
        // grows from the bottom.
        let pkt = build_control_frame(&client_session, session_id, &[0xFE]);

        let (demux, _ctrl_rx) = StreamDemultiplexer::new(16);
        let demux = Arc::new(demux);
        let streams: Arc<DashMap<u32, Arc<TransportStream>>> = Arc::new(DashMap::new());
        let (deliver_tx, mut deliver_rx) = mpsc::unbounded_channel::<DeliverItem>();
        let undelivered = AtomicU64::new(0);
        let (ack_a, ack_b) = mpsc::channel::<Vec<u8>>(4);
        let transport: Arc<ChannelTransport> = Arc::new(ChannelTransport {
            tx: ack_a,
            rx: Mutex::new(ack_b),
        });
        let obs = Observability::new(ObservabilityConfig::default());
        let mut scratch = test_recv_scratch(&obs, 64);
        let (no_link, no_inc_tx) = noop_accept_sinks();
        handle_packet(
            pkt,
            session_id,
            &server_session,
            &streams,
            &demux,
            &transport,
            &transport,
            &deliver_tx,
            &undelivered,
            &mut scratch,
            &obs,
            LegType::Tcp,
            &no_link,
            &no_inc_tx,
            &connected_state(),
        )
        .await;

        assert!(
            deliver_rx.try_recv().is_err(),
            "an unknown control subtype must be dropped, never handed to the application"
        );
        assert_eq!(
            undelivered.load(Ordering::Acquire),
            0,
            "a dropped control frame must not be charged to the delivery backlog"
        );
    }

    /// Run one inbound packet through `handle_packet` and report both what was handed
    /// to the delivery task and whether the receive path recorded the peer's close.
    async fn run_recv_watching_close(
        pkt: PhantomPacket,
        session_id: SessionId,
        server_session: &Arc<InnerSession>,
    ) -> Option<DeliverItem> {
        let (demux, _ctrl_rx) = StreamDemultiplexer::new(16);
        let demux = Arc::new(demux);
        let streams: Arc<DashMap<u32, Arc<TransportStream>>> = Arc::new(DashMap::new());
        let (deliver_tx, mut deliver_rx) = mpsc::unbounded_channel::<DeliverItem>();
        let undelivered = AtomicU64::new(0);
        let (ack_a, ack_b) = mpsc::channel::<Vec<u8>>(4);
        let transport: Arc<ChannelTransport> = Arc::new(ChannelTransport {
            tx: ack_a,
            rx: Mutex::new(ack_b),
        });
        let obs = Observability::new(ObservabilityConfig::default());
        let mut scratch = test_recv_scratch(&obs, 64);
        let (no_link, no_inc_tx) = noop_accept_sinks();
        handle_packet(
            pkt,
            session_id,
            server_session,
            &streams,
            &demux,
            &transport,
            &transport,
            &deliver_tx,
            &undelivered,
            &mut scratch,
            &obs,
            LegType::Tcp,
            &no_link,
            &no_inc_tx,
            &connected_state(),
        )
        .await;
        deliver_rx.try_recv().ok()
    }

    /// The close frame the live emitter actually puts on the wire: an
    /// `ENCRYPTED | CONTROL` packet whose sealed plaintext is the single
    /// [`ControlSubtype::CLOSE`] byte, header-protected, padded — and **the same size
    /// as an ordinary one-byte reliable application write from the same session**.
    ///
    /// That last clause is the assertion this test exists for, and it is the opposite
    /// of what the emitter's documentation used to claim. Padding was described as
    /// putting the close on a size nothing else emits; a default session's one-byte
    /// reliable write produces the identical datagram, because the padded control
    /// plaintext and a four-byte stream offset plus one application byte are both five
    /// bytes. So the close is *not* distinguishable by size alone from every other
    /// frame — only from most of them.
    ///
    /// What padding does buy, stated no wider than it is: the wire size no longer
    /// carries the control body's length. An unpadded control frame is exactly its
    /// plaintext length read off the wire, so a later subtype with a two- or
    /// three-byte body would be a different size and an observer counting bytes could
    /// tell them apart. What it does not buy is hiding that a session ended — three
    /// copies back to back followed by silence is a pattern, not a size, and no amount
    /// of per-frame padding removes a pattern.
    ///
    /// Both halves are measured off emitters rather than recomputed from the padding
    /// step. The earlier version of this test built its comparison size by calling
    /// `padding_trailer_len` itself, which is the same function the emitter calls: it
    /// compared one copy of the padding logic against another, and would have been
    /// satisfied by whatever that function did. Here the close comes out of
    /// `send_control_close` and the frame it is compared against comes out of the
    /// ordinary reliable drain, so the equality is a statement about two emitters.
    #[tokio::test]
    async fn a_close_frame_is_padded_and_shares_its_size_with_a_one_byte_reliable_write() {
        use crate::crypto::adaptive_crypto::AEAD_OVERHEAD;

        let session_id = fixed_session_id();
        let (client_session, server_session) = paired_sessions(session_id);
        let (client_transport, server_transport) = ChannelTransport::pair();
        let client_transport = Arc::new(client_transport);
        let obs = Observability::new(ObservabilityConfig::default());

        assert!(
            send_control_close(&client_transport, &client_session, session_id, &obs).await,
            "sealing and sending a close frame must succeed on a healthy session"
        );
        let close_wire = server_transport
            .recv_bytes()
            .await
            .expect("the close frame reaches the peer");

        // The counterexample, emitted by the ordinary data path of the same session —
        // default shaping, so `PaddingPolicy::None` and no trailer of its own.
        let stream = Arc::new(TransportStream::new(1));
        stream
            .send_reliable(Bytes::from_static(b"x"))
            .await
            .expect("one application byte");
        let streams: Arc<DashMap<u32, Arc<TransportStream>>> = Arc::new(DashMap::new());
        streams.insert(1u32, stream);
        drain_streams_priority_ordered(
            &client_transport,
            &client_session,
            session_id,
            &streams,
            &obs,
        )
        .await;
        let data_wire = server_transport
            .recv_bytes()
            .await
            .expect("the one-byte write reaches the peer");

        let bare = PacketHeader::SIZE + CONTROL_SUBTYPE_LEN + AEAD_OVERHEAD;
        assert!(
            close_wire.len() > bare,
            "an unpadded close frame is {bare} B, which is its exact plaintext length \
             read off the wire; got {} B",
            close_wire.len()
        );
        assert_eq!(
            close_wire.len(),
            data_wire.len(),
            "the close and a one-byte reliable write are one size on the wire, so a \
             claim that the padded close lands on a size nothing else emits is false — \
             and a reader who believed it would misjudge what the frame leaks"
        );

        let pkt = server_session
            .parse_protected(&close_wire)
            .expect("the close frame is header-protected like any other packet");
        assert!(
            pkt.header.flags.contains(PacketFlags::ENCRYPTED),
            "a close frame must be ENCRYPTED — the recv gate drops anything else (Inv-2)"
        );
        assert!(pkt.header.flags.contains(PacketFlags::CONTROL));
        assert!(
            pkt.header.flags.contains(PacketFlags::PADDED),
            "the padding trailer must be announced so the receiver strips it"
        );
        let plaintext = server_session
            .decrypt_packet(&pkt.header, &pkt.payload, &pkt.extensions)
            .expect("the peer's key opens it");
        assert!(
            plaintext.len() > CONTROL_SUBTYPE_LEN,
            "the sealed plaintext must be longer than the body it carries, or the wire \
             size is still the body length and the padding bought nothing"
        );
        assert_eq!(
            shaping::strip_padding(&plaintext).expect("well-formed padding trailer"),
            &[ControlSubtype::CLOSE],
            "the control body is the close subtype and nothing else"
        );
    }

    /// The draining window is bounded at both ends, and on any real path it is one of
    /// the two bounds — never the multiplication between them.
    ///
    /// That is worth pinning because the arithmetic invites the opposite reading. The
    /// window is `3 × min_rtt` clamped to `[200 ms, 600 ms]`, and `min_rtt` opens at
    /// [`INITIAL_MIN_RTT`] (100 ms), which lands at exactly 300 ms — so 300 ms looks
    /// like the ordinary case and was written down as one. It is not: it is the value
    /// for a session that has never timed a round trip, and a session that has
    /// exchanged one acknowledged packet has replaced the guess with a measurement.
    ///
    /// The two measurements below are the ones this project actually has. On loopback,
    /// `min_rtt` after a single exchange is a few hundred microseconds — 213 µs
    /// server-side and 384 µs client-side in the run these figures come from — so
    /// three of it is under a millisecond and **the floor decides**: every fast-path
    /// session drains for 200 ms. On the WAN path the performance campaign measures,
    /// 235 ms, three of it is 705 ms and **the ceiling decides**: 600 ms. Between them
    /// they cover the range a deployment is in, which is why the bounds are the
    /// interesting part of this function and the multiplication is not.
    ///
    /// The floor exists because a sub-millisecond measurement would drain nothing —
    /// the displacement the window absorbs comes from the path's queues, not its
    /// length. The ceiling exists because the measurement is one the peer can inflate
    /// by delaying its own acknowledgements, and the length of a *local* commitment
    /// must not be a number a remote party writes. The last row is the arithmetic
    /// case: an absurd measurement must clamp, not overflow on its way there.
    #[test]
    fn the_draining_window_is_one_of_its_two_bounds_on_any_real_path() {
        use crate::transport::bandwidth_estimator::INITIAL_MIN_RTT;
        use std::time::Duration;

        // Loopback, measured: the floor binds, and by three orders of magnitude.
        for measured in [
            Duration::ZERO,
            Duration::from_micros(213),
            Duration::from_micros(384),
            Duration::from_millis(10),
        ] {
            assert_eq!(
                drain_window_for_rtt(measured),
                DRAIN_WINDOW_MIN,
                "on a fast path a round-trip measurement is too small to size a timeout \
                 with, so the floor is what the window is — not a value derived from \
                 {measured:?}"
            );
        }

        // The campaign's WAN path: the ceiling binds.
        assert_eq!(
            drain_window_for_rtt(Duration::from_millis(235)),
            DRAIN_WINDOW_MAX,
            "three round trips on the reference WAN path is 705 ms, so the ceiling is \
             what the window is there"
        );

        // The one value that is neither bound is the one nothing has measured: the
        // opening guess, which a single acknowledged packet replaces.
        let unmeasured = drain_window_for_rtt(INITIAL_MIN_RTT);
        assert_eq!(unmeasured, Duration::from_millis(300));
        assert!(
            unmeasured > DRAIN_WINDOW_MIN && unmeasured < DRAIN_WINDOW_MAX,
            "the 300 ms figure belongs to a session with no round-trip measurement at \
             all; calling it the ordinary case misreads the guess as an observation"
        );

        for inflated in [
            Duration::from_secs(1),
            Duration::from_secs(3600),
            Duration::MAX,
        ] {
            assert_eq!(
                drain_window_for_rtt(inflated),
                DRAIN_WINDOW_MAX,
                "no round-trip measurement, however inflated, may lengthen the window \
                 past its ceiling — the peer supplies that measurement"
            );
        }
    }

    /// An authenticated close frame ends the session and hands the application
    /// nothing. Both halves matter: the subtype byte must not surface as data, and
    /// the pump must learn that the peer left — which is the whole point of the frame
    /// and the only thing that makes a PhantomUDP slot free before the timer.
    #[tokio::test]
    async fn authenticated_close_frame_records_the_peer_close_and_delivers_nothing() {
        let session_id = fixed_session_id();
        let (client_session, server_session) = paired_sessions(session_id);
        let pkt = build_control_frame(&client_session, session_id, &[ControlSubtype::CLOSE]);

        assert!(
            !server_session.peer_closed(),
            "no close has been announced yet"
        );
        let delivered = run_recv_watching_close(pkt, session_id, &server_session).await;

        assert!(
            server_session.peer_closed(),
            "an authenticated close frame must be recorded so the pump can tear down"
        );
        assert!(
            delivered.is_none(),
            "a close frame carries no application bytes"
        );
    }

    /// A `CONTROL` frame whose plaintext names no subtype must not end the session.
    ///
    /// The close is the lowest assigned subtype and `0x00` is assigned to nothing, so
    /// the two shapes closest to "accidentally a close" are an empty body and a zeroed
    /// one. Neither may work: a receiver that read a missing subtype as its default,
    /// or treated an empty control body as a close, would let a peer bug — or a
    /// truncation that survived AEAD because it was produced before sealing — end a
    /// session that nobody asked to end.
    #[tokio::test]
    async fn control_frame_without_a_subtype_byte_does_not_end_the_session() {
        let session_id = fixed_session_id();
        let (client_session, server_session) = paired_sessions(session_id);

        for body in [b"".as_slice(), b"\x00".as_slice()] {
            let pkt = build_control_frame(&client_session, session_id, body);
            let delivered = run_recv_watching_close(pkt, session_id, &server_session).await;
            assert!(
                !server_session.peer_closed(),
                "a {}-byte control body must not read as a close",
                body.len()
            );
            assert!(
                delivered.is_none(),
                "a control frame never reaches the application"
            );
        }
    }

    /// The announcement is a fixed small number of copies, and only from a session
    /// that reached the wire.
    ///
    /// The count is fixed rather than retried-until-something because the frame is
    /// unacknowledged: there is no signal that could terminate a retry loop except
    /// one from the peer we have just stopped hearing from, and a loop without one
    /// spends packet numbers — the resource Invariant 8 bounds — on a session that is
    /// over. The `Handshaking` half pins that a connection which never established
    /// announces nothing: it has no peer state to release and its keys were never
    /// agreed.
    #[tokio::test]
    async fn close_is_announced_a_fixed_number_of_times_and_only_once_established() {
        let session_id = fixed_session_id();
        let (client_session, _server_session) = paired_sessions(session_id);
        let (client_transport, mut server_transport) = ChannelTransport::pair();
        let client_transport = Arc::new(client_transport);
        let obs = Observability::new(ObservabilityConfig::default());

        // A session still handshaking announces nothing.
        client_session.set_state(SessionState::Handshaking);
        announce_close(&client_transport, &client_session, session_id, &obs).await;
        assert!(
            server_transport.rx.get_mut().try_recv().is_err(),
            "a session that never established must announce no close"
        );

        client_session.set_state(SessionState::Connected);
        announce_close(&client_transport, &client_session, session_id, &obs).await;
        let mut copies = 0usize;
        while server_transport.rx.get_mut().try_recv().is_ok() {
            copies += 1;
        }
        assert_eq!(
            copies, CLOSE_FRAME_COPIES,
            "the close must be announced exactly {CLOSE_FRAME_COPIES} times — redundancy \
             is the only loss tolerance an unacknowledged frame has, and a fixed count \
             is the only one that cannot run away"
        );
    }

    /// Two established sessions joined by an in-memory pipe, each running the production
    /// pump. Returns the session a test will close, the one facing it, and the latter's
    /// negotiated inner session, which is where a close announcement is recorded when it
    /// arrives.
    fn live_session_pair() -> (Arc<PhantomSession>, Arc<PhantomSession>, Arc<InnerSession>) {
        let session_id = fixed_session_id();
        let (closing_inner, peer_inner) = paired_sessions(session_id);
        // `announce_close` speaks only for a session that reached the wire, and these two
        // skipped the handshake that would have said so.
        closing_inner.set_state(SessionState::Connected);
        peer_inner.set_state(SessionState::Connected);
        let (closing_t, peer_t) = ChannelTransport::pair();
        let closing = PhantomSession::from_accepted_server_session(
            "closing".into(),
            closing_t,
            closing_inner,
        );
        let peer = PhantomSession::from_accepted_server_session(
            "never-reads".into(),
            peer_t,
            peer_inner.clone(),
        );
        (closing, peer, peer_inner)
    }

    /// A session driven into the state a local close has to get out of, facing a peer
    /// that never reads.
    ///
    /// The peer's application never calls `recv()`, so its receive window stops opening
    /// once the bounded queue in front of `recv()` is full. It still acknowledges
    /// everything it was sent, answers persist probes and answers keep-alives, so the
    /// liveness timer never has a reason to end either side. The closing session is
    /// handed several times what that window and its own send buffer hold between them,
    /// which leaves its pump holding writes the send buffer refused — and while it holds
    /// any, it takes no further command. A second writer then fills the command channel
    /// behind them, so a caller that has to wait for room in that channel waits for good.
    ///
    /// Also returns the closing session's observability handle, whose active-sessions
    /// gauge is the pump's own record of having exited, and the writer's task, which only
    /// ends once the pump lets go of the channel it is blocked on.
    async fn wedge_a_session_behind_a_peer_that_never_reads() -> (
        Arc<PhantomSession>,
        Arc<PhantomSession>,
        Arc<InnerSession>,
        Arc<Observability>,
        tokio::task::JoinHandle<()>,
    ) {
        let (closing, peer, peer_inner) = live_session_pair();
        let obs = closing.observability();

        // Several times what the peer's window and this side's 1024-segment send buffer can
        // take between them, so most of it can only wait in the pump's queue of refused writes.
        closing
            .send(vec![0x5A; 4 << 20])
            .await
            .expect("the pump takes the write in");
        let stream = closing.open_stream().expect("open a stream");
        let writer =
            tokio::spawn(
                async move { while stream.send_reliable(vec![0xC3; 64]).await.is_ok() {} },
            );

        // The witness that the pump holds refused writes: the raw stream's send buffer is
        // full and the command channel is full behind it, and stays full. A pump still
        // reading commands would be emptying the channel as fast as the writer fills it.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            let buffer_full = closing
                .streams
                .get(&RAW_APP_STREAM_ID)
                .is_some_and(|s| s.send_buffer_full());
            if buffer_full && closing.cmd_tx.capacity() == 0 {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the harness never wedged the session: send buffer full = {buffer_full}, \
                 command-channel room = {}",
                closing.cmd_tx.capacity()
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert_eq!(
            closing.cmd_tx.capacity(),
            0,
            "the command channel drained again, so the pump is still reading it and the \
             session is not wedged"
        );
        assert_eq!(obs.snapshot().active_sessions, 1, "the pump is running");
        assert!(!peer_inner.peer_closed(), "nobody has asked to close yet");
        (closing, peer, peer_inner, obs, writer)
    }

    /// What a session that has let go looks like from outside: the peer heard the close,
    /// the pump's gauge came back down, and a writer blocked on the command channel was
    /// released because the pump dropped its end.
    ///
    /// Five seconds is generous for work that takes milliseconds, and a session that
    /// fails this does not fail it by being slow: nothing in its configuration will ever
    /// end it.
    async fn assert_the_session_let_go(
        obs: &Arc<Observability>,
        peer_inner: &Arc<InnerSession>,
        writer: tokio::task::JoinHandle<()>,
    ) {
        let bound = std::time::Duration::from_secs(5);
        let deadline = std::time::Instant::now() + bound;
        while (obs.snapshot().active_sessions != 0 || !peer_inner.peer_closed())
            && std::time::Instant::now() < deadline
        {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(
            peer_inner.peer_closed(),
            "the peer never received the close announcement within {bound:?}"
        );
        assert_eq!(
            obs.snapshot().active_sessions,
            0,
            "the pump was still running {bound:?} after the close was requested"
        );
        assert!(
            tokio::time::timeout(bound, writer).await.is_ok(),
            "a writer blocked on the command channel was never released, so the pump never \
             dropped its end of it"
        );
    }

    /// `disconnect()` ends a session whose peer has stopped reading, and returns
    /// promptly while doing it.
    ///
    /// The close used to travel on the command channel, behind the application's writes,
    /// and the pump stops reading that channel while it holds a write the send buffer
    /// refused — which it holds until the peer acknowledges data the peer's own closed
    /// window forbids sending. So a peer that stopped reading but kept answering held the
    /// session open for as long as it chose: the close was never read, the pump, its
    /// buffers and its demux routes stayed up, and with the channel full `disconnect()`
    /// did not even return. On a server that is a client deciding when it may be evicted.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn disconnect_ends_a_session_whose_peer_stopped_reading() {
        let (closing, _peer, peer_inner, obs, writer) =
            wedge_a_session_behind_a_peer_that_never_reads().await;

        let returned =
            tokio::time::timeout(std::time::Duration::from_secs(2), closing.disconnect()).await;
        assert!(
            matches!(returned, Ok(Ok(()))),
            "disconnect() did not return within 2 s: it is waiting for room in a command \
             channel the pump has stopped reading"
        );
        assert_the_session_let_go(&obs, &peer_inner, writer).await;
    }

    /// Dropping the handle is the same request with no await to make, so it must end
    /// the same wedged session. Its old form was a `try_send` into that full command
    /// channel, which failed silently and left the pump running with nothing that would
    /// ever stop it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn dropping_the_handle_ends_a_session_whose_peer_stopped_reading() {
        let (closing, _peer, peer_inner, obs, writer) =
            wedge_a_session_behind_a_peer_that_never_reads().await;

        drop(closing);
        assert_the_session_let_go(&obs, &peer_inner, writer).await;
    }

    /// An accepted session reaped by the liveness timer reports why, as a client does.
    ///
    /// The pump has always written the cause into the slot it was handed; the accepted
    /// session's handle was built with a fresh slot of its own instead, so on the server
    /// side `last_error()` answered `None` for a death the pump had recorded, and `recv()`
    /// fell back to an untyped "closed". The client path never had the defect, which is
    /// why the liveness integration tests — both client-side — did not see it.
    #[tokio::test]
    async fn an_accepted_session_reaped_by_the_liveness_timer_reports_the_cause() {
        let session_id = fixed_session_id();
        let (inner, _peer_inner) = paired_sessions(session_id);
        inner.set_state(SessionState::Connected);
        // The far end of the pipe is held and never read: nothing this session sends is
        // acknowledged, and nothing arrives.
        let (transport, _silent_peer) = ChannelTransport::pair();
        let session =
            PhantomSession::from_accepted_server_session("reaped".into(), transport, inner);
        assert!(
            session
                .set_liveness_config(crate::transport::liveness::LivenessConfig::for_test())
                .await
        );
        // Something in flight, so the silence counts against the path.
        session
            .send(b"never acknowledged".to_vec())
            .await
            .expect("send");

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while session.connection_state() != ConnectionState::Dead {
            assert!(
                std::time::Instant::now() < deadline,
                "the liveness timer never reaped the session; state {:?}",
                session.connection_state()
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(
            matches!(session.last_error().await, Some(CoreError::Timeout)),
            "an accepted session reaped by the liveness timer must say why; last_error() gave \
             {:?}",
            session.last_error().await
        );
    }

    /// How much a test hands a session whose peer has stopped reading its socket. Far more
    /// than the shrunken socket buffers of `connection_whose_far_end_never_reads` hold, so
    /// the pump is left holding most of it.
    const UNREAD_BACKLOG: usize = 16 << 20;

    /// A session over a real TCP connection whose peer never reads its socket, driven until
    /// the pump is parked inside a transport write.
    ///
    /// This is a different wedge from `wedge_a_session_behind_a_peer_that_never_reads`: there
    /// the peer's *application* stops reading and its protocol stack goes on acknowledging, so
    /// the pump is merely refused by a closed window and keeps turning. Here the peer's socket
    /// stops draining, so the kernel's buffers fill and the write that finds them full waits
    /// for the peer — inside an arm of the pump's loop, where nothing else, the local close
    /// included, gets a turn until it returns.
    ///
    /// The writes are unreliable ones on an opened stream: neither congestion- nor
    /// flow-controlled, so the pump hands every one of them to the transport, and a peer that
    /// acknowledges nothing cannot hold them back. The witness that the pump is parked is that
    /// the bytes it has put on the wire stop growing while most of the backlog is unsent.
    ///
    /// Returns the session, its observability handle, whose active-sessions gauge is the
    /// pump's record of having exited, and the inner session holding the keys of its peer —
    /// the one that can open what the wedged session writes, for a test that goes on to
    /// read the socket. The far end of the connection stays with the caller, which keeps
    /// it alive and does not read it until it chooses to.
    async fn wedge_a_session_on_a_socket_its_peer_never_reads(
        transport: crate::api::tcp_transport::TcpSessionTransport,
    ) -> (Arc<PhantomSession>, Arc<Observability>, Arc<InnerSession>) {
        let session_id = fixed_session_id();
        let (inner, peer_inner) = paired_sessions(session_id);
        inner.set_state(SessionState::Connected);
        let session =
            PhantomSession::from_accepted_server_session("closing".into(), transport, inner);
        let obs = session.observability();

        let stream = session.open_stream().expect("open a stream");
        stream
            .send_unreliable(vec![0xE7; UNREAD_BACKLOG])
            .await
            .expect("the pump takes the write in");

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let mut last = obs.snapshot().bytes_sent;
        loop {
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            let now = obs.snapshot().bytes_sent;
            if now > 0 && now == last {
                break;
            }
            last = now;
            assert!(
                std::time::Instant::now() < deadline,
                "the harness never parked the pump: {now} bytes went out and kept going"
            );
        }
        assert!(
            (last as usize) < UNREAD_BACKLOG / 2,
            "{last} of {UNREAD_BACKLOG} bytes went out, so the socket was not what stopped the \
             pump and this harness proves nothing"
        );
        assert_eq!(obs.snapshot().active_sessions, 1, "the pump is running");
        (session, obs, peer_inner)
    }

    /// Wait up to `bound` for the pump behind `obs` to exit, and say whether it did.
    async fn pump_exits_within(obs: &Arc<Observability>, bound: std::time::Duration) -> bool {
        let deadline = std::time::Instant::now() + bound;
        while obs.snapshot().active_sessions != 0 {
            if std::time::Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        true
    }

    /// A TCP transport over a connection whose peer never reads, with a write-stall
    /// deadline of `stall`. Returns the far end too, which the caller keeps alive.
    async fn tcp_transport_whose_peer_never_reads(
        stall: std::time::Duration,
    ) -> (
        crate::api::tcp_transport::TcpSessionTransport,
        tokio::net::TcpStream,
    ) {
        let (near, far) =
            crate::api::tcp_transport::test_support::connection_whose_far_end_never_reads().await;
        let transport = crate::api::tcp_transport::TcpSessionTransport::new(near)
            .with_write_stall_timeout(stall);
        (transport, far)
    }

    /// Read length-prefixed frames off `far` until the connection ends, and count the
    /// session-close announcements among them.
    ///
    /// It never gives up on a quiet connection by itself: letting go of `far` would end
    /// the connection from this side, and a session that ended because its transport
    /// closed would pass for one that honoured its close. The caller bounds the wait.
    ///
    /// `peer_inner` holds the keys of the session on the far side, so it can strip header
    /// protection from every frame and open the ones flagged `CONTROL`; a frame counts
    /// only if the AEAD opens it and its subtype is `CLOSE`.
    async fn count_close_announcements(
        mut far: tokio::net::TcpStream,
        peer_inner: &InnerSession,
    ) -> usize {
        use tokio::io::AsyncReadExt;
        let mut closes = 0usize;
        loop {
            let mut len = [0u8; 4];
            if far.read_exact(&mut len).await.is_err() {
                return closes;
            }
            let mut frame = vec![0u8; u32::from_be_bytes(len) as usize];
            if far.read_exact(&mut frame).await.is_err() {
                return closes;
            }
            let Ok(packet) = peer_inner.parse_protected(&frame) else {
                continue;
            };
            if !packet.header.flags.contains(PacketFlags::CONTROL) {
                continue;
            }
            let opened =
                peer_inner.decrypt_packet(&packet.header, &packet.payload, &packet.extensions);
            if opened.is_ok_and(|plain| plain.first() == Some(&ControlSubtype::CLOSE)) {
                closes += 1;
            }
        }
    }

    /// A close requested while the pump is parked in a write the peer is not taking is
    /// read, carried out and announced as soon as that write returns — not held until
    /// the write deadline ends the session regardless.
    ///
    /// The close is a request the pump reads between turns of its loop, and this pump is
    /// in the middle of one. The deadline here is far longer than the test, so nothing
    /// but the close can end this session within the bound: once the peer starts reading
    /// again the write completes, and the pump must then take the close, push what it
    /// still holds, announce the close and exit. What it leaves behind has to be the
    /// orderly end — `Closed` with no cause — and the far end has to find the
    /// announcement on the wire.
    async fn a_close_requested_during_a_parked_write_is_honoured_once_it_returns(drop_it: bool) {
        let stall = std::time::Duration::from_secs(120);
        let (transport, far) = tcp_transport_whose_peer_never_reads(stall).await;
        let (closing, obs, peer_inner) =
            wedge_a_session_on_a_socket_its_peer_never_reads(transport).await;

        let closing = if drop_it {
            drop(closing);
            None
        } else {
            closing.disconnect().await.expect("disconnect");
            Some(closing)
        };
        // Nothing can act on the close while the write is parked: the harness has already
        // watched the pump stop making progress, and the peer still is not reading.
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        assert_eq!(
            obs.snapshot().active_sessions,
            1,
            "the pump exited while parked in a write its peer was not taking, so this harness \
             is not testing a parked pump"
        );

        let reader = tokio::spawn(async move { count_close_announcements(far, &peer_inner).await });
        let bound = std::time::Duration::from_secs(20);
        assert!(
            pump_exits_within(&obs, bound).await,
            "the pump was still running {bound:?} after the peer started reading again: the \
             close requested while its write was parked was never carried out"
        );
        if let Some(closing) = closing {
            assert_eq!(
                closing.connection_state(),
                ConnectionState::Closed,
                "a close carried out once the write returned is an orderly end"
            );
            assert!(
                closing.last_error().await.is_none(),
                "an orderly end has no cause; last_error() gave {:?}",
                closing.last_error().await
            );
        }
        let closes = tokio::time::timeout(std::time::Duration::from_secs(30), reader)
            .await
            .expect("the far end's reader never finished")
            .expect("reader");
        assert!(
            closes > 0,
            "the close was carried out but never announced to the peer"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_disconnect_during_a_parked_write_is_honoured_once_the_write_returns() {
        a_close_requested_during_a_parked_write_is_honoured_once_it_returns(false).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_handle_dropped_during_a_parked_write_is_honoured_once_the_write_returns() {
        a_close_requested_during_a_parked_write_is_honoured_once_it_returns(true).await;
    }

    /// A close requested while the pump is parked in a write its peer never takes does
    /// not keep the session alive past the write deadline, and does not turn a death into
    /// an orderly end: the session ends `Dead`, with `Timeout`, once the deadline passes.
    ///
    /// This does not show the close being read — the deadline ends this session whether
    /// or not anyone asked, which is what the harness is for, and
    /// `a_disconnect_during_a_parked_write_is_honoured_once_the_write_returns` is the test
    /// of the close itself. What this pins is the other half of `disconnect()`'s contract
    /// on a stream socket that stays full: the call returns at once, nothing it does
    /// cancels or outlasts the deadline, and the outcome is reported as the death it is,
    /// since a close that could not be announced has not ended anything in order.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_disconnect_on_a_socket_that_stays_full_ends_the_session_dead_at_the_deadline() {
        let stall = std::time::Duration::from_secs(2);
        let (transport, _far) = tcp_transport_whose_peer_never_reads(stall).await;
        let (closing, obs, _peer_inner) =
            wedge_a_session_on_a_socket_its_peer_never_reads(transport).await;

        closing.disconnect().await.expect("disconnect");
        let bound = stall + std::time::Duration::from_secs(8);
        assert!(
            pump_exits_within(&obs, bound).await,
            "the pump was still running {bound:?} after the close was requested: it is parked \
             in a write its peer will never take"
        );
        assert_eq!(
            closing.connection_state(),
            ConnectionState::Dead,
            "a close that could not be carried out must not read as an orderly end"
        );
        assert!(
            matches!(closing.last_error().await, Some(CoreError::Timeout)),
            "last_error() should name the stalled write; got {:?}",
            closing.last_error().await
        );
    }

    /// Dropping the handle is the same request with no await to make; it too leaves the
    /// deadline to end the session, and nothing about the drop keeps the pump running
    /// past it. Like the test above, this proves the bound, not that the request was read.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_handle_dropped_on_a_socket_that_stays_full_lets_the_pump_end_at_the_deadline() {
        let stall = std::time::Duration::from_secs(2);
        let (transport, _far) = tcp_transport_whose_peer_never_reads(stall).await;
        let (closing, obs, _peer_inner) =
            wedge_a_session_on_a_socket_its_peer_never_reads(transport).await;

        drop(closing);
        let bound = stall + std::time::Duration::from_secs(8);
        assert!(
            pump_exits_within(&obs, bound).await,
            "the pump was still running {bound:?} after the handle was dropped: it is parked \
             in a write its peer will never take"
        );
    }

    /// A session whose peer stopped reading its socket ends by itself, as a death with a
    /// cause, with nobody asking it to.
    ///
    /// Nothing else would end it: the liveness sweep runs between turns of the pump's
    /// loop, and so could not run while the pump waited on the write — and these writes
    /// are unreliable, so they leave nothing in flight for it to judge anyway. The cause
    /// has to be readable everywhere a caller looks for one, and `recv()` is where an
    /// echo-style handler looks: its channel closes as the session ends, and what it
    /// reports then is whatever the slot held at that moment.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_session_whose_peer_stopped_reading_its_socket_dies_with_a_timeout() {
        let stall = std::time::Duration::from_millis(1500);
        let (transport, _far) = tcp_transport_whose_peer_never_reads(stall).await;
        let (session, obs, _peer_inner) =
            wedge_a_session_on_a_socket_its_peer_never_reads(transport).await;

        let received = tokio::time::timeout(std::time::Duration::from_secs(10), session.recv())
            .await
            .expect("recv() was still waiting 10 s later: the session never ended");
        assert!(
            matches!(received, Err(CoreError::Timeout)),
            "recv() should report the transport's Timeout once the session ends; got \
             {received:?}"
        );
        assert!(
            pump_exits_within(&obs, std::time::Duration::from_secs(5)).await,
            "the pump was still running after recv() reported the session over"
        );
        assert_eq!(session.connection_state(), ConnectionState::Dead);
        assert!(
            matches!(session.last_error().await, Some(CoreError::Timeout)),
            "last_error() should name the cause; got {:?}",
            session.last_error().await
        );
        assert!(
            matches!(session.send(b"x".to_vec()).await, Err(CoreError::Timeout)),
            "send() on a dead session should report the cause"
        );
    }

    /// The write deadline the configuration tests hand the entry points: short enough
    /// that a session given it dies well inside `CONFIGURED_DEADLINE_BOUND`, while one
    /// that ignored it and kept the thirty-second default would still be waiting.
    const CONFIGURED_WRITE_DEADLINE: std::time::Duration = std::time::Duration::from_secs(1);
    const CONFIGURED_DEADLINE_BOUND: std::time::Duration = std::time::Duration::from_secs(10);

    /// A config whose only departure from the default is the write deadline.
    fn config_with_write_deadline(deadline: std::time::Duration) -> crate::config::PhantomConfig {
        crate::config::PhantomConfig {
            write_stall_timeout: deadline,
            ..crate::config::PhantomConfig::default()
        }
    }

    /// Hand `session` far more than a peer that never reads can absorb, and return what
    /// `recv()` reports within `CONFIGURED_DEADLINE_BOUND` — `None` if it is still
    /// waiting then.
    async fn flood_a_peer_that_never_reads(
        session: &PhantomSession,
    ) -> Option<Result<Vec<u8>, CoreError>> {
        let stream = session.open_stream().expect("open a stream");
        stream
            .send_unreliable(vec![0xE7; UNREAD_BACKLOG])
            .await
            .expect("the pump takes the write in");
        tokio::time::timeout(CONFIGURED_DEADLINE_BOUND, session.recv())
            .await
            .ok()
    }

    /// A listening socket whose accepted connections get a small receive buffer, so a
    /// peer that stops reading them fills up after a few kibibytes.
    fn listener_with_small_receive_buffers() -> tokio::net::TcpListener {
        let socket = tokio::net::TcpSocket::new_v4().expect("socket");
        socket
            .set_recv_buffer_size(crate::api::tcp_transport::test_support::SMALL_SOCKET_BUFFER)
            .expect("shrink the receive buffer");
        socket
            .bind("127.0.0.1:0".parse().expect("addr"))
            .expect("bind");
        socket.listen(16).expect("listen")
    }

    /// A TCP server that completes the handshake with whoever connects and then never
    /// reads its socket again. Returns its port and the verifying key a client pins; the
    /// task holding the accepted connection runs until the test ends.
    async fn a_tcp_server_that_stops_reading_after_the_handshake() -> (u16, Vec<u8>) {
        let listener = listener_with_small_receive_buffers();
        let port = listener.local_addr().expect("addr").port();
        let hs = HandshakeServer::new().expect("handshake server");
        let key = hs.verifying_key().to_bytes();
        tokio::spawn(async move {
            let (stream, peer) = listener.accept().await.expect("accept");
            let transport = crate::api::tcp_transport::TcpSessionTransport::new(stream);
            crate::api::listener::drive_server_handshake(&transport, &hs, peer.ip())
                .await
                .expect("server handshake");
            // Hold the connection open and never read it.
            std::future::pending::<()>().await;
            drop(transport);
        });
        (port, key)
    }

    /// `connect_pinned_with_config` builds its TCP transport with the config's write
    /// deadline: a session given one second over a server that stops reading is dead
    /// within the bound, where the thirty-second default would still be waiting.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn connect_pinned_with_config_applies_the_configured_write_deadline() {
        let (port, key) = a_tcp_server_that_stops_reading_after_the_handshake().await;
        let session = connect_pinned_with_config(
            "127.0.0.1".into(),
            port,
            key,
            config_with_write_deadline(CONFIGURED_WRITE_DEADLINE),
        )
        .await
        .expect("connect");
        session.await_ready().await.expect("handshake");

        let received = flood_a_peer_that_never_reads(&session)
            .await
            .unwrap_or_else(|| {
                panic!(
                    "recv() was still waiting {CONFIGURED_DEADLINE_BOUND:?} later: the session is \
                 not using the configured {CONFIGURED_WRITE_DEADLINE:?} write deadline"
                )
            });
        assert!(
            matches!(received, Err(CoreError::Timeout)),
            "a write the server never takes should end the session with Timeout; got \
             {received:?}"
        );
        assert_eq!(session.connection_state(), ConnectionState::Dead);
    }

    /// A TCP listener built with a config gives every accepted connection the config's
    /// write deadline.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_listener_built_with_a_config_applies_its_write_deadline() {
        let mut config = crate::config::PhantomConfig::server();
        config.write_stall_timeout = CONFIGURED_WRITE_DEADLINE;
        let listener = crate::api::listener::PhantomListener::builder("127.0.0.1:0")
            .config(config)
            .bind()
            .await
            .expect("bind");
        let addr: std::net::SocketAddr = listener.local_addr().parse().expect("addr");
        let key = HybridVerifyingKey::from_bytes(&listener.verifying_key_bytes()).expect("key");

        // The client completes the handshake and then never reads its socket again.
        tokio::spawn(async move {
            let socket = tokio::net::TcpSocket::new_v4().expect("socket");
            socket
                .set_recv_buffer_size(crate::api::tcp_transport::test_support::SMALL_SOCKET_BUFFER)
                .expect("shrink the receive buffer");
            let stream = socket.connect(addr).await.expect("connect");
            let transport = crate::api::tcp_transport::TcpSessionTransport::new(stream);
            run_client_handshake(&transport, &key, None)
                .await
                .expect("client handshake");
            std::future::pending::<()>().await;
            drop(transport);
        });
        let accepted = tokio::time::timeout(std::time::Duration::from_secs(10), listener.accept())
            .await
            .expect("no connection was accepted")
            .expect("accept");
        let session = accepted.session();

        let received = flood_a_peer_that_never_reads(&session)
            .await
            .unwrap_or_else(|| {
                panic!(
                    "recv() was still waiting {CONFIGURED_DEADLINE_BOUND:?} later: the accepted \
                 session is not using the configured {CONFIGURED_WRITE_DEADLINE:?} write \
                 deadline"
                )
            });
        assert!(
            matches!(received, Err(CoreError::Timeout)),
            "a write the client never takes should end the session with Timeout; got \
             {received:?}"
        );
        assert_eq!(session.connection_state(), ConnectionState::Dead);
    }

    /// The mimicry connect that takes a config gives its leg the config's write deadline,
    /// the same as `connect_pinned_with_config` does over plain TCP.
    #[cfg(feature = "mimicry")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn connect_pinned_mimic_with_config_applies_the_configured_write_deadline() {
        use crate::transport::legs::mimic_tls::{MimicConfig, MimicTlsLeg};

        let listener = listener_with_small_receive_buffers();
        let port = listener.local_addr().expect("addr").port();
        let hs = HandshakeServer::new().expect("handshake server");
        let key = hs.verifying_key().to_bytes();
        // A mimicry server that completes the prelude and the handshake, then never reads.
        tokio::spawn(async move {
            let (stream, peer) = listener.accept().await.expect("accept");
            let leg = MimicTlsLeg::accept(stream, &MimicConfig::new("server-ignored"))
                .await
                .expect("server prelude");
            crate::api::listener::drive_server_handshake(&leg, &hs, peer.ip())
                .await
                .expect("server handshake");
            std::future::pending::<()>().await;
            drop(leg);
        });

        let session = connect_pinned_mimic_with_config(
            "127.0.0.1".into(),
            port,
            key,
            "cover.example.com".into(),
            config_with_write_deadline(CONFIGURED_WRITE_DEADLINE),
        )
        .await
        .expect("connect");
        session.await_ready().await.expect("handshake");

        let received = flood_a_peer_that_never_reads(&session)
            .await
            .unwrap_or_else(|| {
                panic!(
                    "recv() was still waiting {CONFIGURED_DEADLINE_BOUND:?} later: the mimicry \
                 session is not using the configured {CONFIGURED_WRITE_DEADLINE:?} write \
                 deadline"
                )
            });
        assert!(
            matches!(received, Err(CoreError::Timeout)),
            "a write the server never takes should end the session with Timeout; got \
             {received:?}"
        );
        assert_eq!(session.connection_state(), ConnectionState::Dead);
    }

    /// A mimicry listener built with a config gives every accepted leg the config's write
    /// deadline, the same as the plain TCP listener does.
    #[cfg(feature = "mimicry")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_mimicry_listener_built_with_a_config_applies_its_write_deadline() {
        use crate::transport::legs::mimic_tls::{MimicConfig, MimicTlsLeg};

        let mut config = crate::config::PhantomConfig::server();
        config.write_stall_timeout = CONFIGURED_WRITE_DEADLINE;
        let listener = crate::api::listener::PhantomListener::builder("127.0.0.1:0")
            .mimic_sni("mimic")
            .config(config)
            .bind()
            .await
            .expect("bind");
        let addr: std::net::SocketAddr = listener.local_addr().parse().expect("addr");
        let key = HybridVerifyingKey::from_bytes(&listener.verifying_key_bytes()).expect("key");

        // The client completes the prelude and the handshake, then never reads again.
        tokio::spawn(async move {
            let socket = tokio::net::TcpSocket::new_v4().expect("socket");
            socket
                .set_recv_buffer_size(crate::api::tcp_transport::test_support::SMALL_SOCKET_BUFFER)
                .expect("shrink the receive buffer");
            let stream = socket.connect(addr).await.expect("connect");
            let leg = MimicTlsLeg::connect(stream, &MimicConfig::new("cover.example.com"))
                .await
                .expect("client prelude");
            run_client_handshake(&leg, &key, None)
                .await
                .expect("client handshake");
            std::future::pending::<()>().await;
            drop(leg);
        });
        let accepted = tokio::time::timeout(std::time::Duration::from_secs(10), listener.accept())
            .await
            .expect("no connection was accepted")
            .expect("accept");
        let session = accepted.session();

        let received = flood_a_peer_that_never_reads(&session)
            .await
            .unwrap_or_else(|| {
                panic!(
                    "recv() was still waiting {CONFIGURED_DEADLINE_BOUND:?} later: the accepted \
                 mimicry session is not using the configured {CONFIGURED_WRITE_DEADLINE:?} \
                 write deadline"
                )
            });
        assert!(
            matches!(received, Err(CoreError::Timeout)),
            "a write the client never takes should end the session with Timeout; got \
             {received:?}"
        );
        assert_eq!(session.connection_state(), ConnectionState::Dead);
    }

    /// A zero write deadline is refused where it is supplied, before any I/O: by
    /// `connect_pinned_with_config` before it opens a socket — here to a listener that
    /// would accept the connection — and by both ways of binding a TCP listener with a
    /// config, before the port is bound.
    #[tokio::test]
    async fn a_zero_write_deadline_is_refused_before_any_io() {
        let listening = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listening.local_addr().expect("addr").port();
        let key = HandshakeServer::new()
            .expect("handshake server")
            .verifying_key()
            .to_bytes();
        let zero = config_with_write_deadline(std::time::Duration::ZERO);

        let connected =
            connect_pinned_with_config("127.0.0.1".into(), port, key, zero.clone()).await;
        assert!(
            matches!(connected, Err(CoreError::ConfigError(_))),
            "connect_pinned_with_config must refuse a zero write deadline; got {:?}",
            connected.map(|_| "a session")
        );

        let built = crate::api::listener::PhantomListener::builder("127.0.0.1:0")
            .config(zero.clone())
            .bind()
            .await;
        assert!(
            matches!(built, Err(CoreError::ConfigError(_))),
            "a listener builder must refuse a zero write deadline; got {:?}",
            built.map(|_| "a listener")
        );

        let seed = crate::api::identity::generate_signing_key().expect("seed");
        let bound = crate::api::listener::PhantomListener::bind_with_config_bytes(
            "127.0.0.1:0".into(),
            seed,
            zero,
        )
        .await;
        assert!(
            matches!(bound, Err(CoreError::ConfigError(_))),
            "bind_with_config_bytes must refuse a zero write deadline; got {:?}",
            bound.map(|_| "a listener")
        );
    }

    /// A transport whose writes never return and whose reads give up on the peer when
    /// told to. It orders the two events the way a pump cannot hide: the send loop is
    /// parked in a write, so its teardown — the other place the cause is recorded and
    /// `Dead` published — is not coming, and whatever `recv()`, `connection_state()` and
    /// `send()` report once the read gives up, the receive task reported on its way out.
    struct GivesUpWhileAWriteIsParked {
        write_parked: Arc<std::sync::atomic::AtomicBool>,
        read_gives_up: Arc<tokio::sync::Notify>,
    }

    impl SessionTransport for GivesUpWhileAWriteIsParked {
        async fn send_bytes(&self, _data: &[u8]) -> Result<(), CoreError> {
            self.write_parked.store(true, Ordering::Release);
            std::future::pending().await
        }

        async fn recv_bytes(&self) -> Result<Bytes, CoreError> {
            self.read_gives_up.notified().await;
            Err(CoreError::Timeout)
        }
    }

    /// When the transport gives up, the session reads as dead with its cause at once —
    /// not only after the send loop has wound down.
    ///
    /// The receive task is usually the first part of the pump to hear of a give-up, and
    /// it ends the channel `recv()` waits on as it goes. If it left the cause and the
    /// state to the send loop's teardown, `recv()` could wake to an untyped "closed"
    /// while the cause was still unwritten, and `connection_state()` could go on reading
    /// `Connected` — with `send()` accepting writes for a transport that refuses every
    /// one — for as long as the send loop took to notice. Here it never notices, so both
    /// have to come from the receive task.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_session_whose_transport_gives_up_reads_as_dead_before_its_pump_tears_down() {
        let session_id = fixed_session_id();
        let (inner, _peer_inner) = paired_sessions(session_id);
        inner.set_state(SessionState::Connected);
        let write_parked = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let read_gives_up = Arc::new(tokio::sync::Notify::new());
        let transport = GivesUpWhileAWriteIsParked {
            write_parked: write_parked.clone(),
            read_gives_up: read_gives_up.clone(),
        };
        let session =
            PhantomSession::from_accepted_server_session("parked".into(), transport, inner);
        let obs = session.observability();

        session
            .send(b"parks the send loop".to_vec())
            .await
            .expect("the pump takes the write in");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !write_parked.load(Ordering::Acquire) {
            assert!(
                std::time::Instant::now() < deadline,
                "the pump never reached the transport"
            );
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }

        read_gives_up.notify_one();
        let received = tokio::time::timeout(std::time::Duration::from_secs(5), session.recv())
            .await
            .expect("recv() was still waiting 5 s after the transport gave up");
        assert!(
            matches!(received, Err(CoreError::Timeout)),
            "recv() must report the transport's Timeout, not a bare close; got {received:?}"
        );
        assert_eq!(
            session.connection_state(),
            ConnectionState::Dead,
            "recv() reported the session over while its state still said otherwise"
        );
        assert!(!session.is_data_ready());
        assert!(
            matches!(session.last_error().await, Some(CoreError::Timeout)),
            "last_error() should name the cause; got {:?}",
            session.last_error().await
        );
        assert!(
            matches!(session.send(b"x".to_vec()).await, Err(CoreError::Timeout)),
            "send() on a session whose transport gave up must report the cause, not queue"
        );
        assert_eq!(
            obs.snapshot().active_sessions,
            1,
            "the send loop is still parked in its write, so none of the above came from its \
             teardown"
        );
    }

    /// A liveness verdict computed on the send loop never walks back a state the session
    /// cannot leave.
    ///
    /// The verdict is not the only writer of the state: the receive task publishes `Dead`
    /// when the transport gives up and `Draining` when the peer's close arrives, and
    /// `disconnect()` publishes `Closed` from the caller's thread — each of them while the
    /// send loop may be between reading the path's signals and publishing what they say.
    /// A `Recovered` verdict landing after any of them would tell a caller who had
    /// already seen the session end that it was `Connected` again.
    #[test]
    fn a_liveness_verdict_does_not_overwrite_a_state_the_session_cannot_leave() {
        let session_id = fixed_session_id();
        let (inner, _peer_inner) = paired_sessions(session_id);
        inner.set_state(SessionState::Connected);
        for ended in [
            ConnectionState::Dead,
            ConnectionState::Closed,
            ConnectionState::Failed,
            ConnectionState::Draining,
        ] {
            let state = Arc::new(AtomicU8::new(ended as u8));
            let terminal_error = parking_lot::Mutex::new(None);
            // Migrating, with inbound heard just now: the verdict is `Recovered`, which
            // publishes `Connected`.
            let mut migrating_since = Some(std::time::Instant::now());
            let died = apply_liveness(&inner, &state, &terminal_error, &mut migrating_since);
            assert!(!died);
            assert!(
                migrating_since.is_none(),
                "the verdict under test was not `Recovered`"
            );
            assert_eq!(
                ConnectionState::from_u8(state.load(Ordering::Relaxed)),
                ended,
                "a `Recovered` verdict overwrote {ended:?}"
            );
        }

        // The ordinary transition still happens.
        let state = Arc::new(AtomicU8::new(ConnectionState::Migrating as u8));
        let terminal_error = parking_lot::Mutex::new(None);
        let mut migrating_since = Some(std::time::Instant::now());
        apply_liveness(&inner, &state, &terminal_error, &mut migrating_since);
        assert_eq!(
            ConnectionState::from_u8(state.load(Ordering::Relaxed)),
            ConnectionState::Connected
        );
    }

    /// A write handed to `send()` and then a `disconnect()` — or a dropped handle — in
    /// the next statement still reaches the peer, whichever of the two the pump notices
    /// first.
    ///
    /// The close does not wait in line behind the application's writes, so the writes
    /// queued ahead of it have to be taken in by the close itself. On a single-threaded
    /// runtime nothing runs between the two statements, so the pump wakes to find both
    /// the write and the close waiting and picks between them at random; thirty-two
    /// rounds put both orders in play with near certainty, and a close that dropped what
    /// was queued ahead of it would lose the write in about half of them.
    #[tokio::test]
    async fn a_write_queued_before_a_close_reaches_the_peer_whichever_the_pump_sees_first() {
        const LAST_WORDS: &[u8] = b"the-last-thing-said";
        for round in 0..32 {
            let (closing, peer, _peer_inner) = live_session_pair();
            closing
                .send(LAST_WORDS.to_vec())
                .await
                .expect("the write is accepted");
            if round % 2 == 0 {
                closing.disconnect().await.expect("disconnect");
            } else {
                drop(closing);
            }
            let received = tokio::time::timeout(std::time::Duration::from_secs(5), peer.recv())
                .await
                .unwrap_or_else(|_| panic!("round {round}: nothing reached the peer"))
                .unwrap_or_else(|e| panic!("round {round}: the peer's session ended first: {e}"));
            assert_eq!(
                received, LAST_WORDS,
                "round {round}: the write queued ahead of the close did not reach the peer"
            );
        }
    }

    /// A write queued while the handshake is still running, followed by a close
    /// requested before it finishes, is still pushed once the handshake completes.
    ///
    /// Pre-handshake writes do not come through the command channel at all: the pump
    /// moves them into its queue of not-yet-admitted writes when it starts, and the
    /// ordinary arms admit them on their first turn. A pump that starts with a close
    /// already requested finds that arm ready at the same moment, so the close has to
    /// admit them itself. One that skipped the admission would announce the close with
    /// the write still unsent in about a third of these rounds — the close arm is one
    /// of three ready on that first turn — so sixteen rounds all pass by luck less than
    /// twice in a thousand runs.
    #[tokio::test]
    async fn a_write_queued_during_the_handshake_is_pushed_by_a_close_requested_during_it() {
        use crate::api::full_duplex_tests::{drive_server, Link};

        const LAST_WORDS: &[u8] = b"said-before-the-keys-were-agreed";
        for round in 0..16 {
            let server_hs = HandshakeServer::new().unwrap();
            let pinned = server_hs.verifying_key().clone();
            let (client_link, server_link) = Link::pair(std::time::Duration::ZERO, 1 << 40);
            let client =
                PhantomSession::connect_with_transport("test-server:9000", client_link, pinned);
            client
                .send(LAST_WORDS.to_vec())
                .await
                .expect("a write is queued while connecting");
            assert_eq!(
                client.connection_state(),
                ConnectionState::Connecting,
                "round {round}: the write must land in the pre-handshake queue"
            );
            client.disconnect().await.expect("disconnect");

            let server = drive_server(server_hs, server_link).await;
            let received = tokio::time::timeout(std::time::Duration::from_secs(5), server.recv())
                .await
                .unwrap_or_else(|_| panic!("round {round}: nothing reached the peer"))
                .unwrap_or_else(|e| panic!("round {round}: the peer's session ended first: {e}"));
            assert_eq!(
                received, LAST_WORDS,
                "round {round}: the pre-handshake write was not pushed ahead of the close"
            );
        }
    }

    /// A connecting session and the session that accepted it, handshaken for real over an
    /// in-memory link with no delay.
    ///
    /// The stream tests need the two roles: stream ids are allocated by parity, and a pair of
    /// accepted sessions — [`live_session_pair`] — allocates from the same half on both ends,
    /// so the peer takes each other's streams for ones of its own that it never opened.
    async fn connected_client_and_server() -> (Arc<PhantomSession>, Arc<PhantomSession>) {
        let (client, server, _) =
            crate::api::full_duplex_tests::establish_counted(std::time::Duration::ZERO, 1 << 40)
                .await;
        (client, server)
    }

    /// Wait, for at most ten seconds, until the send buffer of `closing`'s stream `id` is
    /// full — the point at which the pump holds refused writes and stops reading commands.
    async fn wait_until_send_buffer_full(closing: &PhantomSession, id: u32) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while !closing
            .streams
            .get(&id)
            .is_some_and(|s| s.send_buffer_full())
        {
            assert!(
                std::time::Instant::now() < deadline,
                "stream {id}'s send buffer never filled, so the pump never stopped reading \
                 commands and the case under test was never reached"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }

    /// Assert that exactly `waiting` commands are sitting unread in `closing`'s command
    /// channel, and still are a moment later — so the pump has stopped reading it.
    async fn assert_commands_waiting(closing: &PhantomSession, waiting: usize) {
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert_eq!(
            closing.cmd_tx.max_capacity() - closing.cmd_tx.capacity(),
            waiting,
            "the commands under test have to be waiting in the command channel, or this test \
             is not testing the case it is for"
        );
    }

    /// Everything the peer reads on `stream` up to its EOF, as `(bytes of filler, anything
    /// else in arrival order)`. Each read has ten seconds to arrive.
    async fn read_to_eof(
        stream: &crate::api::stream::PhantomStream,
        filler: u8,
    ) -> (usize, Vec<Vec<u8>>) {
        let mut bulk = 0usize;
        let mut rest = Vec::new();
        loop {
            let read = tokio::time::timeout(std::time::Duration::from_secs(10), stream.recv())
                .await
                .unwrap_or_else(|_| {
                    panic!(
                        "stream {}: recv() stalled after {bulk} bytes and {} other read(s), \
                         with no EOF",
                        stream.stream_id(),
                        rest.len()
                    )
                })
                .expect("the read half ends cleanly");
            match read {
                Some(bytes) if rest.is_empty() && bytes.iter().all(|&b| b == filler) => {
                    bulk += bytes.len()
                }
                Some(bytes) => rest.push(bytes),
                None => return (bulk, rest),
            }
        }
    }

    /// Writes a stream handle queued before it was dropped reach the peer ahead of the EOF
    /// the drop sends — including writes that were still waiting in the command channel,
    /// behind a write the send buffer refused, when the handle went.
    ///
    /// Dropping a handle closes its stream's writing half, but a drop cannot wait for room in
    /// the command channel and does not travel through it, so the pump can hear of it before
    /// it has read the handle's last writes. Closing the stream at that moment would put the
    /// FIN ahead of them, and the pump would then discard them as writes made after the
    /// close. The peer here does not read until everything is queued: its window closes, the
    /// stream's send buffer fills, and the pump stops reading commands — which is what keeps
    /// the last two writes in the channel.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn writes_queued_before_a_stream_handle_is_dropped_reach_the_peer_before_its_eof() {
        const BULK: usize = 4 << 20;
        let (closing, peer) = connected_client_and_server().await;

        let stream = closing.open_stream().expect("open a stream");
        let id = stream.stream_id();
        stream
            .send_reliable(vec![0x5A; BULK])
            .await
            .expect("the pump takes the bulk in");
        wait_until_send_buffer_full(&closing, id).await;
        stream
            .send_reliable(b"tail-one".to_vec())
            .await
            .expect("the command channel takes the write");
        stream
            .send_reliable(b"tail-two".to_vec())
            .await
            .expect("the command channel takes the write");
        assert_commands_waiting(&closing, 2).await;
        drop(stream);

        let theirs = tokio::time::timeout(std::time::Duration::from_secs(10), peer.accept_stream())
            .await
            .expect("the peer never saw the stream")
            .expect("accept_stream");
        assert_eq!(theirs.stream_id(), id);
        let (bulk, rest) = read_to_eof(&theirs, 0x5A).await;
        assert_eq!(bulk, BULK, "the bulk arrived short");
        assert_eq!(
            rest,
            vec![b"tail-one".to_vec(), b"tail-two".to_vec()],
            "the writes queued before the drop must reach the peer, in order, ahead of the EOF"
        );
    }

    /// A write made on a stream after its `disconnect()` never reaches the peer — reliable
    /// or not — including while the FIN is still waiting for room in the send buffer.
    ///
    /// This pins what `PhantomStream::disconnect` promises. The write returns `Ok`, because
    /// the command channel takes it; it is then discarded when the pump reaches it, which it
    /// does only once the FIN ahead of it has been admitted.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_write_after_a_stream_close_is_discarded_while_the_close_waits_for_room() {
        const BULK: usize = 4 << 20;
        let (closing, peer) = connected_client_and_server().await;

        let stream = closing.open_stream().expect("open a stream");
        let id = stream.stream_id();
        stream
            .send_reliable(vec![0x5A; BULK])
            .await
            .expect("the pump takes the bulk in");
        wait_until_send_buffer_full(&closing, id).await;
        stream.disconnect().await.expect("close the writing half");
        stream
            .send_unreliable(b"unreliable-after-the-close".to_vec())
            .await
            .expect("the command channel takes the write");
        stream
            .send_reliable(b"reliable-after-the-close".to_vec())
            .await
            .expect("the command channel takes the write");
        assert_commands_waiting(&closing, 3).await;

        let theirs = tokio::time::timeout(std::time::Duration::from_secs(10), peer.accept_stream())
            .await
            .expect("the peer never saw the stream")
            .expect("accept_stream");
        let (bulk, rest) = read_to_eof(&theirs, 0x5A).await;
        assert_eq!(bulk, BULK, "the bulk arrived short");
        assert!(
            rest.is_empty(),
            "the peer read {rest:?} on a stream that had been closed before it was written"
        );
        if let Ok(read) =
            tokio::time::timeout(std::time::Duration::from_millis(300), theirs.recv()).await
        {
            panic!("the peer read {read:?} after the EOF");
        }
    }

    /// One end of an in-memory pipe whose path can be cut — every frame in either direction
    /// then disappears, as on a network that has gone away — and which `migrate()` or
    /// `migrate_server()` restores, standing in for a rebind onto a path that works.
    struct CuttableTransport {
        inner: ChannelTransport,
        cut: Arc<AtomicBool>,
        migrations: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl SessionTransport for CuttableTransport {
        async fn send_bytes(&self, data: &[u8]) -> Result<(), CoreError> {
            if self.cut.load(Ordering::SeqCst) {
                return Ok(());
            }
            self.inner.send_bytes(data).await
        }

        async fn recv_bytes(&self) -> Result<Bytes, CoreError> {
            loop {
                let frame = self.inner.recv_bytes().await?;
                if !self.cut.load(Ordering::SeqCst) {
                    return Ok(frame);
                }
            }
        }

        fn supports_migration(&self) -> bool {
            true
        }

        async fn migrate(&self, _local_addr: String) -> Result<(), CoreError> {
            self.migrations.fetch_add(1, Ordering::SeqCst);
            self.cut.store(false, Ordering::SeqCst);
            Ok(())
        }

        async fn migrate_server(&self, _local_addr: String) -> Result<(), CoreError> {
            self.migrations.fetch_add(1, Ordering::SeqCst);
            self.cut.store(false, Ordering::SeqCst);
            Ok(())
        }
    }

    /// An upload larger than the send buffer is under way when the path dies, and the
    /// migration that would save the session has to go through while the upload is stalled.
    ///
    /// Nothing is acknowledged on a dead path, so the stream's send buffer stays full, the
    /// pump keeps holding the writes it refused, and it stops reading its command channel —
    /// which a second writer then fills. `migrate()` used to travel on that channel: it
    /// blocked for room in it, and had it found room the pump would still never have read it,
    /// so the session sat in `Migrating` until the liveness timer declared it dead, at exactly
    /// the moment a migration was what it needed. With `server_side` the migrating session
    /// holds the accepting end's keys and calls `migrate_server()`; otherwise it holds the
    /// connecting end's and calls `migrate()`.
    async fn migration_goes_through_while_an_upload_is_stalled_on_a_dead_path(server_side: bool) {
        const UPLOAD: usize = 2 << 20;
        let session_id = fixed_session_id();
        let (client_inner, server_inner) = paired_sessions(session_id);
        client_inner.set_state(SessionState::Connected);
        server_inner.set_state(SessionState::Connected);
        let (migrating_inner, peer_inner) = if server_side {
            (server_inner, client_inner)
        } else {
            (client_inner, server_inner)
        };
        let (migrating_t, peer_t) = ChannelTransport::pair();
        let cut = Arc::new(AtomicBool::new(false));
        let migrations = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let migrating = PhantomSession::from_accepted_server_session(
            "migrating".into(),
            CuttableTransport {
                inner: migrating_t,
                cut: cut.clone(),
                migrations: migrations.clone(),
            },
            migrating_inner,
        );
        let peer = PhantomSession::from_accepted_server_session("peer".into(), peer_t, peer_inner);

        // The peer reads everything it is sent, so once the path is back nothing but the
        // path stands between the upload and its end.
        let received = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let reader = {
            let peer = peer.clone();
            let received = received.clone();
            tokio::spawn(async move {
                while let Ok(bytes) = peer.recv().await {
                    received.fetch_add(bytes.len(), Ordering::SeqCst);
                }
            })
        };

        cut.store(true, Ordering::SeqCst);
        migrating
            .send(vec![0x5A; UPLOAD])
            .await
            .expect("the pump takes the upload in");
        // A second writer keeps handing the session small writes until told to stop, which
        // fills the command channel once the pump stops reading it. It counts what it handed
        // over, since all of that is owed to the peer as well.
        let stop = Arc::new(AtomicBool::new(false));
        let written = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let writer = {
            let migrating = migrating.clone();
            let stop = stop.clone();
            let written = written.clone();
            tokio::spawn(async move {
                while !stop.load(Ordering::SeqCst) && migrating.send(vec![0xC3; 64]).await.is_ok() {
                    written.fetch_add(64, Ordering::SeqCst);
                }
            })
        };

        // Witness: the upload's send buffer is full of segments nobody acknowledges, and the
        // command channel is full behind the writes the pump refused.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            let buffer_full = migrating
                .streams
                .get(&RAW_APP_STREAM_ID)
                .is_some_and(|s| s.send_buffer_full());
            if buffer_full && migrating.cmd_tx.capacity() == 0 {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the upload never stalled: send buffer full = {buffer_full}, command-channel \
                 room = {}",
                migrating.cmd_tx.capacity()
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        // The liveness sweep notices the silence: the state an embedder migrates on.
        while migrating.connection_state() != ConnectionState::Migrating {
            assert!(
                std::time::Instant::now() < deadline,
                "the dead path was never noticed; state {:?}",
                migrating.connection_state()
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        let bound = std::time::Duration::from_secs(2);
        let call = if server_side {
            tokio::time::timeout(bound, migrating.migrate_server("0.0.0.0:0".into())).await
        } else {
            tokio::time::timeout(bound, migrating.migrate("0.0.0.0:0".into())).await
        };
        assert!(
            matches!(call, Ok(Ok(()))),
            "the migration request did not return within {bound:?}: {call:?}"
        );
        let deadline = std::time::Instant::now() + bound;
        while migrations.load(Ordering::SeqCst) == 0 {
            assert!(
                std::time::Instant::now() < deadline,
                "the migration was accepted but not carried out within {bound:?}: the pump \
                 never read it while the upload was stalled"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        stop.store(true, Ordering::SeqCst);
        tokio::time::timeout(std::time::Duration::from_secs(30), writer)
            .await
            .expect("the second writer was never let through once the path was back")
            .expect("writer task");

        // And the session goes on: everything handed to it arrives over the restored path,
        // and the liveness sweep sees the path come back rather than declaring it dead.
        let owed = UPLOAD + written.load(Ordering::SeqCst);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        while received.load(Ordering::SeqCst) < owed {
            assert!(
                std::time::Instant::now() < deadline,
                "{} of {owed} bytes arrived after the migration; state {:?}",
                received.load(Ordering::SeqCst),
                migrating.connection_state()
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert_eq!(received.load(Ordering::SeqCst), owed);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while migrating.connection_state() != ConnectionState::Connected {
            assert!(
                std::time::Instant::now() < deadline,
                "the session never recovered from the migration; state {:?}",
                migrating.connection_state()
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        reader.abort();
        let _ = migrating.disconnect().await;
        let _ = peer.disconnect().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn migrate_goes_through_while_an_upload_is_stalled_on_a_dead_path() {
        migration_goes_through_while_an_upload_is_stalled_on_a_dead_path(false).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn migrate_server_goes_through_while_an_upload_is_stalled_on_a_dead_path() {
        migration_goes_through_while_an_upload_is_stalled_on_a_dead_path(true).await;
    }

    /// A migration requested and then a `disconnect()`, back to back, is carried out before
    /// the close — so the close's final flush goes out on the path the application moved
    /// to rather than on the one it moved away from.
    ///
    /// The two travel on different channels and the pump can find both waiting at once. On
    /// a single-threaded runtime nothing runs between the two calls, so the pump wakes to
    /// exactly that and picks between the arms at random; a close that did not take in the
    /// control queued ahead of it would skip the migration in about half of these rounds.
    #[tokio::test]
    async fn a_migration_requested_before_a_close_is_carried_out_first() {
        for round in 0..32 {
            let session_id = fixed_session_id();
            let (client_inner, server_inner) = paired_sessions(session_id);
            client_inner.set_state(SessionState::Connected);
            server_inner.set_state(SessionState::Connected);
            let (migrating_t, peer_t) = ChannelTransport::pair();
            let migrations = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let migrating = PhantomSession::from_accepted_server_session(
                "migrating".into(),
                CuttableTransport {
                    inner: migrating_t,
                    cut: Arc::new(AtomicBool::new(false)),
                    migrations: migrations.clone(),
                },
                client_inner,
            );
            let _peer =
                PhantomSession::from_accepted_server_session("peer".into(), peer_t, server_inner);
            let obs = migrating.observability();
            // Let the pump start and park, so the two requests below meet it together.
            tokio::task::yield_now().await;

            migrating
                .migrate("0.0.0.0:0".into())
                .await
                .expect("the migration request is taken");
            migrating.disconnect().await.expect("disconnect");

            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            while obs.snapshot().active_sessions != 0 {
                assert!(
                    std::time::Instant::now() < deadline,
                    "round {round}: the pump never exited"
                );
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
            assert_eq!(
                migrations.load(Ordering::SeqCst),
                1,
                "round {round}: the close went ahead of the migration requested before it"
            );
        }
    }

    #[tokio::test]
    async fn v2_recv_handles_coalesced_bundle_and_routes_each_subpayload() {
        use crate::transport::packet_coalescer::{CoalescerConfig, PacketCoalescer};

        let session_id = fixed_session_id();
        let (client_session, server_session) = paired_sessions(session_id);

        // Build a COALESCED bundle of three sub-payloads.
        let mut coalescer = PacketCoalescer::new(CoalescerConfig::default());
        coalescer.push(b"alpha");
        coalescer.push(b"bravo");
        coalescer.push(b"charlie");
        let bundle = coalescer.flush().expect("bundle");

        // Encrypt the bundle and wrap it in a V2 packet with
        // ENCRYPTED + COALESCED flags.
        let stream_id: TransportStreamId = 3;
        let flag_bits = PacketFlags::ENCRYPTED | PacketFlags::COALESCED;
        let header = PacketHeader::new(session_id, stream_id, 0, PacketFlags::new(flag_bits))
            .with_epoch(client_session.current_epoch());
        let ciphertext = client_session
            .encrypt_packet(&header, &bundle, &[])
            .expect("encrypt bundle");
        let v2 = PhantomPacket::new(header, ciphertext);

        let (demux, _ctrl_rx) = StreamDemultiplexer::new(16);
        let demux = Arc::new(demux);
        let streams: Arc<DashMap<u32, Arc<TransportStream>>> = Arc::new(DashMap::new());
        let (deliver_tx, mut deliver_rx) = mpsc::unbounded_channel::<DeliverItem>();
        let undelivered = AtomicU64::new(0);
        let (ack_a, ack_b) = mpsc::channel::<Vec<u8>>(4);
        let transport_send: Arc<ChannelTransport> = Arc::new(ChannelTransport {
            tx: ack_a,
            rx: Mutex::new(ack_b),
        });

        let obs = Observability::new(ObservabilityConfig::default());
        let mut scratch = test_recv_scratch(&obs, 256);
        let (no_link, no_inc_tx) = noop_accept_sinks();
        handle_packet(
            v2,
            session_id,
            &server_session,
            &streams,
            &demux,
            &transport_send,
            &transport_send,
            &deliver_tx,
            &undelivered,
            &mut scratch,
            &obs,
            LegType::Tcp,
            &no_link,
            &no_inc_tx,
            &connected_state(),
        )
        .await;

        // Each sub-payload is handed off IN ORDER through the single FIFO
        // delivery channel, every one tagged with the outer stream id, and the
        // total counted toward the undelivered backlog.
        let (sa, a) = match deliver_rx.recv().await.expect("alpha") {
            DeliverItem::Data(sid, bytes, _) => (sid, bytes),
            DeliverItem::Close(sid) => panic!("unexpected Close({sid}) for alpha"),
            DeliverItem::Retire(sid) => panic!("unexpected Retire({sid}) for alpha"),
        };
        let (sb, b) = match deliver_rx.recv().await.expect("bravo") {
            DeliverItem::Data(sid, bytes, _) => (sid, bytes),
            DeliverItem::Close(sid) => panic!("unexpected Close({sid}) for bravo"),
            DeliverItem::Retire(sid) => panic!("unexpected Retire({sid}) for bravo"),
        };
        let (sc, c) = match deliver_rx.recv().await.expect("charlie") {
            DeliverItem::Data(sid, bytes, _) => (sid, bytes),
            DeliverItem::Close(sid) => panic!("unexpected Close({sid}) for charlie"),
            DeliverItem::Retire(sid) => panic!("unexpected Retire({sid}) for charlie"),
        };
        assert_eq!(
            (sa, sb, sc),
            (stream_id as u32, stream_id as u32, stream_id as u32)
        );
        assert_eq!(&a[..], b"alpha");
        assert_eq!(&b[..], b"bravo");
        assert_eq!(&c[..], b"charlie");
        assert_eq!(
            undelivered.load(Ordering::Acquire),
            delivery_charge(5) + delivery_charge(5) + delivery_charge(7),
            "each sub-payload is charged its own item structure, not just its bytes"
        );
    }

    /// The delivery backlog stands at its cap plus one frame's charge before the reader
    /// notices, and [`MAX_DELIVERY_CHARGE_PER_FRAME`] is what that second term is published
    /// as. The cap is a flat 4 MiB everywhere it is quoted, so if a frame can charge more
    /// than the published overshoot then what a session really holds is more than what is
    /// written down.
    ///
    /// The expensive frame is not the fullest one. A `COALESCED` bundle becomes one queued
    /// item per non-empty sub-payload and each item carries the full structure charge, so
    /// the worst frame is the one carrying the most sub-payloads: a two-byte length prefix
    /// and the single byte that keeps the sub-payload from being skipped as empty. This
    /// builds exactly that frame at the largest size the receive gate admits and puts it
    /// through the real receive path.
    #[tokio::test]
    async fn one_frame_cannot_charge_the_backlog_more_than_the_published_overshoot() {
        use crate::transport::mtu::{MAX_RECV_FRAME, MAX_RECV_PAYLOAD};
        use crate::transport::packet_coalescer::{HEADER_SIZE, SUB_HEADER_SIZE};

        let session_id = fixed_session_id();
        let (client_session, server_session) = paired_sessions(session_id);

        // A bundle packed with the smallest sub-payload that still gets queued.
        let subs = (MAX_RECV_PAYLOAD - HEADER_SIZE) / (SUB_HEADER_SIZE + 1);
        let mut bundle = Vec::with_capacity(MAX_RECV_PAYLOAD);
        bundle.extend_from_slice(&(subs as u16).to_be_bytes());
        for _ in 0..subs {
            bundle.extend_from_slice(&1u16.to_be_bytes());
            bundle.push(0xA5);
        }

        let stream_id: TransportStreamId = 3;
        let flag_bits = PacketFlags::ENCRYPTED | PacketFlags::COALESCED;
        let header = PacketHeader::new(session_id, stream_id, 0, PacketFlags::new(flag_bits))
            .with_epoch(client_session.current_epoch());
        let ciphertext = client_session
            .encrypt_packet(&header, &bundle, &[])
            .expect("encrypt bundle");
        let packet = PhantomPacket::new(header, ciphertext);
        let wire = client_session
            .protect_packet(&packet)
            .expect("header protection");
        assert!(
            wire.len() <= MAX_RECV_FRAME,
            "this frame must be one the gate admits, or it is not the worst case the \
             backlog can be charged: {} B against {MAX_RECV_FRAME} B",
            wire.len()
        );

        let (demux, _ctrl_rx) = StreamDemultiplexer::new(16);
        let demux = Arc::new(demux);
        let streams: Arc<DashMap<u32, Arc<TransportStream>>> = Arc::new(DashMap::new());
        let (deliver_tx, _deliver_rx) = mpsc::unbounded_channel::<DeliverItem>();
        let undelivered = AtomicU64::new(0);
        let (ack_a, ack_b) = mpsc::channel::<Vec<u8>>(4);
        let transport_send: Arc<ChannelTransport> = Arc::new(ChannelTransport {
            tx: ack_a,
            rx: Mutex::new(ack_b),
        });

        let obs = Observability::new(ObservabilityConfig::default());
        let mut scratch = test_recv_scratch(&obs, 256);
        let (no_link, no_inc_tx) = noop_accept_sinks();
        handle_packet(
            packet,
            session_id,
            &server_session,
            &streams,
            &demux,
            &transport_send,
            &transport_send,
            &deliver_tx,
            &undelivered,
            &mut scratch,
            &obs,
            LegType::Tcp,
            &no_link,
            &no_inc_tx,
            &connected_state(),
        )
        .await;

        let charged = undelivered.load(Ordering::Acquire);
        // Positive control: a frame that queued one item, or none, would satisfy the bound
        // below without being the shape it is meant to test.
        assert!(
            charged > 100 * delivery_charge(1),
            "the frame queued almost nothing ({charged} B charged), so it is not \
             exercising the many-items case the overshoot is sized for"
        );
        assert!(
            charged <= MAX_DELIVERY_CHARGE_PER_FRAME,
            "one frame charged the backlog {charged} B against a published overshoot of \
             {MAX_DELIVERY_CHARGE_PER_FRAME} B — the backlog can stand higher above \
             {RECV_DELIVERY_HARD_CAP} B than the documentation says"
        );
    }

    /// Ordering across two COALESCED bundles: the single FIFO delivery channel
    /// must hand the first bundle's `[A, B, C]` and the second bundle's `[D]` to
    /// the consumer in exactly `A, B, C, D` — decoupling delivery from the reader
    /// must not reorder application bytes. (COALESCED is delivered immediately in
    /// arrival order — it is not reassembled by stream offset and is not mixed with
    /// RELIABLE frames on a stream by the live sender.)
    #[tokio::test]
    async fn delivery_preserves_order_across_coalesced_then_normal_frame() {
        use crate::transport::packet_coalescer::{CoalescerConfig, PacketCoalescer};

        let session_id = fixed_session_id();
        let (client_session, server_session) = paired_sessions(session_id);
        let stream_id: TransportStreamId = 1;

        let build_bundle = |seq: u32, items: &[&[u8]]| -> PhantomPacket {
            let mut coalescer = PacketCoalescer::new(CoalescerConfig::default());
            for it in items {
                coalescer.push(it);
            }
            let bundle = coalescer.flush().expect("bundle");
            let flag_bits = PacketFlags::ENCRYPTED | PacketFlags::COALESCED;
            let h = PacketHeader::new(
                session_id,
                stream_id,
                seq as u64,
                PacketFlags::new(flag_bits),
            )
            .with_epoch(client_session.current_epoch());
            let ct = client_session
                .encrypt_packet(&h, &bundle, &[])
                .expect("encrypt bundle");
            PhantomPacket::new(h, ct)
        };

        // Frame 1: COALESCED [A, B, C] at sequence 0; Frame 2: COALESCED [D] at seq 1.
        let coalesced = build_bundle(0, &[b"A", b"B", b"C"]);
        let normal = build_bundle(1, &[b"D"]);

        let (demux, _ctrl) = StreamDemultiplexer::new(16);
        let demux = Arc::new(demux);
        let streams: Arc<DashMap<u32, Arc<TransportStream>>> = Arc::new(DashMap::new());
        let (deliver_tx, mut deliver_rx) = mpsc::unbounded_channel::<DeliverItem>();
        let undelivered = AtomicU64::new(0);
        let (ack_a, ack_b) = mpsc::channel::<Vec<u8>>(8);
        let transport_send: Arc<ChannelTransport> = Arc::new(ChannelTransport {
            tx: ack_a,
            rx: Mutex::new(ack_b),
        });
        let obs = Observability::new(ObservabilityConfig::default());
        let mut scratch = test_recv_scratch(&obs, 256);

        for pkt in [coalesced, normal] {
            let (no_link, no_inc_tx) = noop_accept_sinks();
            handle_packet(
                pkt,
                session_id,
                &server_session,
                &streams,
                &demux,
                &transport_send,
                &transport_send,
                &deliver_tx,
                &undelivered,
                &mut scratch,
                &obs,
                LegType::Tcp,
                &no_link,
                &no_inc_tx,
                &connected_state(),
            )
            .await;
        }

        // Drain the FIFO delivery channel — order must be exactly A, B, C, D.
        let mut got: Vec<Bytes> = Vec::new();
        while let Ok(item) = deliver_rx.try_recv() {
            if let DeliverItem::Data(_sid, b, _) = item {
                got.push(b);
            }
        }
        let seen: Vec<&[u8]> = got.iter().map(|b| &b[..]).collect();
        assert_eq!(seen, vec![&b"A"[..], b"B", b"C", b"D"]);
    }

    /// **A.5 reordered delivery.** Two RELIABLE frames arriving OUT OF sequence order on
    /// the wire (seq 1 before seq 0) must be delivered to the app IN sequence
    /// order (`zero`, `one`). Before the receive-side reorder fix, the live pump
    /// delivered in decrypt-arrival order, breaking reliable in-order delivery
    /// over a reordering (UDP) path.
    #[tokio::test]
    async fn reliable_frames_delivered_in_sequence_order_despite_arrival_order() {
        let session_id = fixed_session_id();
        let (client_session, server_session) = paired_sessions(session_id);
        let stream_id: TransportStreamId = 1;

        let f0 = decode_recv_frame(
            &build_app_frame(&client_session, session_id, stream_id, 0, b"zero"),
            session_id,
        );
        let f1 = decode_recv_frame(
            &build_app_frame(&client_session, session_id, stream_id, 1, b"one"),
            session_id,
        );

        let (demux, _ctrl) = StreamDemultiplexer::new(16);
        let demux = Arc::new(demux);
        let streams: Arc<DashMap<u32, Arc<TransportStream>>> = Arc::new(DashMap::new());
        let (deliver_tx, mut deliver_rx) = mpsc::unbounded_channel::<DeliverItem>();
        let undelivered = AtomicU64::new(0);
        let (ack_a, ack_b) = mpsc::channel::<Vec<u8>>(8);
        let transport_send: Arc<ChannelTransport> = Arc::new(ChannelTransport {
            tx: ack_a,
            rx: Mutex::new(ack_b),
        });
        let obs = Observability::new(ObservabilityConfig::default());
        let mut scratch = test_recv_scratch(&obs, 256);

        // Deliver OUT OF ORDER on the wire: seq 1 first, then seq 0.
        for pkt in [f1, f0] {
            let (no_link, no_inc_tx) = noop_accept_sinks();
            handle_packet(
                pkt,
                session_id,
                &server_session,
                &streams,
                &demux,
                &transport_send,
                &transport_send,
                &deliver_tx,
                &undelivered,
                &mut scratch,
                &obs,
                LegType::Tcp,
                &no_link,
                &no_inc_tx,
                &connected_state(),
            )
            .await;
        }

        let mut got: Vec<Bytes> = Vec::new();
        while let Ok(item) = deliver_rx.try_recv() {
            if let DeliverItem::Data(_sid, b, _) = item {
                got.push(b);
            }
        }
        let seen: Vec<&[u8]> = got.iter().map(|b| &b[..]).collect();
        assert_eq!(
            seen,
            vec![&b"zero"[..], b"one"],
            "reliable data must be delivered in sequence order, not arrival order"
        );
    }

    /// **A.5 control-gap regression (the bidirectional-hang fix).** Reliable data
    /// whose wire `header.sequence` has a HOLE (a control frame — ACK /
    /// WINDOW_UPDATE — consumed that sequence) but whose gap-free `stream_offset`
    /// is contiguous must still deliver in order WITHOUT stalling on the sequence
    /// hole. Here header seqs are 0 and 2 (seq 1 = a control frame), offsets 0 and
    /// 1. Reordering keyed on the raw `header.sequence` hangs forever waiting for
    /// seq 1; keyed on `stream_offset` it delivers `a, b`.
    #[tokio::test]
    async fn reliable_delivery_skips_control_frame_sequence_holes() {
        let session_id = fixed_session_id();
        let (client_session, server_session) = paired_sessions(session_id);
        let stream_id: TransportStreamId = 1;

        // header.seq 0, offset 0, "a"; header.seq 2, offset 1, "b" (seq 1 is a hole).
        let a = decode_recv_frame(
            &build_app_frame_with_offset(&client_session, session_id, stream_id, 0, 0, b"a"),
            session_id,
        );
        let b = decode_recv_frame(
            &build_app_frame_with_offset(&client_session, session_id, stream_id, 2, 1, b"b"),
            session_id,
        );

        let (demux, _ctrl) = StreamDemultiplexer::new(16);
        let demux = Arc::new(demux);
        let streams: Arc<DashMap<u32, Arc<TransportStream>>> = Arc::new(DashMap::new());
        let (deliver_tx, mut deliver_rx) = mpsc::unbounded_channel::<DeliverItem>();
        let undelivered = AtomicU64::new(0);
        let (ack_a, ack_b) = mpsc::channel::<Vec<u8>>(8);
        let transport_send: Arc<ChannelTransport> = Arc::new(ChannelTransport {
            tx: ack_a,
            rx: Mutex::new(ack_b),
        });
        let obs = Observability::new(ObservabilityConfig::default());
        let mut scratch = test_recv_scratch(&obs, 256);

        for pkt in [a, b] {
            let (no_link, no_inc_tx) = noop_accept_sinks();
            handle_packet(
                pkt,
                session_id,
                &server_session,
                &streams,
                &demux,
                &transport_send,
                &transport_send,
                &deliver_tx,
                &undelivered,
                &mut scratch,
                &obs,
                LegType::Tcp,
                &no_link,
                &no_inc_tx,
                &connected_state(),
            )
            .await;
        }

        let mut got: Vec<Bytes> = Vec::new();
        while let Ok(item) = deliver_rx.try_recv() {
            if let DeliverItem::Data(_sid, x, _) = item {
                got.push(x);
            }
        }
        let seen: Vec<&[u8]> = got.iter().map(|b| &b[..]).collect();
        assert_eq!(
            seen,
            vec![&b"a"[..], b"b"],
            "reliable data must deliver in stream_offset order, skipping control-frame \
             sequence holes (not stall on them)"
        );
    }

    /// A peer that ignores flow control and floods application data faster than
    /// the app drains must NOT grow the receive backlog without bound: once the
    /// undelivered backlog crosses the reader's hard cap, the session is torn
    /// down (state → `Closed`) instead of buffering unboundedly. The app here
    /// never calls `recv()`, so the delivery channel fills and the reader's
    /// pre-decrypt cap gate fires.
    ///
    /// The flood uses the largest frame the receive gate admits, which is also the
    /// fastest way to the cap: bigger frames are refused before they are decrypted, and
    /// smaller ones cost the flooder a frame each for less backlog. That the cap still
    /// trips at that size is the part worth checking — a gate that made the cap
    /// unreachable would have quietly replaced one bound with another.
    #[tokio::test]
    async fn peer_ignoring_flow_control_trips_delivery_hard_cap_and_closes_session() {
        let session_id = fixed_session_id();
        let (client_inner, server_inner) = paired_sessions(session_id);
        let (client_t, server_t) = ChannelTransport::pair();
        let client_t = Arc::new(client_t);

        // Full server-side session with a running pump; the app NEVER drains it.
        let server = PhantomSession::from_accepted_server_session(
            "flooder".to_string(),
            server_t,
            server_inner,
        );

        // Drain and discard everything the server sends back (ACKs / control)
        // so the server reader never blocks on the back channel — a real
        // flooding peer likewise keeps emptying its socket. Without this the
        // reader would wedge on its own ACK send and the cap could never trip.
        let drain_t = client_t.clone();
        let drainer = tokio::spawn(async move { while drain_t.recv_bytes().await.is_ok() {} });

        // Malicious client: flood valid RELIABLE app packets with unique
        // monotonic sequences (so none are replay-dropped) and never honor a
        // WINDOW_UPDATE — i.e. ignore flow control entirely.
        let payload = vec![0xABu8; crate::transport::mtu::MAX_APP_CHUNK];
        let mut seq: u32 = 0;
        let mut torn_down = false;
        // Comfortably more than `RECV_DELIVERY_HARD_CAP / (MAX_APP_CHUNK +
        // DELIVERY_ITEM_OVERHEAD_BYTES)`, so the cap is reached well before the loop runs
        // out and a failure means the cap did not trip rather than that the flood was short.
        for _ in 0..8000 {
            if server.connection_state() == ConnectionState::Closed {
                torn_down = true;
                break;
            }
            let flag_bits = PacketFlags::RELIABLE | PacketFlags::ENCRYPTED;
            let header = PacketHeader::new(session_id, 1, seq as u64, PacketFlags::new(flag_bits))
                .with_epoch(client_inner.current_epoch());
            // Reliable plaintext = [stream_offset: u32 BE][payload] (A.5). Offsets
            // are contiguous (== seq), so every frame delivers in order and grows
            // the undelivered backlog — exactly what should trip the hard cap.
            let mut pt = Vec::with_capacity(4 + payload.len());
            pt.extend_from_slice(&seq.to_be_bytes());
            pt.extend_from_slice(&payload);
            let ct = client_inner
                .encrypt_packet(&header, &pt, &[])
                .expect("encrypt");
            // Bound the send so a torn-down (or wedged) transport can't hang the
            // test: a closed channel or a stalled reader both mean the flood is
            // no longer absorbed — i.e. the session is being torn down.
            // This frame traverses the server pump's transport, which removes
            // header protection on recv — so apply it on the way out.
            let packet = PhantomPacket::new(header, ct);
            let wire = client_inner
                .protect_packet(&packet)
                .expect("header protection");
            match tokio::time::timeout(
                std::time::Duration::from_secs(5),
                client_t.send_bytes(&wire),
            )
            .await
            {
                Ok(Ok(())) => {}
                _ => {
                    torn_down = true;
                    break;
                }
            }
            seq = seq.wrapping_add(1);
            tokio::task::yield_now().await;
        }
        assert!(
            torn_down,
            "a peer flooding past the delivery hard cap must get its session torn down"
        );

        // Definitive: the session ends up Closed.
        let mut closed = false;
        for _ in 0..200 {
            if server.connection_state() == ConnectionState::Closed {
                closed = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        drainer.abort();
        assert!(
            closed,
            "session state must be Closed after the hard cap trips"
        );
    }

    /// Phase 4.4 — BBR ACK feedback drives the pacer rate. Build a
    /// realistic DeliverySample with known sent_at/acked_at timestamps
    /// and packet size; assert that calling `on_packet_acked` causes
    /// the pacer to leave its default unlimited state with a finite
    /// finite positive rate.
    #[tokio::test]
    async fn bbr_on_ack_drives_pacer_rate() {
        use crate::transport::bandwidth_estimator::DeliverySample;
        use std::time::{Duration, Instant};

        let session_id = fixed_session_id();
        let (client_session, _server_session) = paired_sessions(session_id);

        // The default Pacer is `unlimited` — track it before/after.
        assert!(!client_session.pacer().is_enabled());

        // Simulate sending a 1500-byte packet, then receiving an ACK
        // 20 ms later. We feed a few samples in a row so the EMA
        // estimator has data to work with.
        let now = Instant::now();
        for i in 0..16 {
            let sent_at = now - Duration::from_millis(20 + i * 5);
            let acked_at = now - Duration::from_millis(i * 5);
            let sample = DeliverySample {
                delivered_bytes: 0,
                delivered_at: sent_at,
                sent_at,
                acked_at,
                packet_bytes: 1500,
                is_app_limited: false,
                ack_delay_us: 100,
                rtt_sampled: true,
            };
            client_session.on_packet_sent(1500);
            let _ = client_session.on_packet_acked(sample);
        }

        // The pacer should now be set to a real rate (still
        // "unlimited" handle, but with a finite stored rate). The
        // BandwidthEstimator's `pacing_rate()` is what gets pushed
        // into the pacer; assert it is non-zero and finite.
        let snap = client_session.bandwidth_snapshot();
        assert!(
            snap.pacing_rate_bps > 0,
            "expected pacing_rate to be non-zero, got {}",
            snap.pacing_rate_bps,
        );
        // The pacer's stored rate must match the estimator's view
        // (Session.on_packet_acked mirrors them).
        assert_eq!(client_session.pacer().rate(), snap.pacing_rate_bps);
        // ...and the rate must now be governing something. A rate written into
        // a disabled pacer is the defect this test was named for and did not
        // catch: BBR computed a pacing rate for every session ever opened and
        // nothing on the send path ever asked for it.
        assert!(
            client_session.pacer().is_enabled(),
            "the estimator measured {} B/s and pacing is still switched off",
            snap.bottleneck_bw_bps
        );
    }

    /// A migration lands on a different network, so the old path's rate must not
    /// meter the new one. `reset_congestion` drops the estimate; pacing has to
    /// go with it, back to the same "nothing measured yet" state a fresh session
    /// starts in — otherwise the first flight on the new path is metered against
    /// a rate belonging to a path that is gone.
    #[tokio::test]
    async fn a_congestion_reset_puts_pacing_back_to_unmeasured() {
        let session_id = fixed_session_id();
        let (client_session, _server_session) = paired_sessions(session_id);

        seed_bandwidth_estimate(
            &client_session,
            100,
            1_200,
            std::time::Duration::from_millis(200),
        );
        assert!(
            client_session.pacer().is_enabled(),
            "precondition: a measured path paces"
        );

        client_session.reset_congestion();

        assert_eq!(
            client_session.bandwidth_snapshot().bottleneck_bw_bps,
            0,
            "the reset must drop the old path's estimate"
        );
        assert!(
            !client_session.pacer().is_enabled(),
            "pacing survived a congestion reset — the new path would be metered at the \
             dead path's rate"
        );
    }

    /// Phase 4.3 — WINDOW_UPDATE round-trip under the cumulative-limit model.
    /// The receive **delivery** task moves the limit on real app consumption and stages it;
    /// the **send loop** flushes it as a single encrypted WINDOW_UPDATE via
    /// `flush_pending_window_updates`, eight big-endian bytes of it. The sender then takes
    /// the **maximum** of the announced total and the one it already held — it does not add.
    #[tokio::test]
    async fn flow_control_window_update_round_trip() {
        use crate::transport::stream::INITIAL_STREAM_WINDOW;

        let session_id = fixed_session_id();
        let (client_session, server_session) = paired_sessions(session_id);

        let stream_id: TransportStreamId = 9;
        let server_streams: Arc<DashMap<u32, Arc<TransportStream>>> = Arc::new(DashMap::new());
        let server_stream = Arc::new(TransportStream::new(stream_id));
        server_streams.insert(stream_id as u32, server_stream.clone());

        // Client also has a Stream so we can apply the inbound limit.
        let client_stream = Arc::new(TransportStream::new(stream_id));

        // Pre-drain the client's peer_send_window so the limit has a real
        // effect to assert against.
        let drain = INITIAL_STREAM_WINDOW - 1000;
        assert!(client_stream.try_consume_send_window(drain));
        assert_eq!(client_stream.peer_send_window(), 1000);

        // The delivery task moves the limit on real consumption: model one drain that
        // crosses the half-window threshold and stage the limit exactly as
        // `run_data_pump`'s delivery task does.
        let consumed = INITIAL_STREAM_WINDOW / 2 + 1;
        let limit = server_stream
            .record_app_consumed(consumed, true)
            .expect("threshold crossed → limit advertised");
        server_stream.stage_window_update_limit(limit);

        // The send loop flushes the staged limit as a single WINDOW_UPDATE.
        let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(4);
        let (back_tx, back_rx) = mpsc::channel::<Vec<u8>>(4);
        let server_outbound: Arc<ChannelTransport> = Arc::new(ChannelTransport {
            tx: out_tx,
            rx: Mutex::new(back_rx),
        });
        let _keep = back_tx;
        let obs = Observability::new(ObservabilityConfig::default());
        flush_pending_window_updates(
            &server_outbound,
            &server_session,
            session_id,
            &server_streams,
            &obs,
        )
        .await;

        // Exactly one WINDOW_UPDATE was emitted; decrypt it and read the limit.
        let frame = tokio::time::timeout(std::time::Duration::from_millis(100), out_rx.recv())
            .await
            .expect("expected a WINDOW_UPDATE frame")
            .expect("channel open");
        let pv2 = client_session.parse_protected(&frame).unwrap();
        assert!(pv2.header.flags.contains(PacketFlags::WINDOW_UPDATE));
        // The control frame's sequence comes from the stream's own send space —
        // distinct from any data packet so the AEAD nonce never repeats.
        let pt = client_session
            .decrypt_packet(&pv2.header, &pv2.payload, &[])
            .expect("decrypt WINDOW_UPDATE");
        assert_eq!(pt.len(), WINDOW_UPDATE_PAYLOAD_LEN);
        let announced = u64::from_be_bytes(
            <[u8; WINDOW_UPDATE_PAYLOAD_LEN]>::try_from(&pt[..]).expect("length just asserted"),
        );
        assert_eq!(
            announced, limit,
            "WINDOW_UPDATE carries the cumulative limit (bytes consumed plus one window)"
        );
        // Exactly one frame was emitted — nothing else is queued on the wire.
        assert!(
            out_rx.try_recv().is_err(),
            "exactly one WINDOW_UPDATE must be emitted"
        );

        // The staged slot is now empty — a second flush emits nothing.
        flush_pending_window_updates(
            &server_outbound,
            &server_session,
            session_id,
            &server_streams,
            &obs,
        )
        .await;
        assert!(
            out_rx.try_recv().is_err(),
            "no spurious second WINDOW_UPDATE after the limit was already flushed"
        );

        // Apply the limit on the client side. It has sent `drain` bytes, so the room it is
        // left with is the announced total less what it has already spent — and a second
        // application of the same frame adds nothing, which is what makes the frame safe to
        // duplicate.
        client_stream.apply_peer_window_limit(announced);
        let room = announced - u64::from(drain);
        assert_eq!(u64::from(client_stream.peer_send_window()), room);
        client_stream.apply_peer_window_limit(announced);
        assert_eq!(u64::from(client_stream.peer_send_window()), room);
    }

    /// The flow-control persist probe as it actually reaches the wire.
    ///
    /// A stream the peer's window has stopped, with nothing outstanding, has no event left
    /// that could free it: no acknowledgement is coming, and the room that would arrive
    /// rides in a frame nothing retransmits. The drain therefore emits a probe — and what it
    /// emits has to be checked here rather than at the stream, because it is this path that
    /// decides what the peer actually receives. The frame is `RELIABLE | ENCRYPTED`, carries
    /// its four-byte stream offset and **not one byte of the payload queued behind it**, and
    /// is not a FIN.
    #[tokio::test]
    async fn a_window_blocked_drain_puts_an_empty_probe_on_the_wire() {
        let session_id = fixed_session_id();
        let (client_session, server_session) = paired_sessions(session_id);

        let (tx_a, mut rx_a) = mpsc::channel::<Vec<u8>>(32);
        let (tx_b, rx_b) = mpsc::channel::<Vec<u8>>(32);
        let transport: Arc<ChannelTransport> = Arc::new(ChannelTransport {
            tx: tx_a,
            rx: Mutex::new(rx_b),
        });
        let _keep = tx_b;

        let streams: Arc<DashMap<u32, Arc<TransportStream>>> = Arc::new(DashMap::new());
        let blocked = Arc::new(TransportStream::new(7));
        // A window closes by sending, so one segment has already gone out and been
        // acknowledged — which is also the delivered offset a probe repeats.
        blocked
            .send_reliable(Bytes::from_static(b"delivered"))
            .await
            .unwrap();
        let sent = blocked
            .poll_send(u64::MAX, 0, std::time::Instant::now(), false)
            .await
            .expect("the initial window admits the first segment");
        blocked.ack(sent.stream_offset).await;
        assert!(blocked.try_consume_send_window(blocked.peer_send_window()));
        blocked
            .send_reliable(Bytes::from_static(b"queued-behind-a-closed-window"))
            .await
            .unwrap();
        streams.insert(7, blocked.clone());

        let obs = Observability::new(ObservabilityConfig::default());
        drain_streams_priority_ordered(&transport, &client_session, session_id, &streams, &obs)
            .await;

        let frame = tokio::time::timeout(std::time::Duration::from_millis(100), rx_a.recv())
            .await
            .expect("a blocked stream with nothing outstanding must probe")
            .expect("channel open");
        let v2 = server_session.parse_protected(&frame).unwrap();
        assert!(v2.header.flags.contains(PacketFlags::RELIABLE));
        assert!(v2.header.flags.contains(PacketFlags::ENCRYPTED));
        assert!(
            !v2.header.flags.contains(PacketFlags::FIN),
            "the probe must not be mistaken for the FIN sentinel"
        );
        let plaintext = server_session
            .decrypt_packet(&v2.header, &v2.payload, &[])
            .expect("decrypt the probe");
        assert_eq!(
            plaintext.len(),
            4,
            "the probe carried {} application bytes past a closed window",
            plaintext.len() - 4
        );
        assert_eq!(
            blocked.peer_send_window(),
            0,
            "the probe must not debit a window that has nothing in it"
        );
        assert!(
            rx_a.try_recv().is_err(),
            "one probe per interval — the drain emitted more than one"
        );
    }

    /// The other half of the same exchange: what the receiver does with a probe.
    ///
    /// It re-states the stream's current limit — every byte its application has consumed
    /// plus one advertised window — which is a total, so one answer makes up for however many
    /// earlier `WINDOW_UPDATE` frames the path ate. It is still bounded by consumption: a
    /// receiver whose application has read nothing answers with the number the peer is
    /// already stopped at, which is what leaves it able to hold a peer still.
    #[tokio::test]
    async fn a_probe_is_answered_with_the_receivers_current_limit() {
        use crate::transport::stream::INITIAL_STREAM_WINDOW;

        let session_id = fixed_session_id();
        let (client_session, server_session) = paired_sessions(session_id);
        let stream_id: TransportStreamId = 9;

        // Two receiving streams, differing only in whether their application read anything.
        let consumed = INITIAL_STREAM_WINDOW / 4; // below the half-window emission threshold
        let reading = Arc::new(TransportStream::new(stream_id));
        assert_eq!(
            reading.record_app_consumed(consumed, true),
            None,
            "below the threshold no frame is emitted — that is the state a probe finds"
        );
        let idle = Arc::new(TransportStream::new(stream_id));
        let opening = u64::from(INITIAL_STREAM_WINDOW);

        // Distinct packet numbers per case: the two probes share one `server_session`, and
        // a repeat of a packet number it has already opened is rejected by the replay window
        // (Invariant 4) before it reaches the probe branch at all — which would leave the
        // second case asserting nothing.
        for (pn, (stream, expected)) in [
            (reading, Some(opening + u64::from(consumed))),
            (idle, Some(opening)),
        ]
        .into_iter()
        .enumerate()
        {
            let streams: Arc<DashMap<u32, Arc<TransportStream>>> = Arc::new(DashMap::new());
            streams.insert(stream_id as u32, stream.clone());

            let (demux, _ctrl_rx) = StreamDemultiplexer::new(16);
            let demux = Arc::new(demux);
            let (deliver_tx, mut deliver_rx) = mpsc::unbounded_channel::<DeliverItem>();
            let undelivered = AtomicU64::new(0);
            let (ack_a, ack_b) = mpsc::channel::<Vec<u8>>(4);
            let transport_send: Arc<ChannelTransport> = Arc::new(ChannelTransport {
                tx: ack_a,
                rx: Mutex::new(ack_b),
            });
            let obs = Observability::new(ObservabilityConfig::default());
            let mut scratch = test_recv_scratch(&obs, 256);
            let (no_link, no_inc_tx) = noop_accept_sinks();

            // A reliable frame with an empty payload: the probe, exactly as the drain above
            // puts it on the wire.
            let frame = build_app_frame_with_offset(
                &client_session,
                session_id,
                stream_id,
                pn as u32,
                0,
                b"",
            );
            handle_packet(
                decode_recv_frame(&frame, session_id),
                session_id,
                &server_session,
                &streams,
                &demux,
                &transport_send,
                &transport_send,
                &deliver_tx,
                &undelivered,
                &mut scratch,
                &obs,
                LegType::Tcp,
                &no_link,
                &no_inc_tx,
                &connected_state(),
            )
            .await;

            assert_eq!(
                stream.take_pending_window_update(),
                expected,
                "the answer to a probe must be the limit the application earned, and the \
                 non-reading receiver's must be the one its peer already has"
            );
            assert!(
                deliver_rx.try_recv().is_err(),
                "an empty probe was handed to the application as data"
            );
        }
    }

    /// Phase 4.3 — priority scheduler ordering. Two streams enqueue
    /// data simultaneously; the higher-priority one must be drained
    /// first, all of its data before any of the lower one's.
    #[tokio::test]
    async fn priority_scheduler_drains_higher_priority_stream_first() {
        // Build a real Session (any crypto state — we only inspect
        // send order, not ciphertext) and an Arc<Stream> per stream.
        let session_id = fixed_session_id();
        let (client_session, _server_session) = paired_sessions(session_id);

        // Capture every outbound packet by stuffing into a channel-
        // backed transport whose tx end we can drain after.
        let (tx_a, mut rx_a) = mpsc::channel::<Vec<u8>>(32);
        let (tx_b, rx_b) = mpsc::channel::<Vec<u8>>(32);
        let transport: Arc<ChannelTransport> = Arc::new(ChannelTransport {
            tx: tx_a,
            rx: Mutex::new(rx_b),
        });
        let _keep = tx_b; // keep the recv side alive

        let streams: Arc<DashMap<u32, Arc<TransportStream>>> = Arc::new(DashMap::new());

        // Stream 11: low priority (1), 3 reliable chunks.
        let low = Arc::new(TransportStream::new(11));
        low.set_priority(1);
        low.send_reliable(Bytes::from_static(b"L0")).await.unwrap();
        low.send_reliable(Bytes::from_static(b"L1")).await.unwrap();
        low.send_reliable(Bytes::from_static(b"L2")).await.unwrap();
        streams.insert(11, low);

        // Stream 22: HIGH priority (100), 3 reliable chunks.
        let hi = Arc::new(TransportStream::new(22));
        hi.set_priority(100);
        hi.send_reliable(Bytes::from_static(b"H0")).await.unwrap();
        hi.send_reliable(Bytes::from_static(b"H1")).await.unwrap();
        hi.send_reliable(Bytes::from_static(b"H2")).await.unwrap();
        streams.insert(22, hi);

        let obs = Observability::new(ObservabilityConfig::default());
        drain_streams_priority_ordered(&transport, &client_session, session_id, &streams, &obs)
            .await;

        // Pull all packets off the channel and verify their order:
        // the three H* chunks must come before any L* chunk.
        let mut order: Vec<&'static str> = Vec::new();
        while let Ok(frame) =
            tokio::time::timeout(std::time::Duration::from_millis(50), rx_a.recv()).await
        {
            let bytes = match frame {
                Some(b) => b,
                None => break,
            };
            let v2 = _server_session.parse_protected(&bytes).unwrap();
            // Decrypt under the SERVER role so the per-direction key
            // matches the client-side encrypt.
            let plaintext = _server_session
                .decrypt_packet(&v2.header, &v2.payload, &[])
                .expect("decrypt");
            // Reliable frames carry a 4-byte stream_offset prefix (A.5); the tag is
            // the application payload after it.
            let tag: &'static str = match &plaintext[4..] {
                b"H0" => "H0",
                b"H1" => "H1",
                b"H2" => "H2",
                b"L0" => "L0",
                b"L1" => "L1",
                b"L2" => "L2",
                other => panic!("unexpected payload {:?}", other),
            };
            order.push(tag);
        }

        // All H* before any L*.
        let first_low = order
            .iter()
            .position(|s| s.starts_with('L'))
            .unwrap_or(order.len());
        let last_high = order.iter().rposition(|s| s.starts_with('H')).unwrap();
        assert!(
            last_high < first_low,
            "strict priority violated: order = {:?}",
            order
        );
    }

    #[tokio::test]
    async fn v2_recv_echoes_path_validation_challenge_back_as_response() {
        // Two paired sessions on different IDs (so neither has a
        // pending challenge for the path). The "responder" sees a
        // PATH_VALIDATION packet on a new path id and must echo the
        // 32-byte payload back via the transport.
        let session_id = fixed_session_id();
        let (client_session, server_session) = paired_sessions(session_id);

        // Build a PATH_VALIDATION packet with ENCRYPTED + path_id=7.
        let path_id: u8 = 7;
        let payload = [0xDEu8; crate::transport::path::PATH_CHALLENGE_LEN];
        let flag_bits = PacketFlags::ENCRYPTED | PacketFlags::PATH_VALIDATION;
        let header = PacketHeader::new(session_id, 0, 0, PacketFlags::new(flag_bits))
            .with_epoch(client_session.current_epoch())
            .with_path_id(path_id);
        let ciphertext = client_session
            .encrypt_packet(&header, &payload, &[])
            .expect("encrypt challenge");
        let v2 = PhantomPacket::new(header, ciphertext);

        let (demux, _ctrl_rx) = StreamDemultiplexer::new(16);
        let demux = Arc::new(demux);
        let streams: Arc<DashMap<u32, Arc<TransportStream>>> = Arc::new(DashMap::new());
        let (deliver_tx, _deliver_rx) = mpsc::unbounded_channel::<DeliverItem>();
        let undelivered = AtomicU64::new(0);
        // Server's outbound transport — captures the echo back.
        let (echo_tx, mut echo_rx) = mpsc::channel::<Vec<u8>>(4);
        let (back_tx, back_rx) = mpsc::channel::<Vec<u8>>(4);
        let transport_send: Arc<ChannelTransport> = Arc::new(ChannelTransport {
            tx: echo_tx,
            rx: Mutex::new(back_rx),
        });
        let _back_tx_keepalive = back_tx; // keep the recv side alive

        let obs = Observability::new(ObservabilityConfig::default());
        let mut scratch = test_recv_scratch(&obs, 256);

        let (no_link, no_inc_tx) = noop_accept_sinks();
        handle_packet(
            v2,
            session_id,
            &server_session,
            &streams,
            &demux,
            &transport_send,
            &transport_send,
            &deliver_tx,
            &undelivered,
            &mut scratch,
            &obs,
            LegType::Tcp,
            &no_link,
            &no_inc_tx,
            &connected_state(),
        )
        .await;

        // Server should have emitted a PATH_VALIDATION response on the
        // outbound transport. Pull it out and verify it carries the
        // same payload back.
        let echo_bytes =
            tokio::time::timeout(std::time::Duration::from_millis(200), echo_rx.recv())
                .await
                .expect("echo should arrive")
                .expect("channel open");

        // Decrypt the echo on the original (client) side — server-side
        // ciphertext authenticates the round-trip.
        // The server emitted this echo with header protection; unmask from the
        // client side (== the server's send HP key).
        let echo_v2 = client_session.parse_protected(&echo_bytes).unwrap();
        assert!(echo_v2.header.flags.contains(PacketFlags::PATH_VALIDATION));
        assert_eq!(echo_v2.header.path_id, path_id);
    }

    // ────────────────────────────────────────────────────────────────────
    // 0-RTT early-data
    // ────────────────────────────────────────────────────────────────────

    /// Full 0-RTT round-trip over `ChannelTransport`: a priming handshake
    /// populates the server cache and yields a resumption hint; a second
    /// connect via `connect_with_resumption` carries application early-data
    /// sealed inside the resuming ClientHello, which the server decrypts and
    /// surfaces. The client learns the verdict via `early_data_accepted()`.
    ///
    /// The server side runs inline (not a spawned task) so its
    /// `ChannelTransport` halves stay alive in scope — dropping them
    /// would close the client's data pump and flip the session to
    /// `Closed` before the assertions run.
    #[tokio::test]
    async fn zero_rtt_early_data_full_round_trip() {
        // One HandshakeServer shared across both phases so its session
        // cache persists between the priming handshake and the resume.
        let server_hs = HandshakeServer::new().unwrap();
        let server_pinned_key = server_hs.verifying_key().clone();
        let client_ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();

        // ── Step 1: prime — a normal handshake fills the cache ──
        let (c1, s1) = ChannelTransport::pair();
        let phase1_session =
            PhantomSession::connect_with_transport("test:9000", c1, server_pinned_key.clone());

        let hello_bytes = s1.recv_bytes().await.unwrap();
        let ch = borsh::from_slice::<ClientHello>(&hello_bytes).unwrap();
        let retry = match server_hs.process_client_hello(&ch, 0, client_ip) {
            HandshakeResponse::Retry(r) => r,
            _ => panic!("expected Retry"),
        };
        s1.send_bytes(&ServerReply::Retry(retry).to_wire().unwrap())
            .await
            .unwrap();
        let next = s1.recv_bytes().await.unwrap();
        let ch2 = borsh::from_slice::<ClientHello>(&next).unwrap();
        match server_hs.process_client_hello(&ch2, 0, client_ip) {
            HandshakeResponse::Success(sh, _session, _) => {
                s1.send_bytes(&ServerReply::Hello(sh).to_wire().unwrap())
                    .await
                    .unwrap();
            }
            _ => panic!("expected Success"),
        }

        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        assert_eq!(
            phase1_session.connection_state(),
            ConnectionState::Connected
        );
        let hint = phase1_session
            .resumption_hint()
            .await
            .expect("phase 1 produced a resumption hint");

        // ── Step 2: resume — the ClientHello carries sealed early-data ──
        // Use the builder API: `.resumption(hint, early_data)` is the
        // canonical path now that the removed `connect_with_resumption`
        // method is no longer available.
        let early_payload = b"zero-rtt application bytes".to_vec();
        let (c2, s2) = ChannelTransport::pair();
        let phase2_session = PhantomSession::builder("test:9000")
            .transport(c2)
            .pinned_key(server_pinned_key.clone())
            .resumption(hint, early_payload.clone())
            .connect()
            .await
            .expect("early_data is within the size cap");

        let hello_bytes = s2.recv_bytes().await.unwrap();
        let ch3 = borsh::from_slice::<ClientHello>(&hello_bytes).unwrap();
        assert!(
            ch3.early_data.is_some(),
            "phase 2 hello carries sealed 0-RTT early-data"
        );
        match server_hs.process_client_hello(&ch3, 0, client_ip) {
            HandshakeResponse::Success(sh, _session, early_data) => {
                // The server decrypted exactly what the client sealed.
                assert_eq!(early_data.as_deref(), Some(&early_payload[..]));
                assert!(sh.early_data_accepted);
                s2.send_bytes(&ServerReply::Hello(sh).to_wire().unwrap())
                    .await
                    .unwrap();
            }
            _ => {
                panic!("expected Success with accepted early-data — the resumption ticket is fresh")
            }
        }

        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        assert_eq!(
            phase2_session.connection_state(),
            ConnectionState::Connected
        );
        assert_eq!(
            phase2_session.early_data_accepted().await,
            Some(true),
            "client must see the server accepted its 0-RTT early-data"
        );

        // Keep the server transports alive until every assertion has
        // run — see the doc comment above.
        drop((s1, s2));
    }

    /// Invariant 9 through the server's real admission path: a resumed connect carrying
    /// the largest early-data payload the client accepts (`EARLY_DATA_MAX_LEN` bytes)
    /// completes, with the payload taken as 0-RTT. The client caps the plaintext, while
    /// the listener's pre-decode walk bounds the sealed field, which is one GCM tag
    /// longer. When the walk bounded the sealed field at the plaintext cap, this hello
    /// was refused before it was decoded, and a payload the client had just accepted
    /// turned a 0-RTT attempt that may only ever be declined into a failed handshake.
    ///
    /// Both phases go through `drive_server_handshake`, the function both listeners
    /// share, so the walk is on the path; a direct `process_client_hello` call, as in
    /// the test above, would step around it.
    #[tokio::test]
    async fn zero_rtt_full_size_early_data_passes_the_listener_admission_walk() {
        use crate::api::listener::drive_server_handshake;

        let server_hs = HandshakeServer::new().unwrap();
        let server_pinned_key = server_hs.verifying_key().clone();
        let client_ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        let wait = std::time::Duration::from_secs(5);

        // ── Prime: a plain connect fills the ticket cache and yields a hint ──
        let (c1, s1) = ChannelTransport::pair();
        let phase1 =
            PhantomSession::connect_with_transport("test:9000", c1, server_pinned_key.clone());
        drive_server_handshake(&s1, &server_hs, client_ip)
            .await
            .expect("priming handshake");
        tokio::time::timeout(wait, phase1.await_ready())
            .await
            .expect("phase 1 resolved in time")
            .expect("phase 1 established");
        let hint = tokio::time::timeout(wait, async {
            loop {
                if let Some(h) = phase1.resumption_hint().await {
                    return h;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("phase 1 produced a resumption hint");

        // ── Resume with a payload of exactly the client-side cap ──
        let payload = vec![0xA5u8; EARLY_DATA_MAX_LEN];
        let (c2, s2) = ChannelTransport::pair();
        let phase2 = PhantomSession::builder("test:9000")
            .transport(c2)
            .pinned_key(server_pinned_key)
            .resumption(hint, payload.clone())
            .connect()
            .await
            .expect("a payload of exactly the cap passes the client-side check");

        let (_server_session, early) = drive_server_handshake(&s2, &server_hs, client_ip)
            .await
            .expect("the listener must admit a hello whose early-data the client accepted");
        assert_eq!(
            early.as_deref(),
            Some(&payload[..]),
            "a fresh ticket takes the full-size payload as 0-RTT"
        );

        tokio::time::timeout(wait, phase2.await_ready())
            .await
            .expect("phase 2 resolved in time")
            .expect("phase 2 established");
        assert_eq!(phase2.early_data_accepted().await, Some(true));

        // The server halves stay alive until here so neither client pump sees its
        // transport close before the assertions have run.
        drop((s1, s2));
    }

    /// `connect_pinned_with_resumption` validates the `ResumptionHint`
    /// field lengths *before* opening any socket — a hint whose
    /// `session_id` or `resumption_secret` is not exactly 32 bytes is a
    /// caller bug and surfaces as `ValidationError`, never a network
    /// round-trip.
    #[tokio::test]
    async fn connect_pinned_with_resumption_rejects_malformed_hint() {
        let server_hs = HandshakeServer::new().unwrap();
        let pinned = server_hs.verifying_key().to_bytes();

        // 5 bytes, not 32.
        let bad_hint = ResumptionHint::new(vec![0u8; 5], vec![0u8; 32]);

        let err = connect_pinned_with_resumption(
            "127.0.0.1".to_string(),
            9,
            pinned,
            bad_hint,
            Vec::new(),
        )
        .await
        .expect_err("a 5-byte session_id must be rejected");

        assert!(
            matches!(err, CoreError::ValidationError(_)),
            "expected ValidationError, got {err:?}"
        );
    }

    /// `connect_pinned_udp_with_resumption` validates the `ResumptionHint`
    /// field lengths *before* resolving the host or binding a UDP socket — a
    /// malformed hint is a caller bug and surfaces as `ValidationError`, never
    /// a network round-trip. UDP sibling of
    /// `connect_pinned_with_resumption_rejects_malformed_hint`.
    #[tokio::test]
    async fn connect_pinned_udp_with_resumption_rejects_malformed_hint() {
        let server_hs = HandshakeServer::new().unwrap();
        let pinned = server_hs.verifying_key().to_bytes();

        let bad_hint = ResumptionHint::new(vec![0u8; 5], vec![0u8; 32]); // not 32 bytes

        let err = connect_pinned_udp_with_resumption(
            "127.0.0.1".to_string(),
            9,
            pinned,
            bad_hint,
            Vec::new(),
        )
        .await
        .expect_err("a 5-byte session_id must be rejected");

        assert!(
            matches!(err, CoreError::ValidationError(_)),
            "expected ValidationError, got {err:?}"
        );
    }

    // ── PhantomStream::set_priority ──────────────────────────────────────────────

    /// Verify that `ControlCommand::SetStreamPriority`, carried out by the pump's control
    /// arm, reaches `Stream::set_priority` and that the stored value is observable via
    /// `Stream::priority()`.
    #[tokio::test]
    async fn set_priority_command_reaches_stream() {
        use crate::transport::stream::Stream as TransportStream;

        // Build a stream table entry the same way run_data_pump does.
        let stream_id: u32 = 42;
        let transport_stream = Arc::new(TransportStream::new(stream_id as TransportStreamId));
        let streams: Arc<DashMap<u32, Arc<TransportStream>>> = Arc::new(DashMap::new());
        streams.insert(stream_id, transport_stream.clone());

        assert_eq!(
            transport_stream.priority(),
            0,
            "default priority should be 0"
        );

        let (session, _peer) = paired_sessions(fixed_session_id());
        let (transport, _far_end) = ChannelTransport::pair();
        take_control(
            ControlCommand::SetStreamPriority {
                stream_id,
                priority: 99,
            },
            &Arc::new(transport),
            &session,
            &streams,
            &Observability::new(ObservabilityConfig::default()),
        )
        .await;

        assert_eq!(
            transport_stream.priority(),
            99,
            "priority must be updated to 99 after SetStreamPriority"
        );
    }

    // ── Non-colliding client-odd / server-even stream ids ────────────────────────

    /// Client and server demuxes opened with `new_with_role` must allocate
    /// non-colliding ids: client gets odd ids ≥ 3, server gets even ids ≥ 2.
    /// Stream id 1 (raw-app) is never returned by `open_stream`.
    #[tokio::test]
    async fn stream_ids_are_non_colliding_client_odd_server_even() {
        let (client_demux, _) = StreamDemultiplexer::new_with_role(16, true);
        let (server_demux, _) = StreamDemultiplexer::new_with_role(16, false);

        // Open several streams on each side.
        let client_ids: Vec<u32> = (0..5)
            .map(|_| {
                client_demux
                    .open_stream(8)
                    .expect("an id is free")
                    .stream_id
            })
            .collect();
        let server_ids: Vec<u32> = (0..5)
            .map(|_| {
                server_demux
                    .open_stream(8)
                    .expect("an id is free")
                    .stream_id
            })
            .collect();

        // Client must produce odd ids ≥ 3.
        for &id in &client_ids {
            assert!(id % 2 == 1, "client id {id} must be odd");
            assert!(
                id >= 3,
                "client id {id} must be ≥ 3 (id 1 is raw-app reserved)"
            );
        }

        // Server must produce even ids ≥ 2.
        for &id in &server_ids {
            assert!(id % 2 == 0, "server id {id} must be even");
            assert!(id >= 2, "server id {id} must be ≥ 2");
        }

        // No overlap between the two sets.
        for &cid in &client_ids {
            assert!(
                !server_ids.contains(&cid),
                "client id {cid} must not appear in server ids"
            );
        }

        // Ids are strictly increasing within each side.
        for w in client_ids.windows(2) {
            assert!(w[1] > w[0], "client ids must be strictly increasing");
        }
        for w in server_ids.windows(2) {
            assert!(w[1] > w[0], "server ids must be strictly increasing");
        }

        // Raw-app stream id 1 is never returned by open_stream on either side.
        assert!(
            !client_ids.contains(&1) && !server_ids.contains(&1),
            "stream id 1 (raw-app) must never be allocated by open_stream"
        );
    }

    // ── Lossless backpressured per-stream recv tests ─────────────────────────────

    /// LOSSLESS: opened-stream (id ≥ 2) delivery is LOSSLESS even when
    /// the consumer pauses and more than the per-stream channel capacity (1024)
    /// frames are in flight.
    ///
    /// The test sends N_FRAMES > 1024 reliable frames, waits until at least the
    /// first `streams_deliver_rx`-deep batches have reached Task B (Task B
    /// backpressures after 1024 on `route_data_async`), then drains the
    /// PhantomStream and asserts zero loss + correct order.
    #[tokio::test]
    async fn opened_stream_delivery_is_lossless_beyond_channel_capacity() {
        const N_FRAMES: u32 = 1100; // > per-stream channel capacity of 1024

        let session_id = fixed_session_id();
        let (client_inner, server_inner) = paired_sessions(session_id);
        let (client_t, server_t) = ChannelTransport::pair();

        // Full server-side session with a running pump.
        let server = PhantomSession::from_accepted_server_session(
            "lossless-test".to_string(),
            server_t,
            server_inner,
        );

        // Open a stream (id ≥ 2) on the server so the demux is registered.
        let stream = server.open_stream().expect("open a stream");
        let stream_id = stream.stream_id() as TransportStreamId;

        // Drain ACKs from the server so its reader never wedges.
        let drain_t = Arc::new(client_t);
        let drain_t2 = drain_t.clone();
        let _drainer = tokio::spawn(async move { while drain_t2.recv_bytes().await.is_ok() {} });

        // Send N_FRAMES reliable frames from the "client" side WITHOUT consuming.
        // Each frame is tagged with its sequence number as payload so we can verify
        // order after draining.
        for seq in 0..N_FRAMES {
            let wire = encrypt_outgoing(
                &client_inner,
                session_id,
                stream_id,
                seq,
                &seq.to_be_bytes(),
            );
            match tokio::time::timeout(std::time::Duration::from_secs(5), drain_t.send_bytes(&wire))
                .await
            {
                Ok(Ok(())) => {}
                _ => panic!("send failed at frame {seq}"),
            }
        }

        // Give the pump time to receive and route all frames. Task B will block
        // after filling the per-stream bounded channel (capacity 1024) but
        // streams_deliver_rx keeps buffering — all N_FRAMES are enqueued.
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        // Drain the opened stream — Task B unblocks once the consumer reads.
        let mut received: Vec<u32> = Vec::new();
        let timeout = std::time::Duration::from_secs(10);
        loop {
            match tokio::time::timeout(timeout, stream.recv()).await {
                Ok(Ok(Some(bytes))) if bytes.len() == 4 => {
                    received.push(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]));
                    if received.len() == N_FRAMES as usize {
                        break;
                    }
                }
                Ok(Ok(Some(_))) => {}  // unexpected length, skip
                Ok(Ok(None)) => break, // clean EOF
                Ok(Err(_)) => break,   // session ended
                Err(_) => panic!("timeout waiting for frame {}", received.len()),
            }
        }

        assert_eq!(
            received.len(),
            N_FRAMES as usize,
            "zero loss: all {N_FRAMES} frames must arrive; got {}",
            received.len()
        );
        let expected: Vec<u32> = (0..N_FRAMES).collect();
        assert_eq!(
            received, expected,
            "frames must arrive in sequence order (lossless + ordered)"
        );
    }

    /// RAW-APP ISOLATION: while an opened-stream (id ≥ 2) consumer is
    /// NOT draining (Task B stalled on the per-stream bounded channel), the
    /// raw-app path (session.send/recv on stream id 1) must still work.
    ///
    /// This is the make-or-break property: opened-stream backpressure must NOT
    /// head-of-line block the raw-app recv path.
    #[tokio::test]
    async fn raw_app_path_unblocked_while_opened_stream_is_backed_up() {
        let session_id = fixed_session_id();
        let (client_inner, server_inner) = paired_sessions(session_id);
        let (client_t, server_t) = ChannelTransport::pair();

        // Full server-side session with a running pump.
        let server = PhantomSession::from_accepted_server_session(
            "hol-test".to_string(),
            server_t,
            server_inner.clone(),
        );

        // Open an id-≥2 stream on the server and NEVER consume it.
        let _unopened = server.open_stream().expect("open a stream");
        let unopened_id = _unopened.stream_id() as TransportStreamId;

        let drain_t = Arc::new(client_t);
        let drain_t2 = drain_t.clone();
        // Drain ACK/WINDOW_UPDATE frames the server sends back.
        let _drainer = tokio::spawn(async move { while drain_t2.recv_bytes().await.is_ok() {} });

        // Flood the opened stream to fill Task B's per-stream channel (capacity 1024)
        // and back up streams_deliver_rx, so Task B is stalled.
        for seq in 0..1100u32 {
            let wire = encrypt_outgoing(
                &client_inner,
                session_id,
                unopened_id,
                seq,
                b"backpressure-filler",
            );
            let _ =
                tokio::time::timeout(std::time::Duration::from_secs(5), drain_t.send_bytes(&wire))
                    .await;
        }

        // Let the pump process those and stall Task B.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // Now send a raw-app (stream id 1) frame. The session.recv() path goes
        // through Task A, which is COMPLETELY INDEPENDENT of Task B.
        // Must use client_inner so HP keys match what the server pump expects
        // (client send HP == server recv HP).
        // packet_number=1100 avoids the replay window (flood used 0..1099);
        // stream_offset=0 (in plaintext prefix) releases the frame immediately
        // from the reorder buffer (no gap stall for the fresh stream-1 state).
        let raw_wire = {
            let flag_bits = PacketFlags::RELIABLE | PacketFlags::ENCRYPTED;
            let hdr = PacketHeader::new(session_id, 1, 1100, PacketFlags::new(flag_bits))
                .with_epoch(client_inner.current_epoch());
            let mut pt = Vec::with_capacity(4 + b"raw-app-works".len());
            pt.extend_from_slice(&0u32.to_be_bytes()); // stream_offset = 0
            pt.extend_from_slice(b"raw-app-works");
            let ct = client_inner
                .encrypt_packet(&hdr, &pt, &[])
                .expect("encrypt raw-app frame");
            let pkt = PhantomPacket::new(hdr, ct);
            client_inner
                .protect_packet(&pkt)
                .expect("protect raw-app frame")
        };
        match tokio::time::timeout(
            std::time::Duration::from_secs(5),
            drain_t.send_bytes(&raw_wire),
        )
        .await
        {
            Ok(Ok(())) => {}
            _ => panic!("raw-app send failed"),
        }

        // Expect to receive the raw-app message within 2 s even though the opened
        // stream's Task B is stalled — proving Tasks A and B are truly independent.
        let received = tokio::time::timeout(std::time::Duration::from_secs(2), server.recv())
            .await
            .expect("raw-app recv timed out — Task B stall is blocking Task A (HoL regression)")
            .expect("recv returned error");

        assert_eq!(
            received, b"raw-app-works",
            "raw-app payload must pass through undisturbed"
        );
    }

    /// NO DOUBLE-DELIVERY: frames sent on an opened stream (id ≥ 2) must
    /// **A delivered frame must carry which path it arrived on.**
    ///
    /// Flow control counts reliable bytes and only those, because those are the only ones
    /// the sending end charged against the window — unreliable data leaves `poll_send`
    /// before the window is consulted. The end that has to act on the distinction is the
    /// delivery task, which sees only what the reader put in the queue, so the reader has
    /// to say. Mislabel an unreliable frame here and the receiving side advertises a limit
    /// its peer never charged itself for, which is the accounting the local ceiling then
    /// has to cut down — spending a bound written for a peer inventing numbers on one
    /// telling the truth.
    ///
    /// Both directions are asserted, because the failure is a boolean: a reader that tagged
    /// everything reliable and one that tagged everything unreliable are different defects,
    /// and the second silently stops the window from ever opening.
    #[tokio::test]
    async fn delivery_says_which_path_a_frame_arrived_on() {
        let session_id = fixed_session_id();
        let (client_session, server_session) = paired_sessions(session_id);

        let (demux, _ctrl_rx) = StreamDemultiplexer::new(16);
        let demux = Arc::new(demux);
        // A client-allocated stream, the parity a client's frames arrive on.
        let _handle = demux.register_stream(3, 64);

        let streams: Arc<DashMap<u32, Arc<TransportStream>>> = Arc::new(DashMap::new());
        let (deliver_tx, mut deliver_rx) = mpsc::unbounded_channel::<DeliverItem>();
        let undelivered = AtomicU64::new(0);
        let (ack_a, ack_b) = mpsc::channel::<Vec<u8>>(16);
        let transport_send: Arc<ChannelTransport> = Arc::new(ChannelTransport {
            tx: ack_a,
            rx: Mutex::new(ack_b),
        });
        let obs = Observability::new(ObservabilityConfig::default());
        let mut scratch = test_recv_scratch(&obs, 256);
        let (no_link, no_inc_tx) = noop_accept_sinks();

        // A reliable frame: `[stream_offset: u32 BE][payload]`, the live sender's framing.
        let reliable = decode_recv_frame(
            &build_app_frame(&client_session, session_id, 3, 0, b"reliable"),
            session_id,
        );
        handle_packet(
            reliable,
            session_id,
            &server_session,
            &streams,
            &demux,
            &transport_send,
            &transport_send,
            &deliver_tx,
            &undelivered,
            &mut scratch,
            &obs,
            LegType::Tcp,
            &no_link,
            &no_inc_tx,
            &connected_state(),
        )
        .await;

        // An unreliable frame on the same stream: no offset prefix, since nothing
        // reassembles it, and the UNRELIABLE flag in place of RELIABLE.
        let header = PacketHeader::new(
            session_id,
            3,
            1,
            PacketFlags::new(PacketFlags::UNRELIABLE | PacketFlags::ENCRYPTED),
        )
        .with_epoch(client_session.current_epoch());
        let ciphertext = client_session
            .encrypt_packet(&header, b"unreliable", &[])
            .expect("encrypt_packet");
        let unreliable = decode_recv_frame(
            &PhantomPacket::new(header, ciphertext).to_wire(),
            session_id,
        );
        handle_packet(
            unreliable,
            session_id,
            &server_session,
            &streams,
            &demux,
            &transport_send,
            &transport_send,
            &deliver_tx,
            &undelivered,
            &mut scratch,
            &obs,
            LegType::Tcp,
            &no_link,
            &no_inc_tx,
            &connected_state(),
        )
        .await;

        let mut seen: Vec<(Vec<u8>, bool)> = Vec::new();
        while let Ok(item) = deliver_rx.try_recv() {
            if let DeliverItem::Data(_sid, bytes, reliable) = item {
                seen.push((bytes.to_vec(), reliable));
            }
        }
        assert_eq!(
            seen,
            vec![
                (b"reliable".to_vec(), true),
                (b"unreliable".to_vec(), false)
            ],
            "each delivered frame must carry the path it arrived on"
        );
    }

    /// NOT appear in session.recv(); frames sent on the raw-app stream (id 1) must
    /// NOT appear in any PhantomStream's rx.
    ///
    /// We drive handle_packet directly (no full pump) so we can inspect the
    /// deliver_tx channel before it is routed, and inspect the demux separately.
    #[tokio::test]
    async fn no_double_delivery_between_raw_app_and_opened_streams() {
        let session_id = fixed_session_id();
        let (client_session, server_session) = paired_sessions(session_id);

        // A registered opened stream (id 3, client-allocated).
        let (demux, _ctrl_rx) = StreamDemultiplexer::new(16);
        let demux = Arc::new(demux);
        let mut stream_handle = demux.register_stream(3, 64);

        let streams: Arc<DashMap<u32, Arc<TransportStream>>> = Arc::new(DashMap::new());
        let (deliver_tx, mut deliver_rx) = mpsc::unbounded_channel::<DeliverItem>();
        let undelivered = AtomicU64::new(0);
        let (ack_a, ack_b) = mpsc::channel::<Vec<u8>>(16);
        let transport_send: Arc<ChannelTransport> = Arc::new(ChannelTransport {
            tx: ack_a,
            rx: Mutex::new(ack_b),
        });
        let obs = Observability::new(ObservabilityConfig::default());
        let mut scratch = test_recv_scratch(&obs, 256);

        // --- Part 1: opened-stream frame (id=3) must NOT arrive as raw-app ---
        let opened_frame = decode_recv_frame(
            &build_app_frame(&client_session, session_id, 3, 0, b"opened-only"),
            session_id,
        );
        let (no_link, no_inc_tx) = noop_accept_sinks();
        handle_packet(
            opened_frame,
            session_id,
            &server_session,
            &streams,
            &demux,
            &transport_send,
            &transport_send,
            &deliver_tx,
            &undelivered,
            &mut scratch,
            &obs,
            LegType::Tcp,
            &no_link,
            &no_inc_tx,
            &connected_state(),
        )
        .await;

        // The item in deliver_tx must be tagged as id=3 (opened stream).
        let item = tokio::time::timeout(std::time::Duration::from_millis(100), deliver_rx.recv())
            .await
            .expect("deliver channel must have item")
            .expect("channel open");
        match &item {
            DeliverItem::Data(sid, _, _) => assert_eq!(
                *sid, 3,
                "opened-stream frame must be tagged stream_id=3, not raw-app"
            ),
            DeliverItem::Close(sid) => panic!("unexpected Close({sid})"),
            DeliverItem::Retire(sid) => panic!("unexpected Retire({sid})"),
        }
        // Nothing else — no second copy.
        assert!(
            deliver_rx.try_recv().is_err(),
            "opened-stream frame must produce exactly ONE DeliverItem, not two"
        );
        // The direct demux path (route_data/non-async) was dropped from the old
        // Task A; the stream_handle's channel must be empty (delivery goes via
        // DeliverItem::Data, not route_data). This confirms no double-delivery at
        // the handle_packet level — the router task (in the live pump) decides the
        // final destination.
        assert!(
            stream_handle.rx.try_recv().is_err(),
            "opened-stream frame must NOT arrive on the demux handle synchronously \
             (delivery is async via Task B)"
        );

        // --- Part 2: raw-app frame (id=1) must be tagged id=1, not sent to demux ---
        // packet_number=1 (unique; 0 was used by Part 1), stream_offset=0
        // (first data on stream 1 → reorder buffer delivers immediately, no gap).
        let raw_frame = decode_recv_frame(
            &build_app_frame_with_offset(&client_session, session_id, 1, 1, 0, b"raw-only"),
            session_id,
        );
        let (no_link, no_inc_tx) = noop_accept_sinks();
        handle_packet(
            raw_frame,
            session_id,
            &server_session,
            &streams,
            &demux,
            &transport_send,
            &transport_send,
            &deliver_tx,
            &undelivered,
            &mut scratch,
            &obs,
            LegType::Tcp,
            &no_link,
            &no_inc_tx,
            &connected_state(),
        )
        .await;

        let raw_item =
            tokio::time::timeout(std::time::Duration::from_millis(100), deliver_rx.recv())
                .await
                .expect("deliver channel must have item for raw-app")
                .expect("channel open");
        match &raw_item {
            DeliverItem::Data(sid, bytes, _) => {
                assert_eq!(*sid, 1, "raw-app frame must be tagged stream_id=1");
                // The RELIABLE path in handle_packet strips the 4-byte stream_offset
                // prefix before handing data to deliver_in_order_run, so the
                // DeliverItem::Data bytes are the raw application payload directly.
                assert_eq!(&bytes[..], b"raw-only", "raw-app payload must match");
            }
            DeliverItem::Close(sid) => panic!("unexpected Close({sid}) for raw-app"),
            DeliverItem::Retire(sid) => panic!("unexpected Retire({sid}) for raw-app"),
        }
        // Nothing else in the channel.
        assert!(
            deliver_rx.try_recv().is_err(),
            "raw-app frame must produce exactly ONE DeliverItem"
        );
        // The opened-stream demux handle must remain empty — raw-app data must
        // never be routed to an opened stream's channel.
        assert!(
            stream_handle.rx.try_recv().is_err(),
            "raw-app frame must NOT arrive on any opened-stream handle"
        );
    }

    // ── Peer-initiated stream accept tests ───────────────────────────────────

    /// When a client sends data on a NEW stream (one the server has
    /// not seen before), the server-side `accept_stream()` returns an
    /// `Arc<PhantomStream>` for that stream, and `recv()` on it yields the data.
    ///
    /// Uses `PhantomSession::from_accepted_server_session` (the full pump) with an
    /// in-memory `ChannelTransport` pair. The client side is a bare `Session` +
    /// `encrypt_outgoing` so the test does not require a real handshake.
    #[tokio::test]
    async fn accept_stream_delivers_peer_initiated_stream() {
        let session_id = fixed_session_id();
        let (client_inner, server_inner) = paired_sessions(session_id);

        let (client_t, server_t) = ChannelTransport::pair();

        // Server session with a running data pump (even ids).
        let server = PhantomSession::from_accepted_server_session(
            "accept-test".to_string(),
            server_t,
            server_inner,
        );

        // Drain any ACK/WINDOW_UPDATE frames the server sends back.
        let client_t = Arc::new(client_t);
        let drain_t = client_t.clone();
        let _drainer = tokio::spawn(async move { while drain_t.recv_bytes().await.is_ok() {} });

        // Client opens stream id 3 (odd = client-allocated) and sends one frame.
        // stream_offset 0, payload b"hello-from-peer".
        let stream_id: TransportStreamId = 3;
        let wire = encrypt_outgoing(&client_inner, session_id, stream_id, 0, b"hello-from-peer");
        client_t.send_bytes(&wire).await.expect("send frame");

        // Server should surface the new stream via accept_stream().
        let accepted =
            tokio::time::timeout(std::time::Duration::from_secs(5), server.accept_stream())
                .await
                .expect("timeout waiting for accept_stream")
                .expect("accept_stream returned Err");

        assert_eq!(
            accepted.stream_id(),
            3,
            "stream id must be 3 (client-allocated)"
        );

        // The first frame should arrive on recv().
        let data = tokio::time::timeout(std::time::Duration::from_secs(5), accepted.recv())
            .await
            .expect("timeout waiting for recv")
            .expect("recv returned Err");

        assert_eq!(
            data,
            Some(b"hello-from-peer".to_vec()),
            "recv must return the payload sent by the client"
        );
    }

    /// A frame larger than anything this side emits must not reach a delivery slot.
    ///
    /// The per-stream delivery channels are bounded in slots, not in bytes, so what a
    /// session holds is the slot count times whatever a peer can put in a slot. Nothing
    /// downstream of the pump limits that: the reorder buffer's byte budget only governs
    /// segments that arrive *out* of order, and in-order data goes straight to the queue.
    /// The pipe itself will hand over 4 MiB on the TCP leg once the frame phase is
    /// `Established`, so without a gate one slot holds 4 MiB and a slot is 1156 B in every
    /// figure that describes this session.
    ///
    /// Two-sided on purpose. The oversized frame claims stream offset 0 on a new stream,
    /// so if it were admitted it would both surface that stream and consume the offset;
    /// the legal frame that follows carries the same offset under a fresh packet number.
    /// Accepting the first therefore makes the second a duplicate and this test reads the
    /// megabyte back instead of the sentence — and refusing *everything* fails it just as
    /// loudly, because then the stream is never accepted at all.
    #[tokio::test]
    async fn an_oversized_inbound_frame_is_refused_without_taking_the_session_down() {
        use crate::transport::mtu::MAX_RECV_FRAME;

        let session_id = fixed_session_id();
        let (client_inner, server_inner) = paired_sessions(session_id);
        let (client_t, server_t) = ChannelTransport::pair();

        let server = PhantomSession::from_accepted_server_session(
            "oversize-test".to_string(),
            server_t,
            server_inner,
        );

        let client_t = Arc::new(client_t);
        let drain_t = client_t.clone();
        let _drainer = tokio::spawn(async move { while drain_t.recv_bytes().await.is_ok() {} });

        // A single reliable segment several hundred times the largest frame the sender
        // budget produces. Nothing about it is malformed — it decrypts, its offset is 0,
        // its stream id is a legal client-allocated one. Only its size is unreasonable.
        let oversized =
            encrypt_outgoing_at(&client_inner, session_id, 3, 0, 0, &vec![0x7Eu8; 1 << 19]);
        assert!(
            oversized.len() > MAX_RECV_FRAME,
            "the frame under test must actually exceed the gate: {} B vs {MAX_RECV_FRAME} B",
            oversized.len()
        );
        client_t
            .send_bytes(&oversized)
            .await
            .expect("send oversized frame");

        // Same stream, same offset, next packet number — the frame a compliant peer
        // would have sent.
        let legal = encrypt_outgoing_at(&client_inner, session_id, 3, 1, 0, b"within budget");
        client_t.send_bytes(&legal).await.expect("send legal frame");

        let accepted =
            tokio::time::timeout(std::time::Duration::from_secs(5), server.accept_stream())
                .await
                .expect("the legal frame must still open the stream")
                .expect("accept_stream returned Err");
        assert_eq!(accepted.stream_id(), 3);

        let data = tokio::time::timeout(std::time::Duration::from_secs(5), accepted.recv())
            .await
            .expect("timeout waiting for recv")
            .expect("recv returned Err");
        // Length first, and without printing the payload: on the failing path the payload
        // is half a megabyte and the length is the whole story.
        let delivered = data.as_ref().map_or(0, Vec::len);
        assert_eq!(
            delivered,
            b"within budget".len(),
            "the stream delivered {delivered} B — the oversized frame was admitted, so a \
             delivery slot holds whatever the byte pipe will carry rather than one chunk"
        );
        assert_eq!(data.as_deref(), Some(&b"within budget"[..]));
    }

    /// A frame the size 0.2.2 emits must still be delivered, or the gate breaks every
    /// session with a peer running the published release.
    ///
    /// That release chunks application data at a flat 1300 bytes, 144 more than this
    /// build's derived budget, so its largest data frame is 1335 bytes on the wire.
    /// A gate set to this side's own budget would refuse it — before the AEAD, so
    /// never acknowledged, and its retransmits would meet the same gate. The session
    /// would not fail: it would stop, with no error on either end and nothing in a
    /// counter, which is the worst shape a compatibility break can take.
    ///
    /// The frame here is built at exactly the released size rather than at
    /// `MAX_RECV_FRAME`, so the test is about the peer this gate has to admit and not
    /// about the constant restating itself. Lowering `MAX_RECV_FRAME` to this side's
    /// own chunk size fails it.
    #[tokio::test]
    async fn a_frame_the_released_version_emits_is_still_delivered() {
        // Both sizes are constants, so the relation between them belongs to the
        // compile-time assertions beside them in `transport::mtu` rather than here —
        // one of those already refuses a build where the gate stops admitting the
        // released chunk, whichever of the two moved.
        use crate::transport::mtu::{LEGACY_APP_CHUNK, MAX_RECV_FRAME};

        let session_id = fixed_session_id();
        let (client_inner, server_inner) = paired_sessions(session_id);
        let (client_t, server_t) = ChannelTransport::pair();

        let server = PhantomSession::from_accepted_server_session(
            "legacy-chunk-test".to_string(),
            server_t,
            server_inner,
        );

        let client_t = Arc::new(client_t);
        let drain_t = client_t.clone();
        let _drainer = tokio::spawn(async move { while drain_t.recv_bytes().await.is_ok() {} });

        let payload = vec![0x5Au8; LEGACY_APP_CHUNK];
        let frame = encrypt_outgoing_at(&client_inner, session_id, 3, 0, 0, &payload);
        assert!(
            frame.len() <= MAX_RECV_FRAME,
            "a released peer's full-size frame is {} B and the gate admits {MAX_RECV_FRAME} B — \
             every such peer would stall here",
            frame.len()
        );
        client_t
            .send_bytes(&frame)
            .await
            .expect("send legacy frame");

        let accepted =
            tokio::time::timeout(std::time::Duration::from_secs(5), server.accept_stream())
                .await
                .expect("a released peer's frame must open the stream")
                .expect("accept_stream returned Err");

        let data = tokio::time::timeout(std::time::Duration::from_secs(5), accepted.recv())
            .await
            .expect("timeout waiting for recv")
            .expect("recv returned Err");
        assert_eq!(
            data.as_ref().map_or(0, Vec::len),
            LEGACY_APP_CHUNK,
            "the released peer's chunk must arrive whole"
        );
    }

    /// Nothing the pump emits may exceed the frame gate the peer applies, or the gate
    /// would be silently breaking legitimate sessions.
    ///
    /// This is the other half of the gate: the constant asserts in `transport::mtu` pin
    /// the three frame shapes against the budget arithmetic, and this watches the wire
    /// while a live pump produces them — chunked application data with padding armed,
    /// SACKs answering inbound reliable segments, window updates as the peer's data is
    /// consumed, and cover traffic filling the idle gaps. A frame shape that grows past
    /// the budget lands here rather than as a peer that stops receiving.
    #[tokio::test]
    async fn no_frame_the_pump_emits_exceeds_the_gate_the_peer_applies() {
        use crate::transport::mtu::{MAX_APP_CHUNK, MAX_RECV_FRAME};
        use std::sync::atomic::AtomicUsize;

        let session_id = fixed_session_id();
        let (client_inner, server_inner) = paired_sessions(session_id);
        let (client_t, server_t) = ChannelTransport::pair();

        let server = Arc::new(PhantomSession::from_accepted_server_session(
            "budget-test".to_string(),
            server_t,
            server_inner,
        ));
        // Padding and cover are the two shapes that grow a frame after the payload is
        // fixed, so arm both rather than measuring only the unshaped path.
        server
            .set_traffic_shaping(TrafficShapingConfig {
                padding: PaddingPolicy::Padme,
                jitter_ms: 0,
                cover_interval_ms: 5,
            })
            .await;

        let widest = Arc::new(AtomicUsize::new(0));
        let seen = widest.clone();
        let client_t = Arc::new(client_t);
        let drain_t = client_t.clone();
        let _drainer = tokio::spawn(async move {
            while let Ok(frame) = drain_t.recv_bytes().await {
                seen.fetch_max(frame.len(), Ordering::Relaxed);
            }
        });

        // Inbound reliable data, so the pump answers with SACKs and eventually window
        // updates as the delivery side consumes it.
        for i in 0..16u32 {
            let wire = encrypt_outgoing(
                &client_inner,
                session_id,
                3,
                i,
                &vec![0x33u8; MAX_APP_CHUNK],
            );
            client_t.send_bytes(&wire).await.expect("send inbound data");
        }

        // Outbound application data far past one window, so the pump chunks it and keeps
        // the wire busy for long enough that the cover timer also fires.
        let bulk = vec![0xC7u8; MAX_APP_CHUNK * 64];
        server.send(bulk).await.expect("bulk send");
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        let widest = widest.load(Ordering::Relaxed);
        // Positive control: a measurement that never saw a full-size data frame would
        // satisfy the bound below without observing anything the gate governs.
        assert!(
            widest > MAX_APP_CHUNK,
            "the wire was never carrying a full-size data frame (widest {widest} B), so \
             the bound below holds vacuously"
        );
        assert!(
            widest <= MAX_RECV_FRAME,
            "the pump put a {widest} B frame on the wire against a {MAX_RECV_FRAME} B \
             receive gate — a compliant peer would drop it"
        );
    }

    /// The `active_streams` gauge must be balanced: `opened` counts only
    /// user-visible ids, `closed` never drives it negative, and `drain` retires
    /// exactly what is still open (and is idempotent, because the pump exit and
    /// `Drop for PhantomSession` both call it).
    #[test]
    fn stream_gauge_is_balanced_and_never_negative() {
        let obs = Observability::new(ObservabilityConfig::default());
        let gauge = StreamGauge::new(obs.clone());

        // Internal ids (0 = control, 1 = raw-app) are not user streams.
        gauge.opened(0);
        gauge.opened(RAW_APP_STREAM_ID);
        assert_eq!(obs.snapshot().active_streams, 0);

        gauge.opened(3);
        gauge.opened(5);
        assert_eq!(obs.snapshot().active_streams, 2);

        gauge.closed(3);
        assert_eq!(obs.snapshot().active_streams, 1);

        // Retiring an id we never counted must not double-decrement.
        gauge.closed(99);
        gauge.closed(5);
        gauge.closed(5);
        assert_eq!(
            obs.snapshot().active_streams,
            0,
            "closed() must floor at zero — a stray retire cannot make the gauge negative"
        );

        // Drain of an empty gauge is a no-op; drain of a live one retires all.
        gauge.drain();
        assert_eq!(obs.snapshot().active_streams, 0);
        gauge.opened(7);
        gauge.opened(9);
        assert_eq!(obs.snapshot().active_streams, 2);
        gauge.drain();
        gauge.drain();
        assert_eq!(
            obs.snapshot().active_streams,
            0,
            "drain must be idempotent — pump exit and Drop both call it"
        );
    }

    /// Locally-opened streams raise the gauge and it comes back down when the
    /// session handle is dropped — including for a session that never had a
    /// running pump.
    #[tokio::test]
    async fn open_stream_gauge_returns_to_zero_on_session_drop() {
        let session = PhantomSession::connect("gauge-test".to_string());
        let obs = session.observability();
        assert_eq!(obs.snapshot().active_streams, 0);

        let _a = session.open_stream().expect("open a stream");
        let _b = session.open_stream().expect("open a stream");
        assert_eq!(
            obs.snapshot().active_streams,
            2,
            "each open_stream() must raise the active-streams gauge"
        );

        drop(session);
        assert_eq!(
            obs.snapshot().active_streams,
            0,
            "dropping the session must retire every stream it still had open"
        );
    }

    /// A peer-initiated stream raises the gauge on the receive path and is
    /// retired when the session tears down (the pump-exit / Drop drain).
    #[tokio::test]
    async fn peer_initiated_stream_gauge_returns_to_zero_at_teardown() {
        let session_id = fixed_session_id();
        let (client_inner, server_inner) = paired_sessions(session_id);
        let (client_t, server_t) = ChannelTransport::pair();

        let server = PhantomSession::from_accepted_server_session(
            "gauge-accept".to_string(),
            server_t,
            server_inner,
        );
        let obs = server.observability();

        let client_t = Arc::new(client_t);
        let drain_t = client_t.clone();
        let _drainer = tokio::spawn(async move { while drain_t.recv_bytes().await.is_ok() {} });

        let wire = encrypt_outgoing(&client_inner, session_id, 3, 0, b"peer-opened");
        client_t.send_bytes(&wire).await.expect("send frame");

        let accepted =
            tokio::time::timeout(std::time::Duration::from_secs(5), server.accept_stream())
                .await
                .expect("timeout waiting for accept_stream")
                .expect("accept_stream returned Err");
        assert_eq!(accepted.stream_id(), 3);
        assert_eq!(
            obs.snapshot().active_streams,
            1,
            "a peer-initiated stream must raise the active-streams gauge"
        );

        drop(accepted);
        drop(server);
        assert_eq!(
            obs.snapshot().active_streams,
            0,
            "session teardown must retire the peer-initiated stream"
        );
    }

    /// The always-on encrypt/decrypt aggregates behind `MetricsSnapshotFfi`
    /// must actually be fed by the pump's send and receive paths (they were
    /// registered but never recorded before this wiring).
    #[tokio::test]
    async fn encrypt_and_decrypt_timings_reach_the_snapshot() {
        let session_id = fixed_session_id();
        let (client_session, server_session) = paired_sessions(session_id);
        let (client_t, server_t) = ChannelTransport::pair();
        let client_t = Arc::new(client_t);

        // Big enough that the AEAD call is far above any platform's `Instant`
        // granularity, so `avg_*_ns > 0` is not a timing race.
        let payload = vec![0xA5u8; 4096];

        let send_obs = Observability::new(ObservabilityConfig::default());
        assert_eq!(send_obs.snapshot().encrypt_count, 0);
        assert!(
            send_app_data(
                &client_t,
                &client_session,
                session_id,
                7,
                &payload,
                PacketFlags::RELIABLE,
                Some(0),
                &send_obs,
            )
            .await
        );
        let sent = send_obs.snapshot();
        assert_eq!(sent.encrypt_count, 1, "one AEAD seal, one sample");
        assert!(sent.avg_encrypt_ns > 0, "the seal must be timed");
        assert_eq!(sent.decrypt_count, 0, "the send path opens nothing");

        // Receive it on the server side through the real recv path.
        let wire = server_t.recv_bytes().await.expect("frame on the wire");
        let pkt = server_session
            .parse_protected(&wire)
            .expect("parse_protected");

        let recv_obs = Observability::new(ObservabilityConfig::default());
        let streams: Arc<DashMap<u32, Arc<TransportStream>>> = Arc::new(DashMap::new());
        let (demux, _ctrl_rx) = StreamDemultiplexer::new(16);
        let demux = Arc::new(demux);
        let (deliver_tx, _deliver_rx) = mpsc::unbounded_channel::<DeliverItem>();
        let undelivered = AtomicU64::new(0);
        let (ack_a, ack_b) = mpsc::channel::<Vec<u8>>(4);
        let ack_transport: Arc<ChannelTransport> = Arc::new(ChannelTransport {
            tx: ack_a,
            rx: Mutex::new(ack_b),
        });
        let mut scratch = test_recv_scratch(&recv_obs, 256);
        let (no_link, no_inc_tx) = noop_accept_sinks();
        handle_packet(
            pkt,
            session_id,
            &server_session,
            &streams,
            &demux,
            &ack_transport,
            &ack_transport,
            &deliver_tx,
            &undelivered,
            &mut scratch,
            &recv_obs,
            LegType::Tcp,
            &no_link,
            &no_inc_tx,
            &connected_state(),
        )
        .await;

        let received = recv_obs.snapshot();
        assert_eq!(received.decrypt_count, 1, "one AEAD open, one sample");
        assert!(received.avg_decrypt_ns > 0, "the open must be timed");
        assert_eq!(
            received.encrypt_count, 1,
            "the reliable frame's inline SACK ACK is itself a timed seal"
        );
    }

    /// `accept_stream()` returns `Err(ConnectionClosed)` once the
    /// session is torn down (the internal channel is dropped).
    #[tokio::test]
    async fn accept_stream_returns_connection_closed_on_session_teardown() {
        // Use the inert `connect()` placeholder: its incoming_stream_rx is
        // backed by a channel whose sender is immediately dropped (no pump
        // running), so `accept_stream()` should return `Err(ConnectionClosed)`.
        let session = PhantomSession::connect("none".into());
        // The sender half was immediately dropped in `connect()` (stored in a
        // local `_incoming_tx` that is dropped at end of the fn). So the
        // channel is closed → recv() returns None → Ok → map_err gives
        // ConnectionClosed.
        let result =
            tokio::time::timeout(std::time::Duration::from_secs(1), session.accept_stream())
                .await
                .expect("should not time out — channel is already closed");

        assert!(
            matches!(result, Err(CoreError::ConnectionClosed)),
            "expected ConnectionClosed on a closed channel"
        );
    }

    // ── SessionBuilder tests ──────────────────────────────────────────────────

    /// `SessionBuilder::connect()` returns `ConfigError` when no pinned key was
    /// supplied — the builder type-state allows calling `.connect()` on a
    /// `SessionBuilder<T>` where T is a concrete transport, but the missing
    /// key must be caught at runtime.
    #[tokio::test]
    async fn session_builder_missing_pinned_key_errors() {
        let (client_t, _server_t) = ChannelTransport::pair();
        let result = PhantomSession::builder("test:9000")
            .transport(client_t)
            .connect()
            .await;
        assert!(
            matches!(result, Err(CoreError::ConfigError(_))),
            "expected ConfigError when pinned_key is not set, got {result:?}"
        );
    }

    /// `SessionBuilder::resumption()` validates the hint to exactly 32-byte fields at
    /// `.connect()` time (the strict FFI path), not a silent truncation — a malformed
    /// hint is a clean `ValidationError` before any I/O.
    #[tokio::test]
    async fn session_builder_rejects_malformed_resumption_hint() {
        let (client_t, _server_t) = ChannelTransport::pair();
        let (_sk, vk) = crate::crypto::hybrid_sign::HybridSigningKey::generate();
        let bad_hint = ResumptionHint::new(vec![0u8; 5], vec![0u8; 32]); // 5 != 32
        let result = PhantomSession::builder("test:9000")
            .pinned_key(vk)
            .resumption(bad_hint, Vec::new())
            .transport(client_t)
            .connect()
            .await;
        assert!(
            matches!(result, Err(CoreError::ValidationError(_))),
            "a 5-byte session_id must be rejected, got {result:?}"
        );
    }

    /// `SessionBuilder` end-to-end: connect with pinned_key set, drive the server
    /// side inline with `HandshakeServer`, verify the session reaches `Connected`.
    #[tokio::test]
    async fn session_builder_e2e_handshake() {
        use crate::transport::handshake::ServerReply;

        let server_hs = HandshakeServer::new().unwrap();
        let server_pinned_key = server_hs.verifying_key().clone();
        let client_ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();

        let (client_t, server_t) = ChannelTransport::pair();

        // Drive the builder-constructed client in the background.
        let session_fut = tokio::spawn(async move {
            PhantomSession::builder("test:9000")
                .pinned_key(server_pinned_key)
                .transport(client_t)
                .connect()
                .await
        });

        // Server side: drive handshake inline (with cookie retry).
        let hello_bytes = server_t.recv_bytes().await.unwrap();
        let ch = borsh::from_slice::<ClientHello>(&hello_bytes).unwrap();
        let retry = match server_hs.process_client_hello(&ch, 0, client_ip) {
            HandshakeResponse::Retry(r) => r,
            _ => panic!("expected Retry"),
        };
        server_t
            .send_bytes(&ServerReply::Retry(retry).to_wire().unwrap())
            .await
            .unwrap();
        let next = server_t.recv_bytes().await.unwrap();
        let ch2 = borsh::from_slice::<ClientHello>(&next).unwrap();
        match server_hs.process_client_hello(&ch2, 0, client_ip) {
            HandshakeResponse::Success(sh, _session, _) => {
                server_t
                    .send_bytes(&ServerReply::Hello(sh).to_wire().unwrap())
                    .await
                    .unwrap();
            }
            _ => panic!("expected Success"),
        }

        let session = session_fut.await.unwrap().expect("builder connect failed");
        // Wait briefly for the background pump to install the session.
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        assert_eq!(
            session.connection_state(),
            ConnectionState::Connected,
            "builder-constructed session must reach Connected after a successful handshake"
        );
        drop(server_t);
    }

    // ── Typed client failure regression tests: last_error / await_ready ────────────

    /// **Wrong-pin regression.** A client connecting against a *wrong* pinned
    /// key must:
    /// 1. Resolve `await_ready()` with `Err(CoreError::ServerIdentityMismatch)` —
    ///    the specific typed variant, not the generic string.
    /// 2. Expose the same error from `last_error()` after the failure.
    /// 3. Surface that error from `send()` rather than the generic "Cannot send in
    ///    state Failed" message.
    ///
    /// This pins the `phantom-cli ping` wrong-key case so it can never regress
    /// to a generic `NetworkError("session not established")`.
    #[tokio::test]
    async fn wrong_pinned_key_await_ready_returns_server_identity_mismatch() {
        use crate::transport::handshake::{HandshakeResponse, HandshakeServer, ServerReply};
        use std::net::IpAddr;

        let (client_transport, server_transport) = ChannelTransport::pair();
        let server_hs = HandshakeServer::new().expect("server hs");
        let _real_server_key = server_hs.verifying_key().clone();

        // Generate a WRONG key that the client will pin (different from the server's).
        let wrong_hs = HandshakeServer::new().expect("wrong hs");
        let wrong_pinned_key = wrong_hs.verifying_key().clone();

        // Client connects but pins the wrong key.
        let session = PhantomSession::connect_with_transport(
            "test-peer:9999",
            client_transport,
            wrong_pinned_key,
        );

        let client_ip: IpAddr = "127.0.0.1".parse().expect("ip");

        // Run the server handshake in the background.
        let server_task = tokio::spawn(async move {
            // Read the ClientHello.
            let hello_bytes = server_transport.recv_bytes().await.unwrap();
            let client_hello: crate::transport::handshake::ClientHello =
                borsh::from_slice(&hello_bytes).unwrap();
            // Drive to Success (server side is valid; only the client's pin is wrong).
            match server_hs.process_client_hello(&client_hello, 0, client_ip) {
                HandshakeResponse::Success(sh, _sess, _) => {
                    server_transport
                        .send_bytes(&ServerReply::Hello(sh).to_wire().unwrap())
                        .await
                        .unwrap();
                }
                HandshakeResponse::Retry(r) => {
                    // Cookie retry: answer once then re-read + process.
                    server_transport
                        .send_bytes(&ServerReply::Retry(r).to_wire().unwrap())
                        .await
                        .unwrap();
                    let next = server_transport.recv_bytes().await.unwrap();
                    let ch2: crate::transport::handshake::ClientHello =
                        borsh::from_slice(&next).unwrap();
                    match server_hs.process_client_hello(&ch2, 0, client_ip) {
                        HandshakeResponse::Success(sh, _sess, _) => {
                            server_transport
                                .send_bytes(&ServerReply::Hello(sh).to_wire().unwrap())
                                .await
                                .unwrap();
                        }
                        other => panic!("unexpected second response: {other:?}"),
                    }
                }
                other => panic!("unexpected response: {other:?}"),
            }
            // Keep the transport alive briefly so the client can read.
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            // Drop to close the channel.
        });

        // 1. await_ready() must return Err(ServerIdentityMismatch).
        let ready_result = session.await_ready().await;
        assert!(
            ready_result.is_err(),
            "await_ready must fail with wrong pinned key"
        );
        match ready_result.unwrap_err() {
            CoreError::ServerIdentityMismatch => { /* expected */ }
            other => panic!("expected ServerIdentityMismatch, got: {:?}", other),
        }

        // 2. last_error() must return the same typed variant.
        match session.last_error().await {
            Some(CoreError::ServerIdentityMismatch) => { /* expected */ }
            other => panic!(
                "last_error() expected Some(ServerIdentityMismatch), got: {:?}",
                other
            ),
        }

        // 3. send() must surface the same error (not "Cannot send in state Failed").
        let send_err = session.send(b"hello".to_vec()).await.unwrap_err();
        match send_err {
            CoreError::ServerIdentityMismatch => { /* expected */ }
            other => panic!("send() expected ServerIdentityMismatch, got: {:?}", other),
        }

        server_task.await.expect("server task must not panic");
    }

    /// **Typed-readiness regression.** A successful handshake must:
    /// 1. Resolve `await_ready()` with `Ok(())`.
    /// 2. Leave `last_error()` returning `None`.
    #[tokio::test]
    async fn successful_handshake_await_ready_returns_ok() {
        use crate::transport::handshake::{HandshakeResponse, HandshakeServer, ServerReply};
        use std::net::IpAddr;

        let (client_transport, server_transport) = ChannelTransport::pair();
        let server_hs = HandshakeServer::new().expect("server hs");
        let server_pinned_key = server_hs.verifying_key().clone();

        let session = PhantomSession::connect_with_transport(
            "test-peer:9999",
            client_transport,
            server_pinned_key,
        );

        let client_ip: IpAddr = "127.0.0.1".parse().expect("ip");

        let server_task = tokio::spawn(async move {
            let hello_bytes = server_transport.recv_bytes().await.unwrap();
            let client_hello: crate::transport::handshake::ClientHello =
                borsh::from_slice(&hello_bytes).unwrap();
            match server_hs.process_client_hello(&client_hello, 0, client_ip) {
                HandshakeResponse::Success(sh, _sess, _) => {
                    server_transport
                        .send_bytes(&ServerReply::Hello(sh).to_wire().unwrap())
                        .await
                        .unwrap();
                }
                HandshakeResponse::Retry(r) => {
                    server_transport
                        .send_bytes(&ServerReply::Retry(r).to_wire().unwrap())
                        .await
                        .unwrap();
                    let next = server_transport.recv_bytes().await.unwrap();
                    let ch2: crate::transport::handshake::ClientHello =
                        borsh::from_slice(&next).unwrap();
                    match server_hs.process_client_hello(&ch2, 0, client_ip) {
                        HandshakeResponse::Success(sh, _sess, _) => {
                            server_transport
                                .send_bytes(&ServerReply::Hello(sh).to_wire().unwrap())
                                .await
                                .unwrap();
                        }
                        other => panic!("unexpected second response: {other:?}"),
                    }
                }
                other => panic!("unexpected response: {other:?}"),
            }
            // Keep server alive for the data pump.
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        });

        // 1. await_ready() must return Ok(()) on a good handshake.
        session
            .await_ready()
            .await
            .expect("await_ready must succeed with correct pinned key");

        // 2. last_error() must be None on success.
        assert!(
            session.last_error().await.is_none(),
            "last_error() must be None after a successful handshake"
        );

        server_task.abort();
    }

    /// **Typed-error regression.** The `CoreError` variants `ServerIdentityMismatch`,
    /// `ProtocolRejected`, and `Unsupported` must be distinct from each other and
    /// from `HandshakeError` — verify the `From<HandshakeError>` mapping is correct.
    #[test]
    fn handshake_error_mapping_to_typed_variants() {
        use crate::transport::handshake::HandshakeError;

        // ServerIdentityMismatch maps to the typed variant.
        match CoreError::from(HandshakeError::ServerIdentityMismatch) {
            CoreError::ServerIdentityMismatch => { /* correct */ }
            other => panic!("expected ServerIdentityMismatch, got: {other:?}"),
        }

        // ProtocolVariantMismatch maps to ProtocolRejected.
        match CoreError::from(HandshakeError::ProtocolVariantMismatch {
            expected: b"phantom-default-1".to_vec(),
            received: b"phantom-fips-1".to_vec(),
        }) {
            CoreError::ProtocolRejected(msg) => {
                assert!(
                    msg.contains("phantom-default-1"),
                    "message should contain expected: {msg}"
                );
                assert!(
                    msg.contains("phantom-fips-1"),
                    "message should contain received: {msg}"
                );
            }
            other => panic!("expected ProtocolRejected, got: {other:?}"),
        }

        // Other errors map to HandshakeError (not the typed variants).
        match CoreError::from(HandshakeError::KemFailed("test".into())) {
            CoreError::HandshakeError(_) => { /* correct */ }
            other => panic!("expected HandshakeError, got: {other:?}"),
        }
    }

    /// `ChannelTransport` is an in-memory test pipe, not a UDP socket, so
    /// `supports_migration()` must return `false` (the trait default).
    #[test]
    fn channel_transport_does_not_support_migration() {
        let (client_transport, _server_transport) = ChannelTransport::pair();
        assert!(
            !client_transport.supports_migration(),
            "ChannelTransport is not address-aware; supports_migration must be false"
        );
    }

    /// Calling `migrate()` on a `ChannelTransport`-backed `SessionTransport`
    /// must return `Err(Unsupported)` — not panic or silently no-op.
    #[tokio::test]
    async fn migrate_on_channel_transport_returns_unsupported() {
        let (client_transport, _server_transport) = ChannelTransport::pair();
        let err = client_transport
            .migrate("127.0.0.1:0".to_string())
            .await
            .unwrap_err();
        assert!(
            matches!(err, CoreError::Unsupported(_)),
            "expected CoreError::Unsupported, got {err:?}"
        );
    }

    /// Calling `migrate_server()` on a `ChannelTransport` must also return
    /// `Err(Unsupported)`.
    #[tokio::test]
    async fn migrate_server_on_channel_transport_returns_unsupported() {
        let (_client_transport, server_transport) = ChannelTransport::pair();
        let err = server_transport
            .migrate_server("127.0.0.1:0".to_string())
            .await
            .unwrap_err();
        assert!(
            matches!(err, CoreError::Unsupported(_)),
            "expected CoreError::Unsupported, got {err:?}"
        );
    }

    /// A `PhantomSession` built on a `ChannelTransport` must expose
    /// `supports_migration() == false`.
    #[tokio::test]
    async fn phantom_session_on_channel_transport_reports_no_migration() {
        let (client_transport, _server_transport) = ChannelTransport::pair();
        let server_hs = HandshakeServer::new().unwrap();
        let server_pinned_key = server_hs.verifying_key().clone();
        let session = PhantomSession::connect_with_transport(
            "test-server:9000",
            client_transport,
            server_pinned_key,
        );
        assert!(
            !session.supports_migration(),
            "session backed by ChannelTransport must not support migration"
        );
    }

    /// A `PhantomSession` built on a `ChannelTransport` must return
    /// `Err(Unsupported)` from the public `migrate()` API without even touching
    /// the command channel.
    #[tokio::test]
    async fn phantom_session_migrate_on_non_udp_returns_unsupported() {
        let (client_transport, _server_transport) = ChannelTransport::pair();
        let server_hs = HandshakeServer::new().unwrap();
        let server_pinned_key = server_hs.verifying_key().clone();
        let session = PhantomSession::connect_with_transport(
            "test-server:9000",
            client_transport,
            server_pinned_key,
        );
        let err = session
            .migrate("127.0.0.1:0".to_string())
            .await
            .unwrap_err();
        assert!(
            matches!(err, CoreError::Unsupported(_)),
            "PhantomSession::migrate on a non-UDP session must return Unsupported; got {err:?}"
        );
    }

    // ────────────────────────────────────────────────────────────────────
    // Datagram budget — one full application chunk is one PhantomUDP datagram
    // ────────────────────────────────────────────────────────────────────

    #[cfg(not(target_arch = "wasm32"))]
    mod datagram_budget {
        use super::*;
        use crate::api::udp_transport::UdpClientTransport;
        use crate::transport::mtu::{
            MAX_APP_CHUNK, MAX_INNER_UNFRAGMENTED, PATH_MTU, PER_PACKET_OVERHEAD,
        };
        use crate::transport::phantom_udp::datagram::{push_datagram, FragmentAssembler};

        /// Outer flags: bit 5 marks a fragment of a larger logical frame.
        const FRAG_BIT: u8 = 0b0010_0000;

        /// Put `payload` on a real socket through the real send path — the pump's
        /// own `send_app_data` (rekey stamp, in-plaintext stream offset, AEAD seal,
        /// header protection) into a real `UdpClientTransport`, which is what
        /// decides how many datagrams it becomes. Returns the datagrams as the peer
        /// saw them, plus the receiving session that can open them.
        async fn datagrams_for(payload: &[u8]) -> (Vec<Vec<u8>>, Arc<InnerSession>, SessionId) {
            let session_id = fixed_session_id();
            let (client, server) = paired_sessions(session_id);
            let peer = tokio::net::UdpSocket::bind("127.0.0.1:0")
                .await
                .expect("bind peer socket");
            let peer_addr = peer.local_addr().expect("peer addr");
            let transport = Arc::new(
                UdpClientTransport::connect(peer_addr)
                    .await
                    .expect("udp connect"),
            );
            // Post-handshake framing: short header, exactly as the pump leaves it.
            transport.set_frame_phase(FramePhase::Established);

            let obs = Observability::new(ObservabilityConfig::default());
            assert!(
                send_app_data(
                    &transport,
                    &client,
                    session_id,
                    1,
                    payload,
                    PacketFlags::RELIABLE,
                    Some(0),
                    &obs,
                )
                .await,
                "the real send path must accept a {}-byte chunk",
                payload.len()
            );

            let mut out = Vec::new();
            let mut buf = vec![0u8; 4096];
            while let Ok(Ok((n, _))) = tokio::time::timeout(
                std::time::Duration::from_millis(300),
                peer.recv_from(&mut buf),
            )
            .await
            {
                out.push(buf[..n].to_vec());
            }
            (out, server, session_id)
        }

        /// The property the chunk size exists to hold: a maximum-size application
        /// chunk leaves as exactly one datagram, with the fragment bit clear.
        ///
        /// Asserted on the datagrams the peer socket actually received, not on a
        /// recomputed constant — the split happens inside the transport, below the
        /// layer that chose the chunk size.
        #[tokio::test]
        async fn a_full_chunk_is_one_unfragmented_datagram() {
            let payload = vec![0x5Au8; MAX_APP_CHUNK];
            let (dgrams, _server, _id) = datagrams_for(&payload).await;
            assert_eq!(
                dgrams.len(),
                1,
                "a {MAX_APP_CHUNK}-byte chunk must not be split; got {} datagrams of sizes {:?}",
                dgrams.len(),
                dgrams.iter().map(|d| d.len()).collect::<Vec<_>>()
            );
            assert_eq!(
                dgrams[0][0] & FRAG_BIT,
                0,
                "the single datagram must not carry the fragment bit"
            );
            assert_eq!(
                dgrams[0].len(),
                PATH_MTU,
                "a full chunk should fill the path MTU exactly — anything less is \
                 headroom paid for on every packet"
            );
        }

        /// Two-sided: one byte past the budget genuinely does fragment, and the two
        /// datagrams reassemble into the original packet, which still decrypts to
        /// the exact payload.
        ///
        /// This rejects a "fix" that suppresses fragmentation (raising
        /// `MAX_INNER_UNFRAGMENTED`, or dropping the oversized-frame split): with
        /// fragmentation gone the datagram count would be 1 and the reassembly
        /// assertion would never run.
        #[tokio::test]
        async fn one_byte_over_the_budget_fragments_and_reassembles() {
            let payload = vec![0xA5u8; MAX_APP_CHUNK + 1];
            let (dgrams, server, session_id) = datagrams_for(&payload).await;
            assert_eq!(
                dgrams.len(),
                2,
                "one byte over the budget costs a second datagram; got sizes {:?}",
                dgrams.iter().map(|d| d.len()).collect::<Vec<_>>()
            );
            for d in &dgrams {
                assert_ne!(d[0] & FRAG_BIT, 0, "both datagrams are fragments");
            }

            let mut asm = FragmentAssembler::new();
            let mut frame = None;
            for d in &dgrams {
                if let (_, Some(done)) = push_datagram(&mut asm, d).expect("decode datagram") {
                    frame = Some(done);
                }
            }
            let frame = frame.expect("the two fragments must reassemble");
            let mut packet = server
                .parse_protected(&frame)
                .expect("strip header protection");
            // The 32-byte session id is authenticated in the AAD but never sent;
            // the receiver fills it from session context, as `handle_packet` does.
            packet.header.session_id = session_id;
            let plaintext = server
                .decrypt_packet(&packet.header, &packet.payload, &[])
                .expect("decrypt reassembled packet");
            assert_eq!(
                &plaintext[4..],
                &payload[..],
                "the reassembled packet must carry the original payload byte-exactly \
                 (the first four plaintext bytes are the reliable stream offset)"
            );
        }

        /// Ties the chunk size to the datagram budget through the real crypto path:
        /// the sealed, header-protected inner frame for a full chunk must measure
        /// exactly `MAX_INNER_UNFRAGMENTED`.
        ///
        /// This rejects a "fix" that merely picks some smaller round number — 1024,
        /// say — which would still pass the no-fragmentation test while quietly
        /// spending an extra datagram every 1156 bytes. It equally rejects raising
        /// the chunk without raising `PATH_MTU`, and catches an overhead change
        /// (header size, tag size, the in-plaintext offset) that the derivation
        /// failed to track.
        #[tokio::test]
        async fn a_full_chunk_measures_exactly_the_unfragmented_budget() {
            let session_id = fixed_session_id();
            let (client, _server) = paired_sessions(session_id);
            let header = PacketHeader::new(
                session_id,
                1,
                0,
                PacketFlags::new(PacketFlags::RELIABLE | PacketFlags::ENCRYPTED),
            );
            let mut plaintext = Vec::with_capacity(4 + MAX_APP_CHUNK);
            plaintext.extend_from_slice(&0u32.to_be_bytes());
            plaintext.extend_from_slice(&vec![0x11u8; MAX_APP_CHUNK]);
            let ciphertext = client
                .encrypt_packet(&header, &plaintext, &[])
                .expect("encrypt");
            let wire = client
                .protect_packet(&PhantomPacket::new(header, ciphertext))
                .expect("header protection");
            assert_eq!(
                wire.len(),
                MAX_INNER_UNFRAGMENTED,
                "measured per-packet overhead is {} bytes, the derivation assumes {}",
                wire.len() - MAX_APP_CHUNK,
                PER_PACKET_OVERHEAD
            );
        }
    }
}
