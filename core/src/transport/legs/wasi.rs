//! [`WasiLeg`] — length-prefix-framed [`SessionTransport`] over a WASI
//! Preview 2 `wasi::sockets::tcp::TcpSocket`.
//!
//! Mirrors [`crate::api::tcp_transport::TcpSessionTransport`]'s framing
//! (4-byte big-endian length prefix per message) so an embedder
//! running inside `wasmtime` / `wasmer` / `jco` can drive the same
//! Phantom Protocol session machinery without code-level branching.
//!
//! **Single-task model.** WASI Preview 2 has no native thread
//! primitive, so this leg blocks the instance on `wasi:io/poll::poll`
//! while it waits on the kernel — `blocking_read` for reads, and for
//! writes an explicit poll on the output stream's readiness (below) —
//! so the WASI host can park the instance without spin-busy-waiting
//! Rust-side. Concurrent sessions inside one WASI instance therefore
//! serialise at the I/O layer; that matches the
//! [`crate::runtime::WasiRuntime`] single-task scheduler and is
//! sufficient for the client-side embedder use cases.
//!
//! **A peer that stops reading.** A write waits for the output stream to
//! accept bytes, and a peer that has stopped reading its socket lets it
//! accept none. Blocking on that without a bound would hold the whole
//! instance — the session's pump, its close, and anything else the guest
//! runs — for as long as the peer chose. So each wait is a poll on the
//! stream's readiness *and* a monotonic-clock timer, and a write that sees
//! no progress for [`WasiLeg::DEFAULT_WRITE_STALL_TIMEOUT`] (adjustable with
//! [`WasiLeg::with_write_stall_timeout`]) fails with [`CoreError::Timeout`],
//! the same rule `TcpSessionTransport` follows: every byte accepted restarts
//! the clock, and after a stall every later send is refused without touching
//! the stream, since the stalled frame may be cut part-way through. A leg
//! dropped after a stall leaves its socket to the host rather than wait for
//! the stalled write to finish; see `Drop for WasiLeg`.
//!
//! **Client-only.** Connection establishment runs through
//! `tcp_create_socket → start_connect → subscribe / poll →
//! finish_connect`. Server-side accept (`start_listen` /
//! `finish_listen` / `accept`) is out of scope —
//! `phantom-server`-on-WASI is deferred (see `docs/DEFERRED_WORK.md`).
//!
//! Module-gated on `cfg(all(feature = "wasi-leg", target_os = "wasi"))`,
//! same gate as [`crate::runtime::WasiRuntime`].

// SAFETY OPT-IN — the WIT-bindgen-generated `TcpSocket` /
// `InputStream` / `OutputStream` resources wrap an opaque numeric
// host handle (`Resource<T>`) and are `!Send + !Sync` by default
// because the compiler cannot see the resource ownership semantics.
// This module's `unsafe impl Send / Sync for WasiLeg` blocks override
// that conservative bound; see the SAFETY block on the impls for the
// soundness argument. Tracked as the third entry in
// `docs/security/panic-sites.md`'s Unsafe Blocks table.
#![allow(unsafe_code)]

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use wasi::clocks::monotonic_clock;
use wasi::io::poll::{self, Pollable};
use wasi::io::streams::StreamError;
use wasi::sockets::instance_network::instance_network;
use wasi::sockets::network::{
    IpAddressFamily, IpSocketAddress, Ipv4SocketAddress, Ipv6SocketAddress,
};
use wasi::sockets::tcp::{InputStream, OutputStream, TcpSocket};
use wasi::sockets::tcp_create_socket::create_tcp_socket;

use crate::errors::CoreError;
use crate::transport::session_transport::SessionTransport;

/// Hard frame cap (WIRE-001). Matches `TcpSessionTransport`'s steady-state cap;
/// rejects an attacker-controlled length prefix that would otherwise drive
/// unbounded `BytesMut` growth. (WasiLeg is a client-only leg, so it has no
/// unauthenticated-server-accept phase to gate more tightly.)
const MAX_FRAME_BYTES: usize = 4 * 1024 * 1024; // 4 MiB

/// Initial recv-accumulator capacity. Sized to a generous MTU so
/// the steady-state path never reallocates after the first frame.
const RECV_BUF_INITIAL_CAPACITY: usize = 64 * 1024;

/// Incremental-read chunk: the accumulator grows by at most this per read, so a
/// peer that DECLARES a large frame but stalls cannot make us pre-commit the
/// full declared length (WIRE-001).
const RECV_CHUNK: usize = 64 * 1024;

/// After a frame larger than `RECV_BUF_INITIAL_CAPACITY * SHRINK_SLACK_MULT`,
/// reset the accumulator to baseline (LEGS-003).
const SHRINK_SLACK_MULT: usize = 4;

/// Length-prefix-framed `SessionTransport` over a WASI Preview 2
/// `TcpSocket`. Holds the connected (input, output) stream pair
/// behind `std::sync::Mutex` so the trait's `Send + Sync` bound is
/// satisfied; the WASI single-task model means lock contention is
/// trivial in practice.
pub struct WasiLeg {
    /// `None` only once `Drop for WasiLeg` has handed the stream to the host;
    /// no method can observe that, since it happens in the destructor.
    output: Mutex<Option<OutputStream>>,
    /// Read half + the per-direction accumulator. Held together so the
    /// buffer lifetime tracks the reader's exactly (same shape as
    /// `TcpSessionTransport` Phase 2.1).
    read: Mutex<(InputStream, BytesMut)>,
    /// How long one write may wait without the stream accepting a byte.
    write_stall_timeout: Duration,
    /// Set by the first write that stalls out, and never cleared: that write may
    /// have left a frame cut part-way through, so nothing may follow it.
    write_stalled: AtomicBool,
    /// Keep the `TcpSocket` alive — dropping it closes the underlying
    /// host file descriptor, which would invalidate the streams. WIT
    /// resource semantics: streams are derived from the socket and
    /// reference it. `None` only once `Drop for WasiLeg` has handed it to
    /// the host along with `output`.
    socket: Option<TcpSocket>,
}

// SAFETY: WIT-bindgen `TcpSocket` / `InputStream` / `OutputStream`
// each wrap an opaque numeric host handle (`Resource<T>`). The two
// *stream* handles live behind `std::sync::Mutex` wrappers (`output`,
// `read`), which are the only access path for them after construction
// — every read and every write goes through a `lock()`-guarded
// section. That single-accessor discipline is what makes sending the
// stream handles across threads sound: at most one thread holds the
// lock at any moment, so a handle is never concurrently observed in
// two places.
//
// `socket` is the deliberate carve-out: it is NOT behind a mutex
// because it is never dereferenced through a shared `&self` — no method
// on `WasiLeg` reads or mutates it. It exists solely to keep the host
// socket fd (and therefore the derived streams) alive for the leg's
// lifetime. Its only accesses are `Drop for WasiLeg`, which may take it
// out and leak it, and the implicit `resource-drop` WIT call otherwise;
// both run with unique ownership of the field (`&mut self`, then the drop
// glue), so neither can race a concurrent read — there are no concurrent
// reads of it at all. A bare `Resource<T>` with exactly one accessor, the
// destructor, needs no interior synchronization to be `Send`/`Sync`-sound.
//
// `WasiLeg` itself is the unit we mark `Send`/`Sync`. The argument
// stands independently of WASI Preview 2's current single-task host
// model: even if `wasi-threads` / `wasi-shared-everything-threads`
// stabilizes and an embedder enables threading inside a WASI
// instance, the mutex contract continues to hold. The `unsafe impl`
// blocks are the contract that *this code* never hands the raw
// handle to a second thread without going through the mutex; the
// `Resource<T>` types are private, so no external code can break
// that.
//
// One caveat: dropping a `Resource<T>` invokes the host's `resource-
// drop` which is itself a WIT call. We rely on `std::sync::Mutex`'s
// `Sync` bound to ensure no concurrent drop + access races; the
// inner field's drop order (`output, read, socket`) preserves the
// WIT parent-after-children invariant.
unsafe impl Send for WasiLeg {}
unsafe impl Sync for WasiLeg {}

/// A leg whose write stalled out leaves its output stream and socket to the host
/// instead of dropping them.
///
/// The stalled write leaves bytes the host accepted and could not deliver,
/// because the peer stopped reading, and a host may finish that write before it
/// lets the output stream go: `wasmtime` does, for as long as the write takes,
/// and a `shutdown` of the socket does not cut it short, it is queued behind the
/// write. Dropping the stream would then block the instance on the very peer
/// the stall gave up on. So the stream is forgotten instead, and the socket with
/// it, since a socket cannot be dropped while a stream derived from it lives.
/// Both stay in the host's table until the instance ends, and so does the
/// connection: the price of not waiting on a peer that may never read again.
/// A leg that never stalled drops both as before, and the host flushes what it
/// wrote.
impl Drop for WasiLeg {
    fn drop(&mut self) {
        if self.write_stalled.load(Ordering::Acquire) {
            let output = self
                .output
                .get_mut()
                .unwrap_or_else(PoisonError::into_inner);
            std::mem::forget(output.take());
            std::mem::forget(self.socket.take());
        }
    }
}

impl WasiLeg {
    /// Connect to `remote` over TCP via the default WASI network
    /// instance. Blocks the WASI guest until the connect completes
    /// or the host returns an error.
    ///
    /// `remote` is a `std::net::SocketAddr`; this constructor
    /// converts it into the WIT-side `IpSocketAddress`. DNS is
    /// **out of scope** — `wasi:sockets/tcp` does not resolve
    /// hostnames, the caller must hand in a resolved address (e.g.
    /// from `wasi:sockets/ip-name-lookup`, not used here).
    pub fn connect(remote: SocketAddr) -> Result<Self, CoreError> {
        let (family, addr) = ip_socket_address_from_std(remote);

        let network = instance_network();
        let socket = create_tcp_socket(family)
            .map_err(|e| CoreError::NetworkError(format!("create_tcp_socket: {:?}", e)))?;
        socket
            .start_connect(&network, addr)
            .map_err(|e| CoreError::NetworkError(format!("start_connect: {:?}", e)))?;

        // Wait for the connect to complete. `subscribe` returns a
        // Pollable that fires when the connect transitions out of
        // the in-progress state; `poll::poll` blocks the WASI guest
        // until that pollable (or any other registered) is ready.
        let pollable = socket.subscribe();
        let _ready = poll::poll(&[&pollable]);

        let (input, output) = socket
            .finish_connect()
            .map_err(|e| CoreError::NetworkError(format!("finish_connect: {:?}", e)))?;

        Ok(Self {
            output: Mutex::new(Some(output)),
            read: Mutex::new((input, BytesMut::with_capacity(RECV_BUF_INITIAL_CAPACITY))),
            write_stall_timeout: Self::DEFAULT_WRITE_STALL_TIMEOUT,
            write_stalled: AtomicBool::new(false),
            socket: Some(socket),
        })
    }

    /// How long a write may go without the output stream accepting a byte before
    /// the leg gives up on its peer, unless
    /// [`with_write_stall_timeout`](Self::with_write_stall_timeout) says otherwise.
    /// Thirty seconds, the figure `TcpSessionTransport` and the mimicry leg start
    /// from too; all three read it from one definition, so they cannot drift apart.
    pub const DEFAULT_WRITE_STALL_TIMEOUT: Duration =
        crate::transport::write_stall::DEFAULT_WRITE_STALL_TIMEOUT;

    /// Replace the write-stall deadline: how long a single write may wait without
    /// the stream accepting a byte before `send_bytes` fails with
    /// [`CoreError::Timeout`] and the leg gives up on its peer. The clock restarts
    /// with every byte accepted — it bounds how long the peer may stop reading,
    /// not how slowly it may read.
    pub fn with_write_stall_timeout(mut self, timeout: Duration) -> Self {
        self.write_stall_timeout = timeout;
        self
    }
}

impl SessionTransport for WasiLeg {
    async fn send_bytes(&self, data: &[u8]) -> Result<(), CoreError> {
        if data.len() > MAX_FRAME_BYTES {
            return Err(CoreError::NetworkError(format!(
                "frame too large: {} > {}",
                data.len(),
                MAX_FRAME_BYTES
            )));
        }
        if self.write_stalled.load(Ordering::Acquire) {
            return Err(CoreError::Timeout);
        }
        // PANIC-SAFETY: the mutex is private and only held by this
        // method; a poison would only arise from a panic inside an
        // earlier `send_bytes` call, an unrecoverable state.
        #[allow(clippy::expect_used)]
        let guard = self.output.lock().expect("WasiLeg output mutex poisoned");
        // Checked again under the lock: the send this one queued behind may be the
        // one that stalled, and what it left on the wire is not a frame boundary.
        if self.write_stalled.load(Ordering::Acquire) {
            return Err(CoreError::Timeout);
        }
        // Only the destructor empties the slot, and nothing can call this after it.
        let Some(out) = guard.as_ref() else {
            return Err(CoreError::ConnectionClosed);
        };
        let len = (data.len() as u32).to_be_bytes();
        match write_all_making_progress(out, &[&len, data], self.write_stall_timeout) {
            Ok(()) => Ok(()),
            Err(WriteFailure::Stalled) => {
                self.write_stalled.store(true, Ordering::Release);
                Err(CoreError::Timeout)
            }
            Err(WriteFailure::Stream(e)) => Err(CoreError::NetworkError(format!("write: {e:?}"))),
        }
    }

    async fn recv_bytes(&self) -> Result<Bytes, CoreError> {
        // PANIC-SAFETY: same shape as `send_bytes` above — the mutex is a
        // private field, held only here, and a poison could only follow a
        // panic inside an earlier `recv_bytes`, after which the WASI input
        // stream and the half-read accumulator are both indeterminate.
        #[allow(clippy::expect_used)]
        let mut guard = self.read.lock().expect("WasiLeg read mutex poisoned");
        let (input, accum) = &mut *guard;

        // Read the 4-byte big-endian length prefix.
        let mut len_buf = [0u8; 4];
        read_exact(input, &mut len_buf)?;
        let len = u32::from_be_bytes(len_buf) as usize;
        if len > MAX_FRAME_BYTES {
            return Err(CoreError::NetworkError(format!(
                "oversized frame from peer: {} > {}",
                len, MAX_FRAME_BYTES
            )));
        }

        // Incremental read (WIRE-001): grow by at most RECV_CHUNK per read, so a
        // peer that declares a large frame but stalls cannot make us pre-commit
        // the full declared length.
        accum.clear();
        let mut filled = 0usize;
        while filled < len {
            let chunk = (len - filled).min(RECV_CHUNK);
            accum.resize(filled + chunk, 0);
            read_exact(input, &mut accum[filled..filled + chunk])?;
            filled += chunk;
        }

        let frame = accum.split_to(len).freeze();
        // LEGS-003: reset the accumulator to baseline after a large frame so one
        // big frame does not pin a large buffer for the connection's life.
        if len > RECV_BUF_INITIAL_CAPACITY * SHRINK_SLACK_MULT {
            *accum = BytesMut::with_capacity(RECV_BUF_INITIAL_CAPACITY);
        }
        Ok(frame)
    }
}

/// Fill `dest` from `input` via repeated `blocking_read` until the
/// slice is full. `blocking_read` returns at least one byte when
/// data is available but may return fewer than requested; loop
/// until satisfied.
fn read_exact(input: &InputStream, dest: &mut [u8]) -> Result<(), CoreError> {
    let mut filled = 0;
    while filled < dest.len() {
        let want = (dest.len() - filled) as u64;
        let chunk = input
            .blocking_read(want)
            .map_err(|e| CoreError::NetworkError(format!("blocking_read: {:?}", e)))?;
        if chunk.is_empty() {
            return Err(CoreError::NetworkError(
                "peer closed the WASI TCP stream (EOF)".into(),
            ));
        }
        let take = chunk.len().min(dest.len() - filled);
        dest[filled..filled + take].copy_from_slice(&chunk[..take]);
        filled += take;
    }
    Ok(())
}

/// Why [`write_all_making_progress`] did not finish.
enum WriteFailure {
    /// The stream accepted nothing for the whole deadline.
    Stalled,
    /// The stream reported an error.
    Stream(StreamError),
}

/// Write every byte of `parts`, in order, then flush — failing with
/// [`WriteFailure::Stalled`] as soon as one wait for the stream has lasted
/// `stall` without the stream accepting anything.
///
/// Uses the non-blocking half of `wasi:io/streams` — `check-write` for how much
/// the stream will take now, `write` for exactly that much — and waits through
/// `wasi:io/poll`, so each wait can be bounded by a timer. The blocking
/// convenience call cannot be bounded, and is specified for at most 4096 bytes
/// a call besides; this takes a frame of any size.
fn write_all_making_progress(
    out: &OutputStream,
    parts: &[&[u8]],
    stall: Duration,
) -> Result<(), WriteFailure> {
    // A child of the stream: it must be dropped before the stream is, which it is,
    // at the end of this call.
    let writable = out.subscribe();
    for part in parts {
        let mut rest: &[u8] = part;
        while !rest.is_empty() {
            let permit = out.check_write().map_err(WriteFailure::Stream)?;
            if permit == 0 {
                wait_for_progress(&writable, stall)?;
                continue;
            }
            let n = usize::try_from(permit).map_or(rest.len(), |p| p.min(rest.len()));
            let (now, later) = rest.split_at(n);
            out.write(now).map_err(WriteFailure::Stream)?;
            rest = later;
        }
    }
    // A flush holds further writes until it completes, and reports completion
    // through the same readiness: `check-write` answers 0 until then.
    out.flush().map_err(WriteFailure::Stream)?;
    while out.check_write().map_err(WriteFailure::Stream)? == 0 {
        wait_for_progress(&writable, stall)?;
    }
    Ok(())
}

/// Block until the stream behind `writable` can take bytes again, or `stall`
/// passes first.
fn wait_for_progress(writable: &Pollable, stall: Duration) -> Result<(), WriteFailure> {
    let nanos = u64::try_from(stall.as_nanos()).unwrap_or(u64::MAX);
    let deadline = monotonic_clock::subscribe_duration(nanos);
    // `poll` answers with the indices of the pollables that are ready; index 0 is
    // the stream. Ready together with the timer still counts as progress.
    if poll::poll(&[writable, &deadline]).contains(&0) {
        Ok(())
    } else {
        Err(WriteFailure::Stalled)
    }
}

/// Convert a `std::net::SocketAddr` to the
/// (`IpAddressFamily`, `IpSocketAddress`) pair the WIT API expects.
fn ip_socket_address_from_std(addr: SocketAddr) -> (IpAddressFamily, IpSocketAddress) {
    match addr {
        SocketAddr::V4(v4) => {
            let octets = v4.ip().octets();
            (
                IpAddressFamily::Ipv4,
                IpSocketAddress::Ipv4(Ipv4SocketAddress {
                    port: v4.port(),
                    address: (octets[0], octets[1], octets[2], octets[3]),
                }),
            )
        }
        SocketAddr::V6(v6) => {
            let segs = v6.ip().segments();
            (
                IpAddressFamily::Ipv6,
                IpSocketAddress::Ipv6(Ipv6SocketAddress {
                    port: v6.port(),
                    flow_info: v6.flowinfo(),
                    address: (
                        segs[0], segs[1], segs[2], segs[3], segs[4], segs[5], segs[6], segs[7],
                    ),
                    scope_id: v6.scope_id(),
                }),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Smoke: the address conversion preserves the IPv4 octets + port.
    #[test]
    fn ipv4_addr_conversion_round_trips() {
        let addr: SocketAddr = "127.0.0.1:4242".parse().unwrap();
        let (family, ip) = ip_socket_address_from_std(addr);
        assert!(matches!(family, IpAddressFamily::Ipv4));
        let IpSocketAddress::Ipv4(v4) = ip else {
            panic!("expected ipv4 variant");
        };
        assert_eq!(v4.port, 4242);
        assert_eq!(v4.address, (127, 0, 0, 1));
    }

    /// Smoke: the address conversion preserves IPv6 segments + port.
    #[test]
    fn ipv6_addr_conversion_round_trips() {
        let addr: SocketAddr = "[::1]:4242".parse().unwrap();
        let (family, ip) = ip_socket_address_from_std(addr);
        assert!(matches!(family, IpAddressFamily::Ipv6));
        let IpSocketAddress::Ipv6(v6) = ip else {
            panic!("expected ipv6 variant");
        };
        assert_eq!(v6.port, 4242);
        assert_eq!(v6.address, (0, 0, 0, 0, 0, 0, 0, 1));
    }
}
