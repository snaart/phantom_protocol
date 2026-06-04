//! [`WasiLeg`] — length-prefix-framed [`SessionTransport`] over a WASI
//! Preview 2 `wasi::sockets::tcp::TcpSocket` (Section B / B3 of the
//! pre-1.0 deferred-followups plan).
//!
//! Mirrors [`crate::api::tcp_transport::TcpSessionTransport`]'s framing
//! (4-byte big-endian length prefix per message) so an embedder
//! running inside `wasmtime` / `wasmer` / `jco` can drive the same
//! Phantom session machinery without code-level branching.
//!
//! **Single-task model.** WASI Preview 2 has no native thread
//! primitive, so this leg uses the `wasi:io/streams` blocking
//! variants (`blocking_read` / `blocking_write_and_flush`). Those
//! internally call `wasi:io/poll::poll`, so the WASI host can park
//! the instance while waiting on the kernel without spin-busy-waiting
//! Rust-side. Concurrent sessions inside one WASI instance therefore
//! serialise at the I/O layer; that matches the
//! [`crate::runtime::WasiRuntime`] single-task scheduler and is
//! sufficient for the client-side embedder use cases B targets.
//!
//! **Client-only for B3.** Connection establishment runs through
//! `tcp_create_socket → start_connect → subscribe / poll →
//! finish_connect`. Server-side accept (`start_listen` /
//! `finish_listen` / `accept`) is out of scope for this commit —
//! `phantom-server`-on-WASI is explicitly deferred in the plan's
//! Decision Point 3.
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
use std::sync::Mutex;

use bytes::{Bytes, BytesMut};
use wasi::io::poll;
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
    output: Mutex<OutputStream>,
    /// Read half + the per-direction accumulator. Held together so the
    /// buffer lifetime tracks the reader's exactly (same shape as
    /// `TcpSessionTransport` Phase 2.1).
    read: Mutex<(InputStream, BytesMut)>,
    /// Keep the `TcpSocket` alive — dropping it closes the underlying
    /// host file descriptor, which would invalidate the streams. WIT
    /// resource semantics: streams are derived from the socket and
    /// reference it.
    _socket: TcpSocket,
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
// `_socket` is the deliberate carve-out: it is NOT behind a mutex
// because it is never dereferenced through a shared `&self` — no method
// on `WasiLeg` reads or mutates it. It exists solely to keep the host
// socket fd (and therefore the derived streams) alive for the leg's
// lifetime. Its only access is the implicit `resource-drop` WIT call
// when `WasiLeg` is dropped, which runs with unique ownership of the
// field (the drop glue holds `&mut`-equivalent exclusive access), so it
// cannot race a concurrent read — there are no concurrent reads of it at
// all. A bare `Resource<T>` with exactly one accessor, the destructor,
// needs no interior synchronization to be `Send`/`Sync`-sound.
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
// inner field's drop order (`output, read, _socket`) preserves the
// WIT parent-after-children invariant.
unsafe impl Send for WasiLeg {}
unsafe impl Sync for WasiLeg {}

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
            output: Mutex::new(output),
            read: Mutex::new((input, BytesMut::with_capacity(RECV_BUF_INITIAL_CAPACITY))),
            _socket: socket,
        })
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
        // PANIC-SAFETY: the mutex is private and only held by this
        // method; a poison would only arise from a panic inside an
        // earlier `send_bytes` call, an unrecoverable state.
        #[allow(clippy::expect_used)]
        let out = self.output.lock().expect("WasiLeg output mutex poisoned");
        let len = (data.len() as u32).to_be_bytes();
        out.blocking_write_and_flush(&len)
            .map_err(|e| CoreError::NetworkError(format!("write length: {:?}", e)))?;
        out.blocking_write_and_flush(data)
            .map_err(|e| CoreError::NetworkError(format!("write payload: {:?}", e)))?;
        Ok(())
    }

    async fn recv_bytes(&self) -> Result<Bytes, CoreError> {
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
