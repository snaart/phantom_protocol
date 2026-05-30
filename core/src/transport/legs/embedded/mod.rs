//! `EmbeddedLeg` — a `SessionTransport` over `embedded-io-async` byte streams,
//! for UART / serial and other embedded byte transports (Phase 3.4).
//!
//! ## Shape
//!
//! `EmbeddedLeg<R, W, const N: usize>` is **passive** — it holds the read/
//! write halves of a pre-split transport behind two `async_lock` mutexes and
//! exposes inherent generic `async fn` send/recv methods (with the framing
//! logic from [`framing`]). The [`SessionTransport`] trait `impl` is
//! **per-concrete (`R`, `W`)** rather than one generic blanket:
//! `embedded-io-async`'s async-fn-in-trait futures are not `Send`-bounded, so
//! a generic `impl<R, W>` cannot satisfy `SessionTransport`'s `+ Send` future
//! bound (un-expressible in stable Rust without `return_type_notation`). With
//! concrete `R`/`W` the compiler sees the HAL's actual future and proves
//! `Send` directly. The `impl_embedded_session_transport!` macro
//! generates the per-pair impl in one line.
//!
//! Behind the `embedded` cargo feature. no_std + alloc-clean — this module
//! only depends on `core`/`alloc`, `bytes`, `async_lock`, and `embedded-io-
//! async`.
//!
//! Phase 3.6 (no-std foundation): production code in this module compiles
//! without `std`. `format!` / `String` / `Vec` come from `alloc`, pulled in by
//! the crate-level `extern crate alloc;` in `lib.rs`. The `#[cfg(test)]` block
//! below intentionally stays std-bound — host tests lean on `tokio`,
//! `std::collections::VecDeque`, `std::sync::Arc`, etc.

#[cfg(not(feature = "std"))]
use alloc::format;

pub mod framing;

use crate::errors::CoreError;
use async_lock::Mutex;
use bytes::Bytes;
use embedded_io_async::{Error, Read, Write};

/// Length-prefix transport over `embedded-io-async` byte streams.
///
/// See the [module docs](self) for the `SessionTransport` hook-up story.
pub struct EmbeddedLeg<R, W, const N: usize> {
    rx: Mutex<(R, [u8; N])>,
    tx: Mutex<W>,
}

impl<R, W, const N: usize> EmbeddedLeg<R, W, N> {
    /// Wrap a pre-split `(reader, writer)` pair. Most embassy UART/USB HALs
    /// offer a `.split()` that produces compatible halves; a non-splittable
    /// shared bus needs a caller-side wrapper.
    pub fn new(reader: R, writer: W) -> Self {
        Self {
            rx: Mutex::new((reader, [0u8; N])),
            tx: Mutex::new(writer),
        }
    }

    /// Recover the inner `(reader, writer)`; consumes the leg.
    pub fn into_inner(self) -> (R, W) {
        let (r, _buf) = self.rx.into_inner();
        let w = self.tx.into_inner();
        (r, w)
    }
}

impl<R, W, const N: usize> EmbeddedLeg<R, W, N>
where
    R: Read,
    W: Write,
{
    /// Send one framed message: 4-byte big-endian length prefix + payload.
    /// Errors if `data.len()` exceeds the leg's buffer `N` or `u32::MAX`, or
    /// on any transport error from `W`.
    pub async fn send_frame(&self, data: &[u8]) -> Result<(), CoreError> {
        let header = framing::encode_header(data.len(), N)
            .map_err(|e| CoreError::NetworkError(format!("framing: {:?}", e)))?;
        let mut w = self.tx.lock().await;
        w.write_all(&header)
            .await
            .map_err(|e| CoreError::NetworkError(format!("write header: {:?}", e.kind())))?;
        w.write_all(data)
            .await
            .map_err(|e| CoreError::NetworkError(format!("write payload: {:?}", e.kind())))?;
        w.flush()
            .await
            .map_err(|e| CoreError::NetworkError(format!("flush: {:?}", e.kind())))?;
        Ok(())
    }

    /// Receive one framed message. Returns the payload as a fresh `Bytes`.
    /// Returns `CoreError::ConnectionClosed` on EOF; `CoreError::NetworkError`
    /// on framing errors or transport errors.
    pub async fn recv_frame(&self) -> Result<Bytes, CoreError> {
        let mut header = [0u8; framing::HEADER_LEN];
        let mut guard = self.rx.lock().await;
        let (r, buf) = &mut *guard;
        r.read_exact(&mut header)
            .await
            .map_err(|_| CoreError::NetworkError("read header".into()))?;
        let len = framing::decode_header(&header, N)
            .map_err(|e| CoreError::NetworkError(format!("framing: {:?}", e)))?;
        r.read_exact(&mut buf[..len])
            .await
            .map_err(|_| CoreError::NetworkError("read payload".into()))?;
        Ok(Bytes::copy_from_slice(&buf[..len]))
    }
}

/// Generate a [`SessionTransport`] impl for a concrete
/// `EmbeddedLeg<$reader, $writer, $n>`.
///
/// `embedded-io-async`'s `Read::read` / `Write::write` are async-fn-in-trait
/// methods whose returned futures are **not** `Send`-bounded. A generic blanket
/// `impl<R, W> SessionTransport for EmbeddedLeg<R, W, N>` therefore cannot
/// satisfy [`SessionTransport`]'s `+ Send` constraint without the unstable
/// `return_type_notation` feature. By emitting the impl with *concrete*
/// `$reader` / `$writer` types, the compiler sees the HAL's actual future at
/// the use site and can prove `Send` directly.
///
/// Downstream HAL adapters call this once per `(reader, writer, N)` triple
/// they expose:
///
/// ```ignore
/// use phantom_core::impl_embedded_session_transport;
/// impl_embedded_session_transport!(MyUartRx, MyUartTx, 1024);
/// ```
///
/// [`SessionTransport`]: crate::transport::session_transport::SessionTransport
#[macro_export]
macro_rules! impl_embedded_session_transport {
    ($reader:ty, $writer:ty, $n:expr) => {
        impl $crate::transport::session_transport::SessionTransport
            for $crate::transport::legs::embedded::EmbeddedLeg<$reader, $writer, $n>
        {
            fn send_bytes(
                &self,
                data: &[u8],
            ) -> impl core::future::Future<Output = Result<(), $crate::errors::CoreError>> + Send
            {
                self.send_frame(data)
            }
            fn recv_bytes(
                &self,
            ) -> impl core::future::Future<
                Output = Result<bytes::Bytes, $crate::errors::CoreError>,
            > + Send {
                self.recv_frame()
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::session_transport::SessionTransport;
    use core::convert::Infallible;
    use std::collections::VecDeque;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::{Mutex as TokioMutex, Notify};

    // Install the `SessionTransport` impl for the test mock pair. Lives inside
    // the test module so the macro's `+ Send` future bound is genuinely
    // exercised on the `MockReader` / `MockWriter` future types; if either
    // were `!Send`, this invocation would fail to compile.
    crate::impl_embedded_session_transport!(MockReader, MockWriter, 1024);

    // ── Mock duplex over `embedded-io-async` ────────────────────────────
    //
    // One-direction byte pipe shared between paired halves. `duplex_pair`
    // returns two `(MockReader, MockWriter)` duplexes cross-connected:
    // A_writer's bytes appear in B_reader's stream, and vice versa.

    struct Pipe {
        buf: VecDeque<u8>,
        closed: bool,
    }

    struct MockReader {
        read_from: Arc<TokioMutex<Pipe>>,
        read_notify: Arc<Notify>,
        max_read: usize,
    }

    struct MockWriter {
        write_to: Arc<TokioMutex<Pipe>>,
        write_notify: Arc<Notify>,
    }

    fn duplex_pair() -> ((MockReader, MockWriter), (MockReader, MockWriter)) {
        duplex_pair_with_chunk(usize::MAX)
    }

    fn duplex_pair_with_chunk(
        max_read: usize,
    ) -> ((MockReader, MockWriter), (MockReader, MockWriter)) {
        let ab = Arc::new(TokioMutex::new(Pipe {
            buf: VecDeque::new(),
            closed: false,
        }));
        let ba = Arc::new(TokioMutex::new(Pipe {
            buf: VecDeque::new(),
            closed: false,
        }));
        let n_ab = Arc::new(Notify::new());
        let n_ba = Arc::new(Notify::new());
        let a = (
            MockReader {
                read_from: ba.clone(),
                read_notify: n_ba.clone(),
                max_read,
            },
            MockWriter {
                write_to: ab.clone(),
                write_notify: n_ab.clone(),
            },
        );
        let b = (
            MockReader {
                read_from: ab,
                read_notify: n_ab,
                max_read,
            },
            MockWriter {
                write_to: ba,
                write_notify: n_ba,
            },
        );
        (a, b)
    }

    impl embedded_io_async::ErrorType for MockReader {
        type Error = Infallible;
    }
    impl embedded_io_async::ErrorType for MockWriter {
        type Error = Infallible;
    }

    impl Read for MockReader {
        async fn read(&mut self, out: &mut [u8]) -> Result<usize, Infallible> {
            if out.is_empty() {
                return Ok(0);
            }
            loop {
                // Arm a Notified BEFORE the lock+check, so any notify between
                // releasing the lock and awaiting the wakeup is not lost.
                let notified = self.read_notify.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                {
                    let mut p = self.read_from.lock().await;
                    if !p.buf.is_empty() {
                        let n = out.len().min(p.buf.len()).min(self.max_read);
                        for slot in out.iter_mut().take(n) {
                            *slot = p.buf.pop_front().expect("checked non-empty");
                        }
                        return Ok(n);
                    }
                    if p.closed {
                        return Ok(0);
                    }
                }
                notified.await;
            }
        }
    }

    impl Write for MockWriter {
        async fn write(&mut self, data: &[u8]) -> Result<usize, Infallible> {
            let mut p = self.write_to.lock().await;
            p.buf.extend(data.iter().copied());
            drop(p);
            self.write_notify.notify_waiters();
            Ok(data.len())
        }
        // `flush` defaults to `Ok(())` — keep the default.
    }

    // ── Tests ───────────────────────────────────────────────────────────

    /// `send_frame` writes the 4-byte big-endian length prefix followed by
    /// the payload, byte-identical to `TcpSessionTransport`'s wire format.
    #[tokio::test]
    async fn send_frame_writes_length_prefixed_payload() {
        let ((a_r, a_w), (mut b_r, _b_w)) = duplex_pair();
        let leg: EmbeddedLeg<MockReader, MockWriter, 1024> = EmbeddedLeg::new(a_r, a_w);

        leg.send_frame(b"hello").await.expect("send_frame");

        let mut buf = vec![0u8; 4 + 5];
        tokio::time::timeout(Duration::from_secs(1), b_r.read_exact(&mut buf))
            .await
            .expect("peer read should not hang")
            .expect("peer read_exact");

        assert_eq!(&buf[..4], &[0x00, 0x00, 0x00, 0x05], "length prefix");
        assert_eq!(&buf[4..], b"hello", "payload");
    }

    /// `recv_frame` reads a 4-byte big-endian length prefix and returns the
    /// payload as `Bytes`.
    #[tokio::test]
    async fn recv_frame_reads_length_prefixed_payload() {
        let ((a_r, a_w), (_b_r, mut b_w)) = duplex_pair();
        let leg: EmbeddedLeg<MockReader, MockWriter, 1024> = EmbeddedLeg::new(a_r, a_w);

        b_w.write_all(&[0x00, 0x00, 0x00, 0x05]).await.unwrap();
        b_w.write_all(b"world").await.unwrap();

        let frame = tokio::time::timeout(Duration::from_secs(1), leg.recv_frame())
            .await
            .expect("recv should not hang")
            .expect("recv_frame");

        assert_eq!(&frame[..], b"world");
    }

    /// Even when the underlying byte stream hands out one byte at a time
    /// (worst-case UART with a 1-byte FIFO), `recv_frame` must drain
    /// `HEADER_LEN + payload` bytes via the internal `read_exact` loop and
    /// reassemble the original frame.
    #[tokio::test]
    async fn recv_frame_reassembles_under_adversarial_chunking() {
        let ((a_r, a_w), (_b_r, mut b_w)) = duplex_pair_with_chunk(1);
        let leg: EmbeddedLeg<MockReader, MockWriter, 1024> = EmbeddedLeg::new(a_r, a_w);

        // Spawn a writer that dribbles the header + payload one byte at a
        // time, with a yield in between so the receiver gets a chance to
        // observe each step.
        let writer = tokio::spawn(async move {
            for &b in &[0x00, 0x00, 0x00, 0x05] {
                b_w.write_all(&[b]).await.expect("write header byte");
                tokio::task::yield_now().await;
            }
            for &b in b"abcde" {
                b_w.write_all(&[b]).await.expect("write payload byte");
                tokio::task::yield_now().await;
            }
        });

        let frame = tokio::time::timeout(Duration::from_secs(1), leg.recv_frame())
            .await
            .expect("recv should not hang under 1-byte chunking")
            .expect("recv_frame");

        writer.await.expect("writer task");
        assert_eq!(&frame[..], b"abcde");
    }

    /// A header announcing a length that exceeds the leg's buffer capacity
    /// `N` must be rejected at the framing layer **before** any payload bytes
    /// are pulled off the wire. This guards a remote peer (or attacker) from
    /// forcing an `N`-bounded receiver to read megabytes.
    #[tokio::test]
    async fn recv_frame_rejects_oversized_header() {
        // N = 8, peer claims a 16-byte payload and writes no payload bytes.
        // If the implementation tried to drain the announced payload, the
        // recv would hang and the timeout would fire instead of an error.
        let ((a_r, a_w), (_b_r, mut b_w)) = duplex_pair();
        let leg: EmbeddedLeg<MockReader, MockWriter, 8> = EmbeddedLeg::new(a_r, a_w);

        b_w.write_all(&[0x00, 0x00, 0x00, 0x10])
            .await
            .expect("write bogus header");
        // Deliberately no payload bytes follow.

        let err = tokio::time::timeout(Duration::from_secs(1), leg.recv_frame())
            .await
            .expect("recv should error fast, not hang on payload");
        match err {
            Err(CoreError::NetworkError(msg)) => {
                assert!(
                    msg.contains("framing"),
                    "expected framing error, got: {msg}"
                );
            }
            other => panic!("expected NetworkError(framing), got {other:?}"),
        }
    }

    /// If the peer closes the pipe mid-header (fewer than 4 bytes delivered),
    /// `read_exact` returns `UnexpectedEof`, which `recv_frame` maps to a
    /// `NetworkError("read header")`. Pinning this prevents a silent stall
    /// or a misleading "read payload" error from a future refactor.
    #[tokio::test]
    async fn recv_frame_returns_error_on_eof_mid_header() {
        let ((a_r, a_w), (_b_r, b_w)) = duplex_pair();
        let leg: EmbeddedLeg<MockReader, MockWriter, 1024> = EmbeddedLeg::new(a_r, a_w);

        // Reach into the peer-side `MockWriter` to push 2 header bytes, then
        // mark the pipe closed and wake the reader.
        let target = b_w.write_to.clone();
        let notify = b_w.write_notify.clone();
        {
            let mut p = target.lock().await;
            p.buf.extend([0x00u8, 0x00]);
            p.closed = true;
        }
        notify.notify_waiters();

        let err = tokio::time::timeout(Duration::from_secs(1), leg.recv_frame())
            .await
            .expect("recv should error fast on EOF");
        match err {
            Err(CoreError::NetworkError(msg)) => {
                assert!(
                    msg.contains("read header"),
                    "expected `read header` in error msg, got: {msg}"
                );
            }
            other => panic!("expected NetworkError(read header), got {other:?}"),
        }
    }

    /// `send_frame` and `recv_frame` take distinct `Mutex`es (`tx` vs `rx`),
    /// so a send on one side and a recv on the other can race without one
    /// blocking the other. Spawning both concurrently and asserting both
    /// finish within a 1-second window confirms the lock-split design.
    #[tokio::test]
    async fn send_recv_run_concurrently_without_blocking() {
        let ((a_r, a_w), (b_r, b_w)) = duplex_pair();
        let leg_a: Arc<EmbeddedLeg<MockReader, MockWriter, 1024>> =
            Arc::new(EmbeddedLeg::new(a_r, a_w));
        let leg_b: Arc<EmbeddedLeg<MockReader, MockWriter, 1024>> =
            Arc::new(EmbeddedLeg::new(b_r, b_w));

        let leg_a_send = Arc::clone(&leg_a);
        let send = tokio::spawn(async move { leg_a_send.send_frame(b"ping").await });
        let leg_b_recv = Arc::clone(&leg_b);
        let recv = tokio::spawn(async move { leg_b_recv.recv_frame().await });

        tokio::time::timeout(Duration::from_secs(1), async {
            send.await.expect("send task").expect("send_frame result");
            let frame = recv.await.expect("recv task").expect("recv_frame result");
            assert_eq!(&frame[..], b"ping");
        })
        .await
        .expect("concurrent send+recv should complete within 1s");
    }

    /// Round-trip a payload through the `SessionTransport` trait surface
    /// (`send_bytes` / `recv_bytes`). This is the proof that the
    /// `impl_embedded_session_transport!` macro invocation above actually
    /// produces a usable impl — without it, the `.send_bytes` and
    /// `.recv_bytes` calls would not resolve.
    #[tokio::test]
    async fn session_transport_round_trip() {
        let ((a_r, a_w), (b_r, b_w)) = duplex_pair();
        let leg_a: EmbeddedLeg<MockReader, MockWriter, 1024> = EmbeddedLeg::new(a_r, a_w);
        let leg_b: EmbeddedLeg<MockReader, MockWriter, 1024> = EmbeddedLeg::new(b_r, b_w);

        tokio::time::timeout(Duration::from_secs(1), async {
            <EmbeddedLeg<MockReader, MockWriter, 1024> as SessionTransport>::send_bytes(
                &leg_a,
                b"hello-trait",
            )
            .await
            .expect("send_bytes");
            let frame =
                <EmbeddedLeg<MockReader, MockWriter, 1024> as SessionTransport>::recv_bytes(&leg_b)
                    .await
                    .expect("recv_bytes");
            assert_eq!(&frame[..], b"hello-trait");
        })
        .await
        .expect("trait round-trip should complete within 1s");
    }

    // ── End-to-end handshake mirror (Phase 3.4.6 deferred e2e) ──────────
    //
    // Mirrors the canonical `test_phantom_session_handshake_via_transport`
    // (in `crate::api::session::tests`) but swaps `ChannelTransport::pair()`
    // for two `EmbeddedLeg<MockReader, MockWriter, 1024>` instances cross-
    // connected via `duplex_pair()`. The decrypt / encrypt helpers are
    // duplicated locally rather than promoted — keeps file-overlap surface
    // at zero so parallel agents in adjacent modules can't conflict.

    use crate::api::session::{ConnectionState, PhantomSession};
    use crate::transport::handshake::{ClientHello, HandshakeResponse, HandshakeServer};
    use crate::transport::types::{
        PacketFlags, PacketFlagsV2, PacketHeader, PacketHeaderV2, PhantomPacketV1, PhantomPacketV2,
        SessionId, StreamId as TransportStreamId, VersionedPacket,
    };

    /// Decrypt an incoming encrypted frame on the test server side.
    /// Wire-version-aware (V1 or V2). Local duplicate of the helper in
    /// `api::session::tests` — see module comment above.
    fn decrypt_incoming_local(
        server_session: &crate::transport::session::Session,
        bytes: &[u8],
    ) -> Vec<u8> {
        let versioned = alkahest::deserialize::<VersionedPacket, VersionedPacket>(bytes)
            .expect("deserialize VersionedPacket");
        match versioned {
            VersionedPacket::V1(pkt) => {
                assert!(
                    pkt.header.flags.contains(PacketFlags::ENCRYPTED),
                    "expected ENCRYPTED flag on V1 application data"
                );
                server_session
                    .decrypt_packet(&pkt.header, &pkt.payload)
                    .expect("decrypt V1 application data")
            }
            VersionedPacket::V2(pkt) => {
                assert!(
                    pkt.header.flags.contains(PacketFlagsV2::ENCRYPTED),
                    "expected ENCRYPTED flag on V2 application data"
                );
                server_session
                    .decrypt_packet_v2(&pkt.header, &pkt.payload)
                    .expect("decrypt V2 application data")
            }
        }
    }

    /// Build an encrypted reply frame from the test server side.
    /// Wire-version-aware. Local duplicate of the helper in
    /// `api::session::tests` — see module comment above.
    fn encrypt_outgoing_local(
        server_session: &crate::transport::session::Session,
        session_id: SessionId,
        stream_id: TransportStreamId,
        sequence: u32,
        payload: &[u8],
    ) -> Vec<u8> {
        if server_session.wire_version() == 2 {
            let flag_bits = PacketFlagsV2::RELIABLE | PacketFlagsV2::ENCRYPTED;
            let header = PacketHeaderV2::new(
                session_id,
                stream_id,
                sequence,
                PacketFlagsV2::new(flag_bits),
            )
            .with_epoch(server_session.current_epoch());
            let ct = server_session
                .encrypt_packet_v2(&header, payload)
                .expect("encrypt V2 reply");
            let packet = PhantomPacketV2::new(header, ct).into_versioned();
            let mut buf = Vec::new();
            let (size, _) = alkahest::serialize_to_vec::<VersionedPacket, _>(&packet, &mut buf);
            buf[..size].to_vec()
        } else {
            let mut flags = PacketFlags::new(PacketFlags::RELIABLE);
            flags.set(PacketFlags::ENCRYPTED);
            let header = PacketHeader::new(session_id, stream_id, sequence, flags);
            let ct = server_session
                .encrypt_packet(&header, payload)
                .expect("encrypt V1 reply");
            let packet = PhantomPacketV1::new(header, ct).into_versioned();
            let mut buf = Vec::new();
            let (size, _) = alkahest::serialize_to_vec::<VersionedPacket, _>(&packet, &mut buf);
            buf[..size].to_vec()
        }
    }

    /// `MockWriter` wrapper that tees every byte through to a side recorder
    /// before forwarding to the underlying pipe. Used to sniff the wire and
    /// assert plaintext like `b"early-data"` never appears in the framed
    /// bytes the client writes.
    struct TeeWriter {
        inner: MockWriter,
        recorder: Arc<TokioMutex<Vec<u8>>>,
    }

    impl embedded_io_async::ErrorType for TeeWriter {
        type Error = Infallible;
    }

    impl Write for TeeWriter {
        async fn write(&mut self, data: &[u8]) -> Result<usize, Infallible> {
            self.recorder.lock().await.extend_from_slice(data);
            self.inner.write(data).await
        }
    }

    // The macro generates the `SessionTransport` impl for this concrete
    // `(MockReader, TeeWriter, 16384)` triple — same `+ Send` future bound
    // as the production embedded triple. A real PQ ClientHello / ServerHello
    // (ML-KEM-768 1184-byte ek + ML-DSA-65 ~3.3 KiB signature + envelope)
    // exceeds the 1024-byte capacity used by the unit framing tests above,
    // so the e2e test uses a 16 KiB buffer.
    crate::impl_embedded_session_transport!(MockReader, TeeWriter, 16384);
    crate::impl_embedded_session_transport!(MockReader, MockWriter, 16384);

    /// End-to-end handshake + encrypted data exchange over `EmbeddedLeg`.
    /// Mirrors `test_phantom_session_handshake_via_transport` from
    /// `api::session::tests`, with a `TeeWriter` on the client side so the
    /// negative assertion (plaintext never on the wire) can read the actual
    /// bytes the client emitted.
    #[tokio::test]
    async fn test_phantom_session_handshake_via_embedded_leg() {
        // Client leg uses TeeWriter to record every transmitted byte.
        // Server leg is a plain MockReader/MockWriter pair.
        let ((client_r, client_w_inner), (server_r, server_w)) = duplex_pair();
        let client_wire_recorder: Arc<TokioMutex<Vec<u8>>> = Arc::new(TokioMutex::new(Vec::new()));
        let client_w = TeeWriter {
            inner: client_w_inner,
            recorder: Arc::clone(&client_wire_recorder),
        };

        let client_leg: EmbeddedLeg<MockReader, TeeWriter, 16384> =
            EmbeddedLeg::new(client_r, client_w);
        let server_leg: EmbeddedLeg<MockReader, MockWriter, 16384> =
            EmbeddedLeg::new(server_r, server_w);

        let server_hs = HandshakeServer::new().expect("HandshakeServer::new");
        let server_pinned_key = server_hs.verifying_key().clone();

        // Spawn the client session — kicks off the background handshake.
        let session = PhantomSession::connect_with_transport(
            "test-server:9000",
            client_leg,
            server_pinned_key,
        );

        // Queue an early message before the handshake completes.
        session
            .send(b"early-data".to_vec())
            .await
            .expect("queue early-data");

        // Server responder task: handles ClientHello (+ optional retry),
        // emits ServerHello, receives the flushed early-data + a post-
        // handshake message, then sends an encrypted reply.
        let server_handle = tokio::spawn(async move {
            let client_ip = "127.0.0.1".parse().expect("parse loopback IP");

            // 1. Receive the first ClientHello. Default client offers V12.
            let client_hello_bytes =
                tokio::time::timeout(Duration::from_secs(5), server_leg.recv_frame())
                    .await
                    .expect("recv ClientHello within 5s")
                    .expect("recv ClientHello frame");
            let client_hello = borsh::from_slice::<ClientHello>(&client_hello_bytes)
                .expect("deserialize ClientHello");

            // 2. Process — may retry with a cookie/PoW challenge.
            let server_session = loop {
                let response = server_hs.process_client_hello(&client_hello, 0, client_ip);
                match response {
                    HandshakeResponse::Retry(retry) => {
                        let retry_bytes =
                            borsh::to_vec(&retry).expect("serialize HelloRetryRequest");
                        tokio::time::timeout(
                            Duration::from_secs(5),
                            server_leg.send_frame(&retry_bytes),
                        )
                        .await
                        .expect("send retry within 5s")
                        .expect("send retry frame");

                        let next_bytes =
                            tokio::time::timeout(Duration::from_secs(5), server_leg.recv_frame())
                                .await
                                .expect("recv retried ClientHello within 5s")
                                .expect("recv retried ClientHello frame");
                        let next_hello = borsh::from_slice::<ClientHello>(&next_bytes)
                            .expect("deserialize retried ClientHello");
                        let resp2 = server_hs.process_client_hello(&next_hello, 0, client_ip);
                        match resp2 {
                            HandshakeResponse::Success(server_hello, session, _) => {
                                let server_hello_bytes =
                                    borsh::to_vec(&server_hello).expect("serialize ServerHello");
                                tokio::time::timeout(
                                    Duration::from_secs(5),
                                    server_leg.send_frame(&server_hello_bytes),
                                )
                                .await
                                .expect("send ServerHello within 5s")
                                .expect("send ServerHello frame");
                                break session;
                            }
                            other => panic!("expected success after retry, got {other:?}"),
                        }
                    }
                    HandshakeResponse::Success(server_hello, session, _) => {
                        let server_hello_bytes =
                            borsh::to_vec(&server_hello).expect("serialize ServerHello");
                        tokio::time::timeout(
                            Duration::from_secs(5),
                            server_leg.send_frame(&server_hello_bytes),
                        )
                        .await
                        .expect("send ServerHello within 5s")
                        .expect("send ServerHello frame");
                        break session;
                    }
                    HandshakeResponse::Fail(e) => panic!("handshake failed: {e:?}"),
                }
            };

            let session_id = *server_session.id();

            // 3. Receive the flushed early-data frame and decrypt it.
            let early_frame = tokio::time::timeout(Duration::from_secs(5), server_leg.recv_frame())
                .await
                .expect("recv early-data within 5s")
                .expect("recv early-data frame");
            let early_plain = decrypt_incoming_local(&server_session, &early_frame);
            assert_eq!(early_plain, b"early-data");

            // 4. Receive the post-handshake message.
            let post_frame = tokio::time::timeout(Duration::from_secs(5), server_leg.recv_frame())
                .await
                .expect("recv after-handshake within 5s")
                .expect("recv after-handshake frame");
            let post_plain = decrypt_incoming_local(&server_session, &post_frame);
            assert_eq!(post_plain, b"after-handshake");

            // 5. Send an encrypted reply.
            let reply = encrypt_outgoing_local(&server_session, session_id, 1, 1, b"server-reply");
            tokio::time::timeout(Duration::from_secs(5), server_leg.send_frame(&reply))
                .await
                .expect("send reply within 5s")
                .expect("send reply frame");
        });

        // Give the handshake time to progress to Connected.
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(session.connection_state(), ConnectionState::Connected);

        // Send the post-handshake message.
        session
            .send(b"after-handshake".to_vec())
            .await
            .expect("send after-handshake");

        // Receive the (decrypted) server reply.
        let reply = tokio::time::timeout(Duration::from_secs(5), session.recv())
            .await
            .expect("recv reply within 5s")
            .expect("recv server-reply");
        assert_eq!(reply, b"server-reply");

        tokio::time::timeout(Duration::from_secs(5), server_handle)
            .await
            .expect("server task within 5s")
            .expect("server task joined");
        session.disconnect().await.expect("close session");

        // Negative assertion: plaintext like "early-data" / "after-handshake"
        // must never appear in the bytes the client emitted on the wire.
        // Mirrors the canonical test's confidentiality check.
        let wire = client_wire_recorder.lock().await;
        assert!(
            !wire
                .windows(b"early-data".len())
                .any(|w| w == b"early-data"),
            "plaintext early-data leaked onto the embedded wire"
        );
        assert!(
            !wire
                .windows(b"after-handshake".len())
                .any(|w| w == b"after-handshake"),
            "plaintext after-handshake leaked onto the embedded wire"
        );
    }
}
