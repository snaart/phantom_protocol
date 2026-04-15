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
//! `Send` directly. A small `macro_rules!` helper will land alongside to
//! generate the per-pair impl in one line.
//!
//! Behind the `embedded` cargo feature. no_std + alloc-clean — this module
//! only depends on `core`/`alloc`, `bytes`, `async_lock`, and `embedded-io-
//! async`.
//!
//! [`SessionTransport`]: crate::transport::session_transport::SessionTransport
//! [`framing`]: crate::transport::legs::embedded::framing

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
}
