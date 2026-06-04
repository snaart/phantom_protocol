//! Length-prefixed `SessionTransport` over `tokio::net::TcpStream`.
//!
//! `SessionTransport` is message-oriented (returns one frame per `recv_bytes`),
//! while TCP is a stream. This adapter inserts a 4-byte big-endian length prefix
//! before each frame so the trait contract is preserved.
//!
//! Phase 2.1: the receive path keeps a single persistent `BytesMut`
//! accumulator across `recv_bytes` calls. Each frame is `split_to`-ed off
//! into an owned `Bytes` which the caller takes — zero-copy from the
//! accumulator to the returned frame, no per-packet `Vec::new` alloc.

use crate::api::session::{FramePhase, SessionTransport};
use crate::errors::CoreError;
use bytes::{Bytes, BytesMut};
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

/// Receive frame cap during the unauthenticated handshake (WIRE-001). A
/// `ClientHello` — even carrying a 16 KiB 0-RTT blob — is well under this, so an
/// oversized DECLARED frame is rejected right after the 4-byte length prefix,
/// before any body is buffered. This bounds the memory a single unauthenticated
/// peer can make the server allocate.
const HANDSHAKE_FRAME_CAP: usize = 64 * 1024; // 64 KiB

/// Receive/send frame cap once the session is established — matches the
/// application-layer delivery cap. Lowered from the historical 16 MiB.
const STEADY_STATE_FRAME_CAP: usize = 4 * 1024 * 1024; // 4 MiB

/// Initial (and shrink-target) capacity for the persistent recv accumulator.
/// Sized to a generous MTU so the typical workload never reallocates.
const RECV_BUF_INITIAL_CAPACITY: usize = 64 * 1024;

/// Incremental-read chunk: the accumulator grows by at most this per read, so a
/// peer that DECLARES a large frame but then stalls cannot make us pre-commit
/// the full declared length (WIRE-001 amplification fix).
const RECV_CHUNK: usize = 64 * 1024;

/// After a frame larger than `RECV_BUF_INITIAL_CAPACITY * SHRINK_SLACK_MULT`, the
/// accumulator is reset to baseline (LEGS-003) so one big frame does not pin a
/// large buffer for the connection's life. Steady-state ~MTU frames stay well
/// under the threshold and never pay a realloc.
const SHRINK_SLACK_MULT: usize = 4;

pub struct TcpSessionTransport {
    write_half: Mutex<tokio::net::tcp::OwnedWriteHalf>,
    /// Read half + the per-direction accumulator. Held together under
    /// one mutex so the buffer lifetime tracks the reader's exactly
    /// (Phase 2.1).
    read_half: Mutex<(tokio::net::tcp::OwnedReadHalf, BytesMut)>,
    /// Current receive frame-size cap (WIRE-001). Starts at the tight handshake
    /// cap and rises to the steady-state cap via [`set_frame_phase`].
    frame_cap: AtomicUsize,
}

impl TcpSessionTransport {
    pub fn new(stream: TcpStream) -> Self {
        let _ = stream.set_nodelay(true);
        let (r, w) = stream.into_split();
        Self {
            write_half: Mutex::new(w),
            read_half: Mutex::new((r, BytesMut::with_capacity(RECV_BUF_INITIAL_CAPACITY))),
            frame_cap: AtomicUsize::new(HANDSHAKE_FRAME_CAP),
        }
    }

    /// Current receive accumulator capacity — test-only accessor for the
    /// LEGS-003 shrink behavior.
    #[cfg(test)]
    pub(crate) async fn accum_capacity(&self) -> usize {
        self.read_half.lock().await.1.capacity()
    }
}

impl SessionTransport for TcpSessionTransport {
    async fn send_bytes(&self, data: &[u8]) -> Result<(), CoreError> {
        if data.len() > STEADY_STATE_FRAME_CAP {
            return Err(CoreError::NetworkError(format!(
                "frame too large: {} > {}",
                data.len(),
                STEADY_STATE_FRAME_CAP
            )));
        }
        let mut w = self.write_half.lock().await;
        let len = (data.len() as u32).to_be_bytes();
        w.write_all(&len)
            .await
            .map_err(|e| CoreError::NetworkError(e.to_string()))?;
        w.write_all(data)
            .await
            .map_err(|e| CoreError::NetworkError(e.to_string()))?;
        w.flush()
            .await
            .map_err(|e| CoreError::NetworkError(e.to_string()))?;
        Ok(())
    }

    async fn recv_bytes(&self) -> Result<Bytes, CoreError> {
        let cap = self.frame_cap.load(Ordering::Relaxed);
        let mut guard = self.read_half.lock().await;
        let (r, buf) = &mut *guard;

        // Read the 4-byte big-endian length prefix.
        let mut len_buf = [0u8; 4];
        r.read_exact(&mut len_buf)
            .await
            .map_err(|e| CoreError::NetworkError(e.to_string()))?;
        let len = u32::from_be_bytes(len_buf) as usize;
        // WIRE-001: reject an oversized DECLARED length up front (phase-gated
        // cap), BEFORE buffering any body bytes.
        if len > cap {
            return Err(CoreError::NetworkError(format!(
                "oversized frame from peer: {} > {}",
                len, cap
            )));
        }

        // Incremental read (WIRE-001): grow the accumulator by at most
        // `RECV_CHUNK` per read, so a peer that declares a large frame but then
        // stalls makes us commit at most one chunk — not the full declared
        // length (no 4-byte → big-alloc amplification). `read_exact` reads
        // exactly the requested bytes, so no subsequent frame leaks into `buf`.
        buf.clear();
        let mut filled = 0usize;
        while filled < len {
            let chunk = (len - filled).min(RECV_CHUNK);
            buf.resize(filled + chunk, 0);
            r.read_exact(&mut buf[filled..filled + chunk])
                .await
                .map_err(|e| CoreError::NetworkError(e.to_string()))?;
            filled += chunk;
        }

        // `split_to(len)` hands the caller an owned `BytesMut` view over the
        // frame; `freeze` makes it an immutable refcounted `Bytes`.
        let frame = buf.split_to(len).freeze();

        // LEGS-003: a single large frame must not pin a large accumulator for
        // the connection's life. After one, reset to baseline (the old large
        // allocation is reclaimed once the frozen frame is also dropped).
        if len > RECV_BUF_INITIAL_CAPACITY * SHRINK_SLACK_MULT {
            *buf = BytesMut::with_capacity(RECV_BUF_INITIAL_CAPACITY);
        }
        Ok(frame)
    }

    fn set_frame_phase(&self, phase: FramePhase) {
        let cap = match phase {
            FramePhase::Handshake => HANDSHAKE_FRAME_CAP,
            FramePhase::Established => STEADY_STATE_FRAME_CAP,
        };
        self.frame_cap.store(cap, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::{TcpListener, TcpStream};

    async fn tcp_pair() -> (TcpSessionTransport, TcpSessionTransport) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let (client, accepted) = tokio::join!(TcpStream::connect(addr), listener.accept());
        let client = client.expect("connect");
        let (server, _) = accepted.expect("accept");
        (
            TcpSessionTransport::new(client),
            TcpSessionTransport::new(server),
        )
    }

    /// **WIRE-001.** During the unauthenticated handshake phase the recv cap is
    /// tight (64 KiB): an oversized DECLARED frame is rejected right after the
    /// 4-byte prefix, before any body is buffered — no 4-byte → big-alloc
    /// amplification.
    #[tokio::test]
    async fn handshake_phase_rejects_oversized_frame() {
        let (client, server) = tcp_pair().await; // server defaults to handshake phase
        let big = vec![0u8; 100 * 1024]; // 100 KiB > 64 KiB handshake cap
        client
            .send_bytes(&big)
            .await
            .expect("send is within the 4 MiB send cap");
        let err = server
            .recv_bytes()
            .await
            .expect_err("oversized handshake-phase frame must be rejected");
        assert!(matches!(err, CoreError::NetworkError(_)));
    }

    /// After establishment the cap rises to 4 MiB, a large frame round-trips, and
    /// (LEGS-003) the accumulator is reset to baseline afterward.
    #[tokio::test]
    async fn established_phase_accepts_large_frame_and_resets_accumulator() {
        let (client, server) = tcp_pair().await;
        server.set_frame_phase(FramePhase::Established);
        let payload = vec![7u8; 1024 * 1024]; // 1 MiB, within the 4 MiB cap
        // Drive send and recv CONCURRENTLY. A 1 MiB `write_all` does not complete
        // until the peer starts draining (the kernel socket buffer is far
        // smaller than 1 MiB once it is contended — e.g. when the parallel test
        // suite saturates loopback), so doing send-then-recv sequentially on one
        // task deadlocks on TCP flow control. `join!` lets the reader drain while
        // the writer fills.
        let (send_res, recv_res) = tokio::join!(client.send_bytes(&payload), server.recv_bytes());
        send_res.expect("send 1 MiB");
        let got = recv_res.expect("recv 1 MiB");
        assert_eq!(got.len(), payload.len());
        assert_eq!(&got[..8], &payload[..8]);
        let cap = server.accum_capacity().await;
        assert!(
            cap <= RECV_BUF_INITIAL_CAPACITY * SHRINK_SLACK_MULT,
            "accumulator must reset to baseline after a large frame (LEGS-003); capacity = {cap}"
        );
        // A small follow-up frame still works.
        client.send_bytes(b"small").await.expect("send small");
        let got = server.recv_bytes().await.expect("recv small");
        assert_eq!(&got[..], b"small");
    }

    /// The send path enforces the 4 MiB steady-state cap (down from 16 MiB).
    #[tokio::test]
    async fn send_rejects_over_steady_state_cap() {
        let (client, _server) = tcp_pair().await;
        let too_big = vec![0u8; STEADY_STATE_FRAME_CAP + 1];
        assert!(client.send_bytes(&too_big).await.is_err());
    }
}
