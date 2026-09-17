//! `MimicTlsLeg` — the TLS-over-TCP active-mimicry `SessionTransport`.
//!
//! Ties the record layer (`super::record`) and the handshake theater
//! (`super::theater`) together: `connect` / `accept` run the one-time synthetic
//! TLS 1.3 prelude, after which `send_bytes` / `recv_bytes` carry Phantom messages
//! inside TLS ApplicationData records. The outer TLS is anti-DPI obfuscation only —
//! see the module head in [`super`].
//!
//! Writes after the prelude follow the same rule as `TcpSessionTransport`, for the
//! same reason — this is a TCP socket, and a peer that stops reading it would
//! otherwise hold the session's pump: a write that makes no progress for
//! [`MimicTlsLeg::DEFAULT_WRITE_STALL_TIMEOUT`] (adjustable with
//! [`MimicTlsLeg::with_write_stall_timeout`]) fails with
//! [`CoreError::Timeout`](crate::errors::CoreError::Timeout), every later write is
//! refused without touching the socket, and the connection is set to end with a
//! reset. The prelude is not affected: its writes already sit under the prelude's
//! own deadline.

use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::time::Duration;

use super::record::{frame_message, RecordDeframer, CT_HANDSHAKE};
use super::server_hello::parse_client_hello;
use super::{client_hello, theater};
use crate::crypto::rng::OsRng;
use crate::errors::CoreError;
use crate::transport::session_transport::{FramePhase, SessionTransport};
use crate::transport::write_stall::{
    reset_on_close, write_all_making_progress, WriteFailure, DEFAULT_WRITE_STALL_TIMEOUT,
};

/// Send-side cap, mirroring `TcpSessionTransport`'s steady-state cap — a single
/// `send_bytes` larger than this is rejected (the peer's de-framer caps the inner
/// message at the same value, so a larger send could never be delivered anyway).
const SEND_CAP: usize = 4 * 1024 * 1024;

/// Per-record socket read granularity during the prelude / data phases.
const READ_SCRATCH: usize = 16 * 1024;

/// Total wall-clock budget for the whole prelude. A stalled or byte-trickling peer
/// is abandoned rather than hanging the task; on the server it also bounds the
/// black-hole hold for an unauthenticated probe.
const PRELUDE_DEADLINE: Duration = Duration::from_secs(10);

/// How old (months) the parroted ClientHello profile may be before the client logs
/// a staleness warning — a drifted JA3/JA4 matches no live browser (threat-model R3).
const PROFILE_STALE_MONTHS: u32 = 6;

/// Warn (once per connect) if the Chrome ClientHello profile has drifted out of the
/// live-browser population. A stale template is a standalone fingerprint — worse
/// than no mimicry — so refresh `client_hello`'s profile from a real capture.
fn warn_if_profile_stale() {
    let now = time::OffsetDateTime::now_utc();
    let now_yyyymm = (now.year() as u32) * 100 + u8::from(now.month()) as u32;
    if !client_hello::profile_is_fresh(now_yyyymm, PROFILE_STALE_MONTHS) {
        log::warn!(
            "MimicTlsLeg: the Chrome ClientHello profile (captured {}) is stale; refresh it \
             from a live browser capture — a drifted JA3/JA4 is itself a fingerprint",
            client_hello::PROFILE_CAPTURED
        );
    }
}

/// Operator-set, per-connection mimicry configuration.
#[derive(Clone, Debug)]
pub struct MimicConfig {
    /// The cover SNI presented in the ClientHello. **Required and rotatable** — a
    /// single network-wide default SNI is itself a blocklist key (threat-model R5). The
    /// operator supplies a plausible cover domain, ideally rotated per connection
    /// and consistent with the server's IP/AS.
    pub sni: String,
}

impl MimicConfig {
    pub fn new(sni: impl Into<String>) -> Self {
        Self { sni: sni.into() }
    }
}

struct ReadState {
    reader: OwnedReadHalf,
    deframer: RecordDeframer,
    scratch: Vec<u8>,
}

/// A TLS-mimicry transport over a single TCP connection. The synthetic handshake
/// runs once in [`connect`](Self::connect) / [`accept`](Self::accept); afterwards
/// the leg is a plain message pipe.
pub struct MimicTlsLeg {
    write_half: Mutex<OwnedWriteHalf>,
    read: Mutex<ReadState>,
    /// 0 = handshake phase, 1 = established (drives the de-framer's inner cap).
    phase: AtomicU8,
    /// How long one write may wait without the socket accepting a byte.
    write_stall_timeout: Duration,
    /// Set by the first write that stalls out, and never cleared: that write may
    /// have left a record cut part-way through on the wire, so nothing may follow it.
    write_stalled: AtomicBool,
}

fn net_err(e: std::io::Error) -> CoreError {
    CoreError::NetworkError(e.to_string())
}

/// Read one complete TLS record of `expected_type` from the socket, growing `buf`
/// as needed. Returns the record's fragment bytes. A wrong type / oversized record
/// is a typed error (the caller — the server — converts it into the black-hole).
async fn read_one_record(
    reader: &mut OwnedReadHalf,
    buf: &mut BytesMut,
    expected_type: u8,
) -> Result<Bytes, CoreError> {
    let mut scratch = [0u8; 4096];
    loop {
        if let Some(frag) = theater::take_record(buf, expected_type)? {
            return Ok(frag);
        }
        let n = reader.read(&mut scratch).await.map_err(net_err)?;
        if n == 0 {
            return Err(CoreError::ConnectionClosed);
        }
        buf.extend_from_slice(&scratch[..n]);
    }
}

impl MimicTlsLeg {
    fn from_halves(
        reader: OwnedReadHalf,
        writer: OwnedWriteHalf,
        deframer: RecordDeframer,
    ) -> Self {
        Self {
            write_half: Mutex::new(writer),
            read: Mutex::new(ReadState {
                reader,
                deframer,
                scratch: vec![0u8; READ_SCRATCH],
            }),
            phase: AtomicU8::new(0),
            write_stall_timeout: Self::DEFAULT_WRITE_STALL_TIMEOUT,
            write_stalled: AtomicBool::new(false),
        }
    }

    /// How long a write after the prelude may go without the socket accepting a
    /// byte before the leg gives up on its peer, unless
    /// [`with_write_stall_timeout`](Self::with_write_stall_timeout) says otherwise.
    /// The same thirty seconds as `TcpSessionTransport`.
    pub const DEFAULT_WRITE_STALL_TIMEOUT: Duration = DEFAULT_WRITE_STALL_TIMEOUT;

    /// Replace the write-stall deadline: how long a single write may wait without
    /// the socket accepting a byte before `send_bytes` fails with
    /// [`CoreError::Timeout`] and the leg gives up on its peer. The clock restarts
    /// with every byte accepted — it bounds how long the peer may stop reading,
    /// not how slowly it may read.
    pub fn with_write_stall_timeout(mut self, timeout: Duration) -> Self {
        self.write_stall_timeout = timeout;
        self
    }

    /// Client side: open the TLS-mimic prelude over `stream`, then return a leg
    /// ready for the inner Phantom handshake. Sends a synthetic ClientHello,
    /// consumes the server flight, sends the client Finished theater.
    pub async fn connect(stream: TcpStream, config: &MimicConfig) -> Result<Self, CoreError> {
        warn_if_profile_stale();
        let _ = stream.set_nodelay(true);
        let (mut reader, mut writer) = stream.into_split();
        let rng = OsRng;

        let fut = async {
            // (1) ClientHello.
            let ch = theater::client_hello_record(&config.sni, &rng)?;
            writer.write_all(&ch).await.map_err(net_err)?;
            writer.flush().await.map_err(net_err)?;

            // (2) consume the four server-flight records in order.
            let mut buf = BytesMut::new();
            for &t in &theater::SERVER_FLIGHT_TYPES {
                read_one_record(&mut reader, &mut buf, t).await?;
            }

            // (3) ChangeCipherSpec + opaque Finished.
            let fin = theater::client_finished_flight(&rng)?;
            writer.write_all(&fin).await.map_err(net_err)?;
            writer.flush().await.map_err(net_err)?;

            Ok::<BytesMut, CoreError>(buf)
        };

        let leftover = tokio::time::timeout(PRELUDE_DEADLINE, fut)
            .await
            .map_err(|_| CoreError::Timeout)??;

        // Any bytes already read past the prelude seed the data de-framer.
        let mut deframer = RecordDeframer::new();
        deframer.push(&leftover);
        Ok(Self::from_halves(reader, writer, deframer))
    }

    /// Server side: accept the TLS-mimic prelude over `stream`. Reads + parses the
    /// ClientHello, answers with a self-consistent ServerHello flight, consumes the
    /// client Finished theater. On any prelude error (a probe / garbage), holds the
    /// connection open and silent until the prelude deadline, then drops it — the
    /// black-hole posture (no eager RST / alert that would distinguish the mimic).
    pub async fn accept(stream: TcpStream, config: &MimicConfig) -> Result<Self, CoreError> {
        let started = std::time::Instant::now();
        let _ = stream.set_nodelay(true);
        let _ = config; // server does not present an SNI; kept for symmetry/future use
        let (mut reader, mut writer) = stream.into_split();
        let rng = OsRng;

        let fut = async {
            // (1) read + parse the ClientHello.
            let mut buf = BytesMut::new();
            let ch = read_one_record(&mut reader, &mut buf, CT_HANDSHAKE).await?;
            let parsed = parse_client_hello(&ch)?;

            // (2) answer with the synthetic server flight.
            let flight = theater::server_flight(&parsed, &rng)?;
            writer.write_all(&flight).await.map_err(net_err)?;
            writer.flush().await.map_err(net_err)?;

            // (3) consume the client's ChangeCipherSpec + Finished.
            for &t in &theater::CLIENT_FINISHED_TYPES {
                read_one_record(&mut reader, &mut buf, t).await?;
            }
            Ok::<BytesMut, CoreError>(buf)
        };

        match tokio::time::timeout(PRELUDE_DEADLINE, fut).await {
            Ok(Ok(leftover)) => {
                let mut deframer = RecordDeframer::new();
                deframer.push(&leftover);
                Ok(Self::from_halves(reader, writer, deframer))
            }
            // Prelude failed or timed out: black-hole. Drain silently until the same
            // wall-clock deadline measured from connection start (NOT a fresh
            // window), so the total time-to-drop is ~PRELUDE_DEADLINE regardless of
            // WHERE the prelude failed — a fast garbage-CH reject and a slow trickle
            // both hold ~10 s, not 10 s vs 20 s. That constant timing is the point:
            // an unauthenticated probe sees a server that went idle after the same
            // interval, not a distinguishable error. (The best posture achievable
            // against a probe; active probing remains a residual the threat model
            // records in its section 6.1.)
            Ok(Err(_)) | Err(_) => {
                let remaining = PRELUDE_DEADLINE.saturating_sub(started.elapsed());
                black_hole(reader, remaining).await;
                Err(CoreError::ConnectionClosed)
            }
        }
    }

    fn current_phase(&self) -> FramePhase {
        match self.phase.load(Ordering::Relaxed) {
            0 => FramePhase::Handshake,
            _ => FramePhase::Established,
        }
    }
}

/// Drain the read half silently for `remaining` (the budget left from the
/// connection's prelude deadline), then return (dropping the socket). No bytes are
/// ever written — the connection simply goes idle and closes, the black-hole
/// posture for an unauthenticated probe. `remaining` is the *residual* budget so
/// the total hold is constant regardless of when the prelude failed.
async fn black_hole(mut reader: OwnedReadHalf, remaining: Duration) {
    let mut scratch = [0u8; 4096];
    let drain = async {
        // Read-and-discard until the peer closes; the outer timeout bounds it.
        loop {
            match reader.read(&mut scratch).await {
                Ok(0) | Err(_) => break,
                Ok(_) => continue,
            }
        }
    };
    let _ = tokio::time::timeout(remaining, drain).await;
}

impl SessionTransport for MimicTlsLeg {
    async fn send_bytes(&self, data: &[u8]) -> Result<(), CoreError> {
        if data.len() > SEND_CAP {
            return Err(CoreError::NetworkError(format!(
                "frame too large: {} > {}",
                data.len(),
                SEND_CAP
            )));
        }
        if self.write_stalled.load(Ordering::Acquire) {
            return Err(CoreError::Timeout);
        }
        let records = frame_message(data)?;
        let mut w = self.write_half.lock().await;
        // Checked again under the lock: the write this one queued behind may be the
        // one that stalled, and what it left on the wire is not a record boundary.
        if self.write_stalled.load(Ordering::Acquire) {
            return Err(CoreError::Timeout);
        }
        match write_all_making_progress(&mut *w, &[&records], self.write_stall_timeout).await {
            Ok(()) => Ok(()),
            Err(WriteFailure::Io(e)) => Err(net_err(e)),
            Err(WriteFailure::Stalled) => {
                self.write_stalled.store(true, Ordering::Release);
                reset_on_close((*w).as_ref());
                log::warn!(
                    "MimicTlsLeg: the peer accepted no bytes for {:?}; giving up on it",
                    self.write_stall_timeout
                );
                Err(CoreError::Timeout)
            }
        }
    }

    async fn recv_bytes(&self) -> Result<Bytes, CoreError> {
        let phase = self.current_phase();
        let mut guard = self.read.lock().await;
        let st = &mut *guard;
        st.deframer.set_phase(phase);
        loop {
            if let Some(msg) = st.deframer.next_message()? {
                return Ok(msg);
            }
            let n = st.reader.read(&mut st.scratch).await.map_err(net_err)?;
            if n == 0 {
                return Err(CoreError::ConnectionClosed);
            }
            // `st.scratch` and `st.deframer` are disjoint fields; split the borrow.
            let (deframer, scratch) = (&mut st.deframer, &st.scratch);
            deframer.push(&scratch[..n]);
        }
    }

    fn set_frame_phase(&self, phase: FramePhase) {
        let v = match phase {
            FramePhase::Handshake => 0,
            FramePhase::Established => 1,
        };
        self.phase.store(v, Ordering::Relaxed);
    }
    // migrate / migrate_server / candidate methods: a TCP-substrate leaf leg
    // correctly inherits the no-op `SessionTransport` defaults (no rebind over a
    // connection-oriented socket) — like `TcpSessionTransport`.
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    /// Establish a client+server `MimicTlsLeg` pair over real TCP loopback by
    /// running both preludes concurrently.
    async fn mimic_pair() -> (MimicTlsLeg, MimicTlsLeg) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server_fut = async {
            let (stream, _) = listener.accept().await.expect("accept");
            MimicTlsLeg::accept(stream, &MimicConfig::new("server-ignored"))
                .await
                .expect("server prelude")
        };
        let client_fut = async {
            let stream = TcpStream::connect(addr).await.expect("connect");
            MimicTlsLeg::connect(stream, &MimicConfig::new("cover.example.com"))
                .await
                .expect("client prelude")
        };
        let (server, client) = tokio::join!(server_fut, client_fut);
        (client, server)
    }

    /// The synthetic prelude completes on both sides over real TCP, and messages
    /// then round-trip bidirectionally (including a > 2^14 multi-record message).
    #[tokio::test]
    #[ignore = "real TCP loopback"]
    async fn prelude_completes_and_messages_round_trip() {
        let (client, server) = mimic_pair().await;
        client.set_frame_phase(FramePhase::Established);
        server.set_frame_phase(FramePhase::Established);

        let (s, r) = tokio::join!(client.send_bytes(b"hello from client"), server.recv_bytes());
        s.expect("client send");
        assert_eq!(&r.expect("server recv")[..], b"hello from client");

        let (s, r) = tokio::join!(server.send_bytes(b"hello from server"), client.recv_bytes());
        s.expect("server send");
        assert_eq!(&r.expect("client recv")[..], b"hello from server");

        // A message larger than one TLS record must split + reassemble.
        let big = vec![0x5au8; 40_000];
        let (s, r) = tokio::join!(client.send_bytes(&big), server.recv_bytes());
        s.expect("client send big");
        assert_eq!(r.expect("server recv big").len(), big.len());
    }

    /// After the prelude, a write the peer never takes fails with `Timeout` instead of
    /// waiting forever, and nothing is written after it.
    ///
    /// Not `#[ignore]`d like the round-trip above, although it runs over real loopback
    /// too: it is the regression test for a peer holding the session's pump by not
    /// reading, and it has to run wherever the feature is tested.
    #[tokio::test]
    async fn a_write_the_peer_never_takes_fails_and_nothing_follows_it() {
        use crate::api::tcp_transport::test_support::connection_whose_far_end_never_reads;
        const STALL: Duration = Duration::from_millis(250);

        let (near, far) = connection_whose_far_end_never_reads().await;
        let server_config = MimicConfig::new("server-ignored");
        let client_config = MimicConfig::new("cover.example.com");
        let (near, far) = tokio::join!(
            MimicTlsLeg::accept(near, &server_config),
            MimicTlsLeg::connect(far, &client_config),
        );
        let near = near
            .expect("server prelude")
            .with_write_stall_timeout(STALL);
        let _far = far.expect("client prelude");
        near.set_frame_phase(FramePhase::Established);

        let outcome = tokio::time::timeout(
            Duration::from_secs(10),
            near.send_bytes(&vec![0x42_u8; 1024 * 1024]),
        )
        .await;
        assert!(
            matches!(outcome, Ok(Err(CoreError::Timeout))),
            "a write the peer never takes must fail with Timeout; got {outcome:?}"
        );
        let next = near.send_bytes(b"after the stall").await;
        assert!(
            matches!(next, Err(CoreError::Timeout)),
            "a write after a stall must be refused, not appended to a cut-off record; got \
             {next:?}"
        );
    }

    /// A peer that sends non-TLS garbage instead of a ClientHello is black-holed:
    /// `accept` errors (no usable session) rather than speaking a distinguishable
    /// alert/RST. The drain returns promptly once the peer closes.
    #[tokio::test]
    #[ignore = "real TCP loopback"]
    async fn server_black_holes_a_garbage_prelude() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server_fut = async {
            let (stream, _) = listener.accept().await.expect("accept");
            MimicTlsLeg::accept(stream, &MimicConfig::new("x")).await
        };
        let client_fut = async {
            let mut stream = TcpStream::connect(addr).await.expect("connect");
            // Not a TLS handshake record — a plain HTTP request line.
            stream
                .write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
                .await
                .expect("write garbage");
            // Hold briefly, then drop so the server's black-hole drain sees EOF.
            tokio::time::sleep(Duration::from_millis(50)).await;
        };
        let (server_res, ()) = tokio::join!(server_fut, client_fut);
        assert!(
            server_res.is_err(),
            "a garbage prelude must be black-holed (accept returns Err)"
        );
    }
}
