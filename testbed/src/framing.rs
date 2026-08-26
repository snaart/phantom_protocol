//! Message framing over a Phantom session.
//!
//! ## Why this exists
//!
//! `PhantomSession::send()` is **not message-preserving**. The data pump splits
//! any payload larger than its internal chunk size (`MAX_APP_CHUNK`, 1156 B —
//! one chunk plus its packet overhead is exactly one PhantomUDP datagram) into
//! chunks and writes each as a separate reliable-stream write; the peer's
//! `recv()` then yields each chunk as its own result. A caller that sends 8 KiB
//! and expects one `recv()` of 8 KiB instead gets eight.
//!
//! That behaviour is undocumented on `send`/`recv`, and it is silent: the first
//! chunk of a structured message still parses as a valid — but truncated —
//! message, so a naive harness records a *successful* round trip while the
//! payload was quietly cut. This harness hit exactly that and briefly believed
//! large payloads were working.
//!
//! So every testbed message carries its own 4-byte big-endian length prefix and
//! is reassembled here. That makes the harness correct on every leg regardless
//! of chunking — and, because the reassembler counts the chunks each logical
//! message arrived in, it turns the underlying behaviour into a measurement
//! rather than a trap. See the `message_integrity` scenario.
//!
//! ## One pipe abstraction, two protocols
//!
//! [`MsgLink`] is the seam that lets the QUIC reference leg be measured by the
//! same code as the Phantom legs. It is deliberately narrow — offer a framed
//! message, take one back, close — because the moment `upload` had a separate
//! loop per protocol, the two numbers would stop being comparable and nobody
//! would be able to tell from the artifact that they had. The framing above the
//! seam is identical for both, so `upload`, `download` and `bidir` count the
//! same bytes of the same messages whichever transport carries them.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use phantom_protocol::api::session::PhantomSession;
use phantom_protocol::transport::bandwidth_estimator::BW_FILTER_WINDOW;
use phantom_protocol::CoreError;
use tokio::sync::Mutex;

use crate::proto::{Msg, MAX_FRAME_BODY};
use crate::report::{unix_nanos, Leg, WindowSample};

/// Length-prefix width. Matches `TcpSessionTransport`'s own framing choice.
/// Bytes of length prefix every framed message carries.
///
/// Public because a scenario that has to know what a frame costs on the wire —
/// the byte-ceiling sweep, whose whole subject is the frame size — must derive
/// it from the encoder rather than hold its own copy of the number.
pub const LEN_PREFIX: usize = 4;

/// Upper bound on a reassembled message, with room for the verb byte.
const MAX_MESSAGE: usize = MAX_FRAME_BODY + 1;

/// Ceiling on a graceful close, wherever one is attempted.
///
/// Teardown flushes pending reliable data, so a link holding a large
/// unacknowledged backlog can block for a long time. By the time anything calls
/// this the samples are already recorded; waiting on a clean close buys nothing.
const CLOSE_TIMEOUT: Duration = Duration::from_secs(5);

/// A boxed future — what makes [`MsgLink`] usable as a trait object.
///
/// The allocation is one `Box::pin` per operation, against a network round trip
/// or a `send` that is about to touch a socket. It is also paid identically by
/// both protocols, so it cannot tilt a comparison between them.
pub type BoxFut<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// One logical, reliable, ordered byte pipe carrying testbed messages.
///
/// Implemented by [`Framed`] over a `PhantomSession` and by
/// [`crate::quic::QuicLink`] over a single QUIC bidirectional stream. Scenarios
/// that exist to compare the two are written against this trait; scenarios that
/// probe something only Phantom has (resumption, rekey, migration, per-stream
/// multiplexing) keep hold of the concrete session instead.
pub trait MsgLink: Send + Sync {
    /// Short label for the transport underneath, for notes and journal entries.
    fn protocol(&self) -> &'static str;

    /// Send bytes already produced by [`encode_framed`].
    fn send_encoded(&self, wire: Vec<u8>) -> BoxFut<'_, Result<(), CoreError>>;

    /// Receive one complete message, reassembling across transport reads, and
    /// report how it arrived.
    fn recv(&self) -> BoxFut<'_, Result<(Msg, Arrival), CoreError>>;

    /// Close the link. Bounded internally; never propagates a teardown failure,
    /// because a failed close says nothing about the measurement it followed.
    fn close(&self) -> BoxFut<'_, ()>;

    /// This link's view of its own congestion control, in the shared
    /// [`WindowSample`] shape.
    ///
    /// Fields the underlying stack does not expose are left zero rather than
    /// filled with an approximation — see [`crate::quic`] for exactly which
    /// ones that is on the QUIC leg.
    fn window_sample(
        &self,
        leg: Leg,
        phase: String,
        elapsed_ms: u64,
    ) -> BoxFut<'_, Option<WindowSample>>;

    /// The Phantom session behind this link, when there is one.
    ///
    /// `None` for the QUIC reference leg. A caller that needs protocol
    /// internals must say so through this, rather than assuming.
    fn phantom(&self) -> Option<&Arc<PhantomSession>> {
        None
    }

    /// A one-line transport-level summary for the artifact.
    ///
    /// Exists for counters a stack exposes that have no field in
    /// [`WindowSample`] — quinn's cumulative loss, for instance. Reporting them
    /// as prose beats either inventing record fields or dropping the numbers.
    fn transport_note(&self) -> Option<String> {
        None
    }

    /// Frame and send one message.
    fn send(&self, msg: &Msg) -> BoxFut<'_, Result<(), CoreError>> {
        self.send_encoded(encode_framed(msg))
    }
}

/// How a logical message arrived: how many transport reads it took, and how
/// large each was.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Arrival {
    /// Number of `PhantomSession::recv()` results consumed for this message.
    ///
    /// `1` means the session preserved the message boundary. Anything greater
    /// means the payload was split in transit and only reassembly recovered it.
    pub chunks: usize,
    /// Sizes of those reads, in order.
    pub chunk_sizes: Vec<usize>,
    /// Length of the reassembled message.
    pub message_len: usize,
}

/// A Phantom session with message framing layered on top.
pub struct Framed {
    session: Arc<PhantomSession>,
    rx: Mutex<Reassembler>,
}

/// The stream-to-message reassembler, shared by every link implementation.
///
/// Kept transport-agnostic on purpose: a QUIC stream and a Phantom session
/// deliver bytes in different-sized pieces, and the whole point of the framing
/// is that neither the harness nor the resulting numbers can tell.
#[derive(Default)]
pub(crate) struct Reassembler {
    buf: Vec<u8>,
    /// Reads consumed since the last complete message was returned.
    pending_chunks: Vec<usize>,
}

impl Reassembler {
    /// Absorb one transport read.
    pub(crate) fn push_chunk(&mut self, chunk: &[u8]) {
        self.pending_chunks.push(chunk.len());
        self.buf.extend_from_slice(chunk);
    }

    /// Pull one complete message out of the accumulator, if there is one.
    pub(crate) fn take(&mut self) -> Result<Option<(Msg, Arrival)>, CoreError> {
        if self.buf.len() < LEN_PREFIX {
            return Ok(None);
        }
        let len = u32::from_be_bytes([self.buf[0], self.buf[1], self.buf[2], self.buf[3]]) as usize;
        if len > MAX_MESSAGE {
            // A length this large means the stream is desynchronised. Failing
            // loudly beats allocating on a corrupt header.
            return Err(CoreError::ProtocolRejected(format!(
                "framed length {len} exceeds the {MAX_MESSAGE} cap"
            )));
        }
        if self.buf.len() < LEN_PREFIX + len {
            return Ok(None);
        }

        let body = self.buf[LEN_PREFIX..LEN_PREFIX + len].to_vec();
        self.buf.drain(..LEN_PREFIX + len);

        let chunk_sizes = std::mem::take(&mut self.pending_chunks);
        let arrival = Arrival {
            chunks: chunk_sizes.len(),
            chunk_sizes,
            message_len: len,
        };

        let msg = Msg::decode(&body)
            .map_err(|e| CoreError::ProtocolRejected(format!("framed body: {e}")))?;
        Ok(Some((msg, arrival)))
    }
}

impl Framed {
    pub fn new(session: Arc<PhantomSession>) -> Self {
        Self {
            session,
            rx: Mutex::new(Reassembler::default()),
        }
    }

    pub fn session(&self) -> &Arc<PhantomSession> {
        &self.session
    }
}

impl MsgLink for Framed {
    fn protocol(&self) -> &'static str {
        "phantom"
    }

    fn send_encoded(&self, wire: Vec<u8>) -> BoxFut<'_, Result<(), CoreError>> {
        Box::pin(self.session.send(wire))
    }

    fn recv(&self) -> BoxFut<'_, Result<(Msg, Arrival), CoreError>> {
        Box::pin(async move {
            let mut st = self.rx.lock().await;
            loop {
                if let Some(v) = st.take()? {
                    return Ok(v);
                }
                let chunk = self.session.recv().await?;
                st.push_chunk(&chunk);
            }
        })
    }

    fn close(&self) -> BoxFut<'_, ()> {
        Box::pin(async move {
            let _ = tokio::time::timeout(CLOSE_TIMEOUT, self.session.disconnect()).await;
        })
    }

    fn window_sample(
        &self,
        leg: Leg,
        phase: String,
        elapsed_ms: u64,
    ) -> BoxFut<'_, Option<WindowSample>> {
        Box::pin(async move {
            let bw = self.session.bandwidth_snapshot().await?;
            Some(WindowSample {
                leg,
                phase,
                t_unix_ns: unix_nanos(),
                elapsed_ms,
                cwnd_bytes: bw.cwnd_bytes,
                inflight_bytes: bw.inflight_bytes,
                bottleneck_bw_bps: bw.bottleneck_bw_bps,
                last_delivery_rate_bps: bw.last_delivery_rate_bps,
                // Read from the library rather than restated here, so the
                // recorded row names the horizon this binary's estimator
                // actually used.
                bw_filter_window_ms: BW_FILTER_WINDOW.as_millis() as u64,
                pacing_rate_bps: bw.pacing_rate_bps,
                min_rtt_us: bw.min_rtt.as_micros() as u64,
                dry_passes_against_a_full_buffer: bw.dry_passes_against_a_full_buffer,
                app_limited_acked_bytes: bw.app_limited_acked_bytes.0,
                acked_bytes_total: bw.app_limited_acked_bytes.1,
                drain_outcomes: bw.drain_outcomes.to_vec(),
                smoothed_rtt_us: bw.smoothed_rtt.map(|d| d.as_micros() as u64).unwrap_or(0),
                rtt_variation_us: bw.rtt_variation.as_micros() as u64,
                delivered_bytes: bw.delivered_bytes,
                state: bw.state.as_str().to_string(),
                app_limited: bw.app_limited,
                // The two loss figures travel together or not at all: a count of
                // copies on its own says nothing about how many holes bought
                // them, and a count of holes on its own says nothing about what
                // filling them cost.
                bytes_retransmitted: bw.bytes_retransmitted,
                bytes_lost: bw.bytes_lost,
                // And the count those bytes weigh, split by which rule ordered
                // each repair. A byte total cannot say whether a sender's holes
                // were found by acknowledgements naming their successors or by a
                // clock running out, and the two are different findings about the
                // path.
                loss_declarations: bw.loss_declarations,
                repairs_attributed: bw.repairs_attributed,
                declared_by_packet_threshold: bw.declared_by_packet_threshold,
                declared_by_time_threshold: bw.declared_by_time_threshold,
                declared_by_rto: bw.declared_by_rto,
                inflight_hi_bytes: bw.inflight_hi_bytes,
            })
        })
    }

    fn phantom(&self) -> Option<&Arc<PhantomSession>> {
        Some(&self.session)
    }
}

/// Encode a message with its length prefix.
pub fn encode_framed(msg: &Msg) -> Vec<u8> {
    let body = msg.encode();
    let mut out = Vec::with_capacity(LEN_PREFIX + body.len());
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(&body);
    out
}

/// A [`MsgLink`] that answers from a script instead of from a network.
///
/// Both of the harness's silent-loss defects live on the failure side of this
/// trait — a send that does not land, a window the stack cannot yet describe —
/// and neither is reachable through a real session without a real peer and a
/// real path. Scripting the link is what makes them deterministic, and a shared
/// double is what keeps the daemon's tests and the probe's tests agreeing on
/// what a failing link looks like.
#[cfg(test)]
pub(crate) mod testing {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

    use phantom_protocol::CoreError;

    use super::{Arrival, BoxFut, MsgLink, BW_FILTER_WINDOW};
    use crate::proto::Msg;
    use crate::report::{unix_nanos, Leg, WindowSample};

    pub(crate) struct ScriptedLink {
        /// When set, every send fails the way a link whose peer has gone away
        /// fails — the case in which `download:end` was lost, since the mark is
        /// the last thing written before the session is closed.
        pub(crate) send_fails: bool,
        /// When false, `window_sample` yields nothing, standing in for a
        /// `bandwidth_snapshot()` that has produced no estimate yet.
        pub(crate) window_available: bool,
        /// Window sweeps served so far. A test reads this to know the sampler
        /// has actually run, instead of guessing with a sleep.
        pub(crate) window_calls: Arc<AtomicU64>,
        /// `recv` parks until this many sweeps have been served and then yields
        /// `BYE`, which ends a session handler. Zero ends it immediately.
        pub(crate) recv_bye_after_window_calls: u64,
    }

    impl Default for ScriptedLink {
        fn default() -> Self {
            Self {
                send_fails: false,
                window_available: true,
                window_calls: Arc::new(AtomicU64::new(0)),
                recv_bye_after_window_calls: 0,
            }
        }
    }

    impl ScriptedLink {
        /// A link on which nothing can be sent.
        pub(crate) fn failing_sends() -> Self {
            Self {
                send_fails: true,
                ..Self::default()
            }
        }
    }

    impl MsgLink for ScriptedLink {
        fn protocol(&self) -> &'static str {
            "scripted"
        }

        fn send_encoded(&self, _wire: Vec<u8>) -> BoxFut<'_, Result<(), CoreError>> {
            let fails = self.send_fails;
            Box::pin(async move {
                if fails {
                    Err(CoreError::ConnectionClosed)
                } else {
                    Ok(())
                }
            })
        }

        fn recv(&self) -> BoxFut<'_, Result<(Msg, Arrival), CoreError>> {
            Box::pin(async move {
                while self.window_calls.load(Ordering::Relaxed) < self.recv_bye_after_window_calls {
                    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                }
                Ok((Msg::Bye, Arrival::default()))
            })
        }

        fn close(&self) -> BoxFut<'_, ()> {
            Box::pin(async {})
        }

        fn window_sample(
            &self,
            leg: Leg,
            phase: String,
            elapsed_ms: u64,
        ) -> BoxFut<'_, Option<WindowSample>> {
            self.window_calls.fetch_add(1, Ordering::Relaxed);
            let available = self.window_available;
            Box::pin(async move {
                available.then(|| WindowSample {
                    leg,
                    phase,
                    t_unix_ns: unix_nanos(),
                    elapsed_ms,
                    cwnd_bytes: 5600,
                    inflight_bytes: 1400,
                    bottleneck_bw_bps: 125_000,
                    // Deliberately under the filtered maximum above: the double
                    // stands in for a live session, and on a live session the
                    // two readings differ exactly when the filter is holding a
                    // peak the latest sample no longer supports.
                    last_delivery_rate_bps: 100_000,
                    bw_filter_window_ms: BW_FILTER_WINDOW.as_millis() as u64,
                    pacing_rate_bps: 125_000,
                    min_rtt_us: 230_000,
                    dry_passes_against_a_full_buffer: 5,
                    app_limited_acked_bytes: 700,
                    acked_bytes_total: 2800,
                    drain_outcomes: vec![9, 2, 1, 0, 4, 6],
                    smoothed_rtt_us: 244_000,
                    rtt_variation_us: 9_000,
                    delivered_bytes: 1400,
                    state: "probe_bw".to_string(),
                    app_limited: false,
                    // A sender that spent two copies on one hole: the shape a
                    // path that loses its own repairs produces, and distinct
                    // values so a row that dropped or transposed one of these
                    // columns is visible.
                    bytes_retransmitted: 2800,
                    bytes_lost: 1400,
                    loss_declarations: 1,
                    repairs_attributed: 2,
                    declared_by_packet_threshold: 1,
                    declared_by_time_threshold: 0,
                    declared_by_rto: 0,
                    inflight_hi_bytes: 4200,
                })
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::PayloadGen;

    /// Feed the reassembler a byte stream in arbitrary chunk sizes and collect
    /// the messages it yields, exactly as `MsgLink::recv` would.
    fn drain(chunks: &[Vec<u8>]) -> Vec<(Msg, Arrival)> {
        let mut st = Reassembler::default();
        let mut out = Vec::new();
        for c in chunks {
            st.push_chunk(c);
            while let Some(v) = st.take().expect("no framing error") {
                out.push(v);
            }
        }
        out
    }

    #[test]
    fn a_message_delivered_whole_reports_one_chunk() {
        let msg = Msg::Echo {
            seq: 1,
            client_send_ns: 2,
            payload: vec![7; 100],
        };
        let got = drain(&[encode_framed(&msg)]);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].0, msg);
        assert_eq!(got[0].1.chunks, 1, "an unsplit message must report 1 chunk");
    }

    /// The case this module exists for: an 8 KiB message split into chunk-sized
    /// transport reads must come back byte-identical, and must *report* that it
    /// was split.
    #[test]
    fn a_message_split_at_the_chunk_size_is_reassembled_and_reported() {
        let payload = PayloadGen::new(5).fill(8192);
        let msg = Msg::Echo {
            seq: 42,
            client_send_ns: 99,
            payload: payload.clone(),
        };
        let wire = encode_framed(&msg);
        let chunks: Vec<Vec<u8>> = wire
            .chunks(phantom_protocol::transport::mtu::MAX_APP_CHUNK)
            .map(|c| c.to_vec())
            .collect();
        assert!(chunks.len() > 1, "the test must actually split something");

        let got = drain(&chunks);
        assert_eq!(got.len(), 1, "one logical message");
        assert_eq!(got[0].0, msg, "reassembly must be byte-exact");
        assert_eq!(got[0].1.chunks, chunks.len());
        assert_eq!(got[0].1.message_len, msg.encode().len());
        assert!(
            got[0]
                .1
                .chunk_sizes
                .iter()
                .take(chunks.len() - 1)
                .all(|&n| n == phantom_protocol::transport::mtu::MAX_APP_CHUNK),
            "chunk sizes are recorded verbatim: {:?}",
            got[0].1.chunk_sizes
        );
    }

    /// Several messages coalesced into one transport read must all come out.
    #[test]
    fn coalesced_messages_are_all_recovered() {
        let a = Msg::Mark { label: "a".into() };
        let b = Msg::Bye;
        let c = Msg::Sink {
            seq: 3,
            payload: vec![1, 2, 3],
        };
        let mut one = encode_framed(&a);
        one.extend_from_slice(&encode_framed(&b));
        one.extend_from_slice(&encode_framed(&c));

        let got = drain(&[one]);
        assert_eq!(got.len(), 3);
        assert_eq!(got[0].0, a);
        assert_eq!(got[1].0, b);
        assert_eq!(got[2].0, c);
    }

    /// Byte-at-a-time delivery is the pathological case for any reassembler.
    #[test]
    fn one_byte_at_a_time_still_reassembles() {
        let msg = Msg::Sink {
            seq: 9,
            payload: PayloadGen::new(1).fill(300),
        };
        let wire = encode_framed(&msg);
        let chunks: Vec<Vec<u8>> = wire.iter().map(|b| vec![*b]).collect();
        let got = drain(&chunks);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].0, msg);
        assert_eq!(got[0].1.chunks, wire.len());
    }

    #[test]
    fn a_partial_message_yields_nothing_rather_than_a_truncated_one() {
        let msg = Msg::Sink {
            seq: 1,
            payload: vec![4; 500],
        };
        let wire = encode_framed(&msg);
        let got = drain(&[wire[..wire.len() - 1].to_vec()]);
        assert!(
            got.is_empty(),
            "an incomplete message must not be delivered at all"
        );
    }

    #[test]
    fn an_absurd_declared_length_is_rejected_without_allocating() {
        let mut st = Reassembler::default();
        st.push_chunk(&u32::MAX.to_be_bytes());
        st.push_chunk(&[0u8; 16]);
        let r = st.take();
        assert!(matches!(r, Err(CoreError::ProtocolRejected(_))), "{r:?}");
    }

    #[test]
    fn a_desynchronised_body_is_a_typed_error() {
        let mut st = Reassembler::default();
        // Declares 2 bytes, body is an unknown verb.
        st.push_chunk(&2u32.to_be_bytes());
        st.push_chunk(&[0xFE, 0x00]);
        let r = st.take();
        assert!(matches!(r, Err(CoreError::ProtocolRejected(_))), "{r:?}");
    }

    #[test]
    fn arrival_chunk_accounting_resets_between_messages() {
        let a = Msg::Sink {
            seq: 1,
            payload: vec![0; 2000],
        };
        let b = Msg::Sink {
            seq: 2,
            payload: vec![0; 10],
        };
        let mut wire = encode_framed(&a);
        wire.extend_from_slice(&encode_framed(&b));
        let chunks: Vec<Vec<u8>> = wire.chunks(700).map(|c| c.to_vec()).collect();

        let got = drain(&chunks);
        assert_eq!(got.len(), 2);
        // The second message must not inherit the first message's chunk count.
        assert!(
            got[1].1.chunks <= got[0].1.chunks,
            "chunk counters leaked between messages: {:?} then {:?}",
            got[0].1,
            got[1].1
        );
        assert_eq!(got[0].1.message_len, a.encode().len());
        assert_eq!(got[1].1.message_len, b.encode().len());
    }

    /// **Every column the artifact carries must actually be read out of the
    /// snapshot, and the compiler cannot say so.**
    ///
    /// `WindowSample` is a plain struct: a field assigned `0` compiles exactly as
    /// well as one assigned `bw.field`, and the row that results looks like a
    /// measured zero rather than a column that stopped being written. That is not
    /// hypothetical — a previous set of counters reached `MetricsSnapshotFfi` and
    /// stopped there, so a run that was supposed to prove a mechanism worked
    /// recorded nothing and could not say it had recorded nothing. The break was
    /// in the writing, not in the deciding, and nothing failed.
    ///
    /// So this reads the two sources it sits between: the field list of
    /// `WindowSample` out of `report.rs`, and this file's own Phantom-leg
    /// constructor. Every field must either be assigned from `bw` or appear in
    /// the exemption list below with a reason. Adding a column to `report.rs`
    /// without wiring it here turns this red, which is the whole point.
    ///
    /// The exemptions are exemptions from *this* check, not from being recorded:
    /// each is written from something other than the snapshot, and the check
    /// verifies each is at least mentioned so a typo cannot hide inside one.
    #[test]
    fn every_recorded_column_is_read_from_the_snapshot() {
        const REPORT_SRC: &str = include_str!("report.rs");
        const FRAMING_SRC: &str = include_str!("framing.rs");

        // Written from something other than `bw`, each for its own reason.
        const NOT_FROM_THE_SNAPSHOT: &[(&str, &str)] = &[
            ("leg", "an argument — which leg this row describes"),
            ("phase", "an argument — the scenario that was running"),
            ("t_unix_ns", "the sampler's own clock"),
            ("elapsed_ms", "an argument — offset within the transfer"),
            (
                "bw_filter_window_ms",
                "read from the library constant so the row names the horizon this \
                 binary's estimator used, not one restated here",
            ),
            ("min_rtt_us", "converted from bw.min_rtt, a Duration"),
            (
                "app_limited_acked_bytes",
                "the first half of bw.app_limited_acked_bytes, a pair — the two \
                 halves travel as one field because neither is a reading alone",
            ),
            ("acked_bytes_total", "the second half of that same pair"),
            (
                "drain_outcomes",
                "converted from bw.drain_outcomes, a fixed array — the artifact \
                 carries a Vec so a run recorded before the census loads as empty \
                 rather than as six zeros, which would read as a sender whose \
                 every pass ran dry",
            ),
            (
                "smoothed_rtt_us",
                "converted from bw.smoothed_rtt, an Option<Duration> — absent \
                 before the first sample survives Karn's gate, and zero here \
                 rather than a guess",
            ),
            (
                "rtt_variation_us",
                "converted from bw.rtt_variation, a Duration",
            ),
            ("state", "converted from bw.state, an enum"),
        ];

        let fields = window_sample_fields(REPORT_SRC);
        assert!(
            fields.contains(&"cwnd_bytes".to_string()),
            "the field parse produced {} name(s) and none was cwnd_bytes — the \
             parse is broken, so its silence about missing columns means nothing",
            fields.len()
        );

        let ctor = phantom_leg_constructor(FRAMING_SRC);
        assert!(
            ctor.contains("cwnd_bytes: bw.cwnd_bytes"),
            "the constructor slice does not contain a known assignment, so this \
             check is reading the wrong text"
        );

        let mut unwired = Vec::new();
        for f in &fields {
            if let Some((_, _why)) = NOT_FROM_THE_SNAPSHOT.iter().find(|(n, _)| n == f) {
                // Either `name: expr,` or the shorthand `name,` — both are
                // assignments and only the second has no colon.
                assert!(
                    ctor.contains(&format!("{f}:")) || ctor.contains(&format!("{f},")),
                    "{f} is exempted from being read out of the snapshot but is not \
                     written at all"
                );
                continue;
            }
            if !ctor.contains(&format!("{f}: bw.{f},")) {
                unwired.push(f.clone());
            }
        }
        assert!(
            unwired.is_empty(),
            "these columns exist in the artifact but are not read from the \
             snapshot: {unwired:?}"
        );
    }

    /// Field names of `WindowSample`, read out of `report.rs`.
    fn window_sample_fields(src: &str) -> Vec<String> {
        let Some(start) = src.find("pub struct WindowSample") else {
            return Vec::new();
        };
        let mut depth = 0usize;
        let mut end = start;
        for (i, c) in src[start..].char_indices() {
            match c {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = start + i;
                        break;
                    }
                }
                _ => {}
            }
        }
        src[start..end]
            .lines()
            .filter_map(|l| {
                let l = l.trim();
                let rest = l.strip_prefix("pub ")?;
                let name = rest.split(':').next()?;
                name.chars()
                    .all(|c| c.is_ascii_lowercase() || c == '_' || c.is_ascii_digit())
                    .then(|| name.to_string())
            })
            .collect()
    }

    /// The Phantom leg's `WindowSample` constructor, as text, with comments
    /// stripped.
    ///
    /// Stripping them is the whole difference between a gate and a decoration.
    /// The check is a substring test, and every field it looks for is *named* in
    /// the prose above its own assignment — so commenting an assignment out and
    /// hardcoding a zero beside it left the name in view and the gate green. That
    /// is the exact shape of break this exists to catch, and it survived the first
    /// version of it.
    fn phantom_leg_constructor(src: &str) -> String {
        let anchor = "let bw = self.session.bandwidth_snapshot().await?;";
        let Some(start) = src.find(anchor) else {
            return String::new();
        };
        let tail = &src[start..];
        let end = tail.find("\n        })").unwrap_or(tail.len());
        tail[..end]
            .lines()
            .map(|l| match l.find("//") {
                Some(i) => &l[..i],
                None => l,
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}
