//! Leg-aware connection setup and the request/response primitives.
//!
//! Every operation in this module is bounded by a timeout. The probe runs
//! unattended for hours; a single un-bounded `recv()` on a leg that silently
//! stopped delivering would hang the entire run and produce no data at all —
//! which is strictly worse than recording the failure and moving on.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use phantom_protocol::api::session::{PhantomSession, ResumptionHint};
use phantom_protocol::crypto::hybrid_sign::HybridVerifyingKey;
use phantom_protocol::transport::legs::mimic_tls::{MimicConfig, MimicTlsLeg};
use phantom_protocol::CoreError;

use crate::framing::{Arrival, Framed, MsgLink};
use crate::proto::Msg;
use crate::quic::QuicLink;
use crate::report::Leg;

/// Ceiling on a handshake. Generous against a ~230 ms path plus post-quantum
/// key exchange, tight enough that a wedged leg is reported rather than waited on.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// Budget for draining a large backlog before a final control frame lands.
///
/// After a saturating upload the session can hold a substantial queue of
/// unacknowledged data; the closing `SINK_END` sits behind all of it. Judging
/// that by the per-operation timeout would report a stall where there is only a
/// queue.
pub const DRAIN_TIMEOUT: Duration = Duration::from_secs(60);

/// Ceiling on one application round trip.
///
/// Sized against a ~230 ms path with room for several retransmissions. It is
/// deliberately not generous: a lost round trip costs this much wall clock, and
/// at 30 s a single misbehaving payload size could consume more of the run than
/// every healthy scenario combined. That is not hypothetical — it happened.
pub const OP_TIMEOUT: Duration = Duration::from_secs(10);

/// Close a session without letting teardown hang the run.
///
/// `disconnect()` raises a close signal and returns at once; it does not wait
/// for pending data to be flushed or acknowledged. The session's pump then
/// pushes what the congestion and flow-control windows admit, announces the
/// close, and discards whatever is still queued; nothing already sent is
/// retransmitted after that. The run has already recorded its samples by this
/// point, so nothing it measures depends on that tail reaching the peer. The
/// timeout is a guard against a `disconnect()` that ever waits again, not a
/// wait this one is known to need.
pub async fn close_session(session: &Arc<PhantomSession>) {
    let _ = tokio::time::timeout(Duration::from_secs(5), session.disconnect()).await;
}

#[derive(Debug, Clone)]
pub struct Endpoints {
    pub host: String,
    pub tcp_port: u16,
    pub udp_port: u16,
    pub mimic_port: u16,
    pub quic_port: u16,
    pub raw_tcp_port: u16,
    pub raw_udp_port: u16,
    /// The one-way server → client control. Not reachable through
    /// [`Endpoints::port_for`] because it is not a leg of its own: it is a
    /// second probe against the same `raw_udp` control group, measuring the
    /// direction the echo cannot isolate.
    pub raw_udp_down_port: u16,
    /// The one-way client → server control — the same arrangement mirrored, and
    /// for the same reason: the echo bounds the two directions together, and an
    /// `upload` figure needs a denominator in the direction it was measured in.
    pub raw_udp_up_port: u16,
    pub sni: String,
    /// The daemon's QUIC certificate, DER, as pinned by the operator.
    ///
    /// `None` means no pin was supplied, and the QUIC reference leg is skipped
    /// with a recorded note rather than connecting without verification — an
    /// unverified handshake would measure something other than a handshake.
    pub quic_cert: Option<Vec<u8>>,
}

impl Endpoints {
    pub fn port_for(&self, leg: Leg) -> u16 {
        match leg {
            Leg::Udp => self.udp_port,
            Leg::Tcp => self.tcp_port,
            Leg::Mimic => self.mimic_port,
            Leg::Quic => self.quic_port,
            Leg::RawTcp => self.raw_tcp_port,
            Leg::RawUdp => self.raw_udp_port,
        }
    }

    pub fn addr_for(&self, leg: Leg) -> String {
        format!("{}:{}", self.host, self.port_for(leg))
    }

    /// The raw downstream source's address.
    pub fn raw_downstream_addr(&self) -> String {
        format!("{}:{}", self.host, self.raw_udp_down_port)
    }

    /// The raw uplink sink's address.
    pub fn raw_upstream_addr(&self) -> String {
        format!("{}:{}", self.host, self.raw_udp_up_port)
    }
}

/// A short, stable classification of a `CoreError`.
///
/// Recorded alongside the full `Debug` string so analysis can group failures
/// without regex-matching prose — the protocol went to some trouble to make
/// these typed, and throwing that away at the reporting layer would be a waste.
pub fn error_kind(e: &CoreError) -> String {
    match e {
        CoreError::ServerIdentityMismatch => "ServerIdentityMismatch",
        CoreError::ProtocolRejected(_) => "ProtocolRejected",
        CoreError::Unsupported(_) => "Unsupported",
        CoreError::ReplayDetected(_) => "ReplayDetected",
        CoreError::CipherSuiteUnavailable(_) => "CipherSuiteUnavailable",
        CoreError::ConnectionClosed => "ConnectionClosed",
        CoreError::Timeout => "Timeout",
        CoreError::NetworkError(_) => "NetworkError",
        CoreError::CryptoError(_) => "CryptoError",
        CoreError::ConfigError(_) => "ConfigError",
        other => {
            // `CoreError` is `#[non_exhaustive]`; fall back to the variant name
            // rather than mislabelling a future variant as something it isn't.
            let s = format!("{other:?}");
            return s.split(['(', ' ']).next().unwrap_or("Unknown").to_string();
        }
    }
    .to_string()
}

/// Open a session on `leg`, cold (no resumption), and wait until it is usable.
///
/// The `await_ready()` is essential, not defensive. `connect_pinned*` returns a
/// session in `Connecting` state and drives the handshake on a background task,
/// so the call returns before the server's identity has been checked at all.
/// Without this wait:
///
/// - "handshake latency" measures a TCP connect and an allocation, not a
///   post-quantum key exchange;
/// - a deliberately wrong pin looks like a **successful** connect, because
///   `ServerIdentityMismatch` has not been raised yet;
/// - `resumption_hint()` returns `None`, since no ticket exists yet.
///
/// This harness reported all three before the wait was added.
pub async fn connect_leg(
    leg: Leg,
    ep: &Endpoints,
    pin: &[u8],
) -> Result<Arc<PhantomSession>, CoreError> {
    let session = connect_leg_unready(leg, ep, pin).await?;
    tokio::time::timeout(CONNECT_TIMEOUT, session.await_ready())
        .await
        .map_err(|_| CoreError::Timeout)??;
    Ok(session)
}

/// Construct the session without waiting for the handshake.
///
/// Exposed separately so a scenario can measure the two phases apart: the
/// synchronous setup cost and the handshake that follows it.
pub async fn connect_leg_unready(
    leg: Leg,
    ep: &Endpoints,
    pin: &[u8],
) -> Result<Arc<PhantomSession>, CoreError> {
    let fut = async {
        match leg {
            Leg::Udp => {
                phantom_protocol::connect_pinned_udp(ep.host.clone(), ep.udp_port, pin.to_vec())
                    .await
            }
            Leg::Tcp => {
                phantom_protocol::connect_pinned(ep.host.clone(), ep.tcp_port, pin.to_vec()).await
            }
            Leg::Mimic => {
                phantom_protocol::api::session::connect_pinned_mimic(
                    ep.host.clone(),
                    ep.mimic_port,
                    pin.to_vec(),
                    ep.sni.clone(),
                )
                .await
            }
            Leg::Quic | Leg::RawTcp | Leg::RawUdp => Err(CoreError::Unsupported(format!(
                "{leg} carries no Phantom session"
            ))),
        }
    };
    tokio::time::timeout(CONNECT_TIMEOUT, fut)
        .await
        .map_err(|_| CoreError::Timeout)?
}

/// Resolve a leg's host:port to a socket address.
///
/// Only the first result is used, matching what `connect_pinned_udp` does on
/// the Phantom side — a leg that silently tried a second address would not be
/// measuring the same path as its neighbours.
pub async fn resolve(ep: &Endpoints, leg: Leg) -> Result<SocketAddr, CoreError> {
    let addr = ep.addr_for(leg);
    let mut it = tokio::net::lookup_host(addr.clone())
        .await
        .map_err(|e| CoreError::NetworkError(format!("resolve {addr}: {e}")))?;
    it.next()
        .ok_or_else(|| CoreError::NetworkError(format!("{addr} resolved to nothing")))
}

/// Open a link on `leg`, whichever protocol carries it, and wait until it is
/// usable.
///
/// This is the entry point for every scenario that compares the protocol under
/// test against the QUIC reference: both legs come back as an
/// [`MsgLink`], so a comparison cannot accidentally be run over two different
/// code paths measuring two different things.
pub async fn connect_link(
    leg: Leg,
    ep: &Endpoints,
    pin: &[u8],
) -> Result<Arc<dyn MsgLink>, CoreError> {
    Ok(connect_link_staged(leg, ep, pin).await?.0)
}

/// As [`connect_link`], additionally reporting how much of the elapsed time was
/// spent before the handshake began.
///
/// The split exists because the two legs reach a usable connection differently:
/// `connect_pinned*` returns a session in `Connecting` state and runs the
/// handshake on a background task, while quinn's `connect(..).await` resolves
/// only once the TLS handshake is done. Measuring both as one number would
/// quietly compare a socket setup on one leg against a full key exchange on the
/// other. `setup_ns` is the synchronous construction prefix on both.
pub async fn connect_link_staged(
    leg: Leg,
    ep: &Endpoints,
    pin: &[u8],
) -> Result<(Arc<dyn MsgLink>, u64), CoreError> {
    let t0 = Instant::now();
    match leg {
        Leg::Quic => {
            let cert = ep.quic_cert.clone().ok_or_else(|| {
                CoreError::ConfigError(
                    "no QUIC certificate pinned: pass --quic-cert-file or --quic-cert-hex"
                        .to_string(),
                )
            })?;
            let addr = resolve(ep, leg).await?;
            let setup_ns = t0.elapsed().as_nanos() as u64;
            let link = tokio::time::timeout(CONNECT_TIMEOUT, QuicLink::connect(addr, &cert))
                .await
                .map_err(|_| CoreError::Timeout)??;
            Ok((Arc::new(link), setup_ns))
        }
        Leg::Udp | Leg::Tcp | Leg::Mimic => {
            let session = connect_leg_unready(leg, ep, pin).await?;
            let setup_ns = t0.elapsed().as_nanos() as u64;
            tokio::time::timeout(CONNECT_TIMEOUT, session.await_ready())
                .await
                .map_err(|_| CoreError::Timeout)??;
            Ok((Arc::new(Framed::new(session)), setup_ns))
        }
        Leg::RawTcp | Leg::RawUdp => Err(CoreError::Unsupported(format!(
            "{leg} is a raw socket control and carries no protocol"
        ))),
    }
}

/// Open a session on `leg`, offering a resumption ticket and 0-RTT early data.
///
/// TCP and UDP have dedicated `connect_pinned_*_with_resumption` entry points.
/// mimic-TLS does not, so it is assembled from the public pieces — the mimicry
/// prelude runs first, then the resulting leg is handed to the session builder.
/// The result is that all three legs get real 0-RTT coverage instead of the
/// mimic leg being quietly excluded.
pub async fn connect_leg_resumed(
    leg: Leg,
    ep: &Endpoints,
    pin: &[u8],
    hint: Arc<ResumptionHint>,
    early_data: Vec<u8>,
) -> Result<Arc<PhantomSession>, CoreError> {
    let session = connect_leg_resumed_unready(leg, ep, pin, hint, early_data).await?;
    tokio::time::timeout(CONNECT_TIMEOUT, session.await_ready())
        .await
        .map_err(|_| CoreError::Timeout)??;
    Ok(session)
}

async fn connect_leg_resumed_unready(
    leg: Leg,
    ep: &Endpoints,
    pin: &[u8],
    hint: Arc<ResumptionHint>,
    early_data: Vec<u8>,
) -> Result<Arc<PhantomSession>, CoreError> {
    let fut = async move {
        match leg {
            Leg::Udp => {
                phantom_protocol::connect_pinned_udp_with_resumption(
                    ep.host.clone(),
                    ep.udp_port,
                    pin.to_vec(),
                    hint,
                    early_data,
                )
                .await
            }
            Leg::Tcp => {
                phantom_protocol::connect_pinned_with_resumption(
                    ep.host.clone(),
                    ep.tcp_port,
                    pin.to_vec(),
                    hint,
                    early_data,
                )
                .await
            }
            Leg::Mimic => {
                let vk = HybridVerifyingKey::from_bytes(pin)
                    .map_err(|e| CoreError::CryptoError(format!("invalid pin: {e}")))?;
                let addr = format!("{}:{}", ep.host, ep.mimic_port);
                let stream = tokio::net::TcpStream::connect(&addr)
                    .await
                    .map_err(|e| CoreError::NetworkError(format!("connect {addr}: {e}")))?;
                let leg = MimicTlsLeg::connect(stream, &MimicConfig::new(ep.sni.clone())).await?;
                PhantomSession::builder(addr)
                    .pinned_key(vk)
                    .transport(leg)
                    .resumption(hint, early_data)
                    .connect()
                    .await
            }
            Leg::Quic | Leg::RawTcp | Leg::RawUdp => Err(CoreError::Unsupported(format!(
                "{leg} carries no Phantom session"
            ))),
        }
    };
    tokio::time::timeout(CONNECT_TIMEOUT, fut)
        .await
        .map_err(|_| CoreError::Timeout)?
}

/// Open a Phantom session on `leg` and wrap it in testbed framing.
///
/// Phantom-only by construction: the scenarios that call this reach for
/// resumption, rekey, migration or per-stream multiplexing, none of which the
/// reference leg is being asked to imitate. Anything that compares the two goes
/// through [`connect_link`] instead.
pub async fn connect_framed(leg: Leg, ep: &Endpoints, pin: &[u8]) -> Result<Framed, CoreError> {
    Ok(Framed::new(connect_leg(leg, ep, pin).await?))
}

/// Result of one echo round trip.
pub struct EchoOutcome {
    pub rtt_ns: u64,
    pub server_recv_ns: u64,
    pub server_send_ns: u64,
    pub payload_len: usize,
    /// How the reply arrived — `chunks > 1` means the session split it.
    pub arrival: Arrival,
}

/// Send one `ECHO` and wait for its `ECHO_REPLY`, timing the round trip.
///
/// The clock is read immediately before `send` and immediately after the reply
/// is complete, so the measured interval covers exactly the protocol path.
///
/// The echoed payload is compared byte-for-byte against what was sent. That
/// check is not ceremony: `PhantomSession` splits payloads above its chunk size, and a
/// truncated reply still carries a matching `seq`, so without this comparison a
/// silently-cut payload registers as a clean round trip. It did, until this
/// check was added.
pub async fn echo_once(
    framed: &dyn MsgLink,
    seq: u64,
    payload: Vec<u8>,
) -> Result<EchoOutcome, CoreError> {
    let payload_len = payload.len();
    let sent = payload.clone();
    let msg = Msg::Echo {
        seq,
        client_send_ns: crate::report::unix_nanos(),
        payload,
    };

    let t0 = Instant::now();
    framed.send(&msg).await?;

    let deadline = Instant::now() + OP_TIMEOUT;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(CoreError::Timeout);
        }
        let (reply, arrival) = tokio::time::timeout(remaining, framed.recv())
            .await
            .map_err(|_| CoreError::Timeout)??;
        // Skip anything that is not our reply (a straggling frame from an
        // earlier scenario) rather than mis-attributing its arrival time here.
        let Msg::EchoReply {
            seq: got,
            server_recv_ns,
            server_send_ns,
            payload: back,
            ..
        } = reply
        else {
            continue;
        };
        if got != seq {
            continue;
        }
        if back != sent {
            return Err(CoreError::ProtocolRejected(format!(
                "echo payload differs: sent {} B, got {} B back",
                sent.len(),
                back.len()
            )));
        }
        return Ok(EchoOutcome {
            rtt_ns: t0.elapsed().as_nanos() as u64,
            server_recv_ns,
            server_send_ns,
            payload_len,
            arrival,
        });
    }
}

/// Send a frame that expects no reply.
pub async fn send_msg(framed: &dyn MsgLink, msg: Msg) -> Result<(), CoreError> {
    tokio::time::timeout(OP_TIMEOUT, framed.send(&msg))
        .await
        .map_err(|_| CoreError::Timeout)?
}

/// Record a named marker in the server's journal.
///
/// Best-effort by design: a failed marker must never abort a scenario, because
/// the marker exists to annotate the data, not to be part of the measurement.
/// The failure is nevertheless returned rather than dropped here, because
/// best-effort is a statement about control flow and not a licence to lose the
/// fact. Scenarios call `ScenarioOutput::mark`, which keeps the best-effort
/// behaviour and files the failure in `errors.jsonl`; the `Result` is what
/// makes a future caller that ignores it visible to the compiler.
pub async fn mark(framed: &dyn MsgLink, label: impl Into<String>) -> Result<(), CoreError> {
    send_msg(
        framed,
        Msg::Mark {
            label: label.into(),
        },
    )
    .await
}

/// Ask for the server's metric snapshot.
pub async fn fetch_server_stats(framed: &dyn MsgLink) -> Result<serde_json::Value, CoreError> {
    send_msg(framed, Msg::StatsReq).await?;
    let deadline = Instant::now() + OP_TIMEOUT;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(CoreError::Timeout);
        }
        let (msg, _) = tokio::time::timeout(remaining, framed.recv())
            .await
            .map_err(|_| CoreError::Timeout)??;
        if let Msg::Stats { json } = msg {
            return serde_json::from_slice(&json)
                .map_err(|e| CoreError::ProtocolRejected(format!("stats json: {e}")));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ep() -> Endpoints {
        Endpoints {
            host: "example.test".into(),
            tcp_port: 4242,
            udp_port: 4243,
            mimic_port: 4244,
            quic_port: 4245,
            raw_tcp_port: 4342,
            raw_udp_port: 4343,
            raw_udp_down_port: 4344,
            raw_udp_up_port: 4345,
            sni: "www.example.com".into(),
            quic_cert: None,
        }
    }

    #[test]
    fn each_leg_resolves_to_its_own_port() {
        let e = ep();
        assert_eq!(e.port_for(Leg::Tcp), 4242);
        assert_eq!(e.port_for(Leg::Udp), 4243);
        assert_eq!(e.port_for(Leg::Mimic), 4244);
        assert_eq!(e.port_for(Leg::Quic), 4245);
        assert_eq!(e.port_for(Leg::RawTcp), 4342);
        assert_eq!(e.port_for(Leg::RawUdp), 4343);
        assert_eq!(e.addr_for(Leg::Udp), "example.test:4243");
        assert_eq!(e.raw_downstream_addr(), "example.test:4344");
        assert_eq!(e.raw_upstream_addr(), "example.test:4345");

        // No two listeners may share a port, or a run would silently measure
        // the wrong one. The two one-way controls are in the list even though
        // neither is a leg: each is a distinct listener on the daemon.
        let mut ports: Vec<u16> = [
            Leg::Udp,
            Leg::Tcp,
            Leg::Mimic,
            Leg::Quic,
            Leg::RawTcp,
            Leg::RawUdp,
        ]
        .iter()
        .map(|l| e.port_for(*l))
        .collect();
        ports.push(e.raw_udp_down_port);
        ports.push(e.raw_udp_up_port);
        let mut uniq = ports.clone();
        uniq.sort_unstable();
        uniq.dedup();
        assert_eq!(uniq.len(), ports.len(), "listener ports must be distinct");
    }

    #[test]
    fn error_kinds_are_stable_labels() {
        assert_eq!(
            error_kind(&CoreError::ServerIdentityMismatch),
            "ServerIdentityMismatch"
        );
        assert_eq!(
            error_kind(&CoreError::Unsupported("x".into())),
            "Unsupported"
        );
        assert_eq!(error_kind(&CoreError::Timeout), "Timeout");
        assert_eq!(error_kind(&CoreError::ConnectionClosed), "ConnectionClosed");
        assert_eq!(
            error_kind(&CoreError::NetworkError("boom".into())),
            "NetworkError"
        );
        assert_eq!(
            error_kind(&CoreError::ProtocolRejected("v9".into())),
            "ProtocolRejected"
        );
        // Never empty, whatever the variant.
        assert!(!error_kind(&CoreError::CryptoError("x".into())).is_empty());
    }

    #[tokio::test]
    async fn raw_legs_are_not_phantom_connectable() {
        let e = ep();
        for leg in [Leg::RawTcp, Leg::RawUdp, Leg::Quic] {
            let r = connect_leg(leg, &e, &[0u8; 64]).await;
            assert!(
                matches!(r, Err(CoreError::Unsupported(_))),
                "{leg} must not be reachable through the Phantom connect path"
            );
        }
    }

    /// The raw controls are sockets, not protocols: asking for a message link
    /// over one is a harness bug and must be reported as such rather than
    /// producing an empty data set that looks like a failed server.
    #[tokio::test]
    async fn raw_legs_have_no_message_link() {
        let e = ep();
        for leg in [Leg::RawTcp, Leg::RawUdp] {
            let r = connect_link(leg, &e, &[0u8; 64]).await;
            assert!(matches!(r, Err(CoreError::Unsupported(_))), "{leg}");
        }
    }

    /// Without a pinned certificate the QUIC leg must refuse before it touches
    /// the network. Connecting anyway — with verification off — would turn its
    /// handshake number into a measurement of something else entirely.
    #[tokio::test]
    async fn the_quic_leg_refuses_to_run_unpinned() {
        let e = ep();
        assert!(e.quic_cert.is_none());
        match connect_link(Leg::Quic, &e, &[0u8; 64]).await {
            Err(CoreError::ConfigError(msg)) => assert!(msg.contains("certificate"), "{msg}"),
            Err(other) => panic!("an unpinned QUIC leg must be a config error, got {other:?}"),
            Ok(_) => panic!("an unpinned QUIC leg must not connect at all"),
        }
    }
}
