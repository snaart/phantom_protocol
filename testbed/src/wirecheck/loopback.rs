//! The same wire check, on one machine, with no privileges and no far end.
//!
//! The probe's [`wire_capture`](crate::probe::scenarios::wire_capture) scenario
//! answers the question on a real path, and it needs two things most people do
//! not have to hand: a daemon on the other side of the internet, and the right
//! to open a BPF device. A check nobody can run is a check nobody runs. This
//! module is the version anyone can run:
//! `cargo run --bin phantom-wirecheck`, no arguments, no `sudo`.
//!
//! ## Where the capture comes from
//!
//! Not from `tcpdump`. The client is pointed at a **relay** — an ordinary UDP
//! socket that forwards every datagram between the session's two ends and
//! writes each one into a classic-pcap file as it goes. Opening a UDP socket
//! needs no rights at all, so the capture costs nothing but a hop, and the file
//! it writes is read by [`super::read_pcap`] and searched by [`super::analyze`]
//! — the same two functions the privileged path uses. There is one analysis in
//! this repository, not two.
//!
//! What the relay records is the datagram exactly as it crossed: those bytes
//! are forwarded verbatim. The link, IP and UDP headers around them are the
//! relay's own reconstruction, and it names the session's two real endpoints
//! rather than itself, because it is transparent and the datagram really was on
//! its way from one to the other. Nothing below the datagram — link-layer
//! padding, checksum offload, segmentation — is visible to it, and nothing
//! below the datagram is what this check is about.
//!
//! ## What a loopback capture proves
//!
//! That this build, driving a complete PhantomUDP session from handshake to
//! close, puts none of the application payloads it was given onto the wire in
//! the clear — and that the search which says so can find something, because
//! the same pass finds the build's `PROTOCOL_VARIANT` tag in the handshake. A
//! run whose negative search is clean and whose positive control is missing is
//! reported as a failure, here exactly as there.
//!
//! ## What it does not prove
//!
//! - **Nothing about the `ENCRYPTED` flag.** Header protection masks all
//!   fifteen header bytes, so no capture can read it. That question is answered
//!   from the source; [`super::ENCRYPTED_FLAG_STATEMENT`] says where, and every
//!   record carries it verbatim.
//! - **Nothing about a real path.** Loopback has microsecond RTT, no loss, no
//!   reordering and no NAT, so the packets a real path forces — retransmissions,
//!   fragments, path validations, a migration — barely occur here or do not
//!   occur at all. Those are code paths that *build packets*, and a leak
//!   confined to one of them would be invisible to this run. That is the
//!   general rule this repository has already paid for once, and it applies to
//!   a security check as much as to a throughput figure.
//! - **Only PhantomUDP.** The TCP, mimicry and WASI transports are not
//!   exercised. The relay forwards datagrams; a byte-stream leg would need a
//!   different one.
//! - **Only the traffic one short exchange produces.** A packet type this
//!   exchange never emits has not been examined.
//!
//! Everything in that list is reachable by the privileged scenario on the WAN
//! host, and none of it is reachable here. This is the cheap check that runs
//! every time, not the expensive one that runs when it matters.
//!
//! ## Continuous integration
//!
//! This one can run there, and does: the tests at the bottom of this file drive
//! the whole check — relay, capture, search, verdict — under `cargo test
//! --manifest-path testbed/Cargo.toml`, which is CI's `testbed-check` job. They
//! need loopback sockets and nothing else.
//!
//! The `tcpdump` path cannot be wired in on the same terms. Capturing needs
//! `cap_net_raw` or root; some hosted runners would grant it through
//! passwordless `sudo`, but a security check that only runs as root is one that
//! gets switched off the first time it is inconvenient. So the privileged path
//! stays the operator's, and the unprivileged one is what guards the property
//! on every commit.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use phantom_protocol::api::session::PhantomSession;
use phantom_protocol::api::udp_listener::PhantomUdpListener;
use phantom_protocol::transport::handshake::PROTOCOL_VARIANT;
use tokio::net::UdpSocket;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use super::{analyze, needles_for, probe_marker, Findings, PROBE_PAYLOAD_BYTES};
use crate::proto::PayloadGen;
use crate::report::{unix_nanos, ClientMetrics, Leg, WireCheckSample};

/// Application messages the default run drives through the session.
///
/// Enough that the established phase is not one packet wide, few enough that
/// the whole check finishes in well under a second.
pub const DEFAULT_MESSAGES: usize = 8;

/// How long any single step of the exchange may take before the run gives up.
///
/// Generous for loopback by three orders of magnitude: the point is to fail
/// with a sentence rather than to hang a CI job, not to measure anything.
const STEP_TIMEOUT: Duration = Duration::from_secs(10);

/// Time allowed for the closing frames to reach the relay after the session is
/// told to close. Without it the tail of the exchange is missing from exactly
/// the phase being searched.
const DRAIN: Duration = Duration::from_millis(200);

/// Largest datagram the relay will forward.
///
/// A datagram longer than this would be truncated by the receive that carries
/// it, so the figure is set far above PhantomUDP's own 1200-byte path MTU
/// rather than near it — the relay must not be the thing that reshapes the
/// traffic being examined.
const RELAY_BUFFER: usize = 4096;

// ── pcap writing ────────────────────────────────────────────────────────────

/// `DLT_NULL`: a four-byte address family, then the IP packet.
///
/// Chosen because it is what a BSD loopback capture uses, so the file this
/// writes is the same shape as one `tcpdump -i lo0` would produce and
/// [`super::read_pcap`] already handles it with no special case.
pub const LINK_TYPE_NULL: u32 = 0;

/// `AF_INET`, written in the host byte order `DLT_NULL` specifies.
const AF_INET: u32 = 2;

/// The 24-byte classic-pcap file header, little-endian, microsecond stamps.
fn pcap_file_header() -> Vec<u8> {
    let mut out = Vec::with_capacity(24);
    out.extend_from_slice(&0xa1b2_c3d4u32.to_le_bytes());
    out.extend_from_slice(&2u16.to_le_bytes());
    out.extend_from_slice(&4u16.to_le_bytes());
    out.extend_from_slice(&0i32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&65_535u32.to_le_bytes());
    out.extend_from_slice(&LINK_TYPE_NULL.to_le_bytes());
    out
}

/// Wrap one forwarded datagram as a loopback frame: `AF_INET`, an IPv4 header,
/// a UDP header, then the payload byte for byte.
///
/// The two checksums are left zero. Nothing reads them — this file exists to be
/// searched and to be opened in a packet analyser, and both tolerate it — and
/// computing them would invent a second thing that could be wrong.
fn loopback_frame(src: SocketAddr, dst: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let (sip, dip) = match (src.ip(), dst.ip()) {
        (IpAddr::V4(s), IpAddr::V4(d)) => (s, d),
        // The runner binds loopback IPv4 on both ends, so this is unreachable
        // in practice; mapping to the loopback address keeps the frame
        // well-formed rather than half-written if that ever changes.
        _ => (Ipv4Addr::LOCALHOST, Ipv4Addr::LOCALHOST),
    };
    let udp_len = u16::try_from(8 + payload.len()).unwrap_or(u16::MAX);
    let ip_len = u16::try_from(20 + 8 + payload.len()).unwrap_or(u16::MAX);

    let mut f = Vec::with_capacity(32 + payload.len());
    f.extend_from_slice(&AF_INET.to_ne_bytes());

    f.push(0x45);
    f.push(0);
    f.extend_from_slice(&ip_len.to_be_bytes());
    f.extend_from_slice(&0u16.to_be_bytes()); // identification
    f.extend_from_slice(&0u16.to_be_bytes()); // flags + fragment offset
    f.push(64); // TTL
    f.push(17); // UDP
    f.extend_from_slice(&0u16.to_be_bytes()); // header checksum
    f.extend_from_slice(&sip.octets());
    f.extend_from_slice(&dip.octets());

    f.extend_from_slice(&src.port().to_be_bytes());
    f.extend_from_slice(&dst.port().to_be_bytes());
    f.extend_from_slice(&udp_len.to_be_bytes());
    f.extend_from_slice(&0u16.to_be_bytes()); // UDP checksum

    f.extend_from_slice(payload);
    f
}

/// Append one record, stamped with the host's realtime clock.
///
/// The same clock stamps [`WireCheckSample::established_unix_ns`], which is what
/// makes the handshake/established split exact rather than estimated.
fn append_record(buf: &mut Vec<u8>, frame: &[u8]) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO);
    let len = u32::try_from(frame.len()).unwrap_or(u32::MAX);
    let secs = u32::try_from(now.as_secs()).unwrap_or(u32::MAX);
    buf.extend_from_slice(&secs.to_le_bytes());
    buf.extend_from_slice(&now.subsec_micros().to_le_bytes());
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(&frame[..len as usize]);
}

// ── The relay ───────────────────────────────────────────────────────────────

/// A transparent UDP forwarder that writes a pcap of everything it carries.
///
/// The client is given [`Relay::addr`] as the server's address; the relay hands
/// each datagram on to the real server and each reply back, recording both.
pub struct Relay {
    addr: SocketAddr,
    stop: Option<oneshot::Sender<()>>,
    task: JoinHandle<Vec<u8>>,
}

impl Relay {
    /// Start forwarding to `upstream`, capturing as it goes.
    pub async fn start(upstream: SocketAddr) -> std::io::Result<Self> {
        let front = UdpSocket::bind("127.0.0.1:0").await?;
        let addr = front.local_addr()?;
        let back = UdpSocket::bind("127.0.0.1:0").await?;
        back.connect(upstream).await?;

        let (stop_tx, mut stop_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            let mut capture = pcap_file_header();
            // One buffer per direction: the two arms of the select below borrow
            // theirs at the same time.
            let mut c2s = vec![0u8; RELAY_BUFFER];
            let mut s2c = vec![0u8; RELAY_BUFFER];
            let mut client: Option<SocketAddr> = None;
            loop {
                tokio::select! {
                    _ = &mut stop_rx => break,
                    r = front.recv_from(&mut c2s) => {
                        let Ok((n, from)) = r else { break };
                        client = Some(from);
                        append_record(&mut capture, &loopback_frame(from, upstream, &c2s[..n]));
                        if back.send(&c2s[..n]).await.is_err() {
                            break;
                        }
                    }
                    r = back.recv(&mut s2c) => {
                        let Ok(n) = r else { break };
                        let Some(to) = client else { continue };
                        append_record(&mut capture, &loopback_frame(upstream, to, &s2c[..n]));
                        if front.send_to(&s2c[..n], to).await.is_err() {
                            break;
                        }
                    }
                }
            }
            capture
        });

        Ok(Self {
            addr,
            stop: Some(stop_tx),
            task,
        })
    }

    /// Where the client should send. Standing in for the server's own address.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Stop forwarding and take the capture.
    pub async fn finish(mut self) -> Vec<u8> {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        // A relay task that has already returned — because a socket died — is
        // not a reason to lose what it captured before that, so a join error
        // yields an empty capture and the analysis reports the empty file for
        // what it is rather than this function inventing a verdict.
        self.task.await.unwrap_or_default()
    }
}

// ── The run ─────────────────────────────────────────────────────────────────

/// One loopback wire check, from binding the listener to the verdict.
///
/// Returns the same [`WireCheckSample`] the WAN scenario records, so the two
/// are read — and rendered, by [`super::report_lines`] — identically.
pub async fn run(messages: usize, keep_capture_at: Option<&Path>) -> WireCheckSample {
    // One nonce per run, so two runs never share a needle and a hit in an old
    // capture cannot be mistaken for a hit in this one.
    let nonce = unix_nanos();
    let listener = match PhantomUdpListener::bind_udp("127.0.0.1:0".to_string()).await {
        Ok(l) => l,
        Err(e) => return skipped(format!("could not bind a loopback listener: {e}")),
    };
    let server_addr: SocketAddr = match listener.local_addr().parse() {
        Ok(a) => a,
        Err(e) => {
            return skipped(format!(
                "the listener reported an address that will not parse: {e}"
            ))
        }
    };
    let pin = listener.verifying_key_bytes();

    let relay = match Relay::start(server_addr).await {
        Ok(r) => r,
        Err(e) => return skipped(format!("could not start the capturing relay: {e}")),
    };
    let relay_addr = relay.addr();

    // The server: accept one session and echo whatever arrives. `send()` does
    // not preserve message boundaries, so echoing chunk for chunk is the only
    // thing that is correct without framing — and the client below reassembles
    // by counting bytes for the same reason.
    let server = tokio::spawn(async move {
        let outcome = match listener.clone().accept().await {
            Ok(o) => o,
            Err(_) => return,
        };
        let session = outcome.session();
        while let Ok(chunk) = session.recv().await {
            if session.send(chunk).await.is_err() {
                break;
            }
        }
    });

    // Every payload is built before any of them touches the network, so the
    // bytes searched for are the bytes sent rather than a regeneration of them.
    let mut gen = PayloadGen::new(nonce);
    let probes: Vec<(String, Vec<u8>)> = (0..messages)
        .map(|i| {
            let marker = probe_marker(nonce, i);
            let mut payload = marker.as_bytes().to_vec();
            payload.extend_from_slice(&gen.fill(PROBE_PAYLOAD_BYTES.saturating_sub(marker.len())));
            (marker, payload)
        })
        .collect();
    let needles = needles_for(&probes, PROTOCOL_VARIANT);

    let session =
        phantom_protocol::connect_pinned_udp("127.0.0.1".to_string(), relay_addr.port(), pin).await;
    let session = match session {
        Ok(s) => s,
        Err(e) => {
            server.abort();
            let _ = relay.finish().await;
            return skipped(format!("the loopback session could not be started: {e}"));
        }
    };
    // `connect_pinned_udp` returns before the handshake has run, so the pin is
    // not yet known to have held. Waiting here is what makes the split instant
    // below mean what it says.
    match tokio::time::timeout(STEP_TIMEOUT, session.await_ready()).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            server.abort();
            let _ = relay.finish().await;
            return skipped(format!("the loopback handshake failed: {e}"));
        }
        Err(_) => {
            server.abort();
            let _ = relay.finish().await;
            return skipped("the loopback handshake did not complete in time".to_string());
        }
    }

    let established_unix_ns = unix_nanos();

    let mut echo_ok = 0usize;
    let mut echo_failed = 0usize;
    for (_, payload) in &probes {
        if echo_once(&session, payload).await {
            echo_ok += 1;
        } else {
            echo_failed += 1;
        }
    }

    let counters: ClientMetrics = session.metrics_snapshot().into();
    let _ = session.disconnect().await;
    tokio::time::sleep(DRAIN).await;
    server.abort();

    let capture = relay.finish().await;
    let capture_path = keep_capture_at.and_then(|p| write_capture(p, &capture));
    let findings = match analyze(&capture, &needles, established_unix_ns) {
        Ok(f) => f,
        Err(e) => Findings::skipped(format!("the capture could not be read: {e}")),
    };

    WireCheckSample {
        leg: Leg::Udp,
        t_unix_ns: unix_nanos(),
        established_unix_ns,
        probe_messages: probes.len(),
        probe_payload_bytes: PROBE_PAYLOAD_BYTES,
        echo_ok,
        echo_failed,
        capture_command: COMMAND.to_string(),
        capture_path,
        findings,
        session_counters: Some(counters),
    }
}

/// How this record was produced, in the slot the privileged path fills with its
/// `tcpdump` line — so the artifact always says where its evidence came from.
const COMMAND: &str =
    "phantom-wirecheck (in-process loopback session; the capture is written by the \
     forwarding relay, not by tcpdump)";

/// Send one payload and read the echo back, byte for byte.
///
/// Reassembles by counting rather than trusting one `recv()` to return one
/// `send()`: the pump splits at `MAX_APP_CHUNK` and preserves no message
/// boundary, and a harness that assumed otherwise would silently compare a
/// prefix.
async fn echo_once(session: &Arc<PhantomSession>, payload: &[u8]) -> bool {
    if tokio::time::timeout(STEP_TIMEOUT, session.send(payload.to_vec()))
        .await
        .map(|r| r.is_err())
        .unwrap_or(true)
    {
        return false;
    }
    let mut back = Vec::with_capacity(payload.len());
    while back.len() < payload.len() {
        match tokio::time::timeout(STEP_TIMEOUT, session.recv()).await {
            Ok(Ok(chunk)) => back.extend_from_slice(&chunk),
            _ => return false,
        }
    }
    back == payload
}

/// Keep the capture next to whatever asked for it, and report where it went.
///
/// A path that cannot be written is not worth failing the check over — the
/// analysis has already run over the bytes in memory — but it must not be
/// reported as a file that exists either, so the slot stays empty.
fn write_capture(path: &Path, capture: &[u8]) -> Option<String> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() && std::fs::create_dir_all(parent).is_err() {
            return None;
        }
    }
    std::fs::write(path, capture)
        .ok()
        .map(|()| path.display().to_string())
}

/// A run that never reached the wire, with the reason that will be recorded.
fn skipped(why: String) -> WireCheckSample {
    WireCheckSample {
        leg: Leg::Udp,
        t_unix_ns: unix_nanos(),
        established_unix_ns: 0,
        probe_messages: 0,
        probe_payload_bytes: PROBE_PAYLOAD_BYTES,
        echo_ok: 0,
        echo_failed: 0,
        capture_command: COMMAND.to_string(),
        capture_path: None,
        findings: Findings::skipped(why),
        session_counters: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wirecheck::{Polarity, Verdict};

    /// Drive `messages` payloads through a **plaintext** UDP echo behind the
    /// same relay, and analyse the capture with the same needles.
    ///
    /// This is the check applied to a transport that is known to leak, and it
    /// is the only thing that makes the real run's clean result mean anything:
    /// it shows the relay, the pcap writer, the reader, the decoders and the
    /// search can all find an application payload when one is there.
    async fn plaintext_run(messages: usize) -> Findings {
        let echo = UdpSocket::bind("127.0.0.1:0").await.expect("bind echo");
        let echo_addr = echo.local_addr().expect("echo addr");
        tokio::spawn(async move {
            let mut buf = vec![0u8; RELAY_BUFFER];
            while let Ok((n, from)) = echo.recv_from(&mut buf).await {
                if echo.send_to(&buf[..n], from).await.is_err() {
                    break;
                }
            }
        });

        let relay = Relay::start(echo_addr).await.expect("relay");
        let relay_addr = relay.addr();

        let nonce = unix_nanos();
        let mut gen = PayloadGen::new(nonce);
        let probes: Vec<(String, Vec<u8>)> = (0..messages)
            .map(|i| {
                let marker = probe_marker(nonce, i);
                let mut payload = marker.as_bytes().to_vec();
                payload
                    .extend_from_slice(&gen.fill(PROBE_PAYLOAD_BYTES.saturating_sub(marker.len())));
                (marker, payload)
            })
            .collect();
        let needles = needles_for(&probes, PROTOCOL_VARIANT);

        let client = UdpSocket::bind("127.0.0.1:0").await.expect("bind client");
        client.connect(relay_addr).await.expect("connect client");
        // The control belongs where the real run puts it: in the first
        // datagram, before the split instant.
        client.send(PROTOCOL_VARIANT).await.expect("send control");
        let mut buf = vec![0u8; RELAY_BUFFER];
        let _ = tokio::time::timeout(STEP_TIMEOUT, client.recv(&mut buf)).await;

        let established_unix_ns = unix_nanos();
        for (_, payload) in &probes {
            client.send(payload).await.expect("send payload");
            let _ = tokio::time::timeout(STEP_TIMEOUT, client.recv(&mut buf)).await;
        }
        tokio::time::sleep(DRAIN).await;

        let capture = relay.finish().await;
        analyze(&capture, &needles, established_unix_ns).expect("analyze")
    }

    /// The capability proof. Without this passing, every clean result below is
    /// a search that was never shown able to find anything.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_loopback_capture_finds_application_bytes_when_the_transport_sends_them_in_the_clear(
    ) {
        let f = plaintext_run(3).await;
        assert_eq!(
            f.verdict,
            Verdict::Failed,
            "a plaintext echo must be caught: {f:?}"
        );
        assert!(
            f.reasons
                .iter()
                .any(|r| r.contains("plaintext on the wire")),
            "and named as such: {:?}",
            f.reasons
        );
        let leaked = f
            .needles
            .iter()
            .filter(|n| n.polarity == Polarity::MustNotAppear && n.frames_hit > 0)
            .count();
        assert_eq!(
            leaked, 6,
            "both needles of all three messages — whole payload and leading marker: {:?}",
            f.needles
        );
        assert!(
            f.needles
                .iter()
                .filter(|n| n.polarity == Polarity::MustNotAppear)
                .all(|n| n.hits_in_established > 0),
            "and after the split instant, where the search is aimed: {:?}",
            f.needles
        );
    }

    /// The check itself: a real PhantomUDP session, the same relay, the same
    /// analysis.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_phantom_udp_session_puts_no_application_bytes_on_the_loopback_wire() {
        let sample = run(DEFAULT_MESSAGES, None).await;
        let f = &sample.findings;
        assert_eq!(
            f.verdict,
            Verdict::Pass,
            "reasons: {:?}; sample: {sample:?}",
            f.reasons
        );
        assert_eq!(
            sample.echo_ok, DEFAULT_MESSAGES,
            "every payload must have made a byte-exact round trip, or the \
             capture holds less traffic than the verdict claims"
        );
        assert_eq!(sample.echo_failed, 0);
    }

    /// The rule that makes the result above worth reading, asserted on the run
    /// that produced it rather than on a constructed capture.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn the_real_run_fires_its_positive_control_in_the_handshake() {
        let sample = run(2, None).await;
        let control = sample
            .findings
            .needles
            .iter()
            .find(|n| n.polarity == Polarity::MustAppear)
            .expect("the needle set always leads with the control");
        assert!(
            control.frames_hit > 0,
            "the protocol-variant tag must be found, or nothing else in this run \
             means anything: {control:?}"
        );
        assert!(
            control.hits_in_handshake > 0,
            "and it belongs before the split instant, in the signed-but-unencrypted \
             ClientHello: {control:?}"
        );
        assert!(
            sample.findings.established_frames > 0,
            "a capture with no post-handshake traffic proves nothing about \
             application bytes: {:?}",
            sample.findings
        );
    }

    /// The relay's file has to be a capture the shared reader understands, or
    /// the entropy half of the record is computed over nothing.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn every_recorded_datagram_decodes_to_a_transport_payload() {
        let sample = run(2, None).await;
        let f = &sample.findings;
        assert_eq!(f.link_type, LINK_TYPE_NULL);
        assert_eq!(f.link_type_name, "NULL");
        assert_eq!(
            f.frames_decoded, f.frames_total,
            "the writer and the reader must agree on every frame: {:?}",
            f.undecodable
        );
        assert!(
            !f.capture_truncated,
            "the relay closes its own file, so nothing should end mid-record"
        );
        assert!(
            f.established_entropy.full_scale_payloads > 0,
            "the 1 KiB payloads must reach the phase where 8 bits/byte is \
             possible: {:?}",
            f.established_entropy
        );
    }

    /// Both directions have to be in the file. A relay that recorded only what
    /// the client sent would still report a clean negative search, and would
    /// still be half a capture — the server's replies are where a leak in the
    /// download direction would live.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_relay_records_one_frame_each_way_with_the_endpoints_the_right_way_round() {
        let echo = UdpSocket::bind("127.0.0.1:0").await.expect("bind echo");
        let echo_addr = echo.local_addr().expect("echo addr");
        tokio::spawn(async move {
            let mut buf = vec![0u8; RELAY_BUFFER];
            if let Ok((n, from)) = echo.recv_from(&mut buf).await {
                let _ = echo.send_to(&buf[..n], from).await;
            }
        });

        let relay = Relay::start(echo_addr).await.expect("relay");
        let client = UdpSocket::bind("127.0.0.1:0").await.expect("bind client");
        let client_addr = client.local_addr().expect("client addr");
        client.connect(relay.addr()).await.expect("connect");
        client.send(b"one datagram").await.expect("send");
        let mut buf = vec![0u8; RELAY_BUFFER];
        let n = tokio::time::timeout(STEP_TIMEOUT, client.recv(&mut buf))
            .await
            .expect("the echo must come back")
            .expect("recv");
        assert_eq!(&buf[..n], b"one datagram");

        let capture = relay.finish().await;
        let pcap = super::super::read_pcap(&capture).expect("read back");
        assert_eq!(pcap.frames.len(), 2, "one frame each way");

        // Ports, read out of the synthetic UDP headers the writer produced, are
        // what say which way each frame went.
        let ports = |frame: &[u8]| -> (u16, u16) {
            let udp = &frame[24..28];
            (
                u16::from_be_bytes([udp[0], udp[1]]),
                u16::from_be_bytes([udp[2], udp[3]]),
            )
        };
        assert_eq!(
            ports(pcap.frames[0].bytes),
            (client_addr.port(), echo_addr.port()),
            "the first frame is the client's, addressed to the server rather than to the relay"
        );
        assert_eq!(
            ports(pcap.frames[1].bytes),
            (echo_addr.port(), client_addr.port()),
            "and the second is the reply, the other way round"
        );
    }

    /// A capture that cannot be kept must not be reported as a file that
    /// exists: a path in the record is an invitation to go and open it.
    #[test]
    fn a_capture_path_that_cannot_be_written_is_left_empty_rather_than_claimed() {
        assert_eq!(write_capture(Path::new(""), b"anything"), None);

        let dir = std::env::temp_dir().join(format!("wirecheck-{}", unix_nanos()));
        let path = dir.join("kept.pcap");
        let reported = write_capture(&path, b"bytes").expect("a writable path is reported");
        assert_eq!(reported, path.display().to_string());
        assert_eq!(
            std::fs::read(&path).expect("the file is really there"),
            b"bytes"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A run that could not reach the wire is an absence with a cause, never a
    /// pass — the same rule the privileged path follows when it cannot capture.
    #[test]
    fn a_run_that_never_reached_the_wire_is_a_skip_carrying_its_reason() {
        let s = skipped("the loopback handshake failed: nope".to_string());
        assert_eq!(s.findings.verdict, Verdict::Skipped);
        assert_eq!(s.echo_ok, 0);
        assert!(s.capture_path.is_none());
        assert!(s.findings.reasons.iter().any(|r| r.contains("nope")));
        assert!(
            !s.findings.encrypted_flag.is_empty(),
            "and it still carries the statement about the flag no capture can read"
        );
    }

    /// The synthetic headers have to be the ones the shared decoder expects,
    /// down to the byte, or a real run would report every frame undecodable and
    /// still pass its negative search.
    #[test]
    fn a_recorded_frame_decodes_back_to_exactly_the_payload_that_was_forwarded() {
        let src: SocketAddr = "127.0.0.1:40000".parse().expect("src");
        let dst: SocketAddr = "127.0.0.1:4243".parse().expect("dst");
        let payload = b"the exact bytes that crossed".to_vec();
        let frame = loopback_frame(src, dst, &payload);

        let range = super::super::transport_payload(LINK_TYPE_NULL, &frame)
            .expect("the shared decoder must accept the shared writer's output");
        assert_eq!(&frame[range], &payload[..]);

        let mut file = pcap_file_header();
        append_record(&mut file, &frame);
        let pcap = super::super::read_pcap(&file).expect("read back");
        assert_eq!(pcap.link_type, LINK_TYPE_NULL);
        assert_eq!(pcap.frames.len(), 1);
        assert!(!pcap.truncated);
        assert_eq!(pcap.frames[0].bytes, &frame[..]);
    }
}
