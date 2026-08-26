//! The QUIC reference leg.
//!
//! ## Why this exists
//!
//! Every other number this harness produces is either the protocol under test
//! or a raw socket carrying nothing. Between those two lies the question that
//! actually matters — *how does this compare with a mature implementation of
//! the same class?* — and until now the only answers available were opinions.
//! This leg turns it into a measurement: `quinn`, over the same path, in the
//! same run, driving the same application protocol.
//!
//! It is a **reference**, not a competitor and not a control. It carries a full
//! transport (reliable, encrypted, multiplexed, over UDP), so unlike the raw
//! legs it is not a denominator; and it is not the protocol under test, so a
//! result here is never a result *about* Phantom except by comparison.
//!
//! ## What the comparison controls for, and what it does not
//!
//! Controlled: the path, the wall-clock window, the application protocol, the
//! frame sizes, the byte budgets, the measurement code. `upload`, `download`
//! and `bidir` count the same messages over the same framing on both legs, and
//! the daemon runs the *same* session handler behind both.
//!
//! Not controlled, and not controllable:
//!
//! - **Cryptography.** quinn is TLS 1.3 with classical primitives (X25519,
//!   Ed25519/ECDSA). Phantom does a hybrid post-quantum key exchange
//!   (X25519+ML-KEM-768, Ed25519+ML-DSA-65) and signs a ~4 KB hybrid signature
//!   into its handshake. The handshake latencies are therefore **not comparable
//!   like-for-like and the difference is expected**; throughput and loss
//!   behaviour are comparable.
//! - **Congestion control.** quinn ships Cubic (loss-based) by default and that
//!   default is deliberately left alone — the point is to measure the
//!   implementation as it is shipped. Phantom's is BBR-style. Their congestion
//!   windows are not the same statistic; compare outcomes, not curves.
//! - **Flow control.** quinn's default stream receive window is 1.25 MB, which
//!   on a 250 ms path is a hard ~40 Mbit/s ceiling regardless of the link. That
//!   would be measuring quinn's default sizing, not the path — the same trap
//!   the raw TCP control fell into twice with its socket buffers. So the windows
//!   are raised here, symmetrically, to 8 MiB. This is the one tuning knob
//!   touched, and it is touched to *stop* the reference being handicapped.
//!
//! ## Certificates
//!
//! The daemon mints a self-signed certificate on first run and persists it
//! (0600 for the key) exactly as it persists the Phantom signing seed, so its
//! QUIC identity survives a restart. The probe **pins that certificate**: it is
//! the sole trust anchor in an otherwise empty root store, and rustls performs
//! ordinary path and name validation against it. Verification is not disabled,
//! stubbed, or bypassed anywhere in this module, which is what makes the
//! handshake number a real TLS handshake — a probe with no certificate to pin
//! does not connect at all, and the leg is skipped with a recorded note.
//!
//! ## What quinn can and cannot report
//!
//! [`quinn::Connection::stats`] gives a path RTT, a congestion window, and
//! cumulative loss counters. It exposes no bytes-in-flight, no bandwidth
//! estimate, no pacing rate, no delivery total and no app-limited flag, so
//! those [`WindowSample`] fields are left zero rather than filled with
//! something invented. The loss counters have no home in that record and are
//! reported per transfer as scenario notes instead.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use phantom_protocol::CoreError;
use quinn::{ConnectionError, RecvStream, SendStream, TransportErrorCode};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::sync::Mutex;

use crate::framing::{BoxFut, MsgLink, Reassembler};
use crate::proto::Msg;
use crate::report::{unix_nanos, Leg, WindowSample};

/// ALPN both ends require. Not security-relevant; it keeps a stray QUIC client
/// from being served by accident and makes the leg identifiable on the wire.
pub const ALPN: &[u8] = b"phantom-testbed/1";

/// The name in the daemon certificate's SAN, and the name the probe asks for.
///
/// Fixed rather than derived from the host: the daemon binds `0.0.0.0` and has
/// no reliable idea what name or address a probe will reach it by, while
/// quinn takes the socket address and the server name as separate arguments.
/// So the address is dialled and *this* name is validated, against a
/// certificate that is itself the only trust anchor.
pub const SERVER_NAME: &str = "phantom-testd";

/// Flow-control window, both directions, both ends.
///
/// Sized well past the ~1 MB bandwidth-delay product of a 250 ms / 34 Mbit/s
/// path so that flow control is never the binding constraint, for the reason a
/// receive window has to be sized at all: a measurement bounded by a default
/// buffer reports the buffer, not the link.
///
/// Not the same figure the raw TCP control asks for, and the difference is not
/// an oversight. That control asks for 1 MiB because it also *sends*, and at
/// 8 MiB it filled its own send buffer, made the queue into the round trip, and
/// reported 1.34 Mbit/s on a link carrying 9.5. A receive window has no such
/// failure mode: nothing here queues behind it.
const FLOW_WINDOW: u64 = 8 * 1024 * 1024;

/// Idle timeout. Long enough to survive the gaps between scenario phases on a
/// high-latency path, short enough that an abandoned connection does not hold a
/// daemon session slot for the rest of the run.
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// Keep-alive interval, comfortably inside [`IDLE_TIMEOUT`].
const KEEP_ALIVE: Duration = Duration::from_secs(15);

/// Ceiling on a graceful connection close.
const CLOSE_TIMEOUT: Duration = Duration::from_secs(2);

/// Application error code used for every clean close.
const CLOSE_CODE: u32 = 0;

// ── Identity ────────────────────────────────────────────────────────────────

/// The daemon's QUIC identity: a self-signed certificate and its key, in DER.
pub struct QuicIdentity {
    pub cert_der: Vec<u8>,
    pub key_der: Vec<u8>,
}

/// Mint a fresh self-signed certificate for [`SERVER_NAME`].
pub fn generate_identity() -> Result<QuicIdentity> {
    let key = rcgen::KeyPair::generate().context("generate QUIC key pair")?;
    let cert = rcgen::CertificateParams::new(vec![SERVER_NAME.to_string()])
        .context("QUIC certificate parameters")?
        .self_signed(&key)
        .context("self-sign QUIC certificate")?;
    Ok(QuicIdentity {
        cert_der: cert.der().to_vec(),
        key_der: key.serialize_der(),
    })
}

/// Load the persisted certificate and key, or mint and persist a pair.
///
/// Mirrors the Phantom signing seed: the identity survives a restart, so a
/// probe's pin keeps working and a run that spans a daemon restart is not
/// silently comparing two different servers. The key is written 0600; the
/// certificate is public by construction.
pub fn load_or_create_identity(cert_path: &Path, key_path: &Path) -> Result<QuicIdentity> {
    if cert_path.exists() && key_path.exists() {
        let cert_der =
            std::fs::read(cert_path).with_context(|| format!("read {}", cert_path.display()))?;
        let key_der =
            std::fs::read(key_path).with_context(|| format!("read {}", key_path.display()))?;
        anyhow::ensure!(
            !cert_der.is_empty() && !key_der.is_empty(),
            "empty QUIC certificate or key in {}",
            cert_path.display()
        );
        return Ok(QuicIdentity { cert_der, key_der });
    }

    let id = generate_identity()?;
    if let Some(parent) = cert_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    std::fs::write(cert_path, &id.cert_der)
        .with_context(|| format!("write {}", cert_path.display()))?;
    write_private(key_path, &id.key_der)?;
    Ok(id)
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(path)
        .with_context(|| format!("create {}", path.display()))?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}

// ── Configuration ───────────────────────────────────────────────────────────

/// Transport parameters shared by both ends. See [`FLOW_WINDOW`].
fn transport_config() -> quinn::TransportConfig {
    let mut tc = quinn::TransportConfig::default();
    tc.stream_receive_window(FLOW_WINDOW.try_into().unwrap_or(quinn::VarInt::MAX));
    tc.receive_window((FLOW_WINDOW * 2).try_into().unwrap_or(quinn::VarInt::MAX));
    tc.send_window(FLOW_WINDOW * 2);
    if let Ok(t) = IDLE_TIMEOUT.try_into() {
        tc.max_idle_timeout(Some(t));
    }
    tc.keep_alive_interval(Some(KEEP_ALIVE));
    tc
}

/// The rustls crypto provider, named explicitly.
///
/// `rustls::ClientConfig::builder()` reads a process-global default provider,
/// which is a footgun in a binary that also links another TLS-adjacent stack.
/// Naming ring here means this module's behaviour does not depend on what else
/// happens to be in the process.
fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Server config presenting `identity`, TLS 1.3 only.
pub fn server_config(identity: &QuicIdentity) -> Result<quinn::ServerConfig> {
    let cert = CertificateDer::from(identity.cert_der.clone());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(identity.key_der.clone()));

    let mut tls = rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .context("QUIC server TLS versions")?
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .context("QUIC server certificate")?;
    tls.alpn_protocols = vec![ALPN.to_vec()];

    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)
        .context("QUIC server crypto config")?;
    let mut cfg = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    cfg.transport_config(Arc::new(transport_config()));
    Ok(cfg)
}

/// Client config that trusts **only** `cert_der`, TLS 1.3 only.
///
/// The pinned certificate is the entire root store, so a server presenting
/// anything else fails validation. This is stricter than ordinary PKI
/// verification, not weaker than it, and no custom verifier is involved: rustls
/// runs its own path and name checks unmodified.
pub fn client_config(cert_der: &[u8]) -> Result<quinn::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from(cert_der.to_vec()))
        .context("pin the daemon's QUIC certificate")?;

    let mut tls = rustls::ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .context("QUIC client TLS versions")?
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![ALPN.to_vec()];

    let crypto =
        quinn::crypto::rustls::QuicClientConfig::try_from(tls).context("QUIC client crypto")?;
    let mut cfg = quinn::ClientConfig::new(Arc::new(crypto));
    cfg.transport_config(Arc::new(transport_config()));
    Ok(cfg)
}

// ── Error mapping ───────────────────────────────────────────────────────────

/// True when a QUIC connection error was raised by the TLS layer.
///
/// QUIC encodes a TLS alert as transport error code `0x100 | alert`, and
/// quinn's `TransportErrorCode` is opaque apart from the constructor, so the
/// membership test is the constructor run over the 256 possible alerts. Exact,
/// and specifically not a match on the error's prose.
fn is_tls_alert(code: TransportErrorCode) -> bool {
    (0u8..=255).any(|alert| code == TransportErrorCode::crypto(alert))
}

/// Classify a connection error into the harness's shared error type.
///
/// A certificate that does not match the pin is reported as
/// `ServerIdentityMismatch`, the same typed error the Phantom legs raise for a
/// failed pin, so the two are grouped together by analysis rather than one of
/// them hiding inside a generic network failure.
pub(crate) fn map_connection_error(e: &ConnectionError) -> CoreError {
    match e {
        ConnectionError::TransportError(t) if is_tls_alert(t.code) => {
            CoreError::ServerIdentityMismatch
        }
        ConnectionError::ConnectionClosed(f) if is_tls_alert(f.error_code) => {
            CoreError::ServerIdentityMismatch
        }
        ConnectionError::TimedOut => CoreError::Timeout,
        ConnectionError::LocallyClosed | ConnectionError::ApplicationClosed(_) => {
            CoreError::ConnectionClosed
        }
        other => CoreError::NetworkError(format!("quic: {other}")),
    }
}

// ── The link ────────────────────────────────────────────────────────────────

/// A QUIC connection carrying the testbed protocol over one bidirectional
/// stream.
///
/// One stream, not many: the Phantom legs put the whole conversation through a
/// single logical byte pipe, and giving QUIC a stream per message would be
/// measuring a different thing while calling it the same name.
pub struct QuicLink {
    /// The endpoint, when this link is the only thing using it.
    ///
    /// A client dials from its own endpoint and may therefore shut it down on
    /// close. The daemon's endpoint is shared by every accepted connection, so
    /// an accepted link holds `None` and closes only its own connection —
    /// closing the shared endpoint from one session's teardown would take every
    /// other session on the leg down with it, mid-run.
    owned_endpoint: Option<quinn::Endpoint>,
    conn: quinn::Connection,
    send: Mutex<SendStream>,
    recv: Mutex<RecvState>,
}

/// Receive-side state, including the read buffer.
///
/// The buffer lives here rather than in `recv()` because that function runs
/// once per logical message — hundreds of thousands of times across a bulk
/// transfer. Allocating 64 KiB on each call would put a cost inside the loop
/// being measured that the Phantom legs do not pay, quietly tilting the very
/// comparison this leg exists to make.
struct RecvState {
    stream: RecvStream,
    re: Reassembler,
    buf: Vec<u8>,
}

impl RecvState {
    /// Read size. Comfortably above the path MTU, so a busy stream is drained
    /// in few syscalls, and above the largest testbed frame in normal use.
    const READ_BUF: usize = 64 * 1024;

    fn new(stream: RecvStream) -> Self {
        Self {
            stream,
            re: Reassembler::default(),
            buf: vec![0u8; Self::READ_BUF],
        }
    }
}

impl QuicLink {
    /// Dial `addr`, verifying the server against the pinned certificate, and
    /// open the conversation's single bidirectional stream.
    ///
    /// Returns once the QUIC/TLS handshake has completed — unlike Phantom's
    /// `connect_pinned*`, quinn's `connect(..).await` really does mean the
    /// handshake ran, so no separate readiness wait is needed.
    pub async fn connect(addr: SocketAddr, cert_der: &[u8]) -> Result<Self, CoreError> {
        let cfg = client_config(cert_der)
            .map_err(|e| CoreError::ConfigError(format!("quic client config: {e}")))?;

        // A fresh endpoint — and therefore a fresh UDP socket — per connection,
        // matching what `connect_pinned_udp` does on the Phantom side. Sharing
        // one socket across connections would make the concurrency scenario
        // measure a different shape on the two legs.
        let bind: SocketAddr = if addr.is_ipv6() {
            "[::]:0"
                .parse()
                .unwrap_or(SocketAddr::from(([0, 0, 0, 0], 0)))
        } else {
            SocketAddr::from(([0, 0, 0, 0], 0))
        };
        let mut endpoint = quinn::Endpoint::client(bind)
            .map_err(|e| CoreError::NetworkError(format!("quic endpoint bind: {e}")))?;
        endpoint.set_default_client_config(cfg);

        let conn = endpoint
            .connect(addr, SERVER_NAME)
            .map_err(|e| CoreError::NetworkError(format!("quic connect {addr}: {e}")))?
            .await
            .map_err(|e| map_connection_error(&e))?;

        let (send, recv) = conn.open_bi().await.map_err(|e| map_connection_error(&e))?;
        Ok(Self {
            owned_endpoint: Some(endpoint),
            conn,
            send: Mutex::new(send),
            recv: Mutex::new(RecvState::new(recv)),
        })
    }

    /// Wrap an already-established connection and stream (the daemon side).
    ///
    /// The caller keeps the endpoint; see [`QuicLink::owned_endpoint`].
    pub fn accepted(conn: quinn::Connection, send: SendStream, recv: RecvStream) -> Self {
        Self {
            owned_endpoint: None,
            conn,
            send: Mutex::new(send),
            recv: Mutex::new(RecvState::new(recv)),
        }
    }

    pub fn remote_address(&self) -> SocketAddr {
        self.conn.remote_address()
    }

    pub fn stats(&self) -> quinn::ConnectionStats {
        self.conn.stats()
    }

    /// Cumulative loss as quinn sees it, for the notes a transfer leaves behind.
    ///
    /// These have no field in [`WindowSample`] and are not invented into one.
    pub fn loss_note(&self) -> String {
        let s = self.conn.stats();
        format!(
            "quinn path stats: {} packets sent, {} lost ({} B), {} congestion events, current MTU {} B, smoothed RTT {:.2} ms",
            s.path.sent_packets,
            s.path.lost_packets,
            s.path.lost_bytes,
            s.path.congestion_events,
            s.path.current_mtu,
            s.path.rtt.as_secs_f64() * 1e3,
        )
    }
}

impl MsgLink for QuicLink {
    fn protocol(&self) -> &'static str {
        "quic"
    }

    fn send_encoded(&self, wire: Vec<u8>) -> BoxFut<'_, Result<(), CoreError>> {
        Box::pin(async move {
            let mut s = self.send.lock().await;
            s.write_all(&wire)
                .await
                .map_err(|e| CoreError::NetworkError(format!("quic write: {e}")))
        })
    }

    fn recv(&self) -> BoxFut<'_, Result<(Msg, Arrival), CoreError>> {
        Box::pin(async move {
            let mut st = self.recv.lock().await;
            loop {
                if let Some(v) = st.re.take()? {
                    return Ok(v);
                }
                let RecvState { stream, re, buf } = &mut *st;
                match stream.read(buf).await {
                    // A clean stream end is the peer having finished: the same
                    // outcome the Phantom legs report as a closed connection,
                    // so it is reported the same way here.
                    Ok(None) => return Err(CoreError::ConnectionClosed),
                    Ok(Some(n)) => re.push_chunk(&buf[..n]),
                    Err(e) => {
                        return Err(match e {
                            quinn::ReadError::ConnectionLost(c) => map_connection_error(&c),
                            other => CoreError::NetworkError(format!("quic read: {other}")),
                        })
                    }
                }
            }
        })
    }

    fn transport_note(&self) -> Option<String> {
        Some(self.loss_note())
    }

    fn close(&self) -> BoxFut<'_, ()> {
        Box::pin(async move {
            let _ = self.send.lock().await.finish();
            self.conn.close(CLOSE_CODE.into(), b"bye");
            if let Some(ep) = &self.owned_endpoint {
                ep.close(CLOSE_CODE.into(), b"bye");
                // Bounded: `wait_idle` waits for the close to be acknowledged
                // or for the idle timeout, and the samples are already recorded.
                let _ = tokio::time::timeout(CLOSE_TIMEOUT, ep.wait_idle()).await;
            }
        })
    }

    /// See the module docs: only `cwnd_bytes` and `min_rtt_us` are real here,
    /// and `min_rtt_us` carries quinn's *smoothed* RTT.
    fn window_sample(
        &self,
        leg: Leg,
        phase: String,
        elapsed_ms: u64,
    ) -> BoxFut<'_, Option<WindowSample>> {
        let s = self.conn.stats();
        Box::pin(async move {
            Some(WindowSample {
                leg,
                phase,
                t_unix_ns: unix_nanos(),
                elapsed_ms,
                cwnd_bytes: s.path.cwnd,
                inflight_bytes: 0,
                bottleneck_bw_bps: 0,
                last_delivery_rate_bps: 0,
                // Zero rather than the library's horizon: quinn's controller has
                // no windowed maximum, so naming one here would attach a window
                // to a column that carries no reading.
                bw_filter_window_ms: 0,
                pacing_rate_bps: 0,
                min_rtt_us: s.path.rtt.as_micros() as u64,
                dry_passes_against_a_full_buffer: 0,
                app_limited_acked_bytes: 0,
                acked_bytes_total: 0,
                drain_outcomes: Vec::new(),
                smoothed_rtt_us: 0,
                rtt_variation_us: 0,
                delivered_bytes: 0,
                state: "quic:cubic".to_string(),
                app_limited: false,
                // Zero, and deliberately not quinn's `lost_packets`/`lost_bytes`.
                // Those are counted in quinn's own units, over quinn's own
                // packet-number space, and its detector is not the one these
                // columns describe — putting a differently-defined figure in a
                // shared column is how a cross-leg comparison comes to compare
                // two things. quinn's numbers travel as prose, in `loss_note`,
                // where their definition travels with them.
                bytes_retransmitted: 0,
                bytes_lost: 0,
                // Zero for the same reason and one more: the split names three
                // rules — this project's packet threshold, its RACK arm and its
                // RTO — and quinn's detector is not built from them, so a count
                // filed under any of the three would be a reading of a mechanism
                // that is not there.
                loss_declarations: 0,
                repairs_attributed: 0,
                declared_by_packet_threshold: 0,
                declared_by_time_threshold: 0,
                declared_by_rto: 0,
                inflight_hi_bytes: 0,
            })
        })
    }
}

pub use crate::framing::Arrival;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framing::encode_framed;
    use std::net::{IpAddr, Ipv4Addr};

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("tb-quic-{}-{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).expect("mkdir");
        d
    }

    #[test]
    fn a_minted_identity_configures_both_ends() {
        let id = generate_identity().expect("mint");
        assert!(!id.cert_der.is_empty() && !id.key_der.is_empty());
        server_config(&id).expect("server config accepts the minted pair");
        client_config(&id.cert_der).expect("client config pins the minted certificate");
    }

    /// The certificate must survive a restart, or every probe's pin would go
    /// stale the moment the daemon was bounced.
    #[test]
    fn the_identity_is_persisted_and_reloaded_unchanged() {
        let dir = tmpdir("persist");
        let cert = dir.join("quic-cert.der");
        let key = dir.join("quic-key.der");

        let a = load_or_create_identity(&cert, &key).expect("create");
        let b = load_or_create_identity(&cert, &key).expect("reload");
        assert_eq!(
            a.cert_der, b.cert_der,
            "reload must not mint a new identity"
        );
        assert_eq!(a.key_der, b.key_der);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn the_private_key_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmpdir("perm");
        let cert = dir.join("quic-cert.der");
        let key = dir.join("quic-key.der");
        load_or_create_identity(&cert, &key).expect("create");
        let mode = std::fs::metadata(&key).expect("stat").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "the QUIC key must not be group/world readable");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_certificate_that_is_not_a_certificate_is_rejected_at_config_time() {
        assert!(
            client_config(b"not a DER certificate").is_err(),
            "garbage must fail when the pin is loaded, not at the first handshake"
        );
    }

    /// The flow-control windows must clear the path's bandwidth-delay product,
    /// or this leg would report quinn's default sizing as if it were the link.
    #[test]
    fn the_flow_control_window_clears_the_paths_bandwidth_delay_product() {
        // 34 Mbit/s at 250 ms — the measured path — needs ~1.06 MB in flight.
        let bdp_bytes = 34_000_000f64 / 8.0 * 0.250;
        assert!(
            FLOW_WINDOW as f64 > bdp_bytes * 4.0,
            "flow window {FLOW_WINDOW} B leaves no headroom over a {bdp_bytes:.0} B BDP"
        );
        // And quinn's own default would not have.
        const {
            assert!(
                FLOW_WINDOW > 1_250_000,
                "the window must actually be raised above quinn's 1.25 MB default"
            )
        };
    }

    #[test]
    fn tls_alerts_are_recognised_across_the_whole_alert_range() {
        for alert in [0u8, 42, 46, 48, 51, 80, 255] {
            assert!(is_tls_alert(TransportErrorCode::crypto(alert)));
        }
        // A few ordinary transport codes must not be mistaken for alerts.
        for code in [
            TransportErrorCode::NO_ERROR,
            TransportErrorCode::FLOW_CONTROL_ERROR,
            TransportErrorCode::PROTOCOL_VIOLATION,
        ] {
            assert!(!is_tls_alert(code), "{code:?} is not a TLS alert");
        }
    }

    #[test]
    fn connection_errors_map_to_the_shared_typed_errors() {
        assert!(matches!(
            map_connection_error(&ConnectionError::TimedOut),
            CoreError::Timeout
        ));
        assert!(matches!(
            map_connection_error(&ConnectionError::LocallyClosed),
            CoreError::ConnectionClosed
        ));
        assert!(matches!(
            map_connection_error(&ConnectionError::VersionMismatch),
            CoreError::NetworkError(_)
        ));
        assert!(matches!(
            map_connection_error(&ConnectionError::TransportError(
                quinn::TransportErrorCode::crypto(48).into()
            )),
            CoreError::ServerIdentityMismatch,
        ));
    }

    /// Stand up a real quinn server on loopback that echoes one framed message.
    ///
    /// Returns the bound address; the task ends after one connection.
    async fn echo_server(id: &QuicIdentity) -> SocketAddr {
        let cfg = server_config(id).expect("server config");
        let ep = quinn::Endpoint::server(cfg, SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .expect("bind quic server");
        let addr = ep.local_addr().expect("local addr");
        tokio::spawn(async move {
            let Some(incoming) = ep.accept().await else {
                return;
            };
            let Ok(conn) = incoming.await else { return };
            let Ok((send, recv)) = conn.accept_bi().await else {
                return;
            };
            // `ep` stays bound for the life of this task, which is what keeps
            // the server endpoint alive; the link does not own it.
            let link = QuicLink::accepted(conn, send, recv);
            while let Ok((msg, _)) = link.recv().await {
                let reply = match msg {
                    Msg::Echo {
                        seq,
                        client_send_ns,
                        payload,
                    } => Msg::EchoReply {
                        seq,
                        client_send_ns,
                        server_recv_ns: unix_nanos(),
                        server_send_ns: unix_nanos(),
                        payload,
                    },
                    _ => continue,
                };
                if link.send(&reply).await.is_err() {
                    break;
                }
            }
        });
        addr
    }

    /// The whole certificate story, end to end: a pinned probe connects, and
    /// the framing survives a message far larger than one datagram.
    ///
    /// Loopback, so it exercises the configuration rather than a network — but
    /// it is the only thing that proves the pinning arrangement actually
    /// verifies rather than merely compiling.
    #[tokio::test]
    async fn a_pinned_probe_completes_a_real_handshake_and_round_trip() {
        let id = generate_identity().expect("mint");
        let addr = echo_server(&id).await;

        let link = QuicLink::connect(addr, &id.cert_der)
            .await
            .expect("a pinned client must complete the handshake");

        let payload = crate::proto::PayloadGen::new(9).fill(40_000);
        let msg = Msg::Echo {
            seq: 7,
            client_send_ns: 1,
            payload: payload.clone(),
        };
        link.send_encoded(encode_framed(&msg))
            .await
            .expect("send over the bidirectional stream");

        let (back, arrival) = tokio::time::timeout(Duration::from_secs(10), link.recv())
            .await
            .expect("no reply within the budget")
            .expect("reply decodes");
        match back {
            Msg::EchoReply {
                seq, payload: got, ..
            } => {
                assert_eq!(seq, 7);
                assert_eq!(got, payload, "reassembly must be byte-exact");
            }
            other => panic!("unexpected reply {}", other.verb_name()),
        }
        assert!(arrival.message_len > 40_000);

        // The stats this leg reports must be live, not a default-constructed
        // struct: a connection that has moved 40 KB has a non-zero window.
        let w = link
            .window_sample(Leg::Quic, "test".into(), 0)
            .await
            .expect("quinn always has a window to report");
        assert!(w.cwnd_bytes > 0, "cwnd must come from the live connection");
        assert_eq!(w.state, "quic:cubic");
        assert_eq!(
            (w.inflight_bytes, w.bottleneck_bw_bps, w.pacing_rate_bps),
            (0, 0, 0),
            "fields quinn does not expose stay zero rather than being invented"
        );
        assert!(link.loss_note().contains("packets sent"));

        link.close().await;
    }

    /// The pin must be load-bearing: a probe holding the wrong certificate must
    /// fail, and fail as an identity mismatch rather than as a vague network
    /// error. Without this, "the probe pins the certificate" is only a claim.
    #[tokio::test]
    async fn a_probe_pinned_to_the_wrong_certificate_is_refused() {
        let served = generate_identity().expect("mint served");
        let other = generate_identity().expect("mint other");
        let addr = echo_server(&served).await;

        let r = tokio::time::timeout(
            Duration::from_secs(10),
            QuicLink::connect(addr, &other.cert_der),
        )
        .await
        .expect("the attempt must resolve, not hang");

        match r {
            Ok(_) => panic!("a client pinned to a different certificate must not connect"),
            Err(e) => assert!(
                matches!(e, CoreError::ServerIdentityMismatch),
                "a failed pin must be typed as an identity mismatch, got {e:?}"
            ),
        }
    }
}
