//! Regression pins for the **OTel-only** observability instruments.
//!
//! ## Why this file exists
//!
//! Thirteen instruments were registered in
//! `core/src/observability/instruments.rs` but had no recording call site
//! anywhere in the library, so the Grafana panels and the
//! `PhantomPoWRejectionStorm` alert built on them were silently empty. Six of
//! those recorders reach the always-on lock-free atomics and are therefore
//! pinned against a real loopback exchange in `observability_e2e.rs`.
//!
//! The other seven — `record_cookie`, `record_pow`, `record_early_data`,
//! `record_resumption`, `record_rekey`, `record_path_migration` and
//! `record_path_validation` — touch **no atomic at all**. They go straight to
//! `PhantomInstruments`, which is a zero-sized type with `#[inline(always)]`
//! empty methods when `telemetry-otel` is off. There is consequently nothing
//! for `Observability::snapshot()` / `PhantomSession::metrics_snapshot()` to
//! report, and no always-on test can tell "wired" from "not wired" for them.
//! (`observability_atomics.rs::otel_only_recorders_are_invisible_to_the_snapshot`
//! pins that split explicitly.)
//!
//! So this file compiles only under `--features telemetry-otel` — the build in
//! which those instruments are real — installs an **in-memory
//! `SdkMeterProvider`**, drives production code paths, and asserts the
//! corresponding counter series actually appeared with the expected attributes.
//! CI runs it in the existing `telemetry-otel-feature` job. It is NOT
//! `#[ignore]`-gated; every exercise is loopback-only.
//!
//! ## Determinism
//!
//! - One process-wide `SdkMeterProvider` with a `PeriodicReader` whose interval
//!   is effectively infinite: collection only ever happens through an explicit
//!   `force_flush()`, never on a timer.
//! - Every test runs under a global gate mutex, so no two tests record into the
//!   meter concurrently.
//! - Assertions are `>=` deltas measured around the gated section, so a stray
//!   event from a background task that outlived an earlier test can never make
//!   a test fail (it could only mask a regression by *adding* events of exactly
//!   the same attribute set, which no idle task does).
//! - No sleep is used as synchronisation; the only sleeps are inside the server
//!   helper tasks keeping a session alive, and every wait is a bounded
//!   `tokio::time::timeout`. The one event that is inherently a *timer* — the
//!   path-validation expiry sweep — is still not slept on: the challenge itself
//!   is confirmed through a channel, and the sweep's result is then observed by
//!   polling the meter under a deadline with ~15× slack over the budget, so the
//!   test exits the instant the sample lands rather than after a fixed wait.
//! - Assertions are `>=` deltas with two deliberate exceptions
//!   (`rejected_disabled` and the `failure`-must-not-move check), each justified
//!   at the assertion: those exact attribute sets are unreachable from any other
//!   test in this binary, and exactness is what pins the *negative* half of the
//!   contract.

#![cfg(feature = "telemetry-otel")]

use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use opentelemetry_sdk::error::OTelSdkResult;
use opentelemetry_sdk::metrics::data::{AggregatedMetrics, MetricData, ResourceMetrics};
use opentelemetry_sdk::metrics::exporter::PushMetricExporter;
use opentelemetry_sdk::metrics::{PeriodicReader, SdkMeterProvider, Temporality};

use bytes::Bytes;
use phantom_protocol::api::listener::PhantomListener;
use phantom_protocol::api::session::{
    connect_pinned, connect_pinned_udp, connect_pinned_with_resumption, FramePhase, PhantomSession,
    SessionTransport,
};
use phantom_protocol::api::tcp_transport::TcpSessionTransport;
use phantom_protocol::api::udp_listener::PhantomUdpListener;
use phantom_protocol::crypto::hybrid_sign::HybridVerifyingKey;
use phantom_protocol::observability::{Observability, ObservabilityConfig};
use phantom_protocol::transport::handshake::{
    HandshakeClient, HandshakeResponse, HandshakeServer, EARLY_DATA_MAX_LEN,
};
use phantom_protocol::transport::liveness::LivenessConfig;
use phantom_protocol::CoreError;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::timeout;

// ───────────────────────────────────────────────────────────────────────────
// In-memory metric collection
// ───────────────────────────────────────────────────────────────────────────

/// One exported time series: instrument name + its (sorted) attribute set.
type SeriesKey = (String, BTreeMap<String, String>);
/// Cumulative value per series (counter sum, or histogram `_count`).
type Series = HashMap<SeriesKey, i64>;

#[derive(Debug, Default)]
struct Sink {
    series: Mutex<Series>,
}

impl Sink {
    fn merge(&self, rows: Series) {
        let mut guard = self.series.lock().unwrap_or_else(|e| e.into_inner());
        // Cumulative temporality: the newest export carries the running total
        // for each series, so overwriting is the correct merge.
        guard.extend(rows);
    }

    fn snapshot(&self) -> Series {
        self.series
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
}

/// A `PushMetricExporter` that keeps the last exported value of every series in
/// memory. `opentelemetry_sdk`'s own `InMemoryMetricExporter` lives behind its
/// `testing` Cargo feature, which is not (and should not be) enabled for a
/// production dependency — so this file brings its own 40-line equivalent.
#[derive(Debug, Clone)]
struct CollectingExporter {
    sink: Arc<Sink>,
}

fn attrs_of<'a>(
    kvs: impl Iterator<Item = &'a opentelemetry::KeyValue>,
) -> BTreeMap<String, String> {
    kvs.map(|kv| (kv.key.as_str().to_string(), kv.value.to_string()))
        .collect()
}

impl PushMetricExporter for CollectingExporter {
    fn export(&self, metrics: &ResourceMetrics) -> impl Future<Output = OTelSdkResult> + Send {
        let mut rows: Series = HashMap::new();
        for scope in metrics.scope_metrics() {
            for metric in scope.metrics() {
                let name = metric.name().to_string();
                match metric.data() {
                    AggregatedMetrics::U64(MetricData::Sum(sum)) => {
                        for dp in sum.data_points() {
                            rows.insert(
                                (name.clone(), attrs_of(dp.attributes())),
                                i64::try_from(dp.value()).unwrap_or(i64::MAX),
                            );
                        }
                    }
                    AggregatedMetrics::I64(MetricData::Sum(sum)) => {
                        for dp in sum.data_points() {
                            rows.insert((name.clone(), attrs_of(dp.attributes())), dp.value());
                        }
                    }
                    AggregatedMetrics::F64(MetricData::Histogram(h)) => {
                        // For a histogram the observable "did it fire" signal is
                        // the `_count` series.
                        for dp in h.data_points() {
                            rows.insert(
                                (name.clone(), attrs_of(dp.attributes())),
                                i64::try_from(dp.count()).unwrap_or(i64::MAX),
                            );
                        }
                    }
                    _ => {}
                }
            }
        }
        let sink = Arc::clone(&self.sink);
        async move {
            sink.merge(rows);
            Ok(())
        }
    }

    fn force_flush(&self) -> OTelSdkResult {
        Ok(())
    }

    fn shutdown_with_timeout(&self, _timeout: Duration) -> OTelSdkResult {
        Ok(())
    }

    fn temporality(&self) -> Temporality {
        Temporality::Cumulative
    }
}

struct Harness {
    provider: SdkMeterProvider,
    sink: Arc<Sink>,
}

/// Install the in-memory meter provider exactly once, before any
/// `Observability::new` in this binary. `PhantomInstruments::new` builds its
/// instruments from `opentelemetry::global::meter(..)`, so the provider has to
/// be in place first — every test enters through [`gated`], which does this.
fn harness() -> &'static Harness {
    static HARNESS: OnceLock<Harness> = OnceLock::new();
    HARNESS.get_or_init(|| {
        let sink = Arc::new(Sink::default());
        let exporter = CollectingExporter {
            sink: Arc::clone(&sink),
        };
        // A one-day interval means the timer never fires during a test run:
        // the only collection is the explicit `force_flush()` in `collect()`.
        let reader = PeriodicReader::builder(exporter)
            .with_interval(Duration::from_secs(86_400))
            .build();
        let provider = SdkMeterProvider::builder().with_reader(reader).build();
        opentelemetry::global::set_meter_provider(provider.clone());
        Harness { provider, sink }
    })
}

/// Collect every instrument through the SDK and return the current cumulative
/// series map. Synchronous: `SdkMeterProvider::force_flush` hands the work to
/// the reader thread and blocks until it reports back.
fn collect() -> Series {
    let h = harness();
    h.provider.force_flush().expect("force_flush");
    h.sink.snapshot()
}

/// Sum of every series whose instrument name ends with `suffix` and whose
/// attribute set contains all of `want`. `0` when the instrument never
/// recorded — which is precisely the pre-wiring state this file guards against.
fn total(series: &Series, suffix: &str, want: &[(&str, &str)]) -> i64 {
    series
        .iter()
        .filter(|((name, attrs), _)| {
            name.ends_with(suffix)
                && want
                    .iter()
                    .all(|(k, v)| attrs.get(*k).map(String::as_str) == Some(*v))
        })
        .map(|(_, v)| *v)
        .sum()
}

/// Run `body` under the global gate with the meter provider installed, and
/// return `(before, after)` series maps around it.
fn gated<F, R>(body: F) -> (Series, Series)
where
    F: FnOnce() -> R,
{
    static GATE: Mutex<()> = Mutex::new(());
    let _guard = GATE.lock().unwrap_or_else(|e| e.into_inner());
    harness();
    let before = collect();
    body();
    let after = collect();
    (before, after)
}

/// `gated` for async bodies: builds a dedicated multi-threaded runtime so the
/// blocking `force_flush()` never runs inside an async context.
fn gated_async<F, Fut>(body: F) -> (Series, Series)
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = ()>,
{
    gated(|| {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("build test runtime");
        rt.block_on(body());
    })
}

/// Growth of one instrument series across the gated section.
fn delta(before: &Series, after: &Series, suffix: &str, want: &[(&str, &str)]) -> i64 {
    total(after, suffix, want) - total(before, suffix, want)
}

/// Assert an instrument series grew by at least `min` across the gated section.
#[track_caller]
fn assert_grew(before: &Series, after: &Series, suffix: &str, want: &[(&str, &str)], min: i64) {
    let b = total(before, suffix, want);
    let a = total(after, suffix, want);
    assert!(
        a - b >= min,
        "instrument `*{suffix}` with attributes {want:?} must have recorded at least {min} \
         event(s) — before={b} after={a}. A zero delta means the recording call site is \
         missing (the exact defect this file exists to catch)."
    );
}

// ───────────────────────────────────────────────────────────────────────────
// record_cookie — the stateless address-validation gate
// ───────────────────────────────────────────────────────────────────────────

/// A plain PhantomUDP handshake exercises `HandshakeServer::udp_admit` (H-2)
/// twice: the first `ClientHello` carries no cookie so the server issues one
/// (`outcome=issued`), and the client's retry presents it (`outcome=validated_ok`).
/// Both were dead counters before the wiring.
#[test]
fn udp_handshake_records_cookie_issued_and_validated() {
    let (before, after) = gated_async(|| async {
        let listener = PhantomUdpListener::bind_udp("127.0.0.1:0".to_string())
            .await
            .expect("bind_udp");
        let addr: SocketAddr = listener.local_addr().parse().expect("local_addr");
        let pinned = listener.verifying_key_bytes();

        let acceptor = listener.clone();
        let server = tokio::spawn(async move {
            let session = acceptor.accept().await.expect("accept").session();
            let msg = session.recv().await.expect("server recv");
            session.send(msg).await.expect("server echo");
            tokio::time::sleep(Duration::from_millis(150)).await;
        });

        let client = connect_pinned_udp("127.0.0.1".to_string(), addr.port(), pinned)
            .await
            .expect("connect_pinned_udp");
        client.send(b"cookie-probe".to_vec()).await.expect("send");
        let echo = timeout(Duration::from_secs(15), client.recv())
            .await
            .expect("echo timed out")
            .expect("recv");
        assert_eq!(echo, b"cookie-probe");

        client.disconnect().await.expect("disconnect");
        let _ = server.await;
        listener.shutdown();
    });

    assert_grew(
        &before,
        &after,
        ".security.cookie",
        &[("outcome", "issued")],
        1,
    );
    assert_grew(
        &before,
        &after,
        ".security.cookie",
        &[("outcome", "validated_ok")],
        1,
    );
}

// ───────────────────────────────────────────────────────────────────────────
// record_cookie (mismatch) + record_pow
// ───────────────────────────────────────────────────────────────────────────

/// The TCP DoS gate (`cookie_pow_gate`). Driven through the production
/// `HandshakeServer::process_client_hello` with an explicit difficulty, because
/// the adaptive difficulty an idle loopback listener computes is `0` — a real
/// server only demands proof-of-work under load or against a bad-reputation
/// source, neither of which a hermetic test can conjure without lying about
/// load. The gate code exercised is the same code the listener calls.
///
/// `PhantomPoWRejectionStorm` (docs/observability/prometheus/alerts.yml) fires
/// on `outcome="rejected"`, so the `rejected` series is the load-bearing one.
#[test]
fn dos_gate_records_cookie_mismatch_and_pow_outcomes() {
    let (before, after) = gated(|| {
        let obs = Observability::new(ObservabilityConfig::default());
        let server = HandshakeServer::new()
            .expect("HandshakeServer::new")
            .with_observability(obs);
        let client = HandshakeClient::new().expect("HandshakeClient::new");
        let ip: IpAddr = "203.0.113.7".parse().expect("ip");
        let hello = client.create_client_hello();

        // 1. First contact: no cookie, difficulty 8 → Retry carrying a fresh
        //    cookie (`issued`) and a PoW challenge. No PoW event: nothing was
        //    presented, so counting it as a rejection would swamp the alert.
        let retry = match server.process_client_hello(&hello, 8, ip) {
            HandshakeResponse::Retry(r) => r,
            other => panic!("expected Retry, got {other:?}"),
        };
        let cookie = retry.cookie.expect("retry must demand a cookie");
        let challenge = retry.challenge.expect("difficulty 8 must demand a PoW");

        // 2. A forged cookie → `validated_mismatch`.
        let mut forged = hello.clone();
        forged.cookie = Some([0x5A; 32]);
        assert!(matches!(
            server.process_client_hello(&forged, 0, ip),
            HandshakeResponse::Retry(_)
        ));

        // 3. Valid cookie + a bogus solution → `validated_ok` + `rejected`.
        //    An all-zero nonce fails the challenge's keyed-MAC binding, so this
        //    is deterministic (no 1-in-2^8 chance of accidentally passing).
        let mut bad_pow = hello.clone();
        bad_pow.cookie = Some(cookie);
        bad_pow.pow_solution = Some(phantom_protocol::crypto::pow::PoWSolution {
            nonce: [0u8; 32],
            solution: 0,
        });
        assert!(matches!(
            server.process_client_hello(&bad_pow, 8, ip),
            HandshakeResponse::Retry(_)
        ));

        // 4. Valid cookie + a real solution → `solved`, handshake succeeds.
        let mut good = hello.clone();
        good.cookie = Some(cookie);
        good.pow_solution = Some(challenge.solve().expect("solve difficulty-8 PoW"));
        assert!(matches!(
            server.process_client_hello(&good, 8, ip),
            HandshakeResponse::Success(..)
        ));
    });

    assert_grew(
        &before,
        &after,
        ".security.cookie",
        &[("outcome", "issued")],
        1,
    );
    assert_grew(
        &before,
        &after,
        ".security.cookie",
        &[("outcome", "validated_mismatch")],
        1,
    );
    assert_grew(
        &before,
        &after,
        ".security.cookie",
        &[("outcome", "validated_ok")],
        1,
    );
    assert_grew(
        &before,
        &after,
        ".security.pow",
        &[("outcome", "rejected"), ("difficulty", "8")],
        1,
    );
    assert_grew(
        &before,
        &after,
        ".security.pow",
        &[("outcome", "solved"), ("difficulty", "8")],
        1,
    );
}

// ───────────────────────────────────────────────────────────────────────────
// record_resumption + record_early_data
// ───────────────────────────────────────────────────────────────────────────

/// Real TCP loopback 0-RTT: harvest a `ResumptionHint`, resume with early-data
/// (accepted), then resume with the **same** hint again. The ticket is one-shot,
/// so the second attempt cannot be honored — which is how the rejection series
/// gets driven without faking anything.
#[test]
fn zero_rtt_records_resumption_and_early_data_outcomes() {
    let (before, after) = gated_async(|| async {
        let listener = PhantomListener::bind("127.0.0.1:0".to_string())
            .await
            .expect("bind listener");
        let local = listener.local_addr();
        let (host, port_str) = local.rsplit_once(':').expect("host:port");
        let host = host.to_string();
        let port: u16 = port_str.parse().expect("port");
        let pinned = listener.verifying_key_bytes();

        // Echo everything on every accepted session until it closes — the third
        // connection delivers two messages (see the C3 note below), so a
        // fixed one-echo server would deadlock it.
        let server = tokio::spawn(async move {
            for _ in 0..3 {
                let session = listener.accept().await.expect("accept").session();
                tokio::spawn(async move {
                    while let Ok(msg) = session.recv().await {
                        if session.send(msg).await.is_err() {
                            break;
                        }
                    }
                });
            }
            tokio::time::sleep(Duration::from_millis(400)).await;
        });

        // Connection 1 — plain, to mint a ticket.
        let s1 = connect_pinned(host.clone(), port, pinned.clone())
            .await
            .expect("connect_pinned");
        s1.send(b"mint".to_vec()).await.expect("s1 send");
        let r1 = timeout(Duration::from_secs(15), s1.recv())
            .await
            .expect("s1 echo timed out")
            .expect("s1 recv");
        assert_eq!(r1, b"mint");

        let hint = timeout(Duration::from_secs(15), async {
            loop {
                if let Some(h) = s1.resumption_hint().await {
                    return h;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("resumption hint never published");

        // Connection 2 — 0-RTT accepted.
        let s2 = connect_pinned_with_resumption(
            host.clone(),
            port,
            pinned.clone(),
            hint.clone(),
            b"early-payload".to_vec(),
        )
        .await
        .expect("connect_pinned_with_resumption");
        s2.send(b"zero".to_vec()).await.expect("s2 send");
        let r2 = timeout(Duration::from_secs(15), s2.recv())
            .await
            .expect("s2 echo timed out")
            .expect("s2 recv");
        assert_eq!(r2, b"zero");

        // Connection 3 — the SAME one-shot ticket → rejected, 1-RTT fallback.
        let s3 = connect_pinned_with_resumption(
            host,
            port,
            pinned,
            hint,
            b"early-payload-again".to_vec(),
        )
        .await
        .expect("connect_pinned_with_resumption (replay)");
        // C3: the server rejected this connection's early-data, so the client
        // re-queues it at the front of the send queue and it arrives as
        // ordinary 1-RTT application data — hence the *first* echo here is the
        // early-data payload, not the message sent below.
        s3.send(b"one".to_vec()).await.expect("s3 send");
        let requeued = timeout(Duration::from_secs(15), s3.recv())
            .await
            .expect("s3 requeued-early-data echo timed out")
            .expect("s3 recv");
        assert_eq!(
            requeued, b"early-payload-again",
            "rejected 0-RTT early-data must be retransmitted over the 1-RTT session"
        );
        let r3 = timeout(Duration::from_secs(15), s3.recv())
            .await
            .expect("s3 echo timed out")
            .expect("s3 recv");
        assert_eq!(r3, b"one");

        for s in [&s1, &s2, &s3] {
            let _ = s.disconnect().await;
        }
        let _ = server.await;
    });

    assert_grew(
        &before,
        &after,
        ".handshake.resumptions",
        &[("mode", "0rtt"), ("accepted", "true")],
        1,
    );
    assert_grew(
        &before,
        &after,
        ".handshake.resumptions",
        &[("mode", "0rtt"), ("accepted", "false")],
        1,
    );
    assert_grew(
        &before,
        &after,
        ".session.early_data",
        &[("outcome", "accepted")],
        1,
    );
    // The replayed ticket is gone from the cache, so the server cannot tell a
    // consumed id from an unknown one — `rejected_unknown_ticket` is the
    // documented attribution for that class.
    assert_grew(
        &before,
        &after,
        ".session.early_data",
        &[("outcome", "rejected_unknown_ticket")],
        1,
    );
}

/// The remaining two `EarlyDataOutcome` attributions — `rejected_oversized` and
/// `rejected_aead` — need a resuming hello whose sealed blob is deliberately
/// malformed, which no honest client produces. Driven through the production
/// `HandshakeServer::process_client_hello`, one fresh (one-shot) ticket per
/// case.
///
/// These two are the most fragile part of the wiring: the recording site has to
/// *re-derive* the reason from the same size gate `decrypt_early_data` applies
/// internally, so a change to that gate silently mis-attributes without this
/// test.
#[test]
fn malformed_early_data_records_oversized_and_aead_rejections() {
    let (before, after) = gated(|| {
        let obs = Observability::new(ObservabilityConfig::default());
        let server = HandshakeServer::new()
            .expect("HandshakeServer::new")
            .with_observability(obs);
        let ip: IpAddr = "203.0.113.11".parse().expect("ip");

        // A full 1-RTT handshake that leaves a fresh resumption ticket in the
        // server's cache, returning the hint the next hello resumes with.
        let mint = |server: &HandshakeServer| -> ([u8; 32], [u8; 32]) {
            let client = HandshakeClient::new().expect("HandshakeClient::new");
            let mut hello = client.create_client_hello();
            // First contact is always a cookie round.
            let retry = match server.process_client_hello(&hello, 0, ip) {
                HandshakeResponse::Retry(r) => r,
                other => panic!("expected Retry on first contact, got {other:?}"),
            };
            hello.cookie = Some(retry.cookie.expect("retry must demand a cookie"));
            let sh = match server.process_client_hello(&hello, 0, ip) {
                HandshakeResponse::Success(sh, _, _) => sh,
                other => panic!("expected Success with a valid cookie, got {other:?}"),
            };
            let (session, _) = client
                .process_server_hello(&hello, &sh, Some(server.verifying_key()))
                .expect("client verifies the ServerHello");
            session.resumption_hint().expect("ticket minted")
        };

        // 1. Oversized blob → `rejected_oversized`. The resume itself still
        //    succeeds (the binder is valid); only the early-data is dropped.
        let (rid, secret) = mint(&server);
        let client = HandshakeClient::new().expect("HandshakeClient::new");
        let mut oversized = client.create_client_hello_with_resume(rid, &secret, Some(b"payload"));
        oversized.early_data = Some(vec![0u8; EARLY_DATA_MAX_LEN + 17]);
        match server.process_client_hello(&oversized, 0, ip) {
            HandshakeResponse::Success(sh, _, early) => {
                assert!(
                    !sh.early_data_accepted,
                    "an oversized blob must be rejected"
                );
                assert!(early.is_none());
            }
            other => panic!("a valid resume must still complete, got {other:?}"),
        }

        // 2. Corrupted ciphertext of a legal size → `rejected_aead`.
        let (rid2, secret2) = mint(&server);
        let client2 = HandshakeClient::new().expect("HandshakeClient::new");
        let mut tampered =
            client2.create_client_hello_with_resume(rid2, &secret2, Some(b"payload"));
        let blob = tampered.early_data.as_mut().expect("blob was sealed");
        assert!(
            blob.len() <= EARLY_DATA_MAX_LEN + 16,
            "the tampered blob must stay under the size gate so the AEAD is what fails"
        );
        blob[0] ^= 0xFF;
        match server.process_client_hello(&tampered, 0, ip) {
            HandshakeResponse::Success(sh, _, early) => {
                assert!(
                    !sh.early_data_accepted,
                    "a tampered blob must fail the AEAD open"
                );
                assert!(early.is_none());
            }
            other => panic!("a valid resume must still complete, got {other:?}"),
        }
    });

    assert_grew(
        &before,
        &after,
        ".session.early_data",
        &[("outcome", "rejected_oversized")],
        1,
    );
    assert_grew(
        &before,
        &after,
        ".session.early_data",
        &[("outcome", "rejected_aead")],
        1,
    );
    // Both hellos offered a ticket that WAS honored, so the 1-RTT resumption
    // series moved too — the 0-RTT verdict and the resumption verdict are
    // independent, which is the property that lets a dashboard tell "resume
    // worked, early-data did not" from "resume failed".
    assert_grew(
        &before,
        &after,
        ".handshake.resumptions",
        &[("mode", "0rtt"), ("accepted", "false")],
        2,
    );
}

/// The A2b 0-RTT kill switch (`set_early_data_enabled(false)`).
///
/// A server with early data disabled that still receives a hello **offering** a
/// sealed blob emits `outcome=rejected_disabled`. Before this was wired, that
/// case produced no sample at all, so a flat `phantom.session.early_data` line
/// was ambiguous between "no client is offering 0-RTT" and "the operator turned
/// 0-RTT off here" — two very different answers to "why is my 0-RTT hit-rate
/// zero?".
///
/// The delta is asserted **exactly**, not `>=`: this is the only test in the
/// binary that ever disables early data, and no production listener starts
/// disabled, so no background task can contribute a stray `rejected_disabled`.
/// Exactness is what pins the *negative* half of the contract — the plain hello
/// in step (b) offers no blob, is not a 0-RTT decision, and must not add a
/// second sample.
#[test]
fn disabled_early_data_records_rejected_disabled_only_for_an_offered_blob() {
    let (before, after) = gated(|| {
        let obs = Observability::new(ObservabilityConfig::default());
        let server = HandshakeServer::new()
            .expect("HandshakeServer::new")
            .with_observability(obs);
        let ip: IpAddr = "203.0.113.19".parse().expect("ip");

        // A full 1-RTT handshake so there is a genuine ticket to resume with —
        // the kill switch must be what refuses the blob, not a missing ticket.
        let client = HandshakeClient::new().expect("HandshakeClient::new");
        let mut mint = client.create_client_hello();
        let retry = match server.process_client_hello(&mint, 0, ip) {
            HandshakeResponse::Retry(r) => r,
            other => panic!("expected Retry on first contact, got {other:?}"),
        };
        mint.cookie = Some(retry.cookie.expect("retry must demand a cookie"));
        let sh = match server.process_client_hello(&mint, 0, ip) {
            HandshakeResponse::Success(sh, _, _) => sh,
            other => panic!("expected Success with a valid cookie, got {other:?}"),
        };
        let (session, _) = client
            .process_server_hello(&mint, &sh, Some(server.verifying_key()))
            .expect("client verifies the ServerHello");
        let (rid, secret) = session.resumption_hint().expect("ticket minted");

        server.set_early_data_enabled(false);

        // (a) Offered blob + valid ticket → exactly one `rejected_disabled`, and
        //     the resume itself still completes 1-RTT.
        let c2 = HandshakeClient::new().expect("HandshakeClient::new");
        let offered = c2.create_client_hello_with_resume(rid, &secret, Some(b"denied"));
        assert!(
            offered.early_data.is_some(),
            "the client must actually have sealed a blob"
        );
        match server.process_client_hello(&offered, 0, ip) {
            HandshakeResponse::Success(sh, _, early) => {
                assert!(
                    !sh.early_data_accepted,
                    "the kill switch must refuse the blob"
                );
                assert!(early.is_none(), "no early-data plaintext may surface");
            }
            other => panic!("the resume itself must still complete, got {other:?}"),
        }

        // (b) A plain hello offering nothing → NOT an early-data event.
        let c3 = HandshakeClient::new().expect("HandshakeClient::new");
        let mut plain = c3.create_client_hello();
        assert!(plain.early_data.is_none());
        let retry = match server.process_client_hello(&plain, 0, ip) {
            HandshakeResponse::Retry(r) => r,
            other => panic!("expected Retry on first contact, got {other:?}"),
        };
        plain.cookie = Some(retry.cookie.expect("retry must demand a cookie"));
        assert!(matches!(
            server.process_client_hello(&plain, 0, ip),
            HandshakeResponse::Success(..)
        ));
    });

    assert_eq!(
        delta(
            &before,
            &after,
            ".session.early_data",
            &[("outcome", "rejected_disabled")]
        ),
        1,
        "exactly one sample: the offered blob is a rejection, the plain hello is not"
    );
    // The switch is checked before any ticket lookup or AEAD work, so the blob is
    // never attributed to a client-side cause.
    assert_eq!(
        delta(
            &before,
            &after,
            ".session.early_data",
            &[("outcome", "accepted")]
        ),
        0,
        "a disabled server must never record an acceptance"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// record_rekey
// ───────────────────────────────────────────────────────────────────────────

/// Lower both peers' automatic-rekey watermark and run a synchronous soak, so
/// the send side actually rotates (`direction=send`) and the peer follows the
/// authenticated epoch bump (`direction=recv`).
#[test]
fn automatic_rekey_records_both_directions() {
    const MESSAGES: usize = 60;
    const REKEY_EVERY: u64 = 4;

    let (before, after) = gated_async(|| async {
        let listener = PhantomListener::bind("127.0.0.1:0".to_string())
            .await
            .expect("bind listener");
        let addr = listener.local_addr();
        let key =
            HybridVerifyingKey::from_bytes(&listener.verifying_key_bytes()).expect("verifying key");

        let server = tokio::spawn(async move {
            let session = listener.accept().await.expect("accept").session();
            assert!(
                session.set_rekey_threshold(REKEY_EVERY).await,
                "server session must be established"
            );
            for _ in 0..MESSAGES {
                let msg = session.recv().await.expect("server recv");
                session.send(msg).await.expect("server echo");
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        });

        let tcp = TcpStream::connect(&addr).await.expect("tcp connect");
        let client =
            PhantomSession::connect_with_transport(&addr, TcpSessionTransport::new(tcp), key);
        timeout(Duration::from_secs(15), client.await_ready())
            .await
            .expect("handshake timed out")
            .expect("handshake failed");
        assert!(
            client.set_rekey_threshold(REKEY_EVERY).await,
            "client session must be established"
        );

        for i in 0..MESSAGES {
            let msg = format!("rekey-{i}").into_bytes();
            client.send(msg.clone()).await.expect("client send");
            let echo = timeout(Duration::from_secs(15), client.recv())
                .await
                .unwrap_or_else(|_| panic!("echo {i} timed out"))
                .expect("client recv");
            assert_eq!(echo, msg, "echo {i} must survive the rekey boundary");
        }
        assert!(
            client.current_epoch().await.unwrap_or(0) > 0,
            "the soak must actually have rotated keys"
        );

        client.disconnect().await.expect("disconnect");
        let _ = server.await;
    });

    assert_grew(
        &before,
        &after,
        ".session.rekey",
        &[("direction", "send")],
        1,
    );
    assert_grew(
        &before,
        &after,
        ".session.rekey",
        &[("direction", "recv")],
        1,
    );
}

// ───────────────────────────────────────────────────────────────────────────
// record_path_migration + record_path_validation
// ───────────────────────────────────────────────────────────────────────────

/// A real PhantomUDP connection migration over loopback. The client's
/// `migrate()` records `from_path=0,to_path=1`; the server detects the
/// authenticated forward path id (recording its own migration event),
/// challenges the new source, and — when the client echoes the challenge —
/// completes the validation, which is the only site that feeds
/// `phantom.path.validation.duration`.
#[test]
fn udp_migration_records_path_migration_and_validation() {
    const ROUNDS: usize = 6;

    let (before, after) = gated_async(|| async {
        let listener = PhantomUdpListener::bind_udp("127.0.0.1:0".to_string())
            .await
            .expect("bind_udp");
        let addr: SocketAddr = listener.local_addr().parse().expect("local_addr");
        let pinned = listener.verifying_key_bytes();

        let acceptor = listener.clone();
        let server = tokio::spawn(async move {
            let session = acceptor.accept().await.expect("accept").session();
            for _ in 0..ROUNDS {
                let msg = session.recv().await.expect("server recv");
                session.send(msg).await.expect("server echo");
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        });

        let client = connect_pinned_udp("127.0.0.1".to_string(), addr.port(), pinned)
            .await
            .expect("connect_pinned_udp");

        client.send(b"pre-migration".to_vec()).await.expect("send");
        let echo = timeout(Duration::from_secs(15), client.recv())
            .await
            .expect("pre-migration echo timed out")
            .expect("recv");
        assert_eq!(echo, b"pre-migration");

        client
            .migrate("127.0.0.1:0".to_string())
            .await
            .expect("migrate");

        // Post-migration traffic is what makes the server observe the new path
        // id + source, challenge it, and complete the validation.
        for i in 1..ROUNDS {
            let msg = format!("post-migration-{i}").into_bytes();
            client.send(msg.clone()).await.expect("send");
            let echo = timeout(Duration::from_secs(15), client.recv())
                .await
                .unwrap_or_else(|_| panic!("post-migration echo {i} timed out"))
                .expect("recv");
            assert_eq!(echo, msg, "the session must survive the migration");
        }

        client.disconnect().await.expect("disconnect");
        let _ = server.await;
        listener.shutdown();
    });

    // Client side: the local send path moved 0 → 1.
    assert_grew(
        &before,
        &after,
        ".path.migrations",
        &[("from_path", "0"), ("to_path", "1")],
        1,
    );
    // Server side: the peer's authenticated path id moved forward. Recorded
    // with the same `to_path`, so this also proves the *server* reports
    // migrations at all (it never issues `migrate()` itself, so without the
    // peer-detection site the metric would be empty on the side operators
    // actually monitor).
    assert!(
        total(&after, ".path.migrations", &[("to_path", "1")])
            - total(&before, ".path.migrations", &[("to_path", "1")])
            >= 2,
        "both peers must record the migration (client's own move + the server's \
         peer-migration detection): before={} after={}",
        total(&before, ".path.migrations", &[("to_path", "1")]),
        total(&after, ".path.migrations", &[("to_path", "1")])
    );
    // The challenge/response completed: the histogram's `_count` series exists.
    assert_grew(
        &before,
        &after,
        ".path.validation.duration",
        &[("outcome", "success"), ("path_id", "1")],
        1,
    );
}

// ───────────────────────────────────────────────────────────────────────────
// record_path_validation — the unanswered-challenge (timeout) arm
// ───────────────────────────────────────────────────────────────────────────

/// A `SessionTransport` decorator that makes the pump believe an unvalidated
/// migration candidate exists and then swallows the `PATH_CHALLENGE` sent to it.
///
/// That is exactly the shape of a real blackholed migration: the peer's new
/// address is committed as a candidate (post-AEAD, M-1), the challenge goes out
/// to it, and nothing ever comes back. Doing it with a decorator instead of a
/// cut network keeps the test hermetic and instant — the production challenge is
/// really issued by `handle_packet`, really stamped in the pump's challenge map,
/// and really expired by `sweep_path_validation_timeouts`.
///
/// Forwards the **entire** control surface (EPS-04 wrapper contract) — only
/// `has_migration_candidate` / `send_to_candidate` are overridden.
struct BlackholeCandidate {
    inner: TcpSessionTransport,
    /// Flipped off once the challenge is out, so subsequent inbound frames
    /// cannot re-issue (and thereby re-stamp) it.
    candidate: AtomicBool,
    /// Fires when the pump hands us a challenge for the candidate.
    issued: mpsc::UnboundedSender<()>,
}

impl SessionTransport for BlackholeCandidate {
    fn send_bytes(&self, data: &[u8]) -> impl Future<Output = Result<(), CoreError>> + Send {
        self.inner.send_bytes(data)
    }

    fn recv_bytes(&self) -> impl Future<Output = Result<Bytes, CoreError>> + Send {
        self.inner.recv_bytes()
    }

    fn set_frame_phase(&self, phase: FramePhase) {
        self.inner.set_frame_phase(phase);
    }

    fn set_outbound_cid(&self, cid: [u8; 8]) {
        self.inner.set_outbound_cid(cid);
    }

    fn has_migration_candidate(&self) -> bool {
        self.candidate.load(Ordering::Acquire)
    }

    fn send_to_candidate(
        &self,
        _data: &[u8],
    ) -> impl Future<Output = Result<bool, CoreError>> + Send {
        // One challenge is enough to prove the point; stop advertising the
        // candidate so the next inbound frame does not restart the clock.
        self.candidate.store(false, Ordering::Release);
        let _ = self.issued.send(());
        // Report a successful send: the challenge left the building and simply
        // never gets an answer, which is the blackhole we are modelling.
        async { Ok(true) }
    }

    fn confirm_authenticated_source(&self) {
        self.inner.confirm_authenticated_source();
    }

    fn promote_candidate(&self) -> bool {
        self.inner.promote_candidate()
    }

    fn supports_migration(&self) -> bool {
        self.inner.supports_migration()
    }

    fn migrate(&self, local_addr: String) -> impl Future<Output = Result<(), CoreError>> + Send {
        self.inner.migrate(local_addr)
    }

    fn migrate_server(
        &self,
        local_addr: String,
    ) -> impl Future<Output = Result<(), CoreError>> + Send {
        self.inner.migrate_server(local_addr)
    }
}

/// A `PATH_CHALLENGE` the peer never answers must record
/// `outcome=timeout` — the second of the two documented gaps.
///
/// Previously an unanswered challenge recorded nothing at all: only a real
/// response (matching → `success`, mismatched → `failure`) produced a sample, so
/// a migration into a blackhole was invisible and its start stamp leaked. The
/// pump's heartbeat now expires it after the same `path_down_ptos × PTO` budget
/// it already uses to declare a path down.
///
/// Determinism: the challenge is confirmed **through a channel**, not a sleep,
/// and the timeout is then observed by polling the meter under a generous
/// deadline. The polling loop is bounded at 30 s with a 2 s budget, so a loaded
/// CI runner has ~15× slack; the loop exits as soon as the sample lands.
#[test]
fn an_unanswered_path_challenge_records_a_timeout() {
    // Reserved M-3 rebind-validation path id: the challenge the M-3 branch issues
    // when an authenticated frame arrives on the (Validated) path 0 while a
    // migration candidate is outstanding.
    const REBIND_PATH: &str = "255";
    // 2 × max(500 ms, 3 × min_rtt): comfortably longer than a loopback round trip
    // (so a live validation would never be swept) and short enough that the test
    // finishes promptly.
    let liveness = LivenessConfig {
        min_pto: Duration::from_millis(500),
        path_down_ptos: 2,
        ..LivenessConfig::default()
    };

    let (before, after) = gated(|| {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("build test runtime");

        // Establish the session and hold it (plus the runtime) alive while the
        // pump's heartbeat runs; the sweep only ticks on a live pump.
        let client = rt.block_on(async {
            let listener = PhantomListener::bind("127.0.0.1:0".to_string())
                .await
                .expect("bind listener");
            let addr = listener.local_addr();
            let key = HybridVerifyingKey::from_bytes(&listener.verifying_key_bytes())
                .expect("verifying key");

            // Echo until the client goes away; keeps the TCP peer (and therefore
            // the client's reader task, and therefore its pump) alive.
            tokio::spawn(async move {
                let session = listener.accept().await.expect("accept").session();
                while let Ok(msg) = session.recv().await {
                    if session.send(msg).await.is_err() {
                        break;
                    }
                }
            });

            let (issued_tx, mut issued_rx) = mpsc::unbounded_channel::<()>();
            let tcp = TcpStream::connect(&addr).await.expect("tcp connect");
            let transport = BlackholeCandidate {
                inner: TcpSessionTransport::new(tcp),
                candidate: AtomicBool::new(true),
                issued: issued_tx,
            };
            let client = PhantomSession::connect_with_transport(&addr, transport, key);
            timeout(Duration::from_secs(15), client.await_ready())
                .await
                .expect("handshake timed out")
                .expect("handshake failed");
            assert!(
                client.set_liveness_config(liveness).await,
                "session must be established before the liveness override"
            );

            // One echo. The inbound reply is an authenticated app frame on the
            // pre-validated path 0 with a migration candidate outstanding, which
            // is precisely the M-3 branch that issues a challenge on path 255.
            client
                .send(b"provoke-a-challenge".to_vec())
                .await
                .expect("send");
            let echo = timeout(Duration::from_secs(15), client.recv())
                .await
                .expect("echo timed out")
                .expect("recv");
            assert_eq!(echo, b"provoke-a-challenge");

            timeout(Duration::from_secs(15), issued_rx.recv())
                .await
                .expect("the pump never issued a PATH_CHALLENGE to the candidate")
                .expect("challenge channel closed");
            client
        });

        // The challenge is outstanding and unanswerable. Poll the meter (from
        // outside the runtime — `force_flush` blocks) until the sweep reports it.
        let deadline = Instant::now() + Duration::from_secs(30);
        while Instant::now() < deadline {
            let now = collect();
            if total(
                &now,
                ".path.validation.duration",
                &[("outcome", "timeout"), ("path_id", REBIND_PATH)],
            ) > 0
            {
                break;
            }
            std::thread::sleep(Duration::from_millis(25));
        }

        rt.block_on(async {
            let _ = client.disconnect().await;
        });
    });

    assert_grew(
        &before,
        &after,
        ".path.validation.duration",
        &[("outcome", "timeout"), ("path_id", REBIND_PATH)],
        1,
    );
    // A timeout is NOT a failure: nothing answered, so nothing was wrong-answered.
    // Operators alert differently on the two, so the sweep must not borrow the
    // `failure` label.
    assert_eq!(
        delta(
            &before,
            &after,
            ".path.validation.duration",
            &[("outcome", "failure"), ("path_id", REBIND_PATH)]
        ),
        0,
        "an unanswered challenge must not be reported as a validation failure"
    );
}
