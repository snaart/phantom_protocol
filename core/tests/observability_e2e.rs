//! End-to-end observability wiring.
//!
//! A real `PhantomListener` ↔ `PhantomSession` run over TCP loopback must
//! populate the production metrics: the handshake counter, the data-plane
//! packet/byte counters, and — critically — the active-session gauge must go
//! **up and back down** (it previously only ever grew, so a Helm HPA scaling on
//! it triggered permanently after warm-up).
//!
//! The accepted server session shares the listener's `Observability` instance,
//! so `listener.observability().snapshot()` aggregates everything the server's
//! data pump records.
//!
//! ## Scope of this file — which instruments can be pinned here
//!
//! `Observability::snapshot()` / `PhantomSession::metrics_snapshot()` mirror the
//! **always-on lock-free atomics** only. Every recorder that reaches those
//! atomics is pinned here against a real loopback exchange:
//!
//! | facade method                        | snapshot field(s)                     |
//! |--------------------------------------|---------------------------------------|
//! | `record_send` / `record_recv`        | `packets_*` / `bytes_*`               |
//! | `record_handshake*`                  | `handshakes_*`, `handshake_latency_*` |
//! | `session_opened` / `session_closed`  | `active_sessions`                     |
//! | `stream_opened` / `stream_closed`    | `active_streams`                      |
//! | `record_encrypt_ns`                  | `avg_encrypt_ns`, `encrypt_count`     |
//! | `record_decrypt_ns`                  | `avg_decrypt_ns`, `decrypt_count`     |
//! | `record_rtt_us`                      | `rtt_us_path_0`                       |
//!
//! The remaining recorders (`record_cookie`, `record_pow`, `record_early_data`,
//! `record_resumption`, `record_rekey`, `record_path_migration`,
//! `record_path_validation`) are **OTel-only**: they touch no atomic, and with
//! `telemetry-otel` off `PhantomInstruments` is a ZST whose methods compile to
//! nothing. There is therefore no always-on observable to assert on, and they
//! are pinned in `core/tests/observability_instrument_wiring.rs`, which installs
//! an in-memory `SdkMeterProvider` under `--features telemetry-otel`.
//! `observability_atomics.rs::otel_only_recorders_are_invisible_to_the_snapshot`
//! pins that split so a future reader does not waste time looking for them here.

use std::sync::Arc;
use std::time::Duration;

use phantom_protocol::api::{PhantomListener, PhantomSession, TcpSessionTransport};
use phantom_protocol::crypto::hybrid_sign::HybridVerifyingKey;
use phantom_protocol::observability::{MetricsSnapshot, MetricsSnapshotFfi, Observability};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Poll the snapshot until `pred` holds or `bound` elapses. Returns whether it
/// became true — bounded so a wiring regression fails the test instead of
/// hanging the suite.
async fn poll_until(
    obs: &Arc<Observability>,
    pred: impl Fn(&MetricsSnapshot) -> bool,
    bound: Duration,
) -> bool {
    timeout(bound, async {
        loop {
            if pred(&obs.snapshot()) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .is_ok()
}

/// [`poll_until`] over the flat FFI record a language binding actually sees.
async fn poll_until_ffi(
    session: &PhantomSession,
    pred: impl Fn(&MetricsSnapshotFfi) -> bool,
    bound: Duration,
) -> bool {
    timeout(bound, async {
        loop {
            if pred(&session.metrics_snapshot()) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .is_ok()
}

/// Bind a loopback TCP listener and return `(listener, addr, pinned key)`.
async fn bind_loopback() -> (Arc<PhantomListener>, String, HybridVerifyingKey) {
    let listener = PhantomListener::bind("127.0.0.1:0".to_string())
        .await
        .expect("bind listener");
    let addr = listener.local_addr();
    let key =
        HybridVerifyingKey::from_bytes(&listener.verifying_key_bytes()).expect("verifying key");
    (listener, addr, key)
}

/// Pinned client over a fresh TCP connection to `addr`.
async fn connect_client(addr: &str, key: HybridVerifyingKey) -> PhantomSession {
    let tcp = TcpStream::connect(addr).await.expect("tcp connect");
    let client = PhantomSession::connect_with_transport(addr, TcpSessionTransport::new(tcp), key);
    timeout(Duration::from_secs(10), client.await_ready())
        .await
        .expect("handshake timed out")
        .expect("handshake failed");
    client
}

#[tokio::test]
async fn observability_e2e_real_session_populates_metrics_and_gauge() {
    let listener = PhantomListener::bind("127.0.0.1:0".to_string())
        .await
        .expect("bind listener");
    let addr = listener.local_addr();
    let key =
        HybridVerifyingKey::from_bytes(&listener.verifying_key_bytes()).expect("verifying key");
    let obs = listener.observability();

    assert_eq!(
        obs.snapshot().active_sessions,
        0,
        "baseline active-session gauge must be 0"
    );

    // Server: accept one connection and echo a single message, then idle so the
    // detached data pump (which owns the gauge lifecycle) stays up until the
    // client disconnects.
    let server = tokio::spawn(async move {
        let session = listener.accept().await.expect("accept").session();
        let msg = session.recv().await.expect("server recv");
        session.send(msg).await.expect("server send");
        tokio::time::sleep(Duration::from_millis(150)).await;
    });

    // Client: pinned connect, send a message, read the echo.
    let tcp = TcpStream::connect(&addr).await.expect("tcp connect");
    let client = PhantomSession::connect_with_transport(&addr, TcpSessionTransport::new(tcp), key);
    client
        .send(b"observe-me".to_vec())
        .await
        .expect("client send");
    let reply = timeout(Duration::from_secs(5), client.recv())
        .await
        .expect("client recv timeout")
        .expect("client recv");
    assert_eq!(reply, b"observe-me");

    // Gauge went UP, and the handshake + data plane are non-flat.
    assert!(
        poll_until(&obs, |s| s.active_sessions >= 1, Duration::from_secs(3)).await,
        "active-session gauge must rise to >= 1 (snapshot {:?})",
        obs.snapshot()
    );
    let mid = obs.snapshot();
    assert!(
        mid.handshakes_success >= 1,
        "server handshake recorded: {mid:?}"
    );
    assert!(
        mid.packets_sent >= 1,
        "server-side packets_sent recorded: {mid:?}"
    );
    assert!(
        mid.packets_recv >= 1,
        "server-side packets_recv recorded: {mid:?}"
    );
    assert!(
        mid.bytes_sent > 0 && mid.bytes_recv > 0,
        "byte counters must be non-flat: {mid:?}"
    );

    // Tear down: the client disconnects → its pump closes the TCP → the server
    // pump's recv errors → the server pump exits → `session_closed` fires.
    client.disconnect().await.expect("client disconnect");
    assert!(
        poll_until(&obs, |s| s.active_sessions == 0, Duration::from_secs(5)).await,
        "active-session gauge must return to 0 after teardown: {:?}",
        obs.snapshot()
    );

    let _ = server.await;
}

// ───────────────────────────────────────────────────────────────────────────
// Regression: instruments that were REGISTERED but never RECORDED.
//
// Each test below drives a real loopback exchange and then asserts the
// corresponding snapshot field actually moved. Before the wiring these fields
// were permanently zero even under load, which is exactly the failure mode
// nothing was catching.
// ───────────────────────────────────────────────────────────────────────────

/// `record_encrypt_ns` / `record_decrypt_ns` / `record_rtt_us`.
///
/// `MetricsSnapshotFfi::{avg_encrypt_ns, encrypt_count, avg_decrypt_ns,
/// decrypt_count, rtt_us_path_0}` are documented FFI fields available with
/// `telemetry-otel` OFF, and every one of them read zero forever because the
/// pump never called the recorder. This asserts all five on **both** sides of a
/// real TCP session, through the same flat record a Swift/Kotlin/Python binding
/// sees.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn observability_e2e_encrypt_decrypt_and_rtt_reach_the_ffi_snapshot() {
    // Enough round trips that the ARQ has definitely had SACKs come back and
    // retire non-retransmitted segments (the RTT-sampling gate is Karn's
    // algorithm, so a retransmit yields no sample).
    const ROUNDS: usize = 16;
    // Big enough that the AEAD call itself is far above any platform's
    // `Instant` granularity (`avg_*_ns > 0` must not be a clock race), yet
    // under the pump's 1156-byte app-data chunking so one `send()` is exactly
    // one `recv()` and the echo comparison stays a simple equality.
    const PAYLOAD: usize = 1024;

    let (listener, addr, key) = bind_loopback().await;
    let server_obs = listener.observability();

    let server = tokio::spawn(async move {
        let session = listener.accept().await.expect("accept").session();
        for _ in 0..ROUNDS {
            let msg = session.recv().await.expect("server recv");
            session.send(msg).await.expect("server echo");
        }
        // Stay up until the client has read its last echo and sampled RTT.
        tokio::time::sleep(Duration::from_millis(500)).await;
    });

    let client = connect_client(&addr, key).await;

    let baseline = client.metrics_snapshot();
    assert_eq!(
        (baseline.encrypt_count, baseline.decrypt_count),
        (0, 0),
        "a client that has only handshaked must not have sealed/opened data packets yet: {baseline:?}"
    );

    for i in 0..ROUNDS {
        let msg = vec![b'z'; PAYLOAD];
        client.send(msg.clone()).await.expect("client send");
        let echo = timeout(Duration::from_secs(15), client.recv())
            .await
            .unwrap_or_else(|_| panic!("echo {i} timed out"))
            .expect("client recv");
        assert_eq!(echo, msg, "echo {i} must be byte-exact");
    }

    // --- Client side ---
    let c = client.metrics_snapshot();
    assert!(
        c.encrypt_count >= ROUNDS as u64,
        "record_encrypt_ns must fire once per sealed packet — encrypt_count={} after {ROUNDS} sends ({c:?})",
        c.encrypt_count
    );
    assert!(
        c.avg_encrypt_ns > 0,
        "avg_encrypt_ns must be non-zero once the AEAD seal is timed ({c:?})"
    );
    assert!(
        c.decrypt_count >= ROUNDS as u64,
        "record_decrypt_ns must fire once per opened packet — decrypt_count={} after {ROUNDS} echoes ({c:?})",
        c.decrypt_count
    );
    assert!(
        c.avg_decrypt_ns > 0,
        "avg_decrypt_ns must be non-zero once the AEAD open is timed ({c:?})"
    );

    // RTT is published when an authenticated SACK retires a non-retransmitted
    // segment, so it lands slightly after the last echo — poll generously.
    assert!(
        poll_until_ffi(&client, |s| s.rtt_us_path_0 > 0, Duration::from_secs(15)).await,
        "record_rtt_us must publish a sample on path 0 from the SACK path: {:?}",
        client.metrics_snapshot()
    );

    // --- Server side (the listener aggregate the accepted session shares) ---
    let s = server_obs.snapshot();
    assert!(
        s.encrypt_count >= ROUNDS as u64 && s.avg_encrypt_ns > 0,
        "the server pump must time its seals too: {s:?}"
    );
    assert!(
        s.decrypt_count >= ROUNDS as u64 && s.avg_decrypt_ns > 0,
        "the server pump must time its opens too: {s:?}"
    );

    client.disconnect().await.expect("client disconnect");
    let _ = server.await;
}

/// `stream_opened` / `stream_closed` — the balance property.
///
/// `active_streams` is an `UpDownCounter`; an unbalanced gauge is the exact
/// defect already pinned for *sessions* in the first test of this file. Opens N
/// user streams over a real session, watches the gauge rise on both peers, then
/// closes them cleanly (reliable FIN → peer SACK → routing removal) and requires
/// the gauge to come back to its starting value.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn observability_e2e_stream_gauge_returns_to_zero_after_clean_close() {
    const STREAMS: usize = 3;

    let (listener, addr, key) = bind_loopback().await;
    let server_obs = listener.observability();

    // The server holds the session (and therefore keeps ACKing) until the
    // client is done; `hold_rx` is the explicit teardown signal so nothing in
    // this test depends on a sleep for synchronisation.
    let (hold_tx, hold_rx) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        let session = listener.accept().await.expect("accept").session();
        // Drain each peer-initiated stream so the client's writes are consumed
        // and its FINs get acknowledged.
        for _ in 0..STREAMS {
            let stream = session.accept_stream().await.expect("accept_stream");
            tokio::spawn(async move { while let Ok(Some(_)) = stream.recv().await {} });
        }
        let _ = hold_rx.await;
        drop(session);
    });

    let client = connect_client(&addr, key).await;
    let client_obs = client.observability();
    assert_eq!(
        client_obs.snapshot().active_streams,
        0,
        "baseline active-stream gauge must be 0"
    );

    let mut streams = Vec::with_capacity(STREAMS);
    for i in 0..STREAMS {
        let stream = client.open_stream();
        stream
            .send_reliable(format!("stream-{i}-payload").into_bytes())
            .await
            .expect("send_reliable");
        streams.push(stream);
    }
    assert_eq!(
        client_obs.snapshot().active_streams,
        STREAMS as i64,
        "every open_stream() must raise the active-streams gauge"
    );
    assert!(
        poll_until(
            &server_obs,
            |s| s.active_streams >= STREAMS as i64,
            Duration::from_secs(15)
        )
        .await,
        "peer-initiated streams must raise the gauge on the accepting side: {:?}",
        server_obs.snapshot()
    );

    // Clean close: a reliable FIN per stream. The stream leaves the routing
    // tables (and the gauge) only once the peer SACKs that FIN.
    for stream in &streams {
        stream.disconnect().await.expect("stream disconnect");
    }
    assert!(
        poll_until(
            &client_obs,
            |s| s.active_streams == 0,
            Duration::from_secs(20)
        )
        .await,
        "the active-stream gauge must return to 0 after every stream is closed: {:?}",
        client_obs.snapshot()
    );
    // ...and it must not undershoot: a double-retire would drive an
    // UpDownCounter negative, which is unrepresentable in a Prometheus gauge
    // panel and is precisely what `StreamGauge::closed`'s floor prevents.
    assert_eq!(
        client_obs.snapshot().active_streams,
        0,
        "gauge must settle at exactly 0, never below"
    );

    drop(streams);
    client.disconnect().await.expect("client disconnect");
    let _ = hold_tx.send(());
    let _ = server.await;

    assert!(
        poll_until(
            &server_obs,
            |s| s.active_streams == 0 && s.active_sessions == 0,
            Duration::from_secs(20)
        )
        .await,
        "session teardown must retire every peer-initiated stream it still had open: {:?}",
        server_obs.snapshot()
    );
}

/// `stream_closed` on the **abnormal** path — the case a FIN handshake never
/// covers.
///
/// The peer dies with streams still open, so no FIN is ever acknowledged. The
/// data pump's exit drain is the only thing that can retire them. The client
/// handle is deliberately kept alive for the whole assertion so `Drop for
/// PhantomSession` cannot be the one doing the work — if the pump-exit drain
/// regressed, this test fails while the clean-close test above still passes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn observability_e2e_stream_gauge_returns_to_zero_when_the_peer_dies() {
    const STREAMS: usize = 4;

    let (listener, addr, key) = bind_loopback().await;
    let (kill_tx, kill_rx) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        let session = listener.accept().await.expect("accept").session();
        let _ = kill_rx.await;
        // Hard teardown: drop the accepted session and stop listening. The
        // client sees its TCP peer go away mid-stream.
        drop(session);
        listener.shutdown();
    });

    let client = connect_client(&addr, key).await;
    let client_obs = client.observability();

    let mut streams = Vec::with_capacity(STREAMS);
    for i in 0..STREAMS {
        let stream = client.open_stream();
        stream
            .send_reliable(format!("doomed-{i}").into_bytes())
            .await
            .expect("send_reliable");
        streams.push(stream);
    }
    assert_eq!(
        client_obs.snapshot().active_streams,
        STREAMS as i64,
        "streams must be counted before the peer dies"
    );
    assert!(
        poll_until(
            &client_obs,
            |s| s.active_sessions >= 1,
            Duration::from_secs(15)
        )
        .await,
        "the client session gauge must be up before the kill: {:?}",
        client_obs.snapshot()
    );

    let _ = kill_tx.send(());
    let _ = server.await;

    // The client handle (and every `PhantomStream`) is still alive here, so the
    // pump's exit drain is the only path that can zero the gauge.
    assert!(
        poll_until(
            &client_obs,
            |s| s.active_streams == 0,
            Duration::from_secs(20)
        )
        .await,
        "pump-exit drain must retire streams left open by an abnormal close: {:?}",
        client_obs.snapshot()
    );
    assert!(
        poll_until(
            &client_obs,
            |s| s.active_sessions == 0,
            Duration::from_secs(20)
        )
        .await,
        "the session gauge must come back down on an abnormal close too: {:?}",
        client_obs.snapshot()
    );

    // Now let the handles go: the `Drop` drain must be a no-op, not a second
    // retire that pushes the gauge negative.
    drop(streams);
    drop(client);
    assert_eq!(
        client_obs.snapshot().active_streams,
        0,
        "the Drop drain must not double-retire after the pump already drained"
    );
}
