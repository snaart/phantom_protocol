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

use std::sync::Arc;
use std::time::Duration;

use phantom_protocol::api::{PhantomListener, PhantomSession, TcpSessionTransport};
use phantom_protocol::crypto::hybrid_sign::HybridVerifyingKey;
use phantom_protocol::observability::{MetricsSnapshot, Observability};
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
