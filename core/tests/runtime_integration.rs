//! Integration test for Phase 3.1 Runtime trait — verifies that
//! `PhantomSession` and `PhantomListener` actually delegate task spawning
//! to the supplied `Runtime` rather than calling `tokio::spawn` directly.
//!
//! A counting wrapper around [`TokioRuntime`] tallies every `spawn` and
//! `sleep` call. After driving a small handshake-and-echo through
//! `connect_with_transport_with_runtime` we assert the counter is
//! non-zero — proving the runtime indirection is wired all the way
//! through the data pump.

use phantom_core::runtime::{BoxFuture, Runtime, SpawnHandle, TokioRuntime};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

/// Wrapper runtime that counts spawn / sleep calls. Delegates all real
/// work to an inner `TokioRuntime` so the spawned futures actually
/// progress.
#[derive(Default)]
struct CountingRuntime {
    inner: TokioRuntime,
    spawns: AtomicUsize,
    sleeps: AtomicUsize,
}

impl CountingRuntime {
    fn spawns(&self) -> usize {
        self.spawns.load(Ordering::SeqCst)
    }
    fn sleeps(&self) -> usize {
        self.sleeps.load(Ordering::SeqCst)
    }
}

impl Runtime for CountingRuntime {
    fn spawn(&self, fut: BoxFuture<()>) -> SpawnHandle {
        self.spawns.fetch_add(1, Ordering::SeqCst);
        self.inner.spawn(fut)
    }
    fn sleep(&self, duration: Duration) -> BoxFuture<()> {
        self.sleeps.fetch_add(1, Ordering::SeqCst);
        self.inner.sleep(duration)
    }
    fn now_monotonic(&self) -> Instant {
        self.inner.now_monotonic()
    }
    fn now_wall_clock(&self) -> SystemTime {
        self.inner.now_wall_clock()
    }
}

/// End-to-end: bind a listener on a custom runtime, connect a session on
/// a custom runtime, exchange one round trip, verify both runtimes
/// observed at least one `spawn` call from the data pump.
#[tokio::test]
async fn runtime_substitution_drives_session_and_listener() {
    use phantom_core::api::{PhantomListener, PhantomSession, TcpSessionTransport};
    use phantom_core::crypto::hybrid_sign::HybridVerifyingKey;
    use tokio::net::TcpStream;

    let listener_rt: Arc<CountingRuntime> = Arc::new(CountingRuntime::default());
    let client_rt: Arc<CountingRuntime> = Arc::new(CountingRuntime::default());

    // Bind listener on its own counting runtime.
    let listener = PhantomListener::bind_with_runtime(
        "127.0.0.1:0".to_string(),
        listener_rt.clone() as Arc<dyn Runtime>,
    )
    .await
    .expect("bind");

    let server_addr: std::net::SocketAddr = listener.local_addr().parse().expect("addr");
    let server_key = HybridVerifyingKey::from_bytes(&listener.verifying_key_bytes()).expect("key");

    let listener_clone = listener.clone();
    let server_handle = tokio::spawn(async move {
        let session = listener_clone.accept().await.expect("accept").session();
        let req = session.recv().await.expect("recv");
        session.send(req).await.expect("echo");
        tokio::time::sleep(Duration::from_millis(50)).await;
        let _ = session.disconnect().await;
    });

    // Client uses its own counting runtime.
    let stream = TcpStream::connect(server_addr).await.expect("connect");
    let transport = TcpSessionTransport::new(stream);
    let session = PhantomSession::connect_with_transport_with_runtime(
        &server_addr.to_string(),
        transport,
        server_key,
        client_rt.clone() as Arc<dyn Runtime>,
    );

    // Allow the handshake to complete.
    tokio::time::sleep(Duration::from_millis(500)).await;

    session.send(b"ping".to_vec()).await.expect("send");
    let echo = session.recv().await.expect("recv");
    assert_eq!(echo, b"ping");

    server_handle.await.expect("server task");
    session.disconnect().await.expect("close");

    // The whole point of this test: both runtimes saw spawn calls. The
    // listener runtime spawned the data pump for the accepted session;
    // the client runtime spawned the handshake + data pump background
    // task plus the receive child task inside it.
    assert!(
        listener_rt.spawns() >= 1,
        "listener runtime should have observed at least one spawn, got {}",
        listener_rt.spawns()
    );
    assert!(
        client_rt.spawns() >= 1,
        "client runtime should have observed at least one spawn, got {}",
        client_rt.spawns()
    );

    // Sleeps are optional today (data pump uses tokio::time::interval
    // directly, not runtime.sleep — that's a follow-up commit). Just
    // assert the counter is reachable so the field doesn't bitrot.
    let _ = client_rt.sleeps();
}
