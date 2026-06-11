//! End-to-end UDP integration for `PhantomUdpListener` <-> `PhantomSession` over `UdpClientTransport`.
//! `#[ignore]`-gated (run with `-- --ignored`).

use phantom_protocol::api::session::PhantomSession;
use phantom_protocol::api::udp_listener::PhantomUdpListener;
use phantom_protocol::api::udp_transport::UdpClientTransport;
use phantom_protocol::crypto::hybrid_sign::HybridVerifyingKey;
use std::time::Duration;
use tokio::time::timeout;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn udp_integration_pinned_and_encrypted() {
    let listener = PhantomUdpListener::bind_udp("127.0.0.1:0".to_string())
        .await
        .expect("bind_udp");
    let addr: std::net::SocketAddr = listener.local_addr().parse().unwrap();
    let key = HybridVerifyingKey::from_bytes(&listener.verifying_key_bytes()).unwrap();

    let server = tokio::spawn(async move {
        let session = listener.accept().await.expect("accept").session();
        let msg = session.recv().await.expect("server recv");
        assert_eq!(msg, b"hello-from-client");
        session
            .send(b"hello-from-server".to_vec())
            .await
            .expect("server send");
        tokio::time::sleep(Duration::from_millis(200)).await;
    });

    let transport = UdpClientTransport::connect(addr)
        .await
        .expect("udp connect");
    let client = PhantomSession::connect_with_transport(&addr.to_string(), transport, key);
    client
        .send(b"hello-from-client".to_vec())
        .await
        .expect("client send");
    let reply = timeout(Duration::from_secs(10), client.recv())
        .await
        .expect("no timeout")
        .expect("client recv");
    assert_eq!(reply, b"hello-from-server");
    server.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn udp_integration_two_sessions_one_client_socket_is_not_required_but_two_clients_ok() {
    // Two independent clients (each its own socket + CID) to one server socket route correctly —
    // the demux keys on CID, not the 4-tuple.
    let listener = PhantomUdpListener::bind_udp("127.0.0.1:0".to_string())
        .await
        .unwrap();
    let addr: std::net::SocketAddr = listener.local_addr().parse().unwrap();
    let key = HybridVerifyingKey::from_bytes(&listener.verifying_key_bytes()).unwrap();

    let server = tokio::spawn(async move {
        for _ in 0..2 {
            let s = listener.accept().await.expect("accept").session();
            let m = s.recv().await.expect("recv");
            s.send(m).await.expect("echo"); // echo back
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    });

    let mut handles = Vec::new();
    for i in 0u8..2 {
        let key = key.clone();
        let addr = addr;
        handles.push(tokio::spawn(async move {
            let t = UdpClientTransport::connect(addr).await.unwrap();
            let c = PhantomSession::connect_with_transport(&addr.to_string(), t, key);
            let payload = vec![i; 32];
            c.send(payload.clone()).await.unwrap();
            let echo = timeout(Duration::from_secs(10), c.recv())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(echo, payload);
        }));
    }
    for h in handles {
        h.await.unwrap();
    }
    server.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn udp_integration_recovers_dropped_first_flight() {
    use tokio::net::UdpSocket;
    let listener = PhantomUdpListener::bind_udp("127.0.0.1:0".to_string())
        .await
        .unwrap();
    let server_addr: std::net::SocketAddr = listener.local_addr().parse().unwrap();
    let key = HybridVerifyingKey::from_bytes(&listener.verifying_key_bytes()).unwrap();
    let server = tokio::spawn(async move {
        let s = listener.accept().await.expect("accept").session();
        let m = s.recv().await.expect("recv");
        s.send(m).await.expect("echo");
        tokio::time::sleep(Duration::from_millis(200)).await;
    });

    // Relay: client <-> relay <-> server, dropping the very first client->server datagram.
    let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let relay_addr = relay.local_addr().unwrap();
    let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    upstream.connect(server_addr).await.unwrap();
    tokio::spawn(async move {
        let mut c2s_buf = vec![0u8; 2048];
        let mut s2c_buf = vec![0u8; 2048];
        let mut client_addr: Option<std::net::SocketAddr> = None;
        let mut dropped_first = false;
        loop {
            tokio::select! {
                r = relay.recv_from(&mut c2s_buf) => {
                    let (n, from) = r.unwrap();
                    client_addr = Some(from);
                    if !dropped_first { dropped_first = true; continue; } // drop first client->server
                    upstream.send(&c2s_buf[..n]).await.unwrap();
                }
                r = upstream.recv(&mut s2c_buf) => {
                    let n = r.unwrap();
                    if let Some(ca) = client_addr { relay.send_to(&s2c_buf[..n], ca).await.unwrap(); }
                }
            }
        }
    });

    let transport = UdpClientTransport::connect(relay_addr).await.unwrap();
    let client = PhantomSession::connect_with_transport(&relay_addr.to_string(), transport, key);
    client.send(b"ping".to_vec()).await.unwrap();
    let echo = timeout(Duration::from_secs(10), client.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(echo, b"ping");
    server.await.unwrap();
}

/// ★ Phase 4 P4.2 mandatory bidirectional test: a live session **survives** an
/// embedder-triggered migration **mid-exchange**, the reliable byte stream resumes
/// **byte-exact**, and there is **no re-handshake** (the same session/keys persist —
/// the test never reconnects). The server follows the peer to the new address
/// (the client drops its old socket once the new path shows life, so the
/// post-migration echoes can only arrive over the new path the server switched to —
/// the direct peer-switch is unit-tested in `udp_transport::promote_candidate_*`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn udp_integration_migration_survives_mid_exchange() {
    const ROUNDS: usize = 8;

    let listener = PhantomUdpListener::bind_udp("127.0.0.1:0".to_string())
        .await
        .expect("bind_udp");
    let addr: std::net::SocketAddr = listener.local_addr().parse().unwrap();
    let key = HybridVerifyingKey::from_bytes(&listener.verifying_key_bytes()).unwrap();

    // Server echoes ROUNDS messages back over the SAME accepted session. The client
    // migrates mid-stream; the server must keep serving that one session and follow
    // the peer to the new address — never re-accepting / re-handshaking.
    let server = tokio::spawn(async move {
        let session = listener.accept().await.expect("accept").session();
        for _ in 0..ROUNDS {
            let m = session.recv().await.expect("server recv");
            session.send(m).await.expect("server echo");
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    });

    let transport = UdpClientTransport::connect(addr)
        .await
        .expect("udp connect");
    let client = PhantomSession::connect_with_transport(&addr.to_string(), transport, key);

    // Round 0 establishes the data plane on the original path.
    let m0 = b"round-0-pre-migration".to_vec();
    client.send(m0.clone()).await.expect("send 0");
    let e0 = timeout(Duration::from_secs(10), client.recv())
        .await
        .expect("no timeout")
        .expect("recv 0");
    assert_eq!(e0, m0, "pre-migration echo must be byte-exact");

    // Migrate mid-exchange to a fresh local socket (a new ephemeral port = a new
    // source 5-tuple the server detects). Best-effort, non-blocking.
    client
        .migrate("127.0.0.1:0".to_string())
        .await
        .expect("migrate");

    // Rounds 1..ROUNDS: the reliable byte stream continues byte-exact across the
    // migration with NO re-handshake. The server detects the new source, challenges +
    // validates the new path, switches its peer, and keeps echoing.
    for i in 1..ROUNDS {
        let m = format!("round-{i}-post-migration-{}", "x".repeat(i * 7)).into_bytes();
        client.send(m.clone()).await.expect("send post-migration");
        let e = timeout(Duration::from_secs(10), client.recv())
            .await
            .expect("no timeout (the session must survive the migration)")
            .expect("recv post-migration");
        assert_eq!(e, m, "post-migration echo must be byte-exact (round {i})");
    }

    server.await.unwrap();
}

/// A bidirectional UDP relay `client <-> relay <-> server` whose forwarding can be
/// cut and restored at will via the returned flag — used to simulate a path that
/// silently dies (and later returns) without tearing down either endpoint's socket.
async fn spawn_cuttable_relay(
    server_addr: std::net::SocketAddr,
) -> (
    std::net::SocketAddr,
    std::sync::Arc<std::sync::atomic::AtomicBool>,
) {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use tokio::net::UdpSocket;

    let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let relay_addr = relay.local_addr().unwrap();
    let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    upstream.connect(server_addr).await.unwrap();
    let forward = Arc::new(AtomicBool::new(true));
    let f = forward.clone();
    tokio::spawn(async move {
        let mut c2s = vec![0u8; 2048];
        let mut s2c = vec![0u8; 2048];
        let mut client_addr: Option<std::net::SocketAddr> = None;
        loop {
            tokio::select! {
                r = relay.recv_from(&mut c2s) => {
                    let (n, from) = match r { Ok(x) => x, Err(_) => continue };
                    client_addr = Some(from);
                    if f.load(Ordering::Relaxed) {
                        let _ = upstream.send(&c2s[..n]).await;
                    }
                }
                r = upstream.recv(&mut s2c) => {
                    let n = match r { Ok(x) => x, Err(_) => continue };
                    if f.load(Ordering::Relaxed) {
                        if let Some(ca) = client_addr {
                            let _ = relay.send_to(&s2c[..n], ca).await;
                        }
                    }
                }
            }
        }
    });
    (relay_addr, forward)
}

/// P4.3: the SDK autonomously detects a silently-dead path. With outstanding unacked
/// data and no inbound, the client surfaces `ConnectionState::Migrating` (so the
/// embedder can `migrate()`), and — with no recovery before the idle-timeout —
/// transitions to `Dead`. `recv()` must error, never hang.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn udp_liveness_dead_path_surfaces_migrating_then_dead() {
    use phantom_protocol::api::session::ConnectionState;
    use phantom_protocol::transport::liveness::LivenessConfig;
    use std::sync::atomic::Ordering;

    let listener = PhantomUdpListener::bind_udp("127.0.0.1:0".to_string())
        .await
        .expect("bind_udp");
    let server_addr: std::net::SocketAddr = listener.local_addr().parse().unwrap();
    let key = HybridVerifyingKey::from_bytes(&listener.verifying_key_bytes()).unwrap();

    let server = tokio::spawn(async move {
        let session = listener.accept().await.expect("accept").session();
        // Echo until the path dies (then recv() errors and we exit).
        while let Ok(m) = session.recv().await {
            let _ = session.send(m).await;
        }
    });

    let (relay_addr, forward) = spawn_cuttable_relay(server_addr).await;
    let transport = UdpClientTransport::connect(relay_addr)
        .await
        .expect("connect");
    let client = PhantomSession::connect_with_transport(&relay_addr.to_string(), transport, key);

    // Warm up one round trip (establishes + measures RTT).
    client.send(b"warmup".to_vec()).await.expect("send");
    let echo = timeout(Duration::from_secs(10), client.recv())
        .await
        .expect("no timeout")
        .expect("recv");
    assert_eq!(echo, b"warmup");

    // Shrink the liveness thresholds so the state machine fires in milliseconds.
    assert!(
        client.set_liveness_config(LivenessConfig::for_test()).await,
        "session must be established to set the liveness config"
    );

    // Kill the path, then keep sending so there is outstanding unacked data.
    forward.store(false, Ordering::Relaxed);
    for i in 0..30u32 {
        let _ = client.send(format!("post-{i}").into_bytes()).await;
    }

    let mut saw_migrating = false;
    let mut saw_dead = false;
    for _ in 0..400 {
        match client.connection_state() {
            ConnectionState::Migrating => saw_migrating = true,
            ConnectionState::Dead => {
                saw_dead = true;
                break;
            }
            _ => {}
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        saw_migrating,
        "a dead path must surface ConnectionState::Migrating"
    );
    assert!(
        saw_dead,
        "no recovery before the idle-timeout must surface ConnectionState::Dead"
    );

    // recv() on a dead session must resolve with an error, not hang forever.
    let r = timeout(Duration::from_secs(2), client.recv()).await;
    assert!(
        matches!(r, Ok(Err(_))),
        "recv() must error on a dead session (got {r:?})"
    );

    server.abort();
}

/// P4.3: a path that goes silent then RETURNS (before the idle-timeout) recovers the
/// same session — `Migrating → Connected` on resumed inbound — and the reliable byte
/// stream continues byte-exact, with no re-handshake.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn udp_liveness_recovers_when_the_path_returns() {
    use phantom_protocol::api::session::ConnectionState;
    use phantom_protocol::transport::liveness::LivenessConfig;
    use std::sync::atomic::Ordering;

    let listener = PhantomUdpListener::bind_udp("127.0.0.1:0".to_string())
        .await
        .expect("bind_udp");
    let server_addr: std::net::SocketAddr = listener.local_addr().parse().unwrap();
    let key = HybridVerifyingKey::from_bytes(&listener.verifying_key_bytes()).unwrap();

    let server = tokio::spawn(async move {
        let session = listener.accept().await.expect("accept").session();
        while let Ok(m) = session.recv().await {
            let _ = session.send(m).await;
        }
    });

    let (relay_addr, forward) = spawn_cuttable_relay(server_addr).await;
    let transport = UdpClientTransport::connect(relay_addr)
        .await
        .expect("connect");
    let client = PhantomSession::connect_with_transport(&relay_addr.to_string(), transport, key);

    client.send(b"warmup".to_vec()).await.expect("send");
    let echo = timeout(Duration::from_secs(10), client.recv())
        .await
        .expect("no timeout")
        .expect("recv");
    assert_eq!(echo, b"warmup");

    // Short path-down, but a LONG idle-timeout so there is room to recover.
    let cfg = LivenessConfig {
        min_pto: Duration::from_millis(10),
        path_down_ptos: 3,
        idle_timeout: Duration::from_secs(20),
    };
    assert!(client.set_liveness_config(cfg).await);

    // Cut the path + create outstanding data → detect down.
    forward.store(false, Ordering::Relaxed);
    for i in 0..30u32 {
        let _ = client.send(format!("gap-{i}").into_bytes()).await;
    }
    let mut saw_migrating = false;
    for _ in 0..300 {
        if client.connection_state() == ConnectionState::Migrating {
            saw_migrating = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(saw_migrating, "a dead path must surface Migrating");

    // Restore the path: retransmits reach the server, ACKs return → recovery.
    forward.store(true, Ordering::Relaxed);
    let mut recovered = false;
    for _ in 0..500 {
        if client.connection_state() == ConnectionState::Connected {
            recovered = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        recovered,
        "the path returning must recover the session to Connected"
    );

    // The reliable byte stream resumes byte-exact: drain the buffered echoes until the
    // post-recovery marker arrives.
    client.send(b"after-recovery".to_vec()).await.expect("send");
    let mut got_final = false;
    for _ in 0..60 {
        let m = timeout(Duration::from_secs(10), client.recv())
            .await
            .expect("no timeout")
            .expect("recv");
        if m == b"after-recovery" {
            got_final = true;
            break;
        }
    }
    assert!(
        got_final,
        "the reliable stream must resume and deliver post-recovery data byte-exact"
    );

    server.abort();
}
