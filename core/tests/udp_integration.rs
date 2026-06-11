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
