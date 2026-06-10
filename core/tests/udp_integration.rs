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
